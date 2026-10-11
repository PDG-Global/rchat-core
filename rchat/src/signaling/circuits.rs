//! Mutual-intent circuits (spec §6.2). The relay creates a circuit only
//! when both identities have asked for it. A one-sided ask stores a
//! `PendingAsk` and leaves the asker's knock for the target; nothing goes
//! back to the asker, whether the target is online or not.
//!
//! PRIVACY: no log line here carries an identity-derived value.

use super::fair_share::{AskAdmission, Side};
use super::key_auth;
use super::pair_lock::PAIR_LOCKS;
use super::tags::{id_tag, pair_tag, IdTag, PairTag};
use super::{
    admit_circuit, charge_pending, record_created_circuit, refuse_circuit, refuse_pending_target,
    send_frame, uncharge_pending, CircuitPairInfo, CircuitRoutingInfo, ClientCircuitInfo,
    PendingCharge, RelayState, UnifiedConnection,
};
use crate::limits::SourceKey;
use crate::metrics;
use crate::privacy;
use crate::protocol::relay::CircuitToken;
use crate::protocol::unified::{
    CircuitCloseReason, ControlErrorCode, FrameBuilder, PeerBundle, UnifiedFrame,
};
use crate::protocol::{CircuitId, ClientId};
use std::collections::HashSet;
use std::time::{Duration, Instant};
use tracing::{debug, trace};

/// A pending ask expires after this long (and when its asker disconnects).
/// 540 s plus the 60 s sweep interval keeps every ask gone within the
/// spec's 600 s, even while the asker stays connected.
pub(super) const ASK_TTL: Duration = Duration::from_secs(540);
/// Knocks delivered per pending ask, re-asks included.
pub(super) const MAX_KNOCKS_PER_ASK: u8 = 2;
/// Lifetime given to circuit tokens (circuits themselves live while used).
const CIRCUIT_TOKEN_TTL: Duration = Duration::from_secs(3600);

/// One side's standing ask for a pair. Holds the asker's raw bundle for at
/// most `ASK_TTL`.
#[derive(Clone)]
pub(crate) struct PendingAsk {
    pub(super) asker: ClientId,
    pub(super) asker_tag: IdTag,
    pub(super) target_tag: IdTag,
    /// Verified at publish (R5).
    pub(super) asker_bundle: PeerBundle,
    pub(super) ephemeral: [u8; 32],
    pub(super) knocks_delivered: u8,
    pub(super) at: Instant,
    /// The asking connection's source bucket (fair shares, R-2/R-3). Set
    /// when the ask is created and never changed.
    pub(super) source: Option<SourceKey>,
}

/// The caller's proven identity, verified bundle and source bucket; `None`
/// if unproven (R3).
fn proven(
    caller: ClientId,
    state: &RelayState,
) -> Option<([u8; 32], PeerBundle, Option<SourceKey>)> {
    let conn = state.connections.get(&caller)?;
    let bundle = key_auth::proven_bundle(&conn)?;
    Some((
        bundle.identity_key,
        key_auth::peer_bundle(&bundle),
        conn.source,
    ))
}

/// Handle `CircuitAsk` (spec §6.2 steps 1–5) under the pair's lock.
pub(super) async fn handle_circuit_ask(
    caller: ClientId,
    target: [u8; 32],
    ephemeral: [u8; 32],
    knock: Vec<u8>,
    resume: Option<CircuitId>,
    state: &RelayState,
) {
    // 1. Preconditions: proven caller (R3), not asking itself.
    let Some((caller_id, caller_bundle, caller_source)) = proven(caller, state) else {
        let err = FrameBuilder::error(
            ControlErrorCode::AuthenticationFailed,
            "publish a key bundle first",
        );
        let _ = send_frame(caller, err, &state.connections).await;
        return;
    };
    if caller_id == target {
        let err = FrameBuilder::error(
            ControlErrorCode::InvalidMessage,
            "cannot ask for a circuit with yourself",
        );
        let _ = send_frame(caller, err, &state.connections).await;
        return;
    }
    let caller_tag = id_tag(&caller_id);
    let target_tag = id_tag(&target);
    let pair = pair_tag(&caller_id, &target);
    let _pair_guard = PAIR_LOCKS.lock(pair).await;

    // Step 2 (spec §6.2): an active pair is either validly resumed or torn down.
    if let ActivePair::Resumed = resolve_active_pair(caller, caller_tag, pair, resume, state).await
    {
        return;
    }

    // An ask past `ASK_TTL` that the sweep has not reached yet is already
    // gone: it neither matches (step 3) nor takes a re-ask (step 4).
    state.pending_asks.remove_if(&pair, |_, a| {
        Instant::now().saturating_duration_since(a.at) > ASK_TTL
    });

    // 3. Match: the other identity asked and is still here.
    let earlier = state.pending_asks.get(&pair).map(|a| a.clone());
    if let Some(earlier) =
        earlier.filter(|a| a.asker_tag == target_tag && a.target_tag == caller_tag)
    {
        let still_there = state
            .connections
            .get(&earlier.asker)
            .is_some_and(|c| c.proven_identity == Some(target));
        if still_there {
            let sides = [
                Side {
                    tag: earlier.asker_tag,
                    source: earlier.source,
                },
                Side {
                    tag: caller_tag,
                    source: caller_source,
                },
            ];
            if !admit_circuit(state, caller, sides) {
                refuse_circuit(caller, &state.connections).await;
                return;
            }
            create_pair(
                &earlier,
                caller,
                caller_tag,
                caller_source,
                &caller_bundle,
                ephemeral,
                pair,
                state,
            );
            state.pending_asks.remove(&pair);
            // The caller's knock is discarded.
            return;
        }
        state.pending_asks.remove(&pair);
    }

    // 4. Re-ask from the same identity: new EK, at most two knocks per ask.
    // `at` is kept: a re-ask never extends the ask past `ASK_TTL` from the
    // first ask (spec §5.2: the ask is held for at most 600 s). Once it has
    // expired, the next re-ask is a new ask (step 5).
    if let Some(mut pending) = state.pending_asks.get_mut(&pair) {
        if pending.asker_tag == caller_tag {
            pending.asker = caller;
            pending.asker_bundle = caller_bundle;
            pending.ephemeral = ephemeral;
            let deliver = pending.knocks_delivered < MAX_KNOCKS_PER_ASK;
            if deliver {
                pending.knocks_delivered += 1;
            }
            drop(pending);
            if deliver {
                deliver_knock(target_tag, pair, knock, caller_source, state);
            }
            return;
        }
    }

    // 5. A new one-sided ask. Refusals reveal only the caller's own limits
    // (its connection's and its source's shares, or a full relay).
    let charge = charge_pending(
        &state.connections,
        caller,
        target_tag,
        state.config.max_pending_per_connection,
    );
    if charge == PendingCharge::Refused {
        refuse_pending_target(caller, &state.connections).await;
        return;
    }
    // R-3: per-source share; a full table evicts from the heaviest source.
    let admission = state.pending_asks.admit(
        caller_source,
        state.config.max_pending_circuit_targets,
        state.config.max_pending_per_source,
    );
    if admission != AskAdmission::Admitted {
        if charge == PendingCharge::New {
            uncharge_pending(&state.connections, caller, target_tag);
        }
        refuse_pending_target(caller, &state.connections).await;
        return;
    }
    // The asker quota is charged here, before any delivery and whatever the
    // target's presence: over quota, the knock is dropped on every path
    // (no live send, no store) and the ask's re-asks carry none either, so
    // the quota is no presence oracle. The ask itself still stands and can
    // match.
    let knock_allowed = state
        .knocks
        .charge_asker(caller_tag, caller_source, Instant::now());
    state.pending_asks.insert(
        pair,
        PendingAsk {
            asker: caller,
            asker_tag: caller_tag,
            target_tag,
            asker_bundle: caller_bundle,
            ephemeral,
            knocks_delivered: if knock_allowed { 1 } else { MAX_KNOCKS_PER_ASK },
            at: Instant::now(),
            source: caller_source,
        },
    );
    if knock_allowed {
        deliver_knock(target_tag, pair, knock, caller_source, state);
    }
    // Nothing is sent to the caller.
}

/// Hand a knock to the target without ever waiting on it: a live,
/// non-blocking send when it is online with room in its queue, otherwise
/// the knock store (separate budget and caps). A blocking send would stall
/// the asker only when the target is online — a presence timing oracle (L7).
/// The caller has already charged the asker's quota (`charge_asker`).
pub(super) fn deliver_knock(
    target_tag: IdTag,
    pair: PairTag,
    knock: Vec<u8>,
    source: Option<SourceKey>,
    state: &RelayState,
) {
    if try_send_knock_live(target_tag, &knock, state) {
        trace!("Knock delivered live");
        return;
    }
    #[cfg(test)]
    tests_hook::before_knock_queued();
    let _ = state.knocks.enqueue(
        target_tag,
        Some(pair),
        knock,
        crate::protocol::timestamp(),
        &state.message_queues,
        source,
    );
    // A publish by the target may have mapped it and drained its queue
    // between the lookup above and the enqueue: the knock would wait for the
    // next publish. Re-check; if the target is mapped now, take the knock
    // back out of the store (unless the publish already delivered it) and
    // send it live. Removal is atomic, so the knock is delivered at most once.
    // It may then arrive after knocks the publish's drain sent, out of
    // queue order; harmless, as every knock stands alone.
    if !state.identity_to_client.contains_key(&target_tag) {
        trace!("Knock queued");
        return;
    }
    let Some(knock) = state
        .knocks
        .reclaim(target_tag, pair, &state.message_queues)
    else {
        trace!("Knock queued");
        return;
    };
    if try_send_knock_live(target_tag, &knock, state) {
        trace!("Knock delivered live after a concurrent publish");
        return;
    }
    // Online with a full queue: the store keeps it, as above (R4).
    let _ = state.knocks.enqueue(
        target_tag,
        Some(pair),
        knock,
        crate::protocol::timestamp(),
        &state.message_queues,
        source,
    );
    trace!("Knock queued");
}

/// Non-blocking live send of a knock to the target's mapped, proven
/// connection. Never blocks: a blocked send would stall the asker's read
/// loop only when the target is online — a presence timing oracle (L7). A
/// full queue falls back to the store and never disconnects the target.
fn try_send_knock_live(target_tag: IdTag, knock: &[u8], state: &RelayState) -> bool {
    let live = state
        .identity_to_client
        .get(&target_tag)
        .map(|c| *c)
        .and_then(|client| {
            state
                .connections
                .get(&client)
                .filter(|c| c.proven_identity.is_some())
                .map(|c| c.ws_tx.clone())
        });
    let Some(tx) = live else {
        return false;
    };
    let frame = FrameBuilder::queued_message(knock.to_vec()).encode();
    tx.try_send_or_return(frame).is_ok()
}

/// Remove a pair: both routing entries and the pair record. Every member
/// still online, except `notify_except`, gets `CircuitClosed{Normal}` for
/// its own circuit.
pub(super) fn teardown_pair(pair: PairTag, state: &RelayState, notify_except: Option<ClientId>) {
    if let Some((_, info)) = state.identity_pair_circuits.remove(&pair) {
        teardown_removed_pair(info, state, notify_except);
    }
}

/// Remove the routing entries of an already-removed pair record.
fn teardown_removed_pair(
    info: CircuitPairInfo,
    state: &RelayState,
    notify_except: Option<ClientId>,
) {
    state.circuit_counts.release(pair_sides(&info));
    for circuit_id in [info.circuit_id_a, info.circuit_id_b] {
        let Some((_, routing)) = state.circuits.remove(&circuit_id) else {
            continue;
        };
        metrics::CIRCUITS_TOTAL.dec();
        // `client_a` of a routing entry owns that circuit id.
        if let Some(conn) = state.connections.get(&routing.client_a) {
            conn.circuits.remove(&circuit_id);
            if Some(routing.client_a) != notify_except {
                let closed = FrameBuilder::circuit_closed(circuit_id, CircuitCloseReason::Normal);
                let _ = conn.ws_tx.send(closed.encode());
            }
        }
    }
    debug!("Circuit pair torn down");
}

/// Send a `CircuitCreatedV2`. In `test-mitm` builds the frame first passes
/// through the malicious-relay hook (spec E5), which may alter or drop it.
fn send_created(to: ClientId, frame: UnifiedFrame, state: &RelayState) {
    #[cfg(feature = "test-mitm")]
    let frame = match frame {
        UnifiedFrame::Control(mut msg) => {
            if !super::mitm::mitm_rewrite(to, &mut msg, state) {
                return;
            }
            UnifiedFrame::Control(msg)
        }
        other => other,
    };
    if let Some(conn) = state.connections.get(&to) {
        let _ = conn.ws_tx.send(frame.encode());
    }
}

/// The two sides `circuit_counts` charged for a pair.
fn pair_sides(info: &CircuitPairInfo) -> [Side; 2] {
    [
        Side {
            tag: info.slot_a,
            source: info.source_a,
        },
        Side {
            tag: info.slot_b,
            source: info.source_b,
        },
    ]
}

/// Create the pair for `earlier` (initiator, side a) and `caller` (side b)
/// and tell both sides.
#[allow(clippy::too_many_arguments)]
fn create_pair(
    earlier: &PendingAsk,
    caller: ClientId,
    caller_tag: IdTag,
    caller_source: Option<SourceKey>,
    caller_bundle: &PeerBundle,
    caller_ek: [u8; 32],
    pair: PairTag,
    state: &RelayState,
) {
    let (cid_a, cid_b) = (CircuitId::generate(), CircuitId::generate());
    let token_a = CircuitToken::generate(cid_a, CIRCUIT_TOKEN_TTL);
    let token_b = CircuitToken::generate(cid_b, CIRCUIT_TOKEN_TTL);
    let (a, b) = (earlier.asker, caller);

    state.circuits.insert(
        cid_a,
        CircuitRoutingInfo {
            client_a: a,
            client_b: b,
            tag_a: earlier.asker_tag,
            tag_b: caller_tag,
            token_a: token_a.clone(),
            token_b: token_b.clone(),
            pair,
            peer_circuit: cid_b,
        },
    );
    state.circuits.insert(
        cid_b,
        CircuitRoutingInfo {
            client_a: b,
            client_b: a,
            tag_a: caller_tag,
            tag_b: earlier.asker_tag,
            token_a: token_b.clone(),
            token_b: token_a.clone(),
            pair,
            peer_circuit: cid_a,
        },
    );
    let info = CircuitPairInfo {
        circuit_id_a: cid_a,
        circuit_id_b: cid_b,
        token_a: token_a.clone(),
        token_b: token_b.clone(),
        slot_a: earlier.asker_tag,
        slot_b: caller_tag,
        source_a: earlier.source,
        source_b: caller_source,
        orphaned_since: None,
        unresumed_since: None,
        created_at: Instant::now(),
    };
    state.circuit_counts.charge(pair_sides(&info));
    // Under the pair lock any earlier pair was torn down (step 2), but
    // release whatever this replaces so the counts stay exact.
    if let Some(old) = state.identity_pair_circuits.insert(pair, info) {
        state.circuit_counts.release(pair_sides(&old));
    }
    record_created_circuit(&state.connections, b, cid_b);
    metrics::CIRCUITS_TOTAL.inc();
    metrics::CIRCUITS_TOTAL.inc();

    if let Some(conn) = state.connections.get(&a) {
        conn.circuits.insert(
            cid_a,
            ClientCircuitInfo {
                circuit_id: cid_a,
                token: token_a.clone(),
                target_circuit_id: cid_b,
                target_client_id: b,
            },
        );
    }
    send_created(
        a,
        FrameBuilder::circuit_created_v2(
            cid_a,
            token_a.key.to_vec(),
            cid_b,
            0,
            caller_bundle.clone(),
            earlier.ephemeral.to_vec(),
            caller_ek.to_vec(),
        ),
        state,
    );
    if let Some(conn) = state.connections.get(&b) {
        conn.circuits.insert(
            cid_b,
            ClientCircuitInfo {
                circuit_id: cid_b,
                token: token_b.clone(),
                target_circuit_id: cid_a,
                target_client_id: a,
            },
        );
    }
    send_created(
        b,
        FrameBuilder::circuit_created_v2(
            cid_b,
            token_b.key.to_vec(),
            cid_a,
            1,
            earlier.asker_bundle.clone(),
            earlier.ephemeral.to_vec(),
            caller_ek.to_vec(),
        ),
        state,
    );
    trace!(
        "Created circuit pair {} <-> {}",
        privacy::tag(cid_a.as_ref()),
        privacy::tag(cid_b.as_ref())
    );
}

/// How long a pair whose members have both left is kept. Spec §5.2: no
/// structure links two identities later than ten minutes after the last
/// participating connection closed. The sweep runs every 60 s, so a pair is
/// gone at most 540 + 60 = 600 s after its second member left.
pub(super) const PAIR_ORPHAN_TTL: Duration = Duration::from_secs(540);

/// How long a pair is kept while one member is online without resuming it
/// (security review M-1). Cores resume right after their publish is
/// accepted, so this is far longer than a resume takes; with the 60 s sweep
/// such a pair is gone 120-240 s after the member came back.
pub(super) const PAIR_RESUME_GRACE: Duration = Duration::from_secs(120);

/// Outcome of looking at an existing pair for a new ask (spec §6.2 step 2).
pub(super) enum ActivePair {
    /// Valid resume: the caller's slot was rebound; the ask is done.
    Resumed,
    /// No active pair (or it was torn down): continue at step 3.
    Clear,
}

/// Step 2 of `CircuitAsk`. Caller holds `PAIR_LOCKS` for `pair`.
pub(super) async fn resolve_active_pair(
    caller: ClientId,
    caller_tag: IdTag,
    pair: PairTag,
    resume: Option<CircuitId>,
    state: &RelayState,
) -> ActivePair {
    let Some(info) = state.identity_pair_circuits.get(&pair).map(|p| p.clone()) else {
        return ActivePair::Clear;
    };
    let caller_is_a = info.slot_a == caller_tag;
    let (own, other, own_token, peer_token) = if caller_is_a {
        (
            info.circuit_id_a,
            info.circuit_id_b,
            info.token_a.clone(),
            info.token_b.clone(),
        )
    } else {
        (
            info.circuit_id_b,
            info.circuit_id_a,
            info.token_b.clone(),
            info.token_a.clone(),
        )
    };
    // R2: only a connection proven as the slot's identity may rebind it.
    let slot_is_callers = state
        .circuits
        .get(&own)
        .is_some_and(|r| r.tag_a == caller_tag);
    if resume == Some(own) && slot_is_callers {
        rebind_slot(caller, own, other, &own_token, state);
        #[cfg(test)]
        tests_hook::after_rebind();
        // Re-check after the rebind (re-review R-1): every remover takes
        // this pair's lock today, but a pair or routing entry gone by now
        // must never be reported as resumed, or the caller would treat a
        // dead circuit as live. Fall through to a fresh ask instead.
        let still_there = state
            .identity_pair_circuits
            .get_mut(&pair)
            .map(|mut p| {
                p.orphaned_since = None;
                p.unresumed_since = None;
            })
            .is_some()
            && state.circuits.contains_key(&own)
            && state.circuits.contains_key(&other);
        if !still_there {
            if let Some(conn) = state.connections.get(&caller) {
                conn.circuits.remove(&own);
            }
            teardown_pair(pair, state, Some(caller));
            return ActivePair::Clear;
        }
        let to_caller =
            FrameBuilder::circuit_exists(own, own_token.key.to_vec(), other, caller_is_a);
        let _ = send_frame(caller, to_caller, &state.connections).await;
        let peer = state
            .circuits
            .get(&other)
            .map(|r| r.client_a)
            .filter(|p| state.connections.contains_key(p));
        if let Some(peer) = peer {
            let to_peer =
                FrameBuilder::circuit_exists(other, peer_token.key.to_vec(), own, !caller_is_a);
            let _ = send_frame(peer, to_peer, &state.connections).await;
        }
        trace!("Circuit pair resumed");
        return ActivePair::Resumed;
    }
    teardown_pair(pair, state, Some(caller));
    ActivePair::Clear
}

/// Point the caller's side of a pair at the caller's (new) connection.
fn rebind_slot(
    caller: ClientId,
    own: CircuitId,
    other: CircuitId,
    own_token: &CircuitToken,
    state: &RelayState,
) {
    let previous = state.circuits.get_mut(&own).map(|mut r| {
        let old = r.client_a;
        r.client_a = caller;
        old
    });
    let peer = state.circuits.get_mut(&other).map(|mut r| {
        r.client_b = caller;
        r.client_a
    });
    if let Some(old) = previous.filter(|old| *old != caller) {
        if let Some(conn) = state.connections.get(&old) {
            conn.circuits.remove(&own);
        }
    }
    if let Some(conn) = state.connections.get(&caller) {
        conn.circuits.insert(
            own,
            ClientCircuitInfo {
                circuit_id: own,
                token: own_token.clone(),
                target_circuit_id: other,
                target_client_id: peer.unwrap_or(caller),
            },
        );
    }
    if let Some(peer) = peer {
        if let Some(conn) = state.connections.get(&peer) {
            if let Some(mut info) = conn.circuits.get_mut(&other) {
                info.target_client_id = caller;
            }
        }
    }
}

/// `CloseCircuit` from a member tears down the whole pair (H2). The other
/// member gets `CircuitClosed{Normal}` (from `teardown_pair`); the closer's
/// pending ask for this pair is dropped. A non-member is ignored, and the
/// caller gets nothing back either way.
///
/// Membership is decided by the caller's proven identity (its `IdTag`), not
/// by the connection id stored in the routing entry: after a reconnect that
/// entry names the dead connection until a resume rebinds it, and a member
/// that blocks or deletes the peer in that window must still be able to
/// close (security review M-1). Only a proven connection can be a member
/// (R3), and a connection's proven identity never changes (R7).
pub(super) async fn handle_close_circuit(
    caller: ClientId,
    circuit_id: CircuitId,
    state: &RelayState,
) {
    let Some(caller_tag) = state
        .connections
        .get(&caller)
        .and_then(|c| c.proven_identity)
        .map(|id| id_tag(&id))
    else {
        return;
    };
    let is_member = |r: &CircuitRoutingInfo| r.tag_a == caller_tag || r.tag_b == caller_tag;
    let member = state
        .circuits
        .get(&circuit_id)
        .filter(|r| is_member(r))
        .map(|r| r.pair);
    let Some(pair) = member else {
        return;
    };
    let _guard = PAIR_LOCKS.lock(pair).await;
    // Re-check under the lock: the pair may have been replaced meanwhile.
    let still_member = state
        .circuits
        .get(&circuit_id)
        .is_some_and(|r| r.pair == pair && is_member(&r));
    if !still_member {
        return;
    }
    teardown_pair(pair, state, Some(caller));
    state
        .pending_asks
        .remove_if(&pair, |_, ask| ask.asker_tag == caller_tag);
    trace!("Circuit pair closed by a member");
}

/// Disconnect cleanup for circuit state: the client's pending asks go; its
/// pairs stay (the peer may still send, which queues), but a pair whose
/// other member is also gone is marked orphaned now. `conn` has already
/// been removed from `state.connections`.
pub(super) fn on_disconnect(
    client_id: ClientId,
    conn: &UnifiedConnection,
    state: &RelayState,
    now: Instant,
) {
    // O(pending asks), bounded by `max_pending_circuit_targets`; a re-ask
    // from another connection of the same identity moves an ask, so there
    // is no stable per-connection index to use instead.
    state.pending_asks.retain(|_, ask| ask.asker != client_id);
    for entry in conn.circuits.iter() {
        let routing = state
            .circuits
            .get(entry.key())
            .filter(|r| r.client_a == client_id)
            .map(|r| (r.pair, r.client_b));
        let Some((pair, peer)) = routing else {
            continue;
        };
        if !state.connections.contains_key(&peer) {
            if let Some(mut p) = state.identity_pair_circuits.get_mut(&pair) {
                p.orphaned_since.get_or_insert(now);
            }
        }
    }
}

/// Drop pending asks older than `ASK_TTL` or whose asker is gone.
pub(super) fn sweep_asks(now: Instant, live: &HashSet<ClientId>, state: &RelayState) -> usize {
    let before = state.pending_asks.len();
    state.pending_asks.retain(|_, ask| {
        now.saturating_duration_since(ask.at) <= ASK_TTL && live.contains(&ask.asker)
    });
    // Asks inserted concurrently (shard by shard) can make the map grow
    // during the retain (R-8).
    before.saturating_sub(state.pending_asks.len())
}

/// Whether any member of the pair's circuit `circuit_id_a` is connected.
fn pair_has_live_member(p: &CircuitPairInfo, live: &HashSet<ClientId>, state: &RelayState) -> bool {
    state
        .circuits
        .get(&p.circuit_id_a)
        .is_some_and(|r| live.contains(&r.client_a) || live.contains(&r.client_b))
}

/// Whether a member of the pair is online but has not resumed: its slot
/// still names a connection that is gone, while its identity is mapped to a
/// live, proven connection (it reconnected and published, but did not ask
/// with this circuit as `resume_circuit`). Cores resume every circuit they
/// can use right after the publish is accepted, so such a member has no
/// session for the pair: it restarted, or it blocked, unpinned or deleted
/// the peer (security review M-1).
fn pair_has_unresumed_member(
    p: &CircuitPairInfo,
    live: &HashSet<ClientId>,
    state: &RelayState,
) -> bool {
    [p.circuit_id_a, p.circuit_id_b].iter().any(|cid| {
        // Copy out before the next lookup: never hold two map guards.
        let slot = state.circuits.get(cid).map(|r| (r.client_a, r.tag_a));
        let Some((owner, tag)) = slot.filter(|(owner, _)| !live.contains(owner)) else {
            return false;
        };
        let mapped = state.identity_to_client.get(&tag).map(|c| *c);
        mapped.is_some_and(|c| c != owner && live.contains(&c))
    })
}

/// The sweep's expiry predicate for one pair: orphaned past
/// `PAIR_ORPHAN_TTL` with no live member, a member online without resuming
/// for longer than `PAIR_RESUME_GRACE`, or both routing entries gone.
fn pair_expired(
    now: Instant,
    p: &CircuitPairInfo,
    live: &HashSet<ClientId>,
    state: &RelayState,
) -> bool {
    let orphan_expired = !pair_has_live_member(p, live, state)
        && p.orphaned_since
            .is_some_and(|t| now.saturating_duration_since(t) > PAIR_ORPHAN_TTL);
    let unresumed_expired = p
        .unresumed_since
        .is_some_and(|t| now.saturating_duration_since(t) > PAIR_RESUME_GRACE)
        && pair_has_unresumed_member(p, live, state);
    let routing_gone = !state.circuits.contains_key(&p.circuit_id_a)
        && !state.circuits.contains_key(&p.circuit_id_b);
    orphan_expired || unresumed_expired || routing_gone
}

/// Remove pairs orphaned for longer than `PAIR_ORPHAN_TTL` (both members
/// gone), pairs a member left unresumed for longer than `PAIR_RESUME_GRACE`
/// while online, and pairs whose routing entries have vanished. The
/// predicate is re-checked atomically at removal, so a pair resumed or
/// rebuilt since it was selected survives. A torn-down pair's online slot
/// owners get `CircuitClosed{Normal}`.
pub(super) fn sweep_pairs(now: Instant, live: &HashSet<ClientId>, state: &RelayState) -> usize {
    let candidates: Vec<PairTag> = state
        .identity_pair_circuits
        .iter()
        .filter(|e| pair_expired(now, e.value(), live, state))
        .map(|e| *e.key())
        .collect();
    let mut removed = 0;
    for pair in candidates {
        // Re-review R-1: never remove a pair while an ask, resume or close
        // holds its lock (a resume could otherwise report a pair that is
        // gone). A busy pair is left for the next sweep.
        let Some(_guard) = PAIR_LOCKS.try_lock(pair) else {
            continue;
        };
        if let Some((_, info)) = state
            .identity_pair_circuits
            .remove_if(&pair, |_, p| pair_expired(now, p, live, state))
        {
            teardown_removed_pair(info, state, None);
            removed += 1;
        }
    }
    // A pair with a live member is not orphaned (clear a stale timestamp so
    // it cannot shorten later retention); one with no live member and no
    // clock (a missed disconnect) starts its orphan clock now, so it cannot
    // outlive the TTL by more than one sweep. Likewise the unresumed clock
    // starts at the first sweep that sees a member online without resuming,
    // and is cleared once it resumes (or leaves).
    let unresumed: HashSet<PairTag> = state
        .identity_pair_circuits
        .iter()
        .filter(|e| pair_has_unresumed_member(e.value(), live, state))
        .map(|e| *e.key())
        .collect();
    for mut e in state.identity_pair_circuits.iter_mut() {
        if pair_has_live_member(&e, live, state) {
            e.orphaned_since = None;
        } else {
            e.orphaned_since.get_or_insert(now);
        }
        if unresumed.contains(e.key()) {
            e.unresumed_since.get_or_insert(now);
        } else {
            e.unresumed_since = None;
        }
    }
    removed
}

/// R1: `identity_to_client[X]` points only at a live connection proven as X.
#[cfg(test)]
pub(super) fn assert_r1(state: &RelayState) {
    for entry in state.identity_to_client.iter() {
        let conn = state
            .connections
            .get(entry.value())
            .expect("R1: mapping points at a live connection");
        let proven = conn
            .proven_identity
            .expect("R1: mapped connection is proven");
        assert_eq!(
            id_tag(&proven),
            *entry.key(),
            "R1: mapped to its own identity"
        );
    }
}

/// R2: a circuit's owning slot is bound only to a connection proven as the
/// slot's identity.
#[cfg(test)]
pub(super) fn assert_r2_slot(state: &RelayState, circuit_id: CircuitId) {
    let routing = state.circuits.get(&circuit_id).expect("circuit exists");
    if let Some(conn) = state.connections.get(&routing.client_a) {
        assert_eq!(
            conn.proven_identity.map(|p| id_tag(&p)),
            Some(routing.tag_a),
            "R2: slot bound to a connection proven as its identity"
        );
    }
}

/// R3: a pending ask exists only for a proven caller. Every pending ask's
/// asker, while still connected, is proven as the ask's `asker_tag`.
#[cfg(test)]
pub(super) fn assert_r3(state: &RelayState) {
    for ask in state.pending_asks.iter() {
        let (asker, tag) = (ask.asker, ask.asker_tag);
        drop(ask);
        if let Some(conn) = state.connections.get(&asker) {
            assert_eq!(
                conn.proven_identity.map(|p| id_tag(&p)),
                Some(tag),
                "R3: a pending ask comes from a connection proven as its asker"
            );
        }
    }
}

/// R4: `owner`'s queue is delivered only on the success branch of publish.
/// For a connection whose publish was refused: none of `frames` (what it
/// received) is a queued message or relay packet, and `owner`'s queue
/// still holds `queued_before` records.
#[cfg(test)]
pub(super) fn assert_r4_undelivered(
    state: &RelayState,
    owner: IdTag,
    queued_before: usize,
    frames: &[UnifiedFrame],
) {
    assert!(
        !frames.iter().any(|f| matches!(
            f,
            UnifiedFrame::Relay(_)
                | UnifiedFrame::Control(
                    crate::protocol::unified::ControlMessage::QueuedMessage { .. }
                )
        )),
        "R4: nothing from the queue reached a connection whose publish failed"
    );
    let left = state
        .message_queues
        .get(&owner)
        .map_or(0, |q| q.pending.len());
    assert_eq!(left, queued_before, "R4: the queue is untouched");
}

/// R6: no log line carries two or more identity-derived values. `needles`
/// are every such value the test's identities could produce (lowercase).
#[cfg(test)]
pub(super) fn assert_r6(logs: &str, needles: &[String]) {
    for line in logs.lines() {
        let l = line.to_lowercase();
        let hits = needles.iter().filter(|n| l.contains(n.as_str())).count();
        assert!(
            hits < 2,
            "R6: log line carries {hits} identity-derived values: {line}"
        );
    }
}

/// R7: a connection's proven identity, once set, never changes. `proven`
/// is the identity it proved first; a connection already gone passes.
#[cfg(test)]
pub(super) fn assert_r7(state: &RelayState, client: ClientId, proven: [u8; 32]) {
    if let Some(conn) = state.connections.get(&client) {
        assert_eq!(
            conn.proven_identity,
            Some(proven),
            "R7: proven identity never changes"
        );
    }
}

/// R5: a `PeerBundle` sent to a client is the verified published bundle.
#[cfg(test)]
pub(super) fn assert_r5(peer: &PeerBundle, expected: &rchat_core::keyauth::SignedBundle) {
    let got = rchat_core::keyauth::SignedBundle::from_slices(
        &peer.identity_key,
        &peer.identity_agreement_key,
        &peer.signed_pre_key,
        &peer.bundle_signature,
    )
    .expect("R5: well-formed bundle");
    rchat_core::keyauth::verify_bundle(&got).expect("R5: bundle verifies");
    assert_eq!(&got, expected, "R5: byte for byte the published bundle");
}

/// Test hook: runs between the failed live lookup and the queue push in
/// `deliver_knock`, so a test can land a publish exactly there.
#[cfg(test)]
pub(super) mod tests_hook {
    use std::cell::RefCell;

    thread_local! {
        static HOOK: RefCell<Option<Box<dyn FnOnce()>>> = const { RefCell::new(None) };
    }

    pub(in crate::signaling) fn set_before_knock_queued(f: impl FnOnce() + 'static) {
        HOOK.with(|h| *h.borrow_mut() = Some(Box::new(f)));
    }

    pub(super) fn before_knock_queued() {
        if let Some(f) = HOOK.with(|h| h.borrow_mut().take()) {
            f();
        }
    }

    thread_local! {
        static REBIND: RefCell<Option<Box<dyn FnOnce()>>> = const { RefCell::new(None) };
    }

    /// Runs right after a resume rebinds the caller's slot.
    pub(in crate::signaling) fn set_after_rebind(f: impl FnOnce() + 'static) {
        REBIND.with(|h| *h.borrow_mut() = Some(Box::new(f)));
    }

    pub(super) fn after_rebind() {
        if let Some(f) = REBIND.with(|h| h.borrow_mut().take()) {
            f();
        }
    }
}
