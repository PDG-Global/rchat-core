//! Mutual-intent circuits (spec §6.2). The relay creates a circuit only
//! when both identities have asked for it. A one-sided ask stores a
//! `PendingAsk` and leaves the asker's knock for the target; nothing goes
//! back to the asker, whether the target is online or not.
//!
//! Blinded asks (protocol v3 §C.2) name no target: two proven connections
//! of different identities asking with the same rotating pair token are
//! paired, and their pair row is keyed by the token's `BlindTag`, never by
//! the identity pair. They carry no knock and are never resumed.
//!
//! PRIVACY: no log line here carries an identity-derived value.

use super::fair_share::{AskAdmission, AskKey, AskKind, AskLimits, Side};
use super::key_auth;
use super::pair_lock::{KeyedGuard, BLIND_LOCKS, PAIR_LOCKS};
use super::tags::{blind_tag, id_tag, pair_tag, BlindTag, IdTag, PairTag};
use super::{
    admit_circuit, charge_pending, discharge_pending, record_created_circuit, refuse_circuit,
    refuse_pending_target, send_frame, uncharge_pending, BlindPairInfo, ChargeKey, CircuitPairInfo,
    CircuitRoutingInfo, ClientCircuitInfo, PairKey, PendingCharge, RelayState, UnifiedConnection,
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
use std::sync::Arc;
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

/// An ask's ML-KEM-768 ephemeral public key (1184 bytes, length checked by
/// `validate::control`).
pub(crate) type KemEphemeral = [u8; crate::validate::KEM_PK_BYTES];

/// An ask's ephemerals beyond the X25519 key: the ML-KEM-768 public key and
/// the asker's identity signature over both (ruling R7, length checked by
/// `validate::control`, never verified here). Public material, forwarded
/// unmodified in `CircuitCreatedV3`.
#[derive(Clone)]
pub(crate) struct AskEphemerals {
    pub(crate) kem: KemEphemeral,
    pub(crate) sig: [u8; crate::validate::ASK_EPH_SIG_BYTES],
}

/// One side's standing ask for a pair. Holds the asker's raw bundle for at
/// most `ASK_TTL`.
#[derive(Clone)]
pub(crate) struct PendingAsk {
    pub(super) asker: ClientId,
    pub(super) asker_tag: IdTag,
    /// The target's tag; `None` for a blinded ask, which names no target.
    pub(super) target_tag: Option<IdTag>,
    /// Verified at publish (R5). Shared with the asking connection and its
    /// other asks (final re-review N-2): about 1.3 KB not copied per ask.
    pub(super) asker_bundle: Arc<PeerBundle>,
    pub(super) ephemeral: [u8; 32],
    /// The asker's ML-KEM-768 ephemeral public key (protocol v3 §A.3) and
    /// its signature over both ephemerals (R7), beside the X25519 key: same
    /// `ASK_TTL`, replaced on a re-ask, dropped with the ask, forwarded
    /// unmodified in `CircuitCreatedV3`. Public material; like `ephemeral`
    /// it needs no wipe.
    pub(super) kem_ephemeral: Box<AskEphemerals>,
    pub(super) knocks_delivered: u8,
    pub(super) at: Instant,
    /// The asking connection's source bucket (fair shares, R-2/R-3). Set
    /// when the ask is created and never changed.
    pub(super) source: Option<SourceKey>,
}

/// The pending-table limits an ask of `kind` is admitted under.
fn ask_limits(state: &RelayState, kind: AskKind) -> AskLimits {
    let c = &state.config;
    AskLimits {
        global: c.max_pending_circuit_targets,
        per_source: match kind {
            AskKind::Identity => c.max_pending_per_source,
            AskKind::Blind => c.pending_blind_per_source(),
        },
        blind_cap: c.pending_blind_table_cap(),
    }
}

/// The caller's proven identity, verified bundle and source bucket; `None`
/// if unproven (R3).
fn proven(
    caller: ClientId,
    state: &RelayState,
) -> Option<([u8; 32], Arc<PeerBundle>, Option<SourceKey>)> {
    let mut conn = state.connections.get_mut(&caller)?;
    let bundle = key_auth::proven_bundle(&conn)?;
    // One shared copy per connection (N-2), made from the verified bundle
    // and dropped by the next publish.
    let shared = conn
        .peer_bundle
        .get_or_insert_with(|| Arc::new(key_auth::peer_bundle(&bundle)))
        .clone();
    Some((bundle.identity_key, shared, conn.source))
}

/// Handle `CircuitAsk` (spec §6.2 steps 1–5) under the pair's lock.
pub(super) async fn handle_circuit_ask(
    caller: ClientId,
    target: [u8; 32],
    ephemeral: [u8; 32],
    kem_ephemeral: Box<AskEphemerals>,
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
        earlier.filter(|a| a.asker_tag == target_tag && a.target_tag == Some(caller_tag))
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
                &kem_ephemeral,
                PairKey::Identity(pair),
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
            pending.kem_ephemeral = kem_ephemeral;
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
        ChargeKey::Target(target_tag),
        state.config.max_pending_per_connection,
        None,
    );
    if charge == PendingCharge::Refused {
        refuse_pending_target(caller, &state.connections).await;
        return;
    }
    // R-3: per-source share; a full table evicts from the heaviest source.
    let admission = state.pending_asks.admit(
        AskKind::Identity,
        caller_source,
        ask_limits(state, AskKind::Identity),
    );
    if admission != AskAdmission::Admitted {
        if charge == PendingCharge::New {
            uncharge_pending(&state.connections, caller, ChargeKey::Target(target_tag));
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
            target_tag: Some(target_tag),
            asker_bundle: caller_bundle,
            ephemeral,
            kem_ephemeral,
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

/// Whether `caller` is a connection whose publish was accepted (R3).
pub(super) fn is_proven(caller: ClientId, state: &RelayState) -> bool {
    state
        .connections
        .get(&caller)
        .is_some_and(|c| c.proven_identity.is_some())
}

/// Refuse a `CircuitAskBlind` from a connection that has not proven an
/// identity (§C.2). Nothing is parsed further or stored.
pub(super) async fn refuse_unproven_blind(caller: ClientId, state: &RelayState) {
    metrics::BLIND_ASKS_REFUSED_UNPROVEN.inc();
    let err = FrameBuilder::error(
        ControlErrorCode::AuthenticationFailed,
        "publish a key bundle first",
    );
    let _ = send_frame(caller, err, &state.connections).await;
}

/// Handle `CircuitAskBlind` (protocol v3 §C.2) under the token's lock.
///
/// The token is held only as its `BlindTag` (keyed with the per-boot pair
/// key). Two asks with one tag from two different identities are paired
/// (the earlier asker initiates); the same identity again, on any of its
/// connections, is a replay that replaces the held ask silently; a tag
/// whose pair exists refuses further asks with `PairTokenBusy`. The pair
/// row is keyed by the `BlindTag` and holds the two connection slots only.
///
/// What a live blinded circuit still holds that is identity-derived: its
/// two routing entries carry both members' `IdTag`s, exactly as identity
/// circuits do. They file a packet for a member whose connection is gone in
/// that member's offline queue (filed under the recipient only), hand it to
/// the member's new connection through `identity_to_client`, decide close
/// membership after a reconnect, and let the unresumed sweep see a member
/// back on a new connection. Those entries go with the pair (teardown, or
/// the sweep within 600 s of the last member leaving).
pub(super) async fn handle_circuit_ask_blind(
    caller: ClientId,
    token: [u8; 32],
    ephemeral: [u8; 32],
    kem_ephemeral: Box<AskEphemerals>,
    state: &RelayState,
) {
    // Proven caller (R3); `handle_control_message` already checked this
    // before parsing, and a connection never loses its proof (R7).
    let Some((caller_id, caller_bundle, caller_source)) = proven(caller, state) else {
        refuse_unproven_blind(caller, state).await;
        return;
    };
    let caller_tag = id_tag(&caller_id);
    let tag = blind_tag(&token);
    let _guard = BLIND_LOCKS.lock(tag).await;

    // Busy: this token already paired two asks. A third is refused. A
    // caller that is itself one of the row's slot connections most likely
    // lost its `CircuitCreatedV3` (a full outbound queue drops it): the row
    // is torn down (both get `CircuitClosed`) so the pair is not wedged on
    // a spent token, and the caller is still told busy, so it advances its
    // counter and re-asks (ruling R16). The slot check compares connection
    // ids only, no identity.
    let slot_of_row = state
        .blind_pair_circuits
        .get(&tag)
        .map(|r| r.conn_a == caller || r.conn_b == caller);
    if let Some(is_slot) = slot_of_row {
        if is_slot {
            teardown_key(PairKey::Blind(tag), state, None);
            trace!("Blinded pair torn down: a slot re-asked its spent token");
        }
        metrics::BLIND_ASKS_BUSY.inc();
        trace!("Blind ask refused: token busy");
        // The refused ask's own X25519 ephemeral, so the client knows
        // which of its blind asks (which pair) to advance (R16, R22). Only
        // the caller's public value, sent to the caller only; never logged.
        let err = UnifiedFrame::Control(crate::protocol::unified::ControlMessage::PairTokenBusy {
            ephemeral_key: ephemeral.to_vec(),
        });
        let _ = send_frame(caller, err, &state.connections).await;
        return;
    }

    // An ask past `ASK_TTL` the sweep has not reached yet is already gone.
    if state
        .pending_asks
        .remove_blind_if(&tag, |_, a| {
            Instant::now().saturating_duration_since(a.at) > ASK_TTL
        })
        .is_some()
    {
        metrics::BLIND_ASKS_EXPIRED.inc();
    }

    let earlier = state.pending_asks.get_blind(&tag).map(|a| a.clone());
    if let Some(earlier) = earlier {
        // Replay: the same identity, from this or another of its
        // connections. Never a pair; the newer ask replaces the older one
        // silently. `at` is kept, so a replay never extends the ask past
        // `ASK_TTL` from the first one.
        if earlier.asker_tag == caller_tag {
            replace_blind_ask(
                tag,
                &earlier,
                PendingAsk {
                    asker: caller,
                    asker_tag: caller_tag,
                    target_tag: None,
                    asker_bundle: caller_bundle,
                    ephemeral,
                    kem_ephemeral,
                    knocks_delivered: MAX_KNOCKS_PER_ASK,
                    at: earlier.at,
                    source: caller_source,
                },
                state,
            )
            .await;
            return;
        }
        // Match: another identity asked with this token and is still here.
        let still_there = state
            .connections
            .get(&earlier.asker)
            .and_then(|c| c.proven_identity)
            .is_some_and(|id| id_tag(&id) == earlier.asker_tag);
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
                &kem_ephemeral,
                PairKey::Blind(tag),
                state,
            );
            state.pending_asks.remove_blind(&tag);
            // The held ask is consumed: its connection's charge for this
            // token goes with it, so no connection keeps the pair's tag.
            discharge_pending(&state.connections, earlier.asker, ChargeKey::Blind(tag));
            metrics::BLIND_ASKS_MATCHED.inc();
            return;
        }
        state.pending_asks.remove_blind(&tag);
    }

    // A new held ask: the connection's blind share, its source's blind
    // share and the relay-wide table it shares with identity asks. Blind
    // asks have shares of their own (final review M1): a core holds about
    // four per offline contact (current and previous 10-minute slot, each
    // with its ±1 window sibling), and the relay, seeing only unrelated
    // tokens, can only charge per token. The identity shares stay as they
    // were for first contact and the identity fallback.
    let charge = charge_pending(
        &state.connections,
        caller,
        ChargeKey::Blind(tag),
        state.config.pending_blind_per_connection(),
        Some(state.config.blind_ask_rate()),
    );
    if charge == PendingCharge::Refused {
        refuse_pending_target(caller, &state.connections).await;
        return;
    }
    let admission = state.pending_asks.admit(
        AskKind::Blind,
        caller_source,
        ask_limits(state, AskKind::Blind),
    );
    if admission != AskAdmission::Admitted {
        if charge == PendingCharge::New {
            uncharge_pending(&state.connections, caller, ChargeKey::Blind(tag));
        }
        refuse_pending_target(caller, &state.connections).await;
        return;
    }
    #[cfg(test)]
    tests_hook::before_blind_insert();
    state.pending_asks.insert_blind(
        tag,
        PendingAsk {
            asker: caller,
            asker_tag: caller_tag,
            target_tag: None,
            asker_bundle: caller_bundle,
            ephemeral,
            kem_ephemeral,
            // Blinded asks never carry a knock.
            knocks_delivered: MAX_KNOCKS_PER_ASK,
            at: Instant::now(),
            source: caller_source,
        },
    );
    forget_if_gone(tag, caller, state);
    metrics::BLIND_ASKS_ACCEPTED.inc();
    // Nothing is sent to the caller.
}

/// Ruling R18: a packet on blinded circuit `circuit_id` found its
/// destination slot's connection dead and the member live on another
/// connection. A blinded circuit is never resumed or handed over, so the
/// row is torn down now (both slots told `CircuitClosed`; the routing
/// entries, both tags and both source digests go) instead of filing the
/// packet where it would wait for the member's next publish.
pub(super) async fn teardown_moved_blind(circuit_id: CircuitId, state: &RelayState) {
    let key = state.circuits.get(&circuit_id).map(|r| r.pair);
    let Some(PairKey::Blind(tag)) = key else {
        return;
    };
    let _guard = BLIND_LOCKS.lock(tag).await;
    let row_of_circuit = state
        .blind_pair_circuits
        .get(&tag)
        .is_some_and(|r| r.circuit_id_a == circuit_id || r.circuit_id_b == circuit_id);
    if row_of_circuit {
        teardown_key(PairKey::Blind(tag), state, None);
        trace!("Blinded pair torn down: a member is back on a new connection");
    }
}

/// Drop `circuit_id` from `owner`'s R21 index entry (its row went).
fn forget_departed(owner: IdTag, circuit_id: CircuitId, state: &RelayState) {
    state.departed_blind.remove_if_mut(&owner, |_, cids| {
        cids.retain(|c| *c != circuit_id);
        cids.is_empty()
    });
}

/// Ruling R21: identity `tag` is back on `client`, which has just sent its
/// first ask (final review L1: not at the publish, which a background
/// drain also sends; see `note_first_ask`). Each blinded row whose slot for `tag` is
/// still a closed connection is ended now, as R18 ends it at a packet: the
/// peer that stayed gets `CircuitClosed` and re-asks blind at once, instead
/// of waiting for its own next packet or the sweep. Decided under the
/// identity's lock (the member is mapped to `client`), torn down under each
/// row's lock with the slot re-checked.
pub(super) async fn end_departed_blind_rows(tag: IdTag, client: ClientId, state: &RelayState) {
    if !state.departed_blind.contains_key(&tag) {
        return;
    }
    let _identity = super::pair_lock::ID_LOCKS.lock(tag).await;
    let back = state
        .identity_to_client
        .get(&tag)
        .is_some_and(|c| *c == client);
    if !back {
        return;
    }
    let Some((_, cids)) = state.departed_blind.remove(&tag) else {
        return;
    };
    for cid in cids {
        let row = state
            .circuits
            .get(&cid)
            .filter(|r| r.tag_a == tag && !state.connections.contains_key(&r.client_a))
            .map(|r| r.pair);
        let Some(PairKey::Blind(btag)) = row else {
            continue;
        };
        let _guard = BLIND_LOCKS.lock(btag).await;
        let stale = state.blind_pair_circuits.get(&btag).is_some_and(|r| {
            (r.circuit_id_a == cid && !state.connections.contains_key(&r.conn_a))
                || (r.circuit_id_b == cid && !state.connections.contains_key(&r.conn_b))
        });
        if stale {
            teardown_key(PairKey::Blind(btag), state, None);
            metrics::BLIND_ROWS_ENDED_AT_PUBLISH.inc();
            trace!("Blinded pair torn down: its member published again");
        }
    }
}

/// A disconnect removes the connection from `connections` before it drops
/// the connection's asks, so an ask inserted while its connection was
/// closing is either dropped there or seen gone here: no held ask outlives
/// its connection.
fn forget_if_gone(tag: BlindTag, asker: ClientId, state: &RelayState) {
    if !state.connections.contains_key(&asker) {
        state
            .pending_asks
            .remove_blind_if(&tag, |_, a| a.asker == asker);
    }
}

/// Replay of a held blind ask (`held`) by `newer`, the same identity: the
/// newer ask takes its place. A replay from another connection moves the
/// per-connection charge to it, and one from another source re-books the
/// source share (ruling R17 M2), under the same caps as a new ask; over a
/// cap the replay is refused and the held ask stays.
async fn replace_blind_ask(
    tag: BlindTag,
    held: &PendingAsk,
    newer: PendingAsk,
    state: &RelayState,
) {
    let caller = newer.asker;
    let moved_conn = held.asker != caller;
    let charge = if moved_conn {
        let charge = charge_pending(
            &state.connections,
            caller,
            ChargeKey::Blind(tag),
            state.config.pending_blind_per_connection(),
            Some(state.config.blind_ask_rate()),
        );
        if charge == PendingCharge::Refused {
            refuse_pending_target(caller, &state.connections).await;
            return;
        }
        Some(charge)
    } else {
        None
    };
    if held.source != newer.source {
        // Re-book: take the held ask (and its source's share) out, admit the
        // newer source, put the held ask back if it is refused.
        let old = state.pending_asks.remove_blind(&tag).map(|(_, a)| a);
        let admission = state.pending_asks.admit(
            AskKind::Blind,
            newer.source,
            ask_limits(state, AskKind::Blind),
        );
        if admission != AskAdmission::Admitted {
            if let Some(old) = old {
                let held_asker = old.asker;
                state.pending_asks.insert_blind(tag, old);
                // Its connection may have closed meanwhile (review L-3).
                forget_if_gone(tag, held_asker, state);
            }
            if charge == Some(PendingCharge::New) {
                uncharge_pending(&state.connections, caller, ChargeKey::Blind(tag));
            }
            refuse_pending_target(caller, &state.connections).await;
            return;
        }
    }
    #[cfg(test)]
    tests_hook::before_blind_insert();
    state.pending_asks.insert_blind(tag, newer);
    if moved_conn {
        discharge_pending(&state.connections, held.asker, ChargeKey::Blind(tag));
    }
    forget_if_gone(tag, caller, state);
    trace!("Blind ask replaced by a newer one");
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

/// A pair row of either kind, as the lifecycle code (teardown, sweep,
/// orphaning) sees it.
pub(super) trait PairRow {
    /// The circuit ids of side a and side b.
    fn circuit_ids(&self) -> [CircuitId; 2];
    /// The two connection slots, when the row fixes them (blinded rows:
    /// never resumed, never rebound); `None` when they live in the routing
    /// entries only (identity rows, rebound by a resume).
    fn fixed_slots(&self) -> Option<[ClientId; 2]>;
    fn orphaned_since(&self) -> Option<Instant>;
    fn unresumed_since(&self) -> Option<Instant>;
    fn clocks_mut(&mut self) -> (&mut Option<Instant>, &mut Option<Instant>);
    /// The two sides `circuit_counts` charged for this pair. `removed` are
    /// the pair's routing entries, just taken out of `circuits`.
    fn charged_sides(&self, removed: &[(CircuitId, CircuitRoutingInfo)]) -> Option<[Side; 2]>;
}

impl PairRow for CircuitPairInfo {
    fn circuit_ids(&self) -> [CircuitId; 2] {
        [self.circuit_id_a, self.circuit_id_b]
    }
    fn fixed_slots(&self) -> Option<[ClientId; 2]> {
        None
    }
    fn orphaned_since(&self) -> Option<Instant> {
        self.orphaned_since
    }
    fn unresumed_since(&self) -> Option<Instant> {
        self.unresumed_since
    }
    fn clocks_mut(&mut self) -> (&mut Option<Instant>, &mut Option<Instant>) {
        (&mut self.orphaned_since, &mut self.unresumed_since)
    }
    fn charged_sides(&self, _: &[(CircuitId, CircuitRoutingInfo)]) -> Option<[Side; 2]> {
        Some(pair_sides(self))
    }
}

impl PairRow for BlindPairInfo {
    fn circuit_ids(&self) -> [CircuitId; 2] {
        [self.circuit_id_a, self.circuit_id_b]
    }
    fn fixed_slots(&self) -> Option<[ClientId; 2]> {
        Some([self.conn_a, self.conn_b])
    }
    fn orphaned_since(&self) -> Option<Instant> {
        self.orphaned_since
    }
    fn unresumed_since(&self) -> Option<Instant> {
        self.unresumed_since
    }
    fn clocks_mut(&mut self) -> (&mut Option<Instant>, &mut Option<Instant>) {
        (&mut self.orphaned_since, &mut self.unresumed_since)
    }
    /// The row holds no identity tag; the sides come from the routing
    /// entries (either one names both members). Routing entries are only
    /// ever removed together with their row, here.
    fn charged_sides(&self, removed: &[(CircuitId, CircuitRoutingInfo)]) -> Option<[Side; 2]> {
        let (cid, r) = removed.first()?;
        let (tag_a, tag_b) = if *cid == self.circuit_id_a {
            (r.tag_a, r.tag_b)
        } else {
            (r.tag_b, r.tag_a)
        };
        Some([
            Side {
                tag: tag_a,
                source: self.source_a,
            },
            Side {
                tag: tag_b,
                source: self.source_b,
            },
        ])
    }
}

/// The lock serialising one pair row's decisions, of either kind.
pub(super) enum PairGuard {
    Identity(#[allow(dead_code)] KeyedGuard<PairTag>),
    Blind(#[allow(dead_code)] KeyedGuard<BlindTag>),
}

/// Take the lock of `key`'s row.
pub(super) async fn lock_pair(key: PairKey) -> PairGuard {
    match key {
        PairKey::Identity(p) => PairGuard::Identity(PAIR_LOCKS.lock(p).await),
        PairKey::Blind(b) => PairGuard::Blind(BLIND_LOCKS.lock(b).await),
    }
}

/// The lock of `key`'s row if nobody holds it now; never waits.
pub(super) fn try_lock_pair(key: PairKey) -> Option<PairGuard> {
    match key {
        PairKey::Identity(p) => PAIR_LOCKS.try_lock(p).map(PairGuard::Identity),
        PairKey::Blind(b) => BLIND_LOCKS.try_lock(b).map(PairGuard::Blind),
    }
}

/// Remove a pair: both routing entries and the pair record. Every member
/// still online, except `notify_except`, gets `CircuitClosed{Normal}` for
/// its own circuit.
pub(super) fn teardown_pair(pair: PairTag, state: &RelayState, notify_except: Option<ClientId>) {
    if let Some((_, info)) = state.identity_pair_circuits.remove(&pair) {
        teardown_removed_pair(&info, state, notify_except);
    }
}

/// `teardown_pair` for a row of either kind.
pub(super) fn teardown_key(key: PairKey, state: &RelayState, notify_except: Option<ClientId>) {
    match key {
        PairKey::Identity(pair) => teardown_pair(pair, state, notify_except),
        PairKey::Blind(tag) => {
            if let Some((_, info)) = state.blind_pair_circuits.remove(&tag) {
                teardown_removed_pair(&info, state, notify_except);
            }
        }
    }
}

/// Remove the routing entries of an already-removed pair record and
/// release its circuit counts.
fn teardown_removed_pair<P: PairRow>(
    info: &P,
    state: &RelayState,
    notify_except: Option<ClientId>,
) {
    let mut removed = Vec::with_capacity(2);
    for circuit_id in info.circuit_ids() {
        let Some((_, routing)) = state.circuits.remove(&circuit_id) else {
            continue;
        };
        forget_departed(routing.tag_a, circuit_id, state);
        metrics::CIRCUITS_TOTAL.dec();
        // `client_a` of a routing entry owns that circuit id.
        if let Some(mut conn) = state.connections.get_mut(&routing.client_a) {
            conn.circuits.remove(&circuit_id);
            // No stale id of a gone pair stays on the connection (L-4).
            conn.created_circuits.remove(&circuit_id);
            if Some(routing.client_a) != notify_except {
                let closed = FrameBuilder::circuit_closed(circuit_id, CircuitCloseReason::Normal);
                let _ = conn.ws_tx.send(closed.encode());
            }
        }
        removed.push((circuit_id, routing));
    }
    if let Some(sides) = info.charged_sides(&removed) {
        state.circuit_counts.release(sides);
    }
    debug!("Circuit pair torn down");
}

/// Send a `CircuitCreatedV3`. In `test-mitm` builds the frame first passes
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
/// and tell both sides. `key` says which row records it: an identity pair
/// row, or (blinded asks) a row keyed by the token's `BlindTag` that holds
/// no identity value. The caller holds `key`'s lock.
#[allow(clippy::too_many_arguments)]
fn create_pair(
    earlier: &PendingAsk,
    caller: ClientId,
    caller_tag: IdTag,
    caller_source: Option<SourceKey>,
    caller_bundle: &PeerBundle,
    caller_ek: [u8; 32],
    caller_kem: &AskEphemerals,
    key: PairKey,
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
            pair: key,
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
            pair: key,
            peer_circuit: cid_a,
        },
    );
    match key {
        PairKey::Identity(pair) => {
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
            // Under the pair lock any earlier pair was torn down (step 2),
            // but release whatever this replaces so the counts stay exact.
            if let Some(old) = state.identity_pair_circuits.insert(pair, info) {
                state.circuit_counts.release(pair_sides(&old));
            }
        }
        PairKey::Blind(tag) => {
            let info = BlindPairInfo {
                circuit_id_a: cid_a,
                circuit_id_b: cid_b,
                conn_a: a,
                conn_b: b,
                source_a: earlier.source,
                source_b: caller_source,
                orphaned_since: None,
                unresumed_since: None,
                created_at: Instant::now(),
            };
            // Under the token's lock a live row refuses the ask (busy), so
            // there is none to replace; tear one down fully if there were.
            if let Some((_, old)) = state.blind_pair_circuits.remove(&tag) {
                teardown_removed_pair(&old, state, None);
            }
            state.circuit_counts.charge([
                Side {
                    tag: earlier.asker_tag,
                    source: earlier.source,
                },
                Side {
                    tag: caller_tag,
                    source: caller_source,
                },
            ]);
            state.blind_pair_circuits.insert(tag, info);
        }
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
        FrameBuilder::circuit_created_v3(
            cid_a,
            token_a.key.to_vec(),
            cid_b,
            0,
            caller_bundle.clone(),
            earlier.ephemeral.to_vec(),
            caller_ek.to_vec(),
            earlier.kem_ephemeral.kem.to_vec(),
            caller_kem.kem.to_vec(),
            earlier.kem_ephemeral.sig.to_vec(),
            caller_kem.sig.to_vec(),
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
        FrameBuilder::circuit_created_v3(
            cid_b,
            token_b.key.to_vec(),
            cid_a,
            1,
            PeerBundle::clone(&earlier.asker_bundle),
            earlier.ephemeral.to_vec(),
            caller_ek.to_vec(),
            earlier.kem_ephemeral.kem.to_vec(),
            caller_kem.kem.to_vec(),
            earlier.kem_ephemeral.sig.to_vec(),
            caller_kem.sig.to_vec(),
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
    let Some(key) = member else {
        return;
    };
    let _guard = lock_pair(key).await;
    // Re-check under the lock: the pair may have been replaced meanwhile.
    let still_member = state
        .circuits
        .get(&circuit_id)
        .is_some_and(|r| r.pair == key && is_member(&r));
    if !still_member {
        return;
    }
    teardown_key(key, state, Some(caller));
    // A blinded token is spent once paired: there is no ask of the caller's
    // under it to drop.
    if let PairKey::Identity(pair) = key {
        state
            .pending_asks
            .remove_if(&pair, |_, ask| ask.asker_tag == caller_tag);
    }
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
    let _ = state.pending_asks.retain(|_, ask| ask.asker != client_id);
    let own: Vec<CircuitId> = conn.circuits.iter().map(|e| *e.key()).collect();
    for cid in own {
        let routing = state
            .circuits
            .get(&cid)
            .filter(|r| r.client_a == client_id)
            .map(|r| (r.pair, r.client_b, r.tag_a));
        let Some((key, peer, owner_tag)) = routing else {
            continue;
        };
        let peer_gone = !state.connections.contains_key(&peer);
        match key {
            PairKey::Identity(pair) => {
                if peer_gone {
                    if let Some(mut p) = state.identity_pair_circuits.get_mut(&pair) {
                        p.orphaned_since.get_or_insert(now);
                    }
                }
            }
            // Ruling R15: a blinded row is never resumed, so its clock
            // starts when either slot's connection closes (the sweep tears
            // it down `PAIR_ORPHAN_TTL` later, live peer or not), and the
            // last member leaving tears it down now. A busy lock leaves it
            // to the sweep.
            PairKey::Blind(tag) => {
                if let Some(mut p) = state.blind_pair_circuits.get_mut(&tag) {
                    p.orphaned_since.get_or_insert(now);
                }
                let mut ended = false;
                // Fix round 2 N-1: the owner already published on a new,
                // live connection (the common mobile case: the new socket
                // beat the old one's close). Its publish found nothing to
                // end yet, so the row ends here, the peer told at once.
                // Final review L1: only a new connection that has asked; a
                // background drain never re-pairs, so the row waits (in the
                // R21 index) for the foreground connection's first ask.
                let owner_back = state
                    .identity_to_client
                    .get(&owner_tag)
                    .map(|c| *c)
                    .is_some_and(|c| c != client_id && super::is_foreground(c, state));
                if peer_gone || owner_back {
                    if let Some(_guard) = BLIND_LOCKS.try_lock(tag) {
                        // Re-check under the lock that this connection is
                        // still a slot of the row (review L-2).
                        if let Some((_, info)) = state
                            .blind_pair_circuits
                            .remove_if(&tag, |_, r| r.conn_a == client_id || r.conn_b == client_id)
                        {
                            teardown_removed_pair(&info, state, None);
                            ended = true;
                        }
                    }
                }
                // R21: the row stays for the peer; the owner's next publish
                // ends it (`end_departed_blind_rows`). A busy lock with the
                // owner already back leaves it to the sweep (0 s grace).
                if !ended && state.circuits.contains_key(&cid) {
                    state.departed_blind.entry(owner_tag).or_default().push(cid);
                }
            }
        }
    }
}

/// Drop pending asks (identity and blinded) older than `ASK_TTL` or whose
/// asker is gone.
pub(super) fn sweep_asks(now: Instant, live: &HashSet<ClientId>, state: &RelayState) -> usize {
    let fresh = |ask: &PendingAsk| now.saturating_duration_since(ask.at) <= ASK_TTL;
    // Counted from the asks actually removed, so asks inserted concurrently
    // (shard by shard) never skew the count (R-8).
    let removed = state
        .pending_asks
        .retain(|_, ask| fresh(ask) && live.contains(&ask.asker));
    let blind_expired = removed
        .iter()
        .filter(|(key, ask)| matches!(key, AskKey::Blind(_)) && !fresh(ask))
        .count();
    metrics::BLIND_ASKS_EXPIRED.inc_by(blind_expired as u64);
    removed.len()
}

/// Whether any member of the pair's circuit `circuit_id_a` is connected.
fn pair_has_live_member<P: PairRow>(p: &P, live: &HashSet<ClientId>, state: &RelayState) -> bool {
    if let Some(slots) = p.fixed_slots() {
        return slots.iter().any(|c| live.contains(c));
    }
    state
        .circuits
        .get(&p.circuit_ids()[0])
        .is_some_and(|r| live.contains(&r.client_a) || live.contains(&r.client_b))
}

/// Whether a member of the pair is online but has not resumed: its slot
/// still names a connection that is gone, while its identity is mapped to a
/// live, proven connection (it reconnected and published, but did not ask
/// with this circuit as `resume_circuit`). Cores resume every circuit they
/// can use right after the publish is accepted, so such a member has no
/// session for the pair: it restarted, or it blocked, unpinned or deleted
/// the peer (security review M-1). A blinded pair is never resumed (§C.3):
/// a member back on a new connection re-pairs under a new token, so its
/// old pair goes after the same grace.
///
/// Final review L1: for a blinded row the member's new connection must
/// also have asked (`is_foreground`): a background drain publishes and
/// leaves without re-pairing, so until the foreground connection's first
/// ask the member counts as offline and the row stays for the orphan TTL
/// (R15, within 600 s).
fn pair_has_unresumed_member<P: PairRow>(
    p: &P,
    live: &HashSet<ClientId>,
    state: &RelayState,
) -> bool {
    let blinded = p.fixed_slots().is_some();
    p.circuit_ids().iter().any(|cid| {
        // Copy out before the next lookup: never hold two map guards.
        let slot = state.circuits.get(cid).map(|r| (r.client_a, r.tag_a));
        let Some((owner, tag)) = slot.filter(|(owner, _)| !live.contains(owner)) else {
            return false;
        };
        let mapped = state.identity_to_client.get(&tag).map(|c| *c);
        mapped.is_some_and(|c| {
            c != owner && live.contains(&c) && (!blinded || super::is_foreground(c, state))
        })
    })
}

/// The sweep's expiry predicate for one pair: orphaned past
/// `PAIR_ORPHAN_TTL` with no live member, a member online without resuming
/// for longer than `PAIR_RESUME_GRACE`, or both routing entries gone.
fn pair_expired<P: PairRow>(
    now: Instant,
    p: &P,
    live: &HashSet<ClientId>,
    state: &RelayState,
) -> bool {
    // A row with fixed slots (blinded) expires `PAIR_ORPHAN_TTL` after
    // either slot's connection closed, whether or not the other member is
    // still online (ruling R15); an identity row only once no member is.
    let orphan_expired = PairRow::orphaned_since(p)
        .is_some_and(|t| now.saturating_duration_since(t) > PAIR_ORPHAN_TTL)
        && (p.fixed_slots().is_some() || !pair_has_live_member(p, live, state));
    // A blinded row is never resumed, so a member back on a new connection
    // ends it at once (0 s grace, ruling R18); identity rows keep
    // `PAIR_RESUME_GRACE` for their resume.
    let unresumed_expired = match p.fixed_slots() {
        Some(_) => pair_has_unresumed_member(p, live, state),
        None => {
            PairRow::unresumed_since(p)
                .is_some_and(|t| now.saturating_duration_since(t) > PAIR_RESUME_GRACE)
                && pair_has_unresumed_member(p, live, state)
        }
    };
    // Every fixed slot dead: the last-member teardown in `on_disconnect`
    // missed its lock; the next sweep takes it (review L-1).
    let slots_dead = p
        .fixed_slots()
        .is_some_and(|slots| slots.iter().all(|c| !live.contains(c)));
    let [cid_a, cid_b] = p.circuit_ids();
    let routing_gone = !state.circuits.contains_key(&cid_a) && !state.circuits.contains_key(&cid_b);
    orphan_expired || unresumed_expired || slots_dead || routing_gone
}

/// Remove pairs orphaned for longer than `PAIR_ORPHAN_TTL` (both members
/// gone), pairs a member left unresumed for longer than `PAIR_RESUME_GRACE`
/// while online, and pairs whose routing entries have vanished. The
/// predicate is re-checked atomically at removal, so a pair resumed or
/// rebuilt since it was selected survives. A torn-down pair's online slot
/// owners get `CircuitClosed{Normal}`.
pub(super) fn sweep_pairs(now: Instant, live: &HashSet<ClientId>, state: &RelayState) -> usize {
    // R21: an index entry never outlives its row (rows end within
    // `PAIR_ORPHAN_TTL`; teardown prunes, this catches any it missed).
    state.departed_blind.retain(|_, cids| {
        cids.retain(|c| state.circuits.contains_key(c));
        !cids.is_empty()
    });
    sweep_rows(
        &state.identity_pair_circuits,
        PairKey::Identity,
        now,
        live,
        state,
    ) + sweep_rows(&state.blind_pair_circuits, PairKey::Blind, now, live, state)
}

/// `sweep_pairs` over one kind of pair row.
fn sweep_rows<K, P>(
    rows: &dashmap::DashMap<K, P>,
    key_of: fn(K) -> PairKey,
    now: Instant,
    live: &HashSet<ClientId>,
    state: &RelayState,
) -> usize
where
    K: Copy + Eq + std::hash::Hash,
    P: PairRow,
{
    let candidates: Vec<K> = rows
        .iter()
        .filter(|e| pair_expired(now, e.value(), live, state))
        .map(|e| *e.key())
        .collect();
    let mut removed = 0;
    for k in candidates {
        // Re-review R-1: never remove a pair while an ask, resume or close
        // holds its lock (a resume could otherwise report a pair that is
        // gone). A busy pair is left for the next sweep.
        let Some(_guard) = try_lock_pair(key_of(k)) else {
            continue;
        };
        if let Some((_, info)) = rows.remove_if(&k, |_, p| pair_expired(now, p, live, state)) {
            teardown_removed_pair(&info, state, None);
            removed += 1;
        }
    }
    // A pair with a live member is not orphaned (clear a stale timestamp so
    // it cannot shorten later retention); one with no live member and no
    // clock (a missed disconnect) starts its orphan clock now, so it cannot
    // outlive the TTL by more than one sweep. Likewise the unresumed clock
    // starts at the first sweep that sees a member online without resuming,
    // and is cleared once it resumes (or leaves).
    let unresumed: HashSet<K> = rows
        .iter()
        .filter(|e| pair_has_unresumed_member(e.value(), live, state))
        .map(|e| *e.key())
        .collect();
    for mut e in rows.iter_mut() {
        // Fixed slots (blinded rows): the clock runs once either slot's
        // connection is gone; otherwise once no member is live.
        let has_live = match e.value().fixed_slots() {
            Some(slots) => slots.iter().all(|c| live.contains(c)),
            None => pair_has_live_member(e.value(), live, state),
        };
        let is_unresumed = unresumed.contains(e.key());
        let (orphaned_since, unresumed_since) = e.value_mut().clocks_mut();
        if has_live {
            *orphaned_since = None;
        } else {
            orphaned_since.get_or_insert(now);
        }
        if is_unresumed {
            unresumed_since.get_or_insert(now);
        } else {
            *unresumed_since = None;
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
    let got = rchat_core::keyauth::SignedBundle::from_wire(
        &peer.identity_key,
        &peer.identity_agreement_key,
        &peer.kem_pk,
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

    thread_local! {
        static BLIND_INSERT: RefCell<Option<Box<dyn FnOnce()>>> = const { RefCell::new(None) };
    }

    /// Runs right before a blind ask (new or replay) is inserted.
    pub(in crate::signaling) fn set_before_blind_insert(f: impl FnOnce() + 'static) {
        BLIND_INSERT.with(|h| *h.borrow_mut() = Some(Box::new(f)));
    }

    pub(super) fn before_blind_insert() {
        if let Some(f) = BLIND_INSERT.with(|h| h.borrow_mut().take()) {
            f();
        }
    }
}
