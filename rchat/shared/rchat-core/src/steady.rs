//! Steady-rate sending (protocol v3 §B), opt-in. While the app is in the
//! foreground and connected, the core sends one relay packet every slot,
//! to a destination drawn uniformly at random from the circuits open at
//! that moment. Every packet in the shape is a sealed envelope around a
//! ratchet plaintext padded to exactly `STEADY_PLAINTEXT_LEN` bytes.
//!
//! What fills a slot, for the chosen destination, in this order:
//! 1. an owed session notice (`0x06`);
//! 2. one batch of queued receipts (`0x03`, up to 32 ids) or the message
//!    at the head of the session's queue when it fits; when both wait they
//!    take turns, so receipts never starve messages;
//! 3. otherwise a cover packet (`0x05 0x01`), which the peer drops
//!    silently and never answers.
//!
//! Liveness (R23): a peer sent `STEADY_UNHEARD_LIMIT` slots with nothing
//! decrypted from it in between leaves the draw until its next packet
//! decrypts; meanwhile its items go the normal way, outside the shape.
//!
//! Outside the shape, at their normal time and padding bucket: anything
//! that does not fit 1 KiB (images, files, voice notes, texts over
//! `STEADY_MAX_TEXT_BYTES`), the
//! session-init and the initiator's hello sync (§A.4), the resume's
//! re-sends of tracked payloads, knocks, asks, rotation notices and
//! keepalives.
//!
//! Starvation (§B.1): a peer whose waiting item has not been served for
//! more than `3 × n_open` slots overrides the next slot's destination
//! (oldest first). Its clock restarts whenever it is served, so the head
//! of a queue waits at most `4 × n_open` slots: `3n` before it starves,
//! then at most `n - 1` older starved peers ahead of it, one slot each.
//! An item with k items ahead of it for the same peer (messages, receipt
//! batches and notices all count) waits at most `4n·(k + 1)` slots.
//! This override is the one timing leak inside the shape.

use crate::circuits::{COVER_REPLY, COVER_TYPE};
use crate::protocol::MessageType;
use crate::{ClientInner, RChatError};
use rand::rngs::OsRng;
use rand::{Rng, RngCore};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// The slot lengths the app may choose (0.5, 1 and 2 s).
pub const STEADY_SLOT_CHOICES_MS: [u32; 3] = [500, 1000, 2000];
/// The default slot length (§B.1).
pub const STEADY_DEFAULT_SLOT_MS: u32 = 500;
/// Every steady packet's ratchet plaintext is exactly this long after padding.
pub const STEADY_PLAINTEXT_LEN: usize = 1024;
/// The longest text, in UTF-8 bytes, that rides a slot: its type byte,
/// `expire_secs` (§I.2) and one pad byte take the rest of 1 KiB. Longer
/// texts go outside the shape (§B.1).
pub const STEADY_MAX_TEXT_BYTES: usize =
    STEADY_PLAINTEXT_LEN - 1 - crate::disappearing::EXPIRE_LEN - 1;
const _: () = assert!(STEADY_MAX_TEXT_BYTES == 1018);
// A timer change (`0x09`, 13 bytes) always fits a slot (§I.2).
const _: () = assert!(crate::disappearing::TIMER_PLAINTEXT_LEN < STEADY_PLAINTEXT_LEN);
/// A waiting item starves after more than this many slots per open circuit.
pub(crate) const STARVATION_SLOTS_PER_OPEN: u32 = 3;
/// R23: after this many slots sent to a peer with nothing decrypted from
/// it in between, the peer leaves the steady draw until its next packet
/// decrypts. A relay does not close a pair's row while one side is live,
/// so slots to a peer whose connection dropped would otherwise fill its
/// offline queue (1,000 per recipient) and open a ratchet gap the peer
/// cannot skip.
pub const STEADY_UNHEARD_LIMIT: u32 = 64;
// Below the receiver's skip limit: every slot to a vanished peer could be
// lost and its next message still decrypts.
const _: () = assert!(STEADY_UNHEARD_LIMIT < crate::crypto::MAX_SKIP);
// Every slot item is bounded below 1 KiB (M2): the largest receipt
// (`03 kind count 32×id`) and the largest signed notice
// (`06 flags reason count 32×id 64 sig`), each with its one pad byte.
const _: () = assert!(3 + 16 * crate::receipts::MAX_IDS < STEADY_PLAINTEXT_LEN);
const _: () = assert!(4 + 16 * crate::notice::MAX_IDS + 1 + 64 < STEADY_PLAINTEXT_LEN);

/// A peer's identity, lowercase hex.
pub(crate) type PeerHex = String;

/// One of `STEADY_SLOT_CHOICES_MS`.
pub fn valid_slot_ms(ms: u32) -> bool {
    STEADY_SLOT_CHOICES_MS.contains(&ms)
}

/// A ratchet plaintext of `len` bytes (type byte included) fits a slot:
/// padding always adds at least one byte.
pub(crate) fn fits(len: usize) -> bool {
    len < STEADY_PLAINTEXT_LEN
}

/// The `0x01`/`0x02`/`0x07` ratchet plaintext of an app message (its
/// content starts with `expire_secs`, §I.2), or a `0x09` timer change.
pub(crate) fn message_plaintext(msg_type: MessageType, content: &[u8]) -> Vec<u8> {
    let type_byte = match msg_type {
        MessageType::Text | MessageType::E2EEHandshake => 0x01,
        MessageType::Binary | MessageType::Voice => 0x02,
        MessageType::File => crate::file_msg::FILE_TYPE,
        MessageType::Timer => crate::disappearing::TIMER_TYPE,
    };
    let mut plaintext = Vec::with_capacity(1 + content.len());
    plaintext.push(type_byte);
    plaintext.extend_from_slice(content);
    plaintext
}

/// What one slot carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SlotFill {
    Notice,
    Receipt,
    Message,
    Cover,
}

/// Chooses each slot's destination: uniform over the open circuits, unless
/// a peer's waiting item has starved.
pub(crate) struct SteadyScheduler {
    slot: Duration,
    /// Per open peer with a real item waiting: since when it has waited
    /// without being served (restarted at every service).
    pub(crate) waiting_since: HashMap<PeerHex, Instant>,
}

impl SteadyScheduler {
    pub(crate) fn new(slot: Duration) -> Self {
        Self {
            slot,
            waiting_since: HashMap::new(),
        }
    }

    pub(crate) fn slot(&self) -> Duration {
        self.slot
    }

    /// Record whether `peer` has a real item waiting now. A clock starts
    /// when one first waits and is dropped when nothing does.
    pub(crate) fn note_waiting(&mut self, peer: &str, waiting: bool, now: Instant) {
        if waiting {
            self.waiting_since.entry(peer.to_string()).or_insert(now);
        } else {
            self.waiting_since.remove(peer);
        }
    }

    /// `peer` got a slot: its waiting clock (if any) restarts now.
    pub(crate) fn served(&mut self, peer: &str, now: Instant) {
        if let Some(since) = self.waiting_since.get_mut(peer) {
            *since = now;
        }
    }

    /// The destination of the slot at `now`: the longest-starved peer (a
    /// waiting item unserved for more than `3 × open.len()` slots), else
    /// one drawn uniformly from `open`. None without an open circuit.
    pub fn next_destination(
        &mut self,
        open: &[PeerHex],
        rng: &mut impl Rng,
        now: Instant,
    ) -> Option<PeerHex> {
        self.waiting_since.retain(|p, _| open.contains(p));
        if open.is_empty() {
            return None;
        }
        let n = u32::try_from(open.len()).unwrap_or(u32::MAX);
        let limit = self
            .slot
            .saturating_mul(STARVATION_SLOTS_PER_OPEN.saturating_mul(n));
        let starved = self
            .waiting_since
            .iter()
            .filter(|(_, since)| now.saturating_duration_since(**since) > limit)
            .min_by(|a, b| a.1.cmp(b.1).then_with(|| a.0.cmp(b.0)))
            .map(|(p, _)| p.clone());
        if starved.is_some() {
            return starved;
        }
        Some(open[rng.gen_range(0..open.len())].clone())
    }
}

impl ClientInner {
    /// Apply a steady setting (under the client lock). A change of slot
    /// length or of whether steady runs ends the running slot task; the
    /// shared tick starts a new one when it should run. What waited for
    /// slots goes the normal way once steady stops.
    pub(crate) fn apply_steady(&mut self, enabled: bool, slot_ms: u32, foreground: bool) {
        let was_active = self.steady_active();
        let slot_ms = if valid_slot_ms(slot_ms) {
            slot_ms
        } else {
            STEADY_DEFAULT_SLOT_MS
        };
        if slot_ms != self.steady_slot_ms || (enabled && foreground) != was_active {
            self.steady_task_gen = self.steady_task_gen.wrapping_add(1);
            self.steady_task_running = false;
        }
        if slot_ms != self.steady_slot_ms {
            self.steady = SteadyScheduler::new(Duration::from_millis(u64::from(slot_ms)));
        }
        self.steady_enabled = enabled;
        self.steady_slot_ms = slot_ms;
        self.steady_foreground = foreground;
        if was_active && !self.steady_active() {
            self.steady.waiting_since.clear();
            // Receipts and notices held for slots: through the normal
            // (batched, delayed) path now. Parked messages are sent by
            // the next `flush_queued_sends`.
            let mut owed: Vec<String> = self
                .pending_receipts
                .keys()
                .map(|(p, _)| p.clone())
                .chain(self.notice_due.iter().cloned())
                .collect();
            owed.sort();
            owed.dedup();
            for peer in owed {
                self.flush_receipts(&peer);
            }
        }
    }

    /// Steady is on and the app is in the foreground.
    pub(crate) fn steady_active(&self) -> bool {
        // Never in a background drain (§H.1), whatever the app set.
        self.steady_enabled && self.steady_foreground && !self.in_drain()
    }

    /// R23: `peer` left the draw (unheard for `STEADY_UNHEARD_LIMIT` slots).
    pub(crate) fn steady_paused(&self, peer: &str) -> bool {
        self.steady_unheard
            .get(peer)
            .is_some_and(|n| *n >= STEADY_UNHEARD_LIMIT)
    }

    /// Small sends, receipts and notices for `peer` wait for slots: steady
    /// active and the peer not paused. A paused peer's items take the
    /// normal path, outside the shape, with today's semantics.
    pub(crate) fn steady_holds(&self, peer: &str) -> bool {
        self.steady_active() && !self.steady_paused(peer)
    }

    /// The slot timer should run: steady active, the transport usable, and
    /// at least one open circuit.
    pub(crate) fn steady_should_run(&self) -> bool {
        self.steady_active() && self.transport_usable() && !self.steady_open_peers().is_empty()
    }

    /// The circuits a slot may go to, sorted: an accepted peer with a live
    /// circuit on this connection and an established session that can send
    /// now. A pair still owed its session-init (or the initiator's hello
    /// sync that carries it) is not open: the init goes first, outside the
    /// shape (§A.4). A peer re-pairing blind has no live circuit.
    pub(crate) fn steady_open_peers(&self) -> Vec<PeerHex> {
        let mut open: Vec<PeerHex> = self
            .session_manager
            .get_all_recipients()
            .into_iter()
            .filter(|p| {
                self.check_sendable(p).is_ok()
                    && !self.steady_paused(p)
                    && self.has_live_circuit(p)
                    && !self.hello_sync_due.contains(p)
                    && self.session_manager.get(p).is_some_and(|s| {
                        s.can_send()
                            && !s.init_out.as_ref().is_some_and(
                                |i| !matches!(&i.sent, Some(x) if !x.payload.is_empty()),
                            )
                    })
            })
            .collect();
        open.sort();
        open
    }

    /// `peer` has a real item that would fill its slot.
    fn steady_has_item(&self, peer: &str) -> bool {
        self.notice_due.contains(peer)
            || self
                .pending_receipts
                .iter()
                .any(|((p, _), ids)| p == peer && !ids.is_empty())
            || self.session_manager.get(peer).is_some_and(|s| {
                s.pending_messages
                    .front()
                    .is_some_and(|m| fits(1 + m.content.len()))
            })
    }

    /// One slot, with the OS CSPRNG choosing the destination.
    pub(crate) fn fire_steady_slot(&mut self, now: Instant) -> Option<SlotFill> {
        self.fire_steady_slot_with(now, &mut OsRng)
    }

    /// One slot: at most one packet, to one open circuit. Nothing without
    /// steady active, a usable transport and an open circuit.
    pub(crate) fn fire_steady_slot_with(
        &mut self,
        now: Instant,
        rng: &mut impl RngCore,
    ) -> Option<SlotFill> {
        if !self.steady_active() || !self.transport_usable() {
            return None;
        }
        let open = self.steady_open_peers();
        for p in &open {
            let waiting = self.steady_has_item(p);
            self.steady.note_waiting(p, waiting, now);
        }
        let dest = self.steady.next_destination(&open, rng, now)?;
        // Counted before the seal (R26), so the seal's own durable write
        // carries it: a relaunch restores the count, never one behind.
        let before = self.steady_unheard.get(&dest).copied().unwrap_or(0);
        self.steady_unheard
            .insert(dest.clone(), before.saturating_add(1));
        self.steady_padding = true;
        let fill = self.steady_fill(&dest);
        self.steady_padding = false;
        // Served whatever went: an item that could not leave does not take
        // every later slot through the starvation override.
        self.steady.served(&dest, now);
        if fill.is_none() {
            // Nothing left: not counted (a write already made errs high).
            self.steady_unheard.insert(dest.clone(), before);
        } else {
            let unheard = before.saturating_add(1);
            if unheard == STEADY_UNHEARD_LIMIT {
                log::debug!("[RUST] steady: a peer left the draw (unheard)");
                self.steady_message_turn.remove(&dest);
                // Its held receipts and notice go the normal way now;
                // parked messages go with the next `flush_queued_sends`.
                self.flush_receipts(&dest);
            }
        }
        fill
    }

    /// The slot sealed an item that did not fit (never expected, M2):
    /// send what `send` sends again outside the shape, at its bucket.
    fn steady_resend_oversize(&mut self, send: impl FnOnce(&mut Self)) {
        if self
            .steady_oversize
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            log::warn!("[RUST] a steady slot item did not fit; sent outside the shape");
            self.steady_padding = false;
            send(self);
            self.steady_padding = true;
        }
    }

    /// A message that fits waits at the head of `peer`'s queue.
    fn steady_message_waiting(&self, peer: &str) -> bool {
        self.session_manager.get(peer).is_some_and(|s| {
            s.pending_messages
                .front()
                .is_some_and(|m| fits(1 + m.content.len()))
        })
    }

    /// Fill `peer`'s slot (sealed at exactly `STEADY_PLAINTEXT_LEN`).
    fn steady_fill(&mut self, peer: &str) -> Option<SlotFill> {
        if self.notice_due.contains(peer) {
            if self.send_notice_now(peer) {
                return Some(SlotFill::Notice);
            }
            self.steady_resend_oversize(|c| {
                c.send_notice_now(peer);
            });
        }
        // A flagged notice still owed holds the receipts (as in
        // `send_receipts_now`).
        let held = self.notice_due.contains(peer) && self.notice_flag_pending.contains_key(peer);
        // M1: when both wait, receipts and messages take turns, so a
        // stream of receipts never starves our messages (each counts as
        // an item in the 4n·k bound).
        let message_waiting = self.steady_message_waiting(peer);
        if message_waiting
            && self.steady_message_turn.contains(peer)
            && self.steady_send_message(peer)
        {
            self.steady_message_turn.remove(peer);
            return Some(SlotFill::Message);
        }
        if !held {
            if self.send_receipt_batches(peer, 1) > 0 {
                if message_waiting {
                    self.steady_message_turn.insert(peer.to_string());
                }
                return Some(SlotFill::Receipt);
            }
            self.steady_resend_oversize(|c| {
                c.send_receipt_batches(peer, usize::MAX);
            });
        }
        if self.steady_send_message(peer) {
            self.steady_message_turn.remove(peer);
            return Some(SlotFill::Message);
        }
        match self.steady_send_cover(peer) {
            Ok(()) => Some(SlotFill::Cover),
            Err(_) => {
                log::debug!("[RUST] steady cover not sent");
                None
            }
        }
    }

    /// Send the message at the head of `peer`'s queue if it fits a slot,
    /// with the queued path's tracking: tracked before the send, and kept
    /// tracked if the transport refuses it, so the resume re-sends the same
    /// bytes. A failed write (D28) puts it back at the head.
    fn steady_send_message(&mut self, peer: &str) -> bool {
        let msg = {
            let Some(mut s) = self.session_manager.get_mut(peer) else {
                return false;
            };
            if !s
                .pending_messages
                .front()
                .is_some_and(|m| fits(1 + m.content.len()))
            {
                return false;
            }
            match s.pending_messages.pop_front() {
                Some(m) => m,
                None => return false,
            }
        };
        let Some(id) = crate::circuits::message_id_from_hex(&msg.id.0) else {
            return false;
        };
        let plaintext = zeroize::Zeroizing::new(message_plaintext(msg.msg_type, &msg.content));
        let packet = match self.seal_ratchet(peer, id, &plaintext) {
            Ok(p) => p,
            Err(RChatError::StatePersistFailed) => {
                if let Some(mut s) = self.session_manager.get_mut(peer) {
                    s.pending_messages.push_front(msg);
                }
                return false;
            }
            Err(_) => {
                // Never dropped silently (M6): the app hears it was lost.
                log::warn!("[RUST] a queued message could not be sent");
                self.emit_status(crate::status::StatusEvent::QueuedSendLost {
                    peer: peer.to_string(),
                    message_id: msg.id.0.clone(),
                });
                return false;
            }
        };
        let id_hex = hex::encode(id);
        let (circuit, payload) = (packet.circuit_id.clone(), packet.payload.clone());
        self.track_sent(peer, &id_hex, circuit, payload, &plaintext);
        if self.send_now(packet.encode_with_frame_type()).is_err() {
            log::debug!("[RUST] steady message refused by the transport; tracked for the resume");
        }
        true
    }

    /// A steady cover packet, `0x05 0x01` (never answered, §B.1). Never
    /// ack-tracked and outside the cover-request hourly cap (§B.3). It also
    /// stands for one due reply to the peer's cover requests.
    fn steady_send_cover(&mut self, peer: &str) -> Result<(), RChatError> {
        self.check_sendable(peer)?;
        if !self.transport_usable() {
            return Err(RChatError::NotConnected);
        }
        let mut id = [0u8; 16];
        OsRng.fill_bytes(&mut id);
        let packet = self.seal_ratchet(peer, id, &[COVER_TYPE, COVER_REPLY])?;
        self.send_now(packet.encode_with_frame_type())?;
        let now = Instant::now();
        if let Some(i) = self
            .cover_replies_due
            .iter()
            .position(|(p, at)| p == peer && *at <= now)
        {
            self.cover_replies_due.remove(i);
        }
        Ok(())
    }
}

/// The slot timer: a dedicated interval at the slot length, started by the
/// shared tick only while `steady_should_run` holds. Missed ticks are
/// delayed, never burst to catch up (after a stall or a suspend). It ends
/// when steady should no longer run or its setting changed (`gen`).
pub(crate) fn spawn_steady(
    weak: std::sync::Weak<tokio::sync::RwLock<ClientInner>>,
    gen: u64,
    slot: Duration,
) {
    tokio::spawn(async move {
        let mut timer = tokio::time::interval_at(tokio::time::Instant::now() + slot, slot);
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            timer.tick().await;
            let Some(inner) = weak.upgrade() else { break };
            let mut guard = inner.write().await;
            if guard.steady_task_gen != gen {
                break; // a newer setting owns the timer now
            }
            if !guard.steady_should_run() {
                guard.steady_task_running = false;
                break;
            }
            let _ = guard.fire_steady_slot(std::time::Instant::now());
            guard.flush_deferred_writes();
        }
    });
}

#[cfg(test)]
mod tests;
