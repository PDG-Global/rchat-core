//! Background delivery (protocol v3 §H.1): a short connection that only
//! receives.
//!
//! While iOS lets the app run in the background for a moment, it connects,
//! proves its identity (publish), takes the relay's offline-queue drain and
//! any knocks, hands each to the app, waits until the app has stored them
//! (`mark_message_seen`, spec §18.7 D36), and disconnects.
//!
//! The drain is a mode of the client, not a second client: while it is on,
//! nothing but signaling (the hello and the publish) leaves the device.
//! No circuit asks (identity or blind, §C), no resumes, no closes, no cover
//! or steady traffic (§B), no receipts and no queued sends. What the drain
//! would have sent waits for the next foreground connection: delivered
//! receipts stay owed in the peer records (persisted), asks stay deferred,
//! closes stay pending.
//!
//! It ends on the relay's `QueueHandedOver` marker (ruling R34a), sent on
//! the same connection after every queued record: once the marker has
//! been handled, every queued frame before it has been too (one socket,
//! one ordered event queue). A short grace after it catches packets the
//! relay forwarded live. Only if no marker comes does a byte-level quiet
//! window end it (bytes, never whole frames: a large frame still arriving
//! keeps it open).

use crate::{ClientInner, RChatClient, RChatError};
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// After the marker: no frame and no byte for this long (live forwards).
pub const DRAIN_MARKER_GRACE: Duration = Duration::from_millis(300);

/// How long after the publish a drain waits for the marker before the
/// byte-level fallback may end it.
pub const DRAIN_MARKER_WAIT: Duration = Duration::from_secs(6);

/// The fallback's quiet window: no byte at all for this long.
pub const DRAIN_QUIET: Duration = Duration::from_millis(1500);

/// The longest drain the core runs, whatever the caller asks: iOS gives a
/// background refresh about 30 s in all (the app asks for 20 s).
pub const DRAIN_MAX: Duration = Duration::from_secs(25);

/// The shortest drain the core runs (a connect and a publish need it).
pub const DRAIN_MIN: Duration = Duration::from_secs(1);

/// The connect phase's share of the budget (R34 I-2): one attempt, no
/// reconnects, at most this long.
pub const DRAIN_CONNECT_MAX: Duration = Duration::from_secs(8);

/// After giving up a connect: how long to look for its result.
const GIVE_UP_SETTLE: Duration = Duration::from_millis(150);

/// How often the wait checks the drain's progress.
const DRAIN_POLL: Duration = Duration::from_millis(25);

/// How long the end of a drain waits for queued callbacks to reach the app.
const DRAIN_CALLBACK_FLUSH: Duration = Duration::from_secs(2);

/// The same, when the drain was cancelled (R34 M-3): the task expires soon.
const DRAIN_CALLBACK_FLUSH_CANCELLED: Duration = Duration::from_millis(200);

/// One background drain's progress (memory only; one per connection).
#[derive(Debug)]
pub(crate) struct DrainState {
    /// When the publish on the drain's connection was accepted.
    pub(crate) published_at: Option<Instant>,
    /// When the relay's `QueueHandedOver` marker was handled (R34a).
    pub(crate) handed_over_at: Option<Instant>,
    /// When the last frame was handled (or the drain began).
    pub(crate) last_activity: Instant,
    /// Messages, files and requests handed to the app on this drain.
    pub(crate) delivered: u32,
    /// (sender, id) handed to the app and not yet confirmed stored.
    pub(crate) awaiting: HashSet<(String, [u8; 16])>,
    /// A protocol failure that ended the drain's connection.
    pub(crate) failure: Option<String>,
    /// The drain's connect attempt was given up (cancel or deadline): the
    /// state stays, so a `connect()` that takes the lock late refuses
    /// instead of making a normal connection (round 2 N-1). Cleared by that
    /// connect. Nothing but signaling leaves meanwhile.
    pub(crate) aborted: bool,
    /// The connect phase's timeout (one attempt, R34 I-2).
    pub(crate) connect_secs: u32,
    /// Tests: shorter windows.
    pub(crate) grace: Duration,
    pub(crate) marker_wait: Duration,
    pub(crate) quiet: Duration,
}

/// Where a drain stands.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum DrainProgress {
    /// Not published yet, still receiving, or waiting for the app.
    Waiting,
    /// Everything received and stored: the count of items handed over.
    Complete(u32),
    /// The connection failed for good (relay identity, key auth...).
    Failed(String),
}

/// How a drain with its own connect ended (`RChatClient::drain_connecting`).
#[derive(Debug)]
pub(crate) enum DrainEnd {
    /// Connected and drained (fully, or until cancelled or the deadline
    /// after the publish): the count of items handed over.
    Drained(u32),
    /// The connect itself returned an error: nothing was drained, drain
    /// mode is off and the client is as it was.
    NotConnected(RChatError),
    /// The connect was given up (cancel or deadline) while still running:
    /// a late finish is refused or dropped (round 2 N-1, N-3).
    GaveUp(RChatError),
    /// Connected, but the drain failed (relay identity, key auth, no
    /// publish in time).
    Failed(RChatError),
}

impl ClientInner {
    /// Enter drain mode (before the connect that will drain). The connect
    /// gets `connect_secs` and one attempt.
    #[cfg(test)]
    pub(crate) fn begin_drain(&mut self, now: Instant) {
        self.begin_drain_with(now, DRAIN_CONNECT_MAX.as_secs() as u32);
    }

    pub(crate) fn begin_drain_with(&mut self, now: Instant, connect_secs: u32) {
        self.drain = Some(DrainState {
            published_at: None,
            handed_over_at: None,
            last_activity: now,
            delivered: 0,
            awaiting: HashSet::new(),
            failure: None,
            aborted: false,
            connect_secs: connect_secs.max(1),
            grace: DRAIN_MARKER_GRACE,
            marker_wait: DRAIN_MARKER_WAIT,
            quiet: DRAIN_QUIET,
        });
    }

    /// Drain mode is on: only signaling may leave.
    pub(crate) fn in_drain(&self) -> bool {
        self.drain.is_some()
    }

    /// A frame was handled: the grace and quiet windows start again.
    pub(crate) fn drain_note_activity(&mut self, now: Instant) {
        if let Some(d) = self.drain.as_mut() {
            d.last_activity = now;
        }
    }

    /// The publish on the drain's connection was accepted.
    pub(crate) fn drain_note_published(&mut self, now: Instant) {
        if let Some(d) = self.drain.as_mut() {
            d.published_at = Some(now);
            d.last_activity = now;
        }
    }

    /// The relay's `QueueHandedOver` (R34a). Only after a publish on this
    /// connection (the frame gate already holds back anything earlier).
    /// Outside a drain it changes nothing.
    pub(crate) fn drain_note_handed_over(&mut self, now: Instant) {
        if let Some(d) = self.drain.as_mut() {
            if d.published_at.is_some() {
                d.handed_over_at.get_or_insert(now);
            }
        }
    }

    /// A message or file went to the app: counted, and awaited until the
    /// app confirms it stored it.
    pub(crate) fn drain_note_delivered(&mut self, sender_hex: &str, id: [u8; 16]) {
        if let Some(d) = self.drain.as_mut() {
            d.delivered += 1;
            d.awaiting.insert((sender_hex.to_lowercase(), id));
        }
    }

    /// A message request went to the app: counted (nothing to confirm).
    pub(crate) fn drain_note_request(&mut self) {
        if let Some(d) = self.drain.as_mut() {
            d.delivered += 1;
        }
    }

    /// The app confirmed `id` from `sender_hex` stored (or dropped on purpose).
    pub(crate) fn drain_note_stored(&mut self, sender_hex: &str, id: [u8; 16]) {
        if let Some(d) = self.drain.as_mut() {
            d.awaiting.remove(&(sender_hex.to_lowercase(), id));
        }
    }

    /// The drain's connection failed for good.
    pub(crate) fn drain_note_failure(&mut self, err: &RChatError) {
        if let Some(d) = self.drain.as_mut() {
            d.failure.get_or_insert_with(|| err.to_string());
        }
    }

    /// Where the drain stands at `now`, with the socket's byte clock.
    pub(crate) fn drain_progress(&self, now: Instant) -> DrainProgress {
        let bytes_at = self.websocket.as_ref().and_then(|w| w.last_bytes_at());
        self.drain_progress_at(now, bytes_at)
    }

    /// `drain_progress` with the last time any byte arrived (`bytes_at`).
    pub(crate) fn drain_progress_at(
        &self,
        now: Instant,
        bytes_at: Option<Instant>,
    ) -> DrainProgress {
        let Some(d) = self.drain.as_ref() else {
            return DrainProgress::Waiting;
        };
        if let Some(f) = &d.failure {
            return DrainProgress::Failed(f.clone());
        }
        let Some(published) = d.published_at else {
            return DrainProgress::Waiting;
        };
        // The latest sign of life: a handled frame, or any byte read.
        let alive = bytes_at.map_or(d.last_activity, |b| b.max(d.last_activity));
        let quiet_for = now.saturating_duration_since(alive);
        let ended = match d.handed_over_at {
            // Everything queued was handled before the marker; a short
            // grace for live forwards.
            Some(marker) => {
                now.saturating_duration_since(marker) >= d.grace && quiet_for >= d.grace
            }
            // No marker (yet): only after waiting for it, and only once no
            // byte has arrived for the quiet window.
            None => {
                now.saturating_duration_since(published) >= d.marker_wait && quiet_for >= d.quiet
            }
        };
        if ended && d.awaiting.is_empty() {
            DrainProgress::Complete(d.delivered)
        } else {
            DrainProgress::Waiting
        }
    }

    /// End the drain: what it owes is written (owed receipts stay in the
    /// peer records for the next foreground connection), the transport is
    /// taken and drain mode ends in the same step, so nothing can leave in
    /// between. Returns the transport to shut down and the count.
    pub(crate) fn end_drain(&mut self) -> (Option<crate::transport::WebSocketClient>, u32) {
        let owed: Vec<String> = self
            .pending_receipts
            .iter()
            .filter(|(_, ids)| !ids.is_empty())
            .map(|((peer, _), _)| peer.clone())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        for peer in owed {
            let _ = self.persist_peer(&peer);
        }
        self.flush_deferred_writes();
        let ws = self.websocket.take();
        self.set_connected(false);
        self.is_key_bundle_published = false;
        self.retire_connection();
        self.publish_requested = false;
        let count = self.drain.take().map_or(0, |d| d.delivered);
        (ws, count)
    }

    /// The shared timer's work (every `TICK_INTERVAL`). True when queued
    /// sends should be flushed after the lock is released.
    pub(crate) fn tick(&mut self, now: Instant) -> bool {
        self.purge_stale(now);
        self.retry_held();
        self.fire_ack_expiry(now);
        self.flush_deferred_writes();
        if self.in_drain() {
            // Nothing that sends: re-asks, receipts, cover, notices and
            // queued messages all wait for the next foreground connection.
            return false;
        }
        self.fire_due_reasks(now);
        self.fire_due_receipts(now);
        self.fire_cover(now);
        self.redrive_owed_sends(now);
        true
    }
}

impl RChatClient {
    /// Background delivery (§H.1) on this client: connect (one attempt,
    /// bounded, racing `cancel`), publish, take the offline queue and
    /// knocks, hand them to the app, wait until the app stored them, then
    /// drop the transport (the client, with its sessions, stays for the
    /// next foreground connection). Nothing but signaling leaves.
    ///
    /// Refused with `ForegroundConnected` while this client is connected:
    /// a connected client already receives the queue itself, and the drain
    /// never takes its connection over. `timeout` is clamped to
    /// `DRAIN_MIN..=DRAIN_MAX`; `cancel` ends the drain early (the iOS
    /// expiration handler), keeping what was stored. Returns the number of
    /// messages, files and requests handed to the app.
    pub fn background_drain(
        self: &Arc<Self>,
        timeout: Duration,
        cancel: &AtomicBool,
    ) -> Result<u32, RChatError> {
        if self.connected_now() {
            return Err(RChatError::ForegroundConnected);
        }
        let deadline = Instant::now() + timeout.clamp(DRAIN_MIN, DRAIN_MAX);
        match self.drain_connecting(deadline, &|| cancel.load(Ordering::SeqCst)) {
            DrainEnd::Drained(n) => Ok(n),
            DrainEnd::NotConnected(e) | DrainEnd::GaveUp(e) | DrainEnd::Failed(e) => Err(e),
        }
    }

    /// The connected mirror, read without the client lock.
    pub(crate) fn connected_now(&self) -> bool {
        self.connected_mirror.load(Ordering::SeqCst)
    }

    /// The connect phase's timeout for a drain ending at `deadline`: at
    /// most `DRAIN_CONNECT_MAX`, and at most 40% of what is left, so the
    /// drain itself keeps most of the budget.
    pub(crate) fn drain_connect_secs(deadline: Instant) -> u32 {
        let left = deadline.saturating_duration_since(Instant::now());
        (left.mul_f32(0.4).min(DRAIN_CONNECT_MAX).as_secs() as u32).max(1)
    }

    /// Drain mode on (before the drain's connect). A transport still
    /// trying to reconnect on its own is replaced by the drain's.
    pub(crate) fn begin_drain_now(&self, deadline: Instant) -> Result<(), RChatError> {
        let connect_secs = Self::drain_connect_secs(deadline);
        let inner = self.inner.clone();
        crate::block_on_async(self.runtime.clone(), move || async move {
            let mut guard = inner.write().await;
            guard.begin_drain_with(Instant::now(), connect_secs);
            let ws = guard.websocket.take();
            if ws.is_some() {
                guard.set_connected(false);
                guard.is_key_bundle_published = false;
                guard.retire_connection();
            }
            drop(guard);
            if let Some(ws) = ws {
                ws.disconnect().await;
            }
            Ok(())
        })
    }

    /// Begin, connect and drain (R34 I-2). The connect runs on its own
    /// thread and races `cancelled()` and the deadline: either ends the
    /// wait at once, retiring the attempt (its connection, if it still
    /// opens, is dropped) and leaving drain mode. Never waits on the
    /// network past the connect timeout, never more than once.
    pub(crate) fn drain_connecting(
        self: &Arc<Self>,
        deadline: Instant,
        cancelled: &dyn Fn() -> bool,
    ) -> DrainEnd {
        if let Err(e) = self.begin_drain_now(deadline) {
            self.leave_drain();
            return DrainEnd::NotConnected(e);
        }
        let (tx, rx) = std::sync::mpsc::channel();
        let connecting = self.clone();
        std::thread::spawn(move || {
            let _ = tx.send(connecting.connect());
        });
        loop {
            match rx.recv_timeout(DRAIN_POLL) {
                Ok(Ok(())) => break,
                Ok(Err(e)) => {
                    self.leave_drain();
                    return DrainEnd::NotConnected(e);
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    self.leave_drain();
                    return DrainEnd::NotConnected(RChatError::Internal {
                        message: "drain connect thread ended".into(),
                    });
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    if cancelled() || Instant::now() >= deadline {
                        self.give_up_drain_connect();
                        // A connect that finished just as it was given up
                        // can't clear the mark itself: done here.
                        if rx.recv_timeout(GIVE_UP_SETTLE).is_ok() {
                            self.clear_aborted_drain();
                        }
                        return DrainEnd::GaveUp(RChatError::ConnectionFailed {
                            message: "background drain ended before its connect".into(),
                        });
                    }
                }
            }
        }
        match self.finish_drain(deadline, cancelled) {
            Ok(n) => DrainEnd::Drained(n),
            Err(e) => DrainEnd::Failed(e),
        }
    }

    /// Wait for the drain to complete (or fail, time out or be cancelled),
    /// then end it.
    pub(crate) fn finish_drain(
        &self,
        deadline: Instant,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<u32, RChatError> {
        let mut was_cancelled = false;
        let outcome = loop {
            // Never waits for a busy lock: busy means still working.
            let progress = self
                .inner
                .try_read()
                .map_or(DrainProgress::Waiting, |i| i.drain_progress(Instant::now()));
            match progress {
                DrainProgress::Complete(_) => break Ok(()),
                DrainProgress::Failed(f) => break Err(RChatError::ConnectionFailed { message: f }),
                DrainProgress::Waiting => {}
            }
            was_cancelled = cancelled();
            if was_cancelled || Instant::now() >= deadline {
                // Whatever was stored stays stored; anything handed over
                // but unconfirmed is reported to the sender's recovery.
                let inner = self.inner.clone();
                let published = crate::block_on_async(self.runtime.clone(), move || async move {
                    let guard = inner.read().await;
                    Ok(guard
                        .drain
                        .as_ref()
                        .is_some_and(|d| d.published_at.is_some()))
                })?;
                break if published {
                    Ok(())
                } else {
                    Err(RChatError::ConnectionFailed {
                        message: "background drain ended before the publish".into(),
                    })
                };
            }
            std::thread::sleep(DRAIN_POLL);
        };
        let count = self.end_drain_now()?;
        // Every call queued for the app (the last message, a request) is
        // delivered before the caller hears the drain ended; briefly when
        // cancelled, so the app can still persist before the task expires.
        let flush = if was_cancelled {
            DRAIN_CALLBACK_FLUSH_CANCELLED
        } else {
            let left = deadline.saturating_duration_since(Instant::now());
            left.max(Duration::from_millis(200))
                .min(DRAIN_CALLBACK_FLUSH)
        };
        self.callback_hub.flush(flush);
        outcome.map(|()| count)
    }

    /// `end_drain`, then the transport shut down without the lock and the
    /// app told it is disconnected.
    fn end_drain_now(&self) -> Result<u32, RChatError> {
        let inner = self.inner.clone();
        crate::block_on_async(self.runtime.clone(), move || async move {
            let mut guard = inner.write().await;
            let (ws, count) = guard.end_drain();
            if let Some(cb) = &guard.callbacks {
                cb.on_connection_status_changed(crate::ConnectionStatus::Disconnected);
            }
            drop(guard);
            if let Some(ws) = ws {
                ws.disconnect().await;
            }
            Ok(count)
        })
    }

    /// The connect attempt is given up: the drain state stays, marked
    /// aborted, so a `connect()` that still takes the lock refuses, and one
    /// already on the network (one attempt, no reconnect) is dropped by the
    /// retired generation; either clears the state.
    fn give_up_drain_connect(&self) {
        let inner = self.inner.clone();
        let _ = crate::block_on_async(self.runtime.clone(), move || async move {
            let mut guard = inner.write().await;
            if let Some(d) = guard.drain.as_mut() {
                d.aborted = true;
            }
            guard.retire_connection();
            let ws = guard.websocket.take();
            guard.set_connected(false);
            guard.is_key_bundle_published = false;
            drop(guard);
            if let Some(ws) = ws {
                ws.disconnect().await;
            }
            Ok(())
        });
    }

    /// An aborted drain state nobody else will clear (its connect already
    /// returned): drain mode off.
    fn clear_aborted_drain(&self) {
        let inner = self.inner.clone();
        let _ = crate::block_on_async(self.runtime.clone(), move || async move {
            let mut guard = inner.write().await;
            if guard.drain.as_ref().is_some_and(|d| d.aborted) {
                guard.drain = None;
            }
            Ok(())
        });
    }

    /// Drain mode off without a drain (its connect failed): the attempt is
    /// retired, so a connection it still opens is dropped.
    fn leave_drain(&self) {
        let inner = self.inner.clone();
        let _ = crate::block_on_async(self.runtime.clone(), move || async move {
            let mut guard = inner.write().await;
            guard.drain = None;
            guard.retire_connection();
            let ws = guard.websocket.take();
            guard.set_connected(false);
            guard.is_key_bundle_published = false;
            drop(guard);
            if let Some(ws) = ws {
                ws.disconnect().await;
            }
            Ok(())
        });
    }
}

#[cfg(test)]
mod tests;
