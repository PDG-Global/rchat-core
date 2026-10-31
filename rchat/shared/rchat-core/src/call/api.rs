//! The app's call API on `RChatClient` (spec §6 "API"). Signalling calls
//! take the client lock like any send; PCM and polling never do: PCM goes
//! through `CallAudioHandle`, which holds only the call's own audio slot
//! (D37).

use super::machine::{MediaControl, VideoPrefs};
use super::video::engine::{EncoderHint, TakenFrame, VideoControl};
use super::video::frag::TooSmall;
use super::{unix_ms, CallId};
use crate::{block_on_async, RChatClient, RChatError};
use parking_lot::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

/// The audio side of the current call, for the app's audio thread (D37):
/// the call's media slot and mute flag only. It never takes the client
/// lock; each call takes the slot's own mutex just long enough to clone
/// the media handle.
#[derive(Clone)]
pub struct CallAudioHandle {
    audio: Arc<Mutex<Option<Arc<dyn MediaControl>>>>,
    muted: Arc<AtomicBool>,
}

impl CallAudioHandle {
    pub(crate) fn new(
        audio: Arc<Mutex<Option<Arc<dyn MediaControl>>>>,
        muted: Arc<AtomicBool>,
    ) -> Self {
        Self { audio, muted }
    }

    /// One 20 ms frame of captured PCM (960 samples); 960 taken, or 0.
    pub fn push_pcm(&self, pcm: &[i16]) -> usize {
        let media = self.audio.lock().clone();
        media.map_or(0, |m| m.push_pcm(pcm))
    }

    /// One 20 ms frame to play (960 samples); silence and 0 without a call.
    pub fn pull_pcm(&self, out: &mut [i16]) -> usize {
        let media = self.audio.lock().clone();
        match media {
            Some(m) => m.pull_pcm(out),
            None => {
                out.fill(0);
                0
            }
        }
    }

    /// Mute (kept until the call ends; applied to media started later).
    pub fn set_muted(&self, muted: bool) {
        self.muted.store(muted, Ordering::SeqCst);
        // The slot's lock is released before the media is touched; the flag
        // is applied until stable, so a racing call start can't leave the
        // media unmuted under a muted flag (`machine::apply_mute`).
        let media = self.audio.lock().clone();
        if let Some(m) = media {
            super::machine::apply_mute(&self.muted, m.as_ref());
        }
    }
}

/// The video side of the current call, for the app's camera, encoder and
/// decoder threads: the call's video slot and the video prefs only, never
/// the client lock. Without a call each returns 0, `None` or an inactive
/// hint.
#[derive(Clone)]
pub struct CallVideoHandle {
    video: Arc<Mutex<Option<Arc<dyn VideoControl>>>>,
    prefs: Arc<VideoPrefs>,
}

impl CallVideoHandle {
    pub(crate) fn new(
        video: Arc<Mutex<Option<Arc<dyn VideoControl>>>>,
        prefs: Arc<VideoPrefs>,
    ) -> Self {
        Self { video, prefs }
    }

    fn media(&self) -> Option<Arc<dyn VideoControl>> {
        self.video.lock().clone()
    }

    /// One encoded frame: fragments queued, 0 when not sending, -9 bad input.
    pub fn send_frame(&self, data: &[u8], keyframe: bool, rotation_deg: u16) -> i32 {
        self.media().map_or(0, |m| {
            m.send_frame(data, keyframe, rotation_deg, Instant::now())
        })
    }

    /// The next complete frame into `out`, if any.
    pub fn take(&self, out: &mut [u8]) -> Result<Option<TakenFrame>, TooSmall> {
        match self.media() {
            Some(m) => m.take(out, Instant::now()),
            None => Ok(None),
        }
    }

    pub fn encoder_hint(&self) -> EncoderHint {
        self.media().map_or(
            EncoderHint {
                generation: 0,
                width: 0,
                height: 0,
                fps: 0,
                bitrate: 0,
                keyframe: false,
                active: false,
            },
            |m| m.encoder_hint(),
        )
    }

    /// The encoder hint when a call has video media; None without one.
    pub fn encoder_hint_if_media(&self) -> Option<EncoderHint> {
        self.media().map(|m| m.encoder_hint())
    }

    /// Set this client's Caps prefs (the FFI calls it under its video lock).
    pub fn configure(&self, codec_mask: u8, want_1080: bool, software_encoder: bool) {
        self.prefs.set(codec_mask, want_1080, software_encoder);
    }

    /// The app's decoder failed: ask for a keyframe.
    pub fn need_keyframe(&self) {
        if let Some(m) = self.media() {
            m.need_keyframe(Instant::now());
        }
    }

    /// `PowerManager` thermal status, 0-6 (kept for video started later).
    pub fn set_thermal(&self, level: u8) {
        self.prefs.set_thermal(level);
        if let Some(m) = self.media() {
            m.set_thermal(level);
        }
    }
}

fn call_id(hex: &str) -> Result<CallId, RChatError> {
    CallId::from_hex(&hex.to_lowercase()).ok_or(RChatError::InvalidParameter {
        message: "call id".into(),
    })
}

impl RChatClient {
    /// Place a call to an accepted contact; the new call's id (32 hex).
    pub fn call_place(&self, peer_hex: String) -> Result<String, RChatError> {
        let inner = self.inner.clone();
        block_on_async(self.runtime.clone(), move || async move {
            let peer = peer_hex.to_lowercase();
            inner
                .write()
                .await
                .call_place(&peer, Instant::now(), unix_ms())
                .map(|id| id.hex())
        })
    }

    /// Place a video call from the chat header (R18); the new call's id.
    pub fn call_place_video(&self, peer_hex: String) -> Result<String, RChatError> {
        let inner = self.inner.clone();
        block_on_async(self.runtime.clone(), move || async move {
            let peer = peer_hex.to_lowercase();
            inner
                .write()
                .await
                .call_place_video(&peer, Instant::now(), unix_ms())
                .map(|id| id.hex())
        })
    }

    /// My camera on or off in the current call (R17).
    pub fn call_video_set_camera(&self, on: bool) -> Result<(), RChatError> {
        let inner = self.inner.clone();
        block_on_async(self.runtime.clone(), move || async move {
            inner
                .write()
                .await
                .call_video_set_camera(on, Instant::now())
        })
    }

    /// Accept (true) or Not now (false) for the peer's video request.
    pub fn call_video_respond(&self, accept: bool) -> Result<(), RChatError> {
        let inner = self.inner.clone();
        block_on_async(self.runtime.clone(), move || async move {
            inner
                .write()
                .await
                .call_video_respond(accept, Instant::now())
        })
    }

    /// This client's video Caps for the next call: codec mask (bit0 H.265,
    /// bit1 H.264), 1080p wanted, software encoder.
    pub fn call_video_configure(&self, codec_mask: u8, want_1080: bool, software_encoder: bool) {
        self.call_video_prefs
            .set(codec_mask, want_1080, software_encoder);
    }

    /// Adopt the process-wide video prefs the app set before this client
    /// existed (`rchat_call_video_configure` / `_set_thermal` with no client).
    pub fn call_video_adopt_prefs(&self, prefs: &VideoPrefs) {
        self.call_video_prefs.copy_from(prefs);
    }

    /// (codec mask, 1080p wanted, software encoder, thermal level).
    pub fn call_video_prefs_snapshot(&self) -> (u8, bool, bool, u8) {
        self.call_video_prefs.snapshot()
    }

    /// The call's video handle, for threads that must not wait on the
    /// client. Valid for this client's whole life.
    pub fn call_video_handle(&self) -> CallVideoHandle {
        CallVideoHandle::new(self.call_video.clone(), self.call_video_prefs.clone())
    }

    pub fn call_answer(&self, call_id_hex: String) -> Result<(), RChatError> {
        let id = call_id(&call_id_hex)?;
        let inner = self.inner.clone();
        block_on_async(self.runtime.clone(), move || async move {
            inner
                .write()
                .await
                .call_answer(id, Instant::now(), unix_ms())
        })
    }

    pub fn call_decline(&self, call_id_hex: String, busy: bool) -> Result<(), RChatError> {
        let id = call_id(&call_id_hex)?;
        let inner = self.inner.clone();
        block_on_async(self.runtime.clone(), move || async move {
            inner.write().await.call_decline(id, busy, unix_ms())
        })
    }

    pub fn call_end(&self, call_id_hex: String) -> Result<(), RChatError> {
        let id = call_id(&call_id_hex)?;
        let inner = self.inner.clone();
        block_on_async(self.runtime.clone(), move || async move {
            inner.write().await.call_end(id, Instant::now(), unix_ms())
        })
    }

    /// The call's audio handle, for an audio thread that must not wait on
    /// the client (D37). Valid for this client's whole life.
    pub fn call_audio_handle(&self) -> CallAudioHandle {
        CallAudioHandle::new(self.call_audio.clone(), self.call_muted.clone())
    }

    /// Mute (kept until the call ends; applied to media started later).
    pub fn call_set_muted(&self, muted: bool) {
        self.call_audio_handle().set_muted(muted)
    }

    /// One 20 ms frame of captured PCM (960 samples); 960 taken, or 0.
    pub fn call_push_pcm(&self, pcm: &[i16]) -> usize {
        self.call_audio_handle().push_pcm(pcm)
    }

    /// One 20 ms frame to play (960 samples); silence and 0 without a call.
    pub fn call_pull_pcm(&self, out: &mut [i16]) -> usize {
        self.call_audio_handle().pull_pcm(out)
    }

    /// The next call event as JSON, or None (D19).
    pub fn call_poll_event(&self) -> Option<String> {
        self.call_events.lock().pop_front().map(|e| e.to_json())
    }
}
