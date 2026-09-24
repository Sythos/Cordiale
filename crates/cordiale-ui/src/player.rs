// MIT License
//
// Copyright (c) 2026 Sythos
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

//! The integrated radio player: an MP3 or Ogg Vorbis HTTP stream decoded
//! with rodio, the same on every platform.
//!
//! Three threads per tuned station: the network thread reads the stream
//! (splitting off ICY titles), the decoder thread turns bytes into samples,
//! and rodio's output pulls those samples, playing silence rather than
//! blocking when the network falls behind. Tuning another station or
//! stopping drops the channels, which winds the threads down.

use std::io::{Read, Seek, SeekFrom};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError};
use std::sync::{Arc, Mutex};
use std::thread;

use cordiale_core::radio::{IcyChunk, RadioStream};
use rodio::{ChannelCount, Sample, SampleRate, Source};

/// What the player reports; `generation` names the tune it belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlayerEvent {
    Playing,
    /// A track title carried by the stream itself (ICY metadata).
    Title(String),
    /// The stream couldn't be opened, decoded or played.
    Failed(String),
    /// The server ended the stream.
    Ended,
}

enum Command {
    Play {
        url: String,
        hint: &'static str,
        generation: u64,
    },
    Stop,
    Volume(f32),
}

/// Handle to the audio thread, which owns the output device.
pub struct RadioPlayer {
    commands: mpsc::Sender<Command>,
}

impl RadioPlayer {
    /// Starts the audio thread; `on_event` runs on the player's threads.
    pub fn spawn(on_event: impl Fn(u64, PlayerEvent) + Send + Sync + 'static) -> Self {
        let (commands, rx) = mpsc::channel();
        let on_event: Arc<dyn Fn(u64, PlayerEvent) + Send + Sync> = Arc::new(on_event);
        thread::spawn(move || audio_thread(rx, on_event));
        Self { commands }
    }

    /// Tunes `url`; `hint` is the decoder's format hint (`mp3` or `ogg`).
    pub fn play(&self, url: &str, hint: &'static str, generation: u64) {
        let _ = self.commands.send(Command::Play {
            url: url.to_string(),
            hint,
            generation,
        });
    }

    pub fn stop(&self) {
        let _ = self.commands.send(Command::Stop);
    }

    /// `volume` from 0.0 (silent) to 1.0.
    pub fn set_volume(&self, volume: f32) {
        let _ = self.commands.send(Command::Volume(volume.clamp(0.0, 1.0)));
    }
}

type EventSink = Arc<dyn Fn(u64, PlayerEvent) + Send + Sync>;

fn audio_thread(commands: Receiver<Command>, on_event: EventSink) {
    let mut device: Option<rodio::MixerDeviceSink> = None;
    let mut current: Option<(Arc<rodio::Player>, Arc<AtomicBool>)> = None;
    let mut volume = 1.0;
    for command in commands {
        match command {
            Command::Play {
                url,
                hint,
                generation,
            } => {
                stop_current(&mut current);
                if device.is_none() {
                    match rodio::DeviceSinkBuilder::open_default_sink() {
                        Ok(mut sink) => {
                            sink.log_on_drop(false);
                            device = Some(sink);
                        }
                        Err(err) => {
                            on_event(generation, PlayerEvent::Failed(err.to_string()));
                            continue;
                        }
                    }
                }
                let Some(sink) = device.as_ref() else {
                    continue;
                };
                let player = Arc::new(rodio::Player::connect_new(sink.mixer()));
                player.set_volume(volume);
                let cancelled = Arc::new(AtomicBool::new(false));
                start_stream(
                    url,
                    hint,
                    generation,
                    Arc::clone(&player),
                    Arc::clone(&cancelled),
                    Arc::clone(&on_event),
                );
                current = Some((player, cancelled));
            }
            Command::Stop => stop_current(&mut current),
            Command::Volume(value) => {
                volume = value;
                if let Some((player, _)) = &current {
                    player.set_volume(volume);
                }
            }
        }
    }
}

fn stop_current(current: &mut Option<(Arc<rodio::Player>, Arc<AtomicBool>)>) {
    if let Some((player, cancelled)) = current.take() {
        cancelled.store(true, Ordering::Relaxed);
        player.stop();
    }
}

/// Stream bytes buffered between the network and the decoder (chunks as
/// the server sends them), and decoded sample blocks between the decoder
/// and the output: a few seconds each, so a slow network or a busy decoder
/// holds the other back instead of growing memory.
const BYTE_CHUNKS: usize = 256;
const SAMPLE_BLOCKS: usize = 64;
/// Frames per decoded block handed to the output.
const BLOCK_FRAMES: usize = 1024;

fn start_stream(
    url: String,
    hint: &'static str,
    generation: u64,
    player: Arc<rodio::Player>,
    cancelled: Arc<AtomicBool>,
    on_event: EventSink,
) {
    let (bytes_tx, bytes_rx) = mpsc::sync_channel::<Vec<u8>>(BYTE_CHUNKS);
    let network_cancelled = Arc::clone(&cancelled);
    let network_events = Arc::clone(&on_event);
    thread::spawn(move || {
        network_thread(url, generation, bytes_tx, network_cancelled, network_events)
    });
    thread::spawn(move || {
        decoder_thread(hint, generation, bytes_rx, player, cancelled, on_event);
    });
}

fn network_thread(
    url: String,
    generation: u64,
    bytes: SyncSender<Vec<u8>>,
    cancelled: Arc<AtomicBool>,
    on_event: EventSink,
) {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => {
            on_event(generation, PlayerEvent::Failed(err.to_string()));
            return;
        }
    };
    runtime.block_on(async {
        let mut stream = match RadioStream::open(&url).await {
            Ok(stream) => stream,
            Err(err) => {
                on_event(generation, PlayerEvent::Failed(err.to_string()));
                return;
            }
        };
        loop {
            if cancelled.load(Ordering::Relaxed) {
                return;
            }
            match stream.next().await {
                Ok(Some(chunks)) => {
                    for chunk in chunks {
                        match chunk {
                            // Blocks while the decoder is behind: this
                            // runtime runs nothing else.
                            IcyChunk::Audio(audio) => {
                                if bytes.send(audio).is_err() {
                                    return;
                                }
                            }
                            IcyChunk::Title(title) => {
                                on_event(generation, PlayerEvent::Title(title));
                            }
                        }
                    }
                }
                Ok(None) => {
                    on_event(generation, PlayerEvent::Ended);
                    return;
                }
                Err(err) => {
                    if !cancelled.load(Ordering::Relaxed) {
                        on_event(generation, PlayerEvent::Failed(err.to_string()));
                    }
                    return;
                }
            }
        }
    });
}

fn decoder_thread(
    hint: &'static str,
    generation: u64,
    bytes: Receiver<Vec<u8>>,
    player: Arc<rodio::Player>,
    cancelled: Arc<AtomicBool>,
    on_event: EventSink,
) {
    let reader = StreamReader::new(bytes);
    let decoder = match rodio::decoder::DecoderBuilder::new()
        .with_data(reader)
        .with_hint(hint)
        .with_seekable(false)
        .build()
    {
        Ok(decoder) => decoder,
        Err(err) => {
            if !cancelled.load(Ordering::Relaxed) {
                on_event(generation, PlayerEvent::Failed(err.to_string()));
            }
            return;
        }
    };
    let channels = decoder.channels();
    let sample_rate = decoder.sample_rate();
    let block_len = BLOCK_FRAMES * usize::from(channels.get());
    let (samples_tx, samples_rx) = mpsc::sync_channel::<Vec<Sample>>(SAMPLE_BLOCKS);
    player.append(LiveSource::new(samples_rx, channels, sample_rate));
    on_event(generation, PlayerEvent::Playing);

    let mut block = Vec::with_capacity(block_len);
    for sample in decoder {
        block.push(sample);
        if block.len() == block_len {
            if cancelled.load(Ordering::Relaxed)
                || samples_tx
                    .send(std::mem::replace(&mut block, Vec::with_capacity(block_len)))
                    .is_err()
            {
                return;
            }
        }
    }
    let _ = samples_tx.send(block);
}

/// The stream's bytes as a `Read` for the decoder. It can't seek; the
/// decoder is told so, and only asks where it is.
struct StreamReader {
    chunks: Mutex<Receiver<Vec<u8>>>,
    current: Vec<u8>,
    offset: usize,
    position: u64,
}

impl StreamReader {
    fn new(chunks: Receiver<Vec<u8>>) -> Self {
        Self {
            chunks: Mutex::new(chunks),
            current: Vec::new(),
            offset: 0,
            position: 0,
        }
    }
}

impl Read for StreamReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        while self.offset >= self.current.len() {
            let next = match self.chunks.lock() {
                Ok(chunks) => chunks.recv(),
                Err(_) => return Ok(0),
            };
            match next {
                Ok(chunk) => {
                    self.current = chunk;
                    self.offset = 0;
                }
                // The network side is gone: end of stream.
                Err(_) => return Ok(0),
            }
        }
        let count = buf.len().min(self.current.len() - self.offset);
        buf[..count].copy_from_slice(&self.current[self.offset..self.offset + count]);
        self.offset += count;
        self.position += count as u64;
        Ok(count)
    }
}

impl Seek for StreamReader {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        match pos {
            SeekFrom::Current(0) => Ok(self.position),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "a live stream can't seek",
            )),
        }
    }
}

/// Decoded blocks as a rodio source. When the decoder falls behind it
/// plays a frame of silence instead of waiting, so the output never
/// stalls; blocks are whole frames, so channels stay aligned.
struct LiveSource {
    blocks: Receiver<Vec<Sample>>,
    block: Vec<Sample>,
    offset: usize,
    silence_left: usize,
    channels: ChannelCount,
    sample_rate: SampleRate,
}

impl LiveSource {
    fn new(blocks: Receiver<Vec<Sample>>, channels: ChannelCount, sample_rate: SampleRate) -> Self {
        Self {
            blocks,
            block: Vec::new(),
            offset: 0,
            silence_left: 0,
            channels,
            sample_rate,
        }
    }
}

impl Iterator for LiveSource {
    type Item = Sample;

    fn next(&mut self) -> Option<Sample> {
        loop {
            if self.silence_left > 0 {
                self.silence_left -= 1;
                return Some(0.0);
            }
            if let Some(sample) = self.block.get(self.offset) {
                self.offset += 1;
                return Some(*sample);
            }
            match self.blocks.try_recv() {
                Ok(block) => {
                    self.block = block;
                    self.offset = 0;
                }
                Err(TryRecvError::Empty) => {
                    self.silence_left = usize::from(self.channels.get());
                }
                Err(TryRecvError::Disconnected) => return None,
            }
        }
    }
}

impl Source for LiveSource {
    fn current_span_len(&self) -> Option<usize> {
        None
    }

    fn channels(&self) -> ChannelCount {
        self.channels
    }

    fn sample_rate(&self) -> SampleRate {
        self.sample_rate
    }

    fn total_duration(&self) -> Option<std::time::Duration> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_reader_reads_chunks_in_order_and_ends() {
        let (tx, rx) = mpsc::sync_channel(4);
        tx.send(b"Og".to_vec()).unwrap();
        tx.send(b"gS".to_vec()).unwrap();
        drop(tx);
        let mut reader = StreamReader::new(rx);
        let mut all = Vec::new();
        reader.read_to_end(&mut all).unwrap();
        assert_eq!(all, b"OggS");
        assert_eq!(reader.seek(SeekFrom::Current(0)).unwrap(), 4);
        assert!(reader.seek(SeekFrom::Start(0)).is_err());
    }

    #[test]
    fn live_source_fills_gaps_with_whole_silent_frames() {
        let (tx, rx) = mpsc::sync_channel(4);
        let two = ChannelCount::new(2).unwrap();
        let rate = SampleRate::new(44_100).unwrap();
        let mut source = LiveSource::new(rx, two, rate);
        // Nothing decoded yet: one silent stereo frame.
        assert_eq!(source.next(), Some(0.0));
        assert_eq!(source.next(), Some(0.0));
        tx.send(vec![0.5, -0.5]).unwrap();
        assert_eq!(source.next(), Some(0.5));
        assert_eq!(source.next(), Some(-0.5));
        drop(tx);
        assert_eq!(source.next(), None);
    }
}
