//! Container readers for the in-app video player: MP4/MOV/M4V and WebM.
//!
//! Each reader finds the first video track and the sample list that the
//! decoder needs. WebM also gives the Opus or Vorbis packets. The readers only read
//! the headers and the sample tables; they never run code from the file, and
//! every length that the file gives is checked against the data.

/// Most samples a track may list. A longer table is refused.
const MAX_SAMPLES: usize = 2_000_000;

/// One coded video frame inside the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sample {
    pub offset: usize,
    pub size: usize,
    /// Presentation time in microseconds, from the start of the track.
    pub pts_us: i64,
    pub key: bool,
}

/// The video codec of a track, as far as the player has a decoder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VideoCodec {
    H264,
    Hevc,
    Vp8,
    Vp9,
    Av1,
    /// The track exists, but no decoder is built in for it.
    Other,
}

#[derive(Debug, Clone)]
pub struct VideoTrack {
    pub codec: VideoCodec,
    pub width: u32,
    pub height: u32,
    /// H.264 and HEVC: the parameter set NAL units from `avcC` or `hvcC`, in
    /// file order. AV1: the one configuration OBU block from `av1C`.
    pub parameter_sets: Vec<Vec<u8>>,
    /// H.264 and HEVC: bytes of the length field before each NAL unit in a
    /// sample.
    pub nal_length_size: usize,
    pub samples: Vec<Sample>,
}

/// The Vorbis audio of a WebM file. `headers` holds the identification and
/// the setup packets one after the other, as symphonia reads them.
#[derive(Debug, Clone)]
pub struct VorbisTrack {
    pub channels: usize,
    pub sample_rate: u32,
    pub headers: Vec<u8>,
    /// Packet position in the file, and its time in microseconds.
    pub packets: Vec<(usize, usize, i64)>,
}

/// The Opus audio of a WebM file.
#[derive(Debug, Clone)]
pub struct OpusTrack {
    pub channels: usize,
    pub pre_skip: usize,
    /// Packet position in the file, and its time in microseconds.
    pub packets: Vec<(usize, usize, i64)>,
}

#[derive(Debug, Clone, Default)]
pub struct WebmMedia {
    pub video: Option<VideoTrack>,
    pub audio: Option<OpusTrack>,
    pub vorbis: Option<VorbisTrack>,
    pub duration_us: Option<i64>,
}

fn be16(data: &[u8], at: usize) -> Option<u16> {
    let bytes = data.get(at..at.checked_add(2)?)?;
    Some(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn be32(data: &[u8], at: usize) -> Option<u32> {
    let bytes = data.get(at..at.checked_add(4)?)?;
    Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn be64(data: &[u8], at: usize) -> Option<u64> {
    let bytes = data.get(at..at.checked_add(8)?)?;
    let mut array = [0u8; 8];
    array.copy_from_slice(bytes);
    Some(u64::from_be_bytes(array))
}

type Fourcc = [u8; 4];

/// The boxes at one level of an MP4 file: the type and the body.
fn boxes(data: &[u8]) -> Vec<(Fourcc, &[u8])> {
    let mut out = Vec::new();
    let mut at = 0usize;
    while data.len().saturating_sub(at) >= 8 {
        let Some(size32) = be32(data, at) else { break };
        let kind = [data[at + 4], data[at + 5], data[at + 6], data[at + 7]];
        let (header, size) = match size32 {
            0 => (8usize, (data.len() - at) as u64),
            1 => match be64(data, at + 8) {
                Some(size) => (16usize, size),
                None => break,
            },
            n => (8usize, u64::from(n)),
        };
        let Ok(size) = usize::try_from(size) else {
            break;
        };
        if size < header || size > data.len() - at {
            break;
        }
        out.push((kind, &data[at + header..at + size]));
        at += size;
    }
    out
}

fn child<'a>(level: &[(Fourcc, &'a [u8])], kind: &[u8; 4]) -> Option<&'a [u8]> {
    level
        .iter()
        .find(|(found, _)| found == kind)
        .map(|(_, body)| *body)
}

fn scaled_us(ticks: i64, timescale: u32) -> i64 {
    if timescale == 0 {
        return 0;
    }
    (i128::from(ticks) * 1_000_000 / i128::from(timescale)) as i64
}

/// The video sample list of an MP4, MOV or M4V file.
pub fn mp4_video(data: &[u8]) -> Result<VideoTrack, String> {
    let top = boxes(data);
    let moov = child(&top, b"moov").ok_or("no movie header")?;
    for (kind, trak) in boxes(moov) {
        if &kind != b"trak" {
            continue;
        }
        if let Some(track) = mp4_track(trak)? {
            return Ok(track);
        }
    }
    Err("no video track".to_string())
}

fn mp4_track(trak: &[u8]) -> Result<Option<VideoTrack>, String> {
    let trak = boxes(trak);
    let Some(mdia) = child(&trak, b"mdia") else {
        return Ok(None);
    };
    let mdia = boxes(mdia);
    let is_video = child(&mdia, b"hdlr").is_some_and(|hdlr| hdlr.get(8..12) == Some(b"vide"));
    if !is_video {
        return Ok(None);
    }
    let timescale = child(&mdia, b"mdhd")
        .and_then(|mdhd| match mdhd.first() {
            Some(1) => be32(mdhd, 20),
            _ => be32(mdhd, 12),
        })
        .filter(|scale| *scale != 0)
        .ok_or("bad media header")?;
    let minf = child(&mdia, b"minf").ok_or("no media information")?;
    let stbl = child(&boxes(minf), b"stbl").ok_or("no sample table")?;
    let stbl = boxes(stbl);
    let stsd = child(&stbl, b"stsd").ok_or("no sample description")?;
    let mut track = sample_entry(stsd);
    if track.codec == VideoCodec::Other {
        return Ok(Some(track));
    }
    track.samples = sample_list(&stbl, timescale)?;
    Ok(Some(track))
}

/// Reads the first entry of `stsd`.
fn sample_entry(stsd: &[u8]) -> VideoTrack {
    let mut track = VideoTrack {
        codec: VideoCodec::Other,
        width: 0,
        height: 0,
        parameter_sets: Vec::new(),
        nal_length_size: 4,
        samples: Vec::new(),
    };
    let Some(entry) = stsd.get(8..) else {
        return track;
    };
    let Some((kind, body)) = boxes(entry).into_iter().next() else {
        return track;
    };
    track.width = u32::from(be16(body, 24).unwrap_or(0));
    track.height = u32::from(be16(body, 26).unwrap_or(0));
    let Some(extra) = body.get(78..) else {
        return track;
    };
    let config = boxes(extra);
    match &kind {
        b"hvc1" | b"hev1" => {
            if let Some((length_size, sets)) = child(&config, b"hvcC").and_then(hevc_config) {
                track.codec = VideoCodec::Hevc;
                track.nal_length_size = length_size;
                track.parameter_sets = sets;
            }
        }
        b"avc1" | b"avc3" => {
            if let Some((length_size, sets)) = child(&config, b"avcC").and_then(avc_config) {
                track.codec = VideoCodec::H264;
                track.nal_length_size = length_size;
                track.parameter_sets = sets;
            }
        }
        b"av01" => {
            if let Some(obus) = child(&config, b"av1C").and_then(av1_config) {
                track.codec = VideoCodec::Av1;
                track.parameter_sets = vec![obus];
            }
        }
        _ => {}
    }
    track
}

/// The NAL length size and the parameter sets (SPS, then PPS) of an `avcC`
/// record.
pub fn avc_config(record: &[u8]) -> Option<(usize, Vec<Vec<u8>>)> {
    let length_size = usize::from(*record.get(4)? & 3) + 1;
    let mut at = 6usize;
    let mut sets = Vec::new();
    let sps_count = usize::from(*record.get(5)? & 0x1F);
    for group in 0..2 {
        let count = if group == 0 {
            sps_count
        } else {
            let count = usize::from(*record.get(at)?);
            at += 1;
            count
        };
        for _ in 0..count {
            let length = usize::from(be16(record, at)?);
            let nal = record.get(at + 2..at + 2 + length)?;
            sets.push(nal.to_vec());
            at += 2 + length;
        }
    }
    Some((length_size, sets))
}

/// The configuration OBUs of an `av1C` record: the bytes after its four-byte
/// header. They carry the sequence header.
pub fn av1_config(record: &[u8]) -> Option<Vec<u8>> {
    if *record.first()? & 0x7F != 1 {
        return None;
    }
    Some(record.get(4..)?.to_vec())
}

/// The NAL length size and the parameter sets of an `hvcC` record.
fn hevc_config(record: &[u8]) -> Option<(usize, Vec<Vec<u8>>)> {
    let length_size = usize::from(*record.get(21)? & 3) + 1;
    let arrays = usize::from(*record.get(22)?);
    let mut at = 23usize;
    let mut sets = Vec::new();
    for _ in 0..arrays {
        let count = usize::from(be16(record, at + 1)?);
        at += 3;
        for _ in 0..count {
            let length = usize::from(be16(record, at)?);
            let nal = record.get(at + 2..at + 2 + length)?;
            sets.push(nal.to_vec());
            at += 2 + length;
        }
    }
    Some((length_size, sets))
}

fn sample_list(stbl: &[(Fourcc, &[u8])], timescale: u32) -> Result<Vec<Sample>, String> {
    let bad = || "bad sample table".to_string();
    let stsz = child(stbl, b"stsz").ok_or_else(bad)?;
    let fixed = be32(stsz, 4).ok_or_else(bad)? as usize;
    let count = be32(stsz, 8).ok_or_else(bad)? as usize;
    if count > MAX_SAMPLES {
        return Err("too many samples".to_string());
    }
    let mut sizes = Vec::with_capacity(count);
    for index in 0..count {
        sizes.push(if fixed != 0 {
            fixed
        } else {
            be32(stsz, 12 + 4 * index).ok_or_else(bad)? as usize
        });
    }
    let offsets = chunk_offsets(stbl)?;
    let stsc = child(stbl, b"stsc").ok_or_else(bad)?;
    let runs = be32(stsc, 4).ok_or_else(bad)? as usize;
    // Check the whole run table before any chunk scan: the runs must fit in
    // the box, and `first_chunk` must start at 1 or more, grow strictly and
    // stay inside the chunk table. Then the run ranges cannot overlap and the
    // total work stays bounded by the chunk count.
    if runs > MAX_SAMPLES || runs > stsc.len().saturating_sub(8) / 12 {
        return Err(bad());
    }
    let mut previous = 0usize;
    for run in 0..runs {
        let first = be32(stsc, 8 + 12 * run).ok_or_else(bad)? as usize;
        if first <= previous || first > offsets.len() {
            return Err(bad());
        }
        previous = first;
    }
    let mut positions = Vec::with_capacity(count);
    'runs: for run in 0..runs {
        let first = be32(stsc, 8 + 12 * run).ok_or_else(bad)? as usize;
        let per_chunk = be32(stsc, 12 + 12 * run).ok_or_else(bad)? as usize;
        let end = match be32(stsc, 8 + 12 * (run + 1)) {
            Some(next) if run + 1 < runs => next as usize,
            _ => offsets.len() + 1,
        };
        for chunk in first..end {
            let mut at = offsets[chunk - 1];
            for _ in 0..per_chunk {
                if positions.len() >= count {
                    break 'runs;
                }
                let size = sizes[positions.len()];
                positions.push((at, size));
                at = at.checked_add(size).ok_or_else(bad)?;
            }
            if positions.len() >= count {
                break 'runs;
            }
        }
    }
    if positions.len() != count {
        return Err(bad());
    }
    // Decode time, then presentation time.
    let mut decode: Vec<i64> = Vec::with_capacity(count);
    let stts = child(stbl, b"stts").ok_or_else(bad)?;
    let entries = be32(stts, 4).ok_or_else(bad)? as usize;
    let mut clock = 0i64;
    for entry in 0..entries {
        let repeat = be32(stts, 8 + 8 * entry).ok_or_else(bad)? as usize;
        let delta = i64::from(be32(stts, 12 + 8 * entry).ok_or_else(bad)?);
        for _ in 0..repeat.min(count.saturating_sub(decode.len())) {
            decode.push(clock);
            clock += delta;
        }
    }
    if decode.len() != count {
        return Err(bad());
    }
    let mut shift = vec![0i64; count];
    if let Some(ctts) = child(stbl, b"ctts") {
        let entries = be32(ctts, 4).ok_or_else(bad)? as usize;
        let mut index = 0usize;
        for entry in 0..entries {
            let repeat = be32(ctts, 8 + 8 * entry).ok_or_else(bad)? as usize;
            let offset = i64::from(be32(ctts, 12 + 8 * entry).ok_or_else(bad)? as i32);
            for _ in 0..repeat.min(count.saturating_sub(index)) {
                shift[index] = offset;
                index += 1;
            }
        }
    }
    let keys: Option<Vec<usize>> = match child(stbl, b"stss") {
        Some(stss) => {
            let entries = be32(stss, 4).ok_or_else(bad)? as usize;
            // Check the count before the loop: it must fit in the box and the limit.
            if entries > MAX_SAMPLES || entries > stss.len().saturating_sub(8) / 4 {
                return Err(bad());
            }
            let mut keys = Vec::with_capacity(entries);
            for entry in 0..entries {
                keys.push(be32(stss, 8 + 4 * entry).ok_or_else(bad)? as usize);
            }
            Some(keys)
        }
        None => None,
    };
    let mut samples: Vec<Sample> = positions
        .iter()
        .enumerate()
        .map(|(index, (offset, size))| Sample {
            offset: *offset,
            size: *size,
            pts_us: scaled_us(decode[index] + shift[index], timescale),
            key: keys
                .as_ref()
                .is_none_or(|keys| keys.binary_search(&(index + 1)).is_ok()),
        })
        .collect();
    let first = samples
        .iter()
        .map(|sample| sample.pts_us)
        .min()
        .unwrap_or(0);
    for sample in &mut samples {
        sample.pts_us -= first;
    }
    Ok(samples)
}

fn chunk_offsets(stbl: &[(Fourcc, &[u8])]) -> Result<Vec<usize>, String> {
    let bad = || "bad chunk table".to_string();
    let (table, wide) = match (child(stbl, b"stco"), child(stbl, b"co64")) {
        (Some(table), _) => (table, false),
        (None, Some(table)) => (table, true),
        (None, None) => return Err(bad()),
    };
    let count = be32(table, 4).ok_or_else(bad)? as usize;
    if count > MAX_SAMPLES {
        return Err(bad());
    }
    let mut offsets = Vec::with_capacity(count);
    for index in 0..count {
        let offset = if wide {
            be64(table, 8 + 8 * index).ok_or_else(bad)?
        } else {
            u64::from(be32(table, 8 + 4 * index).ok_or_else(bad)?)
        };
        offsets.push(usize::try_from(offset).map_err(|_| bad())?);
    }
    Ok(offsets)
}

// ----- WebM (Matroska) -----

const ID_SEGMENT: u32 = 0x1853_8067;
const ID_INFO: u32 = 0x1549_A966;
const ID_TIMECODE_SCALE: u32 = 0x2A_D7B1;
const ID_DURATION: u32 = 0x4489;
const ID_TRACKS: u32 = 0x1654_AE6B;
const ID_TRACK_ENTRY: u32 = 0xAE;
const ID_TRACK_NUMBER: u32 = 0xD7;
const ID_CODEC_ID: u32 = 0x86;
const ID_CODEC_PRIVATE: u32 = 0x63A2;
const ID_DEFAULT_DURATION: u32 = 0x23_E383;
const ID_VIDEO: u32 = 0xE0;
const ID_PIXEL_WIDTH: u32 = 0xB0;
const ID_PIXEL_HEIGHT: u32 = 0xBA;
const ID_CLUSTER: u32 = 0x1F43_B675;
const ID_CLUSTER_TIMECODE: u32 = 0xE7;
const ID_SIMPLE_BLOCK: u32 = 0xA3;
const ID_BLOCK_GROUP: u32 = 0xA0;
const ID_BLOCK: u32 = 0xA1;

/// An EBML variable-length number at `at`: the value and its length. For an
/// element ID the marker bit stays; for a size it is removed. `None` for a
/// size means "unknown".
fn vint(data: &[u8], at: usize, keep_marker: bool) -> Option<(Option<u64>, usize)> {
    let first = *data.get(at)?;
    let length = first.leading_zeros() as usize + 1;
    if length > 8 {
        return None;
    }
    let bytes = data.get(at..at.checked_add(length)?)?;
    let mask = (1u64 << (8 - length)) - 1;
    let mut value = if keep_marker {
        u64::from(first)
    } else {
        u64::from(first) & mask
    };
    let mut all_ones = u64::from(first) & mask == mask;
    for byte in &bytes[1..] {
        value = (value << 8) | u64::from(*byte);
        all_ones &= *byte == 0xFF;
    }
    if !keep_marker && all_ones {
        return Some((None, length));
    }
    Some((Some(value), length))
}

/// An EBML lace size at `at`: the value and its length. All-ones is a valid
/// value here, not the "unknown" size of an element.
fn lace_vint(data: &[u8], at: usize) -> Option<(u64, usize)> {
    let (value, length) = vint(data, at, true)?;
    Some((value? & ((1u64 << (7 * length)) - 1), length))
}

#[derive(Default)]
struct Entry {
    number: u64,
    codec: String,
    private: Vec<u8>,
    width: u32,
    height: u32,
    /// `DefaultDuration` in nanoseconds, 0 when the track has none.
    default_duration_ns: u64,
}

#[derive(Default)]
struct Walker {
    scale_ns: u64,
    duration: f64,
    entries: Vec<Entry>,
    cluster_time: i64,
    /// Track number, offset, size, time in timecode units, key frame and
    /// whether the frame follows another frame of the same laced block.
    blocks: Vec<(u64, usize, usize, i64, bool, bool)>,
    /// The first malformed laced block.
    error: Option<String>,
}

/// The frames of a block payload as (offset, size) pairs relative to the
/// payload start. `lacing` is the lacing field of the block flags.
fn lace_frames(payload: &[u8], lacing: u8) -> Result<Vec<(usize, usize)>, String> {
    if lacing == 0 {
        return Ok(vec![(0, payload.len())]);
    }
    let count = usize::from(*payload.first().ok_or("laced block has no frame count")?) + 1;
    let mut at = 1usize;
    let mut sizes: Vec<usize> = Vec::with_capacity(count);
    match lacing {
        // Xiph: each size is a run of 255 bytes closed by a smaller byte.
        1 => {
            for _ in 1..count {
                let mut size = 0usize;
                loop {
                    let byte = *payload.get(at).ok_or("truncated Xiph lacing sizes")?;
                    at += 1;
                    size = size
                        .checked_add(usize::from(byte))
                        .ok_or("Xiph frame size overflows")?;
                    if byte != 255 {
                        break;
                    }
                }
                sizes.push(size);
            }
        }
        // Fixed size: the frames share the payload equally.
        2 => {
            let rest = payload.len() - at;
            if !rest.is_multiple_of(count) {
                return Err("fixed-size lacing does not divide the payload".to_string());
            }
            sizes.resize(count - 1, rest / count);
        }
        // EBML: the first size, then signed differences.
        _ => {
            let (first, length) = lace_vint(payload, at).ok_or("truncated EBML lacing sizes")?;
            at += length;
            let mut size = i64::try_from(first).map_err(|_| "EBML frame size overflows")?;
            if count > 1 {
                sizes.push(usize::try_from(size).map_err(|_| "EBML frame size overflows")?);
            }
            for _ in 2..count {
                let (raw, length) = lace_vint(payload, at).ok_or("truncated EBML lacing sizes")?;
                at += length;
                let raw = i64::try_from(raw).map_err(|_| "EBML frame size overflows")?;
                let bias = (1i64 << (7 * length - 1)) - 1;
                size = size
                    .checked_add(raw - bias)
                    .ok_or("EBML frame size overflows")?;
                sizes.push(usize::try_from(size).map_err(|_| "EBML frame size is negative")?);
            }
        }
    }
    // The last frame takes what the other frames leave.
    let mut frames = Vec::with_capacity(count);
    let mut offset = at;
    for size in sizes {
        let end = offset
            .checked_add(size)
            .filter(|end| *end <= payload.len())
            .ok_or("laced frame runs past the block")?;
        frames.push((offset, size));
        offset = end;
    }
    if offset > payload.len() {
        return Err("laced sizes run past the block".to_string());
    }
    frames.push((offset, payload.len() - offset));
    Ok(frames)
}

/// The duration in microseconds of an Opus packet, from its first bytes.
fn opus_packet_us(packet: &[u8]) -> Option<i64> {
    let toc = *packet.first()?;
    let config = toc >> 3;
    let frame_us: i64 = match config {
        0..=11 => [10_000, 20_000, 40_000, 60_000][usize::from(config % 4)],
        12..=15 => [10_000, 20_000][usize::from(config % 2)],
        _ => [2_500, 5_000, 10_000, 20_000][usize::from(config % 4)],
    };
    let frames = match toc & 3 {
        0 => 1,
        1 | 2 => 2,
        _ => i64::from(*packet.get(1)? & 0x3F),
    };
    Some(frame_us * frames)
}

fn unsigned(body: &[u8]) -> u64 {
    body.iter()
        .take(8)
        .fold(0u64, |acc, byte| (acc << 8) | u64::from(*byte))
}

impl Walker {
    fn walk(&mut self, data: &[u8], base: usize, depth: usize) {
        if depth > 8 {
            return;
        }
        let mut at = 0usize;
        while at < data.len() {
            let Some((Some(id), id_len)) = vint(data, at, true) else {
                return;
            };
            if id_len > 4 {
                return;
            }
            let Some((size, size_len)) = vint(data, at + id_len, false) else {
                return;
            };
            let start = at + id_len + size_len;
            let end = match size {
                Some(size) => usize::try_from(size)
                    .ok()
                    .and_then(|size| start.checked_add(size))
                    .filter(|end| *end <= data.len()),
                None => Some(data.len()),
            };
            let Some(end) = end else { return };
            self.element(id as u32, &data[start..end], base + start, depth);
            at = end;
        }
    }

    fn element(&mut self, id: u32, body: &[u8], base: usize, depth: usize) {
        match id {
            ID_SEGMENT | ID_INFO | ID_TRACKS | ID_CLUSTER | ID_BLOCK_GROUP | ID_VIDEO => {
                self.walk(body, base, depth + 1)
            }
            ID_TIMECODE_SCALE => self.scale_ns = unsigned(body),
            ID_DURATION => {
                self.duration = match body.len() {
                    4 => f64::from(f32::from_bits(unsigned(body) as u32)),
                    8 => f64::from_bits(unsigned(body)),
                    _ => 0.0,
                }
            }
            ID_TRACK_ENTRY => {
                self.entries.push(Entry::default());
                self.walk(body, base, depth + 1);
            }
            ID_TRACK_NUMBER => {
                if let Some(entry) = self.entries.last_mut() {
                    entry.number = unsigned(body);
                }
            }
            ID_CODEC_ID => {
                if let Some(entry) = self.entries.last_mut() {
                    entry.codec = String::from_utf8_lossy(body).into_owned();
                }
            }
            ID_CODEC_PRIVATE => {
                if let Some(entry) = self.entries.last_mut() {
                    entry.private = body.to_vec();
                }
            }
            ID_PIXEL_WIDTH => {
                if let Some(entry) = self.entries.last_mut() {
                    entry.width = unsigned(body) as u32;
                }
            }
            ID_PIXEL_HEIGHT => {
                if let Some(entry) = self.entries.last_mut() {
                    entry.height = unsigned(body) as u32;
                }
            }
            ID_DEFAULT_DURATION => {
                if let Some(entry) = self.entries.last_mut() {
                    entry.default_duration_ns = unsigned(body);
                }
            }
            ID_CLUSTER_TIMECODE => self.cluster_time = unsigned(body) as i64,
            ID_SIMPLE_BLOCK => self.block(body, base, None),
            // A block in a group has no key frame flag; it is taken as one.
            ID_BLOCK => self.block(body, base, Some(true)),
            _ => {}
        }
    }

    fn block(&mut self, body: &[u8], base: usize, group_key: Option<bool>) {
        let Some((Some(track), length)) = vint(body, 0, false) else {
            return;
        };
        let (Some(relative), Some(flags)) = (be16(body, length), body.get(length + 2)) else {
            return;
        };
        if self.blocks.len() >= MAX_SAMPLES {
            return;
        }
        let key = group_key.unwrap_or(flags & 0x80 != 0);
        let header = length + 3;
        let frames = match lace_frames(&body[header..], (flags >> 1) & 3) {
            Ok(frames) => frames,
            Err(reason) => {
                if self.error.is_none() {
                    self.error = Some(format!("laced block of track {track}: {reason}"));
                }
                return;
            }
        };
        for (index, (offset, size)) in frames.into_iter().enumerate() {
            if self.blocks.len() >= MAX_SAMPLES {
                break;
            }
            self.blocks.push((
                track,
                base + header + offset,
                size,
                self.cluster_time + i64::from(relative as i16),
                key && index == 0,
                index > 0,
            ));
        }
    }
}

/// The video and the Opus audio of a WebM file.
pub fn webm(data: &[u8]) -> Result<WebmMedia, String> {
    let mut walker = Walker {
        scale_ns: 1_000_000,
        ..Walker::default()
    };
    walker.walk(data, 0, 0);
    if let Some(error) = walker.error.take() {
        return Err(error);
    }
    let unit_us = |ticks: i64| ticks.saturating_mul(walker.scale_ns as i64) / 1000;
    let mut media = WebmMedia::default();
    if walker.duration > 0.0 {
        media.duration_us = Some(unit_us(walker.duration as i64));
    }
    for entry in &walker.entries {
        let samples = || -> Vec<(usize, usize, i64, bool, bool)> {
            walker
                .blocks
                .iter()
                .filter(|block| block.0 == entry.number)
                .map(|block| (block.1, block.2, unit_us(block.3), block.4, block.5))
                .collect()
        };
        match entry.codec.as_str() {
            "V_VP9" | "V_VP8" | "V_AV1" | "V_MPEGH/ISO/HEVC" | "V_MPEG4/ISO/AVC"
                if media.video.is_none() =>
            {
                let list = samples();
                let first = list.iter().map(|sample| sample.2).min().unwrap_or(0);
                let (codec, length_size, parameter_sets) = webm_codec(entry);
                media.video = Some(VideoTrack {
                    codec,
                    width: entry.width,
                    height: entry.height,
                    parameter_sets,
                    nal_length_size: length_size,
                    samples: list
                        .into_iter()
                        .map(|(offset, size, pts_us, key, _)| Sample {
                            offset,
                            size,
                            pts_us: pts_us - first,
                            key,
                        })
                        .collect(),
                });
            }
            "A_OPUS" if media.audio.is_none() => {
                let channels = entry.private.get(9).map_or(2, |c| usize::from(*c));
                let pre_skip =
                    usize::from(be16(&entry.private, 10).map(u16::swap_bytes).unwrap_or(0));
                media.audio = Some(OpusTrack {
                    channels: channels.clamp(1, 2),
                    pre_skip,
                    packets: audio_packets(data, samples(), entry, true),
                });
            }
            "A_VORBIS" if media.audio.is_none() && media.vorbis.is_none() => {
                if let Some((channels, sample_rate, headers)) = vorbis_headers(&entry.private) {
                    media.vorbis = Some(VorbisTrack {
                        channels,
                        sample_rate,
                        headers,
                        packets: audio_packets(data, samples(), entry, false),
                    });
                }
            }
            _ => {}
        }
    }
    if media.video.is_none() {
        return Err("no video track".to_string());
    }
    Ok(media)
}

/// The audio packets of a track. A frame that follows another frame of a
/// laced block starts when the previous frame ends.
fn audio_packets(
    data: &[u8],
    list: Vec<(usize, usize, i64, bool, bool)>,
    entry: &Entry,
    opus: bool,
) -> Vec<(usize, usize, i64)> {
    let default_us = i64::try_from(entry.default_duration_ns / 1000).unwrap_or(0);
    let mut out: Vec<(usize, usize, i64)> = Vec::with_capacity(list.len());
    for (offset, size, pts_us, _, continued) in list {
        let mut pts_us = pts_us;
        if continued {
            if let Some(&(previous, previous_size, previous_pts)) = out.last() {
                let duration = if default_us > 0 {
                    default_us
                } else if opus {
                    data.get(previous..previous.saturating_add(previous_size))
                        .and_then(opus_packet_us)
                        .unwrap_or(0)
                } else {
                    0
                };
                pts_us = previous_pts.saturating_add(duration);
            }
        }
        out.push((offset, size, pts_us));
    }
    out
}

/// The codec of a WebM video track, with its NAL length size and parameter
/// sets from `CodecPrivate`.
fn webm_codec(entry: &Entry) -> (VideoCodec, usize, Vec<Vec<u8>>) {
    match entry.codec.as_str() {
        "V_VP9" => (VideoCodec::Vp9, 4, Vec::new()),
        "V_VP8" => (VideoCodec::Vp8, 4, Vec::new()),
        "V_AV1" => match av1_config(&entry.private) {
            Some(obus) => (VideoCodec::Av1, 4, vec![obus]),
            // No `av1C`: the sequence header is then inside the frames.
            None => (VideoCodec::Av1, 4, Vec::new()),
        },
        "V_MPEG4/ISO/AVC" => match avc_config(&entry.private) {
            Some((length_size, sets)) => (VideoCodec::H264, length_size, sets),
            None => (VideoCodec::Other, 4, Vec::new()),
        },
        "V_MPEGH/ISO/HEVC" => match hevc_config(&entry.private) {
            Some((length_size, sets)) => (VideoCodec::Hevc, length_size, sets),
            None => (VideoCodec::Other, 4, Vec::new()),
        },
        _ => (VideoCodec::Other, 4, Vec::new()),
    }
}

/// The channels, the sample rate and the identification and setup packets
/// from the `CodecPrivate` of a Vorbis track. The three header packets come
/// with Xiph lacing: the count, the sizes of all but the last, the data.
fn vorbis_headers(private: &[u8]) -> Option<(usize, u32, Vec<u8>)> {
    if *private.first()? != 2 {
        return None;
    }
    let mut at = 1usize;
    let mut sizes = [0usize; 2];
    for size in &mut sizes {
        loop {
            let byte = *private.get(at)?;
            at += 1;
            *size = size.checked_add(usize::from(byte))?;
            if byte != 255 {
                break;
            }
        }
    }
    let ident = private.get(at..at.checked_add(sizes[0])?)?;
    let setup_start = at.checked_add(sizes[0])?.checked_add(sizes[1])?;
    let setup = private.get(setup_start..)?;
    // The identification packet: type 1, "vorbis", version, channels, rate.
    if ident.len() < 30 || ident.first() != Some(&1) || ident.get(1..7) != Some(b"vorbis") {
        return None;
    }
    if setup.first() != Some(&5) {
        return None;
    }
    let channels = usize::from(*ident.get(11)?);
    let rate = u32::from_le_bytes([
        *ident.get(12)?,
        *ident.get(13)?,
        *ident.get(14)?,
        *ident.get(15)?,
    ]);
    if channels == 0 || rate == 0 {
        return None;
    }
    let mut headers = ident.to_vec();
    headers.extend_from_slice(setup);
    Some((channels, rate, headers))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn boxed(kind: &[u8; 4], body: &[u8]) -> Vec<u8> {
        let mut out = ((body.len() + 8) as u32).to_be_bytes().to_vec();
        out.extend_from_slice(kind);
        out.extend_from_slice(body);
        out
    }

    fn full(kind: &[u8; 4], words: &[u32]) -> Vec<u8> {
        let mut body = vec![0u8; 4];
        for word in words {
            body.extend_from_slice(&word.to_be_bytes());
        }
        boxed(kind, &body)
    }

    #[test]
    fn boxes_stop_at_a_bad_length() {
        let mut data = boxed(b"free", &[1, 2, 3]);
        data.extend_from_slice(&[0, 0, 0, 99, b'm', b'o', b'o', b'v']);
        let found = boxes(&data);
        assert_eq!(found.len(), 1);
        assert_eq!(&found[0].0, b"free");
    }

    #[test]
    fn sample_tables_give_offsets_times_and_key_frames() {
        // 3 samples of 10 bytes: chunk 1 holds two, chunk 2 holds one.
        let stsz = full(b"stsz", &[0, 3, 10, 10, 10]);
        let stsc = full(b"stsc", &[2, 1, 2, 1, 2, 1, 1]);
        let stco = full(b"stco", &[2, 100, 200]);
        let stts = full(b"stts", &[1, 3, 1000]);
        let ctts = full(b"ctts", &[2, 1, 2000, 2, 0]);
        let stss = full(b"stss", &[1, 1]);
        let mut stbl = Vec::new();
        for part in [&stsz, &stsc, &stco, &stts, &ctts, &stss] {
            stbl.extend_from_slice(part);
        }
        let list = sample_list(&boxes(&stbl), 1000).expect("table");
        assert_eq!(list.len(), 3);
        assert_eq!(
            (list[0].offset, list[1].offset, list[2].offset),
            (100, 110, 200)
        );
        // pts: 0+2000, 1000+0, 2000+0 ms, moved so the first is 0.
        assert_eq!(
            list.iter().map(|s| s.pts_us).collect::<Vec<_>>(),
            vec![1_000_000, 0, 1_000_000]
        );
        assert_eq!(
            list.iter().map(|s| s.key).collect::<Vec<_>>(),
            vec![true, false, false]
        );
    }

    /// A sample table of one sample with the given sync-sample box.
    fn table_with_stss(stss: &[u8]) -> Vec<u8> {
        let mut stbl = Vec::new();
        for part in [
            full(b"stsz", &[0, 1, 10, 10]),
            full(b"stsc", &[1, 1, 1, 1]),
            full(b"stco", &[1, 100]),
            full(b"stts", &[1, 1, 1000]),
        ] {
            stbl.extend_from_slice(&part);
        }
        stbl.extend_from_slice(stss);
        stbl
    }

    #[test]
    fn a_valid_sync_table_gives_the_key_frames() {
        let stbl = table_with_stss(&full(b"stss", &[1, 1]));
        let list = sample_list(&boxes(&stbl), 1000).expect("table");
        assert_eq!(list.len(), 1);
        assert!(list[0].key);
    }

    #[test]
    fn a_truncated_sync_table_is_refused() {
        let stbl = table_with_stss(&full(b"stss", &[3, 1]));
        assert!(sample_list(&boxes(&stbl), 1000).is_err());
    }

    #[test]
    fn a_sync_table_with_an_excessive_count_is_refused() {
        let stbl = table_with_stss(&full(b"stss", &[u32::MAX, 1]));
        assert!(sample_list(&boxes(&stbl), 1000).is_err());
    }

    /// A table of two samples in two chunks with the given chunk-run words.
    fn table_with_runs(runs: &[u32]) -> Vec<u8> {
        let mut stbl = Vec::new();
        for part in [
            full(b"stsz", &[0, 2, 10, 10, 10]),
            full(b"stsc", runs),
            full(b"stco", &[2, 100, 200]),
            full(b"stts", &[1, 2, 1000]),
        ] {
            stbl.extend_from_slice(&part);
        }
        stbl
    }

    #[test]
    fn a_valid_run_table_maps_the_chunks() {
        let stbl = table_with_runs(&[2, 1, 1, 1, 2, 1, 1]);
        let list = sample_list(&boxes(&stbl), 1000).expect("table");
        assert_eq!((list[0].offset, list[1].offset), (100, 200));
    }

    #[test]
    fn invalid_first_chunk_values_are_refused() {
        // Decreasing, repeated, zero and out of range.
        for runs in [
            [2, 2, 1, 1, 1, 1, 1],
            [2, 1, 1, 1, 1, 1, 1],
            [2, 0, 1, 1, 1, 1, 1],
            [2, 1, 1, 1, 3, 1, 1],
        ] {
            let stbl = table_with_runs(&runs);
            assert!(sample_list(&boxes(&stbl), 1000).is_err(), "{runs:?}");
        }
    }

    /// A table of `samples` samples with `chunks` chunks and the given run words.
    fn table_with_many_chunks(samples: u32, chunks: u32, runs: &[u32]) -> Vec<u8> {
        let mut offsets = vec![chunks];
        offsets.extend((0..chunks).map(|chunk| 100 + chunk * 10));
        let mut stbl = Vec::new();
        for part in [
            full(b"stsz", &[10, samples]),
            full(b"stsc", runs),
            full(b"stco", &offsets),
            full(b"stts", &[1, samples, 1000]),
        ] {
            stbl.extend_from_slice(&part);
        }
        stbl
    }

    #[test]
    fn alternating_runs_over_many_chunks_are_refused() {
        // The run order fails at the second run, before any chunk scan.
        let mut runs = vec![400];
        for run in 0..400u32 {
            runs.extend_from_slice(&[if run % 2 == 0 { 400 } else { 1 }, 1, 1]);
        }
        let stbl = table_with_many_chunks(2, 400, &runs);
        assert!(sample_list(&boxes(&stbl), 1000).is_err());
        // The same table with increasing runs is valid, so only the run order
        // causes the error above.
        let mut runs = vec![400];
        for run in 1..=400u32 {
            runs.extend_from_slice(&[run, 1, 1]);
        }
        let stbl = table_with_many_chunks(2, 400, &runs);
        assert!(sample_list(&boxes(&stbl), 1000).is_ok());
    }

    #[test]
    fn many_valid_runs_stop_at_the_sample_count() {
        // Three samples are enough: the parser stops in the third chunk, and
        // the huge per-chunk count of the last run is never used.
        let mut runs = vec![400];
        for run in 1..=400u32 {
            runs.extend_from_slice(&[run, if run == 400 { u32::MAX } else { 1 }, 1]);
        }
        let stbl = table_with_many_chunks(3, 400, &runs);
        let list = sample_list(&boxes(&stbl), 1000).expect("table");
        assert_eq!(list.len(), 3);
        assert_eq!(list[2].offset, 120);
    }

    #[test]
    fn a_run_count_larger_than_the_box_is_refused() {
        let stbl = table_with_runs(&[u32::MAX, 1, 1, 1]);
        assert!(sample_list(&boxes(&stbl), 1000).is_err());
    }

    #[test]
    fn a_table_with_too_many_samples_is_refused() {
        let stsz = full(b"stsz", &[0, u32::MAX, 0]);
        assert!(sample_list(&boxes(&stsz), 1000).is_err());
    }

    #[test]
    fn hevc_config_gives_the_parameter_sets() {
        let mut record = vec![0u8; 22];
        record[21] = 0x03;
        record.push(1);
        record.extend_from_slice(&[0x20, 0, 1, 0, 3, 0x40, 1, 2]);
        let (length_size, sets) = hevc_config(&record).expect("config");
        assert_eq!(length_size, 4);
        assert_eq!(sets, vec![vec![0x40, 1, 2]]);
        assert!(hevc_config(&record[..24]).is_none());
    }

    #[test]
    fn a_file_without_a_movie_header_is_refused() {
        assert!(mp4_video(&boxed(b"free", &[])).is_err());
        assert!(mp4_video(b"garbage").is_err());
    }

    #[test]
    fn variable_numbers_follow_ebml() {
        assert_eq!(vint(&[0x81], 0, false), Some((Some(1), 1)));
        assert_eq!(vint(&[0x40, 0x02], 0, false), Some((Some(2), 2)));
        assert_eq!(vint(&[0xFF], 0, false), Some((None, 1)));
        assert_eq!(
            vint(&[0x1A, 0x45, 0xDF, 0xA3], 0, true),
            Some((Some(0x1A45_DFA3), 4))
        );
        assert_eq!(vint(&[0x00], 0, false), None);
    }

    #[test]
    fn a_file_with_no_video_track_is_refused() {
        assert!(webm(&[0x1A, 0x45, 0xDF, 0xA3, 0x80]).is_err());
        assert!(webm(b"").is_err());
    }

    /// An EBML element with an eight-byte size.
    fn element(id: &[u8], body: &[u8]) -> Vec<u8> {
        let mut out = id.to_vec();
        out.push(0x01);
        out.extend_from_slice(&(body.len() as u64).to_be_bytes()[1..]);
        out.extend_from_slice(body);
        out
    }

    /// A WebM file with one video track and one block of the track.
    fn webm_file(codec: &str, private: &[u8], extra_entries: &[Vec<u8>]) -> Vec<u8> {
        let mut entry = element(&[0xD7], &[1]);
        entry.extend(element(&[0x86], codec.as_bytes()));
        if !private.is_empty() {
            entry.extend(element(&[0x63, 0xA2], private));
        }
        let mut video = element(&[0xB0], &[0x01, 0x40]);
        video.extend(element(&[0xBA], &[0x00, 0xF0]));
        entry.extend(element(&[0xE0], &video));
        let mut tracks = element(&[0xAE], &entry);
        for extra in extra_entries {
            tracks.extend_from_slice(extra);
        }
        let mut cluster = element(&[0xE7], &[0]);
        // Track 1, time 0, key frame, three bytes of data.
        cluster.extend(element(&[0xA3], &[0x81, 0, 0, 0x80, 7, 8, 9]));
        let mut segment = element(&[0x16, 0x54, 0xAE, 0x6B], &tracks);
        segment.extend(element(&[0x1F, 0x43, 0xB6, 0x75], &cluster));
        element(&[0x18, 0x53, 0x80, 0x67], &segment)
    }

    #[test]
    fn webm_names_the_vp8_vp9_and_av1_tracks() {
        for (name, codec) in [
            ("V_VP8", VideoCodec::Vp8),
            ("V_VP9", VideoCodec::Vp9),
            ("V_UNKNOWN_THING", VideoCodec::Other),
        ] {
            let result = webm(&webm_file(name, &[], &[]));
            if codec == VideoCodec::Other {
                assert!(result.is_err());
                continue;
            }
            let media = result.expect("media");
            let track = media.video.expect("video");
            assert_eq!(track.codec, codec);
            assert_eq!((track.width, track.height), (320, 240));
            assert_eq!(track.samples.len(), 1);
            assert!(track.samples[0].key);
            assert_eq!(track.samples[0].size, 3);
        }
        // AV1 keeps the configuration OBUs that follow the four-byte header.
        let media = webm(&webm_file("V_AV1", &[0x81, 0, 0, 0, 0x0A, 0x0B], &[])).expect("media");
        let track = media.video.expect("video");
        assert_eq!(track.codec, VideoCodec::Av1);
        assert_eq!(track.parameter_sets, vec![vec![0x0A, 0x0B]]);
        // A configuration of another version is not taken.
        let media = webm(&webm_file("V_AV1", &[0x82, 0, 0, 0, 1], &[])).expect("media");
        assert!(media.video.expect("video").parameter_sets.is_empty());
    }

    #[test]
    fn webm_gives_the_h264_parameter_sets() {
        // avcC: version, profile, compatibility, level, length size 4, one
        // SPS of two bytes, one PPS of one byte.
        let record = [1, 66, 0, 30, 0xFF, 0xE1, 0, 2, 0x67, 0x42, 1, 0, 1, 0x68];
        let media = webm(&webm_file("V_MPEG4/ISO/AVC", &record, &[])).expect("media");
        let track = media.video.expect("video");
        assert_eq!(track.codec, VideoCodec::H264);
        assert_eq!(track.nal_length_size, 4);
        assert_eq!(track.parameter_sets, vec![vec![0x67, 0x42], vec![0x68]]);
        // A record that is cut short makes the track unusable, not a panic.
        let media = webm(&webm_file("V_MPEG4/ISO/AVC", &record[..8], &[])).expect("media");
        assert_eq!(media.video.expect("video").codec, VideoCodec::Other);
    }

    #[test]
    fn avc_config_reads_the_length_size_and_both_sets() {
        let record = [
            1, 100, 0, 40, 0xFD, 0xE2, 0, 1, 0x67, 0, 2, 0x68, 0x69, 1, 0, 1, 0x6A,
        ];
        let (length_size, sets) = avc_config(&record).expect("config");
        assert_eq!(length_size, 2);
        assert_eq!(sets.len(), 3);
        assert_eq!(sets[0], vec![0x67]);
        assert_eq!(sets[1], vec![0x68, 0x69]);
        assert_eq!(sets[2], vec![0x6A]);
        assert!(avc_config(&record[..6]).is_none());
        assert!(avc_config(&[]).is_none());
    }

    /// The `CodecPrivate` of a Vorbis track: three header packets with Xiph
    /// lacing.
    fn vorbis_private(channels: u8, rate: u32, setup: &[u8]) -> Vec<u8> {
        let mut ident = vec![1];
        ident.extend_from_slice(b"vorbis");
        ident.extend_from_slice(&0u32.to_le_bytes());
        ident.push(channels);
        ident.extend_from_slice(&rate.to_le_bytes());
        ident.extend_from_slice(&[0u8; 14]);
        let comment = [3u8, b'v', b'o', b'r', b'b', b'i', b's'];
        let mut private = vec![2, ident.len() as u8, comment.len() as u8];
        private.extend_from_slice(&ident);
        private.extend_from_slice(&comment);
        private.extend_from_slice(setup);
        private
    }

    #[test]
    fn vorbis_headers_give_the_channels_the_rate_and_the_set_up_data() {
        let private = vorbis_private(2, 44_100, &[5, 1, 2, 3]);
        let (channels, rate, headers) = vorbis_headers(&private).expect("headers");
        assert_eq!((channels, rate), (2, 44_100));
        // The identification packet and the setup packet, no comment.
        assert_eq!(headers.len(), 30 + 4);
        assert_eq!(headers[0], 1);
        assert_eq!(&headers[30..], &[5, 1, 2, 3]);
    }

    #[test]
    fn bad_vorbis_headers_are_refused() {
        assert!(vorbis_headers(&[]).is_none());
        assert!(vorbis_headers(&[1, 2, 3]).is_none());
        // Not a setup packet at the end.
        assert!(vorbis_headers(&vorbis_private(2, 44_100, &[4, 1])).is_none());
        // No channels, and no rate.
        assert!(vorbis_headers(&vorbis_private(0, 44_100, &[5])).is_none());
        assert!(vorbis_headers(&vorbis_private(2, 0, &[5])).is_none());
        // A size that runs past the data.
        assert!(vorbis_headers(&[2, 255, 255, 1]).is_none());
    }

    /// A WebM file with a video track and an Opus track whose only block has
    /// the given flags and laced payload.
    fn laced_opus_file(flags: u8, laced: &[u8]) -> Vec<u8> {
        let mut video = element(&[0xD7], &[1]);
        video.extend(element(&[0x86], b"V_VP8"));
        let mut audio = element(&[0xD7], &[2]);
        audio.extend(element(&[0x86], b"A_OPUS"));
        let mut tracks = element(&[0xAE], &video);
        tracks.extend(element(&[0xAE], &audio));
        let mut block = vec![0x82, 0, 0, flags];
        block.extend_from_slice(laced);
        let mut cluster = element(&[0xE7], &[0]);
        cluster.extend(element(&[0xA3], &block));
        let mut segment = element(&[0x16, 0x54, 0xAE, 0x6B], &tracks);
        segment.extend(element(&[0x1F, 0x43, 0xB6, 0x75], &cluster));
        element(&[0x18, 0x53, 0x80, 0x67], &segment)
    }

    #[test]
    fn xiph_laced_opus_frames_are_all_returned_in_order() {
        // Frames of 1, 2 and 3 bytes; TOC 0xF8 is a 20 ms CELT frame.
        let file = laced_opus_file(0x02, &[2, 1, 2, 0xF8, 0xF8, 1, 0xF8, 2, 3]);
        let packets = webm(&file).expect("media").audio.expect("audio").packets;
        assert_eq!(packets.len(), 3);
        assert_eq!(
            packets.iter().map(|p| p.1).collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        assert!(packets[0].0 < packets[1].0 && packets[1].0 < packets[2].0);
        assert_eq!(
            packets.iter().map(|p| p.2).collect::<Vec<_>>(),
            vec![0, 20_000, 40_000]
        );
    }

    #[test]
    fn fixed_laced_opus_frames_share_the_payload() {
        let file = laced_opus_file(0x04, &[1, 0xF8, 1, 0xF8, 2]);
        let packets = webm(&file).expect("media").audio.expect("audio").packets;
        assert_eq!(packets.iter().map(|p| p.1).collect::<Vec<_>>(), vec![2, 2]);
    }

    #[test]
    fn ebml_laced_opus_frames_use_signed_differences() {
        // Sizes 3, then 2 (difference -1) and the 1 byte that remains.
        let file = laced_opus_file(0x06, &[2, 0x83, 0xBE, 0xF8, 1, 2, 0xF8, 3, 4]);
        let packets = webm(&file).expect("media").audio.expect("audio").packets;
        assert_eq!(
            packets.iter().map(|p| p.1).collect::<Vec<_>>(),
            vec![3, 2, 1]
        );
    }

    #[test]
    fn a_block_without_lacing_gives_one_packet() {
        let packets = webm(&laced_opus_file(0x00, &[0xF8, 1]))
            .expect("media")
            .audio
            .expect("audio")
            .packets;
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].1, 2);
    }

    #[test]
    fn lace_frames_reads_every_mode() {
        assert_eq!(lace_frames(&[1, 2, 3], 0).unwrap(), vec![(0, 3)]);
        assert_eq!(
            lace_frames(&[1, 2, 9, 9, 9], 1).unwrap(),
            vec![(2, 2), (4, 1)]
        );
        assert_eq!(lace_frames(&[1, 7, 7], 2).unwrap(), vec![(1, 1), (2, 1)]);
        assert_eq!(
            lace_frames(&[1, 0x82, 5, 5, 5], 3).unwrap(),
            vec![(2, 2), (4, 1)]
        );
        // An EBML size with all bits set is a value: 127 bytes.
        let mut ebml = vec![1, 0xFF];
        ebml.extend(vec![0u8; 128]);
        assert_eq!(lace_frames(&ebml, 3).unwrap(), vec![(2, 127), (129, 1)]);
        // A difference of +64 is also all ones: sizes 1, 65 and 1.
        let mut ebml = vec![2, 0x81, 0xFF];
        ebml.extend(vec![0u8; 67]);
        assert_eq!(
            lace_frames(&ebml, 3).unwrap(),
            vec![(3, 1), (4, 65), (69, 1)]
        );
        // A Xiph size of 255 continues in the next byte.
        let mut xiph = vec![1, 255, 1];
        xiph.extend(vec![0u8; 257]);
        assert_eq!(lace_frames(&xiph, 1).unwrap(), vec![(3, 256), (259, 1)]);
    }

    #[test]
    fn malformed_lacing_is_refused() {
        assert!(lace_frames(&[], 1).is_err());
        // Truncated Xiph sizes.
        assert!(lace_frames(&[2, 255], 1).is_err());
        // A frame larger than the block.
        assert!(lace_frames(&[1, 9, 1], 1).is_err());
        // Fixed size that does not divide the payload.
        assert!(lace_frames(&[1, 1, 2, 3], 2).is_err());
        // EBML: truncated, frame past the block, negative size.
        assert!(lace_frames(&[2, 0x81], 3).is_err());
        assert!(lace_frames(&[1, 0xFF, 1], 3).is_err());
        assert!(lace_frames(&[2, 0x81, 0x80, 1, 1], 3).is_err());
        // A large frame count with no data.
        assert!(lace_frames(&[255, 1], 1).is_err());
        // The error reaches the caller of `webm`.
        assert!(webm(&laced_opus_file(0x02, &[1, 9, 1])).is_err());
    }

    #[test]
    fn a_video_only_file_has_no_audio_and_no_error() {
        let media = webm(&webm_file("V_VP8", &[], &[])).expect("media");
        assert!(media.audio.is_none() && media.vorbis.is_none());
    }

    #[test]
    fn opus_packet_durations_follow_the_toc() {
        assert_eq!(opus_packet_us(&[0xF8]), Some(20_000));
        assert_eq!(opus_packet_us(&[0xF9]), Some(40_000));
        assert_eq!(opus_packet_us(&[0xFB, 3]), Some(60_000));
        assert_eq!(opus_packet_us(&[0x00]), Some(10_000));
        assert_eq!(opus_packet_us(&[]), None);
    }

    #[test]
    fn webm_gives_the_vorbis_track() {
        let private = vorbis_private(2, 48_000, &[5, 9]);
        let mut audio = element(&[0xD7], &[2]);
        audio.extend(element(&[0x86], b"A_VORBIS"));
        audio.extend(element(&[0x63, 0xA2], &private));
        let media = webm(&webm_file("V_VP8", &[], &[element(&[0xAE], &audio)])).expect("media");
        let track = media.vorbis.expect("vorbis");
        assert_eq!((track.channels, track.sample_rate), (2, 48_000));
        assert!(media.audio.is_none());
    }

    #[test]
    fn mp4_sample_entries_name_h264_and_av1() {
        // A visual sample entry: 78 bytes of fields, then the config box.
        let entry = |kind: &[u8; 4], config: &[u8]| {
            let mut body = vec![0u8; 78];
            body[24..26].copy_from_slice(&64u16.to_be_bytes());
            body[26..28].copy_from_slice(&48u16.to_be_bytes());
            body.extend(config);
            let mut stsd = vec![0u8; 8];
            stsd.extend(boxed(kind, &body));
            stsd
        };
        let avcc = boxed(
            b"avcC",
            &[1, 66, 0, 30, 0xFF, 0xE1, 0, 1, 0x67, 1, 0, 1, 0x68],
        );
        let track = sample_entry(&entry(b"avc1", &avcc));
        assert_eq!(track.codec, VideoCodec::H264);
        assert_eq!((track.width, track.height), (64, 48));
        assert_eq!(track.parameter_sets, vec![vec![0x67], vec![0x68]]);
        let av1c = boxed(b"av1C", &[0x81, 0, 0, 0, 0x0A]);
        let track = sample_entry(&entry(b"av01", &av1c));
        assert_eq!(track.codec, VideoCodec::Av1);
        assert_eq!(track.parameter_sets, vec![vec![0x0A]]);
        // A known name without its config box has no decoder to use.
        assert_eq!(sample_entry(&entry(b"avc1", &[])).codec, VideoCodec::Other);
    }
}
