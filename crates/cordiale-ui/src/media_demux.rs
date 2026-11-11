//! Container readers for the in-app video player: MP4/MOV/M4V and WebM.
//!
//! Each reader finds the first video track and the sample list that the
//! decoder needs. WebM also gives the Opus packets. The readers only read
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
    Hevc,
    Vp9,
    /// The track exists, but no decoder is built in for it.
    Other,
}

#[derive(Debug, Clone)]
pub struct VideoTrack {
    pub codec: VideoCodec,
    pub width: u32,
    pub height: u32,
    /// HEVC: the parameter set NAL units from `hvcC`, in file order.
    pub parameter_sets: Vec<Vec<u8>>,
    /// HEVC: bytes of the length field before each NAL unit in a sample.
    pub nal_length_size: usize,
    pub samples: Vec<Sample>,
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
    if &kind != b"hvc1" && &kind != b"hev1" {
        return track;
    }
    let Some(extra) = body.get(78..) else {
        return track;
    };
    if let Some(hvcc) = child(&boxes(extra), b"hvcC") {
        if let Some((length_size, sets)) = hevc_config(hvcc) {
            track.codec = VideoCodec::Hevc;
            track.nal_length_size = length_size;
            track.parameter_sets = sets;
        }
    }
    track
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
    let mut positions = Vec::with_capacity(count);
    for run in 0..runs {
        let first = be32(stsc, 8 + 12 * run).ok_or_else(bad)? as usize;
        let per_chunk = be32(stsc, 12 + 12 * run).ok_or_else(bad)? as usize;
        let end = match be32(stsc, 8 + 12 * (run + 1)) {
            Some(next) if run + 1 < runs => next as usize,
            _ => offsets.len() + 1,
        };
        for chunk in first.max(1)..end.min(offsets.len() + 1) {
            let mut at = offsets[chunk - 1];
            for _ in 0..per_chunk {
                if positions.len() >= count {
                    break;
                }
                let size = sizes[positions.len()];
                positions.push((at, size));
                at = at.checked_add(size).ok_or_else(bad)?;
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
    let keys: Option<Vec<usize>> = child(stbl, b"stss").map(|stss| {
        let entries = be32(stss, 4).unwrap_or(0) as usize;
        (0..entries)
            .filter_map(|entry| be32(stss, 8 + 4 * entry))
            .map(|number| number as usize)
            .collect()
    });
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

#[derive(Default)]
struct Entry {
    number: u64,
    codec: String,
    private: Vec<u8>,
    width: u32,
    height: u32,
}

#[derive(Default)]
struct Walker {
    scale_ns: u64,
    duration: f64,
    entries: Vec<Entry>,
    cluster_time: i64,
    /// Track number, offset, size, time in timecode units, key frame.
    blocks: Vec<(u64, usize, usize, i64, bool)>,
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
        // Laced blocks are not read.
        if flags & 0x06 != 0 || self.blocks.len() >= MAX_SAMPLES {
            return;
        }
        let key = group_key.unwrap_or(flags & 0x80 != 0);
        let header = length + 3;
        self.blocks.push((
            track,
            base + header,
            body.len() - header,
            self.cluster_time + i64::from(relative as i16),
            key,
        ));
    }
}

/// The video and the Opus audio of a WebM file.
pub fn webm(data: &[u8]) -> Result<WebmMedia, String> {
    let mut walker = Walker {
        scale_ns: 1_000_000,
        ..Walker::default()
    };
    walker.walk(data, 0, 0);
    let unit_us = |ticks: i64| ticks.saturating_mul(walker.scale_ns as i64) / 1000;
    let mut media = WebmMedia::default();
    if walker.duration > 0.0 {
        media.duration_us = Some(unit_us(walker.duration as i64));
    }
    for entry in &walker.entries {
        let samples = || -> Vec<(usize, usize, i64, bool)> {
            walker
                .blocks
                .iter()
                .filter(|block| block.0 == entry.number)
                .map(|block| (block.1, block.2, unit_us(block.3), block.4))
                .collect()
        };
        match entry.codec.as_str() {
            codec @ ("V_VP9" | "V_VP8" | "V_AV1" | "V_MPEGH/ISO/HEVC") if media.video.is_none() => {
                let list = samples();
                let first = list.iter().map(|sample| sample.2).min().unwrap_or(0);
                media.video = Some(VideoTrack {
                    codec: if codec == "V_VP9" {
                        VideoCodec::Vp9
                    } else {
                        VideoCodec::Other
                    },
                    width: entry.width,
                    height: entry.height,
                    parameter_sets: Vec::new(),
                    nal_length_size: 4,
                    samples: list
                        .into_iter()
                        .map(|(offset, size, pts_us, key)| Sample {
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
                    packets: samples()
                        .into_iter()
                        .map(|(offset, size, pts_us, _)| (offset, size, pts_us))
                        .collect(),
                });
            }
            _ => {}
        }
    }
    if media.video.is_none() {
        return Err("no video track".to_string());
    }
    Ok(media)
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
}
