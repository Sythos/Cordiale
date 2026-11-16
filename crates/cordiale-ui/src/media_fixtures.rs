//! Small video files for the tests. Each one is a valid file that the player
//! decodes: an MP4 with one H.264 picture and a WebM with one VP8 picture.
//! Both pictures are 32x16 pixels, two macroblocks wide.

/// Width and height of the picture in both files.
pub const PICTURE_SIZE: (u32, u32) = (32, 16);

/// Writes bits, most significant bit first.
#[derive(Default)]
struct Bits {
    bytes: Vec<u8>,
    used: u8,
}

impl Bits {
    fn bit(&mut self, value: bool) {
        if self.used == 0 {
            self.bytes.push(0);
        }
        if value {
            let last = self.bytes.len() - 1;
            self.bytes[last] |= 0x80 >> self.used;
        }
        self.used = (self.used + 1) % 8;
    }

    fn bits(&mut self, value: u32, count: u32) {
        for shift in (0..count).rev() {
            self.bit((value >> shift) & 1 == 1);
        }
    }

    /// An unsigned Exp-Golomb number.
    fn ue(&mut self, value: u32) {
        let coded = value + 1;
        let length = 32 - coded.leading_zeros();
        self.bits(0, length - 1);
        self.bits(coded, length);
    }

    /// Zero bits up to the next byte.
    fn align(&mut self) {
        while self.used != 0 {
            self.bit(false);
        }
    }

    fn raw(&mut self, data: &[u8]) {
        assert_eq!(self.used, 0);
        self.bytes.extend_from_slice(data);
    }

    /// The stop bit and the zero bits after it.
    fn finish(mut self) -> Vec<u8> {
        self.bit(true);
        self.align();
        self.bytes
    }
}

/// The sequence parameter set: baseline profile, two macroblocks by one.
fn h264_sps() -> Vec<u8> {
    let mut bits = Bits::default();
    bits.bits(0x67, 8);
    bits.bits(66, 8);
    bits.bits(0xC0, 8);
    bits.bits(30, 8);
    bits.ue(0); // sequence parameter set id
    bits.ue(0); // log2 max frame number minus 4
    bits.ue(2); // picture order count type
    bits.ue(1); // reference frames
    bits.bit(false); // gaps in frame number
    bits.ue(1); // width in macroblocks minus 1
    bits.ue(0); // height in map units minus 1
    bits.bit(true); // frame macroblocks only
    bits.bit(true); // direct 8x8 inference
    bits.bit(false); // cropping
    bits.bit(false); // video usability information
    bits.finish()
}

fn h264_pps() -> Vec<u8> {
    let mut bits = Bits::default();
    bits.bits(0x68, 8);
    bits.ue(0); // picture parameter set id
    bits.ue(0); // sequence parameter set id
    bits.bit(false); // CAVLC
    bits.bit(false); // bottom field picture order
    bits.ue(0); // slice groups minus 1
    bits.ue(0); // reference index 0 minus 1
    bits.ue(0); // reference index 1 minus 1
    bits.bit(false); // weighted prediction
    bits.bits(0, 2); // weighted bi-prediction
    bits.ue(0); // initial QP minus 26
    bits.ue(0); // initial QS minus 26
    bits.ue(0); // chroma QP offset
    bits.bit(false); // deblocking control
    bits.bit(false); // constrained intra prediction
    bits.bit(false); // redundant picture count
    bits.finish()
}

/// An IDR slice of two I_PCM macroblocks: the left one dark, the right one
/// bright, so a test sees the order of the pixels. The samples are never
/// zero, so the data needs no emulation prevention bytes.
fn h264_slice() -> Vec<u8> {
    let mut bits = Bits::default();
    bits.bits(0x65, 8);
    bits.ue(0); // first macroblock
    bits.ue(7); // slice type I, all slices
    bits.ue(0); // picture parameter set id
    bits.bits(0, 4); // frame number
    bits.ue(0); // IDR picture id
    bits.bit(false); // no output of prior pictures
    bits.bit(false); // long term reference
    bits.ue(0); // slice QP delta
    for luma in [0x20u8, 0xE0] {
        bits.ue(25); // I_PCM
        bits.align();
        bits.raw(&[luma; 256]);
        bits.raw(&[0x80; 128]);
    }
    bits.finish()
}

fn mp4_box(kind: &[u8; 4], body: &[u8]) -> Vec<u8> {
    let mut out = u32::try_from(body.len() + 8)
        .expect("box size")
        .to_be_bytes()
        .to_vec();
    out.extend_from_slice(kind);
    out.extend_from_slice(body);
    out
}

/// A box with a version and flags field, then 32-bit words.
fn mp4_words(kind: &[u8; 4], words: &[u32]) -> Vec<u8> {
    let mut body = vec![0u8; 4];
    for word in words {
        body.extend_from_slice(&word.to_be_bytes());
    }
    mp4_box(kind, &body)
}

/// The `moov` box for one sample of `size` bytes at file offset `offset`.
fn mp4_movie(size: u32, offset: u32) -> Vec<u8> {
    let sps = h264_sps();
    let pps = h264_pps();
    let mut avcc = vec![1, sps[1], sps[2], sps[3], 0xFF, 0xE1];
    avcc.extend_from_slice(&u16::try_from(sps.len()).expect("size").to_be_bytes());
    avcc.extend_from_slice(&sps);
    avcc.push(1);
    avcc.extend_from_slice(&u16::try_from(pps.len()).expect("size").to_be_bytes());
    avcc.extend_from_slice(&pps);

    let mut entry = vec![0u8; 6];
    entry.extend_from_slice(&1u16.to_be_bytes()); // data reference index
    entry.extend_from_slice(&[0u8; 16]);
    entry.extend_from_slice(&(PICTURE_SIZE.0 as u16).to_be_bytes());
    entry.extend_from_slice(&(PICTURE_SIZE.1 as u16).to_be_bytes());
    entry.extend_from_slice(&0x0048_0000u32.to_be_bytes()); // 72 dpi
    entry.extend_from_slice(&0x0048_0000u32.to_be_bytes());
    entry.extend_from_slice(&[0u8; 4]);
    entry.extend_from_slice(&1u16.to_be_bytes()); // frame count
    entry.extend_from_slice(&[0u8; 32]); // compressor name
    entry.extend_from_slice(&0x0018u16.to_be_bytes()); // depth
    entry.extend_from_slice(&0xFFFFu16.to_be_bytes());
    entry.extend(mp4_box(b"avcC", &avcc));

    let mut stsd = vec![0u8; 4];
    stsd.extend_from_slice(&1u32.to_be_bytes());
    stsd.extend(mp4_box(b"avc1", &entry));

    let mut stbl = mp4_box(b"stsd", &stsd);
    stbl.extend(mp4_words(b"stts", &[1, 1, 1000]));
    stbl.extend(mp4_words(b"stsc", &[1, 1, 1, 1]));
    stbl.extend(mp4_words(b"stsz", &[0, 1, size]));
    stbl.extend(mp4_words(b"stco", &[1, offset]));
    let minf = mp4_box(b"minf", &mp4_box(b"stbl", &stbl));

    // Version, times, time scale 1000, duration 1000, language, quality.
    let mdhd = mp4_words(b"mdhd", &[0, 0, 1000, 1000, 0x55C4_0000]);
    let mut hdlr = vec![0u8; 8];
    hdlr.extend_from_slice(b"vide");
    hdlr.extend_from_slice(&[0u8; 12]);
    hdlr.push(0);
    let mut mdia = mdhd;
    mdia.extend(mp4_box(b"hdlr", &hdlr));
    mdia.extend(minf);
    mp4_box(b"moov", &mp4_box(b"trak", &mp4_box(b"mdia", &mdia)))
}

/// An MP4 file with one H.264 picture, [`PICTURE_SIZE`] pixels.
pub fn mp4_h264() -> Vec<u8> {
    let slice = h264_slice();
    let mut sample = u32::try_from(slice.len())
        .expect("slice size")
        .to_be_bytes()
        .to_vec();
    sample.extend_from_slice(&slice);
    let mut ftyp = b"isom".to_vec();
    ftyp.extend_from_slice(&[0u8; 4]);
    ftyp.extend_from_slice(b"isomavc1");
    let mut file = mp4_box(b"ftyp", &ftyp);
    // The size of the movie box does not depend on the offset it holds.
    let sample_size = u32::try_from(sample.len()).expect("sample size");
    let movie_size = mp4_movie(sample_size, 0).len();
    let offset = u32::try_from(file.len() + movie_size + 8).expect("offset");
    file.extend(mp4_movie(sample_size, offset));
    file.extend(mp4_box(b"mdat", &sample));
    file
}

/// An EBML element with an eight-byte size.
fn element(id: &[u8], body: &[u8]) -> Vec<u8> {
    let mut out = id.to_vec();
    out.push(0x01);
    out.extend_from_slice(&(body.len() as u64).to_be_bytes()[1..]);
    out.extend_from_slice(body);
    out
}

/// A VP8 key frame of [`PICTURE_SIZE`] pixels. Both partitions hold zero
/// bytes, and a bool decoder reads zero bits from them whatever the
/// probabilities are: B_PRED with DC prediction, no residual and no
/// loop filter, which is a valid picture of one flat color.
fn vp8_key_frame() -> Vec<u8> {
    const FIRST_PARTITION: usize = 128;
    const TOKEN_PARTITION: usize = 128;
    // Key frame (bit 0 is 0), version 0, shown, size of the first partition.
    let tag = (1u32 << 4) | ((FIRST_PARTITION as u32) << 5);
    let mut frame = tag.to_le_bytes()[..3].to_vec();
    frame.extend_from_slice(&[0x9D, 0x01, 0x2A]);
    frame.extend_from_slice(&(PICTURE_SIZE.0 as u16).to_le_bytes());
    frame.extend_from_slice(&(PICTURE_SIZE.1 as u16).to_le_bytes());
    frame.extend(vec![0u8; FIRST_PARTITION + TOKEN_PARTITION]);
    frame
}

/// A WebM file with one VP8 picture, [`PICTURE_SIZE`] pixels.
pub fn webm_vp8() -> Vec<u8> {
    let mut header = element(&[0x42, 0x82], b"webm");
    header.extend(element(&[0x42, 0x87], &[4]));
    header.extend(element(&[0x42, 0x85], &[2]));
    let mut video = element(&[0xB0], &(PICTURE_SIZE.0 as u16).to_be_bytes());
    video.extend(element(&[0xBA], &(PICTURE_SIZE.1 as u16).to_be_bytes()));
    let mut track = element(&[0xD7], &[1]);
    track.extend(element(&[0x83], &[1]));
    track.extend(element(&[0x86], b"V_VP8"));
    track.extend(element(&[0xE0], &video));
    let tracks = element(&[0x16, 0x54, 0xAE, 0x6B], &element(&[0xAE], &track));
    // Track 1, time 0, key frame.
    let mut block = vec![0x81, 0, 0, 0x80];
    block.extend(vp8_key_frame());
    let mut cluster = element(&[0xE7], &[0]);
    cluster.extend(element(&[0xA3], &block));
    let mut segment = tracks;
    segment.extend(element(&[0x1F, 0x43, 0xB6, 0x75], &cluster));
    let mut file = element(&[0x1A, 0x45, 0xDF, 0xA3], &header);
    file.extend(element(&[0x18, 0x53, 0x80, 0x67], &segment));
    file
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_bit_writer_codes_exp_golomb_numbers() {
        let mut bits = Bits::default();
        bits.ue(0); // 1
        bits.ue(7); // 0001000
        bits.align();
        assert_eq!(bits.bytes, vec![0b1000_1000]);
        let mut bits = Bits::default();
        bits.ue(25); // 000011010
        assert_eq!(bits.finish(), vec![0b0000_1101, 0b0100_0000]);
    }

    #[test]
    fn the_files_have_the_expected_containers() {
        let mp4 = crate::media_demux::mp4_video(&mp4_h264()).expect("mp4");
        assert_eq!(mp4.codec, crate::media_demux::VideoCodec::H264);
        assert_eq!((mp4.width, mp4.height), PICTURE_SIZE);
        assert_eq!(mp4.samples.len(), 1);
        let webm = crate::media_demux::webm(&webm_vp8())
            .expect("webm")
            .video
            .expect("video");
        assert_eq!(webm.codec, crate::media_demux::VideoCodec::Vp8);
        assert_eq!((webm.width, webm.height), PICTURE_SIZE);
        assert_eq!(webm.samples.len(), 1);
    }
}
