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

//! Internet radio streams for the integrated player: the HTTP stream,
//! with Shoutcast/Icecast (ICY) metadata split from the audio, and the
//! playlist files stations publish.

use reqwest::header::{HeaderValue, CONTENT_TYPE};
use serde_json::Value;

/// A stream's audio codec, which the player decodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RadioCodec {
    Mp3,
    Vorbis,
}

impl RadioCodec {
    /// The file extension hint the decoder is given.
    pub fn extension(self) -> &'static str {
        match self {
            Self::Mp3 => "mp3",
            Self::Vorbis => "ogg",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Mp3 => "MP3",
            Self::Vorbis => "Ogg Vorbis",
        }
    }
}

/// Where a station publishes its current track.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NowPlayingSource {
    /// SomaFM's `songs/<id>.json`; the first song is the current one.
    SomaFm(&'static str),
    /// An Icecast `status-json.xsl`, read for the mount being streamed.
    IcecastStatus {
        url: &'static str,
        mount: &'static str,
    },
}

/// One station of the radio picker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RadioStation {
    pub id: &'static str,
    pub title: &'static str,
    pub genres: &'static [&'static str],
    pub description: &'static str,
    pub stream_url: &'static str,
    pub codec: RadioCodec,
    /// Kilobits per second, when the station states it.
    pub bitrate: Option<u32>,
    pub now_playing: Option<NowPlayingSource>,
}

/// The stations Cicchetto offers, in its order: SomaFM channels plus a few
/// other Icecast stations, as direct MP3 or Ogg Vorbis streams.
pub const RADIO_STATIONS: &[RadioStation] = &[
    RadioStation {
        id: "groovesalad",
        title: "Groove Salad",
        genres: &["ambient", "electronic"],
        description: "A nicely chilled plate of ambient/downtempo beats and grooves.",
        stream_url: "https://ice.somafm.com/groovesalad-128-mp3",
        codec: RadioCodec::Mp3,
        bitrate: Some(128),
        now_playing: Some(NowPlayingSource::SomaFm("https://api.somafm.com/songs/groovesalad.json")),
    },
    RadioStation {
        id: "dronezone",
        title: "Drone Zone",
        genres: &["ambient"],
        description: "Served best chilled, safe with most medications. Atmospheric textures with minimal beats.",
        stream_url: "https://ice.somafm.com/dronezone-128-mp3",
        codec: RadioCodec::Mp3,
        bitrate: Some(128),
        now_playing: Some(NowPlayingSource::SomaFm("https://api.somafm.com/songs/dronezone.json")),
    },
    RadioStation {
        id: "spacestation",
        title: "Space Station Soma",
        genres: &["electronic"],
        description: "Tune in, turn on, space out. Spaced-out ambient and mid-tempo electronica.",
        stream_url: "https://ice.somafm.com/spacestation-128-mp3",
        codec: RadioCodec::Mp3,
        bitrate: Some(128),
        now_playing: Some(NowPlayingSource::SomaFm("https://api.somafm.com/songs/spacestation.json")),
    },
    RadioStation {
        id: "lush",
        title: "Lush",
        genres: &["electronic"],
        description: "Sensuous and mellow female vocals, many with an electronic influence.",
        stream_url: "https://ice.somafm.com/lush-128-mp3",
        codec: RadioCodec::Mp3,
        bitrate: Some(128),
        now_playing: Some(NowPlayingSource::SomaFm("https://api.somafm.com/songs/lush.json")),
    },
    RadioStation {
        id: "indiepop",
        title: "Indie Pop Rocks!",
        genres: &["alternative", "rock"],
        description: "New and classic favorite indie pop tracks.",
        stream_url: "https://ice.somafm.com/indiepop-128-mp3",
        codec: RadioCodec::Mp3,
        bitrate: Some(128),
        now_playing: Some(NowPlayingSource::SomaFm("https://api.somafm.com/songs/indiepop.json")),
    },
    RadioStation {
        id: "u80s",
        title: "Underground 80s",
        genres: &["alternative", "electronic"],
        description: "Early 80s UK Synthpop and a bit of New Wave.",
        stream_url: "https://ice.somafm.com/u80s-128-mp3",
        codec: RadioCodec::Mp3,
        bitrate: Some(128),
        now_playing: Some(NowPlayingSource::SomaFm("https://api.somafm.com/songs/u80s.json")),
    },
    RadioStation {
        id: "secretagent",
        title: "Secret Agent",
        genres: &["lounge"],
        description: "The soundtrack for your stylish, mysterious, dangerous life. For Spies and PIs too!",
        stream_url: "https://ice.somafm.com/secretagent-128-mp3",
        codec: RadioCodec::Mp3,
        bitrate: Some(128),
        now_playing: Some(NowPlayingSource::SomaFm("https://api.somafm.com/songs/secretagent.json")),
    },
    RadioStation {
        id: "defcon",
        title: "DEF CON Radio",
        genres: &["electronic", "specials"],
        description: "Music for Hacking. The DEF CON Year-Round Channel.",
        stream_url: "https://ice.somafm.com/defcon-128-mp3",
        codec: RadioCodec::Mp3,
        bitrate: Some(128),
        now_playing: Some(NowPlayingSource::SomaFm("https://api.somafm.com/songs/defcon.json")),
    },
    RadioStation {
        id: "folkfwd",
        title: "Folk Forward",
        genres: &["folk", "alternative"],
        description: "Indie Folk, Alt-folk and the occasional folk classics. ",
        stream_url: "https://ice.somafm.com/folkfwd-128-mp3",
        codec: RadioCodec::Mp3,
        bitrate: Some(128),
        now_playing: Some(NowPlayingSource::SomaFm("https://api.somafm.com/songs/folkfwd.json")),
    },
    RadioStation {
        id: "bootliquor",
        title: "Boot Liquor",
        genres: &["americana"],
        description: "Americana Roots music for Cowhands, Cowpokes and Cowtippers",
        stream_url: "https://ice.somafm.com/bootliquor-128-mp3",
        codec: RadioCodec::Mp3,
        bitrate: Some(128),
        now_playing: Some(NowPlayingSource::SomaFm("https://api.somafm.com/songs/bootliquor.json")),
    },
    RadioStation {
        id: "bossa",
        title: "Bossa Beyond",
        genres: &["bossanova", "world"],
        description: "Silky-smooth, laid-back Brazilian-style rhythms of Bossa Nova, Samba and beyond",
        stream_url: "https://ice.somafm.com/bossa-128-mp3",
        codec: RadioCodec::Mp3,
        bitrate: Some(128),
        now_playing: Some(NowPlayingSource::SomaFm("https://api.somafm.com/songs/bossa.json")),
    },
    RadioStation {
        id: "reggae",
        title: "Heavyweight Reggae",
        genres: &["reggae"],
        description: "Reggae, Ska, Rocksteady classic and deep tracks.",
        stream_url: "https://ice.somafm.com/reggae-128-mp3",
        codec: RadioCodec::Mp3,
        bitrate: Some(160),
        now_playing: Some(NowPlayingSource::SomaFm("https://api.somafm.com/songs/reggae.json")),
    },
    RadioStation {
        id: "sonicuniverse",
        title: "Sonic Universe",
        genres: &["jazz"],
        description: "Transcending the world of jazz with eclectic, avant-garde takes on tradition.",
        stream_url: "https://ice.somafm.com/sonicuniverse-128-mp3",
        codec: RadioCodec::Mp3,
        bitrate: Some(128),
        now_playing: Some(NowPlayingSource::SomaFm("https://api.somafm.com/songs/sonicuniverse.json")),
    },
    RadioStation {
        id: "missioncontrol",
        title: "Mission Control",
        genres: &["ambient", "electronic"],
        description: "Celebrating NASA and Space Explorers everywhere.",
        stream_url: "https://ice.somafm.com/missioncontrol-128-mp3",
        codec: RadioCodec::Mp3,
        bitrate: Some(128),
        now_playing: Some(NowPlayingSource::SomaFm("https://api.somafm.com/songs/missioncontrol.json")),
    },
    RadioStation {
        id: "fluid",
        title: "Fluid",
        genres: &["electronic", "hiphop"],
        description: "Drown in the electronic sound of instrumental hiphop, future soul and liquid trap.",
        stream_url: "https://ice.somafm.com/fluid-128-mp3",
        codec: RadioCodec::Mp3,
        bitrate: Some(128),
        now_playing: Some(NowPlayingSource::SomaFm("https://api.somafm.com/songs/fluid.json")),
    },
    RadioStation {
        id: "metal",
        title: "Metal Detector",
        genres: &["metal"],
        description: "From black to doom, prog to sludge, thrash to post, stoner to crossover, punk to industrial.",
        stream_url: "https://ice.somafm.com/metal-128-mp3",
        codec: RadioCodec::Mp3,
        bitrate: Some(128),
        now_playing: Some(NowPlayingSource::SomaFm("https://api.somafm.com/songs/metal.json")),
    },
    RadioStation {
        id: "seventies",
        title: "Left Coast 70s",
        genres: &["70s", "rock"],
        description: "Mellow album rock from the Seventies. Yacht not required.",
        stream_url: "https://ice.somafm.com/seventies-128-mp3",
        codec: RadioCodec::Mp3,
        bitrate: Some(128),
        now_playing: Some(NowPlayingSource::SomaFm("https://api.somafm.com/songs/seventies.json")),
    },
    RadioStation {
        id: "poptron",
        title: "PopTron",
        genres: &["alternative"],
        description: "Electropop and indie dance rock with sparkle and pop.",
        stream_url: "https://ice.somafm.com/poptron-128-mp3",
        codec: RadioCodec::Mp3,
        bitrate: Some(128),
        now_playing: Some(NowPlayingSource::SomaFm("https://api.somafm.com/songs/poptron.json")),
    },
    RadioStation {
        id: "covers",
        title: "Covers",
        genres: &["eclectic"],
        description: "Just covers. Songs you know by artists you don't. We've got you covered.",
        stream_url: "https://ice.somafm.com/covers-128-mp3",
        codec: RadioCodec::Mp3,
        bitrate: Some(128),
        now_playing: Some(NowPlayingSource::SomaFm("https://api.somafm.com/songs/covers.json")),
    },
    RadioStation {
        id: "brfm",
        title: "Black Rock FM",
        genres: &["eclectic"],
        description: "From the Black Rock Desert playa to the world, year round!",
        stream_url: "https://ice.somafm.com/brfm-128-mp3",
        codec: RadioCodec::Mp3,
        bitrate: Some(128),
        now_playing: Some(NowPlayingSource::SomaFm("https://api.somafm.com/songs/brfm.json")),
    },
    RadioStation {
        id: "doomed",
        title: "Doomed",
        genres: &["ambient", "industrial"],
        description: "Where every day is Halloween: dark industrial/ambient music for tortured souls.",
        stream_url: "https://ice.somafm.com/doomed-128-mp3",
        codec: RadioCodec::Mp3,
        bitrate: Some(128),
        now_playing: Some(NowPlayingSource::SomaFm("https://api.somafm.com/songs/doomed.json")),
    },
    RadioStation {
        id: "rockantenne-metal",
        title: "ROCK ANTENNE Heavy Metal",
        genres: &["metal", "rock"],
        description: "Heavy metal around the clock, from Bavaria's rock station.",
        stream_url: "https://stream.rockantenne.de/heavy-metal/stream/mp3",
        codec: RadioCodec::Mp3,
        bitrate: Some(128),
        now_playing: None,
    },
    RadioStation {
        id: "kohina",
        title: "Kohina",
        genres: &["chiptune", "demoscene"],
        description: "Hand picked chip tunes from classic computers and consoles. SID, Amiga, Atari ST, Arcade, PC, and more!",
        stream_url: "https://kohina.brona.dk/icecast/stream.ogg",
        codec: RadioCodec::Vorbis,
        bitrate: Some(128),
        now_playing: Some(NowPlayingSource::IcecastStatus {
            url: "https://kohina.brona.dk/icecast/status-json.xsl",
            mount: "/stream.ogg",
        }),
    },
    RadioStation {
        id: "knac",
        title: "KNAC Pure Rock",
        genres: &["rock", "metal"],
        description: "Hard rock and metal out of Los Angeles. The loudest dot com on the planet.",
        stream_url: "https://s6.autopo.st/proxy/ggjdvxin?mp=/stream",
        codec: RadioCodec::Mp3,
        bitrate: Some(128),
        now_playing: None,
    },
];

/// A station's current track; `artist` is `None` when the feed gives one
/// joined line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Track {
    pub artist: Option<String>,
    pub title: String,
}

impl Track {
    /// `Artist — Title`, or the title alone.
    pub fn label(&self) -> String {
        match &self.artist {
            Some(artist) => format!("{artist} — {}", self.title),
            None => self.title.clone(),
        }
    }
}

/// The `/np` action text, as Cicchetto sends it.
pub fn now_playing_line(track: &Track, station: &str) -> String {
    format!("is now playing: {} [{station}]", track.label())
}

/// How often the now-playing feed is read, and after how long without an
/// answer the last track counts as stale (Cicchetto's 60 s and 3 polls).
pub const NOW_PLAYING_POLL_SECS: u64 = 60;
pub const NOW_PLAYING_STALE_SECS: u64 = NOW_PLAYING_POLL_SECS * 3;

fn trimmed(value: Option<&Value>) -> String {
    value
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or_default()
        .to_string()
}

/// The first song of a SomaFM `songs/<id>.json` feed.
pub fn parse_somafm_songs(body: &Value) -> Option<Track> {
    let first = body.get("songs")?.as_array()?.first()?;
    let title = trimmed(first.get("title"));
    if title.is_empty() {
        return None;
    }
    let artist = trimmed(first.get("artist"));
    Some(Track {
        artist: (!artist.is_empty()).then_some(artist),
        title,
    })
}

/// The title of `mount` in an Icecast `status-json.xsl` document.
pub fn parse_icecast_status(body: &Value, mount: &str) -> Option<Track> {
    let sources = body.get("icestats")?.get("source")?;
    let sources = match sources {
        Value::Array(sources) => sources.clone(),
        single => vec![single.clone()],
    };
    let row = sources.iter().find(|row| {
        let listen = trimmed(row.get("listenurl"));
        reqwest::Url::parse(&listen).is_ok_and(|url| url.path() == mount)
    })?;
    let title = trimmed(row.get("title"));
    (!title.is_empty()).then_some(Track {
        artist: None,
        title,
    })
}

/// Reads a station's now-playing feed; `None` for no usable answer.
pub async fn fetch_now_playing(source: NowPlayingSource) -> Option<Track> {
    let url = match source {
        NowPlayingSource::SomaFm(url) => url,
        NowPlayingSource::IcecastStatus { url, .. } => url,
    };
    let http = reqwest::Client::builder()
        .user_agent(concat!("Cordiale/", env!("CARGO_PKG_VERSION")))
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .ok()?;
    let body: Value = http
        .get(url)
        .send()
        .await
        .ok()?
        .error_for_status()
        .ok()?
        .json()
        .await
        .ok()?;
    match source {
        NowPlayingSource::SomaFm(_) => parse_somafm_songs(&body),
        NowPlayingSource::IcecastStatus { mount, .. } => parse_icecast_status(&body, mount),
    }
}

/// What an ICY stream carries: audio bytes, or a new track title.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IcyChunk {
    Audio(Vec<u8>),
    Title(String),
}

/// Splits an ICY stream into audio and titles. With `icy-metaint: N` the
/// server sends N audio bytes, then one length byte (times 16) of
/// metadata such as `StreamTitle='Artist - Title';`, and so on. Without
/// the header everything is audio.
#[derive(Debug, Clone)]
pub struct IcyDemuxer {
    metaint: Option<usize>,
    until_meta: usize,
    meta_remaining: Option<usize>,
    meta: Vec<u8>,
}

impl IcyDemuxer {
    pub fn new(metaint: Option<usize>) -> Self {
        let metaint = metaint.filter(|interval| *interval > 0);
        Self {
            metaint,
            until_meta: metaint.unwrap_or(0),
            meta_remaining: None,
            meta: Vec::new(),
        }
    }

    /// Feeds bytes as they arrive; audio comes out in order, with a title
    /// wherever a metadata block carried one.
    pub fn push(&mut self, mut bytes: &[u8]) -> Vec<IcyChunk> {
        let mut chunks = Vec::new();
        let Some(metaint) = self.metaint else {
            if !bytes.is_empty() {
                chunks.push(IcyChunk::Audio(bytes.to_vec()));
            }
            return chunks;
        };
        let mut audio = Vec::new();
        while !bytes.is_empty() {
            match self.meta_remaining {
                None if self.until_meta > 0 => {
                    let take = self.until_meta.min(bytes.len());
                    audio.extend_from_slice(&bytes[..take]);
                    self.until_meta -= take;
                    bytes = &bytes[take..];
                }
                None => {
                    let length = usize::from(bytes[0]) * 16;
                    bytes = &bytes[1..];
                    if length == 0 {
                        self.until_meta = metaint;
                    } else {
                        self.meta_remaining = Some(length);
                        self.meta.clear();
                    }
                }
                Some(remaining) => {
                    let take = remaining.min(bytes.len());
                    self.meta.extend_from_slice(&bytes[..take]);
                    bytes = &bytes[take..];
                    if take == remaining {
                        self.meta_remaining = None;
                        self.until_meta = metaint;
                        if !audio.is_empty() {
                            chunks.push(IcyChunk::Audio(std::mem::take(&mut audio)));
                        }
                        if let Some(title) = stream_title(&self.meta) {
                            chunks.push(IcyChunk::Title(title));
                        }
                    } else {
                        self.meta_remaining = Some(remaining - take);
                    }
                }
            }
        }
        if !audio.is_empty() {
            chunks.push(IcyChunk::Audio(audio));
        }
        chunks
    }
}

/// The `StreamTitle` of an ICY metadata block, if it has one.
pub fn stream_title(meta: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(meta);
    let text = text.trim_end_matches('\0');
    let start = text.find("StreamTitle='")? + "StreamTitle='".len();
    let rest = &text[start..];
    let end = rest.find("';").unwrap_or(rest.len());
    let title = rest[..end].trim();
    (!title.is_empty()).then(|| title.to_string())
}

/// Stream URLs listed in a `.pls` or `.m3u` playlist, in order.
pub fn playlist_urls(playlist: &str) -> Vec<String> {
    playlist
        .lines()
        .map(str::trim)
        .filter_map(|line| {
            let url = match line.split_once('=') {
                Some((key, value)) if key.to_ascii_lowercase().starts_with("file") => value.trim(),
                _ => line,
            };
            (url.starts_with("http://") || url.starts_with("https://")).then(|| url.to_string())
        })
        .collect()
}

/// Why a stream couldn't be opened or read.
#[derive(Debug)]
pub enum RadioError {
    Http(reqwest::Error),
    /// A playlist that lists no stream.
    EmptyPlaylist,
}

impl std::fmt::Display for RadioError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Http(err) => write!(f, "{err}"),
            Self::EmptyPlaylist => write!(f, "the playlist lists no stream"),
        }
    }
}

impl From<reqwest::Error> for RadioError {
    fn from(err: reqwest::Error) -> Self {
        Self::Http(err)
    }
}

/// An open radio stream.
pub struct RadioStream {
    response: reqwest::Response,
    demuxer: IcyDemuxer,
    /// The server's `Content-Type`, such as `audio/mpeg` or `application/ogg`.
    pub content_type: Option<String>,
}

impl RadioStream {
    /// Connects to `url`, asking for ICY titles. A playlist URL is
    /// followed to its first stream.
    pub async fn open(url: &str) -> Result<Self, RadioError> {
        let http = reqwest::Client::builder()
            .user_agent(concat!("Cordiale/", env!("CARGO_PKG_VERSION")))
            .build()?;
        let mut response = Self::get(&http, url).await?;
        if is_playlist(url, response.headers().get(CONTENT_TYPE)) {
            let text = response.text().await?;
            let stream = playlist_urls(&text)
                .into_iter()
                .next()
                .ok_or(RadioError::EmptyPlaylist)?;
            response = Self::get(&http, &stream).await?;
        }
        let metaint = response
            .headers()
            .get("icy-metaint")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.trim().parse().ok());
        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        Ok(Self {
            response,
            demuxer: IcyDemuxer::new(metaint),
            content_type,
        })
    }

    async fn get(http: &reqwest::Client, url: &str) -> Result<reqwest::Response, reqwest::Error> {
        http.get(url)
            .header("Icy-MetaData", "1")
            .send()
            .await?
            .error_for_status()
    }

    /// The next audio and titles; `None` when the server ends the stream.
    pub async fn next(&mut self) -> Result<Option<Vec<IcyChunk>>, RadioError> {
        Ok(self
            .response
            .chunk()
            .await?
            .map(|bytes| self.demuxer.push(&bytes)))
    }
}

fn is_playlist(url: &str, content_type: Option<&HeaderValue>) -> bool {
    let path = url
        .split(['?', '#'])
        .next()
        .unwrap_or(url)
        .to_ascii_lowercase();
    let content_type = content_type
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();
    path.ends_with(".pls")
        || path.ends_with(".m3u")
        || content_type.contains("scpls")
        || content_type.contains("mpegurl")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn now_playing_feeds_and_line() {
        let soma = serde_json::json!({"songs": [
            {"title": " Roygbiv ", "artist": "Boards of Canada"},
            {"title": "older", "artist": "x"}
        ]});
        let track = parse_somafm_songs(&soma).expect("a track");
        assert_eq!(
            now_playing_line(&track, "Groove Salad"),
            "is now playing: Boards of Canada — Roygbiv [Groove Salad]"
        );
        assert_eq!(parse_somafm_songs(&serde_json::json!({"songs": []})), None);
        let icecast = serde_json::json!({"icestats": {"source": [
            {"listenurl": "http://host:8000/other.mp3", "title": "nope"},
            {"listenurl": "http://host:8000/stream.ogg", "title": "Hubbard - Commando"}
        ]}});
        let track = parse_icecast_status(&icecast, "/stream.ogg").expect("a track");
        assert_eq!(track.label(), "Hubbard - Commando");
        let single = serde_json::json!({"icestats": {"source":
            {"listenurl": "http://host/stream.ogg", "title": "solo"}}});
        assert!(parse_icecast_status(&single, "/stream.ogg").is_some());
        assert_eq!(parse_icecast_status(&icecast, "/missing"), None);
    }

    #[test]
    fn stations_are_mp3_or_vorbis_with_unique_ids() {
        let mut ids: Vec<&str> = RADIO_STATIONS.iter().map(|station| station.id).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), RADIO_STATIONS.len());
        assert!(RADIO_STATIONS
            .iter()
            .any(|station| station.codec == RadioCodec::Vorbis));
        assert!(RADIO_STATIONS
            .iter()
            .all(|station| station.stream_url.starts_with("https://")));
    }

    #[test]
    fn demuxer_splits_audio_and_titles_across_pushes() {
        let meta = b"StreamTitle='Boards of Canada - Roygbiv';StreamUrl='';";
        let mut block = vec![0u8; 64];
        block[..meta.len()].copy_from_slice(meta);
        let mut stream = b"abcd".to_vec();
        stream.push(4); // 4 * 16 = 64 bytes of metadata
        stream.extend_from_slice(&block);
        stream.extend_from_slice(b"efgh");
        stream.push(0); // an empty metadata block
        stream.extend_from_slice(b"ij");

        let mut demuxer = IcyDemuxer::new(Some(4));
        let mut chunks = Vec::new();
        for piece in stream.chunks(3) {
            chunks.extend(demuxer.push(piece));
        }
        let audio: Vec<u8> = chunks
            .iter()
            .filter_map(|chunk| match chunk {
                IcyChunk::Audio(bytes) => Some(bytes.clone()),
                IcyChunk::Title(_) => None,
            })
            .flatten()
            .collect();
        assert_eq!(audio, b"abcdefghij");
        assert!(chunks.contains(&IcyChunk::Title("Boards of Canada - Roygbiv".to_string())));
    }

    #[test]
    fn without_metaint_everything_is_audio() {
        let mut demuxer = IcyDemuxer::new(None);
        assert_eq!(
            demuxer.push(b"OggS"),
            vec![IcyChunk::Audio(b"OggS".to_vec())]
        );
        assert_eq!(stream_title(b"StreamTitle='';\0\0"), None);
    }

    #[test]
    fn playlists_list_their_streams() {
        let pls = "[playlist]\nnumberofentries=2\nFile1=https://ice1.somafm.com/groovesalad-128-mp3\nTitle1=Groove Salad\nFile2=https://ice2.somafm.com/groovesalad-128-mp3\n";
        assert_eq!(
            playlist_urls(pls),
            vec![
                "https://ice1.somafm.com/groovesalad-128-mp3",
                "https://ice2.somafm.com/groovesalad-128-mp3"
            ]
        );
        let m3u = "#EXTM3U\n#EXTINF:-1,Station\nhttp://example.org/stream.ogg\n";
        assert_eq!(playlist_urls(m3u), vec!["http://example.org/stream.ogg"]);
        assert!(is_playlist("https://somafm.com/groovesalad.pls", None));
        assert!(!is_playlist(
            "https://ice1.somafm.com/groovesalad-128-mp3",
            None
        ));
    }
}
