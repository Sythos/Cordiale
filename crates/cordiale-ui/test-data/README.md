# Test data

Small audio files for the tests of the media player. The sound of every file
is a synthetic sine tone made with FFmpeg, so the files hold no third-party
content and have no licence issue. Every file is smaller than 12 KB.

| File | Content | Command |
|---|---|---|
| `tone_aac_lc_stereo.m4a` | AAC-LC, 2 channels, 44100 Hz, 1 s | `ffmpeg -y -f lavfi -i "sine=frequency=440:sample_rate=44100:duration=1" -ac 2 -c:a aac -b:a 48k -movflags +faststart tone_aac_lc_stereo.m4a` |
| `tone_aac_lc_mono_8k.m4a` | AAC-LC, 1 channel, 8000 Hz, 0.5 s | `ffmpeg -y -f lavfi -i "sine=frequency=440:sample_rate=8000:duration=0.5" -ac 1 -c:a aac -b:a 24k -movflags +faststart tone_aac_lc_mono_8k.m4a` |
| `tone_aac_51.m4a` | AAC-LC, 6 channels (5.1), 44100 Hz, 0.3 s. No decoder of the player plays it. | `ffmpeg -y -f lavfi -i "sine=frequency=440:sample_rate=44100:duration=0.3" -ac 6 -channel_layout 5.1 -c:a aac -b:a 96k -movflags +faststart tone_aac_51.m4a` |
| `tone_ac3.mp4` | AC-3, 2 channels, 48000 Hz, 0.3 s. No decoder of the player plays it. | `ffmpeg -y -f lavfi -i "sine=frequency=440:sample_rate=48000:duration=0.3" -ac 2 -c:a ac3 -b:a 96k -movflags +faststart tone_ac3.mp4` |
| `tone_he_aac_explicit_sbr.m4a` | The stereo AAC-LC file, with an audio specific configuration that signals SBR (HE-AAC) in the explicit way. The AAC data is plain AAC-LC. | see below |

## `tone_he_aac_explicit_sbr.m4a`

The file is `tone_aac_lc_stereo.m4a` with one change: the 5 bytes of the audio
specific configuration, `12 10 56 e5 00`, are replaced by `2a 10 88 00 00`.
The new bytes say: object type 5 (SBR), sampling frequency index 4 (44100 Hz),
channel configuration 2, extension sampling frequency index 1 (88200 Hz),
underlying object type 2 (AAC-LC), and three zero flags of the AAC-LC set-up.
The 0.6 series of symphonia refuses such a stream. The 0.5 series reads the
AAC-LC layer.

```python
data = bytearray(open("tone_aac_lc_stereo.m4a", "rb").read())
old = bytes.fromhex("1210" "56e500")
assert data.count(old) == 1
at = data.find(old)
data[at:at + 5] = bytes.fromhex("2a10880000")
open("tone_he_aac_explicit_sbr.m4a", "wb").write(data)
```
