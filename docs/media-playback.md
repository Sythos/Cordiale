# Riproduzione audio e video: misure, tarature e prove a mano

Il lettore (`crates/cordiale-ui/src/media_player.rs`) decodifica in Rust puro.
La decodifica hardware è opzionale (`media_hw.rs`, feature `hw-decode`).

## Come è fatta la riproduzione

- **Audio:** un thread di lavoro (`audio_worker`) legge e decodifica i pacchetti e
  li passa all'uscita audio con una coda limitata (`AUDIO_QUEUE_CHUNKS`, 32
  blocchi). L'uscita non decodifica mai: prende solo campioni già pronti.
- **Video:** il thread del controller decodifica, converte in RGBA e consegna i
  fotogrammi alla finestra. Con una traccia audio, l'audio è l'orologio del
  video; senza audio si usa l'orologio di sistema.
- **Coda dei fotogrammi:** `queue_frames()` la dimensiona sul formato
  dell'immagine, tra 4 e 12 fotogrammi e al massimo 96 MiB di immagini
  decodificate (`QUEUE_BYTES`). Un 4K ne tiene 8, un 1080p 12.
- **Tempo di decodifica per ogni giro:** un giro del controller decodifica
  campioni finché la coda è piena o finché sono passati 8 ms
  (`DECODE_SLICE`), con almeno un campione e al massimo 8
  (`DECODE_MAX_SAMPLES`). Così un fotogramma lento non blocca i comandi di
  pausa e di posizione.
- **Attesa del controller:** da 1 ms (la coda ha posto: si decodifica subito) a
  15 ms (la coda è piena: si aspetta il prossimo fotogramma).

## Misure

Alla chiusura di ogni file il lettore scrive una riga nel registro
dell'applicazione:

```
media playback: decoder=software shown=120 late=3 dropped=1 starved=0 decode_avg=2.1ms decode_max=9.0ms convert_max=4.0ms audio_underruns=0
```

| Campo | Significato |
|---|---|
| `decoder` | `software` o il nome del percorso hardware (`VA-API`, `VDPAU`, `D3D11VA`, `DXVA2`, `VideoToolbox`); `(fallback)` se l'hardware si è fermato |
| `shown` | fotogrammi inviati alla finestra |
| `late` | fotogrammi mostrati con più di un tempo di fotogramma di ritardo |
| `dropped` | fotogrammi dovuti ma saltati perché ne era dovuto uno più nuovo |
| `starved` | volte in cui la coda si è svuotata durante la riproduzione |
| `decode_avg`, `decode_max` | tempo di decodifica di un campione |
| `convert_max` | tempo massimo della conversione colore di un'immagine |
| `audio_underruns` | volte in cui l'uscita audio ha trovato la coda vuota (un vuoto nel suono); l'attesa all'inizio e dopo uno spostamento non conta |

Come leggerle: `starved` alto con `decode_max` oltre il tempo di fotogramma
significa che il decodificatore è troppo lento (provare l'hardware).
`convert_max` alto indica la conversione colore. `audio_underruns` maggiore di
zero indica un vuoto nel suono.

## Decodifica hardware (opzionale)

- La feature `hw-decode` di `cordiale-ui` usa FFmpeg: VA-API e VDPAU su Linux,
  D3D11VA e DXVA2 su Windows, VideoToolbox su macOS. Funziona per H.264, HEVC,
  VP9 e AV1; VP8 resta in software.
- È spenta di default, come `video-shrink`: i pacchetti attuali non la
  includono, e una build che la vuole deve avere le librerie di sviluppo di
  FFmpeg. Il job CI `hw-decode` la compila e la prova su Linux.
- Senza la feature, senza un decodificatore adatto nel sistema, o con
  `CORDIALE_VIDEO_DECODE=software`, il file si riproduce con i
  decodificatori software, senza errori.
- Se l'hardware si ferma durante la riproduzione, il lettore passa al software
  dal fotogramma chiave precedente e la riga di registro riporta
  `(fallback)`.

## Prove a mano per ogni piattaforma

La CI non ha audio, schermo né scheda video: le prove sul suono e sul
video reali si fanno a mano. Usare file piccoli e condivisibili: un file
audio (MP3 o FLAC), un video H.264 con audio e un video ad alto carico (1080p
a 60 fps o 4K, H.264 o HEVC). Per ogni prova annotare sistema operativo,
sistema grafico, contenitore e codec, dimensione e frequenza del video,
frequenza e canali dell'audio, e la riga `media playback:` del registro.

1. **Windows**, build con `--features hw-decode`: riprodurre i tre file;
   `decoder` deve essere `D3D11VA` o `DXVA2` con una scheda adatta.
   Ripetere con `CORDIALE_VIDEO_DECODE=software`.
2. **macOS** (ARM64 e x64), build con `--features hw-decode`: `decoder` deve
   essere `VideoToolbox`. Ripetere in software.
3. **Linux/X11** e **Linux/Wayland**, build con `--features hw-decode` e un
   driver VA-API: `decoder` deve essere `VA-API`. Senza driver il file deve
   comunque partire in software.
4. Su ogni sistema controllare: nessun vuoto ricorrente nel suono
   (`audio_underruns` vicino a zero), nessuno scatto ricorrente nel video
   (`late` e `starved` bassi), audio e video allineati dopo play, pausa,
   ripresa e spostamento, e l'interfaccia reattiva durante l'apertura e la
   riproduzione di un file grande.
5. Con una macchina senza hardware adatto, controllare che la riproduzione
   continui in software e senza errori.

Nessuna di queste prove è stata ancora fatta con audio, schermi e schede
video reali.
