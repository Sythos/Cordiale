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
- Il formato dei fotogrammi hardware è quello che il codec dichiara per il
  tipo di dispositivo aperto (`avcodec_get_hw_config`), non il primo formato
  hardware offerto. L'intervallo di colore (pieno o limitato) passa dal
  fotogramma decodificato alla copia in memoria.
- Se l'hardware si ferma durante la riproduzione, anche per un errore di
  decodifica (non solo per un campione rifiutato), il lettore passa al software
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

## Build per i tester

- **Linux x64:** il workflow manuale `Dev Build` (job `linux-x64-hw-dev`)
  compila con `--features hw-decode` e carica un tarball. Il binario usa le
  librerie condivise di FFmpeg del sistema: il tester ha bisogno delle
  librerie di FFmpeg della stessa versione di quelle del runner
  (`ubuntu-26.04`), cioè di una distribuzione recente.
- **Windows x64:** il job `windows-x64-hw-dev` compila con `--features
  hw-decode` e carica uno zip con il solo `cordiale-ui.exe`. FFmpeg viene da
  vcpkg con il triplet `x64-windows-static-md` (libreria statica, runtime C
  dinamico): nessuna DLL di FFmpeg accanto all'eseguibile. Non è un
  installer.
- **macOS ARM64 e x64:** il job `macos-hw-dev` (un lavoro per architettura)
  compila con `--features hw-decode` e FFmpeg di Homebrew, e carica un
  tarball. Il tester installa lo stesso FFmpeg con `brew install ffmpeg`.
- Windows resta anche il job `windows-x64-dev` (senza `hw-decode`): serve per
  la prova in software.
- Ogni job del workflow `Dev Build` si avvia a mano. Il tester scarica
  l'artefatto, esegue le prove qui sotto e aggiunge le righe al registro.

## Pacchetti di rilascio: perché `hw-decode` resta spenta

La feature si accende nei pacchetti solo dopo che le prove a mano passano,
perché oggi un binario con `hw-decode` collega FFmpeg in modo dinamico:

- il nome della libreria cambia tra le distribuzioni (per esempio
  `libavcodec.so.60` su Ubuntu 24.04 e `.so.61` su Debian 13): il binario
  compilato su `ubuntu-24.04` non partirebbe su Debian 13;
- `packaging/check-linux-deps.sh` rifiuta le librerie che la sua tabella non
  conosce, e per AlmaLinux e Arch i pacchetti di FFmpeg hanno altri nomi;
- su Windows e macOS le librerie di FFmpeg vanno incluse nell'installer, e
  sul bersaglio `aarch64-unknown-linux-gnu` la build con `cross` non le ha.

Per accenderla servono quindi: una scelta di collegamento (statico, o
librerie incluse) per ogni piattaforma e un job di pacchetto provato su di
essa. Le build per i tester sopra provano due collegamenti candidati:

- **Windows:** FFmpeg statico da vcpkg (`x64-windows-static-md`), un solo
  eseguibile. Se la prova passa, è la scelta per l'installer NSIS.
- **macOS:** FFmpeg di Homebrew in modo dinamico. Per un pacchetto servirebbe
  includere le librerie nel bundle `.app`: da decidere dopo la prova.
- **Linux:** collegamento dinamico alle librerie della distribuzione; per i
  pacchetti serve una build statica di FFmpeg o una tabella di dipendenze per
  ogni distribuzione.

I pacchetti (`packages.yml`) restano senza `hw-decode` fino ai risultati nel
registro qui sotto: accenderla senza prove può impedire l'avvio del programma
sul sistema dell'utente.

## Cosa resta da fare (solo prove sul campo)

Il codice della issue #787 è completo: restano solo lavori che si fanno fuori
da GitHub, con hardware reale.

1. **Prove a mano.** Un tester scarica la build del proprio sistema (sezione
   «Build per i tester»), esegue i punti 1-5 di «Prove a mano per ogni
   piattaforma» e scrive in un commento della issue #787 una riga per ogni
   file, con i campi della tabella qui sotto. Chi tiene la documentazione
   copia le righe nella tabella.
2. **Taratura.** Se la tabella lo chiede, si cambia un solo valore alla volta,
   seguendo le regole del registro, e si ripete la prova.
3. **Pacchetti.** Si accende `hw-decode` in `packages.yml` per una
   piattaforma solo quando tutte queste condizioni sono vere:
   - le prove di quella piattaforma sono nella tabella, con `decoder` uguale
     al percorso hardware atteso e `audio_underruns` vicino a zero;
   - la prova in software (`CORDIALE_VIDEO_DECODE=software`) è nella
     tabella e riproduce senza errori;
   - esiste una scelta di collegamento per quella piattaforma
     (sezione «Pacchetti di rilascio») e il pacchetto parte su un sistema
     senza FFmpeg installato.
   Le piattaforme che non soddisfano le condizioni restano senza `hw-decode`.

## Registro dei risultati

Per ogni prova a mano, aggiungere una riga. Le tarature (`QUEUE_MIN_FRAMES`,
`QUEUE_MAX_FRAMES`, `QUEUE_BYTES`, `DECODE_SLICE`, `DECODE_MAX_SAMPLES`,
`AUDIO_QUEUE_CHUNKS`) si cambiano solo se i risultati lo chiedono:

- `starved` alto con `decode_max` sotto il tempo di fotogramma: alzare
  `QUEUE_MIN_FRAMES` o `QUEUE_BYTES`;
- `starved` alto con `decode_max` sopra il tempo di fotogramma: il
  decodificatore è lento, non la coda (provare l'hardware);
- `audio_underruns` maggiore di zero: alzare `AUDIO_QUEUE_CHUNKS`;
- l'interfaccia lenta durante la decodifica: abbassare `DECODE_SLICE`.

| Sistema e grafica | File (contenitore, codec, formato) | `decoder` | `late` | `starved` | `audio_underruns` | Note |
|---|---|---|---|---|---|---|
| _nessuna prova ancora registrata_ | | | | | | |
