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
media playback: audio=playing decoder=software shown=120 late=3 dropped=1 starved=0 decode_avg=2.1ms decode_max=9.0ms convert_max=4.0ms audio_underruns=0
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
| `audio` | stato del suono all'apertura: `playing` (suono su un'uscita aperta), `no_output` (il file ha un suono ma nessuna uscita è aperta: parte muto), `no_track` (nessuna traccia audio, o traccia che non si apre) |
| `audio_underruns` | volte in cui l'uscita audio ha trovato la coda vuota (un vuoto nel suono); l'attesa all'inizio e dopo uno spostamento non conta |

Come leggerle: `starved` alto con `decode_max` oltre il tempo di fotogramma
significa che il decodificatore è troppo lento (provare l'hardware).
`convert_max` alto indica la conversione colore. `audio_underruns` maggiore di
zero indica un vuoto nel suono.

## Decodifica hardware (opzionale)

- La feature `hw-decode` di `cordiale-ui` usa FFmpeg: VA-API e VDPAU su Linux,
  D3D11VA e DXVA2 su Windows, VideoToolbox su macOS. Funziona per H.264, HEVC,
  VP9 e AV1; VP8 resta in software.
- È spenta di default, come `video-shrink`: una build che la vuole deve avere
  le librerie di sviluppo di FFmpeg. I job CI `hw-decode` la compilano e la
  provano su Linux, su Windows x64 (FFmpeg statico da vcpkg, come nel
  pacchetto di rilascio) e su macOS (FFmpeg di Homebrew). Tra i pacchetti di
  rilascio la includono Windows (x64 e ARM64) e macOS; i pacchetti Linux no
  (sezione «Pacchetti di rilascio»).
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

Esito (2026-11-15): il responsabile del progetto ha riferito che le prove a
mano sono passate. Non ha mandato le righe `media playback:`: la tabella in
fondo non contiene misure, e le tarature restano ai valori attuali.

## Prova del video senza suono (issue 825)

Prova a mano per trovare la causa di un video senza suono. Ripetere su
Windows, macOS e Linux, con un'uscita audio reale.

1. Aprire Impostazioni > Debug e copiare il rapporto. La riga `Audio output`
   riporta il dispositivo predefinito e il sistema audio. `Not available`
   significa che il sistema non indica un dispositivo.
2. Riprodurre un file audio, un video con audio e un video senza traccia
   audio. Annotare il contenitore, il codec video e il codec audio.
3. Leggere il registro. Il video con audio deve avere la riga
   `audio output opened: <dispositivo>`. Queste righe indicano la causa:
   - `no audio output: <errore>`: l'uscita non si apre;
   - `video has a sound, but no audio output is open`: il video parte senza
     suono perché manca l'uscita;
   - `webm audio track could not be opened` o una riga sulla traccia audio
     di un MP4: il decodificatore non legge la traccia.
4. Il video senza traccia audio non deve scrivere errori audio.
5. Riprodurre lo stesso video due volte, con la decodifica hardware accesa e
   con `CORDIALE_VIDEO_DECODE=software`. Confrontare il suono e la riga
   `media playback:` (`audio`, `decoder`, `audio_underruns`). `audio=no_output`
   con un video che ha un suono indica l'uscita come causa; `audio=no_track`
   con una traccia presente indica il decodificatore. Se il suono è uguale e
   `audio_underruns` è uguale, la decodifica hardware non è la causa.
6. Controllare audio e video allineati dopo play, pausa, ripresa e
   spostamento.

Esito: queste prove richiedono un dispositivo audio reale e non girano in CI.
Nessun risultato è stato consegnato finora: la causa resta non confermata.

## Prova della scelta dell'uscita audio (issue 830)

Prova a mano da ripetere su Windows, macOS e Linux, meglio con un computer che
ha più uscite audio. Radio, file audio e audio dei video usano la stessa
uscita.

1. Aprire Impostazioni > Generale. La sezione `Uscita audio` sta prima di
   `Upload`. L'elenco ha solo uscite, nessun microfono; la prima voce è
   l'uscita predefinita del sistema.
2. Avviare una radio e scegliere un'altra uscita senza premere `Applica`: il
   suono resta sull'uscita di prima.
3. Premere `Applica`: la radio passa alla nuova uscita con la stessa stazione e
   lo stesso volume.
4. Aprire un file audio e un video con audio, scegliere un'altra uscita e
   premere `Applica`: posizione, pausa e volume restano.
5. Riavviare Cordiale: la scelta resta selezionata.
6. Scollegare l'uscita scelta e riaprire la scheda: compare l'avviso che
   l'uscita non c'è e il suono va sull'uscita predefinita.
7. Se l'uscita nuova non si apre, il suono in corso resta sulla vecchia uscita
   e sotto l'elenco compare l'avviso che non ha potuto passare alla nuova.

Esito: queste prove richiedono dispositivi audio reali e non girano in CI.
Nessun risultato è stato consegnato finora.

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

## Pacchetti di rilascio

La feature si accende in una piattaforma solo se esiste una scelta di
collegamento che non dipende dalle librerie del sistema dell'utente. Dove FFmpeg
è collegato in modo statico, l'eseguibile non ha bisogno di FFmpeg nel sistema.

| Piattaforma | Hardware | Collegamento |
|---|---|---|
| Windows x64 | D3D11VA, DXVA2 | FFmpeg da vcpkg, triplet `x64-windows-static-md`, feature `hw-decode` |
| Windows ARM64 | D3D11VA, DXVA2 | FFmpeg da vcpkg, triplet `arm64-windows-static-md` (build incrociata sul runner x64), feature `hw-decode` |
| macOS ARM64 | VideoToolbox | FFmpeg da vcpkg, triplet `arm64-osx`, statico con pkg-config, feature `hw-decode-static` |
| macOS x64 | VideoToolbox | FFmpeg da vcpkg, triplet `x64-osx` (build incrociata sul runner ARM64), feature `hw-decode-static` |
| Linux | nessuno | software |

Regole del workflow `packages.yml`:

- Windows (x64 e ARM64) e macOS hanno un ripiego: se l'installazione di
  FFmpeg o la build con hardware fallisce, il job compila senza `hw-decode`,
  scrive un avviso (`::warning::`) e una riga nel riepilogo del job con il
  nome del pacchetto, e il pacchetto usa il software. Il job resta verde: il
  riepilogo è l'unico segnale.
- Su Windows `avcodec.lib` ha bisogno delle librerie di sistema `mfuuid` e
  `strmiids` (GUID di Media Foundation: `IID_IMFTransform`,
  `IID_IMFMediaEventGenerator`, `IID_ICodecAPI`). Il percorso vcpkg di
  `ffmpeg-sys-next` non le collega: lo fa `crates/cordiale-ui/build.rs` con la
  feature `hw-decode`, per x64 e ARM64. Senza, il collegamento fallisce con
  simboli esterni non risolti (la release v1.0.20 si è fermata così).
- Ogni job di Windows controlla che l'eseguibile non importi una DLL di FFmpeg.
  Ogni job di macOS controlla con `otool -L` che non colleghi `libav*`,
  `libsw*` né un percorso di Homebrew. Il controllo fa fallire il pacchetto
  che non partirebbe senza FFmpeg.
- La CI (job `hw-decode (windows-latest)` e `hw-decode (macos-latest)`)
  compila e prova `hw-decode` su Windows x64 e su macOS prima di una release,
  ma non sono controlli obbligatori. Windows ARM64 condivide le stesse
  librerie di collegamento e le build con vcpkg su ARM64 e su macOS (statico)
  sono provate solo dalla release o dall'avvio manuale di `Packages`. Se il
  ripiego scatta, l'avviso appare nel riepilogo del job.

Perché Linux resta in software, decisione presa: un collegamento statico di
FFmpeg non ha un percorso hardware senza le librerie condivise di VA-API, e
queste cambiano tra le distribuzioni. Un collegamento dinamico non parte su
tutte le distribuzioni:

- il nome della libreria cambia (per esempio `libavcodec.so.60` su Ubuntu 24.04
  e `.so.61` su Debian 13): il binario compilato su `ubuntu-24.04` non partirebbe
  su Debian 13;
- `packaging/check-linux-deps.sh` rifiuta le librerie che la sua tabella non
  conosce, e per AlmaLinux e Arch i pacchetti di FFmpeg hanno altri nomi;
- sul bersaglio `aarch64-unknown-linux-gnu` la build con `cross` non ha le
  librerie di FFmpeg.

Su Linux la decodifica hardware resta disponibile con la build di prova
`linux-x64-hw-dev` del workflow `Dev Build`.

## Cosa resta da fare

Il codice della issue #787 è completo. Resta solo l'esito della prossima
release (o di un avvio manuale di `Packages`):

- il pacchetto Windows x64 con `hw-decode` parte su un sistema senza FFmpeg
  (il job lo controlla sull'eseguibile: nessuna DLL di FFmpeg);
- le build con hardware di Windows (x64 e ARM64) e macOS riescono, o il
  ripiego compila il pacchetto in software con un avviso.

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
| Tutte le piattaforme | Prove a mano riferite come passate dal responsabile (2026-11-15) | n/d | n/d | n/d | n/d | Nessuna riga di registro consegnata: nessuna misura qui |
