# 7. Immagini di copertura: PNG, JPEG e foto dello smartphone

| | |
| --- | --- |
| Documento | SDD-07 — Immagini di copertura, formati delle immagini e metodi di inserimento |
| Sistema | shardpix 1.2.0 (non ancora rilasciato) |
| Stato | Bozza |
| Ultima revisione | 2026-10-07 |
| Lingua | Italiano (traduzione di [docs/07-covers-and-formats.md](../docs/07-covers-and-formats.md); in caso di differenze fa fede l'inglese) |

## 7.1 Scopo

In quale foto si nasconde una quota conta quanto il modo in cui la si
nasconde. Questo documento spiega come PNG e JPEG memorizzano una fotografia,
che cosa questo significa per la steganografia, quali metodi di inserimento
offre shardpix e come ottenere una buona immagine di copertura da uno
smartphone. Le misure su cui si basano questi consigli sono in 05 §5.5.

## 7.2 Come PNG e JPEG memorizzano una fotografia

| | PNG (e TIFF, BMP) | JPEG (e HEIC, AVIF, WebP con perdita) |
| --- | --- | --- |
| Che cosa viene memorizzato | Il valore di ogni pixel, esattamente | Blocchi 8x8 di coefficienti DCT, divisi per una tabella di quantizzazione e arrotondati |
| Compressione | Senza perdita | Con perdita: l'arrotondamento butta via informazione |
| Dove possono stare i dati nascosti | Nel bit meno significativo del valore di ogni pixel | Nei coefficienti DCT quantizzati |
| Che cosa succede se si salva di nuovo | Niente: i pixel tornano identici | Tutto viene quantizzato di nuovo: i bit nascosti nei pixel vengono distrutti |
| Provenienza tipica | Screenshot, esportazioni da RAW, programmi di fotoritocco | Tutte le fotocamere degli smartphone, tutte le app di messaggistica, il web |

La conseguenza è che **la steganografia nel dominio dei pixel e il JPEG sono
incompatibili in due modi**:

1. **In uscita.** Un carico scritto negli LSB dei pixel non sopravvive al
   salvataggio in JPEG, per questo shardpix scrive solo PNG (ADR-10).
2. **In ingresso.** Un JPEG decodificato in pixel non è una foto qualsiasi:
   ogni blocco 8x8 è la DCT inversa di coefficienti arrotondati, quindi i
   valori dei suoi pixel sono vincolati. Cambiarne anche uno solo di ±1
   produce un blocco che nessun compressore JPEG avrebbe potuto produrre, e la
   *steganalisi di compatibilità JPEG* (Fridrich, Goljan e Du, 2001) lo rileva
   a **qualsiasi** tasso di inserimento, qualunque sia il metodo che ha scelto
   i pixel. Inoltre, un PNG che si vede chiaramente essere stato un JPEG è già
   di per sé insolito.

HEIC, AVIF e WebP con perdita usano blocchi di trasformata più grandi e di
dimensione variabile; lo stesso ragionamento vale anche per loro, anche se gli
attacchi di compatibilità su questi formati sono meno studiati. shardpix li
tratta come il JPEG: i pixel decodificati non sono un'immagine di copertura
pulita.

## 7.3 Metodi di inserimento

| Metodo | Formato | Come viene scritta una quota | Campioni modificati da una quota (BOSSbase 512x512, media di 60) | Contro rilevatori addestrati (05 §5.5) | Uso |
| --- | --- | --- | ---: | --- | --- |
| `adaptive` (predefinito) | v4 | Modifiche di ±1 collocate da un codice a traliccio di sindrome dove il costo HiLL è più basso: nelle texture e nel rumore, lontano dalle zone uniformi | 208 | Vedi 05 §5.5.6 | Sempre, a meno che non serva il formato 3 |
| `matching` | v3 | Modifiche di ±1 in posizioni pseudo-casuali derivate dalla chiave, un bit per campione | 633 | SRM-lite: errore del 42,5% a 512x512 | Compatibilità con shardpix 1.1 |
| `replacement` | v3 | LSB sovrascritto in posizioni derivate dalla chiave | circa 630 | Violato da RS e chi-quadro | Solo per dimostrazioni |

**L'inserimento adattivo in un paragrafo.** Una *mappa dei costi* (HiLL: un
filtro passa-alto e due filtri passa-basso) assegna a ogni campione un
punteggio che indica quanto è rischiosa una modifica di ±1 in quel punto: alto
nei cieli, nei muri e sulla pelle, basso nel fogliame, nella ghiaia e nel
rumore del sensore. Il carico non viene scritto un bit per campione, ma come
*sindrome* di un blocco di campioni candidati (Filler, Judas e Fridrich,
2011): chi inserisce può scegliere quali campioni modificare, purché la
sindrome del blocco coincida con il messaggio, e l'algoritmo di Viterbi trova
la scelta con il costo totale più basso. Chi estrae si limita a calcolare la
sindrome e non ha mai bisogno della mappa dei costi. Ciò che riduce la
rilevabilità è fare meno modifiche, e farle dove l'immagine è già
imprevedibile.

**Struttura del formato 4.** Tre codici di sindrome, ciascuno dei quali va
letto prima di poter individuare il successivo: il sale pubblico e il byte di
costo (larghezza fissa, matrice pubblica), la lunghezza mascherata (larghezza
fissa, matrice derivata dalla chiave) e il corpo sigillato (larghezza ricavata
dalla lunghezza, fino a 128 candidati per bit). Dettagli in 01 §1.5.1.
shardpix 1.2 legge entrambi i formati; shardpix 1.1 non può leggere il
formato 4.

**Inserimento nel dominio JPEG — non ancora implementato.** Il metodo adatto
alle foto degli smartphone modifica direttamente i coefficienti DCT quantizzati
(con costi come UERD o J-UNIWARD e gli stessi codici a traliccio di sindrome)
e scrive un JPEG con le tabelle di quantizzazione e i metadati originali. Il
risultato è un JPEG che sembra uscito normalmente da una fotocamera, e
l'attacco di compatibilità del §7.2 non si applica più, perché nessun pixel
viene mai arrotondato di nuovo; ciò a cui deve resistere, invece, è la
steganalisi nel dominio JPEG. È il prossimo passo previsto (§7.6); fino ad
allora, shardpix inserisce i dati solo nei pixel.

## 7.4 Che cosa succede oggi a ciascun tipo di file in ingresso

| File in ingresso | Che cosa fa shardpix | File in uscita | Giudizio |
| --- | --- | --- | --- |
| Foto PNG, TIFF o BMP, a 8 bit, mai compressa in JPEG | Inserisce i dati nei pixel | PNG | **La migliore immagine di copertura** |
| RAW / DNG (iPhone ProRAW, RAW di Android) | Non viene letta direttamente: prima va sviluppata ed esportata in PNG o TIFF a 8 bit | PNG | **La migliore immagine di copertura**, dopo l'esportazione |
| JPEG (formato predefinito "Più compatibile" del telefono, la maggior parte delle fotocamere) | La decodifica, inserisce i dati nei pixel e mostra un avviso | PNG | Rilevabile dalla steganalisi di compatibilità JPEG, qualunque sia il metodo |
| HEIC (formato predefinito "Alta efficienza" dell'iPhone) | Non leggibile (Pillow non supporta HEIF) | — | Si può convertire, ma il risultato è un'immagine con perdita decodificata: stesso problema del JPEG |
| PNG o TIFF a 16 bit | Rifiutata | — | Esportala a 8 bit |
| Screenshot | Inserisce i dati nei pixel | PNG | Funziona, ma le ampie zone uniformi lasciano al metodo adattivo poca texture in cui nascondersi; meglio usare foto |

## 7.5 Le foto dello smartphone, in pratica

Lo smartphone è un'ottima fotocamera per shardpix; il problema sono i suoi
formati di file predefiniti. Per ottenere un'immagine di copertura pulita:

1. **Scatta in RAW, se il telefono lo permette.** Sui modelli iPhone Pro
   attiva *Impostazioni → Fotocamera → Formati → Apple ProRAW*; su Android
   molte app fotocamera offrono il RAW (DNG) nella modalità Pro o manuale.
   Sviluppa il DNG su un computer (darktable, RawTherapee, Lightroom, Apple
   Photos) ed **esporta un PNG o un TIFF a 8 bit alla piena risoluzione**,
   senza aumentare la nitidezza né ridurre il rumore oltre le impostazioni
   predefinite: è proprio nel rumore del sensore che il metodo adattivo
   nasconde le sue modifiche.
2. **Usa foto a colori di almeno 2 megapixel**, con texture: fogliame,
   ghiaia, tessuti, folle. La rilevabilità diminuisce con la radice quadrata
   del numero di campioni (05 §5.5.5). Una foto da smartphone è di solito da
   12 megapixel, ben al di sopra della soglia.
3. **Se hai a disposizione solo un JPEG**, l'inserimento funziona comunque, ma
   comporta il rischio descritto nel §7.2. Ridurre la foto di un fattore due o
   più attenua la traccia della griglia 8x8 ed è una contromisura diffusa; qui
   però *non* è stata misurata, e il risultato è un PNG di dimensioni insolite
   per uno smartphone. Meglio il RAW.
4. **Non pubblicare né conservare mai l'originale accanto all'immagine con i
   dati nascosti.** Chi le ha entrambe vede ogni campione modificato
   (05 §5.6).
5. **Trasferisci le immagini come file, mai come "foto".** Le app di
   messaggistica e i social network ricomprimono le immagini e distruggono il
   carico. Inviale come documenti, come allegati e-mail o tramite un servizio
   di archiviazione cloud.
6. **Aspettati che i metadati siano diversi.** Il PNG in uscita conserva il
   profilo colore ICC ma non i dati EXIF; una foto da smartphone senza EXIF
   può, in alcuni contesti, dare nell'occhio di per sé.

## 7.6 Piano di sviluppo: inserimento nel dominio JPEG

Il metodo JPEG leggerà i coefficienti quantizzati senza decodificare
l'immagine (`jpeglib`), calcolerà i costi UERD per ciascun coefficiente,
scriverà il carico con gli stessi codici a traliccio di sindrome nei
coefficienti AC diversi da zero e salverà un JPEG con le tabelle di
quantizzazione, il sottocampionamento della crominanza e i dati EXIF
originali. Sarà valutato con rilevatori nel dominio JPEG (DCTR, GFR) su
BOSSbase compresso a qualità 75 e 95, come avviene per i metodi spaziali in
05 §5.5. Finché queste misure non saranno state fatte, restano validi i
consigli del §7.5.

## 7.7 Riepilogo: quale immagine di copertura dovrei usare?

| Se hai | Cosa fare |
| --- | --- |
| Uno smartphone o una fotocamera che scatta in RAW | Scatta in RAW, esporta in PNG/TIFF a 8 bit, ≥ 2 MP, a colori, con una scena ricca di texture |
| Solo JPEG | Usali sapendo che c'è il rischio descritto nel §7.2, oppure aspetta l'inserimento nel dominio JPEG |
| Foto HEIC | Imposta la fotocamera sul RAW, oppure tratta gli HEIC convertiti come i JPEG |
| Immagini prese dal web | Non usarle: basta una ricerca inversa per immagini per trovare l'originale |
