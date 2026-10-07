# 7. Immagini di copertura: PNG, JPEG e foto dello smartphone

| | |
| --- | --- |
| Documento | SDD-07 — Immagini di copertura, formati delle immagini e metodi di inserimento |
| Sistema | shardpix 2.0.0 |
| Stato | Approvato |
| Ultima revisione | 2026-10-07 |
| Lingua | Italiano (traduzione di [docs/07-covers-and-formats.md](../docs/07-covers-and-formats.md); in caso di differenze fa fede l'inglese) |

## 7.1 In breve

**Usa le foto scattate dal tuo smartphone così come sono.** shardpix
riconosce un JPEG e nasconde la quota dentro il JPEG stesso: il risultato è
un JPEG con le stesse impostazioni di qualità e gli stessi metadati della
fotocamera. Un'esportazione in PNG, TIFF o RAW dà invece un PNG. Non devi
scegliere nessun metodo: decide il file.

Quattro regole contano più di tutto il resto:

1. una foto a colori di almeno 2 megapixel e con un po' di texture (qualsiasi
   foto da smartphone va bene);
2. una foto originale che nessun altro possiede: mai una presa dal web, mai
   una salvata da una chat o da un social (sono ricompresse, e a bassa
   qualità JPEG le quote diventano rilevabili quando se ne aggregano
   diverse, 05 §5.5.8), e non pubblicare mai l'originale;
3. invia il risultato come **file** (allegato e-mail, archivio cloud, "invia
   come documento"), mai come "foto" in un'app di messaggistica, che la
   ricomprimerebbe;
4. su iPhone, lascia la fotocamera su *Più compatibile* (JPEG) anziché su
   *Alta efficienza* (HEIC), che shardpix non è in grado di leggere.

Il resto di questo documento spiega il perché. Le misure su cui si basa sono
in 05 §5.5.

## 7.2 Come PNG e JPEG memorizzano una fotografia

| | PNG (e TIFF, BMP) | JPEG (e HEIC, AVIF, WebP con perdita) |
| --- | --- | --- |
| Che cosa viene memorizzato | Il valore di ogni pixel, esattamente | Blocchi 8x8 di coefficienti DCT, divisi per una tabella di quantizzazione e arrotondati |
| Compressione | Senza perdita | Con perdita: l'arrotondamento butta via informazione |
| Dove possono stare i dati nascosti | Nel bit meno significativo del valore di ogni pixel | Nei coefficienti DCT quantizzati |
| Che cosa succede se si salva di nuovo | Niente: i pixel tornano identici | Tutto viene quantizzato di nuovo: qualsiasi dato nascosto viene distrutto |
| Provenienza tipica | Screenshot, esportazioni da RAW, programmi di fotoritocco | Tutte le fotocamere degli smartphone, tutte le app di messaggistica, il web |

Per questo un JPEG va trattato **nel suo dominio**. Decodificarlo in pixel,
nascondere lì i dati e salvare un PNG (come faceva shardpix prima del
formato 5) fallisce per due motivi: il PNG di una foto da smartphone è già
di per sé insolito, e i pixel di un JPEG decodificato rispettano la
quantizzazione a blocchi 8x8, quindi una modifica di ±1 produce un blocco che
nessun compressore JPEG avrebbe potuto produrre. La *steganalisi di
compatibilità JPEG* (Fridrich, Goljan e Du, 2001) lo rileva a qualsiasi
tasso di inserimento.

## 7.3 I due formati che shardpix scrive

| Immagine di copertura | Formato | Dove va la quota | File in uscita | Misurato contro |
| --- | --- | --- | --- | --- |
| JPEG (foto da smartphone, la maggior parte delle fotocamere) | 5 | Coefficienti AC diversi da zero della luminanza, scelti da un codice a traliccio di sindrome con costi UERD | JPEG con le stesse tabelle di quantizzazione e gli stessi metadati | DCTR (05 §5.5.8) |
| PNG, TIFF, BMP, esportazione da RAW | 4 | Valori dei pixel compresi tra 2 e 253, scelti da un codice a traliccio di sindrome con costi HiLL | PNG | SPAM, SRM-lite, aggregato (05 §5.5.6–5.5.7) |

Entrambi i formati si basano sulla stessa idea. Un **costo** indica quanto è
rischiosa una modifica di ±1 in ciascun punto: alto dove l'immagine è
uniforme e prevedibile (un cielo, un muro, un blocco 8x8 piatto), basso dove
è movimentata (fogliame, ghiaia, rumore del sensore). Il carico viene scritto
come **sindrome** di un blocco di posizioni candidate (Filler, Judas e
Fridrich, 2011): chi inserisce può modificarne una qualsiasi, purché la
sindrome del blocco coincida con il messaggio, e l'algoritmo di Viterbi
sceglie le modifiche con il costo totale più basso. Chi estrae si limita a
calcolare la sindrome e non ha mai bisogno dei costi.

Che cosa aggiunge il formato 5 per il JPEG:

- **Si spostano solo i coefficienti AC diversi da zero.** Trasformare uno zero
  in un valore diverso da zero è la modifica più rilevabile in un JPEG, quindi
  gli zeri e i coefficienti DC non vengono mai toccati, e un coefficiente che
  vale ±1 si allontana sempre dallo zero. L'insieme dei coefficienti
  utilizzabili è lo stesso prima e dopo, così chi estrae lo ritrova senza
  bisogno di informazioni aggiuntive.
- **Costi UERD** (Guo et al., 2015): una modifica costa il passo di
  quantizzazione della sua frequenza diviso per l'energia del suo blocco e dei
  blocchi vicini; costa poco nei blocchi movimentati e alle basse frequenze,
  molto nei blocchi piatti.
- **Nient'altro cambia.** L'immagine non viene mai decodificata né
  ricompressa: tabelle di quantizzazione, crominanza, dimensioni e metadati
  EXIF e ICC vengono riscritti tali e quali.

I formati usati in precedenza (3: un bit per campione con LSB matching o
replacement) non sono più offerti dalla CLI. Restano nella libreria solo come
termine di confronto per i benchmark.

## 7.4 Che cosa succede a ciascun tipo di file in ingresso

| File in ingresso | Che cosa fa shardpix | File in uscita | Giudizio |
| --- | --- | --- | --- |
| JPEG da smartphone o fotocamera | Inserisce i dati nei coefficienti (formato 5) | JPEG | **Buona immagine di copertura**, così com'è |
| Foto PNG, TIFF o BMP a 8 bit | Inserisce i dati nei pixel (formato 4) | PNG | **Buona immagine di copertura** |
| RAW / DNG (iPhone ProRAW, RAW di Android) | Non viene letta direttamente: esportala in PNG o TIFF a 8 bit | PNG | **Buona immagine di copertura**, dopo l'esportazione |
| HEIC ("Alta efficienza" dell'iPhone) | Non leggibile (Pillow non supporta HEIF) | — | Imposta la fotocamera su JPEG; convertire un HEIC in JPEG comprime la foto due volte |
| PNG o TIFF a 16 bit | Rifiutata | — | Esportala a 8 bit |
| Screenshot | Inserisce i dati nei pixel | PNG | Funziona, ma le zone uniformi lasciano poca texture; meglio usare foto |

Il tipo di file viene riconosciuto dai primi byte del file, non dal nome, e il
file in uscita deve avere l'estensione corrispondente (`.jpg` o `.png`).

## 7.5 Le foto dello smartphone, passo per passo

1. **Impostazioni della fotocamera.** Su iPhone: *Impostazioni → Fotocamera →
   Formati → Più compatibile*. Le fotocamere Android salvano in JPEG già per
   impostazione predefinita. Mantieni la qualità più alta e la risoluzione
   piena.
2. **Scegli le foto.** Scene ricche di texture (alberi, strade, tessuti,
   folle) piuttosto che un cielo azzurro o un muro bianco. Foto scattate da te
   e mai condivise.
3. **Copiale sul computer come file originali**: con il cavo, oppure con un
   archivio cloud impostato per conservare gli originali. Evita qualsiasi
   passaggio che le ridimensioni o le converta lungo la strada.
4. **Sigilla** con `shardpix seal secret.pdf photo1.jpg photo2.jpg ... -k 3 -p`.
   La cartella `sealed/` riceve un `.jpg` per ogni foto e il file vault.
5. **Consegna i file `.jpg` come file**, e cancella gli originali o tienili
   privati. Ogni custode può tenere la foto in un album: l'importante è che non
   venga mai ricompressa (niente modifiche, niente "salva con nome", niente app
   di messaggistica in modalità foto).

## 7.6 Limiti che restano

- **Struttura del file.** Le tabelle di quantizzazione e i metadati vengono
  conservati, ma il file viene riscritto da libjpeg: le tabelle di Huffman,
  l'ordine dei marcatori o la codifica progressiva possono differire da ciò
  che scrive un certo modello di telefono. Un analista forense che confronti la
  struttura del file con l'output abituale di quel telefono potrebbe accorgersi
  che è stato riscritto, senza però scoprire nulla sulla quota. La steganalisi
  del contenuto è una questione a parte (05 §5.5.8).
- **Solo la luminanza.** I coefficienti di crominanza non vengono mai usati:
  sono meno numerosi, quantizzati in modo più grossolano, e in ogni caso la
  capacità supera di gran lunga quella necessaria per una quota.
- **JPEG di bassa qualità.** A qualità 95 il formato 5 è al livello del caso
  contro DCTR, con un'immagine e con cinquanta aggregate; a qualità 75 è
  debolmente rilevabile su un'immagine (42,5%) e chiaramente con molte (7,8%
  con cinquanta). Usa i file originali della fotocamera, che i telefoni
  salvano a qualità 90 o più (05 §5.5.8). `embed` e `seal` stimano la
  qualità di ogni JPEG dalla sua tabella di quantizzazione e avvisano sotto
  90; `capacity` mostra la stima.
- **Rilevatori.** Il formato 5 è stato misurato contro DCTR; rilevatori JPEG
  più potenti (GFR, reti profonde come SRNet per JPEG) non sono stati provati.

## 7.7 Riepilogo: quale immagine di copertura dovrei usare?

| Se hai | Cosa fare |
| --- | --- |
| Uno smartphone | Usa le sue foto JPEG così come sono: con texture, a piena risoluzione, mai condivise |
| Esportazioni da RAW o foto PNG | Usale: danno file in uscita PNG (formato 4) |
| Foto HEIC | Imposta la fotocamera su JPEG per le foto che userai |
| Immagini prese dal web | Non usarle: basta una ricerca inversa per immagini per trovare l'originale |
