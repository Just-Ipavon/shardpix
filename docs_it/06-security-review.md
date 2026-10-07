# 6. Revisione di sicurezza

| | |
| --- | --- |
| Documento | SDD-06 — Rapporto della revisione di sicurezza interna |
| Sistema | shardpix 1.1.0 (revisione iniziata sulla 1.0.0) |
| Stato | Completo |
| Ultima revisione | 2026-10-06 |
| Lingua | Italiano (traduzione di [docs/06-security-review.md](../docs/06-security-review.md); in caso di differenze fa fede l'inglese) |

## 6.1 Scopo, ambito e indipendenza

Questo rapporto documenta una revisione di sicurezza strutturata di shardpix:
che cosa è stato esaminato, come, che cosa è stato trovato e che cosa si è
fatto al riguardo. Segue la struttura di un rapporto di audit di terze parti,
in modo che un futuro auditor indipendente possa partire da qui.

**Non è un audit indipendente.** La revisione è stata svolta parallelamente
allo sviluppo del codice che esamina. Il suo valore sta nel fatto che il metodo
è esplicito e riproducibile — ogni strumento, configurazione e risultato
riportati di seguito possono essere rieseguiti a partire dal repository — non
nell'indipendenza del revisore. Si veda il §6.12 per ciò su cui dovrebbe
concentrarsi una revisione indipendente.

**Nell'ambito:** ogni modulo del pacchetto `shardpix`, con particolare
attenzione a `stego.py`, `shamir.py`, `gf256.py` e `vault.py`; i formati su
disco; la gestione di file e segreti da parte dell'interfaccia a riga di
comando; le dipendenze.

**Fuori dall'ambito:** le librerie `cryptography`, NumPy e Pillow in sé; il
sistema operativo ospite; la steganalisi addestrata (si veda 05 §5.6).

## 6.2 Metodo

| Attività | Strumento | Versione | Che cosa stabilisce |
| --- | --- | --- | --- |
| Analisi statica | bandit | 1.9.4 | Schemi Python notoriamente insicuri (casualità debole, deserializzazione non sicura, shell injection, segreti cablati nel codice, …) |
| Analisi statica | semgrep con le 112 regole del set ufficiale `python` | 1.179.0 | La stessa classe di problemi, comprese le regole sull'uso scorretto delle API crittografiche |
| Audit delle dipendenze | pip-audit sul database degli avvisi di PyPI | 2.10.1 | Vulnerabilità note nelle quattro dipendenze di runtime e nelle loro dipendenze |
| Property-based testing e fuzzing | Hypothesis | 6.168 | Le affermazioni di correttezza valgono per input generati; i parser falliscono solo con il proprio errore su input arbitrari |
| Mutation testing | mutmut, con ogni mutante sopravvissuto rieseguito sull'intera suite al di fuori di mutmut | 3.8.0 | I test rilevano davvero i guasti nel nucleo crittografico, invece di limitarsi a eseguirlo |
| Revisione manuale | OWASP ASVS 4.0.3 capitolo V6 (crittografia dei dati memorizzati) e controlli selezionati di V2, V5, V7, V12, V14; OWASP Password Storage Cheat Sheet | — | Progetto e implementazione confrontati con una checklist esterna |

La gravità usa quattro livelli: **Alta** (compromette la riservatezza o
l'integrità dei dati sigillati nel modello di minaccia di 05), **Media**
(indebolisce una proprietà di sicurezza o un parametro dichiarato), **Bassa**
(robustezza o difesa in profondità), **Info** (nessun impatto diretto;
processo o documentazione).

## 6.3 Riepilogo

| | |
| --- | --- |
| Problemi rilevati | 8: 0 Alta, 1 Media, 2 Bassa, 5 Info |
| Corretti | 5 (tutti quelli di gravità Media e Bassa, 2 Info) |
| Accettati con motivazione | 3 Info |
| Analisi statica | 0 problemi (bandit, 112 regole semgrep); 0 vulnerabilità note in 9 dipendenze |
| Fuzzing | 16 proprietà, 48.000 casi generati per esecuzione nel profilo fuzz; 1 crash trovato e corretto |
| Mutation testing | 1.575 mutanti; 90,9% rilevati, 95,6% di quelli non equivalenti; ogni sopravvissuto esaminato (§6.8) |
| Test | 255 prima della revisione, 310 dopo |

Nessun problema rilevato ha compromesso la riservatezza o l'integrità dei file
sigillati. Il risultato più significativo è SR-01: il rafforzamento della
passphrase era al di sotto dell'attuale raccomandazione OWASP, e il formato
dell'immagine non aveva spazio per aumentarlo senza rendere illeggibili le
immagini esistenti. Entrambi gli aspetti sono corretti nella 1.1.0.

## 6.4 Problemi rilevati

| Id | Gravità | Titolo | Rilevato da | Stato |
| --- | --- | --- | --- | --- |
| SR-01 | Media | Costo di scrypt inferiore alla raccomandazione OWASP e non memorizzato nell'immagine | Revisione manuale | Corretto nella 1.1.0 |
| SR-02 | Bassa | `chi2_sf` va in crash con una statistica subnormale | Fuzzing | Corretto nella 1.1.0 |
| SR-03 | Bassa | Output creati con verifica-poi-scrittura: una finestra di race e link simbolici pendenti seguiti | Revisione manuale | Corretto nella 1.1.0 |
| SR-04 | Info | Lacune nei test: derivazione della chiave in modalità pubblica, campi del rapporto e dettagli degli errori non vincolati | Mutation testing | Corretto nella 1.1.0 (31 test aggiunti) |
| SR-05 | Info | `--method replacement` offerto senza avvertimento | Revisione manuale | Corretto nella 1.1.0 |
| SR-06 | Info | Dipendenze specificate solo con limite inferiore; nessun file di lock | Revisione manuale | Accettato |
| SR-07 | Info | Le posizioni di sale e costo sono pubbliche e dipendono solo dai campioni idonei | Revisione manuale | Accettato |
| SR-08 | Info | Hook di iniezione `random_bytes` nell'API pubblica | Revisione manuale | Accettato |

### SR-01 — Costo di scrypt inferiore alla raccomandazione OWASP e non memorizzato (Media)

**Osservazione.** Le passphrase venivano rafforzate con scrypt N = 2^15,
r = 8, p = 1 (32 MiB). L'OWASP Password Storage Cheat Sheet raccomanda
N = 2^17, r = 8, p = 1 (128 MiB), o configurazioni equivalenti che scambiano
memoria con parallelismo, come N = 2^15 con p = 3. Con p = 1, 2^15 fornisce
circa un terzo del lavoro raccomandato per tentativo. Inoltre i parametri erano
impliciti nel formato: aumentarli avrebbe reso illeggibile ogni immagine
esistente, il che in pratica significa che non sarebbero mai stati aumentati
(ASVS 6.2.4, agilità crittografica).

**Impatto.** Un attaccante in possesso di un'immagine stego (ADV-2) può
provare tentativi di passphrase circa tre volte più velocemente di quanto
raccomandato. La riservatezza del *file* non è compromessa — si basa sulla
soglia, non sulla passphrase — ma l'affermazione che un'immagine non riveli la
propria quota (SP-05) è più debole per le passphrase a bassa entropia.

**Correzione.** Il formato stego v3 memorizza log2(N) in un byte accanto al
sale, lungo il percorso pubblico. I nuovi inserimenti usano N = 2^17 (≈ 0,4 s
e 128 MiB per immagine). L'estrazione accetta valori da 2^10 a 2^18 e rifiuta
qualsiasi altro valore *prima* di chiamare scrypt, così un'immagine
contraffatta non può indurre l'estrattore ad allocare gigabyte (un costo di
2^30 richiederebbe 128 GiB). Test: `test_cost_is_read_from_the_image`,
`test_forged_cost_is_rejected_before_any_key_derivation`,
`test_production_scrypt_cost`, test a risposta nota aggiornati.

**Compromesso.** Sigillare cinque immagini ora richiede circa 2 secondi in
scrypt, e dissigillarne tre circa 1,3 secondi. Le immagini create con la 1.0
non sono leggibili dalla 1.1; nessuna immagine 1.0 era stata distribuita.

### SR-02 — `chi2_sf` va in crash con una statistica subnormale (Bassa)

**Osservazione.** Hypothesis ha generato `statistic = 5e-324` (il più piccolo
double positivo). Dimezzandolo si ha un underflow a 0, e la valutazione della
serie calcola poi `log(0)`, sollevando `ValueError`.

**Impatto.** Un crash in `analyze` per una statistica che le immagini reali non
producono mai; nessun impatto sulla sicurezza, ma è proprio il tipo di caso
limite che un parser di dati forniti da un attaccante non deve avere.

**Correzione.** Il test sullo zero viene eseguito dopo il dimezzamento. Test
di regressione `test_subnormal_statistic_does_not_crash`.

### SR-03 — Verifica-poi-scrittura sugli output (Bassa)

**Osservazione.** Ogni output era protetto da `path.exists()` seguito da una
scrittura. Tra le due operazioni c'è una finestra in cui un file può comparire
(TOCTOU), e `exists()` restituisce `False` per un link simbolico *pendente*,
che la scrittura poi segue: un link con lo stesso nome del file ripristinato da
`unseal` reindirizzerebbe la scrittura verso la destinazione del link.

**Impatto.** Richiede un attaccante in grado di creare link nella directory in
cui l'utente scrive, cosa che l'ipotesi 1 di 05 esclude in larga misura. Difesa
in profondità.

**Correzione.** Tutti gli output passano per `images.write_new`, che crea i
file con `O_CREAT | O_EXCL` a meno che non sia specificato `--force`: il
controllo di esistenza e la creazione sono un'unica operazione atomica, e
qualsiasi nome esistente — compreso un link pendente — viene rifiutato. Test:
`TestWriteNew`, `test_dangling_symlink_is_never_followed`.

### SR-04 — Lacune nei test individuate dal mutation testing (Info)

**Osservazione.** Il mutation testing ha mostrato guasti che la suite non
avrebbe intercettato. Il più rilevante: nessun test vincolava la derivazione
della chiave *senza* passphrase, quindi modificare la stringa di derivazione
della modalità pubblica avrebbe reso silenziosamente illeggibile ogni immagine
priva di passphrase, con tutti i test superati. Altri: campi del rapporto per
immagine (`path`, `share_index`, `detail`) che potevano essere errati senza far
fallire alcun test; i dettagli `rejected` trasportati dagli errori sulle quote;
il budget di ricerca e l'ordine dei blocchi; i confini esatti della capacità;
il comportamento dei limiti ingenui usati dal benchmark.

**Correzione.** 31 test aggiunti (si veda il §6.8), tra cui un test a risposta
nota per l'inserimento in modalità pubblica. I 55 test aggiunti complessivamente
dalla revisione sono questi, le 16 proprietà del §6.7 e 8 test di regressione
per SR-01, SR-02, SR-03 e SR-05.

### SR-05 — Modalità di sostituzione senza avvertimento (Info)

`--method replacement` esiste per dimostrare ciò che gli attacchi rilevano.
Usata per un vault reale, rende le immagini rilevabili (05 §5.5). La CLI ora
stampa un avvertimento ogni volta che viene selezionata.

### SR-06 — Nessun file di lock (Accettato, Info)

Le dipendenze di runtime hanno solo limiti inferiori, e la CI installa le
versioni più recenti. Una release malevola o difettosa di una dipendenza
verrebbe quindi recepita. Accettato per uno strumento in stile libreria che gli
utenti installano nei propri ambienti, dove un file di lock non si
applicherebbe; mitigato da pip-audit nella CI e dai test a risposta nota, che
falliscono se l'aggiornamento di una dipendenza cambia un qualsiasi output.

### SR-07 — Posizioni pubbliche del sale (Accettato, Info)

Le 136 posizioni che contengono il sale e il costo sono derivate da una chiave
pubblica e dall'insieme dei campioni idonei, quindi chiunque può localizzarle e
leggerle. Devono essere leggibili prima che esista qualsiasi chiave. Il sale è
uniformemente casuale e il byte del costo è costante, quindi ciò che un
osservatore vi legge sono 128 bit casuali e 8 bit che sono per lo più LSB
inalterati dell'immagine di copertura in posizioni sparse — non più
distinguibili da un'immagine pulita di qualsiasi altro gruppo di 136 campioni.
Accettato.

### SR-08 — Hook `random_bytes` (Accettato, Info)

`embed`, `split` e `seal` accettano un callable `random_bytes` affinché i test
possano essere deterministici. Un chiamante che passasse un generatore debole
indebolirebbe ogni chiave. La CLI non ne passa mai uno; il parametro è
documentato come hook per i test. Accettato.

## 6.5 Revisione precedente (prima della 1.0.0)

Una lettura indipendente del codice prima del rilascio 1.0.0 ha segnalato
problemi che sono stati corretti prima di quel rilascio; sono elencati qui per
completezza.

| Gravità | Problema | Correzione |
| --- | --- | --- |
| Alta | Una sola quota errata elencata per prima poteva esaurire la ricerca; una valanga di quote che riutilizzavano uno stesso indice la faceva esplodere | Prima i blocchi disgiunti, poi combinazioni di indici con una quota per indice (ADR-09) |
| Media | Veniva accettato il primo sottoinsieme autoconsistente, quindi quote fabbricate potevano prevalere | Ricerca per cluster; decide il tag GCM del vault (ADR-09) |
| Media | Sale derivato dalla dimensione dell'immagine: posizioni e chiavi condivise tra immagini, scrypt precalcolabile | Sale casuale per immagine (ADR-05) |
| Media | Memoria proporzionale alla dimensione dell'immagine (circa 1 GiB per una foto da 12 MP) | Percorso con campionamento per rifiuto (ADR-04) |
| Media | `--name` poteva sovrascrivere un'immagine di quota; collisioni di nomi che differivano solo per maiuscole/minuscole | Controlli di collisione con case folding |
| Media | Diversi errori terminavano con traceback | `ShardpixError` ovunque, `OSError` intercettato in `main` |
| Media | I nomi dei file ripristinati potevano contenere caratteri di controllo e sequenze di escape | `safe_filename` rimuove Cc/Cf e i nomi riservati |
| Bassa | Immagini di copertura JPEG rilevabili tramite analisi di compatibilità JPEG | Avvertimento e documentazione |
| Bassa | `combine -o` poteva sovrascrivere il proprio input | Input protetti |

## 6.6 Analisi statica

| Strumento | Configurazione | Risultato |
| --- | --- | --- |
| bandit | Set di regole predefinito, ricorsivo su `shardpix/` (2.522 righe) | 0 problemi |
| semgrep | 112 regole del set ufficiale `python` | 0 problemi rilevati, 0 errori |
| pip-audit | `requirements.txt`, 9 pacchetti risolti | 0 vulnerabilità note |

Un risultato pulito da questi strumenti è atteso per codice che non usa
`eval`, `pickle`, `subprocess` né `random` e non riceve input dalla rete; il
loro ruolo è fare in modo che resti così. Tutti e tre ora vengono eseguiti nel
job CI `security` a ogni push.

## 6.7 Property-based testing e fuzzing

[tests/test_properties.py](../tests/test_properties.py) enuncia 16 proprietà.
Il profilo predefinito esegue 60 casi per proprietà nella suite normale; il
profilo `fuzz` (`HYPOTHESIS_PROFILE=fuzz`, eseguito nella CI) ne esegue 3.000,
circa 48.000 casi in 90 secondi.

| Area | Proprietà |
| --- | --- |
| GF(256) | Assiomi di campo; la divisione inverte la moltiplicazione |
| Shamir | Qualsiasi sottoinsieme di almeno k quote recupera il segreto e verifica ogni quota; meno di k falliscono sempre; le codifiche sono senza perdita |
| Shamir | `from_bytes` e `from_text` sollevano solo `ShareFormatError` su byte e testo arbitrari |
| Shamir | Qualsiasi singolo byte corrotto viene intercettato dal checksum |
| Shamir | Un valore alterato con un checksum valido non viene mai usato, e il segreto autentico viene comunque recuperato |
| Stego | Qualsiasi carico che ci stia compie il ciclo completo su immagini casuali di ogni modalità, con distorsione ≤ 1 |
| Stego | La modifica di un qualsiasi singolo campione produce il carico originale o nessuno — mai dati diversi |
| Stego | L'estrazione da immagini arbitrarie solleva solo `PayloadNotFoundError` |
| Vault | Il parser dell'intestazione solleva solo `VaultError` su byte arbitrari |
| Vault | L'output di `safe_filename` non contiene mai separatori, caratteri di controllo o di formato, `.`/`..` o nomi riservati, per qualsiasi input Unicode |
| Analisi | `chi2_sf` è una probabilità decrescente; RS non va mai in crash e resta finito |

Una proprietà è fallita durante la revisione: la proprietà di monotonia di
`chi2_sf` ha individuato SR-02. Tutte le proprietà passano dopo la correzione.

## 6.8 Mutation testing

Il mutation testing introduce piccoli guasti — un operatore invertito, una
costante modificata, un argomento eliminato — e verifica che qualche test
fallisca. Misura se i test *rilevano* i guasti, cosa che la copertura delle
righe non può fare.

mutmut è stato eseguito su `gf256.py`, `shamir.py`, `stego.py` e `vault.py`.
Poiché mutmut instrumenta il codice a livello di funzione e seleziona i test
per funzione, può segnalare come sopravvissuto un mutante che la suite reale
intercetterebbe. Ogni mutante segnalato come sopravvissuto è stato quindi
applicato a una copia pulita del sorgente, ed è stata eseguita su di esso
l'intera suite.

| Turno | Codice | Mutanti | Rilevati | Sopravvissuti dopo la riesecuzione | Punteggio |
| --- | --- | ---: | ---: | ---: | ---: |
| 1 | 1.0.0, suite originale | 1.552 | 1.287 | 228 (+37 non rieseguiti) | 82,9% (limite inferiore) |
| 2 | dopo il primo giro di nuovi test e SR-01 | 1.573 | 1.386 | 150 (+37 non rieseguiti) | 88,1% (limite inferiore) |
| 3 | codice finale, suite finale | 1.575 | 1.429 | 146 | 90,7% |
| 3, dopo le ultime due correzioni | idem, più i due test descritti sotto | 1.575 | 1.431 | 144 | **90,9%** |

"Rilevati" conta i mutanti che fanno fallire un test o ne provocano il timeout
(un ciclo infinito è un guasto rilevato). Nei turni 1 e 2, 37 mutanti di metodi
di classe non hanno potuto essere riapplicati dallo script di verifica e sono
contati come sopravvissuti; nel turno 3 sono stati invece riapplicati con
`mutmut apply` (4 sono stati rilevati, 33 sopravvivono e sono classificati più
sotto). Dei 146 sopravvissuti del turno 3, due hanno evidenziato lacune reali,
colmate in seguito e verificate riapplicando il mutante:

- `rstrip("=")` → `rstrip("XX=XX")` in `Share.to_text`. Base32 contiene la
  lettera X; una quota la cui codifica termina con "X" perderebbe caratteri.
  Gli input casuali dei test non producono quasi mai una quota del genere —
  solo le lunghezze multiple di 5 byte sono prive di padding, e anche in quel
  caso solo 1 volta su 32 — quindi ora un test dedicato ne costruisce una.
- `save_png(..., overwrite=force)` → `save_png(...)` in `seal`: innocuo perché
  `seal` controlla prima l'esistenza dei file, ma riapriva la race di SR-03.
  `save_png` ora usa per impostazione predefinita la creazione esclusiva.

I mutanti sopravvissuti del turno finale, classificati uno per uno:

| Categoria | Mutanti | Perché sopravvivono |
| --- | ---: | --- |
| Testo dei messaggi di errore e del rapporto | 66 | I test confrontano i messaggi per parole chiave, non carattere per carattere; un messaggio mutato si legge comunque come un errore. Scelta deliberata: vincolare ogni messaggio renderebbe la suite fragile senza proteggere alcuna proprietà di sicurezza. |
| Equivalenti: argomenti predefiniti e parametri innocui | 39 | `to_bytes(2, "big")` → `to_bytes(2)` (big-endian è il valore predefinito da Python 3.11), `strict=True` su zip di uguale lunghezza, `copy=True` su una conversione che copia sempre, `"utf-8"` → `"UTF-8"`, un `maxmem` di scrypt più grande, … |
| Equivalenti: elementi identici | 6 | `subset[0]` → `subset[1]` dove ogni elemento ha lo stesso group id, la stessa soglia e la stessa lunghezza. |
| Equivalenti: argomentati singolarmente | 33 | Riavvolgimento della tabella degli antilogaritmi in `div`; valori iniziali di tabelle che vengono interamente sovrascritte; dimensioni dei batch del percorso, che per costruzione non possono cambiare il percorso; la coda di rifiuto del percorso (probabilità inferiore a 10⁻¹⁰); controlli preliminari più deboli seguiti da un'autenticazione che fallisce comunque; `support = used − confirmed`, che è uguale per due cluster esattamente quando lo è `used + confirmed`, poiché entrambi usano k quote. |
| **Totale** | **144** | |

Escludendo i 78 mutanti equivalenti, che per definizione nessun test può
rilevare, la suite rileva 1.431 mutanti su 1.497 (95,6%); i restanti 66 sono
testi di messaggi.

Esempi di mutanti che sopravvivono perché equivalenti:

- `EXP[LOG[a] + ORDER - LOG[b]]` → `EXP[LOG[a] - ORDER - LOG[b]]` in `div`:
  l'indice diventa negativo, Python indicizza dalla fine della tabella di 510
  voci, e la tabella degli antilogaritmi è periodica con periodo 255 — stesso
  risultato.
- `share.group_id != subset[0].group_id` → `subset[1]`: ogni quota di un
  cluster ha lo stesso group id.
- Dimensioni dei batch nel percorso con chiave: il percorso è la stessa
  sequenza comunque venga letto il keystream (ADR-04), che è esattamente la
  proprietà che il mutante non può violare.
- Rifiuto della coda distorta delle parole a 64 bit: per qualsiasi dimensione
  dell'immagine la probabilità che una parola cada nella coda è inferiore a
  10⁻¹⁰, quindi nessun test può osservarne la rimozione; il rifiuto viene
  mantenuto perché la correttezza non dovrebbe dipendere dalla probabilità.

## 6.9 Checklist della revisione manuale

| Controllo | Requisito | Valutazione |
| --- | --- | --- |
| ASVS 6.2.1 | I moduli falliscono in modo sicuro; nessun oracolo nella gestione degli errori | Superato. Passphrase errata, immagine pulita e immagine modificata danno un unico errore (SP-08); i fallimenti di decifratura non restituiscono mai dati parziali. |
| ASVS 6.2.2 | Algoritmi e librerie collaudati dall'industria | Superato. AES-GCM, ChaCha20, HMAC-SHA256, HKDF, scrypt da `cryptography`/`hashlib`. Codice proprio limitato a Shamir, GF(256), inserimento e steganalisi (ADR-02). |
| ASVS 6.2.3 | Configurazione corretta di IV, modalità e padding | Superato. Solo AEAD; nonce casuali a 96 bit; nessun padding. |
| ASVS 6.2.4 | Algoritmi e parametri sostituibili | Superato dopo SR-01. Ogni formato è versionato; il costo di scrypt è memorizzato per immagine. |
| ASVS 6.2.5 | Nessuna modalità o primitiva insicura | Superato. Nessun ECB, CBC, MD5, SHA-1. ChaCha20 è usato come keystream con nonce nullo sotto chiavi monouso. |
| ASVS 6.2.6 | Nonce non riutilizzati con la stessa chiave | Superato. Ogni chiave AES-GCM cifra una sola volta: la chiave del vault è nuova per ogni vault, la chiave stego nuova per ogni immagine grazie al sale. |
| ASVS 6.2.7 | I dati cifrati sono autenticati | Superato. Vault, carico stego e quote sono tutti autenticati; l'intestazione del vault è AAD. |
| ASVS 6.2.8 | Operazioni a tempo costante sui segreti | Parziale. I confronti di MAC e checksum usano `hmac.compare_digest`. Le consultazioni delle tabelle GF(256) non sono a tempo costante; accettato per uno strumento locale (05 §5.6). |
| ASVS 6.3.1 | Casualità crittograficamente sicura | Superato. `os.urandom` per chiavi, sali, nonce, coefficienti e direzioni ±1. `numpy.random` compare solo nel benchmark e nei test. |
| ASVS 6.3.3 | Entropia sufficiente | Superato. Chiavi a 256 bit, sali e group id a 128 bit. |
| ASVS 6.4.1–6.4.2 | Materiale delle chiavi isolato, non esposto | Superato con limitazione. Le chiavi non toccano mai il disco; le passphrase non compaiono mai sulla riga di comando. Python non può cancellare la memoria (05 §5.6). |
| ASVS 2.4.1 / OWASP cheat sheet | Hashing della passphrase con una funzione approvata, memory-hard, e parametri attuali | Superato dopo SR-01 (scrypt N = 2^17, r = 8, p = 1). |
| ASVS 5.1.3 / 12.1.1 | Validazione degli input; limiti di risorse sui file | Superato. Limite contro le bombe di decompressione, limite di 2 GiB per file, tetto al costo di scrypt, budget di ricerca, controlli di lunghezza prima della decifratura. |
| ASVS 7.4.1 | Messaggi di errore generici, nessuno stack trace | Superato. `TestCleanErrors`. |
| ASVS 12.3.1–12.3.2 | I nomi di file provenienti da dati non fidati sono sanificati; nessun path traversal | Superato. `safe_filename`, verificato con test di proprietà. |
| ASVS V12.3 (generale) | File scritti senza race né attraversamento di link | Superato dopo SR-03. |
| ASVS 14.2.1 | Dipendenze aggiornate, nessuna vulnerabilità nota | Superato, con SR-06 accettato. |

## 6.10 Rischi accettati

Oltre a SR-06–SR-08, restano accettate le limitazioni elencate in 05 §5.6: la
debole rilevabilità delle quote in immagini di copertura piccole da parte della
steganalisi addestrata (misurata in 05 §5.5.5; mitigata usando immagini di
copertura a colori di almeno 2 megapixel), le immagini di copertura JPEG, la
disponibilità delle immagini di copertura, la ricompressione durante il
trasporto, i metadati visibili del vault, una sola passphrase per vault,
l'aritmetica non a tempo costante e la memoria che non può essere cancellata, e
il budget di ricerca come limite contro il denial of service.

## 6.11 Riprodurre questa revisione

```bash
pip install -e ".[dev,audit]" semgrep

bandit -r shardpix
semgrep scan --config p/python --metrics=off shardpix
pip-audit -r requirements.txt

HYPOTHESIS_PROFILE=fuzz pytest -q tests/test_properties.py

mutmut run          # configuration in pyproject.toml ([tool.mutmut])
mutmut results      # then re-run each survivor against the full suite
```

## 6.12 Consegna per una revisione indipendente

Un revisore esterno darebbe il massimo contributo attaccando ciò che questa
revisione ha potuto soltanto argomentare:

1. **SP-03, segretezza di k − 1 quote con la chiave MAC condivisa** (ADR-08).
   L'argomentazione è in 05 §5.3 e un test enumera esaustivamente il caso
   k = 2; uno schema di dimostrazione rivisto da qualcun altro chiuderebbe la
   questione.
2. **La ricerca per cluster** (`shamir.recover_all`) con insiemi di quote
   ostili, compresi il budget e le motivazioni riportate.
3. **La rilevabilità** contro una steganalisi addestrata più forte di quella
   che 05 §5.5.5 ha potuto eseguire su una CPU — l'SRM completo, SRNet — e su
   grandi foto a colori, dove la soglia dei 2 megapixel è estrapolata, non
   misurata. Test in condizioni di cover-source mismatch mostrerebbero quanto
   del vantaggio misurato sopravvive fuori dal laboratorio.
4. **Il percorso pubblico** e se le sue posizioni, insieme al byte del costo,
   lascino trapelare qualcosa attraverso molte immagini.
5. **I canali laterali** nell'estrazione, qualora shardpix venisse mai usato al
   di fuori di una macchina locale fidata.
