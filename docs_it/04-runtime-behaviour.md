# 4. Comportamento a runtime

| | |
| --- | --- |
| Documento | SDD-04 — Vista dinamica |
| Sistema | shardpix 2.0.0 |
| Stato | Approvato |
| Ultima revisione | 2026-10-07 |
| Lingua | Italiano (traduzione di [docs/04-runtime-behaviour.md](../docs/04-runtime-behaviour.md); in caso di differenze fa fede l'inglese) |

## 4.1 Scopo

Questo documento descrive ciò che accade a runtime: le interazioni tra i
componenti per ciascun comando principale, l'algoritmo di recupero delle quote,
il modo in cui gli errori si propagano fino ai codici di uscita e quanto tempo
richiedono le operazioni. La struttura statica corrispondente si trova in
[01-architecture.md](01-architecture.md).

## 4.2 Sigillare un file

```mermaid
sequenceDiagram
    actor O as Proprietario
    participant CLI as cli.cmd_seal
    participant V as vault.seal
    participant IMG as images
    participant SH as shamir.split
    participant ST as stego.embed

    O->>CLI: shardpix seal notes.pdf photos/*.png -k 3 -p
    activate CLI
    CLI->>O: Passphrase / Ripeti la passphrase
    O-->>CLI: passphrase
    CLI->>V: seal(file, covers, 3, out_dir, passphrase)
    activate V
    V->>V: verifica k, n, immagini di copertura distinte,<br/>dimensione del file, lunghezza del nome
    V->>V: calcola gli output, rifiuta collisioni<br/>e sovrascritture
    loop ogni immagine di copertura
        V->>IMG: load_image(cover)
        IMG-->>V: Carrier
        V->>V: verifica capacità >= 109 byte
    end
    Note over V: non è ancora stato scritto nulla
    V->>V: chiave casuale, id di gruppo, nonce
    V->>V: AES-256-GCM(nome + file),<br/>AAD = intestazione
    V->>SH: split(key, 3, n, group_id)
    SH-->>V: n quote
    loop quota i nell'immagine di copertura i
        V->>ST: embed(carrier, share, passphrase)
        ST-->>V: Carrier stego, EmbedReport
        V->>IMG: save_png(stego, sealed/cover_i.png)
    end
    V->>V: scrive sealed/notes.pdf.spx
    V-->>CLI: SealResult
    deactivate V
    CLI-->>O: tabella: immagine, quota, tasso, modifiche
    CLI-->>O: uscita 0
    deactivate CLI
```

Ogni controllo che può fallire viene eseguito prima della prima scrittura,
quindi un errore di battitura nel nome di un'immagine di copertura o
un'immagine di copertura troppo piccola lasciano la directory di output
esattamente com'era. Gli unici errori che possono lasciare un output parziale
sono quelli del file system stesso (disco pieno, permessi) a metà della
scrittura.

## 4.3 Aprire un vault

```mermaid
sequenceDiagram
    actor R as Parte che recupera
    participant CLI as cli.cmd_unseal
    participant V as vault.unseal
    participant ST as stego.extract
    participant SH as shamir.recover_all

    R->>CLI: shardpix unseal notes.pdf.spx a.png b.png c.png d.png -p
    activate CLI
    CLI->>V: unseal(vault, images, passphrase)
    activate V
    V->>V: legge l'intestazione, scarta i percorsi ripetuti
    loop ogni immagine
        V->>ST: extract(carrier, passphrase)
        alt carico trovato
            ST-->>V: byte
            V->>V: analizza la Share, confronta l'id di gruppo
        else passphrase errata / pulita / modificata
            ST-->>V: PayloadNotFoundError
            V->>V: esito "nessun carico"
        end
    end
    V->>SH: recover_all(shares)
    SH-->>V: cluster, dal più grande
    loop ogni cluster
        V->>V: decifratura AES-GCM con la chiave del cluster
        alt il tag è verificato
            V->>V: mantiene questo cluster, si ferma
        end
    end
    V-->>CLI: UnsealResult (nome del file, dati, esiti)
    deactivate V
    CLI-->>R: tabella: immagine, quota, stato, dettaglio
    CLI->>CLI: nome ripulito, rifiuta la sovrascrittura
    CLI-->>R: file scritto, uscita 0
    deactivate CLI
```

Il tag di autenticazione del vault è l'arbitro di ultima istanza. Le quote
possono soltanto dimostrare di essere coerenti tra loro; solo il vault può
dimostrare che sono le *sue* quote. È questo che sventa un insieme di quote
fabbricate che risulti più numeroso di quello autentico (05 SP-06).

## 4.4 Inserimento di un carico

```mermaid
sequenceDiagram
    participant C as chiamante
    participant E as stego.embed
    participant W as SampleOrder
    participant K as derive_key

    participant T as stc / costi

    C->>E: embed(carrier, payload, passphrase)
    E->>E: campioni, idonei = 2..253, verifica della capacità
    E->>E: sale = 16 byte casuali, costo = 17 | 0x80
    E->>K: derive_key(passphrase, salt, versione 4)
    K->>K: scrypt(N=2^17, r=8, p=1) poi HKDF x4
    K-->>E: order, aead, length_mask, code
    E->>E: frame = lunghezza mascherata + nonce + AES-GCM(carico)
    E->>T: costi HiLL di ogni campione
    E->>W: percorso pubblico sui campioni idonei
    W-->>E: 136 x w0 candidati per sale e costo
    E->>W: percorso con chiave sugli idonei esclusi quelli
    W-->>E: 32 x w0 candidati per la lunghezza,<br/>poi w x 8 x (len(frame) - 4) per il corpo
    loop sale + costo, lunghezza, corpo
        E->>T: Viterbi: LSB a costo minimo con la sindrome corretta
        T-->>E: campioni da invertire
        E->>E: modifica ciascuno di +-1 (in su a 2, in giù a 253)
    end
    E-->>C: carrier stego, EmbedReport
```

Un'immagine di copertura JPEG segue invece lo stesso percorso tramite
`jpeg.embed` (formato 5): `media.open_cover` ne legge i coefficienti
quantizzati senza decodificarli, i candidati sono i coefficienti AC di
luminanza non nulli, i costi sono UERD, e il risultato viene riscritto come
JPEG con le tabelle e i metadati originali. I metodi di base del formato 3,
usati solo dai benchmark, scrivono un bit per campione senza costi né codici.

## 4.5 Estrazione di un carico

L'estrazione rispecchia l'inserimento. Prova prima il formato 4 e, se non
trova nulla, il formato 3; un byte di costo appartenente all'altro formato, o
un costo fuori intervallo, termina un tentativo prima di qualsiasi derivazione
della chiave, quindi la lettura di un'immagine in formato 3 non costa quasi mai
un secondo scrypt. Nel formato 4 ogni lettura descritta sotto è una sindrome
su `w0` o `w` candidati per bit anziché un singolo LSB; il diagramma mostra il
formato 3. In entrambi i casi il percorso viene letto due volte. L'estrattore
ha prima bisogno di 32 posizioni per leggere la lunghezza, e solo allora sa
quante altre leggerne. `SampleOrder.first` memorizza in cache ciò che ha già
calcolato, così la seconda chiamata estende la prima invece di ricominciare da
capo e, poiché ogni prefisso del percorso è stabile (ADR-04), le prime 32
posizioni sono le stesse in entrambe le chiamate.

```mermaid
sequenceDiagram
    participant C as chiamante
    participant X as stego.extract
    participant W as SampleOrder

    C->>X: extract(carrier, passphrase)
    X->>X: idonei = 2..253 (stesso insieme di prima dell'inserimento)
    X->>W: percorso pubblico
    W-->>X: 136 posizioni
    X->>X: sale e costo = i loro LSB,<br/>rifiuta costi oltre 2^18, deriva le chiavi
    X->>W: percorso con chiave: first(32)
    W-->>X: posizioni della lunghezza
    X->>X: smaschera la lunghezza, verifica i limiti
    X->>W: percorso con chiave: first(32 + 8 x lunghezza)
    W-->>X: posizioni del frame (prefisso riutilizzato)
    X->>X: decifratura AES-GCM
    alt il tag è verificato
        X-->>C: carico
    else
        X-->>C: PayloadNotFoundError
    end
```

## 4.6 Recupero delle quote: ricerca dei cluster

`shamir.recover_all` deve gestire qualsiasi combinazione di quote valide,
danneggiate, duplicate, estranee e fabbricate, con una quantità di lavoro
limitata.

```mermaid
flowchart TD
    A([quote]) --> B[deduplica per codifica]
    B --> C[raggruppa per id di gruppo, soglia, lunghezza del segreto]
    C --> D{gruppo successivo}
    D -->|nessuno rimasto| M
    D --> E{almeno k indici distinti<br/>rimasti nel pool?}
    E -->|no| D
    E -->|sì| F[k-sottoinsieme candidato successivo:<br/>prima blocchi disgiunti,<br/>poi combinazioni di indici]
    F --> G{budget residuo?}
    G -->|no| D
    G -->|sì| H[interpola il segreto e la chiave MAC]
    H --> I{ogni quota del sottoinsieme<br/>è verificata con quella chiave?}
    I -->|no| F
    I -->|sì| J[cluster = sottoinsieme + ogni quota del pool<br/>verificata con la chiave]
    J --> K[rimuove il cluster dal pool]
    K --> E
    M{qualche cluster?} -->|no| N([errore InsufficientShares o<br/>ShareAuthentication])
    M -->|sì| O[ordina i cluster per dimensione,<br/>associa un motivo a ogni altra quota]
    O --> P([lista di Recovery])
```

Due proprietà rendono questo procedimento economico nella pratica e corretto
sotto attacco.

**I cluster non si sovrappongono mai.** Il MAC di una quota viene verificato
con una sola chiave MAC, quindi una quota autentica non può mai entrare in un
cluster fabbricato e viceversa. Rimuovere dal pool un cluster trovato non fa
quindi perdere nulla.

**I blocchi disgiunti vengono per primi.** Se le quote non valide sono meno dei
blocchi di k, un blocco è interamente valido. Con una quota danneggiata su
venti in una suddivisione 6-di-20 il secondo candidato ha successo; nel
semplice ordine delle combinazioni i primi C(19, 5) = 11.628 candidati
conterrebbero tutti la quota danneggiata. Le combinazioni di indici incrociate
con una quota per indice garantiscono poi che un'ondata di impostori che
riutilizzano uno stesso indice costi un tentativo per impostore, non
un'esplosione di combinazioni.

`combine` prende il primo recupero (il più grande) e rifiuta i pareggi;
`unseal` li prova tutti contro il tag del vault.

## 4.7 Ciclo di vita di un'immagine durante l'apertura

```mermaid
stateDiagram-v2
    [*] --> Loaded: load_image
    Loaded --> Unreadable: non è un'immagine
    Loaded --> Extracted: carico autenticato
    Loaded --> NoPayload: passphrase errata, pulita o modificata
    Extracted --> Rejected: non è una quota valida
    Extracted --> OtherVault: id di gruppo diverso
    Extracted --> Duplicate: stessa quota di un'immagine precedente
    Extracted --> Candidate
    Candidate --> Used: nel cluster che apre il vault, interpolata
    Candidate --> Verified: in quel cluster, non necessaria
    Candidate --> Rejected: fuori da esso (corrotta, contraffatta)
    Candidate --> Unverified: recupero fallito, la quota sembrava valida
    Unreadable --> [*]
    NoPayload --> [*]
    OtherVault --> [*]
    Duplicate --> [*]
    Used --> [*]
    Verified --> [*]
    Rejected --> [*]
    Unverified --> [*]
```

Ogni immagine termina in esattamente uno stato, e la CLI stampa una riga per
immagine sia che l'apertura riesca sia che fallisca: chi deve rintracciare un
detentore mancante ha bisogno di sapere quale immagine ha causato il problema.

## 4.8 Propagazione degli errori

| Livello | Meccanismo | Esempio |
| --- | --- | --- |
| Funzioni pure | Sollevano una specifica sottoclasse di `ShardpixError`, o `ValueError` per una precondizione violata | `CapacityError`, `ShareFormatError` |
| Lavoro per immagine in `unseal` | Intercettato e registrato come `ImageOutcome`; il ciclo prosegue | Un'immagine illeggibile non impedisce la lettura delle altre |
| Lavoro per riga in `combine` | Righe malformate raccolte come problemi, segnalate, saltate | Una quota troncata in un file di cinque |
| Errori del vault e delle quote | Sollevati con i dettagli allegati (`outcomes`, `rejected`) | `VaultError` contiene l'intera tabella per immagine |
| `cli.main` | `ShardpixError` e `OSError` → messaggio di una riga, uscita 1; argparse → uscita 2; Ctrl-C → uscita 130 | `error: s.jpg: output must be a .png file …` |

| Codice di uscita | Significato |
| --- | --- |
| 0 | Successo |
| 1 | Errore previsto: input non valido, passphrase errata, quote insufficienti, errore di I/O |
| 2 | Errore di utilizzo (opzione sconosciuta, argomento mancante) |
| 130 | Interrotto |

La validazione avviene il prima possibile: la soglia, le immagini di copertura
e ogni percorso di output vengono controllati prima che la passphrase venga
usata per qualsiasi cosa, e prima che venga scritto un solo file.

## 4.9 Profilo dei tempi indicativo

Misurato su una VM cloud (Python 3.13, un core), come ordine di grandezza.
Le righe del formato 4 sono state misurate mentre un altro job condivideva la
CPU, quindi sono limiti superiori.

| Operazione | Durata |
| --- | --- |
| Derivazione della chiave (scrypt, N = 2^17) | ~0,42 s per immagine |
| `embed` / `extract`, 512 × 512 RGB, carico di una quota di vault, formato 3 | ~0,45 s ciascuno, principalmente scrypt |
| `embed`, 1920 × 1080 RGB, carico di una quota di vault, formato 3 | ~0,5 s |
| `embed`, carico di una quota di vault, formato 4: 512 × 512 / 1920 × 1080 / 12 MP RGB | ~1,7 s / ~2,3 s / ~8,4 s: scrypt, HiLL sull'intera immagine, Viterbi |
| `extract`, carico di una quota di vault, formato 4, una qualsiasi delle dimensioni sopra | ~0,5 s, principalmente scrypt |
| `seal`, file da 1 MB, 5 immagini di copertura da 512 × 512 | ~2,4 s |
| `seal`, file da 1 MB, 5 immagini di copertura da 1920 × 1080 | ~5,3 s: compressione PNG e scrypt |
| `unseal`, 3 immagini da 512 × 512 o 1920 × 1080 | ~1,3 s, principalmente scrypt |
| `analyze`, 1920 × 1080 RGB | ~1,2 s (RS 0,3 s, chi quadrato sequenziale 0,9 s) |
| Benchmark completo (10 immagini di copertura, 4 strategie, 11 tassi) | ~40 s |
| Suite di test (369 test) | ~60 s con i test del rilevatore addestrato e quelli adattivi |

Nel formato 3 il costo del posizionamento di un carico non dipende dalla
dimensione dell'immagine (ADR-04); ciò che cresce con l'immagine sono la
decodifica, la maschera di idoneità e la codifica PNG. Il formato 4 aggiunge la
mappa dei costi HiLL, che viene calcolata sull'intera immagine e domina per le
foto di grandi dimensioni, e un passaggio di Viterbi la cui lunghezza dipende
solo dal carico.
La dimensione del file conta poco: AES-GCM gira alla velocità della memoria.

## 4.10 Strategia di verifica

```mermaid
graph LR
    subgraph offline["Suite automatica: 310 test, ~9 s, nessuna rete"]
        U1["Aritmetica<br/>GF(256) vs riferimento,<br/>chi2 vs SciPy"]
        U2["Formati<br/>test a risposta nota"]
        U3["Comportamento di sicurezza<br/>manomissione, contraffazione,<br/>passphrase errata"]
        U4["Statistica<br/>attacchi su immagini di copertura sintetiche"]
        U5["CLI<br/>codici di uscita, nessun traceback"]
    end

    subgraph manual["Misurato su fotografie reali"]
        M1["Benchmark<br/>10 foto di pubblico dominio"]
        M2["Revisione indipendente del codice"]
    end

    offline --> CI["CI: Python 3.10–3.13<br/>ruff + pytest"]

    style offline fill:#ebfbee
    style manual fill:#e7f5ff
```

| File di test | Test | Obiettivo |
| --- | --- | --- |
| `test_gf256.py` | 18 | Tutti i 65.536 prodotti confrontati con shift-and-add; esempi FIPS-197; assiomi di campo |
| `test_shamir.py` | 62 | Ogni k-sottoinsieme; segretezza teorica dell'informazione per enumerazione; manomissione; cluster contraffatti; robustezza della ricerca |
| `test_stego.py` | 54 | Andata e ritorno in ogni modalità; autenticazione; limiti di distorsione; invarianza alla saturazione; proprietà del percorso; derivazione della chiave |
| `test_images.py` | 19 | Conversione di modalità, preservazione del canale alfa, output senza perdita, creazione esclusiva dei file |
| `test_chi_square.py` | 17 | Funzione di sopravvivenza vs SciPy; rilevamento su istogrammi "a pettine" |
| `test_rs.py` | 13 | Operazioni di flip; le stime seguono la sostituzione; matching ingenuo vs consapevole della saturazione |
| `test_vault.py` | 59 | Ogni sottoinsieme apre il vault; errori; insiemi contraffatti; collisioni; nomi ripristinati |
| `test_cli.py` | 47 | Ogni comando dall'inizio alla fine; errori puliti |
| `test_known_answers.py` | 5 | Posizioni del percorso, byte delle quote, pixel stego (con e senza passphrase) e byte del vault fissati |
| `test_properties.py` | 16 | Test basati su proprietà e fuzzing del parser (Hypothesis); `HYPOTHESIS_PROFILE=fuzz` per 3.000 casi ciascuno |

Due scelte mantengono la suite veloce e deterministica. Le immagini di
copertura vengono sintetizzate da funzioni regolari più un lieve rumore anziché
caricate da disco, e modellate in base a ciò che ciascun test misura: un
istogramma "a pettine" per i test del chi quadrato, uno con contrasto esteso per
i test sulle immagini pulite. Inoltre il costo di scrypt viene ridotto per i
test da una fixture autouse, mentre un test dedicato verifica i parametri di
produzione e i test a risposta nota vengono eseguiti con essi.
