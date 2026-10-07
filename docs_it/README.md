# Documentazione tecnica — shardpix

> Traduzione italiana di [docs/README.md](../docs/README.md). In caso di differenze fa fede la versione inglese.

| | |
| --- | --- |
| Sistema | shardpix 1.1.0 |
| Tipo di documento | Software Design Description (SDD) |
| Struttura di riferimento | ISO/IEC/IEEE 1016 |
| Notazione dei diagrammi | UML 2.5, resa in Mermaid |
| Ultima revisione | 2026-10-06 |

## Indice

| Documento | Contenuto | A chi è rivolto |
| --- | --- | --- |
| [01 — Architettura](01-architecture.md) | Vista di contesto, package, modello dei dati, formati su disco, decisioni architetturali (ADR), deployment, requisiti non funzionali | A chi deve capire come è costruito il sistema, e perché |
| [02 — Casi d'uso](02-use-cases.md) | Attori, diagramma dei casi d'uso, nove specifiche dettagliate con flussi principali e alternativi, scenari operativi, vincoli di legittimità | A chi deve capire a che cosa serve il sistema |
| [03 — Riferimento delle funzioni](03-function-reference.md) | Ogni modulo, funzione, classe e costante: comportamento, casi limite, gestione degli errori, test che li coprono | A chi modifica o estende il codice |
| [04 — Comportamento a runtime](04-runtime-behaviour.md) | Diagrammi di sequenza, l'algoritmo di recupero delle quote, propagazione degli errori, codici di uscita, profilo dei tempi, strategia di verifica | A chi deve capire che cosa succede a runtime |
| [05 — Analisi di sicurezza](05-security-analysis.md) | Modello delle minacce, proprietà di sicurezza e relative argomentazioni, parametri crittografici, risultati di steganalisi, limitazioni note | A chi deve decidere se fidarsene |
| [06 — Revisione di sicurezza](06-security-review.md) | Rapporto di revisione interna: metodo, analisi statica, fuzzing, mutation testing, checklist ASVS, rilievi e correzioni, passaggio di consegne per un audit indipendente | A chi valuta come sono state verificate le affermazioni |
| [07 — Immagini di copertura e formati](07-covers-and-formats.md) | PNG e JPEG, i metodi di inserimento, che cosa succede a ciascun tipo di input, le foto da telefono passo per passo | A chi sceglie le foto da usare |

Per l'installazione e l'uso quotidiano, vedere il [README del progetto](../README.it.md).

## Diagrammi inclusi

| Tipo UML | Dove | Oggetto |
| --- | --- | --- |
| Diagramma di contesto | 01 §1.2 | Sistema, attori e artefatti che produce |
| Diagramma dei package | 01 §1.3 | Livelli e regola delle dipendenze |
| Diagramma delle classi | 01 §1.4 | Modello dei dati dei livelli stego, sharing e vault |
| Diagramma di deployment | 01 §1.7 | Nodo di esecuzione e artefatti consegnati a ciascun custode |
| Diagramma dei casi d'uso | 02 §2.2 | Nove casi d'uso con relazioni *include* ed *extend* |
| Diagramma di sequenza | 04 §4.2–4.5 | `seal`, `unseal`, inserimento, estrazione |
| Diagramma di attività | 04 §4.6 | Recupero delle quote: ricerca per cluster |
| Diagramma di stato | 04 §4.7 | Vita di una singola immagine durante `unseal` |

I diagrammi sono scritti in Mermaid e resi nativamente da GitHub, GitLab e dalla
maggior parte degli editor Markdown. Non richiedono strumenti esterni né
esportazione di immagini: il sorgente del diagramma è versionato accanto al
testo, così una modifica al codice e il relativo aggiornamento del diagramma
finiscono nello stesso commit. I grafici in 05 sono generati dal benchmark
(`python -m shardpix.analysis.benchmark`) a partire dai risultati grezzi in
[data/benchmark.json](../docs/data/benchmark.json), e dal benchmark con rilevatore
addestrato (`python -m shardpix.analysis.ml_benchmark --plot-only --size 512`)
a partire da [data/ml_benchmark_512.json](../docs/data/ml_benchmark_512.json) e
[data/ml_benchmark_256.json](../docs/data/ml_benchmark_256.json).

## Convenzioni

- I riferimenti al codice sono link relativi al file sorgente, così restano
  navigabili sia su GitHub sia in locale.
- Le decisioni architetturali sono numerate `ADR-nn` e citate dai documenti che
  ne dipendono.
- I casi d'uso sono numerati `UC-nn`; la matrice di tracciabilità in
  [02 §2.3](02-use-cases.md) collega ciascuno di essi al modulo che lo realizza
  e ai test che lo verificano.
- Le proprietà di sicurezza sono numerate `SP-nn` in
  [05 §5.3](05-security-analysis.md).
- I layout dei byte sono big-endian ovunque.

## Manutenzione

Questa documentazione descrive il comportamento effettivo del codice alla
revisione indicata sopra, non un'intenzione progettuale. Qualsiasi modifica che
alteri la firma di una funzione, un flusso di errore, un codice di uscita o un
formato su disco richiede che il documento corrispondente sia aggiornato nello
stesso commit; una modifica a un formato richiede inoltre una nuova versione del
formato e nuovi valori in
[tests/test_known_answers.py](../tests/test_known_answers.py).
