# Machine Learning Report

> **Status: trained, evaluated and deployed (artifact `1.0.0`).** All numbers
> below come from the saved artifact and the held-out split. Nothing here is a
> placeholder or an estimate.

## 1. Task and labels

Three-class email classification:

| Label | Meaning |
|---|---|
| `LEGITIMATE` | Ordinary non-spam business or personal mail |
| `SPAM` | Unsolicited bulk or commercial mail |
| `PHISHING` | Credential theft, brand impersonation or fraudulent payment mail |

The ML module is one signal among five rule-based detection modules. It never
decides the final verdict alone; the risk engine weights it conservatively and
verified malicious evidence always outranks it.

## 2. Dataset

Built by `ml/preprocessing/build_dataset.py` from documented public corpora.

| Source | Files | Label | Records after cleaning |
|---|---|---:|---:|
| SpamAssassin public corpus | `20030228_easy_ham`, `20030228_hard_ham` | LEGITIMATE | 2,722 |
| SpamAssassin public corpus | `20030228_spam`, `20050311_spam_2` | SPAM | 1,808 |
| Jose Nazario phishing corpus | `phishing-2023`, `phishing-2024`, `phishing-2025` | PHISHING | 1,220 |

- SpamAssassin: <https://spamassassin.apache.org/old/publiccorpus/>. Public
  research corpus; copyright of message text remains with the original senders.
  The corpus itself warns against sending these messages to live mail systems.
- Nazario: <https://monkey.org/~jose/phishing/>. **CC-BY-4.0**. Hand-classified
  and representative rather than exhaustive. Attribution: Jose Nazario.
- Raw records: 5,949. Exact duplicates removed: 199. Final records: 5,750.

Near-duplicate messages are grouped with MinHash LSH over 5-word shingles
(16 lanes, 8 bands) within each label before splitting. Groups never cross
splits, so campaign variants cannot leak from train to test.

Split: stratified by label at the group level, 70/15/15.

| Split | LEGITIMATE | SPAM | PHISHING | Total |
|---|---:|---:|---:|---:|
| Train | 1,906 | 1,286 | 854 | 4,046 |
| Validation | 408 | 251 | 183 | 842 |
| Test | 408 | 271 | 183 | 862 |

Cleaning: subject + `text/plain` body; HTML-to-text when no plain part exists;
attachments ignored; body capped at 20,000 characters for storage; exact
whitespace normalization; empty/short messages dropped.

## 3. Features

- Word TF-IDF, `ngram_range=(1,2)`, 60,000 features, `min_df=2`, sublinear TF.
- Character TF-IDF, `char_wb`, `ngram_range=(3,5)`, 80,000 features, `min_df=3`.
- Combined with a scikit-learn `FeatureUnion`; subject and body are concatenated
  and truncated to 8,000 characters for training and inference.
- Vectorizers are fitted inside each pipeline fold, never on validation/test.

## 4. Models compared

3-fold stratified cross-validation on the training split. `LinearSVC` uses
sigmoid calibration; `MultinomialNB` also uses sigmoid calibration so its
probabilities are usable confidence values. Class weights are balanced for the
linear models and Random Forest.

| Model | Accuracy | Macro F1 | Phishing precision | Phishing recall |
|---|---:|---:|---:|---:|
| MultinomialNB (calibrated) | 0.9748 | 0.9745 | 0.9870 | 0.9684 |
| Logistic Regression | 0.9790 | 0.9789 | 0.9917 | 0.9730 |
| Linear SVM (calibrated) | 0.9815 | 0.9810 | 0.9813 | 0.9813 |
| Random Forest | 0.9686 | 0.9674 | 0.9975 | 0.9426 |

Validation results (fit on train, no test leakage):

| Model | Accuracy | Macro F1 | Phishing precision | Phishing recall |
|---|---:|---:|---:|---:|
| MultinomialNB | 0.9786 | 0.9778 | 0.9944 | 0.9617 |
| **Logistic Regression** | **0.9846** | **0.9840** | **1.0000** | **0.9617** |
| Linear SVM | 0.9846 | 0.9832 | 0.9888 | 0.9672 |
| Random Forest | 0.9715 | 0.9681 | 1.0000 | 0.9180 |

Selection order: highest validation phishing F1, then phishing recall, then
macro F1. **Logistic Regression** was selected and refitted on train +
validation.

## 5. Held-out test results

Evaluated once with the refitted model.

| Metric | Value |
|---|---:|
| Accuracy | 0.9861 |
| Macro F1 | 0.9865 |
| Phishing precision | 0.9945 |
| Phishing recall | 0.9891 |
| Phishing F1 | 0.9918 |

| Class | Precision | Recall | F1 | Support |
|---|---:|---:|---:|---:|
| LEGITIMATE | 0.9926 | 0.9828 | 0.9877 | 408 |
| SPAM | 0.9710 | 0.9889 | 0.9799 | 271 |
| PHISHING | 0.9945 | 0.9891 | 0.9918 | 183 |

Confusion matrix (rows actual, columns predicted):

|  | LEGITIMATE | SPAM | PHISHING |
|---|---:|---:|---:|
| LEGITIMATE | 401 | 6 | 1 |
| SPAM | 3 | 268 | 0 |
| PHISHING | 0 | 2 | 181 |

## 6. Calibration and per-source diagnostics

- Expected calibration error on the test split (10 bins): **0.0523**.
- Mean predicted confidence: 0.9338; accuracy: 0.9861.

Per-source test behaviour (from `ml/evaluation/evaluate.py`):

| Source | Records | Accuracy | Phishing recall |
|---|---:|---:|---:|
| Nazario 2023 | 75 | 1.0000 | 1.0000 |
| Nazario 2024 | 42 | 0.9524 | 0.9524 |
| Nazario 2025 | 66 | 1.0000 | 1.0000 |
| SpamAssassin easy_ham | 380 | 1.0000 | — |
| SpamAssassin hard_ham | 28 | 0.7500 | — |
| SpamAssassin spam | 85 | 0.9765 | — |
| SpamAssassin spam_2 | 186 | 0.9946 | — |

## 7. Known limitations

- **Source and temporal shift.** Legitimate and spam mail are from 2003–2005
  SpamAssassin; phishing is from 2023–2025. In-distribution numbers are strong,
  but they do not measure generalization to new senders, eras or languages.
- **Hard legitimate mail is weaker**: 21 of 28 hard-ham messages were correct
  (75%), with 6 classified as spam and 1 as phishing.
- **Out-of-distribution false positives were observed.** Modern, short,
  plain-text mail (for example a benign report or invoice note) can be scored as
  phishing with high confidence because no modern benign corpus is included.
  This is why the risk engine down-weights ML (`+20 × confidence` for phishing),
  never lets a standalone ML label decide the verdict, and always keeps verified
  malicious evidence and rule-based findings authoritative.
- English only; no attachment or header features; no sender reputation in the
  ML features.
- Confidence is usable but not perfectly calibrated; expect drift on mail unlike
  the training corpora.

Retraining with a licensed modern benign corpus is the highest-value next step.

## 8. Artifact layout

```
ml/artifacts/1.0.0/
├── pipeline.joblib   # complete TF-IDF + LogisticRegression pipeline
├── metadata.json     # version, algorithm, counts, dataset hash, versions
└── metrics.json      # CV, validation, test, calibration, per-source diagnostics
```

`metadata.json` and `metrics.json` are read by `/api/v1/ml/status` and
`/api/v1/ml/metrics`. The backend loads the newest artifact directory (or
`ML_ACTIVE_VERSION`) lazily at inference time. Missing artifacts produce
`UNAVAILABLE`, never a random prediction.

## 9. Reproduction

```bash
# From the repository root
backend/.venv/bin/python ml/preprocessing/build_dataset.py
backend/.venv/bin/python ml/training/train.py --version 1.0.0
backend/.venv/bin/python ml/evaluation/evaluate.py --version 1.0.0 --update
```

Datasets are downloaded into `ml/datasets/raw/` and processed into
`ml/datasets/processed/`. Raw and processed corpora are git-ignored; the exact
counts, hashes and sources are recorded here and in `metadata.json`.
