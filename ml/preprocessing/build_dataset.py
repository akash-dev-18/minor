"""Build a three-class email dataset from documented public corpora.

Sources
-------
- SpamAssassin public corpus (easy_ham, hard_ham, spam, spam_2):
  https://spamassassin.apache.org/old/publiccorpus/
  Public research corpus; copyright of message text remains with the original
  senders. Do not send these messages to live mail systems.
- Jose Nazario phishing corpus (phishing-2025):
  https://monkey.org/~jose/phishing/
  Licensed CC-BY-4.0. Hand-classified, representative rather than exhaustive.

The script downloads archives into ``ml/datasets/raw`` (when missing), extracts
subject + plain text/HTML body, de-duplicates by normalized text hash, and
writes a stratified split plus a dataset card with exact counts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import mailbox
import random
import re
import tarfile
import urllib.request
import zlib
from datetime import datetime, timezone
from email import message_from_bytes, policy
from email.message import Message
from email.utils import parsedate_to_datetime
from html.parser import HTMLParser
from pathlib import Path

SPAMASSASSIN_BASE = "https://spamassassin.apache.org/old/publiccorpus"
SPAMASSASSIN_FILES = {
    "20030228_easy_ham.tar.bz2": "LEGITIMATE",
    "20030228_hard_ham.tar.bz2": "LEGITIMATE",
    "20030228_spam.tar.bz2": "SPAM",
    "20050311_spam_2.tar.bz2": "SPAM",
}
NAZARIO_FILES = {
    "phishing-2023": "PHISHING",
    "phishing-2024": "PHISHING",
    "phishing-2025": "PHISHING",
}

LABELS = ("LEGITIMATE", "SPAM", "PHISHING")
MAX_BODY_CHARS = 20_000
SEED = 20261108
MINHASH_LANES = 16
MINHASH_BANDS = 8
GROUPING_MAX_CHARS = 4_000


class _TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.parts: list[str] = []
        self._skip = False

    def handle_starttag(self, tag: str, attrs) -> None:  # noqa: ANN001
        if tag in {"script", "style"}:
            self._skip = True

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style"}:
            self._skip = False

    def handle_data(self, data: str) -> None:
        if not self._skip:
            self.parts.append(data)


def html_to_text(html: str) -> str:
    parser = _TextExtractor()
    try:
        parser.feed(html)
    except Exception:  # noqa: BLE001
        return html
    return " ".join(parser.parts)


def _decode_part(part: Message) -> str:
    payload = part.get_payload(decode=True)
    if payload is None:
        return ""
    charset = part.get_content_charset() or "utf-8"
    for candidate in (charset, "utf-8", "latin-1"):
        try:
            return payload.decode(candidate, errors="replace")
        except LookupError:
            continue
    return payload.decode("utf-8", errors="replace")


def extract_text(message: Message) -> tuple[str, str]:
    subject = ""
    try:
        subject = str(message.get("subject", ""))
    except Exception:  # noqa: BLE001
        subject = ""
    subject = re.sub(r"\s+", " ", subject).strip()

    plain: list[str] = []
    html: list[str] = []
    parts = message.walk() if message.is_multipart() else [message]
    for part in parts:
        if part.is_multipart():
            continue
        content_type = (part.get_content_type() or "").lower()
        disposition = (part.get("content-disposition") or "").lower()
        if "attachment" in disposition:
            continue
        if content_type == "text/plain":
            plain.append(_decode_part(part))
        elif content_type == "text/html":
            html.append(html_to_text(_decode_part(part)))

    body = "\n".join(plain).strip()
    if not body:
        body = "\n".join(html)
    body = re.sub(r"[ \t]+", " ", body)
    body = re.sub(r"\n{3,}", "\n\n", body).strip()
    return subject, body[:MAX_BODY_CHARS]


def _message_date(message: Message) -> str | None:
    raw = message.get("date")
    if not raw:
        return None
    try:
        return parsedate_to_datetime(str(raw)).astimezone(timezone.utc).isoformat()
    except (TypeError, ValueError):
        return None


def record_from_bytes(raw: bytes, source: str, label: str) -> dict | None:
    try:
        message = message_from_bytes(raw, policy=policy.default)
    except Exception:  # noqa: BLE001
        return None
    subject, body = extract_text(message)
    if len(subject) + len(body) < 24:
        return None
    return {
        "subject": subject,
        "body": body,
        "label": label,
        "source": source,
        "date": _message_date(message),
    }


def download(url: str, target: Path) -> Path:
    if target.is_file() and target.stat().st_size > 0:
        return target
    target.parent.mkdir(parents=True, exist_ok=True)
    print(f"downloading {url}")
    with urllib.request.urlopen(url, timeout=120) as response, target.open("wb") as handle:
        while chunk := response.read(1024 * 256):
            handle.write(chunk)
    return target


def load_tar(path: Path, source: str, label: str) -> list[dict]:
    records: list[dict] = []
    with tarfile.open(path, "r:bz2") as archive:
        for member in archive:
            if not member.isfile() or member.name.startswith("."):
                continue
            handle = archive.extractfile(member)
            if handle is None:
                continue
            record = record_from_bytes(handle.read(), source, label)
            if record:
                records.append(record)
    return records


def load_mbox(path: Path, source: str, label: str) -> list[dict]:
    records: list[dict] = []
    box = mailbox.mbox(str(path), create=False)
    try:
        for message in box:
            record = record_from_bytes(message.as_bytes(), source, label)
            if record:
                records.append(record)
    finally:
        box.close()
    return records


def text_hash(record: dict) -> str:
    normalized = re.sub(r"\s+", " ", f"{record['subject']}\n{record['body']}").strip().lower()
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _shingle_hashes(record: dict) -> list[int]:
    text = f"{record['subject']} {record['body']}"[:GROUPING_MAX_CHARS].lower()
    tokens = re.findall(r"[a-z0-9]+", text)
    shingles = [" ".join(tokens[index : index + 5]) for index in range(0, max(0, len(tokens) - 4))]
    return [zlib.crc32(shingle.encode("utf-8")) for shingle in shingles]


def make_hash_coefficients(seed: int) -> list[tuple[int, int]]:
    rng = random.Random(seed)
    return [
        (rng.randrange(1, 2**31 - 1), rng.randrange(0, 2**31 - 1))
        for _ in range(MINHASH_LANES)
    ]


def minhash_signature(record: dict, coefficients: list[tuple[int, int]]) -> tuple[int, ...]:
    hashes = _shingle_hashes(record)
    if not hashes:
        return tuple([0] * len(coefficients))
    return tuple(
        min((a * value + b) & 0xFFFFFFFF for value in hashes) for a, b in coefficients
    )


def assign_groups(records: list[dict], seed: int) -> None:
    parent = list(range(len(records)))

    def find(index: int) -> int:
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    def union(left: int, right: int) -> None:
        left_root, right_root = find(left), find(right)
        if left_root != right_root:
            parent[right_root] = left_root

    coefficients = make_hash_coefficients(seed)
    signatures = [minhash_signature(record, coefficients) for record in records]
    for band in range(MINHASH_BANDS):
        buckets: dict[tuple, int] = {}
        start = band * (MINHASH_LANES // MINHASH_BANDS)
        end = start + (MINHASH_LANES // MINHASH_BANDS)
        for index, signature in enumerate(signatures):
            key = (records[index]["label"], signature[start:end])
            if key in buckets:
                union(buckets[key], index)
            else:
                buckets[key] = index

    group_ids: dict[int, int] = {}
    for index in range(len(records)):
        root = find(index)
        group_ids.setdefault(root, len(group_ids))
        records[index]["group"] = group_ids[root]
    return None


def grouped_split(records: list[dict], seed: int) -> dict[str, list[dict]]:
    rng = random.Random(seed)
    groups: dict[int, list[dict]] = {}
    for record in records:
        groups.setdefault(record["group"], []).append(record)

    splits = {"train": [], "validation": [], "test": []}
    targets = {"train": 0.70, "validation": 0.15, "test": 0.15}
    for label in LABELS:
        label_groups = [items for items in groups.values() if items[0]["label"] == label]
        rng.shuffle(label_groups)
        total = sum(len(items) for items in label_groups)
        assigned = 0
        for items in label_groups:
            remaining = label_groups[label_groups.index(items) + 1 :] if False else []
            train_goal = total * targets["train"]
            validation_goal = total * (targets["train"] + targets["validation"])
            if assigned < train_goal:
                split = "train"
            elif assigned < validation_goal:
                split = "validation"
            else:
                split = "test"
            splits[split].extend(items)
            assigned += len(items)
    for items in splits.values():
        rng.shuffle(items)
    return splits


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--seed", type=int, default=SEED)
    args = parser.parse_args()

    root: Path = args.root
    raw_dir = root / "datasets" / "raw"
    processed_dir = root / "datasets" / "processed"
    processed_dir.mkdir(parents=True, exist_ok=True)

    records: list[dict] = []
    for filename, label in SPAMASSASSIN_FILES.items():
        archive = download(f"{SPAMASSASSIN_BASE}/{filename}", raw_dir / filename)
        source = "spamassassin:" + filename.replace(".tar.bz2", "")
        records.extend(load_tar(archive, source, label))

    for filename, label in NAZARIO_FILES.items():
        archive = download(f"https://monkey.org/~jose/phishing/{filename}", raw_dir / filename)
        records.extend(load_mbox(archive, "nazario:" + filename, label))

    seen: set[str] = set()
    deduped: list[dict] = []
    duplicates = 0
    for record in records:
        digest = text_hash(record)
        if digest in seen:
            duplicates += 1
            continue
        seen.add(digest)
        record["text_hash"] = digest
        deduped.append(record)

    assign_groups(deduped, args.seed)
    splits = grouped_split(deduped, args.seed)

    for name, items in splits.items():
        target = processed_dir / f"{name}.jsonl"
        with target.open("w", encoding="utf-8") as handle:
            for item in items:
                handle.write(json.dumps(item, ensure_ascii=False) + "\n")

    def counts(items: list[dict]) -> dict[str, int]:
        return {label: sum(1 for item in items if item["label"] == label) for label in LABELS}

    by_source: dict[str, dict[str, int]] = {}
    for record in deduped:
        source_counts = by_source.setdefault(record["source"], {label: 0 for label in LABELS})
        source_counts[record["label"]] += 1

    card = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "seed": args.seed,
        "total_raw_records": len(records),
        "duplicates_removed": duplicates,
        "total_records": len(deduped),
        "label_counts": counts(deduped),
        "split_counts": {name: counts(items) for name, items in splits.items()},
        "grouping": {
            "method": "minhash LSH on 5-word shingles, grouped within label",
            "lanes": MINHASH_LANES,
            "bands": MINHASH_BANDS,
            "grouped_records": len({record["group"] for record in deduped}),
        },
        "source_counts": by_source,
        "sources": {
            "spamassassin": {
                "url": "https://spamassassin.apache.org/old/publiccorpus/",
                "files": list(SPAMASSASSIN_FILES),
                "labels": sorted(set(SPAMASSASSIN_FILES.values())),
                "terms": "Public research corpus. Copyright of message text remains with "
                "the original senders. Do not route these messages to live mail systems.",
            },
            "nazario": {
                "url": "https://monkey.org/~jose/phishing/",
                "files": list(NAZARIO_FILES),
                "labels": sorted(set(NAZARIO_FILES.values())),
                "license": "CC-BY-4.0",
                "attribution": "Jose Nazario phishing corpus",
            },
        },
        "processing": {
            "text": "subject + text/plain body, HTML converted to text when no plain part",
            "max_body_chars": MAX_BODY_CHARS,
            "attachments": "ignored",
            "deduplication": "sha256 of lowercased whitespace-normalized subject+body",
            "split": "label-stratified group split 70/15/15; near-duplicate groups never cross splits",
        },
    }
    (processed_dir / "dataset_card.json").write_text(
        json.dumps(card, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print(json.dumps(card["label_counts"], indent=2))
    print(json.dumps(card["split_counts"], indent=2))


if __name__ == "__main__":
    main()
