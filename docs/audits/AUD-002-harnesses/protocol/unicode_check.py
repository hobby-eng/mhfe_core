"""AUD-002 protocol harness: the Unicode 18.0.0 password encoding and BIP39 passphrase NFKD of
mhfe-core against an independent NFKD built from UnicodeData.txt 18.0.0.

1. The Python NFKD is first checked against NormalizationTest.txt 18.0.0 (every line, and every
   code point outside Part 1 normalizing to itself), so that it can serve as the oracle.
2. Every Unicode scalar value alone goes through `Password::new`: P_enc or the refusal must be the
   oracle's (Cc and U+2028/U+2029 refused, General_Category Cn refused, Private Use accepted).
3. Seeded random strings of starters, non-starters of many classes, Hangul and compatibility
   characters go through `Password::new` and `Seed::derive` (BIP39 PBKDF2 with the passphrase in
   NFKD, where unassigned code points stay unchanged).

    python3 -I unicode_check.py --adapter <binary> --ucd UnicodeData-18.0.0.txt \
        --normalization-test NormalizationTest.txt --english english.txt

Exits 1 on any mismatch.
"""

import argparse
import json
import os
import random
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mhfe_ref as ref  # noqa: E402 - needs the sys.path line above


def run_adapter(adapter, requests):
    data = "".join(json.dumps(request) + "\n" for request in requests)
    done = subprocess.run([adapter], input=data.encode(), capture_output=True, check=True)
    answers = [json.loads(line) for line in done.stdout.decode().splitlines()]
    assert len(answers) == len(requests), "one answer per request"
    return answers


def answer_of(kind_value):
    kind, value = kind_value
    return {"ok": value} if kind == "ok" else {"err": value}


def main():
    parser = argparse.ArgumentParser()
    for option in ("--adapter", "--ucd", "--normalization-test", "--english"):
        parser.add_argument(option, required=True)
    parser.add_argument("--random-cases", type=int, default=200_000)
    parser.add_argument("--seed-cases", type=int, default=2_000)
    args = parser.parse_args()
    ucd = ref.Ucd(args.ucd)
    bip = ref.Bip39(args.english)
    failures = []

    # 1. The oracle against NormalizationTest.txt.
    test = ref.checked_file(args.normalization_test, ref.NORMALIZATION_TEST_18_SHA256)
    part1 = set()
    lines = 0
    part = None
    for line in test.decode("utf-8").splitlines():
        if line.startswith("@Part"):
            part = line.split()[0]
            continue
        if not line or line.startswith("#"):
            continue
        columns = ["".join(chr(int(c, 16)) for c in column.split())
                   for column in line.split(";")[:5]]
        if part == "@Part1":
            part1.add(ord(columns[0]))
        for column in columns:
            if ucd.nfkd(column) != columns[4]:
                failures.append(f"oracle: {line}")
        lines += 1
    for point in range(0x110000):
        if 0xD800 <= point <= 0xDFFF or point in part1:
            continue
        if ucd.nfkd(chr(point)) != chr(point):
            failures.append(f"oracle: U+{point:04X} outside Part 1 changes")
    print(f"oracle: {lines} NormalizationTest lines, {len(part1)} Part 1 code points")
    if failures:
        print("\n".join(failures[:20]))
        sys.exit(1)

    # 2. Every scalar value alone.
    points = [p for p in range(0x110000) if not 0xD800 <= p <= 0xDFFF]
    answers = run_adapter(args.adapter, [{"op": "password", "text": chr(p)} for p in points])
    tally = {}
    for point, answer in zip(points, answers):
        expected = answer_of(ucd.password(chr(point)))
        key = "ok" if "ok" in expected else expected["err"]
        tally[key] = tally.get(key, 0) + 1
        if answer != expected:
            failures.append(f"U+{point:04X}: {answer} != {expected}")
    print(f"every scalar value: {len(points)}, outcomes {tally}")

    # 3. Seeded random strings.
    rng = random.Random(0x41554430303232)  # "AUD0022" in ASCII
    nonstarters = sorted(ucd.ccc)
    decomposing = sorted(ucd.decomposition)
    pool = [
        lambda: rng.choice(nonstarters),
        lambda: rng.choice(nonstarters),
        lambda: rng.choice(decomposing),
        lambda: rng.randrange(0xAC00, 0xD7A4),
        lambda: rng.randrange(0x20, 0x7F),
        lambda: rng.choice([0x0F73, 0x0F75, 0x0F81, 0x0344, 0x0340, 0x0341, 0x0343, 0x0958,
                            0x1E0A, 0x0307, 0x0323, 0xFDFA, 0x3300, 0x2126, 0x212B]),
        lambda: rng.choice([0x0378, 0x50000, 0xE0080, 0xFDD0, 0xE000, 0x10FFFD, 0x209D]),
    ]
    texts = []
    for _ in range(args.random_cases):
        length = rng.randrange(1, 24)
        texts.append("".join(chr(rng.choice(pool)()) for _ in range(length)))
    answers = run_adapter(args.adapter, [{"op": "password", "text": t} for t in texts])
    for text, answer in zip(texts, answers):
        expected = answer_of(ucd.password(text))
        if answer != expected:
            failures.append(f"{text!r}: {answer} != {expected}")
    print(f"random passwords: {len(texts)}")

    # Seeds: any passphrase, unassigned code points and controls included.
    requests, expected = [], []
    for case in range(args.seed_cases):
        entropy = rng.randbytes(32)
        phrase = bip.text(bip.from_entropy(entropy))
        length = rng.randrange(0, 30)
        passphrase = "".join(chr(rng.choice(pool + [lambda: rng.randrange(0, 0x20)])())
                             for _ in range(length))
        requests.append({"op": "seed", "phrase": phrase, "passphrase": passphrase})
        seed = ref.wallet_check_seed(phrase, ucd.nfkd(passphrase))
        t = ref.wallet_check_digest(seed)
        expected.append({"seed": seed.hex(), "passes": t[:2] == b"\0\0"})
    answers = run_adapter(args.adapter, requests)
    for request, answer, want in zip(requests, answers, expected):
        if answer != want:
            failures.append(f"seed {request['passphrase']!r}: {answer} != {want}")
    print(f"random passphrase seeds: {len(requests)}")

    if failures:
        print(f"FAILED: {len(failures)}")
        print("\n".join(failures[:30]))
        sys.exit(1)
    print("Unicode checks match.")


if __name__ == "__main__":
    main()
