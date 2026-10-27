"""AUD-002 protocol harness: replays every public vector of the MHFE specification 0.7.0 with the
independent Python implementation in mhfe_ref.py, without the Rust crate and without Argon2id:
each round takes its recorded Argon2id output. Exits 1 when any check fails, after every
group has run.

    python3 -I replay_vectors.py --vectors <mhfe_spec>/vectors --english english.txt \
        --eff eff_large_wordlist.txt --ucd UnicodeData-18.0.0.txt
"""

import argparse
import hashlib
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mhfe_ref as ref  # noqa: E402 - needs the sys.path line above

failures = []
counts = {}


def check(group, condition, message):
    counts[group] = counts.get(group, 0) + 1
    if not condition:
        failures.append(f"{group}: {message}")


def h(text):
    return bytes.fromhex(text)


def sums(folder):
    names = []
    for line in open(os.path.join(folder, "SHA256SUMS")):
        digest, name = line.rstrip("\n").split("  ")
        data = open(os.path.join(folder, name), "rb").read()
        check("sha256sums", hashlib.sha256(data).hexdigest() == digest, f"{folder}/{name}")
        names.append(name)
    return names


def recorded_keys(transcript):
    password = h(transcript["inputs"]["password_nfkd_utf8_hex"])
    cost = (transcript["argon2"]["memory_kib"], transcript["argon2"]["passes"])
    keys = {}
    for direction in ("encryption", "decryption"):
        for record in transcript[direction]["rounds"]:
            keys[h(record["salt_hex"])] = h(record["argon2_key_hex"])

    def key_of(pwd, salt, memory_kib, passes):
        assert pwd == password and (memory_kib, passes) == cost, "P_enc or cost"
        return keys[salt]

    return key_of


def compare_rounds(group, name, recorded, computed):
    check(group, len(recorded) == len(computed) == 12, f"{name}: round count")
    for want, got in zip(recorded, computed):
        index = want["round"]
        check(group, got["index"] == index, f"{name}: round order {got['index']} != {index}")
        for field, value in [("left_before_hex", "left_before"),
                             ("right_before_hex", "right_before"),
                             ("salt_input_hex", "salt_input"), ("salt_hex", "salt"),
                             ("argon2_key_hex", "key"), ("mask_input_hex", "mask_input"),
                             ("mask_hex", "mask"), ("left_after_hex", "left_after"),
                             ("right_after_hex", "right_after")]:
            check(group, h(want[field]) == got[value], f"{name} round {index} {field}")


def readings_of(bip, suite, state, stated, container_words):
    if suite == 4:
        return [{"words": container_words, "verified": False,
                 "phrase": bip.text(bip.from_entropy(state))}]
    found = ref.detected(state)
    rules = ref.length_rules(found, stated)
    if rules is None:
        return None
    return [{"words": words, "verified": verified,
             "phrase": bip.text(bip.from_entropy(state[: words // 3 * 4]))}
            for words, verified in rules]


def replay_transcript(bip, ucd, transcript):
    suite = 3 if transcript["suite_id"] == ref.SUITE3.decode() else 4
    group = f"suite{suite}-transcripts"
    name = transcript["name"]
    inputs = transcript["inputs"]
    kind, numbers = bip.read(inputs["phrase"])
    check(group, kind == "ok", f"{name}: phrase")
    entropy = bip.entropy_of(numbers)
    check(group, h(inputs["password_utf8_hex"]) == inputs["password"].encode(), f"{name}: utf8")
    check(group, ucd.password(inputs["password"]) == ("ok", inputs["password_nfkd_utf8_hex"]),
          f"{name}: P_enc")
    password = h(inputs["password_nfkd_utf8_hex"])
    pim, mem = inputs["pim"], inputs["memory_level"]
    argon2 = transcript["argon2"]
    check(group, (argon2["variant"], argon2["version"], argon2["lanes"], argon2["output_bytes"])
          == ("Argon2id", 0x13, 4, 32), f"{name}: Argon2 parameters")
    check(group, (argon2["memory_kib"], argon2["passes"]) == (ref.mem_kib(mem), ref.passes(pim)),
          f"{name}: cost")
    if suite == 3:
        packing = transcript["packing"]
        x = ref.pack(entropy)
        check(group, packing["words"] == len(numbers), f"{name}: words")
        check(group, h(packing["entropy_hex"]) == entropy, f"{name}: entropy")
        check(group, h(packing["verifier_hex"]) == x[len(entropy):], f"{name}: verifier")
        check(group, h(packing["state_hex"]) == x, f"{name}: state")
    else:
        state = transcript["state"]
        x = entropy
        check(group, (state["words"], state["entropy_bits"], state["half_bytes"])
              == (len(numbers), 8 * len(x), len(x) // 2), f"{name}: geometry")
        check(group, h(state["state_hex"]) == x, f"{name}: state")
    key_of = recorded_keys(transcript)
    record = []
    y = ref.forward(suite, x, pim, mem, password, key_of, record)
    check(group, h(transcript["encryption"]["input_state_hex"]) == x, f"{name}: input")
    compare_rounds(group, name, transcript["encryption"]["rounds"], record)
    check(group, h(transcript["encryption"]["output_state_hex"]) == y, f"{name}: Y")
    check(group, y != x, f"{name}: fixed point")
    container = bip.text(bip.from_entropy(y))
    check(group, transcript["container"] == container, f"{name}: container")
    # Recovery starts from the container's words.
    kind, container_numbers = bip.read(transcript["container"])
    back_entropy = bip.entropy_of(container_numbers)
    record = []
    back = ref.inverse(suite, back_entropy, pim, mem, password, key_of, record)
    check(group, h(transcript["decryption"]["input_state_hex"]) == back_entropy, f"{name}: input")
    compare_rounds(group, name, transcript["decryption"]["rounds"], record)
    check(group, h(transcript["decryption"]["output_state_hex"]) == back == x, f"{name}: X")
    recovery = transcript["recovery"]
    recorded = recovery if isinstance(recovery, list) else [recovery]
    computed = readings_of(bip, suite, back, None, len(container_numbers))
    check(group, computed == recorded, f"{name}: readings {computed} != {recorded}")
    return container, (password, pim, mem, key_of)


def replay_recovery_cases(bip, folder, suite, transcripts):
    group = f"suite{suite}-recovery-cases"
    cases = json.load(open(os.path.join(folder, "negative-cases.json")))
    replayed = 0
    for case in cases:
        name = case["name"]
        stated = case["words"] or None
        kind, numbers = bip.read(case["container"])
        check(group, kind == "ok", f"{name}: container")
        container_words = len(numbers)
        refusal = ref.admission(container_words, stated, None)
        same = [t for t in transcripts.values() if t[0] == case["container"]
                and t[1]["password"] == case["password"] and t[1]["pim"] == case["pim"]
                and t[1]["memory_level"] == case["memory_level"]]
        if refusal is not None:
            check(group, case["error_code"] == "LENGTH_CHOICE_NOT_APPLICABLE"
                  and case["recovery"] == [], f"{name}: {refusal}")
            replayed += 1
            continue
        if not same:
            # Wrong password or setting: Argon2id at full cost is needed for the state. The
            # expectation must still be the length rules' outcome when no verifier passes.
            expected = ref.length_rules([], stated) if suite == 3 else [(container_words, False)]
            if expected is None:
                check(group, case["error_code"] == "VERIFIER_MISMATCH" and case["recovery"] == [],
                      f"{name}: expected no reading")
            else:
                shape = [(r["words"], r["verified"]) for r in case["recovery"]]
                check(group, case.get("error_code") is None and shape == expected,
                      f"{name}: {shape} != {expected}")
            counts["recovery-cases-needing-full-cost"] = (
                counts.get("recovery-cases-needing-full-cost", 0) + 1)
            continue
        password, pim, mem, key_of = same[0][2]
        state = ref.inverse(suite, bip.entropy_of(numbers), pim, mem, password, key_of)
        computed = readings_of(bip, suite, state, stated, container_words)
        recorded = case["recovery"]
        if name == "selected-24-words":
            # The removed manual mode's one reading: the length rules give it last.
            computed = computed[-1:]
        check(group, computed == recorded, f"{name}: {computed} != {recorded}")
        replayed += 1
    return replayed


def replay_suite3_validation(bip, ucd, folder):
    cases = json.load(open(os.path.join(folder, "validation-cases.json")))
    group = "suite3-validation"
    for case in cases["settings"]:
        pim, mem = case["pim"], case["memory_level"]
        if "expected_error" in case:
            want = "INVALID_PIM" if pim > 1023 else "INVALID_MEMORY_LEVEL" if mem > 21 else None
            check(group, case["expected_error"] == want, case["id"])
        else:
            check(group, (ref.mem_kib(mem), ref.passes(pim))
                  == (case["expected_memory_kib"], case["expected_passes"]), case["id"])
    for case in cases["phrases"]:
        if case["operation"] == "encrypt":
            check(group, bip.read(case["phrase"])[0] == "err"
                  and case["expected_error"] == "INVALID_PHRASE", case["id"])
        else:
            kind, numbers = bip.read(case["container"])
            stated = case.get("words")
            if kind == "err" or len(numbers) != 24:
                want = "INVALID_CONTAINER"
            else:
                refusal = ref.admission(24, stated, 3)
                invalid = refusal is not None and refusal.startswith("InvalidWord")
                want = "INVALID_WORD_COUNT" if invalid else None
            check(group, case["expected_error"] == want, case["id"])
    for case in cases["length_detection"]:
        state = h(case["state_hex"])
        check(group, ref.detected(state) == case["matching_short_lengths"], case["id"])
        if "entropy_hex" in case:
            check(group, ref.pack(h(case["entropy_hex"])) == state, case["id"])
    case = cases["verifier_serialization"]
    entropy = h(case["entropy_hex"])
    check(group, hashlib.sha256(entropy).hexdigest() == case["sha256_hex"], "verifier sha")
    check(group, ref.pack(entropy) == h(case["state_hex"])
          and ref.pack(entropy)[28:] == h(case["verifier_hex"]), "verifier serialization")
    codes = {"ForbiddenCharacter": "CONTROL_CHARACTER_IN_PASSWORD",
             "UnassignedCharacter": "UNASSIGNED_CHARACTER", "EmptyPassword": "EMPTY_PASSWORD"}
    for case in cases["passwords"]:
        replay_password(ucd, "suite3-passwords", case, codes)
    for case in cases["javascript_passwords"]:
        units = [int(unit, 16) for unit in case["utf16_code_units_hex"]]
        lone = any(0xD800 <= u <= 0xDFFF for u in units)
        check(group, lone and case["expected_error"] == "INVALID_PASSWORD_TEXT", case["id"])


def replay_password(ucd, group, case, codes):
    data = (h(case["repeat_utf8_hex"]) * case["count"] if "repeat_utf8_hex" in case
            else h(case["input_utf8_hex"]))
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        check(group, case["expected_error"] == "INVALID_PASSWORD_UTF8", case["id"])
        return
    kind, value = ucd.password(text)
    if "expected_error" in case:
        want = case["expected_error"]
        too_long = value.startswith("PasswordTooLong")
        got = codes.get(value, "PASSWORD_TOO_LONG" if too_long else value)
        check(group, kind == "err" and got == want, f"{case['id']}: {value}")
        if "expected_nfkd_bytes" in case:
            check(group, value == f"PasswordTooLong {{ bytes: {case['expected_nfkd_bytes']} }}",
                  case["id"])
    else:
        check(group, kind == "ok", f"{case['id']}: {value}")
        if "expected_nfkd_utf8_hex" in case:
            check(group, value == case["expected_nfkd_utf8_hex"], case["id"])
        if "expected_nfkd_bytes" in case:
            check(group, len(value) // 2 == case["expected_nfkd_bytes"], case["id"])


def replay_suite4_validation(bip, folder):
    cases = json.load(open(os.path.join(folder, "validation-cases.json")))
    group = "suite4-validation"
    check(group, cases["suite_id"] == ref.SUITE4.decode(), "suite id")
    for case in cases["ent_separation"]:
        key = h(case["key_hex"])
        values = ref.round_values(4, case["entropy_bits"], case["pim"], case["memory_level"],
                                  case["round"], h(case["half_hex"]), b"", lambda *_: key)
        check(group, case["entropy_bits"] == case["words"] // 3 * 32, case["id"])
        for field in ("salt_input", "salt", "mask_input", "mask"):
            check(group, values[field] == h(case[field + "_hex"]), f"{case['id']} {field}")
    for case in cases["refusals"]:
        kind, numbers = bip.read(case["text"])
        check(group, kind == "ok" and case["expected"] == "rejected", case["id"])
        if case["operation"] == "encrypt-same-length":
            check(group, len(numbers) == 24, case["id"])
        else:
            check(group, ref.admission(len(numbers), case.get("words"), case.get("suite"))
                  is not None, case["id"])
    return len(cases["refusals"])


def replay_profiles(bip, eff, readme):
    text = open(readme, encoding="utf-8").read()
    group = "profile-wallet-check"
    rows = re.findall(r"^\| (\d+) +\| (`TREZOR`|empty string) +\| `([0-9a-f]{64})` \|$", text,
                      re.M)
    check(group, len(rows) == 2, "two digest rows")
    for counter, passphrase, digest in rows:
        entropy = bytes(24) + int(counter).to_bytes(8, "big")
        mnemonic = bip.text(bip.from_entropy(entropy))
        q = "TREZOR" if passphrase == "`TREZOR`" else ""
        t = ref.wallet_check_digest(ref.wallet_check_seed(mnemonic, q))
        check(group, t.hex() == digest and t[:2] == b"\0\0", f"{counter}")
    for counter, q, prefix in [(76562, "", "ebd07f71"), (98918, "TREZOR", "8d2b97fb")]:
        check(group, prefix in text, f"{prefix} in README")
        mnemonic = bip.text(bip.from_entropy(bytes(24) + counter.to_bytes(8, "big")))
        t = ref.wallet_check_digest(ref.wallet_check_seed(mnemonic, q))
        check(group, t.hex().startswith(prefix) and t[:2] != b"\0\0", f"{counter} {q!r}")
    mnemonic = bip.text(bip.from_entropy(bytes(24) + (76562).to_bytes(8, "big")))
    seed = ref.wallet_check_seed(mnemonic, "TREZOR")
    check(group, ref.sha256(b"MHFE-WALLET-CHECK-SEED-1" + seed).hex().startswith("f2c9f765"),
          "without BE32(256)")
    spoil = bip.text(bip.from_entropy(bytes(24) + (98918).to_bytes(8, "big")))
    check(group, spoil == "abandon " * 21 + "absorb another spoil", "98918 words")

    group = "profile-repair"
    field = ref.Gf2048()
    spec = open(os.path.join(os.path.dirname(readme), "..", "..", "README.md"), encoding="utf-8")
    spec = spec.read()
    for k in (2, 4, 6, 8):
        listed = re.search(rf"^g_{k}: ([0-9, ]+)$", spec, re.M).group(1)
        check(group, field.generator(k) == [int(v) for v in listed.split(", ")], f"g_{k}")
    card_rows = re.findall(r"^\| (`[^`]+`|`abandon` 23 times, then `art`) +\| ([a-z /`]+?) +\|$",
                           text, re.M)
    check(group, len(card_rows) == 4, "four card rows")
    containers = {}
    for source, cards in card_rows:
        if "23 times" in source:
            container = "abandon " * 23 + "art"
        else:
            path = os.path.join(os.path.dirname(readme), "..", "..", source.strip("`"))
            container = json.load(open(path))["container"]
        containers[source] = container
        numbers = bip.read(container)[1]
        for k, card in zip((2, 4, 6, 8), [c.strip(" `") for c in cards.split(" / ")]):
            parity = field.parity(numbers, k)
            check(group, bip.text(parity) == card, f"{source} k={k}")
            check(group, field.is_codeword(numbers + parity, k), f"{source} k={k} codeword")
    zero12 = bip.read(containers["`vectors/suite3/zero-12.json`"])[1]
    card = field.parity(zero12, 4)
    for damage, expected in [({3: None, 17: None}, {3: "tower", 17: "cycle"}),
                             ({10: "zoo", 5: None}, {5: "iron", 10: "rib"}),
                             ({3: "zoo", 17: "abandon"}, {3: "tower", 17: "cycle"})]:
        received = zero12 + card
        erased = []
        for position, word in damage.items():
            if word is None:
                erased.append(position - 1)
            else:
                received[position - 1] = bip.index[word]
        repaired = None
        wrong = [p - 1 for p, w in damage.items() if w is not None]
        repaired = field.solve_at(received, sorted(erased + wrong), 4)
        check(group, repaired == zero12 + card, f"repair {damage}")
        check(group, all(bip.words[repaired[p - 1]] == w for p, w in expected.items()),
              f"repair words {expected}")

    group = "profile-password-check"
    index = {word: number for number, word in enumerate(eff)}
    rows = re.findall(r"^\| `(\d{5} \d{5} \d{5} \d{5} \d{5})` \| (\d+) +\| `([a-z -]+)` +\|$",
                      text, re.M)
    check(group, len(rows) == 4, "four check-word rows")
    for rolls, check_value, password in rows:
        drawn = [sum((int(d) - 1) * 6 ** (4 - p) for p, d in enumerate(roll))
                 for roll in rolls.split()]
        c = ref.check_index(drawn)
        check(group, c == int(check_value), rolls)
        check(group, " ".join(eff[i] for i in drawn + [c]) == password, rolls)
        check(group, ref.check_password(eff, index, password) == {"kind": "Fits"}, password)
    erased = ref.check_password(eff, index, "jovial trailing ? pavilion cresting ninth")
    check(group, erased == {"kind": "OneErased", "position": 3, "word": "chokehold"}, "chokehold")


def main():
    parser = argparse.ArgumentParser()
    for option in ("--vectors", "--english", "--eff", "--ucd"):
        parser.add_argument(option, required=True)
    args = parser.parse_args()
    bip = ref.Bip39(args.english)
    ucd = ref.Ucd(args.ucd)
    eff = ref.eff_words(args.eff)
    transcripts = {}
    for suite, folder in ((3, "suite3"), (4, "suite4")):
        path = os.path.join(args.vectors, folder)
        for name in sums(path):
            if name in ("negative-cases.json", "validation-cases.json"):
                continue
            transcript = json.load(open(os.path.join(path, name)))
            container, keys = replay_transcript(bip, ucd, transcript)
            transcripts[(suite, name)] = (container, transcript["inputs"], keys)
        counts[f"suite{suite}-transcript-files"] = sum(1 for key in transcripts if key[0] == suite)
        replayed = replay_recovery_cases(
            bip, path, suite, {k: v for k, v in transcripts.items() if k[0] == suite})
        counts[f"suite{suite}-recovery-cases-replayed"] = replayed
    replay_suite3_validation(bip, ucd, os.path.join(args.vectors, "suite3"))
    counts["suite4-refusals"] = replay_suite4_validation(bip, os.path.join(args.vectors, "suite4"))
    unicode18 = os.path.join(args.vectors, "unicode18")
    sums(unicode18)
    codes = {"ForbiddenCharacter": "CONTROL_CHARACTER_IN_PASSWORD",
             "UnassignedCharacter": "UNASSIGNED_CHARACTER", "EmptyPassword": "EMPTY_PASSWORD"}
    for case in json.load(open(os.path.join(unicode18, "password-encoding.json")))["passwords"]:
        replay_password(ucd, "unicode18-passwords", case, codes)
    replay_profiles(bip, eff, os.path.join(args.vectors, "profiles", "README.md"))
    for group, count in sorted(counts.items()):
        print(f"{group}: {count}")
    if failures:
        print(f"FAILED: {len(failures)}")
        for failure in failures[:50]:
            print("  " + failure)
        sys.exit(1)
    print("All vector replays match.")


if __name__ == "__main__":
    main()
