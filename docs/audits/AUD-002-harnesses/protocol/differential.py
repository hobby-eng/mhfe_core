"""AUD-002 protocol harness: seeded differential and negative probes of mhfe-core's public API
(through the Rust adapter) against the independent implementation in mhfe_ref.py.

Groups: reading phrases and words, entropy encoding, creation step 2, encryption and recovery of
both suites at every length with a stand-in Argon2id (every salt and cost compared), recovery of
arbitrary states (the ambiguous ones included) under every stated length and suite, the admission
table exhaustively, repair cards and repairs (within and beyond the bound), the password check
word, the wallet-check draw, and the EFF list. Exits 1 on any mismatch.

    python3 -I differential.py --adapter <binary> --english english.txt \
        --eff eff_large_wordlist.txt --vectors <mhfe_spec>/vectors \
        --ucd UnicodeData-18.0.0.txt [--scale N]
"""

import argparse
import itertools
import json
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mhfe_ref as ref  # noqa: E402 - needs the sys.path line above
from unicode_check import run_adapter  # noqa: E402 - needs the sys.path line above

failures = []
counts = {}


def compare(group, request, answer, expected):
    counts[group] = counts.get(group, 0) + 1
    if answer != expected:
        failures.append(f"{group}: {json.dumps(request)[:300]}"
                        f"\n    got  {json.dumps(answer)[:400]}"
                        f"\n    want {json.dumps(expected)[:400]}")


def batch(adapter, group, pairs):
    """Runs (request, expected) pairs through the adapter and compares the answers."""
    if not pairs:
        return
    answers = run_adapter(adapter, [request for request, _ in pairs])
    for (request, expected), answer in zip(pairs, answers):
        compare(group, request, answer, expected)


ASCII_WORDS = ["public", "test", "password", "Correct", "HORSE", "battery", "staple", "a", "1"]
UNICODE = ["\xe9", "e\u0301", "\ufb01", "\uff30", "\u2460", "\u0439", "\ud55c", "\U0001f510",
           "\xa0", "\u212b", "\ue000", "\u1e9b\u0323", "\u0f73", "\u209d"]
WHITE = sorted(ref.WHITE_SPACE)


def random_password(rng):
    parts = [rng.choice(ASCII_WORDS + UNICODE) for _ in range(rng.randrange(1, 6))]
    return rng.choice([" ", "", "-", "  "]).join(parts)


def random_entropy(rng, size):
    kind = rng.randrange(6)
    if kind == 0:
        return bytes(size)
    if kind == 1:
        return b"\xff" * size
    if kind == 2:
        zeros = min(size, rng.randrange(1, 4))
        return bytes(zeros) + rng.randbytes(size - zeros)
    return rng.randbytes(size)


def fit(data, size):
    return (data + bytes(size))[:size]


def phrase_answer(bip, text):
    kind, value = bip.read(text)
    if kind == "err":
        return {"err": value}
    return {"ok": bip.text(value), "words": len(value)}


def mangle(rng, bip, numbers):
    """A typed form of a phrase: letter case, four-letter prefixes and any White_Space."""
    tokens = []
    for number in numbers:
        word = bip.words[number]
        if rng.random() < 0.3:
            word = word[: rng.randrange(4, len(word) + 1)] if len(word) > 4 else word
        word = "".join(c.upper() if rng.random() < 0.3 else c for c in word)
        tokens.append(word)

    def sep():
        return "".join(rng.choice(WHITE) for _ in range(rng.randrange(1, 3)))

    damage = rng.randrange(10)
    if damage == 0:
        at = rng.randrange(len(tokens))
        tokens[at] = rng.choice(["xyzw", "aba", "ab", "\u212aite", "abandons", "abandon\u200b",
                                 "ab\xe1ndon", "zoo1", "?", "ACTIONS", "actr", "a" * 40])
    elif damage == 1:
        tokens[rng.randrange(len(tokens))] = rng.choice(bip.words)
    elif damage == 2:
        del tokens[rng.randrange(len(tokens))]
    elif damage == 3:
        tokens.insert(rng.randrange(len(tokens) + 1), rng.choice(bip.words))
    text = sep() if rng.random() < 0.3 else ""
    text += sep().join(tokens)
    return text + (sep() if rng.random() < 0.3 else "")


def reading_group(adapter, bip, rng, scale):
    pairs = []
    for _ in range(300 * scale):
        size = rng.choice([16, 20, 24, 28, 32])
        numbers = bip.from_entropy(random_entropy(rng, size))
        text = mangle(rng, bip, numbers)
        pairs.append(({"op": "read", "text": text}, phrase_answer(bip, text)))
    for text in ["", " ", "abandon " * 11 + "about", "\u3000".join(["abandon"] * 11 + ["about"]),
                 "\xa0".join(["abandon"] * 11 + ["about"]), "abandon\u200babandon",
                 "abandon " * 11 + "abou", "ABANDON " * 11 + "ABOUT"]:
        pairs.append(({"op": "read", "text": text}, phrase_answer(bip, text)))
    batch(adapter, "phrase-read", pairs)

    pairs = []
    for word in bip.words:
        for length in range(1, len(word) + 1):
            for token in {word[:length], word[:length].upper(), word[:length].title()}:
                pairs.append(({"op": "read_word", "token": token}, {"ok": bip.read_word(token)}))
    for token in ["", "abandonx", "abstracts", "\u212aite", "kite\u0301", "zoo\n", "Zoo",
                  "acti", "act", "ac", "a" * 9, "\u0130tem", "item"]:
        pairs.append(({"op": "read_word", "token": token}, {"ok": bip.read_word(token)}))
    batch(adapter, "read-word", pairs)

    pairs = []
    for size in range(0, 41):
        for _ in range(3):
            entropy = random_entropy(rng, size) if size else b""
            entropy = fit(entropy, size)
            numbers = bip.from_entropy(entropy)
            expected = ({"err": f"InvalidEntropyLength {{ bytes: {size} }}"} if numbers is None
                        else {"ok": bip.text(numbers), "words": len(numbers)})
            pairs.append(({"op": "from_entropy", "entropy": entropy.hex()}, expected))
    batch(adapter, "from-entropy", pairs)


# Literal rows of the official BIP39 test vectors (trezor/python-mnemonic vectors.json, passphrase
# "TREZOR"): entropy, mnemonic, seed. Literal values, not another call of the same conversion.
BIP39_VECTORS = [
    ("00" * 16, "abandon " * 11 + "about",
     "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c9"
     "2f2cf141630c7a3c4ab7c81b2f001698e7463b04"),
    ("7f" * 16, "legal winner thank year wave sausage worth useful legal winner thank yellow",
     "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937"
     "a1c1069be3a3a5bd381ee6260e8d9739fce1f607"),
    ("80" * 16, "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
     "d71de856f81a8acc65e6fc851a38d4d7ec216fd0796d0a6827a3ad6ed5511a30fa280f12eb2e47ed2ac03b5c"
     "462a0358d18d69fe4f985ec81778c1b370b652a8"),
    ("ff" * 16, "zoo " * 11 + "wrong",
     "ac27495480225222079d7be181583751e86f571027b0497b5b5d11218e0a8a13332572917f0f8e5a589620c6"
     "f15b11c61dee327651a14c34e18231052e48c069"),
    ("00" * 24, "abandon " * 17 + "agent",
     "035895f2f481b1b0f01fcf8c289c794660b289981a78f8106447707fdd9666ca06da5a9a565181599b79f53b"
     "844d8a71dd9f439c52a3d7b3e8a79c906ac845fa"),
    ("7f" * 24, "legal winner thank year wave sausage worth useful legal winner thank year wave "
     "sausage worth useful legal will",
     "f2b94508732bcbacbcc020faefecfc89feafa6649a5491b8c952cede496c214a0c7b3c392d168748f2d4a612"
     "bada0753b52a1c7ac53c1e93abd5c6320b9e95dd"),
    ("00" * 32, "abandon " * 23 + "art",
     "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8"
     "d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8"),
    ("7f" * 32, "legal winner thank year wave sausage worth useful legal winner thank year wave "
     "sausage worth useful legal winner thank year wave sausage worth title",
     "bc09fca1804f7e69da93c2f2028eb238c227f2e9dda30cd63699232578480a4021b146ad717fbb7e451ce9eb"
     "835f43620bf5c514db0f8add49f5d121449d3e87"),
    ("80" * 32, "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd "
     "amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
     "c0c519bd0e91a2ed54357d9d1ebef6f5af218a153624cf4f2da911a0ed8f7a09e2ef61af0aca007096df4300"
     "22f7a2b6fb91661a9589097069720d015e4e982f"),
    ("ff" * 32, "zoo " * 23 + "vote",
     "dd48c104698c30cfe2b6142103248622fb7bb0ff692eebb00089b32d22484e1613912f0a5b694407be899ffd"
     "31ed3992c456cdf60f5d4564b8ba3f05a69890ad"),
]


def bip39_vector_group(adapter):
    pairs = []
    for entropy, mnemonic, seed in BIP39_VECTORS:
        words = len(mnemonic.split())
        pairs.append(({"op": "from_entropy", "entropy": entropy},
                      {"ok": mnemonic, "words": words}))
        pairs.append(({"op": "read", "text": mnemonic.upper()}, {"ok": mnemonic, "words": words}))
        pairs.append(({"op": "seed", "phrase": mnemonic, "passphrase": "TREZOR"},
                      {"seed": seed, "passes": None if words != 24 else
                       ref.wallet_check_digest(bytes.fromhex(seed))[:2] == b"\0\0"}))
    batch(adapter, "bip39-literal-vectors", pairs)


def ambiguous_states(vectors):
    cases = json.load(open(os.path.join(vectors, "suite3", "validation-cases.json")))
    return [bytes.fromhex(case["state_hex"]) for case in cases["length_detection"]
            if case["id"].startswith("ambiguous")]


def creation_step_2_group(adapter, bip, rng, vectors, scale):
    pairs = []
    states = ambiguous_states(vectors)
    entropies = []
    for state in states:
        found = ref.detected(state)
        entropies += [state[: words // 3 * 4] for words in found] + [state]
    entropies += [rng.randbytes(rng.choice([16, 20, 24, 28, 32])) for _ in range(100 * scale)]
    for entropy in entropies:
        numbers = bip.from_entropy(entropy)
        own = len(numbers)
        expected = [w for w in ref.detected(ref.pack(entropy)) if w != own]
        pairs.append(({"op": "other_lengths", "phrase": bip.text(numbers)}, {"ok": expected}))
    batch(adapter, "creation-step-2", pairs)


def encryption_group(adapter, bip, rng, scale):
    pairs = []
    decrypts = []
    for case in range(60 * scale):
        suite = rng.choice([3, 4])
        words = rng.choice([12, 15, 18, 21] + ([24] if suite == 3 else []))
        entropy = fit(random_entropy(rng, words // 3 * 4), words // 3 * 4)
        phrase = bip.text(bip.from_entropy(entropy))
        password = random_password(rng)
        pim = rng.choice([0, 0, 1, 2, 1023, rng.randrange(1024)])
        mem = rng.choice([0, 0, 1, 21, rng.randrange(22)])
        kind, p_enc = UCD.password(password)
        assert kind == "ok", password
        p_enc = bytes.fromhex(p_enc)
        key_of = ref.stand_in_key
        x = ref.pack(entropy) if suite == 3 else entropy
        forward_record, inverse_record = [], []
        y = ref.forward(suite, x, pim, mem, p_enc, key_of, forward_record)
        container = bip.text(bip.from_entropy(y))
        ref.inverse(suite, y, pim, mem, p_enc, key_of, inverse_record)
        calls = [[r["salt"].hex(), ref.mem_kib(mem), ref.passes(pim), p_enc.hex()]
                 for r in forward_record + inverse_record]
        expected = {"ok": container, "words": len(y) * 3 // 4, "shown": [container],
                    "rounds": [[r, 24] for r in range(1, 25)], "calls": calls}
        request = {"op": "encrypt", "phrase": phrase, "password": password, "suite": suite,
                   "pim": pim, "mem": mem}
        pairs.append((request, expected))
        # Recovery: the right password or another one, any stated length and suite.
        wrong = rng.random() < 0.3
        recover_password = random_password(rng) if wrong else password
        decrypts.append((container, recover_password, pim, mem))
    # Refusals before Argon2id.
    zero24 = bip.text(bip.from_entropy(bytes(32)))
    pairs.append(({"op": "encrypt", "phrase": zero24, "password": "pw", "suite": 4, "pim": 0,
                   "mem": 0}, {"err": "SameLengthNeedsShortPhrase", "calls": 0}))
    for pim, mem, error in [(1024, 0, "InvalidPim { pim: 1024 }"),
                            (0, 22, "InvalidMemoryLevel { level: 22 }"),
                            (4294967295, 4294967295, "InvalidPim { pim: 4294967295 }")]:
        pairs.append(({"op": "encrypt", "phrase": zero24, "password": "pw", "suite": 3,
                       "pim": pim, "mem": mem}, {"err": error}))
    batch(adapter, "encrypt", pairs)
    return decrypts


def expected_recovery(bip, container_words, state_of, suite_given, stated, readings):
    refusal = ref.admission(container_words, stated, suite_given)
    if refusal is not None:
        return {"err": refusal, "calls": 0}
    suite = 3 if container_words == 24 else 4
    state = state_of(suite)
    found = ref.detected(state) if suite == 3 else []
    answers = []
    for asked in readings:
        refusal = ref.admission(container_words, asked, None)
        if refusal is not None:
            answers.append({"err": refusal})
            continue
        if suite == 4:
            rules = [(container_words, False)]
        else:
            rules = ref.length_rules(found, asked)
        if rules is None:
            answers.append({"err": "VerifierMismatch"})
            continue
        answers.append({"ok": [{"words": w, "verified": v,
                                "phrase": bip.text(bip.from_entropy(state[: w // 3 * 4]))}
                               for w, v in rules]})
    return {"ok": {"suite": suite, "detected": found, "readings": answers}, "calls": 12}


READINGS = [None, 12, 15, 18, 21, 24, 13, 0]
STATED = [None, None, 12, 15, 18, 21, 24, 13, 0, 25]
SUITES = [None, None, 3, 4]


def recovery_group(adapter, bip, rng, vectors, decrypts, scale):
    pairs = []

    def add(container, password, pim, mem, stated, suite):
        kind, p_enc = UCD.password(password)
        p_enc = bytes.fromhex(p_enc)
        container_numbers = bip.read(container)[1]
        y = bip.entropy_of(container_numbers)

        def state_of(s):
            return ref.inverse(s, y, pim, mem, p_enc, ref.stand_in_key)

        expected = expected_recovery(bip, len(container_numbers), state_of, suite, stated,
                                     READINGS)
        request = {"op": "decrypt", "container": container, "password": password, "pim": pim,
                   "mem": mem, "stated": stated, "suite": suite, "readings": READINGS}
        pairs.append((request, expected))

    for container, password, pim, mem in decrypts:
        add(container, password, pim, mem, rng.choice(STATED), rng.choice(SUITES))
    # Arbitrary states made into containers by the Python forward permutation: packed short
    # phrases, the ambiguous states of the corpus, random 24-word states.
    states = ambiguous_states(vectors)
    states += [ref.pack(rng.randbytes(rng.choice([16, 20, 24, 28]))) for _ in range(20 * scale)]
    states += [rng.randbytes(32) for _ in range(10 * scale)]
    for state in states:
        password = random_password(rng)
        p_enc = bytes.fromhex(UCD.password(password)[1])
        y = ref.forward(3, state, 0, 0, p_enc, ref.stand_in_key)
        container = bip.text(bip.from_entropy(y))
        for stated in [None, 12, 15, 18, 21, 24]:
            add(container, password, 0, 0, stated, None)
    batch(adapter, "decrypt", pairs)

    # The admission table, exhaustively: every container length, stated length and suite.
    pairs = []
    for words in ref.WORD_COUNTS:
        container = bip.text(bip.from_entropy(rng.randbytes(words // 3 * 4)))
        for stated in [None, 0, 1, 3, 11, 12, 13, 14, 15, 16, 18, 20, 21, 22, 23, 24, 25, 27, 48,
                       2 ** 32 + 12]:
            for suite in [None, 3, 4]:
                add(container, "pw", 0, 0, stated, suite)
    batch(adapter, "admission", pairs)


def card_group(adapter, bip, rng, scale):
    field = ref.Gf2048()
    pairs = []
    containers = []
    for _ in range(40 * scale):
        words = rng.choice(ref.WORD_COUNTS)
        numbers = bip.from_entropy(fit(random_entropy(rng, words // 3 * 4), words // 3 * 4))
        containers.append(numbers)
        for k in range(0, 11):
            request = {"op": "card", "container": bip.text(numbers), "k": k}
            if k in (2, 4, 6, 8):
                expected = {"ok": bip.text(field.parity(numbers, k))}
            else:
                expected = {"err": f"CardWordCount {{ words: {k} }}"}
            pairs.append((request, expected))
    batch(adapter, "card", pairs)
    return containers


def expected_repair(bip, field, written_tokens, card_tokens, small, known=None):
    """The repair the profile gives, or NotPossible; `None` when only the properties of an answer
    can be checked (damage beyond the bound on a long codeword). `known` is the codeword when the
    damage is within the bound, which is then the only codeword within it (minimum distance
    k + 1); otherwise a small code is searched exhaustively by Gaussian elimination."""
    n, k = len(written_tokens), len(card_tokens)
    if n not in ref.WORD_COUNTS:
        return {"err": f"ContainerWordCount {{ words: {n} }}"}
    if k not in (2, 4, 6, 8):
        return {"err": f"CardWordCount {{ words: {k} }}"}
    received, erased = [], []
    for position, token in enumerate(written_tokens + card_tokens):
        word = bip.read_word(token)
        if word is None:
            erased.append(position)
            received.append(0)
        else:
            received.append(bip.index[word])
    if len(erased) > k:
        return {"err": "NotPossible"}
    found = {tuple(known)} if known is not None else set()
    readable = [] if known is not None else [p for p in range(n + k) if p not in erased]
    for wrong in range(0 if known is not None else (k - len(erased)) // 2 + 1):
        if not small and wrong > 1:
            return None
        for chosen in itertools.combinations(readable, wrong):
            codeword = field.solve_at(received, sorted(erased + list(chosen)), k)
            if codeword is not None:
                found.add(tuple(codeword))
        if found:
            break
    assert len(found) <= 1, "two codewords within the bound"
    if not found:
        return {"err": "NotPossible"} if small or len(erased) == k else None
    codeword = list(found.pop())
    if bip.entropy_of(codeword[:n]) is None:
        return {"err": "NotPossible"}
    changes = []
    for position in range(n + k):
        if position in erased or codeword[position] != received[position]:
            on_card = position >= n
            changes.append([on_card, position - n + 1 if on_card else position + 1,
                            None if position in erased else bip.words[received[position]],
                            bip.words[codeword[position]]])
    return {"ok": bip.text(codeword[:n]), "changes": changes}


def repair_group(adapter, bip, rng, containers, scale):
    field = ref.Gf2048()
    pairs = []
    unchecked = []
    junk = ["?", "", "xyzw", "ab", "abandons", "\xe1bout", "-"]
    for numbers in containers:
        n = len(numbers)
        for k in (2, 4, 6, 8):
            codeword = numbers + field.parity(numbers, k)
            for _ in range(3):
                tokens = [bip.words[c] for c in codeword]
                tokens = [t[: rng.randrange(4, len(t) + 1)] if len(t) > 4 and rng.random() < 0.2
                          else t for t in tokens]
                beyond = rng.random() < 0.3
                s = rng.randrange(0, k + 1)
                e = rng.randrange(0, (k - s) // 2 + 1)
                if beyond:
                    e += rng.randrange(1, 3)
                positions = rng.sample(range(n + k), min(n + k, s + e))
                for at in positions[:s]:
                    tokens[at] = rng.choice(junk) or "?"
                for at in positions[s:]:
                    other = rng.randrange(2047)
                    other += other >= codeword[at]
                    tokens[at] = bip.words[other]
                written, card = " ".join(tokens[:n]), " ".join(tokens[n:])
                small = n + k <= 20
                known = codeword if not beyond else None
                expected = expected_repair(bip, field, tokens[:n], tokens[n:], small, known)
                request = {"op": "repair", "written": written, "card": card}
                if expected is None:
                    unchecked.append((request, tokens, k))
                else:
                    pairs.append((request, expected))
                    if not beyond:
                        assert expected["ok"] == bip.text(numbers), "within the bound"
    # Word counts and token reading.
    zero = bip.text(bip.from_entropy(bytes(16)))
    card = bip.text(field.parity(bip.from_entropy(bytes(16)), 2))
    for written, card_text in [(zero, ""), (zero, "a b c"), ("abandon " * 11, card),
                               (zero + " zoo", card), (zero, card + " zoo" * 7)]:
        expected = expected_repair(bip, field, ref.split_white(written),
                                   ref.split_white(card_text), True)
        pairs.append(({"op": "repair", "written": written, "card": card_text}, expected))
    batch(adapter, "repair", pairs)
    # Beyond the bound on long codewords: the answer must be a codeword within the bound that
    # passes its checksum, and the changes must name every word that differs from what was read.
    answers = run_adapter(adapter, [request for request, _, _ in unchecked])
    for (request, tokens, k), answer in zip(unchecked, answers):
        counts["repair-beyond-bound-properties"] = counts.get("repair-beyond-bound-properties",
                                                              0) + 1
        if "err" in answer:
            if answer != {"err": "NotPossible"}:
                failures.append(f"repair beyond: {request} {answer}")
            continue
        n = len(tokens) - k
        container = bip.read(answer["ok"])
        card_words = [bip.read_word(t) for t in tokens[n:]]
        corrected = container[1] + [bip.index[w] if w else 0 for w in card_words]
        for on_card, position, _, word in answer["changes"]:
            corrected[(n if on_card else 0) + position - 1] = bip.index[word]
        read = [bip.read_word(t) for t in tokens]
        differ = [p for p in range(n + k) if read[p] is None or bip.index[read[p]] != corrected[p]]
        s = sum(1 for r in read if r is None)
        e = len(differ) - s
        ok = (container[0] == "ok" and field.is_codeword(corrected, k) and 2 * e + s <= k
              and len(answer["changes"]) == len(differ))
        if not ok:
            failures.append(f"repair beyond: {request} {answer}")


def check_word_group(adapter, eff, rng, scale):
    index = {word: number for number, word in enumerate(eff)}
    pairs = []
    for _ in range(200 * scale):
        drawn = [rng.randrange(7776) for _ in range(5)]
        if rng.random() < 0.1:
            drawn[rng.randrange(5)] = rng.randrange(7776, 65536)
        expected = ref.check_index(drawn) if max(drawn) < 7776 else None
        pairs.append(({"op": "check_word", "drawn": drawn}, {"ok": expected}))
    for drawn in ([0] * 5, [7775] * 5, [7776, 0, 0, 0, 0], [65535] * 5):
        expected = ref.check_index(drawn) if max(drawn) < 7776 else None
        pairs.append(({"op": "check_word", "drawn": drawn}, {"ok": expected}))
    batch(adapter, "check-word", pairs)

    pairs = []
    for _ in range(100 * scale):
        drawn = [rng.randrange(7776) for _ in range(5)]
        tokens = [eff[i] for i in drawn + [ref.check_index(drawn)]]
        kind = rng.randrange(8)
        if kind == 1:
            tokens[rng.randrange(6)] = rng.choice(["?", "", "Zoom", "yoyo", "drop down", "x"])
        elif kind == 2:
            tokens[rng.randrange(6)] = rng.choice(eff)
        elif kind == 3:
            for at in rng.sample(range(6), 2):
                tokens[at] = "?"
        elif kind == 4:
            del tokens[rng.randrange(6)]
        elif kind == 5:
            a, b = rng.sample(range(6), 2)
            tokens[a], tokens[b] = tokens[b], tokens[a]
        password = " ".join(tokens)
        if kind == 6:
            password = rng.choice(["  ", " ", "\t", "\xa0"]).join(tokens)
        if kind == 7:
            password = password.upper() if rng.random() < 0.5 else " " + password
        expected = ref.check_password(eff, index, password)
        pairs.append(({"op": "check", "password": password}, expected))
    batch(adapter, "check", pairs)

    answer = run_adapter(adapter, [{"op": "eff"}])[0]
    compare("eff-list", {"op": "eff"}, answer, {"ok": eff})


def draw_group(adapter, bip, rng, scale):
    pairs = []
    passing = {"TREZOR": bytes(24) + (76562).to_bytes(8, "big"),
               "": bytes(24) + (98918).to_bytes(8, "big")}
    for _ in range(4 * scale):
        passphrase = rng.choice(list(passing))
        trials = [rng.randbytes(32) for _ in range(rng.randrange(0, 4))]
        if rng.random() < 0.8:
            trials.insert(rng.randrange(len(trials) + 1), passing[passphrase])
        trials.append(passing[passphrase])
        used = None
        for at, trial in enumerate(trials, 1):
            phrase = bip.text(bip.from_entropy(trial))
            seed = ref.wallet_check_seed(phrase, passphrase)
            if ref.wallet_check_digest(seed)[:2] == b"\0\0":
                used = at
                break
        request = {"op": "draw", "passphrase": passphrase, "trials": [t.hex() for t in trials]}
        pairs.append((request, {"ok": bip.text(bip.from_entropy(trials[used - 1])), "used": used}))
    pairs.append(({"op": "draw", "passphrase": "TREZOR", "trials": [bytes(32).hex()]},
                  {"err": "Cancelled", "used": 1}))
    batch(adapter, "draw", pairs)
    # The check's answer for every length: Some only for 24 words.
    pairs = []
    for words in ref.WORD_COUNTS:
        entropy = rng.randbytes(words // 3 * 4)
        phrase = bip.text(bip.from_entropy(entropy))
        seed = ref.wallet_check_seed(phrase, "")
        passes = ref.wallet_check_digest(seed)[:2] == b"\0\0" if words == 24 else None
        pairs.append(({"op": "seed", "phrase": phrase, "passphrase": ""},
                      {"seed": seed.hex(), "passes": passes}))
    batch(adapter, "seed-lengths", pairs)


UCD = None


def main():
    global UCD
    parser = argparse.ArgumentParser()
    for option in ("--adapter", "--english", "--eff", "--vectors", "--ucd"):
        parser.add_argument(option, required=True)
    parser.add_argument("--scale", type=int, default=10)
    args = parser.parse_args()
    bip = ref.Bip39(args.english)
    eff = ref.eff_words(args.eff)
    UCD = ref.Ucd(args.ucd)
    rng = random.Random(0x4155443030325F70)
    bip39_vector_group(args.adapter)
    reading_group(args.adapter, bip, rng, args.scale)
    creation_step_2_group(args.adapter, bip, rng, args.vectors, args.scale)
    decrypts = encryption_group(args.adapter, bip, rng, args.scale)
    recovery_group(args.adapter, bip, rng, args.vectors, decrypts, args.scale)
    containers = card_group(args.adapter, bip, rng, args.scale)
    repair_group(args.adapter, bip, rng, containers, args.scale)
    check_word_group(args.adapter, eff, rng, args.scale)
    draw_group(args.adapter, bip, rng, args.scale)
    for group, count in sorted(counts.items()):
        print(f"{group}: {count}")
    if failures:
        print(f"FAILED: {len(failures)}")
        print("\n".join(failures[:30]))
        sys.exit(1)
    print("All differential probes match.")


if __name__ == "__main__":
    main()
