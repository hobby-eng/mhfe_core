"""AUD-002 protocol harness: an independent Python implementation of the MHFE specification 0.7.0
parts that mhfe-core implements, written from the specification text, not from the Rust code.

Standard library only. Argon2id is a parameter (`key_of`): the transcripts supply their recorded
keys and the differential uses the stand-in engine that the Rust adapter also uses.
"""

import hashlib
import hmac

BIP39_ENGLISH_SHA256 = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
EFF_LARGE_SHA256 = "addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e"
UNICODE_DATA_18_SHA256 = "0736451de439ae7baf1425136617da495e09ee5afbe6e394374db7009ea08950"
NORMALIZATION_TEST_18_SHA256 = "25a50d816764b04abfb4a646d3eb2b2a803284c3873d9a06757b94fe4513dde3"

WORD_COUNTS = (12, 15, 18, 21, 24)
SHORT = (12, 15, 18, 21)
SUITE3 = b"MHFE-BIP39-256-EXPERIMENTAL-3"
SUITE4 = b"MHFE-BIP39-LP-EXPERIMENTAL-4"
STAND_IN_TAG = b"AUD-002 stand-in Argon2id"

# Unicode's White_Space property (PropList.txt), which Rust's split_whitespace uses.
WHITE_SPACE = set(map(chr, [*range(0x9, 0xE), 0x20, 0x85, 0xA0, 0x1680, *range(0x2000, 0x200B),
                            0x2028, 0x2029, 0x202F, 0x205F, 0x3000]))


def sha256(data):
    return hashlib.sha256(data).digest()


def be32(value):
    return value.to_bytes(4, "big")


def checked_file(path, digest):
    data = open(path, "rb").read()
    actual = hashlib.sha256(data).hexdigest()
    if actual != digest:
        raise SystemExit(f"{path}: SHA-256 {actual}, expected {digest}")
    return data


# ------------------------------------------------------------- BIP39 (English) and reading words

class Bip39:
    def __init__(self, english_path):
        self.words = checked_file(english_path, BIP39_ENGLISH_SHA256).decode("ascii").split("\n")
        if self.words[-1] == "":
            self.words.pop()
        assert len(self.words) == 2048
        self.index = {word: number for number, word in enumerate(self.words)}

    def from_entropy(self, entropy):
        if len(entropy) * 8 not in (128, 160, 192, 224, 256):
            return None
        bits = int.from_bytes(entropy, "big")
        checksum_bits = len(entropy) * 8 // 32
        checksum = sha256(entropy)[0] >> (8 - checksum_bits)
        total = (bits << checksum_bits) | checksum
        count = (len(entropy) * 8 + checksum_bits) // 11
        numbers = [(total >> (11 * (count - 1 - at))) & 0x7FF for at in range(count)]
        return numbers

    def text(self, numbers):
        return " ".join(self.words[number] for number in numbers)

    def entropy_of(self, numbers):
        """The entropy of word numbers, or None when the checksum fails."""
        count = len(numbers)
        total = 0
        for number in numbers:
            total = (total << 11) | number
        checksum_bits = count // 3
        entropy_bits = count * 11 - checksum_bits
        entropy = (total >> checksum_bits).to_bytes(entropy_bits // 8, "big")
        if total & ((1 << checksum_bits) - 1) != sha256(entropy)[0] >> (8 - checksum_bits):
            return None
        return entropy

    def read_word(self, token):
        """Reading words: ASCII letter case ignored, an exact word first, else the only word that
        a token of four letters or more begins."""
        if not token.isascii():
            return None
        typed = token.lower()
        if typed in self.index:
            return typed
        if len(typed) < 4:
            return None
        matches = [word for word in self.words if word.startswith(typed)]
        return matches[0] if len(matches) == 1 else None

    def read(self, text):
        """('ok', numbers) or ('err', reason) in the crate's documented order of refusals."""
        tokens = split_white(text)
        if len(tokens) not in WORD_COUNTS:
            return ("err", f"InvalidWordCount {{ words: {len(tokens)} }}")
        numbers = []
        for position, token in enumerate(tokens, 1):
            word = self.read_word(token)
            if word is None:
                return ("err", f"UnknownWord {{ position: {position} }}")
            numbers.append(self.index[word])
        if self.entropy_of(numbers) is None:
            return ("err", "InvalidChecksum")
        return ("ok", numbers)


def split_white(text):
    tokens, current = [], []
    for character in text:
        if character in WHITE_SPACE:
            if current:
                tokens.append("".join(current))
                current = []
        else:
            current.append(character)
    if current:
        tokens.append("".join(current))
    return tokens


# ---------------------------------------------------------------- packing, permutation, recovery

def pack(entropy):
    r = 256 - 8 * len(entropy)
    return entropy + sha256(entropy)[: r // 8] if r else entropy


def detected(state):
    found = []
    for words in SHORT:
        size = words // 3 * 4
        if state[size:] == sha256(state[:size])[: 32 - size]:
            found.append(words)
    return found


def mem_kib(level):
    return (2 + level % 2) * 2 ** (20 + level // 2)


def passes(pim):
    return 12 * (pim + 1)


def stand_in_key(password, salt, memory_kib, passes_):
    return sha256(STAND_IN_TAG + be32(memory_kib) + be32(passes_) + be32(len(password))
                  + password + salt)


def round_values(suite, ent_bits, pim, mem, index, half, password, key_of):
    """RoundMask(i, R) and what it is made of, as the specification writes D_i, S_i, K_i, M_i."""
    suite_id = SUITE3 if suite == 3 else SUITE4
    settings = be32(mem) + be32(pim) + (be32(ent_bits) if suite == 4 else b"") + be32(index)
    salt_input = suite_id + b"/ROUND-SALT" + settings + half
    mask_input = suite_id + b"/ROUND-MASK" + settings + half
    salt = hashlib.blake2b(salt_input, digest_size=32).digest()[:16]
    key = key_of(password, salt, mem_kib(mem), passes(pim))
    mask = hmac.new(key, mask_input, hashlib.sha256).digest()[: len(half)]
    return {"salt_input": salt_input, "mask_input": mask_input, "salt": salt, "key": key,
            "mask": mask}


def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b, strict=True))


def forward(suite, x, pim, mem, password, key_of, record=None):
    h = len(x) // 2
    left, right = x[:h], x[h:]
    for index in range(12):
        values = round_values(suite, 8 * len(x), pim, mem, index, right, password, key_of)
        if record is not None:
            record.append(dict(values, index=index, left_before=left, right_before=right))
        left, right = right, xor(left, values["mask"])
        if record is not None:
            record[-1].update(left_after=left, right_after=right)
    return left + right


def inverse(suite, y, pim, mem, password, key_of, record=None):
    h = len(y) // 2
    left, right = y[:h], y[h:]  # L_{i+1}, R_{i+1}
    for index in range(11, -1, -1):
        r_i = left
        values = round_values(suite, 8 * len(y), pim, mem, index, r_i, password, key_of)
        if record is not None:
            record.append(dict(values, index=index, left_before=left, right_before=right))
        l_i = xor(right, values["mask"])
        left, right = l_i, r_i
        if record is not None:
            record[-1].update(left_after=left, right_after=right)
    return left + right


def length_rules(found, stated):
    """The readings of 'Recovering a mnemonic' as (words, verified) pairs, None for no reading."""
    every = [(words, True) for words in found] + [(24, False)]
    if stated is None:
        if len(found) == 1:
            return [(found[0], True)]
        return every if found else [(24, False)]
    if stated in found:
        return [(stated, True)]
    if stated != 24:
        return length_rules(found, None) if found else None
    return every if found else [(24, False)]


def admission(container_words, stated, suite):
    """The admission table of 'Choosing the suite and the length during recovery': None when the
    container is admitted, else the refusal in the crate's documented order."""
    selected = 3 if container_words == 24 else 4
    if suite is not None and suite != selected:
        return f"SuiteNotAdmitted {{ container_words: {container_words} }}"
    if stated is not None:
        if stated not in WORD_COUNTS:
            return f"InvalidWordCount {{ words: {stated} }}"
        if container_words != 24 and stated != container_words:
            return f"LengthNotAdmitted {{ container_words: {container_words} }}"
    return None


# ---------------------------------------------------------------- MHFE-REPAIR-1: GF(2^11)

class Gf2048:
    """GF(2^11) by bitwise multiplication modulo x^11 + x^2 + 1 (no tables)."""

    POLY = (1 << 11) | (1 << 2) | 1

    def mul(self, a, b):
        result = 0
        while b:
            if b & 1:
                result ^= a
            b >>= 1
            a <<= 1
            if a & (1 << 11):
                a ^= self.POLY
        return result

    def power(self, a, exponent):
        result = 1
        while exponent:
            if exponent & 1:
                result = self.mul(result, a)
            a = self.mul(a, a)
            exponent >>= 1
        return result

    def inverse(self, a):
        return self.power(a, 2046)

    def generator(self, k):
        g = [1]  # highest degree first
        for j in range(1, k + 1):
            root = self.power(2, j)
            g = [a ^ self.mul(root, b) for a, b in zip(g + [0], [0] + g)]
        return g

    def parity(self, data, k):
        """r(x) = m(x) x^k mod g(x) by long division, highest degree first."""
        g = self.generator(k)
        remainder = list(data) + [0] * k
        for at in range(len(data)):
            factor = remainder[at]
            if factor:
                for offset, coefficient in enumerate(g):
                    remainder[at + offset] ^= self.mul(factor, coefficient)
        return remainder[len(data):]

    def evaluate(self, coefficients, x):
        value = 0
        for coefficient in coefficients:
            value = self.mul(value, x) ^ coefficient
        return value

    def is_codeword(self, symbols, k):
        return all(self.evaluate(symbols, self.power(2, j)) == 0 for j in range(1, k + 1))

    def solve_at(self, received, positions, k):
        """The codeword equal to `received` outside `positions`, by Gaussian elimination on the
        parity checks c(alpha^j) = 0; None when there is none."""
        n = len(received)
        known = [0 if at in positions else value for at, value in enumerate(received)]
        rows = []
        for j in range(1, k + 1):
            alpha_j = self.power(2, j)
            row = [self.power(alpha_j, n - 1 - at) for at in positions]
            rows.append(row + [self.evaluate(known, alpha_j)])
        unknowns = len(positions)
        pivot_row = 0
        pivots = []
        for column in range(unknowns):
            pivot = next((r for r in range(pivot_row, k) if rows[r][column]), None)
            if pivot is None:
                return None
            rows[pivot_row], rows[pivot] = rows[pivot], rows[pivot_row]
            scale = self.inverse(rows[pivot_row][column])
            rows[pivot_row] = [self.mul(scale, value) for value in rows[pivot_row]]
            for r in range(k):
                if r != pivot_row and rows[r][column]:
                    factor = rows[r][column]
                    rows[r] = [a ^ self.mul(factor, b) for a, b in zip(rows[r], rows[pivot_row])]
            pivots.append(column)
            pivot_row += 1
        if any(rows[r][unknowns] for r in range(pivot_row, k)):
            return None
        corrected = list(known)
        for r, column in enumerate(pivots):
            corrected[positions[column]] = rows[r][unknowns]
        return corrected


# ---------------------------------------------------------------- MHFE-PASSWORD-CHECK-1

def eff_words(path):
    lines = checked_file(path, EFF_LARGE_SHA256).decode("ascii").split("\n")
    assert lines[-1] == ""
    words = [line.split("\t")[1] for line in lines[:-1]]
    assert len(words) == 7776
    return words


def check_index(drawn):
    return (drawn[0] + 5 * drawn[1] + 7 * drawn[2] + 11 * drawn[3] + 13 * drawn[4]) % 7776


def check_password(words, index, password):
    """The profile's checking rule: split at U+0020, compare tokens exactly as written."""
    tokens = password.split(" ")
    if len(tokens) != 6:
        return {"kind": "NotApplicable"}
    numbers = [index.get(token) for token in tokens]
    erased = [at for at, number in enumerate(numbers) if number is None]
    if len(erased) > 1:
        return {"kind": "NotApplicable"}

    def fitting(at):
        for candidate in range(7776):
            trial = list(numbers)
            trial[at] = candidate
            if check_index(trial[:5]) == trial[5]:
                return words[candidate]
        raise AssertionError("no fit")

    if erased:
        return {"kind": "OneErased", "position": erased[0] + 1, "word": fitting(erased[0])}
    if check_index(numbers[:5]) == numbers[5]:
        return {"kind": "Fits"}
    return {"kind": "Mismatch", "candidates": [fitting(at) for at in range(6)]}


# ---------------------------------------------------------------- NFKD with the Unicode 18.0.0 UCD

class Ucd:
    S_BASE, L_BASE, V_BASE, T_BASE = 0xAC00, 0x1100, 0x1161, 0x11A7
    L_COUNT, V_COUNT, T_COUNT = 19, 21, 28

    def __init__(self, unicode_data_path):
        text = checked_file(unicode_data_path, UNICODE_DATA_18_SHA256).decode("utf-8")
        self.assigned = bytearray(0x110000)
        self.category = {}
        self.ccc = {}
        self.decomposition = {}
        first = None
        for line in text.splitlines():
            fields = line.split(";")
            code = int(fields[0], 16)
            name, category = fields[1], fields[2]
            if name.endswith(", First>"):
                first = code
                continue
            start = first if name.endswith(", Last>") else code
            first = None
            for point in range(start, code + 1):
                self.assigned[point] = 1
                self.category[point] = category
            if int(fields[3]):
                self.ccc[code] = int(fields[3])
            if fields[5]:
                parts = fields[5].split()
                if parts[0].startswith("<"):
                    parts = parts[1:]
                self.decomposition[code] = [int(part, 16) for part in parts]

    def decompose(self, code, out):
        s_index = code - self.S_BASE
        if 0 <= s_index < self.L_COUNT * self.V_COUNT * self.T_COUNT:
            out.append(self.L_BASE + s_index // (self.V_COUNT * self.T_COUNT))
            out.append(self.V_BASE + s_index % (self.V_COUNT * self.T_COUNT) // self.T_COUNT)
            if s_index % self.T_COUNT:
                out.append(self.T_BASE + s_index % self.T_COUNT)
            return
        mapping = self.decomposition.get(code)
        if mapping is None:
            out.append(code)
            return
        for part in mapping:
            self.decompose(part, out)

    def nfkd(self, text):
        out = []
        for character in text:
            self.decompose(ord(character), out)
        # Canonical ordering: a stable sort of every run of non-starters by combining class.
        result, run = [], []
        for code in out:
            if self.ccc.get(code, 0) == 0:
                result.extend(sorted(run, key=lambda c: self.ccc[c]))
                run = []
                result.append(code)
            else:
                run.append(code)
        result.extend(sorted(run, key=lambda c: self.ccc[c]))
        return "".join(map(chr, result))

    def password(self, text):
        """P_enc, or the refusal in the crate's documented order."""
        if any(self.category.get(ord(c)) == "Cc" or c in "\u2028\u2029" for c in text):
            return ("err", "ForbiddenCharacter")
        if not all(self.assigned[ord(c)] for c in text):
            return ("err", "UnassignedCharacter")
        encoded = self.nfkd(text).encode("utf-8")
        if not encoded:
            return ("err", "EmptyPassword")
        if len(encoded) > 1024:
            return ("err", f"PasswordTooLong {{ bytes: {len(encoded)} }}")
        return ("ok", encoded.hex())


def wallet_check_seed(mnemonic_text, normalized_passphrase):
    return hashlib.pbkdf2_hmac("sha512", mnemonic_text.encode("utf-8"),
                               b"mnemonic" + normalized_passphrase.encode("utf-8"), 2048, 64)


def wallet_check_digest(seed):
    return sha256(b"MHFE-WALLET-CHECK-SEED-1" + be32(256) + seed)
