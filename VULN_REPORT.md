# Vulnerability Report — xmlsec Injected Bugs

This document records the 5 bugs manually injected into the xmlsec codebase for fuzzing research.
Each entry describes the location, the exact change made, the vulnerability class, the expected
sanitizer signal, the associated fuzzing harness, and the seeds most likely to trigger it.

---

## Bug 1 — Use-After-Free in `xmlSecBufferFinalize`

**File:** `src/buffer.c`
**Function:** `xmlSecBufferFinalize`
**Vulnerability Class:** Use-After-Free (UAF) — heap write to freed memory
**Expected Sanitizer Signal:** AddressSanitizer `heap-use-after-free` (WRITE)

### Change

The order of `xmlFree` and `xmlSecBufferEmpty` was swapped:

```c
// BEFORE (correct)
xmlSecBufferEmpty(buf);       // zeros buf->data, sets size=0
if(buf->data != 0) {
    xmlFree(buf->data);       // then frees
}

// AFTER (buggy)
if(buf->data != 0) {
    xmlFree(buf->data);       // frees first
}
xmlSecBufferEmpty(buf);       // then zeros — writes to freed heap via memset()
```

`xmlSecBufferEmpty` calls `memset(buf->data, 0, buf->maxSize)`. After `xmlFree`, `buf->data`
points to freed heap memory. This is a write UAF of up to `buf->maxSize` bytes.

### Trigger Condition

Any code path that creates and destroys an `xmlSecBuffer` with non-zero content.
This includes nearly every xmlsec operation (signature creation/verification,
encryption, key loading) since all use `xmlSecBuffer` internally.

### Harness

`tests/oss-fuzz/harness_buffer.c`

### Seeds

`tests/oss-fuzz/seeds/buffer/seed_uaf_finalize`
`tests/oss-fuzz/seeds/buffer/seed_removehead_underflow`

---

## Bug 2 — Integer Underflow + Heap Corruption in `xmlSecBufferRemoveHead`

**File:** `src/buffer.c`
**Function:** `xmlSecBufferRemoveHead`
**Vulnerability Class:** Integer underflow → heap buffer overflow (via `memmove`)
**Expected Sanitizer Signal:** AddressSanitizer `heap-buffer-overflow` (READ+WRITE)

### Change

The comparison operator was inverted:

```c
// BEFORE (correct)
if(size < buf->size) {
    buf->size -= size;
    memmove(buf->data, buf->data + size, buf->size);
} else {
    buf->size = 0;
}

// AFTER (buggy)
if(size > buf->size) {       // reversed: now fires when size > buf->size
    buf->size -= size;       // integer underflow: wraps to SIZE_MAX - (size-buf->size-1)
    memmove(buf->data, buf->data + size, buf->size);  // memmove with huge count
} else {
    buf->size = 0;
}
```

When the caller passes `size > buf->size`, `buf->size -= size` wraps around (unsigned
subtraction). The resulting `buf->size` is a near-`SIZE_MAX` value. The subsequent `memmove`
copies that many bytes, producing a massive out-of-bounds read and write.

### Trigger Condition

Call `xmlSecBufferRemoveHead(buf, n)` where `n > buf->size`. The harness explicitly
exercises this case. It can also be triggered by crafted XML input that causes the
library to attempt head removal of more bytes than the buffer currently contains.

### Harness

`tests/oss-fuzz/harness_buffer.c`

Byte 0 of the seed controls `remove_size`. A value of `0xC8` (200) with 9 bytes of
payload data (`buf->size = 9`) satisfies `remove_size > buf->size`.

### Seeds

`tests/oss-fuzz/seeds/buffer/seed_removehead_underflow`

---

## Bug 3 — Heap Out-of-Bounds Write in `xmlSecPtrListEnsureSize`

**File:** `src/list.c`
**Function:** `xmlSecPtrListEnsureSize` (static)
**Vulnerability Class:** Heap buffer overflow (OOB write)
**Expected Sanitizer Signal:** AddressSanitizer `heap-buffer-overflow` (WRITE)

### Change

The growth formula in `xmlSecAllocModeDouble` was reduced:

```c
// BEFORE (correct)
case xmlSecAllocModeDouble:
    newSize = 2 * size + 32;
    break;

// AFTER (buggy)
case xmlSecAllocModeDouble:
    newSize = size / 2 + 32;
    break;
```

`gInitialSize` is 64. The formula `size / 2 + 32` equals `gInitialSize` when `size = 64`.
After the initial allocation (capacity 64), the list fills up (`use = 63, max = 64`).
The next `Add` calls `EnsureSize(list, 64)`:
- `newSize = 64/2 + 32 = 64`. Not less than `gInitialSize`, so no floor applies.
- `list->max` stays 64. After the add, `use = 64`.

The following `Add` calls `EnsureSize(list, 65)`:
- `newSize = 65/2 + 32 = 64` (integer division). `list->max` becomes 64 again.
- The write `list->data[list->use++]` writes to `list->data[64]` — **one pointer past
  the end of a 64-pointer allocation**.

### Trigger Condition

Add more than 64 items to any `xmlSecPtrList`. The harness drives this directly.
In real XML processing this occurs via transform chains, key lists, and reference lists.

### Harness

`tests/oss-fuzz/harness_list.c`

### Seeds

`tests/oss-fuzz/seeds/list/seed_oob_80items` — adds 80 items (exceeds capacity by 16)
`tests/oss-fuzz/seeds/list/seed_oob_65items` — adds 65 items (minimum to trigger)

---

## Bug 4 — Heap Out-of-Bounds Write in `xmlSecBase64GetEncodeSize`

**File:** `src/base64.c`
**Function:** `xmlSecBase64GetEncodeSize` (static)
**Vulnerability Class:** Heap buffer overflow (OOB write via `memcpy` / null-terminator write)
**Expected Sanitizer Signal:** AddressSanitizer `heap-buffer-overflow` (WRITE)

### Change

The safety margin in the encode output size formula was reduced:

```c
// BEFORE (correct)
size = (4 * inSize) / 3 + 4;

// AFTER (buggy)
size = (4 * inSize) / 3 + 1;
```

`xmlSecBase64Encode` allocates `xmlSecBase64GetEncodeSize(0, inSize)` bytes and then
writes `ptr[outUpdatedSize + outFinalSize] = '\0'`. The actual number of output
characters for `n` input bytes is `ceil(n/3) * 4`.

With the buggy formula (no columns), the allocation is `(4n/3) + 1 + 1 = (4n/3) + 2`.
For most input lengths, `ceil(n/3)*4 + 1 > (4n/3) + 2`, meaning the null-terminator
write goes past the end:

| n | Allocated (buggy) | Needed | OOB? |
|---|-------------------|--------|------|
| 1 | 3                 | 5      | YES (−2) |
| 2 | 4                 | 5      | YES (−1) |
| 4 | 7                 | 9      | YES (−2) |
| 5 | 8                 | 9      | YES (−1) |
| 7 | 11                | 13     | YES (−2) |

### Trigger Condition

Call `xmlSecBase64Encode` with any input length that is **not** a multiple of 3.
This occurs in signature template creation, key encoding, and certificate processing.

### Harness

`tests/oss-fuzz/harness_base64.c`

### Seeds

`tests/oss-fuzz/seeds/base64/seed_1byte` — 1 byte input, OOB by 2
`tests/oss-fuzz/seeds/base64/seed_4bytes` — 4 bytes input, OOB by 2
`tests/oss-fuzz/seeds/base64/seed_10bytes` — 10 bytes input, OOB by 2

---

## Bug 5 — Heap Out-of-Bounds Write in `xmlSecBnToString`

**File:** `src/bn.c`
**Function:** `xmlSecBnToString`
**Vulnerability Class:** Heap buffer overflow (OOB write via `memset`)
**Expected Sanitizer Signal:** AddressSanitizer `heap-buffer-overflow` (WRITE)

### Change

The allocation for the result string is one byte short:

```c
// BEFORE (correct)
len = 8 * size + 1 + 1;
res = (xmlChar*)xmlMalloc(len + 1);   // allocates len+1 bytes

// AFTER (buggy)
len = 8 * size + 1 + 1;
res = (xmlChar*)xmlMalloc(len);       // allocates len bytes (one less)
```

Immediately after the allocation, the function calls:

```c
memset(res, 0, len + 1);
```

With the buggy allocation of `len` bytes, `memset(res, 0, len + 1)` writes `len + 1`
bytes — one byte past the end of the allocation. This is an **immediate** heap OOB
write triggered on every call to `xmlSecBnToString` with a non-empty BN.

### Trigger Condition

Any call to `xmlSecBnToString`, `xmlSecBnToHexString`, or `xmlSecBnToDecString` with a
non-zero BN. These are called during RSA/DSA key serialization, X.509 serial number
formatting, and XML signature template generation.

### Harness

`tests/oss-fuzz/harness_bn.c`

### Seeds

`tests/oss-fuzz/seeds/bn/seed_base2_large` — base 2 with 16-byte BN
`tests/oss-fuzz/seeds/bn/seed_base16` — base 16 with 20-byte BN
`tests/oss-fuzz/seeds/bn/seed_base10` — base 10 with 32-byte BN

---

## Summary Table

| # | File | Function | Class | Harness |
|---|------|----------|-------|---------|
| 1 | `src/buffer.c` | `xmlSecBufferFinalize` | UAF write | `harness_buffer.c` |
| 2 | `src/buffer.c` | `xmlSecBufferRemoveHead` | Integer underflow → heap overflow | `harness_buffer.c` |
| 3 | `src/list.c` | `xmlSecPtrListEnsureSize` | Heap OOB write (off-by-half alloc) | `harness_list.c` |
| 4 | `src/base64.c` | `xmlSecBase64GetEncodeSize` | Heap OOB write (undersized alloc) | `harness_base64.c` |
| 5 | `src/bn.c` | `xmlSecBnToString` | Heap OOB write (malloc off-by-one) | `harness_bn.c` |

## Harness and Seed File Structure

```
tests/oss-fuzz/
├── harness_buffer.c          # Targets Bugs 1 & 2
├── harness_list.c            # Targets Bug 3
├── harness_base64.c          # Targets Bug 4
├── harness_bn.c              # Targets Bug 5
├── harness_xml.c             # End-to-end harness covering all bugs
└── seeds/
    ├── buffer/
    │   ├── seed_uaf_finalize
    │   └── seed_removehead_underflow
    ├── list/
    │   ├── seed_oob_80items
    │   └── seed_oob_65items
    ├── base64/
    │   ├── seed_1byte
    │   ├── seed_4bytes
    │   └── seed_10bytes
    ├── bn/
    │   ├── seed_base2_large
    │   ├── seed_base16
    │   └── seed_base10
    └── xml/
        ├── seed_xml_basic.xml
        └── seed_xml_base64_various.xml
```

## Building the Harnesses

All harnesses follow the same pattern as the existing `xmlsec_target.c`:
- Entry point `LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)`
- Error suppression via `xmlSetGenericErrorFunc(NULL, &ignore)` only
- Minimal includes (only the xmlsec headers needed for that harness)
- No `xmlSecInit()` call required

### OSS-Fuzz (automated)

`tests/oss-fuzz/build.sh` uses the standard OSS-Fuzz environment variables
(`$CC`, `$CFLAGS`, `$LIB_FUZZING_ENGINE`, `$OUT`, `$SRC`, `$WORK`) to build
**all** `.c` files in the `tests/oss-fuzz/` directory in one pass. The existing
`xmlsec_target.c` and every new `harness_*.c` are built identically.

Seed corpora are automatically packed into per-harness `*_seed_corpus.zip` files
in `$OUT`, matching the OSS-Fuzz corpus naming convention.

### Local replication

```sh
export CC=clang
export CFLAGS="-fsanitize=address,fuzzer-no-link -g -O1"
export LIB_FUZZING_ENGINE="-fsanitize=fuzzer"
export OUT=/tmp/xmlsec-fuzz-out
export SRC=$(pwd)/..     # parent of the xmlsec checkout
export WORK=/tmp/xmlsec-fuzz-work
mkdir -p "$OUT" "$WORK"

bash tests/oss-fuzz/build.sh

# Run a harness against its seed corpus:
"$OUT/harness_buffer" tests/oss-fuzz/seeds/buffer/
"$OUT/harness_list"   tests/oss-fuzz/seeds/list/
"$OUT/harness_base64" tests/oss-fuzz/seeds/base64/
"$OUT/harness_bn"     tests/oss-fuzz/seeds/bn/
"$OUT/harness_xml"    tests/oss-fuzz/seeds/xml/
```
