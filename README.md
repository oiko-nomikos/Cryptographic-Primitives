# Cryptographic Primitives – Educational Implementations

**From-scratch implementations of core cryptographic algorithms** based on official NIST standards.

This project is **purely educational / experimental**.  
It demonstrates how AES, SHA-256, HMAC, and a simple password-based key derivation function can be implemented from specification — without relying on external libraries.

**Never use this code for real security-sensitive applications.**

## What this project contains

- AES-128/192/256 in CBC mode with PKCS#7 padding  
- SHA-256 hash function  
- HMAC-SHA256  
- A simple iterative password-based key derivation function (inspired by PBKDF2)  
- **Custom timing-based entropy collection & randomness pool** (the main invention of this project)  
- Command-line encrypt/decrypt demo that reads/writes an `encrypted.dat` file

All cryptographic primitives (AES, SHA-256, HMAC) are **independent re-implementations** written from the public specifications:

- AES — NIST FIPS 197  
- SHA-256 — NIST FIPS 180-4  
- HMAC — NIST FIPS 198  
- PBKDF-style key derivation — NIST SP 800-132  

## The Heart of the Project: Custom Randomness Generation

The **primary motivation** for building this entire demo was to create a **completely self-contained randomness system** — no OS APIs, no hardware RNGs, no external dependencies — just pure software extracting entropy from the real world.

### RandomNumberGenerator – The Bit Harvester

This class is the core invention: it turns tiny variations in **CPU execution timing** into usable random bits.

**How it works (step by step):**

1. Runs a fixed number of iterations (default: 1000).
2. In each iteration:
   - Measures the exact nanosecond duration of a trivial countdown loop (`while (x > 0) x--;` with x=10).
   - Compares the duration to a running global average.
   - If shorter than average → bit = 0  
     If longer than average → bit = 1  
   (This simple comparison acts as a basic debiasing mechanism.)
3. Stores bits in a sliding window deque of size 512.
4. When the window is full:
   - Packs the 512 bits into a 64-byte block.
   - Feeds it into SHA-256.
   - Converts the 256-bit hash output into a string of 256 '0'/'1' characters (whitening step).
   - Appends this to the result.
5. After all iterations, returns a long bit string (typically hundreds of thousands of bits).

**Why this is clever / educational:**
- Demonstrates real entropy extraction from **non-obvious sources** (CPU jitter caused by scheduling, cache, interrupts, etc.).
- Shows basic debiasing (average comparison) and whitening (hash function).
- Fully transparent — you can see exactly where randomness comes from.

**Limitations (important!):**
- Entropy quality is **very low** on modern hardware (timings are often too stable or predictable).
- Easily influenced by system load, CPU frequency scaling, virtualization, etc.
- Not suitable for cryptographic key material — included only for learning.

### BinaryEntropyPool – The On-Demand Bit Reservoir

This class manages the bits produced by `RandomNumberGenerator` in a reusable, thread-safe way.

**How it works:**

1. Maintains a growing string `bitPool` of '0'/'1' characters.
2. When someone requests `get(bitsNeeded)`:
   - If not enough bits in pool → calls `rng.run()` to generate more and appends them.
   - Extracts exactly `bitsNeeded` bits from the front.
   - Removes the used bits (keeps the rest for next time).
3. Protected by a mutex for thread safety (though the demo is single-threaded).

**Why it's useful:**
- Lazy evaluation: only generates bits when actually needed (e.g., for salt or IV).
- Acts as a buffer so you don't waste entropy by regenerating on every call.
- Simple interface: `bep.get(128)` → 128 random bits as string.

**Combined effect:**
Together, these classes let the entire program generate salts and IVs **without ever calling the OS for randomness** — making the demo 100% self-contained and a nice teaching tool for "how randomness can be harvested from nothing".

## Purpose & Goals

This project exists to help understand **how modern symmetric cryptography actually works under the hood**, with a special focus on randomness generation.

It tries to solve / illustrate:

- How block ciphers (AES) operate in CBC mode  
- How cryptographic hash functions (SHA-256) process data  
- How message authentication codes (HMAC) are constructed  
- How passwords can be turned into cryptographic keys  
- **How to extract usable randomness from timing jitter in software** (the main invention)

It's meant for:

- Learning cryptography implementation  
- CTF challenges / academic exercises  
- Understanding NIST standards by reading code instead of just math  
- Experimenting with DIY entropy collection

## Important Security Warnings

**THIS CODE IS NOT SECURE FOR REAL USE.**

Critical problems / limitations include:

- The custom timing-based RNG has **extremely low entropy** on modern hardware and is **completely unsuitable** for generating keys, IVs, or salts.
- No side-channel attack mitigations (timing, cache, power analysis, etc.)
- No formal verification or extensive test vectors beyond basic sanity checks
- No resistance to fault injection, padding oracles, or other active attacks
- Iteration count (100,000) is far too low for real password protection in 2026
- No memory-hardness (vulnerable to GPU/ASIC cracking)

**Do NOT use this software to protect real data, passwords, financial information, personal secrets, or anything valuable.**

For anything that actually matters, use well-audited, battle-tested libraries:

- OpenSSL  
- libsodium  
- cryptography (Python)  
- Bouncy Castle (Java)  
- age / rage (modern file encryption tools)

## How to build & run

Requirements:

- C++23 compiler (g++ with `-std=c++23`)
- MSYS2 / MinGW or similar environment (on Windows)

```bash
g++ -std=c++23 -Wall -Wextra -pthread -g AES.cpp -o aes-demo
