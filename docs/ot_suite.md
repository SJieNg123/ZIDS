# NP-ED25519-SHA256-v1

This is a base-OT suite. No IKNP, KOS, VOLE, fake extension, Beaver correction or separate short-key mode is implemented. The suite preserves ZIDS's n invocations of chosen-message 1-of-256 OT and uses 8n base bit transfers.

## Sources and exact construction

Base OT follows Naor and Pinkas, Efficient Oblivious Transfer Protocols, SODA 2001, Protocol 3.1, specialized to N=2. The author's [publication list](https://www.pinkas.net/) identifies the paper. The [paper copy inspected for Protocol 3.1](https://github.com/isislovecruft/library--/blob/master/cryptography%20%26%20mathematics/oblivious%20transfer/Efficient%20Oblivious%20Transfer%20Protocols%20%282001%29%20-%20Naor%2C%20Pinkas.pdf) contains the amortized construction on page 5 and its parallel-transfer simulation argument on page 6.

The reduction follows Naor and Pinkas, Computationally Secure Oblivious Transfer, Protocol 2.1. The [author manuscript](https://github.com/isislovecruft/library--/blob/master/cryptography%20%26%20mathematics/oblivious%20transfer/Computationally%20Secure%20Oblivious%20Transfer%20%282000%29%20-%20Naor%2C%20Pinkas.pdf) was visually inspected on pages 5–6. It is the earlier manuscript of the work cited as [22] in ZIDS, not a claim to possess the journal's source code.

## Native group

Use the prime-order subgroup of Edwards25519, order l = 2^252 + 27742317777372353535851937790883648493, with canonical 32-byte compressed point encoding. Arithmetic is PyNaCl 1.6.2 over libsodium. Use `crypto_core_ed25519_is_valid_point` on every received point and `crypto_scalarmult_ed25519_*_noclamp` for scalars sampled uniformly in 1..l-1. Reject identity, small-order points, noncanonical encodings, and points outside the main subgroup. Do not clamp scalars or substitute X25519's different public-key interface. The [libsodium point API](https://doc.libsodium.org/advanced/point-arithmetic) documents these checks.

This replaces the paper's P-192 group. It also replaces the old project's unchecked modular group arithmetic. Native secret scalar multiplication avoids implementing private exponentiation with Python integers. Python memory does not provide guaranteed erasure, and local process compromise or microarchitectural side channels are outside the protocol model.

## Base OT transcript in additive notation

1. Sender samples c,r and publishes C=cG and A=rG. It precomputes rC. A fresh pair is used for each batch.
2. Receiver samples t for each transfer with choice d. For d=0 send B=tG. For d=1 send B=C-tG. Resample when either B or C-B is identity so the accepted distribution is symmetric.
3. Sender validates B and C-B. Compute T0=rB and T1=rC-T0. Encrypt both equal-length messages with independent domain-separated hash pads H(Td, transcript_context, transfer_index, d).
4. Receiver computes T=tA and opens only ciphertext d. The receiver sends no completion or decryption-success signal.

Use SHAKE256 as the variable-length random-oracle pad with length-delimited fields and the requested output length. The original construction assumes CDH and a random oracle. The group is fixed by the suite, never supplied by an untrusted peer. Context includes suite, session, batch, counts, lengths, setup points, query binding and transfer index. Branch separation also handles a malicious receiver selecting B=C/2. Fresh batches and explicit indices prevent hash input reuse.

For a malicious sender, receiver queries have the same distribution for both choices after validated setup. For a malicious receiver, learning both hash inputs for one transfer recovers rC, contradicting CDH in the random-oracle argument. Protocol 3.1's simulator observes hash queries to extract at most one transfer choice and extends to batches using distinct contexts. This is the conditional basis for the asymmetric ZIDS security target, not a claim of UC security or external certification.

## 1-of-256 reduction

For each position generate eight independent pairs of 32-byte seeds S[j,0], S[j,1]. Choice bits are least-significant-bit first. For each complete byte option x, compute:

```text
pad_x = XOR over j=0..7 of F(S[j,bit_j(x)], context || j || x || message_length)
ciphertext_x = message_x XOR pad_x
```

F is counter-mode HMAC-SHA256 with an explicit output-length field. In particular, the COMPLETE option x is present in every PRF invocation. This is the difference that prevents the old four-ciphertext XOR cancellation. Obtain eight chosen seeds through eight real base OTs. Reconstruct only the pad for the chosen byte. The reduction is Protocol 2.1's PRF construction, with explicit framing and domain separation.

All 256 messages at each position have one public length. Sender and receiver APIs expose only their own inputs. The receiver cannot access seed pairs or invoke the same sender object again. A sender batch is consumed before returning a response, even if validation fails.

## Differences and validation

| Item | This suite |
| --- | --- |
| Curve | Edwards25519 prime subgroup instead of P-192 |
| Hash | SHAKE256 base-OT RO and HMAC-SHA256 reduction PRF |
| Extension | Explicitly absent, 8n public-key bit transfers |
| OT preprocessing | Absent, base OT takes place online |
| Schedule | Base OT setup/query/response, then all option ciphertexts in fixed public fragments |
| Output length | Chosen messages are complete padded group-key bundles |
| Security claim | CDH/RO base OT plus PRF reduction under the stated static-corruption model |

Native primitive smoke command on Windows and Linux: `uv run --locked python -B tools/check_v2_crypto.py`. Windows and Ubuntu 24.04.1 WSL2 have been measured locally. Remote CI and the target workstation remain separate validation environments.

Large-message transport slices the same PRF output, preserving the total message
length, option index and HMAC block counters. It does not introduce wrapping
keys, OT extension or another reduction. See `protocol_spec.md` for fragment
ordering and spooling. Individual OT message lengths fit the existing uint32
context field. Aggregate file sizes have no default cap.
