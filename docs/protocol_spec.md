# ZIDS v2 protocol contract

Scope: EasyList network matching through the sparse ODFA in ZIDS §5.4, using base OT only. OT extension, Beaver OT preprocessing and §6.5 wrapping-key optimization are excluded by the user's 2026-10-04 instruction. Browser execution is excluded.

## Boundaries

Server input is a total byte-alphabet DFA with a final output function. Client input is a nonempty byte string X. EasyList maps caller-supplied request context to X and rules to this DFA. Public parameters are version, suite, n, Q, outmax, cmax, k and a fixed output alphabet. Rule sources, rule hashes, transition tables, group membership, permutations, keys and pads are server-private. Only the final ALLOW/BLOCK/NOMATCH is returned locally to the client. No intermediate result or decode failure is sent to the server.

Client input validity and authenticity as browser traffic are not guaranteed. A malicious server can choose a wrong policy or corrupt its ciphertexts. The ZIDS theorem protects privacy against such a server, not correctness of its policy. This implementation targets static corruptions and authenticated peer transport, with no UC or arbitrary concurrent-composition claim.

## Sparse DFA and bit layout

For each state q, group all bytes leading to the same destination. Deduplicate those sets globally into C. C_x is the set of groups containing x. outmax is the maximum groups at a state and cmax is max_x |C_x|. Neither catalog nor group identifiers leave the server.

Let b = ceil(log2 Q), k = 128 and w = 2k+b. Q is at least 2. Add unreachable dummy states when required to encode the public output labels. A cell consists of outmax entries of exactly w bits, packed big-endian into ceil(outmax*w/8) bytes with canonical zero high alignment bits. Bit-level entry masks use w random bits. State labels and next pads use b and k bits respectively.

Each session has independent permutations pi_i from original to permuted states, independent k-bit pads P[i,permuted_state] and independent w-bit K[i,group]. For i<n-1 the plaintext transition entry is next_state || next_pad || zero^k. For i=n-1 it is a zero-extended (k+b)-bit final label || zero^k. Real entries are XORed with their group key. Cells are padded with uniform w-bit dummy entries, shuffled, and masked as a whole with a domain-separated PRG seeded by the current pad.

For each position i the OT sender provides 256 messages. Message x is the shuffled keys for C_x, padded to cmax with uniform keys. The bundle uses cmax*ceil(w/8) bytes, each key has canonical high alignment bits. Independent group keys are shared between overlapping C_x bundles at the same position, as required by the paper.

The client starts with pi_0(q0) and its pad. At each position it opens exactly one local cell, tries all entry/key combinations, checks the zero tail, state bounds and terminal format, and requires exactly one valid candidate. The probability of a wrong key passing the tail is bounded using the number of attempts and 2^-k. Only after n transitions does it output the final label. No public accept map, inverse permutation, row alphabet or master is needed.

## Wire and lifecycle

Use versioned length-prefixed binary frames with a fixed-size header containing message kind, opaque 128-bit session ID, monotonically ordered batch ID and payload length. Reject unknown kinds, versions, excess lengths, truncation, duplicate/reordered batches and extra bytes. Raw OT choices, DFA state indices and rules are not wire fields. Public dimensions determine all message counts and sizes.

For each base-OT batch the message schedule is sender setup, receiver query, sender response. Batching does not change the number of public-key bit transfers. The final receiver result and any decoding error are local only. Whole public artifacts are prefetched, never fetched according to a DFA path.

Compiled policy can be reused. Garbling and OT records cannot. Session states are CREATED -> PREPARED -> RESERVED -> CONSUMED, with failure after reservation -> BURNED. Reservation must be atomic. Restart never makes a reserved session reusable. New input always requires a new session. Same-transcript retries cannot obtain a second choice. Public manifests contain only the stated leakage and ciphertext framing/digests. Private manifests bind source, compiler, policy, suite and session.

## Resource and implementation boundaries

The new implementation lives in `src/zids_v2/` to prevent accidental imports of audited legacy crypto and to preserve the user's existing modified experiments. At CLI cutover, this package becomes the documented supported path. Legacy files are retained as historical experiments, not silently selected as fallbacks.

Before allocation, estimate GDFA bytes as n*Q*ceil(outmax*w/8), bundle bytes as n*256*cmax*ceil(w/8), and base OT transfers as 8n. Enforce resource caps with explicit errors. Do not drop rules, shorten X or reuse garbling to meet caps.

Tests must cover n=1, all byte choices, cmax>1, non-identity permutations, non-byte-aligned layouts, malformed points/frames/entries, replay and cross-session mixing. End-to-end tests compare independent EasyList reference, plaintext policy DFA and private evaluation. Functional and attack regression tests are evidence of correctness, not a general security proof.
