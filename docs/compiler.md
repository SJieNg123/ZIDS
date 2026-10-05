# Private policy compiler

`src/zids_v2/compiler.py` compiles the declared EasyList profile and the complete
framed request context into one total 256-byte DFA. Request type, party and the
most specific matching document-domain suffix constrain each URL matcher.
Document and generic-block exceptions include the explicitly supplied ancestors.

The Thompson NFA uses zero-width URL-boundary assertions for anchors. Search,
wildcards and negated character classes cannot consume field delimiters. Literal
bytes, ASCII classes, alternatives, groups, bounded and unbounded repetition and
URL start/end anchors are supported. Backreferences, lookaround, word boundaries
and inline flags produce coverage errors. There is no regex runtime in the client.
The compiler follows the reference's pattern-and-input lowercasing behavior,
including its effect on raw regex escapes.

NFA accept flags implement the full policy at EOS only. ALLOW wins, otherwise
specific blocking wins, otherwise generic blocking wins unless disabled by a
document exception. Output-preserving Moore refinement keeps the three labels
distinct. It does not merge BLOCK and ALLOW into a common accepting partition.

Rules with identical context conditions and action share a regex-prefix trie.
Context guards remain separate, while matched URL suffixes are shared by policy
flag and frame kind. Once such a suffix is active, earlier URL alternatives with
the same effect cannot change its output and are removed from the subset. Literal
trie edges use a single new state. These transformations preserve policy effects
without retaining the identity of a matched rule.

Compilation has no default NFA state, DFA state or time limit. The CLI and
benchmark run until completion or an actual allocation, process or OS failure.
`--max-nfa`, `--max-dfa` and `--seconds` are optional, explicitly requested limits
for reproducing earlier bounded attempts. Omit all three for unlimited compilation.
Regex feature validation runs separately before whole-policy construction.
Exceeding an explicitly requested bound is an error, never rule pruning or a
plaintext fallback. Python 3.12's regex parser is an explicit implementation
dependency. Runtime matching does not use it.

The benchmark also removes its outer compile-worker timeout when `--seconds`
is omitted. It monitors worker exit so a killed worker cannot leave its parent
waiting forever for a missing result. Each scale writes `compile-progress.jsonl`
with phase changes and periodic NFA/DFA counts, elapsed time, worker PID and peak
RSS. These are local server diagnostics. They are not protocol messages.

Tests compare the independent ABP reference against 192 context combinations and
80 regex/domain combinations. Three fresh GDFA evaluations using actual NP base
OT check BLOCK, ALLOW and NOMATCH against that reference and the plaintext DFA.
Protocol role separation is additionally tested in independent processes.

The full snapshot's 47,154 parser-supported network rules pass regex feature
validation. This does not imply that their combined DFA fits available hardware.
The compiler's state counts, grouping bounds and source hashes are server-private.

For recoverable compilation, pass `--checkpoint PATH.sqlite` to `compile`.
Matching existing checkpoints resume automatically. Use a new output directory
for a resumed CLI attempt, keeping the same input text and checkpoint path.
The benchmark enables a separate checkpoint per scale. SQLite commits completed
transitions and newly discovered subsets together every 1,000 rows or 30 seconds.
Abrupt exit rolls back only the uncommitted transaction. Source text, compiler
sources, Python version and constructed NFA are bound to the checkpoint, and an
OS lock excludes concurrent writers. Checkpoints contain private policy only.
Completed determinization is retained if later minimization or output fails.
Construction and minimization restart on recovery. OT sessions are never resumed.
