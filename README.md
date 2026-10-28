# PRF Network DAG Learning Example

A small, executable learning repo showing how PRF evidence nodes can be packaged
as a network-scoped, forkable DAG and checked independently by two local replicas.

This is a teaching example. It is not a PRF network protocol, canonical PRF
schema, consensus implementation, or production ratification service. “Replica”
in the packet example means a second local verifier given the same packet and a
separately configured trusted network root. The checkpoint exercise adds
loopback HTTP exchange between separate local source processes, but does not
establish an independently operated network or a globally current graph.

## Run it

Requirements: Java 17+ and Clojure CLI.

```sh
clojure -M:run
clojure -M:test
```

The first run fetches the pinned PRF framework dependency. The CLI prints the
network root, graph root, node/head counts, and whether both local replicas
accept the same packet.

## What the example contains

`src/prf/network/dag/learning.clj` builds one immutable network context with a
membership snapshot and a simple ratification policy. It creates a shared claim
basis node, then three child attestations: two approvals and one preserved
rejection/dissent. The child nodes form a fork from the same basis. PRF's
attestation DAG builder gives those nodes canonical content identities and
PRF's node validator checks node hashes, parent references, duplicates and
cycles. The graph wrapper binds the node set to the network context and gets a
separate domain-separated root.

Each local replica checks:

- the network root against its locally trusted expected root;
- that every node carries the same network binding;
- the PRF execution-node DAG validation result;
- declared graph-edge structure and the wrapper's graph root.

The tests mutate the network identity, a node and a node's network binding to
show that mismatched packets fail closed.

## What the example does not establish

The membership list and threshold are illustrative inputs, not authenticated
appointments. The example attestations are structurally valid but not
cryptographically signed, and a `:rejected` claim is only a preserved dissent
record; it is not a policy evaluation. No code here counts votes into an
accepted decision or authorizes a consequential transition. A real consumer
must verify signer identity and eligibility, bind each attestation to the exact
basis and policy, evaluate ratification under its authority policy, and verify
the authorized result again when consuming it.

The packet example does not provide peer discovery, transport, durable replicated
storage, fork choice, append authorization, equivocation handling, ordering,
finality, or a truthful global “latest” view. The separate checkpoint exercise
below demonstrates read-only HTTP exchange and signed head comparison, not those
network services. Content addressing proves that a packet matches its contents;
reachability proves graph connectivity within that packet. Neither proves that
the packet is complete or current.

## Checkpoint head observation (integration exercise)

`src/prf/network/dag/head_observation.clj` adds a deliberately small read-only
HTTP adapter for PRO-94. A source exposes `GET /head?nonce=...`,
`GET /checkpoints/{root}`, and `GET /checkpoints?since={root}`. The latter two
return immutable checkpoint/certificate/reconstruction packages from callbacks
provided by the host. The client sends a fresh random nonce to each head source;
the consumer fetches successor packages from a pinned checkpoint and reconstructs
them with PRF before passing authenticated observations to PRF's
`verify-observed-heads` API. This repo owns HTTP framing only; PRF owns canonical
validation, signatures, network/key binding, freshness, certified-history and
conflict checks. The transport does not accept writes, choose a fork or assert
global latestness. EDN responses are parsed without custom tagged readers and
all routes set `Cache-Control: no-store`.

The API is provided by the PRO-93 PRF checkpoint implementation. The dependency
is pinned to immutable commit `fa13bf6ec38d41db8b4d9b387ec9173d0c58a2ed` from
[draft PRF pull request #27](https://github.com/protocol-robustness/protocol-robustness-framework/pull/27).
This allows the demonstration and verifier-dependent tests to run from a public
checkout. The PR is awaiting review and merge, so treat this as a candidate
implementation until that review completes. After merge, update the pin to the
reviewed PRF revision.

```sh
clojure -M:test
clojure -M:head-demo
```

The second command creates a four-witness snapshot and two 2-of-4 certificates
for different successors of the same pinned genesis. It starts two loopback
HTTP source processes; each generates an ephemeral observation key and serves
one immutable successor package. The local coordinator receives each public
key at startup, pins it for this run, requests fresh nonce-bound heads, and
launches two additional fresh JVM verifier processes. Each verifier fetches,
reconstructs and certifies one history from the same pinned genesis; the
coordinator then reports `:conflicting` for the two signed heads. The key
exchange is demo bootstrapping, not an external trust ceremony. The threshold
does not meet the configured
intersection bound, so the certificates are not presented as Byzantine-safe.
The command writes a new EDN evidence bundle containing both checkpoint
packages, certificates, source public keys, signed observations, nonces and
verification results. It refuses to overwrite an existing bundle. Set
`PRF_CHECKPOINT_SOURCE_REVISION` and `PRF_CHECKPOINT_SOURCE_DIRTY` when running
the demo to retain the local PRF checkout's revision and dirty-state indicator
in the bundle. The source
processes and coordinator share one machine and operator, so this is not
evidence of administrative independence or a public network.

The tests also verify that POST is rejected, responses are not cached,
one stale source is enough to classify the observation as stale, replayed nonces
and expired/future observations do not count as current, and invalid signatures
or a wrong network identity fail verification. These checks run against the
exact PRF candidate commit above; the local adapter does not copy or approximate
the verifier. The optional local checkout override remains useful when changing
PRF source during development.

The host application supplies `start-source!` an observation provider that
signs the nonce and current checkpoint for each request. It separately
configures the verifier with pinned source IDs, public keys and independence
groups, plus a certified history reconstructed through PRF. The adapter
generates a distinct nonce per source, then passes both artifacts and nonce
bindings to `prf-verifier`. A matching result means only that the configured
sources freshly reported the same certified head.

This is an integration contract, not a deployed service. The source callbacks
must serve content-addressed immutable package bodies, and operators must retain
fetched observations, packages and conflict evidence if they need a forensic
record. The two source processes have separate ephemeral keys but share a host
and coordinator; they do not establish operator or infrastructure independence.
A source that is one checkpoint behind is stale relative to a separately
reconstructed newer head;
two valid equal-sequence successors of one parent remain `conflicting` with
both packages available for review. Even agreement from two configured sources
cannot exclude a newer checkpoint withheld from both.

## Guided checkpoint walkthrough

The [`prf-notebooks` checkpoint walkthrough](https://github.com/protocol-robustness/prf-notebooks/blob/network-checkpoint-walkthrough/notebooks/network_checkpoint_head_observation.clj)
guides you through running `-M:head-demo`, retaining its evidence bundle, and
inspecting the branch certificates, per-source observations, verifier outcomes
and evidence limits. It uses this repository's existing demo; it does not
reimplement checkpoint construction or verification.

Use a local PRF checkout that exposes the checkpoint API. From this repository,
run the following after setting `PRF_CHECKPOINT_SOURCE_ROOT` to that checkout:

```sh
export PRF_CHECKPOINT_SOURCE_REVISION="$(jj --repository "$PRF_CHECKPOINT_SOURCE_ROOT" log -r @ --no-graph -T 'commit_id')"
export PRF_CHECKPOINT_SOURCE_DIRTY=unknown
# For a Git checkout, use `git -C "$PRF_CHECKPOINT_SOURCE_ROOT" rev-parse HEAD`
# and record `git status --porcelain` separately if the worktree is dirty.
export PRF_NETWORK_DEMO_EVIDENCE="$PWD/target/head-observation-$(date -u +%Y%m%dT%H%M%SZ)-$$.edn"
mkdir -p target
clojure -Sdeps "{:deps {protocol-robustness/framework {:local/root \"$PRF_CHECKPOINT_SOURCE_ROOT\"}}}" \
  -M:head-demo "$PRF_NETWORK_DEMO_EVIDENCE"
```

Then start Clerk from a `prf-notebooks` checkout with the evidence path in the
environment:

```sh
PRF_NETWORK_DEMO_EVIDENCE="$PRF_NETWORK_DEMO_EVIDENCE" clojure -M:prf-host:serve
```

Open `http://localhost:7777/notebooks/network_checkpoint_head_observation.clj`.
The notebook parses and displays the saved bundle. It reports missing or
unreadable files instead of silently substituting fixture results.

## How to extend the exercise

1. Replace the illustrative membership map with a frozen, authenticated
   authority snapshot and test appointment/removal transitions.
2. Sign each attestation and independently verify keys against that snapshot.
3. Bind attestations to a canonical basis root covering workflow/claim identity,
   question, evidence and policy roots.
4. Add a signed ratification decision that names the exact basis and verifies it
   again at consumption.
5. Only then design a production transport and replication protocol. Specify fork handling,
   append authority, replay protection and how peers establish currentness before
   calling this a network-native DAG.

The PRF APIs in use are pinned in [`deps.edn`](deps.edn), rather than copied into
this repository. The local `prf-learning-*` envelope is deliberately namespaced
to avoid implying that it is an established canonical PRF schema.
