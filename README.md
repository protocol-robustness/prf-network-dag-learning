# PRF Network DAG Learning Example

A small, executable learning repo showing how PRF evidence nodes can be packaged
as a network-scoped, forkable DAG and checked independently by two local replicas.

This is a teaching example. It is not a PRF network protocol, canonical PRF
schema, consensus implementation, or production ratification service. “Replica”
here means a second local verifier given the same packet and a separately
configured trusted network root. It does not mean peers exchanged data or agreed
on the globally current graph.

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

The example also does not provide peer discovery, transport, durable replicated
storage, fork choice, append authorization, equivocation handling, ordering,
finality, or a truthful global “latest” view. Content addressing proves that a
packet matches its contents; reachability proves graph connectivity within that
packet. Neither proves that the packet is complete or current.

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

The API is provided by the PRO-93/94 PRF checkpoint implementation. The default
published dependency revision currently predates it, so default tests cover
transport framing; use the local PRF checkout override below to exercise signed
observation verification and conflict classification against the implementation:

```sh
clojure -Sdeps '{:deps {protocol-robustness/framework {:local/root "/path/to/agent-c-2"}}}' -M:test
clojure -Sdeps '{:deps {protocol-robustness/framework {:local/root "/path/to/agent-c-2"}}}' -M:head-demo
```

The second command creates a four-witness snapshot and two 2-of-4 certificates
for different successors of the same pinned genesis. It starts two loopback
HTTP sources with separate ephemeral observation keys, requests fresh
nonce-bound heads, and launches two fresh JVM verifier processes. Each fetches,
reconstructs and certifies one history from the same pinned genesis; the
coordinator then reports `:conflicting` for the two signed heads. The threshold
does not meet the configured
intersection bound, so the certificates are not presented as Byzantine-safe.
The command writes a new EDN evidence bundle containing both checkpoint
packages, certificates, source public keys, signed observations, nonces and
verification results. It refuses to overwrite an existing bundle. Record the exact PRF revision used for each local run alongside the evidence bundle. These local endpoints share one machine
and JVM, so this is not evidence of independent operators or a public network.

The project must pin a published, reviewed PRF revision exposing
`resolver-sim.network.checkpoint/verify-observed-heads` before the end-to-end
signed-observation test runs from the default public dependency. The local
adapter does not copy or approximate that verifier.

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
record. Two localhost processes are useful for the mechanics test but do not
establish operator or infrastructure independence. A source that is one
checkpoint behind is stale relative to a separately reconstructed newer head;
two valid equal-sequence successors of one parent remain `conflicting` with
both packages available for review. Even agreement from two configured sources
cannot exclude a newer checkpoint withheld from both.

## How to extend the exercise

1. Replace the illustrative membership map with a frozen, authenticated
   authority snapshot and test appointment/removal transitions.
2. Sign each attestation and independently verify keys against that snapshot.
3. Bind attestations to a canonical basis root covering workflow/claim identity,
   question, evidence and policy roots.
4. Add a signed ratification decision that names the exact basis and verifies it
   again at consumption.
5. Only then design a transport and replication protocol. Specify fork handling,
   append authority, replay protection and how peers establish currentness before
   calling this a network-native DAG.

The PRF APIs in use are pinned in [`deps.edn`](deps.edn), rather than copied into
this repository. The local `prf-learning-*` envelope is deliberately namespaced
to avoid implying that it is an established canonical PRF schema.
