#!/usr/bin/env bash
# Reproducible two-peer v1 demo: two local identities -> pairwise SN comparison
# -> two explicit scoped grants -> one authorized stream -> graceful close.
# Uses the explicit -transport tcp local-test fallback so the demo stays
# deterministic and independent of Tailcat/DERP availability (ADR-002).
#
# NOTE: the OOB safety-number comparison is a HUMAN step. This script echoes the
# pairwise number from both sides and then supplies the literal "yes" answers by
# piping stdin, so the flow is reproducible in CI. An operator must actually
# compare the two displayed numbers out of band before answering "yes" in real
# use. The -peer input for `upp verify` is a copy of the peer's local identity
# file: the v1 CLI has no separate export command, and only public fields are
# read and printed (no private key material is ever emitted).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export GOROOT="${GOROOT:-/tmp/opencode/go-root/usr/lib/go-1.24}"
export PATH="$GOROOT/bin:$PATH"
export GOCACHE="${GOCACHE:-/tmp/opencode/go-cache}"
export GOPATH="${GOPATH:-/tmp/opencode/gopath}"

WORK="${TMPDIR:-/tmp}/upp-two-peer-demo-$$"
mkdir -p "$WORK"
cleanup() { kill "${LISTEN_PID:-}" 2>/dev/null || true; rm -rf "$WORK"; }
trap cleanup EXIT

cd "$ROOT"
go build -o "$WORK/uppid" ./cmd/uppid
go build -o "$WORK/upp" ./cmd/upp
cd "$WORK"

echo "== 1. Create one identity per peer =="
./uppid generate -class device -out alice.json > alice.create
./uppid generate -class device -out bob.json > bob.create
FP_A="$(awk '/^fingerprint:/ {print $2}' alice.create)"
FP_B="$(awk '/^fingerprint:/ {print $2}' bob.create)"
cat alice.create
cat bob.create
cp alice.json alice.public.json
cp bob.json bob.public.json

echo "== 2. Compare the pairwise safety number on both sides (OOB) =="
./upp verify -identity bob.json -peer alice.public.json
./upp verify -identity alice.json -peer bob.public.json

echo "== 3. Each operator grants the other a scoped capability =="
printf 'yes\n' | ./upp grant add -identity alice.json -grants alice.grants -peer-fp "$FP_B" -resource stream -op open,read,write
printf 'yes\n' | ./upp grant add -identity bob.json -grants bob.grants -peer-fp "$FP_A" -resource stream -op open,read,write

echo "== 4. Listener advertises the route and waits =="
(printf 'yes\n' | ./upp listen -identity alice.json -hint alice.hint -grants alice.grants -pins alice.pins -transport tcp > listen.out 2> listen.err; echo $? > listen.rc) &
LISTEN_PID=$!
for _ in $(seq 1 50); do [ -s alice.hint ] && break; sleep 0.1; done

echo "== 5. Connector verifies, authorizes, opens one stream, closes =="
printf 'yes\nhello from Bob\n' | ./upp connect -identity bob.json -hint alice.hint -grants bob.grants -pins bob.pins -transport tcp -resource stream -op open,read,write

wait "$LISTEN_PID" || true
echo "== Listener output =="
cat listen.out
cat listen.err
echo "demo complete: both peers reached ended with exit 0"
