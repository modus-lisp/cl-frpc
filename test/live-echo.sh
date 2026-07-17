#!/usr/bin/env bash
# test/live-echo.sh — LIVE integration test against a real frps.
#
# Downloads the frp release (if not cached), starts frps with a token, then runs
# test/live-echo.lisp which exposes an echo handler via :frp and connects through the
# public port to verify a byte round-trip through the tunnel.  Needs: network (first run),
# sbcl + Quicklisp, and cl-frpc on the ASDF path.
set -u
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
work="${TMPDIR:-/tmp}/cl-frpc-live"
mkdir -p "$work"
ver=0.61.1
tgz="$work/frp_${ver}_linux_amd64.tar.gz"
dir="$work/frp_${ver}_linux_amd64"
if [ ! -x "$dir/frps" ]; then
  echo "== fetching frp $ver =="
  curl -fsSL -o "$tgz" \
    "https://github.com/fatedier/frp/releases/download/v${ver}/frp_${ver}_linux_amd64.tar.gz" || {
      echo "download failed (no network?) — skipping live test"; exit 0; }
  tar xzf "$tgz" -C "$work"
fi
cat > "$work/frps.toml" <<'TOML'
bindPort = 7000
auth.method = "token"
auth.token = "testtoken"
log.to = "console"
log.level = "info"
TOML
pkill -x frps 2>/dev/null; sleep 1
"$dir/frps" -c "$work/frps.toml" > "$work/frps.log" 2>&1 &
frps=$!
sleep 2
echo "== running tunnel echo through cl-frpc =="
: "${CL_SOURCE_REGISTRY:=(:source-registry (:tree \"$here/../..\") :inherit-configuration)}"
export CL_SOURCE_REGISTRY
sbcl --dynamic-space-size 2048 --non-interactive --load "$here/live-echo.lisp" 2>&1 | grep -aE '@@|\[cl-frpc\]'
rc=${PIPESTATUS[0]}
pkill -x frps 2>/dev/null
echo "== frps saw =="; grep -aoE 'new proxy .* success|get a user connection' "$work/frps.log" | tail -2
exit "$rc"
