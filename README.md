# cl-frpc

An **[frp](https://github.com/fatedier/frp) reverse-proxy client in pure Common Lisp** —
give a machine behind NAT a public endpoint through an frp relay (`frps`), like a
self-hosted ngrok. No FFI: TLS is [`seal`](https://github.com/modus-lisp/seal), not
OpenSSL.

It implements the frp **v0 control protocol** (1-byte type + 8-byte length + JSON body),
token auth (`privilege_key = md5(token + unix_ts)`), 30s heartbeats, **yamux**
multiplexing (frp's `transport.tcpMux` default), and AES-128-CFB wire encryption. Its one
outbound connection is a [`cl-transport`](https://github.com/modus-lisp/cl-transport)
`dial`, so the tunnel itself can run **direct / SOCKS5 / Tor**.

Verified end-to-end against a **real, unmodified frps 0.61.1** (see `test/live-echo.sh`):
seal-TLS handshake, login, `NewProxy`, and a byte round-trip through a live tunnel.

## Use

### As a cl-transport inbound backend (uniform `expose`)

`cl-frpc` registers `:frp` with cl-transport's inbound registry, so it mirrors `dial`:

```lisp
(ql:quickload "cl-frpc")

;; expose a handler: every inbound connection to the public tcp port 6000 on the frps
;; server is delivered to ON-CONNECTION as (stream peer).
(cl-transport:expose
  (lambda (stream peer)
    (declare (ignore peer))
    (loop for b = (read-byte stream nil :eof) until (eq b :eof)
          do (write-byte b stream) (force-output stream)))   ; echo
  :backend :frp :server "frps.example.com" :port 7000 :token "…"
  :proxy-type "tcp" :remote-port 6000 :tls t)
;; => a zero-arg closer thunk; the tunnel is supervised (auto-reconnect) by default.
```

### Bridging to a local backend (classic tunnel)

```lisp
(cl-frpc:run :host "frps.example.com" :port 7000 :token "…"
             :proxy-type "tcp" :remote-port 6000
             :local-host "127.0.0.1" :local-port 8080)   ; blocks
```

HTTP/HTTPS proxies work too (`:proxy-type "http" :subdomain "myapp"` /
`:custom-domains '("app.example.com")`).

## Layout

```
src/yamux.lisp     hashicorp/yamux client (framing, flow control, streams)
src/frpc.lisp      frp v0 protocol, auth, wire crypto, work-conns, RUN
src/backend.lisp   EXPOSE + registers :frp with cl-transport
test/offline-test  unit gate (framing, auth, AES-CFB, registration) — no network
test/live-echo.sh  live integration test against a real frps
```

MIT.
