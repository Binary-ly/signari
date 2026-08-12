# Vanity import path

`index.html` must be served at `https://signari.dev/` **and at every path under it**,
because the go command asks for the full import path first:

```
GET https://signari.dev/engine?go-get=1
```

## Caddy

```caddyfile
signari.dev {
    root * /srv/vanity
    try_files {path} /index.html      # catch-all: every path gets the meta tag
    file_server
}
```

## nginx

```nginx
location / { try_files $uri /index.html; }
```

## Verify before announcing anything

```sh
curl -s "https://signari.dev/engine?go-get=1" | grep go-import
GOPROXY=direct GOFLAGS=-mod=mod go install signari.dev/engine/cmd/signari@latest
```

The second command is the real test — it is what a stranger runs. Once
proxy.golang.org has cached a version, the domain being briefly down no longer
breaks `go get`, but the FIRST resolution needs it reachable.

## Moving the code later

Edit the repo URL in `index.html`. Nothing else changes, and no downstream import
path breaks — which is the whole point of not using a GitHub path.
