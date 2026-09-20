set shell := ["bash", "-cu"]

host_target := `cargo -vV | sed -n 's/^host: //p'`

build:
    ./node_modules/.bin/napi build --release --platform --esm --target {{host_target}}

build-all:
    ./node_modules/.bin/napi build --release --platform --esm --target aarch64-apple-darwin
    ./node_modules/.bin/napi build --release --platform --esm --target x86_64-apple-darwin

test: build
    npm test

check:
    npm run check

release-check:
    npm run release:check

pack: release-check
    npm pack --ignore-scripts

clean:
    cargo clean
