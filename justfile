set shell := ["zsh", "-cu"]

host_target := `cargo -vV | sed -n 's/^host: //p'`

build:
    ./node_modules/.bin/napi build --release --platform --esm --target {{host_target}}

test: build
    npm test

check:
    npm run check

clean:
    cargo clean
