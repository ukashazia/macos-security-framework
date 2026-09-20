set shell := ["bash", "-cu"]

host_target := arch() + "-apple-darwin"

build:
    ./node_modules/.bin/napi build --release --platform --esm --target {{ host_target }}

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

publish:
    node -e "const version = require('./package.json').version; if (process.env.GITHUB_REF_NAME !== 'v' + version) throw new Error('release tag must be v' + version)"
    npm ci --ignore-scripts
    just build-all
    npm publish --access public --provenance

clean:
    cargo clean
