set shell := ["bash", "-cu"]

host_target := arch() + "-apple-darwin"
publish_provenance := if env_var_or_default("GITHUB_ACTIONS", "") == "true" { "--provenance" } else { "" }

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
    node -e "const tag = process.env.GITHUB_REF_NAME; const version = require('./package.json').version; if (tag && tag !== 'v' + version) throw new Error('release tag must be v' + version)"
    npm ci --ignore-scripts
    if [[ "${GITHUB_ACTIONS:-}" == "true" ]]; then just build-all; fi
    npm publish --access public {{ publish_provenance }}

clean:
    cargo clean
