set shell := ["bash", "-cu"]

host_target := arch() + "-apple-darwin"
github_actions := env_var_or_default("GITHUB_ACTIONS", "")
publish_provenance := if github_actions == "true" { "--provenance" } else { "" }

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

bump version:
    npm version "{{ version }}" --no-git-tag-version --ignore-scripts
    node -e "const fs = require('node:fs'); \
        const version = require('./package.json').version; \
        const path = 'Cargo.toml'; \
        const cargo = fs.readFileSync(path, 'utf8'); \
        const updated = cargo.replace( \
          /^version = \"[^\"]+\"$/m, \
          'version = \"' + version + '\"', \
        ); \
        if (updated === cargo) { \
          throw new Error('Cargo.toml package version not found'); \
        } \
        fs.writeFileSync(path, updated);"
    cargo metadata --format-version 1 --no-deps >/dev/null

publish:
    node -e "const tag = process.env.GITHUB_REF_NAME; \
        const version = require('./package.json').version; \
        if (tag && tag !== 'v' + version) { \
          throw new Error('release tag must be v' + version); \
        }"
    npm ci --ignore-scripts
    if [[ "${GITHUB_ACTIONS:-}" == "true" ]]; then \
        just build-all; \
    fi
    npm publish --access public {{ publish_provenance }}

clean:
    rm -rf -- target node_modules index.js index.d.ts *.node *.tgz .DS_Store
