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
    node scripts/bump-version.mjs "{{ version }}"

publish:
    npm ci --ignore-scripts
    npm run verify:version
    if [[ "${GITHUB_ACTIONS:-}" == "true" ]]; then \
        just build-all; \
    fi
    npm publish --access public {{ publish_provenance }}

clean:
    rm -rf -- target node_modules index.js index.d.ts *.node *.tgz .DS_Store
