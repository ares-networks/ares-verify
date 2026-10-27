GO      ?= go
VERSION ?= dev
LDFLAGS := -s -w -buildid= -X main.version=$(VERSION)
SHA256  := $(shell command -v sha256sum >/dev/null 2>&1 && echo sha256sum || echo shasum -a 256)
FLAGS   := -trimpath -buildvcs=false -ldflags "$(LDFLAGS)"

.PHONY: build test vet fmt-check smoke gate ci dist fixtures repro clean

build:
	CGO_ENABLED=0 $(GO) build $(FLAGS) -o bin/ares-verify ./cmd/ares-verify

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

fmt-check:
	@test -z "$$(gofmt -l .)" || { gofmt -l .; echo "gofmt needed"; exit 1; }

# CLI smoke: committed fixtures exit as expected.
smoke:
	CGO_ENABLED=0 $(GO) build $(FLAGS) -o bin/smoke/ares-verify ./cmd/ares-verify
	@for f in valid hashes-only; do bin/smoke/ares-verify testdata/$$f.zip >/dev/null || { echo "$$f should pass"; exit 1; }; done
	@for f in tampered-record dropped-record missing-endorsement swapped-party-cert; do 	  if bin/smoke/ares-verify testdata/$$f.zip >/dev/null; then echo "$$f should fail"; exit 1; fi; done
	@echo "smoke: ok"

gate:
	./scripts/public-gate.sh

ci: fmt-check vet test smoke repro gate

# Release binaries + SHA256SUMS into dist/ (same flags as build, so reproducible).
PLATFORMS := darwin/amd64 darwin/arm64 linux/amd64 linux/arm64 windows/amd64 windows/arm64
dist:
	rm -rf dist && mkdir -p dist
	@for p in $(PLATFORMS); do 	  os=$${p%/*}; arch=$${p#*/}; ext=$$( [ $$os = windows ] && echo .exe ); 	  out=dist/ares-verify-$(VERSION)-$$os-$$arch$$ext; 	  CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch $(GO) build $(FLAGS) -o $$out ./cmd/ares-verify || exit 1; 	done
	cd dist && $(SHA256) ares-verify-* > SHA256SUMS && cat SHA256SUMS

# Regenerate testdata/*.zip (new keys each run; commit the result).
fixtures:
	$(GO) run ./cmd/gen-fixtures -out testdata

# Build twice into separate dirs and compare: the binary must be bit-for-bit reproducible.
repro:
	CGO_ENABLED=0 $(GO) build $(FLAGS) -o bin/repro-a/ares-verify ./cmd/ares-verify
	CGO_ENABLED=0 $(GO) build $(FLAGS) -o bin/repro-b/ares-verify ./cmd/ares-verify
	@a=$$($(SHA256) bin/repro-a/ares-verify | cut -d' ' -f1); \
	 b=$$($(SHA256) bin/repro-b/ares-verify | cut -d' ' -f1); \
	 echo "$$a"; echo "$$b"; test "$$a" = "$$b"

clean:
	rm -rf bin dist
