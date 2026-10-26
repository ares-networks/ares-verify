GO      ?= go
VERSION ?= dev
LDFLAGS := -s -w -buildid= -X main.version=$(VERSION)
FLAGS   := -trimpath -buildvcs=false -ldflags "$(LDFLAGS)"

.PHONY: build test vet fixtures repro clean

build:
	CGO_ENABLED=0 $(GO) build $(FLAGS) -o bin/ares-verify ./cmd/ares-verify

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

# Regenerate testdata/*.zip (new keys each run; commit the result).
fixtures:
	$(GO) run ./cmd/gen-fixtures -out testdata

# Build twice into separate dirs and compare: the binary must be bit-for-bit reproducible.
repro:
	CGO_ENABLED=0 $(GO) build $(FLAGS) -o bin/repro-a/ares-verify ./cmd/ares-verify
	CGO_ENABLED=0 $(GO) build $(FLAGS) -o bin/repro-b/ares-verify ./cmd/ares-verify
	@a=$$(shasum -a 256 bin/repro-a/ares-verify | cut -d' ' -f1); \
	 b=$$(shasum -a 256 bin/repro-b/ares-verify | cut -d' ' -f1); \
	 echo "$$a"; echo "$$b"; test "$$a" = "$$b"

clean:
	rm -rf bin dist
