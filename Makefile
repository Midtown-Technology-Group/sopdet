BINARY  := sopdet
VERSION ?= 0.1.0-dev
LDFLAGS := -s -w -X main.Version=$(VERSION)
DIST    := dist

.PHONY: build cross test vet fmt clean sign-public sign-private publish-public publish-private

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/$(BINARY)

cross:
	GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY)-windows-amd64.exe ./cmd/$(BINARY)
	GOOS=windows GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY)-windows-arm64.exe ./cmd/$(BINARY)
	GOOS=linux   GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY)-linux-amd64 ./cmd/$(BINARY)
	GOOS=linux   GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY)-linux-arm64 ./cmd/$(BINARY)
	GOOS=darwin  GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY)-darwin-arm64 ./cmd/$(BINARY)

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

clean:
	rm -rf bin

# --- signing and publishing -------------------------------------------------
# Runs on a Windows signing host with Azure Artifact Signing configured
# (see scripts/artifact-signing.env.example). Public Trust -> assessment tier,
# Private Trust -> internal fleet tier.

sign-public: cross
	@mkdir -p $(DIST)/signed-public
	pwsh -NoProfile -File scripts/sign-artifacts.ps1 -Profile Public \
		-File bin/sopdet-windows-amd64.exe -File bin/sopdet-windows-arm64.exe \
		-OutDir $(DIST)/signed-public

sign-private: cross
	@mkdir -p $(DIST)/signed-private
	pwsh -NoProfile -File scripts/sign-artifacts.ps1 -Profile Private \
		-File bin/sopdet-windows-amd64.exe -File bin/sopdet-windows-arm64.exe \
		-OutDir $(DIST)/signed-private

publish-public: cross
	bash scripts/publish.sh public $(DIST)/signed-public

publish-private: sign-private
	bash scripts/publish.sh private $(DIST)/signed-private
