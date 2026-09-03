NAME := reconctl
RELEASE_DIR := .release

.PHONY: build lint release

build:
	task build
	task app:build

lint:
	task gen:ocsf:check
	gavel lint golangci-lint
	betterleaks dir .agents app cmd config contract hack internal inventory templates .gavel.yaml .gitignore .gitmodules README.md Taskfile.yaml Makefile THIRD_PARTY_NOTICES.md embed.go go.mod go.sum --redact --no-banner
	task app:lint

release:
	task app:build
	rm -rf $(RELEASE_DIR)
	mkdir -p $(RELEASE_DIR)
	@set -eu; \
	for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64; do \
		os=$${target%/*}; \
		arch=$${target#*/}; \
		artifact="$(NAME)-$$os-$$arch"; \
		binary="$(RELEASE_DIR)/$(NAME)"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -o "$$binary" ./cmd/reconctl; \
		(cd $(RELEASE_DIR) && tar czf "$$artifact.tar.gz" "$(NAME)"); \
		rm "$$binary"; \
	done
	@cd $(RELEASE_DIR) && sha256sum *.tar.gz > checksums.txt
