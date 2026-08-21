.PHONY: build lint

build:
	task build
	task app:build

lint:
	gavel lint golangci-lint
	betterleaks dir .agents app cmd config contract hack internal inventory templates .gavel.yaml .gitignore .gitmodules README.md Taskfile.yaml Makefile THIRD_PARTY_NOTICES.md embed.go go.mod go.sum --redact --no-banner
	task app:lint
