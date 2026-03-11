# LLM.md - Hanzo Krakend

## Overview
Go module: github.com/krakend/krakend-ce/v2

## Tech Stack
- **Language**: Go

## Build & Run
```bash
go build ./...
go test ./...
```

## Structure
```
krakend/
  Dockerfile
  Dockerfile-builder
  Dockerfile-builder-linux
  LICENSE
  Makefile
  README.md
  SECURITY.md
  backend_factory.go
  builder/
  cmd/
  deps.sh
  encoding.go
  executor.go
  find_glibc.sh
  go.mod
```

## Key Files
- `README.md` -- Project documentation
- `go.mod` -- Go module definition
- `Makefile` -- Build automation
- `Dockerfile` -- Container build
