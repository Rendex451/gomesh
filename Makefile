BIN := bin/gomesh
 
.PHONY: build test bench lab-config lab-up lab-down wg-up wg-bench wg-down
 
build:
	go build -o $(BIN) ./cmd/gomesh
 
test:
	go test -race ./...
 
bench:
	go test -run='^$$' -bench=. -benchmem ./...
 
lab-config: build
	./scripts/gen-lab-config.sh
 
lab-up:
	./scripts/lab-up.sh
 
lab-down:
	./scripts/lab-down.sh
 
wg-up:
	./scripts/wg-baseline.sh up
 
wg-bench:
	./scripts/wg-baseline.sh bench
 
wg-down:
	./scripts/wg-baseline.sh down
