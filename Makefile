ENTRY := ./cmd/web/main.go
BINARY := app

build:
	go build -o $(BINARY) $(ENTRY)

clean:
	rm -f $(BINARY)

