.PHONY: build test clean

APPNAME := dynamodb-encryption-example

# The go compiler to use
GO := go

DIR := example

build:
	cd $(DIR) && $(GO) build -o ../$(APPNAME)

test:
	cd $(DIR) && $(GO) test -v ./...

clean:
	rm -f $(APPNAME)

run: build
	./$(APPNAME)
