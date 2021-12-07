# ethhelpers

`ethhelpers` is a simple CLI tool that does a bunch of random useful stuff related to developing
on EVM chains.

For example:

* Generate public/private keypairs for testing, with the option to encrypt the private key using AES.
* Encode / Decode EVM function calls.
* More random stuff as it comes up.

## Installing

Should be as simple as:

```
go install github.com/makramkd/ethhelpers
```

Or if you don't want to pollute your Go binary path with another executable, you can just clone and build it using `go build`.
