[![GoDoc](https://godoc.org/github.com/Teamwork/spamc?status.svg)](https://teamwork.github.io/spamc/)
[![Build Status](https://travis-ci.org/Teamwork/spamc.svg?branch=master)](https://travis-ci.org/Teamwork/spamc)
[![codecov](https://codecov.io/gh/Teamwork/spamc/branch/master/graph/badge.svg?token=n0k8YjbQOL)](https://codecov.io/gh/Teamwork/spamc)

spamc is a Go client library for SpamAssassin's spamd daemon.

It started out as a fork of saintienn/go-spamc with some fixes, but has since
been completely rewritten.

Basic example:

```go
// Connect
c := New(TCPDialer("127.0.0.1:783"))
ctx := context.Background()

msg := strings.NewReader("Subject: Hello\r\n\r\nHey there!\r\n")

// Check if a message is spam.
check, err := c.Check(ctx, msg, nil)
if err != nil {
    log.Fatal(err)
}
fmt.Println(check.Score)

// Report ham for training.
tell, err := c.Tell(ctx, msg, Header{}.
    Set("Message-class", "ham").
    Set("Set", "local"))
if err != nil {
    log.Fatal(err)
}
fmt.Println(tell)
```

See godoc for the full documentation.

Runnings tests
--------------

Use `./bin/test` to run all tests; use `./bin/test -b testsa` to run tests that
require a running SpamAssassin instance. This will automatically run SA in a
Docker container. You can also use the `SPAMC_SA_ADDRESS` to set the SA address.
