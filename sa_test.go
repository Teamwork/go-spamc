// +build testsa

package spamc

import (
	"context"
	"io/ioutil"
	"os"
	"strings"
	"testing"
)

var addr = os.Getenv("SPAMC_SA_ADDRESS")

func TestSAPing(t *testing.T) {
	client := New(TCPDialer(addr))
	err := client.Ping(context.Background())
	if err != nil {
		t.Fatal(err)
	}
}

func TestSACheck(t *testing.T) {
	client := New(TCPDialer(addr))
	r, err := client.Check(context.Background(), strings.NewReader("\r\nPenis viagra\r\n"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if r == nil {
		t.Fatal("r is nil")
	}
	if r.Score < 5 {
		t.Errorf("score lower than 5: %#v", r)
	}
}

func TestSASymbols(t *testing.T) {
	client := New(TCPDialer(addr))
	r, err := client.Symbols(context.Background(), strings.NewReader(""+
		"Date: now\r\n"+
		"From: invalid\r\n"+
		"Subject: Hello\r\n"+
		"Message-ID: <serverfoo2131645635@example.com>\r\n"+
		"\r\n\r\nthe body penis viagra\r\n"+
		""), nil)
	if err != nil {
		t.Fatal(err)
	}
	if r == nil {
		t.Fatal("r is nil")
	}
	if r.Score < 3 {
		t.Errorf("score lower than 3: %#v", r)
	}
}

func TestSAReport(t *testing.T) {
	client := New(TCPDialer(addr))
	r, err := client.Report(context.Background(), strings.NewReader(""+
		"Date: now\r\n"+
		"From: a@example.com\r\n"+
		"Subject: Hello\r\n"+
		"Message-ID: <serverfoo2131645635@example.com>\r\n"+
		"\r\n\r\nthe body"+
		""), nil)
	if err != nil {
		t.Fatal(err)
	}
	if r == nil {
		t.Fatal("r is nil")
	}

	if len(r.Report.Table) < 2 {
		t.Error("report table unexpectedly short")
	}
}

func TestSAProcess(t *testing.T) {
	client := New(TCPDialer(addr))
	r, err := client.Process(context.Background(), strings.NewReader(""+
		"Date: now\r\n"+
		"From: a@example.com\r\n"+
		"Subject: Hello\r\n"+
		"Message-ID: <serverfoo2131645635@example.com>\r\n"+
		"\r\n\r\nthe body"+
		""), nil)
	if err != nil {
		t.Fatal(err)
	}
	if r == nil {
		t.Fatal("r is nil")
	}
	defer r.Message.Close() // nolint: errcheck

	b, err := ioutil.ReadAll(r.Message)
	if err != nil {
		t.Fatal(err)
	}
	m := string(b)

	if !strings.Contains(m, "X-Spam-Status: ") {
		t.Errorf("message did not have X-Spam-Status: %#v", m)
	}
	if !strings.Contains(m, "Subject: Hello\r\n") {
		t.Errorf("message did not have the subject: %#v", m)
	}
	if !strings.Contains(m, "the body") {
		t.Errorf("message did not have the body: %#v", m)
	}
}

func TestSAHeaders(t *testing.T) {
	client := New(TCPDialer(addr))
	r, err := client.Headers(context.Background(), strings.NewReader(""+
		"Date: now\r\n"+
		"From: a@example.com\r\n"+
		"Subject: Hello\r\n"+
		"Message-ID: <serverfoo2131645635@example.com>\r\n"+
		"\r\n\r\nthe body"+
		""), nil)
	if err != nil {
		t.Fatal(err)
	}
	if r == nil {
		t.Fatal("r is nil")
	}
	defer r.Message.Close() // nolint: errcheck

	b, err := ioutil.ReadAll(r.Message)
	if err != nil {
		t.Fatal(err)
	}
	m := string(b)

	if !strings.Contains(m, "X-Spam-Status: ") {
		t.Errorf("message did not have X-Spam-Status: %#v", m)
	}
	if !strings.Contains(m, "Subject: Hello\r\n") {
		t.Errorf("message did not have the subject: %#v", m)
	}
	if strings.Contains(m, "the body") {
		t.Errorf("message did have the body: %#v", m)
	}
}

func TestSATell(t *testing.T) {
	client := New(TCPDialer(addr))
	message := strings.NewReader("Subject: Hello, world!\r\n\r\nTest message.\r\n")
	r, err := client.Tell(context.Background(), message, Header{}.
		Set("Message-class", "spam").
		Set("set", "remote"))
	if err != nil {
		t.Fatal(err)
	}
	if r == nil {
		t.Fatal("r is nil")
	}

	//if r.DidSet[0] != "remote" {
	//	t.Errorf("DidSet wrong: %#v", r.DidSet)
	//}
	//if len(r.DidRemove) != 0 {
	//	t.Errorf("DidRemove wrong: %#v", r.DidSet)
	//}
}

// Make sure SA works when we send the message without trailing newline.
func TestSANoTrailingNewline(t *testing.T) {
	client := New(TCPDialer(addr))

	r, err := client.Check(context.Background(), strings.NewReader("woot"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if r == nil {
		t.Fatal("r is nil")
	}

	r, err = client.Check(context.Background(), strings.NewReader("Subject: woot\r\n\r\nwoot"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if r == nil {
		t.Fatal("r is nil")
	}
}
