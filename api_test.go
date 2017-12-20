package spamc

import (
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"reflect"
	"strings"
	"testing"

	"github.com/teamwork/test"
	"github.com/teamwork/test/fakeconn"
)

func TestPing(t *testing.T) {
	cases := []struct {
		in, wantErr string
	}{
		{"SPAMD/1.5 0 PONG\r\n", ""},
		{"SPAMD/1.5 1 error\r\n", "spamd returned code 1"},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%v", i), func(t *testing.T) {
			err := newClient(tc.in).Ping(context.Background())
			if !test.ErrorContains(err, tc.wantErr) {
				t.Errorf("wrong error\nout:  %#v\nwant: %#v\n", err, tc.wantErr)
			}
		})
	}
}

func TestCheck(t *testing.T) {
	cases := []struct {
		in      string
		want    *ResponseCheck
		wantErr string
	}{
		{
			"SPAMD/1.1 0 EX_OK\r\nSpam: yes; 6.42 / 5.0\r\n\r\n",
			&ResponseCheck{
				ResponseScore: ResponseScore{
					IsSpam:    true,
					Score:     6.42,
					BaseScore: 5,
				},
			},
			"",
		},
		{
			"SPAMD/1.1 0 EX_OK\r\nSpam: no; -2.0 / 5.0\r\n\r\n",
			&ResponseCheck{
				ResponseScore: ResponseScore{
					IsSpam:    false,
					Score:     -2.0,
					BaseScore: 5,
				},
			},
			"",
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%v", i), func(t *testing.T) {
			out, err := newClient(tc.in).
				Check(context.Background(), strings.NewReader("A message"), nil)

			if !test.ErrorContains(err, tc.wantErr) {
				t.Errorf("wrong error\nout:  %#v\nwant: %#v\n", err, tc.wantErr)
			}
			if !reflect.DeepEqual(out, tc.want) {
				t.Errorf("\nout:  %#v\nwant: %#v\n", out, tc.want)
			}
		})
	}
}

func TestSymbols(t *testing.T) {
	cases := []struct {
		in      string
		want    *ResponseSymbols
		wantErr string
	}{
		{
			"SPAMD/1.1 0 EX_OK\r\n" +
				"Content-length: 50\r\n" +
				"Spam: False ; 1.6 / 5.0\r\n" +
				"\r\n" +
				"INVALID_DATE,MISSING_HEADERS,NO_RECEIVED,NO_RELAYS\r\n",
			&ResponseSymbols{
				ResponseScore: ResponseScore{
					IsSpam:    false,
					Score:     1.6,
					BaseScore: 5.0,
				},
				Symbols: []string{"INVALID_DATE", "MISSING_HEADERS", "NO_RECEIVED", "NO_RELAYS"},
			},
			"",
		},
		{
			"SPAMD/1.1 0 EX_OK\r\n" +
				"Content-length: 50\r\n" +
				"Spam: False ; 1.6 / 5.0\r\n" +
				"\r\n" +
				"\r\n",
			&ResponseSymbols{
				ResponseScore: ResponseScore{
					IsSpam:    false,
					Score:     1.6,
					BaseScore: 5.0,
				},
				Symbols: *new([]string),
			},
			"",
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%v", i), func(t *testing.T) {
			out, err := newClient(tc.in).
				Symbols(context.Background(), strings.NewReader("A message"), nil)

			if !test.ErrorContains(err, tc.wantErr) {
				t.Errorf("wrong error\nout:  %#v\nwant: %#v\n", err, tc.wantErr)
			}
			if !reflect.DeepEqual(out, tc.want) {
				t.Errorf("\nout:  %#v\nwant: %#v\n", out, tc.want)
			}
		})
	}
}

func TestReport(t *testing.T) {
	cases := []struct {
		in      string
		want    *ResponseReport
		wantErr string
	}{
		{
			strings.Replace(normalizeSpace(`
				SPAMD/1.1 0 EX_OK
				Content-length: 50
				Spam: False ; 1.6 / 5.0

				Spam detection software, running on the system "d311d8df23f8",
				has NOT identified this incoming email as spam.

				Content preview:  the body [...]

				Content analysis details:   (1.6 points, 5.0 required)

				 pts rule name              description
				---- ---------------------- --------------------------------------------------
				 0.4 INVALID_DATE           Invalid Date: header (not RFC 2822)
				-0.0 NO_RELAYS              Informational: message was not relayed via SMTP
				-1.2 MISSING_HEADERS        Missing To: header
			`), "\n", "\r\n", -1),
			&ResponseReport{
				ResponseScore: ResponseScore{
					IsSpam:    false,
					Score:     1.6,
					BaseScore: 5.0,
				},
				Report: Report{
					Intro: normalizeSpace(`
					Spam detection software, running on the system "d311d8df23f8",
					has NOT identified this incoming email as spam.

					Content preview:  the body [...]

					Content analysis details:   (1.6 points, 5.0 required)
				`),
					Table: []struct {
						Points      float64
						Rule        string
						Description string
					}{
						{
							Points:      0.4,
							Rule:        "INVALID_DATE",
							Description: "Invalid Date: header (not RFC 2822)",
						},
						{
							Points:      0.0,
							Rule:        "NO_RELAYS",
							Description: "Informational: message was not relayed via SMTP",
						},
						{
							Points:      -1.2,
							Rule:        "MISSING_HEADERS",
							Description: "Missing To: header",
						},
					},
				},
			},
			"",
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%v", i), func(t *testing.T) {
			c := newClient(tc.in)

			out, err := c.Report(context.Background(), strings.NewReader("A message"), nil)
			if !test.ErrorContains(err, tc.wantErr) {
				t.Errorf("wrong error\nout:  %#v\nwant: %#v\n", err, tc.wantErr)
			}
			if !reflect.DeepEqual(out, tc.want) {
				t.Errorf("\nout:  %#v\nwant: %#v\n", out, tc.want)
			}
		})
	}
}

func TestProcess(t *testing.T) {
	cases := []struct {
		in      string
		want    *ResponseProcess
		wantMsg string
		wantErr string
	}{
		{
			strings.Replace(normalizeSpace(`
				SPAMD/1.1 0 EX_OK
				Content-length: 50
				Spam: False ; 1.6 / 5.0

				Subject: foo
				X-Spam: yes

				asd
			`), "\n", "\r\n", -1),
			&ResponseProcess{
				ResponseScore: ResponseScore{
					IsSpam:    false,
					Score:     1.6,
					BaseScore: 5.0,
				},
			},
			"Subject: foo\r\nX-Spam: yes\r\n\r\nasd",
			"",
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%v", i), func(t *testing.T) {
			out, err := newClient(tc.in).
				Process(context.Background(), strings.NewReader("A message"), nil)

			if !test.ErrorContains(err, tc.wantErr) {
				t.Errorf("wrong error\nout:  %#v\nwant: %#v\n", err, tc.wantErr)
			}

			b, err := ioutil.ReadAll(out.Message)
			msg := string(b)
			_ = out.Message.Close()
			out.Message = nil
			if err != nil {
				t.Fatal(err)
			}

			if msg != tc.wantMsg {
				t.Errorf("message wrong\nout:  %#v\nwant: %#v\n", msg, tc.wantMsg)
			}

			if !reflect.DeepEqual(out, tc.want) {
				t.Errorf("\nout:  %#v\nwant: %#v\n", out, tc.want)
			}

		})
	}
}

func TestHeaders(t *testing.T) {
	cases := []struct {
		in      string
		want    *ResponseProcess
		wantMsg string
		wantErr string
	}{
		{
			strings.Replace(normalizeSpace(`
				SPAMD/1.1 0 EX_OK
				Content-length: 50
				Spam: False ; 1.6 / 5.0

				Subject: foo
				X-Spam: yes
			`), "\n", "\r\n", -1),
			&ResponseProcess{
				ResponseScore: ResponseScore{
					IsSpam:    false,
					Score:     1.6,
					BaseScore: 5.0,
				},
			},
			"Subject: foo\r\nX-Spam: yes",
			"",
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%v", i), func(t *testing.T) {
			out, err := newClient(tc.in).
				Headers(context.Background(), strings.NewReader("A message"), nil)

			if !test.ErrorContains(err, tc.wantErr) {
				t.Errorf("wrong error\nout:  %#v\nwant: %#v\n", err, tc.wantErr)
			}

			b, err := ioutil.ReadAll(out.Message)
			msg := string(b)
			_ = out.Message.Close()
			out.Message = nil
			if err != nil {
				t.Fatal(err)
			}

			if msg != tc.wantMsg {
				t.Errorf("message wrong\nout:  %#v\nwant: %#v\n", msg, tc.wantMsg)
			}

			if !reflect.DeepEqual(out, tc.want) {
				t.Errorf("\nout:  %#v\nwant: %#v\n", out, tc.want)
			}

		})
	}
}

func TestTell(t *testing.T) {
	cases := []struct {
		in      string
		want    *ResponseTell
		wantErr string
	}{
		{
			"SPAMD/1.1 0 EX_OK\r\n" +
				"Content-length: 0\r\n" +
				"DidSet: local,remote\r\n" +
				"\r\n",
			&ResponseTell{
				DidSet: []string{"local", "remote"},
			},
			"",
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%v", i), func(t *testing.T) {
			out, err := newClient(tc.in).
				Tell(context.Background(), strings.NewReader("A message"), nil)

			if !test.ErrorContains(err, tc.wantErr) {
				t.Errorf("wrong error\nout:  %#v\nwant: %#v\n", err, tc.wantErr)
			}
			if !reflect.DeepEqual(out, tc.want) {
				t.Errorf("\nout:  %#v\nwant: %#v\n", out, tc.want)
			}
		})
	}
}

type testDialer struct {
	conn fakeconn.Conn
}

func (d *testDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d.conn, nil
}

func newClient(resp string) *Client {
	conn := fakeconn.New()
	conn.ReadFrom.WriteString(resp)
	return New(func(ctx context.Context) (net.Conn, error) {
		return conn, nil
	})
}

func TestHeader(t *testing.T) {
	t.Run("set", func(t *testing.T) {
		h := Header{}.Set("xxx", "asD").Set("awe-CV", "zxc")
		it := h.Iterate()
		want := [][]string{{"Awe-cv", "zxc"}, {"Xxx", "asD"}}
		if !reflect.DeepEqual(it, want) {
			t.Errorf("\nout:  %#v\nwant: %#v\n", it, want)
		}
		if h.normalizeKey("") != "" {
			t.Error("normalizeKey with empty string")
		}
	})

	t.Run("message-class", func(t *testing.T) {
		Header{}.Set("message-class", "spam")
		Header{}.Set("message-class", "ham")
		Header{}.Set("message-class", "")
		Header{}.Set("set", "local")
		Header{}.Set("set", "local,remote")
		Header{}.Set("set", "")
	})

	t.Run("panic", func(t *testing.T) {
		func() {
			defer func() {
				r := recover()
				if r == nil {
					t.Error("did not panic")
				}
			}()
			Header{}.Set("message-class", "hello")
		}()

		func() {
			defer func() {
				r := recover()
				if r == nil {
					t.Error("did not panic")
				}
			}()

			Header{}.Set("set", "hello")
		}()
	})
}
