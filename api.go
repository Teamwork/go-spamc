package spamc

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"sort"
	"strings"
	"time"

	"github.com/pkg/errors"
)

// Client is a connection to the spamd daemon.
type Client struct {
	// DefaultUser is the User to send if a command didn't specify one.
	DefaultUser string

	addr   string
	dialer Dialer
	conn   net.Conn
}

// Error is used for spamd responses; it contains the spamd exit code.
type Error struct {
	msg  string
	Code int64  // Code from spamd
	Line string // Line of text from spamd, unaltered.
}

func (e Error) Error() string { return e.msg }

// Dialer to connect to spamd.
type Dialer func(context.Context) (net.Conn, error)

// Header for requests and responses.
type Header map[string]string

// Set a header. This will normalize the key casing, which is important because
// SpamAssassin may ignore the header otherwise.
//
// The map is modified in-place, but is also returned for easier use:
//
//   fun(Header{}.Set("key", "value").Set("foo", "bar"))
func (h Header) Set(k, v string) Header {
	k = h.normalizeKey(k)

	switch k {
	case "Message-class":
		v := strings.ToLower(v)
		if v != "" && v != "spam" && v != "ham" {
			panic(fmt.Sprintf("unknown value for %v header: %v", k, v))
		}
	case "Set", "Remove":
		v := strings.Split(strings.ToLower(v), ",")
		for _, x := range v {
			if x != "" && x != "local" && x != "remote" {
				panic(fmt.Sprintf("unknown value for %v header: %v", k, x))
			}
		}
	}
	h[k] = v
	return h
}

// Get a header value; the second return value indicates if the map has this
// key.
func (h Header) Get(k string) (string, bool) {
	v, ok := h[h.normalizeKey(k)]
	return v, ok
}

// Iterate over the map in alphabetical order.
func (h Header) Iterate() [][]string {
	r := make([][]string, len(h))
	i := 0
	for k, v := range h {
		r[i] = []string{k, v}
		i++
	}
	sort.Slice(r, func(i, j int) bool { return r[i][0] < r[j][0] })
	return r
}

// Normalize the header casing.
func (h Header) normalizeKey(k string) string {
	if len(k) == 0 {
		return ""
	}

	k = strings.ToLower(k)
	switch k {
	case "didremove", "did-remove":
		return "DidRemove"
	case "didset", "did-set":
		return "DidSet"
	default:
		return strings.ToUpper(string(k[0])) + k[1:]
	}
}

// New creates a new Client instance.
//
// Examples:
//
//   New(TCPDialer("127.0.0.1:783"))
//   New(UnixDialer("/path/to/sock.unix"))
func New(d Dialer) *Client {
	return &Client{dialer: d}
}

// TCPDialer creates a TCP Dialer with a 20 second timeout.
func TCPDialer(addr string) Dialer {
	return buildDialer(addr, "tcp", 20*time.Second)
}

// UnixDialer creates a Unix Dialer with a 20 second timeout.
func UnixDialer(addr string) Dialer {
	return buildDialer(addr, "unix", 20*time.Second)
}

// Ping returns a confirmation that spamd is alive.
func (c *Client) Ping(ctx context.Context) error {
	read, err := c.send(ctx, cmdPing, strings.NewReader(""), nil)
	if err != nil {
		return errors.Wrap(err, "error sending command to spamd")
	}
	defer read.Close() // nolint: errcheck

	tp := textproto.NewReader(bufio.NewReader(read))
	return parseCodeLine(tp, true)
}

// ResponseScore contains the Spam score of this email; used in various
// different responses.
type ResponseScore struct {
	IsSpam    bool    // IsSpam reports if this message is considered spam.
	Score     float64 // Score is the spam score of this message.
	BaseScore float64 // BaseScore is the "minimum spam score" configured on the server.
}

// ResponseCheck is the response from the Check command.
type ResponseCheck struct {
	ResponseScore
}

// Check if the passed message is spam.
func (c *Client) Check(
	ctx context.Context,
	msg io.Reader,
	hdr Header,
) (*ResponseCheck, error) {

	read, err := c.send(ctx, cmdCheck, msg, hdr)
	if err != nil {
		return nil, errors.Wrap(err, "error sending command to spamd")
	}
	defer read.Close() // nolint: errcheck

	respHeaders, _, err := readResponse(read)
	if err != nil {
		return nil, errors.Wrap(err, "could not parse spamd response")
	}

	isSpam, score, baseScore, err := parseSpamHeader(respHeaders)
	if err != nil {
		return nil, errors.Wrap(err, "could not read Spam header")
	}

	return &ResponseCheck{
		ResponseScore: ResponseScore{
			IsSpam:    isSpam,
			Score:     score,
			BaseScore: baseScore,
		},
	}, nil
}

// ResponseSymbols is the response from the Symbols command.
type ResponseSymbols struct {
	ResponseScore

	// Symbols that matched.
	Symbols []string
}

// Symbols checks if the message is spam and returns the score and a list of all
// symbols that were hit.
func (c *Client) Symbols(
	ctx context.Context,
	msg io.Reader,
	hdr Header,
) (*ResponseSymbols, error) {

	// SPAMD/1.1 0 EX_OK
	// Content-length: 50
	// Spam: False ; 1.6 / 5.0
	//
	// INVALID_DATE,MISSING_HEADERS,NO_RECEIVED,NO_RELAYS
	read, err := c.send(ctx, cmdSymbols, msg, hdr)
	if err != nil {
		return nil, errors.Wrap(err, "error sending command to spamd")
	}
	defer read.Close() // nolint: errcheck

	respHeaders, tp, err := readResponse(read)
	if err != nil {
		return nil, errors.Wrap(err, "could not parse spamd response")
	}

	isSpam, score, baseScore, err := parseSpamHeader(respHeaders)
	if err != nil {
		return nil, errors.Wrap(err, "could not read Spam header")
	}

	body, err := readBody(tp)
	if err != nil {
		return nil, errors.Wrap(err, "could not read body")
	}

	s := strings.Split(strings.TrimSpace(body), ",")
	// Special case when symbols list is empty.
	if len(s) == 1 && s[0] == "" {
		s = *new([]string)
	}

	return &ResponseSymbols{
		ResponseScore: ResponseScore{
			IsSpam:    isSpam,
			Score:     score,
			BaseScore: baseScore,
		},
		Symbols: s,
	}, nil
}

// ResponseReport is the response from the Report and ReportIfSpam commands.
type ResponseReport struct {
	ResponseScore

	// Report broken down in the found rules and their descriptions.
	Report Report
}

// Report gives a detailed textual report for the message.
func (c *Client) Report(
	ctx context.Context,
	msg io.Reader,
	hdr Header,
) (*ResponseReport, error) {
	return c.report(ctx, cmdReport, msg, hdr)
}

// ReportIfSpam gives a detailed textual report for the message if it is
// considered spam. If it's not it will set just the spam score.
func (c *Client) ReportIfSpam(
	ctx context.Context,
	msg io.Reader,
	hdr Header,
) (*ResponseReport, error) {
	return c.report(ctx, cmdReportIfspam, msg, hdr)
}

// Implement Report and ReportIfSpam
func (c *Client) report(
	ctx context.Context,
	cmd string,
	msg io.Reader,
	hdr Header,
) (*ResponseReport, error) {

	read, err := c.send(ctx, cmd, msg, hdr)
	if err != nil {
		return nil, errors.Wrap(err, "error sending command to spamd")
	}
	defer read.Close() // nolint: errcheck

	respHeaders, tp, err := readResponse(read)
	if err != nil {
		return nil, errors.Wrap(err, "could not parse spamd response")
	}

	isSpam, score, baseScore, err := parseSpamHeader(respHeaders)
	if err != nil {
		return nil, errors.Wrap(err, "could not read Spam header")
	}

	report, err := parseReport(tp)
	if err != nil {
		return nil, errors.Wrap(err, "could not parse report")
	}

	return &ResponseReport{
		ResponseScore: ResponseScore{
			IsSpam:    isSpam,
			Score:     score,
			BaseScore: baseScore,
		},
		Report: report,
	}, nil
}

// ResponseProcess is the response from the Process and Headers commands.
type ResponseProcess struct {
	ResponseScore

	// Message headers and body.
	Message io.ReadCloser
}

type rc struct {
	read io.ReadCloser
	buff *bufio.Reader
}

func (r rc) Read(p []byte) (n int, err error) {
	return r.buff.Read(p)
}

func (r rc) Close() error {
	return r.read.Close()
}

// Process this message and return a modified message.
//
// Do not forget to close the Message reader!
func (c *Client) Process(
	ctx context.Context,
	msg io.Reader,
	hdr Header,
) (*ResponseProcess, error) {

	read, err := c.send(ctx, cmdProcess, msg, hdr)
	if err != nil {
		return nil, errors.Wrap(err, "error sending command to spamd")
	}

	respHeaders, tp, err := readResponse(read)
	if err != nil {
		return nil, errors.Wrap(err, "could not parse spamd response")
	}

	isSpam, score, baseScore, err := parseSpamHeader(respHeaders)
	if err != nil {
		return nil, errors.Wrap(err, "could not read Spam header")
	}

	return &ResponseProcess{
		ResponseScore: ResponseScore{
			IsSpam:    isSpam,
			Score:     score,
			BaseScore: baseScore,
		},
		Message: rc{read: read, buff: tp.R},
	}, nil
}

// Headers is the same as Process() but returns only modified headers and not
// the body.
//
// Do not forget to close the Message reader!
func (c *Client) Headers(
	ctx context.Context,
	msg io.Reader,
	hdr Header,
) (*ResponseProcess, error) {

	read, err := c.send(ctx, cmdHeaders, msg, hdr)
	if err != nil {
		return nil, errors.Wrap(err, "error sending command to spamd")
	}

	respHeaders, tp, err := readResponse(read)
	if err != nil {
		return nil, errors.Wrap(err, "could not parse spamd response")
	}

	isSpam, score, baseScore, err := parseSpamHeader(respHeaders)
	if err != nil {
		return nil, errors.Wrap(err, "could not read Spam header")
	}

	return &ResponseProcess{
		ResponseScore: ResponseScore{
			IsSpam:    isSpam,
			Score:     score,
			BaseScore: baseScore,
		},
		Message: rc{read: read, buff: tp.R},
	}, nil
}

// ResponseTell is the response of a TELL command.
type ResponseTell struct {
	DidSet    []string
	DidRemove []string
}

// Tell what type of we are to process and what should be done with that
// message.
//
// This includes setting or removing a local or a remote database (learning,
// reporting, forgetting, revoking).
//
// Message-class clasifies the message you're sending, and either the Set or
// Remove header specifies which action you want to take.
//
// To learn a message as spam:
//
//     c.Tell(ctx, msg, Header{}.
//         Set("Message-class", "spam").
//         Set("Set", "local"))
//
// Or to learn a message as ham:
//
//     c.Tell(ctx, msg, Header{}.
//         Set("Message-class", "ham").
//         Set("Set", "local"))
func (c *Client) Tell(
	ctx context.Context,
	msg io.Reader,
	hdr Header,
) (*ResponseTell, error) {

	read, err := c.send(ctx, cmdTell, msg, hdr)
	defer read.Close() // nolint: errcheck
	if err != nil {
		if serr, ok := err.(Error); ok && serr.Code == 69 {
			return nil, errors.New(
				"TELL commands are not enabled, set the --allow-tell switch")
		}
		return nil, err
	}

	respHeaders, _, err := readResponse(read)
	if err != nil {
		return nil, errors.Wrap(err, "could not parse spamd response")
	}

	r := &ResponseTell{}
	if h, ok := respHeaders.Get("DidSet"); ok {
		r.DidSet = strings.Split(h, ",")
	}
	if h, ok := respHeaders.Get("DidRemove"); ok {
		r.DidRemove = strings.Split(h, ",")
	}

	return r, nil
}
