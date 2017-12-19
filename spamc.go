package spamc

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
)

// Protocol version we talk.
const clientProtocolVersion = "1.5"

// Command types.
const (
	cmdCheck        = "CHECK"
	cmdSymbols      = "SYMBOLS"
	cmdReport       = "REPORT"
	cmdReportIfspam = "REPORT_IFSPAM"
	cmdPing         = "PING"
	cmdTell         = "TELL"
	cmdProcess      = "PROCESS"
	cmdHeaders      = "HEADERS"
)

// Server protocol version we understand.
var serverProtocolVersions = []string{"1.0", "1.1"}

// mapping of the error codes to the error messages.
var errorMessages = map[int]string{
	64: "Command line usage error",               // EX_USAGE
	65: "Data format error",                      // EX_DATA_ERR
	66: "Cannot open input",                      // EX_NO_INPUT
	67: "Addressee unknown",                      // EX_NO_USER
	68: "Host name unknown",                      // EX_NO_HOST
	69: "Service unavailable",                    // EX_UNAVAILABLE
	70: "Internal software error",                // EX_SOFTWARE
	71: "System error",                           // EX_OSERR
	72: "Critical OS file missing",               // EX_OSFILE
	73: "Can't create (user) output file",        // EX_CANTCREAT
	74: "Input/output error",                     // EX_IOERR
	75: "Temp failure; user is invited to retry", // EX_TEMPFAIL
	76: "Remote error in protocol",               // EX_PROTOCOL
	77: "Permission denied",                      // EX_NOPERM
	78: "Configuration error",                    // EX_CONFIG
	79: "Read timeout",                           // EX_TIMEOUT
}

// send a command to spamd.
func (c *Client) send(
	ctx context.Context,
	cmd string,
	message io.Reader,
	headers Header,
) (io.ReadCloser, error) {

	conn, err := c.dial(ctx)
	if err != nil {
		return nil, errors.Wrapf(err, "could not dial to %v", c.addr)
	}

	if err := c.write(conn, cmd, message, headers); err != nil {
		return nil, err
	}

	return conn, nil
}

// write the command to the connection.
func (c *Client) write(
	conn net.Conn,
	cmd string,
	message io.Reader,
	headers Header,
) error {

	if strings.TrimSpace(cmd) == "" {
		return errors.New("empty command")
	}

	if headers == nil {
		headers = make(Header)
	}
	if _, ok := headers.Get("User"); !ok && c.DefaultUser != "" {
		headers.Set("User", c.DefaultUser)
	}

	buf := bytes.NewBufferString("")
	tp := textproto.NewWriter(bufio.NewWriter(buf))

	// Attempt to get the size if it wasn't explicitly given.
	if _, ok := headers.Get("Content-Length"); !ok {
		size, err := sizeFromReader(message)
		if err != nil {
			return errors.Wrap(err, "could not determine size of message")
		}
		headers.Set("Content-length", fmt.Sprintf("%v", size))
	}

	err := tp.PrintfLine("%v SPAMC/%v", cmd, clientProtocolVersion)
	if err != nil {
		return err
	}

	for _, v := range headers.Iterate() {
		if err := tp.PrintfLine("%v: %v", v[0], v[1]); err != nil {
			return err
		}
	}

	if err := tp.PrintfLine(""); err != nil {
		return err
	}
	if err := tp.W.Flush(); err != nil {
		return err
	}

	// Write to spamd.
	if _, err := io.Copy(conn, io.MultiReader(buf, message)); err != nil {
		conn.Close() // nolint: errcheck
		return errors.Wrap(err, "could not send to spamd")
	}

	// Close connection for writing; this makes sure all buffered data is sent.
	switch cc := conn.(type) {
	case *net.TCPConn:
		return cc.CloseWrite()
	case *net.UnixConn:
		return cc.CloseWrite()
	}

	return nil
}

func sizeFromReader(r io.Reader) (int64, error) {
	switch v := r.(type) {
	case *strings.Reader:
		return v.Size(), nil
	case *bytes.Reader:
		return v.Size(), nil
	case *os.File:
		stat, err := v.Stat()
		if err != nil {
			return 0, err
		}
		return stat.Size(), nil
	default:
		return 0, errors.Errorf("unknown type: %T", v)
	}

}

func (c *Client) dial(ctx context.Context) (net.Conn, error) {
	conn, err := c.dialer.DialContext(ctx, "tcp", c.addr)
	if err != nil {
		if conn != nil {
			conn.Close() // nolint: errcheck
		}
		return nil, errors.Wrap(err, "could not connect to spamd")
	}

	// Set connection timeout
	if ndial, ok := c.dialer.(*net.Dialer); ok {
		err = conn.SetDeadline(time.Now().Add(ndial.Timeout))
		if err != nil {
			conn.Close() // nolint: errcheck
			return nil, errors.Wrap(err, "connection to spamd timed out")
		}
	}

	return conn, nil
}

// The spamd protocol is a HTTP-esque protocol; a response's first line is the
// response code:
//
//     SPAMD/1.1 0 EX_OK\r\n
//
// Next, it can set some headers:
//
//     Content-length: <size>\r\n
//
// After a blank line we get the response body, which is different for the
// various commands.
//
// A non-0 (or EX_OK) status code is considered an error.
func readResponse(read io.Reader) (Header, *textproto.Reader, error) {
	tp := textproto.NewReader(bufio.NewReader(read))

	// We can't use textproto's ReadCodeLine() here, as SA's response is not
	// quite compatible.
	if err := parseCodeLine(tp, false); err != nil {
		return nil, tp, err
	}

	tpHeader, err := tp.ReadMIMEHeader()
	if err != nil {
		return nil, tp, errors.Wrap(err, "could not read headers")
	}

	headers := make(Header)
	for k, v := range tpHeader {
		headers.Set(k, v[0])
	}

	return headers, tp, nil
}

func parseCodeLine(tp *textproto.Reader, isPing bool) error {
	line, err := tp.ReadLine()
	if err != nil {
		return err
	}

	if len(line) < 11 {
		return errors.Errorf("short response: %v", line)
	}
	if !strings.HasPrefix(line, "SPAMD/") {
		return errors.Errorf("unrecognised response: %v", line)
	}

	version := line[6:9]

	// The PING command is special as it will return the *client* version,
	// rather than the server version.
	if isPing {
		if version != clientProtocolVersion {
			return errors.Errorf("unexpected version: %v; we expected %v",
				version, clientProtocolVersion)
		}
	} else {
		// in some errors it uses version 1.0, so accept both 1.0 and 1.1.
		//     spamd/1.0 76 bad header line: asdasd
		if !supportedVersion(version) {
			return errors.Errorf(
				"unknown server protocol version %v; we only understand versions %v",
				version, serverProtocolVersions)
		}
	}

	s := strings.Split(line[10:], " ")
	code, err := strconv.Atoi(s[0])
	if err != nil {
		return errors.Wrap(err, "could not parse return code")
	}
	if code != 0 {
		text := strings.Join(s[1:], " ")
		if msg, ok := errorMessages[code]; ok {
			return errors.Errorf("spamd returned code %v: %v: %v", code, msg, text)
		}
		return errors.Errorf("spamd returned code %v: %v", code, text)
	}

	return nil
}

func supportedVersion(v string) bool {
	for i := range serverProtocolVersions {
		if serverProtocolVersions[i] == v {
			return true
		}
	}
	return false
}

func readBody(tp *textproto.Reader) (string, error) {
	body := ""
loop:
	for {
		line, err := tp.ReadLine()
		switch err {
		case nil:
			// Do nothing
		case io.EOF:
			break loop
		default:
			return "", err
		}

		body += line + "\r\n"
	}

	return body, nil
}

// Parse the Spam: response header:
//    Spam <yes|no> ; <score> / <base-score>
// example:
//    Spam: yes ; 6.66 / 5.0
func parseSpamHeader(respHeaders Header) (bool, float64, float64, error) {
	spam, ok := respHeaders.Get("Spam")
	if !ok || len(spam) == 0 {
		return false, 0, 0, errors.New("header missing")
	}

	if len(spam) == 0 {
		return false, 0, 0, errors.New("header empty")
	}

	s := strings.Split(spam, ";")
	if len(s) != 2 {
		return false, 0, 0, errors.Errorf("unexpected data: %v", spam[0])
	}

	isSpam := false
	switch strings.ToLower(strings.TrimSpace(s[0])) {
	case "true", "yes":
		isSpam = true
	case "false", "no":
		isSpam = false
	default:
		return false, 0, 0, errors.Errorf("unknown spam status: %v", s[0])
	}

	split := strings.Split(s[1], "/")
	if len(split) != 2 {
		return false, 0, 0, errors.Errorf("unexpected data: %v", s[1])
	}
	score, err := strconv.ParseFloat(strings.TrimSpace(split[0]), 64)
	if err != nil {
		return false, 0, 0, errors.Errorf("could not parse spam score: %v", err)
	}
	baseScore, err := strconv.ParseFloat(strings.TrimSpace(split[1]), 64)
	if err != nil {
		return false, 0, 0, errors.Errorf("could not parse base spam score: %v", err)
	}

	return isSpam, score, baseScore, nil
}

// Report contains the parsed results of the Report command.
type Report struct {
	Intro string
	Table []struct {
		Points      float64
		Rule        string
		Description string
	}
}

// String formats the reports like SpamAssassin.
func (r Report) String() string {
	table := " pts rule name                        description\n"
	table += "---- -------------------------------- --------------------------------------------------\n"

	for _, t := range r.Table {
		leadingSpace := ""
		// Only checking if t.Points is >=0 is not enough because sometimes
		// the score is -0.0 which equals to 0 even if it starts with a `-`
		if !strings.HasPrefix(fmt.Sprintf("%f", t.Points), "-") {
			leadingSpace = " "
		}

		line := fmt.Sprintf("%v%.1f %v", leadingSpace, t.Points, t.Rule)
		numberOfSpaces := 38 - len(line)
		if numberOfSpaces <= 0 {
			numberOfSpaces = 1
		}
		line += strings.Repeat(" ", numberOfSpaces) + t.Description + "\n"
		table += line
	}

	return r.Intro + "\n\n" + table
}

var reTableLine = regexp.MustCompile(`(-?[0-9.]+)\s+([A-Z0-9_]+)\s+(.+)`)

// parse report output; example report:
//
// Spam detection software, running on the system "d311d8df23f8",
// has NOT identified this incoming email as spam.  The original
// message has been attached to this so you can view it or label
// similar future email.  If you have any questions, see
// the administrator of that system for details.
//
// Content preview:  the body [...]
//
// Content analysis details:   (1.6 points, 5.0 required)
//
//  pts rule name              description
// ---- ---------------------- --------------------------------------------------
//  0.4 INVALID_DATE           Invalid Date: header (not RFC 2822)
// -0.0 NO_RELAYS              Informational: message was not relayed via SMTP
//  1.2 MISSING_HEADERS        Missing To: header
// -0.0 NO_RECEIVED            Informational: message has no Received headers
func parseReport(tp *textproto.Reader) (Report, error) {
	report := Report{}
	table := false

	for {
		line, err := tp.ReadLine()
		if err != nil {
			if err == io.EOF {
				break
			}
			return report, err
		}

		switch {
		case !table && strings.HasPrefix(line, " pts rule name"):
			table = true

		case table && strings.HasPrefix(line, "---- -"):
			continue

		case !table:
			report.Intro += line + "\n"

		case table:
			s := reTableLine.FindAllStringSubmatch(line, -1)
			if len(s) != 1 {
				continue
			}

			if len(s[0]) != 4 {
				continue
			}

			points, err := strconv.ParseFloat(s[0][1], 64)
			if err != nil {
				continue
			}

			report.Table = append(report.Table, struct {
				Points      float64
				Rule        string
				Description string
			}{
				points, s[0][2], s[0][3],
			})
		}
	}

	report.Intro = strings.TrimSpace(report.Intro)
	return report, nil
}
