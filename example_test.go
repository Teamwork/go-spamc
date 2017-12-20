package spamc

import (
	"context"
	"fmt"
	"log"
	"strings"
)

func Example() {
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
}
