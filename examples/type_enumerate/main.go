package main

import (
	"context"
	"fmt"
	"time"

	"github.com/cyberxnomad/mdns"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ch, err := mdns.Query(ctx, []mdns.Question{mdns.TypeEnumQuestion})
	if err != nil {
		panic(err)
	}

	for entry := range ch {
		fmt.Println(entry.Name)
	}
}
