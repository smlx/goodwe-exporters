package main

import (
	"fmt"
)

// ServeCmd represents the `serve` command.
type ServeCmd struct{}

// Run the serve command.
func (*ServeCmd) Run() error {
	fmt.Println("start mitm")
	return nil
}
