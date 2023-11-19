package main

import (
	"github.com/alecthomas/kong"
)

// CLI represents the command-line interface.
type CLI struct {
	Serve   ServeCmd   `kong:"cmd,default,help='Start the MITM server'"`
	Version VersionCmd `kong:"cmd,help='Print version information'"`
}

func main() {
	// parse CLI config
	cli := CLI{}
	kctx := kong.Parse(&cli,
		kong.UsageOnError(),
	)
	// execute CLI
	kctx.FatalIfErrorf(kctx.Run())
}
