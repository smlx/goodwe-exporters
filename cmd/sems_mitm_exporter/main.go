// Package main is the sems_mitm_exporter executable.
package main

import (
	"log/slog"
	"os"

	"github.com/alecthomas/kong"
)

// CLI represents the command-line interface.
type CLI struct {
	Debug   bool       `kong:"env='DEBUG',help='Enable debug logging'"`
	Serve   ServeCmd   `kong:"cmd,default,help='Start the MITM server'"`
	Version VersionCmd `kong:"cmd,help='Print version information'"`
}

func main() {
	// parse CLI config
	cli := CLI{}
	kctx := kong.Parse(&cli, kong.UsageOnError())
	// configure the logger
	var log *slog.Logger
	if cli.Debug {
		log = slog.New(slog.NewJSONHandler(os.Stderr,
			&slog.HandlerOptions{Level: slog.LevelDebug}))
	} else {
		log = slog.New(slog.NewJSONHandler(os.Stdout, nil))
	}
	// execute CLI
	kctx.FatalIfErrorf(kctx.Run(log))
}
