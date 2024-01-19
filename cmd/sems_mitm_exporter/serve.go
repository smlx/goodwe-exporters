package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/smlx/goodwe/mitm"
	"golang.org/x/sync/errgroup"
)

const (
	metricsPort        = ":14028"
	metricsReadTimeout = 2 * time.Second
)

// ServeCmd represents the `serve` command.
type ServeCmd struct {
	Batsignal       bool `kong:"env='BATSIGNAL',help='Enable Batsignal mode (draws the bat-insignia on the SEMS portal graph)'"`
	SEMSPassthrough bool `kong:"env='SEMS_PASSTHROUGH',default='true',help='Enable passthrough to SEMS Portal'"`
}

// Run the serve command.
func (cmd *ServeCmd) Run(log *slog.Logger) error {
	// handle signals
	ctx, stop := signal.NotifyContext(
		context.Background(),
		syscall.SIGTERM,
		syscall.SIGINT)
	defer stop()
	// configure metrics server
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	metricsSrv := http.Server{
		Addr:         metricsPort,
		ReadTimeout:  metricsReadTimeout,
		WriteTimeout: metricsReadTimeout,
		Handler:      mux,
	}
	// set up multithreading
	var eg *errgroup.Group
	eg, ctx = errgroup.WithContext(ctx)
	// start metrics server
	eg.Go(func() error {
		if err := metricsSrv.ListenAndServe(); err != http.ErrServerClosed {
			return err
		}
		return nil
	})
	// start metrics server shutdown handler for graceful shutdown
	eg.Go(func() error {
		<-ctx.Done()
		timeoutCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		return metricsSrv.Shutdown(timeoutCtx)
	})
	// start mitm server
	if cmd.SEMSPassthrough {
		eg.Go(func() error {
			return mitm.NewServer(cmd.Batsignal).Serve(ctx, log)
		})
	} else {
		// TODO SEMS Emulator: semsem.NewServer().Serve(ctx,log)
		return fmt.Errorf("SEMS Emulator not yet implemented")
	}
	return eg.Wait()
}
