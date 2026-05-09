package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"ssh-proxy/internal/config"
	"ssh-proxy/internal/metrics"
	"ssh-proxy/internal/proxy"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/sync/errgroup"
)

func main() {
	os.Exit(run())
}

func run() int {
	if err := execute(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

func execute() error {
	runtime.GOMAXPROCS(runtime.NumCPU())

	configPath := flag.String("config", "/etc/ssh-proxy/config.yaml", "path to the proxy configuration file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}

	logger, cleanup, err := buildLogger(cfg.Logging)
	if err != nil {
		return err
	}
	defer cleanup()

	metricRegistry := metrics.New()
	proxyServer, err := proxy.NewServer(cfg, logger, metricRegistry)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	group, groupCtx := errgroup.WithContext(ctx)
	group.Go(func() error {
		return proxyServer.ListenAndServe(groupCtx)
	})

	if cfg.Metrics.Enabled {
		metricsServer := &http.Server{
			Addr:    cfg.Metrics.Listen,
			Handler: metricsHandler(cfg.Metrics.Path, metricRegistry),
		}

		logger.Info("metrics server listening", zap.String("listen", cfg.Metrics.Listen), zap.String("path", cfg.Metrics.Path))

		group.Go(func() error {
			go func() {
				<-groupCtx.Done()
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = metricsServer.Shutdown(shutdownCtx)
			}()

			if err := metricsServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				return fmt.Errorf("serve metrics endpoint: %w", err)
			}
			return nil
		})
	}

	if err := group.Wait(); err != nil && !errors.Is(err, net.ErrClosed) {
		return err
	}

	return nil
}

func metricsHandler(path string, metricRegistry *metrics.Registry) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(path, metricRegistry.Handler())
	return mux
}

func buildLogger(cfg config.LoggingConfig) (*zap.Logger, func(), error) {
	level, err := zap.ParseAtomicLevel(cfg.Level)
	if err != nil {
		return nil, nil, fmt.Errorf("parse log level %q: %w", cfg.Level, err)
	}

	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.TimeKey = "ts"
	encoderConfig.LevelKey = "level"
	encoderConfig.MessageKey = "msg"
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder

	var encoder zapcore.Encoder
	if cfg.Format == "text" {
		encoder = zapcore.NewConsoleEncoder(encoderConfig)
	} else {
		encoder = zapcore.NewJSONEncoder(encoderConfig)
	}

	writeSyncer, closer, err := logOutput(cfg.Output)
	if err != nil {
		return nil, nil, err
	}

	logger := zap.New(
		zapcore.NewCore(encoder, writeSyncer, level),
		zap.AddCaller(),
		zap.AddStacktrace(zap.ErrorLevel),
	)

	cleanup := func() {
		_ = logger.Sync()
		if closer != nil {
			_ = closer.Close()
		}
	}

	return logger, cleanup, nil
}

func logOutput(output string) (zapcore.WriteSyncer, io.Closer, error) {
	if output == "stdout" {
		return zapcore.AddSync(os.Stdout), nil, nil
	}

	if err := os.MkdirAll(filepath.Dir(output), 0o755); err != nil {
		return nil, nil, fmt.Errorf("create log directory: %w", err)
	}

	file, err := os.OpenFile(output, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, nil, fmt.Errorf("open log output %q: %w", output, err)
	}

	return zapcore.AddSync(file), file, nil
}
