package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/AustralianCyberSecurityCentre/azul-bedrock/v13/gosrc/plugin"
	"github.com/AustralianCyberSecurityCentre/azul-plugin-retroindexer/internal/dispatcher"
	"github.com/AustralianCyberSecurityCentre/azul-plugin-retroindexer/internal/indexing"
	"github.com/AustralianCyberSecurityCentre/azul-plugin-retroindexer/internal/storage"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
func run() error {
	mode := flag.String("mode", "all", "all (Go plugin ingestor + indexer), or index (index existing staging batches)")
	flush := flag.Bool("flush", false, "rotate current cache into ready batch and exit")
	flag.Parse()
	cfg, err := indexing.FromEnv()
	if err != nil {
		return err
	}
	p, err := indexing.New(cfg)
	if err != nil {
		return err
	}
	if *flush {
		return p.Flush()
	}
	if *mode != "index" && *mode != "all" {
		return fmt.Errorf("unsupported mode %q", *mode)
	}
	sc, err := storage.FromEnv()
	if err != nil {
		return err
	}
	publisher, err := storage.New(sc)
	if err != nil {
		return err
	}
	upload := func(path string) error {
		if publisher == nil {
			return fmt.Errorf("cloud storage disabled")
		}
		key, err := publisher.UploadFile(path, cfg.Name)
		if err == nil {
			log.Printf("uploaded index %s => %s", path, key)
		}
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	indexTick := func() error {
		_, indexErr := p.IndexReady(ctx, nil)
		// Even after an indexing failure, retry publishing indexes from prior passes.
		if publisher != nil {
			n, syncErr := p.SyncUploads(publisher.Target(), upload, sc.KeepLocal)
			if syncErr != nil {
				if cfg.Once {
					return fmt.Errorf("cloud publish: %w", syncErr)
				}
				log.Printf("cloud publication pending; retaining local .bgi for retry: %v", syncErr)
			} else if n > 0 {
				log.Printf("published %d indexes to %s (keep local: %t)", n, sc.Backend, sc.KeepLocal)
			}
		} else {
			log.Printf("local-only test mode: .bgi files remain in %s", cfg.Root)
		}
		return indexErr
	}

	background := func() {
		for ctx.Err() == nil {
			if err := p.MaybePeriodic(); err != nil {
				log.Printf("periodic staging failed: %v", err)
			}
			if err := indexTick(); err != nil {
				log.Printf("indexing error: %v", err)
			}
			if cfg.Once {
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(cfg.Poll):
			}
		}
	}
	if *mode == "index" {
		if cfg.Once {
			if err := p.MaybePeriodic(); err != nil {
				return err
			}
			return indexTick()
		}
		background()
		return nil
	}
	// The native runner executes Dispatcher jobs; the background indexer uses the
	// same Pipeline and PVC directories. Indexing is not a second dispatcher plugin.
	go background()
	log.Printf("starting native Go Retrohunt ingest plugin + background BigGrep indexer")
	reason := plugin.NewPluginRunner(&dispatcher.IngestPlugin{Pipeline: p}).Run()
	log.Printf("Azul plugin runner exited: %s", reason)
	stop()
	return nil
}
