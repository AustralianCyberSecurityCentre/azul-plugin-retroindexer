package indexing

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config controls local staging, rotation, and BigGrep execution.
type Config struct {
	Root            string
	Name            string
	StreamLabels    map[string]bool
	MaxBytes        int64
	MinFreeBytes    int64
	Timeout         time.Duration
	Periodic        time.Duration
	Poll            time.Duration
	Bigindex        string
	Once            bool
	SplitOnFailure  bool
	RequireHistoric bool
}

func getenv(key, fallback string) string {
	if x := os.Getenv(key); x != "" {
		return x
	}
	return fallback
}
func parseInt(key string, defaultValue int64) (int64, error) {
	x := os.Getenv(key)
	if x == "" {
		return defaultValue, nil
	}
	n, err := strconv.ParseInt(x, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return n, nil
}

// FromEnv reads deployment settings and validates limits before startup.
func FromEnv() (Config, error) {
	c := Config{Root: getenv("RETROINDEXER_ROOT_PATH", "/indices"), Name: getenv("RETROINDEXER_INDEXER_NAME", "content"), Bigindex: getenv("RETROINDEXER_BGINDEX", "bgindex"), StreamLabels: make(map[string]bool), SplitOnFailure: true}
	for _, s := range strings.Split(getenv("RETROINDEXER_STREAM_LABELS", "content"), ",") {
		if t := strings.TrimSpace(s); t != "" {
			c.StreamLabels[t] = true
		}
	}
	max, err := parseInt("RETROINDEXER_MAX_BYTES_BEFORE_INDEXING", 10*1024*1024*1024)
	if err != nil {
		return c, err
	}
	c.MaxBytes = max
	minFree, err := parseInt("RETROINDEXER_MIN_FREE_BYTES", 5*1024*1024*1024)
	if err != nil {
		return c, err
	}
	c.MinFreeBytes = minFree
	timeout, err := parseInt("RETROINDEXER_TIMEOUT_MINUTES", 60)
	if err != nil {
		return c, err
	}
	c.Timeout = time.Duration(timeout) * time.Minute
	periodic, err := parseInt("RETROINDEXER_PERIODIC_MINUTES", 60)
	if err != nil {
		return c, err
	}
	c.Periodic = time.Duration(periodic) * time.Minute
	poll, err := parseInt("RETROINDEXER_POLL_SECONDS", 10)
	if err != nil {
		return c, err
	}
	c.Poll = time.Duration(poll) * time.Second
	c.Once = strings.EqualFold(getenv("RETROINDEXER_ONCE", "false"), "true")
	c.RequireHistoric = strings.EqualFold(getenv("RETROINDEXER_REQUIRE_HISTORIC", "false"), "true")
	c.SplitOnFailure = !strings.EqualFold(getenv("RETROINDEXER_SPLIT_ON_FAILURE", "true"), "false")
	if c.Name == "" || strings.ContainsAny(c.Name, "/\\.") {
		return c, fmt.Errorf("unsafe indexer name %q", c.Name)
	}
	if c.MaxBytes < 4 || c.MinFreeBytes < 0 || c.Timeout <= 0 || c.Poll <= 0 {
		return c, fmt.Errorf("invalid max bytes, timeout or poll interval")
	}
	return c, nil
}
