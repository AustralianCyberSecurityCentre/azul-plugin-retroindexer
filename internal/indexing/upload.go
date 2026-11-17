package indexing

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type uploadReceipt struct {
	Target  string `json:"target"`
	Size    int64  `json:"size"`
	ModTime int64  `json:"mod_time"`
}

// SyncUploads publishes completed indexes from the staging PVC to Bedrock
// object storage. Upload failures leave local indexes available for retries.
// Local indexes are deleted only after a successful Put and unchanged-file
// check. Retain-local mode uses a target-scoped receipt to avoid republishing
// giant indexes every polling cycle; receipts are not used in cleanup mode.
func (p *Pipeline) SyncUploads(target string, upload func(string) error, keepLocal bool) (int, error) {
	if target == "" || upload == nil {
		return 0, fmt.Errorf("cannot sync indexes: cloud publisher is not configured")
	}
	files, err := os.ReadDir(p.bgiDir())
	if err != nil {
		return 0, err
	}
	// Receipts are scoped to the destination, avoiding false positives after a backend change.
	targetHash := sha256.Sum256([]byte(target))
	suffix := hex.EncodeToString(targetHash[:8])
	count := 0
	for _, file := range files {
		if file.IsDir() || strings.HasPrefix(file.Name(), ".") || !strings.HasSuffix(file.Name(), ".bgi") {
			continue
		}
		path := filepath.Join(p.bgiDir(), file.Name())
		before, err := os.Stat(path)
		if err != nil {
			return count, err
		}
		if !before.Mode().IsRegular() {
			continue
		}
		receiptPath := filepath.Join(p.stateDir(), "uploaded-"+file.Name()+"-"+suffix+".json")
		if keepLocal {
			var receipt uploadReceipt
			if raw, readErr := os.ReadFile(receiptPath); readErr == nil && json.Unmarshal(raw, &receipt) == nil &&
				receipt.Target == target && receipt.Size == before.Size() && receipt.ModTime == before.ModTime().UnixNano() {
				continue
			}
		}
		if err := upload(path); err != nil {
			return count, fmt.Errorf("upload %s: %w", path, err)
		}
		after, err := os.Stat(path)
		if err != nil {
			return count, fmt.Errorf("stat uploaded index %s: %w", path, err)
		}
		if before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
			return count, fmt.Errorf("index changed during cloud upload: %s (retained for retry)", path)
		}
		if keepLocal {
			// Keep a durable receipt so test-mode indexes are not sent every poll.
			data, err := json.Marshal(uploadReceipt{Target: target, Size: before.Size(), ModTime: before.ModTime().UnixNano()})
			if err != nil {
				return count, err
			}
			tmp, err := os.CreateTemp(p.stateDir(), ".uploaded-")
			if err != nil {
				return count, err
			}
			_, writeErr := tmp.Write(data)
			if writeErr == nil {
				writeErr = tmp.Sync()
			}
			if closeErr := tmp.Close(); writeErr == nil {
				writeErr = closeErr
			}
			if writeErr == nil {
				writeErr = os.Rename(tmp.Name(), receiptPath)
			}
			_ = os.Remove(tmp.Name())
			if writeErr != nil {
				return count, writeErr
			}
		} else {
			if err := os.Remove(path); err != nil {
				return count, fmt.Errorf("uploaded but could not remove local index %s: %w", path, err)
			}
			// Remove an obsolete testing-mode receipt if it exists.
			_ = os.Remove(receiptPath)
		}
		count++
	}
	return count, nil
}
