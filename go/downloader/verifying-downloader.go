package downloader

import (
	"context"
	"fmt"
	"net/url"
	"os"

	"github.com/golang/glog"
	"github.com/vbauerster/mpb/v5"
)

type DownloadVerifier interface {
	IsValid(path string) error
}

/*
 * Returns: Boolean of whether the data at finalPath is now valid, and any error. It is possible
 * that err != nil and yet finalPath is valid, so callers should rely on the boolean and merely
 * log the error as needed.
 */
func DownloadAndVerifyFileSync(ctx context.Context, verifyFunc DownloadVerifier, auditor DownloadAuditor,
	identifier DownloadIdentifier, display *mpb.Progress, crlUrl url.URL, finalPath string, maxRetries uint) (bool, error) {
	dlTracer := NewDownloadTracer()
	auditCtx := dlTracer.Configure(ctx)

	tmpPath := fmt.Sprintf("%s.tmp", finalPath)
	defer func() {
		removeErr := os.Remove(tmpPath)
		if removeErr != nil && !os.IsNotExist(removeErr) {
			glog.Warningf("[%s] Failed to remove invalid tmp file %s: %s", identifier.ID(), tmpPath, removeErr)
		}
	}()

	dlErr := DownloadFileSync(auditCtx, display, crlUrl, tmpPath, maxRetries)
	if dlErr != nil {
		auditor.FailedDownload(identifier, &crlUrl, dlTracer, dlErr)
		glog.Warningf("[%s] Failed to download from %s to tmp file %s: %s", identifier.ID(), crlUrl.String(), tmpPath, dlErr)

		existingValidErr := verifyFunc.IsValid(finalPath)
		if existingValidErr == nil {
			// The existing file at finalPath is OK.
			return true, dlErr
		}
		return false, dlErr
	}

	dlValidErr := verifyFunc.IsValid(tmpPath)
	if dlValidErr != nil {
		auditor.FailedVerifyUrl(identifier, &crlUrl, dlTracer, dlValidErr)

		existingValidErr := verifyFunc.IsValid(finalPath)
		if existingValidErr == nil {
			// The existing file at finalPath is OK.
			return true, dlValidErr
		}

		auditor.FailedVerifyPath(identifier, finalPath, existingValidErr)
		glog.Errorf("[%s] Couldn't verify already-on-disk path %s: %s", identifier.ID(), finalPath, existingValidErr)
		return false, existingValidErr
	}

	renameErr := os.Rename(tmpPath, finalPath)
	if renameErr != nil {
		glog.Errorf("[%s] Couldn't rename %s to %s: %s", identifier.ID(), tmpPath, finalPath, renameErr)
		return false, renameErr
	}

	return true, nil

}
