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

	attemptFallbackToExistingFile := func(err error) (bool, error) {
		existingValidErr := verifyFunc.IsValid(finalPath)
		if existingValidErr == nil {
			// The existing file at finalPath is OK.
			return true, err
		}
		// We don't log to the auditor here since the local file being bad isn't necessarily this run's fault,
		// and it will be handled later in aggregate-crls if it is relevant at that stage.
		combinedError := fmt.Errorf("[%s] Couldn't verify already-on-disk path %s. Local error=%s, Caused by=%s",
			identifier.ID(), finalPath, existingValidErr, err)
		glog.Error(combinedError)
		return false, combinedError
	}

	dlErr := DownloadFileSync(auditCtx, display, crlUrl, tmpPath, maxRetries)
	if dlErr != nil {
		auditor.FailedDownload(identifier, &crlUrl, dlTracer, dlErr)
		glog.Warningf("[%s] Failed to download from %s to tmp file %s: %s", identifier.ID(), crlUrl.String(), tmpPath, dlErr)

		return attemptFallbackToExistingFile(dlErr)
	}

	dlValidErr := verifyFunc.IsValid(tmpPath)
	if dlValidErr != nil {
		auditor.FailedVerifyUrl(identifier, &crlUrl, dlTracer, dlValidErr)

		return attemptFallbackToExistingFile(dlValidErr)
	}

	renameErr := os.Rename(tmpPath, finalPath)
	if renameErr != nil {
		glog.Errorf("[%s] Couldn't rename %s to %s: %s", identifier.ID(), tmpPath, finalPath, renameErr)

		return attemptFallbackToExistingFile(renameErr)
	}

	return true, nil

}
