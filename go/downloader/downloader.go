package downloader

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/golang/glog"
	"github.com/vbauerster/mpb"
	"github.com/vbauerster/mpb/decor"
)

type DownloadAction int

const (
	Create   DownloadAction = 0
	Resume   DownloadAction = 1
	UpToDate DownloadAction = 2
)

func GetSizeAndDateOfFile(path string) (int64, time.Time, error) {
	curFile, err := os.Open(path)
	if err != nil {
		return 0, time.Time{}, err
	}
	stat, err := curFile.Stat()
	if err != nil {
		return 0, time.Time{}, err
	}
	curFile.Close()

	return stat.Size(), stat.ModTime(), nil
}

func determineAction(client *http.Client, crlUrl url.URL, path string) (DownloadAction, int64) {
	szOnDisk, localDate, err := GetSizeAndDateOfFile(path)
	if err != nil {
		glog.V(1).Infof("[%s] CREATE: File not on disk: %s ", crlUrl.String(), err)
		return Create, 0
	}
	req, err := http.NewRequest("HEAD", crlUrl.String(), nil)
	if err != nil {
		return Create, 0
	}
	req.Header.Add("X-Automated-Tool", "https://github.com/mozilla/crlite")

	resp, err := client.Do(req)
	if err != nil {
		return Create, 0
	}

	eTag := resp.Header.Get("Etag")
	lastMod, err := http.ParseTime(resp.Header.Get("Last-Modified"))
	if err != nil {
		glog.V(1).Infof("[%s] CREATE: Invalid last-modified: %s [%s]", crlUrl.String(), err, resp.Header.Get("Last-Modified"))
		return Create, 0
	}
	szOnServer, err := strconv.ParseInt(resp.Header.Get("Content-Length"), 10, 64)
	if err != nil {
		glog.V(1).Infof("[%s] CREATE: No content length: %s [%s]", crlUrl.String(), err, resp.Header.Get("Content-Length"))
		return Create, 0
	}

	if !localDate.Before(lastMod) && szOnServer == szOnDisk {
		glog.V(1).Infof("[%s] UP TO DATE", crlUrl.String())
		return UpToDate, 0
	}

	if resp.Header.Get("Content-Length") != "bytes" {
		glog.V(1).Infof("[%s] Content-Length not supported", crlUrl.String())
	}
	if szOnServer == szOnDisk {
		glog.V(1).Infof("[%s] Disk size equals server", crlUrl.String())
	}
	if localDate.Before(lastMod) {
		glog.V(1).Infof("[%s] Local Date is before last modified header date", crlUrl.String())
	}

	if resp.Header.Get("Content-Length") == "bytes" && !localDate.Before(lastMod) && szOnServer > szOnDisk {
		glog.V(1).Infof("[%s] RESUME: { Already on disk: %d %s, Last-Modified: %s, Etag: %s, Length: %d }", crlUrl.String(), szOnDisk, localDate.String(), lastMod.String(), eTag, szOnServer)
		return Resume, szOnDisk
	}

	return Create, 0
}

func download(display *mpb.Progress, crlUrl url.URL, path string) error {
	client := &http.Client{}

	action, offset := determineAction(client, crlUrl, path)

	if action == UpToDate {
		return nil
	}

	req, err := http.NewRequest("GET", crlUrl.String(), nil)
	if err != nil {
		return err
	}

	req.Header.Add("X-Automated-Tool", "https://github.com/mozilla/crlite")
	if action == Resume {
		req.Header.Add("Content-Range", fmt.Sprintf("bytes: %d-", offset))
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Non-OK status: %s", resp.Status)
	}

	var outFileParams int
	switch action {
	case Resume:
		outFileParams = os.O_APPEND | os.O_WRONLY
	case Create:
		outFileParams = os.O_TRUNC | os.O_CREATE | os.O_WRONLY
	default:
		panic("Unexpected action.")
	}

	outFile, err := os.OpenFile(path, outFileParams, 0644)
	if err != nil {
		return err
	}
	defer outFile.Close()

	progBar := display.AddBar(resp.ContentLength,
		mpb.PrependDecorators(
			decor.Name(crlUrl.String()),
		),
		mpb.AppendDecorators(
			decor.EwmaETA(decor.ET_STYLE_GO, 16),
			decor.CountersKibiByte(" %6.1f / %6.1f"),
		),
		mpb.BarRemoveOnComplete(),
	)

	if action == Resume {
		progBar.IncrBy((int)(offset))
	}

	defer resp.Body.Close()
	reader := progBar.ProxyReader(resp.Body)

	// and copy from reader, propagating errors
	totalBytes, err := io.Copy(outFile, reader)
	if err != nil {
		return err
	}

	// Sometimes ContentLength is crazy far off.
	progBar.SetTotal(totalBytes, true)

	lastMod, err := http.ParseTime(resp.Header.Get("Last-Modified"))
	if err != nil {
		glog.Warningf("[%s] Couldn't set modified time: %s [%s]", crlUrl.String(), err, resp.Header.Get("Last-Modified"))
		return nil
	}

	if err := os.Chtimes(path, lastMod, lastMod); err != nil {
		glog.Warningf("Couldn't set modified time: %s", err)
	}
	return nil
}

func DownloadFileSync(display *mpb.Progress, crlUrl url.URL, path string) error {
	glog.V(1).Infof("Downloading %s from %s", path, crlUrl.String())

	return download(display, crlUrl, path)
}
