package downloader

import (
	"net/url"
)

type DownloadIdentifier interface {
	ID() string
}

type DownloadAuditor interface {
	FailedDownload(identifier DownloadIdentifier, crlUrl *url.URL, dlTracer *DownloadTracer, err error)
	FailedVerifyUrl(identifier DownloadIdentifier, crlUrl *url.URL, dlTracer *DownloadTracer, err error)
	FailedVerifyPath(identifier DownloadIdentifier, crlPath string, err error)
}
