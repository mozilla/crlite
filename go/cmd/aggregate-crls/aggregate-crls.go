package main

import (
	"flag"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/golang/glog"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/jcjones/ct-mapreduce/storage"
	"github.com/vbauerster/mpb"
	"github.com/vbauerster/mpb/decor"
)

var (
	crlpath = flag.String("crlpath", "<path>", "input path of .crl files")
	outfile = flag.String("out", "<path>", "output json dictionary of revocations")
)

const (
	kSuffixCRL = ".crl"
)

func processCRL(aPath string, aRevoked *storage.KnownCertificates) {
	glog.Infof("Proesss %s", aPath)
	crlBytes, err := ioutil.ReadFile(aPath)
	if err != nil {
		glog.Warningf("Error reading %s: %s", aPath, err)
		return
	}

	crl, err := x509.ParseCRL(crlBytes)
	if err != nil {
		glog.Warningf("Error parsing %s: %s", aPath, err)
		return
	}

	if crl.HasExpired(time.Now()) {
		glog.Warningf("CRL is expired, but proceeding anyway: %s", aPath)
	}

	for _, ent := range crl.TBSCertList.RevokedCertificates {
		newRevocation, err := aRevoked.WasUnknown(ent.SerialNumber)
		if err != nil {
			glog.Warningf("Error recording revocation %s [%v]: %s", aPath, ent.SerialNumber, err)
		}
		if newRevocation {
			glog.Infof("Newly seen revocation: %s [%v]", aPath, ent.SerialNumber)
		}
	}
}

func main() {
	flag.Parse()

	if *crlpath == "<path>" || *outfile == "<path>" {
		flag.Usage()
		return
	}

	// Start the display
	display := mpb.New()

	revokedCerts := storage.NewKnownCertificates(*outfile, 0644)
	if err := revokedCerts.Load(); err != nil {
		glog.Infof("Making new revocation storage file %s", *outfile)
	}
	defer revokedCerts.Save()

	queue := make(chan string, 1024*16)

	var count int64
	err := filepath.Walk(*crlpath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			glog.Warningf("prevent panic by handling failure accessing a path %q: %v", path, err)
			return err
		}

		if strings.HasSuffix(info.Name(), kSuffixCRL) {
			queue <- path
			count = count + 1
		}
		return nil
	})
	if err != nil {
		glog.Fatalf("Error walking from disk: %s", err)
	}
	close(queue)

	progressBar := display.AddBar(count,
		mpb.AppendDecorators(
			decor.Percentage(),
			decor.Name(""),
			decor.EwmaETA(decor.ET_STYLE_GO, 128, decor.WC{W: 14}),
			decor.CountersNoUnit("%d / %d", decor.WCSyncSpace),
		),
	)

	cycleTime := time.Now()
	for path := range queue {
		processCRL(path, revokedCerts)
		progressBar.IncrBy(1, time.Since(cycleTime))
		cycleTime = time.Now()
	}

	glog.Infof("Completed.")
}
