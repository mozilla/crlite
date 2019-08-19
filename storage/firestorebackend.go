package storage

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	// "os"
	"path/filepath"
	// "time"

	"cloud.google.com/go/firestore"
	"github.com/orcaman/writerseeker"
	"google.golang.org/api/iterator"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const kFdata = "d"

type FirestoreBackend struct {
	ctx    context.Context
	client *firestore.Client
}

func NewFirestoreBackend(ctx context.Context, projectId string) (*FirestoreBackend, error) {
	client, err := firestore.NewClient(ctx, projectId)
	if err != nil {
		return nil, err
	}

	return &FirestoreBackend{ctx, client}, nil
}

func (db *FirestoreBackend) Close() error {
	return db.client.Close()
}

func (db *FirestoreBackend) Store(id string, data []byte) error {
	doc := db.client.Doc(id)
	if doc == nil {
		return fmt.Errorf("Couldn't open Document %s. Remember that Firestore heirarchies must alterante Document/Collections.", id)
	}

	fmt.Printf("Storing %+v into %s\n", len(data), id)
	_, err := doc.Set(db.ctx, map[string]interface{}{kFdata: data})
	return err
}

func (db *FirestoreBackend) Load(id string) ([]byte, error) {
	fmt.Printf("Loading from %s\n", id)

	doc := db.client.Doc(id)
	if doc == nil {
		return []byte{}, fmt.Errorf("Couldn't open Document %s. Remember that Firestore heirarchies must alterante Document/Collections.", id)
	}

	docsnap, err := doc.Get(db.ctx)
	if err != nil {
		return []byte{}, err
	}

	data, err := docsnap.DataAt(kFdata)
	return data.([]byte), err
}

func (db *FirestoreBackend) List(path string, walkFn filepath.WalkFunc) error {
	return fmt.Errorf("Not implemented")
}

func (db *FirestoreBackend) getAsBufferCreateIfNeeded(id string) (*writerseeker.WriterSeeker, error) {
	data, err := db.Load(id)
	if err != nil {
		// Ignore NotFound
		if status.Code(err) != codes.NotFound {
			return nil, err
		}
	}
	buffer := &writerseeker.WriterSeeker{}
	if _, err := buffer.Write(data); err != nil {
		return nil, err
	}
	return buffer, nil
}

func (db *FirestoreBackend) Writer(id string, append bool) (io.WriteCloser, error) {
	var buffer *writerseeker.WriterSeeker
	var err error

	if append {
		buffer, err = db.getAsBufferCreateIfNeeded(id)
		if err != nil {
			return nil, err
		}
	} else {
		buffer = &writerseeker.WriterSeeker{}
	}

	return db.NewFirestoreRemoteFile(false, true, id, buffer), err
}

func (db *FirestoreBackend) ReadWriter(id string) (io.ReadWriteCloser, error) {
	buffer, err := db.getAsBufferCreateIfNeeded(id)
	if err != nil {
		return nil, err
	}

	return db.NewFirestoreRemoteFile(true, true, id, buffer), nil
}

func (db *FirestoreBackend) deleteCollection(ref *firestore.CollectionRef, batchSize int) error {
	for {
		// Get a batch of documents
		iter := ref.Limit(batchSize).Documents(db.ctx)
		numDeleted := 0

		// Iterate through the documents, adding
		// a delete operation for each one to a
		// WriteBatch.
		batch := db.client.Batch()
		for {
			doc, err := iter.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				return err
			}

			batch.Delete(doc.Ref)
			numDeleted++
		}

		// If there are no documents to delete,
		// the process is over.
		if numDeleted == 0 {
			return nil
		}

		_, err := batch.Commit(db.ctx)
		if err != nil {
			return err
		}
	}
}

type firestoreRemoteFile struct {
	readable  bool
	writeable bool
	backend   FirestoreBackend
	id        string
	buffer    *writerseeker.WriterSeeker
	reader    io.Reader
}

func (db *FirestoreBackend) NewFirestoreRemoteFile(readable bool, writeable bool, id string, buffer *writerseeker.WriterSeeker) *firestoreRemoteFile {
	reader := buffer.Reader()
	return &firestoreRemoteFile{readable, writeable, *db, id, buffer, reader}
}

func (rf *firestoreRemoteFile) Read(p []byte) (n int, err error) {
	if !rf.readable {
		return 0, fmt.Errorf("Not readable")
	}
	return rf.reader.Read(p)
}

func (rf *firestoreRemoteFile) Write(p []byte) (n int, err error) {
	if !rf.writeable {
		return 0, fmt.Errorf("Not writeable")
	}
	return rf.buffer.Write(p)
}

func (rf *firestoreRemoteFile) Close() error {
	if !rf.readable && !rf.writeable {
		return fmt.Errorf("%s already closed", rf.id)
	}

	var err error
	if rf.writeable {
		// err = rf.backend.Store(rf.id, rf.Reader()) // TODO
		data, err := ioutil.ReadAll(rf.buffer.Reader())
		if err != nil {
			return err
		}
		if err = rf.backend.Store(rf.id, data); err != nil {
			return err
		}
	}

	rf.readable = false
	rf.writeable = false
	return err
}

// type firestoreRemoteFileInfo struct {
// 	name  string
// 	size  int64
// 	isDir bool
// }

// func (rfi *firestoreRemoteFileInfo) Name() string {
// 	return rfi.name
// }

// func (rfi *firestoreRemoteFileInfo) Size() int64 {
// 	return rfi.size
// }

// func (rfi *firestoreRemoteFileInfo) Mode() os.FileMode {
// 	return 0644
// }

// func (rfi *firestoreRemoteFileInfo) ModTime() time.Time {
// 	return time.Now()
// }

// func (rfi *firestoreRemoteFileInfo) IsDir() bool {
// 	return rfi.isDir
// }

// func (rfi *firestoreRemoteFileInfo) Sys() interface{} {
// 	return nil
// }
