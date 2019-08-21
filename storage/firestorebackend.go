package storage

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

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

func (db *FirestoreBackend) MarkDirty(id string) error {
	// is this needed?
	return nil
}

func (db *FirestoreBackend) Store(docType DocumentType, id string, data []byte) error {
	doc := db.client.Doc(id)
	if doc == nil {
		return fmt.Errorf("Couldn't open Document %s. Remember that Firestore heirarchies must alterante Document/Collections.", id)
	}

	fmt.Printf("Storing %+v into %s\n", len(data), id)
	_, err := doc.Set(db.ctx, map[string]interface{}{
		"type": docType.String(),
		kFdata: data,
	})
	return err
}

func (db *FirestoreBackend) Load(docType DocumentType, id string) ([]byte, error) {
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

func (db *FirestoreBackend) listCollection(relativePath string, coll *firestore.CollectionRef, walkFn filepath.WalkFunc) error {
	fmt.Printf("listCollection %v\n", relativePath)
	err := walkFn(relativePath, &firestoreRemoteFileInfo{coll.Path, 0, true}, nil)
	if err != nil {
		fmt.Printf("listCollection walkFn err %+v\n", err)
		return err
	}

	iter := coll.DocumentRefs(db.ctx)
	for {
		doc, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil || doc == nil {
			fmt.Printf("listCollection iter.Next err %+v\n", err)
			return err
		}

		err = db.listDocument(filepath.Join(relativePath, doc.ID), doc, walkFn)
		if err != nil {
			fmt.Printf("listCollection listDocument err %+v\n", err)
			return err
		}
	}
	return nil
}

func (db *FirestoreBackend) listIterColl(relativePath string, iter *firestore.CollectionIterator, walkFn filepath.WalkFunc) error {
	for {
		col, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil || col == nil {
			fmt.Printf("listIterColl iter err %+v\n", err)
			return err
		}

		err = db.listCollection(filepath.Join(relativePath, col.ID), col, walkFn)
		if err != nil {
			fmt.Printf("listIterColl listCollection err %+v\n", err)
			return err
		}
	}
	return nil
}

func (db *FirestoreBackend) listDocument(relativePath string, doc *firestore.DocumentRef, walkFn filepath.WalkFunc) error {
	fmt.Printf("listDocument %v\n", relativePath)
	err := walkFn(relativePath, &firestoreRemoteFileInfo{doc.Path, 0, false}, nil)
	if err != nil {
		fmt.Printf("listDocument walkFn err %+v\n", err)
		return err
	}

	// doc.Collections() on a DocumentRef is forbidden, so we must use a query
	// iter := doc.Where()
	// return db.listIterColl(relativePath, iter, walkFn)
	return db.listIterColl(relativePath, doc.Collections(db.ctx), walkFn)
	// return nil
}

func (db *FirestoreBackend) listRoot(walkFn filepath.WalkFunc) error {
	// fmt.Printf("listRoot\n")
	return fmt.Errorf("Not allowed to list root. Seems not to work.")
	// Don't walk for the root
	// return db.listIterColl(db.client.Collections(db.ctx), walkFn)
}

func (db *FirestoreBackend) List(path string, walkFn filepath.WalkFunc) error {
	fmt.Printf("List %v\n", path)

	if strings.Count(path, "/")%2 == 0 {
		if path == "" {
			// This requires a special case, sadly
			return db.listRoot(walkFn)
		}
		coll := db.client.Collection(path)
		if coll != nil {
			return db.listCollection(path, coll, walkFn)
		}
		return fmt.Errorf("Collection for [%s] is nil", path)
	} else {
		doc := db.client.Doc(path)
		if doc != nil {
			return db.listDocument(path, doc, walkFn)
		}
		return fmt.Errorf("Document for [%s] is nil", path)
	}
}

func (db *FirestoreBackend) getAsBufferCreateIfNeeded(id string) (*writerseeker.WriterSeeker, error) {
	data, err := db.Load(TypeBulk, id)
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
		if err = rf.backend.Store(TypeBulk, rf.id, data); err != nil {
			return err
		}
	}

	rf.readable = false
	rf.writeable = false
	return err
}

type firestoreRemoteFileInfo struct {
	name  string
	size  int64
	isDir bool
}

func (rfi *firestoreRemoteFileInfo) Name() string {
	return rfi.name
}

func (rfi *firestoreRemoteFileInfo) Size() int64 {
	return rfi.size
}

func (rfi *firestoreRemoteFileInfo) Mode() os.FileMode {
	return 0644
}

func (rfi *firestoreRemoteFileInfo) ModTime() time.Time {
	return time.Now() // TODO ?
}

func (rfi *firestoreRemoteFileInfo) IsDir() bool {
	return rfi.isDir
}

func (rfi *firestoreRemoteFileInfo) Sys() interface{} {
	return nil
}
