package utils

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
)

type FolderDatabase struct {
	rootDir     *os.File
	permissions os.FileMode
	folderSize  uint64
}

func isDirectory(aPath string) bool {
	fileStat, err := os.Stat(aPath)
	if err != nil {
		return false
	}

	return fileStat.IsDir()
}

func NewFolderDatabase(aPath string, aPerms os.FileMode, aFolderSize uint64) (*FolderDatabase, error) {
	if !isDirectory(aPath) {
		return nil, fmt.Errorf("%s is not a directory. Aborting.", aPath)
	}

	fileObj, err := os.Open(aPath)
	if err != nil {
		return nil, err
	}

	db := &FolderDatabase{
		rootDir:     fileObj,
		permissions: aPerms,
		folderSize:  aFolderSize,
	}

	return db, nil
}

func idToString(aID uint64) string {
	return fmt.Sprintf("%010x", aID)
}

func (db *FolderDatabase) getPathForID(aID uint64) (string, string) {
	subdirName := idToString(aID / db.folderSize)
	dirPath := filepath.Join(db.rootDir.Name(), subdirName)
	fileName := idToString(aID)
	filePath := filepath.Join(dirPath, fileName)
	return dirPath, filePath
}

func (db *FolderDatabase) Store(aID uint64, aData []byte) error {
	dirPath, filePath := db.getPathForID(aID)
	if !isDirectory(dirPath) {
		err := os.Mkdir(dirPath, os.ModeDir|0777)
		if err != nil {
			return err
		}
	}
	_, err := os.Stat(filePath)
	if err != nil && os.IsNotExist(err) {
		return ioutil.WriteFile(filePath, aData, db.permissions)
	}
	// Already exists, so skip
	return nil
}

func (db *FolderDatabase) Get(aID uint64) ([]byte, error) {
	_, fileName := db.getPathForID(aID)
	return ioutil.ReadFile(fileName)
}
