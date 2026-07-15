// Command package-release zips a built plugin library and writes a sha256
// checksum entry compatible with the CLIProxyAPI plugin store installer.
package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	library := flag.String("library", "", "path to the built plugin dynamic library")
	archive := flag.String("archive", "", "path of the zip archive to create")
	checksum := flag.String("checksum", "", "path of the sha256 checksum file to create")
	flag.Parse()
	if *library == "" || *archive == "" || *checksum == "" {
		fmt.Fprintln(os.Stderr, "usage: package-release -library <lib> -archive <zip> -checksum <sha256>")
		os.Exit(2)
	}
	if err := run(*library, *archive, *checksum); err != nil {
		fmt.Fprintln(os.Stderr, "package-release:", err)
		os.Exit(1)
	}
}

func run(libraryPath, archivePath, checksumPath string) error {
	libraryData, errRead := os.ReadFile(libraryPath)
	if errRead != nil {
		return fmt.Errorf("read library: %w", errRead)
	}
	archiveData, errZip := buildArchive(filepath.Base(libraryPath), libraryData)
	if errZip != nil {
		return errZip
	}
	if errMkdir := os.MkdirAll(filepath.Dir(archivePath), 0o755); errMkdir != nil {
		return fmt.Errorf("create archive dir: %w", errMkdir)
	}
	if errWrite := os.WriteFile(archivePath, archiveData, 0o644); errWrite != nil {
		return fmt.Errorf("write archive: %w", errWrite)
	}
	digest := sha256.Sum256(archiveData)
	entry := fmt.Sprintf("%s  %s\n", hex.EncodeToString(digest[:]), filepath.Base(archivePath))
	if errWrite := os.WriteFile(checksumPath, []byte(entry), 0o644); errWrite != nil {
		return fmt.Errorf("write checksum: %w", errWrite)
	}
	return nil
}

// buildArchive stores the library at the zip root: the plugin store installer
// requires the dynamic library as a root entry named after the plugin ID.
func buildArchive(entryName string, data []byte) ([]byte, error) {
	var buf bytes.Buffer
	writer := zip.NewWriter(&buf)
	header := &zip.FileHeader{Name: entryName, Method: zip.Deflate}
	header.SetMode(0o755)
	entry, errHeader := writer.CreateHeader(header)
	if errHeader != nil {
		return nil, fmt.Errorf("create zip entry: %w", errHeader)
	}
	if _, errWrite := entry.Write(data); errWrite != nil {
		return nil, fmt.Errorf("write zip entry: %w", errWrite)
	}
	if errClose := writer.Close(); errClose != nil {
		return nil, fmt.Errorf("finalize zip: %w", errClose)
	}
	return buf.Bytes(), nil
}
