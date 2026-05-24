// Mini Go upload handler — planted upload vulnerabilities for truth-set.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

// -----------------------------------------------------------------------
// PLANTED BUG 1 (lines 18-35):
// r.FormFile("file") saved with io.Copy to path built from file.Filename
// Attacker-controlled filename used directly — path traversal possible
// -----------------------------------------------------------------------
func uploadHandlerUnsafe(w http.ResponseWriter, r *http.Request) {   // line 18
	// Parse the multipart form with no size limit
	r.ParseMultipartForm(0) // no size limit

	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Attacker controls header.Filename — path traversal via ../../
	dest := filepath.Join("/uploads/", header.Filename)              // line 29
	out, _ := os.Create(dest)
	defer out.Close()
	io.Copy(out, file)                                               // line 32
	fmt.Fprintf(w, "Saved to: %s", dest)
}                                                                    // line 34


// -----------------------------------------------------------------------
// PLANTED BUG 2 (lines 38-55):
// File served directly under r.Static("/uploads/") — public access
// No size limit configured
// -----------------------------------------------------------------------
func uploadHandlerNoSizeLimit(w http.ResponseWriter, r *http.Request) {   // line 38
	// No MaxBytesReader — no upload size limit at all
	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer file.Close()

	safeBase := randomHex(16)
	dest := filepath.Join("/uploads/", safeBase)   // at least uses random name
	out, _ := os.Create(dest)
	defer out.Close()
	io.Copy(out, file)
	fmt.Fprintf(w, "saved %s as %s", header.Filename, safeBase)
}                                                                    // line 52


// -----------------------------------------------------------------------
// NEGATIVE CASE (lines 57-80):
// Proper: size-limited + random name + storage outside webroot
// -----------------------------------------------------------------------
func uploadHandlerSafe(w http.ResponseWriter, r *http.Request) {    // line 57
	// Limit upload size to 10 MB
	r.Body = http.MaxBytesReader(w, r.Body, 10<<20)
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		http.Error(w, "file too large", http.StatusBadRequest)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer file.Close()
	_ = header.Filename // not used as storage path

	// Server-generated filename — attacker has no control
	randomName := randomHex(16)
	dest := filepath.Join("/var/data/uploads/", randomName)
	out, _ := os.Create(dest)
	defer out.Close()
	io.Copy(out, file)                                               // line 76
	fmt.Fprintf(w, "id: %s", randomName)
}                                                                    // line 78


func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func main() {
	http.HandleFunc("/upload_unsafe", uploadHandlerUnsafe)
	http.HandleFunc("/upload_no_size", uploadHandlerNoSizeLimit)
	http.HandleFunc("/upload_safe", uploadHandlerSafe)
	http.ListenAndServe(":8080", nil)
}
