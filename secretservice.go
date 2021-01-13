package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"

	"github.com/spf13/cobra"
	"github.com/zeebo/errs"
	"github.com/zeebo/errs/errdata"
	"golang.org/x/crypto/nacl/secretbox"
	monkit "gopkg.in/spacemonkeygo/monkit.v2"

	"storj.io/private/process"
)

var (
	cfg struct {
		Addr   string `default:"0.0.0.0:8080" help:"address to listen on"`
		Secret string `default:"" help:"encryption secret"`
	}

	mon = monkit.Package()

	ErrConfig           = errs.Class("configuration")
	ErrMissingField     = errs.Class("missing field")
	ErrInvalidOp        = errs.Class("invalid op")
	ErrDecryptionFailed = errs.Class("decryption failed")
	ErrDecodingFailed   = errs.Class("decoding failed")
)

type errStatusCode int

func init() {
	errdata.Set(&ErrMissingField, errStatusCode(0), http.StatusBadRequest)
	errdata.Set(&ErrInvalidOp, errStatusCode(0), http.StatusNotFound)
	errdata.Set(&ErrDecryptionFailed, errStatusCode(0), http.StatusBadRequest)
	errdata.Set(&ErrDecodingFailed, errStatusCode(0), http.StatusBadRequest)
}

func main() {
	cmd := &cobra.Command{
		Use:   "encryption",
		Short: "service that does encryption/decryption",
		RunE:  cmdRun,
	}
	process.Bind(cmd, &cfg)
	process.Exec(cmd)
}

func cmdRun(cmd *cobra.Command, args []string) (err error) {
	if cfg.Secret == "" {
		return ErrConfig.New("--secret flag missing. please set an encryption secret")
	}
	fmt.Printf("listening on %v\n", cfg.Addr)
	return http.ListenAndServe(cfg.Addr, NewService(cfg.Secret))
}

func NewService(secret string) *Service {
	return &Service{key: sha256.Sum256([]byte(secret))}
}

type Service struct {
	key [32]byte
}

func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	err := s.serveHTTP(r.Context(), w, r)
	if err != nil {
		statusCode, ok := errdata.Get(err, errStatusCode(0)).(int)
		if !ok {
			statusCode = http.StatusInternalServerError
		}
		http.Error(w, err.Error(), statusCode)
	}
}

func (s *Service) serveHTTP(ctx context.Context, w http.ResponseWriter, r *http.Request) (err error) {
	defer mon.Task()(&ctx)(&err)

	switch r.URL.Path {
	case "/encrypt":
		return s.Encrypt(ctx, w, r)
	case "/decrypt":
		return s.Decrypt(ctx, w, r)
	}

	return ErrInvalidOp.New("%q", r.URL.Path)
}

func (s *Service) Encrypt(ctx context.Context, w http.ResponseWriter, r *http.Request) (err error) {
	defer mon.Task()(&ctx)(&err)

	plaintext := r.FormValue("plaintext")
	if plaintext == "" {
		return ErrMissingField.New("plaintext")
	}

	var nonce [24]byte
	_, err = rand.Read(nonce[:])
	if err != nil {
		return errs.Wrap(err)
	}

	ciphertext := secretbox.Seal(nonce[:], []byte(plaintext), &nonce, &s.key)
	_, err = fmt.Fprintln(w, base64.URLEncoding.EncodeToString(ciphertext))
	return errs.Wrap(err)
}

func (s *Service) Decrypt(ctx context.Context, w http.ResponseWriter, r *http.Request) (err error) {
	defer mon.Task()(&ctx)(&err)

	ciphertext := r.FormValue("ciphertext")
	if ciphertext == "" {
		return ErrMissingField.New("ciphertext")
	}

	decoded, err := base64.URLEncoding.DecodeString(ciphertext)
	if err != nil {
		SendAlert(string(ciphertext))
		return ErrDecodingFailed.Wrap(err)
	}

	if len(decoded) < 24 {
		return ErrDecodingFailed.New("input too short")
	}

	var nonce [24]byte
	copy(nonce[:], decoded[:24])

	plaintext, ok := secretbox.Open(nil, decoded[24:], &nonce, &s.key)
	if !ok {
		return ErrDecryptionFailed.New("")
	}

	_, err = fmt.Fprintln(w, string(plaintext))
	return errs.Wrap(err)
}
