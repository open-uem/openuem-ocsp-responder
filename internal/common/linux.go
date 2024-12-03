//go:build linux

package common

import (
	"log"

	"github.com/doncicuto/openuem_utils"
	"gopkg.in/ini.v1"
)

func (w *Worker) GenerateOCSPResponderConfig() error {
	var err error

	// Get new OCSP Responder

	w.DBUrl, err = openuem_utils.CreatePostgresDatabaseURL()
	if err != nil {
		log.Printf("[ERROR]: %v", err)
		return err
	}

	// Open ini file
	cfg, err := ini.Load("/etc/openuem-server/openuem.ini")
	if err != nil {
		return err
	}

	key, err := cfg.Section("Server").GetKey("ca_cert_path")
	if err != nil {
		return err
	}

	w.CACert, err = openuem_utils.ReadPEMCertificate(key.String())
	if err != nil {
		log.Printf("[ERROR]: could not read CA certificate in %s", key.String())
		return err
	}

	key, err = cfg.Section("Server").GetKey("ocsp_cert_path")
	if err != nil {
		return err
	}

	w.OCSPCert, err = openuem_utils.ReadPEMCertificate(key.String())
	if err != nil {
		log.Println("[ERROR]: could not read OCSP certificate")
		return err
	}

	key, err = cfg.Section("Server").GetKey("ocsp_key_path")
	if err != nil {
		return err
	}

	w.OCSPPrivateKey, err = openuem_utils.ReadPEMPrivateKey(key.String())
	if err != nil {
		log.Println("[ERROR]: could not read OCSP private key")
		return err
	}

	key, err = cfg.Section("Server").GetKey("ocsp_port")
	if err != nil {
		return err
	}

	w.Port = key.String()

	return nil
}