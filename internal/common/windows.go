//go:build windows

package common

import (
	"log"
	"path/filepath"

	"github.com/doncicuto/openuem_utils"
	"golang.org/x/sys/windows/registry"
)

func (w *Worker) GenerateOCSPResponderConfig() error {
	var err error

	// Get new OCSP Responder

	cwd, err := GetWd()
	if err != nil {
		log.Println("[ERROR]: could not get working directory")
		return err
	}

	w.DBUrl, err = openuem_utils.CreatePostgresDatabaseURL()
	if err != nil {
		log.Printf("[ERROR]: %v", err)
		return err
	}

	caCertPath := filepath.Join(cwd, "certificates/ca/ca.cer")
	w.CACert, err = openuem_utils.ReadPEMCertificate(caCertPath)
	if err != nil {
		log.Printf("[ERROR]: could not read CA certificate in %s", caCertPath)
		return err
	}

	ocspCertPath := filepath.Join(cwd, "certificates/ocsp/ocsp.cer")
	w.OCSPCert, err = openuem_utils.ReadPEMCertificate(ocspCertPath)
	if err != nil {
		log.Println("[ERROR]: could not read OCSP certificate")
		return err
	}

	ocspKeyPath := filepath.Join(cwd, "certificates/ocsp/ocsp.key")
	w.OCSPPrivateKey, err = openuem_utils.ReadPEMPrivateKey(ocspKeyPath)
	if err != nil {
		log.Println("[ERROR]: could not read OCSP private key")
		return err
	}

	k, err := openuem_utils.OpenRegistryForQuery(registry.LOCAL_MACHINE, `SOFTWARE\OpenUEM\Server`)
	if err != nil {
		log.Println("[ERROR]: could not open registry")
		return err
	}
	defer k.Close()

	w.Port, err = openuem_utils.GetValueFromRegistry(k, "OCSPPort")
	if err != nil {
		log.Println("[ERROR]: could not read OCSP responders from registry")
		return err
	}

	return nil
}
