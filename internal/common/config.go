package common

import (
	"log"

	"github.com/open-uem/utils"
	"gopkg.in/ini.v1"
)

func (w *Worker) GenerateOCSPResponderConfig() error {
	var err error

	// Get config file location
	configFile := utils.GetConfigFile()

	// Get new OCSP Responder
	w.DBUrl, err = utils.CreatePostgresDatabaseURL()
	if err != nil {
		log.Printf("[ERROR]: %v", err)
		return err
	}

	// Open ini file
	cfg, err := ini.Load(configFile)
	if err != nil {
		return err
	}

	key, err := cfg.Section("Certificates").GetKey("CACert")
	if err != nil {
		return err
	}

	w.CACert, err = utils.ReadPEMCertificate(key.String())
	if err != nil {
		log.Printf("[ERROR]: could not read CA certificate in %s", key.String())
		return err
	}

	key, err = cfg.Section("Certificates").GetKey("OCSPCert")
	if err != nil {
		return err
	}

	w.OCSPCert, err = utils.ReadPEMCertificate(key.String())
	if err != nil {
		log.Println("[ERROR]: could not read OCSP certificate")
		return err
	}

	key, err = cfg.Section("Certificates").GetKey("OCSPKey")
	if err != nil {
		return err
	}

	w.OCSPPrivateKey, err = utils.ReadPEMPrivateKey(key.String())
	if err != nil {
		log.Println("[ERROR]: could not read OCSP private key")
		return err
	}

	key, err = cfg.Section("OCSP").GetKey("OCSPPort")
	if err != nil {
		return err
	}

	w.Port = key.String()

	return nil
}
