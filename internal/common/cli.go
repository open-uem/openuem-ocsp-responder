package common

import (
	"path/filepath"

	"github.com/doncicuto/openuem_utils"
	"github.com/urfave/cli/v2"
)

func (w *Worker) GenerateOCSPResponderConfigFromCLI(cCtx *cli.Context) error {
	var err error

	w.DBUrl = cCtx.String("dburl")

	cwd, err := GetWd()
	if err != nil {
		return err
	}

	caCertPath := filepath.Join(cwd, cCtx.String("cacert"))
	w.CACert, err = openuem_utils.ReadPEMCertificate(caCertPath)
	if err != nil {
		return err
	}

	ocspCertPath := filepath.Join(cwd, cCtx.String("cert"))
	w.OCSPCert, err = openuem_utils.ReadPEMCertificate(ocspCertPath)
	if err != nil {
		return err
	}

	ocspKeyPath := filepath.Join(cwd, cCtx.String("key"))
	w.OCSPPrivateKey, err = openuem_utils.ReadPEMPrivateKey(ocspKeyPath)
	if err != nil {
		return err
	}

	w.Port = cCtx.String("port")

	return nil
}
