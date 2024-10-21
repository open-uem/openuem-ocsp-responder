package commands

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/doncicuto/openuem-ocsp-responder/internal/models"
	"github.com/doncicuto/openuem-ocsp-responder/internal/server"
	"github.com/doncicuto/openuem_utils"
	"github.com/urfave/cli/v2"
)

func StartOCSPResponder() *cli.Command {
	return &cli.Command{
		Name:   "start",
		Usage:  "Start OCSP Responder server",
		Action: startOCSPResponder,
		Flags:  OCSPResponderFlags(),
	}
}

func OCSPResponderFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:    "cacert",
			Value:   "certificates/ca.cer",
			Usage:   "the path to your CA certificate file in PEM format",
			EnvVars: []string{"CA_CERT_FILENAME"},
		},
		&cli.StringFlag{
			Name:    "cert",
			Value:   "certificates/ocsp.cer",
			Usage:   "the path to your OCSP server certificate file in PEM format",
			EnvVars: []string{"SERVER_CERT_FILENAME"},
		},
		&cli.StringFlag{
			Name:    "key",
			Value:   "certificates/ocsp.key",
			Usage:   "the path to your OCSP server private key file in PEM format",
			EnvVars: []string{"SERVER_KEY_FILENAME"},
		},
		&cli.StringFlag{
			Name:     "dburl",
			Usage:    "the Postgres database connection url e.g (postgres://user:password@host:5432/openuem)",
			EnvVars:  []string{"DATABASE_URL"},
			Required: true,
		},
	}
}

func startOCSPResponder(cCtx *cli.Context) error {
	log.Printf("🗃️   connecting to database")
	model, err := models.New(cCtx.String("dburl"))
	if err != nil {
		log.Fatal(fmt.Errorf("could not connect to database, reason: %s", err.Error()))
	}
	defer model.Close()

	cwd, err := os.Getwd()
	if err != nil {
		return err
	}

	log.Printf("📜  reading CA certificate")
	caCertPath := filepath.Join(cwd, cCtx.String("cacert"))
	caCert, err := openuem_utils.ReadPEMCertificate(caCertPath)
	if err != nil {
		return err
	}

	log.Printf("📜  reading OCSP responder certificate")
	ocspCertPath := filepath.Join(cwd, cCtx.String("cert"))
	ocspCert, err := openuem_utils.ReadPEMCertificate(ocspCertPath)
	if err != nil {
		return err
	}

	log.Printf("🔑  reading OCSP responder key")
	ocspKeyPath := filepath.Join(cwd, cCtx.String("key"))
	ocspKey, err := openuem_utils.ReadPEMPrivateKey(ocspKeyPath)
	if err != nil {
		return err
	}

	log.Printf("🌐  launching server")
	go func() {
		ws := server.New(model, ":8000", caCert, ocspCert, ocspKey)
		if err := ws.Serve(); err != http.ErrServerClosed {
			log.Fatal(fmt.Errorf("the server has stopped, reason: %s", err.Error()))
		}
		defer ws.Close()
	}()

	log.Printf("🆔  writing PIDFILE")
	// Save pid to PIDFILE
	if err := os.WriteFile("PIDFILE", []byte(strconv.Itoa(os.Getpid())), 0666); err != nil {
		return err
	}

	// Keep the connection alive
	done := make(chan os.Signal, 1)
	signal.Notify(done, syscall.SIGINT, syscall.SIGTERM, os.Interrupt)
	log.Printf("✅  the OCSP responder is ready and listening on %s\n", cCtx.String("address"))
	<-done
	log.Printf("👋  the OCSP responder has stopped listening\n")
	return nil
}
