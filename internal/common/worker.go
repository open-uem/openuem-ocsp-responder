package common

import (
	"crypto/rsa"
	"crypto/x509"
	"log"
	"net/http"
	"path/filepath"

	"github.com/doncicuto/openuem-ocsp-responder/internal/models"
	"github.com/doncicuto/openuem-ocsp-responder/internal/server"
	"github.com/doncicuto/openuem_utils"
	"github.com/go-co-op/gocron/v2"
	"golang.org/x/sys/windows/registry"
)

type Worker struct {
	Model          *models.Model
	WebServer      *server.WebServer
	Logger         *openuem_utils.OpenUEMLogger
	DBConnectJob   gocron.Job
	TaskScheduler  gocron.Scheduler
	DBUrl          string
	CACert         *x509.Certificate
	OCSPCert       *x509.Certificate
	OCSPPrivateKey *rsa.PrivateKey
	DatabaseType   string
}

func NewWorker(logName string) *Worker {
	worker := Worker{}
	if logName != "" {
		worker.Logger = openuem_utils.NewLogger(logName)
	}
	return &worker
}

func (w *Worker) StartWorker() {
	var err error

	// Start Task Scheduler
	w.TaskScheduler, err = gocron.NewScheduler()
	if err != nil {
		log.Printf("[ERROR]: could not create task scheduler, reason: %s", err.Error())
		return
	}
	w.TaskScheduler.Start()
	log.Println("[INFO]: task scheduler has been started")

	// Start a job to try to connect with the database
	if err := w.StartDBConnectJob(); err != nil {
		log.Printf("[ERROR]: could not start DB connect job, reason: %s", err.Error())
		return
	}

	// TODO may we set the port from registry key and avoid harcoding it?
	log.Println("[INFO]: launching server")
	w.WebServer = server.New(w.Model, ":8000", w.CACert, w.OCSPCert, w.OCSPPrivateKey)

	go func() {
		if err := w.WebServer.Serve(); err != http.ErrServerClosed {
			log.Printf("[ERROR]: the server has stopped, reason: %v", err.Error())
		}
	}()

	log.Println("[INFO]: OCSP responder is running")
}

func (w *Worker) StopWorker() {
	w.Model.Close()
	w.Logger.Close()
	if err := w.TaskScheduler.Shutdown(); err != nil {
		log.Printf("[ERROR]: could not stop the task scheduler, reason: %s", err.Error())
	}
	w.WebServer.Close()
}

func (w *Worker) GenerateOCSPResponderConfig() error {
	var err error

	// Get new OCSP Responder

	cwd, err := GetWd()
	if err != nil {
		log.Println("[ERROR]: could not get working directory")
		return err
	}

	k, err := openuem_utils.OpenRegistryForQuery(registry.LOCAL_MACHINE, `SOFTWARE\OpenUEM\Server`)
	if err != nil {
		log.Println("[ERROR]: could not open registry")
		return err
	}
	defer k.Close()

	w.DatabaseType, err = openuem_utils.GetValueFromRegistry(k, "Database")
	if err != nil {
		log.Println("[ERROR]: could not read database type from registry")
		return err
	}

	if w.DatabaseType == "SQLite" {
		w.DBUrl = filepath.Join(cwd, "database", "openuem.db")
	} else {
		w.DBUrl, err = openuem_utils.CreatePostgresDatabaseURL()
		if err != nil {
			log.Printf("[ERROR]: %v", err)
			return err
		}
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

	return nil
}
