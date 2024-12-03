package common

import (
	"crypto/rsa"
	"crypto/x509"
	"log"

	"github.com/doncicuto/openuem-ocsp-responder/internal/models"
	"github.com/doncicuto/openuem-ocsp-responder/internal/server"
	"github.com/doncicuto/openuem_ent/component"
	"github.com/doncicuto/openuem_utils"
	"github.com/go-co-op/gocron/v2"
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
	Port           string
	Component      component.Component
	Version        string
	Channel        component.Channel
}

func NewWorker(logName string) *Worker {
	worker := Worker{}
	if logName != "" {
		worker.Logger = openuem_utils.NewLogger(logName)
	}

	worker.Version = VERSION
	worker.Component = component.ComponentOcsp
	worker.Channel = CHANNEL
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

}

func (w *Worker) StopWorker() {
	if w.Model != nil {
		w.Model.Close()
	}

	if w.TaskScheduler != nil {
		if err := w.TaskScheduler.Shutdown(); err != nil {
			log.Printf("[ERROR]: could not stop the task scheduler, reason: %s", err.Error())
		}
	}

	if w.WebServer != nil {
		w.WebServer.Close()
	}

	log.Println("[INFO]: the OCSP responder has stopped")
	if w.Logger != nil {
		w.Logger.Close()
	}

}
