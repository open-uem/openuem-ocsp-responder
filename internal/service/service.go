package main

import (
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/doncicuto/openuem-ocsp-responder/internal/models"
	"github.com/doncicuto/openuem-ocsp-responder/internal/server"
	"github.com/doncicuto/openuem_utils"
	"github.com/go-co-op/gocron/v2"
	"golang.org/x/sys/windows/svc"
)

type OCSPResponderService struct {
	Model         *models.Model
	WebServer     *server.WebServer
	Logger        *openuem_utils.OpenUEMLogger
	DBConnectJob  gocron.Job
	TaskScheduler gocron.Scheduler
	DBUrl         string
}

func NewOCSPResponder() *OCSPResponderService {
	return &OCSPResponderService{
		Logger: openuem_utils.NewLogger("openuem-ocsp-responder.txt"),
	}
}

func (r *OCSPResponderService) Start() {
	var err error

	// Get new OCSP Responder
	r.DBUrl, err = openuem_utils.CreatePostgresDatabaseURL()
	if err != nil {
		log.Printf("[ERROR]: %v\n", err)
		return
	}

	// Start Task Scheduler
	r.TaskScheduler, err = gocron.NewScheduler()
	if err != nil {
		log.Printf("[ERROR]: could not create task scheduler, reason: %s", err.Error())
		return
	}
	r.TaskScheduler.Start()
	log.Println("[INFO]: task scheduler has been started")

	// Start a job to try to connect with the database
	if err := r.startDBConnectJob(); err != nil {
		log.Printf("[ERROR]: could not start DB connect job, reason: %s", err.Error())
		return
	}

	ex, err := os.Executable()
	if err != nil {
		log.Printf("[ERROR]:could not get executable info: %v", err)
	}
	cwd := filepath.Dir(ex)

	caCertPath := filepath.Join(cwd, "certificates/ca/ca.cer")
	caCert, err := openuem_utils.ReadPEMCertificate(caCertPath)
	if err != nil {
		log.Printf("[ERROR]: could not read CA certificate in %s", caCertPath)
		return
	}

	ocspCertPath := filepath.Join(cwd, "certificates/ocsp/ocsp.cer")
	ocspCert, err := openuem_utils.ReadPEMCertificate(ocspCertPath)
	if err != nil {
		log.Println("[ERROR]: could not read OCSP certificate")
		return
	}

	ocspKeyPath := filepath.Join(cwd, "certificates/ocsp/ocsp.key")
	ocspKey, err := openuem_utils.ReadPEMPrivateKey(ocspKeyPath)
	if err != nil {
		log.Println("[ERROR]: could not read OCSP private key")
		return
	}

	// TODO may we set the port from registry key and avoid harcoding it?
	log.Println("[INFO]: launching server")
	ws := server.New(r.Model, ":8000", caCert, ocspCert, ocspKey)

	go func() {
		if err := ws.Serve(); err != http.ErrServerClosed {
			log.Printf("[ERROR]: the server has stopped, reason: %v", err.Error())
		}
	}()

	log.Println("[INFO]: OCSP responder is running")
}

func (r *OCSPResponderService) Stop() {
	r.Model.Close()
	if err := r.TaskScheduler.Shutdown(); err != nil {
		log.Printf("[ERROR]: could not stop the task scheduler, reason: %s", err.Error())
	}
	r.Logger.Close()
	r.WebServer.Close()
}

func (r *OCSPResponderService) startDBConnectJob() error {
	var err error

	// Run initially
	r.Model, err = models.New(r.DBUrl)
	if err == nil {
		log.Println("[INFO]: connection established with database")
		return err
	}

	// Create task for running the agent
	r.DBConnectJob, err = r.TaskScheduler.NewJob(
		gocron.DurationJob(
			time.Duration(time.Duration(2*time.Minute)),
		),
		gocron.NewTask(
			func() {
				r.Model, err = models.New(r.DBUrl)
				if err != nil {
					return
				}
				log.Println("[INFO]: connection established with database")

				if err := r.TaskScheduler.RemoveJob(r.DBConnectJob.ID()); err != nil {
					return
				}
			},
		),
	)
	if err != nil {
		log.Fatalf("[FATAL]: could not start the DB connect job: %v", err)
		return err
	}

	log.Printf("[INFO]: new DB connect job has been scheduled every %d minutes", 2)
	return nil
}

func main() {

	r := NewOCSPResponder()
	s := openuem_utils.NewOpenUEMWindowsService()
	s.ServiceStart = r.Start
	s.ServiceStop = r.Stop

	// Run service
	err := svc.Run("openuem-ocsp-responder", s)
	if err != nil {
		log.Printf("[ERROR]: could not run service: %v", err)
	}
}
