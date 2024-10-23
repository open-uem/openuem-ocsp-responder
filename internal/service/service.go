package main

import (
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/doncicuto/openuem-ocsp-responder/internal/models"
	"github.com/doncicuto/openuem-ocsp-responder/internal/server"
	"github.com/doncicuto/openuem_utils"
	"golang.org/x/sys/windows/svc"
)

type OCSPResponderService struct {
	Model     *models.Model
	WebServer *server.WebServer
	Logger    *openuem_utils.OpenUEMLogger
}

func NewOCSPResponder() *OCSPResponderService {
	return &OCSPResponderService{
		Logger: openuem_utils.NewLogger("openuem-ocsp-responder.txt"),
	}
}

func (r *OCSPResponderService) Start() {
	var err error

	// Get new OCSP Responder
	dbUrl, err := openuem_utils.CreatePostgresDatabaseURL()
	if err != nil {
		log.Printf("[ERROR]: %v\n", err)
		return
	}

	model, err := models.New(dbUrl)
	if err != nil {
		log.Println("[ERROR]: could not open database connection")
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
	ws := server.New(model, ":8000", caCert, ocspCert, ocspKey)

	go func() {
		if err := ws.Serve(); err != http.ErrServerClosed {
			log.Printf("[ERROR]: the server has stopped, reason: %v", err.Error())
		}
	}()

	log.Println("[INFO]: OCSP responder is running")
}

func (r *OCSPResponderService) Stop() {
	r.Logger.Close()
	r.WebServer.Close()
	r.Model.Close()
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
