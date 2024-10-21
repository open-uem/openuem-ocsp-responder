package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/danieljoos/wincred"
	"github.com/doncicuto/openuem-ocsp-responder/internal/models"
	"github.com/doncicuto/openuem-ocsp-responder/internal/server"
	"github.com/doncicuto/openuem-ocsp-responder/internal/service/logger"
	"github.com/doncicuto/openuem_utils"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
)

type OpenUEMService struct {
	Logger *logger.OpenUEMLogger
}

func New(l *logger.OpenUEMLogger) *OpenUEMService {
	return &OpenUEMService{
		Logger: l,
	}
}

func (s *OpenUEMService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	var err error
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}
	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}

	// Get new OCSP Responder
	dbUrl := createDatabaseURL()
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

	// service control manager
loop:
	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
				time.Sleep(100 * time.Millisecond)
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				log.Println("[INFO]: service has received the stop or shutdown command")
				s.Logger.Close()
				ws.Close()
				model.Close()
				break loop
			default:
				log.Println("[WARN]: unexpected control request")
				return true, 1
			}
		}
	}
	changes <- svc.Status{State: svc.StopPending}
	return true, 0
}

func main() {
	// Instantiate logger
	l := logger.New()

	// Instantiate service
	s := New(l)

	// Run service
	err := svc.Run("openuem-ocsp-responder", s)
	if err != nil {
		log.Printf("[ERROR]: could not run service: %v", err)
	}
}

func createDatabaseURL() string {
	var err error
	// Create DATABASE_URL env variable
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\OpenUEM\Server`, registry.QUERY_VALUE)
	if err != nil {
		log.Println("[ERROR]: could not open registry to search OpenUEM Server entries")
		return ""
	}
	defer k.Close()

	user, _, err := k.GetStringValue("PostgresUser")
	if err != nil {
		log.Println("[ERROR]: could not read PostgresUser from registry")
		return ""
	}

	host, _, err := k.GetStringValue("PostgresHost")
	if err != nil {
		log.Println("[ERROR]: could not read PostgresHost from registry")
		return ""
	}

	port, _, err := k.GetStringValue("PostgresPort")
	if err != nil {
		log.Println("[ERROR]: could not read PostgresPort from registry")
		return ""
	}

	database, _, err := k.GetStringValue("PostgresDatabase")
	if err != nil {
		log.Println("[ERROR]: could not read PostgresDatabase from registry")
		return ""
	}

	pass, err := wincred.GetGenericCredential(host + ":" + port)
	if err != nil {
		log.Println("[ERROR]: could not read password from Windows Credential Manager")
		return ""
	}

	decodedPass := UTF16BytesToString(pass.CredentialBlob, binary.LittleEndian)
	return fmt.Sprintf("postgres://%s:%s@%s:%s/%s", user, decodedPass, host, port, database)
}

func UTF16BytesToString(b []byte, o binary.ByteOrder) string {
	utf := make([]uint16, (len(b)+(2-1))/2)
	for i := 0; i+(2-1) < len(b); i += 2 {
		utf[i/2] = o.Uint16(b[i:])
	}
	if len(b)/2 < len(utf) {
		utf[len(utf)-1] = utf8.RuneError
	}
	return string(utf16.Decode(utf))
}
