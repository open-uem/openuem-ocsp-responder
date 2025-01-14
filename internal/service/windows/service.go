//go:build windows

package main

import (
	"log"

	"github.com/open-uem/openuem-ocsp-responder/internal/common"
	"github.com/open-uem/utils"
	"golang.org/x/sys/windows/svc"
)

func main() {
	w := common.NewWorker("openuem-ocsp-responder.txt")
	if err := w.GenerateOCSPResponderConfig(); err != nil {
		log.Printf("[ERROR]: could not generate config for OCSP responder: %v", err)
	}

	s := utils.NewOpenUEMWindowsService()
	s.ServiceStart = w.StartWorker
	s.ServiceStop = w.StopWorker

	// Run service
	err := svc.Run("openuem-ocsp-responder", s)
	if err != nil {
		log.Printf("[ERROR]: could not run service: %v", err)
	}
}
