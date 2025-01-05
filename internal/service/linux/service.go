//go:build linux

package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/open-uem/openuem-ocsp-responder/internal/common"
)

func main() {
	w := common.NewWorker("openuem-ocsp-responder")
	if err := w.GenerateOCSPResponderConfig(); err != nil {
		log.Printf("[ERROR]: could not generate config for OCSP responder: %v", err)
	}

	w.StartWorker()

	// Keep the connection alive
	done := make(chan os.Signal, 1)
	signal.Notify(done, syscall.SIGINT, syscall.SIGTERM, os.Interrupt)
	<-done

	w.StopWorker()
}
