package models

import (
	"context"

	"github.com/doncicuto/openuem_ent"
	"github.com/doncicuto/openuem_ent/revocation"
)

func (m *Model) GetRevoked(serial int64) (*openuem_ent.Revocation, error) {
	return m.Client.Revocation.Query().Where(revocation.ID(serial)).Only(context.Background())
}
