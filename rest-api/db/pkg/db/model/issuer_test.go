// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"context"
	"testing"

	"github.com/NVIDIA/infra-controller/rest-api/db/pkg/db"
	"github.com/NVIDIA/infra-controller/rest-api/db/pkg/util"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testIssuerSetupSchema(t *testing.T, dbSession *db.Session) {
	err := dbSession.DB.ResetModel(context.Background(), (*Issuer)(nil))
	assert.Nil(t, err)
	// the partial unique index is created by migration, not by ResetModel
	_, err = dbSession.DB.ExecContext(context.Background(),
		"CREATE UNIQUE INDEX IF NOT EXISTS issuer_issuer_url_active_idx ON issuer(issuer_url) WHERE deleted IS NULL")
	assert.Nil(t, err)
}

func testIssuerCreateInput(name, org, issuerURL string, createdBy uuid.UUID) IssuerCreateInput {
	return IssuerCreateInput{
		Name:        name,
		IssuerURL:   issuerURL,
		JWKSURL:     issuerURL + "/.well-known/jwks.json",
		Origin:      "custom",
		Audiences:   []string{"nico"},
		JWKSTimeout: "5s",
		ClaimMappings: []IssuerClaimMapping{{
			OrgName: org,
			Roles:   []string{"TENANT_ADMIN"},
		}},
		Status:    IssuerStatusPending,
		CreatedBy: createdBy,
	}
}

func TestIssuerSQLDAO_CreateAndGet(t *testing.T) {
	ctx := context.Background()
	dbSession := util.GetTestDBSession(t, false)
	defer dbSession.Close()
	testIssuerSetupSchema(t, dbSession)

	dao := NewIssuerDAO(dbSession)
	createdBy := uuid.New()

	created, err := dao.Create(ctx, nil, testIssuerCreateInput("acme-idp", "tenant-acme", "https://idp.acme.com", createdBy))
	require.Nil(t, err)
	require.NotNil(t, created)
	assert.Equal(t, "https://idp.acme.com", created.IssuerURL)
	assert.Equal(t, IssuerStatusPending, created.Status)
	require.Len(t, created.ClaimMappings, 1)
	assert.Equal(t, "tenant-acme", created.ClaimMappings[0].OrgName)
	assert.Equal(t, []string{"TENANT_ADMIN"}, created.ClaimMappings[0].Roles)
	assert.Equal(t, []string{"nico"}, created.Audiences)
	assert.Equal(t, "5s", created.JWKSTimeout)
	assert.False(t, created.Created.IsZero())

	// GetByID
	got, err := dao.GetByID(ctx, nil, created.ID)
	require.Nil(t, err)
	assert.Equal(t, created.ID, got.ID)
	assert.Equal(t, "acme-idp", got.Name)

	// GetByIssuerURL
	byURL, err := dao.GetByIssuerURL(ctx, nil, "https://idp.acme.com")
	require.Nil(t, err)
	assert.Equal(t, created.ID, byURL.ID)

	// missing ID / URL -> ErrDoesNotExist
	_, err = dao.GetByID(ctx, nil, uuid.New())
	assert.ErrorIs(t, err, db.ErrDoesNotExist)
	_, err = dao.GetByIssuerURL(ctx, nil, "https://nope.example.com")
	assert.ErrorIs(t, err, db.ErrDoesNotExist)
}

func TestIssuerSQLDAO_GetAll(t *testing.T) {
	ctx := context.Background()
	dbSession := util.GetTestDBSession(t, false)
	defer dbSession.Close()
	testIssuerSetupSchema(t, dbSession)

	dao := NewIssuerDAO(dbSession)
	createdBy := uuid.New()

	_, err := dao.Create(ctx, nil, testIssuerCreateInput("acme-idp", "tenant-acme", "https://idp.acme.com", createdBy))
	require.Nil(t, err)
	_, err = dao.Create(ctx, nil, testIssuerCreateInput("globex-idp", "tenant-globex", "https://idp.globex.com", createdBy))
	require.Nil(t, err)
	_, err = dao.Create(ctx, nil, testIssuerCreateInput("acme-backup", "tenant-acme-backup", "https://idp.acme-backup.com", createdBy))
	require.Nil(t, err)

	all, err := dao.GetAll(ctx, nil)
	require.Nil(t, err)
	assert.Len(t, all, 3)
}

func TestIssuerSQLDAO_Update(t *testing.T) {
	ctx := context.Background()
	dbSession := util.GetTestDBSession(t, false)
	defer dbSession.Close()
	testIssuerSetupSchema(t, dbSession)

	dao := NewIssuerDAO(dbSession)
	created, err := dao.Create(ctx, nil, testIssuerCreateInput("acme-idp", "tenant-acme", "https://idp.acme.com", uuid.New()))
	require.Nil(t, err)

	newJWKS := "https://idp.acme.com/rotated/jwks.json"
	ready := IssuerStatusReady
	updated, err := dao.Update(ctx, nil, IssuerUpdateInput{
		IssuerID: created.ID,
		JWKSURL:  &newJWKS,
		ClaimMappings: []IssuerClaimMapping{{
			OrgName: "tenant-acme",
			Roles:   []string{"TENANT_ADMIN", "PROVIDER_ADMIN"},
		}},
		Status: &ready,
	})
	require.Nil(t, err)
	assert.Equal(t, newJWKS, updated.JWKSURL)
	require.Len(t, updated.ClaimMappings, 1)
	assert.Equal(t, []string{"TENANT_ADMIN", "PROVIDER_ADMIN"}, updated.ClaimMappings[0].Roles)
	assert.Equal(t, IssuerStatusReady, updated.Status)
	// immutable field unchanged
	assert.Equal(t, "https://idp.acme.com", updated.IssuerURL)
}

func TestIssuerSQLDAO_DuplicateActiveURLRejected(t *testing.T) {
	ctx := context.Background()
	dbSession := util.GetTestDBSession(t, false)
	defer dbSession.Close()
	testIssuerSetupSchema(t, dbSession)

	dao := NewIssuerDAO(dbSession)
	_, err := dao.Create(ctx, nil, testIssuerCreateInput("acme-idp", "tenant-acme", "https://idp.acme.com", uuid.New()))
	require.Nil(t, err)

	// a second active row with the same issuer_url violates the partial unique index
	_, err = dao.Create(ctx, nil, testIssuerCreateInput("acme-dup", "tenant-dup", "https://idp.acme.com", uuid.New()))
	require.Error(t, err)
	assert.True(t, dbSession.GetErrorChecker().IsUniqueConstraintError(err))
}

func TestIssuerSQLDAO_SoftDeleteAndReRegister(t *testing.T) {
	ctx := context.Background()
	dbSession := util.GetTestDBSession(t, false)
	defer dbSession.Close()
	testIssuerSetupSchema(t, dbSession)

	dao := NewIssuerDAO(dbSession)
	created, err := dao.Create(ctx, nil, testIssuerCreateInput("acme-idp", "tenant-acme", "https://idp.acme.com", uuid.New()))
	require.Nil(t, err)

	// soft-delete
	err = dao.Delete(ctx, nil, created.ID)
	require.Nil(t, err)

	// deleted row is excluded from active reads
	_, err = dao.GetByID(ctx, nil, created.ID)
	assert.ErrorIs(t, err, db.ErrDoesNotExist)
	_, err = dao.GetByIssuerURL(ctx, nil, "https://idp.acme.com")
	assert.ErrorIs(t, err, db.ErrDoesNotExist)
	all, err := dao.GetAll(ctx, nil)
	require.Nil(t, err)
	assert.Len(t, all, 0)

	// the same issuer URL can be re-registered after offboard
	recreated, err := dao.Create(ctx, nil, testIssuerCreateInput("acme-idp", "tenant-acme", "https://idp.acme.com", uuid.New()))
	require.Nil(t, err)
	assert.NotEqual(t, created.ID, recreated.ID)
	active, err := dao.GetByIssuerURL(ctx, nil, "https://idp.acme.com")
	require.Nil(t, err)
	assert.Equal(t, recreated.ID, active.ID)
}
