// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"context"
	"database/sql"
	"time"

	"github.com/NVIDIA/infra-controller/rest-api/db/pkg/db"
	stracer "github.com/NVIDIA/infra-controller/rest-api/db/pkg/tracer"
	"github.com/google/uuid"

	"github.com/uptrace/bun"
)

const (
	// IssuerStatusPending indicates the issuer's JWKS has not yet been fetched successfully
	IssuerStatusPending = "Pending"
	// IssuerStatusReady indicates the issuer's JWKS has been fetched successfully
	IssuerStatusReady = "Ready"
)

// IssuerClaimMapping is the persisted form of an issuer claim mapping.
type IssuerClaimMapping struct {
	OrgAttribute        string   `json:"orgAttribute,omitempty"`
	OrgDisplayAttribute string   `json:"orgDisplayAttribute,omitempty"`
	OrgName             string   `json:"orgName,omitempty"`
	OrgDisplayName      string   `json:"orgDisplayName,omitempty"`
	RolesAttribute      string   `json:"rolesAttribute,omitempty"`
	Roles               []string `json:"roles,omitempty"`
	IsServiceAccount    bool     `json:"isServiceAccount,omitempty"`
}

// Issuer represents entries in the issuer table
type Issuer struct {
	bun.BaseModel `bun:"table:issuer,alias:iss"`

	ID                           uuid.UUID            `bun:"type:uuid,pk"`
	Name                         string               `bun:"name,notnull"`
	IssuerURL                    string               `bun:"issuer_url,notnull"`
	JWKSURL                      string               `bun:"jwks_url,notnull"`
	Origin                       string               `bun:"origin,notnull"`
	ServiceAccount               bool                 `bun:"service_account,notnull"`
	Audiences                    []string             `bun:"audiences,type:jsonb"`
	Scopes                       []string             `bun:"scopes,type:jsonb"`
	JWKSTimeout                  string               `bun:"jwks_timeout"`
	ClaimMappings                []IssuerClaimMapping `bun:"claim_mappings,type:jsonb"`
	AllowDuplicateStaticOrgNames bool                 `bun:"allow_duplicate_static_org_names,notnull"`
	Status                       string               `bun:"status,notnull"`
	Created                      time.Time            `bun:"created,nullzero,notnull,default:current_timestamp"`
	Updated                      time.Time            `bun:"updated,nullzero,notnull,default:current_timestamp"`
	Deleted                      *time.Time           `bun:"deleted,soft_delete"`
	CreatedBy                    uuid.UUID            `bun:"created_by,type:uuid,notnull"`
}

// IssuerCreateInput input parameters for Create method
type IssuerCreateInput struct {
	Name                         string
	IssuerURL                    string
	JWKSURL                      string
	Origin                       string
	ServiceAccount               bool
	Audiences                    []string
	Scopes                       []string
	JWKSTimeout                  string
	ClaimMappings                []IssuerClaimMapping
	AllowDuplicateStaticOrgNames bool
	Status                       string
	CreatedBy                    uuid.UUID
}

// IssuerUpdateInput input parameters for Update method. IssuerURL and Origin are immutable.
type IssuerUpdateInput struct {
	IssuerID                     uuid.UUID
	Name                         *string
	JWKSURL                      *string
	ServiceAccount               *bool
	Audiences                    []string
	Scopes                       []string
	JWKSTimeout                  *string
	ClaimMappings                []IssuerClaimMapping
	AllowDuplicateStaticOrgNames *bool
	Status                       *string
}

var _ bun.BeforeAppendModelHook = (*Issuer)(nil)

// BeforeAppendModel is a hook that is called before the model is appended to the query
func (iss *Issuer) BeforeAppendModel(_ context.Context, query bun.Query) error {
	switch query.(type) {
	case *bun.InsertQuery:
		iss.Created = db.GetCurTime()
		iss.Updated = db.GetCurTime()
	case *bun.UpdateQuery:
		iss.Updated = db.GetCurTime()
	}
	return nil
}

// IssuerDAO is the data access interface for Issuer
type IssuerDAO interface {
	Create(ctx context.Context, tx *db.Tx, input IssuerCreateInput) (*Issuer, error)
	GetByID(ctx context.Context, tx *db.Tx, id uuid.UUID) (*Issuer, error)
	GetByIssuerURL(ctx context.Context, tx *db.Tx, issuerURL string) (*Issuer, error)
	GetAll(ctx context.Context, tx *db.Tx) ([]Issuer, error)
	Update(ctx context.Context, tx *db.Tx, input IssuerUpdateInput) (*Issuer, error)
	Delete(ctx context.Context, tx *db.Tx, id uuid.UUID) error
}

// IssuerSQLDAO implements IssuerDAO for SQL
type IssuerSQLDAO struct {
	dbSession  *db.Session
	tracerSpan *stracer.TracerSpan
}

// Create creates a new Issuer from the given input
func (isd IssuerSQLDAO) Create(ctx context.Context, tx *db.Tx, input IssuerCreateInput) (*Issuer, error) {
	ctx, issDAOSpan := isd.tracerSpan.CreateChildInCurrentContext(ctx, "IssuerDAO.Create")
	if issDAOSpan != nil {
		defer issDAOSpan.End()

		isd.tracerSpan.SetAttribute(issDAOSpan, "name", input.Name)
	}

	iss := &Issuer{
		ID:                           uuid.New(),
		Name:                         input.Name,
		IssuerURL:                    input.IssuerURL,
		JWKSURL:                      input.JWKSURL,
		Origin:                       input.Origin,
		ServiceAccount:               input.ServiceAccount,
		Audiences:                    input.Audiences,
		Scopes:                       input.Scopes,
		JWKSTimeout:                  input.JWKSTimeout,
		ClaimMappings:                input.ClaimMappings,
		AllowDuplicateStaticOrgNames: input.AllowDuplicateStaticOrgNames,
		Status:                       input.Status,
		CreatedBy:                    input.CreatedBy,
	}

	_, err := db.GetIDB(tx, isd.dbSession).NewInsert().Model(iss).Exec(ctx)
	if err != nil {
		return nil, err
	}

	niss, err := isd.GetByID(ctx, tx, iss.ID)
	if err != nil {
		return nil, err
	}

	return niss, nil
}

// GetByID returns an Issuer by ID
// returns db.ErrDoesNotExist error if the record is not found
func (isd IssuerSQLDAO) GetByID(ctx context.Context, tx *db.Tx, id uuid.UUID) (*Issuer, error) {
	ctx, issDAOSpan := isd.tracerSpan.CreateChildInCurrentContext(ctx, "IssuerDAO.GetByID")
	if issDAOSpan != nil {
		defer issDAOSpan.End()

		isd.tracerSpan.SetAttribute(issDAOSpan, "id", id.String())
	}

	iss := &Issuer{}

	err := db.GetIDB(tx, isd.dbSession).NewSelect().Model(iss).Where("iss.id = ?", id).Scan(ctx)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, db.ErrDoesNotExist
		}
		return nil, err
	}

	return iss, nil
}

// GetByIssuerURL returns an active Issuer by its issuer URL
// returns db.ErrDoesNotExist error if the record is not found
func (isd IssuerSQLDAO) GetByIssuerURL(ctx context.Context, tx *db.Tx, issuerURL string) (*Issuer, error) {
	ctx, issDAOSpan := isd.tracerSpan.CreateChildInCurrentContext(ctx, "IssuerDAO.GetByIssuerURL")
	if issDAOSpan != nil {
		defer issDAOSpan.End()

		isd.tracerSpan.SetAttribute(issDAOSpan, "issuer_url", issuerURL)
	}

	iss := &Issuer{}

	err := db.GetIDB(tx, isd.dbSession).NewSelect().Model(iss).Where("iss.issuer_url = ?", issuerURL).Scan(ctx)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, db.ErrDoesNotExist
		}
		return nil, err
	}

	return iss, nil
}

// GetAll returns all active Issuers
func (isd IssuerSQLDAO) GetAll(ctx context.Context, tx *db.Tx) ([]Issuer, error) {
	ctx, issDAOSpan := isd.tracerSpan.CreateChildInCurrentContext(ctx, "IssuerDAO.GetAll")
	if issDAOSpan != nil {
		defer issDAOSpan.End()
	}

	isss := []Issuer{}

	err := db.GetIDB(tx, isd.dbSession).NewSelect().Model(&isss).Order("iss.created ASC").Scan(ctx)
	if err != nil {
		return nil, err
	}

	return isss, nil
}

// Update updates specified fields of an existing Issuer
func (isd IssuerSQLDAO) Update(ctx context.Context, tx *db.Tx, input IssuerUpdateInput) (*Issuer, error) {
	ctx, issDAOSpan := isd.tracerSpan.CreateChildInCurrentContext(ctx, "IssuerDAO.Update")
	if issDAOSpan != nil {
		defer issDAOSpan.End()

		isd.tracerSpan.SetAttribute(issDAOSpan, "id", input.IssuerID.String())
	}

	iss := &Issuer{
		ID: input.IssuerID,
	}

	updatedFields := []string{}

	if input.Name != nil {
		iss.Name = *input.Name
		updatedFields = append(updatedFields, "name")
	}
	if input.JWKSURL != nil {
		iss.JWKSURL = *input.JWKSURL
		updatedFields = append(updatedFields, "jwks_url")
	}
	if input.ServiceAccount != nil {
		iss.ServiceAccount = *input.ServiceAccount
		updatedFields = append(updatedFields, "service_account")
	}
	if input.Audiences != nil {
		iss.Audiences = input.Audiences
		updatedFields = append(updatedFields, "audiences")
	}
	if input.Scopes != nil {
		iss.Scopes = input.Scopes
		updatedFields = append(updatedFields, "scopes")
	}
	if input.JWKSTimeout != nil {
		iss.JWKSTimeout = *input.JWKSTimeout
		updatedFields = append(updatedFields, "jwks_timeout")
	}
	if input.ClaimMappings != nil {
		iss.ClaimMappings = input.ClaimMappings
		updatedFields = append(updatedFields, "claim_mappings")
	}
	if input.AllowDuplicateStaticOrgNames != nil {
		iss.AllowDuplicateStaticOrgNames = *input.AllowDuplicateStaticOrgNames
		updatedFields = append(updatedFields, "allow_duplicate_static_org_names")
	}
	if input.Status != nil {
		iss.Status = *input.Status
		updatedFields = append(updatedFields, "status")
	}

	if len(updatedFields) > 0 {
		updatedFields = append(updatedFields, "updated")

		_, err := db.GetIDB(tx, isd.dbSession).NewUpdate().Model(iss).Column(updatedFields...).Where("id = ?", input.IssuerID).Exec(ctx)
		if err != nil {
			return nil, err
		}
	}

	niss, err := isd.GetByID(ctx, tx, input.IssuerID)
	if err != nil {
		return nil, err
	}

	return niss, nil
}

// Delete soft-deletes an Issuer by ID
// error is returned only if there is a db error; deleting a non-existent row is a no-op
func (isd IssuerSQLDAO) Delete(ctx context.Context, tx *db.Tx, id uuid.UUID) error {
	ctx, issDAOSpan := isd.tracerSpan.CreateChildInCurrentContext(ctx, "IssuerDAO.Delete")
	if issDAOSpan != nil {
		defer issDAOSpan.End()

		isd.tracerSpan.SetAttribute(issDAOSpan, "id", id.String())
	}

	_, err := db.GetIDB(tx, isd.dbSession).NewDelete().Model((*Issuer)(nil)).Where("id = ?", id).Exec(ctx)
	if err != nil {
		return err
	}

	return nil
}

// NewIssuerDAO creates and returns a new data access object for Issuer
func NewIssuerDAO(dbSession *db.Session) IssuerDAO {
	return IssuerSQLDAO{
		dbSession:  dbSession,
		tracerSpan: stracer.NewTracerSpan(),
	}
}
