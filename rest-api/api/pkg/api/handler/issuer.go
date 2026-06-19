// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"go.opentelemetry.io/otel/attribute"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog"

	"github.com/NVIDIA/infra-controller/rest-api/api/internal/config"
	common "github.com/NVIDIA/infra-controller/rest-api/api/pkg/api/handler/util/common"
	"github.com/NVIDIA/infra-controller/rest-api/api/pkg/api/model"
	auth "github.com/NVIDIA/infra-controller/rest-api/auth/pkg/authorization"
	cauth "github.com/NVIDIA/infra-controller/rest-api/auth/pkg/config"
	cutil "github.com/NVIDIA/infra-controller/rest-api/common/pkg/util"
	cdb "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db"
	cdbm "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db/model"
)

const issuerRegistrationLockName = "issuer-registration"

func acquireIssuerRegistrationLock(ctx context.Context, tx *cdb.Tx) error {
	return tx.TryAcquireAdvisoryLock(ctx, cdb.GetAdvisoryLockIDFromString(issuerRegistrationLockName), nil)
}

func bindIssuerUpdateRequest(c echo.Context, apiRequest *model.APIIssuerUpdateRequest) (string, error) {
	body, err := io.ReadAll(c.Request().Body)
	if err != nil {
		return "", err
	}

	raw := map[string]json.RawMessage{}
	err = json.Unmarshal(body, &raw)
	if err != nil {
		return "", err
	}

	for _, field := range []string{"issuerUrl", "origin"} {
		_, ok := raw[field]
		if ok {
			return field, nil
		}
	}

	return "", json.Unmarshal(body, apiRequest)
}

func overlayIssuerUpdate(existing *cdbm.Issuer, apiRequest model.APIIssuerUpdateRequest, claimMappings []cdbm.IssuerClaimMapping) cdbm.Issuer {
	candidate := *existing
	if apiRequest.Name != nil {
		candidate.Name = *apiRequest.Name
	}
	if apiRequest.JWKSURL != nil {
		candidate.JWKSURL = *apiRequest.JWKSURL
	}
	if apiRequest.ServiceAccount != nil {
		candidate.ServiceAccount = *apiRequest.ServiceAccount
	}
	if apiRequest.Audiences != nil {
		candidate.Audiences = apiRequest.Audiences
	}
	if apiRequest.Scopes != nil {
		candidate.Scopes = apiRequest.Scopes
	}
	if apiRequest.JWKSTimeout != nil {
		candidate.JWKSTimeout = *apiRequest.JWKSTimeout
	}
	if claimMappings != nil {
		candidate.ClaimMappings = claimMappings
	}
	if apiRequest.AllowDuplicateStaticOrgNames != nil {
		candidate.AllowDuplicateStaticOrgNames = *apiRequest.AllowDuplicateStaticOrgNames
	}
	return candidate
}

// applyIssuerAndReconcile hot-applies iss into the live JWT origin map, settles
// its persisted status (Ready when the JWKS is reachable, Pending otherwise,
// writing back only on change), and rebuilds the reserved-org set. It returns
// the issuer reflecting any status change. Shared by the create and update
// handlers, which previously duplicated this block.
func applyIssuerAndReconcile(ctx context.Context, cfg *config.Config, dbSession *cdb.Session, iss *cdbm.Issuer, logger zerolog.Logger) *cdbm.Issuer {
	status := cdbm.IssuerStatusReady
	aerr := cfg.ApplyIssuer(iss)
	if aerr != nil {
		logger.Warn().Err(aerr).Str("issuer_url", iss.IssuerURL).Msg("issuer JWKS not yet reachable; persisting as Pending")
		status = cdbm.IssuerStatusPending
	}
	if status != iss.Status {
		issDAO := cdbm.NewIssuerDAO(dbSession)
		updated, uerr := cdb.WithTxResult(ctx, dbSession, func(tx *cdb.Tx) (*cdbm.Issuer, error) {
			return issDAO.Update(ctx, tx, cdbm.IssuerUpdateInput{IssuerID: iss.ID, Status: &status})
		})
		if uerr != nil {
			logger.Error().Err(uerr).Str("issuer_url", iss.IssuerURL).Msg("failed to update issuer status after apply")
		} else {
			iss = updated
		}
	}
	rerr := cfg.RebuildReservedOrgs(ctx, dbSession)
	if rerr != nil {
		logger.Error().Err(rerr).Msg("failed to rebuild reserved org set after issuer apply")
	}
	return iss
}

// ~~~~~ Create Handler ~~~~~ //

// CreateIssuerHandler is the API Handler for registering a new Issuer binding
type CreateIssuerHandler struct {
	dbSession  *cdb.Session
	cfg        *config.Config
	tracerSpan *cutil.TracerSpan
}

// NewCreateIssuerHandler initializes and returns a new handler for registering an Issuer
func NewCreateIssuerHandler(dbSession *cdb.Session, cfg *config.Config) CreateIssuerHandler {
	return CreateIssuerHandler{
		dbSession:  dbSession,
		cfg:        cfg,
		tracerSpan: cutil.NewTracerSpan(),
	}
}

// Handle godoc
// @Summary Register an OIDC issuer binding
// @Description Register an OIDC issuer-to-org trust binding. Provider Admin only.
// @Tags Issuer
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param org path string true "Name of NGC organization (provider org)"
// @Param message body model.APIIssuerCreateRequest true "Issuer registration request"
// @Success 201 {object} model.APIIssuer
// @Router /v2/org/{org}/nico/issuer [post]
func (cih CreateIssuerHandler) Handle(c echo.Context) error {
	org, dbUser, ctx, logger, handlerSpan := common.SetupHandler("Issuer", "Create", c, cih.tracerSpan)
	if handlerSpan != nil {
		defer handlerSpan.End()
	}

	if dbUser == nil {
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve current user", nil)
	}

	// Validate org
	ok, err := auth.ValidateOrgMembership(dbUser, org)
	if !ok {
		if err != nil {
			logger.Error().Err(err).Msg("error validating org membership for User in request")
		} else {
			logger.Warn().Msg("could not validate org membership for user, access denied")
		}
		return cutil.NewAPIErrorResponse(c, http.StatusForbidden, fmt.Sprintf("Failed to validate membership for org: %s", org), nil)
	}

	// Validate role, only Provider Admins are allowed to interact with Issuer endpoints
	ok = auth.ValidateUserRoles(dbUser, org, nil, auth.ProviderAdminRole)
	if !ok {
		logger.Warn().Msg("user does not have Provider Admin role, access denied")
		return cutil.NewAPIErrorResponse(c, http.StatusForbidden, "User does not have Provider Admin role with org", nil)
	}

	apiRequest := model.APIIssuerCreateRequest{}
	err = c.Bind(&apiRequest)
	if err != nil {
		logger.Warn().Err(err).Msg("error binding request data into API model")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Failed to parse request data, potentially invalid structure", nil)
	}
	verr := apiRequest.Validate()
	if verr != nil {
		logger.Warn().Err(verr).Msg("error validating Issuer creation request data")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Error validating Issuer creation request data", verr)
	}

	cih.tracerSpan.SetAttribute(handlerSpan, attribute.String("issuer_url", apiRequest.IssuerURL), logger)

	// a statically-configured issuer cannot be registered
	if cih.cfg.IsStaticIssuer(apiRequest.IssuerURL) {
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Cannot register a statically-configured issuer", nil)
	}

	origin := apiRequest.Origin
	if origin == "" {
		origin = cauth.TokenOriginCustom
	} else {
		normalized, oerr := config.ParseOriginString(origin)
		if oerr != nil {
			return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, fmt.Sprintf("Invalid origin: %s", origin), nil)
		}
		origin = normalized
	}
	if origin != cauth.TokenOriginCustom {
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Dynamic issuer registration only supports custom origins", nil)
	}

	candidate := &cdbm.Issuer{
		Name:                         apiRequest.Name,
		IssuerURL:                    apiRequest.IssuerURL,
		JWKSURL:                      apiRequest.JWKSURL,
		Origin:                       origin,
		ServiceAccount:               apiRequest.ServiceAccount,
		Audiences:                    apiRequest.Audiences,
		Scopes:                       apiRequest.Scopes,
		JWKSTimeout:                  apiRequest.JWKSTimeout,
		ClaimMappings:                model.APIClaimMappings(apiRequest.ClaimMappings).ToDB(),
		AllowDuplicateStaticOrgNames: apiRequest.AllowDuplicateStaticOrgNames,
	}

	issDAO := cdbm.NewIssuerDAO(cih.dbSession)

	iss, err := cdb.WithTxResult(ctx, cih.dbSession, func(tx *cdb.Tx) (*cdbm.Issuer, error) {
		derr := acquireIssuerRegistrationLock(ctx, tx)
		if derr != nil {
			logger.Error().Err(derr).Msg("failed to acquire issuer registration advisory lock")
			return nil, cutil.NewAPIError(http.StatusInternalServerError, "Failed to register issuer, unable to acquire lock", nil)
		}

		verr := cih.cfg.ValidateRegisteredIssuer(ctx, cih.dbSession, tx, candidate, nil)
		if verr != nil {
			logger.Warn().Err(verr).Msg("issuer registration rejected by config validation")
			return nil, cutil.NewAPIError(http.StatusBadRequest, fmt.Sprintf("Invalid issuer registration: %s", verr), nil)
		}

		return issDAO.Create(ctx, tx, cdbm.IssuerCreateInput{
			Name:                         apiRequest.Name,
			IssuerURL:                    apiRequest.IssuerURL,
			JWKSURL:                      apiRequest.JWKSURL,
			Origin:                       origin,
			ServiceAccount:               apiRequest.ServiceAccount,
			Audiences:                    apiRequest.Audiences,
			Scopes:                       apiRequest.Scopes,
			JWKSTimeout:                  apiRequest.JWKSTimeout,
			ClaimMappings:                candidate.ClaimMappings,
			AllowDuplicateStaticOrgNames: apiRequest.AllowDuplicateStaticOrgNames,
			Status:                       cdbm.IssuerStatusPending,
			CreatedBy:                    dbUser.ID,
		})
	})
	if err != nil {
		if cih.dbSession.GetErrorChecker().IsUniqueConstraintError(err) {
			return cutil.NewAPIErrorResponse(c, http.StatusConflict, "An issuer with this issuerUrl is already registered", validation.Errors{
				"issuerUrl": errors.New("already registered"),
			})
		}
		return common.HandleTxError(c, logger, err, "Failed to register issuer due to DB transaction error")
	}

	// Hot-apply into the live JWT origin map and settle status + reserved orgs.
	iss = applyIssuerAndReconcile(ctx, cih.cfg, cih.dbSession, iss, logger)

	logger.Info().Str("issuer_url", iss.IssuerURL).Str("status", iss.Status).Msg("finishing API handler")
	return c.JSON(http.StatusCreated, model.NewAPIIssuer(iss))
}

// ~~~~~ GetAll Handler ~~~~~ //

// GetAllIssuerHandler is the API Handler for listing registered Issuers
type GetAllIssuerHandler struct {
	dbSession  *cdb.Session
	cfg        *config.Config
	tracerSpan *cutil.TracerSpan
}

// NewGetAllIssuerHandler initializes and returns a new handler for listing Issuers
func NewGetAllIssuerHandler(dbSession *cdb.Session, cfg *config.Config) GetAllIssuerHandler {
	return GetAllIssuerHandler{
		dbSession:  dbSession,
		cfg:        cfg,
		tracerSpan: cutil.NewTracerSpan(),
	}
}

// Handle godoc
// @Summary List registered OIDC issuer bindings
// @Description List all registered OIDC issuer bindings. Provider Admin only.
// @Tags Issuer
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param org path string true "Name of NGC organization (provider org)"
// @Success 200 {array} []model.APIIssuer
// @Router /v2/org/{org}/nico/issuer [get]
func (gaih GetAllIssuerHandler) Handle(c echo.Context) error {
	org, dbUser, ctx, logger, handlerSpan := common.SetupHandler("Issuer", "GetAll", c, gaih.tracerSpan)
	if handlerSpan != nil {
		defer handlerSpan.End()
	}

	if dbUser == nil {
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve current user", nil)
	}

	// Validate org
	ok, err := auth.ValidateOrgMembership(dbUser, org)
	if !ok {
		if err != nil {
			logger.Error().Err(err).Msg("error validating org membership for User in request")
		} else {
			logger.Warn().Msg("could not validate org membership for user, access denied")
		}
		return cutil.NewAPIErrorResponse(c, http.StatusForbidden, fmt.Sprintf("Failed to validate membership for org: %s", org), nil)
	}

	// Validate role, only Provider Admins are allowed to interact with Issuer endpoints
	ok = auth.ValidateUserRoles(dbUser, org, nil, auth.ProviderAdminRole)
	if !ok {
		logger.Warn().Msg("user does not have Provider Admin role, access denied")
		return cutil.NewAPIErrorResponse(c, http.StatusForbidden, "User does not have Provider Admin role with org", nil)
	}

	issuers, err := cdbm.NewIssuerDAO(gaih.dbSession).GetAll(ctx, nil)
	if err != nil {
		logger.Error().Err(err).Msg("error retrieving Issuers")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve issuers due to data store error", nil)
	}

	apiIssuers := []model.APIIssuer{}
	for i := range issuers {
		apiIssuers = append(apiIssuers, *model.NewAPIIssuer(&issuers[i]))
	}

	logger.Info().Msg("finishing API handler")
	return c.JSON(http.StatusOK, apiIssuers)
}

// ~~~~~ Get Handler ~~~~~ //

// GetIssuerHandler is the API Handler for getting a single Issuer
type GetIssuerHandler struct {
	dbSession  *cdb.Session
	cfg        *config.Config
	tracerSpan *cutil.TracerSpan
}

// NewGetIssuerHandler initializes and returns a new handler for getting an Issuer
func NewGetIssuerHandler(dbSession *cdb.Session, cfg *config.Config) GetIssuerHandler {
	return GetIssuerHandler{
		dbSession:  dbSession,
		cfg:        cfg,
		tracerSpan: cutil.NewTracerSpan(),
	}
}

// Handle godoc
// @Summary Get a registered OIDC issuer binding
// @Description Get a registered OIDC issuer binding by ID. Provider Admin only.
// @Tags Issuer
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param org path string true "Name of NGC organization (provider org)"
// @Param id path string true "ID of Issuer"
// @Success 200 {object} model.APIIssuer
// @Router /v2/org/{org}/nico/issuer/{id} [get]
func (gih GetIssuerHandler) Handle(c echo.Context) error {
	org, dbUser, ctx, logger, handlerSpan := common.SetupHandler("Issuer", "Get", c, gih.tracerSpan)
	if handlerSpan != nil {
		defer handlerSpan.End()
	}

	if dbUser == nil {
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve current user", nil)
	}

	// Validate org
	ok, err := auth.ValidateOrgMembership(dbUser, org)
	if !ok {
		if err != nil {
			logger.Error().Err(err).Msg("error validating org membership for User in request")
		} else {
			logger.Warn().Msg("could not validate org membership for user, access denied")
		}
		return cutil.NewAPIErrorResponse(c, http.StatusForbidden, fmt.Sprintf("Failed to validate membership for org: %s", org), nil)
	}

	// Validate role, only Provider Admins are allowed to interact with Issuer endpoints
	ok = auth.ValidateUserRoles(dbUser, org, nil, auth.ProviderAdminRole)
	if !ok {
		logger.Warn().Msg("user does not have Provider Admin role, access denied")
		return cutil.NewAPIErrorResponse(c, http.StatusForbidden, "User does not have Provider Admin role with org", nil)
	}

	issID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Invalid Issuer ID in URL", nil)
	}

	iss, err := cdbm.NewIssuerDAO(gih.dbSession).GetByID(ctx, nil, issID)
	if err != nil {
		if err == cdb.ErrDoesNotExist {
			return cutil.NewAPIErrorResponse(c, http.StatusNotFound, "Could not find issuer", nil)
		}
		logger.Error().Err(err).Msg("error retrieving Issuer from DB")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve issuer due to data store error", nil)
	}

	logger.Info().Msg("finishing API handler")
	return c.JSON(http.StatusOK, model.NewAPIIssuer(iss))
}

// ~~~~~ Update Handler ~~~~~ //

// UpdateIssuerHandler is the API Handler for updating an Issuer binding
type UpdateIssuerHandler struct {
	dbSession  *cdb.Session
	cfg        *config.Config
	tracerSpan *cutil.TracerSpan
}

// NewUpdateIssuerHandler initializes and returns a new handler for updating an Issuer
func NewUpdateIssuerHandler(dbSession *cdb.Session, cfg *config.Config) UpdateIssuerHandler {
	return UpdateIssuerHandler{
		dbSession:  dbSession,
		cfg:        cfg,
		tracerSpan: cutil.NewTracerSpan(),
	}
}

// Handle godoc
// @Summary Update a registered OIDC issuer binding
// @Description Update a registered OIDC issuer binding (JWKS URL, roles, audiences). Provider Admin only.
// @Tags Issuer
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param org path string true "Name of NGC organization (provider org)"
// @Param id path string true "ID of Issuer"
// @Param message body model.APIIssuerUpdateRequest true "Issuer update request"
// @Success 200 {object} model.APIIssuer
// @Router /v2/org/{org}/nico/issuer/{id} [patch]
func (uih UpdateIssuerHandler) Handle(c echo.Context) error {
	org, dbUser, ctx, logger, handlerSpan := common.SetupHandler("Issuer", "Update", c, uih.tracerSpan)
	if handlerSpan != nil {
		defer handlerSpan.End()
	}

	if dbUser == nil {
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve current user", nil)
	}

	// Validate org
	ok, err := auth.ValidateOrgMembership(dbUser, org)
	if !ok {
		if err != nil {
			logger.Error().Err(err).Msg("error validating org membership for User in request")
		} else {
			logger.Warn().Msg("could not validate org membership for user, access denied")
		}
		return cutil.NewAPIErrorResponse(c, http.StatusForbidden, fmt.Sprintf("Failed to validate membership for org: %s", org), nil)
	}

	// Validate role, only Provider Admins are allowed to interact with Issuer endpoints
	ok = auth.ValidateUserRoles(dbUser, org, nil, auth.ProviderAdminRole)
	if !ok {
		logger.Warn().Msg("user does not have Provider Admin role, access denied")
		return cutil.NewAPIErrorResponse(c, http.StatusForbidden, "User does not have Provider Admin role with org", nil)
	}

	issID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Invalid Issuer ID in URL", nil)
	}

	apiRequest := model.APIIssuerUpdateRequest{}
	immutableField, err := bindIssuerUpdateRequest(c, &apiRequest)
	if err != nil {
		logger.Warn().Err(err).Msg("error binding request data into API model")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Failed to parse request data, potentially invalid structure", nil)
	}
	if immutableField != "" {
		logger.Warn().Str("field", immutableField).Msg("immutable issuer field specified in update request")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Issuer update contains immutable field", validation.Errors{
			immutableField: errors.New("field is immutable"),
		})
	}
	verr := apiRequest.Validate()
	if verr != nil {
		logger.Warn().Err(verr).Msg("error validating Issuer update request data")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Error validating Issuer update data", verr)
	}

	issDAO := cdbm.NewIssuerDAO(uih.dbSession)
	claimMappings := model.APIClaimMappings(apiRequest.ClaimMappings).ToDB()

	iss, err := cdb.WithTxResult(ctx, uih.dbSession, func(tx *cdb.Tx) (*cdbm.Issuer, error) {
		derr := acquireIssuerRegistrationLock(ctx, tx)
		if derr != nil {
			logger.Error().Err(derr).Msg("failed to acquire issuer registration advisory lock")
			return nil, cutil.NewAPIError(http.StatusInternalServerError, "Failed to update issuer, unable to acquire lock", nil)
		}

		existing, derr := issDAO.GetByID(ctx, tx, issID)
		if derr != nil {
			if derr == cdb.ErrDoesNotExist {
				return nil, cutil.NewAPIError(http.StatusNotFound, "Could not find issuer to update", nil)
			}
			logger.Error().Err(derr).Msg("error retrieving Issuer from DB")
			return nil, cutil.NewAPIError(http.StatusInternalServerError, "Could not find issuer due to data store error", nil)
		}

		candidate := overlayIssuerUpdate(existing, apiRequest, claimMappings)
		verr := uih.cfg.ValidateRegisteredIssuer(ctx, uih.dbSession, tx, &candidate, &issID)
		if verr != nil {
			logger.Warn().Err(verr).Msg("issuer update rejected by config validation")
			return nil, cutil.NewAPIError(http.StatusBadRequest, fmt.Sprintf("Invalid issuer update: %s", verr), nil)
		}

		return issDAO.Update(ctx, tx, cdbm.IssuerUpdateInput{
			IssuerID:                     issID,
			Name:                         apiRequest.Name,
			JWKSURL:                      apiRequest.JWKSURL,
			ServiceAccount:               apiRequest.ServiceAccount,
			Audiences:                    apiRequest.Audiences,
			Scopes:                       apiRequest.Scopes,
			JWKSTimeout:                  apiRequest.JWKSTimeout,
			ClaimMappings:                claimMappings,
			AllowDuplicateStaticOrgNames: apiRequest.AllowDuplicateStaticOrgNames,
		})
	})
	if err != nil {
		return common.HandleTxError(c, logger, err, "Failed to update issuer due to DB transaction error")
	}

	// Re-apply into the live JWT origin map and settle status + reserved orgs.
	iss = applyIssuerAndReconcile(ctx, uih.cfg, uih.dbSession, iss, logger)

	logger.Info().Str("issuer_url", iss.IssuerURL).Str("status", iss.Status).Msg("finishing API handler")
	return c.JSON(http.StatusOK, model.NewAPIIssuer(iss))
}

// ~~~~~ Delete Handler ~~~~~ //

// DeleteIssuerHandler is the API Handler for deregistering an Issuer binding
type DeleteIssuerHandler struct {
	dbSession  *cdb.Session
	cfg        *config.Config
	tracerSpan *cutil.TracerSpan
}

// NewDeleteIssuerHandler initializes and returns a new handler for deregistering an Issuer
func NewDeleteIssuerHandler(dbSession *cdb.Session, cfg *config.Config) DeleteIssuerHandler {
	return DeleteIssuerHandler{
		dbSession:  dbSession,
		cfg:        cfg,
		tracerSpan: cutil.NewTracerSpan(),
	}
}

// Handle godoc
// @Summary Deregister an OIDC issuer binding
// @Description Deregister (soft-delete) an OIDC issuer binding. Provider Admin only.
// @Tags Issuer
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param org path string true "Name of NGC organization (provider org)"
// @Param id path string true "ID of Issuer"
// @Success 202
// @Router /v2/org/{org}/nico/issuer/{id} [delete]
func (dih DeleteIssuerHandler) Handle(c echo.Context) error {
	org, dbUser, ctx, logger, handlerSpan := common.SetupHandler("Issuer", "Delete", c, dih.tracerSpan)
	if handlerSpan != nil {
		defer handlerSpan.End()
	}

	if dbUser == nil {
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve current user", nil)
	}

	// Validate org
	ok, err := auth.ValidateOrgMembership(dbUser, org)
	if !ok {
		if err != nil {
			logger.Error().Err(err).Msg("error validating org membership for User in request")
		} else {
			logger.Warn().Msg("could not validate org membership for user, access denied")
		}
		return cutil.NewAPIErrorResponse(c, http.StatusForbidden, fmt.Sprintf("Failed to validate membership for org: %s", org), nil)
	}

	// Validate role, only Provider Admins are allowed to interact with Issuer endpoints
	ok = auth.ValidateUserRoles(dbUser, org, nil, auth.ProviderAdminRole)
	if !ok {
		logger.Warn().Msg("user does not have Provider Admin role, access denied")
		return cutil.NewAPIErrorResponse(c, http.StatusForbidden, "User does not have Provider Admin role with org", nil)
	}

	issID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Invalid Issuer ID in URL", nil)
	}

	issDAO := cdbm.NewIssuerDAO(dih.dbSession)
	iss, err := issDAO.GetByID(ctx, nil, issID)
	if err != nil {
		if err == cdb.ErrDoesNotExist {
			return cutil.NewAPIErrorResponse(c, http.StatusNotFound, "Could not find issuer with specified ID", nil)
		}
		logger.Error().Err(err).Msg("error retrieving Issuer from DB")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve issuer due to data store error", nil)
	}

	err = cdb.WithTx(ctx, dih.dbSession, func(tx *cdb.Tx) error {
		return issDAO.Delete(ctx, tx, issID)
	})
	if err != nil {
		return common.HandleTxError(c, logger, err, "Failed to deregister issuer due to DB transaction error")
	}

	// Remove from the live map.
	dih.cfg.RemoveIssuer(iss.IssuerURL)

	rerr := dih.cfg.RebuildReservedOrgs(ctx, dih.dbSession)
	if rerr != nil {
		logger.Error().Err(rerr).Msg("failed to rebuild reserved org set after issuer delete")
	}

	logger.Info().Str("issuer_url", iss.IssuerURL).Msg("finishing API handler")
	return c.String(http.StatusAccepted, "Deletion request was accepted")
}
