// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/NVIDIA/infra-controller/rest-api/api/pkg/api/handler/util/common"
	"github.com/NVIDIA/infra-controller/rest-api/api/pkg/api/model"
	authz "github.com/NVIDIA/infra-controller/rest-api/auth/pkg/authorization"
	cauth "github.com/NVIDIA/infra-controller/rest-api/auth/pkg/config"
	"github.com/NVIDIA/infra-controller/rest-api/common/pkg/otelecho"
	cdb "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db"
	cdbm "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db/model"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testIssuerSetupSchema(t *testing.T, dbSession *cdb.Session) {
	// Only the tables these tests touch: User (for the authenticated caller) and Issuer.
	err := dbSession.DB.ResetModel(context.Background(), (*cdbm.User)(nil))
	assert.Nil(t, err)
	err = dbSession.DB.ResetModel(context.Background(), (*cdbm.Issuer)(nil))
	assert.Nil(t, err)
}

// stub JWKS endpoint returning an empty key set so ApplyIssuer's UpdateJWKS
// fails deterministically (no network/DNS), leaving the row Pending.
func testIssuerJWKSStub(t *testing.T) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestIssuerHandler_Create(t *testing.T) {
	ctx := context.Background()
	dbSession := testInstanceInitDB(t)
	defer dbSession.Close()
	testIssuerSetupSchema(t, dbSession)

	cfg := common.GetTestConfig()
	cfg.JwtOriginConfig = cauth.NewJWTOriginConfig()
	tracer, _, ctx := common.TestCommonTraceProviderSetup(t, ctx)

	jwks := testIssuerJWKSStub(t)

	providerOrg := "test-provider-org"
	providerAdmin := testInstanceBuildUser(t, dbSession, uuid.New().String(), providerOrg, []string{authz.ProviderAdminRole})
	tenantAdmin := testInstanceBuildUser(t, dbSession, uuid.New().String(), providerOrg, []string{authz.TenantAdminRole})
	otherOrgAdmin := testInstanceBuildUser(t, dbSession, uuid.New().String(), "some-other-org", []string{authz.ProviderAdminRole})

	// pre-existing binding to exercise dup-url and dup-static-org rejection.
	// JWKS URLs must be distinct across issuers (config-parity uniqueness); the
	// stub serves the same empty key set for any path.
	issDAO := cdbm.NewIssuerDAO(dbSession)
	_, err := issDAO.Create(ctx, nil, cdbm.IssuerCreateInput{
		Name: "existing", IssuerURL: "https://idp.existing.com", JWKSURL: jwks.URL + "/existing", Origin: "custom",
		ClaimMappings: []cdbm.IssuerClaimMapping{{OrgName: "tenant-existing", Roles: []string{"TENANT_ADMIN"}}},
		Status:        cdbm.IssuerStatusPending, CreatedBy: providerAdmin.ID,
	})
	require.Nil(t, err)

	body := func(name, org, issuerURL string) string {
		return fmt.Sprintf(`{"name":%q,"issuerUrl":%q,"jwksUrl":%q,"claimMappings":[{"orgName":%q,"roles":["TENANT_ADMIN"]}]}`, name, issuerURL, jwks.URL+"/"+name, org)
	}

	tests := []struct {
		name           string
		reqOrgName     string
		user           *cdbm.User
		reqBody        string
		expectedStatus int
	}{
		{"provider admin registers external issuer", providerOrg, providerAdmin, body("acme-idp", "tenant-acme", "https://idp.acme.com"), http.StatusCreated},
		{"tenant admin forbidden", providerOrg, tenantAdmin, body("x", "tenant-x", "https://idp.x.com"), http.StatusForbidden},
		{"non-member forbidden", providerOrg, otherOrgAdmin, body("y", "tenant-y", "https://idp.y.com"), http.StatusForbidden},
		{"invalid issuer url", providerOrg, providerAdmin, body("z", "tenant-z", "not-a-url"), http.StatusBadRequest},
		{"non-custom origin rejected", providerOrg, providerAdmin, fmt.Sprintf(`{"name":"kas-idp","origin":"kas-legacy","issuerUrl":"https://idp.kas.com","jwksUrl":%q,"claimMappings":[{"orgName":"tenant-kas","roles":["TENANT_ADMIN"]}]}`, jwks.URL+"/kas"), http.StatusBadRequest},
		{"top-level service account rejected", providerOrg, providerAdmin, fmt.Sprintf(`{"name":"svc-idp","issuerUrl":"https://idp.svc.com","jwksUrl":%q,"serviceAccount":true,"claimMappings":[{"orgName":"tenant-svc","roles":["TENANT_ADMIN"]}]}`, jwks.URL+"/svc"), http.StatusBadRequest},
		{"missing claim mappings", providerOrg, providerAdmin, fmt.Sprintf(`{"name":"empty-idp","issuerUrl":"https://idp.empty.com","jwksUrl":%q}`, jwks.URL+"/empty"), http.StatusBadRequest},
		{"missing roles", providerOrg, providerAdmin, fmt.Sprintf(`{"name":"n","issuerUrl":"https://idp.n.com","jwksUrl":%q,"claimMappings":[{"orgName":"tenant-n"}]}`, jwks.URL+"/n"), http.StatusBadRequest},
		{"invalid role", providerOrg, providerAdmin, fmt.Sprintf(`{"name":"badrole","issuerUrl":"https://idp.badrole.com","jwksUrl":%q,"claimMappings":[{"orgName":"tenant-badrole","roles":["NOT_A_ROLE"]}]}`, jwks.URL+"/badrole"), http.StatusBadRequest},
		{"duplicate issuer url", providerOrg, providerAdmin, body("dup", "tenant-other", "https://idp.existing.com"), http.StatusConflict},
		// duplicate static org is rejected unless allowDuplicateStaticOrgNames is set (config parity)
		{"duplicate static org rejected", providerOrg, providerAdmin, body("dup-org", "tenant-existing", "https://idp.dup2.com"), http.StatusBadRequest},
		{"duplicate static org allowed with flag", providerOrg, providerAdmin, fmt.Sprintf(`{"name":"flagged","issuerUrl":"https://idp.flagged.com","jwksUrl":%q,"allowDuplicateStaticOrgNames":true,"claimMappings":[{"orgName":"tenant-existing","roles":["TENANT_ADMIN"]}]}`, jwks.URL+"/flagged"), http.StatusCreated},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := echo.New()
			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tc.reqBody))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			ec := e.NewContext(req, rec)
			ec.SetParamNames("orgName")
			ec.SetParamValues(tc.reqOrgName)
			if tc.user != nil {
				ec.Set("user", tc.user)
			}
			ec.SetRequest(ec.Request().WithContext(context.WithValue(ctx, otelecho.TracerKey, tracer)))

			err := NewCreateIssuerHandler(dbSession, cfg).Handle(ec)
			assert.Nil(t, err)
			assert.Equal(t, tc.expectedStatus, rec.Code)

			if tc.expectedStatus == http.StatusCreated {
				rsp := &model.APIIssuer{}
				require.Nil(t, json.Unmarshal(rec.Body.Bytes(), rsp))
				assert.NotEmpty(t, rsp.ID)
				require.Len(t, rsp.ClaimMappings, 1)
				// JWKS stub serves no keys, so the binding persists as Pending.
				assert.Equal(t, cdbm.IssuerStatusPending, rsp.Status)
			}
		})
	}
}

func TestIssuerHandler_Lifecycle(t *testing.T) {
	ctx := context.Background()
	dbSession := testInstanceInitDB(t)
	defer dbSession.Close()
	testIssuerSetupSchema(t, dbSession)

	cfg := common.GetTestConfig()
	cfg.JwtOriginConfig = cauth.NewJWTOriginConfig()
	tracer, _, ctx := common.TestCommonTraceProviderSetup(t, ctx)
	jwks := testIssuerJWKSStub(t)

	providerOrg := "test-provider-org"
	admin := testInstanceBuildUser(t, dbSession, uuid.New().String(), providerOrg, []string{authz.ProviderAdminRole})

	newCtx := func() context.Context { return context.WithValue(ctx, otelecho.TracerKey, tracer) }
	run := func(h interface{ Handle(echo.Context) error }, method, path, id, body string) *httptest.ResponseRecorder {
		e := echo.New()
		req := httptest.NewRequest(method, "/", strings.NewReader(body))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		ec := e.NewContext(req, rec)
		if id != "" {
			ec.SetParamNames("orgName", "id")
			ec.SetParamValues(providerOrg, id)
		} else {
			ec.SetParamNames("orgName")
			ec.SetParamValues(providerOrg)
		}
		ec.Set("user", admin)
		ec.SetRequest(ec.Request().WithContext(newCtx()))
		require.Nil(t, h.Handle(ec))
		return rec
	}

	// Create
	createBody := fmt.Sprintf(`{"name":"acme-idp","issuerUrl":"https://idp.acme.com","jwksUrl":%q,"claimMappings":[{"orgName":"tenant-acme","roles":["TENANT_ADMIN"]}]}`, jwks.URL)
	rec := run(NewCreateIssuerHandler(dbSession, cfg), http.MethodPost, "/issuer", "", createBody)
	require.Equal(t, http.StatusCreated, rec.Code)
	created := &model.APIIssuer{}
	require.Nil(t, json.Unmarshal(rec.Body.Bytes(), created))

	// GetAll
	rec = run(NewGetAllIssuerHandler(dbSession, cfg), http.MethodGet, "/issuer", "", "")
	require.Equal(t, http.StatusOK, rec.Code)
	var list []model.APIIssuer
	require.Nil(t, json.Unmarshal(rec.Body.Bytes(), &list))
	assert.Len(t, list, 1)

	// Get by id
	rec = run(NewGetIssuerHandler(dbSession, cfg), http.MethodGet, "/issuer/:id", created.ID, "")
	assert.Equal(t, http.StatusOK, rec.Code)

	// Get unknown id -> 404
	rec = run(NewGetIssuerHandler(dbSession, cfg), http.MethodGet, "/issuer/:id", uuid.New().String(), "")
	assert.Equal(t, http.StatusNotFound, rec.Code)

	// Get invalid id -> 400
	rec = run(NewGetIssuerHandler(dbSession, cfg), http.MethodGet, "/issuer/:id", "not-a-uuid", "")
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	// Update claim mappings
	rec = run(NewUpdateIssuerHandler(dbSession, cfg), http.MethodPatch, "/issuer/:id", created.ID, `{"claimMappings":[{"orgName":"tenant-acme","roles":["TENANT_ADMIN","PROVIDER_ADMIN"]}]}`)
	require.Equal(t, http.StatusOK, rec.Code)
	updated := &model.APIIssuer{}
	require.Nil(t, json.Unmarshal(rec.Body.Bytes(), updated))
	require.Len(t, updated.ClaimMappings, 1)
	assert.Equal(t, []string{"TENANT_ADMIN", "PROVIDER_ADMIN"}, updated.ClaimMappings[0].Roles)

	// Immutable fields are rejected instead of being silently ignored by the JSON binder.
	rec = run(NewUpdateIssuerHandler(dbSession, cfg), http.MethodPatch, "/issuer/:id", created.ID, `{"issuerUrl":"https://idp.other.com"}`)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	rec = run(NewUpdateIssuerHandler(dbSession, cfg), http.MethodPatch, "/issuer/:id", created.ID, `{"origin":"custom"}`)
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	// Update unknown id -> 404
	rec = run(NewUpdateIssuerHandler(dbSession, cfg), http.MethodPatch, "/issuer/:id", uuid.New().String(), `{}`)
	assert.Equal(t, http.StatusNotFound, rec.Code)

	// Update invalid id -> 400
	rec = run(NewUpdateIssuerHandler(dbSession, cfg), http.MethodPatch, "/issuer/:id", "not-a-uuid", `{}`)
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	// Delete unknown id -> 404
	rec = run(NewDeleteIssuerHandler(dbSession, cfg), http.MethodDelete, "/issuer/:id", uuid.New().String(), "")
	assert.Equal(t, http.StatusNotFound, rec.Code)

	// Delete invalid id -> 400
	rec = run(NewDeleteIssuerHandler(dbSession, cfg), http.MethodDelete, "/issuer/:id", "not-a-uuid", "")
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	// Delete
	rec = run(NewDeleteIssuerHandler(dbSession, cfg), http.MethodDelete, "/issuer/:id", created.ID, "")
	assert.Equal(t, http.StatusAccepted, rec.Code)

	// GetAll now empty
	rec = run(NewGetAllIssuerHandler(dbSession, cfg), http.MethodGet, "/issuer", "", "")
	require.Equal(t, http.StatusOK, rec.Code)
	require.Nil(t, json.Unmarshal(rec.Body.Bytes(), &list))
	assert.Len(t, list, 0)
}

// TestIssuerHandler_Authz asserts every issuer endpoint rejects a non-Provider-Admin caller.
func TestIssuerHandler_Authz(t *testing.T) {
	ctx := context.Background()
	dbSession := testInstanceInitDB(t)
	defer dbSession.Close()
	testIssuerSetupSchema(t, dbSession)

	cfg := common.GetTestConfig()
	cfg.JwtOriginConfig = cauth.NewJWTOriginConfig()
	tracer, _, ctx := common.TestCommonTraceProviderSetup(t, ctx)

	providerOrg := "test-provider-org"
	tenantAdmin := testInstanceBuildUser(t, dbSession, uuid.New().String(), providerOrg, []string{authz.TenantAdminRole})

	run := func(h interface{ Handle(echo.Context) error }, method, id, body string) int {
		e := echo.New()
		req := httptest.NewRequest(method, "/", strings.NewReader(body))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		ec := e.NewContext(req, rec)
		if id != "" {
			ec.SetParamNames("orgName", "id")
			ec.SetParamValues(providerOrg, id)
		} else {
			ec.SetParamNames("orgName")
			ec.SetParamValues(providerOrg)
		}
		ec.Set("user", tenantAdmin)
		ec.SetRequest(ec.Request().WithContext(context.WithValue(ctx, otelecho.TracerKey, tracer)))
		require.Nil(t, h.Handle(ec))
		return rec.Code
	}

	id := uuid.New().String()
	assert.Equal(t, http.StatusForbidden, run(NewCreateIssuerHandler(dbSession, cfg), http.MethodPost, "", `{"name":"x","issuerUrl":"https://idp.x.com","jwksUrl":"https://idp.x.com/jwks"}`))
	assert.Equal(t, http.StatusForbidden, run(NewGetAllIssuerHandler(dbSession, cfg), http.MethodGet, "", ""))
	assert.Equal(t, http.StatusForbidden, run(NewGetIssuerHandler(dbSession, cfg), http.MethodGet, id, ""))
	assert.Equal(t, http.StatusForbidden, run(NewUpdateIssuerHandler(dbSession, cfg), http.MethodPatch, id, `{}`))
	assert.Equal(t, http.StatusForbidden, run(NewDeleteIssuerHandler(dbSession, cfg), http.MethodDelete, id, ""))
}
