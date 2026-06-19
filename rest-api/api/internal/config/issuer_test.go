// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	authz "github.com/NVIDIA/infra-controller/rest-api/auth/pkg/authorization"
	cauth "github.com/NVIDIA/infra-controller/rest-api/auth/pkg/config"
	"github.com/NVIDIA/infra-controller/rest-api/auth/pkg/processors"
	testutil "github.com/NVIDIA/infra-controller/rest-api/auth/pkg/testing"
	cdbm "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db/model"
	cdbu "github.com/NVIDIA/infra-controller/rest-api/db/pkg/util"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testIssuerKID = "test-key-id"

// jwksServerForKey serves a single-RSA-key JWKS.
func jwksServerForKey(t *testing.T, key *rsa.PrivateKey) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"keys": []map[string]interface{}{{
				"kty": "RSA",
				"kid": testIssuerKID,
				"use": "sig",
				"alg": "RS256",
				"n":   testutil.EncodeBase64URLBigInt(key.N),
				"e":   testutil.EncodeBase64URLBigInt(big.NewInt(int64(key.E))),
			}},
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func emptyJWKSServer(t *testing.T) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func mintToken(t *testing.T, key *rsa.PrivateKey, issuerURL, sub string) string {
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss":   issuerURL,
		"sub":   sub,
		"email": "user@acme.example",
		"iat":   jwt.NewNumericDate(time.Now()),
		"exp":   jwt.NewNumericDate(time.Now().Add(time.Hour)),
	})
	tok.Header["kid"] = testIssuerKID
	s, err := tok.SignedString(key)
	require.NoError(t, err)
	return s
}

func echoCtxForOrg(routeOrg string) echo.Context {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	ec := e.NewContext(req, httptest.NewRecorder())
	ec.SetParamNames("orgName")
	ec.SetParamValues(routeOrg)
	return ec
}

// TestApplyIssuer_VerifySeam verifies a hot-applied issuer's token is accepted for
// its bound org, rejected for another org, and rejected after deregistration.
func TestApplyIssuer_VerifySeam(t *testing.T) {
	ctx := context.Background()
	dbSession := cdbu.GetTestDBSession(t, false)
	defer dbSession.Close()
	require.Nil(t, dbSession.DB.ResetModel(ctx, (*cdbm.User)(nil)))

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	jwksSrv := jwksServerForKey(t, key)

	cfg := NewConfig()
	cfg.JwtOriginConfig = cauth.NewJWTOriginConfig()
	cfg.JwtOriginConfig.SetProcessorForOrigin(cauth.TokenOriginCustom, processors.NewCustomProcessor(dbSession))

	const issuerURL = "https://idp.acme.example"
	iss := &cdbm.Issuer{
		ID:        uuid.New(),
		Name:      "acme-idp",
		IssuerURL: issuerURL,
		JWKSURL:   jwksSrv.URL,
		Origin:    cauth.TokenOriginCustom,
		ClaimMappings: []cdbm.IssuerClaimMapping{{
			OrgName: "tenant-acme",
			Roles:   []string{authz.TenantAdminRole},
		}},
		Status: cdbm.IssuerStatusPending,
	}

	// Hot-apply the issuer.
	require.NoError(t, cfg.ApplyIssuer(iss))

	jo := cfg.JwtOriginConfig
	require.NotNil(t, jo.GetConfig(issuerURL), "ApplyIssuer must install a JwksConfig keyed by the issuer URL")
	proc := jo.GetProcessorByIssuer(issuerURL)
	require.NotNil(t, proc, "issuer must resolve to the custom processor")

	logger := zerolog.Nop()
	token := mintToken(t, key, issuerURL, "user-1")

	// Own-org request -> accepted, org resolved to the registered binding.
	ecOwn := echoCtxForOrg("tenant-acme")
	user, apiErr := proc.ProcessToken(ecOwn, token, jo.GetConfig(issuerURL), logger)
	require.Nil(t, apiErr, "token from a registered issuer must be accepted for its bound org")
	require.NotNil(t, user)
	_, oerr := user.OrgData.GetOrgByName("tenant-acme")
	assert.NoError(t, oerr, "verified user must carry the issuer's pinned org")

	// Cross-org request (same valid token, different route org) -> rejected.
	ecCross := echoCtxForOrg("tenant-globex")
	_, apiErr = proc.ProcessToken(ecCross, token, jo.GetConfig(issuerURL), logger)
	require.NotNil(t, apiErr, "token bound to tenant-acme must not authorize tenant-globex")
	assert.Equal(t, http.StatusUnauthorized, apiErr.Code)

	// Deregister -> issuer no longer resolves (middleware would return 401).
	cfg.RemoveIssuer(issuerURL)
	assert.Nil(t, jo.GetConfig(issuerURL))
	assert.Nil(t, jo.GetProcessorByIssuer(issuerURL))
}

func TestApplyIssuer_FailedFetchReplacesLiveConfig(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	reachable := jwksServerForKey(t, key)
	unreachable := emptyJWKSServer(t)

	cfg := &Config{
		v:               newViper(),
		JwtOriginConfig: cauth.NewJWTOriginConfig(),
	}

	const issuerURL = "https://idp.acme.example"
	oldCfg := cauth.NewJwksConfig("old-idp", reachable.URL, issuerURL, cauth.TokenOriginCustom, false, nil, nil)
	oldCfg.ClaimMappings = []cauth.ClaimMapping{{OrgName: "tenant-old", Roles: []string{authz.TenantAdminRole}}}
	require.NoError(t, oldCfg.UpdateJWKS())
	require.Positive(t, oldCfg.KeyCount())
	cfg.JwtOriginConfig.AddJwksConfig(oldCfg)

	err = cfg.ApplyIssuer(&cdbm.Issuer{
		ID:        uuid.New(),
		Name:      "new-idp",
		IssuerURL: issuerURL,
		JWKSURL:   unreachable.URL,
		Origin:    cauth.TokenOriginCustom,
		ClaimMappings: []cdbm.IssuerClaimMapping{{
			OrgName: "tenant-new",
			Roles:   []string{authz.TenantAdminRole},
		}},
		Status: cdbm.IssuerStatusPending,
	})

	require.Error(t, err)
	got := cfg.JwtOriginConfig.GetConfig(issuerURL)
	require.NotNil(t, got)
	assert.Equal(t, "new-idp", got.Name)
	assert.Equal(t, unreachable.URL, got.URL)
	assert.Zero(t, got.KeyCount(), "failed hot-apply must not keep old JWKS keys live")
	require.Len(t, got.ClaimMappings, 1)
	assert.Equal(t, "tenant-new", got.ClaimMappings[0].OrgName)
}

// TestSeedIssuersFromDB verifies boot seeding: static-config issuers are skipped,
// an unreachable JWKS is non-fatal, and the reserved org set is the union of
// config-static orgs and the DB issuers' static orgs.
func TestSeedIssuersFromDB(t *testing.T) {
	ctx := context.Background()
	dbSession := cdbu.GetTestDBSession(t, false)
	defer dbSession.Close()
	require.NoError(t, dbSession.DB.ResetModel(ctx, (*cdbm.Issuer)(nil)))

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	reachable := jwksServerForKey(t, key)
	unreachable := emptyJWKSServer(t)

	dao := cdbm.NewIssuerDAO(dbSession)
	// reachable issuer -> applied with keys
	_, err = dao.Create(ctx, nil, cdbm.IssuerCreateInput{
		Name: "reachable", IssuerURL: "https://idp.reachable.example", JWKSURL: reachable.URL, Origin: cauth.TokenOriginCustom,
		ClaimMappings: []cdbm.IssuerClaimMapping{{OrgName: "tenant-reachable", Roles: []string{"TENANT_ADMIN"}}},
		Status:        cdbm.IssuerStatusPending, CreatedBy: uuid.New(),
	})
	require.NoError(t, err)
	// unreachable JWKS -> non-fatal, still installed for lazy refresh
	_, err = dao.Create(ctx, nil, cdbm.IssuerCreateInput{
		Name: "pending", IssuerURL: "https://idp.pending.example", JWKSURL: unreachable.URL, Origin: cauth.TokenOriginCustom,
		ClaimMappings: []cdbm.IssuerClaimMapping{{OrgName: "tenant-pending", Roles: []string{"TENANT_ADMIN"}}},
		Status:        cdbm.IssuerStatusReady, CreatedBy: uuid.New(),
	})
	require.NoError(t, err)
	// issuer URL matching a static config issuer (authn.nvidia.com from config.yaml) -> skipped
	_, err = dao.Create(ctx, nil, cdbm.IssuerCreateInput{
		Name: "shadow-static", IssuerURL: "authn.nvidia.com", JWKSURL: unreachable.URL, Origin: cauth.TokenOriginKasLegacy,
		Status: cdbm.IssuerStatusPending, CreatedBy: uuid.New(),
	})
	require.NoError(t, err)

	cfg := NewConfig()
	cfg.JwtOriginConfig = cauth.NewJWTOriginConfig()

	require.NoError(t, cfg.SeedIssuersFromDB(ctx, dbSession))

	jo := cfg.JwtOriginConfig
	require.NotNil(t, jo.GetConfig("https://idp.reachable.example"))
	assert.Positive(t, jo.GetConfig("https://idp.reachable.example").KeyCount(), "reachable issuer JWKS should be fetched")
	require.NotNil(t, jo.GetConfig("https://idp.pending.example"), "unreachable issuer is still installed for lazy refresh")
	assert.Nil(t, jo.GetConfig("authn.nvidia.com"), "statically-configured issuer URL must be skipped")

	reachableRow, err := dao.GetByIssuerURL(ctx, nil, "https://idp.reachable.example")
	require.NoError(t, err)
	assert.Equal(t, cdbm.IssuerStatusReady, reachableRow.Status)
	pendingRow, err := dao.GetByIssuerURL(ctx, nil, "https://idp.pending.example")
	require.NoError(t, err)
	assert.Equal(t, cdbm.IssuerStatusPending, pendingRow.Status)

	// reserved org set includes the DB issuers' static orgs. Every installed
	// config is wired to the shared set, so assert via a wired config's own
	// ReservedOrgNames (the same read path the auth hot-path uses).
	reachableCfg := jo.GetConfig("https://idp.reachable.example")
	require.NotNil(t, reachableCfg.ReservedOrgNames, "installed config must be wired to the reserved-org set")
	assert.True(t, reachableCfg.ReservedOrgNames.Has("tenant-reachable"))
	assert.True(t, reachableCfg.ReservedOrgNames.Has("tenant-pending"))
}
