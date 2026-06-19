// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"context"
	"fmt"
	"strings"
	"time"

	cauth "github.com/NVIDIA/infra-controller/rest-api/auth/pkg/config"
	cdb "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db"
	cdbm "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db/model"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

// dbClaimMappingsToAuth copies persisted claim mappings into the auth shape.
func dbClaimMappingsToAuth(in []cdbm.IssuerClaimMapping) []cauth.ClaimMapping {
	out := make([]cauth.ClaimMapping, len(in))
	for i, cm := range in {
		out[i] = cauth.ClaimMapping{
			OrgAttribute:        cm.OrgAttribute,
			OrgDisplayAttribute: cm.OrgDisplayAttribute,
			OrgName:             cm.OrgName,
			OrgDisplayName:      cm.OrgDisplayName,
			RolesAttribute:      cm.RolesAttribute,
			Roles:               cm.Roles,
			IsServiceAccount:    cm.IsServiceAccount,
		}
	}
	return out
}

// jwksConfigForIssuer builds a JwksConfig from a DB Issuer.
func (c *Config) jwksConfigForIssuer(iss *cdbm.Issuer) *cauth.JwksConfig {
	jwksCfg := cauth.NewJwksConfig(iss.Name, iss.JWKSURL, iss.IssuerURL, iss.Origin, iss.ServiceAccount, iss.Audiences, iss.Scopes)
	if iss.JWKSTimeout != "" {
		d, err := time.ParseDuration(iss.JWKSTimeout)
		if err == nil {
			jwksCfg.JWKSTimeout = d
		}
	}

	mappings := dbClaimMappingsToAuth(iss.ClaimMappings)
	for i := range mappings {
		mappings[i].OrgName = strings.ToLower(mappings[i].OrgName)
	}
	jwksCfg.ClaimMappings = mappings
	// The shared reserved-org set is wired in by AddJwksConfig when this config
	// is installed (via ApplyIssuer/SeedIssuersFromDB).
	return jwksCfg
}

// issuerToConfig maps a DB Issuer back to an IssuerConfig for validation.
func (c *Config) issuerToConfig(iss *cdbm.Issuer) IssuerConfig {
	return IssuerConfig{
		Name:                         iss.Name,
		Origin:                       iss.Origin,
		JWKS:                         iss.JWKSURL,
		Issuer:                       iss.IssuerURL,
		ServiceAccount:               iss.ServiceAccount,
		Audiences:                    iss.Audiences,
		Scopes:                       iss.Scopes,
		JWKSTimeout:                  iss.JWKSTimeout,
		ClaimMappings:                dbClaimMappingsToAuth(iss.ClaimMappings),
		AllowDuplicateStaticOrgNames: iss.AllowDuplicateStaticOrgNames,
	}
}

// ValidateRegisteredIssuer validates candidate against the static config issuers
// and all registered DB issuers, excluding excludeID.
func (c *Config) ValidateRegisteredIssuer(ctx context.Context, dbSession *cdb.Session, tx *cdb.Tx, candidate *cdbm.Issuer, excludeID *uuid.UUID) error {
	combined := c.GetIssuersConfig()

	existing, err := cdbm.NewIssuerDAO(dbSession).GetAll(ctx, tx)
	if err != nil {
		return err
	}
	for i := range existing {
		if excludeID != nil && existing[i].ID == *excludeID {
			continue
		}
		combined = append(combined, c.issuerToConfig(&existing[i]))
	}
	combined = append(combined, c.issuerToConfig(candidate))

	return c.ValidateIssuersConfig(combined)
}

// ApplyIssuer hot-applies a DB Issuer into the live JWT origin map.
func (c *Config) ApplyIssuer(iss *cdbm.Issuer) error {
	joCfg := c.GetOrInitJWTOriginConfig()
	if joCfg == nil {
		return fmt.Errorf("JWT origin config not initialized")
	}
	jwksCfg := c.jwksConfigForIssuer(iss)
	joCfg.AddJwksConfig(jwksCfg)
	err := jwksCfg.UpdateJWKS()
	if err != nil {
		return err
	}
	return nil
}

// RemoveIssuer removes an issuer from the live JWT origin map.
func (c *Config) RemoveIssuer(issuerURL string) {
	if c.JwtOriginConfig != nil {
		c.JwtOriginConfig.RemoveConfig(issuerURL)
	}
}

// configStaticOrgNames returns the lowercased static org names declared by the
// statically-configured issuers. Config is immutable after boot, so this is
// cheap to recompute on demand.
func (c *Config) configStaticOrgNames() map[string]bool {
	out := make(map[string]bool)
	for _, issuerCfg := range c.GetIssuersConfig() {
		for _, mapping := range issuerCfg.ClaimMappings {
			if mapping.OrgName != "" {
				out[strings.ToLower(mapping.OrgName)] = true
			}
		}
	}
	return out
}

// RebuildReservedOrgs recomputes the reserved org set from config and DB static orgs.
func (c *Config) RebuildReservedOrgs(ctx context.Context, dbSession *cdb.Session) error {
	joCfg := c.GetOrInitJWTOriginConfig()
	if joCfg == nil {
		return fmt.Errorf("JWT origin config not initialized")
	}

	issuers, err := cdbm.NewIssuerDAO(dbSession).GetAll(ctx, nil)
	if err != nil {
		return err
	}

	union := c.configStaticOrgNames()
	for i := range issuers {
		for _, cm := range issuers[i].ClaimMappings {
			if cm.OrgName != "" {
				union[strings.ToLower(cm.OrgName)] = true
			}
		}
	}

	joCfg.ReplaceReservedOrgs(union)
	return nil
}

// SeedIssuersFromDB applies all registered DB issuers into the live JWT origin map at startup.
// A statically-configured issuer URL is skipped; a JWKS fetch failure is non-fatal.
func (c *Config) SeedIssuersFromDB(ctx context.Context, dbSession *cdb.Session) error {
	joCfg := c.GetOrInitJWTOriginConfig()
	if joCfg == nil {
		return fmt.Errorf("JWT origin config not initialized")
	}

	issuers, err := cdbm.NewIssuerDAO(dbSession).GetAll(ctx, nil)
	if err != nil {
		return err
	}

	issDAO := cdbm.NewIssuerDAO(dbSession)
	for i := range issuers {
		ctxErr := ctx.Err()
		if ctxErr != nil {
			return ctxErr
		}

		iss := &issuers[i]
		if c.IsStaticIssuer(iss.IssuerURL) {
			log.Warn().Str("issuer", iss.IssuerURL).Msg("Skipping DB issuer that is statically configured")
			continue
		}
		jwksCfg := c.jwksConfigForIssuer(iss)
		joCfg.AddJwksConfig(jwksCfg)
		status := cdbm.IssuerStatusReady
		uerr := jwksCfg.UpdateJWKSWithContext(ctx)
		if uerr != nil {
			ctxErr = ctx.Err()
			if ctxErr != nil {
				return ctxErr
			}
			status = cdbm.IssuerStatusPending
			log.Warn().Err(uerr).Str("issuer", iss.IssuerURL).
				Msg("Failed to fetch JWKS for DB-registered issuer at boot; will lazy-refresh on first use")
		}
		if iss.Status != status {
			_, uerr = cdb.WithTxResult(ctx, dbSession, func(tx *cdb.Tx) (*cdbm.Issuer, error) {
				return issDAO.Update(ctx, tx, cdbm.IssuerUpdateInput{IssuerID: iss.ID, Status: &status})
			})
			if uerr != nil {
				return uerr
			}
		}
	}

	rerr := c.RebuildReservedOrgs(ctx, dbSession)
	if rerr != nil {
		return rerr
	}

	log.Info().Int("count", len(issuers)).Msg("Seeded DB-registered issuers into JWT origin config")
	return nil
}

// IsStaticIssuer reports whether the given issuer URL is configured as a static issuer.
func (c *Config) IsStaticIssuer(issuerURL string) bool {
	for _, issuerCfg := range c.GetIssuersConfig() {
		if issuerCfg.Issuer == issuerURL {
			return true
		}
	}
	return false
}
