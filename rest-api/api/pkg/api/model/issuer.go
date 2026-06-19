// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"errors"
	"time"

	"github.com/NVIDIA/infra-controller/rest-api/api/pkg/api/model/util"
	cauth "github.com/NVIDIA/infra-controller/rest-api/auth/pkg/config"
	cdbm "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db/model"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	validationis "github.com/go-ozzo/ozzo-validation/v4/is"
)

// APIClaimMapping is the API representation of an issuer claim mapping
type APIClaimMapping struct {
	// OrgAttribute is the JWT claim path to extract org name (dynamic mapping)
	OrgAttribute string `json:"orgAttribute,omitempty"`
	// OrgDisplayAttribute is the JWT claim path for org display name (dynamic mapping)
	OrgDisplayAttribute string `json:"orgDisplayAttribute,omitempty"`
	// OrgName is the fixed organization name (static mapping)
	OrgName string `json:"orgName,omitempty"`
	// OrgDisplayName is the display name for a static org mapping
	OrgDisplayName string `json:"orgDisplayName,omitempty"`
	// RolesAttribute is the JWT claim path to extract roles (dynamic roles)
	RolesAttribute string `json:"rolesAttribute,omitempty"`
	// Roles is the static role list
	Roles []string `json:"roles,omitempty"`
	// IsServiceAccount assigns service-account roles
	IsServiceAccount bool `json:"isServiceAccount,omitempty"`
}

// validateClaimMappingRoles checks a mapping's static roles against the allowed set
func validateClaimMappingRoles(value any) error {
	cm, ok := value.(APIClaimMapping)
	if !ok {
		return nil
	}
	for _, role := range cm.Roles {
		if !cauth.IsValidRole(role) {
			return errors.New(validationErrorInvalidRole)
		}
	}
	return nil
}

// APIIssuerCreateRequest is the data structure to capture a request to register an OIDC issuer binding
type APIIssuerCreateRequest struct {
	// Name is a human-readable name for the issuer binding
	Name string `json:"name"`
	// IssuerURL is the expected "iss" claim value
	IssuerURL string `json:"issuerUrl"`
	// JWKSURL is the JWKS endpoint used to verify token signatures
	JWKSURL string `json:"jwksUrl"`
	// Origin is the token origin type (defaults to "custom" when empty)
	Origin string `json:"origin"`
	// ServiceAccount marks the issuer as a service-account issuer
	ServiceAccount bool `json:"serviceAccount"`
	// Audiences are the allowed audience values
	Audiences []string `json:"audiences"`
	// Scopes are the required scopes
	Scopes []string `json:"scopes"`
	// JWKSTimeout is the JWKS fetch timeout (e.g. "5s", "1m")
	JWKSTimeout string `json:"jwksTimeout"`
	// ClaimMappings map token claims to org and roles
	ClaimMappings []APIClaimMapping `json:"claimMappings"`
	// AllowDuplicateStaticOrgNames allows this issuer's static orgs to duplicate others
	AllowDuplicateStaticOrgNames bool `json:"allowDuplicateStaticOrgNames"`
}

// Validate ensures that the values passed in the request are acceptable
func (icr APIIssuerCreateRequest) Validate() error {
	return validation.ValidateStruct(&icr,
		validation.Field(&icr.Name,
			validation.Required.Error(validationErrorStringLength),
			validation.By(util.ValidateNameCharacters),
			validation.Length(2, 256).Error(validationErrorStringLength)),
		validation.Field(&icr.IssuerURL,
			validation.Required.Error(validationErrorValueRequired),
			validationis.URL.Error(validationErrorInvalidURL)),
		validation.Field(&icr.JWKSURL,
			validation.Required.Error(validationErrorValueRequired),
			validationis.URL.Error(validationErrorInvalidURL)),
		validation.Field(&icr.ClaimMappings,
			validation.Each(validation.By(validateClaimMappingRoles))),
	)
}

// APIIssuerUpdateRequest is the data structure to capture a request to update an issuer binding.
// IssuerURL and Origin are immutable and therefore not updatable.
type APIIssuerUpdateRequest struct {
	// Name is a human-readable name for the issuer binding
	Name *string `json:"name"`
	// JWKSURL is the JWKS endpoint used to verify token signatures
	JWKSURL *string `json:"jwksUrl"`
	// ServiceAccount marks the issuer as a service-account issuer
	ServiceAccount *bool `json:"serviceAccount"`
	// Audiences are the allowed audience values
	Audiences []string `json:"audiences"`
	// Scopes are the required scopes
	Scopes []string `json:"scopes"`
	// JWKSTimeout is the JWKS fetch timeout (e.g. "5s", "1m")
	JWKSTimeout *string `json:"jwksTimeout"`
	// ClaimMappings map token claims to org and roles
	ClaimMappings []APIClaimMapping `json:"claimMappings"`
	// AllowDuplicateStaticOrgNames allows this issuer's static orgs to duplicate others
	AllowDuplicateStaticOrgNames *bool `json:"allowDuplicateStaticOrgNames"`
}

// Validate ensures that the values passed in the request are acceptable
func (iur APIIssuerUpdateRequest) Validate() error {
	return validation.ValidateStruct(&iur,
		validation.Field(&iur.Name,
			validation.When(iur.Name != nil, validation.Required.Error(validationErrorStringLength)),
			validation.When(iur.Name != nil, validation.By(util.ValidateNameCharacters)),
			validation.When(iur.Name != nil, validation.Length(2, 256).Error(validationErrorStringLength))),
		validation.Field(&iur.JWKSURL,
			validation.When(iur.JWKSURL != nil, validationis.URL.Error(validationErrorInvalidURL))),
		validation.Field(&iur.ClaimMappings,
			validation.Each(validation.By(validateClaimMappingRoles))),
	)
}

// APIIssuer is the API representation of a registered issuer binding
type APIIssuer struct {
	// ID is the unique UUID v4 identifier for the Issuer
	ID string `json:"id"`
	// Name is the human-readable name for the issuer binding
	Name string `json:"name"`
	// IssuerURL is the expected "iss" claim value
	IssuerURL string `json:"issuerUrl"`
	// JWKSURL is the JWKS endpoint used to verify token signatures
	JWKSURL string `json:"jwksUrl"`
	// Origin is the token origin type
	Origin string `json:"origin"`
	// ServiceAccount marks the issuer as a service-account issuer
	ServiceAccount bool `json:"serviceAccount"`
	// Audiences are the allowed audience values
	Audiences []string `json:"audiences,omitempty"`
	// Scopes are the required scopes
	Scopes []string `json:"scopes,omitempty"`
	// JWKSTimeout is the JWKS fetch timeout
	JWKSTimeout string `json:"jwksTimeout,omitempty"`
	// ClaimMappings map token claims to org and roles
	ClaimMappings []APIClaimMapping `json:"claimMappings,omitempty"`
	// AllowDuplicateStaticOrgNames allows this issuer's static orgs to duplicate others
	AllowDuplicateStaticOrgNames bool `json:"allowDuplicateStaticOrgNames"`
	// Status indicates whether the issuer's JWKS has been fetched successfully
	Status string `json:"status"`
	// Created indicates the ISO datetime string for when the Issuer was created
	Created time.Time `json:"created"`
	// Updated indicates the ISO datetime string for when the Issuer was last updated
	Updated time.Time `json:"updated"`
}

// APIClaimMappings is a list of API claim mappings with DB conversions.
type APIClaimMappings []APIClaimMapping

// ToDB converts the API claim mappings into the DB model shape.
func (in APIClaimMappings) ToDB() []cdbm.IssuerClaimMapping {
	if in == nil {
		return nil
	}
	out := make([]cdbm.IssuerClaimMapping, len(in))
	for i, cm := range in {
		out[i] = cdbm.IssuerClaimMapping{
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

// FromDB populates the API claim mappings from the DB model shape.
func (in *APIClaimMappings) FromDB(db []cdbm.IssuerClaimMapping) {
	if db == nil {
		*in = nil
		return
	}
	out := make(APIClaimMappings, len(db))
	for i, cm := range db {
		out[i] = APIClaimMapping{
			OrgAttribute:        cm.OrgAttribute,
			OrgDisplayAttribute: cm.OrgDisplayAttribute,
			OrgName:             cm.OrgName,
			OrgDisplayName:      cm.OrgDisplayName,
			RolesAttribute:      cm.RolesAttribute,
			Roles:               cm.Roles,
			IsServiceAccount:    cm.IsServiceAccount,
		}
	}
	*in = out
}

// NewAPIIssuer accepts a DB layer Issuer object and returns an API object
func NewAPIIssuer(iss *cdbm.Issuer) *APIIssuer {
	var claimMappings APIClaimMappings
	claimMappings.FromDB(iss.ClaimMappings)
	return &APIIssuer{
		ID:                           iss.ID.String(),
		Name:                         iss.Name,
		IssuerURL:                    iss.IssuerURL,
		JWKSURL:                      iss.JWKSURL,
		Origin:                       iss.Origin,
		ServiceAccount:               iss.ServiceAccount,
		Audiences:                    iss.Audiences,
		Scopes:                       iss.Scopes,
		JWKSTimeout:                  iss.JWKSTimeout,
		ClaimMappings:                claimMappings,
		AllowDuplicateStaticOrgNames: iss.AllowDuplicateStaticOrgNames,
		Status:                       iss.Status,
		Created:                      iss.Created,
		Updated:                      iss.Updated,
	}
}
