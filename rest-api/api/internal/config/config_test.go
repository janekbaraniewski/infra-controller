// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	cauth "github.com/NVIDIA/infra-controller/rest-api/auth/pkg/config"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type logContainsWriter struct {
	needle string
	seen   chan struct{}
}

func (w logContainsWriter) Write(p []byte) (int, error) {
	if strings.Contains(string(p), w.needle) {
		select {
		case w.seen <- struct{}{}:
		default:
		}
	}
	return len(p), nil
}

func writeConfigForTest(t *testing.T, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

func TestNewConfig(t *testing.T) {
	tests := []struct {
		name string
		want *Config
	}{
		{
			name: "initialize config",
			want: &Config{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewConfig()

			defaultPath := ProjectRoot + "/config.yaml"

			assert.Equal(t, defaultPath, got.GetPathToConfig())
		})
	}
}

func TestValidateIssuersConfig_CustomClaimMappingRules(t *testing.T) {
	cfg := &Config{v: newViper()}

	validCustom := IssuerConfig{
		Name:   "external-idp",
		Origin: cauth.TokenOriginCustom,
		JWKS:   "https://idp.example.com/jwks",
		Issuer: "https://idp.example.com",
		ClaimMappings: []cauth.ClaimMapping{{
			OrgName: "tenant-a",
			Roles:   []string{"TENANT_ADMIN"},
		}},
	}

	tests := []struct {
		name    string
		issuer  IssuerConfig
		wantErr string
	}{
		{
			name:   "custom issuer with mapping is valid",
			issuer: validCustom,
		},
		{
			name: "custom issuer without mappings is invalid",
			issuer: IssuerConfig{
				Name:   "external-idp",
				Origin: cauth.TokenOriginCustom,
				JWKS:   "https://idp.example.com/jwks",
				Issuer: "https://idp.example.com",
			},
			wantErr: "claimMappings are required",
		},
		{
			name: "non-custom issuer with mappings is invalid",
			issuer: IssuerConfig{
				Name:   "kas-idp",
				Origin: cauth.TokenOriginKasLegacy,
				JWKS:   "https://idp.example.com/jwks",
				Issuer: "https://idp.example.com",
				ClaimMappings: []cauth.ClaimMapping{{
					OrgName: "tenant-a",
					Roles:   []string{"TENANT_ADMIN"},
				}},
			},
			wantErr: "claimMappings are only allowed for custom origin issuers",
		},
		{
			name: "custom issuer rejects issuer-level service account",
			issuer: IssuerConfig{
				Name:           "external-idp",
				Origin:         cauth.TokenOriginCustom,
				JWKS:           "https://idp.example.com/jwks",
				Issuer:         "https://idp.example.com",
				ServiceAccount: true,
				ClaimMappings: []cauth.ClaimMapping{{
					OrgName: "tenant-a",
					Roles:   []string{"TENANT_ADMIN"},
				}},
			},
			wantErr: "serviceAccount is not supported for custom origin issuers",
		},
		{
			name: "non-custom issuer without mappings remains valid",
			issuer: IssuerConfig{
				Name:   "kas-idp",
				Origin: cauth.TokenOriginKasLegacy,
				JWKS:   "https://idp.example.com/jwks",
				Issuer: "https://idp.example.com",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := cfg.ValidateIssuersConfig([]IssuerConfig{tt.issuer})
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestConfig_WatchConfigFile(t *testing.T) {
	const initialSitePhoneHomeURL = "http://initial.example/phone_home"

	tests := []struct {
		name string // description of this test case
		run  func(t *testing.T, c *Config, configPath string)
	}{
		{
			name: "keeps current site phone home URL when changed config cannot be read",
			run: func(t *testing.T, c *Config, configPath string) {
				seenConfigChange := make(chan struct{}, 1)
				previousLogger := log.Logger
				log.Logger = zerolog.New(logContainsWriter{
					needle: "config file changed",
					seen:   seenConfigChange,
				})
				t.Cleanup(func() {
					log.Logger = previousLogger
				})

				require.NoError(t, os.WriteFile(configPath, []byte("site:\n  phoneHomeUrl: [\n"), 0o600))

				require.Eventually(t, func() bool {
					select {
					case <-seenConfigChange:
						return true
					default:
						return false
					}
				}, 3*time.Second, 100*time.Millisecond)
				assert.Equal(t, initialSitePhoneHomeURL, c.GetSitePhoneHomeUrl())
			},
		},
		{
			name: "reloads site phone home URL from changed config",
			run: func(t *testing.T, c *Config, configPath string) {
				const updatedSitePhoneHomeURL = "http://updated.example/phone_home"

				require.NoError(t, os.WriteFile(configPath, []byte(`
log:
  level: debug
site:
  phoneHomeUrl: http://updated.example/phone_home
`), 0o600))

				require.Eventually(t, func() bool {
					return c.GetSitePhoneHomeUrl() == updatedSitePhoneHomeURL
				}, 3*time.Second, 100*time.Millisecond)
				assert.Equal(t, "info", c.v.GetString(ConfigLogLevel))
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configPath := writeConfigForTest(t, `
site:
  phoneHomeUrl: http://initial.example/phone_home
`)
			c := &Config{v: viper.New()}
			c.v.SetDefault(ConfigFilePath, configPath)
			c.v.SetConfigFile(configPath)
			c.v.SetDefault(ConfigLogLevel, "info")
			c.SetSitePhoneHomeUrl(initialSitePhoneHomeURL)
			c.WatchConfigFile()
			tt.run(t, c, configPath)
		})
	}
}
