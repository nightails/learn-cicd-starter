package auth

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetAPIKey(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "ApiKey test-api-key")

	apiKey, err := GetAPIKey(headers)

	require.NoError(t, err)
	assert.Equal(t, "test-api-key", apiKey)
}

func TestGetAPIKeyNoAuthorizationHeader(t *testing.T) {
	headers := http.Header{}

	apiKey, err := GetAPIKey(headers)

	assert.Empty(t, apiKey)
	assert.Equal(t, ErrNoAuthHeaderIncluded, err)
}

func TestGetAPIKeyMalformedAuthorizationHeader(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "Bearer test-api-key")

	apiKey, err := GetAPIKey(headers)

	assert.Empty(t, apiKey)
	assert.EqualError(t, err, "malformed authorization header")
}
