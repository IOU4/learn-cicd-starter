package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		authorization string
		wantKey       string
		wantErr       string
	}{
		{
			name:    "missing authorization header",
			wantErr: ErrNoAuthHeaderIncluded.Error(),
		},
		{
			name:          "malformed authorization header",
			authorization: "Bearer token",
			wantErr:       "malformed authorization header",
		},
		{
			name:          "authorization header missing key",
			authorization: "ApiKey",
			wantErr:       "malformed authorization header",
		},
		{
			name:          "valid api key",
			authorization: "ApiKey test-key",
			wantKey:       "test-key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := make(http.Header)
			if tt.authorization != "" {
				headers.Set("Authorization", tt.authorization)
			}

			gotKey, err := GetAPIKey(headers)
			if tt.wantErr != "" {
				if err == nil || err.Error() != tt.wantErr {
					t.Fatalf("GetAPIKey() error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("GetAPIKey() unexpected error = %v", err)
			}
			if gotKey != tt.wantKey {
				t.Errorf("GetAPIKey() = %q, want %q", gotKey, tt.wantKey)
			}
		})
	}
}
