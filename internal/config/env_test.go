package config

import (
	"os"
	"testing"
)

func TestGetEnv(t *testing.T) {
	tests := []struct {
		name         string
		key          string
		defaultValue string
		envValue     string
		setEnv       bool
		want         string
	}{
		{
			name:         "returns environment variable when set",
			key:          "TEST_VAR",
			defaultValue: "default",
			envValue:     "actual",
			setEnv:       true,
			want:         "actual",
		},
		{
			name:         "returns default when env not set",
			key:          "UNSET_VAR",
			defaultValue: "default",
			setEnv:       false,
			want:         "default",
		},
		{
			name:         "returns empty string when set to empty",
			key:          "EMPTY_VAR",
			defaultValue: "default",
			envValue:     "",
			setEnv:       true,
			want:         "default",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setEnv {
				os.Setenv(tt.key, tt.envValue)
				defer os.Unsetenv(tt.key)
			}

			got := GetEnv(tt.key, tt.defaultValue)
			if got != tt.want {
				t.Errorf("GetEnv() = %v, want %v", got, tt.want)
			}
		})
	}
}
