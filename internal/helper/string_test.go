package helper

import (
	"reflect"
	"testing"
)

func TestSplitAndTrim(t *testing.T) {
	tests := []struct {
		name string
		s    string
		sep  string
		want []string
	}{
		{
			name: "splits and trims spaces",
			s:    "token1, token2 , token3",
			sep:  ",",
			want: []string{"token1", "token2", "token3"},
		},
		{
			name: "handles empty string",
			s:    "",
			sep:  ",",
			want: []string{},
		},
		{
			name: "filters empty parts",
			s:    "token1,,token2",
			sep:  ",",
			want: []string{"token1", "token2"},
		},
		{
			name: "handles tabs and newlines",
			s:    "token1\t,\ntoken2",
			sep:  ",",
			want: []string{"token1", "token2"},
		},
		{
			name: "handles multiple spaces",
			s:    "  token1  ,  token2  ",
			sep:  ",",
			want: []string{"token1", "token2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SplitAndTrim(tt.s, tt.sep)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SplitAndTrim() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTrimSpace(t *testing.T) {
	tests := []struct {
		name string
		s    string
		want string
	}{
		{
			name: "trims leading and trailing spaces",
			s:    "  hello  ",
			want: "hello",
		},
		{
			name: "trims tabs and newlines",
			s:    "\t\nhello\r\n",
			want: "hello",
		},
		{
			name: "handles empty string",
			s:    "",
			want: "",
		},
		{
			name: "handles whitespace only",
			s:    "   \t\n  ",
			want: "",
		},
		{
			name: "preserves internal whitespace",
			s:    "  hello world  ",
			want: "hello world",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := TrimSpace(tt.s)
			if got != tt.want {
				t.Errorf("TrimSpace() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSplitString(t *testing.T) {
	tests := []struct {
		name string
		s    string
		sep  string
		want []string
	}{
		{
			name: "basic split",
			s:    "a,b,c",
			sep:  ",",
			want: []string{"a", "b", "c"},
		},
		{
			name: "empty string",
			s:    "",
			sep:  ",",
			want: []string{},
		},
		{
			name: "multi-char separator",
			s:    "a::b::c",
			sep:  "::",
			want: []string{"a", "b", "c"},
		},
		{
			name: "empty parts",
			s:    "a,,c",
			sep:  ",",
			want: []string{"a", "", "c"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := splitString(tt.s, tt.sep)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("splitString() = %v, want %v", got, tt.want)
			}
		})
	}
}
