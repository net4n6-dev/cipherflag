package certspotter

import "testing"

func TestValidateDomain(t *testing.T) {
	cases := []struct {
		name            string
		domain          string
		requestsPerHour int
		wantErr         bool
	}{
		{"valid default rate", "example.com", 0, false},
		{"valid explicit rate", "example.com", 100, false},
		{"empty domain", "", 0, true},
		{"negative rate", "example.com", -1, true},
		{"rate too high", "example.com", 100001, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateDomain(tc.domain, tc.requestsPerHour)
			if (err != nil) != tc.wantErr {
				t.Errorf("ValidateDomain() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}
