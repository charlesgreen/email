package main

import (
	"net/mail"
	"strings"
	"testing"
)

// TestParseSCLHeader tests the parseSCLHeader function with various SCL values
func TestParseSCLHeader(t *testing.T) {
	tests := []struct {
		name          string
		header        string
		headerSource  string
		expectedScore int
		expectedDesc  string
		expectNil     bool
	}{
		{
			name:          "SCL -1 (skipped filtering)",
			header:        "CIP:255.255.255.255;CTRY:;LANG:en;SCL:-1;SRV:;IPV:NLI;SFV:NSPM;H:server.example.com;PTR:;CAT:NONE;SFS:;DIR:INB;",
			headerSource:  "X-Forefront-Antispam-Report",
			expectedScore: -1,
			expectedDesc:  "Skipped spam filtering (safe sender or SCL override)",
			expectNil:     false,
		},
		{
			name:          "SCL 0 (not spam)",
			header:        "CIP:10.0.0.1;CTRY:US;SCL:0;SRV:;IPV:CAL;SFV:NSPM;",
			headerSource:  "X-Forefront-Antispam-Report",
			expectedScore: 0,
			expectedDesc:  "Not spam",
			expectNil:     false,
		},
		{
			name:          "SCL 1 (not spam)",
			header:        "SCL:1;SRV:;IPV:CAL;",
			headerSource:  "X-Forefront-Antispam-Report",
			expectedScore: 1,
			expectedDesc:  "Not spam",
			expectNil:     false,
		},
		{
			name:          "SCL 2 (low spam probability)",
			header:        "SCL:2;PCL:0;RULEID:;",
			headerSource:  "X-Forefront-Antispam-Report",
			expectedScore: 2,
			expectedDesc:  "Low spam probability",
			expectNil:     false,
		},
		{
			name:          "SCL 3 (low spam probability)",
			header:        "CIP:192.168.1.1;SCL:3;DIR:INB;",
			headerSource:  "X-Forefront-Antispam-Report",
			expectedScore: 3,
			expectedDesc:  "Low spam probability",
			expectNil:     false,
		},
		{
			name:          "SCL 4 (low spam probability)",
			header:        "SCL:4;SFV:SPM;",
			headerSource:  "X-Forefront-Antispam-Report",
			expectedScore: 4,
			expectedDesc:  "Low spam probability",
			expectNil:     false,
		},
		{
			name:          "SCL 5 (spam)",
			header:        "CIP:203.0.113.1;CTRY:XX;SCL:5;SFV:SPM;",
			headerSource:  "X-Forefront-Antispam-Report",
			expectedScore: 5,
			expectedDesc:  "Spam",
			expectNil:     false,
		},
		{
			name:          "SCL 6 (spam)",
			header:        "SCL:6;SFV:SPM;DIR:INB;",
			headerSource:  "X-Forefront-Antispam-Report",
			expectedScore: 6,
			expectedDesc:  "Spam",
			expectNil:     false,
		},
		{
			name:          "SCL 7 (high confidence spam)",
			header:        "SCL:7;SFV:SPM;",
			headerSource:  "X-Forefront-Antispam-Report",
			expectedScore: 7,
			expectedDesc:  "High confidence spam",
			expectNil:     false,
		},
		{
			name:          "SCL 8 (high confidence spam)",
			header:        "CIP:198.51.100.1;SCL:8;SFV:SPM;",
			headerSource:  "X-Forefront-Antispam-Report",
			expectedScore: 8,
			expectedDesc:  "High confidence spam",
			expectNil:     false,
		},
		{
			name:          "SCL 9 (high confidence spam)",
			header:        "SCL:9;SFV:SPM;DIR:INB;",
			headerSource:  "X-Forefront-Antispam-Report",
			expectedScore: 9,
			expectedDesc:  "High confidence spam",
			expectNil:     false,
		},
		{
			name:         "Empty header",
			header:       "",
			headerSource: "X-Forefront-Antispam-Report",
			expectNil:    true,
		},
		{
			name:         "No SCL value",
			header:       "CIP:10.0.0.1;CTRY:US;SRV:;IPV:CAL;",
			headerSource: "X-Forefront-Antispam-Report",
			expectNil:    true,
		},
		{
			name:         "Invalid SCL (non-numeric)",
			header:       "SCL:invalid;SRV:;",
			headerSource: "X-Forefront-Antispam-Report",
			expectNil:    true,
		},
		{
			name:          "SCL at beginning of header",
			header:        "SCL:5;CIP:10.0.0.1;CTRY:US;",
			headerSource:  "X-Forefront-Antispam-Report",
			expectedScore: 5,
			expectedDesc:  "Spam",
			expectNil:     false,
		},
		{
			name:          "SCL at end of header",
			header:        "CIP:10.0.0.1;CTRY:US;SRV:;IPV:CAL;SCL:3",
			headerSource:  "X-Forefront-Antispam-Report",
			expectedScore: 3,
			expectedDesc:  "Low spam probability",
			expectNil:     false,
		},
		{
			name:          "SCL in middle of header",
			header:        "CIP:10.0.0.1;CTRY:US;SCL:7;SRV:;IPV:CAL;DIR:INB;",
			headerSource:  "X-Forefront-Antispam-Report",
			expectedScore: 7,
			expectedDesc:  "High confidence spam",
			expectNil:     false,
		},
		{
			name:          "Multiple SCL values (first should be used)",
			header:        "SCL:2;CIP:10.0.0.1;SCL:8;CTRY:US;",
			headerSource:  "X-Forefront-Antispam-Report",
			expectedScore: 2,
			expectedDesc:  "Low spam probability",
			expectNil:     false,
		},
		{
			name:         "SCL with spaces around colon",
			header:       "CIP:10.0.0.1;SCL: 4 ;CTRY:US;",
			headerSource: "X-Forefront-Antispam-Report",
			// The regex pattern requires no space after SCL:
			expectNil: true,
		},
		{
			name:         "Out of range SCL (10)",
			header:       "SCL:10;SRV:;",
			headerSource: "X-Forefront-Antispam-Report",
			// The function logs a warning and rejects out-of-range values
			expectNil: true,
		},
		{
			name:         "Out of range SCL (-2)",
			header:       "SCL:-2;SRV:;",
			headerSource: "X-Forefront-Antispam-Report",
			// The function logs a warning and rejects out-of-range values
			expectNil: true,
		},
		{
			name:         "SCL with no value",
			header:       "SCL:;SRV:;",
			headerSource: "X-Forefront-Antispam-Report",
			expectNil:    true,
		},
		{
			name:          "SCL with decimal value",
			header:        "SCL:5.5;SRV:;",
			headerSource:  "X-Forefront-Antispam-Report",
			expectedScore: 5,
			expectedDesc:  "Spam",
			expectNil:     false,
			// Regex pattern \d+ matches digits, so it captures "5" from "5.5"
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseSCLHeader(tt.header, tt.headerSource)

			if tt.expectNil {
				if result != nil {
					t.Errorf("Expected nil result, got %+v", result)
				}
				return
			}

			if result == nil {
				t.Fatalf("Expected non-nil result, got nil")
			}

			if result.Score != tt.expectedScore {
				t.Errorf("Expected score %d, got %d", tt.expectedScore, result.Score)
			}

			if result.Description != tt.expectedDesc {
				t.Errorf("Expected description %q, got %q", tt.expectedDesc, result.Description)
			}

			if result.HeaderSource != tt.headerSource {
				t.Errorf("Expected header source %q, got %q", tt.headerSource, result.HeaderSource)
			}

			// Verify raw header is sanitized (no newlines)
			if strings.Contains(result.RawHeader, "\n") || strings.Contains(result.RawHeader, "\r") {
				t.Errorf("Raw header contains newlines: %q", result.RawHeader)
			}
		})
	}
}

// TestGetSCLDescription tests the getSCLDescription function
func TestGetSCLDescription(t *testing.T) {
	tests := []struct {
		score       int
		description string
	}{
		{-1, "Skipped spam filtering (safe sender or SCL override)"},
		{0, "Not spam"},
		{1, "Not spam"},
		{2, "Low spam probability"},
		{3, "Low spam probability"},
		{4, "Low spam probability"},
		{5, "Spam"},
		{6, "Spam"},
		{7, "High confidence spam"},
		{8, "High confidence spam"},
		{9, "High confidence spam"},
		{10, "Unknown spam confidence level"},
		{-2, "Unknown spam confidence level"},
		{100, "Unknown spam confidence level"},
		{-100, "Unknown spam confidence level"},
	}

	for _, tt := range tests {
		t.Run(tt.description, func(t *testing.T) {
			result := getSCLDescription(tt.score)
			if result != tt.description {
				t.Errorf("getSCLDescription(%d) = %q; want %q", tt.score, result, tt.description)
			}
		})
	}
}

// TestExtractSCLResults tests the extractSCLResults function
func TestExtractSCLResults(t *testing.T) {
	tests := []struct {
		name          string
		headers       map[string][]string
		expectedScore int
		expectedDesc  string
		expectNil     bool
	}{
		{
			name: "X-Forefront-Antispam-Report with SCL:5",
			headers: map[string][]string{
				"X-Forefront-Antispam-Report": {"CIP:203.0.113.1;CTRY:XX;SCL:5;SFV:SPM;"},
			},
			expectedScore: 5,
			expectedDesc:  "Spam",
			expectNil:     false,
		},
		{
			name: "X-Forefront-Antispam-Report-Untrusted with SCL:7",
			headers: map[string][]string{
				"X-Forefront-Antispam-Report-Untrusted": {"SCL:7;SFV:SPM;"},
			},
			expectedScore: 7,
			expectedDesc:  "High confidence spam",
			expectNil:     false,
		},
		{
			name: "Both headers present (trusted takes precedence)",
			headers: map[string][]string{
				"X-Forefront-Antispam-Report":           {"SCL:2;SRV:;"},
				"X-Forefront-Antispam-Report-Untrusted": {"SCL:8;SRV:;"},
			},
			expectedScore: 2,
			expectedDesc:  "Low spam probability",
			expectNil:     false,
		},
		{
			name: "No SCL headers",
			headers: map[string][]string{
				"Authentication-Results": {"example.com; spf=pass"},
			},
			expectNil: true,
		},
		{
			name: "Empty SCL header",
			headers: map[string][]string{
				"X-Forefront-Antispam-Report": {""},
			},
			expectNil: true,
		},
		{
			name: "SCL header with no SCL value",
			headers: map[string][]string{
				"X-Forefront-Antispam-Report": {"CIP:10.0.0.1;CTRY:US;SRV:;"},
			},
			expectNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Convert map to mail.Header
			header := make(mail.Header)
			for key, values := range tt.headers {
				for _, value := range values {
					header[key] = append(header[key], value)
				}
			}

			result := extractSCLResults(header)

			if tt.expectNil {
				if result != nil {
					t.Errorf("Expected nil result, got %+v", result)
				}
				return
			}

			if result == nil {
				t.Fatalf("Expected non-nil result, got nil")
			}

			if result.Score != tt.expectedScore {
				t.Errorf("Expected score %d, got %d", tt.expectedScore, result.Score)
			}

			if result.Description != tt.expectedDesc {
				t.Errorf("Expected description %q, got %q", tt.expectedDesc, result.Description)
			}
		})
	}
}

// TestParseSCLHeaderEdgeCases tests edge cases for SCL header parsing
func TestParseSCLHeaderEdgeCases(t *testing.T) {
	tests := []struct {
		name          string
		header        string
		headerSource  string
		expectNil     bool
		expectedScore int
		expectedDesc  string
	}{
		{
			name: "Very long header",
			header: "CIP:10.0.0.1;CTRY:US;LANG:en;SCL:5;SRV:;IPV:CAL;SFV:SPM;" +
				strings.Repeat("A", 10000),
			headerSource: "X-Forefront-Antispam-Report",
			expectNil:    false,
		},
		{
			name:         "Header with newlines (should be sanitized)",
			header:       "CIP:10.0.0.1;\nSCL:3;\r\nCTRY:US;",
			headerSource: "X-Forefront-Antispam-Report",
			expectNil:    false,
		},
		{
			name:         "Header with special characters",
			header:       "CIP:10.0.0.1;SCL:4;CTRY:US;EXTRA:<script>alert('xss')</script>",
			headerSource: "X-Forefront-Antispam-Report",
			expectNil:    false,
		},
		{
			name:         "Header with Unicode characters",
			header:       "CIP:10.0.0.1;SCL:2;CTRY:日本;",
			headerSource: "X-Forefront-Antispam-Report",
			expectNil:    false,
		},
		{
			name:         "Case sensitivity test (lowercase scl)",
			header:       "CIP:10.0.0.1;scl:5;CTRY:US;",
			headerSource: "X-Forefront-Antispam-Report",
			expectNil:    true, // Regex looks for uppercase SCL
		},
		{
			name:         "Mixed case SCL",
			header:       "CIP:10.0.0.1;Scl:5;CTRY:US;",
			headerSource: "X-Forefront-Antispam-Report",
			expectNil:    true, // Regex looks for uppercase SCL
		},
		{
			name:         "SCL with leading zeros",
			header:       "SCL:05;SRV:;",
			headerSource: "X-Forefront-Antispam-Report",
			expectNil:    false,
		},
		{
			name:         "SCL with plus sign",
			header:       "SCL:+5;SRV:;",
			headerSource: "X-Forefront-Antispam-Report",
			expectNil:    true, // Regex only matches optional minus sign
		},
		{
			name:          "SCL-like but not SCL",
			header:        "XSCL:5;SCLX:7;MYSCL:9;",
			headerSource:  "X-Forefront-Antispam-Report",
			expectedScore: 5,
			expectedDesc:  "Spam",
			expectNil:     false,
			// Regex pattern "SCL:" will match "XSCL:5" (the "SCL:5" part)
		},
		{
			name:         "SCL with whitespace",
			header:       "SCL : 5 ; SRV:;",
			headerSource: "X-Forefront-Antispam-Report",
			expectNil:    true, // Regex doesn't allow spaces
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseSCLHeader(tt.header, tt.headerSource)

			if tt.expectNil {
				if result != nil {
					t.Errorf("Expected nil result for %q, got %+v", tt.name, result)
				}
			} else {
				if result == nil {
					t.Errorf("Expected non-nil result for %q, got nil", tt.name)
				} else {
					// Optionally verify score and description if specified
					if tt.expectedScore != 0 && result.Score != tt.expectedScore {
						t.Errorf("Expected score %d, got %d", tt.expectedScore, result.Score)
					}
					if tt.expectedDesc != "" && result.Description != tt.expectedDesc {
						t.Errorf("Expected description %q, got %q", tt.expectedDesc, result.Description)
					}
				}
			}
		})
	}
}

// TestSCLResultStruct tests that SCLResult struct is properly populated
func TestSCLResultStruct(t *testing.T) {
	header := "CIP:10.0.0.1;CTRY:US;SCL:6;SRV:;IPV:CAL;"
	headerSource := "X-Forefront-Antispam-Report"

	result := parseSCLHeader(header, headerSource)

	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	// Check all fields are populated
	if result.Score != 6 {
		t.Errorf("Expected Score=6, got %d", result.Score)
	}

	if result.Description != "Spam" {
		t.Errorf("Expected Description='Spam', got %q", result.Description)
	}

	if result.HeaderSource != headerSource {
		t.Errorf("Expected HeaderSource=%q, got %q", headerSource, result.HeaderSource)
	}

	if result.RawHeader == "" {
		t.Error("Expected RawHeader to be populated, got empty string")
	}

	// Verify RawHeader is sanitized
	if strings.Contains(result.RawHeader, "\n") || strings.Contains(result.RawHeader, "\r") {
		t.Errorf("RawHeader should not contain newlines: %q", result.RawHeader)
	}
}

// TestSCLHeaderLengthValidation tests that excessively long headers are truncated
func TestSCLHeaderLengthValidation(t *testing.T) {
	// Create a header longer than MaxHeaderLength
	longHeader := "SCL:5;" + strings.Repeat("A", MaxHeaderLength+1000)

	header := make(mail.Header)
	header["X-Forefront-Antispam-Report"] = []string{longHeader}

	result := extractSCLResults(header)

	if result == nil {
		t.Fatal("Expected non-nil result even with truncated header")
	}

	// The raw header should be truncated to MaxHeaderLength
	if len(result.RawHeader) > MaxHeaderLength {
		t.Errorf("RawHeader length %d exceeds MaxHeaderLength %d",
			len(result.RawHeader), MaxHeaderLength)
	}
}

// TestMultipleSCLValuesInHeader tests that only the first SCL value is extracted
func TestMultipleSCLValuesInHeader(t *testing.T) {
	header := "SCL:1;CIP:10.0.0.1;SCL:9;CTRY:US;SCL:5;"
	headerSource := "X-Forefront-Antispam-Report"

	result := parseSCLHeader(header, headerSource)

	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	// Should use the first SCL value (1)
	if result.Score != 1 {
		t.Errorf("Expected first SCL value (1), got %d", result.Score)
	}

	if result.Description != "Not spam" {
		t.Errorf("Expected 'Not spam' description, got %q", result.Description)
	}
}

// TestSCLBoundaryValues tests SCL values at boundaries
func TestSCLBoundaryValues(t *testing.T) {
	tests := []struct {
		score        int
		description  string
		categoryName string
	}{
		{-1, "Skipped spam filtering (safe sender or SCL override)", "Skipped"},
		{0, "Not spam", "Not spam lower bound"},
		{1, "Not spam", "Not spam upper bound"},
		{2, "Low spam probability", "Low spam lower bound"},
		{3, "Low spam probability", "Low spam middle"},
		{4, "Low spam probability", "Low spam upper bound"},
		{5, "Spam", "Spam lower bound"},
		{6, "Spam", "Spam upper bound"},
		{7, "High confidence spam", "High spam lower bound"},
		{8, "High confidence spam", "High spam middle"},
		{9, "High confidence spam", "High spam upper bound"},
	}

	for _, tt := range tests {
		t.Run(tt.categoryName, func(t *testing.T) {
			desc := getSCLDescription(tt.score)
			if desc != tt.description {
				t.Errorf("Score %d: expected %q, got %q", tt.score, tt.description, desc)
			}
		})
	}
}
