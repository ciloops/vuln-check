package grype

// Subset of grype's JSON presenter models (grype/presenter/models).
// Only the fields vuln-check reads are declared.

type Document struct {
	Matches    []Match    `json:"matches"`
	Source     *Source    `json:"source"`
	Distro     Distro     `json:"distro"`
	Descriptor Descriptor `json:"descriptor"`
}

type Match struct {
	Vulnerability          Vulnerability           `json:"vulnerability"`
	RelatedVulnerabilities []VulnerabilityMetadata `json:"relatedVulnerabilities"`
	MatchDetails           []MatchDetails          `json:"matchDetails"`
	Artifact               Artifact                `json:"artifact"`
}

type Vulnerability struct {
	VulnerabilityMetadata
	Fix  Fix     `json:"fix"`
	Risk float64 `json:"risk"`
}

type VulnerabilityMetadata struct {
	ID             string           `json:"id"`
	DataSource     string           `json:"dataSource"`
	Namespace      string           `json:"namespace,omitempty"`
	Severity       string           `json:"severity,omitempty"`
	URLs           []string         `json:"urls"`
	Description    string           `json:"description,omitempty"`
	Cvss           []Cvss           `json:"cvss"`
	KnownExploited []KnownExploited `json:"knownExploited,omitempty"`
	EPSS           []EPSS           `json:"epss,omitempty"`
}

type Cvss struct {
	Source  string      `json:"source,omitempty"`
	Type    string      `json:"type,omitempty"`
	Version string      `json:"version"`
	Vector  string      `json:"vector"`
	Metrics CvssMetrics `json:"metrics"`
}

type CvssMetrics struct {
	BaseScore float64 `json:"baseScore"`
}

type KnownExploited struct {
	CVE       string `json:"cve"`
	DateAdded string `json:"dateAdded,omitempty"`
}

type EPSS struct {
	CVE        string  `json:"cve"`
	EPSS       float64 `json:"epss"`
	Percentile float64 `json:"percentile"`
	Date       string  `json:"date"`
}

type Fix struct {
	Versions []string `json:"versions"`
	State    string   `json:"state"`
}

type MatchDetails struct {
	Type    string      `json:"type"`
	Matcher string      `json:"matcher"`
	Fix     *FixDetails `json:"fix,omitempty"`
}

type FixDetails struct {
	SuggestedVersion string `json:"suggestedVersion"`
}

type Artifact struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Version   string     `json:"version"`
	Type      string     `json:"type"`
	Locations []Location `json:"locations"`
	Language  string     `json:"language"`
	PURL      string     `json:"purl"`
}

type Location struct {
	Path string `json:"path"`
}

type Source struct {
	Type   string `json:"type"`
	Target any    `json:"target"`
}

type Distro struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Descriptor struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	DB        any    `json:"db,omitempty"`
	Timestamp string `json:"timestamp,omitempty"`
}

// CycloneDX subset used to read the full package inventory.

type CycloneDX struct {
	Components []Component `json:"components"`
}

type Component struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version"`
	PURL    string `json:"purl"`
}

type VersionInfo struct {
	Version string `json:"version"`
}
