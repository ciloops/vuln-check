package report

import (
	"encoding/json"

	"github.com/ciloops/vuln-check/internal/model"
	"github.com/ciloops/vuln-check/internal/remediate"
)

type Full struct {
	Status string             `json:"status"`
	Scan   *model.Scan        `json:"scan"`
	Plan   []remediate.Action `json:"plan"`
}

func BuildFull(scan *model.Scan, plan []remediate.Action, opts Options) Full {
	return Full{Status: BuildAgent(scan, plan, opts).Status, Scan: scan, Plan: plan}
}

func (f Full) JSON() []byte {
	b, _ := json.MarshalIndent(f, "", "  ")
	return b
}
