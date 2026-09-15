package plan

import (
	_ "embed"
	"html/template"
)

// The Plan page keeps its HTML and Plan-specific assets embedded in the binary.
// Shared product styling and branding are loaded from the stable public assets
// hosted by www.telecrypt.io, so Storage Web and Plan use one editable source.

//go:embed assets/plan.html
var planHTML string

//go:embed assets/plan.css
var planCSS []byte

//go:embed assets/plan.js
var planJS []byte

var planTmpl = template.Must(template.New("plan").Parse(planHTML))
