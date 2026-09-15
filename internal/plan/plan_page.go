package plan

import (
	_ "embed"
	"html/template"
)

// The Plan presentation is kept in local embedded assets. This makes the page
// independently maintainable without introducing a frontend build or a runtime
// dependency. Its tokens mirror the framework-neutral shared UI source in
// www.telecrypt.io:
// light canvas and surfaces, system type, compact controls, small radii, and
// neutral borders. Product identity remains local: Plan uses TeleCrypt's
// original custom mark without a runtime asset dependency.

//go:embed assets/plan.html
var planHTML string

// planProductCSS is vendored byte-for-byte from the exact www.telecrypt.io
// release recorded in SHARED_UI_PROVENANCE.json. It is embedded because Plan
// has no frontend build or runtime package manager.
//
//go:embed assets/product.css
var planProductCSS []byte

//go:embed assets/plan.css
var planCSS []byte

//go:embed assets/plan.js
var planJS []byte

//go:embed assets/logo-mark.png
var planLogoPNG []byte

var planTmpl = template.Must(template.New("plan").Parse(planHTML))
