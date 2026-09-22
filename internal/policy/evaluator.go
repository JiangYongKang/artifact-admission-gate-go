package policy

import (
	"fmt"
	"sort"
	"strings"

	"github.com/highcumontoa/artifact-admission-gate-go/internal/model"
)

// Evaluate checks a verified artifact/chain/SBOM against p and returns the
// ordered list of rule violations. An empty slice means the policy is
// satisfied. Evaluation is a pure function so concurrent or repeated checks
// of the same input under the same policy always produce identical results:
// membership tests are used and every range over user supplied data is
// sorted before contributing to the output.
func Evaluate(p model.Policy, artifactDigest, builderID string, chainLength int, sbom *model.SBOM) []model.PolicyViolation {
	var violations []model.PolicyViolation

	// Rule: trusted builder.
	if !contains(p.AllowedBuilders, builderID) {
		violations = append(violations, model.PolicyViolation{
			Rule:   "allowed-builders",
			Detail: fmt.Sprintf("builder %q is not in the allow-list [%s]", builderID, strings.Join(sortedCopy(p.AllowedBuilders), ", ")),
		})
	}

	// Rule: minimum provenance chain length.
	if chainLength < p.RequiredMinChainLength {
		violations = append(violations, model.PolicyViolation{
			Rule:   "min-chain-length",
			Detail: fmt.Sprintf("chain length %d is below required minimum %d", chainLength, p.RequiredMinChainLength),
		})
	}

	if sbom != nil {
		// Rule: license allow-list.
		allowedAny := contains(p.AllowedLicenses, "*")
		badLicenses := map[string]bool{}
		for _, pkg := range sbom.Packages {
			lic := strings.TrimSpace(pkg.License)
			if allowedAny {
				if lic == "" {
					badLicenses[pkg.Name+":<empty>"] = true
				}
				continue
			}
			if !contains(p.AllowedLicenses, lic) {
				badLicenses[pkg.Name+":"+lic] = true
			}
		}
		if len(badLicenses) > 0 {
			violations = append(violations, model.PolicyViolation{
				Rule:   "allowed-licenses",
				Detail: "packages with disallowed or missing licenses: " + strings.Join(sortedKeys(badLicenses), ", "),
			})
		}

		// Rule: denied packages.
		denied := map[string]bool{}
		for _, pkg := range sbom.Packages {
			if contains(p.DeniedPackages, pkg.Name) {
				denied[pkg.Name+"@"+pkg.Version] = true
			}
		}
		if len(denied) > 0 {
			violations = append(violations, model.PolicyViolation{
				Rule:   "denied-packages",
				Detail: "artifact contains denied packages: " + strings.Join(sortedKeys(denied), ", "),
			})
		}
	}

	return violations
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
