package scan

import "github.com/ArmisSecurity/armis-cli/internal/cli"

// WarnNoScanResults explains a completed scan whose results the API did not
// return (api.ErrNoScanResults). Such a scan is not reported as clean: the
// command exits as if its results could not be retrieved, so a --fail-on gate
// fails closed instead of passing on an empty result.
func WarnNoScanResults(scanID string) {
	cli.PrintWarningf("The API returned no results for scan %s, so it is not reported as clean. "+
		"This happens when another scan of the same folder and files finished at about the same time "+
		"(for example, push and pull-request builds of one commit). Re-run the scan to gate on fresh results.", scanID)
}
