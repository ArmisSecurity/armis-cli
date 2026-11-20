package project

import "testing"

func TestDecide(t *testing.T) {
	tests := []struct {
		name        string
		project     string
		report      bool
		ci          bool
		ciVar       string
		wantPublish bool
		wantTrigger string
		wantReason  string
	}{
		// No --project: never published, wherever it runs.
		{name: "no project, local", wantPublish: false},
		{name: "no project, CI", ci: true, ciVar: "CI", wantPublish: false},
		{name: "no project, --report", report: true, wantPublish: false},

		// --project in CI publishes automatically.
		{name: "project, CI", project: "svc", ci: true, ciVar: "GITHUB_ACTIONS",
			wantPublish: true, wantTrigger: TriggerCLICI, wantReason: "CI detected (GITHUB_ACTIONS)"},
		{name: "project, CI without a variable name", project: "svc", ci: true,
			wantPublish: true, wantTrigger: TriggerCLICI, wantReason: "CI detected"},
		{name: "project, CI and --report stays a CI run", project: "svc", ci: true, ciVar: "CI", report: true,
			wantPublish: true, wantTrigger: TriggerCLICI, wantReason: "CI detected (CI)"},

		// --project on a developer machine stays local unless --report.
		{name: "project, local", project: "svc", wantPublish: false},
		{name: "project, local, --report", project: "svc", report: true,
			wantPublish: true, wantTrigger: TriggerCLIDev, wantReason: "--report"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Decide(tt.project, tt.report, tt.ci, tt.ciVar)
			if got.Publish != tt.wantPublish || got.Trigger != tt.wantTrigger || got.Reason != tt.wantReason {
				t.Errorf("Decide(%q, report=%v, ci=%v, %q) = %+v, want {Publish:%v Trigger:%q Reason:%q}",
					tt.project, tt.report, tt.ci, tt.ciVar, got, tt.wantPublish, tt.wantTrigger, tt.wantReason)
			}
		})
	}
}
