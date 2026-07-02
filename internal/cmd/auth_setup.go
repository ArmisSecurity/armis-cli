package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/auth"
	"github.com/ArmisSecurity/armis-cli/internal/cli"
	"github.com/ArmisSecurity/armis-cli/internal/cmd/cmdutil"
	"github.com/ArmisSecurity/armis-cli/internal/output"
	"github.com/charmbracelet/huh"
	"github.com/spf13/cobra"
)

// Recognized Armis roles for group_mapping values. The backend maps an IdP
// group to one of these; anything else is silently unrecognized at login time,
// so we constrain the input here to catch typos early.
const (
	roleAdmin     = "admin"
	roleDeveloper = "developer"

	// maxConfigBytes bounds a --config document read from stdin. A configuration
	// is only a few hundred bytes; the cap guards against an unbounded pipe.
	maxConfigBytes = 2 << 10 // 2 KiB

	// defaultGroupClaim is the ID-token claim carrying the user's groups, used
	// when the admin does not specify one.
	defaultGroupClaim = "groups"
)

var (
	setupConfigInput string // --config: file path, "-" for stdin, or inline JSON
	setupUpdate      bool   // --update: force the PUT (update) path
	setupYes         bool   // --yes: skip the review confirmation
)

var authSetupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Register your tenant's identity provider (IdP) for SSO",
	Long: `Register (or update) your tenant's identity-provider configuration so your
users can sign in with 'armis-cli auth login'.

This is an IT-admin task: run it once after you register armis-cli as an OIDC
application in your IdP (Okta, Entra ID, Keycloak, …). It posts the resulting
configuration to the Armis admin API.

Two ways to provide the configuration:

  Interactive (default)   The CLI walks you through each value and explains
                          where to find it.

  From JSON (--config)    Provide the whole configuration as one JSON document
                          for scripting (MDM, CI). --config accepts a file path,
                          '-' to read stdin, or an inline JSON string.

Authentication uses your existing Armis credentials, resolved the same way as
the scan commands (a stored SSO session, client credentials, or an API token).
Your OIDC client secret is sent only in this request — it is never stored or
printed.`,
	Example: `  # Interactive setup
  armis-cli auth setup

  # From a JSON file
  armis-cli auth setup --config idp.json

  # Inline JSON, non-interactive (e.g. in a script)
  armis-cli auth setup --config '{"tenant_id":"acme",...}' --yes

  # Update an existing configuration (rotate the secret, change mappings)
  armis-cli auth setup --config idp.json --update`,
	Args: cobra.NoArgs,
	RunE: runAuthSetup,
}

func init() {
	authSetupCmd.Flags().StringVar(&setupConfigInput, "config", "", "IdP configuration as JSON: a file path, '-' for stdin, or an inline JSON string")
	authSetupCmd.Flags().BoolVar(&setupUpdate, "update", false, "Update an existing configuration (PUT) instead of creating a new one")
	authSetupCmd.Flags().BoolVar(&setupYes, "yes", false, "Skip the review confirmation (for non-interactive use)")
	authCmd.AddCommand(authSetupCmd)
}

func runAuthSetup(cmd *cobra.Command, _ []string) error {
	// Resolve the admin's credentials up front so authentication problems surface
	// before we prompt for (or read) any IdP details.
	provider, err := getAuthProvider(cmd.Context())
	if err != nil {
		return err
	}

	client, err := auth.NewIdpConfigClient(getAPIBaseURL(), provider, debug)
	if err != nil {
		return err
	}

	// Pass the command's context through; each network call applies its own
	// per-request timeout (see withRequestTimeout). We must NOT wrap a single
	// deadline around the whole flow — the interactive forms can take minutes and
	// would otherwise consume the budget before the request is even sent.
	ctx := cmd.Context()

	// The --config path is for scripting (MDM, CI): the caller supplies the whole
	// configuration as one document, so we don't pre-flight or prompt.
	if setupConfigInput != "" {
		return runConfigFileSetup(ctx, client)
	}
	if !cli.IsInteractive() {
		return fmt.Errorf("no configuration provided: pass --config (a file, '-' for stdin, or inline JSON), or run in an interactive terminal")
	}
	return runInteractiveSetup(ctx, client)
}

// idpRequestTimeout bounds a single admin-API request. It is applied per call so
// that time spent in the interactive forms never counts against a request's
// deadline.
const idpRequestTimeout = 30 * time.Second

// withRequestTimeout derives a per-request context from the command context.
func withRequestTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, idpRequestTimeout)
}

// runConfigFileSetup handles the non-interactive --config path: load the full
// configuration from JSON and create it (or update it wholesale with --update).
func runConfigFileSetup(ctx context.Context, client *auth.IdpConfigClient) error {
	reqCfg, err := loadIdpConfigFromJSON(setupConfigInput)
	if err != nil {
		return err
	}

	// ema_enabled is not supported by the backend yet; always send false.
	reqCfg.EMAEnabled = false

	if err := validateIdpConfig(reqCfg); err != nil {
		return err
	}

	// Review + confirm (unless --yes). The client secret is masked.
	printIdpConfigSummary(reqCfg)
	if !setupYes {
		confirmed, cerr := confirmSetup(setupUpdate)
		if cerr != nil {
			return cerr
		}
		if !confirmed {
			fmt.Fprintln(os.Stderr, "  Cancelled — nothing was sent.")
			return nil
		}
	}

	if setupUpdate {
		return sendUpdate(ctx, client, reqCfg)
	}
	return sendCreate(ctx, client, reqCfg)
}

// runInteractiveSetup guides an admin through setup. It first resolves the tenant
// and fetches any existing configuration: if one exists, it shows a pre-filled
// form where every field is optional (blank means "keep") and sends only the
// changed fields — so an admin can, say, tweak a group mapping without re-entering
// the client secret. Otherwise it collects a full configuration and creates it.
func runInteractiveSetup(ctx context.Context, client *auth.IdpConfigClient) error {
	tenant, err := promptSetupTenantID(strings.TrimSpace(tenantID))
	if err != nil {
		return err
	}
	if tenant == "" {
		return fmt.Errorf("tenant ID is required")
	}

	existing, err := fetchExistingConfig(ctx, client, tenant)
	if err != nil {
		return err
	}

	if existing != nil {
		return runInteractiveUpdate(ctx, client, existing)
	}
	return runInteractiveCreate(ctx, client, tenant)
}

// runInteractiveCreate collects a full configuration for a tenant that has none
// yet and creates it.
func runInteractiveCreate(ctx context.Context, client *auth.IdpConfigClient, tenant string) error {
	reqCfg, err := promptIdpConfig(tenant)
	if err != nil {
		return err
	}
	reqCfg.EMAEnabled = false

	if err := validateIdpConfig(reqCfg); err != nil {
		return err
	}

	printIdpConfigSummary(reqCfg)
	if !setupYes {
		confirmed, cerr := confirmSetup(false)
		if cerr != nil {
			return cerr
		}
		if !confirmed {
			fmt.Fprintln(os.Stderr, "  Cancelled — nothing was sent.")
			return nil
		}
	}
	return sendCreate(ctx, client, reqCfg)
}

// runInteractiveUpdate shows a form pre-filled from the existing configuration and
// PUTs only the fields the admin changed, relying on the backend to merge them.
func runInteractiveUpdate(ctx context.Context, client *auth.IdpConfigClient, existing *auth.IdpConfigResponse) error {
	fmt.Fprintf(os.Stderr, "%s Found an existing IdP configuration for tenant %q — editing it.\n",
		output.IconPointer, existing.TenantID)
	fmt.Fprintln(os.Stderr, "  Leave a field unchanged to keep its current value; only edits are sent.")

	upd, changed, err := promptIdpConfigUpdate(existing)
	if err != nil {
		return err
	}
	if !changed {
		fmt.Fprintln(os.Stderr, "  No changes — nothing to update.")
		return nil
	}

	printIdpConfigUpdateSummary(existing, upd)
	if !setupYes {
		confirmed, cerr := confirmSetup(true)
		if cerr != nil {
			return cerr
		}
		if !confirmed {
			fmt.Fprintln(os.Stderr, "  Cancelled — the existing configuration was left unchanged.")
			return nil
		}
	}

	reqCtx, cancel := withRequestTimeout(ctx)
	defer cancel()
	if _, err := client.Update(reqCtx, existing.TenantID, upd); err != nil {
		return describeIdpConfigError(err)
	}
	fmt.Fprintf(os.Stderr, "%s IdP configuration updated for tenant %q.\n", output.IconSuccess, existing.TenantID)
	printPostSetupHint(existing.TenantID)
	return nil
}

// fetchExistingConfig returns the tenant's current configuration, or nil if none
// exists yet (404). Other failures (401/403/transport) are returned as actionable
// errors so we don't fall through to a create form after, say, an auth failure.
func fetchExistingConfig(ctx context.Context, client *auth.IdpConfigClient, tenant string) (*auth.IdpConfigResponse, error) {
	reqCtx, cancel := withRequestTimeout(ctx)
	defer cancel()
	cfg, err := client.Get(reqCtx, tenant)
	if err == nil {
		return cfg, nil
	}
	var ce *auth.IdpConfigError
	if errors.As(err, &ce) && ce.StatusCode == http.StatusNotFound {
		return nil, nil // not configured yet — proceed to create
	}
	return nil, describeIdpConfigError(err)
}

// sendCreate POSTs a new configuration. On 409 it offers to switch to the update
// (PUT) path, automatically when --yes is set and interactively otherwise.
func sendCreate(ctx context.Context, client *auth.IdpConfigClient, reqCfg *auth.IdpConfigCreateRequest) error {
	reqCtx, cancel := withRequestTimeout(ctx)
	defer cancel()
	_, err := client.Create(reqCtx, reqCfg)
	if err == nil {
		fmt.Fprintf(os.Stderr, "%s IdP configuration created for tenant %q.\n", output.IconSuccess, reqCfg.TenantID)
		printPostSetupHint(reqCfg.TenantID)
		return nil
	}

	// On conflict, offer to switch to the update path. In an interactive terminal
	// (and when not already skipping prompts with --yes) we ask; otherwise we
	// stop and point the user at --update, so a scripted create never silently
	// overwrites an existing configuration.
	var ce *auth.IdpConfigError
	if errors.As(err, &ce) && ce.StatusCode == http.StatusConflict {
		if !setupYes && cli.IsInteractive() {
			ok, cerr := confirmUpdateExisting(reqCfg.TenantID)
			if cerr != nil {
				return cerr
			}
			if ok {
				return sendUpdate(ctx, client, reqCfg)
			}
			fmt.Fprintln(os.Stderr, "  Cancelled — the existing configuration was left unchanged.")
			return nil
		}
		return fmt.Errorf("an IdP configuration already exists for tenant %q; re-run with --update to replace it", reqCfg.TenantID)
	}

	return describeIdpConfigError(err)
}

// sendUpdate PUTs the configuration for the tenant. Every field is sent, so an
// update fully replaces the stored values (and rotates the secret).
func sendUpdate(ctx context.Context, client *auth.IdpConfigClient, reqCfg *auth.IdpConfigCreateRequest) error {
	upd := &auth.IdpConfigUpdateRequest{
		IdpType:          setupStrPtr(reqCfg.IdpType),
		Issuer:           setupStrPtr(reqCfg.Issuer),
		OIDCClientID:     setupStrPtr(reqCfg.OIDCClientID),
		OIDCClientSecret: setupStrPtr(reqCfg.OIDCClientSecret),
		GroupClaim:       setupStrPtr(reqCfg.GroupClaim),
		GroupMapping:     reqCfg.GroupMapping,
		EMAEnabled:       setupBoolPtr(false),
		Enabled:          setupBoolPtr(reqCfg.Enabled),
	}
	reqCtx, cancel := withRequestTimeout(ctx)
	defer cancel()
	if _, err := client.Update(reqCtx, reqCfg.TenantID, upd); err != nil {
		return describeIdpConfigError(err)
	}
	fmt.Fprintf(os.Stderr, "%s IdP configuration updated for tenant %q.\n", output.IconSuccess, reqCfg.TenantID)
	printPostSetupHint(reqCfg.TenantID)
	return nil
}

// describeIdpConfigError turns an *IdpConfigError into an actionable message for
// the common statuses (401/404/422); other errors pass through.
func describeIdpConfigError(err error) error {
	var ce *auth.IdpConfigError
	if !errors.As(err, &ce) {
		return err
	}
	switch ce.StatusCode {
	case http.StatusUnauthorized:
		return fmt.Errorf("not authorized (401): %s\n  Check your Armis credentials — an admin API token is required to register an IdP configuration", detailOr(ce, "authentication failed"))
	case http.StatusForbidden:
		return fmt.Errorf("forbidden (403): %s\n  Your credentials may be scoped to a different tenant", detailOr(ce, "access denied"))
	case http.StatusNotFound:
		return fmt.Errorf("no existing configuration to update (404): %s\n  Run 'armis-cli auth setup' without --update to create it first", detailOr(ce, "not found"))
	case http.StatusUnprocessableEntity:
		return fmt.Errorf("the configuration was rejected (422): %s", detailOr(ce, "validation failed"))
	default:
		return err
	}
}

func detailOr(ce *auth.IdpConfigError, fallback string) string {
	if ce.Detail != "" {
		return ce.Detail
	}
	return fallback
}

// printPostSetupHint points the admin at the next step once a config exists.
func printPostSetupHint(tenantID string) {
	fmt.Fprintf(os.Stderr, "  Users can now sign in with: armis-cli auth login --tenant-id %s\n", tenantID)
}

// -- Interactive prompting ---------------------------------------------------

// promptSetupTenantID resolves the tenant to configure. When a value is already
// known (from --tenant-id / ARMIS_TENANT_ID) it is used as-is; otherwise the admin
// is asked. The tenant is resolved before anything else so we can pre-flight an
// existence check and branch between the create and update forms.
func promptSetupTenantID(known string) (string, error) {
	if known != "" {
		return known, nil
	}
	tenant := ""
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Title("Armis tenant ID").
				Description("Your Armis tenant identifier (also set via --tenant-id / ARMIS_TENANT_ID).").
				Value(&tenant),
		),
	).WithTheme(cmdutil.GetInstallTheme()).WithAccessible(!cli.ColorsEnabled())
	if err := form.Run(); err != nil {
		if errors.Is(err, huh.ErrUserAborted) {
			return "", fmt.Errorf("setup cancelled")
		}
		return "", err
	}
	return strings.TrimSpace(tenant), nil
}

// promptIdpConfig walks the admin through every configuration value, explaining
// where each comes from. Groups are collected per-role (admin, developer) so the
// admin maps IdP groups to known Armis roles rather than typing role names. Each
// role accepts a comma-separated list, so several groups can grant the same role.
// The tenant is resolved by the caller and shown for confirmation.
func promptIdpConfig(tenant string) (*auth.IdpConfigCreateRequest, error) {
	theme := cmdutil.GetInstallTheme()
	accessible := !cli.ColorsEnabled()

	cfg := &auth.IdpConfigCreateRequest{
		TenantID:   tenant,
		GroupClaim: defaultGroupClaim,
		Enabled:    true,
	}
	var adminGroups, developerGroups string

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Title("IdP type").
				Description("Your identity provider, e.g. okta, entra, keycloak.").
				Value(&cfg.IdpType),
			huh.NewInput().
				Title("Issuer URL").
				Description("The IdP's OIDC issuer (from its discovery document), e.g. https://acme.okta.com.").
				Value(&cfg.Issuer),
		),
		huh.NewGroup(
			huh.NewInput().
				Title("OIDC client ID").
				Description("The client ID from the armis-cli app you registered in your IdP.").
				Value(&cfg.OIDCClientID),
			huh.NewInput().
				Title("OIDC client secret").
				Description("The client secret for that app. Sent once to register — never stored or printed.").
				EchoMode(huh.EchoModePassword).
				Value(&cfg.OIDCClientSecret),
			huh.NewInput().
				Title("Group claim").
				Description("The ID-token claim carrying the user's groups (default: groups).").
				Value(&cfg.GroupClaim),
		),
		huh.NewGroup(
			huh.NewNote().
				Title("Map IdP groups to Armis roles").
				Description("Enter the IdP group names that grant each role, comma-separated.\nList several groups for a role if more than one should have it.\nLeave a role blank to skip it — at least one is required."),
			huh.NewInput().
				Title("IdP groups for the 'admin' role").
				Description("Comma-separated. Users in any of these groups become Armis admins.").
				Value(&adminGroups),
			huh.NewInput().
				Title("IdP groups for the 'developer' role").
				Description("Comma-separated, e.g. core-developers, contract-developers.").
				Value(&developerGroups),
		),
	).WithTheme(theme).WithAccessible(accessible)

	if err := form.Run(); err != nil {
		if errors.Is(err, huh.ErrUserAborted) {
			return nil, fmt.Errorf("setup cancelled")
		}
		return nil, err
	}

	if cfg.GroupClaim == "" {
		cfg.GroupClaim = defaultGroupClaim
	}

	byRole := map[string][]string{}
	if g := splitGroups(adminGroups); len(g) > 0 {
		byRole[roleAdmin] = g
	}
	if g := splitGroups(developerGroups); len(g) > 0 {
		byRole[roleDeveloper] = g
	}
	mapping, err := assembleGroupMapping(byRole)
	if err != nil {
		return nil, err
	}
	cfg.GroupMapping = mapping

	return cfg, nil
}

// splitGroups parses a comma-separated group list, trimming blanks.
func splitGroups(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// assembleGroupMapping flattens the role→groups input the CLI collects into the
// group→role map the backend stores. It validates every role and rejects a group
// listed under two different roles (a group can grant only one Armis role).
func assembleGroupMapping(byRole map[string][]string) (map[string]string, error) {
	out := map[string]string{}
	for role, groups := range byRole {
		if role != roleAdmin && role != roleDeveloper {
			return nil, fmt.Errorf("group_mapping has unrecognized role %q; use %q or %q", role, roleAdmin, roleDeveloper)
		}
		for _, g := range groups {
			g = strings.TrimSpace(g)
			if g == "" {
				continue
			}
			if existing, ok := out[g]; ok && existing != role {
				return nil, fmt.Errorf("group %q is mapped to both %q and %q; a group can grant only one role", g, existing, role)
			}
			out[g] = role
		}
	}
	return out, nil
}

// promptIdpConfigUpdate shows an edit form pre-filled from the existing config and
// returns an update request carrying only the fields the admin changed, plus a
// flag indicating whether anything changed. The secret starts blank (the API never
// returns it) and is sent only if the admin types a new one — so a group-mapping
// tweak needs no secret. Group mappings are edited per role as comma-separated
// lists, pre-filled from the current mapping.
func promptIdpConfigUpdate(existing *auth.IdpConfigResponse) (*auth.IdpConfigUpdateRequest, bool, error) {
	theme := cmdutil.GetInstallTheme()
	accessible := !cli.ColorsEnabled()

	byRole := groupsByRole(existing.GroupMapping)
	idpType := existing.IdpType
	issuer := existing.Issuer
	clientID := existing.OIDCClientID
	groupClaim := existing.GroupClaim
	adminGroups := strings.Join(byRole[roleAdmin], ", ")
	developerGroups := strings.Join(byRole[roleDeveloper], ", ")
	enabled := existing.Enabled
	var newSecret string

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Title("IdP type").
				Description("Your identity provider, e.g. okta, entra, keycloak.").
				Value(&idpType),
			huh.NewInput().
				Title("Issuer URL").
				Description("The IdP's OIDC issuer (from its discovery document).").
				Value(&issuer),
		),
		huh.NewGroup(
			huh.NewInput().
				Title("OIDC client ID").
				Description("The client ID from the armis-cli app you registered in your IdP.").
				Value(&clientID),
			huh.NewInput().
				Title("New OIDC client secret").
				Description("Leave blank to keep the current secret. Type a value only to rotate it.").
				EchoMode(huh.EchoModePassword).
				Value(&newSecret),
			huh.NewInput().
				Title("Group claim").
				Description("The ID-token claim carrying the user's groups.").
				Value(&groupClaim),
		),
		huh.NewGroup(
			huh.NewNote().
				Title("Map IdP groups to Armis roles").
				Description("Comma-separated IdP group names per role. Edit to change the mapping;\nclear a role to remove all its groups. The mapping is replaced as edited."),
			huh.NewInput().
				Title("IdP groups for the 'admin' role").
				Value(&adminGroups),
			huh.NewInput().
				Title("IdP groups for the 'developer' role").
				Value(&developerGroups),
			huh.NewConfirm().
				Title("Enabled?").
				Description("Whether SSO login is active for this tenant.").
				Value(&enabled),
		),
	).WithTheme(theme).WithAccessible(accessible)

	if err := form.Run(); err != nil {
		if errors.Is(err, huh.ErrUserAborted) {
			return nil, false, fmt.Errorf("setup cancelled")
		}
		return nil, false, err
	}

	upd := &auth.IdpConfigUpdateRequest{}
	changed := false

	if v := strings.TrimSpace(idpType); v != existing.IdpType {
		upd.IdpType = setupStrPtr(v)
		changed = true
	}
	if v := strings.TrimSpace(issuer); v != existing.Issuer {
		upd.Issuer = setupStrPtr(v)
		changed = true
	}
	if v := strings.TrimSpace(clientID); v != existing.OIDCClientID {
		upd.OIDCClientID = setupStrPtr(v)
		changed = true
	}
	if v := strings.TrimSpace(groupClaim); v != existing.GroupClaim {
		upd.GroupClaim = setupStrPtr(v)
		changed = true
	}
	// Only rotate the secret when the admin actually typed one.
	if newSecret != "" {
		upd.OIDCClientSecret = setupStrPtr(newSecret)
		changed = true
	}
	if enabled != existing.Enabled {
		upd.Enabled = setupBoolPtr(enabled)
		changed = true
	}

	// Re-derive the mapping from the (possibly edited) per-role lists and send it
	// only when it differs from the stored one.
	newByRole := map[string][]string{}
	if g := splitGroups(adminGroups); len(g) > 0 {
		newByRole[roleAdmin] = g
	}
	if g := splitGroups(developerGroups); len(g) > 0 {
		newByRole[roleDeveloper] = g
	}
	mapping, err := assembleGroupMapping(newByRole)
	if err != nil {
		return nil, false, err
	}
	if len(mapping) == 0 {
		return nil, false, fmt.Errorf("at least one group→role mapping is required (map an IdP group to %q or %q)", roleAdmin, roleDeveloper)
	}
	if !sameMapping(mapping, existing.GroupMapping) {
		upd.GroupMapping = mapping
		changed = true
	}

	return upd, changed, nil
}

// sameMapping reports whether two group→role maps are identical.
func sameMapping(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// printIdpConfigUpdateSummary renders only the fields that will change, so the
// admin sees exactly what the merge update sends. The secret is shown as rotated
// (never printed) when present.
func printIdpConfigUpdateSummary(existing *auth.IdpConfigResponse, upd *auth.IdpConfigUpdateRequest) {
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintf(os.Stderr, "  Changes to send for tenant %q:\n", existing.TenantID)
	if upd.IdpType != nil {
		fmt.Fprintf(os.Stderr, "    IdP type:         %s → %s\n", existing.IdpType, *upd.IdpType)
	}
	if upd.Issuer != nil {
		fmt.Fprintf(os.Stderr, "    Issuer:           %s → %s\n", existing.Issuer, *upd.Issuer)
	}
	if upd.OIDCClientID != nil {
		fmt.Fprintf(os.Stderr, "    OIDC client ID:   %s → %s\n", existing.OIDCClientID, *upd.OIDCClientID)
	}
	if upd.OIDCClientSecret != nil {
		fmt.Fprintln(os.Stderr, "    OIDC secret:      (rotated)")
	}
	if upd.GroupClaim != nil {
		fmt.Fprintf(os.Stderr, "    Group claim:      %s → %s\n", existing.GroupClaim, *upd.GroupClaim)
	}
	if upd.Enabled != nil {
		fmt.Fprintf(os.Stderr, "    Enabled:          %t → %t\n", existing.Enabled, *upd.Enabled)
	}
	if upd.GroupMapping != nil {
		fmt.Fprintln(os.Stderr, "    Role → IdP groups:")
		byRole := groupsByRole(upd.GroupMapping)
		for _, role := range []string{roleAdmin, roleDeveloper} {
			if groups := byRole[role]; len(groups) > 0 {
				fmt.Fprintf(os.Stderr, "      %s: %s\n", role, strings.Join(groups, ", "))
			}
		}
	}
	fmt.Fprintln(os.Stderr, "")
}

// confirmSetup shows a yes/no confirmation before sending.
func confirmSetup(update bool) (bool, error) {
	action := "Create this IdP configuration?"
	if update {
		action = "Update this IdP configuration?"
	}
	confirmed := true
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewConfirm().
				Title(action).
				Affirmative("Yes, send it").
				Negative("No, cancel").
				Value(&confirmed),
		),
	).WithTheme(cmdutil.GetInstallTheme()).WithAccessible(!cli.ColorsEnabled())
	if err := form.Run(); err != nil {
		if errors.Is(err, huh.ErrUserAborted) {
			return false, nil
		}
		return false, err
	}
	return confirmed, nil
}

// confirmUpdateExisting asks whether to replace an existing config after a 409.
func confirmUpdateExisting(tenantID string) (bool, error) {
	update := true
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewConfirm().
				Title(fmt.Sprintf("A configuration already exists for tenant %q. Replace it?", tenantID)).
				Affirmative("Yes, update it").
				Negative("No, cancel").
				Value(&update),
		),
	).WithTheme(cmdutil.GetInstallTheme()).WithAccessible(!cli.ColorsEnabled())
	if err := form.Run(); err != nil {
		if errors.Is(err, huh.ErrUserAborted) {
			return false, nil
		}
		return false, err
	}
	return update, nil
}

// -- JSON input --------------------------------------------------------------

// idpConfigInput is the JSON shape accepted by --config. It mirrors the backend
// request except group_mapping, which is role→[groups] here (an admin thinks
// "which groups get the developer role?"), and is flattened to the backend's
// group→role map before sending.
type idpConfigInput struct {
	TenantID         string              `json:"tenant_id"`
	IdpType          string              `json:"idp_type"`
	Issuer           string              `json:"issuer"`
	OIDCClientID     string              `json:"oidc_client_id"`
	OIDCClientSecret string              `json:"oidc_client_secret"` //nolint:gosec // G117: JSON field name, not a secret value
	GroupClaim       string              `json:"group_claim"`
	GroupMapping     map[string][]string `json:"group_mapping"`
	Enabled          *bool               `json:"enabled"`
}

// readConfigFile reads an operator-supplied --config file, bounding the read to
// maxConfigBytes so a path to a huge file cannot exhaust memory.
func readConfigFile(path string) ([]byte, error) {
	// armis:ignore cwe:22 reason:path is the --config value the operator running the CLI chose; reading their own file from any location is the intended behavior, not attacker-controlled input
	f, err := os.Open(path) // #nosec G304 -- operator-supplied config path, read intentionally
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck // read-only
	return io.ReadAll(io.LimitReader(f, maxConfigBytes))
}

// loadIdpConfigFromJSON resolves --config (inline JSON, stdin, or a file path)
// and decodes it. Unknown fields are rejected so typos surface immediately.
func loadIdpConfigFromJSON(input string) (*auth.IdpConfigCreateRequest, error) {
	var raw []byte
	var err error

	switch {
	case input == "-":
		// An IdP config is a few hundred bytes; cap the read so an unbounded pipe
		// cannot exhaust memory.
		raw, err = io.ReadAll(io.LimitReader(os.Stdin, maxConfigBytes))
	case strings.HasPrefix(strings.TrimSpace(input), "{"):
		raw = []byte(input)
	default:
		raw, err = readConfigFile(input)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	in := &idpConfigInput{}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(in); err != nil {
		return nil, fmt.Errorf("invalid config JSON: %w", err)
	}

	mapping, err := assembleGroupMapping(in.GroupMapping)
	if err != nil {
		return nil, err
	}

	cfg := &auth.IdpConfigCreateRequest{
		TenantID:         in.TenantID,
		IdpType:          in.IdpType,
		Issuer:           in.Issuer,
		OIDCClientID:     in.OIDCClientID,
		OIDCClientSecret: in.OIDCClientSecret,
		GroupClaim:       in.GroupClaim,
		GroupMapping:     mapping,
		// Default enabled to true when omitted, matching the interactive path
		// and the backend model.
		Enabled: in.Enabled == nil || *in.Enabled,
	}
	if cfg.GroupClaim == "" {
		cfg.GroupClaim = defaultGroupClaim
	}
	return cfg, nil
}

// -- Validation & summary ----------------------------------------------------

// validateIdpConfig checks the required fields and that every group_mapping
// value is a recognized Armis role.
func validateIdpConfig(cfg *auth.IdpConfigCreateRequest) error {
	var missing []string
	if strings.TrimSpace(cfg.TenantID) == "" {
		missing = append(missing, "tenant_id")
	}
	if strings.TrimSpace(cfg.IdpType) == "" {
		missing = append(missing, "idp_type")
	}
	if strings.TrimSpace(cfg.Issuer) == "" {
		missing = append(missing, "issuer")
	}
	if strings.TrimSpace(cfg.OIDCClientID) == "" {
		missing = append(missing, "oidc_client_id")
	}
	if strings.TrimSpace(cfg.OIDCClientSecret) == "" {
		missing = append(missing, "oidc_client_secret")
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing required field(s): %s", strings.Join(missing, ", "))
	}

	if len(cfg.GroupMapping) == 0 {
		return fmt.Errorf("at least one group→role mapping is required (map an IdP group to %q or %q)", roleAdmin, roleDeveloper)
	}
	for group, role := range cfg.GroupMapping {
		if strings.TrimSpace(group) == "" {
			return fmt.Errorf("group_mapping has an empty group name")
		}
		if role != roleAdmin && role != roleDeveloper {
			return fmt.Errorf("group_mapping[%q] = %q is not a recognized role; use %q or %q", group, role, roleAdmin, roleDeveloper)
		}
	}
	return nil
}

// printIdpConfigSummary renders the configuration for review, masking the secret.
func printIdpConfigSummary(cfg *auth.IdpConfigCreateRequest) {
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "  Review IdP configuration:")
	fmt.Fprintf(os.Stderr, "    Tenant ID:        %s\n", cfg.TenantID)
	fmt.Fprintf(os.Stderr, "    IdP type:         %s\n", cfg.IdpType)
	fmt.Fprintf(os.Stderr, "    Issuer:           %s\n", cfg.Issuer)
	fmt.Fprintf(os.Stderr, "    OIDC client ID:   %s\n", cfg.OIDCClientID)
	fmt.Fprintf(os.Stderr, "    OIDC secret:      %s\n", maskSecret(cfg.OIDCClientSecret))
	fmt.Fprintf(os.Stderr, "    Group claim:      %s\n", cfg.GroupClaim)
	fmt.Fprintf(os.Stderr, "    Enabled:          %t\n", cfg.Enabled)
	fmt.Fprintln(os.Stderr, "    Role → IdP groups:")
	byRole := groupsByRole(cfg.GroupMapping)
	for _, role := range []string{roleAdmin, roleDeveloper} {
		if groups := byRole[role]; len(groups) > 0 {
			fmt.Fprintf(os.Stderr, "      %s: %s\n", role, strings.Join(groups, ", "))
		}
	}
	fmt.Fprintln(os.Stderr, "")
}

// groupsByRole inverts the backend's group→role map into role→[groups] for
// display, with each role's groups sorted for stable output.
func groupsByRole(mapping map[string]string) map[string][]string {
	out := map[string][]string{}
	for group, role := range mapping {
		out[role] = append(out[role], group)
	}
	for role := range out {
		sort.Strings(out[role])
	}
	return out
}

// maskSecret returns a fixed-width mask that reveals only the secret's length
// category, never its content.
func maskSecret(s string) string {
	if s == "" {
		return "(none)"
	}
	return fmt.Sprintf("•••••••• (%d chars)", len(s))
}

func setupStrPtr(s string) *string { return &s }
func setupBoolPtr(b bool) *bool    { return &b }
