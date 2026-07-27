# SSO Setup Guide for IT Administrators

Configure Single Sign-On so your developers authenticate the Armis developer
tools (`armis-cli` and the Armis MCP plugins) with your organization's existing
identity provider (IdP) — Okta, Microsoft Entra ID, Keycloak, or any other
OIDC-compliant IdP.

With SSO, there are **no per-user secrets to distribute**: developers sign in
through your IdP in the browser, governed by your existing MFA and
conditional-access policies, and access follows their IdP state.

> Client credentials (`ARMIS_CLIENT_ID` / `ARMIS_CLIENT_SECRET`) remain
> supported for CI/CD and service accounts. SSO is for interactive use on
> developer machines.

## Overview

Three one-time steps by IT, then a one-time browser sign-in per developer:

1. **Register `armis-cli` as an OIDC app in your IdP** (Step 1).
2. **Register your IdP with Armis** and map IdP groups to Armis roles, using
   `armis-cli auth setup` (Step 2).
3. **Deploy `armis-cli` to developer machines via MDM** with two environment
   variables and no secrets (Step 3).

## Prerequisites

- **`armis-cli` installed on your admin machine**, to run the setup command. See
  the [`armis-cli` repository](https://github.com/ArmisSecurity/armis-cli).
- **Armis API credentials.** In VIPR, open `<base_VIPR_URL>/settings/api-access`
  and copy a `client_id` and `client_secret`.
- **Admin access to your IdP**, to create an application and configure claims.

You do **not** need to look up your `tenant_id` or region — `armis-cli auth
setup` reads both from your API credentials and prints the environment variables
to deploy in Step 3.

> **Regions.** The one place you must know your region is the **redirect URI** in
> Step 1. Armis currently has two regions: **default** (`https://moose.armis.com`)
> and **EU** (`https://eu.moose.armis.com`). Use the host that matches your
> deployment; if unsure, ask your Armis contact.

## Step 1 — Register `armis-cli` in your IdP

Create a **confidential OIDC / OAuth2 web application** in your IdP and configure:

- **Redirect URI:** `<your-region-host>/oauth2/device/callback`
  (e.g. `https://moose.armis.com/oauth2/device/callback`, or the `eu.` host for EU).
- **Grant type:** Authorization Code.
- **Scopes:** `openid`, `email`, `profile`.
- **Groups claim:** include the user's group memberships in the token under a
  claim (commonly `groups`). Armis uses this to assign each user's role.

Then collect these values for Step 2: **Issuer** (OIDC issuer URL), **Client ID**,
**Client secret**, the **group claim name**, and the **IdP groups** that should
become Armis admins and developers.

Provider-specific notes (follow your IdP's own docs for the current UI):

- **Okta** — Applications → Create App Integration → OIDC / Web Application. Issuer
  is your org URL (`https://<org>.okta.com`). Add a `groups` claim to the ID token
  set to emit **Always**, and assign the relevant groups to the app.
- **Microsoft Entra ID** — App registrations → New registration (platform: Web).
  Issuer is `https://login.microsoftonline.com/<tenant-guid>/v2.0`. Add a groups
  claim under Token configuration — Entra emits **group object IDs**, so use those
  IDs as the group values in Step 2.
- **Keycloak** — Clients → Create client (OpenID Connect), enable Client
  authentication + Standard flow. Issuer is `https://<host>/realms/<realm>`. Add a
  *Group Membership* mapper so groups appear under the `groups` claim.

## Step 2 — Register your IdP with Armis

From your admin machine, run:

```bash
armis-cli auth setup \
  --client-id "$ARMIS_CLIENT_ID" \
  --client-secret "$ARMIS_CLIENT_SECRET"
```

The command auto-detects your region and tenant from your credentials, 
then walks you through the values from Step 1: IdP type,
issuer, client ID, client secret, and group claim.

For the role mapping, it asks which IdP groups become **admins** (full
administrative access) and which become **developers** (day-to-day scanning). List
several groups per role if needed; each group maps to exactly one role.

It shows a review summary (client secret masked) for confirmation. The secret is
sent only in this one request — never printed, stored locally, or returned by the
API.

On success it prints the environment variables to deploy in Step 3.

## Step 3 — Deploy the tools to developer machines (MDM)

Roll `armis-cli` out through your MDM (see the
[repository](https://github.com/ArmisSecurity/armis-cli) for installers), then set
the environment variables from Step 2's output via MDM policy:

```bash
export ARMIS_TENANT_ID="acme"
export ARMIS_DEFAULT_AUTH_METHOD="SSO"
# Non-default regions only
export ARMIS_REGION="eu1"
```

The first Armis command a developer runs then opens the browser for sign-in
(they can also run `armis-cli auth login`). The session is shared across
`armis-cli` and the Armis MCP plugins, and tokens refresh silently.

## Verifying and updating

Re-running `armis-cli auth setup` fetches the existing configuration, shows the
current values (secrets excluded) and lets you **edit it in place** — for example 
to rotate the secret or change a group mapping. 
This both verifies the registration and is how you update it later.

For an end-to-end check, have a developer run `armis-cli auth login` and confirm
sign-in completes with the expected role.

## Troubleshooting

| Symptom | Fix |
| ------- | --- |
| Setup rejected as unauthorized | Wrong/expired API credentials. Re-copy them from `<base_VIPR_URL>/settings/api-access`. |
| Developer sign-in fails with "access denied" | The user isn't in any mapped group. Add their IdP group under `admin` or `developer` (Step 2). |
| Redirect / callback error during sign-in | The redirect URI in your IdP doesn't match your region host (Step 1). |


