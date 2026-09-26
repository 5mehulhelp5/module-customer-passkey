# DmLab_CustomerPasskey

> Passwordless storefront login for Magento 2 with passkeys (WebAuthn / FIDO2).

![License](https://img.shields.io/badge/license-OSL--3.0-green) ![Magento](https://img.shields.io/badge/Magento-2.4-orange) ![PHP](https://img.shields.io/badge/PHP-8.3--8.5-blue) ![Version](https://img.shields.io/badge/version-0.0.1-lightgrey)

Passwordless, phishing-resistant customer login for the Magento 2 storefront using
**passkeys (WebAuthn / FIDO2)**. Magento is the relying party (verifier) — there is no
external IdP, no OIDC, and no shared SSO core. The module is standalone and coexists with
`customer-sso` on the same login page and the same `customer_entity`.

## Requirements

- Magento 2.4.9 (`magento/framework >= 103.0`), PHP 8.3–8.5
- `web-auth/webauthn-lib ^4.0`
- HTTPS on the storefront (WebAuthn requires a secure context)

## Install

```bash
composer require dmlab/module-customer-passkey
bin/magento module:enable DmLab_CustomerPasskey
bin/magento setup:upgrade
bin/magento setup:di:compile        # production mode
```

This creates the `dmlab_passkey_credential` table (one row per registered passkey,
cascades with its customer).

## Configuration

Admin → Stores → Configuration → **DMLab → Customer Passkey → General**
(`dmlab_customer_passkey/general/*`). Configurable per website/store view.

| Field | Default | Notes |
|---|---|---|
| Enable Passkey Login | No | Master switch; adds the button and enables all endpoints. |
| Relying Party Display Name | store name | Name the authenticator shows during a ceremony. |
| User Verification | preferred | `required` / `preferred` / `discouraged` — force PIN/biometric or not. |
| Authenticator Attachment | any | `any` / `platform` (Touch ID, Windows Hello) / `cross-platform` (security keys). |
| Ceremony Timeout (ms) | 60000 | Browser wait for the authenticator. |
| Allow Passwordless Sign-In | Yes | Offers usernameless "Sign in with a passkey" via discoverable credentials. The storefront login button also requires this to be Yes. |

The **RP ID** is derived from the base-URL host (e.g. `magento.loc`); the origin is validated
against the store URL. Both must be stable HTTPS hosts.

## Usage

**Add a passkey** — a logged-in customer opens My Account → **Passkeys**, clicks *Add a
passkey*, and completes the browser prompt (Touch ID / Face ID / Windows Hello / security key).
Credentials can be renamed and deleted from the same page; a customer can only manage their own.

**Passwordless login** — on the storefront login page a *Sign in with a passkey* button runs
`navigator.credentials.get()` with no email (discoverable/resident keys). A valid assertion resolves
the credential to its customer and establishes the storefront session. The button renders only when
*Allow Passwordless Sign-In* is Yes; with it disabled no passkey button is shown. The
`login/options` endpoint also accepts an `email` parameter (email-first, scoped `allowCredentials`),
but v1 ships no storefront UI that drives it.

## Endpoints

Frontend router `customerpasskey`:

| Ceremony | Options | Verify |
|---|---|---|
| Registration (logged-in) | `customerpasskey/register/options` | `customerpasskey/register/verify` |
| Authentication | `customerpasskey/login/options` | `customerpasskey/login/verify` |
| Manage | `customerpasskey/manage/index`, `.../rename`, `.../delete` | |

Challenges are one-time and stored in the customer session; ceremony endpoints are rate-limited.
The authenticator sign counter is persisted and checked on every assertion — a regression is
flagged as a possible clone and denied.

## Themes

Ships a Luma template and a Hyvä-compatible variant
(`view/frontend/templates/login/passkey-button-hyva.phtml`) that a Hyvä theme wires up by pointing
its `customer_account_login` layout at the template. The button renders on `customer_account_login`
only when the module is enabled and a usable ceremony is available, so it drops onto an existing
login page without assuming it is the only method.

## Coexistence

Standalone: depends only on `magento/framework` + `web-auth/webauthn-lib`. It does **not** use
`sso-core` and does **not** depend on `customer-sso`. When both are installed each simply adds its
own button to `customer_account_login`, and both resolve to the same `customer_entity` — no shared
core, no cross-module dependency.

## Browser / authenticator support

Any WebAuthn-capable browser: Chrome, Safari, Firefox, Edge. Authenticators: platform (Touch ID,
Face ID, Windows Hello, Android) and cross-platform (FIDO2 security keys). Passwordless requires
discoverable-credential support (current browsers + platform authenticators).

## Tests

```bash
vendor/bin/phpunit -c Test/Unit/phpunit.xml
```

Real-authenticator flows (Touch ID / security key) are verified manually.

## License

[OSL-3.0](LICENSE) © DMLab. Commercial licensing and support: <https://dmlab.work>.
