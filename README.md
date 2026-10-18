# DmLab_CustomerPasskey

> Passwordless storefront login for Magento 2 with passkeys (WebAuthn / FIDO2).

[![CI](https://github.com/dmlab-work/module-customer-passkey/actions/workflows/ci.yml/badge.svg)](https://github.com/dmlab-work/module-customer-passkey/actions/workflows/ci.yml) [![codecov](https://codecov.io/gh/dmlab-work/module-customer-passkey/graph/badge.svg)](https://codecov.io/gh/dmlab-work/module-customer-passkey) [![Packagist Version](https://img.shields.io/packagist/v/dmlab/module-customer-passkey)](https://packagist.org/packages/dmlab/module-customer-passkey) [![Downloads](https://img.shields.io/packagist/dt/dmlab/module-customer-passkey)](https://packagist.org/packages/dmlab/module-customer-passkey) [![PHP](https://img.shields.io/packagist/dependency-v/dmlab/module-customer-passkey/php)](https://packagist.org/packages/dmlab/module-customer-passkey) [![License](https://img.shields.io/packagist/l/dmlab/module-customer-passkey)](LICENSE) ![Magento](https://img.shields.io/badge/Magento-2.4-orange)

Passwordless, phishing-resistant customer login for the Magento 2 storefront using
**passkeys (WebAuthn / FIDO2)**. Magento is the relying party (verifier) — there is no
external IdP, no OIDC, and no shared SSO core. The module is standalone and coexists with
`customer-sso` on the same login page and the same `customer_entity`.

## Requirements

- Magento 2.4.9 (`magento/framework >= 103.0`), PHP 8.3–8.5
- `web-auth/webauthn-lib ^5.3.5`, `web-auth/cose-lib ^4.8`, `symfony/serializer`, `symfony/uid` (`^6.4|^7.0|^8.0`)
- Magento modules Customer, Store, Config, Backend, Ui, Email (bundled with 2.4.9)
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

Upgrading from 0.1.x: passkeys registered as non-resident (passwordless was disabled) can no longer
sign in — affected customers must re-enrol.

## Configuration

Admin → Stores → Configuration → **DMLab → Customer Passkey**
(`dmlab_customer_passkey/*`). Configurable per website/store view.

**General** (`general/*`)

| Field | Default | Notes |
|---|---|---|
| Enable Passkey Login | No | Master switch; adds the button and enables all endpoints. |
| Relying Party Display Name | store name | Name the authenticator shows during a ceremony. |
| User Verification | preferred | `required` / `preferred` / `discouraged` — force PIN/biometric or not. |
| Authenticator Attachment | any | `any` / `platform` (Touch ID, Windows Hello) / `cross-platform` (security keys). |
| Ceremony Timeout (ms) | 60000 | Browser wait for the authenticator. |
| Allow Passwordless Sign-In | Yes | Offers usernameless "Sign in with a passkey" via discoverable credentials. With No there is no storefront passkey sign-in (no button; `login/options` requires an email). |
| Re-authentication Window (s) | 300 | Adding a passkey within this time after sign-in needs no password; later the current password is asked. |

**Notifications** (`notification/*`)

| Field | Default | Notes |
|---|---|---|
| Email Customer on Passkey Changes | Yes | Emails the customer when a passkey is added or removed (by the customer or an admin). |
| Email Sender | General Contact | Store email identity. |
| Passkey Added / Removed Template | module default | Override under Marketing → Email Templates. |

The **RP ID** is derived from the base-URL host (e.g. `magento.loc`); the origin is validated
against the store URL. Both must be stable HTTPS hosts.

## Usage

**Add a passkey** — a logged-in customer opens My Account → **Passkeys**, clicks *Add a
passkey*, and completes the browser prompt (Touch ID / Face ID / Windows Hello / security key).
Outside the re-authentication window the page asks for the current password first; customers without
a password (e.g. SSO-created) are told to sign in again. Wrong passwords count toward Magento's
customer lockout; a locked account is refused. "Login as Customer" sessions always need the password. Every new passkey is a resident
(discoverable) key. Credentials can be renamed and deleted from the same page; a customer can only
manage their own.

**Passwordless login** — on the storefront login page a *Sign in with a passkey* button runs
`navigator.credentials.get()` with no email (discoverable/resident keys). A valid assertion resolves
the credential to its customer and establishes the storefront session and refreshes private content
(minicart, customer name). The button renders only when *Allow Passwordless Sign-In* is Yes. Login is
discoverable-only: `allowCredentials` is always empty, so the response is identical for any email.
An optional `email` parameter on `login/options` only scopes the challenge server-side — the
assertion must then belong to that customer.

**Admin revoke** — Customers → All Customers → edit → **Passkeys** tab lists the customer's passkeys
(label, created, last used, AAGUID) with a *Revoke* action for a lost device. Requires ACL
`DmLab_CustomerPasskey::manage` (Customers → All Customers → Manage Customer Passkeys).

## Endpoints

Frontend router `customerpasskey`:

| Ceremony | Options | Verify |
|---|---|---|
| Registration (logged-in) | `customerpasskey/register/options` | `customerpasskey/register/verify` |
| Authentication | `customerpasskey/login/options` | `customerpasskey/login/verify` |
| Manage | `customerpasskey/manage/index`, `.../rename`, `.../delete` | |

Outside the re-authentication window `register/options` returns
`401 {"success": false, "reauth": true, "message": "..."}`; retry with a `password` param.

Admin router `customerpasskey` (ACL `DmLab_CustomerPasskey::manage`): `customerpasskey/customer/revoke`
— POST `customer_id`, `entity_id`, `form_key`; redirects back to the customer edit page.

Challenges are one-time, bound to their ceremony (a login challenge cannot complete a registration)
and stored in the customer session; ceremony endpoints are rate-limited.
The authenticator sign counter is persisted and checked on every assertion — a regression is
flagged as a possible clone and denied.

## Themes

Ships a Luma template and a Hyvä-compatible variant
(`view/frontend/templates/login/passkey-button-hyva.phtml`) that a Hyvä theme wires up by pointing
its `customer_account_login` layout at the template. The button renders on `customer_account_login`
only when the module is enabled and a usable ceremony is available, so it drops onto an existing
login page without assuming it is the only method.

## Coexistence

Standalone: depends only on Magento core modules + `web-auth/webauthn-lib`. It does **not** use
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
