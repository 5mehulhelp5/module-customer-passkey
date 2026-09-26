/**
 * Copyright © DMLab. All rights reserved.
 *
 * My Account passkey management for the Luma theme.
 *
 * Add: fetches PublicKeyCredentialCreationOptions, runs the registration ceremony
 * via navigator.credentials.create(), posts the attestation to the verify
 * endpoint. Rename/Delete: post the row's entity_id (and a new label) to the
 * manage endpoints. Each successful action reloads the section. Bound with
 * data-mage-init from manage/list.phtml.
 */
define(['jquery', 'mage/translate'], function ($, $t) {
    'use strict';

    /**
     * Decode unpadded base64url (the WebAuthn JSON transport form) to an ArrayBuffer.
     *
     * @param {String} value
     * @return {ArrayBuffer}
     */
    function base64UrlDecode(value) {
        var pad = value.length % 4,
            base64 = value.replace(/-/g, '+').replace(/_/g, '/') + (pad ? '='.repeat(4 - pad) : ''),
            binary = window.atob(base64),
            bytes = new Uint8Array(binary.length),
            i;

        for (i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }

        return bytes.buffer;
    }

    /**
     * Encode an ArrayBuffer as unpadded base64url.
     *
     * @param {ArrayBuffer} buffer
     * @return {String}
     */
    function base64UrlEncode(buffer) {
        var bytes = new Uint8Array(buffer),
            binary = '',
            i;

        for (i = 0; i < bytes.length; i++) {
            binary += String.fromCharCode(bytes[i]);
        }

        return window.btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }

    /**
     * POST a form-encoded body (with the form key) and resolve the JSON response.
     *
     * @param {String} url
     * @param {Object} config
     * @param {Object} body
     * @return {Promise}
     */
    function post(url, config, body) {
        return $.ajax({
            url: url,
            type: 'POST',
            dataType: 'json',
            data: $.extend({form_key: config.formKey}, body)
        });
    }

    /**
     * Build the navigator.credentials.create() publicKey options from the endpoint JSON.
     *
     * @param {Object} options
     * @return {Object}
     */
    function toCreationOptions(options) {
        return {
            challenge: base64UrlDecode(options.challenge),
            rp: options.rp,
            user: {
                id: base64UrlDecode(options.user.id),
                name: options.user.name,
                displayName: options.user.displayName
            },
            pubKeyCredParams: options.pubKeyCredParams,
            timeout: options.timeout,
            authenticatorSelection: options.authenticatorSelection,
            attestation: options.attestation,
            excludeCredentials: (options.excludeCredentials || []).map(function (descriptor) {
                return {
                    type: descriptor.type,
                    id: base64UrlDecode(descriptor.id),
                    transports: descriptor.transports
                };
            })
        };
    }

    /**
     * Serialize the browser attestation into the JSON the verify endpoint loads.
     *
     * @param {PublicKeyCredential} credential
     * @return {Object}
     */
    function toPayload(credential) {
        return {
            id: credential.id,
            rawId: base64UrlEncode(credential.rawId),
            type: credential.type,
            response: {
                clientDataJSON: base64UrlEncode(credential.response.clientDataJSON),
                attestationObject: base64UrlEncode(credential.response.attestationObject)
            }
        };
    }

    return function (config, element) {
        var $root = $(element),
            $message = $root.find('[data-role="passkey-message"]');

        function notify(text) {
            $message.text(text);
        }

        function fail() {
            notify($t('Something went wrong. Please try again.'));
        }

        function reloadOn(result) {
            if (result && result.success) {
                window.location.reload();

                return;
            }

            notify(result && result.message ? result.message : $t('Something went wrong. Please try again.'));
        }

        $root.on('click', '[data-role="passkey-add"]', function () {
            if (!window.PublicKeyCredential) {
                notify($t('Passkeys are not supported on this browser.'));

                return;
            }

            notify('');

            post(config.optionsUrl, config, {}).then(function (options) {
                return navigator.credentials.create({publicKey: toCreationOptions(options)});
            }).then(function (credential) {
                return post(config.verifyUrl, config, {
                    publicKeyCredential: JSON.stringify(toPayload(credential))
                });
            }).then(reloadOn).catch(fail);
        });

        $root.on('click', '[data-role="passkey-rename"]', function () {
            var $row = $(this).closest('[data-role="passkey-row"]'),
                current = $row.find('[data-role="passkey-label"]').text(),
                label = window.prompt($t('New passkey name'), current);

            if (label === null) {
                return;
            }

            notify('');
            post(config.renameUrl, config, {
                entity_id: $row.data('entity-id'),
                label: label
            }).then(reloadOn).catch(fail);
        });

        $root.on('click', '[data-role="passkey-delete"]', function () {
            var $row = $(this).closest('[data-role="passkey-row"]');

            if (!window.confirm($t('Remove this passkey?'))) {
                return;
            }

            notify('');
            post(config.deleteUrl, config, {
                entity_id: $row.data('entity-id')
            }).then(reloadOn).catch(fail);
        });
    };
});
