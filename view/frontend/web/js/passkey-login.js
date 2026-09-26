/**
 * Copyright © DMLab. All rights reserved.
 *
 * Discoverable ("Sign in with a passkey") storefront login for the Luma theme.
 *
 * Fetches PublicKeyCredentialRequestOptions from the options endpoint, runs the
 * WebAuthn assertion ceremony via navigator.credentials.get() with no
 * allowCredentials (a resident passkey is offered without an email), posts the
 * assertion to the verify endpoint, and reloads on success. Bound with
 * data-mage-init from passkey-button.phtml.
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
     * Build the navigator.credentials.get() publicKey options from the endpoint JSON.
     *
     * @param {Object} options
     * @return {Object}
     */
    function toRequestOptions(options) {
        return {
            challenge: base64UrlDecode(options.challenge),
            rpId: options.rpId,
            userVerification: options.userVerification,
            timeout: options.timeout,
            allowCredentials: (options.allowCredentials || []).map(function (descriptor) {
                return {
                    type: descriptor.type,
                    id: base64UrlDecode(descriptor.id),
                    transports: descriptor.transports
                };
            })
        };
    }

    /**
     * Serialize the browser assertion into the JSON the verify endpoint loads.
     *
     * @param {PublicKeyCredential} assertion
     * @return {Object}
     */
    function toPayload(assertion) {
        return {
            id: assertion.id,
            rawId: base64UrlEncode(assertion.rawId),
            type: assertion.type,
            response: {
                clientDataJSON: base64UrlEncode(assertion.response.clientDataJSON),
                authenticatorData: base64UrlEncode(assertion.response.authenticatorData),
                signature: base64UrlEncode(assertion.response.signature),
                userHandle: assertion.response.userHandle ?
                    base64UrlEncode(assertion.response.userHandle) : null
            }
        };
    }

    return function (config, element) {
        var $root = $(element),
            $button = $root.find('[data-role="passkey-login"]'),
            $message = $root.find('[data-role="passkey-message"]');

        function fail() {
            $button.prop('disabled', false);
            $message.text($t('Could not sign you in with a passkey. Please try again.'));
        }

        $button.on('click', function () {
            if ($button.prop('disabled')) {
                return;
            }

            if (!window.PublicKeyCredential) {
                $message.text($t('Passkeys are not supported on this browser.'));

                return;
            }

            $button.prop('disabled', true);
            $message.text('');

            post(config.optionsUrl, config, {}).then(function (options) {
                return navigator.credentials.get({publicKey: toRequestOptions(options)});
            }).then(function (assertion) {
                return post(config.verifyUrl, config, {
                    publicKeyCredential: JSON.stringify(toPayload(assertion))
                });
            }).then(function (result) {
                if (result && result.success) {
                    window.location.reload();

                    return;
                }

                fail();
            }).catch(fail);
        });
    };
});
