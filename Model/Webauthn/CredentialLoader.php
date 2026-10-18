<?php
/**
 * Copyright © DMLab. All rights reserved.
 * Licensed under the Open Software License version 3.0 (OSL-3.0). See LICENSE.
 */
declare(strict_types=1);

namespace DmLab\CustomerPasskey\Model\Webauthn;

use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Webauthn\Exception\InvalidDataException;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialDescriptor;

/**
 * Turns the browser credential JSON (decoded to an array) into the library's
 * {@see PublicKeyCredential} via the library serializer.
 *
 * Only the `none` attestation statement support is registered (the manager's
 * default), matching the attestation conveyance this module requests. The
 * top-level shape is checked first: the library denormalizer neither rejects a
 * missing member nor a non-`public-key` type.
 */
class CredentialLoader
{
    /**
     * Load the credential, throwing on any malformed input.
     *
     * @param array<string,mixed> $credential
     * @throws \Throwable when the payload is not a valid public-key credential
     */
    public function load(array $credential): PublicKeyCredential
    {
        foreach (['id', 'rawId', 'type'] as $key) {
            if (!isset($credential[$key]) || !is_string($credential[$key])) {
                throw InvalidDataException::create($credential, sprintf('The parameter "%s" is invalid.', $key));
            }
        }
        if ($credential['type'] !== PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY) {
            throw InvalidDataException::create($credential, 'Unsupported credential type.');
        }
        if (!isset($credential['response']) || !is_array($credential['response'])) {
            throw InvalidDataException::create($credential, 'The parameter "response" is invalid.');
        }

        $loaded = (new WebauthnSerializerFactory(AttestationStatementSupportManager::create()))
            ->create()
            ->deserialize(json_encode($credential, JSON_THROW_ON_ERROR), PublicKeyCredential::class, 'json');
        if (!$loaded instanceof PublicKeyCredential) {
            throw InvalidDataException::create($credential, 'The credential could not be loaded.');
        }

        return $loaded;
    }
}
