<?php
/**
 * Copyright © DMLab. All rights reserved.
 */
declare(strict_types=1);

namespace DmLab\CustomerPasskey\Model\Webauthn;

use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialOptions;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRequestOptions;

/**
 * Serializes WebAuthn ceremony options into the browser-facing JSON shape the
 * WebAuthn API consumes (`PublicKeyCredentialCreationOptionsJSON`): binary
 * challenge and ids as unpadded base64url, camelCase keys, optional members
 * omitted when unset.
 *
 * Hand-rolled rather than via the library's Symfony-serializer factory so the
 * module depends only on `magento/framework` + `web-auth/webauthn-lib` — no
 * `symfony/serializer` — and emits no deprecations.
 */
class OptionsSerializer
{
    /**
     * The options as a JSON-ready associative array.
     *
     * @param PublicKeyCredentialOptions $options
     * @return array<string,mixed>
     */
    public function toArray(PublicKeyCredentialOptions $options): array
    {
        if ($options instanceof PublicKeyCredentialCreationOptions) {
            return $this->creation($options);
        }
        if ($options instanceof PublicKeyCredentialRequestOptions) {
            return $this->request($options);
        }

        throw new \InvalidArgumentException(sprintf('Unsupported options type "%s".', $options::class));
    }

    /**
     * Serialize creation options to their browser JSON array.
     *
     * @param PublicKeyCredentialCreationOptions $options
     * @return array<string,mixed>
     */
    private function creation(PublicKeyCredentialCreationOptions $options): array
    {
        $json = [
            'rp' => array_filter(
                ['id' => $options->rp->id, 'name' => $options->rp->name],
                static fn($v): bool => $v !== null
            ),
            'user' => [
                'id' => $this->base64Url($options->user->id),
                'name' => $options->user->name,
                'displayName' => $options->user->displayName,
            ],
            'challenge' => $this->base64Url($options->challenge),
            'pubKeyCredParams' => array_map(
                static fn(PublicKeyCredentialParameters $p): array => ['type' => $p->type, 'alg' => $p->alg],
                $options->pubKeyCredParams
            ),
        ];

        if ($options->timeout !== null) {
            $json['timeout'] = $options->timeout;
        }
        if ($options->excludeCredentials !== []) {
            $json['excludeCredentials'] = array_map(
                fn(PublicKeyCredentialDescriptor $d): array => $this->descriptor($d),
                $options->excludeCredentials
            );
        }
        if ($options->authenticatorSelection !== null) {
            $json['authenticatorSelection'] = $this->authenticatorSelection($options->authenticatorSelection);
        }
        if ($options->attestation !== null) {
            $json['attestation'] = $options->attestation;
        }

        return $json;
    }

    /**
     * Serialize request options to their browser JSON array
     * (`PublicKeyCredentialRequestOptionsJSON`): challenge as base64url, plus the
     * optional rpId, userVerification, allowCredentials and timeout when set.
     *
     * @param PublicKeyCredentialRequestOptions $options
     * @return array<string,mixed>
     */
    private function request(PublicKeyCredentialRequestOptions $options): array
    {
        $json = ['challenge' => $this->base64Url($options->challenge)];

        if ($options->rpId !== null) {
            $json['rpId'] = $options->rpId;
        }
        if ($options->userVerification !== null) {
            $json['userVerification'] = $options->userVerification;
        }
        if ($options->allowCredentials !== []) {
            $json['allowCredentials'] = array_map(
                fn(PublicKeyCredentialDescriptor $d): array => $this->descriptor($d),
                $options->allowCredentials
            );
        }
        if ($options->timeout !== null) {
            $json['timeout'] = $options->timeout;
        }

        return $json;
    }

    /**
     * Serialize a credential descriptor (id as base64url, transports when present).
     *
     * @param PublicKeyCredentialDescriptor $descriptor
     * @return array<string,mixed>
     */
    private function descriptor(PublicKeyCredentialDescriptor $descriptor): array
    {
        $json = ['type' => $descriptor->type, 'id' => $this->base64Url($descriptor->id)];
        if ($descriptor->transports !== []) {
            $json['transports'] = $descriptor->transports;
        }

        return $json;
    }

    /**
     * Serialize authenticator-selection criteria, omitting unset optional members.
     *
     * @param AuthenticatorSelectionCriteria $criteria
     * @return array<string,mixed>
     */
    private function authenticatorSelection(AuthenticatorSelectionCriteria $criteria): array
    {
        $json = ['userVerification' => $criteria->userVerification];
        if ($criteria->authenticatorAttachment !== null) {
            $json['authenticatorAttachment'] = $criteria->authenticatorAttachment;
        }
        if ($criteria->residentKey !== null) {
            $json['residentKey'] = $criteria->residentKey;
        }
        if ($criteria->requireResidentKey !== null) {
            $json['requireResidentKey'] = $criteria->requireResidentKey;
        }

        return $json;
    }

    /**
     * Encode raw bytes as unpadded base64url (the WebAuthn JSON transport form).
     *
     * @param string $raw
     */
    private function base64Url(string $raw): string
    {
        return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
    }
}
