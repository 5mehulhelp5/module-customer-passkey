<?php
/**
 * Copyright © DMLab. All rights reserved.
 */
declare(strict_types=1);

namespace DmLab\CustomerPasskey\Model\Registration;

use Cose\Algorithms;
use DmLab\CustomerPasskey\Model\Config;
use DmLab\CustomerPasskey\Model\Webauthn\RelyingPartyEntityFactory;
use Webauthn\AttestationStatement\AttestationObjectLoader;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialLoader;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialUserEntity;

/**
 * Verifies a WebAuthn registration (attestation) response against the challenge
 * the {@see \DmLab\CustomerPasskey\Controller\Register\Options} controller
 * issued, returning the {@see PublicKeyCredentialSource} to persist.
 *
 * The original creation options are reconstructed from the consumed challenge plus
 * the logged-in customer (the relying party is Magento, so the customer is the
 * WebAuthn user). The library's creation ceremony then enforces challenge match,
 * origin/RP-ID binding, user presence/verification and a known attestation format;
 * any failure throws and the controller reports it generically.
 *
 * The `none` attestation format only is accepted — this module requests no
 * attestation conveyance (privacy-preserving, matching the options factory), so
 * authenticators return an empty statement.
 */
class AttestationVerifier
{
    /**
     * COSE algorithms accepted, mirroring the creation options: ES256 then RS256.
     */
    private const ALGORITHMS = [Algorithms::COSE_ALGORITHM_ES256, Algorithms::COSE_ALGORITHM_RS256];

    /**
     * @param RelyingPartyEntityFactory $relyingPartyEntityFactory
     * @param Config $config
     */
    public function __construct(
        private readonly RelyingPartyEntityFactory $relyingPartyEntityFactory,
        private readonly Config $config
    ) {
    }

    /**
     * Verify the attestation and return the credential source to store.
     *
     * @param int $customerId owning customer entity id (the WebAuthn user handle)
     * @param string $username account email issued as the credential's `name`
     * @param string $displayName human-friendly account name
     * @param string $challenge the raw challenge consumed from the session
     * @param array<string,mixed> $credential decoded browser credential JSON
     * @param int|string|null $storeId
     * @throws \Throwable when the attestation is invalid (bad/expired challenge,
     *                    origin/RP-ID mismatch, wrong response type, …)
     */
    public function verify(
        int $customerId,
        string $username,
        string $displayName,
        string $challenge,
        array $credential,
        $storeId = null
    ): PublicKeyCredentialSource {
        $rp = $this->relyingPartyEntityFactory->create($storeId);
        $options = PublicKeyCredentialCreationOptions::create(
            $rp,
            PublicKeyCredentialUserEntity::create($username, (string)$customerId, $displayName),
            $challenge,
            array_map(
                static fn(int $alg): PublicKeyCredentialParameters => PublicKeyCredentialParameters::createPk($alg),
                self::ALGORITHMS
            ),
            // Carry the configured user-verification requirement: the creation
            // ceremony reads it from authenticatorSelection, so without it a
            // modified client could skip a required PIN/biometric and still pass.
            AuthenticatorSelectionCriteria::create(null, $this->config->getUserVerification($storeId))
        );

        $publicKeyCredential = $this->loader()->loadArray($credential);
        $response = $publicKeyCredential->response;
        if (!$response instanceof AuthenticatorAttestationResponse) {
            throw new \InvalidArgumentException('The credential is not a registration (attestation) response.');
        }

        return $this->validator()->check($response, $options, (string)$rp->id);
    }

    /**
     * Loader turning the browser credential JSON into library value objects.
     *
     * Only the `none` attestation statement support this module offers is registered.
     */
    private function loader(): PublicKeyCredentialLoader
    {
        $support = AttestationStatementSupportManager::create();
        $support->add(NoneAttestationStatementSupport::create());

        return PublicKeyCredentialLoader::create(AttestationObjectLoader::create($support));
    }

    /**
     * Attestation-response validator running the standard creation ceremony.
     */
    private function validator(): AuthenticatorAttestationResponseValidator
    {
        return AuthenticatorAttestationResponseValidator::create(
            ceremonyStepManager: (new CeremonyStepManagerFactory())->creationCeremony()
        );
    }
}
