<?php
/**
 * Copyright © DMLab. All rights reserved.
 */
declare(strict_types=1);

namespace DmLab\CustomerPasskey\Model\Authentication;

use DmLab\CustomerPasskey\Model\Config;
use DmLab\CustomerPasskey\Model\Webauthn\CredentialSourceRepository;
use DmLab\CustomerPasskey\Model\Webauthn\RelyingPartyEntityFactory;
use Webauthn\AttestationStatement\AttestationObjectLoader;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\PublicKeyCredentialLoader;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialSource;

/**
 * Verifies a WebAuthn authentication (assertion) response against the challenge
 * the {@see \DmLab\CustomerPasskey\Controller\Login\Options} controller
 * issued, returning the {@see PublicKeyCredentialSource} whose owning customer id
 * ({@see PublicKeyCredentialSource::$userHandle}) the caller logs in.
 *
 * The stored credential is resolved by the asserted credential id through our
 * storage ({@see CredentialSourceRepository}); an unknown id is rejected before
 * any cryptographic work. The library's request ceremony then enforces challenge
 * match, origin/RP-ID binding, user presence/verification, the signature against
 * the stored public key, and the sign counter — a counter that did not advance is
 * a cloned authenticator and throws. On success the source carries the fresh
 * counter for the caller to persist.
 */
class AssertionVerifier
{
    /**
     * @param Config $config
     * @param RelyingPartyEntityFactory $relyingPartyEntityFactory
     * @param CredentialSourceRepository $credentialSourceRepository
     */
    public function __construct(
        private readonly Config $config,
        private readonly RelyingPartyEntityFactory $relyingPartyEntityFactory,
        private readonly CredentialSourceRepository $credentialSourceRepository
    ) {
    }

    /**
     * Verify the assertion and return the authenticated credential source.
     *
     * @param string $challenge the raw challenge consumed from the session
     * @param array<string,mixed> $credential decoded browser credential JSON
     * @param int|null $expectedCustomerId the account an email-first request was
     *                 scoped to (0 = unknown email, rejects everything); null for an
     *                 unscoped discoverable request, which accepts any resident key
     * @param int|string|null $storeId
     * @throws \Throwable when the assertion is invalid (bad/expired challenge,
     *                    origin/RP-ID mismatch, unknown credential, credential not
     *                    owned by the scoped account, bad signature, counter
     *                    regression, …)
     */
    public function verify(
        string $challenge,
        array $credential,
        ?int $expectedCustomerId = null,
        $storeId = null
    ): PublicKeyCredentialSource {
        $rp = $this->relyingPartyEntityFactory->create($storeId);
        $rpId = (string)$rp->id;

        $options = PublicKeyCredentialRequestOptions::create(
            $challenge,
            $rpId === '' ? null : $rpId,
            [],
            $this->config->getUserVerification($storeId),
            $this->config->getTimeout($storeId)
        );

        $publicKeyCredential = $this->loader()->loadArray($credential);
        $response = $publicKeyCredential->response;
        if (!$response instanceof AuthenticatorAssertionResponse) {
            throw new \InvalidArgumentException('The credential is not an authentication (assertion) response.');
        }

        $source = $this->credentialSourceRepository->findOneByCredentialId($publicKeyCredential->getRawId());
        if ($source === null) {
            throw new \InvalidArgumentException('The credential is not registered.');
        }

        // Email-first request: the credential must belong to the scoped account.
        // An empty library allowCredentials list is not enforced by the request
        // ceremony, so this is checked here — it is also what makes disabling
        // passwordless login effective server-side (an unknown email scopes to 0).
        if ($expectedCustomerId !== null && (int)$source->userHandle !== $expectedCustomerId) {
            throw new \InvalidArgumentException('The credential does not belong to the requested account.');
        }

        return $this->validator()->check(
            $source,
            $response,
            $options,
            $rpId,
            $source->userHandle
        );
    }

    /**
     * Loader turning the browser credential JSON into library value objects.
     *
     * Only the `none` attestation statement support this module offers is registered;
     * an assertion carries no attestation statement, so the manager is a formality.
     */
    private function loader(): PublicKeyCredentialLoader
    {
        $support = AttestationStatementSupportManager::create();
        $support->add(NoneAttestationStatementSupport::create());

        return PublicKeyCredentialLoader::create(AttestationObjectLoader::create($support));
    }

    /**
     * Assertion-response validator running the standard request ceremony, whose
     * counter step ({@see \Webauthn\CeremonyStep\CheckCounter}) performs clone
     * detection.
     */
    private function validator(): AuthenticatorAssertionResponseValidator
    {
        return AuthenticatorAssertionResponseValidator::create(
            ceremonyStepManager: (new CeremonyStepManagerFactory())->requestCeremony()
        );
    }
}
