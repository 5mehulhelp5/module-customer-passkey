<?php
/**
 * Copyright © MageDevGroup. All rights reserved.
 */
declare(strict_types=1);

namespace MageDevGroup\CustomerPasskey\Controller\Register;

use MageDevGroup\CustomerPasskey\Model\Config;
use MageDevGroup\CustomerPasskey\Model\Registration\AttestationVerifier;
use MageDevGroup\CustomerPasskey\Model\Security\RateLimiter;
use MageDevGroup\CustomerPasskey\Model\Webauthn\ChallengeStorage;
use MageDevGroup\CustomerPasskey\Model\Webauthn\CredentialSourceRepository;
use Magento\Customer\Api\Data\CustomerInterface;
use Magento\Customer\Model\Session;
use Magento\Framework\App\Action\HttpPostActionInterface;
use Magento\Framework\App\RequestInterface;
use Magento\Framework\Controller\Result\Json;
use Magento\Framework\Controller\Result\JsonFactory;
use Psr\Log\LoggerInterface;

/**
 * Completes passkey registration: validates the attestation the authenticator
 * produced for the options {@see Options} issued, then stores the new credential
 * for the logged-in customer with an optional label.
 *
 * The one-time challenge is consumed from the session before verification, so a
 * replayed attestation finds none and is rejected. A verified credential whose id
 * is already registered is refused (a passkey enrols once). Every validation
 * failure is logged and reported generically — details never reach the client.
 */
class Verify implements HttpPostActionInterface
{
    /** Throttle bucket and budget: caps attestation submissions per client. */
    private const RATE_BUCKET = 'register_verify';
    private const RATE_MAX_ATTEMPTS = 10;
    private const RATE_WINDOW_SECONDS = 60;

    /**
     * @param Config $config
     * @param Session $customerSession
     * @param RequestInterface $request
     * @param AttestationVerifier $attestationVerifier
     * @param ChallengeStorage $challengeStorage
     * @param CredentialSourceRepository $credentialSourceRepository
     * @param JsonFactory $resultJsonFactory
     * @param LoggerInterface $logger
     * @param RateLimiter $rateLimiter
     */
    public function __construct(
        private readonly Config $config,
        private readonly Session $customerSession,
        private readonly RequestInterface $request,
        private readonly AttestationVerifier $attestationVerifier,
        private readonly ChallengeStorage $challengeStorage,
        private readonly CredentialSourceRepository $credentialSourceRepository,
        private readonly JsonFactory $resultJsonFactory,
        private readonly LoggerInterface $logger,
        private readonly RateLimiter $rateLimiter
    ) {
    }

    /**
     * Store the attested credential, or a JSON error.
     *
     * Status codes: 403 disabled/anonymous, 429 throttled, 400 bad payload/challenge,
     * 409 duplicate, 422 invalid attestation.
     *
     * @return Json
     */
    public function execute(): Json
    {
        $result = $this->resultJsonFactory->create();

        if (!$this->config->isEnabled()) {
            return $this->error($result, 403, __('Passkeys are not available.'));
        }

        if (!$this->customerSession->isLoggedIn()) {
            return $this->error($result, 403, __('Please sign in to add a passkey.'));
        }

        if (!$this->rateLimiter->registerAttempt(
            self::RATE_BUCKET,
            self::RATE_MAX_ATTEMPTS,
            self::RATE_WINDOW_SECONDS
        )) {
            return $this->error($result, 429, __('Too many passkey attempts. Please wait and try again.'));
        }

        $credential = $this->decodeCredential();
        if ($credential === null) {
            return $this->error($result, 400, __('Invalid passkey payload.'));
        }

        $pending = $this->challengeStorage->consume();
        if ($pending === null || $pending['challenge'] === '') {
            return $this->error($result, 400, __('Your passkey registration expired. Please try again.'));
        }

        try {
            $customer = $this->customerSession->getCustomerData();
            $source = $this->attestationVerifier->verify(
                (int)$this->customerSession->getCustomerId(),
                (string)$customer->getEmail(),
                $this->displayName($customer),
                $pending['challenge'],
                $credential
            );
        } catch (\Throwable $e) {
            $this->logger->critical($e);

            return $this->error($result, 422, __('Could not verify your passkey. Please try again.'));
        }

        if ($this->credentialSourceRepository->findOneByCredentialId($source->publicKeyCredentialId) !== null) {
            return $this->error($result, 409, __('This passkey is already registered.'));
        }

        $label = trim((string)$this->request->getParam('label', ''));
        $this->credentialSourceRepository->saveNewCredential($source, $label !== '' ? $label : null);

        return $result->setData(['success' => true, 'message' => __('Passkey added.')]);
    }

    /**
     * The decoded browser credential JSON, or null when absent/malformed.
     *
     * @return array<string,mixed>|null
     */
    private function decodeCredential(): ?array
    {
        $raw = (string)$this->request->getParam('publicKeyCredential', '');
        if ($raw === '') {
            return null;
        }

        $decoded = json_decode($raw, true);

        return is_array($decoded) ? $decoded : null;
    }

    /**
     * The authenticator `displayName`: full name, or the email when name is blank.
     *
     * @param CustomerInterface $customer
     */
    private function displayName(CustomerInterface $customer): string
    {
        $name = trim(sprintf('%s %s', (string)$customer->getFirstname(), (string)$customer->getLastname()));

        return $name !== '' ? $name : (string)$customer->getEmail();
    }

    /**
     * Emit a JSON error with the given HTTP status.
     *
     * @param Json $result
     * @param int $code
     * @param \Magento\Framework\Phrase $message
     */
    private function error(Json $result, int $code, \Magento\Framework\Phrase $message): Json
    {
        return $result->setHttpResponseCode($code)->setData([
            'success' => false,
            'message' => $message,
        ]);
    }
}
