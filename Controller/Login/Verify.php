<?php
/**
 * Copyright © MageDevGroup. All rights reserved.
 */
declare(strict_types=1);

namespace MageDevGroup\CustomerPasskey\Controller\Login;

use MageDevGroup\CustomerPasskey\Model\Authentication\AssertionVerifier;
use MageDevGroup\CustomerPasskey\Model\Config;
use MageDevGroup\CustomerPasskey\Model\Security\RateLimiter;
use MageDevGroup\CustomerPasskey\Model\Webauthn\ChallengeStorage;
use MageDevGroup\CustomerPasskey\Model\Webauthn\CredentialSourceRepository;
use Magento\Customer\Api\CustomerRepositoryInterface;
use Magento\Customer\Api\Data\CustomerInterface;
use Magento\Customer\Model\AccountConfirmation;
use Magento\Customer\Model\AuthenticationInterface;
use Magento\Customer\Model\Config\Share;
use Magento\Customer\Model\Session;
use Magento\Framework\App\Action\HttpPostActionInterface;
use Magento\Framework\App\RequestInterface;
use Magento\Framework\Controller\Result\Json;
use Magento\Framework\Controller\Result\JsonFactory;
use Magento\Framework\Exception\LocalizedException;
use Magento\Store\Model\StoreManagerInterface;
use Psr\Log\LoggerInterface;
use Webauthn\PublicKeyCredentialSource;

/**
 * Completes a passwordless storefront login: validates the assertion the
 * authenticator produced for the options {@see Options} issued, then establishes
 * the customer session for the credential's owner.
 *
 * A public endpoint (no session exists yet). The one-time challenge is consumed
 * from the session before verification, so a replayed assertion finds none and is
 * rejected. Verification enforces origin/RP-ID binding, the signature against the
 * stored public key, and the sign counter (clone detection); the credential's
 * updated counter is persisted so a subsequent replay of the same assertion is
 * caught. Every failure is logged and reported generically — details, including
 * whether a credential exists, never reach the client.
 */
class Verify implements HttpPostActionInterface
{
    /** Throttle bucket and budget: caps assertion brute-forcing per client. */
    private const RATE_BUCKET = 'login_verify';
    private const RATE_MAX_ATTEMPTS = 10;
    private const RATE_WINDOW_SECONDS = 60;

    /**
     * @param Config $config
     * @param Session $customerSession
     * @param RequestInterface $request
     * @param AssertionVerifier $assertionVerifier
     * @param ChallengeStorage $challengeStorage
     * @param CredentialSourceRepository $credentialSourceRepository
     * @param CustomerRepositoryInterface $customerRepository
     * @param JsonFactory $resultJsonFactory
     * @param LoggerInterface $logger
     * @param RateLimiter $rateLimiter
     * @param StoreManagerInterface $storeManager
     * @param AuthenticationInterface $authentication
     * @param AccountConfirmation $accountConfirmation
     * @param Share $shareConfig
     */
    public function __construct(
        private readonly Config $config,
        private readonly Session $customerSession,
        private readonly RequestInterface $request,
        private readonly AssertionVerifier $assertionVerifier,
        private readonly ChallengeStorage $challengeStorage,
        private readonly CredentialSourceRepository $credentialSourceRepository,
        private readonly CustomerRepositoryInterface $customerRepository,
        private readonly JsonFactory $resultJsonFactory,
        private readonly LoggerInterface $logger,
        private readonly RateLimiter $rateLimiter,
        private readonly StoreManagerInterface $storeManager,
        private readonly AuthenticationInterface $authentication,
        private readonly AccountConfirmation $accountConfirmation,
        private readonly Share $shareConfig
    ) {
    }

    /**
     * Establish the session for the asserted credential's owner, or a JSON error.
     *
     * Status codes: 403 disabled, 429 throttled, 400 bad payload/challenge,
     * 422 invalid assertion.
     *
     * @return Json
     */
    public function execute(): Json
    {
        $result = $this->resultJsonFactory->create();

        if (!$this->config->isEnabled()) {
            return $this->error($result, 403, __('Passkey sign-in is not available.'));
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
            return $this->error($result, 400, __('Your passkey sign-in expired. Please try again.'));
        }

        try {
            $source = $this->assertionVerifier->verify($pending['challenge'], $credential, $pending['scope']);
            $this->credentialSourceRepository->saveCredentialSource($source);
            $this->login($source);
        } catch (\Throwable $e) {
            $this->logger->critical($e);

            return $this->error($result, 422, __('Could not sign you in with that passkey. Please try again.'));
        }

        return $result->setData(['success' => true, 'message' => __('Signed in.')]);
    }

    /**
     * Load the owning customer and start an authenticated storefront session.
     *
     * Regenerates the session id (native login semantics).
     *
     * @param PublicKeyCredentialSource $source
     * @throws \Magento\Framework\Exception\NoSuchEntityException when the owner is gone
     * @throws LocalizedException when the account is not eligible to sign in
     */
    private function login(PublicKeyCredentialSource $source): void
    {
        $customer = $this->customerRepository->getById((int)$source->userHandle);
        $this->assertEligible($customer);
        $this->customerSession->setCustomerDataAsLoggedIn($customer);
    }

    /**
     * Apply the native account eligibility gate a password login enforces: under
     * per-website account sharing the credential's owner must belong to the current
     * website (global sharing lets an account sign in on any website, matching
     * native login), the account must not be locked, and must be confirmed (both
     * new-account and pending email-change confirmation). A failure throws and the
     * caller reports it generically, so passkey login cannot sidestep policy that
     * password authentication applies.
     *
     * @param CustomerInterface $customer
     * @throws LocalizedException
     */
    private function assertEligible(CustomerInterface $customer): void
    {
        $customerWebsiteId = (int)$customer->getWebsiteId();
        if ($this->shareConfig->isWebsiteScope()
            && $customerWebsiteId !== (int)$this->storeManager->getStore()->getWebsiteId()
        ) {
            throw new LocalizedException(__('This passkey cannot be used to sign in here.'));
        }

        $customerId = (int)$customer->getId();
        if ($this->authentication->isLocked($customerId)) {
            throw new LocalizedException(__('This account is locked.'));
        }

        if ($customer->getConfirmation()
            && ($this->accountConfirmation->isConfirmationRequired(
                $customerWebsiteId,
                $customerId,
                (string)$customer->getEmail()
            )
                || $this->accountConfirmation->isEmailChangedConfirmationRequired(
                    $customerWebsiteId,
                    $customerId,
                    (string)$customer->getEmail()
                ))
        ) {
            throw new LocalizedException(__('This account is not confirmed.'));
        }
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
