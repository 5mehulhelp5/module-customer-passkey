<?php
/**
 * Copyright © DMLab. All rights reserved.
 * Licensed under the Open Software License version 3.0 (OSL-3.0). See LICENSE.
 */
declare(strict_types=1);

namespace DmLab\CustomerPasskey\Controller\Login;

use DmLab\CustomerPasskey\Model\Authentication\RequestOptionsFactory;
use DmLab\CustomerPasskey\Model\Config;
use DmLab\CustomerPasskey\Model\Security\RateLimiter;
use DmLab\CustomerPasskey\Model\Webauthn\ChallengeStorage;
use DmLab\CustomerPasskey\Model\Webauthn\OptionsSerializer;
use Magento\Customer\Api\CustomerRepositoryInterface;
use Magento\Framework\App\Action\HttpPostActionInterface;
use Magento\Framework\App\RequestInterface;
use Magento\Framework\Controller\Result\Json;
use Magento\Framework\Controller\Result\JsonFactory;
use Magento\Framework\Exception\NoSuchEntityException;
use Magento\Store\Model\StoreManagerInterface;
use Psr\Log\LoggerInterface;

/**
 * Returns the {@see \Webauthn\PublicKeyCredentialRequestOptions} that drive
 * `navigator.credentials.get()` for a passwordless storefront login, and persists
 * the freshly generated challenge in the session for the verify step to consume.
 *
 * A public endpoint (login runs before a session exists). Options are always
 * discoverable (empty `allowCredentials`), so the response is identical for any
 * email. Without an `email` it is offered only when passwordless login is enabled;
 * an `email` only scopes the stored challenge to that account (0 when unknown),
 * which the verify step enforces server-side.
 */
class Options implements HttpPostActionInterface
{
    /** Throttle bucket and budget: caps discoverable-options / challenge minting. */
    private const RATE_BUCKET = 'login_options';
    private const RATE_MAX_ATTEMPTS = 30;
    private const RATE_WINDOW_SECONDS = 60;

    /**
     * @param Config $config
     * @param RequestOptionsFactory $requestOptionsFactory
     * @param ChallengeStorage $challengeStorage
     * @param OptionsSerializer $optionsSerializer
     * @param CustomerRepositoryInterface $customerRepository
     * @param StoreManagerInterface $storeManager
     * @param RequestInterface $request
     * @param JsonFactory $resultJsonFactory
     * @param LoggerInterface $logger
     * @param RateLimiter $rateLimiter
     */
    public function __construct(
        private readonly Config $config,
        private readonly RequestOptionsFactory $requestOptionsFactory,
        private readonly ChallengeStorage $challengeStorage,
        private readonly OptionsSerializer $optionsSerializer,
        private readonly CustomerRepositoryInterface $customerRepository,
        private readonly StoreManagerInterface $storeManager,
        private readonly RequestInterface $request,
        private readonly JsonFactory $resultJsonFactory,
        private readonly LoggerInterface $logger,
        private readonly RateLimiter $rateLimiter
    ) {
    }

    /**
     * Emit the request options, or a JSON error.
     *
     * Status codes: 403 disabled, 429 throttled, 400 email required (discoverable
     * off), 500 failure.
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

        $email = trim((string)$this->request->getParam('email', ''));
        if ($email === '' && !$this->config->isPasswordlessAllowed()) {
            return $this->error($result, 400, __('Please enter your email to sign in with a passkey.'));
        }

        try {
            // No email → unscoped, any resident key may assert. An email scopes the
            // challenge to its account (0 when unknown) for the verify step only.
            $scope = $email !== '' ? ($this->resolveCustomerId($email) ?? 0) : null;
            $options = $this->requestOptionsFactory->create();

            $this->challengeStorage->save(ChallengeStorage::CEREMONY_LOGIN, $options->challenge, $scope);

            return $result->setData($this->optionsSerializer->toArray($options));
        } catch (\Throwable $e) {
            $this->logger->critical($e);

            return $this->error($result, 500, __('Could not start passkey sign-in. Please try again.'));
        }
    }

    /**
     * The current website's customer id for the email, or null when unknown.
     *
     * Used only for the server-side challenge scope, never in the response.
     *
     * @param string $email
     */
    private function resolveCustomerId(string $email): ?int
    {
        try {
            $websiteId = (int)$this->storeManager->getStore()->getWebsiteId();

            return (int)$this->customerRepository->get($email, $websiteId)->getId();
        } catch (NoSuchEntityException $e) {
            return null;
        }
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
