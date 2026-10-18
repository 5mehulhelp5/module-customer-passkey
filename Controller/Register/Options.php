<?php
/**
 * Copyright © DMLab. All rights reserved.
 * Licensed under the Open Software License version 3.0 (OSL-3.0). See LICENSE.
 */
declare(strict_types=1);

namespace DmLab\CustomerPasskey\Controller\Register;

use DmLab\CustomerPasskey\Model\Config;
use DmLab\CustomerPasskey\Model\Registration\CreationOptionsFactory;
use DmLab\CustomerPasskey\Model\Security\RateLimiter;
use DmLab\CustomerPasskey\Model\Security\RecentAuthentication;
use DmLab\CustomerPasskey\Model\Webauthn\ChallengeStorage;
use DmLab\CustomerPasskey\Model\Webauthn\OptionsSerializer;
use Magento\Customer\Api\Data\CustomerInterface;
use Magento\Customer\Model\Session;
use Magento\Framework\App\Action\HttpPostActionInterface;
use Magento\Framework\App\RequestInterface;
use Magento\Framework\Controller\Result\Json;
use Magento\Framework\Controller\Result\JsonFactory;
use Magento\Framework\Phrase;
use Psr\Log\LoggerInterface;

/**
 * Returns the {@see \Webauthn\PublicKeyCredentialCreationOptions} for the
 * logged-in customer to drive `navigator.credentials.create()`, and persists the
 * freshly generated challenge, bound to this customer, for the verify step to consume.
 *
 * Requires an authenticated customer — a passkey always enrols against a known
 * account, so an anonymous request is refused with 403. Outside the
 * re-authentication window the customer must confirm their password (`password`
 * param) first, else 401 with `reauth: true`. Any build failure is logged and
 * reported generically; the raw options are never partially emitted.
 */
class Options implements HttpPostActionInterface
{
    /** Throttle bucket and budget: caps challenge minting per client. */
    private const RATE_BUCKET = 'register_options';
    private const RATE_MAX_ATTEMPTS = 30;
    private const RATE_WINDOW_SECONDS = 60;

    /**
     * @param Config $config
     * @param Session $customerSession
     * @param CreationOptionsFactory $creationOptionsFactory
     * @param ChallengeStorage $challengeStorage
     * @param OptionsSerializer $optionsSerializer
     * @param JsonFactory $resultJsonFactory
     * @param LoggerInterface $logger
     * @param RateLimiter $rateLimiter
     * @param RecentAuthentication $recentAuthentication
     * @param RequestInterface $request
     */
    public function __construct(
        private readonly Config $config,
        private readonly Session $customerSession,
        private readonly CreationOptionsFactory $creationOptionsFactory,
        private readonly ChallengeStorage $challengeStorage,
        private readonly OptionsSerializer $optionsSerializer,
        private readonly JsonFactory $resultJsonFactory,
        private readonly LoggerInterface $logger,
        private readonly RateLimiter $rateLimiter,
        private readonly RecentAuthentication $recentAuthentication,
        private readonly RequestInterface $request
    ) {
    }

    /**
     * Emit the creation options, or a JSON error (403 disabled/anonymous /
     * 429 throttled / 401 re-authentication required / 500 failure).
     *
     * @return Json
     */
    public function execute(): Json
    {
        $result = $this->resultJsonFactory->create();

        if (!$this->config->isEnabled()) {
            return $result->setHttpResponseCode(403)->setData([
                'success' => false,
                'message' => __('Passkeys are not available.'),
            ]);
        }

        if (!$this->customerSession->isLoggedIn()) {
            return $result->setHttpResponseCode(403)->setData([
                'success' => false,
                'message' => __('Please sign in to add a passkey.'),
            ]);
        }

        if (!$this->rateLimiter->registerAttempt(
            self::RATE_BUCKET,
            self::RATE_MAX_ATTEMPTS,
            self::RATE_WINDOW_SECONDS
        )) {
            return $result->setHttpResponseCode(429)->setData([
                'success' => false,
                'message' => __('Too many passkey attempts. Please wait and try again.'),
            ]);
        }

        if (!$this->recentAuthentication->isFresh()) {
            $password = (string)$this->request->getParam('password', '');
            $customerId = (int)$this->customerSession->getCustomerId();
            if ($password === '' || !$this->recentAuthentication->confirmPassword($customerId, $password)) {
                return $result->setHttpResponseCode(401)->setData([
                    'success' => false,
                    'reauth' => true,
                    'message' => $this->reauthMessage($password !== ''),
                ]);
            }
            $this->recentAuthentication->markNow();
        }

        try {
            $customer = $this->customerSession->getCustomerData();
            $customerId = (int)$this->customerSession->getCustomerId();
            $options = $this->creationOptionsFactory->create(
                $customerId,
                (string)$customer->getEmail(),
                $this->displayName($customer)
            );

            $this->challengeStorage->save(ChallengeStorage::CEREMONY_REGISTER, $options->challenge, $customerId);

            return $result->setData($this->optionsSerializer->toArray($options));
        } catch (\Throwable $e) {
            $this->logger->critical($e);

            return $result->setHttpResponseCode(500)->setData([
                'success' => false,
                'message' => __('Could not start passkey registration. Please try again.'),
            ]);
        }
    }

    /**
     * The 401 prompt; customers without a password (SSO) are told to sign in again.
     *
     * @param bool $passwordGiven
     */
    private function reauthMessage(bool $passwordGiven): Phrase
    {
        return $passwordGiven
            ? __('The password is incorrect. No password (e.g. SSO)? Sign out and sign in again.')
            : __('Confirm your password to add a passkey. No password (e.g. SSO)? Sign out and sign in again.');
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
}
