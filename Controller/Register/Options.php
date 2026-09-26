<?php
/**
 * Copyright © DMLab. All rights reserved.
 */
declare(strict_types=1);

namespace DmLab\CustomerPasskey\Controller\Register;

use DmLab\CustomerPasskey\Model\Config;
use DmLab\CustomerPasskey\Model\Registration\CreationOptionsFactory;
use DmLab\CustomerPasskey\Model\Security\RateLimiter;
use DmLab\CustomerPasskey\Model\Webauthn\ChallengeStorage;
use DmLab\CustomerPasskey\Model\Webauthn\OptionsSerializer;
use Magento\Customer\Api\Data\CustomerInterface;
use Magento\Customer\Model\Session;
use Magento\Framework\App\Action\HttpPostActionInterface;
use Magento\Framework\Controller\Result\Json;
use Magento\Framework\Controller\Result\JsonFactory;
use Psr\Log\LoggerInterface;

/**
 * Returns the {@see \Webauthn\PublicKeyCredentialCreationOptions} for the
 * logged-in customer to drive `navigator.credentials.create()`, and persists the
 * freshly generated challenge in the session for the verify step to consume.
 *
 * Requires an authenticated customer — a passkey always enrols against a known
 * account, so an anonymous request is refused with 403. Any build failure is
 * logged and reported generically; the raw options are never partially emitted.
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
     */
    public function __construct(
        private readonly Config $config,
        private readonly Session $customerSession,
        private readonly CreationOptionsFactory $creationOptionsFactory,
        private readonly ChallengeStorage $challengeStorage,
        private readonly OptionsSerializer $optionsSerializer,
        private readonly JsonFactory $resultJsonFactory,
        private readonly LoggerInterface $logger,
        private readonly RateLimiter $rateLimiter
    ) {
    }

    /**
     * Emit the creation options, or a JSON error (403 disabled/anonymous /
     * 429 throttled / 500 failure).
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

        try {
            $customer = $this->customerSession->getCustomerData();
            $options = $this->creationOptionsFactory->create(
                (int)$this->customerSession->getCustomerId(),
                (string)$customer->getEmail(),
                $this->displayName($customer)
            );

            $this->challengeStorage->save($options->challenge);

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
