<?php
/**
 * Copyright © DMLab. All rights reserved.
 */
declare(strict_types=1);

namespace DmLab\CustomerPasskey\Block\Manage;

use DmLab\CustomerPasskey\Model\Config;
use DmLab\CustomerPasskey\Model\Credential;
use DmLab\CustomerPasskey\Model\CredentialRepository;
use Magento\Customer\Model\Session;
use Magento\Framework\Data\Form\FormKey;
use Magento\Framework\Serialize\Serializer\Json;
use Magento\Framework\View\Element\Template;
use Magento\Framework\View\Element\Template\Context;

/**
 * Renders the signed-in customer's registered passkeys on the My Account
 * "Passkeys" page, plus the endpoints the JS drives (add via the registration
 * ceremony, rename, delete).
 *
 * Lists only the current customer's credentials — the block never accepts an id
 * from the request, so it cannot surface another shopper's passkeys. When the
 * module is disabled it still renders (the page is reachable) but reports no
 * passkeys and hides the add control via {@see isEnabled()}.
 */
class ListPasskeys extends Template
{
    /** Storefront route issuing the registration options (add a passkey). */
    private const REGISTER_OPTIONS_ROUTE = 'customerpasskey/register/options';

    /** Storefront route verifying the attestation (add a passkey). */
    private const REGISTER_VERIFY_ROUTE = 'customerpasskey/register/verify';

    /** Storefront route renaming a passkey. */
    private const RENAME_ROUTE = 'customerpasskey/manage/rename';

    /** Storefront route deleting a passkey. */
    private const DELETE_ROUTE = 'customerpasskey/manage/delete';

    /** @var Credential[]|null */
    private ?array $passkeys = null;

    /**
     * @param Context $context
     * @param Config $config
     * @param Session $customerSession
     * @param CredentialRepository $credentials
     * @param FormKey $formKey
     * @param Json $json
     * @param array<string,mixed> $data
     */
    public function __construct(
        Context $context,
        private readonly Config $config,
        private readonly Session $customerSession,
        private readonly CredentialRepository $credentials,
        private readonly FormKey $formKey,
        private readonly Json $json,
        array $data = []
    ) {
        parent::__construct($context, $data);
    }

    /**
     * Whether adding a passkey is offered (the module is enabled for the store).
     */
    public function isEnabled(): bool
    {
        return $this->config->isEnabled();
    }

    /**
     * The signed-in customer's registered passkeys, oldest first (cached per render).
     *
     * @return Credential[]
     */
    public function getPasskeys(): array
    {
        if ($this->passkeys === null) {
            $this->passkeys = $this->credentials->listByCustomer((int)$this->customerSession->getCustomerId());
        }

        return $this->passkeys;
    }

    /**
     * Whether the customer has at least one registered passkey.
     */
    public function hasPasskeys(): bool
    {
        return $this->getPasskeys() !== [];
    }

    /**
     * A credential's display label, falling back to a generic name when unset.
     *
     * @param Credential $credential
     */
    public function getLabel(Credential $credential): string
    {
        $label = $credential->label !== null ? trim($credential->label) : '';

        return $label !== '' ? $label : (string)__('Passkey');
    }

    /**
     * Format a stored timestamp for display, or an em dash when never set.
     *
     * @param string|null $value
     */
    public function renderDate(?string $value): string
    {
        if ($value === null || $value === '') {
            return '—';
        }

        return $this->formatDate($value, \IntlDateFormatter::MEDIUM, true);
    }

    /**
     * JSON config the JS component consumes: ceremony/manage endpoints + form key.
     */
    public function getJsonConfig(): string
    {
        return $this->json->serialize([
            'optionsUrl' => $this->getUrl(self::REGISTER_OPTIONS_ROUTE),
            'verifyUrl' => $this->getUrl(self::REGISTER_VERIFY_ROUTE),
            'renameUrl' => $this->getUrl(self::RENAME_ROUTE),
            'deleteUrl' => $this->getUrl(self::DELETE_ROUTE),
            'formKey' => $this->formKey->getFormKey(),
        ]);
    }
}
