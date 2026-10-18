<?php
/**
 * Copyright © DMLab. All rights reserved.
 * Licensed under the Open Software License version 3.0 (OSL-3.0). See LICENSE.
 */
declare(strict_types=1);

namespace DmLab\CustomerPasskey\Block\Adminhtml\Customer\Edit\Tab;

use DmLab\CustomerPasskey\Model\Credential;
use DmLab\CustomerPasskey\Model\CredentialRepository;
use Magento\Backend\Block\Template;
use Magento\Backend\Block\Template\Context;
use Magento\Ui\Component\Layout\Tabs\TabInterface;

/**
 * "Passkeys" tab on the admin customer edit page: lists the customer's passkeys
 * and lets an admin revoke one (e.g. a lost device). Shown only for an existing
 * customer and to roles granted `DmLab_CustomerPasskey::manage`.
 */
class Passkeys extends Template implements TabInterface
{
    public const ACL_RESOURCE = 'DmLab_CustomerPasskey::manage';

    /** Admin route revoking a passkey. */
    private const REVOKE_ROUTE = 'customerpasskey/customer/revoke';

    /**
     * @var string
     */
    protected $_template = 'DmLab_CustomerPasskey::customer/passkeys.phtml';

    /** @var Credential[]|null */
    private ?array $passkeys = null;

    /**
     * @param Context $context
     * @param CredentialRepository $credentials
     * @param array<string,mixed> $data
     */
    public function __construct(
        Context $context,
        private readonly CredentialRepository $credentials,
        array $data = []
    ) {
        parent::__construct($context, $data);
    }

    /**
     * The edited customer's id, or 0 on the new-customer page.
     */
    public function getCustomerId(): int
    {
        return (int)$this->getRequest()->getParam('id', 0);
    }

    /**
     * The customer's passkeys, oldest first (cached per render).
     *
     * @return Credential[]
     */
    public function getPasskeys(): array
    {
        if ($this->passkeys === null) {
            $this->passkeys = $this->credentials->listByCustomer($this->getCustomerId());
        }

        return $this->passkeys;
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
     * The revoke form action.
     */
    public function getRevokeUrl(): string
    {
        return $this->getUrl(self::REVOKE_ROUTE);
    }

    /**
     * @inheritdoc
     */
    public function getTabLabel()
    {
        return __('Passkeys');
    }

    /**
     * @inheritdoc
     */
    public function getTabTitle()
    {
        return __('Passkeys');
    }

    /**
     * @inheritdoc
     */
    public function getTabClass()
    {
        return '';
    }

    /**
     * @inheritdoc
     */
    public function getTabUrl()
    {
        return '';
    }

    /**
     * @inheritdoc
     */
    public function isAjaxLoaded()
    {
        return false;
    }

    /**
     * @inheritdoc
     */
    public function canShowTab()
    {
        return $this->getCustomerId() > 0 && $this->_authorization->isAllowed(self::ACL_RESOURCE);
    }

    /**
     * @inheritdoc
     */
    public function isHidden()
    {
        return false;
    }
}
