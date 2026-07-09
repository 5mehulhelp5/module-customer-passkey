<?php
/**
 * Copyright © MageDevGroup. All rights reserved.
 */
declare(strict_types=1);

namespace MageDevGroup\CustomerPasskey\Model\Config\Source;

use MageDevGroup\CustomerPasskey\Model\Config;
use Magento\Framework\Data\OptionSourceInterface;

/**
 * Dropdown source for the authenticator-attachment preference — which class of
 * authenticator to steer the customer toward: built-in platform (Touch ID,
 * Windows Hello), roaming cross-platform (hardware key), or no restriction
 * ({@see Config::ATTACHMENT_ANY}).
 */
class AuthenticatorAttachment implements OptionSourceInterface
{
    /**
     * @inheritDoc
     *
     * @return array<int,array{value:string,label:\Magento\Framework\Phrase}>
     */
    public function toOptionArray(): array
    {
        return [
            ['value' => Config::ATTACHMENT_ANY, 'label' => __('Any')],
            ['value' => Config::ATTACHMENT_PLATFORM, 'label' => __('Platform (Touch ID, Windows Hello)')],
            ['value' => Config::ATTACHMENT_CROSS_PLATFORM, 'label' => __('Cross-platform (security key)')],
        ];
    }
}
