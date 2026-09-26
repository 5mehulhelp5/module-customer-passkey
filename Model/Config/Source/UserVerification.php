<?php
/**
 * Copyright © DMLab. All rights reserved.
 */
declare(strict_types=1);

namespace DmLab\CustomerPasskey\Model\Config\Source;

use DmLab\CustomerPasskey\Model\Config;
use Magento\Framework\Data\OptionSourceInterface;

/**
 * Dropdown source for the WebAuthn user-verification requirement — whether the
 * authenticator must prove the user (PIN/biometric) during a ceremony. The safe
 * default is {@see Config::USER_VERIFICATION_PREFERRED}.
 */
class UserVerification implements OptionSourceInterface
{
    /**
     * @inheritDoc
     *
     * @return array<int,array{value:string,label:\Magento\Framework\Phrase}>
     */
    public function toOptionArray(): array
    {
        return [
            ['value' => Config::USER_VERIFICATION_REQUIRED, 'label' => __('Required')],
            ['value' => Config::USER_VERIFICATION_PREFERRED, 'label' => __('Preferred')],
            ['value' => Config::USER_VERIFICATION_DISCOURAGED, 'label' => __('Discouraged')],
        ];
    }
}
