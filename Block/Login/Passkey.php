<?php
/**
 * Copyright © DMLab. All rights reserved.
 */
declare(strict_types=1);

namespace DmLab\CustomerPasskey\Block\Login;

use DmLab\CustomerPasskey\Model\Config;
use Magento\Framework\Data\Form\FormKey;
use Magento\Framework\Serialize\Serializer\Json;
use Magento\Framework\View\Element\Template;
use Magento\Framework\View\Element\Template\Context;

/**
 * "Sign in with a passkey" button injected into the storefront customer login page.
 *
 * Discoverable/usernameless login: the button runs `navigator.credentials.get()`
 * with no `allowCredentials`, so a resident passkey is offered without the shopper
 * typing an email. It is shown only when the module is enabled and passwordless
 * login is allowed; otherwise it renders nothing, leaving the native form (and any
 * other login-method module, e.g. `customer-sso`) untouched. Coexists with password
 * login rather than replacing it.
 */
class Passkey extends Template
{
    /** Storefront route issuing the request options (frontName/controller/action). */
    private const OPTIONS_ROUTE = 'customerpasskey/login/options';

    /** Storefront route verifying the assertion and establishing the session. */
    private const VERIFY_ROUTE = 'customerpasskey/login/verify';

    /**
     * @param Context $context
     * @param Config $config
     * @param FormKey $formKey
     * @param Json $json
     * @param array<string,mixed> $data
     */
    public function __construct(
        Context $context,
        private readonly Config $config,
        private readonly FormKey $formKey,
        private readonly Json $json,
        array $data = []
    ) {
        parent::__construct($context, $data);
    }

    /**
     * Whether the passkey button should be shown: enabled and discoverable login on.
     */
    public function isAvailable(): bool
    {
        return $this->config->isEnabled() && $this->config->isPasswordlessAllowed();
    }

    /**
     * The button label.
     */
    public function getButtonLabel(): string
    {
        return (string)__('Sign in with a passkey');
    }

    /**
     * JSON config the JS component consumes.
     *
     * Carries the ceremony endpoints and the form key the (public, POST) controllers
     * require.
     */
    public function getJsonConfig(): string
    {
        return $this->json->serialize([
            'optionsUrl' => $this->getUrl(self::OPTIONS_ROUTE),
            'verifyUrl' => $this->getUrl(self::VERIFY_ROUTE),
            'formKey' => $this->formKey->getFormKey(),
        ]);
    }

    /**
     * Render nothing unless the button is available (module off / passwordless off).
     */
    protected function _toHtml(): string
    {
        if (!$this->isAvailable()) {
            return '';
        }

        return parent::_toHtml();
    }
}
