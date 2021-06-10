<?php

/*
 * This file is part of AWS Cognito Auth solution.
 *
 * (c) EllaiSys <support@ellaisys.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace BluefynInternational\Cognito;

use BluefynInternational\Cognito\Validators\AwsCognitoTokenValidator;

class AwsCognitoToken
{
    /**
     * @var string
     */
    private $token;

    /**
     * AwsCognitoToken constructor.
     *
     * @param $token
     */
    public function __construct($token)
    {
        $this->token = (string) (new AwsCognitoTokenValidator())->check($token);
    }

    /**
     * @return string
     */
    public function get()
    {
        return $this->token;
    }

    /**
     * @return string
     */
    public function __toString()
    {
        return $this->get();
    }
}
