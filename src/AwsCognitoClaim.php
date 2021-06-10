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

use Aws\Result as AwsResult;
use BluefynInternational\Cognito\Validators\AwsCognitoTokenValidator;
use Exception;
use Illuminate\Contracts\Auth\Authenticatable;

class AwsCognitoClaim
{
    /**
     * @var string
     */
    public $token;


    /**
     * @var object
     */
    public $data;

    /**
     * @var string
     */
    public $username;

    /**
     * @var \Illuminate\Contracts\Auth\Authenticatable
     */
    public $user;

    /**
     * @var \mixed
     */
    public $sub;

    /**
     * AwsCognitoClaim constructor.
     *
     * @param AwsResult            $result
     * @param Authenticatable|null $user
     * @param string               $username
     *
     * @throws Exception
     */
    public function __construct(AwsResult $result, ?Authenticatable $user, string $username)
    {
        try {
            $authResult = $result['AuthenticationResult'];

            if (! is_array($authResult)) {
                throw new Exception('Malformed AWS Authentication Result.', 400);
            }

            //Create token object
            $token = $authResult['AccessToken'];

            $this->token = (string) (new AwsCognitoTokenValidator())->check($token);
            $this->data = $authResult;
            $this->username = $username;
            $this->user = $user;
            $this->sub = $user['id'];
        } catch (Exception $e) {
            throw $e;
        }
    }


    /**
     * Get the token.
     *
     * @return string
     */
    public function getToken()
    {
        return $this->token;
    }

    /**
     * Get the data.
     *
     * @return array
     */
    public function getData()
    {
        return $this->data;
    }

    /**
     * Get the User.
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable
     */
    public function getUser()
    {
        return $this->user;
    }

    /**
     * Get the Sub Data.
     *
     * @return mixed
     */
    public function getSub()
    {
        return $this->sub;
    }

    /**
     * Get the token when casting to string.
     *
     * @return string
     */
    public function __toString()
    {
        return $this->getToken();
    }
}
