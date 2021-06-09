<?php

/*
 * This file is part of AWS Cognito Auth solution.
 *
 * (c) EllaiSys <support@ellaisys.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Ellaisys\Cognito;

use Ellaisys\Cognito\Providers\StorageProvider;

class AwsCognitoManager
{
    /**
     * The provider.
     *
     * @var \Ellaisys\Cognito\Providers\StorageProvider
     */
    protected $provider;

    /**
     * The blacklist.
     *
     * @var \Tymon\JWTAuth\Blacklist
     */
    protected $blacklist;

    /**
     * The AWS Cognito token.
     *
     * @var string|null
     */
    protected $token;

    /**
     * The AwsCognito Claim token.
     *
     * @var \Ellaisys\Cognito\AwsCognitoClaim|null
     */
    protected $claim;

    /**
     * AwsCognitoManager constructor.
     *
     * @param StorageProvider               $provider
     * @param null|\Tymon\JWTAuth\Blacklist $blacklist
     */
    public function __construct(StorageProvider $provider, $blacklist = null)
    {
        $this->provider = $provider;
        $this->blacklist = $blacklist;
    }

    /**
     * @param \Ellaisys\Cognito\AwsCognitoClaim $claim
     *
     * @return $this
     */
    public function encode(AwsCognitoClaim $claim) : self
    {
        $this->claim = $claim;
        $this->token = $claim->getToken();

        return $this;
    }


    /**
     * @return \Ellaisys\Cognito\AwsCognitoClaim|null
     */
    public function decode()
    {
        return ($this->claim) ? $this->claim : null;
    }


    /**
     * @return bool
     */
    public function store() : bool
    {
        $data = $this->claim->getData();
        $durationInSecs = ($data) ? (int) $data['ExpiresIn'] : 3600;
        $this->provider->add($this->token, json_encode($this->claim), $durationInSecs);

        return true;
    }


    /**
     * @param string $token
     *
     * @return $this
     */
    public function fetch(string $token) : self
    {
        $this->token = $token;
        $claim = $this->provider->get($token);
        $this->claim = $claim ? json_decode($claim, true) : null;

        return $this;
    }


    /**
     * @param string $token
     *
     * @return $this
     */
    public function release(string $token) : self
    {
        $this->provider->destroy($token);

        return $this;
    }
}
