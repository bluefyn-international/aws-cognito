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

use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Lang;
use Illuminate\Support\Facades\Password;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Auth\Authenticatable;
use Ellaisys\Cognito\Http\Parser\Parser;
use Ellaisys\Cognito\Exceptions\AwsCognitoException;
use Ellaisys\Cognito\Exceptions\InvalidTokenException;

class AwsCognito
{
    /**
     * The authentication provider.
     *
     * @var \Ellaisys\Cognito\Contracts\Providers\Auth
     */
    protected $auth;

    /**
     * Aws Cognito Manager
     *
     * @var \Ellaisys\Cognito\AwsCognitoManager
     */
    protected $manager;

    /**
     * The HTTP parser.
     *
     * @var \Ellaisys\Cognito\Http\Parser\Parser
     */
    protected $parser;

    /**
     * The AwsCognito Claim token
     * 
     * @var \Ellaisys\Cognito\AwsCognitoClaim|null
     */
    protected $claim;

    /**
     * The AWS Cognito token.
     *
     * @var \Ellaisys\Cognito\AwsCognitoToken|string|null
     */
    protected $token;

    /**
     * AwsCognito constructor.
     * @param AwsCognitoManager $manager
     * @param Parser            $parser
     */
    public function __construct(AwsCognitoManager $manager, Parser $parser)
    {
        $this->manager = $manager;
        $this->parser = $parser;
    }

    /**
     * @return AwsCognitoToken|string|null
     */
    public function getToken()
    {
        if ($this->token === null) {
            try {
                $this->parseToken();
            } catch (AwsCognitoException $e) {
                $this->token = null;
            }
        }

        return $this->token;
    }

    /**
     * @return $this
     *
     * @throws AwsCognitoException
     */
    public function parseToken() : self
    {
        //Parse the token
        $token = $this->parser->parseToken();

        if (empty($token)) {
            throw new AwsCognitoException('The token could not be parsed from the request');
        }

        return $this->setToken($token);
    }


    /**
     * @param string $token
     *
     * @return $this
     *
     * @throws AwsCognitoException
     */
    public function setToken(string $token) : self
    {
        $this->token = (new AwsCognitoToken($token));
        if (empty($this->token)) {
            throw new AwsCognitoException('The token could not be validated.');
        }

        return $this;
    }


    /**
     * @return AwsCognitoClaim|null
     */
    public function getClaim()
    {
        return (!empty($this->claim))?$this->claim:null;
    }


    /**
     * @param AwsCognitoClaim $claim
     *
     * @return $this
     *
     * @throws AwsCognitoException
     */
    public function setClaim(AwsCognitoClaim $claim) : self
    {
        $this->claim = $claim;
        $this->token = $this->setToken($claim->getToken());

        return $this;
    }


    /**
     * @param bool $forceForever
     *
     * @return $this
     */
    public function unsetToken(bool $forceForever = false) : self
    {
        $tokenKey = $this->token->get();
        $this->manager->release($tokenKey);
        $this->claim = null;
        $this->token = null;

        return $this;
    }


    /**
     * @param Request $request
     *
     * @return $this
     */
    public function setRequest(Request $request) : self
    {
        $this->parser->setRequest($request);

        return $this;
    }


    /**
     * @return Parser
     */
    public function parser()
    {
        return $this->parser;
    }


    /**
     * @return $this
     *
     * @throws InvalidTokenException
     */
    public function authenticate() : self
    {
        $claim = $this->manager->fetch($this->token->get())->decode();
        $this->claim = $claim;

        if (empty($this->claim)) {
            throw new InvalidTokenException();
        }

        return $this; //->user();
    }


    /**
     * @return Authenticatable
     *
     * @throws InvalidTokenException
     */
    public function toUser()
    {
        return $this->authenticate()->user();
    }


    /**
     * @return Authenticatable|null
     *
     * @throws InvalidTokenException
     */
    public function user()
    {
        //Get Claim
        if (empty($this->claim)) {
            throw new InvalidTokenException();
        }

        return $this->claim->getUser();
    }


    /**
     * @return mixed
     */
    public function storeToken()
    {
        return $this->manager->encode($this->claim)->store();
    }

}