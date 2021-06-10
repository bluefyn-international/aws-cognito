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

use BluefynInternational\Cognito\Exceptions\AwsCognitoException;
use BluefynInternational\Cognito\Exceptions\InvalidTokenException;
use BluefynInternational\Cognito\Http\Parser\Parser;
use Illuminate\Contracts\Auth\Authenticatable;

class AwsCognito
{
    /**
     * The authentication provider.
     *
     * @var \BluefynInternational\Cognito\Contracts\Providers\Auth
     */
    protected $auth;

    /**
     * Aws Cognito Manager.
     *
     * @var \BluefynInternational\Cognito\AwsCognitoManager
     */
    protected $manager;

    /**
     * The HTTP parser.
     *
     * @var \BluefynInternational\Cognito\Http\Parser\Parser
     */
    protected $parser;

    /**
     * The AwsCognito Claim token.
     *
     * @var \BluefynInternational\Cognito\AwsCognitoClaim|null
     */
    protected $claim;

    /**
     * The AWS Cognito token.
     *
     * @var \BluefynInternational\Cognito\AwsCognitoToken|string|null
     */
    protected $token;

    /**
     * AwsCognito constructor.
     *
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
     * @throws AwsCognitoException
     *
     * @return $this
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
     * @throws AwsCognitoException
     *
     * @return $this
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
        return (! empty($this->claim)) ? $this->claim : null;
    }


    /**
     * @param AwsCognitoClaim $claim
     *
     * @throws AwsCognitoException
     *
     * @return $this
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
     * @throws InvalidTokenException
     *
     * @return $this
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
     * @throws InvalidTokenException
     *
     * @return Authenticatable
     */
    public function toUser()
    {
        return $this->authenticate()->user();
    }


    /**
     * @throws InvalidTokenException
     *
     * @return Authenticatable|null
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
