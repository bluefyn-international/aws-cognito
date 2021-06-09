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

use Ellaisys\Cognito\AwsCognitoClaim;
use Ellaisys\Cognito\AwsCognitoManager;
use Ellaisys\Cognito\Http\Parser\Parser;

use Exception;
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
     * JWT constructor.
     *
     * @param  \Ellaisys\Cognito\Manager  $manager
     * @param  \Ellaisys\Cognito\Http\Parser\Parser  $parser
     *
     * @return void
     */
    public function __construct(AwsCognitoManager $manager, Parser $parser)
    {
        $this->manager = $manager;
        $this->parser = $parser;
    }


    /**
     * Get the token.
     *
     * @return \Ellaisys\Cognito\AwsCognitoToken|null
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
     * Parse the token from the request.
     *
     * @throws \Ellaisys\Cognito\Exceptions\AwsCognitoException
     *
     * @return \Ellaisys\Cognito\AwsCognito
     */
    public function parseToken()
    {
        //Parse the token
        $token = $this->parser->parseToken();

        if (empty($token)) {
            throw new AwsCognitoException('The token could not be parsed from the request');
        }

        return $this->setToken($token);
    }


    /**
     * Set the token.
     *
     * @param  \string  $token
     *
     * @return \Ellaisys\Cognito\AwsCognito
     */
    public function setToken(string $token)
    {
        $this->token = (new AwsCognitoToken($token));
        if (empty($this->token)) {
            throw new AwsCognitoException('The token could not be validated.');
        }

        return $this;
    }


    /**
     * Get the token.
     *
     * @return \Ellaisys\Cognito\AwsCognitoClaim|null
     */
    public function getClaim()
    {
        return (!empty($this->claim))?$this->claim:null;
    }


    /**
     * Set the claim.
     *
     * @param  \Ellaisys\Cognito\AwsCognitoClaim  $claim
     *
     * @return \Ellaisys\Cognito\AwsCognito
     */
    public function setClaim(AwsCognitoClaim $claim)
    {
        $this->claim = $claim;
        $this->token = $this->setToken($claim->getToken());

        return $this;
    }


    /**
     * Unset the current token.
     *
     * @return \Ellaisys\Cognito\AwsCognito
     */
    public function unsetToken($forceForever = false)
    {
        $tokenKey = $this->token->get();
        $this->manager->release($tokenKey);
        $this->claim = null;
        $this->token = null;

        return $this;
    }


    /**
     * Set the request instance.
     *
     * @param  \Illuminate\Http\Request  $request
     *
     * @return \Ellaisys\Cognito\AwsCognito
     */
    public function setRequest(Request $request)
    {
        $this->parser->setRequest($request);

        return $this;
    }


    /**
     * Get the Parser instance.
     *
     * @return \Ellaisys\Cognito\Http\Parser\Parser
     */
    public function parser()
    {
        return $this->parser;
    }


    /**
     * Authenticate a user via a token.
     *
     * @return \Ellaisys\Cognito\AwsCognito|false
     */
    public function authenticate()
    {
        $claim = $this->manager->fetch($this->token->get())->decode();
        $this->claim = $claim;

        if (empty($this->claim)) {
            throw new InvalidTokenException();
        }

        return $this; //->user();
    }


    /**
     * Alias for authenticate().
     *
     * @return \Tymon\JWTAuth\Contracts\JWTSubject|false
     */
    public function toUser()
    {
        return $this->authenticate();
    }


    /**
     * Get the authenticated user.
     * 
     * @throws InvalidTokenException
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable
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
     * Persist token.
     *
     * @return \boolean
     */
    public function storeToken()
    {
        return $this->manager->encode($this->claim)->store();
    }

} //Class ends