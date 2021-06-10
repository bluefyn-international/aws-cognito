<?php

/*
 * This file is part of AWS Cognito Auth solution.
 *
 * (c) EllaiSys <support@ellaisys.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace BluefynInternational\Cognito\Guards;

use Aws\CognitoIdentityProvider\Exception\CognitoIdentityProviderException;
use Aws\Result as AwsResult;
use BluefynInternational\Cognito\AwsCognito;
use BluefynInternational\Cognito\AwsCognitoClaim;
use BluefynInternational\Cognito\AwsCognitoClient;
use BluefynInternational\Cognito\Exceptions\AwsCognitoException;

use BluefynInternational\Cognito\Exceptions\InvalidUserModelException;
use BluefynInternational\Cognito\Exceptions\NoLocalUserException;
use Exception;

use Illuminate\Auth\TokenGuard;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;

class CognitoTokenGuard extends TokenGuard
{
    /**
     * Username key.
     *
     * @var \string
     */
    protected $keyUsername;


    /**
     * @var \AwsCognitoClient
     */
    protected $client;


    /**
     * The AwsCognito instance.
     *
     * @var \BluefynInternational\Cognito\AwsCognito
     */
    protected $cognito;


    /**
     * The AwsCognito Claim token.
     *
     * @var \BluefynInternational\Cognito\AwsCognitoClaim|null
     */
    protected $claim;


    /**
     * CognitoTokenGuard constructor.
     *
     * @param $callback
     * @param AwsCognitoClient $client
     * @param Request          $request
     * @param UserProvider     $provider
     */
    public function __construct(
        AwsCognito $cognito,
        AwsCognitoClient $client,
        Request $request,
        UserProvider $provider = null,
        string $keyUsername = 'email'
    ) {
        $this->cognito = $cognito;
        $this->client = $client;
        $this->keyUsername = $keyUsername;

        parent::__construct($provider, $request);
    }


    /**
     * @param mixed $user
     * @param array $credentials
     *
     * @throws InvalidUserModelException
     *
     * @return bool
     */
    protected function hasValidCredentials($user, $credentials)
    {
        /** @var Result $response */
        $result = $this->client->authenticate($credentials[$this->keyUsername], $credentials['password']);

        if (! empty($result) && $result instanceof AwsResult) {
            if (isset($result['ChallengeName']) &&
                in_array($result['ChallengeName'], config('cognito.forced_challenge_names'))) {
                //Check for forced action on challenge status
                if (config('cognito.force_password_change_api')) {
                    $this->claim = [
                        'session_token' => $result['Session'],
                        'username'      => $credentials[$this->keyUsername],
                        'status'        => $result['ChallengeName'],
                    ];
                } else {
                    if (config('cognito.force_password_auto_update_api')) {
                        //Force set password same as authenticated with challenge state
                        $this->client->confirmPassword($credentials[$this->keyUsername], $credentials['password'], $result['Session']);

                        //Get the result object again
                        $result = $this->client->authenticate($credentials[$this->keyUsername], $credentials['password']);

                        if (empty($result)) {
                            return false;
                        }
                    } else {
                        $this->claim = null;
                    }
                }
            }

            //Create Claim for confirmed users
            if (! isset($result['ChallengeName'])) {
                //Create claim token
                $this->claim = new AwsCognitoClaim($result, $user, $credentials[$this->keyUsername]);
            }

            return ($this->claim) ? true : false;
        } else {
            return false;
        }

        return false;
    }


    /**
     * Attempt to authenticate a user using the given credentials.
     *
     * @param array $credentials
     * @param bool  $remember
     *
     * @throws
     *
     * @return bool
     */
    public function attempt(array $credentials = [], $remember = false)
    {
        try {
            $this->lastAttempted = $user = $this->provider->retrieveByCredentials($credentials);

            //Check if the user exists in local data store
            if (! ($user instanceof Authenticatable)) {
                throw new NoLocalUserException();
            }

            if ($this->hasValidCredentials($user, $credentials)) {
                return $this->login($user);
            }

            return false;
        } catch (NoLocalUserException $e) {
            Log::error('CognitoTokenGuard:attempt:NoLocalUserException:');

            throw $e;
        } catch (CognitoIdentityProviderException $e) {
            Log::error('CognitoTokenGuard:attempt:CognitoIdentityProviderException:' . $e->getAwsErrorCode());

            //Set proper route
            if (! empty($e->getAwsErrorCode())) {
                $errorCode = 'CognitoIdentityProviderException';

                switch ($e->getAwsErrorCode()) {
                    case 'PasswordResetRequiredException':
                        $errorCode = 'cognito.validation.auth.reset_password';
                        break;

                    case 'NotAuthorizedException':
                        $errorCode = 'cognito.validation.auth.user_unauthorized';
                        break;

                    default:
                        $errorCode = $e->getAwsErrorCode();
                        break;
                }

                return response()->json(['error' => $errorCode, 'message' => $e->getAwsErrorCode()], 400);
            }

            return $e->getAwsErrorCode();
        } catch (AwsCognitoException $e) {
            Log::error('CognitoTokenGuard:attempt:AwsCognitoException:' . $e->getMessage());

            throw $e;
        } catch (Exception $e) {
            Log::error('CognitoTokenGuard:attempt:Exception:' . $e->getMessage());

            throw $e;
        }
    }


    /**
     * Create a token for a user.
     *
     * @param \Illuminate\Contracts\Auth\Authenticatable $user
     *
     * @return claim
     */
    private function login($user)
    {
        if (! empty($this->claim)) {

            //Save the claim if it matches the Cognito Claim
            if ($this->claim instanceof AwsCognitoClaim) {

                //Set Token
                $this->setToken();
            }

            //Set user
            $this->setUser($user);
        }

        return $this->claim;
    } //Fucntion ends


    /**
     * Set the token.
     *
     * @return $this
     */
    public function setToken()
    {
        $this->cognito->setClaim($this->claim)->storeToken();

        return $this;
    }


    /**
     * Logout the user, thus invalidating the token.
     *
     * @param bool $forceForever
     *
     * @return void
     */
    public function logout($forceForever = false)
    {
        $this->invalidate($forceForever);
        $this->user = null;
    }


    /**
     * Invalidate the token.
     *
     * @param bool $forceForever
     *
     * @return \BluefynInternational\Cognito\AwsCognito
     */
    public function invalidate($forceForever = false)
    {
        return $this->cognito->unsetToken($forceForever);
    }


    /**
     * Get the authenticated user.
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable
     */
    public function user()
    {

        //Check if the user exists
        if (! is_null($this->user)) {
            return $this->user;
        }

        //Retrieve token from request and authenticate
        return $this->getTokenForRequest();
    }


    /**
     * Get the token for the current request.
     *
     * @return string
     */
    public function getTokenForRequest()
    {
        //Check for request having token
        if (! $this->cognito->parser()->setRequest($this->request)->hasToken()) {
            return null;
        }

        if (! $this->cognito->parseToken()->authenticate()) {
            throw new NoLocalUserException();
        }

        //Get claim
        $claim = $this->cognito->getClaim();

        if (empty($claim)) {
            return null;
        }

        //Get user and return
        return $this->user = $this->provider->retrieveById($claim['sub']);
    }
}
