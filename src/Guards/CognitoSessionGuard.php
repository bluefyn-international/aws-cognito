<?php

/*
 * This file is part of AWS Cognito Auth solution.
 *
 * (c) EllaiSys <support@ellaisys.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Ellaisys\Cognito\Guards;

use Aws\CognitoIdentityProvider\Exception\CognitoIdentityProviderException;
use Aws\Result as AwsResult;
use Ellaisys\Cognito\AwsCognitoClient;
use Ellaisys\Cognito\Exceptions\AwsCognitoException;
use Ellaisys\Cognito\Exceptions\InvalidUserModelException;
use Ellaisys\Cognito\Exceptions\NoLocalUserException;
use Exception;
use Illuminate\Auth\SessionGuard;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Session\Session;
use Illuminate\Support\Facades\Log;
use Symfony\Component\HttpFoundation\Request;

class CognitoSessionGuard extends SessionGuard implements StatefulGuard
{
    /**
     * @var AwsCognitoClient
     */
    protected $client;


    /**
     * @var Authentication Challenge
     */
    protected $challengeName;


    /**
     * CognitoSessionGuard constructor.
     *
     * @param string           $name
     * @param AwsCognitoClient $client
     * @param UserProvider     $provider
     * @param Session          $session
     * @param null|Request     $request
     */
    public function __construct(
        string $name,
        AwsCognitoClient $client,
        UserProvider $provider,
        Session $session,
        ?Request $request = null
    ) {
        $this->client = $client;
        parent::__construct($name, $provider, $session, $request);
    }


    /**
     * @param       $user
     * @param array $credentials
     *
     * @return bool
     */
    protected function hasValidCredentials($user, array $credentials) : bool
    {
        /** @var Result $response */
        $result = $this->client->authenticate($credentials['email'], $credentials['password']);

        if (! empty($result) && $result instanceof AwsResult) {
            if (isset($result['ChallengeName']) &&
                in_array($result['ChallengeName'], config('cognito.forced_challenge_names'))) {
                $this->challengeName = $result['ChallengeName'];
            }

            return $user instanceof Authenticatable;
        }

        return false;
    }


    /**
     * @param array $credentials
     * @param false $remember
     *
     * @return bool
     *
     * @throws AwsCognitoException
     * @throws NoLocalUserException
     */
    public function attempt(array $credentials = [], bool $remember = false) : bool
    {
        try {
            //Fire event for authenticating
            $this->fireAttemptEvent($credentials, $remember);

            //Get user from presisting store
            $this->lastAttempted = $user = $this->provider->retrieveByCredentials($credentials);

            //Check if the user exists in local data store
            if (! ($user instanceof Authenticatable)) {
                throw new NoLocalUserException();
            }

            //Authenticate with cognito
            if ($this->hasValidCredentials($user, $credentials)) {
                $this->login($user, $remember);

                //Fire successful attempt
                $this->fireAuthenticatedEvent($user);

                if ((! empty($this->challengeName)) && config('cognito.force_password_change_web')) {
                    switch ($this->challengeName) {
                        case AwsCognitoClient::NEW_PASSWORD_CHALLENGE:
                        case AwsCognitoClient::RESET_REQUIRED_PASSWORD:
                            return redirect(route(config('cognito.force_redirect_route_name')))
                                ->with('success', true)
                                ->with('force', true)
                                ->with('messaage', $this->challengeName);

                        default:
                            return true;
                    }
                }

                return true;
            }

            //Fire failed attempt
            $this->fireFailedEvent($user, $credentials);

            return false;
        } catch (NoLocalUserException $e) {
            Log::error('CognitoSessionGuard:attempt:NoLocalUserException:' . $e->getMessage());

            //Fire failed attempt
            $this->fireFailedEvent($user, $credentials);

            throw $e;
        } catch (CognitoIdentityProviderException $e) {
            Log::error('CognitoSessionGuard:attempt:CognitoIdentityProviderException:' . $e->getAwsErrorCode());

            //Fire failed attempt
            $this->fireFailedEvent($user, $credentials);

            //Set proper route
            if (! empty($e->getAwsErrorCode())) {
                switch ($e->getAwsErrorCode()) {
                    case 'PasswordResetRequiredException':
                        return redirect(route('cognito.form.reset.password.code'))
                            ->with('success', false)
                            ->with('force', true)
                            ->with('messaage', $e->getAwsErrorCode());

                    default:
                        return $e->getAwsErrorCode();
                }
            }

            return $e->getAwsErrorCode();
        } catch (AwsCognitoException $e) {
            Log::error('CognitoSessionGuard:attempt:AwsCognitoException:' . $e->getMessage());

            //Fire failed attempt
            $this->fireFailedEvent($user, $credentials);

            throw $e;
        } catch (Exception $e) {
            Log::error('CognitoSessionGuard:attempt:Exception:' . $e->getMessage());

            //Fire failed attempt
            $this->fireFailedEvent($user, $credentials);

            return false;
        }
    }
}
