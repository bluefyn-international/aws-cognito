<?php

/*
 * This file is part of AWS Cognito Auth solution.
 *
 * (c) EllaiSys <support@ellaisys.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace BluefynInternational\Cognito\Auth;

use Auth;
use Aws\CognitoIdentityProvider\Exception\CognitoIdentityProviderException;
use BluefynInternational\Cognito\Exceptions\NoLocalUserException;
use Exception;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Log;
use Illuminate\Validation\ValidationException;

trait AuthenticatesUsers
{
    /**
     * @param Collection $request
     * @param string     $guard
     * @param string     $paramUsername
     * @param string     $paramPassword
     * @param bool       $isJsonResponse
     *
     * @return mixed|void
     */
    protected function attemptLogin(
        Collection $request,
        string $guard = 'web',
        string $paramUsername = 'email',
        string $paramPassword = 'password',
        bool $isJsonResponse = false
    ) {
        try {
            //Get key fields
            $keyUsername = 'email';
            $keyPassword = 'password';
            $rememberMe = $request->has('remember') ? $request['remember'] : false;

            //Generate credentials array
            $credentials = [
                $keyUsername => $request[$paramUsername],
                $keyPassword => $request[$paramPassword],
            ];

            //Authenticate User
            $claim = Auth::guard($guard)->attempt($credentials, $rememberMe);
        } catch (NoLocalUserException $e) {
            Log::error('AuthenticatesUsers:attemptLogin:NoLocalUserException');

            if (config('cognito.add_missing_local_user_sso')) {
                $this->createLocalUser($credentials);
            }

            return $this->sendFailedLoginResponse($e, $isJsonResponse);
        } catch (CognitoIdentityProviderException $e) {
            Log::error('AuthenticatesUsers:attemptLogin:CognitoIdentityProviderException');

            return $this->sendFailedCognitoResponse($e);
        } catch (Exception $e) {
            Log::error('AuthenticatesUsers:attemptLogin:Exception');

            return $this->sendFailedLoginResponse($e, $isJsonResponse);
        }

        return $claim;
    }


    /**
     * Create a local user if one does not exist.
     *
     * @param array $credentials
     *
     * @return mixed
     */
    protected function createLocalUser(array $credentials)
    {
        return true;
    }


    /**
     * Handle Failed Cognito Exception.
     *
     * @param CognitoIdentityProviderException $exception
     */
    private function sendFailedCognitoResponse(CognitoIdentityProviderException $exception)
    {
        throw ValidationException::withMessages([
            $this->username() => $exception->getAwsErrorMessage(),
        ]);
    }


    /**
     * @param Exception|null $exception
     * @param bool           $isJsonResponse
     *
     * @return mixed
     */
    private function sendFailedLoginResponse(
        ?Exception $exception = null,
        bool $isJsonResponse = false
    ) {
        $message = 'FailedLoginResponse';

        if (! empty($exception)) {
            $message = $exception->getMessage();
        }

        if ($isJsonResponse) {
            return response()->json([
                'error'   => 'cognito.validation.auth.failed',
                'message' => $message,
            ], 400);
        }

        return redirect()->back()
            ->withErrors([
                'username' => $message,
            ]);
    }
}
