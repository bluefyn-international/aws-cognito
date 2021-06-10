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

use BluefynInternational\Cognito\AwsCognitoClient;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Password;

trait SendsPasswordResetEmails
{
    /**
     * @param Collection $request
     * @param string     $usernameKey
     * @param bool       $resetTypeCode
     * @param bool       $isJsonResponse
     * @param array|null $attributes
     *
     * @return bool
     */
    public function sendResetLinkEmail(
        Collection $request,
        string $usernameKey = 'email',
        bool $resetTypeCode = true,
        bool $isJsonResponse = false,
        ?array $attributes = null
    ) {
        //Cognito reset link
        $response = $this->sendCognitoResetLinkEmail($request[$usernameKey], $attributes);

        //JSON Response
        if ($isJsonResponse) {
            return $response;
        }

        //Action Response
        if ($response) {
            if ($resetTypeCode) {
                return redirect(route('cognito.form.reset.password.code'))
                    ->withInput($request->only($usernameKey))
                    ->with('success', true);
            } else {
                return redirect(route('welcome'))
                    ->with('success', true);
            }
        } else {
            return redirect()->back()
                ->withInput($request->only($usernameKey))
                ->withErrors([$usernameKey => 'cognito.invalid_user']);
        }
    }


    /**
     * @param string     $username
     * @param array|null $attributes
     *
     * @return bool
     */
    public function sendCognitoResetLinkEmail(string $username, ?array $attributes = null)
    {
        //Send AWS Cognito reset link
        $response = app()->make(AwsCognitoClient::class)->sendResetLink($username, $attributes);

        return $response == Password::RESET_LINK_SENT;
    }
}
