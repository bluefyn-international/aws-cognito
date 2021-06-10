<?php

/*
 * This file is part of AWS Cognito Auth solution.
 *
 * (c) EllaiSys <support@ellaisys.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Ellaisys\Cognito\Auth;

use Ellaisys\Cognito\AwsCognitoClient;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Password;

use Illuminate\Support\Facades\Validator;

use Illuminate\Validation\ValidationException;

trait ResetsPasswords
{
    /**
     * Reset the given user's password.
     *
     * @param \Illuminate\Http\Request|Illuminate\Support\Collection $request
     * @param string                                                 $paramUsername
     * @param string                                                 $paramToken
     * @param string                                                 $passwordNew
     *
     * @return \Illuminate\Http\RedirectResponse
     */
    public function reset(
        $request,
        string $paramUsername = 'email',
        string $paramToken = 'token',
        string $passwordNew = 'password'
    ) {
        $validator = Validator::make($request->all(), $this->rules());

        if ($validator->fails()) {
            throw new ValidationException($validator);
        }

        if (! $request instanceof Collection) {
            throw new \InvalidArgumentException();
        }

        //Create AWS Cognito Client
        $client = app()->make(AwsCognitoClient::class);

        //Get User Data
        $user = $client->getUser($request[$paramUsername]);

        //Check user status and change password
        if (($user['UserStatus'] == AwsCognitoClient::USER_STATUS_CONFIRMED) ||
            ($user['UserStatus'] == AwsCognitoClient::RESET_REQUIRED_PASSWORD)) {
            $response = $client->resetPassword($request[$paramToken], $request[$paramUsername], $request[$passwordNew]);
        } else {
            return false;
        }

        return $response;
    }


    /**
     * Display the password reset view for the given token.
     *
     * If no token is present, display the link request form.
     *
     * @param \Illuminate\Http\Request $request
     * @param string|null              $token
     *
     * @return \Illuminate\Contracts\View\Factory|\Illuminate\View\View
     */
    public function showResetForm(Request $request, ?string $token = null)
    {
        return view('vendor.black-bits.laravel-cognito-auth.reset-password')->with(
            ['email' => $request->email],
        );
    }


    /**
     * Get the password reset validation rules.
     *
     * @return array
     */
    protected function rules() : array
    {
        return [
            'token'    => 'required_without:code',
            'code'     => 'required_without:token',
            'email'    => 'required|email',
            'password' => 'required|confirmed|min:8',
        ];
    }
}
