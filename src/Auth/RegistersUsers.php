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
use Ellaisys\Cognito\Exceptions\InvalidUserFieldException;

use Illuminate\Support\Collection;

use Illuminate\Support\Facades\Log;

trait RegistersUsers
{
    /**
     * @param Collection  $request
     * @param array|null  $clientMetadata
     * @param string|null $actionMethod
     *
     * @throws InvalidUserFieldException
     *
     * @return mixed
     */
    public function createCognitoUser(Collection $request, array $clientMetadata = null, ?string $actionMethod = null)
    {
        //Initialize Cognito Attribute array
        $attributes = [];

        //Get the registeration fields
        $userFields = config('cognito.cognito_user_fields');

        //Iterate the fields
        foreach ($userFields as $key => $userField) {
            if ($request->has($userField)) {
                $attributes[$key] = $request->get($userField);
            } else {
                Log::error('RegistersUsers:createCognitoUser:InvalidUserFieldException');
                Log::error("The configured user field {$userField} is not provided in the request.");

                throw new InvalidUserFieldException("The configured user field {$userField} is not provided in the request.");
            }
        }

        //Register the user in Cognito
        $userKey = $request->has('username') ? 'username' : 'email';

        //Temporary Password paramter
        $password = $request->has('password') ? $request['password'] : null;

        return app()->make(AwsCognitoClient::class)->inviteUser($request[$userKey], $password, $attributes, $clientMetadata, $actionMethod);
    }
}
