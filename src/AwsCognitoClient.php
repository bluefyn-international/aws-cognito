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

use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;
use Aws\CognitoIdentityProvider\Exception\CognitoIdentityProviderException;
use Illuminate\Support\Facades\Lang;
use Illuminate\Support\Facades\Password;

class AwsCognitoClient
{
    /**
     * Constant representing the user status as Confirmed.
     *
     * @var string
     */
    const USER_STATUS_CONFIRMED = 'CONFIRMED';

    /**
     * Constant representing the user needs a new password.
     *
     * @var string
     */
    const NEW_PASSWORD_CHALLENGE = 'NEW_PASSWORD_REQUIRED';

    /**
     * Constant representing the user needs to reset password.
     *
     * @var string
     */
    const RESET_REQUIRED_PASSWORD = 'RESET_REQUIRED';

    /**
     * Constant representing the force new password status.
     *
     * @var string
     */
    const FORCE_CHANGE_PASSWORD = 'FORCE_CHANGE_PASSWORD';

    /**
     * Constant representing the password reset required exception.
     *
     * @var string
     */
    const RESET_REQUIRED = 'PasswordResetRequiredException';

    /**
     * Constant representing the user not found exception.
     *
     * @var string
     */
    const USER_NOT_FOUND = 'UserNotFoundException';

    /**
     * Constant representing the username exists exception.
     *
     * @var string
     */
    const USERNAME_EXISTS = 'UsernameExistsException';

    /**
     * Constant representing the invalid password exception.
     *
     * @var string
     */
    const INVALID_PASSWORD = 'InvalidPasswordException';

    /**
     * Constant representing the code mismatch exception.
     *
     * @var string
     */
    const CODE_MISMATCH = 'CodeMismatchException';

    /**
     * Constant representing the expired code exception.
     *
     * @var string
     */
    const EXPIRED_CODE = 'ExpiredCodeException';

    /**
     * Constant representing if an invite message should be sent.
     *
     * @var string
     */
    const ACTION_METHOD_SUPPRESS = 'SUPPRESS';

    const ACTION_METHOD_RESEND = 'RESEND';

    /**
     * @var CognitoIdentityProviderClient
     */
    protected CognitoIdentityProviderClient $client;

    /**
     * @var string
     */
    protected string $clientId;

    /**
     * @var string
     */
    protected string $clientSecret;

    /**
     * @var string
     */
    protected string $poolId;

    /**
     * AwsCognitoClient constructor.
     *
     * @param CognitoIdentityProviderClient $client
     * @param string                        $clientId
     * @param string                        $clientSecret
     * @param string                        $poolId
     */
    public function __construct(
        CognitoIdentityProviderClient $client,
        $clientId,
        $clientSecret,
        $poolId
    ) {
        $this->client = $client;
        $this->clientId = $clientId;
        $this->clientSecret = $clientSecret;
        $this->poolId = $poolId;
    }


    /**
     * Checks if credentials of a user are valid.
     *
     * @see http://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminInitiateAuth.html
     *
     * @param string $username
     * @param string $password
     *
     * @return \Aws\Result|bool
     */
    public function authenticate($username, $password)
    {
        $response = $this->client->adminInitiateAuth([
            'AuthFlow'       => 'ADMIN_NO_SRP_AUTH',
            'AuthParameters' => [
                'USERNAME'    => $username,
                'PASSWORD'    => $password,
                'SECRET_HASH' => $this->cognitoSecretHash($username),
            ],
            'ClientId'   => $this->clientId,
            'UserPoolId' => $this->poolId,
        ]);

        return $response;
    }


    /**
     * Registers a user in the given user pool.
     *
     * @param $username
     * @param $password
     * @param array $attributes
     *
     * @return bool
     */
    public function register($username, $password, array $attributes = [])
    {
        try {
            $response = $this->client->signUp([
                'ClientId'       => $this->clientId,
                'Password'       => $password,
                'SecretHash'     => $this->cognitoSecretHash($username),
                'UserAttributes' => $this->formatAttributes($attributes),
                'Username'       => $username,
            ]);
        } catch (CognitoIdentityProviderException $e) {
            if ($e->getAwsErrorCode() === self::USERNAME_EXISTS) {
                return false;
            }

            throw $e;
        }

        return (bool) $response['UserConfirmed'];
    }


    /**
     * Send a password reset code to a user.
     *
     * @see https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ForgotPassword.html
     *
     * @param string     $username
     * @param array|null $clientMetadata (optional)
     *
     * @return string
     */
    public function sendResetLink(string $username, ?array $clientMetadata = null) : string
    {
        try {
            //Build payload
            $payload = [
                'ClientId'       => $this->clientId,
                'ClientMetadata' => $this->buildClientMetadata(['username' => $username], $clientMetadata),
                'SecretHash'     => $this->cognitoSecretHash($username),
                'Username'       => $username,
            ];

            $result = $this->client->forgotPassword($payload);
        } catch (CognitoIdentityProviderException $e) {
            if ($e->getAwsErrorCode() === self::USER_NOT_FOUND) {
                return Password::INVALID_USER;
            }

            throw $e;
        }

        return Password::RESET_LINK_SENT;
    }


    /**
     * Reset a users password based on reset code.
     * https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ConfirmForgotPassword.html.
     *
     * @param string $code
     * @param string $username
     * @param string $password
     *
     * @return string
     */
    public function resetPassword(string $code, string $username, string $password) : string
    {
        try {
            $this->client->confirmForgotPassword([
                'ClientId'         => $this->clientId,
                'ConfirmationCode' => $code,
                'Password'         => $password,
                'SecretHash'       => $this->cognitoSecretHash($username),
                'Username'         => $username,
            ]);
        } catch (CognitoIdentityProviderException $e) {
            if ($e->getAwsErrorCode() === self::USER_NOT_FOUND) {
                return Password::INVALID_USER;
            }

            if ($e->getAwsErrorCode() === self::INVALID_PASSWORD) {
                return Lang::has('passwords.password') ? 'passwords.password' : $e->getAwsErrorMessage();
            }

            if ($e->getAwsErrorCode() === self::CODE_MISMATCH || $e->getAwsErrorCode() === self::EXPIRED_CODE) {
                return Password::INVALID_TOKEN;
            }

            throw $e;
        }

        return Password::PASSWORD_RESET;
    }


    /**
     * @param string      $username
     * @param string|null $password
     * @param array       $attributes
     * @param array|null  $clientMetadata
     * @param string|null $actionMethod
     *
     * @return bool
     */
    public function inviteUser(
        string $username,
        string $password = null,
        array $attributes = [],
        ?array $clientMetadata = null,
        ?string $actionMethod = null
    ) : bool {
        //Force validate email
        if ($attributes['email']) {
            $attributes['email_verified'] = 'true';
        }

        //Generate payload
        $payload = [
            'UserPoolId'     => $this->poolId,
            'Username'       => $username,
            'UserAttributes' => $this->formatAttributes($attributes),
        ];

        //Set Client Metadata
        if (! empty($clientMetadata)) {
            $payload['ClientMetadata'] = $this->buildClientMetadata([], $clientMetadata);
        }

        if (in_array($actionMethod, [self::ACTION_METHOD_SUPPRESS, self::ACTION_METHOD_RESEND])) {
            $payload['MessageAction'] = $actionMethod;
        }

        //Set Temporary password
        if (! empty($password)) {
            $payload['TemporaryPassword'] = $password;
        }

        if (config('cognito.add_user_delivery_mediums') != "DEFAULT") {
            $payload['DesiredDeliveryMediums'] = [
                config('cognito.add_user_delivery_mediums'),
            ];
        }

        try {
            $this->client->adminCreateUser($payload);
        } catch (CognitoIdentityProviderException $e) {
            if ($e->getAwsErrorCode() === self::USERNAME_EXISTS) {
                return false;
            }

            throw $e;
        }

        return true;
    }


    /**
     * Set a new password for a user that has been flagged as needing a password change.
     * http://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminRespondToAuthChallenge.html.
     *
     * @param string $username
     * @param string $password
     * @param string $session
     *
     * @return bool
     */
    public function confirmPassword(string $username, string $password, string $session)
    {
        try {
            $this->client->AdminRespondToAuthChallenge([
                'ClientId'           => $this->clientId,
                'UserPoolId'         => $this->poolId,
                'Session'            => $session,
                'ChallengeResponses' => [
                    'NEW_PASSWORD' => $password,
                    'USERNAME'     => $username,
                    'SECRET_HASH'  => $this->cognitoSecretHash($username),
                ],
                'ChallengeName' => 'NEW_PASSWORD_REQUIRED',
            ]);
        } catch (CognitoIdentityProviderException $e) {
            if ($e->getAwsErrorCode() === self::CODE_MISMATCH || $e->getAwsErrorCode() === self::EXPIRED_CODE) {
                return Password::INVALID_TOKEN;
            }

            throw $e;
        }

        return Password::PASSWORD_RESET;
    }


    /**
     * @param string $username
     *
     * @see https://docs.aws.amazon.com/aws-sdk-php/v3/api/api-cognito-idp-2016-04-18.html#admindeleteuser
     */
    public function deleteUser(string $username)
    {
        if (config('cognito.delete_user')) {
            $this->client->adminDeleteUser([
                'UserPoolId' => $this->poolId,
                'Username'   => $username,
            ]);
        }
    }


    /**
     * Sets the specified user's password in a user pool as an administrator.
     *
     * @see https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminSetUserPassword.html
     *
     * @param string $username
     * @param string $password
     * @param bool   $permanent
     *
     * @return string
     */
    public function setUserPassword(string $username, string $password, bool $permanent = true) : string
    {
        try {
            $this->client->adminSetUserPassword([
                'Password'   => $password,
                'Permanent'  => $permanent,
                'Username'   => $username,
                'UserPoolId' => $this->poolId,
            ]);
        } catch (CognitoIdentityProviderException $e) {
            if ($e->getAwsErrorCode() === self::USER_NOT_FOUND) {
                return Password::INVALID_USER;
            }

            if ($e->getAwsErrorCode() === self::INVALID_PASSWORD) {
                return Lang::has('passwords.password') ? 'passwords.password' : $e->getAwsErrorMessage();
            }

            throw $e;
        }

        return Password::PASSWORD_RESET;
    }


    /**
     * Changes the password for a specified user in a user pool.
     *
     * @see https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ChangePassword.html
     *
     * @param string $accessToken
     * @param string $passwordOld
     * @param string $passwordNew
     *
     * @return bool|string
     */
    public function changePassword(string $accessToken, string $passwordOld, string $passwordNew)
    {
        try {
            $this->client->changePassword([
                'AccessToken'      => $accessToken,
                'PreviousPassword' => $passwordOld,
                'ProposedPassword' => $passwordNew,
            ]);
        } catch (CognitoIdentityProviderException $e) {
            if ($e->getAwsErrorCode() === self::USER_NOT_FOUND) {
                return Password::INVALID_USER;
            }

            if ($e->getAwsErrorCode() === self::INVALID_PASSWORD) {
                return Lang::has('passwords.password') ? 'passwords.password' : $e->getAwsErrorMessage();
            }

            throw $e;
        }

        return true;
    }


    /**
     * @param string $username
     */
    public function invalidatePassword(string $username)
    {
        $this->client->adminResetUserPassword([
            'UserPoolId' => $this->poolId,
            'Username'   => $username,
        ]);
    }

    /**
     * @param string $username
     */
    public function confirmSignUp(string $username)
    {
        $this->client->adminConfirmSignUp([
            'UserPoolId' => $this->poolId,
            'Username'   => $username,
        ]);
    }


    /**
     * @param string $username
     * @param string $confirmationCode
     *
     * @return string
     */
    public function confirmUserSignUp(string $username, string $confirmationCode) : string
    {
        try {
            $this->client->confirmSignUp([
                'ClientId'         => $this->clientId,
                'SecretHash'       => $this->cognitoSecretHash($username),
                'Username'         => $username,
                'ConfirmationCode' => $confirmationCode,
            ]);
        } catch (CognitoIdentityProviderException $e) {
            if ($e->getAwsErrorCode() === self::USER_NOT_FOUND) {
                return 'validation.invalid_user';
            }

            if ($e->getAwsErrorCode() === self::CODE_MISMATCH || $e->getAwsErrorCode() === self::EXPIRED_CODE) {
                return 'validation.invalid_token';
            }

            if ($e->getAwsErrorCode() === 'NotAuthorizedException' and $e->getAwsErrorMessage() === 'User cannot be confirmed. Current status is CONFIRMED') {
                return 'validation.confirmed';
            }

            if ($e->getAwsErrorCode() === 'LimitExceededException') {
                return 'validation.exceeded';
            }

            throw $e;
        }
    }

    /**
     * @param string $username
     *
     * @return string
     */
    public function resendToken(string $username) : string
    {
        try {
            $this->client->resendConfirmationCode([
                'ClientId'   => $this->clientId,
                'SecretHash' => $this->cognitoSecretHash($username),
                'Username'   => $username,
            ]);
        } catch (CognitoIdentityProviderException $e) {
            if ($e->getAwsErrorCode() === self::USER_NOT_FOUND) {
                return 'validation.invalid_user';
            }

            if ($e->getAwsErrorCode() === 'LimitExceededException') {
                return 'validation.exceeded';
            }

            if ($e->getAwsErrorCode() === 'InvalidParameterException') {
                return 'validation.confirmed';
            }

            throw $e;
        }
    }


    // HELPER FUNCTIONS
    /**
     * Set a users attributes.
     * http://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminUpdateUserAttributes.html.
     *
     * @param string $username
     * @param array  $attributes
     *
     * @return bool
     */
    public function setUserAttributes($username, array $attributes) : bool
    {
        $this->client->AdminUpdateUserAttributes([
            'Username'       => $username,
            'UserPoolId'     => $this->poolId,
            'UserAttributes' => $this->formatAttributes($attributes),
        ]);

        return true;
    }


    /**
     * Creates the Cognito secret hash.
     *
     * @param string $username
     *
     * @return string
     */
    protected function cognitoSecretHash(string $username) : string
    {
        return $this->hash($username . $this->clientId);
    }


    /**
     * Creates a HMAC from a string.
     *
     * @param string $message
     *
     * @return string
     */
    protected function hash(string $message) : string
    {
        $hash = hash_hmac(
            'sha256',
            $message,
            $this->clientSecret,
            true,
        );

        return base64_encode($hash);
    }


    /**
     * Get user details.
     * http://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_GetUser.html.
     *
     * @param string $username
     *
     * @return mixed
     */
    public function getUser(string $username)
    {
        try {
            $user = $this->client->AdminGetUser([
                'Username'   => $username,
                'UserPoolId' => $this->poolId,
            ]);
        } catch (CognitoIdentityProviderException $e) {
            return null;
        }

        return $user;
    }

    /**
     * @see https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminSetUserPassword.html
     *
     * @param string $newPassword
     * @param string $username
     * @param bool   $permanent
     *
     * @return bool
     */
    public function adminSetUserPassword(string $newPassword, string $username, bool $permanent = false) : bool
    {
        $successful = false;
        try {
            $response = $this->client->AdminSetUserPassword([
                'Username'   => $username,
                'Password'   => $newPassword,
                'Permanent'  => $permanent,
                'UserPoolId' => $this->poolId,
            ]);
            $successful = $response->toArray()['@metadata']['status'] == 200;
        } catch (CognitoIdentityProviderException $e) {
        }

        return $successful;
    }

    public function adminConfirmSignUp(string $username, array $clientMetadata = []) : bool
    {
        $successful = false;
        try {
            $payload = [
                'Username'   => $username,
                'UserPoolId' => $this->poolId,
            ];
            if ($clientMetadata) {
                $payload['ClientMetadata'] = $clientMetadata;
            }

            $response = $this->client->AdminConfirmSignUp($payload);
            $successful = $response->toArray()['@metadata']['status'] == 200;
        } catch (CognitoIdentityProviderException $e) {
        }

        return $successful;
    }

    public function adminDisableUser(string $username) : bool
    {
        $successful = false;
        try {
            $response = $this->client->AdminDisableUser([
                'Username'   => $username,
                'UserPoolId' => $this->poolId,
            ]);
            $successful = $response->toArray()['@metadata']['status'] == 200;
        } catch (CognitoIdentityProviderException $e) {
        }

        return $successful;
    }

    public function adminEnableUser(string $username) : bool
    {
        $successful = false;
        try {
            $response = $this->client->AdminEnableUser([
                'Username'   => $username,
                'UserPoolId' => $this->poolId,
            ]);
            $successful = $response->toArray()['@metadata']['status'] == 200;
        } catch (CognitoIdentityProviderException $e) {
        }

        return $successful;
    }

    /**
     * Format attributes in Name/Value array.
     *
     * @param array $attributes
     *
     * @return array
     */
    protected function formatAttributes(array $attributes) : array
    {
        $userAttributes = [];

        foreach ($attributes as $key => $value) {
            $userAttributes[] = [
                'Name'  => $key,
                'Value' => $value,
            ];
        }

        return $userAttributes;
    }


    /**
     * Build Client Metadata to be forwarded to Cognito.
     *
     * @param array      $attributes
     * @param array|null $clientMetadata
     *
     * @return array|null
     */
    protected function buildClientMetadata(array $attributes, ?array $clientMetadata = null) : ?array
    {
        if (! empty($clientMetadata)) {
            $userAttributes = array_merge($attributes, $clientMetadata);
        } else {
            $userAttributes = $attributes;
        }

        return $userAttributes;
    }
}
