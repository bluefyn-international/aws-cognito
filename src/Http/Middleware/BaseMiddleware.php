<?php

/*
 * This file is part of AWS Cognito Auth solution.
 *
 * (c) EllaiSys <support@ellaisys.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Ellaisys\Cognito\Http\Middleware;

use Ellaisys\Cognito\AwsCognito;
use Ellaisys\Cognito\Exceptions\NoTokenException;
use Exception;
use Illuminate\Http\Request;
use Symfony\Component\HttpKernel\Exception\UnauthorizedHttpException;

abstract class BaseMiddleware
{
    /**
     * The Cognito Authenticator.
     *
     * @var \Ellaisys\Cognito\AwsCognito
     */
    protected $cognito;

    /**
     * Create a new BaseMiddleware instance.
     *
     * @param \Ellaisys\Cognito\AwsCognito $cognito
     *
     * @return void
     */
    public function __construct(AwsCognito $cognito)
    {
        $this->cognito = $cognito;
    }

    /**
     * @param Request $request
     *
     * @throws NoTokenException
     */
    public function checkForToken(Request $request)
    {
        if (! $this->cognito->parser()->setRequest($request)->hasToken()) {
            throw new NoTokenException();
        }
    }


    /**
     * @param Request $request
     *
     * @throws NoTokenException
     * @throws \Ellaisys\Cognito\Exceptions\AwsCognitoException
     * @throws \Ellaisys\Cognito\Exceptions\InvalidTokenException
     */
    public function authenticate(Request $request)
    {
        try {
            $this->checkForToken($request);

            if (! $this->cognito->parseToken()->authenticate()) {
                throw new UnauthorizedHttpException('aws-cognito', 'User not found');
            }
        } catch (Exception $e) {
            throw $e;
        }
    }


    /**
     * Set the authentication header.
     *
     * @param \Illuminate\Http\Response|\Illuminate\Http\JsonResponse $response
     * @param string|null                                             $token
     *
     * @return \Illuminate\Http\Response|\Illuminate\Http\JsonResponse
     */
    protected function setAuthenticationHeader($response, ?string $token = null)
    {
        $token = $token ?: $this->cognito->refresh();
        $response->headers->set('Authorization', 'Bearer ' . $token);

        return $response;
    }
}
