<?php

/*
 * This file is part of AWS Cognito Auth solution.
 *
 * (c) EllaiSys <support@ellaisys.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace BluefynInternational\Cognito\Http\Middleware;

use BluefynInternational\Cognito\AwsCognito;
use BluefynInternational\Cognito\Exceptions\NoTokenException;
use Exception;
use Illuminate\Http\Request;
use Symfony\Component\HttpKernel\Exception\UnauthorizedHttpException;

abstract class BaseMiddleware
{
    /**
     * The Cognito Authenticator.
     *
     * @var \BluefynInternational\Cognito\AwsCognito
     */
    protected $cognito;

    /**
     * Create a new BaseMiddleware instance.
     *
     * @param \BluefynInternational\Cognito\AwsCognito $cognito
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
     * @throws \BluefynInternational\Cognito\Exceptions\AwsCognitoException
     * @throws \BluefynInternational\Cognito\Exceptions\InvalidTokenException
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
