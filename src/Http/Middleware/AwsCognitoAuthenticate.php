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

use Closure;
use Ellaisys\Cognito\Exceptions\InvalidTokenException;
use Ellaisys\Cognito\Exceptions\NoTokenException;
use Exception;
use Illuminate\Http\Request;

class AwsCognitoAuthenticate extends BaseMiddleware
{
    /**
     * @param Request $request
     * @param Closure $next
     *
     * @return mixed
     */
    public function handle(Request $request, Closure $next)
    {
        try {
            $routeMiddleware = $request->route()->middleware();

            if (empty($routeMiddleware) || (count($routeMiddleware) < 1)) {
                return response()->json(['error' => 'UNAUTHORIZED_REQUEST', 'exception' => null], 401);
            }

            $this->authenticate($request);

            return $next($request);
        } catch (Exception $e) {
            if ($e instanceof NoTokenException) {
                return response()->json(['error' => 'UNAUTHORIZED_REQUEST', 'exception' => 'NoTokenException'], 401);
            }

            if ($e instanceof InvalidTokenException) {
                return response()->json(['error' => 'UNAUTHORIZED_REQUEST', 'exception' => 'InvalidTokenException'], 401);
            }

            return response()->json(['error' => $e->getMessage()], 401);
        }
    }
}
