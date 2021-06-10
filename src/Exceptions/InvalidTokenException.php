<?php

namespace Ellaisys\Cognito\Exceptions;

use Exception;

use Illuminate\Auth\AuthenticationException;
use Throwable;

class InvalidTokenException extends Exception
{
    /**
     * Report the exception.
     *
     * @return void
     */
    public function report($message = 'Invalid Authentication Token')
    {
        throw new AuthenticationException($message);
    }
}
