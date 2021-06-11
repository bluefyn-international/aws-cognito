<?php

namespace BluefynInternational\Cognito\Exceptions;

use Exception;

use Illuminate\Auth\AuthenticationException;

class NoTokenException extends Exception
{
    /**
     * Report the exception.
     *
     * @return void
     */
    public function report($message = 'Authentication token not provided')
    {
        throw new AuthenticationException($message);
    }
}
