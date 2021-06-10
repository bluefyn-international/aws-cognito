<?php

namespace BluefynInternational\Cognito\Exceptions;

use Exception;
use Throwable;

class TokenBlacklistedException extends Exception
{
    /**
     * Report the exception.
     *
     * @return void
     */
    public function report()
    {
        //
    }
}
