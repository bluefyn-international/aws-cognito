<?php

namespace BluefynInternational\Cognito\Exceptions;

use Exception;

class InvalidUserFieldException extends Exception
{
    /**
     * Report the exception.
     *
     * @return void
     */
    public function report($message = 'Invalid User Field Exception')
    {
        abort(403, $message);
    }
}
