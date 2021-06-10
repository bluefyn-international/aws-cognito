<?php

namespace Ellaisys\Cognito\Exceptions;

use Exception;

use Throwable;

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
