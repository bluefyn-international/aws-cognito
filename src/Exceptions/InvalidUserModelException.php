<?php

namespace Ellaisys\Cognito\Exceptions;

use Exception;

use Illuminate\Database\Eloquent\ModelNotFoundException;
use Throwable;

class InvalidUserModelException extends Exception
{
    /**
     * Report the exception.
     *
     * @return void
     */
    public function report()
    {
        throw new ModelNotFoundException();
    }
}
