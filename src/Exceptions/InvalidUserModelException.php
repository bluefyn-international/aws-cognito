<?php

namespace BluefynInternational\Cognito\Exceptions;

use Exception;

use Illuminate\Database\Eloquent\ModelNotFoundException;

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
