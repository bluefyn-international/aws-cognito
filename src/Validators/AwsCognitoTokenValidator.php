<?php

/*
 * This file is part of AWS Cognito Auth solution.
 *
 * (c) EllaiSys <support@ellaisys.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace BluefynInternational\Cognito\Validators;

use BluefynInternational\Cognito\Exceptions\InvalidTokenException;

class AwsCognitoTokenValidator
{
    /**
     * @param $value
     *
     * @throws InvalidTokenException
     *
     * @return string
     */
    public function check(string $value) : string
    {
        return $this->validateStructure($value);
    }

    /**
     * @param $token
     *
     * @throws InvalidTokenException
     *
     * @return string
     */
    protected function validateStructure(string $token) : string
    {
        $parts = explode('.', $token);

        if (count($parts) !== 3) {
            throw new InvalidTokenException('Wrong number of segments');
        }

        $parts = array_filter(array_map('trim', $parts));

        if (count($parts) !== 3 || implode('.', $parts) !== $token) {
            throw new InvalidTokenException('Malformed token');
        }

        return $token;
    }
}
