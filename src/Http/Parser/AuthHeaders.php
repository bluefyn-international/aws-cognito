<?php

/*
 * This file is part of AWS Cognito Auth solution.
 *
 * (c) EllaiSys <support@ellaisys.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace BluefynInternational\Cognito\Http\Parser;

use Illuminate\Http\Request;

class AuthHeaders //implements ParserContract
{
    /**
     * The header name.
     *
     * @var string
     */
    protected string $header = 'authorization';

    /**
     * The header prefix.
     *
     * @var string
     */
    protected string $prefix = 'bearer';

    /**
     * Attempt to parse the token from some other possible headers.
     *
     * @param \Illuminate\Http\Request $request
     *
     * @return null|string
     */
    protected function fromAltHeaders(Request $request)
    {
        return $request->server->get('HTTP_AUTHORIZATION') ?: $request->server->get('REDIRECT_HTTP_AUTHORIZATION');
    }


    /**
     * Try to parse the token from the request header.
     *
     * @param \Illuminate\Http\Request $request
     *
     * @return null|string|void
     */
    public function parse(Request $request)
    {
        $header = $request->headers->get($this->header) ?: $this->fromAltHeaders($request);

        if ($header && preg_match('/' . $this->prefix . '\s*(\S+)\b/i', $header, $matches)) {
            return $matches[1];
        }
    }


    /**
     * Set the header name.
     *
     * @param string $headerName
     *
     * @return $this
     */
    public function setHeaderName(string $headerName) : self
    {
        $this->header = $headerName;

        return $this;
    }


    /**
     * Set the header prefix.
     *
     * @param string $headerPrefix
     *
     * @return $this
     */
    public function setHeaderPrefix(string $headerPrefix) : self
    {
        $this->prefix = $headerPrefix;

        return $this;
    }
}
