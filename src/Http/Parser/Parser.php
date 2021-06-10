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

class Parser
{
    /**
     * The chain.
     *
     * @var array
     */
    private array $chain;

    /**
     * The request.
     *
     * @var \Illuminate\Http\Request
     */
    protected $request;

    /**
     * Constructor.
     *
     * @param \Illuminate\Http\Request $request
     * @param array                    $chain
     *
     * @return void
     */
    public function __construct(Request $request, array $chain = [])
    {
        $this->request = $request;
        $this->chain = $chain;
    }

    /**
     * Get the parser chain.
     *
     * @return array
     */
    public function getChain() : array
    {
        return $this->chain;
    }


    /**
     * Set the order of the parser chain.
     *
     * @param array $chain
     *
     * @return $this
     */
    public function setChain(array $chain) : self
    {
        $this->chain = $chain;

        return $this;
    }

    /**
     * Alias for setting the order of the chain.
     *
     * @param array $chain
     *
     * @return $this
     */
    public function setChainOrder(array $chain) : self
    {
        return $this->setChain($chain);
    }


    /**
     * Iterate through the parsers and attempt to retrieve
     * a value, otherwise return null.
     *
     * @return string|null|void
     */
    public function parseToken()
    {
        foreach ($this->chain as $parser) {
            if ($response = $parser->parse($this->request)) {
                return $response;
            }
        }
    }

    /**
     * Check whether a token exists in the chain.
     *
     * @return bool
     */
    public function hasToken() : bool
    {
        return $this->parseToken() !== null;
    }

    /**
     * Set the request instance.
     *
     * @param \Illuminate\Http\Request $request
     *
     * @return $this
     */
    public function setRequest(Request $request) : self
    {
        $this->request = $request;

        return $this;
    }
}
