<?php

/*
 * This file is part of AWS Cognito Auth solution.
 *
 * (c) EllaiSys <support@ellaisys.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Ellaisys\Cognito\Providers;

use Illuminate\Support\Facades\Cache;
use Psr\SimpleCache\CacheInterface as PsrCacheInterface;

class StorageProvider
{
    /**
     * The cache repository contract.
     *
     * @var \Illuminate\Contracts\Cache\Repository
     */
    protected $cache;

    /**
     * The used cache tag.
     *
     * @var string
     */
    protected $tag = 'ellaisys.aws.cognito';

    /**
     * @var bool
     */
    protected $supportsTags;

    /**
     * Constructor.
     *
     * @param \Illuminate\Contracts\Cache\Repository $cache
     *
     * @return void
     */
    public function __construct(string $provider = 'file')
    {
        $this->cache = Cache::store($provider);
        $this->supportsTags = false;
    }


    /**
     * Add a new item into storage.
     *
     * @param string $key
     * @param mixed  $value
     * @param int    $duration in seconds
     *
     * @return void
     */
    public function add(string $key, $value, int $duration = 3600)
    {
        $this->cache()->put($key, $value, $duration);
    }


    /**
     * Add a new item into storage forever.
     *
     * @param string $key
     * @param mixed  $value
     *
     * @return void
     */
    public function forever(string $key, $value)
    {
        $this->cache()->forever($key, $value);
    }


    /**
     * Check for an item in storage.
     *
     * @param string $key
     *
     * @return bool
     */
    public function has(string $key) : bool
    {
        return $this->cache()->has($key);
    }


    /**
     * Get an item from storage.
     *
     * @param string $key
     *
     * @return mixed
     */
    public function get(string $key)
    {
        return $this->cache()->get($key);
    }


    /**
     * Remove an item from storage.
     *
     * @param string $key
     *
     * @return bool
     */
    public function destroy(string $key) : bool
    {
        if ($this->has($key)) {
            return $this->cache()->forget($key);
        }

        return false;
    }


    /**
     * Remove all items associated with the tag.
     *
     * @return void
     */
    public function flush()
    {
        $this->cache()->flush();
    }


    /**
     * Return the cache instance with tags attached.
     *
     * @return \Illuminate\Contracts\Cache\Repository
     */
    protected function cache()
    {
        if ($this->supportsTags === null) {
            $this->determineTagSupport();
        }

        if ($this->supportsTags) {
            return $this->cache->tags($this->tag);
        }

        return $this->cache;
    }

    /**
     * Detect as best we can whether tags are supported with this repository & store,
     * and save our result on the $supportsTags flag.
     *
     * @return void
     */
    protected function determineTagSupport()
    {
        $this->supportsTags = false;

        if (method_exists($this->cache, 'tags') || $this->cache instanceof PsrCacheInterface) {
            try {
                // Attempt the repository tags command, which throws exceptions when unsupported
                $this->cache->tags($this->tag);
                $this->supportsTags = true;
            } catch (BadMethodCallException $ex) {
            }
        }
    }
}
