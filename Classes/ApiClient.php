<?php

namespace Flowpack\OAuth2\Client\Facebook;

/*
 * This file is part of the Flowpack.OAuth2.Client.Facebook package.
 *
 * (c) Contributors of the Flowpack Team - flowpack.org
 *
 * This package is Open Source Software. For the full copyright and license
 * information, please view the LICENSE file which was distributed with this
 * source code.
 */

use Neos\Flow\Annotations as Flow;
use Neos\Flow\Http\Client\CurlEngine;
use Neos\Flow\Http\Client\RequestEngineInterface;
use Neos\Flow\Http\Request;
use Neos\Flow\Http\Uri;
use Neos\Flow\ObjectManagement\DependencyInjection\DependencyProxy;

/**
 * @Flow\Scope("singleton")
 */
class ApiClient
{
    /**
     * @var RequestEngineInterface
     */
    protected $requestEngine;

    /**
     * @var string
     */
    protected $endpoint = 'https://graph.facebook.com';

    /**
     * @var string
     */
    protected $appSecret;

    /**
     * The access token to use for the request.
     *
     * @var string
     */
    protected $currentAccessToken;

    /**
     */
    public function initializeObject()
    {
        if (($this->requestEngine instanceof DependencyProxy
                && $this->requestEngine->_getClassName() === 'Neos\Flow\Http\Client\CurlEngine')
            || $this->requestEngine instanceof CurlEngine) {
            $this->requestEngine->setOption(CURLOPT_CAINFO, FLOW_PATH_PACKAGES . 'Application/Flowpack.OAuth2.Client/Resources/Private/cacert.pem');
            $this->requestEngine->setOption(CURLOPT_SSL_VERIFYPEER, true);
        }
    }

    /**
     * @param string $resource
     * @param string $method
     * @return \Neos\Flow\Http\Response
     */
    public function query($resource, $method = 'GET')
    {
        $uri = new Uri($this->endpoint . $resource);
        parse_str((string)$uri->getQuery(), $query);
        $query['access_token'] = $this->currentAccessToken;
        $query['appsecret_proof'] = hash_hmac('sha256', $this->currentAccessToken, $this->appSecret);
        $uri->setQuery(http_build_query($query));

        $request = Request::create($uri, $method);
        $response = $this->requestEngine->sendRequest($request);
        return $response;
    }

    /**
     * @param string $currentAccessToken
     */
    public function setCurrentAccessToken($currentAccessToken)
    {
        $this->currentAccessToken = $currentAccessToken;
    }
}

;
