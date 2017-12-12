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

use Flowpack\OAuth2\Client\Endpoint\AbstractHttpTokenEndpoint;
use Flowpack\OAuth2\Client\Endpoint\TokenEndpointInterface;
use Flowpack\OAuth2\Client\Exception as OAuth2Exception;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Http\Request;
use Neos\Flow\Http\Uri;
use Neos\Flow\Log\SecurityLoggerInterface;

/**
 * @Flow\Scope("singleton")
 */
class TokenEndpoint extends AbstractHttpTokenEndpoint implements TokenEndpointInterface
{
    /**
     * @Flow\Inject
     * @var SecurityLoggerInterface
     */
    protected $securityLogger;

    /**
     * Inspect the received access token as documented in https://developers.facebook.com/docs/facebook-login/access-tokens/, section Getting Info about Tokens and Debugging
     *
     * @param array $tokenToInspect
     * @return array
     * @throws OAuth2Exception
     */
    public function requestValidatedTokenInformation($tokenToInspect)
    {
        $applicationToken = $this->requestClientCredentialsGrantAccessToken();
        $requestArguments = [
            'input_token' => $tokenToInspect['access_token'],
            'access_token' => $applicationToken['access_token']
        ];
        $request = Request::create(new Uri('https://graph.facebook.com/debug_token?' . http_build_query($requestArguments)));
        $response = $this->requestEngine->sendRequest($request);
        $responseContent = $response->getContent();
        if ($response->getStatusCode() !== 200) {
            throw new OAuth2Exception(sprintf('The response was not of type 200 but gave code and error %d "%s"', $response->getStatusCode(), $responseContent), 1383758360);
        }

        $responseArray = json_decode($responseContent, true, 16, JSON_BIGINT_AS_STRING);
        $responseArray['data']['app_id'] = (string)$responseArray['data']['app_id'];
        $responseArray['data']['user_id'] = (string)$responseArray['data']['user_id'];
        $clientIdentifier = (string)$this->clientIdentifier;

        if (!$responseArray['data']['is_valid']
            || $responseArray['data']['app_id'] !== $clientIdentifier
        ) {
            $this->securityLogger->log('Requesting validated token information from the Facebook endpoint did not succeed.', LOG_NOTICE, ['response' => var_export($responseArray, true), 'clientIdentifier' => $clientIdentifier]);
            return false;
        } else {
            return $responseArray['data'];
        }
    }

    /**
     * @param $shortLivedToken
     * @return string
     */
    public function requestLongLivedToken($shortLivedToken)
    {
        return $this->requestAccessToken('fb_exchange_token', ['fb_exchange_token' => $shortLivedToken]);
    }
}
