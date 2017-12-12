<?php

namespace Flowpack\OAuth2\Client\Facebook;

use Flowpack\OAuth2\Client\Provider\AbstractClientProvider;
use Flowpack\OAuth2\Client\Token\AbstractClientToken;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Log\SecurityLoggerInterface;
use Neos\Flow\Persistence\PersistenceManagerInterface;
use Neos\Flow\Security\Account;
use Neos\Flow\Security\AccountRepository;
use Neos\Flow\Security\Authentication\TokenInterface;
use Neos\Flow\Security\Context;
use Neos\Flow\Security\Exception\UnsupportedAuthenticationTokenException;
use Neos\Flow\Security\Policy\PolicyService;

class Provider extends AbstractClientProvider
{
    /**
     * @Flow\Inject
     * @var SecurityLoggerInterface
     */
    protected $securityLogger;

    /**
     * @Flow\Inject
     * @var PolicyService
     */
    protected $policyService;

    /**
     * @Flow\Inject
     * @var AccountRepository
     */
    protected $accountRepository;

    /**
     * @Flow\Inject
     * @var Context
     */
    protected $securityContext;

    /**
     * @Flow\Inject
     * @var TokenEndpoint
     */
    protected $endpoint;

    /**
     * @Flow\Inject
     * @var AuthorizationFlow
     */
    protected $authorizationFlow;

    /**
     * @Flow\Inject
     * @var PersistenceManagerInterface
     */
    protected $persistenceManager;

    /**
     * Tries to authenticate the given token. Sets isAuthenticated to TRUE if authentication succeeded.
     *
     * @param TokenInterface $authenticationToken The token to be authenticated
     * @throws \Neos\Flow\Security\Exception\UnsupportedAuthenticationTokenException
     * @return void
     */
    public function authenticate(TokenInterface $authenticationToken)
    {
        if (!($authenticationToken instanceof AbstractClientToken)) {
            throw new UnsupportedAuthenticationTokenException('This provider cannot authenticate the given token.', 1383754993);
        }

        $credentials = $authenticationToken->getCredentials();

        // Inspect the received access token as documented in https://developers.facebook.com/docs/facebook-login/login-flow-for-web-no-jssdk/
        $tokenInformation = $this->endpoint->requestValidatedTokenInformation($credentials);

        if ($tokenInformation === false) {
            $authenticationToken->setAuthenticationStatus(TokenInterface::WRONG_CREDENTIALS);
            return;
        }

        // Check if the permitted scopes suffice:
        $necessaryScopes = $this->options['scopes'];
        $scopesHavingPermissionFor = $tokenInformation['scopes'];
        $requiredButNotPermittedScopes = array_diff($necessaryScopes, $scopesHavingPermissionFor);
        if (count($requiredButNotPermittedScopes) > 0) {
            $authenticationToken->setAuthenticationStatus(TokenInterface::WRONG_CREDENTIALS);
            $this->securityLogger->log('The permitted scopes do not satisfy the required once.', LOG_NOTICE, ['necessaryScopes' => $necessaryScopes, 'allowedScopes' => $scopesHavingPermissionFor]);
            return;
        }

        // From here, we surely know the user is considered authenticated against the remote service,
        // yet to check if there is an immanent account present.
        $authenticationToken->setAuthenticationStatus(TokenInterface::AUTHENTICATION_SUCCESSFUL);
        /** @var $account \Neos\Flow\Security\Account */
        $account = null;
        $isNewCreatedAccount = false;
        $providerName = $this->name;
        $accountRepository = $this->accountRepository;
        $this->securityContext->withoutAuthorizationChecks(function () use ($tokenInformation, $providerName, $accountRepository, &$account) {
            $account = $accountRepository->findByAccountIdentifierAndAuthenticationProviderName($tokenInformation['user_id'], $providerName);
        });

        if ($account === null) {
            $account = new Account();
            $isNewCreatedAccount = true;
            $account->setAccountIdentifier($tokenInformation['user_id']);
            $account->setAuthenticationProviderName($providerName);

            // adding in Settings.yaml specified roles to the account
            // so the account can be authenticate against a role in the frontend for example
            $roles = [];
            foreach ($this->options['authenticateRoles'] as $roleIdentifier) {
                $roles[] = $this->policyService->getRole($roleIdentifier);
            }
            $account->setRoles($roles);
            $this->accountRepository->add($account);
        }
        $authenticationToken->setAccount($account);

        // request long-live token and attach that to the account
        $longLivedToken = $this->endpoint->requestLongLivedToken($credentials['access_token']);
        $account->setCredentialsSource($longLivedToken['access_token']);
        $account->authenticationAttempted(TokenInterface::AUTHENTICATION_SUCCESSFUL);

        $this->accountRepository->update($account);
        $this->persistenceManager->persistAll();

        // Only if defined a Party for the account is created
        if ($this->options['partyCreation'] && $isNewCreatedAccount) {
            $this->authorizationFlow->createPartyAndAttachToAccountFor($authenticationToken);
        }
    }

    /**
     * Returns the class names of the tokens this provider is responsible for.
     *
     * @return array The class name of the token this provider is responsible for
     */
    public function getTokenClassNames()
    {
        return [Token::class];
    }
}
