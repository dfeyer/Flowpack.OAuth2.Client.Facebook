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

use Flowpack\OAuth2\Client\Exception\InvalidPartyDataException;
use Flowpack\OAuth2\Client\Flow\AbstractFlow;
use Flowpack\OAuth2\Client\Flow\FlowInterface;
use Flowpack\OAuth2\Client\Token\AbstractClientToken;
use Neos\Flow\Annotations as Flow;
use Neos\Party\Domain\Model\ElectronicAddress;
use Neos\Party\Domain\Model\Person;
use Neos\Party\Domain\Model\PersonName;
use Neos\Party\Domain\Repository\PartyRepository;
use Neos\Flow\Configuration\ConfigurationManager;

class AuthorizationFlow extends AbstractFlow implements FlowInterface
{
    /**
     * @Flow\Inject
     * @var ConfigurationManager
     */
    protected $configurationManager;

    /**
     * @Flow\Inject
     * @var ApiClient
     */
    protected $api;

    /**
     * Creates a party for the given account
     *
     * @param AbstractClientToken $token
     * @throws InvalidPartyDataException
     */
    public function createPartyAndAttachToAccountFor(AbstractClientToken $token)
    {
        $this->initializeUserData($token);
        $userData = $this->authenticationServicesUserData[(string)$token];

        $party = new Person();
        $party->setName(new PersonName('', $userData['first_name'], '', $userData['last_name']));
        // Todo: this is not covered by the Person implementation, we should have a solution for that
        #$party->setBirthDate(\DateTime::createFromFormat('!m/d/Y', $userData['birthday'], new \DateTimeZone('UTC')));
        #$party->setGender(substr($userData['gender'], 0, 1));
        $electronicAddress = new ElectronicAddress();
        $electronicAddress->setType(ElectronicAddress::TYPE_EMAIL);
        $electronicAddress->setIdentifier($userData['email']);
        $electronicAddress->isApproved(true);
        $party->addElectronicAddress($electronicAddress);
        $party->setPrimaryElectronicAddress($electronicAddress);

        $partyValidator = $this->validatorResolver->getBaseValidatorConjunction('Neos\Party\Domain\Model\Person');
        $validationResult = $partyValidator->validate($party);
        if ($validationResult->hasErrors()) {
            throw new InvalidPartyDataException('The created party does not satisfy the requirements', 1384266207);
        }

        $account = $token->getAccount();
        $account->setParty($party);
        $this->accountRepository->update($account);
        $this->partyRepository->add($party);

        $this->persistenceManager->persistAll();
    }

    /**
     * Returns the token class name this flow is responsible for
     *
     * @return string
     */
    public function getTokenClassName()
    {
        return Token::class;
    }

    /**
     * getting all the defined data from facebook
     * @param AbstractClientToken $token
     */
    protected function initializeUserData(AbstractClientToken $token)
    {
        $credentials = $token->getCredentials();
        $this->api->setCurrentAccessToken($credentials['access_token']);
        $query = $this->buildQuery();
        $content = $this->api->query($query)->getContent();
        $this->authenticationServicesUserData[(string)$token] = json_decode($content, true);
    }

    /**
     * builds the query from the fields in Settings.yaml
     * there is no further check if the fields are allowed in the scopes
     * for further information have a look at https://developers.facebook.com/docs/facebook-login/permissions
     *
     * @return string
     */
    protected function buildQuery()
    {
        $query = '/me';
        $this->authenticationServicesFields = $this->configurationManager->getConfiguration(ConfigurationManager::CONFIGURATION_TYPE_SETTINGS, 'Neos.Flow.security.authentication.providers.FacebookOAuth2Provider.providerOptions.fields');
        $fields = implode(',', $this->authenticationServicesFields);

        $query = $query . '?fields=' . $fields;
        return $query;
    }
}
