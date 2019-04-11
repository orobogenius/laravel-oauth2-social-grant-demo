<?php

namespace App\OAuth\Bridge\Grant;

use DateInterval;
use League\OAuth2\Server\RequestEvent;
use App\OAuth\SocialUserProviderInterface;
use Psr\Http\Message\ServerRequestInterface;
use League\OAuth2\Server\Grant\AbstractGrant;
use League\OAuth2\Server\Entities\UserEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;

class SocialGrant extends AbstractGrant
{
    /**
     * The social user provider implementation.
     * 
     * @var SocialUserProviderInterface
    */
    protected $socialUserProvider;

    /**
     * Create a Social Grant instance.
     * 
     * @param SocialUserProviderInterface  $socialUserProvider
     * @param RefreshTokenRepositoryInterface  $refreshTokenRepository
     * 
     * @return void
    */
    public function __construct(
        SocialUserProviderInterface $socialUserProvider,
        RefreshTokenRepositoryInterface $refreshTokenRepository
    )
    {
        $this->socialUserProvider = $socialUserProvider;
        $this->setRefreshTokenRepository($refreshTokenRepository);
        $this->refreshTokenTTL = new \DateInterval('P1M');
    }

    /**
     * {@inheritdoc}
    */
    public function respondToAccessTokenRequest(
        ServerRequestInterface $request,
        ResponseTypeInterface $responseType,
        DateInterval $accessTokenTTL
    ) {
        $client = $this->validateClient($request);

        $scopes = $this->validateScopes($this->getRequestParameter('scope', $request, $this->defaultScope));

        $user = $this->validateUser($request);

        // Finalize the requested scopes
        $finalizedScopes = $this->scopeRepository->finalizeScopes($scopes, $this->getIdentifier(), $client, $user->getIdentifier());

        // Issue and persist new tokens
        $accessToken = $this->issueAccessToken($accessTokenTTL, $client, $user->getIdentifier(), $finalizedScopes);
        $refreshToken = $this->issueRefreshToken($accessToken);

        // Send events to emitter
        $this->getEmitter()->emit(new RequestEvent(RequestEvent::ACCESS_TOKEN_ISSUED, $request));
        $this->getEmitter()->emit(new RequestEvent(RequestEvent::REFRESH_TOKEN_ISSUED, $request));

        // Inject tokens into response
        $responseType->setAccessToken($accessToken);
        $responseType->setRefreshToken($refreshToken);

        return $responseType;
    }

    /**
     * Validate the user.
     * 
     * @param ServerRequestInterface $request
     *
     * @throws OAuthServerException
     *
     * @return UserEntityInterface
     */
    protected function validateUser(ServerRequestInterface $request)
    {
        $provider = $this->getRequestParameter('provider', $request);
        
        if (is_null($provider)) {
            throw OAuthServerException::invalidRequest('provider');
        }

        if (! $this->isProviderSupported($provider)) {
            throw OAuthServerException::invalidRequest('provider', 'Invalid provider');
        }

        $accessToken = $this->getRequestParameter('access_token', $request);

        if (is_null($accessToken)) {
            throw OAuthServerException::invalidRequest('access_token');
        }

        // Get user from social network provider
        $user = $this->socialUserProvider->getUserEntityByAccessToken(
            $provider,
            $accessToken
        );

        if ($user instanceof UserEntityInterface === false) {
            $this->getEmitter()->emit(new RequestEvent(RequestEvent::USER_AUTHENTICATION_FAILED, $request));

            throw OAuthServerException::invalidCredentials();
        }

        return $user;
    }

    /**
     * Determine if the provider is supported.
     * 
     * @param string  $provider
     * @return bool
    */
    protected function isProviderSupported($provider)
    {
        return in_array($provider, config('auth.social.providers'));
    }

    /**
     * {@inheritdoc}
     */
    public function getIdentifier()
    {
        return 'social';
    }
}