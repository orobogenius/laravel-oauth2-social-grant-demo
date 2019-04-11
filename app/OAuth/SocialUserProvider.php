<?php

namespace App\OAuth;

use App\Repositories\UserRepository;
use Laravel\Socialite\Facades\Socialite;
use Laravel\Passport\Bridge\User as UserEntity;
use League\OAuth2\Server\Exception\OAuthServerException;

class SocialUserProvider implements SocialUserProviderInterface
{
    /**
     * The user repository instance.
     * 
     * @var UserRepository
    */
    protected $userRepository;

    /**
     * Create a social user provider instance.
     * 
     * @param UserRepository  $userRepository
    */
    public function __construct(UserRepository $userRepository)
    {
        $this->userRepository = $userRepository;
    }

    /**
     * {@inheritdoc}
    */
    public function getUserEntityByAccessToken($provider, $accessToken)
    {
        $user = $this->getUserFromSocialProvider($provider, $accessToken);

        if (! $user) {
            return;
        }

        return new UserEntity($user->getAuthIdentifier());
    }

    /**
     * Get the user from the specified provider using the given access token.
     * 
     * @param string  $provider
     * @param string  $accessToken
     * 
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     * 
     * @return \App\User
    */
    public function getUserFromSocialProvider($provider, $accessToken)
    {
        try {
            $user = Socialite::driver($provider)->userFromToken($accessToken);
        } catch (\Exception $ex) {
            throw new OAuthServerException(
                'Authentication error, invalid access token',
                $errorCode = 400,
                'invalid_request'
            );            
        }

        return $this->userRepository->findOrCreateSocialUser(
            array_merge($user->getRaw(), ['provider' => $provider])
        );
    }
}