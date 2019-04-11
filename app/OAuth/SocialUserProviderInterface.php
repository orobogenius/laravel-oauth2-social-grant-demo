<?php

namespace App\OAuth;

interface SocialUserProviderInterface
{
    /**
     * Get a social user from the provider by their access token.
     *
     * @param string  $provider
     * @param string  $accessToken
     *
     * @return \League\OAuth2\Server\Entities\UserEntityInterface
     */
    public function getUserEntityByAccessToken($provider, $accessToken);
}
