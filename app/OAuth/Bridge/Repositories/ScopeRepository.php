<?php

namespace App\OAuth\Bridge\Repositories;

use Laravel\Passport\Passport;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use Laravel\Passport\Bridge\ScopeRepository as PassportScopeRepository;

class ScopeRepository extends PassportScopeRepository
{
    /**
     * {@inheritdoc}
     */
    public function finalizeScopes(
        array $scopes, $grantType,
        ClientEntityInterface $clientEntity, $userIdentifier = null)
    {
        return collect($scopes)->filter(function ($scope) {
            return Passport::hasScope($scope->getIdentifier());
        })->values()->all();
    }
}