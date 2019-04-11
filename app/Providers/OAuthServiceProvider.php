<?php

namespace App\Providers;

use Laravel\Passport\Passport;
use App\OAuth\SocialUserProvider;
use App\OAuth\Bridge\Grant\SocialGrant;
use Illuminate\Support\ServiceProvider;
use App\OAuth\SocialUserProviderInterface;
use League\OAuth2\Server\AuthorizationServer;
use App\OAuth\Bridge\Repositories\ScopeRepository;
use Laravel\Passport\Bridge\RefreshTokenRepository;

class OAuthServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     *
     * @return void
     */
    public function register()
    {
        $this->app->extend(AuthorizationServer::class, function ($server, $app) {
            return tap($server, function ($server) {
                $server->enableGrantType(
                    $grantType = $this->makeSocialGrant(), Passport::tokensExpireIn()
                );

                // Allow all scopes to be requested for this grant
                $grantType->setScopeRepository(
                    $this->app->make(ScopeRepository::class)
                );
            });
        });

        $this->app->singleton(SocialUserProviderInterface::class, SocialUserProvider::class);
    }

    /**
     * Create and configure and instance of Social Grant.
     * 
     * @return \App\OAuth\Bridge\Grant\SocialGrant
    */
    protected function makeSocialGrant()
    {
        $grant = new SocialGrant(
            $this->app->make(SocialUserProviderInterface::class),
            $this->app->make(RefreshTokenRepository::class)
        );

        $grant->setRefreshTokenTTL(Passport::refreshTokensExpireIn());

        return $grant;
    }

    /**
     * Bootstrap any application services.
     *
     * @return void
     */
    public function boot()
    {
        //
    }
}
