<?php

namespace App\Repositories;

use App\User;

class UserRepository
{
    /**
     * @var \Illuminate\Database\Eloquent\Model
    */
    protected $model;

    /**
     * Create a new user repository instance.
     * 
     * @param \App\User
    */
    public function __construct(User $model)
    {
        $this->model = $model;
    }

    /**
     * Retrieve or create a new resource owner.
     * 
     * @param array  $attributes
     * @return App\User
    */
    public function findOrCreateSocialUser(array $attributes)
    {
        return $this->model->firstOrCreate(
            ['provider_id' => $attributes['id']],
            $attributes
        );
    }
}