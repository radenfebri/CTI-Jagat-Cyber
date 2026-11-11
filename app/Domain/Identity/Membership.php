<?php

namespace App\Domain\Identity;

use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;

class Membership extends Model
{
    use HasUuids;

    public const OWNER = 'owner';

    public const ADMIN = 'admin';

    protected $fillable = ['organization_id', 'user_id', 'role'];
}
