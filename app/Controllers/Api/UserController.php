<?php

namespace App\Controllers\Api;

use App\Controllers\BaseController;

class UserController extends BaseController
{
    public function profile()
    {
        $user = auth()->user();
        return $this->response
            ->setJSON(['data' => $user]);
    }
}
