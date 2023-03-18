<?php

namespace App\Controllers\Api;

use App\Controllers\BaseController;
use CodeIgniter\API\ResponseTrait;

class UserController extends BaseController
{
    use ResponseTrait;

    public function profile()
    {
        $user = auth()->user();
        return $this->respond($user, 200);

        //return $this->response
        //    ->setJSON(['data' => $user]);
    }
}
