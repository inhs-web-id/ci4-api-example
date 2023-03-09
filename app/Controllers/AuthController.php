<?php

namespace App\Controllers;

use App\Controllers\BaseController;

class AuthController extends BaseController
{
    public function index()
    {
        //
    }

    public function login()
    {
        // Validate credentials
        $rules = setting('Validation.login') ?? [
            'email' => [
                'label' => 'Auth.email',
                'rules' => config('AuthSession')->emailValidationRules,
            ],
            'password' => [
                'label' => 'Auth.password',
                'rules' => 'required',
            ],
        ];

        if (! $this->validate($rules)) {
            return $this->response
                ->setJSON(['errors' => $this->validator->getErrors()])
                ->setStatusCode(422);
        }

        // Attempt to login
        $result = auth()->attempt($this->request->getPost(setting('Auth.validFields')));
        if (! $result->isOK()) {
            return $this->response
                ->setJSON(['error' => $result->reason()])
                ->setStatusCode(401);
        }

        // Generate token and return to client
        $token = auth()->user()->generateAccessToken(service('request')->getVar('device_name'));

        return $this->response
            ->setJSON(['token' => $token->raw_token]);
    }
}
