<?php

namespace App\Controllers;

use App\Controllers\BaseController;
use CodeIgniter\Shield\Entities\User;
use CodeIgniter\Shield\Exceptions\ValidationException;
use CodeIgniter\Events\Events;

class AuthController extends BaseController
{
    public function register()
    {
        if (auth()->loggedIn()) {
            return $this->response
                ->setJSON(['errors' => 'Already Logged!'])
                ->setStatusCode(422);
        }

        $registrationUsernameRules = array_merge(
            config('AuthSession')->usernameValidationRules,
            [sprintf('is_unique[%s.username]', config('Auth')->tables['users'])]
        );
        $registrationEmailRules = array_merge(
            config('AuthSession')->emailValidationRules,
            [sprintf('is_unique[%s.secret]', config('Auth')->tables['identities'])]
        );

        $rules = setting('Validation.registration') ?? [
            'username' => [
                'label' => 'Auth.username',
                'rules' => $registrationUsernameRules,
            ],
            'email' => [
                'label' => 'Auth.email',
                'rules' => $registrationEmailRules,
            ],
            'password' => [
                'label' => 'Auth.password',
                'rules' => 'required|strong_password',
            ],
            'password_confirm' => [
                'label' => 'Auth.passwordConfirm',
                'rules' => 'required|matches[password]',
            ],
        ];

        if (! $this->validate($rules)) {
            return $this->response
                ->setJSON(['errors' => $this->validator->getErrors()])
                ->setStatusCode(422);
        }

        $users = model(setting('Auth.userProvider'));
        $allowedPostFields = array_keys($rules);
        $user              = new User();
        $user->fill($this->request->getPost($allowedPostFields));

        // Workaround for email only registration/login
        if ($user->username === null) {
            $user->username = null;
        }

        try {
            $users->save($user);
        } catch (ValidationException $e) {
            return $this->response
                ->setJSON(['errors' => $users->errors()])
                ->setStatusCode(422);
        }

        // To get the complete user object with ID, we need to get from the database
        $user = $users->findById($users->getInsertID());

        // Add to default group
        $users->addToDefaultGroup($user);

        Events::trigger('register', $user);

        /** @var Session $authenticator */
        $authenticator = auth('session')->getAuthenticator();

        $authenticator->startLogin($user);

        // If an action has been defined for register, start it up.
        $hasAction = $authenticator->startUpAction('register', $user);
        if ($hasAction) {
            return $this->response
            ->setJSON(['message', lang('Auth.needActivate')]);
        }

        $user->activate();

        $authenticator->completeLogin($user);

        return $this->response
            ->setJSON(['message', lang('Auth.registerSuccess')]);
    }

    public function login()
    {
        if (auth()->loggedIn()) {
            return $this->response
                ->setJSON(['errors' => 'Already Logged!'])
                ->setStatusCode(422);
        }

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

        $credentials             = $this->request->getPost(setting('Auth.validFields'));
        $credentials             = array_filter($credentials);
        $credentials['password'] = $this->request->getPost('password');

        // Attempt to login
        $result = auth()->attempt($credentials);
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

    public function logout()
    {
        auth()->logout();
        return $this->response
            ->setJSON(['message' => lang('Auth.successLogout')]);
    }
}
