<?php
/**
 * Created by PhpStorm.
 * User: SaliproPham
 * Date: 17/9/2015
 * Time: 6:11 PM
 */

class Auth_Login_Slogin extends \Auth\Auth_Login_Driver
{
    /**
     * @var  Database_Result  when login succeeded
     */
    protected $user = null;

    /**
     * @var  array  value for guest login
     */
    protected static $guest_login = array(
        'Id' => 0,
        'Username' => 'guest',
        'GroupId' => '0',
        'LoginHash' => false,
        'Email' => false,
    );

    /**
     * @var  array  SimpleAuth class config
     */
    protected $config = array(
        'drivers' => array('group' => array('Sgroup'),'acl' => array('Sacl')),
        'additional_fields' => array('profile_fields'),
    );

    public static $config_file = 'auth_simple';

    /**
     * Load the config and setup the remember-me session if needed
     */
    public static function _init()
    {
        # custom config file name to load
        if(!\File::exists(APPPATH .'config/' .static::$config_file . '.php')){
            throw new Exception(static::$config_file .' not found',404);
        }

        \Config::load(static::$config_file, true);
        # reset simpleauth config
        \Config::set('simpleauth',array());

        // setup the remember-me session object if needed
        if (\Config::get(static::$config_file .'.remember_me.enabled', false))
        {
            static::$remember_me = \Session::forge(array(
                'driver' => 'cookie',
                'cookie' => array(
                    'cookie_name' => \Config::get(static::$config_file .'.remember_me.cookie_name', 'rmcookie'),
                ),
                'encrypt_cookie' => true,
                'expire_on_close' => false,
                'expiration_time' => \Config::get(static::$config_file .'.remember_me.expiration', 86400 * 31),
            ));
        }
    }


    /**
     * Check for login
     *
     * @return  bool
     */
    protected function perform_check()
    {
        // fetch the username and login hash from the session
        $username    = \Session::get(static::$config_file.'_username');
        $login_hash  = \Session::get(static::$config_file.'_loginhash');

        // only worth checking if there's both a username and login-hash
        if ( ! empty($username) and ! empty($login_hash))
        {
            if(is_null($this->user) and \Config::get('auth.use_session',false)){
                $this->user = \Session::get(static::$config_file.'_userlogin',null);
            }

            if (is_null($this->user) or ($this->user['Username'] != $username and $this->user != static::$guest_login))
            {
                $this->user = \DB::select_array(\Config::get(static::$config_file .'.table_columns', array('*')))
                    ->where('Username', '=', $username)
                    ->from(\Config::get(static::$config_file .'.table_users'))
                    ->execute(\Config::get(static::$config_file .'.db_connection'))->current();
            }

            // return true when login was verified, and either the hash matches or multiple logins are allowed
            if ($this->user and (\Config::get(static::$config_file .'.multiple_logins', false) or $this->user['LoginHash'] === $login_hash))
            {
                return true;
            }
        }

        // not logged in, do we have remember-me active and a stored user_id?
        elseif (static::$remember_me and $user_id = static::$remember_me->get('user_id', null))
        {
            return $this->force_login($user_id);
        }

        // no valid login when still here, ensure empty session and optionally set guest_login
        $this->user = \Config::get(static::$config_file .'.guest_login', true) ? static::$guest_login : false;

        \Session::delete(static::$config_file.'_username');
        \Session::delete(static::$config_file.'_loginhash');
        \Session::delete(static::$config_file.'_userlogin');
        return false;
    }

    /**
     * Check the user exists
     *
     * @return  bool
     */
    public function validate_user($username_or_email = '', $password = '')
    {
        $username_or_email = trim($username_or_email) ?: trim(\Input::post(\Config::get(static::$config_file .'.username_post_key', 'Username')));
        $password = trim($password) ?: trim(\Input::post(\Config::get(static::$config_file .'.password_post_key', 'Password')));

        if (empty($username_or_email) or empty($password))
        {
            return false;
        }
        $password = $this->hash_password($password);
        $user = \DB::select_array(\Config::get(static::$config_file .'.table_columns', array('*')))
            ->where_open()
            ->where('Username', $username_or_email)
            ->or_where('Email', $username_or_email)
            ->where_close()
            ->where('Password', $password)
            ->and_where('Activated', 1)
            ->from(\Config::get(static::$config_file .'.table_users'))
            ->execute(\Config::get(static::$config_file .'.db_connection'))->current();

        return $user ?: false;
    }

    /**
     * Login user
     *
     * @param   string
     * @param   string
     * @return  bool
     */
    public function login($username_or_email = '', $password = '')
    {
        if ( ! ($this->user = $this->validate_user($username_or_email, $password)))
        {
            $this->user = \Config::get(static::$config_file .'.guest_login', true) ? static::$guest_login : false;
            \Session::delete(static::$config_file.'_username');
            \Session::delete(static::$config_file.'_loginhash');
            \Session::delete(static::$config_file.'_userlogin');
            return false;
        }

        // register so Auth::logout() can find us
        Auth::_register_verified($this);

        \Session::set(static::$config_file.'_username', $this->user['Username']);
        \Session::set(static::$config_file.'_loginhash', $this->create_login_hash());
        // allow to save userinfo on session
        if(\Config::get('auth.use_session',false)){
            \Session::set(static::$config_file.'_userlogin', $this->user);
        }
        \Session::instance()->rotate();
        return true;
    }

    /**
     * Force login user
     *
     * @param   string
     * @return  bool
     */
    public function force_login($user_id = '')
    {
        if (empty($user_id))
        {
            return false;
        }

        $this->user = \DB::select_array(\Config::get(static::$config_file .'.table_columns', array('*')))
            ->where_open()
            ->where('ID', '=', $user_id)
            ->or_where('Uuid', $user_id)
            ->where_close()
            ->and_where('Activated', 1)
            ->from(\Config::get(static::$config_file .'.table_users'))
            ->execute(\Config::get(static::$config_file .'.db_connection'))
            ->current();

        if ($this->user == false)
        {
            $this->user = \Config::get(static::$config_file .'.guest_login', true) ? static::$guest_login : false;
            \Session::delete(static::$config_file.'_username');
            \Session::delete(static::$config_file.'_loginhash');
            \Session::set(static::$config_file.'_userlogin', $this->user);
            return false;
        }

        \Session::set(static::$config_file.'_username', $this->user['username']);
        \Session::set(static::$config_file.'_loginhash', $this->create_login_hash());
        // allow to save userinfo on session
        if(\Config::get('auth.use_session',false)){
            \Session::set(static::$config_file.'_userlogin', $this->user);
        }

        // and rotate the session id, we've elevated rights
        \Session::instance()->rotate();

        // register so Auth::logout() can find us
        Auth::_register_verified($this);

        return true;
    }

    /**
     * Logout user
     *
     * @return  bool
     */
    public function logout()
    {
        $this->user = \Config::get(static::$config_file .'.guest_login', true) ? static::$guest_login : false;
        \Session::delete(static::$config_file.'_username');
        \Session::delete(static::$config_file.'_loginhash');
        \Session::set(static::$config_file.'_userlogin', $this->user);
        return true;
    }

    /**
     * Create new user
     *
     * @param   string
     * @param   string
     * @param   string  must contain valid email address
     * @param   int     group id
     * @param   Array
     * @return  bool
     */
    public function create_user($username, $password, $email, $group = 1, Array $profile_fields = array())
    {
        $password = trim($password);
        $email = filter_var(trim($email), FILTER_VALIDATE_EMAIL);

        if (empty($username) or empty($password) or empty($email))
        {
            throw new \SimpleUserUpdateException('Username, password or email address is not given, or email address is invalid', 1);
        }

        $same_users = \DB::select_array(\Config::get(static::$config_file .'.table_columns', array('*')))
            ->where('Username', '=', $username)
            ->or_where('Email', '=', $email)
            ->from(\Config::get(static::$config_file .'.table_name'))
            ->execute(\Config::get(static::$config_file .'.db_connection'));

        if ($same_users->count() > 0)
        {
            if (in_array(strtolower($email), array_map('strtolower', $same_users->current())))
            {
                throw new \SimpleUserUpdateException('Email address already exists', 2);
            }
            else
            {
                throw new \SimpleUserUpdateException('Username already exists', 3);
            }
        }

        $user = array(
            'Uuid'        => \Str::random('uuid'),
            'Username'        => (string) $username,
            'Password'        => $this->hash_password((string) $password),
            'Email'           => $email,
            'GroupId'           => (int) $group,
            'LastLogin'      => 0,
            'LoginHash'      => ''
        );

        //prepare data for userinfo
        $profile_fields['UserId'] = null;

        try
        {
            \DB::start_transaction();

            $result = \DB::insert(\Config::get(static::$config_file .'.table_users'))
                ->set($user)
                ->execute(\Config::get(static::$config_file .'.db_connection'));

            $profile_fields['UserId'] = ($result[1] > 0) ? $result[0] : null;
            $info = \DB::insert(\Config::get(static::$config_file .'.table_usersinfo'))
                ->set($profile_fields)
                ->execute(\Config::get(static::$config_file .'.db_connection'));

            \DB::commit_transaction();
            return ($result[1] > 0) ? $result[0] : false;
        }
        catch (Exception $e)
        {
            // rollback pending transactional queries
            \DB::rollback_transaction();
            throw $e;
        }

        return false;

    }

    /**
     * Update a user's properties [ONLY USERLOGIN - email, password, group]
     * Note: Username cannot be updated, to update password the old password must be passed as old_password
     *
     * @param   Array  properties to be updated including profile fields
     * @param   string
     * @return  bool
     */
    public function update_user($values, $username = null)
    {
        $username = $username ?: $this->user['Username'];
        $current_values = \DB::select_array(\Config::get(static::$config_file .'.table_columns', array('*')))
            ->where('Username', '=', $username)
            ->from(\Config::get(static::$config_file .'.table_users'))
            ->execute(\Config::get(static::$config_file .'.db_connection'));

        if (empty($current_values))
        {
            throw new \SimpleUserUpdateException('Username not found', 4);
        }

        $update = array();
        if (array_key_exists('username', $values))
        {
            throw new \SimpleUserUpdateException('Username cannot be changed.', 5);
        }
        if (array_key_exists('password', $values))
        {
            if (empty($values['old_password'])
                or $current_values->get('Password') != $this->hash_password(trim($values['old_password'])))
            {
                throw new \SimpleUserWrongPassword('Old password is invalid');
            }

            $password = trim(strval($values['password']));
            if ($password === '')
            {
                throw new \SimpleUserUpdateException('Password can\'t be empty.', 6);
            }
            $update['Password'] = $this->hash_password($password);
            unset($values['password']);
        }
        if (array_key_exists('old_password', $values))
        {
            unset($values['old_password']);
        }
        if (array_key_exists('email', $values))
        {
            $email = filter_var(trim($values['email']), FILTER_VALIDATE_EMAIL);
            if ( ! $email)
            {
                throw new \SimpleUserUpdateException('Email address is not valid', 7);
            }
            $matches = \DB::select()
                ->where('Email', '=', $email)
                ->where('Username', '!=', $username)
                ->from(\Config::get(static::$config_file .'.table_user'))
                ->execute(\Config::get(static::$config_file .'.db_connection'));
            if (count($matches))
            {
                throw new \SimpleUserUpdateException('Email address is already in use', 11);
            }
            $update['Email'] = $email;
            unset($values['email']);
        }
        if (array_key_exists('group', $values))
        {
            if (is_numeric($values['group']))
            {
                $update['GroupId'] = (int) $values['group'];
            }
            unset($values['group']);
        }


        $update['UpdatedAt'] = \Date::forge()->get_timestamp();

        $affected_rows = \DB::update(\Config::get(static::$config_file .'.table_users'))
            ->set($update)
            ->where('Username', '=', $username)
            ->execute(\Config::get(static::$config_file .'.db_connection'));

        // Refresh user
        if ($this->user['Username'] == $username)
        {
            $this->user = \DB::select_array(\Config::get(static::$config_file .'.table_columns', array('*')))
                ->where('Username', '=', $username)
                ->from(\Config::get(static::$config_file .'.table_users'))
                ->execute(\Config::get(static::$config_file .'.db_connection'))->current();
        }

        return $affected_rows > 0;
    }

    /**
     * Change a user's password
     *
     * @param   string
     * @param   string
     * @param   string  username or null for current user
     * @return  bool
     */
    public function change_password($old_password, $new_password, $username = null)
    {
        try
        {
            return (bool) $this->update_user(array('old_password' => $old_password, 'password' => $new_password), $username);
        }
            // Only catch the wrong password exception
        catch (SimpleUserWrongPassword $e)
        {
            return false;
        }
    }

    /**
     * Generates new random password, sets it for the given username and returns the new password.
     * To be used for resetting a user's forgotten password, should be emailed afterwards.
     *
     * @param   string  $username
     * @return  string
     */
    public function reset_password($username_uuid)
    {
        $new_password = \Str::random('alnum', 8);
        $password_hash = $this->hash_password($new_password);

        $affected_rows = \DB::update(\Config::get(static::$config_file .'.table_users'))
            ->set(array('Password' => $password_hash))
            ->where('Username', '=', $username_uuid)
            ->or_where('Uuid', $username_uuid)
            ->execute(\Config::get(static::$config_file .'.db_connection'));

        if ( ! $affected_rows)
        {
            throw new \SimpleUserUpdateException('Failed to reset password, user was invalid.', 8);
        }

        return $new_password;
    }

    /**
     * Deletes a given user
     *
     * @param   string
     * @return  bool
     */
    public function delete_user($username_uuid)
    {
        if (empty($username_uuid))
        {
            throw new \SimpleUserUpdateException('Cannot delete user with empty username', 9);
        }

        $affected_rows = \DB::update(\Config::get(static::$config_file .'.table_users'))
            ->value('Activated', 0)
            ->where('username', '=', $username_uuid)
            ->or_where('Uuid', $username_uuid)
            ->execute(\Config::get(static::$config_file .'.db_connection'));

        return $affected_rows > 0;
    }

    /**
     * Creates a temporary hash that will validate the current login
     *
     * @return  string
     */
    public function create_login_hash()
    {
        if (empty($this->user))
        {
            throw new \SimpleUserUpdateException('User not logged in, can\'t create login hash.', 10);
        }

        $last_login = \Date::forge()->get_timestamp();
        $login_hash = sha1(\Config::get(static::$config_file .'.login_hash_salt').$this->user['Username'].$last_login);

        \DB::update(\Config::get(static::$config_file .'.table_users'))
            ->set(array('LastLogin' => $last_login, 'LoginHash' => $login_hash))
            ->where('Username', '=', $this->user['Username'])
            ->execute(\Config::get(static::$config_file .'.db_connection'));

        $this->user['LoginHash'] = $login_hash;

        return $login_hash;
    }

    /**
     * Get the user's ID
     *
     * @return  Array  containing this driver's ID & the user's ID
     */
    public function get_user_id()
    {
        if (empty($this->user))
        {
            return false;
        }

        return $this->user['Id'];
    }

    /**
     * Get the user's groups
     *
     * @return  Array  containing the group driver ID & the user's group ID
     */
    public function get_groups()
    {
        if (empty($this->user))
        {
            return false;
        }
        return array(array($this->config['drivers']['group'][0], $this->user['GroupId']));
    }

    /**
     * Getter for user data
     *
     * @param  string  name of the user field to return
     * @param  mixed  value to return if the field requested does not exist
     *
     * @return  mixed
     */
    public function get($field, $default = null)
    {
        if (isset($this->user[$field]))
        {
            return $this->user[$field];
        }
        else
        {
            return $this->get_profile_fields($field, $default);
        }

        return $default;
    }

    /**
     * Get the user's emailaddress
     *
     * @return  string
     */
    public function get_email()
    {
        return $this->get('Email', false);
    }

    /**
     * Get the user's screen name
     *
     * @return  string
     */
    public function get_screen_name()
    {
        if (empty($this->user))
        {
            return false;
        }

        return $this->user['Username'];
    }

    /**
     * Get the user's profile fields
     *
     * @return  Array
     */
    public function get_profile_fields($field = null, $default = null, $username = null)
    {
        $username = $username ?: $this->user['Username'];
        if (empty($username))
        {
            return false;
        }

        $current_values = \DB::select_array(array('i.*'))
            ->where('Username', '=', $username)
            ->from(array(\Config::get(static::$config_file .'.table_users'),'u'))
            ->join(array(\Config::get(static::$config_file .'.table_usersinfo'),'i'), 'LEFT')
            ->on('u.Id','=','i.Id')
            ->execute(\Config::get(static::$config_file .'.db_connection'))->current();

        if (empty($current_values))
        {
            return false;
        }


        return is_null($field) ? $current_values : \Arr::get($current_values, $field, $default);
    }


    /**
     * Extension of base driver method to default to user group instead of user id
     */
    public function has_access($condition, $driver = null, $user = null)
    {
        if (is_null($user))
        {
            $groups = $this->get_groups();
            $user = reset($groups);
        }
        return parent::has_access($condition, $this->config['drivers']['acl'][0], $user);
    }

    /**
     * Extension of base driver because this supports a guest login when switched on
     */
    public function guest_login()
    {
        return \Config::get(static::$config_file .'.guest_login', true);
    }



    //////////////////////////////// It's mine

    /**
     * @param null $field array(key=>value)
     * @param null $default
     * @param null $username
     * @return bool
     */
    public function update_profile(Array $field, $username = null)
    {

        try{
            $username = $username ?: $this->user['Username'];
            if (empty($username) || empty($field) || !is_array($field))
            {
                return false;
            }
            $current_values = \DB::select_array(\Config::get(static::$config_file .'.table_columns', array('*')))
                ->where('Username', '=', $username)
                ->from(\Config::get(static::$config_file .'.table_users'))
                ->execute(\Config::get(static::$config_file .'.db_connection'));

            if($current_values->count() < 1){
                return false;
            }
            $field['UpdatedAt'] = \Date::forge()->get_timestamp();
            $affected_rows = \DB::update(\Config::get(static::$config_file .'.table_usersinfo'))
                ->set($field)
                ->where('UserId', '=', $current_values->get('Id'))
                ->execute(\Config::get(static::$config_file .'.db_connection'));
        }
        catch (\Exception $e){
            logger(400,$e->getMessage(),__METHOD__);
            return false;
        }

        return $affected_rows > 0;
    }
}

// end of file simpleauth.php