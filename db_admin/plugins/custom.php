<?php

class CustomCredentials
{
    private array $config;

    public function __construct()
    {
        $configFile = __DIR__ . '/../config.php';
        if (!file_exists($configFile)) {
            throw new RuntimeException(
                'Adminer config not found. Copy db_admin/config.example.php to db_admin/config.php'
            );
        }
        $this->config = require $configFile;
    }

    function loginForm()
    {
        $adminer = adminer();
        echo "<table cellspacing='0' class='layout'>\n";
        echo '<input type="hidden" name="auth[driver]" value="sqlite">';
        echo '<input type="hidden" name="auth[db]" value="' . h($this->config['db_path']) . '" autocapitalize="off">' . "\n";
        echo $adminer->loginFormField('username', '<tr><th>' . lang('Username') . '<td>', '<input name="auth[username]" id="username" value="' . h($_GET["username"]) . '" autocomplete="username" autocapitalize="off">');
        echo $adminer->loginFormField('password', '<tr><th>' . lang('Password') . '<td>', '<input type="password" name="auth[password]" autocomplete="current-password">' . "\n");
        echo "</table>\n";
        echo "<p><input type='submit' value='" . lang('Login') . "'>\n";
        return true;
    }

    function navigation()
    {
        return true;
    }

    function credentials()
    {
        $username = $_GET["username"];
        $password = get_password();

        foreach ($this->config['users'] as $user) {
            if ($user['user'] === $username && $user['pass'] === $password) {
                return [SERVER, $username, ''];
            }
        }

        return [SERVER, $username, $password];
    }

    function login($login, $password)
    {
        foreach ($this->config['users'] as $user) {
            if ($user['user'] === $login && $user['pass'] === $password) {
                return true;
            }
        }
        return false;
    }
}
