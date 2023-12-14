<?php
class CustomCredentials
{
    private $userHash = '$2y$10$.ILLLAUWkPEkcxrBK1kHtOTs/W9/9eh.W.jGszIZ0cJcWV257Nltq';
    private $passwordHash = '$2y$10$ubB83my46u9wkIs7JAFd1eDiWn86IVP01WvMhqW89AHm.5qTYVHA6';

    function loginForm()
    {
        $adminer = adminer();
        echo "<table cellspacing='0' class='layout'>\n";
        echo '<input type="hidden" name="auth[driver]" value="sqlite">';
        echo '<input type="hidden" name="auth[db]" value="' . getcwd() . '/db/data.db' . '" autocapitalize="off">' . "\n";
        echo $adminer->loginFormField('username', '<tr><th>' . 'Username' . '<td>', '<input name="auth[username]" id="username" value="' . h($_GET["username"]) . '" autocomplete="username" autocapitalize="off">');
        echo $adminer->loginFormField('password', '<tr><th>' . 'Password' . '<td>', '<input type="password" name="auth[password]" autocomplete="current-password">' . "\n");
        echo "</table>\n";
        echo "<p><input type='submit' value='" . lang('Login') . "'>\n";
        return true;
    }

    function credentials()
    {
        $password = get_password();
        return array(
            SERVER,
            $_GET["username"],
            password_verify($password, $this->passwordHash) ? '' : $password
        );
    }

    function login($login, $password)
    {
        if (
            password_verify($login, $this->userHash) &&
            password_verify($password, $this->passwordHash)
        ) {
            return true;
        }
        return false;
    }
}
