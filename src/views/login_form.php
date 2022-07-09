<h1>Login</h1>
<?php
$query = "q=$session_id&s=$scopes&m=$response_mode";
$action = "$sub_path/realms/$realm/protocol/openid-connect/login-actions/authenticate?$query"
?>
<form method="POST" action="<?= $action ?>">
  <label>
    email
    <input type="email" name="email" value="<?= $email ?>" />
  </label>
  <label>
    password
    <input type="password" name="password" value="<?= $password ?>" />
  </label>
  <button type="submit">Log In</button>
  <? if ($error) : ?>
    <p class="error"><?= $error ?> </p>
  <? endif; ?>
</form>