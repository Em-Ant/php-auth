<h1>Login</h1>
<?php $query = "?q=$session_id&s=$scopes" ?>
<form method="POST" action="login-actions/authenticate<?php echo $query ?>">
  <label>
    email
    <input type="email" name="email" />
  </label>
  <label>
    password
    <input type="password" name="password" />
  </label>
  <button type="submit">Log In</button>
</form>