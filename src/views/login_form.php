<h1>Login</h1>
<form method="POST" action="login-actions/authenticate?q=<?php echo $session_id; ?>">
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