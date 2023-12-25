<?php
// phpcs:disable Generic.Files.LineLength
if (!(isset($login_id) && isset($realm))) {
    throw new \RuntimeException('login form: missing required parameters');
}

$query = "q=$login_id";
$action = ($sub_path ?? '') . "/realms/$realm/protocol/openid-connect/login-actions/authenticate?$query";

?>
<form method="POST" action="<?= $action ?>" autocomplete="off">
    <div class="segment">
        <h1>Login</h1>
    </div>

    <label>
        <input type="email" name="email" value="<?= $email ?? '' ?>" placeholder="Email" aria-label="email" />
    </label>
    <label>
        <input type="password" name="password" value="<?= $password ?? '' ?>" placeholder="Password" aria-label="password" />
    </label>
    <?php if (isset($error) && $error) : ?>
        <p class="error"><?= $error ?> </p>
    <?php endif; ?>
    <button aria-label="submit" class="submit" type="submit">
        <span role="image" alt="open lock icon" class="icon">
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512">
                <path d="M368 192H192v-80a64 64 0 11128 0 16 16 0 0032 0 96 96 0 10-192 0v80h-16a64.07 64.07 0 00-64 64v176a64.07 64.07 0 0064 64h224a64.07 64.07 0 0064-64V256a64.07 64.07 0 00-64-64z" />
            </svg>
        </span>
    </button>

</form>