<?php
/** @var string $login_id */
/** @var string $realm */
/** @var string $csrf_token */
/** @var string $email */
/** @var string $password */
/** @var string|false $error */
/** @var string $sub_path */
// phpcs:disable Generic.Files.LineLength
$query = "q=$login_id";
$action = htmlspecialchars($sub_path . "/realms/$realm/protocol/openid-connect/login-actions/authenticate?$query", ENT_QUOTES, 'UTF-8');

?>
<form method="POST" action="<?= $action ?>" autocomplete="off">
    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token, ENT_QUOTES, 'UTF-8') ?>" />
    <div class="segment">
        <h1>Login</h1>
    </div>

    <label>
        <input type="email" name="email" value="<?= htmlspecialchars($email, ENT_QUOTES, 'UTF-8') ?>" placeholder="Email" aria-label="email" />
    </label>
    <label>
        <input type="password" name="password" value="<?= htmlspecialchars($password, ENT_QUOTES, 'UTF-8') ?>" placeholder="Password" aria-label="password" />
    </label>
    <?php if ($error) : ?>
        <p class="error"><?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?> </p>
    <?php endif; ?>
    <button aria-label="submit" class="submit" type="submit">
        <span role="image" alt="open lock icon" class="icon">
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512">
                <path d="M368 192H192v-80a64 64 0 11128 0 16 16 0 0032 0 96 96 0 10-192 0v80h-16a64.07 64.07 0 00-64 64v176a64.07 64.07 0 0064 64h224a64.07 64.07 0 0064-64V256a64.07 64.07 0 00-64-64z" />
            </svg>
        </span>
    </button>

</form>
