<?php

/** @var string $error */ /** @var string $sub_path */ ?>
<h1><?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?> </h1>
<div>
  <img src="<?= htmlspecialchars($sub_path, ENT_QUOTES, 'UTF-8') ?>/error.svg" alt="error icon" />
</div>