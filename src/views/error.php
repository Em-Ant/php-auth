<h1><?= htmlspecialchars($error ?? 'Generic Error', ENT_QUOTES, 'UTF-8') ?> </h1>
<div>
  <img src="<?= htmlspecialchars($sub_path ?? '', ENT_QUOTES, 'UTF-8') ?>/public/error.svg" alt="error icon" />
</div>