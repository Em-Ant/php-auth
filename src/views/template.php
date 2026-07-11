<?php
$sub_path = $GLOBALS['sub_path'] ?: '';
$title = htmlspecialchars($title ?? 'Auth', ENT_QUOTES, 'UTF-8');
$sp = htmlspecialchars($sub_path, ENT_QUOTES, 'UTF-8');
?>

<!DOCTYPE html>
<html lang="en">

<head>
  <title><?= $title ?></title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="shortcut icon" href="<?= $sp ?>/public/favicon.ico" type="image/x-icon" />
  <link href="https://fonts.googleapis.com/css?family=Roboto" rel="stylesheet" type="text/css">
  <link href="<?= $sp ?>/public/style.css" rel="stylesheet" type="text/css">
</head>

<body>
  <?php
    if (isset($view)) {
        include $view;
    }
    ?>
</body>

</html>