<?php
$sub_path = $GLOBALS['sub_path'] ?: '';
$title = $title ?: 'Auth';
?>

<!DOCTYPE html>
<html lang="en">

<head>
  <title><?= $title ?></title>
  <link rel="shortcut icon" href="<?= $sub_path ?>/public/favicon.ico" type="image/x-icon" />
  <link href="https://fonts.googleapis.com/css?family=Roboto" rel="stylesheet" type="text/css">
  <link href="<?= $sub_path ?>/public/style.css" rel="stylesheet" type="text/css">
</head>

<body>
  <?php
  include $view;
  ?>
</body>

</html>