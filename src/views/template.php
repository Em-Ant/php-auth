<!DOCTYPE html>
<html>

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
  <div class="footer">
    <p>
      by <a href="http://www.emant.altervista.org">em-ant</a> |
      <a href="https://github.com/Em-Ant">github</a> |
      <a href="http://codepen.io/Em-Ant/">codepen</a> |
      <a href="http://www.freecodecamp.com/em-ant">freeCodeCamp</a>
      <?php
      if ($view_code) echo " | <a href=\"$base_url\">&lt;&lt; index</a>";
      ?>
    </p>
  </div>
</body>

</html>