

<?php
function adminer_object()
{
    // required to run any plugin
    include_once "plugins/plugin.php";
    include_once "plugins/custom.php";


    // enable extra drivers just by including them
    //~ include "./plugins/drivers/simpledb.php";

    $plugins = array(
        new CustomCredentials()
        // specify enabled plugins here
    );

    /* It is possible to combine customization and plugins:
    class AdminerCustomization extends AdminerPlugin {
    }
    return new AdminerCustomization($plugins);
    */

    return new AdminerPlugin($plugins);
}

// include original Adminer or Adminer Editor
include("adminer.php");
?>