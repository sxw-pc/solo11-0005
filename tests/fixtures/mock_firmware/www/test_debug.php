<?php
// Artificial debug page used only by the offline test fixture.
define('DEBUG_TEST', true);
if (isset($_GET['debug'])) {
    phpinfo();
}
?>
