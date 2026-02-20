    <?php
        if (isset($_FILES["image"])){
            $filename = $_FILES["image"]["tmp_name"][0];
            $handle = fopen($filename, "rb");
            $content = fread($handle, filesize($filename));

            // Check this is a valid JPEG and not a PHP file
            if (
                   (strpos($_FILES["image"]["name"][0],".jpg") || strpos($_FILES["image"]["name"][0],".jpeg"))
                && strcmp(substr($content, 0, 2), hex2bin('ffd8')) === 0
                && strpos($content, hex2bin('ffd9'))
            ){
                $name = basename($filename);
                move_uploaded_file($filename, __DIR__ . '/uploads/' . $name . '.jpg');
                echo '<p style="color:forestgreen;">This is a valid JPEG! You can <a href="./uploads/' . $name . '.jpg">go see it here</a>.</p>';
            } else {
                echo '<p style="color:red;">This is a fake JPEG!</p>';
            }
        } elseif (isset($_POST["phar"])){
            $pharFile = $_POST["phar"];
            if (@include("phar://" . $pharFile)) {
                echo '<p style="color:forestgreen;">PHAR file executed successfully!</p>';
            } else {
                echo '<p style="color:red;">Error when including PHAR file "' . htmlspecialchars($pharFile) . '": ' . error_get_last()["message"] . '</p>';
            }
        }
        
        if (isset($_GET["page"]) && $_GET["page"] = "admin"){
    ?>
        <p>This is the admin interface where I can execute PHAR files to update my site.<br/>
        You can't use it anyway because you don't know where the PHAR files are located</p>
        <form method="POST">
            <p>
                <label for="phar">Path to the PHAR file:</label><br/>
                <input name="phar" type="text">
            </p>
            <p><input type="submit" value="Execute"></p>
        </form>
    <?php
        } else {
    ?>
        <p>I collect pictures from all around the world! Please send me yours too! <b>(JPEG only!)</b></p>
        <form enctype="multipart/form-data" method="POST">
            <p>
                <label for="image">Your picture: </label><br/>
                <input name="image[]" type="file" accept="image/jpeg">
            </p>
            <p><input type="submit" value="Submit"></p>
        </form>
    <?php 
        }
    ?>