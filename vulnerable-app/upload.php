<?php
$upload_dir = getenv('UPLOAD_DIR') ?: '/var/www/uploads';
if (!is_dir($upload_dir)) {
    mkdir($upload_dir, 0777, true);
}

$message = "";
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_FILES['file_upload'])) {
        $file = $_FILES['file_upload'];
        if ($file['error'] === UPLOAD_ERR_OK) {
            $filename = basename($file['name']);
            $target_file = $upload_dir . '/' . $filename;
            if (move_uploaded_file($file['tmp_name'], $target_file)) {
                $message = "<p style='color: #00e676;'>Success! File saved to " . htmlspecialchars($target_file) . "</p>";
            } else {
                $message = "<p style='color: #ff2d55;'>Error moving uploaded file.</p>";
            }
        } else {
            $message = "<p style='color: #ff2d55;'>Upload error code: " . $file['error'] . "</p>";
        }
    } else {
        $message = "<p style='color: #ff2d55;'>Missing file upload field.</p>";
    }
}
?>
<!DOCTYPE html>
<html>
<head>
    <title>Nullsploit Testing - Vulnerable Upload Portal</title>
    <style>
        body { background: #0b0f19; color: #f3f4f6; font-family: sans-serif; text-align: center; padding: 50px; }
        .card { background: #141b2e; padding: 40px; border-radius: 12px; display: inline-block; border: 1px solid #1f2937; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }
        h1 { color: #00d4ff; }
        input[type=file] { margin: 20px 0; display: block; width: 100%; }
        input[type=submit] { background: #00d4ff; color: #0b0f19; border: none; padding: 10px 20px; border-radius: 6px; cursor: pointer; font-weight: bold; }
    </style>
</head>
<body>
    <div class="card">
        <h1>Nullsploit PHP Target Portal</h1>
        <p>This server runs PHP via PHP-FPM and is vulnerable to arbitrary file uploads.</p>
        <form action="/upload.php" method="post" enctype="multipart/form-data">
            <input type="file" name="file_upload">
            <input type="submit" value="Upload to <?php echo htmlspecialchars($upload_dir); ?>">
        </form>
        <?php echo $message; ?>
    </div>
</body>
</html>
