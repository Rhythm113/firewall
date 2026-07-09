#!/usr/bin/env python3
import cgi
import os
import sys

# Enable traceback debugging for testing
import cgitb
cgitb.enable()

UPLOAD_DIR = "/var/www/uploads"

print("Content-Type: text/html")
print()

print("""
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
        <h1>Nullsploit Sandbox Target Portal</h1>
        <p>This server has a known arbitrary file upload vulnerability. Uploading a webshell will trigger the async YARA engine scan.</p>
        <form action="/cgi-bin/upload.py" method="post" enctype="multipart/form-data">
            <input type="file" name="file_upload">
            <input type="submit" value="Upload to /var/www/uploads/">
        </form>
""")

# Process upload if POST
if os.environ.get("REQUEST_METHOD") == "POST":
    form = cgi.FieldStorage()
    
    if "file_upload" in form:
        fileitem = form["file_upload"]
        
        # Test if the file was uploaded
        if fileitem.filename:
            # strip leading path for security, but save with raw user-supplied extension (vulnerable!)
            fn = os.path.basename(fileitem.filename)
            
            # Ensure upload dir exists
            os.makedirs(UPLOAD_DIR, exist_ok=True)
            
            filepath = os.path.join(UPLOAD_DIR, fn)
            with open(filepath, 'wb') as f:
                f.write(fileitem.file.read())
                
            print(f"<p style='color: #00e676;'>Success! File saved to {filepath}</p>")
        else:
            print("<p style='color: #ff2d55;'>Error: No file uploaded</p>")
    else:
        print("<p style='color: #ff2d55;'>Error: Missing form field 'file_upload'</p>")

print("""
    </div>
</body>
</html>
""")
