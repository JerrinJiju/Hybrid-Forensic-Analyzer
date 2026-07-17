<!DOCTYPE html>
<html>
<head>
    <title>File Analyzer</title>
</head>
<body>

<h2>File Analyzer</h2>

<p>Upload a file for forensic analysis</p>

<form method="POST" enctype="multipart/form-data">
    <input type="file" name="file">
    <button type="submit">Analyze</button>
</form>

<br>
<a href="{{ url_for('dashboard') }}">Back to Dashboard</a>

</body>
</html>