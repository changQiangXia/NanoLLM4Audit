param(
  [string]$PythonExe = "python"
)

$env:PYTHONPATH = "$PWD\src"
& $PythonExe -m nanoaudit.cli --config configs/default.toml run --rebuild-data
& $PythonExe scripts/check_outputs.py
