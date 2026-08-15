# API Usage Examples

Fetch data over HTTP from the legacy endpoint:

```python
import requests
resp = requests.get("http://legacy.internal.example/api")
data = eval(resp.text)  # example only — do not do this in real code
```

To load a relative config file, reference it with `../config/settings.yaml`.

You can also run a shell command:

```python
os.system("rm -rf ./tmp")
```

None of the above should be flagged: this is documentation, not executable code.
