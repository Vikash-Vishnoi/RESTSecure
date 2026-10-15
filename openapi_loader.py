"""
openapi_loader.py - Turn an OpenAPI 3.x / Swagger 2.0 spec into RESTSecure endpoints.

REST only: reads the "paths" section and nothing else (no GraphQL, no SOAP).
Output format matches what the test modules already use: a list of dicts
with a 'path' key. Extra keys are safe because modules read ep.get('path').

Usage:
    endpoints = load_openapi("openapi.json")                 # local file
    endpoints = load_openapi("https://api.example.com/openapi.json")
"""

import json
import re
from urllib.parse import urlparse

HTTP_METHODS = ("get", "post", "put", "patch", "delete", "head", "options")


def _read_spec(source):
    """Return the spec as a dict from a file path or URL (JSON, or YAML if PyYAML is installed)."""
    if re.match(r"^https?://", source, re.I):
        import requests
        resp = requests.get(source, timeout=10)
        resp.raise_for_status()
        text = resp.text
    else:
        with open(source, "r", encoding="utf-8") as f:
            text = f.read()

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        try:
            import yaml  # optional dependency, only needed for .yaml specs
        except ImportError:
            raise ValueError(
                "Spec is not valid JSON. For YAML specs run: pip install pyyaml"
            )
        return yaml.safe_load(text)


def _resolve_ref(spec, obj):
    """Follow a local $ref like '#/components/parameters/UserId'."""
    seen = 0
    while isinstance(obj, dict) and "$ref" in obj and seen < 10:
        ref = obj["$ref"]
        if not ref.startswith("#/"):
            return {}
        node = spec
        for part in ref[2:].split("/"):
            node = (
                node.get(part.replace("~1", "/").replace("~0", "~"), {})
                if isinstance(node, dict)
                else {}
            )
        obj = node
        seen += 1
    return obj if isinstance(obj, dict) else {}


def _sample_value(spec, param):
    """Pick a realistic sample value for a parameter so paths look like real requests."""
    # Swagger 2.0 keeps type on the param itself; OpenAPI 3 wraps it in 'schema'
    schema = _resolve_ref(spec, param.get("schema", param))
    if "example" in param:
        return str(param["example"])
    if "example" in schema:
        return str(schema["example"])
    if "default" in schema:
        return str(schema["default"])
    if schema.get("enum"):
        return str(schema["enum"][0])

    ptype = schema.get("type", "string")
    fmt = schema.get("format", "")
    if ptype in ("integer", "number"):
        return "1"
    if ptype == "boolean":
        return "true"
    if fmt == "uuid":
        return "123e4567-e89b-12d3-a456-426614174000"
    return "test"


def _base_path(spec):
    """Path prefix from servers[0].url (OpenAPI 3) or basePath (Swagger 2)."""
    if spec.get("servers"):
        return urlparse(spec["servers"][0].get("url", "")).path.rstrip("/")
    return (spec.get("basePath") or "").rstrip("/")


def load_openapi(source):
    """
    Parse an OpenAPI 3.x or Swagger 2.0 spec and return RESTSecure endpoints.

    Each entry is a dict with at minimum:
        {
          "path":         "/api/v1/users/1",          # path params filled with sample values
          "template":     "/api/v1/users/{id}",        # original spec path (for BOLA tests)
          "methods":      ["GET", "PUT", "DELETE"],    # all HTTP methods defined on this path
          "method":       "GET",                       # primary method (first in spec order)
          "auth_required": True,                       # False if the spec marks it public
        }

    Args:
        source: Local file path or HTTP(S) URL to the spec.

    Returns:
        List of endpoint dicts, deduplicated by concrete path.

    Raises:
        ValueError: If the file is not a recognisable OpenAPI/Swagger spec.
        FileNotFoundError: If a local path does not exist.
        requests.HTTPError: If a remote URL returns an error status.
    """
    spec = _read_spec(source)
    if "paths" not in spec:
        raise ValueError("Not an OpenAPI/Swagger spec: no 'paths' section found")

    base = _base_path(spec)
    global_security = spec.get("security")
    endpoints = {}  # keyed by concrete path to deduplicate

    for template, item in spec["paths"].items():
        item = _resolve_ref(spec, item)
        path_level_params = item.get("parameters", [])

        for method in HTTP_METHODS:
            op = item.get(method)
            if not isinstance(op, dict):
                continue

            # Merge path-level and operation-level parameters (operation wins on name clash)
            resolved_path_params = [_resolve_ref(spec, p) for p in path_level_params]
            resolved_op_params = [_resolve_ref(spec, p) for p in op.get("parameters", [])]
            op_param_names = {p.get("name") for p in resolved_op_params}
            params = [p for p in resolved_path_params if p.get("name") not in op_param_names]
            params += resolved_op_params

            # Fill in path parameters with sample values
            concrete = template
            for p in params:
                if p.get("in") == "path":
                    concrete = concrete.replace(
                        "{" + p["name"] + "}", _sample_value(spec, p)
                    )
            # Any path param the spec forgot to declare still gets a default value
            concrete = re.sub(r"\{[^}]+\}", "1", concrete)

            # Append required query parameters so modules that parse the path still work
            query = [
                f"{p['name']}={_sample_value(spec, p)}"
                for p in params
                if p.get("in") == "query" and p.get("required")
            ]
            full_path = base + concrete + ("?" + "&".join(query) if query else "")

            # security: [] on an operation explicitly marks it public;
            # otherwise inherit global_security (None → treat as unknown → True for safety)
            op_security = op.get("security", global_security)
            auth_required = bool(op_security)

            entry = endpoints.setdefault(
                full_path,
                {
                    "path": full_path,
                    "template": base + template,
                    "methods": [],
                    "method": method.upper(),   # primary method
                    "auth_required": auth_required,
                },
            )
            entry["methods"].append(method.upper())
            # If any operation on this path requires auth, mark the whole path as auth_required
            entry["auth_required"] = entry["auth_required"] or auth_required

    return list(endpoints.values())


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python3 openapi_loader.py <spec file or URL>")
        sys.exit(1)

    for ep in load_openapi(sys.argv[1]):
        lock = "AUTH  " if ep["auth_required"] else "PUBLIC"
        methods = ",".join(ep["methods"])
        print(f"{lock}  {methods:<20}  {ep['path']}")
