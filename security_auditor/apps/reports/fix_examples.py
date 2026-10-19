"""Concrete, copy-pasteable remediation guidance per finding family.

For every finding the report should say *exactly* what to fix.  This module
maps finding titles (substring match, engine-agnostic) to a concrete
before/after code pair so developers get an actionable patch, not generic
advice.  All "before" snippets are illustrative; the actual vulnerable line
is shown from the finding's masked evidence snippet.
"""
from __future__ import annotations

from typing import Optional

# order matters: first match wins, most specific first
FIX_TABLE: list[tuple[tuple[str, ...], str, str, str]] = [
    # (title keywords, problem, before, after)
    (("Hardcoded Django SECRET_KEY", "Insecure Django setting: SECRET_KEY"),
     "The Django SECRET_KEY is committed in source. Anyone with repo access can "
     "forge sessions, password-reset tokens and signed URLs.",
     'SECRET_KEY = "django-insecure-xxxxxx..."   # settings.py',
     'import os\n'
     'SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]   # fail fast if missing\n'
     '# generate one:  python -c "from django.core.management.utils import '
     'get_random_secret_key; print(get_random_secret_key())"\n'
     '# store it in the environment / a secret manager, never in git. '
     'Rotate it now - the old value is compromised.'),

    (("Insecure Django setting: DEBUG",),
     "DEBUG is enabled outside a clearly-safe dev profile. A deployed DEBUG "
     "leaks settings, environment variables and tracebacks with secrets.",
     "DEBUG = True",
     'DEBUG = os.environ.get("DJANGO_DEBUG", "false").lower() == "true"\n'
     'ALLOWED_HOSTS = [h for h in os.environ.get("DJANGO_ALLOWED_HOSTS", "").split(",") if h]'),

    (("eval/exec/compile", "Dynamic code execution"),
     "User-controlled data reaches eval()/exec() - direct remote code execution.",
     'result = eval(request.GET.get("expr"))',
     "# Remove eval/exec entirely.\n"
     "# If you must evaluate user expressions, parse them safely:\n"
     "import ast\n"
     'value = ast.literal_eval(request.GET.get("expr"))   # literals only\n'
     "# or a dedicated parser (e.g. simpleeval with an explicit allow-list)."),

    (("Dynamic SQL",),
     "SQL is built by string formatting with user data - SQL injection.",
     'cursor.execute("SELECT * FROM t WHERE name = \'%s\'" % request.GET["q"])',
     'cursor.execute("SELECT * FROM t WHERE name = %s", [request.GET["q"]])\n'
     "# Prefer the ORM:  Model.objects.filter(name=request.GET[\"q\"])"),

    (("os.system/os.popen", "Shell command execution"),
     "os.system()/os.popen() with dynamic input allows command injection.",
     'os.system("ping " + host)',
     'import subprocess\n'
     'subprocess.run(["ping", "-c", "1", host], check=True)\n'
     "# argument list form - no shell interpretation; validate `host` against an allow-list"),

    (("shell=True",),
     "subprocess with shell=True passes the command line to a shell - "
     "metacharacters in user data become commands.",
     'subprocess.run(f"convert {path} out.png", shell=True)',
     'subprocess.run(["convert", path, "out.png"], check=True)\n'
     "# drop shell=True; pass an argument list and validate/quote each part"),

    (("mark_safe",),
     "mark_safe() on dynamic content disables escaping - stored/reflected XSS.",
     "return mark_safe(user_content)",
     "from django.utils.html import format_html, escape\n"
     'return format_html("<b>{}</b>", user_content)   # escapes automatically\n'
     "# or escape(user_content) when building strings manually"),

    (("|safe filter", "autoescape disabled"),
     "Template autoescaping is disabled, rendering raw HTML - XSS.",
     "{{ user_content|safe }}  /  {% autoescape off %}",
     "{{ user_content }}                       # escaped by default\n"
     "# if you must render trusted rich text, sanitise first (bleach/bleach-allowlist)"),

    (("Mass assignment",),
     "**request.data is expanded straight into the ORM - attackers set any "
     "model field (is_staff, price, owner_id...).",
     "User.objects.create(**request.data)",
     "# Use a DRF serializer with an explicit field whitelist:\n"
     "class UserSerializer(serializers.ModelSerializer):\n"
     "    class Meta:\n"
     "        model = User\n"
     '        fields = ["username", "email"]   # only assignable fields\n'
     'ser = UserSerializer(data=request.data); ser.is_valid(raise_exception=True)'),

    (("AllowAny", "Empty permission_classes"),
     "The API view explicitly allows anonymous access - endpoints that should "
     "require authentication are open to anyone.",
     "permission_classes = [AllowAny]",
     "from rest_framework.permissions import IsAuthenticated\n"
     "permission_classes = [IsAuthenticated]\n"
     "# and set a restrictive default in settings:\n"
     'REST_FRAMEWORK = {"DEFAULT_PERMISSION_CLASSES": '
     '["rest_framework.permissions.IsAuthenticated"]}\n'
     "# add object-level checks (get_object -> obj.owner == request.user)"),

    (("Empty authentication_classes",),
     "Authentication classes are emptied, so no user is ever authenticated on "
     "this view - permission checks become meaningless.",
     "authentication_classes = []",
     'authentication_classes = [JWTAuthentication]   # or SessionAuthentication\n'
     "# set a safe DEFAULT_AUTHENTICATION_CLASSES globally instead"),

    (("Pickle",),
     "pickle.loads on untrusted data executes arbitrary code on deserialization.",
     "obj = pickle.loads(request.body)",
     "import json\n"
     "obj = json.loads(request.body)\n"
     "# if you must exchange complex objects: signed tokens (itsdangerous) "
     "or a safe format with schema validation"),

    (("Unsafe YAML",),
     "yaml.load() without SafeLoader instantiates arbitrary Python objects - RCE.",
     "data = yaml.load(raw)",
     "data = yaml.safe_load(raw)"),

    (("Server-side request", "SSRF"),
     "The server fetches a user-supplied URL - SSRF against internal services.",
     'resp = requests.get(request.GET["url"])',
     "# Allow-list scheme + hosts, block private ranges:\n"
     "from urllib.parse import urlparse\n"
     "u = urlparse(url)\n"
     'assert u.scheme in ("https",) and u.hostname in TRUSTED_HOSTS and '
     'not ipaddress.ip_address(socket.gethostbyname(u.hostname)).is_private\n'
     "resp = requests.get(u.geturl(), timeout=5)"),

    (("Redirect to dynamic",),
     "Open redirect: the target URL comes from user input without validation.",
     'return redirect(request.GET["next"])',
     "from django.utils.http import url_has_allowed_host_and_scheme\n"
     "next_url = request.GET.get(\"next\", \"/\")\n"
     'if not url_has_allowed_host_and_scheme(next_url, allowed_hosts={request.get_host()}):\n'
     '    next_url = "/"\n'
     "return redirect(next_url)"),

    (("Dynamic file serving", "Path traversal"),
     "File paths derived from user input are opened directly - path traversal "
     "can read /etc/passwd, settings, keys.",
     'return FileResponse(open(base + request.GET["file"], "rb"))',
     "import os\n"
     "root = os.path.realpath(BASE_DIR)\n"
     "target = os.path.realpath(os.path.join(root, request.GET[\"file\"]))\n"
     "if not target.startswith(root + os.sep): raise Http404()\n"
     "# better: serve by id -> whitelist of allowed files stored in DB"),

    (("Weak hash",),
     "MD5/SHA1 used (often for passwords) - broken, fast to brute-force.",
     'digest = hashlib.md5(password.encode()).hexdigest()',
     "from django.contrib.auth.hashers import make_password, check_password\n"
     "stored = make_password(password)     # PBKDF2/Argon2, salted\n"
     "# or hashlib.scrypt(password, salt=salt, n=2**14, r=8, p=1)"),

    (("mktemp",),
     "tempfile.mktemp() is predictable/race-prone - symlink attacks.",
     "f = tempfile.mktemp()",
     "fd, path = tempfile.mkstemp()     # or tempfile.NamedTemporaryFile(delete=False)"),

    (("CSRF exemption",),
     "@csrf_exempt on a state-changing view lets forged cross-site requests "
     "execute as the logged-in user.",
     "@csrf_exempt\n"
     "def transfer(request): ...",
     "# remove @csrf_exempt; keep CsrfViewMiddleware enabled and ensure the "
     "form/AJAX sends the CSRF token ({{ csrf_token }} / X-CSRFToken header)"),

    (("Sensitive field exposed",),
     "The serializer exposes a sensitive model field (password/secret/PII) in "
     "API responses.",
     "class Meta:\n    model = User\n    fields = \"__all__\"",
     "class Meta:\n    model = User\n"
     '    fields = ["id", "username", "email"]\n'
     '    extra_kwargs = {"password": {"write_only": True}}'),

    (("Stripe", "credential", "AWS access key", "GitHub token", "private key"),
     "A live-format credential is hardcoded in the repository.",
     'API_KEY = "sk_live_..."',
     'API_KEY = os.environ["PAYMENT_API_KEY"]\n'
     "# load from environment/secret manager; rotate the leaked credential "
     "immediately and purge it from git history (git filter-repo)"),

    (("PostgreSQL port", "Redis port", "MySQL port", "reachable on"),
     "A database/broker port is reachable on the scanned host. If that host is "
     "not meant to expose it, any local process (or the network, if bound "
     "beyond loopback) can connect.",
     "# postgres listening on 0.0.0.0:5432, trust auth",
     "# bind to loopback only:  listen_addresses = 'localhost'  (postgresql.conf)\n"
     "# redis:  bind 127.0.0.1 + requirepass + protected-mode yes\n"
     "# enforce password/SCRAM auth and, if the host is remote-reachable, a firewall rule"),

    (("Server-side template injection",),
     "User input reaches template rendering (Template()/SSTI) - code execution.",
     'render(request, Template(user_tpl))',
     "# never compile user-supplied templates; use fixed templates with "
     "context variables: render(request, 'fixed.html', {'v': user_value})"),

    (("XXE",),
     "XML parsed with entity expansion enabled - XXE / SSRF / file read.",
     "xml.etree.ElementTree.fromstring(raw)",
     "import defusedxml.ElementTree as ET\n"
     "root = ET.fromstring(raw)"),

    (("upload", "Upload"),
     "Uploaded files accepted without validation - executable/webshell upload.",
     "open(dest, 'wb').write(request.FILES['f'].read())",
     "# validate extension + MIME + size against an allow-list, store outside "
     "the web root with random names, never execute; scan AV if sensitive"),
]

GENERIC_FALLBACK = (
    "Review the flagged code against the requirement's remediation note and the "
    "mapped CWE; fix the root cause, add a regression test, and re-run "
    "`security-audit retest` to confirm the finding disappears.")


def fix_for(finding: dict) -> dict:
    """Return {problem, before, after} for a finding dict, by title matching."""
    title = (finding.get("title") or "").lower()
    for keywords, problem, before, after in FIX_TABLE:
        if any(k.lower() in title for k in keywords):
            return {"problem": problem, "before": before, "after": after}
    return {"problem": "", "before": "", "after": GENERIC_FALLBACK}
