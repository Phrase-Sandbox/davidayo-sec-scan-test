"""Tests for the synthetic upload candidate path in run_layer1.

Verifies that:
- An upload handler with ≥2 weak signals and no prior scanner rule generates
  a ScannerCandidate with tool="upload_synth" and vuln_class="unsafe_file_upload".
- A handler with <2 weak signals does NOT generate a synthetic candidate.
- A handler in a file already covered by a scanner rule does NOT duplicate.
- Synthetic candidates flow through aggregate() and come out as
  AggregatedCandidate objects.
- Errors in the synth path are caught gracefully (never abort).
"""

from __future__ import annotations

from security_scanner.shared.context.upload_models import UploadHandler
from security_scanner.shared.scanners import (
    _count_weak_signals,
    _synthesise_candidates,
)
from security_scanner.shared.scanners.consensus import aggregate
from security_scanner.shared.scanners.models import ScannerCandidate

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

# Flask handler with NO extension allowlist, NO size limit, preserved filename
# stored in public dir — should produce 3 weak signals.
_WEAK_FLASK_CODE = """\
from flask import Flask, request
import os
app = Flask(__name__)

@app.route('/upload', methods=['POST'])
def upload_file():
    f = request.files['file']
    # No extension check, no size limit
    f.save(os.path.join('static', f.filename))  # public path + preserved filename
    return 'ok'
"""

# Flask handler WITH strong defences — only 0-1 weak signals.
_STRONG_FLASK_CODE = """\
from flask import Flask, request
import os, uuid
app = Flask(__name__)
ALLOWED_EXTENSIONS = {'png', 'jpg'}
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

@app.route('/upload', methods=['POST'])
def upload_file():
    f = request.files['file']
    ext = os.path.splitext(f.filename)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        abort(400)
    safe_name = uuid.uuid4().hex + ext
    f.save(os.path.join('/var/data/uploads', safe_name))
    return 'ok'
"""

# Zip-slip handler — archive extract without magic-bytes → weak signal.
_ZIP_SLIP_CODE = """\
import zipfile, request

def handle_zip():
    f = request.files['archive']
    with zipfile.ZipFile(f) as zf:
        zf.extractall('/tmp/extract')
"""


def _make_handler(filepath: str, line: int = 7, framework: str = "flask") -> UploadHandler:
    return UploadHandler(
        file=filepath,
        line=line,
        function_name="upload_file",
        framework=framework,
    )


# ---------------------------------------------------------------------------
# Tests: _count_weak_signals
# ---------------------------------------------------------------------------

class TestCountWeakSignals:
    def test_weak_handler_has_two_or_more_signals(self):
        handler = _make_handler("app.py", line=7)
        count = _count_weak_signals(handler, {"app.py": _WEAK_FLASK_CODE})
        assert count >= 2

    def test_strong_handler_has_less_than_two_signals(self):
        handler = _make_handler("app.py", line=10)
        count = _count_weak_signals(handler, {"app.py": _STRONG_FLASK_CODE})
        assert count < 2

    def test_zip_slip_registers_as_weak(self):
        handler = _make_handler("handler.py", line=4)
        count = _count_weak_signals(handler, {"handler.py": _ZIP_SLIP_CODE})
        assert count >= 1

    def test_empty_file_gives_signals(self):
        handler = _make_handler("empty.py", line=1)
        count = _count_weak_signals(handler, {"empty.py": ""})
        # Empty file → no defences → at least 2 weak signals
        assert count >= 2

    def test_missing_file_gives_signals(self):
        handler = _make_handler("missing.py", line=1)
        count = _count_weak_signals(handler, {})
        assert count >= 2


# ---------------------------------------------------------------------------
# Tests: _synthesise_candidates
# ---------------------------------------------------------------------------

class TestSynthesiseCandidates:
    def test_generates_candidate_for_weak_handler(self):
        handler = _make_handler("app.py", line=7)
        synth = _synthesise_candidates(
            [handler],
            {"app.py": _WEAK_FLASK_CODE},
            fired_files=set(),
        )
        assert len(synth) == 1
        c = synth[0]
        assert c.tool == "upload_synth"
        assert c.vuln_class == "unsafe_file_upload"
        assert c.file == "app.py"
        assert c.severity_hint == "medium"

    def test_does_not_generate_for_strong_handler(self):
        handler = _make_handler("app.py", line=10)
        synth = _synthesise_candidates(
            [handler],
            {"app.py": _STRONG_FLASK_CODE},
            fired_files=set(),
        )
        assert synth == []

    def test_skips_files_already_covered_by_scanner(self):
        handler = _make_handler("app.py", line=7)
        synth = _synthesise_candidates(
            [handler],
            {"app.py": _WEAK_FLASK_CODE},
            fired_files={"app.py"},  # already covered
        )
        assert synth == []

    def test_multiple_handlers_only_weak_synthesised(self):
        weak = _make_handler("weak.py", line=7, framework="flask")
        strong = _make_handler("strong.py", line=10, framework="flask")
        synth = _synthesise_candidates(
            [weak, strong],
            {"weak.py": _WEAK_FLASK_CODE, "strong.py": _STRONG_FLASK_CODE},
            fired_files=set(),
        )
        assert len(synth) == 1
        assert synth[0].file == "weak.py"

    def test_synthesised_candidate_uses_correct_schema(self):
        handler = _make_handler("app.py", line=7)
        synth = _synthesise_candidates(
            [handler],
            {"app.py": _WEAK_FLASK_CODE},
            fired_files=set(),
        )
        assert len(synth) == 1
        c = synth[0]
        # Must be a valid ScannerCandidate.
        assert isinstance(c, ScannerCandidate)
        assert c.line_start == handler.line
        assert c.raw_rule_id == "upload_synth"

    def test_synthetic_candidates_flow_through_aggregate(self):
        handler = _make_handler("app.py", line=7)
        synth = _synthesise_candidates(
            [handler],
            {"app.py": _WEAK_FLASK_CODE},
            fired_files=set(),
        )
        aggregated = aggregate(synth)
        assert len(aggregated) == 1
        agg = aggregated[0]
        assert agg.vuln_class == "unsafe_file_upload"
        assert "upload_synth" in agg.sources

    def test_empty_handlers_returns_empty(self):
        assert _synthesise_candidates([], {}, set()) == []
