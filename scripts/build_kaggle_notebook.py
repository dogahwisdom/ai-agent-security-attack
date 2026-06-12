#!/usr/bin/env python3
"""Generate a compact Kaggle notebook matching the official getting-started layout."""

from __future__ import annotations

import base64
import json
from pathlib import Path


def _bundle_files(root: Path) -> dict[str, bytes]:
    files: dict[str, bytes] = {
        root.joinpath("attack.py").name: root.joinpath("attack.py").read_bytes()
    }
    for source in sorted((root / "src/agent_security").rglob("*.py")):
        relative = source.relative_to(root / "src/agent_security").as_posix()
        files[f"agent_security/{relative}"] = source.read_bytes()
    return files


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    bundle = _bundle_files(root)
    payload = base64.b64encode(
        json.dumps({k: base64.b64encode(v).decode() for k, v in bundle.items()}).encode()
    ).decode()

    deploy_cell = f'''import base64
import json
from pathlib import Path

bundle = json.loads(base64.b64decode("{payload}").decode())
working = Path("/kaggle/working")
for relative, content_b64 in bundle.items():
    path = working / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(base64.b64decode(content_b64))

attack = working / "attack.py"
if not attack.exists():
    raise FileNotFoundError("attack.py was not written to /kaggle/working")

print("attack.py written", attack.stat().st_size, "bytes")

# Competition submit expects submission.csv in notebook output (scores filled on hidden rerun).
submission = working / "submission.csv"
if not submission.exists():
    submission.write_text("Id,Score\\nwarmup,0.0\\n")
print("submission.csv written", submission.stat().st_size, "bytes")
'''

    notebook = {
        "cells": [
            {
                "cell_type": "markdown",
                "metadata": {},
                "source": [
                    "# JED Attack Submission\n",
                    "\n",
                    "Multi-step red-team attack via `MultiStepExplorer` — a modular Go-Explore pipeline "
                    "for reproducible tool-use failures in agent environments.\n",
                ],
            },
            {
                "cell_type": "code",
                "metadata": {},
                "source": [
                    "import glob\n",
                    "import sys\n",
                    "from pathlib import Path\n",
                    "\n",
                    "sys.argv = [sys.argv[0]]\n",
                    "\n",
                    "for candidate in glob.glob('/kaggle/input/**/kaggle_evaluation', recursive=True):\n",
                    "    dataset_root = str(Path(candidate).parent)\n",
                    "    if dataset_root not in sys.path:\n",
                    "        sys.path.insert(0, dataset_root)\n",
                    "    print('Dataset root:', dataset_root)\n",
                    "    break\n",
                    "else:\n",
                    "    raise RuntimeError('Attach competition data first.')\n",
                    "\n",
                    "sys.path.insert(0, '/kaggle/working')\n",
                    "print('Setup complete')\n",
                ],
                "outputs": [],
                "execution_count": None,
            },
            {
                "cell_type": "code",
                "metadata": {},
                "source": deploy_cell.splitlines(keepends=True),
                "outputs": [],
                "execution_count": None,
            },
            {
                "cell_type": "code",
                "metadata": {},
                "source": [
                    "import kaggle_evaluation.jed_attack_134815.jed_attack_inference_server as server\n",
                    "\n",
                    "server.JEDAttackInferenceServer().serve()\n",
                ],
                "outputs": [],
                "execution_count": None,
            },
        ],
        "metadata": {
            "kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
            "language_info": {"name": "python"},
        },
        "nbformat": 4,
        "nbformat_minor": 5,
    }

    out = root / "kaggle_kernel" / "jed-attack-submission.ipynb"
    out.write_text(json.dumps(notebook, indent=1))
    print(f"Built {out} ({len(bundle)} files bundled)")


if __name__ == "__main__":
    main()
