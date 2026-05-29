# Harbor SBOM License Reporter

A lightweight Python script for collecting SBOM-based package and license data
from container images stored in Harbor.

The script reads image references from text files, resolves the matching Harbor
artifacts, retrieves available SBOMs, and writes JSON/CSV reports for compliance
and auditing workflows.

## Overview

This tool performs the following steps:

1. Scans image definition files, for example `images_*.txt`
2. Extracts and deduplicates container image references
3. Resolves artifacts through the Harbor API
4. Retrieves SBOMs for available images
5. Extracts package and license data
6. Generates structured reports
7. Optionally downloads relevant SPDX license texts

## Project Structure

```text
.
├── harbor_sbom_report.py
├── image_files/
│   ├── README.md
│   └── images_example.txt
├── requirements.txt
└── README.md
```

`image_files/` contains only neutral example input files. Put your real image
lists in that directory locally, or pass a separate directory with
`--image-dir`. Generated reports are written to `out/` by default and are not
intended to be committed.

## Input Files

By default, the script scans files in `image_files/` whose names start with:

```text
images_
```

Each non-empty, non-comment line should contain one image reference:

```text
harbor.example.com/project/repository:tag
```

Use [image_files/images_example.txt](image_files/images_example.txt) as a
template and replace the example references with images that exist in your
Harbor instance.

## Outputs

Each run creates a timestamped directory:

```text
out/YYYYMMDD_HHMMSS/
```

The output directory contains:

| File or directory | Description |
| --- | --- |
| `missing_harbor_artifacts.json` | Images that could not be resolved in Harbor |
| `package_licenses.csv` | Full package/license rows extracted from SBOMs |
| `package_licenses_minimal.csv` | Deduplicated package, version, and license view |
| `run_summary.json` | Machine-readable run summary |
| `licenses/` | Downloaded SPDX license texts, unless disabled |

## Installation

Requirements:

- Python 3.10+
- Harbor API access

Install dependencies:

```bash
pip install -r requirements.txt
```

## Configuration

Create a local `.env` file in the project root:

```env
HARBOR_API_BASE_URL=https://harbor.example.com/api/v2.0
HARBOR_USERNAME=your-username
HARBOR_PASSWORD=your-password
```

Do not commit `.env` or real image lists. They may contain credentials,
internal registry names, product names, or other private operational details.

## Usage

Default run:

```bash
python harbor_sbom_report.py
```

Custom options:

```bash
python harbor_sbom_report.py \
  --image-dir ./image_files \
  --output-dir ./out \
  --verbose
```

Skip downloading license text files:

```bash
python harbor_sbom_report.py --no-license-files
```

## CLI Options

| Option | Description |
| --- | --- |
| `--image-dir` | Directory containing image definition files |
| `--prefix` | File prefix, default: `images_` |
| `--output-dir` | Base output directory |
| `--request-timeout` | HTTP timeout in seconds |
| `--max-retries` | Retry attempts for transient Harbor API failures |
| `--backoff-factor` | Retry backoff factor |
| `--no-license-files` | Do not download SPDX license text files |
| `--quiet` | Only log warnings and errors |
| `--verbose` | Enable debug logging |

## Exit Codes

| Code | Meaning |
| --- | --- |
| `0` | Success |
| `2` | Configuration error, for example missing env vars |
| `3` | Input error, for example invalid files or image references |
| `4` | Runtime error |
| `5` | Partial success, for example missing artifacts or SBOM failures |

## Notes

- Duplicate image references are automatically removed.
- Missing artifacts do not fail the whole run, but they are reported.
- SBOM retrieval failures are tracked separately.
- `.gitignore` excludes local credentials, generated reports, and private
  image input files by default.

## Example Output

```text
out/
└── 20260414_134731/
    ├── licenses/
    ├── missing_harbor_artifacts.json
    ├── package_licenses.csv
    ├── package_licenses_minimal.csv
    └── run_summary.json
```
