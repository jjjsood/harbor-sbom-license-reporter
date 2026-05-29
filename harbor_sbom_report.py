from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import re
import sys
from dataclasses import dataclass, replace
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set
from urllib.parse import quote

import requests
from dotenv import load_dotenv
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


load_dotenv()


EXIT_OK = 0
EXIT_CONFIG_ERROR = 2
EXIT_INPUT_ERROR = 3
EXIT_RUNTIME_ERROR = 4
EXIT_PARTIAL_SUCCESS = 5


LOGGER = logging.getLogger("harbor_sbom_report")

SPDX_LICENSE_TEXT_BASE_URL = "https://raw.githubusercontent.com/spdx/license-list-data/main/text"
LICENSE_DOWNLOAD_FILENAME = "LICENSE.txt"

RELEVANT_LICENSE_IDS: Set[str] = {
    "Apache-1.1",
    "Apache-2.0",
    "MIT",
    "ISC",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "BSD-4-Clause",
    "0BSD",
    "MPL-1.1",
    "MPL-2.0",
    "EPL-1.0",
    "EPL-2.0",
    "CDDL-1.0",
    "CDDL-1.1",
    "Zlib",
    "Python-2.0",
    "PSF-2.0",
    "Unicode-DFS-2015",
    "Unicode-DFS-2016",
    "OpenSSL",
    "BSL-1.0",
    "Artistic-2.0",
    "LGPL-2.1-only",
    "LGPL-2.1-or-later",
    "LGPL-3.0-only",
    "LGPL-3.0-or-later",
    "GPL-2.0-only",
    "GPL-2.0-or-later",
    "GPL-3.0-only",
    "GPL-3.0-or-later",
    "AGPL-3.0-only",
    "AGPL-3.0-or-later",
}

LICENSE_EXPRESSION_OPERATOR_PATTERN = re.compile(
    r"\s+(?:AND|OR|WITH)\s+|\(|\)|\+",
    flags=re.IGNORECASE,
)

VALID_SPDX_ID_PATTERN = re.compile(r"^[A-Za-z0-9.\-]+$")


@dataclass(frozen=True)
class ImageReference:
    """
    Represent a parsed container image reference.

    Attributes:
        url:
            Full image URL as read from an input file.
        project:
            Harbor project name extracted from the image URL.
        repository:
            Repository path within the Harbor project.
        tag:
            Image tag extracted from the image URL.
        digest:
            Harbor artifact digest for the resolved SBOM, if available.
    """

    url: str
    project: str
    repository: str
    tag: str
    digest: Optional[str] = None


@dataclass(frozen=True)
class HarborConfig:
    """
    Hold Harbor API connection settings.

    Attributes:
        api_base_url:
            Harbor API base URL, for example:
            https://harbor.example.com/api/v2.0
        username:
            Harbor username for basic authentication.
        password:
            Harbor password for basic authentication.
    """

    api_base_url: str
    username: str
    password: str

    @classmethod
    def from_env(cls) -> "HarborConfig":
        """
        Build a HarborConfig instance from required environment variables.

        Required variables:
            HARBOR_API_BASE_URL
            HARBOR_USERNAME
            HARBOR_PASSWORD

        Returns:
            HarborConfig populated from the process environment.

        Raises:
            RuntimeError:
                If any required environment variable is missing or empty.
        """
        return cls(
            api_base_url=get_required_env("HARBOR_API_BASE_URL").rstrip("/"),
            username=get_required_env("HARBOR_USERNAME"),
            password=get_required_env("HARBOR_PASSWORD"),
        )


@dataclass(frozen=True)
class ProcessingStats:
    """
    Store summary information about a script run.

    Attributes:
        image_file_count:
            Number of input files scanned.
        image_count:
            Number of image references after deduplication.
        resolved_count:
            Number of images for which an SBOM digest was found.
        missing_count:
            Number of images not found in Harbor or not resolvable.
        package_row_count:
            Number of package-license rows written to the CSV report.
        minimal_row_count:
            Number of rows written to the minimal CSV report.
        sbom_fetch_failures:
            Number of images whose SBOM digest was known but whose SBOM
            document could not be retrieved.
        license_file_count:
            Number of license text files successfully downloaded.
        license_download_failures:
            Number of license text downloads that failed.
        skipped_license_ids:
            Number of license identifiers that were ignored because they
            are not standard SPDX IDs or not in scope.
    """

    image_file_count: int
    image_count: int
    resolved_count: int
    missing_count: int
    package_row_count: int
    minimal_row_count: int
    sbom_fetch_failures: int
    license_file_count: int
    license_download_failures: int
    skipped_license_ids: int


def configure_logging(*, quiet: bool, verbose: bool) -> None:
    """
    Configure application logging.

    Args:
        quiet:
            If True, only warnings and errors are emitted.
        verbose:
            If True, debug-level output is enabled.

    Notes:
        If both quiet and verbose are false, logging defaults to INFO level.
        If both are provided, quiet takes precedence.
    """
    if quiet:
        level = logging.WARNING
    elif verbose:
        level = logging.DEBUG
    else:
        level = logging.INFO

    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def get_required_env(name: str) -> str:
    """
    Return a required environment variable value.

    Args:
        name:
            Name of the environment variable.

    Returns:
        The environment variable value.

    Raises:
        RuntimeError:
            If the environment variable is missing or empty.
    """
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


def build_timestamped_output_dir(base_output_dir: Path) -> Path:
    """
    Create and return a timestamped output directory.

    Args:
        base_output_dir:
            Base directory under which a timestamped run directory will be
            created.

    Returns:
        The created timestamped output directory.

    Example:
        If base_output_dir is ./out and the current time is 2026-04-14 09:30:00,
        the function may create and return:
        ./out/20260414_093000
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = base_output_dir / timestamp
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir


def find_image_definition_files(
    base_dir: Path,
    filename_prefix: str = "images_",
) -> List[Path]:
    """
    Return all matching image definition files from a directory.

    Args:
        base_dir:
            Directory containing image definition files.
        filename_prefix:
            Prefix used to identify relevant files.

    Returns:
        Sorted list of matching file paths.

    Raises:
        FileNotFoundError:
            If the input directory does not exist.
        NotADirectoryError:
            If the input path exists but is not a directory.
    """
    if not base_dir.exists():
        raise FileNotFoundError(f"Image directory does not exist: {base_dir}")
    if not base_dir.is_dir():
        raise NotADirectoryError(f"Image directory is not a directory: {base_dir}")

    files = sorted(
        path
        for path in base_dir.iterdir()
        if path.is_file() and path.name.startswith(filename_prefix)
    )

    LOGGER.debug("Found %d image definition file(s) in %s", len(files), base_dir)
    return files


def parse_image_reference(image_url: str) -> ImageReference:
    """
    Parse a container image URL into Harbor components.

    Expected format:
        registry/project/repository:tag

    Args:
        image_url:
            Full image reference, including registry, project, repository,
            and tag.

    Returns:
        Parsed ImageReference object.

    Raises:
        ValueError:
            If the image reference does not match the expected format.
    """
    try:
        _, remainder = image_url.split("/", 1)
        project, remainder = remainder.split("/", 1)
        repository, tag = remainder.rsplit(":", 1)
    except ValueError as exc:
        raise ValueError(f"Invalid image reference: {image_url}") from exc

    return ImageReference(
        url=image_url,
        project=project,
        repository=repository,
        tag=tag,
    )


def extract_image_references(files: Iterable[Path]) -> List[ImageReference]:
    """
    Extract image references from the supplied files.

    Behavior:
        - Empty lines are ignored.
        - Lines starting with '#' are ignored.
        - Each remaining line must contain one image reference.

    Args:
        files:
            Iterable of image definition files.

    Returns:
        List of parsed ImageReference objects, including duplicates if the
        same reference appears multiple times across files.

    Raises:
        ValueError:
            If any non-comment, non-empty line contains an invalid image
            reference. The raised message includes file and line number.
    """
    images: List[ImageReference] = []

    for file_path in files:
        with file_path.open(encoding="utf-8") as handle:
            for line_number, raw_line in enumerate(handle, start=1):
                line = raw_line.strip()

                if not line or line.startswith("#"):
                    continue

                try:
                    images.append(parse_image_reference(line))
                except ValueError as exc:
                    raise ValueError(
                        f"{file_path}:{line_number}: {exc}"
                    ) from exc

    LOGGER.debug("Extracted %d raw image reference(s)", len(images))
    return images


def deduplicate_image_references(
    images: List[ImageReference],
) -> List[ImageReference]:
    """
    Deduplicate image references while preserving first-seen order.

    Args:
        images:
            Image references, potentially including duplicates.

    Returns:
        List of unique image references in stable input order.
    """
    unique: List[ImageReference] = []
    seen: set[str] = set()

    for image in images:
        if image.url in seen:
            continue
        seen.add(image.url)
        unique.append(image)

    LOGGER.debug(
        "Deduplicated image references from %d to %d",
        len(images),
        len(unique),
    )

    return unique


def encode_repository_name(repository: str) -> str:
    """
    Encode a Harbor repository name for use in API paths.

    Harbor expects repository paths containing slashes to be double-encoded.

    Args:
        repository:
            Repository path inside a Harbor project.

    Returns:
        Harbor-compatible encoded repository path.
    """
    return quote(quote(repository, safe=""), safe="")


class HarborClient:
    """
    Provide a small Harbor API client with retry-enabled HTTP access.

    The client uses a shared requests.Session configured with:
        - basic authentication
        - JSON accept header
        - retry behavior for transient HTTP and network failures
    """

    def __init__(
        self,
        config: HarborConfig,
        *,
        timeout: int = 30,
        max_retries: int = 3,
        backoff_factor: float = 1.0,
    ) -> None:
        """
        Initialize the Harbor client.

        Args:
            config:
                Harbor connection settings.
            timeout:
                Request timeout in seconds.
            max_retries:
                Maximum number of retry attempts for transient failures.
            backoff_factor:
                Retry backoff factor passed to urllib3 Retry.
        """
        self.base_url = config.api_base_url
        self.timeout = timeout
        self.session = requests.Session()
        self.session.auth = (config.username, config.password)
        self.session.headers.update({"Accept": "application/json"})

        retry = Retry(
            total=max_retries,
            connect=max_retries,
            read=max_retries,
            status=max_retries,
            backoff_factor=backoff_factor,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset({"GET"}),
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)

    def fetch_artifact_with_sbom_overview(
        self,
        project: str,
        repository: str,
        tag: str,
    ) -> Optional[dict]:
        """
        Fetch Harbor artifact metadata including SBOM overview for a tag.

        Args:
            project:
                Harbor project name.
            repository:
                Repository path inside the Harbor project.
            tag:
                Image tag to resolve.

        Returns:
            Parsed artifact JSON if the request succeeds, otherwise None.
        """
        encoded_repository = encode_repository_name(repository)
        url = (
            f"{self.base_url}/projects/{project}/repositories/"
            f"{encoded_repository}/artifacts/{tag}"
        )

        params = {
            "page": 1,
            "page_size": 10,
            "with_tag": "false",
            "with_label": "false",
            "with_scan_overview": "false",
            "with_sbom_overview": "true",
            "with_accessory": "false",
            "with_signature": "false",
            "with_immutable_status": "false",
        }

        LOGGER.debug(
            "Fetching artifact metadata for %s/%s:%s",
            project,
            repository,
            tag,
        )

        try:
            response = self.session.get(url, params=params, timeout=self.timeout)
        except requests.RequestException as exc:
            LOGGER.warning(
                "Artifact metadata request failed for %s/%s:%s: %s",
                project,
                repository,
                tag,
                exc,
            )
            return None

        if not response.ok:
            LOGGER.warning(
                "Artifact metadata request returned %s for %s/%s:%s",
                response.status_code,
                project,
                repository,
                tag,
            )
            return None

        return response.json()

    def fetch_sbom(
        self,
        project: str,
        repository: str,
        digest: str,
    ) -> Optional[dict]:
        """
        Fetch the SBOM addition for a Harbor artifact digest.

        Args:
            project:
                Harbor project name.
            repository:
                Repository path inside the Harbor project.
            digest:
                Artifact digest to use as the Harbor artifact reference.

        Returns:
            Parsed SBOM JSON if available, otherwise None.
        """
        encoded_repository = encode_repository_name(repository)
        url = (
            f"{self.base_url}/projects/{project}/repositories/"
            f"{encoded_repository}/artifacts/{digest}/additions/sbom"
        )

        LOGGER.debug(
            "Fetching SBOM for %s/%s digest=%s",
            project,
            repository,
            digest,
        )

        try:
            response = self.session.get(url, timeout=self.timeout)
        except requests.RequestException as exc:
            LOGGER.warning(
                "SBOM request failed for %s/%s digest=%s: %s",
                project,
                repository,
                digest,
                exc,
            )
            return None

        if not response.ok:
            LOGGER.warning(
                "SBOM request returned %s for %s/%s digest=%s",
                response.status_code,
                project,
                repository,
                digest,
            )
            return None

        return response.json()

    def download_text_file(self, url: str) -> Optional[str]:
        """
        Download a text file and return its content.

        Args:
            url:
                Full URL of the remote text file.

        Returns:
            Decoded text content if successful, otherwise None.
        """
        LOGGER.debug("Downloading text file from %s", url)

        try:
            response = self.session.get(url, timeout=self.timeout)
        except requests.RequestException as exc:
            LOGGER.warning("License text download failed for %s: %s", url, exc)
            return None

        if not response.ok:
            LOGGER.warning(
                "License text download returned %s for %s",
                response.status_code,
                url,
            )
            return None

        response.encoding = response.encoding or "utf-8"
        return response.text


def collect_artifacts_with_sbom_digest(
    images: List[ImageReference],
    harbor: HarborClient,
) -> tuple[List[ImageReference], List[ImageReference]]:
    """
    Resolve Harbor artifacts and collect those with SBOM digests.

    Args:
        images:
            Deduplicated list of image references to resolve.
        harbor:
            Harbor API client.

    Returns:
        A tuple containing:
            - images successfully resolved with an SBOM digest
            - images missing from Harbor or without resolvable artifact metadata
    """
    resolved: List[ImageReference] = []
    missing: List[ImageReference] = []

    for image in images:
        artifact = harbor.fetch_artifact_with_sbom_overview(
            project=image.project,
            repository=image.repository,
            tag=image.tag,
        )

        if not artifact:
            missing.append(image)
            continue

        sbom_overview = artifact.get("sbom_overview") or {}
        sbom_digest = sbom_overview.get("sbom_digest")

        if sbom_digest:
            resolved.append(replace(image, digest=sbom_digest))
        else:
            LOGGER.info(
                "No SBOM digest found for %s/%s:%s",
                image.project,
                image.repository,
                image.tag,
            )

    return resolved, missing


def write_missing_artifacts_json(
    missing_artifacts: List[ImageReference],
    output_path: Path,
) -> None:
    """
    Write unresolved image references to a JSON report file.

    Args:
        missing_artifacts:
            Images that could not be resolved in Harbor.
        output_path:
            Destination JSON file path.
    """
    payload = [
        {
            "url": image.url,
            "project": image.project,
            "repository": image.repository,
            "tag": image.tag,
            "image": f"{image.project}/{image.repository}:{image.tag}",
        }
        for image in missing_artifacts
    ]

    output_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True),
        encoding="utf-8",
    )

    LOGGER.info("Wrote missing artifact report: %s", output_path)


def build_license_ref_lookup(sbom: dict) -> Dict[str, str]:
    """
    Build a lookup from SPDX LicenseRef identifiers to readable names.

    Args:
        sbom:
            Parsed SPDX SBOM document.

    Returns:
        Mapping from license ID to a readable name.
    """
    lookup: Dict[str, str] = {}

    for item in sbom.get("hasExtractedLicensingInfos", []):
        license_id = item.get("licenseId")
        license_name = item.get("name")
        if license_id:
            lookup[license_id] = license_name or license_id

    return lookup


def get_annotation_value(
    annotations: List[dict],
    prefix: str,
) -> Optional[str]:
    """
    Return the suffix of the first annotation comment matching a prefix.

    Args:
        annotations:
            List of SPDX annotation objects.
        prefix:
            Required prefix of the annotation comment.

    Returns:
        The suffix after the prefix, stripped of surrounding whitespace,
        or None if no matching annotation exists.
    """
    for annotation in annotations or []:
        comment = annotation.get("comment", "")
        if comment.startswith(prefix):
            return comment.removeprefix(prefix).strip()
    return None


def get_purl(package: dict) -> Optional[str]:
    """
    Extract the package URL from an SPDX package object.

    Args:
        package:
            SPDX package object.

    Returns:
        The package URL if available, otherwise None.
    """
    for ref in package.get("externalRefs", []):
        if ref.get("referenceType") == "purl":
            return ref.get("referenceLocator")
    return None


def resolve_license_expression(
    license_expression: Optional[str],
    license_ref_lookup: Dict[str, str],
) -> Optional[str]:
    """
    Replace SPDX LicenseRef tokens in a license expression with readable names.

    Args:
        license_expression:
            Original license expression from the SBOM.
        license_ref_lookup:
            Mapping produced from extracted licensing info entries.

    Returns:
        The resolved license expression, or the original value if no
        replacement is needed or the input is empty.
    """
    if not license_expression:
        return license_expression

    resolved = license_expression
    for license_id, readable_name in license_ref_lookup.items():
        resolved = resolved.replace(license_id, readable_name)

    return resolved


def extract_package_license_rows(
    sbom: dict,
    image: ImageReference,
) -> List[dict]:
    """
    Extract package-license rows from a single SPDX SBOM document.

    Behavior:
        - Packages with primaryPackagePurpose == "CONTAINER" are skipped.
        - Both declared and concluded license expressions are included.
        - LicenseRef values are resolved to readable names when possible.

    Args:
        sbom:
            Parsed SPDX SBOM document.
        image:
            ImageReference associated with the SBOM.

    Returns:
        List of row dictionaries suitable for CSV export.
    """
    rows: List[dict] = []
    license_ref_lookup = build_license_ref_lookup(sbom)

    for package in sbom.get("packages", []):
        if package.get("primaryPackagePurpose") == "CONTAINER":
            continue

        annotations = package.get("annotations", [])
        license_declared = package.get("licenseDeclared")
        license_concluded = package.get("licenseConcluded")

        rows.append(
            {
                "image_url": image.url,
                "image": f"{image.project}/{image.repository}:{image.tag}",
                "sbom_digest": image.digest,
                "package_name": package.get("name"),
                "package_version": package.get("versionInfo"),
                "package_spdxid": package.get("SPDXID"),
                "package_purpose": package.get("primaryPackagePurpose"),
                "package_type": get_annotation_value(annotations, "PkgType: "),
                "purl": get_purl(package),
                "supplier": package.get("supplier"),
                "license_declared": license_declared,
                "license_concluded": license_concluded,
                "license_declared_resolved": resolve_license_expression(
                    license_declared,
                    license_ref_lookup,
                ),
                "license_concluded_resolved": resolve_license_expression(
                    license_concluded,
                    license_ref_lookup,
                ),
            }
        )

    return rows


def collect_package_licenses(
    images_with_sbom_digest: List[ImageReference],
    harbor: HarborClient,
) -> tuple[List[dict], int]:
    """
    Fetch all available SBOMs and extract package-license rows.

    Args:
        images_with_sbom_digest:
            Images that have a resolved SBOM digest.
        harbor:
            Harbor API client.

    Returns:
        A tuple containing:
            - list of CSV row dictionaries
            - number of SBOM fetch failures
    """
    rows: List[dict] = []
    sbom_fetch_failures = 0

    for image in images_with_sbom_digest:
        if not image.digest:
            continue

        sbom = harbor.fetch_sbom(
            project=image.project,
            repository=image.repository,
            digest=image.digest,
        )

        if not sbom:
            sbom_fetch_failures += 1
            continue

        rows.extend(extract_package_license_rows(sbom, image))

    return rows, sbom_fetch_failures


def write_package_licenses_csv(rows: List[dict], output_path: Path) -> None:
    """
    Write extracted package-license rows to a CSV file.

    Args:
        rows:
            CSV row dictionaries.
        output_path:
            Destination CSV file path.

    Notes:
        If no rows are present, an empty file is created.
    """
    if not rows:
        output_path.write_text("", encoding="utf-8")
        LOGGER.info("Wrote empty license report: %s", output_path)
        return

    fieldnames = list(rows[0].keys())

    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    LOGGER.info("Wrote package license report: %s", output_path)


def choose_preferred_license(row: dict) -> Optional[str]:
    """
    Return the preferred license field for minimal reporting.

    Priority:
        1. license_concluded_resolved
        2. license_declared_resolved
        3. license_concluded
        4. license_declared
    """
    for key in (
        "license_concluded_resolved",
        "license_declared_resolved",
        "license_concluded",
        "license_declared",
    ):
        value = row.get(key)
        if value:
            return value
    return None


def build_minimal_license_rows(rows: List[dict]) -> List[dict]:
    """
    Build a deduplicated minimal package-license view.

    Output fields:
        - package_name
        - package_version
        - license

    Deduplication key:
        (package_name, package_version, license)
    """
    minimal_rows: List[dict] = []
    seen: Set[tuple[str, str, str]] = set()

    for row in rows:
        package_name = (row.get("package_name") or "").strip()
        package_version = (row.get("package_version") or "").strip()
        license_name = (choose_preferred_license(row) or "").strip()

        key = (package_name, package_version, license_name)
        if key in seen:
            continue

        seen.add(key)
        minimal_rows.append(
            {
                "package_name": package_name,
                "package_version": package_version,
                "license": license_name,
            }
        )

    minimal_rows.sort(
        key=lambda item: (
            item["package_name"].lower(),
            item["package_version"].lower(),
            item["license"].lower(),
        )
    )
    return minimal_rows


def write_minimal_package_licenses_csv(rows: List[dict], output_path: Path) -> None:
    """
    Write the minimal package-license CSV.

    Args:
        rows:
            Minimal CSV rows containing package_name, package_version, license.
        output_path:
            Destination CSV file path.
    """
    fieldnames = ["package_name", "package_version", "license"]

    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    LOGGER.info("Wrote minimal package license report: %s", output_path)


def sanitize_filename(value: str) -> str:
    """
    Sanitize a string for filesystem-safe filenames.
    """
    sanitized = re.sub(r"[^A-Za-z0-9._-]+", "_", value.strip())
    return sanitized.strip("._") or "unknown"


def extract_spdx_ids_from_expression(expression: Optional[str]) -> Set[str]:
    """
    Extract standard SPDX license identifiers from a license expression.

    Notes:
        - Operators like AND/OR/WITH are removed.
        - Parentheses are ignored.
        - Tokens starting with LicenseRef- or DocumentRef- are ignored.
        - Tokens must look like SPDX IDs to be accepted.
    """
    if not expression:
        return set()

    raw_tokens = LICENSE_EXPRESSION_OPERATOR_PATTERN.split(expression)
    ids: Set[str] = set()

    for token in raw_tokens:
        token = token.strip()
        if not token:
            continue

        upper_token = token.upper()
        if upper_token in {"AND", "OR", "WITH"}:
            continue

        if token.startswith("LicenseRef-") or token.startswith("DocumentRef-"):
            continue

        if token in {"NOASSERTION", "NONE", "UNKNOWN"}:
            continue

        if not VALID_SPDX_ID_PATTERN.match(token):
            continue

        ids.add(token)

    return ids


def collect_relevant_license_ids(minimal_rows: List[dict]) -> tuple[Set[str], int]:
    """
    Collect relevant SPDX license IDs from minimal rows.

    Returns:
        Tuple of:
            - relevant SPDX IDs to download
            - number of skipped/non-standard license IDs seen
    """
    relevant_ids: Set[str] = set()
    skipped_count = 0

    for row in minimal_rows:
        expression = row.get("license")
        for license_id in extract_spdx_ids_from_expression(expression):
            if license_id in RELEVANT_LICENSE_IDS:
                relevant_ids.add(license_id)
            else:
                skipped_count += 1

    return relevant_ids, skipped_count


def download_license_texts(
    harbor: HarborClient,
    license_ids: Set[str],
    output_dir: Path,
) -> tuple[int, int]:
    """
    Download SPDX license texts into a target directory.

    Directory layout:
        licenses/
            Apache-2.0/
                LICENSE.txt
            MIT/
                LICENSE.txt

    Args:
        harbor:
            Reused HTTP client.
        license_ids:
            SPDX license IDs to download.
        output_dir:
            Base licenses directory.

    Returns:
        Tuple of:
            - successful download count
            - failed download count
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    success_count = 0
    failure_count = 0

    for license_id in sorted(license_ids):
        license_subdir = output_dir / sanitize_filename(license_id)
        license_subdir.mkdir(parents=True, exist_ok=True)
        destination = license_subdir / LICENSE_DOWNLOAD_FILENAME

        url = f"{SPDX_LICENSE_TEXT_BASE_URL}/{quote(license_id, safe='')}.txt"
        content = harbor.download_text_file(url)

        if content is None:
            failure_count += 1
            continue

        destination.write_text(content, encoding="utf-8")
        LOGGER.info("Downloaded license text for %s -> %s", license_id, destination)
        success_count += 1

    return success_count, failure_count


def write_run_summary(
    stats: ProcessingStats,
    output_path: Path,
) -> None:
    """
    Write a machine-readable JSON summary for the script run.

    Args:
        stats:
            Processing summary values.
        output_path:
            Destination JSON file path.
    """
    payload = {
        "image_file_count": stats.image_file_count,
        "image_count": stats.image_count,
        "resolved_count": stats.resolved_count,
        "missing_count": stats.missing_count,
        "package_row_count": stats.package_row_count,
        "minimal_row_count": stats.minimal_row_count,
        "sbom_fetch_failures": stats.sbom_fetch_failures,
        "license_file_count": stats.license_file_count,
        "license_download_failures": stats.license_download_failures,
        "skipped_license_ids": stats.skipped_license_ids,
    }

    output_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True),
        encoding="utf-8",
    )

    LOGGER.info("Wrote run summary: %s", output_path)


def determine_exit_code(stats: ProcessingStats) -> int:
    """
    Determine the process exit code for the run.

    Rules:
        - EXIT_OK if the run completed without missing artifacts or SBOM
          fetch failures.
        - EXIT_PARTIAL_SUCCESS if the run completed but had unresolved
          artifacts, SBOM retrieval failures, or license download failures.

    Args:
        stats:
            Processing summary values.

    Returns:
        Process exit code suitable for CI/cron usage.
    """
    if (
        stats.missing_count > 0
        or stats.sbom_fetch_failures > 0
        or stats.license_download_failures > 0
    ):
        return EXIT_PARTIAL_SUCCESS
    return EXIT_OK


def parse_args() -> argparse.Namespace:
    """
    Parse command-line arguments.

    Returns:
        Parsed argparse namespace.
    """
    parser = argparse.ArgumentParser(
        description="Collect SBOM package license data for Harbor images."
    )
    parser.add_argument(
        "--image-dir",
        type=Path,
        default=Path("./image_files"),
        help="Directory containing image definition files.",
    )
    parser.add_argument(
        "--prefix",
        default="images_",
        help="Filename prefix for image definition files.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("./out"),
        help="Base output directory. A timestamped subdirectory is created per run.",
    )
    parser.add_argument(
        "--request-timeout",
        type=int,
        default=30,
        help="HTTP request timeout in seconds.",
    )
    parser.add_argument(
        "--max-retries",
        type=int,
        default=3,
        help="Maximum retry attempts for transient Harbor API failures.",
    )
    parser.add_argument(
        "--backoff-factor",
        type=float,
        default=1.0,
        help="Retry backoff factor for Harbor API requests.",
    )
    parser.add_argument(
        "--no-license-files",
        action="store_true",
        help="Do not download license text files into the timestamped output directory.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Only log warnings and errors.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable debug logging.",
    )
    return parser.parse_args()


def main() -> int:
    """
    Run the Harbor SBOM reporting workflow.

    Workflow:
        1. Read Harbor configuration from environment variables.
        2. Discover image definition files.
        3. Parse and deduplicate image references.
        4. Resolve Harbor artifacts and SBOM digests.
        5. Fetch SBOM documents and extract package-license rows.
        6. Write JSON and CSV output files to a timestamped output directory.
        7. Optionally download relevant license texts into licenses/.
        8. Return a process exit code suitable for automation.

    Returns:
        Process exit code.
    """
    args = parse_args()
    configure_logging(quiet=args.quiet, verbose=args.verbose)

    try:
        config = HarborConfig.from_env()
    except RuntimeError as exc:
        LOGGER.error(str(exc))
        return EXIT_CONFIG_ERROR

    try:
        output_dir = build_timestamped_output_dir(args.output_dir)
        missing_output = output_dir / "missing_harbor_artifacts.json"
        licenses_output = output_dir / "package_licenses.csv"
        minimal_output = output_dir / "package_licenses_minimal.csv"
        summary_output = output_dir / "run_summary.json"
        license_files_output_dir = output_dir / "licenses"

        image_definition_files = find_image_definition_files(
            base_dir=args.image_dir,
            filename_prefix=args.prefix,
        )

        raw_images = extract_image_references(image_definition_files)
        used_images = deduplicate_image_references(raw_images)

        harbor = HarborClient(
            config,
            timeout=args.request_timeout,
            max_retries=args.max_retries,
            backoff_factor=args.backoff_factor,
        )

        images_with_sbom_digest, missing_artifacts = collect_artifacts_with_sbom_digest(
            images=used_images,
            harbor=harbor,
        )

        write_missing_artifacts_json(
            missing_artifacts=missing_artifacts,
            output_path=missing_output,
        )

        package_license_rows, sbom_fetch_failures = collect_package_licenses(
            images_with_sbom_digest=images_with_sbom_digest,
            harbor=harbor,
        )

        write_package_licenses_csv(
            rows=package_license_rows,
            output_path=licenses_output,
        )

        minimal_rows = build_minimal_license_rows(package_license_rows)
        write_minimal_package_licenses_csv(
            rows=minimal_rows,
            output_path=minimal_output,
        )

        relevant_license_ids, skipped_license_ids = collect_relevant_license_ids(
            minimal_rows
        )

        license_file_count = 0
        license_download_failures = 0

        if args.no_license_files:
            LOGGER.info("License file download disabled by --no-license-files")
        elif relevant_license_ids:
            license_file_count, license_download_failures = download_license_texts(
                harbor=harbor,
                license_ids=relevant_license_ids,
                output_dir=license_files_output_dir,
            )
        else:
            LOGGER.info("No relevant SPDX license IDs found for license file download")

        stats = ProcessingStats(
            image_file_count=len(image_definition_files),
            image_count=len(used_images),
            resolved_count=len(images_with_sbom_digest),
            missing_count=len(missing_artifacts),
            package_row_count=len(package_license_rows),
            minimal_row_count=len(minimal_rows),
            sbom_fetch_failures=sbom_fetch_failures,
            license_file_count=license_file_count,
            license_download_failures=license_download_failures,
            skipped_license_ids=skipped_license_ids,
        )

        write_run_summary(
            stats=stats,
            output_path=summary_output,
        )

        LOGGER.info("Run completed")
        LOGGER.info("Output directory: %s", output_dir)
        LOGGER.info(
            (
                "Summary: files=%d images=%d resolved=%d missing=%d "
                "license_rows=%d minimal_rows=%d sbom_failures=%d "
                "license_files=%d license_download_failures=%d skipped_license_ids=%d"
            ),
            stats.image_file_count,
            stats.image_count,
            stats.resolved_count,
            stats.missing_count,
            stats.package_row_count,
            stats.minimal_row_count,
            stats.sbom_fetch_failures,
            stats.license_file_count,
            stats.license_download_failures,
            stats.skipped_license_ids,
        )

        return determine_exit_code(stats)

    except (FileNotFoundError, NotADirectoryError, ValueError) as exc:
        LOGGER.error(str(exc))
        return EXIT_INPUT_ERROR
    except Exception as exc:
        LOGGER.exception("Unhandled runtime error: %s", exc)
        return EXIT_RUNTIME_ERROR


if __name__ == "__main__":
    sys.exit(main())