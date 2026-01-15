"""Output file writing for BloodHound CE."""

from __future__ import annotations

import json
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any

from rich.console import Console

console = Console()


class OutputWriter:
    """Write BloodHound CE output files."""

    def __init__(self, output_dir: str | Path, domain: str):
        self.output_dir = Path(output_dir)
        self.domain = domain.replace(".", "_").upper()
        self.timestamp = datetime.now().strftime("%Y%m%d%H%M%S")

    def ensure_output_dir(self) -> None:
        """Create output directory if it doesn't exist."""
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def get_filename(self, suffix: str) -> str:
        """Generate consistent filename."""
        return f"{self.timestamp}_{self.domain}_certihound_{suffix}"

    def write_json(self, data: dict[str, Any], filename: str) -> Path:
        """Write data to JSON file."""
        self.ensure_output_dir()
        filepath = self.output_dir / filename
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
        return filepath

    def write_bloodhound_json(self, output: dict[str, Any]) -> list[Path]:
        """Write BloodHound CE compatible JSON files."""
        self.ensure_output_dir()
        written_files = []

        # Write each object type to separate file
        # Note: BloodHound CE processes edges from node Aces, not separate relationship files
        for obj_type in ["certtemplates", "enterprisecas", "rootcas", "ntauthstores", "aiacas"]:
            if obj_type in output and output[obj_type]["data"]:
                filename = self.get_filename(f"{obj_type}.json")
                filepath = self.write_json(output[obj_type], filename)
                written_files.append(filepath)
                console.print(f"[green][+] Written {filepath}[/green]")

        return written_files

    def write_bloodhound_zip(self, output: dict[str, Any]) -> Path:
        """Write BloodHound CE compatible ZIP file."""
        self.ensure_output_dir()
        zip_filename = self.get_filename("bloodhound.zip")
        zip_path = self.output_dir / zip_filename

        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            # Write each object type
            # Note: BloodHound CE processes edges from node Aces, not separate relationship files
            for obj_type in ["certtemplates", "enterprisecas", "rootcas", "ntauthstores", "aiacas"]:
                if obj_type in output and output[obj_type]["data"]:
                    json_content = json.dumps(output[obj_type], indent=2, default=str)
                    zf.writestr(f"{self.timestamp}_{obj_type}.json", json_content)

        console.print(f"[green][+] Written {zip_path}[/green]")
        return zip_path

    def write_vulnerability_report(self, vulnerabilities: list[dict]) -> Path:
        """Write vulnerability report."""
        self.ensure_output_dir()
        filename = self.get_filename("vulnerabilities.json")
        filepath = self.output_dir / filename

        report = {
            "generated": datetime.now().isoformat(),
            "domain": self.domain,
            "total_vulnerabilities": len(vulnerabilities),
            "vulnerabilities": vulnerabilities,
        }

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, default=str)

        console.print(f"[green][+] Written vulnerability report: {filepath}[/green]")
        return filepath

    def write_summary(self, summary: dict) -> Path:
        """Write collection summary."""
        self.ensure_output_dir()
        filename = self.get_filename("summary.json")
        filepath = self.output_dir / filename

        summary["generated"] = datetime.now().isoformat()

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2, default=str)

        console.print(f"[green][+] Written summary: {filepath}[/green]")
        return filepath

    def write_all(
        self,
        output: dict[str, Any],
        format: str = "zip",
    ) -> dict[str, list[Path] | Path]:
        """Write all output files."""
        result: dict[str, list[Path] | Path] = {}

        if format in ("json", "both"):
            result["json_files"] = self.write_bloodhound_json(output)

        if format in ("zip", "both"):
            result["zip_file"] = self.write_bloodhound_zip(output)

        if output.get("vulnerabilities"):
            result["vulnerability_report"] = self.write_vulnerability_report(
                output["vulnerabilities"]
            )

        # Always write summary
        from .bloodhound import BloodHoundOutput

        summary = {
            "domain": self.domain,
            "templates": len(output.get("certtemplates", {}).get("data", [])),
            "enterprise_cas": len(output.get("enterprisecas", {}).get("data", [])),
            "root_cas": len(output.get("rootcas", {}).get("data", [])),
            "ntauth_stores": len(output.get("ntauthstores", {}).get("data", [])),
            "aia_cas": len(output.get("aiacas", {}).get("data", [])),
            "edges": len(output.get("edges", [])),
            "vulnerabilities": len(output.get("vulnerabilities", [])),
        }
        result["summary"] = self.write_summary(summary)

        return result
