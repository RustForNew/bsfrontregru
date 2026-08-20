from __future__ import annotations

import concurrent.futures
import hashlib
import json
import os
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from xhttp_setup.errors import InstallerError
from xhttp_setup.exit_installer import XRAY_VERSION, _firewall_plan
from xhttp_setup.models import ExitDesired, Handoff
from xhttp_setup.pc_autosetup import (
    PcUserInputs,
    _load_pending_pc_exit,
    clear_pending_pc_exit,
    inspect_existing_pc_exit,
    write_pending_pc_exit,
)
from xhttp_setup.remote_exit import RemoteExitTarget
from xhttp_setup.remote_network import RemoteExitNetworkState


CLIENT_ID = "d342d11e-d424-4583-b36e-524ab1f0afa4"
XHTTP_PATH = "/api/resume-path-0123456789"
ENCRYPTION = "mlkem768x25519plus.native.0rtt.clientmaterialxxxxxxxx"


def completed(argv, returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(argv, returncode, stdout, stderr)


class ResumeSSH:
    def __init__(self, files: dict[str, tuple[str, str, str]]):
        self.files = files
        self.calls: list[list[str]] = []
        self.service_active = True
        self.listener_matches = True

    def command(self, argv, *, check=True, timeout=300):
        del check, timeout
        argv = list(argv)
        self.calls.append(argv)
        if argv[:4] == ["env", "LC_ALL=C", "LANG=C", "stat"]:
            path = argv[-1]
            content, group, mode = self.files[path]
            size = len(content.encode("utf-8"))
            return completed(
                argv, stdout=f"root:{group}:{mode}:regular file:{size}\n"
            )
        if argv[:2] == ["sha256sum", "--"]:
            path = argv[-1]
            content = self.files[path][0].encode("utf-8")
            return completed(
                argv, stdout=f"{hashlib.sha256(content).hexdigest()}  {path}\n"
            )
        if argv[:2] == ["cat", "--"]:
            return completed(argv, stdout=self.files[argv[-1]][0])
        if argv[:2] == ["systemctl", "is-active"]:
            return completed(
                argv,
                returncode=0 if self.service_active else 3,
                stdout="active\n" if self.service_active else "inactive\n",
            )
        if argv[:2] == ["systemctl", "is-enabled"]:
            return completed(argv, stdout="enabled\n")
        if argv[:3] == ["systemctl", "show", "--property=MainPID"]:
            return completed(argv, stdout="1234\n")
        if argv[:3] == ["ss", "-H", "-lntp"]:
            listener = (
                'LISTEN 0 4096 *:8083 *:* users:(("xray",pid=1234,fd=9))\n'
                if self.listener_matches
                else 'LISTEN 0 4096 *:8083 *:* users:(("other",pid=44,fd=9))\n'
            )
            return completed(argv, stdout=listener)
        raise AssertionError(argv)


class PcExitResumeTests(unittest.TestCase):
    def _fixture(self, root: Path):
        handoff = Handoff(
            exit_address="8.8.8.8",
            exit_port=8083,
            client_id=CLIENT_ID,
            xhttp_path=XHTTP_PATH,
            encryption=ENCRYPTION,
            expected_egress_ip="8.8.8.8",
        ).validate()
        desired = ExitDesired(
            public_address="8.8.8.8",
            listen_port=8083,
            front_egress_ip="9.9.9.9",
            xhttp_path=XHTTP_PATH,
            client_id=CLIENT_ID,
            expected_egress_ip="8.8.8.8",
        ).validate()
        output = root / "state"
        output.mkdir(mode=0o700)
        handoff_text = json.dumps(
            handoff.to_dict(), ensure_ascii=False, indent=2, sort_keys=True
        ) + "\n"
        firewall_text = _firewall_plan(desired)
        (output / "handoff.json").write_bytes(handoff_text.encode("utf-8"))
        (output / "firewall-plan.txt").write_bytes(firewall_text.encode("utf-8"))
        os.chmod(output / "handoff.json", 0o600)
        os.chmod(output / "firewall-plan.txt", 0o600)
        config = '{"log": {"loglevel": "warning"}}\n'
        receipt = {
            "schema_version": 1,
            "xray_version": XRAY_VERSION,
            "config_sha256": hashlib.sha256(config.encode()).hexdigest(),
            "public_address": desired.public_address,
            "listen_port": desired.listen_port,
            "front_egress_ip": desired.front_egress_ip,
            "expected_egress_ip": desired.expected_egress_ip,
            "xhttp_path_sha256": hashlib.sha256(XHTTP_PATH.encode()).hexdigest(),
            "client_id_sha256": hashlib.sha256(CLIENT_ID.encode()).hexdigest(),
            "service": "xhttp-setup-xray.service",
        }
        files = {
            "/var/lib/xhttp-setup/handoff.json": (handoff_text, "root", "600"),
            "/var/lib/xhttp-setup/firewall-plan.txt": (
                firewall_text,
                "root",
                "600",
            ),
            "/var/lib/xhttp-setup/current.json": (
                json.dumps(receipt, indent=2, sort_keys=True) + "\n",
                "root",
                "600",
            ),
            "/etc/xhttp-setup/xray.json": (config, "xhttp-setup", "640"),
        }
        return output, desired, handoff, ResumeSSH(files)

    def _inspect(
        self,
        output: Path,
        ssh: ResumeSSH,
        *,
        network=None,
        egress=None,
        pending_desired: ExitDesired | None = None,
    ):
        network = network or RemoteExitNetworkState(
            os_id="ubuntu", ufw_allow_indices=(1,), ufw_deny_indices=(2, 3)
        )
        egress = egress or "8.8.8.8"
        with (
            patch(
                "xhttp_setup.remote_network.preflight_remote_exit_network",
                return_value=network,
            ) as preflight,
            patch(
                "xhttp_setup.remote_prepare.measure_remote_exit_egress",
                return_value=egress,
            ) as measure,
        ):
            result = inspect_existing_pc_exit(
                ssh,
                output_dir=output,
                exit_address="8.8.8.8",
                ssh_port=22,
                pending_desired=pending_desired,
            )
        return result, preflight, measure

    def test_exact_local_remote_service_receipt_and_ufw_are_reused(self):
        with tempfile.TemporaryDirectory() as temp:
            output, desired, handoff, ssh = self._fixture(Path(temp))
            result, preflight, measure = self._inspect(output, ssh)

        self.assertIsNotNone(result)
        self.assertEqual(result.desired, desired)
        self.assertEqual(result.handoff, handoff)
        self.assertNotIn(ENCRYPTION, repr(result))
        preflight.assert_called_once()
        measure.assert_called_once_with(ssh)

    def test_no_local_artifacts_is_a_new_install_without_remote_calls(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            result = inspect_existing_pc_exit(
                Mock(), output_dir=root, exit_address="8.8.8.8", ssh_port=22
            )
        self.assertIsNone(result)

    def test_partial_local_artifacts_fail_before_remote_checks(self):
        with tempfile.TemporaryDirectory() as temp:
            output, _, _, ssh = self._fixture(Path(temp))
            (output / "firewall-plan.txt").unlink()
            with self.assertRaisesRegex(InstallerError, "неполны"):
                inspect_existing_pc_exit(
                    ssh,
                    output_dir=output,
                    exit_address="8.8.8.8",
                    ssh_port=22,
                )
        self.assertEqual(ssh.calls, [])

    def test_exact_pending_allows_only_transaction_owned_partial_artifacts(self):
        for missing in ("handoff.json", "firewall-plan.txt"):
            with self.subTest(missing=missing):
                with tempfile.TemporaryDirectory() as temp:
                    output, desired, _, ssh = self._fixture(Path(temp))
                    (output / missing).unlink()
                    result = inspect_existing_pc_exit(
                        ssh,
                        output_dir=output,
                        exit_address="8.8.8.8",
                        ssh_port=22,
                        pending_desired=desired,
                    )
                self.assertIsNone(result)
                self.assertEqual(ssh.calls, [])

        with tempfile.TemporaryDirectory() as temp:
            output, desired, _, ssh = self._fixture(Path(temp))
            (output / "firewall-plan.txt").unlink()
            payload = json.loads((output / "handoff.json").read_text("utf-8"))
            payload["client_id"] = "5297917d-18dd-4d4f-9a77-b53f4fdc0d13"
            (output / "handoff.json").write_text(
                json.dumps(payload) + "\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(InstallerError, "Неполный handoff"):
                inspect_existing_pc_exit(
                    ssh,
                    output_dir=output,
                    exit_address="8.8.8.8",
                    ssh_port=22,
                    pending_desired=desired,
                )
        self.assertEqual(ssh.calls, [])

        with tempfile.TemporaryDirectory() as temp:
            output, desired, _, ssh = self._fixture(Path(temp))
            (output / "handoff.json").unlink()
            firewall = output / "firewall-plan.txt"
            firewall.write_text(
                firewall.read_text("utf-8") + "tampered\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(InstallerError, "Неполный firewall-plan"):
                inspect_existing_pc_exit(
                    ssh,
                    output_dir=output,
                    exit_address="8.8.8.8",
                    ssh_port=22,
                    pending_desired=desired,
                )
        self.assertEqual(ssh.calls, [])

    def test_remote_artifact_mismatch_fails_before_network_or_egress(self):
        with tempfile.TemporaryDirectory() as temp:
            output, _, _, ssh = self._fixture(Path(temp))
            content, group, mode = ssh.files["/var/lib/xhttp-setup/handoff.json"]
            ssh.files["/var/lib/xhttp-setup/handoff.json"] = (
                content + " ",
                group,
                mode,
            )
            with (
                patch(
                    "xhttp_setup.remote_network.preflight_remote_exit_network"
                ) as preflight,
                patch(
                    "xhttp_setup.remote_prepare.measure_remote_exit_egress"
                ) as measure,
            ):
                with self.assertRaisesRegex(InstallerError, "артефакты различаются"):
                    inspect_existing_pc_exit(
                        ssh,
                        output_dir=output,
                        exit_address="8.8.8.8",
                        ssh_port=22,
                    )
        preflight.assert_not_called()
        measure.assert_not_called()

    def test_wrong_listener_missing_rules_or_changed_egress_fail_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            output, _, _, ssh = self._fixture(Path(temp))
            ssh.listener_matches = False
            with self.assertRaisesRegex(InstallerError, "не принадлежит"):
                self._inspect(output, ssh)

        with tempfile.TemporaryDirectory() as temp:
            output, _, _, ssh = self._fixture(Path(temp))
            network = RemoteExitNetworkState(
                os_id="ubuntu", ufw_allow_indices=(), ufw_deny_indices=(1,)
            )
            with self.assertRaisesRegex(InstallerError, "allow/deny"):
                self._inspect(output, ssh, network=network)

        with tempfile.TemporaryDirectory() as temp:
            output, _, _, ssh = self._fixture(Path(temp))
            with self.assertRaisesRegex(InstallerError, "IPv4.*изменился"):
                self._inspect(output, ssh, egress="1.1.1.1")

    @unittest.skipUnless(os.name == "posix", "POSIX pending file semantics")
    def test_pending_exit_marker_is_private_exactly_bound_and_removable(self):
        desired = ExitDesired(
            public_address="8.8.8.8",
            listen_port=8083,
            front_egress_ip="9.9.9.9",
            xhttp_path=XHTTP_PATH,
            client_id=CLIENT_ID,
            expected_egress_ip="8.8.8.8",
        ).validate()
        target = RemoteExitTarget(
            host="8.8.8.8",
            port=22,
            user="root",
            host_key_sha256="SHA256:" + ("A" * 43),
        ).validate()
        inputs = PcUserInputs(
            exit_host="8.8.8.8",
            exit_port=22,
            exit_user="root",
            exit_password="exit-secret-not-for-marker",
            panel_url="https://vip999.hosting.reg.ru:1500/",
            panel_user="u1234567",
            panel_password="panel-secret-not-for-marker",
            front_connect_ip="192.0.2.30",
            domain="front.example.org",
        ).validate()

        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "state"
            output.mkdir(mode=0o700)
            marker = write_pending_pc_exit(
                output_dir=output,
                prepared=SimpleNamespace(
                    exit_target=target,
                    desired_exit=desired,
                ),
                domain=inputs.domain,
            )
            raw = marker.read_text(encoding="utf-8")
            self.assertEqual(marker.stat().st_mode & 0o777, 0o600)
            self.assertNotIn(inputs.exit_password, raw)
            self.assertNotIn(inputs.panel_password, raw)
            self.assertEqual(
                _load_pending_pc_exit(
                    output_dir=output,
                    inputs=inputs,
                    exit_target=target,
                ),
                desired,
            )
            self.assertEqual(
                write_pending_pc_exit(
                    output_dir=output,
                    prepared=SimpleNamespace(
                        exit_target=target,
                        desired_exit=desired,
                    ),
                    domain=inputs.domain,
                ),
                marker,
            )

            alternate = ExitDesired(
                public_address=desired.public_address,
                listen_port=desired.listen_port,
                front_egress_ip=desired.front_egress_ip,
                xhttp_path=desired.xhttp_path,
                client_id="5297917d-18dd-4d4f-9a77-b53f4fdc0d13",
                expected_egress_ip=desired.expected_egress_ip,
            ).validate()
            with self.assertRaisesRegex(InstallerError, "другую транзакцию"):
                write_pending_pc_exit(
                    output_dir=output,
                    prepared=SimpleNamespace(
                        exit_target=target,
                        desired_exit=alternate,
                    ),
                    domain=inputs.domain,
                )
            self.assertEqual(marker.read_text(encoding="utf-8"), raw)

            wrong_domain = PcUserInputs(
                **{
                    **inputs.__dict__,
                    "domain": "other.example.org",
                }
            ).validate()
            with self.assertRaisesRegex(InstallerError, "другой установке"):
                _load_pending_pc_exit(
                    output_dir=output,
                    inputs=wrong_domain,
                    exit_target=target,
                )

            wrong_target = RemoteExitTarget(
                host="1.1.1.1",
                port=22,
                user="root",
                host_key_sha256=target.host_key_sha256,
            ).validate()
            with self.assertRaisesRegex(InstallerError, "другому SSH endpoint"):
                _load_pending_pc_exit(
                    output_dir=output,
                    inputs=inputs,
                    exit_target=wrong_target,
                )

            clear_pending_pc_exit(output)
            self.assertFalse(marker.exists())
            self.assertIsNone(
                _load_pending_pc_exit(
                    output_dir=output,
                    inputs=inputs,
                    exit_target=target,
                )
            )

            barrier = threading.Barrier(2)

            def race_write(candidate: ExitDesired) -> tuple[str, str]:
                barrier.wait(timeout=5)
                try:
                    write_pending_pc_exit(
                        output_dir=output,
                        prepared=SimpleNamespace(
                            exit_target=target,
                            desired_exit=candidate,
                        ),
                        domain=inputs.domain,
                    )
                except InstallerError:
                    return "blocked", candidate.client_id
                return "written", candidate.client_id

            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                outcomes = list(pool.map(race_write, (desired, alternate)))
            self.assertEqual(
                sorted(status for status, _ in outcomes),
                ["blocked", "written"],
            )
            winner = next(value for status, value in outcomes if status == "written")
            stored = json.loads(marker.read_text(encoding="utf-8"))
            self.assertEqual(stored["desired_exit"]["client_id"], winner)


if __name__ == "__main__":
    unittest.main()
