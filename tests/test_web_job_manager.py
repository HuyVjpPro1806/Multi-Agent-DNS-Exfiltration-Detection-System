"""Unit tests for web pipeline job state helpers."""

import json
from types import SimpleNamespace

import pytest

from webapp.job_manager import (
    JobManager,
    PipelineJob,
    apply_log_event,
    initial_agents,
    parse_tcpdump_interfaces,
    safe_upload_name,
    summarize_scores,
    validate_capture_options,
    validate_interface,
)


def make_job(tmp_path, mode="pcap"):
    return PipelineJob(
        id="test-job",
        filename=f"sample.{mode}",
        mode=mode,
        input_path=tmp_path / f"sample.{mode}",
        job_dir=tmp_path,
        agents=initial_agents(mode),
    )


def test_safe_upload_name_removes_parent_path():
    assert safe_upload_name("../../capture.pcap") == "capture.pcap"
    assert safe_upload_name(r"..\..\capture.pcap") == "capture.pcap"


def test_safe_upload_name_rejects_unsupported_extension():
    with pytest.raises(ValueError):
        safe_upload_name("payload.exe")


def test_csv_job_skips_pcap_reader():
    assert initial_agents("csv")["pcap_reader_agent"] == "skipped"


def test_parse_tcpdump_interfaces():
    output = (
        "1.eth0 [Up, Running]\n"
        "2.any (Pseudo-device that captures on all interfaces) [Up, Running]\n"
        "invalid line\n"
    )

    assert parse_tcpdump_interfaces(output) == [
        {"id": "1", "label": "eth0 [Up, Running]"},
        {
            "id": "2",
            "label": "any (Pseudo-device that captures on all interfaces) [Up, Running]",
        },
    ]


@pytest.mark.parametrize(
    ("timeout", "max_packets"),
    [(4, 100), (301, 100), (30, 0), (30, 10_001)],
)
def test_capture_options_reject_out_of_range_values(timeout, max_packets):
    with pytest.raises(ValueError):
        validate_capture_options(timeout, max_packets)


def test_validate_interface_normalizes_default_and_rejects_control_characters():
    assert validate_interface(" default ") is None
    assert validate_interface(" 2 ") == "2"
    with pytest.raises(ValueError):
        validate_interface("eth0\nmalformed")


def test_list_interfaces_uses_tcpdump_numeric_selectors(tmp_path, monkeypatch):
    manager = JobManager(tmp_path / "jobs")
    monkeypatch.setattr("webapp.job_manager.shutil.which", lambda name: "/usr/bin/tcpdump")
    monkeypatch.setattr(
        "webapp.job_manager.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0,
            stdout="1.eth0 [Up]\n2.any [Up]\n",
            stderr="",
        ),
    )

    assert manager.list_interfaces() == {
        "available": True,
        "detail": "",
        "interfaces": [
            {"id": "1", "label": "eth0 [Up]"},
            {"id": "2", "label": "any [Up]"},
        ],
    }


def test_log_events_update_agent_state(tmp_path):
    job = make_job(tmp_path)

    apply_log_event(job, "SUBAGENT START | entropy_agent")
    assert job.agents["entropy_agent"] == "running"

    apply_log_event(job, "SUBAGENT END | entropy_agent | elapsed=0.10s")
    assert job.agents["entropy_agent"] == "completed"

    apply_log_event(job, "SUBAGENT FAILED | report_agent | elapsed=0.20s")
    assert job.agents["report_agent"] == "failed"


def test_summarize_scores(tmp_path):
    scores_path = tmp_path / "scores.json"
    scores_path.write_text(
        json.dumps(
            [
                {"verdict": "benign", "combined_score": 0.1},
                {"verdict": "suspected", "combined_score": 0.92},
            ]
        ),
        encoding="utf-8",
    )

    assert summarize_scores(scores_path) == {
        "total_queries": 2,
        "suspected_count": 1,
        "highest_risk_score": 0.92,
    }
