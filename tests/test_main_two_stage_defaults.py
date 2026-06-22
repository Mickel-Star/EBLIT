import argparse

from src.process.main import _add_two_stage_args


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    _add_two_stage_args(parser)
    return parser


def test_two_stage_is_enabled_by_default() -> None:
    args = _parser().parse_args([])
    assert args.two_stage is True


def test_no_two_stage_disables_pipeline() -> None:
    args = _parser().parse_args(["--no-two-stage"])
    assert args.two_stage is False


def test_explicit_two_stage_keeps_pipeline_enabled() -> None:
    args = _parser().parse_args(["--two-stage"])
    assert args.two_stage is True
