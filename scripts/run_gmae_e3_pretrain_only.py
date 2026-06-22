from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from src.common.io import write_json
from src.knowledge.kb_builders import (
    KB_PATHS,
    _filter_training_graph,
    _build_manifest_record,
    _write_gmae_manifest,
    _e3_manifest_sources,
    _init_gmae_runtime,
    _train_gmae_from_manifest,
    _save_named_gmae_runtime,
    TRANSFER_GMAE_CONTEXT_TAG,
)
from src.process.e3_cdm_adapter import build_e3_windows
from src.process.window_io import dump_window_graph

def main():
    KB_PATHS.ensure_layout()
    e3_root = Path('/home/john/yzx/DARPA/cadets').resolve()
    groundtruth_path = e3_root / 'cadets.txt'
    output_root = Path('/home/john/yzx/EBLIT/data/processed/gmae_e3_pretrain_only').resolve()
    e3_windows_dir = output_root / 'e3_windows'
    e3_manifest_path = output_root / 'gmae_e3_manifest.json'
    output_root.mkdir(parents=True, exist_ok=True)
    e3_windows_dir.mkdir(parents=True, exist_ok=True)

    e3_results, e3_summary = build_e3_windows(
        e3_dir=str(e3_root),
        groundtruth_path=str(groundtruth_path),
        window_seconds=1800,
        stride_seconds=600,
        time_bin_seconds=60,
        max_windows=0,
        emit_partial=False,
    )

    e3_records = []
    for idx, item in enumerate(e3_results, start=1):
        graph = _filter_training_graph(item.graph)
        window_id = f'e3_window_{idx:06d}'
        output_path = e3_windows_dir / f'{window_id}.json'
        dump_window_graph(str(output_path), graph)
        e3_records.append(
            _build_manifest_record(
                window_id,
                str(output_path),
                graph,
                source_log_file=str(e3_root),
                source_run_id=item.source_run_id,
                source_profile=item.source_profile,
                split_role=item.split_role,
            )
        )

    e3_manifest = _write_gmae_manifest(
        manifest_path=str(e3_manifest_path),
        log_file='',
        logs_dir=str(e3_root),
        source_mode='e3_cadets_pretrain',
        sources=_e3_manifest_sources(e3_root),
        windows_dir=str(e3_windows_dir),
        persist_windows=True,
        window_seconds=1800,
        reduction_config={
            'window_seconds': 1800,
            'stride_seconds': 600,
            'time_bin_seconds': 60,
            'edge_key_mode': 'event_time_bin',
        },
        records=e3_records,
    )
    e3_manifest['summary']['excluded_attack_window_count'] = int(e3_summary.get('excluded_attack_window_count') or 0)
    write_json(str(e3_manifest_path), e3_manifest)

    runtime = _init_gmae_runtime()
    runtime['config'] = dict(runtime.get('config') or {})
    runtime['config']['feature_profile'] = 'transfer_v1'
    runtime['epochs'] = 5
    training_result = _train_gmae_from_manifest(runtime, str(e3_manifest_path))
    _save_named_gmae_runtime(
        runtime=runtime,
        manifest_payload=e3_manifest,
        training_result=training_result,
        checkpoint_path=KB_PATHS.gmae_e3_pretrained_path,
        meta_path=KB_PATHS.gmae_e3_pretrained_meta_path,
        calibration_path=KB_PATHS.gmae_calibration_path,
        process_error_calibration_path=KB_PATHS.process_error_calibration_path,
        context={
            'stage': 'e3_pretrain',
            'mode': TRANSFER_GMAE_CONTEXT_TAG,
            'e3_dir': str(e3_root),
            'groundtruth': str(groundtruth_path),
            'pretrain_only': True,
        },
    )
    print({
        'output_root': str(output_root),
        'manifest_path': str(e3_manifest_path),
        'window_count': len(e3_records),
        'e3_summary': e3_summary,
        'saved_baseline': bool(training_result.get('saved_baseline')),
        'best_epoch': training_result.get('best_epoch'),
        'best_metric_value': training_result.get('best_metric_value'),
        'rejected_reason': training_result.get('rejected_reason'),
        'quality_gate_errors': training_result.get('quality_gate_errors'),
    })

if __name__ == '__main__':
    main()

