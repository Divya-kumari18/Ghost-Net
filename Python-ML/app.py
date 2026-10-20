from __future__ import annotations

import importlib.util
import os
import sys
import hmac
import joblib
import sklearn
import warnings
from sklearn.exceptions import InconsistentVersionWarning
import numpy as np
from pathlib import Path
from threading import RLock
from typing import Any

import pandas as pd
from flask import Flask, jsonify, request
import static_model
from sequence_model import SequenceModel
STATIC_MODEL_PATH=Path(os.getenv("STATIC_MALWARE_MODEL",str(Path(__file__).resolve().parent/"data"/"static-malware.joblib")))
SEQUENCE_MODEL=SequenceModel(Path(__file__).resolve().parent/"data"/"cnn-lstm")

ROOT_DIR = Path(__file__).resolve().parent
MALWARE_DIR = ROOT_DIR / "Malware Detection Model"
ANOMALY_DIR = ROOT_DIR / "Anomly Detection Model"
YARA_DIR = ROOT_DIR / "Yara Detection Model"
DEFAULT_YARA_RULES_DIR = YARA_DIR / "Rules"


def _load_module(module_name: str, module_path: Path):
    if not module_path.exists():
        raise FileNotFoundError(f"Module not found: {module_path}")
    spec = importlib.util.spec_from_file_location(module_name, str(module_path))
    if spec is None or spec.loader is None:
        raise ImportError(f"Could not create import spec for {module_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 4 * 1024 * 1024
API_KEY = os.getenv('GHOSTNET_ML_API_KEY', '')
SCAN_ROOTS = [Path(p).resolve() for p in os.getenv('GHOSTNET_SCAN_ROOTS', str(ROOT_DIR.parent / 'uploads')).split(os.pathsep) if p]

@app.before_request
def authenticate():
    if request.path not in {'/', '/api/health'}:
        if not API_KEY or not hmac.compare_digest(request.headers.get('X-API-Key', ''), API_KEY):
            return jsonify({'error': 'Valid service API key required'}), 401

def allowed_file(raw):
    path = Path(str(raw)).expanduser().resolve(strict=True)
    if not path.is_file() or not any(path.is_relative_to(root) for root in SCAN_ROOTS):
        raise ValueError('File must be within a configured GHOSTNET_SCAN_ROOTS directory')
    return path

def allowed_rules(raw=None):
    path = Path(raw).expanduser().resolve(strict=True) if raw else DEFAULT_YARA_RULES_DIR.resolve()
    if path != DEFAULT_YARA_RULES_DIR.resolve():
        raise ValueError('Request cannot override the configured rule directory')
    return path

@app.errorhandler(ValueError)
def invalid_input(ex):
    return jsonify({'error': str(ex)}), 400


# Malware model integration
_malware_err: str | None = None
_malware_predict_fn = None

try:
    malware_predict_mod = _load_module("ghostnet_malware_predict", MALWARE_DIR / "predict.py")
    _malware_predict_fn = getattr(malware_predict_mod, "predict", None)
    if _malware_predict_fn is None:
        raise RuntimeError("Missing predict() in Malware Detection Model/predict.py")
except Exception as ex:
    _malware_err = str(ex)


# YARA integration
_yara_err: str | None = None
_yara_load_rules = None
_yara_scan_file = None
_yara_rules_cache: dict[str, Any] = {}

try:
    yara_core_mod = _load_module("ghostnet_yara_core", YARA_DIR / "yaradetect" / "core.py")
    _yara_load_rules = getattr(yara_core_mod, "load_rules_from_dir", None)
    _yara_scan_file = getattr(yara_core_mod, "scan_file", None)
    if _yara_load_rules is None or _yara_scan_file is None:
        raise RuntimeError("Missing load_rules_from_dir() or scan_file() in YARA core module")
except Exception as ex:
    _yara_err = str(ex)


# Anomaly integration
_anomaly_err: str | None = None


class AnomalyService:
    def __init__(self) -> None:
        self._lock = RLock()
        self._detector = None
        self._scaler = None
        self._feature_cols: list[str] = []
        self._encoders: dict[str, Any] = {}
        self._baseline_rows: int = 0
        self._load_error = None
        self._state_path = Path(os.getenv('IDS_MODEL_PATH', str(ROOT_DIR / 'data' / 'anomaly.joblib')))

        self._mod = _load_module("ghostnet_ids_anomaly", ANOMALY_DIR / "idsanomly.py")
        self._fit_preprocessor = getattr(self._mod, "fit_preprocessor")
        self._transform_records = getattr(self._mod, "transform_records")
        self._IsolationForestDetector = getattr(self._mod, "IsolationForestDetector")
        if self._state_path.exists():
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter('error', InconsistentVersionWarning)
                    bundle = joblib.load(self._state_path)
                if not isinstance(bundle,dict) or bundle.get('sklearn_version')!=sklearn.__version__:
                    raise ValueError('Anomaly artifact/runtime mismatch; retrain the baseline')
                self._detector, self._scaler, self._feature_cols, self._encoders, self._baseline_rows = bundle['state']
            except Exception as ex:
                self._load_error=str(ex)

    def train(self, baseline_df: pd.DataFrame, contamination: float = 0.05) -> dict[str, Any]:
        if len(baseline_df) < 20:
            raise ValueError("At least 20 baseline records are required")
        if not 0 < contamination <= 0.5:
            raise ValueError("contamination must be in (0, 0.5]")

        with self._lock:
            X_train, scaler, feature_cols, encoders = self._fit_preprocessor(baseline_df)
            detector = self._IsolationForestDetector(contamination=contamination)
            if not np.isfinite(X_train).all():
                raise ValueError('Training features must be finite')
            detector.fit(X_train)
            self._state_path.parent.mkdir(parents=True, exist_ok=True)
            temporary = self._state_path.with_suffix('.tmp')
            joblib.dump({'sklearn_version':sklearn.__version__,'state':(detector, scaler, list(feature_cols), dict(encoders), len(baseline_df))}, temporary)
            temporary.replace(self._state_path)

            self._detector = detector
            self._scaler = scaler
            self._feature_cols = list(feature_cols)
            self._encoders = dict(encoders)
            self._baseline_rows = int(len(baseline_df))
            self._load_error = None

            return {
                "trained": True,
                "baselineRows": self._baseline_rows,
                "featureCount": len(self._feature_cols),
                "error": self._load_error,
                "contamination": contamination,
            }

    def is_ready(self) -> bool:
        with self._lock:
            return self._detector is not None

    def state(self) -> dict[str, Any]:
        with self._lock:
            return {
                "ready": self._detector is not None,
                "baselineRows": self._baseline_rows,
                "featureCount": len(self._feature_cols),
                "error": self._load_error,
            }

    def detect(self, records_df: pd.DataFrame) -> list[dict[str, Any]]:
        if records_df.empty:
            return []

        with self._lock:
            if self._detector is None or self._scaler is None:
                raise RuntimeError("Anomaly model is not trained")

            missing = set(self._feature_cols) - set(records_df.columns)
            if missing:
                raise ValueError(f'Missing trained features: {sorted(missing)}')
            X_scaled = self._transform_records(
                records_df,
                self._feature_cols,
                self._scaler,
                self._encoders,
            )
            if not np.isfinite(X_scaled).all():
                raise ValueError('Inference features must be finite')
            preds = self._detector.predict(X_scaled)
            scores = self._detector.score_samples(X_scaled)

        output: list[dict[str, Any]] = []
        for i, pred in enumerate(preds):
            output.append(
                {
                    "index": i,
                    "anomaly": bool(pred == 1),
                    "anomaly_flag": int(pred),
                    "anomaly_score": float(round(float(scores[i]), 6)),
                }
            )
        return output


_anomaly_service = None
try:
    _anomaly_service = AnomalyService()
except Exception as ex:
    _anomaly_err = str(ex)


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        if value is None:
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def _scan_file_with_malware(file_path: Path) -> dict[str, Any]:
    if not STATIC_MODEL_PATH.exists():
        raise ValueError('No trained static-file model. Use YARA or train static_model.py on labeled files.')
    return static_model.predict(file_path,STATIC_MODEL_PATH)


def _load_rules_cached(rules_dir: Path):
    key = str(rules_dir.resolve()) + str([(str(p), p.stat().st_mtime_ns, p.stat().st_size) for p in sorted(rules_dir.rglob("*")) if p.is_file()])
    if key in _yara_rules_cache:
        return _yara_rules_cache[key]
    if _yara_load_rules is None:
        raise RuntimeError(_yara_err or "YARA engine is unavailable")
    rules = _yara_load_rules(rules_dir)
    _yara_rules_cache.clear()
    _yara_rules_cache[key] = rules
    return rules


def _scan_file_with_yara(file_path: Path, rules_dir: Path) -> dict[str, Any]:
    if _yara_scan_file is None:
        raise RuntimeError(_yara_err or "YARA engine is unavailable")

    rules = _load_rules_cached(rules_dir)
    result = _yara_scan_file(rules, file_path)
    matched_rules = result.get("matched_rules", [])

    return {
        "status": "ok",
        "source": "yara",
        "filePath": str(file_path),
        "rulesDir": str(rules_dir),
        "matched": len(matched_rules) > 0,
        "matchCount": len(matched_rules),
        "matchedRules": matched_rules,
        "matches": result.get("matches", {}),
        "details": {"rulesLoaded": len(rules)},
    }


def _parse_records(payload: dict[str, Any]) -> list[dict[str, Any]]:
    if isinstance(payload.get("records"), list):
        return [r for r in payload["records"] if isinstance(r, dict)]
    if isinstance(payload.get("samples"), list):
        return [r for r in payload["samples"] if isinstance(r, dict)]
    if isinstance(payload.get("record"), dict):
        return [payload["record"]]
    if isinstance(payload.get("features"), dict):
        return [payload["features"]]
    return []


def _load_baseline_if_configured() -> str | None:
    if _anomaly_service is None:
        return _anomaly_err or "Anomaly service unavailable"

    baseline_path = os.getenv("IDS_BASELINE_CSV", "").strip()
    if not baseline_path:
        return None

    path = Path(baseline_path).expanduser().resolve()
    if not path.exists() or not path.is_file():
        return f"Configured IDS_BASELINE_CSV not found: {path}"

    df = pd.read_csv(path)
    _anomaly_service.train(df)
    return None


_baseline_init_err = _load_baseline_if_configured()


@app.route("/", methods=["GET"])
def index():
    return jsonify(
        {
            "service": "ghostnet-ml-unified",
            "status": "ok",
            "endpoints": [
                "/api/health",
                "/api/scan-file",
                "/api/malware/scan-file",
                "/api/yara/scan-file",
                "/api/anomaly/detect",
                "/api/anomaly/batch",
                "/api/anomaly/train",
                "/api/model/retrain",
            ],
        }
    )


@app.route("/api/health", methods=["GET"])
def health():
    anomaly_state = _anomaly_service.state() if _anomaly_service else {"ready": False}
    yara_error = _yara_err
    if yara_error is None:
        try:
            _load_rules_cached(DEFAULT_YARA_RULES_DIR)
        except Exception as ex:
            yara_error = str(ex)
    return jsonify(
        {
            "status": "ok",
            "services": {
                "malware": {"ready": _malware_err is None, "inputType": "linux-process-telemetry", "fileScanReady": STATIC_MODEL_PATH.exists(), "error": _malware_err},
                "yara": {
                    "ready": yara_error is None,
                    "error": yara_error,
                    "defaultRulesDir": str(DEFAULT_YARA_RULES_DIR),
                },
                "sequence": {"ready":SEQUENCE_MODEL.model is not None,"error":SEQUENCE_MODEL.error},
                "anomaly": {
                    **anomaly_state,
                    "error": _anomaly_err or _baseline_init_err or anomaly_state.get('error'),
                },
            },
        }
    )


@app.route("/api/malware/scan-file", methods=["POST"])
@app.route("/api/scan-file", methods=["POST"])
def malware_or_compat_scan_file():
    try:
        body = request.get_json(silent=True) or {}
        file_path_raw = body.get("filePath")
        if not file_path_raw:
            return jsonify({"error": "filePath is required"}), 400

        file_path = allowed_file(file_path_raw)
        if not file_path.exists() or not file_path.is_file():
            return jsonify({"error": f"File not found or not a regular file: {file_path}"}), 400

        # Compatibility mode:
        # If caller includes rulesDir (as Java YARA integration does), treat as YARA scan.
        if body.get("rulesDir") or str(body.get("engine", "")).lower() == "yara":
            rules_dir_raw = body.get("rulesDir")
            rules_dir = allowed_rules(rules_dir_raw)
            if not rules_dir.exists() or not rules_dir.is_dir():
                return jsonify({"error": f"Rules directory not found: {rules_dir}"}), 400
            return jsonify(_scan_file_with_yara(file_path, rules_dir)), 200

        return jsonify(_scan_file_with_malware(file_path)), 200
    except (ValueError, FileNotFoundError) as ex:
        return jsonify({"error": str(ex)}), 400
    except Exception as ex:
        app.logger.exception("Detection request failed")
        return jsonify({"error": "Detection engine unavailable; no verdict issued"}), 503


@app.route("/api/yara/scan-file", methods=["POST"])
def yara_scan_file_api():
    try:
        body = request.get_json(silent=True) or {}
        file_path_raw = body.get("filePath")
        if not file_path_raw:
            return jsonify({"error": "filePath is required"}), 400

        rules_dir_raw = body.get("rulesDir")
        rules_dir = allowed_rules(rules_dir_raw)
        file_path = allowed_file(file_path_raw)

        if not file_path.exists() or not file_path.is_file():
            return jsonify({"error": f"File not found or not a regular file: {file_path}"}), 400
        if not rules_dir.exists() or not rules_dir.is_dir():
            return jsonify({"error": f"Rules directory not found: {rules_dir}"}), 400

        return jsonify(_scan_file_with_yara(file_path, rules_dir)), 200
    except (ValueError, FileNotFoundError) as ex:
        return jsonify({"error": str(ex)}), 400
    except Exception as ex:
        app.logger.exception("Detection request failed")
        return jsonify({"error": "Detection engine unavailable; no verdict issued"}), 503


@app.route("/api/anomaly/train", methods=["POST"])
def anomaly_train():
    try:
        if _anomaly_service is None:
            return jsonify({"error": _anomaly_err or "Anomaly service unavailable"}), 500

        body = request.get_json(silent=True) or {}
        contamination = _safe_float(body.get("contamination"), 0.05)

        records = _parse_records(body)
        baseline_csv = body.get("baselineCsvPath")

        if records:
            baseline_df = pd.DataFrame(records)
        elif baseline_csv:
            baseline_df = pd.read_csv(allowed_file(baseline_csv))
        else:
            return jsonify({"error": "Provide records/samples/record/features or baselineCsvPath"}), 400

        result = _anomaly_service.train(baseline_df, contamination=contamination)
        return jsonify({"status": "ok", **result}), 200
    except (ValueError, FileNotFoundError) as ex:
        return jsonify({"error": str(ex)}), 400
    except Exception as ex:
        app.logger.exception("Detection request failed")
        return jsonify({"error": "Detection engine unavailable; no verdict issued"}), 503


@app.route("/api/anomaly/detect", methods=["POST"])
def anomaly_detect():
    try:
        if _anomaly_service is None:
            return jsonify({"error": _anomaly_err or "Anomaly service unavailable"}), 500

        body = request.get_json(silent=True) or {}
        records = _parse_records(body)
        if not records:
            return jsonify({"error": "Missing record/features payload"}), 400

        if not _anomaly_service.is_ready():
            return (
                jsonify(
                    {
                        "error": "Anomaly model is not trained",
                        "hint": "Call /api/anomaly/train",
                    }
                ),
                503,
            )

        detections = _anomaly_service.detect(pd.DataFrame(records))
        first = detections[0] if detections else {"anomaly": False, "anomaly_score": 0.0}

        return (
            jsonify(
                {
                    "status": "ok",
                    "anomaly": first.get("anomaly", False),
                    "anomaly_flag": first.get("anomaly_flag", 0),
                    "anomaly_score": first.get("anomaly_score", 0.0),
                    "details": first,
                }
            ),
            200,
        )
    except (ValueError, FileNotFoundError) as ex:
        return jsonify({"error": str(ex)}), 400
    except Exception as ex:
        app.logger.exception("Detection request failed")
        return jsonify({"error": "Detection engine unavailable; no verdict issued"}), 503


@app.route("/api/anomaly/batch", methods=["POST"])
def anomaly_batch():
    try:
        if _anomaly_service is None:
            return jsonify({"error": _anomaly_err or "Anomaly service unavailable"}), 500

        body = request.get_json(silent=True) or {}
        records = _parse_records(body)
        if not records:
            return jsonify({"error": "Missing records/samples payload"}), 400

        if not _anomaly_service.is_ready():
            return (
                jsonify(
                    {
                        "error": "Anomaly model is not trained",
                        "hint": "Call /api/anomaly/train",
                    }
                ),
                503,
            )

        detections = _anomaly_service.detect(pd.DataFrame(records))
        alert_count = sum(1 for item in detections if item.get("anomaly"))

        return (
            jsonify(
                {
                    "status": "ok",
                    "count": len(detections),
                    "alerts": alert_count,
                    "results": detections,
                }
            ),
            200,
        )
    except (ValueError, FileNotFoundError) as ex:
        return jsonify({"error": str(ex)}), 400
    except Exception as ex:
        app.logger.exception("Detection request failed")
        return jsonify({"error": "Detection engine unavailable; no verdict issued"}), 503


@app.route("/api/model/retrain", methods=["POST"])
def model_retrain():
    try:
        if _anomaly_service is None:
            return jsonify({"error": _anomaly_err or "Anomaly service unavailable"}), 500

        body = request.get_json(silent=True) or {}
        model_type = str(body.get("type", "anomaly")).lower()
        if model_type not in {"anomaly", "ids"}:
            return jsonify({"error": f"Unsupported model type: {model_type}"}), 400

        samples = body.get("samples")
        if not isinstance(samples, list) or not samples:
            return jsonify({"error": "samples must be a non-empty array of records"}), 400

        baseline_df = pd.DataFrame([r for r in samples if isinstance(r, dict)])
        if baseline_df.empty:
            return jsonify({"error": "No valid sample records provided"}), 400

        result = _anomaly_service.train(baseline_df, contamination=_safe_float(body.get("contamination"), 0.05))
        return jsonify({"status": "ok", "model": "anomaly", **result}), 200
    except (ValueError, FileNotFoundError) as ex:
        return jsonify({"error": str(ex)}), 400
    except Exception as ex:
        app.logger.exception("Detection request failed")
        return jsonify({"error": "Detection engine unavailable; no verdict issued"}), 503


@app.route('/api/traffic/analyze',methods=['POST'])
def traffic_analyze():
    body=request.get_json(silent=True)
    if not isinstance(body,dict):
        raise ValueError('Request body must be a JSON object')
    records=body.get('records',[])
    if not isinstance(records,list) or not 1<=len(records)<=1000:
        raise ValueError('Provide 1..1000 traffic records')
    from sequence_model import FEATURES,STEPS
    missing=sorted({key for row in records if not isinstance(row,dict) for key in FEATURES})
    missing.extend(sorted({key for row in records if isinstance(row,dict) for key in FEATURES if key not in row}))
    if missing:
        raise ValueError(f'Missing traffic fields: {sorted(set(missing))}')
    features=pd.DataFrame([{key:row[key] for key in FEATURES} for row in records])
    if _anomaly_service is None or not _anomaly_service.is_ready():
        return jsonify({'error':'Train the anomaly baseline with the traffic feature schema first'}),503
    result=_anomaly_service.detect(features)
    if SEQUENCE_MODEL.model is not None:
        groups={}
        for index,row in enumerate(records):
            identity=(row.get('sourceIp'),row.get('destinationIp'),row['source_port'],row['destination_port'],row['protocol_id'])
            groups.setdefault(identity,[]).append(index)
        sequences=[];indexes=[]
        for group in groups.values():
            for end in range(STEPS,len(group)+1,STEPS):
                chunk=group[end-STEPS:end];sequences.append([[records[i][key] for key in FEATURES] for i in chunk]);indexes.append(chunk)
        if sequences:
            for chunk,probability in zip(indexes,SEQUENCE_MODEL.predict(sequences)):
                for i in chunk:
                    result[i]['cnn_lstm_probability']=probability
                    result[i]['anomaly']=bool(result[i]['anomaly'] and probability>=.5)
                    result[i]['ensemble']='isolation-forest-and-cnn-lstm'
    return jsonify({'results':result})

@app.route('/api/sequence/detect',methods=['POST'])
def sequence_detect():
    if SEQUENCE_MODEL.model is None:return jsonify({'error':SEQUENCE_MODEL.error}),503
    body=request.get_json() or {}
    return jsonify({'probabilities':SEQUENCE_MODEL.predict(body.get('sequences',[]))})

@app.route('/api/malware/predict',methods=['POST'])
def process_predict():
    if _malware_predict_fn is None:return jsonify({'error':'Process model unavailable; retrain with the installed runtime'}),503
    return jsonify(_malware_predict_fn((request.get_json() or {}).get('features',{})))

if __name__ == "__main__":
    host = os.getenv("ML_APP_HOST", "127.0.0.1")
    port = int(os.getenv("ML_APP_PORT", "5000"))
    app.run(host=host, port=port, debug=False)
