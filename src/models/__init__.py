import importlib.util
import pathlib
import sys

_models_py = pathlib.Path(__file__).resolve().parent.parent / 'models.py'
if _models_py.exists():
    _Legacy = importlib.util.spec_from_file_location('src.models_legacy', _models_py)
    _Holder = importlib.util.module_from_spec(_Legacy)
    _Legacy.loader.exec_module(_Holder)
    sys.modules['src.models_legacy'] = _Holder
    ModelEvaluator = _Holder.ModelEvaluator  # noqa: F401