"""Lazy local Transformers inference shared by the answer and safety models."""
import logging
import threading
from typing import Any

logger = logging.getLogger(__name__)


class TransformersRuntime:
    def __init__(self, model_id: str):
        self.model_id = model_id
        self._model: Any = None
        self._tokenizer: Any = None
        self._torch: Any = None
        self._load_lock = threading.Lock()
        self._generation_lock = threading.Lock()
        self._last_error: str | None = None

    def _load(self) -> None:
        if self._model is not None:
            return

        with self._load_lock:
            if self._model is not None:
                return

            try:
                import torch
                from transformers import AutoModelForCausalLM, AutoTokenizer
            except ImportError as exc:
                self._last_error = type(exc).__name__
                raise RuntimeError(
                    "Local inference dependencies are missing. Install "
                    "backend/requirements-local.txt to enable local models."
                ) from exc

            try:
                tokenizer = AutoTokenizer.from_pretrained(self.model_id, token=False)
                model = AutoModelForCausalLM.from_pretrained(
                    self.model_id,
                    token=False,
                    torch_dtype="auto",
                    device_map="auto",
                    low_cpu_mem_usage=True,
                )
                model.eval()
            except Exception as exc:
                self._last_error = type(exc).__name__
                raise

            self._torch = torch
            self._tokenizer = tokenizer
            self._model = model
            self._last_error = None

            device_map = getattr(model, "hf_device_map", None)
            if device_map:
                placement: Any = device_map
            else:
                placement = str(model.device)
            cuda_available = bool(torch.cuda.is_available())
            gpu_name = torch.cuda.get_device_name(0) if cuda_available else None
            logger.info(
                "Loaded local model %s (dtype=%s, placement=%s, cuda=%s, gpu=%s)",
                self.model_id,
                getattr(model, "dtype", "unknown"),
                placement,
                cuda_available,
                gpu_name,
            )

    def generate(self, messages: list[dict[str, str]], max_new_tokens: int) -> str:
        with self._generation_lock:
            self._load()
            try:
                inputs = self._tokenizer.apply_chat_template(
                    messages,
                    tokenize=True,
                    add_generation_prompt=True,
                    return_tensors="pt",
                    return_dict=True,
                ).to(self._model.device)
                generation_args = {
                    "max_new_tokens": max_new_tokens,
                    "do_sample": False,
                }
                eos_token_id = getattr(self._tokenizer, "eos_token_id", None)
                if eos_token_id is not None:
                    generation_args["pad_token_id"] = eos_token_id

                with self._torch.inference_mode():
                    outputs = self._model.generate(**inputs, **generation_args)

                input_length = inputs["input_ids"].shape[-1]
                answer = self._tokenizer.decode(
                    outputs[0, input_length:],
                    skip_special_tokens=True,
                    clean_up_tokenization_spaces=False,
                ).strip()
                if not answer:
                    raise RuntimeError(f"Model {self.model_id} returned an empty response.")
                self._last_error = None
                return answer
            except Exception as exc:
                self._last_error = type(exc).__name__
                raise

    def diagnostics(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "model_id": self.model_id,
            "loaded": self._model is not None,
            "device_map": None,
            "dtype": None,
            "runtime_available": False,
            "runtime_message": None,
            "cuda_available": None,
            "gpu_name": None,
            "gpu_memory_allocated_gib": None,
            "gpu_memory_reserved_gib": None,
            "last_error": self._last_error,
        }
        try:
            import torch
            import transformers  # noqa: F401
        except ImportError:
            result["runtime_message"] = (
                "Install backend/requirements-local.txt to enable local models."
            )
            return result

        result["runtime_available"] = True
        cuda_available = bool(torch.cuda.is_available())
        result["cuda_available"] = cuda_available
        if cuda_available:
            result["gpu_name"] = torch.cuda.get_device_name(0)
            result["gpu_memory_allocated_gib"] = round(
                torch.cuda.memory_allocated(0) / 1024**3, 2
            )
            result["gpu_memory_reserved_gib"] = round(
                torch.cuda.memory_reserved(0) / 1024**3, 2
            )
        if self._model is not None:
            device_map = getattr(self._model, "hf_device_map", None)
            result["device_map"] = (
                {str(key): str(value) for key, value in device_map.items()}
                if device_map
                else {"model": str(self._model.device)}
            )
            result["dtype"] = str(getattr(self._model, "dtype", "unknown"))
        result["last_error"] = self._last_error
        return result
