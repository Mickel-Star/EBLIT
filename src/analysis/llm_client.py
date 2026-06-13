#!/usr/bin/env python3
"""
LLM客户端模块
处理与大语言模型的交互
"""

import os
import abc
import json
from typing import Dict, Any, Optional

class LLMClient(abc.ABC):
    """LLM客户端基类"""
    
    @abc.abstractmethod
    def generate_report(self, prompt: str) -> str:
        """生成报告"""
        pass

class MockLLMClient(LLMClient):
    """模拟LLM客户端（用于测试或无API Key时）"""
    
    def generate_report(self, prompt: str) -> str:
        return f"""
[MOCK REPORT]
Based on the provided context, the process appears suspicious.
...
(This is a mock response because the LLM API request failed or no Key was configured)
"""

class OpenAILLMClient(LLMClient):
    """OpenAI兼容的LLM客户端（支持 Mistral, Ollama, DeepSeek 等）"""
    
    def __init__(
        self,
        api_key: str,
        base_url: str = None,
        model: str = "gpt-3.5-turbo",
        timeout_seconds: int = 30,
        max_retries: int = 0,
    ):
        try:
            from openai import OpenAI
            # 兼容性处理：如果是 Ollama，api_key 可以是任意值
            if not api_key and "localhost" in (base_url or ""):
                api_key = "ollama"
                
            self.client = OpenAI(
                api_key=api_key,
                base_url=base_url,
                timeout=timeout_seconds,
                max_retries=max_retries,
            )
            self.model = model
            self.timeout_seconds = int(timeout_seconds)
            self._timeouts = 0
            self._disabled = False
        except ImportError:
            raise ImportError("Please install 'openai' package: pip install openai")

    def generate_report(self, prompt: str) -> str:
        if self._disabled:
            return MockLLMClient().generate_report(prompt)
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert specializing in intrusion detection and provenance analysis."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                timeout=self.timeout_seconds,
            )
            return response.choices[0].message.content
        except Exception as e:
            err = str(e)
            if "Request timed out" in err or "Read timed out" in err or "timed out" in err:
                self._timeouts += 1
                if self._timeouts >= 3:
                    self._disabled = True
            if "Connection error" in err or "handshake" in err:
                self._disabled = True
            error_msg = f"Warning: OpenAI API request failed: {e}. Falling back to Mock client."
            print(error_msg)
            return MockLLMClient().generate_report(prompt) + f"\n\n[System Error Details]: {str(e)}"

def get_llm_client() -> LLMClient:
    """获取配置的LLM客户端"""
    # 0. 计算项目根目录
    current_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.abspath(os.path.join(current_dir, '../../'))

    proxy_port = (os.environ.get("PROXY_PORT") or "").strip()
    has_proxy = any(
        (os.environ.get(k) or "").strip()
        for k in ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "https_proxy", "http_proxy", "all_proxy")
    )
    if proxy_port and not has_proxy:
        os.environ.setdefault("HTTP_PROXY", f"http://127.0.0.1:{proxy_port}")
        os.environ.setdefault("HTTPS_PROXY", f"http://127.0.0.1:{proxy_port}")
        os.environ.setdefault("ALL_PROXY", f"http://127.0.0.1:{proxy_port}")
    
    # 1. 尝试从配置文件读取（支持本地覆盖：config.local.json）
    config_path = os.path.join(project_root, 'config', 'config.json')
    config_local_path = os.path.join(project_root, 'config', 'config.local.json')
    file_config = {}
    try:
        full_config = {}
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                full_config = json.load(f) or {}
        if os.path.exists(config_local_path):
            with open(config_local_path, 'r') as f:
                local_cfg = json.load(f) or {}
            if isinstance(local_cfg, dict):
                for k, v in local_cfg.items():
                    full_config[k] = v

        llm_cfg = (full_config.get('llm', {}) or {}) if isinstance(full_config, dict) else {}
        if isinstance(llm_cfg.get("providers"), dict):
            provider = (llm_cfg.get("provider") or llm_cfg.get("active_provider") or "").strip()
            if provider and provider in llm_cfg["providers"]:
                file_config = llm_cfg["providers"][provider] or {}
            else:
                file_config = llm_cfg["providers"].get("mistral") or next(iter(llm_cfg["providers"].values()), {}) or {}
        else:
            file_config = llm_cfg
    except Exception as e:
        print(f"Warning: Failed to load config: {e}")

    api_type = (file_config.get("api_type") or "").strip().lower()
    api_key = (file_config.get("api_key") or "").strip()
    api_key_env = (file_config.get("api_key_env") or "").strip()
    base_url = (file_config.get("base_url") or "").strip()
    model = (file_config.get("model") or "").strip()
    timeout_seconds = int(file_config.get("timeout_seconds") or 30)
    max_retries = int(file_config.get("max_retries") or 0)
    timeout_override = (os.environ.get("LLM_TIMEOUT_SECONDS") or "").strip()
    if timeout_override:
        try:
            timeout_seconds = int(timeout_override)
        except Exception:
            pass
    retries_override = (os.environ.get("LLM_MAX_RETRIES") or "").strip()
    if retries_override:
        try:
            max_retries = int(retries_override)
        except Exception:
            pass

    if api_type == "deepseek":
        api_key_env = api_key_env or "DEEPSEEK_API_KEY"
        base_url = base_url or "https://api.deepseek.com/v1"
        model = model or "deepseek-chat"
        timeout_seconds = timeout_seconds or 60
        max_retries = max_retries or 1
    elif api_type == "mistral":
        api_key_env = api_key_env or "MISTRAL_API_KEY"
        base_url = base_url or "https://api.mistral.ai/v1"
        model = model or "mistral-large-latest"

    if not api_key:
        if api_key_env:
            api_key = (os.environ.get(api_key_env) or "").strip()
        if not api_key:
            api_key = (
                os.environ.get("DEEPSEEK_API_KEY")
                or os.environ.get("MISTRAL_API_KEY")
                or os.environ.get("OPENAI_API_KEY")
                or ""
            ).strip()

    if not base_url:
        base_url = (os.environ.get("DEEPSEEK_BASE_URL") or os.environ.get("MISTRAL_BASE_URL") or os.environ.get("OPENAI_BASE_URL") or "").strip()
    if not model:
        model = (os.environ.get("LLM_MODEL") or os.environ.get("DEEPSEEK_MODEL") or os.environ.get("MISTRAL_MODEL") or "").strip()
    
    # 自动检测 Mistral/Ollama 配置 (仅当没有配置 API Key 时)
    if not api_key and not base_url:
        # 尝试默认的 Ollama 配置
        import requests
        try:
            # 检查本地 Ollama 是否运行
            requests.get("http://localhost:11434", timeout=0.5)
            print("Detected local Ollama instance, using Mistral (or specified model).")
            api_key = "ollama"
            base_url = "http://localhost:11434/v1"
            model = model or "mistral"
        except:
            pass

    if base_url and not api_key and "localhost" not in base_url:
        print("No LLM API key found for the configured provider. Using Mock client.")
        return MockLLMClient()

    if api_key or base_url:
        try:
            # 仅当使用本地 Ollama 时允许无 api_key
            if base_url and not api_key and "localhost" in base_url:
                api_key = "ollama"
            
            return OpenAILLMClient(
                api_key=api_key, 
                base_url=base_url, 
                model=model or "gpt-3.5-turbo",
                timeout_seconds=timeout_seconds,
                max_retries=max_retries,
            )
        except ImportError:
            print("Warning: 'openai' package not found, falling back to Mock client.")
            return MockLLMClient()
    else:
        print("No LLM configuration found (OPENAI_API_KEY or local Ollama). Using Mock client.")
        return MockLLMClient()
