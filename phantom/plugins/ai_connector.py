import os
import json
import requests
from typing import Optional, Dict, Any
from phantom.modules.base_module import BaseModule
from phantom.utils.notifier import notifier

class AIConnectorPlugin(BaseModule):
    module_name = "ai_connector"

    def __init__(self):
        super().__init__()
        # Configuration from environment variables
        self.provider = os.getenv("AI_PROVIDER", "").lower()
        self.api_key = os.getenv("AI_API_KEY", "")
        self.endpoint = os.getenv("AI_ENDPOINT", "")
        self.model = os.getenv("AI_MODEL", "gpt-3.5-turbo" if self.provider == "openai" else "llama3")
        
        # Determine if AI is enabled
        self.enabled = self.provider in ["openai", "ollama"]
        if self.provider == "openai" and not self.api_key:
            self.enabled = False
        if self.provider == "ollama" and not self.endpoint:
            self.endpoint = "http://localhost:11434/api/chat"

    def _call_api(self, prompt: str, system_prompt: str = "You are a senior security researcher.") -> Optional[str]:
        """Generic API caller for OpenAI or Ollama."""
        if not self.enabled:
            return None

        try:
            if self.provider == "openai":
                headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
                payload = {
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": prompt}
                    ],
                    "temperature": 0.3
                }
                resp = requests.post("https://api.openai.com/v1/chat/completions", headers=headers, json=payload, timeout=30)
                resp.raise_for_status()
                return resp.json()["choices"][0]["message"]["content"].strip()

            elif self.provider == "ollama":
                payload = {
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": prompt}
                    ],
                    "stream": False,
                    "options": {"temperature": 0.3}
                }
                resp = requests.post(self.endpoint, json=payload, timeout=60)
                resp.raise_for_status()
                return resp.json()["message"]["content"].strip()

        except Exception as e:
            notifier.error(f"AI API call failed: {e}")
            return None
        return None

    def interpret_cve(self, cve_id: str, description: str) -> Optional[str]:
        """Logically parse CVE description for quick understanding."""
        if not self.enabled:
            return None

        system = "You are a CVE interpreter. Output only a concise Markdown list: Prereq, Complexity, Vector (RCE/LPE/etc)."
        prompt = f"Analyze this CVE:
ID: {cve_id}
Description: {description}"
        
        return self._call_api(prompt, system_prompt=system)

    def generate_executive_summary(self, session_data: Dict[str, Any]) -> Optional[str]:
        """Generate an AI-powered Executive Summary from session results."""
        if not self.enabled:
            return None

        # Clean session data for the prompt (keep it lightweight)
        clean_data = {
            "target": session_data.get("target"),
            "notes": session_data.get("notes", []),
            "results_keys": list(session_data.get("results", {}).keys())
        }
        
        system = "You are a Lead Pentester. Generate a structured Executive Summary in Markdown. Highlight critical points and suggest next steps."
        prompt = f"Session Data: {json.dumps(clean_data, indent=2)}

Generate report:"
        
        return self._call_api(prompt, system_prompt=system)
