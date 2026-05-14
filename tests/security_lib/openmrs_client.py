import os
from typing import Optional, Dict, Any

import requests


class OpenMRSClient:
    def __init__(
        self,
        base_url: Optional[str] = None,
        rest_url: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        timeout: int = 30,
    ):
        self.base_url = (base_url or os.getenv("O3_BASE_URL", "http://localhost/openmrs")).rstrip("/")
        self.rest_url = (rest_url or os.getenv("O3_REST_URL", self.base_url + "/ws/rest/v1")).rstrip("/")
        self.username = (
            username
            or os.getenv("O3_TEST_USERNAME")
            or os.getenv("O3_ADMIN_USERNAME")
            or "admin"
        )
        self.password = (
            password
            or os.getenv("O3_TEST_PASSWORD")
            or os.getenv("O3_ADMIN_PASSWORD")
            or "Admin123"
        )
        self.timeout = timeout
        self.session = requests.Session()

    def credentials_configured(self) -> bool:
        return bool(self.username and self.password)

    def login(self) -> requests.Response:
        if not self.credentials_configured():
            raise RuntimeError("OpenMRS credentials are not configured in environment variables.")

        url = self.base_url + "/login.htm"
        data = {
            "uname": self.username,
            "pw": self.password,
        }

        response = self.session.post(url, data=data, timeout=self.timeout)
        return response

    def logout(self) -> requests.Response:
        url = self.base_url + "/logout"
        response = self.session.get(url, timeout=self.timeout)
        return response

    def get_session(self) -> requests.Response:
        url = self.rest_url + "/session"
        response = self.session.get(url, timeout=self.timeout)
        return response

    def get_system_information(self) -> requests.Response:
        url = self.rest_url + "/systeminformation"
        response = self.session.get(url, timeout=self.timeout)
        return response

    def describe_configuration(self) -> Dict[str, Any]:
        return {
            "base_url": self.base_url,
            "rest_url": self.rest_url,
            "username_configured": bool(self.username),
            "password_configured": bool(self.password),
            "timeout": self.timeout,
        }