#!/usr/bin/python3

import json
import logging

import urllib3
import base64

import argparse

logger = logging.getLogger(__name__)


class Client:
    def __init__(self, token: str, secret: str):
        """
        See the documentation at https://api.domeneshop.no/docs/ for
        help on how to acquire your API credentials.
        :param token: The API client token
        :type token: str
        :param secret: The API client secret
        :type secret: str
        """

        self._headers = {
            "Authorization": "Basic {}".format(
                base64.b64encode("{}:{}".format(
                    token, secret).encode()).decode()
            ),
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "domeneshop-python/0.4.2",
        }
        self._http = urllib3.HTTPSConnectionPool(
            "api.domeneshop.no", 443, maxsize=5, block=True, headers=self._headers
        )

    def get_domains(self):
        """
        Retrieve a list of all domains.
        :return: A list of domain dictionaries
        """
        resp = self._request("GET", "/domains")
        domains = json.loads(resp.data.decode('utf-8'))
        return domains

    # DNS records

    def get_records(self, domain_id: int):
        """
        Retrieve DNS records for a domain, or raises an error.

        :param domain_id: The domain ID to operate on
        :return: A list of record dictionaries
        """
        resp = self._request("GET", "/domains/{0}/dns".format(domain_id))
        records = json.loads(resp.data.decode('utf-8'))
        return records

    def update_dyndns(self, domain_name: str, myip: None):
        """
        dyndns update
        """
        if myip is None:
            self._request(
                "GET", "/dyndns/update?hostname={0}".format(domain_name))
        else:
            self._request(
                "GET", "/dyndns/update?hostname={0}&myip={1}".format(domain_name, myip))

    def _request(self, method="GET", endpoint="/", data=None):
        if data is not None:
            data = json.dumps(data).encode("utf-8")
        try:
            resp = self._http.request(method, "/v0" + endpoint, body=data)
            if resp.status >= 400:
                try:
                    data = json.loads(resp.data.decode('utf-8'))
                except json.JSONDecodeError:
                    data = {"error": resp.status,
                            "help": "A server error occurred."}
                raise DomeneshopError(resp.status, data) from None
        except urllib3.exceptions.HTTPError as e:
            raise e
        else:
            return resp


class DomeneshopError(Exception):
    def __init__(self, status_code: int, error: dict):
        """
        Exception raised for API errors.
            :param status_code: The HTTP status code
            :type status_code: int
            :param error: The error returned from the API
            :type error: dict
        """
        self.status_code = status_code
        self.error_code = error.get("code")
        self.help = error.get("help")

        error_message = "{0} {1}. {2}".format(
            self.status_code, self.error_code, self.help
        )

        super().__init__(error_message)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Domeneshop dynamic dns parser")
    parser.add_argument("-t", "--token", type=str,
                        help="Domeneshop token", required=True)
    parser.add_argument("-s", "--secret", type=str,
                        help="Domeneshop secret", required=True)
    parser.add_argument("-d", "--domain_name", type=str,
                        help="Domain name for dyndns", required=True)

    args = parser.parse_args()

    print(args)
    client = Client(args.token, args.secret)
    client.update_dyndns(args.domain_name, None)

    # verify domain
    domains = client.get_domains()
    id = None
    base_domain = args.domain_name.replace(
        args.domain_name.split(".")[0]+".", "")
    for domain in domains:
        if domain["domain"] == base_domain:
            id = domain["id"]
            break

    print(client.get_records(id))
