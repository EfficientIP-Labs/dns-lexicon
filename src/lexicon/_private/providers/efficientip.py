"""Module provider for EfficientIP SOLIDserver"""

import json
import logging
import re
import ipaddress
from argparse import ArgumentParser
from typing import List, Optional

import requests
import urllib3

from lexicon.exceptions import AuthenticationError
from lexicon.interfaces import Provider as BaseProvider

LOGGER = logging.getLogger(__name__)

_NAMESERVER_DOMAINS = []

# Simple FQDN/hostname validator (allows optional trailing dot)
_FQDN_REGEXP = re.compile(
	r"^(?=.{1,253}$)(?!-)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?$"
)

class Provider(BaseProvider):
	"""Provider class for EfficientIP SOLIDserver"""

	# Supported record types for EfficientIP REST operations (SRV not supported)
	SUPPORTED_RRTYPES = ["A", "AAAA", "CNAME", "TXT"]

	@staticmethod
	def get_nameservers() -> List[str]:
		return _NAMESERVER_DOMAINS

	@staticmethod
	def configure_parser(parser: ArgumentParser) -> None:
		parser.description = """
			EfficientIP provider scaffold. Configure authentication
			and API endpoint related options here.
		"""
		parser.add_argument(
			"--auth-username",
			help="specify username or token ID for authentication",
		)
		parser.add_argument(
			"--auth-password",
			help="specify API secret for authentication",
		)
		# FIXME - Support API Tokens
		# parser.add_argument(
		# 	"--auth-id",
		# 	help="specify username or token ID for authentication",
		# )
		# parser.add_argument(
		# 	"--auth-secret",
		# 	help="specify API secret for authentication",
		# )
		# parser.add_argument(
		# 	"--auth-method",
		# 	help="specify API authentication method (basic|token)",
		# )
		parser.add_argument(
			"--sds-host",
			help="specify the EfficientIP SOLIDserver hostname or IP address",
		)
		parser.add_argument(
			"--sds-dns",
			help="specify the managed DNS smart or server name",
		)
		parser.add_argument(
			"--sds-view",
			help="specify the managed DNS view name",
		)
		parser.add_argument(
			"--no-verify-ssl",
			action="store_true",
			help="disable SSL certificate verification for the SOLIDserver connection",
		)

	def __init__(self, config):
		super(Provider, self).__init__(config)
		self.domain_id: Optional[str] = None
		# Default API endpoint can be overridden via --api-endpoint
		self.sds_host = self._get_provider_option("sds_host")

	def authenticate(self):
		"""
		Authenticate against EfficientIP SOLIDserver using basic auth.
		Validate that the specified dns server is either a smart or a standalone DNS server.

		Requires `--auth-username`, `--auth-password` and `--sds-host`.
		Also reads `--sds-dns` and optional `--sds-view` which are used
		by the DNS RR endpoints.
		"""
		username = self._get_provider_option("auth_username")
		password = self._get_provider_option("auth_password")
		self.sds_host = self.sds_host or self._get_provider_option("sds_host")
		self.sds_dns = self._get_provider_option("sds_dns")
		self.sds_view = self._get_provider_option("sds_view")

		if not username or not password:
			raise AuthenticationError("`auth_username` and `auth_password` are required for EfficientIP provider")
		if not self.sds_host:
			raise AuthenticationError("`sds_host` is required for EfficientIP provider")
		if not self.sds_dns:
			raise AuthenticationError("`sds_dns` is required (the DNS server name)")

		# Store credentials for requests
		self._auth = (username, password)

		# Verify that the provided sds_dns corresponds to a smart or
		# standalone DNS server (vdns_parent_id == 0). Query the
		# `/rest/dns_server_list` endpoint for this purpose.

		where = f"dns_name='{self.sds_dns}'"
		params = {"WHERE": where, "SELECT": "dns_name,vdns_parent_id"}
		endpoint = "/rest/dns_server_list"
		payload = self._get(endpoint, params)

		raw = []
		if isinstance(payload, dict):
			raw = payload.get("data") or payload.get("result") or payload.get("dns_server") or []
		elif isinstance(payload, list):
			raw = payload

		if not raw:
			raise AuthenticationError(f"No managed DNS server found ({self.sds_dns})")

		server = raw[0]
		vdns_parent = server.get("vdns_parent_id")
		try:
			vdns_parent_int = int(vdns_parent)
		except Exception:
			vdns_parent_int = 0

		if vdns_parent_int != 0:
			raise AuthenticationError(
				"Provided DNS server is not a smart nor a standalone DNS server; you must interact with the smart or a standalone dns server."
			)

		# domain_id is not used by EfficientIP in the same way as other
		# providers, keep domain for compatibility with base class
		self.domain_id = self.domain

	def cleanup(self) -> None:
		pass

	def create_record(self, rtype, name, content):
		"""Create a DNS record

		Validate record type against supported types; unsupported types
		are logged and the method returns False to indicate no action.
		"""
		# Validate rtype
		if rtype not in self.SUPPORTED_RRTYPES:
			LOGGER.error("Unsupported record type '%s' for EfficientIP provider", rtype)
			return False

		# Validate content according to rtype
		if not self._validate_content(rtype, content):
			# _validate_content logs the specific error
			return False

		LOGGER.debug(f"domain: {self.domain}")
		#UNABLE to retrieve non altered domain name ... # LOGGER.debug(f"orignal domain name: {self.config.resolve("lexicon:domain")}")
		LOGGER.debug(f"sanitized name: {self._fqdn_name(name) if name else 'N/A'}")

		# Build query parameters expected by EfficientIP SOLIDserver REST API
		params = {
			"dns_name": self.sds_dns,
			"rr_type": rtype,
			"rr_ttl": int(self._get_lexicon_option("ttl") or 300),
			"rr_name": self._fqdn_name(name),
			"rr_value1": content,
		}

		if self.sds_view:
			params["dns_view_name"] = self.sds_view

		endpoint = "/rest/dns_rr_add"
		payload = self._post(endpoint, params)

		if payload:
			return True
		
		return False

	def list_records(self, rtype=None, name=None, content=None):
		"""
		List DNS records.

		EfficientIP's `dns_rr_list` expects a single `WHERE` parameter
		containing URL-encoded filter expressions and supports a `SELECT`
		parameter to limit returned fields. Build `WHERE` from the
		available arguments and include `SELECT` with the requested
		fields: `rr_id, rr_full_name, rr_type, value1, ttl`.
		"""

		LOGGER.debug(f"domain: {self.domain}")
		#UNABLE to retrieve non altered domain name ... # LOGGER.debug(f"orignal domain name: {self.config.resolve("lexicon:domain")}")
		LOGGER.debug(f"sanitized name: {self._fqdn_name(name) if name else 'N/A'}")

		# Build WHERE filter parts
		where_parts = []
		# mandatory dns server identifier (quoted)
		where_parts.append(f"dns_name='{self.sds_dns}'")

		if self.sds_view:
			where_parts.append(f"dns_view_name='{self.sds_view}'")

		if rtype:
			where_parts.append(f"rr_type='{rtype}'")

		if name:
			# match by full name using SQL-like wildcard (%value%) — do not quote the
			# wildcard expression per SOLIDserver expectations
			where_parts.append(f"rr_full_name = '" + self._fqdn_name(name) + "'")
		else:
			where_parts.append(f"rr_full_name like '%." + self.domain + "'")

		if content:
			# value1 is the column containing the RR content, match with %%value%%
			where_parts.append(f"value1 = '{content}'")

		# Conditions in WHERE must be combined with AND
		where = " AND ".join(where_parts)

		params = {
			"WHERE": where,
			"SELECT": "rr_id,rr_full_name, rr_type, value1, ttl",
		}

		endpoint = "/rest/dns_rr_list"

		# Fetch raw records from provider
		raw_records = self._get(endpoint, params) or []

		# Transform provider response into lexicon canonical record form
		records = []

		for record in raw_records:
			# Extract values once
			rr_type = record.get("rr_type")
			content_val = record.get("value1")

			# Normalize AAAA values to compressed IPv6 representation when possible
			if rr_type == "AAAA" and content_val:
				try:
					content_val = ipaddress.IPv6Address(content_val).compressed
				except ipaddress.AddressValueError:
					LOGGER.debug("Could not parse IPv6 address: %s", content_val)

			records.append(
				{
					"id": record.get("rr_id"),
					"type": rr_type,
					"name": record.get("rr_full_name"),
					"ttl": record.get("ttl"),
					"content": content_val,
				}
			)

		return records

	def update_record(self, identifier=None, rtype=None, name=None, content=None):
		"""Update an existing record"""
		if content is None:
			LOGGER.error("NNo content provided for update - won't update")
			return False
		
		# Find existing records matching rtype and name
		existing = self.list_records(rtype, name)
		if not existing:
			LOGGER.error("No matching records found matching type and name - won't update")
			return False

		# If multiple records found, avoid guessing which to replace
		if len(existing) > 1:
			LOGGER.error("Multiple records found matching type and name - won't update")
			return False

		# Delete the found record(s) and create the new one
		record = existing[0]
		self.delete_record(rtype=record.get("type"), name=record.get("name"), content=record.get("content"))
		return self.create_record(rtype or record.get("type"), name or record.get("name"), content)

	def delete_record(self, identifier=None, rtype=None, name=None, content=None):
		"""Delete an existing record"""
		params = {
			"dns_name": self.sds_dns,
			"rr_type": rtype,
			"rr_ttl": int(self._get_lexicon_option("ttl") or 300),
			"rr_name": self._fqdn_name(name),
			"rr_value1": content,
		}

		if self.sds_view:
			params["dns_view_name"] = self.sds_view

		endpoint = "/rest/dns_rr_delete"
		payload = self._delete(endpoint, params)

		if payload:
			return True
		
		return False

	# Helpers
	def _fqdn_name(self, record_name):
			# Sanitize record_name by removing trailing dots
			record_name = record_name.rstrip(".")
			# check if the record_name is fully specified
			if not record_name.endswith(self.domain):
					record_name = f"{record_name}.{self.domain}"
			# return the FQDN without trailing dots
			return f"{record_name}"

	def _validate_content(self, rtype: str, content: str) -> bool:
		"""Validate `content` according to `rtype`.

		Returns True if valid, False otherwise (and logs an error).
		"""
		if content is None:
			LOGGER.error("No content provided for record type %s", rtype)
			return False

		try:
			if rtype == "A":
				ipaddress.IPv4Address(content)
				return True
			if rtype == "AAAA":
				ipaddress.IPv6Address(content)
				return True
			if rtype == "CNAME":
				# CNAME target must be a valid FQDN/hostname
				if not _FQDN_REGEXP.match(content):
					LOGGER.error("Invalid CNAME target '%s' (not a valid FQDN)", content)
					return False
				return True
			if rtype == "TXT":
				# Any string is acceptable for TXT — ensure it's not empty
				if content == "":
					LOGGER.error("TXT record content must not be empty")
					return False
				return True
			# SRV records are not supported by this provider implementation
			# default: unknown type — already filtered earlier, but be safe
			LOGGER.error("Unhandled record type for validation: %s", rtype)
			return False
		except Exception as err:
			LOGGER.error("Error validating content for %s: %s", rtype, err)
			return False

	def _request(self, action: str = "GET", url: str = "/", data=None, query_params=None):
		if query_params is None:
			query_params = {}

		# Build base URL from sds_host. Allow full URL in sds_host as well.
		base = self.sds_host or ""
		if not base.startswith("http"):
			base = "https://" + base

		full_url = base.rstrip("/") + url
		# Use basic auth tuple stored in authenticate
		auth = getattr(self, "_auth", None)

		# Determine SSL verification behavior: allow disabling via provider option
		no_verify = self._get_provider_option("no_verify_ssl")
		verify = not bool(no_verify)

		# If SSL verification is disabled, suppress the InsecureRequestWarning
		if not verify:
			urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

		# EfficientIP expects URL encoded query parameters for these REST
		# endpoints. Use `params` to send them in the query string.
		try:
			response = requests.request(action, full_url, params=query_params, auth=auth, verify=verify)
			response.raise_for_status()
		except requests.exceptions.HTTPError as err:
			# If the server returned a 400, report invalid parameters clearly.
			resp = getattr(err, "response", None)
			if resp is not None and getattr(resp, "status_code", None) == 400:
				body = resp.text
				LOGGER.error("Invalid parameters (400) provider response: %s", body)
				return None
			# Re-raise other HTTP errors
			raise

		# Try to parse JSON, fall back to an empty structure
		try:
			return response.json()
		except ValueError:
			LOGGER.error("Invalid response: %s", response.text)
			return None

	def _get(self, url, params=None):
		return self._request("GET", url, None, params)

	def _post(self, url, params=None, data=None):
		return self._request("POST", url, data, params)

	def _put(self, url, params=None, data=None):
		return self._request("PUT", url, data, None)

	def _delete(self, url, params=None):
		return self._request("DELETE", url, None, params)
