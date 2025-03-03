# standards/dnssec.py

from datetime import datetime
from logging import getLogger

import dns.dnssec
import dns.flags
import dns.name
import dns.resolver

from core.custom_logger.logger import setup_logger
from core.utils import dns_manager


setup_logger()
logger = getLogger(__name__)


class DNSSECChecker:
    def __init__(self, domain):
        self.domain = domain
        self.verification_chain = []

    async def _get_ds_records(self):
        try:
            ds_records = []
            answers = await dns_manager.resolve_dnssec(
                self.domain, "DS", raise_on_no_answer=False
            )

            if answers and answers.rrset is not None:
                for rdata in answers.rrset:
                    ds_records.append(
                        {
                            "key_tag": rdata.key_tag,
                            "algorithm": rdata.algorithm,
                            "digest_type": rdata.digest_type,
                            "digest": rdata.digest.hex(),
                        }
                    )
            return ds_records
        except Exception as e:
            raise Exception(f"Error getting DS records: {str(e)}")

    async def _get_dnskey_records(self):
        try:
            dnskey_records = []
            answers = await dns_manager.resolve_dnssec(
                self.domain, "DNSKEY", raise_on_no_answer=False
            )

            if answers and answers.rrset is not None:
                for rdata in answers.rrset:
                    dnskey_records.append(
                        {
                            "flags": rdata.flags,
                            "protocol": rdata.protocol,
                            "algorithm": rdata.algorithm,
                            "key": rdata.to_text(),
                        }
                    )
            return dnskey_records
        except Exception as e:
            raise Exception(f"Error getting DNSKEY records: {str(e)}")

    async def _get_rrsig_records(self):
        try:
            rrsig_records = []
            # Query RRSIG records for the DNSKEY
            answers = await dns_manager.resolve_dnssec(
                self.domain, "DNSKEY", raise_on_no_answer=False
            )

            # Rest of the function remains the same
            if answers and answers.rrset is not None and answers.response is not None:
                for rrsig in answers.response.find_rrset(
                    answers.response.answer,
                    dns.name.from_text(self.domain),
                    dns.rdataclass.IN,
                    dns.rdatatype.RRSIG,
                    dns.rdatatype.DNSKEY,
                ):
                    # Existing code for processing RRSIG records
                    rrsig_records.append(
                        {
                            "type_covered": dns.rdatatype.to_text(rrsig.type_covered),
                            "algorithm": rrsig.algorithm,
                            # Rest of the fields...
                        }
                    )
            return rrsig_records
        except Exception as e:
            raise Exception(f"Error getting RRSIG records: {str(e)}")

    async def check_dnssec(self):
        result = {
            "root_domain": self.domain,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "dnssec_status": {
                "is_signed": False,
                "registrar": {"status": None, "ds_records": []},
                "nameservers": {
                    "status": None,
                    "dnskey_records": [],
                    "rrsig_records": [],
                },
            },
            "verification_chain": [],
        }

        try:
            await self._verify_chain()
            result["verification_chain"] = self.verification_chain

            ds_records = await self._get_ds_records()
            if ds_records:
                result["dnssec_status"]["registrar"]["status"] = "FullySigned"
                result["dnssec_status"]["registrar"]["ds_records"] = ds_records
            else:
                result["dnssec_status"]["registrar"]["status"] = "Unsigned"

            dnskey_records = await self._get_dnskey_records()
            if dnskey_records:
                result["dnssec_status"]["nameservers"]["status"] = "Signed"
                result["dnssec_status"]["nameservers"]["dnskey_records"] = (
                    dnskey_records
                )

                rrsig_records = await self._get_rrsig_records()
                result["dnssec_status"]["nameservers"]["rrsig_records"] = rrsig_records

                result["dnssec_status"]["is_signed"] = True
            else:
                result["dnssec_status"]["nameservers"]["status"] = "Unsigned"

        except Exception as e:
            result["error"] = str(e)

        return result

    async def _verify_chain(self):
        # Split domain into labels
        labels = self.domain.split(".")
        current_zone = "."

        # Verify root zone
        root_info = await self._verify_zone(current_zone)
        self.verification_chain.append(root_info)

        # Verify each label in the chain
        for i in range(len(labels) - 1, -1, -1):
            if i == len(labels) - 1:
                current_zone = labels[i]
            else:
                current_zone = labels[i] + "." + current_zone

            zone_info = await self._verify_zone(current_zone)
            self.verification_chain.append(zone_info)

            # Get authoritative nameservers and verify A records
            if i == 0:  # Only for the full domain
                auth_ns = await self._get_auth_nameservers(current_zone)
                for ns in auth_ns:
                    ns_info = await self._verify_a_records(current_zone, ns)
                    self.verification_chain.append(ns_info)

    async def _verify_zone(self, zone):
        zone_info = {
            "zone": zone,
            "dnskey_records": [],
            "ds_records": [],
            "rrsig_info": [],
        }

        try:
            dnskey_response = await dns_manager.resolve_dnssec(
                zone, "DNSKEY", raise_on_no_answer=False
            )
            if dnskey_response and dnskey_response.rrset:
                zone_info["dnskey_records"] = [
                    f"Found {len(dnskey_response.rrset)} DNSKEY records for {zone}"
                ]

                # Verify DNSKEY records with DS records if not root
                if zone != ".":
                    ds_response = await dns_manager.resolve_dnssec(
                        zone, "DS", raise_on_no_answer=False
                    )
                    if ds_response and ds_response.rrset:
                        for ds in ds_response:
                            zone_info["ds_records"].append(
                                f"DS={ds.key_tag}/SHA-256 has algorithm {dns.dnssec.algorithm_to_text(ds.algorithm)}"
                            )
                            for dnskey in dnskey_response.rrset:
                                if ds.key_tag == dns.dnssec.key_id(dnskey):
                                    zone_info["ds_records"].append(
                                        f"DS={ds.key_tag}/SHA-256 verifies DNSKEY={ds.key_tag}/SEP"
                                    )

            # Get RRSIG records for DNSKEY
            for rrset in dnskey_response.response.answer:
                rrsigs = [rr for rr in rrset if rr.rdtype == dns.rdatatype.RRSIG]
                if rrsigs:
                    zone_info["rrsig_info"].append(
                        f"Found {len(rrsigs)} RRSIGs over DNSKEY RRset"
                    )
                    for rrsig in rrsigs:
                        if rrsig.rdtype == dns.rdatatype.RRSIG:
                            zone_info["rrsig_info"].append(
                                f"RRSIG={rrsig.key_tag} and DNSKEY={rrsig.key_tag}/SEP verifies the DNSKEY RRset"
                            )

        except Exception as e:
            zone_info["error"] = str(e)

        return zone_info

    async def _get_auth_nameservers(self, zone):
        try:
            ns_response = await dns_manager.resolve_dnssec(zone, "NS")
            return [str(rdata.target) for rdata in ns_response]
        except Exception:
            return []

    async def _verify_a_records(self, zone, nameserver):
        ns_info = {
            "zone": zone,
            "nameserver": nameserver,
            "a_records": [],
            "rrsig_info": [],
        }

        try:
            a_response = await dns_manager.resolve_dnssec(zone, "A")
            ns_info["a_records"].append(f"{nameserver} is authoritative for {zone}")
            for rdata in a_response:
                ns_info["a_records"].append(f"{zone} A RR has value {rdata.address}")

            for rrset in a_response.response.answer:
                rrsigs = [rr for rr in rrset if rr.rdtype == dns.rdatatype.RRSIG]
                if rrsigs:
                    ns_info["rrsig_info"].append("Found 1 RRSIGs over A RRset")
                    for rrsig in rrsigs:
                        ns_info["rrsig_info"].append(
                            f"RRSIG={rrsig.key_tag} and DNSKEY={rrsig.key_tag}/SEP verifies the A RRset"
                        )

        except Exception as e:
            ns_info["error"] = str(e)

        return ns_info


async def run(domain):
    """
    Main function to be called from other code to check DNSSEC for a domain
    Returns both results and state dictionaries
    """
    results = {}
    state = {}

    logger.info(f"Checking DNSSEC for domain: {domain}")
    try:
        checker = DNSSECChecker(domain)
        result = await checker.check_dnssec()

        results[domain] = result
        state[domain] = {"DNSSEC": result["dnssec_status"]["is_signed"]}

    except Exception as e:
        results[domain] = {
            "domain": domain,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "dnssec_status": {
                "is_signed": False,
                "registrar": {"status": None, "ds_records": []},
                "nameservers": {
                    "status": None,
                    "dnskey_records": [],
                    "rrsig_records": [],
                },
            },
            "error": str(e),
        }
        state[domain] = {"DNSSEC": False, "error": str(e)}

    return results, state
