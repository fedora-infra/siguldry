# SPDX-License-Identifier: MIT
# Copyright (c) Microsoft Corporation.

"""
A small shim to deal with Koji from Rust.

Koji's XMLRPC API with Kerberos authentication seem like a bit of a headache to deal with
from Rust, so (for now) we will just use the Python implementation. This module is intended
to be limited to operations that would be otherwise a hassle to do in Rust.
"""
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from urllib.parse import urlsplit, urlunsplit
import base64

import koji


class MissingSignaturesError(Exception):
    """Raised when a build has RPMs missing required signatures."""

    def __init__(self, build_id: int, sigkey: str, missing: list[dict]):
        self.build_id = build_id
        self.sigkey = sigkey
        self.missing = missing
        super().__init__(
            f"Build {build_id} has {len(missing)} RPM(s) missing signature from key '{sigkey}'"
        )


@dataclass
class TagEvent:
    # The username that caused the tag event.
    creator_name: str
    # The name of the tag the event happened to.
    tag_name: str
    # The event ID?
    create_event: int


@dataclass
class Rpm:
    id: int
    draft: bool
    name: str
    epoch: Optional[int]
    version: str
    release: str
    arch: str
    size: int
    # The download URL for the RPM
    url: str
    # The SHA256 as a hex string of the unsigned RPM.
    sha256sum: str
    # The key IDs for which a signature already exists in Koji.
    # In most cases this will be empty, but if we get interrupted partway
    # through signing a build, we can use this to skip over ones we've already
    # signed.
    existing_sigkeys: list[str]


@dataclass
class Build:
    # The build ID in Koji.
    id: int
    tag_history: list[TagEvent]
    # The list of RPMs in this build.
    rpms: list[Rpm]


class Client:
    """A thin Koji client wrapper that exposes the functions Rust needs"""

    def __init__(
        self,
        hub_url: str,
        principal: Optional[str] = None,
        keytab: Optional[Path] = None,
        ccache: Optional[Path] = None,
        readonly: bool = False,
    ):
        """
        Initialize a new client and attempts to authenticate.

        In the event that authentication fails, Koji raises koji.GSSAPIAuthError
        """
        self.hub_url = hub_url
        self.principal = principal
        self.keytab = keytab
        self.ccache = ccache
        self.readonly = readonly

        split_url = urlsplit(self.hub_url)
        self.pathinfo = koji.PathInfo(
            urlunsplit((split_url.scheme, split_url.netloc, "", "", ""))
        )

        # Koji sets the default request timeout to 12 hours, and will retry 30 times.
        # For larger outages, we'll retry at the Rust layer and, failing that, when
        # the AMQP message is re-delivered.
        client_opts = {
            "auth_timeout": 15,
            "timeout": 15,
            "max_retries": 10,
            "retry_interval": 5,
        }
        self.client = koji.ClientSession(self.hub_url, opts=client_opts)
        if self.readonly is False:
            self.client.gssapi_login(
                principal=self.principal, keytab=self.keytab, ccache=self.ccache
            )

    def build_info(self, build_id: int) -> Build:
        # Query the history of the tag_listing table for the build, filtering to the active (latest) event
        # TODO can have multiple results return active, sort by event_id? return all results?
        tag_history = self.client.queryHistory(
            tables=["tag_listing"], build=build_id, active=True
        )
        tag_history = [
            TagEvent(
                create_event=e["create_event"],
                creator_name=e["creator_name"],
                tag_name=e["tag.name"],
            )
            for e in tag_history.get("tag_listing", [])
        ]
        koji_build = self.client.getBuild(build_id)
        rpms = []
        for rpm in self.client.listRPMs(build_id):
            # Empty string means unsigned
            existing_sigkeys = [
                sig["sigkey"]
                for sig in self.client.queryRPMSigs(rpm_id=rpm["id"])
                if sig["sigkey"]
            ]
            rpm_checksums = self.client.getRPMChecksums(
                rpm["id"], checksum_types=["sha256"], cacheonly=False
            )
            rpm_download_url = (
                self.pathinfo.build(koji_build) + "/" + self.pathinfo.rpm(rpm)
            )
            rpm_info = Rpm(
                id=rpm["id"],
                draft=rpm["draft"],
                name=rpm["name"],
                epoch=rpm["epoch"],
                version=rpm["version"],
                release=rpm["release"],
                arch=rpm["arch"],
                size=rpm["size"],
                url=rpm_download_url,
                sha256sum=rpm_checksums[""]["sha256"],
                existing_sigkeys=existing_sigkeys,
            )
            rpms.append(rpm_info)

        build = Build(
            id=build_id,
            tag_history=tag_history,
            rpms=rpms,
        )
        return build

    def add_signature(self, rpm_id: int, expected_sigkey: str, signed_package: Path):
        """
        Submit a new signature header for the given RPM.

        In the event that a signature already exists for that sigkey, Koji raises, I think,
        GenericError. TODO: This exception is also raised if it can't rip out the key header.

        Args:
            rpm_id: The Koji RPM ID
            expected_sigkey: The hex string ID of the key that's expected to to have signed the RPM.
            signed_package: Path to the signed package.
        """
        # Probably should replace this with real bindings to librpm
        # Need to string-ify the path because Koji has a "isinstance" check on it for string types
        # and it utterly fails to handle Python Path objects, which it treats as file objects. Duck
        # typing.
        sighdr = koji.rip_rpm_sighdr(str(signed_package))
        sigkey = koji.get_sighdr_key(sighdr)
        if sigkey != expected_sigkey:
            raise ValueError(
                f"Expected signature with keyid '{expected_sigkey}', but got '{sigkey}'"
            )

        if self.readonly:
            return

        self.client.addRPMSig(rpm_id, base64.b64encode(sighdr).decode(encoding="utf-8"))

    def write_signed_rpm(self, rpm_id: int, sigkey: str):
        if self.readonly is False:
            self.client.writeSignedRPM(rpm_id, sigkey)

    def move_build(
        self, build_id: int, expected_sigkey: str, tag_from: str, tag_to: str
    ) -> int:
        """
        Move a build from one tag to another.

        This should be called after all the RPMs in the build have been signed.
        """
        # Double check all the signatures are present before we move it over.
        sigs_missing = []
        for rpm in self.client.listRPMs(build_id):
            sigs = self.client.queryRPMSigs(rpm_id=rpm["id"], sigkey=expected_sigkey)
            if len(sigs) == 0:
                sigs_missing.append(rpm)

        if self.readonly:
            return 0

        if sigs_missing:
            raise MissingSignaturesError(build_id, expected_sigkey, sigs_missing)

        task_id = self.client.tagBuild(tag_to, build_id, False, tag_from)
        return task_id
