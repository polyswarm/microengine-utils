from pydantic import BaseModel, Field
from .constants import PLATFORM_MACHINE, PLATFORM_OS, ENGINE_NAME
from polyswarmartifact.schema.verdict import Verdict
from typing import Optional, Union
from datetime import datetime

class EngineInfo(BaseModel):
    """A standard object to store scanner & signature metadata

    Notes::

    Some engines report signature metadata with their scan's output, others
    do so during expensive signature updates.

    You can use `EngineInfo` in both cases, providing a way to store the
    results of `update` or just to simplify the logic of setting up
    a `ScanResult`'s scanner info ::

        class Engine(Scanner):
            info = EngineInfo(version=polyswarm_nanoav.__version__)

            def update(...):
                update: Mapping[str, str] = ... #
                self.info.signature_version = update['definitions_version']
                self.info.engine_version = update['engine_version']

            def sync_scan(...)
                scan_result: ScanResult = do_scan(...)
                self.info.update_verdict(scan_result.verdict)
                return scan_result
    """
    operating_system: str = Field(
        default=PLATFORM_OS,
        alias='platform',
        description="platform, e.g `linux', `windows' or `darwin'",
    )

    architecture: str = Field(
        default=PLATFORM_MACHINE,
        alias='machine',
        description="machine architecture, e.g `amd64' or `i386'",
    )

    engine_name: Optional[str] = Field(
        default=ENGINE_NAME,
        alias='name',
        description="captures the name of this engine",
    )

    wrapper_version: Optional[str] = Field(
        alias='version',
        description="captures the module version of the microengine that rendered this verdict",
    )

    engine_version: Optional[str] = Field(
        alias='vendor_version',
        description="captures the version of engine itself",
    )

    definitions_version: Optional[str] = Field(
        alias='signature_version',
        description="captures the version of the engine's signatures/definitions used",
    )

    definitions_timestamp: Optional[Union[str, datetime]] = Field(
        alias='signature_timestamp',
        description="captures the release date of the signatures/definitions used",
    )

    def scanner_info(self) -> 'Mapping':
        """Returns a ``dict`` usable as ``Verdict.set_scanner_info`` kwargs"""
        return {k: v for k, v in self.dict(by_alias=True, exclude_none=True, exclude_unset=True).items() if k in {
                'operating_system',
                'architecture'
                'version',
                'signature_version',
                'vendor_version',
            }}

    @property
    def signature_info(self):
        """Combine signature version and release into an easily destructured value"""
        return '{} <{!s}>'.format(self.definitions_version, self.definitions_timestamp)

    def graft(self, scan: 'ScanResult') -> 'ScanResult':
        """Update a ``ScanResult``'s with shared scanner metadata"""
        if getattr(scan, 'metadata', None):
            # try to parse the JSON string/dict/... inside `scan.metadata' into a `Verdict'
            if not isinstance(scan.metadata, Verdict):
                scan.metadata = Verdict.parse_raw(scan.metadata)
        else:
            # if the ScanResult doesn't exist or is falsy, build a new one so we can at least fill
            # in the bare-bones of scanner information
            scan.metadata = Verdict().set_malware_family('')

        scan.metadata.set_scanner(**self.scanner_info())
        scan.metadata = scan.metadata.json()

    def update(self, **kwargs):
        for name, field in self.__fields__.items():
            if name in kwargs:
                setattr(self, name, kwargs[name])
            elif field.alias in kwargs:
                setattr(self, name, kwargs[field.alias])

    class Config:
        allow_mutation = True
        allow_population_by_field_name = True