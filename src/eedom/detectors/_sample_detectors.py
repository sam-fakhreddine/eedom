"""Export sample detectors for framework demonstration.
"""
from eedom.detectors.process.tested_by import TestedByAnnotationDetector
from eedom.detectors.reliability.cache_eviction import CacheEvictionDetector
from eedom.detectors.security.jwt_audience import JWTAudienceDetector
from eedom.detectors.security.secret_str import SecretStrDetector

__all__ = [
    "JWTAudienceDetector",
    "SecretStrDetector",
    "CacheEvictionDetector",
    "TestedByAnnotationDetector",
]
