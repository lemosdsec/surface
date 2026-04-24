"""
Django settings for surface project unit tests

as the main settings file loads values from enviornment, this one should make sure values are set as expected by tests
"""

from .settings import *  # noqa: F403

AVZONE = 'test'
LOGBASECOMMAND_PREFIX = 'surface.command'
SCANNERS_PROXY_IMAGE = 'registry.com/test/squid'
