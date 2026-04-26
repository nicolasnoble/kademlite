# Copyright (c) The kademlite Authors
# SPDX-License-Identifier: MIT OR Apache-2.0


def pytest_configure(config):
    """Set asyncio_mode to auto so async tests run without explicit markers."""
    config.option.asyncio_mode = "auto"
