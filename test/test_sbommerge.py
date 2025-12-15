from logging import getLogger, DEBUG, INFO
from pathlib import Path

import pytest

from sbommerge import cli

TEST_DIR = Path(__file__).parent

SPDX_FILE_1 = f"{TEST_DIR}/files/file1.spdx.json"
SPDX_FILE_2 = f"{TEST_DIR}/files/file2.spdx.json"


@pytest.mark.parametrize(
    "arguments, result",
    [
        ([SPDX_FILE_1, SPDX_FILE_2], True),
        ([SPDX_FILE_1, SPDX_FILE_1], False),  # Files should not be the same
        (["WRONGFILE", SPDX_FILE_2], False),  # Files should exist
        ([SPDX_FILE_1, "WRONGFILE"], False),  # Files should exist
        (["WRONGFILE", "WRONGFILE"], False),  # Files should exist
    ],
)
def test_arguments_valid_files(arguments, result):
    parser = cli.create_argument_parser()
    args = parser.parse_args(arguments)
    assert result == cli.validate_arguments(args)


@pytest.mark.parametrize(
    "options, loglevel",
    [
        ([], INFO),
        (["--debug"], DEBUG),
    ],
)
def test_loglevel(options, loglevel):
    logger = getLogger(cli.APP_NAME)
    parser = cli.create_argument_parser()
    args = parser.parse_args(options + [SPDX_FILE_1, SPDX_FILE_2])
    cli.set_log_level(args)
    assert(loglevel == logger.level)
