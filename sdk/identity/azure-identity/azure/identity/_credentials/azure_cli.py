# ------------------------------------
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ------------------------------------
from datetime import datetime
import json
import os
import platform
import re
import sys

import subprocess
import six

from azure.core.credentials import AccessToken
from azure.core.exceptions import ClientAuthenticationError

from .. import CredentialUnavailableError
from .._internal import _scopes_to_resource

CLI_NOT_FOUND = "Azure CLI not found on path"
COMMAND_LINE = "az account get-access-token --output json --resource {}"

EPOCH = datetime(1970, 1, 1)


class AzureCliCredential(object):
    def get_token(self, *scopes, **kwargs):  # pylint:disable=unused-argument
        resource = _scopes_to_resource(*scopes)
        output, error = _run_command(COMMAND_LINE.format(resource))
        if error:
            raise error

        try:
            return parse_token(output)
        except (KeyError, ValueError) as ex:
            sanitized_output = sanitize_output(output)
            error = ClientAuthenticationError(message="Unexpected output from Azure CLI: '{}'".format(sanitized_output))
            six.raise_from(error, ex)


def parse_token(output):
    """Parse output of 'az account get-access-token' to an AccessToken.

    In particular, convert the CLI's "expiresOn" value, the string representation of a local datetime, to epoch seconds.
    """
    token = json.loads(output)
    parsed_expires_on = datetime.strptime(token["expiresOn"], "%Y-%m-%d %H:%M:%S.%f")
    expires_on = (parsed_expires_on - EPOCH).total_seconds()

    return AccessToken(token["accessToken"], int(expires_on))


def get_safe_working_dir():
    """Invoke 'az' from a directory on $PATH to get 'az' from the path, not the executing program's directory"""

    path = os.environ["PATH"]
    if sys.platform.startswith("win"):
        return path.split(";")[0]
    else:
        return path.split(":")[0]


def sanitize_output(output):
    """Redact access tokens from CLI output to prevent error messages revealing them"""
    return re.sub(r"\"accessToken\": \"(.*?)(\"|$)", "****", output)


def _run_command(command):
    if sys.platform.startswith("win"):
        args = ["cmd", "/c", command]
    else:
        args = ["/bin/sh", "-c", command]
    try:
        working_directory = get_safe_working_dir()

        kwargs = {"stderr": subprocess.STDOUT, "cwd": working_directory, "universal_newlines": True}
        if platform.python_version() >= "3.3":
            kwargs["timeout"] = 10

        output = subprocess.check_output(args, **kwargs)
        return six.ensure_str(output), None
    except subprocess.CalledProcessError as ex:
        # non-zero return from shell
        if ex.returncode == 127 or ex.output.startswith("'az' is not recognized"):
            error = CredentialUnavailableError(message=CLI_NOT_FOUND)
        else:
            # return code is from the CLI -> propagate its output
            if ex.output:
                message = sanitize_output(ex.output)
            else:
                message = "Failed to invoke Azure CLI"
            error = ClientAuthenticationError(message=message)
    except OSError as ex:
        # failed to execute 'cmd' or '/bin/sh'; CLI may or may not be installed
        error = CredentialUnavailableError(message="Failed to execute '{}'".format(args[0]))
    except Exception as ex:
        error = ex

    return None, error
