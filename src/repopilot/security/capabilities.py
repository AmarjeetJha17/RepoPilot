"""Trusted capability categories assigned to tool definitions by application code."""

from enum import StrEnum


class Capability(StrEnum):
    """Security-relevant operation classes; model arguments cannot select these."""

    REPOSITORY_READ = "repository_read"
    REPOSITORY_SEARCH = "repository_search"
    STAGED_FILE_MODIFICATION = "staged_file_modification"
    LIVE_REPOSITORY_MODIFICATION = "live_repository_modification"
    SANDBOXED_TEST_EXECUTION = "sandboxed_test_execution"
    HOST_COMMAND_EXECUTION = "host_command_execution"
    NETWORK_ACCESS = "network_access"
    CREDENTIAL_ACCESS = "credential_access"
    DANGEROUS_GIT_OPERATION = "dangerous_git_operation"
    POLICY_CONFIGURATION_MODIFICATION = "policy_configuration_modification"
