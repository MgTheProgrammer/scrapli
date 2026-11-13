import pytest

from scrapli import (
    AuthOptions,
    Cli,
    HostKeyHash,
    LookupKeyValue,
    Netconf,
    SessionOptions,
    TransportSsh2Options,
)
from scrapli.exceptions import FFIException

PROXY_JUMP_ARGNAMES = (
    "platform",
    "input_",
)
PROXY_JUMP_ARGVALUES = (
    (
        "arista_eos",
        "show version | i Kernel",
    ),
    (
        "nokia_srl",
        "show version | grep OS",
    ),
)
PROXY_JUMP_IDS = (
    "arista-eos-bin",
    "nokia_srl-bin",
)


@pytest.mark.parametrize(
    argnames=PROXY_JUMP_ARGNAMES,
    argvalues=PROXY_JUMP_ARGVALUES,
    ids=PROXY_JUMP_IDS,
)
def test_proxy_jump_ssh2(platform, input_, is_darwin, eos_available, cli_assert_result):
    if platform == "arista_eos":
        if eos_available is False:
            # because we cant have this publicly in ci afaik
            pytest.skip("eos not available, skipping...")

        definition_file_or_name = "arista_eos"

        transport_options = TransportSsh2Options(
            proxy_jump_host="172.20.20.17",
            proxy_jump_username="admin",
            proxy_jump_password="admin",
        )
    else:
        definition_file_or_name = "nokia_srlinux"

        transport_options = TransportSsh2Options(
            proxy_jump_host="172.20.20.16",
            proxy_jump_username="admin",
            proxy_jump_password="NokiaSrl1!",
        )

    cli = Cli(
        definition_file_or_name=definition_file_or_name,
        host="localhost" if is_darwin else "172.20.20.19",
        port=24022 if is_darwin else 22,
        auth_options=AuthOptions(
            # to the jumphost
            username="scrapli-pw",
            password="scrapli-123-pw",
            # we use the lookups from primary auth regardless
            lookups=[LookupKeyValue(key="enable", value="libscrapli")],
        ),
        session_options=SessionOptions(),
        transport_options=transport_options,
    )

    with cli as c:
        cli_assert_result(actual=c.send_input(input_=input_))


PROXY_JUMP_NETCONF_ARGNAMES = (
    "platform",
    "filter_",
)
PROXY_JUMP_NETCONF_ARGVALUES = (
    (
        "arista_eos",
        "<system><config><hostname></hostname></config></system>",
    ),
    (
        "nokia_srl",
        '<system xmlns="urn:nokia.com:srlinux:general:system"><ssh-server xmlns="urn:nokia.com:srlinux:linux:ssh"><name>mgmt</name></ssh-server></system>',
    ),
)
PROXY_JUMP_NETCONF_IDS = (
    "arista-eos-bin",
    "nokia_srl-bin",
)


@pytest.mark.parametrize(
    argnames=PROXY_JUMP_NETCONF_ARGNAMES,
    argvalues=PROXY_JUMP_NETCONF_ARGVALUES,
    ids=PROXY_JUMP_NETCONF_IDS,
)
def test_proxy_jump_netconf_ssh2(
    platform, filter_, is_darwin, eos_available, netconf_assert_result
):
    if platform == "arista_eos":
        if eos_available is False:
            # because we cant have this publicly in ci afaik
            pytest.skip("eos not available, skipping...")

        transport_options = TransportSsh2Options(
            proxy_jump_host="172.20.20.17",
            proxy_jump_port=830,
            proxy_jump_username="admin",
            proxy_jump_password="admin",
        )
    else:
        transport_options = TransportSsh2Options(
            proxy_jump_host="172.20.20.16",
            proxy_jump_port=830,
            proxy_jump_username="admin",
            proxy_jump_password="NokiaSrl1!",
        )

    netconf = Netconf(
        host="localhost" if is_darwin else "172.20.20.19",
        port=24022 if is_darwin else 22,
        auth_options=AuthOptions(
            # to the jumphost
            username="scrapli-pw",
            password="scrapli-123-pw",
            # we use the lookups from primary auth regardless
            lookups=[LookupKeyValue(key="enable", value="libscrapli")],
        ),
        session_options=SessionOptions(),
        transport_options=transport_options,
    )

    with netconf as n:
        netconf_assert_result(actual=n.get(filter_=filter_))


HOST_KEY_DIGEST_LENS = {
    HostKeyHash.MD5: 16,
    HostKeyHash.SHA1: 20,
    HostKeyHash.SHA256: 32,
}


@pytest.mark.parametrize(
    argnames="hash_",
    argvalues=tuple(HostKeyHash),
    ids=tuple(h.value for h in HostKeyHash),
)
@pytest.mark.parametrize(
    argnames=("platform", "transport"),
    argvalues=(("netopeer", "ssh2"),),
    ids=("netopeer-ssh2",),
)
def test_get_host_key_fingerprint_proxy_jump(hash_, netconf, is_darwin):
    with netconf as n:
        direct = n.get_host_key_fingerprint(hash_=hash_)

    assert len(direct) == HOST_KEY_DIGEST_LENS[hash_]

    proxied_netconf = Netconf(
        host="localhost" if is_darwin else "172.20.20.19",
        port=24022 if is_darwin else 22,
        auth_options=AuthOptions(
            # to the jumphost
            username="scrapli-pw",
            password="scrapli-123-pw",
        ),
        transport_options=TransportSsh2Options(
            # always the clab address since this is resolved from the jump host
            proxy_jump_host="172.20.20.18",
            proxy_jump_port=830,
            proxy_jump_username="root",
            proxy_jump_password="password",
        ),
    )

    with proxied_netconf as n:
        # when proxy jumping we should get the target device, not the jump host
        assert n.get_host_key_fingerprint(hash_=hash_) == direct


@pytest.mark.parametrize(
    argnames=("platform", "transport"),
    argvalues=(("netopeer", "bin"),),
    ids=("netopeer-bin",),
)
def test_get_host_key_fingerprint_not_ssh2(netconf):
    with netconf as n:
        with pytest.raises(FFIException):
            n.get_host_key_fingerprint()
