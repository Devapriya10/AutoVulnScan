import pytest

from main import validate_target


def test_valid_ipv4_address():
    """Test that a valid IPv4 address is accepted."""

    result = validate_target(
        "127.0.0.1"
    )

    assert result == "127.0.0.1"


def test_valid_ipv6_address():
    """Test that a valid IPv6 address is accepted."""

    result = validate_target(
        "::1"
    )

    assert result == "::1"


def test_valid_network_range():
    """Test that a valid network range is accepted."""

    result = validate_target(
        "192.168.1.0/24"
    )

    assert result == "192.168.1.0/24"


def test_network_range_is_normalized():
    """Test that non-strict network ranges are accepted."""

    result = validate_target(
        "192.168.1.25/24"
    )

    assert result == "192.168.1.25/24"


def test_valid_hostname():
    """Test that a valid hostname is accepted."""

    result = validate_target(
        "example.com"
    )

    assert result == "example.com"


def test_valid_hostname_with_subdomain():
    """Test that a hostname with subdomains is accepted."""

    result = validate_target(
        "scan.example.com"
    )

    assert result == "scan.example.com"


def test_target_with_leading_and_trailing_spaces():
    """Test that surrounding whitespace is removed."""

    result = validate_target(
        "  127.0.0.1  "
    )

    assert result == "127.0.0.1"


def test_empty_target():
    """Test that an empty target is rejected."""

    with pytest.raises(
        ValueError,
        match="Target cannot be empty."
    ):
        validate_target("")


def test_whitespace_only_target():
    """Test that a whitespace-only target is rejected."""

    with pytest.raises(
        ValueError,
        match="Target cannot be empty."
    ):
        validate_target("   ")


def test_target_with_internal_spaces():
    """Test that targets containing spaces are rejected."""

    with pytest.raises(
        ValueError,
        match="Target must not contain spaces."
    ):
        validate_target(
            "127.0.0.1 test"
        )


def test_target_too_long():
    """Test that targets longer than 253 characters are rejected."""

    target = "a" * 254

    with pytest.raises(
        ValueError,
        match="Target is too long."
    ):
        validate_target(target)


def test_invalid_target():
    """Test that an invalid target is rejected."""

    with pytest.raises(
        ValueError,
        match="Invalid target"
    ):
        validate_target(
            "not_a_valid_target!"
        )


def test_invalid_ip_format():
    """Test that an invalid target format is rejected."""

    with pytest.raises(
        ValueError,
        match="Invalid target"
    ):
        validate_target(
            "192.168.1.1/999"
        )


def test_invalid_hostname():
    """Test that an invalid hostname is rejected."""

    with pytest.raises(
        ValueError,
        match="Invalid target"
    ):
        validate_target(
            "-invalid-hostname"
        )
