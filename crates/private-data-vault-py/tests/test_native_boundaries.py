"""Exercise the installed abi3 wheel's native artifact boundaries."""

import hashlib
import hmac
import uuid

import pytest
from private_data_vault import (
    ArtifactChunkCipher,
    ArtifactIntakeCommitment,
    ArtifactSha256,
    SoftwareKmsCipher,
    artifact_sha256_hex,
    pack_artifact_frame,
    unpack_artifact_frame,
)


def test_integrity_buffers_and_commitment() -> None:
    payload = b"synthetic"
    expected = hashlib.sha256(payload).hexdigest()
    digest = ArtifactSha256()
    digest.update(memoryview(payload[:3]))
    digest.update(memoryview(payload[3:]))
    assert digest.hexdigest() == artifact_sha256_hex(memoryview(payload)) == expected
    key, prefix = b"proof key", b"intake prefix"
    commitment = ArtifactIntakeCommitment(key, prefix)
    commitment.update(memoryview(payload))
    assert commitment.verify(
        hmac.new(key, prefix + payload, hashlib.sha256).hexdigest()
    )
    with pytest.raises(ValueError):
        commitment.update(payload)
    with pytest.raises(BufferError):
        artifact_sha256_hex(memoryview(payload)[::2])


def test_software_kms_wrap_authentication() -> None:
    cipher = SoftwareKmsCipher(memoryview(bytes(range(32))))
    nonce, key, aad = bytes(range(12)), bytes(range(32, 64)), b"tenant context"
    wrapped = cipher.wrap_key(nonce, key, aad)
    assert cipher.unwrap_key(nonce, wrapped, aad, ValueError) == key
    with pytest.raises(ValueError):
        cipher.unwrap_key(nonce, wrapped, b"wrong context", ValueError)
    with pytest.raises(ValueError):
        cipher.unwrap_key(
            nonce, wrapped[:-1] + bytes([wrapped[-1] ^ 1]), aad, ValueError
        )


def test_frame_frozen_vector_and_refusal() -> None:
    frame = bytes.fromhex(
        "4d564e310000000000000007000000030000000161000000000000000378797a"
    )
    parts = (b"a", b"", b"xyz")
    assert pack_artifact_frame((7).to_bytes(8, "big"), parts) == frame
    assert unpack_artifact_frame(frame) == (7, parts)
    assert unpack_artifact_frame(frame[:-1]) is None


def test_chunk_frozen_vector_and_authentication() -> None:
    def field(value: bytes) -> bytes:
        return len(value).to_bytes(4, "big") + value

    aad = b"".join(
        (
            field(b"maivn-vault-chunk-v1"),
            field(b"tenant_golden"),
            field(uuid.UUID("0f1e2d3c-4b5a-4968-8776-a5b4c3d2e1f0").bytes),
            field(b"value_map"),
            (3).to_bytes(8, "big"),
        )
    )
    plaintext = b"golden chunk plaintext"
    wire = bytes.fromhex(
        "4d564331070c5809934f0350ddd48dd05b30707c0fabdde0246ee3ab3e15e3dee3a4a97d7eccc77e0515cfa7"
        "9ea0614db9f7f7b12986"
    )
    cipher = ArtifactChunkCipher(bytes(range(16)), memoryview(bytes(range(32, 64))))
    assert cipher.seal(aad, memoryview(plaintext)) == (
        wire,
        "fc9f2de1f262d1381602831d9fecf80486b81bef364411c863f834bf69ca589b",
    )
    assert cipher.open(aad, memoryview(wire)) == plaintext
    with pytest.raises(ValueError):
        cipher.open(b"wrong context", wire)
    with pytest.raises(ValueError):
        cipher.open(aad, wire[:-1] + bytes([wire[-1] ^ 1]))


@pytest.mark.parametrize(
    "bad_tag", ["", "0" * 63, "0" * 65, "G" * 64, "A" * 64, "0" * 64]
)
def test_commitment_rejects_noncanonical_or_incorrect_tags_once(bad_tag: str) -> None:
    commitment = ArtifactIntakeCommitment(bytearray(b"key"), bytearray(b"prefix"))
    commitment.update(bytearray(b"data"))
    assert not commitment.verify(bad_tag)
    with pytest.raises(ValueError):
        commitment.verify(bad_tag)
    with pytest.raises(ValueError):
        commitment.update(b"more")


def test_commitment_discard_and_digest_snapshots() -> None:
    digest = ArtifactSha256()
    digest.update(bytearray(b"a"))
    assert digest.hexdigest() == hashlib.sha256(b"a").hexdigest()
    digest.update(b"b")
    assert digest.hexdigest() == hashlib.sha256(b"ab").hexdigest()
    assert artifact_sha256_hex(bytearray(b"ab")) == digest.hexdigest()
    commitment = ArtifactIntakeCommitment(b"key", b"prefix")
    commitment.discard()
    commitment.discard()
    with pytest.raises(ValueError):
        commitment.verify("0" * 64)
    with pytest.raises(TypeError):
        artifact_sha256_hex("not bytes")


def test_frame_mutable_buffers_and_malformed_inputs() -> None:
    frame = pack_artifact_frame(
        bytearray((9).to_bytes(8, "big")), [bytearray(b"a"), b"bc"]
    )
    assert unpack_artifact_frame(frame) == (9, (b"a", b"bc"))
    assert unpack_artifact_frame(bytearray(frame)) == (
        9,
        (bytearray(b"a"), bytearray(b"bc")),
    )
    for malformed in (b"", b"BAD!" + frame[4:], frame[:15], frame[:-1], frame + b"x"):
        assert unpack_artifact_frame(malformed) is None
    assert unpack_artifact_frame(b"MVN1" + bytes(8) + (100).to_bytes(4, "big")) is None
    with pytest.raises(TypeError):
        pack_artifact_frame(bytes(8), [object()])


def test_chunk_buffer_validation_and_round_trip() -> None:
    cipher = ArtifactChunkCipher(bytes(16), bytearray(range(32)))
    wire, digest = cipher.seal(b"aad", bytearray(b"payload"))
    assert digest == hashlib.sha256(wire).hexdigest()
    assert cipher.open(b"aad", bytearray(wire)) == b"payload"
    with pytest.raises(ValueError):
        cipher.open(b"aad", b"short")
    with pytest.raises(TypeError):
        cipher.seal(b"aad", "plaintext")
    with pytest.raises(BufferError):
        cipher.seal(b"aad", memoryview(b"abcdef")[::2])


def test_software_kms_refuses_invalid_inputs_without_releasing_plaintext() -> None:
    with pytest.raises(ValueError):
        SoftwareKmsCipher(b"short")
    with pytest.raises(TypeError):
        SoftwareKmsCipher("not bytes")
    with pytest.raises(BufferError):
        SoftwareKmsCipher(memoryview(bytes(64))[::2])
    cipher = SoftwareKmsCipher(bytearray(range(32)))
    nonce, key = bytes(12), bytes(range(32))
    with pytest.raises(ValueError):
        cipher.wrap_key(bytes(11), key, b"")
    with pytest.raises(ValueError):
        cipher.wrap_key(nonce, b"short", b"")
    with pytest.raises(ValueError):
        cipher.unwrap_key(nonce, b"short", b"", ValueError)


def test_frame_bytes_subclass_and_legacy_non_bytes_refusals() -> None:
    class BytesSubclass(bytes):
        pass

    class FrameLike:
        def __init__(self, prefix: bool, length: int) -> None:
            self.prefix = prefix
            self.length = length

        def startswith(self, prefix: bytes) -> bool:
            assert prefix == b"MVN1"
            return self.prefix

        def __len__(self) -> int:
            return self.length

    frame = pack_artifact_frame(bytes(8), [b"a"])
    assert unpack_artifact_frame(BytesSubclass(frame)) == (0, (b"a",))
    assert unpack_artifact_frame(FrameLike(False, len(frame))) is None
    assert unpack_artifact_frame(FrameLike(True, 4)) is None
    with pytest.raises(TypeError, match="frame must be bytes or bytearray"):
        unpack_artifact_frame(FrameLike(True, len(frame)))


def test_software_kms_buffer_formats_and_authenticated_wrong_key_size() -> None:
    from array import array

    with pytest.raises(TypeError):
        SoftwareKmsCipher(memoryview(array("I", [0] * 8)))
    with pytest.raises(ValueError):
        SoftwareKmsCipher(memoryview(bytearray(31)))
    cipher = SoftwareKmsCipher(bytes(32))
    # NIST AES-256-GCM empty plaintext/AAD vector: authentic but not a tenant key.
    empty_tag = bytes.fromhex("530f8afbc74536b9a963b4f1c4cb738b")
    assert cipher.unwrap_key(bytes(12), empty_tag, b"", ValueError) is None


def test_chunk_rejects_non_byte_and_non_buffer_plaintext() -> None:
    from array import array

    cipher = ArtifactChunkCipher(bytes(16), bytes(32))
    with pytest.raises(TypeError):
        cipher.seal(b"aad", memoryview(array("I", [1])))
    with pytest.raises(TypeError):
        cipher.seal(b"aad", object())
