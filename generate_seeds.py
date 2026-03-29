#!/usr/bin/env python3
"""
BinFuzz Seed Generator
Produces targeted GGUF and ONNX seed files for AFL++ fuzzing of llama.cpp and ONNX Runtime.

Each seed is crafted to stress a specific code path in the parser, making AFL++ more
likely to find crashes faster rather than starting from random bytes.
"""

import os
import re
import struct
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO,
                    format='%(levelname)s  %(message)s')
log = logging.getLogger(__name__)

# ── GGUF constants ────────────────────────────────────────────────────────────

GGUF_MAGIC   = b'GGUF'
GGUF_VERSION = 3

# Metadata value types
T_UINT8   = 0
T_INT8    = 1
T_UINT16  = 2
T_INT16   = 3
T_UINT32  = 4
T_INT32   = 5
T_FLOAT32 = 6
T_BOOL    = 7
T_STRING  = 8
T_ARRAY   = 9
T_UINT64  = 10
T_INT64   = 11
T_FLOAT64 = 12

# GGML tensor types
GGML_F32  = 0
GGML_F16  = 1
GGML_Q4_0 = 2
GGML_Q8_0 = 8


# ── GGUF serialisation helpers ────────────────────────────────────────────────

def gguf_str(s: bytes) -> bytes:
    """Encode a GGUF string (uint64 length + raw bytes)."""
    return struct.pack('<Q', len(s)) + s


def gguf_kv(key: bytes, vtype: int, value: bytes) -> bytes:
    return gguf_str(key) + struct.pack('<I', vtype) + value


def gguf_kv_string(key: bytes, val: bytes) -> bytes:
    return gguf_kv(key, T_STRING, gguf_str(val))


def gguf_kv_uint32(key: bytes, val: int) -> bytes:
    return gguf_kv(key, T_UINT32, struct.pack('<I', val))


def gguf_kv_uint64(key: bytes, val: int) -> bytes:
    return gguf_kv(key, T_UINT64, struct.pack('<Q', val))


def gguf_kv_float32(key: bytes, val: float) -> bytes:
    return gguf_kv(key, T_FLOAT32, struct.pack('<f', val))


def gguf_kv_array(key: bytes, elem_type: int, elements: list[bytes]) -> bytes:
    body = struct.pack('<II', elem_type, len(elements)) + b''.join(elements)
    return gguf_kv(key, T_ARRAY, body)


def gguf_header(version: int, tensor_count: int, kv_count: int) -> bytes:
    return GGUF_MAGIC + struct.pack('<IQQ', version, tensor_count, kv_count)


def gguf_tensor_info(name: bytes, dims: list[int],
                     tensor_type: int, offset: int) -> bytes:
    return (gguf_str(name)
            + struct.pack('<I', len(dims))
            + b''.join(struct.pack('<Q', d) for d in dims)
            + struct.pack('<I', tensor_type)
            + struct.pack('<Q', offset))


def pad32(data: bytes) -> bytes:
    """Pad data to next 32-byte boundary."""
    r = len(data) % 32
    return data + (b'\x00' * (32 - r) if r else b'')


def minimal_llama_metadata() -> tuple[bytes, int]:
    """
    Return (metadata_bytes, kv_count) for the minimum KV pairs that make
    llama.cpp recognise the file as a valid llama architecture model.
    """
    kvs = [
        gguf_kv_string(b'general.architecture',  b'llama'),
        gguf_kv_string(b'general.name',           b'fuzz-seed'),
        gguf_kv_uint32(b'llama.context_length',   512),
        gguf_kv_uint32(b'llama.embedding_length',  64),
        gguf_kv_uint32(b'llama.block_count',        1),
        gguf_kv_uint32(b'llama.attention.head_count', 2),
        gguf_kv_uint32(b'llama.feed_forward_length', 128),
        gguf_kv_uint32(b'llama.rope.dimension_count', 32),
        gguf_kv_float32(b'llama.attention.layer_norm_rms_epsilon', 1e-5),
        gguf_kv_uint32(b'tokenizer.ggml.model',   0),
        gguf_kv_array(b'tokenizer.ggml.tokens', T_STRING,
                      [gguf_str(t) for t in [b'<unk>', b'<s>', b'</s>',
                                              b'a', b'b', b'c']]),
        gguf_kv_array(b'tokenizer.ggml.scores', T_FLOAT32,
                      [struct.pack('<f', float(i)) for i in range(6)]),
        gguf_kv_array(b'tokenizer.ggml.token_type', T_INT32,
                      [struct.pack('<i', 0) for _ in range(6)]),
    ]
    return b''.join(kvs), len(kvs)


def build_minimal_model() -> bytes:
    """
    A complete, structurally valid (tiny) llama GGUF model.
    Small enough for fast AFL++ executions, valid enough to reach deep parser code.
    """
    meta_bytes, kv_count = minimal_llama_metadata()

    # One tiny embedding tensor:  vocab_size(6) × embed_dim(64) × F32
    vocab, embed = 6, 64
    tensor_data_size = vocab * embed * 4               # float32
    tensor_data      = b'\x00' * tensor_data_size

    tensor_info = gguf_tensor_info(
        b'token_embd.weight', [embed, vocab], GGML_F32, 0
    )

    header  = gguf_header(GGUF_VERSION, 1, kv_count)
    pre_data = header + meta_bytes + tensor_info
    # tensor data must be 32-byte aligned relative to file start
    padding = b'\x00' * ((32 - len(pre_data) % 32) % 32)

    return pre_data + padding + tensor_data


# ── Seed definitions ──────────────────────────────────────────────────────────

def seeds_valid() -> dict[str, bytes]:
    """Structurally valid seeds — give AFL++ a correct starting point."""
    base  = build_minimal_model()
    meta2, kv2 = minimal_llama_metadata()

    # Version 1 minimal (no tensors, no KV)
    v1_min = gguf_header(1, 0, 0)
    # Version 2 minimal
    v2_min = gguf_header(2, 0, 0)
    # Version 3 minimal — no tensors, no KV (smallest valid file)
    v3_min = gguf_header(3, 0, 0)

    return {
        'valid_minimal_v3.gguf':     v3_min,
        'valid_minimal_v1.gguf':     v1_min,
        'valid_minimal_v2.gguf':     v2_min,
        'valid_full_model.gguf':     base,
    }


def seeds_header_corruption() -> dict[str, bytes]:
    """Corrupt the 24-byte header to hit magic/version validation branches."""
    base = gguf_header(3, 0, 0)
    return {
        # Wrong magic
        'hdr_magic_ggjt.gguf':        b'GGJT' + base[4:],
        'hdr_magic_null.gguf':        b'\x00\x00\x00\x00' + base[4:],
        'hdr_magic_partial.gguf':     b'GGU\x00' + base[4:],
        'hdr_magic_reversed.gguf':    b'FUGGG'[:4] + base[4:],
        # Version edge cases
        'hdr_version_0.gguf':         GGUF_MAGIC + struct.pack('<IQQ', 0, 0, 0),
        'hdr_version_4.gguf':         GGUF_MAGIC + struct.pack('<IQQ', 4, 0, 0),
        'hdr_version_max.gguf':       GGUF_MAGIC + struct.pack('<IQQ', 0xFFFFFFFF, 0, 0),
        'hdr_version_max32.gguf':     GGUF_MAGIC + struct.pack('<IQQ', 0x7FFFFFFF, 0, 0),
    }


def seeds_count_overflows() -> dict[str, bytes]:
    """
    Huge tensor_count or kv_count to trigger integer overflow / huge malloc
    in the initial allocation loops.
    """
    U64_MAX  = 0xFFFFFFFFFFFFFFFF
    I64_MAX  = 0x7FFFFFFFFFFFFFFF
    HUGE     = 0x0000000100000000  # 4 billion — just above uint32 max
    return {
        'cnt_tensor_u64max.gguf':   GGUF_MAGIC + struct.pack('<IQQ', 3, U64_MAX, 0),
        'cnt_kv_u64max.gguf':       GGUF_MAGIC + struct.pack('<IQQ', 3, 0, U64_MAX),
        'cnt_both_u64max.gguf':     GGUF_MAGIC + struct.pack('<IQQ', 3, U64_MAX, U64_MAX),
        'cnt_tensor_i64max.gguf':   GGUF_MAGIC + struct.pack('<IQQ', 3, I64_MAX, 0),
        'cnt_tensor_4b.gguf':       GGUF_MAGIC + struct.pack('<IQQ', 3, HUGE, 0),
        'cnt_kv_4b.gguf':           GGUF_MAGIC + struct.pack('<IQQ', 3, 0, HUGE),
        'cnt_tensor_1.gguf':        GGUF_MAGIC + struct.pack('<IQQ', 3, 1, 0),   # 1 tensor, no info
        'cnt_kv_1.gguf':            GGUF_MAGIC + struct.pack('<IQQ', 3, 0, 1),   # 1 kv, no data
    }


def seeds_string_corruption() -> dict[str, bytes]:
    """Corrupt string length fields — primary source of heap overflows."""
    U64_MAX = 0xFFFFFFFFFFFFFFFF
    I64_MAX = 0x7FFFFFFFFFFFFFFF
    base    = gguf_header(3, 0, 1)   # 1 KV entry expected

    def raw_kv(key_len: int, key_bytes: bytes,
               vtype: int, val_len: int, val_bytes: bytes) -> bytes:
        return (struct.pack('<Q', key_len) + key_bytes
                + struct.pack('<I', vtype)
                + struct.pack('<Q', val_len) + val_bytes)

    # Key length overflows
    overflow_key = base + struct.pack('<Q', U64_MAX) + b'a' * 8
    huge_key     = base + struct.pack('<Q', I64_MAX) + b'b' * 8
    zero_key     = base + struct.pack('<Q', 0) + struct.pack('<I', T_UINT32) + struct.pack('<I', 0)

    # Valid key, corrupt string value length
    valid_key   = struct.pack('<Q', 4) + b'test'
    str_val_overflow = base + valid_key + struct.pack('<I', T_STRING) + struct.pack('<Q', U64_MAX)
    str_val_huge     = base + valid_key + struct.pack('<I', T_STRING) + struct.pack('<Q', I64_MAX)

    # Array with huge element count
    huge_array = (base + valid_key
                  + struct.pack('<I', T_ARRAY)
                  + struct.pack('<I', T_UINT32)   # elem type
                  + struct.pack('<I', 0xFFFFFFFF)) # element count

    # Nested array (array of arrays)
    nested_array = (base + valid_key
                    + struct.pack('<I', T_ARRAY)
                    + struct.pack('<I', T_ARRAY)
                    + struct.pack('<I', 4)
                    + struct.pack('<I', T_UINT32)
                    + struct.pack('<I', 1)
                    + struct.pack('<I', 42))

    return {
        'str_key_len_u64max.gguf':      overflow_key,
        'str_key_len_i64max.gguf':      huge_key,
        'str_key_len_zero.gguf':        zero_key,
        'str_val_len_u64max.gguf':      str_val_overflow,
        'str_val_len_i64max.gguf':      str_val_huge,
        'str_array_count_max.gguf':     huge_array,
        'str_nested_array.gguf':        nested_array,
    }


def seeds_tensor_corruption() -> dict[str, bytes]:
    """Corrupt tensor info fields — target dimension/type/offset parsing."""
    U64_MAX  = 0xFFFFFFFFFFFFFFFF
    U32_MAX  = 0xFFFFFFFF
    meta, kv_count = minimal_llama_metadata()

    def header_with_tensor(tensor_info: bytes) -> bytes:
        return gguf_header(3, 1, kv_count) + meta + tensor_info

    name = gguf_str(b'token_embd.weight')

    def tensor(n_dims: int, dims: list[int], ttype: int, offset: int) -> bytes:
        return (name
                + struct.pack('<I', n_dims)
                + b''.join(struct.pack('<Q', d) for d in dims)
                + struct.pack('<I', ttype)
                + struct.pack('<Q', offset))

    return {
        # Dimension count overflow
        'tens_ndims_u32max.gguf':       header_with_tensor(name + struct.pack('<I', U32_MAX)),
        'tens_ndims_zero.gguf':         header_with_tensor(tensor(0, [], GGML_F32, 0)),
        # Dimension value overflows — product overflows size_t
        'tens_dim_u64max.gguf':         header_with_tensor(tensor(1, [U64_MAX], GGML_F32, 0)),
        'tens_dim_overflow_2d.gguf':    header_with_tensor(tensor(2, [U64_MAX, U64_MAX], GGML_F32, 0)),
        'tens_dim_large_2d.gguf':       header_with_tensor(tensor(2, [0x100000, 0x100000], GGML_F32, 0)),
        'tens_dim_zero.gguf':           header_with_tensor(tensor(2, [0, 64], GGML_F32, 0)),
        # Invalid tensor type
        'tens_type_invalid.gguf':       header_with_tensor(tensor(1, [64], U32_MAX, 0)),
        'tens_type_large.gguf':         header_with_tensor(tensor(1, [64], 0xFF, 0)),
        # Offset overflows
        'tens_offset_u64max.gguf':      header_with_tensor(tensor(2, [64, 6], GGML_F32, U64_MAX)),
        'tens_offset_negative.gguf':    header_with_tensor(tensor(2, [64, 6], GGML_F32, 0xFFFFFFFF00000000)),
        # Mismatched: says 2 tensors but only info for 1
        'tens_count_mismatch.gguf':     gguf_header(3, 2, kv_count) + meta + tensor(2, [64, 6], GGML_F32, 0),
    }


def seeds_truncated() -> dict[str, bytes]:
    """Truncated files — hit every early-exit and bounds-check path."""
    full = build_minimal_model()
    return {
        'trunc_1byte.gguf':             full[:1],
        'trunc_2bytes.gguf':            full[:2],
        'trunc_magic_only.gguf':        full[:4],           # magic, no version
        'trunc_after_version.gguf':     full[:8],           # magic + version only
        'trunc_after_tensor_cnt.gguf':  full[:16],          # magic + version + tensor_count
        'trunc_after_header.gguf':      full[:24],          # complete header, no KV
        'trunc_mid_kv_key.gguf':        full[:32],          # mid-way through first KV key
        'trunc_mid_kv_value.gguf':      full[:48],          # mid-way through first KV value
        'trunc_80pct.gguf':             full[:int(len(full) * 0.8)],
        'trunc_90pct.gguf':             full[:int(len(full) * 0.9)],
        'trunc_last_byte.gguf':         full[:-1],
    }


def seeds_metadata_type_confusion() -> dict[str, bytes]:
    """
    Known-valid key names with wrong value types — hit type-switch branches
    and mismatched-expectation code paths.
    """
    results = {}
    base_header = gguf_header(3, 0, 1)
    key = gguf_str(b'general.architecture')

    for tname, ttype, val in [
        ('uint8',   T_UINT8,   struct.pack('<B', 42)),
        ('int8',    T_INT8,    struct.pack('<b', -1)),
        ('uint16',  T_UINT16,  struct.pack('<H', 9999)),
        ('uint32',  T_UINT32,  struct.pack('<I', 0xDEADBEEF)),
        ('int32',   T_INT32,   struct.pack('<i', -999)),
        ('float32', T_FLOAT32, struct.pack('<f', 3.14)),
        ('bool',    T_BOOL,    b'\x01'),
        ('uint64',  T_UINT64,  struct.pack('<Q', 0xCAFEBABEDEADBEEF)),
    ]:
        results[f'meta_arch_as_{tname}.gguf'] = (
            base_header + key + struct.pack('<I', ttype) + val
        )

    # Bool with invalid value (not 0 or 1)
    results['meta_bool_invalid.gguf'] = (
        base_header + gguf_str(b'general.quantized') + struct.pack('<I', T_BOOL) + b'\xFF'
    )
    return results


def seeds_alignment() -> dict[str, bytes]:
    """Bad tensor data alignment — hit alignment assertions and padding code."""
    meta, kv_count = minimal_llama_metadata()
    tensor_info = gguf_tensor_info(b'token_embd.weight', [64, 6], GGML_F32, 0)
    header = gguf_header(3, 1, kv_count)
    base   = header + meta + tensor_info

    tensor_data = b'\xAB' * (6 * 64 * 4)  # float32 data

    # No padding — data starts immediately (likely misaligned)
    no_pad    = base + tensor_data
    # Off-by-one padding
    one_pad   = base + b'\x00' + tensor_data
    # 31-byte padding (one short of correct 32-byte alignment)
    short_pad = base + b'\x00' * 31 + tensor_data
    # 33-byte padding (one over)
    over_pad  = base + b'\x00' * 33 + tensor_data

    return {
        'align_no_padding.gguf':    no_pad,
        'align_one_pad.gguf':       one_pad,
        'align_31_pad.gguf':        short_pad,
        'align_33_pad.gguf':        over_pad,
    }


# ── ONNX seed generator ───────────────────────────────────────────────────────

def build_minimal_onnx() -> bytes:
    """
    Minimal valid ONNX protobuf.  Field IDs from the ONNX spec:
      ModelProto:
        ir_version (1, varint)
        opset_import (8, length-delimited) → OperatorSetIdProto
          domain (1, string)
          version (2, varint)
        graph (7, length-delimited) → GraphProto
          node (1, length-delimited) → NodeProto  (empty)
          name (2, string)
    """
    def varint(n: int) -> bytes:
        out = b''
        while True:
            b = n & 0x7F
            n >>= 7
            out += bytes([b | (0x80 if n else 0)])
            if not n:
                break
        return out

    def pb_field(field_id: int, wire_type: int, data: bytes) -> bytes:
        tag = (field_id << 3) | wire_type
        return varint(tag) + (varint(len(data)) if wire_type == 2 else b'') + data

    def pb_string(field_id: int, s: bytes) -> bytes:
        return pb_field(field_id, 2, s)

    def pb_varint(field_id: int, n: int) -> bytes:
        return pb_field(field_id, 0, varint(n))

    def pb_bytes(field_id: int, b: bytes) -> bytes:
        return pb_field(field_id, 2, b)

    opset  = pb_string(1, b'') + pb_varint(2, 17)        # domain='', version=17
    graph  = pb_string(2, b'fuzz-graph')                  # name only, no nodes
    model  = (pb_varint(1, 8)                             # ir_version=8
              + pb_bytes(8, opset)                        # opset_import
              + pb_bytes(7, graph))                       # graph
    return model


def seeds_onnx() -> dict[str, bytes]:
    """ONNX seeds targeting protobuf parsing and model validation."""
    base = build_minimal_onnx()
    return {
        'onnx_valid_minimal.onnx':         base,
        'onnx_empty.onnx':                 b'',
        'onnx_truncated_half.onnx':        base[:len(base)//2],
        'onnx_truncated_1byte.onnx':       base[:1],
        'onnx_all_zeros.onnx':             b'\x00' * 64,
        'onnx_all_ff.onnx':                b'\xFF' * 64,
        'onnx_large_ir_version.onnx':      b'\x08\xFF\xFF\xFF\xFF\x0F' + base[2:],  # ir_version=MAX
        'onnx_random_protobuf.onnx':       bytes(range(256)) * 2,
        'onnx_huge_field_len.onnx':        b'\x3A\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x01' + b'x',
    }


# ── Deep-valid seeds ──────────────────────────────────────────────────────────
# Seeds that pass ALL header / metadata checks so AFL++ reaches the deep
# tensor-allocation and weight-loading code in llama_model_load_tensors().
# Without these, AFL++ gets stuck at early rejection branches and never
# reaches the memory-management code where bugs live.

def full_llama_metadata(context_length: int = 512, embedding_length: int = 64,
                        block_count: int = 1, head_count: int = 2,
                        head_count_kv: int = 2, ff_length: int = 128,
                        rope_dim: int = 32, vocab_size: int = 6) -> tuple[bytes, int]:
    """Full set of KV pairs required for llama.cpp to begin loading weights."""
    tokens = [b'<unk>', b'<s>', b'</s>', b'a', b'b', b'c'][:vocab_size]
    kvs = [
        gguf_kv_string(b'general.architecture',                b'llama'),
        gguf_kv_string(b'general.name',                        b'fuzz-deep'),
        gguf_kv_uint32(b'llama.context_length',                context_length),
        gguf_kv_uint32(b'llama.embedding_length',              embedding_length),
        gguf_kv_uint32(b'llama.block_count',                   block_count),
        gguf_kv_uint32(b'llama.feed_forward_length',           ff_length),
        gguf_kv_uint32(b'llama.rope.dimension_count',          rope_dim),
        gguf_kv_uint32(b'llama.attention.head_count',          head_count),
        gguf_kv_uint32(b'llama.attention.head_count_kv',       head_count_kv),
        gguf_kv_float32(b'llama.attention.layer_norm_rms_epsilon', 1e-5),
        gguf_kv_string(b'tokenizer.ggml.model',                b'llama'),
        gguf_kv_array(b'tokenizer.ggml.tokens', T_STRING,
                      [gguf_str(t) for t in tokens]),
        gguf_kv_array(b'tokenizer.ggml.scores', T_FLOAT32,
                      [struct.pack('<f', float(i)) for i in range(vocab_size)]),
        gguf_kv_array(b'tokenizer.ggml.token_type', T_INT32,
                      [struct.pack('<i', 0) for _ in range(vocab_size)]),
        gguf_kv_uint32(b'tokenizer.ggml.bos_token_id', 1),
        gguf_kv_uint32(b'tokenizer.ggml.eos_token_id', 2),
    ]
    return b''.join(kvs), len(kvs)


def build_deep_model(context_length: int = 512, embedding_length: int = 64,
                     block_count: int = 1, head_count: int = 2,
                     ff_length: int = 128, rope_dim: int = 32,
                     vocab_size: int = 6,
                     corrupt_data: bool = False,
                     tensor_dims_override: list | None = None,
                     tensor_offset_override: int | None = None) -> bytes:
    """
    Complete GGUF that passes all header + metadata validation.
    Optionally corrupts the tensor data/offset/dims for deep crash coverage.
    """
    meta_bytes, kv_count = full_llama_metadata(
        context_length, embedding_length, block_count, head_count, head_count,
        ff_length, rope_dim, vocab_size,
    )
    dims   = tensor_dims_override if tensor_dims_override is not None else [embedding_length, vocab_size]
    offset = tensor_offset_override if tensor_offset_override is not None else 0

    tensor_info = gguf_tensor_info(b'token_embd.weight', dims, GGML_F32, offset)
    header      = gguf_header(GGUF_VERSION, 1, kv_count)
    pre_data    = header + meta_bytes + tensor_info
    padding     = b'\x00' * ((32 - len(pre_data) % 32) % 32)

    data_size = max(0, embedding_length) * max(0, vocab_size) * 4
    tensor_data = (b'\xff' * data_size) if corrupt_data else (b'\x00' * data_size)
    return pre_data + padding + tensor_data


def seeds_deep_valid() -> dict[str, bytes]:
    """
    Seeds that reach llama_model_load_tensors() — the code that allocates and
    maps weight data.  Without ASAN these may be silent; with ASAN preloaded
    by AFL++ they will turn heap OOB / wrong-size allocations into SIGABRT.
    """
    U64_MAX = 0xFFFFFFFFFFFFFFFF
    U32_MAX = 0xFFFFFFFF

    full = build_deep_model()

    return {
        # Good base for AFL++ to mutate from — structurally 100 % valid
        'deep_base_valid.gguf':            full,

        # Tensor data filled with 0xFF → NaN / Inf floats → numerical edge cases
        'deep_tensor_data_ff.gguf':        build_deep_model(corrupt_data=True),

        # Tensor offset past EOF → OOB mmap/read during weight mapping
        'deep_offset_past_eof.gguf':       build_deep_model(tensor_offset_override=0xFFFFFFFF),

        # Tensor offset into the header area → wrong section read
        'deep_offset_into_header.gguf':    build_deep_model(tensor_offset_override=4),

        # Hugely large context → forces giant KV-cache allocation
        'deep_huge_context.gguf':          build_deep_model(context_length=U32_MAX),

        # Zero context length → division-by-zero or zero-size alloc edge case
        'deep_zero_context.gguf':          build_deep_model(context_length=0),

        # Large embedding_length → huge weight tensor allocation
        'deep_large_embedding.gguf':       build_deep_model(
                                               embedding_length=65536,
                                               ff_length=65536 * 4,
                                               rope_dim=64),

        # Declared tensor dims overflow (total bytes = U64_MAX × vocab × 4)
        'deep_dim_u64max.gguf':            build_deep_model(
                                               tensor_dims_override=[U64_MAX, 6]),

        # Zero first dimension → zero-size tensor edge case
        'deep_dim_zero.gguf':              build_deep_model(
                                               tensor_dims_override=[0, 64]),

        # 1000 blocks → allocation loop repeated 1000 × for attention tensors
        'deep_many_blocks.gguf':           build_deep_model(
                                               block_count=1000, context_length=64),

        # head_count > embedding_length → head_size rounds to 0 or wraps
        'deep_head_overflow.gguf':         build_deep_model(
                                               head_count=U32_MAX, embedding_length=64),

        # Truncated by 1 byte — weight mmap reads past the file
        'deep_truncated_1b.gguf':          full[:-1],

        # Truncated midway through tensor data
        'deep_truncated_half_data.gguf':   full[:len(full) - (64 * 6 * 4) // 2],

        # Trailing garbage — AFL++ learns to keep valid prefix + mutate suffix
        'deep_trailing_garbage.gguf':      full + b'\xff' * 512,
    }


# ── Writer ────────────────────────────────────────────────────────────────────

CATEGORIES = [
    ('llama', 'valid',             seeds_valid),
    ('llama', 'deep_valid',        seeds_deep_valid),
    ('llama', 'header_corruption', seeds_header_corruption),
    ('llama', 'count_overflows',   seeds_count_overflows),
    ('llama', 'string_corruption', seeds_string_corruption),
    ('llama', 'tensor_corruption', seeds_tensor_corruption),
    ('llama', 'truncated',         seeds_truncated),
    ('llama', 'type_confusion',    seeds_metadata_type_confusion),
    ('llama', 'alignment',         seeds_alignment),
    ('onnx',  'valid',             seeds_onnx),
]


def main():
    base_dir = Path(__file__).parent / 'seeds'

    total = 0
    for binary_type, category, fn in CATEGORIES:
        out_dir = base_dir / binary_type / category
        out_dir.mkdir(parents=True, exist_ok=True)

        seeds = fn()
        for filename, data in seeds.items():
            path = out_dir / filename
            path.write_bytes(data)
            log.info(f"  {binary_type}/{category}/{filename:45s}  {len(data):>8,} bytes")
            total += 1

    # Flat corpus directories AFL++ will use directly
    for binary_type in ('llama', 'onnx'):
        flat = base_dir / binary_type / 'corpus'
        flat.mkdir(parents=True, exist_ok=True)

        src = base_dir / binary_type
        for seed_file in src.rglob('*.*'):
            if seed_file.parent.name == 'corpus':
                continue
            dest = flat / f"{seed_file.parent.name}__{seed_file.name}"
            dest.write_bytes(seed_file.read_bytes())

    log.info(f"\nGenerated {total} seeds across {len(CATEGORIES)} categories")
    log.info(f"Flat corpus: {base_dir}/llama/corpus/  ({len(list((base_dir/'llama'/'corpus').glob('*')))} files)")
    log.info(f"Flat corpus: {base_dir}/onnx/corpus/   ({len(list((base_dir/'onnx'/'corpus').glob('*')))} files)")
    log.info(f"\nPoint AFL++ at:  seeds/llama/corpus/  or  seeds/onnx/corpus/")


if __name__ == '__main__':
    main()
