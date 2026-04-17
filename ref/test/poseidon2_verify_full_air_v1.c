#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../poseidon2.h"
#include "../api.h"
#include "../address.h"
#include "../hash_poseidon2_adapter.h"
#include "../stark/air_verify_full.h"

static void fail(const char *name)
{
    printf("FAIL: %s\n", name);
}

static void addr_set_byte(uint32_t addr_words[8], size_t byte_index, uint8_t value)
{
    size_t word = byte_index / 4u;
    size_t shift = (byte_index % 4u) * 8u;
    uint32_t mask = (uint32_t)0xffu << shift;
    addr_words[word] = (addr_words[word] & ~mask) | ((uint32_t)value << shift);
}

static uint8_t addr_get_byte(const uint32_t addr_words[8], size_t byte_index)
{
    size_t word = byte_index / 4u;
    size_t shift = (byte_index % 4u) * 8u;
    return (uint8_t)((addr_words[word] >> shift) & 0xffu);
}

typedef struct
{
    uint32_t hash_message_calls;
    uint32_t prf_addr_calls;
    uint32_t fors_addr_calls;
    uint32_t wots_addr_calls;
    uint32_t merkle_addr_calls;
    uint32_t top_merkle_calls;
} module_stats_t;

static void collect_module_stats(const spx_p2_trace *trace, module_stats_t *stats)
{
    size_t i;
    memset(stats, 0, sizeof(*stats));
    for (i = 0; i < trace->call_count; i++)
    {
        const spx_p2_hash_call *call = &trace->calls[i];
        uint8_t type_byte = addr_get_byte(call->addr_words, SPX_OFFSET_TYPE);
        uint8_t hgt = addr_get_byte(call->addr_words, SPX_OFFSET_TREE_HGT);
        if (call->domain_tag == SPX_P2_DOMAIN_HASH_MESSAGE)
        {
            stats->hash_message_calls++;
        }
        if (call->domain_tag == SPX_P2_DOMAIN_PRF_ADDR)
        {
            stats->prf_addr_calls++;
        }
        if (type_byte == SPX_ADDR_TYPE_FORSPRF ||
            type_byte == SPX_ADDR_TYPE_FORSTREE ||
            type_byte == SPX_ADDR_TYPE_FORSPK)
        {
            stats->fors_addr_calls++;
        }
        if (type_byte == SPX_ADDR_TYPE_WOTSPRF ||
            type_byte == SPX_ADDR_TYPE_WOTS ||
            type_byte == SPX_ADDR_TYPE_WOTSPK)
        {
            stats->wots_addr_calls++;
        }
        if (type_byte == SPX_ADDR_TYPE_HASHTREE)
        {
            stats->merkle_addr_calls++;
            if ((call->domain_tag == SPX_P2_DOMAIN_THASH_H ||
                 call->domain_tag == SPX_P2_DOMAIN_THASH_TL) &&
                hgt >= (uint8_t)(SPX_TREE_HEIGHT - 1))
            {
                stats->top_merkle_calls++;
            }
        }
    }
}

int main(void)
{
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t pk_tampered[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
    uint8_t com[SPX_N];
    uint8_t sig[SPX_BYTES];
    uint8_t m[24];
    uint8_t r[16];
    size_t siglen = 0;
    spx_p2_trace trace;
    spx_p2_trace trace_tampered;
    spx_p2_witness_row_v1 *rows = 0;
    size_t row_count = 0;
    spx_p2_verify_full_proof_v1 proof;
    uint32_t module_constraints = 0, module_violations = 0;
    uint32_t constraints = 0, violations = 0;
    module_stats_t stats;
    size_t i;
    int found_prf = 0, found_hash_message = 0, found_top_merkle = 0;
    int found_wots_f = 0, found_thash_h = 0;

    memset(m, 0x5a, sizeof(m));
    memset(r, 0xa5, sizeof(r));

    if (crypto_sign_keypair(pk, sk) != 0)
    {
        fail("keypair");
        return 1;
    }
    spx_p2_commit(com, m, sizeof(m), r, sizeof(r));
    if (crypto_sign_signature(sig, &siglen, com, SPX_N, sk) != 0 || siglen != SPX_BYTES)
    {
        fail("sign");
        return 1;
    }
    if (spx_p2_trace_verify_com(&trace, pk, com, sig) != 0)
    {
        fail("trace_verify");
        return 1;
    }
    if (spx_p2_witness_count_rows_v1(&trace, &row_count) != 0 || row_count == 0)
    {
        fail("count_rows");
        return 1;
    }
    rows = (spx_p2_witness_row_v1 *)malloc(row_count * sizeof(spx_p2_witness_row_v1));
    if (rows == 0)
    {
        fail("malloc_rows");
        return 1;
    }
    if (spx_p2_witness_build_rows_v1(rows, row_count, &row_count, &trace) != 0)
    {
        fail("build_rows");
        free(rows);
        return 1;
    }
    if (spx_p2_verify_full_air_eval_module_constraints_v1(&trace, &module_constraints, &module_violations) != 0)
    {
        fail("eval_module");
        free(rows);
        return 1;
    }
    if (module_violations != 0)
    {
        collect_module_stats(&trace, &stats);
        printf("DEBUG module: constraints=%u violations=%u hash_message=%u prf_addr=%u fors=%u wots=%u merkle=%u top_merkle=%u calls=%u dropped=(%u,%u)\n",
               module_constraints, module_violations,
               stats.hash_message_calls, stats.prf_addr_calls,
               stats.fors_addr_calls, stats.wots_addr_calls,
               stats.merkle_addr_calls, stats.top_merkle_calls,
               trace.call_count, trace.dropped_calls, trace.dropped_lanes);
        fail("module_violations_nonzero");
        free(rows);
        return 1;
    }

    if (spx_p2_verify_full_air_eval_constraints_v1(pk, com, sig, &trace, rows, row_count,
                                                   &constraints, &violations) != 0)
    {
        fail("eval");
        free(rows);
        return 1;
    }
    if (violations != 0)
    {
        fail("violations_nonzero");
        free(rows);
        return 1;
    }
    if (spx_p2_verify_full_air_prove_v1(&proof, pk, com, sig, &trace, rows, row_count) != 0)
    {
        fail("prove");
        free(rows);
        return 1;
    }
    if (spx_p2_verify_full_air_verify_v1(&proof, pk, com, sig, &trace, rows, row_count) != 0)
    {
        fail("verify");
        free(rows);
        return 1;
    }

    memcpy(pk_tampered, pk, sizeof(pk_tampered));
    pk_tampered[SPX_N] ^= 1u;
    if (spx_p2_verify_full_air_eval_constraints_v1(pk_tampered, com, sig, &trace, rows, row_count,
                                                    &constraints, &violations) != 0 ||
        violations == 0)
    {
        fail("tamper_pk_root_binding");
        free(rows);
        return 1;
    }

    sig[0] ^= 1u;
    if (spx_p2_verify_full_air_verify_v1(&proof, pk, com, sig, &trace, rows, row_count) == 0)
    {
        fail("tamper_sigma");
        free(rows);
        return 1;
    }
    sig[0] ^= 1u;

    rows[1].lane_value ^= 1u;
    if (spx_p2_verify_full_air_verify_v1(&proof, pk, com, sig, &trace, rows, row_count) == 0)
    {
        fail("tamper_rows");
        free(rows);
        return 1;
    }
    rows[1].lane_value ^= 1u;

    memcpy(&trace_tampered, &trace, sizeof(trace_tampered));
    trace_tampered.calls[0].domain_tag ^= 1u;
    if (spx_p2_verify_full_air_verify_v1(&proof, pk, com, sig, &trace_tampered, rows, row_count) == 0)
    {
        fail("tamper_trace");
        free(rows);
        return 1;
    }

    trace_tampered = trace;
    trace_tampered.dropped_calls = 1;
    if (spx_p2_verify_full_air_verify_v1(&proof, pk, com, sig, &trace_tampered, rows, row_count) == 0)
    {
        fail("tamper_drop_meta");
        free(rows);
        return 1;
    }

    memcpy(&trace_tampered, &trace, sizeof(trace_tampered));
    for (i = 0; i < trace_tampered.call_count; i++)
    {
        if (trace_tampered.calls[i].domain_tag == SPX_P2_DOMAIN_PRF_ADDR)
        {
            addr_set_byte(trace_tampered.calls[i].addr_words, SPX_OFFSET_TYPE, (uint8_t)SPX_ADDR_TYPE_WOTS);
            found_prf = 1;
            break;
        }
    }
    if (!found_prf)
    {
        printf("INFO: skip tamper_prf_type_module (no prf_addr call in trace)\n");
    }
    else if (spx_p2_verify_full_air_eval_module_constraints_v1(&trace_tampered, &module_constraints, &module_violations) != 0 ||
             module_violations == 0)
    {
        fail("tamper_prf_type_module");
        free(rows);
        return 1;
    }

    memcpy(&trace_tampered, &trace, sizeof(trace_tampered));
    for (i = 0; i < trace_tampered.call_count; i++)
    {
        if (trace_tampered.calls[i].domain_tag == SPX_P2_DOMAIN_HASH_MESSAGE)
        {
            trace_tampered.calls[i].output_real_len ^= 1u;
            found_hash_message = 1;
            break;
        }
    }
    if (!found_hash_message)
    {
        printf("INFO: skip tamper_hash_message_len_module (no hash_message call in trace)\n");
    }
    else if (spx_p2_verify_full_air_eval_module_constraints_v1(&trace_tampered, &module_constraints, &module_violations) != 0 ||
             module_violations == 0)
    {
        fail("tamper_hash_message_len_module");
        free(rows);
        return 1;
    }

    memcpy(&trace_tampered, &trace, sizeof(trace_tampered));
    for (i = 0; i < trace_tampered.call_count; i++)
    {
        uint8_t type_byte = addr_get_byte(trace_tampered.calls[i].addr_words, SPX_OFFSET_TYPE);
        if (type_byte == SPX_ADDR_TYPE_WOTS &&
            trace_tampered.calls[i].domain_tag == SPX_P2_DOMAIN_THASH_F)
        {
            trace_tampered.calls[i].domain_tag = SPX_P2_DOMAIN_THASH_H;
            found_wots_f = 1;
            break;
        }
    }
    if (!found_wots_f)
    {
        printf("INFO: skip tamper_wots_domain_module (no WOTS+THASH_F call in trace)\n");
    }
    else if (spx_p2_verify_full_air_eval_module_constraints_v1(&trace_tampered, &module_constraints, &module_violations) != 0 ||
             module_violations == 0)
    {
        fail("tamper_wots_domain_module");
        free(rows);
        return 1;
    }

    memcpy(&trace_tampered, &trace, sizeof(trace_tampered));
    for (i = 0; i < trace_tampered.call_count; i++)
    {
        if (trace_tampered.calls[i].domain_tag == SPX_P2_DOMAIN_THASH_H)
        {
            trace_tampered.calls[i].input_real_len += SPX_N;
            found_thash_h = 1;
            break;
        }
    }
    if (!found_thash_h)
    {
        printf("INFO: skip tamper_thash_h_inblocks_module (no THASH_H call in trace)\n");
    }
    else if (spx_p2_verify_full_air_eval_module_constraints_v1(&trace_tampered, &module_constraints, &module_violations) != 0 ||
             module_violations == 0)
    {
        fail("tamper_thash_h_inblocks_module");
        free(rows);
        return 1;
    }

    memcpy(&trace_tampered, &trace, sizeof(trace_tampered));
    found_top_merkle = 0;
    for (i = 0; i < trace_tampered.call_count; i++)
    {
        uint8_t type_byte = addr_get_byte(trace_tampered.calls[i].addr_words, SPX_OFFSET_TYPE);
        uint8_t hgt = addr_get_byte(trace_tampered.calls[i].addr_words, SPX_OFFSET_TREE_HGT);
        if (type_byte == SPX_ADDR_TYPE_HASHTREE)
        {
            if (hgt >= (uint8_t)(SPX_TREE_HEIGHT - 1))
            {
                found_top_merkle = 1;
            }
            addr_set_byte(trace_tampered.calls[i].addr_words, SPX_OFFSET_TREE_HGT, 0u);
        }
    }
    if (!found_top_merkle)
    {
        printf("INFO: skip tamper_top_merkle_module (no top merkle call in trace)\n");
    }
    else
    {
        int module_ret = spx_p2_verify_full_air_eval_module_constraints_v1(&trace_tampered, &module_constraints, &module_violations);
        if (module_ret != 0 || module_violations == 0)
        {
            module_stats_t tampered_stats;
            collect_module_stats(&trace_tampered, &tampered_stats);
            printf("DEBUG tamper_top: ret=%d constraints=%u violations=%u hash_message=%u prf_addr=%u fors=%u wots=%u merkle=%u top_merkle=%u\n",
                   module_ret, module_constraints, module_violations,
                   tampered_stats.hash_message_calls, tampered_stats.prf_addr_calls,
                   tampered_stats.fors_addr_calls, tampered_stats.wots_addr_calls,
                   tampered_stats.merkle_addr_calls, tampered_stats.top_merkle_calls);
            fail("tamper_top_merkle_module");
            free(rows);
            return 1;
        }
    }

    printf("poseidon2_verify_full_air_v1 test: OK | constraints=%u module_constraints=%u rows=%llu calls=%u\n",
           constraints, module_constraints, (unsigned long long)row_count, trace.call_count);
    free(rows);
    return 0;
}
