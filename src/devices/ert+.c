/** @file
    ERT SCM sensors.

    Copyright (C) 2020 Benjamin Larsson.

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

#include "decoder.h"

/**
ERT SCM+ / IDM sensors.

Random information:

https://github.com/bemasher/rtlamr

https://github.com/bemasher/rtlamr/wiki/Protocol

https://en.wikipedia.org/wiki/Encoder_receiver_transmitter

*/

struct header_t {
    uint8_t sync[2];
    uint8_t protocol_id;
};

struct scm {
    struct header_t header;
    uint8_t endpoint_type;
    uint32_t endpoint_id;
    uint32_t consumption;
    uint16_t tamper;
    uint16_t checksum;
};

#pragma pack(push, 1)
struct idm_t {
    uint8_t preamble[2];
    struct header_t header;
    uint8_t packet_length;
    uint8_t hamming_code;
    uint8_t application_version;
    uint8_t endpoint_type;
    uint32_t endpoint_id;
    uint8_t consumption_interval_count; // Indicates when received message from new interval
    uint8_t module_programming_state;
    uint8_t tamper_count[6];
    uint16_t async_count;
    uint8_t power_outage_flags[6];
    uint32_t last_consumption;
    uint8_t differential_consumption[53];
    uint16_t transmit_time_offset;
    uint16_t meter_id_checksum;
    uint16_t packet_checksum;
};
#pragma pack(pop)

uint16_t
byte_swap_16(uint16_t num)
{
    return (num >> 8) | (num << 8);
}

uint32_t byte_swap_32(uint32_t num)
{
    return ((num >> 24) & 0xff) |      // move byte 3 to byte 0
           ((num << 8) & 0xff0000) |   // move byte 1 to byte 2
           ((num >> 8) & 0xff00) |     // move byte 2 to byte 1
           ((num << 24) & 0xff000000); // byte 0 to byte 3
}

static int ertp_decode(r_device *decoder, bitbuffer_t *bitbuffer)
{
    static const uint8_t ERT_PREAMBLE[] = {0x16, 0xA3};
    static const uint8_t SCM_PLUS_ID    = 0x1E;
    static const uint8_t IDM_ID         = 0x1C;
    struct scm b, d;
    struct header_t header;
    struct idm_t idm_raw_packet, idm_proccessed_packet;
    data_t *data;

    // Need at least 128 bytes to decode.
    if (bitbuffer->bits_per_row[0] <= 16 * 8)
        return DECODE_ABORT_LENGTH;

    uint32_t message_idx = bitbuffer_search(bitbuffer, 0, 0, ERT_PREAMBLE, 16);
    if (message_idx == bitbuffer->bits_per_row[0])
        return DECODE_FAIL_SANITY;

    bitbuffer_extract_bytes(bitbuffer, 0, message_idx, (void *)&header, sizeof(struct header_t)*8);
    // Handle SCM+ messages
    if (header.protocol_id == SCM_PLUS_ID)
    {
        bitbuffer_extract_bytes(bitbuffer, 0, message_idx, (void *)&b, sizeof(struct scm));
        memcpy(d.header.sync, b.header.sync, 2);
        d.header.protocol_id = b.header.protocol_id;
        d.endpoint_type = b.endpoint_type;
        d.endpoint_id   = byte_swap_32(b.endpoint_id);
        d.consumption   = byte_swap_32(b.consumption);
        d.tamper        = byte_swap_16(b.tamper);
        d.checksum      = byte_swap_16(b.checksum);

        uint16_t checksum;
        if ((checksum = crc16(&b.header.protocol_id, 12, 0x1021, 0xFFFF) ^ 0xFFFF) != d.checksum) {
            printf("%#04x != %#04x\n", checksum, d.checksum);
            return DECODE_FAIL_MIC;
        }

        /* clang-format off */
        data = data_make(
                "model", "", DATA_STRING, "ERT-SCM+",
                "protocol_id", "Protocol Id", DATA_FORMAT, "0x%02x", DATA_INT, d.header.protocol_id,
                "endpoint_type", "Endpoint Type", DATA_FORMAT, "0x%02x", DATA_INT, d.endpoint_type,
                "id", "Endpoint ID", DATA_FORMAT, "%d", DATA_INT, d.endpoint_id,
                "consumption", "Consumption Data", DATA_FORMAT, "%d", DATA_INT, d.consumption,
                "tamper", "Tamper", DATA_FORMAT, "0x%04x", DATA_INT, d.tamper,
                "mic", "Integrity", DATA_STRING, "CRC",
                NULL);
        /* clang-format on */
    }
    // Handle IDM messages
    else if  (header.protocol_id == IDM_ID)
    {
        // Need at least 128 bytes to decode.
        if (bitbuffer->bits_per_row[0] < 92 * 8)
            return DECODE_ABORT_LENGTH;

        bitbuffer_extract_bytes(bitbuffer, 0, message_idx - 2 * 8, (void *)&idm_raw_packet, sizeof(struct idm_t)*8);

        // Few sanity checks
        if (idm_raw_packet.packet_length != 0x5C)
        {
            return DECODE_FAIL_SANITY;
        }
        if (idm_raw_packet.hamming_code != 0xC6)
        {
            return DECODE_FAIL_SANITY;
        }

        // Copy all of the data, then transform the data as necessary
        memcpy(&idm_proccessed_packet, &idm_raw_packet, sizeof(struct idm_t));
        idm_proccessed_packet.header.protocol_id = idm_raw_packet.header.protocol_id;
        idm_proccessed_packet.endpoint_id        = byte_swap_32(idm_raw_packet.endpoint_id);
        idm_proccessed_packet.last_consumption   = byte_swap_32(idm_raw_packet.last_consumption);
        idm_proccessed_packet.transmit_time_offset = byte_swap_16(idm_raw_packet.transmit_time_offset);
        idm_proccessed_packet.meter_id_checksum    = byte_swap_16(idm_raw_packet.meter_id_checksum);
        idm_proccessed_packet.packet_checksum  = byte_swap_16(idm_raw_packet.packet_checksum);

        uint16_t checksum = crc16(&idm_raw_packet.header.protocol_id, 92 - 6, 0x1021, 0xFFFF) ^ 0xFFFF;

        if (checksum != idm_proccessed_packet.packet_checksum)
            return DECODE_FAIL_MIC;

        // print_idm(idm_raw_packet);
        // print_idm(idm_proccessed_packet);
        data = data_make(
                "model", "", DATA_STRING, "ERT-IDM",
                "protocol_id", "Protocol Id", DATA_FORMAT, "0x%02x", DATA_INT, idm_proccessed_packet.header.protocol_id,
                "endpoint_type", "Endpoint Type", DATA_FORMAT, "0x%02x", DATA_INT, idm_proccessed_packet.endpoint_type,
                "id", "Endpoint ID", DATA_FORMAT, "%d", DATA_INT, idm_proccessed_packet.endpoint_id,
                "consumption_int_cnt", "Consumption Interval Count", DATA_FORMAT, "0x%02x", DATA_INT, idm_proccessed_packet.consumption_interval_count,
                "module_prog_state", "Module Programming State", DATA_FORMAT, "0x%02x", DATA_INT, idm_proccessed_packet.module_programming_state,
                "async_count", "Async Count", DATA_FORMAT, "0x%04x", DATA_INT, idm_proccessed_packet.async_count,
                "consumption", "Energy", DATA_FORMAT, "%d", DATA_INT, idm_proccessed_packet.last_consumption,
                // "tamper", "Tamper Counts", DATA_ARRAY, data_array(6, DATA_INT, idm_proccessed_packet.tamper_count),
                "transmit_time_offset", "Transmit Time Offset", DATA_FORMAT, "0x%04x", DATA_INT, idm_proccessed_packet.transmit_time_offset,
                "mic", "Integrity", DATA_STRING, "CRC",
                NULL);
    }
    else
    {
        return DECODE_FAIL_SANITY;
    }

    decoder_output_data(decoder, data);
    return 1;
}

static char *output_fields[] = {
        "model",
        "protocol_id",
        "endpoint_type",
        "id",
        "consumption_int_cnt",
        "module_prog_state",
        "async_count",
        "consumption",
        "tamper",
        "transmit_time_offset",
        "mic",
        NULL,
};

r_device ert_scm_plus = {
        .name        = "ert_scm_plus",
        .modulation  = OOK_PULSE_MANCHESTER_ZEROBIT,
        .short_width = 30,
        .long_width  = 0,
        .gap_limit   = 0,
        .reset_limit = 64,
        .decode_fn   = &ertp_decode,
        .disabled    = 0,
        .fields      = output_fields,
};
