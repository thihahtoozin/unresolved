#ifndef DNS_H
#define DNS_H

#include <stdint.h>
#include <sys/socket.h>
#include "zoneloader.h"

#define MASK_1BIT 0x01          // 0b00000001
#define MASK_2BITS 0x03         // 0b00000011
#define MASK_3BITS 0x07         // 0b00000111
#define MASK_4BITS 0x0F         // 0b00001111
#define MASK_8BITS 0xFF         // 0b11111111

#define DNS_MAX_RDATA 256
#define MAX_PENDINGS 10

/* Header 12 Bytes */
typedef struct{
    uint16_t trans_id;           // ID
    uint16_t flags;              // Raw Flags
    uint16_t qd_count;           // Num of Questions
    uint16_t an_count;           // Num of Answer Records
    uint16_t ns_count;           // Num of NS Records
    uint16_t ar_count;           // Num of Additional Records
    //flag_t flag_values;
}dns_header_t;

/* Flag Values */
typedef struct{
    unsigned int qr;             // 0 for request, 1 for response
    unsigned int opcode;         // 0 for standard query
    unsigned int aa;             // Authoritative Answer
    unsigned int tc;             // TrunCation
    unsigned int rd;             // Recursion Desired
    unsigned int ra;             // Recursion Available
    unsigned int rcode;          // Response Code (0 for no error)
}dns_flag_t;

/* Query */
typedef struct{
    char question[128];          // www.example.com.
    size_t q_len;
    uint16_t qtype;
    uint16_t qclass;
}dns_query_t;

/* Answer, Authority, Additional */
typedef struct{
    /* Name */
    uint16_t name_ptr;           // Message Compression (`c0 0c` for 12 bytes offset) 0xc00c

    /* Type, Class, TTL */
    uint16_t type;               // A, CNAME, ...
    uint16_t class_;             // IN
    uint32_t ttl;                // Time To Live in seconds

    /* RDATA */
    uint16_t rdlength;           // Length of RDATA
    char rdata[DNS_MAX_RDATA];   // Variable length accouding to rdlength
}dns_rr_t;

/* DNS Packet */
typedef struct{
    dns_header_t header;             // Header
    dns_query_t query;               // Question
    dns_rr_t ans;                   // Answer
}dns_t;

/* Zone Lookup */
typedef struct{
    record_t *answers[8];        // Addresses to Resource Records
    size_t n_ans;

    record_t *additional[8];      // Addresses to Additional Records
    size_t n_add;

    short authoritative;         // 0 for Authoritative Answer
}zone_lookup_res_t;

/* TXID Mappings */
typedef struct{
        int in_use;  // 0 for not using, 1 for using

        uint16_t client_txid;
        uint16_t upstream_txid;

        struct sockaddr_in *client_addr;

}pending_query_t;


#endif
