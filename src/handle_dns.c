#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <sys/socket.h>
#include <arpa/inet.h>

#include "dns.h"
#include "client.h"
#include "zoneloader.h"

// int offset = 12;
int parse_question(const char *buffer, int offset, dns_query_t *query){
    int pos = offset;
    unsigned int question_len = 0;
    unsigned int query_i = 0;
    while(buffer[pos] != '\0'){
        int label_len = buffer[pos++];
        if(label_len == 0) break;

        question_len += label_len;
        for(int i = 0; i < label_len; i++){
            query->question[query_i++] = buffer[pos++];
        }
        query->question[query_i++] = '.';
        question_len++;
    }
    if(query_i > 0) query_i--;       // To remove the last dot
    query->question[query_i] = '\0'; // Overwrites the last dot at the end
    pos++;                           // Skip the null byte on buffer
    
    query->qtype = (buffer[pos] << 8) | buffer[pos+1];
    pos += 2;

    query->qclass = (buffer[pos] << 8) | buffer[pos+1];
    pos += 2;

    query->q_len = question_len;

    return pos; // returns the final offset value
}

void read_request(const char *buffer, client_t *client){

    /* Extract data from the client's request */

    /* Extract Header */
    dns_t *req = &client->req;
    dns_header_t *header = &req->header;
    dns_query_t *query = &req->query;

    header->trans_id = ((unsigned char) buffer[0] << 8) | (unsigned char) buffer[1];
    uint16_t x = (buffer[0] << 8) | buffer[1];
    printf("header->trans_id : %d\n", header->trans_id);
    printf("x : %d\n", x);
    printf("buffer[0] : %d\n", buffer[0]);
    printf("buffer[1] : %d\n", buffer[1]);
    header->flags = (buffer[2] << 8) | buffer[3];
    header->qd_count = (buffer[4] << 8) | buffer[5];   // Number of Questions
    header->an_count = (buffer[6] << 8) | buffer[7];   // Number of Answer Records
    header->ns_count = (buffer[8] << 8) | buffer[9];   // Number of Name Server Records
    header->ar_count = (buffer[10] << 8) | buffer[11]; // Number of Additional Records

    // Flag Values
    // flag_t *flag_values = &header->flag_values;
    // flag_values->qr = (flags >> 15) & MASK_1BIT;       // Must be 0 for request
    // flag_values->opcode = (flags >> 11) & MASK_4BITS;  // 0 for standard query
    // flag_values->aa = (flags >> 10) & MASK_1BIT;       // Authoritative Answer
    // flag_values->tc = (flags >> 9) & MASK_1BIT;        // TrunCation
    // flag_values->rd = (flags >> 8) & MASK_1BIT;        // Recursion Desired
    // flag_values->ra = (flags >> 7) & MASK_1BIT;        // Recursion Available
    // flag_values->rcode = flags & MASK_4BITS;           // Response Code (can hard code 0 for no error)

    /* Extract Question */
    parse_question(buffer, 12, query);
    // query->question
}

// this updates an_count, ns_count, ar_count, rdlength
static void find_match(const char *buffer, dns_t *req, zone_t zone, uint8_t *rep_p, int *rep_len){
    printf("find_match\n");

    /* Response Header Section */
    dns_header_t rep_header = {0};
    rep_header.trans_id = req->header.trans_id;       // Transaction ID
    printf("req->header.trans_id : %d\n", req->header.trans_id);
    uint16_t req_opcode = (req->header.flags >> 11) & MASK_4BITS; // Extract Opcode from the request header
    uint16_t req_rd = (req->header.flags >> 8) & MASK_1BIT;       // Extract Recursion Desired from the request header
    
    rep_header.flags = 0;                             // Flags (these will eventually store in memory in little endian anyway)
    rep_header.flags |= (1 << 15);                    // QR = 1 for response
    rep_header.flags |= (req_opcode << 11);           // OPCODE = copy from client (0 for standard query)
    rep_header.flags |= (1 << 10);                    // AA = 1 for Authoritative Answer
    rep_header.flags |= (0 << 9);                     // TC = 0 (Not truncated)
    rep_header.flags |= (req_rd << 8);                // RD = copy from client
    rep_header.flags |= (0 << 7);                     // RA = 0 (Recursion is not available for now but later)
    rep_header.flags |= (0);                          // RCODE = 0 (No error)
    // Counts
    rep_header.qd_count = req->header.qd_count;
    rep_header.an_count = 0;                          // INITIALIZED TO ZERO
    rep_header.ns_count = 0;                          // INITIALIZED TO ZERO
    rep_header.ar_count = 0;                          // INITIALIZED TO ZERO

    /* Answer Section */
    dns_rr_t *ans = malloc(sizeof(dns_rr_t));

    ans->ttl = zone.ttl;                              // Time To Live in seconds
    dns_query_t *query = &req->query;

    printf("_____________\n");
    printf("%d", query->qtype);
    const char *query_t_str;
    switch(query->qtype){
        case 1:
            query_t_str = "A";
            break;
        case 5:
            query_t_str = "CNAME";
            break;
        default:
            query_t_str = "UNKNOWN";
            break;
    }

    // Loop through records in zone_t
    for(int i = 0; i < zone.n_records; i++){
        printf("for loop\n");
        // Find the matched question with the matched type
        printf("zone.type\t");
        printf(zone.records[i].type);
        printf("\n");
        printf("query_t_str\t");
        printf(query_t_str);
        printf("\n");
        if((strncmp(zone.records[i].name, query->question, strlen(query->question)) == 0) && (strcmp(zone.records[i].type, query_t_str) == 0)){ 
            printf("[ rec found ]\t %s %s\n", query->question, query_t_str);
            rep_header.an_count++;

            ans->name_ptr = 0xc00c;                        // (3 << 14) | 12;       // do manually for now c0 0c
            ans->type = 1;                                 // A
            ans->class_ = 1;                               // IN
            ans->rdlength = strlen(zone.records[i].value);

            strcpy(ans->rdata, zone.records[i].value);

            // Count NS records
            if(strncmp(query_t_str, "NS", 2) == 0){
                rep_header.ns_count++;
            }
            break;
        } 
    }

    /* Write header to the response packet */
    // memcpy(rep_p, &rep_header, 12);
    printf("rep_header.trans_id : %d\n", rep_header.trans_id);
    rep_p[0] = (rep_header.trans_id >> 8) & MASK_8BITS;  // Transaction ID [MSB]
    rep_p[1] = rep_header.trans_id & MASK_8BITS;         //                [LSB]
    rep_p[2] = (rep_header.flags >> 8) & MASK_8BITS;     // Flags          [MSB]
    rep_p[3] = rep_header.flags & MASK_8BITS;            //                [LSB]
    rep_p[4] = (rep_header.qd_count >> 8) & MASK_8BITS;  // Question Count [MSB]
    rep_p[5] = rep_header.qd_count & MASK_8BITS;         //                [LSB]
    rep_p[6] = (rep_header.an_count >> 8) & MASK_8BITS;  // Answer Count   [MSB]
    rep_p[7] = rep_header.an_count & MASK_8BITS;         //                [LSB]
    rep_p[8] = (rep_header.ns_count >> 8) & MASK_8BITS;  // NS Count       [MSB]
    rep_p[9] = rep_header.ns_count & MASK_8BITS;         //                [LSB]
    rep_p[10] = (rep_header.ar_count >> 8) & MASK_8BITS; // AR Count       [MSB]
    rep_p[11] = rep_header.ar_count & MASK_8BITS;        //                [LSB]
    *rep_len = 12;

    /* Write the Question back to the response packet */

    int q_end_pos = parse_question(buffer, 12, query);
    memcpy(rep_p + 12, buffer + 12, q_end_pos-12-4-1); // domain
    // *rep_len += query->q_len;
    *rep_len += q_end_pos-12-4-1;

    size_t pos = *rep_len;

    printf("-------------------\n");
    printf("%d\n", query->qtype);
    printf("%d\n", query->qclass);
    
    rep_p[pos++] = 0;
    rep_p[pos++] = (query->qtype >> 8) & MASK_8BITS;
    rep_p[pos++] = query->qtype & MASK_8BITS;

    rep_p[pos++] = (query->qclass >> 8) & MASK_8BITS;
    rep_p[pos++] = query->qclass & MASK_8BITS;

    /* Write the Answer Section */
    printf("%d\n", ans->name_ptr);
    rep_p[pos++] = (ans->name_ptr >> 8) & MASK_8BITS;    // Name           [MSB]
    rep_p[pos++] = ans->name_ptr & MASK_8BITS;           //                [LSB]
    rep_p[pos++] = (ans->type >> 8) & MASK_8BITS;        // Type           [MSB]
    rep_p[pos++] = ans->type & MASK_8BITS;               //                [LSB]
    rep_p[pos++] = (ans->class_ >> 8) & MASK_8BITS;      // Class          [MSB]
    rep_p[pos++] = ans->class_ & MASK_8BITS;             //                [LSB]
    rep_p[pos++] = (ans->ttl >> 24) & MASK_8BITS;        // TTL            [MSB]
    rep_p[pos++] = (ans->ttl >> 16) & MASK_8BITS;        //
    rep_p[pos++] = (ans->ttl >> 8) & MASK_8BITS;         //
    rep_p[pos++] = ans->ttl & MASK_8BITS;                //                [LSB]
    ans->rdlength = 0x04;
    rep_p[pos++] = (ans->rdlength >> 8) & MASK_8BITS;    // RDLENGTH       [MSB]
    rep_p[pos++] = ans->rdlength & MASK_8BITS;           //                [LSB]
    inet_pton(AF_INET, ans->rdata, rep_p+pos);
    pos += 4; //strlen(ans->rdata);
    *rep_len = pos;

    /* Free Memories */
    free(ans);
}

void write_response(const char *buffer, int serv_sock, client_t *client, zone_t zone, socklen_t addr_len){
    /* Response Packet*/
    uint8_t rep_p[512];
    int rep_len;
    dns_t *req = &client->req;
    
    find_match(buffer, req, zone, rep_p, &rep_len);

    //sendto(serv_sock, msg, strlen(msg), 0, (struct sockaddr *) &client.addr, addr_len);
    sendto(serv_sock, rep_p, rep_len, 0, (struct sockaddr *) &client->addr, addr_len);
}

