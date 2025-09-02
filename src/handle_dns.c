#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <sys/socket.h>
#include <arpa/inet.h>

#include "dns.h"
#include "client.h"
#include "zoneloader.h"

ssize_t format_fqdn(const char *domain, void **addr){
    /* This function split the `www.example.com.` into
     * 03 77 77 77 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00
     * (03 w w w 07 e x a m p l e 03 c o m 00)
     * write the results to the specified address and
     * return the amount of bytes written
     */

    uint8_t hold[256]; // Temporary memory to build up the result

    const char *start = domain;  // these pointers will be 
    const char *end;             // dynamically updated
    size_t pos = 0;              // current write position
    uint8_t len = 0;
    while(1){
        end = strchr(start, '.');
        if(!end){
            end = start + strlen(start);
        }
        len = end - start;

        hold[pos++] = len;               // store len
        memcpy(hold+pos, start, len);    // store the string

        pos += len;                      // track on tmp
        if(*end == '\0') break;
        start = end+1;                   // track on string
    }
    hold[pos++] = 0;

    void *tmp = realloc(*addr, pos);     // resize the space pointed by the address provided
    if(!tmp){
        perror("realloc() failed!");
        return -1;
    }
    *addr = tmp;
    memcpy(*addr, hold, pos);

    return pos;
}

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
    // printf("header->trans_id : %d\n", header->trans_id);
    // printf("buffer[0] : %d\n", buffer[0]);
    // printf("buffer[1] : %d\n", buffer[1]);
    header->flags = ((unsigned char) buffer[2] << 8) | (unsigned char) buffer[3];
    header->qd_count = ((unsigned char) buffer[4] << 8) | (unsigned char) buffer[5];   // Number of Questions
    header->an_count = ((unsigned char) buffer[6] << 8) | (unsigned char) buffer[7];   // Number of Answer Records
    header->ns_count = ((unsigned char) buffer[8] << 8) | (unsigned char) buffer[9];   // Number of Name Server Records
    header->ar_count = ((unsigned char) buffer[10] << 8) | (unsigned char) buffer[11]; // Number of Additional Records

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

    /* Response Header Section */
    dns_header_t rep_header = {0};
    rep_header.trans_id = req->header.trans_id;       // Transaction ID
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
        // Find the matched question with the matched type
        if((strncmp(zone.records[i].name, query->question, strlen(query->question)) == 0) && (strcmp(zone.records[i].type, query_t_str) == 0)){ 
            printf("[ Record Found ]\t %s %s\n", query->question, query_t_str);
            rep_header.an_count++;

            // AAAA (TYPE - 28)
            // A Record
            if(strncmp(query_t_str, "A", 1) == 0){
                printf("A Record\n");
                ans->type = 1;                                 // A
                ans->class_ = 1;                               // IN
                ans->rdlength = 0x04;                          // IPv4 addresses takes only 4 bytes
                strcpy(ans->rdata, zone.records[i].value);

                break;
            }

            // NS Record [ NOT DONE YET ]
            if(strncmp(query_t_str, "NS", 2) == 0){
                printf("NS Record\n");
                ans->type = 2;                                 // NS
                ans->class_ = 1;                               // IN
                rep_header.ns_count++;
                ans->rdlength = strlen(zone.records[i].value);
                strcpy(ans->rdata, zone.records[i].value);     // make it [count][label][count][label]... [ <= START HERE   ] 

                break;
            }

            // CNAME Record [ NOT DONE YET ]
            if(strncmp(query_t_str, "CNAME", 5) == 0){
                printf("NS Record\n");
                ans->type = 5;                                 // CNAME
                ans->class_ = 1;                               // IN
                //rep_header.ns_count++;

                break;
            }
            // SOA  (TYPE - 6)
            // PTR  (TYPE - 12)

        } 
    }

    /* Write header to the response packet */
    int header_len = 0;
    /* Craft Response Header (Most Significant Byte on the least index) */
    rep_p[header_len++] = (rep_header.trans_id >> 8) & MASK_8BITS;  // Transaction ID [MSB]
    rep_p[header_len++] = rep_header.trans_id & MASK_8BITS;         //                [LSB]
    rep_p[header_len++] = (rep_header.flags >> 8) & MASK_8BITS;     // Flags          [MSB]
    rep_p[header_len++] = rep_header.flags & MASK_8BITS;            //                [LSB]
    rep_p[header_len++] = (rep_header.qd_count >> 8) & MASK_8BITS;  // Question Count [MSB]
    rep_p[header_len++] = rep_header.qd_count & MASK_8BITS;         //                [LSB]
    rep_p[header_len++] = (rep_header.an_count >> 8) & MASK_8BITS;  // Answer Count   [MSB]
    rep_p[header_len++] = rep_header.an_count & MASK_8BITS;         //                [LSB]
    rep_p[header_len++] = (rep_header.ns_count >> 8) & MASK_8BITS;  // NS Count       [MSB]
    rep_p[header_len++] = rep_header.ns_count & MASK_8BITS;         //                [LSB]
    rep_p[header_len++] = (rep_header.ar_count >> 8) & MASK_8BITS;  // AR Count       [MSB]
    rep_p[header_len++] = rep_header.ar_count & MASK_8BITS;         //                [LSB]

    *rep_len = header_len;                       // 12
    // for the case where there is anything between header and question
    int q_offset = *rep_len;                     // 12
    ans->name_ptr = (3 << 14) | q_offset;        // 0xc00c; if the q_offset is 12

    /* Write the Question back to the response packet */
    int q_end_pos = parse_question(buffer, q_offset, query);
    memcpy(rep_p + *rep_len, buffer + 12, q_end_pos-q_offset-4-1); // domain -4 for qtype and qclass -1 for null byte
    *rep_len += q_end_pos-header_len-4-1;

    size_t pos = *rep_len;
    
    rep_p[pos++] = 0;
    rep_p[pos++] = (query->qtype >> 8) & MASK_8BITS;
    rep_p[pos++] = query->qtype & MASK_8BITS;

    rep_p[pos++] = (query->qclass >> 8) & MASK_8BITS;
    rep_p[pos++] = query->qclass & MASK_8BITS;

    /* Write the Answer Section */
    // printf("%d\n", ans->name_ptr);
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
    rep_p[pos++] = (ans->rdlength >> 8) & MASK_8BITS;    // RDLENGTH       [MSB]
    rep_p[pos++] = ans->rdlength & MASK_8BITS;           //                [LSB]
    if(ans->type && 0x1){
        /* A */
        inet_pton(AF_INET, ans->rdata, rep_p+pos);
    }else if(ans->type && 0x2){
        /* CNAME */
        memcpy(rep_p+pos, ans->rdata, strlen(ans->rdata)+1);
    }
    pos += 4; //strlen(ans->rdata);
    *rep_len = pos;

    /* Free Memories */
    free(ans);
}

void write_response(const char *buffer, int serv_sock, client_t *client, zone_t zone, socklen_t addr_len){

    uint8_t rep_p[512]; // Response Packet
    int rep_len;

    dns_t *req = &client->req; 
    find_match(buffer, req, zone, rep_p, &rep_len);

    sendto(serv_sock, rep_p, rep_len, 0, (struct sockaddr *) &client->addr, addr_len);
}

