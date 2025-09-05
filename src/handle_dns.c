#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <sys/socket.h>
#include <arpa/inet.h>

#include "dns.h"
#include "client.h"
#include "zoneloader.h"

ssize_t encode_fqdn(const char *domain, void **addr){
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

static void forward_query(const char *buffer, ssize_t bytes_recv, client_t *client, int serv_sock, int upstream_sock, struct sockaddr_in ext_serv_addr){

    uint8_t upstream_rep_p[512]; // Upstream Request Packet
    struct sockaddr_in rep_addr;
    socklen_t rep_addr_len = sizeof(rep_addr);

    // send request to the external DNS server

    socklen_t ext_addr_len = sizeof(ext_serv_addr);
    sendto(upstream_sock, buffer, bytes_recv, 0, (struct sockaddr *) &ext_serv_addr, ext_addr_len);

    ssize_t ret_bytes = recvfrom(upstream_sock, upstream_rep_p, sizeof(upstream_rep_p), 0, (struct sockaddr *) &rep_addr, &rep_addr_len);

    // relay the response back to the client
    socklen_t cli_addr_len = sizeof(client->addr);
    sendto(serv_sock, upstream_rep_p, ret_bytes, 0, (struct sockaddr *) &client->addr, cli_addr_len);
}

int parse_question(const char *buffer, int offset, dns_query_t *query){
    int pos = offset;
    unsigned int question_len = 0;
    unsigned int query_i = 0;
    while(buffer[pos] != '\0'){
        int label_len = (unsigned char) buffer[pos++];
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

/* These funcitons return the amount of bytes written */
static int write_header(uint8_t *rep_p, dns_t *req, uint16_t an_count, uint16_t ns_count, uint16_t ar_count){

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
    rep_header.an_count = an_count;                   // INITIALIZED TO ZERO
    rep_header.ns_count = ns_count;                   // INITIALIZED TO ZERO
    rep_header.ar_count = ar_count;                   // INITIALIZED TO ZERO

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

    return header_len; // 12 bytes
};

static int write_question(uint8_t *rep_p, const char *buffer, dns_query_t *query, int q_offset){

    // int q_offset = *rep_len;                  // 12
    size_t q_pos = q_offset;

    // ans->name_ptr = (3 << 14) | q_offset;        // 0xc00c; if the q_offset is 12

    int q_end_pos = parse_question(buffer, q_offset, query);
    memcpy(rep_p + q_offset, buffer + q_offset, q_end_pos-q_offset-4-1); // domain -4 for qtype and qclass -1 for null byte
    q_pos += q_end_pos - q_offset - 4 - 1;
    
    rep_p[q_pos++] = 0;
    rep_p[q_pos++] = (query->qtype >> 8) & MASK_8BITS;
    rep_p[q_pos++] = query->qtype & MASK_8BITS;

    rep_p[q_pos++] = (query->qclass >> 8) & MASK_8BITS;
    rep_p[q_pos++] = query->qclass & MASK_8BITS;

    return q_pos;
}

static int write_answer(uint8_t *rep_p, dns_rr_t *ans, dns_rr_t *add_ans, int q_offset, int ans_offset, ssize_t encoded_domain_len){
    size_t pos = ans_offset;
    ans->name_ptr = (3 << 14) | q_offset;        // 0xc00c; if the q_offset is 12

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
    //printf("ANS_T %hu\n", ans->type);
    if(ans->type == 1){
        /* A */
        printf("A 0x1\n");
        inet_pton(AF_INET, ans->rdata, rep_p+pos);
        pos += 4;       // 32 bit IPv4 address
    }else if(ans->type == 2){
        /* NS */
        printf("NS 0x2\n");
        memcpy(rep_p+pos, ans->rdata, encoded_domain_len);
        pos += encoded_domain_len - 1; // -1 for removing one of the 2 null bytes
    }else if(ans->type == 5){
        /* CNAME */
        printf("CNAME 0x5\n");
        memcpy(rep_p+pos, ans->rdata, encoded_domain_len);
        // pos += encoded_domain_len - 1; // -1 for removing one of the 2 null bytes
        pos += ans->rdlength; // -1 for removing one of the 2 null bytes

        /* A as Additional */
        printf("Additional A 0x1\n");
        memcpy(rep_p + pos, ans->rdata, ans->rdlength);
        pos += ans->rdlength;
        rep_p[pos++] = (add_ans->type >> 8) & MASK_8BITS;        // Type           [MSB]
        rep_p[pos++] = add_ans->type & MASK_8BITS;               //                [LSB]
        rep_p[pos++] = (add_ans->class_ >> 8) & MASK_8BITS;      // Class          [MSB]
        rep_p[pos++] = add_ans->class_ & MASK_8BITS;             //                [LSB]
        rep_p[pos++] = (add_ans->ttl >> 24) & MASK_8BITS;        // TTL            [MSB]
        rep_p[pos++] = (add_ans->ttl >> 16) & MASK_8BITS;        //
        rep_p[pos++] = (add_ans->ttl >> 8) & MASK_8BITS;         //
        rep_p[pos++] = add_ans->ttl & MASK_8BITS;                //                [LSB]
        rep_p[pos++] = (add_ans->rdlength >> 8) & MASK_8BITS;    // RDLENGTH       [MSB]
        rep_p[pos++] = add_ans->rdlength & MASK_8BITS;           //                [LSB]

        inet_pton(AF_INET, add_ans->rdata, rep_p+pos);
        pos += 4;       // 32 bit IPv4 address

    }
    // *rep_len = pos;
    return pos;
}

static int find_match(const char *buffer, dns_t *req, zone_t zone, uint8_t *rep_p, int *rep_len){

    /* Answer Section */
    dns_rr_t *ans = malloc(sizeof(dns_rr_t));         // Answer RR
    dns_rr_t *add_ans = malloc(sizeof(dns_rr_t));     // Additional RR

    ans->ttl = zone.ttl;                              // Time To Live in seconds for AN
    add_ans->ttl = zone.ttl;                          // Time To Live in seconds for AR
    dns_query_t *query = &req->query;

    /* Find Match */
    const char *query_t_str;
    ssize_t encoded_domain_len = 0;
    switch(query->qtype){
        case 1:
            query_t_str = "A";
            break;
        case 2:
            query_t_str = "NS";
            break;
        case 5:
            query_t_str = "CNAME";
            break;
        default:
            query_t_str = "UNKNOWN";
            break;
    }
    printf("QUERY_T_STR : %s\n", query_t_str);

    uint16_t an_count = 0;
    uint16_t ns_count = 0;
    uint16_t ar_count = 0;

    // Loop through records in zone_t
    int rec_found = 0;
    for(int i = 0; i < zone.n_records; i++){
        // Find the matched question with the matched type
        // if((strncmp(zone.records[i].name, query->question, strlen(query->question)) == 0) && (strcmp(zone.records[i].type, query_t_str) == 0))
        if((strncmp(zone.records[i].name, query->question, strlen(query->question)) == 0)){ 
            // printf("[ Record Found ]\t %s %s\n", query->question, query_t_str);
            an_count++;

            // AAAA (TYPE - 28)
            // A Record
            if(strncmp(zone.records[i].type, "A", 1) == 0){
                printf("A Record\n");
                ans->type = 1;                                 // A
                ans->class_ = 1;                               // IN
                ans->rdlength = 0x04;                          // IPv4 addresses takes only 4 bytes
                strcpy(ans->rdata, zone.records[i].value);

                rec_found = 1;
                break;
            }

            // NS Record
            if(strncmp(zone.records[i].type, "NS", 2) == 0){
                printf("NS Record\n");

                /* Header */
                //rep_header.ns_count++;                       // I'm still uncertain about when to turn this on.

                /* Answer */
                ans->type = 2;                                 // NS
                ans->class_ = 1;                               // IN

                void *addr = NULL;                                                               // Address of the encoded bytes
                encoded_domain_len = encode_fqdn(zone.records[i].value, &addr);                  // Encode domain into [count][label]...
                memcpy(ans->rdata, addr, encoded_domain_len);
                free(addr);
                ans->rdlength = encoded_domain_len-1;

                rec_found = 1;
                break;
            }

            // CNAME Record
            if(strncmp(zone.records[i].type, "CNAME", 5) == 0){
                printf("CNAME Record\n");

                /* Header */
                ar_count++;                                    // Append one A record as Additional RR
                //ns_count++;                                  // I'm still uncertain about when to turn this on.

                /* Answer */
                ans->type = 5;                                 // CNAME
                ans->class_ = 1;                               // IN

                void *addr = NULL;                                                               // Address of the encoded bytes
                encoded_domain_len = encode_fqdn(zone.records[i].value, &addr);                  // Encode domain into [count][label]...
                memcpy(ans->rdata, addr, encoded_domain_len);
                free(addr);
                ans->rdlength = encoded_domain_len-1;

                /* Additional RR for A Record */
                // dns_rr_t *add_ans = malloc(sizeof(dns_rr_t));
                printf("Additional A Record\n");
                add_ans->type = 1;                                 // A
                add_ans->class_ = 1;                               // IN
                add_ans->rdlength = 0x04;                          // IPv4 addresses takes only 4 bytes

                // Search of A records
                for(int j = 0; j < zone.n_records; j++){
                    if(strncmp(zone.records[j].type, "A", 1) == 0){
                        printf("------------------\n");
                        printf("IP ADDR : %s\n", zone.records[j].value);
                        strcpy(add_ans->rdata, zone.records[j].value);
                        printf("ADD AND : %s\n", add_ans->rdata);
                        break;
                    }
                }

                rec_found = 1;
                break;
            }
            // SOA  (TYPE - 6)
            // PTR  (TYPE - 12)

        } 
    }
    if(rec_found == 0) return -1;

    /* Write the Header Section */
    int header_len = write_header(rep_p, req, an_count, ns_count, ar_count);
    *rep_len = header_len;

    /* 
     * for any case where there is anything between header and question
     */

    /* Write the Question Section */
    int q_offset = *rep_len;   // 12
    *rep_len = write_question(rep_p, buffer, query, q_offset);

    /* Write the Answer Section */
    *rep_len = write_answer(rep_p, ans, add_ans, q_offset, *rep_len, encoded_domain_len);

    /* Free Memories */
    free(ans);
    free(add_ans);
    return 0;
}

void write_response(const char *buffer, ssize_t bytes_recv, int serv_sock, int upstream_sock, client_t *client, zone_t zone, socklen_t addr_len, struct sockaddr_in ext_serv_addr){

    uint8_t rep_p[512];          // Response Packet
    uint8_t upstream_req_p[512]; // Upstream Request Packet
    int rep_len;
    int found;

    dns_t *req = &client->req; 
    found = find_match(buffer, req, zone, rep_p, &rep_len);

    if(found == -1){
        forward_query(buffer, bytes_recv, client, serv_sock, upstream_sock, ext_serv_addr);
    }else{
        sendto(serv_sock, rep_p, rep_len, 0, (struct sockaddr *) &client->addr, addr_len);
    }
}

