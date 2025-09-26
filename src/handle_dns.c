#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <sys/socket.h>
#include <arpa/inet.h>

#include "dns.h"
#include "client.h"
#include "zoneloader.h"
#include "globals.h"

ssize_t encode_fqdn(const char *domain, void **addr){
    /* This function split the `www.example.com.` into
     * 03 77 77 77 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00
     * (03 w w w 07 e x a m p l e 03 c o m 00)
     * write the results to the specified address and
     * return the amount of bytes written
     *
     * RETURN VALUE : the length (or the next index) of the
     *                end of the encoded domain
     * 03  w  w  w 07  e  x  a  m  p  l  e 03  c  o  m 00
     * 03 77 77 77 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00
     *                                                    ^
     *                                                   [17] <= ret value
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

uint16_t map_txid(client_t *client){
        /* THIS FUNCTION IS FOR OUTBOUND REQUEST */
        /* This function maps the client_txid with the
         * generated txid that will be used to make the
         * upstream DNS request
         *
         * RETURN VALUE: TXID used in upstream request
         *               is returned. 0 is returned
         *               when the txid tracking is full.
         */

        /* Extract client's TXID from the buffer (or from the client struct) */
        uint16_t client_txid = client->req.header.trans_id;

        /* Adding a new pending query to the tracking list */
        for(int i = 0; i < MAX_PENDINGS; i++){
                if(pending_queries[i].in_use == 1) continue;
                // Add to the list when we find the space to add
                pending_queries[i].client_txid = client_txid;
                pending_queries[i].upstream_txid = txid_counter++;
                pending_queries[i].client_addr = client->addr;
                pending_queries[i].in_use = 1;

                return pending_queries[i].upstream_txid;
        }
        return 0; // `pending_queries` tracking list is full
}

pending_query_t *find_txid(uint16_t upstream_txid){
    /* Find client's TXID with the provided upstream TXID */
    for(int i = 0; i < MAX_PENDINGS; i++){
        if(pending_queries[i].in_use == 0) continue;
        if(pending_queries[i].upstream_txid == upstream_txid){
            return &pending_queries[i];
        }
    }
    return NULL;
}

void free_txid(uint16_t upstream_txid){
    /* Find and change the `in_use` value to zero */
    pending_query_t *pending_q = find_txid(upstream_txid);
    if(pending_q) pending_q->in_use = 0;
}

static ssize_t forward_upstream(const char *buffer, ssize_t bytes_recv, int upstream_sock, struct sockaddr_in ext_serv_addr, client_t *client){
    /* The function creates the map for TXIDs and
     * relays the client's request to the external server .
     * This is only meant for upstream
     */

    uint8_t forward_pkt[512];

    /* Copy the buffer to the custom packet crafting space (We are editing) */
    memcpy(forward_pkt, buffer, bytes_recv);

    /* Add client's TXID  to the tracking list and get new upstream TXID */
    uint16_t upstream_txid = map_txid(client);
    if(upstream_txid == 0){
        fprintf(stderr, "Pending list is full\n");
        exit(EXIT_FAILURE);
    }

    /* Inside the buffer, replace the client's TXID with the new upstream TXID */
    forward_pkt[0] = (upstream_txid >> 8) & MASK_8BITS;
    forward_pkt[1] = upstream_txid & MASK_8BITS;

    /* Send request to the external DNS server */
    socklen_t ext_addr_len = sizeof(ext_serv_addr);
    return sendto(upstream_sock, forward_pkt, bytes_recv, 0, (struct sockaddr *) &ext_serv_addr, ext_addr_len);
}

ssize_t forward_downstream(int serv_sock, int upstream_sock){
    /* Called by main epoll */
    uint8_t upstream_rep_p[512];                // Upstream Response Packet
    struct sockaddr_in rep_addr;                // External server address
    socklen_t rep_addr_len = sizeof(rep_addr);  //

    ssize_t ret_bytes = recvfrom(upstream_sock, upstream_rep_p, sizeof(upstream_rep_p), 0, (struct sockaddr *) &rep_addr, &rep_addr_len);

    /* Extract TXID */
    uint16_t upstream_txid = ((unsigned char) upstream_rep_p[0] << 8) | (unsigned char) upstream_rep_p[1];

    /* TXID Looking up and mapping the right client to get `client` */
    pending_query_t *pending_q = find_txid(upstream_txid);
    uint16_t client_txid;
    if(pending_q != NULL){
        client_txid = pending_q->client_txid;
    }else{
        printf("pending_q is NULL\n");
    }

    upstream_rep_p[0] = (client_txid >> 8) & MASK_8BITS;
    upstream_rep_p[1] = client_txid & MASK_8BITS;

    if(pending_q) pending_q->in_use = 0; // free TXID
    // free_txid(upstream_txid);

    // Relay the response back to the client
    socklen_t cli_addr_len = sizeof(struct sockaddr_in);
    ssize_t b_sent = sendto(serv_sock, upstream_rep_p, ret_bytes, 0, (struct sockaddr *) &pending_q->client_addr, cli_addr_len);
    // printf("Bytes sent downstream : %ld\n", b_sent);

    return b_sent;
}

int parse_question(const char *buffer, int offset, dns_query_t *query){
    /*
     * This function gets the question domain from the question section
     * and fills in the dns_query_t *query
     */

    int pos = offset;
    unsigned int question_len = 0;
    unsigned int query_i = 0;

    /* Decode the question to the domain in constrast of `encode_fqdn` */
    while(buffer[pos] != '\0'){
        int label_len = (unsigned char) buffer[pos++];
        if(label_len == 0) break;

        question_len += label_len;
        if(query_i + label_len + 1 >= sizeof(query->question)) break; // Prevent overflow
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
    /*
     * Extract the data(Header & Question sections) from the client's
     * request and build the client's structure for tracking
     */

    dns_t *req = &client->req;
    dns_header_t *header = &req->header;
    dns_query_t *query = &req->query;

    /* Extract Header */
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

static int write_header(uint8_t *rep_p, const dns_t *req, const zone_lookup_res_t *res){

    /* Response Header Section */
    dns_header_t rep_header = {0};
    rep_header.trans_id = req->header.trans_id;       // Transaction ID
    uint16_t req_opcode = (req->header.flags >> 11) & MASK_4BITS; // Extract Opcode from the request header
    uint16_t req_rd = (req->header.flags >> 8) & MASK_1BIT;       // Extract Recursion Desired from the request header
    
    rep_header.flags = 0;                             // Flags (these will eventually store in memory in little endian anyway)
    rep_header.flags |= (1 << 15);                    // QR = 1 for response
    rep_header.flags |= (req_opcode << 11);           // OPCODE = copy from client (0 for standard query)
    rep_header.flags |= (res->authoritative << 10);   // AA (Authoritative Answer)
    rep_header.flags |= (0 << 9);                     // TC = 0 (Not truncated)
    rep_header.flags |= (req_rd << 8);                // RD = copy from client
    rep_header.flags |= (0 << 7);                     // RA = 0 (Recursion is not available for now but later)
    rep_header.flags |= (0);                          // RCODE = 0 (No error)
    // Counts
    rep_header.qd_count = req->header.qd_count;
    rep_header.an_count = res->n_ans;
    rep_header.ns_count = 0;
    rep_header.ar_count = res->n_add;

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

static int write_question(const char *buffer, dns_query_t *query, int q_offset, uint8_t *rep_p){

    size_t q_pos = q_offset;

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

static int write_answer(dns_rr_t *ans, dns_rr_t *add_ans, int ans_offset, uint8_t *rep_p){
    size_t pos = ans_offset;

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
        inet_pton(AF_INET, ans->rdata, rep_p+pos);
        pos += ans->rdlength;       // 32 bit IPv4 address (can manually set to 4)
    }else if(ans->type == 2){
        /* NS */
        memcpy(rep_p+pos, ans->rdata, ans->rdlength);
        pos += ans->rdlength;
    }else if(ans->type == 5){
        /* CNAME */
        memcpy(rep_p+pos, ans->rdata, ans->rdlength);
        pos += ans->rdlength;

        add_ans->name_ptr = (3 << 14) | ans_offset;              // NAME offset for CNAME Additional Record

        /* A as Additional */
        rep_p[pos++] = (add_ans->name_ptr >> 8) & MASK_8BITS;    // Name           [MSB]
        rep_p[pos++] = add_ans->name_ptr & MASK_8BITS;           //                [LSB]

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
        pos += add_ans->rdlength;       // 32 bit IPv4 address

    }

    return pos;
}

int lookup_zone(dns_query_t *query, const zone_t *zone, zone_lookup_res_t *res){
    /* This function find the match in the zone file and
     * decide wheter to relay the request to the external
     * resolver.
     * If the requested domain is not the NXDOMAIN, the 
     * function will update the `res` with the
     * right `record_t` address.
     *
     * RETURN VALUE : The number of answers found
     */

    memset(res, 0, sizeof(zone_lookup_res_t));

    /* Look through the records in the zone structure and find the matching record with the question */
    for(size_t i = 0; i < zone->n_records; ++i){
        const record_t *record = &zone->records[i];
        // printf("%s\t%s\n", query->question, record->name);
        if (strncmp(query->question, record->name, strlen(record->name)-1) != 0) continue;
        /* Domain in the question is found in one of the records inside the zone struct */

        /* Check for NS Record */
        if(strncmp(record->type, "NS", 2) == 0){
            if (query->qtype == 2){
                res->answers[res->n_ans++] = record;
                break;
            }else{
                continue;
            }
        }

        /* Add to the answer list */
        res->answers[res->n_ans++] = record;

        /* Additional Record in the case of CNAME */
        if(strcmp(record->type,"CNAME") == 0){
            /* Look through the records again to find the matching A record name with the CNAME Record value */
            for(size_t j = 0; j < zone->n_records && res->n_add < 8; ++j){
                if(strcmp(zone->records[j].type, "A") == 0 && strcmp(zone->records[j].name, record->value) == 0){
                    /* The matched record found */
                    res->additional[res->n_add++] = &zone->records[j];
                }
            }
        }

        /* Authoritative Answer */
        if(strstr(zone->origin, query->question) != NULL) res->authoritative = 1;

    }

    return res->n_ans > 0 ? 1 : 0;
}

int write_dns_response(const char *buffer, dns_t *req, zone_lookup_res_t *res, uint8_t *rep_p){
    /*
     * This function constracts a DNS packet depending on the client's
     * request and the result of the DNS lookup and writes it to the
     * provided buffer.
     *
     * RETURN VALUE: the written length in bytes of the reponse in the
     *               address space.
     *
     */

    int rep_len;
    dns_rr_t *ans = malloc(sizeof(dns_rr_t));         // Answer RR
    dns_rr_t *add_ans = malloc(sizeof(dns_rr_t));     // Additional RR

    memset(ans, 0, sizeof(dns_rr_t));
    memset(add_ans, 0, sizeof(dns_rr_t));

    /* Write the Header Section */
    int header_len = write_header(rep_p, req, res);
    rep_len = header_len;
    
    /* Write the Question Section */
    int q_offset = rep_len;   // 12
    dns_query_t *query = &req->query;
    rep_len = write_question(buffer, query, q_offset, rep_p);

    /* Write the Answer Section */
    for(size_t i = 0; i < res->n_ans; ++i){
        const record_t *record = res->answers[i];
        // printf("record->name : %s\n", record->name);
        // printf("record->type : %s\n", record->type);
        if(strcmp(record->type, "A") == 0){
            ans->name_ptr = (3 << 14) | q_offset;     // 0xc00c; if the q_offset is 12

            ans->type = 1;                            // A
            ans->class_ = 1;                          // IN
            ans->ttl = 3600;                          // zone.ttl;

            ans->rdlength = 0x04;                     // IPv4 addresses takes only 4 bytes
            strcpy(ans->rdata, record->value);

            // rep_len += 2+2+4+ans->rdlength;
            // break;
        }
        else if(strcmp(record->type, "NS") == 0){
            ans->name_ptr = (3 << 14) | q_offset;     // 0xc00c; if the q_offset is 12

            ans->type = 2;                            // NS
            ans->class_ = 1;                          // IN
            ans->ttl = 3600;                          // zone.ttl;

            void *addr = NULL;                                                  // Address of the encoded bytes
            ans->rdlength = encode_fqdn(record->value, &addr)-1;                // Encode domain into [count][label]...
            memcpy(ans->rdata, addr, ans->rdlength);
            free(addr);
            //rep_len += 2+2+4+ans->rdlength;

            //ans->rdlength = encode_fqdn(record->value, (void *) ans->rdata);  // Encode domain into [count][label]...

            //break;
        }
        else if(strcmp(record->type, "CNAME") == 0){
            ans->name_ptr = (3 << 14) | q_offset;     // 0xc00c; if the q_offset is 12

            ans->type = 5;                            // CNAME
            ans->class_ = 1;                          // IN
            ans->ttl = 3600;                          // zone.ttl;
 
            void *addr = NULL;                                                  // Address of the encoded bytes
            ans->rdlength = encode_fqdn(record->value, &addr)-1;                // Encode domain into [count][label]...
            memcpy(ans->rdata, addr, ans->rdlength);
            free(addr);
            // rep_len += 2+2+4+ans->rdlength;

            //ans->rdlength = encode_fqdn(record->value, (void *) ans->rdata);  // Encode domain into [count][label]...

            /* Additional A Record */
            add_ans->type = 1;                        // A
            add_ans->class_ = 1;                      // IN
            add_ans->rdlength = 0x04;                 // IPv4 addresses takes only 4 bytes
            strcpy(add_ans->rdata,res->additional[0]->value);
            // rep_len += 2+2+4+add_ans->rdlength;

            // `add_ans->name_ptr` will be populated in write_answer() for the case of additional record

            //break;
        }
        rep_len = write_answer(ans, add_ans, rep_len, rep_p);
    }

    /* Free Memories */
    free(ans);
    free(add_ans);

    return rep_len;
}

int handle_dns(const char *buffer, ssize_t bytes_recv, int serv_sock, int upstream_sock, client_t *client, zone_t *zone_addr, socklen_t addr_len, struct sockaddr_in ext_serv_addr){
    /* The Orchestrator Function */

    uint8_t rep_p[512];          // Response Packet
    int rep_len;
    int found = 0;

    dns_t *req = &client->req; 
    zone_lookup_res_t res;
    int n_ans = lookup_zone(&req->query, zone_addr, &res);

    if(n_ans > 0){
        rep_len = write_dns_response(buffer, req, &res, rep_p);
        sendto(serv_sock, rep_p, rep_len, 0, (struct sockaddr *) &client->addr, addr_len);
        found = 1;
    }else{
        forward_upstream(buffer, bytes_recv, upstream_sock, ext_serv_addr, client);
        found = 0;
    }
    return found;
}


