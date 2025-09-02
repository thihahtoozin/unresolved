#ifndef ZONELOADER_H
#define ZONELOADER_H

#include <stdio.h>
#include <stdint.h>

#define MAX_DOMAIN_LEN 255
#define MAX_RECS 128

typedef struct{
    char mname[MAX_DOMAIN_LEN]; // Primary NS
    char rname[MAX_DOMAIN_LEN]; // Responsible person's email
    unsigned int serial;
    unsigned int refresh;
    unsigned int retry;
    unsigned int expire;
    unsigned int min_ttl;
}soa_t;

typedef struct{
    char name[MAX_DOMAIN_LEN];
    char rec_class[8];
    char type[8];
    char value[255];
}record_t;

typedef struct{
    uint32_t ttl;                      // ttl
    char origin[MAX_DOMAIN_LEN];       // origin domain string
    soa_t soa;                         // SOA sub structure
    record_t records[MAX_RECS];        // array of records
    size_t n_records;                  // record count
}zone_t;

void get_fqdn(const char *name, const char *origin, char *out);
void strip_comments(char *line, char c);
void strip_spaces(char *line);
int parse_zone_file(const char *filepath, zone_t *zone);

#endif

