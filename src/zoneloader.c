#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "zoneloader.h"

#define LINE_SIZE 512

void strip_comments(char *line, char c){
    char *p = strchr(line, c);
    if(p) *p = '\0';
}

void strip_spaces(char *line){
    char *start = line;
    while(isspace((unsigned char) *start)) start++; 
    char *end = start + strlen(start) - 1;
    while(end > start && isspace((unsigned char) *end)) *end-- = '\0';
    memmove(line, start, strlen(start)+1);
}

void get_fqdn(const char *name, const char *origin, char *out){
    size_t len = strlen(name);
    if(strcmp(name, "@") == 0){
        // @ means origin
        snprintf(out, MAX_DOMAIN_LEN, "%s", origin);
    }else if(len > 0 && name[len-1] == '.'){
        // if the domain ends with '.', it is already a FQDN
        snprintf(out, MAX_DOMAIN_LEN, "%s", name);
    }else{
        // relative append origin with '.'
        snprintf(out, MAX_DOMAIN_LEN, "%s.%s", name, origin);
    }
}

int parse_zone_file(const char *filepath, zone_t *zone){
    char line[LINE_SIZE];
    FILE *fp = fopen(filepath, "r");
    zone->n_records = 0;

    while(fgets(line, sizeof(line), fp)){
        strip_comments(line, ';');
        strip_spaces(line);

        if(strlen(line) == 0) continue;

        // TTL
        if(strncmp(line, "$TTL", 4) == 0){
            unsigned int ttl;
            if(sscanf(line, "$TTL %u", &ttl) == 1){
                zone->ttl = ttl;
            }
            continue;
        }

        // ORIGIN
        if(strncmp(line, "$ORIGIN", 7) == 0){
            char origin[MAX_DOMAIN_LEN];
            if(sscanf(line, "$ORIGIN %s", origin) == 1){
                snprintf(zone->origin, MAX_DOMAIN_LEN, "%s", origin);
            }
            continue;
        }

        // SOA
        char mname[MAX_DOMAIN_LEN], rname[MAX_DOMAIN_LEN];
        unsigned int serial, refresh, retry, expire, min_ttl;
        if(strstr(line, "SOA")){
            if(sscanf(line, "%*s %*s SOA %s %s", mname, rname) != 2){
                fprintf(stderr, "Cannot read SOA");
                return -1;
            }
            soa_t *soa = &zone->soa;
            get_fqdn(mname, zone->origin, soa->mname);
            get_fqdn(rname, zone->origin, soa->rname);

            unsigned int line_count = 0;
            while(fgets(line, sizeof(line), fp)){
                strip_comments(line, ';');
                strip_spaces(line);

                if(line_count == 0 && sscanf(line, "%u", &serial) == 1) { soa->serial = serial; line_count++; continue;}
                if(line_count == 1 && sscanf(line, "%u", &refresh) == 1) { soa->refresh = refresh; line_count++; continue;}
                if(line_count == 2 && sscanf(line, "%u", &retry) == 1) {soa->retry = retry; line_count++; continue;}
                if(line_count == 3 && sscanf(line, "%u", &expire) == 1) {soa->expire = expire; line_count++; continue;}
                if(line_count == 4 && sscanf(line, "%u", &min_ttl) == 1) {soa->min_ttl = min_ttl; break;}
            }
            continue;
        }

        // Records
        char name[MAX_DOMAIN_LEN], rec_class[8], type[8], value[255];
        if(sscanf(line, "%s %s %s %s", name, rec_class, type, value) == 4){
            record_t *record = &zone->records[zone->n_records++];
            get_fqdn(name, zone->origin, record->name);
            snprintf(record->rec_class, 8, "%s", rec_class);
            snprintf(record->type, 8, "%s", type);
            snprintf(record->value, 255, "%s", value);
        }

    }
    fclose(fp);
    return 0;
}

