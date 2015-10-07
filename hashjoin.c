#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct hash_t hash_t;

typedef struct entry_t entry_t;

struct entry_t {
    char *key;
    size_t keysz;
    char **values;
    size_t nb_values;
    entry_t *next;
};

struct hash_t {
    entry_t **buckets;
    uint32_t nb_buckets;
    uint32_t hashmask;
};

struct hashjoin_cfg_t {
    hash_t *hash;
    int field1, field2, fixed, negate;
    char separator1, separator2;
    size_t size;
};

typedef struct hashjoin_cfg_t hashjoin_cfg_t;

static inline hash_t *hash_make(register uint32_t v)
{
    hash_t *result;

    /* quick computation of closest bigger power of 2. */
    v--;
    v |= v >> 1;
    v |= v >> 2;
    v |= v >> 4;
    v |= v >> 8;
    v |= v >> 16;
    v++;

    result = malloc(sizeof(struct hash_t));
    if (NULL != result) {
        result->buckets = calloc(v, sizeof(entry_t *));
        if (NULL == result->buckets) {
            free(result);
            fprintf(stderr, "allocation error inon_obj_make\n");
            return NULL;
        }
        result->nb_buckets = v;
        result->hashmask = v - 1;
    } else {
        fprintf(stderr, "allocation error inon_obj_make\n");
    }

    return result;
}

static inline void hash_destroy(hash_t *hash)
{
    size_t i, j;

    for (i = 0; i < hash->nb_buckets; i++) {
        entry_t *tmp_entry, *next_entry;
        tmp_entry = hash->buckets[i];
        if (tmp_entry) {
            do {
                next_entry = tmp_entry->next;
                free(tmp_entry->key);
                for (j = 0; j < tmp_entry->nb_values; j++) {
                    free(tmp_entry->values[j]);
                }
                free(tmp_entry->values);
                free(tmp_entry);
                tmp_entry = next_entry;
            } while (NULL != next_entry);
        }
    }
    free(hash->buckets);
    free(hash);
}

static inline uint32_t str_hash(const char *key, uint32_t len, uint32_t seed) {
    static const uint32_t c1 = 0xcc9e2d51;
    static const uint32_t c2 = 0x1b873593;
    static const uint32_t r1 = 15;
    static const uint32_t r2 = 13;
    static const uint32_t m = 5;
    static const uint32_t n = 0xe6546b64;

    uint32_t hash = seed;

    const int nblocks = len / 4;
    const uint32_t *blocks = (const uint32_t *) key;
    int i;
    for (i = 0; i < nblocks; i++) {
        uint32_t k = blocks[i];
        k *= c1;
        k = (k << r1) | (k >> (32 - r1));
        k *= c2;

        hash ^= k;
        hash = ((hash << r2) | (hash >> (32 - r2))) * m + n;
    }

    const uint8_t *tail = (const uint8_t *) (key + nblocks * 4);
    uint32_t k1 = 0;

    switch (len & 3) {
        case 3:
            k1 ^= tail[2] << 16;
        case 2:
            k1 ^= tail[1] << 8;
        case 1:
            k1 ^= tail[0];

            k1 *= c1;
            k1 = (k1 << r1) | (k1 >> (32 - r1));
            k1 *= c2;
            hash ^= k1;
    }

    hash ^= len;
    hash ^= (hash >> 16);
    hash *= 0x85ebca6b;
    hash ^= (hash >> 13);
    hash *= 0xc2b2ae35;
    hash ^= (hash >> 16);

    return hash;
}

static inline entry_t *entry_make(const char *key, size_t keysz, const char *value) {
    entry_t *result;

    result = malloc(sizeof(struct entry_t));
    if (NULL != result) {
        result->nb_values = 1;
        result->values = malloc(result->nb_values * sizeof(char *));
        if (NULL != result->values) {
            result->key = malloc(keysz * sizeof(char));
            if (NULL == result->key) {
                fprintf(stderr, "allocation error key in entry_make\n");
                free(result);
                free(result->values);
                result = NULL;
            } else {
                memcpy(result->key, key, keysz);
                result->keysz = keysz;
                *(result->values) = strdup(value);
                if (NULL == *(result->values)) {
                    fprintf(stderr, "allocation error values content in entry_make\n");
                    free(result->key);
                    free(result->values);
                    free(result);
                    result = NULL;
                } else {
                    result->next = NULL;
                }
            }
        } else {
            fprintf(stderr, "allocation error for values in entry_make\n");
            free(result);
            result = NULL;
        }
    } else {
        fprintf(stderr, "allocation error in entry_make\n");
    }

    return result;
}

static inline int hash_add(hash_t *hash, const char *key, size_t keysz, const char *value)
{
    entry_t *tmp_entry;
    uint32_t bucket;

    bucket = str_hash(key, keysz, 0xdeadbeef) & hash->hashmask;
    tmp_entry = hash->buckets[bucket];

    while((NULL != tmp_entry) && ((keysz != tmp_entry->keysz) || (0 != memcmp(tmp_entry->key, key, keysz))))
        tmp_entry = tmp_entry->next;

    if (NULL != tmp_entry) {
        char **tmp_values;
        tmp_entry->nb_values += 1;
        tmp_values = realloc(tmp_entry->values, tmp_entry->nb_values * sizeof(char *));
        if (NULL != tmp_values) {
            tmp_entry->values = tmp_values;
        } else {
            fprintf(stderr, "reallocation error in hash_add\n");
            return -1;
        }
        tmp_entry->values[tmp_entry->nb_values - 1] = strdup(value);
    } else {
        if (NULL != hash->buckets[bucket]) {
            tmp_entry = entry_make(key, keysz, value);
            tmp_entry->next = hash->buckets[bucket];
            hash->buckets[bucket] = tmp_entry;
        } else {
            hash->buckets[bucket] = entry_make(key, keysz, value);
        }
        if (NULL == hash->buckets[bucket]) {
            fprintf(stderr, "an error occurred while calling entry_make\n");
            return -1;
        }
    }

    return 0;
}

static inline char **hash_get(hash_t *hash, const char *key, size_t keysz, size_t *nb_values)
{
    entry_t *tmp_entry;
    uint32_t bucket;

    bucket = str_hash(key, keysz, 0xdeadbeef) & hash->hashmask;
    tmp_entry = hash->buckets[bucket];

    while((NULL != tmp_entry) && ((keysz != tmp_entry->keysz) || (0 != memcmp(tmp_entry->key, key, keysz))))
        tmp_entry = tmp_entry->next;

    if (NULL != tmp_entry) {
        *nb_values = tmp_entry->nb_values;
        return tmp_entry->values;
    }

    *nb_values = 0;
    return NULL;
}

#define SKIP_SEPARATOR(c, end, ptr, line, tmp, skipped_tag, error) {     \
    end = memchr(ptr, c, sizeof(line) - (ptr - line));                   \
    if (NULL == end) {                                                   \
        fprintf(stderr, "missing %ith %c in %s\n", skipped_tag, c, tmp); \
        error = 1;                                                       \
    } else {                                                             \
        ptr = end + 1;                                                   \
    }                                                                    \
}

static inline int read_file(const char *fname, hashjoin_cfg_t *conf)
{
    char line[4096], key[4096], cspn[2];
    FILE *fd;
    char *tmp, *ptr, *end;
    size_t line_len, keysz;
    int i, rv, error;

    cspn[0] = conf->separator1;
    cspn[1] = '\0';
    fd = fopen(fname, "r");
    if (NULL == fd) {
        fprintf(stderr, "an error occurred calling fopen: %s\n", fname);
        return -1;
    }
    do {
        error = 0;
        tmp = fgets(line, sizeof(line), fd);
        if (NULL != tmp) {
            ptr = tmp;
            line_len = strlen(ptr);
            if('\n' == ptr[line_len - 1]) {
                line_len--;
                ptr[line_len] = '\0';
            }
            for (i = 0; (i < conf->field1) && (0 == error); i++) {
                SKIP_SEPARATOR(conf->separator1, end, ptr, line, tmp, i, error);
            }
            if (0 != error) {
                continue;
            }
            keysz = strcspn(ptr, cspn);
            memcpy(key, ptr, keysz);
            if (0 == conf->negate) {
                tmp = line;
            } else {
                tmp = "a";
            }
            if (0 != conf->fixed) {
                if (keysz > conf->fixed)
                    keysz = conf->fixed;
            }
            rv = hash_add(conf->hash, key, keysz, tmp);
            if (0 != rv) {
                fprintf(stderr, "an error occurred while calling hash_add (%s:%s)\n", fname, line);
                return rv;
            }
        }
    } while(0 == feof(fd));

    return 0;
}

static inline int process_file(const char *fname, hashjoin_cfg_t *conf)
{
    char line[4096], key[4096], cspn[2];
    FILE *fd;
    char *tmp, *ptr, *end, **values;
    size_t line_len, keysz, nb_values;
    int i, error;

    cspn[0] = conf->separator2;
    cspn[1] = '\0';
    fd = fopen(fname, "r");
    if (NULL == fd) {
        fprintf(stderr, "an error occurred calling fopen: %s\n", fname);
        return -1;
    }
    do {
        error = 0;
        tmp = fgets(line, sizeof(line), fd);
        if (NULL != tmp) {
            ptr = tmp;
            line_len = strlen(ptr);
            if('\n' == ptr[line_len - 1]) {
                line_len--;
                ptr[line_len] = '\0';
            }
            for (i = 0; (i < conf->field2) && (0 == error); i++) {
                SKIP_SEPARATOR(conf->separator2, end, ptr, line, tmp, i, error);
            }
            if (0 != error) {
                continue;
            }
            keysz = strcspn(ptr, cspn);
            memcpy(key, ptr, keysz);
            if (0 != conf->fixed) {
                if (keysz > conf->fixed)
                    keysz = conf->fixed;
            }
            values = hash_get(conf->hash, key, keysz, &nb_values);
            if (NULL != values) {
                if (0 == conf->negate) {
                    size_t j;
                    for (j = 0; j < nb_values; j++) {
                        fprintf(stdout, "%s", line);
                        fprintf(stdout, "%c", conf->separator2);
                        for (i = 0; values[j][i] != '\0'; i++)
                            if(values[j][i] == conf->separator1)
                                values[j][i] = conf->separator2;
                        fprintf(stdout, "%s", values[j]);
                        fprintf(stdout, "\n");
                    }
                }
            } else {
                if (0 != conf->negate) {
                    fprintf(stdout, "%s\n", line);
                }
            }
        }
    } while(0 == feof(fd));

    return 0;
}

/* load first file field in a hash, then, matches it in second file field then append 1 to 2. */
/* -n negate the match: If field in file 2 doesn't match any in file 1, display line */
int main(int argc, char * const *argv)
{
    /* options descriptor */
    static struct option longopts[] = {
        { "field1", required_argument, NULL, '1' },
        { "field2", required_argument, NULL, '2' },
        { "size", required_argument, NULL, 'S' },
        { "fixed", required_argument, NULL, 'f' },
        { "negate", no_argument, NULL, 'n' },
        { "sep1", required_argument, NULL, 'x' },
        { "sep2", required_argument, NULL, 'y' },
        { NULL, 0, NULL, 0 }
    };
    hashjoin_cfg_t conf;
    // size_t expected_size = 100; /* TODO add heuristic to guess that number avg line size / byte sz */
    int ch, rv;

    conf.hash = NULL;
    conf.field1 = 0;
    conf.field2 = 0;
    conf.fixed = 0;
    conf.negate = 0;
    conf.separator1 = ',';
    conf.separator2 = ',';
    conf.size = 8000000;
    while ((ch = getopt_long(argc, argv, "1:2:S:f:nx:y:", longopts, NULL)) != -1)
        switch (ch) {
            case '1':
                conf.field1 = atoi(optarg) - 1;
                break;
            case '2':
                conf.field2 = atoi(optarg) - 1;
                break;
            case 'S':
                conf.size = atoi(optarg);
                break;
            case 'f':
                conf.fixed = atoi(optarg);
                break;
            case 'n':
                conf.negate = 1;
                break;
            case 'x':
                conf.separator1 = *optarg;
                break;
            case 'y':
                conf.separator2 = *optarg;
                break;
            default:
                fprintf(stderr, "getopt not happy\n");
        }
    conf.hash = hash_make(conf.size);
    argc -= optind;
    argv += optind;
    if (argc < 2) {
        fprintf(stderr, "missing files?\n");
        return -1;
    }
    rv = read_file(argv[0], &conf);
    if (0 != rv) {
        fprintf(stderr, "an error occurred while calling read_file(%s)\n", argv[1]);
        return -1;
    }
    rv = process_file(argv[1], &conf);
    if (0 != rv) {
        fprintf(stderr, "an error occurred while calling process_file(%s)\n", argv[2]);
        return -1;
    }
    hash_destroy(conf.hash);

    return 0;
}
