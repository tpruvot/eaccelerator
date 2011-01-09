/*
   +----------------------------------------------------------------------+
   | eAccelerator project                                                 |
   +----------------------------------------------------------------------+
   | Copyright (c) 2004 - 2010 eAccelerator                               |
   | http://eaccelerator.net                                              |
   +----------------------------------------------------------------------+
   | This program is free software; you can redistribute it and/or        |
   | modify it under the terms of the GNU General Public License          |
   | as published by the Free Software Foundation; either version 2       |
   | of the License, or (at your option) any later version.               |
   |                                                                      |
   | This program is distributed in the hope that it will be useful,      |
   | but WITHOUT ANY WARRANTY; without even the implied warranty of       |
   | MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the        |
   | GNU General Public License for more details.                         |
   |                                                                      |
   | You should have received a copy of the GNU General Public License    |
   | along with this program; if not, write to the Free Software          |
   | Foundation, Inc., 59 Temple Place - Suite 330, Boston,               |
   | MA  02111-1307, USA.                                                 |
   |                                                                      |
   | A copy is availble at http://www.gnu.org/copyleft/gpl.txt            |
   +----------------------------------------------------------------------+
   $Id: $
*/

#include "eaccelerator.h"

#ifdef HAVE_EACCELERATOR

#include "eaccelerator_version.h"
#include "ea_restore.h"
#include "ea_crc32.h"
#include "debug.h"
#include "ea_cache.h"

#include "zend.h"
#include "ext/standard/md5.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifdef WIN32
#  include <limits.h>
#else
#  ifdef HAVE_UNISTD_H
#    include <unistd.h>
#  endif
#endif

#include <string.h>

static int binary_eaccelerator_version[2];
static int binary_php_version[2];
static int binary_zend_version[2];

extern eaccelerator_mm* ea_mm_instance;
extern ea_hashtable_t *script_ht;

extern zend_bool ea_scripts_shm_only;

#define MAX_VERSION_STRING 255
static void encode_version(const char *str, int *version, int *extra)
{
    unsigned int a = 0;
    unsigned int b = 0;
    unsigned int c = 0;
    unsigned int d = 0;
    size_t len;
    char s[MAX_VERSION_STRING];
    char buf[MAX_VERSION_STRING];

    len = strlen(str);
    memcpy(buf, str, (len > MAX_VERSION_STRING) ? MAX_VERSION_STRING : len);
    buf[MAX_VERSION_STRING - 1] = '\0';

    memset(s, 0, MAX_VERSION_STRING);
    sscanf(str, "%u.%u.%u%s", &a, &b, &c, s);

    if (s[0] == '.') {
        sscanf(s, ".%u-%s", &d, buf);
    } else if (s[0] == '-') {
        memcpy(buf, &s[1], MAX_VERSION_STRING - 1);
    } else {
        memcpy(buf, s, MAX_VERSION_STRING);
    }

    *version = ((a & 0xff) << 24) | ((b & 0xff) << 16) | 
        ((c & 0xff) << 8) | (d & 0xff);

    if (buf[0] == 0) {
        a = 0;
        b = 0;
    } else if (strncasecmp(buf, "rev", 3) == 0) {
        a = 1;
        sscanf(buf, "rev%u", &b);
    } else if (strncasecmp(buf, "rc", 2) == 0) {
        a = 2;
        sscanf(buf, "rc%u", &b);
    } else if (strncasecmp(buf, "beta", 4) == 0) {
        a = 3;
        sscanf(buf, "beta%u", &b);
    } else {
        a = 0xf;
        // just encode the first 4 bytes
        b = ((buf[0] & 0x7f) << 21) | ((buf[1] & 0x7f) << 14) | 
            ((buf[2] & 0x7f) << 7) | (buf[3] & 0x7f);
    }

    *extra = ((a & 0xf) << 28) | (0x0fffffff & b);
}

#ifdef DEBUG
static void decode_version(int version, int extra, char *str, size_t len)
{
    int number;

    if ((version & 0xff) == 0) {
        number = snprintf(str, len, "%u.%u.%u", (version >> 24),
                ((version >> 16) & 0xff), ((version >> 8) & 0xff));
    } else {
        number = snprintf(str, len, "%u.%u.%u.%u", (version >> 24),
                ((version >> 16) & 0xff), ((version >> 8) & 0xff), (version & 0xff));
    }

    if (extra != 0) {
        unsigned int type = ((extra >> 28) & 0xf);
        extra = (extra & 0x0fffffff);
        switch (type) {
            case 1:
                snprintf(&str[number], len, "-rev%u", extra);
                break;
            case 2:
                snprintf(&str[number], len, "-rc%u", extra);
                break;
            case 3:
                snprintf(&str[number], len, "-beta%u", extra);
                break;
            case 15:
                if (len >= number + 5) {
                    str[number] = '-';
                    str[number + 1] = (extra >> 21) & 0x7f;
                    str[number + 2] = (extra >> 14) & 0x7f;
                    str[number + 3] = (extra >> 7) & 0x7f;
                    str[number + 4] = extra & 0x7f;
                    str[number + 5] = '\0';
                }
                break;
            default:
                break;
        }
    }
}
#endif

static char num2hex[] = 
{'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};

static void make_hash_dirs(char *fullpath, int lvl) 
{
    int j;
    int n = strlen(fullpath);
    mode_t old_umask = umask(0);

    if (lvl < 1) {
        return;
    }
    if (fullpath[n-1] != '/') {
        fullpath[n++] = '/';
    }

    for (j = 0; j < 16; j++) {
        fullpath[n] = num2hex[j];       
        fullpath[n+1] = 0;
        mkdir(fullpath, 0777);
        make_hash_dirs(fullpath, lvl-1);
    }
    fullpath[n+2] = 0;
    umask(old_umask);
}

static int ea_cache_file_key(char *cache_dir, char* s, const char* prefix, const char* key TSRMLS_DC) {
    char md5str[33];
    PHP_MD5_CTX context;
    unsigned char digest[16];
    int i;
    int n;

    md5str[0] = '\0';
    PHP_MD5Init(&context);
    PHP_MD5Update(&context, (unsigned char*)key, strlen(key));
    PHP_MD5Final(digest, &context);
    make_digest(md5str, digest);
    snprintf(s, MAXPATHLEN-1, "%s/", cache_dir);
    n = strlen(s);
    for (i = 0; i < EACCELERATOR_HASH_LEVEL && n < MAXPATHLEN - 1; i++) {
        s[n++] = md5str[i];
        s[n++] = '/';
    }
    s[n] = 0;
    snprintf(&s[n], MAXPATHLEN-1-n, "%s%s", prefix, md5str);
    return 1;
}

void ea_cache_init()
{
    encode_version(EACCELERATOR_VERSION, &binary_eaccelerator_version[0],
            &binary_eaccelerator_version[1]);
    encode_version(PHP_VERSION, &binary_php_version[0],
            &binary_php_version[1]);
    encode_version(ZEND_VERSION, &binary_zend_version[0],
            &binary_zend_version[1]);
}

/* 
 * A function to check if the header of a cache file valid is.
 */
inline int header_check(ea_file_header_t *hdr)
{
#ifdef DEBUG
    char current[MAX_VERSION_STRING];
    char cache[MAX_VERSION_STRING];
#endif

    if (strncmp(hdr->magic, EA_MAGIC, 8) != 0) {
#ifdef DEBUG
        ea_debug_printf(EA_DEBUG_CACHE, "Magic header mismatch.");
#endif
        return 0;
    }
    if (hdr->eaccelerator_version[0] != binary_eaccelerator_version[0] 
            || hdr->eaccelerator_version[1] != binary_eaccelerator_version[1]) {
#ifdef DEBUG
        decode_version(hdr->eaccelerator_version[0], hdr->eaccelerator_version[1], cache, MAX_VERSION_STRING);
        decode_version(binary_eaccelerator_version[0], binary_eaccelerator_version[1], current, MAX_VERSION_STRING);
        ea_debug_printf(EA_DEBUG_CACHE, "eAccelerator version mismatch, cache file %s and current version %s\n", cache, current);
#endif
        return 0;
    }
    if (hdr->zend_version[0] != binary_zend_version[0] 
            || hdr->zend_version[1] != binary_zend_version[1]) {
#ifdef DEBUG
        decode_version(hdr->zend_version[0], hdr->zend_version[1], cache, MAX_VERSION_STRING);
        decode_version(binary_zend_version[0], binary_zend_version[1], current, MAX_VERSION_STRING);
        ea_debug_printf(EA_DEBUG_CACHE, "Zend version mismatch, cache file %s and current version %s\n", cache, current);
#endif
        return 0;
    }
    if (hdr->php_version[0] != binary_php_version[0] 
            || hdr->php_version[1] != binary_php_version[1]) {
#ifdef DEBUG
        decode_version(hdr->php_version[0], hdr->php_version[1], cache, MAX_VERSION_STRING);
        decode_version(binary_php_version[0], binary_php_version[1], current, MAX_VERSION_STRING);
        ea_debug_printf(EA_DEBUG_CACHE, "PHP version mismatch, cache file %s and current version %s\n", cache, current);
#endif
        return 0;
    }
    return 1;
}

/* 
 * A function to create the header for a cache file.
 */
inline void header_init(ea_file_header_t *hdr)
{
    strncpy(hdr->magic, EA_MAGIC, 8);
    hdr->eaccelerator_version[0] = binary_eaccelerator_version[0];
    hdr->eaccelerator_version[1] = binary_eaccelerator_version[1];
    hdr->zend_version[0] = binary_zend_version[0];
    hdr->zend_version[1] = binary_zend_version[1];
    hdr->php_version[0] = binary_php_version[0];  
    hdr->php_version[1] = binary_php_version[1];
}

/* this function does no locking */
static ea_cache_entry* ea_cache_file_get(char *cache_dir, const char *key, void *data, 
        int (* compare_func) (ea_cache_entry *, void *))
{
    int fd;
    char file[MAXPATHLEN];
    ea_file_header_t header;
    ea_cache_entry *script;
    TSRMLS_FETCH();

    DBG(ea_debug_printf, (EA_DEBUG_CACHE, "Finding key '%s' in disk cache: ", key));

    if (!ea_cache_file_key(cache_dir, file, "eaccelerator-", key TSRMLS_CC)) {
        DBG(ea_debug_printf, (EA_DEBUG_CACHE, "md5 failed\n"));
        return NULL;
    }

    if ((fd = open(file, O_RDONLY)) == -1) {
        // error openening the file
        DBG(ea_debug_printf, (EA_DEBUG_CACHE, "error opening file %s\n", file));
        return NULL;
    }

    // lock the file
    EACCELERATOR_FLOCK(fd, LOCK_SH);

    // read the header and check it
    if (read(fd, &header, sizeof(ea_file_header_t)) != sizeof(ea_file_header_t)) {
        EACCELERATOR_FLOCK(fd, LOCK_UN);
        close(fd);
        DBG(ea_debug_printf, (EA_DEBUG_CACHE, "file is to small to contain a header\n"));
        return NULL;
    }

    if (!header_check(&header)) {
        EACCELERATOR_FLOCK(fd, LOCK_UN);
        close(fd);
        unlink(file);
        DBG(ea_debug_printf, (EA_DEBUG_CACHE, "header check failed\n"));
        return NULL;
    }

    // allocate memory for the script
    script = ea_malloc_nolock(header.size);
    // TODO: if there isn't any space, do some garbage collection
    if (script == NULL) { // we don't have memory available, use emalloc
        script = emalloc(header.size);
        if (script == NULL) { // we didn't find memory
            EACCELERATOR_FLOCK(fd, LOCK_UN);
            close(fd);
            DBG(ea_debug_printf, (EA_DEBUG_CACHE, "can't allocate memory\n"));
            return NULL;
        }
        script->alloc = ea_emalloc;
    } else {
        script->alloc = ea_shared_mem;
    }

    // read the script from disk
    if (read(fd, script, header.size) != header.size || script->size != header.size
            || header.crc32 != ea_crc32((const char *)script, script->size)) {
        // something fishy is going on
        EACCELERATOR_FLOCK(fd, LOCK_UN);
        close(fd);
        unlink(file);
        DBG(ea_debug_printf, (EA_DEBUG_CACHE, "cache file is corrupted\n"));
        return NULL;
    }
    EACCELERATOR_FLOCK(fd, LOCK_UN);
    close(fd);

    // does the filename and the key match?
    if (strcmp(key, script->key) != 0) {
        EA_FREE_CACHE_ENTRY_NO_LOCK(script);
        DBG(ea_debug_printf, (EA_DEBUG_CACHE, "keys didn't match!\n", key));
        unlink(file);
        return NULL;
    }

    // check if the script is valid
    if (compare_func != NULL && !compare_func(script, data)) {
        EA_FREE_CACHE_ENTRY_NO_LOCK(script);
        unlink(file);
        DBG(ea_debug_printf, (EA_DEBUG_CACHE, "compare function failed\n", key));
        return NULL;
    }

    // fix the pointers
    script->next = NULL;
    script->ref_cnt = 0;
    eaccelerator_fixup(script->data, header.base TSRMLS_CC);

    DBG(ea_debug_printf, (EA_DEBUG_CACHE, "done\n"));
    return script;
}

static int ea_cache_file_put(char * cache_dir, ea_cache_entry *script)
{
    int fd;
    char file[MAXPATHLEN];
    ea_file_header_t header;
    int ret = 0;
    TSRMLS_FETCH();

    if (!ea_cache_file_key(cache_dir, file, "eaccelerator-", script->key TSRMLS_CC)) {
        return 0;
    }

    unlink(file);
    if ((fd = open(file, O_CREAT | O_WRONLY | O_EXCL, S_IRUSR | S_IWUSR)) == -1) {
        ea_debug_log("Open for writing failed for '%s': %s\n", file, strerror(errno));
        return 0;
    }

    EACCELERATOR_FLOCK(fd, LOCK_EX);

    // create a header
    header_init(&header);
    header.size = script->size;
    header.mtime = script->mtime;
    header.crc32 = ea_crc32((const char *)script, script->size);
    header.base = (void *)script;

    // write the file
    ret = (write(fd, &header, sizeof(ea_file_header_t)) == sizeof(ea_file_header_t));
    if (ret) {
        ret = (write(fd, script, script->size) == script->size);
    }
    EACCELERATOR_FLOCK(fd, LOCK_UN);

    close(fd);

    if (!ret) {
        unlink(file);
    }
    DBG(ea_debug_printf, (EA_DEBUG_CACHE, "Stored %s in cache file %s\n", script->key, file));
    return ret;
}

#ifdef DEBUG
/* this function does no locking */
static void ea_cache_dump_ht(ea_hashtable_t *ht)
{
    int i;
    ea_cache_entry *p;

    ea_debug_printf(EA_DEBUG_CACHE, "Dumping ht with %d buckets and %d elements\n", 
            ht->size, ht->elements);

    for (i = 0; i < ht->size; ++i) {
        p = ht->entries[i];
        while (p != NULL) {
            ea_debug_printf(EA_DEBUG_CACHE, "\t%d (0x%x) => %s\n", i, p->hv, p->key);
            if (p != NULL && p == p->next) {
                ea_debug_printf(EA_DEBUG_CACHE, "\tStupid fuck, you made a loop!\n");
                return;
            }
            p = p->next;
        } 
    }
}
#endif

/* this function does no locking */
static ea_hashtable_t* ea_cache_hashtable_init(size_t start_size)
{
    ea_hashtable_t *table;
    
    // allocate table
	table = ea_malloc(sizeof(ea_hashtable_t));
    if (table == NULL) {
        DBG(ea_debug_printf, (EA_DEBUG_CACHE, "Unable to allocate space for hashtable\n"));
        return NULL;
    }
    memset(table, 0, sizeof(ea_hashtable_t));
    
    table->size = start_size;
    
    // allocate storage for all slots
    table->entries = ea_malloc(sizeof(ea_cache_entry*) * start_size);
	if (table->entries == NULL) {
		ea_free_nolock(table);
		DBG(ea_debug_printf, (EA_DEBUG_CACHE, "Unable to allocate space for hashtable\n"));
		return NULL;
	}
    memset(table->entries, 0, sizeof(ea_cache_entry*) * start_size);
    
    // when the table reaches this number of elements it needs to be resized
    table->max_load = (size_t)(start_size * EA_HASHTABLE_LOAD_FACTOR);

	DBG(ea_debug_printf, (EA_DEBUG_CACHE, 
		"Created hashtable with %d buckets, will resize on %d buckets\n",
		table->size, table->max_load));
    
    return table;
}

// remove the script when the ref_cnt is 0 otherwise just mark 
// it as removed, the last process which puts the refcount to 
// zero should remove it
#define REMOVE_ENTRY(p) p->ref_cnt--; \
    if (p->ref_cnt == 0) { \
        ea_free_nolock(p); \
    }

/* this function does not do locking */
static void ea_cache_hashtable_grow(ea_hashtable_t *ht, time_t req_time)
{
    ea_cache_entry **new_entries;
    ea_cache_entry *p, *q;
    size_t new_size;
    unsigned int i, index;

    // double the size
    new_size = ht->size * 2;

    // allocate storage for all slots
    new_entries = ea_malloc_nolock(sizeof(ea_cache_entry*) * new_size);
    if (new_entries == NULL) {
        /* TODO
         * growing the hashtable can only be done while it's locked. For this we
         * use the nolock free and malloc versions. It's possible we don't have enough
         * memory available to allocate a new hashtable, we can't call gc or prune
         * because they need to be called outside a lock.
         * When a hashtable is search, expired entries are removed, for now this should
         * free enough memory to grow the hashtable, if not this function will be called
         * on every add but it will never grow.
         */
        DBG(ea_debug_printf, (EA_DEBUG_CACHE, 
                    "Unable to grow the hashtable. Allocating %d bytes failed\n", 
                    sizeof(ea_cache_entry*) * new_size));
        return;
    }
    memset(new_entries, 0, sizeof(ea_cache_entry *) * new_size);

    // rehash the table
    for (i = 0; i < ht->size; ++i) {
        p = ht->entries[i];
        while (p != NULL) {
            //TODO: only copy entries when they are all valid 
            q = p->next;

            // add the entry to the new hash table
            index = p->hv & (new_size - 1);
            p->next = new_entries[index];
            new_entries[index] = p;

            p = q;
        }
    }

    ea_free_nolock(ht->entries);    
    ht->entries = new_entries;

    ht->size = new_size;
    ht->max_load = (size_t)(new_size * EA_HASHTABLE_LOAD_FACTOR);

    DBG(ea_debug_printf, (EA_DEBUG_CACHE, "Resized hashtable to %d\n", new_size));
}

/* this function does not do locking */
ea_cache_entry* ea_cache_hashtable_get(ea_hashtable_t *ht, const char *key, 
        time_t req_time, time_t ttl, void *data, 
        int (* compare_func) (ea_cache_entry *, void *))
{
    unsigned int hv, slot;
    ea_cache_entry *entry, *p, *next;
    size_t key_len = strlen(key);

    hv = zend_get_hash_value((char *)key, key_len);
    slot = hv & (ht->size - 1);

    DBG(ea_debug_printf, (EA_DEBUG_CACHE, 
                "Searching key '%s' with hv 0x%x in hashtable (slot %d): ", key, hv, slot));

    entry = ht->entries[slot];
    p = NULL;
    next = NULL;

    while (entry != NULL) {
        if (ttl > 0 && entry->atime + ttl < req_time) {
            // key is expired
            if (p == NULL) {
                // first bucket in slot
                ht->entries[slot] = entry->next;
            } else {
                p->next = entry->next;
            }
            next = entry->next;
            ht->elements--;
            REMOVE_ENTRY(entry);

            // continue our iteration
            entry = next;
        } else if (hv == entry->hv && strncmp(key, entry->key, key_len) == 0) {
            if (compare_func != NULL && !compare_func(entry, data)) { 
                // key isn't valid, remove it
                if (p == NULL) {
                    // first bucket in slot
                    ht->entries[slot] = entry->next;
                } else {
                    p->next = entry->next;
                }
                next = entry->next;
                ht->elements--;
                DBG(ea_debug_printf, (EA_DEBUG_CACHE, "found it but not valid, removing\n"));
                REMOVE_ENTRY(entry);

                // continue our iteration
                entry = next;
            } else {
                entry->ref_cnt++;
                entry->nhits++;
                entry->atime = req_time;
                DBG(ea_debug_printf, (EA_DEBUG_CACHE, "found it\n"));
                return entry;
            }
        } else {
            // entry could have been removed
            p = entry;
            entry = entry->next;
        }
    }

    DBG(ea_debug_printf, (EA_DEBUG_CACHE, "it's not here\n"));

    return NULL;
}

/* this function does not do locking */
static void ea_cache_hashtable_put(ea_hashtable_t *ht, time_t req_time,
        time_t ttl, ea_cache_entry *entry)
{
    unsigned int slot;
    ea_cache_entry *p, *q;
    size_t key_len = strlen(entry->key);

    entry->hv = zend_get_hash_value((char *)entry->key, key_len);
    slot = entry->hv & (ht->size - 1);

    entry->next = ht->entries[slot];
    ht->entries[slot] = entry;

    DBG(ea_debug_printf, (EA_DEBUG_CACHE, 
                "Stored key '%s' with hv 0x%x in hashtable at slot %d\n", 
                entry->key, entry->hv, slot)); 

    // when the entry is in the hashtable it's ref_cnt is set to 1, this means
    // that a ref_cnt of 0 means the entry can be removed. No removed list is 
    // needed this way
    entry->ref_cnt = 1;
    entry->atime = req_time;

    // when the hashtable load exceeds the loadfactor, resize it
    ht->elements++;
#ifdef EA_CACHE_DYN_HT	
    if (ht->elements >= ht->max_load) {
        // resize the table
        ea_cache_hashtable_grow(ht, req_time);
    }
#endif

    // maybe we need to remove a value with the same key (replacing an old value)
    q = entry;
    p = entry->next;

    while (p != NULL) {
        // inv: q != NULL
        if (p->hv == entry->hv && strncmp(p->key, entry->key, key_len) == 0) {
            DBG(ea_debug_printf, (EA_DEBUG_CACHE, 
                        "Removed %s from hashtable (replacement)\n", p->key));
            // this is an old value of the same data, remove it
            q->next = p->next;
            ht->elements--;

            REMOVE_ENTRY(p);
            
            p = q;
        } else if (ttl > 0 && p->atime + ttl < req_time) {
            q->next = p->next;
            ht->elements--;
            
            REMOVE_ENTRY(p);

            p = q;
        }

        q = p;
        p = p->next;
    }
}

/* 
 * prune all remove all expired items from the given hashtable
 * this function does not do locking
 */
static ea_cache_hashtable_prune_nolock(ea_hashtable_t *ht, time_t req_time, time_t ttl)
{
    ea_cache_entry *p = NULL;
    ea_cache_entry *q = NULL;
    ea_cache_entry *next = NULL;
    int i;

    DBG(ea_debug_printf, (EA_DEBUG_CACHE, "Pruning ht with %d buckets and %d elements\n", 
                ht->size, ht->elements));

    for (i = 0; i < ht->size; ++i) {
        p = ht->entries[i];
        q = NULL;
        while (p != NULL) {
            if (ttl > 0 && p->atime + ttl < req_time) {
                DBG(ea_debug_printf, (EA_DEBUG_CACHE, "Removing expired key '%s' from slot %d\n",
                    p->key, i));
                if (q == NULL) {
                    // first bucket in slot
                    ht->entries[i] = p->next;
                } else {
                    q->next = p->next;
                }
                next = p->next;
                ht->elements--;
                
                REMOVE_ENTRY(p);
                p = next;
            } else {
                q = p;
                p = p->next;
            }
        } 
    }
}

static ea_cache_hashtable_prune(ea_hashtable_t *ht, time_t req_time, time_t ttl)
{
    EACCELERATOR_UNPROTECT();
    EACCELERATOR_LOCK_RD();

    ea_cache_hashtable_prune_nolock(ht, req_time, ttl);

    EACCELERATOR_UNLOCK_RD();
    EACCELERATOR_PROTECT();
}

static ea_cache_hashtable_purge(ea_hashtable_t *ht)
{ 
    ea_cache_entry *p = NULL;
    ea_cache_entry *next = NULL;
    int i;

    EACCELERATOR_UNPROTECT();
    EACCELERATOR_LOCK_RD();

    for (i = 0; i < ht->size; ++i) {
        p = ht->entries[i];
        while (p != NULL) {
            next = p->next;
            ht->elements--;
            REMOVE_ENTRY(p);
            p = next;
        }
        ht->entries[i] = NULL;
    }

    EACCELERATOR_UNLOCK_RD();
    EACCELERATOR_PROTECT();   
}

int ea_cache_put(ea_cache_request_t *request, ea_cache_entry *entry)
{
    if (entry->alloc == ea_shared_mem) {
        EACCELERATOR_UNPROTECT();
        EACCELERATOR_LOCK_RW();

        ea_cache_hashtable_put(request->cache->ht, request->req_time, request->cache->ttl, entry);

        DBG(ea_debug_printf, (EA_DEBUG_CACHE, "Put %s in hashtable, refcount is %d\n", 
                    entry->key, entry->ref_cnt));

        EACCELERATOR_UNLOCK_RW();
        EACCELERATOR_PROTECT();
    }

    return ea_cache_file_put(request->cache->cache_dir, entry);
}

ea_cache_entry *ea_cache_get(ea_cache_request_t *request, const char *key, void *data)
{
    ea_cache_entry *script = NULL;
    ea_used_entry_t *used = NULL;

    EACCELERATOR_UNPROTECT();
    EACCELERATOR_LOCK_RW();

    // get it from shared memory
    script = ea_cache_hashtable_get(request->cache->ht, key, request->req_time,
            request->cache->ttl, data, request->cache->compare_func);

    if (script == NULL) { // it's not in memory, load it from disk
        // get a script from disk cache
        script = ea_cache_file_get(request->cache->cache_dir, key, data, request->cache->compare_func);

        if (script != NULL) {
            if (script->alloc == ea_shared_mem) {
                ea_cache_hashtable_put(request->cache->ht, request->req_time,
                    request->cache->ttl, script);
                script->ref_cnt++;
            } else {
                script->ref_cnt = 1;   
            }
        }
    }

    if (script != NULL) {
        // add it to the list of entries that are in use by this process
        used = emalloc(sizeof(ea_used_entry_t));

        if (used == NULL) {
            script->ref_cnt--;

            if (script->ref_cnt <= 0) {
                EA_FREE_CACHE_ENTRY_NO_LOCK(script);
                script = NULL;
            }
        }

        if (used != NULL) {
            used->entry = script;
            used->next = request->used_entries;
            request->used_entries = used;
        }
    }

    EACCELERATOR_UNLOCK_RW();
    EACCELERATOR_PROTECT();

#ifdef DEBUG
    if (script != NULL) {
        ea_debug_printf(EA_DEBUG_CACHE, "Found key '%s' with refcount %d\n", 
                key, script->ref_cnt);
    }
#endif

    return script;
}

ea_cache_t *ea_cache_create(char *cache_dir, size_t size)
{
    ea_cache_t *cache;
    char fullpath[MAXPATHLEN];

    if(!ea_scripts_shm_only) {
        snprintf(fullpath, MAXPATHLEN-1, "%s/", cache_dir);
        DBG(ea_debug_printf, (EA_DEBUG_CACHE, "Creating cache directory %s\n", fullpath));
        make_hash_dirs(fullpath, EACCELERATOR_HASH_LEVEL);
    }

    cache = ea_malloc(sizeof(ea_cache_t));
    memset(cache, 0, sizeof(ea_cache_t));
    if (cache == NULL) {
        return NULL;   
    }
    cache->ht = ea_cache_hashtable_init(size);
    cache->cache_dir = cache_dir;

    return cache;
}

void ea_cache_walk_ht(ea_cache_t *cache, 
        void (* format_func) (ea_cache_entry *, void *), void *data)
{
    int i;
    ea_cache_entry *p;

    EACCELERATOR_UNPROTECT();
    EACCELERATOR_LOCK_RD();

    DBG(ea_debug_printf, (EA_DEBUG_CACHE, "Walking ht with %d buckets and %d elements\n", 
                cache->ht->size, cache->ht->elements));

    for (i = 0; i < cache->ht->size; ++i) {
        p = cache->ht->entries[i];
        while (p != NULL) {
            if (p != NULL && p == p->next) {
                DBG(ea_debug_printf, (EA_DEBUG_CACHE, "Stupid fuck, you made a loop in your HT!\n"));
                return;
            }
            format_func(p, data);
            p = p->next;
        } 
    }

    EACCELERATOR_UNLOCK_RD();
    EACCELERATOR_PROTECT();
}

ea_cache_request_t *ea_cache_rinit(ea_cache_t *cache)
{
    ea_cache_request_t *request = NULL;

    request = emalloc(sizeof(ea_cache_request_t));

    if (request == NULL) {
        DBG(ea_debug_printf, (EA_DEBUG_CACHE, "Unable to allocate memory for request structure!\n"));
        return NULL;
    }

    request->cache = cache;
    request->used_entries = NULL;
    request->req_time = time(NULL);

    return request;
}

void ea_cache_rshutdown(ea_cache_request_t *request) {
    ea_used_entry_t *p, *r;

    p = request->used_entries;

    if (p != NULL) {
        EACCELERATOR_UNPROTECT();
        EACCELERATOR_LOCK_RW(); /** LOCK **/

        // decrement the reference counts from used cache entries for this request
        while (p != NULL) {
            p->entry->ref_cnt--;
            if (p->entry->ref_cnt <= 0) {
                DBG(ea_debug_printf, (EA_DEBUG_CACHE,
                            "Removing %s with refcount 0\n", p->entry->key));
                EA_FREE_CACHE_ENTRY_NO_LOCK(p->entry);
                p->entry = NULL;
            }
            r = p;
            p = p->next;

            efree(r);
        }
        EACCELERATOR_UNLOCK_RW(); /** UNLOCK **/
        EACCELERATOR_PROTECT();
    }

    efree(request);
    request = NULL;
}

ea_cache_entry *ea_cache_alloc_entry(char *key, size_t len, size_t size)
{
    ea_cache_entry *entry = NULL;
    size_t alloc_size = size;
    char *data = NULL;

    // add the size of the cache structure
    ADDSIZE(alloc_size, offsetof(ea_cache_entry, key) + len + 1);

    // TODO: align needed here?

    EACCELERATOR_UNPROTECT();
    entry = ea_malloc(alloc_size);
    if (entry == NULL) {
        EACCELERATOR_PROTECT();
        entry = emalloc(alloc_size);
        if (entry == NULL) {
            return NULL;
        }
        memset(entry, 0, alloc_size);
        entry->alloc = ea_emalloc;
    } else {
        memset(entry, 0, alloc_size);
        entry->alloc = ea_shared_mem;
    }

    // put the key in the cache structure and set the data pointer
    memcpy(entry->key, key, len + 1);
    data = (char *)entry;
    data += (offsetof(ea_cache_entry, key) + len + 1);
    EACCELERATOR_ALIGN(data);

    entry->data = (void *)data;
    entry->size = size;

    fprintf(stderr, "entry=%p data=%p entry->data=%p len=%d\n", entry, data, 
        entry->data, offsetof(ea_cache_entry, key) + len + 1);
    fflush(stderr);

    return entry;
}

void ea_cache_prune(ea_cache_request_t *request)
{
    DBG(ea_debug_printf, (EA_DEBUG_CACHE, "Pruning expired entries\n"));

    // prune hashtable
    ea_cache_hashtable_prune(request->cache->ht, request->req_time, request->cache->ttl);
}

static void ea_cache_file_purge(const char* dir)
#ifndef ZEND_WIN32
{
	DIR *dp;
	struct dirent *entry;
	char s[MAXPATHLEN];
	struct stat dirstat;
	
	if ((dp = opendir(dir)) != NULL) {
		while ((entry = readdir(dp)) != NULL) {
			strncpy(s, dir, MAXPATHLEN - 1);
			strlcat(s, "/", MAXPATHLEN);
			strlcat(s, entry->d_name, MAXPATHLEN);
			if (strstr(entry->d_name, "eaccelerator") == entry->d_name) {
				unlink(s);
			}
			if (stat(s, &dirstat) != -1) {
				if (strcmp(entry->d_name, ".") == 0)
					continue;
				if (strcmp(entry->d_name, "..") == 0)
					continue;
				if (S_ISDIR(dirstat.st_mode)) {
					ea_cache_file_purge(s);
				}
			}
		}
		closedir (dp);
	} else {
		ea_debug_error("[%s] Could not open cachedir %s\n", 
            EACCELERATOR_EXTENSION_NAME, dir);
	}
}
#else
{
	HANDLE  hFind;
    WIN32_FIND_DATA wfd;
    char path[MAXPATHLEN];
    size_t dirlen = strlen(dir);
  
    memcpy(path, dir, dirlen);
    strcpy(path + dirlen++, "\\eaccelerator*");

    hFind = FindFirstFile(path, &wfd);
	if (hFind == INVALID_HANDLE_VALUE) {
		do {
			strcpy(path + dirlen, wfd.cFileName);
			if (FILE_ATTRIBUTE_DIRECTORY & wfd.dwFileAttributes) {
				ea_cache_file_purge(path);
			} else if (!DeleteFile(path)) {
				ea_debug_error("[%s] Can't delete file %s: error %d\n",
                    EACCELERATOR_EXTENSION_NAME, path, GetLastError());
			}
		} while (FindNextFile(hFind, &wfd));
	}
    FindClose (hFind);
}
#endif

void ea_cache_purge(ea_cache_request_t *request)
{
    DBG(ea_debug_printf, (EA_DEBUG_CACHE, "Pruning expired entries\n"));

    // purge the hashtable
    ea_cache_hashtable_purge(request->cache->ht);

    // purge the file cache
    ea_cache_file_purge(request->cache->cache_dir);
}

#endif /* HAVE_EACCELERATOR */

/*
 * vim: noet tabstop=4 softtabstop=4 shiftwidth=4 expandtab
 */
