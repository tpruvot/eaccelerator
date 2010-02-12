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

#ifndef EA_CACHE_H
#define EA_CACHE_H

#include "eaccelerator.h"

#define EA_CACHE_DYN_HT
#define EACCELERATOR_HASH_LEVEL 2
#define EA_HASH_SIZE            2
#define EA_HASH_MAX				(EA_HASH_SIZE-1)

typedef enum _ea_alloc_place {
    ea_shared_mem,
    ea_emalloc,
    ea_malloc
} ea_alloc_place;

/*
 * An entry in the cache
 */
typedef struct ea_cache_entry {
    struct ea_cache_entry *next;
    ea_alloc_place alloc;       /* allocated by which mem manger     */
    unsigned int hv;            /* hash value                        */
    off_t filesize;             /* file size                         */
    time_t mtime;               /* file last modification time       */
    time_t ctime;				/* timestamp of cache entry			 */
    time_t atime;               /* expiration time                   */
    size_t size;                /* entry size (bytes)                */
    unsigned int nhits;         /* hits count                        */
    int ref_cnt;                /* how many processes uses the entry */
    void *data;                 /* the data this entry points to     */
    char key[1];                /* real file name (must be last el.) */
} ea_cache_entry;

typedef struct _ea_script_t {
    ea_op_array *op_array;      /* script's global scope code        */
    ea_fc_entry *f_head;        /* list of nested functions          */
    ea_fc_entry *c_head;        /* list of nested classes            */
} ea_script_t;

/*
 * Linked list of ea_cache_entry which are used by process/thread
 */
typedef struct _ea_used_entry_t {
    struct _ea_used_entry_t *next;
    ea_cache_entry *entry;
} ea_used_entry_t;

/*
 * Hashtable structure
 */
typedef struct ea_hashtable_t {
    size_t size;
    size_t elements;
    size_t max_load;
    ea_cache_entry **entries;
} ea_hashtable_t;

/*
 * Cache structure
 */
typedef struct ea_cache_t {
    ea_hashtable_t *ht;
    int (* compare_func) (ea_cache_entry *, void *);
    ea_cache_place place;
    time_t ttl;			                                /* the ttl for cache entries */
    char *cache_dir;
} ea_cache_t;

/*
 * Variables that are thread/process specific for the cache
 */
typedef struct _ea_cache_request_t {
	ea_cache_t *cache;
	ea_used_entry_t *used_entries;
	time_t req_time;																		/* the time used to update and check ttl */
} ea_cache_request_t;

/*
 * File header to write in cache files
 */
typedef struct ea_file_header_t {
    char magic[8];              /* "EACCELERATOR" */
    int eaccelerator_version[2];
    int zend_version[2];
    int php_version[2];
    int size;
    time_t mtime;
    void *base;
    unsigned int crc32;
} ea_file_header_t;

#define EA_HASHTABLE_LOAD_FACTOR 0.8

inline void header_init(ea_file_header_t *hdr); //FIXME
inline int header_check(ea_file_header_t *hdr); //FIXME

/**
 * Put a cache entry in given cache. When this function returns this function
 * doesn't increment the refcount so it means when you use the entry and put 
 * it in the used list you need to increment the refcount!!!!
 * 
 * @param ea_cache_request_t A pointer to the request structure  linked with
 *		the cache to get the entry from
 * @parma ea_cache_entry A pointer to the entry that needs to be stored in the cache
 */
int ea_cache_put(ea_cache_request_t *request, ea_cache_entry *entry);

/**
 * Get an entry from the cache. When the function returns it will increment the 
 * refcount of the entry. Make sure you decrement the refcount when a request is 
 * done otherwise the entry will live forever.
 * 
 * @param ea_cache_request_t A pointer to the request structure  linked with
 *		the cache to get the entry from
 * @param char A pointer to the string to lookup the entry in the cache
 * @param void A pointer to the extra data needed by the compare function
 * @return The entry from the cache or null if it's not found
 */
ea_cache_entry *ea_cache_get(ea_cache_request_t *request, const char *key, void *data);

/**
 * Initialise a new cache with the given size as the number of initial buckets.
 *
 * @paran char * The path of the directory to create the cache in
 * @param size_t The size of the hashtable
 * @return A newly created cache
 */
ea_cache_t *ea_cache_create(char *cache_dir, size_t size);

/**
 * Initialise the cache
 */
void ea_cache_init();

/**
 * Initialise the request structure for the current request.
 */
ea_cache_request_t *ea_cache_rinit(ea_cache_t *cache);

/**
 * Walk through all the cached scripts in that are in memory.
 *
 * @param cache The cache to walk the hashtable from
 * @param format_func The function to format the cache entries
 * @param data Data to pass to the format function.
 */
void ea_cache_walk_ht(ea_cache_t *cache, void (* format_func) (ea_cache_entry *, void *data), void *data);

/**
 * Get an entry from the hashtable
 */
ea_cache_entry* ea_cache_hashtable_get(ea_hashtable_t *ht, const char *key, time_t req_time, time_t ttl, 
		void *data, int (* compare_func) (ea_cache_entry *, void *));

/**
 * Allocate and initialise a cache entry. If the alloc type of the entry is
 * ea_shared_mem then the shared memory region needs to be protected again.
 */
ea_cache_entry *ea_cache_alloc_entry(char *key, size_t key_len, size_t size);

/**
 * Prune expired entries from memory and cache
 */
void ea_cache_prune(ea_cache_request_t *request);

/**
 * Purge all entries from the cache
 */
void ea_cache_purge(ea_cache_request_t *request);

#define ea_malloc(size)        mm_malloc_lock(ea_mm_instance->mm, size);
#define ea_free(x)             mm_free_lock(ea_mm_instance->mm, x)
#define ea_malloc_nolock(size) mm_malloc_nolock(ea_mm_instance->mm, size)
#define ea_free_nolock(x)      mm_free_nolock(ea_mm_instance->mm, x)

/* two macros to free cache entries */
#define EA_FREE_CACHE_ENTRY_NO_LOCK(p) { if (p->alloc == ea_shared_mem)\
    ea_free_nolock(p); else if (p->alloc == ea_emalloc) efree(p);\
    else if (p->alloc == ea_malloc) free(p); }
                
#define EA_FREE_CACHE_ENTRY(p) { EACCELERATOR_LOCK_RW();\
    EA_FREE_CACHE_ENTRY_NO_LOCK(p);\
    EACCELERATOR_UNLOCK_RW(); }

// add the given length to the size var and aling it
#define ADDSIZE(size, len) (size) += (len); \
    EA_SIZE_ALIGN(size);

/* refactor todo list 
 * 
 * TODO reintroduce the nreloads variable
 * TODO used entry when adding it to file cache
 * TODO do cache place stuff
 * TODO do cleaning 
 * TODO garbage collection / pruning / malloc2 -> allocation
 * TODO handle return codes in get/put
 * TODO add bit marking
 * TODO handle filename collisions
 * TODO limit access to cache and ht outside ea_cache
 */

#endif /*EA_CACHE_H*/

/*
 * vim: noet tabstop=4 softtabstop=4 shiftwidth=4 expandtab
 */
