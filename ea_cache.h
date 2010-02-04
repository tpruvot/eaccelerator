/*
   +----------------------------------------------------------------------+
   | eAccelerator project                                                 |
   +----------------------------------------------------------------------+
   | Copyright (c) 2004 - 2007 eAccelerator                               |
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

/*
 * An entry in the cache
 */
typedef struct ea_cache_entry {
    struct ea_cache_entry *next;
    ea_alloc_place alloc;       /* allocated by which mem manger     */
    unsigned int hv;            /* hash value                        */
    off_t filesize;             /* file size                         */
    time_t mtime;               /* file last modification time       */
		time_t ts;									/* timestamp of cache entry					 */
    time_t ttl;                 /* expiration time                   */
    size_t size;                /* entry size (bytes)                */
    unsigned int nhits;         /* hits count                        */
    ea_op_array *op_array;      /* script's global scope code        */
    ea_fc_entry *f_head;        /* list of nested functions          */
    ea_fc_entry *c_head;        /* list of nested classes            */
    unsigned int nreloads;      /* count of reloads                  */
    int ref_cnt;                /* how many processes uses the entry */
    void *data;                 /* the data this entry points to     */
		int removed :1;
    char key[1];                /* real file name (must be last el.) */
} ea_cache_entry;

/*
 * Linked list of ea_cache_entry which are used by process/thread
 */
typedef struct _ea_used_entry {
    struct _ea_used_entry *next;
    ea_cache_entry *entry;
} ea_used_entry;

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
} ea_cache_t;

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
 * @param ea_cache_t A pointer to the structure that defines the cache to store the entry in
 * @parma ea_cache_entry A pointer to the entry that needs to be stored in the cache
 */
int ea_cache_put(ea_cache_t *cache, ea_cache_entry *entry);

/**
 * Get an entry from the cache. When the function returns it will increment the 
 * refcount of the entry. Make sure you decrement the refcount when a request is 
 * done otherwise the entry will live forever.
 * 
 * @param ea_cache_t A pointer to the structure that defines the cache to get teh entry from
 * @param char A pointer to the string to lookup the entry in the cache
 * @param void A pointer to the extra data needed by the compare function
 * @return The entry from the cache or null if it's not found
 */
ea_cache_entry *ea_cache_get(ea_cache_t *cache, const char *key, void *data);

/**
 * Initialise a new cache with the given size as the number of initial buckets.
 * 
 * @param size The size of the hashtable
 * @return A newly created cache
 */
ea_cache_t *ea_cache_create(size_t size);

/**
 * Initialise the cache
 */
void ea_cache_init();

/* refactor todo list 
 * 
 * TODO reintroduce the nreloaders variable
 * TODO used entry when adding it to file cache
 * TODO do ttl stuff
 * TODO do cache place stuff
 * TODO do cleaning / garbage collection / pruning
 * TODO handle return codes in get/put
 * TODO add bit marking
 * TODO port shm_api
 * TODO port session_handler
 * TODO port content_cache
 * TODO handle filename collisions
 */

#endif /*EA_CACHE_H*/

/*
 * vim: noet tabstop=2 softtabstop=2 shiftwidth=2
 */
