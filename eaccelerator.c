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
   $Id$
*/

#include "eaccelerator.h"
#include "eaccelerator_version.h"

#ifdef HAVE_EACCELERATOR

#include "opcodes.h"

#include "zend.h"
#include "zend_API.h"
#include "zend_extensions.h"

#include "debug.h"
#include "ea_store.h"
#include "ea_restore.h"
#include "ea_info.h"
#include "ea_dasm.h"
#include "ea_cache.h"

#include <sys/types.h>
#include <sys/stat.h>
#ifdef ZEND_WIN32
#  include "fnmatch.h"
#  include "win32/time.h"
#  include <time.h>
#  include <sys/utime.h>
#else
#  include <fnmatch.h>
#  include <sys/file.h>
#  include <sys/time.h>
#  include <utime.h>
#endif
#include <fcntl.h>

#ifndef O_BINARY
#  define O_BINARY 0
#endif

#include "php.h"
#include "php_ini.h"
#include "php_logos.h"
#include "main/fopen_wrappers.h"
#include "ext/standard/info.h"
#include "ext/standard/php_incomplete_class.h"

#include "SAPI.h"

#define MAX_DUP_STR_LEN 256

/* Globals (different for each process/thread) */
ZEND_DECLARE_MODULE_GLOBALS(eaccelerator)

/* Globals (common for each process/thread) */
static long ea_shm_size = 0;
long ea_shm_max = 0;
static long ea_shm_ttl = 0;
static long ea_shm_prune_period = 0;
extern long ea_debug;
zend_bool ea_scripts_shm_only = 0;

eaccelerator_mm* ea_mm_instance = NULL;
static int ea_is_zend_extension = 0;
static int ea_is_extension      = 0;
zend_extension* ZendOptimizer = NULL;

static HashTable ea_global_function_table;
static HashTable ea_global_class_table;

ea_cache_t *ea_script_cache = NULL;

/* pointer to the properties_info hashtable destructor */
extern dtor_func_t properties_info_dtor;

/* saved original functions */
static zend_op_array *(*ea_saved_zend_compile_file)(zend_file_handle *file_handle, int type TSRMLS_DC);

#ifdef DEBUG
static void (*ea_saved_zend_execute)(zend_op_array *op_array TSRMLS_DC);
#endif

/* external declarations */
PHPAPI void php_stripslashes(char *str, int *len TSRMLS_DC);

ZEND_DLEXPORT zend_op_array* eaccelerator_compile_file(zend_file_handle *file_handle, int type TSRMLS_DC);

static int is_valid_script(ea_cache_entry *script, void *data)
{
	if (((struct stat *)data)->st_mtime != script->mtime || 
			((struct stat *)data)->st_size != script->filesize) {
		return 0;
	}

	return 1;   
}

/* Initialise the shared memory */
static int init_mm(TSRMLS_D) {
  pid_t  owner = getpid();
  MM     *mm;
  size_t total;
  char   mm_path[MAXPATHLEN];

#ifdef ZEND_WIN32
    snprintf(mm_path, MAXPATHLEN, "%s.%s", EACCELERATOR_MM_FILE, sapi_module.name);
#else
    snprintf(mm_path, MAXPATHLEN, "%s.%s%d", EACCELERATOR_MM_FILE, sapi_module.name, owner);
#endif
  
	if ((ea_mm_instance = (eaccelerator_mm*)mm_attach(ea_shm_size*1024*1024, mm_path)) != NULL) {
#ifdef ZTS
    ea_mutex = tsrm_mutex_alloc();
#endif
    return SUCCESS;
  }
  mm = mm_create(ea_shm_size*1024*1024, mm_path);

  if (!mm) {
    return FAILURE;
  }

#ifdef ZEND_WIN32
  DBG(ea_debug_printf, (EA_DEBUG, "init_mm [%d]\n", owner));
#else
  DBG(ea_debug_printf, (EA_DEBUG, "init_mm [%d,%d]\n", owner, getppid()));
#endif

#ifdef ZTS
  ea_mutex = tsrm_mutex_alloc();
#endif
	
  total = mm_available(mm);
  ea_mm_instance = mm_malloc_lock(mm, sizeof(*ea_mm_instance));
  if (!ea_mm_instance) {
    return FAILURE;
  }

  mm_set_attach(mm, ea_mm_instance);
  memset(ea_mm_instance, 0, sizeof(*ea_mm_instance));
  ea_mm_instance->owner = owner;
  ea_mm_instance->mm = mm;
  ea_mm_instance->total = total;
  ea_mm_instance->enabled = 1;
  ea_mm_instance->optimizer_enabled = 1;
  ea_mm_instance->last_prune = time(NULL);	/* this time() call is harmless since this is init phase */

	ea_script_cache = ea_cache_create(EA_HASH_SIZE);
	if (ea_script_cache == NULL) {
		return FAILURE; 
	}
  ea_script_cache->compare_func = is_valid_script;

  EACCELERATOR_PROTECT();
  return SUCCESS;
}

/* Clean up the shared memory */
static void shutdown_mm(TSRMLS_D) {
  if (ea_mm_instance) {
#ifdef ZEND_WIN32
    if (ea_mm_instance->owner == getpid()) {
#else
    if (getpgrp() == getpid()) {
#endif
      MM *mm = ea_mm_instance->mm;
#ifdef ZEND_WIN32
      DBG(ea_debug_printf, (EA_DEBUG, "shutdown_mm [%d]\n", getpid()));
#else
      DBG(ea_debug_printf, (EA_DEBUG, "shutdown_mm [%d,%d]\n", getpid(), getppid()));
#endif
#ifdef ZTS
      tsrm_mutex_free(ea_mutex);
#endif
      if (mm) {
        mm_destroy(mm);
      }
      ea_mm_instance = NULL;
    }
  }
}

/* called after succesful compilation, from eaccelerator_compile file */
/* Adds the data from the compilation of the script to the cache */
static int eaccelerator_store(char* key, struct stat *buf,
												zend_op_array* op_array,
                        Bucket* f, Bucket *c TSRMLS_DC) {
	ea_cache_entry *script;

	int len = strlen(key);
	int use_shm = 1;
	int size = 0;
	int ret = 0;

	// calculate the script size
	zend_try {
		size = calc_size(key, op_array, f, c TSRMLS_CC);
	} zend_catch {
		size =  0;
	} zend_end_try();

	if (size == 0) {
		return 0;
	}

	DBG(ea_debug_pad, (EA_DEBUG TSRMLS_CC));
	DBG(ea_debug_printf, (EA_DEBUG, "[%d] eaccelerator_store:  returned %d, mm=%x\n", getpid(), size, ea_mm_instance->mm));

	script = ea_cache_alloc_entry(size);

	if (script) {
		eaccelerator_store_int(script, key, len, op_array, f, c TSRMLS_CC);

		script->mtime = buf->st_mtime;
		script->ts = EAG(req_start);
		script->filesize = buf->st_size;
		script->size = size;
		script->alloc = (use_shm == 1) ? ea_shared_mem : ea_emalloc;

		EACCELERATOR_PROTECT();

		ret = ea_cache_put(EAG(cache_request), script);

		mm_check_mem((void *)script);

		if (script->alloc == ea_emalloc) {
			efree(script);
		} else {
			EACCELERATOR_PROTECT();
		}
	}
	return ret;
}

/* Try to restore a file from the cache. If the file isn't found in memory, the 
   the disk cache is checked */
static zend_op_array* eaccelerator_restore(char *realname, struct stat *buf,
                                      time_t compile_time TSRMLS_DC) {
	ea_cache_entry *script;
	zend_op_array *op_array = NULL;

  script = ea_cache_get(EAG(cache_request), realname, (void *)buf);

	if (script != NULL && script->op_array != NULL) {
		EAG(class_entry) = NULL;
		op_array = restore_op_array(NULL, script->op_array TSRMLS_CC);
		if (op_array != NULL) {
			ea_fc_entry *e;

			EAG(mem) = op_array->filename;
			/* only restore the classes and functions when we restore this script 
			 * for the first time. 
			 */
			if (!zend_hash_exists(&EAG(restored), script->key, strlen(script->key))) {
				for (e = script->c_head; e!=NULL; e = e->next) {
					restore_class(e TSRMLS_CC);
				}
				for (e = script->f_head; e!=NULL; e = e->next) {
					restore_function(e TSRMLS_CC);
				}
				zend_hash_add(&EAG(restored), script->key, strlen(script->key), NULL, 0, NULL);  
			}
			EAG(mem) = script->key;
		}
#ifdef ZEND_COMPILE_DELAYED_BINDING
		zend_do_delayed_early_binding(op_array TSRMLS_CC);
#endif
	}
	return op_array;
}

/*
 * Returns the realpath for given filename according to include path
 */
static char *ea_resolve_path(const char *filename, int filename_length, const char *path TSRMLS_DC)
{
	char resolved_path[MAXPATHLEN];
	char trypath[MAXPATHLEN];
	const char *ptr, *end, *p;
	char *actual_path;
	php_stream_wrapper *wrapper;

	if (!filename) {
		return NULL;
	}

	/* Don't resolve paths which contain protocol (except of file://) */
	for (p = filename; isalnum((int)*p) || *p == '+' || *p == '-' || *p == '.'; p++);
	if ((*p == ':') && (p - filename > 1) && (p[1] == '/') && (p[2] == '/')) {
		wrapper = php_stream_locate_url_wrapper(filename, &actual_path, STREAM_OPEN_FOR_INCLUDE TSRMLS_CC);
		if (wrapper == &php_plain_files_wrapper) {
			if (tsrm_realpath(actual_path, resolved_path TSRMLS_CC)) {
				return estrdup(resolved_path);
			}
		}
		return NULL;
	}

	if ((*filename == '.' && 
	     (IS_SLASH(filename[1]) || 
	      ((filename[1] == '.') && IS_SLASH(filename[2])))) ||
	    IS_ABSOLUTE_PATH(filename, filename_length) ||
	    !path ||
	    !*path) {
		if (tsrm_realpath(filename, resolved_path TSRMLS_CC)) {
			return estrdup(resolved_path);
		} else {
			return NULL;
		}
	}

	ptr = path;
	while (ptr && *ptr) {
		/* Check for stream wrapper */
		int is_stream_wrapper = 0;

		for (p = ptr; isalnum((int)*p) || *p == '+' || *p == '-' || *p == '.'; p++);
		if ((*p == ':') && (p - ptr > 1) && (p[1] == '/') && (p[2] == '/')) {
			/* .:// or ..:// is not a stream wrapper */
			if (p[-1] != '.' || p[-2] != '.' || p - 2 != ptr) {
				p += 3;
				is_stream_wrapper = 1;
			}
		}
		end = strchr(p, DEFAULT_DIR_SEPARATOR);
		if (end) {
			if ((end-ptr) + 1 + filename_length + 1 >= MAXPATHLEN) {
				ptr = end + 1;
				continue;
			}
			memcpy(trypath, ptr, end-ptr);
			trypath[end-ptr] = '/';
			memcpy(trypath+(end-ptr)+1, filename, filename_length+1);
			ptr = end+1;
		} else {
			int len = strlen(ptr);

			if (len + 1 + filename_length + 1 >= MAXPATHLEN) {
				break;
			}
			memcpy(trypath, ptr, len);
			trypath[len] = '/';
			memcpy(trypath+len+1, filename, filename_length+1);
			ptr = NULL;
		}
		actual_path = trypath;
		if (is_stream_wrapper) {
			wrapper = php_stream_locate_url_wrapper(trypath, &actual_path, STREAM_OPEN_FOR_INCLUDE TSRMLS_CC);
			if (!wrapper) {
				continue;
			} else if (wrapper != &php_plain_files_wrapper) {
				if (wrapper->wops->url_stat) {
					php_stream_statbuf ssb;

					if (SUCCESS == wrapper->wops->url_stat(wrapper, trypath, 0, &ssb, NULL TSRMLS_CC)) {
						return estrdup(trypath);
					}
				}
				continue;
			}
		}
		if (tsrm_realpath(actual_path, resolved_path TSRMLS_CC)) {
			return estrdup(resolved_path);
		}
	} /* end provided path */

	/* check in calling scripts' current working directory as a fall back case
	 */
	if (zend_is_executing(TSRMLS_C)) {
		char *exec_fname = zend_get_executed_filename(TSRMLS_C);
		int exec_fname_length = strlen(exec_fname);

		while ((--exec_fname_length >= 0) && !IS_SLASH(exec_fname[exec_fname_length]));
		if (exec_fname && exec_fname[0] != '[' &&
		    exec_fname_length > 0 &&
		    exec_fname_length + 1 + filename_length + 1 < MAXPATHLEN) {
			memcpy(trypath, exec_fname, exec_fname_length + 1);
			memcpy(trypath+exec_fname_length + 1, filename, filename_length+1);
			actual_path = trypath;

			/* Check for stream wrapper */
			for (p = trypath; isalnum((int)*p) || *p == '+' || *p == '-' || *p == '.'; p++);
			if ((*p == ':') && (p - trypath > 1) && (p[1] == '/') && (p[2] == '/')) {
				wrapper = php_stream_locate_url_wrapper(trypath, &actual_path, STREAM_OPEN_FOR_INCLUDE TSRMLS_CC);
				if (!wrapper) {
					return NULL;
				} else if (wrapper != &php_plain_files_wrapper) {
					if (wrapper->wops->url_stat) {
						php_stream_statbuf ssb;

						if (SUCCESS == wrapper->wops->url_stat(wrapper, trypath, 0, &ssb, NULL TSRMLS_CC)) {
							return estrdup(trypath);
						}
					}
					return NULL;
				}
			}

			if (tsrm_realpath(actual_path, resolved_path TSRMLS_CC)) {
				return estrdup(resolved_path);
			}
		}
	}

	return NULL;
}

/**
 * Get the real filename of the file represented by the given file_handle.
 * If unable to determine the realfilename this function returns 0, otherwise
 * it returns 1.
 *
 * realfilename should be MAXPATHLEN long.
 */
static int ea_get_realname(zend_file_handle *file_handle, char* realname TSRMLS_DC) {
	// at least one of these should have value
  if (file_handle->opened_path == NULL && file_handle->filename == NULL) {
		return 0;
	}

	if (file_handle->opened_path != NULL) {
		strcpy(realname, file_handle->opened_path);
		return 1;
	}

	if (PG(include_path) == NULL || 
			file_handle->filename[0] == '.' ||
      IS_SLASH(file_handle->filename[0]) ||
      IS_ABSOLUTE_PATH(file_handle->filename, strlen(file_handle->filename))) {
    
		return VCWD_REALPATH(file_handle->filename, realname) != NULL;
	} else {
    int filename_len = strlen(file_handle->filename);
		char* temp_name = ea_resolve_path(file_handle->filename, filename_len, PG(include_path) TSRMLS_CC);

		if (temp_name == NULL) {
			return 0;
		}

		strcpy(realname, temp_name);
		efree(temp_name);
		return 1;
	}

	return 0;
}

static int ea_get_phar_name(const char* filename, size_t filename_len, char* phar_name) {
	size_t i = 0;

	for (i = sizeof("phar://"); i < filename_len - sizeof(".phar"); ++i) {
		if (filename[i] == '.' && filename[i + 1] == 'p' && filename[i + 2] == 'h' &&
				filename[i + 3] == 'a' && filename[i + 4] == 'r') {
			int copy_len = (i - sizeof("phar://") + sizeof(".phar"));
			if (copy_len >= MAXPATHLEN - 1) {
				return 0;
			}
			memcpy(phar_name, &filename[sizeof("phar://") - 1], copy_len);
			phar_name[copy_len] = '\0';
			return 1;
		}
	}
	return 0;
}

/* 
 * Stat the file that belongs to file_handle. It puts result of the stat call
 * in buf and the real filename in realname.
 *
 * Returns 0 when the stat failed or if unable to perform a stat call. If successful
 * it returns 1
 */
static int eaccelerator_stat(zend_file_handle *file_handle,
                        char* realname, struct stat* buf TSRMLS_DC) {
	if (!ea_get_realname(file_handle, realname TSRMLS_CC)) {
#ifdef ZEND_ENGINE_2_3
		if (strncmp(file_handle->filename, "phar://", sizeof("phar://"))) {
			// Determine the name of the phar archive and use this filename to do the
			// stat call. Return filename as realname.
			char phar_name[MAXPATHLEN];
			size_t filename_len = strlen(file_handle->filename);

			if (!ea_get_phar_name(file_handle->filename, filename_len, phar_name)) {
				return 0;
			}
			// TODO: resolve this problem
			if (filename_len >= MAXPATHLEN) {
				return 0;
			}
			strcpy(realname, file_handle->filename);
		  return (stat(phar_name, buf) == 0 && S_ISREG(buf->st_mode));
		}
#endif
		return 0;
	}

	return (stat(realname, buf) == 0 && S_ISREG(buf->st_mode));
}

static int ea_match(struct ea_pattern_t *list, const char *path)
{
	struct ea_pattern_t *p;
	char result, positive;

	// apply all patterns
	//  - when not patterns are given, *accept*
	//  - when a pattern with a ! matches, *reject*
	//  - when no negative pattern matches and a positive pattern match, *accept*
	//  - when no negative pattern matches and there are no possitive patterns, *accept*
	//  - *reject*

	if (list == NULL) {
		// there are no patterns, accept
		return 1;
	}

	result = 0; // there are patterns, so if no positive pattern matches, reject
	positive = 0;
	p = list;
	while (p != NULL) {
		if (p->pattern[0] == '!') {
			if ((fnmatch((const char *)(p->pattern + 1), path, 0) == 0)) {
				// a negative pattern matches, accept
				return 0;
			}
		} else {
			result |= (fnmatch((const char *)p->pattern, path, 0) == 0);
			positive = 1;
		}
		p = p->next;
	}

  return result | !positive;
}

/* copy of zend_class_add_ref, the linker isn't able to link to it any more
 * in php 5.3
 * TODO: see if we can steal the pointer
 */
void ea_class_add_ref(zend_class_entry **ce)
{
	(*ce)->refcount++;
}

/*
 * Intercept compilation of PHP file.  If we already have the file in
 * our cache, restore it.  Otherwise call the original Zend compilation
 * function and store the compiled zend_op_array in out cache.
 * This function is called again for each PHP file included in the
 * main PHP file.
 */
ZEND_DLEXPORT zend_op_array* eaccelerator_compile_file(zend_file_handle *file_handle, int type TSRMLS_DC) {
  zend_op_array *t;
  struct stat buf;
  char  realname[MAXPATHLEN];
  int stat_result = 0;
#ifdef DEBUG
  struct timeval tv_start;
#endif
  int ok_to_cache = 0;
#ifdef ZEND_ENGINE_2_3
  zend_uint orig_compiler_options;
#endif

  DBG(ea_debug_start_time, (&tv_start));
  DBG(ea_debug_printf, (EA_DEBUG, "[%d] Enter COMPILE\n",getpid()));
  DBG(ea_debug_printf, (EA_DEBUG, "[%d] compile_file: \"%s\"\n",getpid(), file_handle->filename));
#ifdef DEBUG
  EAG(xpad)+=2;
#endif

  stat_result = eaccelerator_stat(file_handle, realname, &buf TSRMLS_CC);

  ok_to_cache = ea_match(EAG(pattern_list), file_handle->filename);

  // eAccelerator isn't working, so just compile the file
  if (!EAG(enabled) || (ea_mm_instance == NULL) || 
      !ea_mm_instance->enabled || file_handle == NULL ||
      file_handle->filename == NULL || stat_result == 0 || !ok_to_cache) {
    DBG(ea_debug_printf, (EA_DEBUG, "\t[%d] compile_file: compiling\n", getpid()));
    t = ea_saved_zend_compile_file(file_handle, type TSRMLS_CC);
    DBG(ea_debug_printf, (EA_TEST_PERFORMANCE, "\t[%d] compile_file: end (%ld)\n", getpid(), ea_debug_elapsed_time(&tv_start)));
    DBG(ea_debug_printf, (EA_DEBUG, "\t[%d] compile_file: end\n", getpid()));
#ifdef DEBUG
    EAG(xpad)-=2;
#endif
    DBG(ea_debug_printf, (EA_DEBUG, "[%d] Leave COMPILE\n", getpid()));
    return t;
  }

  /* only restore file when open_basedir allows it */
  if (PG(open_basedir) && php_check_open_basedir(realname TSRMLS_CC)) {
    zend_error(E_ERROR, "Can't load %s, open_basedir restriction.", file_handle->filename);
  }

  if (buf.st_mtime >= EAG(req_start) && ea_debug > 0) {
		ea_debug_log("EACCELERATOR: Warning: \"%s\" is cached but it's mtime is in the future.\n", file_handle->filename);
  }

  t = eaccelerator_restore(realname, &buf, EAG(req_start) TSRMLS_CC);

// segv74: really cheap work around to auto_global problem.
//         it makes just in time to every time.
  zend_is_auto_global("_GET", sizeof("_GET")-1 TSRMLS_CC);
  zend_is_auto_global("_POST", sizeof("_POST")-1 TSRMLS_CC);
  zend_is_auto_global("_COOKIE", sizeof("_COOKIE")-1 TSRMLS_CC);
  zend_is_auto_global("_SERVER", sizeof("_SERVER")-1 TSRMLS_CC);
  zend_is_auto_global("_ENV", sizeof("_ENV")-1 TSRMLS_CC);
  zend_is_auto_global("_REQUEST", sizeof("_REQUEST")-1 TSRMLS_CC);
  zend_is_auto_global("_FILES", sizeof("_FILES")-1 TSRMLS_CC);

  if (t != NULL) { // restore from cache
#ifdef DEBUG
    ea_debug_log("[%d] EACCELERATOR hit: \"%s\"\n", getpid(), t->filename);
#else
    ea_debug_log("EACCELERATOR hit: \"%s\"\n", t->filename);
#endif

    zend_llist_add_element(&CG(open_files), file_handle);
    if (file_handle->opened_path == NULL && file_handle->type != ZEND_HANDLE_STREAM) {
      file_handle->handle.stream.handle = (void*)1;
      file_handle->opened_path = EAG(mem);	/* EAG(mem) = p->realfilename from eaccelerator_restore here */
    }

    DBG(ea_debug_printf, (EA_TEST_PERFORMANCE, "\t[%d] compile_file: restored (%ld)\n", getpid(), ea_debug_elapsed_time(&tv_start)));
    DBG(ea_debug_printf, (EA_DEBUG, "\t[%d] compile_file: restored\n", getpid()));
#ifdef DEBUG
    EAG(xpad)-=2;
#endif
    DBG(ea_debug_printf, (EA_DEBUG, "[%d] Leave COMPILE\n", getpid()));

    return t;

  } else { // not in cache or must be recompiled
		Bucket *function_table_tail;
		Bucket *class_table_tail;
		HashTable* orig_function_table;
		HashTable* orig_class_table;
		HashTable* orig_eg_class_table = NULL;
		HashTable tmp_function_table;
		HashTable tmp_class_table;
		zend_function tmp_func;
		zend_class_entry tmp_class;
		int ea_bailout;

#ifdef DEBUG
    ea_debug_printf(EA_DEBUG, "\t[%d] compile_file: marking\n", getpid());
    if (CG(class_table) != EG(class_table)) {
      ea_debug_printf(EA_DEBUG, "\t[%d] oops, CG(class_table)[%08x] != EG(class_table)[%08x]\n", getpid(), CG(class_table), EG(class_table));
      ea_debug_log_hashkeys("CG(class_table)\n", CG(class_table));
      ea_debug_log_hashkeys("EG(class_table)\n", EG(class_table));
    } else {
      ea_debug_printf(EA_DEBUG, "\t[%d] OKAY. That what I thought, CG(class_table)[%08x] == EG(class_table)[%08x]\n", getpid(), CG(class_table), EG(class_table));
      ea_debug_log_hashkeys("CG(class_table)\n", CG(class_table));
    }
#endif

    zend_hash_init_ex(&tmp_function_table, 100, NULL, ZEND_FUNCTION_DTOR, 1, 0);
    zend_hash_copy(&tmp_function_table, &ea_global_function_table, NULL, &tmp_func, sizeof(zend_function));
    orig_function_table = CG(function_table);
    CG(function_table) = &tmp_function_table;

    zend_hash_init_ex(&tmp_class_table, 10, NULL, ZEND_CLASS_DTOR, 1, 0);
		zend_hash_copy(&tmp_class_table, &ea_global_class_table, (copy_ctor_func_t)ea_class_add_ref, &tmp_class, sizeof(zend_class_entry *));

    orig_class_table = CG(class_table);;
    CG(class_table) = &tmp_class_table;
    orig_eg_class_table = EG(class_table);;
    EG(class_table) = &tmp_class_table;

    /* Storing global pre-compiled functions and classes */
    function_table_tail = CG(function_table)->pListTail;
    class_table_tail = CG(class_table)->pListTail;

    DBG(ea_debug_printf, (EA_TEST_PERFORMANCE, "\t[%d] compile_file: compiling (%ld)\n", getpid(), ea_debug_elapsed_time(&tv_start)));
    
		if (EAG(optimizer_enabled) && ea_mm_instance->optimizer_enabled) {
			EAG(compiler) = 1;
		}

	/* try to compile the script */
    ea_bailout = 0;
    zend_try {
#ifdef ZEND_ENGINE_2_3
      orig_compiler_options = CG(compiler_options);
      CG(compiler_options) |= ZEND_COMPILE_IGNORE_INTERNAL_CLASSES | ZEND_COMPILE_DELAYED_BINDING;  
#endif
      t = ea_saved_zend_compile_file(file_handle, type TSRMLS_CC);
#ifdef ZEND_ENGINE_2_3
      CG(compiler_options) = orig_compiler_options;
#endif
    } zend_catch {
      CG(function_table) = orig_function_table;
      CG(class_table) = orig_class_table;
      EG(class_table) = orig_eg_class_table;
      ea_bailout = 1;
    } zend_end_try();
    if (ea_bailout) {
      zend_bailout();
    }
    DBG(ea_debug_log_hashkeys, ("class_table\n", CG(class_table)));

    EAG(compiler) = 0;
    if (t != NULL && file_handle->opened_path != NULL && 
         ((stat(file_handle->opened_path, &buf) == 0) && S_ISREG(buf.st_mode))) {

      DBG(ea_debug_printf, (EA_TEST_PERFORMANCE, "\t[%d] compile_file: storing in cache (%ld)\n", getpid(), ea_debug_elapsed_time(&tv_start)));
      DBG(ea_debug_printf, (EA_DEBUG, "\t[%d] compile_file: storing in cache\n", getpid()));
      function_table_tail = function_table_tail ? function_table_tail->pListNext : CG(function_table)->pListHead;
      class_table_tail = class_table_tail ? class_table_tail->pListNext : CG(class_table)->pListHead;

      if (eaccelerator_store(file_handle->opened_path, &buf, t, function_table_tail, class_table_tail TSRMLS_CC)) {
#ifdef DEBUG
        ea_debug_log("[%d] EACCELERATOR cached: \"%s\"\n", getpid(), file_handle->opened_path);
#else
        ea_debug_log("EACCELERATOR cached: \"%s\"\n", file_handle->opened_path);
#endif
      } else {
#ifdef DEBUG
        ea_debug_log("[%d] EACCELERATOR can't cache: \"%s\"\n", getpid(), file_handle->opened_path);
#else
        ea_debug_log("EACCELERATOR can't cache: \"%s\"\n", file_handle->opened_path);
#endif
      }
    } else {
      function_table_tail = function_table_tail ? function_table_tail->pListNext : CG(function_table)->pListHead;
      class_table_tail = class_table_tail ? class_table_tail->pListNext : CG(class_table)->pListHead;
    }
    CG(function_table) = orig_function_table;
    CG(class_table) = orig_class_table;
    EG(class_table) = orig_eg_class_table;
    DBG(ea_debug_printf, (EA_DEBUG, "\t[%d] restoring CG(class_table)[%08x] != EG(class_table)[%08x]\n", 
                getpid(), CG(class_table), EG(class_table)));
    while (function_table_tail != NULL) {
      zend_op_array *op_array = (zend_op_array*)function_table_tail->pData;
      if (op_array->type == ZEND_USER_FUNCTION) {
        if (zend_hash_add(CG(function_table), function_table_tail->arKey, function_table_tail->nKeyLength, op_array, 
                    sizeof(zend_op_array), NULL) == FAILURE && function_table_tail->arKey[0] != '\000') {
          CG(in_compilation) = 1;
          CG(compiled_filename) = file_handle->opened_path;
          CG(zend_lineno) = op_array->line_start;
          zend_error(E_ERROR, "Cannot redeclare %s()", function_table_tail->arKey);
        }
      }
      function_table_tail = function_table_tail->pListNext;
    }
    while (class_table_tail != NULL) {
      zend_class_entry **ce = (zend_class_entry**)class_table_tail->pData;
      if ((*ce)->type == ZEND_USER_CLASS) {
        if (zend_hash_add(CG(class_table), class_table_tail->arKey, class_table_tail->nKeyLength, 
                    ce, sizeof(zend_class_entry*), NULL) == FAILURE && class_table_tail->arKey[0] != '\000') {
          CG(in_compilation) = 1;
          CG(compiled_filename) = file_handle->opened_path;
          CG(zend_lineno) = (*ce)->line_start;
          zend_error(E_ERROR, "Cannot redeclare class %s", class_table_tail->arKey);
        }
      }
      class_table_tail = class_table_tail->pListNext;
    }
    tmp_function_table.pDestructor = NULL;
    tmp_class_table.pDestructor = NULL;
    zend_hash_destroy(&tmp_function_table);
    zend_hash_destroy(&tmp_class_table);
  }
  DBG(ea_debug_printf, (EA_TEST_PERFORMANCE, "\t[%d] compile_file: end (%ld)\n", getpid(), ea_debug_elapsed_time(&tv_start)));
  DBG(ea_debug_printf, (EA_DEBUG, "\t[%d] compile_file: end\n", getpid()));
#ifdef DEBUG
  EAG(xpad)-=2;
#endif
  DBG(ea_debug_printf, (EA_DEBUG, "[%d] Leave COMPILE\n", getpid()));
  #ifdef ZEND_COMPILE_DELAYED_BINDING
      zend_do_delayed_early_binding(t TSRMLS_CC);
  #endif
  return t;
}

#ifdef DEBUG
static void profile_execute(zend_op_array *op_array TSRMLS_DC)
{
  int i;
  struct timeval tv_start;
  long usec;

  for (i=0;i<EAG(profile_level);i++)
    DBG(ea_debug_put, (EA_PROFILE_OPCODES, "  "));
  ea_debug_printf(EA_PROFILE_OPCODES, "enter profile_execute: %s:%s\n", op_array->filename, op_array->function_name);
  ea_debug_start_time(&tv_start);
  EAG(self_time)[EAG(profile_level)] = 0;
  EAG(profile_level)++;
  ea_debug_printf(EA_PROFILE_OPCODES, "About to enter zend_execute...\n");
  ea_saved_zend_execute(op_array TSRMLS_CC);
  ea_debug_printf(EA_PROFILE_OPCODES, "Finished zend_execute...\n");
  usec = ea_debug_elapsed_time(&tv_start);
  EAG(profile_level)--;
  if (EAG(profile_level) > 0)
    EAG(self_time)[EAG(profile_level)-1] += usec;
  for (i=0;i<EAG(profile_level);i++)
    DBG(ea_debug_put, (EA_PROFILE_OPCODES, "  "));
  ea_debug_printf(EA_PROFILE_OPCODES, "leave profile_execute: %s:%s (%ld,%ld)\n", op_array->filename, op_array->function_name, usec, usec-EAG(self_time)[EAG(profile_level)]);
}

ZEND_DLEXPORT zend_op_array* profile_compile_file(zend_file_handle *file_handle, int type TSRMLS_DC) {
  zend_op_array *t;
  int i;
  struct timeval tv_start;
  long usec;

  ea_debug_start_time(&tv_start);
  EAG(self_time)[EAG(profile_level)] = 0;
  t = eaccelerator_compile_file(file_handle, type TSRMLS_CC);
  usec = ea_debug_elapsed_time(&tv_start);
  if (EAG(profile_level) > 0)
    EAG(self_time)[EAG(profile_level)-1] += usec;
  for (i=0;i<EAG(profile_level);i++)
    DBG(ea_debug_put, (EA_PROFILE_OPCODES, "  "));
  return t;
}

#endif  /* DEBUG */

/* Format Bytes */
void format_size(char* s, unsigned int size, int legend) {
  unsigned int i = 0;
  unsigned int n = 0;
  char ch;
  do {
    if ((n != 0) && (n % 3 == 0)) {
      s[i++] = ',';
    }
    s[i++] = (char)((int)'0' + (size % 10));
    n++;
    size = size / 10;
  } while (size != 0);
  s[i] = '\0';
  n = 0; i--;
  while (n < i) {
    ch = s[n];
    s[n] = s[i];
    s[i] = ch;
    n++, i--;
  }
  if (legend) {
    strcat(s, " Bytes");
  }
}

/* eAccelerator entry for phpinfo() */
PHP_MINFO_FUNCTION(eaccelerator) {
  char s[32];

  php_info_print_table_start();
  php_info_print_table_header(2, "eAccelerator support", "enabled");
  php_info_print_table_row(2, "Version", EACCELERATOR_VERSION);
  php_info_print_table_row(2, "Caching Enabled", (EAG(enabled) && (ea_mm_instance != NULL) && 
              ea_mm_instance->enabled)?"true":"false");
  php_info_print_table_row(2, "Optimizer Enabled", (EAG(optimizer_enabled) && 
							(ea_mm_instance != NULL) && ea_mm_instance->optimizer_enabled)?"true":"false");
  if (ea_mm_instance != NULL) {
    size_t available;
    EACCELERATOR_UNPROTECT();
    available = mm_available(ea_mm_instance->mm);
    EACCELERATOR_LOCK_RD();
    EACCELERATOR_PROTECT();
    format_size(s, ea_mm_instance->total, 1);
    php_info_print_table_row(2, "Memory Size", s);
    format_size(s, available, 1);
    php_info_print_table_row(2, "Memory Available", s);
    format_size(s, ea_mm_instance->total - available, 1);
    php_info_print_table_row(2, "Memory Allocated", s);
    snprintf(s, 32, "%u", ea_script_cache->ht->elements);
    php_info_print_table_row(2, "Cached Scripts", s);
    EACCELERATOR_UNPROTECT();
    EACCELERATOR_UNLOCK_RD();
    EACCELERATOR_PROTECT();
  }
  php_info_print_table_end();

  DISPLAY_INI_ENTRIES();
}

/* 
 * Parse a list of filters which is seperated by a " "
 */
static struct ea_pattern_t *ea_parse_filter(char *filter)
{
	char *saveptr = NULL, *token = NULL;
	struct ea_pattern_t *list_head = NULL, *p = NULL;
	size_t len;

	// tokenize the filter string on a space
	while ((token = php_strtok_r(filter, " ", &saveptr)) != NULL) {
		filter = NULL;
		list_head = malloc(sizeof(struct ea_pattern_t));
		memset(list_head, 0, sizeof(struct ea_pattern_t));

		len = strlen(token);
		list_head->pattern = malloc(len + 1);
		strncpy(list_head->pattern, token, len + 1); 
		list_head->next = p;
		p = list_head;
	}

	return list_head;
}

/******************************************************************************/
/*
 * Begin of dynamic loadable module interfaces.
 * There are two interfaces:
 *  - standard php module,
 *  - zend extension.
 */
PHP_INI_MH(eaccelerator_filter) {
  EAG(pattern_list) = ea_parse_filter(new_value);
  return SUCCESS;
}

static PHP_INI_MH(eaccelerator_OnUpdateLong) {
  long *p = (long*)mh_arg1;
  *p = zend_atoi(new_value, new_value_length);
  return SUCCESS;
}

static PHP_INI_MH(eaccelerator_OnUpdateBool) {
  zend_bool *p = (zend_bool*)mh_arg1;
  if (strncasecmp("on", new_value, sizeof("on"))) {
    *p = (zend_bool) atoi(new_value);
  } else {
    *p = (zend_bool) 1;
  }
  return SUCCESS;
}

PHP_INI_BEGIN()
STD_PHP_INI_ENTRY("eaccelerator.enable",        "1", PHP_INI_ALL, OnUpdateBool, enabled, zend_eaccelerator_globals, eaccelerator_globals)
STD_PHP_INI_ENTRY("eaccelerator.optimizer",     "1", PHP_INI_ALL, OnUpdateBool, optimizer_enabled, zend_eaccelerator_globals, eaccelerator_globals)
ZEND_INI_ENTRY1("eaccelerator.shm_size",        "0", PHP_INI_SYSTEM, eaccelerator_OnUpdateLong, &ea_shm_size)
ZEND_INI_ENTRY1("eaccelerator.shm_max",         "0", PHP_INI_SYSTEM, eaccelerator_OnUpdateLong, &ea_shm_max)
ZEND_INI_ENTRY1("eaccelerator.shm_ttl",         "0", PHP_INI_SYSTEM, eaccelerator_OnUpdateLong, &ea_shm_ttl)
ZEND_INI_ENTRY1("eaccelerator.shm_prune_period", "0", PHP_INI_SYSTEM, eaccelerator_OnUpdateLong, &ea_shm_prune_period)
ZEND_INI_ENTRY1("eaccelerator.debug",           "1", PHP_INI_SYSTEM, eaccelerator_OnUpdateLong, &ea_debug)
STD_PHP_INI_ENTRY("eaccelerator.log_file",      "", PHP_INI_SYSTEM, OnUpdateString, ea_log_file, zend_eaccelerator_globals, eaccelerator_globals)
ZEND_INI_ENTRY1("eaccelerator.shm_only",        "0", PHP_INI_SYSTEM, eaccelerator_OnUpdateBool, &ea_scripts_shm_only)
#ifdef WITH_EACCELERATOR_INFO
STD_PHP_INI_ENTRY("eaccelerator.allowed_admin_path",       "", PHP_INI_SYSTEM, OnUpdateString, allowed_admin_path, zend_eaccelerator_globals, eaccelerator_globals)
#endif
STD_PHP_INI_ENTRY("eaccelerator.cache_dir",      "/tmp/eaccelerator", PHP_INI_SYSTEM, OnUpdateString, cache_dir, zend_eaccelerator_globals, eaccelerator_globals)
PHP_INI_ENTRY("eaccelerator.filter",             "",  PHP_INI_ALL, eaccelerator_filter)
PHP_INI_END()

/* signal handlers */
#ifdef WITH_EACCELERATOR_CRASH_DETECTION
static void eaccelerator_crash_handler(int dummy) {
  struct tm *loctime;

  TSRMLS_FETCH();
  fflush(stdout);
  fflush(stderr);
#ifdef SIGSEGV
  if (EAG(original_sigsegv_handler) != eaccelerator_crash_handler) {
    signal(SIGSEGV, EAG(original_sigsegv_handler));
  } else {
    signal(SIGSEGV, SIG_DFL);
  }
#endif
#ifdef SIGFPE
  if (EAG(original_sigfpe_handler) != eaccelerator_crash_handler) {
    signal(SIGFPE, EAG(original_sigfpe_handler));
  } else {
    signal(SIGFPE, SIG_DFL);
  }
#endif
#ifdef SIGBUS
  if (EAG(original_sigbus_handler) != eaccelerator_crash_handler) {
    signal(SIGBUS, EAG(original_sigbus_handler));
  } else {
    signal(SIGBUS, SIG_DFL);
  }
#endif
#ifdef SIGILL
  if (EAG(original_sigill_handler) != eaccelerator_crash_handler) {
    signal(SIGILL, EAG(original_sigill_handler));
  } else {
    signal(SIGILL, SIG_DFL);
  }
#endif
#ifdef SIGABRT
  if (EAG(original_sigabrt_handler) != eaccelerator_crash_handler) {
    signal(SIGABRT, EAG(original_sigabrt_handler));
  } else {
    signal(SIGABRT, SIG_DFL);
  }
#endif
  ea_cache_rshutdown(EAG(cache_request));

  loctime = localtime(&EAG(req_start));

  if (EG(active_op_array)) {
    fprintf(stderr, "[%s] [notice] EACCELERATOR(%d): PHP crashed on opline %ld of %s() at %s:%u\n\n",
      asctime(loctime),
      getpid(),
      (long)(active_opline-EG(active_op_array)->opcodes),
      get_active_function_name(TSRMLS_C),
      zend_get_executed_filename(TSRMLS_C),
      zend_get_executed_lineno(TSRMLS_C));
  } else {
    fprintf(stderr, "[%s] [notice] EACCELERATOR(%d): PHP crashed\n\n", asctime(loctime), getpid());
  }
#if !defined(WIN32) && !defined(NETWARE)
  kill(getpid(), dummy);
#else
  raise(dummy);
#endif
}
#endif

static void eaccelerator_init_globals(zend_eaccelerator_globals *eag)
{
	eag->enabled = 1;
	eag->cache_dir = NULL;
	eag->optimizer_enabled = 1;
	eag->compiler = 0;
	eag->ea_log_file = '\000';
	eag->in_request = 0;
	eag->allowed_admin_path= NULL;
	eag->pattern_list = NULL;
}

static void eaccelerator_globals_dtor(zend_eaccelerator_globals *eag)
{
	struct ea_pattern_t *p, *q;

	/* free the list of patterns */
	p = eag->pattern_list;
	while (p != NULL) {
		q = p;
		free(p->pattern);
		free(p);
		p = q->next;
	}
	eag->pattern_list = NULL;
}

static void register_eaccelerator_as_zend_extension();

static int eaccelerator_check_php_version(TSRMLS_D) {
  zval v;
  int ret = 0;
  if (zend_get_constant("PHP_VERSION", sizeof("PHP_VERSION")-1, &v TSRMLS_CC)) {
    if (Z_TYPE(v) == IS_STRING &&
        Z_STRLEN(v) == sizeof(PHP_VERSION)-1 &&
        strcmp(Z_STRVAL(v),PHP_VERSION) == 0) {
      ret = 1;
    } else {
      ea_debug_error("[%s] This build of \"%s\" was compiled for PHP version %s. Rebuild it for your PHP version (%s) or download precompiled binaries.\n", 
					EACCELERATOR_EXTENSION_NAME, EACCELERATOR_EXTENSION_NAME,PHP_VERSION,Z_STRVAL(v));
    }
    zval_dtor(&v);
  } else {
    ea_debug_error("[%s] This build of \"%s\" was compiled for PHP version %s. Rebuild it for your PHP version.\n",
				EACCELERATOR_EXTENSION_NAME, EACCELERATOR_EXTENSION_NAME, PHP_VERSION);
  }
  return ret;
}

PHP_MINIT_FUNCTION(eaccelerator) {
  char fullpath[MAXPATHLEN];

  if (type == MODULE_PERSISTENT) {
#ifndef ZEND_WIN32
    if (strcmp(sapi_module.name,"apache") == 0) {
      if (getpid() != getpgrp()) {
        return SUCCESS;
      }
    }
#endif
  }
  if (!eaccelerator_check_php_version(TSRMLS_C)) {
    /* 
		 * do not return FAILURE, because it causes PHP to completely fail.
		 * Just disable eAccelerator instead of making eA fail starting php
		 */
    return SUCCESS;
  }
  ZEND_INIT_MODULE_GLOBALS(eaccelerator, eaccelerator_init_globals, NULL);
  REGISTER_INI_ENTRIES();
  REGISTER_STRING_CONSTANT("EACCELERATOR_VERSION", EACCELERATOR_VERSION, CONST_CS | CONST_PERSISTENT);
  REGISTER_LONG_CONSTANT("EACCELERATOR_SHM_AND_DISK", ea_shm_and_disk, CONST_CS | CONST_PERSISTENT);
  REGISTER_LONG_CONSTANT("EACCELERATOR_SHM", ea_shm, CONST_CS | CONST_PERSISTENT);
  REGISTER_LONG_CONSTANT("EACCELERATOR_SHM_ONLY", ea_shm_only, CONST_CS | CONST_PERSISTENT);
  REGISTER_LONG_CONSTANT("EACCELERATOR_DISK_ONLY", ea_disk_only, CONST_CS | CONST_PERSISTENT);
  REGISTER_LONG_CONSTANT("EACCELERATOR_NONE", ea_none, CONST_CS | CONST_PERSISTENT);
  ea_is_extension = 1;

  ea_debug_init(TSRMLS_C);
	ea_cache_init();

  if (type == MODULE_PERSISTENT &&
      strcmp(sapi_module.name, "cgi") != 0 &&
      strcmp(sapi_module.name, "cli") != 0) {
    DBG(ea_debug_put, (EA_DEBUG, "\n=======================================\n"));
    DBG(ea_debug_printf, (EA_DEBUG, "[%d] EACCELERATOR STARTED\n", getpid()));
    DBG(ea_debug_put, (EA_DEBUG, "=======================================\n"));

    if (init_mm(TSRMLS_C) == FAILURE) {
      zend_error(E_CORE_WARNING,"[%s] Can not create shared memory area", EACCELERATOR_EXTENSION_NAME);
      return FAILURE;
    }
    ea_saved_zend_compile_file = zend_compile_file;

#ifdef DEBUG
    zend_compile_file = profile_compile_file;
    ea_saved_zend_execute = zend_execute;
    zend_execute = profile_execute;
#else
    zend_compile_file = eaccelerator_compile_file;
#endif
  }
  
  if (!ea_is_zend_extension) {
    register_eaccelerator_as_zend_extension();
  }
  
  /* cache the properties_info destructor */
  properties_info_dtor = get_zend_destroy_property_info(TSRMLS_C);
  return SUCCESS;
}

PHP_MSHUTDOWN_FUNCTION(eaccelerator) {
  if (ea_mm_instance == NULL || !ea_is_extension) {
    return SUCCESS;
  }
  zend_compile_file = ea_saved_zend_compile_file;
  shutdown_mm(TSRMLS_C);
  DBG(ea_debug_put, (EA_DEBUG, "========================================\n"));
  DBG(ea_debug_printf, (EA_DEBUG, "[%d] EACCELERATOR STOPPED\n", getpid()));
  DBG(ea_debug_put, (EA_DEBUG, "========================================\n\n"));
  ea_debug_shutdown();
  UNREGISTER_INI_ENTRIES();
#ifdef ZTS
  ts_free_id(eaccelerator_globals_id);
#else
  eaccelerator_globals_dtor(&eaccelerator_globals TSRMLS_CC);
#endif
  ea_is_zend_extension = 0;
  ea_is_extension = 0;
  return SUCCESS;
}

PHP_RINIT_FUNCTION(eaccelerator)
{
	if (ea_mm_instance == NULL) {
		return SUCCESS;
	}

	DBG(ea_debug_printf, (EA_DEBUG, "[%d] Enter RINIT\n",getpid()));
	DBG(ea_debug_put, (EA_PROFILE_OPCODES, "\n========================================\n"));

	EAG(cache_request) = ea_cache_rinit(ea_script_cache);

	EAG(in_request) = 1;
	EAG(compiler) = 0;
	EAG(refcount_helper) = 1;
	EAG(req_start) = sapi_get_request_time(TSRMLS_C);	/* record request start time for later use */

	zend_hash_init(&EAG(restored), 0, NULL, NULL, 0);

#ifdef DEBUG
	EAG(xpad) = 0;
	EAG(profile_level) = 0;
#endif

/*
#ifdef WITH_EACCELERATOR_CRASH_DETECTION
#ifdef SIGSEGV
	EAG(original_sigsegv_handler) = signal(SIGSEGV, eaccelerator_crash_handler);
#endif
#ifdef SIGFPE
	EAG(original_sigfpe_handler) = signal(SIGFPE, eaccelerator_crash_handler);
#endif
#ifdef SIGBUS
	EAG(original_sigbus_handler) = signal(SIGBUS, eaccelerator_crash_handler);
#endif
#ifdef SIGILL
	EAG(original_sigill_handler) = signal(SIGILL, eaccelerator_crash_handler);
#endif
#ifdef SIGABRT
	EAG(original_sigabrt_handler) = signal(SIGABRT, eaccelerator_crash_handler);
#endif
#endif*/

	DBG(ea_debug_printf, (EA_DEBUG, "[%d] Leave RINIT\n",getpid()));
	
	return SUCCESS;
}

PHP_RSHUTDOWN_FUNCTION(eaccelerator)
{
	if (ea_mm_instance == NULL) {
		return SUCCESS;
	}
	zend_hash_destroy(&EAG(restored));
#ifdef WITH_EACCELERATOR_CRASH_DETECTION
#ifdef SIGSEGV
	if (EAG(original_sigsegv_handler) != eaccelerator_crash_handler) {
		signal(SIGSEGV, EAG(original_sigsegv_handler));
	} else {
		signal(SIGSEGV, SIG_DFL);
	}
#endif
#ifdef SIGFPE
	if (EAG(original_sigfpe_handler) != eaccelerator_crash_handler) {
		signal(SIGFPE, EAG(original_sigfpe_handler));
	} else {
		signal(SIGFPE, SIG_DFL);
	}
#endif
#ifdef SIGBUS
	if (EAG(original_sigbus_handler) != eaccelerator_crash_handler) {
		signal(SIGBUS, EAG(original_sigbus_handler));
	} else {
		signal(SIGBUS, SIG_DFL);
	}
#endif
#ifdef SIGILL
	if (EAG(original_sigill_handler) != eaccelerator_crash_handler) {
		signal(SIGILL, EAG(original_sigill_handler));
	} else {
		signal(SIGILL, SIG_DFL);
	}
#endif
#ifdef SIGABRT
	if (EAG(original_sigabrt_handler) != eaccelerator_crash_handler) {
		signal(SIGABRT, EAG(original_sigabrt_handler));
	} else {
		signal(SIGABRT, SIG_DFL);
	}
#endif
#endif
	DBG(ea_debug_printf, (EA_DEBUG, "[%d] Enter RSHUTDOWN\n",getpid()));
	ea_cache_rshutdown(EAG(cache_request));
	EAG(in_request) = 0;
	DBG(ea_debug_printf, (EA_DEBUG, "[%d] Leave RSHUTDOWN\n",getpid()));
	return SUCCESS;
}

ZEND_BEGIN_ARG_INFO(eaccelerator_second_arg_force_ref, 0)
  ZEND_ARG_PASS_INFO(0)
  ZEND_ARG_PASS_INFO(1)
ZEND_END_ARG_INFO();

function_entry eaccelerator_functions[] = {
#ifdef WITH_EACCELERATOR_INFO
  PHP_FE(eaccelerator_caching, NULL)
  PHP_FE(eaccelerator_clear, NULL)
	PHP_FE(eaccelerator_clean, NULL)
  PHP_FE(eaccelerator_info, NULL)
  PHP_FE(eaccelerator_purge, NULL)
  PHP_FE(eaccelerator_cached_scripts, NULL)
  #ifdef WITH_EACCELERATOR_OPTIMIZER
    PHP_FE(eaccelerator_optimizer, NULL)
  #endif
#endif
#ifdef WITH_EACCELERATOR_DISASSEMBLER
  PHP_FE(eaccelerator_dasm_file, NULL)
#endif
  {NULL, NULL, NULL, 0U, 0U}
};

zend_module_entry eaccelerator_module_entry = {
#if ZEND_MODULE_API_NO >= 20010901
  STANDARD_MODULE_HEADER,
#endif
  EACCELERATOR_EXTENSION_NAME,
  eaccelerator_functions,
  PHP_MINIT(eaccelerator),
  PHP_MSHUTDOWN(eaccelerator),
  PHP_RINIT(eaccelerator),
  PHP_RSHUTDOWN(eaccelerator),
  PHP_MINFO(eaccelerator),
#if ZEND_MODULE_API_NO >= 20010901
  EACCELERATOR_VERSION,          /* extension version number (string) */
#endif
  STANDARD_MODULE_PROPERTIES
};

#if defined(COMPILE_DL_EACCELERATOR)
ZEND_GET_MODULE(eaccelerator)
#endif

static startup_func_t last_startup;
static zend_llist_element *eaccelerator_el;

static const unsigned char eaccelerator_logo[] = {
      71,  73,  70,  56,  57,  97,  88,   0,  31,   0, 
     213,   0,   0, 150, 153, 196, 237, 168,  86, 187, 
     206, 230,   4,   4,   4, 108, 110, 144,  99, 144, 
     199, 136, 138, 184,  87,  88, 109, 165, 165, 167, 
     163, 166, 202, 240, 151,  44, 149,  91,  21, 225, 
     225, 229,   4,  76, 164, 252, 215, 171, 255, 255, 
     255, 212, 212, 224, 241, 200, 149, 141, 144, 192, 
     216, 216, 226, 251, 230, 205, 192, 193, 218, 207, 
     221, 238, 181, 188, 216, 130, 132, 168, 150, 152, 
     185, 152, 152, 154, 180, 181, 198, 215, 184, 147, 
      40, 102, 177, 224, 232, 242, 244, 244, 244, 235, 
     236, 239, 118, 121, 157, 193, 193, 194, 146, 148, 
     174, 181, 143,  96, 154, 183, 219, 156, 159, 200, 
     126, 128, 170, 174, 175, 193,  65,  39,   7, 232, 
     214, 192, 254, 241, 226, 246, 246, 248, 108,  65, 
      13, 142, 144, 185, 252, 224, 189, 138, 171, 213, 
      69, 122, 188, 239, 244, 249,  48,  49,  60, 176, 
     178, 209, 200, 201, 222, 252, 252, 253, 251, 251, 
     251, 162, 163, 187, 208, 208, 213, 169, 171, 205, 
     241, 234, 225, 255, 252, 249, 254, 248, 241, 140, 
     142, 169, 249, 186, 111,  33, 249,   4,   0,   0, 
       0,   0,   0,  44,   0,   0,   0,   0,  88,   0, 
      31,   0,   0,   6, 255,  64, 137, 112,  72,  44, 
      26, 143, 200, 164, 114, 201,  92,  62, 158, 208, 
     168, 116,  74, 173,  90, 175, 216, 108,  85, 168, 
     237, 122, 191,  15,  25, 163, 118, 209, 153,   0, 
      68, 128,  73, 119, 169,  49, 100,  86,  46, 120, 
      78, 127, 216,  60,  21,  93,  83,   8, 208,  85, 
      60,  54,  83, 114, 117, 132,  89,  32,  23,  38, 
      73,  38, 103,  72,  38,  23,  32,  82, 123, 146, 
     147,  69, 106,   9,  52,  21,  19,  53, 137, 138, 
      51,  51, 156, 141,  21, 100,  52,   9, 148, 166, 
     123,   0, 106, 126,  16,  21, 104,  67, 169, 106, 
     140,   9,   3, 159, 140,  18, 176, 182,   0,  23, 
      21, 101,  67,  21,  80,  32,  52, 192,  52,  44, 
       6,  16,  15,   6,  23,  44,  81,  24,  81,  25, 
      81, 194,  80,  25,   6,  18,  12,  80,  23,  15, 
     169,  15, 172, 155, 105,  33,   7,   4, 158,  46, 
       0,  33,   3,   7,   7,  51,   7, 139, 231, 225, 
       7,  25, 124,  23,  23,  52, 190,  19,   4, 205, 
      44,  27,   4,   4,  19,  57,  15,  33,  15,  32, 
      54,  64, 168, 241,   0,   5,  10,  28, 255,  54, 
     160, 120, 128, 163, 160,  65,   2,  15, 244, 229, 
     200, 113, 162,  26,   4,  20, 252,  22, 130, 128, 
      48,  98, 131,  30,  34,  38, 102, 208,  58,  64, 
     203,   4,  73, 115,   3,   6, 184, 152,  69,  75, 
     228,   1,  87,  38,  80, 204,  19, 242, 235,   9, 
      54,  31,   4,  78, 212, 152, 192, 128,   1,   8, 
     255,  31,  79,  78, 108,  99, 245, 239,  24,   3, 
     136,  16,  32, 212, 139,  24,  34,  83,   8,   3, 
      62,  33, 128,  56,  90,   3,  68, 136,  17, 173, 
     138, 176,  76,  16, 114,  64,   2, 145,   4,   0, 
     136, 196, 128, 129,  22, 215, 146,  66,  50, 224, 
     248,  40,  33, 147,  62,   2,  11,  39, 120, 120, 
      48, 162,  33,  10,   2,  44,  62,  64, 156, 144, 
     244,  31, 129,  17,  12,  31, 240, 157, 240,  76, 
     238, 131,  12,   4, 160, 110,   4,   1, 130, 192, 
       6,   6,  33, 112, 212,  48, 226, 195, 220,  25, 
     145,  95, 189, 118,  77,  64,  50, 236, 172,  79, 
      66,  92, 140,  96,  11,   0,  71,  78,  12,  39, 
      12, 108, 200,  71,  32,  68, 190,  16,  38,  70, 
      56,  54, 120,  87,  71, 136,  16,  25,  70,  36, 
     160, 141,  65,  33,  10,  12,  57,  13,  36, 240, 
     173,  15,  64,   2,  31,  58, 186, 189,  34,  96, 
     238,  86,  73,  90, 198,  75, 146,  12,   1, 128, 
     249, 203, 208,  62,  74,   9,  49,  96,   0,   3, 
      53,   9,   6,  78, 220,  78, 141, 218, 251, 137, 
      19, 168, 199, 163, 230,  46, 254, 246, 120, 247, 
     169, 193, 183, 127, 234,  34,  67,   6,  63,  51, 
     249, 156,  12,  55, 160, 181,  57, 114, 255, 137, 
      52,   3, 127,  62,  12, 129,  65, 118,  74, 112, 
     247,  29, 120, 219,  81, 163, 224, 130, 224,  61, 
      40, 225, 130,  15, 222, 162,  74,  60, 160, 116, 
     181,  95,   6,  36, 189, 212, 255, 225, 103,  39, 
      97, 224,  74, 119, 186, 157,  98, 162,  18, 169, 
     172,  65,   3,  13,  40, 184, 178, 149,  14,   9, 
     160,  97,   2,  87,  18, 204, 104,  66,  89,  51, 
      24,  23, 163,  16,  62, 132, 224, 195,  90,  39, 
       6, 121, 132,  37,  58, 176, 136, 195,  59,  46, 
     152, 133,  98, 135, 174,   8, 129, 129, 143,  56, 
      36, 160,  93,  33,  84,  82,  97,   3,  11,  12, 
     136, 128,   3,  66, 227,  44,  49,   2, 110,  67, 
     248, 224, 131,   6,  34,  48, 176, 204,   3, 131, 
      84, 169, 230,  19,  44, 128, 144, 195,   6,  71, 
     190, 179,   4,  26,  46, 136, 169,   1,  10,  57, 
     236, 192,   2,  15,  79, 164, 185, 166, 154,  55, 
     124, 192, 192, 155,   8, 228,  54, 130,  11, 136, 
     134,  86, 167, 152,  99,  34, 176,  65,  14,  12, 
     124,  16,   8,  20, 126,  62, 176,   2,   5,  20, 
     188, 160, 233, 166, 155,  58, 224, 105,   4,  61, 
     252,  73,  69, 160,  59,  12,  42,   2,  10,   8, 
      32, 160, 193, 170, 171, 166, 138, 130,   8, 144, 
     238, 240,   1, 159, 145,  72,   0,   5,  15,  20, 
      56,  16,  65,   4,  63,   4, 224, 171,   2,   1, 
       0, 171, 192, 176, 195,   6,  32, 234,  21, 129, 
     126,  48,  85,  79, 204,  50,  43, 235,   7,  55, 
     196,  97, 171, 165, 159, 254, 240, 195, 176,  63, 
     188, 240,   0, 173,  80, 244, 192, 194, 153,   2, 
     192, 113, 236, 184, 114, 172,  96, 174, 185, 152, 
      82, 160, 255, 133,   7,  13,  20, 240, 132,  12, 
       5, 196,  80, 192,  92,  15, 192,  32, 175,   0, 
      15,  88,  16, 195, 190,  22, 148, 224, 238,  19, 
     250, 242,  27, 176, 188, 226, 198, 128, 205, 190, 
     252, 202,  96, 111,   1, 248,  62, 128, 112,   1, 
      22,  80, 106, 235,  11,  14,  80, 188, 107, 175, 
     190, 250, 106,  45, 198,   1, 144, 192, 193,  19, 
       5,  52, 208,  64,  24,  29, 116,  96, 111,   3, 
     240,  54,   0,  67, 200,   2,   8, 160,  50,  12, 
      30, 216,  11, 133, 203,  48, 192,  76,  51,  12, 
     237,  62, 112,  65, 187,  54, 216, 107, 178,   7, 
      49, 168,  28,  52, 190, 237, 194,  80, 178, 196, 
      43, 108,  28, 172,   2,  11, 120, 204, 193, 211, 
      17, 112, 176, 235, 211,  28, 236, 240,  68,   7, 
      33, 151, 128, 179, 184,  45,  55,  32,  64, 180, 
      22, 120, 224, 114, 203,  10, 199,  48, 179, 215, 
     225, 186,  12, 178, 217,  33, 163,  92, 175, 217, 
      22, 120, 125, 131,  13, 242,  62, 224, 117, 189, 
      35, 247,  41, 129,   3, 196,  50, 189,  64,  11, 
      36, 216,  48, 183,  29,  79,   4,  98, 195, 164, 
      46, 119,  80, 180, 217, 103,  75, 225, 178, 200, 
       2, 200, 252, 196, 227, 104, 139,  44, 242,   5, 
      50,  52, 160,  56,  12, 111,  63, 160, 246,  19, 
     246, 218,  96, 121, 206, 122, 191, 224, 247, 223, 
      45, 164, 238, 244, 174, 172,  63, 173, 238,   3, 
       5, 152,  28,  50, 206,  17,  43,  76, 154,  51, 
     232,  93,  67,  33, 185, 231, 121, 243,  46,  64, 
      12,  29,  60,  80, 130, 208, 193, 203, 204,  46, 
     231,  50,  96, 109, 119, 205,  13, 208, 139, 166, 
     173,  42, 144, 176,  64,  10, 212,  87, 159, 250, 
       2, 216, 103, 191, 192,  14, 129, 168, 252, 132, 
     202,  33,   7,  93, 188, 230, 138, 139, 221,   0, 
     191,  56, 239, 203, 240, 249,  49,  88, 160, 118, 
     220,  43, 155, 189, 115, 204, 140, 227, 172, 120, 
     243, 118, 135, 139, 245, 164, 149,  78,  74, 248, 
     220, 130, 187, 193, 224,  30,  16,  51, 113, 149, 
     160,   4,  54, 208,  90,   9, 102,  86,  51,  56, 
     196, 172, 102,  98, 171,  25,  12,  74, 240,  64, 
     152, 197, 204,  38,  53, 139,  88, 189,  90, 182, 
     192, 201, 213, 236,  76,  48, 179, 129,   5,  96, 
     166, 183, 113, 153,  80,  77,  66,  74, 161,  10, 
      41,  17,   4,   0,  59,   0 };
 
static int eaccelerator_last_startup(zend_extension *extension) {
  int ret;
  extension->startup = last_startup;
  ret = extension->startup(extension);
  zend_extensions.count++;
  eaccelerator_el->next = zend_extensions.head;
  eaccelerator_el->prev = NULL;
  zend_extensions.head->prev = eaccelerator_el;
  zend_extensions.head = eaccelerator_el;
  if (ZendOptimizer) {
    if ((ZendOptimizer = zend_get_extension("Zend Optimizer")) != NULL) {
      ZendOptimizer->op_array_handler = NULL;
    }
  }
  return ret;
}

ZEND_DLEXPORT int eaccelerator_zend_startup(zend_extension *extension) {
 ea_is_zend_extension = 1;
  eaccelerator_el   = NULL;
  last_startup = NULL;

  if (!ea_is_extension) {
    if (zend_startup_module(&eaccelerator_module_entry) != SUCCESS) {
      return FAILURE;
    }
  }

  if (zend_llist_count(&zend_extensions) > 1) {
    zend_llist_element *p = zend_extensions.head;
    while (p != NULL) {
      zend_extension* ext = (zend_extension*)(p->data);
      if (strcmp(ext->name, EACCELERATOR_EXTENSION_NAME) == 0) {
        /* temporary removing eAccelerator extension */
        zend_extension* last_ext = (zend_extension*)zend_extensions.tail->data;
        if (eaccelerator_el != NULL) {
          zend_error(E_CORE_ERROR,"[%s] %s %s can not be loaded twice",
                   EACCELERATOR_EXTENSION_NAME,
                   EACCELERATOR_EXTENSION_NAME,
                   EACCELERATOR_VERSION);
          exit(1);
        }
        if (last_ext != ext) {
          eaccelerator_el = p;
          last_startup = last_ext->startup;
          last_ext->startup = eaccelerator_last_startup;
          zend_extensions.count--;
          if (p->prev != NULL) {
            p->prev->next = p->next;
          } else {
            zend_extensions.head = p->next;
          }
          if (p->next != NULL) {
            p->next->prev = p->prev;
          } else {
            zend_extensions.tail = p->prev;
          }
        }
      } else if (strcmp(ext->name, "Zend Extension Manager") == 0 ||
                 strcmp(ext->name, "Zend Optimizer") == 0) {
        /* Disable ZendOptimizer Optimizations */
        ZendOptimizer = ext;
        ext->op_array_handler = NULL;
      }
      p = p->next;
    }
  }

  php_register_info_logo(EACCELERATOR_VERSION_GUID, "text/plain", (unsigned char*)EACCELERATOR_VERSION_STRING, sizeof(EACCELERATOR_VERSION_STRING));
  php_register_info_logo(EACCELERATOR_LOGO_GUID,    "image/gif",  (unsigned char*)eaccelerator_logo, sizeof(eaccelerator_logo));

  return SUCCESS;
}

#ifndef ZEND_EXT_API
#  define ZEND_EXT_API    ZEND_DLEXPORT
#endif

ZEND_EXTENSION();

ZEND_DLEXPORT zend_extension zend_extension_entry = {
  EACCELERATOR_EXTENSION_NAME,
  EACCELERATOR_VERSION,
  "eAccelerator",
  "http://eaccelerator.net",
  "Copyright (c) 2004-2010 eAccelerator",
  eaccelerator_zend_startup,
  NULL,
  NULL,   /* void (*activate)() */
  NULL,   /* void (*deactivate)() */
  NULL,   /* void (*message_handle)(int message, void *arg) */
#ifdef WITH_EACCELERATOR_OPTIMIZER
  eaccelerator_optimize,   /* void (*op_array_handler)(zend_op_array *o_a); */
#else
  NULL,   /* void (*op_array_handler)(zend_op_array *o_a); */
#endif
  NULL,   /* void (*statement_handler)(zend_op_array *o_a); */
  NULL,   /* void (*fcall_begin_handler)(zend_op_array *o_a); */
  NULL,   /* void (*fcall_end_handler)(zend_op_array *o_a); */
  NULL,   /* void (*op_array_ctor)(zend_op_array *o_a); */
  NULL,   /* void (*op_array_dtor)(zend_op_array *o_a); */
#ifdef COMPAT_ZEND_EXTENSION_PROPERTIES
  NULL,   /* api_no_check */
  COMPAT_ZEND_EXTENSION_PROPERTIES
#else
  STANDARD_ZEND_EXTENSION_PROPERTIES
#endif
};

static zend_extension eaccelerator_extension_entry = {
  EACCELERATOR_EXTENSION_NAME,
  EACCELERATOR_VERSION,
  "eAccelerator",
  "http://eaccelerator.net",
  "Copyright (c) 2004-2010 eAccelerator",
  eaccelerator_zend_startup,
  NULL,
  NULL,   /* void (*activate)() */
  NULL,   /* void (*deactivate)() */
  NULL,   /* void (*message_handle)(int message, void *arg) */
#ifdef WITH_EACCELERATOR_OPTIMIZER
  eaccelerator_optimize,   /* void (*op_array_handler)(zend_op_array *o_a); */
#else
  NULL,   /* void (*op_array_handler)(zend_op_array *o_a); */
#endif
  NULL,   /* void (*statement_handler)(zend_op_array *o_a); */
  NULL,   /* void (*fcall_begin_handler)(zend_op_array *o_a); */
  NULL,   /* void (*fcall_end_handler)(zend_op_array *o_a); */
  NULL,   /* void (*op_array_ctor)(zend_op_array *o_a); */
  NULL,   /* void (*op_array_dtor)(zend_op_array *o_a); */
#ifdef COMPAT_ZEND_EXTENSION_PROPERTIES
  NULL,   /* api_no_check */
  COMPAT_ZEND_EXTENSION_PROPERTIES
#else
  STANDARD_ZEND_EXTENSION_PROPERTIES
#endif
};

static void register_eaccelerator_as_zend_extension() {
  zend_extension extension = eaccelerator_extension_entry;
  extension.handle = 0;
  zend_llist_prepend_element(&zend_extensions, &extension);
}

/******************************************************************************/

#endif  /* #ifdef HAVE_EACCELERATOR */

/*
 * Local variables:
 * tab-width: 2
 * c-basic-offset: 2
 * End:
 * vim: noet tabstop=2 softtabstop=2 shiftwidth=2
 */
