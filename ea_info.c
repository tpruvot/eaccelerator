/*
   +----------------------------------------------------------------------+
   | eAccelerator project                                                 |
   +----------------------------------------------------------------------+
   | Copyright (c) 2004 - 2010 eAccelerator                               |
   | http://eaccelerator.net                                  			  |
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
#include "ea_cache.h"
#include "ea_info.h"
#include "mm.h"
#include "zend.h"
#include "fopen_wrappers.h"
#include "debug.h"
#include <fcntl.h>

#ifndef O_BINARY
#  define O_BINARY 0
#endif

#ifdef WITH_EACCELERATOR_INFO

#define NOT_ADMIN_WARNING "This script isn't in the allowed_admin_path setting!"

extern eaccelerator_mm *ea_mm_instance;
extern ea_cache_t *ea_script_cache;

/* for checking if shm_only storage */
extern zend_bool ea_scripts_shm_only;

/* {{{ isAdminAllowed(): check if the admin functions are allowed for the calling script */
static int isAdminAllowed(TSRMLS_D) {
    const char *filename = zend_get_executed_filename(TSRMLS_C);
    if (EAG(allowed_admin_path) && *EAG(allowed_admin_path)) {
        char *path;
        char *p;
        char *next;

        path = estrdup(EAG(allowed_admin_path));
        p = path;

        while (p && *p) {
            next = strchr(p, DEFAULT_DIR_SEPARATOR); 
            if (next != NULL) {
                *next = '\0';
                ++next;
            }
            
            if (!php_check_specific_open_basedir(p, filename TSRMLS_CC)) {
                efree(path);
                return 1;
            }

            p = next;
        }
        efree(path);
        return 0;
    }
    return 0;
}
/* }}} */

/* {{{ PHP_FUNCTION(eaccelerator_prune): remove all expired scripts from shared memory */
PHP_FUNCTION(eaccelerator_prune)
{
	time_t t;

	if (ea_mm_instance == NULL) {
		RETURN_NULL();
	}

	if (!isAdminAllowed(TSRMLS_C)) {
		zend_error(E_WARNING, NOT_ADMIN_WARNING);
		RETURN_NULL();
	}

	ea_cache_prune(EAG(cache_request));
}
/* }}} */

/* {{{ PHP_FUNCTION(eaccelerator_purge): remove all scripts from file and memory */
PHP_FUNCTION(eaccelerator_purge)
{
	time_t t;

	if (ea_mm_instance == NULL) {
		RETURN_NULL();
	}

	if (!isAdminAllowed(TSRMLS_C)) {
		zend_error(E_WARNING, NOT_ADMIN_WARNING);
		RETURN_NULL();
	}

	ea_cache_purge(EAG(cache_request));
}
/* }}} */

/* {{{ PHP_FUNCTION(eaccelerator_optimizer): enable or disable optimizer */
#ifdef WITH_EACCELERATOR_OPTIMIZER
PHP_FUNCTION(eaccelerator_optimizer) 
{
    zend_bool enable;
    
	if (ea_mm_instance == NULL) {
		RETURN_NULL();
	}

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "b", &enable) == FAILURE)
		return;

    if (isAdminAllowed(TSRMLS_C)) {
        EACCELERATOR_UNPROTECT();
        if (enable) {
            ea_mm_instance->optimizer_enabled = 1;
        } else {
            ea_mm_instance->optimizer_enabled = 0;
        }
        EACCELERATOR_PROTECT();
    } else {
        zend_error(E_WARNING, NOT_ADMIN_WARNING);
    }
    
    RETURN_NULL();
}
#endif
/* }}} */

/* {{{ PHP_FUNCTION(eaccelerator_caching): enable or disable caching */
PHP_FUNCTION(eaccelerator_caching) 
{
    zend_bool enable;

	if (ea_mm_instance == NULL) {
		RETURN_NULL();
	}

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "b", &enable) == FAILURE)
		return;

    if (isAdminAllowed(TSRMLS_C)) {
        EACCELERATOR_UNPROTECT();
        if (enable) {
            ea_mm_instance->enabled = 1;
        } else {
            ea_mm_instance->enabled = 0;
        }
        EACCELERATOR_PROTECT();
    } else {
        zend_error(E_WARNING, NOT_ADMIN_WARNING);
    }
    
    RETURN_NULL();
}
/* }}} */

/* {{{ PHP_FUNCTION(eaccelerator_info): get info about eaccelerator */
// returns info about eaccelerator as an array
// returhs the same as eaccelerator section in phpinfo
PHP_FUNCTION (eaccelerator_info)
{
	unsigned int available;
    char *shm, *sem;

    shm = (char *)mm_shm_type();
    sem = (char *)mm_sem_type();

	if (ea_mm_instance == NULL) {
		RETURN_NULL();
	}

	available = mm_available (ea_mm_instance->mm);

	// init return table
	array_init(return_value);
	
	// put eaccelerator information
	add_assoc_string(return_value, "version", EACCELERATOR_VERSION, 1);
	add_assoc_string(return_value, "shm_type", shm, 1);
    add_assoc_string(return_value, "sem_type", sem, 1);
    add_assoc_string(return_value, "logo", EACCELERATOR_LOGO_GUID, 1);
	add_assoc_bool(return_value, "cache", (EAG (enabled)
		&& (ea_mm_instance != NULL)
		&& ea_mm_instance->enabled) ? 1 : 0);
	add_assoc_bool(return_value, "optimizer", (EAG (optimizer_enabled)
		&& (ea_mm_instance != NULL)
		&& ea_mm_instance->optimizer_enabled) ? 1 : 0);
	add_assoc_long(return_value, "memorySize", ea_mm_instance->total);
	add_assoc_long(return_value, "memoryAvailable", available);
	add_assoc_long(return_value, "memoryAllocated", ea_mm_instance->total - available);
	add_assoc_long(return_value, "cachedScripts", ea_script_cache->ht->elements);
	add_assoc_long(return_value, "htSize", ea_script_cache->ht->size);

	return;
}
/* }}} */

/* {{{ PHP_FUNCTION(eaccelerator_cached_scripts): Get an array with information about all cached scripts */
void format_cache_entry(ea_cache_entry *p, void *data)
{
	zval *table = (zval *) data;
	zval *script = NULL;

	MAKE_STD_ZVAL(script);
	array_init(script);
	add_assoc_string(script, "file", p->key, 1);
	add_assoc_long(script, "mtime", p->mtime);
	add_assoc_long(script, "ctime", p->ctime);
	add_assoc_long(script, "atime", p->atime);
	add_assoc_long(script, "size", p->size);
	add_assoc_long(script, "usecount", p->ref_cnt);
	add_assoc_long(script, "hits", p->nhits);
	add_next_index_zval(table, script); 
}

PHP_FUNCTION(eaccelerator_cached_scripts)
{
    ea_cache_entry *p;
    int i;

 	if (ea_mm_instance == NULL) {
		RETURN_NULL();
	}

	if (!isAdminAllowed(TSRMLS_C)) {
        zend_error(E_WARNING, NOT_ADMIN_WARNING);
        RETURN_NULL();
    }

    array_init(return_value);

	ea_cache_walk_ht(ea_script_cache, format_cache_entry, (void *)return_value);
}
/* }}} */

#endif	/* WITH_EACCELERATOR_INFO */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */

