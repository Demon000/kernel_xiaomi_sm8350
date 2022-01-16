/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __PSTORE_BLK_H_
#define __PSTORE_BLK_H_

#include <linux/types.h>
#include <linux/pstore.h>
#include <linux/pstore_zone.h>

/**
 * typedef pstore_blk_panic_write_op - panic write operation to block device
 *
 * @buf: the data to write
 * @start_sect: start sector to block device
 * @sects: sectors count on buf
 *
 * Return: On success, zero should be returned. Others mean error.
 *
 * Panic write to block device must be aligned to SECTOR_SIZE.
 */
typedef int (*pstore_blk_panic_write_op)(const char *buf, sector_t start_sect,
		sector_t sects);

/**
 * struct pstore_blk_info - pstore/blk registration details
 *
 * @major:	Which major device number to support with pstore/blk
 * @flags:	The supported PSTORE_FLAGS_* from linux/pstore.h.
 * @panic_write:The write operation only used for the panic case.
 *		This can be NULL, but is recommended to avoid losing
 *		crash data if the kernel's IO path or work queues are
 *		broken during a panic.
 * @devt:	The dev_t that pstore/blk has attached to.
 * @nr_sects:	Number of sectors on @devt.
 * @start_sect:	Starting sector on @devt.
 */
struct pstore_blk_info {
	unsigned int major;
	unsigned int flags;
	pstore_blk_panic_write_op panic_write;

	/* Filled in by pstore/blk after registration. */
	dev_t devt;
	sector_t nr_sects;
	sector_t start_sect;
};

int  register_pstore_blk(struct pstore_blk_info *info);
void unregister_pstore_blk(unsigned int major);

#endif
