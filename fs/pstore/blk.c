// SPDX-License-Identifier: GPL-2.0
/*
 * Implements pstore backend driver that write to block (or non-block) storage
 * devices, using the pstore/zone API.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/blkdev.h>
#include <linux/delay.h>
#include <linux/string.h>
#include <linux/platform_device.h>
#include <linux/pstore_blk.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/mount.h>
#include <linux/syscalls.h>
#include <linux/writeback.h>
#include <linux/workqueue.h>

#include <asm/unaligned.h>
#include <scsi/scsi.h>
#include <scsi/scsi_dbg.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_eh.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi_proto.h>
#include <scsi/scsi_transport.h>
#include "../../drivers/scsi/sd.h"
#include "../../drivers/scsi/scsi_priv.h"

#define bdev_to_sdev(bdev) \
	scsi_disk(bdev->bd_disk)->device

static long kmsg_size = CONFIG_PSTORE_BLK_KMSG_SIZE;
module_param(kmsg_size, long, 0400);
MODULE_PARM_DESC(kmsg_size, "kmsg dump record size in kbytes");

static int max_reason = CONFIG_PSTORE_BLK_MAX_REASON;
module_param(max_reason, int, 0400);
MODULE_PARM_DESC(max_reason,
		 "maximum reason for kmsg dump (default 2: Oops and Panic)");

#if IS_ENABLED(CONFIG_PSTORE_PMSG)
static long pmsg_size = CONFIG_PSTORE_BLK_PMSG_SIZE;
#else
static long pmsg_size = -1;
#endif
module_param(pmsg_size, long, 0400);
MODULE_PARM_DESC(pmsg_size, "pmsg size in kbytes");

#if IS_ENABLED(CONFIG_PSTORE_CONSOLE)
static long console_size = CONFIG_PSTORE_BLK_CONSOLE_SIZE;
#else
static long console_size = -1;
#endif
module_param(console_size, long, 0400);
MODULE_PARM_DESC(console_size, "console size in kbytes");

#if IS_ENABLED(CONFIG_PSTORE_FTRACE)
static long ftrace_size = CONFIG_PSTORE_BLK_FTRACE_SIZE;
#else
static long ftrace_size = -1;
#endif
module_param(ftrace_size, long, 0400);
MODULE_PARM_DESC(ftrace_size, "ftrace size in kbytes");

static bool best_effort;
module_param(best_effort, bool, 0400);
MODULE_PARM_DESC(best_effort, "use best effort to write (i.e. do not require storage driver pstore support, default: off)");

static bool scsi_panic_write;
module_param(scsi_panic_write, bool, 0400);
MODULE_PARM_DESC(scsi_panic_write, "use SCSI methods for writing when in panic");

/*
 * blkdev - the block device to use for pstore storage
 * See Documentation/admin-guide/pstore-blk.rst for details.
 */
static char blkdev[80] = CONFIG_PSTORE_BLK_BLKDEV;
module_param_string(blkdev, blkdev, 80, 0400);
MODULE_PARM_DESC(blkdev, "block device for pstore storage");

/*
 * All globals must only be accessed under the pstore_blk_lock
 * during the register/unregister functions.
 */
static DEFINE_MUTEX(pstore_blk_lock);
static DEFINE_MUTEX(pstore_blk_write_lock);
static struct block_device *psbdev;
static struct pstore_device_info *pstore_device_info;

#define check_size(name, alignsize) ({				\
	long _##name_ = (name);					\
	_##name_ = _##name_ <= 0 ? 0 : (_##name_ * 1024);	\
	if (_##name_ & ((alignsize) - 1)) {			\
		pr_info(#name " must align to %d\n",		\
				(alignsize));			\
		_##name_ = ALIGN(name, (alignsize));		\
	}							\
	_##name_;						\
})

#define verify_size(name, alignsize, enabled) {			\
	long _##name_;						\
	if (enabled)						\
		_##name_ = check_size(name, alignsize);		\
	else							\
		_##name_ = 0;					\
	/* Synchronize module parameters with resuls. */	\
	name = _##name_ / 1024;					\
	dev->zone.name = _##name_;				\
}

static int __register_pstore_device(struct pstore_device_info *dev)
{
	int ret;

	lockdep_assert_held(&pstore_blk_lock);

	if (!dev) {
		pr_err("NULL device info\n");
		return -EINVAL;
	}
	if (!dev->zone.total_size) {
		pr_err("zero sized device\n");
		return -EINVAL;
	}
	if (!dev->zone.read) {
		pr_err("no read handler for device\n");
		return -EINVAL;
	}
	if (!dev->zone.write) {
		pr_err("no write handler for device\n");
		return -EINVAL;
	}

	/* someone already registered before */
	if (pstore_device_info)
		return -EBUSY;

	/* zero means not limit on which backends to attempt to store. */
	if (!dev->flags)
		dev->flags = UINT_MAX;

	/* Copy in module parameters. */
	verify_size(kmsg_size, 4096, dev->flags & PSTORE_FLAGS_DMESG);
	verify_size(pmsg_size, 4096, dev->flags & PSTORE_FLAGS_PMSG);
	verify_size(console_size, 4096, dev->flags & PSTORE_FLAGS_CONSOLE);
	verify_size(ftrace_size, 4096, dev->flags & PSTORE_FLAGS_FTRACE);
	dev->zone.max_reason = max_reason;

	/* Initialize required zone ownership details. */
	dev->zone.name = KBUILD_MODNAME;
	dev->zone.owner = THIS_MODULE;

	ret = register_pstore_zone(&dev->zone);
	if (ret == 0)
		pstore_device_info = dev;

	return ret;
}
/**
 * register_pstore_device() - register non-block device to pstore/blk
 *
 * @dev: non-block device information
 *
 * Return:
 * * 0		- OK
 * * Others	- something error.
 */
int register_pstore_device(struct pstore_device_info *dev)
{
	int ret;

	mutex_lock(&pstore_blk_lock);
	ret = __register_pstore_device(dev);
	mutex_unlock(&pstore_blk_lock);

	return ret;
}
EXPORT_SYMBOL_GPL(register_pstore_device);

static void __unregister_pstore_device(struct pstore_device_info *dev)
{
	lockdep_assert_held(&pstore_blk_lock);
	if (pstore_device_info && pstore_device_info == dev) {
		unregister_pstore_zone(&dev->zone);
		pstore_device_info = NULL;
	}
}

/**
 * unregister_pstore_device() - unregister non-block device from pstore/blk
 *
 * @dev: non-block device information
 */
void unregister_pstore_device(struct pstore_device_info *dev)
{
	mutex_lock(&pstore_blk_lock);
	__unregister_pstore_device(dev);
	mutex_unlock(&pstore_blk_lock);
}
EXPORT_SYMBOL_GPL(unregister_pstore_device);

static void diskio_done(struct scsi_cmnd *cmd)
{
	struct scsi_sense_hdr sshr;
	int i;

	for (i = 0; i < cmd->sdb.table.nents; i++) {
		struct scatterlist *sg = &cmd->sdb.table.sgl[i];
		struct page *pg = (struct page *)sg->page_link;
		put_page(pg);
	}

	scsi_normalize_sense(cmd->sense_buffer,
			     sizeof(struct scsi_sense_hdr), &sshr);

	scsi_put_command(cmd);
}

static int prepare_command(struct pstore_device_info *dev)
{
	struct scsi_device *sdev = bdev_to_sdev(psbdev);
	struct scsi_cmnd *scmnd = &dev->scsi_rq->scmnd;

	if (sdev->sdev_state != SDEV_RUNNING)
		return -1;

	scsi_init_command(sdev, scmnd);
	scmnd->request = &dev->scsi_rq->rq;
	scmnd->scsi_done = diskio_done;
	scmnd->transfersize = sdev->sector_size;

	return 0;
}

static int send_command(struct pstore_device_info *dev)
{
	struct scsi_cmnd *scmnd = &dev->scsi_rq->scmnd;

	return scmnd->device->host->hostt->queuecommand(scmnd->device->host,
							scmnd);
}

static int do_sync(struct pstore_device_info *dev)
{
	struct scsi_cmnd *scmnd = &dev->scsi_rq->scmnd;
	char cdb[10] = {0};
	int ret;

	ret = prepare_command(dev);
	if (ret)
		return ret;

	scmnd->cmnd = cdb;
	scmnd->cmd_len = sizeof(cdb);
	scmnd->cmnd[0] = SYNCHRONIZE_CACHE;

	return send_command(dev);
}

static int do_write(struct pstore_device_info *dev, const char *buf, loff_t to,
		    size_t len)
{
	struct scsi_device *sdev = bdev_to_sdev(psbdev);
	struct scsi_cmnd *scmnd = &dev->scsi_rq->scmnd;
	unsigned int offset, nr_pages, i;
	char cdb[16] = {0};
	sector_t lba;
	int ret;

	ret = prepare_command(dev);
	if (ret)
		return ret;

	nr_pages = ((u64)buf + len + PAGE_SIZE - 1) / PAGE_SIZE -
		   (u64)buf / PAGE_SIZE;
	lba = sectors_to_logical(sdev, psbdev->bd_part->start_sect);
	offset = ((to & ~PAGE_MASK) ? 1 : 0) + (to >> PAGE_SHIFT) + lba;

	scmnd->cmnd = cdb;
	scmnd->sdb.length = len;
	scmnd->sdb.table.nents = nr_pages;
	scmnd->sdb.table.orig_nents = nr_pages;
	scmnd->sdb.table.sgl = dev->scsi_rq->sgl;
	scmnd->sc_data_direction = DMA_TO_DEVICE;

	if (offset > 0xffffffff || len > 0xffff) {
		scmnd->cmd_len = 16;
		scmnd->cmnd[0] = WRITE_16;
		put_unaligned_be64(offset, &scmnd->cmnd[2]);
		put_unaligned_be32(len, &scmnd->cmnd[10]);
	} else {
		scmnd->cmd_len = 10;
		scmnd->cmnd[0] = WRITE_10;
		put_unaligned_be32(offset, &scmnd->cmnd[2]);
		put_unaligned_be16(len, &scmnd->cmnd[7]);
	}

	for (i = 0; i < nr_pages; i++) {
		struct scatterlist *sg = &scmnd->sdb.table.sgl[i];
		struct page *pg = virt_to_page(buf + i * PAGE_SIZE);

		sg->page_link = (unsigned long)pg;
		sg->dma_address = page_to_phys(pg);
		sg->offset = 0;

		if (i == nr_pages - 1) {
			sg->length = len % PAGE_SIZE ?: PAGE_SIZE;
			sg->dma_length = len % PAGE_SIZE ?: PAGE_SIZE;
		} else {
			sg->length = PAGE_SIZE;
			sg->dma_length = PAGE_SIZE;
			sg_mark_end(sg);
		}
	}

	return send_command(dev);
}

static ssize_t psblk_scsi_blk_panic_write(const char *buf, size_t bytes,
		loff_t pos)
{
	struct pstore_device_info *dev = pstore_device_info;
	int ret;

	ret = do_write(dev, buf, pos, bytes);
	if (ret)
		return ret;

	ret = do_sync(dev);
	if (ret)
		return ret;

	mdelay(10);

	return bytes;
}

static ssize_t psblk_generic_blk_read(char *buf, size_t bytes, loff_t pos)
{
	struct address_space *mapping = psbdev->bd_inode->i_mapping;
	int index = pos >> PAGE_SHIFT;
	int offset = pos & ~PAGE_MASK;
	struct page *page;
	ssize_t retlen = 0;
	int cpylen;

	while (bytes) {
		if (offset + bytes > PAGE_SIZE)
			cpylen = PAGE_SIZE - offset;
		else
			cpylen = bytes;

		bytes = bytes - cpylen;

		page = read_mapping_page(mapping, index, NULL);
		if (IS_ERR(page))
			return PTR_ERR(page);

		memcpy(buf, page_address(page) + offset, cpylen);
		put_page(page);

		retlen += cpylen;

		buf += cpylen;
		offset = 0;
		index++;
	}

	return retlen;
}

static ssize_t _psblk_generic_blk_write(const char *buf, size_t bytes,
					loff_t pos)
{
	struct address_space *mapping = psbdev->bd_inode->i_mapping;
	int index = pos >> PAGE_SHIFT;
	int offset = pos & ~PAGE_MASK;
	struct page *page;
	ssize_t retlen = 0;
	int cpylen;

	while (bytes) {
		if (offset + bytes > PAGE_SIZE)
			cpylen = PAGE_SIZE - offset;
		else
			cpylen = bytes;

		bytes = bytes - cpylen;

		page = read_mapping_page(mapping, index, NULL);
		if (IS_ERR(page))
			return PTR_ERR(page);

		if (memcmp(page_address(page) + offset, buf, cpylen)) {
			lock_page(page);
			memcpy(page_address(page) + offset, buf, cpylen);
			set_page_dirty(page);
			unlock_page(page);
			balance_dirty_pages_ratelimited(mapping);
		}
		put_page(page);

		retlen += cpylen;

		buf += cpylen;
		offset = 0;
		index++;
	}

	return retlen;
}

static ssize_t psblk_generic_blk_write(const char *buf, size_t bytes,
				       loff_t pos)
{
	ssize_t retlen;

	if (in_interrupt() || irqs_disabled())
		return -EBUSY;

	mutex_lock(&pstore_blk_write_lock);
	retlen = _psblk_generic_blk_write(buf, bytes, pos);
	mutex_unlock(&pstore_blk_write_lock);

	return retlen;
}

/* get information of pstore/blk */
int pstore_blk_get_config(struct pstore_blk_config *info)
{
	strncpy(info->device, blkdev, 80);
	info->max_reason = max_reason;
	info->kmsg_size = check_size(kmsg_size, 4096);
	info->pmsg_size = check_size(pmsg_size, 4096);
	info->ftrace_size = check_size(ftrace_size, 4096);
	info->console_size = check_size(console_size, 4096);

	return 0;
}
EXPORT_SYMBOL_GPL(pstore_blk_get_config);

#define BLOCK_DEVICE_FIND_RETRIES	1000
#define BLOCK_DEVICE_FIND_WAIT		10
#define BLOCK_DEVICE_MODE		(FMODE_READ | FMODE_WRITE | FMODE_EXCL)
static struct block_device *find_block_device(struct pstore_device_info *dev,
					      const char *path)
{
	dev_t devt;
	int i;

	for (i = 0; i < BLOCK_DEVICE_FIND_RETRIES; i++) {
		devt = name_to_dev_t(path);
		if (devt)
			break;

		msleep(BLOCK_DEVICE_FIND_WAIT);
	}

	if (!devt) {
		pr_err("failed to resolve '%s'\n", path);
		return NULL;
	}

	return blkdev_get_by_dev(devt, BLOCK_DEVICE_MODE, dev);
}

static int __best_effort_init(void)
{
	struct pstore_device_info *dev;
	int ret;

	/* No best-effort mode requested. */
	if (!best_effort)
		return 0;

	/* Reject an empty blkdev. */
	if (!blkdev[0]) {
		pr_err("blkdev empty with best_effort=Y\n");
		return -EINVAL;
	}

	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev)
		return -ENOMEM;

	psbdev = find_block_device(dev, blkdev);
	if (!psbdev)
		return -ENODEV;

	dev->zone.read = psblk_generic_blk_read;
	dev->zone.write = psblk_generic_blk_write;
	dev->zone.total_size = psbdev->bd_inode->i_size & PAGE_MASK;

	if (scsi_panic_write) {
		struct scsi_device *sdev = bdev_to_sdev(psbdev);
		dev->scsi_rq = kzalloc(sizeof(*dev->scsi_rq) +
				       sdev->host->hostt->cmd_size, GFP_KERNEL);
		if (!dev->scsi_rq)
			goto put_bdev;

		dev->zone.panic_write = psblk_scsi_blk_panic_write;
	}

	ret = __register_pstore_device(dev);
	if (ret)
		goto free_scsi_rq;

	pr_info("attached %s (%lu)", blkdev, dev->zone.total_size);
	if (!scsi_panic_write)
		pr_cont(" (no dedicated panic_write!)");
	pr_cont("\n");

	return 0;

free_scsi_rq:
	kfree(dev->scsi_rq);

put_bdev:
	blkdev_put(psbdev, BLOCK_DEVICE_MODE);
	psbdev = NULL;

free_dev:
	kfree(dev);

	return ret;
}

static void best_effort_init(struct work_struct *work)
{
	mutex_lock(&pstore_blk_lock);
	__best_effort_init();
	mutex_unlock(&pstore_blk_lock);
}

static void __exit __best_effort_exit(void)
{
	/*
	 * Currently, the only user of psblk_file is best_effort, so
	 * we can assume that pstore_device_info is associated with it.
	 * Once there are "real" blk devices, there will need to be a
	 * dedicated pstore_blk_info, etc.
	 */
	if (psbdev) {
		struct pstore_device_info *dev = pstore_device_info;

		__unregister_pstore_device(dev);
		kfree(dev);
		blkdev_put(psbdev, BLOCK_DEVICE_MODE);
		psbdev = NULL;
	}
}

static DECLARE_WORK(best_effort_init_work, best_effort_init);

static int __init pstore_blk_init(void)
{
	schedule_work(&best_effort_init_work);

	return 0;
}
late_initcall(pstore_blk_init);

static void __exit pstore_blk_exit(void)
{
	mutex_lock(&pstore_blk_lock);
	__best_effort_exit();
	/* If we've been asked to unload, unregister any remaining device. */
	__unregister_pstore_device(pstore_device_info);
	mutex_unlock(&pstore_blk_lock);
}
module_exit(pstore_blk_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("WeiXiong Liao <liaoweixiong@allwinnertech.com>");
MODULE_AUTHOR("Kees Cook <keescook@chromium.org>");
MODULE_DESCRIPTION("pstore backend for block devices");
