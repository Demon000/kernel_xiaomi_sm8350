// SPDX-License-Identifier: GPL-2.0-only

#include <linux/ctype.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/uio.h>

#define LOGGER_MAGIC		'l'
#define LOG_ID_EVENTS		2

struct log_time {
	uint32_t tv_sec;
	uint32_t tv_nsec;
} __attribute__((__packed__));

struct android_pmsg_log_header {
	uint8_t magic;
	uint16_t len;
	uint16_t uid;
	uint16_t pid;
} __attribute__((__packed__));

struct android_log_header {
	uint8_t id;
	uint16_t tid;
	struct log_time realtime;
} __attribute__((__packed__));

struct android_pmsg_prio_header {
	uint8_t prio;
} __attribute__((__packed__));

struct android_pmsg_tag_header {
	uint32_t tag;
} __attribute__((__packed__));

static DEFINE_MUTEX(pmsg_lock);
static char pmsg_buffer[1024];

static void pmsg_write_buf(const char *buf, size_t size)
{
	bool is_printable = true;
	ssize_t i;

	if (!size)
		return;

	for (i = 0; i < size - 1 && is_printable; i++)
		is_printable = isprint(buf[i]) ||
			       isspace(buf[i]);

	if (is_printable) {
		if (!buf[size - 1])
			size--;

		pr_cont("%.*s", size, buf);
	} else {
		for (i = 0; i < size; i++)
			pr_cont("%02x ", buf[i]);
	}
}

static bool pmsg_is_pmsg_header(unsigned long part, const struct iovec *iov)
{
	struct android_pmsg_log_header pmsg_header;
	void __user *buf = iov->iov_base;
	size_t len = iov->iov_len;

	int ret;

	if (part != 0)
		return false;

	if (len != sizeof(pmsg_header))
		return false;

	ret = __copy_from_user(&pmsg_header, buf, len);
	if (ret)
		return false;

	if (pmsg_header.magic != LOGGER_MAGIC)
		return false;

	return true;
}

static bool pmsg_is_header(unsigned long part, const struct iovec *iov,
			   bool *ignore)
{
	struct android_log_header header;
	void __user *buf = iov->iov_base;
	size_t len = iov->iov_len;
	int ret;

	if (part != 1)
		return false;

	if (len != sizeof(struct android_log_header))
		return false;

	ret = __copy_from_user(&header, buf, len);
	if (ret)
		return false;

	if (header.id == LOG_ID_EVENTS)
		*ignore = true;

	return true;
}

static bool pmsg_is_prio_or_tag(unsigned long part, const struct iovec *iov)
{
	size_t len = iov->iov_len;

	if (part != 2)
		return false;

	if (len != sizeof(struct android_pmsg_prio_header) &&
	    len != sizeof(struct android_pmsg_tag_header))
		return false;

	return true;
}

static bool pmsg_is_name_tag(unsigned long part)
{
	return part == 3;
}

static bool pmsg_is_message(unsigned long part)
{
	return part == 4;
}

static void pmsg_write_one(const struct iovec *iov)
{
	void __user *buf = iov->iov_base;
	size_t len = iov->iov_len;

	if (len > sizeof(pmsg_buffer))
		len = sizeof(pmsg_buffer);

	mutex_lock(&pmsg_lock);
	__copy_from_user(pmsg_buffer, buf, len);
	pmsg_write_buf(pmsg_buffer, len);
	mutex_unlock(&pmsg_lock);
}

static void pmsg_write_all(struct iov_iter *from)
{
	size_t len;

	mutex_lock(&pmsg_lock);
	len = copy_from_iter(pmsg_buffer, sizeof(pmsg_buffer), from);
	pmsg_write_buf(pmsg_buffer, len);
	mutex_unlock(&pmsg_lock);
}

static ssize_t pmsg_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	size_t count = iov_iter_count(from);
	bool ignore = false;
	unsigned long i;

	if (!iter_is_iovec(from))
		return -EINVAL;

	for (i = 0; i < from->nr_segs; i++) {
		const struct iovec *iov = &from->iov[i];

		if (pmsg_is_pmsg_header(i, iov) ||
		    pmsg_is_prio_or_tag(i, iov)) {
			continue;
		} else if (pmsg_is_header(i, iov, &ignore)) {
			if (ignore)
				break;

			continue;
		} else if (pmsg_is_name_tag(i)) {
			pr_err("");
			pmsg_write_one(iov);
			pr_cont(": ");
			continue;
		} else if (pmsg_is_message(i)) {
			pmsg_write_one(iov);
			pr_cont("\n");
			continue;
		} else {
			pmsg_write_all(from);
			break;
		}
	}

	return count;
}

static const struct file_operations pmsg_fops = {
	.owner = THIS_MODULE,
	.write_iter = pmsg_write_iter,
	.llseek = noop_llseek,
};

struct miscdevice pmsg_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "pmsg0",
	.fops = &pmsg_fops,
};

static int __init pmsg_init(void)
{
	return misc_register(&pmsg_device);
}

static void __exit pmsg_exit(void)
{
	misc_deregister(&pmsg_device);
}

module_init(pmsg_init);
module_exit(pmsg_exit);

MODULE_DESCRIPTION("PMSG driver");
MODULE_AUTHOR("Cosmin Tanislav <demonsingur@gmail.com>");
MODULE_LICENSE("GPL");
