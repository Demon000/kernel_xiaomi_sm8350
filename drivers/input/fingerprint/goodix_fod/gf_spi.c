// SPDX-License-Identifier: GPL-2.0-only

#include <linux/compat.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/gpio.h>
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/regulator/consumer.h>
#include <linux/slab.h>

struct gf_dev {
	struct miscdevice	miscdev;

	struct device		*dev;
	struct regulator	*vreg;
	struct gpio_desc	*reset_gpiod;
};

static long gf_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	return 0;
}

#ifdef CONFIG_COMPAT
static long gf_compat_ioctl(struct file *filp, unsigned int cmd,
			    unsigned long arg)
{
	return gf_ioctl(filp, cmd, (unsigned long)compat_ptr(arg));
}
#endif /*CONFIG_COMPAT */

static const struct file_operations gf_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.unlocked_ioctl = gf_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = gf_compat_ioctl,
#endif
};

static int gf_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct gf_dev *gf;
	int ret;

	gf = devm_kzalloc(dev, sizeof(*gf), GFP_KERNEL);
	if (!gf)
		return -ENOMEM;

	gf->dev = dev;
	platform_set_drvdata(pdev, gf);

	gf->vreg = devm_regulator_get(dev, "l11c_vdd");
	if (IS_ERR(gf->vreg)) {
		ret = PTR_ERR(gf->vreg);
		dev_err(dev, "failed to get regulator: %d\n", ret);
		return ret;
	}

	gf->reset_gpiod = devm_gpiod_get(dev, "reset", GPIOD_OUT_LOW);
	if (IS_ERR(gf->reset_gpiod)) {
		ret = PTR_ERR(gf->reset_gpiod);
		dev_err(dev, "failed to get reset GPIO: %d\n", ret);
		return ret;
	}

	ret = regulator_set_voltage(gf->vreg, 3000000, 3000000);
	if (ret)
		return ret;

	ret = regulator_set_load(gf->vreg, 200000);
	if (ret)
		return ret;

	ret = regulator_enable(gf->vreg);
	if (ret)
		return ret;

	gpiod_set_value_cansleep(gf->reset_gpiod, 1);
	msleep(3);

	gf->miscdev.minor = MISC_DYNAMIC_MINOR;
	gf->miscdev.name = "goodix_fp";
	gf->miscdev.fops = &gf_fops;

	return misc_register(&gf->miscdev);
}

static int gf_remove(struct platform_device *pdev)
{
	struct gf_dev *gf = platform_get_drvdata(pdev);

	misc_deregister(&gf->miscdev);

	return 0;
}

static struct of_device_id gf_match_table[] = {
	{ .compatible = "goodix,fingerprint" },
	{},
};

static struct platform_driver gf_driver = {
	.driver = {
		.name = "goodix_fp",
		.owner = THIS_MODULE,
		.of_match_table = gf_match_table,
	},
	.probe = gf_probe,
	.remove = gf_remove,
};

module_platform_driver(gf_driver);

MODULE_DESCRIPTION("Goodix fingerprint driver");
MODULE_AUTHOR("Cosmin Tanislav <demonsingur@gmail.com>");
MODULE_LICENSE("GPL");
