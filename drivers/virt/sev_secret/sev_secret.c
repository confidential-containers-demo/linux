// SPDX-License-Identifier: GPL-2.0
/*
 * sev_secret module
 *
 * Copyright (C) 2021 IBM Corporation
 * Author: Dov Murik <dovmurik@linux.ibm.com>
 */

#include <linux/seq_file.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/io.h>
#include <linux/security.h>
#include <linux/efi.h>

/**
 * sev_secret: Allow reading confidential computing secret area via securityfs
 * interface.
 *
 * When the module is loaded (and securityfs is mounted, typically under
 * /sys/kernel/security), an "sev_secret" directory is created in securityfs.
 * In it, a file is created for each secret entry.  The name of each such file
 * is the GUID of the secret entry, and its content is the secret data.
 */

#define SEV_SECRET_NUM_FILES 64

#define EFI_SEVSECRET_TABLE_HEADER_GUID \
	EFI_GUID(0x1e74f542, 0x71dd, 0x4d66, 0x96, 0x3e, 0xef, 0x42, 0x87, 0xff, 0x17, 0x3b)

struct sev_secret {
	struct dentry *fs_dir;
	struct dentry *fs_files[SEV_SECRET_NUM_FILES];
	struct linux_efi_confidential_computing_secret_area *secret_area;
};

/*
 * Structure of the SEV secret area
 *
 * Offset   Length
 * (bytes)  (bytes)  Usage
 * -------  -------  -----
 *       0       16  Secret table header GUID (must be 1e74f542-71dd-4d66-963e-ef4287ff173b)
 *      16        4  Length of bytes of the entire secret area
 *
 *      20       16  First secret entry's GUID
 *      36        4  First secret entry's length in bytes (= 16 + 4 + x)
 *      40        x  First secret entry's data
 *
 *    40+x       16  Second secret entry's GUID
 *    56+x        4  Second secret entry's length in bytes (= 16 + 4 + y)
 *    60+x        y  Second secret entry's data
 *
 * (... and so on for additional entries)
 *
 * The GUID of each secret entry designates the usage of the secret data.
 */

/**
 * struct secret_header - Header of entire secret area; this should be followed
 * by instances of struct secret_entry.
 * @guid:	Must be EFI_SEVSECRET_TABLE_HEADER_GUID
 * @len:	Length in bytes of entire secret area, including header
 */
struct secret_header {
	efi_guid_t guid;
	u32 len;
} __attribute((packed));

/**
 * struct secret_entry - Holds one secret entry
 * @guid:	Secret-specific GUID
 * @len:	Length of secret entry, including its guid and len fields
 * @data:	The secret data
 */
struct secret_entry {
	efi_guid_t guid;
	u32 len;
	u8 data[];
} __attribute((packed));

static struct sev_secret the_sev_secret;

static size_t secret_entry_data_len(struct secret_entry *e)
{
	return e->len - sizeof(*e);
}

static int sev_secret_bin_file_show(struct seq_file *file, void *data)
{
	struct secret_entry *e = file->private;

	if (e)
		seq_write(file, e->data, secret_entry_data_len(e));

	return 0;
}
DEFINE_SHOW_ATTRIBUTE(sev_secret_bin_file);

static inline struct sev_secret *sev_secret_get(void)
{
	return &the_sev_secret;
}

static int sev_secret_map_area(void)
{
	struct sev_secret *s = sev_secret_get();
	struct linux_efi_confidential_computing_secret_area *secret_area;
	u32 secret_area_size;

	if (efi.confidential_computing_secret == EFI_INVALID_TABLE_ADDR) {
		pr_err("Secret area address is not available\n");
		return -EINVAL;
	}

	secret_area =
		memremap(efi.confidential_computing_secret, sizeof(*secret_area), MEMREMAP_WB);
	if (secret_area == NULL) {
		pr_err("Could not map secret area header\n");
		return -ENOMEM;
	}

	secret_area_size = sizeof(*secret_area) + secret_area->size;
	memunmap(secret_area);

	secret_area = memremap(efi.confidential_computing_secret, secret_area_size, MEMREMAP_WB);
	if (secret_area == NULL) {
		pr_err("Could not map secret area\n");
		return -ENOMEM;
	}

	s->secret_area = secret_area;
	return 0;
}

static void sev_secret_securityfs_teardown(void)
{
	struct sev_secret *s = sev_secret_get();
	int i;

	for (i = (SEV_SECRET_NUM_FILES - 1); i >= 0; i--)
		if (s->fs_files[i])
			securityfs_remove(s->fs_files[i]);

	if (s->fs_dir)
		securityfs_remove(s->fs_dir);

	pr_debug("Removed sev_secret securityfs entries\n");
}

static int sev_secret_securityfs_setup(void)
{
	efi_guid_t tableheader_guid = EFI_SEVSECRET_TABLE_HEADER_GUID;
	struct sev_secret *s = sev_secret_get();
	int ret = 0, i = 0, bytes_left;
	unsigned char *ptr;
	struct secret_header *h;
	struct secret_entry *e;
	struct dentry *dent;
	char guid_str[EFI_VARIABLE_GUID_LEN + 1];

	s->fs_dir = NULL;
	memset(s->fs_files, 0, sizeof(s->fs_files));

	dent = securityfs_create_dir("sev_secret", NULL);
	if (IS_ERR(dent)) {
		pr_err("Error creating SEV secret securityfs directory entry");
		return PTR_ERR(dent);
	}
	s->fs_dir = dent;

	ptr = s->secret_area->area;
	h = (struct secret_header *)ptr;
	if (memcmp(&h->guid, &tableheader_guid, sizeof(h->guid))) {
		pr_err("SEV secret area does not start with correct GUID\n");
		ret = -EINVAL;
		goto err_cleanup;
	}
	if (h->len < sizeof(*h)) {
		pr_err("SEV secret area reported length is too small\n");
		ret = -EINVAL;
		goto err_cleanup;
	}

	bytes_left = h->len - sizeof(*h);
	ptr += sizeof(*h);
	while (bytes_left >= (int)sizeof(*e) && i < SEV_SECRET_NUM_FILES) {
		e = (struct secret_entry *)ptr;
		if (e->len < sizeof(*e) || e->len > (unsigned int)bytes_left) {
			pr_err("SEV secret area is corrupted\n");
			ret = -EINVAL;
			goto err_cleanup;
		}

		efi_guid_to_str(&e->guid, guid_str);

		dent = securityfs_create_file(guid_str, 0440, s->fs_dir, (void *)e,
					      &sev_secret_bin_file_fops);
		if (IS_ERR(dent)) {
			pr_err("Error creating SEV secret securityfs entry\n");
			ret = PTR_ERR(dent);
			goto err_cleanup;
		}

		s->fs_files[i++] = dent;
		ptr += e->len;
		bytes_left -= e->len;
	}

	pr_debug("Created %d entries in sev_secret securityfs\n", i);
	return 0;

err_cleanup:
	sev_secret_securityfs_teardown();
	return ret;
}

static void sev_secret_unmap_area(void)
{
	struct sev_secret *s = sev_secret_get();

	if (s->secret_area) {
		memunmap(s->secret_area);
		s->secret_area = NULL;
	}
}

static int __init sev_secret_init(void)
{
	int ret;

	ret = sev_secret_map_area();
	if (ret)
		return ret;

	ret = sev_secret_securityfs_setup();
	if (ret)
		goto err_unmap;

	return ret;

err_unmap:
	sev_secret_unmap_area();
	return ret;
}

static void __exit sev_secret_exit(void)
{
	sev_secret_securityfs_teardown();
	sev_secret_unmap_area();
}

module_init(sev_secret_init);
module_exit(sev_secret_exit);

MODULE_DESCRIPTION("AMD SEV confidential computing secret area access");
MODULE_AUTHOR("IBM");
MODULE_LICENSE("GPL");
