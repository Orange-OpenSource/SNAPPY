// SPDX-License-Identifier: GPL-2.0-only
/*
*
* SNAPPY Linux Security Module
*
* Author: Maxime Bélair <maxime.belair@orange.com>
*
* Copyright (C) 2020 - 2021 Orange
*/

#include <linux/err.h>
#include <linux/init.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/filter.h>
#include <linux/seq_file.h>
#include <linux/bpf.h>
#include <linux/security.h>

#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>


#include "snappy_fs.h"
#include "snappy.h"


//#define SNAPPY_SFS_NAME "snappy"

//extern struct snappy_hook snappy_hook_array[];

static struct dentry *snappy_dir, *snappy_policy_dir;

struct snappy_hook *get_hook_from_fd(int fd) {
    struct fd f = fdget(fd);
    struct snappy_hook *h;
    int ret;

    if (!f.file) {
        ret = -EBADF;
        goto error;
    }

    /*
     * Only CAP_MAC_ADMIN users are allowed to make
     * changes to LSM hooks
     */
    if (sysctl_unprivileged_bpf_disabled && !capable(CAP_MAC_ADMIN)) {
        ret = -EPERM;
        goto error;
    }

    /*if (!is_snappy_hook_file(f.file)) {
        ret = -EINVAL;
        goto error;
    }*/
	/*
     * It's wrong to attach the program to the hook
     * if the file is not opened for a write. Note that,
     * this is an EBADF and not an EPERM because the file
     * has been opened with an incorrect mode.
     */
    if (!(f.file->f_mode & FMODE_WRITE)) {
        ret = -EBADF;
        goto error;
    }

    /*
     * The securityfs dentry never disappears, so we don't need to take a
     * reference to it.
     */
    h = file_dentry(f.file)->d_fsdata;
    if (WARN_ON(!h)) {
        ret = -EINVAL;
        goto error;
    }
    fdput(f);
    return h;

error:
    fdput(f);
    return ERR_PTR(ret);
}
/*
static void *seq_start(struct seq_file *m, loff_t *pos)
	__acquires(rcu) {
	struct snappy_hook *h;
	struct dentry *dentry;
	ruct bpf_prog_array *progs;
	struct bpf_prog_array_item *item;

	 *
	 * rcu_read_lock() must be held before any return statement
	 * because the stop() will always be called and thus call
	 * rcu_read_unlock()
	 *
	rcu_read_lock();

	dentry = file_dentry(m->file);
	h = dentry->d_fsdata;
	if (WARN_ON(!h))
		return ERR_PTR(-EFAULT);

	progs = rcu_dereference(h->progs);
	if ((*pos) >= bpf_prog_array_length(progs))
		return NULL;

	item = progs->items + *pos;
	if (!item->prog)
		return NULL;

	return item;
}
*//*
static void *seq_next(struct seq_file *m, void *v, loff_t *pos)
{
	struct bpf_prog_array_item *item = v;

	item++;
	++*pos;

	if (!item->prog)
		return NULL;

	return item;
}
*//*
static void seq_stop(struct seq_file *m, void *v)
	__releases(rcu)
{
	rcu_read_unlock();
}

static int show_prog(struct seq_file *m, void *v)
{
	struct bpf_prog_array_item *item = v;

	seq_printf(m, "%s\n", item->prog->aux->name);
	return 0;
}
*/
static const struct seq_operations seq_ops = {
	/*.show	= show_prog,
	.start	= seq_start,
	.next	= seq_next,
	.stop	= seq_stop,*/
};

//static int hook_open(struct inode *inode, struct file *file)
//{
//	return seq_open(file, &seq_ops);
//}

static const struct file_operations snappy_hook_ops = {
	.read 		= snappy_get_bpf,
	.open		= snappy_hook_open,
	.write		= snappy_remove_bpf,
	//.read		= seq_read,
	//.llseek		= seq_lseek,
	//.release	= seq_release,
};

int snappy_fs_initialized;

bool is_snappy_hook_file(struct file *f)
{
	return f->f_op == &snappy_hook_ops;
}

void snappy_free_hook(struct snappy_hook *h)
{
	securityfs_remove(h->h_dentry);
	h->h_dentry = NULL;
}
int snappy_init_hook(struct snappy_hook *h) {
	struct dentry *h_dentry;
	int*type = kmalloc(sizeof(int) , GFP_KERNEL);
	*type = h->h_type;
	h_dentry = securityfs_create_file(h->name, 0777, snappy_policy_dir, type, &snappy_hook_ops);

	if (IS_ERR(h_dentry))
		return PTR_ERR(h_dentry);

	mutex_init(&h->mutex);
	h_dentry->d_fsdata = h;
	h->h_dentry = h_dentry;
	return 0;
}

static const struct file_operations snappy_load_ops = {
    .open   = &snappy_load_open,
    .write  = &snappy_load_write,
    .release= &snappy_load_release,
};


static const struct file_operations snappy_list_ops = {
	.read = snappy_get_helpers,
};

//static const struct file_operations snappy_list_bpf_ops = {
//	.read = snappy_get_bpf,
//};



/*static const tree_descr snappy_files[] = {
	{"snappy_load", 0600, &snappy_load_ops},
	{"list_helpers", 0777, &snappy_load_ops},
};*/

static int __init snappy_fs_policy_init(void) {
	struct dentry* h_dentry = securityfs_create_file("snappy_load", 0600, snappy_dir, NULL, &snappy_load_ops);
	if(IS_ERR(h_dentry)) {
		printk(KERN_INFO "ERROR");
		return PTR_ERR(h_dentry);
	}
	h_dentry = securityfs_create_file("list_helpers", 0777, snappy_dir, NULL, &snappy_list_ops);
	if(IS_ERR(h_dentry)) {
		printk(KERN_INFO "ERROR");
		return PTR_ERR(h_dentry);
	}

//	h_dentry = securityfs_create_file("list_bpf", 0777, snappy_dir, NULL, &snappy_list_bpf_ops);
//	if(IS_ERR(h_dentry)) {
//		printk(KERN_INFO "ERROR");
//		return PTR_ERR(h_dentry);
//	}

	return 0;
}


static int __init snappy_fs_init(void)
{

	//struct snappy_hook *hook;
	int ret;

	snappy_dir = securityfs_create_dir(SNAPPY_SFS_NAME, NULL);
	if (IS_ERR(snappy_dir)) {
		ret = PTR_ERR(snappy_dir);
		pr_err("Unable to create snappy sysfs dir: %d\n", ret);
		snappy_dir = NULL;
		return ret;
	}

	snappy_policy_dir = securityfs_create_dir(SNAPPY_POLICIES_DIR_NAME, snappy_dir);
	if (IS_ERR(snappy_policy_dir)) {
		ret = PTR_ERR(snappy_policy_dir);
		pr_err("Unable to create snappy sysfs dir: %d\n", ret);
		snappy_policy_dir = NULL;
		return ret;
	}


	/**
	 * Setup I/O interaction with Snappy
	 * Used for setting up BPF helpers, setting jails...
	 * 
	 */
	snappy_fs_policy_init();	

	/*
	 * If there is an error in initializing a hook, the initialization
	 * logic makes sure that it has been freed, but this means that
	 * cleanup should be called for all the other hooks. The cleanup
	 * logic handles uninitialized data.
	 */
	/*snappy_for_each_hook(hook) {
		ret = snappy_init_hook(hook, snappy_dir);
		if (ret < 0)
			goto error;
	}
	*/
	//snappy_fs_initialized = 1;
	return 0;
/*error:
	snappy_for_each_hook(hook)
		snappy_free_hook(hook);
	securityfs_remove(snappy_dir);
	return ret;
*/
}

late_initcall(snappy_fs_init);
