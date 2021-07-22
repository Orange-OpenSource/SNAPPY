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


#include "lsmpp_fs.h"
#include "lsmpp.h"


//#define LSMPP_SFS_NAME "lsmpp"

//extern struct lsmpp_hook lsmpp_hook_array[];

static struct dentry *lsmpp_dir, *lsmpp_policy_dir;

struct lsmpp_hook *get_hook_from_fd(int fd) {
    struct fd f = fdget(fd);
    struct lsmpp_hook *h;
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

    /*if (!is_lsmpp_hook_file(f.file)) {
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
	struct lsmpp_hook *h;
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

static int hook_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &seq_ops);
}

static const struct file_operations lsmpp_hook_ops = {
	.open		= hook_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
};

int lsmpp_fs_initialized;

bool is_lsmpp_hook_file(struct file *f)
{
	return f->f_op == &lsmpp_hook_ops;
}

void lsmpp_free_hook(struct lsmpp_hook *h)
{
	securityfs_remove(h->h_dentry);
	h->h_dentry = NULL;
}
int lsmpp_init_hook(struct lsmpp_hook *h) {
	struct dentry *h_dentry;

	h_dentry = securityfs_create_file(h->name, 0777, lsmpp_policy_dir,
			NULL, &lsmpp_hook_ops);

	if (IS_ERR(h_dentry))
		return PTR_ERR(h_dentry);

	mutex_init(&h->mutex);
	h_dentry->d_fsdata = h;
	h->h_dentry = h_dentry;
	return 0;
}

static const struct file_operations lsmpp_load_ops = {
    .open   = &lsmpp_load_open,
    .write  = &lsmpp_load_write,
    .release= &lsmpp_load_release,
};


static const struct file_operations lsmpp_list_ops = {
	.read = lsmpp_get_helpers,
};

/*static const tree_descr lsmpp_files[] = {
	{"lsmpp_load", 0600, &lsmpp_load_ops},
	{"list_helpers", 0777, &lsmpp_load_ops},
};*/

static int __init lsmpp_fs_policy_init(void) {
	struct dentry* h_dentry = securityfs_create_file("lsmpp_load", 0600, lsmpp_dir, NULL, &lsmpp_load_ops);
	if(IS_ERR(h_dentry)) {
		printk(KERN_INFO "ERROR");
		return PTR_ERR(h_dentry);
	}
	h_dentry = securityfs_create_file("list_helpers", 0777, lsmpp_dir, NULL, &lsmpp_list_ops);
	if(IS_ERR(h_dentry)) {
		printk(KERN_INFO "ERROR");
		return PTR_ERR(h_dentry);
	}

	return 0;
}

static int __init lsmpp_fs_init(void)
{

	//struct lsmpp_hook *hook;
	int ret;

	lsmpp_dir = securityfs_create_dir(LSMPP_SFS_NAME, NULL);
	if (IS_ERR(lsmpp_dir)) {
		ret = PTR_ERR(lsmpp_dir);
		pr_err("Unable to create lsmpp sysfs dir: %d\n", ret);
		lsmpp_dir = NULL;
		return ret;
	}

	lsmpp_policy_dir = securityfs_create_dir(LSMPP_POLICIES_DIR_NAME, lsmpp_dir);
	if (IS_ERR(lsmpp_policy_dir)) {
		ret = PTR_ERR(lsmpp_policy_dir);
		pr_err("Unable to create lsmpp sysfs dir: %d\n", ret);
		lsmpp_policy_dir = NULL;
		return ret;
	}


	/**
	 * Setup I/O interaction with LSM++
	 * Used for setting up BPF helpers, setting jails...
	 * 
	 */
	lsmpp_fs_policy_init();	

	/*
	 * If there is an error in initializing a hook, the initialization
	 * logic makes sure that it has been freed, but this means that
	 * cleanup should be called for all the other hooks. The cleanup
	 * logic handles uninitialized data.
	 */
	/*lsmpp_for_each_hook(hook) {
		ret = lsmpp_init_hook(hook, lsmpp_dir);
		if (ret < 0)
			goto error;
	}
	*/
	//lsmpp_fs_initialized = 1;
	return 0;
/*error:
	lsmpp_for_each_hook(hook)
		lsmpp_free_hook(hook);
	securityfs_remove(lsmpp_dir);
	return ret;
*/
}

late_initcall(lsmpp_fs_init);
