/**
 *
 * @Author Sarah Alvarez (sarahal1@umbc.edu)
 * This file contains the implementation for a pwkeeper device module.
 * 
 * Cited Sources:
 *  * https://stackoverflow.com/questions/39229639/how-to-get-current-processs-uid-and-euid-in-linux-kernel-4-2
 *
 */

/*
 * This file uses kernel-doc style comments, which is similar to
 * Javadoc and Doxygen-style comments. See
 * ~/linux/Documentation/doc-guide/kernel-doc.rst for details.
 */

/*
 * Getting compilation warnings? The Linux kernel is written against
 * C89, which means:
 *  - No // comments, and
 *  - All variables must be declared at the top of functions.
 * Read ~/linux/Documentation/process/coding-style.rst to ensure your
 * project compiles without warnings.
 */

#define pr_fmt(fmt) "pwkeeper: " fmt

#include <linux/pid_namespace.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/gfp.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/list.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/uidgid.h>
#include <linux/vmalloc.h>
#include <asm/uaccess.h>
#include <crypto/hash.h>

#include "xt_cs421net.h"

#define MASTERPW_LEN 32
#define ACCOUNTNAME_LEN 16
#define ACCOUNTPW_LEN 16

struct master_entry {
	struct list_head list;
	kuid_t user_id;
	unsigned char umaster_pass[MASTERPW_LEN];
};

struct account_entry {
	struct list_head list;
	kuid_t user_id;
	char account_name[ACCOUNTNAME_LEN + 1];
	unsigned char uaccount_pass[ACCOUNTPW_LEN + 1];
};

static LIST_HEAD(master_list);
static LIST_HEAD(account_list);
static DEFINE_SPINLOCK(spinny);

/**
 * sha3_digest() - calculate the SHA-3 digest for an arbitrary input buffer
 * @input: input data buffer
 * @input_len: number of bytes in @input
 * @digest: destination pointer to store digest
 * @digest_len: size of digest buffer (in/out parameter)
 *
 * Hash the input buffer pointed to by @input, up to @input_len
 * bytes. Store the resulting digest at @digest. Afterwards, update
 * the value pointed to by @digest_len by the size of the stored
 * digest.
 *
 * <strong>You do not need to modify this function.</strong>
 *
 * Return: 0 on success, negative on error
 */
static int sha3_digest(const void *input, size_t input_len, u8 * digest,
		       size_t * digest_len)
{
	struct crypto_shash *sha3_tfm;
	struct shash_desc *sha3_desc;
	unsigned int digestsize;
	size_t i;
	int retval;

	sha3_tfm = crypto_alloc_shash("sha3-512", 0, 0);
	if (IS_ERR_OR_NULL(sha3_tfm)) {
		pr_err("Could not allocate hash tfm: %ld\n", PTR_ERR(sha3_tfm));
		return PTR_ERR(sha3_tfm);
	}

	digestsize = crypto_shash_digestsize(sha3_tfm);
	if (*digest_len < digestsize) {
		pr_err("Digest buffer too small, need at least %u bytes\n",
		       digestsize);
		retval = -EINVAL;
		goto out;
	}

	sha3_desc =
	    kzalloc(sizeof(*sha3_desc) + crypto_shash_descsize(sha3_tfm),
		    GFP_KERNEL);
	if (!sha3_desc) {
		pr_err("Could not allocate hash desc\n");
		retval = -ENOMEM;
		goto out;
	}
	sha3_desc->tfm = sha3_tfm;
	sha3_desc->flags = CRYPTO_TFM_REQ_MAY_SLEEP;

	retval = crypto_shash_digest(sha3_desc, input, input_len, digest);
	*digest_len = digestsize;
	pr_info("Hashed %zu bytes, digest = ", input_len);
	for (i = 0; i < digestsize; i++)
		pr_cont("%02x", digest[i]);
	pr_info("\n");
	kfree(sha3_desc);
out:
	crypto_free_shash(sha3_tfm);
	return retval;
}

/**
 * kdf() - calculate the 16 byte account password
 * @password : buffer where final password should go
 * @m_pass : master password
 * @a_name : account name
 *
 * Follow the steps outlined in the project description to create
 * Account password. 
 *
 * Return: nothing
 */
void kdf(unsigned char *password, unsigned char *m_pass, unsigned char *a_name)
{
	int value = MASTERPW_LEN + ACCOUNTNAME_LEN;
	unsigned char temp[value];
	unsigned char digest_buffer[64];
	size_t digest_len = sizeof(digest_buffer);
	int i;
	int j;

	/* Set first 32 bytes to user's master password */
	for (i = 0; i < MASTERPW_LEN; i++)
		temp[i] = m_pass[i];

	/* Set the last 16 bytes to the account name */
	j = MASTERPW_LEN;
	for (i = 0; i < ACCOUNTNAME_LEN; i++) {
		temp[j] = a_name[i];
		j++;
	}

	/* Hash the temp buffer using SHA3 */
	sha3_digest(temp, value, digest_buffer, &digest_len);

	/* Take lower 6 bits of byte and add 48. Store as ith byte of password */
	for (i = 0; i < ACCOUNTPW_LEN; i++) {
		password[i] = (digest_buffer[i] & 0x3F) + 0x30;
	}
	password[ACCOUNTPW_LEN] = '\0';
}

/**
 * pwkeeper_master_write() - callback invoked when a process writes to
 * /dev/pwkeeper_master
 * @filp: process's file object that is writing to this device (ignored)
 * @ubuf: source buffer from user
 * @count: number of bytes in @ubuf
 * @ppos: file offset (in/out parameter)
 *
 * If *@ppos does not point to zero, do nothing and return -EINVAL.
 *
 * Copy the contents of @ubuf to the master password for the user, the
 * lesser of @count and MASTERPW_LEN. Then increment the value pointed
 * to by @ppos by the number of bytes copied.
 *
 * When replacing an existing master password, recalculate all account
 * passwords.
 *
 * <em>Caution: @ubuf is not a string; it is not null-terminated.</em>
 *
 * Return: number of bytes copied from @ubuf, or negative on error
 */
static ssize_t pwkeeper_master_write(struct file *filp,
				     const char __user * ubuf, size_t count,
				     loff_t * ppos)
{
	int retval;
	int i;
	int user_exists = -1;	/* -1 is nonexistent, 1 for exist */
	struct master_entry *entry;
	const struct cred *cred = current_cred();
	kuid_t curr_user_id = cred->uid;
	size_t bytes_to_copy;

	/* If ppos does not point to 0, return -EINVAL */
	if (*ppos != 0) {
		printk("Write error, ppos = %lld\n", *ppos);
		return -EINVAL;
	}
	printk("ppos = %lld\n", *ppos);
	/* Check if user exists in the master_list LL */
	spin_lock(&spinny);
	if (!list_empty(&master_list)) {
		printk("master list is not empty. Searching through KLL...\n");
		list_for_each_entry(entry, &master_list, list) {
			/* If user exists, update their password */
			if ((entry->user_id).val == curr_user_id.val) {
				printk
				    ("User exists! Modifying the password...\n");
				user_exists = 1;
				/* Get lesser of count and MASTERPW_LEN */
				bytes_to_copy =
				    (count <=
				     MASTERPW_LEN ? count : MASTERPW_LEN);
				/* If bytes_to_copy is less than 32 bytes, pad with null bytes (Assume 0x0 not \0) */
				if (bytes_to_copy < MASTERPW_LEN) {
					for (i = MASTERPW_LEN - 1;
					     i >= bytes_to_copy; i--) {
						entry->umaster_pass[i] = '\0';
					}
				}
				/* Copy from ubuf */
				retval =
				    copy_from_user(entry->umaster_pass, ubuf,
						   bytes_to_copy);
				if (retval != 0) {
					printk("Write error\n");
					spin_unlock(&spinny);
					return retval;
				}
				/* Increment ppos by number of bytes copied */
				*ppos += bytes_to_copy;
			}
		}
	}

	/* If user does not exist, create new entry and set password */
	if (user_exists == -1) {
		printk("User does not exist and/or KLL is empty\n");
		entry = kmalloc(sizeof(*entry), GFP_KERNEL);
		if (!entry) {
			spin_unlock(&spinny);
			return -ENOMEM;
		}
		entry->user_id = curr_user_id;
		/* Get lesser of count and MASTERPW_LEN */
		bytes_to_copy = (count <= MASTERPW_LEN ? count : MASTERPW_LEN);
		printk("bytes_to_copy = %ld\n", bytes_to_copy);
		/* If bytes_to_copy is less than 32 bytes, pad with null bytes (Assume 0x0 not \0) */
		if (bytes_to_copy < MASTERPW_LEN) {
			for (i = MASTERPW_LEN - 1; i >= bytes_to_copy; i--) {
				entry->umaster_pass[i] = '\0';
			}
		}
		/* Copy from ubuf */
		retval =
		    copy_from_user(entry->umaster_pass, ubuf, bytes_to_copy);
		if (retval != 0) {
			printk("Write error\n");
			spin_unlock(&spinny);
			return retval;
		}
		/* Increment ppos by number of bytes copied */
		*ppos += bytes_to_copy;

		list_add_tail(&entry->list, &master_list);
	}
	spin_unlock(&spinny);
	printk("RETURNING!\n");
	return bytes_to_copy;
}

/**
 * pwkeeper_account_read() - callback invoked when a process reads
 * from /dev/pwkeeper_account
 * @filp: process's file object that is reading from this device (ignored)
 * @ubuf: destination to store account password
 * @count: number of bytes in @ubuf
 * @ppos: file offset (in/out parameter)
 *
 * Write to @ubuf the password generated for the most recently written
 * account name for the current UID, offset by @ppos. Copy the lesser
 * of @count and (ACCOUNTPW_LEN - *@ppos). Then increment the value
 * pointed to by @ppos by the number of bytes written. If @ppos is
 * greater than or equal to ACCOUNTPW_LEN, then write
 * nothing.
 *
 * If no account name was set (via previous successful invocation of
 * pwkeeper_account_write()), do nothing and return -ENOKEY.
 *
 * Return: number of bytes written to @ubuf, 0 on end of file, or
 * negative on error
 */
static ssize_t pwkeeper_account_read(struct file *filp, char __user * ubuf,
				     size_t count, loff_t * ppos)
{
	int accounts_searched = 0;
	int retval;
	int user_exists = -1;
	int account_exists = -1;
	size_t bytes_to_read;
	size_t bytes_allowed;
	struct master_entry *m_entry;
	struct account_entry *a_entry;
	struct account_entry *recent = NULL;
	const struct cred *cred = current_cred();
	kuid_t curr_user_id = cred->uid;

	unsigned char *mpass = "";
	unsigned char *aname = "";

	spin_lock(&spinny);
	/* Find the user's master password */
	if (!list_empty(&master_list)) {
		printk("Finding the user's master password\n");
		list_for_each_entry(m_entry, &master_list, list) {
			if ((m_entry->user_id).val == curr_user_id.val) {
				user_exists = 1;
				mpass = m_entry->umaster_pass;
			}
		}
	}

	/* Find most recent account made by current user */
	if (!list_empty(&account_list)) {
		printk("Finding the users recent account\n");
		list_for_each_entry(a_entry, &account_list, list) {
			if ((a_entry->user_id).val == curr_user_id.val) {
				accounts_searched++;
				printk("Account found #%d\n",
				       accounts_searched);
				account_exists = 1;
				recent = a_entry;
				aname = a_entry->account_name;
			}
		}
	}

	/* If no user account exists, return -ENOKEY */
	if (account_exists == -1 || user_exists == -1) {
		printk("User has no accounts\n");
		spin_unlock(&spinny);
		return -ENOKEY;
	}
	/* If user account exists, write to ubuf the password of the account */
	else {
		printk("User has an account so generate password\n");
		/* Generate password using KDF. Write to ubuf and store in account */
		kdf(recent->uaccount_pass, mpass, aname);

		/* If ppos is greater than or equal to ACCOUNTPW_LEN, do nothing */
		if (*ppos >= ACCOUNTPW_LEN) {
			spin_unlock(&spinny);
			return 0;
		}
		bytes_allowed = ACCOUNTPW_LEN - *ppos;
		bytes_to_read =
		    (count <= bytes_allowed ? count : bytes_allowed);

		/* Copy to ubuf */
		retval =
		    copy_to_user(ubuf, recent->uaccount_pass, bytes_to_read);
		if (retval != 0) {
			spin_unlock(&spinny);
			return -EINVAL;
		}
		*ppos += bytes_to_read;
	}
	spin_unlock(&spinny);
	return bytes_to_read;
}

/**
 * pwkeeper_account_write() - callback invoked when a process writes
 * to /dev/pwkeeper_account
 * @filp: process's file object that is writing to this device (ignored)
 * @ubuf: source buffer from user
 * @count: number of bytes in @ubuf
 * @ppos: file offset (in/out parameter)
 *
 * If *@ppos does not point to zero, do nothing and return -EINVAL.
 *
 * If the current user has not set a master password, do nothing and
 * return -ENOKEY.
 *
 * Otherwise check if @ubuf is already in the accounts list associated
 * with the current user. If it is already there, do nothing and
 * return @count.
 *
 * Otherwise, create a new node in the accounts list associated with
 * the current user. Copy the contents of @ubuf to that node, the
 * lesser of @count and ACCOUNTNAME_LEN. Increment the value pointed
 * to by @ppos by the number of bytes copied. Finally, perform the key
 * derivation function as specified in the project description, to
 * determine the account's password.
 *
 * <em>Caution: @ubuf is not a string; it is not null-terminated.</em>
 *
 * Return: @count, or negative on error
 */
static ssize_t pwkeeper_account_write(struct file *filp,
				      const char __user * ubuf, size_t count,
				      loff_t * ppos)
{
	int retval;
	int i;
	int user_exists = -1;
	int account_exists = -1;
	int same_name = 1;
	int same_user = -1;
	struct master_entry *m_entry;
	struct account_entry *a_entry;
	const struct cred *cred = current_cred();
	kuid_t curr_user_id = cred->uid;
	size_t bytes_to_copy;
	unsigned char a_name[ACCOUNTNAME_LEN];

	/* If ppos does not point to 0, return -EINVAL */
	if (*ppos != 0)
		return -EINVAL;

	spin_lock(&spinny);
	/* Check if current user has set a master password */
	if (!list_empty(&master_list)) {
		list_for_each_entry(m_entry, &master_list, list) {
			if ((m_entry->user_id).val == curr_user_id.val) {
				printk
				    ("Current user has set their master password.\n");
				user_exists = 1;
			}
		}
	}
	/* If user not found in master_list, then master password not created */
	if (user_exists == -1) {
		printk("Current user has not set their master password.\n");
		spin_unlock(&spinny);
		return -ENOKEY;
	}
	/* User made master password so proceed with account management */
	else {
		/* Get the name of the account */
		bytes_to_copy =
		    (count <= ACCOUNTNAME_LEN ? count : ACCOUNTNAME_LEN);
		/* Pad with '\0' if needed */
		if (bytes_to_copy < ACCOUNTNAME_LEN) {
			for (i = ACCOUNTNAME_LEN - 1; i >= bytes_to_copy; i--) {
				a_name[i] = '\0';
			}
		}
		/* Copy from ubuf */
		retval = copy_from_user(a_name, ubuf, bytes_to_copy);
		if (retval != 0) {
			spin_unlock(&spinny);
			return -EINVAL;
		}
		*ppos += bytes_to_copy;

		/* Check if account name with same UID already exists */
		printk
		    ("Checking if the account already exists under that user\n");
		if (!list_empty(&account_list)) {
			list_for_each_entry(a_entry, &account_list, list) {
				for (i = 0; i < ACCOUNTNAME_LEN; i++) {
					if (a_name[i] !=
					    (a_entry->account_name)[i]) {
						same_name = -1;
					}
				}
				if ((a_entry->user_id).val == curr_user_id.val) {
					same_user = 1;
				}
				if (same_name == 1 && same_user == 1) {
					printk
					    ("User already made this account\n");
					account_exists = 1;
				}
			}
		}
		/* If doesn't exits, make new account entry */
		if (account_exists == -1) {
			printk
			    ("The account doesn't exist, so make a new one\n");
			a_entry = kmalloc(sizeof(*a_entry), GFP_KERNEL);
			if (!a_entry) {
				spin_unlock(&spinny);
				return -ENOMEM;
			}
			a_entry->user_id = curr_user_id;
			for (i = 0; i < ACCOUNTNAME_LEN; i++) {
				(a_entry->account_name)[i] = a_name[i];
			}

			/* 
			   Don't generate password yet! Easier to generate upon request.
			   This ensures the most up-to-date master password.
			 */

			list_add_tail(&a_entry->list, &account_list);
		}
	}
	spin_unlock(&spinny);
	return bytes_to_copy;
}

static const struct file_operations pwkeeper_master_fops = {
	.write = pwkeeper_master_write,
};

static struct miscdevice pwkeeper_master_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "pwkeeper_master",
	.fops = &pwkeeper_master_fops,
	.mode = 0666
};

static const struct file_operations pwkeeper_account_fops = {
	.read = pwkeeper_account_read,
	.write = pwkeeper_account_write,
};

static struct miscdevice pwkeeper_account_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "pwkeeper_account",
	.fops = &pwkeeper_account_fops,
	.mode = 0666
};

/**
 * pwkeeper_accounts_show() - callback invoked when a process reads from
 * /sys/devices/platform/pwkeeper/accounts
 *
 * @dev: device driver data for sysfs entry (ignored)
 * @attr: sysfs entry context (ignored)
 * @buf: destination to store current user's accounts
 *
 * Write to @buf, up to PAGE_SIZE characters, a human-readable message
 * that lists all accounts registered for the current UID, and the
 * associated account passwords. Note that @buf is a normal character
 * buffer, not a __user buffer. Use scnprintf() in this function.
 *
 * @return Number of bytes written to @buf, or negative on error.
 */
static ssize_t pwkeeper_accounts_show(struct device *dev,
				      struct device_attribute *attr, char *buf)
{
	int written = 0;
	int user_exists = -1;

	const struct cred *cred = current_cred();
	kuid_t curr_user_id = cred->uid;

	struct account_entry *a_entry;
	struct master_entry *m_entry;

	unsigned char *mpass = "";

	spin_lock(&spinny);
	/* Get master password of current user */
	if (!list_empty(&master_list)) {
		list_for_each_entry(m_entry, &master_list, list) {
			if ((m_entry->user_id).val == curr_user_id.val) {
				user_exists = 1;
				mpass = m_entry->umaster_pass;
			}
		}
	}

	written += scnprintf(buf, PAGE_SIZE, "Account  Password\n");
	written +=
	    scnprintf(buf + written, PAGE_SIZE - written,
		      "-------  --------\n");

	if (!list_empty(&account_list) && user_exists == 1) {
		list_for_each_entry(a_entry, &account_list, list) {
			/* Print account name and account password */
			if ((a_entry->user_id).val == curr_user_id.val) {
				/* Generate password just in case */
				kdf(a_entry->uaccount_pass, mpass,
				    a_entry->account_name);
				(a_entry->account_name)[ACCOUNTNAME_LEN] = '\0';
				written +=
				    scnprintf(buf + written,
					      PAGE_SIZE - written, "%s  %s\n",
					      a_entry->account_name,
					      a_entry->uaccount_pass);
			}
		}
	}

	spin_unlock(&spinny);
	return written;
}

/**
 * pwkeeper_master_show() - callback invoked when a process reads from
 * /sys/devices/platform/pwkeeper/masters
 *
 * @dev: device driver data for sysfs entry (ignored)
 * @attr: sysfs entry context (ignored)
 * @buf: destination to store login statistics
 *
 * Check if the calling process has CAP_SYS_ADMIN. If not, return
 * -EPERM.
 *
 * Otherwise, write to @buf, up to PAGE_SIZE characters, a
 * human-readable message that lists all users IDs that have
 * registered master passwords. Note that @buf is a normal character
 * buffer, not a __user buffer. Use scnprintf() in this function.
 *
 * @return Number of bytes written to @buf, or negative on error.
 */
static ssize_t pwkeeper_masters_show(struct device *dev,
				     struct device_attribute *attr, char *buf)
{
	int written = 0;
	struct master_entry *m_entry;
	struct pid_namespace *pid_ns = task_active_pid_ns(current);

	/* Deny calling process if it does not have CAP_SYS_ADMIN capabilities */
	if (!ns_capable(pid_ns->user_ns, CAP_SYS_ADMIN))
		return -EPERM;

	spin_lock(&spinny);
	written += scnprintf(buf, PAGE_SIZE, "Registered UIDs\n");
	written +=
	    scnprintf(buf + written, PAGE_SIZE - written, "---------------\n");

	/* Print out all UIDs */
	if (!list_empty(&master_list)) {
		list_for_each_entry(m_entry, &master_list, list) {
			written +=
			    scnprintf(buf + written, PAGE_SIZE - written,
				      "%d\n", (m_entry->user_id).val);
		}
	}

	spin_unlock(&spinny);
	return written;
}

static DEVICE_ATTR(accounts, S_IRUGO, pwkeeper_accounts_show, NULL);
static DEVICE_ATTR(masters, S_IRUGO, pwkeeper_masters_show, NULL);

/**
 * cs421net_top() - top-half of CS421Net ISR
 * @irq: IRQ that was invoked (ignored)
 * @cookie: Pointer to data that was passed into
 * request_threaded_irq() (ignored)
 *
 * If @irq is CS421NET_IRQ, then wake up the bottom-half. Otherwise,
 * return IRQ_NONE.
 */
static irqreturn_t cs421net_top(int irq, void *cookie)
{
	if (irq == CS421NET_IRQ) {
		return IRQ_WAKE_THREAD;
	} else {
		return IRQ_NONE;
	}
}

/**
 * cs421net_bottom() - bottom-half to CS421Net ISR
 * @irq: IRQ that was invoked (ignore)
 * @cookie: Pointer that was passed into request_threaded_irq()
 * (ignored)
 *
 * Fetch the incoming packet, via cs421net_get_data(). Treat the input
 * as a 32-BIT LITTLE ENDIAN BINARY VALUE representing a UID. Search
 * through the master list and accounts list, deleting all nodes with
 * that UID. If the UID is exactly zero, then delete ALL nodes in the
 * master and accounts lists.
 *
 * If the packet length is not exactly 4 bytes, or if the provided
 * value does not match a registered UID in the master list, then do
 * nothing.
 *
 * Remember to add appropriate spin lock calls in this function.
 *
 * <em>Caution: The incoming payload is not a string; it is not null-terminated.</em>
 * You can NOT use strcpy() or strlen() on it.
 *
 * Return: always IRQ_HANDLED
 */
static irqreturn_t cs421net_bottom(int irq, void *cookie)
{
	/* Part 5: YOUR CODE HERE */
	char *incoming;
	size_t packet_size = 4;
	int recieved_uid = 0;

	struct master_entry *m_entry, *m_temp;
	struct account_entry *a_entry, *a_temp;

	incoming = cs421net_get_data(&packet_size);

	/* Convert to decimal for easy use */
	if (incoming[0] < 0)
		recieved_uid += (incoming[0] - 0xFFFFFF00);
	else
		recieved_uid += incoming[0];
	recieved_uid += incoming[1] * 16 * 16;
	recieved_uid += incoming[2] * 16 * 16 * 16 * 16;
	recieved_uid += incoming[3] * 16 * 16 * 16 * 16 * 16 * 16 * 16 * 16;
	printk("UID = %d\n", recieved_uid);

	/* Find every thing with this UID and delete it */
	spin_lock(&spinny);
	/* Search through and delete matching entries in master_list */
	if (!list_empty(&master_list)) {
		list_for_each_entry_safe(m_entry, m_temp, &master_list, list) {
			if ((m_entry->user_id).val == recieved_uid) {
				list_del(&m_entry->list);
				kfree(m_entry);
			}
		}
	}

	/* Search through and delete matching entries in account_list */
	if (!list_empty(&account_list)) {
		list_for_each_entry_safe(a_entry, a_temp, &account_list, list) {
			if ((a_entry->user_id).val == recieved_uid) {
				list_del(&a_entry->list);
				kfree(a_entry);
			}
		}
	}

	spin_unlock(&spinny);
	return IRQ_HANDLED;
}

/**
 * pwkeeper_probe() - callback invoked when this driver is probed
 * @pdev platform device driver data (ignored)
 *
 * Return: 0 on successful probing, negative on error
 */
static int pwkeeper_probe(struct platform_device *pdev)
{
	int retval;

	retval = misc_register(&pwkeeper_master_dev);
	if (retval) {
		pr_err("Could not register master device\n");
		goto err;
	}

	retval = misc_register(&pwkeeper_account_dev);
	if (retval) {
		pr_err("Could not register account device\n");
		goto err_deregister_master;
	}

	retval = device_create_file(&pdev->dev, &dev_attr_accounts);
	if (retval) {
		pr_err("Could not create sysfs entry\n");
		goto err_deregister_account;
	}

	retval = device_create_file(&pdev->dev, &dev_attr_masters);
	if (retval) {
		pr_err("Could not create sysfs entry\n");
		goto err_remove_sysfs_accounts;
	}

	/*
	 * In part 5, register the ISR and enable network
	 * integration. Make sure you clean up upon error.
	 */
	retval =
	    request_threaded_irq(CS421NET_IRQ, cs421net_top, cs421net_bottom, 0,
				 "Proj 2 IRQ", NULL);
	if (retval) {
		pr_err("Could not register IRQ\n");
		goto err_remove_sysfs_masters;
	}
	cs421net_enable();

	pr_info("Probe successful\n");
	return 0;

err_remove_sysfs_masters:
	device_remove_file(&pdev->dev, &dev_attr_masters);
err_remove_sysfs_accounts:
	device_remove_file(&pdev->dev, &dev_attr_accounts);
err_deregister_account:
	misc_deregister(&pwkeeper_account_dev);
err_deregister_master:
	misc_deregister(&pwkeeper_master_dev);
err:
	pr_err("Probe failed, error %d\n", retval);
	return retval;

}

/**
 * pwkeeper_remove() - callback when this driver is removed
 * @pdev platform device driver data (ignored)
 *
 * Return: Always 0
 */
static int pwkeeper_remove(struct platform_device *pdev)
{
	struct master_entry *m_entry, *m_temp;
	struct account_entry *a_entry, *a_temp;
	pr_info("Removing\n");

	/*
	 * In part 5, disable network integration and remove the ISR.
	 */
	cs421net_disable();
	free_irq(CS421NET_IRQ, NULL);

	/*
	 * In part 3, free all memory associated with accounts list.
	 */
	spin_lock(&spinny);
	list_for_each_entry_safe(a_entry, a_temp, &account_list, list) {
		list_del(&a_entry->list);
		kfree(a_entry);
	}
	INIT_LIST_HEAD(&account_list);
	spin_unlock(&spinny);

	/*
	 * In part 2, free all memory associated with master password
	 * list.
	 */
	spin_lock(&spinny);
	list_for_each_entry_safe(m_entry, m_temp, &master_list, list) {
		list_del(&m_entry->list);
		kfree(m_entry);
	}
	INIT_LIST_HEAD(&master_list);
	spin_unlock(&spinny);

	device_remove_file(&pdev->dev, &dev_attr_masters);
	device_remove_file(&pdev->dev, &dev_attr_accounts);
	misc_deregister(&pwkeeper_account_dev);
	misc_deregister(&pwkeeper_master_dev);
	return 0;
}

static struct platform_driver cs421_driver = {
	.driver = {
		   .name = "pwkeeper",
		   },
	.probe = pwkeeper_probe,
	.remove = pwkeeper_remove,
};

static struct platform_device *pdev;

/**
 * cs421_init() -  create the platform driver
 * This is needed so that the device gains a sysfs group.
 *
 * <strong>You do not need to modify this function.</strong>
 */
static int __init cs421_init(void)
{
	pdev = platform_device_register_simple("pwkeeper", -1, NULL, 0);
	if (IS_ERR(pdev))
		return PTR_ERR(pdev);
	return platform_driver_register(&cs421_driver);
}

/**
 * cs421_exit() - remove the platform driver
 * Unregister the driver from the platform bus.
 *
 * <strong>You do not need to modify this function.</strong>
 */
static void __exit cs421_exit(void)
{
	platform_driver_unregister(&cs421_driver);
	platform_device_unregister(pdev);
}

module_init(cs421_init);
module_exit(cs421_exit);

MODULE_DESCRIPTION("CS421 Password Keeper - project 2");
MODULE_LICENSE("GPL");
