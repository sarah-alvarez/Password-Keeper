/**
 *
 * @Author Sarah Alvarez (sarahal1@umbc.edu)
 * This file contains the unit tests for the pwkeeper module.
 * 
 * Cited Sources:
 *  * https://stackoverflow.com/questions/39229639/how-to-get-current-processs-uid-and-euid-in-linux-kernel-4-2
 *
 */

#include "cs421net.h"
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <errno.h>

/**
 * num_account() - calculate how many accounts a user has
 * @str : buffer that holds output from accounts_show() in pwkeeper.c
 *
 * Iterates though @str and counts '\n' until '\0' is found.
 *
 * Return : number of accounts found
 */
int num_account(char *str)
{
	int num_of_accounts = 0;
	int index = 36;		// Bypass unecessary chars
	char currchar = str[index];
	while (currchar != '\0') {
		if (currchar == '\n')
			num_of_accounts++;
		index++;
		currchar = str[index];
	}
	return num_of_accounts;
}

/**
 * main() - run tests
 *
 * Do all unit tests
 *
 * Return : 0 always
 */
int main(void)
{
	int tests_passed = 0;	// number of tests passed
	int num_tests = 10;	// total number of tests
	char *password = "mypassword";
	char *longpassword = "passwordpasswordpasswordpasswordpassword";
	char *account = "myaccountname";
	char *longaccount = "accountaccountaccount";
	int master_fd = open("/dev/pwkeeper_master", O_RDWR);
	int account_fd = open("/dev/pwkeeper_account", O_RDWR);
	int acread_fd =
	    open("/sys/devices/platform/pwkeeper/accounts", O_RDONLY);

	char temp[32] = { '\0' };
	char buf[PAGE_SIZE] = { '\0' };

	cs421net_init();

/* Test 1: Create an account without a master password */
	printf("***TEST 1\n");
	printf("   Writing '%s' to /dev/pwkeeper_account\n", account);
	printf("   Should return error...\n");
	if (write(account_fd, account, 13) < 0) {
		perror("   Returned error! ");
		printf("***PASSED TEST 1\n\n");
		tests_passed++;
	} else {
		printf("   Did not return error\n");
		printf("***FAILED TEST 1\n\n");
	}

/* Test 2: Create a master password */
/* Can't actually check contents because no read callback for pwkeeper_master */
	printf("***TEST 2\n");
	printf("   Writing '%s' to /dev/pwkeeper_master\n", password);
	printf("   Should not return error...\n");
	if (write(master_fd, password, 10) < 0) {
		perror("   Returned error! ");
		printf("***FAILED TEST 2\n\n");
	} else {
		printf("   Did not return error\n");
		printf("***PASSED TEST 2\n\n");
		tests_passed++;
	}

/* Test 3: Attempt to read the master password */
	printf("***TEST 3\n");
	printf("   Attempting to read from /dev/pwkeeper_master\n");
	printf("   Should return error...\n");
	if (read(master_fd, temp, 32) < 0) {
		perror("   Returned error! ");
		printf("***PASSED TEST 3\n\n");
		tests_passed++;
	} else {
		printf("   Did not return error\n");
		printf("***FAILED TEST 3\n\n");
	}

/* Test 4: Create an account */
/* CHECK CONTENTS */
	printf("***TEST 4\n");
	printf("   Writing %s to /dev/pwkeeper_account\n", account);
	printf("   Should not return error...\n");
	if (write(account_fd, account, 13) < 0) {
		perror("   Returned error! ");
		printf("***FAILED TEST 4\n\n");
	} else {
		printf("   Did not return error\n");
		printf("***PASSED TEST 4\n\n");
		tests_passed++;
	}
	if (read(acread_fd, buf, PAGE_SIZE) < 0) {
		perror("   Returned error! ");
	} else {
		num_account(buf);
	}

/* Test 5: Change master password to something bigger than 32 bytes */
	close(master_fd);
	master_fd = open("/dev/pwkeeper_master", O_RDWR);
	printf("***TEST 5");
	printf("   Write 39 bytes to pwkeeper_master\n");
	printf("   Should return error...\n");
	if (write(master_fd, longpassword, 39) < 0) {
		perror("   Returned error! ");
		printf("***PASSED TEST 5\n\n");
		tests_passed++;
	} else {
		printf("   Did not return error\n");
		printf("***FAILED TEST 5\n\n");
	}

/* Test 6: Try to add the same account again */
	close(account_fd);
	account_fd = open("/dev/pwkeeper_account", O_RDWR);
	close(acread_fd);
	acread_fd = open("/sys/devices/platform/pwkeeper/accounts", O_RDONLY);
	char test6_buf[PAGE_SIZE] = { '\0' };
	printf("***TEST 6\n");
	printf("   Writing %s to /dev/pwkeeper_account again\n", account);
	if (write(account_fd, account, 13) < 0) {
		perror("   Returned error! ");
		printf("***FAILED TEST 6\n\n");
	} else {
		printf("   Reading accounts\n");
		printf("   Should only be 1 account...\n");
		if (read(acread_fd, test6_buf, PAGE_SIZE) < 0) {
			perror("   Returned error! ");
			printf("***FAILED TEST 6\n\n");
		} else {
			int num = num_account(test6_buf);
			printf("\n%s\n", test6_buf);
			if (num == 1) {
				printf("   Only 1 account!\n");
				printf("***PASSED TEST 6\n\n");
				tests_passed++;
			} else {
				printf("   Oh no! There are %d accounts!\n",
				       num);
				printf("***FAILED TEST 6\n\n");
			}
		}
	}

/* Test 7: Try to write account name bigger than 16 bytes */
	close(account_fd);
	account_fd = open("/dev/pwkeeper_account", O_RDWR);
	close(acread_fd);
	acread_fd = open("/sys/devices/platform/pwkeeper/accounts", O_RDONLY);
	char test7_buf[PAGE_SIZE] = { '\0' };
	printf("***TEST 7");
	printf("   Write 21 bytes to pwkeeper_account\n");
	printf("   Should return error...\n");
	if (write(account_fd, longaccount, 21) < 0) {
		perror("   Returned error! ");
		printf("***FAILED TEST 7\n\n");
	} else {
		printf("   Did not return error\n");
		if (read(acread_fd, test7_buf, PAGE_SIZE) < 0) {
			perror("   Returned error! ");
			printf("***FAILED TEST 7\n\n");
		} else {
			int num = num_account(test7_buf);
			printf("\n%s\n", test7_buf);
			if (num == 2) {
				printf("   2 accounts found!\n");
				printf("***PASSED TEST 7\n\n");
				tests_passed++;
			} else {
				printf("   Oh no! There are %d accounts!\n",
				       num);
				printf("***FAILED TEST 7\n\n");
			}
		}
	}

/* Test 8: Send wrong UID to device */
	char payload[4] = { 0x00, 0x08, 0x00, 0x00 };
	char test8_buf[PAGE_SIZE] = { '\0' };
	printf("***TEST 8\n");
	printf("   Sending UID 2048 (Assuming curr UID is 1000)\n");
	if (cs421net_send(payload, 4)) {
		printf("   Send success\n");
		printf("   Checking accounts...");

		close(acread_fd);
		acread_fd =
		    open("/sys/devices/platform/pwkeeper/accounts", O_RDONLY);
		if (read(acread_fd, test8_buf, PAGE_SIZE) < 0) {
			perror("   Returned error! ");
			printf("***FAILED TEST 8\n\n");
		} else {
			int num = num_account(test8_buf);
			printf("\n%s\n", test8_buf);
			if (num == 2) {
				printf("   2 accounts found!\n");
				printf("***PASSED TEST 8\n\n");
				tests_passed++;
			} else {
				printf("   Oh no! There are %d accounts!\n",
				       num);
				printf("***FAILED TEST 8\n\n");
			}
		}

	} else {
		printf("   Send fail\n");
		printf("***FAILED TEST 8\n\n");
	}

/* Test 9: Send more than 4 bytes to device */
	char payload2[5] = { 0x00, 0x08, 0x07, 0x00, 0x00 };
	char test9_buf[PAGE_SIZE] = { '\0' };
	printf("***TEST 9\n");
	printf("   Sending 5 bytes...\n");
	if (cs421net_send(payload2, 5)) {
		printf("   Send success\n");
		printf("   Checking accounts...");

		close(acread_fd);
		acread_fd =
		    open("/sys/devices/platform/pwkeeper/accounts", O_RDONLY);
		if (read(acread_fd, test9_buf, PAGE_SIZE) < 0) {
			perror("   Returned error! ");
			printf("***FAILED TEST 9\n\n");
		} else {
			int num = num_account(test9_buf);
			printf("\n%s\n", test9_buf);
			if (num == 2) {
				printf("   2 accounts found!\n");
				printf("***PASSED TEST 9\n\n");
				tests_passed++;
			} else {
				printf("   Oh no! There are %d accounts!\n",
				       num);
				printf("***FAILED TEST 9\n\n");
			}
		}

	} else {
		printf("   Send fail\n");
		printf("***FAILED TEST 9\n\n");
	}

/* Test 10: Send right UID to device */
	char payload3[4] = { 0xe8, 0x03, 0x00, 0x00 };
	char test10_buf[PAGE_SIZE] = { '\0' };
	printf("***TEST 10\n");
	printf("   Sending UID 1000 (Assuming curr UID is 1000)\n");
	if (cs421net_send(payload3, 4)) {
		printf("   Send success\n");
		printf("   Checking accounts...");

		close(acread_fd);
		acread_fd =
		    open("/sys/devices/platform/pwkeeper/accounts", O_RDONLY);
		if (read(acread_fd, test10_buf, PAGE_SIZE) < 0) {
			perror("   Returned error! ");
			printf("***FAILED TEST 10\n\n");
		} else {
			int num = num_account(test10_buf);
			printf("\n%s\n", test10_buf);
			if (num == 0) {
				printf("   0 accounts found!\n");
				printf("***PASSED TEST 10\n\n");
				tests_passed++;
			} else {
				printf("   Oh no! There are %d accounts!\n",
				       num);
				printf("***FAILED TEST 10\n\n");
			}
		}

	} else {
		printf("   Send fail\n");
		printf("***FAILED TEST 10\n\n");
	}

	printf("***** [PASSED %d OUT OF %d TESTS] *****\n", tests_passed,
	       num_tests);

	return 0;
}
