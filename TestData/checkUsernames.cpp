#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <cstdlib>
using namespace std;

char * get_username() {
	char *username;
	char user[64];
	size_t nSize = sizeof(user) - 1;

	username = (char *) malloc(nSize);
	if (!username) {
		return NULL;
	}
	if (0 == getlogin_r(username, nSize)) {
		free(username);
		return NULL;
	}
	return username;
}

int main() {

	const char* szUsernames[] = {
		"CurrentUser",
		"Sandbox",
		"user",
		"sand box",
	    "malware",
		"maltest",
		"test user",
		"virus",
	};
	char *username;

	if (NULL == (username = get_username())) {
		return 1;
	}

	char msg[256];
	long dwlength = sizeof(szUsernames) / sizeof(szUsernames[0]);
	for (int i = 0; i < dwlength; i++) {

		printf("Checking if username matches : %s ", szUsernames[i]);

		bool matched = false;
		if (0 == strcmp(szUsernames[i], username)) {
			matched = true;
		}

		puts(msg);
	}

	free(username);
	return 0;
}
