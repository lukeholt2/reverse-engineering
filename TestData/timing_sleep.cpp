#include <unistd.h>

int main()
{
	/* 
	This trick is about performing a low number of seconds to sleep but in a loop,
	the reason behind that sandboxes tries to avoid patching such sleeps because it
	could lead to race conditions and also because it is just negliable. However,
	when you do it in a loop, you can make it efficiant to cuz the sandboxe to reach
	its timeout.
	*/

	int delayInMillis_divided = 3000 / 1000;

	/* Example: we want to sleep 300 seeconds, then we can sleep
	0.3s for 1000 times which is like: 300 seconds = 5 minues */
	for (int i = 0; i < 1000; i++) {
		sleep(delayInMillis_divided);
	}

	// Malicious code goes here

	return 1;
}
