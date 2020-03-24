#include <stdio.h>
#include <unistd.h>
#include <pthread.h>

int main(){
	execl("/bin/ls", "/bin/ls", (char*) NULL);
	printf("Hello World");
    execl("./lsmpp2", "./lsmpp2", (char*) NULL);
	printf("executed");
	execl("/bin/ls", "/bin/ls", (char*) NULL);
	printf("end");
	return 0;
}
