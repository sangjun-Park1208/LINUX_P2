#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <errno.h>
#include <sys/wait.h>

#define BUF_MAX 1024
#define ARGMAX 5

int split(char* string, char* seperator, char* argv[]);

int main(){
	char input[BUF_MAX];
	int argc = 0;
	char* argv[ARGMAX];
	pid_t pid;
	int status;


	while(1){
		printf("20182613> ");
		fgets(input, sizeof(input), stdin);
		input[strlen(input) - 1] = '\0';
		argc = split(input, " ", argv);

		if(argc == 0){
			continue;
		}

		pid = fork();

		if(pid == 0){
			if(!strcmp(argv[0], "fmd5")){
				if(argc != 5){
					fprintf(stderr, "Usage : fmd5 [FILE_EXTENSION] [MINSIZE] [MAXSIZE] [TARGET_DIRECTORY]\n");
					continue;
				}
				execl("./ssu_find-md5", argv[1], argv[2], argv[3], argv[4], (char*)0);
			}

			else if(!strcmp(argv[0], "fsha1")){
				if(argc != 5){
					fprintf(stderr, "Usage : fmd5 [FILE_EXTENSION] [MINSIZE] [MAXSIZE] [TARGET_DIRECTORY]\n");
					continue;
				}
				execl("./ssu_find-sha1", argv[1], argv[2], argv[3], argv[4], (char*)0);
			}

			else if(!strcmp(argv[0], "exit")){
				printf("Prompt End\n");
				exit(0);
			}

			else{
				execl("./ssu_help", argv[1], (char*)0);
				continue;
			}

			printf("Child process exit\n");
			exit(0);
		}
		else if(pid>0){
			pid_t waitPID;
			waitPID = wait(&status);
			if(!strcmp(argv[0], "exit"))
				exit(0);
			continue;
			if(waitPID == -1){
				printf("wait error : errno %d\n", errno);
			}
//			else if(WEXITSTATUS(status) == 127){
//				exit(0);
//			}
			else{
				if(WIFEXITED(status)){
//					printf("wait : child process exit(normal)\n");
				}
				else if(WIFSIGNALED(status)){
//					printf("wait : child process exit(abnormal)\n");
				}
			}
//			printf("wait : parent(main) process exit\n");
//			printf("waidPID : %d\n", waitPID);

		}

		break;
	}

	exit(0);
}

int split(char* string, char* seperator, char* argv[]){
	int argc = 0;
	char* ptr = NULL;

	ptr = strtok(string, seperator);
	while(ptr != NULL){
		argv[argc++] = ptr;
		ptr = strtok(NULL, " ");
	}
	
	return argc;
}
