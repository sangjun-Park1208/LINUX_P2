#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <string.h>
#include <sys/wait.h>
#include <openssl/md5.h>
#include <dirent.h>
#include <time.h>
#include <errno.h>

#define BUF_MAX 1024
#define PATH_MAX 4096
#define ARG_MAX 4
#define BUFSIZE 1024*16
#define HASH_SIZE 35

typedef struct Node{
	char data[PATH_MAX];
	struct Node* next;
	unsigned char hash[HASH_SIZE];
}Node;

typedef struct Queue{
	Node* front;
	Node* rear;
	int count;
}Queue;

int COUNT_FILE;
int COUNT_MD5;
int COUNT;
void initQueue(Queue* queue);
int isEmpty(Queue* queue);
void enqueue(Queue* queue, char* data);
char* dequeue(Queue* queue, char* data);
int get_dupList(char* Ext, char* Min, char* Max, char* Target_dir, Queue* regList_queue, Queue* dupSet);
void check_targetDir(char* Ext, char* Target_dir);
int BFS(char* Ext, char* Min, char* Max, char* Target_dir, Queue* regList_queue, Queue* dupSet);
void do_fp(FILE* f, unsigned char* hash);
void md5(FILE* f, unsigned char* hash);
off_t get_fileSize(char* path);
int check_ext(char* Ext, char* tmp_path);
int check_size(char* Min, char* Max, char* tmp_path);
int MD5_Init(MD5_CTX* c);
int MD5_Update(MD5_CTX* c, const void* data, unsigned long len);
int MD5_Final(unsigned char* md, MD5_CTX* c);
void print_dupList(Queue* reg_dupList, int k);
void print_queue(Queue* queue);


unsigned char hashVal[HASH_SIZE];

int main(int argc, char* argv[]){
	struct timeval startTime, endTime;
	gettimeofday(&startTime, NULL);
	Queue* RegularFile_dupList = (Queue*)malloc(sizeof(Queue) * 1000000);	
	Queue* dupSet = (Queue*)malloc(sizeof(Queue) * 1000000);
	char* Ext = (char*)malloc(strlen(argv[0]));
	char* Min = (char*)malloc(strlen(argv[1]));
	char* Max = (char*)malloc(strlen(argv[2]));
	char* Target_dir = (char*)malloc(strlen(argv[3]));

	strcpy(Ext, argv[0]);
	strcpy(Min, argv[1]);
	strcpy(Max, argv[2]);
	strcpy(Target_dir, argv[3]);

	printf("Ext : %s\nMin : %s\nMax : %s\nTarget_dir : %s\n\n", Ext, Min, Max, Target_dir);
	int k = get_dupList(Ext, Min, Max, Target_dir, RegularFile_dupList, dupSet);

	printf("k : %d\n", k);
	print_dupList(dupSet, k);
	
	printf("COUNT_FILE : %d\n", COUNT_FILE);
	gettimeofday(&endTime, NULL);
	printf("Searching time: %ld:%llu(sec:usec)\n\n", endTime.tv_sec - startTime.tv_sec, (unsigned long long)endTime.tv_usec - (unsigned long long)startTime.tv_usec);
	printf("fmd5 process is over\n");
	exit(0);
}

/*** Queue ***/ 
void initQueue(Queue* queue){
	queue->front = queue->rear = NULL;
	queue->count = 0;
}

int isEmpty(Queue* queue){
	return queue->count == 0;
}

void enqueue(Queue* queue, char* data){
	Node* newNode = (Node*)malloc(sizeof(Node));
	memset(hashVal, '\0', HASH_SIZE);

	FILE* IN;
	if((IN = fopen(data, "r")) == NULL){
		fprintf(stderr, "fopen error in md5 hash function\n");
		printf("%s\n", strerror(errno));
		exit(1);
	}


	md5(IN, hashVal);
	fclose(IN);

	strcpy(newNode->data, data);
	strcpy(newNode->hash, hashVal);
	newNode->next = NULL;
	if(isEmpty(queue))
		queue->front = newNode;
	else
		queue->rear->next = newNode;
	queue->rear = newNode;
	queue->count++;
}

char* dequeue(Queue* queue, char* data){
	Node* ptr;
	if(isEmpty(queue))
		return NULL;
	ptr = queue->front;
	strcpy(data, ptr->data);
	queue->front = ptr->next;
	free(ptr);
	queue->count--;
	return data;
}
/***************/


int get_dupList(char* Ext, char* Min, char* Max, char* Target_dir, Queue* regList_queue, Queue* dupSet){
	int dupset_Count = 0; // RegularFile_dupList count => return value
	char realPath[PATH_MAX];
	memset(realPath, '\0', PATH_MAX);
	if(Target_dir[0] == '~'){
		if(strlen(Target_dir) > 1){
			char ptr[PATH_MAX];
			strcpy(ptr, &Target_dir[2]);
			sprintf(Target_dir, "%s/%s", "/home/sangjun", ptr);
			printf("changed Target_dir : %s\n", Target_dir);
		}
		else{
			sprintf(Target_dir, "%s", "/home/sangjun");
			printf("changed Target_dir : %s\n", Target_dir);
		}
	}
	
	check_targetDir(Ext, Target_dir); // check if Target_dir is correct input or not.

	if(!strcmp(Target_dir, "/")){
		dupset_Count = BFS(Ext, Min, Max, "/", regList_queue, dupSet); // start BFS with real path
	}
	else if(Target_dir[0] == '.'){
		if(realpath(Target_dir, realPath) == NULL){
			fprintf(stderr, "realpath() error\n");
			exit(1); // exit fmd5 process
		}
		dupset_Count = BFS(Ext, Min, Max, realPath, regList_queue, dupSet); // start BFS with real path
	}
	else{
		if(realpath(Target_dir, realPath) == NULL){ // check correct realpath or not
			fprintf(stderr, "realpath() error\n");
			exit(1);
		}
		dupset_Count = BFS(Ext, Min, Max, realPath, regList_queue, dupSet); // start BFS with real path
	}

	return dupset_Count;
}

void check_targetDir(char* Ext, char* Target_dir){
	struct stat st;
	if(lstat(Target_dir, &st) < 0){ // if (Target_dir != DIRECTORY || Target_dir == !FILE)
		printf("Not a Directory or file\n");
		exit(1); // exit fmd5 process
	}
	if(Ext[0] != '*'){ // Extension must starts with '*'
		printf("Extension Error\n");
		exit(1); // if not, then exit fmd5 process
	}
	if(Ext[strlen(Ext)-1] == '.'){ // Extension must ends with '*' or "other _ext"
		printf("Extension Error\n");
		exit(1); // if not, then exit fmd5 process
	}
	if(strstr(Ext, ".") == NULL && strlen(Ext) != 1){ // if Extension contain '.' , then it's length should bigger than 1
		printf("Extension Error\n");
		exit(1);
	}

}

int BFS(char* Ext, char* Min, char* Max, char* Target_dir, Queue* regList_queue, Queue* dupSet){

	int dupset_Count = 0;
	Queue dir_queue;
	initQueue(&dir_queue);
	enqueue(&dir_queue, Target_dir);
	struct dirent** namelist;
	struct stat st;
	char curr_dir[PATH_MAX-256];
	char tmp_buf[PATH_MAX];
	while(!isEmpty(&dir_queue)){
		memset(curr_dir, '\0', PATH_MAX);
		memset(tmp_buf, '\0', PATH_MAX);
		strcpy(curr_dir, dequeue(&dir_queue, tmp_buf));
		int fileCnt = scandir(curr_dir, &namelist, NULL, alphasort);
		for(int i=2; i<fileCnt; i++){
			if(!strcmp(namelist[i]->d_name, "."))
				continue;
			if(!strcmp(namelist[i]->d_name, ".."))
				continue;
			printf("COUNT_FILE : %d\n", COUNT_FILE++);

			char tmp_path[PATH_MAX];
			memset(tmp_path, '\0', PATH_MAX);
			if(!strcmp(curr_dir, "/"))
				sprintf(tmp_path, "%s%s", curr_dir, namelist[i]->d_name);
			else
				sprintf(tmp_path, "%s/%s", curr_dir, namelist[i]->d_name);
			lstat(tmp_path, &st);
			printf("tmp_path : %s\n", tmp_path);

			unsigned char tmp_sc[HASH_SIZE];
			memset(tmp_sc, '\0', HASH_SIZE);
			FILE* IN;
			if((IN = fopen(tmp_path, "r")) == NULL){
				printf("In BFS() fopen() : %s\n", strerror(errno));
				printf("tmp_path : %s\n", tmp_path);
				continue;
			}
			if(!S_ISDIR(st.st_mode) && !S_ISREG(st.st_mode)){
				printf("not dir & not reg\n");
				fclose(IN);
				continue;
			}

			md5(IN, tmp_sc);
			fclose(IN);
			int tmpSize = get_fileSize(tmp_path);

			if(S_ISDIR(st.st_mode)){
				if((strcmp(tmp_path, "/proc") == 0) || (strcmp(tmp_path, "/run") == 0) || (strcmp(tmp_path, "/sys") == 0) ){
					continue;
				}
				else{
					enqueue(&dir_queue, tmp_path);
				}
			}
			else if(S_ISREG(st.st_mode)){
				int condition = 0;
				condition += check_ext(Ext, tmp_path);
				condition += check_size(Min, Max, tmp_path);

				if(condition == 0){
					if(dupset_Count==0){
						Queue queue;
						initQueue(&queue);
						enqueue(&queue, tmp_path);
						regList_queue[dupset_Count++] = queue;
					}
					else{
						int isFirst = 1;
						for(int j=0; j<dupset_Count; j++){
							if((strcmp(tmp_sc, regList_queue[j].front->hash) == 0 )
									&& (tmpSize == get_fileSize(regList_queue[j].front->data))){ // if hash value & size is same

								enqueue(&regList_queue[j], tmp_path);	
								printf("COUNT : %d\n", COUNT++);
//								printf("COUNT_MD5 : %d\n", COUNT_MD5);
//								print_queue(&regList_queue[j]);
								isFirst = 0;
								break;
							}
						}
						if(isFirst == 1){
							Queue queue;
							initQueue(&queue);
							enqueue(&queue, tmp_path);
							regList_queue[dupset_Count++] = queue;
						}
					}
				}
			}
			else if(S_ISCHR(st.st_mode)){
				continue;
			}
		}
	}

	dupset_Count--;

	
	int check = 0;
	for(int i=0; i<dupset_Count; i++){
		if(regList_queue[i].count == 1){
			initQueue(&regList_queue[i]);
		}
		else{
			dupSet[check++] = regList_queue[i];
		}
	}
	return check;
}



void md5(FILE* f, unsigned char* hash){
	COUNT_MD5++;
	MD5_CTX c;
	unsigned char md[MD5_DIGEST_LENGTH];
	int fd;
	int i;
	static unsigned char buf[BUFSIZE];
	fd = fileno(f);
	MD5_Init(&c);
	for(;;){
		i = read(fd, buf, BUFSIZE);
		if(i<=0) break;
		MD5_Update(&c, buf, (unsigned long)i);
	}
	MD5_Final(&(md[0]), &c);
	for(int i=0; i<MD5_DIGEST_LENGTH; i++)
		sprintf(hash+(i*2), "%02x", md[i]);
}



off_t get_fileSize(char* path){
	struct stat st;
	char buf[PATH_MAX];
	memset(buf, '\0', PATH_MAX);
	strcpy(buf, path);
	lstat(buf, &st);

	return st.st_size;
}

int check_ext(char* Ext, char* tmp_path){
	if(strcmp(Ext, "*") == 0)
		return 0;
	else{
		if(strrchr(tmp_path, '.') == NULL)
			return 1;

		printf("&Ext[2] : %s\n", &Ext[2]);
		printf("strrchr(tmp_path, '.')+1 : %s\n", strrchr(tmp_path, '.')+1);
		if(!strcmp(&Ext[2], strrchr(tmp_path, '.')+1))
			return 0;
		else
			return 1;
	}
}

int check_size(char* Min, char* Max, char* tmp_path){
	struct stat st;
	lstat(tmp_path, &st);

	if((strcmp(Min, "~") == 0) && (strcmp(Max, "~") == 0))
		return 0;
	else if((strcmp(Min, "~") != 0) && (strcmp(Max, "~") == 0)){
		int minsize = atoi(Min);
		if((strstr(Min, "kb") != NULL) || (strstr(Min, "KB") != NULL) || (strstr(Min, "Kb") != NULL))
			minsize *= 1000;
		else if((strstr(Min, "mb") != NULL) || (strstr(Min, "MB") != NULL) || (strstr(Min, "Mb") != NULL))
			minsize *= 1000000;
		else if((strstr(Min, "gb") != NULL) || (strstr(Min, "GB") != NULL) || (strstr(Min, "Gb") != NULL))
			minsize *= 1000000000;

		if(minsize <= st.st_size)
			return 0;
		else
			return 1;
	}
	else if((strcmp(Min, "~") == 0) && (strcmp(Max, "~") != 0)){
		int maxsize = atoi(Max);
		if((strstr(Max, "kb") != NULL) || (strstr(Max, "KB") != NULL) || (strstr(Max, "Kb") != NULL))
			maxsize *= 1000;
		else if((strstr(Max, "mb") != NULL) || (strstr(Max, "MB") != NULL) || (strstr(Max, "Mb") != NULL))
			maxsize *= 1000000;
		else if((strstr(Max, "gb") != NULL) || (strstr(Max, "GB") != NULL) || (strstr(Max, "Gb") != NULL))
			maxsize *= 1000000000;

		if(st.st_size <= maxsize)
			return 0;
		else
			return 1;
	}
	else{
		int minsize = atoi(Min);
		if((strstr(Min, "kb") != NULL) || (strstr(Min, "KB") != NULL) || (strstr(Min, "Kb") != NULL))
			minsize *= 1000;
		else if((strstr(Min, "mb") != NULL) || (strstr(Min, "MB") != NULL) || (strstr(Min, "Mb") != NULL))
			minsize *= 1000000;
		else if((strstr(Min, "gb") != NULL) || (strstr(Min, "GB") != NULL) || (strstr(Min, "Gb") != NULL))
			minsize *= 1000000000;
		
		int maxsize = atoi(Max);
		if((strstr(Max, "kb") != NULL) || (strstr(Max, "KB") != NULL) || (strstr(Max, "Kb") != NULL))
			maxsize *= 1000;
		else if((strstr(Max, "mb") != NULL) || (strstr(Max, "MB") != NULL) || (strstr(Max, "Mb") != NULL))
			maxsize *= 1000000;
		else if((strstr(Max, "gb") != NULL) || (strstr(Max, "GB") != NULL) || (strstr(Max, "Gb") != NULL))
			maxsize *= 1000000000;
		

		if((minsize <= st.st_size) && (st.st_size <= maxsize))
			return 0;
		else
			return 1;
	}
	
	return 0;
}

void print_dupList(Queue* reg_dupList, int k){
	unsigned char tmp[HASH_SIZE];
	for(int i=0; i<k; i++){
		memset(tmp, '\0', HASH_SIZE);
		FILE* IN;
		if((IN = fopen(reg_dupList[i].front->data, "r")) == NULL){
			printf("In print_dupList fopen(): %s\n", strerror(errno));
		}

		md5(IN, tmp);
		fclose(IN);
		printf("---- Identical files #%d (%ld bytes - ", i+1, get_fileSize(reg_dupList[i].front->data));
		for(int j=0; j<MD5_DIGEST_LENGTH; j++)
			printf("%02x",tmp[j]);
		printf(") ----\n");
		print_queue(&reg_dupList[i]);
	}
}

void print_queue(Queue* queue){
	Node* tmp = queue->front;
	int index = 1;
	struct stat st;
	while(tmp!= NULL){
		lstat(tmp->data, &st);
		time_t mt = st.st_mtime;
		time_t at = st.st_atime;
		struct tm mT;
		struct tm aT;
		localtime_r(&mt, &mT);
		localtime_r(&at, &aT);

		printf("[%d] %s (mtime : %d-%02d-%02d %02d:%02d:%02d) (atime : %d-%02d-%02d %02d:%02d:%02d)\n",
				index++, tmp->data,
				mT.tm_year+1900, mT.tm_mon+1, mT.tm_mday+1, mT.tm_hour, mT.tm_min, mT.tm_sec,
				aT.tm_year+1900, aT.tm_mon+1, aT.tm_mday+1, aT.tm_hour, aT.tm_min, aT.tm_sec);
		tmp = tmp->next;
	}
	printf("\n");
}







