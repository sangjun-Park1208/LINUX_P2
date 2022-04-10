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
#define QUEUE_SIZE 1000000
#define FILE_SIZE 16
#define INPUT_MAX 3

typedef struct Node{
	char data[PATH_MAX];
	struct Node* next;
	unsigned char hash[HASH_SIZE];
	double size;
}Node;

typedef struct Queue{
	Node* front;
	Node* rear;
	int count;
}Queue;

int COUNT_FILE;
int COUNT_MD5;
int DUP;
int DIF_FILE;

int split(char* string, char* seperator, char* argv[]);
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
void sort_dupSet(Queue* dupSet, int k);
void fmd5_delete(void);
char* toComma(long n, char* fileSize);


unsigned char hashVal[HASH_SIZE];

int main(int argc, char* argv[]){
	struct timeval startTime, endTime;
	gettimeofday(&startTime, NULL);
	Queue* RegularFile_dupList = (Queue*)malloc(sizeof(Queue) * QUEUE_SIZE);	
	Queue* dupSet = (Queue*)malloc(sizeof(Queue) * QUEUE_SIZE);
	char* Ext = (char*)malloc(strlen(argv[0]));
	char* Min = (char*)malloc(strlen(argv[1]));
	char* Max = (char*)malloc(strlen(argv[2]));
	char* Target_dir = (char*)malloc(strlen(argv[3]));

	strcpy(Ext, argv[0]);
	strcpy(Min, argv[1]);
	strcpy(Max, argv[2]);
	strcpy(Target_dir, argv[3]);

	int k = get_dupList(Ext, Min, Max, Target_dir, RegularFile_dupList, dupSet);

	sort_dupSet(dupSet, k);
	print_dupList(dupSet, k);
	
	printf("COUNT_FILE : %d\n", COUNT_FILE); // number of total file count
	printf("DUP_COUNT : %d\n", DUP); // number of duplicate file count
	printf("DIFF_FILE : %d\n", DIF_FILE); // number of different file count
	gettimeofday(&endTime, NULL);
	printf("Searching time: %ld:%llu(sec:usec)\n\n", endTime.tv_sec - startTime.tv_sec, (unsigned long long)endTime.tv_usec - (unsigned long long)startTime.tv_usec);



// delete option //
	
	char input[BUF_MAX];
	char* input_v[INPUT_MAX];
	int input_cnt = 0;
	while(1){
		
		for(int i=0; i<INPUT_MAX; i++)
			memset(&input_v[i], '\0', sizeof(input_v[i]));
		
		printf(">> ");
		fgets(input, sizeof(input), stdin);
		input[strlen(input)-1] = '\0';
		input_cnt = split(input, " ", input_v);

		if(input_cnt == 0){ // press enter
			continue;
		}

		if(!strcmp(input_v[0], "exit")){ // press "exit"
			printf("Back to Prompt\n");
			exit(0);
		}

		if(input_cnt != 2 && input_cnt != 3){ // input error : d(3), i(2), f(2), t(2)
			printf("input error\n");
			continue;
		}

		if(!strcmp(input_v[1], "d")){

		}
		else if(!strcmp(input_v[1], "i")){

		}
		else if(!strcmp(input_v[1], "f")){

		}
		else if(!strcmp(input_v[1], "t")){

		}
		
		else{
			printf("input error\n");
			continue;
		}

	}


	printf("fmd5 process is over\n");
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

/*** Queue ***/ 
void initQueue(Queue* queue){
	queue->front = queue->rear = NULL;
	queue->count = 0;
	return;
}

int isEmpty(Queue* queue){
	return queue->count == 0;
}

void enqueue(Queue* queue, char* data){
	Node* newNode = (Node*)malloc(sizeof(Node));
	memset(hashVal, '\0', HASH_SIZE);

	FILE* IN;
	if((IN = fopen(data, "r")) == NULL){
		fprintf(stderr, "fopen error in enqueue function\n");
		printf("%s\n", strerror(errno));
		exit(1);
	}


	md5(IN, hashVal);
	fclose(IN);

	newNode->size = get_fileSize(data);
	strcpy(newNode->data, data);
	strcpy(newNode->hash, hashVal);
	newNode->next = NULL;
	if(isEmpty(queue))
		queue->front = newNode;
	else
		queue->rear->next = newNode;
	queue->rear = newNode;
	queue->count++;
	return;
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
	return;

}

int BFS(char* Ext, char* Min, char* Max, char* Target_dir, Queue* regList_queue, Queue* dupSet){

	int dupset_Count = 0;
	Queue dir_queue;
	initQueue(&dir_queue);
	enqueue(&dir_queue, Target_dir); // make enter while loop condition : set [TARGET_DIRECTORY] into Queue(directory).
	struct dirent** namelist;
	struct stat st;
	char curr_dir[PATH_MAX-256]; // to resolve sprintf size warning
	char tmp_buf[PATH_MAX];
	while(!isEmpty(&dir_queue)){ // while loop condition : if direcory Queue is not empty -> keep going
		memset(curr_dir, '\0', PATH_MAX);
		memset(tmp_buf, '\0', PATH_MAX);
		strcpy(curr_dir, dequeue(&dir_queue, tmp_buf)); // dequeue directory Queue, copy string to 'curr_dir'
		int fileCnt = scandir(curr_dir, &namelist, NULL, alphasort); // get every files in current directory
		for(int i=2; i<fileCnt; i++){
			if(!strcmp(namelist[i]->d_name, ".")) // except '.' direcotry
				continue;
			if(!strcmp(namelist[i]->d_name, "..")) // except '..' directory
				continue;
			COUNT_FILE++;
			char tmp_path[PATH_MAX];
			memset(tmp_path, '\0', PATH_MAX);
			if(!strcmp(curr_dir, "/")) // if [TARGET_DIRECTORY] is root('/') 
				sprintf(tmp_path, "%s%s", curr_dir, namelist[i]->d_name);
			else // [TARGET_DIRECTORY] is not a root.
				sprintf(tmp_path, "%s/%s", curr_dir, namelist[i]->d_name);
			lstat(tmp_path, &st);

			unsigned char tmp_sc[HASH_SIZE];
			memset(tmp_sc, '\0', HASH_SIZE);
			FILE* IN;
			if((IN = fopen(tmp_path, "r")) == NULL){
				continue;
			}
			if(!S_ISDIR(st.st_mode) && !S_ISREG(st.st_mode)){ // if not directory & not regular file -> close file and keep going.
				fclose(IN);
				continue;
			}

			md5(IN, tmp_sc);
			fclose(IN);
			int tmpSize = get_fileSize(tmp_path);

			if(S_ISDIR(st.st_mode)){
				if((strcmp(tmp_path, "/proc") == 0) || (strcmp(tmp_path, "/run") == 0) || (strcmp(tmp_path, "/sys") == 0) ){ // except /proc, /run, /sys directory
					continue;
				}
				else{
					enqueue(&dir_queue, tmp_path); // other direcory -> enqueue to Queue(directory)
				}
			}
			else if(S_ISREG(st.st_mode)){
				int condition = 0;
				condition += check_ext(Ext, tmp_path); // if condition == 0 -> meet [FILE_EXTENSION] condition
				condition += check_size(Min, Max, tmp_path); // if condition == 0 -> meet [MIN], [MAX] condition

				if(condition == 0){
					if(dupset_Count==0){ // if first file -> just enqueue and keep going
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
								DUP++;
								isFirst = 0;
								break;
							}
						}
						if(isFirst == 1){
							DIF_FILE++;
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


	if(dupset_Count == 1){} // if dupset_Count is 1, just execute for loop
	else
		dupset_Count--;

	int check = 0;
	for(int i=0; i<dupset_Count; i++){ // extracting specific duplicat_list (node count should more than 2)
		if(regList_queue[i].count == 1){
			initQueue(&regList_queue[i]);
		}
		else{
			dupSet[check++] = regList_queue[i];
		}
	}
	return check; // number of duplicate set.
}



void md5(FILE* f, unsigned char* hash){ // 'hash' <- hash value in here
	COUNT_MD5++; // check number of calls : md5()
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
	return;
}



off_t get_fileSize(char* path){ // get path from parameter -> return path's(file's) size
	struct stat st;
	char buf[PATH_MAX];
	memset(buf, '\0', PATH_MAX);
	strcpy(buf, path);
	lstat(buf, &st);

	return st.st_size;
}

int check_ext(char* Ext, char* tmp_path){
	if(strcmp(Ext, "*") == 0) // '*' means check every files, no matter what extension is.
		return 0;
	else{ // some extension is after '*'
		if(strrchr(tmp_path, '.') == NULL) // if there is no '.' after * -> wrong path
			return 1;

		if(!strcmp(&Ext[2], strrchr(tmp_path, '.')+1)) // if Ext and tmp_path has same extension -> return 0
			return 0;
		else // Extension not same -> return 1
			return 1; 
	}
}

int check_size(char* Min, char* Max, char* tmp_path){
	struct stat st;
	lstat(tmp_path, &st);

	if((strcmp(Min, "~") == 0) && (strcmp(Max, "~") == 0)) // if [MIN] == "~" and [MAX] == "~"
		return 0;
	else if((strcmp(Min, "~") != 0) && (strcmp(Max, "~") == 0)){ 
		double minsize = atof(Min); // get integer value
		if((strstr(Min, "kb") != NULL) || (strstr(Min, "KB") != NULL) || (strstr(Min, "Kb") != NULL)) // set unit
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
		double maxsize = atoi(Max);
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
		double minsize = atof(Min);
		if((strstr(Min, "kb") != NULL) || (strstr(Min, "KB") != NULL) || (strstr(Min, "Kb") != NULL))
			minsize *= 1000;
		else if((strstr(Min, "mb") != NULL) || (strstr(Min, "MB") != NULL) || (strstr(Min, "Mb") != NULL))
			minsize *= 1000000;
		else if((strstr(Min, "gb") != NULL) || (strstr(Min, "GB") != NULL) || (strstr(Min, "Gb") != NULL))
			minsize *= 1000000000;
		
		double maxsize = atof(Max);
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

void print_dupList(Queue* reg_dupList, int k){ // print duplicate list -> terminal(stdout)
	unsigned char tmp[HASH_SIZE];
	char fileSize[FILE_SIZE];
	for(int i=0; i<k; i++){
		memset(tmp, '\0', HASH_SIZE);
		memset(fileSize, '\0', FILE_SIZE);
		FILE* IN;
		if((IN = fopen(reg_dupList[i].front->data, "r")) == NULL){
			printf("In print_dupList fopen(): %s\n", strerror(errno));
		}

		md5(IN, tmp);
		fclose(IN);
		toComma(reg_dupList[i].front->size, fileSize);
//		printf("---- Identical files #%d (%ld bytes - ", i+1, get_fileSize(reg_dupList[i].front->data));
		printf("---- Identical files #%d (%s bytes - ", i+1, fileSize);
		for(int j=0; j<MD5_DIGEST_LENGTH; j++)
			printf("%02x",tmp[j]);
		printf(") ----\n");
		print_queue(&reg_dupList[i]); // call each set's index(member)
	}
	return;
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
	return;
}


void sort_dupSet(Queue* dupSet, int k){
	for(int i=k; i>0; i--){
		for(int j=0; j<i-1; j++){
			if(dupSet[j].front->size > dupSet[j+1].front->size){
				Queue tmpQueuePtr = dupSet[j];
				dupSet[j] = dupSet[j+1];
				dupSet[j+1] = tmpQueuePtr;
			}
		}
	}
	return;
}

char* toComma(long n, char* com_str){
	char str[FILE_SIZE];
//	char com_str[FILE_SIZE];

	sprintf(str, "%ld", n);
	int len = strlen(str);
	int mod = len % 3;
	int id = 0;

	for(int i=0; i<len; i++){
		if((i!=0) && ((i % 3) == mod))
			com_str[id++] = ',';
		com_str[id++] = str[i];
	}
	com_str[id] = 0x00;
	return com_str;
}


void fmd5_delete(){

}

