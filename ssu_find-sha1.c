#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <string.h>
#include <sys/wait.h>
#include <openssl/sha.h>
#include <dirent.h>
#include <time.h>
#include <errno.h>

#define BUF_MAX 1024
#define PATH_MAX 4096
#define ARG_MAX 4
#define BUFSIZE 1024*16
#define HASH_SIZE 42
#define QUEUE_SIZE 1000000
#define FILE_SIZE 16
#define INPUT_MAX 3

typedef struct Node{
	char data[PATH_MAX]; // path
	struct Node* next; // next
	struct Node* prev; // previous
	unsigned char hash[HASH_SIZE]; // hash value
	double size; // file size
}Node;

typedef struct Queue{
	Node* front; // front(start)
	Node* rear; // rear(end)
	int count; // number of nodes in each Queue
}Queue;

int COUNT_FILE; // DEBUG : number of file in [TARGET_DIRECTORY]
int COUNT_SHA1; // DEBUG : number of function call : sha1()
int DUP; // DEBUG : number of duplicate set
int DIF_FILE; // DEBUG : number of difference files
unsigned char hashVal[HASH_SIZE]; // in enqueue() -> store hash value in each node

int split(char* string, char* seperator, char* argv[]); // split string by seperator
void initQueue(Queue* queue); // initiate Queue
int isEmpty(Queue* queue);
void enqueue(Queue* queue, char* data); 
char* dequeue(Queue* queue, char* data);
int deleteNode(Queue* queue, int SET_IDX, int LIST_IDX, int k); // delete [d] OPTION 
int deleteNode_ask(Queue* queue, int SET_IDX, int LIST_IDX, int k); // delete [i] OPTION
void deleteNode_force(Queue* queue, int SET_IDX, int REC_IDX, int k); // delete [f] OPTION
int get_dupList(char* Ext, char* Min, char* Max, char* Target_dir, Queue* regList_queue, Queue* dupSet);
void check_targetDir(char* Ext, char* Target_dir); // check input error in [TARGET_DIRECTORY]
int BFS(char* Ext, char* Min, char* Max, char* Target_dir, Queue* regList_queue, Queue* dupSet); // BFS algorithm : Searching
void sha1(FILE* f, unsigned char* hash); // get hash value
off_t get_fileSize(char* path);
int check_ext(char* Ext, char* tmp_path); // for [FILE_EXTENSION] : check error, string compare with EXTENSION
int check_size(char* Min, char* Max, char* tmp_path); // for [MIN], [MAX] : check error, check if "MIX <= fileSize <= MAX" or not
int SHA1_Init(SHA_CTX* c); // sha1
int SHA1_Update(SHA_CTX* c, const void* data, unsigned long len); // sha1
int SHA1_Final(unsigned char* md, SHA_CTX* c); // sha1
void print_dupList(Queue* reg_dupList, int k); // print every duplicate set under [TARGET_DIRECTORY] -> call print_queue()
void print_queue(Queue* queue);
void sort_dupSet(Queue* dupSet, int k); // Sorting duplicate set by it's fileSize (Bubble Sort)
char* toComma(long n, char* fileSize); // if fileSize is more than 1000Byte, insert comma(',') in mod(3)
int get_recentIDX(Queue* dupSet, int SET_IDX); // for [f], [t] OPTION : get recent modified file IDX in linked list
int d_delete(int SET_IDX, int LIST_IDX,Queue* dupSet, int k); // delete [d]
int i_delete(int SET_IDX, Queue* dupSet, int k); // delete [i]
int f_delete(int SET_IDX, Queue* dupSet, int k); // delete [f]
int t_delete(int SET_IDX, Queue* dupSet, int k); // delete [t]


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
	dupSet = (Queue*)realloc(dupSet, sizeof(Queue) * k);
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

		/******* [OPTION] ******/
		if(input_cnt != 2 && input_cnt != 3){ // input error : d(3), i(2), f(2), t(2)
			printf("input error\n");
			continue;
		}

		if(!strcmp(input_v[1], "d")){ // d : input_cnt == 3
			if(input_cnt != 3){
				printf("(d) input error\n");
				continue;
			}
			k = d_delete(atoi(input_v[0]), atoi(input_v[2]), dupSet, k);
			print_dupList(dupSet, k);
		}
		else if(!strcmp(input_v[1], "i")){ // i : input_cnt == 2
			if(input_cnt != 2){
				printf("(i) input error\n");
				continue;
			}
			k = i_delete(atoi(input_v[0]), dupSet, k);
			print_dupList(dupSet, k);
		}
		else if(!strcmp(input_v[1], "f")){ // f : input_cnt == 2
			if(input_cnt != 2){
				printf("(f) input error\n");
				continue;
			}
			k = f_delete(atoi(input_v[0]), dupSet, k);
			print_dupList(dupSet, k);
		}
		else if(!strcmp(input_v[1], "t")){ // t : input_cnt == 2
			if(input_cnt != 2){
				printf("(t) input error\n");
				continue;
			}
			k = t_delete(atoi(input_v[0]), dupSet, k);
			print_dupList(dupSet, k);
		}
		else{
			printf("input error\n");
			continue;
		}
		/*********************/

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


	sha1(IN, hashVal);
	fclose(IN);

	newNode->size = get_fileSize(data);
	strcpy(newNode->data, data);
	strcpy(newNode->hash, hashVal);
	newNode->next = NULL;
	newNode->prev = queue->rear;
	if(isEmpty(queue)){
		queue->front = newNode;
		queue->rear = newNode;
	}
	else{
		queue->rear->next = newNode;
	}
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

int deleteNode(Queue* queue, int SET_IDX, int LIST_IDX, int k){
	int t = k;
	Node* tmp;

	if(LIST_IDX == 1){
		if(unlink(queue[SET_IDX].front->data) < 0){
			fprintf(stderr, "unlink error\n");
			return k;
		}
		tmp = queue[SET_IDX].front;
		queue[SET_IDX].front = queue[SET_IDX].front->next;
		queue[SET_IDX].count--;
		free(tmp);
	}

	else if(LIST_IDX == queue[SET_IDX].count){
		if(unlink(queue[SET_IDX].rear->data) < 0){
			fprintf(stderr, "unlink error\n");
			return k;
		}
		tmp = queue[SET_IDX].rear;
		queue[SET_IDX].rear = queue[SET_IDX].rear->prev;
		queue[SET_IDX].rear->next = NULL;
		queue[SET_IDX].count--;
		tmp->next = NULL;
		free(tmp);
	}

	else{
		tmp = queue[SET_IDX].front;
		for(int i=1; i<LIST_IDX; i++){
			if(tmp->next != NULL){
				tmp = tmp->next;
			}
		}
		if(unlink(tmp->data) < 0){
			fprintf(stderr, "unlink error\n");
			return k;
		}
		tmp->prev->next = tmp->next;
		tmp->next->prev = tmp->prev;
		queue[SET_IDX].count--;
		free(tmp);
	}
	if(queue[SET_IDX].count == 1)
		t--;

	return t;
}

int deleteNode_ask(Queue* queue, int SET_IDX, int LIST_IDX, int k){
	int t = k;
	Node* cur, *tmp;
	int input;
	cur = queue[SET_IDX].front;
	for(int i=1; i<=LIST_IDX; i++){
		if(i == 1){
			printf("Delete \"%s\"? [y/n] ", queue[SET_IDX].front->data);
			input = getc(stdin);
			if(input == 'n' || input == 'N'){
				cur = cur->next;
				cur->prev = queue[SET_IDX].front;
			}
			else if(input == 'y' || input == 'Y'){
	
				if(unlink(queue[SET_IDX].front->data) < 0){
					fprintf(stderr, "unlink error\n");
					return k;
				}
				tmp = queue[SET_IDX].front;
				cur = cur->next;
				queue[SET_IDX].front = queue[SET_IDX].front->next;
				queue[SET_IDX].count--;
				free(tmp);
			}
			else{
				printf("Input error (front) (y / n)\n");
				return k;
			}
	
		}
		else if(i == LIST_IDX){
			printf("Delete \"%s\"? [y/n] ", queue[SET_IDX].rear->data);
			input = getc(stdin);
			if(input == 'n' || input == 'N'){
			}
			else if(input == 'y' || input == 'Y'){
				if(unlink(queue[SET_IDX].rear->data) < 0){
					fprintf(stderr, "unlink error\n");
					return k;
				}
				cur = queue[SET_IDX].rear;
				queue[SET_IDX].rear = queue[SET_IDX].rear->prev;
				cur->next = NULL;
				queue[SET_IDX].rear->next = NULL;
				queue[SET_IDX].count--;
			}
			else{
				printf("Input error(rear) (y / n)\n");
				return k;
			}
		}
		else{
			printf("Delete \"%s\"? [y/n] ", cur->data);
			input = getc(stdin);
			if(input == 'n' || input == 'N'){
				cur = cur->next;
			}
			else if(input == 'y' || input == 'Y'){
	
				if(unlink(cur->data) < 0){
					fprintf(stderr, "unlink error\n");
					return k;
				}
				if(!strcmp(cur->data, queue[SET_IDX].front->data)){
					cur = cur->next;
					queue[SET_IDX].front = queue[SET_IDX].front->next;
					queue[SET_IDX].count--;
				}
				else{
					cur->prev->next = cur->next;
					cur->next->prev = cur->prev;
					cur = cur->next;
					queue[SET_IDX].count--;
				}
			}
			else{
				printf("Input error(middle) (y / n)\n");
				return k;
			}
		}
		
		while(getchar() != '\n')
			continue;
	}

	if(queue[SET_IDX].count == 1 || queue[SET_IDX].count == 0)
		t--;

	return t;
}


void deleteNode_force(Queue* dupSet, int SET_IDX, int REC_IDX, int k){
	Node* tmp = dupSet[SET_IDX].front;
	int i=1;
	struct stat st;

	while(dupSet[SET_IDX].count > 1){
		if(i == REC_IDX){
			lstat(tmp->data, &st);
			time_t mt = st.st_mtime;
			struct tm mT;
			localtime_r(&mt,&mT);

			printf("Left file in #%d : %s (%d-%02d-%02d %02d:%02d:%02d)\n\n", SET_IDX+1, tmp->data,
					mT.tm_year+1900, mT.tm_mon+1, mT.tm_mday+1, mT.tm_hour, mT.tm_min, mT.tm_sec);
		}
		else{
			if(unlink(tmp->data)<0){
				fprintf(stderr, "unlink error\n");
				return;
			}

			dupSet[SET_IDX].count--;
		}
		i++;
		tmp = tmp->next;
	}
	return;
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
			exit(1); // exit fsha1 process
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
		exit(1); // exit fsha1 process
	}
	if(Ext[0] != '*'){ // Extension must starts with '*'
		printf("Extension Error\n");
		exit(1); // if not, then exit fsha1 process
	}
	if(Ext[strlen(Ext)-1] == '.'){ // Extension must ends with '*' or "other _ext"
		printf("Extension Error\n");
		exit(1); // if not, then exit fsha1 process
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

			sha1(IN, tmp_sc);
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



void sha1(FILE* f, unsigned char* hash){ // 'hash' <- hash value in here
	COUNT_SHA1++; // check number of calls : sha1()
	SHA_CTX c;
	unsigned char md[SHA_DIGEST_LENGTH];
	int fd;
	int i;
	static unsigned char buf[BUFSIZE];
	fd = fileno(f);
	SHA1_Init(&c);
	for(;;){
		i = read(fd, buf, BUFSIZE);
		if(i<=0) break;
		SHA1_Update(&c, buf, (unsigned long)i);
	}
	SHA1_Final(&(md[0]), &c);
	for(int i=0; i<SHA_DIGEST_LENGTH; i++)
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

		sha1(IN, tmp);
		fclose(IN);
		toComma(reg_dupList[i].front->size, fileSize);
		printf("---- Identical files #%d (%s bytes - ", i+1, fileSize);
		for(int j=0; j<SHA_DIGEST_LENGTH; j++)
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


int get_recentIDX(Queue* dupSet, int SET_IDX){
	int REC_IDX = 1;
	int checkIDX = 1;
	struct stat st;
	Node* tmp = dupSet[SET_IDX].front;
	tmp = tmp->next;
	lstat(dupSet[SET_IDX].front->data, &st);
	time_t REC_TIME = st.st_mtime;
	while(tmp != NULL){
		checkIDX++;
		lstat(tmp->data, &st);
		if(REC_TIME < st.st_mtime){
			REC_TIME = st.st_mtime;
			REC_IDX = checkIDX;
		}
		tmp = tmp->next;
	}


	free(tmp);

	return REC_IDX;
}

int d_delete(int SET_IDX, int LIST_IDX, Queue* dupSet, int k){
	if(SET_IDX < 0 || LIST_IDX < 0){
		fprintf(stderr, "[INDEX] input error(non-negative)\n");
		return k;
	}
	int t = k;
	k = deleteNode(dupSet, SET_IDX-1, LIST_IDX, k);

	if(t == k){} // after delete -> no change in dupSet list index
	else{ // after delete -> dupSet list index--
		if(SET_IDX == t){ //  SET_IDX == last index of dupSet
			initQueue(&dupSet[SET_IDX]);
		}
		else{ // SET_IDX != last index of dupSet
			for(int i=SET_IDX-1; i<k; i++){ 
				dupSet[i] = dupSet[i+1];
			}
			initQueue(&dupSet[k]);
		}
	}
	return k;
}

int i_delete(int SET_IDX, Queue* dupSet, int k){
	if(SET_IDX < 0){
		fprintf(stderr, "[INDEX] input error(non-negative)\n");
		return k;	
	}
	int t = k;
	k = deleteNode_ask(dupSet, SET_IDX-1, dupSet[SET_IDX-1].count, k);

	if(t == k){} // after delete -> no change in dupSet list index
	else{ // after delete -> dupSet list index--
		if(SET_IDX == t){ //  SET_IDX == last index of dupSet
			initQueue(&dupSet[SET_IDX]);
		}
		else{ // SET_IDX != last index of dupSet
			for(int i=SET_IDX-1; i<k; i++){ 
				dupSet[i] = dupSet[i+1];
			}
			initQueue(&dupSet[k]);
		}
	}

	return k;
}



int f_delete(int SET_IDX, Queue* dupSet, int k){
	if(SET_IDX < 0){
		fprintf(stderr, "[INDEX] input error(non-negative)\n");
		return k;	
	}

	int REC_IDX;

	REC_IDX = get_recentIDX(dupSet, SET_IDX-1);
	deleteNode_force(dupSet, SET_IDX-1, REC_IDX, k);
	if(SET_IDX == k){
		initQueue(&dupSet[SET_IDX]);
	}
	else{
		for(int i=SET_IDX-1; i<k; i++){
			dupSet[i] = dupSet[i+1];
		}
		initQueue(&dupSet[k]);
	}

	return k-1;
}

int t_delete(int SET_IDX, Queue* dupSet, int k){
	if(SET_IDX < 0){
		fprintf(stderr, "[INDEX] input error(non-negative)\n");
		return k;	
	}
	int t = k;

	return k;
}
