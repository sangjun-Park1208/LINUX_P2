all : ssu_sdup ssu_find-md5 ssu_find-sha1 ssu_help

ssu_sdup : ssu_sdup.o
	gcc ssu_sdup.o -o ssu_sdup

ssu_help : ssu_help.o
	gcc ssu_help.o -o ssu_help

ssu_find-md5 : ssu_find-md5.o
	gcc ssu_find-md5.o -o ssu_find-md5 -lcrypto

ssu_find-sha1 : ssu_find-sha1.o
	gcc ssu_find-sha1.o -o ssu_find-sha1 -lcrypto

ssu_sdup.o: ssu_sdup.c
	gcc -c ssu_sdup.c

ssu_help.o: ssu_help.c
	gcc -c ssu_help.c

ssu_find-md5.o: ssu_find-md5.c
	gcc -c ssu_find-md5.c -lcrypto

ssu_find-sha1.o: ssu_find-sha1.c
	gcc -c ssu_find-sha1.c -lcrypto

clean:
	rm ssu_sdup.o
	rm ssu_help.o
	rm ssu_find-md5.o
	rm ssu_find-sha1.o
	rm ssu_sdup
