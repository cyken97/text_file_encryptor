all: encrypt352.c encrypt-module.c encrypt-module.h
	gcc -o encrypt352 encrypt352.c encrypt-module.c -pthread