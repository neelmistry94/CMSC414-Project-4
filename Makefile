CC = gcc
CFLAGS = -fno-stack-protector -Wall -Iutil -Iatm -Ibank -Irouter -I. -g -O0
LIBS = -lssl -lcrypto -ldl
UTILS = util/list.c

UNAME := $(shell uname)
ifeq ($(UNAME),Linux)
CFLAGS += -DLINUX -I/usr/local/ssl/include -L/usr/local/ssl/lib
endif



all: bin/atm bin/bank bin/router bin/init

bin/atm : atm/atm-main.c atm/atm.c
	${CC} ${CFLAGS} atm/atm.c atm/atm-main.c -o bin/atm ${LIBS}

bin/bank : bank/bank-main.c bank/bank.c
	${CC} ${CFLAGS} bank/bank.c bank/bank-main.c ${UTILS} -o bin/bank ${LIBS}

bin/router : router/router-main.c router/router.c
	${CC} ${CFLAGS} router/router.c router/router-main.c -o bin/router ${LIBS}

bin/init : init.c
	${CC} ${CFLAGS} init.c -o bin/init ${LIBS}

test : util/list.c util/list_example.c util/hash_table.c util/hash_table_example.c
	${CC} ${CFLAGS} util/list.c util/list_example.c -o bin/list-test ${LIBS}
	${CC} ${CFLAGS} util/list.c util/hash_table.c util/hash_table_example.c -o bin/hash-table-test ${LIBS}

clean:
	cd bin && rm -f atm bank router init list-test hash-table-test *.atm *.bank *.card

reset:
	cd bin && rm -f *.atm *.bank *.card

cclear:
	cd bin && rm -f *.card

mcclear:
	make && make cclear
