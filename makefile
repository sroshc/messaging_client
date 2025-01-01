CC = cc
CFLAGS = -Wall -g
OBJ = server.o hash.o parser.o userdb.o encode.o msgqueue.o
TARGET = server

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJ) -l sqlite3 -l json-c -l ssl -l crypto -g

server.o: server.c 
	$(CC) $(CFLAGS) -c server.c

userdb.o: lib/src/userdb.c lib/include/userdb.h
	$(CC) $(CFLAGS) -c lib/src/userdb.c 

hash.o: lib/src/hash.c lib/include/hash.h
	$(CC) $(CFLAGS) -c lib/src/hash.c

parser.o: lib/src/parser.c lib/include/parser.h
	$(CC) $(CFLAGS) -c lib/src/parser.c

encode.o: lib/src/encode.c lib/include/encode.h
	$(CC) $(CFLAGS) -c lib/src/encode.c

msgqueue.o: lib/src/msgqueue.c lib/include/msgqueue.h
	$(CC) $(CFLAGS) -c lib/src/msgqueue.c

clean:
	rm -f $(OBJ) $(TARGET)