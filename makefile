CC = cc
CFLAGS = -Wall -g
OBJ = server.o hash.o parser.o userdb.o
TARGET = server

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJ) -l sqlite3 -l json-c -l ssl -l crypto 

server.o: server.c 
	$(CC) $(CFLAGS) -c server.c

userdb.o: lib/src/userdb.c lib/include/userdb.h
	$(CC) $(CFLAGS) -c lib/src/userdb.c 

hash.o: lib/src/hash.c lib/include/hash.h
	$(CC) $(CFLAGS) -c lib/src/hash.c

parser.o: lib/src/parser.c lib/include/parser.h
	$(CC) $(CFLAGS) -c lib/src/parser.c

clean:
	rm -f $(OBJ) $(TARGET)