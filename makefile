CC = cc
CFLAGS = -Wall -g
OBJ = server.o hash.o parser.o userdb.o
TARGET = server

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJ) -l sqlite3

server.o: driver.c lib/wordlib.h
	$(CC) $(CFLAGS) -c driver.c

hash.o: lib/src/hash.c lib/include/hash.h
	$(CC) $(CFLAGS) -c lib/word.c 

term.o: lib/term.c lib/termlib.h
	$(CC) $(CFLAGS) -c lib/term.c

worddb.o: lib/worddb.c lib/worddblib.h
	$(CC) $(CFLAGS) -c lib/worddb.c

clean:
	rm -f $(OBJ) $(TARGET)