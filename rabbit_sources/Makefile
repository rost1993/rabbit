CC=gcc
CFLAGS=-Wall

MAIN_OBJS=ecrypt-sync.o rabbit.o main.o
BIGTEST_OBJS=ecrypt-sync.o rabbit.o bigtest_2.o

MAIN=main
BIGTEST=bigtest_2

all: $(MAIN) $(BIGTEST)

.c.o:
	$(CC) $(CFLAGS) -c $^ -o $@

$(MAIN): $(MAIN_OBJS)
	$(CC) $(CFLAGS) -o $@ $^

$(BIGTEST): $(BIGTEST_OBJS)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f *.o $(MAIN) $(BIGTEST)
