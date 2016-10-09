## core information
## build-configuration info
CC           = gcc

OBJ_DIR     = ./obj
OBJS        = $(OBJ_DIR)/afpacket.o\
              $(OBJ_DIR)/pktrecv.o
              
HEADS   = pub.h afpacket.h

EXEC    = ./pkt_recv

all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) -o $(EXEC) $(OBJS) -lpthread -lm -static
##scp $(EXEC) root@192.168.9.88:~

$(OBJ_DIR)/afpacket.o : afpacket.c $(HEADS)
	$(CC)  -c afpacket.c -o $(OBJ_DIR)/afpacket.o
	
$(OBJ_DIR)/pktrecv.o : pktrecv.c $(HEADS)
	$(CC)  -c pktrecv.c -o $(OBJ_DIR)/pktrecv.o
	
clean:
	rm -f $(EXEC) $(OBJS) *.bak