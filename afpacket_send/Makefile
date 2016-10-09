## core information
## build-configuration info
CC           = gcc 

OBJ_DIR     = ./obj
OBJS        = $(OBJ_DIR)/dictionary.o\
              $(OBJ_DIR)/iniparser.o\
              $(OBJ_DIR)/afpacket.o\
              $(OBJ_DIR)/pktsend.o
              
HEADS   = dictionary.h iniparser.h pub.h afpacket.h

EXEC    = ./main

all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) -o $(EXEC) $(OBJS) -lpthread -lm -static
##scp $(EXEC) root@192.168.9.88:~
	
$(OBJ_DIR)/dictionary.o : dictionary.c $(HEADS)
	$(CC)  -c dictionary.c -o $(OBJ_DIR)/dictionary.o

$(OBJ_DIR)/iniparser.o : iniparser.c $(HEADS)
	$(CC)  -c iniparser.c -o $(OBJ_DIR)/iniparser.o
	
$(OBJ_DIR)/afpacket.o : afpacket.c $(HEADS)
	$(CC)  -c afpacket.c -o $(OBJ_DIR)/afpacket.o
	
$(OBJ_DIR)/pktsend.o : pktsend.c $(HEADS)
	$(CC)  -c pktsend.c -o $(OBJ_DIR)/pktsend.o
	
clean:
	rm -f $(EXEC) $(OBJS) *.bak
