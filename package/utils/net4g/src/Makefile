
CLIENT 		 = net4g
CLIENT_OBJ 	 = main.o

UART_CFLAGS       = $(CFLAGS) -g -Wall -std=gnu99
UART_LDFLAGS      = $(LDFLAGS) -lm -lpthread

all: clean  $(CLIENT)
	
$(CLIENT):$(CLIENT_OBJ)
	$(CC) -o $@ $^ $(UART_LDFLAGS) -llua -lubox

%.o : %.c
	$(CC) -c $< $(UART_CFLAGS) -o $@

clean:
	rm -rf *.[oa]  $(CLIENT) *.~ *~

