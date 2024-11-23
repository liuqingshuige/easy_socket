# 获取当前目录下的所有c文件
SRC = $(wildcard *.c) 

# 将src中的所有.c文件替换为.o文件
OBJS = $(patsubst %.c,%.o,$(SRC)) 

CC = gcc

RM = rm -rf

LIBS_PATH =

LIBS = -lpthread

INCLUDE = -I./

TARGET = test

$(TARGET): $(OBJS)
	$(CC) -o $(TARGET) $(OBJS) $(INCLUDE) $(LIBS_PATH) $(LIBS)
	$(RM) *.o
		
$(OBJS): $(SRC)	
	$(CC) -c $(SRC) $(INCLUDE) $(LIBS_PATH) $(LIBS)

.PHONY: clean
clean:
	rm -f *.o $(TARGET)


