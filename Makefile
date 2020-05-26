CC            := gcc
OUT_FILE_NAME := lcp.a

CFLAGS        := -fPIC -O0 -g -Wall -c -pedantic -std=c89 -ansi -I.

# The directory to put the object-files into
OBJ_DIR       := ./obj

$(OUT_FILE_NAME): $(patsubst %.c,$(OBJ_DIR)/%.o,$(wildcard *.c))
	@ar -r -o $@ $^
	@echo "Linking complete!"

$(OBJ_DIR)/%.o: %.c dirmake
	@$(CC) -c $(CFLAGS) -o $@  $<
	@echo "Compiled "$<" successfully!"

dirmake:
	@mkdir -p $(OBJ_DIR)
