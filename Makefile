# ------------------------------------------------
# Generic Makefile, capable of including static
# libraries
#
# Modified by:      admin@enudstudios.com
# Date:             2020-01-09
#
# Original Author:  yanick.rochon@gmail.com
# Date:             2011-08-10
# ------------------------------------------------

# Name of the created executable
TARGET     := liblcp.a

# Get the absolute path to the directory this makefile is in
MKFILE_PTH := $(abspath $(lastword $(MAKEFILE_LIST)))
MKFILE_DIR := $(dir $(MKFILE_PTH))

# The compiler to use
CC         := gcc
# Error flags for compiling
ERRFLAGS   := -Wall -Wextra -Wmissing-prototypes -Wstrict-prototypes -Wold-style-definition
# Compiling flags here
CFLAGS     := -g -O0 -ansi -std=c89 -I. -I./inc/ -pedantic

# The linker to use
LINKER     := gcc

# Change these to proper directories where each file should be
SRCDIR     := src
OBJDIR     := obj

SOURCES    := $(wildcard $(SRCDIR)/*.c)
OBJECTS    := $(SOURCES:$(SRCDIR)/%.c=$(OBJDIR)/%.o)

rm         := rm -f

$(TARGET): $(OBJECTS)
	@ar -r -o $@ $^
	@echo "Linking complete!"

$(OBJECTS): $(OBJDIR)/%.o : $(SRCDIR)/%.c
	@$(CC) $(CFLAGS) $(ERRFLAGS) -c $< -o $@
	@echo "Compiled "$<" successfully!"
