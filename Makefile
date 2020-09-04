SRCDIR ?= src
OBJDIR ?= obj
BINDIR ?= bin

target := $(BINDIR)/opt
srcs := $(foreach sdir, $(SRCDIR), $(wildcard $(sdir)/*.c))
objects := $(patsubst $(SRCDIR)/%.c, $(OBJDIR)/%.o, $(srcs))
$(info $(srcs) $(objects))

ifeq ($(OS),Windows_NT)
	LLIB := -ladvapi32 -liphlpapi -lpsapi -luser32 -luserenv -lws2_32 -luv
else
	LLIB := -luv
endif

all: $(target)

$(target): checkdirs $(objects)
	
	gcc -Wall -O2 -g\
		$(objects) -o $@ \
		$(LLIB)
		

checkdirs: 
	mkdir -p $(BINDIR)
	mkdir -p $(OBJDIR)

$(objects): $(OBJDIR)/%.o : $(SRCDIR)/%.c
	cc -c -g $< -o  $@


.PHONY : clean
clean :
	-rm -r $(OBJDIR) $(BINDIR)