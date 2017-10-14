CPP_FILES := $(wildcard src/*.cpp)
OBJ_FILES := $(addprefix obj/,$(notdir $(CPP_FILES:.cpp=.o)))
LD_FLAGS := -lpcap
CC_FLAGS := -I include/

mydump: $(OBJ_FILES)
	g++ -o $@ $^ $(LD_FLAGS)

obj/%.o: src/%.cpp
	g++ $(CC_FLAGS) -c -o $@ $<

clean :
	\rm -fr obj/*
	\rm -fr mydump
	\rm -fr *~
	\rm -fr src/*~
	\rm -fr include/*~
