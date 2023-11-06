objects = interceptd.o

interceptd.o: interceptd.cpp
	gcc -c interceptd.cpp
	
all: $(objects)
	 gcc -o interceptd $(objects) -lstdc++
clean:
	 rm -f *.o
	 