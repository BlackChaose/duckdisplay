run:
	gcc -Wall -Wextra -Wshadow -pedantic -fsanitize=address  ./src/main.c -o ./bin/toby
	./bin/toby
debug:
	gcc -g ./src/main.c
	gdb -tui a.out