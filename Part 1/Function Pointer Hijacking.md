Im still extremly new to this so if anyone reads this and sees the amount of stuff called\worded wrong let me know
==================================================================================================================

For This Part it is simply going to be the most basic type of exploit, overwriting the EIP with another functions address
It also is going to be a high level view of the stack ect as im still learning and not informed Enough to be trying to teach people (If Anyone Ever Reads this)

Here Is a Good Link Explaining the Stack And Stack Smashing
      https://owasp.org/www-chapter-pune/meetups/2019/August/Buffer_overflow_by_Renuka_Sharma.pdf

----

For refernce Here is the source Code
============================================================
        #include <stdio.h>
        #include <stdlib.h>
        #include <string.h>
        
        void shell() {
        	system("/bin/bash");
        }
        
        
        void copy(char *msg) {
        	char buffer[250];
        	strcpy(buffer, msg);
        }
        
        int main(int argc, char const *argv[])
        {
        	copy(argv[1]);
        	printf("Nice One Retard It Didnt Overflow!\n");
        	return 0;
        }
==============================================================

As You can see all it does is, instatly Jump to the copy function and passes argv[1] (The First Command line argument, ./buffer Hello, it passes hello)
Which then simply just uses strcpy to copy it into the buffer which has a max value of 250 bytes (Note How strcpy Has 0 boundry checking)
There is also the function "shell" but it never gets called so its just dead code

But What If we could copy so many characters into the buffer that it "overflows" into other memory address's? What Effects Could that possibly have?

NOTE
    Modern Day Systems Have Built In protections against these Types of attacks such as ASLR(Address space layout randomization), DEP (Data Execution Protection), NX (No Executable)
    But Since We a Simply beginners we will turn these off (For this type of attack NX/DEP Doesnt really matter as we arent injecting shellcode)

    To Turn Off ASLR 
            echo 0 > /proc/sys/kernel/randomize_va_space ; Will Need Sudo Or Root

    To Turn Off DEP/NX
            compile with the flag: -z execstack, this allow the stack\heap to be executable

============================

Now Lets Compile Our Program so we can start
      gcc -m32 -fno-stack-protection -no-pie -g -z execstack -o buffer buffer.c

      -m32
          Compile to a 32bit exectuable, Uses ASM instructions such as EAX, EBX, ECX, EDX, ESP, EBP, EIP

      -fno-stack-protection
          Turn Off Stack Protection mechanisms, Such as Stack Smashing Protection(SSP), These are made to identify Stack Based Overflow attempts and stop attackers

      -no-pie 
          Turn Off Postion Independant executable, PIE randomizes the base address of exectuables, makes it harder to find/predict memory addresses

      -g
          Include Debugging information

      -z exectack
          Allows the stack/heap to be executable
=============================

Now Onto the Fun Part! Lets start exploiting this program


For Starters Let Just Pass 10 Characters

![First](https://github.com/zevuxo1/Buffer-Overflow-Tutorial/assets/155918223/ea0257bd-8653-4900-a6d4-10714dad3a2e)





        
  
      


  