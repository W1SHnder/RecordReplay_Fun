/*BEGIN_LEGAL 
		Intel Open Source License 

		Copyright (c) 2002-2016 Intel Corporation. All rights reserved.

		Redistribution and use in source and binary forms, with or without
		modification, are permitted provided that the following conditions are
met:

Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.  Redistributions
in binary form must reproduce the above copyright notice, this list of
conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.  Neither the name of
the Intel Corporation nor the names of its contributors may be used to
endorse or promote products derived from this software without
specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE INTEL OR
ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
END_LEGAL */
/*
	*  This file contains an ISA-portable PIN tool for tracing system calls
	*/


#define NDEBUG

#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <string>
#include <vector>

#include <sys/syscall.h>
#include "pin.H"

#include <sys/time.h>
#include <errno.h>
#include <signal.h>
#include <iostream>
#include <time.h>


using std::string;
using std::cerr;
using std::endl;

FILE * trace;
bool isMainProgram = false;

KNOB<BOOL>   KnobReplay(KNOB_MODE_WRITEONCE,  "pintool",
				"replay", "0", "replay the program");

KNOB<string> KnobLogFile(KNOB_MODE_WRITEONCE, "pintool", "o", "trace.out", "specify trace file name");

std::vector<std::pair<ADDRINT, ADDRINT>> syscall_returns;

//Instrumentation variables
char num1_str[1024];
char num2_str[1024];
bool read_found = false;
ADDRINT read_buf = 0;


/*
struct RtnData {
  int err;
  
  char* return;
}; 

struct ProgramData {
  char* num1;
  char* num2;
  vector<Return> syscall_returns;
  vector<Return> libcall_returns;
  
};

vector<Return> syscall_returns = {};

ProgramData* ReadData(FILE* f) {
  ProgramData out = 
} //ReadData
*/

/*
VOID AppStart(VOID *v)
{
  num1 = (char*)malloc(100);

}
*/

VOID SysBefore(ADDRINT ip, ADDRINT num, ADDRINT arg0, ADDRINT arg1, ADDRINT arg2, 
		      ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, CONTEXT *ctxt)
{
  if(!isMainProgram) return;
  
  if(KnobReplay == true)
    {
           
    } else {
   	if (num == SYS_read && !read_found) {
	    read_found = true;
	    read_buf = arg1;
	} 
    } //endif
}


VOID SysAfter(ADDRINT ret, ADDRINT err)
{
  //std::cout << "Reacehd SysAfter" << endl;
  if(!isMainProgram) return;
  
  if(KnobReplay == false)
    { 
      // Record non-deterministic inputs and store to "trace"
      
      //Record num2
      if (read_found && read_buf != 0) {
	
	char* read_str = (char*)malloc(ret);
	PIN_SafeCopy(read_str, (void*)read_buf, ret);
	fprintf(trace, "num2: %s\n", read_str);
	fflush(trace);
	free(read_str);
	read_buf = 0;
      } //endif
    } //endif
}

VOID MainBegin()
{ 
  isMainProgram = true;
}

VOID MainReturn()
{
  isMainProgram = false;
}



/*
VOID rand_hook(CONTEXT *ctxt)
{
  if (KnobReplay) {
    fprintf((FILE*)1, "Not yet implemented");
  } else {
    unsigned long int rand_num = PIN_CallApplicationFunction(ctxt, PIN_ThreadId(), CALLINGSTD_DEFAULT, (AFUNPTR)IARG_ORIG_FUNCPTR);
    fprintf(trace, "rand: %lu\n", rand_num);
    fflush(trace);
  } 
}

*/

VOID timeBefore(time_t *timer)
{
  fprintf(trace, "time: %lu\n", *timer);
} 

time_t time_hook(CONTEXT* ctxt, AFUNPTR time_fp, time_t* tmr)
{
  std::cout << "Reached bullshit" << endl;
 

  time_t res;

  PIN_CallApplicationFunction(ctxt, PIN_ThreadId(), 
		  CALLINGSTD_DEFAULT, time_fp, 
		  PIN_PARG(time_t), res, PIN_PARG(time_t*), tmr, PIN_PARG_END());

  if (KnobReplay) {

  } else {
    std::cout << "Reached time hook" << endl;
    //ADDRINT timer = PIN_GetContextReg(ctxt, REG_RAX);
    fprintf(trace, "time: %lu\n", res);
  }
    return res;
}

VOID Image(IMG img, VOID *v)
{
  RTN mainRtn = RTN_FindByName(img, "__libc_start_main");
  //ADDRINT mainaddr = (ADDRINT)0x4012A1;
  //RTN mainRtn = RTN_FindByAddress(mainaddr); 
  //RTN freadRtn = RTN_FindByName(img, "fread");
  //RTN localtimeRtn = RTN_FindByName(img, "localtime");
  if(RTN_Valid(mainRtn))
    {
      RTN_Open(mainRtn);
      RTN_InsertCall(mainRtn, IPOINT_BEFORE, (AFUNPTR)MainBegin, IARG_END);
      RTN_InsertCall(mainRtn, IPOINT_AFTER, (AFUNPTR)MainReturn, IARG_END);
      RTN_Close(mainRtn);
    }
  
  
  RTN timeRtn = RTN_FindByName(img, "time"); 
  
  if (RTN_Valid(timeRtn))
    {
      //RTN_Open(timeRtn); 
      PROTO protoTime = PROTO_Allocate(PIN_PARG(time_t*), CALLINGSTD_DEFAULT, "time", PIN_PARG(time_t *), PIN_PARG_END());
      RTN_ReplaceSignature(timeRtn, AFUNPTR(time_hook), 
		      IARG_PROTOTYPE, protoTime, 
		      IARG_CONST_CONTEXT, 
		      IARG_ORIG_FUNCPTR, 
		      IARG_FUNCARG_ENTRYPOINT_VALUE, 0, 
		      IARG_END);
      //RTN_Close(timeRtn);
    }
  
  
}

VOID Instruction(INS ins, VOID *v)
{
  if(INS_IsSyscall(ins)) {
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SysBefore),
		   IARG_INST_PTR, IARG_SYSCALL_NUMBER,
		   IARG_SYSARG_VALUE, 0, IARG_SYSARG_VALUE, 1,
		   IARG_SYSARG_VALUE, 2, IARG_SYSARG_VALUE, 3,
		   IARG_SYSARG_VALUE, 4, IARG_SYSARG_VALUE, 5,
		   IARG_CONTEXT, IARG_END);
  }
} //Instruction


VOID SyscallExit(THREADID threadIndex, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v)
{
  SysAfter(PIN_GetSyscallReturn(ctxt, std), PIN_GetSyscallErrno(ctxt, std));
}

VOID Fini(INT32 code, VOID *v)
{
  std::cout << "Reached Fini" << endl; 
  fclose(trace);
}

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage()
{
  cerr <<
    "This tool record/replay the program.\n"
    "\n";

  cerr << KNOB_BASE::StringKnobSummary();

  cerr << endl;

  return -1; 

}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char *argv[])
{
  /*
    if (KnobReplay) {
    FILE* temp = fopen(KnobLogFile.Value().c_str(), "rb");
    fscanf(temp, "num1: %s\n", argv[argc-1]);
    std::cout << "num1: " << argv[argc-1] << endl;
  }
  */
  PIN_InitSymbols();
  if (PIN_Init(argc, argv)) return Usage();
 
	
  if (KnobReplay)
    {
      trace = fopen(KnobLogFile.Value().c_str(), "rb");
      fscanf(trace, "num1: %s\n", num1_str);
      fscanf(trace, "num2: %s\n", num2_str); 
      //Replaces argv1
      //fscanf(trace, "num1: %s\n", argv[argc-1]);
      //std::cout << "num1: " << argv[argc-1] << endl;
      //if (PIN_Init(argc, argv)) return Usage();
      printf("====== REPLAY MODE =======\n");
    }
  else
    {
      trace = fopen(KnobLogFile.Value().c_str(), "wb");
      //Stores the first number to trace
      fprintf(trace, "num1: %s\n", argv[argc-1]);
      //if (PIN_Init(argc, argv)) return Usage();
      printf("====== RECORDING MODE =======\n");
    }

  if(trace == NULL)
    {
      fprintf(stderr, "File open error! (trace.out)\n");
      return 0;
    }


  IMG_AddInstrumentFunction(Image, 0);
  INS_AddInstrumentFunction(Instruction, 0);
  PIN_AddSyscallExitFunction(SyscallExit, 0);


  PIN_AddFiniFunction(Fini, 0);

  // Never returns
  PIN_StartProgram();

  return 0;
}
