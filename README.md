# ZigZagFuzz

ZigZagFuzz is implemented on top of AFL++, and you can use ZigZagFuzz in a similar way to AFL++.
The documentation below focuses on the difference from AFL++.
Please refer [AFL++_readme](README_AFL++.md) to get a basic understanding of the base fuzzer, AFL++.

We recently updated the underlying AFL++ version to the recent version (4.22a).
If you find any problem regarding the code, please open a github issue.
You can find the archived version in another branch (tosem_2024).

## Prerequisite
ZigZagFuzz has been tested on Ubuntu 18.04 and 20.04.

1. Clang/LLVM 13.0.1 (You may need some minor changes for other LLVM versions)
1. Whole Program LLVM in Go ([gllvm](https://github.com/SRI-CSL/gllvm))
1. Python 3
1. (Optional) gcovr

## Build
You can simply run `make` command to build ZigZagFuzz.

## Instrumentation
You can perform instrumentation in the same way as AFL++.
I recommend you to use [gllvm](https://github.com/SRI-CSL/gllvm) and get a whole bitcode of the subject program before performing instrumentation.

For example, `${ZigZagFuzz_repo}/afl-clang-lto++ <target.bc> -o <target.afl> <ld flags...>` will give you an instrumented program.

## Structure of a test case
ZigZagFuzz considers a test case as a pair of a program option input and a file input.
To conveniently mutate both inputs, ZigZagFuzz generates two separate files for each test case.
(One for the command line option, and the other for the file.)

The file inputs are saved in the ordinary `queue` directory in the output directory,
while the command-line option inputs are saved in the `queue_argv` directory.
Each file pair with the same ID will be considered as a test case.

The instrumented program will take only one command-line option,
the path to the command-line option input file. The instrumented code in the main function
will interpret the given command-line option input file, and it will begin the execution.

## Run ZigZagFuzz
You can start execution as similar to AFL++.

For example, you can run `afl-fuzz` with the following command.

`${ZigZagFuzz_repo}/afl-fuzz -i <initial seed dir> -o <output dir> -K 2 -a <dictinary file path> -- <target.afl> <initial args...>`

You can find dictionary file examples in `paper_exp/keyword_dict/`.
The dictionary file is a simple list of keywords that can be used in command-line options.

## Experiment setups
You can find experiment materials in `paper_exp/`.

## Replay
When ZigZagFuzz saves program option input files, it replaces the file path arguments with the placeholder string `@@`.
This makes it easier to mutate command-line option files during fuzzing.

To replay a saved test case, you must replace the first occurrence of `@@` in the command-line input with the actual path to the corresponding file input.

Refer to the following example for clarification.

## Working example
1. Build ZigZagFuzz
    ```bash
    cd ${ZigZagFuzz_Repo}
    make
    ```
2. Build and instrument a target program
    ```bash
    mkdir subjects
    wget https://github.com/davea42/libdwarf-code/releases/download/v0.5.0/libdwarf-0.5.0.tar.xz
    tar -xf libdwarf-0.5.0.tar.xz
    cd libdwarf-code-0.5.0
    bash ./autogen.sh
    CC=gclang ./configure --prefix=`pwd`/install_dir --disable-shared
    make -j 20
    make install
    cd install_dir/bin
    get-bc dwarfudmp
    ${ZigZagFuzz_repo}/afl-clang-lto ./dwarfdump.bc -o ../../../subjects/dwarfdump.afl -lz
    ```

3. Run ZigZagFuzz
    ```bash
    cd /tmp/
    ${ZigZagFuzz_Repo}/afl-fuzz -i ${ZigZagFuzz_Repo}/paper_exp/init_seeds/dwarfdump \
        -o out_dwarfdump_1 -K 2 -a ${ZigZagFuzz_Repo}/paper_exp/keyword_dict/dwarfdump -- \
        subjects/dwarfdump.afl -b -a -r -f -i -ls -c -ta @@
    ```
4. Replay generated test inputs

    0. **Note**
       
       The previously instrumented binary (e.g., `dwarfdump.afl`) cannot be used directly for replaying generated inputs.  
       You must rebuild the program with the following configuration.

    2. **Prepare Inputs**
       
       Each test input consists of:
       - A file input (located under `queue/` or `crashes/`)
       - A command-line input (located under `queue_argvs/` or `crashes_argvs/`)

       Each pair shares the same ID.  
       Crashing inputs are stored under the `crashes` and `crashes_argvs` directories.

   
    3. **Prepare to perform a clean build.**
       
    ```bash
    rm -rf libdwarf-code-0.5.0
    tar -xf libdwarf-0.5.0.tar.xz
    cd libdwarf-code-0.5.0
    ```

    3. **Insert the Replay Probe**
       
    Add the following lines to the beginning of the main function in the target program’s source file
    (e.g., `src/bin/dwarfdump/dwarfdump.c`):

    ```c
    #include "${ZigZagFuzz_repo}/utils/argv_fuzzing/argv-fuzz-inl.h"
    
    int 
    main(int argc, char * argv[])
    {
        AFL_INIT_ARGV();
        ...
    ```

    4. **Rebuild the Program**

    ```bash
    bash ./autogen.sh
    ./configure --prefix=`pwd`/gcov_install --disable-shared
    make -j 20
    make install
    ```

    5. **Run the Replay**
   
    To replay a test case, replace the first `@@` in the saved command-line input with the actual file input path.
   
    For example, if the command line input is `@@ -a -b -c @@`, the actual command line should be `./<program> <poc> -a -b -c @@`.

    - `<program>` is the rebuilt program from step 4
    - `<poc>` is the path to the file input.

4. Replay with gcov coverage information
    1. Prepare to perform a clean build.
    ```bash
    rm -rf libdwarf-code-0.5.0
    tar -xf libdwarf-0.5.0.tar.xz
    cd libdwarf-code-0.5.0
    ```

    2. Put the probe code in the main function as in the following example.
    
    `src/bin/dwarfdump/dwarfdump.c`
    ```c
    #include "${ZigZagFuzz_repo}/utils/argv_fuzzing/argv-fuzz-inl.h"
    
    int 
    main(int argc, char * argv[])
    {
        AFL_INIT_ARGV();
        ...
    ```

    3. Build with coverage configuration flags.

    ```bash
    bash ./autogen.sh
    CFLAGS="-g -O0 --coverage" CC=clang ./configure --prefix=`pwd`/gcov_install --disable-shared
    make -j 20
    make install
    ```

    4. Run the replay script.
    ```bash
    python3 ${ZigZagFuzz_repo}/utils/get_gcov.py libdwarf-code-0.5.0/gcov_install/bin/dwarfdump \
        /tmp/out_dwarfdump_1/default/queue/ 3600 100
    ```
    It will show the branch coverage over time.

