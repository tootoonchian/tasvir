# Tasvir: A Versioned Shared Memory Interface
Tasvir consists of a library and daemon which provides programs a raw, versioned, publish-subscribe shared memory interface.
Tasvir-allocated areas are versioned, atomically updated, and single-writer.

## Building Tasvir

* Install `byobu, cmake, git, uthash-dev`.
* Install DPDK 17.05 and set `RTE_SDK` and `RTE_TARGET`. Insert `igb_uio` and ensure that you can bind the NIC you intend to use with Tasvir to it.
* Clone this repository and use the helper script to compile Tasvir: `scripts/run.sh compile`.
* If successful, the binaries will be under `build/bin`.

## Developing and building your application

Let's assume an application named `testapp` with a single C++ source file `testapp.cpp`. The process is as follows.

* Create a directory under `apps` and add it to `apps/CMakeLists.txt`.
```
mkdir apps/testapp && echo 'add_subdirectory(testapp)' >> apps/CMakeLists.txt
```
* Add a `CMakeLists.txt` file to this directory for building the application. You may use a Tasvir-provided helper macro.
```
echo 'add_tasvir_exec(tasvir_testapp testapp.cpp)' >> apps/testapp/CMakeLists.txt
```
* Use `apps/sample/sample.cpp` as a template for developing your application.
* When you recompile Tasvir, the compiled binary for this app will be placed in `build/bin/tasvir_testapp`.

## Running your application.

Before running a Tasvir-based program, a daemon must be started on each machine.
One of these daemons must be designated as the root daemon to manage the root Tasvir area.
The helper script simplifies this process.

* Create a bash function in `scripts/run.sh` named after your program.
* Inside your function, declare an array named `host_list` which contains the list of machines you want your program to run on.
* Inside your function, declare an associative array named `host_nthreads` which specifies how many threads may be allocated on each machine. Note that the first thread on each machine would be the daemon thread -- to have `n` program threads per machine you must set the values to `n + 1`.
* In the run script, adjust the `HOST_NIC` associative array to list the PCI address of the NIC to be exclusively used by Tasvir for each machine.
* In the run script, adjust the `HOST_NCORES` associative array to list the number of cores available to Tasvir on each machine.
* Ensure that every entry in `host_list` appears in `host_nthreads, HOST_NIC, HOST_NCORES`.
* Use `generate_cmd` to generate and run all the necessary commands. You may use placeholders such as `%TID%, %CORE%, %NTHREADS%` to pass a unique tid, core the program is pinned to, and the total number of threads to your program. The following example passes the core number as the first argument to your program.
```
eval $(generate_cmd $TASVIR_BINDIR/tasvir_testapp %CORE%)
```
* Run your application using `scripts/run.sh testapp`.
* If successful, a byobu session will appear using which you may monitor your program's execution.
* The output of each thread is also logged in `scripts/log/$timestamp`.
