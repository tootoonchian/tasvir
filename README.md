# Tasvir: A Versioned Shared Memory Interface
Tasvir consists of a library and daemon which provides programs a raw, versioned, publish-subscribe shared-memory interface over the network.
Tasvir-allocated areas are versioned, atomically updated, and single-writer.

## Building Tasvir

* Install `byobu, cmake, git, uthash-dev`.
* Install DPDK 19.08 and set `RTE_SDK` and `RTE_TARGET`. Ensure that you can bind the NIC you want Tasvir to use to a DPDK-compatible driver (e.g., `igb_uio` or `vfio_pci`).
* Clone this repository and use the helper script to compile Tasvir: `tools/run.sh compile`.
* If successful, the binaries will be under `build.gcc/bin` or `build.clang/bin` depending on your compiler choice..

## Developing and building your application

To add an application named `testapp` with a single C++ source file `testapp.cpp` to use Tasvir's build process follow these steps:

* Create a directory under `apps` and add it to `apps/CMakeLists.txt`.
```
mkdir apps/testapp && echo 'add_subdirectory(testapp)' >> apps/CMakeLists.txt
```
* Add a `CMakeLists.txt` file to this directory for building the application. You may use our helper macro.
```
echo 'add_tasvir_exec(tasvir_testapp testapp.cpp)' >> apps/testapp/CMakeLists.txt
```
* Follow `apps/sample/counter.cpp` as a template for developing your application.
* The binary for this app will be placed in the build binary directory after compilation.

## Running your application.

Before running a Tasvir-based program, a daemon must be started on each machine.
One of these daemons must be designated as the root daemon to manage the root Tasvir area.
The helper script simplifies this process.
Create `etc/run_testapp.conf` using `etc/run_sample.conf` as a template; the bash variables must start with `testapp_`.
Adjust `etc/tasvir.conf` to match your cluster setup; note that the script needs passwordless ssh access to the listed hosts.
Finally, you would be able to run your application using `tools/run.sh testapp`.
The script prints the directory it logs the outputs to and creates a tmux session to run the experiment.
