# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.8

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /cygdrive/c/Users/pas-s/.CLion2017.2/system/cygwin_cmake/bin/cmake.exe

# The command to remove a file.
RM = /cygdrive/c/Users/pas-s/.CLion2017.2/system/cygwin_cmake/bin/cmake.exe -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /cygdrive/d/Crypto/Crypto2_GIT

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /cygdrive/d/Crypto/Crypto2_GIT/cmake-build-debug

# Include any dependencies generated for this target.
include CMakeFiles/Crypto2_GIT.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/Crypto2_GIT.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/Crypto2_GIT.dir/flags.make

CMakeFiles/Crypto2_GIT.dir/FEAL.cpp.o: CMakeFiles/Crypto2_GIT.dir/flags.make
CMakeFiles/Crypto2_GIT.dir/FEAL.cpp.o: ../FEAL.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/cygdrive/d/Crypto/Crypto2_GIT/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/Crypto2_GIT.dir/FEAL.cpp.o"
	/usr/bin/c++.exe  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/Crypto2_GIT.dir/FEAL.cpp.o -c /cygdrive/d/Crypto/Crypto2_GIT/FEAL.cpp

CMakeFiles/Crypto2_GIT.dir/FEAL.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/Crypto2_GIT.dir/FEAL.cpp.i"
	/usr/bin/c++.exe $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /cygdrive/d/Crypto/Crypto2_GIT/FEAL.cpp > CMakeFiles/Crypto2_GIT.dir/FEAL.cpp.i

CMakeFiles/Crypto2_GIT.dir/FEAL.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/Crypto2_GIT.dir/FEAL.cpp.s"
	/usr/bin/c++.exe $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /cygdrive/d/Crypto/Crypto2_GIT/FEAL.cpp -o CMakeFiles/Crypto2_GIT.dir/FEAL.cpp.s

CMakeFiles/Crypto2_GIT.dir/FEAL.cpp.o.requires:

.PHONY : CMakeFiles/Crypto2_GIT.dir/FEAL.cpp.o.requires

CMakeFiles/Crypto2_GIT.dir/FEAL.cpp.o.provides: CMakeFiles/Crypto2_GIT.dir/FEAL.cpp.o.requires
	$(MAKE) -f CMakeFiles/Crypto2_GIT.dir/build.make CMakeFiles/Crypto2_GIT.dir/FEAL.cpp.o.provides.build
.PHONY : CMakeFiles/Crypto2_GIT.dir/FEAL.cpp.o.provides

CMakeFiles/Crypto2_GIT.dir/FEAL.cpp.o.provides.build: CMakeFiles/Crypto2_GIT.dir/FEAL.cpp.o


CMakeFiles/Crypto2_GIT.dir/main.cpp.o: CMakeFiles/Crypto2_GIT.dir/flags.make
CMakeFiles/Crypto2_GIT.dir/main.cpp.o: ../main.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/cygdrive/d/Crypto/Crypto2_GIT/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object CMakeFiles/Crypto2_GIT.dir/main.cpp.o"
	/usr/bin/c++.exe  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/Crypto2_GIT.dir/main.cpp.o -c /cygdrive/d/Crypto/Crypto2_GIT/main.cpp

CMakeFiles/Crypto2_GIT.dir/main.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/Crypto2_GIT.dir/main.cpp.i"
	/usr/bin/c++.exe $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /cygdrive/d/Crypto/Crypto2_GIT/main.cpp > CMakeFiles/Crypto2_GIT.dir/main.cpp.i

CMakeFiles/Crypto2_GIT.dir/main.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/Crypto2_GIT.dir/main.cpp.s"
	/usr/bin/c++.exe $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /cygdrive/d/Crypto/Crypto2_GIT/main.cpp -o CMakeFiles/Crypto2_GIT.dir/main.cpp.s

CMakeFiles/Crypto2_GIT.dir/main.cpp.o.requires:

.PHONY : CMakeFiles/Crypto2_GIT.dir/main.cpp.o.requires

CMakeFiles/Crypto2_GIT.dir/main.cpp.o.provides: CMakeFiles/Crypto2_GIT.dir/main.cpp.o.requires
	$(MAKE) -f CMakeFiles/Crypto2_GIT.dir/build.make CMakeFiles/Crypto2_GIT.dir/main.cpp.o.provides.build
.PHONY : CMakeFiles/Crypto2_GIT.dir/main.cpp.o.provides

CMakeFiles/Crypto2_GIT.dir/main.cpp.o.provides.build: CMakeFiles/Crypto2_GIT.dir/main.cpp.o


# Object files for target Crypto2_GIT
Crypto2_GIT_OBJECTS = \
"CMakeFiles/Crypto2_GIT.dir/FEAL.cpp.o" \
"CMakeFiles/Crypto2_GIT.dir/main.cpp.o"

# External object files for target Crypto2_GIT
Crypto2_GIT_EXTERNAL_OBJECTS =

Crypto2_GIT.exe: CMakeFiles/Crypto2_GIT.dir/FEAL.cpp.o
Crypto2_GIT.exe: CMakeFiles/Crypto2_GIT.dir/main.cpp.o
Crypto2_GIT.exe: CMakeFiles/Crypto2_GIT.dir/build.make
Crypto2_GIT.exe: CMakeFiles/Crypto2_GIT.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/cygdrive/d/Crypto/Crypto2_GIT/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Linking CXX executable Crypto2_GIT.exe"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/Crypto2_GIT.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/Crypto2_GIT.dir/build: Crypto2_GIT.exe

.PHONY : CMakeFiles/Crypto2_GIT.dir/build

CMakeFiles/Crypto2_GIT.dir/requires: CMakeFiles/Crypto2_GIT.dir/FEAL.cpp.o.requires
CMakeFiles/Crypto2_GIT.dir/requires: CMakeFiles/Crypto2_GIT.dir/main.cpp.o.requires

.PHONY : CMakeFiles/Crypto2_GIT.dir/requires

CMakeFiles/Crypto2_GIT.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/Crypto2_GIT.dir/cmake_clean.cmake
.PHONY : CMakeFiles/Crypto2_GIT.dir/clean

CMakeFiles/Crypto2_GIT.dir/depend:
	cd /cygdrive/d/Crypto/Crypto2_GIT/cmake-build-debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /cygdrive/d/Crypto/Crypto2_GIT /cygdrive/d/Crypto/Crypto2_GIT /cygdrive/d/Crypto/Crypto2_GIT/cmake-build-debug /cygdrive/d/Crypto/Crypto2_GIT/cmake-build-debug /cygdrive/d/Crypto/Crypto2_GIT/cmake-build-debug/CMakeFiles/Crypto2_GIT.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/Crypto2_GIT.dir/depend

