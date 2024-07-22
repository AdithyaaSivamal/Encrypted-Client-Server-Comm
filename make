# Define the compiler and compiler flags
CXX = g++
CXXFLAGS = -shared -fPIC

# Define the directories
RSA_DIR = Encryption_Algs/RSA
AES_DIR = Encryption_Algs/AES

# Define the source files
RSA_SRC = $(RSA_DIR)/rsa.cpp $(RSA_DIR)/helperFunctions.cpp
AES_SRC = $(AES_DIR)/src/aes.cpp $(AES_DIR)/src/transformations.cpp $(AES_DIR)/key_expansion/key_expansion.cpp

# Define the output files
RSA_DLL = $(RSA_DIR)/rsa.dll
AES_DLL = $(AES_DIR)/aes.dll

# Define the libraries
LIBS = -lgmp -lgmpxx

# Default target
all: $(RSA_DLL) $(AES_DLL)

# Rule to build the RSA DLL
$(RSA_DLL): $(RSA_SRC)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

# Rule to build the AES DLL
$(AES_DLL): $(AES_SRC)
	$(CXX) $(CXXFLAGS) -o $@ $^

# Clean target to remove generated files
clean:
	del $(RSA_DLL) $(AES_DLL)
