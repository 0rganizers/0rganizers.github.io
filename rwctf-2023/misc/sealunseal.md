# sealunseal

> So we get some intelSGX sealed data, we have a .so for unseal, do we just need to run that or is it more complicated? -- zeski on discord

Given an executable `app`, some `sealed_data_blob.txt`, and `libenclave_unseal.signed.so` we want to unseal the sealed data. For that, we need to install intel sgx first - and thus, a day was lost.

Once we finally had a machine that actually has an intel cpu, with sgx enabled, the services running, and not in simulated mode (that caused some errors about mismatching the state the original sealer was in), we could run the `app`, and noticed that it does in fact not unseal the data. Instead, it writes new sealed data. With a hardcoded flag placeholder instead of the actual flag.

The challenge description pointed out that this was an example of sealing in one enclave and unsealing in another. We get the enclave for unsealing as an `.so` file and may not change its code.

The binary `app` seems to still contain the `unseal` function, but simply patching the call to be to `unseal` instead of `seal` did not work - because the two functions take different arguments. We also did not get far by diffing the file generated on my machine with the original sealed data.

One of us contemplated that using a debugger inside the enclave would be painful. Another one pointed out that this would require a debug flag set, which would then prevent us from deriving the proper keys unless it was already sealed in debug mode. 
And then we noticed that it actually looks like the debug flag was used.

So we wrote our own app and an `enclave.edl` file to describe the enclave.

```c
// enclave.edl
enclave {
  include "sgx_tseal.h"
  trusted {
    public int unseal_data([in, size=size] sgx_sealed_data_t* data, size_t size);
  };
};
```

```c
// app.c
#include <sgx_uae_service.h>
#include "enclave_u.h"
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

void fail(char* msg) {
  puts(msg);
  exit(1);
}

int main(int argc, char* argv[]) {
  char data[1024];
  int fd = open(argv[1], O_RDONLY);
  if (fd < 0) fail("failed to open file");
  int sz = read(fd, data, 1024);
  if (sz <= 0) fail("failed to read data");
  sgx_enclave_id_t enclave_id;
  sgx_status_t result;
  result = sgx_create_enclave("libenclave_unseal.signed.so", 1, NULL, NULL, &enclave_id, NULL);
  printf("%x\n", result);
  if (result != SGX_SUCCESS) fail("enclave creation failed");
  int ret;
  result = unseal_data(enclave_id, &ret, (sgx_sealed_data_t*) data, 1024);
  if (result != SGX_SUCCESS) fail("enclave run failed");
}
```

```bash
# compilation
$SGX_SDK/bin/x64/sgx_edger8r enclave.edl --search-path $SGX_SDK/include
gcc -o app.o -c app.c -I$SGX_SDK/include
gcc -c enclave_u.c -o enclave_u.o -I$SGX_SDK/include
gcc app.o enclave_u.o -o app -L$SGX_SDK/lib64 -lsgx_urts -lsgx_epid
```

At some point the challenge author made a server available with a working sgx environment and the correct CPU to actually be able to unseal the data. However, it was slow and `apt-get install gdb` sometimes failed. Which was particularly problematic since the timeout was set too low to do any exploring remotely. So we debugged locally first, manually stepping until we were at the right place in the enclave. And then started the debugger on the remote, ran until there again, and dumped the flag.