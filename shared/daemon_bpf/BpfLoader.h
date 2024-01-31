#include <iostream>
#include <ctime>
#include <iomanip>
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <fstream>
#include <bpf_injection_header.h>

class BpfLoader
{
    private:
        bpf_object *obj;
        bpf_program *prog;
        bpf_link *links = nullptr;

    public:
        BpfLoader(bpf_injection_msg_t message, uint32_t prog_len);
        /* Loads the BPF Program inside the kernel and returns the BPF Map FD*/
        int loadAndGetMap();
        ~BpfLoader();
};