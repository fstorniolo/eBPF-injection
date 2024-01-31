/*
 * BPF guest daemon
 * 2022 Luigi Leonardi
 * Based on the previous work by Giacomo Pellicci
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

//#define _GNU_SOURCE
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
//#include <sched.h>

#include <sys/mman.h>
//#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>


#include <iostream>
#include <bitset>
#include <cerrno>
#include <csignal>
#include <ctime>

#include <thread>
#include <chrono>

#include <openssl/conf.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/x509_vfy.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/dh.h>
#include <openssl/crypto.h>

using namespace std;

#include <bpf_injection_msg.h>
#include "BpfLoader.h"
#include "ServiceList.h"

#define DEBUG

#ifdef DEBUG
    #define DBG(x) x
#else
    #define DBG(x)
#endif

// To return informations to the device and then to the host, just write to device
// in order to trigger some action on the host side

struct return_elem_iter {
    uint64_t physical_address;
    uint64_t order;
};

int count_handler_ringbuf = 0;


bpf_injection_msg_t recv_bpf_injection_msg(int fd){
	bpf_injection_msg_t mymsg;
	int32_t len, payload_left;
	mymsg.header.type = ERROR;

	cout<<"Waiting for a bpf_message_header.."<<endl;
	len = read(fd, &(mymsg.header), sizeof(bpf_injection_msg_header));
	if (len < (int32_t)sizeof(bpf_injection_msg_header)) {
	    perror("read: ");
	    return mymsg;
	}

	print_bpf_injection_message(mymsg.header);

	cout<<"Allocating buffer for payload of "<<mymsg.header.payload_len<<" bytes.."<<endl;
	mymsg.payload = new uint8_t[mymsg.header.payload_len];
	cout<<"Buffer allocated"<<endl;

	cout<<"Reading chunk by chunk.."<<endl;
	payload_left = mymsg.header.payload_len;
    uint8_t *addr = static_cast<uint8_t*>(mymsg.payload);

	while(payload_left > 0){

		len = read(fd, addr, payload_left);
		if (len < 0) {
			perror("read: ");
			return mymsg;
		}
		addr += len;
		payload_left -= len;
	}

	cout<<"Received payload of "<<mymsg.header.payload_len<<" bytes."<<endl;
	return mymsg;
}

int handler_ringbuf(void *ctx, void *data, size_t){
    /* Each time a new element is available in the ringbuffer this function is called */
    // cout << "handler_ringbuf called" << endl;
    bpf_event_t *event = static_cast<bpf_event_t*>(data);
    uint32_t data_len = sizeof(bpf_injection_msg_header) + event->size;
    count_handler_ringbuf++;

    bpf_injection_msg_header *hdr = (bpf_injection_msg_header*)malloc(data_len);
    hdr->payload_len = event->size;
    hdr->service = event->type;
    hdr->type = PROGRAM_INJECTION_RESULT;
    hdr->version = 1;

    memcpy((char*)hdr+sizeof(*hdr),&event->payload,hdr->payload_len);

    int dev_fd = reinterpret_cast<long>(ctx);

    if(write(dev_fd,hdr,data_len) == -1){ //Type and Payload
        cout<<"Can't write to the device\n";
        free(hdr);
        return -1;
    }

    free(hdr);
    return 0;

}

void sendAck(int dev_fd,uint8_t service, bool success){

    //header + payload (1 byte)
    uint16_t buf_length = sizeof(bpf_injection_msg_header) + sizeof(bpf_injection_ack);
    uint8_t *buffer = (uint8_t*) malloc(buf_length);

    bpf_injection_msg_header *message = reinterpret_cast<bpf_injection_msg_header*>(buffer);
    message->type = PROGRAM_INJECTION_ACK;
    message->version = DEFAULT_VERSION;
    message->payload_len = sizeof(bpf_injection_ack);
    message->service = service;

    bpf_injection_ack *payload = reinterpret_cast<bpf_injection_ack *>(buffer+sizeof(bpf_injection_msg_header));
    payload->status = (success) ? INJECTION_OK : INJECTION_FAIL;

    int8_t res = write(dev_fd,buffer,buf_length);
    if(res <= 0){
        cout<<"Error while sending ACK"<<endl;
    }

    printf("Ack sent!\n");
    free(buffer);

}

int handleProgramInjection(int dev_fd, bpf_injection_msg_t message, uint32_t prog_len){

    BpfLoader loader(message, prog_len);
    int map_fd = loader.loadAndGetMap();
    if(map_fd < 0){
        cout<<"Map Not Found"<<endl;
        return -1;
    }

    // get localtime in a human readable way
    auto t = std::time(nullptr);
    auto tm = *std::localtime(&t);
    std::stringstream ss;
    ss << std::put_time(&tm, "%d-%B-%Y-%H:%M:%S");

    std::string file_name("/home/luigi/injected_bpf_progs/");
    file_name += ss.str();

    std::cout << "file_name: " << file_name << std::endl;

    // store bpf program
    std::ofstream of(file_name, std::ios::binary | std::ios::out);
    of.write((const char*)message.payload, prog_len);
    of.close();

    // free memory
    delete[] (uint8_t*)message.payload;

    ring_buffer *buffer_bpf = ring_buffer__new(map_fd,handler_ringbuf,(void*)(long)dev_fd,NULL);
    cout<<"[LOG] Starting operations"<<endl;

    sendAck(dev_fd,message.header.service,true);

    std::cout << "pid: " << getpid() << std::endl;

    while(true){
        ring_buffer__poll(buffer_bpf,50);   //50 ms sleep
        // cout << "handler_ringbuff calls: " << count_handler_ringbuf << endl;
        continue;
    }
}

/*This function will kill the service, if found */
void kill_service(ServiceList &list, const bpf_injection_msg_t &message){

    Service s = list.findService(message.header.service);

    if(s.service_id != (uint8_t)-1){
        cout<<"Unloading Service n: "<<(int)s.service_id<<"\n";
        kill(s.pid,SIGKILL);
        list.removeService(s);
    }

}

static bool verify_signed_program(const bpf_injection_msg_t &message, unsigned int &signature_len)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	EVP_PKEY *pubkey;

    if (!ctx){
        perror("ERRORE new");
        return false;
    }

    FILE* pubkey_file = fopen("/home/luigi/.allowed_pubkeys/server_pubkey.pem", "r");

    if(!pubkey_file){ std::cerr << "Error: cannot open file '" << "server_pubkey.pem" << "' (missing?)\n"; return false; }
    pubkey = PEM_read_PUBKEY(pubkey_file, NULL, NULL, NULL);
    fclose(pubkey_file);
    if (!pubkey){ std::cerr << "Error: PEM_read_PUBKEY returned NULL\n"; return false; }


    if(!EVP_VerifyInit(ctx, EVP_sha256())){
        perror("Error In RSA_Init_ex");
        return false;
    }

    signature_len = EVP_PKEY_size(pubkey);
    unsigned int prog_len = message.header.payload_len - signature_len;
    std::cout << "signature_len: " << signature_len << std::endl;

    if (!EVP_VerifyUpdate(ctx, (const void*)message.payload, prog_len)){
        perror("Error in RSA_VerifyUpdate");
        return false;
    }

    if (!EVP_VerifyFinal(ctx, (const unsigned char*)message.payload + prog_len, signature_len, pubkey)) {
        perror("Error in RSA_VerifyFinal");
        return false;
    }

    return true;
}


int main(){

    cout<<"[LOG] Starting Guest Agent"<<endl;

    int fd = open("/dev/virtio-ports/org.fedoraproject.port.0",O_RDWR);
    if(fd < 0){
        cout<<"Error while opening device"<<endl;
        return -1;
    }

    ServiceList list;

    while(true){

        bpf_injection_msg_t message = recv_bpf_injection_msg(fd);

        if(message.header.type == SIGNED_PROGRAM_INJECTION){

            uint32_t signature_len;
            uint32_t prog_len = message.header.payload_len;

            if (verify_signed_program(message, signature_len))
                prog_len -= signature_len;
            else {
                // do not load bpf program!
                std::cout << "Verify fallita, firma non valida" << std::endl;
                continue;
            }

            kill_service(list, message); //Kill running service, if any
            pid_t pid = fork();

            if(pid == 0){ //child
                if(handleProgramInjection(fd,message, prog_len) < 0){
                    cerr<<"Generic Error"<<endl;
                    sendAck(fd,message.header.service,false); //nack to the service
                    return -1;
                }

            } else { //parent

                Service s(message.header.service,pid);
                list.addService(s);

                continue;
            }

        } else if(message.header.type == PROGRAM_INJECTION_UNLOAD){
            kill_service(list, message);
        } else {
            cout<<"Unrecognized Payload Type: 0x"<<hex<<message.header.type<<"\n";
        }

    }


    //cleanup
    close(fd);

	return 0;

}
