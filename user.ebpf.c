#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <stdio.h>
#include <net/if.h>
#include <unistd.h>

#define NET_INTERFACE "your_net_interface_name"

int main() {
    
    int err  = 0;
    
    // opening
    struct bpf_object *obj = bpf_object__open_file("delay.ebpf.o", NULL);

    if (!obj) {
        printf("Couldn't load the ebpf kernel object\n");
        return 1;
    }

    // finding the program
    struct bpf_program *bpf_prog_igr = bpf_object__find_program_by_name(obj, "ingress_traffic");

    if (!bpf_prog_igr) {
        printf("Failed to find ingress program");
        return 1;
    }

    // finding the program
    struct bpf_program *bpf_prog_egr = bpf_object__find_program_by_name(obj, "egress_traffic");

    if (!bpf_prog_egr) {
        printf("Failed to find egress program");
        return 1;
    }

    // loading
    err = bpf_object__load(obj);

    if (err) {
        printf("Failed to load ebpf program\n");
        return err;
    }

    // INGRESS TRAFFIC 
    int igr_prog_fd = bpf_program__fd(bpf_prog_igr);
    if (!igr_prog_fd)
        printf("cannot find the program\n");

    struct bpf_tc_hook igr_hook = {0};

    igr_hook.sz = sizeof(struct bpf_tc_hook),
    igr_hook.ifindex = if_nametoindex(NET_INTERFACE),
    igr_hook.attach_point = BPF_TC_INGRESS,
    

    bpf_tc_hook_create(&igr_hook);

    struct bpf_tc_opts igr_opts = {0};

    igr_opts.sz = sizeof(struct bpf_tc_opts),
    igr_opts.prog_fd = igr_prog_fd,
    igr_opts.prog_id = 0,
    igr_opts.flags = BPF_TC_F_REPLACE,
    igr_opts.priority = 1,
        
    //    .handle = 1,
    
    //bpf_tc_detach(&igr_hook, &igr_opts);
    bpf_tc_attach(&igr_hook, &igr_opts);

    // EGRESS TRAFFIC
    int egr_prog_fd = bpf_program__fd(bpf_prog_egr);
    if (!egr_prog_fd)
        printf("cannot find the program\n");

    printf("id = %d\n", egr_prog_fd);

    struct bpf_tc_hook egr_hook = {0};

    egr_hook.sz = sizeof(struct bpf_tc_hook),
    egr_hook.ifindex = if_nametoindex(NET_INTERFACE),
    egr_hook.attach_point = BPF_TC_EGRESS,
    

    bpf_tc_hook_create(&egr_hook);

    struct bpf_tc_opts egr_opts = {0};

    egr_opts.sz = sizeof(struct bpf_tc_opts),
    egr_opts.prog_fd = egr_prog_fd,
    egr_opts.prog_id = 0,
    egr_opts.flags = BPF_TC_F_REPLACE,
    egr_opts.priority = 1,
        
    //    .handle = 1,
    
    //bpf_tc_detach(&igr_hook, &igr_opts);
    bpf_tc_attach(&egr_hook, &egr_opts);

    
    int c = 0;
    printf("Enter anything and press enter to quit: ");
    scanf("%d", &c);
    if (c)
        goto terminate;
    

terminate:
    bpf_tc_detach(&igr_hook, &igr_opts);
    bpf_tc_hook_destroy(&igr_hook);
    bpf_tc_detach(&egr_hook, &egr_opts);
    bpf_tc_hook_destroy(&egr_hook);

    return 0;
}