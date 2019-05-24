#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <ctype.h>

#include <iptables.h>
#include <linux/netfilter_ipv4/ipt_pktsize.h>

static void help(void)
{
    printf(
    "pktsize v%s options:\n"
    " --size size[:size]        Match packet size against value or range\n"
    "\nExamples:\n"
    " iptables -A FORWARD -m pktsize --size 65 -j DROP\n"
    " iptables -A FORWARD -m pktsize --size 80:120 -j DROP\n"
    , PKTSIZE_VERSION);
}

static struct option opts[] = {
        { "size", 1, NULL, '1' },
        {0}
};

/* 输入参数的可能格式为如下:
	xx         指定数据包大小 XX
	:XX       范围是0~XX    
	YY:       范围是YY~65535
	xx:YY    范围是XX~YY
*/
static void parse_pkts(const char* s,struct ipt_pktsize_info *info){
        char* buff,*cp;
		
        buff = strdup(s);

        if(NULL == (cp=strchr(buff,':'))){
                info->min_pktsize = info->max_pktsize = strtol(buff,NULL,0);
        }else{
                *cp = '\0';
                cp++;

                info->min_pktsize = strtol(buff,NULL,0);
                info->max_pktsize = (cp[0]? strtol(cp,NULL,0):0xFFFF);
        }

        free(buff);

        if (info->min_pktsize > info->max_pktsize)
                exit_error(PARAMETER_PROBLEM,
                           "pktsize min. range value `%u' greater than max. "
                           "range value `%u'", info->min_pktsize, info->max_pktsize);
}


static int
parse(int c, char **argv, int invert, unsigned int *flags,
        const void *entry,
        struct ipt_entry_match **match)
{
        struct ipt_pktsize_info *info = (struct ipt_pktsize_info *)(*match)->data;
        switch(c){
                case '1':
                        if (*flags)
                                exit_error(PARAMETER_PROBLEM,
                                           "size: `--size' may only be "
                                           "specified once");
                        parse_pkts(argv[optind-1], info);
                        *flags = 1;
                        break;
                default:
                        return 0;
        }
        return 1;
}

static void final_check(unsigned int flags)
{
    if (!flags)
            exit_error(PARAMETER_PROBLEM,
            "\npktsize-parameter problem: for pktsize usage type: iptables -m pktsize --help\n");
}


static void __print(struct ipt_pktsize_info * info){
        if (info->max_pktsize == info->min_pktsize)
                printf("%u ", info->min_pktsize);
        else
                printf("%u:%u ", info->min_pktsize, info->max_pktsize);
}

static void print(const void *ip, const struct ipt_entry_match *match, int numeric)
{
        printf("size ");
        __print((struct ipt_pktsize_info *)match->data);

}

static void save(const void *ip, const struct ipt_entry_match *match)
{
        printf("--size ");
        __print((struct ipt_pktsize_info *)match->data);
}


static
struct iptables_match pktsize=
{
    .next           = NULL,
    .name           = "pktsize",
    .version        = IPTABLES_VERSION,
    .size           = IPT_ALIGN(sizeof(struct ipt_pktsize_info)),
    .userspacesize  = IPT_ALIGN(sizeof(struct ipt_pktsize_info)),
    .help           = &help,
    .parse          = &parse,
    .final_check    = &final_check,
    .print          = &print,
    .save           = &save,
    .extra_opts     = opts
};


void _init(void)
{
    register_match(&pktsize);
}

