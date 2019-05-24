#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/version.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter_ipv4/ipt_pktsize.h>

MODULE_AUTHOR("Koorey Wung <wjlkoorey@gmail.com>");
MODULE_DESCRIPTION("iptables pkt size range match module.");
MODULE_LICENSE("GPL");


static int
match(const struct sk_buff *skb,
      const struct net_device *in,
      const struct net_device *out,
      const struct xt_match *match,
      const void *matchinfo,
      int offset,
      unsigned int protoff,
      int *hotdrop)
{
        const struct ipt_pktsize_info *info = matchinfo;
        const struct iphdr *iph = skb->nh.iph;

        int pkttruesize = ntohs(iph->tot_len)-(iph->ihl*4);

        if(pkttruesize>=info->min_pktsize && pkttruesize <=info->max_pktsize){
                return 1;
        }
        else{
                return 0;
        }
    return 1;
}


static struct ipt_match pktsize_match = {
        .name           = "test",
        .family          =AF_INET,
        .match          = match,
        .matchsize    = sizeof(struct ipt_pktsize_info),
        .destroy        = NULL,
        .me              = THIS_MODULE,
};


static int __init init(void)
{
    printk(KERN_INFO "pktsize module loading\n");
    return xt_register_match(&pktsize_match);
}

static void __exit fini(void)
{
    xt_unregister_match(&pktsize_match);
    printk(KERN_INFO "pktsize module unloaded\n");
}

module_init(init);
module_exit(fini);

