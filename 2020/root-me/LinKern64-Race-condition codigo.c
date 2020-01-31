#include <linux/module.h>
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/kdev_t.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <asm/uaccess.h>
#include <linux/slab.h> 


static dev_t first; // Global variable for the first device number
static struct cdev c_dev; // Global variable for the character device structure
static struct class *cl; // Global variable for the device class

struct tostring_s {
  unsigned int pointer;
  unsigned int pointer_max;
  unsigned long long int *tostring_stack;
  ssize_t (*tostring_read)(struct file *f, char __user *buf, size_t len, loff_t *off); 
};

static struct tostring_s *tostring;


static unsigned int taille=2;

module_param(taille, int,1);
MODULE_PARM_DESC(taille, "Stack size in Ko");

static ssize_t tostring_read_hexa(struct file *f, char __user *buf, size_t len, loff_t *off)
{
  printk(KERN_INFO "Tostring: read_hexa()\n");
  if (tostring->pointer > 0)
    return(snprintf(buf,len,"%16llx\n",tostring->tostring_stack[--(tostring->pointer)]));
  else return(0);
}

static int tostring_create(int tl) {
  /*  tostring=kmalloc(sizeof(struct tostring_s), GFP_DMA); */
  taille=tl;
  tostring->tostring_stack=kmalloc(taille*1024, GFP_DMA);
  if (tostring->tostring_stack == NULL) return(-1);
  tostring->pointer_max=(taille*1024)/sizeof(long long int);
  tostring->tostring_read= tostring_read_hexa;
  printk(KERN_INFO "Tostring: Stack size: %dK, locate at %p, max index: %d\n",taille,tostring->tostring_stack,tostring->pointer_max);
  return(0);

}

 
static int tostring_open(struct inode *i, struct file *f){
  printk(KERN_INFO "Tostring: open()\n");
  printk("Tostring: Stack creation with size %dK\n",64);
  if (tostring->tostring_stack==NULL) tostring_create(64);
  if (tostring->tostring_stack==NULL) printk("Tostring: Error in stack creation\n");
  return 0;
}
 
static int tostring_close(struct inode *i, struct file *f)
{
  printk(KERN_INFO "Tostring: close()\n");
  printk("Tostring: Deleting stack\n");
  kfree(tostring->tostring_stack);
  tostring->tostring_stack=NULL;
  tostring->tostring_read=NULL;
  tostring->pointer=0;
  tostring->pointer_max=0;
  return 0;
}
 
static ssize_t tostring_read(struct file *f, char __user *buf, size_t len, loff_t *off)
{
  printk(KERN_INFO "Tostring: read()\n");
  return((tostring->tostring_read)(f, buf, len, off)); 
}


static ssize_t tostring_read_dec(struct file *f, char __user *buf, size_t len, loff_t *off)
{
  printk(KERN_INFO "Tostring: read_dec()\n");
  if (tostring->pointer > 0)
    return(snprintf(buf,len,"%lld\n",tostring->tostring_stack[--(tostring->pointer)]));
  else return(0);
}


 
static ssize_t tostring_write(struct file *f, const char __user *buf,size_t len, loff_t *off)
{
 
  char *bufk;
  int i,j;

  printk(KERN_INFO "Tostring: write()\n");
  // rajout du 0 final
  bufk = kmalloc(len + 1, GFP_DMA);

 
  if (bufk){
 
    if (copy_from_user(bufk, buf, len))
        return -EFAULT;
 
    bufk[len] = '\0';

    i=0;
    while(i <len) {
    /* Les commandes commencent par 10 '*' */
      for (j=0;(j<10) && (bufk[j]=='*');j++);
      if (j == 10) {
	for (j=i+10;(bufk[j]!='\0') && (bufk[j] != '\n');j++);
	bufk[j]='\0';
	printk("Tostring: Cmd %s\n",bufk+i+10);
	switch(bufk[i+10]) {
	case 'H': 
	  tostring->tostring_read= tostring_read_hexa;
	  break;
	case 'D':
	  tostring->tostring_read= tostring_read_dec;
	  break;
	}
	i=j+1;
      }
      else {
	printk("tostring: insertion %lld\n",*((long long int *) (bufk+i)));
	if (tostring->pointer >= tostring->pointer_max) 
	  printk(KERN_INFO "Tostring: full stack\n");
	else
	  tostring->tostring_stack[(tostring->pointer)++]= *((long long int *) (bufk+i));
	i = i+sizeof(long long int);
      }
    }
  kfree(bufk);
  }
  return len;
 
}



 
static struct file_operations pugs_fops =
{
  .owner = THIS_MODULE,
  .open = tostring_open,
  .release = tostring_close,
  .read = tostring_read,
  .write = tostring_write,
};
 
static int __init tostring_init(void) /* Constructor */
{
  printk(KERN_INFO "Tostring registered");
  tostring=kmalloc(sizeof(struct tostring_s), GFP_DMA);
  if (alloc_chrdev_region(&first, 0, 8, "tostring") < 0)
  {
    return -1;
  }
  if ((cl = class_create(THIS_MODULE, "chardrv")) == NULL)
  {
    unregister_chrdev_region(first, 1);
    return -1;
  }
  if (device_create(cl, NULL, first, NULL, "tostring") == NULL)
  {
    printk(KERN_INFO "Tostring error");
    class_destroy(cl);
    unregister_chrdev_region(first, 1);
    return -1;
  }
  cdev_init(&c_dev, &pugs_fops);
  if (cdev_add(&c_dev, first, 1) == -1)
  {
    device_destroy(cl, first);
    class_destroy(cl);
    unregister_chrdev_region(first, 1);
    return -1;
  }
 
  printk(KERN_INFO "<Major, Minor>: <%d, %d>\n", MAJOR(first), MINOR(first));
  return 0;
}
 
static void __exit tostring_exit(void) /* Destructor */
{
    printk(KERN_INFO "Tostring unregistered");
    kfree(tostring->tostring_stack);
    unregister_chrdev_region(first, 1);
}
 
module_init(tostring_init);
module_exit(tostring_exit);
 
MODULE_LICENSE("GPL");
MODULE_AUTHOR("F.Boisson");
MODULE_DESCRIPTION("Module Tostring Integers Dec/Hex");
