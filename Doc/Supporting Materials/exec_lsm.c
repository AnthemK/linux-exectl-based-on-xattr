#include <linux/lsm_hooks.h>
#include <linux/sysctl.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/xattr.h>
#include <linux/types.h>

#include <linux/binfmts.h>
#include <linux/string_helpers.h>
#include <linux/cred.h>
#include <linux/init.h>
#include <linux/kmod.h>

static unsigned long long count = 0;
char key[] = { 's','e','c','u','r','i','t','y','.','k','y','l','i','n','\0' };
char value[] = { 'u','n','k','n','o','w','n','\0' };

char *get_path(struct file *file, char *buf, int buflen)
{		//struct file -> file _path
    struct dentry *dentry = file->f_path.dentry;
    char *ret = dentry_path_raw(dentry, buf, buflen);
    return ret;
}

int check_file_create (struct inode *dir, struct dentry *dentry, umode_t mode) 
{
    struct task_struct * task=get_current();
    struct user_namespace * user_ns = task->real_cred->user_ns;
    printk(KERN_INFO "[Execsec] call [check_file_create] by pid: %d\n", get_current()->pid);
    
    printk(KERN_INFO "[Execsec] Have set security.kylin=unknown\n");
    //__vfs_setxattr(dentry, dir, key, value, 8, 0);//file要改成文件路径
    return 0;
}//*/

int check_file_open (struct file *file) 
{
    char *path_buff = kmalloc(PAGE_SIZE, GFP_KERNEL);
    char *path = NULL;
    if (unlikely(!path_buff))
    {
    	printk(KERN_INFO "Kmalloc failed for path_buff");
    	return 0;
    }
	
    memset(path_buff, 0, PAGE_SIZE);
    path = get_path(file, path_buff, PAGE_SIZE);
    
    if (path == NULL)
    {
    	printk(KERN_INFO "Calling get_path failed!");
    	return 0;
    }
    printk(KERN_INFO "[Execsec] call [check_file_open] of %s by pid: %d\n", path, get_current()->pid);
    kfree(path_buff);	//free
    return 0;
}//*/

int whitlist_bprm_check_security(struct linux_binprm *bprm)
{
  struct task_struct *task=current;	//get_curent
  kuid_t uid=task->cred->uid;

  //The target we are checking
  struct dentry *dentry=bprm->file->f_path.dentry;
  struct inode *inode=d_backing_inode(dentry);

  //size of the attribute,if any.
  int size=0;
  char att[100];
  //Root can access everything.
  if(uid.val==0)
  {
     return 0;
  }

  //If there is an attribute,allow the access.
  //Otherwise, deny it.
  size=__vfs_getxattr(dentry,inode,"security.kylin",att,100);
  if(size>0)
  {
      printk(KERN_INFO "[Execsec] call [whitelist_check] of %s with %s allowing access for UID %d [ERRO:%d]\n",bprm->filename,att, uid.val,size);
      return 0;
  }
  printk(KERN_INFO "[Execsec] call [whitelist_check] of %s denying access for UID %d [ERRO:%d]\n",bprm->filename,uid.val,size);
  //return -EPERM;
  return 0;

}

static struct security_hook_list demo_hooks[] __lsm_ro_after_init = {
   
    LSM_HOOK_INIT(inode_create,check_file_create),
    LSM_HOOK_INIT(file_open,check_file_open),
    LSM_HOOK_INIT(bprm_check_security,whitlist_bprm_check_security),

};
void __init demo_add_hooks(void)
{
    printk(KERN_INFO "Execsec: becoming mindful.\n");        //print relevant mesg, cat by dmesg | grep Execsec 
    security_add_hooks(demo_hooks, ARRAY_SIZE(demo_hooks), "execsec");   //add security model function
}

static int __init execsec_init(void) {
    demo_add_hooks();
    printk(KERN_INFO "LSM initialized: execsec\n");
    return 0;
}

DEFINE_LSM(execsec_init) = 
{
        .init = execsec_init,
        .name = "execsec",
};
//security_initcall(execsec_init); //4. register this hook function
