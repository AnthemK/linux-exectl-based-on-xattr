#include<stdio.h>
#include<attr/xattr.h>
#include<sys/types.h>
#include<string.h>
#define maxlen 1024   
//Maximum length
const char* aimattr = "security.kylin";  //Main xattr
const char* aimvalue[2] = {"verified","unknown"};  //Two Type
const int aimattrlen = 10;
char list[maxlen],tmpxattr[maxlen];   //list of xattrs
char value[maxlen];  //
int worktype,err;
size_t size1,size2; 

int addkylinxattr(char* FilePath){
	err=setxattr(FilePath,aimattr,(void *)aimvalue[1],aimattrlen,0);
	if(err != 0) return -1;
	printf("Add new xattr %s as %s success\n",aimattr,aimvalue[1]);
	return 0;
}

int Queryxattr(char* FilePath){
	size1=listxattr(FilePath,list,maxlen);
	if(size1 == (size_t) (-1)) return -1;
	printf("xattrsize:%ld\n",size1);
	int cnt=1;
	char *nowp=&list[0];
	for(;nowp-&list[0]<size1;){
		printf("In %d-th xattr:%s",cnt,nowp);
		size2=getxattr(FilePath,nowp,value,maxlen);
		if(size2 == (size_t) (-1)) return -1;
		printf("-->%s\n",value);
		memset(value,0,sizeof(value));
		while(*nowp!='\0') nowp++;
		nowp++;
		cnt++;
	}
	return 0;
}

int Modifyxattr(char* FilePath){
	size2=getxattr(FilePath,aimattr,value,maxlen);
	if(size2 == (size_t) (-1)) return -1;
	err=setxattr(FilePath,aimattr,(void *)aimvalue[strcmp(value,aimvalue[1])],aimattrlen,0);
	if(err != 0) return -1;

	printf("Modify xattr %s as %s success\n",aimattr,aimvalue[strcmp(value,aimvalue[1])]);
	return 0;
}
int main(int argc,char *argv[])
{
	//puts("can you reach here?");
	while(worktype>3||worktype<=0) {
		printf("Please input work type:");
		scanf("%d",&worktype);
	}	
	switch(worktype){
		case 1:
			err=addkylinxattr(argv[1]);
			if(err!=0) printf("%m\n", errno);
			break;
		case 2:
			err=Queryxattr(argv[1]);
			if(err!=0) printf("%m\n", errno);
			break;
		case 3:
			err=Modifyxattr(argv[1]);
			if(err!=0) printf("%m\n", errno);
			break;
	}

//*/
	return 0;
}
