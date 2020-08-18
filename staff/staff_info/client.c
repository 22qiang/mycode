#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define LEN 16
#define DATALEN 128

#define MANAGER_LOGIN 	1
#define USER_LOGIN 		2
#define LOGIN           3
#define QUIT 			4
#define MANAGER_Q 		1
#define MANAGER_M 		2
#define MANAGER_A 		3
#define MANAGER_D 		4
#define MANAGER_H 		5
#define MANAGER_QUIT 	6
#define USER_Q 			1
#define USER_M 			2
#define USER_QUIT 		3

typedef struct{
	int id;
	int type;
	char name[LEN];
	char password[8];
	int age;
	char phone[LEN];
	char addr[DATALEN];
	char position[DATALEN];
	char date[DATALEN];
	int level;
	double salaray;
}staff_info_t;

typedef struct {
	int msgtype;
	int usertype;
	char username[LEN];
	char password[8];
	char msg[DATALEN];
	int flags;
	staff_info_t info;
}MSG;

int login(MSG *msg,int fd);
int manager_login(MSG *msg,int fd);
int user_login(MSG *msg,int fd);
int manager_mode(MSG *msg,int fd);
int manager_query(MSG * msg,int fd);
int manager_modify(MSG * msg,int fd);
int manager_add(MSG * msg,int fd);
int manager_delete(MSG * msg,int fd);
int manager_history(MSG * msg,int fd);
int manager_quit(MSG * msg,int fd);
int query_name(MSG *msg,int fd);
int query_all(MSG *msg,int fd);
int user_mode(MSG * msg,int fd);
int user_query(MSG *msg,int fd);
int user_modify(MSG *msg,int fd);
int user_quit(MSG *msg,int fd);

int main(int argc, const char *argv[])
{	
	if(argc != 3)
	{
		fprintf(stderr,"Usage:%s <IP> <Port>\n",argv[0]);
		return -1;
	}
	MSG msg;
	memset(&msg,0,sizeof(MSG));
	int sockfd = socket(AF_INET,SOCK_STREAM,0);
	if(sockfd < 0)
	{
		perror("fail to socket");
		return -1;
	}

	struct sockaddr_in addr = 
	{
		.sin_family = AF_INET,
		.sin_port = htons(atoi(argv[2])),
		.sin_addr.s_addr = inet_addr(argv[1]),
	};
	
	if(connect(sockfd,(struct sockaddr*)&addr,\
				sizeof(addr)) < 0)
	{
		perror("fail to connect");
		return -1;
	}
	printf("%s:%s:%d\n",__FILE__,__func__,__LINE__);
	
	login(&msg,sockfd);

	close(sockfd);
	return 0;
}


int login(MSG *msg,int fd)
{
	while(1)
	{
		memset(msg,0,sizeof(MSG));
		printf("***************************************************************\n");
		printf("*  1.管理员模式     2.普通用户模式     3.注册用户    4.退出   *\n");
		printf("***************************************************************\n");
		printf("请输入你想选择的功能(1~3):");
		scanf("%d%*c",&msg->usertype);
		switch(msg->usertype)
		{
			case MANAGER_LOGIN:
								printf("请输入用户名：");
								scanf("%s%*c",msg->username);
								printf("请输入密码(最多8位)：");
								scanf("%s%*c",msg->password);
								manager_login(msg,fd);
								break;
			case USER_LOGIN:
								printf("请输入用户名：");
								scanf("%s%*c",msg->username);
								printf("请输入密码(最多8位)：");
								scanf("%s%*c",msg->password);
								user_login(msg,fd);
								break;
			case LOGIN:
								printf("注册一个新用户\n");
								manager_add(msg,fd);
								break;
			case QUIT: printf("谢谢使用\n");return 0;break;
			default: printf("输入错误！\n");
		}
	}
	return 0;
}

int manager_login(MSG *msg,int fd)
{
	if(send(fd,msg,sizeof(MSG),0) < 0)
	{
		perror("fail to send in manager_login");
		return -1;
	}
	printf("send success,%d\n",__LINE__);
	if(recv(fd,msg,sizeof(MSG),0) > 0)
	{
		if(strncmp(msg->msg,"OK",2) == 0)
		{
			printf("msg->recvmsg:%s\n",msg->msg);
			printf("亲爱的管理员，欢迎您登陆员工管理系统！");
			puts("");
			manager_mode(msg,fd);
		}
		else
		{
			printf("%s\n",msg->msg);
			printf("账号/密码/权限不匹配,请重新输入！\n");
		}
	}
	return 0;
}

int manager_mode(MSG *msg,int fd)
{
	while(1)
	{
		printf("*********************************************************\n");
		printf("*  1.查询  2.修改  3.添加用户  4.删除用户  5.查询历史   *\n");
		printf("*  6.退出 												*\n");
		printf("*********************************************************\n");
		printf("请输入你想选择的功能：");
		scanf("%d%*c",&msg->msgtype);
		switch(msg->msgtype)
		{
			case MANAGER_Q:manager_query(msg,fd);break;
			case MANAGER_M:manager_modify(msg,fd);break;
			case MANAGER_A:manager_add(msg,fd);break;
			case MANAGER_D:manager_delete(msg,fd);break;
			case MANAGER_H:manager_history(msg,fd);break;
			case MANAGER_QUIT:manager_quit(msg,fd);return 0;break;
			default:
				printf("输入错误重新输入！\n");
		}
	}
	return 0;
}	

int manager_query(MSG * msg,int fd)
{
	printf("This is query\n");
	while(1)
	{
		printf("*********************************************\n");
		printf("*   1.按人名查找    2.查找所有    3.退出    *\n");
		printf("*********************************************\n");
		printf("请输入你选择的功能：");
		scanf("%d%*c",&msg->flags);
		switch(msg->flags)
		{
			case 1:msg->msgtype = 11;query_name(msg,fd);break;
			case 2:msg->msgtype = 12;query_all(msg,fd);break;
			case 3:return 0;break;
		}
	}
	return 0;
}
int query_name(MSG *msg,int fd)
{
	printf("query_name\n");
	memset(msg->msg,0,sizeof(char)*DATALEN);
	memset(&msg->info,0,sizeof(staff_info_t));
	printf("请输入你要搜索的名字：");
	scanf("%s%*c",msg->msg);
	if(send(fd,msg,sizeof(MSG),0) < 0)
	{
		perror("query_name send error");
		return -1;
	}
	if(recv(fd,msg,sizeof(MSG),0) < 0)
	{
		printf("query_name recv error");
		return -1;
	}
	if(strncmp(msg->msg,"OK",2) == 0)
	{
		printf("工号   用户类型   姓名   密码   年龄   电话   地址   职位   入职年月   等级   工资\n");
		printf("==================================================================================\n");
		printf("%d,    %d,    %s,    %s,    %d,    %s,    %s,    %s,    %s,    %d,    %lf\n",\
			msg->info.id,msg->info.type,msg->info.name,msg->info.password,msg->info.age,\
			msg->info.phone,msg->info.addr,msg->info.position,msg->info.date,msg->info.level,msg->info.salaray);
	}
	else
	{
		printf("%s,%d\n",msg->msg,__LINE__);
		printf("输入错误！\n");
	}
	return 0;
}

int query_all(MSG *msg,int fd)
{
	printf("query_all\n");
	int count = 0;
	memset(msg->msg,0,sizeof(char)*DATALEN);
	memset(&msg->info,0,sizeof(staff_info_t));
	if(send(fd,msg,sizeof(MSG),0) < 0)
	{
		perror("query_name send error");
		return -1;
	}
	printf("%d\n",__LINE__);
	printf("工号   用户类型   姓名   密码   年龄   电话   地址   职位   入职年月   等级   工资\n");
	printf("==================================================================================\n");
	while(1)
	{
		recv(fd,msg,sizeof(MSG),0);
		printf("%d,    %d,    %s,    %s,    %d,    %s,    %s,    %s,    %s,    %d,    %lf\n",\
			msg->info.id,msg->info.type,msg->info.name,msg->info.password,msg->info.age,\
			msg->info.phone,msg->info.addr,msg->info.position,msg->info.date,msg->info.level,msg->info.salaray);
		count++;
		if(count == msg->flags)
			break;
	}
	
	return 0;
}

int manager_modify(MSG * msg,int fd)
{
	printf("请输入你想要修改的员工工号：");
	scanf("%s%*c",msg->msg);
	printf("*******************请输入要修改的选项********************\n");
	printf("*******1:姓名    2:密码    3:年龄     4:电话    *********\n");
	printf("*******5:地址    6:职位    7:入职年月 8:等级    *********\n");
	printf("*******9:工资    10:退出                        *********\n");
	printf("*********************************************************\n");
	printf("请输入你想修改的选项：");
	scanf("%d%*c",&msg->flags);
	switch(msg->flags)
	{
		case 1:printf("请输入修改的姓名：");
			   scanf("%s%*c",msg->info.name);
			   break;
		case 2:printf("请输入修改的密码：");
			   scanf("%s%*c",msg->info.password);
			   break;
		case 3:printf("请输入修改的年龄：");
			   scanf("%d%*c",&msg->info.age);
			   break;
		case 4:printf("请输入修改的电话：");
			   scanf("%s%*c",msg->info.phone);
			   break;
		case 5:printf("请输入修改的地址：");
			   scanf("%s%*c",msg->info.addr);
			   break;
		case 6:printf("请输入修改的职位：");
			   scanf("%s%*c",msg->info.position);
			   break;
		case 7:printf("请输入修改的入职年月：");
			   scanf("%s%*c",msg->info.date);
			   break;
		case 8:printf("请输入修改的评级：");
			   scanf("%d%*c",&msg->info.level);
			   break;
		case 9:printf("请输入修改的工资：");
			   scanf("%lf%*c",&msg->info.salaray);
			   break;
		case 10:return 0;break;
	}

	if(send(fd,msg,sizeof(MSG),0) < 0)
	{
		perror("manager_modify send error");
		return -1;
	}
	if(recv(fd,msg,sizeof(MSG),0) < 0)
	{
		perror("manager_modify recv error");
		return -1;
	}
	if(strncmp(msg->msg,"OK",2) == 0)
	{
		printf("修改成功！\n");
	}
	return 0;
}
int manager_add(MSG * msg,int fd)
{
	char opt;
	printf("***************热烈欢迎新员工***************.\n");
	while(1)
	{
		memset(&msg->info,0,sizeof(staff_info_t));
		printf("请输入工号：");
		scanf("%d%*c",&msg->info.id);
		printf("你输入的工号是：%d\n",msg->info.id);
		printf("工号信息一旦录入无法更改，请确认您所输入的是否正确！(Y/N)");
		scanf("%c%*c",&opt);
		if(opt == 'N' || opt == 'n') continue;
		printf("请输入用户名：");
		scanf("%s%*c",msg->info.name);
		printf("请输入用户密码：");
		scanf("%s%*c",msg->info.password);
		printf("请输入年龄：");
		scanf("%d%*c",&msg->info.age);
		printf("请输入电话：");
		scanf("%s%*c",msg->info.phone);
		printf("请输入家庭地址：");
		scanf("%s%*c",msg->info.addr);
		printf("请输入职位：");
		scanf("%s%*c",msg->info.position);
		printf("请输入入职日期：（格式：2019-03-25）：");
		scanf("%s%*c",msg->info.date);
		printf("请输入等级（1-5,5为最高,1为新员工）：");
		scanf("%d%*c",&msg->info.level);
		printf("请输入工资：");
		scanf("%lf%*c",&msg->info.salaray);
		printf("是否为管理员：（Y/N）");
		scanf("%c%*c",&opt);
		if(opt == 'Y' || opt == 'y') msg->info.type = 0;
		if(opt == 'N' || opt == 'n') msg->info.type = 1;
		
		if(send(fd,msg,sizeof(MSG),0) < 0)
		{
			perror("add send error");
			return -1;
		}
		if(recv(fd,msg,sizeof(MSG),0) < 0)
		{
			perror("add recv error");
			return -1;
		}
		if(strncmp(msg->msg,"OK",2) == 0) 
			printf("修改数据库成功！\n");
		else
		{
			printf("修改数据库失败！\n");
			return -1;
		}
		printf("是否继续添加成员：（Y/N）");
		scanf("%c%*c",&opt);
		if(opt == 'N' || opt == 'n') break;
	}
	return 0;
}
int manager_delete(MSG * msg,int fd)
{
	memset(&msg->info,0,sizeof(staff_info_t));
	printf("请输入要删除的用户工号：");
	scanf("%d%*c",&msg->info.id);
	printf("请输入要删除的用户名：");
	scanf("%s%*c",msg->info.name);
	if(send(fd,msg,sizeof(MSG),0) < 0)
	{
		perror("delete send error");
		return -1;
	}
	if(recv(fd,msg,sizeof(MSG),0) < 0)
	{
		perror("delete recv error");
		return -1;
	}
	if(strncmp(msg->msg,"OK",2) == 0) 
		printf("修改数据库成功！删除工号为%d的用户\n",msg->info.id);
	else
	{
		printf("修改数据库失败！\n");
		return -1;
	}

	return 0;
}
int manager_history(MSG * msg,int fd)
{
	int count = 0;
	if(send(fd,msg,sizeof(MSG),0) < 0)
	{
		perror("history send error");
		return -1;
	}

	printf("******************历史信息*************************\n");
	while(1)
	{
		if(recv(fd,msg,sizeof(MSG),0) < 0)
		{
			perror("history recv error");
			return -1;
		}
		printf("%s\n",msg->msg);
		count++;
		if(count == msg->flags)
			break;
	}
	return 0;
}

int manager_quit(MSG * msg,int fd)
{
	if(send(fd,msg,sizeof(MSG),0) < 0)
	{
		perror("delete send error");
		return -1;
	}

	return 0;
}

int user_login(MSG *msg,int fd)
{
	if(send(fd,msg,sizeof(MSG),0) < 0)
	{
		perror("fail to send in user_login");
		return -1;
	}
	printf("%d\n",__LINE__);
	if(recv(fd,msg,sizeof(MSG),0) > 0)
	{
		printf("recv success\n");
		if(strncmp(msg->msg,"OK",2) == 0)
		{
			printf("亲爱的用户，欢迎您登陆员工管理系统！\n");
			user_mode(msg,fd);	
		}
		else
		{
			printf("%s\n",msg->msg);
			printf("账号/密码,请重新输入!\n");
		}
	}
	
	return 0;
}

int user_mode(MSG * msg,int fd)
{
	while(1)
	{
		printf("**********************************************\n");
		printf("****** 1.查询     2.修改     3.退出   ********\n");
		printf("**********************************************\n");
		printf("请输入你想选择的功能：");
		scanf("%d%*c",&msg->msgtype);
		switch(msg->msgtype){
			case USER_Q:user_query(msg,fd);break;
			case USER_M:user_modify(msg,fd);break;
			case USER_QUIT:user_quit(msg,fd);return 0;break;
		}
	}
	return 0;
}

int user_query(MSG *msg,int fd)
{
	if(send(fd,msg,sizeof(MSG),0) < 0)
	{
		perror("user query send error");
		return -1;
	}
	if(recv(fd,msg,sizeof(MSG),0) < 0)
	{
		printf("query_name recv error");
		return -1;
	}
	if(strncmp(msg->msg,"OK",2) == 0)
	{
		printf("工号   用户类型   姓名   密码   年龄   电话   地址   职位   入职年月   等级   工资\n");
		printf("==================================================================================\n");
		printf("%d,    %d,    %s,    %s,    %d,    %s,    %s,    %s,    %s,    %d,    %lf\n",\
			msg->info.id,msg->info.type,msg->info.name,msg->info.password,msg->info.age,\
			msg->info.phone,msg->info.addr,msg->info.position,msg->info.date,msg->info.level,msg->info.salaray);
	}

	return 0;
}
int user_modify(MSG *msg,int fd)
{
	printf("*******************请输入要修改的选项********************\n");
	printf("*******    1:地址    2:电话     3:密码   4.退出  ********\n");
	printf("*********************************************************\n");
	printf("请输入你想修改的选项：");
	scanf("%d%*c",&msg->flags);
	switch(msg->flags)
	{
		case 1:printf("请输入修改的地址：");
			   scanf("%s%*c",msg->info.addr);
			   break;
		case 2:printf("请输入修改的电话：");
			   scanf("%s%*c",msg->info.phone);
			   break;
		case 3:printf("请输入修改的密码(最多8位)：");
			   scanf("%s%*c",msg->info.password);
			   break;
		case 4:return 0;break;
	}

	if(send(fd,msg,sizeof(MSG),0) < 0)
	{
		perror("manager_modify send error");
		return -1;
	}
	if(recv(fd,msg,sizeof(MSG),0) < 0)
	{
		perror("manager_modify recv error");
		return -1;
	}
	if(strncmp(msg->msg,"OK",2) == 0)
	{
		printf("修改成功！\n");
	}

	return 0;
}
int user_quit(MSG *msg,int fd)
{
	if(send(fd,msg,sizeof(MSG),0) < 0)
	{
		perror("user query send error");
		return -1;
	}
	return 0;
}
