#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define BUF_SIZE 1024
void error_handling(char *message);

int main(int argc, char *argv[])
{
	int sock;
	char message[BUF_SIZE];
	int str_len;
	struct sockaddr_in serv_adr;

	char operation[BUF_SIZE] = {0, };
	int menu = 0;

	if(argc != 3) {
		printf("Usage : %s <IP> <port>\n", argv[0]);
		exit(1);
	}

	sock = socket(PF_INET, SOCK_STREAM, 0);
	if(sock == -1)
		error_handling("socket() error");

	memset(&serv_adr, 0, sizeof(serv_adr));
	serv_adr.sin_family = AF_INET;
	serv_adr.sin_addr.s_addr = inet_addr(argv[1]);
	serv_adr.sin_port = htons(atoi(argv[2]));

	if(connect(sock, (struct sockaddr*)&serv_adr, sizeof(serv_adr)) == -1)
		error_handling("connect() error!");
	else
		puts("Connected...........");

	while(1)
	{
		while(1)
		{
			printf("\nMenu\n");
			printf("1: Name to IP\n2: IP to Name\n3: Quit\n");
			fputs("Input Menu: ", stdout);
			scanf("%d", &menu);
			fgetc(stdin);

			if (menu == 1 || menu == 2 || menu == 3)
				break;
		}

		if (menu == 3)
			break;

		*(int *) &operation[0] = menu;

		if (menu == 1)
			fputs("Input Domain Name: ", stdout);
		else if (menu == 2)
			fputs("Input IP: ", stdout);
		else if (menu == 3)
			fputs("Analysis DATA: ", stdout);

		fgets(&operation[4], BUF_SIZE, stdin);

		write(sock, operation, sizeof(operation));
		str_len = read(sock, message, BUF_SIZE);
		message[str_len] = 0;
		printf("Message from server: %s\n", message);
	}

	close(sock);
	return 0;
}

void error_handling(char *message)
{
	fputs(message, stderr);
	fputc('\n', stderr);
	exit(1);
}
