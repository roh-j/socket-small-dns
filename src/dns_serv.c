#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/select.h>
#include <netdb.h>
#include <time.h>

#define BUF_SIZE 1024
#define HASH_SEEK 176
#define LOG_SEEK 73

void name_to_ip(char* query, char* dns_return);
void ip_to_name(struct sockaddr_in serv_adr, char* query, char* dns_return);

int hash(char* key, int key_length, int table_size);
void init_hash_pivot(FILE* fp, int file_seek,
	 char* name_data_domain, char* name_data_ip, int* name_data_hit,
	 char* ip_data_domain, char* ip_data_ip, int* ip_data_hit,
	 char* name_pivot_domain, char* name_pivot_ip, int* name_pivot_hit,
	 char* ip_pivot_domain, char* ip_pivot_ip, int* ip_pivot_hit);
void insert_hash(FILE* fp, int file_seek, int op_type,
	 int name_data_num, int ip_data_num, int table_size,
	 char* data, char* dns_return,
	 char* pivot_domain, char* pivot_ip, int pivot_hit);
void swap_hash(FILE* fp, int pivot_seek, int file_seek, int op_type,
	 char* name_data_domain, char* name_data_ip, int name_data_hit,
	 char* ip_data_domain, char* ip_data_ip, int ip_data_hit,
	 char* name_pivot_domain, char* name_pivot_ip, int name_pivot_hit,
	 char* ip_pivot_domain, char* ip_pivot_ip, int ip_pivot_hit);
void insert_log(FILE* lp, char* log_date, struct sockaddr_in sock_adr, char* query);
void error_handling(char *buf);

int main(int argc, char *argv[])
{
	int serv_sock, clnt_sock;
	struct sockaddr_in serv_adr, clnt_adr, sock_adr;
	struct timeval timeout;
	fd_set reads, cpy_reads;

	socklen_t adr_sz;
	int fd_max, str_len, fd_num, i;
	char buf[BUF_SIZE];

	time_t time_stamp;
	struct tm *t;

	FILE *fp, *lp;
	int name_data_num;
	int ip_data_num;
	int table_size;

	int hash_key, file_seek, pivot_seek;
	int name_pivot_hit, ip_pivot_hit, name_data_hit, ip_data_hit;
	char name_pivot_domain[50] = {0, }, name_pivot_ip[50] = {0, }, ip_pivot_domain[50] = {0, }, ip_pivot_ip[50] = {0, };
	char name_data_domain[50] = {0, }, name_data_ip[50] = {0, }, ip_data_domain[50] = {0, }, ip_data_ip[50] = {0, };

	char dns_return[50] = {0, }, log_date[50] = {0, };

	if(argc != 2) {
		printf("Usage : %s <port>\n", argv[0]);
		exit(1);
	}

	serv_sock = socket(PF_INET, SOCK_STREAM, 0);
	memset(&serv_adr, 0, sizeof(serv_adr));
	serv_adr.sin_family = AF_INET;
	serv_adr.sin_addr.s_addr = htonl(INADDR_ANY);
	serv_adr.sin_port = htons(atoi(argv[1]));

	if(bind(serv_sock, (struct sockaddr*) &serv_adr, sizeof(serv_adr)) == -1)
		error_handling("bind() error");
	if(listen(serv_sock, 5) == -1)
		error_handling("listen() error");

	FD_ZERO(&reads);
	FD_SET(serv_sock, &reads);
	fd_max = serv_sock;

	while(1)
	{
		cpy_reads = reads;
		timeout.tv_sec = 5;
		timeout.tv_usec = 5000;

		if((fd_num = select(fd_max+1, &cpy_reads, 0, 0, &timeout)) == -1)
			break;

		if(fd_num == 0)
			continue;

		for(i = 0; i < fd_max+1; i++)
		{
			if(FD_ISSET(i, &cpy_reads))
			{
				if(i == serv_sock)
				{
					adr_sz = sizeof(clnt_adr);
					clnt_sock = accept(serv_sock, (struct sockaddr*)&clnt_adr, &adr_sz);
					FD_SET(clnt_sock, &reads);
					if(fd_max < clnt_sock)
						fd_max = clnt_sock;
					printf("connected client: %d \n", clnt_sock-3);
				}
				else
				{
					str_len = read(i, buf, BUF_SIZE);
					if(str_len == 0)
					{
						FD_CLR(i, &reads);
						close(i);
						printf("closed client: %d \n", i-3);
					}
					else
					{
						getpeername(i, (struct sockaddr *)&sock_adr, &adr_sz);

						time_stamp = time(NULL);
						t = localtime(&time_stamp);

						sprintf(log_date, "%d/%d/%d", t->tm_year + 1900, t->tm_mon + 1, t->tm_mday);
						printf("DATE: %s\n", log_date);
						printf("CLIENT IP ADDRESS: %s\n", inet_ntoa(sock_adr.sin_addr));

						if ((int) buf[0] == 3)
						{
							/* 공사 중... */
							lp = fopen("data/log.txt", "r");
							fclose(lp);
						}
						else
						{
							fp = fopen("data/hash_table.txt", "r+");
							lp = fopen("data/log.txt", "a");

							if (fp == NULL || lp == NULL)
								printf("ERROR\n");

							fseek(fp, 0, SEEK_SET);
							fscanf(fp, "%30s %20s %10d %80s %20s %10d\n",
									name_data_domain, name_data_ip, &name_data_hit,
									ip_data_domain, ip_data_ip, &ip_data_hit);

							name_data_num = atoi(name_data_ip);
							ip_data_num = atoi(ip_data_ip);
							table_size = atoi(name_data_domain);

							printf("DOMAIN TABLE DATA NUM: %d\n", name_data_num);
							printf("IP TABLE DATA NUM: %d\n", ip_data_num);
							printf("TABLE SIZE: %d\n", table_size);

							hash_key = hash(&buf[4], strlen(&buf[4]), table_size);

							buf[sizeof(int)+strlen(&buf[4])-1] = 0;
							file_seek = hash_key * HASH_SEEK + HASH_SEEK;
							pivot_seek = file_seek;

							printf("FILE POINTER: %d\n", file_seek);
							printf("HASH KEY: %d\n", hash_key);

							init_hash_pivot(fp, file_seek,
											name_data_domain, name_data_ip, &name_data_hit,
								 			ip_data_domain, ip_data_ip, &ip_data_hit,
								 			name_pivot_domain, name_pivot_ip, &name_pivot_hit,
								 			ip_pivot_domain, ip_pivot_ip, &ip_pivot_hit);

							if ((int) buf[0] == 1)
							{
								printf("[HASH] DOMAIN DATA: %s\n", name_data_domain);
								printf("[HASH] IP DATA: %s\n", name_data_ip);

								if (!strcmp(name_data_domain, "NULL"))
								{
									printf("[NAME] CASE 1\n");
									name_to_ip(&buf[4], dns_return);

									if (strcmp(dns_return, "NOT FOUND"))
									{
										printf("[NAME] SUB CASE 1-1\n");
										insert_hash(fp, file_seek, (int) buf[0],
													name_data_num, ip_data_num, table_size,
													&buf[4], dns_return,
													ip_pivot_domain, ip_pivot_ip, ip_pivot_hit);
									}
									else
										printf("[NAME] SUB CASE 1-2\n");

									write(i, dns_return, strlen(dns_return));
								}
								else
								{
									printf("[NAME] CASE 2\n");
									if (!strcmp(name_data_domain, &buf[4]))
									{
										printf("[NAME] SUB CASE 2-1\n");
										fseek(fp, file_seek, SEEK_SET);
										fprintf(fp, "%30s %20s %10d %80s %20s %10d\n",
												name_data_domain, name_data_ip, name_data_hit+1,
												ip_data_domain, ip_data_ip, ip_data_hit);

										dns_return[0] = 0;
										sprintf(dns_return, "%s (Hit: %d)", name_data_ip, name_data_hit+1);
										insert_log(lp, log_date, sock_adr, &buf[4]);
										write(i, dns_return, strlen(dns_return));
									}
									else
									{
										printf("[NAME] SUB CASE 2-2\n");
										while(1)
										{
											file_seek += HASH_SEEK;
											fseek(fp, file_seek, SEEK_SET);
											fscanf(fp, "%30s %20s %10d %80s %20s %10d\n",
													name_data_domain, name_data_ip, &name_data_hit,
													ip_data_domain, ip_data_ip, &ip_data_hit);

											if (!strcmp(name_data_domain, &buf[4]))
											{
												printf("[NAME] SUB CASE 2-2-1\n");

												if (name_pivot_hit < name_data_hit+1)
												{
													printf("[NAME] SUB CASE 2-2-1-1\n");
													swap_hash(fp, pivot_seek, file_seek, (int) buf[0],
														 	  name_data_domain, name_data_ip, name_data_hit,
														 	  ip_data_domain, ip_data_ip, ip_data_hit,
														 	  name_pivot_domain, name_pivot_ip, name_pivot_hit,
														 	  ip_pivot_domain, ip_pivot_ip, ip_pivot_hit);
												}
												else
												{
													printf("[NAME] SUB CASE 2-2-1-2\n");
													fseek(fp, file_seek, SEEK_SET);
													fprintf(fp, "%30s %20s %10d %80s %20s %10d\n",
															name_data_domain, name_data_ip, name_data_hit+1,
															ip_data_domain, ip_data_ip, ip_data_hit);
												}

												dns_return[0] = 0;
												sprintf(dns_return, "%s (Hit: %d)", name_data_ip, name_data_hit+1);
												insert_log(lp, log_date, sock_adr, &buf[4]);
												write(i, dns_return, strlen(dns_return));
												break;
											}
											if (!strcmp(name_data_domain, "NULL"))
											{
												printf("[NAME] SUB CASE 2-2-2\n");
												name_to_ip(&buf[4], dns_return);

												if (strcmp(dns_return, "NOT FOUND"))
												{
													printf("[NAME] SUB CASE 2-2-2-1\n");
													insert_hash(fp, file_seek, (int) buf[0],
																name_data_num, ip_data_num, table_size,
																&buf[4], dns_return,
																ip_data_domain, ip_data_ip, ip_data_hit);
												}
												else
													printf("[NAME] SUB CASE 2-2-2-2\n");

												write(i, dns_return, strlen(dns_return));
												break;
											}
										}
									}
								}
							}
							else if ((int) buf[0] == 2)
							{
								printf("[HASH] DOMAIN DATA: %s\n", ip_data_domain);
								printf("[HASH] IP DATA: %s\n", ip_data_ip);

								if (!strcmp(ip_data_ip, "NULL"))
								{
									printf("[ IP ] CASE 1\n");
									ip_to_name(serv_adr, &buf[4], dns_return);

									if (strcmp(dns_return, "NOT FOUND"))
									{
										printf("[ IP ] SUB CASE 1-1\n");
										insert_hash(fp, file_seek, (int) buf[0],
													name_data_num, ip_data_num, table_size,
													&buf[4], dns_return,
													name_pivot_domain, name_pivot_ip, name_pivot_hit);
									}
									else
										printf("[ IP ] SUB CASE 1-2\n");

									write(i, dns_return, strlen(dns_return));
								}
								else
								{
									printf("[ IP ] CASE 2\n");
									if (!strcmp(ip_data_ip, &buf[4]))
									{
										printf("[ IP ] SUB CASE 2-1\n");
										fseek(fp, file_seek, SEEK_SET);
										fprintf(fp, "%30s %20s %10d %80s %20s %10d\n",
												name_data_domain, name_data_ip, name_data_hit,
												ip_data_domain, ip_data_ip, ip_data_hit+1);

										dns_return[0] = 0;
										sprintf(dns_return, "%s (Hit: %d)", ip_data_domain, ip_data_hit+1);
										insert_log(lp, log_date, sock_adr, &buf[4]);
										write(i, dns_return, strlen(dns_return));
									}
									else
									{
										printf("[ IP ] SUB CASE 2-2\n");
										while(1)
										{
											file_seek += HASH_SEEK;
											fseek(fp, file_seek, SEEK_SET);
											fscanf(fp, "%30s %20s %10d %80s %20s %10d\n",
													name_data_domain, name_data_ip, &name_data_hit,
													ip_data_domain, ip_data_ip, &ip_data_hit);

											if (!strcmp(ip_data_ip, &buf[4]))
											{
												printf("[ IP ] SUB CASE 2-2-1\n");

												if (ip_pivot_hit < ip_data_hit+1)
												{
													printf("[ IP ] SUB CASE 2-2-1-1\n");
													swap_hash(fp, pivot_seek, file_seek, (int) buf[0],
														 	  name_data_domain, name_data_ip, name_data_hit,
														 	  ip_data_domain, ip_data_ip, ip_data_hit,
														 	  name_pivot_domain, name_pivot_ip, name_pivot_hit,
														 	  ip_pivot_domain, ip_pivot_ip, ip_pivot_hit);
												}
												else
												{
													printf("[ IP ] SUB CASE 2-2-1-2\n");
													fseek(fp, file_seek, SEEK_SET);
													fprintf(fp, "%30s %20s %10d %80s %20s %10d\n",
															name_data_domain, name_data_ip, name_data_hit,
															ip_data_domain, ip_data_ip, ip_data_hit+1);
												}

												dns_return[0] = 0;
												sprintf(dns_return, "%s (Hit: %d)", ip_data_domain, ip_data_hit+1);
												insert_log(lp, log_date, sock_adr, &buf[4]);
												write(i, dns_return, strlen(dns_return));
												break;
											}
											if (!strcmp(ip_data_ip, "NULL"))
											{
												printf("[ IP ] SUB CASE 2-2-2\n");
												ip_to_name(serv_adr, &buf[4], dns_return);

												if (strcmp(dns_return, "NOT FOUND"))
												{
													printf("[ IP ] SUB CASE 2-2-2-1\n");
													insert_hash(fp, file_seek, (int) buf[0],
																name_data_num, ip_data_num, table_size,
																&buf[4], dns_return,
																name_data_domain, name_data_ip, name_data_hit);
												}
												else
													printf("[ IP ] SUB CASE 2-2-2-2\n");

												write(i, dns_return, strlen(dns_return));
												break;
											}
										}
									}
								}
							}
							fclose(fp);
							fclose(lp);
						}
					}
				}
			}
		}
	}
	close(serv_sock);
	return 0;
}

void insert_log(FILE* lp, char* log_date, struct sockaddr_in sock_adr, char* query)
{
	/* Cache 적숭 시 로그에 저장 */
	fprintf(lp, "%20s %20s %30s\n", log_date, inet_ntoa(sock_adr.sin_addr), query);
}

void swap_hash(FILE* fp, int pivot_seek, int file_seek, int op_type,
	 char* name_data_domain, char* name_data_ip, int name_data_hit,
	 char* ip_data_domain, char* ip_data_ip, int ip_data_hit,
	 char* name_pivot_domain, char* name_pivot_ip, int name_pivot_hit,
	 char* ip_pivot_domain, char* ip_pivot_ip, int ip_pivot_hit)
{
	/* Hash 테이블 교환 함수 */
	if (op_type == 1)
	{
		fseek(fp, pivot_seek, SEEK_SET);
		fprintf(fp, "%30s %20s %10d %80s %20s %10d\n",
				name_data_domain, name_data_ip, name_data_hit+1,
				ip_pivot_domain, ip_pivot_ip, ip_pivot_hit);
		fseek(fp, file_seek, SEEK_SET);
		fprintf(fp, "%30s %20s %10d %80s %20s %10d\n",
				name_pivot_domain, name_pivot_ip, name_pivot_hit,
				ip_data_domain, ip_data_ip, ip_data_hit);
	}
	else if (op_type == 2)
	{
		fseek(fp, pivot_seek, SEEK_SET);
		fprintf(fp, "%30s %20s %10d %80s %20s %10d\n",
				name_pivot_domain, name_pivot_ip, name_pivot_hit,
				ip_data_domain, ip_data_ip, ip_data_hit+1);
		fseek(fp, file_seek, SEEK_SET);
		fprintf(fp, "%30s %20s %10d %80s %20s %10d\n",
				name_data_domain, name_data_ip, name_data_hit,
				ip_pivot_domain, ip_pivot_ip, ip_pivot_hit);
	}
}

void insert_hash(FILE* fp, int file_seek, int op_type,
	 int name_data_num, int ip_data_num, int table_size,
	 char* data, char* dns_return,
	 char* pivot_domain, char* pivot_ip, int pivot_hit)
{
	/* Hash 삽입 함수 */
	char name_data_num_store[50];
	char ip_data_num_store[50];
	char table_size_store[50];

	fseek(fp, file_seek, SEEK_SET);

	if (op_type == 1)
	{
		fprintf(fp, "%30s %20s %10d %80s %20s %10d\n",
				data, dns_return, 0,
				pivot_domain, pivot_ip, pivot_hit);

		fseek(fp, 0, SEEK_SET);

		sprintf(name_data_num_store, "%d", name_data_num+1);
		sprintf(ip_data_num_store, "%d", ip_data_num);
		sprintf(table_size_store, "%d", table_size);

		fprintf(fp, "%30s %20s %10d %80s %20s %10d\n",
				table_size_store, name_data_num_store, 0,
				table_size_store, ip_data_num_store, 0);

		strcat(dns_return, " (Hit: 0)");
	}
	else if (op_type == 2)
	{
		fprintf(fp, "%30s %20s %10d %80s %20s %10d\n",
				pivot_domain, pivot_ip, pivot_hit,
				dns_return, data, 0);

		fseek(fp, 0, SEEK_SET);

		sprintf(name_data_num_store, "%d", name_data_num);
		sprintf(ip_data_num_store, "%d", ip_data_num+1);
		sprintf(table_size_store, "%d", table_size);

		fprintf(fp, "%30s %20s %10d %80s %20s %10d\n",
				table_size_store, name_data_num_store, 0,
				table_size_store, ip_data_num_store, 0);

		strcat(dns_return, " (Hit: 0)");
	}
}

void init_hash_pivot(FILE* fp, int file_seek,
	 char* name_data_domain, char* name_data_ip, int* name_data_hit,
	 char* ip_data_domain, char* ip_data_ip, int* ip_data_hit,
	 char* name_pivot_domain, char* name_pivot_ip, int* name_pivot_hit,
	 char* ip_pivot_domain, char* ip_pivot_ip, int* ip_pivot_hit)
{
	/* HASH 키의 기준 데이터 */
	name_pivot_domain[0] = 0;
	name_pivot_ip[0] = 0;
	ip_pivot_domain[0] = 0;
	ip_pivot_ip[0] = 0;

	fseek(fp, file_seek, SEEK_SET);
	fscanf(fp, "%30s %20s %10d %80s %20s %10d\n",
			name_data_domain, name_data_ip, name_data_hit,
			ip_data_domain, ip_data_ip, ip_data_hit);

	strcat(name_pivot_domain, name_data_domain);
	strcat(name_pivot_ip, name_data_ip);
	*name_pivot_hit = *name_data_hit;

	strcat(ip_pivot_domain, ip_data_domain);
	strcat(ip_pivot_ip, ip_data_ip);
	*ip_pivot_hit = *ip_data_hit;
}

int hash(char* key, int key_length, int table_size)
{
	/* 자릿수 접기로 HASH 생성 */
	int i = 0;
	int hash_value = 0;

	for(i = 0 ; i < key_length ; i++)
		hash_value = (hash_value) + key[i];

	return hash_value % table_size;
}

void name_to_ip(char* query, char* dns_return)
{
	/* Domain에 대한 IP 반환 */
	dns_return[0] = 0;
	struct hostent *host_name;

	host_name = gethostbyname(query);

	if (host_name)
		strcat(dns_return, inet_ntoa(*(struct in_addr*)host_name->h_addr_list[0]));
	else
		strcat(dns_return, "NOT FOUND");
}

void ip_to_name(struct sockaddr_in serv_adr, char* query, char* dns_return)
{
	/* IP에 대한 Domain 반환 */
	dns_return[0] = 0;
	struct hostent *host_ip;

	memset(&serv_adr, 0, sizeof(serv_adr));
	serv_adr.sin_addr.s_addr = inet_addr(query);

	host_ip = gethostbyaddr((char*)&serv_adr.sin_addr, 4, AF_INET);

	if (host_ip)
		strcat(dns_return, host_ip->h_name);
	else
		strcat(dns_return, "NOT FOUND");
}

void error_handling(char *buf)
{
	fputs(buf, stderr);
	fputc('\n', stderr);
	exit(1);
}
