#include <iostream>
#include <pcap.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <Windows.h>
#include <conio.h>
#include <string>
#include <vector>
#include <iomanip>
#include <thread>
#include <sstream>
#include <cstdlib>
#include <locale>
#include <codecvt>
#include <tuple>
#include <fstream>
#include <mutex>// Para trabajar con hilos
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Iphlpapi.lib")

using namespace std;

int link_hdr_length = 0;
#define TH_SYN  0x02   // SYN flag
#define TH_ACK  0x10   // ACK flag
#define TH_URG  0x20   // URG flag
std::wstring arrowRight = L"→";
std::wstring arrowLeft = L"←";
std::wstring arrowUp = L"↑";
std::wstring arrowDown = L"↓";// Estructuras para los encabezados
// Capa Ethernet
struct ethernet_header {
    unsigned char ether_dest[6];     // Dirección MAC de destino
    unsigned char ether_src[6];      // Dirección MAC de origen
    unsigned short ether_type;       // Tipo de protocolo (IPv4, IPv6, ARP, etc.)
};

// Capa IP
struct ip_header {
    unsigned char  ip_header_len : 4; // Longitud del encabezado IP
    unsigned char  ip_version : 4;   // Versión de IP
    unsigned char  ip_tos;          // Tipo de servicio
    unsigned short ip_total_length; // Longitud total del paquete
    unsigned short ip_id;           // Identificación
    unsigned short ip_frag_offset;  // Desplazamiento de fragmento
    unsigned char  ip_ttl;          // Tiempo de vida
    unsigned char  ip_protocol;     // Protocolo
    unsigned short ip_checksum;     // Suma de verificación
    unsigned int   ip_srcaddr;      // Dirección IP de origen
    unsigned int   ip_destaddr;     // Dirección IP de destino
};

// Capa TCP
struct tcp_header {
    uint16_t tcp_src_port;           // Puerto de origen
    uint16_t tcp_dst_port;           // Puerto de destino
    uint32_t tcp_seq_num;            // Número de secuencia
    uint32_t tcp_ack_num;            // Número de acuse de recibo
    uint8_t  tcp_data_offset : 4;    // Desplazamiento de los datos
    uint8_t  tcp_reserved : 3;       // Reservado
    uint16_t tcp_flags : 9;          // Banderas TCP
    uint16_t tcp_window_size;        // Tamaño de la ventana
    uint16_t tcp_checksum;           // Suma de verificación
    uint16_t tcp_urgent_pointer;     // Puntero urgente
};

// Capa UDP
struct udp_header {
    uint16_t udp_src_port;           // Puerto de origen
    uint16_t udp_dst_port;           // Puerto de destino
    uint16_t udp_length;             // Longitud total del paquete UDP
    uint16_t udp_checksum;           // Suma de verificación
};

// Capa ICMP
struct icmp_header {
    uint8_t  icmp_type;              // Tipo ICMP
    uint8_t  icmp_code;              // Código ICMP
    uint16_t icmp_checksum;          // Suma de verificación
    uint16_t icmp_id;                // ID de mensaje
    uint16_t icmp_seq;               // Secuencia de mensaje
};


struct payload {
    unsigned char* data;  // Apunta a los datos de la carga útil
};


vector<string> packetList;
vector<std::vector<string>> matriz;
vector<string> raw;


int bandera = 1;
int currentPacketIndex = 0;
char filtro = 'a';
char stop;
bool ret = false;
int index = 0;
bool pause = false;
mutex mtx;
int k = 0;
int auxK = 0;
string CadenaFiltro;
pcap_t* capdev;

char* listar();
void call_me(u_char* user, const struct pcap_pkthdr* pkthdr, const u_char* packetd_ptr);
void sniff();
void gotoxy(int x, int y);
void drawHeader();
void flechas(int* count, int cap, int x, int y);
void ocultarCursor();
void mostrarCursor();
void flechas2();
void showPacketList(const vector<string>& packetList, int startIndex);
void showContent(const vector<vector<string>>& packetList);
void showRawContent(const string& rawData);
void guardarCSV(const vector<vector<string>>& m);
string hexToASCII(const string& hexStr);
void mostrarMenuFiltros(const vector<string>&);
void Protocolo();
void Ip();
void Port();
void Salir();
void showRaw(const string& rawData);
volatile bool stopProgram = false;


int main(int argc, char const* argv[]) {

    ocultarCursor();
    while (true) {
        packetList.clear();   // Elimina todos los elementos
        matriz.clear();       // Elimina todas las filas
        raw.clear();
        bandera = 1;
        currentPacketIndex = 0;
         filtro = 'a';
         stop;
         ret = false;
         index = 0;
         pause = false;
        mutex mtx;
         k = 0;
         auxK = 0;

        //funcion Pantalla incio 
        sniff();

    }
    
   
    return 0;
}

char* listar() {
    pcap_if_t* alldevs, * d;
    char errbuf[PCAP_ERRBUF_SIZE];
    char* selected_device = NULL;
    int device_index = 0, choice = 1;
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return NULL;
    }
    int count = 0;
    for (d = alldevs; d != NULL; d = d->next) {
        count++;
    }
    //
    system("cls");
    gotoxy(0, 0);
    cout << "\033[100;90m------------------------------------------------------------------------------------------------------------------------\033[0m" << endl;
    gotoxy(0, 1);
    cout << "\033[100;90m|\033[0m";
    gotoxy(50, 1);
    cout << "DISPOSITIVOS";
    gotoxy(119, 1);
    cout << "\033[100;90m|\033[0m" << endl;
    gotoxy(0, 2);
    cout << "\033[100;90m------------------------------------------------------------------------------------------------------------------------\033[0m" << endl;
    gotoxy(0, 3);

    for (int i = 3; i < 29; i++) {
        gotoxy(0, i);
        cout << "\033[100;90m|\033[0m";
        gotoxy(119, i);
        cout << "\033[100;90m|\033[0m";
    }
    gotoxy(0, 29);
    cout << "\033[100;90m------------------------------------------------------------------------------------------------------------------------\033[0m";
    int index1 = 1;
    for (d = alldevs; d != NULL; d = d->next) {
        if (d->description) {
            gotoxy(40, index1 + 3);
            cout << index1 << "." << d->description << endl;
        }
        index1++;
    }
    //
    flechas(&choice, index1 - 1, 38, 4);
    if (choice < 1 || choice > count) {
        cout << "seleccion invalida" << endl;
        pcap_freealldevs(alldevs);
        return NULL;
    }
    index1 = 1;
    for (d = alldevs; d != NULL; d = d->next) {
        if (index1 == choice) {
            selected_device = d->name;
            break;
        }
        index1++;
    }
    pcap_freealldevs(alldevs);
    return selected_device;
}

void flechas(int* count, int cap, int x, int y) {
    gotoxy(x, y);
    cout << "\033[46;30m[]\033[0m";
    while (true) {
        if (_kbhit()) {
            int key = _getch();
            if (key == 27) { // Tecla ESC

                break;
            }
            if (key == 13) {
                ret = true;
                gotoxy(0, cap + 1);
                break;
            }
            else if (key == 224) { // Código especial para teclas extendidas (flechas)
                key = _getch(); // Captura el código de la flecha
                switch (key) {
                case 72: // Flecha arriba
                    if ((*count) > 1) {
                        (*count)--;
                        gotoxy(x, y);
                        cout << "  ";
                        y--;
                        gotoxy(x, y);
                        cout << "\033[46;30m[]\033[0m";;

                    }
                    break;
                case 80: // Flecha abajo
                    if ((*count) < cap) {
                        (*count)++;
                        gotoxy(x, y);
                        cout << "  ";
                        y++;
                        gotoxy(x, y);
                        cout << "\033[46;30m[]\033[0m";;
                    }
                    break;
                default:

                    break;
                }
            }


        }
    }

}

void call_me(u_char* user, const struct pcap_pkthdr* pkthdr, const u_char* packetd_ptr) {
    string rawData = "";
    for (int i = 0; i < pkthdr->len; i++) {
        stringstream ss;
        ss << hex << setw(2) << setfill('0') << (int)packetd_ptr[i]; // Convertir cada byte en hexadecimal
        rawData += ss.str() + " ";
    }
    // cout << rawData << endl;
    raw.push_back(rawData);
    packetd_ptr += link_hdr_length;
    string result;
    vector<string> auxMAT;
    struct ip_header* ip_hdr = (struct ip_header*)packetd_ptr;
    struct tcp_header* tcp_header;
    struct udp_header* udp_header;
    struct icmp_header* icmp_header;
    int src_port, dst_port;
    char packet_srcip[INET_ADDRSTRLEN];
    char packet_dstip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip_hdr->ip_srcaddr, packet_srcip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &ip_hdr->ip_destaddr, packet_dstip, INET_ADDRSTRLEN);
    int packet_id = ntohs(ip_hdr->ip_id);
    int packet_ttl = ip_hdr->ip_ttl;
    int packet_tos = ip_hdr->ip_tos;
    int packet_len = ntohs(ip_hdr->ip_total_length);
    int packet_hlen = ip_hdr->ip_header_len;
    result = to_string(packet_id) + "|" + packet_srcip + "|" + packet_dstip + "|0x" + to_string(packet_tos) + "|" + to_string(packet_ttl);
    auxMAT.push_back("ID: " + to_string(packet_id));
    auxMAT.push_back("SRC: " + string(packet_srcip));
    auxMAT.push_back("DST: " + string(packet_dstip));
    auxMAT.push_back("TOS: 0x" + to_string(packet_tos));
    auxMAT.push_back("TTL: " + to_string(packet_ttl));
    packetd_ptr += (4 * packet_hlen);

    // Almacenar el contenido raw del paquete en hexadecimal


    int protocol_type = ip_hdr->ip_protocol;
    string aaa = "\033[47;30m" + result + "\033[0m";

    //TIPO DE PEOTOCOLO QUE SE CAPTURA-------------------------------------------------------------------------------------------
    switch (protocol_type) {
    case IPPROTO_TCP:
        tcp_header = (struct tcp_header*)packetd_ptr;
        src_port = tcp_header->tcp_src_port;
        dst_port = tcp_header->tcp_dst_port;
        result += "|TCP|" + string(1, (tcp_header->tcp_flags & TH_SYN ? 'S' : '-')) + "/" + string(1, (tcp_header->tcp_flags & TH_ACK ? 'A' : '-')) + "/" + string(1, (tcp_header->tcp_flags & TH_URG ? 'U' : '-')) + "|" + to_string(src_port) + "|" + to_string(dst_port);
        auxMAT.push_back("PROTO: TCP");
        auxMAT.push_back("FLAGS: " + string(1, (tcp_header->tcp_flags & TH_SYN ? 'S' : '-')) + "/" + string(1, (tcp_header->tcp_flags & TH_ACK ? 'A' : '-')) + "/" + string(1, (tcp_header->tcp_flags & TH_URG ? 'U' : '-')));
        auxMAT.push_back("P_SRC: " + to_string(src_port));
        auxMAT.push_back("P_DST: " + to_string(dst_port));
        aaa = "\033[41;30m" + result + "\033[0m";

        break;
    case IPPROTO_UDP:
        udp_header = (struct udp_header*)packetd_ptr;
        src_port = udp_header->udp_src_port;
        dst_port = udp_header->udp_dst_port;
        result += "|UDP|" + to_string(src_port) + "|" + to_string(dst_port);
        auxMAT.push_back("PROTO: UDP");
        auxMAT.push_back("P_SRC: " + to_string(src_port));
        auxMAT.push_back("P_DST: " + to_string(dst_port));
        aaa = "\033[42;30m" + result + "\033[0m";
        break;
    case IPPROTO_ICMP:
        icmp_header = (struct icmp_header*)packetd_ptr;
        int icmp_type = icmp_header->icmp_type;
        int icmp_type_code = icmp_header->icmp_code;
        result += "|ICMP|" + to_string(icmp_type) + "|" + to_string(icmp_type_code);
        auxMAT.push_back("PROTO: ICMP");
        auxMAT.push_back("TYPE: " + to_string(icmp_type));
        auxMAT.push_back("CODE: " + to_string(icmp_type_code));
        aaa = "\033[43;30m" + result + "\033[0m";
        break;
    }
    //---------------------------------------------------------------------------------------------------------------------------

    //filtro------------------------------------------------------------------------------------------
    if (!pause) {
        switch (filtro) {
        case 'a':packetList.push_back(aaa); matriz.push_back(auxMAT); break;
        case 'u':if (protocol_type == IPPROTO_UDP) {
            packetList.push_back(aaa);
            matriz.push_back(auxMAT);
        } break;
        case 't':if (protocol_type == IPPROTO_TCP) {
            packetList.push_back(aaa);
            matriz.push_back(auxMAT);
        }break;
        case 'i':if (protocol_type == IPPROTO_ICMP) {
            packetList.push_back(aaa);
            matriz.push_back(auxMAT);
        } break;
        case 'd': if (CadenaFiltro == packet_dstip) {
            packetList.push_back(aaa);
            matriz.push_back(auxMAT);
        }break;
        case 's': if (CadenaFiltro == packet_srcip) {
            packetList.push_back(aaa);
            matriz.push_back(auxMAT);
        }break;
        case 'S': if ((protocol_type == IPPROTO_UDP || protocol_type == IPPROTO_TCP) && CadenaFiltro == to_string(src_port)) {
            packetList.push_back(aaa);
            matriz.push_back(auxMAT);
        }break;
        case 'D': if ((protocol_type == IPPROTO_UDP || protocol_type == IPPROTO_TCP) && CadenaFiltro == to_string(dst_port)) {
            packetList.push_back(aaa);
            matriz.push_back(auxMAT);
        }break;
        }
    }

    //-------------------------------------------------------------------------------------------------

    if (packetList.size() > 1000) { // Limita el tamaño máximo
        packetList.erase(packetList.begin()); // Elimina el más antiguo
        matriz.erase(matriz.begin());
        raw.erase(raw.begin());
    }
    index = (int)packetList.size();
    index = max(0, index - 20);
    int ind = index;
    k = (int)packetList.size();
    if (!pause) {
        auxK = k;
        showPacketList(packetList, ind);
    }
}

void sniff() {
    int error = false;
    int prueba;
    WSADATA wsaData;
    const char* device = listar();
    char error_buffer[PCAP_ERRBUF_SIZE];

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        cerr << "Error al inicializar Winsock." << endl;
        exit(1);
    }

    capdev = pcap_open_live(device, BUFSIZ, 0, -1, error_buffer);


    
    
    if (capdev == NULL) {
        return;
    }

    int link_hdr_type = pcap_datalink(capdev);

    switch (link_hdr_type) {
    case DLT_NULL:
        link_hdr_length = 4;
        break;
    case DLT_EN10MB:
        link_hdr_length = 14;
        break;
    default:
        link_hdr_length = 0;
    }

    drawHeader();
    thread hilo(flechas2);
    if (pcap_loop(capdev, 0, call_me, nullptr) == -1) {
        cout << "ERR: pcap_loop() failed!" << endl;
        exit(1);
    }
    hilo.join();

}

void drawHeader() {
    string ren(120, 196);
    string bar(1, 179);
    string in(1, 194);
    system("cls");
    gotoxy(0, 0);
    cout << ren << endl;
    gotoxy(0, 2);
    cout << ren << endl;
    gotoxy(77, 2);
    cout << in;
    for (int i = 3; i < 30; i++) {
        gotoxy(77, i);
        cout << bar;
    }
    gotoxy(0, 24);
    cout << string(77, 196) << string(1, 180);
    gotoxy(0, 25);
    cout << "\033[100;90m" + string(77, 180) + "\n" + string(77, 180) + "\n" + string(77, 180) + "\n" + string(77, 180) + "\n" + string(77, 180) + "\033[0m";
    gotoxy(1, 26);
    cout << "\033[100;30mNAVEGAR EN EL MENU [<][>]\033[0m";
    gotoxy(30, 26);
    cout << "\033[100;30mSELECCIONAR PAQUETE [v][^]\033[0m";
    gotoxy(1, 28);
    cout << "\033[100;30mPAUSAR/CONTINUAR [_]\033[0m";
    gotoxy(30, 28);
    cout << "\033[100;30mSELECCIONAR [S]\033[0m";
    gotoxy(77, 13);
    cout << string(1, 195) + string(42, 196);

}

void gotoxy(int x, int y) {
    HANDLE hcon;
    hcon = GetStdHandle(STD_OUTPUT_HANDLE);
    COORD dwPos;
    dwPos.X = x;
    dwPos.Y = y;
    SetConsoleCursorPosition(hcon, dwPos);
}

void ocultarCursor() {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_CURSOR_INFO cursorInfo;

    GetConsoleCursorInfo(hConsole, &cursorInfo); // Obtener información actual del cursor
    cursorInfo.bVisible = false;                // Hacer que el cursor no sea visible
    SetConsoleCursorInfo(hConsole, &cursorInfo); // Establecer los cambios
}

void mostrarCursor() {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_CURSOR_INFO cursorInfo;

    GetConsoleCursorInfo(hConsole, &cursorInfo);
    cursorInfo.bVisible = true;                // Hacer visible el cursor
    SetConsoleCursorInfo(hConsole, &cursorInfo);
}

void flechas2() {
    int x = 0;
    int y = 23;
    int select = 0;
    vector<string> Menu1 = { "[REGRESAR]","[PROTOCOLO]","[IP]","[PUERTO]","[GUARDAR]" };
    vector<string> Menu1aux = { "\033[40;97m[REGRESAR]\033[0m","\033[40;97m[PROTOCOLO]\033[0m","\033[40;97m[IP]\033[0m","\033[40;97m[PUERTO]\033[0m","\033[40;97m[GUARDAR]\033[0m" };
    mostrarMenuFiltros(Menu1aux);
    while (bandera==1) {
        if (_kbhit()) { // Verifica si se presionó una tecla

            int key = _getch(); // Captura la tecla
            switch (key) {
            case 27: // Tecla ESC
                break;

            case 32: // Barra espaciadora
                if (pause) {
                    pause = false;
                    gotoxy(1, y);
                    cout << "  ";
                    y = 23;
                    select = 0;
                    Menu1aux = { "\033[40;97m[REGRESAR]\033[0m","\033[40;97m[PROTOCOLO]\033[0m","\033[40;97m[IP]\033[0m","\033[40;97m[PUERTO]\033[0m","\033[40;97m[GUARDAR]\033[0m" };
                    mostrarMenuFiltros(Menu1aux);
                }
                else {
                    pause = true;
                }
                break;
            case 's':
            case 'S': // Tecla T o t
                if (pause) {
                    switch (select) {
                    case 0:Salir(); break;
                    case 1:Protocolo(); break;
                    case 2:Ip(); break;
                    case 3:Port(); break;
                    case 4:guardarCSV(matriz); break;
                    default:break;
                    }
                    Menu1aux = { "\033[40;97m[REGRESAR]\033[0m","\033[40;97m[PROTOCOLO]\033[0m","\033[40;97m[IP]\033[0m","\033[40;97m[PUERTO]\033[0m","\033[40;97m[GUARDAR]\033[0m" };
                    mostrarMenuFiltros(Menu1aux);
                }
                break;
            case 'r':
                if (pause) {
                    showRawContent(raw[auxK]);
                }break;
            default:
                // Opción por defecto si no se presiona una tecla relevante
                break;
            }
            if (key == 224) { // Código especial para teclas extendidas (flechas)
                key = _getch(); // Captura el código de la flecha
                switch (key) {
                case 72: // Flecha arriba
                    if (pause) {
                        if ((y) > 3) {
                            gotoxy(1, y);
                            cout << "  ";
                            y--;
                            gotoxy(1, y);
                            cout << "[]";
                            auxK--;
                            showContent(matriz);
                            showRaw(raw[auxK]);
                            //showRawContent(raw[auxK]);
                        }
                    }
                    else {
                        pause = true;
                    }
                    break;
                case 80: // Flecha abajo
                    if (pause) {
                        if ((y) < 22) {
                            gotoxy(1, y);
                            cout << "  ";
                            y++;
                            gotoxy(1, y);
                            cout << "[]";
                            auxK++;
                            showContent(matriz);
                            showRaw(raw[auxK]);
                            // showRawContent(raw[auxK]);

                        }
                    }
                    else {
                        pause = true;
                    }
                    break;
                case 75: // Flecha izquierda
                    if (pause) {
                        if (select >= 0) {
                            string a = "\033[40;97m" + Menu1[select] + "\033[0m";
                            Menu1aux[select] = a;
                            if (select > 0) {
                                select--;
                            }

                            a = "\033[100;97m" + Menu1[select] + "\033[0m";
                            Menu1aux[select] = a;
                            mostrarMenuFiltros(Menu1aux);

                        }
                    }
                    else {
                        pause = true;
                    }
                    break;
                case 77: // Flecha derecha
                    if (pause) {
                        if (select < 4) {
                            string b = "\033[40;97m" + Menu1[select] + "\033[0m";
                            Menu1aux[select] = b;
                            select++;
                            b = "\033[100;97m" + Menu1[select] + "\033[0m";
                            Menu1aux[select] = b;
                            mostrarMenuFiltros(Menu1aux);
                        }

                    }
                    else {
                        pause = true;
                    }
                    break;
                default:

                    break;
                }
            }


        }
    }


}

void showPacketList(const vector<string>& packetList, int startIndex) {

    int count = 3; // Línea inicial
    int endIndex = min(startIndex + 20, (int)packetList.size());

    // Limpiar área de la lista
    for (int i = 3; i < 23; i++) {
        gotoxy(4, i);
        cout << string(70, ' '); // Borra la línea
    }

    // Mostrar paquetes
    for (int i = startIndex; i < endIndex; i++) {
        gotoxy(4, count); // Posiciona el cursor
        cout << packetList[i];
        //cout << packetList.size()<<endl;
        //cout << index;
        count++;

    }
}

void showContent(const vector<vector<string>>& packetList) {
    // Verificar que el índice actual k esté dentro del rango
    if (auxK < 0 || auxK >= (int)packetList.size()) {
        return; // No hacer nada si el índice está fuera de rango
    }

    // Limpiar área de los detalles
    for (int i = 4; i < 13; i++) {
        gotoxy(80, i);
        cout << string(23, ' '); // Borra la línea
    }

    // Mostrar detalles del paquete actual
    for (int i = 0; i < (int)packetList[auxK].size(); i++) {
        gotoxy(80, i + 4);
        cout << packetList[auxK][i];
    }
}

void showRawContent(const string& rawData) {
    std::string nombreArchivo = "archivo_generado.txt";
    string a = hexToASCII(rawData);
    // 1. Crear y escribir en el archivo
    std::ofstream archivo(nombreArchivo);
    if (archivo.is_open()) {
        for (int i = 0; i < rawData.size(); i++) {
            if (i % 48 == 0) {
                archivo << endl;
            }
            archivo << rawData[i];

        }
        archivo << endl;
        for (int i = 0; i < a.size(); i++) {
            if (i % 16 == 0) {
                archivo << endl;
            }
            archivo << a[i];
        }
        archivo.close();

    }

    else {
        std::cerr << "Error al crear el archivo.\n";
        return; // Termina el programa con error
    }
    system(("start " + nombreArchivo).c_str());
}
void showRaw(const string& rawData) {
    int count = 0;
    int auxI = 0;
    int p;
    for (int i = 14; i < 29; i++) {
        gotoxy(80, i);
        cout << string(36, ' '); // Borra la línea
    }


    if (rawData.size() > 460) {
        p = 440;
    }
    else {
        p = rawData.size();
    }
    for (int i = 0; i < p; i++) {
        if (i % 36 == 0) {
            count++;
            auxI = 0;
        }
        gotoxy(80 + auxI, 15 + count);
        cout << rawData[i];
        auxI++;
    }
    gotoxy(80, 15 + count);
    cout << "\033[40;97m[R] para ver RAW completo\033[0m";
}

void guardarCSV(const vector<vector<string>>& m) {
    string nombreArchivo = "matriz.csv";
    ofstream archivo(nombreArchivo);

    if (!archivo.is_open()) {
        cerr << "Error al abrir el archivo." << endl;
        return;
    }

    // Escribir la matriz en el archivo CSV
    for (const auto& fila : m) {
        for (size_t i = 0; i < fila.size(); ++i) {
            archivo << fila[i];
            if (i != fila.size() - 1) { // Separador entre columnas
                archivo << ",";
            }
        }
        archivo << "\n"; // Nueva fila
    }

    archivo.close();
}

string hexToASCII(const string& hexStr) {
    string asciiStr;
    stringstream ss(hexStr);
    string hexByte;
    unsigned int byteValue;

    while (ss >> setw(2) >> hexByte) { // Lee 2 caracteres hexadecimales a la vez
        stringstream hexStream;
        hexStream << hex << hexByte; // Convertir de hex a valor entero
        hexStream >> byteValue;

        // Verifica si el valor es imprimible o especial
        if (byteValue >= 32 && byteValue <= 126) {
            asciiStr += static_cast<char>(byteValue);
        }
        else {
            asciiStr += '.'; // Sustituye valores especiales por un punto
        }
    }

    return asciiStr;
}

void mostrarMenuFiltros(const vector<string>& m) {
    string blank(118, ' ');
    gotoxy(1, 1);
    cout << blank;
    int l = 0;
    //gotoxy(1, 1);
    //cout <<  m[0] ;
    //gotoxy(15, 1);
    //cout <<  m[1] ;
    //gotoxy(27, 1);
    //cout <<  m[2] ;
    //gotoxy(32, 1);
    //cout <<   m[3] ;
    //gotoxy(41, 1);
    //cout <<  m[4] ;
    for (int i = 0; i < m.size(); i++) {
        gotoxy(l, 1);
        cout << m[i];
        l += m[i].length() - 9;
    }
}

void Protocolo() {
    vector<string> Menu1 = { "[ALL]","[TCP]","[UDP]","[ICMP]" };
    vector<string> Menu1aux = { "\033[40;97m[ALL]\033[0m","\033[40;97m[TCP]\033[0m","\033[40;97m[UDP]\033[0m","\033[40;97m[ICMP]\033[0m" };
    mostrarMenuFiltros(Menu1aux);
    int select = 0;
    while (true) {
        if (_kbhit()) { // Verifica si se presionó una tecla
            int key = _getch(); // Captura la tecla
            switch (key) {
            case 's':
            case 'S': // Tecla T o t
                switch (select) {
                case 0:filtro = 'a'; return; break;
                case 1:filtro = 't'; return; break;
                case 2:filtro = 'u'; return; break;
                case 3:filtro = 'i'; return; break;
                default:break;
                }
                break;


            default:
                // Opción por defecto si no se presiona una tecla relevante
                break;
            }
            if (key == 224) { // Código especial para teclas extendidas (flechas)
                key = _getch(); // Captura el código de la flecha
                switch (key) {
                case 75: // Flecha izquierda
                    if (pause) {
                        if (select >= 0) {
                            string a = "\033[40;97m" + Menu1[select] + "\033[0m";
                            Menu1aux[select] = a;
                            if (select > 0) {
                                select--;
                            }
                            a = "\033[100;97m" + Menu1[select] + "\033[0m";
                            Menu1aux[select] = a;
                            mostrarMenuFiltros(Menu1aux);
                        }
                    }
                    else {
                        pause = true;
                    }
                    break;
                case 77: // Flecha derecha
                    if (pause) {
                        if (select < 3) {
                            string b = "\033[40;97m" + Menu1[select] + "\033[0m";
                            Menu1aux[select] = b;
                            select++;
                            b = "\033[100;97m" + Menu1[select] + "\033[0m";
                            Menu1aux[select] = b;
                            mostrarMenuFiltros(Menu1aux);
                        }

                    }
                    else {
                        pause = true;
                    }
                    break;
                default:

                    break;
                }
            }


        }
    }
}

void Ip() {
    string blank(118, ' ');
    vector<string> Menu1 = { "[ORIGEN]","[DESTINO]" };
    vector<string> Menu1aux = { "\033[40;97m[ORIGEN]\033[0m","\033[40;97m[DESTINO]\033[0m", };
    mostrarMenuFiltros(Menu1aux);
    int select = 0;
    while (true) {
        if (_kbhit()) { // Verifica si se presionó una tecla
            int key = _getch(); // Captura la tecla
            switch (key) {
            case 's':
            case 'S': // Tecla T o t
                switch (select) {
                case 0:
                    gotoxy(0, 1);
                    cout << blank;
                    gotoxy(1, 1);
                    cout << "ip:";
                    cin >> CadenaFiltro;
                    filtro = 's';
                    return;
                    break;
                case 1:
                    gotoxy(0, 1);
                    cout << blank;
                    gotoxy(1, 1);
                    cout << "ip:";
                    cin >> CadenaFiltro;
                    filtro = 'd';
                    return;
                    break;
                default:break;
                }
                break;


            default:
                // Opción por defecto si no se presiona una tecla relevante
                break;
            }
            if (key == 224) { // Código especial para teclas extendidas (flechas)
                key = _getch(); // Captura el código de la flecha
                switch (key) {
                case 75: // Flecha izquierda
                    if (pause) {
                        if (select >= 0) {
                            string a = "\033[40;97m" + Menu1[select] + "\033[0m";
                            Menu1aux[select] = a;
                            if (select > 0) {
                                select--;
                            }

                            a = "\033[100;97m" + Menu1[select] + "\033[0m";
                            Menu1aux[select] = a;
                            mostrarMenuFiltros(Menu1aux);
                        }
                    }
                    else {
                        pause = true;
                    }
                    break;
                case 77: // Flecha derecha
                    if (pause) {
                        if (select < 1) {
                            string b = "\033[40;97m" + Menu1[select] + "\033[0m";
                            Menu1aux[select] = b;
                            select++;
                            b = "\033[100;97m" + Menu1[select] + "\033[0m";
                            Menu1aux[select] = b;
                            mostrarMenuFiltros(Menu1aux);
                        }

                    }
                    else {
                        pause = true;
                    }
                    break;
                default:

                    break;
                }
            }


        }
    }
}

void Port() {
    string blank(118, ' ');
    vector<string> Menu1 = { "[ORIGEN]","[DESTINO]" };
    vector<string> Menu1aux = { "\033[40;97m[ORIGEN]\033[0m","\033[40;97m[DESTINO]\033[0m", };
    mostrarMenuFiltros(Menu1aux);
    int select = 0;
    while (true) {
        if (_kbhit()) { // Verifica si se presionó una tecla
            int key = _getch(); // Captura la tecla
            switch (key) {
            case 's':
            case 'S': // Tecla T o t
                switch (select) {
                case 0:
                    gotoxy(0, 1);
                    cout << blank;
                    gotoxy(1, 1);
                    cout << "puerto:";
                    cin >> CadenaFiltro;
                    filtro = 'S';
                    return;
                    break;
                case 1:
                    gotoxy(0, 1);
                    cout << blank;
                    gotoxy(1, 1);
                    cout << "puerto:";
                    cin >> CadenaFiltro;
                    filtro = 'D';
                    return;
                    break;
                default:break;
                }
                break;


            default:
                // Opción por defecto si no se presiona una tecla relevante
                break;
            }
            if (key == 224) { // Código especial para teclas extendidas (flechas)
                key = _getch(); // Captura el código de la flecha
                switch (key) {
                case 75: // Flecha izquierda
                    if (pause) {
                        if (select >= 0) {
                            string a = "\033[40;97m" + Menu1[select] + "\033[0m";
                            Menu1aux[select] = a;
                            if (select > 0) {
                                select--;
                            }
                            a = "\033[100;97m" + Menu1[select] + "\033[0m";
                            Menu1aux[select] = a;
                            mostrarMenuFiltros(Menu1aux);
                        }
                    }
                    else {
                        pause = true;
                    }
                    break;
                case 77: // Flecha derecha
                    if (pause) {
                        if (select < 1) {
                            string b = "\033[40;97m" + Menu1[select] + "\033[0m";
                            Menu1aux[select] = b;
                            select++;
                            b = "\033[100;97m" + Menu1[select] + "\033[0m";
                            Menu1aux[select] = b;
                            mostrarMenuFiltros(Menu1aux);
                        }

                    }
                    else {
                        pause = true;
                    }
                    break;
                default:

                    break;
                }
            }


        }
    }
}

void Salir() {
    string blank(118, ' ');
    vector<string> Menu1 = { "[REGRESAR INICIO]","[GUARDAR Y SALIR]","[CANCELAR]" };
    vector<string> Menu1aux = { "\033[40;97m[REGRESAR INICIO]\033[0m","\033[40;97m[GUARDAR Y SALIR]\033[0m","\033[40;97m[CANCELAR]\033[0m" };
    mostrarMenuFiltros(Menu1aux);
    int select = 0;
    while (true) {
        if (_kbhit()) { // Verifica si se presionó una tecla
            int key = _getch(); // Captura la tecla
            switch (key) {
            case 's':
            case 'S': // Tecla T o t
                switch (select) {
                case 0:
                    system("cls");
                    pcap_breakloop(capdev);
                    bandera = 0;
                    return;

                case 1:
                    guardarCSV(matriz);
                    system("cls");
                    exit(0);
                case 2:
                    return;
                default:break;
                }
                break;


            default:

                break;
            }
            if (key == 224) { // Código especial para teclas extendidas (flechas)
                key = _getch(); // Captura el código de la flecha
                switch (key) {
                case 75: // Flecha izquierda
                    if (pause) {
                        if (select >= 0) {
                            string a = "\033[40;97m" + Menu1[select] + "\033[0m";
                            Menu1aux[select] = a;
                            if (select > 0) {
                                select--;
                            }
                            a = "\033[100;97m" + Menu1[select] + "\033[0m";
                            Menu1aux[select] = a;
                            mostrarMenuFiltros(Menu1aux);
                        }
                    }
                    else {
                        pause = true;
                    }
                    break;
                case 77: // Flecha derecha
                    if (pause) {
                        if (select < 2) {
                            string b = "\033[40;97m" + Menu1[select] + "\033[0m";
                            Menu1aux[select] = b;
                            select++;
                            b = "\033[100;97m" + Menu1[select] + "\033[0m";
                            Menu1aux[select] = b;
                            mostrarMenuFiltros(Menu1aux);
                        }

                    }
                    else {
                        pause = true;
                    }
                    break;
                default:

                    break;
                }
            }


        }
    }
}