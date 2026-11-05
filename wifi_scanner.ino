/*
  CYBERSEC FIELD TOOL
  Wi-Fi Monitor / Passive Sniffer
  Hardware: ESP8266 NodeMCU
  IDE: Arduino IDE 2.x
  Baud rate: 115200

  Funcionalidades:
  - Captura passiva de quadros 802.11
  - Identificação de Management, Control e Data
  - Identificação de subtipos
  - RSSI e canal
  - BSSID quando disponível
  - Estatísticas de captura
  - Varredura de canais 1 a 13

  Não captura payload de aplicações, senhas ou credenciais.
*/

#include <Arduino.h>
#include <ESP8266WiFi.h>

extern "C" {
  #include <user_interface.h>
}

// ========================================
// CONFIGURAÇÕES
// ========================================

#define SERIAL_SPEED 115200

#define CHANNEL_HOPPING true
#define FIRST_CHANNEL 1
#define LAST_CHANNEL 13

#define CHANNEL_INTERVAL 350
#define STATS_INTERVAL 5000

#define QUEUE_SIZE 32

// ========================================
// ESTRUTURAS DO ESP8266 SDK
// ========================================

struct RxControl {
  signed rssi:8;
  unsigned rate:4;
  unsigned is_group:1;
  unsigned:1;
  unsigned sig_mode:2;
  unsigned legacy_length:12;
  unsigned damatch0:1;
  unsigned damatch1:1;
  unsigned bssidmatch0:1;
  unsigned bssidmatch1:1;
  unsigned MCS:7;
  unsigned CWB:1;
  unsigned HT_length:16;
  unsigned Smoothing:1;
  unsigned Not_Sounding:1;
  unsigned:1;
  unsigned Aggregation:1;
  unsigned STBC:2;
  unsigned FEC_CODING:1;
  unsigned SGI:1;
  unsigned rxend_state:8;
  unsigned ampdu_cnt:8;
  unsigned channel:4;
  unsigned:12;
};

struct LenSeq {
  uint16_t len;
  uint16_t seq;
  uint8_t addr3[6];
};

struct sniffer_buf {
  RxControl rx_ctrl;
  uint8_t buf[36];
  uint16_t cnt;
  LenSeq lenseq[1];
};

struct sniffer_buf2 {
  RxControl rx_ctrl;
  uint8_t buf[112];
  uint16_t cnt;
  uint16_t len;
};

// ========================================
// ESTRUTURA DE EVENTOS
// ========================================

struct PacketEvent {
  int8_t rssi;
  uint8_t channel;
  uint16_t length;
  uint8_t type;
  uint8_t subtype;
  uint8_t mac[6];
  bool hasMac;
};

// ========================================
// FILA DE EVENTOS
// ========================================

PacketEvent packetQueue[QUEUE_SIZE];

volatile uint8_t queueHead = 0;
volatile uint8_t queueTail = 0;

volatile uint32_t totalPackets = 0;
volatile uint32_t managementPackets = 0;
volatile uint32_t controlPackets = 0;
volatile uint32_t dataPackets = 0;
volatile uint32_t droppedPackets = 0;

// ========================================
// CONTROLE DE CANAL
// ========================================

uint8_t currentChannel = FIRST_CHANNEL;

unsigned long lastChannelChange = 0;
unsigned long lastStats = 0;

// ========================================
// NOMES DOS QUADROS
// ========================================

const char* getFrameType(uint8_t type) {
  switch (type) {
    case 0: return "MANAGEMENT";
    case 1: return "CONTROL";
    case 2: return "DATA";
    default: return "UNKNOWN";
  }
}

const char* getSubtype(uint8_t type, uint8_t subtype) {

  if (type == 0) {
    switch (subtype) {
      case 0: return "ASSOC_REQUEST";
      case 1: return "ASSOC_RESPONSE";
      case 2: return "REASSOC_REQUEST";
      case 3: return "REASSOC_RESPONSE";
      case 4: return "PROBE_REQUEST";
      case 5: return "PROBE_RESPONSE";
      case 8: return "BEACON";
      case 9: return "ATIM";
      case 10: return "DISASSOCIATION";
      case 11: return "AUTHENTICATION";
      case 12: return "DEAUTHENTICATION";
      case 13: return "ACTION";
      default: return "MGMT_OTHER";
    }
  }

  if (type == 1) {
    switch (subtype) {
      case 8: return "BLOCK_ACK_REQ";
      case 9: return "BLOCK_ACK";
      case 10: return "PS_POLL";
      case 11: return "RTS";
      case 12: return "CTS";
      case 13: return "ACK";
      case 14: return "CF_END";
      case 15: return "CF_END_ACK";
      default: return "CTRL_OTHER";
    }
  }

  if (type == 2) {
    switch (subtype) {
      case 0: return "DATA";
      case 4: return "NULL_DATA";
      case 8: return "QOS_DATA";
      case 12: return "QOS_NULL";
      default: return "DATA_OTHER";
    }
  }

  return "UNKNOWN";
}

// ========================================
// MAC ADDRESS
// ========================================

void formatMAC(const uint8_t* mac, char* output) {

  snprintf(
    output,
    18,
    "%02X:%02X:%02X:%02X:%02X:%02X",
    mac[0], mac[1], mac[2],
    mac[3], mac[4], mac[5]
  );
}

// ========================================
// ADICIONA EVENTO NA FILA
// ========================================

void enqueuePacket(const PacketEvent& event) {

  uint8_t next = (queueHead + 1) % QUEUE_SIZE;

  if (next == queueTail) {
    droppedPackets++;
    return;
  }

  packetQueue[queueHead] = event;
  queueHead = next;
}

// ========================================
// PROCESSAMENTO DO CABEÇALHO
// ========================================

void processFrame(
  const uint8_t* frame,
  uint16_t frameLength,
  int8_t rssi,
  uint8_t channel
) {

  if (frameLength < 2) return;

  uint8_t frameControl0 = frame[0];
  uint8_t frameControl1 = frame[1];

  uint8_t version = frameControl0 & 0x03;
  uint8_t type = (frameControl0 >> 2) & 0x03;
  uint8_t subtype = (frameControl0 >> 4) & 0x0F;

  if (version != 0 || type == 3) return;

  PacketEvent event = {};

  event.rssi = rssi;
  event.channel = channel;
  event.length = frameLength;
  event.type = type;
  event.subtype = subtype;
  event.hasMac = false;

  // Management: BSSID geralmente está no endereço 3.
  if (type == 0 && frameLength >= 24) {

    // Não expõe MAC de origem de Probe Requests.
    if (subtype != 4) {
      memcpy(event.mac, frame + 16, 6);
      event.hasMac = true;
    }
  }

  // Data: determina BSSID conforme ToDS / FromDS.
  if (type == 2 && frameLength >= 24) {

    bool toDS = frameControl1 & 0x01;
    bool fromDS = frameControl1 & 0x02;

    if (!toDS && !fromDS) {
      memcpy(event.mac, frame + 16, 6);
      event.hasMac = true;
    }
    else if (toDS && !fromDS) {
      memcpy(event.mac, frame + 4, 6);
      event.hasMac = true;
    }
    else if (!toDS && fromDS) {
      memcpy(event.mac, frame + 10, 6);
      event.hasMac = true;
    }
  }

  totalPackets++;

  if (type == 0) managementPackets++;
  if (type == 1) controlPackets++;
  if (type == 2) dataPackets++;

  enqueuePacket(event);
}

// ========================================
// CALLBACK DO SNIFFER
// ========================================

void ICACHE_FLASH_ATTR promiscuousCallback(
  uint8_t* buffer,
  uint16_t length
) {

  if (buffer == nullptr) return;

  // Somente metadados físicos, sem cabeçalho MAC disponível.
  if (length == sizeof(RxControl)) return;

  // Pacotes de Management.
  if (length == sizeof(sniffer_buf2)) {

    sniffer_buf2* packet =
      reinterpret_cast<sniffer_buf2*>(buffer);

    if (packet->len >= 2 && packet->len <= 112) {

      processFrame(
        packet->buf,
        packet->len,
        packet->rx_ctrl.rssi,
        packet->rx_ctrl.channel
      );
    }

    return;
  }

  // Pacotes de Data / outros quadros com buffer curto.
  if (length >= sizeof(sniffer_buf)) {

    sniffer_buf* packet =
      reinterpret_cast<sniffer_buf*>(buffer);

    if (packet->cnt == 0) return;

    uint16_t frameLength = packet->lenseq[0].len;

    if (frameLength > 36) frameLength = 36;

    processFrame(
      packet->buf,
      frameLength,
      packet->rx_ctrl.rssi,
      packet->rx_ctrl.channel
    );
  }
}

// ========================================
// IMPRESSÃO NO SERIAL
// ========================================

void printPacket(const PacketEvent& event) {

  char macString[18];

  if (event.hasMac) {
    formatMAC(event.mac, macString);
  } else {
    strcpy(macString, "--");
  }

  Serial.printf(
    "[CH %02u] RSSI: %4d dBm | %-10s | %-20s | LEN: %3u | %s\n",
    event.channel,
    event.rssi,
    getFrameType(event.type),
    getSubtype(event.type, event.subtype),
    event.length,
    macString
  );
}

// ========================================
// DRENAGEM DA FILA
// ========================================

void processQueue() {

  while (queueTail != queueHead) {

    PacketEvent event = packetQueue[queueTail];

    queueTail = (queueTail + 1) % QUEUE_SIZE;

    printPacket(event);
  }
}

// ========================================
// ESTATÍSTICAS
// ========================================

void printStatistics() {

  Serial.println();
  Serial.println("========== WI-FI MONITOR ==========");

  Serial.printf("Canal atual:       %u\n", currentChannel);
  Serial.printf("Total de quadros:  %lu\n", totalPackets);
  Serial.printf("Management:        %lu\n", managementPackets);
  Serial.printf("Control:           %lu\n", controlPackets);
  Serial.printf("Data:              %lu\n", dataPackets);
  Serial.printf("Eventos perdidos:  %lu\n", droppedPackets);

  Serial.println("===================================");
  Serial.println();
}

// ========================================
// TROCA DE CANAL
// ========================================

void changeChannel() {

  if (!CHANNEL_HOPPING) return;

  if (millis() - lastChannelChange < CHANNEL_INTERVAL) {
    return;
  }

  lastChannelChange = millis();

  // Desativa o sniffer antes de mudar o canal.
  wifi_promiscuous_enable(0);

  currentChannel++;

  if (currentChannel > LAST_CHANNEL) {
    currentChannel = FIRST_CHANNEL;
  }

  wifi_set_channel(currentChannel);

  wifi_promiscuous_enable(1);
}

// ========================================
// INICIALIZAÇÃO
// ========================================

void setup() {

  Serial.begin(SERIAL_SPEED);

  delay(500);

  Serial.println();
  Serial.println("==================================");
  Serial.println(" CYBERSEC FIELD TOOL");
  Serial.println(" WI-FI MONITOR / SNIFFER");
  Serial.println("==================================");

  // Modo Station obrigatório para o sniffer.
  wifi_set_opmode(STATION_MODE);

  // Desconecta qualquer associação Wi-Fi.
  wifi_station_disconnect();

  delay(100);

  currentChannel = FIRST_CHANNEL;

  wifi_set_channel(currentChannel);

  // Registra callback.
  wifi_set_promiscuous_rx_cb(promiscuousCallback);

  // Inicia captura passiva.
  wifi_promiscuous_enable(1);

  lastChannelChange = millis();
  lastStats = millis();

  Serial.println("[+] Monitor iniciado.");
  Serial.println("[+] Modo passivo.");
  Serial.println("[+] Captura de quadros 802.11 habilitada.");
  Serial.println("[+] Aguardando atividade Wi-Fi...");
  Serial.println();

  Serial.println(
    "CANAL | RSSI | TIPO | SUBTIPO | TAMANHO | BSSID"
  );
}

// ========================================
// LOOP PRINCIPAL
// ========================================

void loop() {

  processQueue();

  changeChannel();

  if (millis() - lastStats >= STATS_INTERVAL) {

    lastStats = millis();

    printStatistics();
  }

  yield();
}ESP82