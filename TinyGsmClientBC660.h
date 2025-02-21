/**
 * @file       TinyGsmClientBC660.h
 * @author     Volodymyr Shymanskyy and Aurelien BOUIN (SSL)
 * @license    LGPL-3.0
 * @copyright  Copyright (c) 2016 Volodymyr Shymanskyy
 * @date       Apr 2018, Aug 2023 (SSL)
 */

#ifndef SRC_TINYGSMCLIENTBC660_H_
#define SRC_TINYGSMCLIENTBC660_H_
// #pragma message("TinyGSM:  TinyGsmClientBC660")

// #define TINY_GSM_DEBUG Serial

#define TINY_GSM_MUX_COUNT 12
#define TINY_GSM_BUFFER_READ_AND_CHECK_SIZE
#ifdef AT_NL
#undef AT_NL
#endif
#define AT_NL "\r\n"

#ifdef MODEM_MANUFACTURER
#undef MODEM_MANUFACTURER
#endif
#define MODEM_MANUFACTURER "Quectel"

#ifdef MODEM_MODEL
#undef MODEM_MODEL
#endif
#if defined(TINY_GSM_MODEM_BC660) || defined(TINY_GSM_MODEM_BG660SSL)
#define MODEM_MODEL "BC660"
#else
#define MODEM_MODEL "BC660"
#endif

#include "TinyGsmModem.tpp"
#include "TinyGsmTCP.tpp"
#include "TinyGsmSSL.tpp"
#include "TinyGsmGPRS.tpp"
#include "TinyGsmCalling.tpp"
#include "TinyGsmSMS.tpp"
#include "TinyGsmGPS.tpp"
#include "TinyGsmTime.tpp"
#include "TinyGsmNTP.tpp"
#include "TinyGsmBattery.tpp"
#include "TinyGsmTemperature.tpp"

enum BC660RegStatus {
  REG_NO_RESULT    = -1,
  REG_UNREGISTERED = 0,
  REG_SEARCHING    = 2,
  REG_DENIED       = 3,
  REG_OK_HOME      = 1,
  REG_OK_ROAMING   = 5,
  REG_UNKNOWN      = 4,
};

class TinyGsmBC660 : public TinyGsmModem<TinyGsmBC660>,
                     public TinyGsmGPRS<TinyGsmBC660>,
                     public TinyGsmTCP<TinyGsmBC660, TINY_GSM_MUX_COUNT>,
                     public TinyGsmSSL<TinyGsmBC660, TINY_GSM_MUX_COUNT>,
                     public TinyGsmCalling<TinyGsmBC660>,
                     public TinyGsmSMS<TinyGsmBC660>,
                     public TinyGsmGPS<TinyGsmBC660>,
                     public TinyGsmTime<TinyGsmBC660>,
                     public TinyGsmNTP<TinyGsmBC660>,
                     public TinyGsmBattery<TinyGsmBC660>,
                     public TinyGsmTemperature<TinyGsmBC660> {
  friend class TinyGsmModem<TinyGsmBC660>;
  friend class TinyGsmGPRS<TinyGsmBC660>;
  friend class TinyGsmTCP<TinyGsmBC660, TINY_GSM_MUX_COUNT>;
  friend class TinyGsmSSL<TinyGsmBC660, TINY_GSM_MUX_COUNT>;
  friend class TinyGsmCalling<TinyGsmBC660>;
  friend class TinyGsmSMS<TinyGsmBC660>;
  friend class TinyGsmGPS<TinyGsmBC660>;
  friend class TinyGsmTime<TinyGsmBC660>;
  friend class TinyGsmNTP<TinyGsmBC660>;
  friend class TinyGsmBattery<TinyGsmBC660>;
  friend class TinyGsmTemperature<TinyGsmBC660>;

  /*
   * Inner Client
   */
 public:
  class GsmClientBC660 : public GsmClient {
    friend class TinyGsmBC660;
    size_t data_size;

   public:
    GsmClientBC660() {}

    explicit GsmClientBC660(TinyGsmBC660& modem, uint8_t mux = 0) {
      ssl_sock = false;
      init(&modem, mux);
    }

    bool init(TinyGsmBC660* modem, uint8_t mux = 0) {
      this->at       = modem;
      sock_available = 0;
      prev_check     = 0;
      sock_connected = false;
      got_data       = false;
      data_size      = 0;

      if (mux < TINY_GSM_MUX_COUNT) {
        this->mux = mux;
      } else {
        this->mux = (mux % TINY_GSM_MUX_COUNT);
      }
      at->sockets[this->mux] = this;

      return true;
    }

    virtual int connect(const char* host, uint16_t port, int timeout_s) {
      stop();
      TINY_GSM_YIELD();
      rx.clear();
      sock_connected = at->modemConnect(host, port, mux, timeout_s);
      return sock_connected;
    }
    TINY_GSM_CLIENT_CONNECT_OVERRIDES

    virtual void stop(uint32_t maxWaitMs) {
      uint32_t startMillis = millis();
      dumpModemBuffer(maxWaitMs);
      at->sendAT(GF("+QICLOSE="), mux);
      at->waitResponse((maxWaitMs - (millis() - startMillis)), GF("CLOSE OK"));
      sock_connected = false;
    }
    void stop() override {
      stop(15000L);
    }

    /*
     * Extended API
     */

    String remoteIP() TINY_GSM_ATTR_NOT_IMPLEMENTED;

   protected:
    bool ssl_sock;
  };

  /*
   * Inner Secure Client
   */
 public:
  class GsmClientSecureBC660 : public GsmClientBC660 {
   public:
    GsmClientSecureBC660() {}

    explicit GsmClientSecureBC660(TinyGsmBC660& modem, uint8_t mux = 0)
        : GsmClientBC660(modem, mux) {
      ssl_sock = true;
    }

    bool setCertificate(const String& certificateName) {
      return at->setCertificate(certificateName, mux);
    }

    void stop(uint32_t maxWaitMs) override {
      uint32_t startMillis = millis();
      dumpModemBuffer(maxWaitMs);
      at->sendAT(GF("+QSSLCLOSE="), mux);
      sock_connected = false;
      at->waitResponse((maxWaitMs - (millis() - startMillis)));
    }
    void stop() override {
      stop(15000L);
    }
  };

  /*
   * Constructor
   */
 public:
  explicit TinyGsmBC660(Stream& stream) : stream(stream) {
    memset(sockets, 0, sizeof(sockets));
  }

  /*
   * Basic functions
   */
 protected:
  bool initImpl(const char* pin = nullptr) {
    DBG(GF("### TinyGSM Version:"), TINYGSM_VERSION);
    DBG(GF("### TinyGSM Compiled Module:  TinyGsmClientBC660"));

    if (!testAT()) { return false; }

    sendAT(GF("E0"));  // Echo Off
    if (waitResponse() != 1) { return false; }

#ifdef TINY_GSM_DEBUG
    sendAT(GF("+CMEE=2"));  // turn on verbose error codes
#else
    sendAT(GF("+CMEE=0"));  // turn off error codes
#endif
    waitResponse();

    DBG(GF("### Modem:"), getModemName());

    // Disable time and time zone URC's
    sendAT(GF("+CTZR=0"));
    if (waitResponse(10000L) != 1) { return false; }

    // Enable automatic time zone update
    sendAT(GF("+CTZU=1"));
    if (waitResponse(10000L) != 1) { return false; }

    // Enable length on URCs
    sendAT(GF("+QICFG=\"showlength\",1"));
    if (waitResponse(10000L) != 1) { return false; }
    SimStatus ret = getSimStatus();
    // if the sim isn't ready and a pin has been provided, try to unlock the sim
    if (ret != SIM_READY && pin != nullptr && strlen(pin) > 0) {
      simUnlock(pin);
      return (getSimStatus() == SIM_READY);
    } else {
      // if the sim is ready, or it's locked but no pin has been provided,
      // return true
      return (ret == SIM_READY || ret == SIM_LOCKED);
    }
  }

  /*
   * Power functions
   */
 protected:
  bool restartImpl(const char* pin = nullptr) {
    if (!testAT()) { return false; }
    if (!setPhoneFunctionality(1, true)) { return false; }
    waitResponse(10000L, GF("APP RDY"));
    return init(pin);
  }

  bool powerOffImpl() {
    sendAT(GF("+QPOWD=1"));
    waitResponse(300);  // returns OK first
    return waitResponse(300, GF("POWERED DOWN")) == 1;
  }

  // When entering into sleep mode is enabled, DTR is pulled up, and WAKEUP_IN
  // is pulled up, the module can directly enter into sleep mode.If entering
  // into sleep mode is enabled, DTR is pulled down, and WAKEUP_IN is pulled
  // down, there is a need to pull the DTR pin and the WAKEUP_IN pin up first,
  // and then the module can enter into sleep mode.
  bool sleepEnableImpl(bool enable = true) {
    sendAT(GF("+QSCLK="), enable);
    return waitResponse() == 1;
  }

  bool setPhoneFunctionalityImpl(uint8_t fun, bool reset = false,
                                 uint32_t timeout_ms = 15500L) {
    sendAT(GF("+CFUN="), fun, reset ? ",1" : "");
    return waitResponse(timeout_ms, GF("OK")) == 1;
  }

  /*
   * Generic network functions
   */
 public:
  BC660RegStatus getRegistrationStatus() {
    // Check first for EPS registration
    BC660RegStatus epsStatus =
        (BC660RegStatus)getRegistrationStatusXREG("CEREG");

    // If we're connected on EPS, great!
    if (epsStatus == REG_OK_HOME || epsStatus == REG_OK_ROAMING) {
      return epsStatus;
    } else {
      // Otherwise, check generic network status
      return (BC660RegStatus)getRegistrationStatusXREG("CREG");
    }
  }

 protected:
  bool isNetworkConnectedImpl() {
    BC660RegStatus s = getRegistrationStatus();
    return (s == REG_OK_HOME || s == REG_OK_ROAMING);
  }

  /*
   * Secure socket layer (SSL) functions
   */
  // Follows functions as inherited from TinyGsmSSL.tpp

  /*
   * WiFi functions
   */
  // No functions of this type supported

  /*
   * GPRS functions
   */
 protected:
  bool gprsConnectImpl(const char* apn, const char* user = nullptr,
                       const char* pwd = "") {
    gprsDisconnect();

    if (waitResponse() != 1) { return false; }
    // Not sure what would happen if the password is empty, documentation is
    // unclear, best to pass it as empty string?
    char command[100];
    if (user && *user) {
      snprintf(command, sizeof(command),
               "+QCGDEFCONT=\"IP\",\"%s\",\"%s\",\"%s\",1", apn, user, pwd);
    } else {
      snprintf(command, sizeof(command), "+QCGDEFCONT=\"IP\",\"%s\"", apn);
    }
    sendAT(command);
    if (waitResponse() != 1) { return false; }

    sendAT(GF("+QCGDEFCONT?"));
    if (waitResponse() != 1) {
      // Set the APN
      sendAT(GF("+QCGDEFCONT=\"IP\",\""), apn, GF("\""));
      if (waitResponse() != 1) { return false; }
    }

    sendAT(GF("+CGACT=?"));
    if (waitResponse() != 1) {
      // Activate GPRS/CSD Context
      sendAT(GF("+CGACT=1, 1"));
      if (waitResponse(150000L) != 1) { return false; }
    }

    // Attach to Packet Domain service - is this necessary?
    sendAT(GF("+CGATT?"));
    if (waitResponse() != 1) {
      sendAT(GF("+CGATT=1"));
      if (waitResponse(60000L) != 1) { return false; }
    }

    return true;
  }

  bool gprsDisconnectImpl() {
    sendAT(GF("+QIDEACT=1"));  // Deactivate the bearer context
    if (waitResponse(40000L) != 1) { return false; }

    return true;
  }

  String getProviderImpl() {
    sendAT(GF("+QSPN?"));
    if (waitResponse(GF("+QSPN:")) != 1) { return ""; }
    streamSkipUntil('"');                      // Skip mode and format
    String res = stream.readStringUntil('"');  // read the provider
    waitResponse();                            // skip anything else
    return res;
  }

  /*
   * SIM card functions
   */
 protected:
  String getSimCCIDImpl() {
    sendAT(GF("+QCCID"));
    if (waitResponse(GF(AT_NL "+QCCID:")) != 1) { return ""; }
    String res = stream.readStringUntil('\n');
    waitResponse();
    res.trim();
    return res;
  }

  /*
   * Phone Call functions
   */
  // Follows all phone call functions as inherited from TinyGsmCalling.tpp

  /*
   * Audio functions
   */
  // No functions of this type supported

  /*
   * Text messaging (SMS) functions
   */
  // Follows all text messaging (SMS) functions as inherited from TinyGsmSMS.tpp

  /*
   * GSM Location functions
   */
 protected:
  // NOTE:  As of application firmware version 01.016.01.016 triangulated
  // locations can be obtained via the QuecLocator service and accompanying AT
  // commands.  As this is a separate paid service which I do not have access
  // to, I am not implementing it here.

  /*
   * GPS/GNSS/GLONASS location functions
   */
 protected:
  // enable GPS
  bool enableGPSImpl() {
    sendAT(GF("+QGPS=1"));
    if (waitResponse() != 1) { return false; }
    return true;
  }

  bool disableGPSImpl() {
    sendAT(GF("+QGPSEND"));
    if (waitResponse() != 1) { return false; }
    return true;
  }

  // get the RAW GPS output
  String getGPSrawImpl() {
    sendAT(GF("+QGPSLOC=2"));
    if (waitResponse(10000L, GF(AT_NL "+QGPSLOC: ")) != 1) { return ""; }
    String res = stream.readStringUntil('\n');
    waitResponse();
    res.trim();
    return res;
  }

  // get GPS informations
  bool getGPSImpl(float* lat, float* lon, float* speed = 0, float* alt = 0,
                  int* vsat = 0, int* usat = 0, float* accuracy = 0,
                  int* year = 0, int* month = 0, int* day = 0, int* hour = 0,
                  int* minute = 0, int* second = 0) {
    sendAT(GF("+QGPSLOC=2"));
    if (waitResponse(10000L, GF(AT_NL "+QGPSLOC: ")) != 1) {
      // NOTE:  Will return an error if the position isn't fixed
      return false;
    }

    // init variables
    float ilat         = 0;
    float ilon         = 0;
    float ispeed       = 0;
    float ialt         = 0;
    int   iusat        = 0;
    float iaccuracy    = 0;
    int   iyear        = 0;
    int   imonth       = 0;
    int   iday         = 0;
    int   ihour        = 0;
    int   imin         = 0;
    float secondWithSS = 0;

    // UTC date & Time
    ihour        = streamGetIntLength(2);      // Two digit hour
    imin         = streamGetIntLength(2);      // Two digit minute
    secondWithSS = streamGetFloatBefore(',');  // 6 digit second with subseconds

    ilat      = streamGetFloatBefore(',');  // Latitude
    ilon      = streamGetFloatBefore(',');  // Longitude
    iaccuracy = streamGetFloatBefore(',');  // Horizontal precision
    ialt      = streamGetFloatBefore(',');  // Altitude from sea level
    streamSkipUntil(',');                   // GNSS positioning mode
    streamSkipUntil(',');  // Course Over Ground based on true north
    streamSkipUntil(',');  // Speed Over Ground in Km/h
    ispeed = streamGetFloatBefore(',');  // Speed Over Ground in knots

    iday   = streamGetIntLength(2);    // Two digit day
    imonth = streamGetIntLength(2);    // Two digit month
    iyear  = streamGetIntBefore(',');  // Two digit year

    iusat = streamGetIntBefore(',');  // Number of satellites,
    streamSkipUntil('\n');  // The error code of the operation. If it is not
                            // 0, it is the type of error.

    // Set pointers
    if (lat != nullptr) *lat = ilat;
    if (lon != nullptr) *lon = ilon;
    if (speed != nullptr) *speed = ispeed;
    if (alt != nullptr) *alt = ialt;
    if (vsat != nullptr) *vsat = 0;
    if (usat != nullptr) *usat = iusat;
    if (accuracy != nullptr) *accuracy = iaccuracy;
    if (iyear < 2000) iyear += 2000;
    if (year != nullptr) *year = iyear;
    if (month != nullptr) *month = imonth;
    if (day != nullptr) *day = iday;
    if (hour != nullptr) *hour = ihour;
    if (minute != nullptr) *minute = imin;
    if (second != nullptr) *second = static_cast<int>(secondWithSS);

    waitResponse();  // Final OK
    return true;
  }

  /*
   * Time functions
   */
 protected:
  String getGSMDateTimeImpl(TinyGSMDateTimeFormat format) {
    sendAT(GF("+QLTS=2"));
    if (waitResponse(2000L, GF("+QLTS: \"")) != 1) { return ""; }

    String res;

    switch (format) {
      case DATE_FULL: res = stream.readStringUntil('"'); break;
      case DATE_TIME:
        streamSkipUntil(',');
        res = stream.readStringUntil('"');
        break;
      case DATE_DATE: res = stream.readStringUntil(','); break;
    }
    waitResponse();  // Ends with OK
    return res;
  }

  // The BC660 returns UTC time instead of local time as other modules do in
  // response to CCLK, so we're using QLTS where we can specifically request
  // local time.
  bool getNetworkUTCTimeImpl(int* year, int* month, int* day, int* hour,
                             int* minute, int* second, float* timezone) {
    sendAT(GF("+QLTS=1"));
    if (waitResponse(2000L, GF("+QLTS: \"")) != 1) { return false; }

    int iyear     = 0;
    int imonth    = 0;
    int iday      = 0;
    int ihour     = 0;
    int imin      = 0;
    int isec      = 0;
    int itimezone = 0;

    // Date & Time
    iyear       = streamGetIntBefore('/');
    imonth      = streamGetIntBefore('/');
    iday        = streamGetIntBefore(',');
    ihour       = streamGetIntBefore(':');
    imin        = streamGetIntBefore(':');
    isec        = streamGetIntLength(2);
    char tzSign = stream.read();
    itimezone   = streamGetIntBefore(',');
    if (tzSign == '-') { itimezone = itimezone * -1; }
    streamSkipUntil('\n');  // DST flag

    // Set pointers
    if (iyear < 2000) iyear += 2000;
    if (year != nullptr) *year = iyear;
    if (month != nullptr) *month = imonth;
    if (day != nullptr) *day = iday;
    if (hour != nullptr) *hour = ihour;
    if (minute != nullptr) *minute = imin;
    if (second != nullptr) *second = isec;
    if (timezone != nullptr) *timezone = static_cast<float>(itimezone) / 4.0;

    // Final OK
    waitResponse();  // Ends with OK
    return true;
  }

  // The BC660 returns UTC time instead of local time as other modules do in
  // response to CCLK, so we're using QLTS where we can specifically request
  // local time.
  bool getNetworkTimeImpl(int* year, int* month, int* day, int* hour,
                          int* minute, int* second, float* timezone) {
    sendAT(GF("+QLTS=2"));
    if (waitResponse(2000L, GF("+QLTS: \"")) != 1) { return false; }

    int iyear     = 0;
    int imonth    = 0;
    int iday      = 0;
    int ihour     = 0;
    int imin      = 0;
    int isec      = 0;
    int itimezone = 0;

    // Date & Time
    iyear       = streamGetIntBefore('/');
    imonth      = streamGetIntBefore('/');
    iday        = streamGetIntBefore(',');
    ihour       = streamGetIntBefore(':');
    imin        = streamGetIntBefore(':');
    isec        = streamGetIntLength(2);
    char tzSign = stream.read();
    itimezone   = streamGetIntBefore(',');
    if (tzSign == '-') { itimezone = itimezone * -1; }
    streamSkipUntil('\n');  // DST flag

    // Set pointers
    if (iyear < 2000) iyear += 2000;
    if (year != nullptr) *year = iyear;
    if (month != nullptr) *month = imonth;
    if (day != nullptr) *day = iday;
    if (hour != nullptr) *hour = ihour;
    if (minute != nullptr) *minute = imin;
    if (second != nullptr) *second = isec;
    if (timezone != nullptr) *timezone = static_cast<float>(itimezone) / 4.0;

    // Final OK
    waitResponse();  // Ends with OK
    return true;
  }

  /*
   * NTP server functions
   */

  byte NTPServerSyncImpl(String server = "pool.ntp.org", byte = -5) {
    // Request network synchronization
    // AT+QNTP=<contextID>,<server>[,<port>][,<autosettime>]
    sendAT(GF("+QNTP=1,\""), server, '"');
    if (waitResponse(10000L, GF("+QNTP:"))) {
      String result = stream.readStringUntil(',');
      streamSkipUntil('\n');
      result.trim();
      if (TinyGsmIsValidNumber(result)) { return result.toInt(); }
    } else {
      return -1;
    }
    return -1;
  }

  String ShowNTPErrorImpl(byte error) TINY_GSM_ATTR_NOT_IMPLEMENTED;

  /*
   * BLE functions
   */
  // No functions of this type supported

  /*
   * Battery functions
   */
  // Follows all battery functions as inherited from TinyGsmBattery.tpp

  /*
   * Temperature functions
   */
 protected:
  // get temperature in degree celsius
  uint16_t getTemperatureImpl() {
    sendAT(GF("+QTEMP"));
    if (waitResponse(GF(AT_NL "+QTEMP:")) != 1) { return 0; }
    // return temperature in C
    uint16_t res =
        streamGetIntBefore(',');  // read PMIC (primary ic) temperature
    streamSkipUntil(',');         // skip XO temperature ??
    streamSkipUntil('\n');        // skip PA temperature ??
    // Wait for final OK
    waitResponse();
    return res;
  }

  /*
   * Client related functions
   */
 protected:
  bool modemConnect(const char* host, uint16_t port, uint8_t mux,
                    int timeout_s = 150) {
    uint32_t timeout_ms = ((uint32_t)timeout_s) * 1000;
    bool     ssl        = sockets[mux]->ssl_sock;

    if (ssl) {
      // set the ssl version
      // AT+QSSLCFG="sslversion",<ctxindex>,<sslversion>
      // <ctxindex> PDP context identifier
      // <sslversion> 0: QAPI_NET_SSL_3.0
      //              1: QAPI_NET_SSL_PROTOCOL_TLS_1_0
      //              2: QAPI_NET_SSL_PROTOCOL_TLS_1_1
      //              3: QAPI_NET_SSL_PROTOCOL_TLS_1_2
      //              4: ALL
      // NOTE:  despite docs using caps, "sslversion" must be in lower case
      sendAT(GF("+QSSLCFG=\"sslversion\",0,3"));  // TLS 1.2
      if (waitResponse(5000L) != 1) return false;
      // set the ssl cipher_suite
      // AT+QSSLCFG="ciphersuite",<ctxindex>,<cipher_suite>
      // <ctxindex> PDP context identifier
      // <cipher_suite> 0: TODO
      //              1: TODO
      //              0X0035: TLS_RSA_WITH_AES_256_CBC_SHA
      //              0XFFFF: ALL
      // NOTE:  despite docs using caps, "sslversion" must be in lower case
      sendAT(GF(
          "+QSSLCFG=\"ciphersuite\",0,0X0035"));  // TLS_RSA_WITH_AES_256_CBC_SHA
      if (waitResponse(5000L) != 1) return false;
      // set the ssl sec level
      // AT+QSSLCFG="seclevel",<ctxindex>,<sec_level>
      // <ctxindex> PDP context identifier
      // <sec_level> 0: TODO
      //              1: TODO
      //              0X0035: TLS_RSA_WITH_AES_256_CBC_SHA
      //              0XFFFF: ALL
      // NOTE:  despite docs using caps, "sslversion" must be in lower case
      sendAT(GF("+QSSLCFG=\"seclevel\",0,1"));
      if (waitResponse(5000L) != 1) return false;


      if (certificates[mux] != "") {
        // apply the correct certificate to the connection
        // AT+QSSLCFG="cacert",<ctxindex>,<caname>
        // <ctxindex> PDP context identifier
        // <certname> certificate name

        // sendAT(GF("+CASSLCFG="), mux, ",CACERT,\"",
        // certificates[mux].c_str(),
        //        "\"");
        sendAT(GF("+QSSLCFG=\"cacert\",0,\""), certificates[mux].c_str(),
               GF("\""));
        if (waitResponse(5000L) != 1) return false;
      }

      // <PDPcontextID>(1-16), <connectID>(0-11),
      // "TCP/UDP/TCP LISTENER/UDPSERVICE", "<IP_address>/<domain_name>",
      // <remote_port>,<local_port>,<access_mode>(0-2; 0=buffer)
      // may need previous AT+QSSLCFG
      sendAT(GF("+QSSLOPEN=1,1,"), mux, GF(",\""), host, GF("\","), port,
             GF(",0"));
      waitResponse();

      if (waitResponse(timeout_ms, GF(AT_NL "+QSSLOPEN:")) != 1) {
        return false;
      }
      // 20230629 -> +QSSLOPEN: <clientID>,<err>
      // clientID is mux
      // err must be 0
      if (streamGetIntBefore(',') != mux) { return false; }
      // Read status
      return (0 == streamGetIntBefore('\n'));
    } else {
      // AT+QIOPEN=0,0,"TCP","220.180.239.212",8062,0,1
      // <PDPcontextID>(1-16), <connectID>(0-11),
      // "TCP/UDP/TCP LISTENER/UDPSERVICE", "<IP_address>/<domain_name>",
      // <remote_port>,<local_port>,<access_mode>(0-2; 0=buffer)
      sendAT(GF("+QIOPEN=0,"), mux, GF(",\""), GF("TCP"), GF("\",\""), host,
             GF("\","), port, GF(",0,0"));
      waitResponse();

      if (waitResponse(timeout_ms, GF(AT_NL "+QIOPEN:")) != 1) { return false; }

      if (streamGetIntBefore(',') != mux) { return false; }
    }
    // Read status
    return (0 == streamGetIntBefore('\n'));
  }

  int16_t modemSend(const void* buff, size_t len, uint8_t mux) {
    bool ssl = sockets[mux]->ssl_sock;
    if (ssl) {
      sendAT(GF("+QSSLSEND="), mux, ',', (uint16_t)len);
    } else {
      sendAT(GF("+QISEND="), mux, ',', (uint16_t)len);
    }
    if (waitResponse(GF(">")) != 1) {
      // sockets[mux]->data_size      = 0;
      // sockets[mux]->sock_connected = false;
      return 0;
    }
    stream.write(reinterpret_cast<const uint8_t*>(buff), len);
    stream.flush();
    if (waitResponse(GF(AT_NL "SEND OK")) != 1) {
      // sockets[mux]->data_size      = 0;
      // sockets[mux]->sock_connected = false;
      return 0;
    }
    // TODO(?): Wait for ACK? (AT+QISEND=id,0 or AT+QSSLSEND=id,0)
    return len;
  }

  size_t modemRead(size_t size, uint8_t mux) {
    if (!sockets[mux]) return 0;
    bool ssl = sockets[mux]->ssl_sock;
    if (ssl) {
      sendAT(GF("+QSSLRECV="), mux, ',', (uint16_t)size);
      if (waitResponse(GF("+QSSLRECV:")) != 1) {
        DBG("### READ: For unknown reason close");
        return 0;
      }
    } else {
      sendAT(GF("+QIRD="), mux, ',', (uint16_t)size);
      if (waitResponse(GF("+QIRD:")) != 1) {
        // sockets[mux]->data_size      = 0;
        // sockets[mux]->sock_connected = false;
        return 0;
      }
    }
    size_t len = streamGetIntBefore(',');
    streamSkipUntil('"');

    for (int i = 0; i < len; i++) { moveCharFromStreamToFifo(mux); }
    waitResponse();
    sockets[mux]->data_size = sockets[mux]->data_size - len;
    DBG("### READ:", len, "from", mux, size);
    sockets[mux]->sock_available = modemGetAvailable(mux);
    return len;
  }

  size_t modemGetAvailable(uint8_t mux) {
    if (!sockets[mux]) return 0;
    bool   ssl    = sockets[mux]->ssl_sock;
    size_t result = 0;
    if (ssl) {
      sendAT(GF("+QSSLRECV="), mux, GF(",0"));
      if (waitResponse(GF("+QSSLRECV:")) == 1) {
        streamSkipUntil(',');  // Skip total received
        streamSkipUntil(',');  // Skip have read
        result = streamGetIntBefore('\n');
        if (result) { DBG("### DATA AVAILABLE:", result, "on", mux); }
        waitResponse();
      }
    } else {
      if (!sockets[mux]->sock_connected) sockets[mux]->data_size = 0;
      if (sockets[mux]->data_size > 0) {
        result = sockets[mux]->data_size;
        if (result) { DBG("### DATA AVAILABLE:", result, "on", mux, sockets[mux]->sock_connected); }
      }
    }
    if (!result) { sockets[mux]->sock_connected = modemGetConnected(mux); }
    return result;
  }

  bool modemGetConnected(uint8_t mux) {
    bool ssl = sockets[mux]->ssl_sock;
    if (ssl) {
      sendAT(GF("+QSSLSTATE=1,"), mux);
      // +QSSLSTATE: 0,"TCP","151.139.237.11",80,5087,4,1,0,0,"uart1"

      if (waitResponse(GF("+QSSLSTATE:")) != 1) { return false; }

      streamSkipUntil(',');                  // Skip clientID
      streamSkipUntil(',');                  // Skip "SSLClient"
      streamSkipUntil(',');                  // Skip remote ip
      streamSkipUntil(',');                  // Skip remote port
      streamSkipUntil(',');                  // Skip local port
      int8_t res = streamGetIntBefore(',');  // socket state

      waitResponse();

      // 0 Initial, 1 Opening, 2 Connected, 3 Listening, 4 Closing
      return 2 == res;
    } else {
      sendAT(GF("+QISTATE=1,"), mux);
      // +QISTATE: 0,"TCP","220.180.239.212",8062,0,2,0,1

      if (waitResponse(GF("OK"), GF("+QISTATE:"), GF("ERROR")) != 2) {
        return false;
      }

      streamSkipUntil(',');                  // Skip mux
      streamSkipUntil(',');                  // Skip socket type
      streamSkipUntil(',');                  // Skip remote ip
      streamSkipUntil(',');                  // Skip remote port
      streamSkipUntil(',');                  // Skip local port
      int8_t res = streamGetIntBefore(',');  // socket state

      waitResponse();
      DBG("### CLIENT STATUS", res);

      // 0 Initial, 1 Opening, 2 Connected, 3 Listening, 4 Closing
      return 2 == res;
    }
  }

  /*
   * Utilities
   */
 public:
  bool handleURCs(String& data) {
    if (data.endsWith(GF(AT_NL "+QIURC:"))) {
      streamSkipUntil('\"');
      String urc = stream.readStringUntil('\"');
      streamSkipUntil(',');
      if (urc == "recv") {
        int8_t mux = streamGetIntBefore(',');
        size_t len = streamGetIntBefore('\n');
        // Handles 'buff full'
        if (len > 1340) len = 1340;
        DBG("### URC RECV:", mux, len);
        if (mux >= 0 && mux < TINY_GSM_MUX_COUNT && sockets[mux]) {
          sockets[mux]->sock_connected = true;
          sockets[mux]->got_data       = true;
          sockets[mux]->data_size      = len;
        }
      } else if (urc == "closed") {
        int8_t mux = streamGetIntBefore('\n');
        DBG("### URC CLOSE:", mux);
        if (mux >= 0 && mux < TINY_GSM_MUX_COUNT && sockets[mux]) {
          sockets[mux]->sock_connected = false;
        }
      } else {
        Serial.println(data);
        streamSkipUntil('\n');
      }
      data = "";
      return true;
    }
    return false;
  }

 public:
  Stream& stream;

 protected:
  GsmClientBC660* sockets[TINY_GSM_MUX_COUNT];
  String          certificates[TINY_GSM_MUX_COUNT];
};

#endif  // SRC_TINYGSMCLIENTBC660_H_
