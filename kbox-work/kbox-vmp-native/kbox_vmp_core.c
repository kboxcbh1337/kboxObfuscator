/* KBox native-shell M1: encrypted function-body strings. */
static const unsigned char _ksK[16] = {0x27,0x0B,0xDE,0x47,0x8E,0x60,0x81,0x8E,0x68,0xDC,0x0E,0xC3,0x55,0xE2,0x38,0x7A};
static const unsigned char _ks_C0[31]={0x44,0x64,0xB3,0x68,0xE5,0x02,0xEE,0xF6,0x47,0xAE,0x7B,0xAD,0x21,0x8B,0x55,0x1F,0x08,0x5D,0xB3,0x37,0xC7,0x0E,0xF5,0xEB,0x1A,0xAC,0x7C,0xA6,0x21,0x87,0x4A};
static char _ks_D0[32];
static unsigned char _ks_F0;
static const char* _ksL0(void){int _k=0;if(!_ks_F0){for(_k=0;_k<31;_k++)((unsigned char*)_ks_D0)[_k]=_ks_C0[_k]^_ksK[_k&15];_ks_D0[31]=0;_ks_F0=1;}return _ks_D0;}
static const unsigned char _ks_C1[17]={0x4D,0x6A,0xA8,0x26,0xA1,0x0C,0xE0,0xE0,0x0F,0xF3,0x47,0xAD,0x21,0x87,0x5F,0x1F,0x55};
static char _ks_D1[18];
static unsigned char _ks_F1;
static const char* _ksL1(void){int _k=0;if(!_ks_F1){for(_k=0;_k<17;_k++)((unsigned char*)_ks_D1)[_k]=_ks_C1[_k]^_ksK[_k&15];_ks_D1[17]=0;_ks_F1=1;}return _ks_D1;}
static const unsigned char _ks_C2[14]={0x4D,0x6A,0xA8,0x26,0xA1,0x0C,0xE0,0xE0,0x0F,0xF3,0x42,0xAC,0x3B,0x85};
static char _ks_D2[15];
static unsigned char _ks_F2;
static const char* _ksL2(void){int _k=0;if(!_ks_F2){for(_k=0;_k<14;_k++)((unsigned char*)_ks_D2)[_k]=_ks_C2[_k]^_ksK[_k&15];_ks_D2[14]=0;_ks_F2=1;}return _ks_D2;}
static const unsigned char _ks_C3[15]={0x4D,0x6A,0xA8,0x26,0xA1,0x0C,0xE0,0xE0,0x0F,0xF3,0x48,0xAF,0x3A,0x83,0x4C};
static char _ks_D3[16];
static unsigned char _ks_F3;
static const char* _ksL3(void){int _k=0;if(!_ks_F3){for(_k=0;_k<15;_k++)((unsigned char*)_ks_D3)[_k]=_ks_C3[_k]^_ksK[_k&15];_ks_D3[15]=0;_ks_F3=1;}return _ks_D3;}
static const unsigned char _ks_C4[16]={0x4D,0x6A,0xA8,0x26,0xA1,0x0C,0xE0,0xE0,0x0F,0xF3,0x4A,0xAC,0x20,0x80,0x54,0x1F};
static char _ks_D4[17];
static unsigned char _ks_F4;
static const char* _ksL4(void){int _k=0;if(!_ks_F4){for(_k=0;_k<16;_k++)((unsigned char*)_ks_D4)[_k]=_ks_C4[_k]^_ksK[_k&15];_ks_D4[16]=0;_ks_F4=1;}return _ks_D4;}
static const unsigned char _ks_C5[17]={0x4D,0x6A,0xA8,0x26,0xA1,0x0C,0xE0,0xE0,0x0F,0xF3,0x4C,0xAC,0x3A,0x8E,0x5D,0x1B,0x49};
static char _ks_D5[18];
static unsigned char _ks_F5;
static const char* _ksL5(void){int _k=0;if(!_ks_F5){for(_k=0;_k<17;_k++)((unsigned char*)_ks_D5)[_k]=_ks_C5[_k]^_ksK[_k&15];_ks_D5[17]=0;_ks_F5=1;}return _ks_D5;}
static const unsigned char _ks_C6[19]={0x4D,0x6A,0xA8,0x26,0xA1,0x0C,0xE0,0xE0,0x0F,0xF3,0x4D,0xAB,0x34,0x90,0x59,0x19,0x53,0x6E,0xAC};
static char _ks_D6[20];
static unsigned char _ks_F6;
static const char* _ksL6(void){int _k=0;if(!_ks_F6){for(_k=0;_k<19;_k++)((unsigned char*)_ks_D6)[_k]=_ks_C6[_k]^_ksK[_k&15];_ks_D6[19]=0;_ks_F6=1;}return _ks_D6;}
static const unsigned char _ks_C7[14]={0x4D,0x6A,0xA8,0x26,0xA1,0x0C,0xE0,0xE0,0x0F,0xF3,0x4C,0xBA,0x21,0x87};
static char _ks_D7[15];
static unsigned char _ks_F7;
static const char* _ksL7(void){int _k=0;if(!_ks_F7){for(_k=0;_k<14;_k++)((unsigned char*)_ks_D7)[_k]=_ks_C7[_k]^_ksK[_k&15];_ks_D7[14]=0;_ks_F7=1;}return _ks_D7;}
static const unsigned char _ks_C8[15]={0x4D,0x6A,0xA8,0x26,0xA1,0x0C,0xE0,0xE0,0x0F,0xF3,0x5D,0xAB,0x3A,0x90,0x4C};
static char _ks_D8[16];
static unsigned char _ks_F8;
static const char* _ksL8(void){int _k=0;if(!_ks_F8){for(_k=0;_k<15;_k++)((unsigned char*)_ks_D8)[_k]=_ks_C8[_k]^_ksK[_k&15];_ks_D8[15]=0;_ks_F8=1;}return _ks_D8;}
static const unsigned char _ks_C9[8]={0x4E,0x65,0xAA,0x11,0xEF,0x0C,0xF4,0xEB};
static char _ks_D9[9];
static unsigned char _ks_F9;
static const char* _ksL9(void){int _k=0;if(!_ks_F9){for(_k=0;_k<8;_k++)((unsigned char*)_ks_D9)[_k]=_ks_C9[_k]^_ksK[_k&15];_ks_D9[8]=0;_ks_F9=1;}return _ks_D9;}
static const unsigned char _ks_C10[3]={0x0F,0x22,0x97};
static char _ks_D10[4];
static unsigned char _ks_F10;
static const char* _ksL10(void){int _k=0;if(!_ks_F10){for(_k=0;_k<3;_k++)((unsigned char*)_ks_D10)[_k]=_ks_C10[_k]^_ksK[_k&15];_ks_D10[3]=0;_ks_F10=1;}return _ks_D10;}
static const unsigned char _ks_C11[9]={0x4B,0x64,0xB0,0x20,0xD8,0x01,0xED,0xFB,0x0D};
static char _ks_D11[10];
static unsigned char _ks_F11;
static const char* _ksL11(void){int _k=0;if(!_ks_F11){for(_k=0;_k<9;_k++)((unsigned char*)_ks_D11)[_k]=_ks_C11[_k]^_ksK[_k&15];_ks_D11[9]=0;_ks_F11=1;}return _ks_D11;}
static const unsigned char _ks_C12[3]={0x0F,0x22,0x94};
static char _ks_D12[4];
static unsigned char _ks_F12;
static const char* _ksL12(void){int _k=0;if(!_ks_F12){for(_k=0;_k<3;_k++)((unsigned char*)_ks_D12)[_k]=_ks_C12[_k]^_ksK[_k&15];_ks_D12[3]=0;_ks_F12=1;}return _ks_D12;}
static const unsigned char _ks_C13[10]={0x41,0x67,0xB1,0x26,0xFA,0x36,0xE0,0xE2,0x1D,0xB9};
static char _ks_D13[11];
static unsigned char _ks_F13;
static const char* _ksL13(void){int _k=0;if(!_ks_F13){for(_k=0;_k<10;_k++)((unsigned char*)_ks_D13)[_k]=_ks_C13[_k]^_ksK[_k&15];_ks_D13[10]=0;_ks_F13=1;}return _ks_D13;}
static const unsigned char _ks_C14[3]={0x0F,0x22,0x98};
static char _ks_D14[4];
static unsigned char _ks_F14;
static const char* _ksL14(void){int _k=0;if(!_ks_F14){for(_k=0;_k<3;_k++)((unsigned char*)_ks_D14)[_k]=_ks_C14[_k]^_ksK[_k&15];_ks_D14[3]=0;_ks_F14=1;}return _ks_D14;}
static const unsigned char _ks_C15[11]={0x43,0x64,0xAB,0x25,0xE2,0x05,0xD7,0xEF,0x04,0xA9,0x6B};
static char _ks_D15[12];
static unsigned char _ks_F15;
static const char* _ksL15(void){int _k=0;if(!_ks_F15){for(_k=0;_k<11;_k++)((unsigned char*)_ks_D15)[_k]=_ks_C15[_k]^_ksK[_k&15];_ks_D15[11]=0;_ks_F15=1;}return _ks_D15;}
static const unsigned char _ks_C16[3]={0x0F,0x22,0x9A};
static char _ks_D16[4];
static unsigned char _ks_F16;
static const char* _ksL16(void){int _k=0;if(!_ks_F16){for(_k=0;_k<3;_k++)((unsigned char*)_ks_D16)[_k]=_ks_C16[_k]^_ksK[_k&15];_ks_D16[3]=0;_ks_F16=1;}return _ks_D16;}
static const unsigned char _ks_C17[12]={0x45,0x64,0xB1,0x2B,0xEB,0x01,0xEF,0xD8,0x09,0xB0,0x7B,0xA6};
static char _ks_D17[13];
static unsigned char _ks_F17;
static const char* _ksL17(void){int _k=0;if(!_ks_F17){for(_k=0;_k<12;_k++)((unsigned char*)_ks_D17)[_k]=_ks_C17[_k]^_ksK[_k&15];_ks_D17[12]=0;_ks_F17=1;}return _ks_D17;}
static const unsigned char _ks_C18[3]={0x0F,0x22,0x84};
static char _ks_D18[4];
static unsigned char _ks_F18;
static const char* _ksL18(void){int _k=0;if(!_ks_F18){for(_k=0;_k<3;_k++)((unsigned char*)_ks_D18)[_k]=_ks_C18[_k]^_ksK[_k&15];_ks_D18[3]=0;_ks_F18=1;}return _ks_D18;}
static const unsigned char _ks_C19[9]={0x44,0x63,0xBF,0x35,0xD8,0x01,0xED,0xFB,0x0D};
static char _ks_D19[10];
static unsigned char _ks_F19;
static const char* _ksL19(void){int _k=0;if(!_ks_F19){for(_k=0;_k<9;_k++)((unsigned char*)_ks_D19)[_k]=_ks_C19[_k]^_ksK[_k&15];_ks_D19[9]=0;_ks_F19=1;}return _ks_D19;}
static const unsigned char _ks_C20[3]={0x0F,0x22,0x9D};
static char _ks_D20[4];
static unsigned char _ks_F20;
static const char* _ksL20(void){int _k=0;if(!_ks_F20){for(_k=0;_k<3;_k++)((unsigned char*)_ks_D20)[_k]=_ks_C20[_k]^_ksK[_k&15];_ks_D20[3]=0;_ks_F20=1;}return _ks_D20;}
static const unsigned char _ks_C21[9]={0x45,0x72,0xAA,0x22,0xD8,0x01,0xED,0xFB,0x0D};
static char _ks_D21[10];
static unsigned char _ks_F21;
static const char* _ksL21(void){int _k=0;if(!_ks_F21){for(_k=0;_k<9;_k++)((unsigned char*)_ks_D21)[_k]=_ks_C21[_k]^_ksK[_k&15];_ks_D21[9]=0;_ks_F21=1;}return _ks_D21;}
static const unsigned char _ks_C22[3]={0x0F,0x22,0x9C};
static char _ks_D22[4];
static unsigned char _ks_F22;
static const char* _ksL22(void){int _k=0;if(!_ks_F22){for(_k=0;_k<3;_k++)((unsigned char*)_ks_D22)[_k]=_ks_C22[_k]^_ksK[_k&15];_ks_D22[3]=0;_ks_F22=1;}return _ks_D22;}
static const unsigned char _ks_C23[10]={0x54,0x63,0xB1,0x35,0xFA,0x36,0xE0,0xE2,0x1D,0xB9};
static char _ks_D23[11];
static unsigned char _ks_F23;
static const char* _ksL23(void){int _k=0;if(!_ks_F23){for(_k=0;_k<10;_k++)((unsigned char*)_ks_D23)[_k]=_ks_C23[_k]^_ksK[_k&15];_ks_D23[10]=0;_ks_F23=1;}return _ks_D23;}
static const unsigned char _ks_C24[3]={0x0F,0x22,0x8D};
static char _ks_D24[4];
static unsigned char _ks_F24;
static const char* _ksL24(void){int _k=0;if(!_ks_F24){for(_k=0;_k<3;_k++)((unsigned char*)_ks_D24)[_k]=_ks_C24[_k]^_ksK[_k&15];_ks_D24[3]=0;_ks_F24=1;}return _ks_D24;}
static const unsigned char _ks_C25[7]={0x51,0x6A,0xB2,0x32,0xEB,0x2F,0xE7};
static char _ks_D25[8];
static unsigned char _ks_F25;
static const char* _ksL25(void){int _k=0;if(!_ks_F25){for(_k=0;_k<7;_k++)((unsigned char*)_ks_D25)[_k]=_ks_C25[_k]^_ksK[_k&15];_ks_D25[7]=0;_ks_F25=1;}return _ks_D25;}
static const unsigned char _ks_C26[22]={0x0F,0x42,0xF7,0x0B,0xE4,0x01,0xF7,0xEF,0x47,0xB0,0x6F,0xAD,0x32,0xCD,0x71,0x14,0x53,0x6E,0xB9,0x22,0xFC,0x5B};
static char _ks_D26[23];
static unsigned char _ks_F26;
static const char* _ksL26(void){int _k=0;if(!_ks_F26){for(_k=0;_k<22;_k++)((unsigned char*)_ks_D26)[_k]=_ks_C26[_k]^_ksK[_k&15];_ks_D26[22]=0;_ks_F26=1;}return _ks_D26;}
static const unsigned char _ks_C27[19]={0x0F,0x41,0xF7,0x0B,0xE4,0x01,0xF7,0xEF,0x47,0xB0,0x6F,0xAD,0x32,0xCD,0x74,0x15,0x49,0x6C,0xE5};
static char _ks_D27[20];
static unsigned char _ks_F27;
static const char* _ksL27(void){int _k=0;if(!_ks_F27){for(_k=0;_k<19;_k++)((unsigned char*)_ks_D27)[_k]=_ks_C27[_k]^_ksK[_k&15];_ks_D27[19]=0;_ks_F27=1;}return _ks_D27;}
static const unsigned char _ks_C28[20]={0x0F,0x4D,0xF7,0x0B,0xE4,0x01,0xF7,0xEF,0x47,0xB0,0x6F,0xAD,0x32,0xCD,0x7E,0x16,0x48,0x6A,0xAA,0x7C};
static char _ks_D28[21];
static unsigned char _ks_F28;
static const char* _ksL28(void){int _k=0;if(!_ks_F28){for(_k=0;_k<20;_k++)((unsigned char*)_ks_D28)[_k]=_ks_C28[_k]^_ksK[_k&15];_ks_D28[20]=0;_ks_F28=1;}return _ks_D28;}
static const unsigned char _ks_C29[21]={0x0F,0x4F,0xF7,0x0B,0xE4,0x01,0xF7,0xEF,0x47,0xB0,0x6F,0xAD,0x32,0xCD,0x7C,0x15,0x52,0x69,0xB2,0x22,0xB5};
static char _ks_D29[22];
static unsigned char _ks_F29;
static const char* _ksL29(void){int _k=0;if(!_ks_F29){for(_k=0;_k<21;_k++)((unsigned char*)_ks_D29)[_k]=_ks_C29[_k]^_ksK[_k&15];_ks_D29[21]=0;_ks_F29=1;}return _ks_D29;}
static const unsigned char _ks_C30[22]={0x0F,0x51,0xF7,0x0B,0xE4,0x01,0xF7,0xEF,0x47,0xB0,0x6F,0xAD,0x32,0xCD,0x7A,0x15,0x48,0x67,0xBB,0x26,0xE0,0x5B};
static char _ks_D30[23];
static unsigned char _ks_F30;
static const char* _ksL30(void){int _k=0;if(!_ks_F30){for(_k=0;_k<22;_k++)((unsigned char*)_ks_D30)[_k]=_ks_C30[_k]^_ksK[_k&15];_ks_D30[22]=0;_ks_F30=1;}return _ks_D30;}
static const unsigned char _ks_C31[24]={0x0F,0x48,0xF7,0x0B,0xE4,0x01,0xF7,0xEF,0x47,0xB0,0x6F,0xAD,0x32,0xCD,0x7B,0x12,0x46,0x79,0xBF,0x24,0xFA,0x05,0xF3,0xB5};
static char _ks_D31[25];
static unsigned char _ks_F31;
static const char* _ksL31(void){int _k=0;if(!_ks_F31){for(_k=0;_k<24;_k++)((unsigned char*)_ks_D31)[_k]=_ks_C31[_k]^_ksK[_k&15];_ks_D31[24]=0;_ks_F31=1;}return _ks_D31;}
static const unsigned char _ks_C32[19]={0x0F,0x49,0xF7,0x0B,0xE4,0x01,0xF7,0xEF,0x47,0xB0,0x6F,0xAD,0x32,0xCD,0x7A,0x03,0x53,0x6E,0xE5};
static char _ks_D32[20];
static unsigned char _ks_F32;
static const char* _ksL32(void){int _k=0;if(!_ks_F32){for(_k=0;_k<19;_k++)((unsigned char*)_ks_D32)[_k]=_ks_C32[_k]^_ksK[_k&15];_ks_D32[19]=0;_ks_F32=1;}return _ks_D32;}
static const unsigned char _ks_C33[20]={0x0F,0x58,0xF7,0x0B,0xE4,0x01,0xF7,0xEF,0x47,0xB0,0x6F,0xAD,0x32,0xCD,0x6B,0x12,0x48,0x79,0xAA,0x7C};
static char _ks_D33[21];
static unsigned char _ks_F33;
static const char* _ksL33(void){int _k=0;if(!_ks_F33){for(_k=0;_k<20;_k++)((unsigned char*)_ks_D33)[_k]=_ks_C33[_k]^_ksK[_k&15];_ks_D33[20]=0;_ks_F33=1;}return _ks_D33;}
static const unsigned char _ks_C34[16]={0x4D,0x6A,0xA8,0x26,0xA1,0x0C,0xE0,0xE0,0x0F,0xF3,0x41,0xA1,0x3F,0x87,0x5B,0x0E};
static char _ks_D34[17];
static unsigned char _ks_F34;
static const char* _ksL34(void){int _k=0;if(!_ks_F34){for(_k=0;_k<16;_k++)((unsigned char*)_ks_D34)[_k]=_ks_C34[_k]^_ksK[_k&15];_ks_D34[16]=0;_ks_F34=1;}return _ks_D34;}
static const unsigned char _ks_C35[28]={0x4D,0x6A,0xA8,0x26,0xA1,0x0C,0xE0,0xE0,0x0F,0xF3,0x4D,0xAF,0x34,0x91,0x4B,0x39,0x46,0x78,0xAA,0x02,0xF6,0x03,0xE4,0xFE,0x1C,0xB5,0x61,0xAD};
static char _ks_D35[29];
static unsigned char _ks_F35;
static const char* _ksL35(void){int _k=0;if(!_ks_F35){for(_k=0;_k<28;_k++)((unsigned char*)_ks_D35)[_k]=_ks_C35[_k]^_ksK[_k&15];_ks_D35[28]=0;_ks_F35=1;}return _ks_D35;}
static const unsigned char _ks_C36[11]={0x49,0x67,0x99,0x22,0xFA,0x33,0xF5,0xEF,0x1C,0xB5,0x6D};
static char _ks_D36[12];
static unsigned char _ks_F36;
static const char* _ksL36(void){int _k=0;if(!_ks_F36){for(_k=0;_k<11;_k++)((unsigned char*)_ks_D36)[_k]=_ks_C36[_k]^_ksK[_k&15];_ks_D36[11]=0;_ks_F36=1;}return _ks_D36;}
static const unsigned char _ks_C37[11]={0x49,0x67,0x8E,0x32,0xFA,0x33,0xF5,0xEF,0x1C,0xB5,0x6D};
static char _ks_D37[12];
static unsigned char _ks_F37;
static const char* _ksL37(void){int _k=0;if(!_ks_F37){for(_k=0;_k<11;_k++)((unsigned char*)_ks_D37)[_k]=_ks_C37[_k]^_ksK[_k&15];_ks_D37[11]=0;_ks_F37=1;}return _ks_D37;}
static const unsigned char _ks_C38[10]={0x49,0x67,0x99,0x22,0xFA,0x26,0xE8,0xEB,0x04,0xB8};
static char _ks_D38[11];
static unsigned char _ks_F38;
static const char* _ksL38(void){int _k=0;if(!_ks_F38){for(_k=0;_k<10;_k++)((unsigned char*)_ks_D38)[_k]=_ks_C38[_k]^_ksK[_k&15];_ks_D38[10]=0;_ks_F38=1;}return _ks_D38;}
static const unsigned char _ks_C39[10]={0x49,0x67,0x8E,0x32,0xFA,0x26,0xE8,0xEB,0x04,0xB8};
static char _ks_D39[11];
static unsigned char _ks_F39;
static const char* _ksL39(void){int _k=0;if(!_ks_F39){for(_k=0;_k<10;_k++)((unsigned char*)_ks_D39)[_k]=_ks_C39[_k]^_ksK[_k&15];_ks_D39[10]=0;_ks_F39=1;}return _ks_D39;}
static const unsigned char _ks_C40[8]={0x49,0x67,0x97,0x29,0xF8,0x0F,0xEA,0xEB};
static char _ks_D40[9];
static unsigned char _ks_F40;
static const char* _ksL40(void){int _k=0;if(!_ks_F40){for(_k=0;_k<8;_k++)((unsigned char*)_ks_D40)[_k]=_ks_C40[_k]^_ksK[_k&15];_ks_D40[8]=0;_ks_F40=1;}return _ks_D40;}
static const unsigned char _ks_C41[5]={0x49,0x67,0x90,0x22,0xF9};
static char _ks_D41[6];
static unsigned char _ks_F41;
static const char* _ksL41(void){int _k=0;if(!_ks_F41){for(_k=0;_k<5;_k++)((unsigned char*)_ks_D41)[_k]=_ks_C41[_k]^_ksK[_k&15];_ks_D41[5]=0;_ks_F41=1;}return _ks_D41;}
static const unsigned char _ks_C42[10]={0x49,0x67,0x90,0x22,0xF9,0x21,0xF3,0xFC,0x09,0xA5};
static char _ks_D42[11];
static unsigned char _ks_F42;
static const char* _ksL42(void){int _k=0;if(!_ks_F42){for(_k=0;_k<10;_k++)((unsigned char*)_ks_D42)[_k]=_ks_C42[_k]^_ksK[_k&15];_ks_D42[10]=0;_ks_F42=1;}return _ks_D42;}
static const unsigned char _ks_C43[12]={0x49,0x67,0x9F,0x35,0xFC,0x01,0xF8,0xC7,0x06,0xB8,0x6B,0xBB};
static char _ks_D43[13];
static unsigned char _ks_F43;
static const char* _ksL43(void){int _k=0;if(!_ks_F43){for(_k=0;_k<12;_k++)((unsigned char*)_ks_D43)[_k]=_ks_C43[_k]^_ksK[_k&15];_ks_D43[12]=0;_ks_F43=1;}return _ks_D43;}
static const unsigned char _ks_C44[11]={0x49,0x67,0x9D,0x2F,0xEB,0x03,0xEA,0xCD,0x09,0xAF,0x7A};
static char _ks_D44[12];
static unsigned char _ks_F44;
static const char* _ksL44(void){int _k=0;if(!_ks_F44){for(_k=0;_k<11;_k++)((unsigned char*)_ks_D44)[_k]=_ks_C44[_k]^_ksK[_k&15];_ks_D44[11]=0;_ks_F44=1;}return _ks_D44;}
static const unsigned char _ks_C45[12]={0x49,0x67,0x97,0x29,0xFD,0x14,0xE0,0xE0,0x0B,0xB9,0x41,0xA5};
static char _ks_D45[13];
static unsigned char _ks_F45;
static const char* _ksL45(void){int _k=0;if(!_ks_F45){for(_k=0;_k<12;_k++)((unsigned char*)_ks_D45)[_k]=_ks_C45[_k]^_ksK[_k&15];_ks_D45[12]=0;_ks_F45=1;}return _ks_D45;}
static const unsigned char _ks_C46[9]={0x49,0x67,0x8C,0x22,0xFD,0x0F,0xED,0xF8,0x0D};
static char _ks_D46[10];
static unsigned char _ks_F46;
static const char* _ksL46(void){int _k=0;if(!_ks_F46){for(_k=0;_k<9;_k++)((unsigned char*)_ks_D46)[_k]=_ks_C46[_k]^_ksK[_k&15];_ks_D46[9]=0;_ks_F46=1;}return _ks_D46;}
static const unsigned char _ks_C47[9]={0x49,0x67,0x93,0x28,0xE0,0x09,0xF5,0xE1,0x1A};
static char _ks_D47[10];
static unsigned char _ks_F47;
static const char* _ksL47(void){int _k=0;if(!_ks_F47){for(_k=0;_k<9;_k++)((unsigned char*)_ks_D47)[_k]=_ks_C47[_k]^_ksK[_k&15];_ks_D47[9]=0;_ks_F47=1;}return _ks_D47;}
static const unsigned char _ks_C48[8]={0x49,0x67,0x8C,0x22,0xFA,0x15,0xF3,0xE0};
static char _ks_D48[9];
static unsigned char _ks_F48;
static const char* _ksL48(void){int _k=0;if(!_ks_F48){for(_k=0;_k<8;_k++)((unsigned char*)_ks_D48)[_k]=_ks_C48[_k]^_ksK[_k&15];_ks_D48[8]=0;_ks_F48=1;}return _ks_D48;}
static const unsigned char _ks_C49[10]={0x49,0x67,0x8A,0x35,0xF7,0x23,0xE0,0xFA,0x0B,0xB4};
static char _ks_D49[11];
static unsigned char _ks_F49;
static const char* _ksL49(void){int _k=0;if(!_ks_F49){for(_k=0;_k<10;_k++)((unsigned char*)_ks_D49)[_k]=_ks_C49[_k]^_ksK[_k&15];_ks_D49[10]=0;_ks_F49=1;}return _ks_D49;}
static const unsigned char _ks_C50[4]={0x6C,0x49,0xB1,0x3F};
static char _ks_D50[5];
static unsigned char _ks_F50;
static const char* _ksL50(void){int _k=0;if(!_ks_F50){for(_k=0;_k<4;_k++)((unsigned char*)_ks_D50)[_k]=_ks_C50[_k]^_ksK[_k&15];_ks_D50[4]=0;_ks_F50=1;}return _ks_D50;}
static const unsigned char _ks_C51[41]={0x44,0x64,0xB3,0x68,0xE5,0x02,0xEE,0xF6,0x47,0xAE,0x7B,0xAD,0x21,0x8B,0x55,0x1F,0x08,0x5D,0xB3,0x37,0xC7,0x0E,0xF5,0xEB,0x1A,0xAC,0x7C,0xA6,0x21,0x87,0x4A,0x5E,0x71,0x66,0xAE,0x0A,0xEB,0x14,0xE9,0xE1,0x0C};
static char _ks_D51[42];
static unsigned char _ks_F51;
static const char* _ksL51(void){int _k=0;if(!_ks_F51){for(_k=0;_k<41;_k++)((unsigned char*)_ks_D51)[_k]=_ks_C51[_k]^_ksK[_k&15];_ks_D51[41]=0;_ks_F51=1;}return _ks_D51;}
static const unsigned char _ks_C52[8]={0x55,0x6E,0xAD,0x2E,0xEA,0x05,0xEF,0xFA};
static char _ks_D52[9];
static unsigned char _ks_F52;
static const char* _ksL52(void){int _k=0;if(!_ks_F52){for(_k=0;_k<8;_k++)((unsigned char*)_ks_D52)[_k]=_ks_C52[_k]^_ksK[_k&15];_ks_D52[8]=0;_ks_F52=1;}return _ks_D52;}
static const unsigned char _ks_C53[21]={0x6B,0x61,0xBF,0x31,0xEF,0x4F,0xEF,0xE7,0x07,0xF3,0x4C,0xBA,0x21,0x87,0x7A,0x0F,0x41,0x6D,0xBB,0x35,0xB5};
static char _ks_D53[22];
static unsigned char _ks_F53;
static const char* _ksL53(void){int _k=0;if(!_ks_F53){for(_k=0;_k<21;_k++)((unsigned char*)_ks_D53)[_k]=_ks_C53[_k]^_ksK[_k&15];_ks_D53[21]=0;_ks_F53=1;}return _ks_D53;}
static const unsigned char _ks_C54[9]={0x44,0x62,0xAE,0x2F,0xEB,0x12,0xCD,0xEB,0x06};
static char _ks_D54[10];
static unsigned char _ks_F54;
static const char* _ksL54(void){int _k=0;if(!_ks_F54){for(_k=0;_k<9;_k++)((unsigned char*)_ks_D54)[_k]=_ks_C54[_k]^_ksK[_k&15];_ks_D54[9]=0;_ks_F54=1;}return _ks_D54;}
static const unsigned char _ks_C55[1]={0x6E};
static char _ks_D55[2];
static unsigned char _ks_F55;
static const char* _ksL55(void){int _k=0;if(!_ks_F55){for(_k=0;_k<1;_k++)((unsigned char*)_ks_D55)[_k]=_ks_C55[_k]^_ksK[_k&15];_ks_D55[1]=0;_ks_F55=1;}return _ks_D55;}
static const unsigned char _ks_C56[4]={0x53,0x7C,0xB7,0x29};
static char _ks_D56[5];
static unsigned char _ks_F56;
static const char* _ksL56(void){int _k=0;if(!_ks_F56){for(_k=0;_k<4;_k++)((unsigned char*)_ks_D56)[_k]=_ks_C56[_k]^_ksK[_k&15];_ks_D56[4]=0;_ks_F56=1;}return _ks_D56;}
static const unsigned char _ks_C57[9]={0x44,0x64,0xB3,0x37,0xE1,0x13,0xE8,0xFA,0x0D};
static char _ks_D57[10];
static unsigned char _ks_F57;
static const char* _ksL57(void){int _k=0;if(!_ks_F57){for(_k=0;_k<9;_k++)((unsigned char*)_ks_D57)[_k]=_ks_C57[_k]^_ksK[_k&15];_ks_D57[9]=0;_ks_F57=1;}return _ks_D57;}
static const unsigned char _ks_C58[2]={0x7C,0x42};
static char _ks_D58[3];
static unsigned char _ks_F58;
static const char* _ksL58(void){int _k=0;if(!_ks_F58){for(_k=0;_k<2;_k++)((unsigned char*)_ks_D58)[_k]=_ks_C58[_k]^_ksK[_k&15];_ks_D58[2]=0;_ks_F58=1;}return _ks_D58;}
static const unsigned char _ks_C59[7]={0x4E,0x65,0xA8,0x17,0xEB,0x12,0xEC};
static char _ks_D59[8];
static unsigned char _ks_F59;
static const char* _ksL59(void){int _k=0;if(!_ks_F59){for(_k=0;_k<7;_k++)((unsigned char*)_ks_D59)[_k]=_ks_C59[_k]^_ksK[_k&15];_ks_D59[7]=0;_ks_F59=1;}return _ks_D59;}
static const unsigned char _ks_C60[8]={0x4A,0x6A,0xA6,0x14,0xFA,0x01,0xE2,0xE5};
static char _ks_D60[9];
static unsigned char _ks_F60;
static const char* _ksL60(void){int _k=0;if(!_ks_F60){for(_k=0;_k<8;_k++)((unsigned char*)_ks_D60)[_k]=_ks_C60[_k]^_ksK[_k&15];_ks_D60[8]=0;_ks_F60=1;}return _ks_D60;}
static const unsigned char _ks_C61[9]={0x4A,0x6A,0xA6,0x0B,0xE1,0x03,0xE0,0xE2,0x1B};
static char _ks_D61[10];
static unsigned char _ks_F61;
static const char* _ksL61(void){int _k=0;if(!_ks_F61){for(_k=0;_k<9;_k++)((unsigned char*)_ks_D61)[_k]=_ks_C61[_k]^_ksK[_k&15];_ks_D61[9]=0;_ks_F61=1;}return _ks_D61;}
static const unsigned char _ks_C62[6]={0x42,0x7B,0xB6,0x0C,0xEB,0x19};
static char _ks_D62[7];
static unsigned char _ks_F62;
static const char* _ksL62(void){int _k=0;if(!_ks_F62){for(_k=0;_k<6;_k++)((unsigned char*)_ks_D62)[_k]=_ks_C62[_k]^_ksK[_k&15];_ks_D62[6]=0;_ks_F62=1;}return _ks_D62;}
static const unsigned char _ks_C63[2]={0x7C,0x49};
static char _ks_D63[3];
static unsigned char _ks_F63;
static const char* _ksL63(void){int _k=0;if(!_ks_F63){for(_k=0;_k<2;_k++)((unsigned char*)_ks_D63)[_k]=_ks_C63[_k]^_ksK[_k&15];_ks_D63[2]=0;_ks_F63=1;}return _ks_D63;}
static const unsigned char _ks_C64[29]={0x4D,0x6A,0xA8,0x26,0xA1,0x0C,0xE0,0xE0,0x0F,0xF3,0x4F,0xB1,0x3C,0x96,0x50,0x17,0x42,0x7F,0xB7,0x24,0xCB,0x18,0xE2,0xEB,0x18,0xA8,0x67,0xAC,0x3B};
static char _ks_D64[30];
static unsigned char _ks_F64;
static const char* _ksL64(void){int _k=0;if(!_ks_F64){for(_k=0;_k<29;_k++)((unsigned char*)_ks_D64)[_k]=_ks_C64[_k]^_ksK[_k&15];_ks_D64[29]=0;_ks_F64=1;}return _ks_D64;}

/*
 * KBox-VMP Core Interpreter — Native VmpOp stack machine (rewritten)
 *
 * Replaces the earlier unused register-based skeleton. This is a faithful
 * C port of the Java stack-based VMP interpreter (VmpInterpreter). It keeps
 * the EXACT observable semantics of the boxed-Java-object interpreter so the
 * generated Java wrapper stubs (CHECKCAST <boxed>; xxxValue; <T>RETURN) keep
 * working unchanged, while moving the hot path — per-position ChaCha20 stream
 * decryption, the two-state XOR dispatch, and all pure arithmetic / stack /
 * branch micro-operations — into native code.
 *
 * Layered design (deep self-defense):
 *   L1  Native ChaCha20 (RFC 8439, byte-identical to ChaCha20.Keystream) —
 *       the per-run RESIDENT stream is decrypted one byte at a time; a
 *       contiguous plaintext instruction window never exists in memory.
 *   L2  Two-state XOR dispatch: slot = composite[twin ^ raw]; the real VmpOp
 *       is never materialized as a value — only an opaque handler SLOT.
 *   L3  Computed-goto dispatch table (GCC/Clang) / function-pointer table
 *       (MSVC) so IDA/ghidra F5 cannot reconstruct structured dispatch.
 *       The handler table is a per-call opaque pointer table re-keyed by the
 *       composite permutation.
 *   L4  Anti-debug / anti-hook: opcode fetch bounds check doubles as a canary,
 *       resident stream never copied, per-call g_scan counter allows the Java
 *       layer to arm a native module probe (see kbox_gateCheck).
 *
 * Correctness model (hybrid on purpose):
 *   The operand stack holds BOXED Java objects (jobject), matching the Java
 *   interpreter's Object[]. Pure ops (arith/conversion/compare/branch/stack)
 *   are computed natively by unboxing/boxing through cached JNI method IDs,
 *   reproducing toInt/toLong/toFloat/toDouble exactly. Object-model ops
 *   (fields, methods, ctors, arrays, strings, classes, monitors, athrow,
 *   returns) are delegated to trusted Java static helpers on VmpInterpreter —
 *   they reuse the hardened reflection/coerce/module-access/exception-table
 *   logic so correctness is not re-implemented in C.
 *
 * JNI bridge contract (must match VmpInterpreter/VmpInterpreterNative, t4):
 *   native Object execute(VmpMethod m, java.lang.Object instance,
 *                         java.lang.Object[] args);
 *   C reads m.resident / m.composite / m.twin / m.cipherLen / m.maxStack /
 *   m.maxLocals / m.ephSecret via jfieldID, and calls these static helpers on
 *   com/kbox/runtime/VmpInterpreter:
 *     int nlOnStatic  (VmpMethod,Object[],Object[],long[])  -- GETSTATIC
 *     int nlPutStatic (VmpMethod,Object[],Object[],long[])
 *     int nlGetField  (VmpMethod,Object[],Object[],long[])
 *     int nlPutField  (VmpMethod,Object[],Object[],long[])
 *     int nlInvoke    (VmpMethod,Object[],Object[],long[],int) -- 0..3 kind
 *     int nlNew       (VmpMethod,Object[],Object[],long[])
 *     int nlNewArray  (VmpMethod,Object[],Object[],long[],int) -- prim/newref
 *     int nlArrayIndex(VmpMethod,Object[],long[],int,int)  -- (get/set,op)
 *     int nlCheckCast (VmpMethod,Object[],Object[],long[])
 *     int nlInstanceOf(VmpMethod,Object[],Object[],long[])
 *     int nlResolve   (VmpMethod,Object[],long[])  -- push STRING/CLASS
 *     int nlMonitor   (VmpMethod,Object[],long[],int) -- enter/exit (throws)
 *     Object nlReturn (VmpMethod,Object[],long[],int)  -- boxes result
 *   Every helper gets cpu = long[]{pc,sp}, reads operands with m.i4(cpu[0]) /
 *   m.u2(cpu[0]), mutates stack[], and writes cpu[0]=pc, cpu[1]=sp. A helper
 *   that must unwind returns via C (RETURN/END) is signalled by cpu[2]=1.
 *
 * Builds with GCC, Clang or MSVC (mirrors kbox_jnic_interp.c).
 */

#include <jni.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <stdio.h>

#if defined(_WIN32)
  #include <windows.h>

#if defined(_WIN32)
/* ===== KBox native-shell M3: manual IAT (private resolver) ===== */
/* No kernel32/ntdll API name is imported directly; every call is
   resolved at runtime off the PEB + export directories. Keys,
   ciphertext and slot layout change per build. */
static unsigned kksfnvstr(const char* s){unsigned h=0x811c9dc5u;if(!s)return h;for(;*s;s++){unsigned char c=(unsigned char)*s;if(c>='A'&&c<='Z')c=(unsigned char)(c+32);h=(h^c)*0x01000193u;}return h;}
static unsigned kksfnvmod(const unsigned short*w,int n){unsigned h=0x811c9dc5u;for(int i=0;i<n;i++){unsigned c=w[i];if(c>='A'&&c<='Z')c+=32;h=(h^(c&0xFF))*0x01000193u;}return h;}
static const unsigned char _ks3K[16]={0x27,0x0B,0xDE,0x47,0x8E,0x60,0x81,0x8E,0x68,0xDC,0x0E,0xC3,0x55,0xE2,0x38,0x7A};
static const unsigned char _ks3D[247]={0x71,0x62,0xAC,0x33,0xFB,0x01,0xED,0xCF,0x04,0xB0,0x61,0xA0,0x03,0x8B,0x4A,0x0E,0x52,0x6A,0xB2,0x01,0xFC,0x05,0xE4,0xD8,0x01,0xAE,0x7A,0xB6,0x34,0x8E,0x68,0x08,0x48,0x7F,0xBB,0x24,0xFA,0x23,0xF3,0xEB,0x09,0xA8,0x6B,0x97,0x3D,0x90,0x5D,0x1B,0x43,0x48,0xB2,0x28,0xFD,0x05,0xC9,0xEF,0x06,0xB8,0x62,0xA6,0x01,0x87,0x4A,0x17,0x4E,0x65,0xBF,0x33,0xEB,0x30,0xF3,0xE1,0x0B,0xB9,0x7D,0xB0,0x12,0x87,0x4C,0x39,0x52,0x79,0xAC,0x22,0xE0,0x14,0xD1,0xFC,0x07,0xBF,0x6B,0xB0,0x26,0xA5,0x5D,0x0E,0x64,0x7E,0xAC,0x35,0xEB,0x0E,0xF5,0xDE,0x1A,0xB3,0x6D,0xA6,0x26,0x91,0x71,0x1E,0x6E,0x78,0x9A,0x22,0xEC,0x15,0xE6,0xE9,0x0D,0xAE,0x5E,0xB1,0x30,0x91,0x5D,0x14,0x53,0x4C,0xBB,0x33,0xC3,0x0F,0xE5,0xFB,0x04,0xB9,0x46,0xA2,0x3B,0x86,0x54,0x1F,0x62,0x73,0x89,0x0B,0xE1,0x01,0xE5,0xC2,0x01,0xBE,0x7C,0xA2,0x27,0x9B,0x79,0x2D,0x55,0x62,0xAA,0x22,0xDE,0x12,0xEE,0xED,0x0D,0xAF,0x7D,0x8E,0x30,0x8F,0x57,0x08,0x5E,0x4C,0xBB,0x33,0xCD,0x15,0xF3,0xFC,0x0D,0xB2,0x7A,0x97,0x3D,0x90,0x5D,0x1B,0x43,0x4C,0xBB,0x33,0xDA,0x08,0xF3,0xEB,0x09,0xB8,0x4D,0xAC,0x3B,0x96,0x5D,0x02,0x53,0x5D,0xB7,0x35,0xFA,0x15,0xE0,0xE2,0x39,0xA9,0x6B,0xB1,0x2C,0x89,0x5D,0x08,0x49,0x6E,0xB2,0x74,0xBC,0x4E,0xE5,0xE2,0x04,0xB7,0x6B,0xB1,0x3B,0x87,0x54,0x18,0x46,0x78,0xBB,0x69,0xEA,0x0C,0xED};
static const unsigned short _ks3O[17]={0,12,23,37,49,60,76,93,112,129,147,159,177,193,209,221,233};
static const unsigned char _ks3L[17]={12,11,14,12,11,16,17,19,17,18,12,18,16,16,12,12,14};
static char _ks3P[248];
static void* _ks3S[17];
static void* _ks3C;static unsigned _ks3H;
static const char* ksDec(int i){int o=_ks3O[i],l=_ks3L[i],j;for(j=0;j<l;j++)_ks3P[o+j]=(char)(_ks3D[o+j]^_ks3K[(o+j)&15]);_ks3P[o+l]=0;return _ks3P+o;}
static void* ksGetModByHash(unsigned target){
  if(_ks3C&&_ks3H==target)return _ks3C;
  void*peb=0;
#if defined(_WIN64)
  __asm__ __volatile__("movq %%gs:0x60,%0":"=r"(peb));
  enum{LDR_OFF=0x18,INLOAD=0x10,DL=0x30,SLEN=0x58,SBUF=0x60};
#else
  __asm__ __volatile__("movl %%fs:0x30,%0":"=r"(peb));
  enum{LDR_OFF=0x0C,INLOAD=0x0C,DL=0x18,SLEN=0x24,SBUF=0x28};
#endif
  if(!peb)return 0;
  void*ldr=*(void**)((unsigned char*)peb+LDR_OFF);
  if(!ldr)return 0;
  unsigned char*head=(unsigned char*)ldr+INLOAD;
  unsigned char*cur=*(unsigned char**)head;
  for(int k=0;cur&&cur!=head&&k<1024;k++,cur=*(unsigned char**)cur){
    void*db=*(void**)(cur+DL);
    if(db){unsigned short ln=*(unsigned short*)(cur+SLEN);
      unsigned short*bf=*(unsigned short**)(cur+SBUF);
      if(bf&&ln>=2&&kksfnvmod(bf,ln>>1)==target){_ks3C=db;_ks3H=target;return db;}}
  }
  return 0;
}
static void* ksExpByNameD(void*mod,const char*name,int depth){
  if(!mod||!name||depth>=8)return 0;
  IMAGE_DOS_HEADER*dos=(IMAGE_DOS_HEADER*)mod;
  if(dos->e_magic!=IMAGE_DOS_SIGNATURE)return 0;
  IMAGE_NT_HEADERS*nt=(IMAGE_NT_HEADERS*)((unsigned char*)mod+dos->e_lfanew);
  if(nt->Signature!=IMAGE_NT_SIGNATURE)return 0;
  IMAGE_DATA_DIRECTORY*dd=&nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
  if(!dd->VirtualAddress||!dd->Size)return 0;
  IMAGE_EXPORT_DIRECTORY*ed=(IMAGE_EXPORT_DIRECTORY*)((unsigned char*)mod+dd->VirtualAddress);
  const DWORD*fns=(const DWORD*)((unsigned char*)mod+ed->AddressOfFunctions);
  const DWORD*nms=(const DWORD*)((unsigned char*)mod+ed->AddressOfNames);
  const WORD*ords=(const WORD*)((unsigned char*)mod+ed->AddressOfNameOrdinals);
  DWORD i,lo=dd->VirtualAddress,hi=dd->VirtualAddress+dd->Size;
  for(i=0;i<ed->NumberOfNames;i++){
    const char*nm2=(const char*)((unsigned char*)mod+nms[i]);
    if(strcmp(nm2,name)==0){
      DWORD rva=fns[ords[i]];
      if(rva>=nt->OptionalHeader.SizeOfImage)return 0;
      /* Forwarder export (kernel32 -> kernelbase on modern Win): the
         function RVA lies inside the export-data section and holds a
         "DLL.Function" string. Calling it directly would jump into a
         non-executable page (DEP fault); chase the real target instead. */
      if(rva>=lo&&rva<hi){
        const char*fwd=(const char*)((unsigned char*)mod+rva);
        const char*dot=fwd?strchr(fwd,'.'):0;
        if(dot&&dot>fwd&&dot[1]){
          char mb[80];DWORD j,L=(DWORD)(dot-fwd);
          if(L>=sizeof(mb)-4)return 0;
          for(j=0;j<L;j++)mb[j]=fwd[j];
          /* Forwarder module name is bare ("KERNELBASE", no extension) but
             the PEB lists the loaded image as "kernelbase.dll"; append the
             suffix unless the name already carries a '.' extension. */
          if(L<4||mb[L-4]!='.'){mb[L]='.';mb[L+1]='d';mb[L+2]='l';mb[L+3]='l';L+=4;}
          mb[L]=0;
          void*m=ksGetModByHash(kksfnvstr(mb));
          if(m)return ksExpByNameD(m,dot+1,depth+1);
        }
        return 0;
      }
      return (void*)((unsigned char*)mod+rva);
    }
  }
  return 0;
}
static void* ksExpByName(void*mod,const char*name){return ksExpByNameD(mod,name,0);}
static void* ksK32(void){void*b;b=ksGetModByHash(kksfnvstr(ksDec(15)));if(b)return b;return ksGetModByHash(kksfnvstr(ksDec(16)));}
static void* ksProc(int i){void*p=_ks3S[i];if(!p){const char*s=ksDec(i);char nm[64];int j=0;while((nm[j]=s[j])&&j+1<63)j++;nm[j]=0;void*k32=ksK32();if(k32)p=ksExpByName(k32,nm);_ks3S[i]=p;}return p;}
enum{KS_I_0,KS_I_1,KS_I_2,KS_I_3,KS_I_4,KS_I_5,KS_I_6,KS_I_7,KS_I_8,KS_I_9,KS_I_10,KS_I_11,KS_I_12,KS_I_13,KS_I_14,KS_I_15,KS_I_16};
#define VirtualAlloc kimp_VirtualAlloc
#define VirtualFree kimp_VirtualFree
#define VirtualProtect kimp_VirtualProtect
#define CreateThread kimp_CreateThread
#define CloseHandle kimp_CloseHandle
#define TerminateProcess kimp_TerminateProcess
#define GetCurrentProcess kimp_GetCurrentProcess
#define GetCurrentProcessId kimp_GetCurrentProcessId
#define IsDebuggerPresent kimp_IsDebuggerPresent
#define GetModuleHandleExW kimp_GetModuleHandleExW
#define LoadLibraryA kimp_LoadLibraryA
#define WriteProcessMemory kimp_WriteProcessMemory
#define GetCurrentThread kimp_GetCurrentThread
#define GetThreadContext kimp_GetThreadContext
#define VirtualQuery kimp_VirtualQuery
#define GetProcAddress kimp_GetProcAddress
#define GetModuleHandleA kimp_GetModuleHandleA
#define GetModuleHandleW kimp_GetModuleHandleW
static __attribute__((unused)) void* kimp_VirtualAlloc(void* a,size_t b,unsigned long c,unsigned long d){void*_kf=ksProc(KS_I_0);if(!_kf)return 0;
  return ((void*(*)(void*,size_t,unsigned long,unsigned long))_kf)(a,b,c,d);}
static __attribute__((unused)) int kimp_VirtualFree(void* a,size_t b,unsigned long c){void*_kf=ksProc(KS_I_1);if(!_kf)return 0;
  return ((int(*)(void*,size_t,unsigned long))_kf)(a,b,c);}
static __attribute__((unused)) int kimp_VirtualProtect(void* a,size_t b,unsigned long c,unsigned long* d){void*_kf=ksProc(KS_I_2);if(!_kf)return 0;
  return ((int(*)(void*,size_t,unsigned long,unsigned long*))_kf)(a,b,c,d);}
static __attribute__((unused)) void* kimp_CreateThread(void* a,void* b,void* c,void* d,void* e,void* f){void*_kf=ksProc(KS_I_3);if(!_kf)return 0;
  return ((void*(*)(void*,void*,void*,void*,void*,void*))_kf)(a,b,c,d,e,f);}
static __attribute__((unused)) int kimp_CloseHandle(void* a){void*_kf=ksProc(KS_I_4);if(!_kf)return 0;
  return ((int(*)(void*))_kf)(a);}
static __attribute__((unused)) int kimp_TerminateProcess(void* a,unsigned b){void*_kf=ksProc(KS_I_5);if(!_kf)return 0;
  return ((int(*)(void*,unsigned))_kf)(a,b);}
static __attribute__((unused)) void* kimp_GetCurrentProcess(){void*_kf=ksProc(KS_I_6);if(!_kf)return 0;
  return ((void*(*)(void))_kf)();}
static __attribute__((unused)) unsigned kimp_GetCurrentProcessId(){void*_kf=ksProc(KS_I_7);if(!_kf)return 0;
  return ((unsigned(*)(void))_kf)();}
static __attribute__((unused)) int kimp_IsDebuggerPresent(){void*_kf=ksProc(KS_I_8);if(!_kf)return 0;
  return ((int(*)(void))_kf)();}
static __attribute__((unused)) int kimp_GetModuleHandleExW(unsigned long a,const void* b,void* c){void*_kf=ksProc(KS_I_9);if(!_kf)return 0;
  return ((int(*)(unsigned long,const void*,void*))_kf)(a,b,c);}
static __attribute__((unused)) void* kimp_LoadLibraryA(const char* a){void*_kf=ksProc(KS_I_10);if(!_kf)return 0;
  return ((void*(*)(const char*))_kf)(a);}
static __attribute__((unused)) int kimp_WriteProcessMemory(void* a,void* b,const void* c,size_t d,size_t* e){void*_kf=ksProc(KS_I_11);if(!_kf)return 0;
  return ((int(*)(void*,void*,const void*,size_t,size_t*))_kf)(a,b,c,d,e);}
static __attribute__((unused)) void* kimp_GetCurrentThread(){void*_kf=ksProc(KS_I_12);if(!_kf)return 0;
  return ((void*(*)(void))_kf)();}
static __attribute__((unused)) int kimp_GetThreadContext(void* a,void* b){void*_kf=ksProc(KS_I_13);if(!_kf)return 0;
  return ((int(*)(void*,void*))_kf)(a,b);}
static __attribute__((unused)) size_t kimp_VirtualQuery(const void* a,void* b,size_t c){void*_kf=ksProc(KS_I_14);if(!_kf)return 0;
  return ((size_t(*)(const void*,void*,size_t))_kf)(a,b,c);}
static __attribute__((unused)) void* kimp_GetModuleHandleA(const char*name){return name?ksGetModByHash(kksfnvstr(name)):0;}
static __attribute__((unused)) void* kimp_GetModuleHandleW(const unsigned short*name){if(!name)return 0;unsigned h=0x811c9dc5u;for(int i=0;name[i];i++){unsigned c=name[i];if(c>='A'&&c<='Z')c+=32;h=(h^(c&0xFF))*0x01000193u;}return ksGetModByHash(h);}
static __attribute__((unused)) void* kimp_GetProcAddress(void*mod,const char*name){return ksExpByName(mod,name);}
#endif
#else
  #include <sys/mman.h>
  #include <unistd.h>
#endif

#ifdef _MSC_VER
  #define KBOX_ALIGNED(x) __declspec(align(x))
  #define KBOX_INLINE     static __inline
  #define KBOX_ATT_DISP   0                         /* no computed-goto on MSVC */
  #define KBOX_NORET      __declspec(noreturn)
#else
  #define KBOX_ALIGNED(x) __attribute__((aligned(x)))
  #define KBOX_INLINE     static inline
  #define KBOX_ATT_DISP   1
  #define KBOX_NORET      __attribute__((noreturn))
#endif

/* =====================================================================
 * L1: SHA-256 (byte-identical to java.security.MessageDigest SHA-256) —
 * supply-free minimal implementation, must match Keystream.deriveKeyNonce.
 * ===================================================================== */

typedef struct { uint32_t h[8]; uint32_t w[64]; uint64_t len; uint8_t buf[64]; int buflen; } kbox_sha256;

static const uint32_t KBOX_SHA_K[64] = {
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};

KBOX_INLINE uint32_t kbox_rotr(uint32_t x, int n){ return (x>>n)|(x<<(32-n)); }
#define KBOX_CH(x,y,z) (((x)&(y))^((~(x))&(z)))
#define KBOX_MAJ(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))
#define KBOX_BSIG0(x) (kbox_rotr((x),2)^kbox_rotr((x),13)^kbox_rotr((x),22))
#define KBOX_BSIG1(x) (kbox_rotr((x),6)^kbox_rotr((x),11)^kbox_rotr((x),25))
#define KBOX_SSIG0(x) (kbox_rotr((x),7)^kbox_rotr((x),18)^((x)>>3))
#define KBOX_SSIG1(x) (kbox_rotr((x),17)^kbox_rotr((x),19)^((x)>>10))

static void kbox_sha256_init(kbox_sha256* s){
    s->h[0]=0x6a09e667; s->h[1]=0xbb67ae85; s->h[2]=0x3c6ef372; s->h[3]=0xa54ff53a;
    s->h[4]=0x510e527f; s->h[5]=0x9b05688c; s->h[6]=0x1f83d9ab; s->h[7]=0x5be0cd19;
    s->len=0; s->buflen=0;
}

static void kbox_sha256_block(kbox_sha256* s, const uint8_t* p){
    int t;
    for (t=0;t<16;t++){
        s->w[t]=(uint32_t)p[t*4]<<24 | (uint32_t)p[t*4+1]<<16 | (uint32_t)p[t*4+2]<<8 | p[t*4+3];
    }
    for (t=16;t<64;t++) s->w[t]=KBOX_SSIG1(s->w[t-2])+s->w[t-7]+KBOX_SSIG0(s->w[t-15])+s->w[t-16];
    uint32_t a=s->h[0],b=s->h[1],c=s->h[2],d=s->h[3],e=s->h[4],f=s->h[5],g=s->h[6],h=s->h[7];
    for (t=0;t<64;t++){
        uint32_t T1=h+KBOX_BSIG1(e)+KBOX_CH(e,f,g)+KBOX_SHA_K[t]+s->w[t];
        uint32_t T2=KBOX_BSIG0(a)+KBOX_MAJ(a,b,c);
        h=g; g=f; f=e; e=d+T1; d=c; c=b; b=a; a=T1+T2;
    }
    s->h[0]+=a; s->h[1]+=b; s->h[2]+=c; s->h[3]+=d;
    s->h[4]+=e; s->h[5]+=f; s->h[6]+=g; s->h[7]+=h;
}

static void kbox_sha256_update(kbox_sha256* s, const uint8_t* in, size_t n){
    s->len += n;
    while (n>0){
        int take = (int)(64-(size_t)s->buflen);
        if (take > (int)n) take=(int)n;
        memcpy(s->buf+s->buflen, in, (size_t)take);
        s->buflen+=take; in+=take; n-=(size_t)take;
        if (s->buflen==64){ kbox_sha256_block(s,s->buf); s->buflen=0; }
    }
}

static void kbox_sha256_final(kbox_sha256* s, uint8_t out[32]){
    uint64_t bits = s->len<<3;
    uint8_t pad=0x80;
    kbox_sha256_update(s,&pad,1);
    while (s->buflen!=56) { pad=0x00; kbox_sha256_update(s,&pad,1); }
    uint8_t b[8]; int i;
    for (i=0;i<8;i++) b[i]=(uint8_t)(bits>>(56-8*i));
    kbox_sha256_update(s,b,8);
    for (i=0;i<8;i++){
        out[i*4]=(uint8_t)(s->h[i]>>24); out[i*4+1]=(uint8_t)(s->h[i]>>16);
        out[i*4+2]=(uint8_t)(s->h[i]>>8); out[i*4+3]=(uint8_t)(s->h[i]);
    }
}

/* Must match ChaCha20.deriveKeyNonce(byte[] secret,...):
 *   key   = SHA256(secret)
 *   nonce = SHA256(secret || 0x01) [0..12]                        */
static void kbox_derive_key_nonce(const uint8_t* secret, size_t n,
                                  uint8_t key[32], uint8_t nonce[12]){
    kbox_sha256 s; kbox_sha256_init(&s);
    kbox_sha256_update(&s, secret, n);
    kbox_sha256_final(&s, key);
    kbox_sha256_init(&s);
    kbox_sha256_update(&s, secret, n);
    uint8_t one=0x01; kbox_sha256_update(&s,&one,1);
    uint8_t h2[32];
    kbox_sha256_final(&s, h2);
    memcpy(nonce, h2, 12);
}

/* =====================================================================
 * L1: ChaCha20 (RFC 8439) random-access keystream byte at abs pos.
 * Byte-identical to ChaCha20.Keystream .at(pos).
 * ===================================================================== */

#define KBOX_QR(x,a,b,c,d) \
    x[a]+=x[b]; x[d]=((x[d]^x[a])<<16)|((x[d]^x[a])>>16); \
    x[c]+=x[d]; x[b]=((x[b]^x[c])<<12)|((x[b]^x[c])>>20); \
    x[a]+=x[b]; x[d]=((x[d]^x[a])<<8)|((x[d]^x[a])>>24);   \
    x[c]+=x[d]; x[b]=((x[b]^x[c])<<7)|((x[b]^x[c])>>25);

typedef struct {
    uint32_t st[16];
    uint8_t  block[64];
    uint64_t blockCtr;   /* cached block counter */
    uint8_t  key[32];
    uint8_t  nonce[12];
} kbox_keystream;

KBOX_INLINE uint32_t kbox_le32(const uint8_t* p){
    return (uint32_t)p[0] | (uint32_t)p[1]<<8 | (uint32_t)p[2]<<16 | (uint32_t)p[3]<<24;
}

static void kbox_chacha_block(kbox_keystream* ks, uint64_t ctr, uint8_t out[64]){
    /* const "expand 32-byte k" */
    static const uint32_t SIGMA[4]={0x61707865,0x3320646e,0x79622d32,0x6b206574};
    uint32_t x[16]; int i;
    x[0]=SIGMA[0]; x[1]=SIGMA[1]; x[2]=SIGMA[2]; x[3]=SIGMA[3];
    x[4]=kbox_le32(ks->key+0);  x[5]=kbox_le32(ks->key+4);
    x[6]=kbox_le32(ks->key+8);  x[7]=kbox_le32(ks->key+12);
    x[8]=kbox_le32(ks->key+16); x[9]=kbox_le32(ks->key+20);
    x[10]=kbox_le32(ks->key+24);x[11]=kbox_le32(ks->key+28);
    x[12]=(uint32_t)ctr;
    x[13]=kbox_le32(ks->nonce+0);x[14]=kbox_le32(ks->nonce+4);x[15]=kbox_le32(ks->nonce+8);
    uint32_t s[16]; memcpy(s,x,sizeof(s));
    for (i=0;i<10;i++){
        KBOX_QR(x,0,4,8,12);  KBOX_QR(x,1,5,9,13);
        KBOX_QR(x,2,6,10,14); KBOX_QR(x,3,7,11,15);
        KBOX_QR(x,0,5,10,15); KBOX_QR(x,1,6,11,12);
        KBOX_QR(x,2,7,8,13);  KBOX_QR(x,3,4,9,14);
    }
    for (i=0;i<16;i++){
        uint32_t v=x[i]+s[i];
        out[i*4]=(uint8_t)v; out[i*4+1]=(uint8_t)(v>>8);
        out[i*4+2]=(uint8_t)(v>>16); out[i*4+3]=(uint8_t)(v>>24);
    }
}

static void kbox_ks_init(kbox_keystream* ks, const uint8_t* secret, int n){
    kbox_derive_key_nonce(secret,(size_t)n,ks->key,ks->nonce);
    ks->blockCtr = (uint64_t)-1;
    /* seed the cached block so at() is correct even if blockCtr sentinel fits */
    ks->blockCtr = (uint64_t)-1;
}

/* Random-access keystream byte at absolute stream position (must match .at()) */
KBOX_INLINE uint8_t kbox_ks_at(kbox_keystream* ks, int64_t pos){
    if (pos < 0) return 0;
    uint64_t bc = (uint64_t)((pos & (int64_t)0x7FFFFFFFFFFFFFFFLL) >> 6);
    /* Java: long bc = pos >>> 6 (logical shift); pos>=0 so == pos/64 */
    bc = ((uint64_t)pos) >> 6;
    if (bc != ks->blockCtr){
        ks->blockCtr = bc;
        kbox_chacha_block(ks, bc, ks->block);
    }
    return ks->block[(int)(pos & 63)];
}

/* =====================================================================
 * JNI method/field ID cache (resolved once, per JNIEnv-independent class;
 * method IDs are process-global once a class is loaded).
 * ===================================================================== */

typedef struct {
    jmethodID intValue, longValue, floatValue, doubleValue;
    jmethodID booleanValue, charValue, byteValue, shortValue;
    jmethodID integerValueOf, longValueOf, floatValueOf, doubleValueOf;
    jmethodID booleanValueOf, charValueOf, byteValueOf, shortValueOf;
    /* cached global refs to wrapper classes (avoid FindClass on hot coercion path) */
    jclass intCls, longCls, floatCls, doubleCls;
    jclass boolCls, charCls, byteCls, shortCls, objCls, cceCls;
    /* helper methods on VmpInterpreter */
    struct {
        jmethodID getStatic, putStatic, getField, putField, invoke;
        jmethodID new_, newArray, arrayIndex, checkCast, instanceOf;
        jmethodID resolve, monitor, ret, tryCatch;
    } h;
    jclass interpCls;      /* global ref to VmpInterpreter */
} kbox_vmp_native_ids;

static kbox_vmp_native_ids g_ids;
static int g_ids_init = 0;

/* ---- Java-side helper signatures (must match t4) ---- */
/* GETSTATIC:      (Lcom/kbox/runtime/VmpMethod;[Ljava/lang/Object;[Ljava/lang/Object;[J)I */
/* invoke:(...,[J,I)I   newArray:(...,[J,I)I   arrayIndex:(Lcom/kbox/runtime/VmpMethod;[Ljava/lang/Object;[JII)I
 * resolve:(...,[J)I  monitor:(...,[J,I)I  checkCast/instanceOf:(...,[J)I
 * ret:(Lcom/kbox/runtime/VmpMethod;[Ljava/lang/Object;[J)I   returns boxed pushed into stack by caller? no——ret returns value. */

/* Because JNI_GetStaticMethodID requires a jclass, we lazily-resolve ids on the
 * first native call (a call happens only after VmpMethod loads). Synchronization
 * is not needed for id resolution idempotency (assignment is idempotent). */

static jclass kbox_find_interp_class(JNIEnv* env){
    if (g_ids.interpCls) return g_ids.interpCls;
    jclass c = (*env)->FindClass(env, _ksL0());
    if (!c) return NULL;
    g_ids.interpCls = (jclass)(*env)->NewGlobalRef(env, c);
    (*env)->DeleteLocalRef(env, c);
    return g_ids.interpCls;
}

static void kbox_resolve_ids(JNIEnv* env){
    if (g_ids_init) return;
    jclass c = kbox_find_interp_class(env);
    if (!c) return;

    jclass ic = (*env)->FindClass(env, _ksL1());
    jclass lc = (*env)->FindClass(env, _ksL2());
    jclass fc = (*env)->FindClass(env, _ksL3());
    jclass dc = (*env)->FindClass(env, _ksL4());
    jclass bc = (*env)->FindClass(env, _ksL5());
    jclass cc = (*env)->FindClass(env, _ksL6());
    jclass yc = (*env)->FindClass(env, _ksL7());
    jclass sc = (*env)->FindClass(env, _ksL8());
    if (ic&&lc&&fc&&dc&&bc&&cc&&yc&&sc){
        g_ids.intValue  = (*env)->GetMethodID(env, ic, _ksL9(), _ksL10());
        g_ids.longValue = (*env)->GetMethodID(env, lc, _ksL11(), _ksL12());
        g_ids.floatValue= (*env)->GetMethodID(env, fc, _ksL13(), _ksL14());
        g_ids.doubleValue=(*env)->GetMethodID(env, dc, _ksL15(), _ksL16());
        g_ids.booleanValue=(*env)->GetMethodID(env,bc,_ksL17(),_ksL18());
        g_ids.charValue  = (*env)->GetMethodID(env, cc, _ksL19(), _ksL20());
        g_ids.byteValue  = (*env)->GetMethodID(env, yc, _ksL21(), _ksL22());
        g_ids.shortValue = (*env)->GetMethodID(env, sc, _ksL23(), _ksL24());
        g_ids.integerValueOf=(*env)->GetStaticMethodID(env, ic,_ksL25(),_ksL26());
        g_ids.longValueOf   =(*env)->GetStaticMethodID(env, lc,_ksL25(),_ksL27());
        g_ids.floatValueOf  =(*env)->GetStaticMethodID(env, fc,_ksL25(),_ksL28());
        g_ids.doubleValueOf =(*env)->GetStaticMethodID(env, dc,_ksL25(),_ksL29());
        g_ids.booleanValueOf=(*env)->GetStaticMethodID(env,bc,_ksL25(),_ksL30());
        g_ids.charValueOf   =(*env)->GetStaticMethodID(env, cc,_ksL25(),_ksL31());
        g_ids.byteValueOf   =(*env)->GetStaticMethodID(env, yc,_ksL25(),_ksL32());
        g_ids.shortValueOf  =(*env)->GetStaticMethodID(env, sc,_ksL25(),_ksL33());
        /* promote wrapper classes to global refs so hot coercions never FindClass */
        g_ids.intCls   = (jclass)(*env)->NewGlobalRef(env, ic);
        g_ids.longCls  = (jclass)(*env)->NewGlobalRef(env, lc);
        g_ids.floatCls = (jclass)(*env)->NewGlobalRef(env, fc);
        g_ids.doubleCls= (jclass)(*env)->NewGlobalRef(env, dc);
        g_ids.boolCls  = (jclass)(*env)->NewGlobalRef(env, bc);
        g_ids.charCls  = (jclass)(*env)->NewGlobalRef(env, cc);
        g_ids.byteCls  = (jclass)(*env)->NewGlobalRef(env, yc);
        g_ids.shortCls = (jclass)(*env)->NewGlobalRef(env, sc);
        g_ids.objCls   = (jclass)(*env)->NewGlobalRef(env, (*env)->FindClass(env,_ksL34()));
        g_ids.cceCls   = (jclass)(*env)->NewGlobalRef(env, (*env)->FindClass(env,_ksL35()));
    }
    if (ic)(*env)->DeleteLocalRef(env,ic); if (lc)(*env)->DeleteLocalRef(env,lc);
    if (fc)(*env)->DeleteLocalRef(env,fc); if (dc)(*env)->DeleteLocalRef(env,dc);
    if (bc)(*env)->DeleteLocalRef(env,bc); if (cc)(*env)->DeleteLocalRef(env,cc);
    if (yc)(*env)->DeleteLocalRef(env,yc); if (sc)(*env)->DeleteLocalRef(env,sc);

    /* These are string-literal concatenation macros (not variables): the JNI
     * signature is built from adjacent string literals, which C only folds at
     * compile time when each piece is a literal token. */
#define MR "Lcom/kbox/runtime/VmpInterpreter$VmpMethod;"
#define SJ "[Ljava/lang/Object;"
#define LJ "[J"
    g_ids.h.getStatic = (*env)->GetStaticMethodID(env,c, _ksL36(),
             "(" MR SJ SJ LJ ")I");
    g_ids.h.putStatic = (*env)->GetStaticMethodID(env,c, _ksL37(),
             "(" MR SJ SJ LJ ")I");
    g_ids.h.getField  = (*env)->GetStaticMethodID(env,c, _ksL38(),
             "(" MR SJ SJ LJ ")I");
    g_ids.h.putField  = (*env)->GetStaticMethodID(env,c, _ksL39(),
             "(" MR SJ SJ LJ ")I");
    g_ids.h.invoke    = (*env)->GetStaticMethodID(env,c, _ksL40(),
             "(" MR SJ SJ LJ "I)I");
    g_ids.h.new_      = (*env)->GetStaticMethodID(env,c, _ksL41(),
             "(" MR SJ SJ LJ ")I");
    g_ids.h.newArray  = (*env)->GetStaticMethodID(env,c, _ksL42(),
             "(" MR SJ SJ LJ "I)I");
    g_ids.h.arrayIndex= (*env)->GetStaticMethodID(env,c, _ksL43(),
             "(" MR SJ LJ "II)I");
    g_ids.h.checkCast = (*env)->GetStaticMethodID(env,c, _ksL44(),
             "(" MR SJ SJ LJ ")I");
    g_ids.h.instanceOf= (*env)->GetStaticMethodID(env,c, _ksL45(),
             "(" MR SJ SJ LJ ")I");
    g_ids.h.resolve   = (*env)->GetStaticMethodID(env,c, _ksL46(),
             "(" MR SJ LJ ")I");
    g_ids.h.monitor   = (*env)->GetStaticMethodID(env,c, _ksL47(),
             "(" MR SJ SJ LJ "I)I");
    g_ids.h.ret       = (*env)->GetStaticMethodID(env,c, _ksL48(),
             "(" MR SJ SJ LJ "I)I");
    g_ids.h.tryCatch  = (*env)->GetStaticMethodID(env,c, _ksL49(),
             "(" MR SJ LJ "Ljava/lang/Object;I)I");
#undef MR
#undef SJ
#undef LJ
    /* NB: exceptions thrown by helpers are checked after each CallStaticIntMethod */

    g_ids_init = 1;
}

/* =====================================================================
 * Type coercion helpers — must reproduce VmpInterpreter.toInt/toLong/
 * toFloat/toDouble semantics. Return 0 on invalid (caller-visible as an
 * exception path via a pending ClassCastException).
 * ===================================================================== */

KBOX_INLINE jint kbox_toIntOrThrow(JNIEnv* env, jobject o){
    if (!o) { (*env)->ThrowNew(env, g_ids.cceCls, _ksL50()); return 0; }
    if ((*env)->IsInstanceOf(env,o,g_ids.intCls)) {
        return (*env)->CallIntMethod(env,o,g_ids.intValue);
    }
    if ((*env)->IsInstanceOf(env,o,g_ids.boolCls)) {
        jboolean z=(*env)->CallBooleanMethod(env,o,g_ids.booleanValue); return z?1:0;
    }
    if ((*env)->IsInstanceOf(env,o,g_ids.charCls)) {
        return (jint)(*env)->CallCharMethod(env,o,g_ids.charValue);
    }
    if ((*env)->IsInstanceOf(env,o,g_ids.byteCls)) {
        return (jint)(*env)->CallByteMethod(env,o,g_ids.byteValue);
    }
    if ((*env)->IsInstanceOf(env,o,g_ids.shortCls)) {
        return (jint)(*env)->CallShortMethod(env,o,g_ids.shortValue);
    }
    (*env)->ThrowNew(env, g_ids.cceCls, _ksL50());
    return 0;
}

KBOX_INLINE jlong kbox_toLongOrThrow(JNIEnv* env, jobject o){
    if ((*env)->IsInstanceOf(env,o,g_ids.intCls)) return (jlong)(*env)->CallIntMethod(env,o,g_ids.intValue);
    if ((*env)->IsInstanceOf(env,o,g_ids.longCls)) return (jlong)(*env)->CallLongMethod(env,o,g_ids.longValue);
    (*env)->ThrowNew(env, g_ids.cceCls, _ksL50());
    return 0;
}

KBOX_INLINE jfloat kbox_toFloatOrThrow(JNIEnv* env, jobject o){
    if ((*env)->IsInstanceOf(env,o,g_ids.floatCls)) return (jfloat)(*env)->CallFloatMethod(env,o,g_ids.floatValue);
    if ((*env)->IsInstanceOf(env,o,g_ids.intCls)) return (jfloat)(*env)->CallIntMethod(env,o,g_ids.intValue);
    if ((*env)->IsInstanceOf(env,o,g_ids.longCls)) return (jfloat)(*env)->CallLongMethod(env,o,g_ids.longValue);
    (*env)->ThrowNew(env, g_ids.cceCls, _ksL50());
    return 0;
}

KBOX_INLINE jdouble kbox_toDoubleOrThrow(JNIEnv* env, jobject o){
    if ((*env)->IsInstanceOf(env,o,g_ids.doubleCls)) return (jdouble)(*env)->CallDoubleMethod(env,o,g_ids.doubleValue);
    if ((*env)->IsInstanceOf(env,o,g_ids.floatCls)) return (jdouble)(*env)->CallFloatMethod(env,o,g_ids.floatValue);
    if ((*env)->IsInstanceOf(env,o,g_ids.intCls)) return (jdouble)(*env)->CallIntMethod(env,o,g_ids.intValue);
    if ((*env)->IsInstanceOf(env,o,g_ids.longCls)) return (jdouble)(*env)->CallLongMethod(env,o,g_ids.longValue);
    (*env)->ThrowNew(env, g_ids.cceCls, _ksL50());
    return 0;
}

/* Boxing factories (cached classes; returns local ref or NULL on error). */
KBOX_INLINE jobject kbox_boxInt(JNIEnv* env, jint v){
    return (*env)->CallStaticObjectMethod(env, g_ids.intCls, g_ids.integerValueOf, v);
}
KBOX_INLINE jobject kbox_boxLong(JNIEnv* env, jlong v){
    return (*env)->CallStaticObjectMethod(env, g_ids.longCls, g_ids.longValueOf, v);
}
KBOX_INLINE jobject kbox_boxFloat(JNIEnv* env, jfloat v){
    return (*env)->CallStaticObjectMethod(env, g_ids.floatCls, g_ids.floatValueOf, v);
}
KBOX_INLINE jobject kbox_boxDouble(JNIEnv* env, jdouble v){
    return (*env)->CallStaticObjectMethod(env, g_ids.doubleCls, g_ids.doubleValueOf, v);
}

/* =====================================================================
 * CPU frame + VmpMethod field access.
 * ===================================================================== */

typedef struct {
    JNIEnv*        env;
    jobject        m;            /* VmpMethod */
    jobjectArray   stack;        /* Object[] operand stack (maxStack+16) */
    jobjectArray   locals;       /* Object[] locals (maxLocals) */
    jlong          cpu[3];       /* pc, sp, unwindFlg */
    uint8_t*       resident;     /* cached copy of m.resident bytes */
    int32_t        cipherLen;
    uint8_t        codeSet;      /* resident cache valid */
    jint           twin;
    jintArray      composite;    /* cached global/int array ref if exposed */
    const int32_t* compositePtr; /* direct pointer into jintArray (we pin via GetIntArrayElements) */
    jint*          compositeEls;
    int            compositePinned;
    int            maxStack;
    int            maxLocals;
    int            retKind;      /* last *RETURN kind (5 = void) to recover result */
} kbox_cpu_t;

/* VmpMethod field IDs (resolved each native call — cheap, idempotent). */
typedef struct {
    jfieldID resident, cipherLen, twin, composite, invPerm,
             maxStack, maxLocals, ephKey;
} kbox_mfield_t;

static kbox_mfield_t g_mf;
static int g_mf_init = 0;

static void kbox_load_mfield(JNIEnv* env){
    if (g_mf_init) return;
    jclass c = (*env)->FindClass(env, _ksL51());
    if (!c) return;
    g_mf.resident  = (*env)->GetFieldID(env,c,_ksL52(),_ksL53());
    g_mf.cipherLen = (*env)->GetFieldID(env,c,_ksL54(),_ksL55());
    g_mf.twin      = (*env)->GetFieldID(env,c,_ksL56(),_ksL55());
    g_mf.composite = (*env)->GetFieldID(env,c,_ksL57(),_ksL58());
    g_mf.invPerm   = (*env)->GetFieldID(env,c,_ksL59(),_ksL58());
    g_mf.maxStack  = (*env)->GetFieldID(env,c,_ksL60(),_ksL55());
    g_mf.maxLocals = (*env)->GetFieldID(env,c,_ksL61(),_ksL55());
    g_mf.ephKey    = (*env)->GetFieldID(env,c,_ksL62(),_ksL63());
    (*env)->DeleteLocalRef(env,c);
    g_mf_init = 1;
}

/* ==================================================================== */
/* Secure waveform allocation (wipe + unmap in one shot)                */
/* ==================================================================== */
/* Mirrors kbox_bf_loader.c's secureAlloc/secureFree so the working
 * ciphertext wave does NOT live in the Java heap nor in a malloc free-list
 * region: it is reserved as its own page-aligned virtual range (VirtualAlloc /
 * mmap) and wiped + unmapped the moment execution ends, so its address space
 * ceases to exist once consumed. Plaintext still never materializes (b()
 * decrypts one byte at a time), but even the ciphertext working copy is
 * isolated from both the Java heap and C heap scanners. */
static size_t g_vmpPage = 4096;
static size_t kbox_vmpPage(size_t n) {
    if (g_vmpPage == 0) g_vmpPage = 4096;
    return (n + g_vmpPage - 1) & ~(g_vmpPage - 1);
}
static void kbox_vmpWipe(void* p, size_t n) {
    if (p == NULL || n == 0) return;
    volatile uint8_t* v = (volatile uint8_t*)p;
    while (n--) *v++ = (uint8_t)0;
}
/* Grow-only secure arena. Wave buffers are carved from heap-less, self-mapped
 * pages that are (a) never reachable from Java heap scanners, and (b) reused
 * across executions instead of round-tripping VirtualAlloc/VirtualFree each
 * time (per-call alloc churn caused a ~12x slowdown). Backing pages are only
 * ever released at process exit; plaintext/keystream working copies are wiped
 * on release. Thread-safe via a cross-platform spinlock. */
typedef struct kbox_arena_blk {
    struct kbox_arena_blk* next;
    size_t                 cap;
    size_t                 used;
    uint8_t                data[];
} kbox_arena_blk;

static kbox_arena_blk*  g_blkHead = NULL;
static volatile long    g_arenaLock = 0;

static void kbox_vmpLock(void) {
    while (__sync_val_compare_and_swap(&g_arenaLock, 0, 1) != 0) { /* spin */ }
}
static void kbox_vmpUnlock(void) {
    __atomic_store_n(&g_arenaLock, 0, __ATOMIC_RELEASE);
}

static void* kbox_vmpAlloc(size_t n) {
    size_t cap = kbox_vmpPage(n > 0 ? n : 1);
    kbox_vmpLock();
    void* p = NULL;
    kbox_arena_blk* b = g_blkHead;
    if (b && cap <= b->cap - b->used) {
        p = b->data + b->used;
        b->used += cap;
    } else {
        size_t blkCap = cap;
        if (blkCap < ((size_t)1 << 20)) blkCap = ((size_t)1 << 20); /* 1MiB chunks */
        kbox_arena_blk* nb;
#if defined(_WIN32)
        nb = (kbox_arena_blk*)VirtualAlloc(NULL, sizeof(*nb) + blkCap,
                                             MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
#else
        nb = (kbox_arena_blk*)mmap(NULL, sizeof(*nb) + blkCap,
                                     PROT_READ | PROT_WRITE,
                                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (nb == MAP_FAILED) nb = NULL;
#endif
        if (nb) {
            nb->next = g_blkHead;
            nb->cap  = blkCap;
            nb->used = cap;
            g_blkHead = nb;
            p = nb->data;
        }
    }
    kbox_vmpUnlock();
    return p;
}
static void kbox_vmpFree(void* p, size_t used) {
    if (p == NULL) return;
    size_t cap = kbox_vmpPage(used > 0 ? used : 1);
    kbox_vmpWipe(p, cap);   /* wipe full page-rounded range */
    kbox_vmpLock();
    kbox_arena_blk* b = g_blkHead;
    if (b && (uint8_t*)p + cap == b->data + b->used) {
        /* last allocation in head block: LIFO rewind for immediate reuse.
         * Backing pages never leave the arena (guest-page swap cost is gone). */
        b->used -= cap;
    }
    kbox_vmpUnlock();
}

/* Per-position decrypted byte: b(pos) == wav[pos] ^ ksEph.at(pos).
 * The working wave (m.resident, per-run ciphertext) is copied ONCE into a
 * page-allocated secure native buffer (kbox_vmpAlloc) and never pinned from
 * the Java heap during the whole execution. The ephemeral keystream is derived
 * from m.ephKey (the 32-byte per-run key stored by the Java side). b() never
 * stores the plaintext — only this byte. */
typedef struct {
    uint8_t*      wav;       /* secure native copy of m.resident (ENCRYPTED) */
    size_t        waveLen;   /* number of bytes present in wav */
    kbox_keystream eph;
} kbox_stream_t;

static int kbox_prepare_stream(JNIEnv* env, jobject m, kbox_stream_t* st){
    st->wav = NULL; st->waveLen = 0;
    jobject resObj = (*env)->GetObjectField(env,m,g_mf.resident);
    if (!resObj) return 0;
    /* m.resident is an OFF-HEAP direct java.nio.ByteBuffer (②). Read it via its
     * native base address — never a Java heap byte[] — and copy into the secure
     * page arena (wiped+unmapped on release). Falls back to a legacy byte[] only
     * in case the field type was ever reverted. */
    void* dbase = (*env)->GetDirectBufferAddress(env, resObj);
    jlong dcap  = (*env)->GetDirectBufferCapacity(env, resObj);
    if (dbase != NULL && dcap > 0) {
        jsize srcLen = (jsize)dcap;
        st->wav = (uint8_t*)kbox_vmpAlloc((size_t)srcLen);
        if (!st->wav){ (*env)->DeleteLocalRef(env, resObj); return 0; }
        st->waveLen = (size_t)srcLen;
        if (srcLen > 0) memcpy(st->wav, dbase, (size_t)srcLen);
        (*env)->DeleteLocalRef(env, resObj);
    } else {
        /* legacy byte[] field fallback (defensive; not used by current build) */
        jbyteArray resArr = (jbyteArray)resObj;
        jsize rLen = (*env)->GetArrayLength(env, resArr);
        if (rLen < 1){ (*env)->DeleteLocalRef(env, resArr); return 0; }
        st->wav = (uint8_t*)kbox_vmpAlloc((size_t)rLen);
        if (!st->wav){ (*env)->DeleteLocalRef(env, resArr); return 0; }
        st->waveLen = (size_t)rLen;
        (*env)->GetByteArrayRegion(env, resArr, 0, rLen, (jbyte*)st->wav);
        (*env)->DeleteLocalRef(env, resArr);
    }
    /* ephemeral key from m.ephKey */
    jbyteArray ephArr = (jbyteArray)(*env)->GetObjectField(env,m,g_mf.ephKey);
    if (ephArr){
        jsize n = (*env)->GetArrayLength(env, ephArr);
        jbyte tmp[64]; int mv = (n>64)?64:n;
        (*env)->GetByteArrayRegion(env, ephArr, 0, mv, tmp);
        kbox_ks_init(&st->eph, (const uint8_t*)tmp, mv);
        (*env)->DeleteLocalRef(env, ephArr);
    } else {
        uint8_t z[32]; memset(z,0,32); kbox_ks_init(&st->eph,z,32);
    }
    return 1;
}

KBOX_INLINE int32_t kbox_b(kbox_stream_t* st, int32_t pos, int32_t cipherLen){
    if (pos < 0 || pos >= cipherLen) return 0;
    uint8_t res = (uint8_t)st->wav[pos];
    uint8_t ks  = kbox_ks_at(&st->eph, pos);
    return (int32_t)((res ^ ks) & 0xFF);
}

KBOX_INLINE int32_t kbox_i4(kbox_stream_t* st, int32_t pos, int32_t cipherLen){
    return (kbox_b(st,pos,cipherLen)<<24)
         | ((kbox_b(st,pos+1,cipherLen)&0xFF)<<16)
         | ((kbox_b(st,pos+2,cipherLen)&0xFF)<<8)
         | (kbox_b(st,pos+3,cipherLen)&0xFF);
}

KBOX_INLINE int32_t kbox_u2(kbox_stream_t* st, int32_t pos, int32_t cipherLen){
    return ((kbox_b(st,pos,cipherLen)&0xFF)<<8) | (kbox_b(st,pos+1,cipherLen)&0xFF);
}

/* ---- operand stack / locals access ---- */
KBOX_INLINE jobject kbox_pop(JNIEnv* env, kbox_cpu_t* cpu){
    int sp = (int)cpu->cpu[1] - 1;
    cpu->cpu[1] = sp;
    if (sp < 0) { (*env)->ThrowNew(env, (*env)->FindClass(env,_ksL64()),_ksL50()); return NULL; }
    return (*env)->GetObjectArrayElement(env, cpu->stack, sp);
}
KBOX_INLINE void kbox_push(JNIEnv* env, kbox_cpu_t* cpu, jobject v){
    int sp = (int)cpu->cpu[1]++;
    (*env)->SetObjectArrayElement(env, cpu->stack, sp, v);
}
KBOX_INLINE jobject kbox_load(JNIEnv* env, kbox_cpu_t* cpu, int idx){
    return (*env)->GetObjectArrayElement(env, cpu->locals, idx);
}
KBOX_INLINE void kbox_store(JNIEnv* env, kbox_cpu_t* cpu, int idx, jobject v){
    (*env)->SetObjectArrayElement(env, cpu->locals, idx, v);
}

/* =====================================================================
 * Object-model helper invocation (delegates to Java; returns 0 on success,
 * -1 means a pending JNI exception should abort the loop).
 * ===================================================================== */

/* The Java helper contract expects the CPU machine state as a long[] [pc,sp,flg]
 * so it can read inline operands (via VmpMethod.i4/u2 on pc) and set the unwind
 * flag. We marshal the C jlong[3] into a real Java long[] for the call and copy
 * it back afterwards. */
static jlongArray kbox_down_cpu(JNIEnv* env, kbox_cpu_t* cpu){
    jlongArray a = (*env)->NewLongArray(env, 3);
    if (!a) return NULL;
    (*env)->SetLongArrayRegion(env, a, 0, 3, cpu->cpu);
    return a;
}

static void kbox_up_cpu(JNIEnv* env, jlongArray a, kbox_cpu_t* cpu){
    if (a) (*env)->GetLongArrayRegion(env, a, 0, 3, cpu->cpu);
    if (a) (*env)->DeleteLocalRef(env, a);
}

/* Invoke a helper with signature (VmpMethod,Object[],Object[],long[])->int, no kind. */
static int kbox_helper4(JNIEnv* env, jmethodID mid, jobject m, jobjectArray st,
                        jobjectArray lo, kbox_cpu_t* cpu){
    jlongArray c = kbox_down_cpu(env, cpu);
    if (!c) return -1;
    (*env)->CallStaticIntMethod(env, kbox_find_interp_class(env), mid, m, st, lo, c);
    jint pend = (*env)->ExceptionCheck(env);
    kbox_up_cpu(env, c, cpu);
    return pend ? -1 : 0;
}

/* (VmpMethod,Object[],Object[],long[],int)->int */
static int kbox_helper5(JNIEnv* env, jmethodID mid, jobject m, jobjectArray st,
                        jobjectArray lo, kbox_cpu_t* cpu, jint kind){
    jlongArray c = kbox_down_cpu(env, cpu);
    if (!c) return -1;
    (*env)->CallStaticIntMethod(env, kbox_find_interp_class(env), mid, m, st, lo, c, kind);
    jint pend = (*env)->ExceptionCheck(env);
    kbox_up_cpu(env, c, cpu);
    return pend ? -1 : 0;
}

/* (VmpMethod,Object[],long[])->int */
static int kbox_helperStk(JNIEnv* env, jmethodID mid, jobject m, jobjectArray st, kbox_cpu_t* cpu){
    jlongArray c = kbox_down_cpu(env, cpu);
    if (!c) return -1;
    (*env)->CallStaticIntMethod(env, kbox_find_interp_class(env), mid, m, st, c);
    jint pend = (*env)->ExceptionCheck(env);
    kbox_up_cpu(env, c, cpu);
    return pend ? -1 : 0;
}

/* (VmpMethod,Object[],long[],int,int)->int  (array index) */
static int kbox_helperArr(JNIEnv* env, jobject m, jobjectArray st, kbox_cpu_t* cpu, jint gs, jint op){
    jlongArray c = kbox_down_cpu(env, cpu);
    if (!c) return -1;
    (*env)->CallStaticIntMethod(env, kbox_find_interp_class(env), g_ids.h.arrayIndex, m, st, c, gs, op);
    jint pend = (*env)->ExceptionCheck(env);
    kbox_up_cpu(env, c, cpu);
    return pend ? -1 : 0;
}

/* =====================================================================
 * Pure micro-op handlers (native). Each is a switch-case body operating on
 * cpu+stream. Returns 1 to unwind (a *RETURN/END ran and set cpu->cpu[2]).
 * We dispatch through computed-goto (GCC/Clang) or a function-pointer table
 * (MSVC) built from the composite permutation.
 * ===================================================================== */

typedef int (*kbox_handler_t)(kbox_cpu_t* cpu, kbox_stream_t* st);

static int h_ACONST_NULL(kbox_cpu_t* cpu,kbox_stream_t* st){ kbox_push(cpu->env,cpu,NULL); return 0; }
static int h_ICONST(kbox_cpu_t* cpu,kbox_stream_t* st){
    int32_t v=kbox_i4(st,(int32_t)cpu->cpu[0],cpu->cipherLen); cpu->cpu[0]+=4;
    kbox_push(cpu->env,cpu,kbox_boxInt(cpu->env,v)); return 0;
}
static int h_LCONST(kbox_cpu_t* cpu,kbox_stream_t* st){
    int32_t hi=kbox_i4(st,(int32_t)cpu->cpu[0]+0,cpu->cipherLen);
    int32_t lo=kbox_i4(st,(int32_t)cpu->cpu[0]+4,cpu->cipherLen);
    cpu->cpu[0]+=8;
    /* Java: ((long)hi<<32) | (i4(pc+4) & 0xFFFFFFFFL) — mask lo so a negative
       low word cannot smear 1s into the high 32 bits. */
    jlong v=((jlong)hi<<32) | ((jlong)lo & 0xFFFFFFFFL);
    kbox_push(cpu->env,cpu,kbox_boxLong(cpu->env,v)); return 0;
}
static int h_FCONST(kbox_cpu_t* cpu,kbox_stream_t* st){
    int32_t bits=kbox_i4(st,(int32_t)cpu->cpu[0],cpu->cipherLen); cpu->cpu[0]+=4;
    jfloat f; memcpy(&f,&bits,4);
    kbox_push(cpu->env,cpu,kbox_boxFloat(cpu->env,f)); return 0;
}
static int h_DCONST(kbox_cpu_t* cpu,kbox_stream_t* st){
    int32_t hi=kbox_i4(st,(int32_t)cpu->cpu[0]+0,cpu->cipherLen);
    int32_t lo=kbox_i4(st,(int32_t)cpu->cpu[0]+4,cpu->cipherLen);
    cpu->cpu[0]+=8;
    /* Java: ((long)hi<<32) | (i4(pc+4) & 0xFFFFFFFFL) — same low-word masking */
    jlong lv=((jlong)hi<<32)|((jlong)lo & 0xFFFFFFFFL); jdouble d; memcpy(&d,&lv,8);
    kbox_push(cpu->env,cpu,kbox_boxDouble(cpu->env,d)); return 0;
}
/* STRING/CLASS -> Java resolve (pushes cp entry) */
static int h_STRING(kbox_cpu_t* cpu,kbox_stream_t* st){
    return kbox_helperStk(cpu->env,g_ids.h.resolve,cpu->m,cpu->stack,cpu); /* reads m.i4(pc) itself */
}
static int h_CLASS(kbox_cpu_t* cpu,kbox_stream_t* st){
    return kbox_helperStk(cpu->env,g_ids.h.resolve,cpu->m,cpu->stack,cpu);
}

/* ---- loads (copy from locals Object[]) ---- */
#define KBOX_LOAD(kind) static int h_##kind##_LOAD(kbox_cpu_t* cpu,kbox_stream_t* st){ \
    int idx=kbox_u2(st,(int32_t)cpu->cpu[0],cpu->cipherLen); cpu->cpu[0]+=2; \
    kbox_push(cpu->env,cpu,kbox_load(cpu->env,cpu,idx)); return 0; }
KBOX_LOAD(IL) static int h_ILOAD(kbox_cpu_t* cpu,kbox_stream_t* st){ return h_IL_LOAD(cpu,st); }
KBOX_LOAD(LL) /* LLOAD */
KBOX_LOAD(FL) static int h_LLOAD(kbox_cpu_t* cpu,kbox_stream_t* st){ return h_LL_LOAD(cpu,st); }
KBOX_LOAD(DL) static int h_FLOAD(kbox_cpu_t* cpu,kbox_stream_t* st){ return h_DL_LOAD(cpu,st); }
KBOX_LOAD(AL) static int h_ALOAD(kbox_cpu_t* cpu,kbox_stream_t* st){ return h_AL_LOAD(cpu,st); }
static int h_DLOAD(kbox_cpu_t* cpu,kbox_stream_t* st){ return h_DL_LOAD(cpu,st); }

/* stores */
#define KBOX_STORE(kind) static int h_##kind##_STORE(kbox_cpu_t* cpu,kbox_stream_t* st){ \
    int idx=kbox_u2(st,(int32_t)cpu->cpu[0],cpu->cipherLen); cpu->cpu[0]+=2; \
    jobject v=kbox_pop(cpu->env,cpu); if(!v && (*cpu->env)->ExceptionCheck(cpu->env)) return -1; \
    kbox_store(cpu->env,cpu,idx,v); return 0; }
/* The I/F/D/A store bodies are identical (Object copy), so emit all three via
 * one macro after the IS one is inlined above. */
#define KBOX_STORE_FOR_LL KBOX_STORE(FS) KBOX_STORE(DS) KBOX_STORE(AS)
KBOX_STORE(IS) static int h_ISTORE(kbox_cpu_t* cpu,kbox_stream_t* st){ return h_IS_STORE(cpu,st); }
KBOX_STORE(LS) KBOX_STORE_FOR_LL
static int h_LSTORE(kbox_cpu_t* cpu,kbox_stream_t* st){ return h_LS_STORE(cpu,st); }
static int h_FSTORE(kbox_cpu_t* cpu,kbox_stream_t* st){ return h_FS_STORE(cpu,st); }
static int h_DSTORE(kbox_cpu_t* cpu,kbox_stream_t* st){ return h_DS_STORE(cpu,st); }
static int h_ASTORE(kbox_cpu_t* cpu,kbox_stream_t* st){ return h_AS_STORE(cpu,st); }

/* ---- int arithmetic (boxed) ---- */
#define KBOX_IBINOP(name, expr) static int h_##name(kbox_cpu_t* cpu,kbox_stream_t* st){ \
    JNIEnv* e=cpu->env; jobject b=kbox_pop(e,cpu); jobject a=kbox_pop(e,cpu); \
    jint bi=kbox_toIntOrThrow(e,b); if((*e)->ExceptionCheck(e)) return -1; \
    jint ai=kbox_toIntOrThrow(e,a); if((*e)->ExceptionCheck(e)) return -1; \
    jint r=(expr); kbox_push(e,cpu,kbox_boxInt(e,r)); return 0; }
/* IDIV special-cases div-by-zero */
static int h_IDIV(kbox_cpu_t* cpu,kbox_stream_t* st){
    JNIEnv* e=cpu->env; jobject b=kbox_pop(e,cpu); jobject a=kbox_pop(e,cpu);
    jint bi=kbox_toIntOrThrow(e,b); if((*e)->ExceptionCheck(e)) return -1;
    jint ai=kbox_toIntOrThrow(e,a); if((*e)->ExceptionCheck(e)) return -1;
    if (bi==0){ (*e)->ThrowNew(e,(*e)->FindClass(e,"java/lang/ArithmeticException"),"/ by zero"); return -1; }
    kbox_push(e,cpu,kbox_boxInt(e,(jint)(ai/bi))); return 0;
}
static int h_IREM(kbox_cpu_t* cpu,kbox_stream_t* st){
    JNIEnv* e=cpu->env; jobject b=kbox_pop(e,cpu); jobject a=kbox_pop(e,cpu);
    jint bi=kbox_toIntOrThrow(e,b); if((*e)->ExceptionCheck(e)) return -1;
    jint ai=kbox_toIntOrThrow(e,a); if((*e)->ExceptionCheck(e)) return -1;
    if (bi==0){ (*e)->ThrowNew(e,(*e)->FindClass(e,"java/lang/ArithmeticException"),"/ by zero"); return -1; }
    kbox_push(e,cpu,kbox_boxInt(e,(jint)(ai%bi))); return 0;
}
KBOX_IBINOP(IADD, ai+bi)
KBOX_IBINOP(ISUB, ai-bi)
KBOX_IBINOP(IMUL, ai*bi)
KBOX_IBINOP(ISHL, (jint)(ai<<(bi&0x1F)))
KBOX_IBINOP(ISHR, (jint)(ai>>(bi&0x1F)))
KBOX_IBINOP(IUSHR,(jint)((uint32_t)ai>>(bi&0x1F)))
KBOX_IBINOP(IAND, ai&bi)
KBOX_IBINOP(IOR,  ai|bi)
KBOX_IBINOP(IXOR, ai^bi)
static int h_INEG(kbox_cpu_t* cpu,kbox_stream_t* st){
    JNIEnv* e=cpu->env; jobject a=kbox_pop(e,cpu);
    jint ai=kbox_toIntOrThrow(e,a); if((*e)->ExceptionCheck(e)) return -1;
    kbox_push(e,cpu,kbox_boxInt(e,(jint)(-ai))); return 0;
}
static int h_IINC(kbox_cpu_t* cpu,kbox_stream_t* st){
    int idx=kbox_u2(st,(int32_t)cpu->cpu[0],cpu->cipherLen);
    int32_t delta=kbox_i4(st,(int32_t)cpu->cpu[0]+2,cpu->cipherLen);
    cpu->cpu[0]+=6;
    jobject v=kbox_load(cpu->env,cpu,idx);
    jint val=kbox_toIntOrThrow(cpu->env,v); if((*cpu->env)->ExceptionCheck(cpu->env)) return -1;
    kbox_store(cpu->env,cpu,idx,kbox_boxInt(cpu->env,(jint)(val+delta))); return 0;
}

/* ---- conversions (Java casts, matching toInt/toLong/toFloat/toDouble) ---- */
#define KBOX_CONV(name, get, box, cast) static int h_##name(kbox_cpu_t* cpu,kbox_stream_t* st){ \
    JNIEnv* e=cpu->env; jobject a=kbox_pop(e,cpu); \
    jvalue v=get(e,a); if((*e)->ExceptionCheck(e)) return -1; \
    kbox_push(e,cpu, box(e,(cast)v)); return 0; }
/* handled explicitly below to keep types right */
static int h_I2L(kbox_cpu_t* cpu,kbox_stream_t* st){ JNIEnv*e=cpu->env; jobject a=kbox_pop(e,cpu); jint v=kbox_toIntOrThrow(e,a); if((*e)->ExceptionCheck(e))return-1; kbox_push(e,cpu,kbox_boxLong(e,(jlong)v)); return 0; }
static int h_I2F(kbox_cpu_t* cpu,kbox_stream_t* st){ JNIEnv*e=cpu->env; jobject a=kbox_pop(e,cpu); jint v=kbox_toIntOrThrow(e,a); if((*e)->ExceptionCheck(e))return-1; kbox_push(e,cpu,kbox_boxFloat(e,(jfloat)v)); return 0; }
static int h_I2D(kbox_cpu_t* cpu,kbox_stream_t* st){ JNIEnv*e=cpu->env; jobject a=kbox_pop(e,cpu); jint v=kbox_toIntOrThrow(e,a); if((*e)->ExceptionCheck(e))return-1; kbox_push(e,cpu,kbox_boxDouble(e,(jdouble)v)); return 0; }
static int h_L2I(kbox_cpu_t* cpu,kbox_stream_t* st){ JNIEnv*e=cpu->env; jobject a=kbox_pop(e,cpu); jlong v=kbox_toLongOrThrow(e,a); if((*e)->ExceptionCheck(e))return-1; kbox_push(e,cpu,kbox_boxInt(e,(jint)v)); return 0; }
static int h_L2F(kbox_cpu_t* cpu,kbox_stream_t* st){ JNIEnv*e=cpu->env; jobject a=kbox_pop(e,cpu); jlong v=kbox_toLongOrThrow(e,a); if((*e)->ExceptionCheck(e))return-1; kbox_push(e,cpu,kbox_boxFloat(e,(jfloat)v)); return 0; }
static int h_L2D(kbox_cpu_t* cpu,kbox_stream_t* st){ JNIEnv*e=cpu->env; jobject a=kbox_pop(e,cpu); jlong v=kbox_toLongOrThrow(e,a); if((*e)->ExceptionCheck(e))return-1; kbox_push(e,cpu,kbox_boxDouble(e,(jdouble)v)); return 0; }
static int h_F2I(kbox_cpu_t* cpu,kbox_stream_t* st){ JNIEnv*e=cpu->env; jobject a=kbox_pop(e,cpu); jfloat v=kbox_toFloatOrThrow(e,a); if((*e)->ExceptionCheck(e))return-1; kbox_push(e,cpu,kbox_boxInt(e,(jint)v)); return 0; }
static int h_F2L(kbox_cpu_t* cpu,kbox_stream_t* st){ JNIEnv*e=cpu->env; jobject a=kbox_pop(e,cpu); jfloat v=kbox_toFloatOrThrow(e,a); if((*e)->ExceptionCheck(e))return-1; kbox_push(e,cpu,kbox_boxLong(e,(jlong)v)); return 0; }
static int h_F2D(kbox_cpu_t* cpu,kbox_stream_t* st){ JNIEnv*e=cpu->env; jobject a=kbox_pop(e,cpu); jfloat v=kbox_toFloatOrThrow(e,a); if((*e)->ExceptionCheck(e))return-1; kbox_push(e,cpu,kbox_boxDouble(e,(jdouble)v)); return 0; }
static int h_D2I(kbox_cpu_t* cpu,kbox_stream_t* st){ JNIEnv*e=cpu->env; jobject a=kbox_pop(e,cpu); jdouble v=kbox_toDoubleOrThrow(e,a); if((*e)->ExceptionCheck(e))return-1; kbox_push(e,cpu,kbox_boxInt(e,(jint)v)); return 0; }
static int h_D2L(kbox_cpu_t* cpu,kbox_stream_t* st){ JNIEnv*e=cpu->env; jobject a=kbox_pop(e,cpu); jdouble v=kbox_toDoubleOrThrow(e,a); if((*e)->ExceptionCheck(e))return-1; kbox_push(e,cpu,kbox_boxLong(e,(jlong)v)); return 0; }
static int h_D2F(kbox_cpu_t* cpu,kbox_stream_t* st){ JNIEnv*e=cpu->env; jobject a=kbox_pop(e,cpu); jdouble v=kbox_toDoubleOrThrow(e,a); if((*e)->ExceptionCheck(e))return-1; kbox_push(e,cpu,kbox_boxFloat(e,(jfloat)v)); return 0; }
static int h_I2B(kbox_cpu_t* cpu,kbox_stream_t* st){ JNIEnv*e=cpu->env; jobject a=kbox_pop(e,cpu); jint v=kbox_toIntOrThrow(e,a); if((*e)->ExceptionCheck(e))return-1; kbox_push(e,cpu,kbox_boxInt(e,(jint)(jbyte)v)); return 0; }
static int h_I2C(kbox_cpu_t* cpu,kbox_stream_t* st){ JNIEnv*e=cpu->env; jobject a=kbox_pop(e,cpu); jint v=kbox_toIntOrThrow(e,a); if((*e)->ExceptionCheck(e))return-1; kbox_push(e,cpu,kbox_boxInt(e,(jint)(jchar)v)); return 0; }
static int h_I2S(kbox_cpu_t* cpu,kbox_stream_t* st){ JNIEnv*e=cpu->env; jobject a=kbox_pop(e,cpu); jint v=kbox_toIntOrThrow(e,a); if((*e)->ExceptionCheck(e))return-1; kbox_push(e,cpu,kbox_boxInt(e,(jint)(jshort)v)); return 0; }

/* ---- long arithmetic ---- */
#define KBOX_LBINOP(name, expr) static int h_##name(kbox_cpu_t* cpu,kbox_stream_t* st){ \
    JNIEnv* e=cpu->env; jobject b=kbox_pop(e,cpu); jobject a=kbox_pop(e,cpu); \
    jlong bi=kbox_toLongOrThrow(e,b); if((*e)->ExceptionCheck(e)) return -1; \
    jlong ai=kbox_toLongOrThrow(e,a); if((*e)->ExceptionCheck(e)) return -1; \
    kbox_push(e,cpu,kbox_boxLong(e,(expr))); return 0; }
KBOX_LBINOP(LADD, ai+bi) KBOX_LBINOP(LSUB, ai-bi) KBOX_LBINOP(LMUL, ai*bi)
KBOX_LBINOP(LAND, ai&bi) KBOX_LBINOP(LOR, ai|bi) KBOX_LBINOP(LXOR, ai^bi)
static int h_LDIV(kbox_cpu_t* cpu,kbox_stream_t* st){
    JNIEnv*e=cpu->env; jobject b=kbox_pop(e,cpu); jobject a=kbox_pop(e,cpu);
    jlong bi=kbox_toLongOrThrow(e,b); if((*e)->ExceptionCheck(e))return-1;
    jlong ai=kbox_toLongOrThrow(e,a); if((*e)->ExceptionCheck(e))return-1;
    if (bi==0){ (*e)->ThrowNew(e,(*e)->FindClass(e,"java/lang/ArithmeticException"),"/ by zero"); return -1; }
    kbox_push(e,cpu,kbox_boxLong(e,(ai/bi))); return 0;
}
static int h_LREM(kbox_cpu_t* cpu,kbox_stream_t* st){
    JNIEnv*e=cpu->env; jobject b=kbox_pop(e,cpu); jobject a=kbox_pop(e,cpu);
    jlong bi=kbox_toLongOrThrow(e,b); if((*e)->ExceptionCheck(e))return-1;
    jlong ai=kbox_toLongOrThrow(e,a); if((*e)->ExceptionCheck(e))return-1;
    if (bi==0){ (*e)->ThrowNew(e,(*e)->FindClass(e,"java/lang/ArithmeticException"),"/ by zero"); return -1; }
    kbox_push(e,cpu,kbox_boxLong(e,(ai%bi))); return 0;
}
static int h_LNEG(kbox_cpu_t* cpu,kbox_stream_t* st){
    JNIEnv*e=cpu->env; jobject a=kbox_pop(e,cpu);
    jlong v=kbox_toLongOrThrow(e,a); if((*e)->ExceptionCheck(e))return-1;
    kbox_push(e,cpu,kbox_boxLong(e,(jlong)(-v))); return 0;
}
#define KBOX_LSHIFT(name, opshift) static int h_##name(kbox_cpu_t* cpu,kbox_stream_t* st){ \
    JNIEnv*e=cpu->env; jobject b=kbox_pop(e,cpu); jobject a=kbox_pop(e,cpu); \
    jint bi=kbox_toIntOrThrow(e,b); if((*e)->ExceptionCheck(e))return-1; \
    jlong ai=kbox_toLongOrThrow(e,a); if((*e)->ExceptionCheck(e))return-1; \
    kbox_push(e,cpu,kbox_boxLong(e,(ai opshift (bi&0x3F)))); return 0; }
KBOX_LSHIFT(LSHL, <<) KBOX_LSHIFT(LSHR, >>)
static int h_LUSHR(kbox_cpu_t* cpu,kbox_stream_t* st){
    JNIEnv*e=cpu->env; jobject b=kbox_pop(e,cpu); jobject a=kbox_pop(e,cpu);
    jint bi=kbox_toIntOrThrow(e,b); if((*e)->ExceptionCheck(e))return-1;
    jlong ai=kbox_toLongOrThrow(e,a); if((*e)->ExceptionCheck(e))return-1;
    kbox_push(e,cpu,kbox_boxLong(e,(jlong)((uint64_t)ai>>(bi&0x3F)))); return 0;
}
static int h_LCMP(kbox_cpu_t* cpu,kbox_stream_t* st){
    JNIEnv*e=cpu->env; jobject b=kbox_pop(e,cpu); jobject a=kbox_pop(e,cpu);
    jlong bi=kbox_toLongOrThrow(e,b); if((*e)->ExceptionCheck(e))return-1;
    jlong ai=kbox_toLongOrThrow(e,a); if((*e)->ExceptionCheck(e))return-1;
    kbox_push(e,cpu,kbox_boxInt(e,(jint)(ai==bi?0:(ai<bi?-1:1)))); return 0;
}

/* ---- float/double arithmetic ---- */
#define KBOX_FBINOP(name, op, cast) static int h_##name(kbox_cpu_t* cpu,kbox_stream_t* st){ \
    JNIEnv*e=cpu->env; jobject b=kbox_pop(e,cpu); jobject a=kbox_pop(e,cpu); \
    cast v1=kbox_toFloatOrThrow(e,a); if((*e)->ExceptionCheck(e))return-1; \
    cast v2=kbox_toFloatOrThrow(e,b); if((*e)->ExceptionCheck(e))return-1; \
    kbox_push(e,cpu,kbox_boxFloat(e,(v1 op v2))); return 0; }
KBOX_FBINOP(FADD,+,jfloat) KBOX_FBINOP(FSUB,-,jfloat) KBOX_FBINOP(FMUL,*,jfloat) KBOX_FBINOP(FDIV,/,jfloat)
static int h_FREM(kbox_cpu_t* cpu,kbox_stream_t* st){
    JNIEnv*e=cpu->env; jobject b=kbox_pop(e,cpu); jobject a=kbox_pop(e,cpu);
    jfloat v1=kbox_toFloatOrThrow(e,a); if((*e)->ExceptionCheck(e))return-1;
    jfloat v2=kbox_toFloatOrThrow(e,b); if((*e)->ExceptionCheck(e))return-1;
    kbox_push(e,cpu,kbox_boxFloat(e,(float)fmod(v1,v2))); return 0;
}
static int h_FNEG(kbox_cpu_t* cpu,kbox_stream_t* st){
    JNIEnv*e=cpu->env; jobject a=kbox_pop(e,cpu);
    jfloat v=kbox_toFloatOrThrow(e,a); if((*e)->ExceptionCheck(e))return-1;
    kbox_push(e,cpu,kbox_boxFloat(e,(jfloat)(-v))); return 0;
}
/* Replicate Java Float.compare / Double.compare exactly. */
static uint32_t kbox_fToBits(jfloat f){
    uint32_t b; memcpy(&b,&f,4);
    if (isnan(f)) b = 0x7fc00000u;
    return b;
}
static jint kbox_fcompare(jfloat f1, jfloat f2){
    if (f1 < f2) return -1;
    if (f1 > f2) return 1;
    int32_t b1=(int32_t)kbox_fToBits(f1), b2=(int32_t)kbox_fToBits(f2);
    return (b1 == b2) ? 0 : ((b1 < b2) ? -1 : 1);
}
static uint64_t kbox_dToBits(jdouble d){
    uint64_t b; memcpy(&b,&d,8);
    if (isnan(d)) b = 0x7ff8000000000000ULL;
    return b;
}
static jint kbox_dcompare(jdouble d1, jdouble d2){
    if (d1 < d2) return -1;
    if (d1 > d2) return 1;
    int64_t b1=(int64_t)kbox_dToBits(d1), b2=(int64_t)kbox_dToBits(d2);
    return (b1 == b2) ? 0 : ((b1 < b2) ? -1 : 1);
}
static int h_FCMPL(kbox_cpu_t* cpu,kbox_stream_t* st){
    JNIEnv*e=cpu->env; jobject b=kbox_pop(e,cpu); jobject a=kbox_pop(e,cpu);
    jfloat v1=kbox_toFloatOrThrow(e,a); if((*e)->ExceptionCheck(e))return-1;
    jfloat v2=kbox_toFloatOrThrow(e,b); if((*e)->ExceptionCheck(e))return-1;
    jint r; if (isnan(v1)||isnan(v2)) r=-1; else if (v1==v2) r=0; else if (v1<v2) r=-1; else r=1; /* fcmpl: NaN->-1, +-0.0->0 */
    kbox_push(e,cpu,kbox_boxInt(e,r)); return 0;
}
static int h_FCMPG(kbox_cpu_t* cpu,kbox_stream_t* st){
    JNIEnv*e=cpu->env; jobject b=kbox_pop(e,cpu); jobject a=kbox_pop(e,cpu);
    jfloat v1=kbox_toFloatOrThrow(e,a); if((*e)->ExceptionCheck(e))return-1;
    jfloat v2=kbox_toFloatOrThrow(e,b); if((*e)->ExceptionCheck(e))return-1;
    jint r; if (v1==v2) r=0; else if (v1<v2) r=-1; else r=1; /* fcmpg: NaN falls through to +1 */
    kbox_push(e,cpu,kbox_boxInt(e,r)); return 0;
}
#define KBOX_DBINOP(name, op) static int h_##name(kbox_cpu_t* cpu,kbox_stream_t* st){ \
    JNIEnv*e=cpu->env; jobject b=kbox_pop(e,cpu); jobject a=kbox_pop(e,cpu); \
    jdouble v1=kbox_toDoubleOrThrow(e,a); if((*e)->ExceptionCheck(e))return-1; \
    jdouble v2=kbox_toDoubleOrThrow(e,b); if((*e)->ExceptionCheck(e))return-1; \
    kbox_push(e,cpu,kbox_boxDouble(e,(v1 op v2))); return 0; }
KBOX_DBINOP(DADD,+) KBOX_DBINOP(DSUB,-) KBOX_DBINOP(DMUL,*) KBOX_DBINOP(DDIV,/)
static int h_DREM(kbox_cpu_t* cpu,kbox_stream_t* st){
    JNIEnv*e=cpu->env; jobject b=kbox_pop(e,cpu); jobject a=kbox_pop(e,cpu);
    jdouble v1=kbox_toDoubleOrThrow(e,a); if((*e)->ExceptionCheck(e))return-1;
    jdouble v2=kbox_toDoubleOrThrow(e,b); if((*e)->ExceptionCheck(e))return-1;
    kbox_push(e,cpu,kbox_boxDouble(e,(double)fmod(v1,v2))); return 0;
}
static int h_DNEG(kbox_cpu_t* cpu,kbox_stream_t* st){
    JNIEnv*e=cpu->env; jobject a=kbox_pop(e,cpu);
    jdouble v=kbox_toDoubleOrThrow(e,a); if((*e)->ExceptionCheck(e))return-1;
    kbox_push(e,cpu,kbox_boxDouble(e,(jdouble)(-v))); return 0;
}
static int h_DCMPL(kbox_cpu_t* cpu,kbox_stream_t* st){
    JNIEnv*e=cpu->env; jobject b=kbox_pop(e,cpu); jobject a=kbox_pop(e,cpu);
    jdouble v1=kbox_toDoubleOrThrow(e,a); if((*e)->ExceptionCheck(e))return-1;
    jdouble v2=kbox_toDoubleOrThrow(e,b); if((*e)->ExceptionCheck(e))return-1;
    jint r; if (isnan(v1)||isnan(v2)) r=-1; else if (v1==v2) r=0; else if (v1<v2) r=-1; else r=1; /* dcmpl: NaN->-1, +-0.0->0 */
    kbox_push(e,cpu,kbox_boxInt(e,r)); return 0;
}
static int h_DCMPG(kbox_cpu_t* cpu,kbox_stream_t* st){
    JNIEnv*e=cpu->env; jobject b=kbox_pop(e,cpu); jobject a=kbox_pop(e,cpu);
    jdouble v1=kbox_toDoubleOrThrow(e,a); if((*e)->ExceptionCheck(e))return-1;
    jdouble v2=kbox_toDoubleOrThrow(e,b); if((*e)->ExceptionCheck(e))return-1;
    jint r; if (v1==v2) r=0; else if (v1<v2) r=-1; else r=1; /* dcmpg: NaN falls through to +1 */
    kbox_push(e,cpu,kbox_boxInt(e,r)); return 0;
}

/* ---- branches ---- */
#define KBOX_IFZOP(name, cond) static int h_##name(kbox_cpu_t* cpu,kbox_stream_t* st){ \
    JNIEnv*e=cpu->env; int32_t t=kbox_i4(st,(int32_t)cpu->cpu[0],cpu->cipherLen); cpu->cpu[0]+=4; \
    jobject a=kbox_pop(e,cpu); jint v=kbox_toIntOrThrow(e,a); if((*e)->ExceptionCheck(e))return -1; \
    if (cond) cpu->cpu[0]=t; return 0; }
KBOX_IFZOP(IFEQ, v==0) KBOX_IFZOP(IFNE, v!=0) KBOX_IFZOP(IFLT, v<0)
KBOX_IFZOP(IFGE, v>=0) KBOX_IFZOP(IFGT, v>0) KBOX_IFZOP(IFLE, v<=0)
#define KBOX_IFICMP(name, cond) static int h_##name(kbox_cpu_t* cpu,kbox_stream_t* st){ \
    JNIEnv*e=cpu->env; int32_t t=kbox_i4(st,(int32_t)cpu->cpu[0],cpu->cipherLen); cpu->cpu[0]+=4; \
    jobject b=kbox_pop(e,cpu); jobject a=kbox_pop(e,cpu); \
    jint v1=kbox_toIntOrThrow(e,a); if((*e)->ExceptionCheck(e))return -1; \
    jint v2=kbox_toIntOrThrow(e,b); if((*e)->ExceptionCheck(e))return -1; \
    if (v1 cond v2) cpu->cpu[0]=t; return 0; }
KBOX_IFICMP(IF_ICMPEQ,==) KBOX_IFICMP(IF_ICMPNE,!=) KBOX_IFICMP(IF_ICMPLT,<)
KBOX_IFICMP(IF_ICMPGE,>=) KBOX_IFICMP(IF_ICMPGT,>) KBOX_IFICMP(IF_ICMPLE,<=)
#define KBOX_IFACMP(name, eq) static int h_##name(kbox_cpu_t* cpu,kbox_stream_t* st){ \
    JNIEnv*e=cpu->env; int32_t t=kbox_i4(st,(int32_t)cpu->cpu[0],cpu->cipherLen); cpu->cpu[0]+=4; \
    jobject b=kbox_pop(e,cpu); jobject a=kbox_pop(e,cpu); \
    if ((eq)) cpu->cpu[0]=t; return 0; }
KBOX_IFACMP(IF_ACMPEQ, a==b) KBOX_IFACMP(IF_ACMPNE, a!=b)
#define KBOX_IFACZ(name, nn) static int h_##name(kbox_cpu_t* cpu,kbox_stream_t* st){ \
    JNIEnv*e=cpu->env; int32_t t=kbox_i4(st,(int32_t)cpu->cpu[0],cpu->cipherLen); cpu->cpu[0]+=4; \
    jobject a=kbox_pop(e,cpu); if ((nn)) cpu->cpu[0]=t; return 0; }
KBOX_IFACZ(IFNULL, a==NULL) KBOX_IFACZ(IFNONNULL, a!=NULL)
static int h_GOTO(kbox_cpu_t* cpu,kbox_stream_t* st){
    cpu->cpu[0]=kbox_i4(st,(int32_t)cpu->cpu[0],cpu->cipherLen); return 0;
}

/* ---- stack manipulation ---- */
static int h_POP(kbox_cpu_t* cpu,kbox_stream_t* st){ cpu->cpu[1]-=1; return 0; }
static int h_POP2(kbox_cpu_t* cpu,kbox_stream_t* st){ cpu->cpu[1]-=2; return 0; }
static int h_DUP(kbox_cpu_t* cpu,kbox_stream_t* st){
    int sp=(int)cpu->cpu[1]; jobject v=(*cpu->env)->GetObjectArrayElement(cpu->env,cpu->stack,sp-1);
    (*cpu->env)->SetObjectArrayElement(cpu->env,cpu->stack,sp,v); cpu->cpu[1]+=1; return 0;
}
static int h_DUP_X1(kbox_cpu_t* cpu,kbox_stream_t* st){
    JNIEnv*e=cpu->env; int sp=(int)cpu->cpu[1];
    jobject v1=(*e)->GetObjectArrayElement(e,cpu->stack,sp-1);
    jobject v2=(*e)->GetObjectArrayElement(e,cpu->stack,sp-2);
    (*e)->SetObjectArrayElement(e,cpu->stack,sp,v1);
    (*e)->SetObjectArrayElement(e,cpu->stack,sp-1,v2);
    (*e)->SetObjectArrayElement(e,cpu->stack,sp-2,v1);
    cpu->cpu[1]+=1; return 0;
}
static int h_DUP_X2(kbox_cpu_t* cpu,kbox_stream_t* st){
    JNIEnv*e=cpu->env; int sp=(int)cpu->cpu[1];
    jobject v1=(*e)->GetObjectArrayElement(e,cpu->stack,sp-1);
    jobject v2=(*e)->GetObjectArrayElement(e,cpu->stack,sp-2);
    jobject v3=(*e)->GetObjectArrayElement(e,cpu->stack,sp-3);
    (*e)->SetObjectArrayElement(e,cpu->stack,sp,v1);
    (*e)->SetObjectArrayElement(e,cpu->stack,sp-1,v2);
    (*e)->SetObjectArrayElement(e,cpu->stack,sp-2,v3);
    (*e)->SetObjectArrayElement(e,cpu->stack,sp-3,v1);
    cpu->cpu[1]+=1; return 0;
}
static int h_DUP2(kbox_cpu_t* cpu,kbox_stream_t* st){
    JNIEnv*e=cpu->env; int sp=(int)cpu->cpu[1];
    jobject v1=(*e)->GetObjectArrayElement(e,cpu->stack,sp-1);
    jobject v2=(*e)->GetObjectArrayElement(e,cpu->stack,sp-2);
    (*e)->SetObjectArrayElement(e,cpu->stack,sp,v1);
    (*e)->SetObjectArrayElement(e,cpu->stack,sp+1,v2);
    cpu->cpu[1]+=2; return 0;
}
static int h_DUP2_X1(kbox_cpu_t* cpu,kbox_stream_t* st){
    JNIEnv*e=cpu->env; int sp=(int)cpu->cpu[1];
    jobject v1=(*e)->GetObjectArrayElement(e,cpu->stack,sp-1);
    jobject v2=(*e)->GetObjectArrayElement(e,cpu->stack,sp-2);
    jobject v3=(*e)->GetObjectArrayElement(e,cpu->stack,sp-3);
    (*e)->SetObjectArrayElement(e,cpu->stack,sp,v1);
    (*e)->SetObjectArrayElement(e,cpu->stack,sp+1,v2);
    (*e)->SetObjectArrayElement(e,cpu->stack,sp-1,v3);
    (*e)->SetObjectArrayElement(e,cpu->stack,sp-2,v1);
    (*e)->SetObjectArrayElement(e,cpu->stack,sp-3,v2);
    cpu->cpu[1]+=2; return 0;
}
/* DUP2_X2 (JVMS 6.5): ..., v4, v3, v2, v1 -> ..., v2, v1, v4, v3, v2, v1.
 * Single-slot model collapses all four forms to this 4-slot rotation; must
 * stay byte-identical with VmpInterpreter.OP_HANDLER[0xCD] and the JNIC v3
 * interpreter (kbox_jnic_interp_v3.c DUP2_X2). */
static int h_DUP2_X2(kbox_cpu_t* cpu,kbox_stream_t* st){
    JNIEnv*e=cpu->env; int sp=(int)cpu->cpu[1];
    jobject v1=(*e)->GetObjectArrayElement(e,cpu->stack,sp-1);
    jobject v2=(*e)->GetObjectArrayElement(e,cpu->stack,sp-2);
    jobject v3=(*e)->GetObjectArrayElement(e,cpu->stack,sp-3);
    jobject v4=(*e)->GetObjectArrayElement(e,cpu->stack,sp-4);
    (*e)->SetObjectArrayElement(e,cpu->stack,sp-4,v2);
    (*e)->SetObjectArrayElement(e,cpu->stack,sp-3,v1);
    (*e)->SetObjectArrayElement(e,cpu->stack,sp-2,v4);
    (*e)->SetObjectArrayElement(e,cpu->stack,sp-1,v3);
    (*e)->SetObjectArrayElement(e,cpu->stack,sp,v2);
    (*e)->SetObjectArrayElement(e,cpu->stack,sp+1,v1);
    cpu->cpu[1]+=2; return 0;
}
static int h_SWAP(kbox_cpu_t* cpu,kbox_stream_t* st){
    JNIEnv*e=cpu->env; int sp=(int)cpu->cpu[1];
    jobject v1=(*e)->GetObjectArrayElement(e,cpu->stack,sp-1);
    jobject v2=(*e)->GetObjectArrayElement(e,cpu->stack,sp-2);
    (*e)->SetObjectArrayElement(e,cpu->stack,sp-1,v2);
    (*e)->SetObjectArrayElement(e,cpu->stack,sp-2,v1);
    return 0;
}

/* ---- field access -> Java ---- */
static int h_GETSTATIC(kbox_cpu_t* cpu,kbox_stream_t* st){ return kbox_helper4(cpu->env,g_ids.h.getStatic,cpu->m,cpu->stack,cpu->locals,cpu); }
static int h_PUTSTATIC(kbox_cpu_t* cpu,kbox_stream_t* st){ return kbox_helper4(cpu->env,g_ids.h.putStatic,cpu->m,cpu->stack,cpu->locals,cpu); }
static int h_GETFIELD(kbox_cpu_t* cpu,kbox_stream_t* st){ return kbox_helper4(cpu->env,g_ids.h.getField,cpu->m,cpu->stack,cpu->locals,cpu); }
static int h_PUTFIELD(kbox_cpu_t* cpu,kbox_stream_t* st){ return kbox_helper4(cpu->env,g_ids.h.putField,cpu->m,cpu->stack,cpu->locals,cpu); }

/* ---- invocation -> Java ---- */
static int h_INVOKEVIRTUAL(kbox_cpu_t* cpu,kbox_stream_t* st){ return kbox_helper5(cpu->env,g_ids.h.invoke,cpu->m,cpu->stack,cpu->locals,cpu,0); }
static int h_INVOKESPECIAL(kbox_cpu_t* cpu,kbox_stream_t* st){ return kbox_helper5(cpu->env,g_ids.h.invoke,cpu->m,cpu->stack,cpu->locals,cpu,1); }
static int h_INVOKESTATIC(kbox_cpu_t* cpu,kbox_stream_t* st){ return kbox_helper5(cpu->env,g_ids.h.invoke,cpu->m,cpu->stack,cpu->locals,cpu,2); }
static int h_INVOKEINTERFACE(kbox_cpu_t* cpu,kbox_stream_t* st){ return kbox_helper5(cpu->env,g_ids.h.invoke,cpu->m,cpu->stack,cpu->locals,cpu,3); }

/* ---- type / new / arrays -> Java ---- */
static int h_NEW(kbox_cpu_t* cpu,kbox_stream_t* st){ return kbox_helper4(cpu->env,g_ids.h.new_,cpu->m,cpu->stack,cpu->locals,cpu); }
static int h_NEWARRAY(kbox_cpu_t* cpu,kbox_stream_t* st){ return kbox_helper5(cpu->env,g_ids.h.newArray,cpu->m,cpu->stack,cpu->locals,cpu,1); }
static int h_ANEWARRAY(kbox_cpu_t* cpu,kbox_stream_t* st){ return kbox_helper5(cpu->env,g_ids.h.newArray,cpu->m,cpu->stack,cpu->locals,cpu,0); }
static int h_ARRAYLENGTH(kbox_cpu_t* cpu,kbox_stream_t* st){ return kbox_helperArr(cpu->env,cpu->m,cpu->stack,cpu,0,0); }
static int h_AALOAD(kbox_cpu_t* cpu,kbox_stream_t* st){ return kbox_helperArr(cpu->env,cpu->m,cpu->stack,cpu,0,1); }
static int h_AASTORE(kbox_cpu_t* cpu,kbox_stream_t* st){ return kbox_helperArr(cpu->env,cpu->m,cpu->stack,cpu,1,1); }
static int h_IALOAD(kbox_cpu_t* cpu,kbox_stream_t* st){ return kbox_helperArr(cpu->env,cpu->m,cpu->stack,cpu,0,2); }
static int h_IASTORE(kbox_cpu_t* cpu,kbox_stream_t* st){ return kbox_helperArr(cpu->env,cpu->m,cpu->stack,cpu,1,2); }
static int h_BALOAD(kbox_cpu_t* cpu,kbox_stream_t* st){ return kbox_helperArr(cpu->env,cpu->m,cpu->stack,cpu,0,3); }
static int h_BASTORE(kbox_cpu_t* cpu,kbox_stream_t* st){ return kbox_helperArr(cpu->env,cpu->m,cpu->stack,cpu,1,3); }
static int h_CALOAD(kbox_cpu_t* cpu,kbox_stream_t* st){ return kbox_helperArr(cpu->env,cpu->m,cpu->stack,cpu,0,4); }
static int h_CASTORE(kbox_cpu_t* cpu,kbox_stream_t* st){ return kbox_helperArr(cpu->env,cpu->m,cpu->stack,cpu,1,4); }
static int h_SALOAD(kbox_cpu_t* cpu,kbox_stream_t* st){ return kbox_helperArr(cpu->env,cpu->m,cpu->stack,cpu,0,5); }
static int h_SASTORE(kbox_cpu_t* cpu,kbox_stream_t* st){ return kbox_helperArr(cpu->env,cpu->m,cpu->stack,cpu,1,5); }
/* LALOAD/FALOAD/DALOAD/LASTORE/FASTORE/DASTORE — native, mirror Java's
 * Array.getLong/getFloat/getDouble/setLong/setFloat/setDouble semantics
 * (NPE on null array, ArrayIndexOutOfBoundsException on bad index). */
static int h_LALOAD(kbox_cpu_t* cpu,kbox_stream_t* st){
    JNIEnv*e=cpu->env; jobject idx=kbox_pop(e,cpu); jint i=kbox_toIntOrThrow(e,idx); if((*e)->ExceptionCheck(e))return-1;
    jobject a=kbox_pop(e,cpu);
    if(!a){ (*e)->ThrowNew(e,(*e)->FindClass(e,"java/lang/NullPointerException"),"KBox"); return -1; }
    jint len=(*e)->GetArrayLength(e,(jarray)a);
    if(i<0||i>=len){ (*e)->ThrowNew(e,(*e)->FindClass(e,"java/lang/ArrayIndexOutOfBoundsException"),"KBox"); return -1; }
    jlong v=0; (*e)->GetLongArrayRegion(e,(jlongArray)a,i,1,&v);
    if((*e)->ExceptionCheck(e))return-1;
    kbox_push(e,cpu,kbox_boxLong(e,v)); return 0;
}
static int h_FALOAD(kbox_cpu_t* cpu,kbox_stream_t* st){
    JNIEnv*e=cpu->env; jobject idx=kbox_pop(e,cpu); jint i=kbox_toIntOrThrow(e,idx); if((*e)->ExceptionCheck(e))return-1;
    jobject a=kbox_pop(e,cpu);
    if(!a){ (*e)->ThrowNew(e,(*e)->FindClass(e,"java/lang/NullPointerException"),"KBox"); return -1; }
    jint len=(*e)->GetArrayLength(e,(jarray)a);
    if(i<0||i>=len){ (*e)->ThrowNew(e,(*e)->FindClass(e,"java/lang/ArrayIndexOutOfBoundsException"),"KBox"); return -1; }
    jfloat v=0; (*e)->GetFloatArrayRegion(e,(jfloatArray)a,i,1,&v);
    if((*e)->ExceptionCheck(e))return-1;
    kbox_push(e,cpu,kbox_boxFloat(e,v)); return 0;
}
static int h_DALOAD(kbox_cpu_t* cpu,kbox_stream_t* st){
    JNIEnv*e=cpu->env; jobject idx=kbox_pop(e,cpu); jint i=kbox_toIntOrThrow(e,idx); if((*e)->ExceptionCheck(e))return-1;
    jobject a=kbox_pop(e,cpu);
    if(!a){ (*e)->ThrowNew(e,(*e)->FindClass(e,"java/lang/NullPointerException"),"KBox"); return -1; }
    jint len=(*e)->GetArrayLength(e,(jarray)a);
    if(i<0||i>=len){ (*e)->ThrowNew(e,(*e)->FindClass(e,"java/lang/ArrayIndexOutOfBoundsException"),"KBox"); return -1; }
    jdouble v=0; (*e)->GetDoubleArrayRegion(e,(jdoubleArray)a,i,1,&v);
    if((*e)->ExceptionCheck(e))return-1;
    kbox_push(e,cpu,kbox_boxDouble(e,v)); return 0;
}
static int h_LASTORE(kbox_cpu_t* cpu,kbox_stream_t* st){
    JNIEnv*e=cpu->env; jobject bj=kbox_pop(e,cpu); jlong v=kbox_toLongOrThrow(e,bj); if((*e)->ExceptionCheck(e))return-1;
    jobject idx=kbox_pop(e,cpu); jint i=kbox_toIntOrThrow(e,idx); if((*e)->ExceptionCheck(e))return-1;
    jobject a=kbox_pop(e,cpu);
    if(!a){ (*e)->ThrowNew(e,(*e)->FindClass(e,"java/lang/NullPointerException"),"KBox"); return -1; }
    jint len=(*e)->GetArrayLength(e,(jarray)a);
    if(i<0||i>=len){ (*e)->ThrowNew(e,(*e)->FindClass(e,"java/lang/ArrayIndexOutOfBoundsException"),"KBox"); return -1; }
    (*e)->SetLongArrayRegion(e,(jlongArray)a,i,1,&v);
    if((*e)->ExceptionCheck(e))return-1;
    return 0;
}
static int h_FASTORE(kbox_cpu_t* cpu,kbox_stream_t* st){
    JNIEnv*e=cpu->env; jobject bj=kbox_pop(e,cpu); jfloat v=kbox_toFloatOrThrow(e,bj); if((*e)->ExceptionCheck(e))return-1;
    jobject idx=kbox_pop(e,cpu); jint i=kbox_toIntOrThrow(e,idx); if((*e)->ExceptionCheck(e))return-1;
    jobject a=kbox_pop(e,cpu);
    if(!a){ (*e)->ThrowNew(e,(*e)->FindClass(e,"java/lang/NullPointerException"),"KBox"); return -1; }
    jint len=(*e)->GetArrayLength(e,(jarray)a);
    if(i<0||i>=len){ (*e)->ThrowNew(e,(*e)->FindClass(e,"java/lang/ArrayIndexOutOfBoundsException"),"KBox"); return -1; }
    (*e)->SetFloatArrayRegion(e,(jfloatArray)a,i,1,&v);
    if((*e)->ExceptionCheck(e))return-1;
    return 0;
}
static int h_DASTORE(kbox_cpu_t* cpu,kbox_stream_t* st){
    JNIEnv*e=cpu->env; jobject bj=kbox_pop(e,cpu); jdouble v=kbox_toDoubleOrThrow(e,bj); if((*e)->ExceptionCheck(e))return-1;
    jobject idx=kbox_pop(e,cpu); jint i=kbox_toIntOrThrow(e,idx); if((*e)->ExceptionCheck(e))return-1;
    jobject a=kbox_pop(e,cpu);
    if(!a){ (*e)->ThrowNew(e,(*e)->FindClass(e,"java/lang/NullPointerException"),"KBox"); return -1; }
    jint len=(*e)->GetArrayLength(e,(jarray)a);
    if(i<0||i>=len){ (*e)->ThrowNew(e,(*e)->FindClass(e,"java/lang/ArrayIndexOutOfBoundsException"),"KBox"); return -1; }
    (*e)->SetDoubleArrayRegion(e,(jdoubleArray)a,i,1,&v);
    if((*e)->ExceptionCheck(e))return-1;
    return 0;
}
static int h_CHECKCAST(kbox_cpu_t* cpu,kbox_stream_t* st){ return kbox_helper4(cpu->env,g_ids.h.checkCast,cpu->m,cpu->stack,cpu->locals,cpu); }
static int h_INSTANCEOF(kbox_cpu_t* cpu,kbox_stream_t* st){ return kbox_helper4(cpu->env,g_ids.h.instanceOf,cpu->m,cpu->stack,cpu->locals,cpu); }

/* ---- monitor -> Java (throws) ---- */
static int h_MONITORENTER(kbox_cpu_t* cpu,kbox_stream_t* st){ return kbox_helper5(cpu->env,g_ids.h.monitor,cpu->m,cpu->stack,cpu->locals,cpu,0); }
static int h_MONITOREXIT(kbox_cpu_t* cpu,kbox_stream_t* st){ return kbox_helper5(cpu->env,g_ids.h.monitor,cpu->m,cpu->stack,cpu->locals,cpu,1); }
/* ---- athrow -> Java (throws; must consult exception table) --- */
static int h_ATHROW(kbox_cpu_t* cpu,kbox_stream_t* st){
    return kbox_helper5(cpu->env,g_ids.h.monitor,cpu->m,cpu->stack,cpu->locals,cpu,2); /* kind=2 => athrow */
}

/* ---- returns -> Java boxes result, sets cpu[2]=1 ---- */
static int h_IRETURN(kbox_cpu_t* cpu,kbox_stream_t* st){ cpu->retKind=0; return kbox_helper5(cpu->env,g_ids.h.ret,cpu->m,cpu->stack,cpu->locals,cpu,0); }
static int h_LRETURN(kbox_cpu_t* cpu,kbox_stream_t* st){ cpu->retKind=1; return kbox_helper5(cpu->env,g_ids.h.ret,cpu->m,cpu->stack,cpu->locals,cpu,1); }
static int h_FRETURN(kbox_cpu_t* cpu,kbox_stream_t* st){ cpu->retKind=2; return kbox_helper5(cpu->env,g_ids.h.ret,cpu->m,cpu->stack,cpu->locals,cpu,2); }
static int h_DRETURN(kbox_cpu_t* cpu,kbox_stream_t* st){ cpu->retKind=3; return kbox_helper5(cpu->env,g_ids.h.ret,cpu->m,cpu->stack,cpu->locals,cpu,3); }
static int h_ARETURN(kbox_cpu_t* cpu,kbox_stream_t* st){ cpu->retKind=4; return kbox_helper5(cpu->env,g_ids.h.ret,cpu->m,cpu->stack,cpu->locals,cpu,4); }
static int h_RETURN(kbox_cpu_t* cpu,kbox_stream_t* st){ cpu->retKind=5; return kbox_helper5(cpu->env,g_ids.h.ret,cpu->m,cpu->stack,cpu->locals,cpu,5); }
/* Illegal/unknown opcode -> fail-closed, mirroring the Java interpreter's
 * VmpInterpreter.execute(): `if (h == null) throw new RuntimeException("KBox")`.
 * Raising the generic KBox and returning -1 lets the dispatch loop's exception
 * path consult THIS method's exception table exactly like Java (a catch-all may
 * still handle it; otherwise it propagates as a generic KBox failure). The real
 * opcode is never disclosed. */
static int h_ILLEGAL(kbox_cpu_t* cpu,kbox_stream_t* st){
    JNIEnv*e=cpu->env;
    jclass rte=(*e)->FindClass(e,"java/lang/RuntimeException");
    if (rte){ (*e)->ThrowNew(e,rte,"KBox"); (*e)->DeleteLocalRef(e,rte); }
    return -1;
}
static int h_END(kbox_cpu_t* cpu,kbox_stream_t* st){ cpu->cpu[2]=1; return 1; }
/* NOP (VortexVM/L2 interleave filler, real VmpOp 0x45). The dispatch loop has
 * already advanced pc past this 1-byte opcode (opcode fetch advances pc+1 and
 * pure no-operand ops never touch pc again), so this is a pure no-op — the
 * exact counterpart of the Java interpreter's OP_HANDLER[0x45] = c -> false.
 * Its only purpose is proportional anti-analysis run-cost: an interleaved
 * globally-unpredictable number of no-ops per translated VM instruction. */
static int h_NOP(kbox_cpu_t* cpu,kbox_stream_t* st){ (void)cpu; (void)st; return 0; }

/* =====================================================================
 * Dispatch. Opaque pointer table indexed by handler SLOT (0..255). Slot is
 * the output of composite[twin ^ raw]; the real VmpOp is never formed.
 * ===================================================================== */

#if KBOX_ATT_DISP
/* computed-goto friendly default: use a table + switch dispatcher (portable) */
#define KBOX_DISP_TABLE 1
#endif

static const kbox_handler_t* g_handler_table = NULL;
static kbox_handler_t        g_handler_store[256];
static int                   g_handler_init = 0;

/* The handler table is keyed by REAL VmpOp; slot->handler is chosen by the
 * Java composite/microPerm. To keep the C table coincident with the Java
 * handlers[micro[op]] layout we simply fill by opcode; the SLOT value from
 * composite[twin^raw] equals micro[realOp], and we map slot -> handler by
 * inversing: handlerForSlot = table[invMicro[slotLower]]... To be robust we
 * derive the mapping purely in native from composite by NOT inverting; instead
 * the interpreter computes the REAL op from invPerm and looks up OP_HANDLER.
 *
 * IMPORTANT: to guarantee opcode semantic == Java semantic we decode the REAL
 * op (op = invPerm[twin ^ raw]) — matching Java's micro[real] slot ONLY maps
 * to a handler SLOT, but the C code here is keyed by real op. Both agree on
 * semantics; the native side materializes `op` transiently (single byte, wiped
 * at end of iteration) which is the same transient exposure Java has on its
 * error path. This is the pragmatic correctness-first choice; a pure slot-
 * dispatch variant can replace the table indirection later.
 */

static void kbox_init_handlers(void){
    if (g_handler_init) return;
    kbox_handler_t* T = g_handler_store;
    for (int i=0;i<256;i++) T[i]=h_ILLEGAL;   /* default: fail-closed (mirrors Java's null-slot "KBox") */
    T[0x01]=h_ACONST_NULL; T[0x02]=h_ICONST; T[0x03]=h_LCONST; T[0x04]=h_FCONST;
    T[0x05]=h_DCONST;      T[0x06]=h_STRING; T[0x07]=h_CLASS;
    T[0x10]=h_ILOAD; T[0x11]=h_LLOAD; T[0x12]=h_FLOAD; T[0x13]=h_DLOAD; T[0x14]=h_ALOAD;
    T[0x18]=h_ISTORE; T[0x19]=h_LSTORE; T[0x1A]=h_FSTORE; T[0x1B]=h_DSTORE; T[0x1C]=h_ASTORE;
    T[0x20]=h_IADD; T[0x21]=h_ISUB; T[0x22]=h_IMUL; T[0x23]=h_IDIV; T[0x24]=h_IREM;
    T[0x25]=h_INEG; T[0x26]=h_ISHL; T[0x27]=h_ISHR; T[0x28]=h_IUSHR;
    T[0x29]=h_IAND; T[0x2A]=h_IOR; T[0x2B]=h_IXOR; T[0x2C]=h_IINC;
    T[0x2D]=h_I2L; T[0x2E]=h_I2F; T[0x2F]=h_I2D;
    T[0xA0]=h_L2I; T[0xA1]=h_L2F; T[0xA2]=h_L2D;
    T[0xA3]=h_F2I; T[0xA4]=h_F2L; T[0xA5]=h_F2D;
    T[0xA6]=h_D2I; T[0xA7]=h_D2L; T[0xA8]=h_D2F;
    T[0xA9]=h_I2B; T[0xAA]=h_I2C; T[0xAB]=h_I2S;
    T[0xAC]=h_LCMP; T[0xAD]=h_LADD; T[0xAE]=h_LSUB; T[0xAF]=h_LMUL;
    T[0xB0]=h_LDIV; T[0xB1]=h_LREM; T[0xB2]=h_LNEG;
    T[0xB3]=h_LSHL; T[0xB4]=h_LSHR; T[0xB5]=h_LUSHR;
    T[0xB6]=h_LAND; T[0xB7]=h_LOR; T[0xB8]=h_LXOR;
    T[0xB9]=h_FADD; T[0xBA]=h_FSUB; T[0xBB]=h_FMUL; T[0xBC]=h_FDIV;
    T[0xBD]=h_FREM; T[0xBE]=h_FNEG;
    T[0xBF]=h_DADD; T[0xC0]=h_DSUB; T[0xC1]=h_DMUL; T[0xC2]=h_DDIV;
    T[0xC3]=h_DREM; T[0xC4]=h_DNEG;
    T[0xC5]=h_FCMPL; T[0xC6]=h_FCMPG; T[0xC7]=h_DCMPL; T[0xC8]=h_DCMPG;
    T[0x30]=h_IFEQ; T[0x31]=h_IFNE; T[0x32]=h_IFLT; T[0x33]=h_IFGE;
    T[0x34]=h_IFGT; T[0x35]=h_IFLE;
    T[0x36]=h_IF_ICMPEQ; T[0x37]=h_IF_ICMPNE; T[0x38]=h_IF_ICMPLT;
    T[0x39]=h_IF_ICMPGE; T[0x3A]=h_IF_ICMPGT; T[0x3B]=h_IF_ICMPLE;
    T[0x3C]=h_IFNULL; T[0x3D]=h_IFNONNULL;
    T[0x3E]=h_GOTO; T[0x3F]=h_IF_ACMPEQ; T[0xC9]=h_IF_ACMPNE;
    T[0x40]=h_POP; T[0x41]=h_POP2; T[0x42]=h_DUP; T[0x43]=h_DUP_X1;
    T[0xCA]=h_DUP_X2; T[0xCB]=h_DUP2; T[0xCC]=h_DUP2_X1; T[0xCD]=h_DUP2_X2; T[0x44]=h_SWAP;
    T[0x45]=h_NOP;   /* VortexVM/L2 interleave filler (no-op) */
    T[0x50]=h_GETSTATIC; T[0x51]=h_PUTSTATIC; T[0x52]=h_GETFIELD; T[0x53]=h_PUTFIELD;
    T[0x60]=h_INVOKEVIRTUAL; T[0x61]=h_INVOKESPECIAL; T[0x62]=h_INVOKESTATIC; T[0x63]=h_INVOKEINTERFACE;
    T[0x70]=h_NEW; T[0x71]=h_NEWARRAY; T[0x72]=h_ANEWARRAY; T[0x73]=h_ARRAYLENGTH;
    T[0x74]=h_AALOAD; T[0x75]=h_AASTORE; T[0x76]=h_IALOAD; T[0x77]=h_IASTORE;
    T[0x7A]=h_BALOAD; T[0x7B]=h_BASTORE; T[0x7C]=h_CALOAD; T[0x7D]=h_CASTORE;
    T[0x7E]=h_SALOAD; T[0x7F]=h_SASTORE;
    T[0x83]=h_LALOAD; T[0x84]=h_FALOAD; T[0x85]=h_DALOAD;
    T[0x86]=h_LASTORE; T[0x87]=h_FASTORE; T[0x88]=h_DASTORE;
    T[0x78]=h_CHECKCAST; T[0x79]=h_INSTANCEOF;
    T[0x80]=h_MONITORENTER; T[0x81]=h_MONITOREXIT; T[0x82]=h_ATHROW;
    T[0x90]=h_IRETURN; T[0x91]=h_LRETURN; T[0x92]=h_FRETURN; T[0x93]=h_DRETURN;
    T[0x94]=h_ARETURN; T[0x95]=h_RETURN;
    T[0xFF]=h_END;
    g_handler_init = 1;
}

/* =====================================================================
 * Public entry point — must mirror VmpInterpreterNative stage-1 bridge:
 *   static native Object execute(VmpMethod m, Object instance, Object[] args)
 * ===================================================================== */

JNIEXPORT jobject JNICALL Java_com_kbox_runtime_VmpInterpreterNative_execute(
        JNIEnv* env, jclass self, jobject m, jobject instance, jobjectArray args){
    kbox_resolve_ids(env);
    kbox_load_mfield(env);
    kbox_init_handlers();

    if (!g_ids_init || !g_mf_init){
        (*env)->ThrowNew(env, (*env)->FindClass(env,"java/lang/RuntimeException"),
            "KBox");
        return NULL;
    }

    /* ---- create operand stack & locals arrays ---- */
    jint maxStack  = (*env)->GetIntField(env, m, g_mf.maxStack);
    jint maxLocals = (*env)->GetIntField(env, m, g_mf.maxLocals);
    jclass objCls = (*env)->FindClass(env, "java/lang/Object");

    jobjectArray stack  = (*env)->NewObjectArray(env, maxStack + 16, objCls, NULL);
    jobjectArray locals = (*env)->NewObjectArray(env, maxLocals, objCls, NULL);
    if (stack==NULL || locals==NULL) return NULL;
    (*env)->DeleteLocalRef(env, objCls);

    /* ---- load locals: instance first, then args ---- */
    int li = 0;
    if (instance != NULL){
        (*env)->SetObjectArrayElement(env, locals, li++, instance);
    }
    if (args != NULL){
        jsize na = (*env)->GetArrayLength(env, args);
        for (jsize i=0;i<na;i++){
            jobject a = (*env)->GetObjectArrayElement(env, args, i);
            (*env)->SetObjectArrayElement(env, locals, li++, a);
            (*env)->DeleteLocalRef(env, a);
        }
    }

    /* ---- CPU frame ---- */
    kbox_cpu_t cpu; memset(&cpu,0,sizeof(cpu));
    cpu.env = env; cpu.m = m;
    cpu.stack = stack; cpu.locals = locals;
    cpu.cpu[0]=0; cpu.cpu[1]=0; cpu.cpu[2]=0;   /* pc=0; operand-stack sp EMPTY (locals separate) */
    cpu.maxStack = maxStack; cpu.maxLocals = maxLocals;
    cpu.twin = (*env)->GetIntField(env, m, g_mf.twin);
    cpu.cipherLen = (*env)->GetIntField(env, m, g_mf.cipherLen);

    /* ---- stream (resident + eph keystream) ---- */
    kbox_stream_t st; memset(&st,0,sizeof(st));
    if (!kbox_prepare_stream(env, m, &st)){
        (*env)->ThrowNew(env, (*env)->FindClass(env,"java/lang/RuntimeException"),
            "KBox");
        return NULL;
    }

    /* ---- composite array copy (plain ints) ---- */
    jintArray composite = (jintArray)(*env)->GetObjectField(env, m, g_mf.composite);
    jint compositeEls[256];
    if (composite){
        jint* ptr = (*env)->GetIntArrayElements(env, composite, NULL);
        jsize n = (*env)->GetArrayLength(env, composite);
        if (n>256) n=256;
        memcpy(compositeEls, ptr, (size_t)n*sizeof(jint));
        if (n<256) for (jsize k=n;k<256;k++) compositeEls[k]=(jint)k;
        (*env)->ReleaseIntArrayElements(env, composite, ptr, JNI_ABORT);
        (*env)->DeleteLocalRef(env, composite);
    } else {
        for (int k=0;k<256;k++) compositeEls[k]=(jint)k;
    }
    /* ---- invPerm copy (plain ints) ---- */
    jintArray invPermArr = (jintArray)(*env)->GetObjectField(env, m, g_mf.invPerm);
    jint invPermEls[256];
    if (invPermArr){
        jint* ptr = (*env)->GetIntArrayElements(env, invPermArr, NULL);
        jsize n = (*env)->GetArrayLength(env, invPermArr);
        if (n>256) n=256;
        memcpy(invPermEls, ptr, (size_t)n*sizeof(jint));
        if (n<256) for (jsize k=n;k<256;k++) invPermEls[k]=(jint)k;
        (*env)->ReleaseIntArrayElements(env, invPermArr, ptr, JNI_ABORT);
        (*env)->DeleteLocalRef(env, invPermArr);
    } else {
        for (int k=0;k<256;k++) invPermEls[k]=(jint)k;
    }

    /* Build the native handler table indexed by dispatch SLOT, replicating
     * Java's `m.handlers` layout:
     *   Java: handlers[micro[op]]         = OP_HANDLER[op]
     *         slot = composite[twin^raw]  = micro[inv[twin^raw]]
     *   C  :  for t in 0..255:            realOp = invPerm[t]
     *         T2[composite[t]]            = g_handler_store[realOp]
     * So dispatch slot = composite[twin^raw]:
     *   T2[slot] = g_handler_store[invPerm[twin^raw]]  matches Java EXACTLY,
     * and the real VmpOp is never materialized (slot-only dispatch, same as Java).
     * composite and invPerm are both permutations, so every slot 0..255 is set. */
    kbox_handler_t slotTable[256];
    for (int i=0;i<256;i++) slotTable[i]=h_ILLEGAL;
    for (int t=0;t<256;t++){
        int slot = compositeEls[t];
        if (slot>=0 && slot<256) slotTable[slot] = g_handler_store[invPermEls[t] & 0xFF];
    }

    /* dispatch: slot = composite[twin ^ raw]; run slotTable[slot]. Neither the
     * real VmpOp nor the micro-slot is held longer than one iteration.
     * Robustness closure: a step cap (bounded well above any legit run) turns a
     * tampered/runaway jump loop into a generic failure instead of an unbounded
     * busy-spin (DoS), so no crafted ciphertext can hang the process. */
    int64_t steps = 0;
    const int64_t VMP_MAX_STEPS = ((int64_t)1 << 31);
    int rc = 0;
    for (;;){
        if ((*env)->ExceptionCheck(env)){ rc=-1; break; }
        if (++steps > VMP_MAX_STEPS){
            rc = -2; break;                       /* runaway loop -> generic fail */
        }
        int32_t pc = (int32_t)cpu.cpu[0];
        if (pc < 0 || pc >= cpu.cipherLen) break;             /* END / past end */
        int raw = kbox_b(&st, pc, cpu.cipherLen);
        cpu.cpu[0] = pc + 1;                                   /* advance past opcode */
        int combo = compositeEls[(cpu.twin ^ raw) & 0xFF];
        kbox_handler_t h = slotTable[combo & 0xFF];
        int r = h(&cpu, &st);
        if (r < 0 && (*env)->ExceptionCheck(env)){
            /* Closed-state-machine exception handling: a helper surfaced a JNI
             * exception (an invoked callee threw, athrow, a coercing helper, ...).
             * Before unwinding, consult THIS method's exception table — if opcode
             * pc is covered and the catch type matches, clear the pending JNI
             * exception, push the (unwrapped) exception and jump to the handler,
             * exactly like the Java-fallback interpreter's post-dispatch catch.
             * If no local handler matches, re-raise the original exception so the
             * invoking context (or the JVM) sees it. */
            jobject exc = (*env)->ExceptionOccurred(env);
            (*env)->ExceptionClear(env);
            jint handled = 0;
            jlongArray c = kbox_down_cpu(env, &cpu);
            if (c){
                handled = (*env)->CallStaticIntMethod(env, kbox_find_interp_class(env),
                                g_ids.h.tryCatch, m, stack, c, exc, (jint)pc);
                kbox_up_cpu(env, c, &cpu);
                (*env)->DeleteLocalRef(env, c);
                if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
            }
            if (handled == 1){
                if (exc) (*env)->DeleteLocalRef(env, exc);
                continue;                          /* resume dispatch at handler pc */
            }
            if (exc){ (*env)->Throw(env, exc); (*env)->DeleteLocalRef(env, exc); }
            rc = -1; break;                        /* pending exception rethrown by JVM */
        }
        if (r < 0){ rc=-1; break; }                            /* exception propagated */
        if (r == 1) break;                                     /* END unwound */
        if (cpu.cpu[2]) break;                                 /* RETURN/ATHROW-unwind set by Java helper */
    }

    /* ---- release stream: wipe + unmap the secure wave buffer ---- */
    if (st.wav){ kbox_vmpFree(st.wav, st.waveLen); st.wav = NULL; st.waveLen = 0; }

    if (rc == -2){
        (*env)->ThrowNew(env, (*env)->FindClass(env,"java/lang/RuntimeException"), "KBox");
    }
    if (rc != 0){
        (*env)->DeleteLocalRef(env, stack);
        (*env)->DeleteLocalRef(env, locals);
        return NULL;                                          /* pending JNI exception rethrown by JVM */
    }

    /* Result is at the top of the operand stack (nlReturn left it there and set
     * cpu[2]=1). A void RETURN (retKind==5) produces no value. */
    jobject ret = NULL;
    if (cpu.cpu[2] && cpu.retKind != 5 && cpu.cpu[1] > 0){
        ret = (*env)->GetObjectArrayElement(env, stack, (jsize)(cpu.cpu[1]-1));
    }
    jobject global = (*env)->NewGlobalRef(env, ret);          /* survive DeleteLocalRef of stack */
    (*env)->DeleteLocalRef(env, stack);
    (*env)->DeleteLocalRef(env, locals);
    (*env)->DeleteLocalRef(env, self);
    return global;                                            /* caller releases via DeleteLocalRef in Java bridge */
}

/* =====================================================================
 * Explicit native binding for cross-ClassLoader execution.
 *
 * VmpInterpreterNative lives inside the BfSecureLoader blob, i.e. it is
 * defined by a child ClassLoader. Automatic JNI symbol resolution for such a
 * class only consults that child's library list, which -- because the VMP DLL
 * is loaded by System.load from NativeLoader (a parent-loader class) -- does
 * NOT contain the DLL, so execute() would never resolve. RegisterNatives with
 * the exact Class object binds the function regardless of which loader defined
 * the class. Called by VmpInterpreterNative.tryExecute() once, right after
 * loadVmp() succeeds, passing VmpInterpreterNative.class.
 * ===================================================================== */
JNIEXPORT void JNICALL Java_com_kbox_runtime_NativeLoader_registerVmpNatives0
    (JNIEnv* env, jclass loaderClass, jclass targetClass){
    (void)loaderClass;
    if (targetClass == NULL) return;
    JNINativeMethod nm;
    nm.name = "execute";
    nm.signature =
        "(Lcom/kbox/runtime/VmpInterpreter$VmpMethod;Ljava/lang/Object;"
        "[Ljava/lang/Object;)Ljava/lang/Object;";
    nm.fnPtr = (void*)Java_com_kbox_runtime_VmpInterpreterNative_execute;
    if ((*env)->RegisterNatives(env, targetClass, &nm, 1) != 0){
        /* Clear any exception; tryExecute will then observe UnsatisfiedLinkError
         * on the real call and degrade to the Java interpreter. */
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
    }
}