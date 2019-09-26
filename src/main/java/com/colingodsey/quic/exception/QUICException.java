package com.colingodsey.quic.exception;

public final class QUICException extends Exception {
    private static final long serialVersionUID = 4L;

    static QUICException[] instances = new QUICException[512];

    public final Code code;

    static {
        for (Code code : Code.values()) {
            instances[code.code] = new QUICException(code);
        }
    }

    public static QUICException get(Code code) {
        return instances[code.code];
    }

    public static QUICException get(int code) {
        return instances[code];
    }

    public static QUICException getTLS(int code) {
        return instances[Code.CRYPTO_ERROR_0.code + code];
    }

    QUICException(Code code) {
        super("QUIC transport error");
        this.code = code;
    }

    @Override
    public String getMessage() {
        return code.toString();
    }

    @Override
    public Throwable initCause(Throwable cause) {
        return this;
    }

    @Override
    public Throwable fillInStackTrace() {
        return this;
    }

    public enum Code {
        /** An endpoint uses this with CONNECTION_CLOSE to signal that the connection is being closed abruptly in the absence of any error. */
        NO_ERROR(0x0),
        /** The endpoint encountered an internal error and cannot continue with the connection. */
        INTERNAL_ERROR(0x1),
        /** The server is currently busy and does not accept any new connections. */
        SERVER_BUSY(0x2),
        /** An endpoint received more data than it permitted in its advertised data limits (see Section 4). */
        FLOW_CONTROL_ERROR(0x3),
        /** An endpoint received a frame for a stream identifier that exceeded its advertised stream limit for the corresponding stream type. */
        STREAM_LIMIT_ERROR(0x4),
        /** An endpoint received a frame for a stream that was not in a state that permitted that frame (see Section 3). */
        STREAM_STATE_ERROR(0x5),
        /** An endpoint received a STREAM frame containing data that exceeded the previously established final size. Or an endpoint received a STREAM frame or a RESET_STREAM frame containing a final size that was lower than the size of stream data that was already received. Or an endpoint received a STREAM frame or a RESET_STREAM frame containing a different final size to the one already established. */
        FINAL_SIZE_ERROR(0x6),
        /** An endpoint received a frame that was badly formatted. For instance, a frame of an unknown type, or an ACK frame that has more acknowledgment ranges than the remainder of the packet could carry. */
        FRAME_ENCODING_ERROR(0x7),
        /** An endpoint received transport parameters that were badly formatted, included an invalid value, was absent even though it is mandatory, was present though it is forbidden, or is otherwise in error. */
        TRANSPORT_PARAMETER_ERROR(0x8),
        /** An endpoint detected an error with protocol compliance that was not covered by more specific error codes. */
        PROTOCOL_VIOLATION(0xA),
        /** An endpoint has received more data in CRYPTO frames than it can buffer. */
        CRYPTO_BUFFER_EXCEEDED(0xD),
        /** The cryptographic handshake failed. A range of 256 values is reserved for carrying error codes specific to the cryptographic handshake that is used. Codes for errors occurring when TLS is used for the crypto handshake are described in Section 4.8 of [QUIC-TLS]. */
        CRYPTO_ERROR_0(0x100),
        CRYPTO_ERROR_1(0x101),
        CRYPTO_ERROR_2(0x102),
        CRYPTO_ERROR_3(0x103),
        CRYPTO_ERROR_4(0x104),
        CRYPTO_ERROR_5(0x105),
        CRYPTO_ERROR_6(0x106),
        CRYPTO_ERROR_7(0x107),
        CRYPTO_ERROR_8(0x108),
        CRYPTO_ERROR_9(0x109),
        CRYPTO_ERROR_10(0x10A),
        CRYPTO_ERROR_11(0x10B),
        CRYPTO_ERROR_12(0x10C),
        CRYPTO_ERROR_13(0x10D),
        CRYPTO_ERROR_14(0x10E),
        CRYPTO_ERROR_15(0x10F),
        CRYPTO_ERROR_16(0x110),
        CRYPTO_ERROR_17(0x111),
        CRYPTO_ERROR_18(0x112),
        CRYPTO_ERROR_19(0x113),
        CRYPTO_ERROR_20(0x114),
        CRYPTO_ERROR_21(0x115),
        CRYPTO_ERROR_22(0x116),
        CRYPTO_ERROR_23(0x117),
        CRYPTO_ERROR_24(0x118),
        CRYPTO_ERROR_25(0x119),
        CRYPTO_ERROR_26(0x11A),
        CRYPTO_ERROR_27(0x11B),
        CRYPTO_ERROR_28(0x11C),
        CRYPTO_ERROR_29(0x11D),
        CRYPTO_ERROR_30(0x11E),
        CRYPTO_ERROR_31(0x11F),
        CRYPTO_ERROR_32(0x120),
        CRYPTO_ERROR_33(0x121),
        CRYPTO_ERROR_34(0x122),
        CRYPTO_ERROR_35(0x123),
        CRYPTO_ERROR_36(0x124),
        CRYPTO_ERROR_37(0x125),
        CRYPTO_ERROR_38(0x126),
        CRYPTO_ERROR_39(0x127),
        CRYPTO_ERROR_40(0x128),
        CRYPTO_ERROR_41(0x129),
        CRYPTO_ERROR_42(0x12A),
        CRYPTO_ERROR_43(0x12B),
        CRYPTO_ERROR_44(0x12C),
        CRYPTO_ERROR_45(0x12D),
        CRYPTO_ERROR_46(0x12E),
        CRYPTO_ERROR_47(0x12F),
        CRYPTO_ERROR_48(0x130),
        CRYPTO_ERROR_49(0x131),
        CRYPTO_ERROR_50(0x132),
        CRYPTO_ERROR_51(0x133),
        CRYPTO_ERROR_52(0x134),
        CRYPTO_ERROR_53(0x135),
        CRYPTO_ERROR_54(0x136),
        CRYPTO_ERROR_55(0x137),
        CRYPTO_ERROR_56(0x138),
        CRYPTO_ERROR_57(0x139),
        CRYPTO_ERROR_58(0x13A),
        CRYPTO_ERROR_59(0x13B),
        CRYPTO_ERROR_60(0x13C),
        CRYPTO_ERROR_61(0x13D),
        CRYPTO_ERROR_62(0x13E),
        CRYPTO_ERROR_63(0x13F),
        CRYPTO_ERROR_64(0x140),
        CRYPTO_ERROR_65(0x141),
        CRYPTO_ERROR_66(0x142),
        CRYPTO_ERROR_67(0x143),
        CRYPTO_ERROR_68(0x144),
        CRYPTO_ERROR_69(0x145),
        CRYPTO_ERROR_70(0x146),
        CRYPTO_ERROR_71(0x147),
        CRYPTO_ERROR_72(0x148),
        CRYPTO_ERROR_73(0x149),
        CRYPTO_ERROR_74(0x14A),
        CRYPTO_ERROR_75(0x14B),
        CRYPTO_ERROR_76(0x14C),
        CRYPTO_ERROR_77(0x14D),
        CRYPTO_ERROR_78(0x14E),
        CRYPTO_ERROR_79(0x14F),
        CRYPTO_ERROR_80(0x150),
        CRYPTO_ERROR_81(0x151),
        CRYPTO_ERROR_82(0x152),
        CRYPTO_ERROR_83(0x153),
        CRYPTO_ERROR_84(0x154),
        CRYPTO_ERROR_85(0x155),
        CRYPTO_ERROR_86(0x156),
        CRYPTO_ERROR_87(0x157),
        CRYPTO_ERROR_88(0x158),
        CRYPTO_ERROR_89(0x159),
        CRYPTO_ERROR_90(0x15A),
        CRYPTO_ERROR_91(0x15B),
        CRYPTO_ERROR_92(0x15C),
        CRYPTO_ERROR_93(0x15D),
        CRYPTO_ERROR_94(0x15E),
        CRYPTO_ERROR_95(0x15F),
        CRYPTO_ERROR_96(0x160),
        CRYPTO_ERROR_97(0x161),
        CRYPTO_ERROR_98(0x162),
        CRYPTO_ERROR_99(0x163),
        CRYPTO_ERROR_100(0x164),
        CRYPTO_ERROR_101(0x165),
        CRYPTO_ERROR_102(0x166),
        CRYPTO_ERROR_103(0x167),
        CRYPTO_ERROR_104(0x168),
        CRYPTO_ERROR_105(0x169),
        CRYPTO_ERROR_106(0x16A),
        CRYPTO_ERROR_107(0x16B),
        CRYPTO_ERROR_108(0x16C),
        CRYPTO_ERROR_109(0x16D),
        CRYPTO_ERROR_110(0x16E),
        CRYPTO_ERROR_111(0x16F),
        CRYPTO_ERROR_112(0x170),
        CRYPTO_ERROR_113(0x171),
        CRYPTO_ERROR_114(0x172),
        CRYPTO_ERROR_115(0x173),
        CRYPTO_ERROR_116(0x174),
        CRYPTO_ERROR_117(0x175),
        CRYPTO_ERROR_118(0x176),
        CRYPTO_ERROR_119(0x177),
        CRYPTO_ERROR_120(0x178),
        CRYPTO_ERROR_121(0x179),
        CRYPTO_ERROR_122(0x17A),
        CRYPTO_ERROR_123(0x17B),
        CRYPTO_ERROR_124(0x17C),
        CRYPTO_ERROR_125(0x17D),
        CRYPTO_ERROR_126(0x17E),
        CRYPTO_ERROR_127(0x17F),
        CRYPTO_ERROR_128(0x180),
        CRYPTO_ERROR_129(0x181),
        CRYPTO_ERROR_130(0x182),
        CRYPTO_ERROR_131(0x183),
        CRYPTO_ERROR_132(0x184),
        CRYPTO_ERROR_133(0x185),
        CRYPTO_ERROR_134(0x186),
        CRYPTO_ERROR_135(0x187),
        CRYPTO_ERROR_136(0x188),
        CRYPTO_ERROR_137(0x189),
        CRYPTO_ERROR_138(0x18A),
        CRYPTO_ERROR_139(0x18B),
        CRYPTO_ERROR_140(0x18C),
        CRYPTO_ERROR_141(0x18D),
        CRYPTO_ERROR_142(0x18E),
        CRYPTO_ERROR_143(0x18F),
        CRYPTO_ERROR_144(0x190),
        CRYPTO_ERROR_145(0x191),
        CRYPTO_ERROR_146(0x192),
        CRYPTO_ERROR_147(0x193),
        CRYPTO_ERROR_148(0x194),
        CRYPTO_ERROR_149(0x195),
        CRYPTO_ERROR_150(0x196),
        CRYPTO_ERROR_151(0x197),
        CRYPTO_ERROR_152(0x198),
        CRYPTO_ERROR_153(0x199),
        CRYPTO_ERROR_154(0x19A),
        CRYPTO_ERROR_155(0x19B),
        CRYPTO_ERROR_156(0x19C),
        CRYPTO_ERROR_157(0x19D),
        CRYPTO_ERROR_158(0x19E),
        CRYPTO_ERROR_159(0x19F),
        CRYPTO_ERROR_160(0x1A0),
        CRYPTO_ERROR_161(0x1A1),
        CRYPTO_ERROR_162(0x1A2),
        CRYPTO_ERROR_163(0x1A3),
        CRYPTO_ERROR_164(0x1A4),
        CRYPTO_ERROR_165(0x1A5),
        CRYPTO_ERROR_166(0x1A6),
        CRYPTO_ERROR_167(0x1A7),
        CRYPTO_ERROR_168(0x1A8),
        CRYPTO_ERROR_169(0x1A9),
        CRYPTO_ERROR_170(0x1AA),
        CRYPTO_ERROR_171(0x1AB),
        CRYPTO_ERROR_172(0x1AC),
        CRYPTO_ERROR_173(0x1AD),
        CRYPTO_ERROR_174(0x1AE),
        CRYPTO_ERROR_175(0x1AF),
        CRYPTO_ERROR_176(0x1B0),
        CRYPTO_ERROR_177(0x1B1),
        CRYPTO_ERROR_178(0x1B2),
        CRYPTO_ERROR_179(0x1B3),
        CRYPTO_ERROR_180(0x1B4),
        CRYPTO_ERROR_181(0x1B5),
        CRYPTO_ERROR_182(0x1B6),
        CRYPTO_ERROR_183(0x1B7),
        CRYPTO_ERROR_184(0x1B8),
        CRYPTO_ERROR_185(0x1B9),
        CRYPTO_ERROR_186(0x1BA),
        CRYPTO_ERROR_187(0x1BB),
        CRYPTO_ERROR_188(0x1BC),
        CRYPTO_ERROR_189(0x1BD),
        CRYPTO_ERROR_190(0x1BE),
        CRYPTO_ERROR_191(0x1BF),
        CRYPTO_ERROR_192(0x1C0),
        CRYPTO_ERROR_193(0x1C1),
        CRYPTO_ERROR_194(0x1C2),
        CRYPTO_ERROR_195(0x1C3),
        CRYPTO_ERROR_196(0x1C4),
        CRYPTO_ERROR_197(0x1C5),
        CRYPTO_ERROR_198(0x1C6),
        CRYPTO_ERROR_199(0x1C7),
        CRYPTO_ERROR_200(0x1C8),
        CRYPTO_ERROR_201(0x1C9),
        CRYPTO_ERROR_202(0x1CA),
        CRYPTO_ERROR_203(0x1CB),
        CRYPTO_ERROR_204(0x1CC),
        CRYPTO_ERROR_205(0x1CD),
        CRYPTO_ERROR_206(0x1CE),
        CRYPTO_ERROR_207(0x1CF),
        CRYPTO_ERROR_208(0x1D0),
        CRYPTO_ERROR_209(0x1D1),
        CRYPTO_ERROR_210(0x1D2),
        CRYPTO_ERROR_211(0x1D3),
        CRYPTO_ERROR_212(0x1D4),
        CRYPTO_ERROR_213(0x1D5),
        CRYPTO_ERROR_214(0x1D6),
        CRYPTO_ERROR_215(0x1D7),
        CRYPTO_ERROR_216(0x1D8),
        CRYPTO_ERROR_217(0x1D9),
        CRYPTO_ERROR_218(0x1DA),
        CRYPTO_ERROR_219(0x1DB),
        CRYPTO_ERROR_220(0x1DC),
        CRYPTO_ERROR_221(0x1DD),
        CRYPTO_ERROR_222(0x1DE),
        CRYPTO_ERROR_223(0x1DF),
        CRYPTO_ERROR_224(0x1E0),
        CRYPTO_ERROR_225(0x1E1),
        CRYPTO_ERROR_226(0x1E2),
        CRYPTO_ERROR_227(0x1E3),
        CRYPTO_ERROR_228(0x1E4),
        CRYPTO_ERROR_229(0x1E5),
        CRYPTO_ERROR_230(0x1E6),
        CRYPTO_ERROR_231(0x1E7),
        CRYPTO_ERROR_232(0x1E8),
        CRYPTO_ERROR_233(0x1E9),
        CRYPTO_ERROR_234(0x1EA),
        CRYPTO_ERROR_235(0x1EB),
        CRYPTO_ERROR_236(0x1EC),
        CRYPTO_ERROR_237(0x1ED),
        CRYPTO_ERROR_238(0x1EE),
        CRYPTO_ERROR_239(0x1EF),
        CRYPTO_ERROR_240(0x1F0),
        CRYPTO_ERROR_241(0x1F1),
        CRYPTO_ERROR_242(0x1F2),
        CRYPTO_ERROR_243(0x1F3),
        CRYPTO_ERROR_244(0x1F4),
        CRYPTO_ERROR_245(0x1F5),
        CRYPTO_ERROR_246(0x1F6),
        CRYPTO_ERROR_247(0x1F7),
        CRYPTO_ERROR_248(0x1F8),
        CRYPTO_ERROR_249(0x1F9),
        CRYPTO_ERROR_250(0x1FA),
        CRYPTO_ERROR_251(0x1FB),
        CRYPTO_ERROR_252(0x1FC),
        CRYPTO_ERROR_253(0x1FD),
        CRYPTO_ERROR_254(0x1FE),
        CRYPTO_ERROR_255(0x1FF);

        static Code[] codes = new Code[512];

        public final int code;

        static void register(Code code) {
            codes[code.code] = code;
        }

        public QUICException ex() {
            return QUICException.get(this);
        }

        Code(int code) {
            this.code = code;
            register(this);
        }
    }
}
