.class public final Ltechnology/cariad/cat/genx/QRCode$Companion;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Ltechnology/cariad/cat/genx/QRCode;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "Companion"
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000B\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0008\u0002\n\u0002\u0010\u0012\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0007\n\u0002\u0010\n\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\t\u0008\u0086\u0003\u0018\u00002\u00020\u0001B\t\u0008\u0002\u00a2\u0006\u0004\u0008\u0002\u0010\u0003J\u0013\u0010\u0008\u001a\u00020\u0005*\u00020\u0004H\u0002\u00a2\u0006\u0004\u0008\u0006\u0010\u0007J\u001b\u0010\u000f\u001a\u0008\u0012\u0004\u0012\u00020\u000c0\u000b2\u0006\u0010\n\u001a\u00020\t\u00a2\u0006\u0004\u0008\r\u0010\u000eJ\u001b\u0010\u0013\u001a\u0008\u0012\u0004\u0012\u00020\u000c0\u000b2\u0006\u0010\u0010\u001a\u00020\u0004\u00a2\u0006\u0004\u0008\u0011\u0010\u0012J\u0013\u0010\u0017\u001a\u00020\u0004*\u00020\u0014H\u0000\u00a2\u0006\u0004\u0008\u0015\u0010\u0016JE\u0010#\u001a\u00020\u000c2\u0006\u0010\u0019\u001a\u00020\u00182\u0006\u0010\u001a\u001a\u00020\t2\u0006\u0010\u001c\u001a\u00020\u001b2\u0006\u0010\u001d\u001a\u00020\u00042\u0006\u0010\u001e\u001a\u00020\u00042\u0006\u0010\u001f\u001a\u00020\u00052\u0006\u0010 \u001a\u00020\u0005\u00a2\u0006\u0004\u0008!\u0010\"\u00a8\u0006$"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/QRCode$Companion;",
        "",
        "<init>",
        "()V",
        "",
        "Llx0/z;",
        "toUShort-BwKQO78",
        "([B)S",
        "toUShort",
        "",
        "qrCodeContent",
        "Llx0/o;",
        "Ltechnology/cariad/cat/genx/QRCode;",
        "parseFromString-IoAF18A",
        "(Ljava/lang/String;)Ljava/lang/Object;",
        "parseFromString",
        "qrCodeData",
        "parseFromQRCode-IoAF18A",
        "([B)Ljava/lang/Object;",
        "parseFromQRCode",
        "",
        "toByteArray$genx_release",
        "(S)[B",
        "toByteArray",
        "Ltechnology/cariad/cat/genx/QRCode$Version;",
        "qrCodeVersion",
        "vin",
        "Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PublicKey;",
        "remotePublicSigningKey",
        "localTransceiverSecret",
        "remoteTransceiverSecret",
        "major",
        "minor",
        "constructForTesting-rUZN81g",
        "(Ltechnology/cariad/cat/genx/QRCode$Version;Ljava/lang/String;Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PublicKey;[B[BSS)Ltechnology/cariad/cat/genx/QRCode;",
        "constructForTesting",
        "genx_release"
    }
    k = 0x1
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation


# direct methods
.method private constructor <init>()V
    .locals 0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lkotlin/jvm/internal/g;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ltechnology/cariad/cat/genx/QRCode$Companion;-><init>()V

    return-void
.end method

.method public static synthetic a()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/QRCode$Companion;->parseFromQRCode_IoAF18A$lambda$2()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic b([B)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/QRCode$Companion;->parseFromQRCode_IoAF18A$lambda$0([B)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic c()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/QRCode$Companion;->parseFromQRCode_IoAF18A$lambda$1$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic d(Ljava/lang/String;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/QRCode$Companion;->parseFromString_IoAF18A$lambda$0(Ljava/lang/String;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static final parseFromQRCode_IoAF18A$lambda$0([B)Ljava/lang/String;
    .locals 2

    .line 1
    array-length p0, p0

    .line 2
    const-string v0, "parseFromQRCode(): The provided QR code data is invalid. Size mismatch ("

    .line 3
    .line 4
    const-string v1, " != 150 or 156)"

    .line 5
    .line 6
    invoke-static {v0, p0, v1}, Lu/w;->e(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0
.end method

.method private static final parseFromQRCode_IoAF18A$lambda$1$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "parseFromQRCode(): The public key in QR code invalid."

    .line 2
    .line 3
    return-object v0
.end method

.method private static final parseFromQRCode_IoAF18A$lambda$2()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "parseFromQRCode(): The signature of the QR code is invalid."

    .line 2
    .line 3
    return-object v0
.end method

.method private static final parseFromString_IoAF18A$lambda$0(Ljava/lang/String;)Ljava/lang/String;
    .locals 2

    .line 1
    const-string v0, "parseFromString(): Could not decode \'"

    .line 2
    .line 3
    const-string v1, "\'"

    .line 4
    .line 5
    invoke-static {v0, p0, v1}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method private final toUShort-BwKQO78([B)S
    .locals 1

    .line 1
    array-length p0, p1

    .line 2
    const/4 v0, 0x2

    .line 3
    if-ne p0, v0, :cond_0

    .line 4
    .line 5
    invoke-static {p1}, Ljava/nio/ByteBuffer;->wrap([B)Ljava/nio/ByteBuffer;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    invoke-virtual {p0}, Ljava/nio/ByteBuffer;->getShort()S

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0

    .line 14
    :cond_0
    new-instance p0, Ljava/lang/Exception;

    .line 15
    .line 16
    const-string p1, "wrong length"

    .line 17
    .line 18
    invoke-direct {p0, p1}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    throw p0
.end method


# virtual methods
.method public final constructForTesting-rUZN81g(Ltechnology/cariad/cat/genx/QRCode$Version;Ljava/lang/String;Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PublicKey;[B[BSS)Ltechnology/cariad/cat/genx/QRCode;
    .locals 9

    .line 1
    const-string p0, "qrCodeVersion"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string p0, "vin"

    .line 7
    .line 8
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string p0, "remotePublicSigningKey"

    .line 12
    .line 13
    invoke-static {p3, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    const-string p0, "localTransceiverSecret"

    .line 17
    .line 18
    invoke-static {p4, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    const-string p0, "remoteTransceiverSecret"

    .line 22
    .line 23
    invoke-static {p5, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    new-instance v0, Ltechnology/cariad/cat/genx/QRCode;

    .line 27
    .line 28
    const/4 v8, 0x0

    .line 29
    move-object v1, p1

    .line 30
    move-object v2, p2

    .line 31
    move-object v3, p3

    .line 32
    move-object v4, p4

    .line 33
    move-object v5, p5

    .line 34
    move v6, p6

    .line 35
    move/from16 v7, p7

    .line 36
    .line 37
    invoke-direct/range {v0 .. v8}, Ltechnology/cariad/cat/genx/QRCode;-><init>(Ltechnology/cariad/cat/genx/QRCode$Version;Ljava/lang/String;Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PublicKey;[B[BSSLkotlin/jvm/internal/g;)V

    .line 38
    .line 39
    .line 40
    return-object v0
.end method

.method public final parseFromQRCode-IoAF18A([B)Ljava/lang/Object;
    .locals 21

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    const-string v2, "qrCodeData"

    .line 6
    .line 7
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    array-length v2, v1

    .line 11
    const/16 v3, 0x96

    .line 12
    .line 13
    const/16 v4, 0x9c

    .line 14
    .line 15
    const-string v5, "GenX"

    .line 16
    .line 17
    const/4 v6, 0x0

    .line 18
    const/4 v7, 0x0

    .line 19
    if-eq v2, v3, :cond_1

    .line 20
    .line 21
    if-eq v2, v4, :cond_0

    .line 22
    .line 23
    new-instance v2, Ltechnology/cariad/cat/genx/j;

    .line 24
    .line 25
    const/4 v3, 0x0

    .line 26
    invoke-direct {v2, v3, v1}, Ltechnology/cariad/cat/genx/j;-><init>(I[B)V

    .line 27
    .line 28
    .line 29
    invoke-static {v0, v5, v6, v2}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 30
    .line 31
    .line 32
    sget-object v0, Ltechnology/cariad/cat/genx/GenXError$InvalidQRCodeData;->INSTANCE:Ltechnology/cariad/cat/genx/GenXError$InvalidQRCodeData;

    .line 33
    .line 34
    invoke-static {v0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 35
    .line 36
    .line 37
    move-result-object v0

    .line 38
    return-object v0

    .line 39
    :cond_0
    move-object v2, v1

    .line 40
    goto :goto_0

    .line 41
    :cond_1
    invoke-virtual {v0, v7}, Ltechnology/cariad/cat/genx/QRCode$Companion;->toByteArray$genx_release(S)[B

    .line 42
    .line 43
    .line 44
    move-result-object v2

    .line 45
    invoke-virtual {v0, v7}, Ltechnology/cariad/cat/genx/QRCode$Companion;->toByteArray$genx_release(S)[B

    .line 46
    .line 47
    .line 48
    move-result-object v3

    .line 49
    invoke-static {v2, v3}, Lmx0/n;->M([B[B)[B

    .line 50
    .line 51
    .line 52
    move-result-object v2

    .line 53
    invoke-virtual {v0, v7}, Ltechnology/cariad/cat/genx/QRCode$Companion;->toByteArray$genx_release(S)[B

    .line 54
    .line 55
    .line 56
    move-result-object v3

    .line 57
    invoke-static {v2, v3}, Lmx0/n;->M([B[B)[B

    .line 58
    .line 59
    .line 60
    move-result-object v2

    .line 61
    invoke-static {v2, v1}, Lmx0/n;->M([B[B)[B

    .line 62
    .line 63
    .line 64
    move-result-object v2

    .line 65
    :goto_0
    const/4 v3, 0x2

    .line 66
    invoke-static {v2, v7, v3}, Lmx0/n;->n([BII)[B

    .line 67
    .line 68
    .line 69
    move-result-object v8

    .line 70
    invoke-direct {v0, v8}, Ltechnology/cariad/cat/genx/QRCode$Companion;->toUShort-BwKQO78([B)S

    .line 71
    .line 72
    .line 73
    move-result v8

    .line 74
    const/4 v9, 0x4

    .line 75
    invoke-static {v2, v3, v9}, Lmx0/n;->n([BII)[B

    .line 76
    .line 77
    .line 78
    move-result-object v3

    .line 79
    invoke-direct {v0, v3}, Ltechnology/cariad/cat/genx/QRCode$Companion;->toUShort-BwKQO78([B)S

    .line 80
    .line 81
    .line 82
    move-result v3

    .line 83
    const/4 v10, 0x6

    .line 84
    invoke-static {v2, v9, v10}, Lmx0/n;->n([BII)[B

    .line 85
    .line 86
    .line 87
    move-result-object v9

    .line 88
    invoke-direct {v0, v9}, Ltechnology/cariad/cat/genx/QRCode$Companion;->toUShort-BwKQO78([B)S

    .line 89
    .line 90
    .line 91
    move-result v9

    .line 92
    const/16 v11, 0x16

    .line 93
    .line 94
    invoke-static {v2, v10, v11}, Lmx0/n;->n([BII)[B

    .line 95
    .line 96
    .line 97
    move-result-object v16

    .line 98
    const/16 v10, 0x26

    .line 99
    .line 100
    invoke-static {v2, v11, v10}, Lmx0/n;->n([BII)[B

    .line 101
    .line 102
    .line 103
    move-result-object v17

    .line 104
    const/16 v11, 0x46

    .line 105
    .line 106
    invoke-static {v2, v10, v11}, Lmx0/n;->n([BII)[B

    .line 107
    .line 108
    .line 109
    move-result-object v10

    .line 110
    const/16 v12, 0x58

    .line 111
    .line 112
    invoke-static {v2, v11, v12}, Lmx0/n;->n([BII)[B

    .line 113
    .line 114
    .line 115
    move-result-object v11

    .line 116
    const/16 v13, 0x5a

    .line 117
    .line 118
    invoke-static {v2, v12, v13}, Lmx0/n;->n([BII)[B

    .line 119
    .line 120
    .line 121
    move-result-object v12

    .line 122
    invoke-direct {v0, v12}, Ltechnology/cariad/cat/genx/QRCode$Companion;->toUShort-BwKQO78([B)S

    .line 123
    .line 124
    .line 125
    move-result v18

    .line 126
    const/16 v12, 0x5c

    .line 127
    .line 128
    invoke-static {v2, v13, v12}, Lmx0/n;->n([BII)[B

    .line 129
    .line 130
    .line 131
    move-result-object v13

    .line 132
    invoke-direct {v0, v13}, Ltechnology/cariad/cat/genx/QRCode$Companion;->toUShort-BwKQO78([B)S

    .line 133
    .line 134
    .line 135
    move-result v19

    .line 136
    invoke-static {v2, v12, v4}, Lmx0/n;->n([BII)[B

    .line 137
    .line 138
    .line 139
    move-result-object v2

    .line 140
    sget-object v4, Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PublicKey;->Companion:Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PublicKey$Companion;

    .line 141
    .line 142
    invoke-virtual {v4, v10}, Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PublicKey$Companion;->invoke([B)Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PublicKey;

    .line 143
    .line 144
    .line 145
    move-result-object v15

    .line 146
    if-nez v15, :cond_2

    .line 147
    .line 148
    new-instance v1, Ltechnology/cariad/cat/genx/s0;

    .line 149
    .line 150
    const/16 v2, 0xe

    .line 151
    .line 152
    invoke-direct {v1, v2}, Ltechnology/cariad/cat/genx/s0;-><init>(I)V

    .line 153
    .line 154
    .line 155
    invoke-static {v0, v5, v6, v1}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 156
    .line 157
    .line 158
    sget-object v0, Ltechnology/cariad/cat/genx/GenXError$InvalidQRCodeData;->INSTANCE:Ltechnology/cariad/cat/genx/GenXError$InvalidQRCodeData;

    .line 159
    .line 160
    invoke-static {v0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 161
    .line 162
    .line 163
    move-result-object v0

    .line 164
    return-object v0

    .line 165
    :cond_2
    array-length v4, v1

    .line 166
    add-int/lit8 v4, v4, -0x40

    .line 167
    .line 168
    if-gez v4, :cond_3

    .line 169
    .line 170
    move v4, v7

    .line 171
    :cond_3
    invoke-static {v4, v1}, Lmx0/n;->U(I[B)Ljava/util/List;

    .line 172
    .line 173
    .line 174
    move-result-object v1

    .line 175
    check-cast v1, Ljava/util/Collection;

    .line 176
    .line 177
    invoke-static {v1}, Lmx0/q;->t0(Ljava/util/Collection;)[B

    .line 178
    .line 179
    .line 180
    move-result-object v1

    .line 181
    invoke-static {v15, v2, v1}, Ltechnology/cariad/cat/genx/crypto/EdDSASigningKt;->isValidSignature(Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PublicKey;[B[B)Z

    .line 182
    .line 183
    .line 184
    move-result v1

    .line 185
    if-nez v1, :cond_4

    .line 186
    .line 187
    new-instance v1, Ltechnology/cariad/cat/genx/s0;

    .line 188
    .line 189
    const/16 v2, 0xf

    .line 190
    .line 191
    invoke-direct {v1, v2}, Ltechnology/cariad/cat/genx/s0;-><init>(I)V

    .line 192
    .line 193
    .line 194
    invoke-static {v0, v5, v6, v1}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 195
    .line 196
    .line 197
    sget-object v0, Ltechnology/cariad/cat/genx/GenXError$InvalidQRCodeSignature;->INSTANCE:Ltechnology/cariad/cat/genx/GenXError$InvalidQRCodeSignature;

    .line 198
    .line 199
    invoke-static {v0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 200
    .line 201
    .line 202
    move-result-object v0

    .line 203
    return-object v0

    .line 204
    :cond_4
    new-instance v0, Ljava/lang/String;

    .line 205
    .line 206
    sget-object v1, Lly0/a;->a:Ljava/nio/charset/Charset;

    .line 207
    .line 208
    invoke-direct {v0, v11, v1}, Ljava/lang/String;-><init>([BLjava/nio/charset/Charset;)V

    .line 209
    .line 210
    .line 211
    const-string v1, "\u0000"

    .line 212
    .line 213
    const-string v2, ""

    .line 214
    .line 215
    invoke-static {v7, v0, v1, v2}, Lly0/w;->t(ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 216
    .line 217
    .line 218
    move-result-object v14

    .line 219
    new-instance v12, Ltechnology/cariad/cat/genx/QRCode;

    .line 220
    .line 221
    new-instance v13, Ltechnology/cariad/cat/genx/QRCode$Version;

    .line 222
    .line 223
    invoke-direct {v13, v8, v3, v9, v6}, Ltechnology/cariad/cat/genx/QRCode$Version;-><init>(SSSLkotlin/jvm/internal/g;)V

    .line 224
    .line 225
    .line 226
    const/16 v20, 0x0

    .line 227
    .line 228
    invoke-direct/range {v12 .. v20}, Ltechnology/cariad/cat/genx/QRCode;-><init>(Ltechnology/cariad/cat/genx/QRCode$Version;Ljava/lang/String;Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PublicKey;[B[BSSLkotlin/jvm/internal/g;)V

    .line 229
    .line 230
    .line 231
    return-object v12
.end method

.method public final parseFromString-IoAF18A(Ljava/lang/String;)Ljava/lang/Object;
    .locals 3

    .line 1
    const-string v0, "qrCodeContent"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const/4 v0, 0x2

    .line 7
    :try_start_0
    invoke-static {p1, v0}, Landroid/util/Base64;->decode(Ljava/lang/String;I)[B

    .line 8
    .line 9
    .line 10
    move-result-object p1
    :try_end_0
    .catch Ljava/lang/IllegalArgumentException; {:try_start_0 .. :try_end_0} :catch_0

    .line 11
    invoke-static {p1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 12
    .line 13
    .line 14
    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/genx/QRCode$Companion;->parseFromQRCode-IoAF18A([B)Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    return-object p0

    .line 19
    :catch_0
    move-exception v0

    .line 20
    new-instance v1, Ltechnology/cariad/cat/genx/k;

    .line 21
    .line 22
    const/4 v2, 0x0

    .line 23
    invoke-direct {v1, p1, v2}, Ltechnology/cariad/cat/genx/k;-><init>(Ljava/lang/String;I)V

    .line 24
    .line 25
    .line 26
    const-string p1, "GenX"

    .line 27
    .line 28
    invoke-static {p0, p1, v0, v1}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 29
    .line 30
    .line 31
    sget-object p0, Ltechnology/cariad/cat/genx/GenXError$InvalidQRCodeData;->INSTANCE:Ltechnology/cariad/cat/genx/GenXError$InvalidQRCodeData;

    .line 32
    .line 33
    invoke-static {p0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    return-object p0
.end method

.method public final toByteArray$genx_release(S)[B
    .locals 0

    .line 1
    const/4 p0, 0x2

    .line 2
    invoke-static {p0}, Ljava/nio/ByteBuffer;->allocate(I)Ljava/nio/ByteBuffer;

    .line 3
    .line 4
    .line 5
    move-result-object p0

    .line 6
    invoke-virtual {p0, p1}, Ljava/nio/ByteBuffer;->putShort(S)Ljava/nio/ByteBuffer;

    .line 7
    .line 8
    .line 9
    invoke-virtual {p0}, Ljava/nio/ByteBuffer;->array()[B

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    const-string p1, "array(...)"

    .line 14
    .line 15
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    return-object p0
.end method
