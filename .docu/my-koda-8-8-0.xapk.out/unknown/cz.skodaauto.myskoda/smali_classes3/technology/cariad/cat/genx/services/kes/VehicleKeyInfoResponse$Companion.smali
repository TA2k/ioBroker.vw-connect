.class public final Ltechnology/cariad/cat/genx/services/kes/VehicleKeyInfoResponse$Companion;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Ltechnology/cariad/cat/genx/services/kes/VehicleKeyInfoResponse;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "Companion"
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u001e\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0008\u0003\n\u0002\u0010\u0008\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0012\n\u0000\u0008\u0086\u0003\u0018\u00002\u00020\u0001B\t\u0008\u0002\u00a2\u0006\u0004\u0008\u0002\u0010\u0003J\u0010\u0010\u0006\u001a\u0004\u0018\u00010\u00072\u0006\u0010\u0008\u001a\u00020\tR\u000e\u0010\u0004\u001a\u00020\u0005X\u0086T\u00a2\u0006\u0002\n\u0000\u00a8\u0006\n"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/services/kes/VehicleKeyInfoResponse$Companion;",
        "",
        "<init>",
        "()V",
        "EXPECTED_SIZE",
        "",
        "fromBytes",
        "Ltechnology/cariad/cat/genx/services/kes/VehicleKeyInfoResponse;",
        "byteArray",
        "",
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
    invoke-direct {p0}, Ltechnology/cariad/cat/genx/services/kes/VehicleKeyInfoResponse$Companion;-><init>()V

    return-void
.end method

.method public static synthetic a()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/services/kes/VehicleKeyInfoResponse$Companion;->fromBytes$lambda$0$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method private static final fromBytes$lambda$0$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "fromBytes(): Cannot parse \'VehicleKeyInfoResponse\': Invalid public key"

    .line 2
    .line 3
    return-object v0
.end method


# virtual methods
.method public final fromBytes([B)Ltechnology/cariad/cat/genx/services/kes/VehicleKeyInfoResponse;
    .locals 16

    .line 1
    move-object/from16 v0, p1

    .line 2
    .line 3
    const-string v1, "byteArray"

    .line 4
    .line 5
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    array-length v1, v0

    .line 9
    const/16 v2, 0x4b

    .line 10
    .line 11
    const/4 v3, 0x0

    .line 12
    if-ge v1, v2, :cond_0

    .line 13
    .line 14
    return-object v3

    .line 15
    :cond_0
    sget-object v1, Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PublicKey;->Companion:Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PublicKey$Companion;

    .line 16
    .line 17
    new-instance v2, Lgy0/j;

    .line 18
    .line 19
    const/16 v4, 0x1f

    .line 20
    .line 21
    const/4 v5, 0x0

    .line 22
    const/4 v6, 0x1

    .line 23
    invoke-direct {v2, v5, v4, v6}, Lgy0/h;-><init>(III)V

    .line 24
    .line 25
    .line 26
    invoke-static {v0, v2}, Lmx0/n;->R([BLgy0/j;)[B

    .line 27
    .line 28
    .line 29
    move-result-object v2

    .line 30
    invoke-virtual {v1, v2}, Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PublicKey$Companion;->invoke([B)Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PublicKey;

    .line 31
    .line 32
    .line 33
    move-result-object v8

    .line 34
    if-nez v8, :cond_1

    .line 35
    .line 36
    new-instance v12, Ltechnology/cariad/cat/genx/services/kes/f;

    .line 37
    .line 38
    const/16 v0, 0x10

    .line 39
    .line 40
    invoke-direct {v12, v0}, Ltechnology/cariad/cat/genx/services/kes/f;-><init>(I)V

    .line 41
    .line 42
    .line 43
    new-instance v9, Lt51/j;

    .line 44
    .line 45
    invoke-static/range {p0 .. p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 46
    .line 47
    .line 48
    move-result-object v14

    .line 49
    const-string v0, "getName(...)"

    .line 50
    .line 51
    invoke-static {v0}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 52
    .line 53
    .line 54
    move-result-object v15

    .line 55
    const-string v10, "GenX"

    .line 56
    .line 57
    sget-object v11, Lt51/e;->a:Lt51/e;

    .line 58
    .line 59
    const/4 v13, 0x0

    .line 60
    invoke-direct/range {v9 .. v15}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 61
    .line 62
    .line 63
    invoke-static {v9}, Lt51/a;->a(Lt51/j;)V

    .line 64
    .line 65
    .line 66
    return-object v3

    .line 67
    :cond_1
    new-instance v1, Lgy0/j;

    .line 68
    .line 69
    const/16 v2, 0x20

    .line 70
    .line 71
    const/16 v4, 0x2f

    .line 72
    .line 73
    invoke-direct {v1, v2, v4, v6}, Lgy0/h;-><init>(III)V

    .line 74
    .line 75
    .line 76
    invoke-static {v0, v1}, Lmx0/n;->R([BLgy0/j;)[B

    .line 77
    .line 78
    .line 79
    move-result-object v9

    .line 80
    new-instance v1, Lgy0/j;

    .line 81
    .line 82
    const/16 v2, 0x30

    .line 83
    .line 84
    const/16 v4, 0x3f

    .line 85
    .line 86
    invoke-direct {v1, v2, v4, v6}, Lgy0/h;-><init>(III)V

    .line 87
    .line 88
    .line 89
    invoke-static {v0, v1}, Lmx0/n;->R([BLgy0/j;)[B

    .line 90
    .line 91
    .line 92
    move-result-object v10

    .line 93
    new-instance v1, Lgy0/j;

    .line 94
    .line 95
    const/16 v2, 0x40

    .line 96
    .line 97
    const/16 v4, 0x41

    .line 98
    .line 99
    invoke-direct {v1, v2, v4, v6}, Lgy0/h;-><init>(III)V

    .line 100
    .line 101
    .line 102
    invoke-static {v0, v1}, Lmx0/n;->R([BLgy0/j;)[B

    .line 103
    .line 104
    .line 105
    move-result-object v1

    .line 106
    invoke-static {v1}, Ltechnology/cariad/cat/genx/ByteArrayExtensionsKt;->toUShort([B)S

    .line 107
    .line 108
    .line 109
    move-result v11

    .line 110
    new-instance v1, Lgy0/j;

    .line 111
    .line 112
    const/16 v2, 0x42

    .line 113
    .line 114
    const/16 v4, 0x43

    .line 115
    .line 116
    invoke-direct {v1, v2, v4, v6}, Lgy0/h;-><init>(III)V

    .line 117
    .line 118
    .line 119
    invoke-static {v0, v1}, Lmx0/n;->R([BLgy0/j;)[B

    .line 120
    .line 121
    .line 122
    move-result-object v1

    .line 123
    invoke-static {v1}, Ltechnology/cariad/cat/genx/ByteArrayExtensionsKt;->toUShort([B)S

    .line 124
    .line 125
    .line 126
    move-result v12

    .line 127
    const/16 v1, 0x44

    .line 128
    .line 129
    aget-byte v1, v0, v1

    .line 130
    .line 131
    if-ne v1, v6, :cond_2

    .line 132
    .line 133
    move v13, v6

    .line 134
    goto :goto_0

    .line 135
    :cond_2
    move v13, v5

    .line 136
    :goto_0
    new-instance v1, Lgy0/j;

    .line 137
    .line 138
    const/16 v2, 0x45

    .line 139
    .line 140
    const/16 v4, 0x46

    .line 141
    .line 142
    invoke-direct {v1, v2, v4, v6}, Lgy0/h;-><init>(III)V

    .line 143
    .line 144
    .line 145
    invoke-static {v0, v1}, Lmx0/n;->R([BLgy0/j;)[B

    .line 146
    .line 147
    .line 148
    move-result-object v1

    .line 149
    invoke-static {v1}, Ltechnology/cariad/cat/genx/ByteArrayExtensionsKt;->toUShort([B)S

    .line 150
    .line 151
    .line 152
    move-result v1

    .line 153
    new-instance v2, Lgy0/j;

    .line 154
    .line 155
    const/16 v4, 0x47

    .line 156
    .line 157
    const/16 v5, 0x48

    .line 158
    .line 159
    invoke-direct {v2, v4, v5, v6}, Lgy0/h;-><init>(III)V

    .line 160
    .line 161
    .line 162
    invoke-static {v0, v2}, Lmx0/n;->R([BLgy0/j;)[B

    .line 163
    .line 164
    .line 165
    move-result-object v2

    .line 166
    invoke-static {v2}, Ltechnology/cariad/cat/genx/ByteArrayExtensionsKt;->toUShort([B)S

    .line 167
    .line 168
    .line 169
    move-result v2

    .line 170
    new-instance v4, Lgy0/j;

    .line 171
    .line 172
    const/16 v5, 0x49

    .line 173
    .line 174
    const/16 v7, 0x4a

    .line 175
    .line 176
    invoke-direct {v4, v5, v7, v6}, Lgy0/h;-><init>(III)V

    .line 177
    .line 178
    .line 179
    invoke-static {v0, v4}, Lmx0/n;->R([BLgy0/j;)[B

    .line 180
    .line 181
    .line 182
    move-result-object v0

    .line 183
    invoke-static {v0}, Ltechnology/cariad/cat/genx/ByteArrayExtensionsKt;->toUShort([B)S

    .line 184
    .line 185
    .line 186
    move-result v0

    .line 187
    new-instance v7, Ltechnology/cariad/cat/genx/services/kes/VehicleKeyInfoResponse;

    .line 188
    .line 189
    new-instance v14, Ltechnology/cariad/cat/genx/QRCode$Version;

    .line 190
    .line 191
    invoke-direct {v14, v1, v2, v0, v3}, Ltechnology/cariad/cat/genx/QRCode$Version;-><init>(SSSLkotlin/jvm/internal/g;)V

    .line 192
    .line 193
    .line 194
    const/4 v15, 0x0

    .line 195
    invoke-direct/range {v7 .. v15}, Ltechnology/cariad/cat/genx/services/kes/VehicleKeyInfoResponse;-><init>(Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PublicKey;[B[BSSZLtechnology/cariad/cat/genx/QRCode$Version;Lkotlin/jvm/internal/g;)V

    .line 196
    .line 197
    .line 198
    return-object v7
.end method
