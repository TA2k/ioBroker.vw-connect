.class public final Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponseKt;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u000e\n\u0000\n\u0002\u0010\u0012\n\u0002\u0018\u0002\n\u0002\u0008\u0002\u001a\u000c\u0010\u0000\u001a\u00020\u0001*\u00020\u0002H\u0000\u001a\u000e\u0010\u0003\u001a\u0004\u0018\u00010\u0002*\u00020\u0001H\u0000\u00a8\u0006\u0004"
    }
    d2 = {
        "toByteArray",
        "",
        "Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponse;",
        "toSmartphoneInformationResponse",
        "genx_release"
    }
    k = 0x2
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation


# direct methods
.method public static synthetic a([B)Ljava/lang/String;
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-static {v0, p0}, Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponseKt;->toSmartphoneInformationResponse$lambda$1(B[B)Ljava/lang/String;

    .line 3
    .line 4
    .line 5
    move-result-object p0

    .line 6
    return-object p0
.end method

.method public static synthetic b()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponseKt;->toSmartphoneInformationResponse$lambda$6$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic c()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponseKt;->toSmartphoneInformationResponse$lambda$4$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic d(I)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponseKt;->toSmartphoneInformationResponse$lambda$2(I)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic e()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponseKt;->toSmartphoneInformationResponse$lambda$9$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic f()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponseKt;->toSmartphoneInformationResponse$lambda$5$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic g()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponseKt;->toSmartphoneInformationResponse$lambda$7$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic h()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponseKt;->toSmartphoneInformationResponse$lambda$8$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static final toByteArray(Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponse;)[B
    .locals 5

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponse;->getPhoneName()Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    sget-object v1, Lly0/a;->a:Ljava/nio/charset/Charset;

    .line 11
    .line 12
    invoke-virtual {v0, v1}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    const-string v2, "getBytes(...)"

    .line 17
    .line 18
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    const/4 v3, 0x0

    .line 22
    invoke-static {v3, v0}, Lmx0/n;->L(B[B)[B

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponse;->getManufacturerName()Ljava/lang/String;

    .line 27
    .line 28
    .line 29
    move-result-object v4

    .line 30
    invoke-virtual {v4, v1}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    .line 31
    .line 32
    .line 33
    move-result-object v4

    .line 34
    invoke-static {v4, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    invoke-static {v0, v4}, Lmx0/n;->M([B[B)[B

    .line 38
    .line 39
    .line 40
    move-result-object v0

    .line 41
    invoke-static {v3, v0}, Lmx0/n;->L(B[B)[B

    .line 42
    .line 43
    .line 44
    move-result-object v0

    .line 45
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponse;->getModelName()Ljava/lang/String;

    .line 46
    .line 47
    .line 48
    move-result-object v4

    .line 49
    invoke-virtual {v4, v1}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    .line 50
    .line 51
    .line 52
    move-result-object v4

    .line 53
    invoke-static {v4, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    invoke-static {v0, v4}, Lmx0/n;->M([B[B)[B

    .line 57
    .line 58
    .line 59
    move-result-object v0

    .line 60
    invoke-static {v3, v0}, Lmx0/n;->L(B[B)[B

    .line 61
    .line 62
    .line 63
    move-result-object v0

    .line 64
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponse;->getSwVersion()Ljava/lang/String;

    .line 65
    .line 66
    .line 67
    move-result-object v4

    .line 68
    invoke-virtual {v4, v1}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    .line 69
    .line 70
    .line 71
    move-result-object v4

    .line 72
    invoke-static {v4, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 73
    .line 74
    .line 75
    invoke-static {v0, v4}, Lmx0/n;->M([B[B)[B

    .line 76
    .line 77
    .line 78
    move-result-object v0

    .line 79
    invoke-static {v3, v0}, Lmx0/n;->L(B[B)[B

    .line 80
    .line 81
    .line 82
    move-result-object v0

    .line 83
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponse;->getAppVersion()Ljava/lang/String;

    .line 84
    .line 85
    .line 86
    move-result-object v4

    .line 87
    invoke-virtual {v4, v1}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    .line 88
    .line 89
    .line 90
    move-result-object v4

    .line 91
    invoke-static {v4, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 92
    .line 93
    .line 94
    invoke-static {v0, v4}, Lmx0/n;->M([B[B)[B

    .line 95
    .line 96
    .line 97
    move-result-object v0

    .line 98
    invoke-static {v3, v0}, Lmx0/n;->L(B[B)[B

    .line 99
    .line 100
    .line 101
    move-result-object v0

    .line 102
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponse;->getAppName()Ljava/lang/String;

    .line 103
    .line 104
    .line 105
    move-result-object p0

    .line 106
    invoke-virtual {p0, v1}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    .line 107
    .line 108
    .line 109
    move-result-object p0

    .line 110
    invoke-static {p0, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 111
    .line 112
    .line 113
    invoke-static {v0, p0}, Lmx0/n;->M([B[B)[B

    .line 114
    .line 115
    .line 116
    move-result-object p0

    .line 117
    invoke-static {v3, p0}, Lmx0/n;->L(B[B)[B

    .line 118
    .line 119
    .line 120
    move-result-object p0

    .line 121
    return-object p0
.end method

.method public static final toSmartphoneInformationResponse([B)Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponse;
    .locals 13

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    array-length v0, p0

    .line 7
    const/4 v1, 0x0

    .line 8
    move v2, v1

    .line 9
    move v3, v2

    .line 10
    :goto_0
    if-ge v2, v0, :cond_1

    .line 11
    .line 12
    aget-byte v4, p0, v2

    .line 13
    .line 14
    if-nez v4, :cond_0

    .line 15
    .line 16
    add-int/lit8 v3, v3, 0x1

    .line 17
    .line 18
    :cond_0
    add-int/lit8 v2, v2, 0x1

    .line 19
    .line 20
    goto :goto_0

    .line 21
    :cond_1
    array-length v0, p0

    .line 22
    const/4 v2, 0x1

    .line 23
    const/4 v4, 0x0

    .line 24
    if-nez v0, :cond_2

    .line 25
    .line 26
    move-object v0, v4

    .line 27
    goto :goto_1

    .line 28
    :cond_2
    array-length v0, p0

    .line 29
    sub-int/2addr v0, v2

    .line 30
    aget-byte v0, p0, v0

    .line 31
    .line 32
    invoke-static {v0}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 33
    .line 34
    .line 35
    move-result-object v0

    .line 36
    :goto_1
    const-string v5, "GenX"

    .line 37
    .line 38
    if-eqz v0, :cond_d

    .line 39
    .line 40
    invoke-virtual {v0}, Ljava/lang/Byte;->byteValue()B

    .line 41
    .line 42
    .line 43
    move-result v0

    .line 44
    if-nez v0, :cond_d

    .line 45
    .line 46
    const/4 v0, 0x6

    .line 47
    if-eq v3, v0, :cond_3

    .line 48
    .line 49
    new-instance v0, Le1/h1;

    .line 50
    .line 51
    const/4 v1, 0x4

    .line 52
    invoke-direct {v0, v3, v1}, Le1/h1;-><init>(II)V

    .line 53
    .line 54
    .line 55
    invoke-static {p0, v5, v4, v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 56
    .line 57
    .line 58
    return-object v4

    .line 59
    :cond_3
    new-array v0, v1, [B

    .line 60
    .line 61
    new-instance v3, Ljava/util/LinkedHashMap;

    .line 62
    .line 63
    invoke-direct {v3}, Ljava/util/LinkedHashMap;-><init>()V

    .line 64
    .line 65
    .line 66
    array-length v6, p0

    .line 67
    if-nez v6, :cond_4

    .line 68
    .line 69
    sget-object v6, Lky0/e;->a:Lky0/e;

    .line 70
    .line 71
    goto :goto_2

    .line 72
    :cond_4
    new-instance v6, Lky0/m;

    .line 73
    .line 74
    const/4 v7, 0x4

    .line 75
    invoke-direct {v6, p0, v7}, Lky0/m;-><init>(Ljava/lang/Object;I)V

    .line 76
    .line 77
    .line 78
    :goto_2
    invoke-interface {v6}, Lky0/j;->iterator()Ljava/util/Iterator;

    .line 79
    .line 80
    .line 81
    move-result-object v6

    .line 82
    move v7, v1

    .line 83
    :goto_3
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    .line 84
    .line 85
    .line 86
    move-result v8

    .line 87
    if-eqz v8, :cond_6

    .line 88
    .line 89
    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 90
    .line 91
    .line 92
    move-result-object v8

    .line 93
    check-cast v8, Ljava/lang/Number;

    .line 94
    .line 95
    invoke-virtual {v8}, Ljava/lang/Number;->byteValue()B

    .line 96
    .line 97
    .line 98
    move-result v8

    .line 99
    if-nez v8, :cond_5

    .line 100
    .line 101
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 102
    .line 103
    .line 104
    move-result-object v8

    .line 105
    new-instance v9, Ljava/lang/String;

    .line 106
    .line 107
    sget-object v10, Lly0/a;->a:Ljava/nio/charset/Charset;

    .line 108
    .line 109
    invoke-direct {v9, v0, v10}, Ljava/lang/String;-><init>([BLjava/nio/charset/Charset;)V

    .line 110
    .line 111
    .line 112
    invoke-interface {v3, v8, v9}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 113
    .line 114
    .line 115
    new-array v0, v1, [B

    .line 116
    .line 117
    add-int/lit8 v7, v7, 0x1

    .line 118
    .line 119
    goto :goto_3

    .line 120
    :cond_5
    array-length v9, v0

    .line 121
    add-int/lit8 v10, v9, 0x1

    .line 122
    .line 123
    invoke-static {v0, v10}, Ljava/util/Arrays;->copyOf([BI)[B

    .line 124
    .line 125
    .line 126
    move-result-object v0

    .line 127
    aput-byte v8, v0, v9

    .line 128
    .line 129
    goto :goto_3

    .line 130
    :cond_6
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 131
    .line 132
    .line 133
    move-result-object v0

    .line 134
    invoke-virtual {v3, v0}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 135
    .line 136
    .line 137
    move-result-object v0

    .line 138
    move-object v7, v0

    .line 139
    check-cast v7, Ljava/lang/String;

    .line 140
    .line 141
    if-nez v7, :cond_7

    .line 142
    .line 143
    new-instance v0, Lmz0/b;

    .line 144
    .line 145
    const/4 v1, 0x6

    .line 146
    invoke-direct {v0, v1}, Lmz0/b;-><init>(I)V

    .line 147
    .line 148
    .line 149
    invoke-static {p0, v5, v4, v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 150
    .line 151
    .line 152
    return-object v4

    .line 153
    :cond_7
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 154
    .line 155
    .line 156
    move-result-object v0

    .line 157
    invoke-virtual {v3, v0}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 158
    .line 159
    .line 160
    move-result-object v0

    .line 161
    move-object v9, v0

    .line 162
    check-cast v9, Ljava/lang/String;

    .line 163
    .line 164
    if-nez v9, :cond_8

    .line 165
    .line 166
    new-instance v0, Lmz0/b;

    .line 167
    .line 168
    const/4 v1, 0x7

    .line 169
    invoke-direct {v0, v1}, Lmz0/b;-><init>(I)V

    .line 170
    .line 171
    .line 172
    invoke-static {p0, v5, v4, v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 173
    .line 174
    .line 175
    return-object v4

    .line 176
    :cond_8
    const/4 v0, 0x2

    .line 177
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 178
    .line 179
    .line 180
    move-result-object v0

    .line 181
    invoke-virtual {v3, v0}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 182
    .line 183
    .line 184
    move-result-object v0

    .line 185
    move-object v10, v0

    .line 186
    check-cast v10, Ljava/lang/String;

    .line 187
    .line 188
    if-nez v10, :cond_9

    .line 189
    .line 190
    new-instance v0, Lmz0/b;

    .line 191
    .line 192
    const/16 v1, 0x8

    .line 193
    .line 194
    invoke-direct {v0, v1}, Lmz0/b;-><init>(I)V

    .line 195
    .line 196
    .line 197
    invoke-static {p0, v5, v4, v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 198
    .line 199
    .line 200
    return-object v4

    .line 201
    :cond_9
    const/4 v0, 0x3

    .line 202
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 203
    .line 204
    .line 205
    move-result-object v0

    .line 206
    invoke-virtual {v3, v0}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 207
    .line 208
    .line 209
    move-result-object v0

    .line 210
    move-object v11, v0

    .line 211
    check-cast v11, Ljava/lang/String;

    .line 212
    .line 213
    if-nez v11, :cond_a

    .line 214
    .line 215
    new-instance v0, Lmz0/b;

    .line 216
    .line 217
    const/16 v1, 0x9

    .line 218
    .line 219
    invoke-direct {v0, v1}, Lmz0/b;-><init>(I)V

    .line 220
    .line 221
    .line 222
    invoke-static {p0, v5, v4, v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 223
    .line 224
    .line 225
    return-object v4

    .line 226
    :cond_a
    const/4 v0, 0x4

    .line 227
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 228
    .line 229
    .line 230
    move-result-object v0

    .line 231
    invoke-virtual {v3, v0}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 232
    .line 233
    .line 234
    move-result-object v0

    .line 235
    move-object v12, v0

    .line 236
    check-cast v12, Ljava/lang/String;

    .line 237
    .line 238
    if-nez v12, :cond_b

    .line 239
    .line 240
    new-instance v0, Lmz0/b;

    .line 241
    .line 242
    const/16 v1, 0xa

    .line 243
    .line 244
    invoke-direct {v0, v1}, Lmz0/b;-><init>(I)V

    .line 245
    .line 246
    .line 247
    invoke-static {p0, v5, v4, v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 248
    .line 249
    .line 250
    return-object v4

    .line 251
    :cond_b
    const/4 v0, 0x5

    .line 252
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 253
    .line 254
    .line 255
    move-result-object v0

    .line 256
    invoke-virtual {v3, v0}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 257
    .line 258
    .line 259
    move-result-object v0

    .line 260
    move-object v8, v0

    .line 261
    check-cast v8, Ljava/lang/String;

    .line 262
    .line 263
    if-nez v8, :cond_c

    .line 264
    .line 265
    new-instance v0, Lmz0/b;

    .line 266
    .line 267
    const/16 v1, 0xb

    .line 268
    .line 269
    invoke-direct {v0, v1}, Lmz0/b;-><init>(I)V

    .line 270
    .line 271
    .line 272
    invoke-static {p0, v5, v4, v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 273
    .line 274
    .line 275
    return-object v4

    .line 276
    :cond_c
    new-instance v6, Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponse;

    .line 277
    .line 278
    invoke-direct/range {v6 .. v12}, Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponse;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 279
    .line 280
    .line 281
    return-object v6

    .line 282
    :cond_d
    new-instance v0, Ln51/a;

    .line 283
    .line 284
    const/4 v1, 0x5

    .line 285
    invoke-direct {v0, v1, p0}, Ln51/a;-><init>(I[B)V

    .line 286
    .line 287
    .line 288
    invoke-static {p0, v5, v4, v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 289
    .line 290
    .line 291
    return-object v4
.end method

.method private static final toSmartphoneInformationResponse$lambda$1(B[B)Ljava/lang/String;
    .locals 2

    .line 1
    const/16 v0, 0x10

    .line 2
    .line 3
    invoke-static {v0}, Lry/a;->a(I)V

    .line 4
    .line 5
    .line 6
    invoke-static {p0, v0}, Ljava/lang/Integer;->toString(II)Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    const-string v0, "toString(...)"

    .line 11
    .line 12
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    const-string v0, "<this>"

    .line 16
    .line 17
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    array-length v0, p1

    .line 21
    if-nez v0, :cond_0

    .line 22
    .line 23
    const/4 p1, 0x0

    .line 24
    goto :goto_0

    .line 25
    :cond_0
    array-length v0, p1

    .line 26
    add-int/lit8 v0, v0, -0x1

    .line 27
    .line 28
    aget-byte p1, p1, v0

    .line 29
    .line 30
    invoke-static {p1}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 31
    .line 32
    .line 33
    move-result-object p1

    .line 34
    :goto_0
    new-instance v0, Ljava/lang/StringBuilder;

    .line 35
    .line 36
    const-string v1, "toSmartphoneInformationResponse(): SmartphoneInformationResponse must end with "

    .line 37
    .line 38
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 42
    .line 43
    .line 44
    const-string p0, ", but ends with "

    .line 45
    .line 46
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 47
    .line 48
    .line 49
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 50
    .line 51
    .line 52
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    return-object p0
.end method

.method private static final toSmartphoneInformationResponse$lambda$2(I)Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "toSmartphoneInformationResponse(): SmartphoneInformationResponse should have 6 delimiter but has "

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method private static final toSmartphoneInformationResponse$lambda$4$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "toSmartphoneInformationResponse(): could not decode \'phoneName\'"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final toSmartphoneInformationResponse$lambda$5$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "toSmartphoneInformationResponse(): could not decode \'manufacturerName\'"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final toSmartphoneInformationResponse$lambda$6$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "toSmartphoneInformationResponse(): could not decode \'modelName\'"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final toSmartphoneInformationResponse$lambda$7$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "toSmartphoneInformationResponse(): could not decode \'swVersion\'"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final toSmartphoneInformationResponse$lambda$8$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "toSmartphoneInformationResponse(): could not decode \'appVersion\'"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final toSmartphoneInformationResponse$lambda$9$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "toSmartphoneInformationResponse(): could not decode \'appName\'"

    .line 2
    .line 3
    return-object v0
.end method
