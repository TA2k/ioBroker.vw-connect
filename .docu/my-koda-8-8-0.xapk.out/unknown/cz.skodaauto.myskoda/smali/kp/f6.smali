.class public abstract Lkp/f6;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(DLqr0/s;Lqr0/e;)Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "unitsType"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-static {p0, p1, p2, p3}, Lkp/f6;->c(DLqr0/s;Lqr0/e;)Llx0/l;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    iget-object p1, p0, Llx0/l;->d:Ljava/lang/Object;

    .line 11
    .line 12
    iget-object p0, p0, Llx0/l;->e:Ljava/lang/Object;

    .line 13
    .line 14
    new-instance p2, Ljava/lang/StringBuilder;

    .line 15
    .line 16
    invoke-direct {p2}, Ljava/lang/StringBuilder;-><init>()V

    .line 17
    .line 18
    .line 19
    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    const-string p1, " "

    .line 23
    .line 24
    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 25
    .line 26
    .line 27
    invoke-virtual {p2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    return-object p0
.end method

.method public static final b(DLqr0/s;)D
    .locals 2

    .line 1
    invoke-virtual {p2}, Ljava/lang/Enum;->ordinal()I

    .line 2
    .line 3
    .line 4
    move-result p2

    .line 5
    if-eqz p2, :cond_2

    .line 6
    .line 7
    const/4 v0, 0x1

    .line 8
    if-eq p2, v0, :cond_1

    .line 9
    .line 10
    const/4 v0, 0x2

    .line 11
    if-ne p2, v0, :cond_0

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    new-instance p0, La8/r0;

    .line 15
    .line 16
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 17
    .line 18
    .line 19
    throw p0

    .line 20
    :cond_1
    :goto_0
    const-wide v0, 0x4099258000000000L    # 1609.375

    .line 21
    .line 22
    .line 23
    .line 24
    .line 25
    :goto_1
    div-double/2addr p0, v0

    .line 26
    goto :goto_2

    .line 27
    :cond_2
    const-wide v0, 0x408f400000000000L    # 1000.0

    .line 28
    .line 29
    .line 30
    .line 31
    .line 32
    goto :goto_1

    .line 33
    :goto_2
    invoke-static {p0, p1}, Lkp/k6;->b(D)D

    .line 34
    .line 35
    .line 36
    move-result-wide p0

    .line 37
    return-wide p0
.end method

.method public static final c(DLqr0/s;Lqr0/e;)Llx0/l;
    .locals 18

    .line 1
    move-wide/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v2, p3

    .line 4
    .line 5
    const-string v3, "unitsType"

    .line 6
    .line 7
    move-object/from16 v4, p2

    .line 8
    .line 9
    invoke-static {v4, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    invoke-virtual {v4}, Ljava/lang/Enum;->ordinal()I

    .line 13
    .line 14
    .line 15
    move-result v3

    .line 16
    const/4 v4, 0x0

    .line 17
    const-string v5, "0"

    .line 18
    .line 19
    const-wide/16 v6, 0x0

    .line 20
    .line 21
    const/16 v8, 0x32

    .line 22
    .line 23
    const-wide/high16 v9, 0x4024000000000000L    # 10.0

    .line 24
    .line 25
    const/4 v11, 0x1

    .line 26
    if-eqz v3, :cond_7

    .line 27
    .line 28
    if-eq v3, v11, :cond_1

    .line 29
    .line 30
    const/4 v12, 0x2

    .line 31
    if-ne v3, v12, :cond_0

    .line 32
    .line 33
    goto :goto_0

    .line 34
    :cond_0
    new-instance v0, La8/r0;

    .line 35
    .line 36
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 37
    .line 38
    .line 39
    throw v0

    .line 40
    :cond_1
    :goto_0
    sget-object v3, Lqr0/f;->h:Lqr0/f;

    .line 41
    .line 42
    invoke-static {v3}, Lkp/m6;->a(Lqr0/m;)Ljava/lang/String;

    .line 43
    .line 44
    .line 45
    move-result-object v3

    .line 46
    sget-object v12, Lqr0/f;->d:Lqr0/f;

    .line 47
    .line 48
    invoke-static {v12}, Lkp/m6;->a(Lqr0/m;)Ljava/lang/String;

    .line 49
    .line 50
    .line 51
    move-result-object v12

    .line 52
    sget-object v13, Lqr0/e;->e:Lqr0/e;

    .line 53
    .line 54
    const-wide v14, 0x4099258000000000L    # 1609.375

    .line 55
    .line 56
    .line 57
    .line 58
    .line 59
    if-eq v2, v13, :cond_6

    .line 60
    .line 61
    div-double v16, v0, v14

    .line 62
    .line 63
    cmpl-double v2, v16, v9

    .line 64
    .line 65
    if-ltz v2, :cond_2

    .line 66
    .line 67
    goto :goto_1

    .line 68
    :cond_2
    const-wide v9, 0x3fd381d7dbf487fdL    # 0.3048

    .line 69
    .line 70
    .line 71
    .line 72
    .line 73
    div-double/2addr v0, v9

    .line 74
    const-wide v9, 0x4080800000000000L    # 528.0

    .line 75
    .line 76
    .line 77
    .line 78
    .line 79
    cmpl-double v2, v0, v9

    .line 80
    .line 81
    if-ltz v2, :cond_3

    .line 82
    .line 83
    const-wide v4, 0x40b4a01a096825a0L    # 5280.101706036745

    .line 84
    .line 85
    .line 86
    .line 87
    .line 88
    div-double/2addr v0, v4

    .line 89
    invoke-static {v11, v0, v1}, Lkp/k6;->a(ID)Ljava/lang/String;

    .line 90
    .line 91
    .line 92
    move-result-object v0

    .line 93
    new-instance v1, Llx0/l;

    .line 94
    .line 95
    invoke-direct {v1, v0, v3}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 96
    .line 97
    .line 98
    return-object v1

    .line 99
    :cond_3
    const-wide/high16 v9, 0x4059000000000000L    # 100.0

    .line 100
    .line 101
    cmpl-double v2, v0, v9

    .line 102
    .line 103
    if-ltz v2, :cond_4

    .line 104
    .line 105
    int-to-double v2, v8

    .line 106
    div-double/2addr v0, v2

    .line 107
    invoke-static {v0, v1}, Lkp/k6;->b(D)D

    .line 108
    .line 109
    .line 110
    move-result-wide v0

    .line 111
    mul-double/2addr v0, v2

    .line 112
    invoke-static {v4, v0, v1}, Lkp/k6;->a(ID)Ljava/lang/String;

    .line 113
    .line 114
    .line 115
    move-result-object v0

    .line 116
    new-instance v1, Llx0/l;

    .line 117
    .line 118
    invoke-direct {v1, v0, v12}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 119
    .line 120
    .line 121
    return-object v1

    .line 122
    :cond_4
    cmpg-double v2, v0, v6

    .line 123
    .line 124
    if-nez v2, :cond_5

    .line 125
    .line 126
    new-instance v0, Llx0/l;

    .line 127
    .line 128
    invoke-direct {v0, v5, v3}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 129
    .line 130
    .line 131
    return-object v0

    .line 132
    :cond_5
    invoke-static {v4, v0, v1}, Lkp/k6;->a(ID)Ljava/lang/String;

    .line 133
    .line 134
    .line 135
    move-result-object v0

    .line 136
    new-instance v1, Llx0/l;

    .line 137
    .line 138
    invoke-direct {v1, v0, v12}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 139
    .line 140
    .line 141
    return-object v1

    .line 142
    :cond_6
    :goto_1
    div-double/2addr v0, v14

    .line 143
    invoke-static {v4, v0, v1}, Lkp/k6;->a(ID)Ljava/lang/String;

    .line 144
    .line 145
    .line 146
    move-result-object v0

    .line 147
    new-instance v1, Llx0/l;

    .line 148
    .line 149
    invoke-direct {v1, v0, v3}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 150
    .line 151
    .line 152
    return-object v1

    .line 153
    :cond_7
    sget-object v3, Lqr0/f;->e:Lqr0/f;

    .line 154
    .line 155
    invoke-static {v3}, Lkp/m6;->a(Lqr0/m;)Ljava/lang/String;

    .line 156
    .line 157
    .line 158
    move-result-object v3

    .line 159
    sget-object v12, Lqr0/f;->g:Lqr0/f;

    .line 160
    .line 161
    invoke-static {v12}, Lkp/m6;->a(Lqr0/m;)Ljava/lang/String;

    .line 162
    .line 163
    .line 164
    move-result-object v12

    .line 165
    sget-object v13, Lqr0/e;->e:Lqr0/e;

    .line 166
    .line 167
    const-wide v14, 0x408f400000000000L    # 1000.0

    .line 168
    .line 169
    .line 170
    .line 171
    .line 172
    if-eq v2, v13, :cond_d

    .line 173
    .line 174
    move-wide/from16 v16, v6

    .line 175
    .line 176
    div-double v6, v0, v14

    .line 177
    .line 178
    cmpl-double v2, v6, v9

    .line 179
    .line 180
    if-ltz v2, :cond_8

    .line 181
    .line 182
    goto :goto_2

    .line 183
    :cond_8
    const-wide/high16 v13, 0x3ff0000000000000L    # 1.0

    .line 184
    .line 185
    cmpl-double v2, v6, v13

    .line 186
    .line 187
    if-ltz v2, :cond_9

    .line 188
    .line 189
    invoke-static {v11, v6, v7}, Lkp/k6;->a(ID)Ljava/lang/String;

    .line 190
    .line 191
    .line 192
    move-result-object v0

    .line 193
    new-instance v1, Llx0/l;

    .line 194
    .line 195
    invoke-direct {v1, v0, v3}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 196
    .line 197
    .line 198
    return-object v1

    .line 199
    :cond_9
    const-wide v6, 0x4072c00000000000L    # 300.0

    .line 200
    .line 201
    .line 202
    .line 203
    .line 204
    cmpl-double v2, v0, v6

    .line 205
    .line 206
    if-ltz v2, :cond_a

    .line 207
    .line 208
    int-to-double v2, v8

    .line 209
    div-double/2addr v0, v2

    .line 210
    invoke-static {v0, v1}, Lkp/k6;->b(D)D

    .line 211
    .line 212
    .line 213
    move-result-wide v0

    .line 214
    mul-double/2addr v0, v2

    .line 215
    invoke-static {v4, v0, v1}, Lkp/k6;->a(ID)Ljava/lang/String;

    .line 216
    .line 217
    .line 218
    move-result-object v0

    .line 219
    new-instance v1, Llx0/l;

    .line 220
    .line 221
    invoke-direct {v1, v0, v12}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 222
    .line 223
    .line 224
    return-object v1

    .line 225
    :cond_a
    cmpl-double v2, v0, v9

    .line 226
    .line 227
    if-ltz v2, :cond_b

    .line 228
    .line 229
    const/16 v2, 0xa

    .line 230
    .line 231
    int-to-double v2, v2

    .line 232
    div-double/2addr v0, v2

    .line 233
    invoke-static {v0, v1}, Lkp/k6;->b(D)D

    .line 234
    .line 235
    .line 236
    move-result-wide v0

    .line 237
    mul-double/2addr v0, v2

    .line 238
    invoke-static {v4, v0, v1}, Lkp/k6;->a(ID)Ljava/lang/String;

    .line 239
    .line 240
    .line 241
    move-result-object v0

    .line 242
    new-instance v1, Llx0/l;

    .line 243
    .line 244
    invoke-direct {v1, v0, v12}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 245
    .line 246
    .line 247
    return-object v1

    .line 248
    :cond_b
    cmpg-double v2, v0, v16

    .line 249
    .line 250
    if-nez v2, :cond_c

    .line 251
    .line 252
    new-instance v0, Llx0/l;

    .line 253
    .line 254
    invoke-direct {v0, v5, v3}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 255
    .line 256
    .line 257
    return-object v0

    .line 258
    :cond_c
    invoke-static {v4, v0, v1}, Lkp/k6;->a(ID)Ljava/lang/String;

    .line 259
    .line 260
    .line 261
    move-result-object v0

    .line 262
    new-instance v1, Llx0/l;

    .line 263
    .line 264
    invoke-direct {v1, v0, v12}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 265
    .line 266
    .line 267
    return-object v1

    .line 268
    :cond_d
    :goto_2
    div-double/2addr v0, v14

    .line 269
    invoke-static {v4, v0, v1}, Lkp/k6;->a(ID)Ljava/lang/String;

    .line 270
    .line 271
    .line 272
    move-result-object v0

    .line 273
    new-instance v1, Llx0/l;

    .line 274
    .line 275
    invoke-direct {v1, v0, v3}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 276
    .line 277
    .line 278
    return-object v1
.end method
