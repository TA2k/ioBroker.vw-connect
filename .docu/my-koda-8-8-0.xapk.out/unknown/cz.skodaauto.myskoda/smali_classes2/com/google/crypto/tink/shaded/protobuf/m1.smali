.class public final Lcom/google/crypto/tink/shaded/protobuf/m1;
.super Lcom/google/crypto/tink/shaded/protobuf/q0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic a:I


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lcom/google/crypto/tink/shaded/protobuf/m1;->a:I

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public static z(J[BII)I
    .locals 2

    .line 1
    if-eqz p4, :cond_2

    .line 2
    .line 3
    const/4 v0, 0x1

    .line 4
    if-eq p4, v0, :cond_1

    .line 5
    .line 6
    const/4 v0, 0x2

    .line 7
    if-ne p4, v0, :cond_0

    .line 8
    .line 9
    invoke-static {p2, p0, p1}, Lcom/google/crypto/tink/shaded/protobuf/l1;->f([BJ)B

    .line 10
    .line 11
    .line 12
    move-result p4

    .line 13
    const-wide/16 v0, 0x1

    .line 14
    .line 15
    add-long/2addr p0, v0

    .line 16
    invoke-static {p2, p0, p1}, Lcom/google/crypto/tink/shaded/protobuf/l1;->f([BJ)B

    .line 17
    .line 18
    .line 19
    move-result p0

    .line 20
    invoke-static {p3, p4, p0}, Lcom/google/crypto/tink/shaded/protobuf/o1;->d(III)I

    .line 21
    .line 22
    .line 23
    move-result p0

    .line 24
    return p0

    .line 25
    :cond_0
    new-instance p0, Ljava/lang/AssertionError;

    .line 26
    .line 27
    invoke-direct {p0}, Ljava/lang/AssertionError;-><init>()V

    .line 28
    .line 29
    .line 30
    throw p0

    .line 31
    :cond_1
    invoke-static {p2, p0, p1}, Lcom/google/crypto/tink/shaded/protobuf/l1;->f([BJ)B

    .line 32
    .line 33
    .line 34
    move-result p0

    .line 35
    invoke-static {p3, p0}, Lcom/google/crypto/tink/shaded/protobuf/o1;->c(II)I

    .line 36
    .line 37
    .line 38
    move-result p0

    .line 39
    return p0

    .line 40
    :cond_2
    sget-object p0, Lcom/google/crypto/tink/shaded/protobuf/o1;->a:Lcom/google/crypto/tink/shaded/protobuf/q0;

    .line 41
    .line 42
    const/16 p0, -0xc

    .line 43
    .line 44
    if-le p3, p0, :cond_3

    .line 45
    .line 46
    const/4 p0, -0x1

    .line 47
    return p0

    .line 48
    :cond_3
    return p3
.end method


# virtual methods
.method public final n([BII)Ljava/lang/String;
    .locals 9

    .line 1
    iget p0, p0, Lcom/google/crypto/tink/shaded/protobuf/m1;->a:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    or-int p0, p2, p3

    .line 7
    .line 8
    array-length v0, p1

    .line 9
    sub-int/2addr v0, p2

    .line 10
    sub-int/2addr v0, p3

    .line 11
    or-int/2addr p0, v0

    .line 12
    if-ltz p0, :cond_9

    .line 13
    .line 14
    add-int p0, p2, p3

    .line 15
    .line 16
    new-array v4, p3, [C

    .line 17
    .line 18
    const/4 p3, 0x0

    .line 19
    move v0, p3

    .line 20
    :goto_0
    if-ge p2, p0, :cond_0

    .line 21
    .line 22
    int-to-long v1, p2

    .line 23
    invoke-static {p1, v1, v2}, Lcom/google/crypto/tink/shaded/protobuf/l1;->f([BJ)B

    .line 24
    .line 25
    .line 26
    move-result v1

    .line 27
    if-ltz v1, :cond_0

    .line 28
    .line 29
    add-int/lit8 p2, p2, 0x1

    .line 30
    .line 31
    add-int/lit8 v2, v0, 0x1

    .line 32
    .line 33
    int-to-char v1, v1

    .line 34
    aput-char v1, v4, v0

    .line 35
    .line 36
    move v0, v2

    .line 37
    goto :goto_0

    .line 38
    :cond_0
    move v5, v0

    .line 39
    :goto_1
    if-ge p2, p0, :cond_8

    .line 40
    .line 41
    add-int/lit8 v0, p2, 0x1

    .line 42
    .line 43
    int-to-long v1, p2

    .line 44
    invoke-static {p1, v1, v2}, Lcom/google/crypto/tink/shaded/protobuf/l1;->f([BJ)B

    .line 45
    .line 46
    .line 47
    move-result v1

    .line 48
    if-ltz v1, :cond_2

    .line 49
    .line 50
    add-int/lit8 p2, v5, 0x1

    .line 51
    .line 52
    int-to-char v1, v1

    .line 53
    aput-char v1, v4, v5

    .line 54
    .line 55
    :goto_2
    if-ge v0, p0, :cond_1

    .line 56
    .line 57
    int-to-long v1, v0

    .line 58
    invoke-static {p1, v1, v2}, Lcom/google/crypto/tink/shaded/protobuf/l1;->f([BJ)B

    .line 59
    .line 60
    .line 61
    move-result v1

    .line 62
    if-ltz v1, :cond_1

    .line 63
    .line 64
    add-int/lit8 v0, v0, 0x1

    .line 65
    .line 66
    add-int/lit8 v2, p2, 0x1

    .line 67
    .line 68
    int-to-char v1, v1

    .line 69
    aput-char v1, v4, p2

    .line 70
    .line 71
    move p2, v2

    .line 72
    goto :goto_2

    .line 73
    :cond_1
    move v5, p2

    .line 74
    move p2, v0

    .line 75
    goto :goto_1

    .line 76
    :cond_2
    const/16 v2, -0x20

    .line 77
    .line 78
    if-ge v1, v2, :cond_4

    .line 79
    .line 80
    if-ge v0, p0, :cond_3

    .line 81
    .line 82
    add-int/lit8 p2, p2, 0x2

    .line 83
    .line 84
    int-to-long v2, v0

    .line 85
    invoke-static {p1, v2, v3}, Lcom/google/crypto/tink/shaded/protobuf/l1;->f([BJ)B

    .line 86
    .line 87
    .line 88
    move-result v0

    .line 89
    add-int/lit8 v2, v5, 0x1

    .line 90
    .line 91
    invoke-static {v1, v0, v4, v5}, Lcom/google/crypto/tink/shaded/protobuf/q0;->b(BB[CI)V

    .line 92
    .line 93
    .line 94
    move v5, v2

    .line 95
    goto :goto_1

    .line 96
    :cond_3
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/d0;->a()Lcom/google/crypto/tink/shaded/protobuf/d0;

    .line 97
    .line 98
    .line 99
    move-result-object p0

    .line 100
    throw p0

    .line 101
    :cond_4
    const/16 v2, -0x10

    .line 102
    .line 103
    if-ge v1, v2, :cond_6

    .line 104
    .line 105
    add-int/lit8 v2, p0, -0x1

    .line 106
    .line 107
    if-ge v0, v2, :cond_5

    .line 108
    .line 109
    add-int/lit8 v2, p2, 0x2

    .line 110
    .line 111
    int-to-long v6, v0

    .line 112
    invoke-static {p1, v6, v7}, Lcom/google/crypto/tink/shaded/protobuf/l1;->f([BJ)B

    .line 113
    .line 114
    .line 115
    move-result v0

    .line 116
    add-int/lit8 p2, p2, 0x3

    .line 117
    .line 118
    int-to-long v2, v2

    .line 119
    invoke-static {p1, v2, v3}, Lcom/google/crypto/tink/shaded/protobuf/l1;->f([BJ)B

    .line 120
    .line 121
    .line 122
    move-result v2

    .line 123
    add-int/lit8 v3, v5, 0x1

    .line 124
    .line 125
    invoke-static {v1, v0, v2, v4, v5}, Lcom/google/crypto/tink/shaded/protobuf/q0;->c(BBB[CI)V

    .line 126
    .line 127
    .line 128
    move v5, v3

    .line 129
    goto :goto_1

    .line 130
    :cond_5
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/d0;->a()Lcom/google/crypto/tink/shaded/protobuf/d0;

    .line 131
    .line 132
    .line 133
    move-result-object p0

    .line 134
    throw p0

    .line 135
    :cond_6
    add-int/lit8 v2, p0, -0x2

    .line 136
    .line 137
    if-ge v0, v2, :cond_7

    .line 138
    .line 139
    add-int/lit8 v2, p2, 0x2

    .line 140
    .line 141
    int-to-long v6, v0

    .line 142
    invoke-static {p1, v6, v7}, Lcom/google/crypto/tink/shaded/protobuf/l1;->f([BJ)B

    .line 143
    .line 144
    .line 145
    move-result v0

    .line 146
    add-int/lit8 v3, p2, 0x3

    .line 147
    .line 148
    int-to-long v6, v2

    .line 149
    invoke-static {p1, v6, v7}, Lcom/google/crypto/tink/shaded/protobuf/l1;->f([BJ)B

    .line 150
    .line 151
    .line 152
    move-result v2

    .line 153
    add-int/lit8 p2, p2, 0x4

    .line 154
    .line 155
    int-to-long v6, v3

    .line 156
    invoke-static {p1, v6, v7}, Lcom/google/crypto/tink/shaded/protobuf/l1;->f([BJ)B

    .line 157
    .line 158
    .line 159
    move-result v3

    .line 160
    move v8, v1

    .line 161
    move v1, v0

    .line 162
    move v0, v8

    .line 163
    invoke-static/range {v0 .. v5}, Lcom/google/crypto/tink/shaded/protobuf/q0;->a(BBBB[CI)V

    .line 164
    .line 165
    .line 166
    add-int/lit8 v5, v5, 0x2

    .line 167
    .line 168
    goto/16 :goto_1

    .line 169
    .line 170
    :cond_7
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/d0;->a()Lcom/google/crypto/tink/shaded/protobuf/d0;

    .line 171
    .line 172
    .line 173
    move-result-object p0

    .line 174
    throw p0

    .line 175
    :cond_8
    new-instance p0, Ljava/lang/String;

    .line 176
    .line 177
    invoke-direct {p0, v4, p3, v5}, Ljava/lang/String;-><init>([CII)V

    .line 178
    .line 179
    .line 180
    return-object p0

    .line 181
    :cond_9
    new-instance p0, Ljava/lang/ArrayIndexOutOfBoundsException;

    .line 182
    .line 183
    array-length p1, p1

    .line 184
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 185
    .line 186
    .line 187
    move-result-object p1

    .line 188
    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 189
    .line 190
    .line 191
    move-result-object p2

    .line 192
    invoke-static {p3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 193
    .line 194
    .line 195
    move-result-object p3

    .line 196
    filled-new-array {p1, p2, p3}, [Ljava/lang/Object;

    .line 197
    .line 198
    .line 199
    move-result-object p1

    .line 200
    const-string p2, "buffer length=%d, index=%d, size=%d"

    .line 201
    .line 202
    invoke-static {p2, p1}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 203
    .line 204
    .line 205
    move-result-object p1

    .line 206
    invoke-direct {p0, p1}, Ljava/lang/ArrayIndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    .line 207
    .line 208
    .line 209
    throw p0

    .line 210
    :pswitch_0
    or-int p0, p2, p3

    .line 211
    .line 212
    array-length v0, p1

    .line 213
    sub-int/2addr v0, p2

    .line 214
    sub-int/2addr v0, p3

    .line 215
    or-int/2addr p0, v0

    .line 216
    if-ltz p0, :cond_13

    .line 217
    .line 218
    add-int p0, p2, p3

    .line 219
    .line 220
    new-array v4, p3, [C

    .line 221
    .line 222
    const/4 p3, 0x0

    .line 223
    move v0, p3

    .line 224
    :goto_3
    if-ge p2, p0, :cond_a

    .line 225
    .line 226
    aget-byte v1, p1, p2

    .line 227
    .line 228
    if-ltz v1, :cond_a

    .line 229
    .line 230
    add-int/lit8 p2, p2, 0x1

    .line 231
    .line 232
    add-int/lit8 v2, v0, 0x1

    .line 233
    .line 234
    int-to-char v1, v1

    .line 235
    aput-char v1, v4, v0

    .line 236
    .line 237
    move v0, v2

    .line 238
    goto :goto_3

    .line 239
    :cond_a
    move v5, v0

    .line 240
    :goto_4
    if-ge p2, p0, :cond_12

    .line 241
    .line 242
    add-int/lit8 v0, p2, 0x1

    .line 243
    .line 244
    move v1, v0

    .line 245
    aget-byte v0, p1, p2

    .line 246
    .line 247
    if-ltz v0, :cond_c

    .line 248
    .line 249
    add-int/lit8 p2, v5, 0x1

    .line 250
    .line 251
    int-to-char v0, v0

    .line 252
    aput-char v0, v4, v5

    .line 253
    .line 254
    move v0, v1

    .line 255
    :goto_5
    if-ge v0, p0, :cond_b

    .line 256
    .line 257
    aget-byte v1, p1, v0

    .line 258
    .line 259
    if-ltz v1, :cond_b

    .line 260
    .line 261
    add-int/lit8 v0, v0, 0x1

    .line 262
    .line 263
    add-int/lit8 v2, p2, 0x1

    .line 264
    .line 265
    int-to-char v1, v1

    .line 266
    aput-char v1, v4, p2

    .line 267
    .line 268
    move p2, v2

    .line 269
    goto :goto_5

    .line 270
    :cond_b
    move v5, p2

    .line 271
    move p2, v0

    .line 272
    goto :goto_4

    .line 273
    :cond_c
    const/16 v2, -0x20

    .line 274
    .line 275
    if-ge v0, v2, :cond_e

    .line 276
    .line 277
    if-ge v1, p0, :cond_d

    .line 278
    .line 279
    add-int/lit8 p2, p2, 0x2

    .line 280
    .line 281
    aget-byte v1, p1, v1

    .line 282
    .line 283
    add-int/lit8 v2, v5, 0x1

    .line 284
    .line 285
    invoke-static {v0, v1, v4, v5}, Lcom/google/crypto/tink/shaded/protobuf/q0;->b(BB[CI)V

    .line 286
    .line 287
    .line 288
    move v5, v2

    .line 289
    goto :goto_4

    .line 290
    :cond_d
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/d0;->a()Lcom/google/crypto/tink/shaded/protobuf/d0;

    .line 291
    .line 292
    .line 293
    move-result-object p0

    .line 294
    throw p0

    .line 295
    :cond_e
    const/16 v2, -0x10

    .line 296
    .line 297
    if-ge v0, v2, :cond_10

    .line 298
    .line 299
    add-int/lit8 v2, p0, -0x1

    .line 300
    .line 301
    if-ge v1, v2, :cond_f

    .line 302
    .line 303
    add-int/lit8 v2, p2, 0x2

    .line 304
    .line 305
    aget-byte v1, p1, v1

    .line 306
    .line 307
    add-int/lit8 p2, p2, 0x3

    .line 308
    .line 309
    aget-byte v2, p1, v2

    .line 310
    .line 311
    add-int/lit8 v3, v5, 0x1

    .line 312
    .line 313
    invoke-static {v0, v1, v2, v4, v5}, Lcom/google/crypto/tink/shaded/protobuf/q0;->c(BBB[CI)V

    .line 314
    .line 315
    .line 316
    move v5, v3

    .line 317
    goto :goto_4

    .line 318
    :cond_f
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/d0;->a()Lcom/google/crypto/tink/shaded/protobuf/d0;

    .line 319
    .line 320
    .line 321
    move-result-object p0

    .line 322
    throw p0

    .line 323
    :cond_10
    add-int/lit8 v2, p0, -0x2

    .line 324
    .line 325
    if-ge v1, v2, :cond_11

    .line 326
    .line 327
    add-int/lit8 v2, p2, 0x2

    .line 328
    .line 329
    aget-byte v1, p1, v1

    .line 330
    .line 331
    add-int/lit8 v3, p2, 0x3

    .line 332
    .line 333
    aget-byte v2, p1, v2

    .line 334
    .line 335
    add-int/lit8 p2, p2, 0x4

    .line 336
    .line 337
    aget-byte v3, p1, v3

    .line 338
    .line 339
    invoke-static/range {v0 .. v5}, Lcom/google/crypto/tink/shaded/protobuf/q0;->a(BBBB[CI)V

    .line 340
    .line 341
    .line 342
    add-int/lit8 v5, v5, 0x2

    .line 343
    .line 344
    goto :goto_4

    .line 345
    :cond_11
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/d0;->a()Lcom/google/crypto/tink/shaded/protobuf/d0;

    .line 346
    .line 347
    .line 348
    move-result-object p0

    .line 349
    throw p0

    .line 350
    :cond_12
    new-instance p0, Ljava/lang/String;

    .line 351
    .line 352
    invoke-direct {p0, v4, p3, v5}, Ljava/lang/String;-><init>([CII)V

    .line 353
    .line 354
    .line 355
    return-object p0

    .line 356
    :cond_13
    new-instance p0, Ljava/lang/ArrayIndexOutOfBoundsException;

    .line 357
    .line 358
    array-length p1, p1

    .line 359
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 360
    .line 361
    .line 362
    move-result-object p1

    .line 363
    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 364
    .line 365
    .line 366
    move-result-object p2

    .line 367
    invoke-static {p3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 368
    .line 369
    .line 370
    move-result-object p3

    .line 371
    filled-new-array {p1, p2, p3}, [Ljava/lang/Object;

    .line 372
    .line 373
    .line 374
    move-result-object p1

    .line 375
    const-string p2, "buffer length=%d, index=%d, size=%d"

    .line 376
    .line 377
    invoke-static {p2, p1}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 378
    .line 379
    .line 380
    move-result-object p1

    .line 381
    invoke-direct {p0, p1}, Ljava/lang/ArrayIndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    .line 382
    .line 383
    .line 384
    throw p0

    .line 385
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final s(IILjava/lang/String;[B)I
    .locals 23

    .line 1
    move/from16 v0, p1

    .line 2
    .line 3
    move/from16 v1, p2

    .line 4
    .line 5
    move-object/from16 v2, p3

    .line 6
    .line 7
    move-object/from16 v3, p0

    .line 8
    .line 9
    move-object/from16 v4, p4

    .line 10
    .line 11
    iget v3, v3, Lcom/google/crypto/tink/shaded/protobuf/m1;->a:I

    .line 12
    .line 13
    packed-switch v3, :pswitch_data_0

    .line 14
    .line 15
    .line 16
    int-to-long v5, v0

    .line 17
    int-to-long v7, v1

    .line 18
    add-long/2addr v7, v5

    .line 19
    invoke-virtual {v2}, Ljava/lang/String;->length()I

    .line 20
    .line 21
    .line 22
    move-result v3

    .line 23
    const-string v9, " at index "

    .line 24
    .line 25
    const-string v10, "Failed writing "

    .line 26
    .line 27
    if-gt v3, v1, :cond_c

    .line 28
    .line 29
    array-length v11, v4

    .line 30
    sub-int/2addr v11, v1

    .line 31
    if-lt v11, v0, :cond_c

    .line 32
    .line 33
    const/4 v0, 0x0

    .line 34
    :goto_0
    const-wide/16 v11, 0x1

    .line 35
    .line 36
    const/16 v1, 0x80

    .line 37
    .line 38
    if-ge v0, v3, :cond_0

    .line 39
    .line 40
    invoke-virtual {v2, v0}, Ljava/lang/String;->charAt(I)C

    .line 41
    .line 42
    .line 43
    move-result v13

    .line 44
    if-ge v13, v1, :cond_0

    .line 45
    .line 46
    add-long/2addr v11, v5

    .line 47
    int-to-byte v1, v13

    .line 48
    invoke-static {v4, v5, v6, v1}, Lcom/google/crypto/tink/shaded/protobuf/l1;->j([BJB)V

    .line 49
    .line 50
    .line 51
    add-int/lit8 v0, v0, 0x1

    .line 52
    .line 53
    move-wide v5, v11

    .line 54
    goto :goto_0

    .line 55
    :cond_0
    if-ne v0, v3, :cond_2

    .line 56
    .line 57
    :cond_1
    long-to-int v0, v5

    .line 58
    goto/16 :goto_5

    .line 59
    .line 60
    :cond_2
    :goto_1
    if-ge v0, v3, :cond_1

    .line 61
    .line 62
    invoke-virtual {v2, v0}, Ljava/lang/String;->charAt(I)C

    .line 63
    .line 64
    .line 65
    move-result v13

    .line 66
    if-ge v13, v1, :cond_3

    .line 67
    .line 68
    cmp-long v14, v5, v7

    .line 69
    .line 70
    if-gez v14, :cond_3

    .line 71
    .line 72
    add-long v14, v5, v11

    .line 73
    .line 74
    int-to-byte v13, v13

    .line 75
    invoke-static {v4, v5, v6, v13}, Lcom/google/crypto/tink/shaded/protobuf/l1;->j([BJB)V

    .line 76
    .line 77
    .line 78
    move-wide/from16 v19, v7

    .line 79
    .line 80
    move-wide/from16 p0, v11

    .line 81
    .line 82
    move-wide v5, v14

    .line 83
    goto/16 :goto_4

    .line 84
    .line 85
    :cond_3
    const/16 v14, 0x800

    .line 86
    .line 87
    const-wide/16 v15, 0x2

    .line 88
    .line 89
    if-ge v13, v14, :cond_4

    .line 90
    .line 91
    sub-long v17, v7, v15

    .line 92
    .line 93
    cmp-long v14, v5, v17

    .line 94
    .line 95
    if-gtz v14, :cond_4

    .line 96
    .line 97
    move-wide/from16 p0, v11

    .line 98
    .line 99
    add-long v11, v5, p0

    .line 100
    .line 101
    ushr-int/lit8 v14, v13, 0x6

    .line 102
    .line 103
    or-int/lit16 v14, v14, 0x3c0

    .line 104
    .line 105
    int-to-byte v14, v14

    .line 106
    invoke-static {v4, v5, v6, v14}, Lcom/google/crypto/tink/shaded/protobuf/l1;->j([BJB)V

    .line 107
    .line 108
    .line 109
    add-long/2addr v5, v15

    .line 110
    and-int/lit8 v13, v13, 0x3f

    .line 111
    .line 112
    or-int/2addr v13, v1

    .line 113
    int-to-byte v13, v13

    .line 114
    invoke-static {v4, v11, v12, v13}, Lcom/google/crypto/tink/shaded/protobuf/l1;->j([BJB)V

    .line 115
    .line 116
    .line 117
    move-wide/from16 v19, v7

    .line 118
    .line 119
    goto/16 :goto_4

    .line 120
    .line 121
    :cond_4
    move-wide/from16 p0, v11

    .line 122
    .line 123
    const v11, 0xdfff

    .line 124
    .line 125
    .line 126
    const v12, 0xd800

    .line 127
    .line 128
    .line 129
    const-wide/16 v17, 0x3

    .line 130
    .line 131
    if-lt v13, v12, :cond_6

    .line 132
    .line 133
    if-ge v11, v13, :cond_5

    .line 134
    .line 135
    goto :goto_2

    .line 136
    :cond_5
    move-wide/from16 v19, v7

    .line 137
    .line 138
    goto :goto_3

    .line 139
    :cond_6
    :goto_2
    sub-long v19, v7, v17

    .line 140
    .line 141
    cmp-long v14, v5, v19

    .line 142
    .line 143
    if-gtz v14, :cond_5

    .line 144
    .line 145
    add-long v11, v5, p0

    .line 146
    .line 147
    ushr-int/lit8 v14, v13, 0xc

    .line 148
    .line 149
    or-int/lit16 v14, v14, 0x1e0

    .line 150
    .line 151
    int-to-byte v14, v14

    .line 152
    invoke-static {v4, v5, v6, v14}, Lcom/google/crypto/tink/shaded/protobuf/l1;->j([BJB)V

    .line 153
    .line 154
    .line 155
    add-long v14, v5, v15

    .line 156
    .line 157
    ushr-int/lit8 v16, v13, 0x6

    .line 158
    .line 159
    move-wide/from16 v19, v7

    .line 160
    .line 161
    and-int/lit8 v7, v16, 0x3f

    .line 162
    .line 163
    or-int/2addr v7, v1

    .line 164
    int-to-byte v7, v7

    .line 165
    invoke-static {v4, v11, v12, v7}, Lcom/google/crypto/tink/shaded/protobuf/l1;->j([BJB)V

    .line 166
    .line 167
    .line 168
    add-long v5, v5, v17

    .line 169
    .line 170
    and-int/lit8 v7, v13, 0x3f

    .line 171
    .line 172
    or-int/2addr v7, v1

    .line 173
    int-to-byte v7, v7

    .line 174
    invoke-static {v4, v14, v15, v7}, Lcom/google/crypto/tink/shaded/protobuf/l1;->j([BJB)V

    .line 175
    .line 176
    .line 177
    goto :goto_4

    .line 178
    :goto_3
    const-wide/16 v7, 0x4

    .line 179
    .line 180
    sub-long v21, v19, v7

    .line 181
    .line 182
    cmp-long v14, v5, v21

    .line 183
    .line 184
    if-gtz v14, :cond_9

    .line 185
    .line 186
    add-int/lit8 v11, v0, 0x1

    .line 187
    .line 188
    if-eq v11, v3, :cond_8

    .line 189
    .line 190
    invoke-virtual {v2, v11}, Ljava/lang/String;->charAt(I)C

    .line 191
    .line 192
    .line 193
    move-result v0

    .line 194
    invoke-static {v13, v0}, Ljava/lang/Character;->isSurrogatePair(CC)Z

    .line 195
    .line 196
    .line 197
    move-result v12

    .line 198
    if-eqz v12, :cond_7

    .line 199
    .line 200
    invoke-static {v13, v0}, Ljava/lang/Character;->toCodePoint(CC)I

    .line 201
    .line 202
    .line 203
    move-result v0

    .line 204
    add-long v12, v5, p0

    .line 205
    .line 206
    ushr-int/lit8 v14, v0, 0x12

    .line 207
    .line 208
    or-int/lit16 v14, v14, 0xf0

    .line 209
    .line 210
    int-to-byte v14, v14

    .line 211
    invoke-static {v4, v5, v6, v14}, Lcom/google/crypto/tink/shaded/protobuf/l1;->j([BJB)V

    .line 212
    .line 213
    .line 214
    add-long v14, v5, v15

    .line 215
    .line 216
    ushr-int/lit8 v16, v0, 0xc

    .line 217
    .line 218
    move-wide/from16 v21, v7

    .line 219
    .line 220
    and-int/lit8 v7, v16, 0x3f

    .line 221
    .line 222
    or-int/2addr v7, v1

    .line 223
    int-to-byte v7, v7

    .line 224
    invoke-static {v4, v12, v13, v7}, Lcom/google/crypto/tink/shaded/protobuf/l1;->j([BJB)V

    .line 225
    .line 226
    .line 227
    add-long v7, v5, v17

    .line 228
    .line 229
    ushr-int/lit8 v12, v0, 0x6

    .line 230
    .line 231
    and-int/lit8 v12, v12, 0x3f

    .line 232
    .line 233
    or-int/2addr v12, v1

    .line 234
    int-to-byte v12, v12

    .line 235
    invoke-static {v4, v14, v15, v12}, Lcom/google/crypto/tink/shaded/protobuf/l1;->j([BJB)V

    .line 236
    .line 237
    .line 238
    add-long v5, v5, v21

    .line 239
    .line 240
    and-int/lit8 v0, v0, 0x3f

    .line 241
    .line 242
    or-int/2addr v0, v1

    .line 243
    int-to-byte v0, v0

    .line 244
    invoke-static {v4, v7, v8, v0}, Lcom/google/crypto/tink/shaded/protobuf/l1;->j([BJB)V

    .line 245
    .line 246
    .line 247
    move v0, v11

    .line 248
    :goto_4
    add-int/lit8 v0, v0, 0x1

    .line 249
    .line 250
    move-wide/from16 v11, p0

    .line 251
    .line 252
    move-wide/from16 v7, v19

    .line 253
    .line 254
    goto/16 :goto_1

    .line 255
    .line 256
    :cond_7
    move v0, v11

    .line 257
    :cond_8
    new-instance v1, Lcom/google/crypto/tink/shaded/protobuf/n1;

    .line 258
    .line 259
    add-int/lit8 v0, v0, -0x1

    .line 260
    .line 261
    invoke-direct {v1, v0, v3}, Lcom/google/crypto/tink/shaded/protobuf/n1;-><init>(II)V

    .line 262
    .line 263
    .line 264
    throw v1

    .line 265
    :cond_9
    if-gt v12, v13, :cond_b

    .line 266
    .line 267
    if-gt v13, v11, :cond_b

    .line 268
    .line 269
    add-int/lit8 v1, v0, 0x1

    .line 270
    .line 271
    if-eq v1, v3, :cond_a

    .line 272
    .line 273
    invoke-virtual {v2, v1}, Ljava/lang/String;->charAt(I)C

    .line 274
    .line 275
    .line 276
    move-result v1

    .line 277
    invoke-static {v13, v1}, Ljava/lang/Character;->isSurrogatePair(CC)Z

    .line 278
    .line 279
    .line 280
    move-result v1

    .line 281
    if-nez v1, :cond_b

    .line 282
    .line 283
    :cond_a
    new-instance v1, Lcom/google/crypto/tink/shaded/protobuf/n1;

    .line 284
    .line 285
    invoke-direct {v1, v0, v3}, Lcom/google/crypto/tink/shaded/protobuf/n1;-><init>(II)V

    .line 286
    .line 287
    .line 288
    throw v1

    .line 289
    :cond_b
    new-instance v0, Ljava/lang/ArrayIndexOutOfBoundsException;

    .line 290
    .line 291
    new-instance v1, Ljava/lang/StringBuilder;

    .line 292
    .line 293
    invoke-direct {v1, v10}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 294
    .line 295
    .line 296
    invoke-virtual {v1, v13}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 297
    .line 298
    .line 299
    invoke-virtual {v1, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 300
    .line 301
    .line 302
    invoke-virtual {v1, v5, v6}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 303
    .line 304
    .line 305
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 306
    .line 307
    .line 308
    move-result-object v1

    .line 309
    invoke-direct {v0, v1}, Ljava/lang/ArrayIndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    .line 310
    .line 311
    .line 312
    throw v0

    .line 313
    :goto_5
    return v0

    .line 314
    :cond_c
    new-instance v4, Ljava/lang/ArrayIndexOutOfBoundsException;

    .line 315
    .line 316
    new-instance v5, Ljava/lang/StringBuilder;

    .line 317
    .line 318
    invoke-direct {v5, v10}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 319
    .line 320
    .line 321
    add-int/lit8 v3, v3, -0x1

    .line 322
    .line 323
    invoke-virtual {v2, v3}, Ljava/lang/String;->charAt(I)C

    .line 324
    .line 325
    .line 326
    move-result v2

    .line 327
    invoke-virtual {v5, v2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 328
    .line 329
    .line 330
    invoke-virtual {v5, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 331
    .line 332
    .line 333
    add-int/2addr v0, v1

    .line 334
    invoke-virtual {v5, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 335
    .line 336
    .line 337
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 338
    .line 339
    .line 340
    move-result-object v0

    .line 341
    invoke-direct {v4, v0}, Ljava/lang/ArrayIndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    .line 342
    .line 343
    .line 344
    throw v4

    .line 345
    :pswitch_0
    invoke-virtual {v2}, Ljava/lang/String;->length()I

    .line 346
    .line 347
    .line 348
    move-result v3

    .line 349
    add-int/2addr v1, v0

    .line 350
    const/4 v5, 0x0

    .line 351
    :goto_6
    const/16 v6, 0x80

    .line 352
    .line 353
    if-ge v5, v3, :cond_d

    .line 354
    .line 355
    add-int v7, v5, v0

    .line 356
    .line 357
    if-ge v7, v1, :cond_d

    .line 358
    .line 359
    invoke-virtual {v2, v5}, Ljava/lang/String;->charAt(I)C

    .line 360
    .line 361
    .line 362
    move-result v8

    .line 363
    if-ge v8, v6, :cond_d

    .line 364
    .line 365
    int-to-byte v6, v8

    .line 366
    aput-byte v6, v4, v7

    .line 367
    .line 368
    add-int/lit8 v5, v5, 0x1

    .line 369
    .line 370
    goto :goto_6

    .line 371
    :cond_d
    if-ne v5, v3, :cond_e

    .line 372
    .line 373
    add-int/2addr v0, v3

    .line 374
    goto/16 :goto_9

    .line 375
    .line 376
    :cond_e
    add-int/2addr v0, v5

    .line 377
    :goto_7
    if-ge v5, v3, :cond_18

    .line 378
    .line 379
    invoke-virtual {v2, v5}, Ljava/lang/String;->charAt(I)C

    .line 380
    .line 381
    .line 382
    move-result v7

    .line 383
    if-ge v7, v6, :cond_f

    .line 384
    .line 385
    if-ge v0, v1, :cond_f

    .line 386
    .line 387
    add-int/lit8 v8, v0, 0x1

    .line 388
    .line 389
    int-to-byte v7, v7

    .line 390
    aput-byte v7, v4, v0

    .line 391
    .line 392
    move v0, v8

    .line 393
    goto/16 :goto_8

    .line 394
    .line 395
    :cond_f
    const/16 v8, 0x800

    .line 396
    .line 397
    if-ge v7, v8, :cond_10

    .line 398
    .line 399
    add-int/lit8 v8, v1, -0x2

    .line 400
    .line 401
    if-gt v0, v8, :cond_10

    .line 402
    .line 403
    add-int/lit8 v8, v0, 0x1

    .line 404
    .line 405
    ushr-int/lit8 v9, v7, 0x6

    .line 406
    .line 407
    or-int/lit16 v9, v9, 0x3c0

    .line 408
    .line 409
    int-to-byte v9, v9

    .line 410
    aput-byte v9, v4, v0

    .line 411
    .line 412
    add-int/lit8 v0, v0, 0x2

    .line 413
    .line 414
    and-int/lit8 v7, v7, 0x3f

    .line 415
    .line 416
    or-int/2addr v7, v6

    .line 417
    int-to-byte v7, v7

    .line 418
    aput-byte v7, v4, v8

    .line 419
    .line 420
    goto :goto_8

    .line 421
    :cond_10
    const v8, 0xdfff

    .line 422
    .line 423
    .line 424
    const v9, 0xd800

    .line 425
    .line 426
    .line 427
    if-lt v7, v9, :cond_11

    .line 428
    .line 429
    if-ge v8, v7, :cond_12

    .line 430
    .line 431
    :cond_11
    add-int/lit8 v10, v1, -0x3

    .line 432
    .line 433
    if-gt v0, v10, :cond_12

    .line 434
    .line 435
    add-int/lit8 v8, v0, 0x1

    .line 436
    .line 437
    ushr-int/lit8 v9, v7, 0xc

    .line 438
    .line 439
    or-int/lit16 v9, v9, 0x1e0

    .line 440
    .line 441
    int-to-byte v9, v9

    .line 442
    aput-byte v9, v4, v0

    .line 443
    .line 444
    add-int/lit8 v9, v0, 0x2

    .line 445
    .line 446
    ushr-int/lit8 v10, v7, 0x6

    .line 447
    .line 448
    and-int/lit8 v10, v10, 0x3f

    .line 449
    .line 450
    or-int/2addr v10, v6

    .line 451
    int-to-byte v10, v10

    .line 452
    aput-byte v10, v4, v8

    .line 453
    .line 454
    add-int/lit8 v0, v0, 0x3

    .line 455
    .line 456
    and-int/lit8 v7, v7, 0x3f

    .line 457
    .line 458
    or-int/2addr v7, v6

    .line 459
    int-to-byte v7, v7

    .line 460
    aput-byte v7, v4, v9

    .line 461
    .line 462
    goto :goto_8

    .line 463
    :cond_12
    add-int/lit8 v10, v1, -0x4

    .line 464
    .line 465
    if-gt v0, v10, :cond_15

    .line 466
    .line 467
    add-int/lit8 v8, v5, 0x1

    .line 468
    .line 469
    invoke-virtual {v2}, Ljava/lang/String;->length()I

    .line 470
    .line 471
    .line 472
    move-result v9

    .line 473
    if-eq v8, v9, :cond_14

    .line 474
    .line 475
    invoke-virtual {v2, v8}, Ljava/lang/String;->charAt(I)C

    .line 476
    .line 477
    .line 478
    move-result v5

    .line 479
    invoke-static {v7, v5}, Ljava/lang/Character;->isSurrogatePair(CC)Z

    .line 480
    .line 481
    .line 482
    move-result v9

    .line 483
    if-eqz v9, :cond_13

    .line 484
    .line 485
    invoke-static {v7, v5}, Ljava/lang/Character;->toCodePoint(CC)I

    .line 486
    .line 487
    .line 488
    move-result v5

    .line 489
    add-int/lit8 v7, v0, 0x1

    .line 490
    .line 491
    ushr-int/lit8 v9, v5, 0x12

    .line 492
    .line 493
    or-int/lit16 v9, v9, 0xf0

    .line 494
    .line 495
    int-to-byte v9, v9

    .line 496
    aput-byte v9, v4, v0

    .line 497
    .line 498
    add-int/lit8 v9, v0, 0x2

    .line 499
    .line 500
    ushr-int/lit8 v10, v5, 0xc

    .line 501
    .line 502
    and-int/lit8 v10, v10, 0x3f

    .line 503
    .line 504
    or-int/2addr v10, v6

    .line 505
    int-to-byte v10, v10

    .line 506
    aput-byte v10, v4, v7

    .line 507
    .line 508
    add-int/lit8 v7, v0, 0x3

    .line 509
    .line 510
    ushr-int/lit8 v10, v5, 0x6

    .line 511
    .line 512
    and-int/lit8 v10, v10, 0x3f

    .line 513
    .line 514
    or-int/2addr v10, v6

    .line 515
    int-to-byte v10, v10

    .line 516
    aput-byte v10, v4, v9

    .line 517
    .line 518
    add-int/lit8 v0, v0, 0x4

    .line 519
    .line 520
    and-int/lit8 v5, v5, 0x3f

    .line 521
    .line 522
    or-int/2addr v5, v6

    .line 523
    int-to-byte v5, v5

    .line 524
    aput-byte v5, v4, v7

    .line 525
    .line 526
    move v5, v8

    .line 527
    :goto_8
    add-int/lit8 v5, v5, 0x1

    .line 528
    .line 529
    goto/16 :goto_7

    .line 530
    .line 531
    :cond_13
    move v5, v8

    .line 532
    :cond_14
    new-instance v0, Lcom/google/crypto/tink/shaded/protobuf/n1;

    .line 533
    .line 534
    add-int/lit8 v5, v5, -0x1

    .line 535
    .line 536
    invoke-direct {v0, v5, v3}, Lcom/google/crypto/tink/shaded/protobuf/n1;-><init>(II)V

    .line 537
    .line 538
    .line 539
    throw v0

    .line 540
    :cond_15
    if-gt v9, v7, :cond_17

    .line 541
    .line 542
    if-gt v7, v8, :cond_17

    .line 543
    .line 544
    add-int/lit8 v1, v5, 0x1

    .line 545
    .line 546
    invoke-virtual {v2}, Ljava/lang/String;->length()I

    .line 547
    .line 548
    .line 549
    move-result v4

    .line 550
    if-eq v1, v4, :cond_16

    .line 551
    .line 552
    invoke-virtual {v2, v1}, Ljava/lang/String;->charAt(I)C

    .line 553
    .line 554
    .line 555
    move-result v1

    .line 556
    invoke-static {v7, v1}, Ljava/lang/Character;->isSurrogatePair(CC)Z

    .line 557
    .line 558
    .line 559
    move-result v1

    .line 560
    if-nez v1, :cond_17

    .line 561
    .line 562
    :cond_16
    new-instance v0, Lcom/google/crypto/tink/shaded/protobuf/n1;

    .line 563
    .line 564
    invoke-direct {v0, v5, v3}, Lcom/google/crypto/tink/shaded/protobuf/n1;-><init>(II)V

    .line 565
    .line 566
    .line 567
    throw v0

    .line 568
    :cond_17
    new-instance v1, Ljava/lang/ArrayIndexOutOfBoundsException;

    .line 569
    .line 570
    new-instance v2, Ljava/lang/StringBuilder;

    .line 571
    .line 572
    const-string v3, "Failed writing "

    .line 573
    .line 574
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 575
    .line 576
    .line 577
    invoke-virtual {v2, v7}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 578
    .line 579
    .line 580
    const-string v3, " at index "

    .line 581
    .line 582
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 583
    .line 584
    .line 585
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 586
    .line 587
    .line 588
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 589
    .line 590
    .line 591
    move-result-object v0

    .line 592
    invoke-direct {v1, v0}, Ljava/lang/ArrayIndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    .line 593
    .line 594
    .line 595
    throw v1

    .line 596
    :cond_18
    :goto_9
    return v0

    .line 597
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final w([BII)I
    .locals 12

    .line 1
    iget p0, p0, Lcom/google/crypto/tink/shaded/protobuf/m1;->a:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    or-int p0, p2, p3

    .line 7
    .line 8
    array-length v0, p1

    .line 9
    sub-int/2addr v0, p3

    .line 10
    or-int/2addr p0, v0

    .line 11
    if-ltz p0, :cond_10

    .line 12
    .line 13
    int-to-long v0, p2

    .line 14
    int-to-long p2, p3

    .line 15
    sub-long/2addr p2, v0

    .line 16
    long-to-int p0, p2

    .line 17
    const/16 p2, 0x10

    .line 18
    .line 19
    const/4 p3, 0x0

    .line 20
    const-wide/16 v2, 0x1

    .line 21
    .line 22
    if-ge p0, p2, :cond_0

    .line 23
    .line 24
    move p2, p3

    .line 25
    goto :goto_1

    .line 26
    :cond_0
    move p2, p3

    .line 27
    move-wide v4, v0

    .line 28
    :goto_0
    if-ge p2, p0, :cond_2

    .line 29
    .line 30
    add-long v6, v4, v2

    .line 31
    .line 32
    invoke-static {p1, v4, v5}, Lcom/google/crypto/tink/shaded/protobuf/l1;->f([BJ)B

    .line 33
    .line 34
    .line 35
    move-result v4

    .line 36
    if-gez v4, :cond_1

    .line 37
    .line 38
    goto :goto_1

    .line 39
    :cond_1
    add-int/lit8 p2, p2, 0x1

    .line 40
    .line 41
    move-wide v4, v6

    .line 42
    goto :goto_0

    .line 43
    :cond_2
    move p2, p0

    .line 44
    :goto_1
    sub-int/2addr p0, p2

    .line 45
    int-to-long v4, p2

    .line 46
    add-long/2addr v0, v4

    .line 47
    :cond_3
    :goto_2
    move p2, p3

    .line 48
    :goto_3
    if-lez p0, :cond_5

    .line 49
    .line 50
    add-long v4, v0, v2

    .line 51
    .line 52
    invoke-static {p1, v0, v1}, Lcom/google/crypto/tink/shaded/protobuf/l1;->f([BJ)B

    .line 53
    .line 54
    .line 55
    move-result p2

    .line 56
    if-ltz p2, :cond_4

    .line 57
    .line 58
    add-int/lit8 p0, p0, -0x1

    .line 59
    .line 60
    move-wide v0, v4

    .line 61
    goto :goto_3

    .line 62
    :cond_4
    move-wide v0, v4

    .line 63
    :cond_5
    if-nez p0, :cond_6

    .line 64
    .line 65
    goto/16 :goto_5

    .line 66
    .line 67
    :cond_6
    add-int/lit8 v4, p0, -0x1

    .line 68
    .line 69
    const/16 v5, -0x20

    .line 70
    .line 71
    const/16 v6, -0x41

    .line 72
    .line 73
    if-ge p2, v5, :cond_9

    .line 74
    .line 75
    if-nez v4, :cond_7

    .line 76
    .line 77
    move p3, p2

    .line 78
    goto/16 :goto_5

    .line 79
    .line 80
    :cond_7
    add-int/lit8 p0, p0, -0x2

    .line 81
    .line 82
    const/16 v4, -0x3e

    .line 83
    .line 84
    if-lt p2, v4, :cond_f

    .line 85
    .line 86
    add-long v4, v0, v2

    .line 87
    .line 88
    invoke-static {p1, v0, v1}, Lcom/google/crypto/tink/shaded/protobuf/l1;->f([BJ)B

    .line 89
    .line 90
    .line 91
    move-result p2

    .line 92
    if-le p2, v6, :cond_8

    .line 93
    .line 94
    goto :goto_4

    .line 95
    :cond_8
    move-wide v0, v4

    .line 96
    goto :goto_2

    .line 97
    :cond_9
    const/16 v7, -0x10

    .line 98
    .line 99
    const-wide/16 v8, 0x2

    .line 100
    .line 101
    if-ge p2, v7, :cond_d

    .line 102
    .line 103
    const/4 v7, 0x2

    .line 104
    if-ge v4, v7, :cond_a

    .line 105
    .line 106
    invoke-static {v0, v1, p1, p2, v4}, Lcom/google/crypto/tink/shaded/protobuf/m1;->z(J[BII)I

    .line 107
    .line 108
    .line 109
    move-result p3

    .line 110
    goto :goto_5

    .line 111
    :cond_a
    add-int/lit8 p0, p0, -0x3

    .line 112
    .line 113
    add-long v10, v0, v2

    .line 114
    .line 115
    invoke-static {p1, v0, v1}, Lcom/google/crypto/tink/shaded/protobuf/l1;->f([BJ)B

    .line 116
    .line 117
    .line 118
    move-result v4

    .line 119
    if-gt v4, v6, :cond_f

    .line 120
    .line 121
    const/16 v7, -0x60

    .line 122
    .line 123
    if-ne p2, v5, :cond_b

    .line 124
    .line 125
    if-lt v4, v7, :cond_f

    .line 126
    .line 127
    :cond_b
    const/16 v5, -0x13

    .line 128
    .line 129
    if-ne p2, v5, :cond_c

    .line 130
    .line 131
    if-ge v4, v7, :cond_f

    .line 132
    .line 133
    :cond_c
    add-long/2addr v0, v8

    .line 134
    invoke-static {p1, v10, v11}, Lcom/google/crypto/tink/shaded/protobuf/l1;->f([BJ)B

    .line 135
    .line 136
    .line 137
    move-result p2

    .line 138
    if-le p2, v6, :cond_3

    .line 139
    .line 140
    goto :goto_4

    .line 141
    :cond_d
    const/4 v5, 0x3

    .line 142
    if-ge v4, v5, :cond_e

    .line 143
    .line 144
    invoke-static {v0, v1, p1, p2, v4}, Lcom/google/crypto/tink/shaded/protobuf/m1;->z(J[BII)I

    .line 145
    .line 146
    .line 147
    move-result p3

    .line 148
    goto :goto_5

    .line 149
    :cond_e
    add-int/lit8 p0, p0, -0x4

    .line 150
    .line 151
    add-long v4, v0, v2

    .line 152
    .line 153
    invoke-static {p1, v0, v1}, Lcom/google/crypto/tink/shaded/protobuf/l1;->f([BJ)B

    .line 154
    .line 155
    .line 156
    move-result v7

    .line 157
    if-gt v7, v6, :cond_f

    .line 158
    .line 159
    shl-int/lit8 p2, p2, 0x1c

    .line 160
    .line 161
    add-int/lit8 v7, v7, 0x70

    .line 162
    .line 163
    add-int/2addr v7, p2

    .line 164
    shr-int/lit8 p2, v7, 0x1e

    .line 165
    .line 166
    if-nez p2, :cond_f

    .line 167
    .line 168
    add-long/2addr v8, v0

    .line 169
    invoke-static {p1, v4, v5}, Lcom/google/crypto/tink/shaded/protobuf/l1;->f([BJ)B

    .line 170
    .line 171
    .line 172
    move-result p2

    .line 173
    if-gt p2, v6, :cond_f

    .line 174
    .line 175
    const-wide/16 v4, 0x3

    .line 176
    .line 177
    add-long/2addr v0, v4

    .line 178
    invoke-static {p1, v8, v9}, Lcom/google/crypto/tink/shaded/protobuf/l1;->f([BJ)B

    .line 179
    .line 180
    .line 181
    move-result p2

    .line 182
    if-le p2, v6, :cond_3

    .line 183
    .line 184
    :cond_f
    :goto_4
    const/4 p3, -0x1

    .line 185
    :goto_5
    return p3

    .line 186
    :cond_10
    new-instance p0, Ljava/lang/ArrayIndexOutOfBoundsException;

    .line 187
    .line 188
    array-length p1, p1

    .line 189
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 190
    .line 191
    .line 192
    move-result-object p1

    .line 193
    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 194
    .line 195
    .line 196
    move-result-object p2

    .line 197
    invoke-static {p3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 198
    .line 199
    .line 200
    move-result-object p3

    .line 201
    filled-new-array {p1, p2, p3}, [Ljava/lang/Object;

    .line 202
    .line 203
    .line 204
    move-result-object p1

    .line 205
    const-string p2, "Array length=%d, index=%d, limit=%d"

    .line 206
    .line 207
    invoke-static {p2, p1}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 208
    .line 209
    .line 210
    move-result-object p1

    .line 211
    invoke-direct {p0, p1}, Ljava/lang/ArrayIndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    .line 212
    .line 213
    .line 214
    throw p0

    .line 215
    :goto_6
    :pswitch_0
    if-ge p2, p3, :cond_11

    .line 216
    .line 217
    aget-byte p0, p1, p2

    .line 218
    .line 219
    if-ltz p0, :cond_11

    .line 220
    .line 221
    add-int/lit8 p2, p2, 0x1

    .line 222
    .line 223
    goto :goto_6

    .line 224
    :cond_11
    if-lt p2, p3, :cond_12

    .line 225
    .line 226
    goto :goto_8

    .line 227
    :cond_12
    :goto_7
    if-lt p2, p3, :cond_13

    .line 228
    .line 229
    :goto_8
    const/4 p0, 0x0

    .line 230
    goto/16 :goto_a

    .line 231
    .line 232
    :cond_13
    add-int/lit8 p0, p2, 0x1

    .line 233
    .line 234
    aget-byte v0, p1, p2

    .line 235
    .line 236
    if-gez v0, :cond_1c

    .line 237
    .line 238
    const/16 v1, -0x20

    .line 239
    .line 240
    const/16 v2, -0x41

    .line 241
    .line 242
    if-ge v0, v1, :cond_15

    .line 243
    .line 244
    if-lt p0, p3, :cond_14

    .line 245
    .line 246
    move p0, v0

    .line 247
    goto :goto_a

    .line 248
    :cond_14
    const/16 v1, -0x3e

    .line 249
    .line 250
    if-lt v0, v1, :cond_1b

    .line 251
    .line 252
    add-int/lit8 p2, p2, 0x2

    .line 253
    .line 254
    aget-byte p0, p1, p0

    .line 255
    .line 256
    if-le p0, v2, :cond_12

    .line 257
    .line 258
    goto :goto_9

    .line 259
    :cond_15
    const/16 v3, -0x10

    .line 260
    .line 261
    if-ge v0, v3, :cond_19

    .line 262
    .line 263
    add-int/lit8 v3, p3, -0x1

    .line 264
    .line 265
    if-lt p0, v3, :cond_16

    .line 266
    .line 267
    invoke-static {p1, p0, p3}, Lcom/google/crypto/tink/shaded/protobuf/o1;->a([BII)I

    .line 268
    .line 269
    .line 270
    move-result p0

    .line 271
    goto :goto_a

    .line 272
    :cond_16
    add-int/lit8 v3, p2, 0x2

    .line 273
    .line 274
    aget-byte p0, p1, p0

    .line 275
    .line 276
    if-gt p0, v2, :cond_1b

    .line 277
    .line 278
    const/16 v4, -0x60

    .line 279
    .line 280
    if-ne v0, v1, :cond_17

    .line 281
    .line 282
    if-lt p0, v4, :cond_1b

    .line 283
    .line 284
    :cond_17
    const/16 v1, -0x13

    .line 285
    .line 286
    if-ne v0, v1, :cond_18

    .line 287
    .line 288
    if-ge p0, v4, :cond_1b

    .line 289
    .line 290
    :cond_18
    add-int/lit8 p2, p2, 0x3

    .line 291
    .line 292
    aget-byte p0, p1, v3

    .line 293
    .line 294
    if-le p0, v2, :cond_12

    .line 295
    .line 296
    goto :goto_9

    .line 297
    :cond_19
    add-int/lit8 v1, p3, -0x2

    .line 298
    .line 299
    if-lt p0, v1, :cond_1a

    .line 300
    .line 301
    invoke-static {p1, p0, p3}, Lcom/google/crypto/tink/shaded/protobuf/o1;->a([BII)I

    .line 302
    .line 303
    .line 304
    move-result p0

    .line 305
    goto :goto_a

    .line 306
    :cond_1a
    add-int/lit8 v1, p2, 0x2

    .line 307
    .line 308
    aget-byte p0, p1, p0

    .line 309
    .line 310
    if-gt p0, v2, :cond_1b

    .line 311
    .line 312
    shl-int/lit8 v0, v0, 0x1c

    .line 313
    .line 314
    add-int/lit8 p0, p0, 0x70

    .line 315
    .line 316
    add-int/2addr p0, v0

    .line 317
    shr-int/lit8 p0, p0, 0x1e

    .line 318
    .line 319
    if-nez p0, :cond_1b

    .line 320
    .line 321
    add-int/lit8 p0, p2, 0x3

    .line 322
    .line 323
    aget-byte v0, p1, v1

    .line 324
    .line 325
    if-gt v0, v2, :cond_1b

    .line 326
    .line 327
    add-int/lit8 p2, p2, 0x4

    .line 328
    .line 329
    aget-byte p0, p1, p0

    .line 330
    .line 331
    if-le p0, v2, :cond_12

    .line 332
    .line 333
    :cond_1b
    :goto_9
    const/4 p0, -0x1

    .line 334
    :goto_a
    return p0

    .line 335
    :cond_1c
    move p2, p0

    .line 336
    goto :goto_7

    .line 337
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
