.class public abstract Ljp/fe;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a([BII)Ljava/lang/String;
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move/from16 v1, p1

    .line 4
    .line 5
    move/from16 v2, p2

    .line 6
    .line 7
    if-ltz v1, :cond_19

    .line 8
    .line 9
    array-length v3, v0

    .line 10
    if-gt v2, v3, :cond_19

    .line 11
    .line 12
    if-gt v1, v2, :cond_19

    .line 13
    .line 14
    sub-int v3, v2, v1

    .line 15
    .line 16
    new-array v3, v3, [C

    .line 17
    .line 18
    const/4 v4, 0x0

    .line 19
    move v5, v4

    .line 20
    :goto_0
    if-ge v1, v2, :cond_18

    .line 21
    .line 22
    aget-byte v6, v0, v1

    .line 23
    .line 24
    if-ltz v6, :cond_1

    .line 25
    .line 26
    int-to-char v6, v6

    .line 27
    add-int/lit8 v7, v5, 0x1

    .line 28
    .line 29
    aput-char v6, v3, v5

    .line 30
    .line 31
    add-int/lit8 v1, v1, 0x1

    .line 32
    .line 33
    :goto_1
    if-ge v1, v2, :cond_0

    .line 34
    .line 35
    aget-byte v5, v0, v1

    .line 36
    .line 37
    if-ltz v5, :cond_0

    .line 38
    .line 39
    add-int/lit8 v1, v1, 0x1

    .line 40
    .line 41
    int-to-char v5, v5

    .line 42
    add-int/lit8 v6, v7, 0x1

    .line 43
    .line 44
    aput-char v5, v3, v7

    .line 45
    .line 46
    move v7, v6

    .line 47
    goto :goto_1

    .line 48
    :cond_0
    :goto_2
    move v5, v7

    .line 49
    goto :goto_0

    .line 50
    :cond_1
    shr-int/lit8 v7, v6, 0x5

    .line 51
    .line 52
    const/4 v8, -0x2

    .line 53
    const/16 v10, 0x80

    .line 54
    .line 55
    const v11, 0xfffd

    .line 56
    .line 57
    .line 58
    const/4 v12, 0x1

    .line 59
    if-ne v7, v8, :cond_6

    .line 60
    .line 61
    add-int/lit8 v7, v1, 0x1

    .line 62
    .line 63
    if-gt v2, v7, :cond_3

    .line 64
    .line 65
    int-to-char v6, v11

    .line 66
    add-int/lit8 v7, v5, 0x1

    .line 67
    .line 68
    aput-char v6, v3, v5

    .line 69
    .line 70
    :cond_2
    :goto_3
    move v9, v12

    .line 71
    goto :goto_5

    .line 72
    :cond_3
    aget-byte v7, v0, v7

    .line 73
    .line 74
    and-int/lit16 v8, v7, 0xc0

    .line 75
    .line 76
    if-ne v8, v10, :cond_5

    .line 77
    .line 78
    xor-int/lit16 v7, v7, 0xf80

    .line 79
    .line 80
    shl-int/lit8 v6, v6, 0x6

    .line 81
    .line 82
    xor-int/2addr v6, v7

    .line 83
    if-ge v6, v10, :cond_4

    .line 84
    .line 85
    int-to-char v6, v11

    .line 86
    add-int/lit8 v7, v5, 0x1

    .line 87
    .line 88
    aput-char v6, v3, v5

    .line 89
    .line 90
    goto :goto_4

    .line 91
    :cond_4
    int-to-char v6, v6

    .line 92
    add-int/lit8 v7, v5, 0x1

    .line 93
    .line 94
    aput-char v6, v3, v5

    .line 95
    .line 96
    :goto_4
    const/4 v9, 0x2

    .line 97
    goto :goto_5

    .line 98
    :cond_5
    int-to-char v6, v11

    .line 99
    add-int/lit8 v7, v5, 0x1

    .line 100
    .line 101
    aput-char v6, v3, v5

    .line 102
    .line 103
    goto :goto_3

    .line 104
    :goto_5
    add-int/2addr v1, v9

    .line 105
    goto :goto_2

    .line 106
    :cond_6
    shr-int/lit8 v7, v6, 0x4

    .line 107
    .line 108
    const v13, 0xe000

    .line 109
    .line 110
    .line 111
    const v14, 0xd800

    .line 112
    .line 113
    .line 114
    const/4 v15, 0x3

    .line 115
    if-ne v7, v8, :cond_c

    .line 116
    .line 117
    add-int/lit8 v7, v1, 0x2

    .line 118
    .line 119
    if-gt v2, v7, :cond_7

    .line 120
    .line 121
    int-to-char v6, v11

    .line 122
    add-int/lit8 v7, v5, 0x1

    .line 123
    .line 124
    aput-char v6, v3, v5

    .line 125
    .line 126
    add-int/lit8 v5, v1, 0x1

    .line 127
    .line 128
    if-le v2, v5, :cond_2

    .line 129
    .line 130
    aget-byte v5, v0, v5

    .line 131
    .line 132
    and-int/lit16 v5, v5, 0xc0

    .line 133
    .line 134
    if-ne v5, v10, :cond_2

    .line 135
    .line 136
    :goto_6
    goto :goto_4

    .line 137
    :cond_7
    add-int/lit8 v8, v1, 0x1

    .line 138
    .line 139
    aget-byte v8, v0, v8

    .line 140
    .line 141
    and-int/lit16 v9, v8, 0xc0

    .line 142
    .line 143
    if-ne v9, v10, :cond_b

    .line 144
    .line 145
    aget-byte v7, v0, v7

    .line 146
    .line 147
    and-int/lit16 v9, v7, 0xc0

    .line 148
    .line 149
    if-ne v9, v10, :cond_a

    .line 150
    .line 151
    const v9, -0x1e080

    .line 152
    .line 153
    .line 154
    xor-int/2addr v7, v9

    .line 155
    shl-int/lit8 v8, v8, 0x6

    .line 156
    .line 157
    xor-int/2addr v7, v8

    .line 158
    shl-int/lit8 v6, v6, 0xc

    .line 159
    .line 160
    xor-int/2addr v6, v7

    .line 161
    const/16 v7, 0x800

    .line 162
    .line 163
    if-ge v6, v7, :cond_8

    .line 164
    .line 165
    int-to-char v6, v11

    .line 166
    add-int/lit8 v7, v5, 0x1

    .line 167
    .line 168
    aput-char v6, v3, v5

    .line 169
    .line 170
    goto :goto_7

    .line 171
    :cond_8
    if-gt v14, v6, :cond_9

    .line 172
    .line 173
    if-ge v6, v13, :cond_9

    .line 174
    .line 175
    int-to-char v6, v11

    .line 176
    add-int/lit8 v7, v5, 0x1

    .line 177
    .line 178
    aput-char v6, v3, v5

    .line 179
    .line 180
    goto :goto_7

    .line 181
    :cond_9
    int-to-char v6, v6

    .line 182
    add-int/lit8 v7, v5, 0x1

    .line 183
    .line 184
    aput-char v6, v3, v5

    .line 185
    .line 186
    :goto_7
    move v9, v15

    .line 187
    goto :goto_5

    .line 188
    :cond_a
    int-to-char v6, v11

    .line 189
    add-int/lit8 v7, v5, 0x1

    .line 190
    .line 191
    aput-char v6, v3, v5

    .line 192
    .line 193
    goto :goto_6

    .line 194
    :cond_b
    int-to-char v6, v11

    .line 195
    add-int/lit8 v7, v5, 0x1

    .line 196
    .line 197
    aput-char v6, v3, v5

    .line 198
    .line 199
    goto/16 :goto_3

    .line 200
    .line 201
    :cond_c
    shr-int/lit8 v7, v6, 0x3

    .line 202
    .line 203
    if-ne v7, v8, :cond_17

    .line 204
    .line 205
    add-int/lit8 v7, v1, 0x3

    .line 206
    .line 207
    if-gt v2, v7, :cond_f

    .line 208
    .line 209
    add-int/lit8 v6, v5, 0x1

    .line 210
    .line 211
    aput-char v11, v3, v5

    .line 212
    .line 213
    add-int/lit8 v5, v1, 0x1

    .line 214
    .line 215
    if-le v2, v5, :cond_e

    .line 216
    .line 217
    aget-byte v5, v0, v5

    .line 218
    .line 219
    and-int/lit16 v5, v5, 0xc0

    .line 220
    .line 221
    if-ne v5, v10, :cond_e

    .line 222
    .line 223
    add-int/lit8 v5, v1, 0x2

    .line 224
    .line 225
    if-le v2, v5, :cond_d

    .line 226
    .line 227
    aget-byte v5, v0, v5

    .line 228
    .line 229
    and-int/lit16 v5, v5, 0xc0

    .line 230
    .line 231
    if-ne v5, v10, :cond_d

    .line 232
    .line 233
    :goto_8
    move v9, v15

    .line 234
    goto/16 :goto_d

    .line 235
    .line 236
    :cond_d
    :goto_9
    const/4 v9, 0x2

    .line 237
    goto/16 :goto_d

    .line 238
    .line 239
    :cond_e
    :goto_a
    move v9, v12

    .line 240
    goto/16 :goto_d

    .line 241
    .line 242
    :cond_f
    add-int/lit8 v8, v1, 0x1

    .line 243
    .line 244
    aget-byte v8, v0, v8

    .line 245
    .line 246
    and-int/lit16 v9, v8, 0xc0

    .line 247
    .line 248
    if-ne v9, v10, :cond_16

    .line 249
    .line 250
    add-int/lit8 v9, v1, 0x2

    .line 251
    .line 252
    aget-byte v9, v0, v9

    .line 253
    .line 254
    and-int/lit16 v12, v9, 0xc0

    .line 255
    .line 256
    if-ne v12, v10, :cond_15

    .line 257
    .line 258
    aget-byte v7, v0, v7

    .line 259
    .line 260
    and-int/lit16 v12, v7, 0xc0

    .line 261
    .line 262
    if-ne v12, v10, :cond_14

    .line 263
    .line 264
    const v10, 0x381f80

    .line 265
    .line 266
    .line 267
    xor-int/2addr v7, v10

    .line 268
    shl-int/lit8 v9, v9, 0x6

    .line 269
    .line 270
    xor-int/2addr v7, v9

    .line 271
    shl-int/lit8 v8, v8, 0xc

    .line 272
    .line 273
    xor-int/2addr v7, v8

    .line 274
    shl-int/lit8 v6, v6, 0x12

    .line 275
    .line 276
    xor-int/2addr v6, v7

    .line 277
    const v7, 0x10ffff

    .line 278
    .line 279
    .line 280
    if-le v6, v7, :cond_10

    .line 281
    .line 282
    add-int/lit8 v6, v5, 0x1

    .line 283
    .line 284
    aput-char v11, v3, v5

    .line 285
    .line 286
    goto :goto_c

    .line 287
    :cond_10
    if-gt v14, v6, :cond_11

    .line 288
    .line 289
    if-ge v6, v13, :cond_11

    .line 290
    .line 291
    add-int/lit8 v6, v5, 0x1

    .line 292
    .line 293
    aput-char v11, v3, v5

    .line 294
    .line 295
    goto :goto_c

    .line 296
    :cond_11
    const/high16 v7, 0x10000

    .line 297
    .line 298
    if-ge v6, v7, :cond_12

    .line 299
    .line 300
    add-int/lit8 v6, v5, 0x1

    .line 301
    .line 302
    aput-char v11, v3, v5

    .line 303
    .line 304
    goto :goto_c

    .line 305
    :cond_12
    if-eq v6, v11, :cond_13

    .line 306
    .line 307
    ushr-int/lit8 v7, v6, 0xa

    .line 308
    .line 309
    const v8, 0xd7c0

    .line 310
    .line 311
    .line 312
    add-int/2addr v7, v8

    .line 313
    int-to-char v7, v7

    .line 314
    add-int/lit8 v8, v5, 0x1

    .line 315
    .line 316
    aput-char v7, v3, v5

    .line 317
    .line 318
    and-int/lit16 v6, v6, 0x3ff

    .line 319
    .line 320
    const v7, 0xdc00

    .line 321
    .line 322
    .line 323
    add-int/2addr v6, v7

    .line 324
    int-to-char v6, v6

    .line 325
    add-int/lit8 v5, v5, 0x2

    .line 326
    .line 327
    aput-char v6, v3, v8

    .line 328
    .line 329
    goto :goto_b

    .line 330
    :cond_13
    add-int/lit8 v6, v5, 0x1

    .line 331
    .line 332
    aput-char v11, v3, v5

    .line 333
    .line 334
    move v5, v6

    .line 335
    :goto_b
    move v6, v5

    .line 336
    :goto_c
    const/4 v9, 0x4

    .line 337
    goto :goto_d

    .line 338
    :cond_14
    add-int/lit8 v6, v5, 0x1

    .line 339
    .line 340
    aput-char v11, v3, v5

    .line 341
    .line 342
    goto :goto_8

    .line 343
    :cond_15
    add-int/lit8 v6, v5, 0x1

    .line 344
    .line 345
    aput-char v11, v3, v5

    .line 346
    .line 347
    goto :goto_9

    .line 348
    :cond_16
    add-int/lit8 v6, v5, 0x1

    .line 349
    .line 350
    aput-char v11, v3, v5

    .line 351
    .line 352
    goto :goto_a

    .line 353
    :goto_d
    add-int/2addr v1, v9

    .line 354
    :goto_e
    move v5, v6

    .line 355
    goto/16 :goto_0

    .line 356
    .line 357
    :cond_17
    add-int/lit8 v6, v5, 0x1

    .line 358
    .line 359
    aput-char v11, v3, v5

    .line 360
    .line 361
    add-int/lit8 v1, v1, 0x1

    .line 362
    .line 363
    goto :goto_e

    .line 364
    :cond_18
    invoke-static {v3, v4, v5}, Lly0/w;->k([CII)Ljava/lang/String;

    .line 365
    .line 366
    .line 367
    move-result-object v0

    .line 368
    return-object v0

    .line 369
    :cond_19
    new-instance v3, Ljava/lang/IndexOutOfBoundsException;

    .line 370
    .line 371
    new-instance v4, Ljava/lang/StringBuilder;

    .line 372
    .line 373
    const-string v5, "size="

    .line 374
    .line 375
    invoke-direct {v4, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 376
    .line 377
    .line 378
    array-length v0, v0

    .line 379
    const-string v5, " beginIndex="

    .line 380
    .line 381
    const-string v6, " endIndex="

    .line 382
    .line 383
    invoke-static {v4, v0, v5, v1, v6}, La7/g0;->u(Ljava/lang/StringBuilder;ILjava/lang/String;ILjava/lang/String;)V

    .line 384
    .line 385
    .line 386
    invoke-virtual {v4, v2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 387
    .line 388
    .line 389
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 390
    .line 391
    .line 392
    move-result-object v0

    .line 393
    invoke-direct {v3, v0}, Ljava/lang/IndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    .line 394
    .line 395
    .line 396
    throw v3
.end method

.method public static b(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;)Ljava/lang/String;
    .locals 5

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->i()I

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 8
    .line 9
    .line 10
    const/4 v1, 0x0

    .line 11
    :goto_0
    invoke-virtual {p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->i()I

    .line 12
    .line 13
    .line 14
    move-result v2

    .line 15
    if-ge v1, v2, :cond_4

    .line 16
    .line 17
    invoke-virtual {p0, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->c(I)B

    .line 18
    .line 19
    .line 20
    move-result v2

    .line 21
    const/16 v3, 0x22

    .line 22
    .line 23
    if-eq v2, v3, :cond_3

    .line 24
    .line 25
    const/16 v3, 0x27

    .line 26
    .line 27
    if-eq v2, v3, :cond_2

    .line 28
    .line 29
    const/16 v3, 0x5c

    .line 30
    .line 31
    if-eq v2, v3, :cond_1

    .line 32
    .line 33
    packed-switch v2, :pswitch_data_0

    .line 34
    .line 35
    .line 36
    const/16 v4, 0x20

    .line 37
    .line 38
    if-lt v2, v4, :cond_0

    .line 39
    .line 40
    const/16 v4, 0x7e

    .line 41
    .line 42
    if-gt v2, v4, :cond_0

    .line 43
    .line 44
    int-to-char v2, v2

    .line 45
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    goto :goto_1

    .line 49
    :cond_0
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 50
    .line 51
    .line 52
    ushr-int/lit8 v3, v2, 0x6

    .line 53
    .line 54
    and-int/lit8 v3, v3, 0x3

    .line 55
    .line 56
    add-int/lit8 v3, v3, 0x30

    .line 57
    .line 58
    int-to-char v3, v3

    .line 59
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 60
    .line 61
    .line 62
    ushr-int/lit8 v3, v2, 0x3

    .line 63
    .line 64
    and-int/lit8 v3, v3, 0x7

    .line 65
    .line 66
    add-int/lit8 v3, v3, 0x30

    .line 67
    .line 68
    int-to-char v3, v3

    .line 69
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 70
    .line 71
    .line 72
    and-int/lit8 v2, v2, 0x7

    .line 73
    .line 74
    add-int/lit8 v2, v2, 0x30

    .line 75
    .line 76
    int-to-char v2, v2

    .line 77
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 78
    .line 79
    .line 80
    goto :goto_1

    .line 81
    :pswitch_0
    const-string v2, "\\r"

    .line 82
    .line 83
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 84
    .line 85
    .line 86
    goto :goto_1

    .line 87
    :pswitch_1
    const-string v2, "\\f"

    .line 88
    .line 89
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 90
    .line 91
    .line 92
    goto :goto_1

    .line 93
    :pswitch_2
    const-string v2, "\\v"

    .line 94
    .line 95
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 96
    .line 97
    .line 98
    goto :goto_1

    .line 99
    :pswitch_3
    const-string v2, "\\n"

    .line 100
    .line 101
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 102
    .line 103
    .line 104
    goto :goto_1

    .line 105
    :pswitch_4
    const-string v2, "\\t"

    .line 106
    .line 107
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 108
    .line 109
    .line 110
    goto :goto_1

    .line 111
    :pswitch_5
    const-string v2, "\\b"

    .line 112
    .line 113
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 114
    .line 115
    .line 116
    goto :goto_1

    .line 117
    :pswitch_6
    const-string v2, "\\a"

    .line 118
    .line 119
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 120
    .line 121
    .line 122
    goto :goto_1

    .line 123
    :cond_1
    const-string v2, "\\\\"

    .line 124
    .line 125
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 126
    .line 127
    .line 128
    goto :goto_1

    .line 129
    :cond_2
    const-string v2, "\\\'"

    .line 130
    .line 131
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 132
    .line 133
    .line 134
    goto :goto_1

    .line 135
    :cond_3
    const-string v2, "\\\""

    .line 136
    .line 137
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 138
    .line 139
    .line 140
    :goto_1
    add-int/lit8 v1, v1, 0x1

    .line 141
    .line 142
    goto/16 :goto_0

    .line 143
    .line 144
    :cond_4
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 145
    .line 146
    .line 147
    move-result-object p0

    .line 148
    return-object p0

    .line 149
    :pswitch_data_0
    .packed-switch 0x7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
