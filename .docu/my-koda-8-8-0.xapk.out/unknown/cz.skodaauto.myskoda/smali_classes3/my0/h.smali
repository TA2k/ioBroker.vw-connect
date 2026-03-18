.class public abstract Lmy0/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:[I

.field public static final b:[I

.field public static final c:[I

.field public static final d:[I


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    const/16 v0, 0xa

    .line 2
    .line 3
    new-array v1, v0, [I

    .line 4
    .line 5
    fill-array-data v1, :array_0

    .line 6
    .line 7
    .line 8
    sput-object v1, Lmy0/h;->a:[I

    .line 9
    .line 10
    new-array v0, v0, [I

    .line 11
    .line 12
    fill-array-data v0, :array_1

    .line 13
    .line 14
    .line 15
    sput-object v0, Lmy0/h;->b:[I

    .line 16
    .line 17
    const/4 v0, 0x3

    .line 18
    const/4 v1, 0x6

    .line 19
    filled-new-array {v0, v1}, [I

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    sput-object v0, Lmy0/h;->c:[I

    .line 24
    .line 25
    new-array v0, v1, [I

    .line 26
    .line 27
    fill-array-data v0, :array_2

    .line 28
    .line 29
    .line 30
    sput-object v0, Lmy0/h;->d:[I

    .line 31
    .line 32
    return-void

    .line 33
    :array_0
    .array-data 4
        0x1
        0xa
        0x64
        0x3e8
        0x2710
        0x186a0
        0xf4240
        0x989680
        0x5f5e100
        0x3b9aca00
    .end array-data

    .line 34
    .line 35
    .line 36
    .line 37
    .line 38
    .line 39
    .line 40
    .line 41
    .line 42
    .line 43
    .line 44
    .line 45
    .line 46
    .line 47
    .line 48
    .line 49
    .line 50
    .line 51
    .line 52
    .line 53
    .line 54
    .line 55
    .line 56
    .line 57
    :array_1
    .array-data 4
        0x1
        0x2
        0x4
        0x5
        0x7
        0x8
        0xa
        0xb
        0xd
        0xe
    .end array-data

    .line 58
    .line 59
    .line 60
    .line 61
    .line 62
    .line 63
    .line 64
    .line 65
    .line 66
    .line 67
    .line 68
    .line 69
    .line 70
    .line 71
    .line 72
    .line 73
    .line 74
    .line 75
    .line 76
    .line 77
    .line 78
    .line 79
    .line 80
    .line 81
    :array_2
    .array-data 4
        0x1
        0x2
        0x4
        0x5
        0x7
        0x8
    .end array-data
.end method

.method public static final a(Ljava/lang/String;Z)J
    .locals 20

    .line 1
    move-object/from16 v3, p0

    .line 2
    .line 3
    invoke-virtual {v3}, Ljava/lang/String;->length()I

    .line 4
    .line 5
    .line 6
    move-result v6

    .line 7
    if-eqz v6, :cond_2b

    .line 8
    .line 9
    sget v0, Lmy0/c;->g:I

    .line 10
    .line 11
    const/4 v7, 0x0

    .line 12
    invoke-virtual {v3, v7}, Ljava/lang/String;->charAt(I)C

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    const/16 v1, 0x2b

    .line 17
    .line 18
    const/16 v2, 0x2d

    .line 19
    .line 20
    const/4 v8, 0x1

    .line 21
    if-eq v0, v1, :cond_0

    .line 22
    .line 23
    if-eq v0, v2, :cond_0

    .line 24
    .line 25
    move v0, v7

    .line 26
    goto :goto_0

    .line 27
    :cond_0
    move v0, v8

    .line 28
    :goto_0
    if-lez v0, :cond_1

    .line 29
    .line 30
    move v9, v8

    .line 31
    goto :goto_1

    .line 32
    :cond_1
    move v9, v7

    .line 33
    :goto_1
    if-eqz v9, :cond_2

    .line 34
    .line 35
    invoke-static {v3, v2}, Lly0/p;->b0(Ljava/lang/String;C)Z

    .line 36
    .line 37
    .line 38
    move-result v1

    .line 39
    if-eqz v1, :cond_2

    .line 40
    .line 41
    move v10, v8

    .line 42
    goto :goto_2

    .line 43
    :cond_2
    move v10, v7

    .line 44
    :goto_2
    const-string v11, "No components"

    .line 45
    .line 46
    if-le v6, v0, :cond_2a

    .line 47
    .line 48
    invoke-virtual {v3, v0}, Ljava/lang/String;->charAt(I)C

    .line 49
    .line 50
    .line 51
    move-result v1

    .line 52
    const/16 v2, 0x50

    .line 53
    .line 54
    const/4 v12, 0x6

    .line 55
    const/16 v13, 0x2e

    .line 56
    .line 57
    const-string v14, "Unexpected order of duration components"

    .line 58
    .line 59
    const/16 v15, 0x3a

    .line 60
    .line 61
    const/16 v4, 0x30

    .line 62
    .line 63
    const/16 v16, 0x0

    .line 64
    .line 65
    const-string v5, "substring(...)"

    .line 66
    .line 67
    const-wide/16 v17, 0x0

    .line 68
    .line 69
    if-ne v1, v2, :cond_12

    .line 70
    .line 71
    add-int/2addr v0, v8

    .line 72
    if-eq v0, v6, :cond_11

    .line 73
    .line 74
    move v2, v7

    .line 75
    move-object/from16 v1, v16

    .line 76
    .line 77
    move-wide/from16 v8, v17

    .line 78
    .line 79
    :goto_3
    if-ge v0, v6, :cond_27

    .line 80
    .line 81
    invoke-virtual {v3, v0}, Ljava/lang/String;->charAt(I)C

    .line 82
    .line 83
    .line 84
    move-result v11

    .line 85
    const/16 v7, 0x54

    .line 86
    .line 87
    if-ne v11, v7, :cond_4

    .line 88
    .line 89
    if-nez v2, :cond_3

    .line 90
    .line 91
    add-int/lit8 v0, v0, 0x1

    .line 92
    .line 93
    if-eq v0, v6, :cond_3

    .line 94
    .line 95
    const/4 v2, 0x1

    .line 96
    const/4 v7, 0x0

    .line 97
    goto :goto_3

    .line 98
    :cond_3
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 99
    .line 100
    invoke-direct {v0}, Ljava/lang/IllegalArgumentException;-><init>()V

    .line 101
    .line 102
    .line 103
    throw v0

    .line 104
    :cond_4
    move v7, v0

    .line 105
    :goto_4
    invoke-virtual {v3}, Ljava/lang/String;->length()I

    .line 106
    .line 107
    .line 108
    move-result v11

    .line 109
    if-ge v7, v11, :cond_6

    .line 110
    .line 111
    invoke-virtual {v3, v7}, Ljava/lang/String;->charAt(I)C

    .line 112
    .line 113
    .line 114
    move-result v11

    .line 115
    if-gt v4, v11, :cond_5

    .line 116
    .line 117
    if-ge v11, v15, :cond_5

    .line 118
    .line 119
    goto :goto_5

    .line 120
    :cond_5
    const-string v4, "+-."

    .line 121
    .line 122
    invoke-static {v4, v11}, Lly0/p;->B(Ljava/lang/CharSequence;C)Z

    .line 123
    .line 124
    .line 125
    move-result v4

    .line 126
    if-eqz v4, :cond_6

    .line 127
    .line 128
    :goto_5
    add-int/lit8 v7, v7, 0x1

    .line 129
    .line 130
    const/16 v4, 0x30

    .line 131
    .line 132
    goto :goto_4

    .line 133
    :cond_6
    invoke-virtual {v3, v0, v7}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 134
    .line 135
    .line 136
    move-result-object v4

    .line 137
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 138
    .line 139
    .line 140
    invoke-virtual {v4}, Ljava/lang/String;->length()I

    .line 141
    .line 142
    .line 143
    move-result v7

    .line 144
    if-eqz v7, :cond_10

    .line 145
    .line 146
    invoke-virtual {v4}, Ljava/lang/String;->length()I

    .line 147
    .line 148
    .line 149
    move-result v7

    .line 150
    add-int/2addr v7, v0

    .line 151
    if-ltz v7, :cond_f

    .line 152
    .line 153
    invoke-virtual {v3}, Ljava/lang/String;->length()I

    .line 154
    .line 155
    .line 156
    move-result v0

    .line 157
    if-ge v7, v0, :cond_f

    .line 158
    .line 159
    invoke-virtual {v3, v7}, Ljava/lang/String;->charAt(I)C

    .line 160
    .line 161
    .line 162
    move-result v0

    .line 163
    add-int/lit8 v7, v7, 0x1

    .line 164
    .line 165
    if-nez v2, :cond_8

    .line 166
    .line 167
    const/16 v11, 0x44

    .line 168
    .line 169
    if-ne v0, v11, :cond_7

    .line 170
    .line 171
    sget-object v0, Lmy0/e;->k:Lmy0/e;

    .line 172
    .line 173
    goto :goto_6

    .line 174
    :cond_7
    new-instance v1, Ljava/lang/IllegalArgumentException;

    .line 175
    .line 176
    new-instance v2, Ljava/lang/StringBuilder;

    .line 177
    .line 178
    const-string v3, "Invalid or unsupported duration ISO non-time unit: "

    .line 179
    .line 180
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 181
    .line 182
    .line 183
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 184
    .line 185
    .line 186
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 187
    .line 188
    .line 189
    move-result-object v0

    .line 190
    invoke-direct {v1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 191
    .line 192
    .line 193
    throw v1

    .line 194
    :cond_8
    const/16 v11, 0x48

    .line 195
    .line 196
    if-eq v0, v11, :cond_b

    .line 197
    .line 198
    const/16 v11, 0x4d

    .line 199
    .line 200
    if-eq v0, v11, :cond_a

    .line 201
    .line 202
    const/16 v11, 0x53

    .line 203
    .line 204
    if-ne v0, v11, :cond_9

    .line 205
    .line 206
    sget-object v0, Lmy0/e;->h:Lmy0/e;

    .line 207
    .line 208
    goto :goto_6

    .line 209
    :cond_9
    new-instance v1, Ljava/lang/IllegalArgumentException;

    .line 210
    .line 211
    new-instance v2, Ljava/lang/StringBuilder;

    .line 212
    .line 213
    const-string v3, "Invalid duration ISO time unit: "

    .line 214
    .line 215
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 216
    .line 217
    .line 218
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 219
    .line 220
    .line 221
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 222
    .line 223
    .line 224
    move-result-object v0

    .line 225
    invoke-direct {v1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 226
    .line 227
    .line 228
    throw v1

    .line 229
    :cond_a
    sget-object v0, Lmy0/e;->i:Lmy0/e;

    .line 230
    .line 231
    goto :goto_6

    .line 232
    :cond_b
    sget-object v0, Lmy0/e;->j:Lmy0/e;

    .line 233
    .line 234
    :goto_6
    if-eqz v1, :cond_c

    .line 235
    .line 236
    invoke-virtual {v1, v0}, Ljava/lang/Enum;->compareTo(Ljava/lang/Enum;)I

    .line 237
    .line 238
    .line 239
    move-result v1

    .line 240
    if-lez v1, :cond_d

    .line 241
    .line 242
    :cond_c
    const/4 v1, 0x0

    .line 243
    goto :goto_7

    .line 244
    :cond_d
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 245
    .line 246
    invoke-direct {v0, v14}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 247
    .line 248
    .line 249
    throw v0

    .line 250
    :goto_7
    invoke-static {v4, v13, v1, v12}, Lly0/p;->J(Ljava/lang/CharSequence;CII)I

    .line 251
    .line 252
    .line 253
    move-result v11

    .line 254
    sget-object v12, Lmy0/e;->h:Lmy0/e;

    .line 255
    .line 256
    if-ne v0, v12, :cond_e

    .line 257
    .line 258
    if-lez v11, :cond_e

    .line 259
    .line 260
    invoke-virtual {v4, v1, v11}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 261
    .line 262
    .line 263
    move-result-object v12

    .line 264
    invoke-static {v12, v5}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 265
    .line 266
    .line 267
    move-object/from16 v19, v14

    .line 268
    .line 269
    invoke-static {v12}, Lmy0/h;->p(Ljava/lang/String;)J

    .line 270
    .line 271
    .line 272
    move-result-wide v13

    .line 273
    invoke-static {v13, v14, v0}, Lmy0/h;->t(JLmy0/e;)J

    .line 274
    .line 275
    .line 276
    move-result-wide v12

    .line 277
    invoke-static {v8, v9, v12, v13}, Lmy0/c;->k(JJ)J

    .line 278
    .line 279
    .line 280
    move-result-wide v8

    .line 281
    invoke-virtual {v4, v11}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    .line 282
    .line 283
    .line 284
    move-result-object v1

    .line 285
    invoke-static {v1, v5}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 286
    .line 287
    .line 288
    invoke-static {v1}, Ljava/lang/Double;->parseDouble(Ljava/lang/String;)D

    .line 289
    .line 290
    .line 291
    move-result-wide v11

    .line 292
    invoke-static {v11, v12, v0}, Lmy0/h;->r(DLmy0/e;)J

    .line 293
    .line 294
    .line 295
    move-result-wide v11

    .line 296
    invoke-static {v8, v9, v11, v12}, Lmy0/c;->k(JJ)J

    .line 297
    .line 298
    .line 299
    move-result-wide v8

    .line 300
    :goto_8
    move-object v1, v0

    .line 301
    move v0, v7

    .line 302
    move-object/from16 v14, v19

    .line 303
    .line 304
    const/16 v4, 0x30

    .line 305
    .line 306
    const/4 v7, 0x0

    .line 307
    const/4 v12, 0x6

    .line 308
    const/16 v13, 0x2e

    .line 309
    .line 310
    goto/16 :goto_3

    .line 311
    .line 312
    :cond_e
    move-object/from16 v19, v14

    .line 313
    .line 314
    invoke-static {v4}, Lmy0/h;->p(Ljava/lang/String;)J

    .line 315
    .line 316
    .line 317
    move-result-wide v11

    .line 318
    invoke-static {v11, v12, v0}, Lmy0/h;->t(JLmy0/e;)J

    .line 319
    .line 320
    .line 321
    move-result-wide v11

    .line 322
    invoke-static {v8, v9, v11, v12}, Lmy0/c;->k(JJ)J

    .line 323
    .line 324
    .line 325
    move-result-wide v8

    .line 326
    goto :goto_8

    .line 327
    :cond_f
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 328
    .line 329
    const-string v1, "Missing unit for value "

    .line 330
    .line 331
    invoke-virtual {v1, v4}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 332
    .line 333
    .line 334
    move-result-object v1

    .line 335
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 336
    .line 337
    .line 338
    throw v0

    .line 339
    :cond_10
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 340
    .line 341
    invoke-direct {v0}, Ljava/lang/IllegalArgumentException;-><init>()V

    .line 342
    .line 343
    .line 344
    throw v0

    .line 345
    :cond_11
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 346
    .line 347
    invoke-direct {v0}, Ljava/lang/IllegalArgumentException;-><init>()V

    .line 348
    .line 349
    .line 350
    throw v0

    .line 351
    :cond_12
    move-object/from16 v19, v14

    .line 352
    .line 353
    if-nez p1, :cond_29

    .line 354
    .line 355
    sub-int v1, v6, v0

    .line 356
    .line 357
    const/16 v2, 0x8

    .line 358
    .line 359
    invoke-static {v1, v2}, Ljava/lang/Math;->max(II)I

    .line 360
    .line 361
    .line 362
    move-result v2

    .line 363
    move-object v1, v5

    .line 364
    const/4 v5, 0x1

    .line 365
    move-object v4, v1

    .line 366
    const/4 v1, 0x0

    .line 367
    move-object v7, v4

    .line 368
    const-string v4, "Infinity"

    .line 369
    .line 370
    move-object v8, v7

    .line 371
    const/16 v7, 0x30

    .line 372
    .line 373
    invoke-static/range {v0 .. v5}, Lly0/w;->r(IIILjava/lang/String;Ljava/lang/String;Z)Z

    .line 374
    .line 375
    .line 376
    move-result v1

    .line 377
    if-eqz v1, :cond_13

    .line 378
    .line 379
    sget-wide v8, Lmy0/c;->e:J

    .line 380
    .line 381
    goto/16 :goto_11

    .line 382
    .line 383
    :cond_13
    xor-int/lit8 v1, v9, 0x1

    .line 384
    .line 385
    if-eqz v9, :cond_15

    .line 386
    .line 387
    invoke-virtual {v3, v0}, Ljava/lang/String;->charAt(I)C

    .line 388
    .line 389
    .line 390
    move-result v2

    .line 391
    const/16 v4, 0x28

    .line 392
    .line 393
    if-ne v2, v4, :cond_15

    .line 394
    .line 395
    invoke-static {v3}, Lly0/p;->N(Ljava/lang/CharSequence;)C

    .line 396
    .line 397
    .line 398
    move-result v2

    .line 399
    const/16 v4, 0x29

    .line 400
    .line 401
    if-ne v2, v4, :cond_15

    .line 402
    .line 403
    add-int/lit8 v0, v0, 0x1

    .line 404
    .line 405
    add-int/lit8 v6, v6, -0x1

    .line 406
    .line 407
    if-eq v0, v6, :cond_14

    .line 408
    .line 409
    move-object/from16 v4, v16

    .line 410
    .line 411
    move-wide/from16 v11, v17

    .line 412
    .line 413
    const/4 v1, 0x0

    .line 414
    const/4 v2, 0x1

    .line 415
    goto :goto_9

    .line 416
    :cond_14
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 417
    .line 418
    invoke-direct {v0, v11}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 419
    .line 420
    .line 421
    throw v0

    .line 422
    :cond_15
    move v2, v1

    .line 423
    move-object/from16 v4, v16

    .line 424
    .line 425
    move-wide/from16 v11, v17

    .line 426
    .line 427
    const/4 v1, 0x0

    .line 428
    :goto_9
    if-ge v0, v6, :cond_26

    .line 429
    .line 430
    if-eqz v1, :cond_16

    .line 431
    .line 432
    if-eqz v2, :cond_16

    .line 433
    .line 434
    :goto_a
    invoke-virtual {v3}, Ljava/lang/String;->length()I

    .line 435
    .line 436
    .line 437
    move-result v1

    .line 438
    if-ge v0, v1, :cond_16

    .line 439
    .line 440
    invoke-virtual {v3, v0}, Ljava/lang/String;->charAt(I)C

    .line 441
    .line 442
    .line 443
    move-result v1

    .line 444
    const/16 v5, 0x20

    .line 445
    .line 446
    if-ne v1, v5, :cond_16

    .line 447
    .line 448
    add-int/lit8 v0, v0, 0x1

    .line 449
    .line 450
    goto :goto_a

    .line 451
    :cond_16
    move v1, v0

    .line 452
    :goto_b
    invoke-virtual {v3}, Ljava/lang/String;->length()I

    .line 453
    .line 454
    .line 455
    move-result v5

    .line 456
    if-ge v1, v5, :cond_18

    .line 457
    .line 458
    invoke-virtual {v3, v1}, Ljava/lang/String;->charAt(I)C

    .line 459
    .line 460
    .line 461
    move-result v5

    .line 462
    if-gt v7, v5, :cond_17

    .line 463
    .line 464
    if-ge v5, v15, :cond_17

    .line 465
    .line 466
    goto :goto_c

    .line 467
    :cond_17
    const/16 v9, 0x2e

    .line 468
    .line 469
    if-ne v5, v9, :cond_18

    .line 470
    .line 471
    :goto_c
    add-int/lit8 v1, v1, 0x1

    .line 472
    .line 473
    goto :goto_b

    .line 474
    :cond_18
    invoke-virtual {v3, v0, v1}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 475
    .line 476
    .line 477
    move-result-object v1

    .line 478
    invoke-static {v1, v8}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 479
    .line 480
    .line 481
    invoke-virtual {v1}, Ljava/lang/String;->length()I

    .line 482
    .line 483
    .line 484
    move-result v5

    .line 485
    if-eqz v5, :cond_25

    .line 486
    .line 487
    invoke-virtual {v1}, Ljava/lang/String;->length()I

    .line 488
    .line 489
    .line 490
    move-result v5

    .line 491
    add-int/2addr v5, v0

    .line 492
    move v0, v5

    .line 493
    :goto_d
    invoke-virtual {v3}, Ljava/lang/String;->length()I

    .line 494
    .line 495
    .line 496
    move-result v9

    .line 497
    if-ge v0, v9, :cond_19

    .line 498
    .line 499
    invoke-virtual {v3, v0}, Ljava/lang/String;->charAt(I)C

    .line 500
    .line 501
    .line 502
    move-result v9

    .line 503
    const/16 v13, 0x61

    .line 504
    .line 505
    if-gt v13, v9, :cond_19

    .line 506
    .line 507
    const/16 v13, 0x7b

    .line 508
    .line 509
    if-ge v9, v13, :cond_19

    .line 510
    .line 511
    add-int/lit8 v0, v0, 0x1

    .line 512
    .line 513
    goto :goto_d

    .line 514
    :cond_19
    invoke-virtual {v3, v5, v0}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 515
    .line 516
    .line 517
    move-result-object v0

    .line 518
    invoke-static {v0, v8}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 519
    .line 520
    .line 521
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 522
    .line 523
    .line 524
    move-result v9

    .line 525
    add-int/2addr v5, v9

    .line 526
    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

    .line 527
    .line 528
    .line 529
    move-result v9

    .line 530
    const/16 v13, 0x64

    .line 531
    .line 532
    if-eq v9, v13, :cond_1f

    .line 533
    .line 534
    const/16 v13, 0x68

    .line 535
    .line 536
    if-eq v9, v13, :cond_1e

    .line 537
    .line 538
    const/16 v13, 0x6d

    .line 539
    .line 540
    if-eq v9, v13, :cond_1d

    .line 541
    .line 542
    const/16 v13, 0x73

    .line 543
    .line 544
    if-eq v9, v13, :cond_1c

    .line 545
    .line 546
    const/16 v13, 0xda6

    .line 547
    .line 548
    if-eq v9, v13, :cond_1b

    .line 549
    .line 550
    const/16 v13, 0xdc5

    .line 551
    .line 552
    if-eq v9, v13, :cond_1a

    .line 553
    .line 554
    const/16 v13, 0xe9e

    .line 555
    .line 556
    if-ne v9, v13, :cond_24

    .line 557
    .line 558
    const-string v9, "us"

    .line 559
    .line 560
    invoke-virtual {v0, v9}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 561
    .line 562
    .line 563
    move-result v9

    .line 564
    if-eqz v9, :cond_24

    .line 565
    .line 566
    sget-object v0, Lmy0/e;->f:Lmy0/e;

    .line 567
    .line 568
    goto :goto_e

    .line 569
    :cond_1a
    const-string v9, "ns"

    .line 570
    .line 571
    invoke-virtual {v0, v9}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 572
    .line 573
    .line 574
    move-result v9

    .line 575
    if-eqz v9, :cond_24

    .line 576
    .line 577
    sget-object v0, Lmy0/e;->e:Lmy0/e;

    .line 578
    .line 579
    goto :goto_e

    .line 580
    :cond_1b
    const-string v9, "ms"

    .line 581
    .line 582
    invoke-virtual {v0, v9}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 583
    .line 584
    .line 585
    move-result v9

    .line 586
    if-eqz v9, :cond_24

    .line 587
    .line 588
    sget-object v0, Lmy0/e;->g:Lmy0/e;

    .line 589
    .line 590
    goto :goto_e

    .line 591
    :cond_1c
    const-string v9, "s"

    .line 592
    .line 593
    invoke-virtual {v0, v9}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 594
    .line 595
    .line 596
    move-result v9

    .line 597
    if-eqz v9, :cond_24

    .line 598
    .line 599
    sget-object v0, Lmy0/e;->h:Lmy0/e;

    .line 600
    .line 601
    goto :goto_e

    .line 602
    :cond_1d
    const-string v9, "m"

    .line 603
    .line 604
    invoke-virtual {v0, v9}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 605
    .line 606
    .line 607
    move-result v9

    .line 608
    if-eqz v9, :cond_24

    .line 609
    .line 610
    sget-object v0, Lmy0/e;->i:Lmy0/e;

    .line 611
    .line 612
    goto :goto_e

    .line 613
    :cond_1e
    const-string v9, "h"

    .line 614
    .line 615
    invoke-virtual {v0, v9}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 616
    .line 617
    .line 618
    move-result v9

    .line 619
    if-eqz v9, :cond_24

    .line 620
    .line 621
    sget-object v0, Lmy0/e;->j:Lmy0/e;

    .line 622
    .line 623
    goto :goto_e

    .line 624
    :cond_1f
    const-string v9, "d"

    .line 625
    .line 626
    invoke-virtual {v0, v9}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 627
    .line 628
    .line 629
    move-result v9

    .line 630
    if-eqz v9, :cond_24

    .line 631
    .line 632
    sget-object v0, Lmy0/e;->k:Lmy0/e;

    .line 633
    .line 634
    :goto_e
    if-eqz v4, :cond_20

    .line 635
    .line 636
    invoke-virtual {v4, v0}, Ljava/lang/Enum;->compareTo(Ljava/lang/Enum;)I

    .line 637
    .line 638
    .line 639
    move-result v4

    .line 640
    if-lez v4, :cond_21

    .line 641
    .line 642
    :cond_20
    move-object/from16 v4, v19

    .line 643
    .line 644
    const/4 v9, 0x6

    .line 645
    const/16 v13, 0x2e

    .line 646
    .line 647
    const/4 v14, 0x0

    .line 648
    goto :goto_f

    .line 649
    :cond_21
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 650
    .line 651
    move-object/from16 v4, v19

    .line 652
    .line 653
    invoke-direct {v0, v4}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 654
    .line 655
    .line 656
    throw v0

    .line 657
    :goto_f
    invoke-static {v1, v13, v14, v9}, Lly0/p;->J(Ljava/lang/CharSequence;CII)I

    .line 658
    .line 659
    .line 660
    move-result v7

    .line 661
    if-lez v7, :cond_23

    .line 662
    .line 663
    invoke-virtual {v1, v14, v7}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 664
    .line 665
    .line 666
    move-result-object v9

    .line 667
    invoke-static {v9, v8}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 668
    .line 669
    .line 670
    invoke-static {v9}, Ljava/lang/Long;->parseLong(Ljava/lang/String;)J

    .line 671
    .line 672
    .line 673
    move-result-wide v13

    .line 674
    invoke-static {v13, v14, v0}, Lmy0/h;->t(JLmy0/e;)J

    .line 675
    .line 676
    .line 677
    move-result-wide v13

    .line 678
    invoke-static {v11, v12, v13, v14}, Lmy0/c;->k(JJ)J

    .line 679
    .line 680
    .line 681
    move-result-wide v11

    .line 682
    invoke-virtual {v1, v7}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    .line 683
    .line 684
    .line 685
    move-result-object v1

    .line 686
    invoke-static {v1, v8}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 687
    .line 688
    .line 689
    invoke-static {v1}, Ljava/lang/Double;->parseDouble(Ljava/lang/String;)D

    .line 690
    .line 691
    .line 692
    move-result-wide v13

    .line 693
    invoke-static {v13, v14, v0}, Lmy0/h;->r(DLmy0/e;)J

    .line 694
    .line 695
    .line 696
    move-result-wide v13

    .line 697
    invoke-static {v11, v12, v13, v14}, Lmy0/c;->k(JJ)J

    .line 698
    .line 699
    .line 700
    move-result-wide v11

    .line 701
    if-lt v5, v6, :cond_22

    .line 702
    .line 703
    :goto_10
    move-object/from16 v19, v4

    .line 704
    .line 705
    const/4 v1, 0x1

    .line 706
    const/16 v7, 0x30

    .line 707
    .line 708
    move-object v4, v0

    .line 709
    move v0, v5

    .line 710
    goto/16 :goto_9

    .line 711
    .line 712
    :cond_22
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 713
    .line 714
    const-string v1, "Fractional component must be last"

    .line 715
    .line 716
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 717
    .line 718
    .line 719
    throw v0

    .line 720
    :cond_23
    invoke-static {v1}, Ljava/lang/Long;->parseLong(Ljava/lang/String;)J

    .line 721
    .line 722
    .line 723
    move-result-wide v13

    .line 724
    invoke-static {v13, v14, v0}, Lmy0/h;->t(JLmy0/e;)J

    .line 725
    .line 726
    .line 727
    move-result-wide v13

    .line 728
    invoke-static {v11, v12, v13, v14}, Lmy0/c;->k(JJ)J

    .line 729
    .line 730
    .line 731
    move-result-wide v11

    .line 732
    goto :goto_10

    .line 733
    :cond_24
    new-instance v1, Ljava/lang/IllegalArgumentException;

    .line 734
    .line 735
    const-string v2, "Unknown duration unit short name: "

    .line 736
    .line 737
    invoke-virtual {v2, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 738
    .line 739
    .line 740
    move-result-object v0

    .line 741
    invoke-direct {v1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 742
    .line 743
    .line 744
    throw v1

    .line 745
    :cond_25
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 746
    .line 747
    invoke-direct {v0}, Ljava/lang/IllegalArgumentException;-><init>()V

    .line 748
    .line 749
    .line 750
    throw v0

    .line 751
    :cond_26
    move-wide v8, v11

    .line 752
    :cond_27
    :goto_11
    if-eqz v10, :cond_28

    .line 753
    .line 754
    invoke-static {v8, v9}, Lmy0/c;->p(J)J

    .line 755
    .line 756
    .line 757
    move-result-wide v0

    .line 758
    return-wide v0

    .line 759
    :cond_28
    return-wide v8

    .line 760
    :cond_29
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 761
    .line 762
    invoke-direct {v0}, Ljava/lang/IllegalArgumentException;-><init>()V

    .line 763
    .line 764
    .line 765
    throw v0

    .line 766
    :cond_2a
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 767
    .line 768
    invoke-direct {v0, v11}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 769
    .line 770
    .line 771
    throw v0

    .line 772
    :cond_2b
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 773
    .line 774
    const-string v1, "The string is empty"

    .line 775
    .line 776
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 777
    .line 778
    .line 779
    throw v0
.end method

.method public static final b(DLmy0/e;Lmy0/e;)D
    .locals 6

    .line 1
    const-string v0, "sourceUnit"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "targetUnit"

    .line 7
    .line 8
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    iget-object p3, p3, Lmy0/e;->d:Ljava/util/concurrent/TimeUnit;

    .line 12
    .line 13
    iget-object p2, p2, Lmy0/e;->d:Ljava/util/concurrent/TimeUnit;

    .line 14
    .line 15
    const-wide/16 v0, 0x1

    .line 16
    .line 17
    invoke-virtual {p3, v0, v1, p2}, Ljava/util/concurrent/TimeUnit;->convert(JLjava/util/concurrent/TimeUnit;)J

    .line 18
    .line 19
    .line 20
    move-result-wide v2

    .line 21
    const-wide/16 v4, 0x0

    .line 22
    .line 23
    cmp-long v4, v2, v4

    .line 24
    .line 25
    if-lez v4, :cond_0

    .line 26
    .line 27
    long-to-double p2, v2

    .line 28
    mul-double/2addr p0, p2

    .line 29
    return-wide p0

    .line 30
    :cond_0
    invoke-virtual {p2, v0, v1, p3}, Ljava/util/concurrent/TimeUnit;->convert(JLjava/util/concurrent/TimeUnit;)J

    .line 31
    .line 32
    .line 33
    move-result-wide p2

    .line 34
    long-to-double p2, p2

    .line 35
    div-double/2addr p0, p2

    .line 36
    return-wide p0
.end method

.method public static final c(JLmy0/e;Lmy0/e;)J
    .locals 1

    .line 1
    const-string v0, "sourceUnit"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "targetUnit"

    .line 7
    .line 8
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    iget-object p3, p3, Lmy0/e;->d:Ljava/util/concurrent/TimeUnit;

    .line 12
    .line 13
    iget-object p2, p2, Lmy0/e;->d:Ljava/util/concurrent/TimeUnit;

    .line 14
    .line 15
    invoke-virtual {p3, p0, p1, p2}, Ljava/util/concurrent/TimeUnit;->convert(JLjava/util/concurrent/TimeUnit;)J

    .line 16
    .line 17
    .line 18
    move-result-wide p0

    .line 19
    return-wide p0
.end method

.method public static final d(JLmy0/e;Lmy0/e;)J
    .locals 1

    .line 1
    const-string v0, "sourceUnit"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "targetUnit"

    .line 7
    .line 8
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    iget-object p3, p3, Lmy0/e;->d:Ljava/util/concurrent/TimeUnit;

    .line 12
    .line 13
    iget-object p2, p2, Lmy0/e;->d:Ljava/util/concurrent/TimeUnit;

    .line 14
    .line 15
    invoke-virtual {p3, p0, p1, p2}, Ljava/util/concurrent/TimeUnit;->convert(JLjava/util/concurrent/TimeUnit;)J

    .line 16
    .line 17
    .line 18
    move-result-wide p0

    .line 19
    return-wide p0
.end method

.method public static final e(J)J
    .locals 2

    .line 1
    const/4 v0, 0x1

    .line 2
    shl-long/2addr p0, v0

    .line 3
    const-wide/16 v0, 0x1

    .line 4
    .line 5
    add-long/2addr p0, v0

    .line 6
    sget v0, Lmy0/c;->g:I

    .line 7
    .line 8
    sget v0, Lmy0/d;->a:I

    .line 9
    .line 10
    return-wide p0
.end method

.method public static final f(J)J
    .locals 6

    .line 1
    const-wide v0, -0x431bde82d7aL

    .line 2
    .line 3
    .line 4
    .line 5
    .line 6
    cmp-long v0, v0, p0

    .line 7
    .line 8
    if-gtz v0, :cond_0

    .line 9
    .line 10
    const-wide v0, 0x431bde82d7bL

    .line 11
    .line 12
    .line 13
    .line 14
    .line 15
    cmp-long v0, p0, v0

    .line 16
    .line 17
    if-gez v0, :cond_0

    .line 18
    .line 19
    const v0, 0xf4240

    .line 20
    .line 21
    .line 22
    int-to-long v0, v0

    .line 23
    mul-long/2addr p0, v0

    .line 24
    invoke-static {p0, p1}, Lmy0/h;->g(J)J

    .line 25
    .line 26
    .line 27
    move-result-wide p0

    .line 28
    return-wide p0

    .line 29
    :cond_0
    const-wide v2, -0x3fffffffffffffffL    # -2.0000000000000004

    .line 30
    .line 31
    .line 32
    .line 33
    .line 34
    const-wide v4, 0x3fffffffffffffffL    # 1.9999999999999998

    .line 35
    .line 36
    .line 37
    .line 38
    .line 39
    move-wide v0, p0

    .line 40
    invoke-static/range {v0 .. v5}, Lkp/r9;->g(JJJ)J

    .line 41
    .line 42
    .line 43
    move-result-wide p0

    .line 44
    invoke-static {p0, p1}, Lmy0/h;->e(J)J

    .line 45
    .line 46
    .line 47
    move-result-wide p0

    .line 48
    return-wide p0
.end method

.method public static final g(J)J
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    shl-long/2addr p0, v0

    .line 3
    sget v0, Lmy0/c;->g:I

    .line 4
    .line 5
    sget v0, Lmy0/d;->a:I

    .line 6
    .line 7
    return-wide p0
.end method

.method public static final h(Ljava/lang/StringBuilder;Ljava/lang/StringBuilder;I)V
    .locals 1

    .line 1
    const/16 v0, 0xa

    .line 2
    .line 3
    if-ge p2, v0, :cond_0

    .line 4
    .line 5
    const/16 v0, 0x30

    .line 6
    .line 7
    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/Appendable;

    .line 8
    .line 9
    .line 10
    :cond_0
    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method public static i(IJ)Lmy0/f;
    .locals 12

    .line 1
    int-to-long v0, p0

    .line 2
    const-wide/32 v2, 0x3b9aca00

    .line 3
    .line 4
    .line 5
    div-long v4, v0, v2

    .line 6
    .line 7
    xor-long v6, v0, v2

    .line 8
    .line 9
    const-wide/16 v8, 0x0

    .line 10
    .line 11
    cmp-long p0, v6, v8

    .line 12
    .line 13
    if-gez p0, :cond_0

    .line 14
    .line 15
    mul-long v6, v4, v2

    .line 16
    .line 17
    cmp-long p0, v6, v0

    .line 18
    .line 19
    if-eqz p0, :cond_0

    .line 20
    .line 21
    const-wide/16 v6, -0x1

    .line 22
    .line 23
    add-long/2addr v4, v6

    .line 24
    :cond_0
    add-long v6, p1, v4

    .line 25
    .line 26
    xor-long v10, p1, v6

    .line 27
    .line 28
    cmp-long p0, v10, v8

    .line 29
    .line 30
    if-gez p0, :cond_2

    .line 31
    .line 32
    xor-long/2addr v4, p1

    .line 33
    cmp-long p0, v4, v8

    .line 34
    .line 35
    if-ltz p0, :cond_2

    .line 36
    .line 37
    cmp-long p0, p1, v8

    .line 38
    .line 39
    if-lez p0, :cond_1

    .line 40
    .line 41
    sget-object p0, Lmy0/f;->g:Lmy0/f;

    .line 42
    .line 43
    return-object p0

    .line 44
    :cond_1
    sget-object p0, Lmy0/f;->f:Lmy0/f;

    .line 45
    .line 46
    return-object p0

    .line 47
    :cond_2
    const-wide p0, -0x701cefeb9bec00L

    .line 48
    .line 49
    .line 50
    .line 51
    .line 52
    cmp-long p0, v6, p0

    .line 53
    .line 54
    if-gez p0, :cond_3

    .line 55
    .line 56
    sget-object p0, Lmy0/f;->f:Lmy0/f;

    .line 57
    .line 58
    return-object p0

    .line 59
    :cond_3
    const-wide p0, 0x701cd2fa9578ffL

    .line 60
    .line 61
    .line 62
    .line 63
    .line 64
    cmp-long p0, v6, p0

    .line 65
    .line 66
    if-lez p0, :cond_4

    .line 67
    .line 68
    sget-object p0, Lmy0/f;->g:Lmy0/f;

    .line 69
    .line 70
    return-object p0

    .line 71
    :cond_4
    rem-long/2addr v0, v2

    .line 72
    xor-long p0, v0, v2

    .line 73
    .line 74
    neg-long v4, v0

    .line 75
    or-long/2addr v4, v0

    .line 76
    and-long/2addr p0, v4

    .line 77
    const/16 p2, 0x3f

    .line 78
    .line 79
    shr-long/2addr p0, p2

    .line 80
    and-long/2addr p0, v2

    .line 81
    add-long/2addr v0, p0

    .line 82
    long-to-int p0, v0

    .line 83
    new-instance p1, Lmy0/f;

    .line 84
    .line 85
    invoke-direct {p1, v6, v7, p0}, Lmy0/f;-><init>(JI)V

    .line 86
    .line 87
    .line 88
    return-object p1
.end method

.method public static final j(J)J
    .locals 2

    .line 1
    const-wide/16 v0, 0x0

    .line 2
    .line 3
    cmp-long p0, p0, v0

    .line 4
    .line 5
    if-gez p0, :cond_0

    .line 6
    .line 7
    sget p0, Lmy0/c;->g:I

    .line 8
    .line 9
    sget-wide p0, Lmy0/c;->f:J

    .line 10
    .line 11
    return-wide p0

    .line 12
    :cond_0
    sget p0, Lmy0/c;->g:I

    .line 13
    .line 14
    sget-wide p0, Lmy0/c;->e:J

    .line 15
    .line 16
    return-wide p0
.end method

.method public static k(Ljava/lang/String;)J
    .locals 4

    .line 1
    const-string v0, "value"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const/4 v0, 0x0

    .line 7
    :try_start_0
    invoke-static {p0, v0}, Lmy0/h;->a(Ljava/lang/String;Z)J

    .line 8
    .line 9
    .line 10
    move-result-wide v0
    :try_end_0
    .catch Ljava/lang/IllegalArgumentException; {:try_start_0 .. :try_end_0} :catch_0

    .line 11
    return-wide v0

    .line 12
    :catch_0
    move-exception v0

    .line 13
    new-instance v1, Ljava/lang/IllegalArgumentException;

    .line 14
    .line 15
    const-string v2, "Invalid duration string format: \'"

    .line 16
    .line 17
    const-string v3, "\'."

    .line 18
    .line 19
    invoke-static {v2, p0, v3}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    invoke-direct {v1, p0, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 24
    .line 25
    .line 26
    throw v1
.end method

.method public static final l(Ljava/lang/String;Ljava/lang/String;ILay0/k;)Lc2/k;
    .locals 2

    .line 1
    invoke-virtual {p0, p2}, Ljava/lang/String;->charAt(I)C

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-static {v0}, Ljava/lang/Character;->valueOf(C)Ljava/lang/Character;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    invoke-interface {p3, v1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p3

    .line 13
    check-cast p3, Ljava/lang/Boolean;

    .line 14
    .line 15
    invoke-virtual {p3}, Ljava/lang/Boolean;->booleanValue()Z

    .line 16
    .line 17
    .line 18
    move-result p3

    .line 19
    if-eqz p3, :cond_0

    .line 20
    .line 21
    const/4 p0, 0x0

    .line 22
    return-object p0

    .line 23
    :cond_0
    new-instance p3, Ljava/lang/StringBuilder;

    .line 24
    .line 25
    const-string v1, "Expected "

    .line 26
    .line 27
    invoke-direct {p3, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    invoke-virtual {p3, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const-string p1, ", but got \'"

    .line 34
    .line 35
    invoke-virtual {p3, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    invoke-virtual {p3, v0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 39
    .line 40
    .line 41
    const-string p1, "\' at position "

    .line 42
    .line 43
    invoke-virtual {p3, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 44
    .line 45
    .line 46
    invoke-virtual {p3, p2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 47
    .line 48
    .line 49
    invoke-virtual {p3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 50
    .line 51
    .line 52
    move-result-object p1

    .line 53
    invoke-static {p0, p1}, Lmy0/h;->m(Ljava/lang/String;Ljava/lang/String;)Lc2/k;

    .line 54
    .line 55
    .line 56
    move-result-object p0

    .line 57
    return-object p0
.end method

.method public static final m(Ljava/lang/String;Ljava/lang/String;)Lc2/k;
    .locals 2

    .line 1
    new-instance v0, Lc2/k;

    .line 2
    .line 3
    const-string v1, " when parsing an Instant from \""

    .line 4
    .line 5
    invoke-static {p1, v1}, Lp3/m;->q(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    const/16 v1, 0x40

    .line 10
    .line 11
    invoke-static {v1, p0}, Lmy0/h;->u(ILjava/lang/String;)Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    invoke-virtual {p1, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    const/16 v1, 0x22

    .line 19
    .line 20
    invoke-virtual {p1, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object p1

    .line 27
    invoke-direct {v0, p1, p0}, Lc2/k;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    return-object v0
.end method

.method public static final n(ILjava/lang/String;)I
    .locals 1

    .line 1
    invoke-virtual {p1, p0}, Ljava/lang/String;->charAt(I)C

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    add-int/lit8 v0, v0, -0x30

    .line 6
    .line 7
    mul-int/lit8 v0, v0, 0xa

    .line 8
    .line 9
    add-int/lit8 p0, p0, 0x1

    .line 10
    .line 11
    invoke-virtual {p1, p0}, Ljava/lang/String;->charAt(I)C

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    add-int/lit8 p0, p0, -0x30

    .line 16
    .line 17
    add-int/2addr p0, v0

    .line 18
    return p0
.end method

.method public static o(Ljava/lang/String;)J
    .locals 4

    .line 1
    const-string v0, "value"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const/4 v0, 0x1

    .line 7
    :try_start_0
    invoke-static {p0, v0}, Lmy0/h;->a(Ljava/lang/String;Z)J

    .line 8
    .line 9
    .line 10
    move-result-wide v0
    :try_end_0
    .catch Ljava/lang/IllegalArgumentException; {:try_start_0 .. :try_end_0} :catch_0

    .line 11
    return-wide v0

    .line 12
    :catch_0
    move-exception v0

    .line 13
    new-instance v1, Ljava/lang/IllegalArgumentException;

    .line 14
    .line 15
    const-string v2, "Invalid ISO duration string format: \'"

    .line 16
    .line 17
    const-string v3, "\'."

    .line 18
    .line 19
    invoke-static {v2, p0, v3}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    invoke-direct {v1, p0, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 24
    .line 25
    .line 26
    throw v1
.end method

.method public static final p(Ljava/lang/String;)J
    .locals 10

    .line 1
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x1

    .line 6
    const/4 v2, 0x0

    .line 7
    if-lez v0, :cond_0

    .line 8
    .line 9
    const-string v3, "+-"

    .line 10
    .line 11
    invoke-virtual {p0, v2}, Ljava/lang/String;->charAt(I)C

    .line 12
    .line 13
    .line 14
    move-result v4

    .line 15
    invoke-static {v3, v4}, Lly0/p;->B(Ljava/lang/CharSequence;C)Z

    .line 16
    .line 17
    .line 18
    move-result v3

    .line 19
    if-eqz v3, :cond_0

    .line 20
    .line 21
    move v3, v1

    .line 22
    goto :goto_0

    .line 23
    :cond_0
    move v3, v2

    .line 24
    :goto_0
    sub-int v4, v0, v3

    .line 25
    .line 26
    const/16 v5, 0x3a

    .line 27
    .line 28
    const/16 v6, 0x30

    .line 29
    .line 30
    const/16 v7, 0x10

    .line 31
    .line 32
    if-le v4, v7, :cond_5

    .line 33
    .line 34
    move v4, v3

    .line 35
    :goto_1
    if-ge v3, v0, :cond_3

    .line 36
    .line 37
    invoke-virtual {p0, v3}, Ljava/lang/String;->charAt(I)C

    .line 38
    .line 39
    .line 40
    move-result v8

    .line 41
    if-ne v8, v6, :cond_1

    .line 42
    .line 43
    if-ne v4, v3, :cond_2

    .line 44
    .line 45
    add-int/lit8 v4, v4, 0x1

    .line 46
    .line 47
    goto :goto_2

    .line 48
    :cond_1
    const/16 v9, 0x31

    .line 49
    .line 50
    if-gt v9, v8, :cond_5

    .line 51
    .line 52
    if-ge v8, v5, :cond_5

    .line 53
    .line 54
    :cond_2
    :goto_2
    add-int/lit8 v3, v3, 0x1

    .line 55
    .line 56
    goto :goto_1

    .line 57
    :cond_3
    sub-int v3, v0, v4

    .line 58
    .line 59
    if-le v3, v7, :cond_5

    .line 60
    .line 61
    invoke-virtual {p0, v2}, Ljava/lang/String;->charAt(I)C

    .line 62
    .line 63
    .line 64
    move-result p0

    .line 65
    const/16 v0, 0x2d

    .line 66
    .line 67
    if-ne p0, v0, :cond_4

    .line 68
    .line 69
    const-wide/high16 v0, -0x8000000000000000L

    .line 70
    .line 71
    return-wide v0

    .line 72
    :cond_4
    const-wide v0, 0x7fffffffffffffffL

    .line 73
    .line 74
    .line 75
    .line 76
    .line 77
    return-wide v0

    .line 78
    :cond_5
    const-string v3, "+"

    .line 79
    .line 80
    invoke-static {p0, v3, v2}, Lly0/w;->x(Ljava/lang/String;Ljava/lang/String;Z)Z

    .line 81
    .line 82
    .line 83
    move-result v2

    .line 84
    if-eqz v2, :cond_6

    .line 85
    .line 86
    if-le v0, v1, :cond_6

    .line 87
    .line 88
    invoke-virtual {p0, v1}, Ljava/lang/String;->charAt(I)C

    .line 89
    .line 90
    .line 91
    move-result v0

    .line 92
    if-gt v6, v0, :cond_6

    .line 93
    .line 94
    if-ge v0, v5, :cond_6

    .line 95
    .line 96
    invoke-static {v1, p0}, Lly0/p;->C(ILjava/lang/String;)Ljava/lang/String;

    .line 97
    .line 98
    .line 99
    move-result-object p0

    .line 100
    invoke-static {p0}, Ljava/lang/Long;->parseLong(Ljava/lang/String;)J

    .line 101
    .line 102
    .line 103
    move-result-wide v0

    .line 104
    return-wide v0

    .line 105
    :cond_6
    invoke-static {p0}, Ljava/lang/Long;->parseLong(Ljava/lang/String;)J

    .line 106
    .line 107
    .line 108
    move-result-wide v0

    .line 109
    return-wide v0
.end method

.method public static final q(JJLmy0/e;)J
    .locals 7

    .line 1
    sub-long v0, p0, p2

    .line 2
    .line 3
    xor-long v2, v0, p0

    .line 4
    .line 5
    xor-long v4, v0, p2

    .line 6
    .line 7
    not-long v4, v4

    .line 8
    and-long/2addr v2, v4

    .line 9
    const-wide/16 v4, 0x0

    .line 10
    .line 11
    cmp-long v2, v2, v4

    .line 12
    .line 13
    if-gez v2, :cond_1

    .line 14
    .line 15
    sget-object v2, Lmy0/e;->g:Lmy0/e;

    .line 16
    .line 17
    invoke-virtual {p4, v2}, Ljava/lang/Enum;->compareTo(Ljava/lang/Enum;)I

    .line 18
    .line 19
    .line 20
    move-result v3

    .line 21
    if-gez v3, :cond_0

    .line 22
    .line 23
    const-wide/16 v0, 0x1

    .line 24
    .line 25
    invoke-static {v0, v1, v2, p4}, Lmy0/h;->c(JLmy0/e;Lmy0/e;)J

    .line 26
    .line 27
    .line 28
    move-result-wide v0

    .line 29
    div-long v3, p0, v0

    .line 30
    .line 31
    div-long v5, p2, v0

    .line 32
    .line 33
    sub-long/2addr v3, v5

    .line 34
    rem-long/2addr p0, v0

    .line 35
    rem-long/2addr p2, v0

    .line 36
    sub-long/2addr p0, p2

    .line 37
    sget p2, Lmy0/c;->g:I

    .line 38
    .line 39
    invoke-static {v3, v4, v2}, Lmy0/h;->t(JLmy0/e;)J

    .line 40
    .line 41
    .line 42
    move-result-wide p2

    .line 43
    invoke-static {p0, p1, p4}, Lmy0/h;->t(JLmy0/e;)J

    .line 44
    .line 45
    .line 46
    move-result-wide p0

    .line 47
    invoke-static {p2, p3, p0, p1}, Lmy0/c;->k(JJ)J

    .line 48
    .line 49
    .line 50
    move-result-wide p0

    .line 51
    return-wide p0

    .line 52
    :cond_0
    invoke-static {v0, v1}, Lmy0/h;->j(J)J

    .line 53
    .line 54
    .line 55
    move-result-wide p0

    .line 56
    invoke-static {p0, p1}, Lmy0/c;->p(J)J

    .line 57
    .line 58
    .line 59
    move-result-wide p0

    .line 60
    return-wide p0

    .line 61
    :cond_1
    invoke-static {v0, v1, p4}, Lmy0/h;->t(JLmy0/e;)J

    .line 62
    .line 63
    .line 64
    move-result-wide p0

    .line 65
    return-wide p0
.end method

.method public static final r(DLmy0/e;)J
    .locals 4

    .line 1
    const-string v0, "unit"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget-object v0, Lmy0/e;->e:Lmy0/e;

    .line 7
    .line 8
    invoke-static {p0, p1, p2, v0}, Lmy0/h;->b(DLmy0/e;Lmy0/e;)D

    .line 9
    .line 10
    .line 11
    move-result-wide v0

    .line 12
    invoke-static {v0, v1}, Ljava/lang/Double;->isNaN(D)Z

    .line 13
    .line 14
    .line 15
    move-result v2

    .line 16
    if-nez v2, :cond_1

    .line 17
    .line 18
    invoke-static {v0, v1}, Lcy0/a;->j(D)J

    .line 19
    .line 20
    .line 21
    move-result-wide v0

    .line 22
    const-wide v2, -0x3ffffffffffa14bfL    # -2.0000000001722644

    .line 23
    .line 24
    .line 25
    .line 26
    .line 27
    cmp-long v2, v2, v0

    .line 28
    .line 29
    if-gtz v2, :cond_0

    .line 30
    .line 31
    const-wide v2, 0x3ffffffffffa14c0L    # 1.999999999913868

    .line 32
    .line 33
    .line 34
    .line 35
    .line 36
    cmp-long v2, v0, v2

    .line 37
    .line 38
    if-gez v2, :cond_0

    .line 39
    .line 40
    invoke-static {v0, v1}, Lmy0/h;->g(J)J

    .line 41
    .line 42
    .line 43
    move-result-wide p0

    .line 44
    return-wide p0

    .line 45
    :cond_0
    sget-object v0, Lmy0/e;->g:Lmy0/e;

    .line 46
    .line 47
    invoke-static {p0, p1, p2, v0}, Lmy0/h;->b(DLmy0/e;Lmy0/e;)D

    .line 48
    .line 49
    .line 50
    move-result-wide p0

    .line 51
    invoke-static {p0, p1}, Lcy0/a;->j(D)J

    .line 52
    .line 53
    .line 54
    move-result-wide p0

    .line 55
    invoke-static {p0, p1}, Lmy0/h;->f(J)J

    .line 56
    .line 57
    .line 58
    move-result-wide p0

    .line 59
    return-wide p0

    .line 60
    :cond_1
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 61
    .line 62
    const-string p1, "Duration value cannot be NaN."

    .line 63
    .line 64
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 65
    .line 66
    .line 67
    throw p0
.end method

.method public static final s(ILmy0/e;)J
    .locals 2

    .line 1
    const-string v0, "unit"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget-object v0, Lmy0/e;->h:Lmy0/e;

    .line 7
    .line 8
    invoke-virtual {p1, v0}, Ljava/lang/Enum;->compareTo(Ljava/lang/Enum;)I

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    if-gtz v0, :cond_0

    .line 13
    .line 14
    int-to-long v0, p0

    .line 15
    sget-object p0, Lmy0/e;->e:Lmy0/e;

    .line 16
    .line 17
    invoke-static {v0, v1, p1, p0}, Lmy0/h;->d(JLmy0/e;Lmy0/e;)J

    .line 18
    .line 19
    .line 20
    move-result-wide p0

    .line 21
    invoke-static {p0, p1}, Lmy0/h;->g(J)J

    .line 22
    .line 23
    .line 24
    move-result-wide p0

    .line 25
    return-wide p0

    .line 26
    :cond_0
    int-to-long v0, p0

    .line 27
    invoke-static {v0, v1, p1}, Lmy0/h;->t(JLmy0/e;)J

    .line 28
    .line 29
    .line 30
    move-result-wide p0

    .line 31
    return-wide p0
.end method

.method public static final t(JLmy0/e;)J
    .locals 7

    .line 1
    const-string v0, "unit"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget-object v0, Lmy0/e;->e:Lmy0/e;

    .line 7
    .line 8
    const-wide v1, 0x3ffffffffffa14bfL    # 1.9999999999138678

    .line 9
    .line 10
    .line 11
    .line 12
    .line 13
    invoke-static {v1, v2, v0, p2}, Lmy0/h;->d(JLmy0/e;Lmy0/e;)J

    .line 14
    .line 15
    .line 16
    move-result-wide v1

    .line 17
    neg-long v3, v1

    .line 18
    cmp-long v3, v3, p0

    .line 19
    .line 20
    if-gtz v3, :cond_0

    .line 21
    .line 22
    cmp-long v1, p0, v1

    .line 23
    .line 24
    if-gtz v1, :cond_0

    .line 25
    .line 26
    invoke-static {p0, p1, p2, v0}, Lmy0/h;->d(JLmy0/e;Lmy0/e;)J

    .line 27
    .line 28
    .line 29
    move-result-wide p0

    .line 30
    invoke-static {p0, p1}, Lmy0/h;->g(J)J

    .line 31
    .line 32
    .line 33
    move-result-wide p0

    .line 34
    return-wide p0

    .line 35
    :cond_0
    sget-object v0, Lmy0/e;->g:Lmy0/e;

    .line 36
    .line 37
    invoke-static {p0, p1, p2, v0}, Lmy0/h;->c(JLmy0/e;Lmy0/e;)J

    .line 38
    .line 39
    .line 40
    move-result-wide v1

    .line 41
    const-wide v3, -0x3fffffffffffffffL    # -2.0000000000000004

    .line 42
    .line 43
    .line 44
    .line 45
    .line 46
    const-wide v5, 0x3fffffffffffffffL    # 1.9999999999999998

    .line 47
    .line 48
    .line 49
    .line 50
    .line 51
    invoke-static/range {v1 .. v6}, Lkp/r9;->g(JJJ)J

    .line 52
    .line 53
    .line 54
    move-result-wide p0

    .line 55
    invoke-static {p0, p1}, Lmy0/h;->e(J)J

    .line 56
    .line 57
    .line 58
    move-result-wide p0

    .line 59
    return-wide p0
.end method

.method public static final u(ILjava/lang/String;)Ljava/lang/String;
    .locals 2

    .line 1
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-gt v0, p0, :cond_0

    .line 6
    .line 7
    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0

    .line 12
    :cond_0
    new-instance v0, Ljava/lang/StringBuilder;

    .line 13
    .line 14
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 15
    .line 16
    .line 17
    const/4 v1, 0x0

    .line 18
    invoke-virtual {p1, v1, p0}, Ljava/lang/String;->subSequence(II)Ljava/lang/CharSequence;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 27
    .line 28
    .line 29
    const-string p0, "..."

    .line 30
    .line 31
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 32
    .line 33
    .line 34
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    return-object p0
.end method
