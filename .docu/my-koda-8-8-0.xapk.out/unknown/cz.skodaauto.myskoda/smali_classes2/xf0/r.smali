.class public final synthetic Lxf0/r;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:Z

.field public final synthetic e:J

.field public final synthetic f:I

.field public final synthetic g:J

.field public final synthetic h:I

.field public final synthetic i:F

.field public final synthetic j:Ljava/lang/Integer;

.field public final synthetic k:J

.field public final synthetic l:J

.field public final synthetic m:Z

.field public final synthetic n:Z

.field public final synthetic o:J

.field public final synthetic p:Z

.field public final synthetic q:I

.field public final synthetic r:J

.field public final synthetic s:J


# direct methods
.method public synthetic constructor <init>(ZJIJIFLjava/lang/Integer;JJZZJZIJJ)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-boolean p1, p0, Lxf0/r;->d:Z

    .line 5
    .line 6
    iput-wide p2, p0, Lxf0/r;->e:J

    .line 7
    .line 8
    iput p4, p0, Lxf0/r;->f:I

    .line 9
    .line 10
    iput-wide p5, p0, Lxf0/r;->g:J

    .line 11
    .line 12
    iput p7, p0, Lxf0/r;->h:I

    .line 13
    .line 14
    iput p8, p0, Lxf0/r;->i:F

    .line 15
    .line 16
    iput-object p9, p0, Lxf0/r;->j:Ljava/lang/Integer;

    .line 17
    .line 18
    iput-wide p10, p0, Lxf0/r;->k:J

    .line 19
    .line 20
    iput-wide p12, p0, Lxf0/r;->l:J

    .line 21
    .line 22
    iput-boolean p14, p0, Lxf0/r;->m:Z

    .line 23
    .line 24
    iput-boolean p15, p0, Lxf0/r;->n:Z

    .line 25
    .line 26
    move-wide/from16 p1, p16

    .line 27
    .line 28
    iput-wide p1, p0, Lxf0/r;->o:J

    .line 29
    .line 30
    move/from16 p1, p18

    .line 31
    .line 32
    iput-boolean p1, p0, Lxf0/r;->p:Z

    .line 33
    .line 34
    move/from16 p1, p19

    .line 35
    .line 36
    iput p1, p0, Lxf0/r;->q:I

    .line 37
    .line 38
    move-wide/from16 p1, p20

    .line 39
    .line 40
    iput-wide p1, p0, Lxf0/r;->r:J

    .line 41
    .line 42
    move-wide/from16 p1, p22

    .line 43
    .line 44
    iput-wide p1, p0, Lxf0/r;->s:J

    .line 45
    .line 46
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 37

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    check-cast v1, Lg3/d;

    .line 6
    .line 7
    sget-object v12, Lxf0/t;->b:Lgy0/j;

    .line 8
    .line 9
    sget-object v13, Lxf0/t;->a:Lgy0/j;

    .line 10
    .line 11
    const-string v2, "$this$Canvas"

    .line 12
    .line 13
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    invoke-interface {v1}, Lg3/d;->e()J

    .line 17
    .line 18
    .line 19
    move-result-wide v2

    .line 20
    const-wide v14, 0xffffffffL

    .line 21
    .line 22
    .line 23
    .line 24
    .line 25
    and-long/2addr v2, v14

    .line 26
    long-to-int v2, v2

    .line 27
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 28
    .line 29
    .line 30
    move-result v2

    .line 31
    const/high16 v3, 0x40000000    # 2.0f

    .line 32
    .line 33
    div-float v16, v2, v3

    .line 34
    .line 35
    iget-boolean v2, v0, Lxf0/r;->d:Z

    .line 36
    .line 37
    const/16 v17, 0x20

    .line 38
    .line 39
    invoke-interface {v1}, Lg3/d;->e()J

    .line 40
    .line 41
    .line 42
    move-result-wide v4

    .line 43
    if-eqz v2, :cond_0

    .line 44
    .line 45
    shr-long v4, v4, v17

    .line 46
    .line 47
    long-to-int v4, v4

    .line 48
    invoke-static {v4}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 49
    .line 50
    .line 51
    move-result v4

    .line 52
    :goto_0
    move/from16 v18, v4

    .line 53
    .line 54
    goto :goto_1

    .line 55
    :cond_0
    shr-long v4, v4, v17

    .line 56
    .line 57
    long-to-int v4, v4

    .line 58
    invoke-static {v4}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 59
    .line 60
    .line 61
    move-result v4

    .line 62
    sub-float v4, v4, v16

    .line 63
    .line 64
    goto :goto_0

    .line 65
    :goto_1
    invoke-interface {v1}, Lg3/d;->e()J

    .line 66
    .line 67
    .line 68
    move-result-wide v4

    .line 69
    and-long/2addr v4, v14

    .line 70
    long-to-int v4, v4

    .line 71
    invoke-static {v4}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 72
    .line 73
    .line 74
    move-result v4

    .line 75
    invoke-interface {v1}, Lg3/d;->e()J

    .line 76
    .line 77
    .line 78
    move-result-wide v5

    .line 79
    and-long/2addr v5, v14

    .line 80
    long-to-int v5, v5

    .line 81
    invoke-static {v5}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 82
    .line 83
    .line 84
    move-result v7

    .line 85
    div-float v19, v4, v3

    .line 86
    .line 87
    iget v3, v0, Lxf0/r;->f:I

    .line 88
    .line 89
    int-to-float v4, v3

    .line 90
    const/high16 v20, 0x42c80000    # 100.0f

    .line 91
    .line 92
    cmpg-float v5, v4, v20

    .line 93
    .line 94
    const/16 v21, 0x1

    .line 95
    .line 96
    const/16 v22, 0x0

    .line 97
    .line 98
    if-gez v5, :cond_1

    .line 99
    .line 100
    move/from16 v9, v22

    .line 101
    .line 102
    goto :goto_2

    .line 103
    :cond_1
    move/from16 v9, v21

    .line 104
    .line 105
    :goto_2
    const/4 v5, 0x0

    .line 106
    if-eqz v2, :cond_2

    .line 107
    .line 108
    iget v6, v13, Lgy0/h;->d:I

    .line 109
    .line 110
    if-le v3, v6, :cond_2

    .line 111
    .line 112
    div-float v4, v4, v20

    .line 113
    .line 114
    mul-float v4, v4, v18

    .line 115
    .line 116
    invoke-static {v5}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 117
    .line 118
    .line 119
    move-result v3

    .line 120
    int-to-long v10, v3

    .line 121
    invoke-static/range {v19 .. v19}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 122
    .line 123
    .line 124
    move-result v3

    .line 125
    int-to-long v5, v3

    .line 126
    shl-long v10, v10, v17

    .line 127
    .line 128
    and-long/2addr v5, v14

    .line 129
    or-long/2addr v5, v10

    .line 130
    invoke-static {v4}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 131
    .line 132
    .line 133
    move-result v3

    .line 134
    int-to-long v3, v3

    .line 135
    invoke-static/range {v19 .. v19}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 136
    .line 137
    .line 138
    move-result v8

    .line 139
    int-to-long v10, v8

    .line 140
    shl-long v3, v3, v17

    .line 141
    .line 142
    and-long/2addr v10, v14

    .line 143
    or-long/2addr v3, v10

    .line 144
    const/4 v10, 0x0

    .line 145
    const/16 v11, 0x1e0

    .line 146
    .line 147
    move-wide/from16 v23, v5

    .line 148
    .line 149
    move v5, v2

    .line 150
    move-wide/from16 v35, v3

    .line 151
    .line 152
    move v4, v7

    .line 153
    move-wide/from16 v6, v35

    .line 154
    .line 155
    iget-wide v2, v0, Lxf0/r;->e:J

    .line 156
    .line 157
    move v8, v4

    .line 158
    move-wide/from16 v35, v23

    .line 159
    .line 160
    move/from16 v23, v5

    .line 161
    .line 162
    move-wide/from16 v24, v14

    .line 163
    .line 164
    move-wide/from16 v4, v35

    .line 165
    .line 166
    const/4 v14, 0x0

    .line 167
    invoke-static/range {v1 .. v11}, Lg3/d;->q(Lg3/d;JJJFILe3/j;I)V

    .line 168
    .line 169
    .line 170
    move v4, v8

    .line 171
    :goto_3
    move/from16 v15, v16

    .line 172
    .line 173
    move/from16 v16, v18

    .line 174
    .line 175
    move/from16 v18, v19

    .line 176
    .line 177
    goto :goto_4

    .line 178
    :cond_2
    move/from16 v23, v2

    .line 179
    .line 180
    move-wide/from16 v24, v14

    .line 181
    .line 182
    move v14, v5

    .line 183
    if-nez v23, :cond_3

    .line 184
    .line 185
    iget v2, v12, Lgy0/h;->e:I

    .line 186
    .line 187
    if-ge v3, v2, :cond_3

    .line 188
    .line 189
    div-float v4, v4, v20

    .line 190
    .line 191
    mul-float v5, v4, v18

    .line 192
    .line 193
    iget-wide v2, v0, Lxf0/r;->g:J

    .line 194
    .line 195
    move v4, v7

    .line 196
    move/from16 v8, v16

    .line 197
    .line 198
    move/from16 v6, v18

    .line 199
    .line 200
    move/from16 v7, v19

    .line 201
    .line 202
    invoke-static/range {v1 .. v8}, Lxf0/t;->b(Lg3/d;JFFFFF)V

    .line 203
    .line 204
    .line 205
    move/from16 v16, v6

    .line 206
    .line 207
    move/from16 v18, v7

    .line 208
    .line 209
    move v15, v8

    .line 210
    goto :goto_4

    .line 211
    :cond_3
    move v4, v7

    .line 212
    goto :goto_3

    .line 213
    :goto_4
    iget v2, v13, Lgy0/h;->d:I

    .line 214
    .line 215
    iget v3, v0, Lxf0/r;->h:I

    .line 216
    .line 217
    iget-object v13, v0, Lxf0/r;->j:Ljava/lang/Integer;

    .line 218
    .line 219
    const/16 v5, 0x50

    .line 220
    .line 221
    const/16 v6, 0x14

    .line 222
    .line 223
    if-le v3, v2, :cond_e

    .line 224
    .line 225
    int-to-float v2, v3

    .line 226
    div-float v2, v2, v20

    .line 227
    .line 228
    mul-float v2, v2, v16

    .line 229
    .line 230
    const v3, 0x3f99999a    # 1.2f

    .line 231
    .line 232
    .line 233
    mul-float v3, v3, v16

    .line 234
    .line 235
    iget v7, v0, Lxf0/r;->i:F

    .line 236
    .line 237
    mul-float/2addr v3, v7

    .line 238
    if-eqz v13, :cond_4

    .line 239
    .line 240
    invoke-virtual {v13}, Ljava/lang/Integer;->intValue()I

    .line 241
    .line 242
    .line 243
    move-result v7

    .line 244
    goto :goto_5

    .line 245
    :cond_4
    move v7, v6

    .line 246
    :goto_5
    if-ge v7, v6, :cond_5

    .line 247
    .line 248
    move v7, v6

    .line 249
    :cond_5
    int-to-float v7, v7

    .line 250
    mul-float v7, v7, v16

    .line 251
    .line 252
    div-float v7, v7, v20

    .line 253
    .line 254
    if-eqz v23, :cond_6

    .line 255
    .line 256
    iget-boolean v8, v0, Lxf0/r;->n:Z

    .line 257
    .line 258
    if-eqz v8, :cond_6

    .line 259
    .line 260
    goto :goto_6

    .line 261
    :cond_6
    move/from16 v21, v22

    .line 262
    .line 263
    :goto_6
    invoke-static {v14, v2}, Ljava/lang/Math;->max(FF)F

    .line 264
    .line 265
    .line 266
    move-result v2

    .line 267
    int-to-float v8, v5

    .line 268
    invoke-interface {v1, v8}, Lt4/c;->w0(F)F

    .line 269
    .line 270
    .line 271
    move-result v8

    .line 272
    sub-float v8, v3, v8

    .line 273
    .line 274
    iget-wide v9, v0, Lxf0/r;->l:J

    .line 275
    .line 276
    if-eqz v21, :cond_7

    .line 277
    .line 278
    move-wide v5, v9

    .line 279
    goto :goto_7

    .line 280
    :cond_7
    sget-wide v26, Le3/s;->h:J

    .line 281
    .line 282
    move-wide/from16 v5, v26

    .line 283
    .line 284
    :goto_7
    if-eqz v21, :cond_8

    .line 285
    .line 286
    sget-wide v9, Le3/s;->h:J

    .line 287
    .line 288
    :cond_8
    invoke-static {v14}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 289
    .line 290
    .line 291
    move-result-object v11

    .line 292
    move/from16 v26, v14

    .line 293
    .line 294
    new-instance v14, Le3/s;

    .line 295
    .line 296
    invoke-direct {v14, v5, v6}, Le3/s;-><init>(J)V

    .line 297
    .line 298
    .line 299
    new-instance v5, Llx0/l;

    .line 300
    .line 301
    invoke-direct {v5, v11, v14}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 302
    .line 303
    .line 304
    const/high16 v6, 0x3f800000    # 1.0f

    .line 305
    .line 306
    invoke-static {v6}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 307
    .line 308
    .line 309
    move-result-object v6

    .line 310
    new-instance v11, Le3/s;

    .line 311
    .line 312
    invoke-direct {v11, v9, v10}, Le3/s;-><init>(J)V

    .line 313
    .line 314
    .line 315
    new-instance v9, Llx0/l;

    .line 316
    .line 317
    invoke-direct {v9, v6, v11}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 318
    .line 319
    .line 320
    filled-new-array {v5, v9}, [Llx0/l;

    .line 321
    .line 322
    .line 323
    move-result-object v5

    .line 324
    const/4 v6, 0x2

    .line 325
    invoke-static {v5, v6}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 326
    .line 327
    .line 328
    move-result-object v5

    .line 329
    check-cast v5, [Llx0/l;

    .line 330
    .line 331
    invoke-static {v8}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 332
    .line 333
    .line 334
    move-result v6

    .line 335
    int-to-long v9, v6

    .line 336
    invoke-static/range {v26 .. v26}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 337
    .line 338
    .line 339
    move-result v6

    .line 340
    move-object v11, v1

    .line 341
    move v14, v2

    .line 342
    int-to-long v1, v6

    .line 343
    shl-long v9, v9, v17

    .line 344
    .line 345
    and-long v1, v1, v24

    .line 346
    .line 347
    or-long v30, v9, v1

    .line 348
    .line 349
    invoke-static {v3}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 350
    .line 351
    .line 352
    move-result v1

    .line 353
    int-to-long v1, v1

    .line 354
    invoke-static/range {v26 .. v26}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 355
    .line 356
    .line 357
    move-result v6

    .line 358
    int-to-long v9, v6

    .line 359
    shl-long v1, v1, v17

    .line 360
    .line 361
    and-long v9, v9, v24

    .line 362
    .line 363
    or-long v32, v1, v9

    .line 364
    .line 365
    array-length v1, v5

    .line 366
    new-instance v2, Ljava/util/ArrayList;

    .line 367
    .line 368
    invoke-direct {v2, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 369
    .line 370
    .line 371
    move/from16 v6, v22

    .line 372
    .line 373
    :goto_8
    if-ge v6, v1, :cond_9

    .line 374
    .line 375
    aget-object v9, v5, v6

    .line 376
    .line 377
    iget-object v9, v9, Llx0/l;->e:Ljava/lang/Object;

    .line 378
    .line 379
    check-cast v9, Le3/s;

    .line 380
    .line 381
    iget-wide v9, v9, Le3/s;->a:J

    .line 382
    .line 383
    move/from16 v27, v1

    .line 384
    .line 385
    new-instance v1, Le3/s;

    .line 386
    .line 387
    invoke-direct {v1, v9, v10}, Le3/s;-><init>(J)V

    .line 388
    .line 389
    .line 390
    invoke-virtual {v2, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 391
    .line 392
    .line 393
    add-int/lit8 v6, v6, 0x1

    .line 394
    .line 395
    move/from16 v1, v27

    .line 396
    .line 397
    goto :goto_8

    .line 398
    :cond_9
    array-length v1, v5

    .line 399
    new-instance v6, Ljava/util/ArrayList;

    .line 400
    .line 401
    invoke-direct {v6, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 402
    .line 403
    .line 404
    move/from16 v9, v22

    .line 405
    .line 406
    :goto_9
    if-ge v9, v1, :cond_a

    .line 407
    .line 408
    aget-object v10, v5, v9

    .line 409
    .line 410
    iget-object v10, v10, Llx0/l;->d:Ljava/lang/Object;

    .line 411
    .line 412
    check-cast v10, Ljava/lang/Number;

    .line 413
    .line 414
    invoke-virtual {v10}, Ljava/lang/Number;->floatValue()F

    .line 415
    .line 416
    .line 417
    move-result v10

    .line 418
    invoke-static {v10}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 419
    .line 420
    .line 421
    move-result-object v10

    .line 422
    invoke-virtual {v6, v10}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 423
    .line 424
    .line 425
    add-int/lit8 v9, v9, 0x1

    .line 426
    .line 427
    goto :goto_9

    .line 428
    :cond_a
    new-instance v27, Le3/b0;

    .line 429
    .line 430
    const/16 v34, 0x0

    .line 431
    .line 432
    move-object/from16 v28, v2

    .line 433
    .line 434
    move-object/from16 v29, v6

    .line 435
    .line 436
    invoke-direct/range {v27 .. v34}, Le3/b0;-><init>(Ljava/util/List;Ljava/util/ArrayList;JJI)V

    .line 437
    .line 438
    .line 439
    invoke-static/range {v26 .. v26}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 440
    .line 441
    .line 442
    move-result v1

    .line 443
    int-to-long v1, v1

    .line 444
    invoke-static/range {v18 .. v18}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 445
    .line 446
    .line 447
    move-result v5

    .line 448
    int-to-long v5, v5

    .line 449
    shl-long v1, v1, v17

    .line 450
    .line 451
    and-long v5, v5, v24

    .line 452
    .line 453
    or-long/2addr v1, v5

    .line 454
    invoke-static {v14}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 455
    .line 456
    .line 457
    move-result v5

    .line 458
    int-to-long v5, v5

    .line 459
    invoke-static/range {v18 .. v18}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 460
    .line 461
    .line 462
    move-result v9

    .line 463
    int-to-long v9, v9

    .line 464
    shl-long v5, v5, v17

    .line 465
    .line 466
    and-long v9, v9, v24

    .line 467
    .line 468
    or-long/2addr v5, v9

    .line 469
    xor-int/lit8 v9, v23, 0x1

    .line 470
    .line 471
    const/4 v10, 0x0

    .line 472
    move/from16 v22, v7

    .line 473
    .line 474
    move-wide v6, v5

    .line 475
    move/from16 v35, v8

    .line 476
    .line 477
    move v8, v4

    .line 478
    move-wide v4, v1

    .line 479
    move/from16 v2, v35

    .line 480
    .line 481
    move-object v1, v11

    .line 482
    const/16 v11, 0x1e0

    .line 483
    .line 484
    move/from16 v28, v2

    .line 485
    .line 486
    move/from16 v26, v3

    .line 487
    .line 488
    iget-wide v2, v0, Lxf0/r;->k:J

    .line 489
    .line 490
    move/from16 p1, v15

    .line 491
    .line 492
    move/from16 v15, v22

    .line 493
    .line 494
    move-object/from16 v22, v13

    .line 495
    .line 496
    move/from16 v13, v26

    .line 497
    .line 498
    move-object/from16 v26, v12

    .line 499
    .line 500
    move v12, v14

    .line 501
    move/from16 v14, v28

    .line 502
    .line 503
    invoke-static/range {v1 .. v11}, Lg3/d;->q(Lg3/d;JJJFILe3/j;I)V

    .line 504
    .line 505
    .line 506
    move v4, v8

    .line 507
    move v8, v9

    .line 508
    iget-boolean v2, v0, Lxf0/r;->m:Z

    .line 509
    .line 510
    if-nez v2, :cond_b

    .line 511
    .line 512
    if-eqz v21, :cond_f

    .line 513
    .line 514
    :cond_b
    if-eqz v21, :cond_c

    .line 515
    .line 516
    invoke-static {v14, v12}, Ljava/lang/Math;->min(FF)F

    .line 517
    .line 518
    .line 519
    move-result v2

    .line 520
    invoke-static {v2, v15}, Ljava/lang/Math;->max(FF)F

    .line 521
    .line 522
    .line 523
    move-result v2

    .line 524
    move v14, v2

    .line 525
    :cond_c
    if-eqz v21, :cond_d

    .line 526
    .line 527
    invoke-static {v13, v12}, Ljava/lang/Math;->min(FF)F

    .line 528
    .line 529
    .line 530
    move-result v2

    .line 531
    invoke-static {v2, v15}, Ljava/lang/Math;->max(FF)F

    .line 532
    .line 533
    .line 534
    move-result v2

    .line 535
    goto :goto_a

    .line 536
    :cond_d
    sub-float v3, v13, p1

    .line 537
    .line 538
    invoke-static {v3, v12}, Ljava/lang/Math;->min(FF)F

    .line 539
    .line 540
    .line 541
    move-result v2

    .line 542
    :goto_a
    invoke-static {v14}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 543
    .line 544
    .line 545
    move-result v3

    .line 546
    int-to-long v5, v3

    .line 547
    invoke-static/range {v18 .. v18}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 548
    .line 549
    .line 550
    move-result v3

    .line 551
    int-to-long v9, v3

    .line 552
    shl-long v5, v5, v17

    .line 553
    .line 554
    and-long v9, v9, v24

    .line 555
    .line 556
    or-long/2addr v5, v9

    .line 557
    invoke-static {v2}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 558
    .line 559
    .line 560
    move-result v2

    .line 561
    int-to-long v2, v2

    .line 562
    invoke-static/range {v18 .. v18}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 563
    .line 564
    .line 565
    move-result v7

    .line 566
    int-to-long v9, v7

    .line 567
    shl-long v2, v2, v17

    .line 568
    .line 569
    and-long v9, v9, v24

    .line 570
    .line 571
    or-long/2addr v2, v9

    .line 572
    const/4 v9, 0x0

    .line 573
    const/16 v10, 0xe0

    .line 574
    .line 575
    move v7, v4

    .line 576
    move-wide/from16 v35, v2

    .line 577
    .line 578
    move-object/from16 v2, v27

    .line 579
    .line 580
    move-wide v3, v5

    .line 581
    move-wide/from16 v5, v35

    .line 582
    .line 583
    invoke-static/range {v1 .. v10}, Lg3/d;->A0(Lg3/d;Le3/p;JJFIFI)V

    .line 584
    .line 585
    .line 586
    move v4, v7

    .line 587
    goto :goto_b

    .line 588
    :cond_e
    move-object/from16 v26, v12

    .line 589
    .line 590
    move-object/from16 v22, v13

    .line 591
    .line 592
    move/from16 p1, v15

    .line 593
    .line 594
    :cond_f
    :goto_b
    if-eqz v23, :cond_13

    .line 595
    .line 596
    move-object/from16 v2, v26

    .line 597
    .line 598
    iget v2, v2, Lgy0/h;->e:I

    .line 599
    .line 600
    const/16 v3, 0x50

    .line 601
    .line 602
    if-ge v3, v2, :cond_10

    .line 603
    .line 604
    const v2, 0x3f4ccccd    # 0.8f

    .line 605
    .line 606
    .line 607
    mul-float v5, v16, v2

    .line 608
    .line 609
    iget-wide v2, v0, Lxf0/r;->o:J

    .line 610
    .line 611
    move/from16 v8, p1

    .line 612
    .line 613
    move/from16 v6, v16

    .line 614
    .line 615
    move/from16 v7, v18

    .line 616
    .line 617
    invoke-static/range {v1 .. v8}, Lxf0/t;->b(Lg3/d;JFFFFF)V

    .line 618
    .line 619
    .line 620
    goto :goto_c

    .line 621
    :cond_10
    move/from16 v6, v16

    .line 622
    .line 623
    move/from16 v7, v18

    .line 624
    .line 625
    :goto_c
    iget-boolean v2, v0, Lxf0/r;->p:Z

    .line 626
    .line 627
    if-eqz v2, :cond_13

    .line 628
    .line 629
    if-eqz v22, :cond_11

    .line 630
    .line 631
    invoke-virtual/range {v22 .. v22}, Ljava/lang/Number;->intValue()I

    .line 632
    .line 633
    .line 634
    move-result v2

    .line 635
    const/16 v11, 0x14

    .line 636
    .line 637
    invoke-static {v2, v11}, Ljava/lang/Math;->max(II)I

    .line 638
    .line 639
    .line 640
    move-result v2

    .line 641
    goto :goto_d

    .line 642
    :cond_11
    const/16 v11, 0x14

    .line 643
    .line 644
    move v2, v11

    .line 645
    :goto_d
    int-to-float v3, v2

    .line 646
    div-float v3, v3, v20

    .line 647
    .line 648
    mul-float/2addr v3, v6

    .line 649
    iget v5, v0, Lxf0/r;->q:I

    .line 650
    .line 651
    if-le v5, v2, :cond_12

    .line 652
    .line 653
    iget-wide v5, v0, Lxf0/r;->s:J

    .line 654
    .line 655
    goto :goto_e

    .line 656
    :cond_12
    iget-wide v5, v0, Lxf0/r;->r:J

    .line 657
    .line 658
    :goto_e
    invoke-static {v3}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 659
    .line 660
    .line 661
    move-result v0

    .line 662
    int-to-long v8, v0

    .line 663
    invoke-static {v7}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 664
    .line 665
    .line 666
    move-result v0

    .line 667
    int-to-long v10, v0

    .line 668
    shl-long v8, v8, v17

    .line 669
    .line 670
    and-long v10, v10, v24

    .line 671
    .line 672
    or-long/2addr v8, v10

    .line 673
    const/high16 v0, 0x40800000    # 4.0f

    .line 674
    .line 675
    add-float/2addr v3, v0

    .line 676
    invoke-static {v3}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 677
    .line 678
    .line 679
    move-result v0

    .line 680
    int-to-long v2, v0

    .line 681
    invoke-static {v7}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 682
    .line 683
    .line 684
    move-result v0

    .line 685
    int-to-long v10, v0

    .line 686
    shl-long v2, v2, v17

    .line 687
    .line 688
    and-long v10, v10, v24

    .line 689
    .line 690
    or-long/2addr v2, v10

    .line 691
    move-object v0, v1

    .line 692
    move v7, v4

    .line 693
    move-wide/from16 v35, v5

    .line 694
    .line 695
    move-wide v5, v2

    .line 696
    move-wide/from16 v1, v35

    .line 697
    .line 698
    move-wide v3, v8

    .line 699
    const/4 v9, 0x0

    .line 700
    const/16 v10, 0x1e0

    .line 701
    .line 702
    const/4 v8, 0x0

    .line 703
    invoke-static/range {v0 .. v10}, Lg3/d;->q(Lg3/d;JJJFILe3/j;I)V

    .line 704
    .line 705
    .line 706
    :cond_13
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 707
    .line 708
    return-object v0
.end method
