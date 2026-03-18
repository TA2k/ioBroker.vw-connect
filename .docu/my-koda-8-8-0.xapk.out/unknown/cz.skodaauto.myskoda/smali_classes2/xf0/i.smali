.class public final synthetic Lxf0/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:Z

.field public final synthetic e:Z

.field public final synthetic f:Z

.field public final synthetic g:J

.field public final synthetic h:J

.field public final synthetic i:J

.field public final synthetic j:J

.field public final synthetic k:J

.field public final synthetic l:J

.field public final synthetic m:J

.field public final synthetic n:J

.field public final synthetic o:Z

.field public final synthetic p:Lxf0/v0;

.field public final synthetic q:Lxf0/a1;


# direct methods
.method public synthetic constructor <init>(ZZZJJJJJJJJZLxf0/v0;Lxf0/a1;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-boolean p1, p0, Lxf0/i;->d:Z

    .line 5
    .line 6
    iput-boolean p2, p0, Lxf0/i;->e:Z

    .line 7
    .line 8
    iput-boolean p3, p0, Lxf0/i;->f:Z

    .line 9
    .line 10
    iput-wide p4, p0, Lxf0/i;->g:J

    .line 11
    .line 12
    iput-wide p6, p0, Lxf0/i;->h:J

    .line 13
    .line 14
    iput-wide p8, p0, Lxf0/i;->i:J

    .line 15
    .line 16
    iput-wide p10, p0, Lxf0/i;->j:J

    .line 17
    .line 18
    iput-wide p12, p0, Lxf0/i;->k:J

    .line 19
    .line 20
    iput-wide p14, p0, Lxf0/i;->l:J

    .line 21
    .line 22
    move-wide/from16 p1, p16

    .line 23
    .line 24
    iput-wide p1, p0, Lxf0/i;->m:J

    .line 25
    .line 26
    move-wide/from16 p1, p18

    .line 27
    .line 28
    iput-wide p1, p0, Lxf0/i;->n:J

    .line 29
    .line 30
    move/from16 p1, p20

    .line 31
    .line 32
    iput-boolean p1, p0, Lxf0/i;->o:Z

    .line 33
    .line 34
    move-object/from16 p1, p21

    .line 35
    .line 36
    iput-object p1, p0, Lxf0/i;->p:Lxf0/v0;

    .line 37
    .line 38
    move-object/from16 p1, p22

    .line 39
    .line 40
    iput-object p1, p0, Lxf0/i;->q:Lxf0/a1;

    .line 41
    .line 42
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 31

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
    const-string v2, "$this$drawBehind"

    .line 8
    .line 9
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    invoke-interface {v1}, Lg3/d;->e()J

    .line 13
    .line 14
    .line 15
    move-result-wide v2

    .line 16
    invoke-static {v2, v3}, Ld3/e;->c(J)F

    .line 17
    .line 18
    .line 19
    move-result v2

    .line 20
    const/high16 v3, 0x40000000    # 2.0f

    .line 21
    .line 22
    div-float/2addr v2, v3

    .line 23
    iget-object v9, v0, Lxf0/i;->q:Lxf0/a1;

    .line 24
    .line 25
    iget v15, v9, Lxf0/a1;->a:F

    .line 26
    .line 27
    const/4 v4, 0x2

    .line 28
    int-to-float v10, v4

    .line 29
    div-float v4, v15, v10

    .line 30
    .line 31
    sub-float/2addr v2, v4

    .line 32
    add-float/2addr v4, v2

    .line 33
    iget v5, v9, Lxf0/a1;->b:F

    .line 34
    .line 35
    mul-float v6, v5, v10

    .line 36
    .line 37
    sub-float/2addr v4, v6

    .line 38
    div-float v16, v5, v10

    .line 39
    .line 40
    sub-float v4, v4, v16

    .line 41
    .line 42
    iget-object v11, v0, Lxf0/i;->p:Lxf0/v0;

    .line 43
    .line 44
    iput v4, v11, Lxf0/v0;->i:F

    .line 45
    .line 46
    iput v2, v11, Lxf0/v0;->j:F

    .line 47
    .line 48
    invoke-interface {v1}, Lg3/d;->e()J

    .line 49
    .line 50
    .line 51
    move-result-wide v4

    .line 52
    invoke-static {v4, v5}, Ld3/e;->c(J)F

    .line 53
    .line 54
    .line 55
    move-result v2

    .line 56
    div-float v4, v2, v3

    .line 57
    .line 58
    iget-boolean v2, v0, Lxf0/i;->e:Z

    .line 59
    .line 60
    iget-boolean v12, v0, Lxf0/i;->f:Z

    .line 61
    .line 62
    if-eqz v2, :cond_0

    .line 63
    .line 64
    if-eqz v12, :cond_0

    .line 65
    .line 66
    new-instance v17, Lg3/h;

    .line 67
    .line 68
    iget v2, v9, Lxf0/a1;->c:F

    .line 69
    .line 70
    const/16 v22, 0x0

    .line 71
    .line 72
    const/16 v23, 0x1e

    .line 73
    .line 74
    const/16 v19, 0x0

    .line 75
    .line 76
    const/16 v20, 0x0

    .line 77
    .line 78
    const/16 v21, 0x0

    .line 79
    .line 80
    move/from16 v18, v2

    .line 81
    .line 82
    invoke-direct/range {v17 .. v23}, Lg3/h;-><init>(FFIILe3/j;I)V

    .line 83
    .line 84
    .line 85
    const-wide/16 v5, 0x0

    .line 86
    .line 87
    const/16 v8, 0x6c

    .line 88
    .line 89
    iget-wide v2, v0, Lxf0/i;->g:J

    .line 90
    .line 91
    move-object/from16 v7, v17

    .line 92
    .line 93
    invoke-static/range {v1 .. v8}, Lg3/d;->u0(Lg3/d;JFJLg3/e;I)V

    .line 94
    .line 95
    .line 96
    :cond_0
    new-instance v4, Lxf0/k;

    .line 97
    .line 98
    const/4 v14, 0x0

    .line 99
    move-object v6, v9

    .line 100
    iget-wide v8, v0, Lxf0/i;->i:J

    .line 101
    .line 102
    move v2, v10

    .line 103
    move-object v7, v11

    .line 104
    iget-wide v10, v0, Lxf0/i;->j:J

    .line 105
    .line 106
    move v5, v12

    .line 107
    iget-wide v12, v0, Lxf0/i;->h:J

    .line 108
    .line 109
    move/from16 v17, v2

    .line 110
    .line 111
    invoke-direct/range {v4 .. v14}, Lxf0/k;-><init>(ZLxf0/a1;Lxf0/v0;JJJI)V

    .line 112
    .line 113
    .line 114
    move-object v9, v4

    .line 115
    move-wide v2, v12

    .line 116
    move-object v13, v6

    .line 117
    move-object v12, v7

    .line 118
    new-instance v18, Lg3/h;

    .line 119
    .line 120
    iget v4, v13, Lxf0/a1;->a:F

    .line 121
    .line 122
    const/16 v23, 0x0

    .line 123
    .line 124
    const/16 v24, 0x1e

    .line 125
    .line 126
    const/16 v20, 0x0

    .line 127
    .line 128
    const/16 v21, 0x0

    .line 129
    .line 130
    const/16 v22, 0x0

    .line 131
    .line 132
    move/from16 v19, v4

    .line 133
    .line 134
    invoke-direct/range {v18 .. v24}, Lg3/h;-><init>(FFIILe3/j;I)V

    .line 135
    .line 136
    .line 137
    iget v4, v12, Lxf0/v0;->j:F

    .line 138
    .line 139
    iget-object v14, v12, Lxf0/v0;->b:Ljava/lang/Integer;

    .line 140
    .line 141
    const-wide/16 v5, 0x0

    .line 142
    .line 143
    const/16 v8, 0x6c

    .line 144
    .line 145
    move-object/from16 v7, v18

    .line 146
    .line 147
    invoke-static/range {v1 .. v8}, Lg3/d;->u0(Lg3/d;JFJLg3/e;I)V

    .line 148
    .line 149
    .line 150
    invoke-virtual {v9, v1}, Lxf0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 151
    .line 152
    .line 153
    new-instance v2, Lg3/h;

    .line 154
    .line 155
    iget v3, v13, Lxf0/a1;->b:F

    .line 156
    .line 157
    const/4 v7, 0x0

    .line 158
    const/16 v8, 0x1e

    .line 159
    .line 160
    const/4 v4, 0x0

    .line 161
    const/4 v5, 0x0

    .line 162
    const/4 v6, 0x0

    .line 163
    invoke-direct/range {v2 .. v8}, Lg3/h;-><init>(FFIILe3/j;I)V

    .line 164
    .line 165
    .line 166
    iget v4, v12, Lxf0/v0;->i:F

    .line 167
    .line 168
    const-wide/16 v5, 0x0

    .line 169
    .line 170
    const/16 v8, 0x6c

    .line 171
    .line 172
    move-object v7, v2

    .line 173
    iget-wide v2, v0, Lxf0/i;->k:J

    .line 174
    .line 175
    invoke-static/range {v1 .. v8}, Lg3/d;->u0(Lg3/d;JFJLg3/e;I)V

    .line 176
    .line 177
    .line 178
    iget-boolean v2, v0, Lxf0/i;->d:Z

    .line 179
    .line 180
    const/16 v18, 0x20

    .line 181
    .line 182
    const-wide v19, 0xffffffffL

    .line 183
    .line 184
    .line 185
    .line 186
    .line 187
    if-nez v2, :cond_2

    .line 188
    .line 189
    iget v2, v12, Lxf0/v0;->i:F

    .line 190
    .line 191
    const/4 v3, 0x3

    .line 192
    int-to-float v3, v3

    .line 193
    invoke-interface {v1, v3}, Lt4/c;->w0(F)F

    .line 194
    .line 195
    .line 196
    move-result v8

    .line 197
    iget-boolean v3, v0, Lxf0/i;->o:Z

    .line 198
    .line 199
    if-eqz v3, :cond_1

    .line 200
    .line 201
    const/16 v3, 0xa

    .line 202
    .line 203
    goto :goto_0

    .line 204
    :cond_1
    const/16 v3, 0x14

    .line 205
    .line 206
    :goto_0
    const/4 v4, 0x0

    .line 207
    :goto_1
    if-ge v4, v3, :cond_2

    .line 208
    .line 209
    invoke-interface {v1}, Lg3/d;->e()J

    .line 210
    .line 211
    .line 212
    move-result-wide v5

    .line 213
    invoke-static {v5, v6}, Ljp/ef;->d(J)J

    .line 214
    .line 215
    .line 216
    move-result-wide v5

    .line 217
    shr-long v5, v5, v18

    .line 218
    .line 219
    long-to-int v5, v5

    .line 220
    invoke-static {v5}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 221
    .line 222
    .line 223
    move-result v5

    .line 224
    float-to-double v5, v5

    .line 225
    add-float v7, v2, v16

    .line 226
    .line 227
    float-to-double v9, v7

    .line 228
    const-wide v21, 0x401921fb54442d18L    # 6.283185307179586

    .line 229
    .line 230
    .line 231
    .line 232
    .line 233
    move-object v7, v1

    .line 234
    move v11, v2

    .line 235
    int-to-double v1, v4

    .line 236
    mul-double v1, v1, v21

    .line 237
    .line 238
    move-wide/from16 v21, v1

    .line 239
    .line 240
    int-to-double v1, v3

    .line 241
    div-double v1, v21, v1

    .line 242
    .line 243
    invoke-static {v1, v2}, Ljava/lang/Math;->sin(D)D

    .line 244
    .line 245
    .line 246
    move-result-wide v21

    .line 247
    mul-double v21, v21, v9

    .line 248
    .line 249
    add-double v5, v21, v5

    .line 250
    .line 251
    invoke-interface {v7}, Lg3/d;->e()J

    .line 252
    .line 253
    .line 254
    move-result-wide v21

    .line 255
    invoke-static/range {v21 .. v22}, Ljp/ef;->d(J)J

    .line 256
    .line 257
    .line 258
    move-result-wide v21

    .line 259
    move-wide/from16 v23, v1

    .line 260
    .line 261
    and-long v1, v21, v19

    .line 262
    .line 263
    long-to-int v1, v1

    .line 264
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 265
    .line 266
    .line 267
    move-result v1

    .line 268
    float-to-double v1, v1

    .line 269
    invoke-static/range {v23 .. v24}, Ljava/lang/Math;->cos(D)D

    .line 270
    .line 271
    .line 272
    move-result-wide v21

    .line 273
    mul-double v21, v21, v9

    .line 274
    .line 275
    add-double v1, v21, v1

    .line 276
    .line 277
    invoke-interface {v7}, Lg3/d;->e()J

    .line 278
    .line 279
    .line 280
    move-result-wide v9

    .line 281
    invoke-static {v9, v10}, Ljp/ef;->d(J)J

    .line 282
    .line 283
    .line 284
    move-result-wide v9

    .line 285
    shr-long v9, v9, v18

    .line 286
    .line 287
    long-to-int v9, v9

    .line 288
    invoke-static {v9}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 289
    .line 290
    .line 291
    move-result v9

    .line 292
    float-to-double v9, v9

    .line 293
    move/from16 v21, v3

    .line 294
    .line 295
    sub-float v3, v11, v16

    .line 296
    .line 297
    move/from16 v22, v4

    .line 298
    .line 299
    float-to-double v3, v3

    .line 300
    invoke-static/range {v23 .. v24}, Ljava/lang/Math;->sin(D)D

    .line 301
    .line 302
    .line 303
    move-result-wide v25

    .line 304
    mul-double v25, v25, v3

    .line 305
    .line 306
    add-double v9, v25, v9

    .line 307
    .line 308
    invoke-interface {v7}, Lg3/d;->e()J

    .line 309
    .line 310
    .line 311
    move-result-wide v25

    .line 312
    invoke-static/range {v25 .. v26}, Ljp/ef;->d(J)J

    .line 313
    .line 314
    .line 315
    move-result-wide v25

    .line 316
    move-wide/from16 v27, v3

    .line 317
    .line 318
    and-long v3, v25, v19

    .line 319
    .line 320
    long-to-int v3, v3

    .line 321
    invoke-static {v3}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 322
    .line 323
    .line 324
    move-result v3

    .line 325
    float-to-double v3, v3

    .line 326
    invoke-static/range {v23 .. v24}, Ljava/lang/Math;->cos(D)D

    .line 327
    .line 328
    .line 329
    move-result-wide v23

    .line 330
    mul-double v23, v23, v27

    .line 331
    .line 332
    add-double v3, v23, v3

    .line 333
    .line 334
    double-to-float v5, v5

    .line 335
    double-to-float v1, v1

    .line 336
    invoke-static {v5}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 337
    .line 338
    .line 339
    move-result v2

    .line 340
    int-to-long v5, v2

    .line 341
    invoke-static {v1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 342
    .line 343
    .line 344
    move-result v1

    .line 345
    int-to-long v1, v1

    .line 346
    shl-long v5, v5, v18

    .line 347
    .line 348
    and-long v1, v1, v19

    .line 349
    .line 350
    or-long/2addr v1, v5

    .line 351
    double-to-float v5, v9

    .line 352
    double-to-float v3, v3

    .line 353
    invoke-static {v5}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 354
    .line 355
    .line 356
    move-result v4

    .line 357
    int-to-long v4, v4

    .line 358
    invoke-static {v3}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 359
    .line 360
    .line 361
    move-result v3

    .line 362
    int-to-long v9, v3

    .line 363
    shl-long v3, v4, v18

    .line 364
    .line 365
    and-long v5, v9, v19

    .line 366
    .line 367
    or-long/2addr v3, v5

    .line 368
    const/4 v10, 0x0

    .line 369
    move v5, v11

    .line 370
    const/16 v11, 0x1f0

    .line 371
    .line 372
    move-object v9, v7

    .line 373
    move-wide v6, v3

    .line 374
    move-wide/from16 v29, v1

    .line 375
    .line 376
    move v1, v5

    .line 377
    move-wide/from16 v4, v29

    .line 378
    .line 379
    iget-wide v2, v0, Lxf0/i;->l:J

    .line 380
    .line 381
    move/from16 v23, v1

    .line 382
    .line 383
    move-object v1, v9

    .line 384
    const/4 v9, 0x0

    .line 385
    invoke-static/range {v1 .. v11}, Lg3/d;->q(Lg3/d;JJJFILe3/j;I)V

    .line 386
    .line 387
    .line 388
    add-int/lit8 v4, v22, 0x1

    .line 389
    .line 390
    move/from16 v3, v21

    .line 391
    .line 392
    move/from16 v2, v23

    .line 393
    .line 394
    goto/16 :goto_1

    .line 395
    .line 396
    :cond_2
    if-eqz v14, :cond_4

    .line 397
    .line 398
    iget v2, v12, Lxf0/v0;->a:I

    .line 399
    .line 400
    invoke-virtual {v14}, Ljava/lang/Integer;->intValue()I

    .line 401
    .line 402
    .line 403
    move-result v3

    .line 404
    if-le v2, v3, :cond_3

    .line 405
    .line 406
    iget-wide v2, v0, Lxf0/i;->n:J

    .line 407
    .line 408
    goto :goto_2

    .line 409
    :cond_3
    iget-wide v2, v0, Lxf0/i;->m:J

    .line 410
    .line 411
    :goto_2
    invoke-virtual {v14}, Ljava/lang/Integer;->intValue()I

    .line 412
    .line 413
    .line 414
    move-result v0

    .line 415
    iget v4, v12, Lxf0/v0;->i:F

    .line 416
    .line 417
    sub-float v4, v4, v16

    .line 418
    .line 419
    iget v5, v12, Lxf0/v0;->j:F

    .line 420
    .line 421
    div-float v15, v15, v17

    .line 422
    .line 423
    add-float/2addr v15, v5

    .line 424
    iget v7, v13, Lxf0/a1;->e:F

    .line 425
    .line 426
    const/16 v5, 0x168

    .line 427
    .line 428
    int-to-float v5, v5

    .line 429
    int-to-float v0, v0

    .line 430
    const/high16 v6, 0x42c80000    # 100.0f

    .line 431
    .line 432
    div-float/2addr v0, v6

    .line 433
    mul-float/2addr v0, v5

    .line 434
    invoke-interface {v1}, Lg3/d;->e()J

    .line 435
    .line 436
    .line 437
    move-result-wide v5

    .line 438
    invoke-static {v5, v6}, Ljp/ef;->d(J)J

    .line 439
    .line 440
    .line 441
    move-result-wide v5

    .line 442
    shr-long v5, v5, v18

    .line 443
    .line 444
    long-to-int v5, v5

    .line 445
    invoke-static {v5}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 446
    .line 447
    .line 448
    move-result v5

    .line 449
    float-to-double v8, v0

    .line 450
    const-wide v10, 0x4056800000000000L    # 90.0

    .line 451
    .line 452
    .line 453
    .line 454
    .line 455
    sub-double/2addr v8, v10

    .line 456
    invoke-static {v8, v9}, Ljava/lang/Math;->toRadians(D)D

    .line 457
    .line 458
    .line 459
    move-result-wide v10

    .line 460
    double-to-float v0, v10

    .line 461
    float-to-double v10, v0

    .line 462
    invoke-static {v10, v11}, Ljava/lang/Math;->cos(D)D

    .line 463
    .line 464
    .line 465
    move-result-wide v10

    .line 466
    double-to-float v0, v10

    .line 467
    mul-float/2addr v0, v15

    .line 468
    add-float/2addr v0, v5

    .line 469
    invoke-interface {v1}, Lg3/d;->e()J

    .line 470
    .line 471
    .line 472
    move-result-wide v5

    .line 473
    invoke-static {v5, v6}, Ljp/ef;->d(J)J

    .line 474
    .line 475
    .line 476
    move-result-wide v5

    .line 477
    and-long v5, v5, v19

    .line 478
    .line 479
    long-to-int v5, v5

    .line 480
    invoke-static {v5}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 481
    .line 482
    .line 483
    move-result v5

    .line 484
    invoke-static {v8, v9}, Ljava/lang/Math;->toRadians(D)D

    .line 485
    .line 486
    .line 487
    move-result-wide v10

    .line 488
    double-to-float v6, v10

    .line 489
    float-to-double v10, v6

    .line 490
    invoke-static {v10, v11}, Ljava/lang/Math;->sin(D)D

    .line 491
    .line 492
    .line 493
    move-result-wide v10

    .line 494
    double-to-float v6, v10

    .line 495
    mul-float/2addr v15, v6

    .line 496
    add-float/2addr v15, v5

    .line 497
    invoke-interface {v1}, Lg3/d;->e()J

    .line 498
    .line 499
    .line 500
    move-result-wide v5

    .line 501
    invoke-static {v5, v6}, Ljp/ef;->d(J)J

    .line 502
    .line 503
    .line 504
    move-result-wide v5

    .line 505
    shr-long v5, v5, v18

    .line 506
    .line 507
    long-to-int v5, v5

    .line 508
    invoke-static {v5}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 509
    .line 510
    .line 511
    move-result v5

    .line 512
    invoke-static {v8, v9}, Ljava/lang/Math;->toRadians(D)D

    .line 513
    .line 514
    .line 515
    move-result-wide v10

    .line 516
    double-to-float v6, v10

    .line 517
    float-to-double v10, v6

    .line 518
    invoke-static {v10, v11}, Ljava/lang/Math;->cos(D)D

    .line 519
    .line 520
    .line 521
    move-result-wide v10

    .line 522
    double-to-float v6, v10

    .line 523
    mul-float/2addr v6, v4

    .line 524
    add-float/2addr v6, v5

    .line 525
    invoke-interface {v1}, Lg3/d;->e()J

    .line 526
    .line 527
    .line 528
    move-result-wide v10

    .line 529
    invoke-static {v10, v11}, Ljp/ef;->d(J)J

    .line 530
    .line 531
    .line 532
    move-result-wide v10

    .line 533
    and-long v10, v10, v19

    .line 534
    .line 535
    long-to-int v5, v10

    .line 536
    invoke-static {v5}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 537
    .line 538
    .line 539
    move-result v5

    .line 540
    invoke-static {v8, v9}, Ljava/lang/Math;->toRadians(D)D

    .line 541
    .line 542
    .line 543
    move-result-wide v8

    .line 544
    double-to-float v8, v8

    .line 545
    float-to-double v8, v8

    .line 546
    invoke-static {v8, v9}, Ljava/lang/Math;->sin(D)D

    .line 547
    .line 548
    .line 549
    move-result-wide v8

    .line 550
    double-to-float v8, v8

    .line 551
    mul-float/2addr v4, v8

    .line 552
    add-float/2addr v4, v5

    .line 553
    invoke-static {v0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 554
    .line 555
    .line 556
    move-result v0

    .line 557
    int-to-long v8, v0

    .line 558
    invoke-static {v15}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 559
    .line 560
    .line 561
    move-result v0

    .line 562
    int-to-long v10, v0

    .line 563
    shl-long v8, v8, v18

    .line 564
    .line 565
    and-long v10, v10, v19

    .line 566
    .line 567
    or-long/2addr v8, v10

    .line 568
    invoke-static {v6}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 569
    .line 570
    .line 571
    move-result v0

    .line 572
    int-to-long v5, v0

    .line 573
    invoke-static {v4}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 574
    .line 575
    .line 576
    move-result v0

    .line 577
    int-to-long v10, v0

    .line 578
    shl-long v4, v5, v18

    .line 579
    .line 580
    and-long v10, v10, v19

    .line 581
    .line 582
    or-long v5, v4, v10

    .line 583
    .line 584
    move-object v0, v1

    .line 585
    move-wide v1, v2

    .line 586
    move-wide v3, v8

    .line 587
    const/4 v9, 0x0

    .line 588
    const/16 v10, 0x1f0

    .line 589
    .line 590
    const/4 v8, 0x0

    .line 591
    invoke-static/range {v0 .. v10}, Lg3/d;->q(Lg3/d;JJJFILe3/j;I)V

    .line 592
    .line 593
    .line 594
    :cond_4
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 595
    .line 596
    return-object v0
.end method
