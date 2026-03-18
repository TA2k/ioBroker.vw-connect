.class public final synthetic Lxf0/k;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Z

.field public final synthetic f:Lxf0/a1;

.field public final synthetic g:Lxf0/v0;

.field public final synthetic h:J

.field public final synthetic i:J

.field public final synthetic j:J


# direct methods
.method public synthetic constructor <init>(ZLxf0/a1;Lxf0/v0;JJJI)V
    .locals 0

    .line 1
    iput p10, p0, Lxf0/k;->d:I

    .line 2
    .line 3
    iput-boolean p1, p0, Lxf0/k;->e:Z

    .line 4
    .line 5
    iput-object p2, p0, Lxf0/k;->f:Lxf0/a1;

    .line 6
    .line 7
    iput-object p3, p0, Lxf0/k;->g:Lxf0/v0;

    .line 8
    .line 9
    iput-wide p4, p0, Lxf0/k;->h:J

    .line 10
    .line 11
    iput-wide p6, p0, Lxf0/k;->i:J

    .line 12
    .line 13
    iput-wide p8, p0, Lxf0/k;->j:J

    .line 14
    .line 15
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 16
    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 30

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lxf0/k;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    move-object/from16 v2, p1

    .line 9
    .line 10
    check-cast v2, Lg3/d;

    .line 11
    .line 12
    const-string v1, "$this$drawBaseGauge"

    .line 13
    .line 14
    invoke-static {v2, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    iget-boolean v1, v0, Lxf0/k;->e:Z

    .line 18
    .line 19
    if-eqz v1, :cond_2

    .line 20
    .line 21
    iget-object v1, v0, Lxf0/k;->f:Lxf0/a1;

    .line 22
    .line 23
    iget v3, v1, Lxf0/a1;->a:F

    .line 24
    .line 25
    const/4 v14, 0x2

    .line 26
    int-to-float v15, v14

    .line 27
    div-float/2addr v3, v15

    .line 28
    invoke-static {v3}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 29
    .line 30
    .line 31
    move-result v4

    .line 32
    int-to-long v4, v4

    .line 33
    invoke-static {v3}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 34
    .line 35
    .line 36
    move-result v3

    .line 37
    int-to-long v6, v3

    .line 38
    const/16 v16, 0x20

    .line 39
    .line 40
    shl-long v3, v4, v16

    .line 41
    .line 42
    const-wide v17, 0xffffffffL

    .line 43
    .line 44
    .line 45
    .line 46
    .line 47
    and-long v5, v6, v17

    .line 48
    .line 49
    or-long v7, v3, v5

    .line 50
    .line 51
    iget-object v3, v0, Lxf0/k;->g:Lxf0/v0;

    .line 52
    .line 53
    iget v4, v3, Lxf0/v0;->j:F

    .line 54
    .line 55
    mul-float/2addr v4, v15

    .line 56
    invoke-static {v4}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 57
    .line 58
    .line 59
    move-result v5

    .line 60
    int-to-long v5, v5

    .line 61
    invoke-static {v4}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 62
    .line 63
    .line 64
    move-result v4

    .line 65
    int-to-long v9, v4

    .line 66
    shl-long v4, v5, v16

    .line 67
    .line 68
    and-long v9, v9, v17

    .line 69
    .line 70
    or-long/2addr v9, v4

    .line 71
    iget v6, v3, Lxf0/v0;->d:F

    .line 72
    .line 73
    new-instance v19, Lg3/h;

    .line 74
    .line 75
    iget v4, v1, Lxf0/a1;->a:F

    .line 76
    .line 77
    const/16 v24, 0x0

    .line 78
    .line 79
    const/16 v25, 0x1a

    .line 80
    .line 81
    const/16 v21, 0x0

    .line 82
    .line 83
    const/16 v22, 0x0

    .line 84
    .line 85
    const/16 v23, 0x0

    .line 86
    .line 87
    move/from16 v20, v4

    .line 88
    .line 89
    invoke-direct/range {v19 .. v25}, Lg3/h;-><init>(FFIILe3/j;I)V

    .line 90
    .line 91
    .line 92
    const/4 v11, 0x0

    .line 93
    const/16 v13, 0x340

    .line 94
    .line 95
    move-object v5, v3

    .line 96
    iget-wide v3, v0, Lxf0/k;->i:J

    .line 97
    .line 98
    move-object v12, v5

    .line 99
    const/high16 v5, -0x3d4c0000    # -90.0f

    .line 100
    .line 101
    move-object v14, v12

    .line 102
    move-object/from16 v12, v19

    .line 103
    .line 104
    invoke-static/range {v2 .. v13}, Lg3/d;->o(Lg3/d;JFFJJFLg3/e;I)V

    .line 105
    .line 106
    .line 107
    iget v6, v14, Lxf0/v0;->c:F

    .line 108
    .line 109
    new-instance v19, Lg3/h;

    .line 110
    .line 111
    iget v3, v1, Lxf0/a1;->a:F

    .line 112
    .line 113
    move/from16 v20, v3

    .line 114
    .line 115
    invoke-direct/range {v19 .. v25}, Lg3/h;-><init>(FFIILe3/j;I)V

    .line 116
    .line 117
    .line 118
    iget-wide v3, v0, Lxf0/k;->h:J

    .line 119
    .line 120
    move-object/from16 v12, v19

    .line 121
    .line 122
    invoke-static/range {v2 .. v13}, Lg3/d;->o(Lg3/d;JFFJJFLg3/e;I)V

    .line 123
    .line 124
    .line 125
    iget v4, v14, Lxf0/v0;->e:F

    .line 126
    .line 127
    new-instance v19, Lg3/h;

    .line 128
    .line 129
    iget v1, v1, Lxf0/a1;->a:F

    .line 130
    .line 131
    move/from16 v20, v1

    .line 132
    .line 133
    invoke-direct/range {v19 .. v25}, Lg3/h;-><init>(FFIILe3/j;I)V

    .line 134
    .line 135
    .line 136
    const/4 v1, 0x3

    .line 137
    int-to-float v1, v1

    .line 138
    invoke-interface {v2, v1}, Lt4/c;->w0(F)F

    .line 139
    .line 140
    .line 141
    move-result v1

    .line 142
    mul-float/2addr v15, v1

    .line 143
    div-float/2addr v1, v15

    .line 144
    invoke-static {v1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 145
    .line 146
    .line 147
    move-result-object v3

    .line 148
    sget-wide v5, Le3/s;->h:J

    .line 149
    .line 150
    new-instance v11, Le3/s;

    .line 151
    .line 152
    invoke-direct {v11, v5, v6}, Le3/s;-><init>(J)V

    .line 153
    .line 154
    .line 155
    new-instance v5, Llx0/l;

    .line 156
    .line 157
    invoke-direct {v5, v3, v11}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 158
    .line 159
    .line 160
    invoke-static {v1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 161
    .line 162
    .line 163
    move-result-object v1

    .line 164
    new-instance v3, Le3/s;

    .line 165
    .line 166
    iget-wide v11, v0, Lxf0/k;->j:J

    .line 167
    .line 168
    invoke-direct {v3, v11, v12}, Le3/s;-><init>(J)V

    .line 169
    .line 170
    .line 171
    new-instance v0, Llx0/l;

    .line 172
    .line 173
    invoke-direct {v0, v1, v3}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 174
    .line 175
    .line 176
    filled-new-array {v5, v0}, [Llx0/l;

    .line 177
    .line 178
    .line 179
    move-result-object v0

    .line 180
    const/4 v1, 0x0

    .line 181
    invoke-static {v1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 182
    .line 183
    .line 184
    move-result v3

    .line 185
    int-to-long v5, v3

    .line 186
    invoke-static {v1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 187
    .line 188
    .line 189
    move-result v3

    .line 190
    int-to-long v11, v3

    .line 191
    shl-long v5, v5, v16

    .line 192
    .line 193
    and-long v11, v11, v17

    .line 194
    .line 195
    or-long v23, v5, v11

    .line 196
    .line 197
    invoke-static {v15}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 198
    .line 199
    .line 200
    move-result v3

    .line 201
    int-to-long v5, v3

    .line 202
    invoke-static {v1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 203
    .line 204
    .line 205
    move-result v1

    .line 206
    int-to-long v11, v1

    .line 207
    shl-long v5, v5, v16

    .line 208
    .line 209
    and-long v11, v11, v17

    .line 210
    .line 211
    or-long v25, v5, v11

    .line 212
    .line 213
    new-instance v1, Ljava/util/ArrayList;

    .line 214
    .line 215
    const/4 v3, 0x2

    .line 216
    invoke-direct {v1, v3}, Ljava/util/ArrayList;-><init>(I)V

    .line 217
    .line 218
    .line 219
    const/4 v5, 0x0

    .line 220
    move v6, v5

    .line 221
    :goto_0
    if-ge v6, v3, :cond_0

    .line 222
    .line 223
    aget-object v3, v0, v6

    .line 224
    .line 225
    iget-object v3, v3, Llx0/l;->e:Ljava/lang/Object;

    .line 226
    .line 227
    check-cast v3, Le3/s;

    .line 228
    .line 229
    iget-wide v11, v3, Le3/s;->a:J

    .line 230
    .line 231
    new-instance v3, Le3/s;

    .line 232
    .line 233
    invoke-direct {v3, v11, v12}, Le3/s;-><init>(J)V

    .line 234
    .line 235
    .line 236
    invoke-virtual {v1, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 237
    .line 238
    .line 239
    add-int/lit8 v6, v6, 0x1

    .line 240
    .line 241
    const/4 v3, 0x2

    .line 242
    goto :goto_0

    .line 243
    :cond_0
    new-instance v3, Ljava/util/ArrayList;

    .line 244
    .line 245
    const/4 v6, 0x2

    .line 246
    invoke-direct {v3, v6}, Ljava/util/ArrayList;-><init>(I)V

    .line 247
    .line 248
    .line 249
    :goto_1
    if-ge v5, v6, :cond_1

    .line 250
    .line 251
    aget-object v11, v0, v5

    .line 252
    .line 253
    iget-object v11, v11, Llx0/l;->d:Ljava/lang/Object;

    .line 254
    .line 255
    check-cast v11, Ljava/lang/Number;

    .line 256
    .line 257
    invoke-virtual {v11}, Ljava/lang/Number;->floatValue()F

    .line 258
    .line 259
    .line 260
    move-result v11

    .line 261
    invoke-static {v11}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 262
    .line 263
    .line 264
    move-result-object v11

    .line 265
    invoke-virtual {v3, v11}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 266
    .line 267
    .line 268
    add-int/lit8 v5, v5, 0x1

    .line 269
    .line 270
    goto :goto_1

    .line 271
    :cond_1
    new-instance v20, Le3/b0;

    .line 272
    .line 273
    const/16 v27, 0x1

    .line 274
    .line 275
    move-object/from16 v21, v1

    .line 276
    .line 277
    move-object/from16 v22, v3

    .line 278
    .line 279
    invoke-direct/range {v20 .. v27}, Le3/b0;-><init>(Ljava/util/List;Ljava/util/ArrayList;JJI)V

    .line 280
    .line 281
    .line 282
    move-wide v5, v7

    .line 283
    move-wide v7, v9

    .line 284
    move-object/from16 v9, v19

    .line 285
    .line 286
    move-object/from16 v3, v20

    .line 287
    .line 288
    invoke-interface/range {v2 .. v9}, Lg3/d;->Y(Le3/b0;FJJLg3/h;)V

    .line 289
    .line 290
    .line 291
    :cond_2
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 292
    .line 293
    return-object v0

    .line 294
    :pswitch_0
    move-object/from16 v1, p1

    .line 295
    .line 296
    check-cast v1, Lg3/d;

    .line 297
    .line 298
    const-string v2, "$this$drawBaseGauge"

    .line 299
    .line 300
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 301
    .line 302
    .line 303
    iget-boolean v2, v0, Lxf0/k;->e:Z

    .line 304
    .line 305
    if-eqz v2, :cond_5

    .line 306
    .line 307
    iget-object v13, v0, Lxf0/k;->f:Lxf0/a1;

    .line 308
    .line 309
    iget v2, v13, Lxf0/a1;->a:F

    .line 310
    .line 311
    const/4 v3, 0x2

    .line 312
    int-to-float v3, v3

    .line 313
    div-float/2addr v2, v3

    .line 314
    invoke-static {v2}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 315
    .line 316
    .line 317
    move-result v4

    .line 318
    int-to-long v4, v4

    .line 319
    invoke-static {v2}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 320
    .line 321
    .line 322
    move-result v2

    .line 323
    int-to-long v6, v2

    .line 324
    const/16 v2, 0x20

    .line 325
    .line 326
    shl-long/2addr v4, v2

    .line 327
    const-wide v8, 0xffffffffL

    .line 328
    .line 329
    .line 330
    .line 331
    .line 332
    and-long/2addr v6, v8

    .line 333
    or-long/2addr v6, v4

    .line 334
    iget-object v14, v0, Lxf0/k;->g:Lxf0/v0;

    .line 335
    .line 336
    iget v4, v14, Lxf0/v0;->j:F

    .line 337
    .line 338
    mul-float/2addr v4, v3

    .line 339
    invoke-static {v4}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 340
    .line 341
    .line 342
    move-result v5

    .line 343
    int-to-long v10, v5

    .line 344
    invoke-static {v4}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 345
    .line 346
    .line 347
    move-result v4

    .line 348
    int-to-long v4, v4

    .line 349
    shl-long/2addr v10, v2

    .line 350
    and-long/2addr v4, v8

    .line 351
    or-long v8, v10, v4

    .line 352
    .line 353
    iget v2, v13, Lxf0/a1;->a:F

    .line 354
    .line 355
    const/high16 v4, 0x40000000    # 2.0f

    .line 356
    .line 357
    div-float v4, v2, v4

    .line 358
    .line 359
    const/16 v5, 0x168

    .line 360
    .line 361
    int-to-float v5, v5

    .line 362
    mul-float/2addr v5, v4

    .line 363
    iget v4, v14, Lxf0/v0;->j:F

    .line 364
    .line 365
    float-to-double v10, v4

    .line 366
    const-wide v15, 0x401921fb54442d18L    # 6.283185307179586

    .line 367
    .line 368
    .line 369
    .line 370
    .line 371
    mul-double/2addr v10, v15

    .line 372
    double-to-float v4, v10

    .line 373
    div-float v22, v5, v4

    .line 374
    .line 375
    iget v10, v14, Lxf0/v0;->c:F

    .line 376
    .line 377
    mul-float v11, v22, v3

    .line 378
    .line 379
    cmpl-float v3, v10, v11

    .line 380
    .line 381
    iget-wide v4, v0, Lxf0/k;->h:J

    .line 382
    .line 383
    move-wide/from16 v23, v4

    .line 384
    .line 385
    move v5, v3

    .line 386
    iget-wide v3, v0, Lxf0/k;->i:J

    .line 387
    .line 388
    if-lez v5, :cond_4

    .line 389
    .line 390
    move/from16 v16, v2

    .line 391
    .line 392
    iget v2, v14, Lxf0/v0;->e:F

    .line 393
    .line 394
    new-instance v15, Lg3/h;

    .line 395
    .line 396
    const/16 v20, 0x0

    .line 397
    .line 398
    const/16 v21, 0x1a

    .line 399
    .line 400
    const/16 v17, 0x0

    .line 401
    .line 402
    const/16 v18, 0x0

    .line 403
    .line 404
    const/16 v19, 0x0

    .line 405
    .line 406
    invoke-direct/range {v15 .. v21}, Lg3/h;-><init>(FFIILe3/j;I)V

    .line 407
    .line 408
    .line 409
    move-wide v5, v6

    .line 410
    move-wide v7, v8

    .line 411
    move-object v9, v15

    .line 412
    invoke-static/range {v1 .. v9}, Lxf0/m;->c(Lg3/d;FJJJLg3/h;)V

    .line 413
    .line 414
    .line 415
    move-wide v8, v7

    .line 416
    move-wide v6, v5

    .line 417
    const/high16 v0, -0x3d4c0000    # -90.0f

    .line 418
    .line 419
    add-float v4, v22, v0

    .line 420
    .line 421
    const/high16 v0, 0x43b40000    # 360.0f

    .line 422
    .line 423
    cmpg-float v0, v10, v0

    .line 424
    .line 425
    if-nez v0, :cond_3

    .line 426
    .line 427
    :goto_2
    move v5, v10

    .line 428
    goto :goto_3

    .line 429
    :cond_3
    sub-float/2addr v10, v11

    .line 430
    goto :goto_2

    .line 431
    :goto_3
    new-instance v14, Lg3/h;

    .line 432
    .line 433
    iget v15, v13, Lxf0/a1;->a:F

    .line 434
    .line 435
    const/16 v19, 0x0

    .line 436
    .line 437
    const/16 v20, 0x1a

    .line 438
    .line 439
    const/16 v16, 0x0

    .line 440
    .line 441
    const/16 v17, 0x1

    .line 442
    .line 443
    const/16 v18, 0x0

    .line 444
    .line 445
    invoke-direct/range {v14 .. v20}, Lg3/h;-><init>(FFIILe3/j;I)V

    .line 446
    .line 447
    .line 448
    const/4 v10, 0x0

    .line 449
    const/16 v12, 0x340

    .line 450
    .line 451
    move-object v11, v14

    .line 452
    move-wide/from16 v2, v23

    .line 453
    .line 454
    invoke-static/range {v1 .. v12}, Lg3/d;->o(Lg3/d;JFFJJFLg3/e;I)V

    .line 455
    .line 456
    .line 457
    new-instance v14, Lg3/h;

    .line 458
    .line 459
    iget v15, v13, Lxf0/a1;->a:F

    .line 460
    .line 461
    const/16 v17, 0x0

    .line 462
    .line 463
    invoke-direct/range {v14 .. v20}, Lg3/h;-><init>(FFIILe3/j;I)V

    .line 464
    .line 465
    .line 466
    const/high16 v4, -0x3d4c0000    # -90.0f

    .line 467
    .line 468
    move-object v11, v14

    .line 469
    move/from16 v5, v22

    .line 470
    .line 471
    invoke-static/range {v1 .. v12}, Lg3/d;->o(Lg3/d;JFFJJFLg3/e;I)V

    .line 472
    .line 473
    .line 474
    goto :goto_4

    .line 475
    :cond_4
    move/from16 v16, v2

    .line 476
    .line 477
    move-wide/from16 v28, v23

    .line 478
    .line 479
    move-wide/from16 v23, v3

    .line 480
    .line 481
    move-wide/from16 v2, v28

    .line 482
    .line 483
    const/16 v4, 0xb4

    .line 484
    .line 485
    int-to-float v4, v4

    .line 486
    const/16 v5, 0x5a

    .line 487
    .line 488
    int-to-float v5, v5

    .line 489
    sub-float v10, v22, v10

    .line 490
    .line 491
    add-float/2addr v10, v5

    .line 492
    sub-float/2addr v4, v10

    .line 493
    new-instance v15, Lg3/h;

    .line 494
    .line 495
    const/16 v20, 0x0

    .line 496
    .line 497
    const/16 v21, 0x1a

    .line 498
    .line 499
    const/16 v17, 0x0

    .line 500
    .line 501
    const/16 v18, 0x1

    .line 502
    .line 503
    const/16 v19, 0x0

    .line 504
    .line 505
    invoke-direct/range {v15 .. v21}, Lg3/h;-><init>(FFIILe3/j;I)V

    .line 506
    .line 507
    .line 508
    const/4 v10, 0x0

    .line 509
    const/16 v12, 0x340

    .line 510
    .line 511
    move v11, v5

    .line 512
    move v5, v4

    .line 513
    const/high16 v4, -0x3ccc0000    # -180.0f

    .line 514
    .line 515
    move-object/from16 v28, v15

    .line 516
    .line 517
    move v15, v11

    .line 518
    move-object/from16 v11, v28

    .line 519
    .line 520
    invoke-static/range {v1 .. v12}, Lg3/d;->o(Lg3/d;JFFJJFLg3/e;I)V

    .line 521
    .line 522
    .line 523
    const/16 v2, -0xb4

    .line 524
    .line 525
    int-to-float v2, v2

    .line 526
    sub-float v4, v2, v22

    .line 527
    .line 528
    add-float v5, v15, v22

    .line 529
    .line 530
    new-instance v15, Lg3/h;

    .line 531
    .line 532
    iget v2, v13, Lxf0/a1;->a:F

    .line 533
    .line 534
    const/16 v18, 0x0

    .line 535
    .line 536
    move/from16 v16, v2

    .line 537
    .line 538
    invoke-direct/range {v15 .. v21}, Lg3/h;-><init>(FFIILe3/j;I)V

    .line 539
    .line 540
    .line 541
    iget-wide v2, v0, Lxf0/k;->j:J

    .line 542
    .line 543
    move-object v11, v15

    .line 544
    invoke-static/range {v1 .. v12}, Lg3/d;->o(Lg3/d;JFFJJFLg3/e;I)V

    .line 545
    .line 546
    .line 547
    iget v2, v14, Lxf0/v0;->e:F

    .line 548
    .line 549
    new-instance v14, Lg3/h;

    .line 550
    .line 551
    iget v15, v13, Lxf0/a1;->a:F

    .line 552
    .line 553
    const/16 v19, 0x0

    .line 554
    .line 555
    const/16 v20, 0x1a

    .line 556
    .line 557
    const/16 v16, 0x0

    .line 558
    .line 559
    const/16 v17, 0x0

    .line 560
    .line 561
    invoke-direct/range {v14 .. v20}, Lg3/h;-><init>(FFIILe3/j;I)V

    .line 562
    .line 563
    .line 564
    move-wide v5, v6

    .line 565
    move-wide v7, v8

    .line 566
    move-object v9, v14

    .line 567
    move-wide/from16 v3, v23

    .line 568
    .line 569
    invoke-static/range {v1 .. v9}, Lxf0/m;->c(Lg3/d;FJJJLg3/h;)V

    .line 570
    .line 571
    .line 572
    :cond_5
    :goto_4
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 573
    .line 574
    return-object v0

    .line 575
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
