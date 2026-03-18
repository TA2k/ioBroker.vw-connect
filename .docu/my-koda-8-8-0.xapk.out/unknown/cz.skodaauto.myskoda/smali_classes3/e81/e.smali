.class public final synthetic Le81/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:J


# direct methods
.method public synthetic constructor <init>(JI)V
    .locals 0

    .line 1
    iput p3, p0, Le81/e;->d:I

    iput-wide p1, p0, Le81/e;->e:J

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(JLjava/lang/Object;I)V
    .locals 0

    .line 2
    iput p4, p0, Le81/e;->d:I

    iput-wide p1, p0, Le81/e;->e:J

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 86

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Le81/e;->d:I

    .line 4
    .line 5
    const-string v2, "Expected NON-NULL \'java.time.LocalTime\', but it was NULL."

    .line 6
    .line 7
    const-string v3, "enabled"

    .line 8
    .line 9
    const-string v4, "profile_id"

    .line 10
    .line 11
    const/4 v5, 0x5

    .line 12
    const-string v6, "$this$drawWithCache"

    .line 13
    .line 14
    const/4 v7, 0x0

    .line 15
    const-string v8, "$this$Canvas"

    .line 16
    .line 17
    const-string v10, "$this$drawBehind"

    .line 18
    .line 19
    const-string v11, "id"

    .line 20
    .line 21
    const-string v12, "_connection"

    .line 22
    .line 23
    const/4 v13, 0x1

    .line 24
    const/4 v9, 0x2

    .line 25
    const/16 v18, 0x20

    .line 26
    .line 27
    sget-object v19, Llx0/b0;->a:Llx0/b0;

    .line 28
    .line 29
    const/16 v20, 0x0

    .line 30
    .line 31
    const-wide v21, 0xffffffffL

    .line 32
    .line 33
    .line 34
    .line 35
    .line 36
    iget-wide v14, v0, Le81/e;->e:J

    .line 37
    .line 38
    packed-switch v1, :pswitch_data_0

    .line 39
    .line 40
    .line 41
    move-object/from16 v1, p1

    .line 42
    .line 43
    check-cast v1, Lg3/d;

    .line 44
    .line 45
    invoke-static {v1, v8}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    invoke-static {}, Le3/l;->a()Le3/i;

    .line 49
    .line 50
    .line 51
    move-result-object v2

    .line 52
    invoke-interface {v1}, Lg3/d;->e()J

    .line 53
    .line 54
    .line 55
    move-result-wide v3

    .line 56
    shr-long v3, v3, v18

    .line 57
    .line 58
    long-to-int v3, v3

    .line 59
    invoke-static {v3}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 60
    .line 61
    .line 62
    move-result v3

    .line 63
    int-to-float v4, v9

    .line 64
    div-float/2addr v3, v4

    .line 65
    invoke-interface {v1}, Lg3/d;->e()J

    .line 66
    .line 67
    .line 68
    move-result-wide v4

    .line 69
    and-long v4, v4, v21

    .line 70
    .line 71
    long-to-int v4, v4

    .line 72
    invoke-static {v4}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 73
    .line 74
    .line 75
    move-result v4

    .line 76
    invoke-virtual {v2, v3, v4}, Le3/i;->h(FF)V

    .line 77
    .line 78
    .line 79
    invoke-interface {v1}, Lg3/d;->e()J

    .line 80
    .line 81
    .line 82
    move-result-wide v3

    .line 83
    shr-long v3, v3, v18

    .line 84
    .line 85
    long-to-int v3, v3

    .line 86
    invoke-static {v3}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 87
    .line 88
    .line 89
    move-result v3

    .line 90
    invoke-virtual {v2, v3, v7}, Le3/i;->g(FF)V

    .line 91
    .line 92
    .line 93
    invoke-virtual {v2, v7, v7}, Le3/i;->g(FF)V

    .line 94
    .line 95
    .line 96
    invoke-virtual {v2}, Le3/i;->e()V

    .line 97
    .line 98
    .line 99
    const/16 v28, 0x0

    .line 100
    .line 101
    const/16 v29, 0x3c

    .line 102
    .line 103
    iget-wide v3, v0, Le81/e;->e:J

    .line 104
    .line 105
    const/16 v27, 0x0

    .line 106
    .line 107
    move-object/from16 v23, v1

    .line 108
    .line 109
    move-object/from16 v24, v2

    .line 110
    .line 111
    move-wide/from16 v25, v3

    .line 112
    .line 113
    invoke-static/range {v23 .. v29}, Lg3/d;->K0(Lg3/d;Le3/i;JFLg3/e;I)V

    .line 114
    .line 115
    .line 116
    return-object v19

    .line 117
    :pswitch_0
    move-object/from16 v0, p1

    .line 118
    .line 119
    check-cast v0, Lg3/d;

    .line 120
    .line 121
    invoke-static {v0, v10}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 122
    .line 123
    .line 124
    invoke-interface {v0}, Lg3/d;->x0()Lgw0/c;

    .line 125
    .line 126
    .line 127
    move-result-object v1

    .line 128
    invoke-virtual {v1}, Lgw0/c;->h()Le3/r;

    .line 129
    .line 130
    .line 131
    move-result-object v23

    .line 132
    int-to-float v1, v9

    .line 133
    invoke-static {}, Le3/j0;->h()Le3/g;

    .line 134
    .line 135
    .line 136
    move-result-object v2

    .line 137
    iget-object v3, v2, Le3/g;->a:Landroid/graphics/Paint;

    .line 138
    .line 139
    new-instance v4, Landroid/graphics/BlurMaskFilter;

    .line 140
    .line 141
    invoke-interface {v0, v1}, Lt4/c;->w0(F)F

    .line 142
    .line 143
    .line 144
    move-result v1

    .line 145
    sget-object v5, Landroid/graphics/BlurMaskFilter$Blur;->NORMAL:Landroid/graphics/BlurMaskFilter$Blur;

    .line 146
    .line 147
    invoke-direct {v4, v1, v5}, Landroid/graphics/BlurMaskFilter;-><init>(FLandroid/graphics/BlurMaskFilter$Blur;)V

    .line 148
    .line 149
    .line 150
    invoke-virtual {v3, v4}, Landroid/graphics/Paint;->setMaskFilter(Landroid/graphics/MaskFilter;)Landroid/graphics/MaskFilter;

    .line 151
    .line 152
    .line 153
    invoke-static {v14, v15}, Le3/j0;->z(J)I

    .line 154
    .line 155
    .line 156
    move-result v1

    .line 157
    invoke-virtual {v3, v1}, Landroid/graphics/Paint;->setColor(I)V

    .line 158
    .line 159
    .line 160
    invoke-interface {v0}, Lg3/d;->e()J

    .line 161
    .line 162
    .line 163
    move-result-wide v3

    .line 164
    shr-long v3, v3, v18

    .line 165
    .line 166
    long-to-int v1, v3

    .line 167
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 168
    .line 169
    .line 170
    move-result v26

    .line 171
    invoke-interface {v0}, Lg3/d;->e()J

    .line 172
    .line 173
    .line 174
    move-result-wide v0

    .line 175
    and-long v0, v0, v21

    .line 176
    .line 177
    long-to-int v0, v0

    .line 178
    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 179
    .line 180
    .line 181
    move-result v27

    .line 182
    invoke-virtual/range {v23 .. v23}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 183
    .line 184
    .line 185
    const/16 v24, 0x0

    .line 186
    .line 187
    const/16 v25, 0x0

    .line 188
    .line 189
    const/high16 v28, 0x42960000    # 75.0f

    .line 190
    .line 191
    const/high16 v29, 0x42d20000    # 105.0f

    .line 192
    .line 193
    move-object/from16 v30, v2

    .line 194
    .line 195
    invoke-interface/range {v23 .. v30}, Le3/r;->j(FFFFFFLe3/g;)V

    .line 196
    .line 197
    .line 198
    return-object v19

    .line 199
    :pswitch_1
    invoke-static {v14, v15}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 200
    .line 201
    .line 202
    move-result-object v0

    .line 203
    return-object v0

    .line 204
    :pswitch_2
    move-object/from16 v1, p1

    .line 205
    .line 206
    check-cast v1, Lv3/j0;

    .line 207
    .line 208
    const-string v2, "$this$onDrawWithContent"

    .line 209
    .line 210
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 211
    .line 212
    .line 213
    invoke-virtual {v1}, Lv3/j0;->b()V

    .line 214
    .line 215
    .line 216
    new-instance v10, Lg3/h;

    .line 217
    .line 218
    int-to-float v2, v9

    .line 219
    invoke-virtual {v1, v2}, Lv3/j0;->w0(F)F

    .line 220
    .line 221
    .line 222
    move-result v11

    .line 223
    const/4 v15, 0x0

    .line 224
    const/16 v16, 0x1e

    .line 225
    .line 226
    const/4 v12, 0x0

    .line 227
    const/4 v13, 0x0

    .line 228
    const/4 v14, 0x0

    .line 229
    invoke-direct/range {v10 .. v16}, Lg3/h;-><init>(FFIILe3/j;I)V

    .line 230
    .line 231
    .line 232
    const/4 v2, 0x4

    .line 233
    int-to-float v2, v2

    .line 234
    invoke-virtual {v1, v2}, Lv3/j0;->w0(F)F

    .line 235
    .line 236
    .line 237
    move-result v2

    .line 238
    invoke-static {v2}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 239
    .line 240
    .line 241
    move-result v3

    .line 242
    int-to-long v3, v3

    .line 243
    invoke-static {v2}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 244
    .line 245
    .line 246
    move-result v2

    .line 247
    int-to-long v5, v2

    .line 248
    shl-long v2, v3, v18

    .line 249
    .line 250
    and-long v4, v5, v21

    .line 251
    .line 252
    or-long v8, v2, v4

    .line 253
    .line 254
    const-wide/16 v6, 0x0

    .line 255
    .line 256
    const/16 v11, 0xe6

    .line 257
    .line 258
    iget-wide v2, v0, Le81/e;->e:J

    .line 259
    .line 260
    const-wide/16 v4, 0x0

    .line 261
    .line 262
    invoke-static/range {v1 .. v11}, Lg3/d;->j0(Lg3/d;JJJJLg3/e;I)V

    .line 263
    .line 264
    .line 265
    return-object v19

    .line 266
    :pswitch_3
    move-object/from16 v12, p1

    .line 267
    .line 268
    check-cast v12, Lg3/d;

    .line 269
    .line 270
    const-string v1, "$this$onDrawBehind"

    .line 271
    .line 272
    invoke-static {v12, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 273
    .line 274
    .line 275
    invoke-static {}, Le3/l;->a()Le3/i;

    .line 276
    .line 277
    .line 278
    move-result-object v13

    .line 279
    invoke-interface {v12}, Lg3/d;->e()J

    .line 280
    .line 281
    .line 282
    move-result-wide v1

    .line 283
    shr-long v1, v1, v18

    .line 284
    .line 285
    long-to-int v1, v1

    .line 286
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 287
    .line 288
    .line 289
    move-result v1

    .line 290
    const v2, 0x3f19999a    # 0.6f

    .line 291
    .line 292
    .line 293
    mul-float/2addr v1, v2

    .line 294
    invoke-virtual {v13, v1, v7}, Le3/i;->h(FF)V

    .line 295
    .line 296
    .line 297
    invoke-interface {v12}, Lg3/d;->e()J

    .line 298
    .line 299
    .line 300
    move-result-wide v1

    .line 301
    shr-long v1, v1, v18

    .line 302
    .line 303
    long-to-int v1, v1

    .line 304
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 305
    .line 306
    .line 307
    move-result v1

    .line 308
    invoke-virtual {v13, v1, v7}, Le3/i;->g(FF)V

    .line 309
    .line 310
    .line 311
    invoke-interface {v12}, Lg3/d;->e()J

    .line 312
    .line 313
    .line 314
    move-result-wide v1

    .line 315
    shr-long v1, v1, v18

    .line 316
    .line 317
    long-to-int v1, v1

    .line 318
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 319
    .line 320
    .line 321
    move-result v1

    .line 322
    const/high16 v2, 0x44200000    # 640.0f

    .line 323
    .line 324
    invoke-virtual {v13, v1, v2}, Le3/i;->g(FF)V

    .line 325
    .line 326
    .line 327
    const/16 v17, 0x0

    .line 328
    .line 329
    const/16 v18, 0x3c

    .line 330
    .line 331
    iget-wide v14, v0, Le81/e;->e:J

    .line 332
    .line 333
    const/16 v16, 0x0

    .line 334
    .line 335
    invoke-static/range {v12 .. v18}, Lg3/d;->K0(Lg3/d;Le3/i;JFLg3/e;I)V

    .line 336
    .line 337
    .line 338
    return-object v19

    .line 339
    :pswitch_4
    move-object/from16 v0, p1

    .line 340
    .line 341
    check-cast v0, Lb3/d;

    .line 342
    .line 343
    invoke-static {v0, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 344
    .line 345
    .line 346
    new-instance v1, Le81/e;

    .line 347
    .line 348
    const/16 v2, 0xe

    .line 349
    .line 350
    invoke-direct {v1, v14, v15, v2}, Le81/e;-><init>(JI)V

    .line 351
    .line 352
    .line 353
    invoke-virtual {v0, v1}, Lb3/d;->b(Lay0/k;)Lb3/g;

    .line 354
    .line 355
    .line 356
    move-result-object v0

    .line 357
    return-object v0

    .line 358
    :pswitch_5
    move-object/from16 v0, p1

    .line 359
    .line 360
    check-cast v0, Lb3/d;

    .line 361
    .line 362
    invoke-static {v0, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 363
    .line 364
    .line 365
    new-instance v1, Le81/e;

    .line 366
    .line 367
    const/16 v2, 0xd

    .line 368
    .line 369
    invoke-direct {v1, v14, v15, v2}, Le81/e;-><init>(JI)V

    .line 370
    .line 371
    .line 372
    new-instance v2, Law/o;

    .line 373
    .line 374
    invoke-direct {v2, v5, v1}, Law/o;-><init>(ILay0/k;)V

    .line 375
    .line 376
    .line 377
    invoke-virtual {v0, v2}, Lb3/d;->b(Lay0/k;)Lb3/g;

    .line 378
    .line 379
    .line 380
    move-result-object v0

    .line 381
    return-object v0

    .line 382
    :pswitch_6
    move-object/from16 v1, p1

    .line 383
    .line 384
    check-cast v1, Ld4/l;

    .line 385
    .line 386
    sget-object v2, Le2/d0;->c:Ld4/z;

    .line 387
    .line 388
    new-instance v3, Le2/c0;

    .line 389
    .line 390
    sget-object v4, Lt1/b0;->d:Lt1/b0;

    .line 391
    .line 392
    sget-object v7, Le2/b0;->e:Le2/b0;

    .line 393
    .line 394
    const/4 v8, 0x1

    .line 395
    iget-wide v5, v0, Le81/e;->e:J

    .line 396
    .line 397
    invoke-direct/range {v3 .. v8}, Le2/c0;-><init>(Lt1/b0;JLe2/b0;Z)V

    .line 398
    .line 399
    .line 400
    invoke-virtual {v1, v2, v3}, Ld4/l;->i(Ld4/z;Ljava/lang/Object;)V

    .line 401
    .line 402
    .line 403
    return-object v19

    .line 404
    :pswitch_7
    move-object/from16 v0, p1

    .line 405
    .line 406
    check-cast v0, Lb3/d;

    .line 407
    .line 408
    iget-object v1, v0, Lb3/d;->d:Lb3/b;

    .line 409
    .line 410
    invoke-interface {v1}, Lb3/b;->e()J

    .line 411
    .line 412
    .line 413
    move-result-wide v1

    .line 414
    shr-long v1, v1, v18

    .line 415
    .line 416
    long-to-int v1, v1

    .line 417
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 418
    .line 419
    .line 420
    move-result v1

    .line 421
    const/high16 v2, 0x40000000    # 2.0f

    .line 422
    .line 423
    div-float/2addr v1, v2

    .line 424
    invoke-static {v0, v1}, Lkp/o;->d(Lb3/d;F)Le3/f;

    .line 425
    .line 426
    .line 427
    move-result-object v2

    .line 428
    new-instance v3, Le3/m;

    .line 429
    .line 430
    invoke-direct {v3, v14, v15, v5}, Le3/m;-><init>(JI)V

    .line 431
    .line 432
    .line 433
    new-instance v4, Lg1/j3;

    .line 434
    .line 435
    const/4 v5, 0x3

    .line 436
    invoke-direct {v4, v1, v2, v3, v5}, Lg1/j3;-><init>(FLjava/lang/Object;Ljava/lang/Object;I)V

    .line 437
    .line 438
    .line 439
    invoke-virtual {v0, v4}, Lb3/d;->b(Lay0/k;)Lb3/g;

    .line 440
    .line 441
    .line 442
    move-result-object v0

    .line 443
    return-object v0

    .line 444
    :pswitch_8
    move-object/from16 v0, p1

    .line 445
    .line 446
    check-cast v0, Lua/a;

    .line 447
    .line 448
    invoke-static {v0, v12}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 449
    .line 450
    .line 451
    const-string v1, "SELECT * FROM charging_profile_timer WHERE profile_id = ?"

    .line 452
    .line 453
    invoke-interface {v0, v1}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 454
    .line 455
    .line 456
    move-result-object v1

    .line 457
    :try_start_0
    invoke-interface {v1, v13, v14, v15}, Lua/c;->bindLong(IJ)V

    .line 458
    .line 459
    .line 460
    invoke-static {v1, v11}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 461
    .line 462
    .line 463
    move-result v0

    .line 464
    invoke-static {v1, v4}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 465
    .line 466
    .line 467
    move-result v4

    .line 468
    invoke-static {v1, v3}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 469
    .line 470
    .line 471
    move-result v3

    .line 472
    const-string v5, "time"

    .line 473
    .line 474
    invoke-static {v1, v5}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 475
    .line 476
    .line 477
    move-result v5

    .line 478
    const-string v6, "type"

    .line 479
    .line 480
    invoke-static {v1, v6}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 481
    .line 482
    .line 483
    move-result v6

    .line 484
    const-string v7, "days"

    .line 485
    .line 486
    invoke-static {v1, v7}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 487
    .line 488
    .line 489
    move-result v7

    .line 490
    const-string v8, "start_air_condition"

    .line 491
    .line 492
    invoke-static {v1, v8}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 493
    .line 494
    .line 495
    move-result v8

    .line 496
    new-instance v9, Ljava/util/ArrayList;

    .line 497
    .line 498
    invoke-direct {v9}, Ljava/util/ArrayList;-><init>()V

    .line 499
    .line 500
    .line 501
    :goto_0
    invoke-interface {v1}, Lua/c;->s0()Z

    .line 502
    .line 503
    .line 504
    move-result v10

    .line 505
    if-eqz v10, :cond_4

    .line 506
    .line 507
    invoke-interface {v1, v0}, Lua/c;->getLong(I)J

    .line 508
    .line 509
    .line 510
    move-result-wide v22

    .line 511
    invoke-interface {v1, v4}, Lua/c;->getLong(I)J

    .line 512
    .line 513
    .line 514
    move-result-wide v24

    .line 515
    invoke-interface {v1, v3}, Lua/c;->getLong(I)J

    .line 516
    .line 517
    .line 518
    move-result-wide v10

    .line 519
    long-to-int v10, v10

    .line 520
    if-eqz v10, :cond_0

    .line 521
    .line 522
    move/from16 v26, v13

    .line 523
    .line 524
    goto :goto_1

    .line 525
    :cond_0
    const/16 v26, 0x0

    .line 526
    .line 527
    :goto_1
    invoke-interface {v1, v5}, Lua/c;->isNull(I)Z

    .line 528
    .line 529
    .line 530
    move-result v10

    .line 531
    if-eqz v10, :cond_1

    .line 532
    .line 533
    move-object/from16 v10, v20

    .line 534
    .line 535
    goto :goto_2

    .line 536
    :cond_1
    invoke-interface {v1, v5}, Lua/c;->g0(I)Ljava/lang/String;

    .line 537
    .line 538
    .line 539
    move-result-object v10

    .line 540
    :goto_2
    invoke-static {v10}, Lwq/f;->m(Ljava/lang/String;)Ljava/time/LocalTime;

    .line 541
    .line 542
    .line 543
    move-result-object v27

    .line 544
    if-eqz v27, :cond_3

    .line 545
    .line 546
    invoke-interface {v1, v6}, Lua/c;->g0(I)Ljava/lang/String;

    .line 547
    .line 548
    .line 549
    move-result-object v28

    .line 550
    invoke-interface {v1, v7}, Lua/c;->g0(I)Ljava/lang/String;

    .line 551
    .line 552
    .line 553
    move-result-object v29

    .line 554
    invoke-interface {v1, v8}, Lua/c;->getLong(I)J

    .line 555
    .line 556
    .line 557
    move-result-wide v10

    .line 558
    long-to-int v10, v10

    .line 559
    if-eqz v10, :cond_2

    .line 560
    .line 561
    move/from16 v30, v13

    .line 562
    .line 563
    goto :goto_3

    .line 564
    :cond_2
    const/16 v30, 0x0

    .line 565
    .line 566
    :goto_3
    new-instance v21, Lod0/p;

    .line 567
    .line 568
    invoke-direct/range {v21 .. v30}, Lod0/p;-><init>(JJZLjava/time/LocalTime;Ljava/lang/String;Ljava/lang/String;Z)V

    .line 569
    .line 570
    .line 571
    move-object/from16 v10, v21

    .line 572
    .line 573
    invoke-virtual {v9, v10}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 574
    .line 575
    .line 576
    goto :goto_0

    .line 577
    :catchall_0
    move-exception v0

    .line 578
    goto :goto_4

    .line 579
    :cond_3
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 580
    .line 581
    invoke-direct {v0, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 582
    .line 583
    .line 584
    throw v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 585
    :cond_4
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 586
    .line 587
    .line 588
    return-object v9

    .line 589
    :goto_4
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 590
    .line 591
    .line 592
    throw v0

    .line 593
    :pswitch_9
    move-object/from16 v0, p1

    .line 594
    .line 595
    check-cast v0, Lua/a;

    .line 596
    .line 597
    invoke-static {v0, v12}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 598
    .line 599
    .line 600
    const-string v1, "SELECT * FROM charging_profile_charging_time WHERE profile_id = ?"

    .line 601
    .line 602
    invoke-interface {v0, v1}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 603
    .line 604
    .line 605
    move-result-object v1

    .line 606
    :try_start_1
    invoke-interface {v1, v13, v14, v15}, Lua/c;->bindLong(IJ)V

    .line 607
    .line 608
    .line 609
    invoke-static {v1, v11}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 610
    .line 611
    .line 612
    move-result v0

    .line 613
    invoke-static {v1, v4}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 614
    .line 615
    .line 616
    move-result v4

    .line 617
    invoke-static {v1, v3}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 618
    .line 619
    .line 620
    move-result v3

    .line 621
    const-string v5, "start_time"

    .line 622
    .line 623
    invoke-static {v1, v5}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 624
    .line 625
    .line 626
    move-result v5

    .line 627
    const-string v6, "end_time"

    .line 628
    .line 629
    invoke-static {v1, v6}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 630
    .line 631
    .line 632
    move-result v6

    .line 633
    new-instance v7, Ljava/util/ArrayList;

    .line 634
    .line 635
    invoke-direct {v7}, Ljava/util/ArrayList;-><init>()V

    .line 636
    .line 637
    .line 638
    :goto_5
    invoke-interface {v1}, Lua/c;->s0()Z

    .line 639
    .line 640
    .line 641
    move-result v8

    .line 642
    if-eqz v8, :cond_a

    .line 643
    .line 644
    invoke-interface {v1, v0}, Lua/c;->getLong(I)J

    .line 645
    .line 646
    .line 647
    move-result-wide v22

    .line 648
    invoke-interface {v1, v4}, Lua/c;->getLong(I)J

    .line 649
    .line 650
    .line 651
    move-result-wide v24

    .line 652
    invoke-interface {v1, v3}, Lua/c;->getLong(I)J

    .line 653
    .line 654
    .line 655
    move-result-wide v8

    .line 656
    long-to-int v8, v8

    .line 657
    if-eqz v8, :cond_5

    .line 658
    .line 659
    move/from16 v26, v13

    .line 660
    .line 661
    goto :goto_6

    .line 662
    :cond_5
    const/16 v26, 0x0

    .line 663
    .line 664
    :goto_6
    invoke-interface {v1, v5}, Lua/c;->isNull(I)Z

    .line 665
    .line 666
    .line 667
    move-result v8

    .line 668
    if-eqz v8, :cond_6

    .line 669
    .line 670
    move-object/from16 v8, v20

    .line 671
    .line 672
    goto :goto_7

    .line 673
    :cond_6
    invoke-interface {v1, v5}, Lua/c;->g0(I)Ljava/lang/String;

    .line 674
    .line 675
    .line 676
    move-result-object v8

    .line 677
    :goto_7
    invoke-static {v8}, Lwq/f;->m(Ljava/lang/String;)Ljava/time/LocalTime;

    .line 678
    .line 679
    .line 680
    move-result-object v27

    .line 681
    if-eqz v27, :cond_9

    .line 682
    .line 683
    invoke-interface {v1, v6}, Lua/c;->isNull(I)Z

    .line 684
    .line 685
    .line 686
    move-result v8

    .line 687
    if-eqz v8, :cond_7

    .line 688
    .line 689
    move-object/from16 v8, v20

    .line 690
    .line 691
    goto :goto_8

    .line 692
    :cond_7
    invoke-interface {v1, v6}, Lua/c;->g0(I)Ljava/lang/String;

    .line 693
    .line 694
    .line 695
    move-result-object v8

    .line 696
    :goto_8
    invoke-static {v8}, Lwq/f;->m(Ljava/lang/String;)Ljava/time/LocalTime;

    .line 697
    .line 698
    .line 699
    move-result-object v28

    .line 700
    if-eqz v28, :cond_8

    .line 701
    .line 702
    new-instance v21, Lod0/j;

    .line 703
    .line 704
    invoke-direct/range {v21 .. v28}, Lod0/j;-><init>(JJZLjava/time/LocalTime;Ljava/time/LocalTime;)V

    .line 705
    .line 706
    .line 707
    move-object/from16 v8, v21

    .line 708
    .line 709
    invoke-virtual {v7, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 710
    .line 711
    .line 712
    goto :goto_5

    .line 713
    :catchall_1
    move-exception v0

    .line 714
    goto :goto_9

    .line 715
    :cond_8
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 716
    .line 717
    invoke-direct {v0, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 718
    .line 719
    .line 720
    throw v0

    .line 721
    :cond_9
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 722
    .line 723
    invoke-direct {v0, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 724
    .line 725
    .line 726
    throw v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 727
    :cond_a
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 728
    .line 729
    .line 730
    return-object v7

    .line 731
    :goto_9
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 732
    .line 733
    .line 734
    throw v0

    .line 735
    :pswitch_a
    move-object/from16 v0, p1

    .line 736
    .line 737
    check-cast v0, Lg3/d;

    .line 738
    .line 739
    invoke-static {v0, v10}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 740
    .line 741
    .line 742
    invoke-interface {v0}, Lg3/d;->x0()Lgw0/c;

    .line 743
    .line 744
    .line 745
    move-result-object v1

    .line 746
    invoke-virtual {v1}, Lgw0/c;->h()Le3/r;

    .line 747
    .line 748
    .line 749
    move-result-object v23

    .line 750
    int-to-float v1, v9

    .line 751
    invoke-static {}, Le3/j0;->h()Le3/g;

    .line 752
    .line 753
    .line 754
    move-result-object v2

    .line 755
    iget-object v3, v2, Le3/g;->a:Landroid/graphics/Paint;

    .line 756
    .line 757
    new-instance v4, Landroid/graphics/BlurMaskFilter;

    .line 758
    .line 759
    invoke-interface {v0, v1}, Lt4/c;->w0(F)F

    .line 760
    .line 761
    .line 762
    move-result v1

    .line 763
    sget-object v5, Landroid/graphics/BlurMaskFilter$Blur;->NORMAL:Landroid/graphics/BlurMaskFilter$Blur;

    .line 764
    .line 765
    invoke-direct {v4, v1, v5}, Landroid/graphics/BlurMaskFilter;-><init>(FLandroid/graphics/BlurMaskFilter$Blur;)V

    .line 766
    .line 767
    .line 768
    invoke-virtual {v3, v4}, Landroid/graphics/Paint;->setMaskFilter(Landroid/graphics/MaskFilter;)Landroid/graphics/MaskFilter;

    .line 769
    .line 770
    .line 771
    invoke-static {v14, v15}, Le3/j0;->z(J)I

    .line 772
    .line 773
    .line 774
    move-result v1

    .line 775
    invoke-virtual {v3, v1}, Landroid/graphics/Paint;->setColor(I)V

    .line 776
    .line 777
    .line 778
    invoke-interface {v0}, Lg3/d;->e()J

    .line 779
    .line 780
    .line 781
    move-result-wide v3

    .line 782
    shr-long v3, v3, v18

    .line 783
    .line 784
    long-to-int v1, v3

    .line 785
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 786
    .line 787
    .line 788
    move-result v26

    .line 789
    invoke-interface {v0}, Lg3/d;->e()J

    .line 790
    .line 791
    .line 792
    move-result-wide v0

    .line 793
    and-long v0, v0, v21

    .line 794
    .line 795
    long-to-int v0, v0

    .line 796
    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 797
    .line 798
    .line 799
    move-result v27

    .line 800
    invoke-virtual/range {v23 .. v23}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 801
    .line 802
    .line 803
    const/16 v24, 0x0

    .line 804
    .line 805
    const/16 v25, 0x0

    .line 806
    .line 807
    const/high16 v28, 0x42960000    # 75.0f

    .line 808
    .line 809
    const/high16 v29, 0x42d20000    # 105.0f

    .line 810
    .line 811
    move-object/from16 v30, v2

    .line 812
    .line 813
    invoke-interface/range {v23 .. v30}, Le3/r;->j(FFFFFFLe3/g;)V

    .line 814
    .line 815
    .line 816
    return-object v19

    .line 817
    :pswitch_b
    move-object/from16 v0, p1

    .line 818
    .line 819
    check-cast v0, Lua/a;

    .line 820
    .line 821
    invoke-static {v0, v12}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 822
    .line 823
    .line 824
    const-string v1, "SELECT * FROM workspec WHERE last_enqueue_time >= ? AND state IN (2, 3, 5) ORDER BY last_enqueue_time DESC"

    .line 825
    .line 826
    invoke-interface {v0, v1}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 827
    .line 828
    .line 829
    move-result-object v1

    .line 830
    :try_start_2
    invoke-interface {v1, v13, v14, v15}, Lua/c;->bindLong(IJ)V

    .line 831
    .line 832
    .line 833
    invoke-static {v1, v11}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 834
    .line 835
    .line 836
    move-result v0

    .line 837
    const-string v2, "state"

    .line 838
    .line 839
    invoke-static {v1, v2}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 840
    .line 841
    .line 842
    move-result v2

    .line 843
    const-string v3, "worker_class_name"

    .line 844
    .line 845
    invoke-static {v1, v3}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 846
    .line 847
    .line 848
    move-result v3

    .line 849
    const-string v4, "input_merger_class_name"

    .line 850
    .line 851
    invoke-static {v1, v4}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 852
    .line 853
    .line 854
    move-result v4

    .line 855
    const-string v5, "input"

    .line 856
    .line 857
    invoke-static {v1, v5}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 858
    .line 859
    .line 860
    move-result v5

    .line 861
    const-string v6, "output"

    .line 862
    .line 863
    invoke-static {v1, v6}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 864
    .line 865
    .line 866
    move-result v6

    .line 867
    const-string v7, "initial_delay"

    .line 868
    .line 869
    invoke-static {v1, v7}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 870
    .line 871
    .line 872
    move-result v7

    .line 873
    const-string v8, "interval_duration"

    .line 874
    .line 875
    invoke-static {v1, v8}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 876
    .line 877
    .line 878
    move-result v8

    .line 879
    const-string v9, "flex_duration"

    .line 880
    .line 881
    invoke-static {v1, v9}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 882
    .line 883
    .line 884
    move-result v9

    .line 885
    const-string v10, "run_attempt_count"

    .line 886
    .line 887
    invoke-static {v1, v10}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 888
    .line 889
    .line 890
    move-result v10

    .line 891
    const-string v11, "backoff_policy"

    .line 892
    .line 893
    invoke-static {v1, v11}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 894
    .line 895
    .line 896
    move-result v11

    .line 897
    const-string v12, "backoff_delay_duration"

    .line 898
    .line 899
    invoke-static {v1, v12}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 900
    .line 901
    .line 902
    move-result v12

    .line 903
    const-string v14, "last_enqueue_time"

    .line 904
    .line 905
    invoke-static {v1, v14}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 906
    .line 907
    .line 908
    move-result v14

    .line 909
    const-string v15, "minimum_retention_duration"

    .line 910
    .line 911
    invoke-static {v1, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 912
    .line 913
    .line 914
    move-result v15

    .line 915
    const-string v13, "schedule_requested_at"

    .line 916
    .line 917
    invoke-static {v1, v13}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 918
    .line 919
    .line 920
    move-result v13

    .line 921
    move/from16 p0, v13

    .line 922
    .line 923
    const-string v13, "run_in_foreground"

    .line 924
    .line 925
    invoke-static {v1, v13}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 926
    .line 927
    .line 928
    move-result v13

    .line 929
    move/from16 p1, v13

    .line 930
    .line 931
    const-string v13, "out_of_quota_policy"

    .line 932
    .line 933
    invoke-static {v1, v13}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 934
    .line 935
    .line 936
    move-result v13

    .line 937
    move/from16 v18, v13

    .line 938
    .line 939
    const-string v13, "period_count"

    .line 940
    .line 941
    invoke-static {v1, v13}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 942
    .line 943
    .line 944
    move-result v13

    .line 945
    move/from16 v19, v13

    .line 946
    .line 947
    const-string v13, "generation"

    .line 948
    .line 949
    invoke-static {v1, v13}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 950
    .line 951
    .line 952
    move-result v13

    .line 953
    move/from16 v21, v13

    .line 954
    .line 955
    const-string v13, "next_schedule_time_override"

    .line 956
    .line 957
    invoke-static {v1, v13}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 958
    .line 959
    .line 960
    move-result v13

    .line 961
    move/from16 v22, v13

    .line 962
    .line 963
    const-string v13, "next_schedule_time_override_generation"

    .line 964
    .line 965
    invoke-static {v1, v13}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 966
    .line 967
    .line 968
    move-result v13

    .line 969
    move/from16 v23, v13

    .line 970
    .line 971
    const-string v13, "stop_reason"

    .line 972
    .line 973
    invoke-static {v1, v13}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 974
    .line 975
    .line 976
    move-result v13

    .line 977
    move/from16 v24, v13

    .line 978
    .line 979
    const-string v13, "trace_tag"

    .line 980
    .line 981
    invoke-static {v1, v13}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 982
    .line 983
    .line 984
    move-result v13

    .line 985
    move/from16 v25, v13

    .line 986
    .line 987
    const-string v13, "backoff_on_system_interruptions"

    .line 988
    .line 989
    invoke-static {v1, v13}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 990
    .line 991
    .line 992
    move-result v13

    .line 993
    move/from16 v26, v13

    .line 994
    .line 995
    const-string v13, "required_network_type"

    .line 996
    .line 997
    invoke-static {v1, v13}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 998
    .line 999
    .line 1000
    move-result v13

    .line 1001
    move/from16 v27, v13

    .line 1002
    .line 1003
    const-string v13, "required_network_request"

    .line 1004
    .line 1005
    invoke-static {v1, v13}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1006
    .line 1007
    .line 1008
    move-result v13

    .line 1009
    move/from16 v28, v13

    .line 1010
    .line 1011
    const-string v13, "requires_charging"

    .line 1012
    .line 1013
    invoke-static {v1, v13}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1014
    .line 1015
    .line 1016
    move-result v13

    .line 1017
    move/from16 v29, v13

    .line 1018
    .line 1019
    const-string v13, "requires_device_idle"

    .line 1020
    .line 1021
    invoke-static {v1, v13}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1022
    .line 1023
    .line 1024
    move-result v13

    .line 1025
    move/from16 v30, v13

    .line 1026
    .line 1027
    const-string v13, "requires_battery_not_low"

    .line 1028
    .line 1029
    invoke-static {v1, v13}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1030
    .line 1031
    .line 1032
    move-result v13

    .line 1033
    move/from16 v31, v13

    .line 1034
    .line 1035
    const-string v13, "requires_storage_not_low"

    .line 1036
    .line 1037
    invoke-static {v1, v13}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1038
    .line 1039
    .line 1040
    move-result v13

    .line 1041
    move/from16 v32, v13

    .line 1042
    .line 1043
    const-string v13, "trigger_content_update_delay"

    .line 1044
    .line 1045
    invoke-static {v1, v13}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1046
    .line 1047
    .line 1048
    move-result v13

    .line 1049
    move/from16 v33, v13

    .line 1050
    .line 1051
    const-string v13, "trigger_max_content_delay"

    .line 1052
    .line 1053
    invoke-static {v1, v13}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1054
    .line 1055
    .line 1056
    move-result v13

    .line 1057
    move/from16 v34, v13

    .line 1058
    .line 1059
    const-string v13, "content_uri_triggers"

    .line 1060
    .line 1061
    invoke-static {v1, v13}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1062
    .line 1063
    .line 1064
    move-result v13

    .line 1065
    move/from16 v35, v13

    .line 1066
    .line 1067
    new-instance v13, Ljava/util/ArrayList;

    .line 1068
    .line 1069
    invoke-direct {v13}, Ljava/util/ArrayList;-><init>()V

    .line 1070
    .line 1071
    .line 1072
    :goto_a
    invoke-interface {v1}, Lua/c;->s0()Z

    .line 1073
    .line 1074
    .line 1075
    move-result v36

    .line 1076
    if-eqz v36, :cond_14

    .line 1077
    .line 1078
    invoke-interface {v1, v0}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1079
    .line 1080
    .line 1081
    move-result-object v38

    .line 1082
    move-object/from16 v71, v13

    .line 1083
    .line 1084
    move/from16 v36, v14

    .line 1085
    .line 1086
    invoke-interface {v1, v2}, Lua/c;->getLong(I)J

    .line 1087
    .line 1088
    .line 1089
    move-result-wide v13

    .line 1090
    long-to-int v13, v13

    .line 1091
    invoke-static {v13}, Ljp/z0;->g(I)Leb/h0;

    .line 1092
    .line 1093
    .line 1094
    move-result-object v39

    .line 1095
    invoke-interface {v1, v3}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1096
    .line 1097
    .line 1098
    move-result-object v40

    .line 1099
    invoke-interface {v1, v4}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1100
    .line 1101
    .line 1102
    move-result-object v41

    .line 1103
    invoke-interface {v1, v5}, Lua/c;->getBlob(I)[B

    .line 1104
    .line 1105
    .line 1106
    move-result-object v13

    .line 1107
    sget-object v14, Leb/h;->b:Leb/h;

    .line 1108
    .line 1109
    invoke-static {v13}, Lkp/b6;->b([B)Leb/h;

    .line 1110
    .line 1111
    .line 1112
    move-result-object v42

    .line 1113
    invoke-interface {v1, v6}, Lua/c;->getBlob(I)[B

    .line 1114
    .line 1115
    .line 1116
    move-result-object v13

    .line 1117
    invoke-static {v13}, Lkp/b6;->b([B)Leb/h;

    .line 1118
    .line 1119
    .line 1120
    move-result-object v43

    .line 1121
    invoke-interface {v1, v7}, Lua/c;->getLong(I)J

    .line 1122
    .line 1123
    .line 1124
    move-result-wide v44

    .line 1125
    invoke-interface {v1, v8}, Lua/c;->getLong(I)J

    .line 1126
    .line 1127
    .line 1128
    move-result-wide v46

    .line 1129
    invoke-interface {v1, v9}, Lua/c;->getLong(I)J

    .line 1130
    .line 1131
    .line 1132
    move-result-wide v48

    .line 1133
    invoke-interface {v1, v10}, Lua/c;->getLong(I)J

    .line 1134
    .line 1135
    .line 1136
    move-result-wide v13

    .line 1137
    long-to-int v13, v13

    .line 1138
    move v14, v2

    .line 1139
    move/from16 v72, v3

    .line 1140
    .line 1141
    invoke-interface {v1, v11}, Lua/c;->getLong(I)J

    .line 1142
    .line 1143
    .line 1144
    move-result-wide v2

    .line 1145
    long-to-int v2, v2

    .line 1146
    invoke-static {v2}, Ljp/z0;->d(I)Leb/a;

    .line 1147
    .line 1148
    .line 1149
    move-result-object v52

    .line 1150
    invoke-interface {v1, v12}, Lua/c;->getLong(I)J

    .line 1151
    .line 1152
    .line 1153
    move-result-wide v53

    .line 1154
    move/from16 v2, v36

    .line 1155
    .line 1156
    invoke-interface {v1, v2}, Lua/c;->getLong(I)J

    .line 1157
    .line 1158
    .line 1159
    move-result-wide v55

    .line 1160
    invoke-interface {v1, v15}, Lua/c;->getLong(I)J

    .line 1161
    .line 1162
    .line 1163
    move-result-wide v57

    .line 1164
    move/from16 v3, p0

    .line 1165
    .line 1166
    invoke-interface {v1, v3}, Lua/c;->getLong(I)J

    .line 1167
    .line 1168
    .line 1169
    move-result-wide v59

    .line 1170
    move/from16 p0, v0

    .line 1171
    .line 1172
    move/from16 v36, v2

    .line 1173
    .line 1174
    move/from16 v0, p1

    .line 1175
    .line 1176
    move/from16 p1, v3

    .line 1177
    .line 1178
    invoke-interface {v1, v0}, Lua/c;->getLong(I)J

    .line 1179
    .line 1180
    .line 1181
    move-result-wide v2

    .line 1182
    long-to-int v2, v2

    .line 1183
    if-eqz v2, :cond_b

    .line 1184
    .line 1185
    const/16 v61, 0x1

    .line 1186
    .line 1187
    :goto_b
    move/from16 v2, v18

    .line 1188
    .line 1189
    move/from16 v18, v4

    .line 1190
    .line 1191
    goto :goto_c

    .line 1192
    :cond_b
    const/16 v61, 0x0

    .line 1193
    .line 1194
    goto :goto_b

    .line 1195
    :goto_c
    invoke-interface {v1, v2}, Lua/c;->getLong(I)J

    .line 1196
    .line 1197
    .line 1198
    move-result-wide v3

    .line 1199
    long-to-int v3, v3

    .line 1200
    invoke-static {v3}, Ljp/z0;->f(I)Leb/e0;

    .line 1201
    .line 1202
    .line 1203
    move-result-object v62

    .line 1204
    move/from16 v3, v19

    .line 1205
    .line 1206
    move/from16 v19, v5

    .line 1207
    .line 1208
    invoke-interface {v1, v3}, Lua/c;->getLong(I)J

    .line 1209
    .line 1210
    .line 1211
    move-result-wide v4

    .line 1212
    long-to-int v4, v4

    .line 1213
    move/from16 v73, v3

    .line 1214
    .line 1215
    move/from16 v5, v21

    .line 1216
    .line 1217
    move/from16 v21, v2

    .line 1218
    .line 1219
    invoke-interface {v1, v5}, Lua/c;->getLong(I)J

    .line 1220
    .line 1221
    .line 1222
    move-result-wide v2

    .line 1223
    long-to-int v2, v2

    .line 1224
    move/from16 v3, v22

    .line 1225
    .line 1226
    invoke-interface {v1, v3}, Lua/c;->getLong(I)J

    .line 1227
    .line 1228
    .line 1229
    move-result-wide v65

    .line 1230
    move/from16 v22, v0

    .line 1231
    .line 1232
    move/from16 v64, v2

    .line 1233
    .line 1234
    move/from16 v0, v23

    .line 1235
    .line 1236
    move/from16 v23, v3

    .line 1237
    .line 1238
    invoke-interface {v1, v0}, Lua/c;->getLong(I)J

    .line 1239
    .line 1240
    .line 1241
    move-result-wide v2

    .line 1242
    long-to-int v2, v2

    .line 1243
    move/from16 v63, v4

    .line 1244
    .line 1245
    move/from16 v3, v24

    .line 1246
    .line 1247
    move/from16 v24, v5

    .line 1248
    .line 1249
    invoke-interface {v1, v3}, Lua/c;->getLong(I)J

    .line 1250
    .line 1251
    .line 1252
    move-result-wide v4

    .line 1253
    long-to-int v4, v4

    .line 1254
    move/from16 v5, v25

    .line 1255
    .line 1256
    invoke-interface {v1, v5}, Lua/c;->isNull(I)Z

    .line 1257
    .line 1258
    .line 1259
    move-result v25

    .line 1260
    if-eqz v25, :cond_c

    .line 1261
    .line 1262
    move-object/from16 v69, v20

    .line 1263
    .line 1264
    :goto_d
    move/from16 v25, v0

    .line 1265
    .line 1266
    move/from16 v0, v26

    .line 1267
    .line 1268
    goto :goto_e

    .line 1269
    :cond_c
    invoke-interface {v1, v5}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1270
    .line 1271
    .line 1272
    move-result-object v25

    .line 1273
    move-object/from16 v69, v25

    .line 1274
    .line 1275
    goto :goto_d

    .line 1276
    :goto_e
    invoke-interface {v1, v0}, Lua/c;->isNull(I)Z

    .line 1277
    .line 1278
    .line 1279
    move-result v26

    .line 1280
    if-eqz v26, :cond_d

    .line 1281
    .line 1282
    move/from16 v67, v2

    .line 1283
    .line 1284
    move/from16 v26, v3

    .line 1285
    .line 1286
    move-object/from16 v2, v20

    .line 1287
    .line 1288
    goto :goto_f

    .line 1289
    :cond_d
    move/from16 v67, v2

    .line 1290
    .line 1291
    move/from16 v26, v3

    .line 1292
    .line 1293
    invoke-interface {v1, v0}, Lua/c;->getLong(I)J

    .line 1294
    .line 1295
    .line 1296
    move-result-wide v2

    .line 1297
    long-to-int v2, v2

    .line 1298
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1299
    .line 1300
    .line 1301
    move-result-object v2

    .line 1302
    :goto_f
    if-eqz v2, :cond_f

    .line 1303
    .line 1304
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 1305
    .line 1306
    .line 1307
    move-result v2

    .line 1308
    if-eqz v2, :cond_e

    .line 1309
    .line 1310
    const/4 v2, 0x1

    .line 1311
    goto :goto_10

    .line 1312
    :cond_e
    const/4 v2, 0x0

    .line 1313
    :goto_10
    invoke-static {v2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 1314
    .line 1315
    .line 1316
    move-result-object v2

    .line 1317
    move-object/from16 v70, v2

    .line 1318
    .line 1319
    :goto_11
    move/from16 v68, v4

    .line 1320
    .line 1321
    move/from16 v2, v27

    .line 1322
    .line 1323
    goto :goto_12

    .line 1324
    :catchall_2
    move-exception v0

    .line 1325
    goto/16 :goto_1b

    .line 1326
    .line 1327
    :cond_f
    move-object/from16 v70, v20

    .line 1328
    .line 1329
    goto :goto_11

    .line 1330
    :goto_12
    invoke-interface {v1, v2}, Lua/c;->getLong(I)J

    .line 1331
    .line 1332
    .line 1333
    move-result-wide v3

    .line 1334
    long-to-int v3, v3

    .line 1335
    invoke-static {v3}, Ljp/z0;->e(I)Leb/x;

    .line 1336
    .line 1337
    .line 1338
    move-result-object v76

    .line 1339
    move/from16 v3, v28

    .line 1340
    .line 1341
    invoke-interface {v1, v3}, Lua/c;->getBlob(I)[B

    .line 1342
    .line 1343
    .line 1344
    move-result-object v4

    .line 1345
    invoke-static {v4}, Ljp/z0;->m([B)Lnb/d;

    .line 1346
    .line 1347
    .line 1348
    move-result-object v75

    .line 1349
    move/from16 v27, v2

    .line 1350
    .line 1351
    move/from16 v28, v3

    .line 1352
    .line 1353
    move/from16 v4, v29

    .line 1354
    .line 1355
    invoke-interface {v1, v4}, Lua/c;->getLong(I)J

    .line 1356
    .line 1357
    .line 1358
    move-result-wide v2

    .line 1359
    long-to-int v2, v2

    .line 1360
    if-eqz v2, :cond_10

    .line 1361
    .line 1362
    const/16 v77, 0x1

    .line 1363
    .line 1364
    :goto_13
    move/from16 v29, v4

    .line 1365
    .line 1366
    move/from16 v2, v30

    .line 1367
    .line 1368
    goto :goto_14

    .line 1369
    :cond_10
    const/16 v77, 0x0

    .line 1370
    .line 1371
    goto :goto_13

    .line 1372
    :goto_14
    invoke-interface {v1, v2}, Lua/c;->getLong(I)J

    .line 1373
    .line 1374
    .line 1375
    move-result-wide v3

    .line 1376
    long-to-int v3, v3

    .line 1377
    if-eqz v3, :cond_11

    .line 1378
    .line 1379
    const/16 v78, 0x1

    .line 1380
    .line 1381
    :goto_15
    move/from16 v30, v5

    .line 1382
    .line 1383
    move/from16 v3, v31

    .line 1384
    .line 1385
    goto :goto_16

    .line 1386
    :cond_11
    const/16 v78, 0x0

    .line 1387
    .line 1388
    goto :goto_15

    .line 1389
    :goto_16
    invoke-interface {v1, v3}, Lua/c;->getLong(I)J

    .line 1390
    .line 1391
    .line 1392
    move-result-wide v4

    .line 1393
    long-to-int v4, v4

    .line 1394
    if-eqz v4, :cond_12

    .line 1395
    .line 1396
    const/16 v79, 0x1

    .line 1397
    .line 1398
    :goto_17
    move v5, v2

    .line 1399
    move/from16 v31, v3

    .line 1400
    .line 1401
    move/from16 v4, v32

    .line 1402
    .line 1403
    goto :goto_18

    .line 1404
    :cond_12
    const/16 v79, 0x0

    .line 1405
    .line 1406
    goto :goto_17

    .line 1407
    :goto_18
    invoke-interface {v1, v4}, Lua/c;->getLong(I)J

    .line 1408
    .line 1409
    .line 1410
    move-result-wide v2

    .line 1411
    long-to-int v2, v2

    .line 1412
    if-eqz v2, :cond_13

    .line 1413
    .line 1414
    const/16 v80, 0x1

    .line 1415
    .line 1416
    :goto_19
    move/from16 v2, v33

    .line 1417
    .line 1418
    goto :goto_1a

    .line 1419
    :cond_13
    const/16 v80, 0x0

    .line 1420
    .line 1421
    goto :goto_19

    .line 1422
    :goto_1a
    invoke-interface {v1, v2}, Lua/c;->getLong(I)J

    .line 1423
    .line 1424
    .line 1425
    move-result-wide v81

    .line 1426
    move/from16 v3, v34

    .line 1427
    .line 1428
    invoke-interface {v1, v3}, Lua/c;->getLong(I)J

    .line 1429
    .line 1430
    .line 1431
    move-result-wide v83

    .line 1432
    move/from16 v32, v0

    .line 1433
    .line 1434
    move/from16 v0, v35

    .line 1435
    .line 1436
    invoke-interface {v1, v0}, Lua/c;->getBlob(I)[B

    .line 1437
    .line 1438
    .line 1439
    move-result-object v33

    .line 1440
    invoke-static/range {v33 .. v33}, Ljp/z0;->b([B)Ljava/util/LinkedHashSet;

    .line 1441
    .line 1442
    .line 1443
    move-result-object v85

    .line 1444
    new-instance v50, Leb/e;

    .line 1445
    .line 1446
    move-object/from16 v74, v50

    .line 1447
    .line 1448
    invoke-direct/range {v74 .. v85}, Leb/e;-><init>(Lnb/d;Leb/x;ZZZZJJLjava/util/Set;)V

    .line 1449
    .line 1450
    .line 1451
    move-object/from16 v50, v74

    .line 1452
    .line 1453
    new-instance v37, Lmb/o;

    .line 1454
    .line 1455
    move/from16 v51, v13

    .line 1456
    .line 1457
    invoke-direct/range {v37 .. v70}, Lmb/o;-><init>(Ljava/lang/String;Leb/h0;Ljava/lang/String;Ljava/lang/String;Leb/h;Leb/h;JJJLeb/e;ILeb/a;JJJJZLeb/e0;IIJIILjava/lang/String;Ljava/lang/Boolean;)V

    .line 1458
    .line 1459
    .line 1460
    move-object/from16 v13, v37

    .line 1461
    .line 1462
    move/from16 v35, v0

    .line 1463
    .line 1464
    move-object/from16 v0, v71

    .line 1465
    .line 1466
    invoke-virtual {v0, v13}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    .line 1467
    .line 1468
    .line 1469
    move/from16 v13, v32

    .line 1470
    .line 1471
    move/from16 v32, v4

    .line 1472
    .line 1473
    move/from16 v4, v18

    .line 1474
    .line 1475
    move/from16 v18, v21

    .line 1476
    .line 1477
    move/from16 v21, v24

    .line 1478
    .line 1479
    move/from16 v24, v26

    .line 1480
    .line 1481
    move/from16 v26, v13

    .line 1482
    .line 1483
    move-object v13, v0

    .line 1484
    move/from16 v33, v2

    .line 1485
    .line 1486
    move/from16 v34, v3

    .line 1487
    .line 1488
    move v2, v14

    .line 1489
    move/from16 v14, v36

    .line 1490
    .line 1491
    move/from16 v3, v72

    .line 1492
    .line 1493
    move/from16 v0, p0

    .line 1494
    .line 1495
    move/from16 p0, p1

    .line 1496
    .line 1497
    move/from16 p1, v22

    .line 1498
    .line 1499
    move/from16 v22, v23

    .line 1500
    .line 1501
    move/from16 v23, v25

    .line 1502
    .line 1503
    move/from16 v25, v30

    .line 1504
    .line 1505
    move/from16 v30, v5

    .line 1506
    .line 1507
    move/from16 v5, v19

    .line 1508
    .line 1509
    move/from16 v19, v73

    .line 1510
    .line 1511
    goto/16 :goto_a

    .line 1512
    .line 1513
    :cond_14
    move-object v0, v13

    .line 1514
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 1515
    .line 1516
    .line 1517
    return-object v0

    .line 1518
    :goto_1b
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 1519
    .line 1520
    .line 1521
    throw v0

    .line 1522
    :pswitch_c
    move-object/from16 v0, p1

    .line 1523
    .line 1524
    check-cast v0, Lg3/d;

    .line 1525
    .line 1526
    invoke-static {v0, v10}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1527
    .line 1528
    .line 1529
    invoke-interface {v0}, Lg3/d;->x0()Lgw0/c;

    .line 1530
    .line 1531
    .line 1532
    move-result-object v1

    .line 1533
    invoke-virtual {v1}, Lgw0/c;->h()Le3/r;

    .line 1534
    .line 1535
    .line 1536
    move-result-object v23

    .line 1537
    int-to-float v1, v9

    .line 1538
    invoke-static {}, Le3/j0;->h()Le3/g;

    .line 1539
    .line 1540
    .line 1541
    move-result-object v2

    .line 1542
    iget-object v3, v2, Le3/g;->a:Landroid/graphics/Paint;

    .line 1543
    .line 1544
    new-instance v4, Landroid/graphics/BlurMaskFilter;

    .line 1545
    .line 1546
    invoke-interface {v0, v1}, Lt4/c;->w0(F)F

    .line 1547
    .line 1548
    .line 1549
    move-result v1

    .line 1550
    sget-object v5, Landroid/graphics/BlurMaskFilter$Blur;->NORMAL:Landroid/graphics/BlurMaskFilter$Blur;

    .line 1551
    .line 1552
    invoke-direct {v4, v1, v5}, Landroid/graphics/BlurMaskFilter;-><init>(FLandroid/graphics/BlurMaskFilter$Blur;)V

    .line 1553
    .line 1554
    .line 1555
    invoke-virtual {v3, v4}, Landroid/graphics/Paint;->setMaskFilter(Landroid/graphics/MaskFilter;)Landroid/graphics/MaskFilter;

    .line 1556
    .line 1557
    .line 1558
    invoke-static {v14, v15}, Le3/j0;->z(J)I

    .line 1559
    .line 1560
    .line 1561
    move-result v1

    .line 1562
    invoke-virtual {v3, v1}, Landroid/graphics/Paint;->setColor(I)V

    .line 1563
    .line 1564
    .line 1565
    invoke-interface {v0}, Lg3/d;->e()J

    .line 1566
    .line 1567
    .line 1568
    move-result-wide v3

    .line 1569
    shr-long v3, v3, v18

    .line 1570
    .line 1571
    long-to-int v1, v3

    .line 1572
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 1573
    .line 1574
    .line 1575
    move-result v26

    .line 1576
    invoke-interface {v0}, Lg3/d;->e()J

    .line 1577
    .line 1578
    .line 1579
    move-result-wide v0

    .line 1580
    and-long v0, v0, v21

    .line 1581
    .line 1582
    long-to-int v0, v0

    .line 1583
    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 1584
    .line 1585
    .line 1586
    move-result v27

    .line 1587
    invoke-virtual/range {v23 .. v23}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1588
    .line 1589
    .line 1590
    const/16 v24, 0x0

    .line 1591
    .line 1592
    const/16 v25, 0x0

    .line 1593
    .line 1594
    const/high16 v28, 0x42960000    # 75.0f

    .line 1595
    .line 1596
    const/high16 v29, 0x42d20000    # 105.0f

    .line 1597
    .line 1598
    move-object/from16 v30, v2

    .line 1599
    .line 1600
    invoke-interface/range {v23 .. v30}, Le3/r;->j(FFFFFFLe3/g;)V

    .line 1601
    .line 1602
    .line 1603
    return-object v19

    .line 1604
    :pswitch_d
    move-object/from16 v3, p1

    .line 1605
    .line 1606
    check-cast v3, Lg3/d;

    .line 1607
    .line 1608
    invoke-static {v3, v8}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1609
    .line 1610
    .line 1611
    const-wide/16 v1, 0x0

    .line 1612
    .line 1613
    invoke-interface {v3}, Lg3/d;->e()J

    .line 1614
    .line 1615
    .line 1616
    move-result-wide v4

    .line 1617
    invoke-static {v4, v5, v1, v2}, Lg3/d;->p0(JJ)J

    .line 1618
    .line 1619
    .line 1620
    move-result-wide v6

    .line 1621
    sget-object v8, Lg3/g;->a:Lg3/g;

    .line 1622
    .line 1623
    iget-wide v4, v0, Le81/e;->e:J

    .line 1624
    .line 1625
    invoke-interface/range {v3 .. v8}, Lg3/d;->T(JJLg3/e;)V

    .line 1626
    .line 1627
    .line 1628
    return-object v19

    .line 1629
    :pswitch_e
    move-object/from16 v0, p1

    .line 1630
    .line 1631
    check-cast v0, Lq6/b;

    .line 1632
    .line 1633
    sget-object v1, Let/h;->b:Lq6/e;

    .line 1634
    .line 1635
    invoke-static {v14, v15}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 1636
    .line 1637
    .line 1638
    move-result-object v2

    .line 1639
    invoke-virtual {v0, v1, v2}, Lq6/b;->e(Lq6/e;Ljava/lang/Object;)V

    .line 1640
    .line 1641
    .line 1642
    return-object v20

    .line 1643
    :pswitch_f
    move-object/from16 v0, p1

    .line 1644
    .line 1645
    check-cast v0, Lua/a;

    .line 1646
    .line 1647
    invoke-static {v0, v12}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1648
    .line 1649
    .line 1650
    const-string v1, "SELECT * from network_log WHERE id == ?"

    .line 1651
    .line 1652
    invoke-interface {v0, v1}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 1653
    .line 1654
    .line 1655
    move-result-object v1

    .line 1656
    const/4 v0, 0x1

    .line 1657
    :try_start_3
    invoke-interface {v1, v0, v14, v15}, Lua/c;->bindLong(IJ)V

    .line 1658
    .line 1659
    .line 1660
    invoke-static {v1, v11}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1661
    .line 1662
    .line 1663
    move-result v0

    .line 1664
    const-string v2, "service_label"

    .line 1665
    .line 1666
    invoke-static {v1, v2}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1667
    .line 1668
    .line 1669
    move-result v2

    .line 1670
    const-string v3, "exception"

    .line 1671
    .line 1672
    invoke-static {v1, v3}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1673
    .line 1674
    .line 1675
    move-result v3

    .line 1676
    const-string v4, "response_body"

    .line 1677
    .line 1678
    invoke-static {v1, v4}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1679
    .line 1680
    .line 1681
    move-result v4

    .line 1682
    const-string v5, "response_code"

    .line 1683
    .line 1684
    invoke-static {v1, v5}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1685
    .line 1686
    .line 1687
    move-result v5

    .line 1688
    const-string v6, "response_headers"

    .line 1689
    .line 1690
    invoke-static {v1, v6}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1691
    .line 1692
    .line 1693
    move-result v6

    .line 1694
    const-string v7, "response_message"

    .line 1695
    .line 1696
    invoke-static {v1, v7}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1697
    .line 1698
    .line 1699
    move-result v7

    .line 1700
    const-string v8, "response_time"

    .line 1701
    .line 1702
    invoke-static {v1, v8}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1703
    .line 1704
    .line 1705
    move-result v8

    .line 1706
    const-string v9, "response_url"

    .line 1707
    .line 1708
    invoke-static {v1, v9}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1709
    .line 1710
    .line 1711
    move-result v9

    .line 1712
    const-string v10, "request_body"

    .line 1713
    .line 1714
    invoke-static {v1, v10}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1715
    .line 1716
    .line 1717
    move-result v10

    .line 1718
    const-string v11, "request_headers"

    .line 1719
    .line 1720
    invoke-static {v1, v11}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1721
    .line 1722
    .line 1723
    move-result v11

    .line 1724
    const-string v12, "request_method"

    .line 1725
    .line 1726
    invoke-static {v1, v12}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1727
    .line 1728
    .line 1729
    move-result v12

    .line 1730
    const-string v13, "request_protocol"

    .line 1731
    .line 1732
    invoke-static {v1, v13}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1733
    .line 1734
    .line 1735
    move-result v13

    .line 1736
    const-string v14, "request_state"

    .line 1737
    .line 1738
    invoke-static {v1, v14}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1739
    .line 1740
    .line 1741
    move-result v14

    .line 1742
    const-string v15, "request_url"

    .line 1743
    .line 1744
    invoke-static {v1, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1745
    .line 1746
    .line 1747
    move-result v15

    .line 1748
    move/from16 p0, v15

    .line 1749
    .line 1750
    const-string v15, "log_type"

    .line 1751
    .line 1752
    invoke-static {v1, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1753
    .line 1754
    .line 1755
    move-result v15

    .line 1756
    move/from16 p1, v15

    .line 1757
    .line 1758
    const-string v15, "timestamp"

    .line 1759
    .line 1760
    invoke-static {v1, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1761
    .line 1762
    .line 1763
    move-result v15

    .line 1764
    invoke-interface {v1}, Lua/c;->s0()Z

    .line 1765
    .line 1766
    .line 1767
    move-result v16

    .line 1768
    if-eqz v16, :cond_15

    .line 1769
    .line 1770
    invoke-interface {v1, v0}, Lua/c;->getLong(I)J

    .line 1771
    .line 1772
    .line 1773
    move-result-wide v22

    .line 1774
    invoke-interface {v1, v2}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1775
    .line 1776
    .line 1777
    move-result-object v24

    .line 1778
    invoke-interface {v1, v3}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1779
    .line 1780
    .line 1781
    move-result-object v25

    .line 1782
    invoke-interface {v1, v4}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1783
    .line 1784
    .line 1785
    move-result-object v26

    .line 1786
    invoke-interface {v1, v5}, Lua/c;->getLong(I)J

    .line 1787
    .line 1788
    .line 1789
    move-result-wide v2

    .line 1790
    long-to-int v0, v2

    .line 1791
    invoke-interface {v1, v6}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1792
    .line 1793
    .line 1794
    move-result-object v28

    .line 1795
    invoke-interface {v1, v7}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1796
    .line 1797
    .line 1798
    move-result-object v29

    .line 1799
    invoke-interface {v1, v8}, Lua/c;->getLong(I)J

    .line 1800
    .line 1801
    .line 1802
    move-result-wide v30

    .line 1803
    invoke-interface {v1, v9}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1804
    .line 1805
    .line 1806
    move-result-object v32

    .line 1807
    invoke-interface {v1, v10}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1808
    .line 1809
    .line 1810
    move-result-object v33

    .line 1811
    invoke-interface {v1, v11}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1812
    .line 1813
    .line 1814
    move-result-object v34

    .line 1815
    invoke-interface {v1, v12}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1816
    .line 1817
    .line 1818
    move-result-object v35

    .line 1819
    invoke-interface {v1, v13}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1820
    .line 1821
    .line 1822
    move-result-object v36

    .line 1823
    invoke-interface {v1, v14}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1824
    .line 1825
    .line 1826
    move-result-object v37

    .line 1827
    move/from16 v2, p0

    .line 1828
    .line 1829
    invoke-interface {v1, v2}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1830
    .line 1831
    .line 1832
    move-result-object v38

    .line 1833
    move/from16 v2, p1

    .line 1834
    .line 1835
    invoke-interface {v1, v2}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1836
    .line 1837
    .line 1838
    move-result-object v2

    .line 1839
    invoke-static {v2}, Lem0/f;->a(Ljava/lang/String;)Lhm0/c;

    .line 1840
    .line 1841
    .line 1842
    move-result-object v39

    .line 1843
    invoke-interface {v1, v15}, Lua/c;->getLong(I)J

    .line 1844
    .line 1845
    .line 1846
    move-result-wide v40

    .line 1847
    new-instance v21, Lem0/g;

    .line 1848
    .line 1849
    move/from16 v27, v0

    .line 1850
    .line 1851
    invoke-direct/range {v21 .. v41}, Lem0/g;-><init>(JLjava/lang/String;Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;JLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lhm0/c;J)V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_3

    .line 1852
    .line 1853
    .line 1854
    move-object/from16 v14, v21

    .line 1855
    .line 1856
    goto :goto_1c

    .line 1857
    :catchall_3
    move-exception v0

    .line 1858
    goto :goto_1d

    .line 1859
    :cond_15
    move-object/from16 v14, v20

    .line 1860
    .line 1861
    :goto_1c
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 1862
    .line 1863
    .line 1864
    return-object v14

    .line 1865
    :goto_1d
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 1866
    .line 1867
    .line 1868
    throw v0

    .line 1869
    :pswitch_10
    move-object/from16 v0, p1

    .line 1870
    .line 1871
    check-cast v0, Lz71/b;

    .line 1872
    .line 1873
    invoke-static {v14, v15, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveActivationViewModelController;->f(JLz71/b;)Llx0/b0;

    .line 1874
    .line 1875
    .line 1876
    move-result-object v0

    .line 1877
    return-object v0

    .line 1878
    nop

    .line 1879
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
