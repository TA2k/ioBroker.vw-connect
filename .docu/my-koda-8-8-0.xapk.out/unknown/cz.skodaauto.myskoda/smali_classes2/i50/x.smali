.class public final Li50/x;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/p;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lx21/y;

.field public final synthetic f:Lay0/a;

.field public final synthetic g:Lay0/a;

.field public final synthetic h:Lay0/k;

.field public final synthetic i:Ll2/b1;

.field public final synthetic j:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;Lx21/y;Lay0/a;Lay0/a;Lay0/k;Ll2/b1;I)V
    .locals 0

    .line 1
    iput p7, p0, Li50/x;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Li50/x;->j:Ljava/lang/Object;

    .line 4
    .line 5
    iput-object p2, p0, Li50/x;->e:Lx21/y;

    .line 6
    .line 7
    iput-object p3, p0, Li50/x;->f:Lay0/a;

    .line 8
    .line 9
    iput-object p4, p0, Li50/x;->g:Lay0/a;

    .line 10
    .line 11
    iput-object p5, p0, Li50/x;->h:Lay0/k;

    .line 12
    .line 13
    iput-object p6, p0, Li50/x;->i:Ll2/b1;

    .line 14
    .line 15
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 16
    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 27

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Li50/x;->d:I

    .line 4
    .line 5
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 6
    .line 7
    iget-object v3, v0, Li50/x;->j:Ljava/lang/Object;

    .line 8
    .line 9
    const/4 v4, 0x2

    .line 10
    const/4 v5, 0x4

    .line 11
    const/4 v6, 0x1

    .line 12
    const/4 v7, 0x0

    .line 13
    packed-switch v1, :pswitch_data_0

    .line 14
    .line 15
    .line 16
    move-object/from16 v8, p1

    .line 17
    .line 18
    check-cast v8, Landroidx/compose/foundation/lazy/a;

    .line 19
    .line 20
    move-object/from16 v1, p2

    .line 21
    .line 22
    check-cast v1, Ljava/lang/Number;

    .line 23
    .line 24
    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    .line 25
    .line 26
    .line 27
    move-result v1

    .line 28
    move-object/from16 v9, p3

    .line 29
    .line 30
    check-cast v9, Ll2/o;

    .line 31
    .line 32
    move-object/from16 v10, p4

    .line 33
    .line 34
    check-cast v10, Ljava/lang/Number;

    .line 35
    .line 36
    invoke-virtual {v10}, Ljava/lang/Number;->intValue()I

    .line 37
    .line 38
    .line 39
    move-result v10

    .line 40
    and-int/lit8 v11, v10, 0x6

    .line 41
    .line 42
    if-nez v11, :cond_1

    .line 43
    .line 44
    move-object v11, v9

    .line 45
    check-cast v11, Ll2/t;

    .line 46
    .line 47
    invoke-virtual {v11, v8}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 48
    .line 49
    .line 50
    move-result v11

    .line 51
    if-eqz v11, :cond_0

    .line 52
    .line 53
    move v4, v5

    .line 54
    :cond_0
    or-int/2addr v4, v10

    .line 55
    goto :goto_0

    .line 56
    :cond_1
    move v4, v10

    .line 57
    :goto_0
    and-int/lit8 v5, v10, 0x30

    .line 58
    .line 59
    if-nez v5, :cond_3

    .line 60
    .line 61
    move-object v5, v9

    .line 62
    check-cast v5, Ll2/t;

    .line 63
    .line 64
    invoke-virtual {v5, v1}, Ll2/t;->e(I)Z

    .line 65
    .line 66
    .line 67
    move-result v5

    .line 68
    if-eqz v5, :cond_2

    .line 69
    .line 70
    const/16 v5, 0x20

    .line 71
    .line 72
    goto :goto_1

    .line 73
    :cond_2
    const/16 v5, 0x10

    .line 74
    .line 75
    :goto_1
    or-int/2addr v4, v5

    .line 76
    :cond_3
    and-int/lit16 v5, v4, 0x93

    .line 77
    .line 78
    const/16 v10, 0x92

    .line 79
    .line 80
    if-eq v5, v10, :cond_4

    .line 81
    .line 82
    goto :goto_2

    .line 83
    :cond_4
    move v6, v7

    .line 84
    :goto_2
    and-int/lit8 v5, v4, 0x1

    .line 85
    .line 86
    move-object v15, v9

    .line 87
    check-cast v15, Ll2/t;

    .line 88
    .line 89
    invoke-virtual {v15, v5, v6}, Ll2/t;->O(IZ)Z

    .line 90
    .line 91
    .line 92
    move-result v5

    .line 93
    if-eqz v5, :cond_5

    .line 94
    .line 95
    check-cast v3, Ljava/util/List;

    .line 96
    .line 97
    invoke-interface {v3, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 98
    .line 99
    .line 100
    move-result-object v1

    .line 101
    move-object/from16 v17, v1

    .line 102
    .line 103
    check-cast v17, Lh50/i0;

    .line 104
    .line 105
    const v1, -0x7a2939a7

    .line 106
    .line 107
    .line 108
    invoke-virtual {v15, v1}, Ll2/t;->Y(I)V

    .line 109
    .line 110
    .line 111
    invoke-virtual/range {v17 .. v17}, Lh50/i0;->a()I

    .line 112
    .line 113
    .line 114
    move-result v1

    .line 115
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 116
    .line 117
    .line 118
    move-result-object v10

    .line 119
    new-instance v16, Li50/x;

    .line 120
    .line 121
    iget-object v1, v0, Li50/x;->i:Ll2/b1;

    .line 122
    .line 123
    const/16 v23, 0x0

    .line 124
    .line 125
    iget-object v9, v0, Li50/x;->e:Lx21/y;

    .line 126
    .line 127
    iget-object v3, v0, Li50/x;->f:Lay0/a;

    .line 128
    .line 129
    iget-object v5, v0, Li50/x;->g:Lay0/a;

    .line 130
    .line 131
    iget-object v0, v0, Li50/x;->h:Lay0/k;

    .line 132
    .line 133
    move-object/from16 v21, v0

    .line 134
    .line 135
    move-object/from16 v22, v1

    .line 136
    .line 137
    move-object/from16 v19, v3

    .line 138
    .line 139
    move-object/from16 v20, v5

    .line 140
    .line 141
    move-object/from16 v18, v9

    .line 142
    .line 143
    invoke-direct/range {v16 .. v23}, Li50/x;-><init>(Ljava/lang/Object;Lx21/y;Lay0/a;Lay0/a;Lay0/k;Ll2/b1;I)V

    .line 144
    .line 145
    .line 146
    move-object/from16 v0, v16

    .line 147
    .line 148
    const v1, 0x62f41d98

    .line 149
    .line 150
    .line 151
    invoke-static {v1, v15, v0}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 152
    .line 153
    .line 154
    move-result-object v14

    .line 155
    const/high16 v0, 0x180000

    .line 156
    .line 157
    and-int/lit8 v1, v4, 0xe

    .line 158
    .line 159
    or-int v16, v1, v0

    .line 160
    .line 161
    const/4 v11, 0x0

    .line 162
    const/4 v12, 0x0

    .line 163
    const/4 v13, 0x0

    .line 164
    invoke-static/range {v8 .. v16}, Llp/de;->a(Landroidx/compose/foundation/lazy/a;Lx21/y;Ljava/lang/Integer;Lx2/s;ZLx2/s;Lt2/b;Ll2/o;I)V

    .line 165
    .line 166
    .line 167
    invoke-virtual {v15, v7}, Ll2/t;->q(Z)V

    .line 168
    .line 169
    .line 170
    goto :goto_3

    .line 171
    :cond_5
    invoke-virtual {v15}, Ll2/t;->R()V

    .line 172
    .line 173
    .line 174
    :goto_3
    return-object v2

    .line 175
    :pswitch_0
    move-object/from16 v1, p1

    .line 176
    .line 177
    check-cast v1, Lx21/k;

    .line 178
    .line 179
    move-object/from16 v8, p2

    .line 180
    .line 181
    check-cast v8, Ljava/lang/Boolean;

    .line 182
    .line 183
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 184
    .line 185
    .line 186
    move-object/from16 v8, p3

    .line 187
    .line 188
    check-cast v8, Ll2/o;

    .line 189
    .line 190
    move-object/from16 v9, p4

    .line 191
    .line 192
    check-cast v9, Ljava/lang/Number;

    .line 193
    .line 194
    invoke-virtual {v9}, Ljava/lang/Number;->intValue()I

    .line 195
    .line 196
    .line 197
    move-result v9

    .line 198
    const-string v10, "$this$ReorderableItem"

    .line 199
    .line 200
    invoke-static {v1, v10}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 201
    .line 202
    .line 203
    and-int/lit8 v10, v9, 0x6

    .line 204
    .line 205
    if-nez v10, :cond_7

    .line 206
    .line 207
    move-object v10, v8

    .line 208
    check-cast v10, Ll2/t;

    .line 209
    .line 210
    invoke-virtual {v10, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 211
    .line 212
    .line 213
    move-result v10

    .line 214
    if-eqz v10, :cond_6

    .line 215
    .line 216
    move v4, v5

    .line 217
    :cond_6
    or-int/2addr v9, v4

    .line 218
    :cond_7
    and-int/lit16 v4, v9, 0x83

    .line 219
    .line 220
    const/16 v5, 0x82

    .line 221
    .line 222
    if-eq v4, v5, :cond_8

    .line 223
    .line 224
    move v4, v6

    .line 225
    goto :goto_4

    .line 226
    :cond_8
    move v4, v7

    .line 227
    :goto_4
    and-int/lit8 v5, v9, 0x1

    .line 228
    .line 229
    check-cast v8, Ll2/t;

    .line 230
    .line 231
    invoke-virtual {v8, v5, v4}, Ll2/t;->O(IZ)Z

    .line 232
    .line 233
    .line 234
    move-result v4

    .line 235
    if-eqz v4, :cond_15

    .line 236
    .line 237
    check-cast v3, Lh50/i0;

    .line 238
    .line 239
    sget-object v4, Lx2/c;->d:Lx2/j;

    .line 240
    .line 241
    invoke-static {v4, v7}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 242
    .line 243
    .line 244
    move-result-object v4

    .line 245
    iget-wide v10, v8, Ll2/t;->T:J

    .line 246
    .line 247
    invoke-static {v10, v11}, Ljava/lang/Long;->hashCode(J)I

    .line 248
    .line 249
    .line 250
    move-result v5

    .line 251
    invoke-virtual {v8}, Ll2/t;->m()Ll2/p1;

    .line 252
    .line 253
    .line 254
    move-result-object v10

    .line 255
    sget-object v11, Lx2/p;->b:Lx2/p;

    .line 256
    .line 257
    invoke-static {v8, v11}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 258
    .line 259
    .line 260
    move-result-object v11

    .line 261
    sget-object v12, Lv3/k;->m1:Lv3/j;

    .line 262
    .line 263
    invoke-virtual {v12}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 264
    .line 265
    .line 266
    sget-object v12, Lv3/j;->b:Lv3/i;

    .line 267
    .line 268
    invoke-virtual {v8}, Ll2/t;->c0()V

    .line 269
    .line 270
    .line 271
    iget-boolean v13, v8, Ll2/t;->S:Z

    .line 272
    .line 273
    if-eqz v13, :cond_9

    .line 274
    .line 275
    invoke-virtual {v8, v12}, Ll2/t;->l(Lay0/a;)V

    .line 276
    .line 277
    .line 278
    goto :goto_5

    .line 279
    :cond_9
    invoke-virtual {v8}, Ll2/t;->m0()V

    .line 280
    .line 281
    .line 282
    :goto_5
    sget-object v12, Lv3/j;->g:Lv3/h;

    .line 283
    .line 284
    invoke-static {v12, v4, v8}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 285
    .line 286
    .line 287
    sget-object v4, Lv3/j;->f:Lv3/h;

    .line 288
    .line 289
    invoke-static {v4, v10, v8}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 290
    .line 291
    .line 292
    sget-object v4, Lv3/j;->j:Lv3/h;

    .line 293
    .line 294
    iget-boolean v10, v8, Ll2/t;->S:Z

    .line 295
    .line 296
    if-nez v10, :cond_a

    .line 297
    .line 298
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 299
    .line 300
    .line 301
    move-result-object v10

    .line 302
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 303
    .line 304
    .line 305
    move-result-object v12

    .line 306
    invoke-static {v10, v12}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 307
    .line 308
    .line 309
    move-result v10

    .line 310
    if-nez v10, :cond_b

    .line 311
    .line 312
    :cond_a
    invoke-static {v5, v8, v5, v4}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 313
    .line 314
    .line 315
    :cond_b
    sget-object v4, Lv3/j;->d:Lv3/h;

    .line 316
    .line 317
    invoke-static {v4, v11, v8}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 318
    .line 319
    .line 320
    sget v4, Li50/z;->a:F

    .line 321
    .line 322
    iget-object v4, v0, Li50/x;->i:Ll2/b1;

    .line 323
    .line 324
    invoke-interface {v4}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 325
    .line 326
    .line 327
    move-result-object v5

    .line 328
    check-cast v5, Ljava/util/List;

    .line 329
    .line 330
    invoke-interface {v5, v3}, Ljava/util/List;->indexOf(Ljava/lang/Object;)I

    .line 331
    .line 332
    .line 333
    move-result v10

    .line 334
    if-eqz v10, :cond_c

    .line 335
    .line 336
    move v10, v6

    .line 337
    goto :goto_6

    .line 338
    :cond_c
    move v10, v7

    .line 339
    :goto_6
    invoke-interface {v5, v3}, Ljava/util/List;->indexOf(Ljava/lang/Object;)I

    .line 340
    .line 341
    .line 342
    move-result v11

    .line 343
    invoke-interface {v5}, Ljava/util/List;->size()I

    .line 344
    .line 345
    .line 346
    move-result v5

    .line 347
    sub-int/2addr v5, v6

    .line 348
    if-eq v11, v5, :cond_d

    .line 349
    .line 350
    move v5, v6

    .line 351
    goto :goto_7

    .line 352
    :cond_d
    move v5, v7

    .line 353
    :goto_7
    invoke-interface {v4}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 354
    .line 355
    .line 356
    move-result-object v4

    .line 357
    check-cast v4, Ljava/util/List;

    .line 358
    .line 359
    invoke-interface {v4, v3}, Ljava/util/List;->indexOf(Ljava/lang/Object;)I

    .line 360
    .line 361
    .line 362
    move-result v18

    .line 363
    iget-boolean v4, v3, Lh50/i0;->a:Z

    .line 364
    .line 365
    iget-object v11, v0, Li50/x;->e:Lx21/y;

    .line 366
    .line 367
    if-eqz v4, :cond_e

    .line 368
    .line 369
    invoke-virtual {v11}, Lx21/y;->g()Z

    .line 370
    .line 371
    .line 372
    move-result v4

    .line 373
    if-nez v4, :cond_e

    .line 374
    .line 375
    move/from16 v19, v6

    .line 376
    .line 377
    goto :goto_8

    .line 378
    :cond_e
    move/from16 v19, v7

    .line 379
    .line 380
    :goto_8
    invoke-virtual {v11}, Lx21/y;->g()Z

    .line 381
    .line 382
    .line 383
    move-result v4

    .line 384
    if-nez v4, :cond_f

    .line 385
    .line 386
    if-eqz v10, :cond_f

    .line 387
    .line 388
    move/from16 v21, v6

    .line 389
    .line 390
    goto :goto_9

    .line 391
    :cond_f
    move/from16 v21, v7

    .line 392
    .line 393
    :goto_9
    invoke-virtual {v11}, Lx21/y;->g()Z

    .line 394
    .line 395
    .line 396
    move-result v4

    .line 397
    if-nez v4, :cond_10

    .line 398
    .line 399
    if-eqz v5, :cond_10

    .line 400
    .line 401
    move/from16 v22, v6

    .line 402
    .line 403
    goto :goto_a

    .line 404
    :cond_10
    move/from16 v22, v7

    .line 405
    .line 406
    :goto_a
    invoke-virtual {v8, v10}, Ll2/t;->h(Z)Z

    .line 407
    .line 408
    .line 409
    move-result v4

    .line 410
    iget-object v5, v0, Li50/x;->f:Lay0/a;

    .line 411
    .line 412
    invoke-virtual {v8, v5}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 413
    .line 414
    .line 415
    move-result v11

    .line 416
    or-int/2addr v4, v11

    .line 417
    invoke-virtual {v8, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 418
    .line 419
    .line 420
    move-result v11

    .line 421
    or-int/2addr v4, v11

    .line 422
    iget-object v11, v0, Li50/x;->g:Lay0/a;

    .line 423
    .line 424
    invoke-virtual {v8, v11}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 425
    .line 426
    .line 427
    move-result v12

    .line 428
    or-int/2addr v4, v12

    .line 429
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 430
    .line 431
    .line 432
    move-result-object v12

    .line 433
    sget-object v13, Ll2/n;->a:Ll2/x0;

    .line 434
    .line 435
    if-nez v4, :cond_11

    .line 436
    .line 437
    if-ne v12, v13, :cond_12

    .line 438
    .line 439
    :cond_11
    new-instance v12, Li50/w;

    .line 440
    .line 441
    invoke-direct {v12, v10, v5, v3, v11}, Li50/w;-><init>(ZLay0/a;Lh50/i0;Lay0/a;)V

    .line 442
    .line 443
    .line 444
    invoke-virtual {v8, v12}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 445
    .line 446
    .line 447
    :cond_12
    move-object/from16 v23, v12

    .line 448
    .line 449
    check-cast v23, Lay0/a;

    .line 450
    .line 451
    invoke-virtual {v8, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 452
    .line 453
    .line 454
    move-result v4

    .line 455
    iget-object v0, v0, Li50/x;->h:Lay0/k;

    .line 456
    .line 457
    invoke-virtual {v8, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 458
    .line 459
    .line 460
    move-result v5

    .line 461
    or-int/2addr v4, v5

    .line 462
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 463
    .line 464
    .line 465
    move-result-object v5

    .line 466
    if-nez v4, :cond_13

    .line 467
    .line 468
    if-ne v5, v13, :cond_14

    .line 469
    .line 470
    :cond_13
    new-instance v5, Lc41/f;

    .line 471
    .line 472
    const/4 v4, 0x7

    .line 473
    invoke-direct {v5, v3, v0, v7, v4}, Lc41/f;-><init>(Ljava/lang/Object;Ljava/lang/Object;ZI)V

    .line 474
    .line 475
    .line 476
    invoke-virtual {v8, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 477
    .line 478
    .line 479
    :cond_14
    move-object/from16 v24, v5

    .line 480
    .line 481
    check-cast v24, Lay0/a;

    .line 482
    .line 483
    and-int/lit8 v26, v9, 0xe

    .line 484
    .line 485
    const/16 v20, 0x0

    .line 486
    .line 487
    move-object/from16 v16, v1

    .line 488
    .line 489
    move-object/from16 v17, v3

    .line 490
    .line 491
    move-object/from16 v25, v8

    .line 492
    .line 493
    invoke-static/range {v16 .. v26}, Li50/z;->h(Lx21/k;Lh50/i0;IZZZZLay0/a;Lay0/a;Ll2/o;I)V

    .line 494
    .line 495
    .line 496
    invoke-virtual {v8, v6}, Ll2/t;->q(Z)V

    .line 497
    .line 498
    .line 499
    goto :goto_b

    .line 500
    :cond_15
    invoke-virtual {v8}, Ll2/t;->R()V

    .line 501
    .line 502
    .line 503
    :goto_b
    return-object v2

    .line 504
    nop

    .line 505
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
