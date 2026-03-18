.class public final synthetic Ld00/l;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lc00/y0;

.field public final synthetic f:Ld00/a;

.field public final synthetic g:Lc00/n1;


# direct methods
.method public synthetic constructor <init>(Lc00/y0;Lc00/n1;Ld00/a;)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    iput v0, p0, Ld00/l;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Ld00/l;->e:Lc00/y0;

    iput-object p2, p0, Ld00/l;->g:Lc00/n1;

    iput-object p3, p0, Ld00/l;->f:Ld00/a;

    return-void
.end method

.method public synthetic constructor <init>(Lc00/y0;Ld00/a;Lc00/n1;)V
    .locals 1

    .line 2
    const/4 v0, 0x1

    iput v0, p0, Ld00/l;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Ld00/l;->e:Lc00/y0;

    iput-object p2, p0, Ld00/l;->f:Ld00/a;

    iput-object p3, p0, Ld00/l;->g:Lc00/n1;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 37

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Ld00/l;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    move-object/from16 v1, p1

    .line 9
    .line 10
    check-cast v1, Lk1/q;

    .line 11
    .line 12
    move-object/from16 v2, p2

    .line 13
    .line 14
    check-cast v2, Ll2/o;

    .line 15
    .line 16
    move-object/from16 v3, p3

    .line 17
    .line 18
    check-cast v3, Ljava/lang/Integer;

    .line 19
    .line 20
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 21
    .line 22
    .line 23
    move-result v3

    .line 24
    const-string v4, "$this$PullToRefreshBox"

    .line 25
    .line 26
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    and-int/lit8 v1, v3, 0x11

    .line 30
    .line 31
    const/16 v4, 0x10

    .line 32
    .line 33
    const/4 v5, 0x1

    .line 34
    const/4 v6, 0x0

    .line 35
    if-eq v1, v4, :cond_0

    .line 36
    .line 37
    move v1, v5

    .line 38
    goto :goto_0

    .line 39
    :cond_0
    move v1, v6

    .line 40
    :goto_0
    and-int/2addr v3, v5

    .line 41
    move-object v11, v2

    .line 42
    check-cast v11, Ll2/t;

    .line 43
    .line 44
    invoke-virtual {v11, v3, v1}, Ll2/t;->O(IZ)Z

    .line 45
    .line 46
    .line 47
    move-result v1

    .line 48
    if-eqz v1, :cond_18

    .line 49
    .line 50
    sget-object v1, Lx2/c;->q:Lx2/h;

    .line 51
    .line 52
    sget-object v2, Landroidx/compose/foundation/layout/d;->c:Landroidx/compose/foundation/layout/FillElement;

    .line 53
    .line 54
    invoke-static {v6, v5, v11}, Lkp/n;->b(IILl2/o;)Le1/n1;

    .line 55
    .line 56
    .line 57
    move-result-object v3

    .line 58
    const/16 v4, 0xe

    .line 59
    .line 60
    invoke-static {v2, v3, v4}, Lkp/n;->d(Lx2/s;Le1/n1;I)Lx2/s;

    .line 61
    .line 62
    .line 63
    move-result-object v2

    .line 64
    sget-object v3, Lk1/j;->c:Lk1/e;

    .line 65
    .line 66
    const/16 v4, 0x30

    .line 67
    .line 68
    invoke-static {v3, v1, v11, v4}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 69
    .line 70
    .line 71
    move-result-object v1

    .line 72
    iget-wide v3, v11, Ll2/t;->T:J

    .line 73
    .line 74
    invoke-static {v3, v4}, Ljava/lang/Long;->hashCode(J)I

    .line 75
    .line 76
    .line 77
    move-result v3

    .line 78
    invoke-virtual {v11}, Ll2/t;->m()Ll2/p1;

    .line 79
    .line 80
    .line 81
    move-result-object v4

    .line 82
    invoke-static {v11, v2}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 83
    .line 84
    .line 85
    move-result-object v2

    .line 86
    sget-object v7, Lv3/k;->m1:Lv3/j;

    .line 87
    .line 88
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 89
    .line 90
    .line 91
    sget-object v7, Lv3/j;->b:Lv3/i;

    .line 92
    .line 93
    invoke-virtual {v11}, Ll2/t;->c0()V

    .line 94
    .line 95
    .line 96
    iget-boolean v8, v11, Ll2/t;->S:Z

    .line 97
    .line 98
    if-eqz v8, :cond_1

    .line 99
    .line 100
    invoke-virtual {v11, v7}, Ll2/t;->l(Lay0/a;)V

    .line 101
    .line 102
    .line 103
    goto :goto_1

    .line 104
    :cond_1
    invoke-virtual {v11}, Ll2/t;->m0()V

    .line 105
    .line 106
    .line 107
    :goto_1
    sget-object v7, Lv3/j;->g:Lv3/h;

    .line 108
    .line 109
    invoke-static {v7, v1, v11}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 110
    .line 111
    .line 112
    sget-object v1, Lv3/j;->f:Lv3/h;

    .line 113
    .line 114
    invoke-static {v1, v4, v11}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 115
    .line 116
    .line 117
    sget-object v1, Lv3/j;->j:Lv3/h;

    .line 118
    .line 119
    iget-boolean v4, v11, Ll2/t;->S:Z

    .line 120
    .line 121
    if-nez v4, :cond_2

    .line 122
    .line 123
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 124
    .line 125
    .line 126
    move-result-object v4

    .line 127
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 128
    .line 129
    .line 130
    move-result-object v7

    .line 131
    invoke-static {v4, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 132
    .line 133
    .line 134
    move-result v4

    .line 135
    if-nez v4, :cond_3

    .line 136
    .line 137
    :cond_2
    invoke-static {v3, v11, v3, v1}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 138
    .line 139
    .line 140
    :cond_3
    sget-object v1, Lv3/j;->d:Lv3/h;

    .line 141
    .line 142
    invoke-static {v1, v2, v11}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 143
    .line 144
    .line 145
    iget-object v1, v0, Ld00/l;->e:Lc00/y0;

    .line 146
    .line 147
    iget-boolean v2, v1, Lc00/y0;->b:Z

    .line 148
    .line 149
    iget-boolean v3, v1, Lc00/y0;->c:Z

    .line 150
    .line 151
    iget-object v4, v1, Lc00/y0;->g:Lc00/x0;

    .line 152
    .line 153
    iget-object v7, v1, Lc00/y0;->f:Lc00/w0;

    .line 154
    .line 155
    iget-object v8, v1, Lc00/y0;->k:Lc00/v0;

    .line 156
    .line 157
    sget-object v9, Lx2/p;->b:Lx2/p;

    .line 158
    .line 159
    if-eqz v2, :cond_4

    .line 160
    .line 161
    const v0, 0x36d0c9c2

    .line 162
    .line 163
    .line 164
    invoke-virtual {v11, v0}, Ll2/t;->Y(I)V

    .line 165
    .line 166
    .line 167
    invoke-static {v11, v6}, Lxf0/i0;->i(Ll2/o;I)V

    .line 168
    .line 169
    .line 170
    invoke-virtual {v11, v6}, Ll2/t;->q(Z)V

    .line 171
    .line 172
    .line 173
    move-object v3, v9

    .line 174
    goto/16 :goto_13

    .line 175
    .line 176
    :cond_4
    const v2, 0x36d2cd03

    .line 177
    .line 178
    .line 179
    invoke-virtual {v11, v2}, Ll2/t;->Y(I)V

    .line 180
    .line 181
    .line 182
    iget-object v2, v8, Lc00/v0;->a:Ljava/lang/String;

    .line 183
    .line 184
    iget-object v10, v8, Lc00/v0;->b:Ljava/lang/String;

    .line 185
    .line 186
    iget v12, v8, Lc00/v0;->c:F

    .line 187
    .line 188
    iget-boolean v15, v8, Lc00/v0;->d:Z

    .line 189
    .line 190
    invoke-virtual {v1}, Lc00/y0;->b()Z

    .line 191
    .line 192
    .line 193
    move-result v20

    .line 194
    iget-boolean v13, v1, Lc00/y0;->o:Z

    .line 195
    .line 196
    sget-object v14, Lc00/x0;->d:Lc00/x0;

    .line 197
    .line 198
    if-ne v4, v14, :cond_5

    .line 199
    .line 200
    iget-boolean v14, v1, Lc00/y0;->d:Z

    .line 201
    .line 202
    if-eqz v14, :cond_5

    .line 203
    .line 204
    move v14, v5

    .line 205
    goto :goto_2

    .line 206
    :cond_5
    move v14, v6

    .line 207
    :goto_2
    sget-object v5, Lc00/x0;->g:Lc00/x0;

    .line 208
    .line 209
    if-ne v4, v5, :cond_6

    .line 210
    .line 211
    const/16 v16, 0x1

    .line 212
    .line 213
    goto :goto_3

    .line 214
    :cond_6
    move/from16 v16, v6

    .line 215
    .line 216
    :goto_3
    const v17, 0x7f08018a

    .line 217
    .line 218
    .line 219
    if-nez v14, :cond_8

    .line 220
    .line 221
    if-eqz v16, :cond_7

    .line 222
    .line 223
    goto :goto_4

    .line 224
    :cond_7
    sget-object v14, Lc00/x0;->e:Lc00/x0;

    .line 225
    .line 226
    if-ne v4, v14, :cond_9

    .line 227
    .line 228
    const v17, 0x7f08018c

    .line 229
    .line 230
    .line 231
    :cond_8
    :goto_4
    move v14, v12

    .line 232
    move/from16 v24, v17

    .line 233
    .line 234
    goto :goto_5

    .line 235
    :cond_9
    invoke-virtual {v1}, Lc00/y0;->b()Z

    .line 236
    .line 237
    .line 238
    move-result v14

    .line 239
    if-eqz v14, :cond_8

    .line 240
    .line 241
    const v17, 0x7f08018b

    .line 242
    .line 243
    .line 244
    goto :goto_4

    .line 245
    :goto_5
    iget-boolean v12, v1, Lc00/y0;->v:Z

    .line 246
    .line 247
    new-instance v17, Lxf0/w0;

    .line 248
    .line 249
    sget-object v6, Lj91/h;->a:Ll2/u2;

    .line 250
    .line 251
    invoke-virtual {v11, v6}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 252
    .line 253
    .line 254
    move-result-object v16

    .line 255
    check-cast v16, Lj91/e;

    .line 256
    .line 257
    invoke-virtual/range {v16 .. v16}, Lj91/e;->d()J

    .line 258
    .line 259
    .line 260
    move-result-wide v26

    .line 261
    move-object/from16 v16, v2

    .line 262
    .line 263
    sget-object v2, Lxf0/h0;->o:Lxf0/h0;

    .line 264
    .line 265
    invoke-virtual {v2, v11}, Lxf0/h0;->a(Ll2/o;)J

    .line 266
    .line 267
    .line 268
    move-result-wide v28

    .line 269
    sget-object v2, Lxf0/h0;->m:Lxf0/h0;

    .line 270
    .line 271
    invoke-virtual {v2, v11}, Lxf0/h0;->a(Ll2/o;)J

    .line 272
    .line 273
    .line 274
    move-result-wide v30

    .line 275
    iget-object v2, v1, Lc00/y0;->e:Lc00/u0;

    .line 276
    .line 277
    move/from16 v18, v3

    .line 278
    .line 279
    sget-object v3, Lc00/u0;->i:Lc00/u0;

    .line 280
    .line 281
    if-eq v2, v3, :cond_a

    .line 282
    .line 283
    sget-object v3, Lc00/u0;->j:Lc00/u0;

    .line 284
    .line 285
    if-ne v2, v3, :cond_b

    .line 286
    .line 287
    :cond_a
    const/4 v2, 0x0

    .line 288
    goto/16 :goto_8

    .line 289
    .line 290
    :cond_b
    if-eqz v18, :cond_c

    .line 291
    .line 292
    const v2, -0x3a1dd652

    .line 293
    .line 294
    .line 295
    invoke-virtual {v11, v2}, Ll2/t;->Y(I)V

    .line 296
    .line 297
    .line 298
    invoke-virtual {v11, v6}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 299
    .line 300
    .line 301
    move-result-object v2

    .line 302
    check-cast v2, Lj91/e;

    .line 303
    .line 304
    invoke-virtual {v2}, Lj91/e;->r()J

    .line 305
    .line 306
    .line 307
    move-result-wide v2

    .line 308
    move-wide/from16 v21, v2

    .line 309
    .line 310
    const/4 v3, 0x0

    .line 311
    invoke-virtual {v11, v3}, Ll2/t;->q(Z)V

    .line 312
    .line 313
    .line 314
    :goto_6
    move v2, v3

    .line 315
    :goto_7
    move-wide/from16 v32, v21

    .line 316
    .line 317
    goto/16 :goto_9

    .line 318
    .line 319
    :cond_c
    const/4 v3, 0x0

    .line 320
    if-eqz v7, :cond_d

    .line 321
    .line 322
    sget-object v3, Lc00/w0;->f:Lc00/w0;

    .line 323
    .line 324
    if-eq v7, v3, :cond_d

    .line 325
    .line 326
    const v2, -0x3a1dbfb3

    .line 327
    .line 328
    .line 329
    invoke-virtual {v11, v2}, Ll2/t;->Y(I)V

    .line 330
    .line 331
    .line 332
    invoke-virtual {v11, v6}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 333
    .line 334
    .line 335
    move-result-object v2

    .line 336
    check-cast v2, Lj91/e;

    .line 337
    .line 338
    invoke-virtual {v2}, Lj91/e;->s()J

    .line 339
    .line 340
    .line 341
    move-result-wide v2

    .line 342
    move-wide/from16 v21, v2

    .line 343
    .line 344
    const/4 v3, 0x0

    .line 345
    invoke-virtual {v11, v3}, Ll2/t;->q(Z)V

    .line 346
    .line 347
    .line 348
    goto :goto_6

    .line 349
    :cond_d
    sget-object v3, Lc00/u0;->f:Lc00/u0;

    .line 350
    .line 351
    if-ne v2, v3, :cond_e

    .line 352
    .line 353
    const v2, -0x3a1db476

    .line 354
    .line 355
    .line 356
    invoke-virtual {v11, v2}, Ll2/t;->Y(I)V

    .line 357
    .line 358
    .line 359
    sget-object v2, Lxf0/h0;->j:Lxf0/h0;

    .line 360
    .line 361
    invoke-virtual {v2, v11}, Lxf0/h0;->a(Ll2/o;)J

    .line 362
    .line 363
    .line 364
    move-result-wide v2

    .line 365
    move-wide/from16 v21, v2

    .line 366
    .line 367
    const/4 v3, 0x0

    .line 368
    invoke-virtual {v11, v3}, Ll2/t;->q(Z)V

    .line 369
    .line 370
    .line 371
    goto :goto_6

    .line 372
    :cond_e
    sget-object v3, Lc00/u0;->g:Lc00/u0;

    .line 373
    .line 374
    if-ne v2, v3, :cond_f

    .line 375
    .line 376
    const v2, -0x3a1da996

    .line 377
    .line 378
    .line 379
    invoke-virtual {v11, v2}, Ll2/t;->Y(I)V

    .line 380
    .line 381
    .line 382
    sget-object v2, Lxf0/h0;->k:Lxf0/h0;

    .line 383
    .line 384
    invoke-virtual {v2, v11}, Lxf0/h0;->a(Ll2/o;)J

    .line 385
    .line 386
    .line 387
    move-result-wide v2

    .line 388
    move-wide/from16 v21, v2

    .line 389
    .line 390
    const/4 v3, 0x0

    .line 391
    invoke-virtual {v11, v3}, Ll2/t;->q(Z)V

    .line 392
    .line 393
    .line 394
    goto :goto_6

    .line 395
    :cond_f
    sget-object v3, Lc00/u0;->h:Lc00/u0;

    .line 396
    .line 397
    if-ne v2, v3, :cond_10

    .line 398
    .line 399
    const v2, -0x3a1d9e36

    .line 400
    .line 401
    .line 402
    invoke-virtual {v11, v2}, Ll2/t;->Y(I)V

    .line 403
    .line 404
    .line 405
    sget-object v2, Lxf0/h0;->k:Lxf0/h0;

    .line 406
    .line 407
    invoke-virtual {v2, v11}, Lxf0/h0;->a(Ll2/o;)J

    .line 408
    .line 409
    .line 410
    move-result-wide v2

    .line 411
    move-wide/from16 v21, v2

    .line 412
    .line 413
    const/4 v2, 0x0

    .line 414
    invoke-virtual {v11, v2}, Ll2/t;->q(Z)V

    .line 415
    .line 416
    .line 417
    goto :goto_7

    .line 418
    :cond_10
    const/4 v2, 0x0

    .line 419
    const v3, -0x3a1d98b3

    .line 420
    .line 421
    .line 422
    invoke-virtual {v11, v3}, Ll2/t;->Y(I)V

    .line 423
    .line 424
    .line 425
    invoke-virtual {v11, v6}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 426
    .line 427
    .line 428
    move-result-object v3

    .line 429
    check-cast v3, Lj91/e;

    .line 430
    .line 431
    invoke-virtual {v3}, Lj91/e;->s()J

    .line 432
    .line 433
    .line 434
    move-result-wide v21

    .line 435
    invoke-virtual {v11, v2}, Ll2/t;->q(Z)V

    .line 436
    .line 437
    .line 438
    goto :goto_7

    .line 439
    :goto_8
    const v3, -0x3a1dddf6

    .line 440
    .line 441
    .line 442
    invoke-virtual {v11, v3}, Ll2/t;->Y(I)V

    .line 443
    .line 444
    .line 445
    sget-object v3, Lxf0/h0;->l:Lxf0/h0;

    .line 446
    .line 447
    invoke-virtual {v3, v11}, Lxf0/h0;->a(Ll2/o;)J

    .line 448
    .line 449
    .line 450
    move-result-wide v21

    .line 451
    invoke-virtual {v11, v2}, Ll2/t;->q(Z)V

    .line 452
    .line 453
    .line 454
    goto/16 :goto_7

    .line 455
    .line 456
    :goto_9
    if-eqz v18, :cond_11

    .line 457
    .line 458
    const v3, -0x3a1d8d72

    .line 459
    .line 460
    .line 461
    invoke-virtual {v11, v3}, Ll2/t;->Y(I)V

    .line 462
    .line 463
    .line 464
    invoke-virtual {v11, v6}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 465
    .line 466
    .line 467
    move-result-object v3

    .line 468
    check-cast v3, Lj91/e;

    .line 469
    .line 470
    invoke-virtual {v3}, Lj91/e;->r()J

    .line 471
    .line 472
    .line 473
    move-result-wide v21

    .line 474
    invoke-virtual {v11, v2}, Ll2/t;->q(Z)V

    .line 475
    .line 476
    .line 477
    :goto_a
    move-object/from16 v25, v17

    .line 478
    .line 479
    move-wide/from16 v34, v21

    .line 480
    .line 481
    goto :goto_b

    .line 482
    :cond_11
    const v3, -0x3a1d8773

    .line 483
    .line 484
    .line 485
    invoke-virtual {v11, v3}, Ll2/t;->Y(I)V

    .line 486
    .line 487
    .line 488
    invoke-virtual {v11, v6}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 489
    .line 490
    .line 491
    move-result-object v3

    .line 492
    check-cast v3, Lj91/e;

    .line 493
    .line 494
    invoke-virtual {v3}, Lj91/e;->s()J

    .line 495
    .line 496
    .line 497
    move-result-wide v21

    .line 498
    invoke-virtual {v11, v2}, Ll2/t;->q(Z)V

    .line 499
    .line 500
    .line 501
    goto :goto_a

    .line 502
    :goto_b
    invoke-direct/range {v25 .. v35}, Lxf0/w0;-><init>(JJJJJ)V

    .line 503
    .line 504
    .line 505
    move-object/from16 v17, v25

    .line 506
    .line 507
    iget-object v2, v0, Ld00/l;->f:Ld00/a;

    .line 508
    .line 509
    iget-object v3, v2, Ld00/a;->c:Lay0/a;

    .line 510
    .line 511
    if-nez v18, :cond_12

    .line 512
    .line 513
    if-nez v7, :cond_12

    .line 514
    .line 515
    goto :goto_c

    .line 516
    :cond_12
    const/4 v3, 0x0

    .line 517
    :goto_c
    iget-object v6, v2, Ld00/a;->d:Lay0/a;

    .line 518
    .line 519
    if-nez v18, :cond_13

    .line 520
    .line 521
    if-nez v7, :cond_13

    .line 522
    .line 523
    move-object/from16 v19, v6

    .line 524
    .line 525
    goto :goto_d

    .line 526
    :cond_13
    const/16 v19, 0x0

    .line 527
    .line 528
    :goto_d
    iget-object v6, v2, Ld00/a;->h:Lay0/a;

    .line 529
    .line 530
    move-object/from16 v18, v3

    .line 531
    .line 532
    iget-boolean v3, v8, Lc00/v0;->e:Z

    .line 533
    .line 534
    if-eqz v3, :cond_14

    .line 535
    .line 536
    move-object/from16 v22, v6

    .line 537
    .line 538
    goto :goto_e

    .line 539
    :cond_14
    const/16 v22, 0x0

    .line 540
    .line 541
    :goto_e
    const/4 v3, 0x3

    .line 542
    const/4 v6, 0x0

    .line 543
    invoke-static {v9, v6, v3}, Landroidx/compose/foundation/layout/d;->v(Lx2/s;Lx2/j;I)Lx2/s;

    .line 544
    .line 545
    .line 546
    move-result-object v6

    .line 547
    iget-object v8, v8, Lc00/v0;->f:Lvf0/g;

    .line 548
    .line 549
    new-instance v3, Lb50/c;

    .line 550
    .line 551
    move-object/from16 v21, v6

    .line 552
    .line 553
    const/16 v6, 0x8

    .line 554
    .line 555
    invoke-direct {v3, v1, v6}, Lb50/c;-><init>(Ljava/lang/Object;I)V

    .line 556
    .line 557
    .line 558
    const v6, 0x75b77eb5

    .line 559
    .line 560
    .line 561
    invoke-static {v6, v11, v3}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 562
    .line 563
    .line 564
    move-result-object v23

    .line 565
    sget-object v27, Ld00/o;->d:Lt2/b;

    .line 566
    .line 567
    const/16 v31, 0x6

    .line 568
    .line 569
    const v32, 0x40200

    .line 570
    .line 571
    .line 572
    move-object v3, v9

    .line 573
    move-object/from16 v9, v21

    .line 574
    .line 575
    move/from16 v21, v13

    .line 576
    .line 577
    const/high16 v13, 0x3fc00000    # 1.5f

    .line 578
    .line 579
    move-object/from16 v28, v11

    .line 580
    .line 581
    move v11, v14

    .line 582
    const/16 v14, 0x10

    .line 583
    .line 584
    move-object v6, v7

    .line 585
    move-object/from16 v7, v16

    .line 586
    .line 587
    const/16 v16, 0x0

    .line 588
    .line 589
    const/16 v25, 0x0

    .line 590
    .line 591
    const-string v26, "climate_control_"

    .line 592
    .line 593
    const v29, 0xd81180

    .line 594
    .line 595
    .line 596
    const/high16 v30, 0x30180000

    .line 597
    .line 598
    move-object/from16 v36, v10

    .line 599
    .line 600
    move-object v10, v8

    .line 601
    move-object/from16 v8, v36

    .line 602
    .line 603
    invoke-static/range {v7 .. v32}, Lxf0/i0;->s(Ljava/lang/String;Ljava/lang/String;Lx2/s;Lvf0/g;FZFIZFLxf0/w0;Lay0/a;Lay0/a;ZZLay0/a;Lay0/o;ILjava/lang/Integer;Ljava/lang/String;Lay0/o;Ll2/o;IIII)V

    .line 604
    .line 605
    .line 606
    move-object/from16 v11, v28

    .line 607
    .line 608
    iget-boolean v7, v1, Lc00/y0;->v:Z

    .line 609
    .line 610
    if-nez v7, :cond_17

    .line 611
    .line 612
    sget-object v7, Lc00/x0;->e:Lc00/x0;

    .line 613
    .line 614
    if-ne v4, v7, :cond_15

    .line 615
    .line 616
    goto :goto_f

    .line 617
    :cond_15
    if-nez v6, :cond_17

    .line 618
    .line 619
    if-ne v4, v5, :cond_16

    .line 620
    .line 621
    goto :goto_f

    .line 622
    :cond_16
    const/4 v5, 0x0

    .line 623
    goto :goto_11

    .line 624
    :cond_17
    :goto_f
    sget-object v4, Lc00/w0;->e:Lc00/w0;

    .line 625
    .line 626
    if-eq v6, v4, :cond_16

    .line 627
    .line 628
    const v4, 0x36edaec5

    .line 629
    .line 630
    .line 631
    invoke-virtual {v11, v4}, Ll2/t;->Y(I)V

    .line 632
    .line 633
    .line 634
    iget-object v4, v2, Ld00/a;->g:Lay0/a;

    .line 635
    .line 636
    const/4 v5, 0x0

    .line 637
    invoke-static {v1, v4, v11, v5}, Ld00/o;->D(Lc00/y0;Lay0/a;Ll2/o;I)V

    .line 638
    .line 639
    .line 640
    :goto_10
    invoke-virtual {v11, v5}, Ll2/t;->q(Z)V

    .line 641
    .line 642
    .line 643
    const/4 v1, 0x3

    .line 644
    goto :goto_12

    .line 645
    :goto_11
    const v1, 0x3664e15e

    .line 646
    .line 647
    .line 648
    invoke-virtual {v11, v1}, Ll2/t;->Y(I)V

    .line 649
    .line 650
    .line 651
    goto :goto_10

    .line 652
    :goto_12
    invoke-static {v3, v1}, Landroidx/compose/foundation/layout/d;->u(Lx2/s;I)Lx2/s;

    .line 653
    .line 654
    .line 655
    move-result-object v8

    .line 656
    iget-object v9, v2, Ld00/a;->j:Lay0/k;

    .line 657
    .line 658
    iget-object v10, v2, Ld00/a;->k:Lay0/n;

    .line 659
    .line 660
    const/16 v12, 0x30

    .line 661
    .line 662
    iget-object v7, v0, Ld00/l;->g:Lc00/n1;

    .line 663
    .line 664
    invoke-static/range {v7 .. v12}, Ld00/o;->z(Lc00/n1;Lx2/s;Lay0/k;Lay0/n;Ll2/o;I)V

    .line 665
    .line 666
    .line 667
    invoke-virtual {v11, v5}, Ll2/t;->q(Z)V

    .line 668
    .line 669
    .line 670
    :goto_13
    sget-object v0, Lj91/a;->a:Ll2/u2;

    .line 671
    .line 672
    invoke-virtual {v11, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 673
    .line 674
    .line 675
    move-result-object v0

    .line 676
    check-cast v0, Lj91/c;

    .line 677
    .line 678
    iget v0, v0, Lj91/c;->f:F

    .line 679
    .line 680
    const/4 v1, 0x1

    .line 681
    invoke-static {v3, v0, v11, v1}, Lvj/b;->z(Lx2/p;FLl2/t;Z)V

    .line 682
    .line 683
    .line 684
    goto :goto_14

    .line 685
    :cond_18
    invoke-virtual {v11}, Ll2/t;->R()V

    .line 686
    .line 687
    .line 688
    :goto_14
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 689
    .line 690
    return-object v0

    .line 691
    :pswitch_0
    move-object/from16 v4, p1

    .line 692
    .line 693
    check-cast v4, Lk1/z0;

    .line 694
    .line 695
    move-object/from16 v1, p2

    .line 696
    .line 697
    check-cast v1, Ll2/o;

    .line 698
    .line 699
    move-object/from16 v2, p3

    .line 700
    .line 701
    check-cast v2, Ljava/lang/Integer;

    .line 702
    .line 703
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 704
    .line 705
    .line 706
    move-result v2

    .line 707
    const-string v3, "paddingValues"

    .line 708
    .line 709
    invoke-static {v4, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 710
    .line 711
    .line 712
    and-int/lit8 v3, v2, 0x6

    .line 713
    .line 714
    if-nez v3, :cond_1a

    .line 715
    .line 716
    move-object v3, v1

    .line 717
    check-cast v3, Ll2/t;

    .line 718
    .line 719
    invoke-virtual {v3, v4}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 720
    .line 721
    .line 722
    move-result v3

    .line 723
    if-eqz v3, :cond_19

    .line 724
    .line 725
    const/4 v3, 0x4

    .line 726
    goto :goto_15

    .line 727
    :cond_19
    const/4 v3, 0x2

    .line 728
    :goto_15
    or-int/2addr v2, v3

    .line 729
    :cond_1a
    and-int/lit8 v3, v2, 0x13

    .line 730
    .line 731
    const/16 v5, 0x12

    .line 732
    .line 733
    if-eq v3, v5, :cond_1b

    .line 734
    .line 735
    const/4 v3, 0x1

    .line 736
    goto :goto_16

    .line 737
    :cond_1b
    const/4 v3, 0x0

    .line 738
    :goto_16
    and-int/lit8 v5, v2, 0x1

    .line 739
    .line 740
    check-cast v1, Ll2/t;

    .line 741
    .line 742
    invoke-virtual {v1, v5, v3}, Ll2/t;->O(IZ)Z

    .line 743
    .line 744
    .line 745
    move-result v3

    .line 746
    if-eqz v3, :cond_1c

    .line 747
    .line 748
    shl-int/lit8 v2, v2, 0x9

    .line 749
    .line 750
    and-int/lit16 v6, v2, 0x1c00

    .line 751
    .line 752
    move-object v5, v1

    .line 753
    iget-object v1, v0, Ld00/l;->e:Lc00/y0;

    .line 754
    .line 755
    iget-object v2, v0, Ld00/l;->g:Lc00/n1;

    .line 756
    .line 757
    iget-object v3, v0, Ld00/l;->f:Ld00/a;

    .line 758
    .line 759
    invoke-static/range {v1 .. v6}, Ld00/o;->h(Lc00/y0;Lc00/n1;Ld00/a;Lk1/z0;Ll2/o;I)V

    .line 760
    .line 761
    .line 762
    goto :goto_17

    .line 763
    :cond_1c
    move-object v5, v1

    .line 764
    invoke-virtual {v5}, Ll2/t;->R()V

    .line 765
    .line 766
    .line 767
    :goto_17
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 768
    .line 769
    return-object v0

    .line 770
    nop

    .line 771
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
