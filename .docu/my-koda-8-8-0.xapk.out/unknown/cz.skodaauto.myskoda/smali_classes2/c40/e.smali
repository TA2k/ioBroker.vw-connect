.class public final Lc40/e;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:Ll2/b1;

.field public final synthetic h:Lz4/k;

.field public final synthetic i:Lay0/a;

.field public final synthetic j:Lay0/a;

.field public final synthetic k:Lay0/a;


# direct methods
.method public synthetic constructor <init>(Ll2/b1;Lz4/k;Lay0/a;Lay0/a;Lay0/a;I)V
    .locals 0

    .line 1
    iput p6, p0, Lc40/e;->f:I

    .line 2
    .line 3
    iput-object p1, p0, Lc40/e;->g:Ll2/b1;

    .line 4
    .line 5
    iput-object p2, p0, Lc40/e;->h:Lz4/k;

    .line 6
    .line 7
    iput-object p3, p0, Lc40/e;->i:Lay0/a;

    .line 8
    .line 9
    iput-object p4, p0, Lc40/e;->j:Lay0/a;

    .line 10
    .line 11
    iput-object p5, p0, Lc40/e;->k:Lay0/a;

    .line 12
    .line 13
    const/4 p1, 0x2

    .line 14
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 15
    .line 16
    .line 17
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 36

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lc40/e;->f:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    move-object/from16 v1, p1

    .line 9
    .line 10
    check-cast v1, Ll2/o;

    .line 11
    .line 12
    move-object/from16 v2, p2

    .line 13
    .line 14
    check-cast v2, Ljava/lang/Number;

    .line 15
    .line 16
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 17
    .line 18
    .line 19
    move-result v2

    .line 20
    and-int/lit8 v2, v2, 0x3

    .line 21
    .line 22
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 23
    .line 24
    const/4 v4, 0x2

    .line 25
    if-ne v2, v4, :cond_1

    .line 26
    .line 27
    move-object v2, v1

    .line 28
    check-cast v2, Ll2/t;

    .line 29
    .line 30
    invoke-virtual {v2}, Ll2/t;->A()Z

    .line 31
    .line 32
    .line 33
    move-result v5

    .line 34
    if-nez v5, :cond_0

    .line 35
    .line 36
    goto :goto_0

    .line 37
    :cond_0
    invoke-virtual {v2}, Ll2/t;->R()V

    .line 38
    .line 39
    .line 40
    move-object/from16 v28, v3

    .line 41
    .line 42
    goto/16 :goto_1

    .line 43
    .line 44
    :cond_1
    :goto_0
    iget-object v2, v0, Lc40/e;->g:Ll2/b1;

    .line 45
    .line 46
    invoke-interface {v2, v3}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 47
    .line 48
    .line 49
    iget-object v2, v0, Lc40/e;->h:Lz4/k;

    .line 50
    .line 51
    iget v5, v2, Lz4/k;->b:I

    .line 52
    .line 53
    invoke-virtual {v2}, Lz4/k;->e()V

    .line 54
    .line 55
    .line 56
    move-object v11, v1

    .line 57
    check-cast v11, Ll2/t;

    .line 58
    .line 59
    const v1, -0x6a3eb2d2

    .line 60
    .line 61
    .line 62
    invoke-virtual {v11, v1}, Ll2/t;->Y(I)V

    .line 63
    .line 64
    .line 65
    invoke-virtual {v2}, Lz4/k;->d()Lt1/j0;

    .line 66
    .line 67
    .line 68
    move-result-object v1

    .line 69
    iget-object v1, v1, Lt1/j0;->e:Ljava/lang/Object;

    .line 70
    .line 71
    check-cast v1, Lz4/k;

    .line 72
    .line 73
    invoke-virtual {v1}, Lz4/k;->c()Lz4/f;

    .line 74
    .line 75
    .line 76
    move-result-object v14

    .line 77
    invoke-virtual {v1}, Lz4/k;->c()Lz4/f;

    .line 78
    .line 79
    .line 80
    move-result-object v15

    .line 81
    invoke-virtual {v1}, Lz4/k;->c()Lz4/f;

    .line 82
    .line 83
    .line 84
    move-result-object v6

    .line 85
    invoke-virtual {v1}, Lz4/k;->c()Lz4/f;

    .line 86
    .line 87
    .line 88
    move-result-object v7

    .line 89
    invoke-virtual {v1}, Lz4/k;->c()Lz4/f;

    .line 90
    .line 91
    .line 92
    move-result-object v1

    .line 93
    const v8, 0x7f08034a

    .line 94
    .line 95
    .line 96
    const/4 v9, 0x0

    .line 97
    invoke-static {v8, v9, v11}, Ljp/fa;->b(IILl2/o;)Li3/c;

    .line 98
    .line 99
    .line 100
    move-result-object v8

    .line 101
    invoke-static {v11}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 102
    .line 103
    .line 104
    move-result-object v10

    .line 105
    invoke-virtual {v10}, Lj91/e;->j()J

    .line 106
    .line 107
    .line 108
    move-result-wide v12

    .line 109
    const/16 v10, 0x14

    .line 110
    .line 111
    int-to-float v10, v10

    .line 112
    sget-object v4, Lx2/p;->b:Lx2/p;

    .line 113
    .line 114
    invoke-static {v4, v10}, Landroidx/compose/foundation/layout/d;->n(Lx2/s;F)Lx2/s;

    .line 115
    .line 116
    .line 117
    move-result-object v9

    .line 118
    move-object/from16 v28, v3

    .line 119
    .line 120
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 121
    .line 122
    .line 123
    move-result-object v3

    .line 124
    move-object/from16 v16, v7

    .line 125
    .line 126
    sget-object v7, Ll2/n;->a:Ll2/x0;

    .line 127
    .line 128
    if-ne v3, v7, :cond_2

    .line 129
    .line 130
    sget-object v3, Luz/r;->e:Luz/r;

    .line 131
    .line 132
    invoke-virtual {v11, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 133
    .line 134
    .line 135
    :cond_2
    check-cast v3, Lay0/k;

    .line 136
    .line 137
    invoke-static {v9, v14, v3}, Lz4/k;->b(Lx2/s;Lz4/f;Lay0/k;)Lx2/s;

    .line 138
    .line 139
    .line 140
    move-result-object v3

    .line 141
    move-wide/from16 v34, v12

    .line 142
    .line 143
    move v13, v10

    .line 144
    move-wide/from16 v9, v34

    .line 145
    .line 146
    const/16 v12, 0x30

    .line 147
    .line 148
    move/from16 v17, v13

    .line 149
    .line 150
    const/4 v13, 0x0

    .line 151
    move-object/from16 v18, v7

    .line 152
    .line 153
    const/4 v7, 0x0

    .line 154
    move-object/from16 p2, v8

    .line 155
    .line 156
    move-object v8, v3

    .line 157
    move-object v3, v6

    .line 158
    move-object/from16 v6, p2

    .line 159
    .line 160
    move-object/from16 v29, v2

    .line 161
    .line 162
    move/from16 p2, v5

    .line 163
    .line 164
    move-object/from16 v5, v16

    .line 165
    .line 166
    move/from16 v30, v17

    .line 167
    .line 168
    move-object/from16 v2, v18

    .line 169
    .line 170
    invoke-static/range {v6 .. v13}, Lh2/f5;->a(Li3/c;Ljava/lang/String;Lx2/s;JLl2/o;II)V

    .line 171
    .line 172
    .line 173
    const v6, 0x7f120437

    .line 174
    .line 175
    .line 176
    invoke-static {v11, v6}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 177
    .line 178
    .line 179
    move-result-object v6

    .line 180
    invoke-static {v11}, Llp/nb;->c(Ll2/o;)Lj91/f;

    .line 181
    .line 182
    .line 183
    move-result-object v7

    .line 184
    invoke-virtual {v7}, Lj91/f;->m()Lg4/p0;

    .line 185
    .line 186
    .line 187
    move-result-object v7

    .line 188
    invoke-static {v11}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 189
    .line 190
    .line 191
    move-result-object v8

    .line 192
    invoke-virtual {v8}, Lj91/e;->s()J

    .line 193
    .line 194
    .line 195
    move-result-wide v9

    .line 196
    invoke-static {v11}, Llp/nb;->b(Ll2/o;)Lj91/c;

    .line 197
    .line 198
    .line 199
    move-result-object v8

    .line 200
    iget v8, v8, Lj91/c;->b:F

    .line 201
    .line 202
    const/4 v12, 0x0

    .line 203
    const/4 v13, 0x2

    .line 204
    invoke-static {v4, v8, v12, v13}, Landroidx/compose/foundation/layout/a;->o(Lx2/s;FFI)Lx2/s;

    .line 205
    .line 206
    .line 207
    move-result-object v8

    .line 208
    const-string v12, "charging_history_discrepancy_banner_title"

    .line 209
    .line 210
    invoke-static {v8, v12}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 211
    .line 212
    .line 213
    move-result-object v8

    .line 214
    invoke-virtual {v11, v14}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 215
    .line 216
    .line 217
    move-result v12

    .line 218
    invoke-virtual {v11, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 219
    .line 220
    .line 221
    move-result v13

    .line 222
    or-int/2addr v12, v13

    .line 223
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 224
    .line 225
    .line 226
    move-result-object v13

    .line 227
    if-nez v12, :cond_3

    .line 228
    .line 229
    if-ne v13, v2, :cond_4

    .line 230
    .line 231
    :cond_3
    new-instance v13, Luz/s;

    .line 232
    .line 233
    const/4 v12, 0x0

    .line 234
    invoke-direct {v13, v14, v1, v12}, Luz/s;-><init>(Lz4/f;Lz4/f;I)V

    .line 235
    .line 236
    .line 237
    invoke-virtual {v11, v13}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 238
    .line 239
    .line 240
    :cond_4
    check-cast v13, Lay0/k;

    .line 241
    .line 242
    invoke-static {v8, v15, v13}, Lz4/k;->b(Lx2/s;Lz4/f;Lay0/k;)Lx2/s;

    .line 243
    .line 244
    .line 245
    move-result-object v8

    .line 246
    const/16 v26, 0x0

    .line 247
    .line 248
    const v27, 0xfff0

    .line 249
    .line 250
    .line 251
    move-object/from16 v24, v11

    .line 252
    .line 253
    const-wide/16 v11, 0x0

    .line 254
    .line 255
    const/4 v13, 0x0

    .line 256
    move-object/from16 v16, v14

    .line 257
    .line 258
    move-object/from16 v17, v15

    .line 259
    .line 260
    const-wide/16 v14, 0x0

    .line 261
    .line 262
    move-object/from16 v18, v16

    .line 263
    .line 264
    const/16 v16, 0x0

    .line 265
    .line 266
    move-object/from16 v19, v17

    .line 267
    .line 268
    const/16 v17, 0x0

    .line 269
    .line 270
    move-object/from16 v20, v18

    .line 271
    .line 272
    move-object/from16 v21, v19

    .line 273
    .line 274
    const-wide/16 v18, 0x0

    .line 275
    .line 276
    move-object/from16 v22, v20

    .line 277
    .line 278
    const/16 v20, 0x0

    .line 279
    .line 280
    move-object/from16 v23, v21

    .line 281
    .line 282
    const/16 v21, 0x0

    .line 283
    .line 284
    move-object/from16 v25, v22

    .line 285
    .line 286
    const/16 v22, 0x0

    .line 287
    .line 288
    move-object/from16 v31, v23

    .line 289
    .line 290
    const/16 v23, 0x0

    .line 291
    .line 292
    move-object/from16 v32, v25

    .line 293
    .line 294
    const/16 v25, 0x0

    .line 295
    .line 296
    move-object/from16 p1, v1

    .line 297
    .line 298
    move-object/from16 v1, v31

    .line 299
    .line 300
    invoke-static/range {v6 .. v27}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 301
    .line 302
    .line 303
    move-object/from16 v11, v24

    .line 304
    .line 305
    const v6, 0x7f12042b

    .line 306
    .line 307
    .line 308
    invoke-static {v11, v6}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 309
    .line 310
    .line 311
    move-result-object v6

    .line 312
    invoke-static {v11}, Llp/nb;->c(Ll2/o;)Lj91/f;

    .line 313
    .line 314
    .line 315
    move-result-object v7

    .line 316
    invoke-virtual {v7}, Lj91/f;->a()Lg4/p0;

    .line 317
    .line 318
    .line 319
    move-result-object v7

    .line 320
    invoke-static {v11}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 321
    .line 322
    .line 323
    move-result-object v8

    .line 324
    invoke-virtual {v8}, Lj91/e;->s()J

    .line 325
    .line 326
    .line 327
    move-result-wide v9

    .line 328
    const-string v8, "charging_history_discrepancy_banner_text"

    .line 329
    .line 330
    invoke-static {v4, v8}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 331
    .line 332
    .line 333
    move-result-object v12

    .line 334
    invoke-static {v11}, Llp/nb;->b(Ll2/o;)Lj91/c;

    .line 335
    .line 336
    .line 337
    move-result-object v8

    .line 338
    iget v14, v8, Lj91/c;->b:F

    .line 339
    .line 340
    invoke-static {v11}, Llp/nb;->b(Ll2/o;)Lj91/c;

    .line 341
    .line 342
    .line 343
    move-result-object v8

    .line 344
    iget v13, v8, Lj91/c;->b:F

    .line 345
    .line 346
    invoke-static {v11}, Llp/nb;->b(Ll2/o;)Lj91/c;

    .line 347
    .line 348
    .line 349
    move-result-object v8

    .line 350
    iget v15, v8, Lj91/c;->b:F

    .line 351
    .line 352
    const/16 v16, 0x0

    .line 353
    .line 354
    const/16 v17, 0x8

    .line 355
    .line 356
    invoke-static/range {v12 .. v17}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 357
    .line 358
    .line 359
    move-result-object v8

    .line 360
    invoke-virtual {v11, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 361
    .line 362
    .line 363
    move-result v12

    .line 364
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 365
    .line 366
    .line 367
    move-result-object v13

    .line 368
    if-nez v12, :cond_5

    .line 369
    .line 370
    if-ne v13, v2, :cond_6

    .line 371
    .line 372
    :cond_5
    new-instance v13, Lc40/g;

    .line 373
    .line 374
    const/4 v12, 0x7

    .line 375
    invoke-direct {v13, v1, v12}, Lc40/g;-><init>(Lz4/f;I)V

    .line 376
    .line 377
    .line 378
    invoke-virtual {v11, v13}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 379
    .line 380
    .line 381
    :cond_6
    check-cast v13, Lay0/k;

    .line 382
    .line 383
    invoke-static {v8, v5, v13}, Lz4/k;->b(Lx2/s;Lz4/f;Lay0/k;)Lx2/s;

    .line 384
    .line 385
    .line 386
    move-result-object v8

    .line 387
    const/16 v26, 0x0

    .line 388
    .line 389
    const v27, 0xfff0

    .line 390
    .line 391
    .line 392
    move-object/from16 v24, v11

    .line 393
    .line 394
    const-wide/16 v11, 0x0

    .line 395
    .line 396
    const/4 v13, 0x0

    .line 397
    const-wide/16 v14, 0x0

    .line 398
    .line 399
    const/16 v16, 0x0

    .line 400
    .line 401
    const/16 v17, 0x0

    .line 402
    .line 403
    const-wide/16 v18, 0x0

    .line 404
    .line 405
    const/16 v20, 0x0

    .line 406
    .line 407
    const/16 v21, 0x0

    .line 408
    .line 409
    const/16 v22, 0x0

    .line 410
    .line 411
    const/16 v23, 0x0

    .line 412
    .line 413
    const/16 v25, 0x0

    .line 414
    .line 415
    invoke-static/range {v6 .. v27}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 416
    .line 417
    .line 418
    move-object/from16 v11, v24

    .line 419
    .line 420
    const v1, 0x7f12042d

    .line 421
    .line 422
    .line 423
    invoke-static {v11, v1}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 424
    .line 425
    .line 426
    move-result-object v10

    .line 427
    invoke-static {v11}, Llp/nb;->b(Ll2/o;)Lj91/c;

    .line 428
    .line 429
    .line 430
    move-result-object v1

    .line 431
    iget v1, v1, Lj91/c;->c:F

    .line 432
    .line 433
    invoke-static {v11}, Llp/nb;->b(Ll2/o;)Lj91/c;

    .line 434
    .line 435
    .line 436
    move-result-object v6

    .line 437
    iget v6, v6, Lj91/c;->b:F

    .line 438
    .line 439
    const/16 v20, 0x0

    .line 440
    .line 441
    const/16 v21, 0xc

    .line 442
    .line 443
    const/16 v19, 0x0

    .line 444
    .line 445
    move/from16 v18, v1

    .line 446
    .line 447
    move-object/from16 v16, v4

    .line 448
    .line 449
    move/from16 v17, v6

    .line 450
    .line 451
    invoke-static/range {v16 .. v21}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 452
    .line 453
    .line 454
    move-result-object v1

    .line 455
    invoke-virtual {v11, v5}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 456
    .line 457
    .line 458
    move-result v6

    .line 459
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 460
    .line 461
    .line 462
    move-result-object v7

    .line 463
    if-nez v6, :cond_7

    .line 464
    .line 465
    if-ne v7, v2, :cond_8

    .line 466
    .line 467
    :cond_7
    new-instance v7, Lc40/g;

    .line 468
    .line 469
    const/16 v6, 0x8

    .line 470
    .line 471
    invoke-direct {v7, v5, v6}, Lc40/g;-><init>(Lz4/f;I)V

    .line 472
    .line 473
    .line 474
    invoke-virtual {v11, v7}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 475
    .line 476
    .line 477
    :cond_8
    check-cast v7, Lay0/k;

    .line 478
    .line 479
    invoke-static {v1, v3, v7}, Lz4/k;->b(Lx2/s;Lz4/f;Lay0/k;)Lx2/s;

    .line 480
    .line 481
    .line 482
    move-result-object v12

    .line 483
    const/4 v6, 0x0

    .line 484
    const/16 v7, 0x18

    .line 485
    .line 486
    iget-object v8, v0, Lc40/e;->j:Lay0/a;

    .line 487
    .line 488
    const/4 v9, 0x0

    .line 489
    const/4 v13, 0x0

    .line 490
    invoke-static/range {v6 .. v13}, Li91/j0;->w0(IILay0/a;Ljava/lang/Integer;Ljava/lang/String;Ll2/o;Lx2/s;Z)V

    .line 491
    .line 492
    .line 493
    const v1, 0x7f080359

    .line 494
    .line 495
    .line 496
    const/4 v3, 0x0

    .line 497
    invoke-static {v1, v3, v11}, Ljp/fa;->b(IILl2/o;)Li3/c;

    .line 498
    .line 499
    .line 500
    move-result-object v6

    .line 501
    invoke-static {v11}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 502
    .line 503
    .line 504
    move-result-object v1

    .line 505
    invoke-virtual {v1}, Lj91/e;->q()J

    .line 506
    .line 507
    .line 508
    move-result-wide v9

    .line 509
    const-string v1, "charging_history_discrepancy_banner_close"

    .line 510
    .line 511
    invoke-static {v4, v1}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 512
    .line 513
    .line 514
    move-result-object v1

    .line 515
    move/from16 v13, v30

    .line 516
    .line 517
    invoke-static {v1, v13}, Landroidx/compose/foundation/layout/d;->n(Lx2/s;F)Lx2/s;

    .line 518
    .line 519
    .line 520
    move-result-object v1

    .line 521
    move-object/from16 v3, v32

    .line 522
    .line 523
    invoke-virtual {v11, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 524
    .line 525
    .line 526
    move-result v4

    .line 527
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 528
    .line 529
    .line 530
    move-result-object v5

    .line 531
    if-nez v4, :cond_9

    .line 532
    .line 533
    if-ne v5, v2, :cond_a

    .line 534
    .line 535
    :cond_9
    new-instance v5, Lc40/g;

    .line 536
    .line 537
    const/16 v4, 0x9

    .line 538
    .line 539
    invoke-direct {v5, v3, v4}, Lc40/g;-><init>(Lz4/f;I)V

    .line 540
    .line 541
    .line 542
    invoke-virtual {v11, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 543
    .line 544
    .line 545
    :cond_a
    check-cast v5, Lay0/k;

    .line 546
    .line 547
    move-object/from16 v3, p1

    .line 548
    .line 549
    invoke-static {v1, v3, v5}, Lz4/k;->b(Lx2/s;Lz4/f;Lay0/k;)Lx2/s;

    .line 550
    .line 551
    .line 552
    move-result-object v12

    .line 553
    iget-object v1, v0, Lc40/e;->k:Lay0/a;

    .line 554
    .line 555
    invoke-virtual {v11, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 556
    .line 557
    .line 558
    move-result v3

    .line 559
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 560
    .line 561
    .line 562
    move-result-object v4

    .line 563
    if-nez v3, :cond_b

    .line 564
    .line 565
    if-ne v4, v2, :cond_c

    .line 566
    .line 567
    :cond_b
    new-instance v4, Lep0/f;

    .line 568
    .line 569
    const/16 v2, 0x12

    .line 570
    .line 571
    invoke-direct {v4, v1, v2}, Lep0/f;-><init>(Ljava/lang/Object;I)V

    .line 572
    .line 573
    .line 574
    invoke-virtual {v11, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 575
    .line 576
    .line 577
    :cond_c
    move-object/from16 v16, v4

    .line 578
    .line 579
    check-cast v16, Lay0/a;

    .line 580
    .line 581
    const/16 v17, 0xf

    .line 582
    .line 583
    const/4 v13, 0x0

    .line 584
    const/4 v14, 0x0

    .line 585
    const/4 v15, 0x0

    .line 586
    invoke-static/range {v12 .. v17}, Landroidx/compose/foundation/a;->f(Lx2/s;ZLjava/lang/String;Ld4/i;Lay0/a;I)Lx2/s;

    .line 587
    .line 588
    .line 589
    move-result-object v8

    .line 590
    const/16 v12, 0x30

    .line 591
    .line 592
    const/4 v7, 0x0

    .line 593
    invoke-static/range {v6 .. v13}, Lh2/f5;->a(Li3/c;Ljava/lang/String;Lx2/s;JLl2/o;II)V

    .line 594
    .line 595
    .line 596
    const/4 v3, 0x0

    .line 597
    invoke-virtual {v11, v3}, Ll2/t;->q(Z)V

    .line 598
    .line 599
    .line 600
    move-object/from16 v1, v29

    .line 601
    .line 602
    iget v1, v1, Lz4/k;->b:I

    .line 603
    .line 604
    move/from16 v2, p2

    .line 605
    .line 606
    if-eq v1, v2, :cond_d

    .line 607
    .line 608
    iget-object v0, v0, Lc40/e;->i:Lay0/a;

    .line 609
    .line 610
    invoke-static {v0, v11}, Ll2/l0;->g(Lay0/a;Ll2/o;)V

    .line 611
    .line 612
    .line 613
    :cond_d
    :goto_1
    return-object v28

    .line 614
    :pswitch_0
    move-object/from16 v1, p1

    .line 615
    .line 616
    check-cast v1, Ll2/o;

    .line 617
    .line 618
    move-object/from16 v2, p2

    .line 619
    .line 620
    check-cast v2, Ljava/lang/Number;

    .line 621
    .line 622
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 623
    .line 624
    .line 625
    move-result v2

    .line 626
    const/4 v3, 0x3

    .line 627
    and-int/2addr v2, v3

    .line 628
    const/4 v4, 0x2

    .line 629
    sget-object v5, Llx0/b0;->a:Llx0/b0;

    .line 630
    .line 631
    if-ne v2, v4, :cond_f

    .line 632
    .line 633
    move-object v2, v1

    .line 634
    check-cast v2, Ll2/t;

    .line 635
    .line 636
    invoke-virtual {v2}, Ll2/t;->A()Z

    .line 637
    .line 638
    .line 639
    move-result v4

    .line 640
    if-nez v4, :cond_e

    .line 641
    .line 642
    goto :goto_2

    .line 643
    :cond_e
    invoke-virtual {v2}, Ll2/t;->R()V

    .line 644
    .line 645
    .line 646
    move-object/from16 p2, v5

    .line 647
    .line 648
    goto/16 :goto_4

    .line 649
    .line 650
    :cond_f
    :goto_2
    iget-object v2, v0, Lc40/e;->g:Ll2/b1;

    .line 651
    .line 652
    invoke-interface {v2, v5}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 653
    .line 654
    .line 655
    iget-object v2, v0, Lc40/e;->h:Lz4/k;

    .line 656
    .line 657
    iget v4, v2, Lz4/k;->b:I

    .line 658
    .line 659
    invoke-virtual {v2}, Lz4/k;->e()V

    .line 660
    .line 661
    .line 662
    move-object v13, v1

    .line 663
    check-cast v13, Ll2/t;

    .line 664
    .line 665
    const v1, -0x340df1eb    # -3.1726634E7f

    .line 666
    .line 667
    .line 668
    invoke-virtual {v13, v1}, Ll2/t;->Y(I)V

    .line 669
    .line 670
    .line 671
    invoke-virtual {v2}, Lz4/k;->d()Lt1/j0;

    .line 672
    .line 673
    .line 674
    move-result-object v1

    .line 675
    iget-object v1, v1, Lt1/j0;->e:Ljava/lang/Object;

    .line 676
    .line 677
    check-cast v1, Lz4/k;

    .line 678
    .line 679
    invoke-virtual {v1}, Lz4/k;->c()Lz4/f;

    .line 680
    .line 681
    .line 682
    move-result-object v6

    .line 683
    invoke-virtual {v1}, Lz4/k;->c()Lz4/f;

    .line 684
    .line 685
    .line 686
    move-result-object v7

    .line 687
    invoke-virtual {v1}, Lz4/k;->c()Lz4/f;

    .line 688
    .line 689
    .line 690
    move-result-object v8

    .line 691
    invoke-virtual {v1}, Lz4/k;->c()Lz4/f;

    .line 692
    .line 693
    .line 694
    move-result-object v9

    .line 695
    invoke-virtual {v1}, Lz4/k;->c()Lz4/f;

    .line 696
    .line 697
    .line 698
    move-result-object v1

    .line 699
    const v10, 0x7f080231

    .line 700
    .line 701
    .line 702
    const/4 v11, 0x0

    .line 703
    invoke-static {v10, v11, v13}, Ljp/fa;->b(IILl2/o;)Li3/c;

    .line 704
    .line 705
    .line 706
    move-result-object v10

    .line 707
    invoke-virtual {v13}, Ll2/t;->L()Ljava/lang/Object;

    .line 708
    .line 709
    .line 710
    move-result-object v12

    .line 711
    sget-object v14, Ll2/n;->a:Ll2/x0;

    .line 712
    .line 713
    if-ne v12, v14, :cond_10

    .line 714
    .line 715
    sget-object v12, Lc40/f;->e:Lc40/f;

    .line 716
    .line 717
    invoke-virtual {v13, v12}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 718
    .line 719
    .line 720
    :cond_10
    check-cast v12, Lay0/k;

    .line 721
    .line 722
    sget-object v15, Lx2/p;->b:Lx2/p;

    .line 723
    .line 724
    invoke-static {v15, v6, v12}, Lz4/k;->b(Lx2/s;Lz4/f;Lay0/k;)Lx2/s;

    .line 725
    .line 726
    .line 727
    move-result-object v6

    .line 728
    sget-object v12, Landroidx/compose/foundation/layout/d;->c:Landroidx/compose/foundation/layout/FillElement;

    .line 729
    .line 730
    invoke-interface {v6, v12}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 731
    .line 732
    .line 733
    move-result-object v6

    .line 734
    move-object/from16 v16, v14

    .line 735
    .line 736
    const/16 v14, 0x6030

    .line 737
    .line 738
    move-object/from16 v17, v15

    .line 739
    .line 740
    const/16 v15, 0x68

    .line 741
    .line 742
    move-object/from16 v18, v7

    .line 743
    .line 744
    const/4 v7, 0x0

    .line 745
    move-object/from16 v19, v9

    .line 746
    .line 747
    const/4 v9, 0x0

    .line 748
    move-object/from16 v20, v8

    .line 749
    .line 750
    move-object v8, v6

    .line 751
    move-object v6, v10

    .line 752
    sget-object v10, Lt3/j;->a:Lt3/x0;

    .line 753
    .line 754
    move/from16 v21, v11

    .line 755
    .line 756
    const/4 v11, 0x0

    .line 757
    move-object/from16 v22, v12

    .line 758
    .line 759
    const/4 v12, 0x0

    .line 760
    move-object/from16 v29, v2

    .line 761
    .line 762
    move/from16 v28, v4

    .line 763
    .line 764
    move-object/from16 p2, v5

    .line 765
    .line 766
    move-object/from16 v0, v16

    .line 767
    .line 768
    move-object/from16 v33, v17

    .line 769
    .line 770
    move-object/from16 v3, v18

    .line 771
    .line 772
    move-object/from16 v4, v19

    .line 773
    .line 774
    move-object/from16 v5, v20

    .line 775
    .line 776
    move-object/from16 v2, v22

    .line 777
    .line 778
    invoke-static/range {v6 .. v15}, Lkp/m;->a(Li3/c;Ljava/lang/String;Lx2/s;Lx2/e;Lt3/k;FLe3/m;Ll2/o;II)V

    .line 779
    .line 780
    .line 781
    invoke-virtual {v13}, Ll2/t;->L()Ljava/lang/Object;

    .line 782
    .line 783
    .line 784
    move-result-object v6

    .line 785
    if-ne v6, v0, :cond_11

    .line 786
    .line 787
    sget-object v6, Lc40/f;->f:Lc40/f;

    .line 788
    .line 789
    invoke-virtual {v13, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 790
    .line 791
    .line 792
    :cond_11
    check-cast v6, Lay0/k;

    .line 793
    .line 794
    invoke-static {v2, v3, v6}, Lz4/k;->b(Lx2/s;Lz4/f;Lay0/k;)Lx2/s;

    .line 795
    .line 796
    .line 797
    move-result-object v10

    .line 798
    const/4 v6, 0x6

    .line 799
    const/4 v7, 0x4

    .line 800
    const-string v8, "intro_player"

    .line 801
    .line 802
    const/4 v11, 0x0

    .line 803
    move-object v9, v13

    .line 804
    invoke-static/range {v6 .. v11}, Llp/qa;->a(IILjava/lang/String;Ll2/o;Lx2/s;Z)V

    .line 805
    .line 806
    .line 807
    const v2, 0x7f080237

    .line 808
    .line 809
    .line 810
    const/4 v3, 0x0

    .line 811
    invoke-static {v2, v3, v13}, Ljp/fa;->b(IILl2/o;)Li3/c;

    .line 812
    .line 813
    .line 814
    move-result-object v6

    .line 815
    sget-wide v2, Le3/s;->e:J

    .line 816
    .line 817
    new-instance v12, Le3/m;

    .line 818
    .line 819
    const/4 v7, 0x5

    .line 820
    invoke-direct {v12, v2, v3, v7}, Le3/m;-><init>(JI)V

    .line 821
    .line 822
    .line 823
    const/high16 v8, 0x3f000000    # 0.5f

    .line 824
    .line 825
    move-object/from16 v9, v33

    .line 826
    .line 827
    invoke-static {v9, v8}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 828
    .line 829
    .line 830
    move-result-object v8

    .line 831
    const/4 v10, 0x3

    .line 832
    invoke-static {v8, v10}, Landroidx/compose/foundation/layout/d;->u(Lx2/s;I)Lx2/s;

    .line 833
    .line 834
    .line 835
    move-result-object v8

    .line 836
    invoke-virtual {v13}, Ll2/t;->L()Ljava/lang/Object;

    .line 837
    .line 838
    .line 839
    move-result-object v10

    .line 840
    if-ne v10, v0, :cond_12

    .line 841
    .line 842
    sget-object v10, Lc40/f;->g:Lc40/f;

    .line 843
    .line 844
    invoke-virtual {v13, v10}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 845
    .line 846
    .line 847
    :cond_12
    check-cast v10, Lay0/k;

    .line 848
    .line 849
    invoke-static {v8, v5, v10}, Lz4/k;->b(Lx2/s;Lz4/f;Lay0/k;)Lx2/s;

    .line 850
    .line 851
    .line 852
    move-result-object v14

    .line 853
    invoke-static {v13}, Llp/nb;->b(Ll2/o;)Lj91/c;

    .line 854
    .line 855
    .line 856
    move-result-object v8

    .line 857
    iget v15, v8, Lj91/c;->e:F

    .line 858
    .line 859
    invoke-static {v13}, Llp/nb;->b(Ll2/o;)Lj91/c;

    .line 860
    .line 861
    .line 862
    move-result-object v8

    .line 863
    iget v8, v8, Lj91/c;->i:F

    .line 864
    .line 865
    const/16 v18, 0x0

    .line 866
    .line 867
    const/16 v19, 0xc

    .line 868
    .line 869
    const/16 v17, 0x0

    .line 870
    .line 871
    move/from16 v16, v8

    .line 872
    .line 873
    invoke-static/range {v14 .. v19}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 874
    .line 875
    .line 876
    move-result-object v8

    .line 877
    const v14, 0x186030

    .line 878
    .line 879
    .line 880
    const/16 v15, 0x28

    .line 881
    .line 882
    move v10, v7

    .line 883
    const/4 v7, 0x0

    .line 884
    move-object/from16 v17, v9

    .line 885
    .line 886
    const/4 v9, 0x0

    .line 887
    move v11, v10

    .line 888
    sget-object v10, Lt3/j;->d:Lt3/x0;

    .line 889
    .line 890
    move/from16 v16, v11

    .line 891
    .line 892
    const/4 v11, 0x0

    .line 893
    move-wide/from16 v18, v2

    .line 894
    .line 895
    move/from16 v2, v16

    .line 896
    .line 897
    move-object/from16 v3, v17

    .line 898
    .line 899
    invoke-static/range {v6 .. v15}, Lkp/m;->a(Li3/c;Ljava/lang/String;Lx2/s;Lx2/e;Lt3/k;FLe3/m;Ll2/o;II)V

    .line 900
    .line 901
    .line 902
    const v6, 0x7f120501

    .line 903
    .line 904
    .line 905
    invoke-static {v13, v6}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 906
    .line 907
    .line 908
    move-result-object v6

    .line 909
    invoke-static {v13}, Llp/nb;->c(Ll2/o;)Lj91/f;

    .line 910
    .line 911
    .line 912
    move-result-object v7

    .line 913
    invoke-virtual {v7}, Lj91/f;->k()Lg4/p0;

    .line 914
    .line 915
    .line 916
    move-result-object v7

    .line 917
    invoke-virtual {v13, v5}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 918
    .line 919
    .line 920
    move-result v8

    .line 921
    invoke-virtual {v13}, Ll2/t;->L()Ljava/lang/Object;

    .line 922
    .line 923
    .line 924
    move-result-object v9

    .line 925
    if-nez v8, :cond_13

    .line 926
    .line 927
    if-ne v9, v0, :cond_14

    .line 928
    .line 929
    :cond_13
    new-instance v9, Lc40/g;

    .line 930
    .line 931
    const/4 v8, 0x0

    .line 932
    invoke-direct {v9, v5, v8}, Lc40/g;-><init>(Lz4/f;I)V

    .line 933
    .line 934
    .line 935
    invoke-virtual {v13, v9}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 936
    .line 937
    .line 938
    :cond_14
    check-cast v9, Lay0/k;

    .line 939
    .line 940
    invoke-static {v3, v4, v9}, Lz4/k;->b(Lx2/s;Lz4/f;Lay0/k;)Lx2/s;

    .line 941
    .line 942
    .line 943
    move-result-object v4

    .line 944
    const/high16 v5, 0x3f800000    # 1.0f

    .line 945
    .line 946
    invoke-static {v4, v5}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 947
    .line 948
    .line 949
    move-result-object v20

    .line 950
    invoke-static {v13}, Llp/nb;->b(Ll2/o;)Lj91/c;

    .line 951
    .line 952
    .line 953
    move-result-object v4

    .line 954
    iget v4, v4, Lj91/c;->e:F

    .line 955
    .line 956
    invoke-static {v13}, Llp/nb;->b(Ll2/o;)Lj91/c;

    .line 957
    .line 958
    .line 959
    move-result-object v5

    .line 960
    iget v5, v5, Lj91/c;->e:F

    .line 961
    .line 962
    invoke-static {v13}, Llp/nb;->b(Ll2/o;)Lj91/c;

    .line 963
    .line 964
    .line 965
    move-result-object v8

    .line 966
    iget v8, v8, Lj91/c;->e:F

    .line 967
    .line 968
    const/16 v24, 0x0

    .line 969
    .line 970
    const/16 v25, 0x8

    .line 971
    .line 972
    move/from16 v21, v4

    .line 973
    .line 974
    move/from16 v22, v5

    .line 975
    .line 976
    move/from16 v23, v8

    .line 977
    .line 978
    invoke-static/range {v20 .. v25}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 979
    .line 980
    .line 981
    move-result-object v8

    .line 982
    new-instance v4, Lr4/k;

    .line 983
    .line 984
    invoke-direct {v4, v2}, Lr4/k;-><init>(I)V

    .line 985
    .line 986
    .line 987
    const/16 v26, 0x0

    .line 988
    .line 989
    const v27, 0xfbf0

    .line 990
    .line 991
    .line 992
    const-wide/16 v11, 0x0

    .line 993
    .line 994
    move-object/from16 v24, v13

    .line 995
    .line 996
    const/4 v13, 0x0

    .line 997
    const-wide/16 v14, 0x0

    .line 998
    .line 999
    const/16 v16, 0x0

    .line 1000
    .line 1001
    move-wide/from16 v9, v18

    .line 1002
    .line 1003
    const-wide/16 v18, 0x0

    .line 1004
    .line 1005
    const/16 v20, 0x0

    .line 1006
    .line 1007
    const/16 v21, 0x0

    .line 1008
    .line 1009
    const/16 v22, 0x0

    .line 1010
    .line 1011
    const/16 v23, 0x0

    .line 1012
    .line 1013
    const/16 v25, 0xc00

    .line 1014
    .line 1015
    move-object/from16 v17, v4

    .line 1016
    .line 1017
    invoke-static/range {v6 .. v27}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 1018
    .line 1019
    .line 1020
    move-object/from16 v13, v24

    .line 1021
    .line 1022
    invoke-virtual {v13}, Ll2/t;->L()Ljava/lang/Object;

    .line 1023
    .line 1024
    .line 1025
    move-result-object v2

    .line 1026
    if-ne v2, v0, :cond_15

    .line 1027
    .line 1028
    sget-object v2, Lc40/f;->h:Lc40/f;

    .line 1029
    .line 1030
    invoke-virtual {v13, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 1031
    .line 1032
    .line 1033
    :cond_15
    check-cast v2, Lay0/k;

    .line 1034
    .line 1035
    invoke-static {v3, v1, v2}, Lz4/k;->b(Lx2/s;Lz4/f;Lay0/k;)Lx2/s;

    .line 1036
    .line 1037
    .line 1038
    move-result-object v0

    .line 1039
    sget-object v1, Lk1/j;->c:Lk1/e;

    .line 1040
    .line 1041
    sget-object v2, Lx2/c;->p:Lx2/h;

    .line 1042
    .line 1043
    const/4 v4, 0x0

    .line 1044
    invoke-static {v1, v2, v13, v4}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 1045
    .line 1046
    .line 1047
    move-result-object v1

    .line 1048
    iget-wide v4, v13, Ll2/t;->T:J

    .line 1049
    .line 1050
    invoke-static {v4, v5}, Ljava/lang/Long;->hashCode(J)I

    .line 1051
    .line 1052
    .line 1053
    move-result v2

    .line 1054
    invoke-virtual {v13}, Ll2/t;->m()Ll2/p1;

    .line 1055
    .line 1056
    .line 1057
    move-result-object v4

    .line 1058
    invoke-static {v13, v0}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 1059
    .line 1060
    .line 1061
    move-result-object v0

    .line 1062
    sget-object v5, Lv3/k;->m1:Lv3/j;

    .line 1063
    .line 1064
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1065
    .line 1066
    .line 1067
    sget-object v5, Lv3/j;->b:Lv3/i;

    .line 1068
    .line 1069
    invoke-virtual {v13}, Ll2/t;->c0()V

    .line 1070
    .line 1071
    .line 1072
    iget-boolean v6, v13, Ll2/t;->S:Z

    .line 1073
    .line 1074
    if-eqz v6, :cond_16

    .line 1075
    .line 1076
    invoke-virtual {v13, v5}, Ll2/t;->l(Lay0/a;)V

    .line 1077
    .line 1078
    .line 1079
    goto :goto_3

    .line 1080
    :cond_16
    invoke-virtual {v13}, Ll2/t;->m0()V

    .line 1081
    .line 1082
    .line 1083
    :goto_3
    sget-object v5, Lv3/j;->g:Lv3/h;

    .line 1084
    .line 1085
    invoke-static {v5, v1, v13}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 1086
    .line 1087
    .line 1088
    sget-object v1, Lv3/j;->f:Lv3/h;

    .line 1089
    .line 1090
    invoke-static {v1, v4, v13}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 1091
    .line 1092
    .line 1093
    sget-object v1, Lv3/j;->j:Lv3/h;

    .line 1094
    .line 1095
    iget-boolean v4, v13, Ll2/t;->S:Z

    .line 1096
    .line 1097
    if-nez v4, :cond_17

    .line 1098
    .line 1099
    invoke-virtual {v13}, Ll2/t;->L()Ljava/lang/Object;

    .line 1100
    .line 1101
    .line 1102
    move-result-object v4

    .line 1103
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1104
    .line 1105
    .line 1106
    move-result-object v5

    .line 1107
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1108
    .line 1109
    .line 1110
    move-result v4

    .line 1111
    if-nez v4, :cond_18

    .line 1112
    .line 1113
    :cond_17
    invoke-static {v2, v13, v2, v1}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 1114
    .line 1115
    .line 1116
    :cond_18
    sget-object v1, Lv3/j;->d:Lv3/h;

    .line 1117
    .line 1118
    invoke-static {v1, v0, v13}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 1119
    .line 1120
    .line 1121
    const v0, 0x7f120500

    .line 1122
    .line 1123
    .line 1124
    invoke-static {v13, v0}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 1125
    .line 1126
    .line 1127
    move-result-object v10

    .line 1128
    const/4 v6, 0x0

    .line 1129
    const/16 v7, 0x3c

    .line 1130
    .line 1131
    move-object/from16 v0, p0

    .line 1132
    .line 1133
    iget-object v8, v0, Lc40/e;->j:Lay0/a;

    .line 1134
    .line 1135
    const/4 v9, 0x0

    .line 1136
    const/4 v12, 0x0

    .line 1137
    move-object/from16 v24, v13

    .line 1138
    .line 1139
    const/4 v13, 0x0

    .line 1140
    const/4 v14, 0x0

    .line 1141
    move-object/from16 v11, v24

    .line 1142
    .line 1143
    invoke-static/range {v6 .. v14}, Li91/j0;->X(IILay0/a;Ljava/lang/Integer;Ljava/lang/String;Ll2/o;Lx2/s;ZZ)V

    .line 1144
    .line 1145
    .line 1146
    move-object v13, v11

    .line 1147
    invoke-static {v13}, Llp/nb;->b(Ll2/o;)Lj91/c;

    .line 1148
    .line 1149
    .line 1150
    move-result-object v1

    .line 1151
    iget v1, v1, Lj91/c;->d:F

    .line 1152
    .line 1153
    const v2, 0x7f1204cf

    .line 1154
    .line 1155
    .line 1156
    invoke-static {v3, v1, v13, v2, v13}, Lvj/b;->m(Lx2/p;FLl2/t;ILl2/t;)Ljava/lang/String;

    .line 1157
    .line 1158
    .line 1159
    move-result-object v10

    .line 1160
    iget-object v8, v0, Lc40/e;->k:Lay0/a;

    .line 1161
    .line 1162
    move-object/from16 v24, v13

    .line 1163
    .line 1164
    const/4 v13, 0x0

    .line 1165
    move-object/from16 v11, v24

    .line 1166
    .line 1167
    invoke-static/range {v6 .. v14}, Li91/j0;->f0(IILay0/a;Ljava/lang/Integer;Ljava/lang/String;Ll2/o;Lx2/s;ZZ)V

    .line 1168
    .line 1169
    .line 1170
    move-object v13, v11

    .line 1171
    invoke-static {v13}, Llp/nb;->b(Ll2/o;)Lj91/c;

    .line 1172
    .line 1173
    .line 1174
    move-result-object v1

    .line 1175
    iget v1, v1, Lj91/c;->i:F

    .line 1176
    .line 1177
    invoke-static {v3, v1}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 1178
    .line 1179
    .line 1180
    move-result-object v1

    .line 1181
    invoke-static {v13, v1}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 1182
    .line 1183
    .line 1184
    const/4 v1, 0x1

    .line 1185
    invoke-virtual {v13, v1}, Ll2/t;->q(Z)V

    .line 1186
    .line 1187
    .line 1188
    const/4 v3, 0x0

    .line 1189
    invoke-virtual {v13, v3}, Ll2/t;->q(Z)V

    .line 1190
    .line 1191
    .line 1192
    move-object/from16 v1, v29

    .line 1193
    .line 1194
    iget v1, v1, Lz4/k;->b:I

    .line 1195
    .line 1196
    move/from16 v2, v28

    .line 1197
    .line 1198
    if-eq v1, v2, :cond_19

    .line 1199
    .line 1200
    iget-object v0, v0, Lc40/e;->i:Lay0/a;

    .line 1201
    .line 1202
    invoke-static {v0, v13}, Ll2/l0;->g(Lay0/a;Ll2/o;)V

    .line 1203
    .line 1204
    .line 1205
    :cond_19
    :goto_4
    return-object p2

    .line 1206
    nop

    .line 1207
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
