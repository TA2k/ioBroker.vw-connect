.class public abstract Lkp/c8;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Ljava/lang/String;Ljava/lang/String;FLjava/lang/String;Ll2/o;II)V
    .locals 35

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move/from16 v2, p5

    .line 6
    .line 7
    const-string v3, "value"

    .line 8
    .line 9
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    const-string v3, "unit"

    .line 13
    .line 14
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    move-object/from16 v3, p4

    .line 18
    .line 19
    check-cast v3, Ll2/t;

    .line 20
    .line 21
    const v4, 0x17e29e81

    .line 22
    .line 23
    .line 24
    invoke-virtual {v3, v4}, Ll2/t;->a0(I)Ll2/t;

    .line 25
    .line 26
    .line 27
    invoke-virtual {v3, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result v4

    .line 31
    const/4 v5, 0x4

    .line 32
    if-eqz v4, :cond_0

    .line 33
    .line 34
    move v4, v5

    .line 35
    goto :goto_0

    .line 36
    :cond_0
    const/4 v4, 0x2

    .line 37
    :goto_0
    or-int/2addr v4, v2

    .line 38
    invoke-virtual {v3, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 39
    .line 40
    .line 41
    move-result v6

    .line 42
    const/16 v7, 0x10

    .line 43
    .line 44
    if-eqz v6, :cond_1

    .line 45
    .line 46
    const/16 v6, 0x20

    .line 47
    .line 48
    goto :goto_1

    .line 49
    :cond_1
    move v6, v7

    .line 50
    :goto_1
    or-int/2addr v4, v6

    .line 51
    and-int/lit8 v6, p6, 0x4

    .line 52
    .line 53
    if-eqz v6, :cond_3

    .line 54
    .line 55
    or-int/lit16 v4, v4, 0x180

    .line 56
    .line 57
    :cond_2
    move/from16 v8, p2

    .line 58
    .line 59
    goto :goto_3

    .line 60
    :cond_3
    and-int/lit16 v8, v2, 0x180

    .line 61
    .line 62
    if-nez v8, :cond_2

    .line 63
    .line 64
    move/from16 v8, p2

    .line 65
    .line 66
    invoke-virtual {v3, v8}, Ll2/t;->d(F)Z

    .line 67
    .line 68
    .line 69
    move-result v9

    .line 70
    if-eqz v9, :cond_4

    .line 71
    .line 72
    const/16 v9, 0x100

    .line 73
    .line 74
    goto :goto_2

    .line 75
    :cond_4
    const/16 v9, 0x80

    .line 76
    .line 77
    :goto_2
    or-int/2addr v4, v9

    .line 78
    :goto_3
    and-int/lit8 v9, p6, 0x8

    .line 79
    .line 80
    if-eqz v9, :cond_5

    .line 81
    .line 82
    or-int/lit16 v4, v4, 0xc00

    .line 83
    .line 84
    move-object/from16 v10, p3

    .line 85
    .line 86
    goto :goto_5

    .line 87
    :cond_5
    move-object/from16 v10, p3

    .line 88
    .line 89
    invoke-virtual {v3, v10}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 90
    .line 91
    .line 92
    move-result v11

    .line 93
    if-eqz v11, :cond_6

    .line 94
    .line 95
    const/16 v11, 0x800

    .line 96
    .line 97
    goto :goto_4

    .line 98
    :cond_6
    const/16 v11, 0x400

    .line 99
    .line 100
    :goto_4
    or-int/2addr v4, v11

    .line 101
    :goto_5
    and-int/lit16 v11, v4, 0x493

    .line 102
    .line 103
    const/16 v12, 0x492

    .line 104
    .line 105
    const/4 v13, 0x1

    .line 106
    if-eq v11, v12, :cond_7

    .line 107
    .line 108
    move v11, v13

    .line 109
    goto :goto_6

    .line 110
    :cond_7
    const/4 v11, 0x0

    .line 111
    :goto_6
    and-int/lit8 v12, v4, 0x1

    .line 112
    .line 113
    invoke-virtual {v3, v12, v11}, Ll2/t;->O(IZ)Z

    .line 114
    .line 115
    .line 116
    move-result v11

    .line 117
    if-eqz v11, :cond_d

    .line 118
    .line 119
    if-eqz v6, :cond_8

    .line 120
    .line 121
    const/16 v6, 0x8

    .line 122
    .line 123
    int-to-float v6, v6

    .line 124
    move/from16 v16, v6

    .line 125
    .line 126
    goto :goto_7

    .line 127
    :cond_8
    move/from16 v16, v8

    .line 128
    .line 129
    :goto_7
    if-eqz v9, :cond_9

    .line 130
    .line 131
    const-string v6, ""

    .line 132
    .line 133
    goto :goto_8

    .line 134
    :cond_9
    move-object v6, v10

    .line 135
    :goto_8
    int-to-float v15, v7

    .line 136
    const/16 v18, 0x0

    .line 137
    .line 138
    const/16 v19, 0x8

    .line 139
    .line 140
    sget-object v14, Lx2/p;->b:Lx2/p;

    .line 141
    .line 142
    move/from16 v17, v15

    .line 143
    .line 144
    invoke-static/range {v14 .. v19}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 145
    .line 146
    .line 147
    move-result-object v7

    .line 148
    move-object/from16 v23, v14

    .line 149
    .line 150
    move/from16 v22, v16

    .line 151
    .line 152
    sget-object v8, Lk1/j;->a:Lk1/c;

    .line 153
    .line 154
    sget-object v9, Lx2/c;->m:Lx2/i;

    .line 155
    .line 156
    const/4 v10, 0x6

    .line 157
    invoke-static {v8, v9, v3, v10}, Lk1/e1;->a(Lk1/g;Lx2/i;Ll2/o;I)Lk1/g1;

    .line 158
    .line 159
    .line 160
    move-result-object v8

    .line 161
    iget-wide v9, v3, Ll2/t;->T:J

    .line 162
    .line 163
    invoke-static {v9, v10}, Ljava/lang/Long;->hashCode(J)I

    .line 164
    .line 165
    .line 166
    move-result v9

    .line 167
    invoke-virtual {v3}, Ll2/t;->m()Ll2/p1;

    .line 168
    .line 169
    .line 170
    move-result-object v10

    .line 171
    invoke-static {v3, v7}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 172
    .line 173
    .line 174
    move-result-object v7

    .line 175
    sget-object v11, Lv3/k;->m1:Lv3/j;

    .line 176
    .line 177
    invoke-virtual {v11}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 178
    .line 179
    .line 180
    sget-object v11, Lv3/j;->b:Lv3/i;

    .line 181
    .line 182
    invoke-virtual {v3}, Ll2/t;->c0()V

    .line 183
    .line 184
    .line 185
    iget-boolean v12, v3, Ll2/t;->S:Z

    .line 186
    .line 187
    if-eqz v12, :cond_a

    .line 188
    .line 189
    invoke-virtual {v3, v11}, Ll2/t;->l(Lay0/a;)V

    .line 190
    .line 191
    .line 192
    goto :goto_9

    .line 193
    :cond_a
    invoke-virtual {v3}, Ll2/t;->m0()V

    .line 194
    .line 195
    .line 196
    :goto_9
    sget-object v11, Lv3/j;->g:Lv3/h;

    .line 197
    .line 198
    invoke-static {v11, v8, v3}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 199
    .line 200
    .line 201
    sget-object v8, Lv3/j;->f:Lv3/h;

    .line 202
    .line 203
    invoke-static {v8, v10, v3}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 204
    .line 205
    .line 206
    sget-object v8, Lv3/j;->j:Lv3/h;

    .line 207
    .line 208
    iget-boolean v10, v3, Ll2/t;->S:Z

    .line 209
    .line 210
    if-nez v10, :cond_b

    .line 211
    .line 212
    invoke-virtual {v3}, Ll2/t;->L()Ljava/lang/Object;

    .line 213
    .line 214
    .line 215
    move-result-object v10

    .line 216
    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 217
    .line 218
    .line 219
    move-result-object v11

    .line 220
    invoke-static {v10, v11}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 221
    .line 222
    .line 223
    move-result v10

    .line 224
    if-nez v10, :cond_c

    .line 225
    .line 226
    :cond_b
    invoke-static {v9, v3, v9, v8}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 227
    .line 228
    .line 229
    :cond_c
    sget-object v8, Lv3/j;->d:Lv3/h;

    .line 230
    .line 231
    invoke-static {v8, v7, v3}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 232
    .line 233
    .line 234
    sget-object v7, Lj91/h;->a:Ll2/u2;

    .line 235
    .line 236
    invoke-virtual {v3, v7}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 237
    .line 238
    .line 239
    move-result-object v8

    .line 240
    check-cast v8, Lj91/e;

    .line 241
    .line 242
    invoke-virtual {v8}, Lj91/e;->q()J

    .line 243
    .line 244
    .line 245
    move-result-wide v8

    .line 246
    sget-object v10, Lt3/d;->a:Lt3/o;

    .line 247
    .line 248
    new-instance v11, Landroidx/compose/foundation/layout/WithAlignmentLineElement;

    .line 249
    .line 250
    invoke-direct {v11, v10}, Landroidx/compose/foundation/layout/WithAlignmentLineElement;-><init>(Lt3/a;)V

    .line 251
    .line 252
    .line 253
    new-instance v12, Ljava/lang/StringBuilder;

    .line 254
    .line 255
    invoke-direct {v12}, Ljava/lang/StringBuilder;-><init>()V

    .line 256
    .line 257
    .line 258
    invoke-virtual {v12, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 259
    .line 260
    .line 261
    const-string v14, "tariff_monthly_fee_value"

    .line 262
    .line 263
    invoke-virtual {v12, v14}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 264
    .line 265
    .line 266
    invoke-virtual {v12}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 267
    .line 268
    .line 269
    move-result-object v12

    .line 270
    invoke-static {v11, v12}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 271
    .line 272
    .line 273
    move-result-object v11

    .line 274
    sget-object v12, Lj91/j;->a:Ll2/u2;

    .line 275
    .line 276
    invoke-virtual {v3, v12}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 277
    .line 278
    .line 279
    move-result-object v14

    .line 280
    check-cast v14, Lj91/f;

    .line 281
    .line 282
    invoke-virtual {v14}, Lj91/f;->h()Lg4/p0;

    .line 283
    .line 284
    .line 285
    move-result-object v14

    .line 286
    and-int/lit8 v19, v4, 0xe

    .line 287
    .line 288
    const/16 v20, 0x0

    .line 289
    .line 290
    const v21, 0xfff0

    .line 291
    .line 292
    .line 293
    move/from16 v16, v5

    .line 294
    .line 295
    move-object v15, v6

    .line 296
    const-wide/16 v5, 0x0

    .line 297
    .line 298
    move-object/from16 v17, v7

    .line 299
    .line 300
    const/4 v7, 0x0

    .line 301
    move-object/from16 v18, v3

    .line 302
    .line 303
    move/from16 v24, v4

    .line 304
    .line 305
    move-wide v3, v8

    .line 306
    const-wide/16 v8, 0x0

    .line 307
    .line 308
    move-object/from16 v25, v10

    .line 309
    .line 310
    const/4 v10, 0x0

    .line 311
    move-object v2, v11

    .line 312
    const/4 v11, 0x0

    .line 313
    move-object/from16 v26, v12

    .line 314
    .line 315
    move/from16 v27, v13

    .line 316
    .line 317
    const-wide/16 v12, 0x0

    .line 318
    .line 319
    move-object v1, v14

    .line 320
    const/4 v14, 0x0

    .line 321
    move-object/from16 v28, v15

    .line 322
    .line 323
    const/4 v15, 0x0

    .line 324
    move/from16 v29, v16

    .line 325
    .line 326
    const/16 v16, 0x0

    .line 327
    .line 328
    move-object/from16 v30, v17

    .line 329
    .line 330
    const/16 v17, 0x0

    .line 331
    .line 332
    move-object/from16 v33, v25

    .line 333
    .line 334
    move-object/from16 v34, v26

    .line 335
    .line 336
    move-object/from16 v31, v28

    .line 337
    .line 338
    move-object/from16 v32, v30

    .line 339
    .line 340
    invoke-static/range {v0 .. v21}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 341
    .line 342
    .line 343
    move-object/from16 v0, v18

    .line 344
    .line 345
    const/4 v1, 0x4

    .line 346
    int-to-float v8, v1

    .line 347
    const/4 v11, 0x0

    .line 348
    const/16 v12, 0xe

    .line 349
    .line 350
    const/4 v9, 0x0

    .line 351
    const/4 v10, 0x0

    .line 352
    move-object/from16 v7, v23

    .line 353
    .line 354
    invoke-static/range {v7 .. v12}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 355
    .line 356
    .line 357
    move-result-object v1

    .line 358
    new-instance v2, Landroidx/compose/foundation/layout/WithAlignmentLineElement;

    .line 359
    .line 360
    move-object/from16 v3, v33

    .line 361
    .line 362
    invoke-direct {v2, v3}, Landroidx/compose/foundation/layout/WithAlignmentLineElement;-><init>(Lt3/a;)V

    .line 363
    .line 364
    .line 365
    invoke-interface {v1, v2}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 366
    .line 367
    .line 368
    move-result-object v1

    .line 369
    const-string v2, "tariff_monthly_fee_unit"

    .line 370
    .line 371
    move-object/from16 v3, v31

    .line 372
    .line 373
    invoke-static {v3, v2, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->s(Ljava/lang/String;Ljava/lang/String;Lx2/s;)Lx2/s;

    .line 374
    .line 375
    .line 376
    move-result-object v2

    .line 377
    move-object/from16 v1, v34

    .line 378
    .line 379
    invoke-virtual {v0, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 380
    .line 381
    .line 382
    move-result-object v1

    .line 383
    check-cast v1, Lj91/f;

    .line 384
    .line 385
    invoke-virtual {v1}, Lj91/f;->b()Lg4/p0;

    .line 386
    .line 387
    .line 388
    move-result-object v1

    .line 389
    move-object/from16 v4, v32

    .line 390
    .line 391
    invoke-virtual {v0, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 392
    .line 393
    .line 394
    move-result-object v4

    .line 395
    check-cast v4, Lj91/e;

    .line 396
    .line 397
    invoke-virtual {v4}, Lj91/e;->q()J

    .line 398
    .line 399
    .line 400
    move-result-wide v4

    .line 401
    shr-int/lit8 v6, v24, 0x3

    .line 402
    .line 403
    and-int/lit8 v19, v6, 0xe

    .line 404
    .line 405
    move-object/from16 v28, v3

    .line 406
    .line 407
    move-wide v3, v4

    .line 408
    const-wide/16 v5, 0x0

    .line 409
    .line 410
    const/4 v7, 0x0

    .line 411
    const-wide/16 v8, 0x0

    .line 412
    .line 413
    const/4 v10, 0x0

    .line 414
    const/4 v11, 0x0

    .line 415
    const-wide/16 v12, 0x0

    .line 416
    .line 417
    move-object/from16 v0, p1

    .line 418
    .line 419
    invoke-static/range {v0 .. v21}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 420
    .line 421
    .line 422
    move-object/from16 v0, v18

    .line 423
    .line 424
    const/4 v1, 0x1

    .line 425
    invoke-virtual {v0, v1}, Ll2/t;->q(Z)V

    .line 426
    .line 427
    .line 428
    move/from16 v3, v22

    .line 429
    .line 430
    move-object/from16 v4, v28

    .line 431
    .line 432
    goto :goto_a

    .line 433
    :cond_d
    move-object v0, v3

    .line 434
    invoke-virtual {v0}, Ll2/t;->R()V

    .line 435
    .line 436
    .line 437
    move v3, v8

    .line 438
    move-object v4, v10

    .line 439
    :goto_a
    invoke-virtual {v0}, Ll2/t;->s()Ll2/u1;

    .line 440
    .line 441
    .line 442
    move-result-object v7

    .line 443
    if-eqz v7, :cond_e

    .line 444
    .line 445
    new-instance v0, Le71/q;

    .line 446
    .line 447
    move-object/from16 v1, p0

    .line 448
    .line 449
    move-object/from16 v2, p1

    .line 450
    .line 451
    move/from16 v5, p5

    .line 452
    .line 453
    move/from16 v6, p6

    .line 454
    .line 455
    invoke-direct/range {v0 .. v6}, Le71/q;-><init>(Ljava/lang/String;Ljava/lang/String;FLjava/lang/String;II)V

    .line 456
    .line 457
    .line 458
    iput-object v0, v7, Ll2/u1;->d:Lay0/n;

    .line 459
    .line 460
    :cond_e
    return-void
.end method

.method public static final b(Ljava/lang/String;Ljava/lang/String;Ll2/o;I)V
    .locals 22

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v2, p2

    .line 6
    .line 7
    check-cast v2, Ll2/t;

    .line 8
    .line 9
    const v3, 0x1f1c4b54

    .line 10
    .line 11
    .line 12
    invoke-virtual {v2, v3}, Ll2/t;->a0(I)Ll2/t;

    .line 13
    .line 14
    .line 15
    invoke-virtual {v2, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    move-result v3

    .line 19
    const/4 v4, 0x4

    .line 20
    if-eqz v3, :cond_0

    .line 21
    .line 22
    move v3, v4

    .line 23
    goto :goto_0

    .line 24
    :cond_0
    const/4 v3, 0x2

    .line 25
    :goto_0
    or-int v3, p3, v3

    .line 26
    .line 27
    invoke-virtual {v2, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result v5

    .line 31
    const/16 v6, 0x10

    .line 32
    .line 33
    if-eqz v5, :cond_1

    .line 34
    .line 35
    const/16 v5, 0x20

    .line 36
    .line 37
    goto :goto_1

    .line 38
    :cond_1
    move v5, v6

    .line 39
    :goto_1
    or-int/2addr v3, v5

    .line 40
    and-int/lit8 v5, v3, 0x13

    .line 41
    .line 42
    const/16 v7, 0x12

    .line 43
    .line 44
    if-eq v5, v7, :cond_2

    .line 45
    .line 46
    const/4 v5, 0x1

    .line 47
    goto :goto_2

    .line 48
    :cond_2
    const/4 v5, 0x0

    .line 49
    :goto_2
    and-int/lit8 v7, v3, 0x1

    .line 50
    .line 51
    invoke-virtual {v2, v7, v5}, Ll2/t;->O(IZ)Z

    .line 52
    .line 53
    .line 54
    move-result v5

    .line 55
    if-eqz v5, :cond_3

    .line 56
    .line 57
    int-to-float v9, v4

    .line 58
    int-to-float v8, v6

    .line 59
    const/4 v11, 0x0

    .line 60
    const/16 v12, 0x8

    .line 61
    .line 62
    sget-object v7, Lx2/p;->b:Lx2/p;

    .line 63
    .line 64
    move v10, v8

    .line 65
    invoke-static/range {v7 .. v12}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 66
    .line 67
    .line 68
    move-result-object v4

    .line 69
    const-string v5, "tariff_description"

    .line 70
    .line 71
    invoke-virtual {v1, v5}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 72
    .line 73
    .line 74
    move-result-object v5

    .line 75
    invoke-static {v4, v5}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 76
    .line 77
    .line 78
    move-result-object v4

    .line 79
    sget-object v5, Lj91/j;->a:Ll2/u2;

    .line 80
    .line 81
    invoke-virtual {v2, v5}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object v5

    .line 85
    check-cast v5, Lj91/f;

    .line 86
    .line 87
    invoke-virtual {v5}, Lj91/f;->b()Lg4/p0;

    .line 88
    .line 89
    .line 90
    move-result-object v5

    .line 91
    and-int/lit8 v19, v3, 0xe

    .line 92
    .line 93
    const/16 v20, 0x0

    .line 94
    .line 95
    const v21, 0xfff8

    .line 96
    .line 97
    .line 98
    move-object/from16 v18, v2

    .line 99
    .line 100
    move-object v2, v4

    .line 101
    const-wide/16 v3, 0x0

    .line 102
    .line 103
    move-object v1, v5

    .line 104
    const-wide/16 v5, 0x0

    .line 105
    .line 106
    const/4 v7, 0x0

    .line 107
    const-wide/16 v8, 0x0

    .line 108
    .line 109
    const/4 v10, 0x0

    .line 110
    const/4 v11, 0x0

    .line 111
    const-wide/16 v12, 0x0

    .line 112
    .line 113
    const/4 v14, 0x0

    .line 114
    const/4 v15, 0x0

    .line 115
    const/16 v16, 0x0

    .line 116
    .line 117
    const/16 v17, 0x0

    .line 118
    .line 119
    invoke-static/range {v0 .. v21}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 120
    .line 121
    .line 122
    goto :goto_3

    .line 123
    :cond_3
    move-object/from16 v18, v2

    .line 124
    .line 125
    invoke-virtual/range {v18 .. v18}, Ll2/t;->R()V

    .line 126
    .line 127
    .line 128
    :goto_3
    invoke-virtual/range {v18 .. v18}, Ll2/t;->s()Ll2/u1;

    .line 129
    .line 130
    .line 131
    move-result-object v1

    .line 132
    if-eqz v1, :cond_4

    .line 133
    .line 134
    new-instance v2, Lbk/c;

    .line 135
    .line 136
    const/16 v3, 0xb

    .line 137
    .line 138
    move-object/from16 v4, p1

    .line 139
    .line 140
    move/from16 v5, p3

    .line 141
    .line 142
    invoke-direct {v2, v0, v4, v5, v3}, Lbk/c;-><init>(Ljava/lang/String;Ljava/lang/String;II)V

    .line 143
    .line 144
    .line 145
    iput-object v2, v1, Ll2/u1;->d:Lay0/n;

    .line 146
    .line 147
    :cond_4
    return-void
.end method

.method public static final c(Ljava/lang/String;FLjava/lang/String;Lg4/p0;Ll2/o;II)V
    .locals 26

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    const-string v1, "name"

    .line 4
    .line 5
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    move-object/from16 v1, p4

    .line 9
    .line 10
    check-cast v1, Ll2/t;

    .line 11
    .line 12
    const v2, -0x164992e1

    .line 13
    .line 14
    .line 15
    invoke-virtual {v1, v2}, Ll2/t;->a0(I)Ll2/t;

    .line 16
    .line 17
    .line 18
    invoke-virtual {v1, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    if-eqz v2, :cond_0

    .line 23
    .line 24
    const/4 v2, 0x4

    .line 25
    goto :goto_0

    .line 26
    :cond_0
    const/4 v2, 0x2

    .line 27
    :goto_0
    or-int v2, p5, v2

    .line 28
    .line 29
    and-int/lit8 v3, p6, 0x2

    .line 30
    .line 31
    const/16 v4, 0x10

    .line 32
    .line 33
    if-eqz v3, :cond_2

    .line 34
    .line 35
    or-int/lit8 v2, v2, 0x30

    .line 36
    .line 37
    :cond_1
    move/from16 v5, p1

    .line 38
    .line 39
    goto :goto_2

    .line 40
    :cond_2
    and-int/lit8 v5, p5, 0x30

    .line 41
    .line 42
    if-nez v5, :cond_1

    .line 43
    .line 44
    move/from16 v5, p1

    .line 45
    .line 46
    invoke-virtual {v1, v5}, Ll2/t;->d(F)Z

    .line 47
    .line 48
    .line 49
    move-result v6

    .line 50
    if-eqz v6, :cond_3

    .line 51
    .line 52
    const/16 v6, 0x20

    .line 53
    .line 54
    goto :goto_1

    .line 55
    :cond_3
    move v6, v4

    .line 56
    :goto_1
    or-int/2addr v2, v6

    .line 57
    :goto_2
    and-int/lit8 v6, p6, 0x4

    .line 58
    .line 59
    if-eqz v6, :cond_4

    .line 60
    .line 61
    or-int/lit16 v2, v2, 0x180

    .line 62
    .line 63
    move-object/from16 v7, p2

    .line 64
    .line 65
    goto :goto_4

    .line 66
    :cond_4
    move-object/from16 v7, p2

    .line 67
    .line 68
    invoke-virtual {v1, v7}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 69
    .line 70
    .line 71
    move-result v8

    .line 72
    if-eqz v8, :cond_5

    .line 73
    .line 74
    const/16 v8, 0x100

    .line 75
    .line 76
    goto :goto_3

    .line 77
    :cond_5
    const/16 v8, 0x80

    .line 78
    .line 79
    :goto_3
    or-int/2addr v2, v8

    .line 80
    :goto_4
    and-int/lit8 v8, p6, 0x8

    .line 81
    .line 82
    if-nez v8, :cond_6

    .line 83
    .line 84
    move-object/from16 v8, p3

    .line 85
    .line 86
    invoke-virtual {v1, v8}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 87
    .line 88
    .line 89
    move-result v9

    .line 90
    if-eqz v9, :cond_7

    .line 91
    .line 92
    const/16 v9, 0x800

    .line 93
    .line 94
    goto :goto_5

    .line 95
    :cond_6
    move-object/from16 v8, p3

    .line 96
    .line 97
    :cond_7
    const/16 v9, 0x400

    .line 98
    .line 99
    :goto_5
    or-int/2addr v2, v9

    .line 100
    and-int/lit16 v9, v2, 0x493

    .line 101
    .line 102
    const/16 v10, 0x492

    .line 103
    .line 104
    if-eq v9, v10, :cond_8

    .line 105
    .line 106
    const/4 v9, 0x1

    .line 107
    goto :goto_6

    .line 108
    :cond_8
    const/4 v9, 0x0

    .line 109
    :goto_6
    and-int/lit8 v10, v2, 0x1

    .line 110
    .line 111
    invoke-virtual {v1, v10, v9}, Ll2/t;->O(IZ)Z

    .line 112
    .line 113
    .line 114
    move-result v9

    .line 115
    if-eqz v9, :cond_f

    .line 116
    .line 117
    invoke-virtual {v1}, Ll2/t;->T()V

    .line 118
    .line 119
    .line 120
    and-int/lit8 v9, p5, 0x1

    .line 121
    .line 122
    if-eqz v9, :cond_b

    .line 123
    .line 124
    invoke-virtual {v1}, Ll2/t;->y()Z

    .line 125
    .line 126
    .line 127
    move-result v9

    .line 128
    if-eqz v9, :cond_9

    .line 129
    .line 130
    goto :goto_7

    .line 131
    :cond_9
    invoke-virtual {v1}, Ll2/t;->R()V

    .line 132
    .line 133
    .line 134
    and-int/lit8 v3, p6, 0x8

    .line 135
    .line 136
    if-eqz v3, :cond_a

    .line 137
    .line 138
    and-int/lit16 v2, v2, -0x1c01

    .line 139
    .line 140
    :cond_a
    move v3, v2

    .line 141
    move v9, v5

    .line 142
    move-object v2, v7

    .line 143
    move-object v6, v8

    .line 144
    goto :goto_b

    .line 145
    :cond_b
    :goto_7
    if-eqz v3, :cond_c

    .line 146
    .line 147
    const/16 v3, 0x8

    .line 148
    .line 149
    int-to-float v3, v3

    .line 150
    goto :goto_8

    .line 151
    :cond_c
    move v3, v5

    .line 152
    :goto_8
    if-eqz v6, :cond_d

    .line 153
    .line 154
    const-string v5, ""

    .line 155
    .line 156
    goto :goto_9

    .line 157
    :cond_d
    move-object v5, v7

    .line 158
    :goto_9
    and-int/lit8 v6, p6, 0x8

    .line 159
    .line 160
    if-eqz v6, :cond_e

    .line 161
    .line 162
    sget-object v6, Lj91/j;->a:Ll2/u2;

    .line 163
    .line 164
    invoke-virtual {v1, v6}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 165
    .line 166
    .line 167
    move-result-object v6

    .line 168
    check-cast v6, Lj91/f;

    .line 169
    .line 170
    invoke-virtual {v6}, Lj91/f;->b()Lg4/p0;

    .line 171
    .line 172
    .line 173
    move-result-object v6

    .line 174
    and-int/lit16 v2, v2, -0x1c01

    .line 175
    .line 176
    move v9, v3

    .line 177
    :goto_a
    move v3, v2

    .line 178
    move-object v2, v5

    .line 179
    goto :goto_b

    .line 180
    :cond_e
    move v9, v3

    .line 181
    move-object v6, v8

    .line 182
    goto :goto_a

    .line 183
    :goto_b
    invoke-virtual {v1}, Ll2/t;->r()V

    .line 184
    .line 185
    .line 186
    int-to-float v8, v4

    .line 187
    const/4 v11, 0x0

    .line 188
    const/16 v12, 0x8

    .line 189
    .line 190
    sget-object v7, Lx2/p;->b:Lx2/p;

    .line 191
    .line 192
    move v10, v8

    .line 193
    invoke-static/range {v7 .. v12}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 194
    .line 195
    .line 196
    move-result-object v4

    .line 197
    move/from16 v22, v9

    .line 198
    .line 199
    const-string v5, "tariff_name"

    .line 200
    .line 201
    invoke-static {v2, v5, v4}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->s(Ljava/lang/String;Ljava/lang/String;Lx2/s;)Lx2/s;

    .line 202
    .line 203
    .line 204
    move-result-object v4

    .line 205
    sget-object v5, Lj91/h;->a:Ll2/u2;

    .line 206
    .line 207
    invoke-virtual {v1, v5}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 208
    .line 209
    .line 210
    move-result-object v5

    .line 211
    check-cast v5, Lj91/e;

    .line 212
    .line 213
    invoke-virtual {v5}, Lj91/e;->q()J

    .line 214
    .line 215
    .line 216
    move-result-wide v7

    .line 217
    and-int/lit8 v5, v3, 0xe

    .line 218
    .line 219
    shr-int/lit8 v3, v3, 0x6

    .line 220
    .line 221
    and-int/lit8 v3, v3, 0x70

    .line 222
    .line 223
    or-int v19, v5, v3

    .line 224
    .line 225
    const/16 v20, 0x0

    .line 226
    .line 227
    const v21, 0xfff0

    .line 228
    .line 229
    .line 230
    move-object/from16 v18, v1

    .line 231
    .line 232
    move-object v1, v6

    .line 233
    const-wide/16 v5, 0x0

    .line 234
    .line 235
    move-wide/from16 v24, v7

    .line 236
    .line 237
    move-object v8, v2

    .line 238
    move-object v2, v4

    .line 239
    move-wide/from16 v3, v24

    .line 240
    .line 241
    const/4 v7, 0x0

    .line 242
    move-object v10, v8

    .line 243
    const-wide/16 v8, 0x0

    .line 244
    .line 245
    move-object v11, v10

    .line 246
    const/4 v10, 0x0

    .line 247
    move-object v12, v11

    .line 248
    const/4 v11, 0x0

    .line 249
    move-object v14, v12

    .line 250
    const-wide/16 v12, 0x0

    .line 251
    .line 252
    move-object v15, v14

    .line 253
    const/4 v14, 0x0

    .line 254
    move-object/from16 v16, v15

    .line 255
    .line 256
    const/4 v15, 0x0

    .line 257
    move-object/from16 v17, v16

    .line 258
    .line 259
    const/16 v16, 0x0

    .line 260
    .line 261
    move-object/from16 v23, v17

    .line 262
    .line 263
    const/16 v17, 0x0

    .line 264
    .line 265
    invoke-static/range {v0 .. v21}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 266
    .line 267
    .line 268
    move-object v4, v1

    .line 269
    move/from16 v2, v22

    .line 270
    .line 271
    move-object/from16 v3, v23

    .line 272
    .line 273
    goto :goto_c

    .line 274
    :cond_f
    move-object/from16 v18, v1

    .line 275
    .line 276
    invoke-virtual/range {v18 .. v18}, Ll2/t;->R()V

    .line 277
    .line 278
    .line 279
    move v2, v5

    .line 280
    move-object v3, v7

    .line 281
    move-object v4, v8

    .line 282
    :goto_c
    invoke-virtual/range {v18 .. v18}, Ll2/t;->s()Ll2/u1;

    .line 283
    .line 284
    .line 285
    move-result-object v8

    .line 286
    if-eqz v8, :cond_10

    .line 287
    .line 288
    new-instance v0, Le71/q;

    .line 289
    .line 290
    const/4 v7, 0x1

    .line 291
    move-object/from16 v1, p0

    .line 292
    .line 293
    move/from16 v5, p5

    .line 294
    .line 295
    move/from16 v6, p6

    .line 296
    .line 297
    invoke-direct/range {v0 .. v7}, Le71/q;-><init>(Ljava/lang/Object;FLjava/lang/Object;Ljava/lang/Object;III)V

    .line 298
    .line 299
    .line 300
    iput-object v0, v8, Ll2/u1;->d:Lay0/n;

    .line 301
    .line 302
    :cond_10
    return-void
.end method

.method public static final d(Lm1/f;Ljava/util/List;Ljava/lang/String;F)V
    .locals 3

    .line 1
    const-string v0, "$this$drawConditions"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    new-instance v1, Li40/j3;

    .line 11
    .line 12
    const/4 v2, 0x1

    .line 13
    invoke-direct {v1, p1, v2}, Li40/j3;-><init>(Ljava/util/List;I)V

    .line 14
    .line 15
    .line 16
    new-instance v2, Lsk/a;

    .line 17
    .line 18
    invoke-direct {v2, p3, p2, p1}, Lsk/a;-><init>(FLjava/lang/String;Ljava/util/List;)V

    .line 19
    .line 20
    .line 21
    new-instance p1, Lt2/b;

    .line 22
    .line 23
    const/4 p2, 0x1

    .line 24
    const p3, 0x799532c4

    .line 25
    .line 26
    .line 27
    invoke-direct {p1, v2, p2, p3}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 28
    .line 29
    .line 30
    const/4 p2, 0x0

    .line 31
    invoke-virtual {p0, v0, p2, v1, p1}, Lm1/f;->p(ILay0/k;Lay0/k;Lt2/b;)V

    .line 32
    .line 33
    .line 34
    return-void
.end method

.method public static final e(Lm1/f;Ljava/lang/String;)V
    .locals 3

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, La71/z0;

    .line 7
    .line 8
    const/16 v1, 0xb

    .line 9
    .line 10
    invoke-direct {v0, p1, v1}, La71/z0;-><init>(Ljava/lang/String;I)V

    .line 11
    .line 12
    .line 13
    new-instance p1, Lt2/b;

    .line 14
    .line 15
    const/4 v1, 0x1

    .line 16
    const v2, 0x1a81f495

    .line 17
    .line 18
    .line 19
    invoke-direct {p1, v0, v1, v2}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 20
    .line 21
    .line 22
    const/4 v0, 0x3

    .line 23
    invoke-static {p0, p1, v0}, Lm1/f;->o(Lm1/f;Lay0/o;I)V

    .line 24
    .line 25
    .line 26
    return-void
.end method

.method public static final f(Lm1/f;Ljava/lang/String;Ljava/lang/String;Lay0/a;)V
    .locals 2

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "localizedPdfLinkLabel"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    new-instance v0, Li40/n2;

    .line 12
    .line 13
    const/16 v1, 0x19

    .line 14
    .line 15
    invoke-direct {v0, p2, p1, p3, v1}, Li40/n2;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 16
    .line 17
    .line 18
    new-instance p1, Lt2/b;

    .line 19
    .line 20
    const/4 p2, 0x1

    .line 21
    const p3, 0x7bd01fde

    .line 22
    .line 23
    .line 24
    invoke-direct {p1, v0, p2, p3}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 25
    .line 26
    .line 27
    const/4 p2, 0x3

    .line 28
    invoke-static {p0, p1, p2}, Lm1/f;->o(Lm1/f;Lay0/o;I)V

    .line 29
    .line 30
    .line 31
    return-void
.end method

.method public static final g(Lm1/f;Ljava/util/List;Ljava/lang/String;Lay0/k;)V
    .locals 3

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "legalDisclaimers"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    new-instance v1, Leh/l;

    .line 16
    .line 17
    const/4 v2, 0x6

    .line 18
    invoke-direct {v1, p1, p3, p2, v2}, Leh/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 19
    .line 20
    .line 21
    new-instance p1, Lt2/b;

    .line 22
    .line 23
    const/4 p2, 0x1

    .line 24
    const p3, 0x548d1401

    .line 25
    .line 26
    .line 27
    invoke-direct {p1, v1, p2, p3}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 28
    .line 29
    .line 30
    invoke-static {p0, v0, p1}, Lm1/f;->q(Lm1/f;ILt2/b;)V

    .line 31
    .line 32
    .line 33
    return-void
.end method

.method public static final h(Lm1/f;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V
    .locals 2

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "value"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "unit"

    .line 12
    .line 13
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    new-instance v0, Li40/n2;

    .line 17
    .line 18
    const/16 v1, 0x1a

    .line 19
    .line 20
    invoke-direct {v0, p1, p2, p3, v1}, Li40/n2;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 21
    .line 22
    .line 23
    new-instance p1, Lt2/b;

    .line 24
    .line 25
    const/4 p2, 0x1

    .line 26
    const p3, -0x5d0b116

    .line 27
    .line 28
    .line 29
    invoke-direct {p1, v0, p2, p3}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 30
    .line 31
    .line 32
    const/4 p2, 0x3

    .line 33
    invoke-static {p0, p1, p2}, Lm1/f;->o(Lm1/f;Lay0/o;I)V

    .line 34
    .line 35
    .line 36
    return-void
.end method

.method public static final i(Lm1/f;Ljava/lang/String;Ljava/lang/String;)V
    .locals 2

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Lb71/e;

    .line 7
    .line 8
    const/4 v1, 0x2

    .line 9
    invoke-direct {v0, p1, p2, v1}, Lb71/e;-><init>(Ljava/lang/String;Ljava/lang/String;I)V

    .line 10
    .line 11
    .line 12
    new-instance p1, Lt2/b;

    .line 13
    .line 14
    const/4 p2, 0x1

    .line 15
    const v1, -0x57d5f7b7

    .line 16
    .line 17
    .line 18
    invoke-direct {p1, v0, p2, v1}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 19
    .line 20
    .line 21
    const/4 p2, 0x3

    .line 22
    invoke-static {p0, p1, p2}, Lm1/f;->o(Lm1/f;Lay0/o;I)V

    .line 23
    .line 24
    .line 25
    return-void
.end method

.method public static final j(Lm1/f;Ljava/lang/String;Ljava/lang/String;)V
    .locals 2

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "name"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    new-instance v0, Lb71/e;

    .line 12
    .line 13
    const/4 v1, 0x3

    .line 14
    invoke-direct {v0, p1, p2, v1}, Lb71/e;-><init>(Ljava/lang/String;Ljava/lang/String;I)V

    .line 15
    .line 16
    .line 17
    new-instance p1, Lt2/b;

    .line 18
    .line 19
    const/4 p2, 0x1

    .line 20
    const v1, -0x43187986

    .line 21
    .line 22
    .line 23
    invoke-direct {p1, v0, p2, v1}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 24
    .line 25
    .line 26
    const/4 p2, 0x3

    .line 27
    invoke-static {p0, p1, p2}, Lm1/f;->o(Lm1/f;Lay0/o;I)V

    .line 28
    .line 29
    .line 30
    return-void
.end method

.method public static final k(Lm1/f;Lug/b;Lay0/a;Lay0/k;)V
    .locals 3

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "uiState"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    iget-object v0, p1, Lug/b;->a:Ljava/lang/String;

    .line 12
    .line 13
    iget-object v1, p1, Lug/b;->b:Ljava/lang/String;

    .line 14
    .line 15
    const-string v2, ""

    .line 16
    .line 17
    invoke-static {p0, v0, v1, v2}, Lkp/c8;->h(Lm1/f;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    iget-object v0, p1, Lug/b;->c:Ljava/lang/String;

    .line 21
    .line 22
    invoke-static {p0, v0, v2}, Lkp/c8;->j(Lm1/f;Ljava/lang/String;Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    iget-boolean v0, p1, Lug/b;->e:Z

    .line 26
    .line 27
    if-eqz v0, :cond_0

    .line 28
    .line 29
    iget-object v0, p1, Lug/b;->d:Ljava/lang/String;

    .line 30
    .line 31
    invoke-static {p0, v0, v2}, Lkp/c8;->i(Lm1/f;Ljava/lang/String;Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    :cond_0
    iget-object v0, p1, Lug/b;->f:Ljava/util/ArrayList;

    .line 35
    .line 36
    const/16 v1, 0x28

    .line 37
    .line 38
    int-to-float v1, v1

    .line 39
    invoke-static {p0, v0, v2, v1}, Lkp/c8;->d(Lm1/f;Ljava/util/List;Ljava/lang/String;F)V

    .line 40
    .line 41
    .line 42
    iget-object v0, p1, Lug/b;->h:Ljava/lang/String;

    .line 43
    .line 44
    invoke-static {p0, v0, v2, p2}, Lkp/c8;->f(Lm1/f;Ljava/lang/String;Ljava/lang/String;Lay0/a;)V

    .line 45
    .line 46
    .line 47
    iget-object p1, p1, Lug/b;->g:Ljava/util/List;

    .line 48
    .line 49
    invoke-static {p0, p1, v2, p3}, Lkp/c8;->g(Lm1/f;Ljava/util/List;Ljava/lang/String;Lay0/k;)V

    .line 50
    .line 51
    .line 52
    return-void
.end method

.method public static l(II)V
    .locals 2

    .line 1
    if-ltz p0, :cond_1

    .line 2
    .line 3
    if-lt p0, p1, :cond_0

    .line 4
    .line 5
    goto :goto_0

    .line 6
    :cond_0
    return-void

    .line 7
    :cond_1
    :goto_0
    new-instance v0, Ljava/lang/IndexOutOfBoundsException;

    .line 8
    .line 9
    const-string v1, "index"

    .line 10
    .line 11
    if-ltz p0, :cond_3

    .line 12
    .line 13
    if-gez p1, :cond_2

    .line 14
    .line 15
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 16
    .line 17
    invoke-static {p1}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 22
    .line 23
    .line 24
    move-result v0

    .line 25
    new-instance v1, Ljava/lang/StringBuilder;

    .line 26
    .line 27
    add-int/lit8 v0, v0, 0xf

    .line 28
    .line 29
    invoke-direct {v1, v0}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 30
    .line 31
    .line 32
    const-string v0, "negative size: "

    .line 33
    .line 34
    invoke-static {p1, v0, v1}, Lvj/b;->h(ILjava/lang/String;Ljava/lang/StringBuilder;)Ljava/lang/String;

    .line 35
    .line 36
    .line 37
    move-result-object p1

    .line 38
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    throw p0

    .line 42
    :cond_2
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 47
    .line 48
    .line 49
    move-result-object p1

    .line 50
    filled-new-array {v1, p0, p1}, [Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    move-result-object p0

    .line 54
    const-string p1, "%s (%s) must be less than size (%s)"

    .line 55
    .line 56
    invoke-static {p1, p0}, Lkp/d8;->c(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 57
    .line 58
    .line 59
    move-result-object p0

    .line 60
    goto :goto_1

    .line 61
    :cond_3
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 62
    .line 63
    .line 64
    move-result-object p0

    .line 65
    filled-new-array {v1, p0}, [Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    move-result-object p0

    .line 69
    const-string p1, "%s (%s) must not be negative"

    .line 70
    .line 71
    invoke-static {p1, p0}, Lkp/d8;->c(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 72
    .line 73
    .line 74
    move-result-object p0

    .line 75
    :goto_1
    invoke-direct {v0, p0}, Ljava/lang/IndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    .line 76
    .line 77
    .line 78
    throw v0
.end method

.method public static m(III)V
    .locals 1

    .line 1
    if-ltz p0, :cond_1

    .line 2
    .line 3
    if-lt p1, p0, :cond_1

    .line 4
    .line 5
    if-le p1, p2, :cond_0

    .line 6
    .line 7
    goto :goto_0

    .line 8
    :cond_0
    return-void

    .line 9
    :cond_1
    :goto_0
    new-instance v0, Ljava/lang/IndexOutOfBoundsException;

    .line 10
    .line 11
    if-ltz p0, :cond_4

    .line 12
    .line 13
    if-gt p0, p2, :cond_4

    .line 14
    .line 15
    if-ltz p1, :cond_3

    .line 16
    .line 17
    if-le p1, p2, :cond_2

    .line 18
    .line 19
    goto :goto_1

    .line 20
    :cond_2
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 21
    .line 22
    .line 23
    move-result-object p1

    .line 24
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    filled-new-array {p1, p0}, [Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    const-string p1, "end index (%s) must not be less than start index (%s)"

    .line 33
    .line 34
    invoke-static {p1, p0}, Lkp/d8;->c(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    goto :goto_2

    .line 39
    :cond_3
    :goto_1
    const-string p0, "end index"

    .line 40
    .line 41
    invoke-static {p1, p2, p0}, Lkp/c8;->n(IILjava/lang/String;)Ljava/lang/String;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    goto :goto_2

    .line 46
    :cond_4
    const-string p1, "start index"

    .line 47
    .line 48
    invoke-static {p0, p2, p1}, Lkp/c8;->n(IILjava/lang/String;)Ljava/lang/String;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    :goto_2
    invoke-direct {v0, p0}, Ljava/lang/IndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    throw v0
.end method

.method public static n(IILjava/lang/String;)Ljava/lang/String;
    .locals 1

    .line 1
    if-gez p0, :cond_0

    .line 2
    .line 3
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    filled-new-array {p2, p0}, [Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    const-string p1, "%s (%s) must not be negative"

    .line 12
    .line 13
    invoke-static {p1, p0}, Lkp/d8;->c(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0

    .line 18
    :cond_0
    if-ltz p1, :cond_1

    .line 19
    .line 20
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 25
    .line 26
    .line 27
    move-result-object p1

    .line 28
    filled-new-array {p2, p0, p1}, [Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    const-string p1, "%s (%s) must not be greater than size (%s)"

    .line 33
    .line 34
    invoke-static {p1, p0}, Lkp/d8;->c(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    return-object p0

    .line 39
    :cond_1
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 40
    .line 41
    invoke-static {p1}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 42
    .line 43
    .line 44
    move-result-object p2

    .line 45
    invoke-virtual {p2}, Ljava/lang/String;->length()I

    .line 46
    .line 47
    .line 48
    move-result p2

    .line 49
    new-instance v0, Ljava/lang/StringBuilder;

    .line 50
    .line 51
    add-int/lit8 p2, p2, 0xf

    .line 52
    .line 53
    invoke-direct {v0, p2}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 54
    .line 55
    .line 56
    const-string p2, "negative size: "

    .line 57
    .line 58
    invoke-static {p1, p2, v0}, Lvj/b;->h(ILjava/lang/String;Ljava/lang/StringBuilder;)Ljava/lang/String;

    .line 59
    .line 60
    .line 61
    move-result-object p1

    .line 62
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 63
    .line 64
    .line 65
    throw p0
.end method
