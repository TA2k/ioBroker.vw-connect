.class public final Lxf0/a0;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic f:Ll2/b1;

.field public final synthetic g:Lz4/k;

.field public final synthetic h:Lay0/a;

.field public final synthetic i:Z

.field public final synthetic j:Lvf0/a;

.field public final synthetic k:J

.field public final synthetic l:Z

.field public final synthetic m:J

.field public final synthetic n:F

.field public final synthetic o:Ljava/lang/Integer;

.field public final synthetic p:Ljava/util/List;

.field public final synthetic q:Lay0/k;


# direct methods
.method public constructor <init>(Ll2/b1;Lz4/k;Lay0/a;ZLvf0/a;JZJFLjava/lang/Integer;Ljava/util/List;Lay0/k;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lxf0/a0;->f:Ll2/b1;

    .line 2
    .line 3
    iput-object p2, p0, Lxf0/a0;->g:Lz4/k;

    .line 4
    .line 5
    iput-object p3, p0, Lxf0/a0;->h:Lay0/a;

    .line 6
    .line 7
    iput-boolean p4, p0, Lxf0/a0;->i:Z

    .line 8
    .line 9
    iput-object p5, p0, Lxf0/a0;->j:Lvf0/a;

    .line 10
    .line 11
    iput-wide p6, p0, Lxf0/a0;->k:J

    .line 12
    .line 13
    iput-boolean p8, p0, Lxf0/a0;->l:Z

    .line 14
    .line 15
    iput-wide p9, p0, Lxf0/a0;->m:J

    .line 16
    .line 17
    iput p11, p0, Lxf0/a0;->n:F

    .line 18
    .line 19
    iput-object p12, p0, Lxf0/a0;->o:Ljava/lang/Integer;

    .line 20
    .line 21
    iput-object p13, p0, Lxf0/a0;->p:Ljava/util/List;

    .line 22
    .line 23
    iput-object p14, p0, Lxf0/a0;->q:Lay0/k;

    .line 24
    .line 25
    const/4 p1, 0x2

    .line 26
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 27
    .line 28
    .line 29
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 47

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    check-cast v1, Ll2/o;

    .line 6
    .line 7
    move-object/from16 v2, p2

    .line 8
    .line 9
    check-cast v2, Ljava/lang/Number;

    .line 10
    .line 11
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 12
    .line 13
    .line 14
    move-result v2

    .line 15
    const/4 v3, 0x3

    .line 16
    and-int/2addr v2, v3

    .line 17
    sget-object v4, Llx0/b0;->a:Llx0/b0;

    .line 18
    .line 19
    const/4 v5, 0x2

    .line 20
    if-ne v2, v5, :cond_1

    .line 21
    .line 22
    move-object v2, v1

    .line 23
    check-cast v2, Ll2/t;

    .line 24
    .line 25
    invoke-virtual {v2}, Ll2/t;->A()Z

    .line 26
    .line 27
    .line 28
    move-result v6

    .line 29
    if-nez v6, :cond_0

    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_0
    invoke-virtual {v2}, Ll2/t;->R()V

    .line 33
    .line 34
    .line 35
    return-object v4

    .line 36
    :cond_1
    :goto_0
    iget-object v2, v0, Lxf0/a0;->f:Ll2/b1;

    .line 37
    .line 38
    invoke-interface {v2, v4}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    iget-object v2, v0, Lxf0/a0;->g:Lz4/k;

    .line 42
    .line 43
    iget v6, v2, Lz4/k;->b:I

    .line 44
    .line 45
    invoke-virtual {v2}, Lz4/k;->e()V

    .line 46
    .line 47
    .line 48
    check-cast v1, Ll2/t;

    .line 49
    .line 50
    const v7, 0xf4ff5b2

    .line 51
    .line 52
    .line 53
    invoke-virtual {v1, v7}, Ll2/t;->Y(I)V

    .line 54
    .line 55
    .line 56
    invoke-virtual {v2}, Lz4/k;->d()Lt1/j0;

    .line 57
    .line 58
    .line 59
    move-result-object v7

    .line 60
    iget-object v7, v7, Lt1/j0;->e:Ljava/lang/Object;

    .line 61
    .line 62
    check-cast v7, Lz4/k;

    .line 63
    .line 64
    invoke-virtual {v7}, Lz4/k;->c()Lz4/f;

    .line 65
    .line 66
    .line 67
    move-result-object v8

    .line 68
    invoke-virtual {v7}, Lz4/k;->c()Lz4/f;

    .line 69
    .line 70
    .line 71
    move-result-object v9

    .line 72
    invoke-virtual {v7}, Lz4/k;->c()Lz4/f;

    .line 73
    .line 74
    .line 75
    move-result-object v7

    .line 76
    sget-object v10, Lk1/j;->g:Lk1/f;

    .line 77
    .line 78
    sget-object v11, Lx2/p;->b:Lx2/p;

    .line 79
    .line 80
    const/high16 v12, 0x3f800000    # 1.0f

    .line 81
    .line 82
    invoke-static {v11, v12}, Landroidx/compose/foundation/layout/d;->c(Lx2/s;F)Lx2/s;

    .line 83
    .line 84
    .line 85
    move-result-object v13

    .line 86
    sget-object v14, Lj91/a;->a:Ll2/u2;

    .line 87
    .line 88
    invoke-virtual {v1, v14}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 89
    .line 90
    .line 91
    move-result-object v14

    .line 92
    check-cast v14, Lj91/c;

    .line 93
    .line 94
    iget v14, v14, Lj91/c;->a:F

    .line 95
    .line 96
    const/16 v17, 0x0

    .line 97
    .line 98
    const/16 v18, 0xe

    .line 99
    .line 100
    const/4 v15, 0x0

    .line 101
    const/16 v16, 0x0

    .line 102
    .line 103
    invoke-static/range {v13 .. v18}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 104
    .line 105
    .line 106
    move-result-object v13

    .line 107
    invoke-virtual {v1, v9}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 108
    .line 109
    .line 110
    move-result v14

    .line 111
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 112
    .line 113
    .line 114
    move-result-object v15

    .line 115
    sget-object v3, Ll2/n;->a:Ll2/x0;

    .line 116
    .line 117
    if-nez v14, :cond_2

    .line 118
    .line 119
    if-ne v15, v3, :cond_3

    .line 120
    .line 121
    :cond_2
    new-instance v15, Lc40/g;

    .line 122
    .line 123
    const/16 v14, 0xd

    .line 124
    .line 125
    invoke-direct {v15, v9, v14}, Lc40/g;-><init>(Lz4/f;I)V

    .line 126
    .line 127
    .line 128
    invoke-virtual {v1, v15}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 129
    .line 130
    .line 131
    :cond_3
    check-cast v15, Lay0/k;

    .line 132
    .line 133
    invoke-static {v13, v8, v15}, Lz4/k;->b(Lx2/s;Lz4/f;Lay0/k;)Lx2/s;

    .line 134
    .line 135
    .line 136
    move-result-object v13

    .line 137
    iget-boolean v14, v0, Lxf0/a0;->i:Z

    .line 138
    .line 139
    invoke-static {v13, v14}, Lxf0/y1;->H(Lx2/s;Z)Lx2/s;

    .line 140
    .line 141
    .line 142
    move-result-object v13

    .line 143
    sget-object v15, Lx2/c;->p:Lx2/h;

    .line 144
    .line 145
    const/4 v12, 0x6

    .line 146
    invoke-static {v10, v15, v1, v12}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 147
    .line 148
    .line 149
    move-result-object v10

    .line 150
    move/from16 v30, v6

    .line 151
    .line 152
    iget-wide v5, v1, Ll2/t;->T:J

    .line 153
    .line 154
    invoke-static {v5, v6}, Ljava/lang/Long;->hashCode(J)I

    .line 155
    .line 156
    .line 157
    move-result v5

    .line 158
    invoke-virtual {v1}, Ll2/t;->m()Ll2/p1;

    .line 159
    .line 160
    .line 161
    move-result-object v6

    .line 162
    invoke-static {v1, v13}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 163
    .line 164
    .line 165
    move-result-object v12

    .line 166
    sget-object v13, Lv3/k;->m1:Lv3/j;

    .line 167
    .line 168
    invoke-virtual {v13}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 169
    .line 170
    .line 171
    sget-object v13, Lv3/j;->b:Lv3/i;

    .line 172
    .line 173
    invoke-virtual {v1}, Ll2/t;->c0()V

    .line 174
    .line 175
    .line 176
    iget-boolean v15, v1, Ll2/t;->S:Z

    .line 177
    .line 178
    if-eqz v15, :cond_4

    .line 179
    .line 180
    invoke-virtual {v1, v13}, Ll2/t;->l(Lay0/a;)V

    .line 181
    .line 182
    .line 183
    goto :goto_1

    .line 184
    :cond_4
    invoke-virtual {v1}, Ll2/t;->m0()V

    .line 185
    .line 186
    .line 187
    :goto_1
    sget-object v13, Lv3/j;->g:Lv3/h;

    .line 188
    .line 189
    invoke-static {v13, v10, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 190
    .line 191
    .line 192
    sget-object v10, Lv3/j;->f:Lv3/h;

    .line 193
    .line 194
    invoke-static {v10, v6, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 195
    .line 196
    .line 197
    sget-object v6, Lv3/j;->j:Lv3/h;

    .line 198
    .line 199
    iget-boolean v10, v1, Ll2/t;->S:Z

    .line 200
    .line 201
    if-nez v10, :cond_5

    .line 202
    .line 203
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 204
    .line 205
    .line 206
    move-result-object v10

    .line 207
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 208
    .line 209
    .line 210
    move-result-object v13

    .line 211
    invoke-static {v10, v13}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 212
    .line 213
    .line 214
    move-result v10

    .line 215
    if-nez v10, :cond_6

    .line 216
    .line 217
    :cond_5
    invoke-static {v5, v1, v5, v6}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 218
    .line 219
    .line 220
    :cond_6
    sget-object v5, Lv3/j;->d:Lv3/h;

    .line 221
    .line 222
    invoke-static {v5, v12, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 223
    .line 224
    .line 225
    const v5, -0x203aa33e

    .line 226
    .line 227
    .line 228
    invoke-virtual {v1, v5}, Ll2/t;->Y(I)V

    .line 229
    .line 230
    .line 231
    iget-object v5, v0, Lxf0/a0;->j:Lvf0/a;

    .line 232
    .line 233
    iget-object v6, v5, Lvf0/a;->b:Ljava/util/List;

    .line 234
    .line 235
    iget-object v10, v5, Lvf0/a;->e:Ljava/lang/Object;

    .line 236
    .line 237
    invoke-interface {v6}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 238
    .line 239
    .line 240
    move-result-object v6

    .line 241
    :goto_2
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    .line 242
    .line 243
    .line 244
    move-result v12

    .line 245
    if-eqz v12, :cond_7

    .line 246
    .line 247
    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 248
    .line 249
    .line 250
    move-result-object v12

    .line 251
    check-cast v12, Ljava/lang/String;

    .line 252
    .line 253
    sget-object v15, Lj91/j;->a:Ll2/u2;

    .line 254
    .line 255
    invoke-virtual {v1, v15}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 256
    .line 257
    .line 258
    move-result-object v15

    .line 259
    check-cast v15, Lj91/f;

    .line 260
    .line 261
    invoke-virtual {v15}, Lj91/f;->e()Lg4/p0;

    .line 262
    .line 263
    .line 264
    move-result-object v15

    .line 265
    sget-object v13, Lj91/h;->a:Ll2/u2;

    .line 266
    .line 267
    invoke-virtual {v1, v13}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 268
    .line 269
    .line 270
    move-result-object v13

    .line 271
    check-cast v13, Lj91/e;

    .line 272
    .line 273
    invoke-virtual {v13}, Lj91/e;->t()J

    .line 274
    .line 275
    .line 276
    move-result-wide v17

    .line 277
    const/16 v13, 0x14

    .line 278
    .line 279
    int-to-float v13, v13

    .line 280
    move-object/from16 v31, v4

    .line 281
    .line 282
    move-object/from16 v16, v12

    .line 283
    .line 284
    const/4 v4, 0x0

    .line 285
    const/4 v12, 0x2

    .line 286
    invoke-static {v11, v13, v4, v12}, Landroidx/compose/foundation/layout/d;->b(Lx2/s;FFI)Lx2/s;

    .line 287
    .line 288
    .line 289
    move-result-object v19

    .line 290
    sget-object v4, Lj91/a;->a:Ll2/u2;

    .line 291
    .line 292
    invoke-virtual {v1, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 293
    .line 294
    .line 295
    move-result-object v4

    .line 296
    check-cast v4, Lj91/c;

    .line 297
    .line 298
    iget v4, v4, Lj91/c;->b:F

    .line 299
    .line 300
    const/16 v23, 0x0

    .line 301
    .line 302
    const/16 v24, 0xe

    .line 303
    .line 304
    const/16 v21, 0x0

    .line 305
    .line 306
    const/16 v22, 0x0

    .line 307
    .line 308
    move/from16 v20, v4

    .line 309
    .line 310
    invoke-static/range {v19 .. v24}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 311
    .line 312
    .line 313
    move-result-object v4

    .line 314
    invoke-static {v4, v14}, Lxf0/y1;->H(Lx2/s;Z)Lx2/s;

    .line 315
    .line 316
    .line 317
    move-result-object v4

    .line 318
    const/16 v27, 0x0

    .line 319
    .line 320
    const v28, 0xfff0

    .line 321
    .line 322
    .line 323
    move/from16 v29, v12

    .line 324
    .line 325
    const-wide/16 v12, 0x0

    .line 326
    .line 327
    move/from16 v19, v14

    .line 328
    .line 329
    const/4 v14, 0x0

    .line 330
    move-object/from16 v20, v7

    .line 331
    .line 332
    move-object/from16 v21, v8

    .line 333
    .line 334
    move-object v8, v15

    .line 335
    move-object/from16 v7, v16

    .line 336
    .line 337
    const-wide/16 v15, 0x0

    .line 338
    .line 339
    move-object/from16 v22, v11

    .line 340
    .line 341
    move-wide/from16 v45, v17

    .line 342
    .line 343
    move-object/from16 v18, v10

    .line 344
    .line 345
    move-wide/from16 v10, v45

    .line 346
    .line 347
    const/16 v17, 0x0

    .line 348
    .line 349
    move-object/from16 v23, v18

    .line 350
    .line 351
    const/16 v18, 0x0

    .line 352
    .line 353
    move/from16 v25, v19

    .line 354
    .line 355
    move-object/from16 v24, v20

    .line 356
    .line 357
    const-wide/16 v19, 0x0

    .line 358
    .line 359
    move-object/from16 v26, v21

    .line 360
    .line 361
    const/16 v21, 0x0

    .line 362
    .line 363
    move-object/from16 v32, v22

    .line 364
    .line 365
    const/16 v22, 0x0

    .line 366
    .line 367
    move-object/from16 v33, v23

    .line 368
    .line 369
    const/16 v23, 0x0

    .line 370
    .line 371
    move-object/from16 v34, v24

    .line 372
    .line 373
    const/16 v24, 0x0

    .line 374
    .line 375
    move-object/from16 v35, v26

    .line 376
    .line 377
    const/16 v26, 0x0

    .line 378
    .line 379
    move-object/from16 p2, v9

    .line 380
    .line 381
    move/from16 v36, v25

    .line 382
    .line 383
    move-object/from16 v25, v1

    .line 384
    .line 385
    move-object v9, v4

    .line 386
    move-object/from16 v4, v34

    .line 387
    .line 388
    move-object/from16 v1, v35

    .line 389
    .line 390
    move/from16 v34, v29

    .line 391
    .line 392
    move-object/from16 v29, v6

    .line 393
    .line 394
    move-object/from16 v6, v32

    .line 395
    .line 396
    move-object/from16 v32, v2

    .line 397
    .line 398
    const/high16 v2, 0x3f800000    # 1.0f

    .line 399
    .line 400
    invoke-static/range {v7 .. v28}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 401
    .line 402
    .line 403
    move-object/from16 v9, p2

    .line 404
    .line 405
    move-object v8, v1

    .line 406
    move-object v7, v4

    .line 407
    move-object v11, v6

    .line 408
    move-object/from16 v1, v25

    .line 409
    .line 410
    move-object/from16 v6, v29

    .line 411
    .line 412
    move-object/from16 v4, v31

    .line 413
    .line 414
    move-object/from16 v2, v32

    .line 415
    .line 416
    move-object/from16 v10, v33

    .line 417
    .line 418
    move/from16 v14, v36

    .line 419
    .line 420
    goto/16 :goto_2

    .line 421
    .line 422
    :cond_7
    move-object/from16 v32, v2

    .line 423
    .line 424
    move-object/from16 v31, v4

    .line 425
    .line 426
    move-object v4, v7

    .line 427
    move-object/from16 v33, v10

    .line 428
    .line 429
    move-object v6, v11

    .line 430
    move/from16 v36, v14

    .line 431
    .line 432
    const/high16 v2, 0x3f800000    # 1.0f

    .line 433
    .line 434
    const/16 v16, 0x0

    .line 435
    .line 436
    move-object v7, v1

    .line 437
    move-object v1, v8

    .line 438
    move-object v8, v9

    .line 439
    const/4 v9, 0x0

    .line 440
    invoke-virtual {v7, v9}, Ll2/t;->q(Z)V

    .line 441
    .line 442
    .line 443
    const/4 v10, 0x1

    .line 444
    invoke-virtual {v7, v10}, Ll2/t;->q(Z)V

    .line 445
    .line 446
    .line 447
    invoke-static {v6, v2}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 448
    .line 449
    .line 450
    move-result-object v11

    .line 451
    invoke-virtual {v7, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 452
    .line 453
    .line 454
    move-result v12

    .line 455
    invoke-virtual {v7}, Ll2/t;->L()Ljava/lang/Object;

    .line 456
    .line 457
    .line 458
    move-result-object v13

    .line 459
    if-nez v12, :cond_8

    .line 460
    .line 461
    if-ne v13, v3, :cond_9

    .line 462
    .line 463
    :cond_8
    new-instance v13, Lc40/g;

    .line 464
    .line 465
    const/16 v12, 0xe

    .line 466
    .line 467
    invoke-direct {v13, v1, v12}, Lc40/g;-><init>(Lz4/f;I)V

    .line 468
    .line 469
    .line 470
    invoke-virtual {v7, v13}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 471
    .line 472
    .line 473
    :cond_9
    check-cast v13, Lay0/k;

    .line 474
    .line 475
    invoke-static {v11, v8, v13}, Lz4/k;->b(Lx2/s;Lz4/f;Lay0/k;)Lx2/s;

    .line 476
    .line 477
    .line 478
    move-result-object v11

    .line 479
    invoke-virtual {v7, v5}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 480
    .line 481
    .line 482
    move-result v12

    .line 483
    iget-wide v13, v0, Lxf0/a0;->k:J

    .line 484
    .line 485
    invoke-virtual {v7, v13, v14}, Ll2/t;->f(J)Z

    .line 486
    .line 487
    .line 488
    move-result v15

    .line 489
    or-int/2addr v12, v15

    .line 490
    invoke-virtual {v7}, Ll2/t;->L()Ljava/lang/Object;

    .line 491
    .line 492
    .line 493
    move-result-object v15

    .line 494
    if-nez v12, :cond_a

    .line 495
    .line 496
    if-ne v15, v3, :cond_b

    .line 497
    .line 498
    :cond_a
    new-instance v15, Lxf0/x;

    .line 499
    .line 500
    invoke-direct {v15, v5, v13, v14}, Lxf0/x;-><init>(Lvf0/a;J)V

    .line 501
    .line 502
    .line 503
    invoke-virtual {v7, v15}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 504
    .line 505
    .line 506
    :cond_b
    check-cast v15, Lay0/k;

    .line 507
    .line 508
    invoke-static {v11, v15}, Landroidx/compose/ui/draw/a;->a(Lx2/s;Lay0/k;)Lx2/s;

    .line 509
    .line 510
    .line 511
    move-result-object v11

    .line 512
    sget-object v12, Lk1/j;->a:Lk1/c;

    .line 513
    .line 514
    sget-object v15, Lx2/c;->m:Lx2/i;

    .line 515
    .line 516
    invoke-static {v12, v15, v7, v9}, Lk1/e1;->a(Lk1/g;Lx2/i;Ll2/o;I)Lk1/g1;

    .line 517
    .line 518
    .line 519
    move-result-object v12

    .line 520
    iget-wide v9, v7, Ll2/t;->T:J

    .line 521
    .line 522
    invoke-static {v9, v10}, Ljava/lang/Long;->hashCode(J)I

    .line 523
    .line 524
    .line 525
    move-result v9

    .line 526
    invoke-virtual {v7}, Ll2/t;->m()Ll2/p1;

    .line 527
    .line 528
    .line 529
    move-result-object v10

    .line 530
    invoke-static {v7, v11}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 531
    .line 532
    .line 533
    move-result-object v11

    .line 534
    sget-object v17, Lv3/k;->m1:Lv3/j;

    .line 535
    .line 536
    invoke-virtual/range {v17 .. v17}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 537
    .line 538
    .line 539
    sget-object v15, Lv3/j;->b:Lv3/i;

    .line 540
    .line 541
    invoke-virtual {v7}, Ll2/t;->c0()V

    .line 542
    .line 543
    .line 544
    iget-boolean v2, v7, Ll2/t;->S:Z

    .line 545
    .line 546
    if-eqz v2, :cond_c

    .line 547
    .line 548
    invoke-virtual {v7, v15}, Ll2/t;->l(Lay0/a;)V

    .line 549
    .line 550
    .line 551
    goto :goto_3

    .line 552
    :cond_c
    invoke-virtual {v7}, Ll2/t;->m0()V

    .line 553
    .line 554
    .line 555
    :goto_3
    sget-object v2, Lv3/j;->g:Lv3/h;

    .line 556
    .line 557
    invoke-static {v2, v12, v7}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 558
    .line 559
    .line 560
    sget-object v2, Lv3/j;->f:Lv3/h;

    .line 561
    .line 562
    invoke-static {v2, v10, v7}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 563
    .line 564
    .line 565
    sget-object v2, Lv3/j;->j:Lv3/h;

    .line 566
    .line 567
    iget-boolean v10, v7, Ll2/t;->S:Z

    .line 568
    .line 569
    if-nez v10, :cond_d

    .line 570
    .line 571
    invoke-virtual {v7}, Ll2/t;->L()Ljava/lang/Object;

    .line 572
    .line 573
    .line 574
    move-result-object v10

    .line 575
    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 576
    .line 577
    .line 578
    move-result-object v12

    .line 579
    invoke-static {v10, v12}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 580
    .line 581
    .line 582
    move-result v10

    .line 583
    if-nez v10, :cond_e

    .line 584
    .line 585
    :cond_d
    invoke-static {v9, v7, v9, v2}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 586
    .line 587
    .line 588
    :cond_e
    sget-object v2, Lv3/j;->d:Lv3/h;

    .line 589
    .line 590
    invoke-static {v2, v11, v7}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 591
    .line 592
    .line 593
    const v2, -0x5d09d27c

    .line 594
    .line 595
    .line 596
    invoke-virtual {v7, v2}, Ll2/t;->Y(I)V

    .line 597
    .line 598
    .line 599
    iget-object v2, v5, Lvf0/a;->a:Ljava/util/List;

    .line 600
    .line 601
    invoke-interface {v2}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 602
    .line 603
    .line 604
    move-result-object v2

    .line 605
    :goto_4
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 606
    .line 607
    .line 608
    move-result v9

    .line 609
    if-eqz v9, :cond_10

    .line 610
    .line 611
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 612
    .line 613
    .line 614
    move-result-object v9

    .line 615
    check-cast v9, Ljava/lang/String;

    .line 616
    .line 617
    sget-object v10, Lj91/j;->a:Ll2/u2;

    .line 618
    .line 619
    invoke-virtual {v7, v10}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 620
    .line 621
    .line 622
    move-result-object v10

    .line 623
    check-cast v10, Lj91/f;

    .line 624
    .line 625
    invoke-virtual {v10}, Lj91/f;->e()Lg4/p0;

    .line 626
    .line 627
    .line 628
    move-result-object v10

    .line 629
    sget-object v11, Lj91/h;->a:Ll2/u2;

    .line 630
    .line 631
    invoke-virtual {v7, v11}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 632
    .line 633
    .line 634
    move-result-object v11

    .line 635
    check-cast v11, Lj91/e;

    .line 636
    .line 637
    invoke-virtual {v11}, Lj91/e;->t()J

    .line 638
    .line 639
    .line 640
    move-result-wide v11

    .line 641
    move-object/from16 v25, v7

    .line 642
    .line 643
    move-object/from16 v18, v8

    .line 644
    .line 645
    const/high16 v15, 0x3f800000    # 1.0f

    .line 646
    .line 647
    float-to-double v7, v15

    .line 648
    const-wide/16 v19, 0x0

    .line 649
    .line 650
    cmpl-double v7, v7, v19

    .line 651
    .line 652
    if-lez v7, :cond_f

    .line 653
    .line 654
    goto :goto_5

    .line 655
    :cond_f
    const-string v7, "invalid weight; must be greater than zero"

    .line 656
    .line 657
    invoke-static {v7}, Ll1/a;->a(Ljava/lang/String;)V

    .line 658
    .line 659
    .line 660
    :goto_5
    new-instance v7, Landroidx/compose/foundation/layout/LayoutWeightElement;

    .line 661
    .line 662
    const/4 v8, 0x1

    .line 663
    invoke-direct {v7, v15, v8}, Landroidx/compose/foundation/layout/LayoutWeightElement;-><init>(FZ)V

    .line 664
    .line 665
    .line 666
    move-wide/from16 v19, v11

    .line 667
    .line 668
    move/from16 v12, v36

    .line 669
    .line 670
    invoke-static {v7, v12}, Lxf0/y1;->H(Lx2/s;Z)Lx2/s;

    .line 671
    .line 672
    .line 673
    move-result-object v7

    .line 674
    new-instance v11, Lr4/k;

    .line 675
    .line 676
    const/4 v12, 0x3

    .line 677
    invoke-direct {v11, v12}, Lr4/k;-><init>(I)V

    .line 678
    .line 679
    .line 680
    const/16 v27, 0x0

    .line 681
    .line 682
    const v28, 0xfbf0

    .line 683
    .line 684
    .line 685
    move-wide/from16 v21, v13

    .line 686
    .line 687
    move v14, v12

    .line 688
    const-wide/16 v12, 0x0

    .line 689
    .line 690
    move/from16 v17, v14

    .line 691
    .line 692
    const/4 v14, 0x0

    .line 693
    move/from16 v29, v15

    .line 694
    .line 695
    move/from16 v23, v16

    .line 696
    .line 697
    const-wide/16 v15, 0x0

    .line 698
    .line 699
    move/from16 v24, v17

    .line 700
    .line 701
    const/16 v17, 0x0

    .line 702
    .line 703
    move/from16 v34, v8

    .line 704
    .line 705
    move-object v8, v10

    .line 706
    move-object/from16 v26, v18

    .line 707
    .line 708
    move-object/from16 v18, v11

    .line 709
    .line 710
    move-wide/from16 v10, v19

    .line 711
    .line 712
    const-wide/16 v19, 0x0

    .line 713
    .line 714
    move-wide/from16 v37, v21

    .line 715
    .line 716
    const/16 v21, 0x0

    .line 717
    .line 718
    const/16 v22, 0x0

    .line 719
    .line 720
    move/from16 v35, v23

    .line 721
    .line 722
    const/16 v23, 0x0

    .line 723
    .line 724
    move/from16 v39, v24

    .line 725
    .line 726
    const/16 v24, 0x0

    .line 727
    .line 728
    move-object/from16 v40, v26

    .line 729
    .line 730
    const/16 v26, 0x0

    .line 731
    .line 732
    move-object/from16 p1, v9

    .line 733
    .line 734
    move-object v9, v7

    .line 735
    move-object/from16 v7, p1

    .line 736
    .line 737
    move-object/from16 p1, v2

    .line 738
    .line 739
    move/from16 v44, v36

    .line 740
    .line 741
    move-wide/from16 v42, v37

    .line 742
    .line 743
    move-object/from16 v41, v40

    .line 744
    .line 745
    const/4 v2, 0x0

    .line 746
    invoke-static/range {v7 .. v28}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 747
    .line 748
    .line 749
    move-object/from16 v2, p1

    .line 750
    .line 751
    move-object/from16 v7, v25

    .line 752
    .line 753
    move-object/from16 v8, v41

    .line 754
    .line 755
    move-wide/from16 v13, v42

    .line 756
    .line 757
    const/16 v16, 0x0

    .line 758
    .line 759
    goto/16 :goto_4

    .line 760
    .line 761
    :cond_10
    move-object/from16 v41, v8

    .line 762
    .line 763
    move-wide/from16 v42, v13

    .line 764
    .line 765
    move/from16 v44, v36

    .line 766
    .line 767
    const/4 v2, 0x0

    .line 768
    invoke-virtual {v7, v2}, Ll2/t;->q(Z)V

    .line 769
    .line 770
    .line 771
    const/4 v8, 0x1

    .line 772
    invoke-virtual {v7, v8}, Ll2/t;->q(Z)V

    .line 773
    .line 774
    .line 775
    sget-object v9, Lx2/c;->o:Lx2/i;

    .line 776
    .line 777
    invoke-virtual {v7, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 778
    .line 779
    .line 780
    move-result v10

    .line 781
    move-object/from16 v11, v41

    .line 782
    .line 783
    invoke-virtual {v7, v11}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 784
    .line 785
    .line 786
    move-result v12

    .line 787
    or-int/2addr v10, v12

    .line 788
    invoke-virtual {v7}, Ll2/t;->L()Ljava/lang/Object;

    .line 789
    .line 790
    .line 791
    move-result-object v12

    .line 792
    if-nez v10, :cond_11

    .line 793
    .line 794
    if-ne v12, v3, :cond_12

    .line 795
    .line 796
    :cond_11
    new-instance v12, Luz/s;

    .line 797
    .line 798
    const/4 v10, 0x1

    .line 799
    invoke-direct {v12, v1, v11, v10}, Luz/s;-><init>(Lz4/f;Lz4/f;I)V

    .line 800
    .line 801
    .line 802
    invoke-virtual {v7, v12}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 803
    .line 804
    .line 805
    :cond_12
    check-cast v12, Lay0/k;

    .line 806
    .line 807
    invoke-static {v6, v4, v12}, Lz4/k;->b(Lx2/s;Lz4/f;Lay0/k;)Lx2/s;

    .line 808
    .line 809
    .line 810
    move-result-object v1

    .line 811
    iget-boolean v4, v0, Lxf0/a0;->l:Z

    .line 812
    .line 813
    invoke-virtual {v7, v4}, Ll2/t;->h(Z)Z

    .line 814
    .line 815
    .line 816
    move-result v4

    .line 817
    move/from16 v12, v44

    .line 818
    .line 819
    invoke-virtual {v7, v12}, Ll2/t;->h(Z)Z

    .line 820
    .line 821
    .line 822
    move-result v6

    .line 823
    or-int/2addr v4, v6

    .line 824
    invoke-virtual {v7, v5}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 825
    .line 826
    .line 827
    move-result v6

    .line 828
    or-int/2addr v4, v6

    .line 829
    iget-wide v10, v0, Lxf0/a0;->m:J

    .line 830
    .line 831
    invoke-virtual {v7, v10, v11}, Ll2/t;->f(J)Z

    .line 832
    .line 833
    .line 834
    move-result v6

    .line 835
    or-int/2addr v4, v6

    .line 836
    iget v6, v0, Lxf0/a0;->n:F

    .line 837
    .line 838
    invoke-virtual {v7, v6}, Ll2/t;->d(F)Z

    .line 839
    .line 840
    .line 841
    move-result v10

    .line 842
    or-int/2addr v4, v10

    .line 843
    invoke-virtual {v7}, Ll2/t;->L()Ljava/lang/Object;

    .line 844
    .line 845
    .line 846
    move-result-object v10

    .line 847
    if-nez v4, :cond_14

    .line 848
    .line 849
    if-ne v10, v3, :cond_13

    .line 850
    .line 851
    goto :goto_6

    .line 852
    :cond_13
    move-object v4, v5

    .line 853
    goto :goto_7

    .line 854
    :cond_14
    :goto_6
    new-instance v15, Lxf0/y;

    .line 855
    .line 856
    iget-wide v10, v0, Lxf0/a0;->m:J

    .line 857
    .line 858
    iget v4, v0, Lxf0/a0;->n:F

    .line 859
    .line 860
    iget-boolean v12, v0, Lxf0/a0;->l:Z

    .line 861
    .line 862
    iget-boolean v13, v0, Lxf0/a0;->i:Z

    .line 863
    .line 864
    move/from16 v21, v4

    .line 865
    .line 866
    move-object/from16 v18, v5

    .line 867
    .line 868
    move-wide/from16 v19, v10

    .line 869
    .line 870
    move/from16 v16, v12

    .line 871
    .line 872
    move/from16 v17, v13

    .line 873
    .line 874
    invoke-direct/range {v15 .. v21}, Lxf0/y;-><init>(ZZLvf0/a;JF)V

    .line 875
    .line 876
    .line 877
    move-object/from16 v4, v18

    .line 878
    .line 879
    invoke-virtual {v7, v15}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 880
    .line 881
    .line 882
    move-object v10, v15

    .line 883
    :goto_7
    check-cast v10, Lay0/k;

    .line 884
    .line 885
    invoke-static {v1, v10}, Landroidx/compose/ui/draw/a;->c(Lx2/s;Lay0/k;)Lx2/s;

    .line 886
    .line 887
    .line 888
    move-result-object v1

    .line 889
    invoke-virtual {v7, v4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 890
    .line 891
    .line 892
    move-result v5

    .line 893
    move-wide/from16 v10, v42

    .line 894
    .line 895
    invoke-virtual {v7, v10, v11}, Ll2/t;->f(J)Z

    .line 896
    .line 897
    .line 898
    move-result v12

    .line 899
    or-int/2addr v5, v12

    .line 900
    invoke-virtual {v7, v6}, Ll2/t;->d(F)Z

    .line 901
    .line 902
    .line 903
    move-result v12

    .line 904
    or-int/2addr v5, v12

    .line 905
    invoke-virtual {v7}, Ll2/t;->L()Ljava/lang/Object;

    .line 906
    .line 907
    .line 908
    move-result-object v12

    .line 909
    if-nez v5, :cond_15

    .line 910
    .line 911
    if-ne v12, v3, :cond_16

    .line 912
    .line 913
    :cond_15
    new-instance v12, Lxf0/z;

    .line 914
    .line 915
    invoke-direct {v12, v4, v10, v11, v6}, Lxf0/z;-><init>(Lvf0/a;JF)V

    .line 916
    .line 917
    .line 918
    invoke-virtual {v7, v12}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 919
    .line 920
    .line 921
    :cond_16
    check-cast v12, Lay0/k;

    .line 922
    .line 923
    invoke-static {v1, v12}, Landroidx/compose/ui/draw/a;->a(Lx2/s;Lay0/k;)Lx2/s;

    .line 924
    .line 925
    .line 926
    move-result-object v1

    .line 927
    const/4 v5, 0x0

    .line 928
    invoke-static {v1, v5, v6, v8}, Landroidx/compose/foundation/layout/a;->o(Lx2/s;FFI)Lx2/s;

    .line 929
    .line 930
    .line 931
    move-result-object v1

    .line 932
    sget-object v5, Lk1/j;->a:Lk1/c;

    .line 933
    .line 934
    const/16 v6, 0x30

    .line 935
    .line 936
    invoke-static {v5, v9, v7, v6}, Lk1/e1;->a(Lk1/g;Lx2/i;Ll2/o;I)Lk1/g1;

    .line 937
    .line 938
    .line 939
    move-result-object v5

    .line 940
    iget-wide v9, v7, Ll2/t;->T:J

    .line 941
    .line 942
    invoke-static {v9, v10}, Ljava/lang/Long;->hashCode(J)I

    .line 943
    .line 944
    .line 945
    move-result v6

    .line 946
    invoke-virtual {v7}, Ll2/t;->m()Ll2/p1;

    .line 947
    .line 948
    .line 949
    move-result-object v9

    .line 950
    invoke-static {v7, v1}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 951
    .line 952
    .line 953
    move-result-object v1

    .line 954
    sget-object v10, Lv3/k;->m1:Lv3/j;

    .line 955
    .line 956
    invoke-virtual {v10}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 957
    .line 958
    .line 959
    sget-object v10, Lv3/j;->b:Lv3/i;

    .line 960
    .line 961
    invoke-virtual {v7}, Ll2/t;->c0()V

    .line 962
    .line 963
    .line 964
    iget-boolean v11, v7, Ll2/t;->S:Z

    .line 965
    .line 966
    if-eqz v11, :cond_17

    .line 967
    .line 968
    invoke-virtual {v7, v10}, Ll2/t;->l(Lay0/a;)V

    .line 969
    .line 970
    .line 971
    goto :goto_8

    .line 972
    :cond_17
    invoke-virtual {v7}, Ll2/t;->m0()V

    .line 973
    .line 974
    .line 975
    :goto_8
    sget-object v10, Lv3/j;->g:Lv3/h;

    .line 976
    .line 977
    invoke-static {v10, v5, v7}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 978
    .line 979
    .line 980
    sget-object v5, Lv3/j;->f:Lv3/h;

    .line 981
    .line 982
    invoke-static {v5, v9, v7}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 983
    .line 984
    .line 985
    sget-object v5, Lv3/j;->j:Lv3/h;

    .line 986
    .line 987
    iget-boolean v9, v7, Ll2/t;->S:Z

    .line 988
    .line 989
    if-nez v9, :cond_18

    .line 990
    .line 991
    invoke-virtual {v7}, Ll2/t;->L()Ljava/lang/Object;

    .line 992
    .line 993
    .line 994
    move-result-object v9

    .line 995
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 996
    .line 997
    .line 998
    move-result-object v10

    .line 999
    invoke-static {v9, v10}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1000
    .line 1001
    .line 1002
    move-result v9

    .line 1003
    if-nez v9, :cond_19

    .line 1004
    .line 1005
    :cond_18
    invoke-static {v6, v7, v6, v5}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 1006
    .line 1007
    .line 1008
    :cond_19
    sget-object v5, Lv3/j;->d:Lv3/h;

    .line 1009
    .line 1010
    invoke-static {v5, v1, v7}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 1011
    .line 1012
    .line 1013
    invoke-virtual {v7}, Ll2/t;->L()Ljava/lang/Object;

    .line 1014
    .line 1015
    .line 1016
    move-result-object v1

    .line 1017
    if-ne v1, v3, :cond_1a

    .line 1018
    .line 1019
    invoke-interface/range {v33 .. v33}, Ljava/util/List;->size()I

    .line 1020
    .line 1021
    .line 1022
    move-result v1

    .line 1023
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1024
    .line 1025
    .line 1026
    move-result-object v1

    .line 1027
    invoke-static {v1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 1028
    .line 1029
    .line 1030
    move-result-object v1

    .line 1031
    invoke-virtual {v7, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 1032
    .line 1033
    .line 1034
    :cond_1a
    check-cast v1, Ll2/b1;

    .line 1035
    .line 1036
    invoke-interface {v1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 1037
    .line 1038
    .line 1039
    move-result-object v3

    .line 1040
    check-cast v3, Ljava/lang/Number;

    .line 1041
    .line 1042
    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    .line 1043
    .line 1044
    .line 1045
    move-result v3

    .line 1046
    invoke-interface/range {v33 .. v33}, Ljava/util/List;->size()I

    .line 1047
    .line 1048
    .line 1049
    move-result v5

    .line 1050
    if-eq v3, v5, :cond_1b

    .line 1051
    .line 1052
    move v9, v8

    .line 1053
    goto :goto_9

    .line 1054
    :cond_1b
    move v9, v2

    .line 1055
    :goto_9
    invoke-interface/range {v33 .. v33}, Ljava/util/List;->size()I

    .line 1056
    .line 1057
    .line 1058
    move-result v3

    .line 1059
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1060
    .line 1061
    .line 1062
    move-result-object v3

    .line 1063
    invoke-interface {v1, v3}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 1064
    .line 1065
    .line 1066
    if-nez v9, :cond_1f

    .line 1067
    .line 1068
    const v1, -0x7c821a78

    .line 1069
    .line 1070
    .line 1071
    invoke-virtual {v7, v1}, Ll2/t;->Y(I)V

    .line 1072
    .line 1073
    .line 1074
    invoke-interface/range {v33 .. v33}, Ljava/util/List;->size()I

    .line 1075
    .line 1076
    .line 1077
    move-result v1

    .line 1078
    move v9, v2

    .line 1079
    :goto_a
    if-ge v9, v1, :cond_1e

    .line 1080
    .line 1081
    move-object/from16 v3, v33

    .line 1082
    .line 1083
    invoke-static {v9, v3}, Lmx0/q;->M(ILjava/util/List;)Ljava/lang/Object;

    .line 1084
    .line 1085
    .line 1086
    move-result-object v5

    .line 1087
    check-cast v5, Ljava/util/List;

    .line 1088
    .line 1089
    if-eqz v5, :cond_1c

    .line 1090
    .line 1091
    invoke-static {v2, v5}, Lmx0/q;->M(ILjava/util/List;)Ljava/lang/Object;

    .line 1092
    .line 1093
    .line 1094
    move-result-object v5

    .line 1095
    check-cast v5, Ljava/lang/Number;

    .line 1096
    .line 1097
    :cond_1c
    invoke-static {v9, v3}, Lmx0/q;->M(ILjava/util/List;)Ljava/lang/Object;

    .line 1098
    .line 1099
    .line 1100
    move-result-object v5

    .line 1101
    check-cast v5, Ljava/util/List;

    .line 1102
    .line 1103
    if-nez v5, :cond_1d

    .line 1104
    .line 1105
    sget-object v5, Lmx0/s;->d:Lmx0/s;

    .line 1106
    .line 1107
    :cond_1d
    move-object/from16 v25, v7

    .line 1108
    .line 1109
    move v7, v9

    .line 1110
    iget v9, v4, Lvf0/a;->c:I

    .line 1111
    .line 1112
    iget v10, v4, Lvf0/a;->f:F

    .line 1113
    .line 1114
    const/4 v15, 0x1

    .line 1115
    const/16 v17, 0x6

    .line 1116
    .line 1117
    iget-object v11, v0, Lxf0/a0;->o:Ljava/lang/Integer;

    .line 1118
    .line 1119
    iget-object v12, v0, Lxf0/a0;->p:Ljava/util/List;

    .line 1120
    .line 1121
    iget-object v13, v0, Lxf0/a0;->q:Lay0/k;

    .line 1122
    .line 1123
    iget-boolean v14, v0, Lxf0/a0;->i:Z

    .line 1124
    .line 1125
    move/from16 v16, v8

    .line 1126
    .line 1127
    move-object v8, v5

    .line 1128
    move/from16 v5, v16

    .line 1129
    .line 1130
    move-object/from16 v16, v25

    .line 1131
    .line 1132
    invoke-static/range {v7 .. v17}, Lxf0/b0;->a(ILjava/util/List;IFLjava/lang/Integer;Ljava/util/List;Lay0/k;ZZLl2/o;I)V

    .line 1133
    .line 1134
    .line 1135
    move v6, v7

    .line 1136
    move-object/from16 v7, v16

    .line 1137
    .line 1138
    add-int/lit8 v9, v6, 0x1

    .line 1139
    .line 1140
    move-object/from16 v33, v3

    .line 1141
    .line 1142
    move v8, v5

    .line 1143
    goto :goto_a

    .line 1144
    :cond_1e
    move v5, v8

    .line 1145
    :goto_b
    invoke-virtual {v7, v2}, Ll2/t;->q(Z)V

    .line 1146
    .line 1147
    .line 1148
    goto :goto_c

    .line 1149
    :cond_1f
    move v5, v8

    .line 1150
    const v1, -0x7ce69cb6

    .line 1151
    .line 1152
    .line 1153
    invoke-virtual {v7, v1}, Ll2/t;->Y(I)V

    .line 1154
    .line 1155
    .line 1156
    goto :goto_b

    .line 1157
    :goto_c
    invoke-virtual {v7, v5}, Ll2/t;->q(Z)V

    .line 1158
    .line 1159
    .line 1160
    invoke-virtual {v7, v2}, Ll2/t;->q(Z)V

    .line 1161
    .line 1162
    .line 1163
    move-object/from16 v1, v32

    .line 1164
    .line 1165
    iget v1, v1, Lz4/k;->b:I

    .line 1166
    .line 1167
    move/from16 v2, v30

    .line 1168
    .line 1169
    if-eq v1, v2, :cond_20

    .line 1170
    .line 1171
    iget-object v0, v0, Lxf0/a0;->h:Lay0/a;

    .line 1172
    .line 1173
    invoke-static {v0, v7}, Ll2/l0;->g(Lay0/a;Ll2/o;)V

    .line 1174
    .line 1175
    .line 1176
    :cond_20
    return-object v31
.end method
