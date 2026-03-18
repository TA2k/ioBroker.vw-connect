.class public final Lvu0/e;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic f:Ll2/b1;

.field public final synthetic g:Lz4/k;

.field public final synthetic h:Lay0/a;

.field public final synthetic i:Ljava/lang/String;

.field public final synthetic j:Ljava/lang/String;

.field public final synthetic k:Z

.field public final synthetic l:Ljava/lang/String;

.field public final synthetic m:Lay0/a;

.field public final synthetic n:Z

.field public final synthetic o:Lay0/a;


# direct methods
.method public constructor <init>(Ll2/b1;Lz4/k;Lay0/a;Ljava/lang/String;Ljava/lang/String;ZLjava/lang/String;Lay0/a;ZLay0/a;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lvu0/e;->f:Ll2/b1;

    .line 2
    .line 3
    iput-object p2, p0, Lvu0/e;->g:Lz4/k;

    .line 4
    .line 5
    iput-object p3, p0, Lvu0/e;->h:Lay0/a;

    .line 6
    .line 7
    iput-object p4, p0, Lvu0/e;->i:Ljava/lang/String;

    .line 8
    .line 9
    iput-object p5, p0, Lvu0/e;->j:Ljava/lang/String;

    .line 10
    .line 11
    iput-boolean p6, p0, Lvu0/e;->k:Z

    .line 12
    .line 13
    iput-object p7, p0, Lvu0/e;->l:Ljava/lang/String;

    .line 14
    .line 15
    iput-object p8, p0, Lvu0/e;->m:Lay0/a;

    .line 16
    .line 17
    iput-boolean p9, p0, Lvu0/e;->n:Z

    .line 18
    .line 19
    iput-object p10, p0, Lvu0/e;->o:Lay0/a;

    .line 20
    .line 21
    const/4 p1, 0x2

    .line 22
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 23
    .line 24
    .line 25
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 35

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
    and-int/lit8 v2, v2, 0x3

    .line 16
    .line 17
    const/4 v3, 0x2

    .line 18
    sget-object v4, Llx0/b0;->a:Llx0/b0;

    .line 19
    .line 20
    if-ne v2, v3, :cond_1

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
    move-result v3

    .line 29
    if-nez v3, :cond_0

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
    iget-object v2, v0, Lvu0/e;->f:Ll2/b1;

    .line 37
    .line 38
    invoke-interface {v2, v4}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    iget-object v2, v0, Lvu0/e;->g:Lz4/k;

    .line 42
    .line 43
    iget v3, v2, Lz4/k;->b:I

    .line 44
    .line 45
    invoke-virtual {v2}, Lz4/k;->e()V

    .line 46
    .line 47
    .line 48
    move-object v10, v1

    .line 49
    check-cast v10, Ll2/t;

    .line 50
    .line 51
    const v1, 0x169819f8

    .line 52
    .line 53
    .line 54
    invoke-virtual {v10, v1}, Ll2/t;->Y(I)V

    .line 55
    .line 56
    .line 57
    invoke-virtual {v2}, Lz4/k;->d()Lt1/j0;

    .line 58
    .line 59
    .line 60
    move-result-object v1

    .line 61
    iget-object v1, v1, Lt1/j0;->e:Ljava/lang/Object;

    .line 62
    .line 63
    check-cast v1, Lz4/k;

    .line 64
    .line 65
    invoke-virtual {v1}, Lz4/k;->c()Lz4/f;

    .line 66
    .line 67
    .line 68
    move-result-object v5

    .line 69
    invoke-virtual {v1}, Lz4/k;->c()Lz4/f;

    .line 70
    .line 71
    .line 72
    move-result-object v6

    .line 73
    invoke-virtual {v1}, Lz4/k;->c()Lz4/f;

    .line 74
    .line 75
    .line 76
    move-result-object v1

    .line 77
    sget-object v7, Lj91/j;->a:Ll2/u2;

    .line 78
    .line 79
    invoke-virtual {v10, v7}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 80
    .line 81
    .line 82
    move-result-object v8

    .line 83
    check-cast v8, Lj91/f;

    .line 84
    .line 85
    invoke-virtual {v8}, Lj91/f;->i()Lg4/p0;

    .line 86
    .line 87
    .line 88
    move-result-object v8

    .line 89
    sget-object v9, Lx2/p;->b:Lx2/p;

    .line 90
    .line 91
    const/high16 v11, 0x3f800000    # 1.0f

    .line 92
    .line 93
    invoke-static {v9, v11}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 94
    .line 95
    .line 96
    move-result-object v12

    .line 97
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 98
    .line 99
    .line 100
    move-result-object v13

    .line 101
    sget-object v14, Ll2/n;->a:Ll2/x0;

    .line 102
    .line 103
    if-ne v13, v14, :cond_2

    .line 104
    .line 105
    sget-object v13, Lvu0/f;->e:Lvu0/f;

    .line 106
    .line 107
    invoke-virtual {v10, v13}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 108
    .line 109
    .line 110
    :cond_2
    check-cast v13, Lay0/k;

    .line 111
    .line 112
    invoke-static {v12, v5, v13}, Lz4/k;->b(Lx2/s;Lz4/f;Lay0/k;)Lx2/s;

    .line 113
    .line 114
    .line 115
    move-result-object v12

    .line 116
    new-instance v13, Lr4/k;

    .line 117
    .line 118
    const/4 v15, 0x5

    .line 119
    invoke-direct {v13, v15}, Lr4/k;-><init>(I)V

    .line 120
    .line 121
    .line 122
    const/16 v25, 0x0

    .line 123
    .line 124
    const v26, 0xfbf8

    .line 125
    .line 126
    .line 127
    move-object/from16 v16, v5

    .line 128
    .line 129
    iget-object v5, v0, Lvu0/e;->i:Ljava/lang/String;

    .line 130
    .line 131
    move-object/from16 v17, v6

    .line 132
    .line 133
    move-object v6, v8

    .line 134
    move-object/from16 v18, v9

    .line 135
    .line 136
    const-wide/16 v8, 0x0

    .line 137
    .line 138
    move-object/from16 v23, v10

    .line 139
    .line 140
    move/from16 v19, v11

    .line 141
    .line 142
    const-wide/16 v10, 0x0

    .line 143
    .line 144
    move-object/from16 v20, v7

    .line 145
    .line 146
    move-object v7, v12

    .line 147
    const/4 v12, 0x0

    .line 148
    move-object/from16 v22, v14

    .line 149
    .line 150
    move-object/from16 v21, v16

    .line 151
    .line 152
    move-object/from16 v16, v13

    .line 153
    .line 154
    const-wide/16 v13, 0x0

    .line 155
    .line 156
    move/from16 v24, v15

    .line 157
    .line 158
    const/4 v15, 0x0

    .line 159
    move-object/from16 v27, v17

    .line 160
    .line 161
    move-object/from16 v28, v18

    .line 162
    .line 163
    const-wide/16 v17, 0x0

    .line 164
    .line 165
    move/from16 v29, v19

    .line 166
    .line 167
    const/16 v19, 0x0

    .line 168
    .line 169
    move-object/from16 v30, v20

    .line 170
    .line 171
    const/16 v20, 0x0

    .line 172
    .line 173
    move-object/from16 v31, v21

    .line 174
    .line 175
    const/16 v21, 0x0

    .line 176
    .line 177
    move-object/from16 v32, v22

    .line 178
    .line 179
    const/16 v22, 0x0

    .line 180
    .line 181
    move/from16 v33, v24

    .line 182
    .line 183
    const/16 v24, 0x0

    .line 184
    .line 185
    move-object/from16 p1, v27

    .line 186
    .line 187
    move/from16 v27, v3

    .line 188
    .line 189
    move-object/from16 v3, p1

    .line 190
    .line 191
    move-object/from16 p2, v1

    .line 192
    .line 193
    move-object/from16 p1, v4

    .line 194
    .line 195
    move-object/from16 v0, v28

    .line 196
    .line 197
    move/from16 v1, v29

    .line 198
    .line 199
    move-object/from16 v4, v31

    .line 200
    .line 201
    move-object/from16 v34, v32

    .line 202
    .line 203
    move-object/from16 v28, v2

    .line 204
    .line 205
    move-object/from16 v2, v30

    .line 206
    .line 207
    invoke-static/range {v5 .. v26}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 208
    .line 209
    .line 210
    move-object/from16 v10, v23

    .line 211
    .line 212
    invoke-virtual {v10, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 213
    .line 214
    .line 215
    move-result-object v2

    .line 216
    check-cast v2, Lj91/f;

    .line 217
    .line 218
    invoke-virtual {v2}, Lj91/f;->b()Lg4/p0;

    .line 219
    .line 220
    .line 221
    move-result-object v6

    .line 222
    invoke-static {v0, v1}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 223
    .line 224
    .line 225
    move-result-object v1

    .line 226
    invoke-virtual {v10, v4}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 227
    .line 228
    .line 229
    move-result v2

    .line 230
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 231
    .line 232
    .line 233
    move-result-object v5

    .line 234
    if-nez v2, :cond_3

    .line 235
    .line 236
    move-object/from16 v2, v34

    .line 237
    .line 238
    if-ne v5, v2, :cond_4

    .line 239
    .line 240
    goto :goto_1

    .line 241
    :cond_3
    move-object/from16 v2, v34

    .line 242
    .line 243
    :goto_1
    new-instance v5, Lc40/g;

    .line 244
    .line 245
    const/16 v7, 0xb

    .line 246
    .line 247
    invoke-direct {v5, v4, v7}, Lc40/g;-><init>(Lz4/f;I)V

    .line 248
    .line 249
    .line 250
    invoke-virtual {v10, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 251
    .line 252
    .line 253
    :cond_4
    check-cast v5, Lay0/k;

    .line 254
    .line 255
    invoke-static {v1, v3, v5}, Lz4/k;->b(Lx2/s;Lz4/f;Lay0/k;)Lx2/s;

    .line 256
    .line 257
    .line 258
    move-result-object v11

    .line 259
    sget-object v1, Lj91/a;->a:Ll2/u2;

    .line 260
    .line 261
    invoke-virtual {v10, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 262
    .line 263
    .line 264
    move-result-object v3

    .line 265
    check-cast v3, Lj91/c;

    .line 266
    .line 267
    iget v13, v3, Lj91/c;->d:F

    .line 268
    .line 269
    const/4 v15, 0x0

    .line 270
    const/16 v16, 0xd

    .line 271
    .line 272
    const/4 v12, 0x0

    .line 273
    const/4 v14, 0x0

    .line 274
    invoke-static/range {v11 .. v16}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 275
    .line 276
    .line 277
    move-result-object v7

    .line 278
    new-instance v3, Lr4/k;

    .line 279
    .line 280
    const/4 v4, 0x5

    .line 281
    invoke-direct {v3, v4}, Lr4/k;-><init>(I)V

    .line 282
    .line 283
    .line 284
    const/16 v25, 0x0

    .line 285
    .line 286
    const v26, 0xfbf8

    .line 287
    .line 288
    .line 289
    move-object/from16 v4, p0

    .line 290
    .line 291
    iget-object v5, v4, Lvu0/e;->j:Ljava/lang/String;

    .line 292
    .line 293
    const-wide/16 v8, 0x0

    .line 294
    .line 295
    move-object/from16 v23, v10

    .line 296
    .line 297
    const-wide/16 v10, 0x0

    .line 298
    .line 299
    const/4 v12, 0x0

    .line 300
    const-wide/16 v13, 0x0

    .line 301
    .line 302
    const/4 v15, 0x0

    .line 303
    const-wide/16 v17, 0x0

    .line 304
    .line 305
    const/16 v19, 0x0

    .line 306
    .line 307
    const/16 v20, 0x0

    .line 308
    .line 309
    const/16 v21, 0x0

    .line 310
    .line 311
    const/16 v22, 0x0

    .line 312
    .line 313
    const/16 v24, 0x0

    .line 314
    .line 315
    move-object/from16 v16, v3

    .line 316
    .line 317
    invoke-static/range {v5 .. v26}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 318
    .line 319
    .line 320
    move-object/from16 v10, v23

    .line 321
    .line 322
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 323
    .line 324
    .line 325
    move-result-object v3

    .line 326
    if-ne v3, v2, :cond_5

    .line 327
    .line 328
    sget-object v3, Lvu0/f;->f:Lvu0/f;

    .line 329
    .line 330
    invoke-virtual {v10, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 331
    .line 332
    .line 333
    :cond_5
    check-cast v3, Lay0/k;

    .line 334
    .line 335
    move-object/from16 v2, p2

    .line 336
    .line 337
    invoke-static {v0, v2, v3}, Lz4/k;->b(Lx2/s;Lz4/f;Lay0/k;)Lx2/s;

    .line 338
    .line 339
    .line 340
    move-result-object v2

    .line 341
    sget-object v3, Lk1/j;->c:Lk1/e;

    .line 342
    .line 343
    sget-object v5, Lx2/c;->p:Lx2/h;

    .line 344
    .line 345
    const/4 v6, 0x0

    .line 346
    invoke-static {v3, v5, v10, v6}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 347
    .line 348
    .line 349
    move-result-object v3

    .line 350
    iget-wide v7, v10, Ll2/t;->T:J

    .line 351
    .line 352
    invoke-static {v7, v8}, Ljava/lang/Long;->hashCode(J)I

    .line 353
    .line 354
    .line 355
    move-result v5

    .line 356
    invoke-virtual {v10}, Ll2/t;->m()Ll2/p1;

    .line 357
    .line 358
    .line 359
    move-result-object v7

    .line 360
    invoke-static {v10, v2}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 361
    .line 362
    .line 363
    move-result-object v2

    .line 364
    sget-object v8, Lv3/k;->m1:Lv3/j;

    .line 365
    .line 366
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 367
    .line 368
    .line 369
    sget-object v8, Lv3/j;->b:Lv3/i;

    .line 370
    .line 371
    invoke-virtual {v10}, Ll2/t;->c0()V

    .line 372
    .line 373
    .line 374
    iget-boolean v9, v10, Ll2/t;->S:Z

    .line 375
    .line 376
    if-eqz v9, :cond_6

    .line 377
    .line 378
    invoke-virtual {v10, v8}, Ll2/t;->l(Lay0/a;)V

    .line 379
    .line 380
    .line 381
    goto :goto_2

    .line 382
    :cond_6
    invoke-virtual {v10}, Ll2/t;->m0()V

    .line 383
    .line 384
    .line 385
    :goto_2
    sget-object v8, Lv3/j;->g:Lv3/h;

    .line 386
    .line 387
    invoke-static {v8, v3, v10}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 388
    .line 389
    .line 390
    sget-object v3, Lv3/j;->f:Lv3/h;

    .line 391
    .line 392
    invoke-static {v3, v7, v10}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 393
    .line 394
    .line 395
    sget-object v3, Lv3/j;->j:Lv3/h;

    .line 396
    .line 397
    iget-boolean v7, v10, Ll2/t;->S:Z

    .line 398
    .line 399
    if-nez v7, :cond_7

    .line 400
    .line 401
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 402
    .line 403
    .line 404
    move-result-object v7

    .line 405
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 406
    .line 407
    .line 408
    move-result-object v8

    .line 409
    invoke-static {v7, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 410
    .line 411
    .line 412
    move-result v7

    .line 413
    if-nez v7, :cond_8

    .line 414
    .line 415
    :cond_7
    invoke-static {v5, v10, v5, v3}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 416
    .line 417
    .line 418
    :cond_8
    sget-object v3, Lv3/j;->d:Lv3/h;

    .line 419
    .line 420
    invoke-static {v3, v2, v10}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 421
    .line 422
    .line 423
    iget-boolean v2, v4, Lvu0/e;->k:Z

    .line 424
    .line 425
    const v3, 0x4d2396f1    # 1.71536144E8f

    .line 426
    .line 427
    .line 428
    if-eqz v2, :cond_a

    .line 429
    .line 430
    const v2, 0x4eaeaebd

    .line 431
    .line 432
    .line 433
    invoke-virtual {v10, v2}, Ll2/t;->Y(I)V

    .line 434
    .line 435
    .line 436
    iget-object v9, v4, Lvu0/e;->l:Ljava/lang/String;

    .line 437
    .line 438
    if-eqz v9, :cond_9

    .line 439
    .line 440
    invoke-virtual {v10, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 441
    .line 442
    .line 443
    move-result-object v2

    .line 444
    check-cast v2, Lj91/c;

    .line 445
    .line 446
    iget v13, v2, Lj91/c;->f:F

    .line 447
    .line 448
    const/4 v15, 0x0

    .line 449
    const/16 v16, 0xd

    .line 450
    .line 451
    const/4 v12, 0x0

    .line 452
    const/4 v14, 0x0

    .line 453
    move-object v11, v0

    .line 454
    invoke-static/range {v11 .. v16}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 455
    .line 456
    .line 457
    move-result-object v0

    .line 458
    move-object/from16 v18, v11

    .line 459
    .line 460
    const/4 v5, 0x0

    .line 461
    move v2, v6

    .line 462
    const/16 v6, 0x38

    .line 463
    .line 464
    iget-object v7, v4, Lvu0/e;->m:Lay0/a;

    .line 465
    .line 466
    const/4 v8, 0x0

    .line 467
    const/4 v12, 0x0

    .line 468
    const/4 v13, 0x0

    .line 469
    move-object v11, v0

    .line 470
    invoke-static/range {v5 .. v13}, Li91/j0;->X(IILay0/a;Ljava/lang/Integer;Ljava/lang/String;Ll2/o;Lx2/s;ZZ)V

    .line 471
    .line 472
    .line 473
    :goto_3
    invoke-virtual {v10, v2}, Ll2/t;->q(Z)V

    .line 474
    .line 475
    .line 476
    goto :goto_4

    .line 477
    :cond_9
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 478
    .line 479
    const-string v1, "Required value was null."

    .line 480
    .line 481
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 482
    .line 483
    .line 484
    throw v0

    .line 485
    :cond_a
    move-object/from16 v18, v0

    .line 486
    .line 487
    move v2, v6

    .line 488
    invoke-virtual {v10, v3}, Ll2/t;->Y(I)V

    .line 489
    .line 490
    .line 491
    goto :goto_3

    .line 492
    :goto_4
    iget-boolean v0, v4, Lvu0/e;->n:Z

    .line 493
    .line 494
    if-eqz v0, :cond_b

    .line 495
    .line 496
    const v0, 0x4eb37ccf    # 1.50565056E9f

    .line 497
    .line 498
    .line 499
    invoke-virtual {v10, v0}, Ll2/t;->Y(I)V

    .line 500
    .line 501
    .line 502
    const v0, 0x7f12035e

    .line 503
    .line 504
    .line 505
    invoke-static {v10, v0}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 506
    .line 507
    .line 508
    move-result-object v9

    .line 509
    invoke-virtual {v10, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 510
    .line 511
    .line 512
    move-result-object v3

    .line 513
    check-cast v3, Lj91/c;

    .line 514
    .line 515
    iget v13, v3, Lj91/c;->c:F

    .line 516
    .line 517
    const/4 v15, 0x0

    .line 518
    const/16 v16, 0xd

    .line 519
    .line 520
    const/4 v12, 0x0

    .line 521
    const/4 v14, 0x0

    .line 522
    move-object/from16 v11, v18

    .line 523
    .line 524
    invoke-static/range {v11 .. v16}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 525
    .line 526
    .line 527
    move-result-object v3

    .line 528
    move-object v14, v11

    .line 529
    invoke-static {v3, v0}, Lxf0/i0;->H(Lx2/s;I)Lx2/s;

    .line 530
    .line 531
    .line 532
    move-result-object v11

    .line 533
    const/4 v5, 0x0

    .line 534
    const/16 v6, 0x38

    .line 535
    .line 536
    iget-object v7, v4, Lvu0/e;->o:Lay0/a;

    .line 537
    .line 538
    const/4 v8, 0x0

    .line 539
    const/4 v12, 0x0

    .line 540
    const/4 v13, 0x0

    .line 541
    invoke-static/range {v5 .. v13}, Li91/j0;->u0(IILay0/a;Ljava/lang/Integer;Ljava/lang/String;Ll2/o;Lx2/s;ZZ)V

    .line 542
    .line 543
    .line 544
    :goto_5
    invoke-virtual {v10, v2}, Ll2/t;->q(Z)V

    .line 545
    .line 546
    .line 547
    goto :goto_6

    .line 548
    :cond_b
    move-object/from16 v14, v18

    .line 549
    .line 550
    invoke-virtual {v10, v3}, Ll2/t;->Y(I)V

    .line 551
    .line 552
    .line 553
    goto :goto_5

    .line 554
    :goto_6
    invoke-virtual {v10, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 555
    .line 556
    .line 557
    move-result-object v0

    .line 558
    check-cast v0, Lj91/c;

    .line 559
    .line 560
    iget v0, v0, Lj91/c;->f:F

    .line 561
    .line 562
    invoke-static {v14, v0}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 563
    .line 564
    .line 565
    move-result-object v0

    .line 566
    invoke-static {v10, v0}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 567
    .line 568
    .line 569
    const/4 v0, 0x1

    .line 570
    invoke-virtual {v10, v0}, Ll2/t;->q(Z)V

    .line 571
    .line 572
    .line 573
    invoke-virtual {v10, v2}, Ll2/t;->q(Z)V

    .line 574
    .line 575
    .line 576
    move-object/from16 v0, v28

    .line 577
    .line 578
    iget v0, v0, Lz4/k;->b:I

    .line 579
    .line 580
    move/from16 v1, v27

    .line 581
    .line 582
    if-eq v0, v1, :cond_c

    .line 583
    .line 584
    iget-object v0, v4, Lvu0/e;->h:Lay0/a;

    .line 585
    .line 586
    invoke-static {v0, v10}, Ll2/l0;->g(Lay0/a;Ll2/o;)V

    .line 587
    .line 588
    .line 589
    :cond_c
    return-object p1
.end method
