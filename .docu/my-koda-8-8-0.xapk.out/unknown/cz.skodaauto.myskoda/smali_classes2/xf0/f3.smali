.class public final Lxf0/f3;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic f:Ll2/b1;

.field public final synthetic g:Lz4/k;

.field public final synthetic h:Lay0/a;

.field public final synthetic i:Lvf0/j;

.field public final synthetic j:J

.field public final synthetic k:J

.field public final synthetic l:J

.field public final synthetic m:J

.field public final synthetic n:J

.field public final synthetic o:J


# direct methods
.method public constructor <init>(Ll2/b1;Lz4/k;Lay0/a;Lvf0/j;JJJJJJ)V
    .locals 0

    .line 1
    iput-object p1, p0, Lxf0/f3;->f:Ll2/b1;

    .line 2
    .line 3
    iput-object p2, p0, Lxf0/f3;->g:Lz4/k;

    .line 4
    .line 5
    iput-object p3, p0, Lxf0/f3;->h:Lay0/a;

    .line 6
    .line 7
    iput-object p4, p0, Lxf0/f3;->i:Lvf0/j;

    .line 8
    .line 9
    iput-wide p5, p0, Lxf0/f3;->j:J

    .line 10
    .line 11
    iput-wide p7, p0, Lxf0/f3;->k:J

    .line 12
    .line 13
    iput-wide p9, p0, Lxf0/f3;->l:J

    .line 14
    .line 15
    iput-wide p11, p0, Lxf0/f3;->m:J

    .line 16
    .line 17
    iput-wide p13, p0, Lxf0/f3;->n:J

    .line 18
    .line 19
    move-wide p1, p15

    .line 20
    iput-wide p1, p0, Lxf0/f3;->o:J

    .line 21
    .line 22
    const/4 p1, 0x2

    .line 23
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 24
    .line 25
    .line 26
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 43

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
    iget-object v4, v0, Lxf0/f3;->i:Lvf0/j;

    .line 16
    .line 17
    iget-boolean v15, v4, Lvf0/j;->h:Z

    .line 18
    .line 19
    and-int/lit8 v2, v2, 0x3

    .line 20
    .line 21
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 22
    .line 23
    const/4 v5, 0x2

    .line 24
    if-ne v2, v5, :cond_1

    .line 25
    .line 26
    move-object v2, v1

    .line 27
    check-cast v2, Ll2/t;

    .line 28
    .line 29
    invoke-virtual {v2}, Ll2/t;->A()Z

    .line 30
    .line 31
    .line 32
    move-result v6

    .line 33
    if-nez v6, :cond_0

    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_0
    invoke-virtual {v2}, Ll2/t;->R()V

    .line 37
    .line 38
    .line 39
    return-object v3

    .line 40
    :cond_1
    :goto_0
    iget-object v2, v0, Lxf0/f3;->f:Ll2/b1;

    .line 41
    .line 42
    invoke-interface {v2, v3}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 43
    .line 44
    .line 45
    iget-object v2, v0, Lxf0/f3;->g:Lz4/k;

    .line 46
    .line 47
    iget v6, v2, Lz4/k;->b:I

    .line 48
    .line 49
    invoke-virtual {v2}, Lz4/k;->e()V

    .line 50
    .line 51
    .line 52
    check-cast v1, Ll2/t;

    .line 53
    .line 54
    const v7, -0x55849611

    .line 55
    .line 56
    .line 57
    invoke-virtual {v1, v7}, Ll2/t;->Y(I)V

    .line 58
    .line 59
    .line 60
    invoke-virtual {v2}, Lz4/k;->d()Lt1/j0;

    .line 61
    .line 62
    .line 63
    move-result-object v7

    .line 64
    iget-object v7, v7, Lt1/j0;->e:Ljava/lang/Object;

    .line 65
    .line 66
    check-cast v7, Lz4/k;

    .line 67
    .line 68
    invoke-virtual {v7}, Lz4/k;->c()Lz4/f;

    .line 69
    .line 70
    .line 71
    move-result-object v8

    .line 72
    invoke-virtual {v7}, Lz4/k;->c()Lz4/f;

    .line 73
    .line 74
    .line 75
    move-result-object v9

    .line 76
    invoke-virtual {v7}, Lz4/k;->c()Lz4/f;

    .line 77
    .line 78
    .line 79
    move-result-object v10

    .line 80
    invoke-virtual {v7}, Lz4/k;->c()Lz4/f;

    .line 81
    .line 82
    .line 83
    move-result-object v38

    .line 84
    sget-object v7, Landroidx/compose/foundation/layout/d;->c:Landroidx/compose/foundation/layout/FillElement;

    .line 85
    .line 86
    sget v11, Lxf0/e3;->c:F

    .line 87
    .line 88
    int-to-float v5, v5

    .line 89
    div-float/2addr v11, v5

    .line 90
    invoke-static {v7, v11}, Landroidx/compose/foundation/layout/a;->m(Lx2/s;F)Lx2/s;

    .line 91
    .line 92
    .line 93
    move-result-object v5

    .line 94
    invoke-virtual {v1, v4}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 95
    .line 96
    .line 97
    move-result v7

    .line 98
    iget-wide v11, v0, Lxf0/f3;->j:J

    .line 99
    .line 100
    invoke-virtual {v1, v11, v12}, Ll2/t;->f(J)Z

    .line 101
    .line 102
    .line 103
    move-result v11

    .line 104
    or-int/2addr v7, v11

    .line 105
    iget-wide v11, v0, Lxf0/f3;->k:J

    .line 106
    .line 107
    invoke-virtual {v1, v11, v12}, Ll2/t;->f(J)Z

    .line 108
    .line 109
    .line 110
    move-result v11

    .line 111
    or-int/2addr v7, v11

    .line 112
    iget-wide v11, v0, Lxf0/f3;->l:J

    .line 113
    .line 114
    invoke-virtual {v1, v11, v12}, Ll2/t;->f(J)Z

    .line 115
    .line 116
    .line 117
    move-result v11

    .line 118
    or-int/2addr v7, v11

    .line 119
    iget-wide v11, v0, Lxf0/f3;->m:J

    .line 120
    .line 121
    invoke-virtual {v1, v11, v12}, Ll2/t;->f(J)Z

    .line 122
    .line 123
    .line 124
    move-result v11

    .line 125
    or-int/2addr v7, v11

    .line 126
    iget-wide v11, v0, Lxf0/f3;->n:J

    .line 127
    .line 128
    invoke-virtual {v1, v11, v12}, Ll2/t;->f(J)Z

    .line 129
    .line 130
    .line 131
    move-result v11

    .line 132
    or-int/2addr v7, v11

    .line 133
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 134
    .line 135
    .line 136
    move-result-object v11

    .line 137
    sget-object v12, Ll2/n;->a:Ll2/x0;

    .line 138
    .line 139
    if-nez v7, :cond_2

    .line 140
    .line 141
    if-ne v11, v12, :cond_3

    .line 142
    .line 143
    :cond_2
    move-object v7, v3

    .line 144
    goto :goto_1

    .line 145
    :cond_3
    move-object/from16 p1, v2

    .line 146
    .line 147
    move-object/from16 v42, v3

    .line 148
    .line 149
    move/from16 v39, v6

    .line 150
    .line 151
    move-object/from16 v41, v8

    .line 152
    .line 153
    move-object v2, v9

    .line 154
    move-object/from16 v40, v10

    .line 155
    .line 156
    move-object v0, v12

    .line 157
    move/from16 p2, v15

    .line 158
    .line 159
    move-object v15, v5

    .line 160
    goto :goto_2

    .line 161
    :goto_1
    new-instance v3, Lxf0/g3;

    .line 162
    .line 163
    move-object v13, v12

    .line 164
    iget-wide v11, v0, Lxf0/f3;->m:J

    .line 165
    .line 166
    move-object/from16 v16, v13

    .line 167
    .line 168
    iget-wide v13, v0, Lxf0/f3;->n:J

    .line 169
    .line 170
    move-object/from16 v18, v5

    .line 171
    .line 172
    move/from16 v17, v6

    .line 173
    .line 174
    iget-wide v5, v0, Lxf0/f3;->j:J

    .line 175
    .line 176
    move-object/from16 v20, v7

    .line 177
    .line 178
    move-object/from16 v19, v8

    .line 179
    .line 180
    iget-wide v7, v0, Lxf0/f3;->k:J

    .line 181
    .line 182
    move-object/from16 v21, v9

    .line 183
    .line 184
    move-object/from16 v22, v10

    .line 185
    .line 186
    iget-wide v9, v0, Lxf0/f3;->l:J

    .line 187
    .line 188
    move-object/from16 p1, v2

    .line 189
    .line 190
    move/from16 p2, v15

    .line 191
    .line 192
    move-object/from16 v0, v16

    .line 193
    .line 194
    move/from16 v39, v17

    .line 195
    .line 196
    move-object/from16 v15, v18

    .line 197
    .line 198
    move-object/from16 v41, v19

    .line 199
    .line 200
    move-object/from16 v42, v20

    .line 201
    .line 202
    move-object/from16 v2, v21

    .line 203
    .line 204
    move-object/from16 v40, v22

    .line 205
    .line 206
    invoke-direct/range {v3 .. v14}, Lxf0/g3;-><init>(Lvf0/j;JJJJJ)V

    .line 207
    .line 208
    .line 209
    invoke-virtual {v1, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 210
    .line 211
    .line 212
    move-object v11, v3

    .line 213
    :goto_2
    check-cast v11, Lay0/k;

    .line 214
    .line 215
    const/4 v3, 0x6

    .line 216
    invoke-static {v15, v11, v1, v3}, Lkp/i;->a(Lx2/s;Lay0/k;Ll2/o;I)V

    .line 217
    .line 218
    .line 219
    const v3, -0x55b776ac

    .line 220
    .line 221
    .line 222
    const/4 v15, 0x0

    .line 223
    sget-object v5, Lx2/p;->b:Lx2/p;

    .line 224
    .line 225
    if-nez p2, :cond_7

    .line 226
    .line 227
    const v6, -0x5573343d

    .line 228
    .line 229
    .line 230
    invoke-virtual {v1, v6}, Ll2/t;->Y(I)V

    .line 231
    .line 232
    .line 233
    iget-object v6, v4, Lvf0/j;->b:Ljava/lang/String;

    .line 234
    .line 235
    sget-object v7, Lj91/j;->a:Ll2/u2;

    .line 236
    .line 237
    invoke-virtual {v1, v7}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 238
    .line 239
    .line 240
    move-result-object v8

    .line 241
    check-cast v8, Lj91/f;

    .line 242
    .line 243
    invoke-virtual {v8}, Lj91/f;->h()Lg4/p0;

    .line 244
    .line 245
    .line 246
    move-result-object v17

    .line 247
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 248
    .line 249
    .line 250
    move-result-object v8

    .line 251
    if-ne v8, v0, :cond_4

    .line 252
    .line 253
    sget-object v8, Lxf0/e1;->k:Lxf0/e1;

    .line 254
    .line 255
    invoke-virtual {v1, v8}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 256
    .line 257
    .line 258
    :cond_4
    check-cast v8, Lay0/k;

    .line 259
    .line 260
    invoke-static {v5, v2, v8}, Lz4/k;->b(Lx2/s;Lz4/f;Lay0/k;)Lx2/s;

    .line 261
    .line 262
    .line 263
    move-result-object v18

    .line 264
    const/16 v36, 0x0

    .line 265
    .line 266
    const v37, 0xfff0

    .line 267
    .line 268
    .line 269
    move-object/from16 v11, p0

    .line 270
    .line 271
    iget-wide v8, v11, Lxf0/f3;->o:J

    .line 272
    .line 273
    const-wide/16 v21, 0x0

    .line 274
    .line 275
    const/16 v23, 0x0

    .line 276
    .line 277
    const-wide/16 v24, 0x0

    .line 278
    .line 279
    const/16 v26, 0x0

    .line 280
    .line 281
    const/16 v27, 0x0

    .line 282
    .line 283
    const-wide/16 v28, 0x0

    .line 284
    .line 285
    const/16 v30, 0x0

    .line 286
    .line 287
    const/16 v31, 0x0

    .line 288
    .line 289
    const/16 v32, 0x0

    .line 290
    .line 291
    const/16 v33, 0x0

    .line 292
    .line 293
    const/16 v35, 0x0

    .line 294
    .line 295
    move-object/from16 v34, v1

    .line 296
    .line 297
    move-object/from16 v16, v6

    .line 298
    .line 299
    move-wide/from16 v19, v8

    .line 300
    .line 301
    invoke-static/range {v16 .. v37}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 302
    .line 303
    .line 304
    move-object/from16 v12, v34

    .line 305
    .line 306
    iget-object v1, v4, Lvf0/j;->a:Ljava/lang/String;

    .line 307
    .line 308
    invoke-virtual {v12, v7}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 309
    .line 310
    .line 311
    move-result-object v6

    .line 312
    check-cast v6, Lj91/f;

    .line 313
    .line 314
    invoke-virtual {v6}, Lj91/f;->l()Lg4/p0;

    .line 315
    .line 316
    .line 317
    move-result-object v17

    .line 318
    sget-object v6, Lj91/a;->a:Ll2/u2;

    .line 319
    .line 320
    invoke-virtual {v12, v6}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 321
    .line 322
    .line 323
    move-result-object v6

    .line 324
    check-cast v6, Lj91/c;

    .line 325
    .line 326
    iget v9, v6, Lj91/c;->b:F

    .line 327
    .line 328
    const/4 v10, 0x7

    .line 329
    const/4 v6, 0x0

    .line 330
    const/4 v7, 0x0

    .line 331
    const/4 v8, 0x0

    .line 332
    invoke-static/range {v5 .. v10}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 333
    .line 334
    .line 335
    move-result-object v6

    .line 336
    invoke-virtual {v12, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 337
    .line 338
    .line 339
    move-result v7

    .line 340
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 341
    .line 342
    .line 343
    move-result-object v8

    .line 344
    if-nez v7, :cond_5

    .line 345
    .line 346
    if-ne v8, v0, :cond_6

    .line 347
    .line 348
    :cond_5
    new-instance v8, Lc40/g;

    .line 349
    .line 350
    const/16 v7, 0x14

    .line 351
    .line 352
    invoke-direct {v8, v2, v7}, Lc40/g;-><init>(Lz4/f;I)V

    .line 353
    .line 354
    .line 355
    invoke-virtual {v12, v8}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 356
    .line 357
    .line 358
    :cond_6
    check-cast v8, Lay0/k;

    .line 359
    .line 360
    move-object/from16 v7, v41

    .line 361
    .line 362
    invoke-static {v6, v7, v8}, Lz4/k;->b(Lx2/s;Lz4/f;Lay0/k;)Lx2/s;

    .line 363
    .line 364
    .line 365
    move-result-object v18

    .line 366
    const/16 v36, 0x0

    .line 367
    .line 368
    const v37, 0xfff0

    .line 369
    .line 370
    .line 371
    iget-wide v6, v11, Lxf0/f3;->o:J

    .line 372
    .line 373
    const-wide/16 v21, 0x0

    .line 374
    .line 375
    const/16 v23, 0x0

    .line 376
    .line 377
    const-wide/16 v24, 0x0

    .line 378
    .line 379
    const/16 v26, 0x0

    .line 380
    .line 381
    const/16 v27, 0x0

    .line 382
    .line 383
    const-wide/16 v28, 0x0

    .line 384
    .line 385
    const/16 v30, 0x0

    .line 386
    .line 387
    const/16 v31, 0x0

    .line 388
    .line 389
    const/16 v32, 0x0

    .line 390
    .line 391
    const/16 v33, 0x0

    .line 392
    .line 393
    const/16 v35, 0x0

    .line 394
    .line 395
    move-object/from16 v16, v1

    .line 396
    .line 397
    move-wide/from16 v19, v6

    .line 398
    .line 399
    move-object/from16 v34, v12

    .line 400
    .line 401
    invoke-static/range {v16 .. v37}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 402
    .line 403
    .line 404
    :goto_3
    invoke-virtual {v12, v15}, Ll2/t;->q(Z)V

    .line 405
    .line 406
    .line 407
    goto :goto_4

    .line 408
    :cond_7
    move-object/from16 v11, p0

    .line 409
    .line 410
    move-object v12, v1

    .line 411
    invoke-virtual {v12, v3}, Ll2/t;->Y(I)V

    .line 412
    .line 413
    .line 414
    goto :goto_3

    .line 415
    :goto_4
    iget-boolean v1, v4, Lvf0/j;->g:Z

    .line 416
    .line 417
    if-eqz v1, :cond_a

    .line 418
    .line 419
    if-nez p2, :cond_a

    .line 420
    .line 421
    const v1, -0x5564c7d9

    .line 422
    .line 423
    .line 424
    invoke-virtual {v12, v1}, Ll2/t;->Y(I)V

    .line 425
    .line 426
    .line 427
    iget-object v1, v4, Lvf0/j;->c:Lvf0/m;

    .line 428
    .line 429
    invoke-static {v1}, Lxf0/y1;->C(Lvf0/m;)I

    .line 430
    .line 431
    .line 432
    move-result v1

    .line 433
    invoke-static {v1, v15, v12}, Ljp/fa;->b(IILl2/o;)Li3/c;

    .line 434
    .line 435
    .line 436
    move-result-object v1

    .line 437
    sget-object v3, Lj91/a;->a:Ll2/u2;

    .line 438
    .line 439
    invoke-virtual {v12, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 440
    .line 441
    .line 442
    move-result-object v6

    .line 443
    check-cast v6, Lj91/c;

    .line 444
    .line 445
    iget v7, v6, Lj91/c;->d:F

    .line 446
    .line 447
    const/4 v9, 0x0

    .line 448
    const/16 v10, 0xd

    .line 449
    .line 450
    const/4 v6, 0x0

    .line 451
    const/4 v8, 0x0

    .line 452
    invoke-static/range {v5 .. v10}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 453
    .line 454
    .line 455
    move-result-object v5

    .line 456
    invoke-virtual {v12, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 457
    .line 458
    .line 459
    move-result-object v3

    .line 460
    check-cast v3, Lj91/c;

    .line 461
    .line 462
    iget v3, v3, Lj91/c;->f:F

    .line 463
    .line 464
    invoke-static {v5, v3}, Landroidx/compose/foundation/layout/d;->n(Lx2/s;F)Lx2/s;

    .line 465
    .line 466
    .line 467
    move-result-object v3

    .line 468
    invoke-virtual {v12, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 469
    .line 470
    .line 471
    move-result v5

    .line 472
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 473
    .line 474
    .line 475
    move-result-object v6

    .line 476
    if-nez v5, :cond_8

    .line 477
    .line 478
    if-ne v6, v0, :cond_9

    .line 479
    .line 480
    :cond_8
    new-instance v6, Lc40/g;

    .line 481
    .line 482
    const/16 v0, 0x15

    .line 483
    .line 484
    invoke-direct {v6, v2, v0}, Lc40/g;-><init>(Lz4/f;I)V

    .line 485
    .line 486
    .line 487
    invoke-virtual {v12, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 488
    .line 489
    .line 490
    :cond_9
    check-cast v6, Lay0/k;

    .line 491
    .line 492
    move-object/from16 v0, v40

    .line 493
    .line 494
    invoke-static {v3, v0, v6}, Lz4/k;->b(Lx2/s;Lz4/f;Lay0/k;)Lx2/s;

    .line 495
    .line 496
    .line 497
    move-result-object v9

    .line 498
    const/16 v13, 0x30

    .line 499
    .line 500
    const/4 v14, 0x0

    .line 501
    const/4 v8, 0x0

    .line 502
    move-object v0, v11

    .line 503
    iget-wide v10, v0, Lxf0/f3;->n:J

    .line 504
    .line 505
    move-object v7, v1

    .line 506
    invoke-static/range {v7 .. v14}, Lh2/f5;->a(Li3/c;Ljava/lang/String;Lx2/s;JLl2/o;II)V

    .line 507
    .line 508
    .line 509
    iget-wide v5, v0, Lxf0/f3;->o:J

    .line 510
    .line 511
    const/16 v9, 0x8

    .line 512
    .line 513
    move-object/from16 v3, p1

    .line 514
    .line 515
    move-object v8, v12

    .line 516
    move-object/from16 v7, v38

    .line 517
    .line 518
    invoke-static/range {v3 .. v9}, Lxf0/y1;->s(Lz4/k;Lvf0/j;JLz4/f;Ll2/o;I)V

    .line 519
    .line 520
    .line 521
    move-object v1, v3

    .line 522
    :goto_5
    invoke-virtual {v12, v15}, Ll2/t;->q(Z)V

    .line 523
    .line 524
    .line 525
    goto :goto_6

    .line 526
    :cond_a
    move-object/from16 v1, p1

    .line 527
    .line 528
    move-object v0, v11

    .line 529
    invoke-virtual {v12, v3}, Ll2/t;->Y(I)V

    .line 530
    .line 531
    .line 532
    goto :goto_5

    .line 533
    :goto_6
    invoke-virtual {v12, v15}, Ll2/t;->q(Z)V

    .line 534
    .line 535
    .line 536
    iget v1, v1, Lz4/k;->b:I

    .line 537
    .line 538
    move/from16 v2, v39

    .line 539
    .line 540
    if-eq v1, v2, :cond_b

    .line 541
    .line 542
    iget-object v0, v0, Lxf0/f3;->h:Lay0/a;

    .line 543
    .line 544
    invoke-static {v0, v12}, Ll2/l0;->g(Lay0/a;Ll2/o;)V

    .line 545
    .line 546
    .line 547
    :cond_b
    return-object v42
.end method
