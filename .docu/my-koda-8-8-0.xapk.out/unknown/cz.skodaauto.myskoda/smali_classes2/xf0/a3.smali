.class public final Lxf0/a3;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic f:Ll2/b1;

.field public final synthetic g:Lz4/k;

.field public final synthetic h:Lay0/a;

.field public final synthetic i:J

.field public final synthetic j:J

.field public final synthetic k:J

.field public final synthetic l:J

.field public final synthetic m:Lvf0/i;

.field public final synthetic n:J

.field public final synthetic o:J

.field public final synthetic p:J

.field public final synthetic q:F


# direct methods
.method public constructor <init>(Ll2/b1;Lz4/k;Lay0/a;JJJJLvf0/i;JJJF)V
    .locals 0

    .line 1
    iput-object p1, p0, Lxf0/a3;->f:Ll2/b1;

    .line 2
    .line 3
    iput-object p2, p0, Lxf0/a3;->g:Lz4/k;

    .line 4
    .line 5
    iput-object p3, p0, Lxf0/a3;->h:Lay0/a;

    .line 6
    .line 7
    iput-wide p4, p0, Lxf0/a3;->i:J

    .line 8
    .line 9
    iput-wide p6, p0, Lxf0/a3;->j:J

    .line 10
    .line 11
    iput-wide p8, p0, Lxf0/a3;->k:J

    .line 12
    .line 13
    iput-wide p10, p0, Lxf0/a3;->l:J

    .line 14
    .line 15
    iput-object p12, p0, Lxf0/a3;->m:Lvf0/i;

    .line 16
    .line 17
    iput-wide p13, p0, Lxf0/a3;->n:J

    .line 18
    .line 19
    move-wide p1, p15

    .line 20
    iput-wide p1, p0, Lxf0/a3;->o:J

    .line 21
    .line 22
    move-wide/from16 p1, p17

    .line 23
    .line 24
    iput-wide p1, p0, Lxf0/a3;->p:J

    .line 25
    .line 26
    move/from16 p1, p19

    .line 27
    .line 28
    iput p1, p0, Lxf0/a3;->q:F

    .line 29
    .line 30
    const/4 p1, 0x2

    .line 31
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 32
    .line 33
    .line 34
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 46

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
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 18
    .line 19
    const/4 v4, 0x2

    .line 20
    if-ne v2, v4, :cond_1

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
    move-result v5

    .line 29
    if-nez v5, :cond_0

    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_0
    invoke-virtual {v2}, Ll2/t;->R()V

    .line 33
    .line 34
    .line 35
    return-object v3

    .line 36
    :cond_1
    :goto_0
    iget-object v2, v0, Lxf0/a3;->f:Ll2/b1;

    .line 37
    .line 38
    invoke-interface {v2, v3}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    iget-object v2, v0, Lxf0/a3;->g:Lz4/k;

    .line 42
    .line 43
    iget v5, v2, Lz4/k;->b:I

    .line 44
    .line 45
    invoke-virtual {v2}, Lz4/k;->e()V

    .line 46
    .line 47
    .line 48
    move-object v11, v1

    .line 49
    check-cast v11, Ll2/t;

    .line 50
    .line 51
    const v1, -0x2e4ddd78

    .line 52
    .line 53
    .line 54
    invoke-virtual {v11, v1}, Ll2/t;->Y(I)V

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
    move-result-object v6

    .line 69
    invoke-virtual {v1}, Lz4/k;->c()Lz4/f;

    .line 70
    .line 71
    .line 72
    move-result-object v7

    .line 73
    invoke-virtual {v1}, Lz4/k;->c()Lz4/f;

    .line 74
    .line 75
    .line 76
    move-result-object v1

    .line 77
    sget-object v12, Landroidx/compose/foundation/layout/d;->c:Landroidx/compose/foundation/layout/FillElement;

    .line 78
    .line 79
    const/16 v17, 0x0

    .line 80
    .line 81
    const v18, 0x7fffb

    .line 82
    .line 83
    .line 84
    const v13, 0x3f7d70a4    # 0.99f

    .line 85
    .line 86
    .line 87
    const/4 v14, 0x0

    .line 88
    const/4 v15, 0x0

    .line 89
    const/16 v16, 0x0

    .line 90
    .line 91
    invoke-static/range {v12 .. v18}, Landroidx/compose/ui/graphics/a;->c(Lx2/s;FFFFLe3/n0;I)Lx2/s;

    .line 92
    .line 93
    .line 94
    move-result-object v8

    .line 95
    sget v9, Lxf0/i3;->c:F

    .line 96
    .line 97
    int-to-float v10, v4

    .line 98
    div-float/2addr v9, v10

    .line 99
    invoke-static {v8, v9}, Landroidx/compose/foundation/layout/a;->m(Lx2/s;F)Lx2/s;

    .line 100
    .line 101
    .line 102
    move-result-object v8

    .line 103
    iget-wide v9, v0, Lxf0/a3;->i:J

    .line 104
    .line 105
    invoke-virtual {v11, v9, v10}, Ll2/t;->f(J)Z

    .line 106
    .line 107
    .line 108
    move-result v9

    .line 109
    iget-wide v12, v0, Lxf0/a3;->j:J

    .line 110
    .line 111
    invoke-virtual {v11, v12, v13}, Ll2/t;->f(J)Z

    .line 112
    .line 113
    .line 114
    move-result v10

    .line 115
    or-int/2addr v9, v10

    .line 116
    iget-wide v12, v0, Lxf0/a3;->k:J

    .line 117
    .line 118
    invoke-virtual {v11, v12, v13}, Ll2/t;->f(J)Z

    .line 119
    .line 120
    .line 121
    move-result v10

    .line 122
    or-int/2addr v9, v10

    .line 123
    iget-wide v12, v0, Lxf0/a3;->l:J

    .line 124
    .line 125
    invoke-virtual {v11, v12, v13}, Ll2/t;->f(J)Z

    .line 126
    .line 127
    .line 128
    move-result v10

    .line 129
    or-int/2addr v9, v10

    .line 130
    iget-object v10, v0, Lxf0/a3;->m:Lvf0/i;

    .line 131
    .line 132
    invoke-virtual {v11, v10}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 133
    .line 134
    .line 135
    move-result v12

    .line 136
    or-int/2addr v9, v12

    .line 137
    iget-wide v12, v0, Lxf0/a3;->n:J

    .line 138
    .line 139
    invoke-virtual {v11, v12, v13}, Ll2/t;->f(J)Z

    .line 140
    .line 141
    .line 142
    move-result v12

    .line 143
    or-int/2addr v9, v12

    .line 144
    iget-wide v12, v0, Lxf0/a3;->o:J

    .line 145
    .line 146
    invoke-virtual {v11, v12, v13}, Ll2/t;->f(J)Z

    .line 147
    .line 148
    .line 149
    move-result v12

    .line 150
    or-int/2addr v9, v12

    .line 151
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 152
    .line 153
    .line 154
    move-result-object v12

    .line 155
    sget-object v13, Ll2/n;->a:Ll2/x0;

    .line 156
    .line 157
    if-nez v9, :cond_3

    .line 158
    .line 159
    if-ne v12, v13, :cond_2

    .line 160
    .line 161
    goto :goto_1

    .line 162
    :cond_2
    move-object/from16 v28, v3

    .line 163
    .line 164
    move/from16 p2, v5

    .line 165
    .line 166
    move-object v4, v10

    .line 167
    move-object v3, v13

    .line 168
    goto :goto_2

    .line 169
    :cond_3
    :goto_1
    new-instance v12, Lxf0/c3;

    .line 170
    .line 171
    iget-wide v14, v0, Lxf0/a3;->n:J

    .line 172
    .line 173
    move/from16 p2, v5

    .line 174
    .line 175
    iget-wide v4, v0, Lxf0/a3;->o:J

    .line 176
    .line 177
    move-object v9, v13

    .line 178
    move-wide/from16 v22, v14

    .line 179
    .line 180
    iget-wide v13, v0, Lxf0/a3;->i:J

    .line 181
    .line 182
    move-object/from16 v28, v3

    .line 183
    .line 184
    move-wide/from16 v24, v4

    .line 185
    .line 186
    iget-wide v3, v0, Lxf0/a3;->j:J

    .line 187
    .line 188
    move-wide v15, v3

    .line 189
    iget-wide v3, v0, Lxf0/a3;->k:J

    .line 190
    .line 191
    move-wide/from16 v17, v3

    .line 192
    .line 193
    iget-wide v3, v0, Lxf0/a3;->l:J

    .line 194
    .line 195
    move-wide/from16 v19, v3

    .line 196
    .line 197
    move-object v3, v9

    .line 198
    move-object/from16 v21, v10

    .line 199
    .line 200
    invoke-direct/range {v12 .. v25}, Lxf0/c3;-><init>(JJJJLvf0/i;JJ)V

    .line 201
    .line 202
    .line 203
    move-object/from16 v4, v21

    .line 204
    .line 205
    invoke-virtual {v11, v12}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 206
    .line 207
    .line 208
    :goto_2
    check-cast v12, Lay0/k;

    .line 209
    .line 210
    const/4 v5, 0x6

    .line 211
    invoke-static {v8, v12, v11, v5}, Lkp/i;->a(Lx2/s;Lay0/k;Ll2/o;I)V

    .line 212
    .line 213
    .line 214
    iget-object v5, v4, Lvf0/i;->d:Lvf0/m;

    .line 215
    .line 216
    iget-object v8, v4, Lvf0/i;->c:Lvf0/m;

    .line 217
    .line 218
    const v9, -0x2e283913

    .line 219
    .line 220
    .line 221
    invoke-virtual {v11, v9}, Ll2/t;->Y(I)V

    .line 222
    .line 223
    .line 224
    const v9, -0x5411cb73

    .line 225
    .line 226
    .line 227
    invoke-virtual {v11, v9}, Ll2/t;->Y(I)V

    .line 228
    .line 229
    .line 230
    const/4 v9, 0x0

    .line 231
    invoke-virtual {v11, v9}, Ll2/t;->q(Z)V

    .line 232
    .line 233
    .line 234
    move-object v10, v6

    .line 235
    iget-object v6, v4, Lvf0/i;->b:Ljava/lang/String;

    .line 236
    .line 237
    sget-object v12, Lj91/j;->a:Ll2/u2;

    .line 238
    .line 239
    invoke-virtual {v11, v12}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 240
    .line 241
    .line 242
    move-result-object v13

    .line 243
    check-cast v13, Lj91/f;

    .line 244
    .line 245
    invoke-virtual {v13}, Lj91/f;->h()Lg4/p0;

    .line 246
    .line 247
    .line 248
    move-result-object v13

    .line 249
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 250
    .line 251
    .line 252
    move-result-object v14

    .line 253
    if-ne v14, v3, :cond_4

    .line 254
    .line 255
    sget-object v14, Lxf0/e1;->j:Lxf0/e1;

    .line 256
    .line 257
    invoke-virtual {v11, v14}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 258
    .line 259
    .line 260
    :cond_4
    check-cast v14, Lay0/k;

    .line 261
    .line 262
    sget-object v15, Lx2/p;->b:Lx2/p;

    .line 263
    .line 264
    invoke-static {v15, v7, v14}, Lz4/k;->b(Lx2/s;Lz4/f;Lay0/k;)Lx2/s;

    .line 265
    .line 266
    .line 267
    move-result-object v14

    .line 268
    const/16 v26, 0x0

    .line 269
    .line 270
    const v27, 0xfff0

    .line 271
    .line 272
    .line 273
    move/from16 v17, v9

    .line 274
    .line 275
    move-object/from16 v16, v10

    .line 276
    .line 277
    iget-wide v9, v0, Lxf0/a3;->p:J

    .line 278
    .line 279
    move-object/from16 v24, v11

    .line 280
    .line 281
    move-object/from16 v18, v12

    .line 282
    .line 283
    const-wide/16 v11, 0x0

    .line 284
    .line 285
    move-object/from16 v19, v7

    .line 286
    .line 287
    move-object v7, v13

    .line 288
    const/4 v13, 0x0

    .line 289
    move-object/from16 v20, v8

    .line 290
    .line 291
    move-object v8, v14

    .line 292
    move-object/from16 v21, v15

    .line 293
    .line 294
    const-wide/16 v14, 0x0

    .line 295
    .line 296
    move-object/from16 v22, v16

    .line 297
    .line 298
    const/16 v16, 0x0

    .line 299
    .line 300
    move/from16 v23, v17

    .line 301
    .line 302
    const/16 v17, 0x0

    .line 303
    .line 304
    move-object/from16 v29, v18

    .line 305
    .line 306
    move-object/from16 v25, v19

    .line 307
    .line 308
    const-wide/16 v18, 0x0

    .line 309
    .line 310
    move-object/from16 v30, v20

    .line 311
    .line 312
    const/16 v20, 0x0

    .line 313
    .line 314
    move-object/from16 v31, v21

    .line 315
    .line 316
    const/16 v21, 0x0

    .line 317
    .line 318
    move-object/from16 v32, v22

    .line 319
    .line 320
    const/16 v22, 0x0

    .line 321
    .line 322
    move/from16 v33, v23

    .line 323
    .line 324
    const/16 v23, 0x0

    .line 325
    .line 326
    move-object/from16 v34, v25

    .line 327
    .line 328
    const/16 v25, 0x0

    .line 329
    .line 330
    move-object/from16 v35, v2

    .line 331
    .line 332
    move-object/from16 v2, v32

    .line 333
    .line 334
    move/from16 v0, v33

    .line 335
    .line 336
    move-object/from16 v32, v31

    .line 337
    .line 338
    move-object/from16 v31, v1

    .line 339
    .line 340
    move-object/from16 v1, v29

    .line 341
    .line 342
    move-object/from16 v29, v5

    .line 343
    .line 344
    move-object/from16 v5, v34

    .line 345
    .line 346
    invoke-static/range {v6 .. v27}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 347
    .line 348
    .line 349
    move-object/from16 v11, v24

    .line 350
    .line 351
    const v6, -0x54118e72

    .line 352
    .line 353
    .line 354
    invoke-virtual {v11, v6}, Ll2/t;->Y(I)V

    .line 355
    .line 356
    .line 357
    invoke-virtual {v11, v0}, Ll2/t;->q(Z)V

    .line 358
    .line 359
    .line 360
    iget-object v6, v4, Lvf0/i;->a:Ljava/lang/String;

    .line 361
    .line 362
    invoke-virtual {v11, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 363
    .line 364
    .line 365
    move-result-object v4

    .line 366
    check-cast v4, Lj91/f;

    .line 367
    .line 368
    invoke-virtual {v4}, Lj91/f;->l()Lg4/p0;

    .line 369
    .line 370
    .line 371
    move-result-object v7

    .line 372
    sget-object v4, Lj91/a;->a:Ll2/u2;

    .line 373
    .line 374
    invoke-virtual {v11, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 375
    .line 376
    .line 377
    move-result-object v8

    .line 378
    check-cast v8, Lj91/c;

    .line 379
    .line 380
    iget v8, v8, Lj91/c;->b:F

    .line 381
    .line 382
    const/16 v20, 0x7

    .line 383
    .line 384
    const/16 v16, 0x0

    .line 385
    .line 386
    const/16 v17, 0x0

    .line 387
    .line 388
    const/16 v18, 0x0

    .line 389
    .line 390
    move/from16 v19, v8

    .line 391
    .line 392
    move-object/from16 v15, v32

    .line 393
    .line 394
    invoke-static/range {v15 .. v20}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 395
    .line 396
    .line 397
    move-result-object v8

    .line 398
    invoke-virtual {v11, v5}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 399
    .line 400
    .line 401
    move-result v9

    .line 402
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 403
    .line 404
    .line 405
    move-result-object v10

    .line 406
    if-nez v9, :cond_5

    .line 407
    .line 408
    if-ne v10, v3, :cond_6

    .line 409
    .line 410
    :cond_5
    new-instance v10, Lc40/g;

    .line 411
    .line 412
    const/16 v9, 0x13

    .line 413
    .line 414
    invoke-direct {v10, v5, v9}, Lc40/g;-><init>(Lz4/f;I)V

    .line 415
    .line 416
    .line 417
    invoke-virtual {v11, v10}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 418
    .line 419
    .line 420
    :cond_6
    check-cast v10, Lay0/k;

    .line 421
    .line 422
    invoke-static {v8, v2, v10}, Lz4/k;->b(Lx2/s;Lz4/f;Lay0/k;)Lx2/s;

    .line 423
    .line 424
    .line 425
    move-result-object v8

    .line 426
    const/16 v26, 0x0

    .line 427
    .line 428
    const v27, 0xfff0

    .line 429
    .line 430
    .line 431
    move-object/from16 v2, p0

    .line 432
    .line 433
    iget-wide v9, v2, Lxf0/a3;->p:J

    .line 434
    .line 435
    move-object/from16 v24, v11

    .line 436
    .line 437
    const-wide/16 v11, 0x0

    .line 438
    .line 439
    const/4 v13, 0x0

    .line 440
    move-object/from16 v32, v15

    .line 441
    .line 442
    const-wide/16 v14, 0x0

    .line 443
    .line 444
    const/16 v16, 0x0

    .line 445
    .line 446
    const/16 v17, 0x0

    .line 447
    .line 448
    const-wide/16 v18, 0x0

    .line 449
    .line 450
    const/16 v20, 0x0

    .line 451
    .line 452
    const/16 v21, 0x0

    .line 453
    .line 454
    const/16 v22, 0x0

    .line 455
    .line 456
    const/16 v23, 0x0

    .line 457
    .line 458
    const/16 v25, 0x0

    .line 459
    .line 460
    move-object/from16 v5, v32

    .line 461
    .line 462
    invoke-static/range {v6 .. v27}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 463
    .line 464
    .line 465
    move-object/from16 v11, v24

    .line 466
    .line 467
    invoke-virtual {v11, v0}, Ll2/t;->q(Z)V

    .line 468
    .line 469
    .line 470
    const v6, -0x2e16d510

    .line 471
    .line 472
    .line 473
    invoke-virtual {v11, v6}, Ll2/t;->Y(I)V

    .line 474
    .line 475
    .line 476
    invoke-virtual {v11, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 477
    .line 478
    .line 479
    move-result-object v6

    .line 480
    check-cast v6, Lj91/c;

    .line 481
    .line 482
    iget v6, v6, Lj91/c;->h:F

    .line 483
    .line 484
    const/4 v7, 0x0

    .line 485
    const/4 v8, 0x2

    .line 486
    invoke-static {v5, v6, v7, v8}, Landroidx/compose/foundation/layout/a;->o(Lx2/s;FFI)Lx2/s;

    .line 487
    .line 488
    .line 489
    move-result-object v6

    .line 490
    iget v7, v2, Lxf0/a3;->q:F

    .line 491
    .line 492
    invoke-virtual {v11, v7}, Ll2/t;->d(F)Z

    .line 493
    .line 494
    .line 495
    move-result v8

    .line 496
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 497
    .line 498
    .line 499
    move-result-object v9

    .line 500
    if-nez v8, :cond_7

    .line 501
    .line 502
    if-ne v9, v3, :cond_8

    .line 503
    .line 504
    :cond_7
    new-instance v9, Lo50/n;

    .line 505
    .line 506
    const/4 v3, 0x1

    .line 507
    invoke-direct {v9, v3, v7}, Lo50/n;-><init>(IF)V

    .line 508
    .line 509
    .line 510
    invoke-virtual {v11, v9}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 511
    .line 512
    .line 513
    :cond_8
    check-cast v9, Lay0/k;

    .line 514
    .line 515
    move-object/from16 v3, v31

    .line 516
    .line 517
    invoke-static {v6, v3, v9}, Lz4/k;->b(Lx2/s;Lz4/f;Lay0/k;)Lx2/s;

    .line 518
    .line 519
    .line 520
    move-result-object v3

    .line 521
    sget-object v6, Lk1/j;->a:Lk1/c;

    .line 522
    .line 523
    sget-object v7, Lx2/c;->m:Lx2/i;

    .line 524
    .line 525
    invoke-static {v6, v7, v11, v0}, Lk1/e1;->a(Lk1/g;Lx2/i;Ll2/o;I)Lk1/g1;

    .line 526
    .line 527
    .line 528
    move-result-object v6

    .line 529
    iget-wide v7, v11, Ll2/t;->T:J

    .line 530
    .line 531
    invoke-static {v7, v8}, Ljava/lang/Long;->hashCode(J)I

    .line 532
    .line 533
    .line 534
    move-result v7

    .line 535
    invoke-virtual {v11}, Ll2/t;->m()Ll2/p1;

    .line 536
    .line 537
    .line 538
    move-result-object v8

    .line 539
    invoke-static {v11, v3}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 540
    .line 541
    .line 542
    move-result-object v3

    .line 543
    sget-object v9, Lv3/k;->m1:Lv3/j;

    .line 544
    .line 545
    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 546
    .line 547
    .line 548
    sget-object v14, Lv3/j;->b:Lv3/i;

    .line 549
    .line 550
    invoke-virtual {v11}, Ll2/t;->c0()V

    .line 551
    .line 552
    .line 553
    iget-boolean v9, v11, Ll2/t;->S:Z

    .line 554
    .line 555
    if-eqz v9, :cond_9

    .line 556
    .line 557
    invoke-virtual {v11, v14}, Ll2/t;->l(Lay0/a;)V

    .line 558
    .line 559
    .line 560
    goto :goto_3

    .line 561
    :cond_9
    invoke-virtual {v11}, Ll2/t;->m0()V

    .line 562
    .line 563
    .line 564
    :goto_3
    sget-object v9, Lv3/j;->g:Lv3/h;

    .line 565
    .line 566
    invoke-static {v9, v6, v11}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 567
    .line 568
    .line 569
    sget-object v6, Lv3/j;->f:Lv3/h;

    .line 570
    .line 571
    invoke-static {v6, v8, v11}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 572
    .line 573
    .line 574
    sget-object v8, Lv3/j;->j:Lv3/h;

    .line 575
    .line 576
    iget-boolean v10, v11, Ll2/t;->S:Z

    .line 577
    .line 578
    if-nez v10, :cond_a

    .line 579
    .line 580
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 581
    .line 582
    .line 583
    move-result-object v10

    .line 584
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 585
    .line 586
    .line 587
    move-result-object v12

    .line 588
    invoke-static {v10, v12}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 589
    .line 590
    .line 591
    move-result v10

    .line 592
    if-nez v10, :cond_b

    .line 593
    .line 594
    :cond_a
    invoke-static {v7, v11, v7, v8}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 595
    .line 596
    .line 597
    :cond_b
    sget-object v7, Lv3/j;->d:Lv3/h;

    .line 598
    .line 599
    invoke-static {v7, v3, v11}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 600
    .line 601
    .line 602
    sget-object v3, Lx2/c;->q:Lx2/h;

    .line 603
    .line 604
    const/high16 v10, 0x3f800000    # 1.0f

    .line 605
    .line 606
    float-to-double v12, v10

    .line 607
    const-wide/16 v31, 0x0

    .line 608
    .line 609
    cmpl-double v12, v12, v31

    .line 610
    .line 611
    const-string v33, "invalid weight; must be greater than zero"

    .line 612
    .line 613
    if-lez v12, :cond_c

    .line 614
    .line 615
    goto :goto_4

    .line 616
    :cond_c
    invoke-static/range {v33 .. v33}, Ll1/a;->a(Ljava/lang/String;)V

    .line 617
    .line 618
    .line 619
    :goto_4
    new-instance v12, Landroidx/compose/foundation/layout/LayoutWeightElement;

    .line 620
    .line 621
    const v34, 0x7f7fffff    # Float.MAX_VALUE

    .line 622
    .line 623
    .line 624
    cmpl-float v13, v10, v34

    .line 625
    .line 626
    if-lez v13, :cond_d

    .line 627
    .line 628
    move/from16 v13, v34

    .line 629
    .line 630
    goto :goto_5

    .line 631
    :cond_d
    move v13, v10

    .line 632
    :goto_5
    const/4 v15, 0x1

    .line 633
    invoke-direct {v12, v13, v15}, Landroidx/compose/foundation/layout/LayoutWeightElement;-><init>(FZ)V

    .line 634
    .line 635
    .line 636
    sget-object v13, Lk1/j;->c:Lk1/e;

    .line 637
    .line 638
    const/16 v0, 0x30

    .line 639
    .line 640
    invoke-static {v13, v3, v11, v0}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 641
    .line 642
    .line 643
    move-result-object v10

    .line 644
    move-object/from16 v36, v1

    .line 645
    .line 646
    iget-wide v0, v11, Ll2/t;->T:J

    .line 647
    .line 648
    invoke-static {v0, v1}, Ljava/lang/Long;->hashCode(J)I

    .line 649
    .line 650
    .line 651
    move-result v0

    .line 652
    invoke-virtual {v11}, Ll2/t;->m()Ll2/p1;

    .line 653
    .line 654
    .line 655
    move-result-object v1

    .line 656
    invoke-static {v11, v12}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 657
    .line 658
    .line 659
    move-result-object v12

    .line 660
    invoke-virtual {v11}, Ll2/t;->c0()V

    .line 661
    .line 662
    .line 663
    iget-boolean v15, v11, Ll2/t;->S:Z

    .line 664
    .line 665
    if-eqz v15, :cond_e

    .line 666
    .line 667
    invoke-virtual {v11, v14}, Ll2/t;->l(Lay0/a;)V

    .line 668
    .line 669
    .line 670
    goto :goto_6

    .line 671
    :cond_e
    invoke-virtual {v11}, Ll2/t;->m0()V

    .line 672
    .line 673
    .line 674
    :goto_6
    invoke-static {v9, v10, v11}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 675
    .line 676
    .line 677
    invoke-static {v6, v1, v11}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 678
    .line 679
    .line 680
    iget-boolean v1, v11, Ll2/t;->S:Z

    .line 681
    .line 682
    if-nez v1, :cond_f

    .line 683
    .line 684
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 685
    .line 686
    .line 687
    move-result-object v1

    .line 688
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 689
    .line 690
    .line 691
    move-result-object v10

    .line 692
    invoke-static {v1, v10}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 693
    .line 694
    .line 695
    move-result v1

    .line 696
    if-nez v1, :cond_10

    .line 697
    .line 698
    :cond_f
    invoke-static {v0, v11, v0, v8}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 699
    .line 700
    .line 701
    :cond_10
    invoke-static {v7, v12, v11}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 702
    .line 703
    .line 704
    invoke-static/range {v30 .. v30}, Lxf0/y1;->C(Lvf0/m;)I

    .line 705
    .line 706
    .line 707
    move-result v0

    .line 708
    const/4 v1, 0x0

    .line 709
    invoke-static {v0, v1, v11}, Ljp/fa;->b(IILl2/o;)Li3/c;

    .line 710
    .line 711
    .line 712
    move-result-object v0

    .line 713
    invoke-virtual {v11, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 714
    .line 715
    .line 716
    move-result-object v1

    .line 717
    check-cast v1, Lj91/c;

    .line 718
    .line 719
    iget v1, v1, Lj91/c;->c:F

    .line 720
    .line 721
    const/16 v20, 0x7

    .line 722
    .line 723
    const/4 v10, 0x1

    .line 724
    const/16 v16, 0x0

    .line 725
    .line 726
    const/16 v17, 0x0

    .line 727
    .line 728
    const/16 v18, 0x0

    .line 729
    .line 730
    move/from16 v19, v1

    .line 731
    .line 732
    move-object v15, v5

    .line 733
    move v1, v10

    .line 734
    invoke-static/range {v15 .. v20}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 735
    .line 736
    .line 737
    move-result-object v5

    .line 738
    move-object/from16 v37, v15

    .line 739
    .line 740
    sget v15, Lxf0/i3;->e:F

    .line 741
    .line 742
    invoke-static {v5, v15}, Landroidx/compose/foundation/layout/d;->n(Lx2/s;F)Lx2/s;

    .line 743
    .line 744
    .line 745
    move-result-object v5

    .line 746
    const/16 v12, 0x30

    .line 747
    .line 748
    move-object v10, v13

    .line 749
    const/4 v13, 0x0

    .line 750
    move-object/from16 v16, v7

    .line 751
    .line 752
    const/4 v7, 0x0

    .line 753
    move-object/from16 v17, v9

    .line 754
    .line 755
    move-object/from16 v18, v10

    .line 756
    .line 757
    iget-wide v9, v2, Lxf0/a3;->n:J

    .line 758
    .line 759
    move-object/from16 v38, v6

    .line 760
    .line 761
    move-object/from16 v39, v8

    .line 762
    .line 763
    move-object/from16 v40, v16

    .line 764
    .line 765
    move-object/from16 v41, v18

    .line 766
    .line 767
    move-object v6, v0

    .line 768
    move-object v8, v5

    .line 769
    move-object/from16 v5, v17

    .line 770
    .line 771
    const/high16 v0, 0x3f800000    # 1.0f

    .line 772
    .line 773
    invoke-static/range {v6 .. v13}, Lh2/f5;->a(Li3/c;Ljava/lang/String;Lx2/s;JLl2/o;II)V

    .line 774
    .line 775
    .line 776
    move-object/from16 v6, v30

    .line 777
    .line 778
    iget-object v6, v6, Lvf0/m;->c:Ljava/lang/String;

    .line 779
    .line 780
    move-object/from16 v7, v36

    .line 781
    .line 782
    invoke-virtual {v11, v7}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 783
    .line 784
    .line 785
    move-result-object v8

    .line 786
    check-cast v8, Lj91/f;

    .line 787
    .line 788
    invoke-virtual {v8}, Lj91/f;->l()Lg4/p0;

    .line 789
    .line 790
    .line 791
    move-result-object v8

    .line 792
    const/16 v26, 0x0

    .line 793
    .line 794
    const v27, 0xfff4

    .line 795
    .line 796
    .line 797
    move-object/from16 v18, v7

    .line 798
    .line 799
    move-object v7, v8

    .line 800
    const/4 v8, 0x0

    .line 801
    iget-wide v9, v2, Lxf0/a3;->n:J

    .line 802
    .line 803
    move-object/from16 v24, v11

    .line 804
    .line 805
    const-wide/16 v11, 0x0

    .line 806
    .line 807
    const/4 v13, 0x0

    .line 808
    move-object/from16 v16, v14

    .line 809
    .line 810
    move/from16 v17, v15

    .line 811
    .line 812
    const-wide/16 v14, 0x0

    .line 813
    .line 814
    move-object/from16 v19, v16

    .line 815
    .line 816
    const/16 v16, 0x0

    .line 817
    .line 818
    move/from16 v20, v17

    .line 819
    .line 820
    const/16 v17, 0x0

    .line 821
    .line 822
    move-object/from16 v36, v18

    .line 823
    .line 824
    move-object/from16 v21, v19

    .line 825
    .line 826
    const-wide/16 v18, 0x0

    .line 827
    .line 828
    move/from16 v22, v20

    .line 829
    .line 830
    const/16 v20, 0x0

    .line 831
    .line 832
    move-object/from16 v23, v21

    .line 833
    .line 834
    const/16 v21, 0x0

    .line 835
    .line 836
    move/from16 v25, v22

    .line 837
    .line 838
    const/16 v22, 0x0

    .line 839
    .line 840
    move-object/from16 v30, v23

    .line 841
    .line 842
    const/16 v23, 0x0

    .line 843
    .line 844
    move/from16 v42, v25

    .line 845
    .line 846
    const/16 v25, 0x0

    .line 847
    .line 848
    move-object/from16 v44, v30

    .line 849
    .line 850
    move-object/from16 v43, v36

    .line 851
    .line 852
    move/from16 v45, v42

    .line 853
    .line 854
    invoke-static/range {v6 .. v27}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 855
    .line 856
    .line 857
    move-object/from16 v11, v24

    .line 858
    .line 859
    invoke-virtual {v11, v1}, Ll2/t;->q(Z)V

    .line 860
    .line 861
    .line 862
    float-to-double v6, v0

    .line 863
    cmpl-double v6, v6, v31

    .line 864
    .line 865
    if-lez v6, :cond_11

    .line 866
    .line 867
    goto :goto_7

    .line 868
    :cond_11
    invoke-static/range {v33 .. v33}, Ll1/a;->a(Ljava/lang/String;)V

    .line 869
    .line 870
    .line 871
    :goto_7
    new-instance v6, Landroidx/compose/foundation/layout/LayoutWeightElement;

    .line 872
    .line 873
    cmpl-float v7, v0, v34

    .line 874
    .line 875
    if-lez v7, :cond_12

    .line 876
    .line 877
    move/from16 v10, v34

    .line 878
    .line 879
    goto :goto_8

    .line 880
    :cond_12
    move v10, v0

    .line 881
    :goto_8
    invoke-direct {v6, v10, v1}, Landroidx/compose/foundation/layout/LayoutWeightElement;-><init>(FZ)V

    .line 882
    .line 883
    .line 884
    move-object/from16 v10, v41

    .line 885
    .line 886
    const/16 v0, 0x30

    .line 887
    .line 888
    invoke-static {v10, v3, v11, v0}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 889
    .line 890
    .line 891
    move-result-object v0

    .line 892
    iget-wide v7, v11, Ll2/t;->T:J

    .line 893
    .line 894
    invoke-static {v7, v8}, Ljava/lang/Long;->hashCode(J)I

    .line 895
    .line 896
    .line 897
    move-result v3

    .line 898
    invoke-virtual {v11}, Ll2/t;->m()Ll2/p1;

    .line 899
    .line 900
    .line 901
    move-result-object v7

    .line 902
    invoke-static {v11, v6}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 903
    .line 904
    .line 905
    move-result-object v6

    .line 906
    invoke-virtual {v11}, Ll2/t;->c0()V

    .line 907
    .line 908
    .line 909
    iget-boolean v8, v11, Ll2/t;->S:Z

    .line 910
    .line 911
    if-eqz v8, :cond_13

    .line 912
    .line 913
    move-object/from16 v8, v44

    .line 914
    .line 915
    invoke-virtual {v11, v8}, Ll2/t;->l(Lay0/a;)V

    .line 916
    .line 917
    .line 918
    goto :goto_9

    .line 919
    :cond_13
    invoke-virtual {v11}, Ll2/t;->m0()V

    .line 920
    .line 921
    .line 922
    :goto_9
    invoke-static {v5, v0, v11}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 923
    .line 924
    .line 925
    move-object/from16 v0, v38

    .line 926
    .line 927
    invoke-static {v0, v7, v11}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 928
    .line 929
    .line 930
    iget-boolean v0, v11, Ll2/t;->S:Z

    .line 931
    .line 932
    if-nez v0, :cond_14

    .line 933
    .line 934
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 935
    .line 936
    .line 937
    move-result-object v0

    .line 938
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 939
    .line 940
    .line 941
    move-result-object v5

    .line 942
    invoke-static {v0, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 943
    .line 944
    .line 945
    move-result v0

    .line 946
    if-nez v0, :cond_15

    .line 947
    .line 948
    :cond_14
    move-object/from16 v0, v39

    .line 949
    .line 950
    goto :goto_b

    .line 951
    :cond_15
    :goto_a
    move-object/from16 v0, v40

    .line 952
    .line 953
    goto :goto_c

    .line 954
    :goto_b
    invoke-static {v3, v11, v3, v0}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 955
    .line 956
    .line 957
    goto :goto_a

    .line 958
    :goto_c
    invoke-static {v0, v6, v11}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 959
    .line 960
    .line 961
    invoke-static/range {v29 .. v29}, Lxf0/y1;->C(Lvf0/m;)I

    .line 962
    .line 963
    .line 964
    move-result v0

    .line 965
    const/4 v3, 0x0

    .line 966
    invoke-static {v0, v3, v11}, Ljp/fa;->b(IILl2/o;)Li3/c;

    .line 967
    .line 968
    .line 969
    move-result-object v6

    .line 970
    invoke-virtual {v11, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 971
    .line 972
    .line 973
    move-result-object v0

    .line 974
    check-cast v0, Lj91/c;

    .line 975
    .line 976
    iget v0, v0, Lj91/c;->c:F

    .line 977
    .line 978
    const/16 v20, 0x7

    .line 979
    .line 980
    const/16 v16, 0x0

    .line 981
    .line 982
    const/16 v17, 0x0

    .line 983
    .line 984
    const/16 v18, 0x0

    .line 985
    .line 986
    move/from16 v19, v0

    .line 987
    .line 988
    move-object/from16 v15, v37

    .line 989
    .line 990
    invoke-static/range {v15 .. v20}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 991
    .line 992
    .line 993
    move-result-object v0

    .line 994
    move/from16 v3, v45

    .line 995
    .line 996
    invoke-static {v0, v3}, Landroidx/compose/foundation/layout/d;->n(Lx2/s;F)Lx2/s;

    .line 997
    .line 998
    .line 999
    move-result-object v8

    .line 1000
    const/16 v12, 0x30

    .line 1001
    .line 1002
    const/4 v13, 0x0

    .line 1003
    const/4 v7, 0x0

    .line 1004
    iget-wide v9, v2, Lxf0/a3;->o:J

    .line 1005
    .line 1006
    invoke-static/range {v6 .. v13}, Lh2/f5;->a(Li3/c;Ljava/lang/String;Lx2/s;JLl2/o;II)V

    .line 1007
    .line 1008
    .line 1009
    move-object/from16 v0, v29

    .line 1010
    .line 1011
    iget-object v6, v0, Lvf0/m;->c:Ljava/lang/String;

    .line 1012
    .line 1013
    move-object/from16 v7, v43

    .line 1014
    .line 1015
    invoke-virtual {v11, v7}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 1016
    .line 1017
    .line 1018
    move-result-object v0

    .line 1019
    check-cast v0, Lj91/f;

    .line 1020
    .line 1021
    invoke-virtual {v0}, Lj91/f;->l()Lg4/p0;

    .line 1022
    .line 1023
    .line 1024
    move-result-object v7

    .line 1025
    const/16 v26, 0x0

    .line 1026
    .line 1027
    const v27, 0xfff4

    .line 1028
    .line 1029
    .line 1030
    const/4 v8, 0x0

    .line 1031
    iget-wide v9, v2, Lxf0/a3;->o:J

    .line 1032
    .line 1033
    move-object/from16 v24, v11

    .line 1034
    .line 1035
    const-wide/16 v11, 0x0

    .line 1036
    .line 1037
    const/4 v13, 0x0

    .line 1038
    const-wide/16 v14, 0x0

    .line 1039
    .line 1040
    const/16 v16, 0x0

    .line 1041
    .line 1042
    const/16 v17, 0x0

    .line 1043
    .line 1044
    const-wide/16 v18, 0x0

    .line 1045
    .line 1046
    const/16 v20, 0x0

    .line 1047
    .line 1048
    const/16 v21, 0x0

    .line 1049
    .line 1050
    const/16 v22, 0x0

    .line 1051
    .line 1052
    const/16 v23, 0x0

    .line 1053
    .line 1054
    const/16 v25, 0x0

    .line 1055
    .line 1056
    invoke-static/range {v6 .. v27}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 1057
    .line 1058
    .line 1059
    move-object/from16 v11, v24

    .line 1060
    .line 1061
    invoke-virtual {v11, v1}, Ll2/t;->q(Z)V

    .line 1062
    .line 1063
    .line 1064
    invoke-virtual {v11, v1}, Ll2/t;->q(Z)V

    .line 1065
    .line 1066
    .line 1067
    const/4 v0, 0x0

    .line 1068
    invoke-virtual {v11, v0}, Ll2/t;->q(Z)V

    .line 1069
    .line 1070
    .line 1071
    invoke-virtual {v11, v0}, Ll2/t;->q(Z)V

    .line 1072
    .line 1073
    .line 1074
    move-object/from16 v0, v35

    .line 1075
    .line 1076
    iget v0, v0, Lz4/k;->b:I

    .line 1077
    .line 1078
    move/from16 v1, p2

    .line 1079
    .line 1080
    if-eq v0, v1, :cond_16

    .line 1081
    .line 1082
    iget-object v0, v2, Lxf0/a3;->h:Lay0/a;

    .line 1083
    .line 1084
    invoke-static {v0, v11}, Ll2/l0;->g(Lay0/a;Ll2/o;)V

    .line 1085
    .line 1086
    .line 1087
    :cond_16
    return-object v28
.end method
