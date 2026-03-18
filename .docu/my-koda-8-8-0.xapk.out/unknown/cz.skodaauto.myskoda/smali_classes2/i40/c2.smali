.class public final synthetic Li40/c2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/String;

.field public final synthetic f:J

.field public final synthetic g:J

.field public final synthetic h:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Integer;JJLjava/lang/String;I)V
    .locals 0

    .line 1
    const/4 p7, 0x0

    iput p7, p0, Li40/c2;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Li40/c2;->h:Ljava/lang/Object;

    iput-wide p2, p0, Li40/c2;->f:J

    iput-wide p4, p0, Li40/c2;->g:J

    iput-object p6, p0, Li40/c2;->e:Ljava/lang/String;

    return-void
.end method

.method public synthetic constructor <init>(Ltz/l2;Ljava/lang/String;JJ)V
    .locals 1

    .line 2
    const/4 v0, 0x1

    iput v0, p0, Li40/c2;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Li40/c2;->h:Ljava/lang/Object;

    iput-object p2, p0, Li40/c2;->e:Ljava/lang/String;

    iput-wide p3, p0, Li40/c2;->f:J

    iput-wide p5, p0, Li40/c2;->g:J

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 36

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Li40/c2;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    iget-object v1, v0, Li40/c2;->h:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v1, Ltz/l2;

    .line 11
    .line 12
    move-object/from16 v2, p1

    .line 13
    .line 14
    check-cast v2, Ll2/o;

    .line 15
    .line 16
    move-object/from16 v3, p2

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
    and-int/lit8 v4, v3, 0x3

    .line 25
    .line 26
    const/4 v5, 0x2

    .line 27
    const/4 v6, 0x1

    .line 28
    const/4 v7, 0x0

    .line 29
    if-eq v4, v5, :cond_0

    .line 30
    .line 31
    move v4, v6

    .line 32
    goto :goto_0

    .line 33
    :cond_0
    move v4, v7

    .line 34
    :goto_0
    and-int/2addr v3, v6

    .line 35
    move-object v13, v2

    .line 36
    check-cast v13, Ll2/t;

    .line 37
    .line 38
    invoke-virtual {v13, v3, v4}, Ll2/t;->O(IZ)Z

    .line 39
    .line 40
    .line 41
    move-result v2

    .line 42
    if-eqz v2, :cond_10

    .line 43
    .line 44
    sget-object v2, Lj91/a;->a:Ll2/u2;

    .line 45
    .line 46
    invoke-virtual {v13, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    move-result-object v3

    .line 50
    check-cast v3, Lj91/c;

    .line 51
    .line 52
    iget v3, v3, Lj91/c;->d:F

    .line 53
    .line 54
    sget-object v4, Lx2/p;->b:Lx2/p;

    .line 55
    .line 56
    invoke-static {v4, v3}, Landroidx/compose/foundation/layout/a;->m(Lx2/s;F)Lx2/s;

    .line 57
    .line 58
    .line 59
    move-result-object v3

    .line 60
    sget-object v5, Lk1/j;->c:Lk1/e;

    .line 61
    .line 62
    sget-object v8, Lx2/c;->p:Lx2/h;

    .line 63
    .line 64
    invoke-static {v5, v8, v13, v7}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 65
    .line 66
    .line 67
    move-result-object v5

    .line 68
    iget-wide v8, v13, Ll2/t;->T:J

    .line 69
    .line 70
    invoke-static {v8, v9}, Ljava/lang/Long;->hashCode(J)I

    .line 71
    .line 72
    .line 73
    move-result v8

    .line 74
    invoke-virtual {v13}, Ll2/t;->m()Ll2/p1;

    .line 75
    .line 76
    .line 77
    move-result-object v9

    .line 78
    invoke-static {v13, v3}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 79
    .line 80
    .line 81
    move-result-object v3

    .line 82
    sget-object v10, Lv3/k;->m1:Lv3/j;

    .line 83
    .line 84
    invoke-virtual {v10}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 85
    .line 86
    .line 87
    sget-object v10, Lv3/j;->b:Lv3/i;

    .line 88
    .line 89
    invoke-virtual {v13}, Ll2/t;->c0()V

    .line 90
    .line 91
    .line 92
    iget-boolean v11, v13, Ll2/t;->S:Z

    .line 93
    .line 94
    if-eqz v11, :cond_1

    .line 95
    .line 96
    invoke-virtual {v13, v10}, Ll2/t;->l(Lay0/a;)V

    .line 97
    .line 98
    .line 99
    goto :goto_1

    .line 100
    :cond_1
    invoke-virtual {v13}, Ll2/t;->m0()V

    .line 101
    .line 102
    .line 103
    :goto_1
    sget-object v11, Lv3/j;->g:Lv3/h;

    .line 104
    .line 105
    invoke-static {v11, v5, v13}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 106
    .line 107
    .line 108
    sget-object v5, Lv3/j;->f:Lv3/h;

    .line 109
    .line 110
    invoke-static {v5, v9, v13}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 111
    .line 112
    .line 113
    sget-object v9, Lv3/j;->j:Lv3/h;

    .line 114
    .line 115
    iget-boolean v12, v13, Ll2/t;->S:Z

    .line 116
    .line 117
    if-nez v12, :cond_2

    .line 118
    .line 119
    invoke-virtual {v13}, Ll2/t;->L()Ljava/lang/Object;

    .line 120
    .line 121
    .line 122
    move-result-object v12

    .line 123
    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 124
    .line 125
    .line 126
    move-result-object v14

    .line 127
    invoke-static {v12, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 128
    .line 129
    .line 130
    move-result v12

    .line 131
    if-nez v12, :cond_3

    .line 132
    .line 133
    :cond_2
    invoke-static {v8, v13, v8, v9}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 134
    .line 135
    .line 136
    :cond_3
    sget-object v8, Lv3/j;->d:Lv3/h;

    .line 137
    .line 138
    invoke-static {v8, v3, v13}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 139
    .line 140
    .line 141
    move-object v3, v8

    .line 142
    iget-object v8, v1, Ltz/l2;->b:Ljava/lang/String;

    .line 143
    .line 144
    sget-object v12, Lj91/j;->a:Ll2/u2;

    .line 145
    .line 146
    invoke-virtual {v13, v12}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 147
    .line 148
    .line 149
    move-result-object v14

    .line 150
    check-cast v14, Lj91/f;

    .line 151
    .line 152
    invoke-virtual {v14}, Lj91/f;->k()Lg4/p0;

    .line 153
    .line 154
    .line 155
    move-result-object v14

    .line 156
    new-instance v15, Ljava/lang/StringBuilder;

    .line 157
    .line 158
    invoke-direct {v15}, Ljava/lang/StringBuilder;-><init>()V

    .line 159
    .line 160
    .line 161
    iget-object v7, v0, Li40/c2;->e:Ljava/lang/String;

    .line 162
    .line 163
    invoke-virtual {v15, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 164
    .line 165
    .line 166
    const-string v6, "_name"

    .line 167
    .line 168
    invoke-virtual {v15, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 169
    .line 170
    .line 171
    invoke-virtual {v15}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 172
    .line 173
    .line 174
    move-result-object v6

    .line 175
    invoke-static {v4, v6}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 176
    .line 177
    .line 178
    move-result-object v6

    .line 179
    const/16 v28, 0x0

    .line 180
    .line 181
    const v29, 0xfff0

    .line 182
    .line 183
    .line 184
    move-object v15, v11

    .line 185
    move-object/from16 v16, v12

    .line 186
    .line 187
    iget-wide v11, v0, Li40/c2;->f:J

    .line 188
    .line 189
    move-object/from16 v17, v9

    .line 190
    .line 191
    move-object/from16 v26, v13

    .line 192
    .line 193
    move-object v9, v14

    .line 194
    const-wide/16 v13, 0x0

    .line 195
    .line 196
    move-object/from16 v18, v15

    .line 197
    .line 198
    const/4 v15, 0x0

    .line 199
    move-object/from16 v20, v16

    .line 200
    .line 201
    move-object/from16 v19, v17

    .line 202
    .line 203
    const-wide/16 v16, 0x0

    .line 204
    .line 205
    move-object/from16 v21, v18

    .line 206
    .line 207
    const/16 v18, 0x0

    .line 208
    .line 209
    move-object/from16 v22, v19

    .line 210
    .line 211
    const/16 v19, 0x0

    .line 212
    .line 213
    move-object/from16 v24, v20

    .line 214
    .line 215
    move-object/from16 v23, v21

    .line 216
    .line 217
    const-wide/16 v20, 0x0

    .line 218
    .line 219
    move-object/from16 v25, v22

    .line 220
    .line 221
    const/16 v22, 0x0

    .line 222
    .line 223
    move-object/from16 v27, v23

    .line 224
    .line 225
    const/16 v23, 0x0

    .line 226
    .line 227
    move-object/from16 v30, v24

    .line 228
    .line 229
    const/16 v24, 0x0

    .line 230
    .line 231
    move-object/from16 v31, v25

    .line 232
    .line 233
    const/16 v25, 0x0

    .line 234
    .line 235
    move-object/from16 v32, v27

    .line 236
    .line 237
    const/16 v27, 0x0

    .line 238
    .line 239
    move-object v0, v3

    .line 240
    move-object v3, v10

    .line 241
    move-object/from16 v33, v30

    .line 242
    .line 243
    move-object v10, v6

    .line 244
    move-object/from16 v30, v7

    .line 245
    .line 246
    move-object/from16 v7, v31

    .line 247
    .line 248
    move-object/from16 v6, v32

    .line 249
    .line 250
    invoke-static/range {v8 .. v29}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 251
    .line 252
    .line 253
    move-object/from16 v13, v26

    .line 254
    .line 255
    invoke-virtual {v13, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 256
    .line 257
    .line 258
    move-result-object v8

    .line 259
    check-cast v8, Lj91/c;

    .line 260
    .line 261
    iget v8, v8, Lj91/c;->c:F

    .line 262
    .line 263
    const/high16 v9, 0x3f800000    # 1.0f

    .line 264
    .line 265
    invoke-static {v4, v8, v13, v4, v9}, Lp3/m;->v(Lx2/p;FLl2/t;Lx2/p;F)Lx2/s;

    .line 266
    .line 267
    .line 268
    move-result-object v8

    .line 269
    sget-object v10, Lx2/c;->n:Lx2/i;

    .line 270
    .line 271
    sget-object v11, Lk1/j;->a:Lk1/c;

    .line 272
    .line 273
    const/16 v12, 0x30

    .line 274
    .line 275
    invoke-static {v11, v10, v13, v12}, Lk1/e1;->a(Lk1/g;Lx2/i;Ll2/o;I)Lk1/g1;

    .line 276
    .line 277
    .line 278
    move-result-object v14

    .line 279
    move-object/from16 v16, v10

    .line 280
    .line 281
    iget-wide v9, v13, Ll2/t;->T:J

    .line 282
    .line 283
    invoke-static {v9, v10}, Ljava/lang/Long;->hashCode(J)I

    .line 284
    .line 285
    .line 286
    move-result v9

    .line 287
    invoke-virtual {v13}, Ll2/t;->m()Ll2/p1;

    .line 288
    .line 289
    .line 290
    move-result-object v10

    .line 291
    invoke-static {v13, v8}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 292
    .line 293
    .line 294
    move-result-object v8

    .line 295
    invoke-virtual {v13}, Ll2/t;->c0()V

    .line 296
    .line 297
    .line 298
    iget-boolean v15, v13, Ll2/t;->S:Z

    .line 299
    .line 300
    if-eqz v15, :cond_4

    .line 301
    .line 302
    invoke-virtual {v13, v3}, Ll2/t;->l(Lay0/a;)V

    .line 303
    .line 304
    .line 305
    goto :goto_2

    .line 306
    :cond_4
    invoke-virtual {v13}, Ll2/t;->m0()V

    .line 307
    .line 308
    .line 309
    :goto_2
    invoke-static {v6, v14, v13}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 310
    .line 311
    .line 312
    invoke-static {v5, v10, v13}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 313
    .line 314
    .line 315
    iget-boolean v10, v13, Ll2/t;->S:Z

    .line 316
    .line 317
    if-nez v10, :cond_5

    .line 318
    .line 319
    invoke-virtual {v13}, Ll2/t;->L()Ljava/lang/Object;

    .line 320
    .line 321
    .line 322
    move-result-object v10

    .line 323
    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 324
    .line 325
    .line 326
    move-result-object v14

    .line 327
    invoke-static {v10, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 328
    .line 329
    .line 330
    move-result v10

    .line 331
    if-nez v10, :cond_6

    .line 332
    .line 333
    :cond_5
    invoke-static {v9, v13, v9, v7}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 334
    .line 335
    .line 336
    :cond_6
    invoke-static {v0, v8, v13}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 337
    .line 338
    .line 339
    const/high16 v15, 0x3f800000    # 1.0f

    .line 340
    .line 341
    float-to-double v8, v15

    .line 342
    const-wide/16 v31, 0x0

    .line 343
    .line 344
    cmpl-double v8, v8, v31

    .line 345
    .line 346
    const-string v34, "invalid weight; must be greater than zero"

    .line 347
    .line 348
    if-lez v8, :cond_7

    .line 349
    .line 350
    goto :goto_3

    .line 351
    :cond_7
    invoke-static/range {v34 .. v34}, Ll1/a;->a(Ljava/lang/String;)V

    .line 352
    .line 353
    .line 354
    :goto_3
    new-instance v8, Landroidx/compose/foundation/layout/LayoutWeightElement;

    .line 355
    .line 356
    const v35, 0x7f7fffff    # Float.MAX_VALUE

    .line 357
    .line 358
    .line 359
    cmpl-float v9, v15, v35

    .line 360
    .line 361
    if-lez v9, :cond_8

    .line 362
    .line 363
    move/from16 v9, v35

    .line 364
    .line 365
    :goto_4
    const/4 v10, 0x1

    .line 366
    goto :goto_5

    .line 367
    :cond_8
    move v9, v15

    .line 368
    goto :goto_4

    .line 369
    :goto_5
    invoke-direct {v8, v9, v10}, Landroidx/compose/foundation/layout/LayoutWeightElement;-><init>(FZ)V

    .line 370
    .line 371
    .line 372
    move-object/from16 v9, v16

    .line 373
    .line 374
    invoke-static {v11, v9, v13, v12}, Lk1/e1;->a(Lk1/g;Lx2/i;Ll2/o;I)Lk1/g1;

    .line 375
    .line 376
    .line 377
    move-result-object v9

    .line 378
    iget-wide v10, v13, Ll2/t;->T:J

    .line 379
    .line 380
    invoke-static {v10, v11}, Ljava/lang/Long;->hashCode(J)I

    .line 381
    .line 382
    .line 383
    move-result v10

    .line 384
    invoke-virtual {v13}, Ll2/t;->m()Ll2/p1;

    .line 385
    .line 386
    .line 387
    move-result-object v11

    .line 388
    invoke-static {v13, v8}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 389
    .line 390
    .line 391
    move-result-object v8

    .line 392
    invoke-virtual {v13}, Ll2/t;->c0()V

    .line 393
    .line 394
    .line 395
    iget-boolean v12, v13, Ll2/t;->S:Z

    .line 396
    .line 397
    if-eqz v12, :cond_9

    .line 398
    .line 399
    invoke-virtual {v13, v3}, Ll2/t;->l(Lay0/a;)V

    .line 400
    .line 401
    .line 402
    goto :goto_6

    .line 403
    :cond_9
    invoke-virtual {v13}, Ll2/t;->m0()V

    .line 404
    .line 405
    .line 406
    :goto_6
    invoke-static {v6, v9, v13}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 407
    .line 408
    .line 409
    invoke-static {v5, v11, v13}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 410
    .line 411
    .line 412
    iget-boolean v3, v13, Ll2/t;->S:Z

    .line 413
    .line 414
    if-nez v3, :cond_a

    .line 415
    .line 416
    invoke-virtual {v13}, Ll2/t;->L()Ljava/lang/Object;

    .line 417
    .line 418
    .line 419
    move-result-object v3

    .line 420
    invoke-static {v10}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 421
    .line 422
    .line 423
    move-result-object v5

    .line 424
    invoke-static {v3, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 425
    .line 426
    .line 427
    move-result v3

    .line 428
    if-nez v3, :cond_b

    .line 429
    .line 430
    :cond_a
    invoke-static {v10, v13, v10, v7}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 431
    .line 432
    .line 433
    :cond_b
    invoke-static {v0, v8, v13}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 434
    .line 435
    .line 436
    iget-object v0, v1, Ltz/l2;->c:Ljava/lang/String;

    .line 437
    .line 438
    if-nez v0, :cond_c

    .line 439
    .line 440
    const v0, -0xf2a93c9

    .line 441
    .line 442
    .line 443
    invoke-virtual {v13, v0}, Ll2/t;->Y(I)V

    .line 444
    .line 445
    .line 446
    const/4 v3, 0x0

    .line 447
    :goto_7
    invoke-virtual {v13, v3}, Ll2/t;->q(Z)V

    .line 448
    .line 449
    .line 450
    const/4 v10, 0x1

    .line 451
    goto/16 :goto_c

    .line 452
    .line 453
    :cond_c
    const/4 v3, 0x0

    .line 454
    const v5, -0xf2a93c8

    .line 455
    .line 456
    .line 457
    invoke-virtual {v13, v5}, Ll2/t;->Y(I)V

    .line 458
    .line 459
    .line 460
    const v5, 0x7f0802d5

    .line 461
    .line 462
    .line 463
    invoke-static {v5, v3, v13}, Ljp/fa;->b(IILl2/o;)Li3/c;

    .line 464
    .line 465
    .line 466
    move-result-object v8

    .line 467
    const/16 v14, 0x30

    .line 468
    .line 469
    move/from16 v17, v15

    .line 470
    .line 471
    const/4 v15, 0x4

    .line 472
    const/4 v9, 0x0

    .line 473
    const/4 v10, 0x0

    .line 474
    move-object/from16 v3, p0

    .line 475
    .line 476
    iget-wide v11, v3, Li40/c2;->g:J

    .line 477
    .line 478
    move/from16 v3, v17

    .line 479
    .line 480
    invoke-static/range {v8 .. v15}, Lh2/f5;->a(Li3/c;Ljava/lang/String;Lx2/s;JLl2/o;II)V

    .line 481
    .line 482
    .line 483
    invoke-virtual {v13, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 484
    .line 485
    .line 486
    move-result-object v2

    .line 487
    check-cast v2, Lj91/c;

    .line 488
    .line 489
    iget v2, v2, Lj91/c;->b:F

    .line 490
    .line 491
    invoke-static {v4, v2}, Landroidx/compose/foundation/layout/d;->r(Lx2/s;F)Lx2/s;

    .line 492
    .line 493
    .line 494
    move-result-object v2

    .line 495
    invoke-static {v13, v2}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 496
    .line 497
    .line 498
    move-object/from16 v2, v33

    .line 499
    .line 500
    invoke-virtual {v13, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 501
    .line 502
    .line 503
    move-result-object v2

    .line 504
    check-cast v2, Lj91/f;

    .line 505
    .line 506
    invoke-virtual {v2}, Lj91/f;->e()Lg4/p0;

    .line 507
    .line 508
    .line 509
    move-result-object v9

    .line 510
    new-instance v2, Ljava/lang/StringBuilder;

    .line 511
    .line 512
    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    .line 513
    .line 514
    .line 515
    move-object/from16 v5, v30

    .line 516
    .line 517
    invoke-virtual {v2, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 518
    .line 519
    .line 520
    const-string v5, "_charging_limit"

    .line 521
    .line 522
    invoke-virtual {v2, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 523
    .line 524
    .line 525
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 526
    .line 527
    .line 528
    move-result-object v2

    .line 529
    invoke-static {v4, v2}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 530
    .line 531
    .line 532
    move-result-object v10

    .line 533
    const/16 v28, 0x0

    .line 534
    .line 535
    const v29, 0xfff0

    .line 536
    .line 537
    .line 538
    move-object/from16 v26, v13

    .line 539
    .line 540
    const-wide/16 v13, 0x0

    .line 541
    .line 542
    const/4 v15, 0x0

    .line 543
    const-wide/16 v16, 0x0

    .line 544
    .line 545
    const/16 v18, 0x0

    .line 546
    .line 547
    const/16 v19, 0x0

    .line 548
    .line 549
    const-wide/16 v20, 0x0

    .line 550
    .line 551
    const/16 v22, 0x0

    .line 552
    .line 553
    const/16 v23, 0x0

    .line 554
    .line 555
    const/16 v24, 0x0

    .line 556
    .line 557
    const/16 v25, 0x0

    .line 558
    .line 559
    const/16 v27, 0x0

    .line 560
    .line 561
    move-object v8, v0

    .line 562
    invoke-static/range {v8 .. v29}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 563
    .line 564
    .line 565
    move-object/from16 v13, v26

    .line 566
    .line 567
    iget-boolean v0, v1, Ltz/l2;->e:Z

    .line 568
    .line 569
    if-eqz v0, :cond_f

    .line 570
    .line 571
    const v0, 0x8bb29ee

    .line 572
    .line 573
    .line 574
    invoke-virtual {v13, v0}, Ll2/t;->Y(I)V

    .line 575
    .line 576
    .line 577
    float-to-double v4, v3

    .line 578
    cmpl-double v0, v4, v31

    .line 579
    .line 580
    if-lez v0, :cond_d

    .line 581
    .line 582
    goto :goto_8

    .line 583
    :cond_d
    invoke-static/range {v34 .. v34}, Ll1/a;->a(Ljava/lang/String;)V

    .line 584
    .line 585
    .line 586
    :goto_8
    new-instance v0, Landroidx/compose/foundation/layout/LayoutWeightElement;

    .line 587
    .line 588
    cmpl-float v2, v3, v35

    .line 589
    .line 590
    if-lez v2, :cond_e

    .line 591
    .line 592
    move/from16 v9, v35

    .line 593
    .line 594
    :goto_9
    const/4 v10, 0x1

    .line 595
    goto :goto_a

    .line 596
    :cond_e
    move v9, v3

    .line 597
    goto :goto_9

    .line 598
    :goto_a
    invoke-direct {v0, v9, v10}, Landroidx/compose/foundation/layout/LayoutWeightElement;-><init>(FZ)V

    .line 599
    .line 600
    .line 601
    invoke-static {v13, v0}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 602
    .line 603
    .line 604
    iget-boolean v0, v1, Ltz/l2;->d:Z

    .line 605
    .line 606
    const/4 v3, 0x0

    .line 607
    invoke-static {v0, v13, v3}, Luz/g0;->a(ZLl2/o;I)V

    .line 608
    .line 609
    .line 610
    :goto_b
    invoke-virtual {v13, v3}, Ll2/t;->q(Z)V

    .line 611
    .line 612
    .line 613
    goto/16 :goto_7

    .line 614
    .line 615
    :cond_f
    const/4 v3, 0x0

    .line 616
    const v0, 0x7f721e5

    .line 617
    .line 618
    .line 619
    invoke-virtual {v13, v0}, Ll2/t;->Y(I)V

    .line 620
    .line 621
    .line 622
    goto :goto_b

    .line 623
    :goto_c
    invoke-static {v13, v10, v10, v10}, Lf2/m0;->w(Ll2/t;ZZZ)V

    .line 624
    .line 625
    .line 626
    goto :goto_d

    .line 627
    :cond_10
    invoke-virtual {v13}, Ll2/t;->R()V

    .line 628
    .line 629
    .line 630
    :goto_d
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 631
    .line 632
    return-object v0

    .line 633
    :pswitch_0
    move-object v3, v0

    .line 634
    iget-object v0, v3, Li40/c2;->h:Ljava/lang/Object;

    .line 635
    .line 636
    move-object v1, v0

    .line 637
    check-cast v1, Ljava/lang/Integer;

    .line 638
    .line 639
    move-object/from16 v7, p1

    .line 640
    .line 641
    check-cast v7, Ll2/o;

    .line 642
    .line 643
    move-object/from16 v0, p2

    .line 644
    .line 645
    check-cast v0, Ljava/lang/Integer;

    .line 646
    .line 647
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 648
    .line 649
    .line 650
    const/4 v0, 0x1

    .line 651
    invoke-static {v0}, Ll2/b;->x(I)I

    .line 652
    .line 653
    .line 654
    move-result v8

    .line 655
    iget-wide v4, v3, Li40/c2;->f:J

    .line 656
    .line 657
    move-wide v9, v4

    .line 658
    iget-wide v4, v3, Li40/c2;->g:J

    .line 659
    .line 660
    iget-object v6, v3, Li40/c2;->e:Ljava/lang/String;

    .line 661
    .line 662
    move-wide v2, v9

    .line 663
    invoke-static/range {v1 .. v8}, Li40/e2;->c(Ljava/lang/Integer;JJLjava/lang/String;Ll2/o;I)V

    .line 664
    .line 665
    .line 666
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 667
    .line 668
    return-object v0

    .line 669
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
