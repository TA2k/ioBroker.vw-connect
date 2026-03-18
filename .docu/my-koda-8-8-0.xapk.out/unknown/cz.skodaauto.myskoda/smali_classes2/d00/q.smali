.class public final synthetic Ld00/q;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Lc00/m1;

.field public final synthetic e:J

.field public final synthetic f:J

.field public final synthetic g:Lay0/k;

.field public final synthetic h:Z


# direct methods
.method public synthetic constructor <init>(Lc00/m1;JJLay0/k;Z)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ld00/q;->d:Lc00/m1;

    .line 5
    .line 6
    iput-wide p2, p0, Ld00/q;->e:J

    .line 7
    .line 8
    iput-wide p4, p0, Ld00/q;->f:J

    .line 9
    .line 10
    iput-object p6, p0, Ld00/q;->g:Lay0/k;

    .line 11
    .line 12
    iput-boolean p7, p0, Ld00/q;->h:Z

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 40

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
    check-cast v2, Ljava/lang/Integer;

    .line 10
    .line 11
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 12
    .line 13
    .line 14
    move-result v2

    .line 15
    and-int/lit8 v3, v2, 0x3

    .line 16
    .line 17
    const/4 v4, 0x2

    .line 18
    const/4 v5, 0x1

    .line 19
    const/4 v6, 0x0

    .line 20
    if-eq v3, v4, :cond_0

    .line 21
    .line 22
    move v3, v5

    .line 23
    goto :goto_0

    .line 24
    :cond_0
    move v3, v6

    .line 25
    :goto_0
    and-int/2addr v2, v5

    .line 26
    move-object v11, v1

    .line 27
    check-cast v11, Ll2/t;

    .line 28
    .line 29
    invoke-virtual {v11, v2, v3}, Ll2/t;->O(IZ)Z

    .line 30
    .line 31
    .line 32
    move-result v1

    .line 33
    if-eqz v1, :cond_10

    .line 34
    .line 35
    sget-object v1, Lx2/p;->b:Lx2/p;

    .line 36
    .line 37
    const/high16 v2, 0x3f800000    # 1.0f

    .line 38
    .line 39
    invoke-static {v1, v2}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 40
    .line 41
    .line 42
    move-result-object v3

    .line 43
    invoke-static {v11}, Llp/nb;->b(Ll2/o;)Lj91/c;

    .line 44
    .line 45
    .line 46
    move-result-object v4

    .line 47
    iget v4, v4, Lj91/c;->j:F

    .line 48
    .line 49
    invoke-static {v3, v4}, Landroidx/compose/foundation/layout/a;->m(Lx2/s;F)Lx2/s;

    .line 50
    .line 51
    .line 52
    move-result-object v3

    .line 53
    sget-object v4, Lk1/j;->c:Lk1/e;

    .line 54
    .line 55
    sget-object v7, Lx2/c;->p:Lx2/h;

    .line 56
    .line 57
    invoke-static {v4, v7, v11, v6}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 58
    .line 59
    .line 60
    move-result-object v4

    .line 61
    iget-wide v7, v11, Ll2/t;->T:J

    .line 62
    .line 63
    invoke-static {v7, v8}, Ljava/lang/Long;->hashCode(J)I

    .line 64
    .line 65
    .line 66
    move-result v7

    .line 67
    invoke-virtual {v11}, Ll2/t;->m()Ll2/p1;

    .line 68
    .line 69
    .line 70
    move-result-object v8

    .line 71
    invoke-static {v11, v3}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 72
    .line 73
    .line 74
    move-result-object v3

    .line 75
    sget-object v9, Lv3/k;->m1:Lv3/j;

    .line 76
    .line 77
    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 78
    .line 79
    .line 80
    sget-object v9, Lv3/j;->b:Lv3/i;

    .line 81
    .line 82
    invoke-virtual {v11}, Ll2/t;->c0()V

    .line 83
    .line 84
    .line 85
    iget-boolean v10, v11, Ll2/t;->S:Z

    .line 86
    .line 87
    if-eqz v10, :cond_1

    .line 88
    .line 89
    invoke-virtual {v11, v9}, Ll2/t;->l(Lay0/a;)V

    .line 90
    .line 91
    .line 92
    goto :goto_1

    .line 93
    :cond_1
    invoke-virtual {v11}, Ll2/t;->m0()V

    .line 94
    .line 95
    .line 96
    :goto_1
    sget-object v10, Lv3/j;->g:Lv3/h;

    .line 97
    .line 98
    invoke-static {v10, v4, v11}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 99
    .line 100
    .line 101
    sget-object v4, Lv3/j;->f:Lv3/h;

    .line 102
    .line 103
    invoke-static {v4, v8, v11}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 104
    .line 105
    .line 106
    sget-object v8, Lv3/j;->j:Lv3/h;

    .line 107
    .line 108
    iget-boolean v12, v11, Ll2/t;->S:Z

    .line 109
    .line 110
    if-nez v12, :cond_2

    .line 111
    .line 112
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 113
    .line 114
    .line 115
    move-result-object v12

    .line 116
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 117
    .line 118
    .line 119
    move-result-object v13

    .line 120
    invoke-static {v12, v13}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 121
    .line 122
    .line 123
    move-result v12

    .line 124
    if-nez v12, :cond_3

    .line 125
    .line 126
    :cond_2
    invoke-static {v7, v11, v7, v8}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 127
    .line 128
    .line 129
    :cond_3
    sget-object v7, Lv3/j;->d:Lv3/h;

    .line 130
    .line 131
    invoke-static {v7, v3, v11}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 132
    .line 133
    .line 134
    sget-object v3, Lx2/c;->n:Lx2/i;

    .line 135
    .line 136
    sget-object v12, Lk1/j;->a:Lk1/c;

    .line 137
    .line 138
    const/16 v13, 0x30

    .line 139
    .line 140
    invoke-static {v12, v3, v11, v13}, Lk1/e1;->a(Lk1/g;Lx2/i;Ll2/o;I)Lk1/g1;

    .line 141
    .line 142
    .line 143
    move-result-object v14

    .line 144
    iget-wide v5, v11, Ll2/t;->T:J

    .line 145
    .line 146
    invoke-static {v5, v6}, Ljava/lang/Long;->hashCode(J)I

    .line 147
    .line 148
    .line 149
    move-result v5

    .line 150
    invoke-virtual {v11}, Ll2/t;->m()Ll2/p1;

    .line 151
    .line 152
    .line 153
    move-result-object v6

    .line 154
    invoke-static {v11, v1}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 155
    .line 156
    .line 157
    move-result-object v15

    .line 158
    invoke-virtual {v11}, Ll2/t;->c0()V

    .line 159
    .line 160
    .line 161
    iget-boolean v13, v11, Ll2/t;->S:Z

    .line 162
    .line 163
    if-eqz v13, :cond_4

    .line 164
    .line 165
    invoke-virtual {v11, v9}, Ll2/t;->l(Lay0/a;)V

    .line 166
    .line 167
    .line 168
    goto :goto_2

    .line 169
    :cond_4
    invoke-virtual {v11}, Ll2/t;->m0()V

    .line 170
    .line 171
    .line 172
    :goto_2
    invoke-static {v10, v14, v11}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 173
    .line 174
    .line 175
    invoke-static {v4, v6, v11}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 176
    .line 177
    .line 178
    iget-boolean v6, v11, Ll2/t;->S:Z

    .line 179
    .line 180
    if-nez v6, :cond_5

    .line 181
    .line 182
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 183
    .line 184
    .line 185
    move-result-object v6

    .line 186
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 187
    .line 188
    .line 189
    move-result-object v13

    .line 190
    invoke-static {v6, v13}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 191
    .line 192
    .line 193
    move-result v6

    .line 194
    if-nez v6, :cond_6

    .line 195
    .line 196
    :cond_5
    invoke-static {v5, v11, v5, v8}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 197
    .line 198
    .line 199
    :cond_6
    invoke-static {v7, v15, v11}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 200
    .line 201
    .line 202
    iget-object v5, v0, Ld00/q;->d:Lc00/m1;

    .line 203
    .line 204
    move-object v6, v7

    .line 205
    iget-object v7, v5, Lc00/m1;->b:Ljava/lang/String;

    .line 206
    .line 207
    invoke-static {v11}, Llp/nb;->c(Ll2/o;)Lj91/f;

    .line 208
    .line 209
    .line 210
    move-result-object v13

    .line 211
    invoke-virtual {v13}, Lj91/f;->a()Lg4/p0;

    .line 212
    .line 213
    .line 214
    move-result-object v13

    .line 215
    const-string v14, "climate_control_plan_title"

    .line 216
    .line 217
    invoke-static {v1, v14}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 218
    .line 219
    .line 220
    move-result-object v14

    .line 221
    const/16 v27, 0x0

    .line 222
    .line 223
    const v28, 0xfff0

    .line 224
    .line 225
    .line 226
    move-object v15, v10

    .line 227
    move-object/from16 v25, v11

    .line 228
    .line 229
    iget-wide v10, v0, Ld00/q;->f:J

    .line 230
    .line 231
    move-object/from16 v18, v8

    .line 232
    .line 233
    move-object/from16 v17, v12

    .line 234
    .line 235
    move-object v8, v13

    .line 236
    const-wide/16 v12, 0x0

    .line 237
    .line 238
    move-object/from16 v19, v9

    .line 239
    .line 240
    move-object v9, v14

    .line 241
    const/4 v14, 0x0

    .line 242
    move-object/from16 v20, v15

    .line 243
    .line 244
    const/16 v21, 0x30

    .line 245
    .line 246
    const-wide/16 v15, 0x0

    .line 247
    .line 248
    move-object/from16 v22, v17

    .line 249
    .line 250
    const/16 v17, 0x0

    .line 251
    .line 252
    move-object/from16 v23, v18

    .line 253
    .line 254
    const/16 v18, 0x0

    .line 255
    .line 256
    move-object/from16 v24, v19

    .line 257
    .line 258
    move-object/from16 v26, v20

    .line 259
    .line 260
    const-wide/16 v19, 0x0

    .line 261
    .line 262
    move/from16 v29, v21

    .line 263
    .line 264
    const/16 v21, 0x0

    .line 265
    .line 266
    move-object/from16 v30, v22

    .line 267
    .line 268
    const/16 v22, 0x0

    .line 269
    .line 270
    move-object/from16 v31, v23

    .line 271
    .line 272
    const/16 v23, 0x0

    .line 273
    .line 274
    move-object/from16 v32, v24

    .line 275
    .line 276
    const/16 v24, 0x0

    .line 277
    .line 278
    move-object/from16 v33, v26

    .line 279
    .line 280
    const/16 v26, 0x180

    .line 281
    .line 282
    move-object/from16 v35, v6

    .line 283
    .line 284
    move/from16 v6, v29

    .line 285
    .line 286
    move-object/from16 v34, v31

    .line 287
    .line 288
    move-object/from16 v29, v4

    .line 289
    .line 290
    move-object/from16 v4, v30

    .line 291
    .line 292
    invoke-static/range {v7 .. v28}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 293
    .line 294
    .line 295
    move-wide/from16 v30, v10

    .line 296
    .line 297
    move-object/from16 v11, v25

    .line 298
    .line 299
    float-to-double v7, v2

    .line 300
    const-wide/16 v36, 0x0

    .line 301
    .line 302
    cmpl-double v7, v7, v36

    .line 303
    .line 304
    const-string v38, "invalid weight; must be greater than zero"

    .line 305
    .line 306
    if-lez v7, :cond_7

    .line 307
    .line 308
    goto :goto_3

    .line 309
    :cond_7
    invoke-static/range {v38 .. v38}, Ll1/a;->a(Ljava/lang/String;)V

    .line 310
    .line 311
    .line 312
    :goto_3
    new-instance v7, Landroidx/compose/foundation/layout/LayoutWeightElement;

    .line 313
    .line 314
    const v39, 0x7f7fffff    # Float.MAX_VALUE

    .line 315
    .line 316
    .line 317
    cmpl-float v8, v2, v39

    .line 318
    .line 319
    if-lez v8, :cond_8

    .line 320
    .line 321
    move/from16 v8, v39

    .line 322
    .line 323
    :goto_4
    const/4 v14, 0x1

    .line 324
    goto :goto_5

    .line 325
    :cond_8
    move v8, v2

    .line 326
    goto :goto_4

    .line 327
    :goto_5
    invoke-direct {v7, v8, v14}, Landroidx/compose/foundation/layout/LayoutWeightElement;-><init>(FZ)V

    .line 328
    .line 329
    .line 330
    invoke-static {v11, v7}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 331
    .line 332
    .line 333
    iget-boolean v7, v5, Lc00/m1;->h:Z

    .line 334
    .line 335
    iget-boolean v9, v5, Lc00/m1;->i:Z

    .line 336
    .line 337
    const-string v8, "climate_control_plan_switch"

    .line 338
    .line 339
    invoke-static {v1, v8}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 340
    .line 341
    .line 342
    move-result-object v8

    .line 343
    const/16 v12, 0x30

    .line 344
    .line 345
    const/4 v13, 0x0

    .line 346
    iget-object v10, v0, Ld00/q;->g:Lay0/k;

    .line 347
    .line 348
    invoke-static/range {v7 .. v13}, Li91/y3;->b(ZLx2/s;ZLay0/k;Ll2/o;II)V

    .line 349
    .line 350
    .line 351
    invoke-virtual {v11, v14}, Ll2/t;->q(Z)V

    .line 352
    .line 353
    .line 354
    invoke-static {v11}, Llp/nb;->b(Ll2/o;)Lj91/c;

    .line 355
    .line 356
    .line 357
    move-result-object v7

    .line 358
    iget v7, v7, Lj91/c;->b:F

    .line 359
    .line 360
    invoke-static {v1, v7}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 361
    .line 362
    .line 363
    move-result-object v7

    .line 364
    invoke-static {v11, v7}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 365
    .line 366
    .line 367
    iget-object v7, v5, Lc00/m1;->c:Ljava/lang/String;

    .line 368
    .line 369
    invoke-static {v11}, Llp/nb;->c(Ll2/o;)Lj91/f;

    .line 370
    .line 371
    .line 372
    move-result-object v8

    .line 373
    invoke-virtual {v8}, Lj91/f;->k()Lg4/p0;

    .line 374
    .line 375
    .line 376
    move-result-object v8

    .line 377
    const-string v9, "climate_control_plan_time"

    .line 378
    .line 379
    invoke-static {v1, v9}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 380
    .line 381
    .line 382
    move-result-object v9

    .line 383
    const/16 v27, 0x0

    .line 384
    .line 385
    const v28, 0xfff0

    .line 386
    .line 387
    .line 388
    move-object/from16 v25, v11

    .line 389
    .line 390
    iget-wide v10, v0, Ld00/q;->e:J

    .line 391
    .line 392
    const-wide/16 v12, 0x0

    .line 393
    .line 394
    const/4 v14, 0x0

    .line 395
    const-wide/16 v15, 0x0

    .line 396
    .line 397
    const/16 v17, 0x0

    .line 398
    .line 399
    const/16 v18, 0x0

    .line 400
    .line 401
    const-wide/16 v19, 0x0

    .line 402
    .line 403
    const/16 v21, 0x0

    .line 404
    .line 405
    const/16 v22, 0x0

    .line 406
    .line 407
    const/16 v23, 0x0

    .line 408
    .line 409
    const/16 v24, 0x0

    .line 410
    .line 411
    const/16 v26, 0x180

    .line 412
    .line 413
    invoke-static/range {v7 .. v28}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 414
    .line 415
    .line 416
    move-object/from16 v11, v25

    .line 417
    .line 418
    iget-object v7, v5, Lc00/m1;->e:Ljava/lang/String;

    .line 419
    .line 420
    const v8, 0x725f5d1b

    .line 421
    .line 422
    .line 423
    invoke-virtual {v11, v8}, Ll2/t;->Y(I)V

    .line 424
    .line 425
    .line 426
    invoke-static {v11}, Llp/nb;->b(Ll2/o;)Lj91/c;

    .line 427
    .line 428
    .line 429
    move-result-object v8

    .line 430
    iget v8, v8, Lj91/c;->c:F

    .line 431
    .line 432
    invoke-static {v1, v8}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 433
    .line 434
    .line 435
    move-result-object v8

    .line 436
    invoke-static {v11, v8}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 437
    .line 438
    .line 439
    invoke-static {v11}, Llp/nb;->c(Ll2/o;)Lj91/f;

    .line 440
    .line 441
    .line 442
    move-result-object v8

    .line 443
    invoke-virtual {v8}, Lj91/f;->a()Lg4/p0;

    .line 444
    .line 445
    .line 446
    move-result-object v8

    .line 447
    const-string v9, "climate_control_plan_frequency"

    .line 448
    .line 449
    invoke-static {v1, v9}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 450
    .line 451
    .line 452
    move-result-object v9

    .line 453
    move-wide/from16 v10, v30

    .line 454
    .line 455
    invoke-static/range {v7 .. v28}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 456
    .line 457
    .line 458
    move-object/from16 v11, v25

    .line 459
    .line 460
    const/4 v7, 0x0

    .line 461
    invoke-virtual {v11, v7}, Ll2/t;->q(Z)V

    .line 462
    .line 463
    .line 464
    invoke-static {v11}, Llp/nb;->b(Ll2/o;)Lj91/c;

    .line 465
    .line 466
    .line 467
    move-result-object v7

    .line 468
    iget v7, v7, Lj91/c;->c:F

    .line 469
    .line 470
    invoke-static {v1, v7}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 471
    .line 472
    .line 473
    move-result-object v7

    .line 474
    invoke-static {v11, v7}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 475
    .line 476
    .line 477
    invoke-static {v4, v3, v11, v6}, Lk1/e1;->a(Lk1/g;Lx2/i;Ll2/o;I)Lk1/g1;

    .line 478
    .line 479
    .line 480
    move-result-object v3

    .line 481
    iget-wide v6, v11, Ll2/t;->T:J

    .line 482
    .line 483
    invoke-static {v6, v7}, Ljava/lang/Long;->hashCode(J)I

    .line 484
    .line 485
    .line 486
    move-result v4

    .line 487
    invoke-virtual {v11}, Ll2/t;->m()Ll2/p1;

    .line 488
    .line 489
    .line 490
    move-result-object v6

    .line 491
    invoke-static {v11, v1}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 492
    .line 493
    .line 494
    move-result-object v7

    .line 495
    invoke-virtual {v11}, Ll2/t;->c0()V

    .line 496
    .line 497
    .line 498
    iget-boolean v8, v11, Ll2/t;->S:Z

    .line 499
    .line 500
    if-eqz v8, :cond_9

    .line 501
    .line 502
    move-object/from16 v8, v32

    .line 503
    .line 504
    invoke-virtual {v11, v8}, Ll2/t;->l(Lay0/a;)V

    .line 505
    .line 506
    .line 507
    :goto_6
    move-object/from16 v15, v33

    .line 508
    .line 509
    goto :goto_7

    .line 510
    :cond_9
    invoke-virtual {v11}, Ll2/t;->m0()V

    .line 511
    .line 512
    .line 513
    goto :goto_6

    .line 514
    :goto_7
    invoke-static {v15, v3, v11}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 515
    .line 516
    .line 517
    move-object/from16 v3, v29

    .line 518
    .line 519
    invoke-static {v3, v6, v11}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 520
    .line 521
    .line 522
    iget-boolean v3, v11, Ll2/t;->S:Z

    .line 523
    .line 524
    if-nez v3, :cond_a

    .line 525
    .line 526
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 527
    .line 528
    .line 529
    move-result-object v3

    .line 530
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 531
    .line 532
    .line 533
    move-result-object v6

    .line 534
    invoke-static {v3, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 535
    .line 536
    .line 537
    move-result v3

    .line 538
    if-nez v3, :cond_b

    .line 539
    .line 540
    :cond_a
    move-object/from16 v3, v34

    .line 541
    .line 542
    goto :goto_9

    .line 543
    :cond_b
    :goto_8
    move-object/from16 v6, v35

    .line 544
    .line 545
    goto :goto_a

    .line 546
    :goto_9
    invoke-static {v4, v11, v4, v3}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 547
    .line 548
    .line 549
    goto :goto_8

    .line 550
    :goto_a
    invoke-static {v6, v7, v11}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 551
    .line 552
    .line 553
    const/16 v3, 0x14

    .line 554
    .line 555
    int-to-float v3, v3

    .line 556
    invoke-static {v1, v3}, Landroidx/compose/foundation/layout/d;->n(Lx2/s;F)Lx2/s;

    .line 557
    .line 558
    .line 559
    move-result-object v9

    .line 560
    const v3, 0x7f0803ad

    .line 561
    .line 562
    .line 563
    const/4 v7, 0x0

    .line 564
    invoke-static {v3, v7, v11}, Ljp/fa;->b(IILl2/o;)Li3/c;

    .line 565
    .line 566
    .line 567
    move-result-object v3

    .line 568
    const/16 v13, 0x1b0

    .line 569
    .line 570
    const/4 v14, 0x0

    .line 571
    const/4 v8, 0x0

    .line 572
    move-object v7, v3

    .line 573
    move-object v12, v11

    .line 574
    move-wide/from16 v10, v30

    .line 575
    .line 576
    invoke-static/range {v7 .. v14}, Lh2/f5;->a(Li3/c;Ljava/lang/String;Lx2/s;JLl2/o;II)V

    .line 577
    .line 578
    .line 579
    move-object v11, v12

    .line 580
    invoke-static {v11}, Llp/nb;->b(Ll2/o;)Lj91/c;

    .line 581
    .line 582
    .line 583
    move-result-object v3

    .line 584
    iget v3, v3, Lj91/c;->b:F

    .line 585
    .line 586
    invoke-static {v1, v3}, Landroidx/compose/foundation/layout/d;->r(Lx2/s;F)Lx2/s;

    .line 587
    .line 588
    .line 589
    move-result-object v3

    .line 590
    invoke-static {v11, v3}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 591
    .line 592
    .line 593
    iget-object v7, v5, Lc00/m1;->d:Ljava/lang/String;

    .line 594
    .line 595
    invoke-static {v11}, Llp/nb;->c(Ll2/o;)Lj91/f;

    .line 596
    .line 597
    .line 598
    move-result-object v3

    .line 599
    invoke-virtual {v3}, Lj91/f;->e()Lg4/p0;

    .line 600
    .line 601
    .line 602
    move-result-object v8

    .line 603
    const-string v3, "climate_control_plan_temperature"

    .line 604
    .line 605
    invoke-static {v1, v3}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 606
    .line 607
    .line 608
    move-result-object v9

    .line 609
    const/16 v27, 0x0

    .line 610
    .line 611
    const v28, 0xfff0

    .line 612
    .line 613
    .line 614
    const-wide/16 v12, 0x0

    .line 615
    .line 616
    const/4 v14, 0x0

    .line 617
    const-wide/16 v15, 0x0

    .line 618
    .line 619
    const/16 v17, 0x0

    .line 620
    .line 621
    const/16 v18, 0x0

    .line 622
    .line 623
    const-wide/16 v19, 0x0

    .line 624
    .line 625
    const/16 v21, 0x0

    .line 626
    .line 627
    const/16 v22, 0x0

    .line 628
    .line 629
    const/16 v23, 0x0

    .line 630
    .line 631
    const/16 v24, 0x0

    .line 632
    .line 633
    const/16 v26, 0x180

    .line 634
    .line 635
    move-object/from16 v25, v11

    .line 636
    .line 637
    move-wide/from16 v10, v30

    .line 638
    .line 639
    invoke-static/range {v7 .. v28}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 640
    .line 641
    .line 642
    move-object/from16 v12, v25

    .line 643
    .line 644
    invoke-static {v12}, Llp/nb;->b(Ll2/o;)Lj91/c;

    .line 645
    .line 646
    .line 647
    move-result-object v3

    .line 648
    iget v3, v3, Lj91/c;->b:F

    .line 649
    .line 650
    invoke-static {v1, v3}, Landroidx/compose/foundation/layout/d;->r(Lx2/s;F)Lx2/s;

    .line 651
    .line 652
    .line 653
    move-result-object v3

    .line 654
    invoke-static {v12, v3}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 655
    .line 656
    .line 657
    iget-object v7, v5, Lc00/m1;->f:Ljava/lang/String;

    .line 658
    .line 659
    if-nez v7, :cond_c

    .line 660
    .line 661
    const v0, -0x2827c44d

    .line 662
    .line 663
    .line 664
    invoke-virtual {v12, v0}, Ll2/t;->Y(I)V

    .line 665
    .line 666
    .line 667
    const/4 v7, 0x0

    .line 668
    invoke-virtual {v12, v7}, Ll2/t;->q(Z)V

    .line 669
    .line 670
    .line 671
    move-object v11, v12

    .line 672
    :goto_b
    const/4 v14, 0x1

    .line 673
    goto/16 :goto_f

    .line 674
    .line 675
    :cond_c
    const v3, -0x2827c44c

    .line 676
    .line 677
    .line 678
    invoke-virtual {v12, v3}, Ll2/t;->Y(I)V

    .line 679
    .line 680
    .line 681
    float-to-double v3, v2

    .line 682
    cmpl-double v3, v3, v36

    .line 683
    .line 684
    if-lez v3, :cond_d

    .line 685
    .line 686
    goto :goto_c

    .line 687
    :cond_d
    invoke-static/range {v38 .. v38}, Ll1/a;->a(Ljava/lang/String;)V

    .line 688
    .line 689
    .line 690
    :goto_c
    new-instance v3, Landroidx/compose/foundation/layout/LayoutWeightElement;

    .line 691
    .line 692
    cmpl-float v4, v2, v39

    .line 693
    .line 694
    if-lez v4, :cond_e

    .line 695
    .line 696
    move/from16 v2, v39

    .line 697
    .line 698
    :cond_e
    const/4 v14, 0x1

    .line 699
    invoke-direct {v3, v2, v14}, Landroidx/compose/foundation/layout/LayoutWeightElement;-><init>(FZ)V

    .line 700
    .line 701
    .line 702
    invoke-static {v12, v3}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 703
    .line 704
    .line 705
    invoke-static {v12}, Llp/nb;->c(Ll2/o;)Lj91/f;

    .line 706
    .line 707
    .line 708
    move-result-object v2

    .line 709
    invoke-virtual {v2}, Lj91/f;->a()Lg4/p0;

    .line 710
    .line 711
    .line 712
    move-result-object v8

    .line 713
    iget-boolean v0, v0, Ld00/q;->h:Z

    .line 714
    .line 715
    if-eqz v0, :cond_f

    .line 716
    .line 717
    const v0, -0x64da106b

    .line 718
    .line 719
    .line 720
    invoke-virtual {v12, v0}, Ll2/t;->Y(I)V

    .line 721
    .line 722
    .line 723
    invoke-static {v12}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 724
    .line 725
    .line 726
    move-result-object v0

    .line 727
    invoke-virtual {v0}, Lj91/e;->s()J

    .line 728
    .line 729
    .line 730
    move-result-wide v10

    .line 731
    const/4 v0, 0x0

    .line 732
    :goto_d
    invoke-virtual {v12, v0}, Ll2/t;->q(Z)V

    .line 733
    .line 734
    .line 735
    goto :goto_e

    .line 736
    :cond_f
    const/4 v0, 0x0

    .line 737
    const v2, -0x64da0e06

    .line 738
    .line 739
    .line 740
    invoke-virtual {v12, v2}, Ll2/t;->Y(I)V

    .line 741
    .line 742
    .line 743
    goto :goto_d

    .line 744
    :goto_e
    const-string v0, "climate_control_plan_state"

    .line 745
    .line 746
    invoke-static {v1, v0}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 747
    .line 748
    .line 749
    move-result-object v9

    .line 750
    const/16 v27, 0x0

    .line 751
    .line 752
    const v28, 0xfff0

    .line 753
    .line 754
    .line 755
    move-object/from16 v25, v12

    .line 756
    .line 757
    const-wide/16 v12, 0x0

    .line 758
    .line 759
    const/4 v14, 0x0

    .line 760
    const-wide/16 v15, 0x0

    .line 761
    .line 762
    const/16 v17, 0x0

    .line 763
    .line 764
    const/16 v18, 0x0

    .line 765
    .line 766
    const-wide/16 v19, 0x0

    .line 767
    .line 768
    const/16 v21, 0x0

    .line 769
    .line 770
    const/16 v22, 0x0

    .line 771
    .line 772
    const/16 v23, 0x0

    .line 773
    .line 774
    const/16 v24, 0x0

    .line 775
    .line 776
    const/16 v26, 0x180

    .line 777
    .line 778
    invoke-static/range {v7 .. v28}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 779
    .line 780
    .line 781
    move-object/from16 v11, v25

    .line 782
    .line 783
    const/4 v7, 0x0

    .line 784
    invoke-virtual {v11, v7}, Ll2/t;->q(Z)V

    .line 785
    .line 786
    .line 787
    goto :goto_b

    .line 788
    :goto_f
    invoke-virtual {v11, v14}, Ll2/t;->q(Z)V

    .line 789
    .line 790
    .line 791
    invoke-virtual {v11, v14}, Ll2/t;->q(Z)V

    .line 792
    .line 793
    .line 794
    goto :goto_10

    .line 795
    :cond_10
    invoke-virtual {v11}, Ll2/t;->R()V

    .line 796
    .line 797
    .line 798
    :goto_10
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 799
    .line 800
    return-object v0
.end method
