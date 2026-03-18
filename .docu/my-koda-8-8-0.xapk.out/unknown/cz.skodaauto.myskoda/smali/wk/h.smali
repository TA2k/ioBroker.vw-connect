.class public final synthetic Lwk/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lzh/a;

.field public final synthetic f:Lay0/k;


# direct methods
.method public synthetic constructor <init>(Lzh/a;Lay0/k;)V
    .locals 1

    .line 1
    const/4 v0, 0x1

    iput v0, p0, Lwk/h;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lwk/h;->e:Lzh/a;

    iput-object p2, p0, Lwk/h;->f:Lay0/k;

    return-void
.end method

.method public synthetic constructor <init>(Lzh/a;Lay0/k;II)V
    .locals 0

    .line 2
    iput p4, p0, Lwk/h;->d:I

    iput-object p1, p0, Lwk/h;->e:Lzh/a;

    iput-object p2, p0, Lwk/h;->f:Lay0/k;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lwk/h;->d:I

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
    check-cast v2, Ljava/lang/Integer;

    .line 15
    .line 16
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 17
    .line 18
    .line 19
    const/16 v2, 0x9

    .line 20
    .line 21
    invoke-static {v2}, Ll2/b;->x(I)I

    .line 22
    .line 23
    .line 24
    move-result v2

    .line 25
    iget-object v3, v0, Lwk/h;->e:Lzh/a;

    .line 26
    .line 27
    iget-object v0, v0, Lwk/h;->f:Lay0/k;

    .line 28
    .line 29
    invoke-static {v3, v0, v1, v2}, Lwk/a;->s(Lzh/a;Lay0/k;Ll2/o;I)V

    .line 30
    .line 31
    .line 32
    :goto_0
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 33
    .line 34
    return-object v0

    .line 35
    :pswitch_0
    move-object/from16 v1, p1

    .line 36
    .line 37
    check-cast v1, Ll2/o;

    .line 38
    .line 39
    move-object/from16 v2, p2

    .line 40
    .line 41
    check-cast v2, Ljava/lang/Integer;

    .line 42
    .line 43
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 44
    .line 45
    .line 46
    move-result v2

    .line 47
    and-int/lit8 v3, v2, 0x3

    .line 48
    .line 49
    const/4 v4, 0x2

    .line 50
    const/4 v5, 0x1

    .line 51
    const/4 v6, 0x0

    .line 52
    if-eq v3, v4, :cond_0

    .line 53
    .line 54
    move v3, v5

    .line 55
    goto :goto_1

    .line 56
    :cond_0
    move v3, v6

    .line 57
    :goto_1
    and-int/2addr v2, v5

    .line 58
    move-object v13, v1

    .line 59
    check-cast v13, Ll2/t;

    .line 60
    .line 61
    invoke-virtual {v13, v2, v3}, Ll2/t;->O(IZ)Z

    .line 62
    .line 63
    .line 64
    move-result v1

    .line 65
    if-eqz v1, :cond_d

    .line 66
    .line 67
    sget-object v1, Landroidx/compose/foundation/layout/d;->c:Landroidx/compose/foundation/layout/FillElement;

    .line 68
    .line 69
    const/16 v2, 0x10

    .line 70
    .line 71
    int-to-float v3, v2

    .line 72
    invoke-static {v13, v2}, Lwk/a;->x(Ll2/o;I)F

    .line 73
    .line 74
    .line 75
    move-result v4

    .line 76
    invoke-static {v1, v3, v4}, Landroidx/compose/foundation/layout/a;->n(Lx2/s;FF)Lx2/s;

    .line 77
    .line 78
    .line 79
    move-result-object v1

    .line 80
    sget-object v3, Lx2/c;->q:Lx2/h;

    .line 81
    .line 82
    sget-object v4, Lk1/j;->c:Lk1/e;

    .line 83
    .line 84
    const/16 v7, 0x36

    .line 85
    .line 86
    invoke-static {v4, v3, v13, v7}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 87
    .line 88
    .line 89
    move-result-object v3

    .line 90
    iget-wide v7, v13, Ll2/t;->T:J

    .line 91
    .line 92
    invoke-static {v7, v8}, Ljava/lang/Long;->hashCode(J)I

    .line 93
    .line 94
    .line 95
    move-result v4

    .line 96
    invoke-virtual {v13}, Ll2/t;->m()Ll2/p1;

    .line 97
    .line 98
    .line 99
    move-result-object v7

    .line 100
    invoke-static {v13, v1}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 101
    .line 102
    .line 103
    move-result-object v1

    .line 104
    sget-object v8, Lv3/k;->m1:Lv3/j;

    .line 105
    .line 106
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 107
    .line 108
    .line 109
    sget-object v8, Lv3/j;->b:Lv3/i;

    .line 110
    .line 111
    invoke-virtual {v13}, Ll2/t;->c0()V

    .line 112
    .line 113
    .line 114
    iget-boolean v9, v13, Ll2/t;->S:Z

    .line 115
    .line 116
    if-eqz v9, :cond_1

    .line 117
    .line 118
    invoke-virtual {v13, v8}, Ll2/t;->l(Lay0/a;)V

    .line 119
    .line 120
    .line 121
    goto :goto_2

    .line 122
    :cond_1
    invoke-virtual {v13}, Ll2/t;->m0()V

    .line 123
    .line 124
    .line 125
    :goto_2
    sget-object v8, Lv3/j;->g:Lv3/h;

    .line 126
    .line 127
    invoke-static {v8, v3, v13}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 128
    .line 129
    .line 130
    sget-object v3, Lv3/j;->f:Lv3/h;

    .line 131
    .line 132
    invoke-static {v3, v7, v13}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 133
    .line 134
    .line 135
    sget-object v3, Lv3/j;->j:Lv3/h;

    .line 136
    .line 137
    iget-boolean v7, v13, Ll2/t;->S:Z

    .line 138
    .line 139
    if-nez v7, :cond_2

    .line 140
    .line 141
    invoke-virtual {v13}, Ll2/t;->L()Ljava/lang/Object;

    .line 142
    .line 143
    .line 144
    move-result-object v7

    .line 145
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 146
    .line 147
    .line 148
    move-result-object v8

    .line 149
    invoke-static {v7, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 150
    .line 151
    .line 152
    move-result v7

    .line 153
    if-nez v7, :cond_3

    .line 154
    .line 155
    :cond_2
    invoke-static {v4, v13, v4, v3}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 156
    .line 157
    .line 158
    :cond_3
    sget-object v3, Lv3/j;->d:Lv3/h;

    .line 159
    .line 160
    invoke-static {v3, v1, v13}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 161
    .line 162
    .line 163
    const/16 v1, 0x20

    .line 164
    .line 165
    invoke-static {v13, v1}, Lwk/a;->x(Ll2/o;I)F

    .line 166
    .line 167
    .line 168
    move-result v3

    .line 169
    sget-object v4, Lx2/p;->b:Lx2/p;

    .line 170
    .line 171
    invoke-static {v4, v3}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 172
    .line 173
    .line 174
    move-result-object v3

    .line 175
    invoke-static {v13, v3}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 176
    .line 177
    .line 178
    iget-object v3, v0, Lwk/h;->e:Lzh/a;

    .line 179
    .line 180
    const/16 v15, 0x8

    .line 181
    .line 182
    invoke-static {v3, v13, v15}, Lwk/a;->v(Lzh/a;Ll2/o;I)V

    .line 183
    .line 184
    .line 185
    const/16 v14, 0x18

    .line 186
    .line 187
    invoke-static {v13, v14}, Lwk/a;->x(Ll2/o;I)F

    .line 188
    .line 189
    .line 190
    move-result v7

    .line 191
    invoke-static {v4, v7}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 192
    .line 193
    .line 194
    move-result-object v7

    .line 195
    invoke-static {v13, v7}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 196
    .line 197
    .line 198
    iget-object v7, v3, Lzh/a;->m:Ljava/util/ArrayList;

    .line 199
    .line 200
    invoke-static {v13}, Lzb/l;->b(Ll2/o;)Z

    .line 201
    .line 202
    .line 203
    move-result v8

    .line 204
    const/16 v9, 0xa0

    .line 205
    .line 206
    if-eqz v8, :cond_4

    .line 207
    .line 208
    int-to-double v8, v9

    .line 209
    const-wide v10, 0x3ff3333333333333L    # 1.2

    .line 210
    .line 211
    .line 212
    .line 213
    .line 214
    div-double/2addr v8, v10

    .line 215
    double-to-float v8, v8

    .line 216
    goto :goto_3

    .line 217
    :cond_4
    int-to-float v8, v9

    .line 218
    :goto_3
    invoke-static {v4, v8}, Landroidx/compose/foundation/layout/d;->n(Lx2/s;F)Lx2/s;

    .line 219
    .line 220
    .line 221
    move-result-object v9

    .line 222
    const/4 v10, 0x0

    .line 223
    const/16 v12, 0x30

    .line 224
    .line 225
    const-string v8, "wallbox_icon"

    .line 226
    .line 227
    move-object v11, v13

    .line 228
    invoke-static/range {v7 .. v12}, Lzb/b;->n(Ljava/util/ArrayList;Ljava/lang/String;Lx2/s;ZLl2/o;I)V

    .line 229
    .line 230
    .line 231
    invoke-static {v13, v2}, Lwk/a;->x(Ll2/o;I)F

    .line 232
    .line 233
    .line 234
    move-result v2

    .line 235
    invoke-static {v4, v2}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 236
    .line 237
    .line 238
    move-result-object v2

    .line 239
    invoke-static {v13, v2}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 240
    .line 241
    .line 242
    iget-boolean v7, v3, Lzh/a;->j:Z

    .line 243
    .line 244
    iget-boolean v8, v3, Lzh/a;->l:Z

    .line 245
    .line 246
    iget-boolean v9, v3, Lzh/a;->k:Z

    .line 247
    .line 248
    iget-object v2, v3, Lzh/a;->o:Lzg/i2;

    .line 249
    .line 250
    iget-object v10, v2, Lzg/i2;->a:Ljava/lang/String;

    .line 251
    .line 252
    const-string v12, "wallbox_status"

    .line 253
    .line 254
    move v2, v14

    .line 255
    const v14, 0x36000

    .line 256
    .line 257
    .line 258
    const-string v11, "wallbox_icon"

    .line 259
    .line 260
    invoke-static/range {v7 .. v14}, Llp/xe;->e(ZZZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ll2/o;I)V

    .line 261
    .line 262
    .line 263
    invoke-static {v13, v1}, Lwk/a;->x(Ll2/o;I)F

    .line 264
    .line 265
    .line 266
    move-result v7

    .line 267
    invoke-static {v4, v7}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 268
    .line 269
    .line 270
    move-result-object v7

    .line 271
    invoke-static {v13, v7}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 272
    .line 273
    .line 274
    invoke-static {v3, v13, v15}, Lwk/a;->c(Lzh/a;Ll2/o;I)V

    .line 275
    .line 276
    .line 277
    invoke-static {v13, v1}, Lwk/a;->x(Ll2/o;I)F

    .line 278
    .line 279
    .line 280
    move-result v1

    .line 281
    invoke-static {v4, v1}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 282
    .line 283
    .line 284
    move-result-object v1

    .line 285
    invoke-static {v13, v1}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 286
    .line 287
    .line 288
    const/high16 v1, 0x3f800000    # 1.0f

    .line 289
    .line 290
    float-to-double v7, v1

    .line 291
    const-wide/16 v9, 0x0

    .line 292
    .line 293
    cmpl-double v7, v7, v9

    .line 294
    .line 295
    if-lez v7, :cond_5

    .line 296
    .line 297
    goto :goto_4

    .line 298
    :cond_5
    const-string v7, "invalid weight; must be greater than zero"

    .line 299
    .line 300
    invoke-static {v7}, Ll1/a;->a(Ljava/lang/String;)V

    .line 301
    .line 302
    .line 303
    :goto_4
    invoke-static {v1, v5, v13}, Lvj/b;->u(FZLl2/t;)V

    .line 304
    .line 305
    .line 306
    iget-boolean v1, v3, Lzh/a;->c:Z

    .line 307
    .line 308
    iget-object v0, v0, Lwk/h;->f:Lay0/k;

    .line 309
    .line 310
    sget-object v7, Ll2/n;->a:Ll2/x0;

    .line 311
    .line 312
    if-eqz v1, :cond_a

    .line 313
    .line 314
    const v1, -0x135e6f45

    .line 315
    .line 316
    .line 317
    invoke-virtual {v13, v1}, Ll2/t;->Y(I)V

    .line 318
    .line 319
    .line 320
    iget-object v1, v3, Lzh/a;->d:Lgh/a;

    .line 321
    .line 322
    invoke-virtual {v13, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 323
    .line 324
    .line 325
    move-result v8

    .line 326
    invoke-virtual {v13, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 327
    .line 328
    .line 329
    move-result v9

    .line 330
    or-int/2addr v8, v9

    .line 331
    invoke-virtual {v13}, Ll2/t;->L()Ljava/lang/Object;

    .line 332
    .line 333
    .line 334
    move-result-object v9

    .line 335
    if-nez v8, :cond_6

    .line 336
    .line 337
    if-ne v9, v7, :cond_7

    .line 338
    .line 339
    :cond_6
    new-instance v9, Lwk/e;

    .line 340
    .line 341
    const/4 v8, 0x2

    .line 342
    invoke-direct {v9, v0, v3, v8}, Lwk/e;-><init>(Lay0/k;Lzh/a;I)V

    .line 343
    .line 344
    .line 345
    invoke-virtual {v13, v9}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 346
    .line 347
    .line 348
    :cond_7
    check-cast v9, Lay0/a;

    .line 349
    .line 350
    invoke-virtual {v13, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 351
    .line 352
    .line 353
    move-result v8

    .line 354
    invoke-virtual {v13, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 355
    .line 356
    .line 357
    move-result v10

    .line 358
    or-int/2addr v8, v10

    .line 359
    invoke-virtual {v13}, Ll2/t;->L()Ljava/lang/Object;

    .line 360
    .line 361
    .line 362
    move-result-object v10

    .line 363
    if-nez v8, :cond_8

    .line 364
    .line 365
    if-ne v10, v7, :cond_9

    .line 366
    .line 367
    :cond_8
    new-instance v10, Lwk/e;

    .line 368
    .line 369
    const/4 v8, 0x3

    .line 370
    invoke-direct {v10, v0, v3, v8}, Lwk/e;-><init>(Lay0/k;Lzh/a;I)V

    .line 371
    .line 372
    .line 373
    invoke-virtual {v13, v10}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 374
    .line 375
    .line 376
    :cond_9
    check-cast v10, Lay0/a;

    .line 377
    .line 378
    invoke-static {v1, v9, v10, v13, v6}, Llp/qe;->b(Lgh/a;Lay0/a;Lay0/a;Ll2/o;I)V

    .line 379
    .line 380
    .line 381
    :goto_5
    invoke-virtual {v13, v6}, Ll2/t;->q(Z)V

    .line 382
    .line 383
    .line 384
    goto :goto_6

    .line 385
    :cond_a
    const v1, -0x13f9b299

    .line 386
    .line 387
    .line 388
    invoke-virtual {v13, v1}, Ll2/t;->Y(I)V

    .line 389
    .line 390
    .line 391
    goto :goto_5

    .line 392
    :goto_6
    const/16 v1, 0x14

    .line 393
    .line 394
    invoke-static {v13, v1}, Lwk/a;->x(Ll2/o;I)F

    .line 395
    .line 396
    .line 397
    move-result v1

    .line 398
    invoke-static {v4, v1}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 399
    .line 400
    .line 401
    move-result-object v1

    .line 402
    invoke-static {v13, v1}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 403
    .line 404
    .line 405
    invoke-virtual {v13, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 406
    .line 407
    .line 408
    move-result v1

    .line 409
    invoke-virtual {v13, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 410
    .line 411
    .line 412
    move-result v8

    .line 413
    or-int/2addr v1, v8

    .line 414
    invoke-virtual {v13}, Ll2/t;->L()Ljava/lang/Object;

    .line 415
    .line 416
    .line 417
    move-result-object v8

    .line 418
    if-nez v1, :cond_b

    .line 419
    .line 420
    if-ne v8, v7, :cond_c

    .line 421
    .line 422
    :cond_b
    new-instance v8, Lwk/e;

    .line 423
    .line 424
    const/4 v1, 0x0

    .line 425
    invoke-direct {v8, v0, v3, v1}, Lwk/e;-><init>(Lay0/k;Lzh/a;I)V

    .line 426
    .line 427
    .line 428
    invoke-virtual {v13, v8}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 429
    .line 430
    .line 431
    :cond_c
    check-cast v8, Lay0/a;

    .line 432
    .line 433
    invoke-static {v8, v13, v6}, Lwk/a;->t(Lay0/a;Ll2/o;I)V

    .line 434
    .line 435
    .line 436
    invoke-static {v13, v2}, Lwk/a;->x(Ll2/o;I)F

    .line 437
    .line 438
    .line 439
    move-result v0

    .line 440
    invoke-static {v4, v0}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 441
    .line 442
    .line 443
    move-result-object v0

    .line 444
    invoke-static {v13, v0}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 445
    .line 446
    .line 447
    invoke-virtual {v13, v5}, Ll2/t;->q(Z)V

    .line 448
    .line 449
    .line 450
    goto :goto_7

    .line 451
    :cond_d
    invoke-virtual {v13}, Ll2/t;->R()V

    .line 452
    .line 453
    .line 454
    :goto_7
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 455
    .line 456
    return-object v0

    .line 457
    :pswitch_1
    move-object/from16 v1, p1

    .line 458
    .line 459
    check-cast v1, Ll2/o;

    .line 460
    .line 461
    move-object/from16 v2, p2

    .line 462
    .line 463
    check-cast v2, Ljava/lang/Integer;

    .line 464
    .line 465
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 466
    .line 467
    .line 468
    const/16 v2, 0x9

    .line 469
    .line 470
    invoke-static {v2}, Ll2/b;->x(I)I

    .line 471
    .line 472
    .line 473
    move-result v2

    .line 474
    iget-object v3, v0, Lwk/h;->e:Lzh/a;

    .line 475
    .line 476
    iget-object v0, v0, Lwk/h;->f:Lay0/k;

    .line 477
    .line 478
    invoke-static {v3, v0, v1, v2}, Lwk/a;->d(Lzh/a;Lay0/k;Ll2/o;I)V

    .line 479
    .line 480
    .line 481
    goto/16 :goto_0

    .line 482
    .line 483
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
