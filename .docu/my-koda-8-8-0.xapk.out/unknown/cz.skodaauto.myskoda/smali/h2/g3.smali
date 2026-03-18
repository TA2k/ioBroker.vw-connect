.class public final Lh2/g3;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Lay0/a;

.field public final synthetic e:Z

.field public final synthetic f:Lay0/a;

.field public final synthetic g:Z


# direct methods
.method public constructor <init>(Lay0/a;Lay0/a;ZZ)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh2/g3;->d:Lay0/a;

    .line 5
    .line 6
    iput-boolean p3, p0, Lh2/g3;->e:Z

    .line 7
    .line 8
    iput-object p2, p0, Lh2/g3;->f:Lay0/a;

    .line 9
    .line 10
    iput-boolean p4, p0, Lh2/g3;->g:Z

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 27

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
    move-object v12, v1

    .line 27
    check-cast v12, Ll2/t;

    .line 28
    .line 29
    invoke-virtual {v12, v2, v3}, Ll2/t;->O(IZ)Z

    .line 30
    .line 31
    .line 32
    move-result v1

    .line 33
    if-eqz v1, :cond_6

    .line 34
    .line 35
    sget-object v1, Lk1/j;->a:Lk1/c;

    .line 36
    .line 37
    sget-object v2, Lx2/c;->m:Lx2/i;

    .line 38
    .line 39
    invoke-static {v1, v2, v12, v6}, Lk1/e1;->a(Lk1/g;Lx2/i;Ll2/o;I)Lk1/g1;

    .line 40
    .line 41
    .line 42
    move-result-object v1

    .line 43
    iget-wide v2, v12, Ll2/t;->T:J

    .line 44
    .line 45
    invoke-static {v2, v3}, Ljava/lang/Long;->hashCode(J)I

    .line 46
    .line 47
    .line 48
    move-result v2

    .line 49
    invoke-virtual {v12}, Ll2/t;->m()Ll2/p1;

    .line 50
    .line 51
    .line 52
    move-result-object v3

    .line 53
    sget-object v4, Lx2/p;->b:Lx2/p;

    .line 54
    .line 55
    invoke-static {v12, v4}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 56
    .line 57
    .line 58
    move-result-object v4

    .line 59
    sget-object v6, Lv3/k;->m1:Lv3/j;

    .line 60
    .line 61
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 62
    .line 63
    .line 64
    sget-object v6, Lv3/j;->b:Lv3/i;

    .line 65
    .line 66
    invoke-virtual {v12}, Ll2/t;->c0()V

    .line 67
    .line 68
    .line 69
    iget-boolean v7, v12, Ll2/t;->S:Z

    .line 70
    .line 71
    if-eqz v7, :cond_1

    .line 72
    .line 73
    invoke-virtual {v12, v6}, Ll2/t;->l(Lay0/a;)V

    .line 74
    .line 75
    .line 76
    goto :goto_1

    .line 77
    :cond_1
    invoke-virtual {v12}, Ll2/t;->m0()V

    .line 78
    .line 79
    .line 80
    :goto_1
    sget-object v6, Lv3/j;->g:Lv3/h;

    .line 81
    .line 82
    invoke-static {v6, v1, v12}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 83
    .line 84
    .line 85
    sget-object v1, Lv3/j;->f:Lv3/h;

    .line 86
    .line 87
    invoke-static {v1, v3, v12}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 88
    .line 89
    .line 90
    sget-object v1, Lv3/j;->j:Lv3/h;

    .line 91
    .line 92
    iget-boolean v3, v12, Ll2/t;->S:Z

    .line 93
    .line 94
    if-nez v3, :cond_2

    .line 95
    .line 96
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 97
    .line 98
    .line 99
    move-result-object v3

    .line 100
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 101
    .line 102
    .line 103
    move-result-object v6

    .line 104
    invoke-static {v3, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 105
    .line 106
    .line 107
    move-result v3

    .line 108
    if-nez v3, :cond_3

    .line 109
    .line 110
    :cond_2
    invoke-static {v2, v12, v2, v1}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 111
    .line 112
    .line 113
    :cond_3
    sget-object v1, Lv3/j;->d:Lv3/h;

    .line 114
    .line 115
    invoke-static {v1, v4, v12}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 116
    .line 117
    .line 118
    sget-object v1, Li2/a1;->b:Lj3/f;

    .line 119
    .line 120
    const v2, -0x404b851f    # -1.41f

    .line 121
    .line 122
    .line 123
    const/high16 v3, -0x3f400000    # -6.0f

    .line 124
    .line 125
    const/high16 v4, 0x41400000    # 12.0f

    .line 126
    .line 127
    const v6, 0x4184b852    # 16.59f

    .line 128
    .line 129
    .line 130
    const/16 v15, 0x20

    .line 131
    .line 132
    const/high16 v7, 0x40c00000    # 6.0f

    .line 133
    .line 134
    if-eqz v1, :cond_4

    .line 135
    .line 136
    :goto_2
    move-object v8, v1

    .line 137
    goto/16 :goto_3

    .line 138
    .line 139
    :cond_4
    new-instance v16, Lj3/e;

    .line 140
    .line 141
    const/16 v24, 0x0

    .line 142
    .line 143
    const/16 v26, 0x60

    .line 144
    .line 145
    const-string v17, "AutoMirrored.Filled.KeyboardArrowLeft"

    .line 146
    .line 147
    const/high16 v18, 0x41c00000    # 24.0f

    .line 148
    .line 149
    const/high16 v19, 0x41c00000    # 24.0f

    .line 150
    .line 151
    const/high16 v20, 0x41c00000    # 24.0f

    .line 152
    .line 153
    const/high16 v21, 0x41c00000    # 24.0f

    .line 154
    .line 155
    const-wide/16 v22, 0x0

    .line 156
    .line 157
    const/16 v25, 0x1

    .line 158
    .line 159
    invoke-direct/range {v16 .. v26}, Lj3/e;-><init>(Ljava/lang/String;FFFFJIZI)V

    .line 160
    .line 161
    .line 162
    move-object/from16 v1, v16

    .line 163
    .line 164
    sget v8, Lj3/h0;->a:I

    .line 165
    .line 166
    new-instance v8, Le3/p0;

    .line 167
    .line 168
    sget-wide v9, Le3/s;->b:J

    .line 169
    .line 170
    invoke-direct {v8, v9, v10}, Le3/p0;-><init>(J)V

    .line 171
    .line 172
    .line 173
    new-instance v9, Ljava/util/ArrayList;

    .line 174
    .line 175
    invoke-direct {v9, v15}, Ljava/util/ArrayList;-><init>(I)V

    .line 176
    .line 177
    .line 178
    new-instance v10, Lj3/n;

    .line 179
    .line 180
    const v11, 0x41768f5c    # 15.41f

    .line 181
    .line 182
    .line 183
    invoke-direct {v10, v11, v6}, Lj3/n;-><init>(FF)V

    .line 184
    .line 185
    .line 186
    invoke-virtual {v9, v10}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 187
    .line 188
    .line 189
    new-instance v10, Lj3/m;

    .line 190
    .line 191
    const v11, 0x412d47ae    # 10.83f

    .line 192
    .line 193
    .line 194
    invoke-direct {v10, v11, v4}, Lj3/m;-><init>(FF)V

    .line 195
    .line 196
    .line 197
    invoke-virtual {v9, v10}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 198
    .line 199
    .line 200
    new-instance v10, Lj3/u;

    .line 201
    .line 202
    const v11, 0x40928f5c    # 4.58f

    .line 203
    .line 204
    .line 205
    const v13, -0x3f6d1eb8    # -4.59f

    .line 206
    .line 207
    .line 208
    invoke-direct {v10, v11, v13}, Lj3/u;-><init>(FF)V

    .line 209
    .line 210
    .line 211
    invoke-virtual {v9, v10}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 212
    .line 213
    .line 214
    new-instance v10, Lj3/m;

    .line 215
    .line 216
    const/high16 v11, 0x41600000    # 14.0f

    .line 217
    .line 218
    invoke-direct {v10, v11, v7}, Lj3/m;-><init>(FF)V

    .line 219
    .line 220
    .line 221
    invoke-virtual {v9, v10}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 222
    .line 223
    .line 224
    new-instance v10, Lj3/u;

    .line 225
    .line 226
    invoke-direct {v10, v3, v7}, Lj3/u;-><init>(FF)V

    .line 227
    .line 228
    .line 229
    invoke-virtual {v9, v10}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 230
    .line 231
    .line 232
    new-instance v10, Lj3/u;

    .line 233
    .line 234
    invoke-direct {v10, v7, v7}, Lj3/u;-><init>(FF)V

    .line 235
    .line 236
    .line 237
    invoke-virtual {v9, v10}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 238
    .line 239
    .line 240
    new-instance v10, Lj3/u;

    .line 241
    .line 242
    const v11, 0x3fb47ae1    # 1.41f

    .line 243
    .line 244
    .line 245
    invoke-direct {v10, v11, v2}, Lj3/u;-><init>(FF)V

    .line 246
    .line 247
    .line 248
    invoke-virtual {v9, v10}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 249
    .line 250
    .line 251
    sget-object v10, Lj3/j;->c:Lj3/j;

    .line 252
    .line 253
    invoke-virtual {v9, v10}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 254
    .line 255
    .line 256
    invoke-static {v1, v9, v8}, Lj3/e;->a(Lj3/e;Ljava/util/ArrayList;Le3/p0;)V

    .line 257
    .line 258
    .line 259
    invoke-virtual {v1}, Lj3/e;->b()Lj3/f;

    .line 260
    .line 261
    .line 262
    move-result-object v1

    .line 263
    sput-object v1, Li2/a1;->b:Lj3/f;

    .line 264
    .line 265
    goto/16 :goto_2

    .line 266
    .line 267
    :goto_3
    const v1, 0x7f1205a5

    .line 268
    .line 269
    .line 270
    invoke-static {v12, v1}, Li2/a1;->k(Ll2/o;I)Ljava/lang/String;

    .line 271
    .line 272
    .line 273
    move-result-object v9

    .line 274
    const/4 v13, 0x0

    .line 275
    const/16 v14, 0x8

    .line 276
    .line 277
    move v1, v7

    .line 278
    iget-object v7, v0, Lh2/g3;->d:Lay0/a;

    .line 279
    .line 280
    const/4 v10, 0x0

    .line 281
    iget-boolean v11, v0, Lh2/g3;->e:Z

    .line 282
    .line 283
    invoke-static/range {v7 .. v14}, Lh2/m3;->h(Lay0/a;Lj3/f;Ljava/lang/String;Lx2/s;ZLl2/o;II)V

    .line 284
    .line 285
    .line 286
    sget-object v7, Li2/a1;->c:Lj3/f;

    .line 287
    .line 288
    if-eqz v7, :cond_5

    .line 289
    .line 290
    :goto_4
    move-object v8, v7

    .line 291
    goto :goto_5

    .line 292
    :cond_5
    new-instance v16, Lj3/e;

    .line 293
    .line 294
    const/16 v24, 0x0

    .line 295
    .line 296
    const/16 v26, 0x60

    .line 297
    .line 298
    const-string v17, "AutoMirrored.Filled.KeyboardArrowRight"

    .line 299
    .line 300
    const/high16 v18, 0x41c00000    # 24.0f

    .line 301
    .line 302
    const/high16 v19, 0x41c00000    # 24.0f

    .line 303
    .line 304
    const/high16 v20, 0x41c00000    # 24.0f

    .line 305
    .line 306
    const/high16 v21, 0x41c00000    # 24.0f

    .line 307
    .line 308
    const-wide/16 v22, 0x0

    .line 309
    .line 310
    const/16 v25, 0x1

    .line 311
    .line 312
    invoke-direct/range {v16 .. v26}, Lj3/e;-><init>(Ljava/lang/String;FFFFJIZI)V

    .line 313
    .line 314
    .line 315
    move-object/from16 v7, v16

    .line 316
    .line 317
    sget v8, Lj3/h0;->a:I

    .line 318
    .line 319
    new-instance v8, Le3/p0;

    .line 320
    .line 321
    sget-wide v9, Le3/s;->b:J

    .line 322
    .line 323
    invoke-direct {v8, v9, v10}, Le3/p0;-><init>(J)V

    .line 324
    .line 325
    .line 326
    new-instance v9, Ljava/util/ArrayList;

    .line 327
    .line 328
    invoke-direct {v9, v15}, Ljava/util/ArrayList;-><init>(I)V

    .line 329
    .line 330
    .line 331
    new-instance v10, Lj3/n;

    .line 332
    .line 333
    const v11, 0x410970a4    # 8.59f

    .line 334
    .line 335
    .line 336
    invoke-direct {v10, v11, v6}, Lj3/n;-><init>(FF)V

    .line 337
    .line 338
    .line 339
    invoke-virtual {v9, v10}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 340
    .line 341
    .line 342
    new-instance v6, Lj3/m;

    .line 343
    .line 344
    const v10, 0x4152b852    # 13.17f

    .line 345
    .line 346
    .line 347
    invoke-direct {v6, v10, v4}, Lj3/m;-><init>(FF)V

    .line 348
    .line 349
    .line 350
    invoke-virtual {v9, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 351
    .line 352
    .line 353
    new-instance v4, Lj3/m;

    .line 354
    .line 355
    const v6, 0x40ed1eb8    # 7.41f

    .line 356
    .line 357
    .line 358
    invoke-direct {v4, v11, v6}, Lj3/m;-><init>(FF)V

    .line 359
    .line 360
    .line 361
    invoke-virtual {v9, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 362
    .line 363
    .line 364
    new-instance v4, Lj3/m;

    .line 365
    .line 366
    const/high16 v6, 0x41200000    # 10.0f

    .line 367
    .line 368
    invoke-direct {v4, v6, v1}, Lj3/m;-><init>(FF)V

    .line 369
    .line 370
    .line 371
    invoke-virtual {v9, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 372
    .line 373
    .line 374
    new-instance v4, Lj3/u;

    .line 375
    .line 376
    invoke-direct {v4, v1, v1}, Lj3/u;-><init>(FF)V

    .line 377
    .line 378
    .line 379
    invoke-virtual {v9, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 380
    .line 381
    .line 382
    new-instance v4, Lj3/u;

    .line 383
    .line 384
    invoke-direct {v4, v3, v1}, Lj3/u;-><init>(FF)V

    .line 385
    .line 386
    .line 387
    invoke-virtual {v9, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 388
    .line 389
    .line 390
    new-instance v1, Lj3/u;

    .line 391
    .line 392
    invoke-direct {v1, v2, v2}, Lj3/u;-><init>(FF)V

    .line 393
    .line 394
    .line 395
    invoke-virtual {v9, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 396
    .line 397
    .line 398
    sget-object v1, Lj3/j;->c:Lj3/j;

    .line 399
    .line 400
    invoke-virtual {v9, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 401
    .line 402
    .line 403
    invoke-static {v7, v9, v8}, Lj3/e;->a(Lj3/e;Ljava/util/ArrayList;Le3/p0;)V

    .line 404
    .line 405
    .line 406
    invoke-virtual {v7}, Lj3/e;->b()Lj3/f;

    .line 407
    .line 408
    .line 409
    move-result-object v7

    .line 410
    sput-object v7, Li2/a1;->c:Lj3/f;

    .line 411
    .line 412
    goto :goto_4

    .line 413
    :goto_5
    const v1, 0x7f1205a4

    .line 414
    .line 415
    .line 416
    invoke-static {v12, v1}, Li2/a1;->k(Ll2/o;I)Ljava/lang/String;

    .line 417
    .line 418
    .line 419
    move-result-object v9

    .line 420
    const/4 v13, 0x0

    .line 421
    const/16 v14, 0x8

    .line 422
    .line 423
    iget-object v7, v0, Lh2/g3;->f:Lay0/a;

    .line 424
    .line 425
    const/4 v10, 0x0

    .line 426
    iget-boolean v11, v0, Lh2/g3;->g:Z

    .line 427
    .line 428
    invoke-static/range {v7 .. v14}, Lh2/m3;->h(Lay0/a;Lj3/f;Ljava/lang/String;Lx2/s;ZLl2/o;II)V

    .line 429
    .line 430
    .line 431
    invoke-virtual {v12, v5}, Ll2/t;->q(Z)V

    .line 432
    .line 433
    .line 434
    goto :goto_6

    .line 435
    :cond_6
    invoke-virtual {v12}, Ll2/t;->R()V

    .line 436
    .line 437
    .line 438
    :goto_6
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 439
    .line 440
    return-object v0
.end method
