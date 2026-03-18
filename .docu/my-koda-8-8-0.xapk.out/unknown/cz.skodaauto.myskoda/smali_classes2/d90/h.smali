.class public final synthetic Ld90/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:I

.field public final synthetic f:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;II)V
    .locals 0

    .line 1
    iput p4, p0, Ld90/h;->d:I

    iput p1, p0, Ld90/h;->e:I

    iput-object p2, p0, Ld90/h;->f:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;II)V
    .locals 0

    .line 2
    iput p3, p0, Ld90/h;->d:I

    iput-object p1, p0, Ld90/h;->f:Ljava/lang/Object;

    iput p2, p0, Ld90/h;->e:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;III)V
    .locals 0

    .line 3
    iput p4, p0, Ld90/h;->d:I

    iput-object p1, p0, Ld90/h;->f:Ljava/lang/Object;

    iput p2, p0, Ld90/h;->e:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lmf0/a;I)V
    .locals 1

    .line 4
    const/16 v0, 0xc

    iput v0, p0, Ld90/h;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Ld90/h;->f:Ljava/lang/Object;

    iput p2, p0, Ld90/h;->e:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 35

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Ld90/h;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    iget-object v1, v0, Ld90/h;->f:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v1, Lqu/a;

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
    iget v0, v0, Ld90/h;->e:I

    .line 24
    .line 25
    or-int/lit8 v0, v0, 0x1

    .line 26
    .line 27
    invoke-static {v0}, Ll2/b;->x(I)I

    .line 28
    .line 29
    .line 30
    move-result v0

    .line 31
    invoke-static {v1, v2, v0}, Lzj0/j;->a(Lqu/a;Ll2/o;I)V

    .line 32
    .line 33
    .line 34
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 35
    .line 36
    return-object v0

    .line 37
    :pswitch_0
    iget-object v1, v0, Ld90/h;->f:Ljava/lang/Object;

    .line 38
    .line 39
    check-cast v1, Le3/s;

    .line 40
    .line 41
    move-object/from16 v2, p1

    .line 42
    .line 43
    check-cast v2, Ll2/o;

    .line 44
    .line 45
    move-object/from16 v3, p2

    .line 46
    .line 47
    check-cast v3, Ljava/lang/Integer;

    .line 48
    .line 49
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 50
    .line 51
    .line 52
    const/4 v3, 0x1

    .line 53
    invoke-static {v3}, Ll2/b;->x(I)I

    .line 54
    .line 55
    .line 56
    move-result v3

    .line 57
    iget v0, v0, Ld90/h;->e:I

    .line 58
    .line 59
    invoke-static {v0, v1, v2, v3}, Lz70/l;->l(ILe3/s;Ll2/o;I)V

    .line 60
    .line 61
    .line 62
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 63
    .line 64
    return-object v0

    .line 65
    :pswitch_1
    iget-object v1, v0, Ld90/h;->f:Ljava/lang/Object;

    .line 66
    .line 67
    check-cast v1, Lm1/t;

    .line 68
    .line 69
    move-object/from16 v2, p1

    .line 70
    .line 71
    check-cast v2, Ll2/o;

    .line 72
    .line 73
    move-object/from16 v3, p2

    .line 74
    .line 75
    check-cast v3, Ljava/lang/Integer;

    .line 76
    .line 77
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 78
    .line 79
    .line 80
    iget v0, v0, Ld90/h;->e:I

    .line 81
    .line 82
    or-int/lit8 v0, v0, 0x1

    .line 83
    .line 84
    invoke-static {v0}, Ll2/b;->x(I)I

    .line 85
    .line 86
    .line 87
    move-result v0

    .line 88
    invoke-static {v1, v2, v0}, Lz10/a;->b(Lm1/t;Ll2/o;I)V

    .line 89
    .line 90
    .line 91
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 92
    .line 93
    return-object v0

    .line 94
    :pswitch_2
    iget-object v1, v0, Ld90/h;->f:Ljava/lang/Object;

    .line 95
    .line 96
    check-cast v1, Lid/e;

    .line 97
    .line 98
    move-object/from16 v2, p1

    .line 99
    .line 100
    check-cast v2, Ll2/o;

    .line 101
    .line 102
    move-object/from16 v3, p2

    .line 103
    .line 104
    check-cast v3, Ljava/lang/Integer;

    .line 105
    .line 106
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 107
    .line 108
    .line 109
    iget v0, v0, Ld90/h;->e:I

    .line 110
    .line 111
    or-int/lit8 v0, v0, 0x1

    .line 112
    .line 113
    invoke-static {v0}, Ll2/b;->x(I)I

    .line 114
    .line 115
    .line 116
    move-result v0

    .line 117
    invoke-static {v1, v2, v0}, Lyj/a;->e(Lid/e;Ll2/o;I)V

    .line 118
    .line 119
    .line 120
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 121
    .line 122
    return-object v0

    .line 123
    :pswitch_3
    iget-object v1, v0, Ld90/h;->f:Ljava/lang/Object;

    .line 124
    .line 125
    check-cast v1, Luu0/r;

    .line 126
    .line 127
    move-object/from16 v2, p1

    .line 128
    .line 129
    check-cast v2, Ll2/o;

    .line 130
    .line 131
    move-object/from16 v3, p2

    .line 132
    .line 133
    check-cast v3, Ljava/lang/Integer;

    .line 134
    .line 135
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 136
    .line 137
    .line 138
    iget v0, v0, Ld90/h;->e:I

    .line 139
    .line 140
    or-int/lit8 v0, v0, 0x1

    .line 141
    .line 142
    invoke-static {v0}, Ll2/b;->x(I)I

    .line 143
    .line 144
    .line 145
    move-result v0

    .line 146
    invoke-static {v1, v2, v0}, Lvu0/g;->l(Luu0/r;Ll2/o;I)V

    .line 147
    .line 148
    .line 149
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 150
    .line 151
    return-object v0

    .line 152
    :pswitch_4
    iget-object v1, v0, Ld90/h;->f:Ljava/lang/Object;

    .line 153
    .line 154
    check-cast v1, Lqu/c;

    .line 155
    .line 156
    move-object/from16 v2, p1

    .line 157
    .line 158
    check-cast v2, Ll2/o;

    .line 159
    .line 160
    move-object/from16 v3, p2

    .line 161
    .line 162
    check-cast v3, Ljava/lang/Integer;

    .line 163
    .line 164
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 165
    .line 166
    .line 167
    iget v0, v0, Ld90/h;->e:I

    .line 168
    .line 169
    or-int/lit8 v0, v0, 0x1

    .line 170
    .line 171
    invoke-static {v0}, Ll2/b;->x(I)I

    .line 172
    .line 173
    .line 174
    move-result v0

    .line 175
    invoke-static {v1, v2, v0}, Llp/cc;->d(Lqu/c;Ll2/o;I)V

    .line 176
    .line 177
    .line 178
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 179
    .line 180
    return-object v0

    .line 181
    :pswitch_5
    iget-object v1, v0, Ld90/h;->f:Ljava/lang/Object;

    .line 182
    .line 183
    check-cast v1, Ltz/w3;

    .line 184
    .line 185
    move-object/from16 v2, p1

    .line 186
    .line 187
    check-cast v2, Ll2/o;

    .line 188
    .line 189
    move-object/from16 v3, p2

    .line 190
    .line 191
    check-cast v3, Ljava/lang/Integer;

    .line 192
    .line 193
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 194
    .line 195
    .line 196
    move-result v3

    .line 197
    and-int/lit8 v4, v3, 0x3

    .line 198
    .line 199
    const/4 v5, 0x2

    .line 200
    const/4 v6, 0x0

    .line 201
    const/4 v7, 0x1

    .line 202
    if-eq v4, v5, :cond_0

    .line 203
    .line 204
    move v4, v7

    .line 205
    goto :goto_0

    .line 206
    :cond_0
    move v4, v6

    .line 207
    :goto_0
    and-int/2addr v3, v7

    .line 208
    check-cast v2, Ll2/t;

    .line 209
    .line 210
    invoke-virtual {v2, v3, v4}, Ll2/t;->O(IZ)Z

    .line 211
    .line 212
    .line 213
    move-result v3

    .line 214
    if-eqz v3, :cond_7

    .line 215
    .line 216
    sget-object v3, Lx2/p;->b:Lx2/p;

    .line 217
    .line 218
    const/high16 v4, 0x3f800000    # 1.0f

    .line 219
    .line 220
    invoke-static {v3, v4}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 221
    .line 222
    .line 223
    move-result-object v5

    .line 224
    sget-object v8, Lj91/a;->a:Ll2/u2;

    .line 225
    .line 226
    invoke-virtual {v2, v8}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 227
    .line 228
    .line 229
    move-result-object v9

    .line 230
    check-cast v9, Lj91/c;

    .line 231
    .line 232
    iget v9, v9, Lj91/c;->j:F

    .line 233
    .line 234
    invoke-static {v5, v9}, Landroidx/compose/foundation/layout/a;->m(Lx2/s;F)Lx2/s;

    .line 235
    .line 236
    .line 237
    move-result-object v5

    .line 238
    sget-object v9, Lk1/j;->c:Lk1/e;

    .line 239
    .line 240
    sget-object v10, Lx2/c;->p:Lx2/h;

    .line 241
    .line 242
    invoke-static {v9, v10, v2, v6}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 243
    .line 244
    .line 245
    move-result-object v6

    .line 246
    iget-wide v9, v2, Ll2/t;->T:J

    .line 247
    .line 248
    invoke-static {v9, v10}, Ljava/lang/Long;->hashCode(J)I

    .line 249
    .line 250
    .line 251
    move-result v9

    .line 252
    invoke-virtual {v2}, Ll2/t;->m()Ll2/p1;

    .line 253
    .line 254
    .line 255
    move-result-object v10

    .line 256
    invoke-static {v2, v5}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 257
    .line 258
    .line 259
    move-result-object v5

    .line 260
    sget-object v11, Lv3/k;->m1:Lv3/j;

    .line 261
    .line 262
    invoke-virtual {v11}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 263
    .line 264
    .line 265
    sget-object v11, Lv3/j;->b:Lv3/i;

    .line 266
    .line 267
    invoke-virtual {v2}, Ll2/t;->c0()V

    .line 268
    .line 269
    .line 270
    iget-boolean v12, v2, Ll2/t;->S:Z

    .line 271
    .line 272
    if-eqz v12, :cond_1

    .line 273
    .line 274
    invoke-virtual {v2, v11}, Ll2/t;->l(Lay0/a;)V

    .line 275
    .line 276
    .line 277
    goto :goto_1

    .line 278
    :cond_1
    invoke-virtual {v2}, Ll2/t;->m0()V

    .line 279
    .line 280
    .line 281
    :goto_1
    sget-object v12, Lv3/j;->g:Lv3/h;

    .line 282
    .line 283
    invoke-static {v12, v6, v2}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 284
    .line 285
    .line 286
    sget-object v6, Lv3/j;->f:Lv3/h;

    .line 287
    .line 288
    invoke-static {v6, v10, v2}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 289
    .line 290
    .line 291
    sget-object v10, Lv3/j;->j:Lv3/h;

    .line 292
    .line 293
    iget-boolean v13, v2, Ll2/t;->S:Z

    .line 294
    .line 295
    if-nez v13, :cond_2

    .line 296
    .line 297
    invoke-virtual {v2}, Ll2/t;->L()Ljava/lang/Object;

    .line 298
    .line 299
    .line 300
    move-result-object v13

    .line 301
    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 302
    .line 303
    .line 304
    move-result-object v14

    .line 305
    invoke-static {v13, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 306
    .line 307
    .line 308
    move-result v13

    .line 309
    if-nez v13, :cond_3

    .line 310
    .line 311
    :cond_2
    invoke-static {v9, v2, v9, v10}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 312
    .line 313
    .line 314
    :cond_3
    sget-object v9, Lv3/j;->d:Lv3/h;

    .line 315
    .line 316
    invoke-static {v9, v5, v2}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 317
    .line 318
    .line 319
    move-object v5, v8

    .line 320
    invoke-interface {v1}, Ltz/w3;->getTitle()Ljava/lang/String;

    .line 321
    .line 322
    .line 323
    move-result-object v8

    .line 324
    sget-object v13, Lj91/j;->a:Ll2/u2;

    .line 325
    .line 326
    invoke-virtual {v2, v13}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 327
    .line 328
    .line 329
    move-result-object v14

    .line 330
    check-cast v14, Lj91/f;

    .line 331
    .line 332
    invoke-virtual {v14}, Lj91/f;->k()Lg4/p0;

    .line 333
    .line 334
    .line 335
    move-result-object v14

    .line 336
    const-string v15, "powerpass_card_title_"

    .line 337
    .line 338
    iget v0, v0, Ld90/h;->e:I

    .line 339
    .line 340
    invoke-static {v15, v0, v3}, Lc1/j0;->k(Ljava/lang/String;ILx2/p;)Lx2/s;

    .line 341
    .line 342
    .line 343
    move-result-object v15

    .line 344
    const/16 v28, 0x0

    .line 345
    .line 346
    const v29, 0xfff8

    .line 347
    .line 348
    .line 349
    move-object/from16 v16, v11

    .line 350
    .line 351
    move-object/from16 v17, v12

    .line 352
    .line 353
    const-wide/16 v11, 0x0

    .line 354
    .line 355
    move-object/from16 v19, v9

    .line 356
    .line 357
    move-object/from16 v18, v13

    .line 358
    .line 359
    move-object v9, v14

    .line 360
    const-wide/16 v13, 0x0

    .line 361
    .line 362
    move-object/from16 v20, v10

    .line 363
    .line 364
    move-object v10, v15

    .line 365
    const/4 v15, 0x0

    .line 366
    move-object/from16 v21, v16

    .line 367
    .line 368
    move-object/from16 v22, v17

    .line 369
    .line 370
    const-wide/16 v16, 0x0

    .line 371
    .line 372
    move-object/from16 v23, v18

    .line 373
    .line 374
    const/16 v18, 0x0

    .line 375
    .line 376
    move-object/from16 v24, v19

    .line 377
    .line 378
    const/16 v19, 0x0

    .line 379
    .line 380
    move-object/from16 v26, v20

    .line 381
    .line 382
    move-object/from16 v25, v21

    .line 383
    .line 384
    const-wide/16 v20, 0x0

    .line 385
    .line 386
    move-object/from16 v27, v22

    .line 387
    .line 388
    const/16 v22, 0x0

    .line 389
    .line 390
    move-object/from16 v30, v23

    .line 391
    .line 392
    const/16 v23, 0x0

    .line 393
    .line 394
    move-object/from16 v31, v24

    .line 395
    .line 396
    const/16 v24, 0x0

    .line 397
    .line 398
    move-object/from16 v32, v25

    .line 399
    .line 400
    const/16 v25, 0x0

    .line 401
    .line 402
    move-object/from16 v33, v27

    .line 403
    .line 404
    const/16 v27, 0x0

    .line 405
    .line 406
    move-object/from16 v7, v31

    .line 407
    .line 408
    move/from16 v31, v0

    .line 409
    .line 410
    move-object v0, v7

    .line 411
    move-object/from16 v34, v30

    .line 412
    .line 413
    move-object/from16 v7, v33

    .line 414
    .line 415
    move-object/from16 v30, v1

    .line 416
    .line 417
    move-object/from16 v1, v26

    .line 418
    .line 419
    move-object/from16 v26, v2

    .line 420
    .line 421
    move-object/from16 v2, v32

    .line 422
    .line 423
    invoke-static/range {v8 .. v29}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 424
    .line 425
    .line 426
    move-object/from16 v8, v26

    .line 427
    .line 428
    invoke-static {v3, v4}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 429
    .line 430
    .line 431
    move-result-object v9

    .line 432
    invoke-virtual {v8, v5}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 433
    .line 434
    .line 435
    move-result-object v4

    .line 436
    check-cast v4, Lj91/c;

    .line 437
    .line 438
    iget v11, v4, Lj91/c;->c:F

    .line 439
    .line 440
    const/4 v13, 0x0

    .line 441
    const/16 v14, 0xd

    .line 442
    .line 443
    const/4 v10, 0x0

    .line 444
    const/4 v12, 0x0

    .line 445
    invoke-static/range {v9 .. v14}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 446
    .line 447
    .line 448
    move-result-object v4

    .line 449
    sget-object v5, Lk1/j;->g:Lk1/f;

    .line 450
    .line 451
    sget-object v9, Lx2/c;->m:Lx2/i;

    .line 452
    .line 453
    const/4 v10, 0x6

    .line 454
    invoke-static {v5, v9, v8, v10}, Lk1/e1;->a(Lk1/g;Lx2/i;Ll2/o;I)Lk1/g1;

    .line 455
    .line 456
    .line 457
    move-result-object v5

    .line 458
    iget-wide v9, v8, Ll2/t;->T:J

    .line 459
    .line 460
    invoke-static {v9, v10}, Ljava/lang/Long;->hashCode(J)I

    .line 461
    .line 462
    .line 463
    move-result v9

    .line 464
    invoke-virtual {v8}, Ll2/t;->m()Ll2/p1;

    .line 465
    .line 466
    .line 467
    move-result-object v10

    .line 468
    invoke-static {v8, v4}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 469
    .line 470
    .line 471
    move-result-object v4

    .line 472
    invoke-virtual {v8}, Ll2/t;->c0()V

    .line 473
    .line 474
    .line 475
    iget-boolean v11, v8, Ll2/t;->S:Z

    .line 476
    .line 477
    if-eqz v11, :cond_4

    .line 478
    .line 479
    invoke-virtual {v8, v2}, Ll2/t;->l(Lay0/a;)V

    .line 480
    .line 481
    .line 482
    goto :goto_2

    .line 483
    :cond_4
    invoke-virtual {v8}, Ll2/t;->m0()V

    .line 484
    .line 485
    .line 486
    :goto_2
    invoke-static {v7, v5, v8}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 487
    .line 488
    .line 489
    invoke-static {v6, v10, v8}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 490
    .line 491
    .line 492
    iget-boolean v2, v8, Ll2/t;->S:Z

    .line 493
    .line 494
    if-nez v2, :cond_5

    .line 495
    .line 496
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 497
    .line 498
    .line 499
    move-result-object v2

    .line 500
    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 501
    .line 502
    .line 503
    move-result-object v5

    .line 504
    invoke-static {v2, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 505
    .line 506
    .line 507
    move-result v2

    .line 508
    if-nez v2, :cond_6

    .line 509
    .line 510
    :cond_5
    invoke-static {v9, v8, v9, v1}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 511
    .line 512
    .line 513
    :cond_6
    invoke-static {v0, v4, v8}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 514
    .line 515
    .line 516
    invoke-interface/range {v30 .. v30}, Ltz/w3;->a()Ljava/lang/String;

    .line 517
    .line 518
    .line 519
    move-result-object v0

    .line 520
    sget-object v1, Lj91/h;->a:Ll2/u2;

    .line 521
    .line 522
    invoke-virtual {v8, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 523
    .line 524
    .line 525
    move-result-object v2

    .line 526
    check-cast v2, Lj91/e;

    .line 527
    .line 528
    invoke-virtual {v2}, Lj91/e;->s()J

    .line 529
    .line 530
    .line 531
    move-result-wide v11

    .line 532
    move-object/from16 v2, v34

    .line 533
    .line 534
    invoke-virtual {v8, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 535
    .line 536
    .line 537
    move-result-object v4

    .line 538
    check-cast v4, Lj91/f;

    .line 539
    .line 540
    invoke-virtual {v4}, Lj91/f;->a()Lg4/p0;

    .line 541
    .line 542
    .line 543
    move-result-object v9

    .line 544
    const-string v4, "powerpass_card_subtitle_"

    .line 545
    .line 546
    move/from16 v5, v31

    .line 547
    .line 548
    invoke-static {v4, v5, v3}, Lc1/j0;->k(Ljava/lang/String;ILx2/p;)Lx2/s;

    .line 549
    .line 550
    .line 551
    move-result-object v10

    .line 552
    const/16 v28, 0x0

    .line 553
    .line 554
    const v29, 0xfff0

    .line 555
    .line 556
    .line 557
    const-wide/16 v13, 0x0

    .line 558
    .line 559
    const/4 v15, 0x0

    .line 560
    const-wide/16 v16, 0x0

    .line 561
    .line 562
    const/16 v18, 0x0

    .line 563
    .line 564
    const/16 v19, 0x0

    .line 565
    .line 566
    const-wide/16 v20, 0x0

    .line 567
    .line 568
    const/16 v22, 0x0

    .line 569
    .line 570
    const/16 v23, 0x0

    .line 571
    .line 572
    const/16 v24, 0x0

    .line 573
    .line 574
    const/16 v25, 0x0

    .line 575
    .line 576
    const/16 v27, 0x0

    .line 577
    .line 578
    move-object/from16 v26, v8

    .line 579
    .line 580
    move-object v8, v0

    .line 581
    invoke-static/range {v8 .. v29}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 582
    .line 583
    .line 584
    move-object/from16 v8, v26

    .line 585
    .line 586
    invoke-interface/range {v30 .. v30}, Ltz/w3;->getValue()Ljava/lang/String;

    .line 587
    .line 588
    .line 589
    move-result-object v0

    .line 590
    invoke-virtual {v8, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 591
    .line 592
    .line 593
    move-result-object v1

    .line 594
    check-cast v1, Lj91/e;

    .line 595
    .line 596
    invoke-virtual {v1}, Lj91/e;->s()J

    .line 597
    .line 598
    .line 599
    move-result-wide v11

    .line 600
    invoke-virtual {v8, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 601
    .line 602
    .line 603
    move-result-object v1

    .line 604
    check-cast v1, Lj91/f;

    .line 605
    .line 606
    invoke-virtual {v1}, Lj91/f;->a()Lg4/p0;

    .line 607
    .line 608
    .line 609
    move-result-object v9

    .line 610
    const-string v1, "powerpass_card_value_"

    .line 611
    .line 612
    invoke-static {v1, v5, v3}, Lc1/j0;->k(Ljava/lang/String;ILx2/p;)Lx2/s;

    .line 613
    .line 614
    .line 615
    move-result-object v10

    .line 616
    move-object v8, v0

    .line 617
    invoke-static/range {v8 .. v29}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 618
    .line 619
    .line 620
    move-object/from16 v8, v26

    .line 621
    .line 622
    const/4 v0, 0x1

    .line 623
    invoke-virtual {v8, v0}, Ll2/t;->q(Z)V

    .line 624
    .line 625
    .line 626
    invoke-virtual {v8, v0}, Ll2/t;->q(Z)V

    .line 627
    .line 628
    .line 629
    goto :goto_3

    .line 630
    :cond_7
    move-object v8, v2

    .line 631
    invoke-virtual {v8}, Ll2/t;->R()V

    .line 632
    .line 633
    .line 634
    :goto_3
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 635
    .line 636
    return-object v0

    .line 637
    :pswitch_6
    iget-object v1, v0, Ld90/h;->f:Ljava/lang/Object;

    .line 638
    .line 639
    check-cast v1, Ltz/x0;

    .line 640
    .line 641
    move-object/from16 v2, p1

    .line 642
    .line 643
    check-cast v2, Ll2/o;

    .line 644
    .line 645
    move-object/from16 v3, p2

    .line 646
    .line 647
    check-cast v3, Ljava/lang/Integer;

    .line 648
    .line 649
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 650
    .line 651
    .line 652
    const/4 v3, 0x1

    .line 653
    invoke-static {v3}, Ll2/b;->x(I)I

    .line 654
    .line 655
    .line 656
    move-result v3

    .line 657
    iget v0, v0, Ld90/h;->e:I

    .line 658
    .line 659
    invoke-static {v1, v0, v2, v3}, Luz/t;->r(Ltz/x0;ILl2/o;I)V

    .line 660
    .line 661
    .line 662
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 663
    .line 664
    return-object v0

    .line 665
    :pswitch_7
    iget-object v1, v0, Ld90/h;->f:Ljava/lang/Object;

    .line 666
    .line 667
    check-cast v1, Lra0/c;

    .line 668
    .line 669
    move-object/from16 v2, p1

    .line 670
    .line 671
    check-cast v2, Ll2/o;

    .line 672
    .line 673
    move-object/from16 v3, p2

    .line 674
    .line 675
    check-cast v3, Ljava/lang/Integer;

    .line 676
    .line 677
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 678
    .line 679
    .line 680
    iget v0, v0, Ld90/h;->e:I

    .line 681
    .line 682
    or-int/lit8 v0, v0, 0x1

    .line 683
    .line 684
    invoke-static {v0}, Ll2/b;->x(I)I

    .line 685
    .line 686
    .line 687
    move-result v0

    .line 688
    invoke-static {v1, v2, v0}, Lta0/f;->a(Lra0/c;Ll2/o;I)V

    .line 689
    .line 690
    .line 691
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 692
    .line 693
    return-object v0

    .line 694
    :pswitch_8
    iget-object v1, v0, Ld90/h;->f:Ljava/lang/Object;

    .line 695
    .line 696
    check-cast v1, Lug/c;

    .line 697
    .line 698
    move-object/from16 v2, p1

    .line 699
    .line 700
    check-cast v2, Ll2/o;

    .line 701
    .line 702
    move-object/from16 v3, p2

    .line 703
    .line 704
    check-cast v3, Ljava/lang/Integer;

    .line 705
    .line 706
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 707
    .line 708
    .line 709
    const/4 v3, 0x1

    .line 710
    invoke-static {v3}, Ll2/b;->x(I)I

    .line 711
    .line 712
    .line 713
    move-result v3

    .line 714
    iget v0, v0, Ld90/h;->e:I

    .line 715
    .line 716
    invoke-static {v1, v0, v2, v3}, Lkp/d8;->a(Lug/c;ILl2/o;I)V

    .line 717
    .line 718
    .line 719
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 720
    .line 721
    return-object v0

    .line 722
    :pswitch_9
    iget-object v1, v0, Ld90/h;->f:Ljava/lang/Object;

    .line 723
    .line 724
    check-cast v1, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPACompose;

    .line 725
    .line 726
    move-object/from16 v2, p1

    .line 727
    .line 728
    check-cast v2, Ll2/o;

    .line 729
    .line 730
    move-object/from16 v3, p2

    .line 731
    .line 732
    check-cast v3, Ljava/lang/Integer;

    .line 733
    .line 734
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 735
    .line 736
    .line 737
    move-result v3

    .line 738
    iget v0, v0, Ld90/h;->e:I

    .line 739
    .line 740
    invoke-static {v1, v0, v2, v3}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPACompose;->k(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPACompose;ILl2/o;I)Llx0/b0;

    .line 741
    .line 742
    .line 743
    move-result-object v0

    .line 744
    return-object v0

    .line 745
    :pswitch_a
    iget-object v1, v0, Ld90/h;->f:Ljava/lang/Object;

    .line 746
    .line 747
    check-cast v1, Lmf0/a;

    .line 748
    .line 749
    move-object/from16 v2, p1

    .line 750
    .line 751
    check-cast v2, Ll2/o;

    .line 752
    .line 753
    move-object/from16 v3, p2

    .line 754
    .line 755
    check-cast v3, Ljava/lang/Integer;

    .line 756
    .line 757
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 758
    .line 759
    .line 760
    iget v0, v0, Ld90/h;->e:I

    .line 761
    .line 762
    or-int/lit8 v0, v0, 0x1

    .line 763
    .line 764
    invoke-static {v0}, Ll2/b;->x(I)I

    .line 765
    .line 766
    .line 767
    move-result v0

    .line 768
    invoke-static {v1, v2, v0}, Lnf0/a;->c(Lmf0/a;Ll2/o;I)V

    .line 769
    .line 770
    .line 771
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 772
    .line 773
    return-object v0

    .line 774
    :pswitch_b
    iget-object v1, v0, Ld90/h;->f:Ljava/lang/Object;

    .line 775
    .line 776
    check-cast v1, Lxh/e;

    .line 777
    .line 778
    move-object/from16 v2, p1

    .line 779
    .line 780
    check-cast v2, Ll2/o;

    .line 781
    .line 782
    move-object/from16 v3, p2

    .line 783
    .line 784
    check-cast v3, Ljava/lang/Integer;

    .line 785
    .line 786
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 787
    .line 788
    .line 789
    iget v0, v0, Ld90/h;->e:I

    .line 790
    .line 791
    or-int/lit8 v0, v0, 0x1

    .line 792
    .line 793
    invoke-static {v0}, Ll2/b;->x(I)I

    .line 794
    .line 795
    .line 796
    move-result v0

    .line 797
    invoke-static {v1, v2, v0}, Ljp/ja;->c(Lxh/e;Ll2/o;I)V

    .line 798
    .line 799
    .line 800
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 801
    .line 802
    return-object v0

    .line 803
    :pswitch_c
    iget-object v1, v0, Ld90/h;->f:Ljava/lang/Object;

    .line 804
    .line 805
    check-cast v1, Lk1/t;

    .line 806
    .line 807
    move-object/from16 v2, p1

    .line 808
    .line 809
    check-cast v2, Ll2/o;

    .line 810
    .line 811
    move-object/from16 v3, p2

    .line 812
    .line 813
    check-cast v3, Ljava/lang/Integer;

    .line 814
    .line 815
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 816
    .line 817
    .line 818
    iget v0, v0, Ld90/h;->e:I

    .line 819
    .line 820
    or-int/lit8 v0, v0, 0x1

    .line 821
    .line 822
    invoke-static {v0}, Ll2/b;->x(I)I

    .line 823
    .line 824
    .line 825
    move-result v0

    .line 826
    invoke-static {v1, v2, v0}, Lmc/d;->e(Lk1/t;Ll2/o;I)V

    .line 827
    .line 828
    .line 829
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 830
    .line 831
    return-object v0

    .line 832
    :pswitch_d
    iget-object v1, v0, Ld90/h;->f:Ljava/lang/Object;

    .line 833
    .line 834
    check-cast v1, Llc/o;

    .line 835
    .line 836
    move-object/from16 v2, p1

    .line 837
    .line 838
    check-cast v2, Ll2/o;

    .line 839
    .line 840
    move-object/from16 v3, p2

    .line 841
    .line 842
    check-cast v3, Ljava/lang/Integer;

    .line 843
    .line 844
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 845
    .line 846
    .line 847
    iget v0, v0, Ld90/h;->e:I

    .line 848
    .line 849
    or-int/lit8 v0, v0, 0x1

    .line 850
    .line 851
    invoke-static {v0}, Ll2/b;->x(I)I

    .line 852
    .line 853
    .line 854
    move-result v0

    .line 855
    invoke-virtual {v1, v2, v0}, Llc/o;->a(Ll2/o;I)V

    .line 856
    .line 857
    .line 858
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 859
    .line 860
    return-object v0

    .line 861
    :pswitch_e
    iget-object v1, v0, Ld90/h;->f:Ljava/lang/Object;

    .line 862
    .line 863
    check-cast v1, Lk30/e;

    .line 864
    .line 865
    move-object/from16 v2, p1

    .line 866
    .line 867
    check-cast v2, Ll2/o;

    .line 868
    .line 869
    move-object/from16 v3, p2

    .line 870
    .line 871
    check-cast v3, Ljava/lang/Integer;

    .line 872
    .line 873
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 874
    .line 875
    .line 876
    iget v0, v0, Ld90/h;->e:I

    .line 877
    .line 878
    or-int/lit8 v0, v0, 0x1

    .line 879
    .line 880
    invoke-static {v0}, Ll2/b;->x(I)I

    .line 881
    .line 882
    .line 883
    move-result v0

    .line 884
    invoke-static {v1, v2, v0}, Llp/ne;->g(Lk30/e;Ll2/o;I)V

    .line 885
    .line 886
    .line 887
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 888
    .line 889
    return-object v0

    .line 890
    :pswitch_f
    iget-object v1, v0, Ld90/h;->f:Ljava/lang/Object;

    .line 891
    .line 892
    check-cast v1, Li91/c2;

    .line 893
    .line 894
    move-object/from16 v2, p1

    .line 895
    .line 896
    check-cast v2, Ll2/o;

    .line 897
    .line 898
    move-object/from16 v3, p2

    .line 899
    .line 900
    check-cast v3, Ljava/lang/Integer;

    .line 901
    .line 902
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 903
    .line 904
    .line 905
    const/4 v3, 0x1

    .line 906
    invoke-static {v3}, Ll2/b;->x(I)I

    .line 907
    .line 908
    .line 909
    move-result v3

    .line 910
    iget v0, v0, Ld90/h;->e:I

    .line 911
    .line 912
    invoke-static {v0, v1, v2, v3}, Llp/ne;->j(ILi91/c2;Ll2/o;I)V

    .line 913
    .line 914
    .line 915
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 916
    .line 917
    return-object v0

    .line 918
    :pswitch_10
    iget-object v1, v0, Ld90/h;->f:Ljava/lang/Object;

    .line 919
    .line 920
    check-cast v1, Liv0/f;

    .line 921
    .line 922
    move-object/from16 v2, p1

    .line 923
    .line 924
    check-cast v2, Ll2/o;

    .line 925
    .line 926
    move-object/from16 v3, p2

    .line 927
    .line 928
    check-cast v3, Ljava/lang/Integer;

    .line 929
    .line 930
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 931
    .line 932
    .line 933
    iget v0, v0, Ld90/h;->e:I

    .line 934
    .line 935
    or-int/lit8 v0, v0, 0x1

    .line 936
    .line 937
    invoke-static {v0}, Ll2/b;->x(I)I

    .line 938
    .line 939
    .line 940
    move-result v0

    .line 941
    invoke-static {v1, v2, v0}, Lkv0/i;->h(Liv0/f;Ll2/o;I)V

    .line 942
    .line 943
    .line 944
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 945
    .line 946
    return-object v0

    .line 947
    :pswitch_11
    iget-object v1, v0, Ld90/h;->f:Ljava/lang/Object;

    .line 948
    .line 949
    check-cast v1, Lmc/x;

    .line 950
    .line 951
    move-object/from16 v2, p1

    .line 952
    .line 953
    check-cast v2, Ll2/o;

    .line 954
    .line 955
    move-object/from16 v3, p2

    .line 956
    .line 957
    check-cast v3, Ljava/lang/Integer;

    .line 958
    .line 959
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 960
    .line 961
    .line 962
    iget v0, v0, Ld90/h;->e:I

    .line 963
    .line 964
    or-int/lit8 v0, v0, 0x1

    .line 965
    .line 966
    invoke-static {v0}, Ll2/b;->x(I)I

    .line 967
    .line 968
    .line 969
    move-result v0

    .line 970
    invoke-static {v1, v2, v0}, Lkk/a;->f(Lmc/x;Ll2/o;I)V

    .line 971
    .line 972
    .line 973
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 974
    .line 975
    return-object v0

    .line 976
    :pswitch_12
    iget-object v1, v0, Ld90/h;->f:Ljava/lang/Object;

    .line 977
    .line 978
    check-cast v1, Li91/g1;

    .line 979
    .line 980
    move-object/from16 v2, p1

    .line 981
    .line 982
    check-cast v2, Ll2/o;

    .line 983
    .line 984
    move-object/from16 v3, p2

    .line 985
    .line 986
    check-cast v3, Ljava/lang/Integer;

    .line 987
    .line 988
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 989
    .line 990
    .line 991
    move-result v3

    .line 992
    and-int/lit8 v4, v3, 0x3

    .line 993
    .line 994
    const/4 v5, 0x2

    .line 995
    const/4 v6, 0x1

    .line 996
    const/4 v7, 0x0

    .line 997
    if-eq v4, v5, :cond_8

    .line 998
    .line 999
    move v4, v6

    .line 1000
    goto :goto_4

    .line 1001
    :cond_8
    move v4, v7

    .line 1002
    :goto_4
    and-int/2addr v3, v6

    .line 1003
    check-cast v2, Ll2/t;

    .line 1004
    .line 1005
    invoke-virtual {v2, v3, v4}, Ll2/t;->O(IZ)Z

    .line 1006
    .line 1007
    .line 1008
    move-result v3

    .line 1009
    if-eqz v3, :cond_a

    .line 1010
    .line 1011
    new-instance v3, Ljava/lang/StringBuilder;

    .line 1012
    .line 1013
    const-string v4, "navigation_action_label_"

    .line 1014
    .line 1015
    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 1016
    .line 1017
    .line 1018
    iget v0, v0, Ld90/h;->e:I

    .line 1019
    .line 1020
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 1021
    .line 1022
    .line 1023
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1024
    .line 1025
    .line 1026
    move-result-object v0

    .line 1027
    const-string v3, "defaultTestTag"

    .line 1028
    .line 1029
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1030
    .line 1031
    .line 1032
    sget-object v3, Lx2/p;->b:Lx2/p;

    .line 1033
    .line 1034
    invoke-static {v3, v0}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 1035
    .line 1036
    .line 1037
    move-result-object v10

    .line 1038
    iget-object v8, v1, Li91/g1;->c:Ljava/lang/String;

    .line 1039
    .line 1040
    sget-object v0, Lh2/p1;->a:Ll2/e0;

    .line 1041
    .line 1042
    invoke-virtual {v2, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 1043
    .line 1044
    .line 1045
    move-result-object v0

    .line 1046
    check-cast v0, Le3/s;

    .line 1047
    .line 1048
    iget-wide v11, v0, Le3/s;->a:J

    .line 1049
    .line 1050
    iget-boolean v0, v1, Li91/g1;->d:Z

    .line 1051
    .line 1052
    if-eqz v0, :cond_9

    .line 1053
    .line 1054
    const v0, -0xabe48dd

    .line 1055
    .line 1056
    .line 1057
    invoke-virtual {v2, v0}, Ll2/t;->Y(I)V

    .line 1058
    .line 1059
    .line 1060
    sget-object v0, Lj91/j;->a:Ll2/u2;

    .line 1061
    .line 1062
    invoke-virtual {v2, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 1063
    .line 1064
    .line 1065
    move-result-object v0

    .line 1066
    check-cast v0, Lj91/f;

    .line 1067
    .line 1068
    iget-object v0, v0, Lj91/f;->k:Ll2/j1;

    .line 1069
    .line 1070
    invoke-virtual {v0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 1071
    .line 1072
    .line 1073
    move-result-object v0

    .line 1074
    check-cast v0, Lg4/p0;

    .line 1075
    .line 1076
    :goto_5
    invoke-virtual {v2, v7}, Ll2/t;->q(Z)V

    .line 1077
    .line 1078
    .line 1079
    move-object v9, v0

    .line 1080
    goto :goto_6

    .line 1081
    :cond_9
    const v0, -0xabe4461

    .line 1082
    .line 1083
    .line 1084
    invoke-virtual {v2, v0}, Ll2/t;->Y(I)V

    .line 1085
    .line 1086
    .line 1087
    sget-object v0, Lj91/j;->a:Ll2/u2;

    .line 1088
    .line 1089
    invoke-virtual {v2, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 1090
    .line 1091
    .line 1092
    move-result-object v0

    .line 1093
    check-cast v0, Lj91/f;

    .line 1094
    .line 1095
    invoke-virtual {v0}, Lj91/f;->d()Lg4/p0;

    .line 1096
    .line 1097
    .line 1098
    move-result-object v0

    .line 1099
    goto :goto_5

    .line 1100
    :goto_6
    const/16 v28, 0x6180

    .line 1101
    .line 1102
    const v29, 0xaff0

    .line 1103
    .line 1104
    .line 1105
    const-wide/16 v13, 0x0

    .line 1106
    .line 1107
    const/4 v15, 0x0

    .line 1108
    const-wide/16 v16, 0x0

    .line 1109
    .line 1110
    const/16 v18, 0x0

    .line 1111
    .line 1112
    const/16 v19, 0x0

    .line 1113
    .line 1114
    const-wide/16 v20, 0x0

    .line 1115
    .line 1116
    const/16 v22, 0x1

    .line 1117
    .line 1118
    const/16 v23, 0x0

    .line 1119
    .line 1120
    const/16 v24, 0x1

    .line 1121
    .line 1122
    const/16 v25, 0x0

    .line 1123
    .line 1124
    const/16 v27, 0x0

    .line 1125
    .line 1126
    move-object/from16 v26, v2

    .line 1127
    .line 1128
    invoke-static/range {v8 .. v29}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 1129
    .line 1130
    .line 1131
    goto :goto_7

    .line 1132
    :cond_a
    move-object/from16 v26, v2

    .line 1133
    .line 1134
    invoke-virtual/range {v26 .. v26}, Ll2/t;->R()V

    .line 1135
    .line 1136
    .line 1137
    :goto_7
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1138
    .line 1139
    return-object v0

    .line 1140
    :pswitch_13
    iget-object v1, v0, Ld90/h;->f:Ljava/lang/Object;

    .line 1141
    .line 1142
    check-cast v1, Lhc/a;

    .line 1143
    .line 1144
    move-object/from16 v2, p1

    .line 1145
    .line 1146
    check-cast v2, Ll2/o;

    .line 1147
    .line 1148
    move-object/from16 v3, p2

    .line 1149
    .line 1150
    check-cast v3, Ljava/lang/Integer;

    .line 1151
    .line 1152
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1153
    .line 1154
    .line 1155
    iget v0, v0, Ld90/h;->e:I

    .line 1156
    .line 1157
    or-int/lit8 v0, v0, 0x1

    .line 1158
    .line 1159
    invoke-static {v0}, Ll2/b;->x(I)I

    .line 1160
    .line 1161
    .line 1162
    move-result v0

    .line 1163
    invoke-static {v1, v2, v0}, Llp/s0;->a(Lhc/a;Ll2/o;I)V

    .line 1164
    .line 1165
    .line 1166
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1167
    .line 1168
    return-object v0

    .line 1169
    :pswitch_14
    iget-object v1, v0, Ld90/h;->f:Ljava/lang/Object;

    .line 1170
    .line 1171
    check-cast v1, Lg61/p;

    .line 1172
    .line 1173
    move-object/from16 v2, p1

    .line 1174
    .line 1175
    check-cast v2, Ll2/o;

    .line 1176
    .line 1177
    move-object/from16 v3, p2

    .line 1178
    .line 1179
    check-cast v3, Ljava/lang/Integer;

    .line 1180
    .line 1181
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 1182
    .line 1183
    .line 1184
    iget v0, v0, Ld90/h;->e:I

    .line 1185
    .line 1186
    or-int/lit8 v0, v0, 0x1

    .line 1187
    .line 1188
    invoke-static {v0}, Ll2/b;->x(I)I

    .line 1189
    .line 1190
    .line 1191
    move-result v0

    .line 1192
    invoke-static {v1, v2, v0}, Lh70/m;->c(Lg61/p;Ll2/o;I)V

    .line 1193
    .line 1194
    .line 1195
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1196
    .line 1197
    return-object v0

    .line 1198
    :pswitch_15
    iget-object v1, v0, Ld90/h;->f:Ljava/lang/Object;

    .line 1199
    .line 1200
    check-cast v1, Lkj/a;

    .line 1201
    .line 1202
    move-object/from16 v2, p1

    .line 1203
    .line 1204
    check-cast v2, Ll2/o;

    .line 1205
    .line 1206
    move-object/from16 v3, p2

    .line 1207
    .line 1208
    check-cast v3, Ljava/lang/Integer;

    .line 1209
    .line 1210
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 1211
    .line 1212
    .line 1213
    iget v0, v0, Ld90/h;->e:I

    .line 1214
    .line 1215
    or-int/lit8 v0, v0, 0x1

    .line 1216
    .line 1217
    invoke-static {v0}, Ll2/b;->x(I)I

    .line 1218
    .line 1219
    .line 1220
    move-result v0

    .line 1221
    invoke-static {v1, v2, v0}, Lgg/b;->b(Lkj/a;Ll2/o;I)V

    .line 1222
    .line 1223
    .line 1224
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1225
    .line 1226
    return-object v0

    .line 1227
    :pswitch_16
    iget-object v1, v0, Ld90/h;->f:Ljava/lang/Object;

    .line 1228
    .line 1229
    check-cast v1, Lb90/d;

    .line 1230
    .line 1231
    move-object/from16 v2, p1

    .line 1232
    .line 1233
    check-cast v2, Ll2/o;

    .line 1234
    .line 1235
    move-object/from16 v3, p2

    .line 1236
    .line 1237
    check-cast v3, Ljava/lang/Integer;

    .line 1238
    .line 1239
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1240
    .line 1241
    .line 1242
    const/4 v3, 0x1

    .line 1243
    invoke-static {v3}, Ll2/b;->x(I)I

    .line 1244
    .line 1245
    .line 1246
    move-result v3

    .line 1247
    iget v0, v0, Ld90/h;->e:I

    .line 1248
    .line 1249
    invoke-static {v1, v0, v2, v3}, Ljp/bg;->b(Lb90/d;ILl2/o;I)V

    .line 1250
    .line 1251
    .line 1252
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1253
    .line 1254
    return-object v0

    .line 1255
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_16
        :pswitch_15
        :pswitch_14
        :pswitch_13
        :pswitch_12
        :pswitch_11
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
