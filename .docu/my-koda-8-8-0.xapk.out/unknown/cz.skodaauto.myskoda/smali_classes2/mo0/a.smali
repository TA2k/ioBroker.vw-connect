.class public final synthetic Lmo0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lmo0/a;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(II)V
    .locals 0

    .line 2
    iput p2, p0, Lmo0/a;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 38

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v0, v0, Lmo0/a;->d:I

    .line 4
    .line 5
    const-class v1, Lwe0/a;

    .line 6
    .line 7
    const-string v2, "$this$viewModel"

    .line 8
    .line 9
    const v3, 0x7f12048d

    .line 10
    .line 11
    .line 12
    const-string v4, "trips_overview_title"

    .line 13
    .line 14
    sget-object v5, Lx2/p;->b:Lx2/p;

    .line 15
    .line 16
    const-class v6, Lxl0/f;

    .line 17
    .line 18
    const-class v7, Lti0/a;

    .line 19
    .line 20
    const-string v8, "null"

    .line 21
    .line 22
    const/4 v9, 0x0

    .line 23
    const/4 v10, 0x2

    .line 24
    const/4 v11, 0x0

    .line 25
    const-string v12, "$this$single"

    .line 26
    .line 27
    const-string v13, "it"

    .line 28
    .line 29
    sget-object v14, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    const/4 v15, 0x1

    .line 32
    packed-switch v0, :pswitch_data_0

    .line 33
    .line 34
    .line 35
    move-object/from16 v0, p1

    .line 36
    .line 37
    check-cast v0, Ll2/o;

    .line 38
    .line 39
    move-object/from16 v1, p2

    .line 40
    .line 41
    check-cast v1, Ljava/lang/Integer;

    .line 42
    .line 43
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 44
    .line 45
    .line 46
    invoke-static {v15}, Ll2/b;->x(I)I

    .line 47
    .line 48
    .line 49
    move-result v1

    .line 50
    invoke-static {v0, v1}, Ln70/a;->d0(Ll2/o;I)V

    .line 51
    .line 52
    .line 53
    return-object v14

    .line 54
    :pswitch_0
    move-object/from16 v0, p1

    .line 55
    .line 56
    check-cast v0, Ll2/o;

    .line 57
    .line 58
    move-object/from16 v1, p2

    .line 59
    .line 60
    check-cast v1, Ljava/lang/Integer;

    .line 61
    .line 62
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 63
    .line 64
    .line 65
    invoke-static {v15}, Ll2/b;->x(I)I

    .line 66
    .line 67
    .line 68
    move-result v1

    .line 69
    invoke-static {v0, v1}, Ln70/a;->a0(Ll2/o;I)V

    .line 70
    .line 71
    .line 72
    return-object v14

    .line 73
    :pswitch_1
    move-object/from16 v0, p1

    .line 74
    .line 75
    check-cast v0, Ll2/o;

    .line 76
    .line 77
    move-object/from16 v1, p2

    .line 78
    .line 79
    check-cast v1, Ljava/lang/Integer;

    .line 80
    .line 81
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 82
    .line 83
    .line 84
    invoke-static {v15}, Ll2/b;->x(I)I

    .line 85
    .line 86
    .line 87
    move-result v1

    .line 88
    invoke-static {v0, v1}, Ln70/a;->v(Ll2/o;I)V

    .line 89
    .line 90
    .line 91
    return-object v14

    .line 92
    :pswitch_2
    move-object/from16 v0, p1

    .line 93
    .line 94
    check-cast v0, Ll2/o;

    .line 95
    .line 96
    move-object/from16 v1, p2

    .line 97
    .line 98
    check-cast v1, Ljava/lang/Integer;

    .line 99
    .line 100
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 101
    .line 102
    .line 103
    invoke-static {v15}, Ll2/b;->x(I)I

    .line 104
    .line 105
    .line 106
    move-result v1

    .line 107
    invoke-static {v0, v1}, Ln70/m;->e(Ll2/o;I)V

    .line 108
    .line 109
    .line 110
    return-object v14

    .line 111
    :pswitch_3
    move-object/from16 v0, p1

    .line 112
    .line 113
    check-cast v0, Ll2/o;

    .line 114
    .line 115
    move-object/from16 v1, p2

    .line 116
    .line 117
    check-cast v1, Ljava/lang/Integer;

    .line 118
    .line 119
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 120
    .line 121
    .line 122
    invoke-static {v15}, Ll2/b;->x(I)I

    .line 123
    .line 124
    .line 125
    move-result v1

    .line 126
    invoke-static {v0, v1}, Ln70/a;->q(Ll2/o;I)V

    .line 127
    .line 128
    .line 129
    return-object v14

    .line 130
    :pswitch_4
    move-object/from16 v0, p1

    .line 131
    .line 132
    check-cast v0, Ll2/o;

    .line 133
    .line 134
    move-object/from16 v1, p2

    .line 135
    .line 136
    check-cast v1, Ljava/lang/Integer;

    .line 137
    .line 138
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 139
    .line 140
    .line 141
    invoke-static {v15}, Ll2/b;->x(I)I

    .line 142
    .line 143
    .line 144
    move-result v1

    .line 145
    invoke-static {v0, v1}, Ln70/a;->z(Ll2/o;I)V

    .line 146
    .line 147
    .line 148
    return-object v14

    .line 149
    :pswitch_5
    move-object/from16 v0, p1

    .line 150
    .line 151
    check-cast v0, Ll2/o;

    .line 152
    .line 153
    move-object/from16 v1, p2

    .line 154
    .line 155
    check-cast v1, Ljava/lang/Integer;

    .line 156
    .line 157
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 158
    .line 159
    .line 160
    invoke-static {v15}, Ll2/b;->x(I)I

    .line 161
    .line 162
    .line 163
    move-result v1

    .line 164
    invoke-static {v0, v1}, Ln70/a;->n(Ll2/o;I)V

    .line 165
    .line 166
    .line 167
    return-object v14

    .line 168
    :pswitch_6
    move-object/from16 v0, p1

    .line 169
    .line 170
    check-cast v0, Ll2/o;

    .line 171
    .line 172
    move-object/from16 v1, p2

    .line 173
    .line 174
    check-cast v1, Ljava/lang/Integer;

    .line 175
    .line 176
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 177
    .line 178
    .line 179
    move-result v1

    .line 180
    and-int/lit8 v2, v1, 0x3

    .line 181
    .line 182
    if-eq v2, v10, :cond_0

    .line 183
    .line 184
    move v9, v15

    .line 185
    :cond_0
    and-int/2addr v1, v15

    .line 186
    move-object v5, v0

    .line 187
    check-cast v5, Ll2/t;

    .line 188
    .line 189
    invoke-virtual {v5, v1, v9}, Ll2/t;->O(IZ)Z

    .line 190
    .line 191
    .line 192
    move-result v0

    .line 193
    if-eqz v0, :cond_1

    .line 194
    .line 195
    new-instance v2, Lm70/p0;

    .line 196
    .line 197
    sget-object v0, Llf0/i;->e:Llf0/i;

    .line 198
    .line 199
    const/16 v1, 0xfe

    .line 200
    .line 201
    invoke-direct {v2, v0, v1}, Lm70/p0;-><init>(Llf0/i;I)V

    .line 202
    .line 203
    .line 204
    const/4 v6, 0x0

    .line 205
    const/4 v7, 0x6

    .line 206
    const/4 v3, 0x0

    .line 207
    const/4 v4, 0x0

    .line 208
    invoke-static/range {v2 .. v7}, Ln70/a;->h0(Lm70/p0;Lx2/s;Lay0/a;Ll2/o;II)V

    .line 209
    .line 210
    .line 211
    goto :goto_0

    .line 212
    :cond_1
    invoke-virtual {v5}, Ll2/t;->R()V

    .line 213
    .line 214
    .line 215
    :goto_0
    return-object v14

    .line 216
    :pswitch_7
    move-object/from16 v0, p1

    .line 217
    .line 218
    check-cast v0, Ll2/o;

    .line 219
    .line 220
    move-object/from16 v1, p2

    .line 221
    .line 222
    check-cast v1, Ljava/lang/Integer;

    .line 223
    .line 224
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 225
    .line 226
    .line 227
    move-result v1

    .line 228
    and-int/lit8 v2, v1, 0x3

    .line 229
    .line 230
    if-eq v2, v10, :cond_2

    .line 231
    .line 232
    move v2, v15

    .line 233
    goto :goto_1

    .line 234
    :cond_2
    move v2, v9

    .line 235
    :goto_1
    and-int/2addr v1, v15

    .line 236
    check-cast v0, Ll2/t;

    .line 237
    .line 238
    invoke-virtual {v0, v1, v2}, Ll2/t;->O(IZ)Z

    .line 239
    .line 240
    .line 241
    move-result v1

    .line 242
    if-eqz v1, :cond_6

    .line 243
    .line 244
    sget-object v1, Lj91/a;->a:Ll2/u2;

    .line 245
    .line 246
    invoke-virtual {v0, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 247
    .line 248
    .line 249
    move-result-object v2

    .line 250
    check-cast v2, Lj91/c;

    .line 251
    .line 252
    iget v2, v2, Lj91/c;->j:F

    .line 253
    .line 254
    invoke-static {v5, v2}, Landroidx/compose/foundation/layout/a;->m(Lx2/s;F)Lx2/s;

    .line 255
    .line 256
    .line 257
    move-result-object v2

    .line 258
    sget-object v6, Lk1/j;->c:Lk1/e;

    .line 259
    .line 260
    sget-object v7, Lx2/c;->p:Lx2/h;

    .line 261
    .line 262
    invoke-static {v6, v7, v0, v9}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 263
    .line 264
    .line 265
    move-result-object v6

    .line 266
    iget-wide v7, v0, Ll2/t;->T:J

    .line 267
    .line 268
    invoke-static {v7, v8}, Ljava/lang/Long;->hashCode(J)I

    .line 269
    .line 270
    .line 271
    move-result v7

    .line 272
    invoke-virtual {v0}, Ll2/t;->m()Ll2/p1;

    .line 273
    .line 274
    .line 275
    move-result-object v8

    .line 276
    invoke-static {v0, v2}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 277
    .line 278
    .line 279
    move-result-object v2

    .line 280
    sget-object v9, Lv3/k;->m1:Lv3/j;

    .line 281
    .line 282
    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 283
    .line 284
    .line 285
    sget-object v9, Lv3/j;->b:Lv3/i;

    .line 286
    .line 287
    invoke-virtual {v0}, Ll2/t;->c0()V

    .line 288
    .line 289
    .line 290
    iget-boolean v10, v0, Ll2/t;->S:Z

    .line 291
    .line 292
    if-eqz v10, :cond_3

    .line 293
    .line 294
    invoke-virtual {v0, v9}, Ll2/t;->l(Lay0/a;)V

    .line 295
    .line 296
    .line 297
    goto :goto_2

    .line 298
    :cond_3
    invoke-virtual {v0}, Ll2/t;->m0()V

    .line 299
    .line 300
    .line 301
    :goto_2
    sget-object v9, Lv3/j;->g:Lv3/h;

    .line 302
    .line 303
    invoke-static {v9, v6, v0}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 304
    .line 305
    .line 306
    sget-object v6, Lv3/j;->f:Lv3/h;

    .line 307
    .line 308
    invoke-static {v6, v8, v0}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 309
    .line 310
    .line 311
    sget-object v6, Lv3/j;->j:Lv3/h;

    .line 312
    .line 313
    iget-boolean v8, v0, Ll2/t;->S:Z

    .line 314
    .line 315
    if-nez v8, :cond_4

    .line 316
    .line 317
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 318
    .line 319
    .line 320
    move-result-object v8

    .line 321
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 322
    .line 323
    .line 324
    move-result-object v9

    .line 325
    invoke-static {v8, v9}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 326
    .line 327
    .line 328
    move-result v8

    .line 329
    if-nez v8, :cond_5

    .line 330
    .line 331
    :cond_4
    invoke-static {v7, v0, v7, v6}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 332
    .line 333
    .line 334
    :cond_5
    sget-object v6, Lv3/j;->d:Lv3/h;

    .line 335
    .line 336
    invoke-static {v6, v2, v0}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 337
    .line 338
    .line 339
    invoke-static {v5, v4}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 340
    .line 341
    .line 342
    move-result-object v18

    .line 343
    invoke-static {v0, v3}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 344
    .line 345
    .line 346
    move-result-object v16

    .line 347
    sget-object v2, Lj91/j;->a:Ll2/u2;

    .line 348
    .line 349
    invoke-virtual {v0, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 350
    .line 351
    .line 352
    move-result-object v3

    .line 353
    check-cast v3, Lj91/f;

    .line 354
    .line 355
    invoke-virtual {v3}, Lj91/f;->a()Lg4/p0;

    .line 356
    .line 357
    .line 358
    move-result-object v17

    .line 359
    sget-object v3, Lj91/h;->a:Ll2/u2;

    .line 360
    .line 361
    invoke-virtual {v0, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 362
    .line 363
    .line 364
    move-result-object v4

    .line 365
    check-cast v4, Lj91/e;

    .line 366
    .line 367
    invoke-virtual {v4}, Lj91/e;->s()J

    .line 368
    .line 369
    .line 370
    move-result-wide v19

    .line 371
    const/16 v36, 0x0

    .line 372
    .line 373
    const v37, 0xfff0

    .line 374
    .line 375
    .line 376
    const-wide/16 v21, 0x0

    .line 377
    .line 378
    const/16 v23, 0x0

    .line 379
    .line 380
    const-wide/16 v24, 0x0

    .line 381
    .line 382
    const/16 v26, 0x0

    .line 383
    .line 384
    const/16 v27, 0x0

    .line 385
    .line 386
    const-wide/16 v28, 0x0

    .line 387
    .line 388
    const/16 v30, 0x0

    .line 389
    .line 390
    const/16 v31, 0x0

    .line 391
    .line 392
    const/16 v32, 0x0

    .line 393
    .line 394
    const/16 v33, 0x0

    .line 395
    .line 396
    const/16 v35, 0x180

    .line 397
    .line 398
    move-object/from16 v34, v0

    .line 399
    .line 400
    invoke-static/range {v16 .. v37}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 401
    .line 402
    .line 403
    invoke-virtual {v0, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 404
    .line 405
    .line 406
    move-result-object v1

    .line 407
    check-cast v1, Lj91/c;

    .line 408
    .line 409
    iget v1, v1, Lj91/c;->c:F

    .line 410
    .line 411
    const-string v4, "trips_overview_no_trips"

    .line 412
    .line 413
    invoke-static {v5, v1, v0, v5, v4}, Lvj/b;->q(Lx2/p;FLl2/t;Lx2/p;Ljava/lang/String;)Lx2/s;

    .line 414
    .line 415
    .line 416
    move-result-object v18

    .line 417
    const v1, 0x7f12048b

    .line 418
    .line 419
    .line 420
    invoke-static {v0, v1}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 421
    .line 422
    .line 423
    move-result-object v16

    .line 424
    invoke-virtual {v0, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 425
    .line 426
    .line 427
    move-result-object v1

    .line 428
    check-cast v1, Lj91/f;

    .line 429
    .line 430
    invoke-virtual {v1}, Lj91/f;->k()Lg4/p0;

    .line 431
    .line 432
    .line 433
    move-result-object v17

    .line 434
    invoke-virtual {v0, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 435
    .line 436
    .line 437
    move-result-object v1

    .line 438
    check-cast v1, Lj91/e;

    .line 439
    .line 440
    invoke-virtual {v1}, Lj91/e;->q()J

    .line 441
    .line 442
    .line 443
    move-result-wide v19

    .line 444
    invoke-static/range {v16 .. v37}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 445
    .line 446
    .line 447
    invoke-virtual {v0, v15}, Ll2/t;->q(Z)V

    .line 448
    .line 449
    .line 450
    goto :goto_3

    .line 451
    :cond_6
    invoke-virtual {v0}, Ll2/t;->R()V

    .line 452
    .line 453
    .line 454
    :goto_3
    return-object v14

    .line 455
    :pswitch_8
    move-object/from16 v0, p1

    .line 456
    .line 457
    check-cast v0, Ll2/o;

    .line 458
    .line 459
    move-object/from16 v1, p2

    .line 460
    .line 461
    check-cast v1, Ljava/lang/Integer;

    .line 462
    .line 463
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 464
    .line 465
    .line 466
    move-result v1

    .line 467
    and-int/lit8 v2, v1, 0x3

    .line 468
    .line 469
    if-eq v2, v10, :cond_7

    .line 470
    .line 471
    move v2, v15

    .line 472
    goto :goto_4

    .line 473
    :cond_7
    move v2, v9

    .line 474
    :goto_4
    and-int/2addr v1, v15

    .line 475
    check-cast v0, Ll2/t;

    .line 476
    .line 477
    invoke-virtual {v0, v1, v2}, Ll2/t;->O(IZ)Z

    .line 478
    .line 479
    .line 480
    move-result v1

    .line 481
    if-eqz v1, :cond_b

    .line 482
    .line 483
    sget-object v1, Lj91/a;->a:Ll2/u2;

    .line 484
    .line 485
    invoke-virtual {v0, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 486
    .line 487
    .line 488
    move-result-object v2

    .line 489
    check-cast v2, Lj91/c;

    .line 490
    .line 491
    iget v2, v2, Lj91/c;->j:F

    .line 492
    .line 493
    invoke-static {v5, v2}, Landroidx/compose/foundation/layout/a;->m(Lx2/s;F)Lx2/s;

    .line 494
    .line 495
    .line 496
    move-result-object v2

    .line 497
    sget-object v6, Lk1/j;->c:Lk1/e;

    .line 498
    .line 499
    sget-object v7, Lx2/c;->p:Lx2/h;

    .line 500
    .line 501
    invoke-static {v6, v7, v0, v9}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 502
    .line 503
    .line 504
    move-result-object v6

    .line 505
    iget-wide v7, v0, Ll2/t;->T:J

    .line 506
    .line 507
    invoke-static {v7, v8}, Ljava/lang/Long;->hashCode(J)I

    .line 508
    .line 509
    .line 510
    move-result v7

    .line 511
    invoke-virtual {v0}, Ll2/t;->m()Ll2/p1;

    .line 512
    .line 513
    .line 514
    move-result-object v8

    .line 515
    invoke-static {v0, v2}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 516
    .line 517
    .line 518
    move-result-object v2

    .line 519
    sget-object v9, Lv3/k;->m1:Lv3/j;

    .line 520
    .line 521
    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 522
    .line 523
    .line 524
    sget-object v9, Lv3/j;->b:Lv3/i;

    .line 525
    .line 526
    invoke-virtual {v0}, Ll2/t;->c0()V

    .line 527
    .line 528
    .line 529
    iget-boolean v10, v0, Ll2/t;->S:Z

    .line 530
    .line 531
    if-eqz v10, :cond_8

    .line 532
    .line 533
    invoke-virtual {v0, v9}, Ll2/t;->l(Lay0/a;)V

    .line 534
    .line 535
    .line 536
    goto :goto_5

    .line 537
    :cond_8
    invoke-virtual {v0}, Ll2/t;->m0()V

    .line 538
    .line 539
    .line 540
    :goto_5
    sget-object v9, Lv3/j;->g:Lv3/h;

    .line 541
    .line 542
    invoke-static {v9, v6, v0}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 543
    .line 544
    .line 545
    sget-object v6, Lv3/j;->f:Lv3/h;

    .line 546
    .line 547
    invoke-static {v6, v8, v0}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 548
    .line 549
    .line 550
    sget-object v6, Lv3/j;->j:Lv3/h;

    .line 551
    .line 552
    iget-boolean v8, v0, Ll2/t;->S:Z

    .line 553
    .line 554
    if-nez v8, :cond_9

    .line 555
    .line 556
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 557
    .line 558
    .line 559
    move-result-object v8

    .line 560
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 561
    .line 562
    .line 563
    move-result-object v9

    .line 564
    invoke-static {v8, v9}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 565
    .line 566
    .line 567
    move-result v8

    .line 568
    if-nez v8, :cond_a

    .line 569
    .line 570
    :cond_9
    invoke-static {v7, v0, v7, v6}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 571
    .line 572
    .line 573
    :cond_a
    sget-object v6, Lv3/j;->d:Lv3/h;

    .line 574
    .line 575
    invoke-static {v6, v2, v0}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 576
    .line 577
    .line 578
    invoke-static {v5, v4}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 579
    .line 580
    .line 581
    move-result-object v18

    .line 582
    invoke-static {v0, v3}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 583
    .line 584
    .line 585
    move-result-object v16

    .line 586
    sget-object v2, Lj91/j;->a:Ll2/u2;

    .line 587
    .line 588
    invoke-virtual {v0, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 589
    .line 590
    .line 591
    move-result-object v3

    .line 592
    check-cast v3, Lj91/f;

    .line 593
    .line 594
    invoke-virtual {v3}, Lj91/f;->a()Lg4/p0;

    .line 595
    .line 596
    .line 597
    move-result-object v17

    .line 598
    sget-object v3, Lj91/h;->a:Ll2/u2;

    .line 599
    .line 600
    invoke-virtual {v0, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 601
    .line 602
    .line 603
    move-result-object v4

    .line 604
    check-cast v4, Lj91/e;

    .line 605
    .line 606
    invoke-virtual {v4}, Lj91/e;->s()J

    .line 607
    .line 608
    .line 609
    move-result-wide v19

    .line 610
    const/16 v36, 0x0

    .line 611
    .line 612
    const v37, 0xfff0

    .line 613
    .line 614
    .line 615
    const-wide/16 v21, 0x0

    .line 616
    .line 617
    const/16 v23, 0x0

    .line 618
    .line 619
    const-wide/16 v24, 0x0

    .line 620
    .line 621
    const/16 v26, 0x0

    .line 622
    .line 623
    const/16 v27, 0x0

    .line 624
    .line 625
    const-wide/16 v28, 0x0

    .line 626
    .line 627
    const/16 v30, 0x0

    .line 628
    .line 629
    const/16 v31, 0x0

    .line 630
    .line 631
    const/16 v32, 0x0

    .line 632
    .line 633
    const/16 v33, 0x0

    .line 634
    .line 635
    const/16 v35, 0x180

    .line 636
    .line 637
    move-object/from16 v34, v0

    .line 638
    .line 639
    invoke-static/range {v16 .. v37}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 640
    .line 641
    .line 642
    invoke-virtual {v0, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 643
    .line 644
    .line 645
    move-result-object v1

    .line 646
    check-cast v1, Lj91/c;

    .line 647
    .line 648
    iget v1, v1, Lj91/c;->c:F

    .line 649
    .line 650
    const-string v4, "trips_overview_unavailable"

    .line 651
    .line 652
    invoke-static {v5, v1, v0, v5, v4}, Lvj/b;->q(Lx2/p;FLl2/t;Lx2/p;Ljava/lang/String;)Lx2/s;

    .line 653
    .line 654
    .line 655
    move-result-object v18

    .line 656
    const v1, 0x7f12025d

    .line 657
    .line 658
    .line 659
    invoke-static {v0, v1}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 660
    .line 661
    .line 662
    move-result-object v16

    .line 663
    invoke-virtual {v0, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 664
    .line 665
    .line 666
    move-result-object v1

    .line 667
    check-cast v1, Lj91/f;

    .line 668
    .line 669
    invoke-virtual {v1}, Lj91/f;->k()Lg4/p0;

    .line 670
    .line 671
    .line 672
    move-result-object v17

    .line 673
    invoke-virtual {v0, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 674
    .line 675
    .line 676
    move-result-object v1

    .line 677
    check-cast v1, Lj91/e;

    .line 678
    .line 679
    invoke-virtual {v1}, Lj91/e;->q()J

    .line 680
    .line 681
    .line 682
    move-result-wide v19

    .line 683
    invoke-static/range {v16 .. v37}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 684
    .line 685
    .line 686
    invoke-virtual {v0, v15}, Ll2/t;->q(Z)V

    .line 687
    .line 688
    .line 689
    goto :goto_6

    .line 690
    :cond_b
    invoke-virtual {v0}, Ll2/t;->R()V

    .line 691
    .line 692
    .line 693
    :goto_6
    return-object v14

    .line 694
    :pswitch_9
    move-object/from16 v0, p1

    .line 695
    .line 696
    check-cast v0, Ll2/o;

    .line 697
    .line 698
    move-object/from16 v1, p2

    .line 699
    .line 700
    check-cast v1, Ljava/lang/Integer;

    .line 701
    .line 702
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 703
    .line 704
    .line 705
    move-result v1

    .line 706
    and-int/lit8 v2, v1, 0x3

    .line 707
    .line 708
    if-eq v2, v10, :cond_c

    .line 709
    .line 710
    move v2, v15

    .line 711
    goto :goto_7

    .line 712
    :cond_c
    move v2, v9

    .line 713
    :goto_7
    and-int/2addr v1, v15

    .line 714
    check-cast v0, Ll2/t;

    .line 715
    .line 716
    invoke-virtual {v0, v1, v2}, Ll2/t;->O(IZ)Z

    .line 717
    .line 718
    .line 719
    move-result v1

    .line 720
    if-eqz v1, :cond_10

    .line 721
    .line 722
    const/high16 v1, 0x3f800000    # 1.0f

    .line 723
    .line 724
    invoke-static {v5, v1}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 725
    .line 726
    .line 727
    move-result-object v1

    .line 728
    sget-object v2, Lj91/a;->a:Ll2/u2;

    .line 729
    .line 730
    invoke-virtual {v0, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 731
    .line 732
    .line 733
    move-result-object v3

    .line 734
    check-cast v3, Lj91/c;

    .line 735
    .line 736
    iget v3, v3, Lj91/c;->d:F

    .line 737
    .line 738
    invoke-static {v1, v3}, Landroidx/compose/foundation/layout/a;->m(Lx2/s;F)Lx2/s;

    .line 739
    .line 740
    .line 741
    move-result-object v1

    .line 742
    sget-object v3, Lk1/j;->a:Lk1/c;

    .line 743
    .line 744
    invoke-virtual {v0, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 745
    .line 746
    .line 747
    move-result-object v2

    .line 748
    check-cast v2, Lj91/c;

    .line 749
    .line 750
    iget v2, v2, Lj91/c;->c:F

    .line 751
    .line 752
    invoke-static {v2}, Lk1/j;->g(F)Lk1/h;

    .line 753
    .line 754
    .line 755
    move-result-object v2

    .line 756
    sget-object v3, Lx2/c;->p:Lx2/h;

    .line 757
    .line 758
    invoke-static {v2, v3, v0, v9}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 759
    .line 760
    .line 761
    move-result-object v2

    .line 762
    iget-wide v3, v0, Ll2/t;->T:J

    .line 763
    .line 764
    invoke-static {v3, v4}, Ljava/lang/Long;->hashCode(J)I

    .line 765
    .line 766
    .line 767
    move-result v3

    .line 768
    invoke-virtual {v0}, Ll2/t;->m()Ll2/p1;

    .line 769
    .line 770
    .line 771
    move-result-object v4

    .line 772
    invoke-static {v0, v1}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 773
    .line 774
    .line 775
    move-result-object v1

    .line 776
    sget-object v5, Lv3/k;->m1:Lv3/j;

    .line 777
    .line 778
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 779
    .line 780
    .line 781
    sget-object v5, Lv3/j;->b:Lv3/i;

    .line 782
    .line 783
    invoke-virtual {v0}, Ll2/t;->c0()V

    .line 784
    .line 785
    .line 786
    iget-boolean v6, v0, Ll2/t;->S:Z

    .line 787
    .line 788
    if-eqz v6, :cond_d

    .line 789
    .line 790
    invoke-virtual {v0, v5}, Ll2/t;->l(Lay0/a;)V

    .line 791
    .line 792
    .line 793
    goto :goto_8

    .line 794
    :cond_d
    invoke-virtual {v0}, Ll2/t;->m0()V

    .line 795
    .line 796
    .line 797
    :goto_8
    sget-object v5, Lv3/j;->g:Lv3/h;

    .line 798
    .line 799
    invoke-static {v5, v2, v0}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 800
    .line 801
    .line 802
    sget-object v2, Lv3/j;->f:Lv3/h;

    .line 803
    .line 804
    invoke-static {v2, v4, v0}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 805
    .line 806
    .line 807
    sget-object v2, Lv3/j;->j:Lv3/h;

    .line 808
    .line 809
    iget-boolean v4, v0, Ll2/t;->S:Z

    .line 810
    .line 811
    if-nez v4, :cond_e

    .line 812
    .line 813
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 814
    .line 815
    .line 816
    move-result-object v4

    .line 817
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 818
    .line 819
    .line 820
    move-result-object v5

    .line 821
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 822
    .line 823
    .line 824
    move-result v4

    .line 825
    if-nez v4, :cond_f

    .line 826
    .line 827
    :cond_e
    invoke-static {v3, v0, v3, v2}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 828
    .line 829
    .line 830
    :cond_f
    sget-object v2, Lv3/j;->d:Lv3/h;

    .line 831
    .line 832
    invoke-static {v2, v1, v0}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 833
    .line 834
    .line 835
    const v1, 0x7f12028b

    .line 836
    .line 837
    .line 838
    invoke-static {v0, v1}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 839
    .line 840
    .line 841
    move-result-object v16

    .line 842
    sget-object v1, Lj91/j;->a:Ll2/u2;

    .line 843
    .line 844
    invoke-virtual {v0, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 845
    .line 846
    .line 847
    move-result-object v2

    .line 848
    check-cast v2, Lj91/f;

    .line 849
    .line 850
    invoke-virtual {v2}, Lj91/f;->k()Lg4/p0;

    .line 851
    .line 852
    .line 853
    move-result-object v17

    .line 854
    const/16 v36, 0x0

    .line 855
    .line 856
    const v37, 0xfffc

    .line 857
    .line 858
    .line 859
    const/16 v18, 0x0

    .line 860
    .line 861
    const-wide/16 v19, 0x0

    .line 862
    .line 863
    const-wide/16 v21, 0x0

    .line 864
    .line 865
    const/16 v23, 0x0

    .line 866
    .line 867
    const-wide/16 v24, 0x0

    .line 868
    .line 869
    const/16 v26, 0x0

    .line 870
    .line 871
    const/16 v27, 0x0

    .line 872
    .line 873
    const-wide/16 v28, 0x0

    .line 874
    .line 875
    const/16 v30, 0x0

    .line 876
    .line 877
    const/16 v31, 0x0

    .line 878
    .line 879
    const/16 v32, 0x0

    .line 880
    .line 881
    const/16 v33, 0x0

    .line 882
    .line 883
    const/16 v35, 0x0

    .line 884
    .line 885
    move-object/from16 v34, v0

    .line 886
    .line 887
    invoke-static/range {v16 .. v37}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 888
    .line 889
    .line 890
    const v2, 0x7f12028a

    .line 891
    .line 892
    .line 893
    invoke-static {v0, v2}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 894
    .line 895
    .line 896
    move-result-object v16

    .line 897
    sget-object v2, Lj91/h;->a:Ll2/u2;

    .line 898
    .line 899
    invoke-virtual {v0, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 900
    .line 901
    .line 902
    move-result-object v2

    .line 903
    check-cast v2, Lj91/e;

    .line 904
    .line 905
    invoke-virtual {v2}, Lj91/e;->s()J

    .line 906
    .line 907
    .line 908
    move-result-wide v19

    .line 909
    invoke-virtual {v0, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 910
    .line 911
    .line 912
    move-result-object v1

    .line 913
    check-cast v1, Lj91/f;

    .line 914
    .line 915
    invoke-virtual {v1}, Lj91/f;->a()Lg4/p0;

    .line 916
    .line 917
    .line 918
    move-result-object v17

    .line 919
    const v37, 0xfff4

    .line 920
    .line 921
    .line 922
    invoke-static/range {v16 .. v37}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 923
    .line 924
    .line 925
    invoke-virtual {v0, v15}, Ll2/t;->q(Z)V

    .line 926
    .line 927
    .line 928
    goto :goto_9

    .line 929
    :cond_10
    invoke-virtual {v0}, Ll2/t;->R()V

    .line 930
    .line 931
    .line 932
    :goto_9
    return-object v14

    .line 933
    :pswitch_a
    move-object/from16 v0, p1

    .line 934
    .line 935
    check-cast v0, Ll2/o;

    .line 936
    .line 937
    move-object/from16 v1, p2

    .line 938
    .line 939
    check-cast v1, Ljava/lang/Integer;

    .line 940
    .line 941
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 942
    .line 943
    .line 944
    move-result v1

    .line 945
    and-int/lit8 v2, v1, 0x3

    .line 946
    .line 947
    if-eq v2, v10, :cond_11

    .line 948
    .line 949
    move v9, v15

    .line 950
    :cond_11
    and-int/2addr v1, v15

    .line 951
    move-object v5, v0

    .line 952
    check-cast v5, Ll2/t;

    .line 953
    .line 954
    invoke-virtual {v5, v1, v9}, Ll2/t;->O(IZ)Z

    .line 955
    .line 956
    .line 957
    move-result v0

    .line 958
    if-eqz v0, :cond_12

    .line 959
    .line 960
    new-instance v2, Lm70/v;

    .line 961
    .line 962
    sget-object v0, Llf0/i;->e:Llf0/i;

    .line 963
    .line 964
    invoke-direct {v2, v0}, Lm70/v;-><init>(Llf0/i;)V

    .line 965
    .line 966
    .line 967
    const/4 v6, 0x0

    .line 968
    const/4 v7, 0x6

    .line 969
    const/4 v3, 0x0

    .line 970
    const/4 v4, 0x0

    .line 971
    invoke-static/range {v2 .. v7}, Ln70/a;->G(Lm70/v;Lx2/s;Lay0/a;Ll2/o;II)V

    .line 972
    .line 973
    .line 974
    goto :goto_a

    .line 975
    :cond_12
    invoke-virtual {v5}, Ll2/t;->R()V

    .line 976
    .line 977
    .line 978
    :goto_a
    return-object v14

    .line 979
    :pswitch_b
    move-object/from16 v0, p1

    .line 980
    .line 981
    check-cast v0, Lk21/a;

    .line 982
    .line 983
    move-object/from16 v1, p2

    .line 984
    .line 985
    check-cast v1, Lg21/a;

    .line 986
    .line 987
    invoke-static {v0, v12}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 988
    .line 989
    .line 990
    invoke-static {v1, v13}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 991
    .line 992
    .line 993
    const-class v0, Lcz/skodaauto/myskoda/feature/mapfueling/system/StartSessionPollingService;

    .line 994
    .line 995
    return-object v0

    .line 996
    :pswitch_c
    move-object/from16 v0, p1

    .line 997
    .line 998
    check-cast v0, Lk21/a;

    .line 999
    .line 1000
    move-object/from16 v1, p2

    .line 1001
    .line 1002
    check-cast v1, Lg21/a;

    .line 1003
    .line 1004
    invoke-static {v0, v12}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1005
    .line 1006
    .line 1007
    invoke-static {v1, v13}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1008
    .line 1009
    .line 1010
    new-instance v1, Lm40/d;

    .line 1011
    .line 1012
    const-class v2, Lve0/u;

    .line 1013
    .line 1014
    sget-object v3, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1015
    .line 1016
    invoke-virtual {v3, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1017
    .line 1018
    .line 1019
    move-result-object v2

    .line 1020
    invoke-virtual {v0, v2, v11, v11}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1021
    .line 1022
    .line 1023
    move-result-object v0

    .line 1024
    check-cast v0, Lve0/u;

    .line 1025
    .line 1026
    invoke-direct {v1, v0}, Lm40/d;-><init>(Lve0/u;)V

    .line 1027
    .line 1028
    .line 1029
    return-object v1

    .line 1030
    :pswitch_d
    move-object/from16 v0, p1

    .line 1031
    .line 1032
    check-cast v0, Lk21/a;

    .line 1033
    .line 1034
    move-object/from16 v1, p2

    .line 1035
    .line 1036
    check-cast v1, Lg21/a;

    .line 1037
    .line 1038
    invoke-static {v0, v12}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1039
    .line 1040
    .line 1041
    invoke-static {v1, v13}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1042
    .line 1043
    .line 1044
    new-instance v0, Lm40/a;

    .line 1045
    .line 1046
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 1047
    .line 1048
    .line 1049
    return-object v0

    .line 1050
    :pswitch_e
    move-object/from16 v0, p1

    .line 1051
    .line 1052
    check-cast v0, Lk21/a;

    .line 1053
    .line 1054
    move-object/from16 v1, p2

    .line 1055
    .line 1056
    check-cast v1, Lg21/a;

    .line 1057
    .line 1058
    invoke-static {v0, v12}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1059
    .line 1060
    .line 1061
    invoke-static {v1, v13}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1062
    .line 1063
    .line 1064
    new-instance v0, Lm40/b;

    .line 1065
    .line 1066
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 1067
    .line 1068
    .line 1069
    const-string v1, ""

    .line 1070
    .line 1071
    iput-object v1, v0, Lm40/b;->a:Ljava/lang/String;

    .line 1072
    .line 1073
    return-object v0

    .line 1074
    :pswitch_f
    move-object/from16 v0, p1

    .line 1075
    .line 1076
    check-cast v0, Lk21/a;

    .line 1077
    .line 1078
    move-object/from16 v1, p2

    .line 1079
    .line 1080
    check-cast v1, Lg21/a;

    .line 1081
    .line 1082
    invoke-static {v0, v12}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1083
    .line 1084
    .line 1085
    invoke-static {v1, v13}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1086
    .line 1087
    .line 1088
    new-instance v1, Lm40/g;

    .line 1089
    .line 1090
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1091
    .line 1092
    invoke-virtual {v2, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1093
    .line 1094
    .line 1095
    move-result-object v3

    .line 1096
    invoke-virtual {v0, v3, v11, v11}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1097
    .line 1098
    .line 1099
    move-result-object v3

    .line 1100
    check-cast v3, Lxl0/f;

    .line 1101
    .line 1102
    const-class v4, Lcz/myskoda/api/bff_fueling/v2/FuelingApi;

    .line 1103
    .line 1104
    invoke-static {v2, v4, v8}, Lia/b;->f(Lkotlin/jvm/internal/h0;Ljava/lang/Class;Ljava/lang/String;)Lh21/b;

    .line 1105
    .line 1106
    .line 1107
    move-result-object v4

    .line 1108
    invoke-virtual {v2, v7}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1109
    .line 1110
    .line 1111
    move-result-object v2

    .line 1112
    invoke-virtual {v0, v2, v4, v11}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1113
    .line 1114
    .line 1115
    move-result-object v0

    .line 1116
    check-cast v0, Lti0/a;

    .line 1117
    .line 1118
    invoke-direct {v1, v3, v0}, Lm40/g;-><init>(Lxl0/f;Lti0/a;)V

    .line 1119
    .line 1120
    .line 1121
    return-object v1

    .line 1122
    :pswitch_10
    move-object/from16 v0, p1

    .line 1123
    .line 1124
    check-cast v0, Lk21/a;

    .line 1125
    .line 1126
    move-object/from16 v1, p2

    .line 1127
    .line 1128
    check-cast v1, Lg21/a;

    .line 1129
    .line 1130
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1131
    .line 1132
    .line 1133
    invoke-static {v1, v13}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1134
    .line 1135
    .line 1136
    new-instance v14, Lq40/c;

    .line 1137
    .line 1138
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1139
    .line 1140
    const-class v2, Lo40/h;

    .line 1141
    .line 1142
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1143
    .line 1144
    .line 1145
    move-result-object v2

    .line 1146
    invoke-virtual {v0, v2, v11, v11}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1147
    .line 1148
    .line 1149
    move-result-object v2

    .line 1150
    move-object v15, v2

    .line 1151
    check-cast v15, Lo40/h;

    .line 1152
    .line 1153
    const-class v2, Lxh0/d;

    .line 1154
    .line 1155
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1156
    .line 1157
    .line 1158
    move-result-object v2

    .line 1159
    invoke-virtual {v0, v2, v11, v11}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1160
    .line 1161
    .line 1162
    move-result-object v2

    .line 1163
    move-object/from16 v16, v2

    .line 1164
    .line 1165
    check-cast v16, Lxh0/d;

    .line 1166
    .line 1167
    const-class v2, Lnn0/j;

    .line 1168
    .line 1169
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1170
    .line 1171
    .line 1172
    move-result-object v2

    .line 1173
    invoke-virtual {v0, v2, v11, v11}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1174
    .line 1175
    .line 1176
    move-result-object v2

    .line 1177
    move-object/from16 v17, v2

    .line 1178
    .line 1179
    check-cast v17, Lnn0/j;

    .line 1180
    .line 1181
    const-class v2, Lo40/t;

    .line 1182
    .line 1183
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1184
    .line 1185
    .line 1186
    move-result-object v2

    .line 1187
    invoke-virtual {v0, v2, v11, v11}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1188
    .line 1189
    .line 1190
    move-result-object v2

    .line 1191
    move-object/from16 v18, v2

    .line 1192
    .line 1193
    check-cast v18, Lo40/t;

    .line 1194
    .line 1195
    const-string v2, "start_fueling_session"

    .line 1196
    .line 1197
    invoke-static {v2}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 1198
    .line 1199
    .line 1200
    move-result-object v2

    .line 1201
    const-class v3, Ljava/lang/Class;

    .line 1202
    .line 1203
    invoke-virtual {v1, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1204
    .line 1205
    .line 1206
    move-result-object v3

    .line 1207
    invoke-virtual {v0, v3, v2, v11}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1208
    .line 1209
    .line 1210
    move-result-object v2

    .line 1211
    move-object/from16 v19, v2

    .line 1212
    .line 1213
    check-cast v19, Ljava/lang/Class;

    .line 1214
    .line 1215
    const-class v2, Lo40/s;

    .line 1216
    .line 1217
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1218
    .line 1219
    .line 1220
    move-result-object v2

    .line 1221
    invoke-virtual {v0, v2, v11, v11}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1222
    .line 1223
    .line 1224
    move-result-object v2

    .line 1225
    move-object/from16 v20, v2

    .line 1226
    .line 1227
    check-cast v20, Lo40/s;

    .line 1228
    .line 1229
    const-class v2, Lo40/f;

    .line 1230
    .line 1231
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1232
    .line 1233
    .line 1234
    move-result-object v2

    .line 1235
    invoke-virtual {v0, v2, v11, v11}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1236
    .line 1237
    .line 1238
    move-result-object v2

    .line 1239
    move-object/from16 v21, v2

    .line 1240
    .line 1241
    check-cast v21, Lo40/f;

    .line 1242
    .line 1243
    const-class v2, Ltr0/b;

    .line 1244
    .line 1245
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1246
    .line 1247
    .line 1248
    move-result-object v1

    .line 1249
    invoke-virtual {v0, v1, v11, v11}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1250
    .line 1251
    .line 1252
    move-result-object v0

    .line 1253
    move-object/from16 v22, v0

    .line 1254
    .line 1255
    check-cast v22, Ltr0/b;

    .line 1256
    .line 1257
    invoke-direct/range {v14 .. v22}, Lq40/c;-><init>(Lo40/h;Lxh0/d;Lnn0/j;Lo40/t;Ljava/lang/Class;Lo40/s;Lo40/f;Ltr0/b;)V

    .line 1258
    .line 1259
    .line 1260
    return-object v14

    .line 1261
    :pswitch_11
    move-object/from16 v0, p1

    .line 1262
    .line 1263
    check-cast v0, Lk21/a;

    .line 1264
    .line 1265
    move-object/from16 v1, p2

    .line 1266
    .line 1267
    check-cast v1, Lg21/a;

    .line 1268
    .line 1269
    invoke-static {v0, v12}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1270
    .line 1271
    .line 1272
    invoke-static {v1, v13}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1273
    .line 1274
    .line 1275
    new-instance v1, Lm30/e;

    .line 1276
    .line 1277
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1278
    .line 1279
    invoke-virtual {v2, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1280
    .line 1281
    .line 1282
    move-result-object v3

    .line 1283
    invoke-virtual {v0, v3, v11, v11}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1284
    .line 1285
    .line 1286
    move-result-object v3

    .line 1287
    check-cast v3, Lxl0/f;

    .line 1288
    .line 1289
    const-class v4, Lcz/myskoda/api/bff_ai_assistant/v2/AiAssistantApi;

    .line 1290
    .line 1291
    invoke-static {v2, v4, v8}, Lia/b;->f(Lkotlin/jvm/internal/h0;Ljava/lang/Class;Ljava/lang/String;)Lh21/b;

    .line 1292
    .line 1293
    .line 1294
    move-result-object v4

    .line 1295
    invoke-virtual {v2, v7}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1296
    .line 1297
    .line 1298
    move-result-object v2

    .line 1299
    invoke-virtual {v0, v2, v4, v11}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1300
    .line 1301
    .line 1302
    move-result-object v0

    .line 1303
    check-cast v0, Lti0/a;

    .line 1304
    .line 1305
    invoke-direct {v1, v3, v0}, Lm30/e;-><init>(Lxl0/f;Lti0/a;)V

    .line 1306
    .line 1307
    .line 1308
    return-object v1

    .line 1309
    :pswitch_12
    move-object/from16 v0, p1

    .line 1310
    .line 1311
    check-cast v0, Lk21/a;

    .line 1312
    .line 1313
    move-object/from16 v1, p2

    .line 1314
    .line 1315
    check-cast v1, Lg21/a;

    .line 1316
    .line 1317
    invoke-static {v0, v12}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1318
    .line 1319
    .line 1320
    invoke-static {v1, v13}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1321
    .line 1322
    .line 1323
    new-instance v1, Lm20/d;

    .line 1324
    .line 1325
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1326
    .line 1327
    invoke-virtual {v2, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1328
    .line 1329
    .line 1330
    move-result-object v3

    .line 1331
    invoke-virtual {v0, v3, v11, v11}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1332
    .line 1333
    .line 1334
    move-result-object v3

    .line 1335
    check-cast v3, Lxl0/f;

    .line 1336
    .line 1337
    const-class v4, Lcz/myskoda/api/bff_garage/v2/GarageApi;

    .line 1338
    .line 1339
    invoke-static {v2, v4, v8}, Lia/b;->f(Lkotlin/jvm/internal/h0;Ljava/lang/Class;Ljava/lang/String;)Lh21/b;

    .line 1340
    .line 1341
    .line 1342
    move-result-object v4

    .line 1343
    invoke-virtual {v2, v7}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1344
    .line 1345
    .line 1346
    move-result-object v2

    .line 1347
    invoke-virtual {v0, v2, v4, v11}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1348
    .line 1349
    .line 1350
    move-result-object v0

    .line 1351
    check-cast v0, Lti0/a;

    .line 1352
    .line 1353
    invoke-direct {v1, v3, v0}, Lm20/d;-><init>(Lxl0/f;Lti0/a;)V

    .line 1354
    .line 1355
    .line 1356
    return-object v1

    .line 1357
    :pswitch_13
    move-object/from16 v0, p1

    .line 1358
    .line 1359
    check-cast v0, Lk21/a;

    .line 1360
    .line 1361
    move-object/from16 v2, p2

    .line 1362
    .line 1363
    check-cast v2, Lg21/a;

    .line 1364
    .line 1365
    invoke-static {v0, v12}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1366
    .line 1367
    .line 1368
    invoke-static {v2, v13}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1369
    .line 1370
    .line 1371
    new-instance v2, Lm20/j;

    .line 1372
    .line 1373
    sget-object v3, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1374
    .line 1375
    const-class v4, Lm20/a;

    .line 1376
    .line 1377
    invoke-static {v3, v4, v8}, Lia/b;->f(Lkotlin/jvm/internal/h0;Ljava/lang/Class;Ljava/lang/String;)Lh21/b;

    .line 1378
    .line 1379
    .line 1380
    move-result-object v4

    .line 1381
    invoke-virtual {v3, v7}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1382
    .line 1383
    .line 1384
    move-result-object v5

    .line 1385
    invoke-virtual {v0, v5, v4, v11}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1386
    .line 1387
    .line 1388
    move-result-object v4

    .line 1389
    check-cast v4, Lti0/a;

    .line 1390
    .line 1391
    invoke-virtual {v3, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1392
    .line 1393
    .line 1394
    move-result-object v1

    .line 1395
    invoke-virtual {v0, v1, v11, v11}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1396
    .line 1397
    .line 1398
    move-result-object v0

    .line 1399
    check-cast v0, Lwe0/a;

    .line 1400
    .line 1401
    invoke-direct {v2, v4, v0}, Lm20/j;-><init>(Lti0/a;Lwe0/a;)V

    .line 1402
    .line 1403
    .line 1404
    return-object v2

    .line 1405
    :pswitch_14
    move-object/from16 v0, p1

    .line 1406
    .line 1407
    check-cast v0, Ll2/o;

    .line 1408
    .line 1409
    move-object/from16 v1, p2

    .line 1410
    .line 1411
    check-cast v1, Ljava/lang/Integer;

    .line 1412
    .line 1413
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1414
    .line 1415
    .line 1416
    invoke-static {v15}, Ll2/b;->x(I)I

    .line 1417
    .line 1418
    .line 1419
    move-result v1

    .line 1420
    invoke-static {v0, v1}, Ljp/t1;->b(Ll2/o;I)V

    .line 1421
    .line 1422
    .line 1423
    return-object v14

    .line 1424
    :pswitch_15
    move-object/from16 v0, p1

    .line 1425
    .line 1426
    check-cast v0, Lu2/b;

    .line 1427
    .line 1428
    move-object/from16 v0, p2

    .line 1429
    .line 1430
    check-cast v0, Ln1/v;

    .line 1431
    .line 1432
    iget-object v1, v0, Ln1/v;->d:Lm1/o;

    .line 1433
    .line 1434
    iget-object v1, v1, Lm1/o;->b:Ll2/g1;

    .line 1435
    .line 1436
    invoke-virtual {v1}, Ll2/g1;->o()I

    .line 1437
    .line 1438
    .line 1439
    move-result v1

    .line 1440
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1441
    .line 1442
    .line 1443
    move-result-object v1

    .line 1444
    iget-object v0, v0, Ln1/v;->d:Lm1/o;

    .line 1445
    .line 1446
    iget-object v0, v0, Lm1/o;->c:Ll2/g1;

    .line 1447
    .line 1448
    invoke-virtual {v0}, Ll2/g1;->o()I

    .line 1449
    .line 1450
    .line 1451
    move-result v0

    .line 1452
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1453
    .line 1454
    .line 1455
    move-result-object v0

    .line 1456
    filled-new-array {v1, v0}, [Ljava/lang/Integer;

    .line 1457
    .line 1458
    .line 1459
    move-result-object v0

    .line 1460
    invoke-static {v0}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 1461
    .line 1462
    .line 1463
    move-result-object v0

    .line 1464
    return-object v0

    .line 1465
    :pswitch_16
    move-object/from16 v0, p1

    .line 1466
    .line 1467
    check-cast v0, Ln1/s;

    .line 1468
    .line 1469
    move-object/from16 v0, p2

    .line 1470
    .line 1471
    check-cast v0, Ljava/lang/Integer;

    .line 1472
    .line 1473
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1474
    .line 1475
    .line 1476
    int-to-long v0, v15

    .line 1477
    new-instance v2, Ln1/b;

    .line 1478
    .line 1479
    invoke-direct {v2, v0, v1}, Ln1/b;-><init>(J)V

    .line 1480
    .line 1481
    .line 1482
    return-object v2

    .line 1483
    :pswitch_17
    move-object/from16 v0, p1

    .line 1484
    .line 1485
    check-cast v0, Ll2/o;

    .line 1486
    .line 1487
    move-object/from16 v1, p2

    .line 1488
    .line 1489
    check-cast v1, Ljava/lang/Integer;

    .line 1490
    .line 1491
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1492
    .line 1493
    .line 1494
    invoke-static {v15}, Ll2/b;->x(I)I

    .line 1495
    .line 1496
    .line 1497
    move-result v1

    .line 1498
    invoke-static {v0, v1}, Ljp/i1;->h(Ll2/o;I)V

    .line 1499
    .line 1500
    .line 1501
    return-object v14

    .line 1502
    :pswitch_18
    move-object/from16 v0, p1

    .line 1503
    .line 1504
    check-cast v0, Ll2/o;

    .line 1505
    .line 1506
    move-object/from16 v1, p2

    .line 1507
    .line 1508
    check-cast v1, Ljava/lang/Integer;

    .line 1509
    .line 1510
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1511
    .line 1512
    .line 1513
    invoke-static {v15}, Ll2/b;->x(I)I

    .line 1514
    .line 1515
    .line 1516
    move-result v1

    .line 1517
    invoke-static {v0, v1}, Ljp/i1;->f(Ll2/o;I)V

    .line 1518
    .line 1519
    .line 1520
    return-object v14

    .line 1521
    :pswitch_19
    move-object/from16 v0, p1

    .line 1522
    .line 1523
    check-cast v0, Ll2/o;

    .line 1524
    .line 1525
    move-object/from16 v1, p2

    .line 1526
    .line 1527
    check-cast v1, Ljava/lang/Integer;

    .line 1528
    .line 1529
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1530
    .line 1531
    .line 1532
    invoke-static {v15}, Ll2/b;->x(I)I

    .line 1533
    .line 1534
    .line 1535
    move-result v1

    .line 1536
    invoke-static {v0, v1}, Ljp/i1;->i(Ll2/o;I)V

    .line 1537
    .line 1538
    .line 1539
    return-object v14

    .line 1540
    :pswitch_1a
    move-object/from16 v0, p1

    .line 1541
    .line 1542
    check-cast v0, Lk21/a;

    .line 1543
    .line 1544
    move-object/from16 v1, p2

    .line 1545
    .line 1546
    check-cast v1, Lg21/a;

    .line 1547
    .line 1548
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1549
    .line 1550
    .line 1551
    invoke-static {v1, v13}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1552
    .line 1553
    .line 1554
    new-instance v1, Lor0/b;

    .line 1555
    .line 1556
    sget-object v2, Lmr0/a;->a:Leo0/b;

    .line 1557
    .line 1558
    iget-object v3, v2, Leo0/b;->b:Ljava/lang/String;

    .line 1559
    .line 1560
    invoke-static {v3}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 1561
    .line 1562
    .line 1563
    move-result-object v3

    .line 1564
    sget-object v4, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1565
    .line 1566
    const-class v5, Lfo0/b;

    .line 1567
    .line 1568
    invoke-virtual {v4, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1569
    .line 1570
    .line 1571
    move-result-object v5

    .line 1572
    invoke-virtual {v0, v5, v3, v11}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1573
    .line 1574
    .line 1575
    move-result-object v3

    .line 1576
    check-cast v3, Lfo0/b;

    .line 1577
    .line 1578
    iget-object v2, v2, Leo0/b;->b:Ljava/lang/String;

    .line 1579
    .line 1580
    invoke-static {v2}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 1581
    .line 1582
    .line 1583
    move-result-object v2

    .line 1584
    const-class v5, Lfo0/c;

    .line 1585
    .line 1586
    invoke-virtual {v4, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1587
    .line 1588
    .line 1589
    move-result-object v5

    .line 1590
    invoke-virtual {v0, v5, v2, v11}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1591
    .line 1592
    .line 1593
    move-result-object v2

    .line 1594
    check-cast v2, Lfo0/c;

    .line 1595
    .line 1596
    const-class v5, Lnr0/e;

    .line 1597
    .line 1598
    invoke-virtual {v4, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1599
    .line 1600
    .line 1601
    move-result-object v4

    .line 1602
    invoke-virtual {v0, v4, v11, v11}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1603
    .line 1604
    .line 1605
    move-result-object v0

    .line 1606
    check-cast v0, Lnr0/e;

    .line 1607
    .line 1608
    invoke-direct {v1, v3, v2, v0}, Lor0/b;-><init>(Lfo0/b;Lfo0/c;Lnr0/e;)V

    .line 1609
    .line 1610
    .line 1611
    return-object v1

    .line 1612
    :pswitch_1b
    move-object/from16 v0, p1

    .line 1613
    .line 1614
    check-cast v0, Lk21/a;

    .line 1615
    .line 1616
    move-object/from16 v1, p2

    .line 1617
    .line 1618
    check-cast v1, Lg21/a;

    .line 1619
    .line 1620
    invoke-static {v0, v12}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1621
    .line 1622
    .line 1623
    invoke-static {v1, v13}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1624
    .line 1625
    .line 1626
    new-instance v1, Llo0/c;

    .line 1627
    .line 1628
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1629
    .line 1630
    invoke-virtual {v2, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1631
    .line 1632
    .line 1633
    move-result-object v3

    .line 1634
    invoke-virtual {v0, v3, v11, v11}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1635
    .line 1636
    .line 1637
    move-result-object v3

    .line 1638
    check-cast v3, Lxl0/f;

    .line 1639
    .line 1640
    const-class v4, Lcz/myskoda/api/bff_maps/v3/MapsApi;

    .line 1641
    .line 1642
    invoke-static {v2, v4, v8}, Lia/b;->f(Lkotlin/jvm/internal/h0;Ljava/lang/Class;Ljava/lang/String;)Lh21/b;

    .line 1643
    .line 1644
    .line 1645
    move-result-object v4

    .line 1646
    invoke-virtual {v2, v7}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1647
    .line 1648
    .line 1649
    move-result-object v2

    .line 1650
    invoke-virtual {v0, v2, v4, v11}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1651
    .line 1652
    .line 1653
    move-result-object v0

    .line 1654
    check-cast v0, Lti0/a;

    .line 1655
    .line 1656
    invoke-direct {v1, v3, v0}, Llo0/c;-><init>(Lxl0/f;Lti0/a;)V

    .line 1657
    .line 1658
    .line 1659
    return-object v1

    .line 1660
    :pswitch_1c
    move-object/from16 v0, p1

    .line 1661
    .line 1662
    check-cast v0, Lk21/a;

    .line 1663
    .line 1664
    move-object/from16 v2, p2

    .line 1665
    .line 1666
    check-cast v2, Lg21/a;

    .line 1667
    .line 1668
    invoke-static {v0, v12}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1669
    .line 1670
    .line 1671
    invoke-static {v2, v13}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1672
    .line 1673
    .line 1674
    new-instance v2, Llo0/a;

    .line 1675
    .line 1676
    sget-object v3, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1677
    .line 1678
    invoke-virtual {v3, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1679
    .line 1680
    .line 1681
    move-result-object v1

    .line 1682
    const-string v3, "clazz"

    .line 1683
    .line 1684
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1685
    .line 1686
    .line 1687
    sget-wide v3, Lmo0/b;->a:J

    .line 1688
    .line 1689
    new-instance v5, Lmy0/c;

    .line 1690
    .line 1691
    invoke-direct {v5, v3, v4}, Lmy0/c;-><init>(J)V

    .line 1692
    .line 1693
    .line 1694
    filled-new-array {v5}, [Ljava/lang/Object;

    .line 1695
    .line 1696
    .line 1697
    move-result-object v3

    .line 1698
    invoke-static {v3}, Lkp/l8;->a([Ljava/lang/Object;)Lg21/a;

    .line 1699
    .line 1700
    .line 1701
    move-result-object v3

    .line 1702
    invoke-virtual {v0, v3, v11, v1}, Lk21/a;->c(Lg21/a;Lh21/a;Lhy0/d;)Ljava/lang/Object;

    .line 1703
    .line 1704
    .line 1705
    move-result-object v0

    .line 1706
    check-cast v0, Lwe0/a;

    .line 1707
    .line 1708
    invoke-direct {v2, v0}, Llo0/a;-><init>(Lwe0/a;)V

    .line 1709
    .line 1710
    .line 1711
    return-object v2

    .line 1712
    nop

    .line 1713
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1c
        :pswitch_1b
        :pswitch_1a
        :pswitch_19
        :pswitch_18
        :pswitch_17
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
