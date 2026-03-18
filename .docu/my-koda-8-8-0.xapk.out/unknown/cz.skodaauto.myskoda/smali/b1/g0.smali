.class public final Lb1/g0;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:Ljava/lang/Object;

.field public final synthetic h:Ljava/lang/Object;

.field public final synthetic i:Ljava/lang/Object;

.field public final synthetic j:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p5, p0, Lb1/g0;->f:I

    .line 2
    .line 3
    iput-object p1, p0, Lb1/g0;->g:Ljava/lang/Object;

    .line 4
    .line 5
    iput-object p2, p0, Lb1/g0;->h:Ljava/lang/Object;

    .line 6
    .line 7
    iput-object p3, p0, Lb1/g0;->i:Ljava/lang/Object;

    .line 8
    .line 9
    iput-object p4, p0, Lb1/g0;->j:Ljava/lang/Object;

    .line 10
    .line 11
    const/4 p1, 0x2

    .line 12
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 13
    .line 14
    .line 15
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 57

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lb1/g0;->f:I

    .line 4
    .line 5
    sget-object v3, Ll2/n;->a:Ll2/x0;

    .line 6
    .line 7
    sget-object v4, Lx2/p;->b:Lx2/p;

    .line 8
    .line 9
    const/4 v5, 0x3

    .line 10
    iget-object v6, v0, Lb1/g0;->i:Ljava/lang/Object;

    .line 11
    .line 12
    iget-object v7, v0, Lb1/g0;->g:Ljava/lang/Object;

    .line 13
    .line 14
    iget-object v8, v0, Lb1/g0;->h:Ljava/lang/Object;

    .line 15
    .line 16
    iget-object v0, v0, Lb1/g0;->j:Ljava/lang/Object;

    .line 17
    .line 18
    sget-object v9, Llx0/b0;->a:Llx0/b0;

    .line 19
    .line 20
    const/4 v10, 0x2

    .line 21
    const/4 v11, 0x0

    .line 22
    const/4 v12, 0x1

    .line 23
    packed-switch v1, :pswitch_data_0

    .line 24
    .line 25
    .line 26
    move-object/from16 v1, p1

    .line 27
    .line 28
    check-cast v1, Ll2/o;

    .line 29
    .line 30
    move-object/from16 v13, p2

    .line 31
    .line 32
    check-cast v13, Ljava/lang/Number;

    .line 33
    .line 34
    invoke-virtual {v13}, Ljava/lang/Number;->intValue()I

    .line 35
    .line 36
    .line 37
    move-result v13

    .line 38
    check-cast v0, Ljh/h;

    .line 39
    .line 40
    check-cast v8, Lz4/k;

    .line 41
    .line 42
    and-int/2addr v5, v13

    .line 43
    if-ne v5, v10, :cond_1

    .line 44
    .line 45
    move-object v5, v1

    .line 46
    check-cast v5, Ll2/t;

    .line 47
    .line 48
    invoke-virtual {v5}, Ll2/t;->A()Z

    .line 49
    .line 50
    .line 51
    move-result v10

    .line 52
    if-nez v10, :cond_0

    .line 53
    .line 54
    goto :goto_0

    .line 55
    :cond_0
    invoke-virtual {v5}, Ll2/t;->R()V

    .line 56
    .line 57
    .line 58
    goto/16 :goto_6

    .line 59
    .line 60
    :cond_1
    :goto_0
    check-cast v7, Ll2/b1;

    .line 61
    .line 62
    invoke-interface {v7, v9}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 63
    .line 64
    .line 65
    iget v5, v8, Lz4/k;->b:I

    .line 66
    .line 67
    invoke-virtual {v8}, Lz4/k;->e()V

    .line 68
    .line 69
    .line 70
    check-cast v1, Ll2/t;

    .line 71
    .line 72
    const v7, -0x4b434dd6

    .line 73
    .line 74
    .line 75
    invoke-virtual {v1, v7}, Ll2/t;->Y(I)V

    .line 76
    .line 77
    .line 78
    invoke-virtual {v8}, Lz4/k;->d()Lt1/j0;

    .line 79
    .line 80
    .line 81
    move-result-object v7

    .line 82
    iget-object v7, v7, Lt1/j0;->e:Ljava/lang/Object;

    .line 83
    .line 84
    check-cast v7, Lz4/k;

    .line 85
    .line 86
    invoke-virtual {v7}, Lz4/k;->c()Lz4/f;

    .line 87
    .line 88
    .line 89
    move-result-object v10

    .line 90
    invoke-virtual {v7}, Lz4/k;->c()Lz4/f;

    .line 91
    .line 92
    .line 93
    move-result-object v13

    .line 94
    invoke-virtual {v7}, Lz4/k;->c()Lz4/f;

    .line 95
    .line 96
    .line 97
    move-result-object v7

    .line 98
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 99
    .line 100
    .line 101
    move-result-object v14

    .line 102
    if-ne v14, v3, :cond_2

    .line 103
    .line 104
    sget-object v14, Lyk/e;->e:Lyk/e;

    .line 105
    .line 106
    invoke-virtual {v1, v14}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 107
    .line 108
    .line 109
    :cond_2
    check-cast v14, Lay0/k;

    .line 110
    .line 111
    invoke-static {v4, v10, v14}, Lz4/k;->b(Lx2/s;Lz4/f;Lay0/k;)Lx2/s;

    .line 112
    .line 113
    .line 114
    move-result-object v10

    .line 115
    sget-object v14, Lk1/j;->c:Lk1/e;

    .line 116
    .line 117
    sget-object v15, Lx2/c;->p:Lx2/h;

    .line 118
    .line 119
    invoke-static {v14, v15, v1, v11}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 120
    .line 121
    .line 122
    move-result-object v14

    .line 123
    move-object/from16 v35, v3

    .line 124
    .line 125
    iget-wide v2, v1, Ll2/t;->T:J

    .line 126
    .line 127
    invoke-static {v2, v3}, Ljava/lang/Long;->hashCode(J)I

    .line 128
    .line 129
    .line 130
    move-result v2

    .line 131
    invoke-virtual {v1}, Ll2/t;->m()Ll2/p1;

    .line 132
    .line 133
    .line 134
    move-result-object v3

    .line 135
    invoke-static {v1, v10}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 136
    .line 137
    .line 138
    move-result-object v10

    .line 139
    sget-object v15, Lv3/k;->m1:Lv3/j;

    .line 140
    .line 141
    invoke-virtual {v15}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 142
    .line 143
    .line 144
    sget-object v15, Lv3/j;->b:Lv3/i;

    .line 145
    .line 146
    invoke-virtual {v1}, Ll2/t;->c0()V

    .line 147
    .line 148
    .line 149
    iget-boolean v11, v1, Ll2/t;->S:Z

    .line 150
    .line 151
    if-eqz v11, :cond_3

    .line 152
    .line 153
    invoke-virtual {v1, v15}, Ll2/t;->l(Lay0/a;)V

    .line 154
    .line 155
    .line 156
    goto :goto_1

    .line 157
    :cond_3
    invoke-virtual {v1}, Ll2/t;->m0()V

    .line 158
    .line 159
    .line 160
    :goto_1
    sget-object v11, Lv3/j;->g:Lv3/h;

    .line 161
    .line 162
    invoke-static {v11, v14, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 163
    .line 164
    .line 165
    sget-object v11, Lv3/j;->f:Lv3/h;

    .line 166
    .line 167
    invoke-static {v11, v3, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 168
    .line 169
    .line 170
    sget-object v3, Lv3/j;->j:Lv3/h;

    .line 171
    .line 172
    iget-boolean v11, v1, Ll2/t;->S:Z

    .line 173
    .line 174
    if-nez v11, :cond_4

    .line 175
    .line 176
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 177
    .line 178
    .line 179
    move-result-object v11

    .line 180
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 181
    .line 182
    .line 183
    move-result-object v14

    .line 184
    invoke-static {v11, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 185
    .line 186
    .line 187
    move-result v11

    .line 188
    if-nez v11, :cond_5

    .line 189
    .line 190
    :cond_4
    invoke-static {v2, v1, v2, v3}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 191
    .line 192
    .line 193
    :cond_5
    sget-object v2, Lv3/j;->d:Lv3/h;

    .line 194
    .line 195
    invoke-static {v2, v10, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 196
    .line 197
    .line 198
    move-object v2, v13

    .line 199
    iget-object v13, v0, Ljh/h;->a:Ljava/lang/String;

    .line 200
    .line 201
    sget-object v3, Lj91/j;->a:Ll2/u2;

    .line 202
    .line 203
    invoke-virtual {v1, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 204
    .line 205
    .line 206
    move-result-object v10

    .line 207
    check-cast v10, Lj91/f;

    .line 208
    .line 209
    invoke-virtual {v10}, Lj91/f;->b()Lg4/p0;

    .line 210
    .line 211
    .line 212
    move-result-object v14

    .line 213
    const-string v10, "wallbox_firmware_current_version"

    .line 214
    .line 215
    invoke-static {v4, v10}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 216
    .line 217
    .line 218
    move-result-object v15

    .line 219
    sget-object v10, Lj91/h;->a:Ll2/u2;

    .line 220
    .line 221
    invoke-virtual {v1, v10}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 222
    .line 223
    .line 224
    move-result-object v11

    .line 225
    check-cast v11, Lj91/e;

    .line 226
    .line 227
    invoke-virtual {v11}, Lj91/e;->q()J

    .line 228
    .line 229
    .line 230
    move-result-wide v16

    .line 231
    const/16 v33, 0x0

    .line 232
    .line 233
    const v34, 0xfff0

    .line 234
    .line 235
    .line 236
    const-wide/16 v18, 0x0

    .line 237
    .line 238
    const/16 v20, 0x0

    .line 239
    .line 240
    const-wide/16 v21, 0x0

    .line 241
    .line 242
    const/16 v23, 0x0

    .line 243
    .line 244
    const/16 v24, 0x0

    .line 245
    .line 246
    const-wide/16 v25, 0x0

    .line 247
    .line 248
    const/16 v27, 0x0

    .line 249
    .line 250
    const/16 v28, 0x0

    .line 251
    .line 252
    const/16 v29, 0x0

    .line 253
    .line 254
    const/16 v30, 0x0

    .line 255
    .line 256
    const/16 v32, 0x180

    .line 257
    .line 258
    move-object/from16 v31, v1

    .line 259
    .line 260
    invoke-static/range {v13 .. v34}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 261
    .line 262
    .line 263
    const v11, 0x7f120c09

    .line 264
    .line 265
    .line 266
    invoke-static {v1, v11}, Lzb/x;->d(Ll2/o;I)Ljava/lang/String;

    .line 267
    .line 268
    .line 269
    move-result-object v13

    .line 270
    invoke-virtual {v1, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 271
    .line 272
    .line 273
    move-result-object v3

    .line 274
    check-cast v3, Lj91/f;

    .line 275
    .line 276
    invoke-virtual {v3}, Lj91/f;->e()Lg4/p0;

    .line 277
    .line 278
    .line 279
    move-result-object v14

    .line 280
    invoke-virtual {v1, v10}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 281
    .line 282
    .line 283
    move-result-object v3

    .line 284
    check-cast v3, Lj91/e;

    .line 285
    .line 286
    invoke-virtual {v3}, Lj91/e;->s()J

    .line 287
    .line 288
    .line 289
    move-result-wide v16

    .line 290
    const v34, 0xfff4

    .line 291
    .line 292
    .line 293
    const/4 v15, 0x0

    .line 294
    const/16 v32, 0x0

    .line 295
    .line 296
    invoke-static/range {v13 .. v34}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 297
    .line 298
    .line 299
    invoke-virtual {v1, v12}, Ll2/t;->q(Z)V

    .line 300
    .line 301
    .line 302
    iget-boolean v3, v0, Ljh/h;->d:Z

    .line 303
    .line 304
    const v11, -0x4bc4d874

    .line 305
    .line 306
    .line 307
    if-eqz v3, :cond_7

    .line 308
    .line 309
    const v3, -0x4b36e9e9

    .line 310
    .line 311
    .line 312
    invoke-virtual {v1, v3}, Ll2/t;->Y(I)V

    .line 313
    .line 314
    .line 315
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 316
    .line 317
    .line 318
    move-result-object v3

    .line 319
    move-object/from16 v13, v35

    .line 320
    .line 321
    if-ne v3, v13, :cond_6

    .line 322
    .line 323
    sget-object v3, Lyk/e;->f:Lyk/e;

    .line 324
    .line 325
    invoke-virtual {v1, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 326
    .line 327
    .line 328
    :cond_6
    check-cast v3, Lay0/k;

    .line 329
    .line 330
    invoke-static {v4, v2, v3}, Lz4/k;->b(Lx2/s;Lz4/f;Lay0/k;)Lx2/s;

    .line 331
    .line 332
    .line 333
    move-result-object v2

    .line 334
    const-string v3, "wallbox_firmware_loading"

    .line 335
    .line 336
    invoke-static {v2, v3}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 337
    .line 338
    .line 339
    move-result-object v2

    .line 340
    const/4 v3, 0x0

    .line 341
    invoke-static {v3, v3, v1, v2}, Li91/j0;->m0(IILl2/o;Lx2/s;)V

    .line 342
    .line 343
    .line 344
    :goto_2
    invoke-virtual {v1, v3}, Ll2/t;->q(Z)V

    .line 345
    .line 346
    .line 347
    goto :goto_3

    .line 348
    :cond_7
    move-object/from16 v13, v35

    .line 349
    .line 350
    const/4 v3, 0x0

    .line 351
    invoke-virtual {v1, v11}, Ll2/t;->Y(I)V

    .line 352
    .line 353
    .line 354
    goto :goto_2

    .line 355
    :goto_3
    iget-boolean v0, v0, Ljh/h;->e:Z

    .line 356
    .line 357
    if-eqz v0, :cond_9

    .line 358
    .line 359
    const v0, -0x4b30e425

    .line 360
    .line 361
    .line 362
    invoke-virtual {v1, v0}, Ll2/t;->Y(I)V

    .line 363
    .line 364
    .line 365
    const v0, 0x7f080348

    .line 366
    .line 367
    .line 368
    invoke-static {v0, v3, v1}, Ljp/fa;->b(IILl2/o;)Li3/c;

    .line 369
    .line 370
    .line 371
    move-result-object v0

    .line 372
    invoke-virtual {v1, v10}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 373
    .line 374
    .line 375
    move-result-object v2

    .line 376
    check-cast v2, Lj91/e;

    .line 377
    .line 378
    invoke-virtual {v2}, Lj91/e;->u()J

    .line 379
    .line 380
    .line 381
    move-result-wide v2

    .line 382
    new-instance v10, Le3/m;

    .line 383
    .line 384
    const/4 v11, 0x5

    .line 385
    invoke-direct {v10, v2, v3, v11}, Le3/m;-><init>(JI)V

    .line 386
    .line 387
    .line 388
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 389
    .line 390
    .line 391
    move-result-object v2

    .line 392
    if-ne v2, v13, :cond_8

    .line 393
    .line 394
    sget-object v2, Lyk/e;->g:Lyk/e;

    .line 395
    .line 396
    invoke-virtual {v1, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 397
    .line 398
    .line 399
    :cond_8
    check-cast v2, Lay0/k;

    .line 400
    .line 401
    invoke-static {v4, v7, v2}, Lz4/k;->b(Lx2/s;Lz4/f;Lay0/k;)Lx2/s;

    .line 402
    .line 403
    .line 404
    move-result-object v2

    .line 405
    const-string v3, "wallbox_firmware_update_badge"

    .line 406
    .line 407
    invoke-static {v2, v3}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 408
    .line 409
    .line 410
    move-result-object v15

    .line 411
    const/16 v21, 0x30

    .line 412
    .line 413
    const/16 v22, 0x38

    .line 414
    .line 415
    const-string v14, "Warning"

    .line 416
    .line 417
    const/16 v16, 0x0

    .line 418
    .line 419
    const/16 v17, 0x0

    .line 420
    .line 421
    const/16 v18, 0x0

    .line 422
    .line 423
    move-object v13, v0

    .line 424
    move-object/from16 v20, v1

    .line 425
    .line 426
    move-object/from16 v19, v10

    .line 427
    .line 428
    invoke-static/range {v13 .. v22}, Lkp/m;->a(Li3/c;Ljava/lang/String;Lx2/s;Lx2/e;Lt3/k;FLe3/m;Ll2/o;II)V

    .line 429
    .line 430
    .line 431
    const/4 v3, 0x0

    .line 432
    :goto_4
    invoke-virtual {v1, v3}, Ll2/t;->q(Z)V

    .line 433
    .line 434
    .line 435
    goto :goto_5

    .line 436
    :cond_9
    invoke-virtual {v1, v11}, Ll2/t;->Y(I)V

    .line 437
    .line 438
    .line 439
    goto :goto_4

    .line 440
    :goto_5
    invoke-virtual {v1, v3}, Ll2/t;->q(Z)V

    .line 441
    .line 442
    .line 443
    iget v0, v8, Lz4/k;->b:I

    .line 444
    .line 445
    if-eq v0, v5, :cond_a

    .line 446
    .line 447
    check-cast v6, Lay0/a;

    .line 448
    .line 449
    invoke-static {v6, v1}, Ll2/l0;->g(Lay0/a;Ll2/o;)V

    .line 450
    .line 451
    .line 452
    :cond_a
    :goto_6
    return-object v9

    .line 453
    :pswitch_0
    move-object/from16 v1, p1

    .line 454
    .line 455
    check-cast v1, Ll2/o;

    .line 456
    .line 457
    move-object/from16 v2, p2

    .line 458
    .line 459
    check-cast v2, Ljava/lang/Number;

    .line 460
    .line 461
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 462
    .line 463
    .line 464
    move-result v2

    .line 465
    and-int/lit8 v2, v2, 0xb

    .line 466
    .line 467
    if-ne v2, v10, :cond_c

    .line 468
    .line 469
    move-object v2, v1

    .line 470
    check-cast v2, Ll2/t;

    .line 471
    .line 472
    invoke-virtual {v2}, Ll2/t;->A()Z

    .line 473
    .line 474
    .line 475
    move-result v3

    .line 476
    if-nez v3, :cond_b

    .line 477
    .line 478
    goto :goto_7

    .line 479
    :cond_b
    invoke-virtual {v2}, Ll2/t;->R()V

    .line 480
    .line 481
    .line 482
    goto :goto_8

    .line 483
    :cond_c
    :goto_7
    check-cast v7, Lvv/m0;

    .line 484
    .line 485
    invoke-static {v7, v1}, Lvv/q0;->a(Lvv/m0;Ll2/o;)Lay0/p;

    .line 486
    .line 487
    .line 488
    move-result-object v2

    .line 489
    check-cast v8, Lg4/p0;

    .line 490
    .line 491
    new-instance v3, Lvv/x0;

    .line 492
    .line 493
    check-cast v6, Lx2/s;

    .line 494
    .line 495
    check-cast v0, Lay0/o;

    .line 496
    .line 497
    const/4 v4, 0x0

    .line 498
    invoke-direct {v3, v6, v0, v4}, Lvv/x0;-><init>(Lx2/s;Lay0/o;I)V

    .line 499
    .line 500
    .line 501
    const v0, 0x23c22af2

    .line 502
    .line 503
    .line 504
    invoke-static {v0, v1, v3}, Lt2/c;->b(ILl2/o;Llx0/e;)Lt2/b;

    .line 505
    .line 506
    .line 507
    move-result-object v0

    .line 508
    const/16 v3, 0x30

    .line 509
    .line 510
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 511
    .line 512
    .line 513
    move-result-object v3

    .line 514
    invoke-interface {v2, v8, v0, v1, v3}, Lay0/p;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 515
    .line 516
    .line 517
    :goto_8
    return-object v9

    .line 518
    :pswitch_1
    move-object/from16 v1, p1

    .line 519
    .line 520
    check-cast v1, Ll2/o;

    .line 521
    .line 522
    move-object/from16 v2, p2

    .line 523
    .line 524
    check-cast v2, Ljava/lang/Number;

    .line 525
    .line 526
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 527
    .line 528
    .line 529
    move-result v2

    .line 530
    and-int/lit8 v2, v2, 0xb

    .line 531
    .line 532
    if-ne v2, v10, :cond_e

    .line 533
    .line 534
    move-object v2, v1

    .line 535
    check-cast v2, Ll2/t;

    .line 536
    .line 537
    invoke-virtual {v2}, Ll2/t;->A()Z

    .line 538
    .line 539
    .line 540
    move-result v3

    .line 541
    if-nez v3, :cond_d

    .line 542
    .line 543
    goto :goto_9

    .line 544
    :cond_d
    invoke-virtual {v2}, Ll2/t;->R()V

    .line 545
    .line 546
    .line 547
    goto :goto_a

    .line 548
    :cond_e
    :goto_9
    check-cast v7, Lvv/n0;

    .line 549
    .line 550
    new-instance v2, Ltv/k;

    .line 551
    .line 552
    check-cast v8, Lxf0/b2;

    .line 553
    .line 554
    check-cast v6, Lx2/s;

    .line 555
    .line 556
    check-cast v0, Lay0/o;

    .line 557
    .line 558
    invoke-direct {v2, v8, v6, v0, v12}, Ltv/k;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 559
    .line 560
    .line 561
    const v0, -0x518d3169

    .line 562
    .line 563
    .line 564
    invoke-static {v0, v1, v2}, Lt2/c;->b(ILl2/o;Llx0/e;)Lt2/b;

    .line 565
    .line 566
    .line 567
    move-result-object v0

    .line 568
    const/16 v2, 0x180

    .line 569
    .line 570
    invoke-static {v7, v0, v1, v2}, Lvv/o0;->a(Lvv/n0;Lt2/b;Ll2/o;I)V

    .line 571
    .line 572
    .line 573
    :goto_a
    return-object v9

    .line 574
    :pswitch_2
    move-object v13, v3

    .line 575
    move-object/from16 v1, p1

    .line 576
    .line 577
    check-cast v1, Ll2/o;

    .line 578
    .line 579
    move-object/from16 v2, p2

    .line 580
    .line 581
    check-cast v2, Ljava/lang/Number;

    .line 582
    .line 583
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 584
    .line 585
    .line 586
    move-result v2

    .line 587
    check-cast v0, Le30/n;

    .line 588
    .line 589
    check-cast v8, Lz4/k;

    .line 590
    .line 591
    and-int/2addr v2, v5

    .line 592
    if-ne v2, v10, :cond_10

    .line 593
    .line 594
    move-object v2, v1

    .line 595
    check-cast v2, Ll2/t;

    .line 596
    .line 597
    invoke-virtual {v2}, Ll2/t;->A()Z

    .line 598
    .line 599
    .line 600
    move-result v3

    .line 601
    if-nez v3, :cond_f

    .line 602
    .line 603
    goto :goto_b

    .line 604
    :cond_f
    invoke-virtual {v2}, Ll2/t;->R()V

    .line 605
    .line 606
    .line 607
    move-object/from16 v18, v9

    .line 608
    .line 609
    goto/16 :goto_e

    .line 610
    .line 611
    :cond_10
    :goto_b
    check-cast v7, Ll2/b1;

    .line 612
    .line 613
    invoke-interface {v7, v9}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 614
    .line 615
    .line 616
    iget v2, v8, Lz4/k;->b:I

    .line 617
    .line 618
    invoke-virtual {v8}, Lz4/k;->e()V

    .line 619
    .line 620
    .line 621
    check-cast v1, Ll2/t;

    .line 622
    .line 623
    const v3, -0x5e5a1dc

    .line 624
    .line 625
    .line 626
    invoke-virtual {v1, v3}, Ll2/t;->Y(I)V

    .line 627
    .line 628
    .line 629
    invoke-virtual {v8}, Lz4/k;->d()Lt1/j0;

    .line 630
    .line 631
    .line 632
    move-result-object v3

    .line 633
    iget-object v3, v3, Lt1/j0;->e:Ljava/lang/Object;

    .line 634
    .line 635
    check-cast v3, Lz4/k;

    .line 636
    .line 637
    invoke-virtual {v3}, Lz4/k;->c()Lz4/f;

    .line 638
    .line 639
    .line 640
    move-result-object v7

    .line 641
    invoke-virtual {v3}, Lz4/k;->c()Lz4/f;

    .line 642
    .line 643
    .line 644
    move-result-object v3

    .line 645
    new-array v11, v10, [Lz4/o;

    .line 646
    .line 647
    const/4 v14, 0x0

    .line 648
    aput-object v7, v11, v14

    .line 649
    .line 650
    aput-object v3, v11, v12

    .line 651
    .line 652
    new-instance v12, Lz4/s;

    .line 653
    .line 654
    iget v15, v8, Lz4/k;->d:I

    .line 655
    .line 656
    add-int/lit8 v5, v15, 0x1

    .line 657
    .line 658
    iput v5, v8, Lz4/k;->d:I

    .line 659
    .line 660
    invoke-static {v15}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 661
    .line 662
    .line 663
    move-result-object v5

    .line 664
    invoke-direct {v12, v5}, Lz4/o;-><init>(Ljava/lang/Object;)V

    .line 665
    .line 666
    .line 667
    new-instance v5, Ld5/a;

    .line 668
    .line 669
    new-array v15, v14, [C

    .line 670
    .line 671
    invoke-direct {v5, v15}, Ld5/b;-><init>([C)V

    .line 672
    .line 673
    .line 674
    const/4 v14, 0x0

    .line 675
    :goto_c
    if-ge v14, v10, :cond_11

    .line 676
    .line 677
    aget-object v15, v11, v14

    .line 678
    .line 679
    iget-object v10, v15, Lz4/o;->b:Ljava/util/LinkedHashMap;

    .line 680
    .line 681
    move-object/from16 v18, v9

    .line 682
    .line 683
    const-class v9, Lz4/a;

    .line 684
    .line 685
    move-object/from16 v19, v11

    .line 686
    .line 687
    sget-object v11, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 688
    .line 689
    invoke-virtual {v11, v9}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 690
    .line 691
    .line 692
    move-result-object v9

    .line 693
    invoke-interface {v9}, Lhy0/d;->getSimpleName()Ljava/lang/String;

    .line 694
    .line 695
    .line 696
    move-result-object v9

    .line 697
    invoke-virtual {v10, v9}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 698
    .line 699
    .line 700
    invoke-virtual {v15}, Lz4/o;->a()Ljava/lang/Object;

    .line 701
    .line 702
    .line 703
    move-result-object v9

    .line 704
    invoke-virtual {v9}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 705
    .line 706
    .line 707
    move-result-object v9

    .line 708
    invoke-static {v9}, Ld5/h;->o(Ljava/lang/String;)Ld5/h;

    .line 709
    .line 710
    .line 711
    move-result-object v9

    .line 712
    invoke-virtual {v5, v9}, Ld5/b;->o(Ld5/c;)V

    .line 713
    .line 714
    .line 715
    add-int/lit8 v14, v14, 0x1

    .line 716
    .line 717
    move-object/from16 v9, v18

    .line 718
    .line 719
    move-object/from16 v11, v19

    .line 720
    .line 721
    const/4 v10, 0x2

    .line 722
    goto :goto_c

    .line 723
    :cond_11
    move-object/from16 v18, v9

    .line 724
    .line 725
    move-object/from16 v19, v11

    .line 726
    .line 727
    new-instance v9, Ld5/a;

    .line 728
    .line 729
    const/4 v14, 0x0

    .line 730
    new-array v10, v14, [C

    .line 731
    .line 732
    invoke-direct {v9, v10}, Ld5/b;-><init>([C)V

    .line 733
    .line 734
    .line 735
    const-string v10, "packed"

    .line 736
    .line 737
    invoke-static {v10}, Ld5/h;->o(Ljava/lang/String;)Ld5/h;

    .line 738
    .line 739
    .line 740
    move-result-object v10

    .line 741
    invoke-virtual {v9, v10}, Ld5/b;->o(Ld5/c;)V

    .line 742
    .line 743
    .line 744
    new-instance v10, Ld5/e;

    .line 745
    .line 746
    const/high16 v11, 0x3f000000    # 0.5f

    .line 747
    .line 748
    invoke-direct {v10, v11}, Ld5/e;-><init>(F)V

    .line 749
    .line 750
    .line 751
    invoke-virtual {v9, v10}, Ld5/b;->o(Ld5/c;)V

    .line 752
    .line 753
    .line 754
    invoke-virtual {v8, v12}, Lz4/k;->a(Lz4/o;)Ld5/f;

    .line 755
    .line 756
    .line 757
    move-result-object v10

    .line 758
    new-instance v11, Ld5/h;

    .line 759
    .line 760
    const-string v12, "vChain"

    .line 761
    .line 762
    invoke-virtual {v12}, Ljava/lang/String;->toCharArray()[C

    .line 763
    .line 764
    .line 765
    move-result-object v12

    .line 766
    invoke-direct {v11, v12}, Ld5/c;-><init>([C)V

    .line 767
    .line 768
    .line 769
    const-wide/16 v14, 0x0

    .line 770
    .line 771
    iput-wide v14, v11, Ld5/c;->e:J

    .line 772
    .line 773
    const/4 v12, 0x5

    .line 774
    int-to-long v14, v12

    .line 775
    invoke-virtual {v11, v14, v15}, Ld5/c;->n(J)V

    .line 776
    .line 777
    .line 778
    const-string v12, "type"

    .line 779
    .line 780
    invoke-virtual {v10, v12, v11}, Ld5/b;->D(Ljava/lang/String;Ld5/c;)V

    .line 781
    .line 782
    .line 783
    const-string v11, "contains"

    .line 784
    .line 785
    invoke-virtual {v10, v11, v5}, Ld5/b;->D(Ljava/lang/String;Ld5/c;)V

    .line 786
    .line 787
    .line 788
    const-string v5, "style"

    .line 789
    .line 790
    invoke-virtual {v10, v5, v9}, Ld5/b;->D(Ljava/lang/String;Ld5/c;)V

    .line 791
    .line 792
    .line 793
    iget v5, v8, Lz4/k;->b:I

    .line 794
    .line 795
    mul-int/lit16 v5, v5, 0x3f1

    .line 796
    .line 797
    add-int/lit8 v5, v5, 0x11

    .line 798
    .line 799
    const v9, 0x3b9aca07

    .line 800
    .line 801
    .line 802
    rem-int/2addr v5, v9

    .line 803
    iput v5, v8, Lz4/k;->b:I

    .line 804
    .line 805
    const/4 v5, 0x0

    .line 806
    :goto_d
    const/4 v10, 0x2

    .line 807
    if-ge v5, v10, :cond_12

    .line 808
    .line 809
    aget-object v10, v19, v5

    .line 810
    .line 811
    invoke-virtual {v10}, Lz4/o;->hashCode()I

    .line 812
    .line 813
    .line 814
    move-result v10

    .line 815
    iget v11, v8, Lz4/k;->b:I

    .line 816
    .line 817
    mul-int/lit16 v11, v11, 0x3f1

    .line 818
    .line 819
    add-int/2addr v11, v10

    .line 820
    rem-int/2addr v11, v9

    .line 821
    iput v11, v8, Lz4/k;->b:I

    .line 822
    .line 823
    add-int/lit8 v5, v5, 0x1

    .line 824
    .line 825
    goto :goto_d

    .line 826
    :cond_12
    sget-object v5, Lz4/b;->a:Lz4/b;

    .line 827
    .line 828
    invoke-virtual {v5}, Ljava/lang/Object;->hashCode()I

    .line 829
    .line 830
    .line 831
    move-result v5

    .line 832
    iget v10, v8, Lz4/k;->b:I

    .line 833
    .line 834
    mul-int/lit16 v10, v10, 0x3f1

    .line 835
    .line 836
    add-int/2addr v10, v5

    .line 837
    rem-int/2addr v10, v9

    .line 838
    iput v10, v8, Lz4/k;->b:I

    .line 839
    .line 840
    iget-object v5, v0, Le30/n;->a:Ljava/lang/String;

    .line 841
    .line 842
    sget-object v9, Lj91/j;->a:Ll2/u2;

    .line 843
    .line 844
    invoke-virtual {v1, v9}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 845
    .line 846
    .line 847
    move-result-object v10

    .line 848
    check-cast v10, Lj91/f;

    .line 849
    .line 850
    invoke-virtual {v10}, Lj91/f;->l()Lg4/p0;

    .line 851
    .line 852
    .line 853
    move-result-object v36

    .line 854
    invoke-virtual {v1, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 855
    .line 856
    .line 857
    move-result v10

    .line 858
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 859
    .line 860
    .line 861
    move-result-object v11

    .line 862
    if-nez v10, :cond_13

    .line 863
    .line 864
    if-ne v11, v13, :cond_14

    .line 865
    .line 866
    :cond_13
    new-instance v11, Lc40/g;

    .line 867
    .line 868
    const/4 v10, 0x4

    .line 869
    invoke-direct {v11, v3, v10}, Lc40/g;-><init>(Lz4/f;I)V

    .line 870
    .line 871
    .line 872
    invoke-virtual {v1, v11}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 873
    .line 874
    .line 875
    :cond_14
    check-cast v11, Lay0/k;

    .line 876
    .line 877
    invoke-static {v4, v7, v11}, Lz4/k;->b(Lx2/s;Lz4/f;Lay0/k;)Lx2/s;

    .line 878
    .line 879
    .line 880
    move-result-object v37

    .line 881
    new-instance v10, Lr4/k;

    .line 882
    .line 883
    const/4 v11, 0x3

    .line 884
    invoke-direct {v10, v11}, Lr4/k;-><init>(I)V

    .line 885
    .line 886
    .line 887
    const/16 v55, 0x0

    .line 888
    .line 889
    const v56, 0xfbf8

    .line 890
    .line 891
    .line 892
    const-wide/16 v38, 0x0

    .line 893
    .line 894
    const-wide/16 v40, 0x0

    .line 895
    .line 896
    const/16 v42, 0x0

    .line 897
    .line 898
    const-wide/16 v43, 0x0

    .line 899
    .line 900
    const/16 v45, 0x0

    .line 901
    .line 902
    const-wide/16 v47, 0x0

    .line 903
    .line 904
    const/16 v49, 0x0

    .line 905
    .line 906
    const/16 v50, 0x0

    .line 907
    .line 908
    const/16 v51, 0x0

    .line 909
    .line 910
    const/16 v52, 0x0

    .line 911
    .line 912
    const/16 v54, 0x0

    .line 913
    .line 914
    move-object/from16 v53, v1

    .line 915
    .line 916
    move-object/from16 v35, v5

    .line 917
    .line 918
    move-object/from16 v46, v10

    .line 919
    .line 920
    invoke-static/range {v35 .. v56}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 921
    .line 922
    .line 923
    iget-object v0, v0, Le30/n;->b:Ljava/lang/String;

    .line 924
    .line 925
    invoke-virtual {v1, v9}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 926
    .line 927
    .line 928
    move-result-object v5

    .line 929
    check-cast v5, Lj91/f;

    .line 930
    .line 931
    invoke-virtual {v5}, Lj91/f;->b()Lg4/p0;

    .line 932
    .line 933
    .line 934
    move-result-object v36

    .line 935
    invoke-virtual {v1, v7}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 936
    .line 937
    .line 938
    move-result v5

    .line 939
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 940
    .line 941
    .line 942
    move-result-object v9

    .line 943
    if-nez v5, :cond_15

    .line 944
    .line 945
    if-ne v9, v13, :cond_16

    .line 946
    .line 947
    :cond_15
    new-instance v9, Lc40/g;

    .line 948
    .line 949
    const/4 v11, 0x5

    .line 950
    invoke-direct {v9, v7, v11}, Lc40/g;-><init>(Lz4/f;I)V

    .line 951
    .line 952
    .line 953
    invoke-virtual {v1, v9}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 954
    .line 955
    .line 956
    :cond_16
    check-cast v9, Lay0/k;

    .line 957
    .line 958
    invoke-static {v4, v3, v9}, Lz4/k;->b(Lx2/s;Lz4/f;Lay0/k;)Lx2/s;

    .line 959
    .line 960
    .line 961
    move-result-object v10

    .line 962
    sget-object v3, Lj91/a;->a:Ll2/u2;

    .line 963
    .line 964
    invoke-virtual {v1, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 965
    .line 966
    .line 967
    move-result-object v3

    .line 968
    check-cast v3, Lj91/c;

    .line 969
    .line 970
    iget v12, v3, Lj91/c;->c:F

    .line 971
    .line 972
    const/4 v14, 0x0

    .line 973
    const/16 v15, 0xd

    .line 974
    .line 975
    const/4 v11, 0x0

    .line 976
    const/4 v13, 0x0

    .line 977
    invoke-static/range {v10 .. v15}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 978
    .line 979
    .line 980
    move-result-object v37

    .line 981
    new-instance v3, Lr4/k;

    .line 982
    .line 983
    const/4 v11, 0x3

    .line 984
    invoke-direct {v3, v11}, Lr4/k;-><init>(I)V

    .line 985
    .line 986
    .line 987
    const/16 v55, 0x0

    .line 988
    .line 989
    const v56, 0xfbf8

    .line 990
    .line 991
    .line 992
    const-wide/16 v38, 0x0

    .line 993
    .line 994
    const-wide/16 v40, 0x0

    .line 995
    .line 996
    const/16 v42, 0x0

    .line 997
    .line 998
    const-wide/16 v43, 0x0

    .line 999
    .line 1000
    const/16 v45, 0x0

    .line 1001
    .line 1002
    const-wide/16 v47, 0x0

    .line 1003
    .line 1004
    const/16 v49, 0x0

    .line 1005
    .line 1006
    const/16 v50, 0x0

    .line 1007
    .line 1008
    const/16 v51, 0x0

    .line 1009
    .line 1010
    const/16 v52, 0x0

    .line 1011
    .line 1012
    const/16 v54, 0x0

    .line 1013
    .line 1014
    move-object/from16 v35, v0

    .line 1015
    .line 1016
    move-object/from16 v53, v1

    .line 1017
    .line 1018
    move-object/from16 v46, v3

    .line 1019
    .line 1020
    invoke-static/range {v35 .. v56}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 1021
    .line 1022
    .line 1023
    const/4 v14, 0x0

    .line 1024
    invoke-virtual {v1, v14}, Ll2/t;->q(Z)V

    .line 1025
    .line 1026
    .line 1027
    iget v0, v8, Lz4/k;->b:I

    .line 1028
    .line 1029
    if-eq v0, v2, :cond_17

    .line 1030
    .line 1031
    check-cast v6, Lay0/a;

    .line 1032
    .line 1033
    invoke-static {v6, v1}, Ll2/l0;->g(Lay0/a;Ll2/o;)V

    .line 1034
    .line 1035
    .line 1036
    :cond_17
    :goto_e
    return-object v18

    .line 1037
    :pswitch_3
    move-object v13, v3

    .line 1038
    move-object/from16 v18, v9

    .line 1039
    .line 1040
    move v14, v11

    .line 1041
    move-object/from16 v1, p1

    .line 1042
    .line 1043
    check-cast v1, Ll2/o;

    .line 1044
    .line 1045
    move-object/from16 v2, p2

    .line 1046
    .line 1047
    check-cast v2, Ljava/lang/Number;

    .line 1048
    .line 1049
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 1050
    .line 1051
    .line 1052
    move-result v2

    .line 1053
    invoke-static {v14}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1054
    .line 1055
    .line 1056
    move-result-object v3

    .line 1057
    and-int/lit8 v5, v2, 0x3

    .line 1058
    .line 1059
    const/4 v10, 0x2

    .line 1060
    if-eq v5, v10, :cond_18

    .line 1061
    .line 1062
    move v5, v12

    .line 1063
    goto :goto_f

    .line 1064
    :cond_18
    const/4 v5, 0x0

    .line 1065
    :goto_f
    and-int/2addr v2, v12

    .line 1066
    check-cast v1, Ll2/t;

    .line 1067
    .line 1068
    invoke-virtual {v1, v2, v5}, Ll2/t;->O(IZ)Z

    .line 1069
    .line 1070
    .line 1071
    move-result v2

    .line 1072
    if-eqz v2, :cond_28

    .line 1073
    .line 1074
    check-cast v7, Lc1/w1;

    .line 1075
    .line 1076
    new-instance v2, Lb1/f;

    .line 1077
    .line 1078
    check-cast v8, Lc1/a0;

    .line 1079
    .line 1080
    invoke-direct {v2, v8, v12}, Lb1/f;-><init>(Ljava/lang/Object;I)V

    .line 1081
    .line 1082
    .line 1083
    sget-object v23, Lc1/d;->j:Lc1/b2;

    .line 1084
    .line 1085
    invoke-virtual {v7}, Lc1/w1;->g()Z

    .line 1086
    .line 1087
    .line 1088
    move-result v5

    .line 1089
    iget-object v8, v7, Lc1/w1;->a:Lap0/o;

    .line 1090
    .line 1091
    if-nez v5, :cond_1c

    .line 1092
    .line 1093
    const v5, 0x63564970

    .line 1094
    .line 1095
    .line 1096
    invoke-virtual {v1, v5}, Ll2/t;->Y(I)V

    .line 1097
    .line 1098
    .line 1099
    invoke-virtual {v1, v7}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 1100
    .line 1101
    .line 1102
    move-result v5

    .line 1103
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 1104
    .line 1105
    .line 1106
    move-result-object v9

    .line 1107
    if-nez v5, :cond_1a

    .line 1108
    .line 1109
    if-ne v9, v13, :cond_19

    .line 1110
    .line 1111
    goto :goto_11

    .line 1112
    :cond_19
    :goto_10
    const/4 v14, 0x0

    .line 1113
    goto :goto_13

    .line 1114
    :cond_1a
    :goto_11
    invoke-static {}, Lgv/a;->e()Lv2/f;

    .line 1115
    .line 1116
    .line 1117
    move-result-object v5

    .line 1118
    if-eqz v5, :cond_1b

    .line 1119
    .line 1120
    invoke-virtual {v5}, Lv2/f;->e()Lay0/k;

    .line 1121
    .line 1122
    .line 1123
    move-result-object v9

    .line 1124
    goto :goto_12

    .line 1125
    :cond_1b
    const/4 v9, 0x0

    .line 1126
    :goto_12
    invoke-static {v5}, Lgv/a;->j(Lv2/f;)Lv2/f;

    .line 1127
    .line 1128
    .line 1129
    move-result-object v10

    .line 1130
    :try_start_0
    invoke-virtual {v8}, Lap0/o;->D()Ljava/lang/Object;

    .line 1131
    .line 1132
    .line 1133
    move-result-object v8
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 1134
    invoke-static {v5, v10, v9}, Lgv/a;->p(Lv2/f;Lv2/f;Lay0/k;)V

    .line 1135
    .line 1136
    .line 1137
    invoke-virtual {v1, v8}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 1138
    .line 1139
    .line 1140
    move-object v9, v8

    .line 1141
    goto :goto_10

    .line 1142
    :goto_13
    invoke-virtual {v1, v14}, Ll2/t;->q(Z)V

    .line 1143
    .line 1144
    .line 1145
    goto :goto_14

    .line 1146
    :catchall_0
    move-exception v0

    .line 1147
    invoke-static {v5, v10, v9}, Lgv/a;->p(Lv2/f;Lv2/f;Lay0/k;)V

    .line 1148
    .line 1149
    .line 1150
    throw v0

    .line 1151
    :cond_1c
    const/4 v14, 0x0

    .line 1152
    const v5, 0x635a29cd

    .line 1153
    .line 1154
    .line 1155
    invoke-virtual {v1, v5}, Ll2/t;->Y(I)V

    .line 1156
    .line 1157
    .line 1158
    invoke-virtual {v1, v14}, Ll2/t;->q(Z)V

    .line 1159
    .line 1160
    .line 1161
    invoke-virtual {v8}, Lap0/o;->D()Ljava/lang/Object;

    .line 1162
    .line 1163
    .line 1164
    move-result-object v9

    .line 1165
    :goto_14
    const v5, 0x522f0047

    .line 1166
    .line 1167
    .line 1168
    invoke-virtual {v1, v5}, Ll2/t;->Y(I)V

    .line 1169
    .line 1170
    .line 1171
    invoke-static {v9, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1172
    .line 1173
    .line 1174
    move-result v8

    .line 1175
    const/4 v9, 0x0

    .line 1176
    const/high16 v10, 0x3f800000    # 1.0f

    .line 1177
    .line 1178
    if-eqz v8, :cond_1d

    .line 1179
    .line 1180
    move v8, v10

    .line 1181
    goto :goto_15

    .line 1182
    :cond_1d
    move v8, v9

    .line 1183
    :goto_15
    invoke-virtual {v1, v14}, Ll2/t;->q(Z)V

    .line 1184
    .line 1185
    .line 1186
    invoke-static {v8}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 1187
    .line 1188
    .line 1189
    move-result-object v20

    .line 1190
    invoke-virtual {v1, v7}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 1191
    .line 1192
    .line 1193
    move-result v8

    .line 1194
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 1195
    .line 1196
    .line 1197
    move-result-object v11

    .line 1198
    if-nez v8, :cond_1e

    .line 1199
    .line 1200
    if-ne v11, v13, :cond_1f

    .line 1201
    .line 1202
    :cond_1e
    new-instance v8, Lb1/f0;

    .line 1203
    .line 1204
    invoke-direct {v8, v7, v14}, Lb1/f0;-><init>(Lc1/w1;I)V

    .line 1205
    .line 1206
    .line 1207
    invoke-static {v8}, Ll2/b;->h(Lay0/a;)Ll2/h0;

    .line 1208
    .line 1209
    .line 1210
    move-result-object v11

    .line 1211
    invoke-virtual {v1, v11}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 1212
    .line 1213
    .line 1214
    :cond_1f
    check-cast v11, Ll2/t2;

    .line 1215
    .line 1216
    invoke-interface {v11}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 1217
    .line 1218
    .line 1219
    move-result-object v8

    .line 1220
    invoke-virtual {v1, v5}, Ll2/t;->Y(I)V

    .line 1221
    .line 1222
    .line 1223
    invoke-static {v8, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1224
    .line 1225
    .line 1226
    move-result v5

    .line 1227
    if-eqz v5, :cond_20

    .line 1228
    .line 1229
    move v9, v10

    .line 1230
    :cond_20
    invoke-virtual {v1, v14}, Ll2/t;->q(Z)V

    .line 1231
    .line 1232
    .line 1233
    invoke-static {v9}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 1234
    .line 1235
    .line 1236
    move-result-object v21

    .line 1237
    invoke-virtual {v1, v7}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 1238
    .line 1239
    .line 1240
    move-result v5

    .line 1241
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 1242
    .line 1243
    .line 1244
    move-result-object v8

    .line 1245
    if-nez v5, :cond_21

    .line 1246
    .line 1247
    if-ne v8, v13, :cond_22

    .line 1248
    .line 1249
    :cond_21
    new-instance v5, Lb1/f0;

    .line 1250
    .line 1251
    invoke-direct {v5, v7, v12}, Lb1/f0;-><init>(Lc1/w1;I)V

    .line 1252
    .line 1253
    .line 1254
    invoke-static {v5}, Ll2/b;->h(Lay0/a;)Ll2/h0;

    .line 1255
    .line 1256
    .line 1257
    move-result-object v8

    .line 1258
    invoke-virtual {v1, v8}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 1259
    .line 1260
    .line 1261
    :cond_22
    check-cast v8, Ll2/t2;

    .line 1262
    .line 1263
    invoke-interface {v8}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 1264
    .line 1265
    .line 1266
    move-result-object v5

    .line 1267
    invoke-virtual {v2, v5, v1, v3}, Lb1/f;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 1268
    .line 1269
    .line 1270
    move-result-object v2

    .line 1271
    move-object/from16 v22, v2

    .line 1272
    .line 1273
    check-cast v22, Lc1/a0;

    .line 1274
    .line 1275
    const/16 v25, 0x0

    .line 1276
    .line 1277
    move-object/from16 v24, v1

    .line 1278
    .line 1279
    move-object/from16 v19, v7

    .line 1280
    .line 1281
    invoke-static/range {v19 .. v25}, Lc1/z1;->c(Lc1/w1;Ljava/lang/Object;Ljava/lang/Object;Lc1/a0;Lc1/b2;Ll2/o;I)Lc1/t1;

    .line 1282
    .line 1283
    .line 1284
    move-result-object v1

    .line 1285
    move-object/from16 v2, v24

    .line 1286
    .line 1287
    invoke-virtual {v2, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 1288
    .line 1289
    .line 1290
    move-result v5

    .line 1291
    invoke-virtual {v2}, Ll2/t;->L()Ljava/lang/Object;

    .line 1292
    .line 1293
    .line 1294
    move-result-object v7

    .line 1295
    if-nez v5, :cond_23

    .line 1296
    .line 1297
    if-ne v7, v13, :cond_24

    .line 1298
    .line 1299
    :cond_23
    new-instance v7, La3/f;

    .line 1300
    .line 1301
    const/16 v5, 0x9

    .line 1302
    .line 1303
    invoke-direct {v7, v1, v5}, La3/f;-><init>(Ljava/lang/Object;I)V

    .line 1304
    .line 1305
    .line 1306
    invoke-virtual {v2, v7}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 1307
    .line 1308
    .line 1309
    :cond_24
    check-cast v7, Lay0/k;

    .line 1310
    .line 1311
    invoke-static {v4, v7}, Landroidx/compose/ui/graphics/a;->a(Lx2/s;Lay0/k;)Lx2/s;

    .line 1312
    .line 1313
    .line 1314
    move-result-object v1

    .line 1315
    check-cast v0, Lt2/b;

    .line 1316
    .line 1317
    sget-object v4, Lx2/c;->d:Lx2/j;

    .line 1318
    .line 1319
    const/4 v14, 0x0

    .line 1320
    invoke-static {v4, v14}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 1321
    .line 1322
    .line 1323
    move-result-object v4

    .line 1324
    iget-wide v7, v2, Ll2/t;->T:J

    .line 1325
    .line 1326
    invoke-static {v7, v8}, Ljava/lang/Long;->hashCode(J)I

    .line 1327
    .line 1328
    .line 1329
    move-result v5

    .line 1330
    invoke-virtual {v2}, Ll2/t;->m()Ll2/p1;

    .line 1331
    .line 1332
    .line 1333
    move-result-object v7

    .line 1334
    invoke-static {v2, v1}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 1335
    .line 1336
    .line 1337
    move-result-object v1

    .line 1338
    sget-object v8, Lv3/k;->m1:Lv3/j;

    .line 1339
    .line 1340
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1341
    .line 1342
    .line 1343
    sget-object v8, Lv3/j;->b:Lv3/i;

    .line 1344
    .line 1345
    invoke-virtual {v2}, Ll2/t;->c0()V

    .line 1346
    .line 1347
    .line 1348
    iget-boolean v9, v2, Ll2/t;->S:Z

    .line 1349
    .line 1350
    if-eqz v9, :cond_25

    .line 1351
    .line 1352
    invoke-virtual {v2, v8}, Ll2/t;->l(Lay0/a;)V

    .line 1353
    .line 1354
    .line 1355
    goto :goto_16

    .line 1356
    :cond_25
    invoke-virtual {v2}, Ll2/t;->m0()V

    .line 1357
    .line 1358
    .line 1359
    :goto_16
    sget-object v8, Lv3/j;->g:Lv3/h;

    .line 1360
    .line 1361
    invoke-static {v8, v4, v2}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 1362
    .line 1363
    .line 1364
    sget-object v4, Lv3/j;->f:Lv3/h;

    .line 1365
    .line 1366
    invoke-static {v4, v7, v2}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 1367
    .line 1368
    .line 1369
    sget-object v4, Lv3/j;->j:Lv3/h;

    .line 1370
    .line 1371
    iget-boolean v7, v2, Ll2/t;->S:Z

    .line 1372
    .line 1373
    if-nez v7, :cond_26

    .line 1374
    .line 1375
    invoke-virtual {v2}, Ll2/t;->L()Ljava/lang/Object;

    .line 1376
    .line 1377
    .line 1378
    move-result-object v7

    .line 1379
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1380
    .line 1381
    .line 1382
    move-result-object v8

    .line 1383
    invoke-static {v7, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1384
    .line 1385
    .line 1386
    move-result v7

    .line 1387
    if-nez v7, :cond_27

    .line 1388
    .line 1389
    :cond_26
    invoke-static {v5, v2, v5, v4}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 1390
    .line 1391
    .line 1392
    :cond_27
    sget-object v4, Lv3/j;->d:Lv3/h;

    .line 1393
    .line 1394
    invoke-static {v4, v1, v2}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 1395
    .line 1396
    .line 1397
    invoke-virtual {v0, v6, v2, v3}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 1398
    .line 1399
    .line 1400
    invoke-virtual {v2, v12}, Ll2/t;->q(Z)V

    .line 1401
    .line 1402
    .line 1403
    goto :goto_17

    .line 1404
    :cond_28
    move-object v2, v1

    .line 1405
    invoke-virtual {v2}, Ll2/t;->R()V

    .line 1406
    .line 1407
    .line 1408
    :goto_17
    return-object v18

    .line 1409
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
