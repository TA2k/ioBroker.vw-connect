.class public final synthetic Lb71/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/String;

.field public final synthetic f:Ljava/lang/String;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;Ljava/lang/String;I)V
    .locals 0

    .line 1
    iput p3, p0, Lb71/e;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lb71/e;->e:Ljava/lang/String;

    .line 4
    .line 5
    iput-object p2, p0, Lb71/e;->f:Ljava/lang/String;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 20

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lb71/e;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    move-object/from16 v1, p1

    .line 9
    .line 10
    check-cast v1, Landroidx/compose/foundation/lazy/a;

    .line 11
    .line 12
    move-object/from16 v2, p2

    .line 13
    .line 14
    check-cast v2, Ll2/o;

    .line 15
    .line 16
    move-object/from16 v3, p3

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
    const-string v4, "$this$item"

    .line 25
    .line 26
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    and-int/lit8 v1, v3, 0x11

    .line 30
    .line 31
    const/16 v4, 0x10

    .line 32
    .line 33
    const/4 v5, 0x1

    .line 34
    if-eq v1, v4, :cond_0

    .line 35
    .line 36
    move v1, v5

    .line 37
    goto :goto_0

    .line 38
    :cond_0
    const/4 v1, 0x0

    .line 39
    :goto_0
    and-int/2addr v3, v5

    .line 40
    move-object v8, v2

    .line 41
    check-cast v8, Ll2/t;

    .line 42
    .line 43
    invoke-virtual {v8, v3, v1}, Ll2/t;->O(IZ)Z

    .line 44
    .line 45
    .line 46
    move-result v1

    .line 47
    if-eqz v1, :cond_1

    .line 48
    .line 49
    const/4 v9, 0x0

    .line 50
    const/16 v10, 0xa

    .line 51
    .line 52
    iget-object v4, v0, Lb71/e;->e:Ljava/lang/String;

    .line 53
    .line 54
    const/4 v5, 0x0

    .line 55
    iget-object v6, v0, Lb71/e;->f:Ljava/lang/String;

    .line 56
    .line 57
    const/4 v7, 0x0

    .line 58
    invoke-static/range {v4 .. v10}, Lkp/c8;->c(Ljava/lang/String;FLjava/lang/String;Lg4/p0;Ll2/o;II)V

    .line 59
    .line 60
    .line 61
    goto :goto_1

    .line 62
    :cond_1
    invoke-virtual {v8}, Ll2/t;->R()V

    .line 63
    .line 64
    .line 65
    :goto_1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 66
    .line 67
    return-object v0

    .line 68
    :pswitch_0
    move-object/from16 v1, p1

    .line 69
    .line 70
    check-cast v1, Landroidx/compose/foundation/lazy/a;

    .line 71
    .line 72
    move-object/from16 v2, p2

    .line 73
    .line 74
    check-cast v2, Ll2/o;

    .line 75
    .line 76
    move-object/from16 v3, p3

    .line 77
    .line 78
    check-cast v3, Ljava/lang/Integer;

    .line 79
    .line 80
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 81
    .line 82
    .line 83
    move-result v3

    .line 84
    const-string v4, "$this$item"

    .line 85
    .line 86
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 87
    .line 88
    .line 89
    and-int/lit8 v1, v3, 0x11

    .line 90
    .line 91
    const/16 v4, 0x10

    .line 92
    .line 93
    const/4 v5, 0x1

    .line 94
    const/4 v6, 0x0

    .line 95
    if-eq v1, v4, :cond_2

    .line 96
    .line 97
    move v1, v5

    .line 98
    goto :goto_2

    .line 99
    :cond_2
    move v1, v6

    .line 100
    :goto_2
    and-int/2addr v3, v5

    .line 101
    check-cast v2, Ll2/t;

    .line 102
    .line 103
    invoke-virtual {v2, v3, v1}, Ll2/t;->O(IZ)Z

    .line 104
    .line 105
    .line 106
    move-result v1

    .line 107
    if-eqz v1, :cond_3

    .line 108
    .line 109
    iget-object v1, v0, Lb71/e;->e:Ljava/lang/String;

    .line 110
    .line 111
    iget-object v0, v0, Lb71/e;->f:Ljava/lang/String;

    .line 112
    .line 113
    invoke-static {v1, v0, v2, v6}, Lkp/c8;->b(Ljava/lang/String;Ljava/lang/String;Ll2/o;I)V

    .line 114
    .line 115
    .line 116
    goto :goto_3

    .line 117
    :cond_3
    invoke-virtual {v2}, Ll2/t;->R()V

    .line 118
    .line 119
    .line 120
    :goto_3
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 121
    .line 122
    return-object v0

    .line 123
    :pswitch_1
    move-object/from16 v1, p1

    .line 124
    .line 125
    check-cast v1, Landroidx/compose/foundation/lazy/a;

    .line 126
    .line 127
    move-object/from16 v2, p2

    .line 128
    .line 129
    check-cast v2, Ll2/o;

    .line 130
    .line 131
    move-object/from16 v3, p3

    .line 132
    .line 133
    check-cast v3, Ljava/lang/Integer;

    .line 134
    .line 135
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 136
    .line 137
    .line 138
    move-result v3

    .line 139
    const-string v4, "$this$item"

    .line 140
    .line 141
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 142
    .line 143
    .line 144
    and-int/lit8 v1, v3, 0x11

    .line 145
    .line 146
    const/16 v4, 0x10

    .line 147
    .line 148
    const/4 v5, 0x1

    .line 149
    if-eq v1, v4, :cond_4

    .line 150
    .line 151
    move v1, v5

    .line 152
    goto :goto_4

    .line 153
    :cond_4
    const/4 v1, 0x0

    .line 154
    :goto_4
    and-int/2addr v3, v5

    .line 155
    move-object v9, v2

    .line 156
    check-cast v9, Ll2/t;

    .line 157
    .line 158
    invoke-virtual {v9, v3, v1}, Ll2/t;->O(IZ)Z

    .line 159
    .line 160
    .line 161
    move-result v1

    .line 162
    if-eqz v1, :cond_5

    .line 163
    .line 164
    sget-object v1, Lj91/j;->a:Ll2/u2;

    .line 165
    .line 166
    invoke-virtual {v9, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 167
    .line 168
    .line 169
    move-result-object v1

    .line 170
    check-cast v1, Lj91/f;

    .line 171
    .line 172
    invoke-virtual {v1}, Lj91/f;->k()Lg4/p0;

    .line 173
    .line 174
    .line 175
    move-result-object v5

    .line 176
    sget-object v1, Lj91/a;->a:Ll2/u2;

    .line 177
    .line 178
    invoke-virtual {v9, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 179
    .line 180
    .line 181
    move-result-object v1

    .line 182
    check-cast v1, Lj91/c;

    .line 183
    .line 184
    iget v1, v1, Lj91/c;->k:F

    .line 185
    .line 186
    const/4 v2, 0x0

    .line 187
    const/4 v3, 0x2

    .line 188
    sget-object v4, Lx2/p;->b:Lx2/p;

    .line 189
    .line 190
    invoke-static {v4, v1, v2, v3}, Landroidx/compose/foundation/layout/a;->o(Lx2/s;FFI)Lx2/s;

    .line 191
    .line 192
    .line 193
    move-result-object v6

    .line 194
    const-string v1, "_header"

    .line 195
    .line 196
    iget-object v2, v0, Lb71/e;->f:Ljava/lang/String;

    .line 197
    .line 198
    invoke-static {v2, v1}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 199
    .line 200
    .line 201
    move-result-object v7

    .line 202
    const/4 v10, 0x0

    .line 203
    const/16 v11, 0x10

    .line 204
    .line 205
    iget-object v4, v0, Lb71/e;->e:Ljava/lang/String;

    .line 206
    .line 207
    const/4 v8, 0x0

    .line 208
    invoke-static/range {v4 .. v11}, Li91/j0;->H(Ljava/lang/String;Lg4/p0;Lx2/s;Ljava/lang/String;Ljava/lang/String;Ll2/o;II)V

    .line 209
    .line 210
    .line 211
    goto :goto_5

    .line 212
    :cond_5
    invoke-virtual {v9}, Ll2/t;->R()V

    .line 213
    .line 214
    .line 215
    :goto_5
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 216
    .line 217
    return-object v0

    .line 218
    :pswitch_2
    move-object/from16 v1, p1

    .line 219
    .line 220
    check-cast v1, Lk1/t;

    .line 221
    .line 222
    move-object/from16 v2, p2

    .line 223
    .line 224
    check-cast v2, Ll2/o;

    .line 225
    .line 226
    move-object/from16 v3, p3

    .line 227
    .line 228
    check-cast v3, Ljava/lang/Integer;

    .line 229
    .line 230
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 231
    .line 232
    .line 233
    move-result v3

    .line 234
    const-string v4, "$this$RpaScaffold"

    .line 235
    .line 236
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 237
    .line 238
    .line 239
    and-int/lit8 v1, v3, 0x11

    .line 240
    .line 241
    const/16 v4, 0x10

    .line 242
    .line 243
    const/4 v5, 0x1

    .line 244
    const/4 v6, 0x0

    .line 245
    if-eq v1, v4, :cond_6

    .line 246
    .line 247
    move v1, v5

    .line 248
    goto :goto_6

    .line 249
    :cond_6
    move v1, v6

    .line 250
    :goto_6
    and-int/2addr v3, v5

    .line 251
    move-object v11, v2

    .line 252
    check-cast v11, Ll2/t;

    .line 253
    .line 254
    invoke-virtual {v11, v3, v1}, Ll2/t;->O(IZ)Z

    .line 255
    .line 256
    .line 257
    move-result v1

    .line 258
    if-eqz v1, :cond_a

    .line 259
    .line 260
    sget-object v1, Lj91/j;->a:Ll2/u2;

    .line 261
    .line 262
    invoke-virtual {v11, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 263
    .line 264
    .line 265
    move-result-object v2

    .line 266
    check-cast v2, Lj91/f;

    .line 267
    .line 268
    invoke-virtual {v2}, Lj91/f;->b()Lg4/p0;

    .line 269
    .line 270
    .line 271
    move-result-object v8

    .line 272
    const/16 v18, 0x0

    .line 273
    .line 274
    const/16 v19, 0x1fc

    .line 275
    .line 276
    iget-object v7, v0, Lb71/e;->e:Ljava/lang/String;

    .line 277
    .line 278
    const/4 v9, 0x0

    .line 279
    const/4 v10, 0x0

    .line 280
    move-object/from16 v17, v11

    .line 281
    .line 282
    const/4 v11, 0x0

    .line 283
    const/4 v12, 0x0

    .line 284
    const/4 v13, 0x0

    .line 285
    const-wide/16 v14, 0x0

    .line 286
    .line 287
    const/16 v16, 0x0

    .line 288
    .line 289
    invoke-static/range {v7 .. v19}, Lkp/x5;->a(Ljava/lang/String;Lg4/p0;Lx2/s;Lay0/k;IZIJLr4/k;Ll2/o;II)V

    .line 290
    .line 291
    .line 292
    move-object/from16 v11, v17

    .line 293
    .line 294
    sget-object v2, Li71/d;->a:Lh71/t;

    .line 295
    .line 296
    iget v3, v2, Lh71/t;->f:F

    .line 297
    .line 298
    sget-object v12, Lx2/p;->b:Lx2/p;

    .line 299
    .line 300
    invoke-static {v12, v3}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 301
    .line 302
    .line 303
    move-result-object v3

    .line 304
    invoke-static {v11, v3}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 305
    .line 306
    .line 307
    sget-object v3, Lk1/j;->a:Lk1/c;

    .line 308
    .line 309
    sget-object v4, Lx2/c;->m:Lx2/i;

    .line 310
    .line 311
    const/16 v7, 0x36

    .line 312
    .line 313
    invoke-static {v3, v4, v11, v7}, Lk1/e1;->a(Lk1/g;Lx2/i;Ll2/o;I)Lk1/g1;

    .line 314
    .line 315
    .line 316
    move-result-object v3

    .line 317
    iget-wide v7, v11, Ll2/t;->T:J

    .line 318
    .line 319
    invoke-static {v7, v8}, Ljava/lang/Long;->hashCode(J)I

    .line 320
    .line 321
    .line 322
    move-result v4

    .line 323
    invoke-virtual {v11}, Ll2/t;->m()Ll2/p1;

    .line 324
    .line 325
    .line 326
    move-result-object v7

    .line 327
    invoke-static {v11, v12}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 328
    .line 329
    .line 330
    move-result-object v8

    .line 331
    sget-object v9, Lv3/k;->m1:Lv3/j;

    .line 332
    .line 333
    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 334
    .line 335
    .line 336
    sget-object v9, Lv3/j;->b:Lv3/i;

    .line 337
    .line 338
    invoke-virtual {v11}, Ll2/t;->c0()V

    .line 339
    .line 340
    .line 341
    iget-boolean v10, v11, Ll2/t;->S:Z

    .line 342
    .line 343
    if-eqz v10, :cond_7

    .line 344
    .line 345
    invoke-virtual {v11, v9}, Ll2/t;->l(Lay0/a;)V

    .line 346
    .line 347
    .line 348
    goto :goto_7

    .line 349
    :cond_7
    invoke-virtual {v11}, Ll2/t;->m0()V

    .line 350
    .line 351
    .line 352
    :goto_7
    sget-object v9, Lv3/j;->g:Lv3/h;

    .line 353
    .line 354
    invoke-static {v9, v3, v11}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 355
    .line 356
    .line 357
    sget-object v3, Lv3/j;->f:Lv3/h;

    .line 358
    .line 359
    invoke-static {v3, v7, v11}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 360
    .line 361
    .line 362
    sget-object v3, Lv3/j;->j:Lv3/h;

    .line 363
    .line 364
    iget-boolean v7, v11, Ll2/t;->S:Z

    .line 365
    .line 366
    if-nez v7, :cond_8

    .line 367
    .line 368
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 369
    .line 370
    .line 371
    move-result-object v7

    .line 372
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 373
    .line 374
    .line 375
    move-result-object v9

    .line 376
    invoke-static {v7, v9}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 377
    .line 378
    .line 379
    move-result v7

    .line 380
    if-nez v7, :cond_9

    .line 381
    .line 382
    :cond_8
    invoke-static {v4, v11, v4, v3}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 383
    .line 384
    .line 385
    :cond_9
    sget-object v3, Lv3/j;->d:Lv3/h;

    .line 386
    .line 387
    invoke-static {v3, v8, v11}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 388
    .line 389
    .line 390
    iget v15, v2, Lh71/t;->b:F

    .line 391
    .line 392
    const/16 v16, 0x0

    .line 393
    .line 394
    const/16 v17, 0xb

    .line 395
    .line 396
    const/4 v13, 0x0

    .line 397
    const/4 v14, 0x0

    .line 398
    invoke-static/range {v12 .. v17}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 399
    .line 400
    .line 401
    move-result-object v7

    .line 402
    sget-object v2, Lh71/q;->a:Ll2/e0;

    .line 403
    .line 404
    invoke-virtual {v11, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 405
    .line 406
    .line 407
    move-result-object v2

    .line 408
    check-cast v2, Lh71/p;

    .line 409
    .line 410
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 411
    .line 412
    .line 413
    const v2, 0x7f08022e

    .line 414
    .line 415
    .line 416
    invoke-static {v2, v6, v11}, Ljp/fa;->b(IILl2/o;)Li3/c;

    .line 417
    .line 418
    .line 419
    move-result-object v8

    .line 420
    sget-object v2, Lh71/m;->a:Ll2/u2;

    .line 421
    .line 422
    invoke-virtual {v11, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 423
    .line 424
    .line 425
    move-result-object v2

    .line 426
    check-cast v2, Lh71/l;

    .line 427
    .line 428
    iget-object v2, v2, Lh71/l;->c:Lh71/f;

    .line 429
    .line 430
    iget-wide v9, v2, Lh71/f;->a:J

    .line 431
    .line 432
    const/4 v12, 0x6

    .line 433
    invoke-static/range {v7 .. v12}, Lkp/i0;->b(Lx2/s;Li3/c;JLl2/o;I)V

    .line 434
    .line 435
    .line 436
    invoke-virtual {v11, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 437
    .line 438
    .line 439
    move-result-object v1

    .line 440
    check-cast v1, Lj91/f;

    .line 441
    .line 442
    invoke-virtual {v1}, Lj91/f;->b()Lg4/p0;

    .line 443
    .line 444
    .line 445
    move-result-object v8

    .line 446
    const/16 v18, 0x0

    .line 447
    .line 448
    const/16 v19, 0x1fc

    .line 449
    .line 450
    iget-object v7, v0, Lb71/e;->f:Ljava/lang/String;

    .line 451
    .line 452
    const/4 v9, 0x0

    .line 453
    const/4 v10, 0x0

    .line 454
    move-object/from16 v17, v11

    .line 455
    .line 456
    const/4 v11, 0x0

    .line 457
    const/4 v12, 0x0

    .line 458
    const/4 v13, 0x0

    .line 459
    const-wide/16 v14, 0x0

    .line 460
    .line 461
    const/16 v16, 0x0

    .line 462
    .line 463
    invoke-static/range {v7 .. v19}, Lkp/x5;->a(Ljava/lang/String;Lg4/p0;Lx2/s;Lay0/k;IZIJLr4/k;Ll2/o;II)V

    .line 464
    .line 465
    .line 466
    move-object/from16 v11, v17

    .line 467
    .line 468
    invoke-virtual {v11, v5}, Ll2/t;->q(Z)V

    .line 469
    .line 470
    .line 471
    goto :goto_8

    .line 472
    :cond_a
    invoke-virtual {v11}, Ll2/t;->R()V

    .line 473
    .line 474
    .line 475
    :goto_8
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 476
    .line 477
    return-object v0

    .line 478
    nop

    .line 479
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
