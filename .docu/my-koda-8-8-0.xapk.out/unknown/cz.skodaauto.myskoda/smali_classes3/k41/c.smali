.class public final synthetic Lk41/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lz70/b;

.field public final synthetic f:Lx31/o;

.field public final synthetic g:Lay0/k;


# direct methods
.method public synthetic constructor <init>(Lz70/b;Lx31/o;Lay0/k;I)V
    .locals 0

    .line 1
    iput p4, p0, Lk41/c;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lk41/c;->e:Lz70/b;

    .line 4
    .line 5
    iput-object p2, p0, Lk41/c;->f:Lx31/o;

    .line 6
    .line 7
    iput-object p3, p0, Lk41/c;->g:Lay0/k;

    .line 8
    .line 9
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 10
    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 30

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lk41/c;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    iget-object v1, v0, Lk41/c;->e:Lz70/b;

    .line 9
    .line 10
    iget-object v1, v1, Lz70/b;->a:Lij0/a;

    .line 11
    .line 12
    move-object/from16 v2, p1

    .line 13
    .line 14
    check-cast v2, Landroidx/compose/foundation/lazy/a;

    .line 15
    .line 16
    move-object/from16 v3, p2

    .line 17
    .line 18
    check-cast v3, Ll2/o;

    .line 19
    .line 20
    move-object/from16 v4, p3

    .line 21
    .line 22
    check-cast v4, Ljava/lang/Integer;

    .line 23
    .line 24
    invoke-virtual {v4}, Ljava/lang/Integer;->intValue()I

    .line 25
    .line 26
    .line 27
    move-result v4

    .line 28
    const-string v5, "$this$item"

    .line 29
    .line 30
    invoke-static {v2, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    and-int/lit8 v2, v4, 0x11

    .line 34
    .line 35
    const/16 v5, 0x10

    .line 36
    .line 37
    const/4 v6, 0x0

    .line 38
    const/4 v7, 0x1

    .line 39
    if-eq v2, v5, :cond_0

    .line 40
    .line 41
    move v2, v7

    .line 42
    goto :goto_0

    .line 43
    :cond_0
    move v2, v6

    .line 44
    :goto_0
    and-int/2addr v4, v7

    .line 45
    move-object v13, v3

    .line 46
    check-cast v13, Ll2/t;

    .line 47
    .line 48
    invoke-virtual {v13, v4, v2}, Ll2/t;->O(IZ)Z

    .line 49
    .line 50
    .line 51
    move-result v2

    .line 52
    if-eqz v2, :cond_6

    .line 53
    .line 54
    sget-object v2, Lk1/j;->g:Lk1/f;

    .line 55
    .line 56
    sget-object v3, Lx2/c;->n:Lx2/i;

    .line 57
    .line 58
    sget-object v4, Lx2/p;->b:Lx2/p;

    .line 59
    .line 60
    const/high16 v5, 0x3f800000    # 1.0f

    .line 61
    .line 62
    invoke-static {v4, v5}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 63
    .line 64
    .line 65
    move-result-object v14

    .line 66
    sget-object v4, Lj91/a;->a:Ll2/u2;

    .line 67
    .line 68
    invoke-virtual {v13, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    move-result-object v4

    .line 72
    check-cast v4, Lj91/c;

    .line 73
    .line 74
    iget v4, v4, Lj91/c;->c:F

    .line 75
    .line 76
    const/16 v19, 0x7

    .line 77
    .line 78
    const/4 v15, 0x0

    .line 79
    const/16 v16, 0x0

    .line 80
    .line 81
    const/16 v17, 0x0

    .line 82
    .line 83
    move/from16 v18, v4

    .line 84
    .line 85
    invoke-static/range {v14 .. v19}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 86
    .line 87
    .line 88
    move-result-object v4

    .line 89
    const/16 v5, 0x36

    .line 90
    .line 91
    invoke-static {v2, v3, v13, v5}, Lk1/e1;->a(Lk1/g;Lx2/i;Ll2/o;I)Lk1/g1;

    .line 92
    .line 93
    .line 94
    move-result-object v2

    .line 95
    iget-wide v8, v13, Ll2/t;->T:J

    .line 96
    .line 97
    invoke-static {v8, v9}, Ljava/lang/Long;->hashCode(J)I

    .line 98
    .line 99
    .line 100
    move-result v3

    .line 101
    invoke-virtual {v13}, Ll2/t;->m()Ll2/p1;

    .line 102
    .line 103
    .line 104
    move-result-object v5

    .line 105
    invoke-static {v13, v4}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 106
    .line 107
    .line 108
    move-result-object v4

    .line 109
    sget-object v8, Lv3/k;->m1:Lv3/j;

    .line 110
    .line 111
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 112
    .line 113
    .line 114
    sget-object v8, Lv3/j;->b:Lv3/i;

    .line 115
    .line 116
    invoke-virtual {v13}, Ll2/t;->c0()V

    .line 117
    .line 118
    .line 119
    iget-boolean v9, v13, Ll2/t;->S:Z

    .line 120
    .line 121
    if-eqz v9, :cond_1

    .line 122
    .line 123
    invoke-virtual {v13, v8}, Ll2/t;->l(Lay0/a;)V

    .line 124
    .line 125
    .line 126
    goto :goto_1

    .line 127
    :cond_1
    invoke-virtual {v13}, Ll2/t;->m0()V

    .line 128
    .line 129
    .line 130
    :goto_1
    sget-object v8, Lv3/j;->g:Lv3/h;

    .line 131
    .line 132
    invoke-static {v8, v2, v13}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 133
    .line 134
    .line 135
    sget-object v2, Lv3/j;->f:Lv3/h;

    .line 136
    .line 137
    invoke-static {v2, v5, v13}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 138
    .line 139
    .line 140
    sget-object v2, Lv3/j;->j:Lv3/h;

    .line 141
    .line 142
    iget-boolean v5, v13, Ll2/t;->S:Z

    .line 143
    .line 144
    if-nez v5, :cond_2

    .line 145
    .line 146
    invoke-virtual {v13}, Ll2/t;->L()Ljava/lang/Object;

    .line 147
    .line 148
    .line 149
    move-result-object v5

    .line 150
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 151
    .line 152
    .line 153
    move-result-object v8

    .line 154
    invoke-static {v5, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 155
    .line 156
    .line 157
    move-result v5

    .line 158
    if-nez v5, :cond_3

    .line 159
    .line 160
    :cond_2
    invoke-static {v3, v13, v3, v2}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 161
    .line 162
    .line 163
    :cond_3
    sget-object v2, Lv3/j;->d:Lv3/h;

    .line 164
    .line 165
    invoke-static {v2, v4, v13}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 166
    .line 167
    .line 168
    new-array v2, v6, [Ljava/lang/Object;

    .line 169
    .line 170
    move-object v3, v1

    .line 171
    check-cast v3, Ljj0/f;

    .line 172
    .line 173
    const v4, 0x7f121141

    .line 174
    .line 175
    .line 176
    invoke-virtual {v3, v4, v2}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 177
    .line 178
    .line 179
    move-result-object v8

    .line 180
    sget-object v2, Lj91/j;->a:Ll2/u2;

    .line 181
    .line 182
    invoke-virtual {v13, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 183
    .line 184
    .line 185
    move-result-object v2

    .line 186
    check-cast v2, Lj91/f;

    .line 187
    .line 188
    invoke-virtual {v2}, Lj91/f;->k()Lg4/p0;

    .line 189
    .line 190
    .line 191
    move-result-object v9

    .line 192
    new-instance v2, Lr4/k;

    .line 193
    .line 194
    const/4 v3, 0x5

    .line 195
    invoke-direct {v2, v3}, Lr4/k;-><init>(I)V

    .line 196
    .line 197
    .line 198
    const/16 v28, 0x0

    .line 199
    .line 200
    const v29, 0xfbfc

    .line 201
    .line 202
    .line 203
    const/4 v10, 0x0

    .line 204
    const-wide/16 v11, 0x0

    .line 205
    .line 206
    move-object/from16 v26, v13

    .line 207
    .line 208
    const-wide/16 v13, 0x0

    .line 209
    .line 210
    const/4 v15, 0x0

    .line 211
    const-wide/16 v16, 0x0

    .line 212
    .line 213
    const/16 v18, 0x0

    .line 214
    .line 215
    const-wide/16 v20, 0x0

    .line 216
    .line 217
    const/16 v22, 0x0

    .line 218
    .line 219
    const/16 v23, 0x0

    .line 220
    .line 221
    const/16 v24, 0x0

    .line 222
    .line 223
    const/16 v25, 0x0

    .line 224
    .line 225
    const/16 v27, 0x0

    .line 226
    .line 227
    move-object/from16 v19, v2

    .line 228
    .line 229
    invoke-static/range {v8 .. v29}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 230
    .line 231
    .line 232
    move-object/from16 v13, v26

    .line 233
    .line 234
    new-array v2, v6, [Ljava/lang/Object;

    .line 235
    .line 236
    check-cast v1, Ljj0/f;

    .line 237
    .line 238
    const v3, 0x7f121142

    .line 239
    .line 240
    .line 241
    invoke-virtual {v1, v3, v2}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 242
    .line 243
    .line 244
    move-result-object v1

    .line 245
    iget-object v2, v0, Lk41/c;->f:Lx31/o;

    .line 246
    .line 247
    iget-object v2, v2, Lx31/o;->i:Ljava/util/List;

    .line 248
    .line 249
    invoke-interface {v2}, Ljava/util/List;->size()I

    .line 250
    .line 251
    .line 252
    move-result v2

    .line 253
    new-instance v3, Ljava/lang/StringBuilder;

    .line 254
    .line 255
    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V

    .line 256
    .line 257
    .line 258
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 259
    .line 260
    .line 261
    const-string v1, " ("

    .line 262
    .line 263
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 264
    .line 265
    .line 266
    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 267
    .line 268
    .line 269
    const-string v1, ")"

    .line 270
    .line 271
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 272
    .line 273
    .line 274
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 275
    .line 276
    .line 277
    move-result-object v12

    .line 278
    iget-object v0, v0, Lk41/c;->g:Lay0/k;

    .line 279
    .line 280
    invoke-virtual {v13, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 281
    .line 282
    .line 283
    move-result v1

    .line 284
    invoke-virtual {v13}, Ll2/t;->L()Ljava/lang/Object;

    .line 285
    .line 286
    .line 287
    move-result-object v2

    .line 288
    if-nez v1, :cond_4

    .line 289
    .line 290
    sget-object v1, Ll2/n;->a:Ll2/x0;

    .line 291
    .line 292
    if-ne v2, v1, :cond_5

    .line 293
    .line 294
    :cond_4
    new-instance v2, Lik/b;

    .line 295
    .line 296
    const/16 v1, 0xa

    .line 297
    .line 298
    invoke-direct {v2, v1, v0}, Lik/b;-><init>(ILay0/k;)V

    .line 299
    .line 300
    .line 301
    invoke-virtual {v13, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 302
    .line 303
    .line 304
    :cond_5
    move-object v10, v2

    .line 305
    check-cast v10, Lay0/a;

    .line 306
    .line 307
    const/4 v8, 0x0

    .line 308
    const/16 v9, 0x1c

    .line 309
    .line 310
    const/4 v11, 0x0

    .line 311
    const/4 v14, 0x0

    .line 312
    const/4 v15, 0x0

    .line 313
    invoke-static/range {v8 .. v15}, Li91/j0;->h0(IILay0/a;Ljava/lang/Integer;Ljava/lang/String;Ll2/o;Lx2/s;Z)V

    .line 314
    .line 315
    .line 316
    invoke-virtual {v13, v7}, Ll2/t;->q(Z)V

    .line 317
    .line 318
    .line 319
    goto :goto_2

    .line 320
    :cond_6
    invoke-virtual {v13}, Ll2/t;->R()V

    .line 321
    .line 322
    .line 323
    :goto_2
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 324
    .line 325
    return-object v0

    .line 326
    :pswitch_0
    move-object/from16 v1, p1

    .line 327
    .line 328
    check-cast v1, Landroidx/compose/foundation/lazy/a;

    .line 329
    .line 330
    move-object/from16 v2, p2

    .line 331
    .line 332
    check-cast v2, Ll2/o;

    .line 333
    .line 334
    move-object/from16 v3, p3

    .line 335
    .line 336
    check-cast v3, Ljava/lang/Integer;

    .line 337
    .line 338
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 339
    .line 340
    .line 341
    move-result v3

    .line 342
    const-string v4, "$this$item"

    .line 343
    .line 344
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 345
    .line 346
    .line 347
    and-int/lit8 v1, v3, 0x11

    .line 348
    .line 349
    const/16 v4, 0x10

    .line 350
    .line 351
    const/4 v5, 0x0

    .line 352
    const/4 v6, 0x1

    .line 353
    if-eq v1, v4, :cond_7

    .line 354
    .line 355
    move v1, v6

    .line 356
    goto :goto_3

    .line 357
    :cond_7
    move v1, v5

    .line 358
    :goto_3
    and-int/2addr v3, v6

    .line 359
    check-cast v2, Ll2/t;

    .line 360
    .line 361
    invoke-virtual {v2, v3, v1}, Ll2/t;->O(IZ)Z

    .line 362
    .line 363
    .line 364
    move-result v1

    .line 365
    if-eqz v1, :cond_a

    .line 366
    .line 367
    sget-object v1, Lj91/a;->a:Ll2/u2;

    .line 368
    .line 369
    invoke-virtual {v2, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 370
    .line 371
    .line 372
    move-result-object v1

    .line 373
    check-cast v1, Lj91/c;

    .line 374
    .line 375
    iget v8, v1, Lj91/c;->d:F

    .line 376
    .line 377
    const/4 v10, 0x0

    .line 378
    const/16 v11, 0xd

    .line 379
    .line 380
    sget-object v6, Lx2/p;->b:Lx2/p;

    .line 381
    .line 382
    const/4 v7, 0x0

    .line 383
    const/4 v9, 0x0

    .line 384
    invoke-static/range {v6 .. v11}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 385
    .line 386
    .line 387
    move-result-object v9

    .line 388
    iget-object v1, v0, Lk41/c;->e:Lz70/b;

    .line 389
    .line 390
    iget-object v1, v1, Lz70/b;->a:Lij0/a;

    .line 391
    .line 392
    new-array v3, v5, [Ljava/lang/Object;

    .line 393
    .line 394
    check-cast v1, Ljj0/f;

    .line 395
    .line 396
    const v4, 0x7f121140

    .line 397
    .line 398
    .line 399
    invoke-virtual {v1, v4, v3}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 400
    .line 401
    .line 402
    move-result-object v7

    .line 403
    iget-object v1, v0, Lk41/c;->f:Lx31/o;

    .line 404
    .line 405
    iget-object v3, v1, Lx31/o;->l:Ll4/v;

    .line 406
    .line 407
    iget v1, v1, Lx31/o;->m:I

    .line 408
    .line 409
    iget-object v3, v3, Ll4/v;->a:Lg4/g;

    .line 410
    .line 411
    iget-object v3, v3, Lg4/g;->e:Ljava/lang/String;

    .line 412
    .line 413
    invoke-static {v1, v3}, Lly0/p;->j0(ILjava/lang/String;)Ljava/lang/String;

    .line 414
    .line 415
    .line 416
    move-result-object v6

    .line 417
    iget-object v0, v0, Lk41/c;->g:Lay0/k;

    .line 418
    .line 419
    invoke-virtual {v2, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 420
    .line 421
    .line 422
    move-result v3

    .line 423
    invoke-virtual {v2}, Ll2/t;->L()Ljava/lang/Object;

    .line 424
    .line 425
    .line 426
    move-result-object v4

    .line 427
    if-nez v3, :cond_8

    .line 428
    .line 429
    sget-object v3, Ll2/n;->a:Ll2/x0;

    .line 430
    .line 431
    if-ne v4, v3, :cond_9

    .line 432
    .line 433
    :cond_8
    new-instance v4, Li50/d;

    .line 434
    .line 435
    const/4 v3, 0x7

    .line 436
    invoke-direct {v4, v3, v0}, Li50/d;-><init>(ILay0/k;)V

    .line 437
    .line 438
    .line 439
    invoke-virtual {v2, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 440
    .line 441
    .line 442
    :cond_9
    move-object v8, v4

    .line 443
    check-cast v8, Lay0/k;

    .line 444
    .line 445
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 446
    .line 447
    .line 448
    move-result-object v14

    .line 449
    const/16 v21, 0x180

    .line 450
    .line 451
    const v22, 0xe7f0

    .line 452
    .line 453
    .line 454
    const/4 v10, 0x0

    .line 455
    const/4 v11, 0x0

    .line 456
    const/4 v12, 0x0

    .line 457
    const/4 v13, 0x0

    .line 458
    const/4 v15, 0x1

    .line 459
    const/16 v16, 0x0

    .line 460
    .line 461
    const/16 v17, 0x0

    .line 462
    .line 463
    const/16 v18, 0x0

    .line 464
    .line 465
    const/16 v20, 0x0

    .line 466
    .line 467
    move-object/from16 v19, v2

    .line 468
    .line 469
    invoke-static/range {v6 .. v22}, Li91/j4;->b(Ljava/lang/String;Ljava/lang/String;Lay0/k;Lx2/s;ZLjava/lang/String;IILjava/lang/Integer;ZLl4/d0;Lt1/o0;Lt1/n0;Ll2/o;III)V

    .line 470
    .line 471
    .line 472
    goto :goto_4

    .line 473
    :cond_a
    move-object/from16 v19, v2

    .line 474
    .line 475
    invoke-virtual/range {v19 .. v19}, Ll2/t;->R()V

    .line 476
    .line 477
    .line 478
    :goto_4
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 479
    .line 480
    return-object v0

    .line 481
    :pswitch_1
    move-object/from16 v1, p1

    .line 482
    .line 483
    check-cast v1, Landroidx/compose/foundation/lazy/a;

    .line 484
    .line 485
    move-object/from16 v2, p2

    .line 486
    .line 487
    check-cast v2, Ll2/o;

    .line 488
    .line 489
    move-object/from16 v3, p3

    .line 490
    .line 491
    check-cast v3, Ljava/lang/Integer;

    .line 492
    .line 493
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 494
    .line 495
    .line 496
    move-result v3

    .line 497
    const-string v4, "$this$item"

    .line 498
    .line 499
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 500
    .line 501
    .line 502
    and-int/lit8 v1, v3, 0x11

    .line 503
    .line 504
    const/16 v4, 0x10

    .line 505
    .line 506
    const/4 v5, 0x0

    .line 507
    const/4 v6, 0x1

    .line 508
    if-eq v1, v4, :cond_b

    .line 509
    .line 510
    move v1, v6

    .line 511
    goto :goto_5

    .line 512
    :cond_b
    move v1, v5

    .line 513
    :goto_5
    and-int/2addr v3, v6

    .line 514
    move-object v11, v2

    .line 515
    check-cast v11, Ll2/t;

    .line 516
    .line 517
    invoke-virtual {v11, v3, v1}, Ll2/t;->O(IZ)Z

    .line 518
    .line 519
    .line 520
    move-result v1

    .line 521
    if-eqz v1, :cond_e

    .line 522
    .line 523
    sget-object v1, Lj91/a;->a:Ll2/u2;

    .line 524
    .line 525
    invoke-virtual {v11, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 526
    .line 527
    .line 528
    move-result-object v1

    .line 529
    check-cast v1, Lj91/c;

    .line 530
    .line 531
    iget v1, v1, Lj91/c;->g:F

    .line 532
    .line 533
    const/16 v17, 0x7

    .line 534
    .line 535
    sget-object v12, Lx2/p;->b:Lx2/p;

    .line 536
    .line 537
    const/4 v13, 0x0

    .line 538
    const/4 v14, 0x0

    .line 539
    const/4 v15, 0x0

    .line 540
    move/from16 v16, v1

    .line 541
    .line 542
    invoke-static/range {v12 .. v17}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 543
    .line 544
    .line 545
    move-result-object v12

    .line 546
    iget-object v1, v0, Lk41/c;->e:Lz70/b;

    .line 547
    .line 548
    iget-object v1, v1, Lz70/b;->a:Lij0/a;

    .line 549
    .line 550
    new-array v2, v5, [Ljava/lang/Object;

    .line 551
    .line 552
    check-cast v1, Ljj0/f;

    .line 553
    .line 554
    const v3, 0x7f121142

    .line 555
    .line 556
    .line 557
    invoke-virtual {v1, v3, v2}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 558
    .line 559
    .line 560
    move-result-object v1

    .line 561
    iget-object v2, v0, Lk41/c;->f:Lx31/o;

    .line 562
    .line 563
    iget-object v2, v2, Lx31/o;->i:Ljava/util/List;

    .line 564
    .line 565
    invoke-interface {v2}, Ljava/util/List;->size()I

    .line 566
    .line 567
    .line 568
    move-result v2

    .line 569
    new-instance v3, Ljava/lang/StringBuilder;

    .line 570
    .line 571
    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V

    .line 572
    .line 573
    .line 574
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 575
    .line 576
    .line 577
    const-string v1, " ("

    .line 578
    .line 579
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 580
    .line 581
    .line 582
    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 583
    .line 584
    .line 585
    const-string v1, ")"

    .line 586
    .line 587
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 588
    .line 589
    .line 590
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 591
    .line 592
    .line 593
    move-result-object v10

    .line 594
    iget-object v0, v0, Lk41/c;->g:Lay0/k;

    .line 595
    .line 596
    invoke-virtual {v11, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 597
    .line 598
    .line 599
    move-result v1

    .line 600
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 601
    .line 602
    .line 603
    move-result-object v2

    .line 604
    if-nez v1, :cond_c

    .line 605
    .line 606
    sget-object v1, Ll2/n;->a:Ll2/x0;

    .line 607
    .line 608
    if-ne v2, v1, :cond_d

    .line 609
    .line 610
    :cond_c
    new-instance v2, Lik/b;

    .line 611
    .line 612
    const/16 v1, 0x9

    .line 613
    .line 614
    invoke-direct {v2, v1, v0}, Lik/b;-><init>(ILay0/k;)V

    .line 615
    .line 616
    .line 617
    invoke-virtual {v11, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 618
    .line 619
    .line 620
    :cond_d
    move-object v8, v2

    .line 621
    check-cast v8, Lay0/a;

    .line 622
    .line 623
    const/4 v6, 0x0

    .line 624
    const/16 v7, 0x18

    .line 625
    .line 626
    const/4 v9, 0x0

    .line 627
    const/4 v13, 0x0

    .line 628
    invoke-static/range {v6 .. v13}, Li91/j0;->h0(IILay0/a;Ljava/lang/Integer;Ljava/lang/String;Ll2/o;Lx2/s;Z)V

    .line 629
    .line 630
    .line 631
    goto :goto_6

    .line 632
    :cond_e
    invoke-virtual {v11}, Ll2/t;->R()V

    .line 633
    .line 634
    .line 635
    :goto_6
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 636
    .line 637
    return-object v0

    .line 638
    nop

    .line 639
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
