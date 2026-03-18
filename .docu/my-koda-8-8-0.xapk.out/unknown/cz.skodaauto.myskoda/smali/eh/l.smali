.class public final synthetic Leh/l;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/p;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;

.field public final synthetic f:Ljava/lang/Object;

.field public final synthetic g:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p4, p0, Leh/l;->d:I

    iput-object p1, p0, Leh/l;->e:Ljava/lang/Object;

    iput-object p2, p0, Leh/l;->f:Ljava/lang/Object;

    iput-object p3, p0, Leh/l;->g:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;ZLjava/lang/Object;I)V
    .locals 0

    .line 2
    iput p5, p0, Leh/l;->d:I

    iput-object p1, p0, Leh/l;->f:Ljava/lang/Object;

    iput-object p2, p0, Leh/l;->e:Ljava/lang/Object;

    iput-object p4, p0, Leh/l;->g:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lyj/b;Lyj/b;Ll2/b1;)V
    .locals 1

    .line 3
    const/4 v0, 0x7

    iput v0, p0, Leh/l;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Leh/l;->f:Ljava/lang/Object;

    iput-object p2, p0, Leh/l;->g:Ljava/lang/Object;

    iput-object p3, p0, Leh/l;->e:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 31

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Leh/l;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    iget-object v1, v0, Leh/l;->e:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v1, Ljava/lang/String;

    .line 11
    .line 12
    iget-object v2, v0, Leh/l;->f:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast v2, Lay0/k;

    .line 15
    .line 16
    iget-object v0, v0, Leh/l;->g:Ljava/lang/Object;

    .line 17
    .line 18
    check-cast v0, Lay0/a;

    .line 19
    .line 20
    move-object/from16 v3, p1

    .line 21
    .line 22
    check-cast v3, Lb1/n;

    .line 23
    .line 24
    move-object/from16 v4, p2

    .line 25
    .line 26
    check-cast v4, Lz9/k;

    .line 27
    .line 28
    move-object/from16 v5, p3

    .line 29
    .line 30
    check-cast v5, Ll2/o;

    .line 31
    .line 32
    move-object/from16 v6, p4

    .line 33
    .line 34
    check-cast v6, Ljava/lang/Integer;

    .line 35
    .line 36
    const-string v7, "$this$composable"

    .line 37
    .line 38
    const-string v8, "it"

    .line 39
    .line 40
    invoke-static {v6, v3, v7, v4, v8}, Lz9/c;->c(Ljava/lang/Integer;Lb1/n;Ljava/lang/String;Lz9/k;Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    const/4 v3, 0x0

    .line 44
    invoke-static {v1, v2, v0, v5, v3}, Ljp/z0;->a(Ljava/lang/String;Lay0/k;Lay0/a;Ll2/o;I)V

    .line 45
    .line 46
    .line 47
    :goto_0
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 48
    .line 49
    return-object v0

    .line 50
    :pswitch_0
    iget-object v1, v0, Leh/l;->f:Ljava/lang/Object;

    .line 51
    .line 52
    check-cast v1, Lyj/b;

    .line 53
    .line 54
    iget-object v2, v0, Leh/l;->e:Ljava/lang/Object;

    .line 55
    .line 56
    check-cast v2, Lyj/b;

    .line 57
    .line 58
    iget-object v0, v0, Leh/l;->g:Ljava/lang/Object;

    .line 59
    .line 60
    check-cast v0, Ly1/i;

    .line 61
    .line 62
    move-object/from16 v3, p1

    .line 63
    .line 64
    check-cast v3, Lb1/n;

    .line 65
    .line 66
    move-object/from16 v4, p2

    .line 67
    .line 68
    check-cast v4, Lz9/k;

    .line 69
    .line 70
    move-object/from16 v5, p3

    .line 71
    .line 72
    check-cast v5, Ll2/o;

    .line 73
    .line 74
    move-object/from16 v6, p4

    .line 75
    .line 76
    check-cast v6, Ljava/lang/Integer;

    .line 77
    .line 78
    const-string v7, "$this$composable"

    .line 79
    .line 80
    const-string v8, "it"

    .line 81
    .line 82
    invoke-static {v6, v3, v7, v4, v8}, Lz9/c;->c(Ljava/lang/Integer;Lb1/n;Ljava/lang/String;Lz9/k;Ljava/lang/String;)V

    .line 83
    .line 84
    .line 85
    const/4 v3, 0x0

    .line 86
    invoke-static {v1, v2, v0, v5, v3}, Lsr/b;->a(Lyj/b;Lyj/b;Ly1/i;Ll2/o;I)V

    .line 87
    .line 88
    .line 89
    goto :goto_0

    .line 90
    :pswitch_1
    iget-object v1, v0, Leh/l;->f:Ljava/lang/Object;

    .line 91
    .line 92
    check-cast v1, Lyj/b;

    .line 93
    .line 94
    iget-object v2, v0, Leh/l;->g:Ljava/lang/Object;

    .line 95
    .line 96
    check-cast v2, Lyj/b;

    .line 97
    .line 98
    iget-object v0, v0, Leh/l;->e:Ljava/lang/Object;

    .line 99
    .line 100
    check-cast v0, Ll2/b1;

    .line 101
    .line 102
    move-object/from16 v3, p1

    .line 103
    .line 104
    check-cast v3, Lb1/n;

    .line 105
    .line 106
    move-object/from16 v4, p2

    .line 107
    .line 108
    check-cast v4, Lz9/k;

    .line 109
    .line 110
    move-object/from16 v5, p3

    .line 111
    .line 112
    check-cast v5, Ll2/o;

    .line 113
    .line 114
    move-object/from16 v6, p4

    .line 115
    .line 116
    check-cast v6, Ljava/lang/Integer;

    .line 117
    .line 118
    const-string v7, "$this$composable"

    .line 119
    .line 120
    const-string v8, "it"

    .line 121
    .line 122
    invoke-static {v6, v3, v7, v4, v8}, Lz9/c;->c(Ljava/lang/Integer;Lb1/n;Ljava/lang/String;Lz9/k;Ljava/lang/String;)V

    .line 123
    .line 124
    .line 125
    check-cast v5, Ll2/t;

    .line 126
    .line 127
    invoke-virtual {v5, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 128
    .line 129
    .line 130
    move-result v3

    .line 131
    invoke-virtual {v5}, Ll2/t;->L()Ljava/lang/Object;

    .line 132
    .line 133
    .line 134
    move-result-object v4

    .line 135
    if-nez v3, :cond_0

    .line 136
    .line 137
    sget-object v3, Ll2/n;->a:Ll2/x0;

    .line 138
    .line 139
    if-ne v4, v3, :cond_1

    .line 140
    .line 141
    :cond_0
    new-instance v4, Lfi/a;

    .line 142
    .line 143
    const/4 v3, 0x1

    .line 144
    invoke-direct {v4, v1, v3}, Lfi/a;-><init>(Lyj/b;I)V

    .line 145
    .line 146
    .line 147
    invoke-virtual {v5, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 148
    .line 149
    .line 150
    :cond_1
    check-cast v4, Lay0/a;

    .line 151
    .line 152
    const/4 v3, 0x6

    .line 153
    const/4 v6, 0x1

    .line 154
    const/4 v7, 0x0

    .line 155
    invoke-static {v6, v4, v5, v3, v7}, Ljp/tb;->a(ZLay0/a;Ll2/o;II)V

    .line 156
    .line 157
    .line 158
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 159
    .line 160
    .line 161
    move-result-object v0

    .line 162
    check-cast v0, Ljava/lang/String;

    .line 163
    .line 164
    invoke-static {v2, v1, v0, v5, v7}, Llp/me;->d(Lyj/b;Lyj/b;Ljava/lang/String;Ll2/o;I)V

    .line 165
    .line 166
    .line 167
    goto :goto_0

    .line 168
    :pswitch_2
    iget-object v1, v0, Leh/l;->e:Ljava/lang/Object;

    .line 169
    .line 170
    check-cast v1, Ljava/util/List;

    .line 171
    .line 172
    iget-object v2, v0, Leh/l;->f:Ljava/lang/Object;

    .line 173
    .line 174
    check-cast v2, Lay0/k;

    .line 175
    .line 176
    iget-object v0, v0, Leh/l;->g:Ljava/lang/Object;

    .line 177
    .line 178
    check-cast v0, Ljava/lang/String;

    .line 179
    .line 180
    move-object/from16 v3, p1

    .line 181
    .line 182
    check-cast v3, Landroidx/compose/foundation/lazy/a;

    .line 183
    .line 184
    move-object/from16 v4, p2

    .line 185
    .line 186
    check-cast v4, Ljava/lang/Integer;

    .line 187
    .line 188
    invoke-virtual {v4}, Ljava/lang/Integer;->intValue()I

    .line 189
    .line 190
    .line 191
    move-result v4

    .line 192
    move-object/from16 v5, p3

    .line 193
    .line 194
    check-cast v5, Ll2/o;

    .line 195
    .line 196
    move-object/from16 v6, p4

    .line 197
    .line 198
    check-cast v6, Ljava/lang/Integer;

    .line 199
    .line 200
    invoke-virtual {v6}, Ljava/lang/Integer;->intValue()I

    .line 201
    .line 202
    .line 203
    move-result v6

    .line 204
    const-string v7, "$this$items"

    .line 205
    .line 206
    invoke-static {v3, v7}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 207
    .line 208
    .line 209
    and-int/lit8 v3, v6, 0x30

    .line 210
    .line 211
    const/16 v7, 0x10

    .line 212
    .line 213
    const/16 v8, 0x20

    .line 214
    .line 215
    if-nez v3, :cond_3

    .line 216
    .line 217
    move-object v3, v5

    .line 218
    check-cast v3, Ll2/t;

    .line 219
    .line 220
    invoke-virtual {v3, v4}, Ll2/t;->e(I)Z

    .line 221
    .line 222
    .line 223
    move-result v3

    .line 224
    if-eqz v3, :cond_2

    .line 225
    .line 226
    move v3, v8

    .line 227
    goto :goto_1

    .line 228
    :cond_2
    move v3, v7

    .line 229
    :goto_1
    or-int/2addr v6, v3

    .line 230
    :cond_3
    and-int/lit16 v3, v6, 0x91

    .line 231
    .line 232
    const/16 v9, 0x90

    .line 233
    .line 234
    const/4 v10, 0x1

    .line 235
    if-eq v3, v9, :cond_4

    .line 236
    .line 237
    move v3, v10

    .line 238
    goto :goto_2

    .line 239
    :cond_4
    const/4 v3, 0x0

    .line 240
    :goto_2
    and-int/2addr v6, v10

    .line 241
    check-cast v5, Ll2/t;

    .line 242
    .line 243
    invoke-virtual {v5, v6, v3}, Ll2/t;->O(IZ)Z

    .line 244
    .line 245
    .line 246
    move-result v3

    .line 247
    if-eqz v3, :cond_9

    .line 248
    .line 249
    invoke-virtual {v5}, Ll2/t;->L()Ljava/lang/Object;

    .line 250
    .line 251
    .line 252
    move-result-object v3

    .line 253
    sget-object v6, Ll2/n;->a:Ll2/x0;

    .line 254
    .line 255
    if-ne v3, v6, :cond_5

    .line 256
    .line 257
    const/4 v3, 0x0

    .line 258
    invoke-static {v3}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 259
    .line 260
    .line 261
    move-result-object v3

    .line 262
    invoke-virtual {v5, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 263
    .line 264
    .line 265
    :cond_5
    check-cast v3, Ll2/b1;

    .line 266
    .line 267
    new-instance v9, Lgl/f;

    .line 268
    .line 269
    invoke-interface {v1, v4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 270
    .line 271
    .line 272
    move-result-object v1

    .line 273
    check-cast v1, Ljava/lang/String;

    .line 274
    .line 275
    invoke-direct {v9, v1, v10}, Lgl/f;-><init>(Ljava/lang/String;Z)V

    .line 276
    .line 277
    .line 278
    invoke-static {v5}, Ldk/b;->n(Ll2/o;)Lg4/g0;

    .line 279
    .line 280
    .line 281
    move-result-object v1

    .line 282
    invoke-static {v9, v1, v5}, Lhl/a;->b(Lgl/h;Lg4/g0;Ll2/o;)Lg4/g;

    .line 283
    .line 284
    .line 285
    move-result-object v11

    .line 286
    int-to-float v14, v8

    .line 287
    int-to-float v13, v7

    .line 288
    const/16 v16, 0x0

    .line 289
    .line 290
    const/16 v17, 0x8

    .line 291
    .line 292
    sget-object v12, Lx2/p;->b:Lx2/p;

    .line 293
    .line 294
    move v15, v13

    .line 295
    invoke-static/range {v12 .. v17}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 296
    .line 297
    .line 298
    move-result-object v1

    .line 299
    invoke-virtual {v5, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 300
    .line 301
    .line 302
    move-result v7

    .line 303
    invoke-virtual {v5}, Ll2/t;->L()Ljava/lang/Object;

    .line 304
    .line 305
    .line 306
    move-result-object v8

    .line 307
    if-nez v7, :cond_6

    .line 308
    .line 309
    if-ne v8, v6, :cond_7

    .line 310
    .line 311
    :cond_6
    new-instance v8, Li50/d;

    .line 312
    .line 313
    const/16 v7, 0x15

    .line 314
    .line 315
    invoke-direct {v8, v7, v2}, Li50/d;-><init>(ILay0/k;)V

    .line 316
    .line 317
    .line 318
    invoke-virtual {v5, v8}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 319
    .line 320
    .line 321
    :cond_7
    check-cast v8, Lay0/k;

    .line 322
    .line 323
    invoke-static {v1, v3, v8}, Lhl/a;->a(Lx2/s;Ll2/b1;Lay0/k;)Lx2/s;

    .line 324
    .line 325
    .line 326
    move-result-object v1

    .line 327
    new-instance v2, Ljava/lang/StringBuilder;

    .line 328
    .line 329
    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    .line 330
    .line 331
    .line 332
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 333
    .line 334
    .line 335
    const-string v0, "tariff_legal_disclaimer_"

    .line 336
    .line 337
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 338
    .line 339
    .line 340
    invoke-virtual {v2, v4}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 341
    .line 342
    .line 343
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 344
    .line 345
    .line 346
    move-result-object v0

    .line 347
    invoke-static {v1, v0}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 348
    .line 349
    .line 350
    move-result-object v12

    .line 351
    sget-object v0, Lj91/j;->a:Ll2/u2;

    .line 352
    .line 353
    invoke-virtual {v5, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 354
    .line 355
    .line 356
    move-result-object v0

    .line 357
    check-cast v0, Lj91/f;

    .line 358
    .line 359
    invoke-virtual {v0}, Lj91/f;->e()Lg4/p0;

    .line 360
    .line 361
    .line 362
    move-result-object v13

    .line 363
    sget-object v0, Lj91/h;->a:Ll2/u2;

    .line 364
    .line 365
    invoke-virtual {v5, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 366
    .line 367
    .line 368
    move-result-object v0

    .line 369
    check-cast v0, Lj91/e;

    .line 370
    .line 371
    invoke-virtual {v0}, Lj91/e;->s()J

    .line 372
    .line 373
    .line 374
    move-result-wide v14

    .line 375
    invoke-virtual {v5}, Ll2/t;->L()Ljava/lang/Object;

    .line 376
    .line 377
    .line 378
    move-result-object v0

    .line 379
    if-ne v0, v6, :cond_8

    .line 380
    .line 381
    new-instance v0, Lle/b;

    .line 382
    .line 383
    const/16 v1, 0x9

    .line 384
    .line 385
    invoke-direct {v0, v3, v1}, Lle/b;-><init>(Ll2/b1;I)V

    .line 386
    .line 387
    .line 388
    invoke-virtual {v5, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 389
    .line 390
    .line 391
    :cond_8
    move-object/from16 v26, v0

    .line 392
    .line 393
    check-cast v26, Lay0/k;

    .line 394
    .line 395
    const/high16 v29, 0x30000

    .line 396
    .line 397
    const/16 v30, 0x7ff0

    .line 398
    .line 399
    const-wide/16 v16, 0x0

    .line 400
    .line 401
    const-wide/16 v18, 0x0

    .line 402
    .line 403
    const/16 v20, 0x0

    .line 404
    .line 405
    const-wide/16 v21, 0x0

    .line 406
    .line 407
    const/16 v23, 0x0

    .line 408
    .line 409
    const/16 v24, 0x0

    .line 410
    .line 411
    const/16 v25, 0x0

    .line 412
    .line 413
    const/16 v28, 0x0

    .line 414
    .line 415
    move-object/from16 v27, v5

    .line 416
    .line 417
    invoke-static/range {v11 .. v30}, Li91/z3;->c(Lg4/g;Lx2/s;Lg4/p0;JJJLr4/k;JIZILay0/k;Ll2/o;III)V

    .line 418
    .line 419
    .line 420
    goto :goto_3

    .line 421
    :cond_9
    move-object/from16 v27, v5

    .line 422
    .line 423
    invoke-virtual/range {v27 .. v27}, Ll2/t;->R()V

    .line 424
    .line 425
    .line 426
    :goto_3
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 427
    .line 428
    return-object v0

    .line 429
    :pswitch_3
    iget-object v1, v0, Leh/l;->e:Ljava/lang/Object;

    .line 430
    .line 431
    check-cast v1, Lay0/k;

    .line 432
    .line 433
    iget-object v2, v0, Leh/l;->f:Ljava/lang/Object;

    .line 434
    .line 435
    check-cast v2, Ljava/util/List;

    .line 436
    .line 437
    iget-object v0, v0, Leh/l;->g:Ljava/lang/Object;

    .line 438
    .line 439
    check-cast v0, Lay0/k;

    .line 440
    .line 441
    move-object/from16 v3, p1

    .line 442
    .line 443
    check-cast v3, Lp1/p;

    .line 444
    .line 445
    move-object/from16 v4, p2

    .line 446
    .line 447
    check-cast v4, Ljava/lang/Integer;

    .line 448
    .line 449
    invoke-virtual {v4}, Ljava/lang/Integer;->intValue()I

    .line 450
    .line 451
    .line 452
    move-result v4

    .line 453
    move-object/from16 v5, p3

    .line 454
    .line 455
    check-cast v5, Ll2/o;

    .line 456
    .line 457
    move-object/from16 v6, p4

    .line 458
    .line 459
    check-cast v6, Ljava/lang/Integer;

    .line 460
    .line 461
    invoke-virtual {v6}, Ljava/lang/Integer;->intValue()I

    .line 462
    .line 463
    .line 464
    move-result v6

    .line 465
    const-string v7, "$this$HorizontalPager"

    .line 466
    .line 467
    invoke-static {v3, v7}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 468
    .line 469
    .line 470
    sget-object v8, Landroidx/compose/foundation/layout/d;->c:Landroidx/compose/foundation/layout/FillElement;

    .line 471
    .line 472
    check-cast v5, Ll2/t;

    .line 473
    .line 474
    invoke-virtual {v5, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 475
    .line 476
    .line 477
    move-result v3

    .line 478
    and-int/lit8 v7, v6, 0x70

    .line 479
    .line 480
    xor-int/lit8 v7, v7, 0x30

    .line 481
    .line 482
    const/4 v14, 0x0

    .line 483
    const/4 v15, 0x1

    .line 484
    const/16 v9, 0x20

    .line 485
    .line 486
    if-le v7, v9, :cond_a

    .line 487
    .line 488
    invoke-virtual {v5, v4}, Ll2/t;->e(I)Z

    .line 489
    .line 490
    .line 491
    move-result v10

    .line 492
    if-nez v10, :cond_b

    .line 493
    .line 494
    :cond_a
    and-int/lit8 v10, v6, 0x30

    .line 495
    .line 496
    if-ne v10, v9, :cond_c

    .line 497
    .line 498
    :cond_b
    move v10, v15

    .line 499
    goto :goto_4

    .line 500
    :cond_c
    move v10, v14

    .line 501
    :goto_4
    or-int/2addr v3, v10

    .line 502
    invoke-virtual {v5}, Ll2/t;->L()Ljava/lang/Object;

    .line 503
    .line 504
    .line 505
    move-result-object v10

    .line 506
    sget-object v11, Ll2/n;->a:Ll2/x0;

    .line 507
    .line 508
    if-nez v3, :cond_d

    .line 509
    .line 510
    if-ne v10, v11, :cond_e

    .line 511
    .line 512
    :cond_d
    new-instance v10, Lcz/k;

    .line 513
    .line 514
    const/4 v3, 0x6

    .line 515
    invoke-direct {v10, v4, v3, v1}, Lcz/k;-><init>(IILay0/k;)V

    .line 516
    .line 517
    .line 518
    invoke-virtual {v5, v10}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 519
    .line 520
    .line 521
    :cond_e
    move-object v12, v10

    .line 522
    check-cast v12, Lay0/a;

    .line 523
    .line 524
    const/16 v13, 0xf

    .line 525
    .line 526
    move v1, v9

    .line 527
    const/4 v9, 0x0

    .line 528
    const/4 v10, 0x0

    .line 529
    move-object v3, v11

    .line 530
    const/4 v11, 0x0

    .line 531
    invoke-static/range {v8 .. v13}, Landroidx/compose/foundation/a;->f(Lx2/s;ZLjava/lang/String;Ld4/i;Lay0/a;I)Lx2/s;

    .line 532
    .line 533
    .line 534
    move-result-object v8

    .line 535
    sget-object v9, Lx2/c;->q:Lx2/h;

    .line 536
    .line 537
    sget-object v10, Lk1/j;->e:Lk1/f;

    .line 538
    .line 539
    const/16 v11, 0x36

    .line 540
    .line 541
    invoke-static {v10, v9, v5, v11}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 542
    .line 543
    .line 544
    move-result-object v9

    .line 545
    iget-wide v10, v5, Ll2/t;->T:J

    .line 546
    .line 547
    invoke-static {v10, v11}, Ljava/lang/Long;->hashCode(J)I

    .line 548
    .line 549
    .line 550
    move-result v10

    .line 551
    invoke-virtual {v5}, Ll2/t;->m()Ll2/p1;

    .line 552
    .line 553
    .line 554
    move-result-object v11

    .line 555
    invoke-static {v5, v8}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 556
    .line 557
    .line 558
    move-result-object v8

    .line 559
    sget-object v12, Lv3/k;->m1:Lv3/j;

    .line 560
    .line 561
    invoke-virtual {v12}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 562
    .line 563
    .line 564
    sget-object v12, Lv3/j;->b:Lv3/i;

    .line 565
    .line 566
    invoke-virtual {v5}, Ll2/t;->c0()V

    .line 567
    .line 568
    .line 569
    iget-boolean v13, v5, Ll2/t;->S:Z

    .line 570
    .line 571
    if-eqz v13, :cond_f

    .line 572
    .line 573
    invoke-virtual {v5, v12}, Ll2/t;->l(Lay0/a;)V

    .line 574
    .line 575
    .line 576
    goto :goto_5

    .line 577
    :cond_f
    invoke-virtual {v5}, Ll2/t;->m0()V

    .line 578
    .line 579
    .line 580
    :goto_5
    sget-object v12, Lv3/j;->g:Lv3/h;

    .line 581
    .line 582
    invoke-static {v12, v9, v5}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 583
    .line 584
    .line 585
    sget-object v9, Lv3/j;->f:Lv3/h;

    .line 586
    .line 587
    invoke-static {v9, v11, v5}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 588
    .line 589
    .line 590
    sget-object v9, Lv3/j;->j:Lv3/h;

    .line 591
    .line 592
    iget-boolean v11, v5, Ll2/t;->S:Z

    .line 593
    .line 594
    if-nez v11, :cond_10

    .line 595
    .line 596
    invoke-virtual {v5}, Ll2/t;->L()Ljava/lang/Object;

    .line 597
    .line 598
    .line 599
    move-result-object v11

    .line 600
    invoke-static {v10}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 601
    .line 602
    .line 603
    move-result-object v12

    .line 604
    invoke-static {v11, v12}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 605
    .line 606
    .line 607
    move-result v11

    .line 608
    if-nez v11, :cond_11

    .line 609
    .line 610
    :cond_10
    invoke-static {v10, v5, v10, v9}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 611
    .line 612
    .line 613
    :cond_11
    sget-object v9, Lv3/j;->d:Lv3/h;

    .line 614
    .line 615
    invoke-static {v9, v8, v5}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 616
    .line 617
    .line 618
    const/high16 v8, 0x3f800000    # 1.0f

    .line 619
    .line 620
    sget-object v9, Lx2/p;->b:Lx2/p;

    .line 621
    .line 622
    invoke-static {v9, v8}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 623
    .line 624
    .line 625
    move-result-object v10

    .line 626
    invoke-interface {v2, v4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 627
    .line 628
    .line 629
    move-result-object v2

    .line 630
    check-cast v2, Ljava/net/URL;

    .line 631
    .line 632
    invoke-static {v2}, Ljp/sf;->h(Ljava/net/URL;)Landroid/net/Uri;

    .line 633
    .line 634
    .line 635
    move-result-object v9

    .line 636
    invoke-virtual {v5, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 637
    .line 638
    .line 639
    move-result v2

    .line 640
    if-le v7, v1, :cond_12

    .line 641
    .line 642
    invoke-virtual {v5, v4}, Ll2/t;->e(I)Z

    .line 643
    .line 644
    .line 645
    move-result v7

    .line 646
    if-nez v7, :cond_13

    .line 647
    .line 648
    :cond_12
    and-int/lit8 v6, v6, 0x30

    .line 649
    .line 650
    if-ne v6, v1, :cond_14

    .line 651
    .line 652
    :cond_13
    move v14, v15

    .line 653
    :cond_14
    or-int v1, v2, v14

    .line 654
    .line 655
    invoke-virtual {v5}, Ll2/t;->L()Ljava/lang/Object;

    .line 656
    .line 657
    .line 658
    move-result-object v2

    .line 659
    if-nez v1, :cond_15

    .line 660
    .line 661
    if-ne v2, v3, :cond_16

    .line 662
    .line 663
    :cond_15
    new-instance v2, Lcz/k;

    .line 664
    .line 665
    const/4 v1, 0x7

    .line 666
    invoke-direct {v2, v4, v1, v0}, Lcz/k;-><init>(IILay0/k;)V

    .line 667
    .line 668
    .line 669
    invoke-virtual {v5, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 670
    .line 671
    .line 672
    :cond_16
    move-object v12, v2

    .line 673
    check-cast v12, Lay0/a;

    .line 674
    .line 675
    const/16 v26, 0x0

    .line 676
    .line 677
    const v27, 0x1fdf4

    .line 678
    .line 679
    .line 680
    const/4 v11, 0x0

    .line 681
    const/4 v13, 0x0

    .line 682
    const/4 v14, 0x0

    .line 683
    move v0, v15

    .line 684
    const/4 v15, 0x0

    .line 685
    sget-object v16, Lt3/j;->b:Lt3/x0;

    .line 686
    .line 687
    const/16 v17, 0x0

    .line 688
    .line 689
    const/16 v18, 0x0

    .line 690
    .line 691
    const/16 v19, 0x0

    .line 692
    .line 693
    const/16 v20, 0x0

    .line 694
    .line 695
    const/16 v21, 0x0

    .line 696
    .line 697
    const/16 v22, 0x0

    .line 698
    .line 699
    const/16 v23, 0x0

    .line 700
    .line 701
    const v25, 0x30000030

    .line 702
    .line 703
    .line 704
    move-object/from16 v24, v5

    .line 705
    .line 706
    invoke-static/range {v9 .. v27}, Lxf0/i0;->c(Landroid/net/Uri;Lx2/s;Lay0/a;Lay0/a;Lay0/a;Ld01/h0;Lx2/e;Lt3/k;Ljava/util/List;Li3/c;Li3/c;Li3/c;ZZLe3/m;Ll2/o;III)V

    .line 707
    .line 708
    .line 709
    invoke-virtual {v5, v0}, Ll2/t;->q(Z)V

    .line 710
    .line 711
    .line 712
    goto/16 :goto_0

    .line 713
    .line 714
    :pswitch_4
    iget-object v1, v0, Leh/l;->f:Ljava/lang/Object;

    .line 715
    .line 716
    check-cast v1, Lmh/r;

    .line 717
    .line 718
    iget-object v2, v0, Leh/l;->e:Ljava/lang/Object;

    .line 719
    .line 720
    check-cast v2, Ll2/b1;

    .line 721
    .line 722
    iget-object v0, v0, Leh/l;->g:Ljava/lang/Object;

    .line 723
    .line 724
    check-cast v0, Lay0/k;

    .line 725
    .line 726
    move-object/from16 v3, p1

    .line 727
    .line 728
    check-cast v3, Lb1/n;

    .line 729
    .line 730
    move-object/from16 v4, p2

    .line 731
    .line 732
    check-cast v4, Lz9/k;

    .line 733
    .line 734
    move-object/from16 v5, p3

    .line 735
    .line 736
    check-cast v5, Ll2/o;

    .line 737
    .line 738
    move-object/from16 v6, p4

    .line 739
    .line 740
    check-cast v6, Ljava/lang/Integer;

    .line 741
    .line 742
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 743
    .line 744
    .line 745
    const-string v6, "$this$composable"

    .line 746
    .line 747
    invoke-static {v3, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 748
    .line 749
    .line 750
    const-string v3, "it"

    .line 751
    .line 752
    invoke-static {v4, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 753
    .line 754
    .line 755
    iget-object v1, v1, Lmh/r;->a:Lmh/j;

    .line 756
    .line 757
    instance-of v3, v1, Lmh/g;

    .line 758
    .line 759
    if-eqz v3, :cond_17

    .line 760
    .line 761
    check-cast v1, Lmh/g;

    .line 762
    .line 763
    goto :goto_6

    .line 764
    :cond_17
    const/4 v1, 0x0

    .line 765
    :goto_6
    const/4 v3, 0x0

    .line 766
    if-eqz v1, :cond_18

    .line 767
    .line 768
    iget-boolean v1, v1, Lmh/g;->b:Z

    .line 769
    .line 770
    goto :goto_7

    .line 771
    :cond_18
    move v1, v3

    .line 772
    :goto_7
    check-cast v5, Ll2/t;

    .line 773
    .line 774
    invoke-virtual {v5, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 775
    .line 776
    .line 777
    move-result v4

    .line 778
    invoke-virtual {v5, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 779
    .line 780
    .line 781
    move-result v6

    .line 782
    or-int/2addr v4, v6

    .line 783
    invoke-virtual {v5}, Ll2/t;->L()Ljava/lang/Object;

    .line 784
    .line 785
    .line 786
    move-result-object v6

    .line 787
    sget-object v7, Ll2/n;->a:Ll2/x0;

    .line 788
    .line 789
    if-nez v4, :cond_19

    .line 790
    .line 791
    if-ne v6, v7, :cond_1a

    .line 792
    .line 793
    :cond_19
    new-instance v6, Lmg/d;

    .line 794
    .line 795
    const/4 v4, 0x1

    .line 796
    invoke-direct {v6, v0, v2, v4}, Lmg/d;-><init>(Lay0/k;Ll2/b1;I)V

    .line 797
    .line 798
    .line 799
    invoke-virtual {v5, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 800
    .line 801
    .line 802
    :cond_1a
    check-cast v6, Lay0/k;

    .line 803
    .line 804
    invoke-virtual {v5, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 805
    .line 806
    .line 807
    move-result v2

    .line 808
    invoke-virtual {v5}, Ll2/t;->L()Ljava/lang/Object;

    .line 809
    .line 810
    .line 811
    move-result-object v4

    .line 812
    if-nez v2, :cond_1b

    .line 813
    .line 814
    if-ne v4, v7, :cond_1c

    .line 815
    .line 816
    :cond_1b
    new-instance v4, Llk/f;

    .line 817
    .line 818
    const/16 v2, 0xd

    .line 819
    .line 820
    invoke-direct {v4, v2, v0}, Llk/f;-><init>(ILay0/k;)V

    .line 821
    .line 822
    .line 823
    invoke-virtual {v5, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 824
    .line 825
    .line 826
    :cond_1c
    check-cast v4, Lay0/a;

    .line 827
    .line 828
    invoke-static {v1, v6, v4, v5, v3}, Lkp/f0;->b(ZLay0/k;Lay0/a;Ll2/o;I)V

    .line 829
    .line 830
    .line 831
    goto/16 :goto_0

    .line 832
    .line 833
    :pswitch_5
    iget-object v1, v0, Leh/l;->f:Ljava/lang/Object;

    .line 834
    .line 835
    check-cast v1, Ly1/i;

    .line 836
    .line 837
    iget-object v2, v0, Leh/l;->e:Ljava/lang/Object;

    .line 838
    .line 839
    check-cast v2, Ll2/b1;

    .line 840
    .line 841
    iget-object v0, v0, Leh/l;->g:Ljava/lang/Object;

    .line 842
    .line 843
    check-cast v0, Ll2/b1;

    .line 844
    .line 845
    move-object/from16 v3, p1

    .line 846
    .line 847
    check-cast v3, Lb1/n;

    .line 848
    .line 849
    move-object/from16 v4, p2

    .line 850
    .line 851
    check-cast v4, Lz9/k;

    .line 852
    .line 853
    move-object/from16 v5, p3

    .line 854
    .line 855
    check-cast v5, Ll2/o;

    .line 856
    .line 857
    move-object/from16 v6, p4

    .line 858
    .line 859
    check-cast v6, Ljava/lang/Integer;

    .line 860
    .line 861
    const-string v7, "$this$composable"

    .line 862
    .line 863
    const-string v8, "it"

    .line 864
    .line 865
    invoke-static {v6, v3, v7, v4, v8}, Lz9/c;->c(Ljava/lang/Integer;Lb1/n;Ljava/lang/String;Lz9/k;Ljava/lang/String;)V

    .line 866
    .line 867
    .line 868
    invoke-interface {v2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 869
    .line 870
    .line 871
    move-result-object v2

    .line 872
    invoke-static {v2}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 873
    .line 874
    .line 875
    check-cast v2, Lug/a;

    .line 876
    .line 877
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 878
    .line 879
    .line 880
    move-result-object v0

    .line 881
    check-cast v0, Lmg/c;

    .line 882
    .line 883
    iget-object v0, v0, Lmg/c;->m:Ljava/lang/String;

    .line 884
    .line 885
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 886
    .line 887
    .line 888
    const/4 v3, 0x0

    .line 889
    invoke-static {v1, v2, v0, v5, v3}, Lkp/z9;->a(Ly1/i;Lug/a;Ljava/lang/String;Ll2/o;I)V

    .line 890
    .line 891
    .line 892
    goto/16 :goto_0

    .line 893
    .line 894
    :pswitch_6
    iget-object v1, v0, Leh/l;->e:Ljava/lang/Object;

    .line 895
    .line 896
    check-cast v1, Ljava/lang/String;

    .line 897
    .line 898
    iget-object v2, v0, Leh/l;->f:Ljava/lang/Object;

    .line 899
    .line 900
    check-cast v2, Ljava/lang/String;

    .line 901
    .line 902
    iget-object v0, v0, Leh/l;->g:Ljava/lang/Object;

    .line 903
    .line 904
    check-cast v0, Lay0/a;

    .line 905
    .line 906
    move-object/from16 v3, p1

    .line 907
    .line 908
    check-cast v3, Lb1/n;

    .line 909
    .line 910
    move-object/from16 v4, p2

    .line 911
    .line 912
    check-cast v4, Lz9/k;

    .line 913
    .line 914
    move-object/from16 v5, p3

    .line 915
    .line 916
    check-cast v5, Ll2/o;

    .line 917
    .line 918
    move-object/from16 v6, p4

    .line 919
    .line 920
    check-cast v6, Ljava/lang/Integer;

    .line 921
    .line 922
    const-string v7, "$this$composable"

    .line 923
    .line 924
    const-string v8, "it"

    .line 925
    .line 926
    invoke-static {v6, v3, v7, v4, v8}, Lz9/c;->c(Ljava/lang/Integer;Lb1/n;Ljava/lang/String;Lz9/k;Ljava/lang/String;)V

    .line 927
    .line 928
    .line 929
    const/4 v3, 0x0

    .line 930
    invoke-static {v1, v2, v0, v5, v3}, Ljp/la;->a(Ljava/lang/String;Ljava/lang/String;Lay0/a;Ll2/o;I)V

    .line 931
    .line 932
    .line 933
    goto/16 :goto_0

    .line 934
    .line 935
    :pswitch_7
    iget-object v1, v0, Leh/l;->e:Ljava/lang/Object;

    .line 936
    .line 937
    check-cast v1, Ll2/b1;

    .line 938
    .line 939
    iget-object v2, v0, Leh/l;->f:Ljava/lang/Object;

    .line 940
    .line 941
    check-cast v2, Ll2/b1;

    .line 942
    .line 943
    iget-object v0, v0, Leh/l;->g:Ljava/lang/Object;

    .line 944
    .line 945
    check-cast v0, Ll2/b1;

    .line 946
    .line 947
    move-object/from16 v3, p1

    .line 948
    .line 949
    check-cast v3, Lz9/y;

    .line 950
    .line 951
    move-object/from16 v4, p2

    .line 952
    .line 953
    check-cast v4, Ljava/lang/String;

    .line 954
    .line 955
    move-object/from16 v5, p3

    .line 956
    .line 957
    check-cast v5, Lai/a;

    .line 958
    .line 959
    move-object/from16 v6, p4

    .line 960
    .line 961
    check-cast v6, Lzg/c1;

    .line 962
    .line 963
    const-string v7, "$this$navigator"

    .line 964
    .line 965
    invoke-static {v3, v7}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 966
    .line 967
    .line 968
    const-string v7, "id"

    .line 969
    .line 970
    invoke-static {v4, v7}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 971
    .line 972
    .line 973
    const-string v7, "loc"

    .line 974
    .line 975
    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 976
    .line 977
    .line 978
    invoke-interface {v1, v4}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 979
    .line 980
    .line 981
    invoke-interface {v2, v5}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 982
    .line 983
    .line 984
    invoke-interface {v0, v6}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 985
    .line 986
    .line 987
    const/4 v0, 0x0

    .line 988
    const/4 v1, 0x6

    .line 989
    const-string v2, "/detail"

    .line 990
    .line 991
    invoke-static {v3, v2, v0, v1}, Lz9/y;->f(Lz9/y;Ljava/lang/String;Lz9/b0;I)V

    .line 992
    .line 993
    .line 994
    goto/16 :goto_0

    .line 995
    .line 996
    :pswitch_8
    iget-object v1, v0, Leh/l;->e:Ljava/lang/Object;

    .line 997
    .line 998
    check-cast v1, Ll2/b1;

    .line 999
    .line 1000
    iget-object v2, v0, Leh/l;->f:Ljava/lang/Object;

    .line 1001
    .line 1002
    check-cast v2, Lyj/b;

    .line 1003
    .line 1004
    iget-object v0, v0, Leh/l;->g:Ljava/lang/Object;

    .line 1005
    .line 1006
    check-cast v0, Lh2/d6;

    .line 1007
    .line 1008
    move-object/from16 v3, p1

    .line 1009
    .line 1010
    check-cast v3, Lb1/n;

    .line 1011
    .line 1012
    move-object/from16 v4, p2

    .line 1013
    .line 1014
    check-cast v4, Lz9/k;

    .line 1015
    .line 1016
    move-object/from16 v5, p3

    .line 1017
    .line 1018
    check-cast v5, Ll2/o;

    .line 1019
    .line 1020
    move-object/from16 v6, p4

    .line 1021
    .line 1022
    check-cast v6, Ljava/lang/Integer;

    .line 1023
    .line 1024
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1025
    .line 1026
    .line 1027
    const-string v6, "$this$composable"

    .line 1028
    .line 1029
    invoke-static {v3, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1030
    .line 1031
    .line 1032
    const-string v3, "it"

    .line 1033
    .line 1034
    invoke-static {v4, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1035
    .line 1036
    .line 1037
    invoke-interface {v1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 1038
    .line 1039
    .line 1040
    move-result-object v1

    .line 1041
    check-cast v1, Ljava/lang/String;

    .line 1042
    .line 1043
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 1044
    .line 1045
    const/4 v4, 0x0

    .line 1046
    check-cast v5, Ll2/t;

    .line 1047
    .line 1048
    if-nez v1, :cond_1d

    .line 1049
    .line 1050
    const v0, -0x7abc70de

    .line 1051
    .line 1052
    .line 1053
    invoke-virtual {v5, v0}, Ll2/t;->Y(I)V

    .line 1054
    .line 1055
    .line 1056
    invoke-virtual {v5, v4}, Ll2/t;->q(Z)V

    .line 1057
    .line 1058
    .line 1059
    const/4 v0, 0x0

    .line 1060
    goto :goto_8

    .line 1061
    :cond_1d
    const v6, -0x7abc70dd    # -9.195146E-36f

    .line 1062
    .line 1063
    .line 1064
    invoke-virtual {v5, v6}, Ll2/t;->Y(I)V

    .line 1065
    .line 1066
    .line 1067
    invoke-static {v1, v0, v5, v4}, Llp/yb;->a(Ljava/lang/String;Lh2/d6;Ll2/o;I)V

    .line 1068
    .line 1069
    .line 1070
    invoke-virtual {v5, v4}, Ll2/t;->q(Z)V

    .line 1071
    .line 1072
    .line 1073
    move-object v0, v3

    .line 1074
    :goto_8
    if-nez v0, :cond_1e

    .line 1075
    .line 1076
    invoke-virtual {v2}, Lyj/b;->invoke()Ljava/lang/Object;

    .line 1077
    .line 1078
    .line 1079
    :cond_1e
    return-object v3

    .line 1080
    nop

    .line 1081
    :pswitch_data_0
    .packed-switch 0x0
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
