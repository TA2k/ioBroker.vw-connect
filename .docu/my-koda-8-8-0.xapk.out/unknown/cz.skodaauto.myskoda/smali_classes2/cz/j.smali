.class public final synthetic Lcz/j;
.super Lkotlin/jvm/internal/k;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V
    .locals 1

    .line 1
    iput p7, p0, Lcz/j;->d:I

    .line 2
    .line 3
    move-object v0, p4

    .line 4
    move-object p4, p2

    .line 5
    move p2, p6

    .line 6
    move-object p6, p5

    .line 7
    move-object p5, v0

    .line 8
    invoke-direct/range {p0 .. p6}, Lkotlin/jvm/internal/j;-><init>(IILjava/lang/Class;Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 28

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lcz/j;->d:I

    .line 4
    .line 5
    const/16 v2, 0x1f

    .line 6
    .line 7
    const/4 v3, 0x4

    .line 8
    const/4 v4, 0x2

    .line 9
    const/4 v5, 0x1

    .line 10
    const/4 v6, 0x0

    .line 11
    const/4 v7, 0x3

    .line 12
    const/4 v8, 0x0

    .line 13
    const-string v9, "p0"

    .line 14
    .line 15
    sget-object v10, Llx0/b0;->a:Llx0/b0;

    .line 16
    .line 17
    packed-switch v1, :pswitch_data_0

    .line 18
    .line 19
    .line 20
    if-nez p1, :cond_0

    .line 21
    .line 22
    invoke-static {v8, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 26
    .line 27
    check-cast v0, Lef/b;

    .line 28
    .line 29
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 30
    .line 31
    .line 32
    new-instance v0, La8/r0;

    .line 33
    .line 34
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 35
    .line 36
    .line 37
    throw v0

    .line 38
    :cond_0
    new-instance v0, Ljava/lang/ClassCastException;

    .line 39
    .line 40
    invoke-direct {v0}, Ljava/lang/ClassCastException;-><init>()V

    .line 41
    .line 42
    .line 43
    throw v0

    .line 44
    :pswitch_0
    move-object/from16 v1, p1

    .line 45
    .line 46
    check-cast v1, Ljava/lang/Boolean;

    .line 47
    .line 48
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 49
    .line 50
    .line 51
    move-result v1

    .line 52
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 53
    .line 54
    check-cast v0, Le1/h;

    .line 55
    .line 56
    iget-object v3, v0, Le1/h;->G:Landroidx/collection/e0;

    .line 57
    .line 58
    if-eqz v1, :cond_1

    .line 59
    .line 60
    invoke-virtual {v0}, Le1/h;->f1()V

    .line 61
    .line 62
    .line 63
    goto/16 :goto_4

    .line 64
    .line 65
    :cond_1
    iget-object v1, v0, Le1/h;->t:Li1/l;

    .line 66
    .line 67
    if-eqz v1, :cond_5

    .line 68
    .line 69
    iget-object v1, v3, Landroidx/collection/e0;->c:[Ljava/lang/Object;

    .line 70
    .line 71
    iget-object v5, v3, Landroidx/collection/e0;->a:[J

    .line 72
    .line 73
    array-length v9, v5

    .line 74
    sub-int/2addr v9, v4

    .line 75
    if-ltz v9, :cond_5

    .line 76
    .line 77
    move v4, v6

    .line 78
    :goto_0
    aget-wide v11, v5, v4

    .line 79
    .line 80
    not-long v13, v11

    .line 81
    const/4 v15, 0x7

    .line 82
    shl-long/2addr v13, v15

    .line 83
    and-long/2addr v13, v11

    .line 84
    const-wide v15, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 85
    .line 86
    .line 87
    .line 88
    .line 89
    and-long/2addr v13, v15

    .line 90
    cmp-long v13, v13, v15

    .line 91
    .line 92
    if-eqz v13, :cond_4

    .line 93
    .line 94
    sub-int v13, v4, v9

    .line 95
    .line 96
    not-int v13, v13

    .line 97
    ushr-int/2addr v13, v2

    .line 98
    const/16 v14, 0x8

    .line 99
    .line 100
    rsub-int/lit8 v13, v13, 0x8

    .line 101
    .line 102
    move v15, v6

    .line 103
    :goto_1
    if-ge v15, v13, :cond_3

    .line 104
    .line 105
    const-wide/16 v16, 0xff

    .line 106
    .line 107
    and-long v16, v11, v16

    .line 108
    .line 109
    const-wide/16 v18, 0x80

    .line 110
    .line 111
    cmp-long v16, v16, v18

    .line 112
    .line 113
    if-gez v16, :cond_2

    .line 114
    .line 115
    shl-int/lit8 v16, v4, 0x3

    .line 116
    .line 117
    add-int v16, v16, v15

    .line 118
    .line 119
    aget-object v16, v1, v16

    .line 120
    .line 121
    move-object/from16 v2, v16

    .line 122
    .line 123
    check-cast v2, Li1/n;

    .line 124
    .line 125
    move/from16 p0, v14

    .line 126
    .line 127
    invoke-virtual {v0}, Lx2/r;->L0()Lvy0/b0;

    .line 128
    .line 129
    .line 130
    move-result-object v14

    .line 131
    move-object/from16 v16, v1

    .line 132
    .line 133
    new-instance v1, Le1/f;

    .line 134
    .line 135
    invoke-direct {v1, v0, v2, v8, v6}, Le1/f;-><init>(Le1/h;Li1/n;Lkotlin/coroutines/Continuation;I)V

    .line 136
    .line 137
    .line 138
    invoke-static {v14, v8, v8, v1, v7}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 139
    .line 140
    .line 141
    goto :goto_2

    .line 142
    :cond_2
    move-object/from16 v16, v1

    .line 143
    .line 144
    move/from16 p0, v14

    .line 145
    .line 146
    :goto_2
    shr-long v11, v11, p0

    .line 147
    .line 148
    add-int/lit8 v15, v15, 0x1

    .line 149
    .line 150
    move/from16 v14, p0

    .line 151
    .line 152
    move-object/from16 v1, v16

    .line 153
    .line 154
    const/16 v2, 0x1f

    .line 155
    .line 156
    goto :goto_1

    .line 157
    :cond_3
    move-object/from16 v16, v1

    .line 158
    .line 159
    move v1, v14

    .line 160
    if-ne v13, v1, :cond_5

    .line 161
    .line 162
    goto :goto_3

    .line 163
    :cond_4
    move-object/from16 v16, v1

    .line 164
    .line 165
    :goto_3
    if-eq v4, v9, :cond_5

    .line 166
    .line 167
    add-int/lit8 v4, v4, 0x1

    .line 168
    .line 169
    move-object/from16 v1, v16

    .line 170
    .line 171
    const/16 v2, 0x1f

    .line 172
    .line 173
    goto :goto_0

    .line 174
    :cond_5
    invoke-virtual {v3}, Landroidx/collection/e0;->a()V

    .line 175
    .line 176
    .line 177
    invoke-virtual {v0}, Le1/h;->g1()V

    .line 178
    .line 179
    .line 180
    :goto_4
    return-object v10

    .line 181
    :pswitch_1
    move-object/from16 v1, p1

    .line 182
    .line 183
    check-cast v1, Lfw0/y0;

    .line 184
    .line 185
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 186
    .line 187
    check-cast v0, Ldw0/d;

    .line 188
    .line 189
    iget-object v0, v0, Ldw0/d;->h:Ldw0/a;

    .line 190
    .line 191
    iget-object v2, v0, Ldw0/a;->b:Ld01/h0;

    .line 192
    .line 193
    if-nez v2, :cond_6

    .line 194
    .line 195
    sget-object v2, Ldw0/d;->m:Llx0/q;

    .line 196
    .line 197
    invoke-virtual {v2}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 198
    .line 199
    .line 200
    move-result-object v2

    .line 201
    check-cast v2, Ld01/h0;

    .line 202
    .line 203
    :cond_6
    invoke-virtual {v2}, Ld01/h0;->a()Ld01/g0;

    .line 204
    .line 205
    .line 206
    move-result-object v2

    .line 207
    new-instance v3, Ld01/t;

    .line 208
    .line 209
    invoke-direct {v3}, Ld01/t;-><init>()V

    .line 210
    .line 211
    .line 212
    iput-object v3, v2, Ld01/g0;->a:Ld01/t;

    .line 213
    .line 214
    iget-object v0, v0, Ldw0/a;->a:Ldj/a;

    .line 215
    .line 216
    invoke-virtual {v0, v2}, Ldj/a;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 217
    .line 218
    .line 219
    if-eqz v1, :cond_b

    .line 220
    .line 221
    iget-object v0, v1, Lfw0/y0;->b:Ljava/lang/Long;

    .line 222
    .line 223
    const-wide v3, 0x7fffffffffffffffL

    .line 224
    .line 225
    .line 226
    .line 227
    .line 228
    const-wide/16 v5, 0x0

    .line 229
    .line 230
    if-eqz v0, :cond_8

    .line 231
    .line 232
    invoke-virtual {v0}, Ljava/lang/Number;->longValue()J

    .line 233
    .line 234
    .line 235
    move-result-wide v7

    .line 236
    sget-object v0, Lfw0/a1;->a:Lt21/b;

    .line 237
    .line 238
    cmp-long v0, v7, v3

    .line 239
    .line 240
    if-nez v0, :cond_7

    .line 241
    .line 242
    move-wide v7, v5

    .line 243
    :cond_7
    sget-object v0, Ljava/util/concurrent/TimeUnit;->MILLISECONDS:Ljava/util/concurrent/TimeUnit;

    .line 244
    .line 245
    invoke-virtual {v2, v7, v8, v0}, Ld01/g0;->b(JLjava/util/concurrent/TimeUnit;)V

    .line 246
    .line 247
    .line 248
    :cond_8
    iget-object v0, v1, Lfw0/y0;->c:Ljava/lang/Long;

    .line 249
    .line 250
    if-eqz v0, :cond_b

    .line 251
    .line 252
    invoke-virtual {v0}, Ljava/lang/Number;->longValue()J

    .line 253
    .line 254
    .line 255
    move-result-wide v0

    .line 256
    sget-object v7, Lfw0/a1;->a:Lt21/b;

    .line 257
    .line 258
    cmp-long v3, v0, v3

    .line 259
    .line 260
    if-nez v3, :cond_9

    .line 261
    .line 262
    move-wide v7, v5

    .line 263
    goto :goto_5

    .line 264
    :cond_9
    move-wide v7, v0

    .line 265
    :goto_5
    sget-object v4, Ljava/util/concurrent/TimeUnit;->MILLISECONDS:Ljava/util/concurrent/TimeUnit;

    .line 266
    .line 267
    invoke-virtual {v2, v7, v8, v4}, Ld01/g0;->d(JLjava/util/concurrent/TimeUnit;)V

    .line 268
    .line 269
    .line 270
    if-nez v3, :cond_a

    .line 271
    .line 272
    goto :goto_6

    .line 273
    :cond_a
    move-wide v5, v0

    .line 274
    :goto_6
    invoke-virtual {v2, v5, v6, v4}, Ld01/g0;->f(JLjava/util/concurrent/TimeUnit;)V

    .line 275
    .line 276
    .line 277
    :cond_b
    new-instance v0, Ld01/h0;

    .line 278
    .line 279
    invoke-direct {v0, v2}, Ld01/h0;-><init>(Ld01/g0;)V

    .line 280
    .line 281
    .line 282
    return-object v0

    .line 283
    :pswitch_2
    move-object/from16 v1, p1

    .line 284
    .line 285
    check-cast v1, Lbl0/i0;

    .line 286
    .line 287
    invoke-static {v1, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 288
    .line 289
    .line 290
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 291
    .line 292
    check-cast v0, Lcl0/s;

    .line 293
    .line 294
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 295
    .line 296
    .line 297
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 298
    .line 299
    .line 300
    move-result-object v2

    .line 301
    check-cast v2, Lcl0/r;

    .line 302
    .line 303
    invoke-static {v2, v8, v6, v5}, Lcl0/r;->a(Lcl0/r;Ljava/util/ArrayList;ZI)Lcl0/r;

    .line 304
    .line 305
    .line 306
    move-result-object v2

    .line 307
    invoke-virtual {v0, v2}, Lql0/j;->g(Lql0/h;)V

    .line 308
    .line 309
    .line 310
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 311
    .line 312
    .line 313
    move-result-object v2

    .line 314
    new-instance v3, Lc80/l;

    .line 315
    .line 316
    const/16 v4, 0x10

    .line 317
    .line 318
    invoke-direct {v3, v4, v0, v1, v8}, Lc80/l;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 319
    .line 320
    .line 321
    invoke-static {v2, v8, v8, v3, v7}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 322
    .line 323
    .line 324
    return-object v10

    .line 325
    :pswitch_3
    move-object/from16 v1, p1

    .line 326
    .line 327
    check-cast v1, Lbl0/f;

    .line 328
    .line 329
    invoke-static {v1, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 330
    .line 331
    .line 332
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 333
    .line 334
    check-cast v0, Lcl0/j;

    .line 335
    .line 336
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 337
    .line 338
    .line 339
    iget-object v2, v0, Lcl0/j;->l:Lbl0/h;

    .line 340
    .line 341
    if-eqz v2, :cond_f

    .line 342
    .line 343
    instance-of v3, v1, Lbl0/b;

    .line 344
    .line 345
    if-eqz v3, :cond_c

    .line 346
    .line 347
    iget-object v3, v2, Lbl0/h;->c:Ljava/util/List;

    .line 348
    .line 349
    invoke-static {v3, v1}, Lcl0/j;->j(Ljava/util/List;Lbl0/f;)Ljava/util/ArrayList;

    .line 350
    .line 351
    .line 352
    move-result-object v5

    .line 353
    const/4 v7, 0x0

    .line 354
    const/16 v8, 0x1b

    .line 355
    .line 356
    const/4 v3, 0x0

    .line 357
    const/4 v4, 0x0

    .line 358
    const/4 v6, 0x0

    .line 359
    invoke-static/range {v2 .. v8}, Lbl0/h;->a(Lbl0/h;Lbl0/e;ZLjava/util/ArrayList;Ljava/util/ArrayList;Ljava/util/ArrayList;I)Lbl0/h;

    .line 360
    .line 361
    .line 362
    move-result-object v1

    .line 363
    invoke-virtual {v0, v1}, Lcl0/j;->h(Lbl0/h;)V

    .line 364
    .line 365
    .line 366
    goto :goto_7

    .line 367
    :cond_c
    instance-of v3, v1, Lbl0/c;

    .line 368
    .line 369
    if-eqz v3, :cond_d

    .line 370
    .line 371
    iget-object v3, v2, Lbl0/h;->d:Ljava/util/List;

    .line 372
    .line 373
    invoke-static {v3, v1}, Lcl0/j;->j(Ljava/util/List;Lbl0/f;)Ljava/util/ArrayList;

    .line 374
    .line 375
    .line 376
    move-result-object v6

    .line 377
    const/4 v7, 0x0

    .line 378
    const/16 v8, 0x17

    .line 379
    .line 380
    const/4 v3, 0x0

    .line 381
    const/4 v4, 0x0

    .line 382
    const/4 v5, 0x0

    .line 383
    invoke-static/range {v2 .. v8}, Lbl0/h;->a(Lbl0/h;Lbl0/e;ZLjava/util/ArrayList;Ljava/util/ArrayList;Ljava/util/ArrayList;I)Lbl0/h;

    .line 384
    .line 385
    .line 386
    move-result-object v1

    .line 387
    invoke-virtual {v0, v1}, Lcl0/j;->h(Lbl0/h;)V

    .line 388
    .line 389
    .line 390
    goto :goto_7

    .line 391
    :cond_d
    instance-of v3, v1, Lbl0/d;

    .line 392
    .line 393
    if-eqz v3, :cond_e

    .line 394
    .line 395
    iget-object v3, v2, Lbl0/h;->e:Ljava/util/List;

    .line 396
    .line 397
    invoke-static {v3, v1}, Lcl0/j;->j(Ljava/util/List;Lbl0/f;)Ljava/util/ArrayList;

    .line 398
    .line 399
    .line 400
    move-result-object v7

    .line 401
    const/16 v8, 0xf

    .line 402
    .line 403
    const/4 v3, 0x0

    .line 404
    const/4 v4, 0x0

    .line 405
    const/4 v5, 0x0

    .line 406
    const/4 v6, 0x0

    .line 407
    invoke-static/range {v2 .. v8}, Lbl0/h;->a(Lbl0/h;Lbl0/e;ZLjava/util/ArrayList;Ljava/util/ArrayList;Ljava/util/ArrayList;I)Lbl0/h;

    .line 408
    .line 409
    .line 410
    move-result-object v1

    .line 411
    invoke-virtual {v0, v1}, Lcl0/j;->h(Lbl0/h;)V

    .line 412
    .line 413
    .line 414
    goto :goto_7

    .line 415
    :cond_e
    new-instance v0, La8/r0;

    .line 416
    .line 417
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 418
    .line 419
    .line 420
    throw v0

    .line 421
    :cond_f
    :goto_7
    return-object v10

    .line 422
    :pswitch_4
    move-object/from16 v1, p1

    .line 423
    .line 424
    check-cast v1, Lgy0/f;

    .line 425
    .line 426
    invoke-static {v1, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 427
    .line 428
    .line 429
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 430
    .line 431
    check-cast v0, Lcl0/j;

    .line 432
    .line 433
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 434
    .line 435
    .line 436
    iget-object v11, v0, Lcl0/j;->l:Lbl0/h;

    .line 437
    .line 438
    if-eqz v11, :cond_11

    .line 439
    .line 440
    new-instance v12, Lbl0/e;

    .line 441
    .line 442
    invoke-interface {v1}, Lgy0/g;->e()Ljava/lang/Comparable;

    .line 443
    .line 444
    .line 445
    move-result-object v2

    .line 446
    check-cast v2, Ljava/lang/Number;

    .line 447
    .line 448
    invoke-virtual {v2}, Ljava/lang/Number;->floatValue()F

    .line 449
    .line 450
    .line 451
    move-result v2

    .line 452
    sget-object v3, Lbl0/g;->j:Lsx0/b;

    .line 453
    .line 454
    invoke-static {v2}, Lcy0/a;->i(F)I

    .line 455
    .line 456
    .line 457
    move-result v2

    .line 458
    invoke-virtual {v3, v2}, Lsx0/b;->get(I)Ljava/lang/Object;

    .line 459
    .line 460
    .line 461
    move-result-object v2

    .line 462
    check-cast v2, Lbl0/g;

    .line 463
    .line 464
    invoke-interface {v1}, Lgy0/g;->g()Ljava/lang/Comparable;

    .line 465
    .line 466
    .line 467
    move-result-object v9

    .line 468
    check-cast v9, Ljava/lang/Number;

    .line 469
    .line 470
    invoke-virtual {v9}, Ljava/lang/Number;->floatValue()F

    .line 471
    .line 472
    .line 473
    move-result v9

    .line 474
    invoke-static {v9}, Lcy0/a;->i(F)I

    .line 475
    .line 476
    .line 477
    move-result v9

    .line 478
    invoke-virtual {v3, v9}, Lsx0/b;->get(I)Ljava/lang/Object;

    .line 479
    .line 480
    .line 481
    move-result-object v3

    .line 482
    check-cast v3, Lbl0/g;

    .line 483
    .line 484
    invoke-direct {v12, v2, v3}, Lbl0/e;-><init>(Lbl0/g;Lbl0/g;)V

    .line 485
    .line 486
    .line 487
    const/16 v16, 0x0

    .line 488
    .line 489
    const/16 v17, 0x1e

    .line 490
    .line 491
    const/4 v13, 0x0

    .line 492
    const/4 v14, 0x0

    .line 493
    const/4 v15, 0x0

    .line 494
    invoke-static/range {v11 .. v17}, Lbl0/h;->a(Lbl0/h;Lbl0/e;ZLjava/util/ArrayList;Ljava/util/ArrayList;Ljava/util/ArrayList;I)Lbl0/h;

    .line 495
    .line 496
    .line 497
    move-result-object v2

    .line 498
    iput-object v2, v0, Lcl0/j;->l:Lbl0/h;

    .line 499
    .line 500
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 501
    .line 502
    .line 503
    move-result-object v2

    .line 504
    check-cast v2, Lcl0/i;

    .line 505
    .line 506
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 507
    .line 508
    .line 509
    move-result-object v3

    .line 510
    check-cast v3, Lcl0/i;

    .line 511
    .line 512
    iget-object v3, v3, Lcl0/i;->a:Lcl0/f;

    .line 513
    .line 514
    if-eqz v3, :cond_10

    .line 515
    .line 516
    new-instance v8, Lcl0/b;

    .line 517
    .line 518
    sget-object v9, Lbl0/e;->c:Lbl0/e;

    .line 519
    .line 520
    invoke-virtual {v12, v9}, Lbl0/e;->equals(Ljava/lang/Object;)Z

    .line 521
    .line 522
    .line 523
    move-result v9

    .line 524
    invoke-direct {v8, v9}, Lcl0/b;-><init>(Z)V

    .line 525
    .line 526
    .line 527
    new-instance v9, Lcl0/a;

    .line 528
    .line 529
    sget-object v11, Lbl0/e;->d:Lbl0/e;

    .line 530
    .line 531
    invoke-virtual {v12, v11}, Lbl0/e;->equals(Ljava/lang/Object;)Z

    .line 532
    .line 533
    .line 534
    move-result v11

    .line 535
    invoke-direct {v9, v11}, Lcl0/a;-><init>(Z)V

    .line 536
    .line 537
    .line 538
    new-instance v11, Lcl0/c;

    .line 539
    .line 540
    sget-object v13, Lbl0/e;->e:Lbl0/e;

    .line 541
    .line 542
    invoke-virtual {v12, v13}, Lbl0/e;->equals(Ljava/lang/Object;)Z

    .line 543
    .line 544
    .line 545
    move-result v12

    .line 546
    invoke-direct {v11, v12}, Lcl0/c;-><init>(Z)V

    .line 547
    .line 548
    .line 549
    new-array v7, v7, [Lcl0/d;

    .line 550
    .line 551
    aput-object v8, v7, v6

    .line 552
    .line 553
    aput-object v9, v7, v5

    .line 554
    .line 555
    aput-object v11, v7, v4

    .line 556
    .line 557
    invoke-static {v7}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 558
    .line 559
    .line 560
    move-result-object v4

    .line 561
    new-instance v5, Lcl0/e;

    .line 562
    .line 563
    invoke-direct {v5, v1}, Lcl0/e;-><init>(Lgy0/f;)V

    .line 564
    .line 565
    .line 566
    iget-boolean v1, v3, Lcl0/f;->c:Z

    .line 567
    .line 568
    new-instance v8, Lcl0/f;

    .line 569
    .line 570
    invoke-direct {v8, v4, v5, v1}, Lcl0/f;-><init>(Ljava/util/List;Lcl0/e;Z)V

    .line 571
    .line 572
    .line 573
    :cond_10
    iget-object v1, v2, Lcl0/i;->b:Lcl0/h;

    .line 574
    .line 575
    iget-object v3, v2, Lcl0/i;->c:Lcl0/h;

    .line 576
    .line 577
    iget-object v2, v2, Lcl0/i;->d:Lcl0/h;

    .line 578
    .line 579
    new-instance v4, Lcl0/i;

    .line 580
    .line 581
    invoke-direct {v4, v8, v1, v3, v2}, Lcl0/i;-><init>(Lcl0/f;Lcl0/h;Lcl0/h;Lcl0/h;)V

    .line 582
    .line 583
    .line 584
    invoke-virtual {v0, v4}, Lql0/j;->g(Lql0/h;)V

    .line 585
    .line 586
    .line 587
    :cond_11
    return-object v10

    .line 588
    :pswitch_5
    move-object/from16 v1, p1

    .line 589
    .line 590
    check-cast v1, Lcl0/d;

    .line 591
    .line 592
    invoke-static {v1, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 593
    .line 594
    .line 595
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 596
    .line 597
    check-cast v0, Lcl0/j;

    .line 598
    .line 599
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 600
    .line 601
    .line 602
    iget-object v2, v0, Lcl0/j;->l:Lbl0/h;

    .line 603
    .line 604
    if-eqz v2, :cond_15

    .line 605
    .line 606
    instance-of v3, v1, Lcl0/b;

    .line 607
    .line 608
    if-eqz v3, :cond_12

    .line 609
    .line 610
    sget-object v1, Lbl0/e;->c:Lbl0/e;

    .line 611
    .line 612
    :goto_8
    move-object v3, v1

    .line 613
    goto :goto_9

    .line 614
    :cond_12
    instance-of v3, v1, Lcl0/a;

    .line 615
    .line 616
    if-eqz v3, :cond_13

    .line 617
    .line 618
    sget-object v1, Lbl0/e;->d:Lbl0/e;

    .line 619
    .line 620
    goto :goto_8

    .line 621
    :cond_13
    instance-of v1, v1, Lcl0/c;

    .line 622
    .line 623
    if-eqz v1, :cond_14

    .line 624
    .line 625
    sget-object v1, Lbl0/e;->e:Lbl0/e;

    .line 626
    .line 627
    goto :goto_8

    .line 628
    :goto_9
    const/4 v7, 0x0

    .line 629
    const/16 v8, 0x1e

    .line 630
    .line 631
    const/4 v4, 0x0

    .line 632
    const/4 v5, 0x0

    .line 633
    const/4 v6, 0x0

    .line 634
    invoke-static/range {v2 .. v8}, Lbl0/h;->a(Lbl0/h;Lbl0/e;ZLjava/util/ArrayList;Ljava/util/ArrayList;Ljava/util/ArrayList;I)Lbl0/h;

    .line 635
    .line 636
    .line 637
    move-result-object v1

    .line 638
    invoke-virtual {v0, v1}, Lcl0/j;->h(Lbl0/h;)V

    .line 639
    .line 640
    .line 641
    goto :goto_a

    .line 642
    :cond_14
    new-instance v0, La8/r0;

    .line 643
    .line 644
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 645
    .line 646
    .line 647
    throw v0

    .line 648
    :cond_15
    :goto_a
    return-object v10

    .line 649
    :pswitch_6
    move-object/from16 v1, p1

    .line 650
    .line 651
    check-cast v1, Lkotlin/coroutines/Continuation;

    .line 652
    .line 653
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 654
    .line 655
    check-cast v0, Lfj/a;

    .line 656
    .line 657
    invoke-interface {v0, v1}, Lfj/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 658
    .line 659
    .line 660
    move-result-object v0

    .line 661
    return-object v0

    .line 662
    :pswitch_7
    move-object/from16 v1, p1

    .line 663
    .line 664
    check-cast v1, Ldi/k;

    .line 665
    .line 666
    invoke-static {v1, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 667
    .line 668
    .line 669
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 670
    .line 671
    check-cast v0, Ldi/o;

    .line 672
    .line 673
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 674
    .line 675
    .line 676
    iget-object v2, v0, Ldi/o;->u:Llx0/q;

    .line 677
    .line 678
    invoke-virtual {v2}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 679
    .line 680
    .line 681
    move-result-object v2

    .line 682
    check-cast v2, Lzb/k0;

    .line 683
    .line 684
    new-instance v3, La60/f;

    .line 685
    .line 686
    const/16 v4, 0x1c

    .line 687
    .line 688
    invoke-direct {v3, v4, v1, v0, v8}, La60/f;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 689
    .line 690
    .line 691
    invoke-static {v2, v3}, Lzb/k0;->b(Lzb/k0;Lay0/n;)V

    .line 692
    .line 693
    .line 694
    return-object v10

    .line 695
    :pswitch_8
    move-object/from16 v1, p1

    .line 696
    .line 697
    check-cast v1, Ldf/b;

    .line 698
    .line 699
    invoke-static {v1, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 700
    .line 701
    .line 702
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 703
    .line 704
    check-cast v0, Ldf/d;

    .line 705
    .line 706
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 707
    .line 708
    .line 709
    sget-object v2, Ldf/b;->a:Ldf/b;

    .line 710
    .line 711
    invoke-virtual {v1, v2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 712
    .line 713
    .line 714
    move-result v1

    .line 715
    if-eqz v1, :cond_16

    .line 716
    .line 717
    iget-object v1, v0, Ldf/d;->d:Lay0/k;

    .line 718
    .line 719
    iget-object v0, v0, Ldf/d;->g:Lyy0/l1;

    .line 720
    .line 721
    invoke-static {v0}, Ldf/d;->a(Lyy0/a2;)Ljava/util/ArrayList;

    .line 722
    .line 723
    .line 724
    move-result-object v0

    .line 725
    invoke-interface {v1, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 726
    .line 727
    .line 728
    return-object v10

    .line 729
    :cond_16
    new-instance v0, La8/r0;

    .line 730
    .line 731
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 732
    .line 733
    .line 734
    throw v0

    .line 735
    :pswitch_9
    move-object/from16 v1, p1

    .line 736
    .line 737
    check-cast v1, Ljava/lang/String;

    .line 738
    .line 739
    invoke-static {v1, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 740
    .line 741
    .line 742
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 743
    .line 744
    check-cast v0, Lc90/n0;

    .line 745
    .line 746
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 747
    .line 748
    .line 749
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 750
    .line 751
    .line 752
    move-result-object v2

    .line 753
    new-instance v3, Lc90/m0;

    .line 754
    .line 755
    invoke-direct {v3, v0, v1, v8, v5}, Lc90/m0;-><init>(Lc90/n0;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 756
    .line 757
    .line 758
    invoke-static {v2, v8, v8, v3, v7}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 759
    .line 760
    .line 761
    return-object v10

    .line 762
    :pswitch_a
    move-object/from16 v1, p1

    .line 763
    .line 764
    check-cast v1, Ljava/lang/String;

    .line 765
    .line 766
    invoke-static {v1, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 767
    .line 768
    .line 769
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 770
    .line 771
    check-cast v0, Lc90/n0;

    .line 772
    .line 773
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 774
    .line 775
    .line 776
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 777
    .line 778
    .line 779
    move-result-object v2

    .line 780
    move-object v11, v2

    .line 781
    check-cast v11, Lc90/k0;

    .line 782
    .line 783
    const/16 v26, 0x0

    .line 784
    .line 785
    const/16 v27, 0x7fef

    .line 786
    .line 787
    const/4 v12, 0x0

    .line 788
    const/4 v13, 0x0

    .line 789
    const/4 v14, 0x0

    .line 790
    const/4 v15, 0x0

    .line 791
    const/16 v17, 0x0

    .line 792
    .line 793
    const/16 v18, 0x0

    .line 794
    .line 795
    const/16 v19, 0x0

    .line 796
    .line 797
    const/16 v20, 0x0

    .line 798
    .line 799
    const/16 v21, 0x0

    .line 800
    .line 801
    const/16 v22, 0x0

    .line 802
    .line 803
    const/16 v23, 0x0

    .line 804
    .line 805
    const/16 v24, 0x0

    .line 806
    .line 807
    const/16 v25, 0x0

    .line 808
    .line 809
    move-object/from16 v16, v1

    .line 810
    .line 811
    invoke-static/range {v11 .. v27}, Lc90/k0;->a(Lc90/k0;Lc90/a;Lb90/m;Ljava/time/LocalDate;Ljava/time/LocalTime;Ljava/lang/String;Lb90/a;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lql0/g;ZLb90/e;Ljava/util/List;Ljava/lang/String;I)Lc90/k0;

    .line 812
    .line 813
    .line 814
    move-result-object v1

    .line 815
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 816
    .line 817
    .line 818
    return-object v10

    .line 819
    :pswitch_b
    move-object/from16 v1, p1

    .line 820
    .line 821
    check-cast v1, Lql0/f;

    .line 822
    .line 823
    invoke-static {v1, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 824
    .line 825
    .line 826
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 827
    .line 828
    check-cast v0, Lc90/n0;

    .line 829
    .line 830
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 831
    .line 832
    .line 833
    sget-object v2, Lql0/c;->a:Lql0/c;

    .line 834
    .line 835
    invoke-virtual {v1, v2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 836
    .line 837
    .line 838
    move-result v1

    .line 839
    if-eqz v1, :cond_17

    .line 840
    .line 841
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 842
    .line 843
    .line 844
    move-result-object v1

    .line 845
    move-object v11, v1

    .line 846
    check-cast v11, Lc90/k0;

    .line 847
    .line 848
    const/16 v26, 0x0

    .line 849
    .line 850
    const/16 v27, 0x7bff

    .line 851
    .line 852
    const/4 v12, 0x0

    .line 853
    const/4 v13, 0x0

    .line 854
    const/4 v14, 0x0

    .line 855
    const/4 v15, 0x0

    .line 856
    const/16 v16, 0x0

    .line 857
    .line 858
    const/16 v17, 0x0

    .line 859
    .line 860
    const/16 v18, 0x0

    .line 861
    .line 862
    const/16 v19, 0x0

    .line 863
    .line 864
    const/16 v20, 0x0

    .line 865
    .line 866
    const/16 v21, 0x0

    .line 867
    .line 868
    const/16 v22, 0x0

    .line 869
    .line 870
    const/16 v23, 0x0

    .line 871
    .line 872
    const/16 v24, 0x0

    .line 873
    .line 874
    const/16 v25, 0x0

    .line 875
    .line 876
    invoke-static/range {v11 .. v27}, Lc90/k0;->a(Lc90/k0;Lc90/a;Lb90/m;Ljava/time/LocalDate;Ljava/time/LocalTime;Ljava/lang/String;Lb90/a;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lql0/g;ZLb90/e;Ljava/util/List;Ljava/lang/String;I)Lc90/k0;

    .line 877
    .line 878
    .line 879
    move-result-object v1

    .line 880
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 881
    .line 882
    .line 883
    goto :goto_b

    .line 884
    :cond_17
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 885
    .line 886
    .line 887
    move-result-object v1

    .line 888
    new-instance v2, Lc90/l0;

    .line 889
    .line 890
    invoke-direct {v2, v0, v8, v5}, Lc90/l0;-><init>(Lc90/n0;Lkotlin/coroutines/Continuation;I)V

    .line 891
    .line 892
    .line 893
    invoke-static {v1, v8, v8, v2, v7}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 894
    .line 895
    .line 896
    :goto_b
    return-object v10

    .line 897
    :pswitch_c
    move-object/from16 v1, p1

    .line 898
    .line 899
    check-cast v1, Ljava/lang/String;

    .line 900
    .line 901
    invoke-static {v1, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 902
    .line 903
    .line 904
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 905
    .line 906
    check-cast v0, Lc90/n0;

    .line 907
    .line 908
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 909
    .line 910
    .line 911
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 912
    .line 913
    .line 914
    move-result-object v2

    .line 915
    new-instance v3, Lc90/m0;

    .line 916
    .line 917
    invoke-direct {v3, v0, v1, v8, v6}, Lc90/m0;-><init>(Lc90/n0;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 918
    .line 919
    .line 920
    invoke-static {v2, v8, v8, v3, v7}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 921
    .line 922
    .line 923
    return-object v10

    .line 924
    :pswitch_d
    move-object/from16 v1, p1

    .line 925
    .line 926
    check-cast v1, Lc90/a;

    .line 927
    .line 928
    invoke-static {v1, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 929
    .line 930
    .line 931
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 932
    .line 933
    check-cast v0, Lc90/g0;

    .line 934
    .line 935
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 936
    .line 937
    .line 938
    iget-object v2, v0, Lc90/g0;->m:La90/f0;

    .line 939
    .line 940
    new-instance v3, Lb90/s;

    .line 941
    .line 942
    iget-object v4, v1, Lc90/a;->a:Ljava/lang/String;

    .line 943
    .line 944
    iget-object v5, v1, Lc90/a;->b:Ljava/lang/String;

    .line 945
    .line 946
    iget-object v1, v1, Lc90/a;->c:Landroid/net/Uri;

    .line 947
    .line 948
    invoke-virtual {v1}, Landroid/net/Uri;->toString()Ljava/lang/String;

    .line 949
    .line 950
    .line 951
    move-result-object v1

    .line 952
    const-string v6, "toString(...)"

    .line 953
    .line 954
    invoke-static {v1, v6}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 955
    .line 956
    .line 957
    invoke-direct {v3, v4, v5, v1}, Lb90/s;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 958
    .line 959
    .line 960
    iget-object v1, v2, La90/f0;->a:La90/q;

    .line 961
    .line 962
    check-cast v1, Ly80/a;

    .line 963
    .line 964
    iput-object v3, v1, Ly80/a;->g:Lb90/s;

    .line 965
    .line 966
    iget-object v0, v0, Lc90/g0;->l:Lnr0/d;

    .line 967
    .line 968
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 969
    .line 970
    .line 971
    return-object v10

    .line 972
    :pswitch_e
    move-object/from16 v1, p1

    .line 973
    .line 974
    check-cast v1, Lql0/f;

    .line 975
    .line 976
    invoke-static {v1, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 977
    .line 978
    .line 979
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 980
    .line 981
    check-cast v0, Lc90/g0;

    .line 982
    .line 983
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 984
    .line 985
    .line 986
    instance-of v1, v1, Lql0/a;

    .line 987
    .line 988
    if-eqz v1, :cond_18

    .line 989
    .line 990
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 991
    .line 992
    .line 993
    move-result-object v1

    .line 994
    move-object v11, v1

    .line 995
    check-cast v11, Lc90/e0;

    .line 996
    .line 997
    const/4 v15, 0x0

    .line 998
    const/16 v16, 0xd

    .line 999
    .line 1000
    const/4 v12, 0x0

    .line 1001
    const/4 v13, 0x0

    .line 1002
    const/4 v14, 0x0

    .line 1003
    invoke-static/range {v11 .. v16}, Lc90/e0;->a(Lc90/e0;ZLql0/g;Ljava/util/ArrayList;Lb90/e;I)Lc90/e0;

    .line 1004
    .line 1005
    .line 1006
    move-result-object v1

    .line 1007
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 1008
    .line 1009
    .line 1010
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 1011
    .line 1012
    .line 1013
    move-result-object v1

    .line 1014
    new-instance v2, Lc90/d0;

    .line 1015
    .line 1016
    invoke-direct {v2, v0, v8, v4}, Lc90/d0;-><init>(Lc90/g0;Lkotlin/coroutines/Continuation;I)V

    .line 1017
    .line 1018
    .line 1019
    invoke-static {v1, v8, v8, v2, v7}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 1020
    .line 1021
    .line 1022
    goto :goto_c

    .line 1023
    :cond_18
    iget-object v0, v0, Lc90/g0;->h:Ltr0/b;

    .line 1024
    .line 1025
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 1026
    .line 1027
    .line 1028
    :goto_c
    return-object v10

    .line 1029
    :pswitch_f
    move-object/from16 v1, p1

    .line 1030
    .line 1031
    check-cast v1, Lql0/f;

    .line 1032
    .line 1033
    invoke-static {v1, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1034
    .line 1035
    .line 1036
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 1037
    .line 1038
    check-cast v0, Lc90/c0;

    .line 1039
    .line 1040
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1041
    .line 1042
    .line 1043
    instance-of v1, v1, Lql0/a;

    .line 1044
    .line 1045
    if-eqz v1, :cond_19

    .line 1046
    .line 1047
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 1048
    .line 1049
    .line 1050
    move-result-object v1

    .line 1051
    move-object v11, v1

    .line 1052
    check-cast v11, Lc90/z;

    .line 1053
    .line 1054
    const/4 v15, 0x0

    .line 1055
    const/16 v16, 0xd

    .line 1056
    .line 1057
    const/4 v12, 0x0

    .line 1058
    const/4 v13, 0x0

    .line 1059
    const/4 v14, 0x0

    .line 1060
    invoke-static/range {v11 .. v16}, Lc90/z;->a(Lc90/z;ZLql0/g;ZLjava/util/ArrayList;I)Lc90/z;

    .line 1061
    .line 1062
    .line 1063
    move-result-object v1

    .line 1064
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 1065
    .line 1066
    .line 1067
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 1068
    .line 1069
    .line 1070
    move-result-object v1

    .line 1071
    new-instance v2, Lc90/y;

    .line 1072
    .line 1073
    invoke-direct {v2, v0, v8, v7}, Lc90/y;-><init>(Lc90/c0;Lkotlin/coroutines/Continuation;I)V

    .line 1074
    .line 1075
    .line 1076
    invoke-static {v1, v8, v8, v2, v7}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 1077
    .line 1078
    .line 1079
    goto :goto_d

    .line 1080
    :cond_19
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 1081
    .line 1082
    .line 1083
    move-result-object v1

    .line 1084
    new-instance v2, Lc90/y;

    .line 1085
    .line 1086
    invoke-direct {v2, v0, v8, v4}, Lc90/y;-><init>(Lc90/c0;Lkotlin/coroutines/Continuation;I)V

    .line 1087
    .line 1088
    .line 1089
    invoke-static {v1, v8, v8, v2, v7}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 1090
    .line 1091
    .line 1092
    :goto_d
    return-object v10

    .line 1093
    :pswitch_10
    move-object/from16 v1, p1

    .line 1094
    .line 1095
    check-cast v1, Ljava/lang/String;

    .line 1096
    .line 1097
    invoke-static {v1, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1098
    .line 1099
    .line 1100
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 1101
    .line 1102
    check-cast v0, Lc90/x;

    .line 1103
    .line 1104
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1105
    .line 1106
    .line 1107
    iget-object v2, v0, Lc90/x;->y:Lvy0/x1;

    .line 1108
    .line 1109
    if-eqz v2, :cond_1a

    .line 1110
    .line 1111
    invoke-virtual {v2, v8}, Lvy0/p1;->d(Ljava/util/concurrent/CancellationException;)V

    .line 1112
    .line 1113
    .line 1114
    :cond_1a
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 1115
    .line 1116
    .line 1117
    move-result-object v2

    .line 1118
    new-instance v3, Lc80/l;

    .line 1119
    .line 1120
    const/4 v4, 0x5

    .line 1121
    invoke-direct {v3, v4, v0, v1, v8}, Lc80/l;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 1122
    .line 1123
    .line 1124
    invoke-static {v2, v8, v8, v3, v7}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 1125
    .line 1126
    .line 1127
    move-result-object v1

    .line 1128
    iput-object v1, v0, Lc90/x;->y:Lvy0/x1;

    .line 1129
    .line 1130
    return-object v10

    .line 1131
    :pswitch_11
    move-object/from16 v1, p1

    .line 1132
    .line 1133
    check-cast v1, Lc90/s;

    .line 1134
    .line 1135
    invoke-static {v1, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1136
    .line 1137
    .line 1138
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 1139
    .line 1140
    check-cast v0, Lc90/x;

    .line 1141
    .line 1142
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1143
    .line 1144
    .line 1145
    iget-object v2, v0, Lc90/x;->r:La90/e0;

    .line 1146
    .line 1147
    iget-object v1, v1, Lc90/s;->e:Lb90/m;

    .line 1148
    .line 1149
    iget-object v2, v2, La90/e0;->a:La90/q;

    .line 1150
    .line 1151
    check-cast v2, Ly80/a;

    .line 1152
    .line 1153
    iput-object v1, v2, Ly80/a;->h:Lb90/m;

    .line 1154
    .line 1155
    iget-object v1, v0, Lc90/x;->v:La90/a0;

    .line 1156
    .line 1157
    sget-object v2, Lb90/d;->d:Lb90/d;

    .line 1158
    .line 1159
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1160
    .line 1161
    .line 1162
    sget-object v2, Lb90/d;->f:Lb90/d;

    .line 1163
    .line 1164
    iget-object v1, v1, La90/a0;->a:La90/q;

    .line 1165
    .line 1166
    check-cast v1, Ly80/a;

    .line 1167
    .line 1168
    iget-object v1, v1, Ly80/a;->j:Ljava/lang/Object;

    .line 1169
    .line 1170
    invoke-interface {v1, v2}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 1171
    .line 1172
    .line 1173
    move-result v1

    .line 1174
    if-eqz v1, :cond_1b

    .line 1175
    .line 1176
    iget-object v0, v0, Lc90/x;->s:Lnr0/c;

    .line 1177
    .line 1178
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 1179
    .line 1180
    .line 1181
    goto :goto_e

    .line 1182
    :cond_1b
    iget-object v0, v0, Lc90/x;->t:Lnr0/b;

    .line 1183
    .line 1184
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 1185
    .line 1186
    .line 1187
    :goto_e
    return-object v10

    .line 1188
    :pswitch_12
    move-object/from16 v7, p1

    .line 1189
    .line 1190
    check-cast v7, Ljava/time/LocalTime;

    .line 1191
    .line 1192
    invoke-static {v7, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1193
    .line 1194
    .line 1195
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 1196
    .line 1197
    check-cast v0, Lc90/i;

    .line 1198
    .line 1199
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1200
    .line 1201
    .line 1202
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 1203
    .line 1204
    .line 1205
    move-result-object v1

    .line 1206
    check-cast v1, Lc90/h;

    .line 1207
    .line 1208
    const/4 v8, 0x0

    .line 1209
    const/16 v9, 0x57

    .line 1210
    .line 1211
    const/4 v2, 0x0

    .line 1212
    const/4 v3, 0x0

    .line 1213
    const/4 v4, 0x0

    .line 1214
    const/4 v5, 0x0

    .line 1215
    const/4 v6, 0x0

    .line 1216
    invoke-static/range {v1 .. v9}, Lc90/h;->a(Lc90/h;ZZZZLjava/time/LocalDate;Ljava/time/LocalTime;Lb90/e;I)Lc90/h;

    .line 1217
    .line 1218
    .line 1219
    move-result-object v1

    .line 1220
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 1221
    .line 1222
    .line 1223
    return-object v10

    .line 1224
    :pswitch_13
    move-object/from16 v1, p1

    .line 1225
    .line 1226
    check-cast v1, Ljava/time/LocalDate;

    .line 1227
    .line 1228
    invoke-static {v1, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1229
    .line 1230
    .line 1231
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 1232
    .line 1233
    check-cast v0, Lc90/i;

    .line 1234
    .line 1235
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1236
    .line 1237
    .line 1238
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 1239
    .line 1240
    .line 1241
    move-result-object v2

    .line 1242
    move-object v11, v2

    .line 1243
    check-cast v11, Lc90/h;

    .line 1244
    .line 1245
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 1246
    .line 1247
    .line 1248
    move-result-object v2

    .line 1249
    check-cast v2, Lc90/h;

    .line 1250
    .line 1251
    iget-boolean v15, v2, Lc90/h;->b:Z

    .line 1252
    .line 1253
    const/16 v18, 0x0

    .line 1254
    .line 1255
    const/16 v19, 0x63

    .line 1256
    .line 1257
    const/4 v12, 0x0

    .line 1258
    const/4 v13, 0x0

    .line 1259
    const/4 v14, 0x0

    .line 1260
    const/16 v17, 0x0

    .line 1261
    .line 1262
    move-object/from16 v16, v1

    .line 1263
    .line 1264
    invoke-static/range {v11 .. v19}, Lc90/h;->a(Lc90/h;ZZZZLjava/time/LocalDate;Ljava/time/LocalTime;Lb90/e;I)Lc90/h;

    .line 1265
    .line 1266
    .line 1267
    move-result-object v1

    .line 1268
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 1269
    .line 1270
    .line 1271
    return-object v10

    .line 1272
    :pswitch_14
    move-object/from16 v1, p1

    .line 1273
    .line 1274
    check-cast v1, Lb90/k;

    .line 1275
    .line 1276
    invoke-static {v1, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1277
    .line 1278
    .line 1279
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 1280
    .line 1281
    check-cast v0, Lc90/f;

    .line 1282
    .line 1283
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1284
    .line 1285
    .line 1286
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 1287
    .line 1288
    .line 1289
    move-result-object v2

    .line 1290
    check-cast v2, Lc90/c;

    .line 1291
    .line 1292
    iget-object v2, v2, Lc90/c;->d:Ljava/util/Set;

    .line 1293
    .line 1294
    check-cast v2, Ljava/lang/Iterable;

    .line 1295
    .line 1296
    invoke-static {v2}, Lmx0/q;->B0(Ljava/lang/Iterable;)Ljava/util/Set;

    .line 1297
    .line 1298
    .line 1299
    move-result-object v15

    .line 1300
    invoke-interface {v15, v1}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 1301
    .line 1302
    .line 1303
    move-result v2

    .line 1304
    if-eqz v2, :cond_1c

    .line 1305
    .line 1306
    invoke-interface {v15, v1}, Ljava/util/Set;->remove(Ljava/lang/Object;)Z

    .line 1307
    .line 1308
    .line 1309
    goto :goto_f

    .line 1310
    :cond_1c
    invoke-interface {v15, v1}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 1311
    .line 1312
    .line 1313
    :goto_f
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 1314
    .line 1315
    .line 1316
    move-result-object v1

    .line 1317
    move-object v11, v1

    .line 1318
    check-cast v11, Lc90/c;

    .line 1319
    .line 1320
    const/16 v23, 0x0

    .line 1321
    .line 1322
    const/16 v24, 0xff7

    .line 1323
    .line 1324
    const/4 v12, 0x0

    .line 1325
    const/4 v13, 0x0

    .line 1326
    const/4 v14, 0x0

    .line 1327
    const/16 v16, 0x0

    .line 1328
    .line 1329
    const/16 v17, 0x0

    .line 1330
    .line 1331
    const/16 v18, 0x0

    .line 1332
    .line 1333
    const/16 v19, 0x0

    .line 1334
    .line 1335
    const/16 v20, 0x0

    .line 1336
    .line 1337
    const/16 v21, 0x0

    .line 1338
    .line 1339
    const/16 v22, 0x0

    .line 1340
    .line 1341
    invoke-static/range {v11 .. v24}, Lc90/c;->a(Lc90/c;Ljava/util/LinkedHashMap;Ljava/util/LinkedHashMap;Ljava/util/LinkedHashMap;Ljava/util/Set;ZLjava/util/Set;Ljava/util/Set;Ljava/util/Set;Ljava/util/ArrayList;ZLql0/g;Lb90/e;I)Lc90/c;

    .line 1342
    .line 1343
    .line 1344
    move-result-object v1

    .line 1345
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 1346
    .line 1347
    .line 1348
    return-object v10

    .line 1349
    :pswitch_15
    move-object/from16 v1, p1

    .line 1350
    .line 1351
    check-cast v1, Ljava/lang/String;

    .line 1352
    .line 1353
    invoke-static {v1, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1354
    .line 1355
    .line 1356
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 1357
    .line 1358
    check-cast v0, Lc90/f;

    .line 1359
    .line 1360
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1361
    .line 1362
    .line 1363
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 1364
    .line 1365
    .line 1366
    move-result-object v2

    .line 1367
    new-instance v4, Lc80/l;

    .line 1368
    .line 1369
    invoke-direct {v4, v3, v0, v1, v8}, Lc80/l;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 1370
    .line 1371
    .line 1372
    invoke-static {v2, v8, v8, v4, v7}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 1373
    .line 1374
    .line 1375
    return-object v10

    .line 1376
    :pswitch_16
    move-object/from16 v1, p1

    .line 1377
    .line 1378
    check-cast v1, Ljava/lang/Number;

    .line 1379
    .line 1380
    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    .line 1381
    .line 1382
    .line 1383
    move-result v1

    .line 1384
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 1385
    .line 1386
    check-cast v0, Lc80/t;

    .line 1387
    .line 1388
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 1389
    .line 1390
    .line 1391
    move-result-object v2

    .line 1392
    check-cast v2, Lc80/r;

    .line 1393
    .line 1394
    iget-object v2, v2, Lc80/r;->a:Ljava/util/List;

    .line 1395
    .line 1396
    invoke-interface {v2}, Ljava/util/List;->size()I

    .line 1397
    .line 1398
    .line 1399
    move-result v2

    .line 1400
    if-ge v2, v3, :cond_1d

    .line 1401
    .line 1402
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 1403
    .line 1404
    .line 1405
    move-result-object v2

    .line 1406
    move-object v11, v2

    .line 1407
    check-cast v11, Lc80/r;

    .line 1408
    .line 1409
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 1410
    .line 1411
    .line 1412
    move-result-object v2

    .line 1413
    check-cast v2, Lc80/r;

    .line 1414
    .line 1415
    iget-object v2, v2, Lc80/r;->a:Ljava/util/List;

    .line 1416
    .line 1417
    check-cast v2, Ljava/util/Collection;

    .line 1418
    .line 1419
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1420
    .line 1421
    .line 1422
    move-result-object v1

    .line 1423
    invoke-static {v2, v1}, Lmx0/q;->b0(Ljava/util/Collection;Ljava/lang/Object;)Ljava/util/ArrayList;

    .line 1424
    .line 1425
    .line 1426
    move-result-object v12

    .line 1427
    const/16 v17, 0x0

    .line 1428
    .line 1429
    const/16 v18, 0x3fe

    .line 1430
    .line 1431
    const/4 v13, 0x0

    .line 1432
    const/4 v14, 0x0

    .line 1433
    const/4 v15, 0x0

    .line 1434
    const/16 v16, 0x0

    .line 1435
    .line 1436
    invoke-static/range {v11 .. v18}, Lc80/r;->a(Lc80/r;Ljava/util/List;ZLjava/lang/String;ZLql0/g;Ljava/lang/String;I)Lc80/r;

    .line 1437
    .line 1438
    .line 1439
    move-result-object v1

    .line 1440
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 1441
    .line 1442
    .line 1443
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 1444
    .line 1445
    .line 1446
    move-result-object v1

    .line 1447
    check-cast v1, Lc80/r;

    .line 1448
    .line 1449
    iget-object v1, v1, Lc80/r;->a:Ljava/util/List;

    .line 1450
    .line 1451
    invoke-interface {v1}, Ljava/util/List;->size()I

    .line 1452
    .line 1453
    .line 1454
    move-result v1

    .line 1455
    if-ne v1, v3, :cond_1d

    .line 1456
    .line 1457
    invoke-virtual {v0}, Lc80/t;->j()V

    .line 1458
    .line 1459
    .line 1460
    :cond_1d
    return-object v10

    .line 1461
    :pswitch_17
    move-object/from16 v1, p1

    .line 1462
    .line 1463
    check-cast v1, Ljava/lang/Number;

    .line 1464
    .line 1465
    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    .line 1466
    .line 1467
    .line 1468
    move-result v1

    .line 1469
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 1470
    .line 1471
    check-cast v0, Lc80/m;

    .line 1472
    .line 1473
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 1474
    .line 1475
    .line 1476
    move-result-object v2

    .line 1477
    check-cast v2, Lc80/k;

    .line 1478
    .line 1479
    iget-object v2, v2, Lc80/k;->a:Ljava/util/List;

    .line 1480
    .line 1481
    invoke-interface {v2}, Ljava/util/List;->size()I

    .line 1482
    .line 1483
    .line 1484
    move-result v2

    .line 1485
    if-ge v2, v3, :cond_21

    .line 1486
    .line 1487
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 1488
    .line 1489
    .line 1490
    move-result-object v2

    .line 1491
    move-object v11, v2

    .line 1492
    check-cast v11, Lc80/k;

    .line 1493
    .line 1494
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 1495
    .line 1496
    .line 1497
    move-result-object v2

    .line 1498
    check-cast v2, Lc80/k;

    .line 1499
    .line 1500
    iget-object v2, v2, Lc80/k;->a:Ljava/util/List;

    .line 1501
    .line 1502
    check-cast v2, Ljava/util/Collection;

    .line 1503
    .line 1504
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1505
    .line 1506
    .line 1507
    move-result-object v1

    .line 1508
    invoke-static {v2, v1}, Lmx0/q;->b0(Ljava/util/Collection;Ljava/lang/Object;)Ljava/util/ArrayList;

    .line 1509
    .line 1510
    .line 1511
    move-result-object v12

    .line 1512
    const/16 v18, 0x0

    .line 1513
    .line 1514
    const/16 v19, 0x7e

    .line 1515
    .line 1516
    const/4 v13, 0x0

    .line 1517
    const/4 v14, 0x0

    .line 1518
    const/4 v15, 0x0

    .line 1519
    const/16 v16, 0x0

    .line 1520
    .line 1521
    const/16 v17, 0x0

    .line 1522
    .line 1523
    invoke-static/range {v11 .. v19}, Lc80/k;->a(Lc80/k;Ljava/util/List;Ljava/lang/String;Lql0/g;Ljava/lang/String;Ljava/lang/String;ZZI)Lc80/k;

    .line 1524
    .line 1525
    .line 1526
    move-result-object v1

    .line 1527
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 1528
    .line 1529
    .line 1530
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 1531
    .line 1532
    .line 1533
    move-result-object v1

    .line 1534
    check-cast v1, Lc80/k;

    .line 1535
    .line 1536
    iget-object v1, v1, Lc80/k;->a:Ljava/util/List;

    .line 1537
    .line 1538
    invoke-interface {v1}, Ljava/util/List;->size()I

    .line 1539
    .line 1540
    .line 1541
    move-result v1

    .line 1542
    if-ne v1, v3, :cond_21

    .line 1543
    .line 1544
    iget-object v1, v0, Lc80/m;->h:Lij0/a;

    .line 1545
    .line 1546
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 1547
    .line 1548
    .line 1549
    move-result-object v2

    .line 1550
    check-cast v2, Lc80/k;

    .line 1551
    .line 1552
    iget-boolean v2, v2, Lc80/k;->f:Z

    .line 1553
    .line 1554
    if-nez v2, :cond_21

    .line 1555
    .line 1556
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 1557
    .line 1558
    .line 1559
    move-result-object v2

    .line 1560
    check-cast v2, Lc80/k;

    .line 1561
    .line 1562
    iget-object v2, v2, Lc80/k;->e:Ljava/lang/String;

    .line 1563
    .line 1564
    sget-object v12, Lmx0/s;->d:Lmx0/s;

    .line 1565
    .line 1566
    if-nez v2, :cond_1f

    .line 1567
    .line 1568
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 1569
    .line 1570
    .line 1571
    move-result-object v2

    .line 1572
    check-cast v2, Lc80/k;

    .line 1573
    .line 1574
    iget-object v2, v2, Lc80/k;->a:Ljava/util/List;

    .line 1575
    .line 1576
    move-object v13, v2

    .line 1577
    check-cast v13, Ljava/lang/Iterable;

    .line 1578
    .line 1579
    const/16 v17, 0x0

    .line 1580
    .line 1581
    const/16 v18, 0x3e

    .line 1582
    .line 1583
    const-string v14, ""

    .line 1584
    .line 1585
    const/4 v15, 0x0

    .line 1586
    const/16 v16, 0x0

    .line 1587
    .line 1588
    invoke-static/range {v13 .. v18}, Lmx0/q;->R(Ljava/lang/Iterable;Ljava/lang/CharSequence;Ljava/lang/String;Ljava/lang/String;Lay0/k;I)Ljava/lang/String;

    .line 1589
    .line 1590
    .line 1591
    move-result-object v2

    .line 1592
    const-string v3, "value"

    .line 1593
    .line 1594
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1595
    .line 1596
    .line 1597
    iget-object v3, v0, Lc80/m;->m:Lwq0/u0;

    .line 1598
    .line 1599
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1600
    .line 1601
    .line 1602
    invoke-static {v2}, Lwq0/u0;->a(Ljava/lang/String;)Ljava/lang/Boolean;

    .line 1603
    .line 1604
    .line 1605
    move-result-object v3

    .line 1606
    invoke-virtual {v3}, Ljava/lang/Boolean;->booleanValue()Z

    .line 1607
    .line 1608
    .line 1609
    move-result v3

    .line 1610
    if-eqz v3, :cond_1e

    .line 1611
    .line 1612
    invoke-virtual {v0, v2}, Lc80/m;->h(Ljava/lang/String;)V

    .line 1613
    .line 1614
    .line 1615
    goto :goto_10

    .line 1616
    :cond_1e
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 1617
    .line 1618
    .line 1619
    move-result-object v2

    .line 1620
    move-object v11, v2

    .line 1621
    check-cast v11, Lc80/k;

    .line 1622
    .line 1623
    new-array v2, v6, [Ljava/lang/Object;

    .line 1624
    .line 1625
    check-cast v1, Ljj0/f;

    .line 1626
    .line 1627
    const v3, 0x7f121246

    .line 1628
    .line 1629
    .line 1630
    invoke-virtual {v1, v3, v2}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 1631
    .line 1632
    .line 1633
    move-result-object v13

    .line 1634
    const/16 v18, 0x0

    .line 1635
    .line 1636
    const/16 v19, 0x7c

    .line 1637
    .line 1638
    const/4 v14, 0x0

    .line 1639
    const/4 v15, 0x0

    .line 1640
    const/16 v16, 0x0

    .line 1641
    .line 1642
    const/16 v17, 0x0

    .line 1643
    .line 1644
    invoke-static/range {v11 .. v19}, Lc80/k;->a(Lc80/k;Ljava/util/List;Ljava/lang/String;Lql0/g;Ljava/lang/String;Ljava/lang/String;ZZI)Lc80/k;

    .line 1645
    .line 1646
    .line 1647
    move-result-object v1

    .line 1648
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 1649
    .line 1650
    .line 1651
    goto :goto_10

    .line 1652
    :cond_1f
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 1653
    .line 1654
    .line 1655
    move-result-object v3

    .line 1656
    check-cast v3, Lc80/k;

    .line 1657
    .line 1658
    iget-object v3, v3, Lc80/k;->a:Ljava/util/List;

    .line 1659
    .line 1660
    move-object v13, v3

    .line 1661
    check-cast v13, Ljava/lang/Iterable;

    .line 1662
    .line 1663
    const/16 v17, 0x0

    .line 1664
    .line 1665
    const/16 v18, 0x3e

    .line 1666
    .line 1667
    const-string v14, ""

    .line 1668
    .line 1669
    const/4 v15, 0x0

    .line 1670
    const/16 v16, 0x0

    .line 1671
    .line 1672
    invoke-static/range {v13 .. v18}, Lmx0/q;->R(Ljava/lang/Iterable;Ljava/lang/CharSequence;Ljava/lang/String;Ljava/lang/String;Lay0/k;I)Ljava/lang/String;

    .line 1673
    .line 1674
    .line 1675
    move-result-object v3

    .line 1676
    invoke-static {v3, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1677
    .line 1678
    .line 1679
    move-result v3

    .line 1680
    if-eqz v3, :cond_20

    .line 1681
    .line 1682
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 1683
    .line 1684
    .line 1685
    move-result-object v1

    .line 1686
    new-instance v3, Lc80/l;

    .line 1687
    .line 1688
    invoke-direct {v3, v6, v0, v2, v8}, Lc80/l;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 1689
    .line 1690
    .line 1691
    invoke-static {v1, v8, v8, v3, v7}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 1692
    .line 1693
    .line 1694
    goto :goto_10

    .line 1695
    :cond_20
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 1696
    .line 1697
    .line 1698
    move-result-object v2

    .line 1699
    move-object v11, v2

    .line 1700
    check-cast v11, Lc80/k;

    .line 1701
    .line 1702
    new-array v2, v6, [Ljava/lang/Object;

    .line 1703
    .line 1704
    check-cast v1, Ljj0/f;

    .line 1705
    .line 1706
    const v3, 0x7f121256

    .line 1707
    .line 1708
    .line 1709
    invoke-virtual {v1, v3, v2}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 1710
    .line 1711
    .line 1712
    move-result-object v13

    .line 1713
    const/16 v18, 0x0

    .line 1714
    .line 1715
    const/16 v19, 0x7c

    .line 1716
    .line 1717
    const/4 v14, 0x0

    .line 1718
    const/4 v15, 0x0

    .line 1719
    const/16 v16, 0x0

    .line 1720
    .line 1721
    const/16 v17, 0x0

    .line 1722
    .line 1723
    invoke-static/range {v11 .. v19}, Lc80/k;->a(Lc80/k;Ljava/util/List;Ljava/lang/String;Lql0/g;Ljava/lang/String;Ljava/lang/String;ZZI)Lc80/k;

    .line 1724
    .line 1725
    .line 1726
    move-result-object v1

    .line 1727
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 1728
    .line 1729
    .line 1730
    :cond_21
    :goto_10
    return-object v10

    .line 1731
    :pswitch_18
    move-object/from16 v1, p1

    .line 1732
    .line 1733
    check-cast v1, Ljava/lang/Number;

    .line 1734
    .line 1735
    invoke-virtual {v1}, Ljava/lang/Number;->longValue()J

    .line 1736
    .line 1737
    .line 1738
    move-result-wide v1

    .line 1739
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 1740
    .line 1741
    check-cast v0, Lc00/t1;

    .line 1742
    .line 1743
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1744
    .line 1745
    .line 1746
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 1747
    .line 1748
    .line 1749
    move-result-object v3

    .line 1750
    new-instance v4, Lc00/p1;

    .line 1751
    .line 1752
    invoke-direct {v4, v0, v1, v2, v8}, Lc00/p1;-><init>(Lc00/t1;JLkotlin/coroutines/Continuation;)V

    .line 1753
    .line 1754
    .line 1755
    invoke-static {v3, v8, v8, v4, v7}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 1756
    .line 1757
    .line 1758
    return-object v10

    .line 1759
    :pswitch_19
    move-object/from16 v1, p1

    .line 1760
    .line 1761
    check-cast v1, Ljava/lang/Number;

    .line 1762
    .line 1763
    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    .line 1764
    .line 1765
    .line 1766
    move-result v1

    .line 1767
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 1768
    .line 1769
    check-cast v0, Lbz/r;

    .line 1770
    .line 1771
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 1772
    .line 1773
    .line 1774
    move-result-object v2

    .line 1775
    check-cast v2, Lbz/q;

    .line 1776
    .line 1777
    iget-object v2, v2, Lbz/q;->f:Ljava/util/List;

    .line 1778
    .line 1779
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1780
    .line 1781
    .line 1782
    move-result-object v3

    .line 1783
    invoke-interface {v2, v3}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 1784
    .line 1785
    .line 1786
    move-result v3

    .line 1787
    if-eqz v3, :cond_22

    .line 1788
    .line 1789
    check-cast v2, Ljava/util/Collection;

    .line 1790
    .line 1791
    invoke-static {v2}, Lmx0/q;->z0(Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 1792
    .line 1793
    .line 1794
    move-result-object v2

    .line 1795
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1796
    .line 1797
    .line 1798
    move-result-object v1

    .line 1799
    invoke-virtual {v2, v1}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z

    .line 1800
    .line 1801
    .line 1802
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 1803
    .line 1804
    .line 1805
    move-result-object v1

    .line 1806
    check-cast v1, Lbz/q;

    .line 1807
    .line 1808
    const/16 v3, 0x1f

    .line 1809
    .line 1810
    invoke-static {v1, v6, v6, v2, v3}, Lbz/q;->a(Lbz/q;IILjava/util/ArrayList;I)Lbz/q;

    .line 1811
    .line 1812
    .line 1813
    move-result-object v1

    .line 1814
    goto :goto_11

    .line 1815
    :cond_22
    const/16 v3, 0x1f

    .line 1816
    .line 1817
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 1818
    .line 1819
    .line 1820
    move-result-object v2

    .line 1821
    check-cast v2, Lbz/q;

    .line 1822
    .line 1823
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 1824
    .line 1825
    .line 1826
    move-result-object v4

    .line 1827
    check-cast v4, Lbz/q;

    .line 1828
    .line 1829
    iget-object v4, v4, Lbz/q;->f:Ljava/util/List;

    .line 1830
    .line 1831
    check-cast v4, Ljava/util/Collection;

    .line 1832
    .line 1833
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1834
    .line 1835
    .line 1836
    move-result-object v1

    .line 1837
    invoke-static {v4, v1}, Lmx0/q;->b0(Ljava/util/Collection;Ljava/lang/Object;)Ljava/util/ArrayList;

    .line 1838
    .line 1839
    .line 1840
    move-result-object v1

    .line 1841
    invoke-static {v2, v6, v6, v1, v3}, Lbz/q;->a(Lbz/q;IILjava/util/ArrayList;I)Lbz/q;

    .line 1842
    .line 1843
    .line 1844
    move-result-object v1

    .line 1845
    :goto_11
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 1846
    .line 1847
    .line 1848
    return-object v10

    .line 1849
    :pswitch_1a
    move-object/from16 v1, p1

    .line 1850
    .line 1851
    check-cast v1, Ljava/lang/Number;

    .line 1852
    .line 1853
    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    .line 1854
    .line 1855
    .line 1856
    move-result v1

    .line 1857
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 1858
    .line 1859
    check-cast v0, Lbz/r;

    .line 1860
    .line 1861
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 1862
    .line 1863
    .line 1864
    move-result-object v2

    .line 1865
    check-cast v2, Lbz/q;

    .line 1866
    .line 1867
    const/16 v3, 0x37

    .line 1868
    .line 1869
    invoke-static {v2, v6, v1, v8, v3}, Lbz/q;->a(Lbz/q;IILjava/util/ArrayList;I)Lbz/q;

    .line 1870
    .line 1871
    .line 1872
    move-result-object v1

    .line 1873
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 1874
    .line 1875
    .line 1876
    return-object v10

    .line 1877
    :pswitch_1b
    move-object/from16 v1, p1

    .line 1878
    .line 1879
    check-cast v1, Ljava/lang/Number;

    .line 1880
    .line 1881
    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    .line 1882
    .line 1883
    .line 1884
    move-result v1

    .line 1885
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 1886
    .line 1887
    check-cast v0, Lbz/r;

    .line 1888
    .line 1889
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 1890
    .line 1891
    .line 1892
    move-result-object v2

    .line 1893
    check-cast v2, Lbz/q;

    .line 1894
    .line 1895
    const/16 v3, 0x3d

    .line 1896
    .line 1897
    invoke-static {v2, v1, v6, v8, v3}, Lbz/q;->a(Lbz/q;IILjava/util/ArrayList;I)Lbz/q;

    .line 1898
    .line 1899
    .line 1900
    move-result-object v1

    .line 1901
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 1902
    .line 1903
    .line 1904
    return-object v10

    .line 1905
    :pswitch_1c
    move-object/from16 v1, p1

    .line 1906
    .line 1907
    check-cast v1, Lbz/k;

    .line 1908
    .line 1909
    invoke-static {v1, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1910
    .line 1911
    .line 1912
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 1913
    .line 1914
    check-cast v0, Lbz/n;

    .line 1915
    .line 1916
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1917
    .line 1918
    .line 1919
    iget-object v2, v0, Lbz/n;->r:Ljava/util/List;

    .line 1920
    .line 1921
    if-eqz v2, :cond_26

    .line 1922
    .line 1923
    check-cast v2, Ljava/lang/Iterable;

    .line 1924
    .line 1925
    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 1926
    .line 1927
    .line 1928
    move-result-object v2

    .line 1929
    :cond_23
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 1930
    .line 1931
    .line 1932
    move-result v3

    .line 1933
    if-eqz v3, :cond_24

    .line 1934
    .line 1935
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1936
    .line 1937
    .line 1938
    move-result-object v3

    .line 1939
    move-object v4, v3

    .line 1940
    check-cast v4, Lqp0/b0;

    .line 1941
    .line 1942
    iget-object v4, v4, Lqp0/b0;->a:Ljava/lang/String;

    .line 1943
    .line 1944
    iget-object v5, v1, Lbz/k;->e:Ljava/lang/String;

    .line 1945
    .line 1946
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1947
    .line 1948
    .line 1949
    move-result v4

    .line 1950
    if-eqz v4, :cond_23

    .line 1951
    .line 1952
    move-object v8, v3

    .line 1953
    :cond_24
    check-cast v8, Lqp0/b0;

    .line 1954
    .line 1955
    if-eqz v8, :cond_25

    .line 1956
    .line 1957
    iget-object v0, v0, Lbz/n;->o:Lzy/y;

    .line 1958
    .line 1959
    iget-object v1, v0, Lzy/y;->b:Lpp0/m1;

    .line 1960
    .line 1961
    invoke-virtual {v1, v8}, Lpp0/m1;->a(Lqp0/b0;)V

    .line 1962
    .line 1963
    .line 1964
    iget-object v0, v0, Lzy/y;->a:Lzy/m;

    .line 1965
    .line 1966
    check-cast v0, Liy/b;

    .line 1967
    .line 1968
    sget-object v1, Lly/b;->P4:Lly/b;

    .line 1969
    .line 1970
    invoke-interface {v0, v1}, Ltl0/a;->a(Lul0/f;)V

    .line 1971
    .line 1972
    .line 1973
    :cond_25
    return-object v10

    .line 1974
    :cond_26
    const-string v0, "waypoints"

    .line 1975
    .line 1976
    invoke-static {v0}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 1977
    .line 1978
    .line 1979
    throw v8

    .line 1980
    nop

    .line 1981
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
