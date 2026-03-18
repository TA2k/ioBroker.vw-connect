.class public final Lc00/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Z

.field public final synthetic f:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;ZI)V
    .locals 0

    .line 1
    iput p3, p0, Lc00/g;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lc00/g;->f:Ljava/lang/Object;

    .line 4
    .line 5
    iput-boolean p2, p0, Lc00/g;->e:Z

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 24

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p2

    .line 4
    .line 5
    iget v2, v0, Lc00/g;->d:I

    .line 6
    .line 7
    packed-switch v2, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    move-object/from16 v2, p1

    .line 11
    .line 12
    check-cast v2, Lne0/s;

    .line 13
    .line 14
    iget-object v3, v0, Lc00/g;->f:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast v3, Ly20/m;

    .line 17
    .line 18
    instance-of v4, v2, Lne0/d;

    .line 19
    .line 20
    sget-object v5, Llx0/b0;->a:Llx0/b0;

    .line 21
    .line 22
    if-eqz v4, :cond_0

    .line 23
    .line 24
    invoke-virtual {v3}, Lql0/j;->a()Lql0/h;

    .line 25
    .line 26
    .line 27
    move-result-object v0

    .line 28
    move-object v6, v0

    .line 29
    check-cast v6, Ly20/h;

    .line 30
    .line 31
    const/16 v22, 0x0

    .line 32
    .line 33
    const v23, 0xf79f

    .line 34
    .line 35
    .line 36
    const/4 v7, 0x0

    .line 37
    const/4 v8, 0x0

    .line 38
    const/4 v9, 0x0

    .line 39
    const/4 v10, 0x0

    .line 40
    const/4 v11, 0x0

    .line 41
    const/4 v12, 0x1

    .line 42
    const/4 v13, 0x0

    .line 43
    const/4 v14, 0x0

    .line 44
    const/4 v15, 0x0

    .line 45
    const/16 v16, 0x0

    .line 46
    .line 47
    const/16 v17, 0x0

    .line 48
    .line 49
    const/16 v18, 0x0

    .line 50
    .line 51
    const/16 v19, 0x0

    .line 52
    .line 53
    const/16 v20, 0x0

    .line 54
    .line 55
    const/16 v21, 0x0

    .line 56
    .line 57
    invoke-static/range {v6 .. v23}, Ly20/h;->a(Ly20/h;Lql0/g;ZZZZZZZLjava/util/List;Ljava/lang/String;ZZZZZLx20/c;I)Ly20/h;

    .line 58
    .line 59
    .line 60
    move-result-object v0

    .line 61
    invoke-virtual {v3, v0}, Lql0/j;->g(Lql0/h;)V

    .line 62
    .line 63
    .line 64
    goto/16 :goto_1

    .line 65
    .line 66
    :cond_0
    instance-of v4, v2, Lne0/e;

    .line 67
    .line 68
    if-eqz v4, :cond_2

    .line 69
    .line 70
    invoke-virtual {v3}, Lql0/j;->a()Lql0/h;

    .line 71
    .line 72
    .line 73
    move-result-object v2

    .line 74
    move-object v6, v2

    .line 75
    check-cast v6, Ly20/h;

    .line 76
    .line 77
    const/16 v22, 0x0

    .line 78
    .line 79
    const v23, 0xffdf

    .line 80
    .line 81
    .line 82
    const/4 v7, 0x0

    .line 83
    const/4 v8, 0x0

    .line 84
    const/4 v9, 0x0

    .line 85
    const/4 v10, 0x0

    .line 86
    const/4 v11, 0x0

    .line 87
    const/4 v12, 0x0

    .line 88
    const/4 v13, 0x0

    .line 89
    const/4 v14, 0x0

    .line 90
    const/4 v15, 0x0

    .line 91
    const/16 v16, 0x0

    .line 92
    .line 93
    const/16 v17, 0x0

    .line 94
    .line 95
    const/16 v18, 0x0

    .line 96
    .line 97
    const/16 v19, 0x0

    .line 98
    .line 99
    const/16 v20, 0x0

    .line 100
    .line 101
    const/16 v21, 0x0

    .line 102
    .line 103
    invoke-static/range {v6 .. v23}, Ly20/h;->a(Ly20/h;Lql0/g;ZZZZZZZLjava/util/List;Ljava/lang/String;ZZZZZLx20/c;I)Ly20/h;

    .line 104
    .line 105
    .line 106
    move-result-object v2

    .line 107
    invoke-virtual {v3, v2}, Lql0/j;->g(Lql0/h;)V

    .line 108
    .line 109
    .line 110
    iget-boolean v0, v0, Lc00/g;->e:Z

    .line 111
    .line 112
    if-eqz v0, :cond_1

    .line 113
    .line 114
    const v0, 0x7f12152f

    .line 115
    .line 116
    .line 117
    goto :goto_0

    .line 118
    :cond_1
    const v0, 0x7f120346

    .line 119
    .line 120
    .line 121
    :goto_0
    iget-object v2, v3, Ly20/m;->x:Lrq0/f;

    .line 122
    .line 123
    new-instance v4, Lsq0/c;

    .line 124
    .line 125
    iget-object v3, v3, Ly20/m;->h:Lij0/a;

    .line 126
    .line 127
    const/4 v6, 0x0

    .line 128
    new-array v7, v6, [Ljava/lang/Object;

    .line 129
    .line 130
    check-cast v3, Ljj0/f;

    .line 131
    .line 132
    invoke-virtual {v3, v0, v7}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 133
    .line 134
    .line 135
    move-result-object v0

    .line 136
    const/4 v3, 0x6

    .line 137
    const/4 v7, 0x0

    .line 138
    invoke-direct {v4, v3, v0, v7, v7}, Lsq0/c;-><init>(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 139
    .line 140
    .line 141
    invoke-virtual {v2, v4, v6, v1}, Lrq0/f;->b(Lsq0/c;ZLkotlin/coroutines/Continuation;)Ljava/lang/Enum;

    .line 142
    .line 143
    .line 144
    move-result-object v0

    .line 145
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 146
    .line 147
    if-ne v0, v1, :cond_3

    .line 148
    .line 149
    move-object v5, v0

    .line 150
    goto :goto_1

    .line 151
    :cond_2
    instance-of v0, v2, Lne0/c;

    .line 152
    .line 153
    if-eqz v0, :cond_4

    .line 154
    .line 155
    invoke-virtual {v3}, Lql0/j;->a()Lql0/h;

    .line 156
    .line 157
    .line 158
    move-result-object v0

    .line 159
    move-object v6, v0

    .line 160
    check-cast v6, Ly20/h;

    .line 161
    .line 162
    check-cast v2, Lne0/c;

    .line 163
    .line 164
    iget-object v0, v3, Ly20/m;->h:Lij0/a;

    .line 165
    .line 166
    invoke-static {v2, v0}, Ljp/rf;->e(Lne0/c;Lij0/a;)Lql0/g;

    .line 167
    .line 168
    .line 169
    move-result-object v7

    .line 170
    const/16 v22, 0x0

    .line 171
    .line 172
    const v23, 0xffde

    .line 173
    .line 174
    .line 175
    const/4 v8, 0x0

    .line 176
    const/4 v9, 0x0

    .line 177
    const/4 v10, 0x0

    .line 178
    const/4 v11, 0x0

    .line 179
    const/4 v12, 0x0

    .line 180
    const/4 v13, 0x0

    .line 181
    const/4 v14, 0x0

    .line 182
    const/4 v15, 0x0

    .line 183
    const/16 v16, 0x0

    .line 184
    .line 185
    const/16 v17, 0x0

    .line 186
    .line 187
    const/16 v18, 0x0

    .line 188
    .line 189
    const/16 v19, 0x0

    .line 190
    .line 191
    const/16 v20, 0x0

    .line 192
    .line 193
    const/16 v21, 0x0

    .line 194
    .line 195
    invoke-static/range {v6 .. v23}, Ly20/h;->a(Ly20/h;Lql0/g;ZZZZZZZLjava/util/List;Ljava/lang/String;ZZZZZLx20/c;I)Ly20/h;

    .line 196
    .line 197
    .line 198
    move-result-object v0

    .line 199
    invoke-virtual {v3, v0}, Lql0/j;->g(Lql0/h;)V

    .line 200
    .line 201
    .line 202
    :cond_3
    :goto_1
    return-object v5

    .line 203
    :cond_4
    new-instance v0, La8/r0;

    .line 204
    .line 205
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 206
    .line 207
    .line 208
    throw v0

    .line 209
    :pswitch_0
    move-object/from16 v1, p1

    .line 210
    .line 211
    check-cast v1, Lne0/t;

    .line 212
    .line 213
    iget-object v2, v0, Lc00/g;->f:Ljava/lang/Object;

    .line 214
    .line 215
    check-cast v2, Lsa0/s;

    .line 216
    .line 217
    instance-of v3, v1, Lne0/c;

    .line 218
    .line 219
    if-eqz v3, :cond_5

    .line 220
    .line 221
    check-cast v1, Lne0/c;

    .line 222
    .line 223
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 224
    .line 225
    .line 226
    invoke-static {v2}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 227
    .line 228
    .line 229
    move-result-object v3

    .line 230
    new-instance v4, Lr60/t;

    .line 231
    .line 232
    const/16 v5, 0xc

    .line 233
    .line 234
    const/4 v6, 0x0

    .line 235
    invoke-direct {v4, v5, v2, v1, v6}, Lr60/t;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 236
    .line 237
    .line 238
    const/4 v1, 0x3

    .line 239
    invoke-static {v3, v6, v6, v4, v1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 240
    .line 241
    .line 242
    invoke-virtual {v2}, Lql0/j;->a()Lql0/h;

    .line 243
    .line 244
    .line 245
    move-result-object v1

    .line 246
    move-object v3, v1

    .line 247
    check-cast v3, Lsa0/p;

    .line 248
    .line 249
    iget-boolean v0, v0, Lc00/g;->e:Z

    .line 250
    .line 251
    xor-int/lit8 v7, v0, 0x1

    .line 252
    .line 253
    const/4 v9, 0x0

    .line 254
    const/16 v10, 0x37

    .line 255
    .line 256
    const/4 v4, 0x0

    .line 257
    const/4 v5, 0x0

    .line 258
    const/4 v6, 0x0

    .line 259
    const/4 v8, 0x0

    .line 260
    invoke-static/range {v3 .. v10}, Lsa0/p;->a(Lsa0/p;ZZZZLjava/lang/String;ZI)Lsa0/p;

    .line 261
    .line 262
    .line 263
    move-result-object v0

    .line 264
    goto :goto_2

    .line 265
    :cond_5
    instance-of v0, v1, Lne0/e;

    .line 266
    .line 267
    if-eqz v0, :cond_6

    .line 268
    .line 269
    invoke-virtual {v2}, Lql0/j;->a()Lql0/h;

    .line 270
    .line 271
    .line 272
    move-result-object v0

    .line 273
    move-object v3, v0

    .line 274
    check-cast v3, Lsa0/p;

    .line 275
    .line 276
    const/4 v9, 0x1

    .line 277
    const/16 v10, 0x1f

    .line 278
    .line 279
    const/4 v4, 0x0

    .line 280
    const/4 v5, 0x0

    .line 281
    const/4 v6, 0x0

    .line 282
    const/4 v7, 0x0

    .line 283
    const/4 v8, 0x0

    .line 284
    invoke-static/range {v3 .. v10}, Lsa0/p;->a(Lsa0/p;ZZZZLjava/lang/String;ZI)Lsa0/p;

    .line 285
    .line 286
    .line 287
    move-result-object v0

    .line 288
    :goto_2
    invoke-virtual {v2, v0}, Lql0/j;->g(Lql0/h;)V

    .line 289
    .line 290
    .line 291
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 292
    .line 293
    return-object v0

    .line 294
    :cond_6
    new-instance v0, La8/r0;

    .line 295
    .line 296
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 297
    .line 298
    .line 299
    throw v0

    .line 300
    :pswitch_1
    instance-of v2, v1, Ln50/f0;

    .line 301
    .line 302
    if-eqz v2, :cond_7

    .line 303
    .line 304
    move-object v2, v1

    .line 305
    check-cast v2, Ln50/f0;

    .line 306
    .line 307
    iget v3, v2, Ln50/f0;->e:I

    .line 308
    .line 309
    const/high16 v4, -0x80000000

    .line 310
    .line 311
    and-int v5, v3, v4

    .line 312
    .line 313
    if-eqz v5, :cond_7

    .line 314
    .line 315
    sub-int/2addr v3, v4

    .line 316
    iput v3, v2, Ln50/f0;->e:I

    .line 317
    .line 318
    goto :goto_3

    .line 319
    :cond_7
    new-instance v2, Ln50/f0;

    .line 320
    .line 321
    invoke-direct {v2, v0, v1}, Ln50/f0;-><init>(Lc00/g;Lkotlin/coroutines/Continuation;)V

    .line 322
    .line 323
    .line 324
    :goto_3
    iget-object v1, v2, Ln50/f0;->d:Ljava/lang/Object;

    .line 325
    .line 326
    sget-object v3, Lqx0/a;->d:Lqx0/a;

    .line 327
    .line 328
    iget v4, v2, Ln50/f0;->e:I

    .line 329
    .line 330
    const/4 v5, 0x1

    .line 331
    if-eqz v4, :cond_9

    .line 332
    .line 333
    if-ne v4, v5, :cond_8

    .line 334
    .line 335
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 336
    .line 337
    .line 338
    goto :goto_4

    .line 339
    :cond_8
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 340
    .line 341
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 342
    .line 343
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 344
    .line 345
    .line 346
    throw v0

    .line 347
    :cond_9
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 348
    .line 349
    .line 350
    iget-object v1, v0, Lc00/g;->f:Ljava/lang/Object;

    .line 351
    .line 352
    check-cast v1, Lyy0/j;

    .line 353
    .line 354
    move-object/from16 v4, p1

    .line 355
    .line 356
    check-cast v4, Lne0/t;

    .line 357
    .line 358
    new-instance v6, Llz/c;

    .line 359
    .line 360
    iget-boolean v0, v0, Lc00/g;->e:Z

    .line 361
    .line 362
    invoke-direct {v6, v0}, Llz/c;-><init>(Z)V

    .line 363
    .line 364
    .line 365
    invoke-static {v4, v6}, Lbb/j0;->c(Lne0/t;Lay0/k;)Lne0/t;

    .line 366
    .line 367
    .line 368
    move-result-object v0

    .line 369
    iput v5, v2, Ln50/f0;->e:I

    .line 370
    .line 371
    invoke-interface {v1, v0, v2}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 372
    .line 373
    .line 374
    move-result-object v0

    .line 375
    if-ne v0, v3, :cond_a

    .line 376
    .line 377
    goto :goto_5

    .line 378
    :cond_a
    :goto_4
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 379
    .line 380
    :goto_5
    return-object v3

    .line 381
    :pswitch_2
    move-object/from16 v2, p1

    .line 382
    .line 383
    check-cast v2, Lne0/t;

    .line 384
    .line 385
    iget-object v3, v0, Lc00/g;->f:Ljava/lang/Object;

    .line 386
    .line 387
    check-cast v3, Lc00/p;

    .line 388
    .line 389
    instance-of v4, v2, Lne0/c;

    .line 390
    .line 391
    sget-object v5, Llx0/b0;->a:Llx0/b0;

    .line 392
    .line 393
    if-eqz v4, :cond_b

    .line 394
    .line 395
    iget-object v0, v3, Lc00/p;->s:Ljn0/c;

    .line 396
    .line 397
    check-cast v2, Lne0/c;

    .line 398
    .line 399
    invoke-virtual {v0, v2, v1}, Ljn0/c;->c(Lne0/c;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 400
    .line 401
    .line 402
    move-result-object v0

    .line 403
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 404
    .line 405
    if-ne v0, v1, :cond_c

    .line 406
    .line 407
    move-object v5, v0

    .line 408
    goto :goto_6

    .line 409
    :cond_b
    instance-of v1, v2, Lne0/e;

    .line 410
    .line 411
    if-eqz v1, :cond_d

    .line 412
    .line 413
    invoke-virtual {v3}, Lql0/j;->a()Lql0/h;

    .line 414
    .line 415
    .line 416
    move-result-object v1

    .line 417
    check-cast v1, Lc00/n;

    .line 418
    .line 419
    iget-object v2, v3, Lc00/p;->l:Lij0/a;

    .line 420
    .line 421
    iget-boolean v0, v0, Lc00/g;->e:Z

    .line 422
    .line 423
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 424
    .line 425
    .line 426
    move-result-object v0

    .line 427
    invoke-static {v1, v2, v0}, Ljp/xb;->x(Lc00/n;Lij0/a;Ljava/lang/Boolean;)Lc00/n;

    .line 428
    .line 429
    .line 430
    move-result-object v0

    .line 431
    invoke-virtual {v3, v0}, Lql0/j;->g(Lql0/h;)V

    .line 432
    .line 433
    .line 434
    :cond_c
    :goto_6
    return-object v5

    .line 435
    :cond_d
    new-instance v0, La8/r0;

    .line 436
    .line 437
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 438
    .line 439
    .line 440
    throw v0

    .line 441
    :pswitch_3
    move-object/from16 v1, p1

    .line 442
    .line 443
    check-cast v1, Llx0/l;

    .line 444
    .line 445
    iget-object v2, v1, Llx0/l;->d:Ljava/lang/Object;

    .line 446
    .line 447
    move-object v5, v2

    .line 448
    check-cast v5, Lne0/s;

    .line 449
    .line 450
    iget-object v1, v1, Llx0/l;->e:Ljava/lang/Object;

    .line 451
    .line 452
    check-cast v1, Ljava/util/List;

    .line 453
    .line 454
    iget-object v2, v0, Lc00/g;->f:Ljava/lang/Object;

    .line 455
    .line 456
    move-object v4, v2

    .line 457
    check-cast v4, Lc00/h;

    .line 458
    .line 459
    invoke-static {v4}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 460
    .line 461
    .line 462
    move-result-object v2

    .line 463
    new-instance v3, Lbc/g;

    .line 464
    .line 465
    const/4 v8, 0x1

    .line 466
    iget-boolean v6, v0, Lc00/g;->e:Z

    .line 467
    .line 468
    const/4 v7, 0x0

    .line 469
    invoke-direct/range {v3 .. v8}, Lbc/g;-><init>(Lql0/j;Ljava/lang/Object;ZLkotlin/coroutines/Continuation;I)V

    .line 470
    .line 471
    .line 472
    const/4 v0, 0x3

    .line 473
    invoke-static {v2, v7, v7, v3, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 474
    .line 475
    .line 476
    check-cast v1, Ljava/lang/Iterable;

    .line 477
    .line 478
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 479
    .line 480
    .line 481
    move-result-object v1

    .line 482
    :goto_7
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 483
    .line 484
    .line 485
    move-result v2

    .line 486
    if-eqz v2, :cond_e

    .line 487
    .line 488
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 489
    .line 490
    .line 491
    move-result-object v2

    .line 492
    check-cast v2, Lcn0/c;

    .line 493
    .line 494
    invoke-static {v4}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 495
    .line 496
    .line 497
    move-result-object v3

    .line 498
    new-instance v5, La7/o;

    .line 499
    .line 500
    const/16 v6, 0xd

    .line 501
    .line 502
    invoke-direct {v5, v6, v2, v4, v7}, La7/o;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 503
    .line 504
    .line 505
    invoke-static {v3, v7, v7, v5, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 506
    .line 507
    .line 508
    goto :goto_7

    .line 509
    :cond_e
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 510
    .line 511
    return-object v0

    .line 512
    nop

    .line 513
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
