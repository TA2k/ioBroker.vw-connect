.class public final Lru0/k0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lty/c;

.field public final b:Lrt0/j;

.field public final c:Llb0/b;

.field public final d:Lqd0/n;

.field public final e:Lqd0/l;

.field public final f:Lq10/c;

.field public final g:Lep0/a;

.field public final h:Llz/e;

.field public final i:Lnn0/f;

.field public final j:Lcc0/h;

.field public final k:Lk70/o;

.field public final l:Ls50/d;

.field public final m:Lhh0/a;

.field public final n:Lkf0/k;


# direct methods
.method public constructor <init>(Lty/c;Lrt0/j;Llb0/b;Lqd0/n;Lqd0/l;Lq10/c;Lep0/a;Llz/e;Lnn0/f;Lcc0/h;Lk70/o;Ls50/d;Lhh0/a;Lkf0/k;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lru0/k0;->a:Lty/c;

    .line 5
    .line 6
    iput-object p2, p0, Lru0/k0;->b:Lrt0/j;

    .line 7
    .line 8
    iput-object p3, p0, Lru0/k0;->c:Llb0/b;

    .line 9
    .line 10
    iput-object p4, p0, Lru0/k0;->d:Lqd0/n;

    .line 11
    .line 12
    iput-object p5, p0, Lru0/k0;->e:Lqd0/l;

    .line 13
    .line 14
    iput-object p6, p0, Lru0/k0;->f:Lq10/c;

    .line 15
    .line 16
    iput-object p7, p0, Lru0/k0;->g:Lep0/a;

    .line 17
    .line 18
    iput-object p8, p0, Lru0/k0;->h:Llz/e;

    .line 19
    .line 20
    iput-object p9, p0, Lru0/k0;->i:Lnn0/f;

    .line 21
    .line 22
    iput-object p10, p0, Lru0/k0;->j:Lcc0/h;

    .line 23
    .line 24
    iput-object p11, p0, Lru0/k0;->k:Lk70/o;

    .line 25
    .line 26
    iput-object p12, p0, Lru0/k0;->l:Ls50/d;

    .line 27
    .line 28
    iput-object p13, p0, Lru0/k0;->m:Lhh0/a;

    .line 29
    .line 30
    iput-object p14, p0, Lru0/k0;->n:Lkf0/k;

    .line 31
    .line 32
    return-void
.end method

.method public static final a(Lru0/k0;Ljava/util/List;Lpw0/a;Lrx0/c;)Ljava/lang/Object;
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p3

    .line 4
    .line 5
    iget-object v2, v0, Lru0/k0;->e:Lqd0/l;

    .line 6
    .line 7
    instance-of v3, v1, Lru0/h0;

    .line 8
    .line 9
    if-eqz v3, :cond_0

    .line 10
    .line 11
    move-object v3, v1

    .line 12
    check-cast v3, Lru0/h0;

    .line 13
    .line 14
    iget v4, v3, Lru0/h0;->o:I

    .line 15
    .line 16
    const/high16 v5, -0x80000000

    .line 17
    .line 18
    and-int v6, v4, v5

    .line 19
    .line 20
    if-eqz v6, :cond_0

    .line 21
    .line 22
    sub-int/2addr v4, v5

    .line 23
    iput v4, v3, Lru0/h0;->o:I

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_0
    new-instance v3, Lru0/h0;

    .line 27
    .line 28
    invoke-direct {v3, v0, v1}, Lru0/h0;-><init>(Lru0/k0;Lrx0/c;)V

    .line 29
    .line 30
    .line 31
    :goto_0
    iget-object v1, v3, Lru0/h0;->m:Ljava/lang/Object;

    .line 32
    .line 33
    sget-object v4, Lqx0/a;->d:Lqx0/a;

    .line 34
    .line 35
    iget v5, v3, Lru0/h0;->o:I

    .line 36
    .line 37
    const/4 v6, 0x2

    .line 38
    const/4 v7, 0x0

    .line 39
    const/4 v8, 0x1

    .line 40
    if-eqz v5, :cond_3

    .line 41
    .line 42
    if-eq v5, v8, :cond_2

    .line 43
    .line 44
    if-ne v5, v6, :cond_1

    .line 45
    .line 46
    iget-boolean v5, v3, Lru0/h0;->l:Z

    .line 47
    .line 48
    iget v10, v3, Lru0/h0;->i:I

    .line 49
    .line 50
    iget v11, v3, Lru0/h0;->h:I

    .line 51
    .line 52
    iget v12, v3, Lru0/h0;->g:I

    .line 53
    .line 54
    iget-object v13, v3, Lru0/h0;->f:Ljava/util/Iterator;

    .line 55
    .line 56
    iget-object v14, v3, Lru0/h0;->e:Ljava/util/Collection;

    .line 57
    .line 58
    check-cast v14, Ljava/util/Collection;

    .line 59
    .line 60
    iget-object v15, v3, Lru0/h0;->d:Lvy0/b0;

    .line 61
    .line 62
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 63
    .line 64
    .line 65
    move/from16 v16, v7

    .line 66
    .line 67
    goto/16 :goto_5

    .line 68
    .line 69
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 70
    .line 71
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 72
    .line 73
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 74
    .line 75
    .line 76
    throw v0

    .line 77
    :cond_2
    iget v5, v3, Lru0/h0;->k:I

    .line 78
    .line 79
    iget v10, v3, Lru0/h0;->j:I

    .line 80
    .line 81
    iget v11, v3, Lru0/h0;->i:I

    .line 82
    .line 83
    iget v12, v3, Lru0/h0;->h:I

    .line 84
    .line 85
    iget v13, v3, Lru0/h0;->g:I

    .line 86
    .line 87
    iget-object v14, v3, Lru0/h0;->f:Ljava/util/Iterator;

    .line 88
    .line 89
    iget-object v15, v3, Lru0/h0;->e:Ljava/util/Collection;

    .line 90
    .line 91
    check-cast v15, Ljava/util/Collection;

    .line 92
    .line 93
    iget-object v9, v3, Lru0/h0;->d:Lvy0/b0;

    .line 94
    .line 95
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 96
    .line 97
    .line 98
    move-object/from16 v17, v15

    .line 99
    .line 100
    move-object v15, v9

    .line 101
    move v9, v10

    .line 102
    move v10, v11

    .line 103
    move v11, v12

    .line 104
    move v12, v13

    .line 105
    move-object v13, v14

    .line 106
    move-object/from16 v14, v17

    .line 107
    .line 108
    goto/16 :goto_3

    .line 109
    .line 110
    :cond_3
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 111
    .line 112
    .line 113
    move-object/from16 v1, p1

    .line 114
    .line 115
    check-cast v1, Ljava/lang/Iterable;

    .line 116
    .line 117
    new-instance v5, Ljava/util/ArrayList;

    .line 118
    .line 119
    invoke-direct {v5}, Ljava/util/ArrayList;-><init>()V

    .line 120
    .line 121
    .line 122
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 123
    .line 124
    .line 125
    move-result-object v1

    .line 126
    move-object v9, v5

    .line 127
    move v10, v7

    .line 128
    move v11, v10

    .line 129
    move v12, v11

    .line 130
    move-object v5, v3

    .line 131
    move-object v3, v1

    .line 132
    move-object/from16 v1, p2

    .line 133
    .line 134
    :goto_1
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 135
    .line 136
    .line 137
    move-result v13

    .line 138
    if-eqz v13, :cond_9

    .line 139
    .line 140
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 141
    .line 142
    .line 143
    move-result-object v13

    .line 144
    check-cast v13, Ltu0/b;

    .line 145
    .line 146
    invoke-virtual {v13}, Ljava/lang/Enum;->ordinal()I

    .line 147
    .line 148
    .line 149
    move-result v13

    .line 150
    packed-switch v13, :pswitch_data_0

    .line 151
    .line 152
    .line 153
    new-instance v0, La8/r0;

    .line 154
    .line 155
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 156
    .line 157
    .line 158
    throw v0

    .line 159
    :pswitch_0
    iget-object v13, v0, Lru0/k0;->b:Lrt0/j;

    .line 160
    .line 161
    new-instance v14, Lrt0/h;

    .line 162
    .line 163
    invoke-direct {v14, v8}, Lrt0/h;-><init>(Z)V

    .line 164
    .line 165
    .line 166
    invoke-virtual {v13, v14}, Lrt0/j;->a(Lrt0/h;)Lzy0/j;

    .line 167
    .line 168
    .line 169
    move-result-object v13

    .line 170
    :goto_2
    move/from16 v16, v7

    .line 171
    .line 172
    move v7, v8

    .line 173
    goto/16 :goto_7

    .line 174
    .line 175
    :pswitch_1
    move/from16 v16, v7

    .line 176
    .line 177
    move v7, v8

    .line 178
    const/4 v13, 0x0

    .line 179
    goto/16 :goto_7

    .line 180
    .line 181
    :pswitch_2
    iget-object v13, v0, Lru0/k0;->g:Lep0/a;

    .line 182
    .line 183
    invoke-virtual {v13}, Lep0/a;->invoke()Ljava/lang/Object;

    .line 184
    .line 185
    .line 186
    move-result-object v13

    .line 187
    check-cast v13, Lyy0/i;

    .line 188
    .line 189
    goto :goto_2

    .line 190
    :pswitch_3
    iget-object v13, v0, Lru0/k0;->i:Lnn0/f;

    .line 191
    .line 192
    invoke-virtual {v13}, Lnn0/f;->invoke()Ljava/lang/Object;

    .line 193
    .line 194
    .line 195
    move-result-object v13

    .line 196
    check-cast v13, Lyy0/i;

    .line 197
    .line 198
    goto :goto_2

    .line 199
    :pswitch_4
    iget-object v13, v0, Lru0/k0;->k:Lk70/o;

    .line 200
    .line 201
    new-instance v14, Lk70/n;

    .line 202
    .line 203
    invoke-direct {v14}, Ljava/lang/Object;-><init>()V

    .line 204
    .line 205
    .line 206
    invoke-virtual {v13, v14}, Lk70/o;->a(Lk70/n;)Lzy0/j;

    .line 207
    .line 208
    .line 209
    move-result-object v13

    .line 210
    goto :goto_2

    .line 211
    :pswitch_5
    iget-object v13, v0, Lru0/k0;->l:Ls50/d;

    .line 212
    .line 213
    invoke-virtual {v13}, Ls50/d;->invoke()Ljava/lang/Object;

    .line 214
    .line 215
    .line 216
    move-result-object v13

    .line 217
    check-cast v13, Lyy0/i;

    .line 218
    .line 219
    goto :goto_2

    .line 220
    :pswitch_6
    iget-object v13, v0, Lru0/k0;->f:Lq10/c;

    .line 221
    .line 222
    new-instance v14, Lq10/b;

    .line 223
    .line 224
    invoke-direct {v14, v8}, Lq10/b;-><init>(Z)V

    .line 225
    .line 226
    .line 227
    invoke-virtual {v13, v14}, Lq10/c;->a(Lq10/b;)Lzy0/j;

    .line 228
    .line 229
    .line 230
    move-result-object v13

    .line 231
    goto :goto_2

    .line 232
    :pswitch_7
    iget-object v13, v0, Lru0/k0;->c:Llb0/b;

    .line 233
    .line 234
    new-instance v14, Llb0/a;

    .line 235
    .line 236
    invoke-direct {v14, v8}, Llb0/a;-><init>(Z)V

    .line 237
    .line 238
    .line 239
    invoke-virtual {v13, v14}, Llb0/b;->a(Llb0/a;)Lzy0/j;

    .line 240
    .line 241
    .line 242
    move-result-object v13

    .line 243
    goto :goto_2

    .line 244
    :pswitch_8
    invoke-virtual {v2}, Lqd0/l;->invoke()Ljava/lang/Object;

    .line 245
    .line 246
    .line 247
    move-result-object v13

    .line 248
    check-cast v13, Lyy0/i;

    .line 249
    .line 250
    goto :goto_2

    .line 251
    :pswitch_9
    iget-object v13, v0, Lru0/k0;->m:Lhh0/a;

    .line 252
    .line 253
    sget-object v14, Lih0/a;->i:Lih0/a;

    .line 254
    .line 255
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 256
    .line 257
    .line 258
    iput-object v1, v5, Lru0/h0;->d:Lvy0/b0;

    .line 259
    .line 260
    move-object v15, v9

    .line 261
    check-cast v15, Ljava/util/Collection;

    .line 262
    .line 263
    iput-object v15, v5, Lru0/h0;->e:Ljava/util/Collection;

    .line 264
    .line 265
    iput-object v3, v5, Lru0/h0;->f:Ljava/util/Iterator;

    .line 266
    .line 267
    iput v10, v5, Lru0/h0;->g:I

    .line 268
    .line 269
    iput v11, v5, Lru0/h0;->h:I

    .line 270
    .line 271
    iput v12, v5, Lru0/h0;->i:I

    .line 272
    .line 273
    iput v7, v5, Lru0/h0;->j:I

    .line 274
    .line 275
    iput v7, v5, Lru0/h0;->k:I

    .line 276
    .line 277
    iput v8, v5, Lru0/h0;->o:I

    .line 278
    .line 279
    invoke-virtual {v13, v14, v5}, Lhh0/a;->b(Lih0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 280
    .line 281
    .line 282
    move-result-object v13

    .line 283
    if-ne v13, v4, :cond_4

    .line 284
    .line 285
    goto :goto_4

    .line 286
    :cond_4
    move v14, v12

    .line 287
    move v12, v10

    .line 288
    move v10, v14

    .line 289
    move-object v15, v1

    .line 290
    move-object v14, v9

    .line 291
    move-object v1, v13

    .line 292
    move-object v13, v3

    .line 293
    move-object v3, v5

    .line 294
    move v5, v7

    .line 295
    move v9, v5

    .line 296
    :goto_3
    check-cast v1, Ljava/lang/Boolean;

    .line 297
    .line 298
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 299
    .line 300
    .line 301
    move-result v1

    .line 302
    move/from16 v16, v7

    .line 303
    .line 304
    iget-object v7, v0, Lru0/k0;->n:Lkf0/k;

    .line 305
    .line 306
    iput-object v15, v3, Lru0/h0;->d:Lvy0/b0;

    .line 307
    .line 308
    move-object v8, v14

    .line 309
    check-cast v8, Ljava/util/Collection;

    .line 310
    .line 311
    iput-object v8, v3, Lru0/h0;->e:Ljava/util/Collection;

    .line 312
    .line 313
    iput-object v13, v3, Lru0/h0;->f:Ljava/util/Iterator;

    .line 314
    .line 315
    iput v12, v3, Lru0/h0;->g:I

    .line 316
    .line 317
    iput v11, v3, Lru0/h0;->h:I

    .line 318
    .line 319
    iput v10, v3, Lru0/h0;->i:I

    .line 320
    .line 321
    iput v9, v3, Lru0/h0;->j:I

    .line 322
    .line 323
    iput v5, v3, Lru0/h0;->k:I

    .line 324
    .line 325
    iput-boolean v1, v3, Lru0/h0;->l:Z

    .line 326
    .line 327
    iput v6, v3, Lru0/h0;->o:I

    .line 328
    .line 329
    invoke-virtual {v7, v3}, Lkf0/k;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 330
    .line 331
    .line 332
    move-result-object v5

    .line 333
    if-ne v5, v4, :cond_5

    .line 334
    .line 335
    :goto_4
    return-object v4

    .line 336
    :cond_5
    move-object/from16 v17, v5

    .line 337
    .line 338
    move v5, v1

    .line 339
    move-object/from16 v1, v17

    .line 340
    .line 341
    :goto_5
    check-cast v1, Lss0/b;

    .line 342
    .line 343
    sget-object v7, Lss0/e;->u:Lss0/e;

    .line 344
    .line 345
    invoke-static {v1, v7}, Llp/pf;->c(Lss0/b;Lss0/e;)Z

    .line 346
    .line 347
    .line 348
    move-result v1

    .line 349
    iget-object v7, v0, Lru0/k0;->d:Lqd0/n;

    .line 350
    .line 351
    new-instance v8, Lqd0/m;

    .line 352
    .line 353
    const/4 v9, 0x1

    .line 354
    invoke-direct {v8, v9}, Lqd0/m;-><init>(Z)V

    .line 355
    .line 356
    .line 357
    invoke-virtual {v7, v8}, Lqd0/n;->a(Lqd0/m;)Lzy0/j;

    .line 358
    .line 359
    .line 360
    move-result-object v7

    .line 361
    if-eqz v5, :cond_6

    .line 362
    .line 363
    if-eqz v1, :cond_6

    .line 364
    .line 365
    invoke-virtual {v2}, Lqd0/l;->invoke()Ljava/lang/Object;

    .line 366
    .line 367
    .line 368
    move-result-object v1

    .line 369
    check-cast v1, Lyy0/i;

    .line 370
    .line 371
    goto :goto_6

    .line 372
    :cond_6
    sget-object v1, Lyy0/h;->d:Lyy0/h;

    .line 373
    .line 374
    :goto_6
    new-array v5, v6, [Lyy0/i;

    .line 375
    .line 376
    aput-object v7, v5, v16

    .line 377
    .line 378
    const/4 v7, 0x1

    .line 379
    aput-object v1, v5, v7

    .line 380
    .line 381
    invoke-static {v5}, Lyy0/u;->D([Lyy0/i;)Lyy0/e;

    .line 382
    .line 383
    .line 384
    move-result-object v1

    .line 385
    move v5, v12

    .line 386
    move v12, v10

    .line 387
    move v10, v5

    .line 388
    move-object v5, v3

    .line 389
    move-object v3, v13

    .line 390
    move-object v9, v14

    .line 391
    move-object v13, v1

    .line 392
    move-object v1, v15

    .line 393
    goto :goto_7

    .line 394
    :pswitch_a
    move/from16 v16, v7

    .line 395
    .line 396
    move v7, v8

    .line 397
    iget-object v8, v0, Lru0/k0;->h:Llz/e;

    .line 398
    .line 399
    new-instance v13, Llz/b;

    .line 400
    .line 401
    invoke-direct {v13, v7}, Llz/b;-><init>(Z)V

    .line 402
    .line 403
    .line 404
    invoke-virtual {v8, v13}, Llz/e;->a(Llz/b;)Lzy0/j;

    .line 405
    .line 406
    .line 407
    move-result-object v13

    .line 408
    goto :goto_7

    .line 409
    :pswitch_b
    move/from16 v16, v7

    .line 410
    .line 411
    move v7, v8

    .line 412
    iget-object v8, v0, Lru0/k0;->a:Lty/c;

    .line 413
    .line 414
    new-instance v13, Lty/b;

    .line 415
    .line 416
    invoke-direct {v13, v7}, Lty/b;-><init>(Z)V

    .line 417
    .line 418
    .line 419
    invoke-virtual {v8, v13}, Lty/c;->a(Lty/b;)Lzy0/j;

    .line 420
    .line 421
    .line 422
    move-result-object v13

    .line 423
    :goto_7
    if-eqz v13, :cond_7

    .line 424
    .line 425
    new-instance v8, Lru0/i0;

    .line 426
    .line 427
    move/from16 v14, v16

    .line 428
    .line 429
    const/4 v15, 0x0

    .line 430
    invoke-direct {v8, v13, v15, v14}, Lru0/i0;-><init>(Lyy0/i;Lkotlin/coroutines/Continuation;I)V

    .line 431
    .line 432
    .line 433
    const/4 v13, 0x3

    .line 434
    invoke-static {v1, v15, v8, v13}, Lvy0/e0;->g(Lvy0/b0;Lpx0/g;Lay0/n;I)Lvy0/i0;

    .line 435
    .line 436
    .line 437
    move-result-object v8

    .line 438
    goto :goto_8

    .line 439
    :cond_7
    move/from16 v14, v16

    .line 440
    .line 441
    const/4 v15, 0x0

    .line 442
    move-object v8, v15

    .line 443
    :goto_8
    if-eqz v8, :cond_8

    .line 444
    .line 445
    invoke-interface {v9, v8}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z

    .line 446
    .line 447
    .line 448
    :cond_8
    move v8, v7

    .line 449
    move v7, v14

    .line 450
    goto/16 :goto_1

    .line 451
    .line 452
    :cond_9
    check-cast v9, Ljava/util/List;

    .line 453
    .line 454
    return-object v9

    .line 455
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_4
        :pswitch_0
    .end packed-switch
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 3

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    check-cast v0, Ljava/util/List;

    .line 4
    .line 5
    new-instance v1, Lru0/j0;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    invoke-direct {v1, p0, v0, v2}, Lru0/j0;-><init>(Lru0/k0;Ljava/util/List;Lkotlin/coroutines/Continuation;)V

    .line 9
    .line 10
    .line 11
    new-instance p0, Lyy0/m1;

    .line 12
    .line 13
    invoke-direct {p0, v1}, Lyy0/m1;-><init>(Lay0/n;)V

    .line 14
    .line 15
    .line 16
    return-object p0
.end method
