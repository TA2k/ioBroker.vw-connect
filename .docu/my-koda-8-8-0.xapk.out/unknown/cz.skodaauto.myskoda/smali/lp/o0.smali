.class public abstract Llp/o0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lh7/a0;Landroid/content/Context;La7/n;Lh7/x;Lh7/p;Lrx0/c;)Ljava/lang/Object;
    .locals 19

    .line 1
    move-object/from16 v5, p0

    .line 2
    .line 3
    move-object/from16 v3, p1

    .line 4
    .line 5
    move-object/from16 v2, p2

    .line 6
    .line 7
    move-object/from16 v0, p5

    .line 8
    .line 9
    instance-of v1, v0, Lh7/r;

    .line 10
    .line 11
    if-eqz v1, :cond_0

    .line 12
    .line 13
    move-object v1, v0

    .line 14
    check-cast v1, Lh7/r;

    .line 15
    .line 16
    iget v4, v1, Lh7/r;->m:I

    .line 17
    .line 18
    const/high16 v6, -0x80000000

    .line 19
    .line 20
    and-int v7, v4, v6

    .line 21
    .line 22
    if-eqz v7, :cond_0

    .line 23
    .line 24
    sub-int/2addr v4, v6

    .line 25
    iput v4, v1, Lh7/r;->m:I

    .line 26
    .line 27
    :goto_0
    move-object v10, v1

    .line 28
    goto :goto_1

    .line 29
    :cond_0
    new-instance v1, Lh7/r;

    .line 30
    .line 31
    invoke-direct {v1, v0}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 32
    .line 33
    .line 34
    goto :goto_0

    .line 35
    :goto_1
    iget-object v0, v10, Lh7/r;->l:Ljava/lang/Object;

    .line 36
    .line 37
    sget-object v11, Lqx0/a;->d:Lqx0/a;

    .line 38
    .line 39
    iget v1, v10, Lh7/r;->m:I

    .line 40
    .line 41
    const/4 v12, 0x2

    .line 42
    const/4 v13, 0x1

    .line 43
    const/4 v14, 0x0

    .line 44
    if-eqz v1, :cond_3

    .line 45
    .line 46
    if-eq v1, v13, :cond_2

    .line 47
    .line 48
    if-ne v1, v12, :cond_1

    .line 49
    .line 50
    iget-object v1, v10, Lh7/r;->g:Ljava/lang/Object;

    .line 51
    .line 52
    check-cast v1, Ll2/w;

    .line 53
    .line 54
    iget-object v2, v10, Lh7/r;->f:Ljava/lang/Object;

    .line 55
    .line 56
    check-cast v2, Ll2/y1;

    .line 57
    .line 58
    iget-object v3, v10, Lh7/r;->e:Ljava/lang/Object;

    .line 59
    .line 60
    check-cast v3, Lvy0/i1;

    .line 61
    .line 62
    iget-object v4, v10, Lh7/r;->d:Ljava/lang/Object;

    .line 63
    .line 64
    check-cast v4, Lh7/f;

    .line 65
    .line 66
    :try_start_0
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 67
    .line 68
    .line 69
    goto/16 :goto_4

    .line 70
    .line 71
    :catchall_0
    move-exception v0

    .line 72
    goto/16 :goto_8

    .line 73
    .line 74
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 75
    .line 76
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 77
    .line 78
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 79
    .line 80
    .line 81
    throw v0

    .line 82
    :cond_2
    iget-object v1, v10, Lh7/r;->k:Ll2/a0;

    .line 83
    .line 84
    iget-object v2, v10, Lh7/r;->j:Ll2/y1;

    .line 85
    .line 86
    iget-object v3, v10, Lh7/r;->i:Lvy0/x1;

    .line 87
    .line 88
    iget-object v4, v10, Lh7/r;->h:Lh7/f;

    .line 89
    .line 90
    iget-object v5, v10, Lh7/r;->g:Ljava/lang/Object;

    .line 91
    .line 92
    check-cast v5, Lh7/x;

    .line 93
    .line 94
    iget-object v6, v10, Lh7/r;->f:Ljava/lang/Object;

    .line 95
    .line 96
    check-cast v6, La7/n;

    .line 97
    .line 98
    iget-object v7, v10, Lh7/r;->e:Ljava/lang/Object;

    .line 99
    .line 100
    check-cast v7, Landroid/content/Context;

    .line 101
    .line 102
    iget-object v8, v10, Lh7/r;->d:Ljava/lang/Object;

    .line 103
    .line 104
    check-cast v8, Lh7/a0;

    .line 105
    .line 106
    :try_start_1
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 107
    .line 108
    .line 109
    move-object v15, v4

    .line 110
    move-object v4, v2

    .line 111
    move-object v2, v6

    .line 112
    move-object v6, v3

    .line 113
    move-object v3, v7

    .line 114
    move-object v7, v5

    .line 115
    move-object v5, v8

    .line 116
    goto/16 :goto_2

    .line 117
    .line 118
    :cond_3
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 119
    .line 120
    .line 121
    new-instance v15, Lh7/f;

    .line 122
    .line 123
    invoke-direct {v15, v5}, Lh7/f;-><init>(Lh7/a0;)V

    .line 124
    .line 125
    .line 126
    new-instance v0, Lh7/u;

    .line 127
    .line 128
    const/4 v1, 0x0

    .line 129
    invoke-direct {v0, v12, v14, v1}, Lh7/u;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 130
    .line 131
    .line 132
    const/4 v7, 0x3

    .line 133
    invoke-static {v5, v14, v14, v0, v7}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 134
    .line 135
    .line 136
    move-result-object v8

    .line 137
    iget-object v0, v5, Lh7/a0;->d:Lvy0/b0;

    .line 138
    .line 139
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 140
    .line 141
    .line 142
    new-instance v9, La7/q1;

    .line 143
    .line 144
    const/16 v1, 0x32

    .line 145
    .line 146
    invoke-direct {v9, v1}, La7/q1;-><init>(I)V

    .line 147
    .line 148
    .line 149
    sget-object v1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 150
    .line 151
    invoke-static {v1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 152
    .line 153
    .line 154
    move-result-object v16

    .line 155
    new-instance v1, Lh7/q;

    .line 156
    .line 157
    invoke-direct {v1, v5, v2, v3}, Lh7/q;-><init>(Lh7/a0;La7/n;Landroid/content/Context;)V

    .line 158
    .line 159
    .line 160
    invoke-virtual/range {p4 .. p4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 161
    .line 162
    .line 163
    invoke-static {}, Lvy0/e0;->d()Lvy0/k1;

    .line 164
    .line 165
    .line 166
    move-result-object v4

    .line 167
    invoke-interface {v0}, Lvy0/b0;->getCoroutineContext()Lpx0/g;

    .line 168
    .line 169
    .line 170
    move-result-object v6

    .line 171
    sget-object v7, Lvy0/h1;->d:Lvy0/h1;

    .line 172
    .line 173
    invoke-interface {v6, v7}, Lpx0/g;->get(Lpx0/f;)Lpx0/e;

    .line 174
    .line 175
    .line 176
    move-result-object v6

    .line 177
    check-cast v6, Lvy0/i1;

    .line 178
    .line 179
    if-eqz v6, :cond_4

    .line 180
    .line 181
    new-instance v7, La3/f;

    .line 182
    .line 183
    const/16 v13, 0x11

    .line 184
    .line 185
    invoke-direct {v7, v4, v13}, La3/f;-><init>(Ljava/lang/Object;I)V

    .line 186
    .line 187
    .line 188
    invoke-interface {v6, v7}, Lvy0/i1;->E(Lay0/k;)Lvy0/r0;

    .line 189
    .line 190
    .line 191
    :cond_4
    invoke-interface {v0}, Lvy0/b0;->getCoroutineContext()Lpx0/g;

    .line 192
    .line 193
    .line 194
    move-result-object v0

    .line 195
    invoke-interface {v0, v4}, Lpx0/g;->plus(Lpx0/g;)Lpx0/g;

    .line 196
    .line 197
    .line 198
    move-result-object v0

    .line 199
    invoke-interface {v0, v1}, Lpx0/g;->plus(Lpx0/g;)Lpx0/g;

    .line 200
    .line 201
    .line 202
    move-result-object v0

    .line 203
    new-instance v1, Ll2/y1;

    .line 204
    .line 205
    invoke-direct {v1, v0}, Ll2/y1;-><init>(Lpx0/g;)V

    .line 206
    .line 207
    .line 208
    new-instance v0, Ly6/b;

    .line 209
    .line 210
    invoke-direct {v0, v9}, Leb/j0;-><init>(Ljava/lang/Object;)V

    .line 211
    .line 212
    .line 213
    new-instance v4, Ll2/a0;

    .line 214
    .line 215
    invoke-direct {v4, v1, v0}, Ll2/a0;-><init>(Ll2/x;Leb/j0;)V

    .line 216
    .line 217
    .line 218
    :try_start_2
    new-instance v0, La7/k0;
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_6

    .line 219
    .line 220
    const/4 v6, 0x0

    .line 221
    move-object/from16 v18, v4

    .line 222
    .line 223
    move-object v4, v1

    .line 224
    move-object/from16 v1, v18

    .line 225
    .line 226
    :try_start_3
    invoke-direct/range {v0 .. v6}, La7/k0;-><init>(Ll2/a0;La7/n;Landroid/content/Context;Ll2/y1;Lh7/a0;Lkotlin/coroutines/Continuation;)V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_5

    .line 227
    .line 228
    .line 229
    move-object v13, v1

    .line 230
    move-object v1, v4

    .line 231
    :try_start_4
    invoke-static {v5, v15, v14, v0, v12}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 232
    .line 233
    .line 234
    new-instance v0, Lg1/y0;
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_4

    .line 235
    .line 236
    move-object v2, v8

    .line 237
    const/4 v8, 0x0

    .line 238
    move-object v5, v9

    .line 239
    const/4 v9, 0x1

    .line 240
    move-object/from16 v6, p0

    .line 241
    .line 242
    move-object/from16 v4, p1

    .line 243
    .line 244
    move-object/from16 v7, p3

    .line 245
    .line 246
    move-object/from16 v17, v2

    .line 247
    .line 248
    move-object/from16 v3, v16

    .line 249
    .line 250
    const/4 v12, 0x3

    .line 251
    move-object/from16 v2, p2

    .line 252
    .line 253
    :try_start_5
    invoke-direct/range {v0 .. v9}, Lg1/y0;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 254
    .line 255
    .line 256
    move-object v5, v4

    .line 257
    move-object v4, v0

    .line 258
    move-object v0, v3

    .line 259
    move-object v3, v5

    .line 260
    move-object v5, v6

    .line 261
    invoke-static {v5, v14, v14, v4, v12}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 262
    .line 263
    .line 264
    new-instance v4, Lh7/t;

    .line 265
    .line 266
    const/4 v6, 0x2

    .line 267
    invoke-direct {v4, v6, v14}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 268
    .line 269
    .line 270
    iput-object v5, v10, Lh7/r;->d:Ljava/lang/Object;

    .line 271
    .line 272
    iput-object v3, v10, Lh7/r;->e:Ljava/lang/Object;

    .line 273
    .line 274
    iput-object v2, v10, Lh7/r;->f:Ljava/lang/Object;

    .line 275
    .line 276
    move-object/from16 v7, p3

    .line 277
    .line 278
    iput-object v7, v10, Lh7/r;->g:Ljava/lang/Object;

    .line 279
    .line 280
    iput-object v15, v10, Lh7/r;->h:Lh7/f;
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_3

    .line 281
    .line 282
    move-object/from16 v6, v17

    .line 283
    .line 284
    :try_start_6
    iput-object v6, v10, Lh7/r;->i:Lvy0/x1;

    .line 285
    .line 286
    iput-object v1, v10, Lh7/r;->j:Ll2/y1;

    .line 287
    .line 288
    iput-object v13, v10, Lh7/r;->k:Ll2/a0;

    .line 289
    .line 290
    const/4 v8, 0x1

    .line 291
    iput v8, v10, Lh7/r;->m:I

    .line 292
    .line 293
    invoke-static {v0, v4, v10}, Lyy0/u;->t(Lyy0/i;Lay0/n;Lrx0/c;)Ljava/lang/Object;

    .line 294
    .line 295
    .line 296
    move-result-object v0
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_2

    .line 297
    if-ne v0, v11, :cond_5

    .line 298
    .line 299
    goto :goto_3

    .line 300
    :cond_5
    move-object v4, v1

    .line 301
    move-object v1, v13

    .line 302
    :goto_2
    :try_start_7
    new-instance v0, La3/g;

    .line 303
    .line 304
    const/4 v8, 0x5

    .line 305
    invoke-direct {v0, v5, v7, v15, v8}, La3/g;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 306
    .line 307
    .line 308
    iput-object v15, v10, Lh7/r;->d:Ljava/lang/Object;

    .line 309
    .line 310
    iput-object v6, v10, Lh7/r;->e:Ljava/lang/Object;

    .line 311
    .line 312
    iput-object v4, v10, Lh7/r;->f:Ljava/lang/Object;

    .line 313
    .line 314
    iput-object v1, v10, Lh7/r;->g:Ljava/lang/Object;

    .line 315
    .line 316
    iput-object v14, v10, Lh7/r;->h:Lh7/f;

    .line 317
    .line 318
    iput-object v14, v10, Lh7/r;->i:Lvy0/x1;

    .line 319
    .line 320
    iput-object v14, v10, Lh7/r;->j:Ll2/y1;

    .line 321
    .line 322
    iput-object v14, v10, Lh7/r;->k:Ll2/a0;

    .line 323
    .line 324
    const/4 v5, 0x2

    .line 325
    iput v5, v10, Lh7/r;->m:I

    .line 326
    .line 327
    invoke-virtual {v2, v3, v0, v10}, La7/n;->d(Landroid/content/Context;La3/g;Lrx0/c;)Ljava/lang/Object;

    .line 328
    .line 329
    .line 330
    move-result-object v0
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_1

    .line 331
    if-ne v0, v11, :cond_6

    .line 332
    .line 333
    :goto_3
    return-object v11

    .line 334
    :cond_6
    move-object v2, v4

    .line 335
    move-object v3, v6

    .line 336
    move-object v4, v15

    .line 337
    :goto_4
    invoke-interface {v1}, Ll2/w;->dispose()V

    .line 338
    .line 339
    .line 340
    invoke-virtual {v4}, Lh7/f;->c()V

    .line 341
    .line 342
    .line 343
    invoke-interface {v3, v14}, Lvy0/i1;->d(Ljava/util/concurrent/CancellationException;)V

    .line 344
    .line 345
    .line 346
    invoke-virtual {v2}, Ll2/y1;->v()V

    .line 347
    .line 348
    .line 349
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 350
    .line 351
    return-object v0

    .line 352
    :catchall_1
    move-exception v0

    .line 353
    move-object v2, v4

    .line 354
    move-object v3, v6

    .line 355
    :goto_5
    move-object v4, v15

    .line 356
    goto :goto_8

    .line 357
    :catchall_2
    move-exception v0

    .line 358
    :goto_6
    move-object v2, v1

    .line 359
    move-object v3, v6

    .line 360
    move-object v1, v13

    .line 361
    goto :goto_5

    .line 362
    :catchall_3
    move-exception v0

    .line 363
    move-object/from16 v6, v17

    .line 364
    .line 365
    goto :goto_6

    .line 366
    :catchall_4
    move-exception v0

    .line 367
    :goto_7
    move-object v6, v8

    .line 368
    goto :goto_6

    .line 369
    :catchall_5
    move-exception v0

    .line 370
    move-object v13, v1

    .line 371
    move-object v1, v4

    .line 372
    goto :goto_7

    .line 373
    :catchall_6
    move-exception v0

    .line 374
    move-object v13, v4

    .line 375
    goto :goto_7

    .line 376
    :goto_8
    invoke-interface {v1}, Ll2/w;->dispose()V

    .line 377
    .line 378
    .line 379
    invoke-virtual {v4}, Lh7/f;->c()V

    .line 380
    .line 381
    .line 382
    invoke-interface {v3, v14}, Lvy0/i1;->d(Ljava/util/concurrent/CancellationException;)V

    .line 383
    .line 384
    .line 385
    invoke-virtual {v2}, Ll2/y1;->v()V

    .line 386
    .line 387
    .line 388
    throw v0
.end method

.method public static final b(III)I
    .locals 1

    .line 1
    if-lez p2, :cond_4

    .line 2
    .line 3
    if-lt p0, p1, :cond_0

    .line 4
    .line 5
    goto :goto_3

    .line 6
    :cond_0
    rem-int v0, p1, p2

    .line 7
    .line 8
    if-ltz v0, :cond_1

    .line 9
    .line 10
    goto :goto_0

    .line 11
    :cond_1
    add-int/2addr v0, p2

    .line 12
    :goto_0
    rem-int/2addr p0, p2

    .line 13
    if-ltz p0, :cond_2

    .line 14
    .line 15
    goto :goto_1

    .line 16
    :cond_2
    add-int/2addr p0, p2

    .line 17
    :goto_1
    sub-int/2addr v0, p0

    .line 18
    rem-int/2addr v0, p2

    .line 19
    if-ltz v0, :cond_3

    .line 20
    .line 21
    goto :goto_2

    .line 22
    :cond_3
    add-int/2addr v0, p2

    .line 23
    :goto_2
    sub-int/2addr p1, v0

    .line 24
    return p1

    .line 25
    :cond_4
    if-gez p2, :cond_9

    .line 26
    .line 27
    if-gt p0, p1, :cond_5

    .line 28
    .line 29
    :goto_3
    return p1

    .line 30
    :cond_5
    neg-int p2, p2

    .line 31
    rem-int/2addr p0, p2

    .line 32
    if-ltz p0, :cond_6

    .line 33
    .line 34
    goto :goto_4

    .line 35
    :cond_6
    add-int/2addr p0, p2

    .line 36
    :goto_4
    rem-int v0, p1, p2

    .line 37
    .line 38
    if-ltz v0, :cond_7

    .line 39
    .line 40
    goto :goto_5

    .line 41
    :cond_7
    add-int/2addr v0, p2

    .line 42
    :goto_5
    sub-int/2addr p0, v0

    .line 43
    rem-int/2addr p0, p2

    .line 44
    if-ltz p0, :cond_8

    .line 45
    .line 46
    goto :goto_6

    .line 47
    :cond_8
    add-int/2addr p0, p2

    .line 48
    :goto_6
    add-int/2addr p0, p1

    .line 49
    return p0

    .line 50
    :cond_9
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 51
    .line 52
    const-string p1, "Step is zero."

    .line 53
    .line 54
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    throw p0
.end method
