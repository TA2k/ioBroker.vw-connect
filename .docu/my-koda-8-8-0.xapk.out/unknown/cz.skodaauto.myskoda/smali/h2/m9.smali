.class public final Lh2/m9;
.super Lrx0/h;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public e:Ljava/lang/Object;

.field public f:Li1/b;

.field public g:Lkotlin/jvm/internal/c0;

.field public h:Lkotlin/jvm/internal/b0;

.field public i:I

.field public synthetic j:Ljava/lang/Object;

.field public final synthetic k:Lh2/u7;

.field public final synthetic l:Lgw0/c;

.field public final synthetic m:Lvy0/b0;


# direct methods
.method public constructor <init>(Lh2/u7;Lgw0/c;Lvy0/b0;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lh2/m9;->k:Lh2/u7;

    .line 2
    .line 3
    iput-object p2, p0, Lh2/m9;->l:Lgw0/c;

    .line 4
    .line 5
    iput-object p3, p0, Lh2/m9;->m:Lvy0/b0;

    .line 6
    .line 7
    const/4 p1, 0x2

    .line 8
    invoke-direct {p0, p1, p4}, Lrx0/h;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 3

    .line 1
    new-instance v0, Lh2/m9;

    .line 2
    .line 3
    iget-object v1, p0, Lh2/m9;->l:Lgw0/c;

    .line 4
    .line 5
    iget-object v2, p0, Lh2/m9;->m:Lvy0/b0;

    .line 6
    .line 7
    iget-object p0, p0, Lh2/m9;->k:Lh2/u7;

    .line 8
    .line 9
    invoke-direct {v0, p0, v1, v2, p2}, Lh2/m9;-><init>(Lh2/u7;Lgw0/c;Lvy0/b0;Lkotlin/coroutines/Continuation;)V

    .line 10
    .line 11
    .line 12
    iput-object p1, v0, Lh2/m9;->j:Ljava/lang/Object;

    .line 13
    .line 14
    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lp3/i0;

    .line 2
    .line 3
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    invoke-virtual {p0, p1, p2}, Lh2/m9;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Lh2/m9;

    .line 10
    .line 11
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 12
    .line 13
    invoke-virtual {p0, p1}, Lh2/m9;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 20

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v2, v0, Lh2/m9;->l:Lgw0/c;

    .line 4
    .line 5
    iget-object v1, v2, Lgw0/c;->e:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v1, Lh2/u7;

    .line 8
    .line 9
    iget-object v7, v0, Lh2/m9;->k:Lh2/u7;

    .line 10
    .line 11
    iget-object v3, v7, Lh2/u7;->m:Ll2/f1;

    .line 12
    .line 13
    iget-object v4, v7, Lh2/u7;->p:Ll2/j1;

    .line 14
    .line 15
    iget-object v8, v7, Lh2/u7;->o:Ll2/j1;

    .line 16
    .line 17
    sget-object v9, Lqx0/a;->d:Lqx0/a;

    .line 18
    .line 19
    iget v5, v0, Lh2/m9;->i:I

    .line 20
    .line 21
    iget-object v10, v0, Lh2/m9;->m:Lvy0/b0;

    .line 22
    .line 23
    const/4 v11, 0x3

    .line 24
    const/4 v6, 0x2

    .line 25
    const/4 v14, 0x1

    .line 26
    if-eqz v5, :cond_4

    .line 27
    .line 28
    if-eq v5, v14, :cond_2

    .line 29
    .line 30
    if-eq v5, v6, :cond_1

    .line 31
    .line 32
    if-ne v5, v11, :cond_0

    .line 33
    .line 34
    iget-object v1, v0, Lh2/m9;->e:Ljava/lang/Object;

    .line 35
    .line 36
    check-cast v1, Lkotlin/jvm/internal/b0;

    .line 37
    .line 38
    iget-object v0, v0, Lh2/m9;->j:Ljava/lang/Object;

    .line 39
    .line 40
    check-cast v0, Li1/b;

    .line 41
    .line 42
    :try_start_0
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catch Ljava/util/concurrent/CancellationException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 43
    .line 44
    .line 45
    move-object v4, v0

    .line 46
    move-object v14, v7

    .line 47
    const/4 v5, 0x0

    .line 48
    move-object/from16 v0, p1

    .line 49
    .line 50
    move-object v7, v2

    .line 51
    goto/16 :goto_c

    .line 52
    .line 53
    :catchall_0
    move-exception v0

    .line 54
    goto/16 :goto_11

    .line 55
    .line 56
    :catch_0
    move-object v14, v7

    .line 57
    const/4 v5, 0x0

    .line 58
    move-object v7, v2

    .line 59
    goto/16 :goto_f

    .line 60
    .line 61
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 62
    .line 63
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 64
    .line 65
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 66
    .line 67
    .line 68
    throw v0

    .line 69
    :cond_1
    iget-object v5, v0, Lh2/m9;->h:Lkotlin/jvm/internal/b0;

    .line 70
    .line 71
    const/16 v16, 0x20

    .line 72
    .line 73
    iget-object v12, v0, Lh2/m9;->g:Lkotlin/jvm/internal/c0;

    .line 74
    .line 75
    iget-object v13, v0, Lh2/m9;->f:Li1/b;

    .line 76
    .line 77
    iget-object v11, v0, Lh2/m9;->e:Ljava/lang/Object;

    .line 78
    .line 79
    check-cast v11, Lp3/t;

    .line 80
    .line 81
    iget-object v15, v0, Lh2/m9;->j:Ljava/lang/Object;

    .line 82
    .line 83
    check-cast v15, Lp3/i0;

    .line 84
    .line 85
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 86
    .line 87
    .line 88
    move-object/from16 v18, v5

    .line 89
    .line 90
    move-object v5, v3

    .line 91
    move-object v3, v12

    .line 92
    move-object v12, v11

    .line 93
    move-object/from16 v11, v18

    .line 94
    .line 95
    move-object/from16 v19, v4

    .line 96
    .line 97
    move v4, v6

    .line 98
    move-object/from16 v18, v7

    .line 99
    .line 100
    move-object v7, v2

    .line 101
    move-object/from16 v2, p1

    .line 102
    .line 103
    goto/16 :goto_4

    .line 104
    .line 105
    :cond_2
    const/16 v16, 0x20

    .line 106
    .line 107
    iget-object v5, v0, Lh2/m9;->j:Ljava/lang/Object;

    .line 108
    .line 109
    check-cast v5, Lp3/i0;

    .line 110
    .line 111
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 112
    .line 113
    .line 114
    move-object/from16 v11, p1

    .line 115
    .line 116
    :cond_3
    move-object v15, v5

    .line 117
    goto :goto_0

    .line 118
    :cond_4
    const/16 v16, 0x20

    .line 119
    .line 120
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 121
    .line 122
    .line 123
    iget-object v5, v0, Lh2/m9;->j:Ljava/lang/Object;

    .line 124
    .line 125
    check-cast v5, Lp3/i0;

    .line 126
    .line 127
    iput-object v5, v0, Lh2/m9;->j:Ljava/lang/Object;

    .line 128
    .line 129
    iput v14, v0, Lh2/m9;->i:I

    .line 130
    .line 131
    invoke-static {v5, v0, v6}, Lg1/g3;->c(Lp3/i0;Lkotlin/coroutines/Continuation;I)Ljava/lang/Object;

    .line 132
    .line 133
    .line 134
    move-result-object v11

    .line 135
    if-ne v11, v9, :cond_3

    .line 136
    .line 137
    goto/16 :goto_b

    .line 138
    .line 139
    :goto_0
    check-cast v11, Lp3/t;

    .line 140
    .line 141
    new-instance v13, Li1/b;

    .line 142
    .line 143
    invoke-direct {v13}, Ljava/lang/Object;-><init>()V

    .line 144
    .line 145
    .line 146
    new-instance v12, Lkotlin/jvm/internal/c0;

    .line 147
    .line 148
    invoke-direct {v12}, Ljava/lang/Object;-><init>()V

    .line 149
    .line 150
    .line 151
    invoke-virtual {v4}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 152
    .line 153
    .line 154
    move-result-object v5

    .line 155
    check-cast v5, Ljava/lang/Boolean;

    .line 156
    .line 157
    invoke-virtual {v5}, Ljava/lang/Boolean;->booleanValue()Z

    .line 158
    .line 159
    .line 160
    move-result v5

    .line 161
    if-eqz v5, :cond_5

    .line 162
    .line 163
    iget-object v5, v7, Lh2/u7;->l:Ll2/g1;

    .line 164
    .line 165
    invoke-virtual {v5}, Ll2/g1;->o()I

    .line 166
    .line 167
    .line 168
    move-result v5

    .line 169
    int-to-float v5, v5

    .line 170
    move-object/from16 v18, v7

    .line 171
    .line 172
    iget-wide v6, v11, Lp3/t;->c:J

    .line 173
    .line 174
    shr-long v6, v6, v16

    .line 175
    .line 176
    long-to-int v6, v6

    .line 177
    invoke-static {v6}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 178
    .line 179
    .line 180
    move-result v6

    .line 181
    sub-float/2addr v5, v6

    .line 182
    goto :goto_1

    .line 183
    :cond_5
    move-object/from16 v18, v7

    .line 184
    .line 185
    iget-wide v5, v11, Lp3/t;->c:J

    .line 186
    .line 187
    shr-long v5, v5, v16

    .line 188
    .line 189
    long-to-int v5, v5

    .line 190
    invoke-static {v5}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 191
    .line 192
    .line 193
    move-result v5

    .line 194
    :goto_1
    iput v5, v12, Lkotlin/jvm/internal/c0;->d:F

    .line 195
    .line 196
    iget-object v6, v1, Lh2/u7;->m:Ll2/f1;

    .line 197
    .line 198
    invoke-virtual {v6}, Ll2/f1;->o()F

    .line 199
    .line 200
    .line 201
    move-result v6

    .line 202
    sub-float/2addr v6, v5

    .line 203
    invoke-static {v6}, Ljava/lang/Math;->abs(F)F

    .line 204
    .line 205
    .line 206
    move-result v6

    .line 207
    iget-object v7, v1, Lh2/u7;->n:Ll2/f1;

    .line 208
    .line 209
    invoke-virtual {v7}, Ll2/f1;->o()F

    .line 210
    .line 211
    .line 212
    move-result v7

    .line 213
    sub-float/2addr v7, v5

    .line 214
    invoke-static {v7}, Ljava/lang/Math;->abs(F)F

    .line 215
    .line 216
    .line 217
    move-result v5

    .line 218
    invoke-static {v6, v5}, Ljava/lang/Float;->compare(FF)I

    .line 219
    .line 220
    .line 221
    move-result v5

    .line 222
    new-instance v6, Lkotlin/jvm/internal/b0;

    .line 223
    .line 224
    invoke-direct {v6}, Ljava/lang/Object;-><init>()V

    .line 225
    .line 226
    .line 227
    if-eqz v5, :cond_7

    .line 228
    .line 229
    if-gez v5, :cond_6

    .line 230
    .line 231
    :goto_2
    move v5, v14

    .line 232
    goto :goto_3

    .line 233
    :cond_6
    const/4 v5, 0x0

    .line 234
    goto :goto_3

    .line 235
    :cond_7
    invoke-virtual {v3}, Ll2/f1;->o()F

    .line 236
    .line 237
    .line 238
    move-result v5

    .line 239
    iget v7, v12, Lkotlin/jvm/internal/c0;->d:F

    .line 240
    .line 241
    cmpl-float v5, v5, v7

    .line 242
    .line 243
    if-lez v5, :cond_6

    .line 244
    .line 245
    goto :goto_2

    .line 246
    :goto_3
    iput-boolean v5, v6, Lkotlin/jvm/internal/b0;->d:Z

    .line 247
    .line 248
    move-object v7, v2

    .line 249
    move-object v5, v3

    .line 250
    iget-wide v2, v11, Lp3/t;->a:J

    .line 251
    .line 252
    iget v14, v11, Lp3/t;->i:I

    .line 253
    .line 254
    iput-object v15, v0, Lh2/m9;->j:Ljava/lang/Object;

    .line 255
    .line 256
    iput-object v11, v0, Lh2/m9;->e:Ljava/lang/Object;

    .line 257
    .line 258
    iput-object v13, v0, Lh2/m9;->f:Li1/b;

    .line 259
    .line 260
    iput-object v12, v0, Lh2/m9;->g:Lkotlin/jvm/internal/c0;

    .line 261
    .line 262
    iput-object v6, v0, Lh2/m9;->h:Lkotlin/jvm/internal/b0;

    .line 263
    .line 264
    move-object/from16 v19, v4

    .line 265
    .line 266
    const/4 v4, 0x2

    .line 267
    iput v4, v0, Lh2/m9;->i:I

    .line 268
    .line 269
    invoke-static {v15, v2, v3, v14, v0}, Lh2/q9;->h(Lp3/i0;JILrx0/a;)Ljava/io/Serializable;

    .line 270
    .line 271
    .line 272
    move-result-object v2

    .line 273
    if-ne v2, v9, :cond_8

    .line 274
    .line 275
    goto/16 :goto_b

    .line 276
    .line 277
    :cond_8
    move-object v3, v12

    .line 278
    move-object v12, v11

    .line 279
    move-object v11, v6

    .line 280
    :goto_4
    check-cast v2, Llx0/l;

    .line 281
    .line 282
    if-eqz v2, :cond_c

    .line 283
    .line 284
    invoke-virtual {v15}, Lp3/i0;->f()Lw3/h2;

    .line 285
    .line 286
    .line 287
    move-result-object v6

    .line 288
    iget v14, v12, Lp3/t;->i:I

    .line 289
    .line 290
    sget v17, Li2/h0;->a:F

    .line 291
    .line 292
    if-ne v14, v4, :cond_9

    .line 293
    .line 294
    invoke-interface {v6}, Lw3/h2;->f()F

    .line 295
    .line 296
    .line 297
    move-result v4

    .line 298
    sget v6, Li2/h0;->a:F

    .line 299
    .line 300
    mul-float/2addr v4, v6

    .line 301
    :goto_5
    move-object/from16 v14, v18

    .line 302
    .line 303
    goto :goto_6

    .line 304
    :cond_9
    invoke-interface {v6}, Lw3/h2;->f()F

    .line 305
    .line 306
    .line 307
    move-result v4

    .line 308
    goto :goto_5

    .line 309
    :goto_6
    iget-object v6, v14, Lh2/u7;->n:Ll2/f1;

    .line 310
    .line 311
    invoke-virtual {v6}, Ll2/f1;->o()F

    .line 312
    .line 313
    .line 314
    move-result v6

    .line 315
    move/from16 p1, v4

    .line 316
    .line 317
    iget v4, v3, Lkotlin/jvm/internal/c0;->d:F

    .line 318
    .line 319
    sub-float/2addr v6, v4

    .line 320
    invoke-static {v6}, Ljava/lang/Math;->abs(F)F

    .line 321
    .line 322
    .line 323
    move-result v4

    .line 324
    cmpg-float v4, v4, p1

    .line 325
    .line 326
    if-gez v4, :cond_d

    .line 327
    .line 328
    invoke-virtual {v5}, Ll2/f1;->o()F

    .line 329
    .line 330
    .line 331
    move-result v4

    .line 332
    iget v5, v3, Lkotlin/jvm/internal/c0;->d:F

    .line 333
    .line 334
    sub-float/2addr v4, v5

    .line 335
    invoke-static {v4}, Ljava/lang/Math;->abs(F)F

    .line 336
    .line 337
    .line 338
    move-result v4

    .line 339
    cmpg-float v4, v4, p1

    .line 340
    .line 341
    if-gez v4, :cond_d

    .line 342
    .line 343
    iget-object v4, v2, Llx0/l;->e:Ljava/lang/Object;

    .line 344
    .line 345
    check-cast v4, Ljava/lang/Number;

    .line 346
    .line 347
    invoke-virtual {v4}, Ljava/lang/Number;->floatValue()F

    .line 348
    .line 349
    .line 350
    move-result v4

    .line 351
    invoke-virtual/range {v19 .. v19}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 352
    .line 353
    .line 354
    move-result-object v5

    .line 355
    check-cast v5, Ljava/lang/Boolean;

    .line 356
    .line 357
    invoke-virtual {v5}, Ljava/lang/Boolean;->booleanValue()Z

    .line 358
    .line 359
    .line 360
    move-result v5

    .line 361
    const/4 v6, 0x0

    .line 362
    if-eqz v5, :cond_b

    .line 363
    .line 364
    cmpl-float v4, v4, v6

    .line 365
    .line 366
    if-ltz v4, :cond_a

    .line 367
    .line 368
    :goto_7
    const/4 v4, 0x1

    .line 369
    goto :goto_8

    .line 370
    :cond_a
    const/4 v4, 0x0

    .line 371
    goto :goto_8

    .line 372
    :cond_b
    cmpg-float v4, v4, v6

    .line 373
    .line 374
    if-gez v4, :cond_a

    .line 375
    .line 376
    goto :goto_7

    .line 377
    :goto_8
    iput-boolean v4, v11, Lkotlin/jvm/internal/b0;->d:Z

    .line 378
    .line 379
    iget v4, v3, Lkotlin/jvm/internal/c0;->d:F

    .line 380
    .line 381
    iget-object v2, v2, Llx0/l;->d:Ljava/lang/Object;

    .line 382
    .line 383
    check-cast v2, Lp3/t;

    .line 384
    .line 385
    const/4 v5, 0x0

    .line 386
    invoke-static {v2, v5}, Lp3/s;->h(Lp3/t;Z)J

    .line 387
    .line 388
    .line 389
    move-result-wide v5

    .line 390
    shr-long v5, v5, v16

    .line 391
    .line 392
    long-to-int v2, v5

    .line 393
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 394
    .line 395
    .line 396
    move-result v2

    .line 397
    add-float/2addr v2, v4

    .line 398
    iput v2, v3, Lkotlin/jvm/internal/c0;->d:F

    .line 399
    .line 400
    goto :goto_9

    .line 401
    :cond_c
    move-object/from16 v14, v18

    .line 402
    .line 403
    :cond_d
    :goto_9
    iget-boolean v2, v11, Lkotlin/jvm/internal/b0;->d:Z

    .line 404
    .line 405
    iget v3, v3, Lkotlin/jvm/internal/c0;->d:F

    .line 406
    .line 407
    if-eqz v2, :cond_e

    .line 408
    .line 409
    iget-object v4, v1, Lh2/u7;->m:Ll2/f1;

    .line 410
    .line 411
    invoke-virtual {v4}, Ll2/f1;->o()F

    .line 412
    .line 413
    .line 414
    move-result v4

    .line 415
    goto :goto_a

    .line 416
    :cond_e
    iget-object v4, v1, Lh2/u7;->n:Ll2/f1;

    .line 417
    .line 418
    invoke-virtual {v4}, Ll2/f1;->o()F

    .line 419
    .line 420
    .line 421
    move-result v4

    .line 422
    :goto_a
    sub-float/2addr v3, v4

    .line 423
    invoke-virtual {v1, v3, v2}, Lh2/u7;->e(FZ)V

    .line 424
    .line 425
    .line 426
    new-instance v1, Lbp0/g;

    .line 427
    .line 428
    const/4 v6, 0x3

    .line 429
    move v3, v2

    .line 430
    move-object v2, v7

    .line 431
    move-object v4, v13

    .line 432
    const/4 v5, 0x0

    .line 433
    invoke-direct/range {v1 .. v6}, Lbp0/g;-><init>(Ljava/lang/Object;ZLjava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 434
    .line 435
    .line 436
    const/4 v2, 0x3

    .line 437
    invoke-static {v10, v5, v5, v1, v2}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 438
    .line 439
    .line 440
    :try_start_1
    sget-object v1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 441
    .line 442
    invoke-virtual {v8, v1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 443
    .line 444
    .line 445
    iget-wide v1, v12, Lp3/t;->a:J

    .line 446
    .line 447
    new-instance v3, Let/g;

    .line 448
    .line 449
    const/16 v6, 0x16

    .line 450
    .line 451
    invoke-direct {v3, v6, v14, v11}, Let/g;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 452
    .line 453
    .line 454
    iput-object v4, v0, Lh2/m9;->j:Ljava/lang/Object;

    .line 455
    .line 456
    iput-object v11, v0, Lh2/m9;->e:Ljava/lang/Object;

    .line 457
    .line 458
    iput-object v5, v0, Lh2/m9;->f:Li1/b;

    .line 459
    .line 460
    iput-object v5, v0, Lh2/m9;->g:Lkotlin/jvm/internal/c0;

    .line 461
    .line 462
    iput-object v5, v0, Lh2/m9;->h:Lkotlin/jvm/internal/b0;

    .line 463
    .line 464
    const/4 v6, 0x3

    .line 465
    iput v6, v0, Lh2/m9;->i:I

    .line 466
    .line 467
    invoke-static {v15, v1, v2, v3, v0}, Lg1/w0;->f(Lp3/i0;JLay0/k;Lrx0/a;)Ljava/lang/Object;

    .line 468
    .line 469
    .line 470
    move-result-object v0
    :try_end_1
    .catch Ljava/util/concurrent/CancellationException; {:try_start_1 .. :try_end_1} :catch_2
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 471
    if-ne v0, v9, :cond_f

    .line 472
    .line 473
    :goto_b
    return-object v9

    .line 474
    :cond_f
    move-object v1, v11

    .line 475
    :goto_c
    :try_start_2
    check-cast v0, Ljava/lang/Boolean;

    .line 476
    .line 477
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 478
    .line 479
    .line 480
    move-result v0

    .line 481
    if-eqz v0, :cond_10

    .line 482
    .line 483
    new-instance v0, Li1/c;

    .line 484
    .line 485
    invoke-direct {v0, v4}, Li1/c;-><init>(Li1/b;)V

    .line 486
    .line 487
    .line 488
    goto :goto_d

    .line 489
    :catch_1
    move-object v0, v4

    .line 490
    goto :goto_f

    .line 491
    :cond_10
    new-instance v0, Li1/a;

    .line 492
    .line 493
    invoke-direct {v0, v4}, Li1/a;-><init>(Li1/b;)V
    :try_end_2
    .catch Ljava/util/concurrent/CancellationException; {:try_start_2 .. :try_end_2} :catch_1
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 494
    .line 495
    .line 496
    :goto_d
    sget-object v2, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 497
    .line 498
    invoke-virtual {v8, v2}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 499
    .line 500
    .line 501
    move-object v4, v0

    .line 502
    :goto_e
    move-object v3, v1

    .line 503
    goto :goto_10

    .line 504
    :catch_2
    move-object v0, v4

    .line 505
    move-object v1, v11

    .line 506
    :goto_f
    :try_start_3
    new-instance v2, Li1/a;

    .line 507
    .line 508
    invoke-direct {v2, v0}, Li1/a;-><init>(Li1/b;)V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 509
    .line 510
    .line 511
    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 512
    .line 513
    invoke-virtual {v8, v0}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 514
    .line 515
    .line 516
    move-object v4, v2

    .line 517
    goto :goto_e

    .line 518
    :goto_10
    iget-object v0, v14, Lh2/u7;->q:Lh2/t7;

    .line 519
    .line 520
    iget-boolean v1, v3, Lkotlin/jvm/internal/b0;->d:Z

    .line 521
    .line 522
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 523
    .line 524
    .line 525
    move-result-object v1

    .line 526
    invoke-virtual {v0, v1}, Lh2/t7;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 527
    .line 528
    .line 529
    new-instance v0, Lg1/y2;

    .line 530
    .line 531
    const/4 v1, 0x5

    .line 532
    move-object v2, v7

    .line 533
    invoke-direct/range {v0 .. v5}, Lg1/y2;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 534
    .line 535
    .line 536
    const/4 v2, 0x3

    .line 537
    invoke-static {v10, v5, v5, v0, v2}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 538
    .line 539
    .line 540
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 541
    .line 542
    return-object v0

    .line 543
    :goto_11
    sget-object v1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 544
    .line 545
    invoke-virtual {v8, v1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 546
    .line 547
    .line 548
    throw v0
.end method
