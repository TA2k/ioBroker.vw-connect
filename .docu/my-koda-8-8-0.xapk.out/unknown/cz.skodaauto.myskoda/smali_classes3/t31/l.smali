.class public final Lt31/l;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public d:Lvy0/h0;

.field public e:Lvy0/h0;

.field public f:Lvy0/h0;

.field public g:Lyy0/j1;

.field public h:Ljava/lang/Object;

.field public i:Lt31/o;

.field public j:Ljava/util/List;

.field public k:Ljava/util/List;

.field public l:Z

.field public m:I

.field public n:I

.field public o:I

.field public p:I

.field public synthetic q:Ljava/lang/Object;

.field public final synthetic r:Lt31/n;

.field public final synthetic s:Z


# direct methods
.method public constructor <init>(Lt31/n;ZLkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lt31/l;->r:Lt31/n;

    .line 2
    .line 3
    iput-boolean p2, p0, Lt31/l;->s:Z

    .line 4
    .line 5
    const/4 p1, 0x2

    .line 6
    invoke-direct {p0, p1, p3}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 2

    .line 1
    new-instance v0, Lt31/l;

    .line 2
    .line 3
    iget-object v1, p0, Lt31/l;->r:Lt31/n;

    .line 4
    .line 5
    iget-boolean p0, p0, Lt31/l;->s:Z

    .line 6
    .line 7
    invoke-direct {v0, v1, p0, p2}, Lt31/l;-><init>(Lt31/n;ZLkotlin/coroutines/Continuation;)V

    .line 8
    .line 9
    .line 10
    iput-object p1, v0, Lt31/l;->q:Ljava/lang/Object;

    .line 11
    .line 12
    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lvy0/b0;

    .line 2
    .line 3
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    invoke-virtual {p0, p1, p2}, Lt31/l;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Lt31/l;

    .line 10
    .line 11
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 12
    .line 13
    invoke-virtual {p0, p1}, Lt31/l;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 29

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v1, v0, Lt31/l;->r:Lt31/n;

    .line 4
    .line 5
    iget-object v2, v1, Lq41/b;->d:Lyy0/c2;

    .line 6
    .line 7
    iget-object v3, v0, Lt31/l;->q:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast v3, Lvy0/b0;

    .line 10
    .line 11
    sget-object v4, Lqx0/a;->d:Lqx0/a;

    .line 12
    .line 13
    iget v5, v0, Lt31/l;->p:I

    .line 14
    .line 15
    const/4 v6, 0x3

    .line 16
    const/4 v7, 0x2

    .line 17
    const/4 v8, 0x1

    .line 18
    const/4 v10, 0x0

    .line 19
    if-eqz v5, :cond_3

    .line 20
    .line 21
    if-eq v5, v8, :cond_2

    .line 22
    .line 23
    if-eq v5, v7, :cond_1

    .line 24
    .line 25
    if-ne v5, v6, :cond_0

    .line 26
    .line 27
    iget v2, v0, Lt31/l;->n:I

    .line 28
    .line 29
    iget v3, v0, Lt31/l;->m:I

    .line 30
    .line 31
    iget-boolean v5, v0, Lt31/l;->l:Z

    .line 32
    .line 33
    iget-object v11, v0, Lt31/l;->k:Ljava/util/List;

    .line 34
    .line 35
    check-cast v11, Ljava/util/List;

    .line 36
    .line 37
    iget-object v12, v0, Lt31/l;->j:Ljava/util/List;

    .line 38
    .line 39
    check-cast v12, Ljava/util/List;

    .line 40
    .line 41
    iget-object v13, v0, Lt31/l;->i:Lt31/o;

    .line 42
    .line 43
    iget-object v14, v0, Lt31/l;->h:Ljava/lang/Object;

    .line 44
    .line 45
    iget-object v15, v0, Lt31/l;->g:Lyy0/j1;

    .line 46
    .line 47
    iget-object v7, v0, Lt31/l;->f:Lvy0/h0;

    .line 48
    .line 49
    iget-object v8, v0, Lt31/l;->e:Lvy0/h0;

    .line 50
    .line 51
    iget-object v9, v0, Lt31/l;->d:Lvy0/h0;

    .line 52
    .line 53
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    move/from16 v26, v5

    .line 57
    .line 58
    move v10, v6

    .line 59
    move-object/from16 v21, v11

    .line 60
    .line 61
    move-object/from16 v23, v12

    .line 62
    .line 63
    move-object/from16 v18, v13

    .line 64
    .line 65
    move v5, v3

    .line 66
    move-object v12, v7

    .line 67
    move-object/from16 v3, p1

    .line 68
    .line 69
    :goto_0
    move-object v13, v8

    .line 70
    goto/16 :goto_5

    .line 71
    .line 72
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 73
    .line 74
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 75
    .line 76
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 77
    .line 78
    .line 79
    throw v0

    .line 80
    :cond_1
    iget v2, v0, Lt31/l;->o:I

    .line 81
    .line 82
    iget v3, v0, Lt31/l;->n:I

    .line 83
    .line 84
    iget v5, v0, Lt31/l;->m:I

    .line 85
    .line 86
    iget-boolean v7, v0, Lt31/l;->l:Z

    .line 87
    .line 88
    iget-object v8, v0, Lt31/l;->j:Ljava/util/List;

    .line 89
    .line 90
    check-cast v8, Ljava/util/List;

    .line 91
    .line 92
    iget-object v9, v0, Lt31/l;->i:Lt31/o;

    .line 93
    .line 94
    iget-object v11, v0, Lt31/l;->h:Ljava/lang/Object;

    .line 95
    .line 96
    iget-object v12, v0, Lt31/l;->g:Lyy0/j1;

    .line 97
    .line 98
    iget-object v13, v0, Lt31/l;->f:Lvy0/h0;

    .line 99
    .line 100
    iget-object v14, v0, Lt31/l;->e:Lvy0/h0;

    .line 101
    .line 102
    iget-object v15, v0, Lt31/l;->d:Lvy0/h0;

    .line 103
    .line 104
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 105
    .line 106
    .line 107
    move v6, v3

    .line 108
    move v3, v2

    .line 109
    move v2, v6

    .line 110
    move-object v6, v12

    .line 111
    move-object v12, v8

    .line 112
    move-object v8, v14

    .line 113
    move-object v14, v11

    .line 114
    move-object v11, v9

    .line 115
    move-object v9, v15

    .line 116
    move-object v15, v6

    .line 117
    move-object/from16 v6, p1

    .line 118
    .line 119
    goto/16 :goto_3

    .line 120
    .line 121
    :cond_2
    iget v2, v0, Lt31/l;->o:I

    .line 122
    .line 123
    iget v3, v0, Lt31/l;->n:I

    .line 124
    .line 125
    iget v5, v0, Lt31/l;->m:I

    .line 126
    .line 127
    iget-boolean v7, v0, Lt31/l;->l:Z

    .line 128
    .line 129
    iget-object v8, v0, Lt31/l;->i:Lt31/o;

    .line 130
    .line 131
    iget-object v9, v0, Lt31/l;->h:Ljava/lang/Object;

    .line 132
    .line 133
    iget-object v11, v0, Lt31/l;->g:Lyy0/j1;

    .line 134
    .line 135
    iget-object v12, v0, Lt31/l;->f:Lvy0/h0;

    .line 136
    .line 137
    iget-object v13, v0, Lt31/l;->e:Lvy0/h0;

    .line 138
    .line 139
    iget-object v14, v0, Lt31/l;->d:Lvy0/h0;

    .line 140
    .line 141
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 142
    .line 143
    .line 144
    move-object v15, v14

    .line 145
    move-object v14, v13

    .line 146
    move-object v13, v12

    .line 147
    move-object v12, v11

    .line 148
    move-object/from16 v11, p1

    .line 149
    .line 150
    goto/16 :goto_2

    .line 151
    .line 152
    :cond_3
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 153
    .line 154
    .line 155
    :cond_4
    invoke-virtual {v2}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 156
    .line 157
    .line 158
    move-result-object v5

    .line 159
    move-object/from16 v16, v5

    .line 160
    .line 161
    check-cast v16, Lt31/o;

    .line 162
    .line 163
    const/16 v24, 0x0

    .line 164
    .line 165
    const/16 v25, 0x1bc

    .line 166
    .line 167
    const/16 v17, 0x1

    .line 168
    .line 169
    const/16 v18, 0x1

    .line 170
    .line 171
    const/16 v19, 0x0

    .line 172
    .line 173
    const/16 v20, 0x0

    .line 174
    .line 175
    const/16 v21, 0x0

    .line 176
    .line 177
    const/16 v22, 0x0

    .line 178
    .line 179
    const/16 v23, 0x0

    .line 180
    .line 181
    invoke-static/range {v16 .. v25}, Lt31/o;->a(Lt31/o;ZZLjava/util/List;Ljava/util/List;Ljava/util/List;Ll4/v;Ljava/lang/String;ZI)Lt31/o;

    .line 182
    .line 183
    .line 184
    move-result-object v7

    .line 185
    invoke-virtual {v2, v5, v7}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 186
    .line 187
    .line 188
    move-result v5

    .line 189
    if-eqz v5, :cond_4

    .line 190
    .line 191
    new-instance v5, Lt31/k;

    .line 192
    .line 193
    const/4 v7, 0x1

    .line 194
    iget-boolean v8, v0, Lt31/l;->s:Z

    .line 195
    .line 196
    invoke-direct {v5, v1, v8, v10, v7}, Lt31/k;-><init>(Lt31/n;ZLkotlin/coroutines/Continuation;I)V

    .line 197
    .line 198
    .line 199
    invoke-static {v3, v10, v5, v6}, Lvy0/e0;->g(Lvy0/b0;Lpx0/g;Lay0/n;I)Lvy0/i0;

    .line 200
    .line 201
    .line 202
    move-result-object v5

    .line 203
    new-instance v7, Lt31/k;

    .line 204
    .line 205
    const/4 v9, 0x0

    .line 206
    invoke-direct {v7, v1, v8, v10, v9}, Lt31/k;-><init>(Lt31/n;ZLkotlin/coroutines/Continuation;I)V

    .line 207
    .line 208
    .line 209
    invoke-static {v3, v10, v7, v6}, Lvy0/e0;->g(Lvy0/b0;Lpx0/g;Lay0/n;I)Lvy0/i0;

    .line 210
    .line 211
    .line 212
    move-result-object v7

    .line 213
    new-instance v8, Lm70/f1;

    .line 214
    .line 215
    const/16 v9, 0x11

    .line 216
    .line 217
    invoke-direct {v8, v1, v10, v9}, Lm70/f1;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 218
    .line 219
    .line 220
    invoke-static {v3, v10, v8, v6}, Lvy0/e0;->g(Lvy0/b0;Lpx0/g;Lay0/n;I)Lvy0/i0;

    .line 221
    .line 222
    .line 223
    move-result-object v3

    .line 224
    iget-object v8, v1, Lt31/n;->p:Landroidx/lifecycle/s0;

    .line 225
    .line 226
    const-class v9, Ll31/m;

    .line 227
    .line 228
    sget-object v11, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 229
    .line 230
    invoke-virtual {v11, v9}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 231
    .line 232
    .line 233
    move-result-object v9

    .line 234
    invoke-static {v8, v9}, Ljp/t0;->c(Landroidx/lifecycle/s0;Lhy0/d;)Ljava/lang/Object;

    .line 235
    .line 236
    .line 237
    move-result-object v8

    .line 238
    check-cast v8, Ll31/m;

    .line 239
    .line 240
    iget-boolean v8, v8, Ll31/m;->b:Z

    .line 241
    .line 242
    move-object v12, v3

    .line 243
    move-object v14, v5

    .line 244
    move-object v13, v7

    .line 245
    move v7, v8

    .line 246
    const/4 v3, 0x0

    .line 247
    const/4 v5, 0x0

    .line 248
    :goto_1
    invoke-virtual {v2}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 249
    .line 250
    .line 251
    move-result-object v9

    .line 252
    move-object v8, v9

    .line 253
    check-cast v8, Lt31/o;

    .line 254
    .line 255
    iput-object v10, v0, Lt31/l;->q:Ljava/lang/Object;

    .line 256
    .line 257
    iput-object v14, v0, Lt31/l;->d:Lvy0/h0;

    .line 258
    .line 259
    iput-object v13, v0, Lt31/l;->e:Lvy0/h0;

    .line 260
    .line 261
    iput-object v12, v0, Lt31/l;->f:Lvy0/h0;

    .line 262
    .line 263
    iput-object v2, v0, Lt31/l;->g:Lyy0/j1;

    .line 264
    .line 265
    iput-object v9, v0, Lt31/l;->h:Ljava/lang/Object;

    .line 266
    .line 267
    iput-object v8, v0, Lt31/l;->i:Lt31/o;

    .line 268
    .line 269
    iput-object v10, v0, Lt31/l;->j:Ljava/util/List;

    .line 270
    .line 271
    iput-object v10, v0, Lt31/l;->k:Ljava/util/List;

    .line 272
    .line 273
    iput-boolean v7, v0, Lt31/l;->l:Z

    .line 274
    .line 275
    iput v5, v0, Lt31/l;->m:I

    .line 276
    .line 277
    iput v3, v0, Lt31/l;->n:I

    .line 278
    .line 279
    const/4 v11, 0x0

    .line 280
    iput v11, v0, Lt31/l;->o:I

    .line 281
    .line 282
    const/4 v15, 0x1

    .line 283
    iput v15, v0, Lt31/l;->p:I

    .line 284
    .line 285
    invoke-interface {v12, v0}, Lvy0/h0;->B(Lrx0/c;)Ljava/lang/Object;

    .line 286
    .line 287
    .line 288
    move-result-object v11

    .line 289
    if-ne v11, v4, :cond_5

    .line 290
    .line 291
    goto/16 :goto_4

    .line 292
    .line 293
    :cond_5
    move-object v15, v14

    .line 294
    move-object v14, v13

    .line 295
    move-object v13, v12

    .line 296
    move-object v12, v2

    .line 297
    const/4 v2, 0x0

    .line 298
    :goto_2
    check-cast v11, Ljava/util/List;

    .line 299
    .line 300
    iput-object v10, v0, Lt31/l;->q:Ljava/lang/Object;

    .line 301
    .line 302
    iput-object v15, v0, Lt31/l;->d:Lvy0/h0;

    .line 303
    .line 304
    iput-object v14, v0, Lt31/l;->e:Lvy0/h0;

    .line 305
    .line 306
    iput-object v13, v0, Lt31/l;->f:Lvy0/h0;

    .line 307
    .line 308
    iput-object v12, v0, Lt31/l;->g:Lyy0/j1;

    .line 309
    .line 310
    iput-object v9, v0, Lt31/l;->h:Ljava/lang/Object;

    .line 311
    .line 312
    iput-object v8, v0, Lt31/l;->i:Lt31/o;

    .line 313
    .line 314
    move-object v6, v11

    .line 315
    check-cast v6, Ljava/util/List;

    .line 316
    .line 317
    iput-object v6, v0, Lt31/l;->j:Ljava/util/List;

    .line 318
    .line 319
    iput-boolean v7, v0, Lt31/l;->l:Z

    .line 320
    .line 321
    iput v5, v0, Lt31/l;->m:I

    .line 322
    .line 323
    iput v3, v0, Lt31/l;->n:I

    .line 324
    .line 325
    iput v2, v0, Lt31/l;->o:I

    .line 326
    .line 327
    const/4 v6, 0x2

    .line 328
    iput v6, v0, Lt31/l;->p:I

    .line 329
    .line 330
    invoke-interface {v15, v0}, Lvy0/h0;->B(Lrx0/c;)Ljava/lang/Object;

    .line 331
    .line 332
    .line 333
    move-result-object v6

    .line 334
    if-ne v6, v4, :cond_6

    .line 335
    .line 336
    goto :goto_4

    .line 337
    :cond_6
    move/from16 v28, v3

    .line 338
    .line 339
    move v3, v2

    .line 340
    move/from16 v2, v28

    .line 341
    .line 342
    move-object/from16 v28, v11

    .line 343
    .line 344
    move-object v11, v8

    .line 345
    move-object v8, v14

    .line 346
    move-object v14, v9

    .line 347
    move-object v9, v15

    .line 348
    move-object v15, v12

    .line 349
    move-object/from16 v12, v28

    .line 350
    .line 351
    :goto_3
    check-cast v6, Ljava/util/List;

    .line 352
    .line 353
    iput-object v10, v0, Lt31/l;->q:Ljava/lang/Object;

    .line 354
    .line 355
    iput-object v9, v0, Lt31/l;->d:Lvy0/h0;

    .line 356
    .line 357
    iput-object v8, v0, Lt31/l;->e:Lvy0/h0;

    .line 358
    .line 359
    iput-object v13, v0, Lt31/l;->f:Lvy0/h0;

    .line 360
    .line 361
    iput-object v15, v0, Lt31/l;->g:Lyy0/j1;

    .line 362
    .line 363
    iput-object v14, v0, Lt31/l;->h:Ljava/lang/Object;

    .line 364
    .line 365
    iput-object v11, v0, Lt31/l;->i:Lt31/o;

    .line 366
    .line 367
    move-object v10, v12

    .line 368
    check-cast v10, Ljava/util/List;

    .line 369
    .line 370
    iput-object v10, v0, Lt31/l;->j:Ljava/util/List;

    .line 371
    .line 372
    move-object v10, v6

    .line 373
    check-cast v10, Ljava/util/List;

    .line 374
    .line 375
    iput-object v10, v0, Lt31/l;->k:Ljava/util/List;

    .line 376
    .line 377
    iput-boolean v7, v0, Lt31/l;->l:Z

    .line 378
    .line 379
    iput v5, v0, Lt31/l;->m:I

    .line 380
    .line 381
    iput v2, v0, Lt31/l;->n:I

    .line 382
    .line 383
    iput v3, v0, Lt31/l;->o:I

    .line 384
    .line 385
    const/4 v10, 0x3

    .line 386
    iput v10, v0, Lt31/l;->p:I

    .line 387
    .line 388
    invoke-interface {v8, v0}, Lvy0/h0;->B(Lrx0/c;)Ljava/lang/Object;

    .line 389
    .line 390
    .line 391
    move-result-object v3

    .line 392
    if-ne v3, v4, :cond_7

    .line 393
    .line 394
    :goto_4
    return-object v4

    .line 395
    :cond_7
    move-object/from16 v21, v6

    .line 396
    .line 397
    move/from16 v26, v7

    .line 398
    .line 399
    move-object/from16 v18, v11

    .line 400
    .line 401
    move-object/from16 v23, v12

    .line 402
    .line 403
    move-object v12, v13

    .line 404
    goto/16 :goto_0

    .line 405
    .line 406
    :goto_5
    move-object/from16 v22, v3

    .line 407
    .line 408
    check-cast v22, Ljava/util/List;

    .line 409
    .line 410
    const-string v25, "1500"

    .line 411
    .line 412
    const/16 v27, 0x60

    .line 413
    .line 414
    const/16 v19, 0x0

    .line 415
    .line 416
    const/16 v20, 0x0

    .line 417
    .line 418
    const/16 v24, 0x0

    .line 419
    .line 420
    invoke-static/range {v18 .. v27}, Lt31/o;->a(Lt31/o;ZZLjava/util/List;Ljava/util/List;Ljava/util/List;Ll4/v;Ljava/lang/String;ZI)Lt31/o;

    .line 421
    .line 422
    .line 423
    move-result-object v3

    .line 424
    move-object v6, v15

    .line 425
    check-cast v6, Lyy0/c2;

    .line 426
    .line 427
    invoke-virtual {v6, v14, v3}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 428
    .line 429
    .line 430
    move-result v3

    .line 431
    if-eqz v3, :cond_9

    .line 432
    .line 433
    invoke-virtual {v1}, Lt31/n;->b()Z

    .line 434
    .line 435
    .line 436
    move-result v0

    .line 437
    if-eqz v0, :cond_8

    .line 438
    .line 439
    invoke-virtual {v1}, Lt31/n;->d()V

    .line 440
    .line 441
    .line 442
    :cond_8
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 443
    .line 444
    return-object v0

    .line 445
    :cond_9
    move v3, v2

    .line 446
    move-object v2, v6

    .line 447
    move-object v14, v9

    .line 448
    move v6, v10

    .line 449
    move/from16 v7, v26

    .line 450
    .line 451
    const/4 v10, 0x0

    .line 452
    goto/16 :goto_1
.end method
