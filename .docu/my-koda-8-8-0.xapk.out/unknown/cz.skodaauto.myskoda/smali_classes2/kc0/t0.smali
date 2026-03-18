.class public final Lkc0/t0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lkc0/g;

.field public final b:Lkc0/h;

.field public final c:Lkc0/b0;

.field public final d:Lkc0/c0;

.field public final e:Lkc0/a0;

.field public final f:Lkc0/r0;

.field public final g:Lqf0/a;

.field public final h:Lzo0/j;

.field public final i:Ljava/util/ArrayList;

.field public final j:Ljava/util/ArrayList;


# direct methods
.method public constructor <init>(Lam0/w;Lkc0/g;Lkc0/h;Lkc0/b0;Lkc0/c0;Lkc0/a0;Lkc0/r0;Lqf0/a;Lzo0/j;Ljava/util/ArrayList;Ljava/util/ArrayList;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p2, p0, Lkc0/t0;->a:Lkc0/g;

    .line 5
    .line 6
    iput-object p3, p0, Lkc0/t0;->b:Lkc0/h;

    .line 7
    .line 8
    iput-object p4, p0, Lkc0/t0;->c:Lkc0/b0;

    .line 9
    .line 10
    iput-object p5, p0, Lkc0/t0;->d:Lkc0/c0;

    .line 11
    .line 12
    iput-object p6, p0, Lkc0/t0;->e:Lkc0/a0;

    .line 13
    .line 14
    iput-object p7, p0, Lkc0/t0;->f:Lkc0/r0;

    .line 15
    .line 16
    iput-object p8, p0, Lkc0/t0;->g:Lqf0/a;

    .line 17
    .line 18
    iput-object p9, p0, Lkc0/t0;->h:Lzo0/j;

    .line 19
    .line 20
    iput-object p10, p0, Lkc0/t0;->i:Ljava/util/ArrayList;

    .line 21
    .line 22
    iput-object p11, p0, Lkc0/t0;->j:Ljava/util/ArrayList;

    .line 23
    .line 24
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lne0/t;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Lkc0/t0;->b(Lne0/t;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lne0/t;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 22

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v0, p2

    .line 4
    .line 5
    instance-of v2, v0, Lkc0/s0;

    .line 6
    .line 7
    if-eqz v2, :cond_0

    .line 8
    .line 9
    move-object v2, v0

    .line 10
    check-cast v2, Lkc0/s0;

    .line 11
    .line 12
    iget v3, v2, Lkc0/s0;->k:I

    .line 13
    .line 14
    const/high16 v4, -0x80000000

    .line 15
    .line 16
    and-int v5, v3, v4

    .line 17
    .line 18
    if-eqz v5, :cond_0

    .line 19
    .line 20
    sub-int/2addr v3, v4

    .line 21
    iput v3, v2, Lkc0/s0;->k:I

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    new-instance v2, Lkc0/s0;

    .line 25
    .line 26
    invoke-direct {v2, v1, v0}, Lkc0/s0;-><init>(Lkc0/t0;Lkotlin/coroutines/Continuation;)V

    .line 27
    .line 28
    .line 29
    :goto_0
    iget-object v0, v2, Lkc0/s0;->i:Ljava/lang/Object;

    .line 30
    .line 31
    sget-object v3, Lqx0/a;->d:Lqx0/a;

    .line 32
    .line 33
    iget v4, v2, Lkc0/s0;->k:I

    .line 34
    .line 35
    sget-object v5, Llx0/b0;->a:Llx0/b0;

    .line 36
    .line 37
    const/4 v6, 0x2

    .line 38
    const/4 v7, 0x1

    .line 39
    const/4 v8, 0x0

    .line 40
    if-eqz v4, :cond_3

    .line 41
    .line 42
    if-eq v4, v7, :cond_2

    .line 43
    .line 44
    if-ne v4, v6, :cond_1

    .line 45
    .line 46
    iget-object v3, v2, Lkc0/s0;->e:Ljava/util/List;

    .line 47
    .line 48
    check-cast v3, Ljava/util/List;

    .line 49
    .line 50
    iget-object v2, v2, Lkc0/s0;->d:Lne0/t;

    .line 51
    .line 52
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    goto/16 :goto_a

    .line 56
    .line 57
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 58
    .line 59
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 60
    .line 61
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    throw v0

    .line 65
    :cond_2
    iget v4, v2, Lkc0/s0;->h:I

    .line 66
    .line 67
    iget-object v9, v2, Lkc0/s0;->g:Ljava/util/Iterator;

    .line 68
    .line 69
    iget-object v10, v2, Lkc0/s0;->f:Lkotlin/jvm/internal/f0;

    .line 70
    .line 71
    iget-object v11, v2, Lkc0/s0;->e:Ljava/util/List;

    .line 72
    .line 73
    check-cast v11, Ljava/util/List;

    .line 74
    .line 75
    iget-object v12, v2, Lkc0/s0;->d:Lne0/t;

    .line 76
    .line 77
    :try_start_0
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 78
    .line 79
    .line 80
    goto/16 :goto_4

    .line 81
    .line 82
    :catch_0
    move-exception v0

    .line 83
    goto/16 :goto_5

    .line 84
    .line 85
    :cond_3
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 86
    .line 87
    .line 88
    new-instance v0, Ljava/util/ArrayList;

    .line 89
    .line 90
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 91
    .line 92
    .line 93
    invoke-static {}, Ljp/k1;->f()Lnx0/c;

    .line 94
    .line 95
    .line 96
    move-result-object v4

    .line 97
    new-instance v9, Lio/ktor/utils/io/g0;

    .line 98
    .line 99
    const/4 v15, 0x0

    .line 100
    const/16 v16, 0xf

    .line 101
    .line 102
    const/4 v10, 0x1

    .line 103
    iget-object v11, v1, Lkc0/t0;->b:Lkc0/h;

    .line 104
    .line 105
    const-class v12, Lkc0/h;

    .line 106
    .line 107
    const-string v13, "clearTokens"

    .line 108
    .line 109
    const-string v14, "clearTokens(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;"

    .line 110
    .line 111
    invoke-direct/range {v9 .. v16}, Lio/ktor/utils/io/g0;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 112
    .line 113
    .line 114
    invoke-virtual {v4, v9}, Lnx0/c;->add(Ljava/lang/Object;)Z

    .line 115
    .line 116
    .line 117
    new-instance v10, Lio/ktor/utils/io/g0;

    .line 118
    .line 119
    const/16 v16, 0x0

    .line 120
    .line 121
    const/16 v17, 0x10

    .line 122
    .line 123
    const/4 v11, 0x1

    .line 124
    iget-object v12, v1, Lkc0/t0;->a:Lkc0/g;

    .line 125
    .line 126
    const-class v13, Lkc0/g;

    .line 127
    .line 128
    const-string v14, "clearTokens"

    .line 129
    .line 130
    const-string v15, "clearTokens(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;"

    .line 131
    .line 132
    invoke-direct/range {v10 .. v17}, Lio/ktor/utils/io/g0;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 133
    .line 134
    .line 135
    invoke-virtual {v4, v10}, Lnx0/c;->add(Ljava/lang/Object;)Z

    .line 136
    .line 137
    .line 138
    new-instance v9, Ljava/util/ArrayList;

    .line 139
    .line 140
    iget-object v10, v1, Lkc0/t0;->j:Ljava/util/ArrayList;

    .line 141
    .line 142
    const/16 v11, 0xa

    .line 143
    .line 144
    invoke-static {v10, v11}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 145
    .line 146
    .line 147
    move-result v12

    .line 148
    invoke-direct {v9, v12}, Ljava/util/ArrayList;-><init>(I)V

    .line 149
    .line 150
    .line 151
    invoke-interface {v10}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 152
    .line 153
    .line 154
    move-result-object v10

    .line 155
    :goto_1
    invoke-interface {v10}, Ljava/util/Iterator;->hasNext()Z

    .line 156
    .line 157
    .line 158
    move-result v12

    .line 159
    if-eqz v12, :cond_4

    .line 160
    .line 161
    invoke-interface {v10}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 162
    .line 163
    .line 164
    move-result-object v12

    .line 165
    move-object v15, v12

    .line 166
    check-cast v15, Lme0/b;

    .line 167
    .line 168
    new-instance v13, Lio/ktor/utils/io/g0;

    .line 169
    .line 170
    const/16 v19, 0x0

    .line 171
    .line 172
    const/16 v20, 0x11

    .line 173
    .line 174
    const/4 v14, 0x1

    .line 175
    const-class v16, Lme0/b;

    .line 176
    .line 177
    const-string v17, "clearSensitiveData"

    .line 178
    .line 179
    const-string v18, "clearSensitiveData(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;"

    .line 180
    .line 181
    invoke-direct/range {v13 .. v20}, Lio/ktor/utils/io/g0;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 182
    .line 183
    .line 184
    invoke-virtual {v9, v13}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 185
    .line 186
    .line 187
    goto :goto_1

    .line 188
    :cond_4
    invoke-virtual {v4, v9}, Lnx0/c;->addAll(Ljava/util/Collection;)Z

    .line 189
    .line 190
    .line 191
    new-instance v9, Ljava/util/ArrayList;

    .line 192
    .line 193
    iget-object v10, v1, Lkc0/t0;->i:Ljava/util/ArrayList;

    .line 194
    .line 195
    invoke-static {v10, v11}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 196
    .line 197
    .line 198
    move-result v11

    .line 199
    invoke-direct {v9, v11}, Ljava/util/ArrayList;-><init>(I)V

    .line 200
    .line 201
    .line 202
    invoke-interface {v10}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 203
    .line 204
    .line 205
    move-result-object v10

    .line 206
    :goto_2
    invoke-interface {v10}, Ljava/util/Iterator;->hasNext()Z

    .line 207
    .line 208
    .line 209
    move-result v11

    .line 210
    if-eqz v11, :cond_5

    .line 211
    .line 212
    invoke-interface {v10}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 213
    .line 214
    .line 215
    move-result-object v11

    .line 216
    move-object v14, v11

    .line 217
    check-cast v14, Lme0/a;

    .line 218
    .line 219
    new-instance v12, Lio/ktor/utils/io/g0;

    .line 220
    .line 221
    const/16 v18, 0x0

    .line 222
    .line 223
    const/16 v19, 0x12

    .line 224
    .line 225
    const/4 v13, 0x1

    .line 226
    const-class v15, Lme0/a;

    .line 227
    .line 228
    const-string v16, "clearSensitiveData"

    .line 229
    .line 230
    const-string v17, "clearSensitiveData(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;"

    .line 231
    .line 232
    invoke-direct/range {v12 .. v19}, Lio/ktor/utils/io/g0;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 233
    .line 234
    .line 235
    invoke-virtual {v9, v12}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 236
    .line 237
    .line 238
    goto :goto_2

    .line 239
    :cond_5
    invoke-virtual {v4, v9}, Lnx0/c;->addAll(Ljava/util/Collection;)Z

    .line 240
    .line 241
    .line 242
    new-instance v13, Lio/ktor/utils/io/g0;

    .line 243
    .line 244
    const/16 v19, 0x1

    .line 245
    .line 246
    const/16 v20, 0x13

    .line 247
    .line 248
    const/4 v14, 0x1

    .line 249
    iget-object v15, v1, Lkc0/t0;->h:Lzo0/j;

    .line 250
    .line 251
    const-class v16, Lly0/q;

    .line 252
    .line 253
    const-string v17, "invoke"

    .line 254
    .line 255
    const-string v18, "invoke(Lcz/skodaauto/myskoda/library/usecase/domain/SuspendUseCase;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;"

    .line 256
    .line 257
    invoke-direct/range {v13 .. v20}, Lio/ktor/utils/io/g0;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 258
    .line 259
    .line 260
    invoke-virtual {v4, v13}, Lnx0/c;->add(Ljava/lang/Object;)Z

    .line 261
    .line 262
    .line 263
    invoke-static {v4}, Ljp/k1;->d(Ljava/util/List;)Lnx0/c;

    .line 264
    .line 265
    .line 266
    move-result-object v4

    .line 267
    new-instance v9, Lkotlin/jvm/internal/f0;

    .line 268
    .line 269
    invoke-direct {v9}, Ljava/lang/Object;-><init>()V

    .line 270
    .line 271
    .line 272
    const/4 v10, 0x0

    .line 273
    invoke-virtual {v4, v10}, Lnx0/c;->listIterator(I)Ljava/util/ListIterator;

    .line 274
    .line 275
    .line 276
    move-result-object v4

    .line 277
    move-object v11, v4

    .line 278
    move-object v12, v9

    .line 279
    move-object v9, v0

    .line 280
    move-object v4, v2

    .line 281
    move-object/from16 v2, p1

    .line 282
    .line 283
    :goto_3
    invoke-interface {v11}, Ljava/util/Iterator;->hasNext()Z

    .line 284
    .line 285
    .line 286
    move-result v0

    .line 287
    if-eqz v0, :cond_8

    .line 288
    .line 289
    invoke-interface {v11}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 290
    .line 291
    .line 292
    move-result-object v0

    .line 293
    check-cast v0, Lay0/k;

    .line 294
    .line 295
    :try_start_1
    iput-object v2, v4, Lkc0/s0;->d:Lne0/t;

    .line 296
    .line 297
    move-object v13, v9

    .line 298
    check-cast v13, Ljava/util/List;

    .line 299
    .line 300
    iput-object v13, v4, Lkc0/s0;->e:Ljava/util/List;

    .line 301
    .line 302
    iput-object v12, v4, Lkc0/s0;->f:Lkotlin/jvm/internal/f0;

    .line 303
    .line 304
    iput-object v11, v4, Lkc0/s0;->g:Ljava/util/Iterator;

    .line 305
    .line 306
    iput v10, v4, Lkc0/s0;->h:I

    .line 307
    .line 308
    iput v7, v4, Lkc0/s0;->k:I

    .line 309
    .line 310
    invoke-interface {v0, v4}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 311
    .line 312
    .line 313
    move-result-object v0
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_1

    .line 314
    if-ne v0, v3, :cond_6

    .line 315
    .line 316
    goto/16 :goto_9

    .line 317
    .line 318
    :cond_6
    move-object/from16 v21, v12

    .line 319
    .line 320
    move-object v12, v2

    .line 321
    move-object v2, v4

    .line 322
    move v4, v10

    .line 323
    move-object/from16 v10, v21

    .line 324
    .line 325
    move-object/from16 v21, v11

    .line 326
    .line 327
    move-object v11, v9

    .line 328
    move-object/from16 v9, v21

    .line 329
    .line 330
    :cond_7
    :goto_4
    move/from16 v21, v4

    .line 331
    .line 332
    move-object v4, v2

    .line 333
    move-object v2, v12

    .line 334
    move-object v12, v10

    .line 335
    move/from16 v10, v21

    .line 336
    .line 337
    move-object/from16 v21, v11

    .line 338
    .line 339
    move-object v11, v9

    .line 340
    move-object/from16 v9, v21

    .line 341
    .line 342
    goto :goto_6

    .line 343
    :catch_1
    move-exception v0

    .line 344
    move-object/from16 v21, v12

    .line 345
    .line 346
    move-object v12, v2

    .line 347
    move-object v2, v4

    .line 348
    move v4, v10

    .line 349
    move-object/from16 v10, v21

    .line 350
    .line 351
    move-object/from16 v21, v11

    .line 352
    .line 353
    move-object v11, v9

    .line 354
    move-object/from16 v9, v21

    .line 355
    .line 356
    :goto_5
    new-instance v13, Lne0/c;

    .line 357
    .line 358
    new-instance v14, Llc0/i;

    .line 359
    .line 360
    invoke-virtual {v0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 361
    .line 362
    .line 363
    move-result-object v15

    .line 364
    new-instance v7, Ljava/lang/StringBuilder;

    .line 365
    .line 366
    const-string v6, "Error while sign out: "

    .line 367
    .line 368
    invoke-direct {v7, v6}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 369
    .line 370
    .line 371
    invoke-virtual {v7, v15}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 372
    .line 373
    .line 374
    invoke-virtual {v7}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 375
    .line 376
    .line 377
    move-result-object v6

    .line 378
    const-string v7, "message"

    .line 379
    .line 380
    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 381
    .line 382
    .line 383
    invoke-direct {v14, v6, v0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 384
    .line 385
    .line 386
    const/16 v17, 0x0

    .line 387
    .line 388
    const/16 v18, 0x1e

    .line 389
    .line 390
    const/4 v15, 0x0

    .line 391
    const/16 v16, 0x0

    .line 392
    .line 393
    invoke-direct/range {v13 .. v18}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 394
    .line 395
    .line 396
    new-instance v0, La60/a;

    .line 397
    .line 398
    const/4 v6, 0x1

    .line 399
    invoke-direct {v0, v13, v6}, La60/a;-><init>(Lne0/c;I)V

    .line 400
    .line 401
    .line 402
    invoke-static {v1, v0}, Llp/nd;->e(Ljava/lang/Object;Lay0/a;)V

    .line 403
    .line 404
    .line 405
    iget-object v0, v10, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 406
    .line 407
    if-nez v0, :cond_7

    .line 408
    .line 409
    iput-object v13, v10, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 410
    .line 411
    goto :goto_4

    .line 412
    :goto_6
    const/4 v6, 0x2

    .line 413
    const/4 v7, 0x1

    .line 414
    goto/16 :goto_3

    .line 415
    .line 416
    :cond_8
    iget-object v0, v12, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 417
    .line 418
    check-cast v0, Lne0/c;

    .line 419
    .line 420
    if-eqz v0, :cond_9

    .line 421
    .line 422
    invoke-interface {v9, v0}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 423
    .line 424
    .line 425
    :cond_9
    instance-of v0, v2, Lne0/c;

    .line 426
    .line 427
    if-eqz v0, :cond_a

    .line 428
    .line 429
    move-object v0, v2

    .line 430
    check-cast v0, Lne0/c;

    .line 431
    .line 432
    goto :goto_7

    .line 433
    :cond_a
    move-object v0, v8

    .line 434
    :goto_7
    if-eqz v0, :cond_b

    .line 435
    .line 436
    invoke-interface {v9, v0}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 437
    .line 438
    .line 439
    :cond_b
    iput-object v2, v4, Lkc0/s0;->d:Lne0/t;

    .line 440
    .line 441
    move-object v0, v9

    .line 442
    check-cast v0, Ljava/util/List;

    .line 443
    .line 444
    iput-object v0, v4, Lkc0/s0;->e:Ljava/util/List;

    .line 445
    .line 446
    iput-object v8, v4, Lkc0/s0;->f:Lkotlin/jvm/internal/f0;

    .line 447
    .line 448
    iput-object v8, v4, Lkc0/s0;->g:Ljava/util/Iterator;

    .line 449
    .line 450
    const/4 v6, 0x2

    .line 451
    iput v6, v4, Lkc0/s0;->k:I

    .line 452
    .line 453
    iget-object v0, v1, Lkc0/t0;->g:Lqf0/a;

    .line 454
    .line 455
    check-cast v0, Lof0/b;

    .line 456
    .line 457
    iget-object v0, v0, Lof0/b;->a:Lve0/u;

    .line 458
    .line 459
    const-string v6, "PREF_DEMO_ENABLED"

    .line 460
    .line 461
    invoke-virtual {v0, v6, v4}, Lve0/u;->k(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 462
    .line 463
    .line 464
    move-result-object v0

    .line 465
    sget-object v4, Lqx0/a;->d:Lqx0/a;

    .line 466
    .line 467
    if-ne v0, v4, :cond_c

    .line 468
    .line 469
    goto :goto_8

    .line 470
    :cond_c
    move-object v0, v5

    .line 471
    :goto_8
    if-ne v0, v3, :cond_d

    .line 472
    .line 473
    :goto_9
    return-object v3

    .line 474
    :cond_d
    move-object v3, v9

    .line 475
    :goto_a
    iget-object v0, v1, Lkc0/t0;->f:Lkc0/r0;

    .line 476
    .line 477
    check-cast v0, Lic0/b;

    .line 478
    .line 479
    iget-object v4, v0, Lic0/b;->a:Ljava/util/ArrayList;

    .line 480
    .line 481
    iput-object v8, v0, Lic0/b;->b:Llc0/j;

    .line 482
    .line 483
    invoke-virtual {v4}, Ljava/util/ArrayList;->clear()V

    .line 484
    .line 485
    .line 486
    const-string v6, "errors"

    .line 487
    .line 488
    invoke-static {v3, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 489
    .line 490
    .line 491
    check-cast v3, Ljava/util/Collection;

    .line 492
    .line 493
    invoke-virtual {v4, v3}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 494
    .line 495
    .line 496
    invoke-interface {v3}, Ljava/util/Collection;->isEmpty()Z

    .line 497
    .line 498
    .line 499
    move-result v3

    .line 500
    if-nez v3, :cond_e

    .line 501
    .line 502
    iget-object v0, v1, Lkc0/t0;->c:Lkc0/b0;

    .line 503
    .line 504
    invoke-virtual {v0}, Lkc0/b0;->invoke()Ljava/lang/Object;

    .line 505
    .line 506
    .line 507
    goto :goto_b

    .line 508
    :cond_e
    instance-of v3, v2, Lne0/e;

    .line 509
    .line 510
    if-eqz v3, :cond_f

    .line 511
    .line 512
    check-cast v2, Lne0/e;

    .line 513
    .line 514
    iget-object v2, v2, Lne0/e;->a:Ljava/lang/Object;

    .line 515
    .line 516
    check-cast v2, Llc0/j;

    .line 517
    .line 518
    iput-object v2, v0, Lic0/b;->b:Llc0/j;

    .line 519
    .line 520
    iget-object v0, v1, Lkc0/t0;->d:Lkc0/c0;

    .line 521
    .line 522
    invoke-virtual {v0}, Lkc0/c0;->invoke()Ljava/lang/Object;

    .line 523
    .line 524
    .line 525
    goto :goto_b

    .line 526
    :cond_f
    new-instance v0, Ljv0/c;

    .line 527
    .line 528
    const/4 v2, 0x5

    .line 529
    invoke-direct {v0, v2}, Ljv0/c;-><init>(I)V

    .line 530
    .line 531
    .line 532
    invoke-static {v8, v1, v0}, Llp/nd;->f(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 533
    .line 534
    .line 535
    iget-object v0, v1, Lkc0/t0;->e:Lkc0/a0;

    .line 536
    .line 537
    invoke-virtual {v0}, Lkc0/a0;->invoke()Ljava/lang/Object;

    .line 538
    .line 539
    .line 540
    :goto_b
    return-object v5
.end method

.method public final c(Lrx0/c;)Ljava/lang/Object;
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-virtual {p0, v0, p1}, Lkc0/t0;->b(Lne0/t;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 3
    .line 4
    .line 5
    move-result-object p0

    .line 6
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    if-ne p0, p1, :cond_0

    .line 9
    .line 10
    return-object p0

    .line 11
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 12
    .line 13
    return-object p0
.end method
