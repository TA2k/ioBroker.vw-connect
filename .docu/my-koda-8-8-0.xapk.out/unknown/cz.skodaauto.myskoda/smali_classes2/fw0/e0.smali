.class public abstract Lfw0/e0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Ljava/util/Set;

.field public static final b:Lt21/b;

.field public static final c:Lgv/a;

.field public static final d:Lgw0/c;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    sget-object v0, Low0/s;->b:Low0/s;

    .line 2
    .line 3
    sget-object v1, Low0/s;->d:Low0/s;

    .line 4
    .line 5
    filled-new-array {v0, v1}, [Low0/s;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    invoke-static {v0}, Lmx0/n;->h0([Ljava/lang/Object;)Ljava/util/Set;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    sput-object v0, Lfw0/e0;->a:Ljava/util/Set;

    .line 14
    .line 15
    const-string v0, "io.ktor.client.plugins.HttpRedirect"

    .line 16
    .line 17
    invoke-static {v0}, Lt21/d;->b(Ljava/lang/String;)Lt21/b;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    sput-object v0, Lfw0/e0;->b:Lt21/b;

    .line 22
    .line 23
    new-instance v0, Lgv/a;

    .line 24
    .line 25
    const/16 v1, 0xa

    .line 26
    .line 27
    invoke-direct {v0, v1}, Lgv/a;-><init>(I)V

    .line 28
    .line 29
    .line 30
    sput-object v0, Lfw0/e0;->c:Lgv/a;

    .line 31
    .line 32
    sget-object v0, Lfw0/c0;->d:Lfw0/c0;

    .line 33
    .line 34
    new-instance v1, Lf31/n;

    .line 35
    .line 36
    const/16 v2, 0x1c

    .line 37
    .line 38
    invoke-direct {v1, v2}, Lf31/n;-><init>(I)V

    .line 39
    .line 40
    .line 41
    const-string v2, "HttpRedirect"

    .line 42
    .line 43
    invoke-static {v2, v0, v1}, Lkp/q9;->a(Ljava/lang/String;Lay0/a;Lay0/k;)Lgw0/c;

    .line 44
    .line 45
    .line 46
    move-result-object v0

    .line 47
    sput-object v0, Lfw0/e0;->d:Lgw0/c;

    .line 48
    .line 49
    return-void
.end method

.method public static final a(Lgw0/h;Lkw0/c;Law0/c;Lzv0/c;Lrx0/c;)Ljava/lang/Object;
    .locals 17

    .line 1
    move-object/from16 v0, p4

    .line 2
    .line 3
    instance-of v1, v0, Lfw0/d0;

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    move-object v1, v0

    .line 8
    check-cast v1, Lfw0/d0;

    .line 9
    .line 10
    iget v2, v1, Lfw0/d0;->j:I

    .line 11
    .line 12
    const/high16 v3, -0x80000000

    .line 13
    .line 14
    and-int v4, v2, v3

    .line 15
    .line 16
    if-eqz v4, :cond_0

    .line 17
    .line 18
    sub-int/2addr v2, v3

    .line 19
    iput v2, v1, Lfw0/d0;->j:I

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    new-instance v1, Lfw0/d0;

    .line 23
    .line 24
    invoke-direct {v1, v0}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 25
    .line 26
    .line 27
    :goto_0
    iget-object v0, v1, Lfw0/d0;->i:Ljava/lang/Object;

    .line 28
    .line 29
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 30
    .line 31
    iget v3, v1, Lfw0/d0;->j:I

    .line 32
    .line 33
    const/4 v4, 0x1

    .line 34
    if-eqz v3, :cond_2

    .line 35
    .line 36
    if-ne v3, v4, :cond_1

    .line 37
    .line 38
    iget-object v3, v1, Lfw0/d0;->h:Lkotlin/jvm/internal/f0;

    .line 39
    .line 40
    iget-object v5, v1, Lfw0/d0;->g:Lkotlin/jvm/internal/f0;

    .line 41
    .line 42
    iget-object v6, v1, Lfw0/d0;->f:Lkotlin/jvm/internal/f0;

    .line 43
    .line 44
    iget-object v7, v1, Lfw0/d0;->e:Lzv0/c;

    .line 45
    .line 46
    iget-object v8, v1, Lfw0/d0;->d:Lgw0/h;

    .line 47
    .line 48
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    move-object/from16 v16, v5

    .line 52
    .line 53
    move-object v5, v1

    .line 54
    move-object v1, v7

    .line 55
    move-object/from16 v7, v16

    .line 56
    .line 57
    goto/16 :goto_7

    .line 58
    .line 59
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 60
    .line 61
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 62
    .line 63
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 64
    .line 65
    .line 66
    throw v0

    .line 67
    :cond_2
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 68
    .line 69
    .line 70
    new-instance v0, Lkotlin/jvm/internal/f0;

    .line 71
    .line 72
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 73
    .line 74
    .line 75
    move-object/from16 v3, p2

    .line 76
    .line 77
    iput-object v3, v0, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 78
    .line 79
    new-instance v3, Lkotlin/jvm/internal/f0;

    .line 80
    .line 81
    invoke-direct {v3}, Ljava/lang/Object;-><init>()V

    .line 82
    .line 83
    .line 84
    move-object/from16 v5, p1

    .line 85
    .line 86
    iput-object v5, v3, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 87
    .line 88
    move-object v5, v0

    .line 89
    move-object v6, v3

    .line 90
    move-object/from16 v0, p0

    .line 91
    .line 92
    move-object v3, v1

    .line 93
    move-object/from16 v1, p3

    .line 94
    .line 95
    :goto_1
    iget-object v7, v5, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 96
    .line 97
    check-cast v7, Law0/c;

    .line 98
    .line 99
    invoke-virtual {v7}, Law0/c;->c()Lkw0/b;

    .line 100
    .line 101
    .line 102
    move-result-object v7

    .line 103
    invoke-interface {v7}, Lkw0/b;->getUrl()Low0/f0;

    .line 104
    .line 105
    .line 106
    move-result-object v7

    .line 107
    iget-object v7, v7, Low0/f0;->j:Low0/b0;

    .line 108
    .line 109
    iget-object v8, v5, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 110
    .line 111
    check-cast v8, Law0/c;

    .line 112
    .line 113
    invoke-virtual {v8}, Law0/c;->c()Lkw0/b;

    .line 114
    .line 115
    .line 116
    move-result-object v8

    .line 117
    invoke-interface {v8}, Lkw0/b;->getUrl()Low0/f0;

    .line 118
    .line 119
    .line 120
    move-result-object v8

    .line 121
    const-string v9, "<this>"

    .line 122
    .line 123
    invoke-static {v8, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 124
    .line 125
    .line 126
    new-instance v10, Ljava/lang/StringBuilder;

    .line 127
    .line 128
    invoke-direct {v10}, Ljava/lang/StringBuilder;-><init>()V

    .line 129
    .line 130
    .line 131
    new-instance v11, Ljava/lang/StringBuilder;

    .line 132
    .line 133
    invoke-direct {v11}, Ljava/lang/StringBuilder;-><init>()V

    .line 134
    .line 135
    .line 136
    iget-object v12, v8, Low0/f0;->k:Llx0/q;

    .line 137
    .line 138
    invoke-virtual {v12}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 139
    .line 140
    .line 141
    move-result-object v12

    .line 142
    check-cast v12, Ljava/lang/String;

    .line 143
    .line 144
    iget-object v13, v8, Low0/f0;->l:Llx0/q;

    .line 145
    .line 146
    invoke-virtual {v13}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 147
    .line 148
    .line 149
    move-result-object v13

    .line 150
    check-cast v13, Ljava/lang/String;

    .line 151
    .line 152
    const/16 v14, 0x3a

    .line 153
    .line 154
    if-nez v12, :cond_3

    .line 155
    .line 156
    goto :goto_2

    .line 157
    :cond_3
    invoke-virtual {v11, v12}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 158
    .line 159
    .line 160
    if-eqz v13, :cond_4

    .line 161
    .line 162
    invoke-virtual {v11, v14}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 163
    .line 164
    .line 165
    invoke-virtual {v11, v13}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 166
    .line 167
    .line 168
    :cond_4
    const-string v12, "@"

    .line 169
    .line 170
    invoke-virtual {v11, v12}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 171
    .line 172
    .line 173
    :goto_2
    invoke-virtual {v11}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 174
    .line 175
    .line 176
    move-result-object v11

    .line 177
    invoke-virtual {v10, v11}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 178
    .line 179
    .line 180
    iget-object v11, v8, Low0/f0;->d:Ljava/lang/String;

    .line 181
    .line 182
    iget-object v12, v8, Low0/f0;->j:Low0/b0;

    .line 183
    .line 184
    iget v8, v8, Low0/f0;->e:I

    .line 185
    .line 186
    if-eqz v8, :cond_8

    .line 187
    .line 188
    iget v13, v12, Low0/b0;->e:I

    .line 189
    .line 190
    if-ne v8, v13, :cond_5

    .line 191
    .line 192
    goto :goto_4

    .line 193
    :cond_5
    new-instance v13, Ljava/lang/StringBuilder;

    .line 194
    .line 195
    invoke-direct {v13}, Ljava/lang/StringBuilder;-><init>()V

    .line 196
    .line 197
    .line 198
    invoke-virtual {v13, v11}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 199
    .line 200
    .line 201
    invoke-virtual {v13, v14}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 202
    .line 203
    .line 204
    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 205
    .line 206
    .line 207
    move-result-object v11

    .line 208
    if-nez v8, :cond_6

    .line 209
    .line 210
    const/4 v11, 0x0

    .line 211
    :cond_6
    if-eqz v11, :cond_7

    .line 212
    .line 213
    invoke-virtual {v11}, Ljava/lang/Integer;->intValue()I

    .line 214
    .line 215
    .line 216
    move-result v8

    .line 217
    goto :goto_3

    .line 218
    :cond_7
    iget v8, v12, Low0/b0;->e:I

    .line 219
    .line 220
    :goto_3
    invoke-virtual {v13, v8}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 221
    .line 222
    .line 223
    invoke-virtual {v13}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 224
    .line 225
    .line 226
    move-result-object v11

    .line 227
    :cond_8
    :goto_4
    invoke-virtual {v10, v11}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 228
    .line 229
    .line 230
    invoke-virtual {v10}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 231
    .line 232
    .line 233
    move-result-object v8

    .line 234
    iget-object v10, v5, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 235
    .line 236
    check-cast v10, Law0/c;

    .line 237
    .line 238
    invoke-virtual {v10}, Law0/c;->d()Law0/h;

    .line 239
    .line 240
    .line 241
    move-result-object v10

    .line 242
    invoke-virtual {v10}, Law0/h;->c()Low0/v;

    .line 243
    .line 244
    .line 245
    move-result-object v10

    .line 246
    iget v10, v10, Low0/v;->d:I

    .line 247
    .line 248
    sget-object v11, Low0/v;->j:Low0/v;

    .line 249
    .line 250
    iget v11, v11, Low0/v;->d:I

    .line 251
    .line 252
    if-eq v10, v11, :cond_a

    .line 253
    .line 254
    sget-object v11, Low0/v;->k:Low0/v;

    .line 255
    .line 256
    iget v11, v11, Low0/v;->d:I

    .line 257
    .line 258
    if-eq v10, v11, :cond_a

    .line 259
    .line 260
    sget-object v11, Low0/v;->m:Low0/v;

    .line 261
    .line 262
    iget v11, v11, Low0/v;->d:I

    .line 263
    .line 264
    if-eq v10, v11, :cond_a

    .line 265
    .line 266
    sget-object v11, Low0/v;->n:Low0/v;

    .line 267
    .line 268
    iget v11, v11, Low0/v;->d:I

    .line 269
    .line 270
    if-eq v10, v11, :cond_a

    .line 271
    .line 272
    sget-object v11, Low0/v;->l:Low0/v;

    .line 273
    .line 274
    iget v11, v11, Low0/v;->d:I

    .line 275
    .line 276
    if-ne v10, v11, :cond_9

    .line 277
    .line 278
    goto :goto_5

    .line 279
    :cond_9
    iget-object v0, v5, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 280
    .line 281
    return-object v0

    .line 282
    :cond_a
    :goto_5
    iget-object v10, v5, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 283
    .line 284
    check-cast v10, Law0/c;

    .line 285
    .line 286
    invoke-virtual {v10}, Law0/c;->d()Law0/h;

    .line 287
    .line 288
    .line 289
    move-result-object v10

    .line 290
    invoke-interface {v10}, Low0/r;->a()Low0/m;

    .line 291
    .line 292
    .line 293
    move-result-object v10

    .line 294
    sget-object v11, Low0/q;->a:Ljava/util/List;

    .line 295
    .line 296
    const-string v11, "Location"

    .line 297
    .line 298
    invoke-interface {v10, v11}, Lvw0/j;->get(Ljava/lang/String;)Ljava/lang/String;

    .line 299
    .line 300
    .line 301
    move-result-object v10

    .line 302
    sget-object v11, Lfw0/e0;->b:Lt21/b;

    .line 303
    .line 304
    if-nez v10, :cond_b

    .line 305
    .line 306
    new-instance v0, Ljava/lang/StringBuilder;

    .line 307
    .line 308
    const-string v1, "Location header missing from redirect response "

    .line 309
    .line 310
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 311
    .line 312
    .line 313
    iget-object v1, v5, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 314
    .line 315
    check-cast v1, Law0/c;

    .line 316
    .line 317
    invoke-virtual {v1}, Law0/c;->c()Lkw0/b;

    .line 318
    .line 319
    .line 320
    move-result-object v1

    .line 321
    invoke-interface {v1}, Lkw0/b;->getUrl()Low0/f0;

    .line 322
    .line 323
    .line 324
    move-result-object v1

    .line 325
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 326
    .line 327
    .line 328
    const-string v1, "; returning response as is"

    .line 329
    .line 330
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 331
    .line 332
    .line 333
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 334
    .line 335
    .line 336
    move-result-object v0

    .line 337
    invoke-interface {v11, v0}, Lt21/b;->g(Ljava/lang/String;)V

    .line 338
    .line 339
    .line 340
    iget-object v0, v5, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 341
    .line 342
    return-object v0

    .line 343
    :cond_b
    iget-object v12, v1, Lzv0/c;->n:Lj1/a;

    .line 344
    .line 345
    iget-object v13, v5, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 346
    .line 347
    check-cast v13, Law0/c;

    .line 348
    .line 349
    invoke-virtual {v13}, Law0/c;->d()Law0/h;

    .line 350
    .line 351
    .line 352
    sget-object v13, Lfw0/e0;->c:Lgv/a;

    .line 353
    .line 354
    invoke-virtual {v12, v13}, Lj1/a;->w(Lgv/a;)V

    .line 355
    .line 356
    .line 357
    new-instance v12, Ljava/lang/StringBuilder;

    .line 358
    .line 359
    const-string v13, "Received redirect response to "

    .line 360
    .line 361
    invoke-direct {v12, v13}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 362
    .line 363
    .line 364
    invoke-virtual {v12, v10}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 365
    .line 366
    .line 367
    const-string v13, " for request "

    .line 368
    .line 369
    invoke-virtual {v12, v13}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 370
    .line 371
    .line 372
    iget-object v13, v5, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 373
    .line 374
    check-cast v13, Law0/c;

    .line 375
    .line 376
    invoke-virtual {v13}, Law0/c;->c()Lkw0/b;

    .line 377
    .line 378
    .line 379
    move-result-object v13

    .line 380
    invoke-interface {v13}, Lkw0/b;->getUrl()Low0/f0;

    .line 381
    .line 382
    .line 383
    move-result-object v13

    .line 384
    invoke-virtual {v12, v13}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 385
    .line 386
    .line 387
    invoke-virtual {v12}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 388
    .line 389
    .line 390
    move-result-object v12

    .line 391
    invoke-interface {v11, v12}, Lt21/b;->h(Ljava/lang/String;)V

    .line 392
    .line 393
    .line 394
    new-instance v12, Lkw0/c;

    .line 395
    .line 396
    invoke-direct {v12}, Lkw0/c;-><init>()V

    .line 397
    .line 398
    .line 399
    iget-object v13, v6, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 400
    .line 401
    check-cast v13, Lkw0/c;

    .line 402
    .line 403
    const-string v14, "builder"

    .line 404
    .line 405
    invoke-static {v13, v14}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 406
    .line 407
    .line 408
    iget-object v14, v13, Lkw0/c;->e:Lvy0/z1;

    .line 409
    .line 410
    iput-object v14, v12, Lkw0/c;->e:Lvy0/z1;

    .line 411
    .line 412
    invoke-virtual {v12, v13}, Lkw0/c;->c(Lkw0/c;)V

    .line 413
    .line 414
    .line 415
    iget-object v13, v12, Lkw0/c;->a:Low0/z;

    .line 416
    .line 417
    iget-object v14, v13, Low0/z;->j:Lj1/a;

    .line 418
    .line 419
    iget-object v14, v14, Lj1/a;->e:Ljava/lang/Object;

    .line 420
    .line 421
    check-cast v14, Low0/n;

    .line 422
    .line 423
    iget-object v14, v14, Lap0/o;->e:Ljava/lang/Object;

    .line 424
    .line 425
    check-cast v14, Ljava/util/Map;

    .line 426
    .line 427
    invoke-interface {v14}, Ljava/util/Map;->clear()V

    .line 428
    .line 429
    .line 430
    invoke-static {v13, v10}, Low0/a0;->b(Low0/z;Ljava/lang/String;)V

    .line 431
    .line 432
    .line 433
    invoke-static {v7, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 434
    .line 435
    .line 436
    iget-object v7, v7, Low0/b0;->d:Ljava/lang/String;

    .line 437
    .line 438
    const-string v14, "https"

    .line 439
    .line 440
    invoke-static {v7, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 441
    .line 442
    .line 443
    move-result v15

    .line 444
    const-string v4, "wss"

    .line 445
    .line 446
    if-nez v15, :cond_c

    .line 447
    .line 448
    invoke-static {v7, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 449
    .line 450
    .line 451
    move-result v7

    .line 452
    if-eqz v7, :cond_e

    .line 453
    .line 454
    :cond_c
    invoke-virtual {v13}, Low0/z;->d()Low0/b0;

    .line 455
    .line 456
    .line 457
    move-result-object v7

    .line 458
    invoke-static {v7, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 459
    .line 460
    .line 461
    iget-object v7, v7, Low0/b0;->d:Ljava/lang/String;

    .line 462
    .line 463
    invoke-static {v7, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 464
    .line 465
    .line 466
    move-result v9

    .line 467
    if-nez v9, :cond_e

    .line 468
    .line 469
    invoke-static {v7, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 470
    .line 471
    .line 472
    move-result v4

    .line 473
    if-eqz v4, :cond_d

    .line 474
    .line 475
    goto :goto_6

    .line 476
    :cond_d
    new-instance v0, Ljava/lang/StringBuilder;

    .line 477
    .line 478
    const-string v1, "Blocked redirect from "

    .line 479
    .line 480
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 481
    .line 482
    .line 483
    iget-object v1, v5, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 484
    .line 485
    check-cast v1, Law0/c;

    .line 486
    .line 487
    invoke-virtual {v1}, Law0/c;->c()Lkw0/b;

    .line 488
    .line 489
    .line 490
    move-result-object v1

    .line 491
    invoke-interface {v1}, Lkw0/b;->getUrl()Low0/f0;

    .line 492
    .line 493
    .line 494
    move-result-object v1

    .line 495
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 496
    .line 497
    .line 498
    const-string v1, " to "

    .line 499
    .line 500
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 501
    .line 502
    .line 503
    invoke-virtual {v0, v10}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 504
    .line 505
    .line 506
    const-string v1, " due to HTTPS downgrade"

    .line 507
    .line 508
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 509
    .line 510
    .line 511
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 512
    .line 513
    .line 514
    move-result-object v0

    .line 515
    invoke-interface {v11, v0}, Lt21/b;->h(Ljava/lang/String;)V

    .line 516
    .line 517
    .line 518
    iget-object v0, v5, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 519
    .line 520
    return-object v0

    .line 521
    :cond_e
    :goto_6
    invoke-static {v13}, Ljp/rc;->d(Low0/z;)Ljava/lang/String;

    .line 522
    .line 523
    .line 524
    move-result-object v4

    .line 525
    invoke-static {v8, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 526
    .line 527
    .line 528
    move-result v4

    .line 529
    if-nez v4, :cond_f

    .line 530
    .line 531
    iget-object v4, v12, Lkw0/c;->c:Low0/n;

    .line 532
    .line 533
    iget-object v4, v4, Lap0/o;->e:Ljava/lang/Object;

    .line 534
    .line 535
    check-cast v4, Ljava/util/Map;

    .line 536
    .line 537
    const-string v7, "Authorization"

    .line 538
    .line 539
    invoke-interface {v4, v7}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 540
    .line 541
    .line 542
    new-instance v4, Ljava/lang/StringBuilder;

    .line 543
    .line 544
    const-string v7, "Removing Authorization header for cross-authority redirect: "

    .line 545
    .line 546
    invoke-direct {v4, v7}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 547
    .line 548
    .line 549
    invoke-virtual {v4, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 550
    .line 551
    .line 552
    const-string v7, " -> "

    .line 553
    .line 554
    invoke-virtual {v4, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 555
    .line 556
    .line 557
    invoke-virtual {v13}, Low0/z;->c()Ljava/lang/String;

    .line 558
    .line 559
    .line 560
    move-result-object v7

    .line 561
    invoke-virtual {v4, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 562
    .line 563
    .line 564
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 565
    .line 566
    .line 567
    move-result-object v4

    .line 568
    invoke-interface {v11, v4}, Lt21/b;->h(Ljava/lang/String;)V

    .line 569
    .line 570
    .line 571
    :cond_f
    iput-object v12, v6, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 572
    .line 573
    iput-object v0, v3, Lfw0/d0;->d:Lgw0/h;

    .line 574
    .line 575
    iput-object v1, v3, Lfw0/d0;->e:Lzv0/c;

    .line 576
    .line 577
    iput-object v5, v3, Lfw0/d0;->f:Lkotlin/jvm/internal/f0;

    .line 578
    .line 579
    iput-object v6, v3, Lfw0/d0;->g:Lkotlin/jvm/internal/f0;

    .line 580
    .line 581
    iput-object v5, v3, Lfw0/d0;->h:Lkotlin/jvm/internal/f0;

    .line 582
    .line 583
    const/4 v4, 0x1

    .line 584
    iput v4, v3, Lfw0/d0;->j:I

    .line 585
    .line 586
    iget-object v7, v0, Lgw0/h;->d:Lfw0/e1;

    .line 587
    .line 588
    invoke-interface {v7, v12, v3}, Lfw0/e1;->a(Lkw0/c;Lrx0/c;)Ljava/lang/Object;

    .line 589
    .line 590
    .line 591
    move-result-object v7

    .line 592
    if-ne v7, v2, :cond_10

    .line 593
    .line 594
    return-object v2

    .line 595
    :cond_10
    move-object v8, v0

    .line 596
    move-object v0, v7

    .line 597
    move-object v7, v6

    .line 598
    move-object v6, v5

    .line 599
    move-object v5, v3

    .line 600
    move-object v3, v6

    .line 601
    :goto_7
    iput-object v0, v3, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 602
    .line 603
    move-object v3, v5

    .line 604
    move-object v5, v6

    .line 605
    move-object v6, v7

    .line 606
    move-object v0, v8

    .line 607
    goto/16 :goto_1
.end method
