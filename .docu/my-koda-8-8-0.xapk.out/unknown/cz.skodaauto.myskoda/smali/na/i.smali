.class public final Lna/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lyy0/j;

.field public final synthetic f:Z

.field public final synthetic g:Ljava/lang/Object;

.field public final synthetic h:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Lyy0/j;Lla/u;ZLay0/k;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lna/i;->d:I

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lna/i;->e:Lyy0/j;

    iput-object p2, p0, Lna/i;->g:Ljava/lang/Object;

    iput-boolean p3, p0, Lna/i;->f:Z

    iput-object p4, p0, Lna/i;->h:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lyy0/j;Lyb0/l;Lzb0/c;Z)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lna/i;->d:I

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lna/i;->e:Lyy0/j;

    iput-object p2, p0, Lna/i;->g:Ljava/lang/Object;

    iput-object p3, p0, Lna/i;->h:Ljava/lang/Object;

    iput-boolean p4, p0, Lna/i;->f:Z

    return-void
.end method


# virtual methods
.method public final emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 13

    .line 1
    iget v0, p0, Lna/i;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lna/i;->g:Ljava/lang/Object;

    .line 7
    .line 8
    move-object v1, v0

    .line 9
    check-cast v1, Lyb0/l;

    .line 10
    .line 11
    instance-of v0, p2, Lyb0/k;

    .line 12
    .line 13
    if-eqz v0, :cond_0

    .line 14
    .line 15
    move-object v0, p2

    .line 16
    check-cast v0, Lyb0/k;

    .line 17
    .line 18
    iget v2, v0, Lyb0/k;->e:I

    .line 19
    .line 20
    const/high16 v3, -0x80000000

    .line 21
    .line 22
    and-int v4, v2, v3

    .line 23
    .line 24
    if-eqz v4, :cond_0

    .line 25
    .line 26
    sub-int/2addr v2, v3

    .line 27
    iput v2, v0, Lyb0/k;->e:I

    .line 28
    .line 29
    :goto_0
    move-object p2, v0

    .line 30
    goto :goto_1

    .line 31
    :cond_0
    new-instance v0, Lyb0/k;

    .line 32
    .line 33
    invoke-direct {v0, p0, p2}, Lyb0/k;-><init>(Lna/i;Lkotlin/coroutines/Continuation;)V

    .line 34
    .line 35
    .line 36
    goto :goto_0

    .line 37
    :goto_1
    iget-object v0, p2, Lyb0/k;->d:Ljava/lang/Object;

    .line 38
    .line 39
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 40
    .line 41
    iget v3, p2, Lyb0/k;->e:I

    .line 42
    .line 43
    const/4 v4, 0x2

    .line 44
    const/4 v5, 0x1

    .line 45
    const/4 v6, 0x0

    .line 46
    if-eqz v3, :cond_3

    .line 47
    .line 48
    if-eq v3, v5, :cond_2

    .line 49
    .line 50
    if-ne v3, v4, :cond_1

    .line 51
    .line 52
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    goto/16 :goto_c

    .line 56
    .line 57
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 58
    .line 59
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 60
    .line 61
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    throw p0

    .line 65
    :cond_2
    iget p0, p2, Lyb0/k;->i:I

    .line 66
    .line 67
    iget-object p1, p2, Lyb0/k;->h:Lne0/e;

    .line 68
    .line 69
    iget-object v3, p2, Lyb0/k;->g:Lyy0/j;

    .line 70
    .line 71
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 72
    .line 73
    .line 74
    goto/16 :goto_a

    .line 75
    .line 76
    :cond_3
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 77
    .line 78
    .line 79
    check-cast p1, Lne0/t;

    .line 80
    .line 81
    const-string v0, "asyncMessage"

    .line 82
    .line 83
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 84
    .line 85
    .line 86
    instance-of v3, p1, Lne0/e;

    .line 87
    .line 88
    if-eqz v3, :cond_8

    .line 89
    .line 90
    :try_start_0
    move-object v0, p1

    .line 91
    check-cast v0, Lne0/e;

    .line 92
    .line 93
    iget-object v0, v0, Lne0/e;->a:Ljava/lang/Object;

    .line 94
    .line 95
    check-cast v0, Ldc0/a;

    .line 96
    .line 97
    invoke-static {v0}, Lwb0/b;->a(Ldc0/a;)Lcz/skodaauto/myskoda/library/asyncevent/data/AsyncEventDto;

    .line 98
    .line 99
    .line 100
    move-result-object v0

    .line 101
    if-eqz v0, :cond_6

    .line 102
    .line 103
    invoke-virtual {v0}, Lcz/skodaauto/myskoda/library/asyncevent/data/AsyncEventDto;->getTraceId()Ljava/lang/String;

    .line 104
    .line 105
    .line 106
    move-result-object v8

    .line 107
    invoke-virtual {v0}, Lcz/skodaauto/myskoda/library/asyncevent/data/AsyncEventDto;->getTimestamp()Ljava/time/OffsetDateTime;

    .line 108
    .line 109
    .line 110
    move-result-object v9

    .line 111
    invoke-virtual {v0}, Lcz/skodaauto/myskoda/library/asyncevent/data/AsyncEventDto;->getProducer()Ljava/lang/String;

    .line 112
    .line 113
    .line 114
    move-result-object v10

    .line 115
    invoke-virtual {v0}, Lcz/skodaauto/myskoda/library/asyncevent/data/AsyncEventDto;->getName()Ljava/lang/String;

    .line 116
    .line 117
    .line 118
    move-result-object v11

    .line 119
    invoke-virtual {v0}, Lcz/skodaauto/myskoda/library/asyncevent/data/AsyncEventDto;->getData()Ljava/lang/String;

    .line 120
    .line 121
    .line 122
    move-result-object v0

    .line 123
    if-eqz v0, :cond_4

    .line 124
    .line 125
    goto :goto_2

    .line 126
    :cond_4
    move-object v0, v6

    .line 127
    :goto_2
    if-eqz v0, :cond_5

    .line 128
    .line 129
    new-instance v7, Lzb0/b;

    .line 130
    .line 131
    invoke-direct {v7, v0}, Lzb0/b;-><init>(Ljava/lang/String;)V

    .line 132
    .line 133
    .line 134
    move-object v12, v7

    .line 135
    goto :goto_3

    .line 136
    :cond_5
    move-object v12, v6

    .line 137
    :goto_3
    new-instance v7, Lzb0/a;

    .line 138
    .line 139
    invoke-direct/range {v7 .. v12}, Lzb0/a;-><init>(Ljava/lang/String;Ljava/time/OffsetDateTime;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Object;)V

    .line 140
    .line 141
    .line 142
    goto :goto_4

    .line 143
    :cond_6
    move-object v7, v6

    .line 144
    :goto_4
    new-instance v0, Lne0/e;

    .line 145
    .line 146
    invoke-direct {v0, v7}, Lne0/e;-><init>(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 147
    .line 148
    .line 149
    goto :goto_5

    .line 150
    :catchall_0
    move-exception v0

    .line 151
    invoke-static {v0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 152
    .line 153
    .line 154
    move-result-object v0

    .line 155
    :goto_5
    invoke-static {v0}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 156
    .line 157
    .line 158
    move-result-object v8

    .line 159
    if-nez v8, :cond_7

    .line 160
    .line 161
    goto :goto_6

    .line 162
    :cond_7
    new-instance v7, Lne0/c;

    .line 163
    .line 164
    const/4 v11, 0x0

    .line 165
    const/16 v12, 0x1e

    .line 166
    .line 167
    const/4 v9, 0x0

    .line 168
    const/4 v10, 0x0

    .line 169
    invoke-direct/range {v7 .. v12}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 170
    .line 171
    .line 172
    move-object v0, v7

    .line 173
    :goto_6
    check-cast v0, Lne0/t;

    .line 174
    .line 175
    goto :goto_7

    .line 176
    :cond_8
    instance-of v0, p1, Lne0/c;

    .line 177
    .line 178
    if-eqz v0, :cond_10

    .line 179
    .line 180
    new-instance v7, Lne0/c;

    .line 181
    .line 182
    new-instance v8, Ljava/lang/IllegalStateException;

    .line 183
    .line 184
    const-string v0, "Unable to parse AsyncMessage because of error while observing AsyncMessage."

    .line 185
    .line 186
    invoke-direct {v8, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 187
    .line 188
    .line 189
    move-object v9, p1

    .line 190
    check-cast v9, Lne0/c;

    .line 191
    .line 192
    const/4 v11, 0x0

    .line 193
    const/16 v12, 0x1c

    .line 194
    .line 195
    const/4 v10, 0x0

    .line 196
    invoke-direct/range {v7 .. v12}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 197
    .line 198
    .line 199
    move-object v0, v7

    .line 200
    :goto_7
    iget-object v7, v1, Lyb0/l;->e:Lyb0/c;

    .line 201
    .line 202
    new-instance v8, Lyb0/b;

    .line 203
    .line 204
    iget-object v9, p0, Lna/i;->h:Ljava/lang/Object;

    .line 205
    .line 206
    check-cast v9, Lzb0/c;

    .line 207
    .line 208
    if-eqz v3, :cond_9

    .line 209
    .line 210
    move-object v10, p1

    .line 211
    check-cast v10, Lne0/e;

    .line 212
    .line 213
    goto :goto_8

    .line 214
    :cond_9
    move-object v10, v6

    .line 215
    :goto_8
    if-eqz v10, :cond_a

    .line 216
    .line 217
    iget-object v10, v10, Lne0/e;->a:Ljava/lang/Object;

    .line 218
    .line 219
    check-cast v10, Ldc0/a;

    .line 220
    .line 221
    goto :goto_9

    .line 222
    :cond_a
    move-object v10, v6

    .line 223
    :goto_9
    invoke-direct {v8, v9, v0, v10}, Lyb0/b;-><init>(Lzb0/c;Lne0/t;Ldc0/a;)V

    .line 224
    .line 225
    .line 226
    sget-object v9, Lge0/a;->d:Lge0/a;

    .line 227
    .line 228
    new-instance v10, Lws/b;

    .line 229
    .line 230
    const/16 v11, 0xc

    .line 231
    .line 232
    invoke-direct {v10, v11, v8, v7, v6}, Lws/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 233
    .line 234
    .line 235
    const/4 v7, 0x3

    .line 236
    invoke-static {v9, v6, v6, v10, v7}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 237
    .line 238
    .line 239
    instance-of v7, v0, Lne0/e;

    .line 240
    .line 241
    const/4 v8, 0x0

    .line 242
    iget-object v9, p0, Lna/i;->e:Lyy0/j;

    .line 243
    .line 244
    if-eqz v7, :cond_e

    .line 245
    .line 246
    move-object v7, v0

    .line 247
    check-cast v7, Lne0/e;

    .line 248
    .line 249
    iget-object v10, v7, Lne0/e;->a:Ljava/lang/Object;

    .line 250
    .line 251
    check-cast v10, Lzb0/a;

    .line 252
    .line 253
    iget-boolean p0, p0, Lna/i;->f:Z

    .line 254
    .line 255
    if-eqz p0, :cond_e

    .line 256
    .line 257
    if-eqz v3, :cond_e

    .line 258
    .line 259
    check-cast p1, Lne0/e;

    .line 260
    .line 261
    iget-object p0, p1, Lne0/e;->a:Ljava/lang/Object;

    .line 262
    .line 263
    check-cast p0, Ldc0/a;

    .line 264
    .line 265
    iget-object p1, p0, Ldc0/a;->b:Ljava/lang/String;

    .line 266
    .line 267
    if-eqz p1, :cond_e

    .line 268
    .line 269
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 270
    .line 271
    .line 272
    move-result p1

    .line 273
    if-nez p1, :cond_b

    .line 274
    .line 275
    goto :goto_b

    .line 276
    :cond_b
    iget-object p1, v1, Lyb0/l;->d:Lcc0/e;

    .line 277
    .line 278
    iget-object p0, p0, Ldc0/a;->a:Ljava/lang/String;

    .line 279
    .line 280
    iput-object v9, p2, Lyb0/k;->g:Lyy0/j;

    .line 281
    .line 282
    iput-object v7, p2, Lyb0/k;->h:Lne0/e;

    .line 283
    .line 284
    iput v8, p2, Lyb0/k;->i:I

    .line 285
    .line 286
    iput v5, p2, Lyb0/k;->e:I

    .line 287
    .line 288
    iget-object p1, p1, Lcc0/e;->a:Lcc0/a;

    .line 289
    .line 290
    check-cast p1, Lac0/w;

    .line 291
    .line 292
    iget-object v3, p1, Lac0/w;->j:Lpx0/g;

    .line 293
    .line 294
    new-instance v5, La60/f;

    .line 295
    .line 296
    const/4 v7, 0x4

    .line 297
    invoke-direct {v5, v7, p1, p0, v6}, La60/f;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 298
    .line 299
    .line 300
    invoke-static {v3, v5, p2}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 301
    .line 302
    .line 303
    move-result-object p0

    .line 304
    if-ne p0, v2, :cond_c

    .line 305
    .line 306
    goto :goto_d

    .line 307
    :cond_c
    move-object p1, v0

    .line 308
    move-object v3, v9

    .line 309
    move-object v0, p0

    .line 310
    move p0, v8

    .line 311
    :goto_a
    check-cast v0, Lne0/t;

    .line 312
    .line 313
    instance-of v5, v0, Lne0/c;

    .line 314
    .line 315
    if-eqz v5, :cond_d

    .line 316
    .line 317
    check-cast v0, Lne0/c;

    .line 318
    .line 319
    new-instance v5, Lam0/y;

    .line 320
    .line 321
    const/4 v7, 0x7

    .line 322
    invoke-direct {v5, v0, v7}, Lam0/y;-><init>(Lne0/c;I)V

    .line 323
    .line 324
    .line 325
    invoke-static {v6, v1, v5}, Llp/nd;->g(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 326
    .line 327
    .line 328
    :cond_d
    move v8, p0

    .line 329
    move-object v0, p1

    .line 330
    move-object v9, v3

    .line 331
    :cond_e
    :goto_b
    iput-object v6, p2, Lyb0/k;->g:Lyy0/j;

    .line 332
    .line 333
    iput-object v6, p2, Lyb0/k;->h:Lne0/e;

    .line 334
    .line 335
    iput v8, p2, Lyb0/k;->i:I

    .line 336
    .line 337
    iput v4, p2, Lyb0/k;->e:I

    .line 338
    .line 339
    invoke-interface {v9, v0, p2}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 340
    .line 341
    .line 342
    move-result-object p0

    .line 343
    if-ne p0, v2, :cond_f

    .line 344
    .line 345
    goto :goto_d

    .line 346
    :cond_f
    :goto_c
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 347
    .line 348
    :goto_d
    return-object v2

    .line 349
    :cond_10
    new-instance p0, La8/r0;

    .line 350
    .line 351
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 352
    .line 353
    .line 354
    throw p0

    .line 355
    :pswitch_0
    instance-of v0, p2, Lna/h;

    .line 356
    .line 357
    if-eqz v0, :cond_11

    .line 358
    .line 359
    move-object v0, p2

    .line 360
    check-cast v0, Lna/h;

    .line 361
    .line 362
    iget v1, v0, Lna/h;->e:I

    .line 363
    .line 364
    const/high16 v2, -0x80000000

    .line 365
    .line 366
    and-int v3, v1, v2

    .line 367
    .line 368
    if-eqz v3, :cond_11

    .line 369
    .line 370
    sub-int/2addr v1, v2

    .line 371
    iput v1, v0, Lna/h;->e:I

    .line 372
    .line 373
    goto :goto_e

    .line 374
    :cond_11
    new-instance v0, Lna/h;

    .line 375
    .line 376
    invoke-direct {v0, p0, p2}, Lna/h;-><init>(Lna/i;Lkotlin/coroutines/Continuation;)V

    .line 377
    .line 378
    .line 379
    :goto_e
    iget-object p2, v0, Lna/h;->d:Ljava/lang/Object;

    .line 380
    .line 381
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 382
    .line 383
    iget v2, v0, Lna/h;->e:I

    .line 384
    .line 385
    const/4 v3, 0x2

    .line 386
    const/4 v4, 0x1

    .line 387
    if-eqz v2, :cond_14

    .line 388
    .line 389
    if-eq v2, v4, :cond_13

    .line 390
    .line 391
    if-ne v2, v3, :cond_12

    .line 392
    .line 393
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 394
    .line 395
    .line 396
    goto :goto_10

    .line 397
    :cond_12
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 398
    .line 399
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 400
    .line 401
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 402
    .line 403
    .line 404
    throw p0

    .line 405
    :cond_13
    iget-object p0, v0, Lna/h;->f:Lyy0/j;

    .line 406
    .line 407
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 408
    .line 409
    .line 410
    goto :goto_f

    .line 411
    :cond_14
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 412
    .line 413
    .line 414
    check-cast p1, Ljava/util/Set;

    .line 415
    .line 416
    iget-object p1, p0, Lna/i;->g:Ljava/lang/Object;

    .line 417
    .line 418
    check-cast p1, Lla/u;

    .line 419
    .line 420
    iget-object p2, p0, Lna/i;->h:Ljava/lang/Object;

    .line 421
    .line 422
    check-cast p2, Lay0/k;

    .line 423
    .line 424
    iget-object v2, p0, Lna/i;->e:Lyy0/j;

    .line 425
    .line 426
    iput-object v2, v0, Lna/h;->f:Lyy0/j;

    .line 427
    .line 428
    iput v4, v0, Lna/h;->e:I

    .line 429
    .line 430
    iget-boolean p0, p0, Lna/i;->f:Z

    .line 431
    .line 432
    invoke-static {v0, p1, v4, p0, p2}, Ljp/ue;->h(Lkotlin/coroutines/Continuation;Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 433
    .line 434
    .line 435
    move-result-object p2

    .line 436
    if-ne p2, v1, :cond_15

    .line 437
    .line 438
    goto :goto_11

    .line 439
    :cond_15
    move-object p0, v2

    .line 440
    :goto_f
    const/4 p1, 0x0

    .line 441
    iput-object p1, v0, Lna/h;->f:Lyy0/j;

    .line 442
    .line 443
    iput v3, v0, Lna/h;->e:I

    .line 444
    .line 445
    invoke-interface {p0, p2, v0}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 446
    .line 447
    .line 448
    move-result-object p0

    .line 449
    if-ne p0, v1, :cond_16

    .line 450
    .line 451
    goto :goto_11

    .line 452
    :cond_16
    :goto_10
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 453
    .line 454
    :goto_11
    return-object v1

    .line 455
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
