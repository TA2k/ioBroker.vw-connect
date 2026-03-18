.class public final synthetic Leb/d0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;

.field public final synthetic f:Ljava/lang/Object;

.field public final synthetic g:Ljava/lang/Object;

.field public final synthetic h:Ljava/lang/Object;

.field public final synthetic i:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Lg4/p0;Lt4/m;Ljava/lang/String;Lt4/c;Lk4/m;)V
    .locals 1

    .line 1
    const/4 v0, 0x3

    iput v0, p0, Leb/d0;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Leb/d0;->e:Ljava/lang/Object;

    iput-object p2, p0, Leb/d0;->g:Ljava/lang/Object;

    iput-object p3, p0, Leb/d0;->f:Ljava/lang/Object;

    iput-object p4, p0, Leb/d0;->h:Ljava/lang/Object;

    iput-object p5, p0, Leb/d0;->i:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V
    .locals 0

    .line 2
    iput p6, p0, Leb/d0;->d:I

    iput-object p1, p0, Leb/d0;->e:Ljava/lang/Object;

    iput-object p2, p0, Leb/d0;->f:Ljava/lang/Object;

    iput-object p3, p0, Leb/d0;->g:Ljava/lang/Object;

    iput-object p4, p0, Leb/d0;->h:Ljava/lang/Object;

    iput-object p5, p0, Leb/d0;->i:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 14

    .line 1
    iget v0, p0, Leb/d0;->d:I

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    const/4 v2, 0x0

    .line 5
    iget-object v3, p0, Leb/d0;->i:Ljava/lang/Object;

    .line 6
    .line 7
    iget-object v4, p0, Leb/d0;->h:Ljava/lang/Object;

    .line 8
    .line 9
    iget-object v5, p0, Leb/d0;->g:Ljava/lang/Object;

    .line 10
    .line 11
    iget-object v6, p0, Leb/d0;->f:Ljava/lang/Object;

    .line 12
    .line 13
    iget-object p0, p0, Leb/d0;->e:Ljava/lang/Object;

    .line 14
    .line 15
    packed-switch v0, :pswitch_data_0

    .line 16
    .line 17
    .line 18
    check-cast p0, Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 19
    .line 20
    move-object v9, v6

    .line 21
    check-cast v9, Lc91/x;

    .line 22
    .line 23
    move-object v8, v5

    .line 24
    check-cast v8, Lz81/l;

    .line 25
    .line 26
    iget-object v0, v8, Lz81/l;->k:Lpx0/g;

    .line 27
    .line 28
    iget-object v5, v8, Lz81/l;->j:Lro/f;

    .line 29
    .line 30
    check-cast v4, Ljava/util/List;

    .line 31
    .line 32
    check-cast v3, Ljava/util/List;

    .line 33
    .line 34
    invoke-virtual {p0}, Lio/opentelemetry/sdk/common/CompletableResultCode;->isSuccess()Z

    .line 35
    .line 36
    .line 37
    move-result p0

    .line 38
    const/4 v11, 0x0

    .line 39
    if-nez p0, :cond_3

    .line 40
    .line 41
    iget p0, v9, Lc91/x;->d:I

    .line 42
    .line 43
    add-int/lit8 v10, p0, 0x1

    .line 44
    .line 45
    check-cast v4, Ljava/util/Collection;

    .line 46
    .line 47
    invoke-static {v8, v4}, Lz81/l;->b(Lz81/l;Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 52
    .line 53
    .line 54
    iget-object v1, v5, Lro/f;->e:Ljava/lang/Object;

    .line 55
    .line 56
    check-cast v1, Lz81/f;

    .line 57
    .line 58
    sget-object v4, Lz81/f;->d:Lz81/f;

    .line 59
    .line 60
    invoke-virtual {v1, v4}, Ljava/lang/Enum;->compareTo(Ljava/lang/Enum;)I

    .line 61
    .line 62
    .line 63
    move-result v1

    .line 64
    if-lez v1, :cond_0

    .line 65
    .line 66
    sget-object v1, Lx51/c;->o1:Lx51/b;

    .line 67
    .line 68
    iget-object v4, v1, Lx51/b;->d:La61/a;

    .line 69
    .line 70
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 71
    .line 72
    .line 73
    iget-object v4, v5, Lro/f;->e:Ljava/lang/Object;

    .line 74
    .line 75
    check-cast v4, Lz81/f;

    .line 76
    .line 77
    sget-object v6, Lz81/f;->e:Lz81/f;

    .line 78
    .line 79
    invoke-virtual {v4, v6}, Ljava/lang/Enum;->compareTo(Ljava/lang/Enum;)I

    .line 80
    .line 81
    .line 82
    move-result v4

    .line 83
    if-lez v4, :cond_0

    .line 84
    .line 85
    iget-object v1, v1, Lx51/b;->d:La61/a;

    .line 86
    .line 87
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 88
    .line 89
    .line 90
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 91
    .line 92
    .line 93
    move-result-object p0

    .line 94
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 95
    .line 96
    .line 97
    move-result v1

    .line 98
    if-eqz v1, :cond_0

    .line 99
    .line 100
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 101
    .line 102
    .line 103
    move-result-object v1

    .line 104
    check-cast v1, Ljava/lang/String;

    .line 105
    .line 106
    sget-object v1, Lx51/c;->o1:Lx51/b;

    .line 107
    .line 108
    iget-object v1, v1, Lx51/b;->d:La61/a;

    .line 109
    .line 110
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 111
    .line 112
    .line 113
    goto :goto_0

    .line 114
    :cond_0
    iget p0, v8, Lz81/l;->g:I

    .line 115
    .line 116
    if-lt v10, p0, :cond_2

    .line 117
    .line 118
    check-cast v3, Ljava/util/Collection;

    .line 119
    .line 120
    invoke-static {v3}, Lz81/l;->a(Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 121
    .line 122
    .line 123
    move-result-object p0

    .line 124
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 125
    .line 126
    .line 127
    iget-object v1, v5, Lro/f;->e:Ljava/lang/Object;

    .line 128
    .line 129
    check-cast v1, Lz81/f;

    .line 130
    .line 131
    sget-object v3, Lz81/f;->d:Lz81/f;

    .line 132
    .line 133
    invoke-virtual {v1, v3}, Ljava/lang/Enum;->compareTo(Ljava/lang/Enum;)I

    .line 134
    .line 135
    .line 136
    move-result v1

    .line 137
    if-lez v1, :cond_1

    .line 138
    .line 139
    sget-object v1, Lx51/c;->o1:Lx51/b;

    .line 140
    .line 141
    iget-object v3, v1, Lx51/b;->d:La61/a;

    .line 142
    .line 143
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 144
    .line 145
    .line 146
    iget-object v3, v5, Lro/f;->e:Ljava/lang/Object;

    .line 147
    .line 148
    check-cast v3, Lz81/f;

    .line 149
    .line 150
    sget-object v4, Lz81/f;->e:Lz81/f;

    .line 151
    .line 152
    invoke-virtual {v3, v4}, Ljava/lang/Enum;->compareTo(Ljava/lang/Enum;)I

    .line 153
    .line 154
    .line 155
    move-result v3

    .line 156
    if-lez v3, :cond_1

    .line 157
    .line 158
    iget-object v1, v1, Lx51/b;->d:La61/a;

    .line 159
    .line 160
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 161
    .line 162
    .line 163
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 164
    .line 165
    .line 166
    move-result-object p0

    .line 167
    :goto_1
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 168
    .line 169
    .line 170
    move-result v1

    .line 171
    if-eqz v1, :cond_1

    .line 172
    .line 173
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 174
    .line 175
    .line 176
    move-result-object v1

    .line 177
    check-cast v1, Ljava/lang/String;

    .line 178
    .line 179
    sget-object v1, Lx51/c;->o1:Lx51/b;

    .line 180
    .line 181
    iget-object v1, v1, Lx51/b;->d:La61/a;

    .line 182
    .line 183
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 184
    .line 185
    .line 186
    goto :goto_1

    .line 187
    :cond_1
    new-instance p0, Lz81/k;

    .line 188
    .line 189
    invoke-direct {p0, v8, v9, v11, v2}, Lz81/k;-><init>(Lz81/l;Lc91/x;Lkotlin/coroutines/Continuation;I)V

    .line 190
    .line 191
    .line 192
    invoke-static {v0, p0}, Lvy0/e0;->K(Lpx0/g;Lay0/n;)Ljava/lang/Object;

    .line 193
    .line 194
    .line 195
    goto :goto_3

    .line 196
    :cond_2
    new-instance v7, La7/y0;

    .line 197
    .line 198
    const/16 v12, 0xa

    .line 199
    .line 200
    invoke-direct/range {v7 .. v12}, La7/y0;-><init>(Ljava/lang/Object;Ljava/lang/Object;ILkotlin/coroutines/Continuation;I)V

    .line 201
    .line 202
    .line 203
    invoke-static {v0, v7}, Lvy0/e0;->K(Lpx0/g;Lay0/n;)Ljava/lang/Object;

    .line 204
    .line 205
    .line 206
    goto :goto_3

    .line 207
    :cond_3
    iget-object p0, v9, Lc91/x;->b:Ljava/util/List;

    .line 208
    .line 209
    check-cast p0, Ljava/util/Collection;

    .line 210
    .line 211
    invoke-static {p0}, Lz81/l;->a(Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 212
    .line 213
    .line 214
    move-result-object p0

    .line 215
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 216
    .line 217
    .line 218
    iget-object v2, v5, Lro/f;->e:Ljava/lang/Object;

    .line 219
    .line 220
    check-cast v2, Lz81/f;

    .line 221
    .line 222
    sget-object v3, Lz81/f;->d:Lz81/f;

    .line 223
    .line 224
    invoke-virtual {v2, v3}, Ljava/lang/Enum;->compareTo(Ljava/lang/Enum;)I

    .line 225
    .line 226
    .line 227
    move-result v2

    .line 228
    if-lez v2, :cond_4

    .line 229
    .line 230
    sget-object v2, Lx51/c;->o1:Lx51/b;

    .line 231
    .line 232
    iget-object v3, v2, Lx51/b;->d:La61/a;

    .line 233
    .line 234
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 235
    .line 236
    .line 237
    iget-object v3, v5, Lro/f;->e:Ljava/lang/Object;

    .line 238
    .line 239
    check-cast v3, Lz81/f;

    .line 240
    .line 241
    sget-object v4, Lz81/f;->e:Lz81/f;

    .line 242
    .line 243
    invoke-virtual {v3, v4}, Ljava/lang/Enum;->compareTo(Ljava/lang/Enum;)I

    .line 244
    .line 245
    .line 246
    move-result v3

    .line 247
    if-lez v3, :cond_4

    .line 248
    .line 249
    iget-object v2, v2, Lx51/b;->d:La61/a;

    .line 250
    .line 251
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 252
    .line 253
    .line 254
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 255
    .line 256
    .line 257
    move-result-object p0

    .line 258
    :goto_2
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 259
    .line 260
    .line 261
    move-result v2

    .line 262
    if-eqz v2, :cond_4

    .line 263
    .line 264
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 265
    .line 266
    .line 267
    move-result-object v2

    .line 268
    check-cast v2, Ljava/lang/String;

    .line 269
    .line 270
    sget-object v2, Lx51/c;->o1:Lx51/b;

    .line 271
    .line 272
    iget-object v2, v2, Lx51/b;->d:La61/a;

    .line 273
    .line 274
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 275
    .line 276
    .line 277
    goto :goto_2

    .line 278
    :cond_4
    new-instance p0, Lz81/k;

    .line 279
    .line 280
    invoke-direct {p0, v8, v9, v11, v1}, Lz81/k;-><init>(Lz81/l;Lc91/x;Lkotlin/coroutines/Continuation;I)V

    .line 281
    .line 282
    .line 283
    invoke-static {v0, p0}, Lvy0/e0;->K(Lpx0/g;Lay0/n;)Ljava/lang/Object;

    .line 284
    .line 285
    .line 286
    :goto_3
    return-void

    .line 287
    :pswitch_0
    check-cast p0, Lg4/p0;

    .line 288
    .line 289
    check-cast v5, Lt4/m;

    .line 290
    .line 291
    move-object v8, v6

    .line 292
    check-cast v8, Ljava/lang/String;

    .line 293
    .line 294
    move-object v13, v4

    .line 295
    check-cast v13, Lt4/c;

    .line 296
    .line 297
    move-object v12, v3

    .line 298
    check-cast v12, Lk4/m;

    .line 299
    .line 300
    const-string v0, "BackgroundTextMeasurement"

    .line 301
    .line 302
    invoke-static {v0}, Landroid/os/Trace;->beginSection(Ljava/lang/String;)V

    .line 303
    .line 304
    .line 305
    :try_start_0
    invoke-static {}, Lv2/l;->k()Lv2/f;

    .line 306
    .line 307
    .line 308
    move-result-object v0

    .line 309
    instance-of v1, v0, Lv2/b;

    .line 310
    .line 311
    const/4 v2, 0x0

    .line 312
    if-eqz v1, :cond_5

    .line 313
    .line 314
    check-cast v0, Lv2/b;

    .line 315
    .line 316
    goto :goto_4

    .line 317
    :cond_5
    move-object v0, v2

    .line 318
    :goto_4
    if-eqz v0, :cond_6

    .line 319
    .line 320
    invoke-virtual {v0, v2, v2}, Lv2/b;->C(Lay0/k;Lay0/k;)Lv2/b;

    .line 321
    .line 322
    .line 323
    move-result-object v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_3

    .line 324
    if-eqz v1, :cond_6

    .line 325
    .line 326
    :try_start_1
    invoke-virtual {v1}, Lv2/f;->j()Lv2/f;

    .line 327
    .line 328
    .line 329
    move-result-object v2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 330
    :try_start_2
    invoke-static {p0, v5}, Lg4/f0;->h(Lg4/p0;Lt4/m;)Lg4/p0;

    .line 331
    .line 332
    .line 333
    move-result-object v9

    .line 334
    sget-object v10, Lmx0/s;->d:Lmx0/s;

    .line 335
    .line 336
    new-instance v7, Lo4/c;

    .line 337
    .line 338
    move-object v11, v10

    .line 339
    invoke-direct/range {v7 .. v13}, Lo4/c;-><init>(Ljava/lang/String;Lg4/p0;Ljava/util/List;Ljava/util/List;Lk4/m;Lt4/c;)V

    .line 340
    .line 341
    .line 342
    invoke-virtual {v7}, Lo4/c;->b()F
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 343
    .line 344
    .line 345
    :try_start_3
    invoke-static {v2}, Lv2/f;->q(Lv2/f;)V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 346
    .line 347
    .line 348
    :try_start_4
    invoke-virtual {v1}, Lv2/b;->w()Lv2/p;

    .line 349
    .line 350
    .line 351
    move-result-object p0

    .line 352
    invoke-virtual {p0}, Lv2/p;->d()V

    .line 353
    .line 354
    .line 355
    invoke-virtual {v1}, Lv2/b;->c()V
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_3

    .line 356
    .line 357
    .line 358
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 359
    .line 360
    .line 361
    return-void

    .line 362
    :catchall_0
    move-exception v0

    .line 363
    move-object p0, v0

    .line 364
    goto :goto_5

    .line 365
    :catchall_1
    move-exception v0

    .line 366
    move-object p0, v0

    .line 367
    :try_start_5
    invoke-static {v2}, Lv2/f;->q(Lv2/f;)V

    .line 368
    .line 369
    .line 370
    throw p0
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_0

    .line 371
    :goto_5
    :try_start_6
    throw p0
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_2

    .line 372
    :catchall_2
    move-exception v0

    .line 373
    move-object p0, v0

    .line 374
    :try_start_7
    invoke-virtual {v1}, Lv2/b;->c()V

    .line 375
    .line 376
    .line 377
    throw p0

    .line 378
    :catchall_3
    move-exception v0

    .line 379
    move-object p0, v0

    .line 380
    goto :goto_6

    .line 381
    :cond_6
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 382
    .line 383
    const-string v0, "Cannot create a mutable snapshot of an read-only snapshot"

    .line 384
    .line 385
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 386
    .line 387
    .line 388
    throw p0
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_3

    .line 389
    :goto_6
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 390
    .line 391
    .line 392
    throw p0

    .line 393
    :pswitch_1
    check-cast p0, Lcom/google/common/util/concurrent/ListenableFuture;

    .line 394
    .line 395
    check-cast v6, Landroidx/lifecycle/x;

    .line 396
    .line 397
    check-cast v5, Lw0/i;

    .line 398
    .line 399
    check-cast v4, Ljava/util/concurrent/Executor;

    .line 400
    .line 401
    check-cast v3, Lb0/d0;

    .line 402
    .line 403
    invoke-interface {p0}, Ljava/util/concurrent/Future;->get()Ljava/lang/Object;

    .line 404
    .line 405
    .line 406
    move-result-object p0

    .line 407
    check-cast p0, Lv0/f;

    .line 408
    .line 409
    new-instance v0, Lb0/h1;

    .line 410
    .line 411
    invoke-direct {v0, v2}, Lb0/h1;-><init>(I)V

    .line 412
    .line 413
    .line 414
    invoke-virtual {v0}, Lb0/h1;->c()Lb0/k1;

    .line 415
    .line 416
    .line 417
    move-result-object v0

    .line 418
    invoke-virtual {v5}, Lw0/i;->getSurfaceProvider()Lb0/j1;

    .line 419
    .line 420
    .line 421
    move-result-object v5

    .line 422
    invoke-virtual {v0, v5}, Lb0/k1;->E(Lb0/j1;)V

    .line 423
    .line 424
    .line 425
    new-instance v5, Ljava/util/LinkedHashSet;

    .line 426
    .line 427
    invoke-direct {v5}, Ljava/util/LinkedHashSet;-><init>()V

    .line 428
    .line 429
    .line 430
    new-instance v7, Lh0/e1;

    .line 431
    .line 432
    invoke-direct {v7, v1}, Lh0/e1;-><init>(I)V

    .line 433
    .line 434
    .line 435
    invoke-virtual {v5, v7}, Ljava/util/AbstractCollection;->add(Ljava/lang/Object;)Z

    .line 436
    .line 437
    .line 438
    new-instance v7, Lb0/r;

    .line 439
    .line 440
    invoke-direct {v7, v5}, Lb0/r;-><init>(Ljava/util/LinkedHashSet;)V

    .line 441
    .line 442
    .line 443
    new-instance v5, Lb0/f0;

    .line 444
    .line 445
    invoke-direct {v5, v2}, Lb0/f0;-><init>(I)V

    .line 446
    .line 447
    .line 448
    sget-object v8, Lh0/x0;->e:Lh0/g;

    .line 449
    .line 450
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 451
    .line 452
    .line 453
    move-result-object v9

    .line 454
    iget-object v5, v5, Lb0/f0;->b:Lh0/j1;

    .line 455
    .line 456
    invoke-virtual {v5, v8, v9}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 457
    .line 458
    .line 459
    new-instance v8, Lh0/x0;

    .line 460
    .line 461
    invoke-static {v5}, Lh0/n1;->a(Lh0/q0;)Lh0/n1;

    .line 462
    .line 463
    .line 464
    move-result-object v5

    .line 465
    invoke-direct {v8, v5}, Lh0/x0;-><init>(Lh0/n1;)V

    .line 466
    .line 467
    .line 468
    invoke-static {v8}, Lh0/a1;->L(Lh0/a1;)V

    .line 469
    .line 470
    .line 471
    new-instance v5, Lb0/i0;

    .line 472
    .line 473
    invoke-direct {v5, v8}, Lb0/i0;-><init>(Lh0/x0;)V

    .line 474
    .line 475
    .line 476
    invoke-virtual {v5, v4, v3}, Lb0/i0;->G(Ljava/util/concurrent/Executor;Lb0/d0;)V

    .line 477
    .line 478
    .line 479
    iget-object v3, p0, Lv0/f;->a:Lcom/google/android/material/datepicker/d;

    .line 480
    .line 481
    invoke-virtual {v3}, Lcom/google/android/material/datepicker/d;->h()V

    .line 482
    .line 483
    .line 484
    const/4 v3, 0x2

    .line 485
    new-array v3, v3, [Lb0/z1;

    .line 486
    .line 487
    aput-object v5, v3, v2

    .line 488
    .line 489
    aput-object v0, v3, v1

    .line 490
    .line 491
    invoke-virtual {p0, v6, v7, v3}, Lv0/f;->a(Landroidx/lifecycle/x;Lb0/r;[Lb0/z1;)V

    .line 492
    .line 493
    .line 494
    return-void

    .line 495
    :pswitch_2
    check-cast p0, Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 496
    .line 497
    check-cast v6, Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 498
    .line 499
    check-cast v5, Ljava/util/concurrent/atomic/AtomicReference;

    .line 500
    .line 501
    check-cast v4, Ljava/util/concurrent/atomic/AtomicInteger;

    .line 502
    .line 503
    check-cast v3, Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 504
    .line 505
    invoke-static {p0, v6, v5, v4, v3}, Lio/opentelemetry/sdk/common/CompletableResultCode;->a(Lio/opentelemetry/sdk/common/CompletableResultCode;Ljava/util/concurrent/atomic/AtomicBoolean;Ljava/util/concurrent/atomic/AtomicReference;Ljava/util/concurrent/atomic/AtomicInteger;Lio/opentelemetry/sdk/common/CompletableResultCode;)V

    .line 506
    .line 507
    .line 508
    return-void

    .line 509
    :pswitch_3
    check-cast p0, Leb/j;

    .line 510
    .line 511
    check-cast v6, Ljava/lang/String;

    .line 512
    .line 513
    check-cast v5, Lay0/a;

    .line 514
    .line 515
    check-cast v4, Landroidx/lifecycle/i0;

    .line 516
    .line 517
    check-cast v3, Ly4/h;

    .line 518
    .line 519
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 520
    .line 521
    .line 522
    invoke-static {}, Lab/a;->a()Z

    .line 523
    .line 524
    .line 525
    move-result p0

    .line 526
    if-eqz p0, :cond_7

    .line 527
    .line 528
    :try_start_8
    const-string v0, "label"

    .line 529
    .line 530
    invoke-static {v6, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 531
    .line 532
    .line 533
    invoke-static {v6}, Ljp/x0;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 534
    .line 535
    .line 536
    move-result-object v0

    .line 537
    invoke-static {v0}, Landroid/os/Trace;->beginSection(Ljava/lang/String;)V
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_5

    .line 538
    .line 539
    .line 540
    :cond_7
    :try_start_9
    invoke-interface {v5}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 541
    .line 542
    .line 543
    sget-object v0, Leb/c0;->b:Leb/b0;

    .line 544
    .line 545
    invoke-virtual {v4, v0}, Landroidx/lifecycle/i0;->k(Ljava/lang/Object;)V

    .line 546
    .line 547
    .line 548
    invoke-virtual {v3, v0}, Ly4/h;->b(Ljava/lang/Object;)Z
    :try_end_9
    .catchall {:try_start_9 .. :try_end_9} :catchall_4

    .line 549
    .line 550
    .line 551
    goto :goto_7

    .line 552
    :catchall_4
    move-exception v0

    .line 553
    :try_start_a
    new-instance v1, Leb/a0;

    .line 554
    .line 555
    invoke-direct {v1, v0}, Leb/a0;-><init>(Ljava/lang/Throwable;)V

    .line 556
    .line 557
    .line 558
    invoke-virtual {v4, v1}, Landroidx/lifecycle/i0;->k(Ljava/lang/Object;)V

    .line 559
    .line 560
    .line 561
    invoke-virtual {v3, v0}, Ly4/h;->d(Ljava/lang/Throwable;)Z
    :try_end_a
    .catchall {:try_start_a .. :try_end_a} :catchall_5

    .line 562
    .line 563
    .line 564
    :goto_7
    if-eqz p0, :cond_8

    .line 565
    .line 566
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 567
    .line 568
    .line 569
    :cond_8
    return-void

    .line 570
    :catchall_5
    move-exception v0

    .line 571
    if-eqz p0, :cond_9

    .line 572
    .line 573
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 574
    .line 575
    .line 576
    :cond_9
    throw v0

    .line 577
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
