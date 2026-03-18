.class public final synthetic Lc8/r;
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


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p5, p0, Lc8/r;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lc8/r;->e:Ljava/lang/Object;

    .line 4
    .line 5
    iput-object p2, p0, Lc8/r;->f:Ljava/lang/Object;

    .line 6
    .line 7
    iput-object p3, p0, Lc8/r;->g:Ljava/lang/Object;

    .line 8
    .line 9
    iput-object p4, p0, Lc8/r;->h:Ljava/lang/Object;

    .line 10
    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final run()V
    .locals 10

    .line 1
    iget v0, p0, Lc8/r;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lc8/r;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 9
    .line 10
    iget-object v1, p0, Lc8/r;->f:Ljava/lang/Object;

    .line 11
    .line 12
    move-object v4, v1

    .line 13
    check-cast v4, Lc91/a0;

    .line 14
    .line 15
    iget-object v1, v4, Lc91/a0;->b:Ljava/util/List;

    .line 16
    .line 17
    iget-object v2, p0, Lc8/r;->g:Ljava/lang/Object;

    .line 18
    .line 19
    move-object v3, v2

    .line 20
    check-cast v3, Lz81/o;

    .line 21
    .line 22
    iget-object v8, v3, Lz81/o;->k:Lpx0/g;

    .line 23
    .line 24
    iget-object v2, v3, Lz81/o;->j:Lro/f;

    .line 25
    .line 26
    iget-object p0, p0, Lc8/r;->h:Ljava/lang/Object;

    .line 27
    .line 28
    check-cast p0, Ljava/util/List;

    .line 29
    .line 30
    invoke-virtual {v0}, Lio/opentelemetry/sdk/common/CompletableResultCode;->isSuccess()Z

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    const/4 v6, 0x0

    .line 35
    if-nez v0, :cond_3

    .line 36
    .line 37
    iget v0, v4, Lc91/a0;->d:I

    .line 38
    .line 39
    add-int/lit8 v5, v0, 0x1

    .line 40
    .line 41
    check-cast v1, Ljava/util/Collection;

    .line 42
    .line 43
    invoke-static {v1}, Lis0/b;->c(Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 44
    .line 45
    .line 46
    move-result-object v0

    .line 47
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 48
    .line 49
    .line 50
    iget-object v1, v2, Lro/f;->e:Ljava/lang/Object;

    .line 51
    .line 52
    check-cast v1, Lz81/f;

    .line 53
    .line 54
    sget-object v7, Lz81/f;->d:Lz81/f;

    .line 55
    .line 56
    invoke-virtual {v1, v7}, Ljava/lang/Enum;->compareTo(Ljava/lang/Enum;)I

    .line 57
    .line 58
    .line 59
    move-result v1

    .line 60
    if-lez v1, :cond_0

    .line 61
    .line 62
    sget-object v1, Lx51/c;->o1:Lx51/b;

    .line 63
    .line 64
    iget-object v7, v1, Lx51/b;->d:La61/a;

    .line 65
    .line 66
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 67
    .line 68
    .line 69
    iget-object v7, v2, Lro/f;->e:Ljava/lang/Object;

    .line 70
    .line 71
    check-cast v7, Lz81/f;

    .line 72
    .line 73
    sget-object v9, Lz81/f;->e:Lz81/f;

    .line 74
    .line 75
    invoke-virtual {v7, v9}, Ljava/lang/Enum;->compareTo(Ljava/lang/Enum;)I

    .line 76
    .line 77
    .line 78
    move-result v7

    .line 79
    if-lez v7, :cond_0

    .line 80
    .line 81
    iget-object v1, v1, Lx51/b;->d:La61/a;

    .line 82
    .line 83
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 84
    .line 85
    .line 86
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 87
    .line 88
    .line 89
    move-result-object v0

    .line 90
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 91
    .line 92
    .line 93
    move-result v1

    .line 94
    if-eqz v1, :cond_0

    .line 95
    .line 96
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 97
    .line 98
    .line 99
    move-result-object v1

    .line 100
    check-cast v1, Ljava/lang/String;

    .line 101
    .line 102
    sget-object v1, Lx51/c;->o1:Lx51/b;

    .line 103
    .line 104
    iget-object v1, v1, Lx51/b;->d:La61/a;

    .line 105
    .line 106
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 107
    .line 108
    .line 109
    goto :goto_0

    .line 110
    :cond_0
    iget v0, v3, Lz81/o;->g:I

    .line 111
    .line 112
    if-lt v5, v0, :cond_2

    .line 113
    .line 114
    check-cast p0, Ljava/util/Collection;

    .line 115
    .line 116
    invoke-static {p0}, Lis0/b;->c(Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 117
    .line 118
    .line 119
    move-result-object p0

    .line 120
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 121
    .line 122
    .line 123
    iget-object v0, v2, Lro/f;->e:Ljava/lang/Object;

    .line 124
    .line 125
    check-cast v0, Lz81/f;

    .line 126
    .line 127
    sget-object v1, Lz81/f;->d:Lz81/f;

    .line 128
    .line 129
    invoke-virtual {v0, v1}, Ljava/lang/Enum;->compareTo(Ljava/lang/Enum;)I

    .line 130
    .line 131
    .line 132
    move-result v0

    .line 133
    if-lez v0, :cond_1

    .line 134
    .line 135
    sget-object v0, Lx51/c;->o1:Lx51/b;

    .line 136
    .line 137
    iget-object v1, v0, Lx51/b;->d:La61/a;

    .line 138
    .line 139
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 140
    .line 141
    .line 142
    iget-object v1, v2, Lro/f;->e:Ljava/lang/Object;

    .line 143
    .line 144
    check-cast v1, Lz81/f;

    .line 145
    .line 146
    sget-object v2, Lz81/f;->e:Lz81/f;

    .line 147
    .line 148
    invoke-virtual {v1, v2}, Ljava/lang/Enum;->compareTo(Ljava/lang/Enum;)I

    .line 149
    .line 150
    .line 151
    move-result v1

    .line 152
    if-lez v1, :cond_1

    .line 153
    .line 154
    iget-object v0, v0, Lx51/b;->d:La61/a;

    .line 155
    .line 156
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 157
    .line 158
    .line 159
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 160
    .line 161
    .line 162
    move-result-object p0

    .line 163
    :goto_1
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 164
    .line 165
    .line 166
    move-result v0

    .line 167
    if-eqz v0, :cond_1

    .line 168
    .line 169
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 170
    .line 171
    .line 172
    move-result-object v0

    .line 173
    check-cast v0, Ljava/lang/String;

    .line 174
    .line 175
    sget-object v0, Lx51/c;->o1:Lx51/b;

    .line 176
    .line 177
    iget-object v0, v0, Lx51/b;->d:La61/a;

    .line 178
    .line 179
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 180
    .line 181
    .line 182
    goto :goto_1

    .line 183
    :cond_1
    new-instance p0, Lz81/n;

    .line 184
    .line 185
    const/4 v0, 0x0

    .line 186
    invoke-direct {p0, v3, v4, v6, v0}, Lz81/n;-><init>(Lz81/o;Lc91/a0;Lkotlin/coroutines/Continuation;I)V

    .line 187
    .line 188
    .line 189
    invoke-static {v8, p0}, Lvy0/e0;->K(Lpx0/g;Lay0/n;)Ljava/lang/Object;

    .line 190
    .line 191
    .line 192
    goto :goto_3

    .line 193
    :cond_2
    new-instance v2, La7/y0;

    .line 194
    .line 195
    const/16 v7, 0xb

    .line 196
    .line 197
    invoke-direct/range {v2 .. v7}, La7/y0;-><init>(Ljava/lang/Object;Ljava/lang/Object;ILkotlin/coroutines/Continuation;I)V

    .line 198
    .line 199
    .line 200
    invoke-static {v8, v2}, Lvy0/e0;->K(Lpx0/g;Lay0/n;)Ljava/lang/Object;

    .line 201
    .line 202
    .line 203
    goto :goto_3

    .line 204
    :cond_3
    check-cast v1, Ljava/util/Collection;

    .line 205
    .line 206
    invoke-static {v1}, Lis0/b;->c(Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 207
    .line 208
    .line 209
    move-result-object p0

    .line 210
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 211
    .line 212
    .line 213
    iget-object v0, v2, Lro/f;->e:Ljava/lang/Object;

    .line 214
    .line 215
    check-cast v0, Lz81/f;

    .line 216
    .line 217
    sget-object v1, Lz81/f;->d:Lz81/f;

    .line 218
    .line 219
    invoke-virtual {v0, v1}, Ljava/lang/Enum;->compareTo(Ljava/lang/Enum;)I

    .line 220
    .line 221
    .line 222
    move-result v0

    .line 223
    if-lez v0, :cond_4

    .line 224
    .line 225
    sget-object v0, Lx51/c;->o1:Lx51/b;

    .line 226
    .line 227
    iget-object v1, v0, Lx51/b;->d:La61/a;

    .line 228
    .line 229
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 230
    .line 231
    .line 232
    iget-object v1, v2, Lro/f;->e:Ljava/lang/Object;

    .line 233
    .line 234
    check-cast v1, Lz81/f;

    .line 235
    .line 236
    sget-object v2, Lz81/f;->e:Lz81/f;

    .line 237
    .line 238
    invoke-virtual {v1, v2}, Ljava/lang/Enum;->compareTo(Ljava/lang/Enum;)I

    .line 239
    .line 240
    .line 241
    move-result v1

    .line 242
    if-lez v1, :cond_4

    .line 243
    .line 244
    iget-object v0, v0, Lx51/b;->d:La61/a;

    .line 245
    .line 246
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 247
    .line 248
    .line 249
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 250
    .line 251
    .line 252
    move-result-object p0

    .line 253
    :goto_2
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 254
    .line 255
    .line 256
    move-result v0

    .line 257
    if-eqz v0, :cond_4

    .line 258
    .line 259
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 260
    .line 261
    .line 262
    move-result-object v0

    .line 263
    check-cast v0, Ljava/lang/String;

    .line 264
    .line 265
    sget-object v0, Lx51/c;->o1:Lx51/b;

    .line 266
    .line 267
    iget-object v0, v0, Lx51/b;->d:La61/a;

    .line 268
    .line 269
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 270
    .line 271
    .line 272
    goto :goto_2

    .line 273
    :cond_4
    new-instance p0, Lz81/n;

    .line 274
    .line 275
    const/4 v0, 0x1

    .line 276
    invoke-direct {p0, v3, v4, v6, v0}, Lz81/n;-><init>(Lz81/o;Lc91/a0;Lkotlin/coroutines/Continuation;I)V

    .line 277
    .line 278
    .line 279
    invoke-static {v8, p0}, Lvy0/e0;->K(Lpx0/g;Lay0/n;)Ljava/lang/Object;

    .line 280
    .line 281
    .line 282
    :goto_3
    return-void

    .line 283
    :pswitch_0
    iget-object v0, p0, Lc8/r;->e:Ljava/lang/Object;

    .line 284
    .line 285
    check-cast v0, Lwn/a;

    .line 286
    .line 287
    iget-object v1, p0, Lc8/r;->f:Ljava/lang/Object;

    .line 288
    .line 289
    check-cast v1, Lrn/j;

    .line 290
    .line 291
    iget-object v2, v1, Lrn/j;->a:Ljava/lang/String;

    .line 292
    .line 293
    iget-object v3, p0, Lc8/r;->g:Ljava/lang/Object;

    .line 294
    .line 295
    check-cast v3, Lon/g;

    .line 296
    .line 297
    iget-object p0, p0, Lc8/r;->h:Ljava/lang/Object;

    .line 298
    .line 299
    check-cast p0, Lrn/h;

    .line 300
    .line 301
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 302
    .line 303
    .line 304
    sget-object v4, Lwn/a;->f:Ljava/util/logging/Logger;

    .line 305
    .line 306
    const-string v5, "Transport backend \'"

    .line 307
    .line 308
    :try_start_0
    iget-object v6, v0, Lwn/a;->c:Lsn/d;

    .line 309
    .line 310
    invoke-virtual {v6, v2}, Lsn/d;->a(Ljava/lang/String;)Lsn/e;

    .line 311
    .line 312
    .line 313
    move-result-object v6

    .line 314
    if-nez v6, :cond_5

    .line 315
    .line 316
    new-instance p0, Ljava/lang/StringBuilder;

    .line 317
    .line 318
    invoke-direct {p0, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 319
    .line 320
    .line 321
    invoke-virtual {p0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 322
    .line 323
    .line 324
    const-string v0, "\' is not registered"

    .line 325
    .line 326
    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 327
    .line 328
    .line 329
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 330
    .line 331
    .line 332
    move-result-object p0

    .line 333
    invoke-virtual {v4, p0}, Ljava/util/logging/Logger;->warning(Ljava/lang/String;)V

    .line 334
    .line 335
    .line 336
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 337
    .line 338
    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 339
    .line 340
    .line 341
    invoke-interface {v3, v0}, Lon/g;->a(Ljava/lang/Exception;)V

    .line 342
    .line 343
    .line 344
    goto :goto_5

    .line 345
    :catch_0
    move-exception v0

    .line 346
    move-object p0, v0

    .line 347
    goto :goto_4

    .line 348
    :cond_5
    check-cast v6, Lpn/b;

    .line 349
    .line 350
    invoke-virtual {v6, p0}, Lpn/b;->a(Lrn/h;)Lrn/h;

    .line 351
    .line 352
    .line 353
    move-result-object p0

    .line 354
    iget-object v2, v0, Lwn/a;->e:Lzn/c;

    .line 355
    .line 356
    new-instance v5, Lbb/i;

    .line 357
    .line 358
    const/16 v6, 0xe

    .line 359
    .line 360
    invoke-direct {v5, v0, v1, p0, v6}, Lbb/i;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 361
    .line 362
    .line 363
    check-cast v2, Lyn/h;

    .line 364
    .line 365
    invoke-virtual {v2, v5}, Lyn/h;->h(Lzn/b;)Ljava/lang/Object;

    .line 366
    .line 367
    .line 368
    const/4 p0, 0x0

    .line 369
    invoke-interface {v3, p0}, Lon/g;->a(Ljava/lang/Exception;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 370
    .line 371
    .line 372
    goto :goto_5

    .line 373
    :goto_4
    new-instance v0, Ljava/lang/StringBuilder;

    .line 374
    .line 375
    const-string v1, "Error scheduling event "

    .line 376
    .line 377
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 378
    .line 379
    .line 380
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 381
    .line 382
    .line 383
    move-result-object v1

    .line 384
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 385
    .line 386
    .line 387
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 388
    .line 389
    .line 390
    move-result-object v0

    .line 391
    invoke-virtual {v4, v0}, Ljava/util/logging/Logger;->warning(Ljava/lang/String;)V

    .line 392
    .line 393
    .line 394
    invoke-interface {v3, p0}, Lon/g;->a(Ljava/lang/Exception;)V

    .line 395
    .line 396
    .line 397
    :goto_5
    return-void

    .line 398
    :pswitch_1
    iget-object v0, p0, Lc8/r;->e:Ljava/lang/Object;

    .line 399
    .line 400
    check-cast v0, Lw0/r;

    .line 401
    .line 402
    iget-object v1, p0, Lc8/r;->f:Ljava/lang/Object;

    .line 403
    .line 404
    check-cast v1, Landroid/view/Surface;

    .line 405
    .line 406
    iget-object v2, p0, Lc8/r;->g:Ljava/lang/Object;

    .line 407
    .line 408
    check-cast v2, Ly4/k;

    .line 409
    .line 410
    iget-object p0, p0, Lc8/r;->h:Ljava/lang/Object;

    .line 411
    .line 412
    check-cast p0, Lb0/x1;

    .line 413
    .line 414
    const-string v3, "TextureViewImpl"

    .line 415
    .line 416
    const-string v4, "Safe to release surface."

    .line 417
    .line 418
    invoke-static {v3, v4}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 419
    .line 420
    .line 421
    iget-object v3, v0, Lw0/r;->l:Lbb/i;

    .line 422
    .line 423
    const/4 v4, 0x0

    .line 424
    if-eqz v3, :cond_6

    .line 425
    .line 426
    invoke-virtual {v3}, Lbb/i;->a()V

    .line 427
    .line 428
    .line 429
    iput-object v4, v0, Lw0/r;->l:Lbb/i;

    .line 430
    .line 431
    :cond_6
    invoke-virtual {v1}, Landroid/view/Surface;->release()V

    .line 432
    .line 433
    .line 434
    iget-object v1, v0, Lw0/r;->g:Ly4/k;

    .line 435
    .line 436
    if-ne v1, v2, :cond_7

    .line 437
    .line 438
    iput-object v4, v0, Lw0/r;->g:Ly4/k;

    .line 439
    .line 440
    :cond_7
    iget-object v1, v0, Lw0/r;->h:Lb0/x1;

    .line 441
    .line 442
    if-ne v1, p0, :cond_8

    .line 443
    .line 444
    iput-object v4, v0, Lw0/r;->h:Lb0/x1;

    .line 445
    .line 446
    :cond_8
    return-void

    .line 447
    :pswitch_2
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 448
    .line 449
    iget-object v1, p0, Lc8/r;->e:Ljava/lang/Object;

    .line 450
    .line 451
    check-cast v1, Llp/sd;

    .line 452
    .line 453
    iget-object v2, p0, Lc8/r;->f:Ljava/lang/Object;

    .line 454
    .line 455
    check-cast v2, Luw/b;

    .line 456
    .line 457
    iget-object v3, p0, Lc8/r;->g:Ljava/lang/Object;

    .line 458
    .line 459
    check-cast v3, Lcom/google/android/material/datepicker/d;

    .line 460
    .line 461
    iget-object p0, p0, Lc8/r;->h:Ljava/lang/Object;

    .line 462
    .line 463
    check-cast p0, Lhu/q;

    .line 464
    .line 465
    const-string v4, "this$0"

    .line 466
    .line 467
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 468
    .line 469
    .line 470
    iget-object v3, v3, Lcom/google/android/material/datepicker/d;->c:Ljava/lang/Object;

    .line 471
    .line 472
    check-cast v3, Lww/e;

    .line 473
    .line 474
    instance-of v4, v1, Lww/a;

    .line 475
    .line 476
    if-eqz v4, :cond_9

    .line 477
    .line 478
    new-instance v4, Ljava/lang/StringBuilder;

    .line 479
    .line 480
    const-string v5, "Store Translations Version "

    .line 481
    .line 482
    invoke-direct {v4, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 483
    .line 484
    .line 485
    check-cast v1, Lww/a;

    .line 486
    .line 487
    iget-object v1, v1, Lww/a;->a:Ljava/lang/String;

    .line 488
    .line 489
    invoke-virtual {v4, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 490
    .line 491
    .line 492
    const-string v5, " for "

    .line 493
    .line 494
    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 495
    .line 496
    .line 497
    invoke-static {v2}, Llp/td;->a(Luw/b;)Ljava/lang/String;

    .line 498
    .line 499
    .line 500
    move-result-object v5

    .line 501
    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 502
    .line 503
    .line 504
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 505
    .line 506
    .line 507
    move-result-object v4

    .line 508
    invoke-static {v4}, Let/d;->c(Ljava/lang/String;)V

    .line 509
    .line 510
    .line 511
    invoke-virtual {v2}, Luw/b;->b()Ljava/lang/String;

    .line 512
    .line 513
    .line 514
    move-result-object v2

    .line 515
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 516
    .line 517
    .line 518
    const-string v4, "localeHash"

    .line 519
    .line 520
    invoke-static {v2, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 521
    .line 522
    .line 523
    iget-object v4, v3, Lww/e;->a:Landroid/content/SharedPreferences;

    .line 524
    .line 525
    invoke-interface {v4}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    .line 526
    .line 527
    .line 528
    move-result-object v4

    .line 529
    invoke-interface {v4, v2, v1}, Landroid/content/SharedPreferences$Editor;->putString(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;

    .line 530
    .line 531
    .line 532
    move-result-object v1

    .line 533
    invoke-interface {v1}, Landroid/content/SharedPreferences$Editor;->apply()V

    .line 534
    .line 535
    .line 536
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 537
    .line 538
    .line 539
    move-result-wide v1

    .line 540
    const-wide/16 v4, 0x3e8

    .line 541
    .line 542
    div-long/2addr v1, v4

    .line 543
    invoke-static {v1, v2}, Ljava/lang/String;->valueOf(J)Ljava/lang/String;

    .line 544
    .line 545
    .line 546
    move-result-object v1

    .line 547
    iget-object v2, v3, Lww/e;->b:Lb81/d;

    .line 548
    .line 549
    sget-object v3, Lww/e;->d:[Lhy0/z;

    .line 550
    .line 551
    const/4 v4, 0x0

    .line 552
    aget-object v3, v3, v4

    .line 553
    .line 554
    invoke-virtual {v2, v3, v1}, Lb81/d;->d(Lhy0/z;Ljava/lang/String;)V

    .line 555
    .line 556
    .line 557
    if-eqz p0, :cond_b

    .line 558
    .line 559
    iget-object p0, p0, Lhu/q;->e:Ljava/lang/Object;

    .line 560
    .line 561
    check-cast p0, Ljj0/e;

    .line 562
    .line 563
    iget-object p0, p0, Ljj0/e;->a:Ldj0/b;

    .line 564
    .line 565
    new-instance v1, Lne0/e;

    .line 566
    .line 567
    invoke-direct {v1, v0}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 568
    .line 569
    .line 570
    iget-object p0, p0, Ldj0/b;->d:Lyy0/q1;

    .line 571
    .line 572
    invoke-virtual {p0, v1}, Lyy0/q1;->a(Ljava/lang/Object;)Z

    .line 573
    .line 574
    .line 575
    goto :goto_6

    .line 576
    :cond_9
    instance-of v2, v1, Lww/c;

    .line 577
    .line 578
    if-eqz v2, :cond_a

    .line 579
    .line 580
    if-eqz p0, :cond_b

    .line 581
    .line 582
    iget-object p0, p0, Lhu/q;->e:Ljava/lang/Object;

    .line 583
    .line 584
    check-cast p0, Ljj0/e;

    .line 585
    .line 586
    iget-object p0, p0, Ljj0/e;->a:Ldj0/b;

    .line 587
    .line 588
    new-instance v1, Lne0/e;

    .line 589
    .line 590
    invoke-direct {v1, v0}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 591
    .line 592
    .line 593
    iget-object p0, p0, Ldj0/b;->d:Lyy0/q1;

    .line 594
    .line 595
    invoke-virtual {p0, v1}, Lyy0/q1;->a(Ljava/lang/Object;)Z

    .line 596
    .line 597
    .line 598
    goto :goto_6

    .line 599
    :cond_a
    instance-of v0, v1, Lww/b;

    .line 600
    .line 601
    if-eqz v0, :cond_b

    .line 602
    .line 603
    if-eqz p0, :cond_b

    .line 604
    .line 605
    iget-object p0, p0, Lhu/q;->e:Ljava/lang/Object;

    .line 606
    .line 607
    check-cast p0, Ljj0/e;

    .line 608
    .line 609
    iget-object p0, p0, Ljj0/e;->a:Ldj0/b;

    .line 610
    .line 611
    new-instance v0, Lne0/c;

    .line 612
    .line 613
    new-instance v1, Lb0/l;

    .line 614
    .line 615
    const-string v2, "Unknown error while update translations"

    .line 616
    .line 617
    invoke-direct {v1, v2}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 618
    .line 619
    .line 620
    const/4 v4, 0x0

    .line 621
    const/16 v5, 0x1e

    .line 622
    .line 623
    const/4 v2, 0x0

    .line 624
    const/4 v3, 0x0

    .line 625
    invoke-direct/range {v0 .. v5}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 626
    .line 627
    .line 628
    iget-object p0, p0, Ldj0/b;->d:Lyy0/q1;

    .line 629
    .line 630
    invoke-virtual {p0, v0}, Lyy0/q1;->a(Ljava/lang/Object;)Z

    .line 631
    .line 632
    .line 633
    :cond_b
    :goto_6
    return-void

    .line 634
    :pswitch_3
    iget-object v0, p0, Lc8/r;->e:Ljava/lang/Object;

    .line 635
    .line 636
    check-cast v0, Lss/b;

    .line 637
    .line 638
    iget-object v1, p0, Lc8/r;->f:Ljava/lang/Object;

    .line 639
    .line 640
    check-cast v1, Ljava/lang/String;

    .line 641
    .line 642
    iget-object v2, p0, Lc8/r;->g:Ljava/lang/Object;

    .line 643
    .line 644
    check-cast v2, Ljava/util/Map;

    .line 645
    .line 646
    iget-object p0, p0, Lc8/r;->h:Ljava/lang/Object;

    .line 647
    .line 648
    check-cast p0, Ljava/util/List;

    .line 649
    .line 650
    iget-object v3, v0, Lss/b;->f:Ljava/lang/Object;

    .line 651
    .line 652
    check-cast v3, Los/h;

    .line 653
    .line 654
    iget-object v0, v0, Lss/b;->k:Ljava/lang/Object;

    .line 655
    .line 656
    check-cast v0, Ljava/util/concurrent/atomic/AtomicMarkableReference;

    .line 657
    .line 658
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicMarkableReference;->getReference()Ljava/lang/Object;

    .line 659
    .line 660
    .line 661
    move-result-object v4

    .line 662
    check-cast v4, Ljava/lang/String;

    .line 663
    .line 664
    if-eqz v4, :cond_c

    .line 665
    .line 666
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicMarkableReference;->getReference()Ljava/lang/Object;

    .line 667
    .line 668
    .line 669
    move-result-object v0

    .line 670
    check-cast v0, Ljava/lang/String;

    .line 671
    .line 672
    invoke-virtual {v3, v1, v0}, Los/h;->j(Ljava/lang/String;Ljava/lang/String;)V

    .line 673
    .line 674
    .line 675
    :cond_c
    invoke-interface {v2}, Ljava/util/Map;->isEmpty()Z

    .line 676
    .line 677
    .line 678
    move-result v0

    .line 679
    if-nez v0, :cond_d

    .line 680
    .line 681
    const/4 v0, 0x0

    .line 682
    invoke-virtual {v3, v1, v2, v0}, Los/h;->h(Ljava/lang/String;Ljava/util/Map;Z)V

    .line 683
    .line 684
    .line 685
    :cond_d
    invoke-interface {p0}, Ljava/util/List;->isEmpty()Z

    .line 686
    .line 687
    .line 688
    move-result v0

    .line 689
    if-nez v0, :cond_e

    .line 690
    .line 691
    invoke-virtual {v3, v1, p0}, Los/h;->i(Ljava/lang/String;Ljava/util/List;)V

    .line 692
    .line 693
    .line 694
    :cond_e
    return-void

    .line 695
    :pswitch_4
    iget-object v0, p0, Lc8/r;->e:Ljava/lang/Object;

    .line 696
    .line 697
    check-cast v0, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender;

    .line 698
    .line 699
    iget-object v1, p0, Lc8/r;->f:Ljava/lang/Object;

    .line 700
    .line 701
    check-cast v1, Ld01/j0;

    .line 702
    .line 703
    iget-object v2, p0, Lc8/r;->g:Ljava/lang/Object;

    .line 704
    .line 705
    check-cast v2, Ljava/util/function/Consumer;

    .line 706
    .line 707
    iget-object p0, p0, Lc8/r;->h:Ljava/lang/Object;

    .line 708
    .line 709
    check-cast p0, Ljava/util/function/Consumer;

    .line 710
    .line 711
    invoke-static {v0, v1, v2, p0}, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender;->b(Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender;Ld01/j0;Ljava/util/function/Consumer;Ljava/util/function/Consumer;)V

    .line 712
    .line 713
    .line 714
    return-void

    .line 715
    :pswitch_5
    iget-object v0, p0, Lc8/r;->e:Ljava/lang/Object;

    .line 716
    .line 717
    check-cast v0, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpGrpcSender;

    .line 718
    .line 719
    iget-object v1, p0, Lc8/r;->f:Ljava/lang/Object;

    .line 720
    .line 721
    check-cast v1, Ld01/j0;

    .line 722
    .line 723
    iget-object v2, p0, Lc8/r;->g:Ljava/lang/Object;

    .line 724
    .line 725
    check-cast v2, Ljava/util/function/Consumer;

    .line 726
    .line 727
    iget-object p0, p0, Lc8/r;->h:Ljava/lang/Object;

    .line 728
    .line 729
    check-cast p0, Ljava/util/function/Consumer;

    .line 730
    .line 731
    invoke-static {v0, v1, v2, p0}, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpGrpcSender;->b(Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpGrpcSender;Ld01/j0;Ljava/util/function/Consumer;Ljava/util/function/Consumer;)V

    .line 732
    .line 733
    .line 734
    return-void

    .line 735
    :pswitch_6
    iget-object v0, p0, Lc8/r;->e:Ljava/lang/Object;

    .line 736
    .line 737
    check-cast v0, Ljava/util/List;

    .line 738
    .line 739
    iget-object v1, p0, Lc8/r;->f:Ljava/lang/Object;

    .line 740
    .line 741
    check-cast v1, Lmb/i;

    .line 742
    .line 743
    iget-object v2, p0, Lc8/r;->g:Ljava/lang/Object;

    .line 744
    .line 745
    check-cast v2, Leb/b;

    .line 746
    .line 747
    iget-object p0, p0, Lc8/r;->h:Ljava/lang/Object;

    .line 748
    .line 749
    check-cast p0, Landroidx/work/impl/WorkDatabase;

    .line 750
    .line 751
    invoke-interface {v0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 752
    .line 753
    .line 754
    move-result-object v3

    .line 755
    :goto_7
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 756
    .line 757
    .line 758
    move-result v4

    .line 759
    if-eqz v4, :cond_f

    .line 760
    .line 761
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 762
    .line 763
    .line 764
    move-result-object v4

    .line 765
    check-cast v4, Lfb/g;

    .line 766
    .line 767
    iget-object v5, v1, Lmb/i;->a:Ljava/lang/String;

    .line 768
    .line 769
    invoke-interface {v4, v5}, Lfb/g;->c(Ljava/lang/String;)V

    .line 770
    .line 771
    .line 772
    goto :goto_7

    .line 773
    :cond_f
    invoke-static {v2, p0, v0}, Lfb/i;->b(Leb/b;Landroidx/work/impl/WorkDatabase;Ljava/util/List;)V

    .line 774
    .line 775
    .line 776
    return-void

    .line 777
    :pswitch_7
    iget-object v0, p0, Lc8/r;->e:Ljava/lang/Object;

    .line 778
    .line 779
    check-cast v0, Landroid/media/AudioTrack;

    .line 780
    .line 781
    iget-object v1, p0, Lc8/r;->f:Ljava/lang/Object;

    .line 782
    .line 783
    check-cast v1, Laq/a;

    .line 784
    .line 785
    iget-object v2, p0, Lc8/r;->g:Ljava/lang/Object;

    .line 786
    .line 787
    check-cast v2, Landroid/os/Handler;

    .line 788
    .line 789
    iget-object p0, p0, Lc8/r;->h:Ljava/lang/Object;

    .line 790
    .line 791
    check-cast p0, Lc8/j;

    .line 792
    .line 793
    const/4 v3, 0x0

    .line 794
    :try_start_1
    invoke-virtual {v0}, Landroid/media/AudioTrack;->flush()V

    .line 795
    .line 796
    .line 797
    invoke-virtual {v0}, Landroid/media/AudioTrack;->release()V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 798
    .line 799
    .line 800
    if-eqz v1, :cond_10

    .line 801
    .line 802
    invoke-virtual {v2}, Landroid/os/Handler;->getLooper()Landroid/os/Looper;

    .line 803
    .line 804
    .line 805
    move-result-object v0

    .line 806
    invoke-virtual {v0}, Landroid/os/Looper;->getThread()Ljava/lang/Thread;

    .line 807
    .line 808
    .line 809
    move-result-object v0

    .line 810
    invoke-virtual {v0}, Ljava/lang/Thread;->isAlive()Z

    .line 811
    .line 812
    .line 813
    move-result v0

    .line 814
    if-eqz v0, :cond_10

    .line 815
    .line 816
    new-instance v0, La8/z;

    .line 817
    .line 818
    const/16 v4, 0x10

    .line 819
    .line 820
    invoke-direct {v0, v4, v1, p0}, La8/z;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 821
    .line 822
    .line 823
    invoke-virtual {v2, v0}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    .line 824
    .line 825
    .line 826
    :cond_10
    sget-object v4, Lc8/y;->l0:Ljava/lang/Object;

    .line 827
    .line 828
    monitor-enter v4

    .line 829
    :try_start_2
    sget p0, Lc8/y;->n0:I

    .line 830
    .line 831
    add-int/lit8 p0, p0, -0x1

    .line 832
    .line 833
    sput p0, Lc8/y;->n0:I

    .line 834
    .line 835
    if-nez p0, :cond_11

    .line 836
    .line 837
    sget-object p0, Lc8/y;->m0:Ljava/util/concurrent/ScheduledExecutorService;

    .line 838
    .line 839
    invoke-interface {p0}, Ljava/util/concurrent/ExecutorService;->shutdown()V

    .line 840
    .line 841
    .line 842
    sput-object v3, Lc8/y;->m0:Ljava/util/concurrent/ScheduledExecutorService;

    .line 843
    .line 844
    goto :goto_8

    .line 845
    :catchall_0
    move-exception v0

    .line 846
    move-object p0, v0

    .line 847
    goto :goto_9

    .line 848
    :cond_11
    :goto_8
    monitor-exit v4

    .line 849
    return-void

    .line 850
    :goto_9
    monitor-exit v4
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 851
    throw p0

    .line 852
    :catchall_1
    move-exception v0

    .line 853
    if-eqz v1, :cond_12

    .line 854
    .line 855
    invoke-virtual {v2}, Landroid/os/Handler;->getLooper()Landroid/os/Looper;

    .line 856
    .line 857
    .line 858
    move-result-object v4

    .line 859
    invoke-virtual {v4}, Landroid/os/Looper;->getThread()Ljava/lang/Thread;

    .line 860
    .line 861
    .line 862
    move-result-object v4

    .line 863
    invoke-virtual {v4}, Ljava/lang/Thread;->isAlive()Z

    .line 864
    .line 865
    .line 866
    move-result v4

    .line 867
    if-eqz v4, :cond_12

    .line 868
    .line 869
    new-instance v4, La8/z;

    .line 870
    .line 871
    const/16 v5, 0x10

    .line 872
    .line 873
    invoke-direct {v4, v5, v1, p0}, La8/z;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 874
    .line 875
    .line 876
    invoke-virtual {v2, v4}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    .line 877
    .line 878
    .line 879
    :cond_12
    sget-object p0, Lc8/y;->l0:Ljava/lang/Object;

    .line 880
    .line 881
    monitor-enter p0

    .line 882
    :try_start_3
    sget v1, Lc8/y;->n0:I

    .line 883
    .line 884
    add-int/lit8 v1, v1, -0x1

    .line 885
    .line 886
    sput v1, Lc8/y;->n0:I

    .line 887
    .line 888
    if-nez v1, :cond_13

    .line 889
    .line 890
    sget-object v1, Lc8/y;->m0:Ljava/util/concurrent/ScheduledExecutorService;

    .line 891
    .line 892
    invoke-interface {v1}, Ljava/util/concurrent/ExecutorService;->shutdown()V

    .line 893
    .line 894
    .line 895
    sput-object v3, Lc8/y;->m0:Ljava/util/concurrent/ScheduledExecutorService;

    .line 896
    .line 897
    goto :goto_a

    .line 898
    :catchall_2
    move-exception v0

    .line 899
    goto :goto_b

    .line 900
    :cond_13
    :goto_a
    monitor-exit p0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    .line 901
    throw v0

    .line 902
    :goto_b
    :try_start_4
    monitor-exit p0
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_2

    .line 903
    throw v0

    .line 904
    nop

    .line 905
    :pswitch_data_0
    .packed-switch 0x0
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
