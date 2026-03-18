.class public final synthetic Lcom/google/firebase/messaging/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/concurrent/Callable;


# instance fields
.field public final synthetic a:I

.field public final synthetic b:Ljava/lang/Object;

.field public final synthetic c:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput p1, p0, Lcom/google/firebase/messaging/h;->a:I

    .line 2
    .line 3
    iput-object p2, p0, Lcom/google/firebase/messaging/h;->b:Ljava/lang/Object;

    .line 4
    .line 5
    iput-object p3, p0, Lcom/google/firebase/messaging/h;->c:Ljava/lang/Object;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final call()Ljava/lang/Object;
    .locals 11

    .line 1
    iget v0, p0, Lcom/google/firebase/messaging/h;->a:I

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    const/4 v2, 0x0

    .line 5
    const/4 v3, 0x0

    .line 6
    packed-switch v0, :pswitch_data_0

    .line 7
    .line 8
    .line 9
    iget-object v0, p0, Lcom/google/firebase/messaging/h;->b:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast v0, Lio/opentelemetry/context/Context;

    .line 12
    .line 13
    iget-object p0, p0, Lcom/google/firebase/messaging/h;->c:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast p0, Ljava/util/concurrent/Callable;

    .line 16
    .line 17
    invoke-static {v0, p0}, Lio/opentelemetry/context/Context;->g(Lio/opentelemetry/context/Context;Ljava/util/concurrent/Callable;)Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    return-object p0

    .line 22
    :pswitch_0
    iget-object v0, p0, Lcom/google/firebase/messaging/h;->b:Ljava/lang/Object;

    .line 23
    .line 24
    check-cast v0, Lfb/c0;

    .line 25
    .line 26
    iget-object p0, p0, Lcom/google/firebase/messaging/h;->c:Ljava/lang/Object;

    .line 27
    .line 28
    check-cast p0, Lfb/f0;

    .line 29
    .line 30
    iget-object v2, p0, Lfb/f0;->a:Lmb/o;

    .line 31
    .line 32
    iget-object v4, p0, Lfb/f0;->c:Ljava/lang/String;

    .line 33
    .line 34
    iget-object v5, p0, Lfb/f0;->i:Lmb/s;

    .line 35
    .line 36
    instance-of v6, v0, Lfb/a0;

    .line 37
    .line 38
    if-eqz v6, :cond_8

    .line 39
    .line 40
    check-cast v0, Lfb/a0;

    .line 41
    .line 42
    iget-object v0, v0, Lfb/a0;->a:Leb/u;

    .line 43
    .line 44
    invoke-virtual {v5, v4}, Lmb/s;->d(Ljava/lang/String;)Leb/h0;

    .line 45
    .line 46
    .line 47
    move-result-object v6

    .line 48
    iget-object v7, p0, Lfb/f0;->h:Landroidx/work/impl/WorkDatabase;

    .line 49
    .line 50
    invoke-virtual {v7}, Landroidx/work/impl/WorkDatabase;->w()Lmb/l;

    .line 51
    .line 52
    .line 53
    move-result-object v7

    .line 54
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 55
    .line 56
    .line 57
    iget-object v7, v7, Lmb/l;->a:Lla/u;

    .line 58
    .line 59
    new-instance v8, Lif0/d;

    .line 60
    .line 61
    const/16 v9, 0x10

    .line 62
    .line 63
    invoke-direct {v8, v4, v9}, Lif0/d;-><init>(Ljava/lang/String;I)V

    .line 64
    .line 65
    .line 66
    invoke-static {v7, v3, v1, v8}, Ljp/ue;->f(Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    if-nez v6, :cond_0

    .line 70
    .line 71
    goto :goto_0

    .line 72
    :cond_0
    sget-object v7, Leb/h0;->e:Leb/h0;

    .line 73
    .line 74
    if-ne v6, v7, :cond_7

    .line 75
    .line 76
    iget-object v6, p0, Lfb/f0;->l:Ljava/lang/String;

    .line 77
    .line 78
    instance-of v7, v0, Leb/t;

    .line 79
    .line 80
    if-eqz v7, :cond_4

    .line 81
    .line 82
    sget-object v7, Lfb/g0;->a:Ljava/lang/String;

    .line 83
    .line 84
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 85
    .line 86
    .line 87
    move-result-object v8

    .line 88
    new-instance v9, Ljava/lang/StringBuilder;

    .line 89
    .line 90
    const-string v10, "Worker result SUCCESS for "

    .line 91
    .line 92
    invoke-direct {v9, v10}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 93
    .line 94
    .line 95
    invoke-virtual {v9, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 96
    .line 97
    .line 98
    invoke-virtual {v9}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 99
    .line 100
    .line 101
    move-result-object v6

    .line 102
    invoke-virtual {v8, v7, v6}, Leb/w;->e(Ljava/lang/String;Ljava/lang/String;)V

    .line 103
    .line 104
    .line 105
    invoke-virtual {v2}, Lmb/o;->b()Z

    .line 106
    .line 107
    .line 108
    move-result v2

    .line 109
    if-eqz v2, :cond_2

    .line 110
    .line 111
    invoke-virtual {p0}, Lfb/f0;->c()V

    .line 112
    .line 113
    .line 114
    :cond_1
    :goto_0
    move v1, v3

    .line 115
    goto/16 :goto_2

    .line 116
    .line 117
    :cond_2
    sget-object v2, Leb/h0;->f:Leb/h0;

    .line 118
    .line 119
    invoke-virtual {v5, v2, v4}, Lmb/s;->j(Leb/h0;Ljava/lang/String;)I

    .line 120
    .line 121
    .line 122
    check-cast v0, Leb/t;

    .line 123
    .line 124
    iget-object v0, v0, Leb/t;->a:Leb/h;

    .line 125
    .line 126
    const-string v2, "getOutputData(...)"

    .line 127
    .line 128
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 129
    .line 130
    .line 131
    iget-object v2, v5, Lmb/s;->a:Lla/u;

    .line 132
    .line 133
    new-instance v6, Ll2/v1;

    .line 134
    .line 135
    const/16 v7, 0xc

    .line 136
    .line 137
    invoke-direct {v6, v7, v0, v4}, Ll2/v1;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 138
    .line 139
    .line 140
    invoke-static {v2, v3, v1, v6}, Ljp/ue;->f(Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 141
    .line 142
    .line 143
    iget-object v0, p0, Lfb/f0;->f:Leb/j;

    .line 144
    .line 145
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 146
    .line 147
    .line 148
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 149
    .line 150
    .line 151
    move-result-wide v8

    .line 152
    iget-object p0, p0, Lfb/f0;->j:Lmb/b;

    .line 153
    .line 154
    invoke-virtual {p0, v4}, Lmb/b;->a(Ljava/lang/String;)Ljava/util/List;

    .line 155
    .line 156
    .line 157
    move-result-object v0

    .line 158
    invoke-interface {v0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 159
    .line 160
    .line 161
    move-result-object v0

    .line 162
    :cond_3
    :goto_1
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 163
    .line 164
    .line 165
    move-result v2

    .line 166
    if-eqz v2, :cond_1

    .line 167
    .line 168
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 169
    .line 170
    .line 171
    move-result-object v2

    .line 172
    check-cast v2, Ljava/lang/String;

    .line 173
    .line 174
    invoke-virtual {v5, v2}, Lmb/s;->d(Ljava/lang/String;)Leb/h0;

    .line 175
    .line 176
    .line 177
    move-result-object v4

    .line 178
    sget-object v6, Leb/h0;->h:Leb/h0;

    .line 179
    .line 180
    if-ne v4, v6, :cond_3

    .line 181
    .line 182
    iget-object v4, p0, Lmb/b;->a:Lla/u;

    .line 183
    .line 184
    new-instance v6, Lif0/d;

    .line 185
    .line 186
    invoke-direct {v6, v2, v7}, Lif0/d;-><init>(Ljava/lang/String;I)V

    .line 187
    .line 188
    .line 189
    invoke-static {v4, v1, v3, v6}, Ljp/ue;->f(Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 190
    .line 191
    .line 192
    move-result-object v4

    .line 193
    check-cast v4, Ljava/lang/Boolean;

    .line 194
    .line 195
    invoke-virtual {v4}, Ljava/lang/Boolean;->booleanValue()Z

    .line 196
    .line 197
    .line 198
    move-result v4

    .line 199
    if-eqz v4, :cond_3

    .line 200
    .line 201
    sget-object v4, Lfb/g0;->a:Ljava/lang/String;

    .line 202
    .line 203
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 204
    .line 205
    .line 206
    move-result-object v6

    .line 207
    const-string v10, "Setting status to enqueued for "

    .line 208
    .line 209
    invoke-virtual {v10, v2}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 210
    .line 211
    .line 212
    move-result-object v10

    .line 213
    invoke-virtual {v6, v4, v10}, Leb/w;->e(Ljava/lang/String;Ljava/lang/String;)V

    .line 214
    .line 215
    .line 216
    sget-object v4, Leb/h0;->d:Leb/h0;

    .line 217
    .line 218
    invoke-virtual {v5, v4, v2}, Lmb/s;->j(Leb/h0;Ljava/lang/String;)I

    .line 219
    .line 220
    .line 221
    invoke-virtual {v5, v8, v9, v2}, Lmb/s;->i(JLjava/lang/String;)V

    .line 222
    .line 223
    .line 224
    goto :goto_1

    .line 225
    :cond_4
    instance-of v4, v0, Leb/s;

    .line 226
    .line 227
    if-eqz v4, :cond_5

    .line 228
    .line 229
    sget-object v0, Lfb/g0;->a:Ljava/lang/String;

    .line 230
    .line 231
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 232
    .line 233
    .line 234
    move-result-object v2

    .line 235
    new-instance v3, Ljava/lang/StringBuilder;

    .line 236
    .line 237
    const-string v4, "Worker result RETRY for "

    .line 238
    .line 239
    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 240
    .line 241
    .line 242
    invoke-virtual {v3, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 243
    .line 244
    .line 245
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 246
    .line 247
    .line 248
    move-result-object v3

    .line 249
    invoke-virtual {v2, v0, v3}, Leb/w;->e(Ljava/lang/String;Ljava/lang/String;)V

    .line 250
    .line 251
    .line 252
    const/16 v0, -0x100

    .line 253
    .line 254
    invoke-virtual {p0, v0}, Lfb/f0;->b(I)V

    .line 255
    .line 256
    .line 257
    goto :goto_2

    .line 258
    :cond_5
    sget-object v1, Lfb/g0;->a:Ljava/lang/String;

    .line 259
    .line 260
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 261
    .line 262
    .line 263
    move-result-object v4

    .line 264
    new-instance v5, Ljava/lang/StringBuilder;

    .line 265
    .line 266
    const-string v7, "Worker result FAILURE for "

    .line 267
    .line 268
    invoke-direct {v5, v7}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 269
    .line 270
    .line 271
    invoke-virtual {v5, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 272
    .line 273
    .line 274
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 275
    .line 276
    .line 277
    move-result-object v5

    .line 278
    invoke-virtual {v4, v1, v5}, Leb/w;->e(Ljava/lang/String;Ljava/lang/String;)V

    .line 279
    .line 280
    .line 281
    invoke-virtual {v2}, Lmb/o;->b()Z

    .line 282
    .line 283
    .line 284
    move-result v1

    .line 285
    if-eqz v1, :cond_6

    .line 286
    .line 287
    invoke-virtual {p0}, Lfb/f0;->c()V

    .line 288
    .line 289
    .line 290
    goto/16 :goto_0

    .line 291
    .line 292
    :cond_6
    invoke-virtual {p0, v0}, Lfb/f0;->d(Leb/u;)V

    .line 293
    .line 294
    .line 295
    goto/16 :goto_0

    .line 296
    .line 297
    :cond_7
    invoke-virtual {v6}, Leb/h0;->a()Z

    .line 298
    .line 299
    .line 300
    move-result v0

    .line 301
    if-nez v0, :cond_1

    .line 302
    .line 303
    const/16 v0, -0x200

    .line 304
    .line 305
    invoke-virtual {p0, v0}, Lfb/f0;->b(I)V

    .line 306
    .line 307
    .line 308
    :goto_2
    move v3, v1

    .line 309
    goto/16 :goto_3

    .line 310
    .line 311
    :cond_8
    instance-of v6, v0, Lfb/z;

    .line 312
    .line 313
    if-eqz v6, :cond_9

    .line 314
    .line 315
    check-cast v0, Lfb/z;

    .line 316
    .line 317
    iget-object v0, v0, Lfb/z;->a:Leb/u;

    .line 318
    .line 319
    invoke-virtual {p0, v0}, Lfb/f0;->d(Leb/u;)V

    .line 320
    .line 321
    .line 322
    goto/16 :goto_3

    .line 323
    .line 324
    :cond_9
    instance-of v6, v0, Lfb/b0;

    .line 325
    .line 326
    if-eqz v6, :cond_c

    .line 327
    .line 328
    check-cast v0, Lfb/b0;

    .line 329
    .line 330
    iget v0, v0, Lfb/b0;->a:I

    .line 331
    .line 332
    const-string v6, " is "

    .line 333
    .line 334
    const-string v7, "Status for "

    .line 335
    .line 336
    iget-object v8, v2, Lmb/o;->y:Ljava/lang/Boolean;

    .line 337
    .line 338
    sget-object v9, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 339
    .line 340
    invoke-static {v8, v9}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 341
    .line 342
    .line 343
    move-result v8

    .line 344
    if-eqz v8, :cond_a

    .line 345
    .line 346
    sget-object v3, Lfb/g0;->a:Ljava/lang/String;

    .line 347
    .line 348
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 349
    .line 350
    .line 351
    move-result-object v4

    .line 352
    new-instance v5, Ljava/lang/StringBuilder;

    .line 353
    .line 354
    const-string v6, "Worker "

    .line 355
    .line 356
    invoke-direct {v5, v6}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 357
    .line 358
    .line 359
    iget-object v2, v2, Lmb/o;->c:Ljava/lang/String;

    .line 360
    .line 361
    invoke-virtual {v5, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 362
    .line 363
    .line 364
    const-string v2, " was interrupted. Backing off."

    .line 365
    .line 366
    invoke-virtual {v5, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 367
    .line 368
    .line 369
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 370
    .line 371
    .line 372
    move-result-object v2

    .line 373
    invoke-virtual {v4, v3, v2}, Leb/w;->a(Ljava/lang/String;Ljava/lang/String;)V

    .line 374
    .line 375
    .line 376
    invoke-virtual {p0, v0}, Lfb/f0;->b(I)V

    .line 377
    .line 378
    .line 379
    goto :goto_2

    .line 380
    :cond_a
    invoke-virtual {v5, v4}, Lmb/s;->d(Ljava/lang/String;)Leb/h0;

    .line 381
    .line 382
    .line 383
    move-result-object p0

    .line 384
    if-eqz p0, :cond_b

    .line 385
    .line 386
    invoke-virtual {p0}, Leb/h0;->a()Z

    .line 387
    .line 388
    .line 389
    move-result v2

    .line 390
    if-nez v2, :cond_b

    .line 391
    .line 392
    sget-object v2, Lfb/g0;->a:Ljava/lang/String;

    .line 393
    .line 394
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 395
    .line 396
    .line 397
    move-result-object v3

    .line 398
    new-instance v8, Ljava/lang/StringBuilder;

    .line 399
    .line 400
    invoke-direct {v8, v7}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 401
    .line 402
    .line 403
    invoke-virtual {v8, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 404
    .line 405
    .line 406
    invoke-virtual {v8, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 407
    .line 408
    .line 409
    invoke-virtual {v8, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 410
    .line 411
    .line 412
    const-string p0, "; not doing any work and rescheduling for later execution"

    .line 413
    .line 414
    invoke-virtual {v8, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 415
    .line 416
    .line 417
    invoke-virtual {v8}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 418
    .line 419
    .line 420
    move-result-object p0

    .line 421
    invoke-virtual {v3, v2, p0}, Leb/w;->a(Ljava/lang/String;Ljava/lang/String;)V

    .line 422
    .line 423
    .line 424
    sget-object p0, Leb/h0;->d:Leb/h0;

    .line 425
    .line 426
    invoke-virtual {v5, p0, v4}, Lmb/s;->j(Leb/h0;Ljava/lang/String;)I

    .line 427
    .line 428
    .line 429
    invoke-virtual {v5, v0, v4}, Lmb/s;->k(ILjava/lang/String;)V

    .line 430
    .line 431
    .line 432
    const-wide/16 v2, -0x1

    .line 433
    .line 434
    invoke-virtual {v5, v2, v3, v4}, Lmb/s;->g(JLjava/lang/String;)I

    .line 435
    .line 436
    .line 437
    goto/16 :goto_2

    .line 438
    .line 439
    :cond_b
    sget-object v0, Lfb/g0;->a:Ljava/lang/String;

    .line 440
    .line 441
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 442
    .line 443
    .line 444
    move-result-object v1

    .line 445
    new-instance v2, Ljava/lang/StringBuilder;

    .line 446
    .line 447
    invoke-direct {v2, v7}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 448
    .line 449
    .line 450
    invoke-virtual {v2, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 451
    .line 452
    .line 453
    invoke-virtual {v2, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 454
    .line 455
    .line 456
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 457
    .line 458
    .line 459
    const-string p0, " ; not doing any work"

    .line 460
    .line 461
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 462
    .line 463
    .line 464
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 465
    .line 466
    .line 467
    move-result-object p0

    .line 468
    invoke-virtual {v1, v0, p0}, Leb/w;->a(Ljava/lang/String;Ljava/lang/String;)V

    .line 469
    .line 470
    .line 471
    goto/16 :goto_0

    .line 472
    .line 473
    :goto_3
    invoke-static {v3}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 474
    .line 475
    .line 476
    move-result-object p0

    .line 477
    return-object p0

    .line 478
    :cond_c
    new-instance p0, La8/r0;

    .line 479
    .line 480
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 481
    .line 482
    .line 483
    throw p0

    .line 484
    :pswitch_1
    iget-object v0, p0, Lcom/google/firebase/messaging/h;->b:Ljava/lang/Object;

    .line 485
    .line 486
    check-cast v0, Les/d;

    .line 487
    .line 488
    iget-object p0, p0, Lcom/google/firebase/messaging/h;->c:Ljava/lang/Object;

    .line 489
    .line 490
    check-cast p0, Les/a;

    .line 491
    .line 492
    iget-object v3, v0, Les/d;->c:Landroidx/lifecycle/c1;

    .line 493
    .line 494
    new-instance v4, Lorg/json/JSONObject;

    .line 495
    .line 496
    invoke-direct {v4}, Lorg/json/JSONObject;-><init>()V

    .line 497
    .line 498
    .line 499
    const-string v5, "playIntegrityToken"

    .line 500
    .line 501
    iget-object p0, p0, Les/a;->d:Ljava/lang/String;

    .line 502
    .line 503
    invoke-virtual {v4, v5, p0}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 504
    .line 505
    .line 506
    invoke-virtual {v4}, Lorg/json/JSONObject;->toString()Ljava/lang/String;

    .line 507
    .line 508
    .line 509
    move-result-object p0

    .line 510
    const-string v4, "UTF-8"

    .line 511
    .line 512
    invoke-virtual {p0, v4}, Ljava/lang/String;->getBytes(Ljava/lang/String;)[B

    .line 513
    .line 514
    .line 515
    move-result-object p0

    .line 516
    iget-object v0, v0, Les/d;->f:Las/e;

    .line 517
    .line 518
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 519
    .line 520
    .line 521
    iget-wide v4, v0, Las/e;->b:J

    .line 522
    .line 523
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 524
    .line 525
    .line 526
    move-result-wide v6

    .line 527
    cmp-long v4, v4, v6

    .line 528
    .line 529
    if-gtz v4, :cond_10

    .line 530
    .line 531
    new-instance v4, Ljava/net/URL;

    .line 532
    .line 533
    iget-object v5, v3, Landroidx/lifecycle/c1;->h:Ljava/lang/Object;

    .line 534
    .line 535
    check-cast v5, Ljava/lang/String;

    .line 536
    .line 537
    iget-object v6, v3, Landroidx/lifecycle/c1;->g:Ljava/lang/Object;

    .line 538
    .line 539
    check-cast v6, Ljava/lang/String;

    .line 540
    .line 541
    iget-object v7, v3, Landroidx/lifecycle/c1;->f:Ljava/lang/Object;

    .line 542
    .line 543
    check-cast v7, Ljava/lang/String;

    .line 544
    .line 545
    const-string v8, "https://firebaseappcheck.googleapis.com/v1/projects/"

    .line 546
    .line 547
    const-string v9, "/apps/"

    .line 548
    .line 549
    const-string v10, ":exchangePlayIntegrityToken?key="

    .line 550
    .line 551
    invoke-static {v8, v5, v9, v6, v10}, Lu/w;->k(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 552
    .line 553
    .line 554
    move-result-object v5

    .line 555
    invoke-virtual {v5, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 556
    .line 557
    .line 558
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 559
    .line 560
    .line 561
    move-result-object v5

    .line 562
    invoke-direct {v4, v5}, Ljava/net/URL;-><init>(Ljava/lang/String;)V

    .line 563
    .line 564
    .line 565
    invoke-virtual {v3, v4, p0, v0, v1}, Landroidx/lifecycle/c1;->D(Ljava/net/URL;[BLas/e;Z)Ljava/lang/String;

    .line 566
    .line 567
    .line 568
    move-result-object p0

    .line 569
    new-instance v0, Lorg/json/JSONObject;

    .line 570
    .line 571
    invoke-direct {v0, p0}, Lorg/json/JSONObject;-><init>(Ljava/lang/String;)V

    .line 572
    .line 573
    .line 574
    const-string p0, "token"

    .line 575
    .line 576
    invoke-virtual {v0, p0}, Lorg/json/JSONObject;->optString(Ljava/lang/String;)Ljava/lang/String;

    .line 577
    .line 578
    .line 579
    move-result-object p0

    .line 580
    sget v1, Lto/c;->a:I

    .line 581
    .line 582
    invoke-static {p0}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 583
    .line 584
    .line 585
    move-result v1

    .line 586
    if-eqz v1, :cond_d

    .line 587
    .line 588
    move-object p0, v2

    .line 589
    :cond_d
    const-string v1, "ttl"

    .line 590
    .line 591
    invoke-virtual {v0, v1}, Lorg/json/JSONObject;->optString(Ljava/lang/String;)Ljava/lang/String;

    .line 592
    .line 593
    .line 594
    move-result-object v0

    .line 595
    invoke-static {v0}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 596
    .line 597
    .line 598
    move-result v1

    .line 599
    if-eqz v1, :cond_e

    .line 600
    .line 601
    goto :goto_4

    .line 602
    :cond_e
    move-object v2, v0

    .line 603
    :goto_4
    if-eqz p0, :cond_f

    .line 604
    .line 605
    if-eqz v2, :cond_f

    .line 606
    .line 607
    new-instance v0, Las/a;

    .line 608
    .line 609
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 610
    .line 611
    .line 612
    iput-object p0, v0, Las/a;->a:Ljava/lang/String;

    .line 613
    .line 614
    iput-object v2, v0, Las/a;->b:Ljava/lang/String;

    .line 615
    .line 616
    return-object v0

    .line 617
    :cond_f
    new-instance p0, Lsr/h;

    .line 618
    .line 619
    const-string v0, "Unexpected server response."

    .line 620
    .line 621
    invoke-direct {p0, v0}, Lsr/h;-><init>(Ljava/lang/String;)V

    .line 622
    .line 623
    .line 624
    throw p0

    .line 625
    :cond_10
    new-instance p0, Lsr/h;

    .line 626
    .line 627
    const-string v0, "Too many attempts."

    .line 628
    .line 629
    invoke-direct {p0, v0}, Lsr/h;-><init>(Ljava/lang/String;)V

    .line 630
    .line 631
    .line 632
    throw p0

    .line 633
    :pswitch_2
    iget-object v0, p0, Lcom/google/firebase/messaging/h;->b:Ljava/lang/Object;

    .line 634
    .line 635
    check-cast v0, Ldu/c;

    .line 636
    .line 637
    iget-object p0, p0, Lcom/google/firebase/messaging/h;->c:Ljava/lang/Object;

    .line 638
    .line 639
    check-cast p0, Ldu/e;

    .line 640
    .line 641
    iget-object v0, v0, Ldu/c;->b:Ldu/o;

    .line 642
    .line 643
    monitor-enter v0

    .line 644
    :try_start_0
    iget-object v1, v0, Ldu/o;->a:Landroid/content/Context;

    .line 645
    .line 646
    iget-object v4, v0, Ldu/o;->b:Ljava/lang/String;

    .line 647
    .line 648
    invoke-virtual {v1, v4, v3}, Landroid/content/Context;->openFileOutput(Ljava/lang/String;I)Ljava/io/FileOutputStream;

    .line 649
    .line 650
    .line 651
    move-result-object v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 652
    :try_start_1
    iget-object p0, p0, Ldu/e;->a:Lorg/json/JSONObject;

    .line 653
    .line 654
    invoke-virtual {p0}, Lorg/json/JSONObject;->toString()Ljava/lang/String;

    .line 655
    .line 656
    .line 657
    move-result-object p0

    .line 658
    const-string v3, "UTF-8"

    .line 659
    .line 660
    invoke-virtual {p0, v3}, Ljava/lang/String;->getBytes(Ljava/lang/String;)[B

    .line 661
    .line 662
    .line 663
    move-result-object p0

    .line 664
    invoke-virtual {v1, p0}, Ljava/io/FileOutputStream;->write([B)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 665
    .line 666
    .line 667
    :try_start_2
    invoke-virtual {v1}, Ljava/io/FileOutputStream;->close()V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 668
    .line 669
    .line 670
    monitor-exit v0

    .line 671
    return-object v2

    .line 672
    :catchall_0
    move-exception p0

    .line 673
    goto :goto_5

    .line 674
    :catchall_1
    move-exception p0

    .line 675
    :try_start_3
    invoke-virtual {v1}, Ljava/io/FileOutputStream;->close()V

    .line 676
    .line 677
    .line 678
    throw p0

    .line 679
    :goto_5
    monitor-exit v0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 680
    throw p0

    .line 681
    :pswitch_3
    iget-object v0, p0, Lcom/google/firebase/messaging/h;->b:Ljava/lang/Object;

    .line 682
    .line 683
    check-cast v0, Landroid/content/Context;

    .line 684
    .line 685
    iget-object p0, p0, Lcom/google/firebase/messaging/h;->c:Ljava/lang/Object;

    .line 686
    .line 687
    check-cast p0, Landroid/content/Intent;

    .line 688
    .line 689
    invoke-static {}, Lcom/google/firebase/messaging/w;->k()Lcom/google/firebase/messaging/w;

    .line 690
    .line 691
    .line 692
    move-result-object v1

    .line 693
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 694
    .line 695
    .line 696
    const-string v4, "FirebaseMessaging"

    .line 697
    .line 698
    const/4 v5, 0x3

    .line 699
    invoke-static {v4, v5}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 700
    .line 701
    .line 702
    move-result v4

    .line 703
    if-eqz v4, :cond_11

    .line 704
    .line 705
    const-string v4, "FirebaseMessaging"

    .line 706
    .line 707
    const-string v6, "Starting service"

    .line 708
    .line 709
    invoke-static {v4, v6}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 710
    .line 711
    .line 712
    :cond_11
    iget-object v4, v1, Lcom/google/firebase/messaging/w;->h:Ljava/lang/Object;

    .line 713
    .line 714
    check-cast v4, Ljava/util/ArrayDeque;

    .line 715
    .line 716
    invoke-virtual {v4, p0}, Ljava/util/ArrayDeque;->offer(Ljava/lang/Object;)Z

    .line 717
    .line 718
    .line 719
    new-instance p0, Landroid/content/Intent;

    .line 720
    .line 721
    const-string v4, "com.google.firebase.MESSAGING_EVENT"

    .line 722
    .line 723
    invoke-direct {p0, v4}, Landroid/content/Intent;-><init>(Ljava/lang/String;)V

    .line 724
    .line 725
    .line 726
    invoke-virtual {v0}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 727
    .line 728
    .line 729
    move-result-object v4

    .line 730
    invoke-virtual {p0, v4}, Landroid/content/Intent;->setPackage(Ljava/lang/String;)Landroid/content/Intent;

    .line 731
    .line 732
    .line 733
    const-string v4, "Error resolving target intent service, skipping classname enforcement. Resolved service was: "

    .line 734
    .line 735
    monitor-enter v1

    .line 736
    :try_start_4
    iget-object v6, v1, Lcom/google/firebase/messaging/w;->e:Ljava/lang/Object;

    .line 737
    .line 738
    check-cast v6, Ljava/lang/String;
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_2

    .line 739
    .line 740
    if-eqz v6, :cond_12

    .line 741
    .line 742
    monitor-exit v1

    .line 743
    move-object v2, v6

    .line 744
    goto/16 :goto_9

    .line 745
    .line 746
    :cond_12
    :try_start_5
    invoke-virtual {v0}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    .line 747
    .line 748
    .line 749
    move-result-object v6

    .line 750
    invoke-virtual {v6, p0, v3}, Landroid/content/pm/PackageManager;->resolveService(Landroid/content/Intent;I)Landroid/content/pm/ResolveInfo;

    .line 751
    .line 752
    .line 753
    move-result-object v3

    .line 754
    if-eqz v3, :cond_17

    .line 755
    .line 756
    iget-object v3, v3, Landroid/content/pm/ResolveInfo;->serviceInfo:Landroid/content/pm/ServiceInfo;

    .line 757
    .line 758
    if-nez v3, :cond_13

    .line 759
    .line 760
    goto :goto_8

    .line 761
    :cond_13
    invoke-virtual {v0}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 762
    .line 763
    .line 764
    move-result-object v6

    .line 765
    iget-object v7, v3, Landroid/content/pm/ServiceInfo;->packageName:Ljava/lang/String;

    .line 766
    .line 767
    invoke-virtual {v6, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 768
    .line 769
    .line 770
    move-result v6

    .line 771
    if-eqz v6, :cond_16

    .line 772
    .line 773
    iget-object v6, v3, Landroid/content/pm/ServiceInfo;->name:Ljava/lang/String;

    .line 774
    .line 775
    if-nez v6, :cond_14

    .line 776
    .line 777
    goto :goto_7

    .line 778
    :cond_14
    const-string v2, "."

    .line 779
    .line 780
    invoke-virtual {v6, v2}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    .line 781
    .line 782
    .line 783
    move-result v2

    .line 784
    if-eqz v2, :cond_15

    .line 785
    .line 786
    new-instance v2, Ljava/lang/StringBuilder;

    .line 787
    .line 788
    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    .line 789
    .line 790
    .line 791
    invoke-virtual {v0}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 792
    .line 793
    .line 794
    move-result-object v4

    .line 795
    invoke-virtual {v2, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 796
    .line 797
    .line 798
    iget-object v3, v3, Landroid/content/pm/ServiceInfo;->name:Ljava/lang/String;

    .line 799
    .line 800
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 801
    .line 802
    .line 803
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 804
    .line 805
    .line 806
    move-result-object v2

    .line 807
    iput-object v2, v1, Lcom/google/firebase/messaging/w;->e:Ljava/lang/Object;

    .line 808
    .line 809
    goto :goto_6

    .line 810
    :catchall_2
    move-exception p0

    .line 811
    goto/16 :goto_c

    .line 812
    .line 813
    :cond_15
    iget-object v2, v3, Landroid/content/pm/ServiceInfo;->name:Ljava/lang/String;

    .line 814
    .line 815
    iput-object v2, v1, Lcom/google/firebase/messaging/w;->e:Ljava/lang/Object;

    .line 816
    .line 817
    :goto_6
    iget-object v2, v1, Lcom/google/firebase/messaging/w;->e:Ljava/lang/Object;

    .line 818
    .line 819
    check-cast v2, Ljava/lang/String;
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_2

    .line 820
    .line 821
    monitor-exit v1

    .line 822
    goto :goto_9

    .line 823
    :cond_16
    :goto_7
    :try_start_6
    const-string v6, "FirebaseMessaging"

    .line 824
    .line 825
    new-instance v7, Ljava/lang/StringBuilder;

    .line 826
    .line 827
    invoke-direct {v7, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 828
    .line 829
    .line 830
    iget-object v4, v3, Landroid/content/pm/ServiceInfo;->packageName:Ljava/lang/String;

    .line 831
    .line 832
    invoke-virtual {v7, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 833
    .line 834
    .line 835
    const-string v4, "/"

    .line 836
    .line 837
    invoke-virtual {v7, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 838
    .line 839
    .line 840
    iget-object v3, v3, Landroid/content/pm/ServiceInfo;->name:Ljava/lang/String;

    .line 841
    .line 842
    invoke-virtual {v7, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 843
    .line 844
    .line 845
    invoke-virtual {v7}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 846
    .line 847
    .line 848
    move-result-object v3

    .line 849
    invoke-static {v6, v3}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_2

    .line 850
    .line 851
    .line 852
    monitor-exit v1

    .line 853
    goto :goto_9

    .line 854
    :cond_17
    :goto_8
    :try_start_7
    const-string v3, "FirebaseMessaging"

    .line 855
    .line 856
    const-string v4, "Failed to resolve target intent service, skipping classname enforcement"

    .line 857
    .line 858
    invoke-static {v3, v4}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_2

    .line 859
    .line 860
    .line 861
    monitor-exit v1

    .line 862
    :goto_9
    if-eqz v2, :cond_19

    .line 863
    .line 864
    const-string v3, "FirebaseMessaging"

    .line 865
    .line 866
    invoke-static {v3, v5}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 867
    .line 868
    .line 869
    move-result v3

    .line 870
    if-eqz v3, :cond_18

    .line 871
    .line 872
    const-string v3, "FirebaseMessaging"

    .line 873
    .line 874
    const-string v4, "Restricting intent to a specific service: "

    .line 875
    .line 876
    invoke-virtual {v4, v2}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 877
    .line 878
    .line 879
    move-result-object v4

    .line 880
    invoke-static {v3, v4}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 881
    .line 882
    .line 883
    :cond_18
    invoke-virtual {v0}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 884
    .line 885
    .line 886
    move-result-object v3

    .line 887
    invoke-virtual {p0, v3, v2}, Landroid/content/Intent;->setClassName(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;

    .line 888
    .line 889
    .line 890
    :cond_19
    :try_start_8
    invoke-virtual {v1, v0}, Lcom/google/firebase/messaging/w;->n(Landroid/content/Context;)Z

    .line 891
    .line 892
    .line 893
    move-result v1

    .line 894
    if-eqz v1, :cond_1a

    .line 895
    .line 896
    invoke-static {v0, p0}, Lcom/google/firebase/messaging/g0;->c(Landroid/content/Context;Landroid/content/Intent;)Landroid/content/ComponentName;

    .line 897
    .line 898
    .line 899
    move-result-object p0

    .line 900
    goto :goto_a

    .line 901
    :cond_1a
    invoke-virtual {v0, p0}, Landroid/content/Context;->startService(Landroid/content/Intent;)Landroid/content/ComponentName;

    .line 902
    .line 903
    .line 904
    move-result-object p0

    .line 905
    const-string v0, "FirebaseMessaging"

    .line 906
    .line 907
    const-string v1, "Missing wake lock permission, service start may be delayed"

    .line 908
    .line 909
    invoke-static {v0, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 910
    .line 911
    .line 912
    :goto_a
    if-nez p0, :cond_1b

    .line 913
    .line 914
    const-string p0, "FirebaseMessaging"

    .line 915
    .line 916
    const-string v0, "Error while delivering the message: ServiceIntent not found."

    .line 917
    .line 918
    invoke-static {p0, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I
    :try_end_8
    .catch Ljava/lang/SecurityException; {:try_start_8 .. :try_end_8} :catch_1
    .catch Ljava/lang/IllegalStateException; {:try_start_8 .. :try_end_8} :catch_0

    .line 919
    .line 920
    .line 921
    const/16 p0, 0x194

    .line 922
    .line 923
    goto :goto_b

    .line 924
    :cond_1b
    const/4 p0, -0x1

    .line 925
    goto :goto_b

    .line 926
    :catch_0
    move-exception p0

    .line 927
    const-string v0, "FirebaseMessaging"

    .line 928
    .line 929
    new-instance v1, Ljava/lang/StringBuilder;

    .line 930
    .line 931
    const-string v2, "Failed to start service while in background: "

    .line 932
    .line 933
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 934
    .line 935
    .line 936
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 937
    .line 938
    .line 939
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 940
    .line 941
    .line 942
    move-result-object p0

    .line 943
    invoke-static {v0, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 944
    .line 945
    .line 946
    const/16 p0, 0x192

    .line 947
    .line 948
    goto :goto_b

    .line 949
    :catch_1
    move-exception p0

    .line 950
    const-string v0, "FirebaseMessaging"

    .line 951
    .line 952
    const-string v1, "Error while delivering the message to the serviceIntent"

    .line 953
    .line 954
    invoke-static {v0, v1, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 955
    .line 956
    .line 957
    const/16 p0, 0x191

    .line 958
    .line 959
    :goto_b
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 960
    .line 961
    .line 962
    move-result-object p0

    .line 963
    return-object p0

    .line 964
    :goto_c
    :try_start_9
    monitor-exit v1
    :try_end_9
    .catchall {:try_start_9 .. :try_end_9} :catchall_2

    .line 965
    throw p0

    .line 966
    nop

    .line 967
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
