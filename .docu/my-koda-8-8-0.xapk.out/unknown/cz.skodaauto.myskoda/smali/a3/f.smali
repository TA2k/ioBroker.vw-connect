.class public final La3/f;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, La3/f;->f:I

    .line 2
    .line 3
    iput-object p1, p0, La3/f;->g:Ljava/lang/Object;

    .line 4
    .line 5
    const/4 p1, 0x1

    .line 6
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    .line 1
    iget v0, p0, La3/f;->f:I

    .line 2
    .line 3
    const/high16 v1, 0x3f800000    # 1.0f

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    const/4 v3, 0x1

    .line 7
    const/4 v4, 0x0

    .line 8
    packed-switch v0, :pswitch_data_0

    .line 9
    .line 10
    .line 11
    check-cast p1, Lx2/q;

    .line 12
    .line 13
    iget-object p0, p0, La3/f;->g:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast p0, Ln2/b;

    .line 16
    .line 17
    invoke-virtual {p0, p1}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 18
    .line 19
    .line 20
    sget-object p0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 21
    .line 22
    return-object p0

    .line 23
    :pswitch_0
    check-cast p1, Lv3/a;

    .line 24
    .line 25
    iget-object p0, p0, La3/f;->g:Ljava/lang/Object;

    .line 26
    .line 27
    check-cast p0, Lv3/i0;

    .line 28
    .line 29
    invoke-interface {p1}, Lv3/a;->w()Z

    .line 30
    .line 31
    .line 32
    move-result v0

    .line 33
    if-nez v0, :cond_0

    .line 34
    .line 35
    goto/16 :goto_3

    .line 36
    .line 37
    :cond_0
    invoke-interface {p1}, Lv3/a;->b()Lv3/i0;

    .line 38
    .line 39
    .line 40
    move-result-object v0

    .line 41
    iget-boolean v0, v0, Lv3/i0;->b:Z

    .line 42
    .line 43
    if-eqz v0, :cond_1

    .line 44
    .line 45
    invoke-interface {p1}, Lv3/a;->t()V

    .line 46
    .line 47
    .line 48
    :cond_1
    invoke-interface {p1}, Lv3/a;->b()Lv3/i0;

    .line 49
    .line 50
    .line 51
    move-result-object v0

    .line 52
    iget-object v0, v0, Lv3/i0;->i:Ljava/util/HashMap;

    .line 53
    .line 54
    invoke-virtual {v0}, Ljava/util/HashMap;->entrySet()Ljava/util/Set;

    .line 55
    .line 56
    .line 57
    move-result-object v0

    .line 58
    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 59
    .line 60
    .line 61
    move-result-object v0

    .line 62
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 63
    .line 64
    .line 65
    move-result v1

    .line 66
    if-eqz v1, :cond_2

    .line 67
    .line 68
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    move-result-object v1

    .line 72
    check-cast v1, Ljava/util/Map$Entry;

    .line 73
    .line 74
    invoke-interface {v1}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 75
    .line 76
    .line 77
    move-result-object v2

    .line 78
    check-cast v2, Lt3/a;

    .line 79
    .line 80
    invoke-interface {v1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 81
    .line 82
    .line 83
    move-result-object v1

    .line 84
    check-cast v1, Ljava/lang/Number;

    .line 85
    .line 86
    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    .line 87
    .line 88
    .line 89
    move-result v1

    .line 90
    invoke-interface {p1}, Lv3/a;->E()Lv3/u;

    .line 91
    .line 92
    .line 93
    move-result-object v3

    .line 94
    invoke-static {p0, v2, v1, v3}, Lv3/i0;->a(Lv3/i0;Lt3/a;ILv3/f1;)V

    .line 95
    .line 96
    .line 97
    goto :goto_0

    .line 98
    :cond_2
    invoke-interface {p1}, Lv3/a;->E()Lv3/u;

    .line 99
    .line 100
    .line 101
    move-result-object p1

    .line 102
    iget-object p1, p1, Lv3/f1;->t:Lv3/f1;

    .line 103
    .line 104
    invoke-static {p1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 105
    .line 106
    .line 107
    :goto_1
    iget-object v0, p0, Lv3/i0;->a:Lt3/e1;

    .line 108
    .line 109
    invoke-interface {v0}, Lv3/a;->E()Lv3/u;

    .line 110
    .line 111
    .line 112
    move-result-object v0

    .line 113
    invoke-virtual {p1, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 114
    .line 115
    .line 116
    move-result v0

    .line 117
    if-nez v0, :cond_4

    .line 118
    .line 119
    invoke-virtual {p0, p1}, Lv3/i0;->b(Lv3/f1;)Ljava/util/Map;

    .line 120
    .line 121
    .line 122
    move-result-object v0

    .line 123
    invoke-interface {v0}, Ljava/util/Map;->keySet()Ljava/util/Set;

    .line 124
    .line 125
    .line 126
    move-result-object v0

    .line 127
    check-cast v0, Ljava/lang/Iterable;

    .line 128
    .line 129
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 130
    .line 131
    .line 132
    move-result-object v0

    .line 133
    :goto_2
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 134
    .line 135
    .line 136
    move-result v1

    .line 137
    if-eqz v1, :cond_3

    .line 138
    .line 139
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 140
    .line 141
    .line 142
    move-result-object v1

    .line 143
    check-cast v1, Lt3/a;

    .line 144
    .line 145
    invoke-virtual {p0, p1, v1}, Lv3/i0;->c(Lv3/f1;Lt3/a;)I

    .line 146
    .line 147
    .line 148
    move-result v2

    .line 149
    invoke-static {p0, v1, v2, p1}, Lv3/i0;->a(Lv3/i0;Lt3/a;ILv3/f1;)V

    .line 150
    .line 151
    .line 152
    goto :goto_2

    .line 153
    :cond_3
    iget-object p1, p1, Lv3/f1;->t:Lv3/f1;

    .line 154
    .line 155
    invoke-static {p1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 156
    .line 157
    .line 158
    goto :goto_1

    .line 159
    :cond_4
    :goto_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 160
    .line 161
    return-object p0

    .line 162
    :pswitch_1
    check-cast p1, Ljava/lang/Throwable;

    .line 163
    .line 164
    iget-object p0, p0, La3/f;->g:Ljava/lang/Object;

    .line 165
    .line 166
    check-cast p0, Ljava/util/concurrent/FutureTask;

    .line 167
    .line 168
    invoke-virtual {p0, v3}, Ljava/util/concurrent/FutureTask;->cancel(Z)Z

    .line 169
    .line 170
    .line 171
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 172
    .line 173
    return-object p0

    .line 174
    :pswitch_2
    check-cast p1, Ljava/lang/Throwable;

    .line 175
    .line 176
    iget-object p0, p0, La3/f;->g:Ljava/lang/Object;

    .line 177
    .line 178
    check-cast p0, Lp3/i0;

    .line 179
    .line 180
    iget-object v0, p0, Lp3/i0;->f:Lvy0/l;

    .line 181
    .line 182
    if-eqz v0, :cond_5

    .line 183
    .line 184
    invoke-virtual {v0, p1}, Lvy0/l;->c(Ljava/lang/Throwable;)Z

    .line 185
    .line 186
    .line 187
    :cond_5
    iput-object v4, p0, Lp3/i0;->f:Lvy0/l;

    .line 188
    .line 189
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 190
    .line 191
    return-object p0

    .line 192
    :pswitch_3
    check-cast p1, Ljava/io/File;

    .line 193
    .line 194
    const-string v0, "it"

    .line 195
    .line 196
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 197
    .line 198
    .line 199
    new-instance v0, Lm6/p0;

    .line 200
    .line 201
    iget-object p0, p0, La3/f;->g:Ljava/lang/Object;

    .line 202
    .line 203
    check-cast p0, Lpw0/a;

    .line 204
    .line 205
    iget-object p0, p0, Lpw0/a;->e:Lpx0/g;

    .line 206
    .line 207
    invoke-direct {v0, p0, p1}, Lm6/p0;-><init>(Lpx0/g;Ljava/io/File;)V

    .line 208
    .line 209
    .line 210
    return-object v0

    .line 211
    :pswitch_4
    check-cast p1, Ljava/lang/Throwable;

    .line 212
    .line 213
    iget-object p0, p0, La3/f;->g:Ljava/lang/Object;

    .line 214
    .line 215
    check-cast p0, Lm6/w;

    .line 216
    .line 217
    iget-object v0, p0, Lm6/w;->j:Llx0/q;

    .line 218
    .line 219
    if-eqz p1, :cond_6

    .line 220
    .line 221
    iget-object p0, p0, Lm6/w;->h:Lm6/x;

    .line 222
    .line 223
    new-instance v1, Lm6/h0;

    .line 224
    .line 225
    invoke-direct {v1, p1}, Lm6/h0;-><init>(Ljava/lang/Throwable;)V

    .line 226
    .line 227
    .line 228
    invoke-virtual {p0, v1}, Lm6/x;->b(Lm6/z0;)V

    .line 229
    .line 230
    .line 231
    :cond_6
    invoke-virtual {v0}, Llx0/q;->isInitialized()Z

    .line 232
    .line 233
    .line 234
    move-result p0

    .line 235
    if-eqz p0, :cond_7

    .line 236
    .line 237
    invoke-virtual {v0}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 238
    .line 239
    .line 240
    move-result-object p0

    .line 241
    check-cast p0, Lm6/e0;

    .line 242
    .line 243
    invoke-virtual {p0}, Lm6/e0;->close()V

    .line 244
    .line 245
    .line 246
    :cond_7
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 247
    .line 248
    return-object p0

    .line 249
    :pswitch_5
    check-cast p1, Ljava/io/IOException;

    .line 250
    .line 251
    iget-object p0, p0, La3/f;->g:Ljava/lang/Object;

    .line 252
    .line 253
    check-cast p0, Lll/d;

    .line 254
    .line 255
    iput-boolean v3, p0, Lll/d;->n:Z

    .line 256
    .line 257
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 258
    .line 259
    return-object p0

    .line 260
    :pswitch_6
    check-cast p1, Lb/a0;

    .line 261
    .line 262
    const-string v0, "$this$addCallback"

    .line 263
    .line 264
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 265
    .line 266
    .line 267
    iget-object p0, p0, La3/f;->g:Ljava/lang/Object;

    .line 268
    .line 269
    check-cast p0, Lkn/k0;

    .line 270
    .line 271
    iget-object p1, p0, Lkn/k0;->h:Lkn/j0;

    .line 272
    .line 273
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 274
    .line 275
    .line 276
    iget-object p0, p0, Lkn/k0;->g:Lay0/a;

    .line 277
    .line 278
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 279
    .line 280
    .line 281
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 282
    .line 283
    return-object p0

    .line 284
    :pswitch_7
    check-cast p1, Lt3/y;

    .line 285
    .line 286
    const-string v0, "it"

    .line 287
    .line 288
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 289
    .line 290
    .line 291
    iget-object p0, p0, La3/f;->g:Ljava/lang/Object;

    .line 292
    .line 293
    check-cast p0, Lkn/m0;

    .line 294
    .line 295
    iput-object p1, p0, Lkn/m0;->a:Lt3/y;

    .line 296
    .line 297
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 298
    .line 299
    return-object p0

    .line 300
    :pswitch_8
    check-cast p1, Le3/k0;

    .line 301
    .line 302
    const-string v0, "$this$graphicsLayer"

    .line 303
    .line 304
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 305
    .line 306
    .line 307
    iget-object p0, p0, La3/f;->g:Ljava/lang/Object;

    .line 308
    .line 309
    check-cast p0, Lc1/c;

    .line 310
    .line 311
    invoke-virtual {p0}, Lc1/c;->d()Ljava/lang/Object;

    .line 312
    .line 313
    .line 314
    move-result-object p0

    .line 315
    check-cast p0, Ljava/lang/Number;

    .line 316
    .line 317
    invoke-virtual {p0}, Ljava/lang/Number;->floatValue()F

    .line 318
    .line 319
    .line 320
    move-result p0

    .line 321
    invoke-static {p0, v2, v1}, Lkp/r9;->d(FFF)F

    .line 322
    .line 323
    .line 324
    move-result p0

    .line 325
    invoke-virtual {p1, p0}, Le3/k0;->b(F)V

    .line 326
    .line 327
    .line 328
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 329
    .line 330
    return-object p0

    .line 331
    :pswitch_9
    check-cast p1, Lj3/c0;

    .line 332
    .line 333
    iget-object p0, p0, La3/f;->g:Ljava/lang/Object;

    .line 334
    .line 335
    check-cast p0, Lj3/c;

    .line 336
    .line 337
    invoke-virtual {p0, p1}, Lj3/c;->g(Lj3/c0;)V

    .line 338
    .line 339
    .line 340
    iget-object p0, p0, Lj3/c;->i:Lay0/k;

    .line 341
    .line 342
    if-eqz p0, :cond_8

    .line 343
    .line 344
    invoke-interface {p0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 345
    .line 346
    .line 347
    :cond_8
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 348
    .line 349
    return-object p0

    .line 350
    :pswitch_a
    check-cast p1, Landroid/content/Context;

    .line 351
    .line 352
    const-string v0, "it"

    .line 353
    .line 354
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 355
    .line 356
    .line 357
    new-instance p1, Lha/b;

    .line 358
    .line 359
    iget-object p0, p0, La3/f;->g:Ljava/lang/Object;

    .line 360
    .line 361
    check-cast p0, Landroid/content/Context;

    .line 362
    .line 363
    const-string v0, "context"

    .line 364
    .line 365
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 366
    .line 367
    .line 368
    invoke-static {p0}, Lc2/h;->c(Landroid/content/Context;)Landroid/adservices/measurement/MeasurementManager;

    .line 369
    .line 370
    .line 371
    move-result-object p0

    .line 372
    const-string v0, "get(context)"

    .line 373
    .line 374
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 375
    .line 376
    .line 377
    invoke-direct {p1, p0}, Lha/d;-><init>(Landroid/adservices/measurement/MeasurementManager;)V

    .line 378
    .line 379
    .line 380
    return-object p1

    .line 381
    :pswitch_b
    check-cast p1, Ljava/lang/Throwable;

    .line 382
    .line 383
    iget-object p0, p0, La3/f;->g:Ljava/lang/Object;

    .line 384
    .line 385
    check-cast p0, Lvy0/i1;

    .line 386
    .line 387
    invoke-interface {p0, v4}, Lvy0/i1;->d(Ljava/util/concurrent/CancellationException;)V

    .line 388
    .line 389
    .line 390
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 391
    .line 392
    return-object p0

    .line 393
    :pswitch_c
    check-cast p1, Ljava/lang/Throwable;

    .line 394
    .line 395
    iget-object p0, p0, La3/f;->g:Ljava/lang/Object;

    .line 396
    .line 397
    check-cast p0, Lh7/f;

    .line 398
    .line 399
    iget-object p1, p0, Lh7/f;->f:Ljava/lang/Object;

    .line 400
    .line 401
    monitor-enter p1

    .line 402
    const/4 v0, 0x5

    .line 403
    :try_start_0
    iput v0, p0, Lh7/f;->g:I

    .line 404
    .line 405
    iput-object v4, p0, Lh7/f;->i:Lvy0/l;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 406
    .line 407
    monitor-exit p1

    .line 408
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 409
    .line 410
    return-object p0

    .line 411
    :catchall_0
    move-exception p0

    .line 412
    monitor-exit p1

    .line 413
    throw p0

    .line 414
    :pswitch_d
    check-cast p1, Lg3/d;

    .line 415
    .line 416
    iget-object p0, p0, La3/f;->g:Ljava/lang/Object;

    .line 417
    .line 418
    check-cast p0, Lh3/c;

    .line 419
    .line 420
    iget-object v0, p0, Lh3/c;->l:Le3/i;

    .line 421
    .line 422
    iget-boolean v1, p0, Lh3/c;->n:Z

    .line 423
    .line 424
    if-eqz v1, :cond_9

    .line 425
    .line 426
    iget-boolean v1, p0, Lh3/c;->w:Z

    .line 427
    .line 428
    if-eqz v1, :cond_9

    .line 429
    .line 430
    if-eqz v0, :cond_9

    .line 431
    .line 432
    invoke-interface {p1}, Lg3/d;->x0()Lgw0/c;

    .line 433
    .line 434
    .line 435
    move-result-object v1

    .line 436
    invoke-virtual {v1}, Lgw0/c;->o()J

    .line 437
    .line 438
    .line 439
    move-result-wide v4

    .line 440
    invoke-virtual {v1}, Lgw0/c;->h()Le3/r;

    .line 441
    .line 442
    .line 443
    move-result-object v2

    .line 444
    invoke-interface {v2}, Le3/r;->o()V

    .line 445
    .line 446
    .line 447
    :try_start_1
    iget-object v2, v1, Lgw0/c;->e:Ljava/lang/Object;

    .line 448
    .line 449
    check-cast v2, Lbu/c;

    .line 450
    .line 451
    iget-object v2, v2, Lbu/c;->e:Ljava/lang/Object;

    .line 452
    .line 453
    check-cast v2, Lgw0/c;

    .line 454
    .line 455
    invoke-virtual {v2}, Lgw0/c;->h()Le3/r;

    .line 456
    .line 457
    .line 458
    move-result-object v2

    .line 459
    invoke-interface {v2, v0, v3}, Le3/r;->e(Le3/i;I)V

    .line 460
    .line 461
    .line 462
    invoke-virtual {p0, p1}, Lh3/c;->d(Lg3/d;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 463
    .line 464
    .line 465
    invoke-static {v1, v4, v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->y(Lgw0/c;J)V

    .line 466
    .line 467
    .line 468
    goto :goto_4

    .line 469
    :catchall_1
    move-exception p0

    .line 470
    invoke-static {v1, v4, v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->y(Lgw0/c;J)V

    .line 471
    .line 472
    .line 473
    throw p0

    .line 474
    :cond_9
    invoke-virtual {p0, p1}, Lh3/c;->d(Lg3/d;)V

    .line 475
    .line 476
    .line 477
    :goto_4
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 478
    .line 479
    return-object p0

    .line 480
    :pswitch_e
    check-cast p1, Le3/k0;

    .line 481
    .line 482
    iget-object p0, p0, La3/f;->g:Ljava/lang/Object;

    .line 483
    .line 484
    check-cast p0, Le3/o0;

    .line 485
    .line 486
    iget v0, p0, Le3/o0;->r:F

    .line 487
    .line 488
    invoke-virtual {p1, v0}, Le3/k0;->l(F)V

    .line 489
    .line 490
    .line 491
    iget v0, p0, Le3/o0;->s:F

    .line 492
    .line 493
    invoke-virtual {p1, v0}, Le3/k0;->p(F)V

    .line 494
    .line 495
    .line 496
    iget v0, p0, Le3/o0;->t:F

    .line 497
    .line 498
    invoke-virtual {p1, v0}, Le3/k0;->b(F)V

    .line 499
    .line 500
    .line 501
    iget v0, p0, Le3/o0;->u:F

    .line 502
    .line 503
    invoke-virtual {p1, v0}, Le3/k0;->B(F)V

    .line 504
    .line 505
    .line 506
    iget v0, p0, Le3/o0;->v:F

    .line 507
    .line 508
    invoke-virtual {p1, v0}, Le3/k0;->D(F)V

    .line 509
    .line 510
    .line 511
    iget v0, p0, Le3/o0;->w:F

    .line 512
    .line 513
    invoke-virtual {p1, v0}, Le3/k0;->t(F)V

    .line 514
    .line 515
    .line 516
    invoke-virtual {p1, v2}, Le3/k0;->g(F)V

    .line 517
    .line 518
    .line 519
    invoke-virtual {p1, v2}, Le3/k0;->h(F)V

    .line 520
    .line 521
    .line 522
    iget v0, p0, Le3/o0;->x:F

    .line 523
    .line 524
    invoke-virtual {p1, v0}, Le3/k0;->i(F)V

    .line 525
    .line 526
    .line 527
    iget v0, p0, Le3/o0;->y:F

    .line 528
    .line 529
    iget v1, p1, Le3/k0;->p:F

    .line 530
    .line 531
    cmpg-float v1, v1, v0

    .line 532
    .line 533
    if-nez v1, :cond_a

    .line 534
    .line 535
    goto :goto_5

    .line 536
    :cond_a
    iget v1, p1, Le3/k0;->d:I

    .line 537
    .line 538
    or-int/lit16 v1, v1, 0x800

    .line 539
    .line 540
    iput v1, p1, Le3/k0;->d:I

    .line 541
    .line 542
    iput v0, p1, Le3/k0;->p:F

    .line 543
    .line 544
    :goto_5
    iget-wide v0, p0, Le3/o0;->z:J

    .line 545
    .line 546
    invoke-virtual {p1, v0, v1}, Le3/k0;->A(J)V

    .line 547
    .line 548
    .line 549
    iget-object v0, p0, Le3/o0;->A:Le3/n0;

    .line 550
    .line 551
    invoke-virtual {p1, v0}, Le3/k0;->w(Le3/n0;)V

    .line 552
    .line 553
    .line 554
    iget-boolean v0, p0, Le3/o0;->B:Z

    .line 555
    .line 556
    invoke-virtual {p1, v0}, Le3/k0;->d(Z)V

    .line 557
    .line 558
    .line 559
    invoke-virtual {p1, v4}, Le3/k0;->f(Le3/o;)V

    .line 560
    .line 561
    .line 562
    iget-wide v0, p0, Le3/o0;->C:J

    .line 563
    .line 564
    invoke-virtual {p1, v0, v1}, Le3/k0;->c(J)V

    .line 565
    .line 566
    .line 567
    iget-wide v0, p0, Le3/o0;->D:J

    .line 568
    .line 569
    invoke-virtual {p1, v0, v1}, Le3/k0;->z(J)V

    .line 570
    .line 571
    .line 572
    iget p0, p0, Le3/o0;->E:I

    .line 573
    .line 574
    iget v0, p1, Le3/k0;->x:I

    .line 575
    .line 576
    if-ne v0, p0, :cond_b

    .line 577
    .line 578
    goto :goto_6

    .line 579
    :cond_b
    iget v0, p1, Le3/k0;->d:I

    .line 580
    .line 581
    const/high16 v1, 0x80000

    .line 582
    .line 583
    or-int/2addr v0, v1

    .line 584
    iput v0, p1, Le3/k0;->d:I

    .line 585
    .line 586
    iput p0, p1, Le3/k0;->x:I

    .line 587
    .line 588
    :goto_6
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 589
    .line 590
    return-object p0

    .line 591
    :pswitch_f
    check-cast p1, Ljava/util/List;

    .line 592
    .line 593
    iget-object p0, p0, La3/f;->g:Ljava/lang/Object;

    .line 594
    .line 595
    check-cast p0, Lo1/t0;

    .line 596
    .line 597
    invoke-virtual {p0}, Lo1/t0;->invoke()Ljava/lang/Object;

    .line 598
    .line 599
    .line 600
    move-result-object p0

    .line 601
    check-cast p0, Ljava/lang/Float;

    .line 602
    .line 603
    invoke-interface {p1, p0}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 604
    .line 605
    .line 606
    invoke-static {v3}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 607
    .line 608
    .line 609
    move-result-object p0

    .line 610
    return-object p0

    .line 611
    :pswitch_10
    check-cast p1, Ld4/l;

    .line 612
    .line 613
    iget-object p0, p0, La3/f;->g:Ljava/lang/Object;

    .line 614
    .line 615
    check-cast p0, Ld4/i;

    .line 616
    .line 617
    iget p0, p0, Ld4/i;->a:I

    .line 618
    .line 619
    invoke-static {p1, p0}, Ld4/x;->i(Ld4/l;I)V

    .line 620
    .line 621
    .line 622
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 623
    .line 624
    return-object p0

    .line 625
    :pswitch_11
    check-cast p1, Ljava/lang/Throwable;

    .line 626
    .line 627
    if-eqz p1, :cond_c

    .line 628
    .line 629
    iget-object p0, p0, La3/f;->g:Ljava/lang/Object;

    .line 630
    .line 631
    check-cast p0, Landroid/os/CancellationSignal;

    .line 632
    .line 633
    invoke-virtual {p0}, Landroid/os/CancellationSignal;->cancel()V

    .line 634
    .line 635
    .line 636
    :cond_c
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 637
    .line 638
    return-object p0

    .line 639
    :pswitch_12
    check-cast p1, Le3/k0;

    .line 640
    .line 641
    iget-object p0, p0, La3/f;->g:Ljava/lang/Object;

    .line 642
    .line 643
    check-cast p0, Landroidx/compose/ui/draw/ShadowGraphicsLayerElement;

    .line 644
    .line 645
    iget v0, p0, Landroidx/compose/ui/draw/ShadowGraphicsLayerElement;->b:F

    .line 646
    .line 647
    invoke-virtual {p1}, Le3/k0;->a()F

    .line 648
    .line 649
    .line 650
    move-result v1

    .line 651
    mul-float/2addr v1, v0

    .line 652
    invoke-virtual {p1, v1}, Le3/k0;->t(F)V

    .line 653
    .line 654
    .line 655
    iget-object v0, p0, Landroidx/compose/ui/draw/ShadowGraphicsLayerElement;->c:Le3/n0;

    .line 656
    .line 657
    invoke-virtual {p1, v0}, Le3/k0;->w(Le3/n0;)V

    .line 658
    .line 659
    .line 660
    iget-boolean v0, p0, Landroidx/compose/ui/draw/ShadowGraphicsLayerElement;->d:Z

    .line 661
    .line 662
    invoke-virtual {p1, v0}, Le3/k0;->d(Z)V

    .line 663
    .line 664
    .line 665
    iget-wide v0, p0, Landroidx/compose/ui/draw/ShadowGraphicsLayerElement;->e:J

    .line 666
    .line 667
    invoke-virtual {p1, v0, v1}, Le3/k0;->c(J)V

    .line 668
    .line 669
    .line 670
    iget-wide v0, p0, Landroidx/compose/ui/draw/ShadowGraphicsLayerElement;->f:J

    .line 671
    .line 672
    invoke-virtual {p1, v0, v1}, Le3/k0;->z(J)V

    .line 673
    .line 674
    .line 675
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 676
    .line 677
    return-object p0

    .line 678
    :pswitch_13
    check-cast p1, Le3/k0;

    .line 679
    .line 680
    iget-object p0, p0, La3/f;->g:Ljava/lang/Object;

    .line 681
    .line 682
    check-cast p0, Ll2/t2;

    .line 683
    .line 684
    invoke-interface {p0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 685
    .line 686
    .line 687
    move-result-object p0

    .line 688
    check-cast p0, Ljava/lang/Number;

    .line 689
    .line 690
    invoke-virtual {p0}, Ljava/lang/Number;->floatValue()F

    .line 691
    .line 692
    .line 693
    move-result p0

    .line 694
    invoke-virtual {p1, p0}, Le3/k0;->b(F)V

    .line 695
    .line 696
    .line 697
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 698
    .line 699
    return-object p0

    .line 700
    :pswitch_14
    iget-object p0, p0, La3/f;->g:Ljava/lang/Object;

    .line 701
    .line 702
    check-cast p0, Lc1/w1;

    .line 703
    .line 704
    iget-object p0, p0, Lc1/w1;->d:Ll2/j1;

    .line 705
    .line 706
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 707
    .line 708
    .line 709
    move-result-object p0

    .line 710
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 711
    .line 712
    .line 713
    move-result p0

    .line 714
    xor-int/2addr p0, v3

    .line 715
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 716
    .line 717
    .line 718
    move-result-object p0

    .line 719
    return-object p0

    .line 720
    :pswitch_15
    check-cast p1, Lc1/o;

    .line 721
    .line 722
    iget v0, p1, Lc1/o;->b:F

    .line 723
    .line 724
    cmpg-float v3, v0, v2

    .line 725
    .line 726
    if-gez v3, :cond_d

    .line 727
    .line 728
    move v0, v2

    .line 729
    :cond_d
    cmpl-float v3, v0, v1

    .line 730
    .line 731
    if-lez v3, :cond_e

    .line 732
    .line 733
    move v0, v1

    .line 734
    :cond_e
    iget v3, p1, Lc1/o;->c:F

    .line 735
    .line 736
    const/high16 v4, -0x41000000    # -0.5f

    .line 737
    .line 738
    cmpg-float v5, v3, v4

    .line 739
    .line 740
    if-gez v5, :cond_f

    .line 741
    .line 742
    move v3, v4

    .line 743
    :cond_f
    const/high16 v5, 0x3f000000    # 0.5f

    .line 744
    .line 745
    cmpl-float v6, v3, v5

    .line 746
    .line 747
    if-lez v6, :cond_10

    .line 748
    .line 749
    move v3, v5

    .line 750
    :cond_10
    iget v6, p1, Lc1/o;->d:F

    .line 751
    .line 752
    cmpg-float v7, v6, v4

    .line 753
    .line 754
    if-gez v7, :cond_11

    .line 755
    .line 756
    goto :goto_7

    .line 757
    :cond_11
    move v4, v6

    .line 758
    :goto_7
    cmpl-float v6, v4, v5

    .line 759
    .line 760
    if-lez v6, :cond_12

    .line 761
    .line 762
    goto :goto_8

    .line 763
    :cond_12
    move v5, v4

    .line 764
    :goto_8
    iget p1, p1, Lc1/o;->a:F

    .line 765
    .line 766
    cmpg-float v4, p1, v2

    .line 767
    .line 768
    if-gez v4, :cond_13

    .line 769
    .line 770
    goto :goto_9

    .line 771
    :cond_13
    move v2, p1

    .line 772
    :goto_9
    cmpl-float p1, v2, v1

    .line 773
    .line 774
    if-lez p1, :cond_14

    .line 775
    .line 776
    goto :goto_a

    .line 777
    :cond_14
    move v1, v2

    .line 778
    :goto_a
    sget-object p1, Lf3/e;->x:Lf3/m;

    .line 779
    .line 780
    invoke-static {v0, v3, v5, v1, p1}, Le3/j0;->b(FFFFLf3/c;)J

    .line 781
    .line 782
    .line 783
    move-result-wide v0

    .line 784
    iget-object p0, p0, La3/f;->g:Ljava/lang/Object;

    .line 785
    .line 786
    check-cast p0, Lf3/c;

    .line 787
    .line 788
    invoke-static {v0, v1, p0}, Le3/s;->a(JLf3/c;)J

    .line 789
    .line 790
    .line 791
    move-result-wide p0

    .line 792
    new-instance v0, Le3/s;

    .line 793
    .line 794
    invoke-direct {v0, p0, p1}, Le3/s;-><init>(J)V

    .line 795
    .line 796
    .line 797
    return-object v0

    .line 798
    :pswitch_16
    iget-object p0, p0, La3/f;->g:Ljava/lang/Object;

    .line 799
    .line 800
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 801
    .line 802
    .line 803
    move-result p0

    .line 804
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 805
    .line 806
    .line 807
    move-result-object p0

    .line 808
    return-object p0

    .line 809
    :pswitch_17
    check-cast p1, Ljava/util/Map$Entry;

    .line 810
    .line 811
    const-string v0, "entry"

    .line 812
    .line 813
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 814
    .line 815
    .line 816
    iget-object p0, p0, La3/f;->g:Ljava/lang/Object;

    .line 817
    .line 818
    check-cast p0, Ljava/util/Collection;

    .line 819
    .line 820
    check-cast p0, Ljava/lang/Iterable;

    .line 821
    .line 822
    invoke-interface {p1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 823
    .line 824
    .line 825
    move-result-object p1

    .line 826
    check-cast p1, Landroid/view/View;

    .line 827
    .line 828
    sget-object v0, Ld6/r0;->a:Ljava/util/WeakHashMap;

    .line 829
    .line 830
    invoke-static {p1}, Ld6/k0;->e(Landroid/view/View;)Ljava/lang/String;

    .line 831
    .line 832
    .line 833
    move-result-object p1

    .line 834
    invoke-static {p0, p1}, Lmx0/q;->A(Ljava/lang/Iterable;Ljava/lang/Object;)Z

    .line 835
    .line 836
    .line 837
    move-result p0

    .line 838
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 839
    .line 840
    .line 841
    move-result-object p0

    .line 842
    return-object p0

    .line 843
    :pswitch_18
    iget-object p0, p0, La3/f;->g:Ljava/lang/Object;

    .line 844
    .line 845
    check-cast p0, Landroidx/collection/r0;

    .line 846
    .line 847
    if-ne p1, p0, :cond_15

    .line 848
    .line 849
    const-string p0, "(this)"

    .line 850
    .line 851
    goto :goto_b

    .line 852
    :cond_15
    invoke-static {p1}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 853
    .line 854
    .line 855
    move-result-object p0

    .line 856
    :goto_b
    return-object p0

    .line 857
    :pswitch_19
    iget-object p0, p0, La3/f;->g:Ljava/lang/Object;

    .line 858
    .line 859
    check-cast p0, Landroidx/collection/m0;

    .line 860
    .line 861
    if-ne p1, p0, :cond_16

    .line 862
    .line 863
    const-string p0, "(this)"

    .line 864
    .line 865
    goto :goto_c

    .line 866
    :cond_16
    invoke-static {p1}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 867
    .line 868
    .line 869
    move-result-object p0

    .line 870
    :goto_c
    return-object p0

    .line 871
    :pswitch_1a
    iget-object p0, p0, La3/f;->g:Ljava/lang/Object;

    .line 872
    .line 873
    check-cast p0, Landroidx/collection/l0;

    .line 874
    .line 875
    if-ne p1, p0, :cond_17

    .line 876
    .line 877
    const-string p0, "(this)"

    .line 878
    .line 879
    goto :goto_d

    .line 880
    :cond_17
    invoke-static {p1}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 881
    .line 882
    .line 883
    move-result-object p0

    .line 884
    :goto_d
    return-object p0

    .line 885
    :pswitch_1b
    check-cast p1, Ljava/lang/Throwable;

    .line 886
    .line 887
    iget-object p0, p0, La3/f;->g:Ljava/lang/Object;

    .line 888
    .line 889
    check-cast p0, Lxy0/x;

    .line 890
    .line 891
    check-cast p0, Lxy0/w;

    .line 892
    .line 893
    invoke-virtual {p0, v4}, Lxy0/w;->e(Ljava/lang/Object;)Ljava/lang/Object;

    .line 894
    .line 895
    .line 896
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 897
    .line 898
    return-object p0

    .line 899
    :pswitch_1c
    check-cast p1, La3/h;

    .line 900
    .line 901
    iget-object v0, p1, Lx2/r;->d:Lx2/r;

    .line 902
    .line 903
    iget-boolean v0, v0, Lx2/r;->q:Z

    .line 904
    .line 905
    if-nez v0, :cond_18

    .line 906
    .line 907
    sget-object p0, Lv3/b2;->e:Lv3/b2;

    .line 908
    .line 909
    goto :goto_f

    .line 910
    :cond_18
    iget-object v0, p1, La3/h;->s:La3/h;

    .line 911
    .line 912
    if-eqz v0, :cond_1a

    .line 913
    .line 914
    iget-object p0, p0, La3/f;->g:Ljava/lang/Object;

    .line 915
    .line 916
    check-cast p0, Lbu/c;

    .line 917
    .line 918
    new-instance v1, La3/f;

    .line 919
    .line 920
    const/4 v2, 0x0

    .line 921
    invoke-direct {v1, p0, v2}, La3/f;-><init>(Ljava/lang/Object;I)V

    .line 922
    .line 923
    .line 924
    invoke-virtual {v1, v0}, La3/f;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 925
    .line 926
    .line 927
    move-result-object p0

    .line 928
    sget-object v2, Lv3/b2;->d:Lv3/b2;

    .line 929
    .line 930
    if-eq p0, v2, :cond_19

    .line 931
    .line 932
    goto :goto_e

    .line 933
    :cond_19
    invoke-static {v0, v1}, Lv3/f;->C(Lv3/c2;Lay0/k;)V

    .line 934
    .line 935
    .line 936
    :cond_1a
    :goto_e
    iput-object v4, p1, La3/h;->s:La3/h;

    .line 937
    .line 938
    iput-object v4, p1, La3/h;->r:La3/h;

    .line 939
    .line 940
    sget-object p0, Lv3/b2;->d:Lv3/b2;

    .line 941
    .line 942
    :goto_f
    return-object p0

    .line 943
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1c
        :pswitch_1b
        :pswitch_1a
        :pswitch_19
        :pswitch_18
        :pswitch_17
        :pswitch_16
        :pswitch_15
        :pswitch_14
        :pswitch_13
        :pswitch_12
        :pswitch_11
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
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
