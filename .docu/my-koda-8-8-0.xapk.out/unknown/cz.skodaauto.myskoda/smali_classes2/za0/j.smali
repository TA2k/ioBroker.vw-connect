.class public final synthetic Lza0/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, Lza0/j;->d:I

    iput-object p1, p0, Lza0/j;->e:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;II)V
    .locals 0

    .line 2
    iput p3, p0, Lza0/j;->d:I

    iput-object p1, p0, Lza0/j;->e:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    .line 1
    iget v0, p0, Lza0/j;->d:I

    .line 2
    .line 3
    iget-object p0, p0, Lza0/j;->e:Ljava/lang/Object;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    check-cast p0, Lzy0/r;

    .line 9
    .line 10
    check-cast p1, Ljava/lang/Integer;

    .line 11
    .line 12
    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    check-cast p2, Lpx0/e;

    .line 17
    .line 18
    invoke-interface {p2}, Lpx0/e;->getKey()Lpx0/f;

    .line 19
    .line 20
    .line 21
    move-result-object p1

    .line 22
    iget-object p0, p0, Lzy0/r;->e:Lpx0/g;

    .line 23
    .line 24
    invoke-interface {p0, p1}, Lpx0/g;->get(Lpx0/f;)Lpx0/e;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    sget-object v1, Lvy0/h1;->d:Lvy0/h1;

    .line 29
    .line 30
    if-eq p1, v1, :cond_1

    .line 31
    .line 32
    if-eq p2, p0, :cond_0

    .line 33
    .line 34
    const/high16 v0, -0x80000000

    .line 35
    .line 36
    goto :goto_2

    .line 37
    :cond_0
    add-int/lit8 v0, v0, 0x1

    .line 38
    .line 39
    goto :goto_2

    .line 40
    :cond_1
    move-object v1, p0

    .line 41
    check-cast v1, Lvy0/i1;

    .line 42
    .line 43
    check-cast p2, Lvy0/i1;

    .line 44
    .line 45
    :goto_0
    const/4 p0, 0x0

    .line 46
    if-nez p2, :cond_2

    .line 47
    .line 48
    move-object p2, p0

    .line 49
    goto :goto_1

    .line 50
    :cond_2
    if-ne p2, v1, :cond_3

    .line 51
    .line 52
    goto :goto_1

    .line 53
    :cond_3
    instance-of p1, p2, Laz0/p;

    .line 54
    .line 55
    if-nez p1, :cond_5

    .line 56
    .line 57
    :goto_1
    if-ne p2, v1, :cond_4

    .line 58
    .line 59
    if-nez v1, :cond_0

    .line 60
    .line 61
    :goto_2
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 62
    .line 63
    .line 64
    move-result-object p0

    .line 65
    return-object p0

    .line 66
    :cond_4
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 67
    .line 68
    new-instance p1, Ljava/lang/StringBuilder;

    .line 69
    .line 70
    const-string v0, "Flow invariant is violated:\n\t\tEmission from another coroutine is detected.\n\t\tChild of "

    .line 71
    .line 72
    invoke-direct {p1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 73
    .line 74
    .line 75
    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 76
    .line 77
    .line 78
    const-string p2, ", expected child of "

    .line 79
    .line 80
    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 81
    .line 82
    .line 83
    invoke-virtual {p1, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 84
    .line 85
    .line 86
    const-string p2, ".\n\t\tFlowCollector is not thread-safe and concurrent emissions are prohibited.\n\t\tTo mitigate this restriction please use \'channelFlow\' builder instead of \'flow\'"

    .line 87
    .line 88
    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 89
    .line 90
    .line 91
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 92
    .line 93
    .line 94
    move-result-object p1

    .line 95
    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 96
    .line 97
    .line 98
    move-result-object p1

    .line 99
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 100
    .line 101
    .line 102
    throw p0

    .line 103
    :cond_5
    check-cast p2, Laz0/p;

    .line 104
    .line 105
    sget-object p1, Lvy0/p1;->e:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 106
    .line 107
    invoke-virtual {p1, p2}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 108
    .line 109
    .line 110
    move-result-object p1

    .line 111
    check-cast p1, Lvy0/o;

    .line 112
    .line 113
    if-eqz p1, :cond_6

    .line 114
    .line 115
    invoke-interface {p1}, Lvy0/o;->getParent()Lvy0/i1;

    .line 116
    .line 117
    .line 118
    move-result-object p0

    .line 119
    :cond_6
    move-object p2, p0

    .line 120
    goto :goto_0

    .line 121
    :pswitch_0
    check-cast p0, Lkh/i;

    .line 122
    .line 123
    check-cast p1, Ll2/o;

    .line 124
    .line 125
    check-cast p2, Ljava/lang/Integer;

    .line 126
    .line 127
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 128
    .line 129
    .line 130
    const/16 p2, 0x9

    .line 131
    .line 132
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 133
    .line 134
    .line 135
    move-result p2

    .line 136
    invoke-static {p0, p1, p2}, Ljp/i1;->g(Lkh/i;Ll2/o;I)V

    .line 137
    .line 138
    .line 139
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 140
    .line 141
    return-object p0

    .line 142
    :pswitch_1
    check-cast p0, Lxj0/o;

    .line 143
    .line 144
    check-cast p1, Ll2/o;

    .line 145
    .line 146
    check-cast p2, Ljava/lang/Integer;

    .line 147
    .line 148
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 149
    .line 150
    .line 151
    check-cast p1, Ll2/t;

    .line 152
    .line 153
    const p2, -0x5216e140

    .line 154
    .line 155
    .line 156
    invoke-virtual {p1, p2}, Ll2/t;->Y(I)V

    .line 157
    .line 158
    .line 159
    iget-char p2, p0, Lxj0/o;->e:C

    .line 160
    .line 161
    iget-boolean p0, p0, Lxj0/o;->f:Z

    .line 162
    .line 163
    if-eqz p0, :cond_7

    .line 164
    .line 165
    sget-object p0, Li91/l2;->d:Li91/l2;

    .line 166
    .line 167
    goto :goto_3

    .line 168
    :cond_7
    sget-object p0, Li91/l2;->e:Li91/l2;

    .line 169
    .line 170
    :goto_3
    sget-object v0, Lw3/h1;->h:Ll2/u2;

    .line 171
    .line 172
    invoke-virtual {p1, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 173
    .line 174
    .line 175
    move-result-object v1

    .line 176
    check-cast v1, Lt4/c;

    .line 177
    .line 178
    const/16 v2, 0x18

    .line 179
    .line 180
    int-to-float v2, v2

    .line 181
    invoke-interface {v1, v2}, Lt4/c;->Q(F)I

    .line 182
    .line 183
    .line 184
    move-result v1

    .line 185
    sget-object v2, Landroid/graphics/Bitmap$Config;->ARGB_8888:Landroid/graphics/Bitmap$Config;

    .line 186
    .line 187
    invoke-static {v1, v1, v2}, Landroid/graphics/Bitmap;->createBitmap(IILandroid/graphics/Bitmap$Config;)Landroid/graphics/Bitmap;

    .line 188
    .line 189
    .line 190
    move-result-object v2

    .line 191
    const-string v3, "createBitmap(...)"

    .line 192
    .line 193
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 194
    .line 195
    .line 196
    new-instance v3, Landroid/graphics/Canvas;

    .line 197
    .line 198
    invoke-direct {v3, v2}, Landroid/graphics/Canvas;-><init>(Landroid/graphics/Bitmap;)V

    .line 199
    .line 200
    .line 201
    invoke-static {p0, p1}, Li91/j0;->N0(Li91/l2;Ll2/t;)J

    .line 202
    .line 203
    .line 204
    move-result-wide v4

    .line 205
    new-instance p0, Landroid/graphics/Paint;

    .line 206
    .line 207
    invoke-direct {p0}, Landroid/graphics/Paint;-><init>()V

    .line 208
    .line 209
    .line 210
    sget-object v6, Landroid/graphics/Paint$Style;->FILL:Landroid/graphics/Paint$Style;

    .line 211
    .line 212
    invoke-virtual {p0, v6}, Landroid/graphics/Paint;->setStyle(Landroid/graphics/Paint$Style;)V

    .line 213
    .line 214
    .line 215
    invoke-static {v4, v5}, Le3/j0;->z(J)I

    .line 216
    .line 217
    .line 218
    move-result v4

    .line 219
    invoke-virtual {p0, v4}, Landroid/graphics/Paint;->setColor(I)V

    .line 220
    .line 221
    .line 222
    const/4 v4, 0x1

    .line 223
    invoke-virtual {p0, v4}, Landroid/graphics/Paint;->setAntiAlias(Z)V

    .line 224
    .line 225
    .line 226
    int-to-float v5, v1

    .line 227
    const/high16 v6, 0x40000000    # 2.0f

    .line 228
    .line 229
    div-float/2addr v5, v6

    .line 230
    invoke-virtual {v3, v5, v5, v5, p0}, Landroid/graphics/Canvas;->drawCircle(FFFLandroid/graphics/Paint;)V

    .line 231
    .line 232
    .line 233
    invoke-static {p2}, Ljava/lang/String;->valueOf(C)Ljava/lang/String;

    .line 234
    .line 235
    .line 236
    move-result-object p0

    .line 237
    new-instance p2, Landroid/text/TextPaint;

    .line 238
    .line 239
    invoke-direct {p2}, Landroid/text/TextPaint;-><init>()V

    .line 240
    .line 241
    .line 242
    sget-object v5, Lj91/h;->a:Ll2/u2;

    .line 243
    .line 244
    invoke-virtual {p1, v5}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 245
    .line 246
    .line 247
    move-result-object v5

    .line 248
    check-cast v5, Lj91/e;

    .line 249
    .line 250
    invoke-virtual {v5}, Lj91/e;->b()J

    .line 251
    .line 252
    .line 253
    move-result-wide v7

    .line 254
    invoke-static {v7, v8}, Le3/j0;->z(J)I

    .line 255
    .line 256
    .line 257
    move-result v5

    .line 258
    invoke-virtual {p2, v5}, Landroid/graphics/Paint;->setColor(I)V

    .line 259
    .line 260
    .line 261
    invoke-virtual {p1, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 262
    .line 263
    .line 264
    move-result-object v0

    .line 265
    check-cast v0, Lt4/c;

    .line 266
    .line 267
    const/16 v5, 0xe

    .line 268
    .line 269
    invoke-static {v5}, Lgq/b;->c(I)J

    .line 270
    .line 271
    .line 272
    move-result-wide v7

    .line 273
    invoke-interface {v0, v7, v8}, Lt4/c;->V(J)F

    .line 274
    .line 275
    .line 276
    move-result v0

    .line 277
    invoke-virtual {p2, v0}, Landroid/graphics/Paint;->setTextSize(F)V

    .line 278
    .line 279
    .line 280
    sget-object v0, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->b:Ll2/u2;

    .line 281
    .line 282
    invoke-virtual {p1, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 283
    .line 284
    .line 285
    move-result-object v0

    .line 286
    check-cast v0, Landroid/content/Context;

    .line 287
    .line 288
    const v5, 0x7f090007

    .line 289
    .line 290
    .line 291
    invoke-static {v0, v5}, Lp5/j;->a(Landroid/content/Context;I)Landroid/graphics/Typeface;

    .line 292
    .line 293
    .line 294
    move-result-object v0

    .line 295
    invoke-virtual {p2, v0}, Landroid/graphics/Paint;->setTypeface(Landroid/graphics/Typeface;)Landroid/graphics/Typeface;

    .line 296
    .line 297
    .line 298
    invoke-virtual {p2, v4}, Landroid/graphics/Paint;->setAntiAlias(Z)V

    .line 299
    .line 300
    .line 301
    invoke-virtual {p2, p0}, Landroid/graphics/Paint;->measureText(Ljava/lang/String;)F

    .line 302
    .line 303
    .line 304
    move-result v0

    .line 305
    invoke-static {v0}, Lcy0/a;->i(F)I

    .line 306
    .line 307
    .line 308
    move-result v0

    .line 309
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 310
    .line 311
    .line 312
    move-result v4

    .line 313
    const/4 v5, 0x0

    .line 314
    invoke-static {p0, v5, v4, p2, v0}, Landroid/text/StaticLayout$Builder;->obtain(Ljava/lang/CharSequence;IILandroid/text/TextPaint;I)Landroid/text/StaticLayout$Builder;

    .line 315
    .line 316
    .line 317
    move-result-object p0

    .line 318
    invoke-virtual {p0}, Landroid/text/StaticLayout$Builder;->build()Landroid/text/StaticLayout;

    .line 319
    .line 320
    .line 321
    move-result-object p0

    .line 322
    const-string p2, "build(...)"

    .line 323
    .line 324
    invoke-static {p0, p2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 325
    .line 326
    .line 327
    invoke-virtual {p0}, Landroid/text/Layout;->getHeight()I

    .line 328
    .line 329
    .line 330
    move-result p2

    .line 331
    sub-int v0, v1, v0

    .line 332
    .line 333
    int-to-float v0, v0

    .line 334
    div-float/2addr v0, v6

    .line 335
    sub-int/2addr v1, p2

    .line 336
    int-to-float p2, v1

    .line 337
    div-float/2addr p2, v6

    .line 338
    invoke-virtual {v3, v0, p2}, Landroid/graphics/Canvas;->translate(FF)V

    .line 339
    .line 340
    .line 341
    invoke-virtual {p0, v3}, Landroid/text/Layout;->draw(Landroid/graphics/Canvas;)V

    .line 342
    .line 343
    .line 344
    invoke-virtual {p1, v5}, Ll2/t;->q(Z)V

    .line 345
    .line 346
    .line 347
    return-object v2

    .line 348
    :pswitch_2
    check-cast p0, Lxj0/n;

    .line 349
    .line 350
    check-cast p1, Ll2/o;

    .line 351
    .line 352
    check-cast p2, Ljava/lang/Integer;

    .line 353
    .line 354
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 355
    .line 356
    .line 357
    check-cast p1, Ll2/t;

    .line 358
    .line 359
    const p2, 0x6a82af7f

    .line 360
    .line 361
    .line 362
    invoke-virtual {p1, p2}, Ll2/t;->Y(I)V

    .line 363
    .line 364
    .line 365
    iget p2, p0, Lxj0/n;->e:I

    .line 366
    .line 367
    iget-boolean p0, p0, Lxj0/n;->f:Z

    .line 368
    .line 369
    if-eqz p0, :cond_8

    .line 370
    .line 371
    sget-object p0, Li91/l2;->d:Li91/l2;

    .line 372
    .line 373
    goto :goto_4

    .line 374
    :cond_8
    sget-object p0, Li91/l2;->e:Li91/l2;

    .line 375
    .line 376
    :goto_4
    const/16 v0, 0x18

    .line 377
    .line 378
    int-to-float v0, v0

    .line 379
    invoke-static {p0, p1}, Li91/j0;->N0(Li91/l2;Ll2/t;)J

    .line 380
    .line 381
    .line 382
    move-result-wide v1

    .line 383
    const/16 p0, 0x14

    .line 384
    .line 385
    int-to-float p0, p0

    .line 386
    sget-object v3, Lj91/h;->a:Ll2/u2;

    .line 387
    .line 388
    invoke-virtual {p1, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 389
    .line 390
    .line 391
    move-result-object v3

    .line 392
    check-cast v3, Lj91/e;

    .line 393
    .line 394
    invoke-virtual {v3}, Lj91/e;->b()J

    .line 395
    .line 396
    .line 397
    move-result-wide v3

    .line 398
    sget-object v5, Lw3/h1;->h:Ll2/u2;

    .line 399
    .line 400
    invoke-virtual {p1, v5}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 401
    .line 402
    .line 403
    move-result-object v6

    .line 404
    check-cast v6, Lt4/c;

    .line 405
    .line 406
    invoke-interface {v6, v0}, Lt4/c;->Q(F)I

    .line 407
    .line 408
    .line 409
    move-result v0

    .line 410
    sget-object v6, Landroid/graphics/Bitmap$Config;->ARGB_8888:Landroid/graphics/Bitmap$Config;

    .line 411
    .line 412
    invoke-static {v0, v0, v6}, Landroid/graphics/Bitmap;->createBitmap(IILandroid/graphics/Bitmap$Config;)Landroid/graphics/Bitmap;

    .line 413
    .line 414
    .line 415
    move-result-object v6

    .line 416
    const-string v7, "createBitmap(...)"

    .line 417
    .line 418
    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 419
    .line 420
    .line 421
    new-instance v7, Landroid/graphics/Canvas;

    .line 422
    .line 423
    invoke-direct {v7, v6}, Landroid/graphics/Canvas;-><init>(Landroid/graphics/Bitmap;)V

    .line 424
    .line 425
    .line 426
    new-instance v8, Landroid/graphics/Paint;

    .line 427
    .line 428
    invoke-direct {v8}, Landroid/graphics/Paint;-><init>()V

    .line 429
    .line 430
    .line 431
    sget-object v9, Landroid/graphics/Paint$Style;->FILL:Landroid/graphics/Paint$Style;

    .line 432
    .line 433
    invoke-virtual {v8, v9}, Landroid/graphics/Paint;->setStyle(Landroid/graphics/Paint$Style;)V

    .line 434
    .line 435
    .line 436
    invoke-static {v1, v2}, Le3/j0;->z(J)I

    .line 437
    .line 438
    .line 439
    move-result v1

    .line 440
    invoke-virtual {v8, v1}, Landroid/graphics/Paint;->setColor(I)V

    .line 441
    .line 442
    .line 443
    const/4 v1, 0x1

    .line 444
    invoke-virtual {v8, v1}, Landroid/graphics/Paint;->setAntiAlias(Z)V

    .line 445
    .line 446
    .line 447
    int-to-float v1, v0

    .line 448
    const/high16 v2, 0x40000000    # 2.0f

    .line 449
    .line 450
    div-float/2addr v1, v2

    .line 451
    invoke-virtual {v7, v1, v1, v1, v8}, Landroid/graphics/Canvas;->drawCircle(FFFLandroid/graphics/Paint;)V

    .line 452
    .line 453
    .line 454
    invoke-virtual {p1, v5}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 455
    .line 456
    .line 457
    move-result-object v1

    .line 458
    check-cast v1, Lt4/c;

    .line 459
    .line 460
    invoke-interface {v1, p0}, Lt4/c;->Q(F)I

    .line 461
    .line 462
    .line 463
    move-result p0

    .line 464
    sget-object v1, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->b:Ll2/u2;

    .line 465
    .line 466
    invoke-virtual {p1, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 467
    .line 468
    .line 469
    move-result-object v1

    .line 470
    check-cast v1, Landroid/content/Context;

    .line 471
    .line 472
    invoke-virtual {v1}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 473
    .line 474
    .line 475
    move-result-object v1

    .line 476
    const-string v5, "getResources(...)"

    .line 477
    .line 478
    invoke-static {v1, v5}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 479
    .line 480
    .line 481
    new-instance v5, Le3/s;

    .line 482
    .line 483
    invoke-direct {v5, v3, v4}, Le3/s;-><init>(J)V

    .line 484
    .line 485
    .line 486
    invoke-static {v1, p2, v5, p0, p0}, Li91/j0;->G0(Landroid/content/res/Resources;ILe3/s;II)Lcb/p;

    .line 487
    .line 488
    .line 489
    move-result-object p2

    .line 490
    sub-int/2addr v0, p0

    .line 491
    int-to-float p0, v0

    .line 492
    div-float/2addr p0, v2

    .line 493
    invoke-virtual {v7, p0, p0}, Landroid/graphics/Canvas;->translate(FF)V

    .line 494
    .line 495
    .line 496
    invoke-virtual {p2, v7}, Lcb/p;->draw(Landroid/graphics/Canvas;)V

    .line 497
    .line 498
    .line 499
    const/4 p0, 0x0

    .line 500
    invoke-virtual {p1, p0}, Ll2/t;->q(Z)V

    .line 501
    .line 502
    .line 503
    return-object v6

    .line 504
    :pswitch_3
    check-cast p0, Lxj0/k;

    .line 505
    .line 506
    check-cast p1, Ll2/o;

    .line 507
    .line 508
    check-cast p2, Ljava/lang/Integer;

    .line 509
    .line 510
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 511
    .line 512
    .line 513
    check-cast p1, Ll2/t;

    .line 514
    .line 515
    const p2, 0x271c403e

    .line 516
    .line 517
    .line 518
    invoke-virtual {p1, p2}, Ll2/t;->Y(I)V

    .line 519
    .line 520
    .line 521
    invoke-static {p0, p1}, Lzj0/d;->m(Lxj0/k;Ll2/o;)Landroid/graphics/Bitmap;

    .line 522
    .line 523
    .line 524
    move-result-object p0

    .line 525
    const/4 p2, 0x0

    .line 526
    invoke-virtual {p1, p2}, Ll2/t;->q(Z)V

    .line 527
    .line 528
    .line 529
    return-object p0

    .line 530
    :pswitch_4
    check-cast p0, Lxj0/q;

    .line 531
    .line 532
    check-cast p1, Ll2/o;

    .line 533
    .line 534
    check-cast p2, Ljava/lang/Integer;

    .line 535
    .line 536
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 537
    .line 538
    .line 539
    move-object v5, p1

    .line 540
    check-cast v5, Ll2/t;

    .line 541
    .line 542
    const p1, -0x1c4a2f03

    .line 543
    .line 544
    .line 545
    invoke-virtual {v5, p1}, Ll2/t;->Y(I)V

    .line 546
    .line 547
    .line 548
    iget-boolean p0, p0, Lxj0/q;->e:Z

    .line 549
    .line 550
    const/4 p1, 0x0

    .line 551
    if-eqz p0, :cond_9

    .line 552
    .line 553
    const p0, -0x1cd45370

    .line 554
    .line 555
    .line 556
    invoke-virtual {v5, p0}, Ll2/t;->Y(I)V

    .line 557
    .line 558
    .line 559
    const p0, 0x7f080314

    .line 560
    .line 561
    .line 562
    invoke-static {v5, p0}, Li91/j0;->J0(Ll2/o;I)Landroid/graphics/Bitmap;

    .line 563
    .line 564
    .line 565
    move-result-object p0

    .line 566
    invoke-virtual {v5, p1}, Ll2/t;->q(Z)V

    .line 567
    .line 568
    .line 569
    goto :goto_5

    .line 570
    :cond_9
    const p0, -0x1cd2dd23

    .line 571
    .line 572
    .line 573
    invoke-virtual {v5, p0}, Ll2/t;->Y(I)V

    .line 574
    .line 575
    .line 576
    sget-object p0, Lj91/h;->a:Ll2/u2;

    .line 577
    .line 578
    invoke-virtual {v5, p0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 579
    .line 580
    .line 581
    move-result-object p2

    .line 582
    check-cast p2, Lj91/e;

    .line 583
    .line 584
    invoke-virtual {p2}, Lj91/e;->j()J

    .line 585
    .line 586
    .line 587
    move-result-wide v1

    .line 588
    invoke-virtual {v5, p0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 589
    .line 590
    .line 591
    move-result-object p0

    .line 592
    check-cast p0, Lj91/e;

    .line 593
    .line 594
    invoke-virtual {p0}, Lj91/e;->b()J

    .line 595
    .line 596
    .line 597
    move-result-wide v3

    .line 598
    const/4 v6, 0x0

    .line 599
    const v0, 0x7f080314

    .line 600
    .line 601
    .line 602
    invoke-static/range {v0 .. v6}, Li91/j0;->K0(IJJLl2/o;I)Landroid/graphics/Bitmap;

    .line 603
    .line 604
    .line 605
    move-result-object p0

    .line 606
    invoke-virtual {v5, p1}, Ll2/t;->q(Z)V

    .line 607
    .line 608
    .line 609
    :goto_5
    invoke-virtual {v5, p1}, Ll2/t;->q(Z)V

    .line 610
    .line 611
    .line 612
    return-object p0

    .line 613
    :pswitch_5
    check-cast p0, Lxj0/p;

    .line 614
    .line 615
    check-cast p1, Ll2/o;

    .line 616
    .line 617
    check-cast p2, Ljava/lang/Integer;

    .line 618
    .line 619
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 620
    .line 621
    .line 622
    check-cast p1, Ll2/t;

    .line 623
    .line 624
    const p2, -0x6e779fba

    .line 625
    .line 626
    .line 627
    invoke-virtual {p1, p2}, Ll2/t;->Y(I)V

    .line 628
    .line 629
    .line 630
    invoke-static {p0, p1}, Lzj0/d;->n(Lxj0/p;Ll2/o;)Landroid/graphics/Bitmap;

    .line 631
    .line 632
    .line 633
    move-result-object p0

    .line 634
    const/4 p2, 0x0

    .line 635
    invoke-virtual {p1, p2}, Ll2/t;->q(Z)V

    .line 636
    .line 637
    .line 638
    return-object p0

    .line 639
    :pswitch_6
    move-object v0, p0

    .line 640
    check-cast v0, Lxj0/f;

    .line 641
    .line 642
    check-cast p1, Ll2/o;

    .line 643
    .line 644
    check-cast p2, Ljava/lang/Integer;

    .line 645
    .line 646
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 647
    .line 648
    .line 649
    move-result p0

    .line 650
    and-int/lit8 p2, p0, 0x3

    .line 651
    .line 652
    const/4 v1, 0x2

    .line 653
    const/4 v2, 0x1

    .line 654
    if-eq p2, v1, :cond_a

    .line 655
    .line 656
    move p2, v2

    .line 657
    goto :goto_6

    .line 658
    :cond_a
    const/4 p2, 0x0

    .line 659
    :goto_6
    and-int/2addr p0, v2

    .line 660
    move-object v4, p1

    .line 661
    check-cast v4, Ll2/t;

    .line 662
    .line 663
    invoke-virtual {v4, p0, p2}, Ll2/t;->O(IZ)Z

    .line 664
    .line 665
    .line 666
    move-result p0

    .line 667
    if-eqz p0, :cond_b

    .line 668
    .line 669
    sget-object p0, Lj91/h;->a:Ll2/u2;

    .line 670
    .line 671
    invoke-virtual {v4, p0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 672
    .line 673
    .line 674
    move-result-object p0

    .line 675
    check-cast p0, Lj91/e;

    .line 676
    .line 677
    invoke-virtual {p0}, Lj91/e;->e()J

    .line 678
    .line 679
    .line 680
    move-result-wide v1

    .line 681
    const/4 v5, 0x0

    .line 682
    const/16 v6, 0xc

    .line 683
    .line 684
    const/4 v3, 0x0

    .line 685
    invoke-static/range {v0 .. v6}, Lzj0/b;->b(Lxj0/f;JZLl2/o;II)V

    .line 686
    .line 687
    .line 688
    goto :goto_7

    .line 689
    :cond_b
    invoke-virtual {v4}, Ll2/t;->R()V

    .line 690
    .line 691
    .line 692
    :goto_7
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 693
    .line 694
    return-object p0

    .line 695
    :pswitch_7
    check-cast p0, [Lay0/o;

    .line 696
    .line 697
    check-cast p1, Ll2/o;

    .line 698
    .line 699
    check-cast p2, Ljava/lang/Integer;

    .line 700
    .line 701
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 702
    .line 703
    .line 704
    const/4 p2, 0x1

    .line 705
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 706
    .line 707
    .line 708
    move-result p2

    .line 709
    invoke-static {p0, p1, p2}, Lzb/b;->m([Lay0/o;Ll2/o;I)V

    .line 710
    .line 711
    .line 712
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 713
    .line 714
    return-object p0

    .line 715
    :pswitch_8
    check-cast p0, Lzb/n;

    .line 716
    .line 717
    check-cast p1, Ll2/o;

    .line 718
    .line 719
    check-cast p2, Ljava/lang/Integer;

    .line 720
    .line 721
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 722
    .line 723
    .line 724
    const/4 p2, 0x1

    .line 725
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 726
    .line 727
    .line 728
    move-result p2

    .line 729
    invoke-virtual {p0, p1, p2}, Lzb/n;->a(Ll2/o;I)V

    .line 730
    .line 731
    .line 732
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 733
    .line 734
    return-object p0

    .line 735
    :pswitch_9
    check-cast p0, Lkn/c0;

    .line 736
    .line 737
    check-cast p1, Ll2/o;

    .line 738
    .line 739
    check-cast p2, Ljava/lang/Integer;

    .line 740
    .line 741
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 742
    .line 743
    .line 744
    const/4 p2, 0x1

    .line 745
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 746
    .line 747
    .line 748
    move-result p2

    .line 749
    invoke-static {p0, p1, p2}, Lzb/b;->i(Lkn/c0;Ll2/o;I)V

    .line 750
    .line 751
    .line 752
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 753
    .line 754
    return-object p0

    .line 755
    :pswitch_a
    move-object v0, p0

    .line 756
    check-cast v0, Ly6/s;

    .line 757
    .line 758
    check-cast p1, Ll2/o;

    .line 759
    .line 760
    check-cast p2, Ljava/lang/Integer;

    .line 761
    .line 762
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 763
    .line 764
    .line 765
    move-result p0

    .line 766
    and-int/lit8 p2, p0, 0x3

    .line 767
    .line 768
    const/4 v1, 0x2

    .line 769
    const/4 v2, 0x1

    .line 770
    if-eq p2, v1, :cond_c

    .line 771
    .line 772
    move p2, v2

    .line 773
    goto :goto_8

    .line 774
    :cond_c
    const/4 p2, 0x0

    .line 775
    :goto_8
    and-int/2addr p0, v2

    .line 776
    move-object v4, p1

    .line 777
    check-cast v4, Ll2/t;

    .line 778
    .line 779
    invoke-virtual {v4, p0, p2}, Ll2/t;->O(IZ)Z

    .line 780
    .line 781
    .line 782
    move-result p0

    .line 783
    if-eqz p0, :cond_d

    .line 784
    .line 785
    sget-object p0, Ly6/o;->a:Ly6/o;

    .line 786
    .line 787
    invoke-static {p0}, Lkp/p7;->b(Ly6/q;)Ly6/q;

    .line 788
    .line 789
    .line 790
    move-result-object v1

    .line 791
    const/16 v5, 0x30

    .line 792
    .line 793
    const/16 v6, 0x10

    .line 794
    .line 795
    const/4 v2, 0x0

    .line 796
    const/4 v3, 0x0

    .line 797
    invoke-static/range {v0 .. v6}, Llp/ag;->a(Ly6/s;Ly6/q;ILy6/g;Ll2/o;II)V

    .line 798
    .line 799
    .line 800
    new-instance v1, Ly6/a;

    .line 801
    .line 802
    const p0, 0x7f0801a6

    .line 803
    .line 804
    .line 805
    invoke-direct {v1, p0}, Ly6/a;-><init>(I)V

    .line 806
    .line 807
    .line 808
    const/16 v6, 0x30

    .line 809
    .line 810
    const/16 v7, 0x1c

    .line 811
    .line 812
    const/4 v2, 0x0

    .line 813
    const/4 v3, 0x0

    .line 814
    move-object v5, v4

    .line 815
    const/4 v4, 0x0

    .line 816
    invoke-static/range {v1 .. v7}, Llp/ag;->a(Ly6/s;Ly6/q;ILy6/g;Ll2/o;II)V

    .line 817
    .line 818
    .line 819
    goto :goto_9

    .line 820
    :cond_d
    invoke-virtual {v4}, Ll2/t;->R()V

    .line 821
    .line 822
    .line 823
    :goto_9
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 824
    .line 825
    return-object p0

    .line 826
    nop

    .line 827
    :pswitch_data_0
    .packed-switch 0x0
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
