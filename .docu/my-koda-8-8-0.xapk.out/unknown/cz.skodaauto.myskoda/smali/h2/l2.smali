.class public final synthetic Lh2/l2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:I

.field public final synthetic f:Ljava/lang/Object;

.field public final synthetic g:Ljava/lang/Object;

.field public final synthetic h:Ljava/lang/Object;

.field public final synthetic i:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Lc1/f1;Lc1/f1;Lc1/f1;ILc1/f1;)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    iput v0, p0, Lh2/l2;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lh2/l2;->f:Ljava/lang/Object;

    iput-object p2, p0, Lh2/l2;->g:Ljava/lang/Object;

    iput-object p3, p0, Lh2/l2;->h:Ljava/lang/Object;

    iput p4, p0, Lh2/l2;->e:I

    iput-object p5, p0, Lh2/l2;->i:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;ILjava/lang/Object;Ll2/b1;Ll2/b1;I)V
    .locals 0

    .line 2
    iput p6, p0, Lh2/l2;->d:I

    iput-object p1, p0, Lh2/l2;->f:Ljava/lang/Object;

    iput p2, p0, Lh2/l2;->e:I

    iput-object p3, p0, Lh2/l2;->g:Ljava/lang/Object;

    iput-object p4, p0, Lh2/l2;->h:Ljava/lang/Object;

    iput-object p5, p0, Lh2/l2;->i:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 14

    .line 1
    iget v0, p0, Lh2/l2;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lh2/l2;->f:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Ll4/v;

    .line 9
    .line 10
    iget-object v1, p0, Lh2/l2;->g:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast v1, Lay0/k;

    .line 13
    .line 14
    iget-object v2, p0, Lh2/l2;->h:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast v2, Ll2/b1;

    .line 17
    .line 18
    iget-object v3, p0, Lh2/l2;->i:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast v3, Ll2/b1;

    .line 21
    .line 22
    check-cast p1, Ll4/v;

    .line 23
    .line 24
    const-string v4, "newValue"

    .line 25
    .line 26
    invoke-static {p1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    iget-wide v4, p1, Ll4/v;->b:J

    .line 30
    .line 31
    iget-object v6, p1, Ll4/v;->c:Lg4/o0;

    .line 32
    .line 33
    invoke-interface {v2, v6}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 34
    .line 35
    .line 36
    iget-object p1, p1, Ll4/v;->a:Lg4/g;

    .line 37
    .line 38
    iget-object p1, p1, Lg4/g;->e:Ljava/lang/String;

    .line 39
    .line 40
    iget-object v2, v0, Ll4/v;->a:Lg4/g;

    .line 41
    .line 42
    iget-object v2, v2, Lg4/g;->e:Ljava/lang/String;

    .line 43
    .line 44
    invoke-static {p1, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 45
    .line 46
    .line 47
    move-result v6

    .line 48
    if-eqz v6, :cond_0

    .line 49
    .line 50
    new-instance p0, Lg4/o0;

    .line 51
    .line 52
    invoke-direct {p0, v4, v5}, Lg4/o0;-><init>(J)V

    .line 53
    .line 54
    .line 55
    invoke-interface {v3, p0}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 56
    .line 57
    .line 58
    goto/16 :goto_4

    .line 59
    .line 60
    :cond_0
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 61
    .line 62
    .line 63
    move-result v6

    .line 64
    invoke-virtual {v2}, Ljava/lang/String;->length()I

    .line 65
    .line 66
    .line 67
    move-result v7

    .line 68
    if-le v6, v7, :cond_8

    .line 69
    .line 70
    iget-wide v4, v0, Ll4/v;->b:J

    .line 71
    .line 72
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 73
    .line 74
    .line 75
    move-result v0

    .line 76
    invoke-virtual {v2}, Ljava/lang/String;->length()I

    .line 77
    .line 78
    .line 79
    move-result v6

    .line 80
    invoke-static {v0, v6}, Ljava/lang/Math;->min(II)I

    .line 81
    .line 82
    .line 83
    move-result v0

    .line 84
    const/4 v6, 0x0

    .line 85
    move v7, v6

    .line 86
    :goto_0
    if-ge v7, v0, :cond_1

    .line 87
    .line 88
    invoke-virtual {p1, v7}, Ljava/lang/String;->charAt(I)C

    .line 89
    .line 90
    .line 91
    move-result v8

    .line 92
    invoke-virtual {v2, v7}, Ljava/lang/String;->charAt(I)C

    .line 93
    .line 94
    .line 95
    move-result v9

    .line 96
    invoke-static {v8, v9, v6}, Lry/a;->c(CCZ)Z

    .line 97
    .line 98
    .line 99
    move-result v8

    .line 100
    if-eqz v8, :cond_1

    .line 101
    .line 102
    add-int/lit8 v7, v7, 0x1

    .line 103
    .line 104
    goto :goto_0

    .line 105
    :cond_1
    add-int/lit8 v0, v7, -0x1

    .line 106
    .line 107
    invoke-static {v0, p1}, Lly0/p;->G(ILjava/lang/CharSequence;)Z

    .line 108
    .line 109
    .line 110
    move-result v8

    .line 111
    if-nez v8, :cond_2

    .line 112
    .line 113
    invoke-static {v0, v2}, Lly0/p;->G(ILjava/lang/CharSequence;)Z

    .line 114
    .line 115
    .line 116
    move-result v0

    .line 117
    if-eqz v0, :cond_3

    .line 118
    .line 119
    :cond_2
    add-int/lit8 v7, v7, -0x1

    .line 120
    .line 121
    :cond_3
    invoke-virtual {p1, v6, v7}, Ljava/lang/String;->subSequence(II)Ljava/lang/CharSequence;

    .line 122
    .line 123
    .line 124
    move-result-object v0

    .line 125
    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 126
    .line 127
    .line 128
    move-result-object v0

    .line 129
    invoke-static {v2, v0}, Lly0/p;->S(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 130
    .line 131
    .line 132
    move-result-object v7

    .line 133
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 134
    .line 135
    .line 136
    move-result v8

    .line 137
    invoke-virtual {v7}, Ljava/lang/String;->length()I

    .line 138
    .line 139
    .line 140
    move-result v9

    .line 141
    invoke-static {v8, v9}, Ljava/lang/Math;->min(II)I

    .line 142
    .line 143
    .line 144
    move-result v10

    .line 145
    move v11, v6

    .line 146
    :goto_1
    if-ge v11, v10, :cond_4

    .line 147
    .line 148
    sub-int v12, v8, v11

    .line 149
    .line 150
    add-int/lit8 v12, v12, -0x1

    .line 151
    .line 152
    invoke-virtual {p1, v12}, Ljava/lang/String;->charAt(I)C

    .line 153
    .line 154
    .line 155
    move-result v12

    .line 156
    sub-int v13, v9, v11

    .line 157
    .line 158
    add-int/lit8 v13, v13, -0x1

    .line 159
    .line 160
    invoke-virtual {v7, v13}, Ljava/lang/String;->charAt(I)C

    .line 161
    .line 162
    .line 163
    move-result v13

    .line 164
    invoke-static {v12, v13, v6}, Lry/a;->c(CCZ)Z

    .line 165
    .line 166
    .line 167
    move-result v12

    .line 168
    if-eqz v12, :cond_4

    .line 169
    .line 170
    add-int/lit8 v11, v11, 0x1

    .line 171
    .line 172
    goto :goto_1

    .line 173
    :cond_4
    sub-int v10, v8, v11

    .line 174
    .line 175
    add-int/lit8 v10, v10, -0x1

    .line 176
    .line 177
    invoke-static {v10, p1}, Lly0/p;->G(ILjava/lang/CharSequence;)Z

    .line 178
    .line 179
    .line 180
    move-result v10

    .line 181
    if-nez v10, :cond_5

    .line 182
    .line 183
    sub-int/2addr v9, v11

    .line 184
    add-int/lit8 v9, v9, -0x1

    .line 185
    .line 186
    invoke-static {v9, v7}, Lly0/p;->G(ILjava/lang/CharSequence;)Z

    .line 187
    .line 188
    .line 189
    move-result v7

    .line 190
    if-eqz v7, :cond_6

    .line 191
    .line 192
    :cond_5
    add-int/lit8 v11, v11, -0x1

    .line 193
    .line 194
    :cond_6
    sub-int v7, v8, v11

    .line 195
    .line 196
    invoke-virtual {p1, v7, v8}, Ljava/lang/String;->subSequence(II)Ljava/lang/CharSequence;

    .line 197
    .line 198
    .line 199
    move-result-object v7

    .line 200
    invoke-virtual {v7}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 201
    .line 202
    .line 203
    move-result-object v7

    .line 204
    invoke-static {v2, v0}, Lly0/p;->S(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 205
    .line 206
    .line 207
    move-result-object v8

    .line 208
    invoke-static {v8, v7}, Lly0/p;->T(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 209
    .line 210
    .line 211
    move-result-object v8

    .line 212
    invoke-static {p1, v0}, Lly0/p;->S(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 213
    .line 214
    .line 215
    move-result-object p1

    .line 216
    invoke-static {p1, v7}, Lly0/p;->T(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 217
    .line 218
    .line 219
    move-result-object p1

    .line 220
    invoke-virtual {v2}, Ljava/lang/String;->length()I

    .line 221
    .line 222
    .line 223
    move-result v2

    .line 224
    iget p0, p0, Lh2/l2;->e:I

    .line 225
    .line 226
    sub-int/2addr p0, v2

    .line 227
    invoke-virtual {v8}, Ljava/lang/String;->length()I

    .line 228
    .line 229
    .line 230
    move-result v2

    .line 231
    add-int/2addr v2, p0

    .line 232
    if-gez v2, :cond_7

    .line 233
    .line 234
    goto :goto_2

    .line 235
    :cond_7
    move v6, v2

    .line 236
    :goto_2
    invoke-static {v0}, Lf2/m0;->n(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 237
    .line 238
    .line 239
    move-result-object p0

    .line 240
    invoke-static {v6, p1}, Lly0/p;->j0(ILjava/lang/String;)Ljava/lang/String;

    .line 241
    .line 242
    .line 243
    move-result-object v0

    .line 244
    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 245
    .line 246
    .line 247
    invoke-virtual {p0, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 248
    .line 249
    .line 250
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 251
    .line 252
    .line 253
    move-result-object p0

    .line 254
    invoke-interface {v1, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 255
    .line 256
    .line 257
    invoke-static {v4, v5}, Lg4/o0;->f(J)I

    .line 258
    .line 259
    .line 260
    move-result p0

    .line 261
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 262
    .line 263
    .line 264
    move-result p1

    .line 265
    invoke-virtual {v8}, Ljava/lang/String;->length()I

    .line 266
    .line 267
    .line 268
    move-result v0

    .line 269
    sub-int/2addr p1, v0

    .line 270
    invoke-static {p1, v6}, Ljava/lang/Math;->min(II)I

    .line 271
    .line 272
    .line 273
    move-result p1

    .line 274
    add-int/2addr p1, p0

    .line 275
    invoke-static {p1, p1}, Lg4/f0;->b(II)J

    .line 276
    .line 277
    .line 278
    move-result-wide v4

    .line 279
    goto :goto_3

    .line 280
    :cond_8
    invoke-interface {v1, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 281
    .line 282
    .line 283
    :goto_3
    new-instance p0, Lg4/o0;

    .line 284
    .line 285
    invoke-direct {p0, v4, v5}, Lg4/o0;-><init>(J)V

    .line 286
    .line 287
    .line 288
    invoke-interface {v3, p0}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 289
    .line 290
    .line 291
    :goto_4
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 292
    .line 293
    return-object p0

    .line 294
    :pswitch_0
    iget-object v0, p0, Lh2/l2;->f:Ljava/lang/Object;

    .line 295
    .line 296
    check-cast v0, Lh2/fc;

    .line 297
    .line 298
    iget-object v1, p0, Lh2/l2;->g:Ljava/lang/Object;

    .line 299
    .line 300
    check-cast v1, Ll2/b1;

    .line 301
    .line 302
    iget-object v2, p0, Lh2/l2;->h:Ljava/lang/Object;

    .line 303
    .line 304
    check-cast v2, Ll2/g1;

    .line 305
    .line 306
    iget-object v3, p0, Lh2/l2;->i:Ljava/lang/Object;

    .line 307
    .line 308
    check-cast v3, Ll2/g1;

    .line 309
    .line 310
    check-cast p1, Lt3/y;

    .line 311
    .line 312
    invoke-interface {v1, p1}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 313
    .line 314
    .line 315
    invoke-interface {p1}, Lt3/y;->h()J

    .line 316
    .line 317
    .line 318
    move-result-wide v4

    .line 319
    const/16 p1, 0x20

    .line 320
    .line 321
    shr-long/2addr v4, p1

    .line 322
    long-to-int p1, v4

    .line 323
    invoke-virtual {v2, p1}, Ll2/g1;->p(I)V

    .line 324
    .line 325
    .line 326
    iget-object p1, v0, Lh2/fc;->a:Landroid/view/View;

    .line 327
    .line 328
    new-instance v0, Landroid/graphics/Rect;

    .line 329
    .line 330
    invoke-direct {v0}, Landroid/graphics/Rect;-><init>()V

    .line 331
    .line 332
    .line 333
    invoke-virtual {p1, v0}, Landroid/view/View;->getWindowVisibleDisplayFrame(Landroid/graphics/Rect;)V

    .line 334
    .line 335
    .line 336
    iget p1, v0, Landroid/graphics/Rect;->top:I

    .line 337
    .line 338
    iget v0, v0, Landroid/graphics/Rect;->bottom:I

    .line 339
    .line 340
    invoke-interface {v1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 341
    .line 342
    .line 343
    move-result-object v1

    .line 344
    check-cast v1, Lt3/y;

    .line 345
    .line 346
    if-eqz v1, :cond_a

    .line 347
    .line 348
    invoke-interface {v1}, Lt3/y;->g()Z

    .line 349
    .line 350
    .line 351
    move-result v2

    .line 352
    if-nez v2, :cond_9

    .line 353
    .line 354
    goto :goto_5

    .line 355
    :cond_9
    const-wide/16 v4, 0x0

    .line 356
    .line 357
    invoke-interface {v1, v4, v5}, Lt3/y;->B(J)J

    .line 358
    .line 359
    .line 360
    move-result-wide v4

    .line 361
    invoke-interface {v1}, Lt3/y;->h()J

    .line 362
    .line 363
    .line 364
    move-result-wide v1

    .line 365
    invoke-static {v1, v2}, Lkp/f9;->c(J)J

    .line 366
    .line 367
    .line 368
    move-result-wide v1

    .line 369
    invoke-static {v4, v5, v1, v2}, Ljp/cf;->c(JJ)Ld3/c;

    .line 370
    .line 371
    .line 372
    move-result-object v1

    .line 373
    goto :goto_6

    .line 374
    :cond_a
    :goto_5
    sget-object v1, Ld3/c;->e:Ld3/c;

    .line 375
    .line 376
    :goto_6
    iget p0, p0, Lh2/l2;->e:I

    .line 377
    .line 378
    add-int v2, p1, p0

    .line 379
    .line 380
    sub-int p0, v0, p0

    .line 381
    .line 382
    iget v4, v1, Ld3/c;->b:F

    .line 383
    .line 384
    int-to-float v0, v0

    .line 385
    cmpl-float v0, v4, v0

    .line 386
    .line 387
    if-gtz v0, :cond_c

    .line 388
    .line 389
    iget v0, v1, Ld3/c;->d:F

    .line 390
    .line 391
    int-to-float p1, p1

    .line 392
    cmpg-float p1, v0, p1

    .line 393
    .line 394
    if-gez p1, :cond_b

    .line 395
    .line 396
    goto :goto_7

    .line 397
    :cond_b
    int-to-float p1, v2

    .line 398
    sub-float/2addr v4, p1

    .line 399
    int-to-float p0, p0

    .line 400
    sub-float/2addr p0, v0

    .line 401
    invoke-static {v4, p0}, Ljava/lang/Math;->max(FF)F

    .line 402
    .line 403
    .line 404
    move-result p0

    .line 405
    invoke-static {p0}, Lcy0/a;->i(F)I

    .line 406
    .line 407
    .line 408
    move-result p0

    .line 409
    goto :goto_8

    .line 410
    :cond_c
    :goto_7
    sub-int/2addr p0, v2

    .line 411
    :goto_8
    const/4 p1, 0x0

    .line 412
    invoke-static {p0, p1}, Ljava/lang/Math;->max(II)I

    .line 413
    .line 414
    .line 415
    move-result p0

    .line 416
    invoke-virtual {v3, p0}, Ll2/g1;->p(I)V

    .line 417
    .line 418
    .line 419
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 420
    .line 421
    return-object p0

    .line 422
    :pswitch_1
    iget-object v0, p0, Lh2/l2;->f:Ljava/lang/Object;

    .line 423
    .line 424
    check-cast v0, Lc1/f1;

    .line 425
    .line 426
    iget-object v1, p0, Lh2/l2;->g:Ljava/lang/Object;

    .line 427
    .line 428
    check-cast v1, Lc1/f1;

    .line 429
    .line 430
    iget-object v2, p0, Lh2/l2;->h:Ljava/lang/Object;

    .line 431
    .line 432
    check-cast v2, Lc1/f1;

    .line 433
    .line 434
    iget-object v3, p0, Lh2/l2;->i:Ljava/lang/Object;

    .line 435
    .line 436
    check-cast v3, Lc1/f1;

    .line 437
    .line 438
    check-cast p1, Lb1/t;

    .line 439
    .line 440
    invoke-virtual {p1}, Lb1/t;->a()Ljava/lang/Object;

    .line 441
    .line 442
    .line 443
    move-result-object p1

    .line 444
    check-cast p1, Lh2/o4;

    .line 445
    .line 446
    iget p1, p1, Lh2/o4;->a:I

    .line 447
    .line 448
    const/4 v4, 0x1

    .line 449
    iget p0, p0, Lh2/l2;->e:I

    .line 450
    .line 451
    const/4 v5, 0x2

    .line 452
    if-ne p1, v4, :cond_d

    .line 453
    .line 454
    new-instance p1, Lh10/d;

    .line 455
    .line 456
    const/16 v4, 0x8

    .line 457
    .line 458
    invoke-direct {p1, v4}, Lh10/d;-><init>(I)V

    .line 459
    .line 460
    .line 461
    invoke-static {p1, v0}, Lb1/o0;->h(Lay0/k;Lc1/a0;)Lb1/t0;

    .line 462
    .line 463
    .line 464
    move-result-object p1

    .line 465
    invoke-static {v1, v5}, Lb1/o0;->c(Lc1/a0;I)Lb1/t0;

    .line 466
    .line 467
    .line 468
    move-result-object v1

    .line 469
    invoke-virtual {p1, v1}, Lb1/t0;->a(Lb1/t0;)Lb1/t0;

    .line 470
    .line 471
    .line 472
    move-result-object p1

    .line 473
    invoke-static {v2, v5}, Lb1/o0;->d(Lc1/a0;I)Lb1/u0;

    .line 474
    .line 475
    .line 476
    move-result-object v1

    .line 477
    new-instance v2, Lac/g;

    .line 478
    .line 479
    const/4 v4, 0x2

    .line 480
    invoke-direct {v2, p0, v4}, Lac/g;-><init>(II)V

    .line 481
    .line 482
    .line 483
    invoke-static {v2, v0}, Lb1/o0;->j(Lay0/k;Lc1/a0;)Lb1/u0;

    .line 484
    .line 485
    .line 486
    move-result-object p0

    .line 487
    invoke-virtual {v1, p0}, Lb1/u0;->a(Lb1/u0;)Lb1/u0;

    .line 488
    .line 489
    .line 490
    move-result-object p0

    .line 491
    invoke-static {p1, p0}, Landroidx/compose/animation/a;->c(Lb1/t0;Lb1/u0;)Lb1/d0;

    .line 492
    .line 493
    .line 494
    move-result-object p0

    .line 495
    goto :goto_9

    .line 496
    :cond_d
    new-instance p1, Lac/g;

    .line 497
    .line 498
    const/4 v4, 0x2

    .line 499
    invoke-direct {p1, p0, v4}, Lac/g;-><init>(II)V

    .line 500
    .line 501
    .line 502
    invoke-static {p1, v0}, Lb1/o0;->h(Lay0/k;Lc1/a0;)Lb1/t0;

    .line 503
    .line 504
    .line 505
    move-result-object p0

    .line 506
    invoke-static {v1, v5}, Lb1/o0;->c(Lc1/a0;I)Lb1/t0;

    .line 507
    .line 508
    .line 509
    move-result-object p1

    .line 510
    invoke-virtual {p0, p1}, Lb1/t0;->a(Lb1/t0;)Lb1/t0;

    .line 511
    .line 512
    .line 513
    move-result-object p0

    .line 514
    new-instance p1, Lh10/d;

    .line 515
    .line 516
    const/16 v1, 0x8

    .line 517
    .line 518
    invoke-direct {p1, v1}, Lh10/d;-><init>(I)V

    .line 519
    .line 520
    .line 521
    invoke-static {p1, v0}, Lb1/o0;->j(Lay0/k;Lc1/a0;)Lb1/u0;

    .line 522
    .line 523
    .line 524
    move-result-object p1

    .line 525
    invoke-static {v2, v5}, Lb1/o0;->d(Lc1/a0;I)Lb1/u0;

    .line 526
    .line 527
    .line 528
    move-result-object v0

    .line 529
    invoke-virtual {p1, v0}, Lb1/u0;->a(Lb1/u0;)Lb1/u0;

    .line 530
    .line 531
    .line 532
    move-result-object p1

    .line 533
    invoke-static {p0, p1}, Landroidx/compose/animation/a;->c(Lb1/t0;Lb1/u0;)Lb1/d0;

    .line 534
    .line 535
    .line 536
    move-result-object p0

    .line 537
    :goto_9
    new-instance p1, La71/a0;

    .line 538
    .line 539
    const/16 v0, 0x1b

    .line 540
    .line 541
    invoke-direct {p1, v3, v0}, La71/a0;-><init>(Ljava/lang/Object;I)V

    .line 542
    .line 543
    .line 544
    new-instance v0, Lb1/f1;

    .line 545
    .line 546
    invoke-direct {v0, p1}, Lb1/f1;-><init>(Lay0/n;)V

    .line 547
    .line 548
    .line 549
    iput-object v0, p0, Lb1/d0;->d:Lb1/f1;

    .line 550
    .line 551
    return-object p0

    .line 552
    nop

    .line 553
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
