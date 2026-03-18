.class public final synthetic Lcom/salesforce/marketingcloud/analytics/piwama/m;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/Comparator;


# instance fields
.field public final synthetic d:I


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lcom/salesforce/marketingcloud/analytics/piwama/m;->d:I

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final compare(Ljava/lang/Object;Ljava/lang/Object;)I
    .locals 4

    .line 1
    iget p0, p0, Lcom/salesforce/marketingcloud/analytics/piwama/m;->d:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, [B

    .line 7
    .line 8
    check-cast p2, [B

    .line 9
    .line 10
    array-length p0, p1

    .line 11
    array-length v0, p2

    .line 12
    if-eq p0, v0, :cond_0

    .line 13
    .line 14
    array-length p0, p1

    .line 15
    array-length p1, p2

    .line 16
    sub-int/2addr p0, p1

    .line 17
    goto :goto_1

    .line 18
    :cond_0
    const/4 p0, 0x0

    .line 19
    move v0, p0

    .line 20
    :goto_0
    array-length v1, p1

    .line 21
    if-ge v0, v1, :cond_2

    .line 22
    .line 23
    aget-byte v1, p1, v0

    .line 24
    .line 25
    aget-byte v2, p2, v0

    .line 26
    .line 27
    if-eq v1, v2, :cond_1

    .line 28
    .line 29
    sub-int p0, v1, v2

    .line 30
    .line 31
    goto :goto_1

    .line 32
    :cond_1
    add-int/lit8 v0, v0, 0x1

    .line 33
    .line 34
    goto :goto_0

    .line 35
    :cond_2
    :goto_1
    return p0

    .line 36
    :pswitch_0
    check-cast p1, Ly9/c0;

    .line 37
    .line 38
    check-cast p2, Ly9/c0;

    .line 39
    .line 40
    iget p0, p2, Ly9/c0;->a:I

    .line 41
    .line 42
    iget v0, p1, Ly9/c0;->a:I

    .line 43
    .line 44
    invoke-static {p0, v0}, Ljava/lang/Integer;->compare(II)I

    .line 45
    .line 46
    .line 47
    move-result p0

    .line 48
    if-eqz p0, :cond_3

    .line 49
    .line 50
    goto :goto_2

    .line 51
    :cond_3
    iget-object p0, p2, Ly9/c0;->c:Ljava/lang/String;

    .line 52
    .line 53
    iget-object v0, p1, Ly9/c0;->c:Ljava/lang/String;

    .line 54
    .line 55
    invoke-virtual {p0, v0}, Ljava/lang/String;->compareTo(Ljava/lang/String;)I

    .line 56
    .line 57
    .line 58
    move-result p0

    .line 59
    if-eqz p0, :cond_4

    .line 60
    .line 61
    goto :goto_2

    .line 62
    :cond_4
    iget-object p0, p2, Ly9/c0;->d:Ljava/lang/String;

    .line 63
    .line 64
    iget-object p1, p1, Ly9/c0;->d:Ljava/lang/String;

    .line 65
    .line 66
    invoke-virtual {p0, p1}, Ljava/lang/String;->compareTo(Ljava/lang/String;)I

    .line 67
    .line 68
    .line 69
    move-result p0

    .line 70
    :goto_2
    return p0

    .line 71
    :pswitch_1
    check-cast p1, Ly9/c0;

    .line 72
    .line 73
    check-cast p2, Ly9/c0;

    .line 74
    .line 75
    iget p0, p2, Ly9/c0;->b:I

    .line 76
    .line 77
    iget v0, p1, Ly9/c0;->b:I

    .line 78
    .line 79
    invoke-static {p0, v0}, Ljava/lang/Integer;->compare(II)I

    .line 80
    .line 81
    .line 82
    move-result p0

    .line 83
    if-eqz p0, :cond_5

    .line 84
    .line 85
    goto :goto_3

    .line 86
    :cond_5
    iget-object p0, p1, Ly9/c0;->c:Ljava/lang/String;

    .line 87
    .line 88
    iget-object v0, p2, Ly9/c0;->c:Ljava/lang/String;

    .line 89
    .line 90
    invoke-virtual {p0, v0}, Ljava/lang/String;->compareTo(Ljava/lang/String;)I

    .line 91
    .line 92
    .line 93
    move-result p0

    .line 94
    if-eqz p0, :cond_6

    .line 95
    .line 96
    goto :goto_3

    .line 97
    :cond_6
    iget-object p0, p1, Ly9/c0;->d:Ljava/lang/String;

    .line 98
    .line 99
    iget-object p1, p2, Ly9/c0;->d:Ljava/lang/String;

    .line 100
    .line 101
    invoke-virtual {p0, p1}, Ljava/lang/String;->compareTo(Ljava/lang/String;)I

    .line 102
    .line 103
    .line 104
    move-result p0

    .line 105
    :goto_3
    return p0

    .line 106
    :pswitch_2
    check-cast p1, Lv3/h0;

    .line 107
    .line 108
    check-cast p2, Lv3/h0;

    .line 109
    .line 110
    iget-object p0, p1, Lv3/h0;->I:Lv3/l0;

    .line 111
    .line 112
    iget-object p0, p0, Lv3/l0;->p:Lv3/y0;

    .line 113
    .line 114
    iget p0, p0, Lv3/y0;->I:F

    .line 115
    .line 116
    iget-object v0, p2, Lv3/h0;->I:Lv3/l0;

    .line 117
    .line 118
    iget-object v0, v0, Lv3/l0;->p:Lv3/y0;

    .line 119
    .line 120
    iget v0, v0, Lv3/y0;->I:F

    .line 121
    .line 122
    cmpg-float v1, p0, v0

    .line 123
    .line 124
    if-nez v1, :cond_7

    .line 125
    .line 126
    invoke-virtual {p1}, Lv3/h0;->w()I

    .line 127
    .line 128
    .line 129
    move-result p0

    .line 130
    invoke-virtual {p2}, Lv3/h0;->w()I

    .line 131
    .line 132
    .line 133
    move-result p1

    .line 134
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->g(II)I

    .line 135
    .line 136
    .line 137
    move-result p0

    .line 138
    goto :goto_4

    .line 139
    :cond_7
    invoke-static {p0, v0}, Ljava/lang/Float;->compare(FF)I

    .line 140
    .line 141
    .line 142
    move-result p0

    .line 143
    :goto_4
    return p0

    .line 144
    :pswitch_3
    check-cast p1, Lu9/c;

    .line 145
    .line 146
    check-cast p2, Lu9/c;

    .line 147
    .line 148
    iget-wide p0, p1, Lu9/c;->b:J

    .line 149
    .line 150
    iget-wide v0, p2, Lu9/c;->b:J

    .line 151
    .line 152
    invoke-static {p0, p1, v0, v1}, Ljava/lang/Long;->compare(JJ)I

    .line 153
    .line 154
    .line 155
    move-result p0

    .line 156
    return p0

    .line 157
    :pswitch_4
    check-cast p1, Lu9/d;

    .line 158
    .line 159
    check-cast p2, Lu9/d;

    .line 160
    .line 161
    iget-object p0, p1, Lu9/d;->a:Lu9/e;

    .line 162
    .line 163
    iget p0, p0, Lu9/e;->b:I

    .line 164
    .line 165
    iget-object p1, p2, Lu9/d;->a:Lu9/e;

    .line 166
    .line 167
    iget p1, p1, Lu9/e;->b:I

    .line 168
    .line 169
    invoke-static {p0, p1}, Ljava/lang/Integer;->compare(II)I

    .line 170
    .line 171
    .line 172
    move-result p0

    .line 173
    return p0

    .line 174
    :pswitch_5
    check-cast p1, Landroid/util/Size;

    .line 175
    .line 176
    check-cast p2, Landroid/util/Size;

    .line 177
    .line 178
    invoke-virtual {p1}, Landroid/util/Size;->getWidth()I

    .line 179
    .line 180
    .line 181
    move-result p0

    .line 182
    int-to-long v0, p0

    .line 183
    invoke-virtual {p1}, Landroid/util/Size;->getHeight()I

    .line 184
    .line 185
    .line 186
    move-result p0

    .line 187
    int-to-long p0, p0

    .line 188
    mul-long/2addr v0, p0

    .line 189
    invoke-virtual {p2}, Landroid/util/Size;->getWidth()I

    .line 190
    .line 191
    .line 192
    move-result p0

    .line 193
    int-to-long p0, p0

    .line 194
    invoke-virtual {p2}, Landroid/util/Size;->getHeight()I

    .line 195
    .line 196
    .line 197
    move-result p2

    .line 198
    int-to-long v2, p2

    .line 199
    mul-long/2addr p0, v2

    .line 200
    sub-long/2addr v0, p0

    .line 201
    invoke-static {v0, v1}, Ljava/lang/Long;->signum(J)I

    .line 202
    .line 203
    .line 204
    move-result p0

    .line 205
    return p0

    .line 206
    :pswitch_6
    check-cast p1, Lgy0/j;

    .line 207
    .line 208
    check-cast p2, Lgy0/j;

    .line 209
    .line 210
    iget p0, p1, Lgy0/h;->d:I

    .line 211
    .line 212
    iget v0, p2, Lgy0/h;->d:I

    .line 213
    .line 214
    if-ne p0, v0, :cond_8

    .line 215
    .line 216
    iget p0, p1, Lgy0/h;->e:I

    .line 217
    .line 218
    iget p1, p2, Lgy0/h;->e:I

    .line 219
    .line 220
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->g(II)I

    .line 221
    .line 222
    .line 223
    move-result p0

    .line 224
    goto :goto_5

    .line 225
    :cond_8
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->g(II)I

    .line 226
    .line 227
    .line 228
    move-result p0

    .line 229
    :goto_5
    return p0

    .line 230
    :pswitch_7
    check-cast p1, Ljava/io/File;

    .line 231
    .line 232
    check-cast p2, Ljava/io/File;

    .line 233
    .line 234
    invoke-virtual {p1}, Ljava/io/File;->getName()Ljava/lang/String;

    .line 235
    .line 236
    .line 237
    move-result-object p0

    .line 238
    sget p1, Lss/a;->f:I

    .line 239
    .line 240
    const/4 v0, 0x0

    .line 241
    invoke-virtual {p0, v0, p1}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 242
    .line 243
    .line 244
    move-result-object p0

    .line 245
    invoke-virtual {p2}, Ljava/io/File;->getName()Ljava/lang/String;

    .line 246
    .line 247
    .line 248
    move-result-object p2

    .line 249
    invoke-virtual {p2, v0, p1}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 250
    .line 251
    .line 252
    move-result-object p1

    .line 253
    invoke-virtual {p0, p1}, Ljava/lang/String;->compareTo(Ljava/lang/String;)I

    .line 254
    .line 255
    .line 256
    move-result p0

    .line 257
    return p0

    .line 258
    :pswitch_8
    check-cast p1, Ljava/io/File;

    .line 259
    .line 260
    check-cast p2, Ljava/io/File;

    .line 261
    .line 262
    invoke-virtual {p2}, Ljava/io/File;->getName()Ljava/lang/String;

    .line 263
    .line 264
    .line 265
    move-result-object p0

    .line 266
    invoke-virtual {p1}, Ljava/io/File;->getName()Ljava/lang/String;

    .line 267
    .line 268
    .line 269
    move-result-object p1

    .line 270
    invoke-virtual {p0, p1}, Ljava/lang/String;->compareTo(Ljava/lang/String;)I

    .line 271
    .line 272
    .line 273
    move-result p0

    .line 274
    return p0

    .line 275
    :pswitch_9
    check-cast p1, Lo1/e0;

    .line 276
    .line 277
    check-cast p2, Lo1/e0;

    .line 278
    .line 279
    invoke-interface {p1}, Lo1/e0;->getIndex()I

    .line 280
    .line 281
    .line 282
    move-result p0

    .line 283
    invoke-interface {p2}, Lo1/e0;->getIndex()I

    .line 284
    .line 285
    .line 286
    move-result p1

    .line 287
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->g(II)I

    .line 288
    .line 289
    .line 290
    move-result p0

    .line 291
    return p0

    .line 292
    :pswitch_a
    check-cast p1, Lo1/c1;

    .line 293
    .line 294
    check-cast p2, Lo1/c1;

    .line 295
    .line 296
    iget p0, p2, Lo1/c1;->a:I

    .line 297
    .line 298
    iget p1, p1, Lo1/c1;->a:I

    .line 299
    .line 300
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->g(II)I

    .line 301
    .line 302
    .line 303
    move-result p0

    .line 304
    return p0

    .line 305
    :pswitch_b
    check-cast p1, Lps/q1;

    .line 306
    .line 307
    check-cast p2, Lps/q1;

    .line 308
    .line 309
    check-cast p1, Lps/f0;

    .line 310
    .line 311
    iget-object p0, p1, Lps/f0;->a:Ljava/lang/String;

    .line 312
    .line 313
    check-cast p2, Lps/f0;

    .line 314
    .line 315
    iget-object p1, p2, Lps/f0;->a:Ljava/lang/String;

    .line 316
    .line 317
    invoke-virtual {p0, p1}, Ljava/lang/String;->compareTo(Ljava/lang/String;)I

    .line 318
    .line 319
    .line 320
    move-result p0

    .line 321
    return p0

    .line 322
    :pswitch_c
    check-cast p1, Ljava/io/File;

    .line 323
    .line 324
    check-cast p2, Ljava/io/File;

    .line 325
    .line 326
    invoke-virtual {p2}, Ljava/io/File;->lastModified()J

    .line 327
    .line 328
    .line 329
    move-result-wide v0

    .line 330
    invoke-virtual {p1}, Ljava/io/File;->lastModified()J

    .line 331
    .line 332
    .line 333
    move-result-wide p0

    .line 334
    invoke-static {v0, v1, p0, p1}, Ljava/lang/Long;->compare(JJ)I

    .line 335
    .line 336
    .line 337
    move-result p0

    .line 338
    return p0

    .line 339
    :pswitch_d
    check-cast p1, Lm9/d;

    .line 340
    .line 341
    check-cast p2, Lm9/d;

    .line 342
    .line 343
    iget p0, p2, Lm9/d;->b:I

    .line 344
    .line 345
    iget p1, p1, Lm9/d;->b:I

    .line 346
    .line 347
    invoke-static {p0, p1}, Ljava/lang/Integer;->compare(II)I

    .line 348
    .line 349
    .line 350
    move-result p0

    .line 351
    return p0

    .line 352
    :pswitch_e
    check-cast p1, Ll2/r0;

    .line 353
    .line 354
    check-cast p2, Ll2/r0;

    .line 355
    .line 356
    iget p0, p1, Ll2/r0;->b:I

    .line 357
    .line 358
    iget p1, p2, Ll2/r0;->b:I

    .line 359
    .line 360
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->g(II)I

    .line 361
    .line 362
    .line 363
    move-result p0

    .line 364
    return p0

    .line 365
    :pswitch_f
    check-cast p1, Lk8/m;

    .line 366
    .line 367
    check-cast p2, Lk8/m;

    .line 368
    .line 369
    iget p0, p1, Lk8/m;->c:F

    .line 370
    .line 371
    iget p1, p2, Lk8/m;->c:F

    .line 372
    .line 373
    invoke-static {p0, p1}, Ljava/lang/Float;->compare(FF)I

    .line 374
    .line 375
    .line 376
    move-result p0

    .line 377
    return p0

    .line 378
    :pswitch_10
    check-cast p1, Lk8/m;

    .line 379
    .line 380
    check-cast p2, Lk8/m;

    .line 381
    .line 382
    iget p0, p1, Lk8/m;->a:I

    .line 383
    .line 384
    iget p1, p2, Lk8/m;->a:I

    .line 385
    .line 386
    sub-int/2addr p0, p1

    .line 387
    return p0

    .line 388
    :pswitch_11
    check-cast p1, Lj8/n;

    .line 389
    .line 390
    check-cast p2, Lj8/n;

    .line 391
    .line 392
    iget-boolean p0, p1, Lj8/n;->h:Z

    .line 393
    .line 394
    iget v0, p1, Lj8/n;->m:I

    .line 395
    .line 396
    if-eqz p0, :cond_9

    .line 397
    .line 398
    iget-boolean p0, p1, Lj8/n;->k:Z

    .line 399
    .line 400
    if-eqz p0, :cond_9

    .line 401
    .line 402
    sget-object p0, Lj8/o;->l:Lhr/w0;

    .line 403
    .line 404
    goto :goto_6

    .line 405
    :cond_9
    sget-object p0, Lj8/o;->l:Lhr/w0;

    .line 406
    .line 407
    invoke-virtual {p0}, Lhr/w0;->a()Lhr/w0;

    .line 408
    .line 409
    .line 410
    move-result-object p0

    .line 411
    :goto_6
    iget-object v1, p1, Lj8/n;->i:Lj8/i;

    .line 412
    .line 413
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 414
    .line 415
    .line 416
    iget p1, p1, Lj8/n;->n:I

    .line 417
    .line 418
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 419
    .line 420
    .line 421
    move-result-object p1

    .line 422
    iget v1, p2, Lj8/n;->n:I

    .line 423
    .line 424
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 425
    .line 426
    .line 427
    move-result-object v1

    .line 428
    sget-object v2, Lhr/z;->a:Lhr/x;

    .line 429
    .line 430
    invoke-virtual {v2, p1, v1, p0}, Lhr/z;->b(Ljava/lang/Object;Ljava/lang/Object;Ljava/util/Comparator;)Lhr/z;

    .line 431
    .line 432
    .line 433
    move-result-object p1

    .line 434
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 435
    .line 436
    .line 437
    move-result-object v0

    .line 438
    iget p2, p2, Lj8/n;->m:I

    .line 439
    .line 440
    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 441
    .line 442
    .line 443
    move-result-object p2

    .line 444
    invoke-virtual {p1, v0, p2, p0}, Lhr/z;->b(Ljava/lang/Object;Ljava/lang/Object;Ljava/util/Comparator;)Lhr/z;

    .line 445
    .line 446
    .line 447
    move-result-object p0

    .line 448
    invoke-virtual {p0}, Lhr/z;->e()I

    .line 449
    .line 450
    .line 451
    move-result p0

    .line 452
    return p0

    .line 453
    :pswitch_12
    check-cast p1, Lj8/n;

    .line 454
    .line 455
    check-cast p2, Lj8/n;

    .line 456
    .line 457
    invoke-static {p1, p2}, Lj8/n;->c(Lj8/n;Lj8/n;)I

    .line 458
    .line 459
    .line 460
    move-result p0

    .line 461
    return p0

    .line 462
    :pswitch_13
    check-cast p1, Ljava/util/List;

    .line 463
    .line 464
    check-cast p2, Ljava/util/List;

    .line 465
    .line 466
    const/4 p0, 0x0

    .line 467
    invoke-interface {p1, p0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 468
    .line 469
    .line 470
    move-result-object p1

    .line 471
    check-cast p1, Lj8/k;

    .line 472
    .line 473
    invoke-interface {p2, p0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 474
    .line 475
    .line 476
    move-result-object p0

    .line 477
    check-cast p0, Lj8/k;

    .line 478
    .line 479
    invoke-virtual {p1, p0}, Lj8/k;->c(Lj8/k;)I

    .line 480
    .line 481
    .line 482
    move-result p0

    .line 483
    return p0

    .line 484
    :pswitch_14
    check-cast p1, Ljava/util/List;

    .line 485
    .line 486
    check-cast p2, Ljava/util/List;

    .line 487
    .line 488
    invoke-static {p1}, Ljava/util/Collections;->max(Ljava/util/Collection;)Ljava/lang/Object;

    .line 489
    .line 490
    .line 491
    move-result-object p0

    .line 492
    check-cast p0, Lj8/e;

    .line 493
    .line 494
    invoke-static {p2}, Ljava/util/Collections;->max(Ljava/util/Collection;)Ljava/lang/Object;

    .line 495
    .line 496
    .line 497
    move-result-object p1

    .line 498
    check-cast p1, Lj8/e;

    .line 499
    .line 500
    invoke-virtual {p0, p1}, Lj8/e;->c(Lj8/e;)I

    .line 501
    .line 502
    .line 503
    move-result p0

    .line 504
    return p0

    .line 505
    :pswitch_15
    check-cast p1, Ljava/util/List;

    .line 506
    .line 507
    check-cast p2, Ljava/util/List;

    .line 508
    .line 509
    new-instance p0, Lcom/salesforce/marketingcloud/analytics/piwama/m;

    .line 510
    .line 511
    const/16 v0, 0xa

    .line 512
    .line 513
    invoke-direct {p0, v0}, Lcom/salesforce/marketingcloud/analytics/piwama/m;-><init>(I)V

    .line 514
    .line 515
    .line 516
    invoke-static {p1, p0}, Ljava/util/Collections;->max(Ljava/util/Collection;Ljava/util/Comparator;)Ljava/lang/Object;

    .line 517
    .line 518
    .line 519
    move-result-object p0

    .line 520
    check-cast p0, Lj8/n;

    .line 521
    .line 522
    new-instance v0, Lcom/salesforce/marketingcloud/analytics/piwama/m;

    .line 523
    .line 524
    const/16 v1, 0xa

    .line 525
    .line 526
    invoke-direct {v0, v1}, Lcom/salesforce/marketingcloud/analytics/piwama/m;-><init>(I)V

    .line 527
    .line 528
    .line 529
    invoke-static {p2, v0}, Ljava/util/Collections;->max(Ljava/util/Collection;Ljava/util/Comparator;)Ljava/lang/Object;

    .line 530
    .line 531
    .line 532
    move-result-object v0

    .line 533
    check-cast v0, Lj8/n;

    .line 534
    .line 535
    invoke-static {p0, v0}, Lj8/n;->c(Lj8/n;Lj8/n;)I

    .line 536
    .line 537
    .line 538
    move-result p0

    .line 539
    invoke-static {p0}, Lhr/x;->f(I)Lhr/z;

    .line 540
    .line 541
    .line 542
    move-result-object p0

    .line 543
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 544
    .line 545
    .line 546
    move-result v0

    .line 547
    invoke-interface {p2}, Ljava/util/List;->size()I

    .line 548
    .line 549
    .line 550
    move-result v1

    .line 551
    invoke-virtual {p0, v0, v1}, Lhr/z;->a(II)Lhr/z;

    .line 552
    .line 553
    .line 554
    move-result-object p0

    .line 555
    new-instance v0, Lcom/salesforce/marketingcloud/analytics/piwama/m;

    .line 556
    .line 557
    const/16 v1, 0xb

    .line 558
    .line 559
    invoke-direct {v0, v1}, Lcom/salesforce/marketingcloud/analytics/piwama/m;-><init>(I)V

    .line 560
    .line 561
    .line 562
    invoke-static {p1, v0}, Ljava/util/Collections;->max(Ljava/util/Collection;Ljava/util/Comparator;)Ljava/lang/Object;

    .line 563
    .line 564
    .line 565
    move-result-object p1

    .line 566
    check-cast p1, Lj8/n;

    .line 567
    .line 568
    new-instance v0, Lcom/salesforce/marketingcloud/analytics/piwama/m;

    .line 569
    .line 570
    invoke-direct {v0, v1}, Lcom/salesforce/marketingcloud/analytics/piwama/m;-><init>(I)V

    .line 571
    .line 572
    .line 573
    invoke-static {p2, v0}, Ljava/util/Collections;->max(Ljava/util/Collection;Ljava/util/Comparator;)Ljava/lang/Object;

    .line 574
    .line 575
    .line 576
    move-result-object p2

    .line 577
    check-cast p2, Lj8/n;

    .line 578
    .line 579
    new-instance v0, Lcom/salesforce/marketingcloud/analytics/piwama/m;

    .line 580
    .line 581
    invoke-direct {v0, v1}, Lcom/salesforce/marketingcloud/analytics/piwama/m;-><init>(I)V

    .line 582
    .line 583
    .line 584
    invoke-virtual {p0, p1, p2, v0}, Lhr/z;->b(Ljava/lang/Object;Ljava/lang/Object;Ljava/util/Comparator;)Lhr/z;

    .line 585
    .line 586
    .line 587
    move-result-object p0

    .line 588
    invoke-virtual {p0}, Lhr/z;->e()I

    .line 589
    .line 590
    .line 591
    move-result p0

    .line 592
    return p0

    .line 593
    :pswitch_16
    check-cast p1, Ljava/util/List;

    .line 594
    .line 595
    check-cast p2, Ljava/util/List;

    .line 596
    .line 597
    const/4 p0, 0x0

    .line 598
    invoke-interface {p1, p0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 599
    .line 600
    .line 601
    move-result-object p1

    .line 602
    check-cast p1, Lj8/f;

    .line 603
    .line 604
    invoke-interface {p2, p0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 605
    .line 606
    .line 607
    move-result-object p0

    .line 608
    check-cast p0, Lj8/f;

    .line 609
    .line 610
    iget p1, p1, Lj8/f;->i:I

    .line 611
    .line 612
    iget p0, p0, Lj8/f;->i:I

    .line 613
    .line 614
    invoke-static {p1, p0}, Ljava/lang/Integer;->compare(II)I

    .line 615
    .line 616
    .line 617
    move-result p0

    .line 618
    return p0

    .line 619
    :pswitch_17
    check-cast p1, Ljava/lang/Integer;

    .line 620
    .line 621
    check-cast p2, Ljava/lang/Integer;

    .line 622
    .line 623
    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    .line 624
    .line 625
    .line 626
    move-result p0

    .line 627
    const/4 v0, -0x1

    .line 628
    if-ne p0, v0, :cond_a

    .line 629
    .line 630
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 631
    .line 632
    .line 633
    move-result p0

    .line 634
    if-ne p0, v0, :cond_c

    .line 635
    .line 636
    const/4 v0, 0x0

    .line 637
    goto :goto_7

    .line 638
    :cond_a
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 639
    .line 640
    .line 641
    move-result p0

    .line 642
    if-ne p0, v0, :cond_b

    .line 643
    .line 644
    const/4 v0, 0x1

    .line 645
    goto :goto_7

    .line 646
    :cond_b
    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    .line 647
    .line 648
    .line 649
    move-result p0

    .line 650
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 651
    .line 652
    .line 653
    move-result p1

    .line 654
    sub-int v0, p0, p1

    .line 655
    .line 656
    :cond_c
    :goto_7
    return v0

    .line 657
    :pswitch_18
    check-cast p1, Lt7/o;

    .line 658
    .line 659
    check-cast p2, Lt7/o;

    .line 660
    .line 661
    iget p0, p2, Lt7/o;->j:I

    .line 662
    .line 663
    iget p1, p1, Lt7/o;->j:I

    .line 664
    .line 665
    sub-int/2addr p0, p1

    .line 666
    return p0

    .line 667
    :pswitch_19
    check-cast p1, Llx0/l;

    .line 668
    .line 669
    check-cast p2, Llx0/l;

    .line 670
    .line 671
    iget-object p0, p1, Llx0/l;->e:Ljava/lang/Object;

    .line 672
    .line 673
    check-cast p0, Ljava/lang/Number;

    .line 674
    .line 675
    invoke-virtual {p0}, Ljava/lang/Number;->intValue()I

    .line 676
    .line 677
    .line 678
    move-result p0

    .line 679
    iget-object p1, p1, Llx0/l;->d:Ljava/lang/Object;

    .line 680
    .line 681
    check-cast p1, Ljava/lang/Number;

    .line 682
    .line 683
    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    .line 684
    .line 685
    .line 686
    move-result p1

    .line 687
    sub-int/2addr p0, p1

    .line 688
    iget-object p1, p2, Llx0/l;->e:Ljava/lang/Object;

    .line 689
    .line 690
    check-cast p1, Ljava/lang/Number;

    .line 691
    .line 692
    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    .line 693
    .line 694
    .line 695
    move-result p1

    .line 696
    iget-object p2, p2, Llx0/l;->d:Ljava/lang/Object;

    .line 697
    .line 698
    check-cast p2, Ljava/lang/Number;

    .line 699
    .line 700
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 701
    .line 702
    .line 703
    move-result p2

    .line 704
    sub-int/2addr p1, p2

    .line 705
    sub-int/2addr p0, p1

    .line 706
    return p0

    .line 707
    :pswitch_1a
    check-cast p1, Lh0/g;

    .line 708
    .line 709
    check-cast p2, Lh0/g;

    .line 710
    .line 711
    iget-object p0, p1, Lh0/g;->a:Ljava/lang/String;

    .line 712
    .line 713
    iget-object p1, p2, Lh0/g;->a:Ljava/lang/String;

    .line 714
    .line 715
    invoke-virtual {p0, p1}, Ljava/lang/String;->compareTo(Ljava/lang/String;)I

    .line 716
    .line 717
    .line 718
    move-result p0

    .line 719
    return p0

    .line 720
    :pswitch_1b
    check-cast p1, Ljava/lang/String;

    .line 721
    .line 722
    check-cast p2, Ljava/lang/String;

    .line 723
    .line 724
    const-string p0, ":"

    .line 725
    .line 726
    invoke-virtual {p1, p0}, Ljava/lang/String;->split(Ljava/lang/String;)[Ljava/lang/String;

    .line 727
    .line 728
    .line 729
    move-result-object p1

    .line 730
    const/4 v0, 0x0

    .line 731
    aget-object p1, p1, v0

    .line 732
    .line 733
    invoke-static {p1}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    .line 734
    .line 735
    .line 736
    move-result p1

    .line 737
    invoke-virtual {p2, p0}, Ljava/lang/String;->split(Ljava/lang/String;)[Ljava/lang/String;

    .line 738
    .line 739
    .line 740
    move-result-object p0

    .line 741
    aget-object p0, p0, v0

    .line 742
    .line 743
    invoke-static {p0}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    .line 744
    .line 745
    .line 746
    move-result p0

    .line 747
    sub-int/2addr p1, p0

    .line 748
    return p1

    .line 749
    :pswitch_1c
    check-cast p1, Lcom/salesforce/marketingcloud/analytics/b;

    .line 750
    .line 751
    check-cast p2, Lcom/salesforce/marketingcloud/analytics/b;

    .line 752
    .line 753
    invoke-static {p1, p2}, Lcom/salesforce/marketingcloud/analytics/piwama/i;->d(Lcom/salesforce/marketingcloud/analytics/b;Lcom/salesforce/marketingcloud/analytics/b;)I

    .line 754
    .line 755
    .line 756
    move-result p0

    .line 757
    return p0

    .line 758
    nop

    .line 759
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
