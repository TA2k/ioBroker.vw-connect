.class public final Lal/q;
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
    iput p2, p0, Lal/q;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lal/q;->e:Ljava/lang/Object;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    .line 1
    iget v0, p0, Lal/q;->d:I

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/4 v2, 0x6

    .line 5
    sget-object v3, Lk1/i1;->a:Lk1/i1;

    .line 6
    .line 7
    const/16 v4, 0x36

    .line 8
    .line 9
    sget-object v5, Lx2/p;->b:Lx2/p;

    .line 10
    .line 11
    sget-object v6, Llx0/b0;->a:Llx0/b0;

    .line 12
    .line 13
    const/4 v7, 0x2

    .line 14
    const/4 v8, 0x1

    .line 15
    iget-object p0, p0, Lal/q;->e:Ljava/lang/Object;

    .line 16
    .line 17
    const/4 v9, 0x0

    .line 18
    packed-switch v0, :pswitch_data_0

    .line 19
    .line 20
    .line 21
    check-cast p1, Ll2/o;

    .line 22
    .line 23
    check-cast p2, Ljava/lang/Number;

    .line 24
    .line 25
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 26
    .line 27
    .line 28
    check-cast p1, Ll2/t;

    .line 29
    .line 30
    const p2, -0x520d2714

    .line 31
    .line 32
    .line 33
    invoke-virtual {p1, p2}, Ll2/t;->Y(I)V

    .line 34
    .line 35
    .line 36
    check-cast p0, Landroid/app/RemoteAction;

    .line 37
    .line 38
    invoke-virtual {p0}, Landroid/app/RemoteAction;->getTitle()Ljava/lang/CharSequence;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    invoke-virtual {p1, v9}, Ll2/t;->q(Z)V

    .line 47
    .line 48
    .line 49
    return-object p0

    .line 50
    :pswitch_0
    check-cast p1, Ll2/o;

    .line 51
    .line 52
    check-cast p2, Ljava/lang/Number;

    .line 53
    .line 54
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 55
    .line 56
    .line 57
    check-cast p1, Ll2/t;

    .line 58
    .line 59
    const p2, 0x38a0c7d5

    .line 60
    .line 61
    .line 62
    invoke-virtual {p1, p2}, Ll2/t;->Y(I)V

    .line 63
    .line 64
    .line 65
    check-cast p0, Landroid/view/textclassifier/TextClassification;

    .line 66
    .line 67
    invoke-virtual {p0}, Landroid/view/textclassifier/TextClassification;->getLabel()Ljava/lang/CharSequence;

    .line 68
    .line 69
    .line 70
    move-result-object p0

    .line 71
    invoke-static {p0}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 72
    .line 73
    .line 74
    move-result-object p0

    .line 75
    invoke-virtual {p1, v9}, Ll2/t;->q(Z)V

    .line 76
    .line 77
    .line 78
    return-object p0

    .line 79
    :pswitch_1
    check-cast p1, Ll2/o;

    .line 80
    .line 81
    check-cast p2, Ljava/lang/Number;

    .line 82
    .line 83
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 84
    .line 85
    .line 86
    check-cast p1, Ll2/t;

    .line 87
    .line 88
    const p2, 0x27b3a34e

    .line 89
    .line 90
    .line 91
    invoke-virtual {p1, p2}, Ll2/t;->Y(I)V

    .line 92
    .line 93
    .line 94
    check-cast p0, Lw1/d;

    .line 95
    .line 96
    iget-object p0, p0, Lw1/d;->b:Ljava/lang/String;

    .line 97
    .line 98
    invoke-virtual {p1, v9}, Ll2/t;->q(Z)V

    .line 99
    .line 100
    .line 101
    return-object p0

    .line 102
    :pswitch_2
    check-cast p1, Ll2/o;

    .line 103
    .line 104
    check-cast p2, Ljava/lang/Number;

    .line 105
    .line 106
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 107
    .line 108
    .line 109
    move-result p0

    .line 110
    and-int/lit8 p2, p0, 0x3

    .line 111
    .line 112
    if-eq p2, v7, :cond_0

    .line 113
    .line 114
    move v9, v8

    .line 115
    :cond_0
    and-int/2addr p0, v8

    .line 116
    check-cast p1, Ll2/t;

    .line 117
    .line 118
    invoke-virtual {p1, p0, v9}, Ll2/t;->O(IZ)Z

    .line 119
    .line 120
    .line 121
    move-result p0

    .line 122
    if-nez p0, :cond_1

    .line 123
    .line 124
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 125
    .line 126
    .line 127
    return-object v6

    .line 128
    :cond_1
    const/4 p0, 0x0

    .line 129
    throw p0

    .line 130
    :pswitch_3
    check-cast p1, Ll2/o;

    .line 131
    .line 132
    check-cast p2, Ljava/lang/Number;

    .line 133
    .line 134
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 135
    .line 136
    .line 137
    move-result p2

    .line 138
    and-int/lit8 v0, p2, 0x3

    .line 139
    .line 140
    if-eq v0, v7, :cond_2

    .line 141
    .line 142
    move v9, v8

    .line 143
    :cond_2
    and-int/2addr p2, v8

    .line 144
    check-cast p1, Ll2/t;

    .line 145
    .line 146
    invoke-virtual {p1, p2, v9}, Ll2/t;->O(IZ)Z

    .line 147
    .line 148
    .line 149
    move-result p2

    .line 150
    if-eqz p2, :cond_6

    .line 151
    .line 152
    sget-object p2, Lk1/j;->b:Lk1/c;

    .line 153
    .line 154
    sget-object v0, Lx2/c;->n:Lx2/i;

    .line 155
    .line 156
    check-cast p0, Lh2/t8;

    .line 157
    .line 158
    iget-object p0, p0, Lh2/t8;->f:Lt2/b;

    .line 159
    .line 160
    invoke-static {p2, v0, p1, v4}, Lk1/e1;->a(Lk1/g;Lx2/i;Ll2/o;I)Lk1/g1;

    .line 161
    .line 162
    .line 163
    move-result-object p2

    .line 164
    iget-wide v0, p1, Ll2/t;->T:J

    .line 165
    .line 166
    invoke-static {v0, v1}, Ljava/lang/Long;->hashCode(J)I

    .line 167
    .line 168
    .line 169
    move-result v0

    .line 170
    invoke-virtual {p1}, Ll2/t;->m()Ll2/p1;

    .line 171
    .line 172
    .line 173
    move-result-object v1

    .line 174
    invoke-static {p1, v5}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 175
    .line 176
    .line 177
    move-result-object v4

    .line 178
    sget-object v5, Lv3/k;->m1:Lv3/j;

    .line 179
    .line 180
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 181
    .line 182
    .line 183
    sget-object v5, Lv3/j;->b:Lv3/i;

    .line 184
    .line 185
    invoke-virtual {p1}, Ll2/t;->c0()V

    .line 186
    .line 187
    .line 188
    iget-boolean v7, p1, Ll2/t;->S:Z

    .line 189
    .line 190
    if-eqz v7, :cond_3

    .line 191
    .line 192
    invoke-virtual {p1, v5}, Ll2/t;->l(Lay0/a;)V

    .line 193
    .line 194
    .line 195
    goto :goto_0

    .line 196
    :cond_3
    invoke-virtual {p1}, Ll2/t;->m0()V

    .line 197
    .line 198
    .line 199
    :goto_0
    sget-object v5, Lv3/j;->g:Lv3/h;

    .line 200
    .line 201
    invoke-static {v5, p2, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 202
    .line 203
    .line 204
    sget-object p2, Lv3/j;->f:Lv3/h;

    .line 205
    .line 206
    invoke-static {p2, v1, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 207
    .line 208
    .line 209
    sget-object p2, Lv3/j;->j:Lv3/h;

    .line 210
    .line 211
    iget-boolean v1, p1, Ll2/t;->S:Z

    .line 212
    .line 213
    if-nez v1, :cond_4

    .line 214
    .line 215
    invoke-virtual {p1}, Ll2/t;->L()Ljava/lang/Object;

    .line 216
    .line 217
    .line 218
    move-result-object v1

    .line 219
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 220
    .line 221
    .line 222
    move-result-object v5

    .line 223
    invoke-static {v1, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 224
    .line 225
    .line 226
    move-result v1

    .line 227
    if-nez v1, :cond_5

    .line 228
    .line 229
    :cond_4
    invoke-static {v0, p1, v0, p2}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 230
    .line 231
    .line 232
    :cond_5
    sget-object p2, Lv3/j;->d:Lv3/h;

    .line 233
    .line 234
    invoke-static {p2, v4, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 235
    .line 236
    .line 237
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 238
    .line 239
    .line 240
    move-result-object p2

    .line 241
    invoke-virtual {p0, v3, p1, p2}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 242
    .line 243
    .line 244
    invoke-virtual {p1, v8}, Ll2/t;->q(Z)V

    .line 245
    .line 246
    .line 247
    goto :goto_1

    .line 248
    :cond_6
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 249
    .line 250
    .line 251
    :goto_1
    return-object v6

    .line 252
    :pswitch_4
    check-cast p1, Ll2/o;

    .line 253
    .line 254
    check-cast p2, Ljava/lang/Number;

    .line 255
    .line 256
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 257
    .line 258
    .line 259
    move-result p2

    .line 260
    check-cast p0, Lh2/r6;

    .line 261
    .line 262
    and-int/lit8 v0, p2, 0x3

    .line 263
    .line 264
    if-eq v0, v7, :cond_7

    .line 265
    .line 266
    move v0, v8

    .line 267
    goto :goto_2

    .line 268
    :cond_7
    move v0, v9

    .line 269
    :goto_2
    and-int/2addr p2, v8

    .line 270
    check-cast p1, Ll2/t;

    .line 271
    .line 272
    invoke-virtual {p1, p2, v0}, Ll2/t;->O(IZ)Z

    .line 273
    .line 274
    .line 275
    move-result p2

    .line 276
    if-eqz p2, :cond_b

    .line 277
    .line 278
    const/high16 p2, 0x3f800000    # 1.0f

    .line 279
    .line 280
    invoke-static {v5, p2}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 281
    .line 282
    .line 283
    move-result-object p2

    .line 284
    iget-object v0, p0, Lh2/r6;->e:Lk1/q1;

    .line 285
    .line 286
    invoke-static {p2, v0}, Lk1/d;->r(Lx2/s;Lk1/q1;)Lx2/s;

    .line 287
    .line 288
    .line 289
    move-result-object p2

    .line 290
    sget v0, Lh2/q6;->a:F

    .line 291
    .line 292
    invoke-static {p2, v1, v0, v8}, Landroidx/compose/foundation/layout/d;->b(Lx2/s;FFI)Lx2/s;

    .line 293
    .line 294
    .line 295
    move-result-object p2

    .line 296
    new-instance v0, Lqe/b;

    .line 297
    .line 298
    const/16 v1, 0x1a

    .line 299
    .line 300
    invoke-direct {v0, v1}, Lqe/b;-><init>(I)V

    .line 301
    .line 302
    .line 303
    invoke-static {p2, v9, v0}, Ld4/n;->b(Lx2/s;ZLay0/k;)Lx2/s;

    .line 304
    .line 305
    .line 306
    move-result-object p2

    .line 307
    sget-object v0, Lk1/j;->a:Lk1/c;

    .line 308
    .line 309
    sget v0, Lh2/q6;->b:F

    .line 310
    .line 311
    invoke-static {v0}, Lk1/j;->g(F)Lk1/h;

    .line 312
    .line 313
    .line 314
    move-result-object v0

    .line 315
    sget-object v1, Lx2/c;->n:Lx2/i;

    .line 316
    .line 317
    iget-object p0, p0, Lh2/r6;->f:Lt2/b;

    .line 318
    .line 319
    invoke-static {v0, v1, p1, v4}, Lk1/e1;->a(Lk1/g;Lx2/i;Ll2/o;I)Lk1/g1;

    .line 320
    .line 321
    .line 322
    move-result-object v0

    .line 323
    iget-wide v4, p1, Ll2/t;->T:J

    .line 324
    .line 325
    invoke-static {v4, v5}, Ljava/lang/Long;->hashCode(J)I

    .line 326
    .line 327
    .line 328
    move-result v1

    .line 329
    invoke-virtual {p1}, Ll2/t;->m()Ll2/p1;

    .line 330
    .line 331
    .line 332
    move-result-object v4

    .line 333
    invoke-static {p1, p2}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 334
    .line 335
    .line 336
    move-result-object p2

    .line 337
    sget-object v5, Lv3/k;->m1:Lv3/j;

    .line 338
    .line 339
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 340
    .line 341
    .line 342
    sget-object v5, Lv3/j;->b:Lv3/i;

    .line 343
    .line 344
    invoke-virtual {p1}, Ll2/t;->c0()V

    .line 345
    .line 346
    .line 347
    iget-boolean v7, p1, Ll2/t;->S:Z

    .line 348
    .line 349
    if-eqz v7, :cond_8

    .line 350
    .line 351
    invoke-virtual {p1, v5}, Ll2/t;->l(Lay0/a;)V

    .line 352
    .line 353
    .line 354
    goto :goto_3

    .line 355
    :cond_8
    invoke-virtual {p1}, Ll2/t;->m0()V

    .line 356
    .line 357
    .line 358
    :goto_3
    sget-object v5, Lv3/j;->g:Lv3/h;

    .line 359
    .line 360
    invoke-static {v5, v0, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 361
    .line 362
    .line 363
    sget-object v0, Lv3/j;->f:Lv3/h;

    .line 364
    .line 365
    invoke-static {v0, v4, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 366
    .line 367
    .line 368
    sget-object v0, Lv3/j;->j:Lv3/h;

    .line 369
    .line 370
    iget-boolean v4, p1, Ll2/t;->S:Z

    .line 371
    .line 372
    if-nez v4, :cond_9

    .line 373
    .line 374
    invoke-virtual {p1}, Ll2/t;->L()Ljava/lang/Object;

    .line 375
    .line 376
    .line 377
    move-result-object v4

    .line 378
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 379
    .line 380
    .line 381
    move-result-object v5

    .line 382
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 383
    .line 384
    .line 385
    move-result v4

    .line 386
    if-nez v4, :cond_a

    .line 387
    .line 388
    :cond_9
    invoke-static {v1, p1, v1, v0}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 389
    .line 390
    .line 391
    :cond_a
    sget-object v0, Lv3/j;->d:Lv3/h;

    .line 392
    .line 393
    invoke-static {v0, p2, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 394
    .line 395
    .line 396
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 397
    .line 398
    .line 399
    move-result-object p2

    .line 400
    invoke-virtual {p0, v3, p1, p2}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 401
    .line 402
    .line 403
    invoke-virtual {p1, v8}, Ll2/t;->q(Z)V

    .line 404
    .line 405
    .line 406
    goto :goto_4

    .line 407
    :cond_b
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 408
    .line 409
    .line 410
    :goto_4
    return-object v6

    .line 411
    :pswitch_5
    check-cast p1, Ll2/o;

    .line 412
    .line 413
    check-cast p2, Ljava/lang/Number;

    .line 414
    .line 415
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 416
    .line 417
    .line 418
    move-result p2

    .line 419
    check-cast p0, Lcom/google/firebase/messaging/w;

    .line 420
    .line 421
    and-int/lit8 v0, p2, 0x3

    .line 422
    .line 423
    if-eq v0, v7, :cond_c

    .line 424
    .line 425
    move v0, v8

    .line 426
    goto :goto_5

    .line 427
    :cond_c
    move v0, v9

    .line 428
    :goto_5
    and-int/2addr p2, v8

    .line 429
    check-cast p1, Ll2/t;

    .line 430
    .line 431
    invoke-virtual {p1, p2, v0}, Ll2/t;->O(IZ)Z

    .line 432
    .line 433
    .line 434
    move-result p2

    .line 435
    if-eqz p2, :cond_12

    .line 436
    .line 437
    const p2, 0x7f1205b2

    .line 438
    .line 439
    .line 440
    invoke-static {p1, p2}, Li2/a1;->k(Ll2/o;I)Ljava/lang/String;

    .line 441
    .line 442
    .line 443
    move-result-object p2

    .line 444
    iget-object v0, p0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 445
    .line 446
    check-cast v0, Lx2/s;

    .line 447
    .line 448
    sget v2, Lh2/j;->a:F

    .line 449
    .line 450
    sget v3, Lh2/j;->b:F

    .line 451
    .line 452
    const/16 v4, 0xa

    .line 453
    .line 454
    invoke-static {v0, v2, v1, v3, v4}, Landroidx/compose/foundation/layout/d;->q(Lx2/s;FFFI)Lx2/s;

    .line 455
    .line 456
    .line 457
    move-result-object v0

    .line 458
    invoke-virtual {p1, p2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 459
    .line 460
    .line 461
    move-result v1

    .line 462
    invoke-virtual {p1}, Ll2/t;->L()Ljava/lang/Object;

    .line 463
    .line 464
    .line 465
    move-result-object v2

    .line 466
    if-nez v1, :cond_d

    .line 467
    .line 468
    sget-object v1, Ll2/n;->a:Ll2/x0;

    .line 469
    .line 470
    if-ne v2, v1, :cond_e

    .line 471
    .line 472
    :cond_d
    new-instance v2, Lac0/r;

    .line 473
    .line 474
    const/16 v1, 0x12

    .line 475
    .line 476
    invoke-direct {v2, p2, v1}, Lac0/r;-><init>(Ljava/lang/String;I)V

    .line 477
    .line 478
    .line 479
    invoke-virtual {p1, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 480
    .line 481
    .line 482
    :cond_e
    check-cast v2, Lay0/k;

    .line 483
    .line 484
    invoke-static {v5, v9, v2}, Ld4/n;->b(Lx2/s;ZLay0/k;)Lx2/s;

    .line 485
    .line 486
    .line 487
    move-result-object p2

    .line 488
    invoke-interface {v0, p2}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 489
    .line 490
    .line 491
    move-result-object p2

    .line 492
    sget-object v0, Lx2/c;->d:Lx2/j;

    .line 493
    .line 494
    invoke-static {v0, v8}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 495
    .line 496
    .line 497
    move-result-object v0

    .line 498
    iget-wide v1, p1, Ll2/t;->T:J

    .line 499
    .line 500
    invoke-static {v1, v2}, Ljava/lang/Long;->hashCode(J)I

    .line 501
    .line 502
    .line 503
    move-result v1

    .line 504
    invoke-virtual {p1}, Ll2/t;->m()Ll2/p1;

    .line 505
    .line 506
    .line 507
    move-result-object v2

    .line 508
    invoke-static {p1, p2}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 509
    .line 510
    .line 511
    move-result-object p2

    .line 512
    sget-object v3, Lv3/k;->m1:Lv3/j;

    .line 513
    .line 514
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 515
    .line 516
    .line 517
    sget-object v3, Lv3/j;->b:Lv3/i;

    .line 518
    .line 519
    invoke-virtual {p1}, Ll2/t;->c0()V

    .line 520
    .line 521
    .line 522
    iget-boolean v4, p1, Ll2/t;->S:Z

    .line 523
    .line 524
    if-eqz v4, :cond_f

    .line 525
    .line 526
    invoke-virtual {p1, v3}, Ll2/t;->l(Lay0/a;)V

    .line 527
    .line 528
    .line 529
    goto :goto_6

    .line 530
    :cond_f
    invoke-virtual {p1}, Ll2/t;->m0()V

    .line 531
    .line 532
    .line 533
    :goto_6
    sget-object v3, Lv3/j;->g:Lv3/h;

    .line 534
    .line 535
    invoke-static {v3, v0, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 536
    .line 537
    .line 538
    sget-object v0, Lv3/j;->f:Lv3/h;

    .line 539
    .line 540
    invoke-static {v0, v2, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 541
    .line 542
    .line 543
    sget-object v0, Lv3/j;->j:Lv3/h;

    .line 544
    .line 545
    iget-boolean v2, p1, Ll2/t;->S:Z

    .line 546
    .line 547
    if-nez v2, :cond_10

    .line 548
    .line 549
    invoke-virtual {p1}, Ll2/t;->L()Ljava/lang/Object;

    .line 550
    .line 551
    .line 552
    move-result-object v2

    .line 553
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 554
    .line 555
    .line 556
    move-result-object v3

    .line 557
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 558
    .line 559
    .line 560
    move-result v2

    .line 561
    if-nez v2, :cond_11

    .line 562
    .line 563
    :cond_10
    invoke-static {v1, p1, v1, v0}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 564
    .line 565
    .line 566
    :cond_11
    sget-object v0, Lv3/j;->d:Lv3/h;

    .line 567
    .line 568
    invoke-static {v0, p2, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 569
    .line 570
    .line 571
    iget-object p0, p0, Lcom/google/firebase/messaging/w;->h:Ljava/lang/Object;

    .line 572
    .line 573
    check-cast p0, Lt2/b;

    .line 574
    .line 575
    invoke-static {v9, p0, p1, v8}, Lia/b;->r(ILt2/b;Ll2/t;Z)V

    .line 576
    .line 577
    .line 578
    goto :goto_7

    .line 579
    :cond_12
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 580
    .line 581
    .line 582
    :goto_7
    return-object v6

    .line 583
    :pswitch_6
    check-cast p1, Ll2/o;

    .line 584
    .line 585
    check-cast p2, Ljava/lang/Number;

    .line 586
    .line 587
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 588
    .line 589
    .line 590
    move-result p2

    .line 591
    and-int/lit8 v0, p2, 0x3

    .line 592
    .line 593
    if-eq v0, v7, :cond_13

    .line 594
    .line 595
    move v0, v8

    .line 596
    goto :goto_8

    .line 597
    :cond_13
    move v0, v9

    .line 598
    :goto_8
    and-int/2addr p2, v8

    .line 599
    check-cast p1, Ll2/t;

    .line 600
    .line 601
    invoke-virtual {p1, p2, v0}, Ll2/t;->O(IZ)Z

    .line 602
    .line 603
    .line 604
    move-result p2

    .line 605
    if-eqz p2, :cond_14

    .line 606
    .line 607
    check-cast p0, Lp31/c;

    .line 608
    .line 609
    iget-boolean p2, p0, Lp31/c;->e:Z

    .line 610
    .line 611
    invoke-static {p0, p2, p1, v9}, Ljp/xc;->b(Lp31/c;ZLl2/o;I)V

    .line 612
    .line 613
    .line 614
    goto :goto_9

    .line 615
    :cond_14
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 616
    .line 617
    .line 618
    :goto_9
    return-object v6

    .line 619
    :pswitch_7
    check-cast p1, Ll2/o;

    .line 620
    .line 621
    check-cast p2, Ljava/lang/Number;

    .line 622
    .line 623
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 624
    .line 625
    .line 626
    move-result p2

    .line 627
    check-cast p0, Lth/a;

    .line 628
    .line 629
    and-int/lit8 v0, p2, 0x3

    .line 630
    .line 631
    if-eq v0, v7, :cond_15

    .line 632
    .line 633
    move v0, v8

    .line 634
    goto :goto_a

    .line 635
    :cond_15
    move v0, v9

    .line 636
    :goto_a
    and-int/2addr p2, v8

    .line 637
    check-cast p1, Ll2/t;

    .line 638
    .line 639
    invoke-virtual {p1, p2, v0}, Ll2/t;->O(IZ)Z

    .line 640
    .line 641
    .line 642
    move-result p2

    .line 643
    if-eqz p2, :cond_16

    .line 644
    .line 645
    iget-object p2, p0, Lth/a;->a:Ljava/lang/String;

    .line 646
    .line 647
    invoke-static {p2, p1, v9}, Lal/a;->q(Ljava/lang/String;Ll2/o;I)V

    .line 648
    .line 649
    .line 650
    const/4 p2, 0x4

    .line 651
    int-to-float p2, p2

    .line 652
    invoke-static {v5, p2}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 653
    .line 654
    .line 655
    move-result-object p2

    .line 656
    invoke-static {p1, p2}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 657
    .line 658
    .line 659
    iget-object p0, p0, Lth/a;->b:Ljava/lang/String;

    .line 660
    .line 661
    invoke-static {p0, p1, v9}, Lal/a;->p(Ljava/lang/String;Ll2/o;I)V

    .line 662
    .line 663
    .line 664
    goto :goto_b

    .line 665
    :cond_16
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 666
    .line 667
    .line 668
    :goto_b
    return-object v6

    .line 669
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
