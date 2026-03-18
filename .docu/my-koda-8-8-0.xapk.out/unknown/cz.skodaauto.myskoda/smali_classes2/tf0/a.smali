.class public final synthetic Ltf0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Ltf0/a;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(II)V
    .locals 0

    .line 2
    iput p2, p0, Ltf0/a;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 13

    .line 1
    iget p0, p0, Ltf0/a;->d:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lu2/b;

    .line 7
    .line 8
    check-cast p2, Luu/g;

    .line 9
    .line 10
    const-string p0, "$this$Saver"

    .line 11
    .line 12
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    const-string p0, "it"

    .line 16
    .line 17
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    invoke-virtual {p2}, Luu/g;->d()Lcom/google/android/gms/maps/model/CameraPosition;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    return-object p0

    .line 25
    :pswitch_0
    check-cast p1, Lk21/a;

    .line 26
    .line 27
    check-cast p2, Lg21/a;

    .line 28
    .line 29
    const-string p0, "$this$single"

    .line 30
    .line 31
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    const-string p0, "it"

    .line 35
    .line 36
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    new-instance p0, Ltm0/c;

    .line 40
    .line 41
    sget-object p2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 42
    .line 43
    const-class v0, Lxl0/f;

    .line 44
    .line 45
    invoke-virtual {p2, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 46
    .line 47
    .line 48
    move-result-object v0

    .line 49
    const/4 v1, 0x0

    .line 50
    invoke-virtual {p1, v0, v1, v1}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    move-result-object v0

    .line 54
    check-cast v0, Lxl0/f;

    .line 55
    .line 56
    const-class v2, Lcz/myskoda/api/bff/v1/VehicleInformationApi;

    .line 57
    .line 58
    const-string v3, "null"

    .line 59
    .line 60
    invoke-static {p2, v2, v3}, Lia/b;->f(Lkotlin/jvm/internal/h0;Ljava/lang/Class;Ljava/lang/String;)Lh21/b;

    .line 61
    .line 62
    .line 63
    move-result-object v2

    .line 64
    const-class v3, Lti0/a;

    .line 65
    .line 66
    invoke-virtual {p2, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 67
    .line 68
    .line 69
    move-result-object p2

    .line 70
    invoke-virtual {p1, p2, v2, v1}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object p1

    .line 74
    check-cast p1, Lti0/a;

    .line 75
    .line 76
    invoke-direct {p0, v0, p1}, Ltm0/c;-><init>(Lxl0/f;Lti0/a;)V

    .line 77
    .line 78
    .line 79
    return-object p0

    .line 80
    :pswitch_1
    check-cast p1, Ll2/o;

    .line 81
    .line 82
    check-cast p2, Ljava/lang/Integer;

    .line 83
    .line 84
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 85
    .line 86
    .line 87
    const/4 p0, 0x7

    .line 88
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 89
    .line 90
    .line 91
    move-result p0

    .line 92
    invoke-static {p1, p0}, Luk/a;->d(Ll2/o;I)V

    .line 93
    .line 94
    .line 95
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 96
    .line 97
    return-object p0

    .line 98
    :pswitch_2
    check-cast p1, Ll2/o;

    .line 99
    .line 100
    check-cast p2, Ljava/lang/Integer;

    .line 101
    .line 102
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 103
    .line 104
    .line 105
    const/4 p0, 0x1

    .line 106
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 107
    .line 108
    .line 109
    move-result p0

    .line 110
    invoke-static {p1, p0}, Luk/a;->c(Ll2/o;I)V

    .line 111
    .line 112
    .line 113
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 114
    .line 115
    return-object p0

    .line 116
    :pswitch_3
    check-cast p1, Ll2/o;

    .line 117
    .line 118
    check-cast p2, Ljava/lang/Integer;

    .line 119
    .line 120
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 121
    .line 122
    .line 123
    const/4 p0, 0x1

    .line 124
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 125
    .line 126
    .line 127
    move-result p0

    .line 128
    invoke-static {p1, p0}, Lu80/a;->a(Ll2/o;I)V

    .line 129
    .line 130
    .line 131
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 132
    .line 133
    return-object p0

    .line 134
    :pswitch_4
    check-cast p1, Ll2/o;

    .line 135
    .line 136
    check-cast p2, Ljava/lang/Integer;

    .line 137
    .line 138
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 139
    .line 140
    .line 141
    const/4 p0, 0x1

    .line 142
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 143
    .line 144
    .line 145
    move-result p0

    .line 146
    invoke-static {p1, p0}, Lu80/a;->b(Ll2/o;I)V

    .line 147
    .line 148
    .line 149
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 150
    .line 151
    return-object p0

    .line 152
    :pswitch_5
    check-cast p1, Ll2/o;

    .line 153
    .line 154
    check-cast p2, Ljava/lang/Integer;

    .line 155
    .line 156
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 157
    .line 158
    .line 159
    const/4 p0, 0x1

    .line 160
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 161
    .line 162
    .line 163
    move-result p0

    .line 164
    invoke-static {p1, p0}, Lu80/a;->d(Ll2/o;I)V

    .line 165
    .line 166
    .line 167
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 168
    .line 169
    return-object p0

    .line 170
    :pswitch_6
    check-cast p1, Ll2/o;

    .line 171
    .line 172
    check-cast p2, Ljava/lang/Integer;

    .line 173
    .line 174
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 175
    .line 176
    .line 177
    const/4 p0, 0x1

    .line 178
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 179
    .line 180
    .line 181
    move-result p0

    .line 182
    invoke-static {p1, p0}, Lu80/a;->c(Ll2/o;I)V

    .line 183
    .line 184
    .line 185
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 186
    .line 187
    return-object p0

    .line 188
    :pswitch_7
    check-cast p1, Ll2/o;

    .line 189
    .line 190
    check-cast p2, Ljava/lang/Integer;

    .line 191
    .line 192
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 193
    .line 194
    .line 195
    const/4 p0, 0x1

    .line 196
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 197
    .line 198
    .line 199
    move-result p0

    .line 200
    invoke-static {p1, p0}, Lu80/a;->c(Ll2/o;I)V

    .line 201
    .line 202
    .line 203
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 204
    .line 205
    return-object p0

    .line 206
    :pswitch_8
    check-cast p1, Ll2/o;

    .line 207
    .line 208
    check-cast p2, Ljava/lang/Integer;

    .line 209
    .line 210
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 211
    .line 212
    .line 213
    move-result p0

    .line 214
    and-int/lit8 p2, p0, 0x3

    .line 215
    .line 216
    const/4 v0, 0x0

    .line 217
    const/4 v1, 0x1

    .line 218
    const/4 v2, 0x2

    .line 219
    if-eq p2, v2, :cond_0

    .line 220
    .line 221
    move p2, v1

    .line 222
    goto :goto_0

    .line 223
    :cond_0
    move p2, v0

    .line 224
    :goto_0
    and-int/2addr p0, v1

    .line 225
    check-cast p1, Ll2/t;

    .line 226
    .line 227
    invoke-virtual {p1, p0, p2}, Ll2/t;->O(IZ)Z

    .line 228
    .line 229
    .line 230
    move-result p0

    .line 231
    if-eqz p0, :cond_4

    .line 232
    .line 233
    sget-object p0, Lk1/j;->c:Lk1/e;

    .line 234
    .line 235
    sget-object p2, Lx2/c;->p:Lx2/h;

    .line 236
    .line 237
    invoke-static {p0, p2, p1, v0}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 238
    .line 239
    .line 240
    move-result-object p0

    .line 241
    iget-wide v3, p1, Ll2/t;->T:J

    .line 242
    .line 243
    invoke-static {v3, v4}, Ljava/lang/Long;->hashCode(J)I

    .line 244
    .line 245
    .line 246
    move-result p2

    .line 247
    invoke-virtual {p1}, Ll2/t;->m()Ll2/p1;

    .line 248
    .line 249
    .line 250
    move-result-object v3

    .line 251
    sget-object v4, Lx2/p;->b:Lx2/p;

    .line 252
    .line 253
    invoke-static {p1, v4}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 254
    .line 255
    .line 256
    move-result-object v4

    .line 257
    sget-object v5, Lv3/k;->m1:Lv3/j;

    .line 258
    .line 259
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 260
    .line 261
    .line 262
    sget-object v5, Lv3/j;->b:Lv3/i;

    .line 263
    .line 264
    invoke-virtual {p1}, Ll2/t;->c0()V

    .line 265
    .line 266
    .line 267
    iget-boolean v6, p1, Ll2/t;->S:Z

    .line 268
    .line 269
    if-eqz v6, :cond_1

    .line 270
    .line 271
    invoke-virtual {p1, v5}, Ll2/t;->l(Lay0/a;)V

    .line 272
    .line 273
    .line 274
    goto :goto_1

    .line 275
    :cond_1
    invoke-virtual {p1}, Ll2/t;->m0()V

    .line 276
    .line 277
    .line 278
    :goto_1
    sget-object v5, Lv3/j;->g:Lv3/h;

    .line 279
    .line 280
    invoke-static {v5, p0, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 281
    .line 282
    .line 283
    sget-object p0, Lv3/j;->f:Lv3/h;

    .line 284
    .line 285
    invoke-static {p0, v3, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 286
    .line 287
    .line 288
    sget-object p0, Lv3/j;->j:Lv3/h;

    .line 289
    .line 290
    iget-boolean v3, p1, Ll2/t;->S:Z

    .line 291
    .line 292
    if-nez v3, :cond_2

    .line 293
    .line 294
    invoke-virtual {p1}, Ll2/t;->L()Ljava/lang/Object;

    .line 295
    .line 296
    .line 297
    move-result-object v3

    .line 298
    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 299
    .line 300
    .line 301
    move-result-object v5

    .line 302
    invoke-static {v3, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 303
    .line 304
    .line 305
    move-result v3

    .line 306
    if-nez v3, :cond_3

    .line 307
    .line 308
    :cond_2
    invoke-static {p2, p1, p2, p0}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 309
    .line 310
    .line 311
    :cond_3
    sget-object p0, Lv3/j;->d:Lv3/h;

    .line 312
    .line 313
    invoke-static {p0, v4, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 314
    .line 315
    .line 316
    new-instance p0, Lt80/d;

    .line 317
    .line 318
    new-instance p2, Lt80/a;

    .line 319
    .line 320
    const-string v3, "Charge faster - Active"

    .line 321
    .line 322
    const-string v4, "Valid until 21. 12. 2025"

    .line 323
    .line 324
    invoke-direct {p2, v3, v4}, Lt80/a;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 325
    .line 326
    .line 327
    const/4 v3, 0x3

    .line 328
    invoke-direct {p0, p2, v3}, Lt80/d;-><init>(Lkp/q9;I)V

    .line 329
    .line 330
    .line 331
    const/4 p2, 0x0

    .line 332
    invoke-static {p0, p2, p1, v0, v2}, Lu80/a;->e(Lt80/d;Lay0/a;Ll2/o;II)V

    .line 333
    .line 334
    .line 335
    invoke-virtual {p1, v1}, Ll2/t;->q(Z)V

    .line 336
    .line 337
    .line 338
    goto :goto_2

    .line 339
    :cond_4
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 340
    .line 341
    .line 342
    :goto_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 343
    .line 344
    return-object p0

    .line 345
    :pswitch_9
    check-cast p1, Ll2/o;

    .line 346
    .line 347
    check-cast p2, Ljava/lang/Integer;

    .line 348
    .line 349
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 350
    .line 351
    .line 352
    const/4 p0, 0x1

    .line 353
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 354
    .line 355
    .line 356
    move-result p0

    .line 357
    invoke-static {p1, p0}, Llp/d1;->a(Ll2/o;I)V

    .line 358
    .line 359
    .line 360
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 361
    .line 362
    return-object p0

    .line 363
    :pswitch_a
    check-cast p1, Lu2/b;

    .line 364
    .line 365
    return-object p2

    .line 366
    :pswitch_b
    check-cast p1, Lu2/b;

    .line 367
    .line 368
    check-cast p2, Lu2/e;

    .line 369
    .line 370
    iget-object p0, p2, Lu2/e;->d:Ljava/util/Map;

    .line 371
    .line 372
    iget-object p1, p2, Lu2/e;->e:Landroidx/collection/q0;

    .line 373
    .line 374
    iget-object p2, p1, Landroidx/collection/q0;->b:[Ljava/lang/Object;

    .line 375
    .line 376
    iget-object v0, p1, Landroidx/collection/q0;->c:[Ljava/lang/Object;

    .line 377
    .line 378
    iget-object p1, p1, Landroidx/collection/q0;->a:[J

    .line 379
    .line 380
    array-length v1, p1

    .line 381
    add-int/lit8 v1, v1, -0x2

    .line 382
    .line 383
    if-ltz v1, :cond_9

    .line 384
    .line 385
    const/4 v2, 0x0

    .line 386
    move v3, v2

    .line 387
    :goto_3
    aget-wide v4, p1, v3

    .line 388
    .line 389
    not-long v6, v4

    .line 390
    const/4 v8, 0x7

    .line 391
    shl-long/2addr v6, v8

    .line 392
    and-long/2addr v6, v4

    .line 393
    const-wide v8, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 394
    .line 395
    .line 396
    .line 397
    .line 398
    and-long/2addr v6, v8

    .line 399
    cmp-long v6, v6, v8

    .line 400
    .line 401
    if-eqz v6, :cond_8

    .line 402
    .line 403
    sub-int v6, v3, v1

    .line 404
    .line 405
    not-int v6, v6

    .line 406
    ushr-int/lit8 v6, v6, 0x1f

    .line 407
    .line 408
    const/16 v7, 0x8

    .line 409
    .line 410
    rsub-int/lit8 v6, v6, 0x8

    .line 411
    .line 412
    move v8, v2

    .line 413
    :goto_4
    if-ge v8, v6, :cond_7

    .line 414
    .line 415
    const-wide/16 v9, 0xff

    .line 416
    .line 417
    and-long/2addr v9, v4

    .line 418
    const-wide/16 v11, 0x80

    .line 419
    .line 420
    cmp-long v9, v9, v11

    .line 421
    .line 422
    if-gez v9, :cond_6

    .line 423
    .line 424
    shl-int/lit8 v9, v3, 0x3

    .line 425
    .line 426
    add-int/2addr v9, v8

    .line 427
    aget-object v10, p2, v9

    .line 428
    .line 429
    aget-object v9, v0, v9

    .line 430
    .line 431
    check-cast v9, Lu2/g;

    .line 432
    .line 433
    invoke-interface {v9}, Lu2/g;->e()Ljava/util/Map;

    .line 434
    .line 435
    .line 436
    move-result-object v9

    .line 437
    invoke-interface {v9}, Ljava/util/Map;->isEmpty()Z

    .line 438
    .line 439
    .line 440
    move-result v11

    .line 441
    if-eqz v11, :cond_5

    .line 442
    .line 443
    invoke-interface {p0, v10}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 444
    .line 445
    .line 446
    goto :goto_5

    .line 447
    :cond_5
    invoke-interface {p0, v10, v9}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 448
    .line 449
    .line 450
    :cond_6
    :goto_5
    shr-long/2addr v4, v7

    .line 451
    add-int/lit8 v8, v8, 0x1

    .line 452
    .line 453
    goto :goto_4

    .line 454
    :cond_7
    if-ne v6, v7, :cond_9

    .line 455
    .line 456
    :cond_8
    if-eq v3, v1, :cond_9

    .line 457
    .line 458
    add-int/lit8 v3, v3, 0x1

    .line 459
    .line 460
    goto :goto_3

    .line 461
    :cond_9
    invoke-interface {p0}, Ljava/util/Map;->isEmpty()Z

    .line 462
    .line 463
    .line 464
    move-result p1

    .line 465
    if-eqz p1, :cond_a

    .line 466
    .line 467
    const/4 p0, 0x0

    .line 468
    :cond_a
    return-object p0

    .line 469
    :pswitch_c
    check-cast p1, Lu2/b;

    .line 470
    .line 471
    check-cast p2, Ll2/b1;

    .line 472
    .line 473
    instance-of p0, p2, Lv2/m;

    .line 474
    .line 475
    if-eqz p0, :cond_c

    .line 476
    .line 477
    check-cast p2, Lv2/m;

    .line 478
    .line 479
    invoke-interface {p2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 480
    .line 481
    .line 482
    move-result-object p0

    .line 483
    sget-object v0, Ll4/v;->d:Lu2/l;

    .line 484
    .line 485
    iget-object v0, v0, Lu2/l;->a:Lay0/n;

    .line 486
    .line 487
    invoke-interface {v0, p1, p0}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 488
    .line 489
    .line 490
    move-result-object p0

    .line 491
    if-eqz p0, :cond_b

    .line 492
    .line 493
    invoke-interface {p2}, Lv2/m;->l()Ll2/n2;

    .line 494
    .line 495
    .line 496
    move-result-object p1

    .line 497
    const-string p2, "null cannot be cast to non-null type androidx.compose.runtime.SnapshotMutationPolicy<kotlin.Any?>"

    .line 498
    .line 499
    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 500
    .line 501
    .line 502
    new-instance p2, Ll2/j1;

    .line 503
    .line 504
    invoke-direct {p2, p0, p1}, Ll2/j1;-><init>(Ljava/lang/Object;Ll2/n2;)V

    .line 505
    .line 506
    .line 507
    goto :goto_6

    .line 508
    :cond_b
    const/4 p2, 0x0

    .line 509
    :goto_6
    return-object p2

    .line 510
    :cond_c
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 511
    .line 512
    const-string p1, "If you use a custom MutableState implementation you have to write a custom Saver and pass it as a saver param to rememberSaveable()"

    .line 513
    .line 514
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 515
    .line 516
    .line 517
    throw p0

    .line 518
    :pswitch_d
    check-cast p1, Lty0/a;

    .line 519
    .line 520
    check-cast p2, Lty0/a;

    .line 521
    .line 522
    const-string p0, "<unused var>"

    .line 523
    .line 524
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 525
    .line 526
    .line 527
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 528
    .line 529
    .line 530
    sget-object p0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 531
    .line 532
    return-object p0

    .line 533
    :pswitch_e
    check-cast p1, Lty0/a;

    .line 534
    .line 535
    check-cast p2, Lty0/a;

    .line 536
    .line 537
    const-string p0, "<unused var>"

    .line 538
    .line 539
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 540
    .line 541
    .line 542
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 543
    .line 544
    .line 545
    sget-object p0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 546
    .line 547
    return-object p0

    .line 548
    :pswitch_f
    check-cast p1, Lty0/a;

    .line 549
    .line 550
    check-cast p2, Lty0/a;

    .line 551
    .line 552
    const-string p0, "<unused var>"

    .line 553
    .line 554
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 555
    .line 556
    .line 557
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 558
    .line 559
    .line 560
    sget-object p0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 561
    .line 562
    return-object p0

    .line 563
    :pswitch_10
    check-cast p1, Lty0/a;

    .line 564
    .line 565
    check-cast p2, Lty0/a;

    .line 566
    .line 567
    const-string p0, "<unused var>"

    .line 568
    .line 569
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 570
    .line 571
    .line 572
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 573
    .line 574
    .line 575
    sget-object p0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 576
    .line 577
    return-object p0

    .line 578
    :pswitch_11
    check-cast p1, Lk21/a;

    .line 579
    .line 580
    check-cast p2, Lg21/a;

    .line 581
    .line 582
    const-string p0, "$this$scopedViewModel"

    .line 583
    .line 584
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 585
    .line 586
    .line 587
    const-string p0, "it"

    .line 588
    .line 589
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 590
    .line 591
    .line 592
    new-instance v0, Lwk0/e0;

    .line 593
    .line 594
    sget-object p0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 595
    .line 596
    const-class p2, Lal0/w0;

    .line 597
    .line 598
    invoke-virtual {p0, p2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 599
    .line 600
    .line 601
    move-result-object p2

    .line 602
    const/4 v1, 0x0

    .line 603
    invoke-virtual {p1, p2, v1, v1}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 604
    .line 605
    .line 606
    move-result-object p2

    .line 607
    check-cast p2, Lal0/w0;

    .line 608
    .line 609
    const-class v2, Lal0/u0;

    .line 610
    .line 611
    invoke-virtual {p0, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 612
    .line 613
    .line 614
    move-result-object v2

    .line 615
    invoke-virtual {p1, v2, v1, v1}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 616
    .line 617
    .line 618
    move-result-object v2

    .line 619
    check-cast v2, Lal0/u0;

    .line 620
    .line 621
    const-class v3, Lcs0/l;

    .line 622
    .line 623
    invoke-virtual {p0, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 624
    .line 625
    .line 626
    move-result-object v3

    .line 627
    invoke-virtual {p1, v3, v1, v1}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 628
    .line 629
    .line 630
    move-result-object v3

    .line 631
    check-cast v3, Lcs0/l;

    .line 632
    .line 633
    const-class v4, Lij0/a;

    .line 634
    .line 635
    invoke-virtual {p0, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 636
    .line 637
    .line 638
    move-result-object v4

    .line 639
    invoke-virtual {p1, v4, v1, v1}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 640
    .line 641
    .line 642
    move-result-object v4

    .line 643
    check-cast v4, Lij0/a;

    .line 644
    .line 645
    const-class v5, Lal0/v0;

    .line 646
    .line 647
    invoke-virtual {p0, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 648
    .line 649
    .line 650
    move-result-object p0

    .line 651
    invoke-virtual {p1, p0, v1, v1}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 652
    .line 653
    .line 654
    move-result-object p0

    .line 655
    move-object v5, p0

    .line 656
    check-cast v5, Lal0/v0;

    .line 657
    .line 658
    move-object v1, p2

    .line 659
    invoke-direct/range {v0 .. v5}, Lwk0/e0;-><init>(Lal0/w0;Lal0/u0;Lcs0/l;Lij0/a;Lal0/v0;)V

    .line 660
    .line 661
    .line 662
    return-object v0

    .line 663
    :pswitch_12
    check-cast p1, Lk21/a;

    .line 664
    .line 665
    check-cast p2, Lg21/a;

    .line 666
    .line 667
    const-string p0, "$this$single"

    .line 668
    .line 669
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 670
    .line 671
    .line 672
    const-string p0, "it"

    .line 673
    .line 674
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 675
    .line 676
    .line 677
    new-instance p0, Lsk0/d;

    .line 678
    .line 679
    sget-object p2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 680
    .line 681
    const-class v0, Lxl0/f;

    .line 682
    .line 683
    invoke-virtual {p2, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 684
    .line 685
    .line 686
    move-result-object v0

    .line 687
    const/4 v1, 0x0

    .line 688
    invoke-virtual {p1, v0, v1, v1}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 689
    .line 690
    .line 691
    move-result-object v0

    .line 692
    check-cast v0, Lxl0/f;

    .line 693
    .line 694
    const-class v2, Lcz/myskoda/api/bff_maps/v3/MapsApi;

    .line 695
    .line 696
    const-string v3, "null"

    .line 697
    .line 698
    invoke-static {p2, v2, v3}, Lia/b;->f(Lkotlin/jvm/internal/h0;Ljava/lang/Class;Ljava/lang/String;)Lh21/b;

    .line 699
    .line 700
    .line 701
    move-result-object v2

    .line 702
    const-class v3, Lti0/a;

    .line 703
    .line 704
    invoke-virtual {p2, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 705
    .line 706
    .line 707
    move-result-object p2

    .line 708
    invoke-virtual {p1, p2, v2, v1}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 709
    .line 710
    .line 711
    move-result-object p1

    .line 712
    check-cast p1, Lti0/a;

    .line 713
    .line 714
    invoke-direct {p0, v0, p1}, Lsk0/d;-><init>(Lxl0/f;Lti0/a;)V

    .line 715
    .line 716
    .line 717
    return-object p0

    .line 718
    :pswitch_13
    check-cast p1, Lk21/a;

    .line 719
    .line 720
    check-cast p2, Lg21/a;

    .line 721
    .line 722
    const-string p0, "$this$single"

    .line 723
    .line 724
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 725
    .line 726
    .line 727
    const-string p0, "it"

    .line 728
    .line 729
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 730
    .line 731
    .line 732
    new-instance p0, Lsk0/f;

    .line 733
    .line 734
    sget-object p2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 735
    .line 736
    const-class v0, Lxl0/f;

    .line 737
    .line 738
    invoke-virtual {p2, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 739
    .line 740
    .line 741
    move-result-object v0

    .line 742
    const/4 v1, 0x0

    .line 743
    invoke-virtual {p1, v0, v1, v1}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 744
    .line 745
    .line 746
    move-result-object v0

    .line 747
    check-cast v0, Lxl0/f;

    .line 748
    .line 749
    const-class v2, Lcz/myskoda/api/bff_maps/v3/MapsApi;

    .line 750
    .line 751
    const-string v3, "null"

    .line 752
    .line 753
    invoke-static {p2, v2, v3}, Lia/b;->f(Lkotlin/jvm/internal/h0;Ljava/lang/Class;Ljava/lang/String;)Lh21/b;

    .line 754
    .line 755
    .line 756
    move-result-object v2

    .line 757
    const-class v3, Lti0/a;

    .line 758
    .line 759
    invoke-virtual {p2, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 760
    .line 761
    .line 762
    move-result-object p2

    .line 763
    invoke-virtual {p1, p2, v2, v1}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 764
    .line 765
    .line 766
    move-result-object p1

    .line 767
    check-cast p1, Lti0/a;

    .line 768
    .line 769
    invoke-direct {p0, v0, p1}, Lsk0/f;-><init>(Lxl0/f;Lti0/a;)V

    .line 770
    .line 771
    .line 772
    return-object p0

    .line 773
    :pswitch_14
    check-cast p1, Lk21/a;

    .line 774
    .line 775
    check-cast p2, Lg21/a;

    .line 776
    .line 777
    const-string p0, "$this$scopedSingle"

    .line 778
    .line 779
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 780
    .line 781
    .line 782
    const-string p0, "it"

    .line 783
    .line 784
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 785
    .line 786
    .line 787
    new-instance p0, Lsk0/b;

    .line 788
    .line 789
    invoke-direct {p0}, Lsk0/b;-><init>()V

    .line 790
    .line 791
    .line 792
    return-object p0

    .line 793
    :pswitch_15
    check-cast p1, Ll2/o;

    .line 794
    .line 795
    check-cast p2, Ljava/lang/Integer;

    .line 796
    .line 797
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 798
    .line 799
    .line 800
    move-result p0

    .line 801
    and-int/lit8 p2, p0, 0x3

    .line 802
    .line 803
    const/4 v0, 0x2

    .line 804
    const/4 v1, 0x0

    .line 805
    const/4 v2, 0x1

    .line 806
    if-eq p2, v0, :cond_d

    .line 807
    .line 808
    move p2, v2

    .line 809
    goto :goto_7

    .line 810
    :cond_d
    move p2, v1

    .line 811
    :goto_7
    and-int/2addr p0, v2

    .line 812
    check-cast p1, Ll2/t;

    .line 813
    .line 814
    invoke-virtual {p1, p0, p2}, Ll2/t;->O(IZ)Z

    .line 815
    .line 816
    .line 817
    move-result p0

    .line 818
    if-eqz p0, :cond_e

    .line 819
    .line 820
    invoke-static {v1, v2, p1, v1}, Lfc/a;->a(IILl2/o;Z)V

    .line 821
    .line 822
    .line 823
    goto :goto_8

    .line 824
    :cond_e
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 825
    .line 826
    .line 827
    :goto_8
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 828
    .line 829
    return-object p0

    .line 830
    :pswitch_16
    check-cast p1, Ll2/o;

    .line 831
    .line 832
    check-cast p2, Ljava/lang/Integer;

    .line 833
    .line 834
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 835
    .line 836
    .line 837
    move-result p0

    .line 838
    and-int/lit8 p2, p0, 0x3

    .line 839
    .line 840
    const/4 v0, 0x2

    .line 841
    const/4 v1, 0x0

    .line 842
    const/4 v2, 0x1

    .line 843
    if-eq p2, v0, :cond_f

    .line 844
    .line 845
    move p2, v2

    .line 846
    goto :goto_9

    .line 847
    :cond_f
    move p2, v1

    .line 848
    :goto_9
    and-int/2addr p0, v2

    .line 849
    check-cast p1, Ll2/t;

    .line 850
    .line 851
    invoke-virtual {p1, p0, p2}, Ll2/t;->O(IZ)Z

    .line 852
    .line 853
    .line 854
    move-result p0

    .line 855
    if-eqz p0, :cond_10

    .line 856
    .line 857
    const/4 p0, 0x0

    .line 858
    invoke-static {v1, v2, p0, p1}, Leh/a;->a(IILjava/lang/String;Ll2/o;)V

    .line 859
    .line 860
    .line 861
    goto :goto_a

    .line 862
    :cond_10
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 863
    .line 864
    .line 865
    :goto_a
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 866
    .line 867
    return-object p0

    .line 868
    :pswitch_17
    check-cast p1, Ll2/o;

    .line 869
    .line 870
    check-cast p2, Ljava/lang/Integer;

    .line 871
    .line 872
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 873
    .line 874
    .line 875
    move-result p0

    .line 876
    and-int/lit8 p2, p0, 0x3

    .line 877
    .line 878
    const/4 v0, 0x2

    .line 879
    const/4 v1, 0x0

    .line 880
    const/4 v2, 0x1

    .line 881
    if-eq p2, v0, :cond_11

    .line 882
    .line 883
    move p2, v2

    .line 884
    goto :goto_b

    .line 885
    :cond_11
    move p2, v1

    .line 886
    :goto_b
    and-int/2addr p0, v2

    .line 887
    check-cast p1, Ll2/t;

    .line 888
    .line 889
    invoke-virtual {p1, p0, p2}, Ll2/t;->O(IZ)Z

    .line 890
    .line 891
    .line 892
    move-result p0

    .line 893
    if-eqz p0, :cond_12

    .line 894
    .line 895
    invoke-static {p1, v1}, Lkp/v8;->a(Ll2/o;I)V

    .line 896
    .line 897
    .line 898
    goto :goto_c

    .line 899
    :cond_12
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 900
    .line 901
    .line 902
    :goto_c
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 903
    .line 904
    return-object p0

    .line 905
    :pswitch_18
    check-cast p1, Ll2/o;

    .line 906
    .line 907
    check-cast p2, Ljava/lang/Integer;

    .line 908
    .line 909
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 910
    .line 911
    .line 912
    move-result p0

    .line 913
    and-int/lit8 p2, p0, 0x3

    .line 914
    .line 915
    const/4 v0, 0x2

    .line 916
    const/4 v1, 0x0

    .line 917
    const/4 v2, 0x1

    .line 918
    if-eq p2, v0, :cond_13

    .line 919
    .line 920
    move p2, v2

    .line 921
    goto :goto_d

    .line 922
    :cond_13
    move p2, v1

    .line 923
    :goto_d
    and-int/2addr p0, v2

    .line 924
    check-cast p1, Ll2/t;

    .line 925
    .line 926
    invoke-virtual {p1, p0, p2}, Ll2/t;->O(IZ)Z

    .line 927
    .line 928
    .line 929
    move-result p0

    .line 930
    if-eqz p0, :cond_14

    .line 931
    .line 932
    invoke-static {p1, v1}, Llp/jb;->a(Ll2/o;I)V

    .line 933
    .line 934
    .line 935
    goto :goto_e

    .line 936
    :cond_14
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 937
    .line 938
    .line 939
    :goto_e
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 940
    .line 941
    return-object p0

    .line 942
    :pswitch_19
    check-cast p1, Ll2/o;

    .line 943
    .line 944
    check-cast p2, Ljava/lang/Integer;

    .line 945
    .line 946
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 947
    .line 948
    .line 949
    move-result p0

    .line 950
    and-int/lit8 p2, p0, 0x3

    .line 951
    .line 952
    const/4 v0, 0x2

    .line 953
    const/4 v1, 0x0

    .line 954
    const/4 v2, 0x1

    .line 955
    if-eq p2, v0, :cond_15

    .line 956
    .line 957
    move p2, v2

    .line 958
    goto :goto_f

    .line 959
    :cond_15
    move p2, v1

    .line 960
    :goto_f
    and-int/2addr p0, v2

    .line 961
    check-cast p1, Ll2/t;

    .line 962
    .line 963
    invoke-virtual {p1, p0, p2}, Ll2/t;->O(IZ)Z

    .line 964
    .line 965
    .line 966
    move-result p0

    .line 967
    if-eqz p0, :cond_16

    .line 968
    .line 969
    invoke-static {p1, v1}, Llp/of;->a(Ll2/o;I)V

    .line 970
    .line 971
    .line 972
    goto :goto_10

    .line 973
    :cond_16
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 974
    .line 975
    .line 976
    :goto_10
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 977
    .line 978
    return-object p0

    .line 979
    :pswitch_1a
    check-cast p1, Lk21/a;

    .line 980
    .line 981
    check-cast p2, Lg21/a;

    .line 982
    .line 983
    const-string p0, "$this$factory"

    .line 984
    .line 985
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 986
    .line 987
    .line 988
    const-string p0, "it"

    .line 989
    .line 990
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 991
    .line 992
    .line 993
    new-instance p0, Lsh0/b;

    .line 994
    .line 995
    const-class p2, Lrh0/f;

    .line 996
    .line 997
    sget-object v0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 998
    .line 999
    invoke-virtual {v0, p2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1000
    .line 1001
    .line 1002
    move-result-object p2

    .line 1003
    const/4 v0, 0x0

    .line 1004
    invoke-virtual {p1, p2, v0, v0}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1005
    .line 1006
    .line 1007
    move-result-object p1

    .line 1008
    check-cast p1, Lrh0/f;

    .line 1009
    .line 1010
    invoke-direct {p0, p1}, Lsh0/b;-><init>(Lrh0/f;)V

    .line 1011
    .line 1012
    .line 1013
    return-object p0

    .line 1014
    :pswitch_1b
    check-cast p1, Lk21/a;

    .line 1015
    .line 1016
    check-cast p2, Lg21/a;

    .line 1017
    .line 1018
    const-string p0, "$this$single"

    .line 1019
    .line 1020
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1021
    .line 1022
    .line 1023
    const-string p0, "it"

    .line 1024
    .line 1025
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1026
    .line 1027
    .line 1028
    new-instance p0, Lsg0/a;

    .line 1029
    .line 1030
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 1031
    .line 1032
    .line 1033
    return-object p0

    .line 1034
    :pswitch_1c
    check-cast p1, Lk21/a;

    .line 1035
    .line 1036
    check-cast p2, Lg21/a;

    .line 1037
    .line 1038
    const-string p0, "$this$single"

    .line 1039
    .line 1040
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1041
    .line 1042
    .line 1043
    const-string p0, "it"

    .line 1044
    .line 1045
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1046
    .line 1047
    .line 1048
    new-instance p0, Lxf0/a;

    .line 1049
    .line 1050
    sget-object p2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1051
    .line 1052
    const-class v0, Landroid/content/Context;

    .line 1053
    .line 1054
    invoke-virtual {p2, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1055
    .line 1056
    .line 1057
    move-result-object v1

    .line 1058
    const/4 v2, 0x0

    .line 1059
    invoke-virtual {p1, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1060
    .line 1061
    .line 1062
    move-result-object v1

    .line 1063
    check-cast v1, Landroid/content/Context;

    .line 1064
    .line 1065
    invoke-virtual {v1}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 1066
    .line 1067
    .line 1068
    move-result-object v1

    .line 1069
    const-string v3, "getResources(...)"

    .line 1070
    .line 1071
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1072
    .line 1073
    .line 1074
    invoke-virtual {p2, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1075
    .line 1076
    .line 1077
    move-result-object p2

    .line 1078
    invoke-virtual {p1, p2, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1079
    .line 1080
    .line 1081
    move-result-object p1

    .line 1082
    check-cast p1, Landroid/content/Context;

    .line 1083
    .line 1084
    invoke-virtual {p1}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 1085
    .line 1086
    .line 1087
    move-result-object p1

    .line 1088
    const-string p2, "getPackageName(...)"

    .line 1089
    .line 1090
    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1091
    .line 1092
    .line 1093
    invoke-direct {p0, v1, p1}, Lxf0/a;-><init>(Landroid/content/res/Resources;Ljava/lang/String;)V

    .line 1094
    .line 1095
    .line 1096
    return-object p0

    .line 1097
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
