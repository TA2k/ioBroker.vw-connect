.class public final La7/j;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Lay0/a;)V
    .locals 1

    const/16 v0, 0x1d

    iput v0, p0, La7/j;->f:I

    .line 1
    check-cast p1, Lkotlin/jvm/internal/k;

    iput-object p1, p0, La7/j;->g:Ljava/lang/Object;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 2
    iput p2, p0, La7/j;->f:I

    iput-object p1, p0, La7/j;->g:Ljava/lang/Object;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 20

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, La7/j;->f:I

    .line 4
    .line 5
    const/4 v2, 0x2

    .line 6
    const/4 v3, 0x7

    .line 7
    const/4 v4, 0x3

    .line 8
    const/4 v5, 0x0

    .line 9
    const/4 v6, 0x0

    .line 10
    const/4 v7, 0x1

    .line 11
    packed-switch v1, :pswitch_data_0

    .line 12
    .line 13
    .line 14
    iget-object v0, v0, La7/j;->g:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast v0, Lkotlin/jvm/internal/k;

    .line 17
    .line 18
    invoke-interface {v0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    return-object v0

    .line 23
    :pswitch_0
    iget-object v0, v0, La7/j;->g:Ljava/lang/Object;

    .line 24
    .line 25
    check-cast v0, Lx4/t;

    .line 26
    .line 27
    invoke-static {v0}, Lx4/t;->i(Lx4/t;)Lt3/y;

    .line 28
    .line 29
    .line 30
    move-result-object v1

    .line 31
    if-eqz v1, :cond_0

    .line 32
    .line 33
    invoke-interface {v1}, Lt3/y;->g()Z

    .line 34
    .line 35
    .line 36
    move-result v2

    .line 37
    if-eqz v2, :cond_0

    .line 38
    .line 39
    move-object v5, v1

    .line 40
    :cond_0
    if-eqz v5, :cond_1

    .line 41
    .line 42
    invoke-virtual {v0}, Lx4/t;->getPopupContentSize-bOM6tXw()Lt4/l;

    .line 43
    .line 44
    .line 45
    move-result-object v0

    .line 46
    if-eqz v0, :cond_1

    .line 47
    .line 48
    move v6, v7

    .line 49
    :cond_1
    invoke-static {v6}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 50
    .line 51
    .line 52
    move-result-object v0

    .line 53
    return-object v0

    .line 54
    :pswitch_1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 55
    .line 56
    return-object v0

    .line 57
    :pswitch_2
    iget-object v0, v0, La7/j;->g:Ljava/lang/Object;

    .line 58
    .line 59
    check-cast v0, Lw3/m0;

    .line 60
    .line 61
    iget-object v0, v0, Lw3/m0;->f:Lvy0/b0;

    .line 62
    .line 63
    invoke-static {v0, v5}, Lvy0/e0;->j(Lvy0/b0;Ljava/util/concurrent/CancellationException;)V

    .line 64
    .line 65
    .line 66
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 67
    .line 68
    return-object v0

    .line 69
    :pswitch_3
    iget-object v0, v0, La7/j;->g:Ljava/lang/Object;

    .line 70
    .line 71
    check-cast v0, Lvw/a;

    .line 72
    .line 73
    invoke-static {v0}, Lvw/a;->a(Lvw/a;)Landroid/content/res/Resources;

    .line 74
    .line 75
    .line 76
    move-result-object v0

    .line 77
    instance-of v1, v0, Lm/f2;

    .line 78
    .line 79
    if-eqz v1, :cond_2

    .line 80
    .line 81
    check-cast v0, Lm/f2;

    .line 82
    .line 83
    goto :goto_0

    .line 84
    :cond_2
    new-instance v1, Lm/f2;

    .line 85
    .line 86
    const-string v2, "s"

    .line 87
    .line 88
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 89
    .line 90
    .line 91
    invoke-direct {v1, v0}, Lm/f2;-><init>(Landroid/content/res/Resources;)V

    .line 92
    .line 93
    .line 94
    move-object v0, v1

    .line 95
    :goto_0
    return-object v0

    .line 96
    :pswitch_4
    iget-object v0, v0, La7/j;->g:Ljava/lang/Object;

    .line 97
    .line 98
    check-cast v0, Lay0/k;

    .line 99
    .line 100
    sget-object v1, Lv3/f1;->N:Le3/k0;

    .line 101
    .line 102
    invoke-interface {v0, v1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 103
    .line 104
    .line 105
    iget-object v0, v1, Le3/k0;->r:Le3/n0;

    .line 106
    .line 107
    iget-wide v2, v1, Le3/k0;->t:J

    .line 108
    .line 109
    iget-object v4, v1, Le3/k0;->v:Lt4/m;

    .line 110
    .line 111
    iget-object v5, v1, Le3/k0;->u:Lt4/c;

    .line 112
    .line 113
    invoke-interface {v0, v2, v3, v4, v5}, Le3/n0;->a(JLt4/m;Lt4/c;)Le3/g0;

    .line 114
    .line 115
    .line 116
    move-result-object v0

    .line 117
    iput-object v0, v1, Le3/k0;->y:Le3/g0;

    .line 118
    .line 119
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 120
    .line 121
    return-object v0

    .line 122
    :pswitch_5
    iget-object v0, v0, La7/j;->g:Ljava/lang/Object;

    .line 123
    .line 124
    check-cast v0, Lv3/h0;

    .line 125
    .line 126
    iget-object v0, v0, Lv3/h0;->I:Lv3/l0;

    .line 127
    .line 128
    iget-object v1, v0, Lv3/l0;->p:Lv3/y0;

    .line 129
    .line 130
    iput-boolean v7, v1, Lv3/y0;->D:Z

    .line 131
    .line 132
    iget-object v0, v0, Lv3/l0;->q:Lv3/u0;

    .line 133
    .line 134
    if-eqz v0, :cond_3

    .line 135
    .line 136
    iput-boolean v7, v0, Lv3/u0;->x:Z

    .line 137
    .line 138
    :cond_3
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 139
    .line 140
    return-object v0

    .line 141
    :pswitch_6
    new-instance v1, Ljava/lang/StringBuilder;

    .line 142
    .line 143
    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    .line 144
    .line 145
    .line 146
    iget-object v0, v0, La7/j;->g:Ljava/lang/Object;

    .line 147
    .line 148
    check-cast v0, Luw/b;

    .line 149
    .line 150
    iget-object v2, v0, Luw/b;->b:Ljava/lang/String;

    .line 151
    .line 152
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 153
    .line 154
    .line 155
    const/16 v2, 0x2d

    .line 156
    .line 157
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 158
    .line 159
    .line 160
    iget-object v3, v0, Luw/b;->a:Ljava/lang/String;

    .line 161
    .line 162
    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 163
    .line 164
    .line 165
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 166
    .line 167
    .line 168
    iget-object v0, v0, Luw/b;->f:Ljava/lang/String;

    .line 169
    .line 170
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 171
    .line 172
    .line 173
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 174
    .line 175
    .line 176
    move-result-object v0

    .line 177
    const-string v1, "s"

    .line 178
    .line 179
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 180
    .line 181
    .line 182
    const-string v1, "SHA-512"

    .line 183
    .line 184
    invoke-static {v1}, Ljava/security/MessageDigest;->getInstance(Ljava/lang/String;)Ljava/security/MessageDigest;

    .line 185
    .line 186
    .line 187
    move-result-object v1

    .line 188
    sget-object v2, Lly0/a;->a:Ljava/nio/charset/Charset;

    .line 189
    .line 190
    invoke-virtual {v0, v2}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    .line 191
    .line 192
    .line 193
    move-result-object v0

    .line 194
    const-string v2, "this as java.lang.String).getBytes(charset)"

    .line 195
    .line 196
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 197
    .line 198
    .line 199
    invoke-virtual {v1, v0}, Ljava/security/MessageDigest;->digest([B)[B

    .line 200
    .line 201
    .line 202
    move-result-object v0

    .line 203
    const-string v1, "digest"

    .line 204
    .line 205
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 206
    .line 207
    .line 208
    new-instance v1, Ljava/lang/StringBuilder;

    .line 209
    .line 210
    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    .line 211
    .line 212
    .line 213
    array-length v2, v0

    .line 214
    :goto_1
    if-ge v6, v2, :cond_4

    .line 215
    .line 216
    aget-byte v3, v0, v6

    .line 217
    .line 218
    invoke-static {v3}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 219
    .line 220
    .line 221
    move-result-object v3

    .line 222
    filled-new-array {v3}, [Ljava/lang/Object;

    .line 223
    .line 224
    .line 225
    move-result-object v3

    .line 226
    invoke-static {v3, v7}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 227
    .line 228
    .line 229
    move-result-object v3

    .line 230
    const-string v4, "%02x"

    .line 231
    .line 232
    invoke-static {v4, v3}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 233
    .line 234
    .line 235
    move-result-object v3

    .line 236
    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 237
    .line 238
    .line 239
    add-int/lit8 v6, v6, 0x1

    .line 240
    .line 241
    goto :goto_1

    .line 242
    :cond_4
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 243
    .line 244
    .line 245
    move-result-object v0

    .line 246
    const-string v1, "digest.fold(StringBuilde\u2026rmat(byte)) }).toString()"

    .line 247
    .line 248
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 249
    .line 250
    .line 251
    return-object v0

    .line 252
    :pswitch_7
    iget-object v0, v0, La7/j;->g:Ljava/lang/Object;

    .line 253
    .line 254
    check-cast v0, Lu3/d;

    .line 255
    .line 256
    iget-object v1, v0, Lu3/d;->c:Ln2/b;

    .line 257
    .line 258
    iget-object v2, v0, Lu3/d;->b:Ln2/b;

    .line 259
    .line 260
    iget-object v3, v0, Lu3/d;->e:Ln2/b;

    .line 261
    .line 262
    iput-boolean v6, v0, Lu3/d;->f:Z

    .line 263
    .line 264
    new-instance v4, Ljava/util/HashSet;

    .line 265
    .line 266
    invoke-direct {v4}, Ljava/util/HashSet;-><init>()V

    .line 267
    .line 268
    .line 269
    iget-object v0, v0, Lu3/d;->d:Ln2/b;

    .line 270
    .line 271
    iget-object v5, v0, Ln2/b;->d:[Ljava/lang/Object;

    .line 272
    .line 273
    iget v7, v0, Ln2/b;->f:I

    .line 274
    .line 275
    move v8, v6

    .line 276
    :goto_2
    if-ge v8, v7, :cond_6

    .line 277
    .line 278
    aget-object v9, v5, v8

    .line 279
    .line 280
    check-cast v9, Lv3/h0;

    .line 281
    .line 282
    iget-object v10, v3, Ln2/b;->d:[Ljava/lang/Object;

    .line 283
    .line 284
    aget-object v10, v10, v8

    .line 285
    .line 286
    check-cast v10, Lu3/h;

    .line 287
    .line 288
    iget-object v9, v9, Lv3/h0;->H:Lg1/q;

    .line 289
    .line 290
    iget-object v9, v9, Lg1/q;->g:Ljava/lang/Object;

    .line 291
    .line 292
    check-cast v9, Lx2/r;

    .line 293
    .line 294
    iget-boolean v11, v9, Lx2/r;->q:Z

    .line 295
    .line 296
    if-eqz v11, :cond_5

    .line 297
    .line 298
    invoke-static {v9, v10, v4}, Lu3/d;->b(Lx2/r;Lu3/h;Ljava/util/HashSet;)V

    .line 299
    .line 300
    .line 301
    :cond_5
    add-int/lit8 v8, v8, 0x1

    .line 302
    .line 303
    goto :goto_2

    .line 304
    :cond_6
    invoke-virtual {v0}, Ln2/b;->i()V

    .line 305
    .line 306
    .line 307
    invoke-virtual {v3}, Ln2/b;->i()V

    .line 308
    .line 309
    .line 310
    iget-object v0, v2, Ln2/b;->d:[Ljava/lang/Object;

    .line 311
    .line 312
    iget v3, v2, Ln2/b;->f:I

    .line 313
    .line 314
    :goto_3
    if-ge v6, v3, :cond_8

    .line 315
    .line 316
    aget-object v5, v0, v6

    .line 317
    .line 318
    check-cast v5, Lv3/c;

    .line 319
    .line 320
    iget-object v7, v1, Ln2/b;->d:[Ljava/lang/Object;

    .line 321
    .line 322
    aget-object v7, v7, v6

    .line 323
    .line 324
    check-cast v7, Lu3/h;

    .line 325
    .line 326
    iget-boolean v8, v5, Lx2/r;->q:Z

    .line 327
    .line 328
    if-eqz v8, :cond_7

    .line 329
    .line 330
    invoke-static {v5, v7, v4}, Lu3/d;->b(Lx2/r;Lu3/h;Ljava/util/HashSet;)V

    .line 331
    .line 332
    .line 333
    :cond_7
    add-int/lit8 v6, v6, 0x1

    .line 334
    .line 335
    goto :goto_3

    .line 336
    :cond_8
    invoke-virtual {v2}, Ln2/b;->i()V

    .line 337
    .line 338
    .line 339
    invoke-virtual {v1}, Ln2/b;->i()V

    .line 340
    .line 341
    .line 342
    invoke-virtual {v4}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    .line 343
    .line 344
    .line 345
    move-result-object v0

    .line 346
    :goto_4
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 347
    .line 348
    .line 349
    move-result v1

    .line 350
    if-eqz v1, :cond_9

    .line 351
    .line 352
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 353
    .line 354
    .line 355
    move-result-object v1

    .line 356
    check-cast v1, Lv3/c;

    .line 357
    .line 358
    invoke-virtual {v1}, Lv3/c;->Z0()V

    .line 359
    .line 360
    .line 361
    goto :goto_4

    .line 362
    :cond_9
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 363
    .line 364
    return-object v0

    .line 365
    :pswitch_8
    iget-object v0, v0, La7/j;->g:Ljava/lang/Object;

    .line 366
    .line 367
    check-cast v0, Lt3/o1;

    .line 368
    .line 369
    invoke-virtual {v0}, Lt3/o1;->a()Lt3/m0;

    .line 370
    .line 371
    .line 372
    move-result-object v0

    .line 373
    iget-object v1, v0, Lt3/m0;->d:Lv3/h0;

    .line 374
    .line 375
    invoke-virtual {v1}, Lv3/h0;->p()Ljava/util/List;

    .line 376
    .line 377
    .line 378
    move-result-object v4

    .line 379
    check-cast v4, Landroidx/collection/j0;

    .line 380
    .line 381
    iget-object v4, v4, Landroidx/collection/j0;->e:Ljava/lang/Object;

    .line 382
    .line 383
    check-cast v4, Ln2/b;

    .line 384
    .line 385
    iget v4, v4, Ln2/b;->f:I

    .line 386
    .line 387
    iget v5, v0, Lt3/m0;->q:I

    .line 388
    .line 389
    if-eq v5, v4, :cond_f

    .line 390
    .line 391
    iget-object v0, v0, Lt3/m0;->i:Landroidx/collection/q0;

    .line 392
    .line 393
    iget-object v4, v0, Landroidx/collection/q0;->c:[Ljava/lang/Object;

    .line 394
    .line 395
    iget-object v0, v0, Landroidx/collection/q0;->a:[J

    .line 396
    .line 397
    array-length v5, v0

    .line 398
    sub-int/2addr v5, v2

    .line 399
    if-ltz v5, :cond_d

    .line 400
    .line 401
    move v2, v6

    .line 402
    :goto_5
    aget-wide v8, v0, v2

    .line 403
    .line 404
    not-long v10, v8

    .line 405
    shl-long/2addr v10, v3

    .line 406
    and-long/2addr v10, v8

    .line 407
    const-wide v12, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 408
    .line 409
    .line 410
    .line 411
    .line 412
    and-long/2addr v10, v12

    .line 413
    cmp-long v10, v10, v12

    .line 414
    .line 415
    if-eqz v10, :cond_c

    .line 416
    .line 417
    sub-int v10, v2, v5

    .line 418
    .line 419
    not-int v10, v10

    .line 420
    ushr-int/lit8 v10, v10, 0x1f

    .line 421
    .line 422
    const/16 v11, 0x8

    .line 423
    .line 424
    rsub-int/lit8 v10, v10, 0x8

    .line 425
    .line 426
    move v12, v6

    .line 427
    :goto_6
    if-ge v12, v10, :cond_b

    .line 428
    .line 429
    const-wide/16 v13, 0xff

    .line 430
    .line 431
    and-long/2addr v13, v8

    .line 432
    const-wide/16 v15, 0x80

    .line 433
    .line 434
    cmp-long v13, v13, v15

    .line 435
    .line 436
    if-gez v13, :cond_a

    .line 437
    .line 438
    shl-int/lit8 v13, v2, 0x3

    .line 439
    .line 440
    add-int/2addr v13, v12

    .line 441
    aget-object v13, v4, v13

    .line 442
    .line 443
    check-cast v13, Lt3/f0;

    .line 444
    .line 445
    iput-boolean v7, v13, Lt3/f0;->d:Z

    .line 446
    .line 447
    :cond_a
    shr-long/2addr v8, v11

    .line 448
    add-int/lit8 v12, v12, 0x1

    .line 449
    .line 450
    goto :goto_6

    .line 451
    :cond_b
    if-ne v10, v11, :cond_d

    .line 452
    .line 453
    :cond_c
    if-eq v2, v5, :cond_d

    .line 454
    .line 455
    add-int/lit8 v2, v2, 0x1

    .line 456
    .line 457
    goto :goto_5

    .line 458
    :cond_d
    iget-object v0, v1, Lv3/h0;->j:Lv3/h0;

    .line 459
    .line 460
    if-eqz v0, :cond_e

    .line 461
    .line 462
    iget-object v0, v1, Lv3/h0;->I:Lv3/l0;

    .line 463
    .line 464
    iget-boolean v0, v0, Lv3/l0;->e:Z

    .line 465
    .line 466
    if-nez v0, :cond_f

    .line 467
    .line 468
    invoke-static {v1, v6, v3}, Lv3/h0;->W(Lv3/h0;ZI)V

    .line 469
    .line 470
    .line 471
    goto :goto_7

    .line 472
    :cond_e
    invoke-virtual {v1}, Lv3/h0;->r()Z

    .line 473
    .line 474
    .line 475
    move-result v0

    .line 476
    if-nez v0, :cond_f

    .line 477
    .line 478
    invoke-static {v1, v6, v3}, Lv3/h0;->Y(Lv3/h0;ZI)V

    .line 479
    .line 480
    .line 481
    :cond_f
    :goto_7
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 482
    .line 483
    return-object v0

    .line 484
    :pswitch_9
    iget-object v0, v0, La7/j;->g:Ljava/lang/Object;

    .line 485
    .line 486
    check-cast v0, Lt3/f0;

    .line 487
    .line 488
    iget-object v1, v0, Lt3/f0;->g:Ll2/j1;

    .line 489
    .line 490
    invoke-virtual {v1}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 491
    .line 492
    .line 493
    move-result-object v1

    .line 494
    check-cast v1, Ljava/lang/Boolean;

    .line 495
    .line 496
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 497
    .line 498
    .line 499
    move-result v1

    .line 500
    if-nez v1, :cond_10

    .line 501
    .line 502
    iget-object v0, v0, Lt3/f0;->c:Ll2/a0;

    .line 503
    .line 504
    if-eqz v0, :cond_10

    .line 505
    .line 506
    invoke-virtual {v0}, Ll2/a0;->l()V

    .line 507
    .line 508
    .line 509
    :cond_10
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 510
    .line 511
    return-object v0

    .line 512
    :pswitch_a
    iget-object v0, v0, La7/j;->g:Ljava/lang/Object;

    .line 513
    .line 514
    check-cast v0, Lay0/a;

    .line 515
    .line 516
    invoke-interface {v0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 517
    .line 518
    .line 519
    move-result-object v0

    .line 520
    check-cast v0, Ljava/io/File;

    .line 521
    .line 522
    const-string v1, "<this>"

    .line 523
    .line 524
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 525
    .line 526
    .line 527
    invoke-virtual {v0}, Ljava/io/File;->getName()Ljava/lang/String;

    .line 528
    .line 529
    .line 530
    move-result-object v1

    .line 531
    const-string v2, "getName(...)"

    .line 532
    .line 533
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 534
    .line 535
    .line 536
    const/16 v2, 0x2e

    .line 537
    .line 538
    const-string v3, ""

    .line 539
    .line 540
    invoke-static {v2, v1, v3}, Lly0/p;->e0(CLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 541
    .line 542
    .line 543
    move-result-object v1

    .line 544
    const-string v2, "preferences_pb"

    .line 545
    .line 546
    invoke-virtual {v1, v2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 547
    .line 548
    .line 549
    move-result v1

    .line 550
    if-eqz v1, :cond_11

    .line 551
    .line 552
    invoke-virtual {v0}, Ljava/io/File;->getAbsoluteFile()Ljava/io/File;

    .line 553
    .line 554
    .line 555
    move-result-object v0

    .line 556
    const-string v1, "file.absoluteFile"

    .line 557
    .line 558
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 559
    .line 560
    .line 561
    return-object v0

    .line 562
    :cond_11
    new-instance v1, Ljava/lang/StringBuilder;

    .line 563
    .line 564
    const-string v2, "File extension for file: "

    .line 565
    .line 566
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 567
    .line 568
    .line 569
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 570
    .line 571
    .line 572
    const-string v0, " does not match required extension for Preferences file: preferences_pb"

    .line 573
    .line 574
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 575
    .line 576
    .line 577
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 578
    .line 579
    .line 580
    move-result-object v0

    .line 581
    new-instance v1, Ljava/lang/IllegalStateException;

    .line 582
    .line 583
    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 584
    .line 585
    .line 586
    move-result-object v0

    .line 587
    invoke-direct {v1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 588
    .line 589
    .line 590
    throw v1

    .line 591
    :pswitch_b
    iget-object v0, v0, La7/j;->g:Ljava/lang/Object;

    .line 592
    .line 593
    check-cast v0, Lo3/g;

    .line 594
    .line 595
    invoke-virtual {v0}, Lo3/g;->X0()Lvy0/b0;

    .line 596
    .line 597
    .line 598
    move-result-object v0

    .line 599
    return-object v0

    .line 600
    :pswitch_c
    iget-object v0, v0, La7/j;->g:Ljava/lang/Object;

    .line 601
    .line 602
    check-cast v0, Lo3/d;

    .line 603
    .line 604
    iget-object v0, v0, Lo3/d;->d:Lvy0/b0;

    .line 605
    .line 606
    return-object v0

    .line 607
    :pswitch_d
    iget-object v0, v0, La7/j;->g:Ljava/lang/Object;

    .line 608
    .line 609
    check-cast v0, Lnn/t;

    .line 610
    .line 611
    iget-object v0, v0, Lnn/t;->b:Ll2/j1;

    .line 612
    .line 613
    invoke-virtual {v0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 614
    .line 615
    .line 616
    move-result-object v0

    .line 617
    check-cast v0, Lnn/i;

    .line 618
    .line 619
    return-object v0

    .line 620
    :pswitch_e
    iget-object v0, v0, La7/j;->g:Ljava/lang/Object;

    .line 621
    .line 622
    check-cast v0, Lvy0/r0;

    .line 623
    .line 624
    invoke-interface {v0}, Lvy0/r0;->dispose()V

    .line 625
    .line 626
    .line 627
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 628
    .line 629
    return-object v0

    .line 630
    :pswitch_f
    sget-object v1, Lm6/b0;->e:Ljava/lang/Object;

    .line 631
    .line 632
    iget-object v0, v0, La7/j;->g:Ljava/lang/Object;

    .line 633
    .line 634
    check-cast v0, Ljava/io/File;

    .line 635
    .line 636
    monitor-enter v1

    .line 637
    :try_start_0
    sget-object v2, Lm6/b0;->d:Ljava/util/LinkedHashSet;

    .line 638
    .line 639
    invoke-virtual {v0}, Ljava/io/File;->getAbsolutePath()Ljava/lang/String;

    .line 640
    .line 641
    .line 642
    move-result-object v0

    .line 643
    invoke-interface {v2, v0}, Ljava/util/Set;->remove(Ljava/lang/Object;)Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 644
    .line 645
    .line 646
    monitor-exit v1

    .line 647
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 648
    .line 649
    return-object v0

    .line 650
    :catchall_0
    move-exception v0

    .line 651
    monitor-exit v1

    .line 652
    throw v0

    .line 653
    :pswitch_10
    new-instance v1, Landroid/view/inputmethod/BaseInputConnection;

    .line 654
    .line 655
    iget-object v0, v0, La7/j;->g:Ljava/lang/Object;

    .line 656
    .line 657
    check-cast v0, Ll4/y;

    .line 658
    .line 659
    iget-object v0, v0, Ll4/y;->a:Landroid/view/View;

    .line 660
    .line 661
    invoke-direct {v1, v0, v6}, Landroid/view/inputmethod/BaseInputConnection;-><init>(Landroid/view/View;Z)V

    .line 662
    .line 663
    .line 664
    return-object v1

    .line 665
    :pswitch_11
    iget-object v0, v0, La7/j;->g:Ljava/lang/Object;

    .line 666
    .line 667
    check-cast v0, Lil/g;

    .line 668
    .line 669
    iget-object v0, v0, Lil/g;->e:Ljava/lang/Object;

    .line 670
    .line 671
    check-cast v0, Landroid/view/View;

    .line 672
    .line 673
    invoke-virtual {v0}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 674
    .line 675
    .line 676
    move-result-object v0

    .line 677
    const-string v1, "input_method"

    .line 678
    .line 679
    invoke-virtual {v0, v1}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    .line 680
    .line 681
    .line 682
    move-result-object v0

    .line 683
    const-string v1, "null cannot be cast to non-null type android.view.inputmethod.InputMethodManager"

    .line 684
    .line 685
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 686
    .line 687
    .line 688
    check-cast v0, Landroid/view/inputmethod/InputMethodManager;

    .line 689
    .line 690
    return-object v0

    .line 691
    :pswitch_12
    iget-object v0, v0, La7/j;->g:Ljava/lang/Object;

    .line 692
    .line 693
    check-cast v0, Lkn/c0;

    .line 694
    .line 695
    invoke-virtual {v0}, Lkn/c0;->i()Lkn/f0;

    .line 696
    .line 697
    .line 698
    move-result-object v0

    .line 699
    return-object v0

    .line 700
    :pswitch_13
    iget-object v0, v0, La7/j;->g:Ljava/lang/Object;

    .line 701
    .line 702
    check-cast v0, Lkl/d;

    .line 703
    .line 704
    new-instance v1, Landroid/graphics/BitmapFactory$Options;

    .line 705
    .line 706
    invoke-direct {v1}, Landroid/graphics/BitmapFactory$Options;-><init>()V

    .line 707
    .line 708
    .line 709
    iget-object v8, v0, Lkl/d;->b:Ltl/l;

    .line 710
    .line 711
    new-instance v9, Lbm/b;

    .line 712
    .line 713
    iget-object v10, v0, Lkl/d;->a:Lkl/l;

    .line 714
    .line 715
    invoke-virtual {v10}, Lkl/l;->p0()Lu01/h;

    .line 716
    .line 717
    .line 718
    move-result-object v11

    .line 719
    invoke-direct {v9, v11, v7}, Lbm/b;-><init>(Lu01/h0;I)V

    .line 720
    .line 721
    .line 722
    invoke-static {v9}, Lu01/b;->c(Lu01/h0;)Lu01/b0;

    .line 723
    .line 724
    .line 725
    move-result-object v11

    .line 726
    iput-boolean v7, v1, Landroid/graphics/BitmapFactory$Options;->inJustDecodeBounds:Z

    .line 727
    .line 728
    invoke-virtual {v11}, Lu01/b0;->b()Lu01/b0;

    .line 729
    .line 730
    .line 731
    move-result-object v12

    .line 732
    new-instance v13, Lcx0/a;

    .line 733
    .line 734
    invoke-direct {v13, v12, v4}, Lcx0/a;-><init>(Ljava/lang/Object;I)V

    .line 735
    .line 736
    .line 737
    invoke-static {v13, v5, v1}, Landroid/graphics/BitmapFactory;->decodeStream(Ljava/io/InputStream;Landroid/graphics/Rect;Landroid/graphics/BitmapFactory$Options;)Landroid/graphics/Bitmap;

    .line 738
    .line 739
    .line 740
    iget-object v12, v9, Lbm/b;->f:Ljava/lang/Object;

    .line 741
    .line 742
    check-cast v12, Ljava/lang/Exception;

    .line 743
    .line 744
    if-nez v12, :cond_3c

    .line 745
    .line 746
    iput-boolean v6, v1, Landroid/graphics/BitmapFactory$Options;->inJustDecodeBounds:Z

    .line 747
    .line 748
    sget-object v12, Lkl/i;->a:Landroid/graphics/Paint;

    .line 749
    .line 750
    iget-object v12, v1, Landroid/graphics/BitmapFactory$Options;->outMimeType:Ljava/lang/String;

    .line 751
    .line 752
    iget-object v0, v0, Lkl/d;->d:Lkl/h;

    .line 753
    .line 754
    sget-object v13, Lkl/j;->a:Ljava/util/Set;

    .line 755
    .line 756
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 757
    .line 758
    .line 759
    move-result v0

    .line 760
    if-eqz v0, :cond_15

    .line 761
    .line 762
    if-eq v0, v7, :cond_13

    .line 763
    .line 764
    if-ne v0, v2, :cond_12

    .line 765
    .line 766
    goto :goto_8

    .line 767
    :cond_12
    new-instance v0, La8/r0;

    .line 768
    .line 769
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 770
    .line 771
    .line 772
    throw v0

    .line 773
    :cond_13
    if-eqz v12, :cond_15

    .line 774
    .line 775
    sget-object v0, Lkl/j;->a:Ljava/util/Set;

    .line 776
    .line 777
    invoke-interface {v0, v12}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 778
    .line 779
    .line 780
    move-result v0

    .line 781
    if-eqz v0, :cond_15

    .line 782
    .line 783
    :goto_8
    new-instance v0, Lv6/g;

    .line 784
    .line 785
    new-instance v12, Lbm/m;

    .line 786
    .line 787
    invoke-virtual {v11}, Lu01/b0;->b()Lu01/b0;

    .line 788
    .line 789
    .line 790
    move-result-object v13

    .line 791
    new-instance v14, Lcx0/a;

    .line 792
    .line 793
    invoke-direct {v14, v13, v4}, Lcx0/a;-><init>(Ljava/lang/Object;I)V

    .line 794
    .line 795
    .line 796
    invoke-direct {v12, v14, v7}, Lbm/m;-><init>(Ljava/io/InputStream;I)V

    .line 797
    .line 798
    .line 799
    invoke-direct {v0, v12}, Lv6/g;-><init>(Ljava/io/InputStream;)V

    .line 800
    .line 801
    .line 802
    new-instance v12, Lkl/g;

    .line 803
    .line 804
    const-string v13, "Orientation"

    .line 805
    .line 806
    invoke-virtual {v0, v7, v13}, Lv6/g;->c(ILjava/lang/String;)I

    .line 807
    .line 808
    .line 809
    move-result v13

    .line 810
    if-eq v13, v2, :cond_14

    .line 811
    .line 812
    if-eq v13, v3, :cond_14

    .line 813
    .line 814
    const/4 v2, 0x4

    .line 815
    if-eq v13, v2, :cond_14

    .line 816
    .line 817
    const/4 v2, 0x5

    .line 818
    if-eq v13, v2, :cond_14

    .line 819
    .line 820
    move v2, v6

    .line 821
    goto :goto_9

    .line 822
    :cond_14
    move v2, v7

    .line 823
    :goto_9
    invoke-virtual {v0}, Lv6/g;->l()I

    .line 824
    .line 825
    .line 826
    move-result v0

    .line 827
    invoke-direct {v12, v0, v2}, Lkl/g;-><init>(IZ)V

    .line 828
    .line 829
    .line 830
    goto :goto_a

    .line 831
    :cond_15
    sget-object v12, Lkl/g;->c:Lkl/g;

    .line 832
    .line 833
    :goto_a
    iget v0, v12, Lkl/g;->b:I

    .line 834
    .line 835
    iget-boolean v2, v12, Lkl/g;->a:Z

    .line 836
    .line 837
    iget-object v3, v9, Lbm/b;->f:Ljava/lang/Object;

    .line 838
    .line 839
    check-cast v3, Ljava/lang/Exception;

    .line 840
    .line 841
    if-nez v3, :cond_3b

    .line 842
    .line 843
    iput-boolean v6, v1, Landroid/graphics/BitmapFactory$Options;->inMutable:Z

    .line 844
    .line 845
    iget-object v3, v8, Ltl/l;->c:Landroid/graphics/ColorSpace;

    .line 846
    .line 847
    iget-object v12, v8, Ltl/l;->a:Landroid/content/Context;

    .line 848
    .line 849
    iget-object v13, v8, Ltl/l;->d:Lul/g;

    .line 850
    .line 851
    if-eqz v3, :cond_16

    .line 852
    .line 853
    iput-object v3, v1, Landroid/graphics/BitmapFactory$Options;->inPreferredColorSpace:Landroid/graphics/ColorSpace;

    .line 854
    .line 855
    :cond_16
    iget-boolean v3, v8, Ltl/l;->h:Z

    .line 856
    .line 857
    iput-boolean v3, v1, Landroid/graphics/BitmapFactory$Options;->inPremultiplied:Z

    .line 858
    .line 859
    iget-object v3, v8, Ltl/l;->b:Landroid/graphics/Bitmap$Config;

    .line 860
    .line 861
    if-nez v2, :cond_17

    .line 862
    .line 863
    if-lez v0, :cond_19

    .line 864
    .line 865
    :cond_17
    if-eqz v3, :cond_18

    .line 866
    .line 867
    sget-object v14, Landroid/graphics/Bitmap$Config;->HARDWARE:Landroid/graphics/Bitmap$Config;

    .line 868
    .line 869
    if-ne v3, v14, :cond_19

    .line 870
    .line 871
    :cond_18
    sget-object v3, Landroid/graphics/Bitmap$Config;->ARGB_8888:Landroid/graphics/Bitmap$Config;

    .line 872
    .line 873
    :cond_19
    iget-boolean v14, v8, Ltl/l;->g:Z

    .line 874
    .line 875
    if-eqz v14, :cond_1a

    .line 876
    .line 877
    sget-object v14, Landroid/graphics/Bitmap$Config;->ARGB_8888:Landroid/graphics/Bitmap$Config;

    .line 878
    .line 879
    if-ne v3, v14, :cond_1a

    .line 880
    .line 881
    iget-object v14, v1, Landroid/graphics/BitmapFactory$Options;->outMimeType:Ljava/lang/String;

    .line 882
    .line 883
    const-string v15, "image/jpeg"

    .line 884
    .line 885
    invoke-static {v14, v15}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 886
    .line 887
    .line 888
    move-result v14

    .line 889
    if-eqz v14, :cond_1a

    .line 890
    .line 891
    sget-object v3, Landroid/graphics/Bitmap$Config;->RGB_565:Landroid/graphics/Bitmap$Config;

    .line 892
    .line 893
    :cond_1a
    iget-object v14, v1, Landroid/graphics/BitmapFactory$Options;->outConfig:Landroid/graphics/Bitmap$Config;

    .line 894
    .line 895
    sget-object v15, Landroid/graphics/Bitmap$Config;->RGBA_F16:Landroid/graphics/Bitmap$Config;

    .line 896
    .line 897
    if-ne v14, v15, :cond_1b

    .line 898
    .line 899
    sget-object v14, Landroid/graphics/Bitmap$Config;->HARDWARE:Landroid/graphics/Bitmap$Config;

    .line 900
    .line 901
    if-eq v3, v14, :cond_1b

    .line 902
    .line 903
    move-object v3, v15

    .line 904
    :cond_1b
    iput-object v3, v1, Landroid/graphics/BitmapFactory$Options;->inPreferredConfig:Landroid/graphics/Bitmap$Config;

    .line 905
    .line 906
    invoke-virtual {v10}, Lkl/l;->a()Llp/qd;

    .line 907
    .line 908
    .line 909
    move-result-object v3

    .line 910
    instance-of v10, v3, Lkl/n;

    .line 911
    .line 912
    const/16 v14, 0x10e

    .line 913
    .line 914
    const/16 v15, 0x5a

    .line 915
    .line 916
    if-eqz v10, :cond_1c

    .line 917
    .line 918
    sget-object v10, Lul/g;->c:Lul/g;

    .line 919
    .line 920
    invoke-static {v13, v10}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 921
    .line 922
    .line 923
    move-result v10

    .line 924
    if-eqz v10, :cond_1c

    .line 925
    .line 926
    iput v7, v1, Landroid/graphics/BitmapFactory$Options;->inSampleSize:I

    .line 927
    .line 928
    iput-boolean v7, v1, Landroid/graphics/BitmapFactory$Options;->inScaled:Z

    .line 929
    .line 930
    check-cast v3, Lkl/n;

    .line 931
    .line 932
    iget v3, v3, Lkl/n;->a:I

    .line 933
    .line 934
    iput v3, v1, Landroid/graphics/BitmapFactory$Options;->inDensity:I

    .line 935
    .line 936
    invoke-virtual {v12}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 937
    .line 938
    .line 939
    move-result-object v3

    .line 940
    invoke-virtual {v3}, Landroid/content/res/Resources;->getDisplayMetrics()Landroid/util/DisplayMetrics;

    .line 941
    .line 942
    .line 943
    move-result-object v3

    .line 944
    iget v3, v3, Landroid/util/DisplayMetrics;->densityDpi:I

    .line 945
    .line 946
    iput v3, v1, Landroid/graphics/BitmapFactory$Options;->inTargetDensity:I

    .line 947
    .line 948
    goto/16 :goto_15

    .line 949
    .line 950
    :cond_1c
    iget v3, v1, Landroid/graphics/BitmapFactory$Options;->outWidth:I

    .line 951
    .line 952
    if-lez v3, :cond_1d

    .line 953
    .line 954
    iget v10, v1, Landroid/graphics/BitmapFactory$Options;->outHeight:I

    .line 955
    .line 956
    if-gtz v10, :cond_1e

    .line 957
    .line 958
    :cond_1d
    move v14, v7

    .line 959
    goto/16 :goto_14

    .line 960
    .line 961
    :cond_1e
    if-eq v0, v15, :cond_20

    .line 962
    .line 963
    if-ne v0, v14, :cond_1f

    .line 964
    .line 965
    goto :goto_b

    .line 966
    :cond_1f
    move v5, v3

    .line 967
    goto :goto_c

    .line 968
    :cond_20
    :goto_b
    move v5, v10

    .line 969
    :goto_c
    if-eq v0, v15, :cond_22

    .line 970
    .line 971
    if-ne v0, v14, :cond_21

    .line 972
    .line 973
    goto :goto_d

    .line 974
    :cond_21
    move v3, v10

    .line 975
    :cond_22
    :goto_d
    iget-object v10, v8, Ltl/l;->e:Lul/f;

    .line 976
    .line 977
    sget-object v14, Lul/g;->c:Lul/g;

    .line 978
    .line 979
    invoke-static {v13, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 980
    .line 981
    .line 982
    move-result v17

    .line 983
    if-eqz v17, :cond_23

    .line 984
    .line 985
    move v15, v5

    .line 986
    goto :goto_e

    .line 987
    :cond_23
    iget-object v15, v13, Lul/g;->a:Llp/u1;

    .line 988
    .line 989
    invoke-static {v15, v10}, Lxl/c;->d(Llp/u1;Lul/f;)I

    .line 990
    .line 991
    .line 992
    move-result v15

    .line 993
    :goto_e
    invoke-static {v13, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 994
    .line 995
    .line 996
    move-result v14

    .line 997
    if-eqz v14, :cond_24

    .line 998
    .line 999
    move v13, v3

    .line 1000
    goto :goto_f

    .line 1001
    :cond_24
    iget-object v13, v13, Lul/g;->b:Llp/u1;

    .line 1002
    .line 1003
    invoke-static {v13, v10}, Lxl/c;->d(Llp/u1;Lul/f;)I

    .line 1004
    .line 1005
    .line 1006
    move-result v13

    .line 1007
    :goto_f
    div-int v14, v5, v15

    .line 1008
    .line 1009
    invoke-static {v14}, Ljava/lang/Integer;->highestOneBit(I)I

    .line 1010
    .line 1011
    .line 1012
    move-result v14

    .line 1013
    div-int v18, v3, v13

    .line 1014
    .line 1015
    invoke-static/range {v18 .. v18}, Ljava/lang/Integer;->highestOneBit(I)I

    .line 1016
    .line 1017
    .line 1018
    move-result v4

    .line 1019
    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    .line 1020
    .line 1021
    .line 1022
    move-result v6

    .line 1023
    if-eqz v6, :cond_26

    .line 1024
    .line 1025
    if-ne v6, v7, :cond_25

    .line 1026
    .line 1027
    invoke-static {v14, v4}, Ljava/lang/Math;->max(II)I

    .line 1028
    .line 1029
    .line 1030
    move-result v4

    .line 1031
    goto :goto_10

    .line 1032
    :cond_25
    new-instance v0, La8/r0;

    .line 1033
    .line 1034
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 1035
    .line 1036
    .line 1037
    throw v0

    .line 1038
    :cond_26
    invoke-static {v14, v4}, Ljava/lang/Math;->min(II)I

    .line 1039
    .line 1040
    .line 1041
    move-result v4

    .line 1042
    :goto_10
    if-ge v4, v7, :cond_27

    .line 1043
    .line 1044
    move v4, v7

    .line 1045
    :cond_27
    iput v4, v1, Landroid/graphics/BitmapFactory$Options;->inSampleSize:I

    .line 1046
    .line 1047
    int-to-double v5, v5

    .line 1048
    move-object/from16 v19, v8

    .line 1049
    .line 1050
    int-to-double v7, v4

    .line 1051
    div-double/2addr v5, v7

    .line 1052
    int-to-double v3, v3

    .line 1053
    div-double/2addr v3, v7

    .line 1054
    int-to-double v7, v15

    .line 1055
    int-to-double v14, v13

    .line 1056
    div-double/2addr v7, v5

    .line 1057
    div-double v3, v14, v3

    .line 1058
    .line 1059
    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    .line 1060
    .line 1061
    .line 1062
    move-result v5

    .line 1063
    if-eqz v5, :cond_29

    .line 1064
    .line 1065
    const/4 v14, 0x1

    .line 1066
    if-ne v5, v14, :cond_28

    .line 1067
    .line 1068
    invoke-static {v7, v8, v3, v4}, Ljava/lang/Math;->min(DD)D

    .line 1069
    .line 1070
    .line 1071
    move-result-wide v3

    .line 1072
    :goto_11
    move-object/from16 v5, v19

    .line 1073
    .line 1074
    goto :goto_12

    .line 1075
    :cond_28
    new-instance v0, La8/r0;

    .line 1076
    .line 1077
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 1078
    .line 1079
    .line 1080
    throw v0

    .line 1081
    :cond_29
    invoke-static {v7, v8, v3, v4}, Ljava/lang/Math;->max(DD)D

    .line 1082
    .line 1083
    .line 1084
    move-result-wide v3

    .line 1085
    goto :goto_11

    .line 1086
    :goto_12
    iget-boolean v5, v5, Ltl/l;->f:Z

    .line 1087
    .line 1088
    const-wide/high16 v6, 0x3ff0000000000000L    # 1.0

    .line 1089
    .line 1090
    if-eqz v5, :cond_2a

    .line 1091
    .line 1092
    cmpl-double v5, v3, v6

    .line 1093
    .line 1094
    if-lez v5, :cond_2a

    .line 1095
    .line 1096
    move-wide v3, v6

    .line 1097
    :cond_2a
    cmpg-double v5, v3, v6

    .line 1098
    .line 1099
    if-nez v5, :cond_2b

    .line 1100
    .line 1101
    const/4 v5, 0x1

    .line 1102
    goto :goto_13

    .line 1103
    :cond_2b
    const/4 v5, 0x0

    .line 1104
    :goto_13
    xor-int/lit8 v8, v5, 0x1

    .line 1105
    .line 1106
    iput-boolean v8, v1, Landroid/graphics/BitmapFactory$Options;->inScaled:Z

    .line 1107
    .line 1108
    if-nez v5, :cond_2d

    .line 1109
    .line 1110
    cmpl-double v5, v3, v6

    .line 1111
    .line 1112
    const v6, 0x7fffffff

    .line 1113
    .line 1114
    .line 1115
    if-lez v5, :cond_2c

    .line 1116
    .line 1117
    int-to-double v7, v6

    .line 1118
    div-double/2addr v7, v3

    .line 1119
    invoke-static {v7, v8}, Lcy0/a;->h(D)I

    .line 1120
    .line 1121
    .line 1122
    move-result v3

    .line 1123
    iput v3, v1, Landroid/graphics/BitmapFactory$Options;->inDensity:I

    .line 1124
    .line 1125
    iput v6, v1, Landroid/graphics/BitmapFactory$Options;->inTargetDensity:I

    .line 1126
    .line 1127
    goto :goto_15

    .line 1128
    :cond_2c
    iput v6, v1, Landroid/graphics/BitmapFactory$Options;->inDensity:I

    .line 1129
    .line 1130
    int-to-double v5, v6

    .line 1131
    mul-double/2addr v5, v3

    .line 1132
    invoke-static {v5, v6}, Lcy0/a;->h(D)I

    .line 1133
    .line 1134
    .line 1135
    move-result v3

    .line 1136
    iput v3, v1, Landroid/graphics/BitmapFactory$Options;->inTargetDensity:I

    .line 1137
    .line 1138
    goto :goto_15

    .line 1139
    :goto_14
    iput v14, v1, Landroid/graphics/BitmapFactory$Options;->inSampleSize:I

    .line 1140
    .line 1141
    const/4 v3, 0x0

    .line 1142
    iput-boolean v3, v1, Landroid/graphics/BitmapFactory$Options;->inScaled:Z

    .line 1143
    .line 1144
    :cond_2d
    :goto_15
    :try_start_1
    new-instance v3, Lcx0/a;

    .line 1145
    .line 1146
    const/4 v4, 0x3

    .line 1147
    invoke-direct {v3, v11, v4}, Lcx0/a;-><init>(Ljava/lang/Object;I)V

    .line 1148
    .line 1149
    .line 1150
    const/4 v4, 0x0

    .line 1151
    invoke-static {v3, v4, v1}, Landroid/graphics/BitmapFactory;->decodeStream(Ljava/io/InputStream;Landroid/graphics/Rect;Landroid/graphics/BitmapFactory$Options;)Landroid/graphics/Bitmap;

    .line 1152
    .line 1153
    .line 1154
    move-result-object v3
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 1155
    invoke-virtual {v11}, Lu01/b0;->close()V

    .line 1156
    .line 1157
    .line 1158
    iget-object v4, v9, Lbm/b;->f:Ljava/lang/Object;

    .line 1159
    .line 1160
    check-cast v4, Ljava/lang/Exception;

    .line 1161
    .line 1162
    if-nez v4, :cond_3a

    .line 1163
    .line 1164
    if-eqz v3, :cond_39

    .line 1165
    .line 1166
    invoke-virtual {v12}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 1167
    .line 1168
    .line 1169
    move-result-object v4

    .line 1170
    invoke-virtual {v4}, Landroid/content/res/Resources;->getDisplayMetrics()Landroid/util/DisplayMetrics;

    .line 1171
    .line 1172
    .line 1173
    move-result-object v4

    .line 1174
    iget v4, v4, Landroid/util/DisplayMetrics;->densityDpi:I

    .line 1175
    .line 1176
    invoke-virtual {v3, v4}, Landroid/graphics/Bitmap;->setDensity(I)V

    .line 1177
    .line 1178
    .line 1179
    if-nez v2, :cond_2e

    .line 1180
    .line 1181
    if-lez v0, :cond_36

    .line 1182
    .line 1183
    :cond_2e
    new-instance v4, Landroid/graphics/Matrix;

    .line 1184
    .line 1185
    invoke-direct {v4}, Landroid/graphics/Matrix;-><init>()V

    .line 1186
    .line 1187
    .line 1188
    invoke-virtual {v3}, Landroid/graphics/Bitmap;->getWidth()I

    .line 1189
    .line 1190
    .line 1191
    move-result v5

    .line 1192
    int-to-float v5, v5

    .line 1193
    const/high16 v6, 0x40000000    # 2.0f

    .line 1194
    .line 1195
    div-float/2addr v5, v6

    .line 1196
    invoke-virtual {v3}, Landroid/graphics/Bitmap;->getHeight()I

    .line 1197
    .line 1198
    .line 1199
    move-result v7

    .line 1200
    int-to-float v7, v7

    .line 1201
    div-float/2addr v7, v6

    .line 1202
    if-eqz v2, :cond_2f

    .line 1203
    .line 1204
    const/high16 v2, -0x40800000    # -1.0f

    .line 1205
    .line 1206
    const/high16 v6, 0x3f800000    # 1.0f

    .line 1207
    .line 1208
    invoke-virtual {v4, v2, v6, v5, v7}, Landroid/graphics/Matrix;->postScale(FFFF)Z

    .line 1209
    .line 1210
    .line 1211
    :cond_2f
    if-lez v0, :cond_30

    .line 1212
    .line 1213
    int-to-float v2, v0

    .line 1214
    invoke-virtual {v4, v2, v5, v7}, Landroid/graphics/Matrix;->postRotate(FFF)Z

    .line 1215
    .line 1216
    .line 1217
    :cond_30
    new-instance v2, Landroid/graphics/RectF;

    .line 1218
    .line 1219
    invoke-virtual {v3}, Landroid/graphics/Bitmap;->getWidth()I

    .line 1220
    .line 1221
    .line 1222
    move-result v5

    .line 1223
    int-to-float v5, v5

    .line 1224
    invoke-virtual {v3}, Landroid/graphics/Bitmap;->getHeight()I

    .line 1225
    .line 1226
    .line 1227
    move-result v6

    .line 1228
    int-to-float v6, v6

    .line 1229
    const/4 v7, 0x0

    .line 1230
    invoke-direct {v2, v7, v7, v5, v6}, Landroid/graphics/RectF;-><init>(FFFF)V

    .line 1231
    .line 1232
    .line 1233
    invoke-virtual {v4, v2}, Landroid/graphics/Matrix;->mapRect(Landroid/graphics/RectF;)Z

    .line 1234
    .line 1235
    .line 1236
    iget v5, v2, Landroid/graphics/RectF;->left:F

    .line 1237
    .line 1238
    cmpg-float v6, v5, v7

    .line 1239
    .line 1240
    if-nez v6, :cond_31

    .line 1241
    .line 1242
    iget v6, v2, Landroid/graphics/RectF;->top:F

    .line 1243
    .line 1244
    cmpg-float v6, v6, v7

    .line 1245
    .line 1246
    if-nez v6, :cond_31

    .line 1247
    .line 1248
    :goto_16
    const/16 v2, 0x5a

    .line 1249
    .line 1250
    goto :goto_17

    .line 1251
    :cond_31
    neg-float v5, v5

    .line 1252
    iget v2, v2, Landroid/graphics/RectF;->top:F

    .line 1253
    .line 1254
    neg-float v2, v2

    .line 1255
    invoke-virtual {v4, v5, v2}, Landroid/graphics/Matrix;->postTranslate(FF)Z

    .line 1256
    .line 1257
    .line 1258
    goto :goto_16

    .line 1259
    :goto_17
    if-eq v0, v2, :cond_34

    .line 1260
    .line 1261
    const/16 v2, 0x10e

    .line 1262
    .line 1263
    if-ne v0, v2, :cond_32

    .line 1264
    .line 1265
    goto :goto_18

    .line 1266
    :cond_32
    invoke-virtual {v3}, Landroid/graphics/Bitmap;->getWidth()I

    .line 1267
    .line 1268
    .line 1269
    move-result v0

    .line 1270
    invoke-virtual {v3}, Landroid/graphics/Bitmap;->getHeight()I

    .line 1271
    .line 1272
    .line 1273
    move-result v2

    .line 1274
    invoke-virtual {v3}, Landroid/graphics/Bitmap;->getConfig()Landroid/graphics/Bitmap$Config;

    .line 1275
    .line 1276
    .line 1277
    move-result-object v5

    .line 1278
    if-nez v5, :cond_33

    .line 1279
    .line 1280
    sget-object v5, Landroid/graphics/Bitmap$Config;->ARGB_8888:Landroid/graphics/Bitmap$Config;

    .line 1281
    .line 1282
    :cond_33
    invoke-static {v0, v2, v5}, Landroid/graphics/Bitmap;->createBitmap(IILandroid/graphics/Bitmap$Config;)Landroid/graphics/Bitmap;

    .line 1283
    .line 1284
    .line 1285
    move-result-object v0

    .line 1286
    goto :goto_19

    .line 1287
    :cond_34
    :goto_18
    invoke-virtual {v3}, Landroid/graphics/Bitmap;->getHeight()I

    .line 1288
    .line 1289
    .line 1290
    move-result v0

    .line 1291
    invoke-virtual {v3}, Landroid/graphics/Bitmap;->getWidth()I

    .line 1292
    .line 1293
    .line 1294
    move-result v2

    .line 1295
    invoke-virtual {v3}, Landroid/graphics/Bitmap;->getConfig()Landroid/graphics/Bitmap$Config;

    .line 1296
    .line 1297
    .line 1298
    move-result-object v5

    .line 1299
    if-nez v5, :cond_35

    .line 1300
    .line 1301
    sget-object v5, Landroid/graphics/Bitmap$Config;->ARGB_8888:Landroid/graphics/Bitmap$Config;

    .line 1302
    .line 1303
    :cond_35
    invoke-static {v0, v2, v5}, Landroid/graphics/Bitmap;->createBitmap(IILandroid/graphics/Bitmap$Config;)Landroid/graphics/Bitmap;

    .line 1304
    .line 1305
    .line 1306
    move-result-object v0

    .line 1307
    :goto_19
    new-instance v2, Landroid/graphics/Canvas;

    .line 1308
    .line 1309
    invoke-direct {v2, v0}, Landroid/graphics/Canvas;-><init>(Landroid/graphics/Bitmap;)V

    .line 1310
    .line 1311
    .line 1312
    sget-object v5, Lkl/i;->a:Landroid/graphics/Paint;

    .line 1313
    .line 1314
    invoke-virtual {v2, v3, v4, v5}, Landroid/graphics/Canvas;->drawBitmap(Landroid/graphics/Bitmap;Landroid/graphics/Matrix;Landroid/graphics/Paint;)V

    .line 1315
    .line 1316
    .line 1317
    invoke-virtual {v3}, Landroid/graphics/Bitmap;->recycle()V

    .line 1318
    .line 1319
    .line 1320
    move-object v3, v0

    .line 1321
    :cond_36
    new-instance v0, Lkl/f;

    .line 1322
    .line 1323
    invoke-virtual {v12}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 1324
    .line 1325
    .line 1326
    move-result-object v2

    .line 1327
    new-instance v4, Landroid/graphics/drawable/BitmapDrawable;

    .line 1328
    .line 1329
    invoke-direct {v4, v2, v3}, Landroid/graphics/drawable/BitmapDrawable;-><init>(Landroid/content/res/Resources;Landroid/graphics/Bitmap;)V

    .line 1330
    .line 1331
    .line 1332
    iget v2, v1, Landroid/graphics/BitmapFactory$Options;->inSampleSize:I

    .line 1333
    .line 1334
    const/4 v14, 0x1

    .line 1335
    if-gt v2, v14, :cond_38

    .line 1336
    .line 1337
    iget-boolean v1, v1, Landroid/graphics/BitmapFactory$Options;->inScaled:Z

    .line 1338
    .line 1339
    if-eqz v1, :cond_37

    .line 1340
    .line 1341
    goto :goto_1a

    .line 1342
    :cond_37
    const/4 v6, 0x0

    .line 1343
    goto :goto_1b

    .line 1344
    :cond_38
    :goto_1a
    const/4 v6, 0x1

    .line 1345
    :goto_1b
    invoke-direct {v0, v4, v6}, Lkl/f;-><init>(Landroid/graphics/drawable/BitmapDrawable;Z)V

    .line 1346
    .line 1347
    .line 1348
    return-object v0

    .line 1349
    :cond_39
    const-string v0, "BitmapFactory returned a null bitmap. Often this means BitmapFactory could not decode the image data read from the input source (e.g. network, disk, or memory) as it\'s not encoded as a valid image format."

    .line 1350
    .line 1351
    new-instance v1, Ljava/lang/IllegalStateException;

    .line 1352
    .line 1353
    invoke-direct {v1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 1354
    .line 1355
    .line 1356
    throw v1

    .line 1357
    :cond_3a
    throw v4

    .line 1358
    :catchall_1
    move-exception v0

    .line 1359
    move-object v1, v0

    .line 1360
    :try_start_2
    throw v1
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    .line 1361
    :catchall_2
    move-exception v0

    .line 1362
    invoke-static {v11, v1}, Llp/vd;->b(Ljava/io/Closeable;Ljava/lang/Throwable;)V

    .line 1363
    .line 1364
    .line 1365
    throw v0

    .line 1366
    :cond_3b
    throw v3

    .line 1367
    :cond_3c
    throw v12

    .line 1368
    :pswitch_14
    iget-object v0, v0, La7/j;->g:Ljava/lang/Object;

    .line 1369
    .line 1370
    check-cast v0, Ljl/h;

    .line 1371
    .line 1372
    iget-object v0, v0, Ljl/h;->u:Ll2/j1;

    .line 1373
    .line 1374
    invoke-virtual {v0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 1375
    .line 1376
    .line 1377
    move-result-object v0

    .line 1378
    check-cast v0, Ltl/h;

    .line 1379
    .line 1380
    return-object v0

    .line 1381
    :pswitch_15
    iget-object v0, v0, La7/j;->g:Ljava/lang/Object;

    .line 1382
    .line 1383
    check-cast v0, Lj3/j0;

    .line 1384
    .line 1385
    iget v1, v0, Lj3/j0;->o:I

    .line 1386
    .line 1387
    iget-object v0, v0, Lj3/j0;->l:Ll2/g1;

    .line 1388
    .line 1389
    invoke-virtual {v0}, Ll2/g1;->o()I

    .line 1390
    .line 1391
    .line 1392
    move-result v2

    .line 1393
    if-ne v1, v2, :cond_3d

    .line 1394
    .line 1395
    invoke-virtual {v0}, Ll2/g1;->o()I

    .line 1396
    .line 1397
    .line 1398
    move-result v1

    .line 1399
    const/4 v14, 0x1

    .line 1400
    add-int/2addr v1, v14

    .line 1401
    invoke-virtual {v0, v1}, Ll2/g1;->p(I)V

    .line 1402
    .line 1403
    .line 1404
    :cond_3d
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1405
    .line 1406
    return-object v0

    .line 1407
    :pswitch_16
    iget-object v0, v0, La7/j;->g:Ljava/lang/Object;

    .line 1408
    .line 1409
    move-object v4, v0

    .line 1410
    check-cast v4, Lh7/f;

    .line 1411
    .line 1412
    invoke-static {}, Ljava/lang/System;->nanoTime()J

    .line 1413
    .line 1414
    .line 1415
    move-result-wide v5

    .line 1416
    new-instance v2, Lkotlin/jvm/internal/e0;

    .line 1417
    .line 1418
    invoke-direct {v2}, Ljava/lang/Object;-><init>()V

    .line 1419
    .line 1420
    .line 1421
    new-instance v3, Lkotlin/jvm/internal/e0;

    .line 1422
    .line 1423
    invoke-direct {v3}, Ljava/lang/Object;-><init>()V

    .line 1424
    .line 1425
    .line 1426
    iget-object v1, v4, Lh7/f;->f:Ljava/lang/Object;

    .line 1427
    .line 1428
    monitor-enter v1

    .line 1429
    :try_start_3
    iget-wide v7, v4, Lh7/f;->h:J

    .line 1430
    .line 1431
    sub-long v7, v5, v7

    .line 1432
    .line 1433
    iput-wide v7, v2, Lkotlin/jvm/internal/e0;->d:J

    .line 1434
    .line 1435
    iget v0, v4, Lh7/f;->g:I

    .line 1436
    .line 1437
    int-to-long v7, v0

    .line 1438
    const-wide/32 v9, 0x3b9aca00

    .line 1439
    .line 1440
    .line 1441
    div-long/2addr v9, v7

    .line 1442
    iput-wide v9, v3, Lkotlin/jvm/internal/e0;->d:J
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_3

    .line 1443
    .line 1444
    monitor-exit v1

    .line 1445
    iget-object v0, v4, Lh7/f;->d:Lvy0/b0;

    .line 1446
    .line 1447
    new-instance v1, Le1/b;

    .line 1448
    .line 1449
    const/4 v7, 0x0

    .line 1450
    invoke-direct/range {v1 .. v7}, Le1/b;-><init>(Lkotlin/jvm/internal/e0;Lkotlin/jvm/internal/e0;Lh7/f;JLkotlin/coroutines/Continuation;)V

    .line 1451
    .line 1452
    .line 1453
    const/4 v2, 0x0

    .line 1454
    const/4 v4, 0x3

    .line 1455
    invoke-static {v0, v2, v2, v1, v4}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 1456
    .line 1457
    .line 1458
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1459
    .line 1460
    return-object v0

    .line 1461
    :catchall_3
    move-exception v0

    .line 1462
    monitor-exit v1

    .line 1463
    throw v0

    .line 1464
    :pswitch_17
    iget-object v0, v0, La7/j;->g:Ljava/lang/Object;

    .line 1465
    .line 1466
    check-cast v0, Le4/a;

    .line 1467
    .line 1468
    const/4 v2, 0x0

    .line 1469
    iput-object v2, v0, Le4/a;->g:Lh91/c;

    .line 1470
    .line 1471
    const-string v1, "OnPositionedDispatch"

    .line 1472
    .line 1473
    invoke-static {v1}, Landroid/os/Trace;->beginSection(Ljava/lang/String;)V

    .line 1474
    .line 1475
    .line 1476
    :try_start_4
    invoke-virtual {v0}, Le4/a;->b()V
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_4

    .line 1477
    .line 1478
    .line 1479
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 1480
    .line 1481
    .line 1482
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1483
    .line 1484
    return-object v0

    .line 1485
    :catchall_4
    move-exception v0

    .line 1486
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 1487
    .line 1488
    .line 1489
    throw v0

    .line 1490
    :pswitch_18
    iget-object v0, v0, La7/j;->g:Ljava/lang/Object;

    .line 1491
    .line 1492
    check-cast v0, Lc3/v;

    .line 1493
    .line 1494
    invoke-virtual {v0}, Lc3/v;->Y0()Lc3/o;

    .line 1495
    .line 1496
    .line 1497
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1498
    .line 1499
    return-object v0

    .line 1500
    :pswitch_19
    move v14, v7

    .line 1501
    iget-object v0, v0, La7/j;->g:Ljava/lang/Object;

    .line 1502
    .line 1503
    check-cast v0, Lc1/w1;

    .line 1504
    .line 1505
    iget-object v1, v0, Lc1/w1;->a:Lap0/o;

    .line 1506
    .line 1507
    invoke-virtual {v1}, Lap0/o;->D()Ljava/lang/Object;

    .line 1508
    .line 1509
    .line 1510
    move-result-object v1

    .line 1511
    sget-object v2, Lb1/i0;->f:Lb1/i0;

    .line 1512
    .line 1513
    if-ne v1, v2, :cond_3e

    .line 1514
    .line 1515
    iget-object v0, v0, Lc1/w1;->d:Ll2/j1;

    .line 1516
    .line 1517
    invoke-virtual {v0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 1518
    .line 1519
    .line 1520
    move-result-object v0

    .line 1521
    if-ne v0, v2, :cond_3e

    .line 1522
    .line 1523
    move v6, v14

    .line 1524
    goto :goto_1c

    .line 1525
    :cond_3e
    const/4 v6, 0x0

    .line 1526
    :goto_1c
    invoke-static {v6}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 1527
    .line 1528
    .line 1529
    move-result-object v0

    .line 1530
    return-object v0

    .line 1531
    :pswitch_1a
    iget-object v0, v0, La7/j;->g:Ljava/lang/Object;

    .line 1532
    .line 1533
    check-cast v0, Law/w;

    .line 1534
    .line 1535
    iget-object v0, v0, Law/w;->b:Ll2/j1;

    .line 1536
    .line 1537
    invoke-virtual {v0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 1538
    .line 1539
    .line 1540
    move-result-object v0

    .line 1541
    check-cast v0, Law/i;

    .line 1542
    .line 1543
    return-object v0

    .line 1544
    :pswitch_1b
    iget-object v0, v0, La7/j;->g:Ljava/lang/Object;

    .line 1545
    .line 1546
    check-cast v0, La7/v0;

    .line 1547
    .line 1548
    sget-object v1, La7/v0;->d:La7/p0;

    .line 1549
    .line 1550
    monitor-enter v1

    .line 1551
    :try_start_5
    sget-object v2, La7/v0;->f:Lm6/g;

    .line 1552
    .line 1553
    if-nez v2, :cond_3f

    .line 1554
    .line 1555
    iget-object v0, v0, La7/v0;->a:Landroid/content/Context;

    .line 1556
    .line 1557
    sget-object v2, La7/v0;->e:Lp6/b;

    .line 1558
    .line 1559
    sget-object v3, La7/p0;->a:[Lhy0/z;

    .line 1560
    .line 1561
    const/16 v18, 0x0

    .line 1562
    .line 1563
    aget-object v3, v3, v18

    .line 1564
    .line 1565
    invoke-virtual {v2, v0, v3}, Lp6/b;->getValue(Ljava/lang/Object;Lhy0/z;)Ljava/lang/Object;

    .line 1566
    .line 1567
    .line 1568
    move-result-object v0

    .line 1569
    move-object v2, v0

    .line 1570
    check-cast v2, Lm6/g;

    .line 1571
    .line 1572
    sput-object v2, La7/v0;->f:Lm6/g;
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_5

    .line 1573
    .line 1574
    goto :goto_1d

    .line 1575
    :catchall_5
    move-exception v0

    .line 1576
    goto :goto_1e

    .line 1577
    :cond_3f
    :goto_1d
    monitor-exit v1

    .line 1578
    return-object v2

    .line 1579
    :goto_1e
    monitor-exit v1

    .line 1580
    throw v0

    .line 1581
    :pswitch_1c
    iget-object v0, v0, La7/j;->g:Ljava/lang/Object;

    .line 1582
    .line 1583
    check-cast v0, La7/n;

    .line 1584
    .line 1585
    iget-object v0, v0, La7/n;->i:Ll2/j1;

    .line 1586
    .line 1587
    invoke-virtual {v0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 1588
    .line 1589
    .line 1590
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1591
    .line 1592
    return-object v0

    .line 1593
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
