.class public final Lj8/n;
.super Lj8/m;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Z

.field public final i:Lj8/i;

.field public final j:Z

.field public final k:Z

.field public final l:Z

.field public final m:I

.field public final n:I

.field public final o:I

.field public final p:I

.field public final q:I

.field public final r:I

.field public final s:Z

.field public final t:I

.field public final u:Z

.field public final v:I

.field public final w:Z

.field public final x:Z

.field public final y:I


# direct methods
.method public constructor <init>(ILt7/q0;ILj8/i;ILjava/lang/String;IZ)V
    .locals 6

    .line 1
    invoke-direct {p0, p1, p2, p3}, Lj8/m;-><init>(ILt7/q0;I)V

    .line 2
    .line 3
    .line 4
    iput-object p4, p0, Lj8/n;->i:Lj8/i;

    .line 5
    .line 6
    iget-boolean p1, p4, Lj8/i;->v:Z

    .line 7
    .line 8
    iget-object p2, p4, Lt7/u0;->i:Lhr/h0;

    .line 9
    .line 10
    iget-object p3, p4, Lt7/u0;->j:Lhr/h0;

    .line 11
    .line 12
    if-eqz p1, :cond_0

    .line 13
    .line 14
    const/16 p1, 0x18

    .line 15
    .line 16
    goto :goto_0

    .line 17
    :cond_0
    const/16 p1, 0x10

    .line 18
    .line 19
    :goto_0
    const/4 p7, 0x0

    .line 20
    iput-boolean p7, p0, Lj8/n;->u:Z

    .line 21
    .line 22
    const/high16 v0, -0x40800000    # -1.0f

    .line 23
    .line 24
    const/4 v1, -0x1

    .line 25
    const/4 v2, 0x1

    .line 26
    if-eqz p8, :cond_5

    .line 27
    .line 28
    iget-object v3, p0, Lj8/m;->g:Lt7/o;

    .line 29
    .line 30
    iget v4, v3, Lt7/o;->u:I

    .line 31
    .line 32
    if-eq v4, v1, :cond_1

    .line 33
    .line 34
    iget v5, p4, Lt7/u0;->a:I

    .line 35
    .line 36
    if-gt v4, v5, :cond_5

    .line 37
    .line 38
    :cond_1
    iget v4, v3, Lt7/o;->v:I

    .line 39
    .line 40
    if-eq v4, v1, :cond_2

    .line 41
    .line 42
    iget v5, p4, Lt7/u0;->b:I

    .line 43
    .line 44
    if-gt v4, v5, :cond_5

    .line 45
    .line 46
    :cond_2
    iget v4, v3, Lt7/o;->y:F

    .line 47
    .line 48
    cmpl-float v5, v4, v0

    .line 49
    .line 50
    if-eqz v5, :cond_3

    .line 51
    .line 52
    iget v5, p4, Lt7/u0;->c:I

    .line 53
    .line 54
    int-to-float v5, v5

    .line 55
    cmpg-float v4, v4, v5

    .line 56
    .line 57
    if-gtz v4, :cond_5

    .line 58
    .line 59
    :cond_3
    iget v3, v3, Lt7/o;->j:I

    .line 60
    .line 61
    if-eq v3, v1, :cond_4

    .line 62
    .line 63
    iget p4, p4, Lt7/u0;->d:I

    .line 64
    .line 65
    if-gt v3, p4, :cond_5

    .line 66
    .line 67
    :cond_4
    move p4, v2

    .line 68
    goto :goto_1

    .line 69
    :cond_5
    move p4, p7

    .line 70
    :goto_1
    iput-boolean p4, p0, Lj8/n;->h:Z

    .line 71
    .line 72
    if-eqz p8, :cond_a

    .line 73
    .line 74
    iget-object p4, p0, Lj8/m;->g:Lt7/o;

    .line 75
    .line 76
    iget p8, p4, Lt7/o;->u:I

    .line 77
    .line 78
    if-eq p8, v1, :cond_6

    .line 79
    .line 80
    if-ltz p8, :cond_a

    .line 81
    .line 82
    :cond_6
    iget p8, p4, Lt7/o;->v:I

    .line 83
    .line 84
    if-eq p8, v1, :cond_7

    .line 85
    .line 86
    if-ltz p8, :cond_a

    .line 87
    .line 88
    :cond_7
    iget p8, p4, Lt7/o;->y:F

    .line 89
    .line 90
    cmpl-float v3, p8, v0

    .line 91
    .line 92
    if-eqz v3, :cond_8

    .line 93
    .line 94
    int-to-float v3, p7

    .line 95
    cmpl-float p8, p8, v3

    .line 96
    .line 97
    if-ltz p8, :cond_a

    .line 98
    .line 99
    :cond_8
    iget p4, p4, Lt7/o;->j:I

    .line 100
    .line 101
    if-eq p4, v1, :cond_9

    .line 102
    .line 103
    if-ltz p4, :cond_a

    .line 104
    .line 105
    :cond_9
    move p4, v2

    .line 106
    goto :goto_2

    .line 107
    :cond_a
    move p4, p7

    .line 108
    :goto_2
    iput-boolean p4, p0, Lj8/n;->j:Z

    .line 109
    .line 110
    invoke-static {p5, p7}, La8/f;->n(IZ)Z

    .line 111
    .line 112
    .line 113
    move-result p4

    .line 114
    iput-boolean p4, p0, Lj8/n;->k:Z

    .line 115
    .line 116
    iget-object p4, p0, Lj8/m;->g:Lt7/o;

    .line 117
    .line 118
    iget p8, p4, Lt7/o;->y:F

    .line 119
    .line 120
    cmpl-float v0, p8, v0

    .line 121
    .line 122
    if-eqz v0, :cond_b

    .line 123
    .line 124
    const/high16 v0, 0x41200000    # 10.0f

    .line 125
    .line 126
    cmpl-float p8, p8, v0

    .line 127
    .line 128
    if-ltz p8, :cond_b

    .line 129
    .line 130
    move p8, v2

    .line 131
    goto :goto_3

    .line 132
    :cond_b
    move p8, p7

    .line 133
    :goto_3
    iput-boolean p8, p0, Lj8/n;->l:Z

    .line 134
    .line 135
    iget p8, p4, Lt7/o;->j:I

    .line 136
    .line 137
    iput p8, p0, Lj8/n;->m:I

    .line 138
    .line 139
    iget p8, p4, Lt7/o;->u:I

    .line 140
    .line 141
    if-eq p8, v1, :cond_d

    .line 142
    .line 143
    iget p4, p4, Lt7/o;->v:I

    .line 144
    .line 145
    if-ne p4, v1, :cond_c

    .line 146
    .line 147
    goto :goto_4

    .line 148
    :cond_c
    mul-int/2addr p8, p4

    .line 149
    goto :goto_5

    .line 150
    :cond_d
    :goto_4
    move p8, v1

    .line 151
    :goto_5
    iput p8, p0, Lj8/n;->n:I

    .line 152
    .line 153
    move p4, p7

    .line 154
    :goto_6
    invoke-virtual {p3}, Ljava/util/AbstractCollection;->size()I

    .line 155
    .line 156
    .line 157
    move-result p8

    .line 158
    const v0, 0x7fffffff

    .line 159
    .line 160
    .line 161
    if-ge p4, p8, :cond_f

    .line 162
    .line 163
    iget-object p8, p0, Lj8/m;->g:Lt7/o;

    .line 164
    .line 165
    invoke-interface {p3, p4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 166
    .line 167
    .line 168
    move-result-object v3

    .line 169
    check-cast v3, Ljava/lang/String;

    .line 170
    .line 171
    invoke-static {p8, v3, p7}, Lj8/o;->r(Lt7/o;Ljava/lang/String;Z)I

    .line 172
    .line 173
    .line 174
    move-result p8

    .line 175
    if-lez p8, :cond_e

    .line 176
    .line 177
    goto :goto_7

    .line 178
    :cond_e
    add-int/lit8 p4, p4, 0x1

    .line 179
    .line 180
    goto :goto_6

    .line 181
    :cond_f
    move p8, p7

    .line 182
    move p4, v0

    .line 183
    :goto_7
    iput p4, p0, Lj8/n;->p:I

    .line 184
    .line 185
    iput p8, p0, Lj8/n;->q:I

    .line 186
    .line 187
    iget-object p3, p0, Lj8/m;->g:Lt7/o;

    .line 188
    .line 189
    iget p3, p3, Lt7/o;->f:I

    .line 190
    .line 191
    sget-object p4, Lj8/o;->l:Lhr/w0;

    .line 192
    .line 193
    if-eqz p3, :cond_10

    .line 194
    .line 195
    if-nez p3, :cond_10

    .line 196
    .line 197
    move p3, v0

    .line 198
    goto :goto_8

    .line 199
    :cond_10
    invoke-static {p7}, Ljava/lang/Integer;->bitCount(I)I

    .line 200
    .line 201
    .line 202
    move-result p3

    .line 203
    :goto_8
    iput p3, p0, Lj8/n;->r:I

    .line 204
    .line 205
    iget-object p3, p0, Lj8/m;->g:Lt7/o;

    .line 206
    .line 207
    iget p3, p3, Lt7/o;->f:I

    .line 208
    .line 209
    if-eqz p3, :cond_12

    .line 210
    .line 211
    and-int/2addr p3, v2

    .line 212
    if-eqz p3, :cond_11

    .line 213
    .line 214
    goto :goto_9

    .line 215
    :cond_11
    move p3, p7

    .line 216
    goto :goto_a

    .line 217
    :cond_12
    :goto_9
    move p3, v2

    .line 218
    :goto_a
    iput-boolean p3, p0, Lj8/n;->s:Z

    .line 219
    .line 220
    invoke-static {p6}, Lj8/o;->u(Ljava/lang/String;)Ljava/lang/String;

    .line 221
    .line 222
    .line 223
    move-result-object p3

    .line 224
    if-nez p3, :cond_13

    .line 225
    .line 226
    move p3, v2

    .line 227
    goto :goto_b

    .line 228
    :cond_13
    move p3, p7

    .line 229
    :goto_b
    iget-object p4, p0, Lj8/m;->g:Lt7/o;

    .line 230
    .line 231
    invoke-static {p4, p6, p3}, Lj8/o;->r(Lt7/o;Ljava/lang/String;Z)I

    .line 232
    .line 233
    .line 234
    move-result p3

    .line 235
    iput p3, p0, Lj8/n;->t:I

    .line 236
    .line 237
    move p3, p7

    .line 238
    :goto_c
    invoke-virtual {p2}, Ljava/util/AbstractCollection;->size()I

    .line 239
    .line 240
    .line 241
    move-result p4

    .line 242
    if-ge p3, p4, :cond_15

    .line 243
    .line 244
    iget-object p4, p0, Lj8/m;->g:Lt7/o;

    .line 245
    .line 246
    iget-object p4, p4, Lt7/o;->n:Ljava/lang/String;

    .line 247
    .line 248
    if-eqz p4, :cond_14

    .line 249
    .line 250
    invoke-interface {p2, p3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 251
    .line 252
    .line 253
    move-result-object p6

    .line 254
    invoke-virtual {p4, p6}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 255
    .line 256
    .line 257
    move-result p4

    .line 258
    if-eqz p4, :cond_14

    .line 259
    .line 260
    move v0, p3

    .line 261
    goto :goto_d

    .line 262
    :cond_14
    add-int/lit8 p3, p3, 0x1

    .line 263
    .line 264
    goto :goto_c

    .line 265
    :cond_15
    :goto_d
    iput v0, p0, Lj8/n;->o:I

    .line 266
    .line 267
    and-int/lit16 p2, p5, 0x180

    .line 268
    .line 269
    const/16 p3, 0x80

    .line 270
    .line 271
    if-ne p2, p3, :cond_16

    .line 272
    .line 273
    move p2, v2

    .line 274
    goto :goto_e

    .line 275
    :cond_16
    move p2, p7

    .line 276
    :goto_e
    iput-boolean p2, p0, Lj8/n;->w:Z

    .line 277
    .line 278
    and-int/lit8 p2, p5, 0x40

    .line 279
    .line 280
    const/16 p3, 0x40

    .line 281
    .line 282
    if-ne p2, p3, :cond_17

    .line 283
    .line 284
    move p2, v2

    .line 285
    goto :goto_f

    .line 286
    :cond_17
    move p2, p7

    .line 287
    :goto_f
    iput-boolean p2, p0, Lj8/n;->x:Z

    .line 288
    .line 289
    iget-object p2, p0, Lj8/m;->g:Lt7/o;

    .line 290
    .line 291
    iget-object p3, p2, Lt7/o;->n:Ljava/lang/String;

    .line 292
    .line 293
    const/4 p4, 0x2

    .line 294
    if-nez p3, :cond_18

    .line 295
    .line 296
    goto :goto_12

    .line 297
    :cond_18
    invoke-virtual {p3}, Ljava/lang/String;->hashCode()I

    .line 298
    .line 299
    .line 300
    move-result p6

    .line 301
    const/4 p8, 0x4

    .line 302
    const/4 v0, 0x3

    .line 303
    sparse-switch p6, :sswitch_data_0

    .line 304
    .line 305
    .line 306
    :goto_10
    move p3, v1

    .line 307
    goto :goto_11

    .line 308
    :sswitch_0
    const-string p6, "video/x-vnd.on2.vp9"

    .line 309
    .line 310
    invoke-virtual {p3, p6}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 311
    .line 312
    .line 313
    move-result p3

    .line 314
    if-nez p3, :cond_19

    .line 315
    .line 316
    goto :goto_10

    .line 317
    :cond_19
    move p3, p8

    .line 318
    goto :goto_11

    .line 319
    :sswitch_1
    const-string p6, "video/avc"

    .line 320
    .line 321
    invoke-virtual {p3, p6}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 322
    .line 323
    .line 324
    move-result p3

    .line 325
    if-nez p3, :cond_1a

    .line 326
    .line 327
    goto :goto_10

    .line 328
    :cond_1a
    move p3, v0

    .line 329
    goto :goto_11

    .line 330
    :sswitch_2
    const-string p6, "video/hevc"

    .line 331
    .line 332
    invoke-virtual {p3, p6}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 333
    .line 334
    .line 335
    move-result p3

    .line 336
    if-nez p3, :cond_1b

    .line 337
    .line 338
    goto :goto_10

    .line 339
    :cond_1b
    move p3, p4

    .line 340
    goto :goto_11

    .line 341
    :sswitch_3
    const-string p6, "video/av01"

    .line 342
    .line 343
    invoke-virtual {p3, p6}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 344
    .line 345
    .line 346
    move-result p3

    .line 347
    if-nez p3, :cond_1c

    .line 348
    .line 349
    goto :goto_10

    .line 350
    :cond_1c
    move p3, v2

    .line 351
    goto :goto_11

    .line 352
    :sswitch_4
    const-string p6, "video/dolby-vision"

    .line 353
    .line 354
    invoke-virtual {p3, p6}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 355
    .line 356
    .line 357
    move-result p3

    .line 358
    if-nez p3, :cond_1d

    .line 359
    .line 360
    goto :goto_10

    .line 361
    :cond_1d
    move p3, p7

    .line 362
    :goto_11
    packed-switch p3, :pswitch_data_0

    .line 363
    .line 364
    .line 365
    :goto_12
    move p8, p7

    .line 366
    goto :goto_13

    .line 367
    :pswitch_0
    move p8, p4

    .line 368
    goto :goto_13

    .line 369
    :pswitch_1
    move p8, v2

    .line 370
    goto :goto_13

    .line 371
    :pswitch_2
    move p8, v0

    .line 372
    goto :goto_13

    .line 373
    :pswitch_3
    const/4 p8, 0x5

    .line 374
    :goto_13
    :pswitch_4
    iput p8, p0, Lj8/n;->y:I

    .line 375
    .line 376
    iget-boolean p3, p0, Lj8/n;->h:Z

    .line 377
    .line 378
    iget-object p6, p0, Lj8/n;->i:Lj8/i;

    .line 379
    .line 380
    iget p8, p2, Lt7/o;->f:I

    .line 381
    .line 382
    and-int/lit16 p8, p8, 0x4000

    .line 383
    .line 384
    if-eqz p8, :cond_1e

    .line 385
    .line 386
    goto :goto_14

    .line 387
    :cond_1e
    iget-boolean p8, p6, Lj8/i;->z:Z

    .line 388
    .line 389
    invoke-static {p5, p8}, La8/f;->n(IZ)Z

    .line 390
    .line 391
    .line 392
    move-result p8

    .line 393
    if-nez p8, :cond_1f

    .line 394
    .line 395
    goto :goto_14

    .line 396
    :cond_1f
    if-nez p3, :cond_20

    .line 397
    .line 398
    iget-boolean p6, p6, Lj8/i;->u:Z

    .line 399
    .line 400
    if-nez p6, :cond_20

    .line 401
    .line 402
    goto :goto_14

    .line 403
    :cond_20
    invoke-static {p5, p7}, La8/f;->n(IZ)Z

    .line 404
    .line 405
    .line 406
    move-result p6

    .line 407
    if-eqz p6, :cond_21

    .line 408
    .line 409
    iget-boolean p6, p0, Lj8/n;->j:Z

    .line 410
    .line 411
    if-eqz p6, :cond_21

    .line 412
    .line 413
    if-eqz p3, :cond_21

    .line 414
    .line 415
    iget p2, p2, Lt7/o;->j:I

    .line 416
    .line 417
    if-eq p2, v1, :cond_21

    .line 418
    .line 419
    and-int/2addr p1, p5

    .line 420
    if-eqz p1, :cond_21

    .line 421
    .line 422
    move p7, p4

    .line 423
    goto :goto_14

    .line 424
    :cond_21
    move p7, v2

    .line 425
    :goto_14
    iput p7, p0, Lj8/n;->v:I

    .line 426
    .line 427
    return-void

    .line 428
    nop

    .line 429
    :sswitch_data_0
    .sparse-switch
        -0x6e5534ef -> :sswitch_4
        -0x631b55f6 -> :sswitch_3
        -0x63185e82 -> :sswitch_2
        0x4f62373a -> :sswitch_1
        0x5f50bed9 -> :sswitch_0
    .end sparse-switch

    .line 430
    .line 431
    .line 432
    .line 433
    .line 434
    .line 435
    .line 436
    .line 437
    .line 438
    .line 439
    .line 440
    .line 441
    .line 442
    .line 443
    .line 444
    .line 445
    .line 446
    .line 447
    .line 448
    .line 449
    .line 450
    .line 451
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_4
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public static c(Lj8/n;Lj8/n;)I
    .locals 4

    .line 1
    iget-boolean v0, p0, Lj8/n;->k:Z

    .line 2
    .line 3
    iget-boolean v1, p1, Lj8/n;->k:Z

    .line 4
    .line 5
    sget-object v2, Lhr/z;->a:Lhr/x;

    .line 6
    .line 7
    invoke-virtual {v2, v0, v1}, Lhr/x;->c(ZZ)Lhr/z;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    iget v1, p0, Lj8/n;->p:I

    .line 12
    .line 13
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    iget v2, p1, Lj8/n;->p:I

    .line 18
    .line 19
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 20
    .line 21
    .line 22
    move-result-object v2

    .line 23
    sget-object v3, Lhr/v0;->f:Lhr/v0;

    .line 24
    .line 25
    invoke-virtual {v0, v1, v2, v3}, Lhr/z;->b(Ljava/lang/Object;Ljava/lang/Object;Ljava/util/Comparator;)Lhr/z;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    iget v1, p0, Lj8/n;->q:I

    .line 30
    .line 31
    iget v2, p1, Lj8/n;->q:I

    .line 32
    .line 33
    invoke-virtual {v0, v1, v2}, Lhr/z;->a(II)Lhr/z;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    iget v1, p0, Lj8/n;->r:I

    .line 38
    .line 39
    iget v2, p1, Lj8/n;->r:I

    .line 40
    .line 41
    invoke-virtual {v0, v1, v2}, Lhr/z;->a(II)Lhr/z;

    .line 42
    .line 43
    .line 44
    move-result-object v0

    .line 45
    iget-boolean v1, p0, Lj8/n;->s:Z

    .line 46
    .line 47
    iget-boolean v2, p1, Lj8/n;->s:Z

    .line 48
    .line 49
    invoke-virtual {v0, v1, v2}, Lhr/z;->c(ZZ)Lhr/z;

    .line 50
    .line 51
    .line 52
    move-result-object v0

    .line 53
    iget v1, p0, Lj8/n;->t:I

    .line 54
    .line 55
    iget v2, p1, Lj8/n;->t:I

    .line 56
    .line 57
    invoke-virtual {v0, v1, v2}, Lhr/z;->a(II)Lhr/z;

    .line 58
    .line 59
    .line 60
    move-result-object v0

    .line 61
    iget-boolean v1, p0, Lj8/n;->l:Z

    .line 62
    .line 63
    iget-boolean v2, p1, Lj8/n;->l:Z

    .line 64
    .line 65
    invoke-virtual {v0, v1, v2}, Lhr/z;->c(ZZ)Lhr/z;

    .line 66
    .line 67
    .line 68
    move-result-object v0

    .line 69
    iget-boolean v1, p0, Lj8/n;->h:Z

    .line 70
    .line 71
    iget-boolean v2, p1, Lj8/n;->h:Z

    .line 72
    .line 73
    invoke-virtual {v0, v1, v2}, Lhr/z;->c(ZZ)Lhr/z;

    .line 74
    .line 75
    .line 76
    move-result-object v0

    .line 77
    iget-boolean v1, p0, Lj8/n;->j:Z

    .line 78
    .line 79
    iget-boolean v2, p1, Lj8/n;->j:Z

    .line 80
    .line 81
    invoke-virtual {v0, v1, v2}, Lhr/z;->c(ZZ)Lhr/z;

    .line 82
    .line 83
    .line 84
    move-result-object v0

    .line 85
    iget v1, p0, Lj8/n;->o:I

    .line 86
    .line 87
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 88
    .line 89
    .line 90
    move-result-object v1

    .line 91
    iget v2, p1, Lj8/n;->o:I

    .line 92
    .line 93
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 94
    .line 95
    .line 96
    move-result-object v2

    .line 97
    invoke-virtual {v0, v1, v2, v3}, Lhr/z;->b(Ljava/lang/Object;Ljava/lang/Object;Ljava/util/Comparator;)Lhr/z;

    .line 98
    .line 99
    .line 100
    move-result-object v0

    .line 101
    iget-boolean v1, p0, Lj8/n;->w:Z

    .line 102
    .line 103
    iget-boolean v2, p1, Lj8/n;->w:Z

    .line 104
    .line 105
    invoke-virtual {v0, v1, v2}, Lhr/z;->c(ZZ)Lhr/z;

    .line 106
    .line 107
    .line 108
    move-result-object v0

    .line 109
    iget-boolean v2, p0, Lj8/n;->x:Z

    .line 110
    .line 111
    iget-boolean v3, p1, Lj8/n;->x:Z

    .line 112
    .line 113
    invoke-virtual {v0, v2, v3}, Lhr/z;->c(ZZ)Lhr/z;

    .line 114
    .line 115
    .line 116
    move-result-object v0

    .line 117
    if-eqz v1, :cond_0

    .line 118
    .line 119
    if-eqz v2, :cond_0

    .line 120
    .line 121
    iget p0, p0, Lj8/n;->y:I

    .line 122
    .line 123
    iget p1, p1, Lj8/n;->y:I

    .line 124
    .line 125
    invoke-virtual {v0, p0, p1}, Lhr/z;->a(II)Lhr/z;

    .line 126
    .line 127
    .line 128
    move-result-object v0

    .line 129
    :cond_0
    invoke-virtual {v0}, Lhr/z;->e()I

    .line 130
    .line 131
    .line 132
    move-result p0

    .line 133
    return p0
.end method


# virtual methods
.method public final a()I
    .locals 0

    .line 1
    iget p0, p0, Lj8/n;->v:I

    .line 2
    .line 3
    return p0
.end method

.method public final b(Lj8/m;)Z
    .locals 2

    .line 1
    check-cast p1, Lj8/n;

    .line 2
    .line 3
    iget-boolean v0, p0, Lj8/n;->u:Z

    .line 4
    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    iget-object v0, p0, Lj8/m;->g:Lt7/o;

    .line 8
    .line 9
    iget-object v0, v0, Lt7/o;->n:Ljava/lang/String;

    .line 10
    .line 11
    iget-object v1, p1, Lj8/m;->g:Lt7/o;

    .line 12
    .line 13
    iget-object v1, v1, Lt7/o;->n:Ljava/lang/String;

    .line 14
    .line 15
    invoke-static {v0, v1}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    if-eqz v0, :cond_1

    .line 20
    .line 21
    :cond_0
    iget-object v0, p0, Lj8/n;->i:Lj8/i;

    .line 22
    .line 23
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 24
    .line 25
    .line 26
    iget-boolean v0, p0, Lj8/n;->w:Z

    .line 27
    .line 28
    iget-boolean v1, p1, Lj8/n;->w:Z

    .line 29
    .line 30
    if-ne v0, v1, :cond_1

    .line 31
    .line 32
    iget-boolean p0, p0, Lj8/n;->x:Z

    .line 33
    .line 34
    iget-boolean p1, p1, Lj8/n;->x:Z

    .line 35
    .line 36
    if-ne p0, p1, :cond_1

    .line 37
    .line 38
    const/4 p0, 0x1

    .line 39
    return p0

    .line 40
    :cond_1
    const/4 p0, 0x0

    .line 41
    return p0
.end method
