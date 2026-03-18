.class public final Lsp/w;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/os/Parcelable$Creator;


# instance fields
.field public final synthetic a:I


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lsp/w;->a:I

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final createFromParcel(Landroid/os/Parcel;)Ljava/lang/Object;
    .locals 24

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    iget v0, v0, Lsp/w;->a:I

    .line 6
    .line 7
    packed-switch v0, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    invoke-static {v1}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    const/4 v2, 0x0

    .line 15
    :goto_0
    invoke-virtual {v1}, Landroid/os/Parcel;->dataPosition()I

    .line 16
    .line 17
    .line 18
    move-result v3

    .line 19
    if-ge v3, v0, :cond_1

    .line 20
    .line 21
    invoke-virtual {v1}, Landroid/os/Parcel;->readInt()I

    .line 22
    .line 23
    .line 24
    move-result v3

    .line 25
    int-to-char v4, v3

    .line 26
    const/4 v5, 0x2

    .line 27
    if-eq v4, v5, :cond_0

    .line 28
    .line 29
    invoke-static {v1, v3}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 30
    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_0
    invoke-static {v1, v3}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 34
    .line 35
    .line 36
    move-result v2

    .line 37
    goto :goto_0

    .line 38
    :cond_1
    invoke-static {v1, v0}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 39
    .line 40
    .line 41
    new-instance v0, Lcq/g;

    .line 42
    .line 43
    invoke-direct {v0, v2}, Lcq/g;-><init>(I)V

    .line 44
    .line 45
    .line 46
    return-object v0

    .line 47
    :pswitch_0
    invoke-static {v1}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 48
    .line 49
    .line 50
    move-result v0

    .line 51
    const/4 v2, 0x0

    .line 52
    const/4 v3, 0x0

    .line 53
    :goto_1
    invoke-virtual {v1}, Landroid/os/Parcel;->dataPosition()I

    .line 54
    .line 55
    .line 56
    move-result v4

    .line 57
    if-ge v4, v0, :cond_4

    .line 58
    .line 59
    invoke-virtual {v1}, Landroid/os/Parcel;->readInt()I

    .line 60
    .line 61
    .line 62
    move-result v4

    .line 63
    int-to-char v5, v4

    .line 64
    const/4 v6, 0x1

    .line 65
    if-eq v5, v6, :cond_3

    .line 66
    .line 67
    const/4 v6, 0x2

    .line 68
    if-eq v5, v6, :cond_2

    .line 69
    .line 70
    invoke-static {v1, v4}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 71
    .line 72
    .line 73
    goto :goto_1

    .line 74
    :cond_2
    invoke-static {v1, v4}, Ljp/xb;->l(Landroid/os/Parcel;I)Z

    .line 75
    .line 76
    .line 77
    move-result v2

    .line 78
    goto :goto_1

    .line 79
    :cond_3
    invoke-static {v1, v4}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 80
    .line 81
    .line 82
    move-result-object v3

    .line 83
    goto :goto_1

    .line 84
    :cond_4
    invoke-static {v1, v0}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 85
    .line 86
    .line 87
    new-instance v0, Lcq/c;

    .line 88
    .line 89
    invoke-direct {v0, v3, v2}, Lcq/c;-><init>(Ljava/lang/String;Z)V

    .line 90
    .line 91
    .line 92
    return-object v0

    .line 93
    :pswitch_1
    invoke-static {v1}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 94
    .line 95
    .line 96
    move-result v0

    .line 97
    const/4 v2, 0x0

    .line 98
    :goto_2
    invoke-virtual {v1}, Landroid/os/Parcel;->dataPosition()I

    .line 99
    .line 100
    .line 101
    move-result v3

    .line 102
    if-ge v3, v0, :cond_6

    .line 103
    .line 104
    invoke-virtual {v1}, Landroid/os/Parcel;->readInt()I

    .line 105
    .line 106
    .line 107
    move-result v3

    .line 108
    int-to-char v4, v3

    .line 109
    const/4 v5, 0x2

    .line 110
    if-eq v4, v5, :cond_5

    .line 111
    .line 112
    invoke-static {v1, v3}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 113
    .line 114
    .line 115
    goto :goto_2

    .line 116
    :cond_5
    invoke-static {v1, v3}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 117
    .line 118
    .line 119
    move-result v2

    .line 120
    goto :goto_2

    .line 121
    :cond_6
    invoke-static {v1, v0}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 122
    .line 123
    .line 124
    new-instance v0, Lcq/f;

    .line 125
    .line 126
    invoke-direct {v0, v2}, Lcq/f;-><init>(I)V

    .line 127
    .line 128
    .line 129
    return-object v0

    .line 130
    :pswitch_2
    invoke-static {v1}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 131
    .line 132
    .line 133
    move-result v0

    .line 134
    const/4 v2, 0x0

    .line 135
    move-object v3, v2

    .line 136
    move-object v4, v3

    .line 137
    :goto_3
    invoke-virtual {v1}, Landroid/os/Parcel;->dataPosition()I

    .line 138
    .line 139
    .line 140
    move-result v5

    .line 141
    if-ge v5, v0, :cond_a

    .line 142
    .line 143
    invoke-virtual {v1}, Landroid/os/Parcel;->readInt()I

    .line 144
    .line 145
    .line 146
    move-result v5

    .line 147
    int-to-char v6, v5

    .line 148
    const/4 v7, 0x2

    .line 149
    if-eq v6, v7, :cond_9

    .line 150
    .line 151
    const/4 v7, 0x3

    .line 152
    if-eq v6, v7, :cond_8

    .line 153
    .line 154
    const/4 v7, 0x4

    .line 155
    if-eq v6, v7, :cond_7

    .line 156
    .line 157
    invoke-static {v1, v5}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 158
    .line 159
    .line 160
    goto :goto_3

    .line 161
    :cond_7
    invoke-static {v1, v5}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 162
    .line 163
    .line 164
    move-result-object v4

    .line 165
    goto :goto_3

    .line 166
    :cond_8
    invoke-static {v1, v5}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 167
    .line 168
    .line 169
    move-result-object v3

    .line 170
    goto :goto_3

    .line 171
    :cond_9
    invoke-static {v1, v5}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 172
    .line 173
    .line 174
    move-result-object v2

    .line 175
    goto :goto_3

    .line 176
    :cond_a
    invoke-static {v1, v0}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 177
    .line 178
    .line 179
    new-instance v0, Lcq/e;

    .line 180
    .line 181
    invoke-direct {v0, v2, v3, v4}, Lcq/e;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 182
    .line 183
    .line 184
    return-object v0

    .line 185
    :pswitch_3
    invoke-static {v1}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 186
    .line 187
    .line 188
    move-result v0

    .line 189
    const/4 v2, 0x0

    .line 190
    const/4 v3, 0x0

    .line 191
    move v4, v2

    .line 192
    move-object v5, v3

    .line 193
    move v3, v4

    .line 194
    :goto_4
    invoke-virtual {v1}, Landroid/os/Parcel;->dataPosition()I

    .line 195
    .line 196
    .line 197
    move-result v6

    .line 198
    if-ge v6, v0, :cond_f

    .line 199
    .line 200
    invoke-virtual {v1}, Landroid/os/Parcel;->readInt()I

    .line 201
    .line 202
    .line 203
    move-result v6

    .line 204
    int-to-char v7, v6

    .line 205
    const/4 v8, 0x2

    .line 206
    if-eq v7, v8, :cond_e

    .line 207
    .line 208
    const/4 v8, 0x3

    .line 209
    if-eq v7, v8, :cond_d

    .line 210
    .line 211
    const/4 v8, 0x4

    .line 212
    if-eq v7, v8, :cond_c

    .line 213
    .line 214
    const/4 v8, 0x5

    .line 215
    if-eq v7, v8, :cond_b

    .line 216
    .line 217
    invoke-static {v1, v6}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 218
    .line 219
    .line 220
    goto :goto_4

    .line 221
    :cond_b
    invoke-static {v1, v6}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 222
    .line 223
    .line 224
    move-result v4

    .line 225
    goto :goto_4

    .line 226
    :cond_c
    invoke-static {v1, v6}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 227
    .line 228
    .line 229
    move-result v3

    .line 230
    goto :goto_4

    .line 231
    :cond_d
    invoke-static {v1, v6}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 232
    .line 233
    .line 234
    move-result v2

    .line 235
    goto :goto_4

    .line 236
    :cond_e
    sget-object v5, Lcq/e;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 237
    .line 238
    invoke-static {v1, v6, v5}, Ljp/xb;->e(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 239
    .line 240
    .line 241
    move-result-object v5

    .line 242
    check-cast v5, Lcq/e;

    .line 243
    .line 244
    goto :goto_4

    .line 245
    :cond_f
    invoke-static {v1, v0}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 246
    .line 247
    .line 248
    new-instance v0, Lcq/d;

    .line 249
    .line 250
    invoke-direct {v0, v5, v2, v3, v4}, Lcq/d;-><init>(Lcq/e;III)V

    .line 251
    .line 252
    .line 253
    return-object v0

    .line 254
    :pswitch_4
    invoke-static {v1}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 255
    .line 256
    .line 257
    move-result v0

    .line 258
    const/4 v2, 0x0

    .line 259
    move-object v3, v2

    .line 260
    :goto_5
    invoke-virtual {v1}, Landroid/os/Parcel;->dataPosition()I

    .line 261
    .line 262
    .line 263
    move-result v4

    .line 264
    if-ge v4, v0, :cond_12

    .line 265
    .line 266
    invoke-virtual {v1}, Landroid/os/Parcel;->readInt()I

    .line 267
    .line 268
    .line 269
    move-result v4

    .line 270
    int-to-char v5, v4

    .line 271
    const/4 v6, 0x2

    .line 272
    if-eq v5, v6, :cond_11

    .line 273
    .line 274
    const/4 v6, 0x3

    .line 275
    if-eq v5, v6, :cond_10

    .line 276
    .line 277
    invoke-static {v1, v4}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 278
    .line 279
    .line 280
    goto :goto_5

    .line 281
    :cond_10
    sget-object v3, Lcq/c1;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 282
    .line 283
    invoke-static {v1, v4, v3}, Ljp/xb;->j(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Ljava/util/ArrayList;

    .line 284
    .line 285
    .line 286
    move-result-object v3

    .line 287
    goto :goto_5

    .line 288
    :cond_11
    invoke-static {v1, v4}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 289
    .line 290
    .line 291
    move-result-object v2

    .line 292
    goto :goto_5

    .line 293
    :cond_12
    invoke-static {v1, v0}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 294
    .line 295
    .line 296
    new-instance v0, Lcq/b;

    .line 297
    .line 298
    invoke-direct {v0, v2, v3}, Lcq/b;-><init>(Ljava/lang/String;Ljava/util/ArrayList;)V

    .line 299
    .line 300
    .line 301
    return-object v0

    .line 302
    :pswitch_5
    invoke-static {v1}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 303
    .line 304
    .line 305
    move-result v0

    .line 306
    const/4 v2, 0x0

    .line 307
    :goto_6
    invoke-virtual {v1}, Landroid/os/Parcel;->dataPosition()I

    .line 308
    .line 309
    .line 310
    move-result v3

    .line 311
    if-ge v3, v0, :cond_14

    .line 312
    .line 313
    invoke-virtual {v1}, Landroid/os/Parcel;->readInt()I

    .line 314
    .line 315
    .line 316
    move-result v3

    .line 317
    int-to-char v4, v3

    .line 318
    const/4 v5, 0x2

    .line 319
    if-eq v4, v5, :cond_13

    .line 320
    .line 321
    invoke-static {v1, v3}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 322
    .line 323
    .line 324
    goto :goto_6

    .line 325
    :cond_13
    invoke-static {v1, v3}, Ljp/xb;->a(Landroid/os/Parcel;I)Landroid/os/Bundle;

    .line 326
    .line 327
    .line 328
    move-result-object v2

    .line 329
    goto :goto_6

    .line 330
    :cond_14
    invoke-static {v1, v0}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 331
    .line 332
    .line 333
    new-instance v0, Lcom/google/firebase/messaging/v;

    .line 334
    .line 335
    invoke-direct {v0, v2}, Lcom/google/firebase/messaging/v;-><init>(Landroid/os/Bundle;)V

    .line 336
    .line 337
    .line 338
    return-object v0

    .line 339
    :pswitch_6
    new-instance v0, Lcom/google/android/material/timepicker/l;

    .line 340
    .line 341
    invoke-virtual {v1}, Landroid/os/Parcel;->readInt()I

    .line 342
    .line 343
    .line 344
    move-result v2

    .line 345
    invoke-virtual {v1}, Landroid/os/Parcel;->readInt()I

    .line 346
    .line 347
    .line 348
    move-result v3

    .line 349
    invoke-virtual {v1}, Landroid/os/Parcel;->readInt()I

    .line 350
    .line 351
    .line 352
    move-result v4

    .line 353
    invoke-virtual {v1}, Landroid/os/Parcel;->readInt()I

    .line 354
    .line 355
    .line 356
    move-result v1

    .line 357
    invoke-direct {v0, v2, v3, v4, v1}, Lcom/google/android/material/timepicker/l;-><init>(IIII)V

    .line 358
    .line 359
    .line 360
    return-object v0

    .line 361
    :pswitch_7
    new-instance v0, Lcom/google/android/material/datepicker/k0;

    .line 362
    .line 363
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 364
    .line 365
    .line 366
    const-class v2, Ljava/lang/Long;

    .line 367
    .line 368
    invoke-virtual {v2}, Ljava/lang/Class;->getClassLoader()Ljava/lang/ClassLoader;

    .line 369
    .line 370
    .line 371
    move-result-object v2

    .line 372
    invoke-virtual {v1, v2}, Landroid/os/Parcel;->readValue(Ljava/lang/ClassLoader;)Ljava/lang/Object;

    .line 373
    .line 374
    .line 375
    move-result-object v1

    .line 376
    check-cast v1, Ljava/lang/Long;

    .line 377
    .line 378
    iput-object v1, v0, Lcom/google/android/material/datepicker/k0;->d:Ljava/lang/Long;

    .line 379
    .line 380
    return-object v0

    .line 381
    :pswitch_8
    new-instance v0, Lcom/google/android/material/datepicker/i0;

    .line 382
    .line 383
    invoke-direct {v0}, Lcom/google/android/material/datepicker/i0;-><init>()V

    .line 384
    .line 385
    .line 386
    const-class v2, Ljava/lang/Long;

    .line 387
    .line 388
    invoke-virtual {v2}, Ljava/lang/Class;->getClassLoader()Ljava/lang/ClassLoader;

    .line 389
    .line 390
    .line 391
    move-result-object v3

    .line 392
    invoke-virtual {v1, v3}, Landroid/os/Parcel;->readValue(Ljava/lang/ClassLoader;)Ljava/lang/Object;

    .line 393
    .line 394
    .line 395
    move-result-object v3

    .line 396
    check-cast v3, Ljava/lang/Long;

    .line 397
    .line 398
    iput-object v3, v0, Lcom/google/android/material/datepicker/i0;->e:Ljava/lang/Long;

    .line 399
    .line 400
    invoke-virtual {v2}, Ljava/lang/Class;->getClassLoader()Ljava/lang/ClassLoader;

    .line 401
    .line 402
    .line 403
    move-result-object v2

    .line 404
    invoke-virtual {v1, v2}, Landroid/os/Parcel;->readValue(Ljava/lang/ClassLoader;)Ljava/lang/Object;

    .line 405
    .line 406
    .line 407
    move-result-object v1

    .line 408
    check-cast v1, Ljava/lang/Long;

    .line 409
    .line 410
    iput-object v1, v0, Lcom/google/android/material/datepicker/i0;->f:Ljava/lang/Long;

    .line 411
    .line 412
    return-object v0

    .line 413
    :pswitch_9
    invoke-virtual {v1}, Landroid/os/Parcel;->readInt()I

    .line 414
    .line 415
    .line 416
    move-result v0

    .line 417
    invoke-virtual {v1}, Landroid/os/Parcel;->readInt()I

    .line 418
    .line 419
    .line 420
    move-result v1

    .line 421
    invoke-static {v0, v1}, Lcom/google/android/material/datepicker/b0;->b(II)Lcom/google/android/material/datepicker/b0;

    .line 422
    .line 423
    .line 424
    move-result-object v0

    .line 425
    return-object v0

    .line 426
    :pswitch_a
    new-instance v0, Lcom/google/android/material/datepicker/k;

    .line 427
    .line 428
    invoke-virtual {v1}, Landroid/os/Parcel;->readLong()J

    .line 429
    .line 430
    .line 431
    move-result-wide v1

    .line 432
    invoke-direct {v0, v1, v2}, Lcom/google/android/material/datepicker/k;-><init>(J)V

    .line 433
    .line 434
    .line 435
    return-object v0

    .line 436
    :pswitch_b
    new-instance v0, Lcom/google/android/material/datepicker/j;

    .line 437
    .line 438
    invoke-virtual {v1}, Landroid/os/Parcel;->readLong()J

    .line 439
    .line 440
    .line 441
    move-result-wide v1

    .line 442
    invoke-direct {v0, v1, v2}, Lcom/google/android/material/datepicker/j;-><init>(J)V

    .line 443
    .line 444
    .line 445
    return-object v0

    .line 446
    :pswitch_c
    const-class v0, Lcom/google/android/material/datepicker/b0;

    .line 447
    .line 448
    invoke-virtual {v0}, Ljava/lang/Class;->getClassLoader()Ljava/lang/ClassLoader;

    .line 449
    .line 450
    .line 451
    move-result-object v2

    .line 452
    invoke-virtual {v1, v2}, Landroid/os/Parcel;->readParcelable(Ljava/lang/ClassLoader;)Landroid/os/Parcelable;

    .line 453
    .line 454
    .line 455
    move-result-object v2

    .line 456
    move-object v4, v2

    .line 457
    check-cast v4, Lcom/google/android/material/datepicker/b0;

    .line 458
    .line 459
    invoke-virtual {v0}, Ljava/lang/Class;->getClassLoader()Ljava/lang/ClassLoader;

    .line 460
    .line 461
    .line 462
    move-result-object v2

    .line 463
    invoke-virtual {v1, v2}, Landroid/os/Parcel;->readParcelable(Ljava/lang/ClassLoader;)Landroid/os/Parcelable;

    .line 464
    .line 465
    .line 466
    move-result-object v2

    .line 467
    move-object v5, v2

    .line 468
    check-cast v5, Lcom/google/android/material/datepicker/b0;

    .line 469
    .line 470
    invoke-virtual {v0}, Ljava/lang/Class;->getClassLoader()Ljava/lang/ClassLoader;

    .line 471
    .line 472
    .line 473
    move-result-object v0

    .line 474
    invoke-virtual {v1, v0}, Landroid/os/Parcel;->readParcelable(Ljava/lang/ClassLoader;)Landroid/os/Parcelable;

    .line 475
    .line 476
    .line 477
    move-result-object v0

    .line 478
    move-object v7, v0

    .line 479
    check-cast v7, Lcom/google/android/material/datepicker/b0;

    .line 480
    .line 481
    const-class v0, Lcom/google/android/material/datepicker/b;

    .line 482
    .line 483
    invoke-virtual {v0}, Ljava/lang/Class;->getClassLoader()Ljava/lang/ClassLoader;

    .line 484
    .line 485
    .line 486
    move-result-object v0

    .line 487
    invoke-virtual {v1, v0}, Landroid/os/Parcel;->readParcelable(Ljava/lang/ClassLoader;)Landroid/os/Parcelable;

    .line 488
    .line 489
    .line 490
    move-result-object v0

    .line 491
    move-object v6, v0

    .line 492
    check-cast v6, Lcom/google/android/material/datepicker/b;

    .line 493
    .line 494
    invoke-virtual {v1}, Landroid/os/Parcel;->readInt()I

    .line 495
    .line 496
    .line 497
    move-result v8

    .line 498
    new-instance v3, Lcom/google/android/material/datepicker/c;

    .line 499
    .line 500
    invoke-direct/range {v3 .. v8}, Lcom/google/android/material/datepicker/c;-><init>(Lcom/google/android/material/datepicker/b0;Lcom/google/android/material/datepicker/b0;Lcom/google/android/material/datepicker/b;Lcom/google/android/material/datepicker/b0;I)V

    .line 501
    .line 502
    .line 503
    return-object v3

    .line 504
    :pswitch_d
    new-instance v0, Lcom/auth0/android/jwt/c;

    .line 505
    .line 506
    invoke-virtual {v1}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 507
    .line 508
    .line 509
    move-result-object v1

    .line 510
    invoke-direct {v0, v1}, Lcom/auth0/android/jwt/c;-><init>(Ljava/lang/String;)V

    .line 511
    .line 512
    .line 513
    return-object v0

    .line 514
    :pswitch_e
    invoke-static {v1}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 515
    .line 516
    .line 517
    move-result v0

    .line 518
    const/4 v2, 0x0

    .line 519
    const/4 v3, 0x0

    .line 520
    move v5, v2

    .line 521
    move v6, v5

    .line 522
    move v10, v6

    .line 523
    move-object v7, v3

    .line 524
    move-object v8, v7

    .line 525
    move-object v9, v8

    .line 526
    :goto_7
    invoke-virtual {v1}, Landroid/os/Parcel;->dataPosition()I

    .line 527
    .line 528
    .line 529
    move-result v2

    .line 530
    if-ge v2, v0, :cond_15

    .line 531
    .line 532
    invoke-virtual {v1}, Landroid/os/Parcel;->readInt()I

    .line 533
    .line 534
    .line 535
    move-result v2

    .line 536
    int-to-char v3, v2

    .line 537
    packed-switch v3, :pswitch_data_1

    .line 538
    .line 539
    .line 540
    invoke-static {v1, v2}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 541
    .line 542
    .line 543
    goto :goto_7

    .line 544
    :pswitch_f
    invoke-static {v1, v2}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 545
    .line 546
    .line 547
    move-result v6

    .line 548
    goto :goto_7

    .line 549
    :pswitch_10
    invoke-static {v1, v2}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 550
    .line 551
    .line 552
    move-result-object v9

    .line 553
    goto :goto_7

    .line 554
    :pswitch_11
    invoke-static {v1, v2}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 555
    .line 556
    .line 557
    move-result-object v8

    .line 558
    goto :goto_7

    .line 559
    :pswitch_12
    invoke-static {v1, v2}, Ljp/xb;->l(Landroid/os/Parcel;I)Z

    .line 560
    .line 561
    .line 562
    move-result v10

    .line 563
    goto :goto_7

    .line 564
    :pswitch_13
    invoke-static {v1, v2}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 565
    .line 566
    .line 567
    move-result-object v7

    .line 568
    goto :goto_7

    .line 569
    :pswitch_14
    invoke-static {v1, v2}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 570
    .line 571
    .line 572
    move-result v5

    .line 573
    goto :goto_7

    .line 574
    :cond_15
    invoke-static {v1, v0}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 575
    .line 576
    .line 577
    new-instance v4, Lcom/google/android/gms/wearable/Term;

    .line 578
    .line 579
    invoke-direct/range {v4 .. v10}, Lcom/google/android/gms/wearable/Term;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    .line 580
    .line 581
    .line 582
    return-object v4

    .line 583
    :pswitch_15
    invoke-static {v1}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 584
    .line 585
    .line 586
    move-result v0

    .line 587
    const-wide/16 v2, 0x0

    .line 588
    .line 589
    const/4 v4, 0x0

    .line 590
    move-wide v9, v2

    .line 591
    move-object v6, v4

    .line 592
    move-object v7, v6

    .line 593
    move-object v8, v7

    .line 594
    :goto_8
    invoke-virtual {v1}, Landroid/os/Parcel;->dataPosition()I

    .line 595
    .line 596
    .line 597
    move-result v2

    .line 598
    if-ge v2, v0, :cond_1a

    .line 599
    .line 600
    invoke-virtual {v1}, Landroid/os/Parcel;->readInt()I

    .line 601
    .line 602
    .line 603
    move-result v2

    .line 604
    int-to-char v3, v2

    .line 605
    const/4 v4, 0x2

    .line 606
    if-eq v3, v4, :cond_19

    .line 607
    .line 608
    const/4 v4, 0x4

    .line 609
    if-eq v3, v4, :cond_18

    .line 610
    .line 611
    const/4 v4, 0x5

    .line 612
    if-eq v3, v4, :cond_17

    .line 613
    .line 614
    const/4 v4, 0x6

    .line 615
    if-eq v3, v4, :cond_16

    .line 616
    .line 617
    invoke-static {v1, v2}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 618
    .line 619
    .line 620
    goto :goto_8

    .line 621
    :cond_16
    invoke-static {v1, v2}, Ljp/xb;->s(Landroid/os/Parcel;I)J

    .line 622
    .line 623
    .line 624
    move-result-wide v2

    .line 625
    move-wide v9, v2

    .line 626
    goto :goto_8

    .line 627
    :cond_17
    invoke-static {v1, v2}, Ljp/xb;->b(Landroid/os/Parcel;I)[B

    .line 628
    .line 629
    .line 630
    move-result-object v2

    .line 631
    move-object v8, v2

    .line 632
    goto :goto_8

    .line 633
    :cond_18
    invoke-static {v1, v2}, Ljp/xb;->a(Landroid/os/Parcel;I)Landroid/os/Bundle;

    .line 634
    .line 635
    .line 636
    move-result-object v2

    .line 637
    move-object v7, v2

    .line 638
    goto :goto_8

    .line 639
    :cond_19
    sget-object v3, Landroid/net/Uri;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 640
    .line 641
    invoke-static {v1, v2, v3}, Ljp/xb;->e(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 642
    .line 643
    .line 644
    move-result-object v2

    .line 645
    check-cast v2, Landroid/net/Uri;

    .line 646
    .line 647
    move-object v6, v2

    .line 648
    goto :goto_8

    .line 649
    :cond_1a
    invoke-static {v1, v0}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 650
    .line 651
    .line 652
    new-instance v5, Lbq/e;

    .line 653
    .line 654
    invoke-direct/range {v5 .. v10}, Lbq/e;-><init>(Landroid/net/Uri;Landroid/os/Bundle;[BJ)V

    .line 655
    .line 656
    .line 657
    return-object v5

    .line 658
    :pswitch_16
    invoke-static {v1}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 659
    .line 660
    .line 661
    move-result v0

    .line 662
    const/4 v2, 0x0

    .line 663
    const/4 v3, 0x0

    .line 664
    :goto_9
    invoke-virtual {v1}, Landroid/os/Parcel;->dataPosition()I

    .line 665
    .line 666
    .line 667
    move-result v4

    .line 668
    if-ge v4, v0, :cond_1d

    .line 669
    .line 670
    invoke-virtual {v1}, Landroid/os/Parcel;->readInt()I

    .line 671
    .line 672
    .line 673
    move-result v4

    .line 674
    int-to-char v5, v4

    .line 675
    const/4 v6, 0x1

    .line 676
    if-eq v5, v6, :cond_1c

    .line 677
    .line 678
    const/4 v6, 0x2

    .line 679
    if-eq v5, v6, :cond_1b

    .line 680
    .line 681
    invoke-static {v1, v4}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 682
    .line 683
    .line 684
    goto :goto_9

    .line 685
    :cond_1b
    invoke-static {v1, v4}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 686
    .line 687
    .line 688
    move-result v2

    .line 689
    goto :goto_9

    .line 690
    :cond_1c
    sget-object v3, Landroid/net/Uri;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 691
    .line 692
    invoke-static {v1, v4, v3}, Ljp/xb;->e(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 693
    .line 694
    .line 695
    move-result-object v3

    .line 696
    check-cast v3, Landroid/net/Uri;

    .line 697
    .line 698
    goto :goto_9

    .line 699
    :cond_1d
    invoke-static {v1, v0}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 700
    .line 701
    .line 702
    new-instance v0, Lbq/j;

    .line 703
    .line 704
    invoke-direct {v0, v3, v2}, Lbq/j;-><init>(Landroid/net/Uri;I)V

    .line 705
    .line 706
    .line 707
    return-object v0

    .line 708
    :pswitch_17
    invoke-static {v1}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 709
    .line 710
    .line 711
    move-result v0

    .line 712
    const/4 v2, 0x0

    .line 713
    move-object v3, v2

    .line 714
    move-object v4, v3

    .line 715
    :goto_a
    invoke-virtual {v1}, Landroid/os/Parcel;->dataPosition()I

    .line 716
    .line 717
    .line 718
    move-result v5

    .line 719
    if-ge v5, v0, :cond_21

    .line 720
    .line 721
    invoke-virtual {v1}, Landroid/os/Parcel;->readInt()I

    .line 722
    .line 723
    .line 724
    move-result v5

    .line 725
    int-to-char v6, v5

    .line 726
    const/4 v7, 0x1

    .line 727
    if-eq v6, v7, :cond_20

    .line 728
    .line 729
    const/4 v7, 0x2

    .line 730
    if-eq v6, v7, :cond_1f

    .line 731
    .line 732
    const/4 v7, 0x3

    .line 733
    if-eq v6, v7, :cond_1e

    .line 734
    .line 735
    invoke-static {v1, v5}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 736
    .line 737
    .line 738
    goto :goto_a

    .line 739
    :cond_1e
    invoke-static {v1, v5}, Ljp/xb;->h(Landroid/os/Parcel;I)Ljava/util/ArrayList;

    .line 740
    .line 741
    .line 742
    move-result-object v4

    .line 743
    goto :goto_a

    .line 744
    :cond_1f
    invoke-static {v1, v5}, Ljp/xb;->h(Landroid/os/Parcel;I)Ljava/util/ArrayList;

    .line 745
    .line 746
    .line 747
    move-result-object v3

    .line 748
    goto :goto_a

    .line 749
    :cond_20
    sget-object v2, Lbq/j;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 750
    .line 751
    invoke-static {v1, v5, v2}, Ljp/xb;->j(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Ljava/util/ArrayList;

    .line 752
    .line 753
    .line 754
    move-result-object v2

    .line 755
    goto :goto_a

    .line 756
    :cond_21
    invoke-static {v1, v0}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 757
    .line 758
    .line 759
    new-instance v0, Lbq/i;

    .line 760
    .line 761
    invoke-direct {v0, v2, v3, v4}, Lbq/i;-><init>(Ljava/util/ArrayList;Ljava/util/ArrayList;Ljava/util/ArrayList;)V

    .line 762
    .line 763
    .line 764
    return-object v0

    .line 765
    :pswitch_18
    invoke-static {v1}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 766
    .line 767
    .line 768
    move-result v0

    .line 769
    const/4 v2, 0x0

    .line 770
    :goto_b
    invoke-virtual {v1}, Landroid/os/Parcel;->dataPosition()I

    .line 771
    .line 772
    .line 773
    move-result v3

    .line 774
    if-ge v3, v0, :cond_23

    .line 775
    .line 776
    invoke-virtual {v1}, Landroid/os/Parcel;->readInt()I

    .line 777
    .line 778
    .line 779
    move-result v3

    .line 780
    int-to-char v4, v3

    .line 781
    const/4 v5, 0x1

    .line 782
    if-eq v4, v5, :cond_22

    .line 783
    .line 784
    invoke-static {v1, v3}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 785
    .line 786
    .line 787
    goto :goto_b

    .line 788
    :cond_22
    sget-object v2, Lbq/j;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 789
    .line 790
    invoke-static {v1, v3, v2}, Ljp/xb;->j(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Ljava/util/ArrayList;

    .line 791
    .line 792
    .line 793
    move-result-object v2

    .line 794
    goto :goto_b

    .line 795
    :cond_23
    invoke-static {v1, v0}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 796
    .line 797
    .line 798
    new-instance v0, Lbq/h;

    .line 799
    .line 800
    invoke-direct {v0, v2}, Lbq/h;-><init>(Ljava/util/ArrayList;)V

    .line 801
    .line 802
    .line 803
    return-object v0

    .line 804
    :pswitch_19
    invoke-static {v1}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 805
    .line 806
    .line 807
    move-result v0

    .line 808
    const/4 v2, 0x0

    .line 809
    const/4 v3, 0x0

    .line 810
    const/4 v4, 0x1

    .line 811
    move v8, v2

    .line 812
    move v9, v8

    .line 813
    move v10, v9

    .line 814
    move v11, v10

    .line 815
    move v13, v11

    .line 816
    move/from16 v16, v13

    .line 817
    .line 818
    move/from16 v18, v16

    .line 819
    .line 820
    move/from16 v23, v18

    .line 821
    .line 822
    move-object v6, v3

    .line 823
    move-object v7, v6

    .line 824
    move-object v12, v7

    .line 825
    move-object v14, v12

    .line 826
    move-object v15, v14

    .line 827
    move-object/from16 v17, v15

    .line 828
    .line 829
    move-object/from16 v20, v17

    .line 830
    .line 831
    move-object/from16 v22, v20

    .line 832
    .line 833
    move/from16 v19, v4

    .line 834
    .line 835
    move/from16 v21, v19

    .line 836
    .line 837
    :goto_c
    invoke-virtual {v1}, Landroid/os/Parcel;->dataPosition()I

    .line 838
    .line 839
    .line 840
    move-result v2

    .line 841
    if-ge v2, v0, :cond_24

    .line 842
    .line 843
    invoke-virtual {v1}, Landroid/os/Parcel;->readInt()I

    .line 844
    .line 845
    .line 846
    move-result v2

    .line 847
    int-to-char v3, v2

    .line 848
    packed-switch v3, :pswitch_data_2

    .line 849
    .line 850
    .line 851
    invoke-static {v1, v2}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 852
    .line 853
    .line 854
    goto :goto_c

    .line 855
    :pswitch_1a
    invoke-static {v1, v2}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 856
    .line 857
    .line 858
    move-result v23

    .line 859
    goto :goto_c

    .line 860
    :pswitch_1b
    sget-object v3, Lbq/h;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 861
    .line 862
    invoke-static {v1, v2, v3}, Ljp/xb;->e(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 863
    .line 864
    .line 865
    move-result-object v2

    .line 866
    move-object/from16 v22, v2

    .line 867
    .line 868
    check-cast v22, Lbq/h;

    .line 869
    .line 870
    goto :goto_c

    .line 871
    :pswitch_1c
    invoke-static {v1, v2}, Ljp/xb;->l(Landroid/os/Parcel;I)Z

    .line 872
    .line 873
    .line 874
    move-result v21

    .line 875
    goto :goto_c

    .line 876
    :pswitch_1d
    sget-object v3, Lbq/i;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 877
    .line 878
    invoke-static {v1, v2, v3}, Ljp/xb;->e(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 879
    .line 880
    .line 881
    move-result-object v2

    .line 882
    move-object/from16 v20, v2

    .line 883
    .line 884
    check-cast v20, Lbq/i;

    .line 885
    .line 886
    goto :goto_c

    .line 887
    :pswitch_1e
    invoke-static {v1, v2}, Ljp/xb;->l(Landroid/os/Parcel;I)Z

    .line 888
    .line 889
    .line 890
    move-result v19

    .line 891
    goto :goto_c

    .line 892
    :pswitch_1f
    invoke-static {v1, v2}, Ljp/xb;->l(Landroid/os/Parcel;I)Z

    .line 893
    .line 894
    .line 895
    move-result v18

    .line 896
    goto :goto_c

    .line 897
    :pswitch_20
    invoke-static {v1, v2}, Ljp/xb;->h(Landroid/os/Parcel;I)Ljava/util/ArrayList;

    .line 898
    .line 899
    .line 900
    move-result-object v17

    .line 901
    goto :goto_c

    .line 902
    :pswitch_21
    invoke-static {v1, v2}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 903
    .line 904
    .line 905
    move-result v16

    .line 906
    goto :goto_c

    .line 907
    :pswitch_22
    invoke-static {v1, v2}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 908
    .line 909
    .line 910
    move-result-object v15

    .line 911
    goto :goto_c

    .line 912
    :pswitch_23
    invoke-static {v1, v2}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 913
    .line 914
    .line 915
    move-result-object v14

    .line 916
    goto :goto_c

    .line 917
    :pswitch_24
    invoke-static {v1, v2}, Ljp/xb;->l(Landroid/os/Parcel;I)Z

    .line 918
    .line 919
    .line 920
    move-result v13

    .line 921
    goto :goto_c

    .line 922
    :pswitch_25
    invoke-static {v1, v2}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 923
    .line 924
    .line 925
    move-result-object v12

    .line 926
    goto :goto_c

    .line 927
    :pswitch_26
    invoke-static {v1, v2}, Ljp/xb;->l(Landroid/os/Parcel;I)Z

    .line 928
    .line 929
    .line 930
    move-result v11

    .line 931
    goto :goto_c

    .line 932
    :pswitch_27
    invoke-static {v1, v2}, Ljp/xb;->l(Landroid/os/Parcel;I)Z

    .line 933
    .line 934
    .line 935
    move-result v10

    .line 936
    goto :goto_c

    .line 937
    :pswitch_28
    invoke-static {v1, v2}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 938
    .line 939
    .line 940
    move-result v9

    .line 941
    goto :goto_c

    .line 942
    :pswitch_29
    invoke-static {v1, v2}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 943
    .line 944
    .line 945
    move-result v8

    .line 946
    goto :goto_c

    .line 947
    :pswitch_2a
    invoke-static {v1, v2}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 948
    .line 949
    .line 950
    move-result-object v7

    .line 951
    goto :goto_c

    .line 952
    :pswitch_2b
    invoke-static {v1, v2}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 953
    .line 954
    .line 955
    move-result-object v6

    .line 956
    goto :goto_c

    .line 957
    :cond_24
    invoke-static {v1, v0}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 958
    .line 959
    .line 960
    new-instance v5, Lcom/google/android/gms/wearable/ConnectionConfiguration;

    .line 961
    .line 962
    invoke-direct/range {v5 .. v23}, Lcom/google/android/gms/wearable/ConnectionConfiguration;-><init>(Ljava/lang/String;Ljava/lang/String;IIZZLjava/lang/String;ZLjava/lang/String;Ljava/lang/String;ILjava/util/ArrayList;ZZLbq/i;ZLbq/h;I)V

    .line 963
    .line 964
    .line 965
    return-object v5

    .line 966
    :pswitch_2c
    invoke-static {v1}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 967
    .line 968
    .line 969
    move-result v0

    .line 970
    const/4 v2, 0x0

    .line 971
    move-object v3, v2

    .line 972
    move-object v4, v3

    .line 973
    move-object v5, v4

    .line 974
    :goto_d
    invoke-virtual {v1}, Landroid/os/Parcel;->dataPosition()I

    .line 975
    .line 976
    .line 977
    move-result v6

    .line 978
    if-ge v6, v0, :cond_29

    .line 979
    .line 980
    invoke-virtual {v1}, Landroid/os/Parcel;->readInt()I

    .line 981
    .line 982
    .line 983
    move-result v6

    .line 984
    int-to-char v7, v6

    .line 985
    const/4 v8, 0x2

    .line 986
    if-eq v7, v8, :cond_28

    .line 987
    .line 988
    const/4 v8, 0x3

    .line 989
    if-eq v7, v8, :cond_27

    .line 990
    .line 991
    const/4 v8, 0x4

    .line 992
    if-eq v7, v8, :cond_26

    .line 993
    .line 994
    const/4 v8, 0x5

    .line 995
    if-eq v7, v8, :cond_25

    .line 996
    .line 997
    invoke-static {v1, v6}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 998
    .line 999
    .line 1000
    goto :goto_d

    .line 1001
    :cond_25
    sget-object v5, Landroid/net/Uri;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 1002
    .line 1003
    invoke-static {v1, v6, v5}, Ljp/xb;->e(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 1004
    .line 1005
    .line 1006
    move-result-object v5

    .line 1007
    check-cast v5, Landroid/net/Uri;

    .line 1008
    .line 1009
    goto :goto_d

    .line 1010
    :cond_26
    sget-object v4, Landroid/os/ParcelFileDescriptor;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 1011
    .line 1012
    invoke-static {v1, v6, v4}, Ljp/xb;->e(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 1013
    .line 1014
    .line 1015
    move-result-object v4

    .line 1016
    check-cast v4, Landroid/os/ParcelFileDescriptor;

    .line 1017
    .line 1018
    goto :goto_d

    .line 1019
    :cond_27
    invoke-static {v1, v6}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 1020
    .line 1021
    .line 1022
    move-result-object v3

    .line 1023
    goto :goto_d

    .line 1024
    :cond_28
    invoke-static {v1, v6}, Ljp/xb;->b(Landroid/os/Parcel;I)[B

    .line 1025
    .line 1026
    .line 1027
    move-result-object v2

    .line 1028
    goto :goto_d

    .line 1029
    :cond_29
    invoke-static {v1, v0}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 1030
    .line 1031
    .line 1032
    new-instance v0, Lcom/google/android/gms/wearable/Asset;

    .line 1033
    .line 1034
    invoke-direct {v0, v2, v3, v4, v5}, Lcom/google/android/gms/wearable/Asset;-><init>([BLjava/lang/String;Landroid/os/ParcelFileDescriptor;Landroid/net/Uri;)V

    .line 1035
    .line 1036
    .line 1037
    return-object v0

    .line 1038
    :pswitch_2d
    invoke-static {v1}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 1039
    .line 1040
    .line 1041
    move-result v0

    .line 1042
    const/4 v2, 0x0

    .line 1043
    move v3, v2

    .line 1044
    move v4, v3

    .line 1045
    move v5, v4

    .line 1046
    :goto_e
    invoke-virtual {v1}, Landroid/os/Parcel;->dataPosition()I

    .line 1047
    .line 1048
    .line 1049
    move-result v6

    .line 1050
    if-ge v6, v0, :cond_2e

    .line 1051
    .line 1052
    invoke-virtual {v1}, Landroid/os/Parcel;->readInt()I

    .line 1053
    .line 1054
    .line 1055
    move-result v6

    .line 1056
    int-to-char v7, v6

    .line 1057
    const/4 v8, 0x1

    .line 1058
    if-eq v7, v8, :cond_2d

    .line 1059
    .line 1060
    const/4 v8, 0x2

    .line 1061
    if-eq v7, v8, :cond_2c

    .line 1062
    .line 1063
    const/4 v8, 0x3

    .line 1064
    if-eq v7, v8, :cond_2b

    .line 1065
    .line 1066
    const/4 v8, 0x4

    .line 1067
    if-eq v7, v8, :cond_2a

    .line 1068
    .line 1069
    invoke-static {v1, v6}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 1070
    .line 1071
    .line 1072
    goto :goto_e

    .line 1073
    :cond_2a
    invoke-static {v1, v6}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 1074
    .line 1075
    .line 1076
    move-result v5

    .line 1077
    goto :goto_e

    .line 1078
    :cond_2b
    invoke-static {v1, v6}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 1079
    .line 1080
    .line 1081
    move-result v4

    .line 1082
    goto :goto_e

    .line 1083
    :cond_2c
    invoke-static {v1, v6}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 1084
    .line 1085
    .line 1086
    move-result v3

    .line 1087
    goto :goto_e

    .line 1088
    :cond_2d
    invoke-static {v1, v6}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 1089
    .line 1090
    .line 1091
    move-result v2

    .line 1092
    goto :goto_e

    .line 1093
    :cond_2e
    invoke-static {v1, v0}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 1094
    .line 1095
    .line 1096
    new-instance v0, Lcom/google/android/gms/wearable/AppTheme;

    .line 1097
    .line 1098
    invoke-direct {v0, v2, v3, v4, v5}, Lcom/google/android/gms/wearable/AppTheme;-><init>(IIII)V

    .line 1099
    .line 1100
    .line 1101
    return-object v0

    .line 1102
    :pswitch_2e
    invoke-static {v1}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 1103
    .line 1104
    .line 1105
    move-result v0

    .line 1106
    const/4 v2, 0x0

    .line 1107
    move-object v4, v2

    .line 1108
    move-object v5, v4

    .line 1109
    move-object v6, v5

    .line 1110
    move-object v7, v6

    .line 1111
    move-object v8, v7

    .line 1112
    move-object v9, v8

    .line 1113
    :goto_f
    invoke-virtual {v1}, Landroid/os/Parcel;->dataPosition()I

    .line 1114
    .line 1115
    .line 1116
    move-result v2

    .line 1117
    if-ge v2, v0, :cond_35

    .line 1118
    .line 1119
    invoke-virtual {v1}, Landroid/os/Parcel;->readInt()I

    .line 1120
    .line 1121
    .line 1122
    move-result v2

    .line 1123
    int-to-char v3, v2

    .line 1124
    const/4 v10, 0x1

    .line 1125
    if-eq v3, v10, :cond_34

    .line 1126
    .line 1127
    const/4 v10, 0x2

    .line 1128
    if-eq v3, v10, :cond_33

    .line 1129
    .line 1130
    const/4 v10, 0x3

    .line 1131
    if-eq v3, v10, :cond_32

    .line 1132
    .line 1133
    const/4 v10, 0x4

    .line 1134
    if-eq v3, v10, :cond_31

    .line 1135
    .line 1136
    const/4 v10, 0x6

    .line 1137
    if-eq v3, v10, :cond_30

    .line 1138
    .line 1139
    const/4 v10, 0x7

    .line 1140
    if-eq v3, v10, :cond_2f

    .line 1141
    .line 1142
    invoke-static {v1, v2}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 1143
    .line 1144
    .line 1145
    goto :goto_f

    .line 1146
    :cond_2f
    invoke-static {v1, v2}, Ljp/xb;->a(Landroid/os/Parcel;I)Landroid/os/Bundle;

    .line 1147
    .line 1148
    .line 1149
    move-result-object v2

    .line 1150
    move-object v9, v2

    .line 1151
    goto :goto_f

    .line 1152
    :cond_30
    invoke-static {v1, v2}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 1153
    .line 1154
    .line 1155
    move-result-object v2

    .line 1156
    move-object v8, v2

    .line 1157
    goto :goto_f

    .line 1158
    :cond_31
    invoke-static {v1, v2}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 1159
    .line 1160
    .line 1161
    move-result-object v2

    .line 1162
    move-object v7, v2

    .line 1163
    goto :goto_f

    .line 1164
    :cond_32
    invoke-static {v1, v2}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 1165
    .line 1166
    .line 1167
    move-result-object v2

    .line 1168
    move-object v6, v2

    .line 1169
    goto :goto_f

    .line 1170
    :cond_33
    invoke-static {v1, v2}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 1171
    .line 1172
    .line 1173
    move-result-object v2

    .line 1174
    move-object v5, v2

    .line 1175
    goto :goto_f

    .line 1176
    :cond_34
    invoke-static {v1, v2}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 1177
    .line 1178
    .line 1179
    move-result-object v2

    .line 1180
    move-object v4, v2

    .line 1181
    goto :goto_f

    .line 1182
    :cond_35
    invoke-static {v1, v0}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 1183
    .line 1184
    .line 1185
    new-instance v3, Lbp/p;

    .line 1186
    .line 1187
    invoke-direct/range {v3 .. v9}, Lbp/p;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Landroid/os/Bundle;)V

    .line 1188
    .line 1189
    .line 1190
    return-object v3

    .line 1191
    :pswitch_2f
    new-instance v0, Landroidx/fragment/app/p1;

    .line 1192
    .line 1193
    invoke-direct {v0, v1}, Landroidx/fragment/app/p1;-><init>(Landroid/os/Parcel;)V

    .line 1194
    .line 1195
    .line 1196
    return-object v0

    .line 1197
    :pswitch_30
    new-instance v0, Landroidx/fragment/app/l1;

    .line 1198
    .line 1199
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 1200
    .line 1201
    .line 1202
    const/4 v2, 0x0

    .line 1203
    iput-object v2, v0, Landroidx/fragment/app/l1;->h:Ljava/lang/String;

    .line 1204
    .line 1205
    new-instance v2, Ljava/util/ArrayList;

    .line 1206
    .line 1207
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 1208
    .line 1209
    .line 1210
    iput-object v2, v0, Landroidx/fragment/app/l1;->i:Ljava/util/ArrayList;

    .line 1211
    .line 1212
    new-instance v2, Ljava/util/ArrayList;

    .line 1213
    .line 1214
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 1215
    .line 1216
    .line 1217
    iput-object v2, v0, Landroidx/fragment/app/l1;->j:Ljava/util/ArrayList;

    .line 1218
    .line 1219
    invoke-virtual {v1}, Landroid/os/Parcel;->createStringArrayList()Ljava/util/ArrayList;

    .line 1220
    .line 1221
    .line 1222
    move-result-object v2

    .line 1223
    iput-object v2, v0, Landroidx/fragment/app/l1;->d:Ljava/util/ArrayList;

    .line 1224
    .line 1225
    invoke-virtual {v1}, Landroid/os/Parcel;->createStringArrayList()Ljava/util/ArrayList;

    .line 1226
    .line 1227
    .line 1228
    move-result-object v2

    .line 1229
    iput-object v2, v0, Landroidx/fragment/app/l1;->e:Ljava/util/ArrayList;

    .line 1230
    .line 1231
    sget-object v2, Landroidx/fragment/app/b;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 1232
    .line 1233
    invoke-virtual {v1, v2}, Landroid/os/Parcel;->createTypedArray(Landroid/os/Parcelable$Creator;)[Ljava/lang/Object;

    .line 1234
    .line 1235
    .line 1236
    move-result-object v2

    .line 1237
    check-cast v2, [Landroidx/fragment/app/b;

    .line 1238
    .line 1239
    iput-object v2, v0, Landroidx/fragment/app/l1;->f:[Landroidx/fragment/app/b;

    .line 1240
    .line 1241
    invoke-virtual {v1}, Landroid/os/Parcel;->readInt()I

    .line 1242
    .line 1243
    .line 1244
    move-result v2

    .line 1245
    iput v2, v0, Landroidx/fragment/app/l1;->g:I

    .line 1246
    .line 1247
    invoke-virtual {v1}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 1248
    .line 1249
    .line 1250
    move-result-object v2

    .line 1251
    iput-object v2, v0, Landroidx/fragment/app/l1;->h:Ljava/lang/String;

    .line 1252
    .line 1253
    invoke-virtual {v1}, Landroid/os/Parcel;->createStringArrayList()Ljava/util/ArrayList;

    .line 1254
    .line 1255
    .line 1256
    move-result-object v2

    .line 1257
    iput-object v2, v0, Landroidx/fragment/app/l1;->i:Ljava/util/ArrayList;

    .line 1258
    .line 1259
    sget-object v2, Landroidx/fragment/app/c;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 1260
    .line 1261
    invoke-virtual {v1, v2}, Landroid/os/Parcel;->createTypedArrayList(Landroid/os/Parcelable$Creator;)Ljava/util/ArrayList;

    .line 1262
    .line 1263
    .line 1264
    move-result-object v2

    .line 1265
    iput-object v2, v0, Landroidx/fragment/app/l1;->j:Ljava/util/ArrayList;

    .line 1266
    .line 1267
    sget-object v2, Landroidx/fragment/app/f1;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 1268
    .line 1269
    invoke-virtual {v1, v2}, Landroid/os/Parcel;->createTypedArrayList(Landroid/os/Parcelable$Creator;)Ljava/util/ArrayList;

    .line 1270
    .line 1271
    .line 1272
    move-result-object v1

    .line 1273
    iput-object v1, v0, Landroidx/fragment/app/l1;->k:Ljava/util/ArrayList;

    .line 1274
    .line 1275
    return-object v0

    .line 1276
    :pswitch_31
    new-instance v0, Landroidx/fragment/app/f1;

    .line 1277
    .line 1278
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 1279
    .line 1280
    .line 1281
    invoke-virtual {v1}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 1282
    .line 1283
    .line 1284
    move-result-object v2

    .line 1285
    iput-object v2, v0, Landroidx/fragment/app/f1;->d:Ljava/lang/String;

    .line 1286
    .line 1287
    invoke-virtual {v1}, Landroid/os/Parcel;->readInt()I

    .line 1288
    .line 1289
    .line 1290
    move-result v1

    .line 1291
    iput v1, v0, Landroidx/fragment/app/f1;->e:I

    .line 1292
    .line 1293
    return-object v0

    .line 1294
    :pswitch_32
    new-instance v0, Landroidx/fragment/app/c;

    .line 1295
    .line 1296
    invoke-direct {v0, v1}, Landroidx/fragment/app/c;-><init>(Landroid/os/Parcel;)V

    .line 1297
    .line 1298
    .line 1299
    return-object v0

    .line 1300
    :pswitch_33
    new-instance v0, Landroidx/fragment/app/b;

    .line 1301
    .line 1302
    invoke-direct {v0, v1}, Landroidx/fragment/app/b;-><init>(Landroid/os/Parcel;)V

    .line 1303
    .line 1304
    .line 1305
    return-object v0

    .line 1306
    :pswitch_34
    invoke-static {v1}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 1307
    .line 1308
    .line 1309
    move-result v0

    .line 1310
    new-instance v3, Ljava/util/ArrayList;

    .line 1311
    .line 1312
    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    .line 1313
    .line 1314
    .line 1315
    const/4 v2, 0x0

    .line 1316
    const/4 v4, 0x0

    .line 1317
    const/4 v5, 0x0

    .line 1318
    move-object v12, v2

    .line 1319
    move v6, v4

    .line 1320
    move v8, v6

    .line 1321
    move v9, v8

    .line 1322
    move v10, v9

    .line 1323
    move v11, v10

    .line 1324
    move v7, v5

    .line 1325
    move v5, v11

    .line 1326
    move v4, v7

    .line 1327
    :goto_10
    invoke-virtual {v1}, Landroid/os/Parcel;->dataPosition()I

    .line 1328
    .line 1329
    .line 1330
    move-result v13

    .line 1331
    if-ge v13, v0, :cond_37

    .line 1332
    .line 1333
    invoke-virtual {v1}, Landroid/os/Parcel;->readInt()I

    .line 1334
    .line 1335
    .line 1336
    move-result v13

    .line 1337
    int-to-char v14, v13

    .line 1338
    packed-switch v14, :pswitch_data_3

    .line 1339
    .line 1340
    .line 1341
    invoke-static {v1, v13}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 1342
    .line 1343
    .line 1344
    goto :goto_10

    .line 1345
    :pswitch_35
    sget-object v12, Lsp/m;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 1346
    .line 1347
    invoke-static {v1, v13, v12}, Ljp/xb;->j(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Ljava/util/ArrayList;

    .line 1348
    .line 1349
    .line 1350
    move-result-object v12

    .line 1351
    goto :goto_10

    .line 1352
    :pswitch_36
    invoke-static {v1, v13}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 1353
    .line 1354
    .line 1355
    move-result v11

    .line 1356
    goto :goto_10

    .line 1357
    :pswitch_37
    invoke-static {v1, v13}, Ljp/xb;->l(Landroid/os/Parcel;I)Z

    .line 1358
    .line 1359
    .line 1360
    move-result v10

    .line 1361
    goto :goto_10

    .line 1362
    :pswitch_38
    invoke-static {v1, v13}, Ljp/xb;->l(Landroid/os/Parcel;I)Z

    .line 1363
    .line 1364
    .line 1365
    move-result v9

    .line 1366
    goto :goto_10

    .line 1367
    :pswitch_39
    invoke-static {v1, v13}, Ljp/xb;->l(Landroid/os/Parcel;I)Z

    .line 1368
    .line 1369
    .line 1370
    move-result v8

    .line 1371
    goto :goto_10

    .line 1372
    :pswitch_3a
    invoke-static {v1, v13}, Ljp/xb;->o(Landroid/os/Parcel;I)F

    .line 1373
    .line 1374
    .line 1375
    move-result v7

    .line 1376
    goto :goto_10

    .line 1377
    :pswitch_3b
    invoke-static {v1, v13}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 1378
    .line 1379
    .line 1380
    move-result v6

    .line 1381
    goto :goto_10

    .line 1382
    :pswitch_3c
    invoke-static {v1, v13}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 1383
    .line 1384
    .line 1385
    move-result v5

    .line 1386
    goto :goto_10

    .line 1387
    :pswitch_3d
    invoke-static {v1, v13}, Ljp/xb;->o(Landroid/os/Parcel;I)F

    .line 1388
    .line 1389
    .line 1390
    move-result v4

    .line 1391
    goto :goto_10

    .line 1392
    :pswitch_3e
    const-class v14, Lsp/w;

    .line 1393
    .line 1394
    invoke-virtual {v14}, Ljava/lang/Class;->getClassLoader()Ljava/lang/ClassLoader;

    .line 1395
    .line 1396
    .line 1397
    move-result-object v14

    .line 1398
    invoke-static {v1, v13}, Ljp/xb;->u(Landroid/os/Parcel;I)I

    .line 1399
    .line 1400
    .line 1401
    move-result v13

    .line 1402
    invoke-virtual {v1}, Landroid/os/Parcel;->dataPosition()I

    .line 1403
    .line 1404
    .line 1405
    move-result v15

    .line 1406
    if-nez v13, :cond_36

    .line 1407
    .line 1408
    goto :goto_10

    .line 1409
    :cond_36
    invoke-virtual {v1, v3, v14}, Landroid/os/Parcel;->readList(Ljava/util/List;Ljava/lang/ClassLoader;)V

    .line 1410
    .line 1411
    .line 1412
    add-int/2addr v15, v13

    .line 1413
    invoke-virtual {v1, v15}, Landroid/os/Parcel;->setDataPosition(I)V

    .line 1414
    .line 1415
    .line 1416
    goto :goto_10

    .line 1417
    :pswitch_3f
    sget-object v2, Lcom/google/android/gms/maps/model/LatLng;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 1418
    .line 1419
    invoke-static {v1, v13, v2}, Ljp/xb;->j(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Ljava/util/ArrayList;

    .line 1420
    .line 1421
    .line 1422
    move-result-object v2

    .line 1423
    goto :goto_10

    .line 1424
    :cond_37
    invoke-static {v1, v0}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 1425
    .line 1426
    .line 1427
    new-instance v1, Lsp/p;

    .line 1428
    .line 1429
    invoke-direct/range {v1 .. v12}, Lsp/p;-><init>(Ljava/util/ArrayList;Ljava/util/ArrayList;FIIFZZZILjava/util/ArrayList;)V

    .line 1430
    .line 1431
    .line 1432
    return-object v1

    .line 1433
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_34
        :pswitch_33
        :pswitch_32
        :pswitch_31
        :pswitch_30
        :pswitch_2f
        :pswitch_2e
        :pswitch_2d
        :pswitch_2c
        :pswitch_19
        :pswitch_18
        :pswitch_17
        :pswitch_16
        :pswitch_15
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

    .line 1434
    .line 1435
    .line 1436
    .line 1437
    .line 1438
    .line 1439
    .line 1440
    .line 1441
    .line 1442
    .line 1443
    .line 1444
    .line 1445
    .line 1446
    .line 1447
    .line 1448
    .line 1449
    .line 1450
    .line 1451
    .line 1452
    .line 1453
    .line 1454
    .line 1455
    .line 1456
    .line 1457
    .line 1458
    .line 1459
    .line 1460
    .line 1461
    .line 1462
    .line 1463
    .line 1464
    .line 1465
    .line 1466
    .line 1467
    .line 1468
    .line 1469
    .line 1470
    .line 1471
    .line 1472
    .line 1473
    .line 1474
    .line 1475
    .line 1476
    .line 1477
    .line 1478
    .line 1479
    .line 1480
    .line 1481
    .line 1482
    .line 1483
    .line 1484
    .line 1485
    .line 1486
    .line 1487
    .line 1488
    .line 1489
    .line 1490
    .line 1491
    .line 1492
    .line 1493
    .line 1494
    .line 1495
    :pswitch_data_1
    .packed-switch 0x1
        :pswitch_14
        :pswitch_13
        :pswitch_12
        :pswitch_11
        :pswitch_10
        :pswitch_f
    .end packed-switch

    .line 1496
    .line 1497
    .line 1498
    .line 1499
    .line 1500
    .line 1501
    .line 1502
    .line 1503
    .line 1504
    .line 1505
    .line 1506
    .line 1507
    .line 1508
    .line 1509
    .line 1510
    .line 1511
    :pswitch_data_2
    .packed-switch 0x2
        :pswitch_2b
        :pswitch_2a
        :pswitch_29
        :pswitch_28
        :pswitch_27
        :pswitch_26
        :pswitch_25
        :pswitch_24
        :pswitch_23
        :pswitch_22
        :pswitch_21
        :pswitch_20
        :pswitch_1f
        :pswitch_1e
        :pswitch_1d
        :pswitch_1c
        :pswitch_1b
        :pswitch_1a
    .end packed-switch

    .line 1512
    .line 1513
    .line 1514
    .line 1515
    .line 1516
    .line 1517
    .line 1518
    .line 1519
    .line 1520
    .line 1521
    .line 1522
    .line 1523
    .line 1524
    .line 1525
    .line 1526
    .line 1527
    .line 1528
    .line 1529
    .line 1530
    .line 1531
    .line 1532
    .line 1533
    .line 1534
    .line 1535
    .line 1536
    .line 1537
    .line 1538
    .line 1539
    .line 1540
    .line 1541
    .line 1542
    .line 1543
    .line 1544
    .line 1545
    .line 1546
    .line 1547
    .line 1548
    .line 1549
    .line 1550
    .line 1551
    :pswitch_data_3
    .packed-switch 0x2
        :pswitch_3f
        :pswitch_3e
        :pswitch_3d
        :pswitch_3c
        :pswitch_3b
        :pswitch_3a
        :pswitch_39
        :pswitch_38
        :pswitch_37
        :pswitch_36
        :pswitch_35
    .end packed-switch
.end method

.method public final newArray(I)[Ljava/lang/Object;
    .locals 0

    .line 1
    iget p0, p0, Lsp/w;->a:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-array p0, p1, [Lcq/g;

    .line 7
    .line 8
    return-object p0

    .line 9
    :pswitch_0
    new-array p0, p1, [Lcq/c;

    .line 10
    .line 11
    return-object p0

    .line 12
    :pswitch_1
    new-array p0, p1, [Lcq/f;

    .line 13
    .line 14
    return-object p0

    .line 15
    :pswitch_2
    new-array p0, p1, [Lcq/e;

    .line 16
    .line 17
    return-object p0

    .line 18
    :pswitch_3
    new-array p0, p1, [Lcq/d;

    .line 19
    .line 20
    return-object p0

    .line 21
    :pswitch_4
    new-array p0, p1, [Lcq/b;

    .line 22
    .line 23
    return-object p0

    .line 24
    :pswitch_5
    new-array p0, p1, [Lcom/google/firebase/messaging/v;

    .line 25
    .line 26
    return-object p0

    .line 27
    :pswitch_6
    new-array p0, p1, [Lcom/google/android/material/timepicker/l;

    .line 28
    .line 29
    return-object p0

    .line 30
    :pswitch_7
    new-array p0, p1, [Lcom/google/android/material/datepicker/k0;

    .line 31
    .line 32
    return-object p0

    .line 33
    :pswitch_8
    new-array p0, p1, [Lcom/google/android/material/datepicker/i0;

    .line 34
    .line 35
    return-object p0

    .line 36
    :pswitch_9
    new-array p0, p1, [Lcom/google/android/material/datepicker/b0;

    .line 37
    .line 38
    return-object p0

    .line 39
    :pswitch_a
    new-array p0, p1, [Lcom/google/android/material/datepicker/k;

    .line 40
    .line 41
    return-object p0

    .line 42
    :pswitch_b
    new-array p0, p1, [Lcom/google/android/material/datepicker/j;

    .line 43
    .line 44
    return-object p0

    .line 45
    :pswitch_c
    new-array p0, p1, [Lcom/google/android/material/datepicker/c;

    .line 46
    .line 47
    return-object p0

    .line 48
    :pswitch_d
    new-array p0, p1, [Lcom/auth0/android/jwt/c;

    .line 49
    .line 50
    return-object p0

    .line 51
    :pswitch_e
    new-array p0, p1, [Lcom/google/android/gms/wearable/Term;

    .line 52
    .line 53
    return-object p0

    .line 54
    :pswitch_f
    new-array p0, p1, [Lbq/e;

    .line 55
    .line 56
    return-object p0

    .line 57
    :pswitch_10
    new-array p0, p1, [Lbq/j;

    .line 58
    .line 59
    return-object p0

    .line 60
    :pswitch_11
    new-array p0, p1, [Lbq/i;

    .line 61
    .line 62
    return-object p0

    .line 63
    :pswitch_12
    new-array p0, p1, [Lbq/h;

    .line 64
    .line 65
    return-object p0

    .line 66
    :pswitch_13
    new-array p0, p1, [Lcom/google/android/gms/wearable/ConnectionConfiguration;

    .line 67
    .line 68
    return-object p0

    .line 69
    :pswitch_14
    new-array p0, p1, [Lcom/google/android/gms/wearable/Asset;

    .line 70
    .line 71
    return-object p0

    .line 72
    :pswitch_15
    new-array p0, p1, [Lcom/google/android/gms/wearable/AppTheme;

    .line 73
    .line 74
    return-object p0

    .line 75
    :pswitch_16
    new-array p0, p1, [Lbp/p;

    .line 76
    .line 77
    return-object p0

    .line 78
    :pswitch_17
    new-array p0, p1, [Landroidx/fragment/app/p1;

    .line 79
    .line 80
    return-object p0

    .line 81
    :pswitch_18
    new-array p0, p1, [Landroidx/fragment/app/l1;

    .line 82
    .line 83
    return-object p0

    .line 84
    :pswitch_19
    new-array p0, p1, [Landroidx/fragment/app/f1;

    .line 85
    .line 86
    return-object p0

    .line 87
    :pswitch_1a
    new-array p0, p1, [Landroidx/fragment/app/c;

    .line 88
    .line 89
    return-object p0

    .line 90
    :pswitch_1b
    new-array p0, p1, [Landroidx/fragment/app/b;

    .line 91
    .line 92
    return-object p0

    .line 93
    :pswitch_1c
    new-array p0, p1, [Lsp/p;

    .line 94
    .line 95
    return-object p0

    .line 96
    nop

    .line 97
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
