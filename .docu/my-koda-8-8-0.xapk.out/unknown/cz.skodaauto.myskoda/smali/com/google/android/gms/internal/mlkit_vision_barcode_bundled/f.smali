.class public final Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/f;
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
    iput p1, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/f;->a:I

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
    .locals 20

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    iget v0, v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/f;->a:I

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
    const-wide/16 v2, 0x0

    .line 15
    .line 16
    const/4 v4, 0x0

    .line 17
    move-wide v6, v2

    .line 18
    move v8, v4

    .line 19
    move v9, v8

    .line 20
    move v10, v9

    .line 21
    move v11, v10

    .line 22
    :goto_0
    invoke-virtual {v1}, Landroid/os/Parcel;->dataPosition()I

    .line 23
    .line 24
    .line 25
    move-result v2

    .line 26
    if-ge v2, v0, :cond_5

    .line 27
    .line 28
    invoke-virtual {v1}, Landroid/os/Parcel;->readInt()I

    .line 29
    .line 30
    .line 31
    move-result v2

    .line 32
    int-to-char v3, v2

    .line 33
    const/4 v4, 0x1

    .line 34
    if-eq v3, v4, :cond_4

    .line 35
    .line 36
    const/4 v4, 0x2

    .line 37
    if-eq v3, v4, :cond_3

    .line 38
    .line 39
    const/4 v4, 0x3

    .line 40
    if-eq v3, v4, :cond_2

    .line 41
    .line 42
    const/4 v4, 0x4

    .line 43
    if-eq v3, v4, :cond_1

    .line 44
    .line 45
    const/4 v4, 0x5

    .line 46
    if-eq v3, v4, :cond_0

    .line 47
    .line 48
    invoke-static {v1, v2}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 49
    .line 50
    .line 51
    goto :goto_0

    .line 52
    :cond_0
    invoke-static {v1, v2}, Ljp/xb;->s(Landroid/os/Parcel;I)J

    .line 53
    .line 54
    .line 55
    move-result-wide v2

    .line 56
    move-wide v6, v2

    .line 57
    goto :goto_0

    .line 58
    :cond_1
    invoke-static {v1, v2}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 59
    .line 60
    .line 61
    move-result v2

    .line 62
    move v11, v2

    .line 63
    goto :goto_0

    .line 64
    :cond_2
    invoke-static {v1, v2}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 65
    .line 66
    .line 67
    move-result v2

    .line 68
    move v10, v2

    .line 69
    goto :goto_0

    .line 70
    :cond_3
    invoke-static {v1, v2}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 71
    .line 72
    .line 73
    move-result v2

    .line 74
    move v9, v2

    .line 75
    goto :goto_0

    .line 76
    :cond_4
    invoke-static {v1, v2}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 77
    .line 78
    .line 79
    move-result v2

    .line 80
    move v8, v2

    .line 81
    goto :goto_0

    .line 82
    :cond_5
    invoke-static {v1, v0}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 83
    .line 84
    .line 85
    new-instance v5, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/f0;

    .line 86
    .line 87
    invoke-direct/range {v5 .. v11}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/f0;-><init>(JIIII)V

    .line 88
    .line 89
    .line 90
    return-object v5

    .line 91
    :pswitch_0
    invoke-static {v1}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 92
    .line 93
    .line 94
    move-result v0

    .line 95
    const/4 v2, 0x0

    .line 96
    const/4 v3, 0x0

    .line 97
    move-object v4, v3

    .line 98
    :goto_1
    invoke-virtual {v1}, Landroid/os/Parcel;->dataPosition()I

    .line 99
    .line 100
    .line 101
    move-result v5

    .line 102
    if-ge v5, v0, :cond_9

    .line 103
    .line 104
    invoke-virtual {v1}, Landroid/os/Parcel;->readInt()I

    .line 105
    .line 106
    .line 107
    move-result v5

    .line 108
    int-to-char v6, v5

    .line 109
    const/4 v7, 0x1

    .line 110
    if-eq v6, v7, :cond_8

    .line 111
    .line 112
    const/4 v7, 0x2

    .line 113
    if-eq v6, v7, :cond_7

    .line 114
    .line 115
    const/4 v7, 0x3

    .line 116
    if-eq v6, v7, :cond_6

    .line 117
    .line 118
    invoke-static {v1, v5}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 119
    .line 120
    .line 121
    goto :goto_1

    .line 122
    :cond_6
    invoke-static {v1, v5}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 123
    .line 124
    .line 125
    move-result v2

    .line 126
    goto :goto_1

    .line 127
    :cond_7
    invoke-static {v1, v5}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 128
    .line 129
    .line 130
    move-result-object v4

    .line 131
    goto :goto_1

    .line 132
    :cond_8
    invoke-static {v1, v5}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 133
    .line 134
    .line 135
    move-result-object v3

    .line 136
    goto :goto_1

    .line 137
    :cond_9
    invoke-static {v1, v0}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 138
    .line 139
    .line 140
    new-instance v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/r;

    .line 141
    .line 142
    invoke-direct {v0, v3, v4, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/r;-><init>(Ljava/lang/String;Ljava/lang/String;I)V

    .line 143
    .line 144
    .line 145
    return-object v0

    .line 146
    :pswitch_1
    invoke-static {v1}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 147
    .line 148
    .line 149
    move-result v0

    .line 150
    const/4 v2, 0x0

    .line 151
    move-object v3, v2

    .line 152
    :goto_2
    invoke-virtual {v1}, Landroid/os/Parcel;->dataPosition()I

    .line 153
    .line 154
    .line 155
    move-result v4

    .line 156
    if-ge v4, v0, :cond_c

    .line 157
    .line 158
    invoke-virtual {v1}, Landroid/os/Parcel;->readInt()I

    .line 159
    .line 160
    .line 161
    move-result v4

    .line 162
    int-to-char v5, v4

    .line 163
    const/4 v6, 0x1

    .line 164
    if-eq v5, v6, :cond_b

    .line 165
    .line 166
    const/4 v6, 0x2

    .line 167
    if-eq v5, v6, :cond_a

    .line 168
    .line 169
    invoke-static {v1, v4}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 170
    .line 171
    .line 172
    goto :goto_2

    .line 173
    :cond_a
    invoke-static {v1, v4}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 174
    .line 175
    .line 176
    move-result-object v3

    .line 177
    goto :goto_2

    .line 178
    :cond_b
    invoke-static {v1, v4}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 179
    .line 180
    .line 181
    move-result-object v2

    .line 182
    goto :goto_2

    .line 183
    :cond_c
    invoke-static {v1, v0}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 184
    .line 185
    .line 186
    new-instance v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q;

    .line 187
    .line 188
    invoke-direct {v0, v2, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 189
    .line 190
    .line 191
    return-object v0

    .line 192
    :pswitch_2
    invoke-static {v1}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 193
    .line 194
    .line 195
    move-result v0

    .line 196
    const/4 v2, 0x0

    .line 197
    move-object v3, v2

    .line 198
    :goto_3
    invoke-virtual {v1}, Landroid/os/Parcel;->dataPosition()I

    .line 199
    .line 200
    .line 201
    move-result v4

    .line 202
    if-ge v4, v0, :cond_f

    .line 203
    .line 204
    invoke-virtual {v1}, Landroid/os/Parcel;->readInt()I

    .line 205
    .line 206
    .line 207
    move-result v4

    .line 208
    int-to-char v5, v4

    .line 209
    const/4 v6, 0x1

    .line 210
    if-eq v5, v6, :cond_e

    .line 211
    .line 212
    const/4 v6, 0x2

    .line 213
    if-eq v5, v6, :cond_d

    .line 214
    .line 215
    invoke-static {v1, v4}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 216
    .line 217
    .line 218
    goto :goto_3

    .line 219
    :cond_d
    invoke-static {v1, v4}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 220
    .line 221
    .line 222
    move-result-object v3

    .line 223
    goto :goto_3

    .line 224
    :cond_e
    invoke-static {v1, v4}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 225
    .line 226
    .line 227
    move-result-object v2

    .line 228
    goto :goto_3

    .line 229
    :cond_f
    invoke-static {v1, v0}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 230
    .line 231
    .line 232
    new-instance v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/p;

    .line 233
    .line 234
    invoke-direct {v0, v2, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/p;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 235
    .line 236
    .line 237
    return-object v0

    .line 238
    :pswitch_3
    invoke-static {v1}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 239
    .line 240
    .line 241
    move-result v0

    .line 242
    const/4 v2, 0x0

    .line 243
    const/4 v3, 0x0

    .line 244
    :goto_4
    invoke-virtual {v1}, Landroid/os/Parcel;->dataPosition()I

    .line 245
    .line 246
    .line 247
    move-result v4

    .line 248
    if-ge v4, v0, :cond_12

    .line 249
    .line 250
    invoke-virtual {v1}, Landroid/os/Parcel;->readInt()I

    .line 251
    .line 252
    .line 253
    move-result v4

    .line 254
    int-to-char v5, v4

    .line 255
    const/4 v6, 0x1

    .line 256
    if-eq v5, v6, :cond_11

    .line 257
    .line 258
    const/4 v6, 0x2

    .line 259
    if-eq v5, v6, :cond_10

    .line 260
    .line 261
    invoke-static {v1, v4}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 262
    .line 263
    .line 264
    goto :goto_4

    .line 265
    :cond_10
    invoke-static {v1, v4}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 266
    .line 267
    .line 268
    move-result-object v2

    .line 269
    goto :goto_4

    .line 270
    :cond_11
    invoke-static {v1, v4}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 271
    .line 272
    .line 273
    move-result v3

    .line 274
    goto :goto_4

    .line 275
    :cond_12
    invoke-static {v1, v0}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 276
    .line 277
    .line 278
    new-instance v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/o;

    .line 279
    .line 280
    invoke-direct {v0, v3, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/o;-><init>(ILjava/lang/String;)V

    .line 281
    .line 282
    .line 283
    return-object v0

    .line 284
    :pswitch_4
    invoke-static {v1}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 285
    .line 286
    .line 287
    move-result v0

    .line 288
    const/4 v2, 0x0

    .line 289
    move-object v4, v2

    .line 290
    move-object v5, v4

    .line 291
    move-object v6, v5

    .line 292
    move-object v7, v6

    .line 293
    move-object v8, v7

    .line 294
    move-object v9, v8

    .line 295
    move-object v10, v9

    .line 296
    :goto_5
    invoke-virtual {v1}, Landroid/os/Parcel;->dataPosition()I

    .line 297
    .line 298
    .line 299
    move-result v2

    .line 300
    if-ge v2, v0, :cond_13

    .line 301
    .line 302
    invoke-virtual {v1}, Landroid/os/Parcel;->readInt()I

    .line 303
    .line 304
    .line 305
    move-result v2

    .line 306
    int-to-char v3, v2

    .line 307
    packed-switch v3, :pswitch_data_1

    .line 308
    .line 309
    .line 310
    invoke-static {v1, v2}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 311
    .line 312
    .line 313
    goto :goto_5

    .line 314
    :pswitch_5
    invoke-static {v1, v2}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 315
    .line 316
    .line 317
    move-result-object v10

    .line 318
    goto :goto_5

    .line 319
    :pswitch_6
    invoke-static {v1, v2}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 320
    .line 321
    .line 322
    move-result-object v9

    .line 323
    goto :goto_5

    .line 324
    :pswitch_7
    invoke-static {v1, v2}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 325
    .line 326
    .line 327
    move-result-object v8

    .line 328
    goto :goto_5

    .line 329
    :pswitch_8
    invoke-static {v1, v2}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 330
    .line 331
    .line 332
    move-result-object v7

    .line 333
    goto :goto_5

    .line 334
    :pswitch_9
    invoke-static {v1, v2}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 335
    .line 336
    .line 337
    move-result-object v6

    .line 338
    goto :goto_5

    .line 339
    :pswitch_a
    invoke-static {v1, v2}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 340
    .line 341
    .line 342
    move-result-object v5

    .line 343
    goto :goto_5

    .line 344
    :pswitch_b
    invoke-static {v1, v2}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 345
    .line 346
    .line 347
    move-result-object v4

    .line 348
    goto :goto_5

    .line 349
    :cond_13
    invoke-static {v1, v0}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 350
    .line 351
    .line 352
    new-instance v3, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n;

    .line 353
    .line 354
    invoke-direct/range {v3 .. v10}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 355
    .line 356
    .line 357
    return-object v3

    .line 358
    :pswitch_c
    invoke-static {v1}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 359
    .line 360
    .line 361
    move-result v0

    .line 362
    const/4 v2, 0x0

    .line 363
    :goto_6
    move-object v3, v2

    .line 364
    :goto_7
    invoke-virtual {v1}, Landroid/os/Parcel;->dataPosition()I

    .line 365
    .line 366
    .line 367
    move-result v4

    .line 368
    if-ge v4, v0, :cond_16

    .line 369
    .line 370
    invoke-virtual {v1}, Landroid/os/Parcel;->readInt()I

    .line 371
    .line 372
    .line 373
    move-result v4

    .line 374
    int-to-char v5, v4

    .line 375
    const/4 v6, 0x1

    .line 376
    if-eq v5, v6, :cond_14

    .line 377
    .line 378
    invoke-static {v1, v4}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 379
    .line 380
    .line 381
    goto :goto_7

    .line 382
    :cond_14
    invoke-static {v1, v4}, Ljp/xb;->u(Landroid/os/Parcel;I)I

    .line 383
    .line 384
    .line 385
    move-result v3

    .line 386
    invoke-virtual {v1}, Landroid/os/Parcel;->dataPosition()I

    .line 387
    .line 388
    .line 389
    move-result v4

    .line 390
    if-nez v3, :cond_15

    .line 391
    .line 392
    goto :goto_6

    .line 393
    :cond_15
    invoke-virtual {v1}, Landroid/os/Parcel;->createFloatArray()[F

    .line 394
    .line 395
    .line 396
    move-result-object v5

    .line 397
    add-int/2addr v4, v3

    .line 398
    invoke-virtual {v1, v4}, Landroid/os/Parcel;->setDataPosition(I)V

    .line 399
    .line 400
    .line 401
    move-object v3, v5

    .line 402
    goto :goto_7

    .line 403
    :cond_16
    invoke-static {v1, v0}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 404
    .line 405
    .line 406
    new-instance v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/d0;

    .line 407
    .line 408
    invoke-direct {v0, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/d0;-><init>([F)V

    .line 409
    .line 410
    .line 411
    return-object v0

    .line 412
    :pswitch_d
    invoke-static {v1}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 413
    .line 414
    .line 415
    move-result v0

    .line 416
    const/4 v2, 0x0

    .line 417
    const/4 v3, 0x0

    .line 418
    move v4, v2

    .line 419
    :goto_8
    move-object v5, v3

    .line 420
    :goto_9
    invoke-virtual {v1}, Landroid/os/Parcel;->dataPosition()I

    .line 421
    .line 422
    .line 423
    move-result v6

    .line 424
    if-ge v6, v0, :cond_1b

    .line 425
    .line 426
    invoke-virtual {v1}, Landroid/os/Parcel;->readInt()I

    .line 427
    .line 428
    .line 429
    move-result v6

    .line 430
    int-to-char v7, v6

    .line 431
    const/4 v8, 0x1

    .line 432
    if-eq v7, v8, :cond_19

    .line 433
    .line 434
    const/4 v8, 0x2

    .line 435
    if-eq v7, v8, :cond_18

    .line 436
    .line 437
    const/4 v8, 0x3

    .line 438
    if-eq v7, v8, :cond_17

    .line 439
    .line 440
    invoke-static {v1, v6}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 441
    .line 442
    .line 443
    goto :goto_9

    .line 444
    :cond_17
    invoke-static {v1, v6}, Ljp/xb;->l(Landroid/os/Parcel;I)Z

    .line 445
    .line 446
    .line 447
    move-result v4

    .line 448
    goto :goto_9

    .line 449
    :cond_18
    invoke-static {v1, v6}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 450
    .line 451
    .line 452
    move-result v2

    .line 453
    goto :goto_9

    .line 454
    :cond_19
    invoke-static {v1, v6}, Ljp/xb;->u(Landroid/os/Parcel;I)I

    .line 455
    .line 456
    .line 457
    move-result v5

    .line 458
    invoke-virtual {v1}, Landroid/os/Parcel;->dataPosition()I

    .line 459
    .line 460
    .line 461
    move-result v6

    .line 462
    if-nez v5, :cond_1a

    .line 463
    .line 464
    goto :goto_8

    .line 465
    :cond_1a
    invoke-virtual {v1}, Landroid/os/Parcel;->createFloatArray()[F

    .line 466
    .line 467
    .line 468
    move-result-object v7

    .line 469
    add-int/2addr v6, v5

    .line 470
    invoke-virtual {v1, v6}, Landroid/os/Parcel;->setDataPosition(I)V

    .line 471
    .line 472
    .line 473
    move-object v5, v7

    .line 474
    goto :goto_9

    .line 475
    :cond_1b
    invoke-static {v1, v0}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 476
    .line 477
    .line 478
    new-instance v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c0;

    .line 479
    .line 480
    invoke-direct {v0, v5, v2, v4}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c0;-><init>([FIZ)V

    .line 481
    .line 482
    .line 483
    return-object v0

    .line 484
    :pswitch_e
    invoke-static {v1}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 485
    .line 486
    .line 487
    move-result v0

    .line 488
    const/4 v2, 0x0

    .line 489
    const/4 v3, 0x0

    .line 490
    const/4 v4, 0x0

    .line 491
    move v6, v2

    .line 492
    move v8, v6

    .line 493
    move v10, v8

    .line 494
    move v9, v3

    .line 495
    move-object v7, v4

    .line 496
    :goto_a
    invoke-virtual {v1}, Landroid/os/Parcel;->dataPosition()I

    .line 497
    .line 498
    .line 499
    move-result v2

    .line 500
    if-ge v2, v0, :cond_21

    .line 501
    .line 502
    invoke-virtual {v1}, Landroid/os/Parcel;->readInt()I

    .line 503
    .line 504
    .line 505
    move-result v2

    .line 506
    int-to-char v3, v2

    .line 507
    const/4 v4, 0x1

    .line 508
    if-eq v3, v4, :cond_20

    .line 509
    .line 510
    const/4 v4, 0x2

    .line 511
    if-eq v3, v4, :cond_1f

    .line 512
    .line 513
    const/4 v4, 0x3

    .line 514
    if-eq v3, v4, :cond_1e

    .line 515
    .line 516
    const/4 v4, 0x4

    .line 517
    if-eq v3, v4, :cond_1d

    .line 518
    .line 519
    const/4 v4, 0x5

    .line 520
    if-eq v3, v4, :cond_1c

    .line 521
    .line 522
    invoke-static {v1, v2}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 523
    .line 524
    .line 525
    goto :goto_a

    .line 526
    :cond_1c
    invoke-static {v1, v2}, Ljp/xb;->l(Landroid/os/Parcel;I)Z

    .line 527
    .line 528
    .line 529
    move-result v10

    .line 530
    goto :goto_a

    .line 531
    :cond_1d
    invoke-static {v1, v2}, Ljp/xb;->o(Landroid/os/Parcel;I)F

    .line 532
    .line 533
    .line 534
    move-result v9

    .line 535
    goto :goto_a

    .line 536
    :cond_1e
    invoke-static {v1, v2}, Ljp/xb;->l(Landroid/os/Parcel;I)Z

    .line 537
    .line 538
    .line 539
    move-result v8

    .line 540
    goto :goto_a

    .line 541
    :cond_1f
    invoke-static {v1, v2}, Ljp/xb;->b(Landroid/os/Parcel;I)[B

    .line 542
    .line 543
    .line 544
    move-result-object v7

    .line 545
    goto :goto_a

    .line 546
    :cond_20
    invoke-static {v1, v2}, Ljp/xb;->l(Landroid/os/Parcel;I)Z

    .line 547
    .line 548
    .line 549
    move-result v6

    .line 550
    goto :goto_a

    .line 551
    :cond_21
    invoke-static {v1, v0}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 552
    .line 553
    .line 554
    new-instance v5, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b0;

    .line 555
    .line 556
    invoke-direct/range {v5 .. v10}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b0;-><init>(Z[BZFZ)V

    .line 557
    .line 558
    .line 559
    return-object v5

    .line 560
    :pswitch_f
    invoke-static {v1}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 561
    .line 562
    .line 563
    move-result v0

    .line 564
    const-wide/16 v2, 0x0

    .line 565
    .line 566
    move-wide v4, v2

    .line 567
    :goto_b
    invoke-virtual {v1}, Landroid/os/Parcel;->dataPosition()I

    .line 568
    .line 569
    .line 570
    move-result v6

    .line 571
    if-ge v6, v0, :cond_24

    .line 572
    .line 573
    invoke-virtual {v1}, Landroid/os/Parcel;->readInt()I

    .line 574
    .line 575
    .line 576
    move-result v6

    .line 577
    int-to-char v7, v6

    .line 578
    const/4 v8, 0x1

    .line 579
    if-eq v7, v8, :cond_23

    .line 580
    .line 581
    const/4 v8, 0x2

    .line 582
    if-eq v7, v8, :cond_22

    .line 583
    .line 584
    invoke-static {v1, v6}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 585
    .line 586
    .line 587
    goto :goto_b

    .line 588
    :cond_22
    invoke-static {v1, v6}, Ljp/xb;->n(Landroid/os/Parcel;I)D

    .line 589
    .line 590
    .line 591
    move-result-wide v4

    .line 592
    goto :goto_b

    .line 593
    :cond_23
    invoke-static {v1, v6}, Ljp/xb;->n(Landroid/os/Parcel;I)D

    .line 594
    .line 595
    .line 596
    move-result-wide v2

    .line 597
    goto :goto_b

    .line 598
    :cond_24
    invoke-static {v1, v0}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 599
    .line 600
    .line 601
    new-instance v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m;

    .line 602
    .line 603
    invoke-direct {v0, v2, v3, v4, v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m;-><init>(DD)V

    .line 604
    .line 605
    .line 606
    return-object v0

    .line 607
    :pswitch_10
    invoke-static {v1}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 608
    .line 609
    .line 610
    move-result v0

    .line 611
    const/4 v2, 0x0

    .line 612
    const/4 v3, 0x0

    .line 613
    move-object v4, v2

    .line 614
    move v5, v3

    .line 615
    move-object v3, v4

    .line 616
    :goto_c
    invoke-virtual {v1}, Landroid/os/Parcel;->dataPosition()I

    .line 617
    .line 618
    .line 619
    move-result v6

    .line 620
    if-ge v6, v0, :cond_29

    .line 621
    .line 622
    invoke-virtual {v1}, Landroid/os/Parcel;->readInt()I

    .line 623
    .line 624
    .line 625
    move-result v6

    .line 626
    int-to-char v7, v6

    .line 627
    const/4 v8, 0x1

    .line 628
    if-eq v7, v8, :cond_28

    .line 629
    .line 630
    const/4 v8, 0x2

    .line 631
    if-eq v7, v8, :cond_27

    .line 632
    .line 633
    const/4 v8, 0x3

    .line 634
    if-eq v7, v8, :cond_26

    .line 635
    .line 636
    const/4 v8, 0x4

    .line 637
    if-eq v7, v8, :cond_25

    .line 638
    .line 639
    invoke-static {v1, v6}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 640
    .line 641
    .line 642
    goto :goto_c

    .line 643
    :cond_25
    invoke-static {v1, v6}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 644
    .line 645
    .line 646
    move-result-object v4

    .line 647
    goto :goto_c

    .line 648
    :cond_26
    invoke-static {v1, v6}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 649
    .line 650
    .line 651
    move-result-object v3

    .line 652
    goto :goto_c

    .line 653
    :cond_27
    invoke-static {v1, v6}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 654
    .line 655
    .line 656
    move-result-object v2

    .line 657
    goto :goto_c

    .line 658
    :cond_28
    invoke-static {v1, v6}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 659
    .line 660
    .line 661
    move-result v5

    .line 662
    goto :goto_c

    .line 663
    :cond_29
    invoke-static {v1, v0}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 664
    .line 665
    .line 666
    new-instance v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l;

    .line 667
    .line 668
    invoke-direct {v0, v5, v2, v3, v4}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l;-><init>(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 669
    .line 670
    .line 671
    return-object v0

    .line 672
    :pswitch_11
    invoke-static {v1}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 673
    .line 674
    .line 675
    move-result v0

    .line 676
    const/4 v2, 0x0

    .line 677
    move-object v4, v2

    .line 678
    move-object v5, v4

    .line 679
    move-object v6, v5

    .line 680
    move-object v7, v6

    .line 681
    move-object v8, v7

    .line 682
    move-object v9, v8

    .line 683
    move-object v10, v9

    .line 684
    move-object v11, v10

    .line 685
    move-object v12, v11

    .line 686
    move-object v13, v12

    .line 687
    move-object v14, v13

    .line 688
    move-object v15, v14

    .line 689
    move-object/from16 v16, v15

    .line 690
    .line 691
    move-object/from16 v17, v16

    .line 692
    .line 693
    :goto_d
    invoke-virtual {v1}, Landroid/os/Parcel;->dataPosition()I

    .line 694
    .line 695
    .line 696
    move-result v2

    .line 697
    if-ge v2, v0, :cond_2a

    .line 698
    .line 699
    invoke-virtual {v1}, Landroid/os/Parcel;->readInt()I

    .line 700
    .line 701
    .line 702
    move-result v2

    .line 703
    int-to-char v3, v2

    .line 704
    packed-switch v3, :pswitch_data_2

    .line 705
    .line 706
    .line 707
    invoke-static {v1, v2}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 708
    .line 709
    .line 710
    goto :goto_d

    .line 711
    :pswitch_12
    invoke-static {v1, v2}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 712
    .line 713
    .line 714
    move-result-object v17

    .line 715
    goto :goto_d

    .line 716
    :pswitch_13
    invoke-static {v1, v2}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 717
    .line 718
    .line 719
    move-result-object v16

    .line 720
    goto :goto_d

    .line 721
    :pswitch_14
    invoke-static {v1, v2}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 722
    .line 723
    .line 724
    move-result-object v15

    .line 725
    goto :goto_d

    .line 726
    :pswitch_15
    invoke-static {v1, v2}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 727
    .line 728
    .line 729
    move-result-object v14

    .line 730
    goto :goto_d

    .line 731
    :pswitch_16
    invoke-static {v1, v2}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 732
    .line 733
    .line 734
    move-result-object v13

    .line 735
    goto :goto_d

    .line 736
    :pswitch_17
    invoke-static {v1, v2}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 737
    .line 738
    .line 739
    move-result-object v12

    .line 740
    goto :goto_d

    .line 741
    :pswitch_18
    invoke-static {v1, v2}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 742
    .line 743
    .line 744
    move-result-object v11

    .line 745
    goto :goto_d

    .line 746
    :pswitch_19
    invoke-static {v1, v2}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 747
    .line 748
    .line 749
    move-result-object v10

    .line 750
    goto :goto_d

    .line 751
    :pswitch_1a
    invoke-static {v1, v2}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 752
    .line 753
    .line 754
    move-result-object v9

    .line 755
    goto :goto_d

    .line 756
    :pswitch_1b
    invoke-static {v1, v2}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 757
    .line 758
    .line 759
    move-result-object v8

    .line 760
    goto :goto_d

    .line 761
    :pswitch_1c
    invoke-static {v1, v2}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 762
    .line 763
    .line 764
    move-result-object v7

    .line 765
    goto :goto_d

    .line 766
    :pswitch_1d
    invoke-static {v1, v2}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 767
    .line 768
    .line 769
    move-result-object v6

    .line 770
    goto :goto_d

    .line 771
    :pswitch_1e
    invoke-static {v1, v2}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 772
    .line 773
    .line 774
    move-result-object v5

    .line 775
    goto :goto_d

    .line 776
    :pswitch_1f
    invoke-static {v1, v2}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 777
    .line 778
    .line 779
    move-result-object v4

    .line 780
    goto :goto_d

    .line 781
    :cond_2a
    invoke-static {v1, v0}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 782
    .line 783
    .line 784
    new-instance v3, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k;

    .line 785
    .line 786
    invoke-direct/range {v3 .. v17}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 787
    .line 788
    .line 789
    return-object v3

    .line 790
    :pswitch_20
    invoke-static {v1}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 791
    .line 792
    .line 793
    move-result v0

    .line 794
    const/4 v2, 0x0

    .line 795
    move-object v4, v2

    .line 796
    move-object v5, v4

    .line 797
    move-object v6, v5

    .line 798
    move-object v7, v6

    .line 799
    move-object v8, v7

    .line 800
    move-object v9, v8

    .line 801
    move-object v10, v9

    .line 802
    :goto_e
    invoke-virtual {v1}, Landroid/os/Parcel;->dataPosition()I

    .line 803
    .line 804
    .line 805
    move-result v2

    .line 806
    if-ge v2, v0, :cond_2b

    .line 807
    .line 808
    invoke-virtual {v1}, Landroid/os/Parcel;->readInt()I

    .line 809
    .line 810
    .line 811
    move-result v2

    .line 812
    int-to-char v3, v2

    .line 813
    packed-switch v3, :pswitch_data_3

    .line 814
    .line 815
    .line 816
    invoke-static {v1, v2}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 817
    .line 818
    .line 819
    goto :goto_e

    .line 820
    :pswitch_21
    sget-object v3, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 821
    .line 822
    invoke-static {v1, v2, v3}, Ljp/xb;->i(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)[Ljava/lang/Object;

    .line 823
    .line 824
    .line 825
    move-result-object v2

    .line 826
    move-object v10, v2

    .line 827
    check-cast v10, [Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g;

    .line 828
    .line 829
    goto :goto_e

    .line 830
    :pswitch_22
    invoke-static {v1, v2}, Ljp/xb;->g(Landroid/os/Parcel;I)[Ljava/lang/String;

    .line 831
    .line 832
    .line 833
    move-result-object v9

    .line 834
    goto :goto_e

    .line 835
    :pswitch_23
    sget-object v3, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 836
    .line 837
    invoke-static {v1, v2, v3}, Ljp/xb;->i(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)[Ljava/lang/Object;

    .line 838
    .line 839
    .line 840
    move-result-object v2

    .line 841
    move-object v8, v2

    .line 842
    check-cast v8, [Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l;

    .line 843
    .line 844
    goto :goto_e

    .line 845
    :pswitch_24
    sget-object v3, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/o;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 846
    .line 847
    invoke-static {v1, v2, v3}, Ljp/xb;->i(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)[Ljava/lang/Object;

    .line 848
    .line 849
    .line 850
    move-result-object v2

    .line 851
    move-object v7, v2

    .line 852
    check-cast v7, [Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/o;

    .line 853
    .line 854
    goto :goto_e

    .line 855
    :pswitch_25
    invoke-static {v1, v2}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 856
    .line 857
    .line 858
    move-result-object v6

    .line 859
    goto :goto_e

    .line 860
    :pswitch_26
    invoke-static {v1, v2}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 861
    .line 862
    .line 863
    move-result-object v5

    .line 864
    goto :goto_e

    .line 865
    :pswitch_27
    sget-object v3, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 866
    .line 867
    invoke-static {v1, v2, v3}, Ljp/xb;->e(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 868
    .line 869
    .line 870
    move-result-object v2

    .line 871
    move-object v4, v2

    .line 872
    check-cast v4, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n;

    .line 873
    .line 874
    goto :goto_e

    .line 875
    :cond_2b
    invoke-static {v1, v0}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 876
    .line 877
    .line 878
    new-instance v3, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j;

    .line 879
    .line 880
    invoke-direct/range {v3 .. v10}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j;-><init>(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n;Ljava/lang/String;Ljava/lang/String;[Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/o;[Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l;[Ljava/lang/String;[Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g;)V

    .line 881
    .line 882
    .line 883
    return-object v3

    .line 884
    :pswitch_28
    invoke-static {v1}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 885
    .line 886
    .line 887
    move-result v0

    .line 888
    const/4 v2, 0x0

    .line 889
    move-object v4, v2

    .line 890
    move-object v5, v4

    .line 891
    move-object v6, v5

    .line 892
    move-object v7, v6

    .line 893
    move-object v8, v7

    .line 894
    move-object v9, v8

    .line 895
    move-object v10, v9

    .line 896
    :goto_f
    invoke-virtual {v1}, Landroid/os/Parcel;->dataPosition()I

    .line 897
    .line 898
    .line 899
    move-result v2

    .line 900
    if-ge v2, v0, :cond_2c

    .line 901
    .line 902
    invoke-virtual {v1}, Landroid/os/Parcel;->readInt()I

    .line 903
    .line 904
    .line 905
    move-result v2

    .line 906
    int-to-char v3, v2

    .line 907
    packed-switch v3, :pswitch_data_4

    .line 908
    .line 909
    .line 910
    invoke-static {v1, v2}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 911
    .line 912
    .line 913
    goto :goto_f

    .line 914
    :pswitch_29
    sget-object v3, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 915
    .line 916
    invoke-static {v1, v2, v3}, Ljp/xb;->e(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 917
    .line 918
    .line 919
    move-result-object v2

    .line 920
    move-object v10, v2

    .line 921
    check-cast v10, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h;

    .line 922
    .line 923
    goto :goto_f

    .line 924
    :pswitch_2a
    sget-object v3, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 925
    .line 926
    invoke-static {v1, v2, v3}, Ljp/xb;->e(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 927
    .line 928
    .line 929
    move-result-object v2

    .line 930
    move-object v9, v2

    .line 931
    check-cast v9, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h;

    .line 932
    .line 933
    goto :goto_f

    .line 934
    :pswitch_2b
    invoke-static {v1, v2}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 935
    .line 936
    .line 937
    move-result-object v8

    .line 938
    goto :goto_f

    .line 939
    :pswitch_2c
    invoke-static {v1, v2}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 940
    .line 941
    .line 942
    move-result-object v7

    .line 943
    goto :goto_f

    .line 944
    :pswitch_2d
    invoke-static {v1, v2}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 945
    .line 946
    .line 947
    move-result-object v6

    .line 948
    goto :goto_f

    .line 949
    :pswitch_2e
    invoke-static {v1, v2}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 950
    .line 951
    .line 952
    move-result-object v5

    .line 953
    goto :goto_f

    .line 954
    :pswitch_2f
    invoke-static {v1, v2}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 955
    .line 956
    .line 957
    move-result-object v4

    .line 958
    goto :goto_f

    .line 959
    :cond_2c
    invoke-static {v1, v0}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 960
    .line 961
    .line 962
    new-instance v3, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/i;

    .line 963
    .line 964
    invoke-direct/range {v3 .. v10}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/i;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h;)V

    .line 965
    .line 966
    .line 967
    return-object v3

    .line 968
    :pswitch_30
    invoke-static {v1}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 969
    .line 970
    .line 971
    move-result v0

    .line 972
    const/4 v2, 0x0

    .line 973
    const/4 v3, 0x0

    .line 974
    move-object v12, v2

    .line 975
    move v5, v3

    .line 976
    move v6, v5

    .line 977
    move v7, v6

    .line 978
    move v8, v7

    .line 979
    move v9, v8

    .line 980
    move v10, v9

    .line 981
    move v11, v10

    .line 982
    :goto_10
    invoke-virtual {v1}, Landroid/os/Parcel;->dataPosition()I

    .line 983
    .line 984
    .line 985
    move-result v2

    .line 986
    if-ge v2, v0, :cond_2d

    .line 987
    .line 988
    invoke-virtual {v1}, Landroid/os/Parcel;->readInt()I

    .line 989
    .line 990
    .line 991
    move-result v2

    .line 992
    int-to-char v3, v2

    .line 993
    packed-switch v3, :pswitch_data_5

    .line 994
    .line 995
    .line 996
    invoke-static {v1, v2}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 997
    .line 998
    .line 999
    goto :goto_10

    .line 1000
    :pswitch_31
    invoke-static {v1, v2}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 1001
    .line 1002
    .line 1003
    move-result-object v12

    .line 1004
    goto :goto_10

    .line 1005
    :pswitch_32
    invoke-static {v1, v2}, Ljp/xb;->l(Landroid/os/Parcel;I)Z

    .line 1006
    .line 1007
    .line 1008
    move-result v11

    .line 1009
    goto :goto_10

    .line 1010
    :pswitch_33
    invoke-static {v1, v2}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 1011
    .line 1012
    .line 1013
    move-result v10

    .line 1014
    goto :goto_10

    .line 1015
    :pswitch_34
    invoke-static {v1, v2}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 1016
    .line 1017
    .line 1018
    move-result v9

    .line 1019
    goto :goto_10

    .line 1020
    :pswitch_35
    invoke-static {v1, v2}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 1021
    .line 1022
    .line 1023
    move-result v8

    .line 1024
    goto :goto_10

    .line 1025
    :pswitch_36
    invoke-static {v1, v2}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 1026
    .line 1027
    .line 1028
    move-result v7

    .line 1029
    goto :goto_10

    .line 1030
    :pswitch_37
    invoke-static {v1, v2}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 1031
    .line 1032
    .line 1033
    move-result v6

    .line 1034
    goto :goto_10

    .line 1035
    :pswitch_38
    invoke-static {v1, v2}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 1036
    .line 1037
    .line 1038
    move-result v5

    .line 1039
    goto :goto_10

    .line 1040
    :cond_2d
    invoke-static {v1, v0}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 1041
    .line 1042
    .line 1043
    new-instance v4, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h;

    .line 1044
    .line 1045
    invoke-direct/range {v4 .. v12}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h;-><init>(IIIIIIZLjava/lang/String;)V

    .line 1046
    .line 1047
    .line 1048
    return-object v4

    .line 1049
    :pswitch_39
    invoke-static {v1}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 1050
    .line 1051
    .line 1052
    move-result v0

    .line 1053
    const/4 v2, 0x0

    .line 1054
    :goto_11
    invoke-virtual {v1}, Landroid/os/Parcel;->dataPosition()I

    .line 1055
    .line 1056
    .line 1057
    move-result v3

    .line 1058
    if-ge v3, v0, :cond_2f

    .line 1059
    .line 1060
    invoke-virtual {v1}, Landroid/os/Parcel;->readInt()I

    .line 1061
    .line 1062
    .line 1063
    move-result v3

    .line 1064
    int-to-char v4, v3

    .line 1065
    const/4 v5, 0x1

    .line 1066
    if-eq v4, v5, :cond_2e

    .line 1067
    .line 1068
    invoke-static {v1, v3}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 1069
    .line 1070
    .line 1071
    goto :goto_11

    .line 1072
    :cond_2e
    sget-object v2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b0;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 1073
    .line 1074
    invoke-static {v1, v3, v2}, Ljp/xb;->e(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 1075
    .line 1076
    .line 1077
    move-result-object v2

    .line 1078
    check-cast v2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b0;

    .line 1079
    .line 1080
    goto :goto_11

    .line 1081
    :cond_2f
    invoke-static {v1, v0}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 1082
    .line 1083
    .line 1084
    new-instance v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/w;

    .line 1085
    .line 1086
    invoke-direct {v0, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/w;-><init>(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b0;)V

    .line 1087
    .line 1088
    .line 1089
    return-object v0

    .line 1090
    :pswitch_3a
    invoke-static {v1}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 1091
    .line 1092
    .line 1093
    move-result v0

    .line 1094
    const/4 v2, 0x0

    .line 1095
    const/4 v3, 0x0

    .line 1096
    move-object v4, v3

    .line 1097
    :goto_12
    invoke-virtual {v1}, Landroid/os/Parcel;->dataPosition()I

    .line 1098
    .line 1099
    .line 1100
    move-result v5

    .line 1101
    if-ge v5, v0, :cond_34

    .line 1102
    .line 1103
    invoke-virtual {v1}, Landroid/os/Parcel;->readInt()I

    .line 1104
    .line 1105
    .line 1106
    move-result v5

    .line 1107
    int-to-char v6, v5

    .line 1108
    const/4 v7, 0x1

    .line 1109
    if-eq v6, v7, :cond_33

    .line 1110
    .line 1111
    const/4 v7, 0x2

    .line 1112
    if-eq v6, v7, :cond_32

    .line 1113
    .line 1114
    const/4 v7, 0x3

    .line 1115
    if-eq v6, v7, :cond_31

    .line 1116
    .line 1117
    const/4 v7, 0x4

    .line 1118
    if-eq v6, v7, :cond_30

    .line 1119
    .line 1120
    invoke-static {v1, v5}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 1121
    .line 1122
    .line 1123
    goto :goto_12

    .line 1124
    :cond_30
    invoke-static {v1, v5}, Ljp/xb;->l(Landroid/os/Parcel;I)Z

    .line 1125
    .line 1126
    .line 1127
    move-result v2

    .line 1128
    goto :goto_12

    .line 1129
    :cond_31
    invoke-static {v1, v5}, Ljp/xb;->l(Landroid/os/Parcel;I)Z

    .line 1130
    .line 1131
    .line 1132
    goto :goto_12

    .line 1133
    :cond_32
    sget-object v4, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/d0;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 1134
    .line 1135
    invoke-static {v1, v5, v4}, Ljp/xb;->e(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 1136
    .line 1137
    .line 1138
    move-result-object v4

    .line 1139
    check-cast v4, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/d0;

    .line 1140
    .line 1141
    goto :goto_12

    .line 1142
    :cond_33
    sget-object v3, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c0;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 1143
    .line 1144
    invoke-static {v1, v5, v3}, Ljp/xb;->e(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 1145
    .line 1146
    .line 1147
    move-result-object v3

    .line 1148
    check-cast v3, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c0;

    .line 1149
    .line 1150
    goto :goto_12

    .line 1151
    :cond_34
    invoke-static {v1, v0}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 1152
    .line 1153
    .line 1154
    new-instance v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v;

    .line 1155
    .line 1156
    invoke-direct {v0, v3, v4, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v;-><init>(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c0;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/d0;Z)V

    .line 1157
    .line 1158
    .line 1159
    return-object v0

    .line 1160
    :pswitch_3b
    invoke-static {v1}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 1161
    .line 1162
    .line 1163
    move-result v0

    .line 1164
    const/4 v2, 0x0

    .line 1165
    move v3, v2

    .line 1166
    :goto_13
    invoke-virtual {v1}, Landroid/os/Parcel;->dataPosition()I

    .line 1167
    .line 1168
    .line 1169
    move-result v4

    .line 1170
    if-ge v4, v0, :cond_37

    .line 1171
    .line 1172
    invoke-virtual {v1}, Landroid/os/Parcel;->readInt()I

    .line 1173
    .line 1174
    .line 1175
    move-result v4

    .line 1176
    int-to-char v5, v4

    .line 1177
    const/4 v6, 0x1

    .line 1178
    if-eq v5, v6, :cond_36

    .line 1179
    .line 1180
    const/4 v6, 0x2

    .line 1181
    if-eq v5, v6, :cond_35

    .line 1182
    .line 1183
    invoke-static {v1, v4}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 1184
    .line 1185
    .line 1186
    goto :goto_13

    .line 1187
    :cond_35
    invoke-static {v1, v4}, Ljp/xb;->l(Landroid/os/Parcel;I)Z

    .line 1188
    .line 1189
    .line 1190
    move-result v3

    .line 1191
    goto :goto_13

    .line 1192
    :cond_36
    invoke-static {v1, v4}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 1193
    .line 1194
    .line 1195
    move-result v2

    .line 1196
    goto :goto_13

    .line 1197
    :cond_37
    invoke-static {v1, v0}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 1198
    .line 1199
    .line 1200
    new-instance v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/u;

    .line 1201
    .line 1202
    invoke-direct {v0, v2, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/u;-><init>(IZ)V

    .line 1203
    .line 1204
    .line 1205
    return-object v0

    .line 1206
    :pswitch_3c
    invoke-static {v1}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 1207
    .line 1208
    .line 1209
    move-result v0

    .line 1210
    const/4 v2, 0x0

    .line 1211
    const/4 v3, 0x0

    .line 1212
    move-object v6, v2

    .line 1213
    move-object v7, v6

    .line 1214
    move-object v8, v7

    .line 1215
    move-object v9, v8

    .line 1216
    move-object v11, v9

    .line 1217
    move-object v12, v11

    .line 1218
    move-object v13, v12

    .line 1219
    move-object v14, v13

    .line 1220
    move-object v15, v14

    .line 1221
    move-object/from16 v16, v15

    .line 1222
    .line 1223
    move-object/from16 v17, v16

    .line 1224
    .line 1225
    move-object/from16 v18, v17

    .line 1226
    .line 1227
    move-object/from16 v19, v18

    .line 1228
    .line 1229
    move v5, v3

    .line 1230
    move v10, v5

    .line 1231
    :goto_14
    invoke-virtual {v1}, Landroid/os/Parcel;->dataPosition()I

    .line 1232
    .line 1233
    .line 1234
    move-result v2

    .line 1235
    if-ge v2, v0, :cond_38

    .line 1236
    .line 1237
    invoke-virtual {v1}, Landroid/os/Parcel;->readInt()I

    .line 1238
    .line 1239
    .line 1240
    move-result v2

    .line 1241
    int-to-char v3, v2

    .line 1242
    packed-switch v3, :pswitch_data_6

    .line 1243
    .line 1244
    .line 1245
    invoke-static {v1, v2}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 1246
    .line 1247
    .line 1248
    goto :goto_14

    .line 1249
    :pswitch_3d
    sget-object v3, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 1250
    .line 1251
    invoke-static {v1, v2, v3}, Ljp/xb;->e(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 1252
    .line 1253
    .line 1254
    move-result-object v2

    .line 1255
    move-object/from16 v19, v2

    .line 1256
    .line 1257
    check-cast v19, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k;

    .line 1258
    .line 1259
    goto :goto_14

    .line 1260
    :pswitch_3e
    sget-object v3, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 1261
    .line 1262
    invoke-static {v1, v2, v3}, Ljp/xb;->e(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 1263
    .line 1264
    .line 1265
    move-result-object v2

    .line 1266
    move-object/from16 v18, v2

    .line 1267
    .line 1268
    check-cast v18, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j;

    .line 1269
    .line 1270
    goto :goto_14

    .line 1271
    :pswitch_3f
    sget-object v3, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/i;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 1272
    .line 1273
    invoke-static {v1, v2, v3}, Ljp/xb;->e(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 1274
    .line 1275
    .line 1276
    move-result-object v2

    .line 1277
    move-object/from16 v17, v2

    .line 1278
    .line 1279
    check-cast v17, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/i;

    .line 1280
    .line 1281
    goto :goto_14

    .line 1282
    :pswitch_40
    sget-object v3, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 1283
    .line 1284
    invoke-static {v1, v2, v3}, Ljp/xb;->e(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 1285
    .line 1286
    .line 1287
    move-result-object v2

    .line 1288
    move-object/from16 v16, v2

    .line 1289
    .line 1290
    check-cast v16, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m;

    .line 1291
    .line 1292
    goto :goto_14

    .line 1293
    :pswitch_41
    sget-object v3, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 1294
    .line 1295
    invoke-static {v1, v2, v3}, Ljp/xb;->e(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 1296
    .line 1297
    .line 1298
    move-result-object v2

    .line 1299
    move-object v15, v2

    .line 1300
    check-cast v15, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q;

    .line 1301
    .line 1302
    goto :goto_14

    .line 1303
    :pswitch_42
    sget-object v3, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/r;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 1304
    .line 1305
    invoke-static {v1, v2, v3}, Ljp/xb;->e(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 1306
    .line 1307
    .line 1308
    move-result-object v2

    .line 1309
    move-object v14, v2

    .line 1310
    check-cast v14, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/r;

    .line 1311
    .line 1312
    goto :goto_14

    .line 1313
    :pswitch_43
    sget-object v3, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/p;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 1314
    .line 1315
    invoke-static {v1, v2, v3}, Ljp/xb;->e(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 1316
    .line 1317
    .line 1318
    move-result-object v2

    .line 1319
    move-object v13, v2

    .line 1320
    check-cast v13, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/p;

    .line 1321
    .line 1322
    goto :goto_14

    .line 1323
    :pswitch_44
    sget-object v3, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/o;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 1324
    .line 1325
    invoke-static {v1, v2, v3}, Ljp/xb;->e(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 1326
    .line 1327
    .line 1328
    move-result-object v2

    .line 1329
    move-object v12, v2

    .line 1330
    check-cast v12, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/o;

    .line 1331
    .line 1332
    goto :goto_14

    .line 1333
    :pswitch_45
    sget-object v3, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 1334
    .line 1335
    invoke-static {v1, v2, v3}, Ljp/xb;->e(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 1336
    .line 1337
    .line 1338
    move-result-object v2

    .line 1339
    move-object v11, v2

    .line 1340
    check-cast v11, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l;

    .line 1341
    .line 1342
    goto :goto_14

    .line 1343
    :pswitch_46
    invoke-static {v1, v2}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 1344
    .line 1345
    .line 1346
    move-result v10

    .line 1347
    goto :goto_14

    .line 1348
    :pswitch_47
    sget-object v3, Landroid/graphics/Point;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 1349
    .line 1350
    invoke-static {v1, v2, v3}, Ljp/xb;->i(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)[Ljava/lang/Object;

    .line 1351
    .line 1352
    .line 1353
    move-result-object v2

    .line 1354
    move-object v9, v2

    .line 1355
    check-cast v9, [Landroid/graphics/Point;

    .line 1356
    .line 1357
    goto :goto_14

    .line 1358
    :pswitch_48
    invoke-static {v1, v2}, Ljp/xb;->b(Landroid/os/Parcel;I)[B

    .line 1359
    .line 1360
    .line 1361
    move-result-object v8

    .line 1362
    goto/16 :goto_14

    .line 1363
    .line 1364
    :pswitch_49
    invoke-static {v1, v2}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 1365
    .line 1366
    .line 1367
    move-result-object v7

    .line 1368
    goto/16 :goto_14

    .line 1369
    .line 1370
    :pswitch_4a
    invoke-static {v1, v2}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 1371
    .line 1372
    .line 1373
    move-result-object v6

    .line 1374
    goto/16 :goto_14

    .line 1375
    .line 1376
    :pswitch_4b
    invoke-static {v1, v2}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 1377
    .line 1378
    .line 1379
    move-result v5

    .line 1380
    goto/16 :goto_14

    .line 1381
    .line 1382
    :cond_38
    invoke-static {v1, v0}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 1383
    .line 1384
    .line 1385
    new-instance v4, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s;

    .line 1386
    .line 1387
    invoke-direct/range {v4 .. v19}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s;-><init>(ILjava/lang/String;Ljava/lang/String;[B[Landroid/graphics/Point;ILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/o;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/p;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/r;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/i;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k;)V

    .line 1388
    .line 1389
    .line 1390
    return-object v4

    .line 1391
    :pswitch_4c
    invoke-static {v1}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 1392
    .line 1393
    .line 1394
    move-result v0

    .line 1395
    const/4 v2, 0x0

    .line 1396
    const/4 v3, 0x0

    .line 1397
    :goto_15
    invoke-virtual {v1}, Landroid/os/Parcel;->dataPosition()I

    .line 1398
    .line 1399
    .line 1400
    move-result v4

    .line 1401
    if-ge v4, v0, :cond_3b

    .line 1402
    .line 1403
    invoke-virtual {v1}, Landroid/os/Parcel;->readInt()I

    .line 1404
    .line 1405
    .line 1406
    move-result v4

    .line 1407
    int-to-char v5, v4

    .line 1408
    const/4 v6, 0x1

    .line 1409
    if-eq v5, v6, :cond_3a

    .line 1410
    .line 1411
    const/4 v6, 0x2

    .line 1412
    if-eq v5, v6, :cond_39

    .line 1413
    .line 1414
    invoke-static {v1, v4}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 1415
    .line 1416
    .line 1417
    goto :goto_15

    .line 1418
    :cond_39
    invoke-static {v1, v4}, Ljp/xb;->g(Landroid/os/Parcel;I)[Ljava/lang/String;

    .line 1419
    .line 1420
    .line 1421
    move-result-object v2

    .line 1422
    goto :goto_15

    .line 1423
    :cond_3a
    invoke-static {v1, v4}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 1424
    .line 1425
    .line 1426
    move-result v3

    .line 1427
    goto :goto_15

    .line 1428
    :cond_3b
    invoke-static {v1, v0}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 1429
    .line 1430
    .line 1431
    new-instance v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g;

    .line 1432
    .line 1433
    invoke-direct {v0, v2, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g;-><init>([Ljava/lang/String;I)V

    .line 1434
    .line 1435
    .line 1436
    return-object v0

    .line 1437
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4c
        :pswitch_3c
        :pswitch_3b
        :pswitch_3a
        :pswitch_39
        :pswitch_30
        :pswitch_28
        :pswitch_20
        :pswitch_11
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch

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
    :pswitch_data_1
    .packed-switch 0x1
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
    .end packed-switch

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
    .line 1496
    .line 1497
    :pswitch_data_2
    .packed-switch 0x1
        :pswitch_1f
        :pswitch_1e
        :pswitch_1d
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
    .end packed-switch

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
    :pswitch_data_3
    .packed-switch 0x1
        :pswitch_27
        :pswitch_26
        :pswitch_25
        :pswitch_24
        :pswitch_23
        :pswitch_22
        :pswitch_21
    .end packed-switch

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
    :pswitch_data_4
    .packed-switch 0x1
        :pswitch_2f
        :pswitch_2e
        :pswitch_2d
        :pswitch_2c
        :pswitch_2b
        :pswitch_2a
        :pswitch_29
    .end packed-switch

    .line 1548
    .line 1549
    .line 1550
    .line 1551
    .line 1552
    .line 1553
    .line 1554
    .line 1555
    .line 1556
    .line 1557
    .line 1558
    .line 1559
    .line 1560
    .line 1561
    .line 1562
    .line 1563
    .line 1564
    .line 1565
    :pswitch_data_5
    .packed-switch 0x1
        :pswitch_38
        :pswitch_37
        :pswitch_36
        :pswitch_35
        :pswitch_34
        :pswitch_33
        :pswitch_32
        :pswitch_31
    .end packed-switch

    .line 1566
    .line 1567
    .line 1568
    .line 1569
    .line 1570
    .line 1571
    .line 1572
    .line 1573
    .line 1574
    .line 1575
    .line 1576
    .line 1577
    .line 1578
    .line 1579
    .line 1580
    .line 1581
    .line 1582
    .line 1583
    .line 1584
    .line 1585
    :pswitch_data_6
    .packed-switch 0x1
        :pswitch_4b
        :pswitch_4a
        :pswitch_49
        :pswitch_48
        :pswitch_47
        :pswitch_46
        :pswitch_45
        :pswitch_44
        :pswitch_43
        :pswitch_42
        :pswitch_41
        :pswitch_40
        :pswitch_3f
        :pswitch_3e
        :pswitch_3d
    .end packed-switch
.end method

.method public final synthetic newArray(I)[Ljava/lang/Object;
    .locals 0

    .line 1
    iget p0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/f;->a:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-array p0, p1, [Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/f0;

    .line 7
    .line 8
    return-object p0

    .line 9
    :pswitch_0
    new-array p0, p1, [Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/r;

    .line 10
    .line 11
    return-object p0

    .line 12
    :pswitch_1
    new-array p0, p1, [Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q;

    .line 13
    .line 14
    return-object p0

    .line 15
    :pswitch_2
    new-array p0, p1, [Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/p;

    .line 16
    .line 17
    return-object p0

    .line 18
    :pswitch_3
    new-array p0, p1, [Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/o;

    .line 19
    .line 20
    return-object p0

    .line 21
    :pswitch_4
    new-array p0, p1, [Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n;

    .line 22
    .line 23
    return-object p0

    .line 24
    :pswitch_5
    new-array p0, p1, [Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/d0;

    .line 25
    .line 26
    return-object p0

    .line 27
    :pswitch_6
    new-array p0, p1, [Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c0;

    .line 28
    .line 29
    return-object p0

    .line 30
    :pswitch_7
    new-array p0, p1, [Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b0;

    .line 31
    .line 32
    return-object p0

    .line 33
    :pswitch_8
    new-array p0, p1, [Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m;

    .line 34
    .line 35
    return-object p0

    .line 36
    :pswitch_9
    new-array p0, p1, [Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l;

    .line 37
    .line 38
    return-object p0

    .line 39
    :pswitch_a
    new-array p0, p1, [Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k;

    .line 40
    .line 41
    return-object p0

    .line 42
    :pswitch_b
    new-array p0, p1, [Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j;

    .line 43
    .line 44
    return-object p0

    .line 45
    :pswitch_c
    new-array p0, p1, [Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/i;

    .line 46
    .line 47
    return-object p0

    .line 48
    :pswitch_d
    new-array p0, p1, [Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h;

    .line 49
    .line 50
    return-object p0

    .line 51
    :pswitch_e
    new-array p0, p1, [Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/w;

    .line 52
    .line 53
    return-object p0

    .line 54
    :pswitch_f
    new-array p0, p1, [Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v;

    .line 55
    .line 56
    return-object p0

    .line 57
    :pswitch_10
    new-array p0, p1, [Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/u;

    .line 58
    .line 59
    return-object p0

    .line 60
    :pswitch_11
    new-array p0, p1, [Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s;

    .line 61
    .line 62
    return-object p0

    .line 63
    :pswitch_12
    new-array p0, p1, [Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g;

    .line 64
    .line 65
    return-object p0

    .line 66
    nop

    .line 67
    :pswitch_data_0
    .packed-switch 0x0
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
