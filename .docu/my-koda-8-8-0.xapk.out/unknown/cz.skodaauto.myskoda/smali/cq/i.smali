.class public final Lcq/i;
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
    iput p1, p0, Lcq/i;->a:I

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
    .locals 11

    .line 1
    iget p0, p0, Lcq/i;->a:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-static {p1}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    const/4 v0, 0x0

    .line 11
    const/4 v1, 0x0

    .line 12
    :goto_0
    invoke-virtual {p1}, Landroid/os/Parcel;->dataPosition()I

    .line 13
    .line 14
    .line 15
    move-result v2

    .line 16
    if-ge v2, p0, :cond_2

    .line 17
    .line 18
    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    int-to-char v3, v2

    .line 23
    const/4 v4, 0x1

    .line 24
    if-eq v3, v4, :cond_1

    .line 25
    .line 26
    const/4 v4, 0x2

    .line 27
    if-eq v3, v4, :cond_0

    .line 28
    .line 29
    invoke-static {p1, v2}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 30
    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_0
    sget-object v0, Lcom/google/android/gms/wearable/Term;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 34
    .line 35
    invoke-static {p1, v2, v0}, Ljp/xb;->j(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Ljava/util/ArrayList;

    .line 36
    .line 37
    .line 38
    move-result-object v0

    .line 39
    goto :goto_0

    .line 40
    :cond_1
    invoke-static {p1, v2}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 41
    .line 42
    .line 43
    move-result v1

    .line 44
    goto :goto_0

    .line 45
    :cond_2
    invoke-static {p1, p0}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 46
    .line 47
    .line 48
    new-instance p0, Lcq/s0;

    .line 49
    .line 50
    invoke-direct {p0, v0, v1}, Lcq/s0;-><init>(Ljava/util/ArrayList;I)V

    .line 51
    .line 52
    .line 53
    return-object p0

    .line 54
    :pswitch_0
    invoke-static {p1}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 55
    .line 56
    .line 57
    move-result p0

    .line 58
    const/4 v0, 0x0

    .line 59
    move v1, v0

    .line 60
    :goto_1
    invoke-virtual {p1}, Landroid/os/Parcel;->dataPosition()I

    .line 61
    .line 62
    .line 63
    move-result v2

    .line 64
    if-ge v2, p0, :cond_5

    .line 65
    .line 66
    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    .line 67
    .line 68
    .line 69
    move-result v2

    .line 70
    int-to-char v3, v2

    .line 71
    const/4 v4, 0x1

    .line 72
    if-eq v3, v4, :cond_4

    .line 73
    .line 74
    const/4 v4, 0x2

    .line 75
    if-eq v3, v4, :cond_3

    .line 76
    .line 77
    invoke-static {p1, v2}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 78
    .line 79
    .line 80
    goto :goto_1

    .line 81
    :cond_3
    invoke-static {p1, v2}, Ljp/xb;->l(Landroid/os/Parcel;I)Z

    .line 82
    .line 83
    .line 84
    move-result v1

    .line 85
    goto :goto_1

    .line 86
    :cond_4
    invoke-static {p1, v2}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 87
    .line 88
    .line 89
    move-result v0

    .line 90
    goto :goto_1

    .line 91
    :cond_5
    invoke-static {p1, p0}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 92
    .line 93
    .line 94
    new-instance p0, Lcq/r0;

    .line 95
    .line 96
    invoke-direct {p0, v0, v1}, Lcq/r0;-><init>(IZ)V

    .line 97
    .line 98
    .line 99
    return-object p0

    .line 100
    :pswitch_1
    invoke-static {p1}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 101
    .line 102
    .line 103
    move-result p0

    .line 104
    const/4 v0, 0x0

    .line 105
    const/4 v1, 0x0

    .line 106
    move v2, v1

    .line 107
    :goto_2
    invoke-virtual {p1}, Landroid/os/Parcel;->dataPosition()I

    .line 108
    .line 109
    .line 110
    move-result v3

    .line 111
    if-ge v3, p0, :cond_9

    .line 112
    .line 113
    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    .line 114
    .line 115
    .line 116
    move-result v3

    .line 117
    int-to-char v4, v3

    .line 118
    const/4 v5, 0x1

    .line 119
    if-eq v4, v5, :cond_8

    .line 120
    .line 121
    const/4 v5, 0x2

    .line 122
    if-eq v4, v5, :cond_7

    .line 123
    .line 124
    const/4 v5, 0x3

    .line 125
    if-eq v4, v5, :cond_6

    .line 126
    .line 127
    invoke-static {p1, v3}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 128
    .line 129
    .line 130
    goto :goto_2

    .line 131
    :cond_6
    invoke-static {p1, v3}, Ljp/xb;->b(Landroid/os/Parcel;I)[B

    .line 132
    .line 133
    .line 134
    move-result-object v0

    .line 135
    goto :goto_2

    .line 136
    :cond_7
    invoke-static {p1, v3}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 137
    .line 138
    .line 139
    move-result v2

    .line 140
    goto :goto_2

    .line 141
    :cond_8
    invoke-static {p1, v3}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 142
    .line 143
    .line 144
    move-result v1

    .line 145
    goto :goto_2

    .line 146
    :cond_9
    invoke-static {p1, p0}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 147
    .line 148
    .line 149
    new-instance p0, Lcq/q0;

    .line 150
    .line 151
    invoke-direct {p0, v0, v1, v2}, Lcq/q0;-><init>([BII)V

    .line 152
    .line 153
    .line 154
    return-object p0

    .line 155
    :pswitch_2
    invoke-static {p1}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 156
    .line 157
    .line 158
    move-result p0

    .line 159
    const/4 v0, 0x0

    .line 160
    const/4 v1, 0x0

    .line 161
    :goto_3
    invoke-virtual {p1}, Landroid/os/Parcel;->dataPosition()I

    .line 162
    .line 163
    .line 164
    move-result v2

    .line 165
    if-ge v2, p0, :cond_c

    .line 166
    .line 167
    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    .line 168
    .line 169
    .line 170
    move-result v2

    .line 171
    int-to-char v3, v2

    .line 172
    const/4 v4, 0x2

    .line 173
    if-eq v3, v4, :cond_b

    .line 174
    .line 175
    const/4 v4, 0x3

    .line 176
    if-eq v3, v4, :cond_a

    .line 177
    .line 178
    invoke-static {p1, v2}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 179
    .line 180
    .line 181
    goto :goto_3

    .line 182
    :cond_a
    invoke-static {p1, v2}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 183
    .line 184
    .line 185
    move-result-object v0

    .line 186
    goto :goto_3

    .line 187
    :cond_b
    invoke-static {p1, v2}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 188
    .line 189
    .line 190
    move-result v1

    .line 191
    goto :goto_3

    .line 192
    :cond_c
    invoke-static {p1, p0}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 193
    .line 194
    .line 195
    new-instance p0, Lcq/p0;

    .line 196
    .line 197
    invoke-direct {p0, v1, v0}, Lcq/p0;-><init>(ILjava/lang/String;)V

    .line 198
    .line 199
    .line 200
    return-object p0

    .line 201
    :pswitch_3
    invoke-static {p1}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 202
    .line 203
    .line 204
    move-result p0

    .line 205
    const/4 v0, 0x0

    .line 206
    const/4 v1, 0x0

    .line 207
    :goto_4
    invoke-virtual {p1}, Landroid/os/Parcel;->dataPosition()I

    .line 208
    .line 209
    .line 210
    move-result v2

    .line 211
    if-ge v2, p0, :cond_f

    .line 212
    .line 213
    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    .line 214
    .line 215
    .line 216
    move-result v2

    .line 217
    int-to-char v3, v2

    .line 218
    const/4 v4, 0x2

    .line 219
    if-eq v3, v4, :cond_e

    .line 220
    .line 221
    const/4 v4, 0x3

    .line 222
    if-eq v3, v4, :cond_d

    .line 223
    .line 224
    invoke-static {p1, v2}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 225
    .line 226
    .line 227
    goto :goto_4

    .line 228
    :cond_d
    sget-object v0, Lcq/c1;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 229
    .line 230
    invoke-static {p1, v2, v0}, Ljp/xb;->e(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 231
    .line 232
    .line 233
    move-result-object v0

    .line 234
    check-cast v0, Lcq/c1;

    .line 235
    .line 236
    goto :goto_4

    .line 237
    :cond_e
    invoke-static {p1, v2}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 238
    .line 239
    .line 240
    move-result v1

    .line 241
    goto :goto_4

    .line 242
    :cond_f
    invoke-static {p1, p0}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 243
    .line 244
    .line 245
    new-instance p0, Lcq/o0;

    .line 246
    .line 247
    invoke-direct {p0, v1, v0}, Lcq/o0;-><init>(ILcq/c1;)V

    .line 248
    .line 249
    .line 250
    return-object p0

    .line 251
    :pswitch_4
    invoke-static {p1}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 252
    .line 253
    .line 254
    move-result p0

    .line 255
    const/4 v0, 0x0

    .line 256
    const/4 v1, 0x0

    .line 257
    :goto_5
    invoke-virtual {p1}, Landroid/os/Parcel;->dataPosition()I

    .line 258
    .line 259
    .line 260
    move-result v2

    .line 261
    if-ge v2, p0, :cond_12

    .line 262
    .line 263
    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    .line 264
    .line 265
    .line 266
    move-result v2

    .line 267
    int-to-char v3, v2

    .line 268
    const/4 v4, 0x2

    .line 269
    if-eq v3, v4, :cond_11

    .line 270
    .line 271
    const/4 v4, 0x3

    .line 272
    if-eq v3, v4, :cond_10

    .line 273
    .line 274
    invoke-static {p1, v2}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 275
    .line 276
    .line 277
    goto :goto_5

    .line 278
    :cond_10
    sget-object v0, Landroid/os/ParcelFileDescriptor;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 279
    .line 280
    invoke-static {p1, v2, v0}, Ljp/xb;->e(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 281
    .line 282
    .line 283
    move-result-object v0

    .line 284
    check-cast v0, Landroid/os/ParcelFileDescriptor;

    .line 285
    .line 286
    goto :goto_5

    .line 287
    :cond_11
    invoke-static {p1, v2}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 288
    .line 289
    .line 290
    move-result v1

    .line 291
    goto :goto_5

    .line 292
    :cond_12
    invoke-static {p1, p0}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 293
    .line 294
    .line 295
    new-instance p0, Lcq/m0;

    .line 296
    .line 297
    invoke-direct {p0, v1, v0}, Lcq/m0;-><init>(ILandroid/os/ParcelFileDescriptor;)V

    .line 298
    .line 299
    .line 300
    return-object p0

    .line 301
    :pswitch_5
    invoke-static {p1}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 302
    .line 303
    .line 304
    move-result p0

    .line 305
    const/4 v0, 0x0

    .line 306
    const/4 v1, 0x0

    .line 307
    :goto_6
    invoke-virtual {p1}, Landroid/os/Parcel;->dataPosition()I

    .line 308
    .line 309
    .line 310
    move-result v2

    .line 311
    if-ge v2, p0, :cond_15

    .line 312
    .line 313
    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    .line 314
    .line 315
    .line 316
    move-result v2

    .line 317
    int-to-char v3, v2

    .line 318
    const/4 v4, 0x1

    .line 319
    if-eq v3, v4, :cond_14

    .line 320
    .line 321
    const/4 v4, 0x2

    .line 322
    if-eq v3, v4, :cond_13

    .line 323
    .line 324
    invoke-static {p1, v2}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 325
    .line 326
    .line 327
    goto :goto_6

    .line 328
    :cond_13
    sget-object v0, Lcq/u;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 329
    .line 330
    invoke-static {p1, v2, v0}, Ljp/xb;->j(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Ljava/util/ArrayList;

    .line 331
    .line 332
    .line 333
    move-result-object v0

    .line 334
    goto :goto_6

    .line 335
    :cond_14
    invoke-static {p1, v2}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 336
    .line 337
    .line 338
    move-result v1

    .line 339
    goto :goto_6

    .line 340
    :cond_15
    invoke-static {p1, p0}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 341
    .line 342
    .line 343
    new-instance p0, Lcq/l0;

    .line 344
    .line 345
    invoke-direct {p0, v0, v1}, Lcq/l0;-><init>(Ljava/util/ArrayList;I)V

    .line 346
    .line 347
    .line 348
    return-object p0

    .line 349
    :pswitch_6
    invoke-static {p1}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 350
    .line 351
    .line 352
    move-result p0

    .line 353
    const/4 v0, 0x0

    .line 354
    const/4 v1, 0x0

    .line 355
    :goto_7
    invoke-virtual {p1}, Landroid/os/Parcel;->dataPosition()I

    .line 356
    .line 357
    .line 358
    move-result v2

    .line 359
    if-ge v2, p0, :cond_18

    .line 360
    .line 361
    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    .line 362
    .line 363
    .line 364
    move-result v2

    .line 365
    int-to-char v3, v2

    .line 366
    const/4 v4, 0x1

    .line 367
    if-eq v3, v4, :cond_17

    .line 368
    .line 369
    const/4 v4, 0x2

    .line 370
    if-eq v3, v4, :cond_16

    .line 371
    .line 372
    invoke-static {p1, v2}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 373
    .line 374
    .line 375
    goto :goto_7

    .line 376
    :cond_16
    sget-object v0, Lcq/u;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 377
    .line 378
    invoke-static {p1, v2, v0}, Ljp/xb;->e(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 379
    .line 380
    .line 381
    move-result-object v0

    .line 382
    check-cast v0, Lcq/u;

    .line 383
    .line 384
    goto :goto_7

    .line 385
    :cond_17
    invoke-static {p1, v2}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 386
    .line 387
    .line 388
    move-result v1

    .line 389
    goto :goto_7

    .line 390
    :cond_18
    invoke-static {p1, p0}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 391
    .line 392
    .line 393
    new-instance p0, Lcq/k0;

    .line 394
    .line 395
    invoke-direct {p0, v1, v0}, Lcq/k0;-><init>(ILcq/u;)V

    .line 396
    .line 397
    .line 398
    return-object p0

    .line 399
    :pswitch_7
    invoke-static {p1}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 400
    .line 401
    .line 402
    move-result p0

    .line 403
    const/4 v0, 0x0

    .line 404
    const/4 v1, 0x0

    .line 405
    :goto_8
    invoke-virtual {p1}, Landroid/os/Parcel;->dataPosition()I

    .line 406
    .line 407
    .line 408
    move-result v2

    .line 409
    if-ge v2, p0, :cond_1b

    .line 410
    .line 411
    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    .line 412
    .line 413
    .line 414
    move-result v2

    .line 415
    int-to-char v3, v2

    .line 416
    const/4 v4, 0x2

    .line 417
    if-eq v3, v4, :cond_1a

    .line 418
    .line 419
    const/4 v4, 0x3

    .line 420
    if-eq v3, v4, :cond_19

    .line 421
    .line 422
    invoke-static {p1, v2}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 423
    .line 424
    .line 425
    goto :goto_8

    .line 426
    :cond_19
    invoke-static {p1, v2}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 427
    .line 428
    .line 429
    move-result-object v0

    .line 430
    goto :goto_8

    .line 431
    :cond_1a
    invoke-static {p1, v2}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 432
    .line 433
    .line 434
    move-result v1

    .line 435
    goto :goto_8

    .line 436
    :cond_1b
    invoke-static {p1, p0}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 437
    .line 438
    .line 439
    new-instance p0, Lcq/j0;

    .line 440
    .line 441
    invoke-direct {p0, v1, v0}, Lcq/j0;-><init>(ILjava/lang/String;)V

    .line 442
    .line 443
    .line 444
    return-object p0

    .line 445
    :pswitch_8
    invoke-static {p1}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 446
    .line 447
    .line 448
    move-result p0

    .line 449
    const/4 v0, 0x0

    .line 450
    const/4 v1, 0x0

    .line 451
    :goto_9
    invoke-virtual {p1}, Landroid/os/Parcel;->dataPosition()I

    .line 452
    .line 453
    .line 454
    move-result v2

    .line 455
    if-ge v2, p0, :cond_1e

    .line 456
    .line 457
    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    .line 458
    .line 459
    .line 460
    move-result v2

    .line 461
    int-to-char v3, v2

    .line 462
    const/4 v4, 0x2

    .line 463
    if-eq v3, v4, :cond_1d

    .line 464
    .line 465
    const/4 v4, 0x3

    .line 466
    if-eq v3, v4, :cond_1c

    .line 467
    .line 468
    invoke-static {p1, v2}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 469
    .line 470
    .line 471
    goto :goto_9

    .line 472
    :cond_1c
    sget-object v0, Lcq/r;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 473
    .line 474
    invoke-static {p1, v2, v0}, Ljp/xb;->e(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 475
    .line 476
    .line 477
    move-result-object v0

    .line 478
    check-cast v0, Lcq/r;

    .line 479
    .line 480
    goto :goto_9

    .line 481
    :cond_1d
    invoke-static {p1, v2}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 482
    .line 483
    .line 484
    move-result v1

    .line 485
    goto :goto_9

    .line 486
    :cond_1e
    invoke-static {p1, p0}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 487
    .line 488
    .line 489
    new-instance p0, Lcq/i0;

    .line 490
    .line 491
    invoke-direct {p0, v1, v0}, Lcq/i0;-><init>(ILcq/r;)V

    .line 492
    .line 493
    .line 494
    return-object p0

    .line 495
    :pswitch_9
    invoke-static {p1}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 496
    .line 497
    .line 498
    move-result p0

    .line 499
    const/4 v0, 0x0

    .line 500
    const/4 v1, 0x0

    .line 501
    :goto_a
    invoke-virtual {p1}, Landroid/os/Parcel;->dataPosition()I

    .line 502
    .line 503
    .line 504
    move-result v2

    .line 505
    if-ge v2, p0, :cond_21

    .line 506
    .line 507
    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    .line 508
    .line 509
    .line 510
    move-result v2

    .line 511
    int-to-char v3, v2

    .line 512
    const/4 v4, 0x2

    .line 513
    if-eq v3, v4, :cond_20

    .line 514
    .line 515
    const/4 v4, 0x3

    .line 516
    if-eq v3, v4, :cond_1f

    .line 517
    .line 518
    invoke-static {p1, v2}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 519
    .line 520
    .line 521
    goto :goto_a

    .line 522
    :cond_1f
    sget-object v0, Lcq/c1;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 523
    .line 524
    invoke-static {p1, v2, v0}, Ljp/xb;->j(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Ljava/util/ArrayList;

    .line 525
    .line 526
    .line 527
    move-result-object v0

    .line 528
    goto :goto_a

    .line 529
    :cond_20
    invoke-static {p1, v2}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 530
    .line 531
    .line 532
    move-result v1

    .line 533
    goto :goto_a

    .line 534
    :cond_21
    invoke-static {p1, p0}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 535
    .line 536
    .line 537
    new-instance p0, Lcq/h0;

    .line 538
    .line 539
    invoke-direct {p0, v0, v1}, Lcq/h0;-><init>(Ljava/util/ArrayList;I)V

    .line 540
    .line 541
    .line 542
    return-object p0

    .line 543
    :pswitch_a
    invoke-static {p1}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 544
    .line 545
    .line 546
    move-result p0

    .line 547
    const/4 v0, 0x0

    .line 548
    const/4 v1, 0x0

    .line 549
    :goto_b
    invoke-virtual {p1}, Landroid/os/Parcel;->dataPosition()I

    .line 550
    .line 551
    .line 552
    move-result v2

    .line 553
    if-ge v2, p0, :cond_24

    .line 554
    .line 555
    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    .line 556
    .line 557
    .line 558
    move-result v2

    .line 559
    int-to-char v3, v2

    .line 560
    const/4 v4, 0x2

    .line 561
    if-eq v3, v4, :cond_23

    .line 562
    .line 563
    const/4 v4, 0x3

    .line 564
    if-eq v3, v4, :cond_22

    .line 565
    .line 566
    invoke-static {p1, v2}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 567
    .line 568
    .line 569
    goto :goto_b

    .line 570
    :cond_22
    sget-object v0, Lcom/google/android/gms/wearable/ConnectionConfiguration;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 571
    .line 572
    invoke-static {p1, v2, v0}, Ljp/xb;->i(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)[Ljava/lang/Object;

    .line 573
    .line 574
    .line 575
    move-result-object v0

    .line 576
    check-cast v0, [Lcom/google/android/gms/wearable/ConnectionConfiguration;

    .line 577
    .line 578
    goto :goto_b

    .line 579
    :cond_23
    invoke-static {p1, v2}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 580
    .line 581
    .line 582
    move-result v1

    .line 583
    goto :goto_b

    .line 584
    :cond_24
    invoke-static {p1, p0}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 585
    .line 586
    .line 587
    new-instance p0, Lcq/g0;

    .line 588
    .line 589
    invoke-direct {p0, v1, v0}, Lcq/g0;-><init>(I[Lcom/google/android/gms/wearable/ConnectionConfiguration;)V

    .line 590
    .line 591
    .line 592
    return-object p0

    .line 593
    :pswitch_b
    invoke-static {p1}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 594
    .line 595
    .line 596
    move-result p0

    .line 597
    const/4 v0, 0x0

    .line 598
    const/4 v1, 0x0

    .line 599
    :goto_c
    invoke-virtual {p1}, Landroid/os/Parcel;->dataPosition()I

    .line 600
    .line 601
    .line 602
    move-result v2

    .line 603
    if-ge v2, p0, :cond_27

    .line 604
    .line 605
    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    .line 606
    .line 607
    .line 608
    move-result v2

    .line 609
    int-to-char v3, v2

    .line 610
    const/4 v4, 0x2

    .line 611
    if-eq v3, v4, :cond_26

    .line 612
    .line 613
    const/4 v4, 0x3

    .line 614
    if-eq v3, v4, :cond_25

    .line 615
    .line 616
    invoke-static {p1, v2}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 617
    .line 618
    .line 619
    goto :goto_c

    .line 620
    :cond_25
    sget-object v0, Lcom/google/android/gms/wearable/ConnectionConfiguration;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 621
    .line 622
    invoke-static {p1, v2, v0}, Ljp/xb;->e(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 623
    .line 624
    .line 625
    move-result-object v0

    .line 626
    check-cast v0, Lcom/google/android/gms/wearable/ConnectionConfiguration;

    .line 627
    .line 628
    goto :goto_c

    .line 629
    :cond_26
    invoke-static {p1, v2}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 630
    .line 631
    .line 632
    move-result v1

    .line 633
    goto :goto_c

    .line 634
    :cond_27
    invoke-static {p1, p0}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 635
    .line 636
    .line 637
    new-instance p0, Lcq/f0;

    .line 638
    .line 639
    invoke-direct {p0, v1, v0}, Lcq/f0;-><init>(ILcom/google/android/gms/wearable/ConnectionConfiguration;)V

    .line 640
    .line 641
    .line 642
    return-object p0

    .line 643
    :pswitch_c
    invoke-static {p1}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 644
    .line 645
    .line 646
    move-result p0

    .line 647
    const/4 v0, 0x0

    .line 648
    const/4 v1, 0x0

    .line 649
    :goto_d
    invoke-virtual {p1}, Landroid/os/Parcel;->dataPosition()I

    .line 650
    .line 651
    .line 652
    move-result v2

    .line 653
    if-ge v2, p0, :cond_2a

    .line 654
    .line 655
    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    .line 656
    .line 657
    .line 658
    move-result v2

    .line 659
    int-to-char v3, v2

    .line 660
    const/4 v4, 0x2

    .line 661
    if-eq v3, v4, :cond_29

    .line 662
    .line 663
    const/4 v4, 0x3

    .line 664
    if-eq v3, v4, :cond_28

    .line 665
    .line 666
    invoke-static {p1, v2}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 667
    .line 668
    .line 669
    goto :goto_d

    .line 670
    :cond_28
    invoke-static {p1, v2}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 671
    .line 672
    .line 673
    move-result-object v0

    .line 674
    goto :goto_d

    .line 675
    :cond_29
    invoke-static {p1, v2}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 676
    .line 677
    .line 678
    move-result v1

    .line 679
    goto :goto_d

    .line 680
    :cond_2a
    invoke-static {p1, p0}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 681
    .line 682
    .line 683
    new-instance p0, Lcq/e0;

    .line 684
    .line 685
    invoke-direct {p0, v1, v0}, Lcq/e0;-><init>(ILjava/lang/String;)V

    .line 686
    .line 687
    .line 688
    return-object p0

    .line 689
    :pswitch_d
    invoke-static {p1}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 690
    .line 691
    .line 692
    move-result p0

    .line 693
    const/4 v0, 0x0

    .line 694
    move v1, v0

    .line 695
    :goto_e
    invoke-virtual {p1}, Landroid/os/Parcel;->dataPosition()I

    .line 696
    .line 697
    .line 698
    move-result v2

    .line 699
    if-ge v2, p0, :cond_2d

    .line 700
    .line 701
    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    .line 702
    .line 703
    .line 704
    move-result v2

    .line 705
    int-to-char v3, v2

    .line 706
    const/4 v4, 0x2

    .line 707
    if-eq v3, v4, :cond_2c

    .line 708
    .line 709
    const/4 v4, 0x3

    .line 710
    if-eq v3, v4, :cond_2b

    .line 711
    .line 712
    invoke-static {p1, v2}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 713
    .line 714
    .line 715
    goto :goto_e

    .line 716
    :cond_2b
    invoke-static {p1, v2}, Ljp/xb;->l(Landroid/os/Parcel;I)Z

    .line 717
    .line 718
    .line 719
    move-result v1

    .line 720
    goto :goto_e

    .line 721
    :cond_2c
    invoke-static {p1, v2}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 722
    .line 723
    .line 724
    move-result v0

    .line 725
    goto :goto_e

    .line 726
    :cond_2d
    invoke-static {p1, p0}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 727
    .line 728
    .line 729
    new-instance p0, Lcq/d0;

    .line 730
    .line 731
    invoke-direct {p0, v0, v1}, Lcq/d0;-><init>(IZ)V

    .line 732
    .line 733
    .line 734
    return-object p0

    .line 735
    :pswitch_e
    invoke-static {p1}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 736
    .line 737
    .line 738
    move-result p0

    .line 739
    const/4 v0, 0x0

    .line 740
    move v1, v0

    .line 741
    move v2, v1

    .line 742
    :goto_f
    invoke-virtual {p1}, Landroid/os/Parcel;->dataPosition()I

    .line 743
    .line 744
    .line 745
    move-result v3

    .line 746
    if-ge v3, p0, :cond_31

    .line 747
    .line 748
    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    .line 749
    .line 750
    .line 751
    move-result v3

    .line 752
    int-to-char v4, v3

    .line 753
    const/4 v5, 0x2

    .line 754
    if-eq v4, v5, :cond_30

    .line 755
    .line 756
    const/4 v5, 0x3

    .line 757
    if-eq v4, v5, :cond_2f

    .line 758
    .line 759
    const/4 v5, 0x4

    .line 760
    if-eq v4, v5, :cond_2e

    .line 761
    .line 762
    invoke-static {p1, v3}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 763
    .line 764
    .line 765
    goto :goto_f

    .line 766
    :cond_2e
    invoke-static {p1, v3}, Ljp/xb;->l(Landroid/os/Parcel;I)Z

    .line 767
    .line 768
    .line 769
    move-result v2

    .line 770
    goto :goto_f

    .line 771
    :cond_2f
    invoke-static {p1, v3}, Ljp/xb;->l(Landroid/os/Parcel;I)Z

    .line 772
    .line 773
    .line 774
    move-result v1

    .line 775
    goto :goto_f

    .line 776
    :cond_30
    invoke-static {p1, v3}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 777
    .line 778
    .line 779
    move-result v0

    .line 780
    goto :goto_f

    .line 781
    :cond_31
    invoke-static {p1, p0}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 782
    .line 783
    .line 784
    new-instance p0, Lcq/c0;

    .line 785
    .line 786
    invoke-direct {p0, v0, v1, v2}, Lcq/c0;-><init>(IZZ)V

    .line 787
    .line 788
    .line 789
    return-object p0

    .line 790
    :pswitch_f
    invoke-static {p1}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 791
    .line 792
    .line 793
    move-result p0

    .line 794
    const/4 v0, 0x0

    .line 795
    move v1, v0

    .line 796
    :goto_10
    invoke-virtual {p1}, Landroid/os/Parcel;->dataPosition()I

    .line 797
    .line 798
    .line 799
    move-result v2

    .line 800
    if-ge v2, p0, :cond_34

    .line 801
    .line 802
    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    .line 803
    .line 804
    .line 805
    move-result v2

    .line 806
    int-to-char v3, v2

    .line 807
    const/4 v4, 0x2

    .line 808
    if-eq v3, v4, :cond_33

    .line 809
    .line 810
    const/4 v4, 0x3

    .line 811
    if-eq v3, v4, :cond_32

    .line 812
    .line 813
    invoke-static {p1, v2}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 814
    .line 815
    .line 816
    goto :goto_10

    .line 817
    :cond_32
    invoke-static {p1, v2}, Ljp/xb;->l(Landroid/os/Parcel;I)Z

    .line 818
    .line 819
    .line 820
    move-result v1

    .line 821
    goto :goto_10

    .line 822
    :cond_33
    invoke-static {p1, v2}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 823
    .line 824
    .line 825
    move-result v0

    .line 826
    goto :goto_10

    .line 827
    :cond_34
    invoke-static {p1, p0}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 828
    .line 829
    .line 830
    new-instance p0, Lcq/b0;

    .line 831
    .line 832
    invoke-direct {p0, v0, v1}, Lcq/b0;-><init>(IZ)V

    .line 833
    .line 834
    .line 835
    return-object p0

    .line 836
    :pswitch_10
    invoke-static {p1}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 837
    .line 838
    .line 839
    move-result p0

    .line 840
    const/4 v0, 0x0

    .line 841
    const/4 v1, 0x0

    .line 842
    :goto_11
    invoke-virtual {p1}, Landroid/os/Parcel;->dataPosition()I

    .line 843
    .line 844
    .line 845
    move-result v2

    .line 846
    if-ge v2, p0, :cond_37

    .line 847
    .line 848
    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    .line 849
    .line 850
    .line 851
    move-result v2

    .line 852
    int-to-char v3, v2

    .line 853
    const/4 v4, 0x2

    .line 854
    if-eq v3, v4, :cond_36

    .line 855
    .line 856
    const/4 v4, 0x3

    .line 857
    if-eq v3, v4, :cond_35

    .line 858
    .line 859
    invoke-static {p1, v2}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 860
    .line 861
    .line 862
    goto :goto_11

    .line 863
    :cond_35
    sget-object v0, Landroid/os/ParcelFileDescriptor;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 864
    .line 865
    invoke-static {p1, v2, v0}, Ljp/xb;->e(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 866
    .line 867
    .line 868
    move-result-object v0

    .line 869
    check-cast v0, Landroid/os/ParcelFileDescriptor;

    .line 870
    .line 871
    goto :goto_11

    .line 872
    :cond_36
    invoke-static {p1, v2}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 873
    .line 874
    .line 875
    move-result v1

    .line 876
    goto :goto_11

    .line 877
    :cond_37
    invoke-static {p1, p0}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 878
    .line 879
    .line 880
    new-instance p0, Lcq/a0;

    .line 881
    .line 882
    invoke-direct {p0, v1, v0}, Lcq/a0;-><init>(ILandroid/os/ParcelFileDescriptor;)V

    .line 883
    .line 884
    .line 885
    return-object p0

    .line 886
    :pswitch_11
    invoke-static {p1}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 887
    .line 888
    .line 889
    move-result p0

    .line 890
    const/4 v0, 0x0

    .line 891
    const/4 v1, 0x0

    .line 892
    :goto_12
    invoke-virtual {p1}, Landroid/os/Parcel;->dataPosition()I

    .line 893
    .line 894
    .line 895
    move-result v2

    .line 896
    if-ge v2, p0, :cond_3a

    .line 897
    .line 898
    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    .line 899
    .line 900
    .line 901
    move-result v2

    .line 902
    int-to-char v3, v2

    .line 903
    const/4 v4, 0x2

    .line 904
    if-eq v3, v4, :cond_39

    .line 905
    .line 906
    const/4 v4, 0x3

    .line 907
    if-eq v3, v4, :cond_38

    .line 908
    .line 909
    invoke-static {p1, v2}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 910
    .line 911
    .line 912
    goto :goto_12

    .line 913
    :cond_38
    sget-object v0, Landroid/os/ParcelFileDescriptor;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 914
    .line 915
    invoke-static {p1, v2, v0}, Ljp/xb;->e(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 916
    .line 917
    .line 918
    move-result-object v0

    .line 919
    check-cast v0, Landroid/os/ParcelFileDescriptor;

    .line 920
    .line 921
    goto :goto_12

    .line 922
    :cond_39
    invoke-static {p1, v2}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 923
    .line 924
    .line 925
    move-result v1

    .line 926
    goto :goto_12

    .line 927
    :cond_3a
    invoke-static {p1, p0}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 928
    .line 929
    .line 930
    new-instance p0, Lcq/z;

    .line 931
    .line 932
    invoke-direct {p0, v1, v0}, Lcq/z;-><init>(ILandroid/os/ParcelFileDescriptor;)V

    .line 933
    .line 934
    .line 935
    return-object p0

    .line 936
    :pswitch_12
    invoke-static {p1}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 937
    .line 938
    .line 939
    move-result p0

    .line 940
    const/4 v0, 0x0

    .line 941
    const/4 v1, 0x0

    .line 942
    :goto_13
    invoke-virtual {p1}, Landroid/os/Parcel;->dataPosition()I

    .line 943
    .line 944
    .line 945
    move-result v2

    .line 946
    if-ge v2, p0, :cond_3d

    .line 947
    .line 948
    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    .line 949
    .line 950
    .line 951
    move-result v2

    .line 952
    int-to-char v3, v2

    .line 953
    const/4 v4, 0x2

    .line 954
    if-eq v3, v4, :cond_3c

    .line 955
    .line 956
    const/4 v4, 0x3

    .line 957
    if-eq v3, v4, :cond_3b

    .line 958
    .line 959
    invoke-static {p1, v2}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 960
    .line 961
    .line 962
    goto :goto_13

    .line 963
    :cond_3b
    sget-object v0, Lcq/b;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 964
    .line 965
    invoke-static {p1, v2, v0}, Ljp/xb;->e(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 966
    .line 967
    .line 968
    move-result-object v0

    .line 969
    check-cast v0, Lcq/b;

    .line 970
    .line 971
    goto :goto_13

    .line 972
    :cond_3c
    invoke-static {p1, v2}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 973
    .line 974
    .line 975
    move-result v1

    .line 976
    goto :goto_13

    .line 977
    :cond_3d
    invoke-static {p1, p0}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 978
    .line 979
    .line 980
    new-instance p0, Lcq/y;

    .line 981
    .line 982
    invoke-direct {p0, v1, v0}, Lcq/y;-><init>(ILcq/b;)V

    .line 983
    .line 984
    .line 985
    return-object p0

    .line 986
    :pswitch_13
    invoke-static {p1}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 987
    .line 988
    .line 989
    move-result p0

    .line 990
    const/4 v0, 0x0

    .line 991
    move v1, v0

    .line 992
    :goto_14
    invoke-virtual {p1}, Landroid/os/Parcel;->dataPosition()I

    .line 993
    .line 994
    .line 995
    move-result v2

    .line 996
    if-ge v2, p0, :cond_40

    .line 997
    .line 998
    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    .line 999
    .line 1000
    .line 1001
    move-result v2

    .line 1002
    int-to-char v3, v2

    .line 1003
    const/4 v4, 0x1

    .line 1004
    if-eq v3, v4, :cond_3f

    .line 1005
    .line 1006
    const/4 v4, 0x2

    .line 1007
    if-eq v3, v4, :cond_3e

    .line 1008
    .line 1009
    invoke-static {p1, v2}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 1010
    .line 1011
    .line 1012
    goto :goto_14

    .line 1013
    :cond_3e
    invoke-static {p1, v2}, Ljp/xb;->l(Landroid/os/Parcel;I)Z

    .line 1014
    .line 1015
    .line 1016
    move-result v1

    .line 1017
    goto :goto_14

    .line 1018
    :cond_3f
    invoke-static {p1, v2}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 1019
    .line 1020
    .line 1021
    move-result v0

    .line 1022
    goto :goto_14

    .line 1023
    :cond_40
    invoke-static {p1, p0}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 1024
    .line 1025
    .line 1026
    new-instance p0, Lcq/x;

    .line 1027
    .line 1028
    invoke-direct {p0, v0, v1}, Lcq/x;-><init>(IZ)V

    .line 1029
    .line 1030
    .line 1031
    return-object p0

    .line 1032
    :pswitch_14
    invoke-static {p1}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 1033
    .line 1034
    .line 1035
    move-result p0

    .line 1036
    const/4 v0, 0x0

    .line 1037
    const/4 v1, 0x0

    .line 1038
    :goto_15
    invoke-virtual {p1}, Landroid/os/Parcel;->dataPosition()I

    .line 1039
    .line 1040
    .line 1041
    move-result v2

    .line 1042
    if-ge v2, p0, :cond_43

    .line 1043
    .line 1044
    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    .line 1045
    .line 1046
    .line 1047
    move-result v2

    .line 1048
    int-to-char v3, v2

    .line 1049
    const/4 v4, 0x2

    .line 1050
    if-eq v3, v4, :cond_42

    .line 1051
    .line 1052
    const/4 v4, 0x3

    .line 1053
    if-eq v3, v4, :cond_41

    .line 1054
    .line 1055
    invoke-static {p1, v2}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 1056
    .line 1057
    .line 1058
    goto :goto_15

    .line 1059
    :cond_41
    sget-object v0, Lcom/google/android/gms/wearable/AppTheme;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 1060
    .line 1061
    invoke-static {p1, v2, v0}, Ljp/xb;->e(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 1062
    .line 1063
    .line 1064
    move-result-object v0

    .line 1065
    check-cast v0, Lcom/google/android/gms/wearable/AppTheme;

    .line 1066
    .line 1067
    goto :goto_15

    .line 1068
    :cond_42
    invoke-static {p1, v2}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 1069
    .line 1070
    .line 1071
    move-result v1

    .line 1072
    goto :goto_15

    .line 1073
    :cond_43
    invoke-static {p1, p0}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 1074
    .line 1075
    .line 1076
    new-instance p0, Lcq/w;

    .line 1077
    .line 1078
    invoke-direct {p0, v1, v0}, Lcq/w;-><init>(ILcom/google/android/gms/wearable/AppTheme;)V

    .line 1079
    .line 1080
    .line 1081
    return-object p0

    .line 1082
    :pswitch_15
    invoke-static {p1}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 1083
    .line 1084
    .line 1085
    move-result p0

    .line 1086
    const/4 v0, 0x0

    .line 1087
    const/4 v1, 0x0

    .line 1088
    :goto_16
    invoke-virtual {p1}, Landroid/os/Parcel;->dataPosition()I

    .line 1089
    .line 1090
    .line 1091
    move-result v2

    .line 1092
    if-ge v2, p0, :cond_46

    .line 1093
    .line 1094
    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    .line 1095
    .line 1096
    .line 1097
    move-result v2

    .line 1098
    int-to-char v3, v2

    .line 1099
    const/4 v4, 0x2

    .line 1100
    if-eq v3, v4, :cond_45

    .line 1101
    .line 1102
    const/4 v4, 0x3

    .line 1103
    if-eq v3, v4, :cond_44

    .line 1104
    .line 1105
    invoke-static {p1, v2}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 1106
    .line 1107
    .line 1108
    goto :goto_16

    .line 1109
    :cond_44
    sget-object v0, Lcq/b;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 1110
    .line 1111
    invoke-static {p1, v2, v0}, Ljp/xb;->j(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Ljava/util/ArrayList;

    .line 1112
    .line 1113
    .line 1114
    move-result-object v0

    .line 1115
    goto :goto_16

    .line 1116
    :cond_45
    invoke-static {p1, v2}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 1117
    .line 1118
    .line 1119
    move-result v1

    .line 1120
    goto :goto_16

    .line 1121
    :cond_46
    invoke-static {p1, p0}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 1122
    .line 1123
    .line 1124
    new-instance p0, Lcq/v;

    .line 1125
    .line 1126
    invoke-direct {p0, v0, v1}, Lcq/v;-><init>(Ljava/util/ArrayList;I)V

    .line 1127
    .line 1128
    .line 1129
    return-object p0

    .line 1130
    :pswitch_16
    invoke-static {p1}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 1131
    .line 1132
    .line 1133
    move-result p0

    .line 1134
    const/4 v0, 0x0

    .line 1135
    :goto_17
    invoke-virtual {p1}, Landroid/os/Parcel;->dataPosition()I

    .line 1136
    .line 1137
    .line 1138
    move-result v1

    .line 1139
    if-ge v1, p0, :cond_48

    .line 1140
    .line 1141
    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    .line 1142
    .line 1143
    .line 1144
    move-result v1

    .line 1145
    int-to-char v2, v1

    .line 1146
    const/4 v3, 0x1

    .line 1147
    if-eq v2, v3, :cond_47

    .line 1148
    .line 1149
    invoke-static {p1, v1}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 1150
    .line 1151
    .line 1152
    goto :goto_17

    .line 1153
    :cond_47
    invoke-static {p1, v1}, Ljp/xb;->b(Landroid/os/Parcel;I)[B

    .line 1154
    .line 1155
    .line 1156
    move-result-object v0

    .line 1157
    goto :goto_17

    .line 1158
    :cond_48
    invoke-static {p1, p0}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 1159
    .line 1160
    .line 1161
    new-instance p0, Lcq/u;

    .line 1162
    .line 1163
    invoke-direct {p0, v0}, Lcq/u;-><init>([B)V

    .line 1164
    .line 1165
    .line 1166
    return-object p0

    .line 1167
    :pswitch_17
    invoke-static {p1}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 1168
    .line 1169
    .line 1170
    move-result p0

    .line 1171
    const/4 v0, 0x0

    .line 1172
    move v1, v0

    .line 1173
    :goto_18
    invoke-virtual {p1}, Landroid/os/Parcel;->dataPosition()I

    .line 1174
    .line 1175
    .line 1176
    move-result v2

    .line 1177
    if-ge v2, p0, :cond_4b

    .line 1178
    .line 1179
    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    .line 1180
    .line 1181
    .line 1182
    move-result v2

    .line 1183
    int-to-char v3, v2

    .line 1184
    const/4 v4, 0x2

    .line 1185
    if-eq v3, v4, :cond_4a

    .line 1186
    .line 1187
    const/4 v4, 0x3

    .line 1188
    if-eq v3, v4, :cond_49

    .line 1189
    .line 1190
    invoke-static {p1, v2}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 1191
    .line 1192
    .line 1193
    goto :goto_18

    .line 1194
    :cond_49
    invoke-static {p1, v2}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 1195
    .line 1196
    .line 1197
    move-result v1

    .line 1198
    goto :goto_18

    .line 1199
    :cond_4a
    invoke-static {p1, v2}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 1200
    .line 1201
    .line 1202
    move-result v0

    .line 1203
    goto :goto_18

    .line 1204
    :cond_4b
    invoke-static {p1, p0}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 1205
    .line 1206
    .line 1207
    new-instance p0, Lcq/t;

    .line 1208
    .line 1209
    invoke-direct {p0, v0, v1}, Lcq/t;-><init>(II)V

    .line 1210
    .line 1211
    .line 1212
    return-object p0

    .line 1213
    :pswitch_18
    invoke-static {p1}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 1214
    .line 1215
    .line 1216
    move-result p0

    .line 1217
    const/4 v0, 0x0

    .line 1218
    move-object v1, v0

    .line 1219
    move-object v2, v1

    .line 1220
    :goto_19
    invoke-virtual {p1}, Landroid/os/Parcel;->dataPosition()I

    .line 1221
    .line 1222
    .line 1223
    move-result v3

    .line 1224
    if-ge v3, p0, :cond_4f

    .line 1225
    .line 1226
    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    .line 1227
    .line 1228
    .line 1229
    move-result v3

    .line 1230
    int-to-char v4, v3

    .line 1231
    const/4 v5, 0x2

    .line 1232
    if-eq v4, v5, :cond_4e

    .line 1233
    .line 1234
    const/4 v5, 0x4

    .line 1235
    if-eq v4, v5, :cond_4d

    .line 1236
    .line 1237
    const/4 v5, 0x5

    .line 1238
    if-eq v4, v5, :cond_4c

    .line 1239
    .line 1240
    invoke-static {p1, v3}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 1241
    .line 1242
    .line 1243
    goto :goto_19

    .line 1244
    :cond_4c
    invoke-static {p1, v3}, Ljp/xb;->b(Landroid/os/Parcel;I)[B

    .line 1245
    .line 1246
    .line 1247
    move-result-object v2

    .line 1248
    goto :goto_19

    .line 1249
    :cond_4d
    invoke-static {p1, v3}, Ljp/xb;->a(Landroid/os/Parcel;I)Landroid/os/Bundle;

    .line 1250
    .line 1251
    .line 1252
    move-result-object v1

    .line 1253
    goto :goto_19

    .line 1254
    :cond_4e
    sget-object v0, Landroid/net/Uri;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 1255
    .line 1256
    invoke-static {p1, v3, v0}, Ljp/xb;->e(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 1257
    .line 1258
    .line 1259
    move-result-object v0

    .line 1260
    check-cast v0, Landroid/net/Uri;

    .line 1261
    .line 1262
    goto :goto_19

    .line 1263
    :cond_4f
    invoke-static {p1, p0}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 1264
    .line 1265
    .line 1266
    new-instance p0, Lcq/r;

    .line 1267
    .line 1268
    invoke-direct {p0, v0, v1, v2}, Lcq/r;-><init>(Landroid/net/Uri;Landroid/os/Bundle;[B)V

    .line 1269
    .line 1270
    .line 1271
    return-object p0

    .line 1272
    :pswitch_19
    invoke-static {p1}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 1273
    .line 1274
    .line 1275
    move-result p0

    .line 1276
    const/4 v0, 0x0

    .line 1277
    move-object v1, v0

    .line 1278
    :goto_1a
    invoke-virtual {p1}, Landroid/os/Parcel;->dataPosition()I

    .line 1279
    .line 1280
    .line 1281
    move-result v2

    .line 1282
    if-ge v2, p0, :cond_52

    .line 1283
    .line 1284
    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    .line 1285
    .line 1286
    .line 1287
    move-result v2

    .line 1288
    int-to-char v3, v2

    .line 1289
    const/4 v4, 0x2

    .line 1290
    if-eq v3, v4, :cond_51

    .line 1291
    .line 1292
    const/4 v4, 0x3

    .line 1293
    if-eq v3, v4, :cond_50

    .line 1294
    .line 1295
    invoke-static {p1, v2}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 1296
    .line 1297
    .line 1298
    goto :goto_1a

    .line 1299
    :cond_50
    invoke-static {p1, v2}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 1300
    .line 1301
    .line 1302
    move-result-object v1

    .line 1303
    goto :goto_1a

    .line 1304
    :cond_51
    invoke-static {p1, v2}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 1305
    .line 1306
    .line 1307
    move-result-object v0

    .line 1308
    goto :goto_1a

    .line 1309
    :cond_52
    invoke-static {p1, p0}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 1310
    .line 1311
    .line 1312
    new-instance p0, Lcom/google/android/gms/wearable/internal/DataItemAssetParcelable;

    .line 1313
    .line 1314
    invoke-direct {p0, v0, v1}, Lcom/google/android/gms/wearable/internal/DataItemAssetParcelable;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 1315
    .line 1316
    .line 1317
    return-object p0

    .line 1318
    :pswitch_1a
    invoke-static {p1}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 1319
    .line 1320
    .line 1321
    move-result p0

    .line 1322
    const/4 v0, 0x0

    .line 1323
    const/4 v1, 0x0

    .line 1324
    move-object v8, v0

    .line 1325
    move-object v9, v8

    .line 1326
    move-object v10, v9

    .line 1327
    move v3, v1

    .line 1328
    move v4, v3

    .line 1329
    move v5, v4

    .line 1330
    move v6, v5

    .line 1331
    move v7, v6

    .line 1332
    :goto_1b
    invoke-virtual {p1}, Landroid/os/Parcel;->dataPosition()I

    .line 1333
    .line 1334
    .line 1335
    move-result v0

    .line 1336
    if-ge v0, p0, :cond_53

    .line 1337
    .line 1338
    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    .line 1339
    .line 1340
    .line 1341
    move-result v0

    .line 1342
    int-to-char v1, v0

    .line 1343
    packed-switch v1, :pswitch_data_1

    .line 1344
    .line 1345
    .line 1346
    invoke-static {p1, v0}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 1347
    .line 1348
    .line 1349
    goto :goto_1b

    .line 1350
    :pswitch_1b
    invoke-static {p1, v0}, Ljp/xb;->t(Landroid/os/Parcel;I)Ljava/lang/Long;

    .line 1351
    .line 1352
    .line 1353
    move-result-object v10

    .line 1354
    goto :goto_1b

    .line 1355
    :pswitch_1c
    invoke-static {p1, v0}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 1356
    .line 1357
    .line 1358
    move-result-object v9

    .line 1359
    goto :goto_1b

    .line 1360
    :pswitch_1d
    sget-object v1, Lcq/c;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 1361
    .line 1362
    invoke-static {p1, v0, v1}, Ljp/xb;->j(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Ljava/util/ArrayList;

    .line 1363
    .line 1364
    .line 1365
    move-result-object v8

    .line 1366
    goto :goto_1b

    .line 1367
    :pswitch_1e
    invoke-static {p1, v0}, Ljp/xb;->l(Landroid/os/Parcel;I)Z

    .line 1368
    .line 1369
    .line 1370
    move-result v7

    .line 1371
    goto :goto_1b

    .line 1372
    :pswitch_1f
    invoke-static {p1, v0}, Ljp/xb;->l(Landroid/os/Parcel;I)Z

    .line 1373
    .line 1374
    .line 1375
    move-result v6

    .line 1376
    goto :goto_1b

    .line 1377
    :pswitch_20
    invoke-static {p1, v0}, Ljp/xb;->l(Landroid/os/Parcel;I)Z

    .line 1378
    .line 1379
    .line 1380
    move-result v5

    .line 1381
    goto :goto_1b

    .line 1382
    :pswitch_21
    invoke-static {p1, v0}, Ljp/xb;->l(Landroid/os/Parcel;I)Z

    .line 1383
    .line 1384
    .line 1385
    move-result v4

    .line 1386
    goto :goto_1b

    .line 1387
    :pswitch_22
    invoke-static {p1, v0}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 1388
    .line 1389
    .line 1390
    move-result v3

    .line 1391
    goto :goto_1b

    .line 1392
    :cond_53
    invoke-static {p1, p0}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 1393
    .line 1394
    .line 1395
    new-instance v2, Lcq/k;

    .line 1396
    .line 1397
    invoke-direct/range {v2 .. v10}, Lcq/k;-><init>(IZZZZLjava/util/ArrayList;Ljava/lang/String;Ljava/lang/Long;)V

    .line 1398
    .line 1399
    .line 1400
    return-object v2

    .line 1401
    :pswitch_23
    invoke-static {p1}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 1402
    .line 1403
    .line 1404
    move-result p0

    .line 1405
    const/4 v0, 0x0

    .line 1406
    const/4 v1, 0x0

    .line 1407
    :goto_1c
    invoke-virtual {p1}, Landroid/os/Parcel;->dataPosition()I

    .line 1408
    .line 1409
    .line 1410
    move-result v2

    .line 1411
    if-ge v2, p0, :cond_56

    .line 1412
    .line 1413
    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    .line 1414
    .line 1415
    .line 1416
    move-result v2

    .line 1417
    int-to-char v3, v2

    .line 1418
    const/4 v4, 0x1

    .line 1419
    if-eq v3, v4, :cond_55

    .line 1420
    .line 1421
    const/4 v4, 0x2

    .line 1422
    if-eq v3, v4, :cond_54

    .line 1423
    .line 1424
    invoke-static {p1, v2}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 1425
    .line 1426
    .line 1427
    goto :goto_1c

    .line 1428
    :cond_54
    invoke-static {p1, v2}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 1429
    .line 1430
    .line 1431
    move-result-object v0

    .line 1432
    goto :goto_1c

    .line 1433
    :cond_55
    invoke-static {p1, v2}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 1434
    .line 1435
    .line 1436
    move-result v1

    .line 1437
    goto :goto_1c

    .line 1438
    :cond_56
    invoke-static {p1, p0}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 1439
    .line 1440
    .line 1441
    new-instance p0, Lcq/j;

    .line 1442
    .line 1443
    invoke-direct {p0, v1, v0}, Lcq/j;-><init>(ILjava/lang/String;)V

    .line 1444
    .line 1445
    .line 1446
    return-object p0

    .line 1447
    :pswitch_24
    invoke-static {p1}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 1448
    .line 1449
    .line 1450
    move-result p0

    .line 1451
    const/4 v0, 0x0

    .line 1452
    :goto_1d
    invoke-virtual {p1}, Landroid/os/Parcel;->dataPosition()I

    .line 1453
    .line 1454
    .line 1455
    move-result v1

    .line 1456
    if-ge v1, p0, :cond_58

    .line 1457
    .line 1458
    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    .line 1459
    .line 1460
    .line 1461
    move-result v1

    .line 1462
    int-to-char v2, v1

    .line 1463
    const/4 v3, 0x2

    .line 1464
    if-eq v2, v3, :cond_57

    .line 1465
    .line 1466
    invoke-static {p1, v1}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 1467
    .line 1468
    .line 1469
    goto :goto_1d

    .line 1470
    :cond_57
    invoke-static {p1, v1}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 1471
    .line 1472
    .line 1473
    move-result v0

    .line 1474
    goto :goto_1d

    .line 1475
    :cond_58
    invoke-static {p1, p0}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 1476
    .line 1477
    .line 1478
    new-instance p0, Lcq/h;

    .line 1479
    .line 1480
    invoke-direct {p0, v0}, Lcq/h;-><init>(I)V

    .line 1481
    .line 1482
    .line 1483
    return-object p0

    .line 1484
    nop

    .line 1485
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_24
        :pswitch_23
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
    :pswitch_data_1
    .packed-switch 0x1
        :pswitch_22
        :pswitch_21
        :pswitch_20
        :pswitch_1f
        :pswitch_1e
        :pswitch_1d
        :pswitch_1c
        :pswitch_1b
    .end packed-switch
.end method

.method public final synthetic newArray(I)[Ljava/lang/Object;
    .locals 0

    .line 1
    iget p0, p0, Lcq/i;->a:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-array p0, p1, [Lcq/s0;

    .line 7
    .line 8
    return-object p0

    .line 9
    :pswitch_0
    new-array p0, p1, [Lcq/r0;

    .line 10
    .line 11
    return-object p0

    .line 12
    :pswitch_1
    new-array p0, p1, [Lcq/q0;

    .line 13
    .line 14
    return-object p0

    .line 15
    :pswitch_2
    new-array p0, p1, [Lcq/p0;

    .line 16
    .line 17
    return-object p0

    .line 18
    :pswitch_3
    new-array p0, p1, [Lcq/o0;

    .line 19
    .line 20
    return-object p0

    .line 21
    :pswitch_4
    new-array p0, p1, [Lcq/m0;

    .line 22
    .line 23
    return-object p0

    .line 24
    :pswitch_5
    new-array p0, p1, [Lcq/l0;

    .line 25
    .line 26
    return-object p0

    .line 27
    :pswitch_6
    new-array p0, p1, [Lcq/k0;

    .line 28
    .line 29
    return-object p0

    .line 30
    :pswitch_7
    new-array p0, p1, [Lcq/j0;

    .line 31
    .line 32
    return-object p0

    .line 33
    :pswitch_8
    new-array p0, p1, [Lcq/i0;

    .line 34
    .line 35
    return-object p0

    .line 36
    :pswitch_9
    new-array p0, p1, [Lcq/h0;

    .line 37
    .line 38
    return-object p0

    .line 39
    :pswitch_a
    new-array p0, p1, [Lcq/g0;

    .line 40
    .line 41
    return-object p0

    .line 42
    :pswitch_b
    new-array p0, p1, [Lcq/f0;

    .line 43
    .line 44
    return-object p0

    .line 45
    :pswitch_c
    new-array p0, p1, [Lcq/e0;

    .line 46
    .line 47
    return-object p0

    .line 48
    :pswitch_d
    new-array p0, p1, [Lcq/d0;

    .line 49
    .line 50
    return-object p0

    .line 51
    :pswitch_e
    new-array p0, p1, [Lcq/c0;

    .line 52
    .line 53
    return-object p0

    .line 54
    :pswitch_f
    new-array p0, p1, [Lcq/b0;

    .line 55
    .line 56
    return-object p0

    .line 57
    :pswitch_10
    new-array p0, p1, [Lcq/a0;

    .line 58
    .line 59
    return-object p0

    .line 60
    :pswitch_11
    new-array p0, p1, [Lcq/z;

    .line 61
    .line 62
    return-object p0

    .line 63
    :pswitch_12
    new-array p0, p1, [Lcq/y;

    .line 64
    .line 65
    return-object p0

    .line 66
    :pswitch_13
    new-array p0, p1, [Lcq/x;

    .line 67
    .line 68
    return-object p0

    .line 69
    :pswitch_14
    new-array p0, p1, [Lcq/w;

    .line 70
    .line 71
    return-object p0

    .line 72
    :pswitch_15
    new-array p0, p1, [Lcq/v;

    .line 73
    .line 74
    return-object p0

    .line 75
    :pswitch_16
    new-array p0, p1, [Lcq/u;

    .line 76
    .line 77
    return-object p0

    .line 78
    :pswitch_17
    new-array p0, p1, [Lcq/t;

    .line 79
    .line 80
    return-object p0

    .line 81
    :pswitch_18
    new-array p0, p1, [Lcq/r;

    .line 82
    .line 83
    return-object p0

    .line 84
    :pswitch_19
    new-array p0, p1, [Lcom/google/android/gms/wearable/internal/DataItemAssetParcelable;

    .line 85
    .line 86
    return-object p0

    .line 87
    :pswitch_1a
    new-array p0, p1, [Lcq/k;

    .line 88
    .line 89
    return-object p0

    .line 90
    :pswitch_1b
    new-array p0, p1, [Lcq/j;

    .line 91
    .line 92
    return-object p0

    .line 93
    :pswitch_1c
    new-array p0, p1, [Lcq/h;

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
