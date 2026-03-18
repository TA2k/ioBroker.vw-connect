.class public final Lcq/x0;
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
    iput p1, p0, Lcq/x0;->a:I

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
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    iget v0, v0, Lcq/x0;->a:I

    .line 6
    .line 7
    packed-switch v0, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    const-string v0, "parcel"

    .line 11
    .line 12
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    new-instance v0, Lgl/b;

    .line 16
    .line 17
    invoke-virtual {v1}, Landroid/os/Parcel;->readInt()I

    .line 18
    .line 19
    .line 20
    move-result v2

    .line 21
    invoke-virtual {v1}, Landroid/os/Parcel;->readInt()I

    .line 22
    .line 23
    .line 24
    move-result v3

    .line 25
    invoke-virtual {v1}, Landroid/os/Parcel;->createStringArrayList()Ljava/util/ArrayList;

    .line 26
    .line 27
    .line 28
    move-result-object v4

    .line 29
    invoke-virtual {v1}, Landroid/os/Parcel;->readInt()I

    .line 30
    .line 31
    .line 32
    move-result v1

    .line 33
    if-eqz v1, :cond_0

    .line 34
    .line 35
    const/4 v1, 0x1

    .line 36
    goto :goto_0

    .line 37
    :cond_0
    const/4 v1, 0x0

    .line 38
    :goto_0
    invoke-direct {v0, v2, v3, v4, v1}, Lgl/b;-><init>(IILjava/util/ArrayList;Z)V

    .line 39
    .line 40
    .line 41
    return-object v0

    .line 42
    :pswitch_0
    const-string v0, "parcel"

    .line 43
    .line 44
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    invoke-virtual {v1}, Landroid/os/Parcel;->readInt()I

    .line 48
    .line 49
    .line 50
    move-result v0

    .line 51
    new-instance v2, Ljava/util/ArrayList;

    .line 52
    .line 53
    invoke-direct {v2, v0}, Ljava/util/ArrayList;-><init>(I)V

    .line 54
    .line 55
    .line 56
    const/4 v3, 0x0

    .line 57
    move v4, v3

    .line 58
    :goto_1
    if-eq v4, v0, :cond_1

    .line 59
    .line 60
    const-class v5, Lgl/a;

    .line 61
    .line 62
    invoke-virtual {v5}, Ljava/lang/Class;->getClassLoader()Ljava/lang/ClassLoader;

    .line 63
    .line 64
    .line 65
    move-result-object v5

    .line 66
    invoke-virtual {v1, v5}, Landroid/os/Parcel;->readParcelable(Ljava/lang/ClassLoader;)Landroid/os/Parcelable;

    .line 67
    .line 68
    .line 69
    move-result-object v5

    .line 70
    invoke-virtual {v2, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 71
    .line 72
    .line 73
    add-int/lit8 v4, v4, 0x1

    .line 74
    .line 75
    goto :goto_1

    .line 76
    :cond_1
    invoke-virtual {v1}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 77
    .line 78
    .line 79
    move-result-object v0

    .line 80
    invoke-virtual {v1}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 81
    .line 82
    .line 83
    move-result-object v4

    .line 84
    invoke-virtual {v1}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 85
    .line 86
    .line 87
    move-result-object v5

    .line 88
    invoke-virtual {v1}, Landroid/os/Parcel;->readInt()I

    .line 89
    .line 90
    .line 91
    move-result v1

    .line 92
    if-eqz v1, :cond_2

    .line 93
    .line 94
    const/4 v3, 0x1

    .line 95
    :cond_2
    move v6, v3

    .line 96
    new-instance v1, Lgl/a;

    .line 97
    .line 98
    move-object v3, v0

    .line 99
    invoke-direct/range {v1 .. v6}, Lgl/a;-><init>(Ljava/util/ArrayList;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    .line 100
    .line 101
    .line 102
    return-object v1

    .line 103
    :pswitch_1
    const-string v0, "inParcel"

    .line 104
    .line 105
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 106
    .line 107
    .line 108
    new-instance v0, Le/j;

    .line 109
    .line 110
    const-class v2, Landroid/content/IntentSender;

    .line 111
    .line 112
    invoke-virtual {v2}, Ljava/lang/Class;->getClassLoader()Ljava/lang/ClassLoader;

    .line 113
    .line 114
    .line 115
    move-result-object v2

    .line 116
    invoke-virtual {v1, v2}, Landroid/os/Parcel;->readParcelable(Ljava/lang/ClassLoader;)Landroid/os/Parcelable;

    .line 117
    .line 118
    .line 119
    move-result-object v2

    .line 120
    invoke-static {v2}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 121
    .line 122
    .line 123
    check-cast v2, Landroid/content/IntentSender;

    .line 124
    .line 125
    const-class v3, Landroid/content/Intent;

    .line 126
    .line 127
    invoke-virtual {v3}, Ljava/lang/Class;->getClassLoader()Ljava/lang/ClassLoader;

    .line 128
    .line 129
    .line 130
    move-result-object v3

    .line 131
    invoke-virtual {v1, v3}, Landroid/os/Parcel;->readParcelable(Ljava/lang/ClassLoader;)Landroid/os/Parcelable;

    .line 132
    .line 133
    .line 134
    move-result-object v3

    .line 135
    check-cast v3, Landroid/content/Intent;

    .line 136
    .line 137
    invoke-virtual {v1}, Landroid/os/Parcel;->readInt()I

    .line 138
    .line 139
    .line 140
    move-result v4

    .line 141
    invoke-virtual {v1}, Landroid/os/Parcel;->readInt()I

    .line 142
    .line 143
    .line 144
    move-result v1

    .line 145
    invoke-direct {v0, v2, v3, v4, v1}, Le/j;-><init>(Landroid/content/IntentSender;Landroid/content/Intent;II)V

    .line 146
    .line 147
    .line 148
    return-object v0

    .line 149
    :pswitch_2
    const-string v0, "parcel"

    .line 150
    .line 151
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 152
    .line 153
    .line 154
    new-instance v0, Le/a;

    .line 155
    .line 156
    invoke-virtual {v1}, Landroid/os/Parcel;->readInt()I

    .line 157
    .line 158
    .line 159
    move-result v2

    .line 160
    invoke-virtual {v1}, Landroid/os/Parcel;->readInt()I

    .line 161
    .line 162
    .line 163
    move-result v3

    .line 164
    if-nez v3, :cond_3

    .line 165
    .line 166
    const/4 v1, 0x0

    .line 167
    goto :goto_2

    .line 168
    :cond_3
    sget-object v3, Landroid/content/Intent;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 169
    .line 170
    invoke-interface {v3, v1}, Landroid/os/Parcelable$Creator;->createFromParcel(Landroid/os/Parcel;)Ljava/lang/Object;

    .line 171
    .line 172
    .line 173
    move-result-object v1

    .line 174
    check-cast v1, Landroid/content/Intent;

    .line 175
    .line 176
    :goto_2
    invoke-direct {v0, v1, v2}, Le/a;-><init>(Landroid/content/Intent;I)V

    .line 177
    .line 178
    .line 179
    return-object v0

    .line 180
    :pswitch_3
    const-string v0, "parcel"

    .line 181
    .line 182
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 183
    .line 184
    .line 185
    move-object v0, v1

    .line 186
    new-instance v1, Ldd/f;

    .line 187
    .line 188
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 189
    .line 190
    .line 191
    move-result-object v2

    .line 192
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 193
    .line 194
    .line 195
    move-result-object v3

    .line 196
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 197
    .line 198
    .line 199
    move-result-object v4

    .line 200
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 201
    .line 202
    .line 203
    move-result-object v5

    .line 204
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 205
    .line 206
    .line 207
    move-result-object v6

    .line 208
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 209
    .line 210
    .line 211
    move-result-object v7

    .line 212
    sget-object v8, Lgz0/p;->Companion:Lgz0/o;

    .line 213
    .line 214
    invoke-virtual {v0}, Landroid/os/Parcel;->readLong()J

    .line 215
    .line 216
    .line 217
    move-result-wide v9

    .line 218
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 219
    .line 220
    .line 221
    invoke-static {v9, v10}, Lgz0/o;->a(J)Lgz0/p;

    .line 222
    .line 223
    .line 224
    move-result-object v8

    .line 225
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 226
    .line 227
    .line 228
    move-result-object v9

    .line 229
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 230
    .line 231
    .line 232
    move-result-object v10

    .line 233
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 234
    .line 235
    .line 236
    move-result-object v11

    .line 237
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 238
    .line 239
    .line 240
    move-result-object v12

    .line 241
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 242
    .line 243
    .line 244
    move-result-object v13

    .line 245
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 246
    .line 247
    .line 248
    move-result-object v14

    .line 249
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 250
    .line 251
    .line 252
    move-result-object v15

    .line 253
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 254
    .line 255
    .line 256
    move-result-object v16

    .line 257
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 258
    .line 259
    .line 260
    move-result-object v17

    .line 261
    invoke-direct/range {v1 .. v17}, Ldd/f;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lgz0/p;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 262
    .line 263
    .line 264
    return-object v1

    .line 265
    :pswitch_4
    move-object v0, v1

    .line 266
    const-string v1, "parcel"

    .line 267
    .line 268
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 269
    .line 270
    .line 271
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 272
    .line 273
    .line 274
    move-result-object v1

    .line 275
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 276
    .line 277
    .line 278
    move-result-object v2

    .line 279
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 280
    .line 281
    .line 282
    move-result v3

    .line 283
    new-instance v4, Ljava/util/ArrayList;

    .line 284
    .line 285
    invoke-direct {v4, v3}, Ljava/util/ArrayList;-><init>(I)V

    .line 286
    .line 287
    .line 288
    const/4 v5, 0x0

    .line 289
    :goto_3
    if-eq v5, v3, :cond_4

    .line 290
    .line 291
    sget-object v6, Ldc/q;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 292
    .line 293
    const/4 v7, 0x1

    .line 294
    invoke-static {v6, v0, v4, v5, v7}, Lvj/b;->a(Landroid/os/Parcelable$Creator;Landroid/os/Parcel;Ljava/util/ArrayList;II)I

    .line 295
    .line 296
    .line 297
    move-result v5

    .line 298
    goto :goto_3

    .line 299
    :cond_4
    new-instance v0, Ldc/w;

    .line 300
    .line 301
    invoke-direct {v0, v1, v2, v4}, Ldc/w;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/util/ArrayList;)V

    .line 302
    .line 303
    .line 304
    return-object v0

    .line 305
    :pswitch_5
    move-object v0, v1

    .line 306
    const-string v1, "parcel"

    .line 307
    .line 308
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 309
    .line 310
    .line 311
    new-instance v1, Ldc/q;

    .line 312
    .line 313
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 314
    .line 315
    .line 316
    move-result-object v2

    .line 317
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 318
    .line 319
    .line 320
    move-result-object v0

    .line 321
    invoke-direct {v1, v2, v0}, Ldc/q;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 322
    .line 323
    .line 324
    return-object v1

    .line 325
    :pswitch_6
    move-object v0, v1

    .line 326
    const-string v1, "parcel"

    .line 327
    .line 328
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 329
    .line 330
    .line 331
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 332
    .line 333
    .line 334
    move-result-object v3

    .line 335
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 336
    .line 337
    .line 338
    move-result-object v4

    .line 339
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 340
    .line 341
    .line 342
    move-result-object v1

    .line 343
    invoke-static {v1}, Ldc/m;->valueOf(Ljava/lang/String;)Ldc/m;

    .line 344
    .line 345
    .line 346
    move-result-object v5

    .line 347
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 348
    .line 349
    .line 350
    move-result-object v6

    .line 351
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 352
    .line 353
    .line 354
    move-result v1

    .line 355
    new-instance v7, Ljava/util/ArrayList;

    .line 356
    .line 357
    invoke-direct {v7, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 358
    .line 359
    .line 360
    const/4 v2, 0x0

    .line 361
    :goto_4
    if-eq v2, v1, :cond_5

    .line 362
    .line 363
    sget-object v8, Ldc/q;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 364
    .line 365
    const/4 v9, 0x1

    .line 366
    invoke-static {v8, v0, v7, v2, v9}, Lvj/b;->a(Landroid/os/Parcelable$Creator;Landroid/os/Parcel;Ljava/util/ArrayList;II)I

    .line 367
    .line 368
    .line 369
    move-result v2

    .line 370
    goto :goto_4

    .line 371
    :cond_5
    new-instance v2, Ldc/n;

    .line 372
    .line 373
    invoke-direct/range {v2 .. v7}, Ldc/n;-><init>(Ljava/lang/String;Ljava/lang/String;Ldc/m;Ljava/lang/String;Ljava/util/ArrayList;)V

    .line 374
    .line 375
    .line 376
    return-object v2

    .line 377
    :pswitch_7
    move-object v0, v1

    .line 378
    new-instance v1, Landroidx/versionedparcelable/ParcelImpl;

    .line 379
    .line 380
    invoke-direct {v1, v0}, Landroidx/versionedparcelable/ParcelImpl;-><init>(Landroid/os/Parcel;)V

    .line 381
    .line 382
    .line 383
    return-object v1

    .line 384
    :pswitch_8
    move-object v0, v1

    .line 385
    invoke-static {v0}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 386
    .line 387
    .line 388
    move-result v1

    .line 389
    const/4 v2, 0x0

    .line 390
    move v3, v2

    .line 391
    :goto_5
    invoke-virtual {v0}, Landroid/os/Parcel;->dataPosition()I

    .line 392
    .line 393
    .line 394
    move-result v4

    .line 395
    if-ge v4, v1, :cond_8

    .line 396
    .line 397
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 398
    .line 399
    .line 400
    move-result v4

    .line 401
    int-to-char v5, v4

    .line 402
    const/4 v6, 0x1

    .line 403
    if-eq v5, v6, :cond_7

    .line 404
    .line 405
    const/4 v6, 0x2

    .line 406
    if-eq v5, v6, :cond_6

    .line 407
    .line 408
    invoke-static {v0, v4}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 409
    .line 410
    .line 411
    goto :goto_5

    .line 412
    :cond_6
    invoke-static {v0, v4}, Ljp/xb;->l(Landroid/os/Parcel;I)Z

    .line 413
    .line 414
    .line 415
    move-result v3

    .line 416
    goto :goto_5

    .line 417
    :cond_7
    invoke-static {v0, v4}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 418
    .line 419
    .line 420
    move-result v2

    .line 421
    goto :goto_5

    .line 422
    :cond_8
    invoke-static {v0, v1}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 423
    .line 424
    .line 425
    new-instance v0, Lcq/c2;

    .line 426
    .line 427
    invoke-direct {v0, v2, v3}, Lcq/c2;-><init>(IZ)V

    .line 428
    .line 429
    .line 430
    return-object v0

    .line 431
    :pswitch_9
    move-object v0, v1

    .line 432
    invoke-static {v0}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 433
    .line 434
    .line 435
    move-result v1

    .line 436
    const/4 v2, 0x0

    .line 437
    const/4 v3, 0x0

    .line 438
    :goto_6
    invoke-virtual {v0}, Landroid/os/Parcel;->dataPosition()I

    .line 439
    .line 440
    .line 441
    move-result v4

    .line 442
    if-ge v4, v1, :cond_b

    .line 443
    .line 444
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 445
    .line 446
    .line 447
    move-result v4

    .line 448
    int-to-char v5, v4

    .line 449
    const/4 v6, 0x1

    .line 450
    if-eq v5, v6, :cond_a

    .line 451
    .line 452
    const/4 v6, 0x2

    .line 453
    if-eq v5, v6, :cond_9

    .line 454
    .line 455
    invoke-static {v0, v4}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 456
    .line 457
    .line 458
    goto :goto_6

    .line 459
    :cond_9
    invoke-static {v0, v4}, Ljp/xb;->h(Landroid/os/Parcel;I)Ljava/util/ArrayList;

    .line 460
    .line 461
    .line 462
    move-result-object v2

    .line 463
    goto :goto_6

    .line 464
    :cond_a
    invoke-static {v0, v4}, Ljp/xb;->l(Landroid/os/Parcel;I)Z

    .line 465
    .line 466
    .line 467
    move-result v3

    .line 468
    goto :goto_6

    .line 469
    :cond_b
    invoke-static {v0, v1}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 470
    .line 471
    .line 472
    new-instance v0, Lcq/a2;

    .line 473
    .line 474
    invoke-direct {v0, v2, v3}, Lcq/a2;-><init>(Ljava/util/ArrayList;Z)V

    .line 475
    .line 476
    .line 477
    return-object v0

    .line 478
    :pswitch_a
    move-object v0, v1

    .line 479
    invoke-static {v0}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 480
    .line 481
    .line 482
    move-result v1

    .line 483
    const/4 v2, 0x0

    .line 484
    const/4 v3, 0x0

    .line 485
    move v4, v3

    .line 486
    move-object v3, v2

    .line 487
    :goto_7
    invoke-virtual {v0}, Landroid/os/Parcel;->dataPosition()I

    .line 488
    .line 489
    .line 490
    move-result v5

    .line 491
    if-ge v5, v1, :cond_f

    .line 492
    .line 493
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 494
    .line 495
    .line 496
    move-result v5

    .line 497
    int-to-char v6, v5

    .line 498
    const/4 v7, 0x1

    .line 499
    if-eq v6, v7, :cond_e

    .line 500
    .line 501
    const/4 v7, 0x2

    .line 502
    if-eq v6, v7, :cond_d

    .line 503
    .line 504
    const/4 v7, 0x3

    .line 505
    if-eq v6, v7, :cond_c

    .line 506
    .line 507
    invoke-static {v0, v5}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 508
    .line 509
    .line 510
    goto :goto_7

    .line 511
    :cond_c
    sget-object v3, Lcq/w1;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 512
    .line 513
    invoke-static {v0, v5, v3}, Ljp/xb;->e(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 514
    .line 515
    .line 516
    move-result-object v3

    .line 517
    check-cast v3, Lcq/w1;

    .line 518
    .line 519
    goto :goto_7

    .line 520
    :cond_d
    sget-object v2, Lcq/y1;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 521
    .line 522
    invoke-static {v0, v5, v2}, Ljp/xb;->j(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Ljava/util/ArrayList;

    .line 523
    .line 524
    .line 525
    move-result-object v2

    .line 526
    goto :goto_7

    .line 527
    :cond_e
    invoke-static {v0, v5}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 528
    .line 529
    .line 530
    move-result v4

    .line 531
    goto :goto_7

    .line 532
    :cond_f
    invoke-static {v0, v1}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 533
    .line 534
    .line 535
    new-instance v0, Lcq/z1;

    .line 536
    .line 537
    invoke-direct {v0, v4, v2, v3}, Lcq/z1;-><init>(ILjava/util/ArrayList;Lcq/w1;)V

    .line 538
    .line 539
    .line 540
    return-object v0

    .line 541
    :pswitch_b
    move-object v0, v1

    .line 542
    invoke-static {v0}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 543
    .line 544
    .line 545
    move-result v1

    .line 546
    const/4 v2, 0x0

    .line 547
    move-object v4, v2

    .line 548
    move-object v5, v4

    .line 549
    move-object v6, v5

    .line 550
    move-object v7, v6

    .line 551
    move-object v8, v7

    .line 552
    move-object v9, v8

    .line 553
    move-object v10, v9

    .line 554
    :goto_8
    invoke-virtual {v0}, Landroid/os/Parcel;->dataPosition()I

    .line 555
    .line 556
    .line 557
    move-result v2

    .line 558
    if-ge v2, v1, :cond_10

    .line 559
    .line 560
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 561
    .line 562
    .line 563
    move-result v2

    .line 564
    int-to-char v3, v2

    .line 565
    packed-switch v3, :pswitch_data_1

    .line 566
    .line 567
    .line 568
    invoke-static {v0, v2}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 569
    .line 570
    .line 571
    goto :goto_8

    .line 572
    :pswitch_c
    sget-object v3, Lcq/a2;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 573
    .line 574
    invoke-static {v0, v2, v3}, Ljp/xb;->e(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 575
    .line 576
    .line 577
    move-result-object v2

    .line 578
    move-object v10, v2

    .line 579
    check-cast v10, Lcq/a2;

    .line 580
    .line 581
    goto :goto_8

    .line 582
    :pswitch_d
    invoke-static {v0, v2}, Ljp/xb;->p(Landroid/os/Parcel;I)Ljava/lang/Float;

    .line 583
    .line 584
    .line 585
    move-result-object v9

    .line 586
    goto :goto_8

    .line 587
    :pswitch_e
    invoke-static {v0, v2}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 588
    .line 589
    .line 590
    move-result-object v8

    .line 591
    goto :goto_8

    .line 592
    :pswitch_f
    invoke-static {v0, v2}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 593
    .line 594
    .line 595
    move-result-object v7

    .line 596
    goto :goto_8

    .line 597
    :pswitch_10
    sget-object v3, Lcq/w1;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 598
    .line 599
    invoke-static {v0, v2, v3}, Ljp/xb;->e(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 600
    .line 601
    .line 602
    move-result-object v2

    .line 603
    move-object v6, v2

    .line 604
    check-cast v6, Lcq/w1;

    .line 605
    .line 606
    goto :goto_8

    .line 607
    :pswitch_11
    invoke-static {v0, v2}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 608
    .line 609
    .line 610
    move-result-object v5

    .line 611
    goto :goto_8

    .line 612
    :pswitch_12
    invoke-static {v0, v2}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 613
    .line 614
    .line 615
    move-result-object v4

    .line 616
    goto :goto_8

    .line 617
    :cond_10
    invoke-static {v0, v1}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 618
    .line 619
    .line 620
    new-instance v3, Lcq/y1;

    .line 621
    .line 622
    invoke-direct/range {v3 .. v10}, Lcq/y1;-><init>(Ljava/lang/String;Ljava/lang/String;Lcq/w1;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Float;Lcq/a2;)V

    .line 623
    .line 624
    .line 625
    return-object v3

    .line 626
    :pswitch_13
    move-object v0, v1

    .line 627
    invoke-static {v0}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 628
    .line 629
    .line 630
    move-result v1

    .line 631
    const/4 v2, 0x0

    .line 632
    const/4 v3, 0x0

    .line 633
    move-object v6, v2

    .line 634
    move-object v7, v6

    .line 635
    move-object v8, v7

    .line 636
    move-object v9, v8

    .line 637
    move-object v10, v9

    .line 638
    move-object v11, v10

    .line 639
    move-object/from16 v16, v11

    .line 640
    .line 641
    move v5, v3

    .line 642
    move v12, v5

    .line 643
    move v13, v12

    .line 644
    move v14, v13

    .line 645
    move v15, v14

    .line 646
    :goto_9
    invoke-virtual {v0}, Landroid/os/Parcel;->dataPosition()I

    .line 647
    .line 648
    .line 649
    move-result v2

    .line 650
    if-ge v2, v1, :cond_11

    .line 651
    .line 652
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 653
    .line 654
    .line 655
    move-result v2

    .line 656
    int-to-char v3, v2

    .line 657
    packed-switch v3, :pswitch_data_2

    .line 658
    .line 659
    .line 660
    invoke-static {v0, v2}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 661
    .line 662
    .line 663
    goto :goto_9

    .line 664
    :pswitch_14
    invoke-static {v0, v2}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 665
    .line 666
    .line 667
    move-result-object v16

    .line 668
    goto :goto_9

    .line 669
    :pswitch_15
    invoke-static {v0, v2}, Ljp/xb;->m(Landroid/os/Parcel;I)B

    .line 670
    .line 671
    .line 672
    move-result v15

    .line 673
    goto :goto_9

    .line 674
    :pswitch_16
    invoke-static {v0, v2}, Ljp/xb;->m(Landroid/os/Parcel;I)B

    .line 675
    .line 676
    .line 677
    move-result v14

    .line 678
    goto :goto_9

    .line 679
    :pswitch_17
    invoke-static {v0, v2}, Ljp/xb;->m(Landroid/os/Parcel;I)B

    .line 680
    .line 681
    .line 682
    move-result v13

    .line 683
    goto :goto_9

    .line 684
    :pswitch_18
    invoke-static {v0, v2}, Ljp/xb;->m(Landroid/os/Parcel;I)B

    .line 685
    .line 686
    .line 687
    move-result v12

    .line 688
    goto :goto_9

    .line 689
    :pswitch_19
    invoke-static {v0, v2}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 690
    .line 691
    .line 692
    move-result-object v11

    .line 693
    goto :goto_9

    .line 694
    :pswitch_1a
    invoke-static {v0, v2}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 695
    .line 696
    .line 697
    move-result-object v10

    .line 698
    goto :goto_9

    .line 699
    :pswitch_1b
    invoke-static {v0, v2}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 700
    .line 701
    .line 702
    move-result-object v9

    .line 703
    goto :goto_9

    .line 704
    :pswitch_1c
    invoke-static {v0, v2}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 705
    .line 706
    .line 707
    move-result-object v8

    .line 708
    goto :goto_9

    .line 709
    :pswitch_1d
    invoke-static {v0, v2}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 710
    .line 711
    .line 712
    move-result-object v7

    .line 713
    goto :goto_9

    .line 714
    :pswitch_1e
    invoke-static {v0, v2}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 715
    .line 716
    .line 717
    move-result-object v6

    .line 718
    goto :goto_9

    .line 719
    :pswitch_1f
    invoke-static {v0, v2}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 720
    .line 721
    .line 722
    move-result v5

    .line 723
    goto :goto_9

    .line 724
    :cond_11
    invoke-static {v0, v1}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 725
    .line 726
    .line 727
    new-instance v4, Lcq/x1;

    .line 728
    .line 729
    invoke-direct/range {v4 .. v16}, Lcq/x1;-><init>(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;BBBBLjava/lang/String;)V

    .line 730
    .line 731
    .line 732
    return-object v4

    .line 733
    :pswitch_20
    move-object v0, v1

    .line 734
    invoke-static {v0}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 735
    .line 736
    .line 737
    move-result v1

    .line 738
    const/4 v2, 0x0

    .line 739
    const/4 v3, 0x0

    .line 740
    move v4, v3

    .line 741
    :goto_a
    invoke-virtual {v0}, Landroid/os/Parcel;->dataPosition()I

    .line 742
    .line 743
    .line 744
    move-result v5

    .line 745
    if-ge v5, v1, :cond_15

    .line 746
    .line 747
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 748
    .line 749
    .line 750
    move-result v5

    .line 751
    int-to-char v6, v5

    .line 752
    const/4 v7, 0x2

    .line 753
    if-eq v6, v7, :cond_14

    .line 754
    .line 755
    const/4 v7, 0x3

    .line 756
    if-eq v6, v7, :cond_13

    .line 757
    .line 758
    const/4 v7, 0x4

    .line 759
    if-eq v6, v7, :cond_12

    .line 760
    .line 761
    invoke-static {v0, v5}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 762
    .line 763
    .line 764
    goto :goto_a

    .line 765
    :cond_12
    invoke-static {v0, v5}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 766
    .line 767
    .line 768
    move-result-object v2

    .line 769
    goto :goto_a

    .line 770
    :cond_13
    invoke-static {v0, v5}, Ljp/xb;->m(Landroid/os/Parcel;I)B

    .line 771
    .line 772
    .line 773
    move-result v4

    .line 774
    goto :goto_a

    .line 775
    :cond_14
    invoke-static {v0, v5}, Ljp/xb;->m(Landroid/os/Parcel;I)B

    .line 776
    .line 777
    .line 778
    move-result v3

    .line 779
    goto :goto_a

    .line 780
    :cond_15
    invoke-static {v0, v1}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 781
    .line 782
    .line 783
    new-instance v0, Lcq/q1;

    .line 784
    .line 785
    invoke-direct {v0, v3, v4, v2}, Lcq/q1;-><init>(BBLjava/lang/String;)V

    .line 786
    .line 787
    .line 788
    return-object v0

    .line 789
    :pswitch_21
    move-object v0, v1

    .line 790
    invoke-static {v0}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 791
    .line 792
    .line 793
    move-result v1

    .line 794
    const/4 v2, 0x0

    .line 795
    const-wide/16 v3, 0x0

    .line 796
    .line 797
    const/4 v5, 0x0

    .line 798
    :goto_b
    invoke-virtual {v0}, Landroid/os/Parcel;->dataPosition()I

    .line 799
    .line 800
    .line 801
    move-result v6

    .line 802
    if-ge v6, v1, :cond_19

    .line 803
    .line 804
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 805
    .line 806
    .line 807
    move-result v6

    .line 808
    int-to-char v7, v6

    .line 809
    const/4 v8, 0x2

    .line 810
    if-eq v7, v8, :cond_18

    .line 811
    .line 812
    const/4 v8, 0x3

    .line 813
    if-eq v7, v8, :cond_17

    .line 814
    .line 815
    const/4 v8, 0x4

    .line 816
    if-eq v7, v8, :cond_16

    .line 817
    .line 818
    invoke-static {v0, v6}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 819
    .line 820
    .line 821
    goto :goto_b

    .line 822
    :cond_16
    sget-object v2, Lcq/e1;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 823
    .line 824
    invoke-static {v0, v6, v2}, Ljp/xb;->j(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Ljava/util/ArrayList;

    .line 825
    .line 826
    .line 827
    move-result-object v2

    .line 828
    goto :goto_b

    .line 829
    :cond_17
    invoke-static {v0, v6}, Ljp/xb;->s(Landroid/os/Parcel;I)J

    .line 830
    .line 831
    .line 832
    move-result-wide v3

    .line 833
    goto :goto_b

    .line 834
    :cond_18
    invoke-static {v0, v6}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 835
    .line 836
    .line 837
    move-result v5

    .line 838
    goto :goto_b

    .line 839
    :cond_19
    invoke-static {v0, v1}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 840
    .line 841
    .line 842
    new-instance v0, Lcq/l1;

    .line 843
    .line 844
    invoke-direct {v0, v5, v3, v4, v2}, Lcq/l1;-><init>(IJLjava/util/ArrayList;)V

    .line 845
    .line 846
    .line 847
    return-object v0

    .line 848
    :pswitch_22
    move-object v0, v1

    .line 849
    invoke-static {v0}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 850
    .line 851
    .line 852
    move-result v1

    .line 853
    const/4 v2, 0x0

    .line 854
    :goto_c
    invoke-virtual {v0}, Landroid/os/Parcel;->dataPosition()I

    .line 855
    .line 856
    .line 857
    move-result v3

    .line 858
    if-ge v3, v1, :cond_1b

    .line 859
    .line 860
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 861
    .line 862
    .line 863
    move-result v3

    .line 864
    int-to-char v4, v3

    .line 865
    const/4 v5, 0x2

    .line 866
    if-eq v4, v5, :cond_1a

    .line 867
    .line 868
    invoke-static {v0, v3}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 869
    .line 870
    .line 871
    goto :goto_c

    .line 872
    :cond_1a
    invoke-static {v0, v3}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 873
    .line 874
    .line 875
    move-result v2

    .line 876
    goto :goto_c

    .line 877
    :cond_1b
    invoke-static {v0, v1}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 878
    .line 879
    .line 880
    new-instance v0, Lcq/a1;

    .line 881
    .line 882
    invoke-direct {v0, v2}, Lcq/a1;-><init>(I)V

    .line 883
    .line 884
    .line 885
    return-object v0

    .line 886
    :pswitch_23
    move-object v0, v1

    .line 887
    invoke-static {v0}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 888
    .line 889
    .line 890
    move-result v1

    .line 891
    const/4 v2, 0x0

    .line 892
    move v3, v2

    .line 893
    :goto_d
    invoke-virtual {v0}, Landroid/os/Parcel;->dataPosition()I

    .line 894
    .line 895
    .line 896
    move-result v4

    .line 897
    if-ge v4, v1, :cond_1e

    .line 898
    .line 899
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 900
    .line 901
    .line 902
    move-result v4

    .line 903
    int-to-char v5, v4

    .line 904
    const/4 v6, 0x2

    .line 905
    if-eq v5, v6, :cond_1d

    .line 906
    .line 907
    const/4 v6, 0x3

    .line 908
    if-eq v5, v6, :cond_1c

    .line 909
    .line 910
    invoke-static {v0, v4}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 911
    .line 912
    .line 913
    goto :goto_d

    .line 914
    :cond_1c
    invoke-static {v0, v4}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 915
    .line 916
    .line 917
    move-result v3

    .line 918
    goto :goto_d

    .line 919
    :cond_1d
    invoke-static {v0, v4}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 920
    .line 921
    .line 922
    move-result v2

    .line 923
    goto :goto_d

    .line 924
    :cond_1e
    invoke-static {v0, v1}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 925
    .line 926
    .line 927
    new-instance v0, Lcq/k1;

    .line 928
    .line 929
    invoke-direct {v0, v2, v3}, Lcq/k1;-><init>(II)V

    .line 930
    .line 931
    .line 932
    return-object v0

    .line 933
    :pswitch_24
    move-object v0, v1

    .line 934
    invoke-static {v0}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 935
    .line 936
    .line 937
    move-result v1

    .line 938
    const/4 v2, 0x0

    .line 939
    const/4 v3, 0x0

    .line 940
    move v4, v3

    .line 941
    :goto_e
    invoke-virtual {v0}, Landroid/os/Parcel;->dataPosition()I

    .line 942
    .line 943
    .line 944
    move-result v5

    .line 945
    if-ge v5, v1, :cond_22

    .line 946
    .line 947
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 948
    .line 949
    .line 950
    move-result v5

    .line 951
    int-to-char v6, v5

    .line 952
    const/4 v7, 0x1

    .line 953
    if-eq v6, v7, :cond_21

    .line 954
    .line 955
    const/4 v7, 0x2

    .line 956
    if-eq v6, v7, :cond_20

    .line 957
    .line 958
    const/4 v7, 0x3

    .line 959
    if-eq v6, v7, :cond_1f

    .line 960
    .line 961
    invoke-static {v0, v5}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 962
    .line 963
    .line 964
    goto :goto_e

    .line 965
    :cond_1f
    invoke-static {v0, v5}, Ljp/xb;->b(Landroid/os/Parcel;I)[B

    .line 966
    .line 967
    .line 968
    move-result-object v2

    .line 969
    goto :goto_e

    .line 970
    :cond_20
    invoke-static {v0, v5}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 971
    .line 972
    .line 973
    move-result v4

    .line 974
    goto :goto_e

    .line 975
    :cond_21
    invoke-static {v0, v5}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 976
    .line 977
    .line 978
    move-result v3

    .line 979
    goto :goto_e

    .line 980
    :cond_22
    invoke-static {v0, v1}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 981
    .line 982
    .line 983
    new-instance v0, Lcq/j1;

    .line 984
    .line 985
    invoke-direct {v0, v2, v3, v4}, Lcq/j1;-><init>([BII)V

    .line 986
    .line 987
    .line 988
    return-object v0

    .line 989
    :pswitch_25
    move-object v0, v1

    .line 990
    invoke-static {v0}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 991
    .line 992
    .line 993
    move-result v1

    .line 994
    const/4 v2, 0x0

    .line 995
    :goto_f
    invoke-virtual {v0}, Landroid/os/Parcel;->dataPosition()I

    .line 996
    .line 997
    .line 998
    move-result v3

    .line 999
    if-ge v3, v1, :cond_24

    .line 1000
    .line 1001
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 1002
    .line 1003
    .line 1004
    move-result v3

    .line 1005
    int-to-char v4, v3

    .line 1006
    const/4 v5, 0x1

    .line 1007
    if-eq v4, v5, :cond_23

    .line 1008
    .line 1009
    invoke-static {v0, v3}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 1010
    .line 1011
    .line 1012
    goto :goto_f

    .line 1013
    :cond_23
    invoke-static {v0, v3}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 1014
    .line 1015
    .line 1016
    move-result-object v2

    .line 1017
    goto :goto_f

    .line 1018
    :cond_24
    invoke-static {v0, v1}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 1019
    .line 1020
    .line 1021
    new-instance v0, Lcq/i1;

    .line 1022
    .line 1023
    invoke-direct {v0, v2}, Lcq/i1;-><init>(Ljava/lang/String;)V

    .line 1024
    .line 1025
    .line 1026
    return-object v0

    .line 1027
    :pswitch_26
    move-object v0, v1

    .line 1028
    invoke-static {v0}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 1029
    .line 1030
    .line 1031
    move-result v1

    .line 1032
    const/4 v2, 0x0

    .line 1033
    :goto_10
    invoke-virtual {v0}, Landroid/os/Parcel;->dataPosition()I

    .line 1034
    .line 1035
    .line 1036
    move-result v3

    .line 1037
    if-ge v3, v1, :cond_26

    .line 1038
    .line 1039
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 1040
    .line 1041
    .line 1042
    move-result v3

    .line 1043
    int-to-char v4, v3

    .line 1044
    const/4 v5, 0x2

    .line 1045
    if-eq v4, v5, :cond_25

    .line 1046
    .line 1047
    invoke-static {v0, v3}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 1048
    .line 1049
    .line 1050
    goto :goto_10

    .line 1051
    :cond_25
    invoke-static {v0, v3}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 1052
    .line 1053
    .line 1054
    move-result v2

    .line 1055
    goto :goto_10

    .line 1056
    :cond_26
    invoke-static {v0, v1}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 1057
    .line 1058
    .line 1059
    new-instance v0, Lcq/h1;

    .line 1060
    .line 1061
    invoke-direct {v0, v2}, Lcq/h1;-><init>(I)V

    .line 1062
    .line 1063
    .line 1064
    return-object v0

    .line 1065
    :pswitch_27
    move-object v0, v1

    .line 1066
    invoke-static {v0}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 1067
    .line 1068
    .line 1069
    move-result v1

    .line 1070
    const/4 v2, 0x0

    .line 1071
    const/4 v3, 0x0

    .line 1072
    :goto_11
    invoke-virtual {v0}, Landroid/os/Parcel;->dataPosition()I

    .line 1073
    .line 1074
    .line 1075
    move-result v4

    .line 1076
    if-ge v4, v1, :cond_29

    .line 1077
    .line 1078
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 1079
    .line 1080
    .line 1081
    move-result v4

    .line 1082
    int-to-char v5, v4

    .line 1083
    const/4 v6, 0x2

    .line 1084
    if-eq v5, v6, :cond_28

    .line 1085
    .line 1086
    const/4 v6, 0x3

    .line 1087
    if-eq v5, v6, :cond_27

    .line 1088
    .line 1089
    invoke-static {v0, v4}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 1090
    .line 1091
    .line 1092
    goto :goto_11

    .line 1093
    :cond_27
    sget-object v2, Lcq/r;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 1094
    .line 1095
    invoke-static {v0, v4, v2}, Ljp/xb;->e(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 1096
    .line 1097
    .line 1098
    move-result-object v2

    .line 1099
    check-cast v2, Lcq/r;

    .line 1100
    .line 1101
    goto :goto_11

    .line 1102
    :cond_28
    invoke-static {v0, v4}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 1103
    .line 1104
    .line 1105
    move-result v3

    .line 1106
    goto :goto_11

    .line 1107
    :cond_29
    invoke-static {v0, v1}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 1108
    .line 1109
    .line 1110
    new-instance v0, Lcq/g1;

    .line 1111
    .line 1112
    invoke-direct {v0, v3, v2}, Lcq/g1;-><init>(ILcq/r;)V

    .line 1113
    .line 1114
    .line 1115
    return-object v0

    .line 1116
    :pswitch_28
    move-object v0, v1

    .line 1117
    invoke-static {v0}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 1118
    .line 1119
    .line 1120
    move-result v1

    .line 1121
    const/4 v2, 0x0

    .line 1122
    const/4 v3, 0x0

    .line 1123
    :goto_12
    invoke-virtual {v0}, Landroid/os/Parcel;->dataPosition()I

    .line 1124
    .line 1125
    .line 1126
    move-result v4

    .line 1127
    if-ge v4, v1, :cond_2c

    .line 1128
    .line 1129
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 1130
    .line 1131
    .line 1132
    move-result v4

    .line 1133
    int-to-char v5, v4

    .line 1134
    const/4 v6, 0x2

    .line 1135
    if-eq v5, v6, :cond_2b

    .line 1136
    .line 1137
    const/4 v6, 0x3

    .line 1138
    if-eq v5, v6, :cond_2a

    .line 1139
    .line 1140
    invoke-static {v0, v4}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 1141
    .line 1142
    .line 1143
    goto :goto_12

    .line 1144
    :cond_2a
    invoke-static {v0, v4}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 1145
    .line 1146
    .line 1147
    move-result-object v2

    .line 1148
    goto :goto_12

    .line 1149
    :cond_2b
    invoke-static {v0, v4}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 1150
    .line 1151
    .line 1152
    move-result v3

    .line 1153
    goto :goto_12

    .line 1154
    :cond_2c
    invoke-static {v0, v1}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 1155
    .line 1156
    .line 1157
    new-instance v0, Lcq/f1;

    .line 1158
    .line 1159
    invoke-direct {v0, v3, v2}, Lcq/f1;-><init>(ILjava/lang/String;)V

    .line 1160
    .line 1161
    .line 1162
    return-object v0

    .line 1163
    :pswitch_29
    move-object v0, v1

    .line 1164
    invoke-static {v0}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 1165
    .line 1166
    .line 1167
    move-result v1

    .line 1168
    const-wide/16 v2, 0x0

    .line 1169
    .line 1170
    const/4 v4, 0x0

    .line 1171
    move-object v5, v4

    .line 1172
    :goto_13
    invoke-virtual {v0}, Landroid/os/Parcel;->dataPosition()I

    .line 1173
    .line 1174
    .line 1175
    move-result v6

    .line 1176
    if-ge v6, v1, :cond_30

    .line 1177
    .line 1178
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 1179
    .line 1180
    .line 1181
    move-result v6

    .line 1182
    int-to-char v7, v6

    .line 1183
    const/4 v8, 0x2

    .line 1184
    if-eq v7, v8, :cond_2f

    .line 1185
    .line 1186
    const/4 v8, 0x3

    .line 1187
    if-eq v7, v8, :cond_2e

    .line 1188
    .line 1189
    const/4 v8, 0x4

    .line 1190
    if-eq v7, v8, :cond_2d

    .line 1191
    .line 1192
    invoke-static {v0, v6}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 1193
    .line 1194
    .line 1195
    goto :goto_13

    .line 1196
    :cond_2d
    invoke-static {v0, v6}, Ljp/xb;->s(Landroid/os/Parcel;I)J

    .line 1197
    .line 1198
    .line 1199
    move-result-wide v2

    .line 1200
    goto :goto_13

    .line 1201
    :cond_2e
    invoke-static {v0, v6}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 1202
    .line 1203
    .line 1204
    move-result-object v5

    .line 1205
    goto :goto_13

    .line 1206
    :cond_2f
    invoke-static {v0, v6}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 1207
    .line 1208
    .line 1209
    move-result-object v4

    .line 1210
    goto :goto_13

    .line 1211
    :cond_30
    invoke-static {v0, v1}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 1212
    .line 1213
    .line 1214
    new-instance v0, Lcq/e1;

    .line 1215
    .line 1216
    invoke-direct {v0, v2, v3, v4, v5}, Lcq/e1;-><init>(JLjava/lang/String;Ljava/lang/String;)V

    .line 1217
    .line 1218
    .line 1219
    return-object v0

    .line 1220
    :pswitch_2a
    move-object v0, v1

    .line 1221
    invoke-static {v0}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 1222
    .line 1223
    .line 1224
    move-result v1

    .line 1225
    const/4 v2, 0x0

    .line 1226
    const/4 v3, 0x0

    .line 1227
    :goto_14
    invoke-virtual {v0}, Landroid/os/Parcel;->dataPosition()I

    .line 1228
    .line 1229
    .line 1230
    move-result v4

    .line 1231
    if-ge v4, v1, :cond_33

    .line 1232
    .line 1233
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 1234
    .line 1235
    .line 1236
    move-result v4

    .line 1237
    int-to-char v5, v4

    .line 1238
    const/4 v6, 0x2

    .line 1239
    if-eq v5, v6, :cond_32

    .line 1240
    .line 1241
    const/4 v6, 0x3

    .line 1242
    if-eq v5, v6, :cond_31

    .line 1243
    .line 1244
    invoke-static {v0, v4}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 1245
    .line 1246
    .line 1247
    goto :goto_14

    .line 1248
    :cond_31
    sget-object v2, Lcq/e;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 1249
    .line 1250
    invoke-static {v0, v4, v2}, Ljp/xb;->e(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 1251
    .line 1252
    .line 1253
    move-result-object v2

    .line 1254
    check-cast v2, Lcq/e;

    .line 1255
    .line 1256
    goto :goto_14

    .line 1257
    :cond_32
    invoke-static {v0, v4}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 1258
    .line 1259
    .line 1260
    move-result v3

    .line 1261
    goto :goto_14

    .line 1262
    :cond_33
    invoke-static {v0, v1}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 1263
    .line 1264
    .line 1265
    new-instance v0, Lcq/d1;

    .line 1266
    .line 1267
    invoke-direct {v0, v3, v2}, Lcq/d1;-><init>(ILcq/e;)V

    .line 1268
    .line 1269
    .line 1270
    return-object v0

    .line 1271
    :pswitch_2b
    move-object v0, v1

    .line 1272
    invoke-static {v0}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 1273
    .line 1274
    .line 1275
    move-result v1

    .line 1276
    const/4 v2, 0x0

    .line 1277
    const/4 v3, 0x0

    .line 1278
    move-object v4, v3

    .line 1279
    move-object v5, v4

    .line 1280
    move v3, v2

    .line 1281
    :goto_15
    invoke-virtual {v0}, Landroid/os/Parcel;->dataPosition()I

    .line 1282
    .line 1283
    .line 1284
    move-result v6

    .line 1285
    if-ge v6, v1, :cond_38

    .line 1286
    .line 1287
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 1288
    .line 1289
    .line 1290
    move-result v6

    .line 1291
    int-to-char v7, v6

    .line 1292
    const/4 v8, 0x2

    .line 1293
    if-eq v7, v8, :cond_37

    .line 1294
    .line 1295
    const/4 v8, 0x3

    .line 1296
    if-eq v7, v8, :cond_36

    .line 1297
    .line 1298
    const/4 v8, 0x4

    .line 1299
    if-eq v7, v8, :cond_35

    .line 1300
    .line 1301
    const/4 v8, 0x5

    .line 1302
    if-eq v7, v8, :cond_34

    .line 1303
    .line 1304
    invoke-static {v0, v6}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 1305
    .line 1306
    .line 1307
    goto :goto_15

    .line 1308
    :cond_34
    invoke-static {v0, v6}, Ljp/xb;->l(Landroid/os/Parcel;I)Z

    .line 1309
    .line 1310
    .line 1311
    move-result v3

    .line 1312
    goto :goto_15

    .line 1313
    :cond_35
    invoke-static {v0, v6}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 1314
    .line 1315
    .line 1316
    move-result v2

    .line 1317
    goto :goto_15

    .line 1318
    :cond_36
    invoke-static {v0, v6}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 1319
    .line 1320
    .line 1321
    move-result-object v5

    .line 1322
    goto :goto_15

    .line 1323
    :cond_37
    invoke-static {v0, v6}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 1324
    .line 1325
    .line 1326
    move-result-object v4

    .line 1327
    goto :goto_15

    .line 1328
    :cond_38
    invoke-static {v0, v1}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 1329
    .line 1330
    .line 1331
    new-instance v0, Lcq/c1;

    .line 1332
    .line 1333
    invoke-direct {v0, v4, v2, v5, v3}, Lcq/c1;-><init>(Ljava/lang/String;ILjava/lang/String;Z)V

    .line 1334
    .line 1335
    .line 1336
    return-object v0

    .line 1337
    :pswitch_2c
    move-object v0, v1

    .line 1338
    invoke-static {v0}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 1339
    .line 1340
    .line 1341
    move-result v1

    .line 1342
    const/4 v2, 0x0

    .line 1343
    move-object v3, v2

    .line 1344
    :goto_16
    invoke-virtual {v0}, Landroid/os/Parcel;->dataPosition()I

    .line 1345
    .line 1346
    .line 1347
    move-result v4

    .line 1348
    if-ge v4, v1, :cond_3b

    .line 1349
    .line 1350
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 1351
    .line 1352
    .line 1353
    move-result v4

    .line 1354
    int-to-char v5, v4

    .line 1355
    const/4 v6, 0x1

    .line 1356
    if-eq v5, v6, :cond_3a

    .line 1357
    .line 1358
    const/4 v6, 0x2

    .line 1359
    if-eq v5, v6, :cond_39

    .line 1360
    .line 1361
    invoke-static {v0, v4}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 1362
    .line 1363
    .line 1364
    goto :goto_16

    .line 1365
    :cond_39
    sget-object v3, Lcom/google/android/gms/common/data/DataHolder;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 1366
    .line 1367
    invoke-static {v0, v4, v3}, Ljp/xb;->e(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 1368
    .line 1369
    .line 1370
    move-result-object v3

    .line 1371
    check-cast v3, Lcom/google/android/gms/common/data/DataHolder;

    .line 1372
    .line 1373
    goto :goto_16

    .line 1374
    :cond_3a
    invoke-static {v0, v4}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 1375
    .line 1376
    .line 1377
    move-result-object v2

    .line 1378
    goto :goto_16

    .line 1379
    :cond_3b
    invoke-static {v0, v1}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 1380
    .line 1381
    .line 1382
    new-instance v0, Lcq/b1;

    .line 1383
    .line 1384
    invoke-direct {v0, v2, v3}, Lcq/b1;-><init>(Ljava/lang/String;Lcom/google/android/gms/common/data/DataHolder;)V

    .line 1385
    .line 1386
    .line 1387
    return-object v0

    .line 1388
    :pswitch_2d
    move-object v0, v1

    .line 1389
    invoke-static {v0}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 1390
    .line 1391
    .line 1392
    move-result v1

    .line 1393
    const/4 v2, 0x0

    .line 1394
    const/4 v3, 0x0

    .line 1395
    move-object v4, v2

    .line 1396
    move v5, v3

    .line 1397
    move-object v3, v4

    .line 1398
    :goto_17
    invoke-virtual {v0}, Landroid/os/Parcel;->dataPosition()I

    .line 1399
    .line 1400
    .line 1401
    move-result v6

    .line 1402
    if-ge v6, v1, :cond_40

    .line 1403
    .line 1404
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 1405
    .line 1406
    .line 1407
    move-result v6

    .line 1408
    int-to-char v7, v6

    .line 1409
    const/4 v8, 0x2

    .line 1410
    if-eq v7, v8, :cond_3f

    .line 1411
    .line 1412
    const/4 v8, 0x3

    .line 1413
    if-eq v7, v8, :cond_3e

    .line 1414
    .line 1415
    const/4 v8, 0x4

    .line 1416
    if-eq v7, v8, :cond_3d

    .line 1417
    .line 1418
    const/4 v8, 0x5

    .line 1419
    if-eq v7, v8, :cond_3c

    .line 1420
    .line 1421
    invoke-static {v0, v6}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 1422
    .line 1423
    .line 1424
    goto :goto_17

    .line 1425
    :cond_3c
    invoke-static {v0, v6}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 1426
    .line 1427
    .line 1428
    move-result-object v4

    .line 1429
    goto :goto_17

    .line 1430
    :cond_3d
    invoke-static {v0, v6}, Ljp/xb;->b(Landroid/os/Parcel;I)[B

    .line 1431
    .line 1432
    .line 1433
    move-result-object v3

    .line 1434
    goto :goto_17

    .line 1435
    :cond_3e
    invoke-static {v0, v6}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 1436
    .line 1437
    .line 1438
    move-result-object v2

    .line 1439
    goto :goto_17

    .line 1440
    :cond_3f
    invoke-static {v0, v6}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 1441
    .line 1442
    .line 1443
    move-result v5

    .line 1444
    goto :goto_17

    .line 1445
    :cond_40
    invoke-static {v0, v1}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 1446
    .line 1447
    .line 1448
    new-instance v0, Lcq/z0;

    .line 1449
    .line 1450
    invoke-direct {v0, v5, v2, v4, v3}, Lcq/z0;-><init>(ILjava/lang/String;Ljava/lang/String;[B)V

    .line 1451
    .line 1452
    .line 1453
    return-object v0

    .line 1454
    :pswitch_2e
    move-object v0, v1

    .line 1455
    invoke-static {v0}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 1456
    .line 1457
    .line 1458
    move-result v1

    .line 1459
    const/4 v2, 0x0

    .line 1460
    move-object v3, v2

    .line 1461
    move-object v4, v3

    .line 1462
    move-object v5, v4

    .line 1463
    :goto_18
    invoke-virtual {v0}, Landroid/os/Parcel;->dataPosition()I

    .line 1464
    .line 1465
    .line 1466
    move-result v6

    .line 1467
    if-ge v6, v1, :cond_45

    .line 1468
    .line 1469
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 1470
    .line 1471
    .line 1472
    move-result v6

    .line 1473
    int-to-char v7, v6

    .line 1474
    const/4 v8, 0x2

    .line 1475
    if-eq v7, v8, :cond_44

    .line 1476
    .line 1477
    const/4 v8, 0x3

    .line 1478
    if-eq v7, v8, :cond_43

    .line 1479
    .line 1480
    const/4 v8, 0x4

    .line 1481
    if-eq v7, v8, :cond_42

    .line 1482
    .line 1483
    const/4 v8, 0x5

    .line 1484
    if-eq v7, v8, :cond_41

    .line 1485
    .line 1486
    invoke-static {v0, v6}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 1487
    .line 1488
    .line 1489
    goto :goto_18

    .line 1490
    :cond_41
    invoke-static {v0, v6}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 1491
    .line 1492
    .line 1493
    move-result-object v5

    .line 1494
    goto :goto_18

    .line 1495
    :cond_42
    invoke-static {v0, v6}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 1496
    .line 1497
    .line 1498
    move-result-object v4

    .line 1499
    goto :goto_18

    .line 1500
    :cond_43
    sget-object v3, Landroid/content/IntentFilter;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 1501
    .line 1502
    invoke-static {v0, v6, v3}, Ljp/xb;->i(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)[Ljava/lang/Object;

    .line 1503
    .line 1504
    .line 1505
    move-result-object v3

    .line 1506
    check-cast v3, [Landroid/content/IntentFilter;

    .line 1507
    .line 1508
    goto :goto_18

    .line 1509
    :cond_44
    invoke-static {v0, v6}, Ljp/xb;->q(Landroid/os/Parcel;I)Landroid/os/IBinder;

    .line 1510
    .line 1511
    .line 1512
    move-result-object v2

    .line 1513
    goto :goto_18

    .line 1514
    :cond_45
    invoke-static {v0, v1}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 1515
    .line 1516
    .line 1517
    new-instance v0, Lcq/n0;

    .line 1518
    .line 1519
    invoke-direct {v0, v2, v3, v4, v5}, Lcq/n0;-><init>(Landroid/os/IBinder;[Landroid/content/IntentFilter;Ljava/lang/String;Ljava/lang/String;)V

    .line 1520
    .line 1521
    .line 1522
    return-object v0

    .line 1523
    :pswitch_2f
    move-object v0, v1

    .line 1524
    invoke-static {v0}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 1525
    .line 1526
    .line 1527
    move-result v1

    .line 1528
    const/4 v2, 0x0

    .line 1529
    const/4 v3, 0x0

    .line 1530
    move-object v4, v3

    .line 1531
    move v3, v2

    .line 1532
    :goto_19
    invoke-virtual {v0}, Landroid/os/Parcel;->dataPosition()I

    .line 1533
    .line 1534
    .line 1535
    move-result v5

    .line 1536
    if-ge v5, v1, :cond_49

    .line 1537
    .line 1538
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 1539
    .line 1540
    .line 1541
    move-result v5

    .line 1542
    int-to-char v6, v5

    .line 1543
    const/4 v7, 0x1

    .line 1544
    if-eq v6, v7, :cond_48

    .line 1545
    .line 1546
    const/4 v7, 0x2

    .line 1547
    if-eq v6, v7, :cond_47

    .line 1548
    .line 1549
    const/4 v7, 0x3

    .line 1550
    if-eq v6, v7, :cond_46

    .line 1551
    .line 1552
    invoke-static {v0, v5}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 1553
    .line 1554
    .line 1555
    goto :goto_19

    .line 1556
    :cond_46
    invoke-static {v0, v5}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 1557
    .line 1558
    .line 1559
    move-result v3

    .line 1560
    goto :goto_19

    .line 1561
    :cond_47
    invoke-static {v0, v5}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 1562
    .line 1563
    .line 1564
    move-result v2

    .line 1565
    goto :goto_19

    .line 1566
    :cond_48
    invoke-static {v0, v5}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 1567
    .line 1568
    .line 1569
    move-result-object v4

    .line 1570
    goto :goto_19

    .line 1571
    :cond_49
    invoke-static {v0, v1}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 1572
    .line 1573
    .line 1574
    new-instance v0, Lcq/w1;

    .line 1575
    .line 1576
    invoke-direct {v0, v4, v2, v3}, Lcq/w1;-><init>(Ljava/lang/String;II)V

    .line 1577
    .line 1578
    .line 1579
    return-object v0

    .line 1580
    nop

    .line 1581
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2f
        :pswitch_2e
        :pswitch_2d
        :pswitch_2c
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
        :pswitch_13
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

    .line 1582
    .line 1583
    .line 1584
    .line 1585
    .line 1586
    .line 1587
    .line 1588
    .line 1589
    .line 1590
    .line 1591
    .line 1592
    .line 1593
    .line 1594
    .line 1595
    .line 1596
    .line 1597
    .line 1598
    .line 1599
    .line 1600
    .line 1601
    .line 1602
    .line 1603
    .line 1604
    .line 1605
    .line 1606
    .line 1607
    .line 1608
    .line 1609
    .line 1610
    .line 1611
    .line 1612
    .line 1613
    .line 1614
    .line 1615
    .line 1616
    .line 1617
    .line 1618
    .line 1619
    .line 1620
    .line 1621
    .line 1622
    .line 1623
    .line 1624
    .line 1625
    .line 1626
    .line 1627
    .line 1628
    .line 1629
    .line 1630
    .line 1631
    .line 1632
    .line 1633
    .line 1634
    .line 1635
    .line 1636
    .line 1637
    .line 1638
    .line 1639
    .line 1640
    .line 1641
    .line 1642
    .line 1643
    :pswitch_data_1
    .packed-switch 0x1
        :pswitch_12
        :pswitch_11
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
    .end packed-switch

    .line 1644
    .line 1645
    .line 1646
    .line 1647
    .line 1648
    .line 1649
    .line 1650
    .line 1651
    .line 1652
    .line 1653
    .line 1654
    .line 1655
    .line 1656
    .line 1657
    .line 1658
    .line 1659
    .line 1660
    .line 1661
    :pswitch_data_2
    .packed-switch 0x2
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
    .end packed-switch
.end method

.method public final newArray(I)[Ljava/lang/Object;
    .locals 0

    .line 1
    iget p0, p0, Lcq/x0;->a:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-array p0, p1, [Lgl/b;

    .line 7
    .line 8
    return-object p0

    .line 9
    :pswitch_0
    new-array p0, p1, [Lgl/a;

    .line 10
    .line 11
    return-object p0

    .line 12
    :pswitch_1
    new-array p0, p1, [Le/j;

    .line 13
    .line 14
    return-object p0

    .line 15
    :pswitch_2
    new-array p0, p1, [Le/a;

    .line 16
    .line 17
    return-object p0

    .line 18
    :pswitch_3
    new-array p0, p1, [Ldd/f;

    .line 19
    .line 20
    return-object p0

    .line 21
    :pswitch_4
    new-array p0, p1, [Ldc/w;

    .line 22
    .line 23
    return-object p0

    .line 24
    :pswitch_5
    new-array p0, p1, [Ldc/q;

    .line 25
    .line 26
    return-object p0

    .line 27
    :pswitch_6
    new-array p0, p1, [Ldc/n;

    .line 28
    .line 29
    return-object p0

    .line 30
    :pswitch_7
    new-array p0, p1, [Landroidx/versionedparcelable/ParcelImpl;

    .line 31
    .line 32
    return-object p0

    .line 33
    :pswitch_8
    new-array p0, p1, [Lcq/c2;

    .line 34
    .line 35
    return-object p0

    .line 36
    :pswitch_9
    new-array p0, p1, [Lcq/a2;

    .line 37
    .line 38
    return-object p0

    .line 39
    :pswitch_a
    new-array p0, p1, [Lcq/z1;

    .line 40
    .line 41
    return-object p0

    .line 42
    :pswitch_b
    new-array p0, p1, [Lcq/y1;

    .line 43
    .line 44
    return-object p0

    .line 45
    :pswitch_c
    new-array p0, p1, [Lcq/x1;

    .line 46
    .line 47
    return-object p0

    .line 48
    :pswitch_d
    new-array p0, p1, [Lcq/q1;

    .line 49
    .line 50
    return-object p0

    .line 51
    :pswitch_e
    new-array p0, p1, [Lcq/l1;

    .line 52
    .line 53
    return-object p0

    .line 54
    :pswitch_f
    new-array p0, p1, [Lcq/a1;

    .line 55
    .line 56
    return-object p0

    .line 57
    :pswitch_10
    new-array p0, p1, [Lcq/k1;

    .line 58
    .line 59
    return-object p0

    .line 60
    :pswitch_11
    new-array p0, p1, [Lcq/j1;

    .line 61
    .line 62
    return-object p0

    .line 63
    :pswitch_12
    new-array p0, p1, [Lcq/i1;

    .line 64
    .line 65
    return-object p0

    .line 66
    :pswitch_13
    new-array p0, p1, [Lcq/h1;

    .line 67
    .line 68
    return-object p0

    .line 69
    :pswitch_14
    new-array p0, p1, [Lcq/g1;

    .line 70
    .line 71
    return-object p0

    .line 72
    :pswitch_15
    new-array p0, p1, [Lcq/f1;

    .line 73
    .line 74
    return-object p0

    .line 75
    :pswitch_16
    new-array p0, p1, [Lcq/e1;

    .line 76
    .line 77
    return-object p0

    .line 78
    :pswitch_17
    new-array p0, p1, [Lcq/d1;

    .line 79
    .line 80
    return-object p0

    .line 81
    :pswitch_18
    new-array p0, p1, [Lcq/c1;

    .line 82
    .line 83
    return-object p0

    .line 84
    :pswitch_19
    new-array p0, p1, [Lcq/b1;

    .line 85
    .line 86
    return-object p0

    .line 87
    :pswitch_1a
    new-array p0, p1, [Lcq/z0;

    .line 88
    .line 89
    return-object p0

    .line 90
    :pswitch_1b
    new-array p0, p1, [Lcq/n0;

    .line 91
    .line 92
    return-object p0

    .line 93
    :pswitch_1c
    new-array p0, p1, [Lcq/w1;

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
