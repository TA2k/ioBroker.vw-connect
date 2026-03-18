.class public abstract Llp/zd;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static a(Lv/b;)Ld01/x;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    sget-object v1, Lh0/r1;->c:Lh0/r1;

    .line 4
    .line 5
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 6
    .line 7
    .line 8
    :try_start_0
    iget-object v1, v1, Lh0/r1;->a:Lf8/d;

    .line 9
    .line 10
    iget-object v1, v1, Lf8/d;->g:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast v1, Ljava/util/concurrent/atomic/AtomicReference;

    .line 13
    .line 14
    invoke-virtual {v1}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object v1

    .line 18
    instance-of v2, v1, Lh0/j;

    .line 19
    .line 20
    if-eqz v2, :cond_0

    .line 21
    .line 22
    new-instance v1, Lk0/j;

    .line 23
    .line 24
    const/4 v2, 0x1

    .line 25
    const/4 v3, 0x0

    .line 26
    invoke-direct {v1, v3, v2}, Lk0/j;-><init>(Ljava/lang/Object;I)V

    .line 27
    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_0
    invoke-static {v1}, Lk0/h;->c(Ljava/lang/Object;)Lk0/j;

    .line 31
    .line 32
    .line 33
    move-result-object v1

    .line 34
    :goto_0
    invoke-interface {v1}, Ljava/util/concurrent/Future;->get()Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    move-result-object v1

    .line 38
    check-cast v1, Lh0/q1;
    :try_end_0
    .catch Ljava/util/concurrent/ExecutionException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/lang/InterruptedException; {:try_start_0 .. :try_end_0} :catch_0

    .line 39
    .line 40
    new-instance v2, Ljava/util/ArrayList;

    .line 41
    .line 42
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 43
    .line 44
    .line 45
    sget-object v3, Landroid/hardware/camera2/CameraCharacteristics;->INFO_SUPPORTED_HARDWARE_LEVEL:Landroid/hardware/camera2/CameraCharacteristics$Key;

    .line 46
    .line 47
    invoke-virtual {v0, v3}, Lv/b;->a(Landroid/hardware/camera2/CameraCharacteristics$Key;)Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object v4

    .line 51
    check-cast v4, Ljava/lang/Integer;

    .line 52
    .line 53
    const/4 v5, 0x2

    .line 54
    const/4 v6, 0x1

    .line 55
    const/4 v7, 0x0

    .line 56
    if-eqz v4, :cond_1

    .line 57
    .line 58
    invoke-virtual {v4}, Ljava/lang/Integer;->intValue()I

    .line 59
    .line 60
    .line 61
    move-result v4

    .line 62
    if-ne v4, v5, :cond_1

    .line 63
    .line 64
    move v4, v6

    .line 65
    goto :goto_1

    .line 66
    :cond_1
    move v4, v7

    .line 67
    :goto_1
    const-class v8, Landroidx/camera/camera2/internal/compat/quirk/AeFpsRangeLegacyQuirk;

    .line 68
    .line 69
    invoke-virtual {v1, v8, v4}, Lh0/q1;->a(Ljava/lang/Class;Z)Z

    .line 70
    .line 71
    .line 72
    move-result v4

    .line 73
    if-eqz v4, :cond_2

    .line 74
    .line 75
    new-instance v4, Landroidx/camera/camera2/internal/compat/quirk/AeFpsRangeLegacyQuirk;

    .line 76
    .line 77
    invoke-direct {v4, v0}, Landroidx/camera/camera2/internal/compat/quirk/AeFpsRangeLegacyQuirk;-><init>(Lv/b;)V

    .line 78
    .line 79
    .line 80
    invoke-virtual {v2, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 81
    .line 82
    .line 83
    :cond_2
    invoke-virtual {v0, v3}, Lv/b;->a(Landroid/hardware/camera2/CameraCharacteristics$Key;)Ljava/lang/Object;

    .line 84
    .line 85
    .line 86
    move-result-object v4

    .line 87
    check-cast v4, Ljava/lang/Integer;

    .line 88
    .line 89
    const-class v4, Landroidx/camera/camera2/internal/compat/quirk/AspectRatioLegacyApi21Quirk;

    .line 90
    .line 91
    invoke-virtual {v1, v4, v7}, Lh0/q1;->a(Ljava/lang/Class;Z)Z

    .line 92
    .line 93
    .line 94
    move-result v4

    .line 95
    if-eqz v4, :cond_3

    .line 96
    .line 97
    new-instance v4, Landroidx/camera/camera2/internal/compat/quirk/AspectRatioLegacyApi21Quirk;

    .line 98
    .line 99
    invoke-direct {v4}, Landroidx/camera/camera2/internal/compat/quirk/AspectRatioLegacyApi21Quirk;-><init>()V

    .line 100
    .line 101
    .line 102
    invoke-virtual {v2, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 103
    .line 104
    .line 105
    :cond_3
    sget-object v4, Landroidx/camera/camera2/internal/compat/quirk/JpegHalCorruptImageQuirk;->a:Ljava/util/HashSet;

    .line 106
    .line 107
    sget-object v8, Landroid/os/Build;->DEVICE:Ljava/lang/String;

    .line 108
    .line 109
    sget-object v9, Ljava/util/Locale;->US:Ljava/util/Locale;

    .line 110
    .line 111
    invoke-virtual {v8, v9}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 112
    .line 113
    .line 114
    move-result-object v8

    .line 115
    invoke-virtual {v4, v8}, Ljava/util/HashSet;->contains(Ljava/lang/Object;)Z

    .line 116
    .line 117
    .line 118
    move-result v4

    .line 119
    const-class v8, Landroidx/camera/camera2/internal/compat/quirk/JpegHalCorruptImageQuirk;

    .line 120
    .line 121
    invoke-virtual {v1, v8, v4}, Lh0/q1;->a(Ljava/lang/Class;Z)Z

    .line 122
    .line 123
    .line 124
    move-result v4

    .line 125
    if-eqz v4, :cond_4

    .line 126
    .line 127
    new-instance v4, Landroidx/camera/camera2/internal/compat/quirk/JpegHalCorruptImageQuirk;

    .line 128
    .line 129
    invoke-direct {v4}, Landroidx/camera/camera2/internal/compat/quirk/JpegHalCorruptImageQuirk;-><init>()V

    .line 130
    .line 131
    .line 132
    invoke-virtual {v2, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 133
    .line 134
    .line 135
    :cond_4
    sget-object v4, Landroidx/camera/camera2/internal/compat/quirk/JpegCaptureDownsizingQuirk;->a:Ljava/util/HashSet;

    .line 136
    .line 137
    sget-object v8, Landroid/os/Build;->MODEL:Ljava/lang/String;

    .line 138
    .line 139
    invoke-virtual {v8, v9}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 140
    .line 141
    .line 142
    move-result-object v10

    .line 143
    invoke-virtual {v4, v10}, Ljava/util/HashSet;->contains(Ljava/lang/Object;)Z

    .line 144
    .line 145
    .line 146
    move-result v4

    .line 147
    if-eqz v4, :cond_5

    .line 148
    .line 149
    sget-object v4, Landroid/hardware/camera2/CameraCharacteristics;->LENS_FACING:Landroid/hardware/camera2/CameraCharacteristics$Key;

    .line 150
    .line 151
    invoke-virtual {v0, v4}, Lv/b;->a(Landroid/hardware/camera2/CameraCharacteristics$Key;)Ljava/lang/Object;

    .line 152
    .line 153
    .line 154
    move-result-object v4

    .line 155
    check-cast v4, Ljava/lang/Integer;

    .line 156
    .line 157
    invoke-virtual {v4}, Ljava/lang/Integer;->intValue()I

    .line 158
    .line 159
    .line 160
    move-result v4

    .line 161
    if-nez v4, :cond_5

    .line 162
    .line 163
    move v4, v6

    .line 164
    goto :goto_2

    .line 165
    :cond_5
    move v4, v7

    .line 166
    :goto_2
    const-class v10, Landroidx/camera/camera2/internal/compat/quirk/JpegCaptureDownsizingQuirk;

    .line 167
    .line 168
    invoke-virtual {v1, v10, v4}, Lh0/q1;->a(Ljava/lang/Class;Z)Z

    .line 169
    .line 170
    .line 171
    move-result v4

    .line 172
    if-eqz v4, :cond_6

    .line 173
    .line 174
    new-instance v4, Landroidx/camera/camera2/internal/compat/quirk/JpegCaptureDownsizingQuirk;

    .line 175
    .line 176
    invoke-direct {v4}, Landroidx/camera/camera2/internal/compat/quirk/JpegCaptureDownsizingQuirk;-><init>()V

    .line 177
    .line 178
    .line 179
    invoke-virtual {v2, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 180
    .line 181
    .line 182
    :cond_6
    invoke-virtual {v0, v3}, Lv/b;->a(Landroid/hardware/camera2/CameraCharacteristics$Key;)Ljava/lang/Object;

    .line 183
    .line 184
    .line 185
    move-result-object v4

    .line 186
    check-cast v4, Ljava/lang/Integer;

    .line 187
    .line 188
    if-eqz v4, :cond_7

    .line 189
    .line 190
    invoke-virtual {v4}, Ljava/lang/Integer;->intValue()I

    .line 191
    .line 192
    .line 193
    move-result v4

    .line 194
    if-ne v4, v5, :cond_7

    .line 195
    .line 196
    move v4, v6

    .line 197
    goto :goto_3

    .line 198
    :cond_7
    move v4, v7

    .line 199
    :goto_3
    const-class v10, Landroidx/camera/camera2/internal/compat/quirk/CamcorderProfileResolutionQuirk;

    .line 200
    .line 201
    invoke-virtual {v1, v10, v4}, Lh0/q1;->a(Ljava/lang/Class;Z)Z

    .line 202
    .line 203
    .line 204
    move-result v4

    .line 205
    if-eqz v4, :cond_8

    .line 206
    .line 207
    new-instance v4, Landroidx/camera/camera2/internal/compat/quirk/CamcorderProfileResolutionQuirk;

    .line 208
    .line 209
    invoke-direct {v4}, Ljava/lang/Object;-><init>()V

    .line 210
    .line 211
    .line 212
    invoke-virtual {v0}, Lv/b;->c()Lrn/i;

    .line 213
    .line 214
    .line 215
    invoke-virtual {v2, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 216
    .line 217
    .line 218
    :cond_8
    sget-object v4, Landroid/os/Build;->HARDWARE:Ljava/lang/String;

    .line 219
    .line 220
    const-string v10, "samsungexynos7420"

    .line 221
    .line 222
    invoke-virtual {v10, v4}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 223
    .line 224
    .line 225
    move-result v10

    .line 226
    if-nez v10, :cond_9

    .line 227
    .line 228
    const-string v10, "universal7420"

    .line 229
    .line 230
    invoke-virtual {v10, v4}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 231
    .line 232
    .line 233
    move-result v4

    .line 234
    if-eqz v4, :cond_a

    .line 235
    .line 236
    :cond_9
    sget-object v4, Landroid/hardware/camera2/CameraCharacteristics;->LENS_FACING:Landroid/hardware/camera2/CameraCharacteristics$Key;

    .line 237
    .line 238
    invoke-virtual {v0, v4}, Lv/b;->a(Landroid/hardware/camera2/CameraCharacteristics$Key;)Ljava/lang/Object;

    .line 239
    .line 240
    .line 241
    move-result-object v4

    .line 242
    check-cast v4, Ljava/lang/Integer;

    .line 243
    .line 244
    invoke-virtual {v4}, Ljava/lang/Integer;->intValue()I

    .line 245
    .line 246
    .line 247
    move-result v4

    .line 248
    if-ne v4, v6, :cond_a

    .line 249
    .line 250
    move v4, v6

    .line 251
    goto :goto_4

    .line 252
    :cond_a
    move v4, v7

    .line 253
    :goto_4
    const-class v10, Landroidx/camera/camera2/internal/compat/quirk/CaptureNoResponseQuirk;

    .line 254
    .line 255
    invoke-virtual {v1, v10, v4}, Lh0/q1;->a(Ljava/lang/Class;Z)Z

    .line 256
    .line 257
    .line 258
    move-result v4

    .line 259
    if-eqz v4, :cond_b

    .line 260
    .line 261
    new-instance v4, Landroidx/camera/camera2/internal/compat/quirk/CaptureNoResponseQuirk;

    .line 262
    .line 263
    invoke-direct {v4}, Landroidx/camera/camera2/internal/compat/quirk/CaptureNoResponseQuirk;-><init>()V

    .line 264
    .line 265
    .line 266
    invoke-virtual {v2, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 267
    .line 268
    .line 269
    :cond_b
    invoke-virtual {v0, v3}, Lv/b;->a(Landroid/hardware/camera2/CameraCharacteristics$Key;)Ljava/lang/Object;

    .line 270
    .line 271
    .line 272
    move-result-object v3

    .line 273
    check-cast v3, Ljava/lang/Integer;

    .line 274
    .line 275
    if-eqz v3, :cond_c

    .line 276
    .line 277
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 278
    .line 279
    .line 280
    move-result v3

    .line 281
    if-ne v3, v5, :cond_c

    .line 282
    .line 283
    move v3, v6

    .line 284
    goto :goto_5

    .line 285
    :cond_c
    move v3, v7

    .line 286
    :goto_5
    const-class v4, Landroidx/camera/camera2/internal/compat/quirk/LegacyCameraOutputConfigNullPointerQuirk;

    .line 287
    .line 288
    invoke-virtual {v1, v4, v3}, Lh0/q1;->a(Ljava/lang/Class;Z)Z

    .line 289
    .line 290
    .line 291
    move-result v3

    .line 292
    if-eqz v3, :cond_d

    .line 293
    .line 294
    new-instance v3, Landroidx/camera/camera2/internal/compat/quirk/LegacyCameraOutputConfigNullPointerQuirk;

    .line 295
    .line 296
    invoke-direct {v3}, Landroidx/camera/camera2/internal/compat/quirk/LegacyCameraOutputConfigNullPointerQuirk;-><init>()V

    .line 297
    .line 298
    .line 299
    invoke-virtual {v2, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 300
    .line 301
    .line 302
    :cond_d
    const-class v3, Landroidx/camera/camera2/internal/compat/quirk/LegacyCameraSurfaceCleanupQuirk;

    .line 303
    .line 304
    invoke-virtual {v1, v3, v7}, Lh0/q1;->a(Ljava/lang/Class;Z)Z

    .line 305
    .line 306
    .line 307
    move-result v3

    .line 308
    if-eqz v3, :cond_e

    .line 309
    .line 310
    new-instance v3, Landroidx/camera/camera2/internal/compat/quirk/LegacyCameraSurfaceCleanupQuirk;

    .line 311
    .line 312
    invoke-direct {v3}, Landroidx/camera/camera2/internal/compat/quirk/LegacyCameraSurfaceCleanupQuirk;-><init>()V

    .line 313
    .line 314
    .line 315
    invoke-virtual {v2, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 316
    .line 317
    .line 318
    :cond_e
    sget-object v3, Landroidx/camera/camera2/internal/compat/quirk/ImageCaptureWashedOutImageQuirk;->a:Ljava/util/List;

    .line 319
    .line 320
    invoke-virtual {v8, v9}, Ljava/lang/String;->toUpperCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 321
    .line 322
    .line 323
    move-result-object v4

    .line 324
    invoke-interface {v3, v4}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 325
    .line 326
    .line 327
    move-result v3

    .line 328
    if-eqz v3, :cond_f

    .line 329
    .line 330
    sget-object v3, Landroid/hardware/camera2/CameraCharacteristics;->LENS_FACING:Landroid/hardware/camera2/CameraCharacteristics$Key;

    .line 331
    .line 332
    invoke-virtual {v0, v3}, Lv/b;->a(Landroid/hardware/camera2/CameraCharacteristics$Key;)Ljava/lang/Object;

    .line 333
    .line 334
    .line 335
    move-result-object v3

    .line 336
    check-cast v3, Ljava/lang/Integer;

    .line 337
    .line 338
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 339
    .line 340
    .line 341
    move-result v3

    .line 342
    if-ne v3, v6, :cond_f

    .line 343
    .line 344
    move v3, v6

    .line 345
    goto :goto_6

    .line 346
    :cond_f
    move v3, v7

    .line 347
    :goto_6
    const-class v4, Landroidx/camera/camera2/internal/compat/quirk/ImageCaptureWashedOutImageQuirk;

    .line 348
    .line 349
    invoke-virtual {v1, v4, v3}, Lh0/q1;->a(Ljava/lang/Class;Z)Z

    .line 350
    .line 351
    .line 352
    move-result v3

    .line 353
    if-eqz v3, :cond_10

    .line 354
    .line 355
    new-instance v3, Landroidx/camera/camera2/internal/compat/quirk/ImageCaptureWashedOutImageQuirk;

    .line 356
    .line 357
    invoke-direct {v3}, Landroidx/camera/camera2/internal/compat/quirk/ImageCaptureWashedOutImageQuirk;-><init>()V

    .line 358
    .line 359
    .line 360
    invoke-virtual {v2, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 361
    .line 362
    .line 363
    :cond_10
    sget-object v3, Landroidx/camera/camera2/internal/compat/quirk/CameraNoResponseWhenEnablingFlashQuirk;->a:Ljava/util/List;

    .line 364
    .line 365
    invoke-virtual {v8, v9}, Ljava/lang/String;->toUpperCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 366
    .line 367
    .line 368
    move-result-object v4

    .line 369
    invoke-interface {v3, v4}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 370
    .line 371
    .line 372
    move-result v3

    .line 373
    if-eqz v3, :cond_11

    .line 374
    .line 375
    sget-object v3, Landroid/hardware/camera2/CameraCharacteristics;->LENS_FACING:Landroid/hardware/camera2/CameraCharacteristics$Key;

    .line 376
    .line 377
    invoke-virtual {v0, v3}, Lv/b;->a(Landroid/hardware/camera2/CameraCharacteristics$Key;)Ljava/lang/Object;

    .line 378
    .line 379
    .line 380
    move-result-object v3

    .line 381
    check-cast v3, Ljava/lang/Integer;

    .line 382
    .line 383
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 384
    .line 385
    .line 386
    move-result v3

    .line 387
    if-ne v3, v6, :cond_11

    .line 388
    .line 389
    move v3, v6

    .line 390
    goto :goto_7

    .line 391
    :cond_11
    move v3, v7

    .line 392
    :goto_7
    const-class v4, Landroidx/camera/camera2/internal/compat/quirk/CameraNoResponseWhenEnablingFlashQuirk;

    .line 393
    .line 394
    invoke-virtual {v1, v4, v3}, Lh0/q1;->a(Ljava/lang/Class;Z)Z

    .line 395
    .line 396
    .line 397
    move-result v3

    .line 398
    if-eqz v3, :cond_12

    .line 399
    .line 400
    new-instance v3, Landroidx/camera/camera2/internal/compat/quirk/CameraNoResponseWhenEnablingFlashQuirk;

    .line 401
    .line 402
    invoke-direct {v3}, Landroidx/camera/camera2/internal/compat/quirk/CameraNoResponseWhenEnablingFlashQuirk;-><init>()V

    .line 403
    .line 404
    .line 405
    invoke-virtual {v2, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 406
    .line 407
    .line 408
    :cond_12
    sget-object v3, Landroid/os/Build;->BRAND:Ljava/lang/String;

    .line 409
    .line 410
    const-string v4, "motorola"

    .line 411
    .line 412
    invoke-virtual {v4, v3}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 413
    .line 414
    .line 415
    move-result v9

    .line 416
    const-string v10, "samsung"

    .line 417
    .line 418
    if-eqz v9, :cond_13

    .line 419
    .line 420
    const-string v9, "MotoG3"

    .line 421
    .line 422
    invoke-virtual {v9, v8}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 423
    .line 424
    .line 425
    move-result v9

    .line 426
    if-eqz v9, :cond_13

    .line 427
    .line 428
    goto :goto_8

    .line 429
    :cond_13
    invoke-virtual {v10, v3}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 430
    .line 431
    .line 432
    move-result v9

    .line 433
    if-eqz v9, :cond_14

    .line 434
    .line 435
    const-string v9, "SM-G532F"

    .line 436
    .line 437
    invoke-virtual {v9, v8}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 438
    .line 439
    .line 440
    move-result v9

    .line 441
    if-eqz v9, :cond_14

    .line 442
    .line 443
    goto :goto_8

    .line 444
    :cond_14
    invoke-virtual {v10, v3}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 445
    .line 446
    .line 447
    move-result v9

    .line 448
    if-eqz v9, :cond_15

    .line 449
    .line 450
    const-string v9, "SM-J700F"

    .line 451
    .line 452
    invoke-virtual {v9, v8}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 453
    .line 454
    .line 455
    move-result v9

    .line 456
    if-eqz v9, :cond_15

    .line 457
    .line 458
    goto :goto_8

    .line 459
    :cond_15
    invoke-virtual {v10, v3}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 460
    .line 461
    .line 462
    move-result v9

    .line 463
    if-eqz v9, :cond_16

    .line 464
    .line 465
    const-string v9, "SM-A920F"

    .line 466
    .line 467
    invoke-virtual {v9, v8}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 468
    .line 469
    .line 470
    move-result v9

    .line 471
    if-eqz v9, :cond_16

    .line 472
    .line 473
    goto :goto_8

    .line 474
    :cond_16
    invoke-virtual {v10, v3}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 475
    .line 476
    .line 477
    move-result v9

    .line 478
    if-eqz v9, :cond_17

    .line 479
    .line 480
    const-string v9, "SM-J415F"

    .line 481
    .line 482
    invoke-virtual {v9, v8}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 483
    .line 484
    .line 485
    move-result v9

    .line 486
    if-eqz v9, :cond_17

    .line 487
    .line 488
    goto :goto_8

    .line 489
    :cond_17
    const-string v9, "xiaomi"

    .line 490
    .line 491
    invoke-virtual {v9, v3}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 492
    .line 493
    .line 494
    move-result v3

    .line 495
    if-eqz v3, :cond_18

    .line 496
    .line 497
    const-string v3, "Mi A1"

    .line 498
    .line 499
    invoke-virtual {v3, v8}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 500
    .line 501
    .line 502
    move-result v3

    .line 503
    if-eqz v3, :cond_18

    .line 504
    .line 505
    :goto_8
    move v3, v6

    .line 506
    goto :goto_9

    .line 507
    :cond_18
    move v3, v7

    .line 508
    :goto_9
    const-class v8, Landroidx/camera/camera2/internal/compat/quirk/YuvImageOnePixelShiftQuirk;

    .line 509
    .line 510
    invoke-virtual {v1, v8, v3}, Lh0/q1;->a(Ljava/lang/Class;Z)Z

    .line 511
    .line 512
    .line 513
    move-result v3

    .line 514
    if-eqz v3, :cond_19

    .line 515
    .line 516
    new-instance v3, Landroidx/camera/camera2/internal/compat/quirk/YuvImageOnePixelShiftQuirk;

    .line 517
    .line 518
    invoke-direct {v3}, Landroidx/camera/camera2/internal/compat/quirk/YuvImageOnePixelShiftQuirk;-><init>()V

    .line 519
    .line 520
    .line 521
    invoke-virtual {v2, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 522
    .line 523
    .line 524
    :cond_19
    sget-object v3, Landroidx/camera/camera2/internal/compat/quirk/FlashTooSlowQuirk;->a:Ljava/util/List;

    .line 525
    .line 526
    invoke-interface {v3}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 527
    .line 528
    .line 529
    move-result-object v3

    .line 530
    :cond_1a
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 531
    .line 532
    .line 533
    move-result v8

    .line 534
    if-eqz v8, :cond_1b

    .line 535
    .line 536
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 537
    .line 538
    .line 539
    move-result-object v8

    .line 540
    check-cast v8, Ljava/lang/String;

    .line 541
    .line 542
    sget-object v9, Landroid/os/Build;->MODEL:Ljava/lang/String;

    .line 543
    .line 544
    sget-object v11, Ljava/util/Locale;->US:Ljava/util/Locale;

    .line 545
    .line 546
    invoke-virtual {v9, v11}, Ljava/lang/String;->toUpperCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 547
    .line 548
    .line 549
    move-result-object v9

    .line 550
    invoke-virtual {v9, v8}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    .line 551
    .line 552
    .line 553
    move-result v8

    .line 554
    if-eqz v8, :cond_1a

    .line 555
    .line 556
    sget-object v3, Landroid/hardware/camera2/CameraCharacteristics;->LENS_FACING:Landroid/hardware/camera2/CameraCharacteristics$Key;

    .line 557
    .line 558
    invoke-virtual {v0, v3}, Lv/b;->a(Landroid/hardware/camera2/CameraCharacteristics$Key;)Ljava/lang/Object;

    .line 559
    .line 560
    .line 561
    move-result-object v3

    .line 562
    check-cast v3, Ljava/lang/Integer;

    .line 563
    .line 564
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 565
    .line 566
    .line 567
    move-result v3

    .line 568
    if-ne v3, v6, :cond_1b

    .line 569
    .line 570
    move v3, v6

    .line 571
    goto :goto_a

    .line 572
    :cond_1b
    move v3, v7

    .line 573
    :goto_a
    const-class v8, Landroidx/camera/camera2/internal/compat/quirk/FlashTooSlowQuirk;

    .line 574
    .line 575
    invoke-virtual {v1, v8, v3}, Lh0/q1;->a(Ljava/lang/Class;Z)Z

    .line 576
    .line 577
    .line 578
    move-result v3

    .line 579
    if-eqz v3, :cond_1c

    .line 580
    .line 581
    new-instance v3, Landroidx/camera/camera2/internal/compat/quirk/FlashTooSlowQuirk;

    .line 582
    .line 583
    invoke-direct {v3}, Landroidx/camera/camera2/internal/compat/quirk/FlashTooSlowQuirk;-><init>()V

    .line 584
    .line 585
    .line 586
    invoke-virtual {v2, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 587
    .line 588
    .line 589
    :cond_1c
    sget-object v3, Landroid/os/Build;->BRAND:Ljava/lang/String;

    .line 590
    .line 591
    const-string v8, "SAMSUNG"

    .line 592
    .line 593
    invoke-virtual {v3, v8}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 594
    .line 595
    .line 596
    move-result v3

    .line 597
    if-eqz v3, :cond_1d

    .line 598
    .line 599
    sget v3, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 600
    .line 601
    const/16 v8, 0x21

    .line 602
    .line 603
    if-ge v3, v8, :cond_1d

    .line 604
    .line 605
    sget-object v3, Landroid/hardware/camera2/CameraCharacteristics;->LENS_FACING:Landroid/hardware/camera2/CameraCharacteristics$Key;

    .line 606
    .line 607
    invoke-virtual {v0, v3}, Lv/b;->a(Landroid/hardware/camera2/CameraCharacteristics$Key;)Ljava/lang/Object;

    .line 608
    .line 609
    .line 610
    move-result-object v3

    .line 611
    check-cast v3, Ljava/lang/Integer;

    .line 612
    .line 613
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 614
    .line 615
    .line 616
    move-result v3

    .line 617
    if-nez v3, :cond_1d

    .line 618
    .line 619
    move v3, v6

    .line 620
    goto :goto_b

    .line 621
    :cond_1d
    move v3, v7

    .line 622
    :goto_b
    const-class v8, Landroidx/camera/camera2/internal/compat/quirk/AfRegionFlipHorizontallyQuirk;

    .line 623
    .line 624
    invoke-virtual {v1, v8, v3}, Lh0/q1;->a(Ljava/lang/Class;Z)Z

    .line 625
    .line 626
    .line 627
    move-result v3

    .line 628
    if-eqz v3, :cond_1e

    .line 629
    .line 630
    new-instance v3, Landroidx/camera/camera2/internal/compat/quirk/AfRegionFlipHorizontallyQuirk;

    .line 631
    .line 632
    invoke-direct {v3}, Landroidx/camera/camera2/internal/compat/quirk/AfRegionFlipHorizontallyQuirk;-><init>()V

    .line 633
    .line 634
    .line 635
    invoke-virtual {v2, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 636
    .line 637
    .line 638
    :cond_1e
    sget-object v3, Landroid/hardware/camera2/CameraCharacteristics;->INFO_SUPPORTED_HARDWARE_LEVEL:Landroid/hardware/camera2/CameraCharacteristics$Key;

    .line 639
    .line 640
    invoke-virtual {v0, v3}, Lv/b;->a(Landroid/hardware/camera2/CameraCharacteristics$Key;)Ljava/lang/Object;

    .line 641
    .line 642
    .line 643
    move-result-object v8

    .line 644
    check-cast v8, Ljava/lang/Integer;

    .line 645
    .line 646
    if-eqz v8, :cond_1f

    .line 647
    .line 648
    invoke-virtual {v8}, Ljava/lang/Integer;->intValue()I

    .line 649
    .line 650
    .line 651
    move-result v8

    .line 652
    if-ne v8, v5, :cond_1f

    .line 653
    .line 654
    move v8, v6

    .line 655
    goto :goto_c

    .line 656
    :cond_1f
    move v8, v7

    .line 657
    :goto_c
    const-class v9, Landroidx/camera/camera2/internal/compat/quirk/ConfigureSurfaceToSecondarySessionFailQuirk;

    .line 658
    .line 659
    invoke-virtual {v1, v9, v8}, Lh0/q1;->a(Ljava/lang/Class;Z)Z

    .line 660
    .line 661
    .line 662
    move-result v8

    .line 663
    if-eqz v8, :cond_20

    .line 664
    .line 665
    new-instance v8, Landroidx/camera/camera2/internal/compat/quirk/ConfigureSurfaceToSecondarySessionFailQuirk;

    .line 666
    .line 667
    invoke-direct {v8}, Landroidx/camera/camera2/internal/compat/quirk/ConfigureSurfaceToSecondarySessionFailQuirk;-><init>()V

    .line 668
    .line 669
    .line 670
    invoke-virtual {v2, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 671
    .line 672
    .line 673
    :cond_20
    invoke-virtual {v0, v3}, Lv/b;->a(Landroid/hardware/camera2/CameraCharacteristics$Key;)Ljava/lang/Object;

    .line 674
    .line 675
    .line 676
    move-result-object v8

    .line 677
    check-cast v8, Ljava/lang/Integer;

    .line 678
    .line 679
    if-eqz v8, :cond_21

    .line 680
    .line 681
    invoke-virtual {v8}, Ljava/lang/Integer;->intValue()I

    .line 682
    .line 683
    .line 684
    move-result v8

    .line 685
    if-ne v8, v5, :cond_21

    .line 686
    .line 687
    move v8, v6

    .line 688
    goto :goto_d

    .line 689
    :cond_21
    move v8, v7

    .line 690
    :goto_d
    const-class v9, Landroidx/camera/camera2/internal/compat/quirk/PreviewOrientationIncorrectQuirk;

    .line 691
    .line 692
    invoke-virtual {v1, v9, v8}, Lh0/q1;->a(Ljava/lang/Class;Z)Z

    .line 693
    .line 694
    .line 695
    move-result v8

    .line 696
    if-eqz v8, :cond_22

    .line 697
    .line 698
    new-instance v8, Landroidx/camera/camera2/internal/compat/quirk/PreviewOrientationIncorrectQuirk;

    .line 699
    .line 700
    invoke-direct {v8}, Landroidx/camera/camera2/internal/compat/quirk/PreviewOrientationIncorrectQuirk;-><init>()V

    .line 701
    .line 702
    .line 703
    invoke-virtual {v2, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 704
    .line 705
    .line 706
    :cond_22
    invoke-virtual {v0, v3}, Lv/b;->a(Landroid/hardware/camera2/CameraCharacteristics$Key;)Ljava/lang/Object;

    .line 707
    .line 708
    .line 709
    move-result-object v8

    .line 710
    check-cast v8, Ljava/lang/Integer;

    .line 711
    .line 712
    if-eqz v8, :cond_23

    .line 713
    .line 714
    invoke-virtual {v8}, Ljava/lang/Integer;->intValue()I

    .line 715
    .line 716
    .line 717
    move-result v8

    .line 718
    if-ne v8, v5, :cond_23

    .line 719
    .line 720
    move v8, v6

    .line 721
    goto :goto_e

    .line 722
    :cond_23
    move v8, v7

    .line 723
    :goto_e
    const-class v9, Landroidx/camera/camera2/internal/compat/quirk/CaptureSessionStuckQuirk;

    .line 724
    .line 725
    invoke-virtual {v1, v9, v8}, Lh0/q1;->a(Ljava/lang/Class;Z)Z

    .line 726
    .line 727
    .line 728
    move-result v8

    .line 729
    if-eqz v8, :cond_24

    .line 730
    .line 731
    new-instance v8, Landroidx/camera/camera2/internal/compat/quirk/CaptureSessionStuckQuirk;

    .line 732
    .line 733
    invoke-direct {v8}, Landroidx/camera/camera2/internal/compat/quirk/CaptureSessionStuckQuirk;-><init>()V

    .line 734
    .line 735
    .line 736
    invoke-virtual {v2, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 737
    .line 738
    .line 739
    :cond_24
    sget-object v8, Landroidx/camera/camera2/internal/compat/quirk/ImageCaptureFlashNotFireQuirk;->b:Ljava/util/List;

    .line 740
    .line 741
    sget-object v9, Landroid/os/Build;->MODEL:Ljava/lang/String;

    .line 742
    .line 743
    sget-object v11, Ljava/util/Locale;->US:Ljava/util/Locale;

    .line 744
    .line 745
    invoke-virtual {v9, v11}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 746
    .line 747
    .line 748
    move-result-object v12

    .line 749
    invoke-interface {v8, v12}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 750
    .line 751
    .line 752
    move-result v8

    .line 753
    if-eqz v8, :cond_25

    .line 754
    .line 755
    sget-object v8, Landroid/hardware/camera2/CameraCharacteristics;->LENS_FACING:Landroid/hardware/camera2/CameraCharacteristics$Key;

    .line 756
    .line 757
    invoke-virtual {v0, v8}, Lv/b;->a(Landroid/hardware/camera2/CameraCharacteristics$Key;)Ljava/lang/Object;

    .line 758
    .line 759
    .line 760
    move-result-object v8

    .line 761
    check-cast v8, Ljava/lang/Integer;

    .line 762
    .line 763
    invoke-virtual {v8}, Ljava/lang/Integer;->intValue()I

    .line 764
    .line 765
    .line 766
    move-result v8

    .line 767
    if-nez v8, :cond_25

    .line 768
    .line 769
    move v8, v6

    .line 770
    goto :goto_f

    .line 771
    :cond_25
    move v8, v7

    .line 772
    :goto_f
    sget-object v12, Landroidx/camera/camera2/internal/compat/quirk/ImageCaptureFlashNotFireQuirk;->a:Ljava/util/List;

    .line 773
    .line 774
    invoke-virtual {v9, v11}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 775
    .line 776
    .line 777
    move-result-object v13

    .line 778
    invoke-interface {v12, v13}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 779
    .line 780
    .line 781
    move-result v12

    .line 782
    if-nez v8, :cond_27

    .line 783
    .line 784
    if-eqz v12, :cond_26

    .line 785
    .line 786
    goto :goto_10

    .line 787
    :cond_26
    move v8, v7

    .line 788
    goto :goto_11

    .line 789
    :cond_27
    :goto_10
    move v8, v6

    .line 790
    :goto_11
    const-class v12, Landroidx/camera/camera2/internal/compat/quirk/ImageCaptureFlashNotFireQuirk;

    .line 791
    .line 792
    invoke-virtual {v1, v12, v8}, Lh0/q1;->a(Ljava/lang/Class;Z)Z

    .line 793
    .line 794
    .line 795
    move-result v8

    .line 796
    if-eqz v8, :cond_28

    .line 797
    .line 798
    new-instance v8, Landroidx/camera/camera2/internal/compat/quirk/ImageCaptureFlashNotFireQuirk;

    .line 799
    .line 800
    invoke-direct {v8}, Landroidx/camera/camera2/internal/compat/quirk/ImageCaptureFlashNotFireQuirk;-><init>()V

    .line 801
    .line 802
    .line 803
    invoke-virtual {v2, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 804
    .line 805
    .line 806
    :cond_28
    sget-object v8, Landroidx/camera/camera2/internal/compat/quirk/ImageCaptureWithFlashUnderexposureQuirk;->a:Ljava/util/List;

    .line 807
    .line 808
    invoke-virtual {v9, v11}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 809
    .line 810
    .line 811
    move-result-object v12

    .line 812
    invoke-interface {v8, v12}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 813
    .line 814
    .line 815
    move-result v8

    .line 816
    if-eqz v8, :cond_29

    .line 817
    .line 818
    sget-object v8, Landroid/hardware/camera2/CameraCharacteristics;->LENS_FACING:Landroid/hardware/camera2/CameraCharacteristics$Key;

    .line 819
    .line 820
    invoke-virtual {v0, v8}, Lv/b;->a(Landroid/hardware/camera2/CameraCharacteristics$Key;)Ljava/lang/Object;

    .line 821
    .line 822
    .line 823
    move-result-object v8

    .line 824
    check-cast v8, Ljava/lang/Integer;

    .line 825
    .line 826
    invoke-virtual {v8}, Ljava/lang/Integer;->intValue()I

    .line 827
    .line 828
    .line 829
    move-result v8

    .line 830
    if-ne v8, v6, :cond_29

    .line 831
    .line 832
    move v8, v6

    .line 833
    goto :goto_12

    .line 834
    :cond_29
    move v8, v7

    .line 835
    :goto_12
    const-class v12, Landroidx/camera/camera2/internal/compat/quirk/ImageCaptureWithFlashUnderexposureQuirk;

    .line 836
    .line 837
    invoke-virtual {v1, v12, v8}, Lh0/q1;->a(Ljava/lang/Class;Z)Z

    .line 838
    .line 839
    .line 840
    move-result v8

    .line 841
    if-eqz v8, :cond_2a

    .line 842
    .line 843
    new-instance v8, Landroidx/camera/camera2/internal/compat/quirk/ImageCaptureWithFlashUnderexposureQuirk;

    .line 844
    .line 845
    invoke-direct {v8}, Landroidx/camera/camera2/internal/compat/quirk/ImageCaptureWithFlashUnderexposureQuirk;-><init>()V

    .line 846
    .line 847
    .line 848
    invoke-virtual {v2, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 849
    .line 850
    .line 851
    :cond_2a
    sget-object v8, Landroidx/camera/camera2/internal/compat/quirk/ImageCaptureFailWithAutoFlashQuirk;->a:Ljava/util/List;

    .line 852
    .line 853
    invoke-virtual {v9, v11}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 854
    .line 855
    .line 856
    move-result-object v9

    .line 857
    invoke-interface {v8, v9}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 858
    .line 859
    .line 860
    move-result v8

    .line 861
    if-eqz v8, :cond_2b

    .line 862
    .line 863
    sget-object v8, Landroid/hardware/camera2/CameraCharacteristics;->LENS_FACING:Landroid/hardware/camera2/CameraCharacteristics$Key;

    .line 864
    .line 865
    invoke-virtual {v0, v8}, Lv/b;->a(Landroid/hardware/camera2/CameraCharacteristics$Key;)Ljava/lang/Object;

    .line 866
    .line 867
    .line 868
    move-result-object v8

    .line 869
    check-cast v8, Ljava/lang/Integer;

    .line 870
    .line 871
    invoke-virtual {v8}, Ljava/lang/Integer;->intValue()I

    .line 872
    .line 873
    .line 874
    move-result v8

    .line 875
    if-nez v8, :cond_2b

    .line 876
    .line 877
    move v8, v6

    .line 878
    goto :goto_13

    .line 879
    :cond_2b
    move v8, v7

    .line 880
    :goto_13
    const-class v9, Landroidx/camera/camera2/internal/compat/quirk/ImageCaptureFailWithAutoFlashQuirk;

    .line 881
    .line 882
    invoke-virtual {v1, v9, v8}, Lh0/q1;->a(Ljava/lang/Class;Z)Z

    .line 883
    .line 884
    .line 885
    move-result v8

    .line 886
    if-eqz v8, :cond_2c

    .line 887
    .line 888
    new-instance v8, Landroidx/camera/camera2/internal/compat/quirk/ImageCaptureFailWithAutoFlashQuirk;

    .line 889
    .line 890
    invoke-direct {v8}, Landroidx/camera/camera2/internal/compat/quirk/ImageCaptureFailWithAutoFlashQuirk;-><init>()V

    .line 891
    .line 892
    .line 893
    invoke-virtual {v2, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 894
    .line 895
    .line 896
    :cond_2c
    invoke-virtual {v0, v3}, Lv/b;->a(Landroid/hardware/camera2/CameraCharacteristics$Key;)Ljava/lang/Object;

    .line 897
    .line 898
    .line 899
    move-result-object v3

    .line 900
    check-cast v3, Ljava/lang/Integer;

    .line 901
    .line 902
    if-eqz v3, :cond_2d

    .line 903
    .line 904
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 905
    .line 906
    .line 907
    move-result v3

    .line 908
    if-ne v3, v5, :cond_2d

    .line 909
    .line 910
    move v3, v6

    .line 911
    goto :goto_14

    .line 912
    :cond_2d
    move v3, v7

    .line 913
    :goto_14
    const-class v5, Landroidx/camera/camera2/internal/compat/quirk/IncorrectCaptureStateQuirk;

    .line 914
    .line 915
    invoke-virtual {v1, v5, v3}, Lh0/q1;->a(Ljava/lang/Class;Z)Z

    .line 916
    .line 917
    .line 918
    move-result v3

    .line 919
    if-eqz v3, :cond_2e

    .line 920
    .line 921
    new-instance v3, Landroidx/camera/camera2/internal/compat/quirk/IncorrectCaptureStateQuirk;

    .line 922
    .line 923
    invoke-direct {v3}, Landroidx/camera/camera2/internal/compat/quirk/IncorrectCaptureStateQuirk;-><init>()V

    .line 924
    .line 925
    .line 926
    invoke-virtual {v2, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 927
    .line 928
    .line 929
    :cond_2e
    sget-object v3, Landroidx/camera/camera2/internal/compat/quirk/TorchFlashRequiredFor3aUpdateQuirk;->a:Ljava/util/List;

    .line 930
    .line 931
    invoke-interface {v3}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 932
    .line 933
    .line 934
    move-result-object v3

    .line 935
    :cond_2f
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 936
    .line 937
    .line 938
    move-result v5

    .line 939
    if-eqz v5, :cond_30

    .line 940
    .line 941
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 942
    .line 943
    .line 944
    move-result-object v5

    .line 945
    check-cast v5, Ljava/lang/String;

    .line 946
    .line 947
    sget-object v8, Landroid/os/Build;->MODEL:Ljava/lang/String;

    .line 948
    .line 949
    sget-object v9, Ljava/util/Locale;->US:Ljava/util/Locale;

    .line 950
    .line 951
    invoke-virtual {v8, v9}, Ljava/lang/String;->toUpperCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 952
    .line 953
    .line 954
    move-result-object v8

    .line 955
    invoke-virtual {v8, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 956
    .line 957
    .line 958
    move-result v5

    .line 959
    if-eqz v5, :cond_2f

    .line 960
    .line 961
    sget-object v3, Landroid/hardware/camera2/CameraCharacteristics;->LENS_FACING:Landroid/hardware/camera2/CameraCharacteristics$Key;

    .line 962
    .line 963
    invoke-virtual {v0, v3}, Lv/b;->a(Landroid/hardware/camera2/CameraCharacteristics$Key;)Ljava/lang/Object;

    .line 964
    .line 965
    .line 966
    move-result-object v3

    .line 967
    check-cast v3, Ljava/lang/Integer;

    .line 968
    .line 969
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 970
    .line 971
    .line 972
    move-result v3

    .line 973
    if-nez v3, :cond_30

    .line 974
    .line 975
    move v3, v6

    .line 976
    goto :goto_15

    .line 977
    :cond_30
    move v3, v7

    .line 978
    :goto_15
    const-class v5, Landroidx/camera/camera2/internal/compat/quirk/TorchFlashRequiredFor3aUpdateQuirk;

    .line 979
    .line 980
    invoke-virtual {v1, v5, v3}, Lh0/q1;->a(Ljava/lang/Class;Z)Z

    .line 981
    .line 982
    .line 983
    move-result v3

    .line 984
    if-eqz v3, :cond_31

    .line 985
    .line 986
    new-instance v3, Landroidx/camera/camera2/internal/compat/quirk/TorchFlashRequiredFor3aUpdateQuirk;

    .line 987
    .line 988
    invoke-direct {v3}, Ljava/lang/Object;-><init>()V

    .line 989
    .line 990
    .line 991
    invoke-virtual {v2, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 992
    .line 993
    .line 994
    :cond_31
    sget-object v3, Landroid/os/Build;->MANUFACTURER:Ljava/lang/String;

    .line 995
    .line 996
    const-string v5, "HUAWEI"

    .line 997
    .line 998
    invoke-virtual {v5, v3}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 999
    .line 1000
    .line 1001
    move-result v8

    .line 1002
    if-eqz v8, :cond_32

    .line 1003
    .line 1004
    const-string v8, "HUAWEI ALE-L04"

    .line 1005
    .line 1006
    sget-object v9, Landroid/os/Build;->MODEL:Ljava/lang/String;

    .line 1007
    .line 1008
    invoke-virtual {v8, v9}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 1009
    .line 1010
    .line 1011
    move-result v8

    .line 1012
    if-eqz v8, :cond_32

    .line 1013
    .line 1014
    goto :goto_16

    .line 1015
    :cond_32
    const-string v8, "Samsung"

    .line 1016
    .line 1017
    invoke-virtual {v8, v3}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 1018
    .line 1019
    .line 1020
    move-result v9

    .line 1021
    if-eqz v9, :cond_33

    .line 1022
    .line 1023
    const-string v9, "sm-j320f"

    .line 1024
    .line 1025
    sget-object v11, Landroid/os/Build;->MODEL:Ljava/lang/String;

    .line 1026
    .line 1027
    invoke-virtual {v9, v11}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 1028
    .line 1029
    .line 1030
    move-result v9

    .line 1031
    if-eqz v9, :cond_33

    .line 1032
    .line 1033
    goto :goto_16

    .line 1034
    :cond_33
    invoke-virtual {v8, v3}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 1035
    .line 1036
    .line 1037
    move-result v9

    .line 1038
    if-eqz v9, :cond_34

    .line 1039
    .line 1040
    const-string v9, "sm-j700f"

    .line 1041
    .line 1042
    sget-object v11, Landroid/os/Build;->MODEL:Ljava/lang/String;

    .line 1043
    .line 1044
    invoke-virtual {v9, v11}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 1045
    .line 1046
    .line 1047
    move-result v9

    .line 1048
    if-eqz v9, :cond_34

    .line 1049
    .line 1050
    goto :goto_16

    .line 1051
    :cond_34
    invoke-virtual {v8, v3}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 1052
    .line 1053
    .line 1054
    move-result v9

    .line 1055
    if-eqz v9, :cond_35

    .line 1056
    .line 1057
    const-string v9, "sm-j111f"

    .line 1058
    .line 1059
    sget-object v11, Landroid/os/Build;->MODEL:Ljava/lang/String;

    .line 1060
    .line 1061
    invoke-virtual {v9, v11}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 1062
    .line 1063
    .line 1064
    move-result v9

    .line 1065
    if-eqz v9, :cond_35

    .line 1066
    .line 1067
    goto :goto_16

    .line 1068
    :cond_35
    const-string v9, "OPPO"

    .line 1069
    .line 1070
    invoke-virtual {v9, v3}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 1071
    .line 1072
    .line 1073
    move-result v9

    .line 1074
    if-eqz v9, :cond_36

    .line 1075
    .line 1076
    const-string v9, "A37F"

    .line 1077
    .line 1078
    sget-object v11, Landroid/os/Build;->MODEL:Ljava/lang/String;

    .line 1079
    .line 1080
    invoke-virtual {v9, v11}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 1081
    .line 1082
    .line 1083
    move-result v9

    .line 1084
    if-eqz v9, :cond_36

    .line 1085
    .line 1086
    goto :goto_16

    .line 1087
    :cond_36
    invoke-virtual {v8, v3}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 1088
    .line 1089
    .line 1090
    move-result v8

    .line 1091
    if-eqz v8, :cond_37

    .line 1092
    .line 1093
    const-string v8, "sm-j510fn"

    .line 1094
    .line 1095
    sget-object v9, Landroid/os/Build;->MODEL:Ljava/lang/String;

    .line 1096
    .line 1097
    invoke-virtual {v8, v9}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 1098
    .line 1099
    .line 1100
    move-result v8

    .line 1101
    if-eqz v8, :cond_37

    .line 1102
    .line 1103
    :goto_16
    move v8, v6

    .line 1104
    goto :goto_17

    .line 1105
    :cond_37
    move v8, v7

    .line 1106
    :goto_17
    const-class v9, Landroidx/camera/camera2/internal/compat/quirk/PreviewStretchWhenVideoCaptureIsBoundQuirk;

    .line 1107
    .line 1108
    invoke-virtual {v1, v9, v8}, Lh0/q1;->a(Ljava/lang/Class;Z)Z

    .line 1109
    .line 1110
    .line 1111
    move-result v8

    .line 1112
    if-eqz v8, :cond_38

    .line 1113
    .line 1114
    new-instance v8, Landroidx/camera/camera2/internal/compat/quirk/PreviewStretchWhenVideoCaptureIsBoundQuirk;

    .line 1115
    .line 1116
    invoke-direct {v8}, Landroidx/camera/camera2/internal/compat/quirk/PreviewStretchWhenVideoCaptureIsBoundQuirk;-><init>()V

    .line 1117
    .line 1118
    .line 1119
    invoke-virtual {v2, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1120
    .line 1121
    .line 1122
    :cond_38
    const-string v8, "Huawei"

    .line 1123
    .line 1124
    invoke-virtual {v8, v3}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 1125
    .line 1126
    .line 1127
    move-result v8

    .line 1128
    const-class v9, Landroidx/camera/camera2/internal/compat/quirk/PreviewDelayWhenVideoCaptureIsBoundQuirk;

    .line 1129
    .line 1130
    invoke-virtual {v1, v9, v8}, Lh0/q1;->a(Ljava/lang/Class;Z)Z

    .line 1131
    .line 1132
    .line 1133
    move-result v8

    .line 1134
    if-eqz v8, :cond_39

    .line 1135
    .line 1136
    new-instance v8, Landroidx/camera/camera2/internal/compat/quirk/PreviewDelayWhenVideoCaptureIsBoundQuirk;

    .line 1137
    .line 1138
    invoke-direct {v8}, Landroidx/camera/camera2/internal/compat/quirk/PreviewDelayWhenVideoCaptureIsBoundQuirk;-><init>()V

    .line 1139
    .line 1140
    .line 1141
    invoke-virtual {v2, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1142
    .line 1143
    .line 1144
    :cond_39
    sget-object v8, Landroid/os/Build;->BRAND:Ljava/lang/String;

    .line 1145
    .line 1146
    const-string v9, "blu"

    .line 1147
    .line 1148
    invoke-virtual {v9, v8}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 1149
    .line 1150
    .line 1151
    move-result v9

    .line 1152
    const-string v11, "itel"

    .line 1153
    .line 1154
    const-string v12, "sp"

    .line 1155
    .line 1156
    const-string v13, "ums"

    .line 1157
    .line 1158
    const-string v14, "Spreadtrum"

    .line 1159
    .line 1160
    const/16 v15, 0x1f

    .line 1161
    .line 1162
    if-eqz v9, :cond_3a

    .line 1163
    .line 1164
    const-string v9, "studio x10"

    .line 1165
    .line 1166
    sget-object v6, Landroid/os/Build;->MODEL:Ljava/lang/String;

    .line 1167
    .line 1168
    invoke-virtual {v9, v6}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 1169
    .line 1170
    .line 1171
    move-result v6

    .line 1172
    if-eqz v6, :cond_3a

    .line 1173
    .line 1174
    :goto_18
    move-object/from16 v16, v10

    .line 1175
    .line 1176
    move v10, v7

    .line 1177
    goto/16 :goto_1d

    .line 1178
    .line 1179
    :cond_3a
    invoke-virtual {v11, v8}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 1180
    .line 1181
    .line 1182
    move-result v6

    .line 1183
    if-eqz v6, :cond_3b

    .line 1184
    .line 1185
    const-string v6, "itel w6004"

    .line 1186
    .line 1187
    sget-object v9, Landroid/os/Build;->MODEL:Ljava/lang/String;

    .line 1188
    .line 1189
    invoke-virtual {v6, v9}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 1190
    .line 1191
    .line 1192
    move-result v6

    .line 1193
    if-eqz v6, :cond_3b

    .line 1194
    .line 1195
    goto :goto_18

    .line 1196
    :cond_3b
    const-string v6, "vivo"

    .line 1197
    .line 1198
    invoke-virtual {v6, v8}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 1199
    .line 1200
    .line 1201
    move-result v6

    .line 1202
    if-eqz v6, :cond_3c

    .line 1203
    .line 1204
    const-string v6, "vivo 1805"

    .line 1205
    .line 1206
    sget-object v9, Landroid/os/Build;->MODEL:Ljava/lang/String;

    .line 1207
    .line 1208
    invoke-virtual {v6, v9}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 1209
    .line 1210
    .line 1211
    move-result v6

    .line 1212
    if-eqz v6, :cond_3c

    .line 1213
    .line 1214
    goto :goto_18

    .line 1215
    :cond_3c
    const-string v6, "positivo"

    .line 1216
    .line 1217
    invoke-virtual {v6, v8}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 1218
    .line 1219
    .line 1220
    move-result v6

    .line 1221
    if-eqz v6, :cond_3d

    .line 1222
    .line 1223
    const-string v6, "twist 2 pro"

    .line 1224
    .line 1225
    sget-object v9, Landroid/os/Build;->MODEL:Ljava/lang/String;

    .line 1226
    .line 1227
    invoke-virtual {v6, v9}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 1228
    .line 1229
    .line 1230
    move-result v6

    .line 1231
    if-eqz v6, :cond_3d

    .line 1232
    .line 1233
    goto :goto_18

    .line 1234
    :cond_3d
    sget-object v6, Landroid/os/Build;->MODEL:Ljava/lang/String;

    .line 1235
    .line 1236
    const-string v9, "pixel 4 xl"

    .line 1237
    .line 1238
    invoke-virtual {v9, v6}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 1239
    .line 1240
    .line 1241
    move-result v9

    .line 1242
    if-eqz v9, :cond_40

    .line 1243
    .line 1244
    sget v9, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 1245
    .line 1246
    const/16 v7, 0x1d

    .line 1247
    .line 1248
    if-ne v9, v7, :cond_40

    .line 1249
    .line 1250
    :cond_3e
    :goto_19
    move-object/from16 v16, v10

    .line 1251
    .line 1252
    :cond_3f
    const/4 v10, 0x0

    .line 1253
    goto/16 :goto_1d

    .line 1254
    .line 1255
    :cond_40
    invoke-virtual {v4, v8}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 1256
    .line 1257
    .line 1258
    move-result v7

    .line 1259
    if-eqz v7, :cond_41

    .line 1260
    .line 1261
    const-string v7, "moto e13"

    .line 1262
    .line 1263
    invoke-virtual {v7, v6}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 1264
    .line 1265
    .line 1266
    move-result v6

    .line 1267
    if-eqz v6, :cond_41

    .line 1268
    .line 1269
    :goto_1a
    goto :goto_19

    .line 1270
    :cond_41
    invoke-virtual {v10, v8}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 1271
    .line 1272
    .line 1273
    move-result v6

    .line 1274
    if-eqz v6, :cond_42

    .line 1275
    .line 1276
    sget-object v6, Landroid/os/Build;->DEVICE:Ljava/lang/String;

    .line 1277
    .line 1278
    const-string v7, "gta8"

    .line 1279
    .line 1280
    invoke-virtual {v7, v6}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 1281
    .line 1282
    .line 1283
    move-result v7

    .line 1284
    if-nez v7, :cond_3e

    .line 1285
    .line 1286
    const-string v7, "gta8wifi"

    .line 1287
    .line 1288
    invoke-virtual {v7, v6}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 1289
    .line 1290
    .line 1291
    move-result v6

    .line 1292
    if-eqz v6, :cond_42

    .line 1293
    .line 1294
    goto :goto_1a

    .line 1295
    :cond_42
    sget v6, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 1296
    .line 1297
    if-lt v6, v15, :cond_43

    .line 1298
    .line 1299
    invoke-static {}, Lh4/b;->n()Ljava/lang/String;

    .line 1300
    .line 1301
    .line 1302
    move-result-object v6

    .line 1303
    invoke-virtual {v14, v6}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 1304
    .line 1305
    .line 1306
    move-result v6

    .line 1307
    if-nez v6, :cond_3e

    .line 1308
    .line 1309
    :cond_43
    sget-object v6, Landroid/os/Build;->HARDWARE:Ljava/lang/String;

    .line 1310
    .line 1311
    const-string v7, "HARDWARE"

    .line 1312
    .line 1313
    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1314
    .line 1315
    .line 1316
    sget-object v7, Ljava/util/Locale;->ROOT:Ljava/util/Locale;

    .line 1317
    .line 1318
    invoke-virtual {v6, v7}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 1319
    .line 1320
    .line 1321
    move-result-object v9

    .line 1322
    const-string v15, "toLowerCase(...)"

    .line 1323
    .line 1324
    invoke-static {v9, v15}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1325
    .line 1326
    .line 1327
    move-object/from16 v16, v10

    .line 1328
    .line 1329
    const/4 v10, 0x0

    .line 1330
    invoke-static {v9, v13, v10}, Lly0/w;->x(Ljava/lang/String;Ljava/lang/String;Z)Z

    .line 1331
    .line 1332
    .line 1333
    move-result v9

    .line 1334
    if-nez v9, :cond_3f

    .line 1335
    .line 1336
    const-string v9, "MANUFACTURER"

    .line 1337
    .line 1338
    invoke-static {v3, v9}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1339
    .line 1340
    .line 1341
    const-string v9, "Itel"

    .line 1342
    .line 1343
    invoke-virtual {v3, v9}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 1344
    .line 1345
    .line 1346
    move-result v3

    .line 1347
    if-nez v3, :cond_45

    .line 1348
    .line 1349
    const-string v3, "BRAND"

    .line 1350
    .line 1351
    invoke-static {v8, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1352
    .line 1353
    .line 1354
    invoke-virtual {v8, v9}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 1355
    .line 1356
    .line 1357
    move-result v3

    .line 1358
    if-eqz v3, :cond_44

    .line 1359
    .line 1360
    goto :goto_1b

    .line 1361
    :cond_44
    const/4 v10, 0x0

    .line 1362
    goto :goto_1c

    .line 1363
    :cond_45
    :goto_1b
    invoke-virtual {v6, v7}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 1364
    .line 1365
    .line 1366
    move-result-object v3

    .line 1367
    invoke-static {v3, v15}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1368
    .line 1369
    .line 1370
    const/4 v10, 0x0

    .line 1371
    invoke-static {v3, v12, v10}, Lly0/w;->x(Ljava/lang/String;Ljava/lang/String;Z)Z

    .line 1372
    .line 1373
    .line 1374
    move-result v3

    .line 1375
    if-eqz v3, :cond_46

    .line 1376
    .line 1377
    goto :goto_1d

    .line 1378
    :cond_46
    :goto_1c
    move v3, v10

    .line 1379
    goto :goto_1e

    .line 1380
    :goto_1d
    const/4 v3, 0x1

    .line 1381
    :goto_1e
    const-class v6, Landroidx/camera/camera2/internal/compat/quirk/ImageCaptureFailedWhenVideoCaptureIsBoundQuirk;

    .line 1382
    .line 1383
    invoke-virtual {v1, v6, v3}, Lh0/q1;->a(Ljava/lang/Class;Z)Z

    .line 1384
    .line 1385
    .line 1386
    move-result v3

    .line 1387
    if-eqz v3, :cond_47

    .line 1388
    .line 1389
    new-instance v3, Landroidx/camera/camera2/internal/compat/quirk/ImageCaptureFailedWhenVideoCaptureIsBoundQuirk;

    .line 1390
    .line 1391
    invoke-direct {v3}, Landroidx/camera/camera2/internal/compat/quirk/ImageCaptureFailedWhenVideoCaptureIsBoundQuirk;-><init>()V

    .line 1392
    .line 1393
    .line 1394
    invoke-virtual {v2, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1395
    .line 1396
    .line 1397
    :cond_47
    sget-object v3, Landroid/os/Build;->MODEL:Ljava/lang/String;

    .line 1398
    .line 1399
    const-string v6, "Pixel 8"

    .line 1400
    .line 1401
    invoke-virtual {v6, v3}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 1402
    .line 1403
    .line 1404
    move-result v6

    .line 1405
    if-eqz v6, :cond_48

    .line 1406
    .line 1407
    sget-object v6, Landroid/hardware/camera2/CameraCharacteristics;->LENS_FACING:Landroid/hardware/camera2/CameraCharacteristics$Key;

    .line 1408
    .line 1409
    invoke-virtual {v0, v6}, Lv/b;->a(Landroid/hardware/camera2/CameraCharacteristics$Key;)Ljava/lang/Object;

    .line 1410
    .line 1411
    .line 1412
    move-result-object v6

    .line 1413
    check-cast v6, Ljava/lang/Integer;

    .line 1414
    .line 1415
    invoke-virtual {v6}, Ljava/lang/Integer;->intValue()I

    .line 1416
    .line 1417
    .line 1418
    move-result v6

    .line 1419
    if-nez v6, :cond_48

    .line 1420
    .line 1421
    const/4 v6, 0x1

    .line 1422
    goto :goto_1f

    .line 1423
    :cond_48
    move v6, v10

    .line 1424
    :goto_1f
    const-class v7, Landroidx/camera/camera2/internal/compat/quirk/TemporalNoiseQuirk;

    .line 1425
    .line 1426
    invoke-virtual {v1, v7, v6}, Lh0/q1;->a(Ljava/lang/Class;Z)Z

    .line 1427
    .line 1428
    .line 1429
    move-result v6

    .line 1430
    if-eqz v6, :cond_49

    .line 1431
    .line 1432
    new-instance v6, Landroidx/camera/camera2/internal/compat/quirk/TemporalNoiseQuirk;

    .line 1433
    .line 1434
    invoke-direct {v6}, Landroidx/camera/camera2/internal/compat/quirk/TemporalNoiseQuirk;-><init>()V

    .line 1435
    .line 1436
    .line 1437
    invoke-virtual {v2, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1438
    .line 1439
    .line 1440
    :cond_49
    sget-object v6, Landroidx/camera/camera2/internal/compat/quirk/ImageCaptureFailedForVideoSnapshotQuirk;->a:Ljava/util/HashSet;

    .line 1441
    .line 1442
    sget-object v7, Ljava/util/Locale;->US:Ljava/util/Locale;

    .line 1443
    .line 1444
    invoke-virtual {v3, v7}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 1445
    .line 1446
    .line 1447
    move-result-object v9

    .line 1448
    invoke-virtual {v6, v9}, Ljava/util/HashSet;->contains(Ljava/lang/Object;)Z

    .line 1449
    .line 1450
    .line 1451
    move-result v6

    .line 1452
    if-nez v6, :cond_4d

    .line 1453
    .line 1454
    sget v6, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 1455
    .line 1456
    const/16 v9, 0x1f

    .line 1457
    .line 1458
    if-lt v6, v9, :cond_4a

    .line 1459
    .line 1460
    invoke-static {}, Lh4/b;->n()Ljava/lang/String;

    .line 1461
    .line 1462
    .line 1463
    move-result-object v6

    .line 1464
    invoke-virtual {v14, v6}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 1465
    .line 1466
    .line 1467
    move-result v6

    .line 1468
    if-nez v6, :cond_4d

    .line 1469
    .line 1470
    :cond_4a
    sget-object v6, Landroid/os/Build;->HARDWARE:Ljava/lang/String;

    .line 1471
    .line 1472
    invoke-virtual {v6, v7}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 1473
    .line 1474
    .line 1475
    move-result-object v9

    .line 1476
    invoke-virtual {v9, v13}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    .line 1477
    .line 1478
    .line 1479
    move-result v9

    .line 1480
    if-nez v9, :cond_4d

    .line 1481
    .line 1482
    invoke-virtual {v11, v8}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 1483
    .line 1484
    .line 1485
    move-result v9

    .line 1486
    if-eqz v9, :cond_4b

    .line 1487
    .line 1488
    invoke-virtual {v6, v7}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 1489
    .line 1490
    .line 1491
    move-result-object v6

    .line 1492
    invoke-virtual {v6, v12}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    .line 1493
    .line 1494
    .line 1495
    move-result v6

    .line 1496
    if-eqz v6, :cond_4b

    .line 1497
    .line 1498
    goto :goto_20

    .line 1499
    :cond_4b
    invoke-virtual {v5, v8}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 1500
    .line 1501
    .line 1502
    move-result v5

    .line 1503
    if-eqz v5, :cond_4c

    .line 1504
    .line 1505
    const-string v5, "FIG-LX1"

    .line 1506
    .line 1507
    invoke-virtual {v5, v3}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 1508
    .line 1509
    .line 1510
    move-result v5

    .line 1511
    if-eqz v5, :cond_4c

    .line 1512
    .line 1513
    goto :goto_20

    .line 1514
    :cond_4c
    move v5, v10

    .line 1515
    goto :goto_21

    .line 1516
    :cond_4d
    :goto_20
    const/4 v5, 0x1

    .line 1517
    :goto_21
    const-class v6, Landroidx/camera/camera2/internal/compat/quirk/ImageCaptureFailedForVideoSnapshotQuirk;

    .line 1518
    .line 1519
    invoke-virtual {v1, v6, v5}, Lh0/q1;->a(Ljava/lang/Class;Z)Z

    .line 1520
    .line 1521
    .line 1522
    move-result v5

    .line 1523
    if-eqz v5, :cond_4e

    .line 1524
    .line 1525
    new-instance v5, Landroidx/camera/camera2/internal/compat/quirk/ImageCaptureFailedForVideoSnapshotQuirk;

    .line 1526
    .line 1527
    invoke-direct {v5}, Landroidx/camera/camera2/internal/compat/quirk/ImageCaptureFailedForVideoSnapshotQuirk;-><init>()V

    .line 1528
    .line 1529
    .line 1530
    invoke-virtual {v2, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1531
    .line 1532
    .line 1533
    :cond_4e
    invoke-virtual {v4, v8}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 1534
    .line 1535
    .line 1536
    move-result v4

    .line 1537
    if-eqz v4, :cond_4f

    .line 1538
    .line 1539
    const-string v4, "moto e20"

    .line 1540
    .line 1541
    invoke-virtual {v4, v3}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 1542
    .line 1543
    .line 1544
    move-result v3

    .line 1545
    if-eqz v3, :cond_4f

    .line 1546
    .line 1547
    iget-object v0, v0, Lv/b;->c:Ljava/lang/String;

    .line 1548
    .line 1549
    const-string v3, "1"

    .line 1550
    .line 1551
    invoke-virtual {v0, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1552
    .line 1553
    .line 1554
    move-result v0

    .line 1555
    if-eqz v0, :cond_4f

    .line 1556
    .line 1557
    const/4 v0, 0x1

    .line 1558
    goto :goto_22

    .line 1559
    :cond_4f
    move v0, v10

    .line 1560
    :goto_22
    const-class v3, Landroidx/camera/camera2/internal/compat/quirk/CaptureSessionStuckWhenCreatingBeforeClosingCameraQuirk;

    .line 1561
    .line 1562
    invoke-virtual {v1, v3, v0}, Lh0/q1;->a(Ljava/lang/Class;Z)Z

    .line 1563
    .line 1564
    .line 1565
    move-result v0

    .line 1566
    if-eqz v0, :cond_50

    .line 1567
    .line 1568
    new-instance v0, Landroidx/camera/camera2/internal/compat/quirk/CaptureSessionStuckWhenCreatingBeforeClosingCameraQuirk;

    .line 1569
    .line 1570
    invoke-direct {v0}, Landroidx/camera/camera2/internal/compat/quirk/CaptureSessionStuckWhenCreatingBeforeClosingCameraQuirk;-><init>()V

    .line 1571
    .line 1572
    .line 1573
    invoke-virtual {v2, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1574
    .line 1575
    .line 1576
    :cond_50
    move-object/from16 v0, v16

    .line 1577
    .line 1578
    invoke-virtual {v0, v8}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 1579
    .line 1580
    .line 1581
    move-result v0

    .line 1582
    if-eqz v0, :cond_51

    .line 1583
    .line 1584
    sget-object v0, Landroid/os/Build;->DEVICE:Ljava/lang/String;

    .line 1585
    .line 1586
    const-string v3, "m55xq"

    .line 1587
    .line 1588
    invoke-virtual {v0, v3}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 1589
    .line 1590
    .line 1591
    move-result v0

    .line 1592
    if-eqz v0, :cond_51

    .line 1593
    .line 1594
    const/4 v6, 0x1

    .line 1595
    goto :goto_23

    .line 1596
    :cond_51
    move v6, v10

    .line 1597
    :goto_23
    const-class v0, Landroidx/camera/camera2/internal/compat/quirk/AbnormalStreamWhenImageAnalysisBindWithTemplateRecordQuirk;

    .line 1598
    .line 1599
    invoke-virtual {v1, v0, v6}, Lh0/q1;->a(Ljava/lang/Class;Z)Z

    .line 1600
    .line 1601
    .line 1602
    move-result v0

    .line 1603
    if-eqz v0, :cond_52

    .line 1604
    .line 1605
    new-instance v0, Landroidx/camera/camera2/internal/compat/quirk/AbnormalStreamWhenImageAnalysisBindWithTemplateRecordQuirk;

    .line 1606
    .line 1607
    invoke-direct {v0}, Landroidx/camera/camera2/internal/compat/quirk/AbnormalStreamWhenImageAnalysisBindWithTemplateRecordQuirk;-><init>()V

    .line 1608
    .line 1609
    .line 1610
    invoke-virtual {v2, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1611
    .line 1612
    .line 1613
    :cond_52
    new-instance v0, Ld01/x;

    .line 1614
    .line 1615
    invoke-direct {v0, v2}, Ld01/x;-><init>(Ljava/util/List;)V

    .line 1616
    .line 1617
    .line 1618
    new-instance v1, Ljava/lang/StringBuilder;

    .line 1619
    .line 1620
    const-string v2, "camera2 CameraQuirks = "

    .line 1621
    .line 1622
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 1623
    .line 1624
    .line 1625
    invoke-static {v0}, Ld01/x;->p(Ld01/x;)Ljava/lang/String;

    .line 1626
    .line 1627
    .line 1628
    move-result-object v2

    .line 1629
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1630
    .line 1631
    .line 1632
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1633
    .line 1634
    .line 1635
    move-result-object v1

    .line 1636
    const-string v2, "CameraQuirks"

    .line 1637
    .line 1638
    invoke-static {v2, v1}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 1639
    .line 1640
    .line 1641
    return-object v0

    .line 1642
    :catch_0
    move-exception v0

    .line 1643
    new-instance v1, Ljava/lang/AssertionError;

    .line 1644
    .line 1645
    const-string v2, "Unexpected error in QuirkSettings StateObservable"

    .line 1646
    .line 1647
    invoke-direct {v1, v2, v0}, Ljava/lang/AssertionError;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 1648
    .line 1649
    .line 1650
    throw v1
.end method
