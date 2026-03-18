.class public final synthetic Lb0/o1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lc6/a;


# instance fields
.field public final synthetic a:I


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lb0/o1;->a:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lgw0/c;I)V
    .locals 0

    .line 2
    iput p2, p0, Lb0/o1;->a:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final accept(Ljava/lang/Object;)V
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v0, v0, Lb0/o1;->a:I

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    const-string v2, "motorola"

    .line 7
    .line 8
    const-string v3, "HUAWEI"

    .line 9
    .line 10
    const-string v4, "google"

    .line 11
    .line 12
    const-string v5, "SAMSUNG"

    .line 13
    .line 14
    const/16 v6, 0x21

    .line 15
    .line 16
    const-string v7, "DeviceQuirks"

    .line 17
    .line 18
    const/4 v9, 0x0

    .line 19
    packed-switch v0, :pswitch_data_0

    .line 20
    .line 21
    .line 22
    move-object/from16 v0, p1

    .line 23
    .line 24
    check-cast v0, Lh0/q1;

    .line 25
    .line 26
    new-instance v1, Ld01/x;

    .line 27
    .line 28
    new-instance v2, Ljava/util/ArrayList;

    .line 29
    .line 30
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 31
    .line 32
    .line 33
    sget v3, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 34
    .line 35
    if-ge v3, v6, :cond_3

    .line 36
    .line 37
    sget-object v3, Landroid/os/Build;->MANUFACTURER:Ljava/lang/String;

    .line 38
    .line 39
    invoke-virtual {v5, v3}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 40
    .line 41
    .line 42
    move-result v4

    .line 43
    if-eqz v4, :cond_0

    .line 44
    .line 45
    sget-object v4, Landroid/os/Build;->DEVICE:Ljava/lang/String;

    .line 46
    .line 47
    const-string v5, "F2Q"

    .line 48
    .line 49
    invoke-virtual {v5, v4}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 50
    .line 51
    .line 52
    move-result v5

    .line 53
    if-nez v5, :cond_2

    .line 54
    .line 55
    const-string v5, "Q2Q"

    .line 56
    .line 57
    invoke-virtual {v5, v4}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 58
    .line 59
    .line 60
    move-result v4

    .line 61
    if-eqz v4, :cond_0

    .line 62
    .line 63
    goto :goto_0

    .line 64
    :cond_0
    const-string v4, "OPPO"

    .line 65
    .line 66
    invoke-virtual {v4, v3}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 67
    .line 68
    .line 69
    move-result v4

    .line 70
    if-eqz v4, :cond_1

    .line 71
    .line 72
    const-string v4, "OP4E75L1"

    .line 73
    .line 74
    sget-object v5, Landroid/os/Build;->DEVICE:Ljava/lang/String;

    .line 75
    .line 76
    invoke-virtual {v4, v5}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 77
    .line 78
    .line 79
    move-result v4

    .line 80
    if-eqz v4, :cond_1

    .line 81
    .line 82
    goto :goto_0

    .line 83
    :cond_1
    const-string v4, "LENOVO"

    .line 84
    .line 85
    invoke-virtual {v4, v3}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 86
    .line 87
    .line 88
    move-result v3

    .line 89
    if-eqz v3, :cond_3

    .line 90
    .line 91
    const-string v3, "Q706F"

    .line 92
    .line 93
    sget-object v4, Landroid/os/Build;->DEVICE:Ljava/lang/String;

    .line 94
    .line 95
    invoke-virtual {v3, v4}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 96
    .line 97
    .line 98
    move-result v3

    .line 99
    if-eqz v3, :cond_3

    .line 100
    .line 101
    :cond_2
    :goto_0
    const/4 v3, 0x1

    .line 102
    goto :goto_1

    .line 103
    :cond_3
    move v3, v9

    .line 104
    :goto_1
    const-class v4, Landroidx/camera/view/internal/compat/quirk/SurfaceViewStretchedQuirk;

    .line 105
    .line 106
    invoke-virtual {v0, v4, v3}, Lh0/q1;->a(Ljava/lang/Class;Z)Z

    .line 107
    .line 108
    .line 109
    move-result v3

    .line 110
    if-eqz v3, :cond_4

    .line 111
    .line 112
    new-instance v3, Landroidx/camera/view/internal/compat/quirk/SurfaceViewStretchedQuirk;

    .line 113
    .line 114
    invoke-direct {v3}, Landroidx/camera/view/internal/compat/quirk/SurfaceViewStretchedQuirk;-><init>()V

    .line 115
    .line 116
    .line 117
    invoke-virtual {v2, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 118
    .line 119
    .line 120
    :cond_4
    const-string v3, "XIAOMI"

    .line 121
    .line 122
    sget-object v4, Landroid/os/Build;->MANUFACTURER:Ljava/lang/String;

    .line 123
    .line 124
    invoke-virtual {v3, v4}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 125
    .line 126
    .line 127
    move-result v3

    .line 128
    if-eqz v3, :cond_5

    .line 129
    .line 130
    const-string v3, "M2101K7AG"

    .line 131
    .line 132
    sget-object v4, Landroid/os/Build;->MODEL:Ljava/lang/String;

    .line 133
    .line 134
    invoke-virtual {v3, v4}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 135
    .line 136
    .line 137
    move-result v3

    .line 138
    if-eqz v3, :cond_5

    .line 139
    .line 140
    const/4 v8, 0x1

    .line 141
    goto :goto_2

    .line 142
    :cond_5
    move v8, v9

    .line 143
    :goto_2
    const-class v3, Landroidx/camera/view/internal/compat/quirk/SurfaceViewNotCroppedByParentQuirk;

    .line 144
    .line 145
    invoke-virtual {v0, v3, v8}, Lh0/q1;->a(Ljava/lang/Class;Z)Z

    .line 146
    .line 147
    .line 148
    move-result v0

    .line 149
    if-eqz v0, :cond_6

    .line 150
    .line 151
    new-instance v0, Landroidx/camera/view/internal/compat/quirk/SurfaceViewNotCroppedByParentQuirk;

    .line 152
    .line 153
    invoke-direct {v0}, Landroidx/camera/view/internal/compat/quirk/SurfaceViewNotCroppedByParentQuirk;-><init>()V

    .line 154
    .line 155
    .line 156
    invoke-virtual {v2, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 157
    .line 158
    .line 159
    :cond_6
    invoke-direct {v1, v2}, Ld01/x;-><init>(Ljava/util/List;)V

    .line 160
    .line 161
    .line 162
    sput-object v1, Ly0/a;->a:Ld01/x;

    .line 163
    .line 164
    new-instance v0, Ljava/lang/StringBuilder;

    .line 165
    .line 166
    const-string v1, "view DeviceQuirks = "

    .line 167
    .line 168
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 169
    .line 170
    .line 171
    sget-object v1, Ly0/a;->a:Ld01/x;

    .line 172
    .line 173
    invoke-static {v1}, Ld01/x;->p(Ld01/x;)Ljava/lang/String;

    .line 174
    .line 175
    .line 176
    move-result-object v1

    .line 177
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 178
    .line 179
    .line 180
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 181
    .line 182
    .line 183
    move-result-object v0

    .line 184
    invoke-static {v7, v0}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 185
    .line 186
    .line 187
    return-void

    .line 188
    :pswitch_0
    move-object/from16 v0, p1

    .line 189
    .line 190
    check-cast v0, Lh0/q1;

    .line 191
    .line 192
    new-instance v1, Ld01/x;

    .line 193
    .line 194
    new-instance v10, Ljava/util/ArrayList;

    .line 195
    .line 196
    invoke-direct {v10}, Ljava/util/ArrayList;-><init>()V

    .line 197
    .line 198
    .line 199
    sget-object v11, Landroidx/camera/camera2/internal/compat/quirk/ImageCapturePixelHDRPlusQuirk;->a:Ljava/util/List;

    .line 200
    .line 201
    sget-object v12, Landroid/os/Build;->MODEL:Ljava/lang/String;

    .line 202
    .line 203
    invoke-interface {v11, v12}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 204
    .line 205
    .line 206
    move-result v11

    .line 207
    const-string v13, "Google"

    .line 208
    .line 209
    if-eqz v11, :cond_7

    .line 210
    .line 211
    sget-object v11, Landroid/os/Build;->MANUFACTURER:Ljava/lang/String;

    .line 212
    .line 213
    invoke-virtual {v13, v11}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 214
    .line 215
    .line 216
    move-result v11

    .line 217
    if-eqz v11, :cond_7

    .line 218
    .line 219
    const/4 v11, 0x1

    .line 220
    goto :goto_3

    .line 221
    :cond_7
    move v11, v9

    .line 222
    :goto_3
    const-class v14, Landroidx/camera/camera2/internal/compat/quirk/ImageCapturePixelHDRPlusQuirk;

    .line 223
    .line 224
    invoke-virtual {v0, v14, v11}, Lh0/q1;->a(Ljava/lang/Class;Z)Z

    .line 225
    .line 226
    .line 227
    move-result v11

    .line 228
    if-eqz v11, :cond_8

    .line 229
    .line 230
    new-instance v11, Landroidx/camera/camera2/internal/compat/quirk/ImageCapturePixelHDRPlusQuirk;

    .line 231
    .line 232
    invoke-direct {v11}, Landroidx/camera/camera2/internal/compat/quirk/ImageCapturePixelHDRPlusQuirk;-><init>()V

    .line 233
    .line 234
    .line 235
    invoke-virtual {v10, v11}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 236
    .line 237
    .line 238
    :cond_8
    const-class v11, Landroidx/camera/camera2/internal/compat/quirk/ExtraCroppingQuirk;

    .line 239
    .line 240
    invoke-static {}, Landroidx/camera/camera2/internal/compat/quirk/ExtraCroppingQuirk;->c()Z

    .line 241
    .line 242
    .line 243
    move-result v14

    .line 244
    invoke-virtual {v0, v11, v14}, Lh0/q1;->a(Ljava/lang/Class;Z)Z

    .line 245
    .line 246
    .line 247
    move-result v11

    .line 248
    if-eqz v11, :cond_9

    .line 249
    .line 250
    new-instance v11, Landroidx/camera/camera2/internal/compat/quirk/ExtraCroppingQuirk;

    .line 251
    .line 252
    invoke-direct {v11}, Landroidx/camera/camera2/internal/compat/quirk/ExtraCroppingQuirk;-><init>()V

    .line 253
    .line 254
    .line 255
    invoke-virtual {v10, v11}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 256
    .line 257
    .line 258
    :cond_9
    sget-object v11, Landroidx/camera/camera2/internal/compat/quirk/Nexus4AndroidLTargetAspectRatioQuirk;->a:Ljava/util/List;

    .line 259
    .line 260
    sget-object v11, Landroid/os/Build;->BRAND:Ljava/lang/String;

    .line 261
    .line 262
    const-string v14, "GOOGLE"

    .line 263
    .line 264
    invoke-virtual {v14, v11}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 265
    .line 266
    .line 267
    const-class v14, Landroidx/camera/camera2/internal/compat/quirk/Nexus4AndroidLTargetAspectRatioQuirk;

    .line 268
    .line 269
    invoke-virtual {v0, v14, v9}, Lh0/q1;->a(Ljava/lang/Class;Z)Z

    .line 270
    .line 271
    .line 272
    move-result v14

    .line 273
    if-eqz v14, :cond_a

    .line 274
    .line 275
    new-instance v14, Landroidx/camera/camera2/internal/compat/quirk/Nexus4AndroidLTargetAspectRatioQuirk;

    .line 276
    .line 277
    invoke-direct {v14}, Landroidx/camera/camera2/internal/compat/quirk/Nexus4AndroidLTargetAspectRatioQuirk;-><init>()V

    .line 278
    .line 279
    .line 280
    invoke-virtual {v10, v14}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 281
    .line 282
    .line 283
    :cond_a
    const-string v14, "OnePlus"

    .line 284
    .line 285
    invoke-virtual {v14, v11}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 286
    .line 287
    .line 288
    move-result v15

    .line 289
    if-eqz v15, :cond_b

    .line 290
    .line 291
    const-string v15, "OnePlus6"

    .line 292
    .line 293
    sget-object v8, Landroid/os/Build;->DEVICE:Ljava/lang/String;

    .line 294
    .line 295
    invoke-virtual {v15, v8}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 296
    .line 297
    .line 298
    move-result v8

    .line 299
    if-eqz v8, :cond_b

    .line 300
    .line 301
    goto/16 :goto_4

    .line 302
    .line 303
    :cond_b
    invoke-virtual {v14, v11}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 304
    .line 305
    .line 306
    move-result v8

    .line 307
    if-eqz v8, :cond_c

    .line 308
    .line 309
    const-string v8, "OnePlus6T"

    .line 310
    .line 311
    sget-object v14, Landroid/os/Build;->DEVICE:Ljava/lang/String;

    .line 312
    .line 313
    invoke-virtual {v8, v14}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 314
    .line 315
    .line 316
    move-result v8

    .line 317
    if-eqz v8, :cond_c

    .line 318
    .line 319
    goto :goto_4

    .line 320
    :cond_c
    invoke-virtual {v3, v11}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 321
    .line 322
    .line 323
    move-result v3

    .line 324
    if-eqz v3, :cond_d

    .line 325
    .line 326
    const-string v3, "HWANE"

    .line 327
    .line 328
    sget-object v8, Landroid/os/Build;->DEVICE:Ljava/lang/String;

    .line 329
    .line 330
    invoke-virtual {v3, v8}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 331
    .line 332
    .line 333
    move-result v3

    .line 334
    if-eqz v3, :cond_d

    .line 335
    .line 336
    goto :goto_4

    .line 337
    :cond_d
    invoke-virtual {v5, v11}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 338
    .line 339
    .line 340
    move-result v3

    .line 341
    if-eqz v3, :cond_e

    .line 342
    .line 343
    const-string v3, "ON7XELTE"

    .line 344
    .line 345
    sget-object v8, Landroid/os/Build;->DEVICE:Ljava/lang/String;

    .line 346
    .line 347
    invoke-virtual {v3, v8}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 348
    .line 349
    .line 350
    move-result v3

    .line 351
    if-eqz v3, :cond_e

    .line 352
    .line 353
    goto :goto_4

    .line 354
    :cond_e
    invoke-virtual {v5, v11}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 355
    .line 356
    .line 357
    move-result v3

    .line 358
    if-eqz v3, :cond_f

    .line 359
    .line 360
    const-string v3, "J7XELTE"

    .line 361
    .line 362
    sget-object v8, Landroid/os/Build;->DEVICE:Ljava/lang/String;

    .line 363
    .line 364
    invoke-virtual {v3, v8}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 365
    .line 366
    .line 367
    move-result v3

    .line 368
    if-eqz v3, :cond_f

    .line 369
    .line 370
    goto :goto_4

    .line 371
    :cond_f
    const-string v3, "REDMI"

    .line 372
    .line 373
    invoke-virtual {v3, v11}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 374
    .line 375
    .line 376
    move-result v3

    .line 377
    if-eqz v3, :cond_10

    .line 378
    .line 379
    const-string v3, "joyeuse"

    .line 380
    .line 381
    sget-object v8, Landroid/os/Build;->DEVICE:Ljava/lang/String;

    .line 382
    .line 383
    invoke-virtual {v3, v8}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 384
    .line 385
    .line 386
    move-result v3

    .line 387
    if-eqz v3, :cond_10

    .line 388
    .line 389
    goto :goto_4

    .line 390
    :cond_10
    invoke-static {}, Landroidx/camera/camera2/internal/compat/quirk/ExcludedSupportedSizesQuirk;->c()Z

    .line 391
    .line 392
    .line 393
    move-result v3

    .line 394
    if-nez v3, :cond_12

    .line 395
    .line 396
    invoke-static {}, Landroidx/camera/camera2/internal/compat/quirk/ExcludedSupportedSizesQuirk;->b()Z

    .line 397
    .line 398
    .line 399
    move-result v3

    .line 400
    if-eqz v3, :cond_11

    .line 401
    .line 402
    goto :goto_4

    .line 403
    :cond_11
    move v3, v9

    .line 404
    goto :goto_5

    .line 405
    :cond_12
    :goto_4
    const/4 v3, 0x1

    .line 406
    :goto_5
    const-class v8, Landroidx/camera/camera2/internal/compat/quirk/ExcludedSupportedSizesQuirk;

    .line 407
    .line 408
    invoke-virtual {v0, v8, v3}, Lh0/q1;->a(Ljava/lang/Class;Z)Z

    .line 409
    .line 410
    .line 411
    move-result v3

    .line 412
    if-eqz v3, :cond_13

    .line 413
    .line 414
    new-instance v3, Landroidx/camera/camera2/internal/compat/quirk/ExcludedSupportedSizesQuirk;

    .line 415
    .line 416
    invoke-direct {v3}, Landroidx/camera/camera2/internal/compat/quirk/ExcludedSupportedSizesQuirk;-><init>()V

    .line 417
    .line 418
    .line 419
    invoke-virtual {v10, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 420
    .line 421
    .line 422
    :cond_13
    sget-object v3, Landroidx/camera/camera2/internal/compat/quirk/CrashWhenTakingPhotoWithAutoFlashAEModeQuirk;->a:Ljava/util/List;

    .line 423
    .line 424
    sget-object v8, Ljava/util/Locale;->US:Ljava/util/Locale;

    .line 425
    .line 426
    invoke-virtual {v12, v8}, Ljava/lang/String;->toUpperCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 427
    .line 428
    .line 429
    move-result-object v14

    .line 430
    invoke-interface {v3, v14}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 431
    .line 432
    .line 433
    move-result v3

    .line 434
    const-class v14, Landroidx/camera/camera2/internal/compat/quirk/CrashWhenTakingPhotoWithAutoFlashAEModeQuirk;

    .line 435
    .line 436
    invoke-virtual {v0, v14, v3}, Lh0/q1;->a(Ljava/lang/Class;Z)Z

    .line 437
    .line 438
    .line 439
    move-result v3

    .line 440
    if-eqz v3, :cond_14

    .line 441
    .line 442
    new-instance v3, Landroidx/camera/camera2/internal/compat/quirk/CrashWhenTakingPhotoWithAutoFlashAEModeQuirk;

    .line 443
    .line 444
    invoke-direct {v3}, Landroidx/camera/camera2/internal/compat/quirk/CrashWhenTakingPhotoWithAutoFlashAEModeQuirk;-><init>()V

    .line 445
    .line 446
    .line 447
    invoke-virtual {v10, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 448
    .line 449
    .line 450
    :cond_14
    sget-object v3, Landroidx/camera/camera2/internal/compat/quirk/PreviewPixelHDRnetQuirk;->a:Ljava/util/List;

    .line 451
    .line 452
    sget-object v3, Landroid/os/Build;->MANUFACTURER:Ljava/lang/String;

    .line 453
    .line 454
    invoke-virtual {v13, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 455
    .line 456
    .line 457
    move-result v13

    .line 458
    if-eqz v13, :cond_15

    .line 459
    .line 460
    sget-object v13, Landroidx/camera/camera2/internal/compat/quirk/PreviewPixelHDRnetQuirk;->a:Ljava/util/List;

    .line 461
    .line 462
    sget-object v14, Landroid/os/Build;->DEVICE:Ljava/lang/String;

    .line 463
    .line 464
    invoke-static {}, Ljava/util/Locale;->getDefault()Ljava/util/Locale;

    .line 465
    .line 466
    .line 467
    move-result-object v15

    .line 468
    invoke-virtual {v14, v15}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 469
    .line 470
    .line 471
    move-result-object v14

    .line 472
    invoke-interface {v13, v14}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 473
    .line 474
    .line 475
    move-result v13

    .line 476
    if-eqz v13, :cond_15

    .line 477
    .line 478
    const/4 v13, 0x1

    .line 479
    goto :goto_6

    .line 480
    :cond_15
    move v13, v9

    .line 481
    :goto_6
    const-class v14, Landroidx/camera/camera2/internal/compat/quirk/PreviewPixelHDRnetQuirk;

    .line 482
    .line 483
    invoke-virtual {v0, v14, v13}, Lh0/q1;->a(Ljava/lang/Class;Z)Z

    .line 484
    .line 485
    .line 486
    move-result v13

    .line 487
    if-eqz v13, :cond_16

    .line 488
    .line 489
    new-instance v13, Landroidx/camera/camera2/internal/compat/quirk/PreviewPixelHDRnetQuirk;

    .line 490
    .line 491
    invoke-direct {v13}, Landroidx/camera/camera2/internal/compat/quirk/PreviewPixelHDRnetQuirk;-><init>()V

    .line 492
    .line 493
    .line 494
    invoke-virtual {v10, v13}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 495
    .line 496
    .line 497
    :cond_16
    invoke-virtual {v3, v8}, Ljava/lang/String;->toUpperCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 498
    .line 499
    .line 500
    move-result-object v13

    .line 501
    invoke-virtual {v5, v13}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 502
    .line 503
    .line 504
    move-result v5

    .line 505
    if-eqz v5, :cond_17

    .line 506
    .line 507
    invoke-virtual {v12, v8}, Ljava/lang/String;->toUpperCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 508
    .line 509
    .line 510
    move-result-object v5

    .line 511
    const-string v13, "SM-A716"

    .line 512
    .line 513
    invoke-virtual {v5, v13}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    .line 514
    .line 515
    .line 516
    move-result v5

    .line 517
    if-eqz v5, :cond_17

    .line 518
    .line 519
    const/4 v5, 0x1

    .line 520
    goto :goto_7

    .line 521
    :cond_17
    move v5, v9

    .line 522
    :goto_7
    const-class v13, Landroidx/camera/camera2/internal/compat/quirk/StillCaptureFlashStopRepeatingQuirk;

    .line 523
    .line 524
    invoke-virtual {v0, v13, v5}, Lh0/q1;->a(Ljava/lang/Class;Z)Z

    .line 525
    .line 526
    .line 527
    move-result v5

    .line 528
    if-eqz v5, :cond_18

    .line 529
    .line 530
    new-instance v5, Landroidx/camera/camera2/internal/compat/quirk/StillCaptureFlashStopRepeatingQuirk;

    .line 531
    .line 532
    invoke-direct {v5}, Landroidx/camera/camera2/internal/compat/quirk/StillCaptureFlashStopRepeatingQuirk;-><init>()V

    .line 533
    .line 534
    .line 535
    invoke-virtual {v10, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 536
    .line 537
    .line 538
    :cond_18
    sget-object v5, Landroidx/camera/camera2/internal/compat/quirk/ExtraSupportedSurfaceCombinationsQuirk;->a:Lh0/d2;

    .line 539
    .line 540
    sget-object v5, Landroid/os/Build;->DEVICE:Ljava/lang/String;

    .line 541
    .line 542
    const-string v13, "heroqltevzw"

    .line 543
    .line 544
    invoke-virtual {v13, v5}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 545
    .line 546
    .line 547
    move-result v13

    .line 548
    if-nez v13, :cond_1c

    .line 549
    .line 550
    const-string v13, "heroqltetmo"

    .line 551
    .line 552
    invoke-virtual {v13, v5}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 553
    .line 554
    .line 555
    move-result v5

    .line 556
    if-eqz v5, :cond_19

    .line 557
    .line 558
    goto :goto_9

    .line 559
    :cond_19
    invoke-virtual {v4, v11}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 560
    .line 561
    .line 562
    move-result v5

    .line 563
    if-nez v5, :cond_1a

    .line 564
    .line 565
    move v5, v9

    .line 566
    goto :goto_8

    .line 567
    :cond_1a
    invoke-virtual {v12, v8}, Ljava/lang/String;->toUpperCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 568
    .line 569
    .line 570
    move-result-object v5

    .line 571
    sget-object v13, Landroidx/camera/camera2/internal/compat/quirk/ExtraSupportedSurfaceCombinationsQuirk;->c:Ljava/util/HashSet;

    .line 572
    .line 573
    invoke-virtual {v13, v5}, Ljava/util/HashSet;->contains(Ljava/lang/Object;)Z

    .line 574
    .line 575
    .line 576
    move-result v5

    .line 577
    :goto_8
    if-nez v5, :cond_1c

    .line 578
    .line 579
    invoke-static {}, Landroidx/camera/camera2/internal/compat/quirk/ExtraSupportedSurfaceCombinationsQuirk;->b()Z

    .line 580
    .line 581
    .line 582
    move-result v5

    .line 583
    if-eqz v5, :cond_1b

    .line 584
    .line 585
    goto :goto_9

    .line 586
    :cond_1b
    move v5, v9

    .line 587
    goto :goto_a

    .line 588
    :cond_1c
    :goto_9
    const/4 v5, 0x1

    .line 589
    :goto_a
    const-class v13, Landroidx/camera/camera2/internal/compat/quirk/ExtraSupportedSurfaceCombinationsQuirk;

    .line 590
    .line 591
    invoke-virtual {v0, v13, v5}, Lh0/q1;->a(Ljava/lang/Class;Z)Z

    .line 592
    .line 593
    .line 594
    move-result v5

    .line 595
    if-eqz v5, :cond_1d

    .line 596
    .line 597
    new-instance v5, Landroidx/camera/camera2/internal/compat/quirk/ExtraSupportedSurfaceCombinationsQuirk;

    .line 598
    .line 599
    invoke-direct {v5}, Landroidx/camera/camera2/internal/compat/quirk/ExtraSupportedSurfaceCombinationsQuirk;-><init>()V

    .line 600
    .line 601
    .line 602
    invoke-virtual {v10, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 603
    .line 604
    .line 605
    :cond_1d
    sget-object v5, Landroidx/camera/camera2/internal/compat/quirk/FlashAvailabilityBufferUnderflowQuirk;->a:Ljava/util/HashSet;

    .line 606
    .line 607
    new-instance v13, Landroid/util/Pair;

    .line 608
    .line 609
    invoke-virtual {v3, v8}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 610
    .line 611
    .line 612
    move-result-object v3

    .line 613
    invoke-virtual {v12, v8}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 614
    .line 615
    .line 616
    move-result-object v14

    .line 617
    invoke-direct {v13, v3, v14}, Landroid/util/Pair;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 618
    .line 619
    .line 620
    invoke-virtual {v5, v13}, Ljava/util/HashSet;->contains(Ljava/lang/Object;)Z

    .line 621
    .line 622
    .line 623
    move-result v3

    .line 624
    const-class v5, Landroidx/camera/camera2/internal/compat/quirk/FlashAvailabilityBufferUnderflowQuirk;

    .line 625
    .line 626
    invoke-virtual {v0, v5, v3}, Lh0/q1;->a(Ljava/lang/Class;Z)Z

    .line 627
    .line 628
    .line 629
    move-result v3

    .line 630
    if-eqz v3, :cond_1e

    .line 631
    .line 632
    new-instance v3, Landroidx/camera/camera2/internal/compat/quirk/FlashAvailabilityBufferUnderflowQuirk;

    .line 633
    .line 634
    invoke-direct {v3}, Landroidx/camera/camera2/internal/compat/quirk/FlashAvailabilityBufferUnderflowQuirk;-><init>()V

    .line 635
    .line 636
    .line 637
    invoke-virtual {v10, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 638
    .line 639
    .line 640
    :cond_1e
    const-string v3, "Huawei"

    .line 641
    .line 642
    invoke-virtual {v3, v11}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 643
    .line 644
    .line 645
    move-result v3

    .line 646
    if-eqz v3, :cond_1f

    .line 647
    .line 648
    const-string v3, "mha-l29"

    .line 649
    .line 650
    invoke-virtual {v3, v12}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 651
    .line 652
    .line 653
    move-result v3

    .line 654
    if-eqz v3, :cond_1f

    .line 655
    .line 656
    const/4 v3, 0x1

    .line 657
    goto :goto_b

    .line 658
    :cond_1f
    move v3, v9

    .line 659
    :goto_b
    const-class v5, Landroidx/camera/camera2/internal/compat/quirk/RepeatingStreamConstraintForVideoRecordingQuirk;

    .line 660
    .line 661
    invoke-virtual {v0, v5, v3}, Lh0/q1;->a(Ljava/lang/Class;Z)Z

    .line 662
    .line 663
    .line 664
    move-result v3

    .line 665
    if-eqz v3, :cond_20

    .line 666
    .line 667
    new-instance v3, Landroidx/camera/camera2/internal/compat/quirk/RepeatingStreamConstraintForVideoRecordingQuirk;

    .line 668
    .line 669
    invoke-direct {v3}, Landroidx/camera/camera2/internal/compat/quirk/RepeatingStreamConstraintForVideoRecordingQuirk;-><init>()V

    .line 670
    .line 671
    .line 672
    invoke-virtual {v10, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 673
    .line 674
    .line 675
    :cond_20
    const-class v3, Landroidx/camera/camera2/internal/compat/quirk/TextureViewIsClosedQuirk;

    .line 676
    .line 677
    invoke-virtual {v0, v3, v9}, Lh0/q1;->a(Ljava/lang/Class;Z)Z

    .line 678
    .line 679
    .line 680
    move-result v3

    .line 681
    if-eqz v3, :cond_21

    .line 682
    .line 683
    new-instance v3, Landroidx/camera/camera2/internal/compat/quirk/TextureViewIsClosedQuirk;

    .line 684
    .line 685
    invoke-direct {v3}, Landroidx/camera/camera2/internal/compat/quirk/TextureViewIsClosedQuirk;-><init>()V

    .line 686
    .line 687
    .line 688
    invoke-virtual {v10, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 689
    .line 690
    .line 691
    :cond_21
    const-class v3, Landroidx/camera/camera2/internal/compat/quirk/CaptureSessionOnClosedNotCalledQuirk;

    .line 692
    .line 693
    invoke-virtual {v0, v3, v9}, Lh0/q1;->a(Ljava/lang/Class;Z)Z

    .line 694
    .line 695
    .line 696
    move-result v3

    .line 697
    if-eqz v3, :cond_22

    .line 698
    .line 699
    new-instance v3, Landroidx/camera/camera2/internal/compat/quirk/CaptureSessionOnClosedNotCalledQuirk;

    .line 700
    .line 701
    invoke-direct {v3}, Landroidx/camera/camera2/internal/compat/quirk/CaptureSessionOnClosedNotCalledQuirk;-><init>()V

    .line 702
    .line 703
    .line 704
    invoke-virtual {v10, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 705
    .line 706
    .line 707
    :cond_22
    sget-object v3, Landroidx/camera/camera2/internal/compat/quirk/TorchIsClosedAfterImageCapturingQuirk;->a:Ljava/util/List;

    .line 708
    .line 709
    invoke-virtual {v12, v8}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 710
    .line 711
    .line 712
    move-result-object v5

    .line 713
    invoke-interface {v3, v5}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 714
    .line 715
    .line 716
    move-result v3

    .line 717
    const-class v5, Landroidx/camera/camera2/internal/compat/quirk/TorchIsClosedAfterImageCapturingQuirk;

    .line 718
    .line 719
    invoke-virtual {v0, v5, v3}, Lh0/q1;->a(Ljava/lang/Class;Z)Z

    .line 720
    .line 721
    .line 722
    move-result v3

    .line 723
    if-eqz v3, :cond_23

    .line 724
    .line 725
    new-instance v3, Landroidx/camera/camera2/internal/compat/quirk/TorchIsClosedAfterImageCapturingQuirk;

    .line 726
    .line 727
    invoke-direct {v3}, Landroidx/camera/camera2/internal/compat/quirk/TorchIsClosedAfterImageCapturingQuirk;-><init>()V

    .line 728
    .line 729
    .line 730
    invoke-virtual {v10, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 731
    .line 732
    .line 733
    :cond_23
    sget-object v3, Landroidx/camera/camera2/internal/compat/quirk/ZslDisablerQuirk;->a:Ljava/util/List;

    .line 734
    .line 735
    const-string v3, "samsung"

    .line 736
    .line 737
    invoke-virtual {v3, v11}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 738
    .line 739
    .line 740
    move-result v5

    .line 741
    const-string v13, "xiaomi"

    .line 742
    .line 743
    if-eqz v5, :cond_24

    .line 744
    .line 745
    sget-object v5, Landroidx/camera/camera2/internal/compat/quirk/ZslDisablerQuirk;->a:Ljava/util/List;

    .line 746
    .line 747
    invoke-static {v5}, Landroidx/camera/camera2/internal/compat/quirk/ZslDisablerQuirk;->b(Ljava/util/List;)Z

    .line 748
    .line 749
    .line 750
    move-result v5

    .line 751
    if-eqz v5, :cond_24

    .line 752
    .line 753
    goto :goto_c

    .line 754
    :cond_24
    invoke-virtual {v13, v11}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 755
    .line 756
    .line 757
    move-result v5

    .line 758
    if-eqz v5, :cond_25

    .line 759
    .line 760
    sget-object v5, Landroidx/camera/camera2/internal/compat/quirk/ZslDisablerQuirk;->b:Ljava/util/List;

    .line 761
    .line 762
    invoke-static {v5}, Landroidx/camera/camera2/internal/compat/quirk/ZslDisablerQuirk;->b(Ljava/util/List;)Z

    .line 763
    .line 764
    .line 765
    move-result v5

    .line 766
    if-eqz v5, :cond_25

    .line 767
    .line 768
    :goto_c
    const/4 v5, 0x1

    .line 769
    goto :goto_d

    .line 770
    :cond_25
    move v5, v9

    .line 771
    :goto_d
    const-class v14, Landroidx/camera/camera2/internal/compat/quirk/ZslDisablerQuirk;

    .line 772
    .line 773
    invoke-virtual {v0, v14, v5}, Lh0/q1;->a(Ljava/lang/Class;Z)Z

    .line 774
    .line 775
    .line 776
    move-result v5

    .line 777
    if-eqz v5, :cond_26

    .line 778
    .line 779
    new-instance v5, Landroidx/camera/camera2/internal/compat/quirk/ZslDisablerQuirk;

    .line 780
    .line 781
    invoke-direct {v5}, Landroidx/camera/camera2/internal/compat/quirk/ZslDisablerQuirk;-><init>()V

    .line 782
    .line 783
    .line 784
    invoke-virtual {v10, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 785
    .line 786
    .line 787
    :cond_26
    invoke-virtual {v2, v11}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 788
    .line 789
    .line 790
    move-result v2

    .line 791
    if-eqz v2, :cond_27

    .line 792
    .line 793
    const-string v2, "moto e5 play"

    .line 794
    .line 795
    invoke-virtual {v2, v12}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 796
    .line 797
    .line 798
    move-result v2

    .line 799
    if-eqz v2, :cond_27

    .line 800
    .line 801
    const/4 v2, 0x1

    .line 802
    goto :goto_e

    .line 803
    :cond_27
    move v2, v9

    .line 804
    :goto_e
    const-class v5, Landroidx/camera/camera2/internal/compat/quirk/ExtraSupportedOutputSizeQuirk;

    .line 805
    .line 806
    invoke-virtual {v0, v5, v2}, Lh0/q1;->a(Ljava/lang/Class;Z)Z

    .line 807
    .line 808
    .line 809
    move-result v2

    .line 810
    if-eqz v2, :cond_28

    .line 811
    .line 812
    new-instance v2, Landroidx/camera/camera2/internal/compat/quirk/ExtraSupportedOutputSizeQuirk;

    .line 813
    .line 814
    invoke-direct {v2}, Landroidx/camera/camera2/internal/compat/quirk/ExtraSupportedOutputSizeQuirk;-><init>()V

    .line 815
    .line 816
    .line 817
    invoke-virtual {v10, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 818
    .line 819
    .line 820
    :cond_28
    sget-object v2, Landroidx/camera/camera2/internal/compat/quirk/InvalidVideoProfilesQuirk;->a:Ljava/util/List;

    .line 821
    .line 822
    invoke-virtual {v3, v11}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 823
    .line 824
    .line 825
    move-result v2

    .line 826
    const-string v3, "tp1a"

    .line 827
    .line 828
    if-eqz v2, :cond_29

    .line 829
    .line 830
    sget-object v2, Landroid/os/Build;->ID:Ljava/lang/String;

    .line 831
    .line 832
    sget-object v5, Ljava/util/Locale;->ROOT:Ljava/util/Locale;

    .line 833
    .line 834
    invoke-virtual {v2, v5}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 835
    .line 836
    .line 837
    move-result-object v2

    .line 838
    invoke-virtual {v2, v3}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    .line 839
    .line 840
    .line 841
    move-result v2

    .line 842
    if-eqz v2, :cond_29

    .line 843
    .line 844
    goto/16 :goto_11

    .line 845
    .line 846
    :cond_29
    sget-object v2, Landroidx/camera/camera2/internal/compat/quirk/InvalidVideoProfilesQuirk;->a:Ljava/util/List;

    .line 847
    .line 848
    sget-object v5, Ljava/util/Locale;->ROOT:Ljava/util/Locale;

    .line 849
    .line 850
    invoke-virtual {v12, v5}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 851
    .line 852
    .line 853
    move-result-object v14

    .line 854
    invoke-interface {v2, v14}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 855
    .line 856
    .line 857
    move-result v2

    .line 858
    if-eqz v2, :cond_2a

    .line 859
    .line 860
    sget-object v2, Landroid/os/Build;->ID:Ljava/lang/String;

    .line 861
    .line 862
    invoke-virtual {v2, v5}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 863
    .line 864
    .line 865
    move-result-object v14

    .line 866
    invoke-virtual {v14, v3}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    .line 867
    .line 868
    .line 869
    move-result v14

    .line 870
    if-nez v14, :cond_31

    .line 871
    .line 872
    invoke-virtual {v2, v5}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 873
    .line 874
    .line 875
    move-result-object v2

    .line 876
    const-string v14, "td1a"

    .line 877
    .line 878
    invoke-virtual {v2, v14}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    .line 879
    .line 880
    .line 881
    move-result v2

    .line 882
    if-eqz v2, :cond_2a

    .line 883
    .line 884
    goto :goto_11

    .line 885
    :cond_2a
    const-string v2, "redmi"

    .line 886
    .line 887
    invoke-virtual {v2, v11}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 888
    .line 889
    .line 890
    move-result v2

    .line 891
    if-nez v2, :cond_2b

    .line 892
    .line 893
    invoke-virtual {v13, v11}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 894
    .line 895
    .line 896
    move-result v2

    .line 897
    if-eqz v2, :cond_2c

    .line 898
    .line 899
    :cond_2b
    sget-object v2, Landroid/os/Build;->ID:Ljava/lang/String;

    .line 900
    .line 901
    invoke-virtual {v2, v5}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 902
    .line 903
    .line 904
    move-result-object v13

    .line 905
    const-string v14, "tkq1"

    .line 906
    .line 907
    invoke-virtual {v13, v14}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    .line 908
    .line 909
    .line 910
    move-result v13

    .line 911
    if-nez v13, :cond_31

    .line 912
    .line 913
    invoke-virtual {v2, v5}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 914
    .line 915
    .line 916
    move-result-object v2

    .line 917
    invoke-virtual {v2, v3}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    .line 918
    .line 919
    .line 920
    move-result v2

    .line 921
    if-eqz v2, :cond_2c

    .line 922
    .line 923
    goto :goto_11

    .line 924
    :cond_2c
    sget-object v2, Landroidx/camera/camera2/internal/compat/quirk/InvalidVideoProfilesQuirk;->b:Ljava/util/List;

    .line 925
    .line 926
    invoke-virtual {v12, v5}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 927
    .line 928
    .line 929
    move-result-object v3

    .line 930
    invoke-interface {v2, v3}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 931
    .line 932
    .line 933
    move-result v2

    .line 934
    if-eqz v2, :cond_2e

    .line 935
    .line 936
    sget v2, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 937
    .line 938
    if-ne v2, v6, :cond_2d

    .line 939
    .line 940
    const/4 v2, 0x1

    .line 941
    goto :goto_f

    .line 942
    :cond_2d
    move v2, v9

    .line 943
    :goto_f
    if-eqz v2, :cond_2e

    .line 944
    .line 945
    goto :goto_11

    .line 946
    :cond_2e
    sget-object v2, Landroidx/camera/camera2/internal/compat/quirk/InvalidVideoProfilesQuirk;->c:Ljava/util/List;

    .line 947
    .line 948
    invoke-virtual {v12, v5}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 949
    .line 950
    .line 951
    move-result-object v3

    .line 952
    invoke-interface {v2, v3}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 953
    .line 954
    .line 955
    move-result v2

    .line 956
    if-eqz v2, :cond_30

    .line 957
    .line 958
    sget v2, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 959
    .line 960
    if-ne v2, v6, :cond_2f

    .line 961
    .line 962
    const/4 v2, 0x1

    .line 963
    goto :goto_10

    .line 964
    :cond_2f
    move v2, v9

    .line 965
    :goto_10
    if-eqz v2, :cond_30

    .line 966
    .line 967
    goto :goto_11

    .line 968
    :cond_30
    move v2, v9

    .line 969
    goto :goto_12

    .line 970
    :cond_31
    :goto_11
    const/4 v2, 0x1

    .line 971
    :goto_12
    const-class v3, Landroidx/camera/camera2/internal/compat/quirk/InvalidVideoProfilesQuirk;

    .line 972
    .line 973
    invoke-virtual {v0, v3, v2}, Lh0/q1;->a(Ljava/lang/Class;Z)Z

    .line 974
    .line 975
    .line 976
    move-result v2

    .line 977
    if-eqz v2, :cond_32

    .line 978
    .line 979
    new-instance v2, Landroidx/camera/camera2/internal/compat/quirk/InvalidVideoProfilesQuirk;

    .line 980
    .line 981
    invoke-direct {v2}, Landroidx/camera/camera2/internal/compat/quirk/InvalidVideoProfilesQuirk;-><init>()V

    .line 982
    .line 983
    .line 984
    invoke-virtual {v10, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 985
    .line 986
    .line 987
    :cond_32
    const-string v2, "samsungexynos7870"

    .line 988
    .line 989
    sget-object v3, Landroid/os/Build;->HARDWARE:Ljava/lang/String;

    .line 990
    .line 991
    invoke-virtual {v2, v3}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 992
    .line 993
    .line 994
    move-result v2

    .line 995
    const-class v3, Landroidx/camera/camera2/internal/compat/quirk/Preview3AThreadCrashQuirk;

    .line 996
    .line 997
    invoke-virtual {v0, v3, v2}, Lh0/q1;->a(Ljava/lang/Class;Z)Z

    .line 998
    .line 999
    .line 1000
    move-result v2

    .line 1001
    if-eqz v2, :cond_33

    .line 1002
    .line 1003
    new-instance v2, Landroidx/camera/camera2/internal/compat/quirk/Preview3AThreadCrashQuirk;

    .line 1004
    .line 1005
    invoke-direct {v2}, Landroidx/camera/camera2/internal/compat/quirk/Preview3AThreadCrashQuirk;-><init>()V

    .line 1006
    .line 1007
    .line 1008
    invoke-virtual {v10, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1009
    .line 1010
    .line 1011
    :cond_33
    sget-object v2, Landroidx/camera/camera2/internal/compat/quirk/SmallDisplaySizeQuirk;->a:Ljava/util/HashMap;

    .line 1012
    .line 1013
    invoke-virtual {v12, v8}, Ljava/lang/String;->toUpperCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 1014
    .line 1015
    .line 1016
    move-result-object v3

    .line 1017
    invoke-virtual {v2, v3}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    .line 1018
    .line 1019
    .line 1020
    move-result v2

    .line 1021
    const-class v3, Landroidx/camera/camera2/internal/compat/quirk/SmallDisplaySizeQuirk;

    .line 1022
    .line 1023
    invoke-virtual {v0, v3, v2}, Lh0/q1;->a(Ljava/lang/Class;Z)Z

    .line 1024
    .line 1025
    .line 1026
    move-result v2

    .line 1027
    if-eqz v2, :cond_34

    .line 1028
    .line 1029
    new-instance v2, Landroidx/camera/camera2/internal/compat/quirk/SmallDisplaySizeQuirk;

    .line 1030
    .line 1031
    invoke-direct {v2}, Landroidx/camera/camera2/internal/compat/quirk/SmallDisplaySizeQuirk;-><init>()V

    .line 1032
    .line 1033
    .line 1034
    invoke-virtual {v10, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1035
    .line 1036
    .line 1037
    :cond_34
    const-class v2, Landroidx/camera/camera2/internal/compat/quirk/PreviewUnderExposureQuirk;

    .line 1038
    .line 1039
    sget-boolean v3, Landroidx/camera/camera2/internal/compat/quirk/PreviewUnderExposureQuirk;->b:Z

    .line 1040
    .line 1041
    invoke-virtual {v0, v2, v3}, Lh0/q1;->a(Ljava/lang/Class;Z)Z

    .line 1042
    .line 1043
    .line 1044
    move-result v2

    .line 1045
    if-eqz v2, :cond_35

    .line 1046
    .line 1047
    sget-object v2, Landroidx/camera/camera2/internal/compat/quirk/PreviewUnderExposureQuirk;->a:Landroidx/camera/camera2/internal/compat/quirk/PreviewUnderExposureQuirk;

    .line 1048
    .line 1049
    invoke-virtual {v10, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1050
    .line 1051
    .line 1052
    :cond_35
    invoke-virtual {v4, v11}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 1053
    .line 1054
    .line 1055
    move-result v2

    .line 1056
    if-eqz v2, :cond_36

    .line 1057
    .line 1058
    sget v2, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 1059
    .line 1060
    const/16 v3, 0x23

    .line 1061
    .line 1062
    if-lt v2, v3, :cond_36

    .line 1063
    .line 1064
    const/4 v8, 0x1

    .line 1065
    goto :goto_13

    .line 1066
    :cond_36
    move v8, v9

    .line 1067
    :goto_13
    const-class v2, Landroidx/camera/camera2/internal/compat/quirk/CaptureSessionShouldUseMrirQuirk;

    .line 1068
    .line 1069
    invoke-virtual {v0, v2, v8}, Lh0/q1;->a(Ljava/lang/Class;Z)Z

    .line 1070
    .line 1071
    .line 1072
    move-result v0

    .line 1073
    if-eqz v0, :cond_37

    .line 1074
    .line 1075
    new-instance v0, Landroidx/camera/camera2/internal/compat/quirk/CaptureSessionShouldUseMrirQuirk;

    .line 1076
    .line 1077
    invoke-direct {v0}, Landroidx/camera/camera2/internal/compat/quirk/CaptureSessionShouldUseMrirQuirk;-><init>()V

    .line 1078
    .line 1079
    .line 1080
    invoke-virtual {v10, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1081
    .line 1082
    .line 1083
    :cond_37
    invoke-direct {v1, v10}, Ld01/x;-><init>(Ljava/util/List;)V

    .line 1084
    .line 1085
    .line 1086
    sput-object v1, Lx/a;->a:Ld01/x;

    .line 1087
    .line 1088
    new-instance v0, Ljava/lang/StringBuilder;

    .line 1089
    .line 1090
    const-string v1, "camera2 DeviceQuirks = "

    .line 1091
    .line 1092
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 1093
    .line 1094
    .line 1095
    sget-object v1, Lx/a;->a:Ld01/x;

    .line 1096
    .line 1097
    invoke-static {v1}, Ld01/x;->p(Ld01/x;)Ljava/lang/String;

    .line 1098
    .line 1099
    .line 1100
    move-result-object v1

    .line 1101
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1102
    .line 1103
    .line 1104
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1105
    .line 1106
    .line 1107
    move-result-object v0

    .line 1108
    invoke-static {v7, v0}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 1109
    .line 1110
    .line 1111
    return-void

    .line 1112
    :pswitch_1
    move-object/from16 v0, p1

    .line 1113
    .line 1114
    check-cast v0, Lh0/q1;

    .line 1115
    .line 1116
    new-instance v1, Ld01/x;

    .line 1117
    .line 1118
    new-instance v5, Ljava/util/ArrayList;

    .line 1119
    .line 1120
    invoke-direct {v5}, Ljava/util/ArrayList;-><init>()V

    .line 1121
    .line 1122
    .line 1123
    sget-object v6, Landroid/os/Build;->BRAND:Ljava/lang/String;

    .line 1124
    .line 1125
    invoke-virtual {v3, v6}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 1126
    .line 1127
    .line 1128
    move-result v3

    .line 1129
    if-eqz v3, :cond_38

    .line 1130
    .line 1131
    const-string v3, "SNE-LX1"

    .line 1132
    .line 1133
    sget-object v8, Landroid/os/Build;->MODEL:Ljava/lang/String;

    .line 1134
    .line 1135
    invoke-virtual {v3, v8}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 1136
    .line 1137
    .line 1138
    move-result v3

    .line 1139
    if-eqz v3, :cond_38

    .line 1140
    .line 1141
    goto :goto_14

    .line 1142
    :cond_38
    const-string v3, "HONOR"

    .line 1143
    .line 1144
    invoke-virtual {v3, v6}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 1145
    .line 1146
    .line 1147
    move-result v3

    .line 1148
    if-eqz v3, :cond_39

    .line 1149
    .line 1150
    const-string v3, "STK-LX1"

    .line 1151
    .line 1152
    sget-object v8, Landroid/os/Build;->MODEL:Ljava/lang/String;

    .line 1153
    .line 1154
    invoke-virtual {v3, v8}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 1155
    .line 1156
    .line 1157
    move-result v3

    .line 1158
    if-eqz v3, :cond_39

    .line 1159
    .line 1160
    :goto_14
    const/4 v3, 0x1

    .line 1161
    goto :goto_15

    .line 1162
    :cond_39
    sget-object v3, Landroid/os/Build;->FINGERPRINT:Ljava/lang/String;

    .line 1163
    .line 1164
    const-string v8, "generic"

    .line 1165
    .line 1166
    invoke-virtual {v3, v8}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    .line 1167
    .line 1168
    .line 1169
    move-result v10

    .line 1170
    if-nez v10, :cond_3b

    .line 1171
    .line 1172
    const-string v10, "unknown"

    .line 1173
    .line 1174
    invoke-virtual {v3, v10}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    .line 1175
    .line 1176
    .line 1177
    move-result v3

    .line 1178
    if-nez v3, :cond_3b

    .line 1179
    .line 1180
    sget-object v3, Landroid/os/Build;->MODEL:Ljava/lang/String;

    .line 1181
    .line 1182
    const-string v10, "google_sdk"

    .line 1183
    .line 1184
    invoke-virtual {v3, v10}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    .line 1185
    .line 1186
    .line 1187
    move-result v11

    .line 1188
    if-nez v11, :cond_3b

    .line 1189
    .line 1190
    const-string v11, "Emulator"

    .line 1191
    .line 1192
    invoke-virtual {v3, v11}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    .line 1193
    .line 1194
    .line 1195
    move-result v11

    .line 1196
    if-nez v11, :cond_3b

    .line 1197
    .line 1198
    const-string v11, "Cuttlefish"

    .line 1199
    .line 1200
    invoke-virtual {v3, v11}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    .line 1201
    .line 1202
    .line 1203
    move-result v11

    .line 1204
    if-nez v11, :cond_3b

    .line 1205
    .line 1206
    const-string v11, "Android SDK built for x86"

    .line 1207
    .line 1208
    invoke-virtual {v3, v11}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    .line 1209
    .line 1210
    .line 1211
    move-result v3

    .line 1212
    if-nez v3, :cond_3b

    .line 1213
    .line 1214
    sget-object v3, Landroid/os/Build;->MANUFACTURER:Ljava/lang/String;

    .line 1215
    .line 1216
    const-string v11, "Genymotion"

    .line 1217
    .line 1218
    invoke-virtual {v3, v11}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    .line 1219
    .line 1220
    .line 1221
    move-result v3

    .line 1222
    if-nez v3, :cond_3b

    .line 1223
    .line 1224
    invoke-virtual {v6, v8}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    .line 1225
    .line 1226
    .line 1227
    move-result v3

    .line 1228
    if-eqz v3, :cond_3a

    .line 1229
    .line 1230
    sget-object v3, Landroid/os/Build;->DEVICE:Ljava/lang/String;

    .line 1231
    .line 1232
    invoke-virtual {v3, v8}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    .line 1233
    .line 1234
    .line 1235
    move-result v3

    .line 1236
    if-nez v3, :cond_3b

    .line 1237
    .line 1238
    :cond_3a
    sget-object v3, Landroid/os/Build;->PRODUCT:Ljava/lang/String;

    .line 1239
    .line 1240
    invoke-virtual {v3, v10}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1241
    .line 1242
    .line 1243
    move-result v3

    .line 1244
    if-nez v3, :cond_3b

    .line 1245
    .line 1246
    sget-object v3, Landroid/os/Build;->HARDWARE:Ljava/lang/String;

    .line 1247
    .line 1248
    const-string v8, "ranchu"

    .line 1249
    .line 1250
    invoke-virtual {v3, v8}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    .line 1251
    .line 1252
    .line 1253
    :cond_3b
    move v3, v9

    .line 1254
    :goto_15
    const-class v8, Landroidx/camera/core/internal/compat/quirk/ImageCaptureRotationOptionQuirk;

    .line 1255
    .line 1256
    invoke-virtual {v0, v8, v3}, Lh0/q1;->a(Ljava/lang/Class;Z)Z

    .line 1257
    .line 1258
    .line 1259
    move-result v3

    .line 1260
    if-eqz v3, :cond_3c

    .line 1261
    .line 1262
    new-instance v3, Landroidx/camera/core/internal/compat/quirk/ImageCaptureRotationOptionQuirk;

    .line 1263
    .line 1264
    invoke-direct {v3}, Landroidx/camera/core/internal/compat/quirk/ImageCaptureRotationOptionQuirk;-><init>()V

    .line 1265
    .line 1266
    .line 1267
    invoke-virtual {v5, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1268
    .line 1269
    .line 1270
    :cond_3c
    const-class v3, Landroidx/camera/core/internal/compat/quirk/SurfaceOrderQuirk;

    .line 1271
    .line 1272
    const/4 v8, 0x1

    .line 1273
    invoke-virtual {v0, v3, v8}, Lh0/q1;->a(Ljava/lang/Class;Z)Z

    .line 1274
    .line 1275
    .line 1276
    move-result v3

    .line 1277
    if-eqz v3, :cond_3d

    .line 1278
    .line 1279
    new-instance v3, Landroidx/camera/core/internal/compat/quirk/SurfaceOrderQuirk;

    .line 1280
    .line 1281
    invoke-direct {v3}, Landroidx/camera/core/internal/compat/quirk/SurfaceOrderQuirk;-><init>()V

    .line 1282
    .line 1283
    .line 1284
    invoke-virtual {v5, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1285
    .line 1286
    .line 1287
    :cond_3d
    sget-object v3, Landroidx/camera/core/internal/compat/quirk/CaptureFailedRetryQuirk;->a:Ljava/util/HashSet;

    .line 1288
    .line 1289
    sget-object v3, Ljava/util/Locale;->US:Ljava/util/Locale;

    .line 1290
    .line 1291
    invoke-virtual {v6, v3}, Ljava/lang/String;->toUpperCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 1292
    .line 1293
    .line 1294
    move-result-object v10

    .line 1295
    sget-object v11, Landroid/os/Build;->MODEL:Ljava/lang/String;

    .line 1296
    .line 1297
    invoke-virtual {v11, v3}, Ljava/lang/String;->toUpperCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 1298
    .line 1299
    .line 1300
    move-result-object v12

    .line 1301
    sget-object v13, Landroidx/camera/core/internal/compat/quirk/CaptureFailedRetryQuirk;->a:Ljava/util/HashSet;

    .line 1302
    .line 1303
    invoke-static {v10, v12}, Landroid/util/Pair;->create(Ljava/lang/Object;Ljava/lang/Object;)Landroid/util/Pair;

    .line 1304
    .line 1305
    .line 1306
    move-result-object v10

    .line 1307
    invoke-virtual {v13, v10}, Ljava/util/HashSet;->contains(Ljava/lang/Object;)Z

    .line 1308
    .line 1309
    .line 1310
    move-result v10

    .line 1311
    const-class v12, Landroidx/camera/core/internal/compat/quirk/CaptureFailedRetryQuirk;

    .line 1312
    .line 1313
    invoke-virtual {v0, v12, v10}, Lh0/q1;->a(Ljava/lang/Class;Z)Z

    .line 1314
    .line 1315
    .line 1316
    move-result v10

    .line 1317
    if-eqz v10, :cond_3e

    .line 1318
    .line 1319
    new-instance v10, Landroidx/camera/core/internal/compat/quirk/CaptureFailedRetryQuirk;

    .line 1320
    .line 1321
    invoke-direct {v10}, Landroidx/camera/core/internal/compat/quirk/CaptureFailedRetryQuirk;-><init>()V

    .line 1322
    .line 1323
    .line 1324
    invoke-virtual {v5, v10}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1325
    .line 1326
    .line 1327
    :cond_3e
    sget-object v10, Landroidx/camera/core/internal/compat/quirk/LowMemoryQuirk;->a:Ljava/util/HashSet;

    .line 1328
    .line 1329
    invoke-virtual {v11, v3}, Ljava/lang/String;->toUpperCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 1330
    .line 1331
    .line 1332
    move-result-object v12

    .line 1333
    invoke-virtual {v10, v12}, Ljava/util/HashSet;->contains(Ljava/lang/Object;)Z

    .line 1334
    .line 1335
    .line 1336
    move-result v10

    .line 1337
    const-class v12, Landroidx/camera/core/internal/compat/quirk/LowMemoryQuirk;

    .line 1338
    .line 1339
    invoke-virtual {v0, v12, v10}, Lh0/q1;->a(Ljava/lang/Class;Z)Z

    .line 1340
    .line 1341
    .line 1342
    move-result v10

    .line 1343
    if-eqz v10, :cond_3f

    .line 1344
    .line 1345
    new-instance v10, Landroidx/camera/core/internal/compat/quirk/LowMemoryQuirk;

    .line 1346
    .line 1347
    invoke-direct {v10}, Landroidx/camera/core/internal/compat/quirk/LowMemoryQuirk;-><init>()V

    .line 1348
    .line 1349
    .line 1350
    invoke-virtual {v5, v10}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1351
    .line 1352
    .line 1353
    :cond_3f
    sget-object v10, Landroidx/camera/core/internal/compat/quirk/LargeJpegImageQuirk;->a:Ljava/util/HashSet;

    .line 1354
    .line 1355
    const-string v10, "Samsung"

    .line 1356
    .line 1357
    invoke-virtual {v10, v6}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 1358
    .line 1359
    .line 1360
    move-result v12

    .line 1361
    if-nez v12, :cond_41

    .line 1362
    .line 1363
    const-string v12, "Vivo"

    .line 1364
    .line 1365
    invoke-virtual {v12, v6}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 1366
    .line 1367
    .line 1368
    move-result v12

    .line 1369
    if-eqz v12, :cond_40

    .line 1370
    .line 1371
    sget-object v12, Landroidx/camera/core/internal/compat/quirk/LargeJpegImageQuirk;->a:Ljava/util/HashSet;

    .line 1372
    .line 1373
    invoke-virtual {v11, v3}, Ljava/lang/String;->toUpperCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 1374
    .line 1375
    .line 1376
    move-result-object v13

    .line 1377
    invoke-virtual {v12, v13}, Ljava/util/HashSet;->contains(Ljava/lang/Object;)Z

    .line 1378
    .line 1379
    .line 1380
    move-result v12

    .line 1381
    if-eqz v12, :cond_40

    .line 1382
    .line 1383
    goto :goto_16

    .line 1384
    :cond_40
    move v12, v9

    .line 1385
    goto :goto_17

    .line 1386
    :cond_41
    :goto_16
    move v12, v8

    .line 1387
    :goto_17
    const-class v13, Landroidx/camera/core/internal/compat/quirk/LargeJpegImageQuirk;

    .line 1388
    .line 1389
    invoke-virtual {v0, v13, v12}, Lh0/q1;->a(Ljava/lang/Class;Z)Z

    .line 1390
    .line 1391
    .line 1392
    move-result v12

    .line 1393
    if-eqz v12, :cond_42

    .line 1394
    .line 1395
    new-instance v12, Landroidx/camera/core/internal/compat/quirk/LargeJpegImageQuirk;

    .line 1396
    .line 1397
    invoke-direct {v12}, Landroidx/camera/core/internal/compat/quirk/LargeJpegImageQuirk;-><init>()V

    .line 1398
    .line 1399
    .line 1400
    invoke-virtual {v5, v12}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1401
    .line 1402
    .line 1403
    :cond_42
    sget-object v12, Landroidx/camera/core/internal/compat/quirk/IncorrectJpegMetadataQuirk;->a:Ljava/util/HashSet;

    .line 1404
    .line 1405
    invoke-virtual {v10, v6}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 1406
    .line 1407
    .line 1408
    move-result v10

    .line 1409
    if-eqz v10, :cond_43

    .line 1410
    .line 1411
    sget-object v10, Landroidx/camera/core/internal/compat/quirk/IncorrectJpegMetadataQuirk;->a:Ljava/util/HashSet;

    .line 1412
    .line 1413
    sget-object v12, Landroid/os/Build;->DEVICE:Ljava/lang/String;

    .line 1414
    .line 1415
    invoke-virtual {v12, v3}, Ljava/lang/String;->toUpperCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 1416
    .line 1417
    .line 1418
    move-result-object v3

    .line 1419
    invoke-virtual {v10, v3}, Ljava/util/HashSet;->contains(Ljava/lang/Object;)Z

    .line 1420
    .line 1421
    .line 1422
    move-result v3

    .line 1423
    if-eqz v3, :cond_43

    .line 1424
    .line 1425
    move v3, v8

    .line 1426
    goto :goto_18

    .line 1427
    :cond_43
    move v3, v9

    .line 1428
    :goto_18
    const-class v10, Landroidx/camera/core/internal/compat/quirk/IncorrectJpegMetadataQuirk;

    .line 1429
    .line 1430
    invoke-virtual {v0, v10, v3}, Lh0/q1;->a(Ljava/lang/Class;Z)Z

    .line 1431
    .line 1432
    .line 1433
    move-result v3

    .line 1434
    if-eqz v3, :cond_44

    .line 1435
    .line 1436
    new-instance v3, Landroidx/camera/core/internal/compat/quirk/IncorrectJpegMetadataQuirk;

    .line 1437
    .line 1438
    invoke-direct {v3}, Landroidx/camera/core/internal/compat/quirk/IncorrectJpegMetadataQuirk;-><init>()V

    .line 1439
    .line 1440
    .line 1441
    invoke-virtual {v5, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1442
    .line 1443
    .line 1444
    :cond_44
    sget-object v3, Landroidx/camera/core/internal/compat/quirk/ImageCaptureFailedForSpecificCombinationQuirk;->a:Ljava/util/HashSet;

    .line 1445
    .line 1446
    const-string v3, "oneplus"

    .line 1447
    .line 1448
    invoke-virtual {v3, v6}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 1449
    .line 1450
    .line 1451
    move-result v3

    .line 1452
    if-eqz v3, :cond_45

    .line 1453
    .line 1454
    const-string v3, "cph2583"

    .line 1455
    .line 1456
    invoke-virtual {v3, v11}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 1457
    .line 1458
    .line 1459
    move-result v3

    .line 1460
    if-eqz v3, :cond_45

    .line 1461
    .line 1462
    goto :goto_19

    .line 1463
    :cond_45
    invoke-virtual {v4, v6}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 1464
    .line 1465
    .line 1466
    move-result v3

    .line 1467
    if-eqz v3, :cond_46

    .line 1468
    .line 1469
    sget-object v3, Landroidx/camera/core/internal/compat/quirk/ImageCaptureFailedForSpecificCombinationQuirk;->a:Ljava/util/HashSet;

    .line 1470
    .line 1471
    invoke-virtual {v11}, Ljava/lang/String;->toLowerCase()Ljava/lang/String;

    .line 1472
    .line 1473
    .line 1474
    move-result-object v4

    .line 1475
    invoke-virtual {v3, v4}, Ljava/util/HashSet;->contains(Ljava/lang/Object;)Z

    .line 1476
    .line 1477
    .line 1478
    move-result v3

    .line 1479
    if-eqz v3, :cond_46

    .line 1480
    .line 1481
    :goto_19
    move v3, v8

    .line 1482
    goto :goto_1a

    .line 1483
    :cond_46
    move v3, v9

    .line 1484
    :goto_1a
    const-class v4, Landroidx/camera/core/internal/compat/quirk/ImageCaptureFailedForSpecificCombinationQuirk;

    .line 1485
    .line 1486
    invoke-virtual {v0, v4, v3}, Lh0/q1;->a(Ljava/lang/Class;Z)Z

    .line 1487
    .line 1488
    .line 1489
    move-result v3

    .line 1490
    if-eqz v3, :cond_47

    .line 1491
    .line 1492
    new-instance v3, Landroidx/camera/core/internal/compat/quirk/ImageCaptureFailedForSpecificCombinationQuirk;

    .line 1493
    .line 1494
    invoke-direct {v3}, Landroidx/camera/core/internal/compat/quirk/ImageCaptureFailedForSpecificCombinationQuirk;-><init>()V

    .line 1495
    .line 1496
    .line 1497
    invoke-virtual {v5, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1498
    .line 1499
    .line 1500
    :cond_47
    sget-object v3, Landroidx/camera/core/internal/compat/quirk/PreviewGreenTintQuirk;->a:Landroidx/camera/core/internal/compat/quirk/PreviewGreenTintQuirk;

    .line 1501
    .line 1502
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1503
    .line 1504
    .line 1505
    invoke-virtual {v2, v6}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 1506
    .line 1507
    .line 1508
    move-result v2

    .line 1509
    if-eqz v2, :cond_48

    .line 1510
    .line 1511
    const-string v2, "moto e20"

    .line 1512
    .line 1513
    invoke-virtual {v2, v11}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 1514
    .line 1515
    .line 1516
    move-result v2

    .line 1517
    if-eqz v2, :cond_48

    .line 1518
    .line 1519
    goto :goto_1b

    .line 1520
    :cond_48
    move v8, v9

    .line 1521
    :goto_1b
    const-class v2, Landroidx/camera/core/internal/compat/quirk/PreviewGreenTintQuirk;

    .line 1522
    .line 1523
    invoke-virtual {v0, v2, v8}, Lh0/q1;->a(Ljava/lang/Class;Z)Z

    .line 1524
    .line 1525
    .line 1526
    move-result v0

    .line 1527
    if-eqz v0, :cond_49

    .line 1528
    .line 1529
    invoke-virtual {v5, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1530
    .line 1531
    .line 1532
    :cond_49
    invoke-direct {v1, v5}, Ld01/x;-><init>(Ljava/util/List;)V

    .line 1533
    .line 1534
    .line 1535
    sput-object v1, Lm0/a;->a:Ld01/x;

    .line 1536
    .line 1537
    new-instance v0, Ljava/lang/StringBuilder;

    .line 1538
    .line 1539
    const-string v1, "core DeviceQuirks = "

    .line 1540
    .line 1541
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 1542
    .line 1543
    .line 1544
    sget-object v1, Lm0/a;->a:Ld01/x;

    .line 1545
    .line 1546
    invoke-static {v1}, Ld01/x;->p(Ld01/x;)Ljava/lang/String;

    .line 1547
    .line 1548
    .line 1549
    move-result-object v1

    .line 1550
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1551
    .line 1552
    .line 1553
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1554
    .line 1555
    .line 1556
    move-result-object v0

    .line 1557
    invoke-static {v7, v0}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 1558
    .line 1559
    .line 1560
    return-void

    .line 1561
    :pswitch_2
    if-nez p1, :cond_4a

    .line 1562
    .line 1563
    invoke-static {}, Llp/k1;->a()V

    .line 1564
    .line 1565
    .line 1566
    throw v1

    .line 1567
    :cond_4a
    new-instance v0, Ljava/lang/ClassCastException;

    .line 1568
    .line 1569
    invoke-direct {v0}, Ljava/lang/ClassCastException;-><init>()V

    .line 1570
    .line 1571
    .line 1572
    throw v0

    .line 1573
    :pswitch_3
    if-nez p1, :cond_4b

    .line 1574
    .line 1575
    invoke-static {}, Llp/k1;->a()V

    .line 1576
    .line 1577
    .line 1578
    throw v1

    .line 1579
    :cond_4b
    new-instance v0, Ljava/lang/ClassCastException;

    .line 1580
    .line 1581
    invoke-direct {v0}, Ljava/lang/ClassCastException;-><init>()V

    .line 1582
    .line 1583
    .line 1584
    throw v0

    .line 1585
    :pswitch_4
    move-object/from16 v0, p1

    .line 1586
    .line 1587
    check-cast v0, Ljava/util/Set;

    .line 1588
    .line 1589
    return-void

    .line 1590
    nop

    .line 1591
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
