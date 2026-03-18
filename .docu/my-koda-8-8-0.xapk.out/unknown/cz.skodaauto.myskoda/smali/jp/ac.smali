.class public final enum Ljp/ac;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljp/j0;


# static fields
.field public static final enum e:Ljp/ac;

.field public static final enum f:Ljp/ac;

.field public static final enum g:Ljp/ac;

.field public static final enum h:Ljp/ac;

.field public static final enum i:Ljp/ac;

.field public static final synthetic j:[Ljp/ac;


# instance fields
.field public final d:I


# direct methods
.method static constructor <clinit>()V
    .locals 57

    .line 1
    new-instance v1, Ljp/ac;

    .line 2
    .line 3
    const-string v0, "NO_ERROR"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v1, v0, v2, v2}, Ljp/ac;-><init>(Ljava/lang/String;II)V

    .line 7
    .line 8
    .line 9
    sput-object v1, Ljp/ac;->e:Ljp/ac;

    .line 10
    .line 11
    new-instance v2, Ljp/ac;

    .line 12
    .line 13
    const-string v0, "INCOMPATIBLE_INPUT"

    .line 14
    .line 15
    const/4 v3, 0x1

    .line 16
    invoke-direct {v2, v0, v3, v3}, Ljp/ac;-><init>(Ljava/lang/String;II)V

    .line 17
    .line 18
    .line 19
    new-instance v3, Ljp/ac;

    .line 20
    .line 21
    const-string v0, "INCOMPATIBLE_OUTPUT"

    .line 22
    .line 23
    const/4 v4, 0x2

    .line 24
    invoke-direct {v3, v0, v4, v4}, Ljp/ac;-><init>(Ljava/lang/String;II)V

    .line 25
    .line 26
    .line 27
    new-instance v4, Ljp/ac;

    .line 28
    .line 29
    const-string v0, "INCOMPATIBLE_TFLITE_VERSION"

    .line 30
    .line 31
    const/4 v5, 0x3

    .line 32
    invoke-direct {v4, v0, v5, v5}, Ljp/ac;-><init>(Ljava/lang/String;II)V

    .line 33
    .line 34
    .line 35
    new-instance v5, Ljp/ac;

    .line 36
    .line 37
    const-string v0, "MISSING_OP"

    .line 38
    .line 39
    const/4 v6, 0x4

    .line 40
    invoke-direct {v5, v0, v6, v6}, Ljp/ac;-><init>(Ljava/lang/String;II)V

    .line 41
    .line 42
    .line 43
    new-instance v6, Ljp/ac;

    .line 44
    .line 45
    const-string v0, "DATA_TYPE_ERROR"

    .line 46
    .line 47
    const/4 v7, 0x5

    .line 48
    const/4 v8, 0x6

    .line 49
    invoke-direct {v6, v0, v7, v8}, Ljp/ac;-><init>(Ljava/lang/String;II)V

    .line 50
    .line 51
    .line 52
    new-instance v0, Ljp/ac;

    .line 53
    .line 54
    const-string v9, "TFLITE_INTERNAL_ERROR"

    .line 55
    .line 56
    const/4 v10, 0x7

    .line 57
    invoke-direct {v0, v9, v8, v10}, Ljp/ac;-><init>(Ljava/lang/String;II)V

    .line 58
    .line 59
    .line 60
    new-instance v8, Ljp/ac;

    .line 61
    .line 62
    const-string v9, "TFLITE_UNKNOWN_ERROR"

    .line 63
    .line 64
    const/16 v11, 0x8

    .line 65
    .line 66
    invoke-direct {v8, v9, v10, v11}, Ljp/ac;-><init>(Ljava/lang/String;II)V

    .line 67
    .line 68
    .line 69
    new-instance v9, Ljp/ac;

    .line 70
    .line 71
    const-string v10, "MEDIAPIPE_ERROR"

    .line 72
    .line 73
    const/16 v12, 0x9

    .line 74
    .line 75
    invoke-direct {v9, v10, v11, v12}, Ljp/ac;-><init>(Ljava/lang/String;II)V

    .line 76
    .line 77
    .line 78
    new-instance v10, Ljp/ac;

    .line 79
    .line 80
    const-string v11, "TIME_OUT_FETCHING_MODEL_METADATA"

    .line 81
    .line 82
    invoke-direct {v10, v11, v12, v7}, Ljp/ac;-><init>(Ljava/lang/String;II)V

    .line 83
    .line 84
    .line 85
    new-instance v11, Ljp/ac;

    .line 86
    .line 87
    const/16 v7, 0xa

    .line 88
    .line 89
    const/16 v12, 0x64

    .line 90
    .line 91
    const-string v13, "MODEL_NOT_DOWNLOADED"

    .line 92
    .line 93
    invoke-direct {v11, v13, v7, v12}, Ljp/ac;-><init>(Ljava/lang/String;II)V

    .line 94
    .line 95
    .line 96
    sput-object v11, Ljp/ac;->f:Ljp/ac;

    .line 97
    .line 98
    new-instance v12, Ljp/ac;

    .line 99
    .line 100
    const/16 v7, 0xb

    .line 101
    .line 102
    const/16 v13, 0x65

    .line 103
    .line 104
    const-string v14, "URI_EXPIRED"

    .line 105
    .line 106
    invoke-direct {v12, v14, v7, v13}, Ljp/ac;-><init>(Ljava/lang/String;II)V

    .line 107
    .line 108
    .line 109
    new-instance v13, Ljp/ac;

    .line 110
    .line 111
    const/16 v7, 0xc

    .line 112
    .line 113
    const/16 v14, 0x66

    .line 114
    .line 115
    const-string v15, "NO_NETWORK_CONNECTION"

    .line 116
    .line 117
    invoke-direct {v13, v15, v7, v14}, Ljp/ac;-><init>(Ljava/lang/String;II)V

    .line 118
    .line 119
    .line 120
    new-instance v14, Ljp/ac;

    .line 121
    .line 122
    const/16 v7, 0xd

    .line 123
    .line 124
    const/16 v15, 0x67

    .line 125
    .line 126
    move-object/from16 v16, v0

    .line 127
    .line 128
    const-string v0, "METERED_NETWORK"

    .line 129
    .line 130
    invoke-direct {v14, v0, v7, v15}, Ljp/ac;-><init>(Ljava/lang/String;II)V

    .line 131
    .line 132
    .line 133
    new-instance v15, Ljp/ac;

    .line 134
    .line 135
    const/16 v0, 0xe

    .line 136
    .line 137
    const/16 v7, 0x68

    .line 138
    .line 139
    move-object/from16 v17, v1

    .line 140
    .line 141
    const-string v1, "DOWNLOAD_FAILED"

    .line 142
    .line 143
    invoke-direct {v15, v1, v0, v7}, Ljp/ac;-><init>(Ljava/lang/String;II)V

    .line 144
    .line 145
    .line 146
    new-instance v0, Ljp/ac;

    .line 147
    .line 148
    const/16 v1, 0xf

    .line 149
    .line 150
    const/16 v7, 0x69

    .line 151
    .line 152
    move-object/from16 v18, v2

    .line 153
    .line 154
    const-string v2, "MODEL_INFO_DOWNLOAD_UNSUCCESSFUL_HTTP_STATUS"

    .line 155
    .line 156
    invoke-direct {v0, v2, v1, v7}, Ljp/ac;-><init>(Ljava/lang/String;II)V

    .line 157
    .line 158
    .line 159
    new-instance v1, Ljp/ac;

    .line 160
    .line 161
    const/16 v2, 0x10

    .line 162
    .line 163
    const/16 v7, 0x6a

    .line 164
    .line 165
    move-object/from16 v19, v0

    .line 166
    .line 167
    const-string v0, "MODEL_INFO_DOWNLOAD_NO_HASH"

    .line 168
    .line 169
    invoke-direct {v1, v0, v2, v7}, Ljp/ac;-><init>(Ljava/lang/String;II)V

    .line 170
    .line 171
    .line 172
    new-instance v0, Ljp/ac;

    .line 173
    .line 174
    const/16 v2, 0x11

    .line 175
    .line 176
    const/16 v7, 0x6b

    .line 177
    .line 178
    move-object/from16 v20, v1

    .line 179
    .line 180
    const-string v1, "MODEL_INFO_DOWNLOAD_CONNECTION_FAILED"

    .line 181
    .line 182
    invoke-direct {v0, v1, v2, v7}, Ljp/ac;-><init>(Ljava/lang/String;II)V

    .line 183
    .line 184
    .line 185
    new-instance v1, Ljp/ac;

    .line 186
    .line 187
    const/16 v2, 0x12

    .line 188
    .line 189
    const/16 v7, 0x6c

    .line 190
    .line 191
    move-object/from16 v21, v0

    .line 192
    .line 193
    const-string v0, "NO_VALID_MODEL"

    .line 194
    .line 195
    invoke-direct {v1, v0, v2, v7}, Ljp/ac;-><init>(Ljava/lang/String;II)V

    .line 196
    .line 197
    .line 198
    new-instance v0, Ljp/ac;

    .line 199
    .line 200
    const/16 v2, 0x13

    .line 201
    .line 202
    const/16 v7, 0x6d

    .line 203
    .line 204
    move-object/from16 v22, v1

    .line 205
    .line 206
    const-string v1, "LOCAL_MODEL_INVALID"

    .line 207
    .line 208
    invoke-direct {v0, v1, v2, v7}, Ljp/ac;-><init>(Ljava/lang/String;II)V

    .line 209
    .line 210
    .line 211
    new-instance v1, Ljp/ac;

    .line 212
    .line 213
    const/16 v2, 0x14

    .line 214
    .line 215
    const/16 v7, 0x6e

    .line 216
    .line 217
    move-object/from16 v23, v0

    .line 218
    .line 219
    const-string v0, "REMOTE_MODEL_INVALID"

    .line 220
    .line 221
    invoke-direct {v1, v0, v2, v7}, Ljp/ac;-><init>(Ljava/lang/String;II)V

    .line 222
    .line 223
    .line 224
    new-instance v0, Ljp/ac;

    .line 225
    .line 226
    const/16 v2, 0x15

    .line 227
    .line 228
    const/16 v7, 0x6f

    .line 229
    .line 230
    move-object/from16 v24, v1

    .line 231
    .line 232
    const-string v1, "REMOTE_MODEL_LOADER_ERROR"

    .line 233
    .line 234
    invoke-direct {v0, v1, v2, v7}, Ljp/ac;-><init>(Ljava/lang/String;II)V

    .line 235
    .line 236
    .line 237
    new-instance v1, Ljp/ac;

    .line 238
    .line 239
    const/16 v2, 0x16

    .line 240
    .line 241
    const/16 v7, 0x70

    .line 242
    .line 243
    move-object/from16 v25, v0

    .line 244
    .line 245
    const-string v0, "REMOTE_MODEL_LOADER_LOADS_NO_MODEL"

    .line 246
    .line 247
    invoke-direct {v1, v0, v2, v7}, Ljp/ac;-><init>(Ljava/lang/String;II)V

    .line 248
    .line 249
    .line 250
    new-instance v0, Ljp/ac;

    .line 251
    .line 252
    const/16 v2, 0x17

    .line 253
    .line 254
    const/16 v7, 0x71

    .line 255
    .line 256
    move-object/from16 v26, v1

    .line 257
    .line 258
    const-string v1, "SMART_REPLY_LANG_ID_DETECTAION_FAILURE"

    .line 259
    .line 260
    invoke-direct {v0, v1, v2, v7}, Ljp/ac;-><init>(Ljava/lang/String;II)V

    .line 261
    .line 262
    .line 263
    new-instance v1, Ljp/ac;

    .line 264
    .line 265
    const/16 v2, 0x18

    .line 266
    .line 267
    const/16 v7, 0x72

    .line 268
    .line 269
    move-object/from16 v27, v0

    .line 270
    .line 271
    const-string v0, "MODEL_NOT_REGISTERED"

    .line 272
    .line 273
    invoke-direct {v1, v0, v2, v7}, Ljp/ac;-><init>(Ljava/lang/String;II)V

    .line 274
    .line 275
    .line 276
    new-instance v0, Ljp/ac;

    .line 277
    .line 278
    const/16 v2, 0x19

    .line 279
    .line 280
    const/16 v7, 0x73

    .line 281
    .line 282
    move-object/from16 v28, v1

    .line 283
    .line 284
    const-string v1, "MODEL_TYPE_MISUSE"

    .line 285
    .line 286
    invoke-direct {v0, v1, v2, v7}, Ljp/ac;-><init>(Ljava/lang/String;II)V

    .line 287
    .line 288
    .line 289
    new-instance v1, Ljp/ac;

    .line 290
    .line 291
    const/16 v2, 0x1a

    .line 292
    .line 293
    const/16 v7, 0x74

    .line 294
    .line 295
    move-object/from16 v29, v0

    .line 296
    .line 297
    const-string v0, "MODEL_HASH_MISMATCH"

    .line 298
    .line 299
    invoke-direct {v1, v0, v2, v7}, Ljp/ac;-><init>(Ljava/lang/String;II)V

    .line 300
    .line 301
    .line 302
    new-instance v0, Ljp/ac;

    .line 303
    .line 304
    const/16 v2, 0x1b

    .line 305
    .line 306
    const/16 v7, 0xc9

    .line 307
    .line 308
    move-object/from16 v30, v1

    .line 309
    .line 310
    const-string v1, "OPTIONAL_MODULE_NOT_AVAILABLE"

    .line 311
    .line 312
    invoke-direct {v0, v1, v2, v7}, Ljp/ac;-><init>(Ljava/lang/String;II)V

    .line 313
    .line 314
    .line 315
    sput-object v0, Ljp/ac;->g:Ljp/ac;

    .line 316
    .line 317
    new-instance v1, Ljp/ac;

    .line 318
    .line 319
    const/16 v2, 0x1c

    .line 320
    .line 321
    const/16 v7, 0xca

    .line 322
    .line 323
    move-object/from16 v31, v0

    .line 324
    .line 325
    const-string v0, "OPTIONAL_MODULE_INIT_ERROR"

    .line 326
    .line 327
    invoke-direct {v1, v0, v2, v7}, Ljp/ac;-><init>(Ljava/lang/String;II)V

    .line 328
    .line 329
    .line 330
    sput-object v1, Ljp/ac;->h:Ljp/ac;

    .line 331
    .line 332
    new-instance v0, Ljp/ac;

    .line 333
    .line 334
    const/16 v2, 0x1d

    .line 335
    .line 336
    const/16 v7, 0xcb

    .line 337
    .line 338
    move-object/from16 v32, v1

    .line 339
    .line 340
    const-string v1, "OPTIONAL_MODULE_INFERENCE_ERROR"

    .line 341
    .line 342
    invoke-direct {v0, v1, v2, v7}, Ljp/ac;-><init>(Ljava/lang/String;II)V

    .line 343
    .line 344
    .line 345
    new-instance v1, Ljp/ac;

    .line 346
    .line 347
    const/16 v2, 0x1e

    .line 348
    .line 349
    const/16 v7, 0xcc

    .line 350
    .line 351
    move-object/from16 v33, v0

    .line 352
    .line 353
    const-string v0, "OPTIONAL_MODULE_RELEASE_ERROR"

    .line 354
    .line 355
    invoke-direct {v1, v0, v2, v7}, Ljp/ac;-><init>(Ljava/lang/String;II)V

    .line 356
    .line 357
    .line 358
    new-instance v0, Ljp/ac;

    .line 359
    .line 360
    const/16 v2, 0x1f

    .line 361
    .line 362
    const/16 v7, 0xcd

    .line 363
    .line 364
    move-object/from16 v34, v1

    .line 365
    .line 366
    const-string v1, "OPTIONAL_TFLITE_MODULE_INIT_ERROR"

    .line 367
    .line 368
    invoke-direct {v0, v1, v2, v7}, Ljp/ac;-><init>(Ljava/lang/String;II)V

    .line 369
    .line 370
    .line 371
    new-instance v1, Ljp/ac;

    .line 372
    .line 373
    const/16 v2, 0x20

    .line 374
    .line 375
    const/16 v7, 0xce

    .line 376
    .line 377
    move-object/from16 v35, v0

    .line 378
    .line 379
    const-string v0, "NATIVE_LIBRARY_LOAD_ERROR"

    .line 380
    .line 381
    invoke-direct {v1, v0, v2, v7}, Ljp/ac;-><init>(Ljava/lang/String;II)V

    .line 382
    .line 383
    .line 384
    new-instance v0, Ljp/ac;

    .line 385
    .line 386
    const/16 v2, 0x21

    .line 387
    .line 388
    const/16 v7, 0xcf

    .line 389
    .line 390
    move-object/from16 v36, v1

    .line 391
    .line 392
    const-string v1, "OPTIONAL_MODULE_CREATE_ERROR"

    .line 393
    .line 394
    invoke-direct {v0, v1, v2, v7}, Ljp/ac;-><init>(Ljava/lang/String;II)V

    .line 395
    .line 396
    .line 397
    new-instance v1, Ljp/ac;

    .line 398
    .line 399
    const/16 v2, 0x22

    .line 400
    .line 401
    const/16 v7, 0x12d

    .line 402
    .line 403
    move-object/from16 v37, v0

    .line 404
    .line 405
    const-string v0, "CAMERAX_SOURCE_ERROR"

    .line 406
    .line 407
    invoke-direct {v1, v0, v2, v7}, Ljp/ac;-><init>(Ljava/lang/String;II)V

    .line 408
    .line 409
    .line 410
    new-instance v0, Ljp/ac;

    .line 411
    .line 412
    const/16 v2, 0x23

    .line 413
    .line 414
    const/16 v7, 0x12e

    .line 415
    .line 416
    move-object/from16 v38, v1

    .line 417
    .line 418
    const-string v1, "CAMERA1_SOURCE_CANT_START_ERROR"

    .line 419
    .line 420
    invoke-direct {v0, v1, v2, v7}, Ljp/ac;-><init>(Ljava/lang/String;II)V

    .line 421
    .line 422
    .line 423
    new-instance v1, Ljp/ac;

    .line 424
    .line 425
    const/16 v2, 0x24

    .line 426
    .line 427
    const/16 v7, 0x12f

    .line 428
    .line 429
    move-object/from16 v39, v0

    .line 430
    .line 431
    const-string v0, "CAMERA1_SOURCE_NO_SUITABLE_SIZE_ERROR"

    .line 432
    .line 433
    invoke-direct {v1, v0, v2, v7}, Ljp/ac;-><init>(Ljava/lang/String;II)V

    .line 434
    .line 435
    .line 436
    new-instance v0, Ljp/ac;

    .line 437
    .line 438
    const/16 v2, 0x25

    .line 439
    .line 440
    const/16 v7, 0x130

    .line 441
    .line 442
    move-object/from16 v40, v1

    .line 443
    .line 444
    const-string v1, "CAMERA1_SOURCE_NO_SUITABLE_FPS_ERROR"

    .line 445
    .line 446
    invoke-direct {v0, v1, v2, v7}, Ljp/ac;-><init>(Ljava/lang/String;II)V

    .line 447
    .line 448
    .line 449
    new-instance v1, Ljp/ac;

    .line 450
    .line 451
    const/16 v2, 0x26

    .line 452
    .line 453
    const/16 v7, 0x131

    .line 454
    .line 455
    move-object/from16 v41, v0

    .line 456
    .line 457
    const-string v0, "CAMERA1_SOURCE_NO_BYTE_SOURCE_FOUND_ERROR"

    .line 458
    .line 459
    invoke-direct {v1, v0, v2, v7}, Ljp/ac;-><init>(Ljava/lang/String;II)V

    .line 460
    .line 461
    .line 462
    new-instance v0, Ljp/ac;

    .line 463
    .line 464
    const/16 v2, 0x27

    .line 465
    .line 466
    const/16 v7, 0x190

    .line 467
    .line 468
    move-object/from16 v42, v1

    .line 469
    .line 470
    const-string v1, "CODE_SCANNER_UNAVAILABLE"

    .line 471
    .line 472
    invoke-direct {v0, v1, v2, v7}, Ljp/ac;-><init>(Ljava/lang/String;II)V

    .line 473
    .line 474
    .line 475
    new-instance v1, Ljp/ac;

    .line 476
    .line 477
    const/16 v2, 0x28

    .line 478
    .line 479
    const/16 v7, 0x191

    .line 480
    .line 481
    move-object/from16 v43, v0

    .line 482
    .line 483
    const-string v0, "CODE_SCANNER_CANCELLED"

    .line 484
    .line 485
    invoke-direct {v1, v0, v2, v7}, Ljp/ac;-><init>(Ljava/lang/String;II)V

    .line 486
    .line 487
    .line 488
    new-instance v0, Ljp/ac;

    .line 489
    .line 490
    const/16 v2, 0x29

    .line 491
    .line 492
    const/16 v7, 0x192

    .line 493
    .line 494
    move-object/from16 v44, v1

    .line 495
    .line 496
    const-string v1, "CODE_SCANNER_CAMERA_PERMISSION_NOT_GRANTED"

    .line 497
    .line 498
    invoke-direct {v0, v1, v2, v7}, Ljp/ac;-><init>(Ljava/lang/String;II)V

    .line 499
    .line 500
    .line 501
    new-instance v1, Ljp/ac;

    .line 502
    .line 503
    const/16 v2, 0x2a

    .line 504
    .line 505
    const/16 v7, 0x193

    .line 506
    .line 507
    move-object/from16 v45, v0

    .line 508
    .line 509
    const-string v0, "CODE_SCANNER_APP_NAME_UNAVAILABLE"

    .line 510
    .line 511
    invoke-direct {v1, v0, v2, v7}, Ljp/ac;-><init>(Ljava/lang/String;II)V

    .line 512
    .line 513
    .line 514
    new-instance v0, Ljp/ac;

    .line 515
    .line 516
    const/16 v2, 0x2b

    .line 517
    .line 518
    const/16 v7, 0x194

    .line 519
    .line 520
    move-object/from16 v46, v1

    .line 521
    .line 522
    const-string v1, "CODE_SCANNER_TASK_IN_PROGRESS"

    .line 523
    .line 524
    invoke-direct {v0, v1, v2, v7}, Ljp/ac;-><init>(Ljava/lang/String;II)V

    .line 525
    .line 526
    .line 527
    new-instance v1, Ljp/ac;

    .line 528
    .line 529
    const/16 v2, 0x2c

    .line 530
    .line 531
    const/16 v7, 0x195

    .line 532
    .line 533
    move-object/from16 v47, v0

    .line 534
    .line 535
    const-string v0, "CODE_SCANNER_PIPELINE_INITIALIZATION_ERROR"

    .line 536
    .line 537
    invoke-direct {v1, v0, v2, v7}, Ljp/ac;-><init>(Ljava/lang/String;II)V

    .line 538
    .line 539
    .line 540
    new-instance v0, Ljp/ac;

    .line 541
    .line 542
    const/16 v2, 0x2d

    .line 543
    .line 544
    const/16 v7, 0x196

    .line 545
    .line 546
    move-object/from16 v48, v1

    .line 547
    .line 548
    const-string v1, "CODE_SCANNER_PIPELINE_INFERENCE_ERROR"

    .line 549
    .line 550
    invoke-direct {v0, v1, v2, v7}, Ljp/ac;-><init>(Ljava/lang/String;II)V

    .line 551
    .line 552
    .line 553
    new-instance v1, Ljp/ac;

    .line 554
    .line 555
    const/16 v2, 0x2e

    .line 556
    .line 557
    const/16 v7, 0x197

    .line 558
    .line 559
    move-object/from16 v49, v0

    .line 560
    .line 561
    const-string v0, "CODE_SCANNER_GOOGLE_PLAY_SERVICES_VERSION_TOO_OLD"

    .line 562
    .line 563
    invoke-direct {v1, v0, v2, v7}, Ljp/ac;-><init>(Ljava/lang/String;II)V

    .line 564
    .line 565
    .line 566
    new-instance v0, Ljp/ac;

    .line 567
    .line 568
    const/16 v2, 0x2f

    .line 569
    .line 570
    const/16 v7, 0x1f4

    .line 571
    .line 572
    move-object/from16 v50, v1

    .line 573
    .line 574
    const-string v1, "LOW_LIGHT_AUTO_EXPOSURE_COMPUTATION_FAILURE"

    .line 575
    .line 576
    invoke-direct {v0, v1, v2, v7}, Ljp/ac;-><init>(Ljava/lang/String;II)V

    .line 577
    .line 578
    .line 579
    new-instance v1, Ljp/ac;

    .line 580
    .line 581
    const/16 v2, 0x30

    .line 582
    .line 583
    const/16 v7, 0x1f5

    .line 584
    .line 585
    move-object/from16 v51, v0

    .line 586
    .line 587
    const-string v0, "LOW_LIGHT_IMAGE_CAPTURE_PROCESSING_FAILURE"

    .line 588
    .line 589
    invoke-direct {v1, v0, v2, v7}, Ljp/ac;-><init>(Ljava/lang/String;II)V

    .line 590
    .line 591
    .line 592
    new-instance v0, Ljp/ac;

    .line 593
    .line 594
    const/16 v2, 0x31

    .line 595
    .line 596
    const/16 v7, 0x258

    .line 597
    .line 598
    move-object/from16 v52, v1

    .line 599
    .line 600
    const-string v1, "PERMISSION_DENIED"

    .line 601
    .line 602
    invoke-direct {v0, v1, v2, v7}, Ljp/ac;-><init>(Ljava/lang/String;II)V

    .line 603
    .line 604
    .line 605
    new-instance v1, Ljp/ac;

    .line 606
    .line 607
    const/16 v2, 0x32

    .line 608
    .line 609
    const/16 v7, 0x259

    .line 610
    .line 611
    move-object/from16 v53, v0

    .line 612
    .line 613
    const-string v0, "CANCELLED"

    .line 614
    .line 615
    invoke-direct {v1, v0, v2, v7}, Ljp/ac;-><init>(Ljava/lang/String;II)V

    .line 616
    .line 617
    .line 618
    new-instance v0, Ljp/ac;

    .line 619
    .line 620
    const/16 v2, 0x33

    .line 621
    .line 622
    const/16 v7, 0x25a

    .line 623
    .line 624
    move-object/from16 v54, v1

    .line 625
    .line 626
    const-string v1, "GOOGLE_PLAY_SERVICES_VERSION_TOO_OLD"

    .line 627
    .line 628
    invoke-direct {v0, v1, v2, v7}, Ljp/ac;-><init>(Ljava/lang/String;II)V

    .line 629
    .line 630
    .line 631
    new-instance v1, Ljp/ac;

    .line 632
    .line 633
    const/16 v2, 0x34

    .line 634
    .line 635
    const/16 v7, 0x25b

    .line 636
    .line 637
    move-object/from16 v55, v0

    .line 638
    .line 639
    const-string v0, "LOW_MEMORY"

    .line 640
    .line 641
    invoke-direct {v1, v0, v2, v7}, Ljp/ac;-><init>(Ljava/lang/String;II)V

    .line 642
    .line 643
    .line 644
    new-instance v0, Ljp/ac;

    .line 645
    .line 646
    const/16 v2, 0x35

    .line 647
    .line 648
    const/16 v7, 0x270f

    .line 649
    .line 650
    move-object/from16 v56, v1

    .line 651
    .line 652
    const-string v1, "UNKNOWN_ERROR"

    .line 653
    .line 654
    invoke-direct {v0, v1, v2, v7}, Ljp/ac;-><init>(Ljava/lang/String;II)V

    .line 655
    .line 656
    .line 657
    sput-object v0, Ljp/ac;->i:Ljp/ac;

    .line 658
    .line 659
    move-object/from16 v7, v16

    .line 660
    .line 661
    move-object/from16 v1, v17

    .line 662
    .line 663
    move-object/from16 v2, v18

    .line 664
    .line 665
    move-object/from16 v16, v19

    .line 666
    .line 667
    move-object/from16 v17, v20

    .line 668
    .line 669
    move-object/from16 v18, v21

    .line 670
    .line 671
    move-object/from16 v19, v22

    .line 672
    .line 673
    move-object/from16 v20, v23

    .line 674
    .line 675
    move-object/from16 v21, v24

    .line 676
    .line 677
    move-object/from16 v22, v25

    .line 678
    .line 679
    move-object/from16 v23, v26

    .line 680
    .line 681
    move-object/from16 v24, v27

    .line 682
    .line 683
    move-object/from16 v25, v28

    .line 684
    .line 685
    move-object/from16 v26, v29

    .line 686
    .line 687
    move-object/from16 v27, v30

    .line 688
    .line 689
    move-object/from16 v28, v31

    .line 690
    .line 691
    move-object/from16 v29, v32

    .line 692
    .line 693
    move-object/from16 v30, v33

    .line 694
    .line 695
    move-object/from16 v31, v34

    .line 696
    .line 697
    move-object/from16 v32, v35

    .line 698
    .line 699
    move-object/from16 v33, v36

    .line 700
    .line 701
    move-object/from16 v34, v37

    .line 702
    .line 703
    move-object/from16 v35, v38

    .line 704
    .line 705
    move-object/from16 v36, v39

    .line 706
    .line 707
    move-object/from16 v37, v40

    .line 708
    .line 709
    move-object/from16 v38, v41

    .line 710
    .line 711
    move-object/from16 v39, v42

    .line 712
    .line 713
    move-object/from16 v40, v43

    .line 714
    .line 715
    move-object/from16 v41, v44

    .line 716
    .line 717
    move-object/from16 v42, v45

    .line 718
    .line 719
    move-object/from16 v43, v46

    .line 720
    .line 721
    move-object/from16 v44, v47

    .line 722
    .line 723
    move-object/from16 v45, v48

    .line 724
    .line 725
    move-object/from16 v46, v49

    .line 726
    .line 727
    move-object/from16 v47, v50

    .line 728
    .line 729
    move-object/from16 v48, v51

    .line 730
    .line 731
    move-object/from16 v49, v52

    .line 732
    .line 733
    move-object/from16 v50, v53

    .line 734
    .line 735
    move-object/from16 v51, v54

    .line 736
    .line 737
    move-object/from16 v52, v55

    .line 738
    .line 739
    move-object/from16 v53, v56

    .line 740
    .line 741
    move-object/from16 v54, v0

    .line 742
    .line 743
    filled-new-array/range {v1 .. v54}, [Ljp/ac;

    .line 744
    .line 745
    .line 746
    move-result-object v0

    .line 747
    sput-object v0, Ljp/ac;->j:[Ljp/ac;

    .line 748
    .line 749
    return-void
.end method

.method public constructor <init>(Ljava/lang/String;II)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 2
    .line 3
    .line 4
    iput p3, p0, Ljp/ac;->d:I

    .line 5
    .line 6
    return-void
.end method

.method public static values()[Ljp/ac;
    .locals 1

    .line 1
    sget-object v0, Ljp/ac;->j:[Ljp/ac;

    .line 2
    .line 3
    invoke-virtual {v0}, [Ljp/ac;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Ljp/ac;

    .line 8
    .line 9
    return-object v0
.end method


# virtual methods
.method public final h()I
    .locals 0

    .line 1
    iget p0, p0, Ljp/ac;->d:I

    .line 2
    .line 3
    return p0
.end method
