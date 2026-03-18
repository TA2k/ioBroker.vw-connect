.class public final enum Lcom/google/protobuf/l;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final enum e:Lcom/google/protobuf/l;

.field public static final enum f:Lcom/google/protobuf/l;

.field public static final g:[Lcom/google/protobuf/l;

.field public static final synthetic h:[Lcom/google/protobuf/l;


# instance fields
.field public final d:I


# direct methods
.method static constructor <clinit>()V
    .locals 86

    .line 1
    new-instance v0, Lcom/google/protobuf/l;

    .line 2
    .line 3
    sget-object v6, Lcom/google/protobuf/x;->h:Lcom/google/protobuf/x;

    .line 4
    .line 5
    const-string v1, "DOUBLE"

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    const/4 v3, 0x0

    .line 9
    const/4 v11, 0x1

    .line 10
    move-object v5, v6

    .line 11
    move v4, v11

    .line 12
    invoke-direct/range {v0 .. v5}, Lcom/google/protobuf/l;-><init>(Ljava/lang/String;IIILcom/google/protobuf/x;)V

    .line 13
    .line 14
    .line 15
    new-instance v2, Lcom/google/protobuf/l;

    .line 16
    .line 17
    sget-object v17, Lcom/google/protobuf/x;->g:Lcom/google/protobuf/x;

    .line 18
    .line 19
    const-string v8, "FLOAT"

    .line 20
    .line 21
    const/4 v9, 0x1

    .line 22
    const/4 v10, 0x1

    .line 23
    move-object v7, v2

    .line 24
    move-object/from16 v12, v17

    .line 25
    .line 26
    invoke-direct/range {v7 .. v12}, Lcom/google/protobuf/l;-><init>(Ljava/lang/String;IIILcom/google/protobuf/x;)V

    .line 27
    .line 28
    .line 29
    move-object/from16 v18, v7

    .line 30
    .line 31
    new-instance v3, Lcom/google/protobuf/l;

    .line 32
    .line 33
    sget-object v24, Lcom/google/protobuf/x;->f:Lcom/google/protobuf/x;

    .line 34
    .line 35
    const-string v8, "INT64"

    .line 36
    .line 37
    const/4 v9, 0x2

    .line 38
    const/4 v10, 0x2

    .line 39
    move-object v7, v3

    .line 40
    move-object/from16 v12, v24

    .line 41
    .line 42
    invoke-direct/range {v7 .. v12}, Lcom/google/protobuf/l;-><init>(Ljava/lang/String;IIILcom/google/protobuf/x;)V

    .line 43
    .line 44
    .line 45
    move-object/from16 v25, v7

    .line 46
    .line 47
    new-instance v4, Lcom/google/protobuf/l;

    .line 48
    .line 49
    const/4 v9, 0x3

    .line 50
    const/4 v10, 0x3

    .line 51
    const-string v8, "UINT64"

    .line 52
    .line 53
    move-object v7, v4

    .line 54
    invoke-direct/range {v7 .. v12}, Lcom/google/protobuf/l;-><init>(Ljava/lang/String;IIILcom/google/protobuf/x;)V

    .line 55
    .line 56
    .line 57
    move-object/from16 v26, v7

    .line 58
    .line 59
    new-instance v5, Lcom/google/protobuf/l;

    .line 60
    .line 61
    sget-object v32, Lcom/google/protobuf/x;->e:Lcom/google/protobuf/x;

    .line 62
    .line 63
    const-string v8, "INT32"

    .line 64
    .line 65
    const/4 v9, 0x4

    .line 66
    const/4 v10, 0x4

    .line 67
    move-object v7, v5

    .line 68
    move-object/from16 v12, v32

    .line 69
    .line 70
    invoke-direct/range {v7 .. v12}, Lcom/google/protobuf/l;-><init>(Ljava/lang/String;IIILcom/google/protobuf/x;)V

    .line 71
    .line 72
    .line 73
    move-object/from16 v33, v7

    .line 74
    .line 75
    new-instance v7, Lcom/google/protobuf/l;

    .line 76
    .line 77
    const/4 v9, 0x5

    .line 78
    const/4 v10, 0x5

    .line 79
    const-string v8, "FIXED64"

    .line 80
    .line 81
    move-object/from16 v12, v24

    .line 82
    .line 83
    invoke-direct/range {v7 .. v12}, Lcom/google/protobuf/l;-><init>(Ljava/lang/String;IIILcom/google/protobuf/x;)V

    .line 84
    .line 85
    .line 86
    move-object/from16 v34, v7

    .line 87
    .line 88
    new-instance v7, Lcom/google/protobuf/l;

    .line 89
    .line 90
    const/4 v9, 0x6

    .line 91
    const/4 v10, 0x6

    .line 92
    const-string v8, "FIXED32"

    .line 93
    .line 94
    move-object/from16 v12, v32

    .line 95
    .line 96
    invoke-direct/range {v7 .. v12}, Lcom/google/protobuf/l;-><init>(Ljava/lang/String;IIILcom/google/protobuf/x;)V

    .line 97
    .line 98
    .line 99
    move-object/from16 v35, v7

    .line 100
    .line 101
    new-instance v7, Lcom/google/protobuf/l;

    .line 102
    .line 103
    sget-object v41, Lcom/google/protobuf/x;->i:Lcom/google/protobuf/x;

    .line 104
    .line 105
    const-string v8, "BOOL"

    .line 106
    .line 107
    const/4 v9, 0x7

    .line 108
    const/4 v10, 0x7

    .line 109
    move-object/from16 v12, v41

    .line 110
    .line 111
    invoke-direct/range {v7 .. v12}, Lcom/google/protobuf/l;-><init>(Ljava/lang/String;IIILcom/google/protobuf/x;)V

    .line 112
    .line 113
    .line 114
    move-object/from16 v42, v7

    .line 115
    .line 116
    new-instance v7, Lcom/google/protobuf/l;

    .line 117
    .line 118
    sget-object v48, Lcom/google/protobuf/x;->j:Lcom/google/protobuf/x;

    .line 119
    .line 120
    const-string v8, "STRING"

    .line 121
    .line 122
    const/16 v9, 0x8

    .line 123
    .line 124
    const/16 v10, 0x8

    .line 125
    .line 126
    move-object/from16 v12, v48

    .line 127
    .line 128
    invoke-direct/range {v7 .. v12}, Lcom/google/protobuf/l;-><init>(Ljava/lang/String;IIILcom/google/protobuf/x;)V

    .line 129
    .line 130
    .line 131
    move-object/from16 v49, v7

    .line 132
    .line 133
    new-instance v7, Lcom/google/protobuf/l;

    .line 134
    .line 135
    sget-object v55, Lcom/google/protobuf/x;->m:Lcom/google/protobuf/x;

    .line 136
    .line 137
    const-string v8, "MESSAGE"

    .line 138
    .line 139
    const/16 v9, 0x9

    .line 140
    .line 141
    const/16 v10, 0x9

    .line 142
    .line 143
    move-object/from16 v12, v55

    .line 144
    .line 145
    invoke-direct/range {v7 .. v12}, Lcom/google/protobuf/l;-><init>(Ljava/lang/String;IIILcom/google/protobuf/x;)V

    .line 146
    .line 147
    .line 148
    move-object/from16 v56, v7

    .line 149
    .line 150
    new-instance v7, Lcom/google/protobuf/l;

    .line 151
    .line 152
    sget-object v12, Lcom/google/protobuf/x;->k:Lcom/google/protobuf/x;

    .line 153
    .line 154
    const-string v8, "BYTES"

    .line 155
    .line 156
    const/16 v9, 0xa

    .line 157
    .line 158
    const/16 v10, 0xa

    .line 159
    .line 160
    invoke-direct/range {v7 .. v12}, Lcom/google/protobuf/l;-><init>(Ljava/lang/String;IIILcom/google/protobuf/x;)V

    .line 161
    .line 162
    .line 163
    move-object/from16 v63, v7

    .line 164
    .line 165
    move-object/from16 v62, v12

    .line 166
    .line 167
    new-instance v7, Lcom/google/protobuf/l;

    .line 168
    .line 169
    const/16 v9, 0xb

    .line 170
    .line 171
    const/16 v10, 0xb

    .line 172
    .line 173
    const-string v8, "UINT32"

    .line 174
    .line 175
    move-object/from16 v12, v32

    .line 176
    .line 177
    invoke-direct/range {v7 .. v12}, Lcom/google/protobuf/l;-><init>(Ljava/lang/String;IIILcom/google/protobuf/x;)V

    .line 178
    .line 179
    .line 180
    move-object/from16 v64, v7

    .line 181
    .line 182
    new-instance v7, Lcom/google/protobuf/l;

    .line 183
    .line 184
    sget-object v70, Lcom/google/protobuf/x;->l:Lcom/google/protobuf/x;

    .line 185
    .line 186
    const-string v8, "ENUM"

    .line 187
    .line 188
    const/16 v9, 0xc

    .line 189
    .line 190
    const/16 v10, 0xc

    .line 191
    .line 192
    move-object/from16 v12, v70

    .line 193
    .line 194
    invoke-direct/range {v7 .. v12}, Lcom/google/protobuf/l;-><init>(Ljava/lang/String;IIILcom/google/protobuf/x;)V

    .line 195
    .line 196
    .line 197
    move-object/from16 v71, v7

    .line 198
    .line 199
    new-instance v7, Lcom/google/protobuf/l;

    .line 200
    .line 201
    const/16 v9, 0xd

    .line 202
    .line 203
    const/16 v10, 0xd

    .line 204
    .line 205
    const-string v8, "SFIXED32"

    .line 206
    .line 207
    move-object/from16 v12, v32

    .line 208
    .line 209
    invoke-direct/range {v7 .. v12}, Lcom/google/protobuf/l;-><init>(Ljava/lang/String;IIILcom/google/protobuf/x;)V

    .line 210
    .line 211
    .line 212
    move-object/from16 v72, v7

    .line 213
    .line 214
    new-instance v7, Lcom/google/protobuf/l;

    .line 215
    .line 216
    const/16 v9, 0xe

    .line 217
    .line 218
    const/16 v10, 0xe

    .line 219
    .line 220
    const-string v8, "SFIXED64"

    .line 221
    .line 222
    move-object/from16 v12, v24

    .line 223
    .line 224
    invoke-direct/range {v7 .. v12}, Lcom/google/protobuf/l;-><init>(Ljava/lang/String;IIILcom/google/protobuf/x;)V

    .line 225
    .line 226
    .line 227
    move-object/from16 v73, v7

    .line 228
    .line 229
    new-instance v16, Lcom/google/protobuf/l;

    .line 230
    .line 231
    const/16 v9, 0xf

    .line 232
    .line 233
    const/16 v10, 0xf

    .line 234
    .line 235
    const-string v8, "SINT32"

    .line 236
    .line 237
    move-object/from16 v7, v16

    .line 238
    .line 239
    move-object/from16 v12, v32

    .line 240
    .line 241
    invoke-direct/range {v7 .. v12}, Lcom/google/protobuf/l;-><init>(Ljava/lang/String;IIILcom/google/protobuf/x;)V

    .line 242
    .line 243
    .line 244
    move-object/from16 v74, v7

    .line 245
    .line 246
    new-instance v7, Lcom/google/protobuf/l;

    .line 247
    .line 248
    const/16 v9, 0x10

    .line 249
    .line 250
    const/16 v10, 0x10

    .line 251
    .line 252
    const-string v8, "SINT64"

    .line 253
    .line 254
    move-object/from16 v12, v24

    .line 255
    .line 256
    invoke-direct/range {v7 .. v12}, Lcom/google/protobuf/l;-><init>(Ljava/lang/String;IIILcom/google/protobuf/x;)V

    .line 257
    .line 258
    .line 259
    move-object/from16 v75, v7

    .line 260
    .line 261
    new-instance v7, Lcom/google/protobuf/l;

    .line 262
    .line 263
    const/16 v9, 0x11

    .line 264
    .line 265
    const/16 v10, 0x11

    .line 266
    .line 267
    const-string v8, "GROUP"

    .line 268
    .line 269
    move-object/from16 v12, v55

    .line 270
    .line 271
    invoke-direct/range {v7 .. v12}, Lcom/google/protobuf/l;-><init>(Ljava/lang/String;IIILcom/google/protobuf/x;)V

    .line 272
    .line 273
    .line 274
    new-instance v1, Lcom/google/protobuf/l;

    .line 275
    .line 276
    const-string v2, "DOUBLE_LIST"

    .line 277
    .line 278
    const/16 v3, 0x12

    .line 279
    .line 280
    const/16 v4, 0x12

    .line 281
    .line 282
    const/16 v23, 0x2

    .line 283
    .line 284
    move/from16 v5, v23

    .line 285
    .line 286
    invoke-direct/range {v1 .. v6}, Lcom/google/protobuf/l;-><init>(Ljava/lang/String;IIILcom/google/protobuf/x;)V

    .line 287
    .line 288
    .line 289
    move-object v8, v1

    .line 290
    new-instance v20, Lcom/google/protobuf/l;

    .line 291
    .line 292
    const/16 v14, 0x13

    .line 293
    .line 294
    const/16 v15, 0x13

    .line 295
    .line 296
    const-string v13, "FLOAT_LIST"

    .line 297
    .line 298
    move-object/from16 v12, v20

    .line 299
    .line 300
    move/from16 v16, v23

    .line 301
    .line 302
    invoke-direct/range {v12 .. v17}, Lcom/google/protobuf/l;-><init>(Ljava/lang/String;IIILcom/google/protobuf/x;)V

    .line 303
    .line 304
    .line 305
    move-object v9, v12

    .line 306
    new-instance v19, Lcom/google/protobuf/l;

    .line 307
    .line 308
    const/16 v21, 0x14

    .line 309
    .line 310
    const/16 v22, 0x14

    .line 311
    .line 312
    const-string v20, "INT64_LIST"

    .line 313
    .line 314
    invoke-direct/range {v19 .. v24}, Lcom/google/protobuf/l;-><init>(Ljava/lang/String;IIILcom/google/protobuf/x;)V

    .line 315
    .line 316
    .line 317
    move-object/from16 v10, v19

    .line 318
    .line 319
    new-instance v19, Lcom/google/protobuf/l;

    .line 320
    .line 321
    const/16 v21, 0x15

    .line 322
    .line 323
    const/16 v22, 0x15

    .line 324
    .line 325
    const-string v20, "UINT64_LIST"

    .line 326
    .line 327
    invoke-direct/range {v19 .. v24}, Lcom/google/protobuf/l;-><init>(Ljava/lang/String;IIILcom/google/protobuf/x;)V

    .line 328
    .line 329
    .line 330
    move-object/from16 v11, v19

    .line 331
    .line 332
    new-instance v27, Lcom/google/protobuf/l;

    .line 333
    .line 334
    const/16 v29, 0x16

    .line 335
    .line 336
    const/16 v30, 0x16

    .line 337
    .line 338
    const-string v28, "INT32_LIST"

    .line 339
    .line 340
    move/from16 v31, v23

    .line 341
    .line 342
    invoke-direct/range {v27 .. v32}, Lcom/google/protobuf/l;-><init>(Ljava/lang/String;IIILcom/google/protobuf/x;)V

    .line 343
    .line 344
    .line 345
    move-object/from16 v76, v27

    .line 346
    .line 347
    new-instance v19, Lcom/google/protobuf/l;

    .line 348
    .line 349
    const/16 v21, 0x17

    .line 350
    .line 351
    const/16 v22, 0x17

    .line 352
    .line 353
    const-string v20, "FIXED64_LIST"

    .line 354
    .line 355
    invoke-direct/range {v19 .. v24}, Lcom/google/protobuf/l;-><init>(Ljava/lang/String;IIILcom/google/protobuf/x;)V

    .line 356
    .line 357
    .line 358
    move-object/from16 v77, v19

    .line 359
    .line 360
    new-instance v27, Lcom/google/protobuf/l;

    .line 361
    .line 362
    const/16 v29, 0x18

    .line 363
    .line 364
    const/16 v30, 0x18

    .line 365
    .line 366
    const-string v28, "FIXED32_LIST"

    .line 367
    .line 368
    invoke-direct/range {v27 .. v32}, Lcom/google/protobuf/l;-><init>(Ljava/lang/String;IIILcom/google/protobuf/x;)V

    .line 369
    .line 370
    .line 371
    move-object/from16 v78, v25

    .line 372
    .line 373
    move-object/from16 v25, v27

    .line 374
    .line 375
    new-instance v36, Lcom/google/protobuf/l;

    .line 376
    .line 377
    const/16 v38, 0x19

    .line 378
    .line 379
    const/16 v39, 0x19

    .line 380
    .line 381
    const-string v37, "BOOL_LIST"

    .line 382
    .line 383
    move/from16 v40, v23

    .line 384
    .line 385
    invoke-direct/range {v36 .. v41}, Lcom/google/protobuf/l;-><init>(Ljava/lang/String;IIILcom/google/protobuf/x;)V

    .line 386
    .line 387
    .line 388
    move-object/from16 v79, v26

    .line 389
    .line 390
    move-object/from16 v26, v36

    .line 391
    .line 392
    new-instance v43, Lcom/google/protobuf/l;

    .line 393
    .line 394
    const/16 v45, 0x1a

    .line 395
    .line 396
    const/16 v46, 0x1a

    .line 397
    .line 398
    const-string v44, "STRING_LIST"

    .line 399
    .line 400
    move/from16 v47, v23

    .line 401
    .line 402
    invoke-direct/range {v43 .. v48}, Lcom/google/protobuf/l;-><init>(Ljava/lang/String;IIILcom/google/protobuf/x;)V

    .line 403
    .line 404
    .line 405
    new-instance v50, Lcom/google/protobuf/l;

    .line 406
    .line 407
    const/16 v52, 0x1b

    .line 408
    .line 409
    const/16 v53, 0x1b

    .line 410
    .line 411
    const-string v51, "MESSAGE_LIST"

    .line 412
    .line 413
    move/from16 v54, v23

    .line 414
    .line 415
    invoke-direct/range {v50 .. v55}, Lcom/google/protobuf/l;-><init>(Ljava/lang/String;IIILcom/google/protobuf/x;)V

    .line 416
    .line 417
    .line 418
    move-object/from16 v44, v50

    .line 419
    .line 420
    new-instance v57, Lcom/google/protobuf/l;

    .line 421
    .line 422
    const/16 v59, 0x1c

    .line 423
    .line 424
    const/16 v60, 0x1c

    .line 425
    .line 426
    const-string v58, "BYTES_LIST"

    .line 427
    .line 428
    move/from16 v61, v23

    .line 429
    .line 430
    invoke-direct/range {v57 .. v62}, Lcom/google/protobuf/l;-><init>(Ljava/lang/String;IIILcom/google/protobuf/x;)V

    .line 431
    .line 432
    .line 433
    new-instance v27, Lcom/google/protobuf/l;

    .line 434
    .line 435
    const/16 v29, 0x1d

    .line 436
    .line 437
    const/16 v30, 0x1d

    .line 438
    .line 439
    const-string v28, "UINT32_LIST"

    .line 440
    .line 441
    invoke-direct/range {v27 .. v32}, Lcom/google/protobuf/l;-><init>(Ljava/lang/String;IIILcom/google/protobuf/x;)V

    .line 442
    .line 443
    .line 444
    move-object/from16 v45, v27

    .line 445
    .line 446
    new-instance v65, Lcom/google/protobuf/l;

    .line 447
    .line 448
    const/16 v67, 0x1e

    .line 449
    .line 450
    const/16 v68, 0x1e

    .line 451
    .line 452
    const-string v66, "ENUM_LIST"

    .line 453
    .line 454
    move/from16 v69, v23

    .line 455
    .line 456
    invoke-direct/range {v65 .. v70}, Lcom/google/protobuf/l;-><init>(Ljava/lang/String;IIILcom/google/protobuf/x;)V

    .line 457
    .line 458
    .line 459
    move-object/from16 v46, v65

    .line 460
    .line 461
    new-instance v27, Lcom/google/protobuf/l;

    .line 462
    .line 463
    const/16 v29, 0x1f

    .line 464
    .line 465
    const/16 v30, 0x1f

    .line 466
    .line 467
    const-string v28, "SFIXED32_LIST"

    .line 468
    .line 469
    invoke-direct/range {v27 .. v32}, Lcom/google/protobuf/l;-><init>(Ljava/lang/String;IIILcom/google/protobuf/x;)V

    .line 470
    .line 471
    .line 472
    move-object/from16 v47, v27

    .line 473
    .line 474
    new-instance v19, Lcom/google/protobuf/l;

    .line 475
    .line 476
    const/16 v21, 0x20

    .line 477
    .line 478
    const/16 v22, 0x20

    .line 479
    .line 480
    const-string v20, "SFIXED64_LIST"

    .line 481
    .line 482
    invoke-direct/range {v19 .. v24}, Lcom/google/protobuf/l;-><init>(Ljava/lang/String;IIILcom/google/protobuf/x;)V

    .line 483
    .line 484
    .line 485
    move-object/from16 v48, v33

    .line 486
    .line 487
    move-object/from16 v33, v19

    .line 488
    .line 489
    new-instance v27, Lcom/google/protobuf/l;

    .line 490
    .line 491
    const/16 v29, 0x21

    .line 492
    .line 493
    const/16 v30, 0x21

    .line 494
    .line 495
    const-string v28, "SINT32_LIST"

    .line 496
    .line 497
    invoke-direct/range {v27 .. v32}, Lcom/google/protobuf/l;-><init>(Ljava/lang/String;IIILcom/google/protobuf/x;)V

    .line 498
    .line 499
    .line 500
    move-object/from16 v58, v34

    .line 501
    .line 502
    move-object/from16 v34, v27

    .line 503
    .line 504
    new-instance v19, Lcom/google/protobuf/l;

    .line 505
    .line 506
    const/16 v21, 0x22

    .line 507
    .line 508
    const/16 v22, 0x22

    .line 509
    .line 510
    const-string v20, "SINT64_LIST"

    .line 511
    .line 512
    invoke-direct/range {v19 .. v24}, Lcom/google/protobuf/l;-><init>(Ljava/lang/String;IIILcom/google/protobuf/x;)V

    .line 513
    .line 514
    .line 515
    move-object/from16 v59, v18

    .line 516
    .line 517
    move-object/from16 v18, v7

    .line 518
    .line 519
    move-object/from16 v7, v35

    .line 520
    .line 521
    move-object/from16 v35, v19

    .line 522
    .line 523
    new-instance v1, Lcom/google/protobuf/l;

    .line 524
    .line 525
    const-string v2, "DOUBLE_LIST_PACKED"

    .line 526
    .line 527
    const/16 v3, 0x23

    .line 528
    .line 529
    const/16 v4, 0x23

    .line 530
    .line 531
    const/16 v23, 0x3

    .line 532
    .line 533
    move/from16 v5, v23

    .line 534
    .line 535
    invoke-direct/range {v1 .. v6}, Lcom/google/protobuf/l;-><init>(Ljava/lang/String;IIILcom/google/protobuf/x;)V

    .line 536
    .line 537
    .line 538
    sput-object v1, Lcom/google/protobuf/l;->e:Lcom/google/protobuf/l;

    .line 539
    .line 540
    new-instance v37, Lcom/google/protobuf/l;

    .line 541
    .line 542
    const/16 v14, 0x24

    .line 543
    .line 544
    const/16 v15, 0x24

    .line 545
    .line 546
    const-string v13, "FLOAT_LIST_PACKED"

    .line 547
    .line 548
    move/from16 v16, v23

    .line 549
    .line 550
    move-object/from16 v12, v37

    .line 551
    .line 552
    invoke-direct/range {v12 .. v17}, Lcom/google/protobuf/l;-><init>(Ljava/lang/String;IIILcom/google/protobuf/x;)V

    .line 553
    .line 554
    .line 555
    new-instance v19, Lcom/google/protobuf/l;

    .line 556
    .line 557
    const/16 v21, 0x25

    .line 558
    .line 559
    const/16 v22, 0x25

    .line 560
    .line 561
    const-string v20, "INT64_LIST_PACKED"

    .line 562
    .line 563
    invoke-direct/range {v19 .. v24}, Lcom/google/protobuf/l;-><init>(Ljava/lang/String;IIILcom/google/protobuf/x;)V

    .line 564
    .line 565
    .line 566
    move-object/from16 v2, v19

    .line 567
    .line 568
    new-instance v19, Lcom/google/protobuf/l;

    .line 569
    .line 570
    const/16 v21, 0x26

    .line 571
    .line 572
    const/16 v22, 0x26

    .line 573
    .line 574
    const-string v20, "UINT64_LIST_PACKED"

    .line 575
    .line 576
    invoke-direct/range {v19 .. v24}, Lcom/google/protobuf/l;-><init>(Ljava/lang/String;IIILcom/google/protobuf/x;)V

    .line 577
    .line 578
    .line 579
    move-object/from16 v3, v19

    .line 580
    .line 581
    new-instance v40, Lcom/google/protobuf/l;

    .line 582
    .line 583
    const/16 v29, 0x27

    .line 584
    .line 585
    const/16 v30, 0x27

    .line 586
    .line 587
    const-string v28, "INT32_LIST_PACKED"

    .line 588
    .line 589
    move/from16 v31, v23

    .line 590
    .line 591
    move-object/from16 v27, v40

    .line 592
    .line 593
    invoke-direct/range {v27 .. v32}, Lcom/google/protobuf/l;-><init>(Ljava/lang/String;IIILcom/google/protobuf/x;)V

    .line 594
    .line 595
    .line 596
    move-object/from16 v4, v27

    .line 597
    .line 598
    new-instance v19, Lcom/google/protobuf/l;

    .line 599
    .line 600
    const/16 v21, 0x28

    .line 601
    .line 602
    const/16 v22, 0x28

    .line 603
    .line 604
    const-string v20, "FIXED64_LIST_PACKED"

    .line 605
    .line 606
    invoke-direct/range {v19 .. v24}, Lcom/google/protobuf/l;-><init>(Ljava/lang/String;IIILcom/google/protobuf/x;)V

    .line 607
    .line 608
    .line 609
    move-object/from16 v5, v19

    .line 610
    .line 611
    new-instance v27, Lcom/google/protobuf/l;

    .line 612
    .line 613
    const/16 v29, 0x29

    .line 614
    .line 615
    const/16 v30, 0x29

    .line 616
    .line 617
    const-string v28, "FIXED32_LIST_PACKED"

    .line 618
    .line 619
    invoke-direct/range {v27 .. v32}, Lcom/google/protobuf/l;-><init>(Ljava/lang/String;IIILcom/google/protobuf/x;)V

    .line 620
    .line 621
    .line 622
    move-object v6, v8

    .line 623
    move-object/from16 v8, v42

    .line 624
    .line 625
    move-object/from16 v42, v27

    .line 626
    .line 627
    new-instance v36, Lcom/google/protobuf/l;

    .line 628
    .line 629
    const/16 v38, 0x2a

    .line 630
    .line 631
    const/16 v39, 0x2a

    .line 632
    .line 633
    const-string v37, "BOOL_LIST_PACKED"

    .line 634
    .line 635
    move/from16 v40, v23

    .line 636
    .line 637
    invoke-direct/range {v36 .. v41}, Lcom/google/protobuf/l;-><init>(Ljava/lang/String;IIILcom/google/protobuf/x;)V

    .line 638
    .line 639
    .line 640
    new-instance v27, Lcom/google/protobuf/l;

    .line 641
    .line 642
    const/16 v29, 0x2b

    .line 643
    .line 644
    const/16 v30, 0x2b

    .line 645
    .line 646
    const-string v28, "UINT32_LIST_PACKED"

    .line 647
    .line 648
    invoke-direct/range {v27 .. v32}, Lcom/google/protobuf/l;-><init>(Ljava/lang/String;IIILcom/google/protobuf/x;)V

    .line 649
    .line 650
    .line 651
    move-object/from16 v13, v44

    .line 652
    .line 653
    move-object/from16 v44, v27

    .line 654
    .line 655
    new-instance v65, Lcom/google/protobuf/l;

    .line 656
    .line 657
    const/16 v67, 0x2c

    .line 658
    .line 659
    const/16 v68, 0x2c

    .line 660
    .line 661
    const-string v66, "ENUM_LIST_PACKED"

    .line 662
    .line 663
    move/from16 v69, v23

    .line 664
    .line 665
    invoke-direct/range {v65 .. v70}, Lcom/google/protobuf/l;-><init>(Ljava/lang/String;IIILcom/google/protobuf/x;)V

    .line 666
    .line 667
    .line 668
    new-instance v27, Lcom/google/protobuf/l;

    .line 669
    .line 670
    const/16 v29, 0x2d

    .line 671
    .line 672
    const/16 v30, 0x2d

    .line 673
    .line 674
    const-string v28, "SFIXED32_LIST_PACKED"

    .line 675
    .line 676
    invoke-direct/range {v27 .. v32}, Lcom/google/protobuf/l;-><init>(Ljava/lang/String;IIILcom/google/protobuf/x;)V

    .line 677
    .line 678
    .line 679
    move-object/from16 v14, v46

    .line 680
    .line 681
    move-object/from16 v46, v27

    .line 682
    .line 683
    new-instance v19, Lcom/google/protobuf/l;

    .line 684
    .line 685
    const/16 v21, 0x2e

    .line 686
    .line 687
    const/16 v22, 0x2e

    .line 688
    .line 689
    const-string v20, "SFIXED64_LIST_PACKED"

    .line 690
    .line 691
    invoke-direct/range {v19 .. v24}, Lcom/google/protobuf/l;-><init>(Ljava/lang/String;IIILcom/google/protobuf/x;)V

    .line 692
    .line 693
    .line 694
    move-object/from16 v15, v47

    .line 695
    .line 696
    move-object/from16 v47, v19

    .line 697
    .line 698
    new-instance v27, Lcom/google/protobuf/l;

    .line 699
    .line 700
    const/16 v29, 0x2f

    .line 701
    .line 702
    const/16 v30, 0x2f

    .line 703
    .line 704
    const-string v28, "SINT32_LIST_PACKED"

    .line 705
    .line 706
    invoke-direct/range {v27 .. v32}, Lcom/google/protobuf/l;-><init>(Ljava/lang/String;IIILcom/google/protobuf/x;)V

    .line 707
    .line 708
    .line 709
    new-instance v19, Lcom/google/protobuf/l;

    .line 710
    .line 711
    const/16 v21, 0x30

    .line 712
    .line 713
    const/16 v22, 0x30

    .line 714
    .line 715
    const-string v20, "SINT64_LIST_PACKED"

    .line 716
    .line 717
    invoke-direct/range {v19 .. v24}, Lcom/google/protobuf/l;-><init>(Ljava/lang/String;IIILcom/google/protobuf/x;)V

    .line 718
    .line 719
    .line 720
    sput-object v19, Lcom/google/protobuf/l;->f:Lcom/google/protobuf/l;

    .line 721
    .line 722
    new-instance v50, Lcom/google/protobuf/l;

    .line 723
    .line 724
    const/16 v52, 0x31

    .line 725
    .line 726
    const/16 v53, 0x31

    .line 727
    .line 728
    const-string v51, "GROUP_LIST"

    .line 729
    .line 730
    invoke-direct/range {v50 .. v55}, Lcom/google/protobuf/l;-><init>(Ljava/lang/String;IIILcom/google/protobuf/x;)V

    .line 731
    .line 732
    .line 733
    new-instance v80, Lcom/google/protobuf/l;

    .line 734
    .line 735
    const/16 v84, 0x4

    .line 736
    .line 737
    sget-object v85, Lcom/google/protobuf/x;->d:Lcom/google/protobuf/x;

    .line 738
    .line 739
    const-string v81, "MAP"

    .line 740
    .line 741
    const/16 v82, 0x32

    .line 742
    .line 743
    const/16 v83, 0x32

    .line 744
    .line 745
    invoke-direct/range {v80 .. v85}, Lcom/google/protobuf/l;-><init>(Ljava/lang/String;IIILcom/google/protobuf/x;)V

    .line 746
    .line 747
    .line 748
    move-object/from16 v38, v2

    .line 749
    .line 750
    move-object/from16 v39, v3

    .line 751
    .line 752
    move-object/from16 v40, v4

    .line 753
    .line 754
    move-object/from16 v41, v5

    .line 755
    .line 756
    move-object/from16 v20, v9

    .line 757
    .line 758
    move-object/from16 v21, v10

    .line 759
    .line 760
    move-object/from16 v22, v11

    .line 761
    .line 762
    move-object/from16 v37, v12

    .line 763
    .line 764
    move-object/from16 v28, v13

    .line 765
    .line 766
    move-object/from16 v31, v14

    .line 767
    .line 768
    move-object/from16 v32, v15

    .line 769
    .line 770
    move-object/from16 v30, v45

    .line 771
    .line 772
    move-object/from16 v5, v48

    .line 773
    .line 774
    move-object/from16 v9, v49

    .line 775
    .line 776
    move-object/from16 v10, v56

    .line 777
    .line 778
    move-object/from16 v29, v57

    .line 779
    .line 780
    move-object/from16 v2, v59

    .line 781
    .line 782
    move-object/from16 v11, v63

    .line 783
    .line 784
    move-object/from16 v12, v64

    .line 785
    .line 786
    move-object/from16 v45, v65

    .line 787
    .line 788
    move-object/from16 v13, v71

    .line 789
    .line 790
    move-object/from16 v14, v72

    .line 791
    .line 792
    move-object/from16 v15, v73

    .line 793
    .line 794
    move-object/from16 v16, v74

    .line 795
    .line 796
    move-object/from16 v17, v75

    .line 797
    .line 798
    move-object/from16 v23, v76

    .line 799
    .line 800
    move-object/from16 v24, v77

    .line 801
    .line 802
    move-object/from16 v3, v78

    .line 803
    .line 804
    move-object/from16 v4, v79

    .line 805
    .line 806
    move-object/from16 v51, v80

    .line 807
    .line 808
    move-object/from16 v49, v19

    .line 809
    .line 810
    move-object/from16 v48, v27

    .line 811
    .line 812
    move-object/from16 v27, v43

    .line 813
    .line 814
    move-object/from16 v19, v6

    .line 815
    .line 816
    move-object/from16 v43, v36

    .line 817
    .line 818
    move-object/from16 v6, v58

    .line 819
    .line 820
    move-object/from16 v36, v1

    .line 821
    .line 822
    move-object v1, v0

    .line 823
    filled-new-array/range {v1 .. v51}, [Lcom/google/protobuf/l;

    .line 824
    .line 825
    .line 826
    move-result-object v0

    .line 827
    sput-object v0, Lcom/google/protobuf/l;->h:[Lcom/google/protobuf/l;

    .line 828
    .line 829
    invoke-static {}, Lcom/google/protobuf/l;->values()[Lcom/google/protobuf/l;

    .line 830
    .line 831
    .line 832
    move-result-object v0

    .line 833
    array-length v1, v0

    .line 834
    new-array v1, v1, [Lcom/google/protobuf/l;

    .line 835
    .line 836
    sput-object v1, Lcom/google/protobuf/l;->g:[Lcom/google/protobuf/l;

    .line 837
    .line 838
    array-length v1, v0

    .line 839
    const/4 v2, 0x0

    .line 840
    :goto_0
    if-ge v2, v1, :cond_0

    .line 841
    .line 842
    aget-object v3, v0, v2

    .line 843
    .line 844
    sget-object v4, Lcom/google/protobuf/l;->g:[Lcom/google/protobuf/l;

    .line 845
    .line 846
    iget v5, v3, Lcom/google/protobuf/l;->d:I

    .line 847
    .line 848
    aput-object v3, v4, v5

    .line 849
    .line 850
    add-int/lit8 v2, v2, 0x1

    .line 851
    .line 852
    goto :goto_0

    .line 853
    :cond_0
    return-void
.end method

.method public constructor <init>(Ljava/lang/String;IIILcom/google/protobuf/x;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 2
    .line 3
    .line 4
    iput p3, p0, Lcom/google/protobuf/l;->d:I

    .line 5
    .line 6
    invoke-static {p4}, Lu/w;->o(I)I

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    const/4 p1, 0x1

    .line 11
    if-eq p0, p1, :cond_1

    .line 12
    .line 13
    const/4 p2, 0x3

    .line 14
    if-eq p0, p2, :cond_0

    .line 15
    .line 16
    goto :goto_0

    .line 17
    :cond_0
    invoke-virtual {p5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 18
    .line 19
    .line 20
    goto :goto_0

    .line 21
    :cond_1
    invoke-virtual {p5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 22
    .line 23
    .line 24
    :goto_0
    if-ne p4, p1, :cond_2

    .line 25
    .line 26
    invoke-virtual {p5}, Ljava/lang/Enum;->ordinal()I

    .line 27
    .line 28
    .line 29
    :cond_2
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Lcom/google/protobuf/l;
    .locals 1

    .line 1
    const-class v0, Lcom/google/protobuf/l;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lcom/google/protobuf/l;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lcom/google/protobuf/l;
    .locals 1

    .line 1
    sget-object v0, Lcom/google/protobuf/l;->h:[Lcom/google/protobuf/l;

    .line 2
    .line 3
    invoke-virtual {v0}, [Lcom/google/protobuf/l;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lcom/google/protobuf/l;

    .line 8
    .line 9
    return-object v0
.end method
