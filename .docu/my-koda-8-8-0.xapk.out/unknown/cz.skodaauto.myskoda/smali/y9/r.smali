.class public final Ly9/r;
.super Landroid/widget/FrameLayout;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final S1:[F


# instance fields
.field public final A:Landroid/widget/TextView;

.field public final A1:Ljava/lang/String;

.field public final B:Landroid/widget/TextView;

.field public B1:Lt7/l0;

.field public final C:Landroid/widget/ImageView;

.field public C1:Z

.field public final D:Landroid/widget/ImageView;

.field public D1:Z

.field public final E:Landroid/widget/ImageView;

.field public E1:Z

.field public final F:Landroid/widget/ImageView;

.field public F1:Z

.field public final G:Landroid/widget/ImageView;

.field public G1:Z

.field public final H:Landroid/widget/ImageView;

.field public H1:Z

.field public final I:Landroid/view/View;

.field public I1:I

.field public final J:Landroid/view/View;

.field public J1:Z

.field public final K:Landroid/view/View;

.field public K1:I

.field public final L:Landroid/widget/TextView;

.field public L1:I

.field public final M:Landroid/widget/TextView;

.field public M1:[J

.field public final N:Ly9/h0;

.field public N1:[Z

.field public final O:Ljava/lang/StringBuilder;

.field public final O1:[J

.field public final P:Ljava/util/Formatter;

.field public final P1:[Z

.field public final Q:Lt7/n0;

.field public Q1:J

.field public final R:Lt7/o0;

.field public R1:Z

.field public final S:Lm8/o;

.field public final T:Landroid/graphics/drawable/Drawable;

.field public final U:Landroid/graphics/drawable/Drawable;

.field public final V:Landroid/graphics/drawable/Drawable;

.field public final W:Landroid/graphics/drawable/Drawable;

.field public final a0:Landroid/graphics/drawable/Drawable;

.field public final b0:Ljava/lang/String;

.field public final c0:Ljava/lang/String;

.field public final d:Ly9/w;

.field public final d0:Ljava/lang/String;

.field public final e:Landroid/content/res/Resources;

.field public final e0:Landroid/graphics/drawable/Drawable;

.field public final f:Ly9/g;

.field public final f0:Landroid/graphics/drawable/Drawable;

.field public final g:Ljava/lang/Class;

.field public final g0:F

.field public final h:Ljava/lang/reflect/Method;

.field public final i:Ljava/lang/reflect/Method;

.field public final j:Ljava/lang/Class;

.field public final k:Ljava/lang/reflect/Method;

.field public final l:Ljava/lang/reflect/Method;

.field public final m:Ljava/util/concurrent/CopyOnWriteArrayList;

.field public final n:Landroidx/recyclerview/widget/RecyclerView;

.field public final o:Ly9/m;

.field public final p:Ly9/j;

.field public final q:Ly9/f;

.field public final q1:F

.field public final r:Ly9/f;

.field public final r1:Ljava/lang/String;

.field public final s:Lro/f;

.field public final s1:Ljava/lang/String;

.field public final t:Landroid/widget/PopupWindow;

.field public final t1:Landroid/graphics/drawable/Drawable;

.field public final u:I

.field public final u1:Landroid/graphics/drawable/Drawable;

.field public final v:Landroid/widget/ImageView;

.field public final v1:Ljava/lang/String;

.field public final w:Landroid/widget/ImageView;

.field public final w1:Ljava/lang/String;

.field public final x:Landroid/widget/ImageView;

.field public final x1:Landroid/graphics/drawable/Drawable;

.field public final y:Landroid/view/View;

.field public final y1:Landroid/graphics/drawable/Drawable;

.field public final z:Landroid/view/View;

.field public final z1:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "media3.ui"

    .line 2
    .line 3
    invoke-static {v0}, Lt7/y;->a(Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const/4 v0, 0x7

    .line 7
    new-array v0, v0, [F

    .line 8
    .line 9
    fill-array-data v0, :array_0

    .line 10
    .line 11
    .line 12
    sput-object v0, Ly9/r;->S1:[F

    .line 13
    .line 14
    return-void

    .line 15
    :array_0
    .array-data 4
        0x3e800000    # 0.25f
        0x3f000000    # 0.5f
        0x3f400000    # 0.75f
        0x3f800000    # 1.0f
        0x3fa00000    # 1.25f
        0x3fc00000    # 1.5f
        0x40000000    # 2.0f
    .end array-data
.end method

.method public constructor <init>(Landroid/content/Context;Landroid/util/AttributeSet;)V
    .locals 34

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v2, p2

    .line 6
    .line 7
    const-string v3, "isScrubbingModeEnabled"

    .line 8
    .line 9
    sget-object v4, Ljava/lang/Boolean;->TYPE:Ljava/lang/Class;

    .line 10
    .line 11
    const-string v5, "setScrubbingModeEnabled"

    .line 12
    .line 13
    const/4 v6, 0x0

    .line 14
    const/4 v7, 0x0

    .line 15
    invoke-direct {v0, v1, v6, v7}, Landroid/widget/FrameLayout;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;I)V

    .line 16
    .line 17
    .line 18
    const/4 v8, 0x1

    .line 19
    iput-boolean v8, v0, Ly9/r;->F1:Z

    .line 20
    .line 21
    const/16 v9, 0x1388

    .line 22
    .line 23
    iput v9, v0, Ly9/r;->I1:I

    .line 24
    .line 25
    iput v7, v0, Ly9/r;->L1:I

    .line 26
    .line 27
    const/16 v9, 0xc8

    .line 28
    .line 29
    iput v9, v0, Ly9/r;->K1:I

    .line 30
    .line 31
    const v11, 0x7f0d0158

    .line 32
    .line 33
    .line 34
    const v12, 0x7f080138

    .line 35
    .line 36
    .line 37
    const v13, 0x7f080137

    .line 38
    .line 39
    .line 40
    const v14, 0x7f080134

    .line 41
    .line 42
    .line 43
    const v15, 0x7f080141

    .line 44
    .line 45
    .line 46
    const v6, 0x7f080139

    .line 47
    .line 48
    .line 49
    const v9, 0x7f080142

    .line 50
    .line 51
    .line 52
    if-eqz v2, :cond_0

    .line 53
    .line 54
    invoke-virtual {v1}, Landroid/content/Context;->getTheme()Landroid/content/res/Resources$Theme;

    .line 55
    .line 56
    .line 57
    move-result-object v10

    .line 58
    sget-object v8, Ly9/b0;->c:[I

    .line 59
    .line 60
    invoke-virtual {v10, v2, v8, v7, v7}, Landroid/content/res/Resources$Theme;->obtainStyledAttributes(Landroid/util/AttributeSet;[III)Landroid/content/res/TypedArray;

    .line 61
    .line 62
    .line 63
    move-result-object v8

    .line 64
    const/4 v10, 0x6

    .line 65
    :try_start_0
    invoke-virtual {v8, v10, v11}, Landroid/content/res/TypedArray;->getResourceId(II)I

    .line 66
    .line 67
    .line 68
    move-result v11

    .line 69
    const/16 v10, 0xc

    .line 70
    .line 71
    invoke-virtual {v8, v10, v12}, Landroid/content/res/TypedArray;->getResourceId(II)I

    .line 72
    .line 73
    .line 74
    move-result v12

    .line 75
    const/16 v10, 0xb

    .line 76
    .line 77
    invoke-virtual {v8, v10, v13}, Landroid/content/res/TypedArray;->getResourceId(II)I

    .line 78
    .line 79
    .line 80
    move-result v13

    .line 81
    const/16 v10, 0xa

    .line 82
    .line 83
    invoke-virtual {v8, v10, v14}, Landroid/content/res/TypedArray;->getResourceId(II)I

    .line 84
    .line 85
    .line 86
    move-result v14

    .line 87
    const/4 v10, 0x7

    .line 88
    invoke-virtual {v8, v10, v15}, Landroid/content/res/TypedArray;->getResourceId(II)I

    .line 89
    .line 90
    .line 91
    move-result v15

    .line 92
    const/16 v10, 0xf

    .line 93
    .line 94
    invoke-virtual {v8, v10, v6}, Landroid/content/res/TypedArray;->getResourceId(II)I

    .line 95
    .line 96
    .line 97
    move-result v6

    .line 98
    const/16 v10, 0x14

    .line 99
    .line 100
    invoke-virtual {v8, v10, v9}, Landroid/content/res/TypedArray;->getResourceId(II)I

    .line 101
    .line 102
    .line 103
    move-result v9

    .line 104
    const/16 v10, 0x9

    .line 105
    .line 106
    const v7, 0x7f080133

    .line 107
    .line 108
    .line 109
    invoke-virtual {v8, v10, v7}, Landroid/content/res/TypedArray;->getResourceId(II)I

    .line 110
    .line 111
    .line 112
    move-result v7

    .line 113
    move-object/from16 v17, v4

    .line 114
    .line 115
    const v4, 0x7f080132

    .line 116
    .line 117
    .line 118
    const/16 v10, 0x8

    .line 119
    .line 120
    invoke-virtual {v8, v10, v4}, Landroid/content/res/TypedArray;->getResourceId(II)I

    .line 121
    .line 122
    .line 123
    move-result v4

    .line 124
    const/16 v10, 0x11

    .line 125
    .line 126
    move/from16 v26, v4

    .line 127
    .line 128
    const v4, 0x7f08013b

    .line 129
    .line 130
    .line 131
    invoke-virtual {v8, v10, v4}, Landroid/content/res/TypedArray;->getResourceId(II)I

    .line 132
    .line 133
    .line 134
    move-result v10

    .line 135
    const/16 v4, 0x12

    .line 136
    .line 137
    move/from16 v18, v6

    .line 138
    .line 139
    const v6, 0x7f08013c

    .line 140
    .line 141
    .line 142
    invoke-virtual {v8, v4, v6}, Landroid/content/res/TypedArray;->getResourceId(II)I

    .line 143
    .line 144
    .line 145
    move-result v4

    .line 146
    const/16 v6, 0x10

    .line 147
    .line 148
    move/from16 v19, v4

    .line 149
    .line 150
    const v4, 0x7f08013a

    .line 151
    .line 152
    .line 153
    invoke-virtual {v8, v6, v4}, Landroid/content/res/TypedArray;->getResourceId(II)I

    .line 154
    .line 155
    .line 156
    move-result v4

    .line 157
    const/16 v6, 0x23

    .line 158
    .line 159
    move/from16 v20, v4

    .line 160
    .line 161
    const v4, 0x7f080140

    .line 162
    .line 163
    .line 164
    invoke-virtual {v8, v6, v4}, Landroid/content/res/TypedArray;->getResourceId(II)I

    .line 165
    .line 166
    .line 167
    move-result v4

    .line 168
    const/16 v6, 0x22

    .line 169
    .line 170
    move/from16 v21, v4

    .line 171
    .line 172
    const v4, 0x7f08013f

    .line 173
    .line 174
    .line 175
    invoke-virtual {v8, v6, v4}, Landroid/content/res/TypedArray;->getResourceId(II)I

    .line 176
    .line 177
    .line 178
    move-result v4

    .line 179
    const/16 v6, 0x25

    .line 180
    .line 181
    move/from16 v22, v4

    .line 182
    .line 183
    const v4, 0x7f080145

    .line 184
    .line 185
    .line 186
    invoke-virtual {v8, v6, v4}, Landroid/content/res/TypedArray;->getResourceId(II)I

    .line 187
    .line 188
    .line 189
    move-result v4

    .line 190
    const/16 v6, 0x24

    .line 191
    .line 192
    move/from16 v23, v4

    .line 193
    .line 194
    const v4, 0x7f080144

    .line 195
    .line 196
    .line 197
    invoke-virtual {v8, v6, v4}, Landroid/content/res/TypedArray;->getResourceId(II)I

    .line 198
    .line 199
    .line 200
    move-result v4

    .line 201
    const/16 v6, 0x2a

    .line 202
    .line 203
    move/from16 v24, v4

    .line 204
    .line 205
    const v4, 0x7f080146

    .line 206
    .line 207
    .line 208
    invoke-virtual {v8, v6, v4}, Landroid/content/res/TypedArray;->getResourceId(II)I

    .line 209
    .line 210
    .line 211
    move-result v4

    .line 212
    iget v6, v0, Ly9/r;->I1:I

    .line 213
    .line 214
    move/from16 v25, v4

    .line 215
    .line 216
    const/16 v4, 0x20

    .line 217
    .line 218
    invoke-virtual {v8, v4, v6}, Landroid/content/res/TypedArray;->getInt(II)I

    .line 219
    .line 220
    .line 221
    move-result v4

    .line 222
    iput v4, v0, Ly9/r;->I1:I

    .line 223
    .line 224
    iget v4, v0, Ly9/r;->L1:I

    .line 225
    .line 226
    const/16 v6, 0x13

    .line 227
    .line 228
    invoke-virtual {v8, v6, v4}, Landroid/content/res/TypedArray;->getInt(II)I

    .line 229
    .line 230
    .line 231
    move-result v4

    .line 232
    iput v4, v0, Ly9/r;->L1:I

    .line 233
    .line 234
    const/16 v4, 0x1d

    .line 235
    .line 236
    const/4 v6, 0x1

    .line 237
    invoke-virtual {v8, v4, v6}, Landroid/content/res/TypedArray;->getBoolean(IZ)Z

    .line 238
    .line 239
    .line 240
    move-result v4

    .line 241
    move/from16 v27, v4

    .line 242
    .line 243
    const/16 v4, 0x1a

    .line 244
    .line 245
    invoke-virtual {v8, v4, v6}, Landroid/content/res/TypedArray;->getBoolean(IZ)Z

    .line 246
    .line 247
    .line 248
    move-result v4

    .line 249
    move/from16 v28, v4

    .line 250
    .line 251
    const/16 v4, 0x1c

    .line 252
    .line 253
    invoke-virtual {v8, v4, v6}, Landroid/content/res/TypedArray;->getBoolean(IZ)Z

    .line 254
    .line 255
    .line 256
    move-result v29

    .line 257
    const/16 v4, 0x1b

    .line 258
    .line 259
    invoke-virtual {v8, v4, v6}, Landroid/content/res/TypedArray;->getBoolean(IZ)Z

    .line 260
    .line 261
    .line 262
    move-result v4

    .line 263
    const/16 v6, 0x1e

    .line 264
    .line 265
    move/from16 v30, v4

    .line 266
    .line 267
    const/4 v4, 0x0

    .line 268
    invoke-virtual {v8, v6, v4}, Landroid/content/res/TypedArray;->getBoolean(IZ)Z

    .line 269
    .line 270
    .line 271
    move-result v6

    .line 272
    move/from16 v31, v6

    .line 273
    .line 274
    const/16 v6, 0x1f

    .line 275
    .line 276
    invoke-virtual {v8, v6, v4}, Landroid/content/res/TypedArray;->getBoolean(IZ)Z

    .line 277
    .line 278
    .line 279
    move-result v6

    .line 280
    move/from16 v32, v6

    .line 281
    .line 282
    const/16 v6, 0x21

    .line 283
    .line 284
    invoke-virtual {v8, v6, v4}, Landroid/content/res/TypedArray;->getBoolean(IZ)Z

    .line 285
    .line 286
    .line 287
    move-result v6

    .line 288
    move/from16 v33, v6

    .line 289
    .line 290
    const/16 v6, 0x27

    .line 291
    .line 292
    invoke-virtual {v8, v6, v4}, Landroid/content/res/TypedArray;->getBoolean(IZ)Z

    .line 293
    .line 294
    .line 295
    move-result v6

    .line 296
    iput-boolean v6, v0, Ly9/r;->J1:Z

    .line 297
    .line 298
    iget v4, v0, Ly9/r;->K1:I

    .line 299
    .line 300
    const/16 v6, 0x26

    .line 301
    .line 302
    invoke-virtual {v8, v6, v4}, Landroid/content/res/TypedArray;->getInt(II)I

    .line 303
    .line 304
    .line 305
    move-result v4

    .line 306
    invoke-virtual {v0, v4}, Ly9/r;->setTimeBarMinUpdateInterval(I)V

    .line 307
    .line 308
    .line 309
    const/4 v4, 0x2

    .line 310
    const/4 v6, 0x1

    .line 311
    invoke-virtual {v8, v4, v6}, Landroid/content/res/TypedArray;->getBoolean(IZ)Z

    .line 312
    .line 313
    .line 314
    move-result v4
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 315
    invoke-virtual {v8}, Landroid/content/res/TypedArray;->recycle()V

    .line 316
    .line 317
    .line 318
    move/from16 v6, v31

    .line 319
    .line 320
    move/from16 v31, v7

    .line 321
    .line 322
    move v7, v15

    .line 323
    move/from16 v15, v25

    .line 324
    .line 325
    move/from16 v25, v22

    .line 326
    .line 327
    move/from16 v22, v29

    .line 328
    .line 329
    move/from16 v29, v10

    .line 330
    .line 331
    move/from16 v10, v23

    .line 332
    .line 333
    move/from16 v23, v27

    .line 334
    .line 335
    move/from16 v27, v20

    .line 336
    .line 337
    move/from16 v20, v6

    .line 338
    .line 339
    move/from16 v6, v26

    .line 340
    .line 341
    move/from16 v26, v21

    .line 342
    .line 343
    move/from16 v21, v30

    .line 344
    .line 345
    move/from16 v30, v6

    .line 346
    .line 347
    move v6, v14

    .line 348
    move/from16 v8, v18

    .line 349
    .line 350
    move/from16 v18, v33

    .line 351
    .line 352
    move v14, v9

    .line 353
    move/from16 v9, v24

    .line 354
    .line 355
    move/from16 v24, v28

    .line 356
    .line 357
    move/from16 v28, v19

    .line 358
    .line 359
    move/from16 v19, v32

    .line 360
    .line 361
    move/from16 v32, v13

    .line 362
    .line 363
    move v13, v4

    .line 364
    goto :goto_0

    .line 365
    :catchall_0
    move-exception v0

    .line 366
    invoke-virtual {v8}, Landroid/content/res/TypedArray;->recycle()V

    .line 367
    .line 368
    .line 369
    throw v0

    .line 370
    :cond_0
    move-object/from16 v17, v4

    .line 371
    .line 372
    move v8, v6

    .line 373
    const v4, 0x7f080146

    .line 374
    .line 375
    .line 376
    const v6, 0x7f08013c

    .line 377
    .line 378
    .line 379
    const v7, 0x7f080133

    .line 380
    .line 381
    .line 382
    const v10, 0x7f080132

    .line 383
    .line 384
    .line 385
    const v18, 0x7f08013b

    .line 386
    .line 387
    .line 388
    const v20, 0x7f08013a

    .line 389
    .line 390
    .line 391
    const v21, 0x7f080140

    .line 392
    .line 393
    .line 394
    const v22, 0x7f08013f

    .line 395
    .line 396
    .line 397
    const v23, 0x7f080145

    .line 398
    .line 399
    .line 400
    const v24, 0x7f080144

    .line 401
    .line 402
    .line 403
    move/from16 v28, v6

    .line 404
    .line 405
    move/from16 v31, v7

    .line 406
    .line 407
    move/from16 v30, v10

    .line 408
    .line 409
    move/from16 v32, v13

    .line 410
    .line 411
    move v6, v14

    .line 412
    move v7, v15

    .line 413
    move/from16 v29, v18

    .line 414
    .line 415
    move/from16 v27, v20

    .line 416
    .line 417
    move/from16 v26, v21

    .line 418
    .line 419
    move/from16 v25, v22

    .line 420
    .line 421
    move/from16 v10, v23

    .line 422
    .line 423
    const/4 v13, 0x1

    .line 424
    const/16 v18, 0x0

    .line 425
    .line 426
    const/16 v19, 0x0

    .line 427
    .line 428
    const/16 v20, 0x0

    .line 429
    .line 430
    const/16 v21, 0x1

    .line 431
    .line 432
    const/16 v22, 0x1

    .line 433
    .line 434
    const/16 v23, 0x1

    .line 435
    .line 436
    move v15, v4

    .line 437
    move v14, v9

    .line 438
    move/from16 v9, v24

    .line 439
    .line 440
    const/16 v24, 0x1

    .line 441
    .line 442
    :goto_0
    invoke-static {v1}, Landroid/view/LayoutInflater;->from(Landroid/content/Context;)Landroid/view/LayoutInflater;

    .line 443
    .line 444
    .line 445
    move-result-object v4

    .line 446
    invoke-virtual {v4, v11, v0}, Landroid/view/LayoutInflater;->inflate(ILandroid/view/ViewGroup;)Landroid/view/View;

    .line 447
    .line 448
    .line 449
    const/high16 v4, 0x40000

    .line 450
    .line 451
    invoke-virtual {v0, v4}, Landroid/view/ViewGroup;->setDescendantFocusability(I)V

    .line 452
    .line 453
    .line 454
    new-instance v4, Ly9/g;

    .line 455
    .line 456
    invoke-direct {v4, v0}, Ly9/g;-><init>(Ly9/r;)V

    .line 457
    .line 458
    .line 459
    iput-object v4, v0, Ly9/r;->f:Ly9/g;

    .line 460
    .line 461
    new-instance v4, Ljava/util/concurrent/CopyOnWriteArrayList;

    .line 462
    .line 463
    invoke-direct {v4}, Ljava/util/concurrent/CopyOnWriteArrayList;-><init>()V

    .line 464
    .line 465
    .line 466
    iput-object v4, v0, Ly9/r;->m:Ljava/util/concurrent/CopyOnWriteArrayList;

    .line 467
    .line 468
    new-instance v4, Lt7/n0;

    .line 469
    .line 470
    invoke-direct {v4}, Lt7/n0;-><init>()V

    .line 471
    .line 472
    .line 473
    iput-object v4, v0, Ly9/r;->Q:Lt7/n0;

    .line 474
    .line 475
    new-instance v4, Lt7/o0;

    .line 476
    .line 477
    invoke-direct {v4}, Lt7/o0;-><init>()V

    .line 478
    .line 479
    .line 480
    iput-object v4, v0, Ly9/r;->R:Lt7/o0;

    .line 481
    .line 482
    new-instance v4, Ljava/lang/StringBuilder;

    .line 483
    .line 484
    invoke-direct {v4}, Ljava/lang/StringBuilder;-><init>()V

    .line 485
    .line 486
    .line 487
    iput-object v4, v0, Ly9/r;->O:Ljava/lang/StringBuilder;

    .line 488
    .line 489
    new-instance v11, Ljava/util/Formatter;

    .line 490
    .line 491
    move/from16 v33, v12

    .line 492
    .line 493
    invoke-static {}, Ljava/util/Locale;->getDefault()Ljava/util/Locale;

    .line 494
    .line 495
    .line 496
    move-result-object v12

    .line 497
    invoke-direct {v11, v4, v12}, Ljava/util/Formatter;-><init>(Ljava/lang/Appendable;Ljava/util/Locale;)V

    .line 498
    .line 499
    .line 500
    iput-object v11, v0, Ly9/r;->P:Ljava/util/Formatter;

    .line 501
    .line 502
    const/4 v4, 0x0

    .line 503
    new-array v11, v4, [J

    .line 504
    .line 505
    iput-object v11, v0, Ly9/r;->M1:[J

    .line 506
    .line 507
    new-array v11, v4, [Z

    .line 508
    .line 509
    iput-object v11, v0, Ly9/r;->N1:[Z

    .line 510
    .line 511
    new-array v11, v4, [J

    .line 512
    .line 513
    iput-object v11, v0, Ly9/r;->O1:[J

    .line 514
    .line 515
    new-array v11, v4, [Z

    .line 516
    .line 517
    iput-object v11, v0, Ly9/r;->P1:[Z

    .line 518
    .line 519
    new-instance v4, Lm8/o;

    .line 520
    .line 521
    const/16 v11, 0x1c

    .line 522
    .line 523
    invoke-direct {v4, v0, v11}, Lm8/o;-><init>(Ljava/lang/Object;I)V

    .line 524
    .line 525
    .line 526
    iput-object v4, v0, Ly9/r;->S:Lm8/o;

    .line 527
    .line 528
    :try_start_1
    const-class v4, Landroidx/media3/exoplayer/ExoPlayer;
    :try_end_1
    .catch Ljava/lang/ClassNotFoundException; {:try_start_1 .. :try_end_1} :catch_1
    .catch Ljava/lang/NoSuchMethodException; {:try_start_1 .. :try_end_1} :catch_1

    .line 529
    .line 530
    :try_start_2
    filled-new-array/range {v17 .. v17}, [Ljava/lang/Class;

    .line 531
    .line 532
    .line 533
    move-result-object v11

    .line 534
    invoke-virtual {v4, v5, v11}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 535
    .line 536
    .line 537
    move-result-object v11
    :try_end_2
    .catch Ljava/lang/ClassNotFoundException; {:try_start_2 .. :try_end_2} :catch_0
    .catch Ljava/lang/NoSuchMethodException; {:try_start_2 .. :try_end_2} :catch_0

    .line 538
    const/4 v12, 0x0

    .line 539
    :try_start_3
    invoke-virtual {v4, v3, v12}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 540
    .line 541
    .line 542
    move-result-object v16
    :try_end_3
    .catch Ljava/lang/ClassNotFoundException; {:try_start_3 .. :try_end_3} :catch_2
    .catch Ljava/lang/NoSuchMethodException; {:try_start_3 .. :try_end_3} :catch_2

    .line 543
    move-object/from16 v12, v16

    .line 544
    .line 545
    goto :goto_3

    .line 546
    :catch_0
    :goto_1
    const/4 v11, 0x0

    .line 547
    goto :goto_2

    .line 548
    :catch_1
    const/4 v4, 0x0

    .line 549
    goto :goto_1

    .line 550
    :catch_2
    :goto_2
    const/4 v12, 0x0

    .line 551
    :goto_3
    iput-object v4, v0, Ly9/r;->g:Ljava/lang/Class;

    .line 552
    .line 553
    iput-object v11, v0, Ly9/r;->h:Ljava/lang/reflect/Method;

    .line 554
    .line 555
    iput-object v12, v0, Ly9/r;->i:Ljava/lang/reflect/Method;

    .line 556
    .line 557
    :try_start_4
    const-string v4, "androidx.media3.transformer.CompositionPlayer"

    .line 558
    .line 559
    invoke-static {v4}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;

    .line 560
    .line 561
    .line 562
    move-result-object v4
    :try_end_4
    .catch Ljava/lang/ClassNotFoundException; {:try_start_4 .. :try_end_4} :catch_4
    .catch Ljava/lang/NoSuchMethodException; {:try_start_4 .. :try_end_4} :catch_4

    .line 563
    :try_start_5
    filled-new-array/range {v17 .. v17}, [Ljava/lang/Class;

    .line 564
    .line 565
    .line 566
    move-result-object v11

    .line 567
    invoke-virtual {v4, v5, v11}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 568
    .line 569
    .line 570
    move-result-object v5
    :try_end_5
    .catch Ljava/lang/ClassNotFoundException; {:try_start_5 .. :try_end_5} :catch_3
    .catch Ljava/lang/NoSuchMethodException; {:try_start_5 .. :try_end_5} :catch_3

    .line 571
    const/4 v12, 0x0

    .line 572
    :try_start_6
    invoke-virtual {v4, v3, v12}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 573
    .line 574
    .line 575
    move-result-object v3
    :try_end_6
    .catch Ljava/lang/ClassNotFoundException; {:try_start_6 .. :try_end_6} :catch_5
    .catch Ljava/lang/NoSuchMethodException; {:try_start_6 .. :try_end_6} :catch_5

    .line 576
    goto :goto_6

    .line 577
    :catch_3
    :goto_4
    const/4 v5, 0x0

    .line 578
    goto :goto_5

    .line 579
    :catch_4
    const/4 v4, 0x0

    .line 580
    goto :goto_4

    .line 581
    :catch_5
    :goto_5
    const/4 v3, 0x0

    .line 582
    :goto_6
    iput-object v4, v0, Ly9/r;->j:Ljava/lang/Class;

    .line 583
    .line 584
    iput-object v5, v0, Ly9/r;->k:Ljava/lang/reflect/Method;

    .line 585
    .line 586
    iput-object v3, v0, Ly9/r;->l:Ljava/lang/reflect/Method;

    .line 587
    .line 588
    const v3, 0x7f0a0139

    .line 589
    .line 590
    .line 591
    invoke-virtual {v0, v3}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 592
    .line 593
    .line 594
    move-result-object v3

    .line 595
    check-cast v3, Landroid/widget/TextView;

    .line 596
    .line 597
    iput-object v3, v0, Ly9/r;->L:Landroid/widget/TextView;

    .line 598
    .line 599
    const v3, 0x7f0a014d

    .line 600
    .line 601
    .line 602
    invoke-virtual {v0, v3}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 603
    .line 604
    .line 605
    move-result-object v3

    .line 606
    check-cast v3, Landroid/widget/TextView;

    .line 607
    .line 608
    iput-object v3, v0, Ly9/r;->M:Landroid/widget/TextView;

    .line 609
    .line 610
    const v3, 0x7f0a0159

    .line 611
    .line 612
    .line 613
    invoke-virtual {v0, v3}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 614
    .line 615
    .line 616
    move-result-object v3

    .line 617
    check-cast v3, Landroid/widget/ImageView;

    .line 618
    .line 619
    iput-object v3, v0, Ly9/r;->F:Landroid/widget/ImageView;

    .line 620
    .line 621
    if-eqz v3, :cond_1

    .line 622
    .line 623
    iget-object v4, v0, Ly9/r;->f:Ly9/g;

    .line 624
    .line 625
    invoke-virtual {v3, v4}, Landroid/view/View;->setOnClickListener(Landroid/view/View$OnClickListener;)V

    .line 626
    .line 627
    .line 628
    :cond_1
    const v4, 0x7f0a013f

    .line 629
    .line 630
    .line 631
    invoke-virtual {v0, v4}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 632
    .line 633
    .line 634
    move-result-object v4

    .line 635
    check-cast v4, Landroid/widget/ImageView;

    .line 636
    .line 637
    iput-object v4, v0, Ly9/r;->G:Landroid/widget/ImageView;

    .line 638
    .line 639
    new-instance v5, Ly9/e;

    .line 640
    .line 641
    const/4 v11, 0x0

    .line 642
    invoke-direct {v5, v0, v11}, Ly9/e;-><init>(Ljava/lang/Object;I)V

    .line 643
    .line 644
    .line 645
    if-nez v4, :cond_2

    .line 646
    .line 647
    const/16 v12, 0x8

    .line 648
    .line 649
    goto :goto_7

    .line 650
    :cond_2
    const/16 v12, 0x8

    .line 651
    .line 652
    invoke-virtual {v4, v12}, Landroid/view/View;->setVisibility(I)V

    .line 653
    .line 654
    .line 655
    invoke-virtual {v4, v5}, Landroid/view/View;->setOnClickListener(Landroid/view/View$OnClickListener;)V

    .line 656
    .line 657
    .line 658
    :goto_7
    const v4, 0x7f0a0144

    .line 659
    .line 660
    .line 661
    invoke-virtual {v0, v4}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 662
    .line 663
    .line 664
    move-result-object v4

    .line 665
    check-cast v4, Landroid/widget/ImageView;

    .line 666
    .line 667
    iput-object v4, v0, Ly9/r;->H:Landroid/widget/ImageView;

    .line 668
    .line 669
    new-instance v5, Ly9/e;

    .line 670
    .line 671
    invoke-direct {v5, v0, v11}, Ly9/e;-><init>(Ljava/lang/Object;I)V

    .line 672
    .line 673
    .line 674
    if-nez v4, :cond_3

    .line 675
    .line 676
    goto :goto_8

    .line 677
    :cond_3
    invoke-virtual {v4, v12}, Landroid/view/View;->setVisibility(I)V

    .line 678
    .line 679
    .line 680
    invoke-virtual {v4, v5}, Landroid/view/View;->setOnClickListener(Landroid/view/View$OnClickListener;)V

    .line 681
    .line 682
    .line 683
    :goto_8
    const v4, 0x7f0a0154

    .line 684
    .line 685
    .line 686
    invoke-virtual {v0, v4}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 687
    .line 688
    .line 689
    move-result-object v4

    .line 690
    iput-object v4, v0, Ly9/r;->I:Landroid/view/View;

    .line 691
    .line 692
    if-eqz v4, :cond_4

    .line 693
    .line 694
    iget-object v5, v0, Ly9/r;->f:Ly9/g;

    .line 695
    .line 696
    invoke-virtual {v4, v5}, Landroid/view/View;->setOnClickListener(Landroid/view/View$OnClickListener;)V

    .line 697
    .line 698
    .line 699
    :cond_4
    const v4, 0x7f0a014c

    .line 700
    .line 701
    .line 702
    invoke-virtual {v0, v4}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 703
    .line 704
    .line 705
    move-result-object v4

    .line 706
    iput-object v4, v0, Ly9/r;->J:Landroid/view/View;

    .line 707
    .line 708
    if-eqz v4, :cond_5

    .line 709
    .line 710
    iget-object v5, v0, Ly9/r;->f:Ly9/g;

    .line 711
    .line 712
    invoke-virtual {v4, v5}, Landroid/view/View;->setOnClickListener(Landroid/view/View$OnClickListener;)V

    .line 713
    .line 714
    .line 715
    :cond_5
    const v4, 0x7f0a012f

    .line 716
    .line 717
    .line 718
    invoke-virtual {v0, v4}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 719
    .line 720
    .line 721
    move-result-object v4

    .line 722
    iput-object v4, v0, Ly9/r;->K:Landroid/view/View;

    .line 723
    .line 724
    if-eqz v4, :cond_6

    .line 725
    .line 726
    iget-object v5, v0, Ly9/r;->f:Ly9/g;

    .line 727
    .line 728
    invoke-virtual {v4, v5}, Landroid/view/View;->setOnClickListener(Landroid/view/View$OnClickListener;)V

    .line 729
    .line 730
    .line 731
    :cond_6
    const v4, 0x7f0a014f

    .line 732
    .line 733
    .line 734
    invoke-virtual {v0, v4}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 735
    .line 736
    .line 737
    move-result-object v5

    .line 738
    check-cast v5, Ly9/h0;

    .line 739
    .line 740
    const v11, 0x7f0a0150

    .line 741
    .line 742
    .line 743
    invoke-virtual {v0, v11}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 744
    .line 745
    .line 746
    move-result-object v11

    .line 747
    if-eqz v5, :cond_7

    .line 748
    .line 749
    iput-object v5, v0, Ly9/r;->N:Ly9/h0;

    .line 750
    .line 751
    goto :goto_9

    .line 752
    :cond_7
    if-eqz v11, :cond_8

    .line 753
    .line 754
    new-instance v5, Ly9/d;

    .line 755
    .line 756
    invoke-direct {v5, v1, v2}, Ly9/d;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;)V

    .line 757
    .line 758
    .line 759
    invoke-virtual {v5, v4}, Landroid/view/View;->setId(I)V

    .line 760
    .line 761
    .line 762
    invoke-virtual {v11}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 763
    .line 764
    .line 765
    move-result-object v2

    .line 766
    invoke-virtual {v5, v2}, Landroid/view/View;->setLayoutParams(Landroid/view/ViewGroup$LayoutParams;)V

    .line 767
    .line 768
    .line 769
    invoke-virtual {v11}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    .line 770
    .line 771
    .line 772
    move-result-object v2

    .line 773
    check-cast v2, Landroid/view/ViewGroup;

    .line 774
    .line 775
    invoke-virtual {v2, v11}, Landroid/view/ViewGroup;->indexOfChild(Landroid/view/View;)I

    .line 776
    .line 777
    .line 778
    move-result v4

    .line 779
    invoke-virtual {v2, v11}, Landroid/view/ViewGroup;->removeView(Landroid/view/View;)V

    .line 780
    .line 781
    .line 782
    invoke-virtual {v2, v5, v4}, Landroid/view/ViewGroup;->addView(Landroid/view/View;I)V

    .line 783
    .line 784
    .line 785
    iput-object v5, v0, Ly9/r;->N:Ly9/h0;

    .line 786
    .line 787
    goto :goto_9

    .line 788
    :cond_8
    const/4 v12, 0x0

    .line 789
    iput-object v12, v0, Ly9/r;->N:Ly9/h0;

    .line 790
    .line 791
    :goto_9
    iget-object v2, v0, Ly9/r;->N:Ly9/h0;

    .line 792
    .line 793
    if-eqz v2, :cond_9

    .line 794
    .line 795
    iget-object v4, v0, Ly9/r;->f:Ly9/g;

    .line 796
    .line 797
    check-cast v2, Ly9/d;

    .line 798
    .line 799
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 800
    .line 801
    .line 802
    iget-object v2, v2, Ly9/d;->A:Ljava/util/concurrent/CopyOnWriteArraySet;

    .line 803
    .line 804
    invoke-virtual {v2, v4}, Ljava/util/concurrent/CopyOnWriteArraySet;->add(Ljava/lang/Object;)Z

    .line 805
    .line 806
    .line 807
    :cond_9
    invoke-virtual {v1}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 808
    .line 809
    .line 810
    move-result-object v2

    .line 811
    iput-object v2, v0, Ly9/r;->e:Landroid/content/res/Resources;

    .line 812
    .line 813
    const v4, 0x7f0a014b

    .line 814
    .line 815
    .line 816
    invoke-virtual {v0, v4}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 817
    .line 818
    .line 819
    move-result-object v4

    .line 820
    check-cast v4, Landroid/widget/ImageView;

    .line 821
    .line 822
    iput-object v4, v0, Ly9/r;->x:Landroid/widget/ImageView;

    .line 823
    .line 824
    if-eqz v4, :cond_a

    .line 825
    .line 826
    iget-object v5, v0, Ly9/r;->f:Ly9/g;

    .line 827
    .line 828
    invoke-virtual {v4, v5}, Landroid/view/View;->setOnClickListener(Landroid/view/View$OnClickListener;)V

    .line 829
    .line 830
    .line 831
    :cond_a
    const v4, 0x7f0a014e

    .line 832
    .line 833
    .line 834
    invoke-virtual {v0, v4}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 835
    .line 836
    .line 837
    move-result-object v4

    .line 838
    check-cast v4, Landroid/widget/ImageView;

    .line 839
    .line 840
    iput-object v4, v0, Ly9/r;->v:Landroid/widget/ImageView;

    .line 841
    .line 842
    if-eqz v4, :cond_b

    .line 843
    .line 844
    invoke-virtual {v1}, Landroid/content/Context;->getTheme()Landroid/content/res/Resources$Theme;

    .line 845
    .line 846
    .line 847
    move-result-object v5

    .line 848
    invoke-virtual {v2, v8, v5}, Landroid/content/res/Resources;->getDrawable(ILandroid/content/res/Resources$Theme;)Landroid/graphics/drawable/Drawable;

    .line 849
    .line 850
    .line 851
    move-result-object v5

    .line 852
    invoke-virtual {v4, v5}, Landroid/widget/ImageView;->setImageDrawable(Landroid/graphics/drawable/Drawable;)V

    .line 853
    .line 854
    .line 855
    iget-object v5, v0, Ly9/r;->f:Ly9/g;

    .line 856
    .line 857
    invoke-virtual {v4, v5}, Landroid/view/View;->setOnClickListener(Landroid/view/View$OnClickListener;)V

    .line 858
    .line 859
    .line 860
    :cond_b
    const v5, 0x7f0a0145

    .line 861
    .line 862
    .line 863
    invoke-virtual {v0, v5}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 864
    .line 865
    .line 866
    move-result-object v5

    .line 867
    check-cast v5, Landroid/widget/ImageView;

    .line 868
    .line 869
    iput-object v5, v0, Ly9/r;->w:Landroid/widget/ImageView;

    .line 870
    .line 871
    if-eqz v5, :cond_c

    .line 872
    .line 873
    invoke-virtual {v1}, Landroid/content/Context;->getTheme()Landroid/content/res/Resources$Theme;

    .line 874
    .line 875
    .line 876
    move-result-object v8

    .line 877
    invoke-virtual {v2, v6, v8}, Landroid/content/res/Resources;->getDrawable(ILandroid/content/res/Resources$Theme;)Landroid/graphics/drawable/Drawable;

    .line 878
    .line 879
    .line 880
    move-result-object v6

    .line 881
    invoke-virtual {v5, v6}, Landroid/widget/ImageView;->setImageDrawable(Landroid/graphics/drawable/Drawable;)V

    .line 882
    .line 883
    .line 884
    iget-object v6, v0, Ly9/r;->f:Ly9/g;

    .line 885
    .line 886
    invoke-virtual {v5, v6}, Landroid/view/View;->setOnClickListener(Landroid/view/View$OnClickListener;)V

    .line 887
    .line 888
    .line 889
    :cond_c
    const v6, 0x7f090002

    .line 890
    .line 891
    .line 892
    invoke-static {v1, v6}, Lp5/j;->a(Landroid/content/Context;I)Landroid/graphics/Typeface;

    .line 893
    .line 894
    .line 895
    move-result-object v6

    .line 896
    const v8, 0x7f0a0152

    .line 897
    .line 898
    .line 899
    invoke-virtual {v0, v8}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 900
    .line 901
    .line 902
    move-result-object v8

    .line 903
    check-cast v8, Landroid/widget/ImageView;

    .line 904
    .line 905
    const v11, 0x7f0a0153

    .line 906
    .line 907
    .line 908
    invoke-virtual {v0, v11}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 909
    .line 910
    .line 911
    move-result-object v11

    .line 912
    check-cast v11, Landroid/widget/TextView;

    .line 913
    .line 914
    if-eqz v8, :cond_d

    .line 915
    .line 916
    invoke-virtual {v1}, Landroid/content/Context;->getTheme()Landroid/content/res/Resources$Theme;

    .line 917
    .line 918
    .line 919
    move-result-object v11

    .line 920
    invoke-virtual {v2, v14, v11}, Landroid/content/res/Resources;->getDrawable(ILandroid/content/res/Resources$Theme;)Landroid/graphics/drawable/Drawable;

    .line 921
    .line 922
    .line 923
    move-result-object v11

    .line 924
    invoke-virtual {v8, v11}, Landroid/widget/ImageView;->setImageDrawable(Landroid/graphics/drawable/Drawable;)V

    .line 925
    .line 926
    .line 927
    iput-object v8, v0, Ly9/r;->z:Landroid/view/View;

    .line 928
    .line 929
    const/4 v12, 0x0

    .line 930
    iput-object v12, v0, Ly9/r;->B:Landroid/widget/TextView;

    .line 931
    .line 932
    goto :goto_a

    .line 933
    :cond_d
    const/4 v12, 0x0

    .line 934
    if-eqz v11, :cond_e

    .line 935
    .line 936
    invoke-virtual {v11, v6}, Landroid/widget/TextView;->setTypeface(Landroid/graphics/Typeface;)V

    .line 937
    .line 938
    .line 939
    iput-object v11, v0, Ly9/r;->B:Landroid/widget/TextView;

    .line 940
    .line 941
    iput-object v11, v0, Ly9/r;->z:Landroid/view/View;

    .line 942
    .line 943
    goto :goto_a

    .line 944
    :cond_e
    iput-object v12, v0, Ly9/r;->B:Landroid/widget/TextView;

    .line 945
    .line 946
    iput-object v12, v0, Ly9/r;->z:Landroid/view/View;

    .line 947
    .line 948
    :goto_a
    iget-object v8, v0, Ly9/r;->z:Landroid/view/View;

    .line 949
    .line 950
    if-eqz v8, :cond_f

    .line 951
    .line 952
    iget-object v11, v0, Ly9/r;->f:Ly9/g;

    .line 953
    .line 954
    invoke-virtual {v8, v11}, Landroid/view/View;->setOnClickListener(Landroid/view/View$OnClickListener;)V

    .line 955
    .line 956
    .line 957
    :cond_f
    const v8, 0x7f0a013d

    .line 958
    .line 959
    .line 960
    invoke-virtual {v0, v8}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 961
    .line 962
    .line 963
    move-result-object v8

    .line 964
    check-cast v8, Landroid/widget/ImageView;

    .line 965
    .line 966
    const v11, 0x7f0a013e

    .line 967
    .line 968
    .line 969
    invoke-virtual {v0, v11}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 970
    .line 971
    .line 972
    move-result-object v11

    .line 973
    check-cast v11, Landroid/widget/TextView;

    .line 974
    .line 975
    if-eqz v8, :cond_10

    .line 976
    .line 977
    invoke-virtual {v1}, Landroid/content/Context;->getTheme()Landroid/content/res/Resources$Theme;

    .line 978
    .line 979
    .line 980
    move-result-object v6

    .line 981
    invoke-virtual {v2, v7, v6}, Landroid/content/res/Resources;->getDrawable(ILandroid/content/res/Resources$Theme;)Landroid/graphics/drawable/Drawable;

    .line 982
    .line 983
    .line 984
    move-result-object v6

    .line 985
    invoke-virtual {v8, v6}, Landroid/widget/ImageView;->setImageDrawable(Landroid/graphics/drawable/Drawable;)V

    .line 986
    .line 987
    .line 988
    iput-object v8, v0, Ly9/r;->y:Landroid/view/View;

    .line 989
    .line 990
    const/4 v12, 0x0

    .line 991
    iput-object v12, v0, Ly9/r;->A:Landroid/widget/TextView;

    .line 992
    .line 993
    goto :goto_b

    .line 994
    :cond_10
    const/4 v12, 0x0

    .line 995
    if-eqz v11, :cond_11

    .line 996
    .line 997
    invoke-virtual {v11, v6}, Landroid/widget/TextView;->setTypeface(Landroid/graphics/Typeface;)V

    .line 998
    .line 999
    .line 1000
    iput-object v11, v0, Ly9/r;->A:Landroid/widget/TextView;

    .line 1001
    .line 1002
    iput-object v11, v0, Ly9/r;->y:Landroid/view/View;

    .line 1003
    .line 1004
    goto :goto_b

    .line 1005
    :cond_11
    iput-object v12, v0, Ly9/r;->A:Landroid/widget/TextView;

    .line 1006
    .line 1007
    iput-object v12, v0, Ly9/r;->y:Landroid/view/View;

    .line 1008
    .line 1009
    :goto_b
    iget-object v6, v0, Ly9/r;->y:Landroid/view/View;

    .line 1010
    .line 1011
    if-eqz v6, :cond_12

    .line 1012
    .line 1013
    iget-object v7, v0, Ly9/r;->f:Ly9/g;

    .line 1014
    .line 1015
    invoke-virtual {v6, v7}, Landroid/view/View;->setOnClickListener(Landroid/view/View$OnClickListener;)V

    .line 1016
    .line 1017
    .line 1018
    :cond_12
    const v6, 0x7f0a0151

    .line 1019
    .line 1020
    .line 1021
    invoke-virtual {v0, v6}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 1022
    .line 1023
    .line 1024
    move-result-object v6

    .line 1025
    check-cast v6, Landroid/widget/ImageView;

    .line 1026
    .line 1027
    iput-object v6, v0, Ly9/r;->C:Landroid/widget/ImageView;

    .line 1028
    .line 1029
    if-eqz v6, :cond_13

    .line 1030
    .line 1031
    iget-object v7, v0, Ly9/r;->f:Ly9/g;

    .line 1032
    .line 1033
    invoke-virtual {v6, v7}, Landroid/view/View;->setOnClickListener(Landroid/view/View$OnClickListener;)V

    .line 1034
    .line 1035
    .line 1036
    :cond_13
    const v7, 0x7f0a0156

    .line 1037
    .line 1038
    .line 1039
    invoke-virtual {v0, v7}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 1040
    .line 1041
    .line 1042
    move-result-object v7

    .line 1043
    check-cast v7, Landroid/widget/ImageView;

    .line 1044
    .line 1045
    iput-object v7, v0, Ly9/r;->D:Landroid/widget/ImageView;

    .line 1046
    .line 1047
    if-eqz v7, :cond_14

    .line 1048
    .line 1049
    iget-object v8, v0, Ly9/r;->f:Ly9/g;

    .line 1050
    .line 1051
    invoke-virtual {v7, v8}, Landroid/view/View;->setOnClickListener(Landroid/view/View$OnClickListener;)V

    .line 1052
    .line 1053
    .line 1054
    :cond_14
    const v8, 0x7f0b000a

    .line 1055
    .line 1056
    .line 1057
    invoke-virtual {v2, v8}, Landroid/content/res/Resources;->getInteger(I)I

    .line 1058
    .line 1059
    .line 1060
    move-result v8

    .line 1061
    int-to-float v8, v8

    .line 1062
    const/high16 v11, 0x42c80000    # 100.0f

    .line 1063
    .line 1064
    div-float/2addr v8, v11

    .line 1065
    iput v8, v0, Ly9/r;->g0:F

    .line 1066
    .line 1067
    const v8, 0x7f0b0009

    .line 1068
    .line 1069
    .line 1070
    invoke-virtual {v2, v8}, Landroid/content/res/Resources;->getInteger(I)I

    .line 1071
    .line 1072
    .line 1073
    move-result v8

    .line 1074
    int-to-float v8, v8

    .line 1075
    div-float/2addr v8, v11

    .line 1076
    iput v8, v0, Ly9/r;->q1:F

    .line 1077
    .line 1078
    const v8, 0x7f0a015e

    .line 1079
    .line 1080
    .line 1081
    invoke-virtual {v0, v8}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 1082
    .line 1083
    .line 1084
    move-result-object v8

    .line 1085
    check-cast v8, Landroid/widget/ImageView;

    .line 1086
    .line 1087
    iput-object v8, v0, Ly9/r;->E:Landroid/widget/ImageView;

    .line 1088
    .line 1089
    if-eqz v8, :cond_15

    .line 1090
    .line 1091
    invoke-virtual {v1}, Landroid/content/Context;->getTheme()Landroid/content/res/Resources$Theme;

    .line 1092
    .line 1093
    .line 1094
    move-result-object v11

    .line 1095
    invoke-virtual {v2, v15, v11}, Landroid/content/res/Resources;->getDrawable(ILandroid/content/res/Resources$Theme;)Landroid/graphics/drawable/Drawable;

    .line 1096
    .line 1097
    .line 1098
    move-result-object v11

    .line 1099
    invoke-virtual {v8, v11}, Landroid/widget/ImageView;->setImageDrawable(Landroid/graphics/drawable/Drawable;)V

    .line 1100
    .line 1101
    .line 1102
    const/4 v11, 0x0

    .line 1103
    invoke-virtual {v0, v8, v11}, Ly9/r;->n(Landroid/view/View;Z)V

    .line 1104
    .line 1105
    .line 1106
    :cond_15
    new-instance v11, Ly9/w;

    .line 1107
    .line 1108
    invoke-direct {v11, v0}, Ly9/w;-><init>(Ly9/r;)V

    .line 1109
    .line 1110
    .line 1111
    iput-object v11, v0, Ly9/r;->d:Ly9/w;

    .line 1112
    .line 1113
    iput-boolean v13, v11, Ly9/w;->C:Z

    .line 1114
    .line 1115
    const v12, 0x7f1202d7

    .line 1116
    .line 1117
    .line 1118
    invoke-virtual {v2, v12}, Landroid/content/res/Resources;->getString(I)Ljava/lang/String;

    .line 1119
    .line 1120
    .line 1121
    move-result-object v12

    .line 1122
    const v13, 0x7f080143

    .line 1123
    .line 1124
    .line 1125
    invoke-virtual {v1}, Landroid/content/Context;->getTheme()Landroid/content/res/Resources$Theme;

    .line 1126
    .line 1127
    .line 1128
    move-result-object v14

    .line 1129
    invoke-virtual {v2, v13, v14}, Landroid/content/res/Resources;->getDrawable(ILandroid/content/res/Resources$Theme;)Landroid/graphics/drawable/Drawable;

    .line 1130
    .line 1131
    .line 1132
    move-result-object v13

    .line 1133
    const v14, 0x7f1202f8

    .line 1134
    .line 1135
    .line 1136
    invoke-virtual {v2, v14}, Landroid/content/res/Resources;->getString(I)Ljava/lang/String;

    .line 1137
    .line 1138
    .line 1139
    move-result-object v14

    .line 1140
    filled-new-array {v12, v14}, [Ljava/lang/String;

    .line 1141
    .line 1142
    .line 1143
    move-result-object v12

    .line 1144
    const v14, 0x7f08012f

    .line 1145
    .line 1146
    .line 1147
    invoke-virtual {v1}, Landroid/content/Context;->getTheme()Landroid/content/res/Resources$Theme;

    .line 1148
    .line 1149
    .line 1150
    move-result-object v15

    .line 1151
    invoke-virtual {v2, v14, v15}, Landroid/content/res/Resources;->getDrawable(ILandroid/content/res/Resources$Theme;)Landroid/graphics/drawable/Drawable;

    .line 1152
    .line 1153
    .line 1154
    move-result-object v14

    .line 1155
    filled-new-array {v13, v14}, [Landroid/graphics/drawable/Drawable;

    .line 1156
    .line 1157
    .line 1158
    move-result-object v13

    .line 1159
    new-instance v14, Ly9/m;

    .line 1160
    .line 1161
    invoke-direct {v14, v0, v12, v13}, Ly9/m;-><init>(Ly9/r;[Ljava/lang/String;[Landroid/graphics/drawable/Drawable;)V

    .line 1162
    .line 1163
    .line 1164
    iput-object v14, v0, Ly9/r;->o:Ly9/m;

    .line 1165
    .line 1166
    const v12, 0x7f0700a4

    .line 1167
    .line 1168
    .line 1169
    invoke-virtual {v2, v12}, Landroid/content/res/Resources;->getDimensionPixelSize(I)I

    .line 1170
    .line 1171
    .line 1172
    move-result v12

    .line 1173
    iput v12, v0, Ly9/r;->u:I

    .line 1174
    .line 1175
    invoke-static {v1}, Landroid/view/LayoutInflater;->from(Landroid/content/Context;)Landroid/view/LayoutInflater;

    .line 1176
    .line 1177
    .line 1178
    move-result-object v12

    .line 1179
    const v13, 0x7f0d015a

    .line 1180
    .line 1181
    .line 1182
    const/4 v15, 0x0

    .line 1183
    invoke-virtual {v12, v13, v15}, Landroid/view/LayoutInflater;->inflate(ILandroid/view/ViewGroup;)Landroid/view/View;

    .line 1184
    .line 1185
    .line 1186
    move-result-object v12

    .line 1187
    check-cast v12, Landroidx/recyclerview/widget/RecyclerView;

    .line 1188
    .line 1189
    iput-object v12, v0, Ly9/r;->n:Landroidx/recyclerview/widget/RecyclerView;

    .line 1190
    .line 1191
    invoke-virtual {v12, v14}, Landroidx/recyclerview/widget/RecyclerView;->setAdapter(Lka/y;)V

    .line 1192
    .line 1193
    .line 1194
    new-instance v13, Landroidx/recyclerview/widget/LinearLayoutManager;

    .line 1195
    .line 1196
    invoke-virtual {v0}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 1197
    .line 1198
    .line 1199
    const/4 v14, 0x1

    .line 1200
    invoke-direct {v13, v14}, Landroidx/recyclerview/widget/LinearLayoutManager;-><init>(I)V

    .line 1201
    .line 1202
    .line 1203
    invoke-virtual {v12, v13}, Landroidx/recyclerview/widget/RecyclerView;->setLayoutManager(Lka/f0;)V

    .line 1204
    .line 1205
    .line 1206
    new-instance v13, Landroid/widget/PopupWindow;

    .line 1207
    .line 1208
    const/4 v15, -0x2

    .line 1209
    invoke-direct {v13, v12, v15, v15, v14}, Landroid/widget/PopupWindow;-><init>(Landroid/view/View;IIZ)V

    .line 1210
    .line 1211
    .line 1212
    iput-object v13, v0, Ly9/r;->t:Landroid/widget/PopupWindow;

    .line 1213
    .line 1214
    iget-object v12, v0, Ly9/r;->f:Ly9/g;

    .line 1215
    .line 1216
    invoke-virtual {v13, v12}, Landroid/widget/PopupWindow;->setOnDismissListener(Landroid/widget/PopupWindow$OnDismissListener;)V

    .line 1217
    .line 1218
    .line 1219
    iput-boolean v14, v0, Ly9/r;->R1:Z

    .line 1220
    .line 1221
    new-instance v12, Lro/f;

    .line 1222
    .line 1223
    invoke-virtual {v0}, Landroid/view/View;->getResources()Landroid/content/res/Resources;

    .line 1224
    .line 1225
    .line 1226
    move-result-object v13

    .line 1227
    invoke-direct {v12, v13}, Lro/f;-><init>(Landroid/content/res/Resources;)V

    .line 1228
    .line 1229
    .line 1230
    iput-object v12, v0, Ly9/r;->s:Lro/f;

    .line 1231
    .line 1232
    invoke-virtual {v1}, Landroid/content/Context;->getTheme()Landroid/content/res/Resources$Theme;

    .line 1233
    .line 1234
    .line 1235
    move-result-object v12

    .line 1236
    invoke-virtual {v2, v10, v12}, Landroid/content/res/Resources;->getDrawable(ILandroid/content/res/Resources$Theme;)Landroid/graphics/drawable/Drawable;

    .line 1237
    .line 1238
    .line 1239
    move-result-object v10

    .line 1240
    iput-object v10, v0, Ly9/r;->t1:Landroid/graphics/drawable/Drawable;

    .line 1241
    .line 1242
    invoke-virtual {v1}, Landroid/content/Context;->getTheme()Landroid/content/res/Resources$Theme;

    .line 1243
    .line 1244
    .line 1245
    move-result-object v10

    .line 1246
    invoke-virtual {v2, v9, v10}, Landroid/content/res/Resources;->getDrawable(ILandroid/content/res/Resources$Theme;)Landroid/graphics/drawable/Drawable;

    .line 1247
    .line 1248
    .line 1249
    move-result-object v9

    .line 1250
    iput-object v9, v0, Ly9/r;->u1:Landroid/graphics/drawable/Drawable;

    .line 1251
    .line 1252
    const v9, 0x7f1202cc

    .line 1253
    .line 1254
    .line 1255
    invoke-virtual {v2, v9}, Landroid/content/res/Resources;->getString(I)Ljava/lang/String;

    .line 1256
    .line 1257
    .line 1258
    move-result-object v9

    .line 1259
    iput-object v9, v0, Ly9/r;->v1:Ljava/lang/String;

    .line 1260
    .line 1261
    const v9, 0x7f1202cb

    .line 1262
    .line 1263
    .line 1264
    invoke-virtual {v2, v9}, Landroid/content/res/Resources;->getString(I)Ljava/lang/String;

    .line 1265
    .line 1266
    .line 1267
    move-result-object v9

    .line 1268
    iput-object v9, v0, Ly9/r;->w1:Ljava/lang/String;

    .line 1269
    .line 1270
    new-instance v9, Ly9/f;

    .line 1271
    .line 1272
    const/4 v14, 0x1

    .line 1273
    invoke-direct {v9, v0, v14}, Ly9/f;-><init>(Ly9/r;I)V

    .line 1274
    .line 1275
    .line 1276
    iput-object v9, v0, Ly9/r;->q:Ly9/f;

    .line 1277
    .line 1278
    new-instance v9, Ly9/f;

    .line 1279
    .line 1280
    const/4 v10, 0x0

    .line 1281
    invoke-direct {v9, v0, v10}, Ly9/f;-><init>(Ly9/r;I)V

    .line 1282
    .line 1283
    .line 1284
    iput-object v9, v0, Ly9/r;->r:Ly9/f;

    .line 1285
    .line 1286
    new-instance v9, Ly9/j;

    .line 1287
    .line 1288
    const v12, 0x7f030004

    .line 1289
    .line 1290
    .line 1291
    invoke-virtual {v2, v12}, Landroid/content/res/Resources;->getStringArray(I)[Ljava/lang/String;

    .line 1292
    .line 1293
    .line 1294
    move-result-object v12

    .line 1295
    sget-object v13, Ly9/r;->S1:[F

    .line 1296
    .line 1297
    invoke-direct {v9, v0, v12, v13}, Ly9/j;-><init>(Ly9/r;[Ljava/lang/String;[F)V

    .line 1298
    .line 1299
    .line 1300
    iput-object v9, v0, Ly9/r;->p:Ly9/j;

    .line 1301
    .line 1302
    invoke-virtual {v1}, Landroid/content/Context;->getTheme()Landroid/content/res/Resources$Theme;

    .line 1303
    .line 1304
    .line 1305
    move-result-object v9

    .line 1306
    move/from16 v12, v33

    .line 1307
    .line 1308
    invoke-virtual {v2, v12, v9}, Landroid/content/res/Resources;->getDrawable(ILandroid/content/res/Resources$Theme;)Landroid/graphics/drawable/Drawable;

    .line 1309
    .line 1310
    .line 1311
    move-result-object v9

    .line 1312
    iput-object v9, v0, Ly9/r;->T:Landroid/graphics/drawable/Drawable;

    .line 1313
    .line 1314
    invoke-virtual {v1}, Landroid/content/Context;->getTheme()Landroid/content/res/Resources$Theme;

    .line 1315
    .line 1316
    .line 1317
    move-result-object v9

    .line 1318
    move/from16 v13, v32

    .line 1319
    .line 1320
    invoke-virtual {v2, v13, v9}, Landroid/content/res/Resources;->getDrawable(ILandroid/content/res/Resources$Theme;)Landroid/graphics/drawable/Drawable;

    .line 1321
    .line 1322
    .line 1323
    move-result-object v9

    .line 1324
    iput-object v9, v0, Ly9/r;->U:Landroid/graphics/drawable/Drawable;

    .line 1325
    .line 1326
    invoke-virtual {v1}, Landroid/content/Context;->getTheme()Landroid/content/res/Resources$Theme;

    .line 1327
    .line 1328
    .line 1329
    move-result-object v9

    .line 1330
    move/from16 v12, v31

    .line 1331
    .line 1332
    invoke-virtual {v2, v12, v9}, Landroid/content/res/Resources;->getDrawable(ILandroid/content/res/Resources$Theme;)Landroid/graphics/drawable/Drawable;

    .line 1333
    .line 1334
    .line 1335
    move-result-object v9

    .line 1336
    iput-object v9, v0, Ly9/r;->x1:Landroid/graphics/drawable/Drawable;

    .line 1337
    .line 1338
    invoke-virtual {v1}, Landroid/content/Context;->getTheme()Landroid/content/res/Resources$Theme;

    .line 1339
    .line 1340
    .line 1341
    move-result-object v9

    .line 1342
    move/from16 v12, v30

    .line 1343
    .line 1344
    invoke-virtual {v2, v12, v9}, Landroid/content/res/Resources;->getDrawable(ILandroid/content/res/Resources$Theme;)Landroid/graphics/drawable/Drawable;

    .line 1345
    .line 1346
    .line 1347
    move-result-object v9

    .line 1348
    iput-object v9, v0, Ly9/r;->y1:Landroid/graphics/drawable/Drawable;

    .line 1349
    .line 1350
    invoke-virtual {v1}, Landroid/content/Context;->getTheme()Landroid/content/res/Resources$Theme;

    .line 1351
    .line 1352
    .line 1353
    move-result-object v9

    .line 1354
    move/from16 v12, v29

    .line 1355
    .line 1356
    invoke-virtual {v2, v12, v9}, Landroid/content/res/Resources;->getDrawable(ILandroid/content/res/Resources$Theme;)Landroid/graphics/drawable/Drawable;

    .line 1357
    .line 1358
    .line 1359
    move-result-object v9

    .line 1360
    iput-object v9, v0, Ly9/r;->V:Landroid/graphics/drawable/Drawable;

    .line 1361
    .line 1362
    invoke-virtual {v1}, Landroid/content/Context;->getTheme()Landroid/content/res/Resources$Theme;

    .line 1363
    .line 1364
    .line 1365
    move-result-object v9

    .line 1366
    move/from16 v12, v28

    .line 1367
    .line 1368
    invoke-virtual {v2, v12, v9}, Landroid/content/res/Resources;->getDrawable(ILandroid/content/res/Resources$Theme;)Landroid/graphics/drawable/Drawable;

    .line 1369
    .line 1370
    .line 1371
    move-result-object v9

    .line 1372
    iput-object v9, v0, Ly9/r;->W:Landroid/graphics/drawable/Drawable;

    .line 1373
    .line 1374
    invoke-virtual {v1}, Landroid/content/Context;->getTheme()Landroid/content/res/Resources$Theme;

    .line 1375
    .line 1376
    .line 1377
    move-result-object v9

    .line 1378
    move/from16 v12, v27

    .line 1379
    .line 1380
    invoke-virtual {v2, v12, v9}, Landroid/content/res/Resources;->getDrawable(ILandroid/content/res/Resources$Theme;)Landroid/graphics/drawable/Drawable;

    .line 1381
    .line 1382
    .line 1383
    move-result-object v9

    .line 1384
    iput-object v9, v0, Ly9/r;->a0:Landroid/graphics/drawable/Drawable;

    .line 1385
    .line 1386
    invoke-virtual {v1}, Landroid/content/Context;->getTheme()Landroid/content/res/Resources$Theme;

    .line 1387
    .line 1388
    .line 1389
    move-result-object v9

    .line 1390
    move/from16 v12, v26

    .line 1391
    .line 1392
    invoke-virtual {v2, v12, v9}, Landroid/content/res/Resources;->getDrawable(ILandroid/content/res/Resources$Theme;)Landroid/graphics/drawable/Drawable;

    .line 1393
    .line 1394
    .line 1395
    move-result-object v9

    .line 1396
    iput-object v9, v0, Ly9/r;->e0:Landroid/graphics/drawable/Drawable;

    .line 1397
    .line 1398
    invoke-virtual {v1}, Landroid/content/Context;->getTheme()Landroid/content/res/Resources$Theme;

    .line 1399
    .line 1400
    .line 1401
    move-result-object v1

    .line 1402
    move/from16 v9, v25

    .line 1403
    .line 1404
    invoke-virtual {v2, v9, v1}, Landroid/content/res/Resources;->getDrawable(ILandroid/content/res/Resources$Theme;)Landroid/graphics/drawable/Drawable;

    .line 1405
    .line 1406
    .line 1407
    move-result-object v1

    .line 1408
    iput-object v1, v0, Ly9/r;->f0:Landroid/graphics/drawable/Drawable;

    .line 1409
    .line 1410
    const v1, 0x7f1202d0

    .line 1411
    .line 1412
    .line 1413
    invoke-virtual {v2, v1}, Landroid/content/res/Resources;->getString(I)Ljava/lang/String;

    .line 1414
    .line 1415
    .line 1416
    move-result-object v1

    .line 1417
    iput-object v1, v0, Ly9/r;->z1:Ljava/lang/String;

    .line 1418
    .line 1419
    const v1, 0x7f1202cf

    .line 1420
    .line 1421
    .line 1422
    invoke-virtual {v2, v1}, Landroid/content/res/Resources;->getString(I)Ljava/lang/String;

    .line 1423
    .line 1424
    .line 1425
    move-result-object v1

    .line 1426
    iput-object v1, v0, Ly9/r;->A1:Ljava/lang/String;

    .line 1427
    .line 1428
    const v1, 0x7f1202da

    .line 1429
    .line 1430
    .line 1431
    invoke-virtual {v2, v1}, Landroid/content/res/Resources;->getString(I)Ljava/lang/String;

    .line 1432
    .line 1433
    .line 1434
    move-result-object v1

    .line 1435
    iput-object v1, v0, Ly9/r;->b0:Ljava/lang/String;

    .line 1436
    .line 1437
    const v1, 0x7f1202db

    .line 1438
    .line 1439
    .line 1440
    invoke-virtual {v2, v1}, Landroid/content/res/Resources;->getString(I)Ljava/lang/String;

    .line 1441
    .line 1442
    .line 1443
    move-result-object v1

    .line 1444
    iput-object v1, v0, Ly9/r;->c0:Ljava/lang/String;

    .line 1445
    .line 1446
    const v1, 0x7f1202d9

    .line 1447
    .line 1448
    .line 1449
    invoke-virtual {v2, v1}, Landroid/content/res/Resources;->getString(I)Ljava/lang/String;

    .line 1450
    .line 1451
    .line 1452
    move-result-object v1

    .line 1453
    iput-object v1, v0, Ly9/r;->d0:Ljava/lang/String;

    .line 1454
    .line 1455
    const v1, 0x7f1202e1

    .line 1456
    .line 1457
    .line 1458
    invoke-virtual {v2, v1}, Landroid/content/res/Resources;->getString(I)Ljava/lang/String;

    .line 1459
    .line 1460
    .line 1461
    move-result-object v1

    .line 1462
    iput-object v1, v0, Ly9/r;->r1:Ljava/lang/String;

    .line 1463
    .line 1464
    const v1, 0x7f1202e0

    .line 1465
    .line 1466
    .line 1467
    invoke-virtual {v2, v1}, Landroid/content/res/Resources;->getString(I)Ljava/lang/String;

    .line 1468
    .line 1469
    .line 1470
    move-result-object v1

    .line 1471
    iput-object v1, v0, Ly9/r;->s1:Ljava/lang/String;

    .line 1472
    .line 1473
    const v1, 0x7f0a0131

    .line 1474
    .line 1475
    .line 1476
    invoke-virtual {v0, v1}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 1477
    .line 1478
    .line 1479
    move-result-object v1

    .line 1480
    check-cast v1, Landroid/view/ViewGroup;

    .line 1481
    .line 1482
    const/4 v14, 0x1

    .line 1483
    invoke-virtual {v11, v1, v14}, Ly9/w;->h(Landroid/view/View;Z)V

    .line 1484
    .line 1485
    .line 1486
    iget-object v1, v0, Ly9/r;->y:Landroid/view/View;

    .line 1487
    .line 1488
    move/from16 v2, v24

    .line 1489
    .line 1490
    invoke-virtual {v11, v1, v2}, Ly9/w;->h(Landroid/view/View;Z)V

    .line 1491
    .line 1492
    .line 1493
    iget-object v1, v0, Ly9/r;->z:Landroid/view/View;

    .line 1494
    .line 1495
    move/from16 v2, v23

    .line 1496
    .line 1497
    invoke-virtual {v11, v1, v2}, Ly9/w;->h(Landroid/view/View;Z)V

    .line 1498
    .line 1499
    .line 1500
    move/from16 v1, v22

    .line 1501
    .line 1502
    invoke-virtual {v11, v4, v1}, Ly9/w;->h(Landroid/view/View;Z)V

    .line 1503
    .line 1504
    .line 1505
    move/from16 v1, v21

    .line 1506
    .line 1507
    invoke-virtual {v11, v5, v1}, Ly9/w;->h(Landroid/view/View;Z)V

    .line 1508
    .line 1509
    .line 1510
    move/from16 v1, v20

    .line 1511
    .line 1512
    invoke-virtual {v11, v7, v1}, Ly9/w;->h(Landroid/view/View;Z)V

    .line 1513
    .line 1514
    .line 1515
    move/from16 v1, v19

    .line 1516
    .line 1517
    invoke-virtual {v11, v3, v1}, Ly9/w;->h(Landroid/view/View;Z)V

    .line 1518
    .line 1519
    .line 1520
    move/from16 v1, v18

    .line 1521
    .line 1522
    invoke-virtual {v11, v8, v1}, Ly9/w;->h(Landroid/view/View;Z)V

    .line 1523
    .line 1524
    .line 1525
    iget v1, v0, Ly9/r;->L1:I

    .line 1526
    .line 1527
    if-eqz v1, :cond_16

    .line 1528
    .line 1529
    move v7, v14

    .line 1530
    goto :goto_c

    .line 1531
    :cond_16
    move v7, v10

    .line 1532
    :goto_c
    invoke-virtual {v11, v6, v7}, Ly9/w;->h(Landroid/view/View;Z)V

    .line 1533
    .line 1534
    .line 1535
    new-instance v1, Lkq/a;

    .line 1536
    .line 1537
    const/4 v2, 0x3

    .line 1538
    invoke-direct {v1, v0, v2}, Lkq/a;-><init>(Ljava/lang/Object;I)V

    .line 1539
    .line 1540
    .line 1541
    invoke-virtual {v0, v1}, Landroid/view/View;->addOnLayoutChangeListener(Landroid/view/View$OnLayoutChangeListener;)V

    .line 1542
    .line 1543
    .line 1544
    return-void
.end method

.method public static a(Ly9/r;Lt7/l0;J)V
    .locals 7

    .line 1
    iget-boolean v0, p0, Ly9/r;->G1:Z

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_2

    .line 5
    .line 6
    check-cast p1, Lap0/o;

    .line 7
    .line 8
    const/16 v0, 0x11

    .line 9
    .line 10
    invoke-virtual {p1, v0}, Lap0/o;->I(I)Z

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    if-eqz v0, :cond_3

    .line 15
    .line 16
    const/16 v0, 0xa

    .line 17
    .line 18
    invoke-virtual {p1, v0}, Lap0/o;->I(I)Z

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    if-eqz v0, :cond_3

    .line 23
    .line 24
    move-object v0, p1

    .line 25
    check-cast v0, La8/i0;

    .line 26
    .line 27
    invoke-virtual {v0}, La8/i0;->k0()Lt7/p0;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    invoke-virtual {v0}, Lt7/p0;->o()I

    .line 32
    .line 33
    .line 34
    move-result v2

    .line 35
    move v3, v1

    .line 36
    :goto_0
    iget-object v4, p0, Ly9/r;->R:Lt7/o0;

    .line 37
    .line 38
    const-wide/16 v5, 0x0

    .line 39
    .line 40
    invoke-virtual {v0, v3, v4, v5, v6}, Lt7/p0;->m(ILt7/o0;J)Lt7/o0;

    .line 41
    .line 42
    .line 43
    move-result-object v4

    .line 44
    iget-wide v4, v4, Lt7/o0;->l:J

    .line 45
    .line 46
    invoke-static {v4, v5}, Lw7/w;->N(J)J

    .line 47
    .line 48
    .line 49
    move-result-wide v4

    .line 50
    cmp-long v6, p2, v4

    .line 51
    .line 52
    if-gez v6, :cond_0

    .line 53
    .line 54
    goto :goto_1

    .line 55
    :cond_0
    add-int/lit8 v6, v2, -0x1

    .line 56
    .line 57
    if-ne v3, v6, :cond_1

    .line 58
    .line 59
    move-wide p2, v4

    .line 60
    :goto_1
    invoke-virtual {p1, p2, p3, v3, v1}, Lap0/o;->P(JIZ)V

    .line 61
    .line 62
    .line 63
    goto :goto_2

    .line 64
    :cond_1
    sub-long/2addr p2, v4

    .line 65
    add-int/lit8 v3, v3, 0x1

    .line 66
    .line 67
    goto :goto_0

    .line 68
    :cond_2
    check-cast p1, Lap0/o;

    .line 69
    .line 70
    const/4 v0, 0x5

    .line 71
    invoke-virtual {p1, v0}, Lap0/o;->I(I)Z

    .line 72
    .line 73
    .line 74
    move-result v0

    .line 75
    if-eqz v0, :cond_3

    .line 76
    .line 77
    move-object v0, p1

    .line 78
    check-cast v0, La8/i0;

    .line 79
    .line 80
    invoke-virtual {v0}, La8/i0;->h0()I

    .line 81
    .line 82
    .line 83
    move-result v0

    .line 84
    invoke-virtual {p1, p2, p3, v0, v1}, Lap0/o;->P(JIZ)V

    .line 85
    .line 86
    .line 87
    :cond_3
    :goto_2
    invoke-virtual {p0}, Ly9/r;->s()V

    .line 88
    .line 89
    .line 90
    return-void
.end method

.method public static synthetic b(Ly9/r;F)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Ly9/r;->setPlaybackSpeed(F)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static c(Lt7/l0;Lt7/o0;)Z
    .locals 8

    .line 1
    check-cast p0, Lap0/o;

    .line 2
    .line 3
    const/16 v0, 0x11

    .line 4
    .line 5
    invoke-virtual {p0, v0}, Lap0/o;->I(I)Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    const/4 v1, 0x0

    .line 10
    if-nez v0, :cond_0

    .line 11
    .line 12
    return v1

    .line 13
    :cond_0
    check-cast p0, La8/i0;

    .line 14
    .line 15
    invoke-virtual {p0}, La8/i0;->k0()Lt7/p0;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    invoke-virtual {p0}, Lt7/p0;->o()I

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    const/4 v2, 0x1

    .line 24
    if-le v0, v2, :cond_4

    .line 25
    .line 26
    const/16 v3, 0x64

    .line 27
    .line 28
    if-le v0, v3, :cond_1

    .line 29
    .line 30
    goto :goto_1

    .line 31
    :cond_1
    move v3, v1

    .line 32
    :goto_0
    if-ge v3, v0, :cond_3

    .line 33
    .line 34
    const-wide/16 v4, 0x0

    .line 35
    .line 36
    invoke-virtual {p0, v3, p1, v4, v5}, Lt7/p0;->m(ILt7/o0;J)Lt7/o0;

    .line 37
    .line 38
    .line 39
    move-result-object v4

    .line 40
    iget-wide v4, v4, Lt7/o0;->l:J

    .line 41
    .line 42
    const-wide v6, -0x7fffffffffffffffL    # -4.9E-324

    .line 43
    .line 44
    .line 45
    .line 46
    .line 47
    cmp-long v4, v4, v6

    .line 48
    .line 49
    if-nez v4, :cond_2

    .line 50
    .line 51
    return v1

    .line 52
    :cond_2
    add-int/lit8 v3, v3, 0x1

    .line 53
    .line 54
    goto :goto_0

    .line 55
    :cond_3
    return v2

    .line 56
    :cond_4
    :goto_1
    return v1
.end method

.method private setPlaybackSpeed(F)V
    .locals 9

    .line 1
    iget-object v0, p0, Ly9/r;->B1:Lt7/l0;

    .line 2
    .line 3
    if-eqz v0, :cond_2

    .line 4
    .line 5
    const/16 v1, 0xd

    .line 6
    .line 7
    check-cast v0, Lap0/o;

    .line 8
    .line 9
    invoke-virtual {v0, v1}, Lap0/o;->I(I)Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    if-nez v0, :cond_0

    .line 14
    .line 15
    goto :goto_0

    .line 16
    :cond_0
    iget-object p0, p0, Ly9/r;->B1:Lt7/l0;

    .line 17
    .line 18
    move-object v0, p0

    .line 19
    check-cast v0, La8/i0;

    .line 20
    .line 21
    invoke-virtual {v0}, La8/i0;->L0()V

    .line 22
    .line 23
    .line 24
    iget-object p0, v0, La8/i0;->y1:La8/i1;

    .line 25
    .line 26
    iget-object p0, p0, La8/i1;->o:Lt7/g0;

    .line 27
    .line 28
    new-instance v1, Lt7/g0;

    .line 29
    .line 30
    iget p0, p0, Lt7/g0;->b:F

    .line 31
    .line 32
    invoke-direct {v1, p1, p0}, Lt7/g0;-><init>(FF)V

    .line 33
    .line 34
    .line 35
    invoke-virtual {v0}, La8/i0;->L0()V

    .line 36
    .line 37
    .line 38
    iget-object p0, v0, La8/i0;->y1:La8/i1;

    .line 39
    .line 40
    iget-object p0, p0, La8/i1;->o:Lt7/g0;

    .line 41
    .line 42
    invoke-virtual {p0, v1}, Lt7/g0;->equals(Ljava/lang/Object;)Z

    .line 43
    .line 44
    .line 45
    move-result p0

    .line 46
    if-eqz p0, :cond_1

    .line 47
    .line 48
    goto :goto_0

    .line 49
    :cond_1
    iget-object p0, v0, La8/i0;->y1:La8/i1;

    .line 50
    .line 51
    invoke-virtual {p0, v1}, La8/i1;->g(Lt7/g0;)La8/i1;

    .line 52
    .line 53
    .line 54
    move-result-object p0

    .line 55
    iget p1, v0, La8/i0;->M:I

    .line 56
    .line 57
    add-int/lit8 p1, p1, 0x1

    .line 58
    .line 59
    iput p1, v0, La8/i0;->M:I

    .line 60
    .line 61
    iget-object p1, v0, La8/i0;->p:La8/q0;

    .line 62
    .line 63
    iget-object p1, p1, La8/q0;->k:Lw7/t;

    .line 64
    .line 65
    const/4 v2, 0x4

    .line 66
    invoke-virtual {p1, v2, v1}, Lw7/t;->a(ILjava/lang/Object;)Lw7/s;

    .line 67
    .line 68
    .line 69
    move-result-object p1

    .line 70
    invoke-virtual {p1}, Lw7/s;->b()V

    .line 71
    .line 72
    .line 73
    const/4 v7, -0x1

    .line 74
    const/4 v8, 0x0

    .line 75
    const/4 v2, 0x0

    .line 76
    const/4 v3, 0x0

    .line 77
    const/4 v4, 0x5

    .line 78
    const-wide v5, -0x7fffffffffffffffL    # -4.9E-324

    .line 79
    .line 80
    .line 81
    .line 82
    .line 83
    move-object v1, p0

    .line 84
    invoke-virtual/range {v0 .. v8}, La8/i0;->J0(La8/i1;IZIJIZ)V

    .line 85
    .line 86
    .line 87
    :cond_2
    :goto_0
    return-void
.end method


# virtual methods
.method public final d(Landroid/view/KeyEvent;)Z
    .locals 13

    .line 1
    invoke-virtual {p1}, Landroid/view/KeyEvent;->getKeyCode()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    iget-object v1, p0, Ly9/r;->B1:Lt7/l0;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-eqz v1, :cond_a

    .line 9
    .line 10
    const/16 v3, 0x58

    .line 11
    .line 12
    const/16 v4, 0x57

    .line 13
    .line 14
    const/16 v5, 0x7f

    .line 15
    .line 16
    const/16 v6, 0x7e

    .line 17
    .line 18
    const/16 v7, 0x4f

    .line 19
    .line 20
    const/16 v8, 0x55

    .line 21
    .line 22
    const/16 v9, 0x59

    .line 23
    .line 24
    const/16 v10, 0x5a

    .line 25
    .line 26
    if-eq v0, v10, :cond_0

    .line 27
    .line 28
    if-eq v0, v9, :cond_0

    .line 29
    .line 30
    if-eq v0, v8, :cond_0

    .line 31
    .line 32
    if-eq v0, v7, :cond_0

    .line 33
    .line 34
    if-eq v0, v6, :cond_0

    .line 35
    .line 36
    if-eq v0, v5, :cond_0

    .line 37
    .line 38
    if-eq v0, v4, :cond_0

    .line 39
    .line 40
    if-ne v0, v3, :cond_a

    .line 41
    .line 42
    :cond_0
    invoke-virtual {p1}, Landroid/view/KeyEvent;->getAction()I

    .line 43
    .line 44
    .line 45
    move-result v11

    .line 46
    const/4 v12, 0x1

    .line 47
    if-nez v11, :cond_9

    .line 48
    .line 49
    if-ne v0, v10, :cond_1

    .line 50
    .line 51
    move-object p0, v1

    .line 52
    check-cast p0, La8/i0;

    .line 53
    .line 54
    invoke-virtual {p0}, La8/i0;->o0()I

    .line 55
    .line 56
    .line 57
    move-result p0

    .line 58
    const/4 p1, 0x4

    .line 59
    if-eq p0, p1, :cond_9

    .line 60
    .line 61
    check-cast v1, Lap0/o;

    .line 62
    .line 63
    const/16 p0, 0xc

    .line 64
    .line 65
    invoke-virtual {v1, p0}, Lap0/o;->I(I)Z

    .line 66
    .line 67
    .line 68
    move-result p1

    .line 69
    if-eqz p1, :cond_9

    .line 70
    .line 71
    move-object p1, v1

    .line 72
    check-cast p1, La8/i0;

    .line 73
    .line 74
    invoke-virtual {p1}, La8/i0;->L0()V

    .line 75
    .line 76
    .line 77
    iget-wide v2, p1, La8/i0;->A:J

    .line 78
    .line 79
    invoke-virtual {v1, p0, v2, v3}, Lap0/o;->R(IJ)V

    .line 80
    .line 81
    .line 82
    goto/16 :goto_0

    .line 83
    .line 84
    :cond_1
    if-ne v0, v9, :cond_2

    .line 85
    .line 86
    move-object v9, v1

    .line 87
    check-cast v9, Lap0/o;

    .line 88
    .line 89
    const/16 v10, 0xb

    .line 90
    .line 91
    invoke-virtual {v9, v10}, Lap0/o;->I(I)Z

    .line 92
    .line 93
    .line 94
    move-result v11

    .line 95
    if-eqz v11, :cond_2

    .line 96
    .line 97
    move-object p0, v9

    .line 98
    check-cast p0, La8/i0;

    .line 99
    .line 100
    invoke-virtual {p0}, La8/i0;->L0()V

    .line 101
    .line 102
    .line 103
    iget-wide p0, p0, La8/i0;->z:J

    .line 104
    .line 105
    neg-long p0, p0

    .line 106
    invoke-virtual {v9, v10, p0, p1}, Lap0/o;->R(IJ)V

    .line 107
    .line 108
    .line 109
    goto :goto_0

    .line 110
    :cond_2
    invoke-virtual {p1}, Landroid/view/KeyEvent;->getRepeatCount()I

    .line 111
    .line 112
    .line 113
    move-result p1

    .line 114
    if-nez p1, :cond_9

    .line 115
    .line 116
    if-eq v0, v7, :cond_7

    .line 117
    .line 118
    if-eq v0, v8, :cond_7

    .line 119
    .line 120
    if-eq v0, v4, :cond_6

    .line 121
    .line 122
    if-eq v0, v3, :cond_5

    .line 123
    .line 124
    if-eq v0, v6, :cond_4

    .line 125
    .line 126
    if-eq v0, v5, :cond_3

    .line 127
    .line 128
    goto :goto_0

    .line 129
    :cond_3
    sget-object p0, Lw7/w;->a:Ljava/lang/String;

    .line 130
    .line 131
    check-cast v1, Lap0/o;

    .line 132
    .line 133
    invoke-virtual {v1, v12}, Lap0/o;->I(I)Z

    .line 134
    .line 135
    .line 136
    move-result p0

    .line 137
    if-eqz p0, :cond_9

    .line 138
    .line 139
    check-cast v1, La8/i0;

    .line 140
    .line 141
    invoke-virtual {v1}, La8/i0;->L0()V

    .line 142
    .line 143
    .line 144
    invoke-virtual {v1, v12, v2}, La8/i0;->I0(IZ)V

    .line 145
    .line 146
    .line 147
    goto :goto_0

    .line 148
    :cond_4
    invoke-static {v1}, Lw7/w;->w(Lt7/l0;)Z

    .line 149
    .line 150
    .line 151
    goto :goto_0

    .line 152
    :cond_5
    check-cast v1, Lap0/o;

    .line 153
    .line 154
    const/4 p0, 0x7

    .line 155
    invoke-virtual {v1, p0}, Lap0/o;->I(I)Z

    .line 156
    .line 157
    .line 158
    move-result p0

    .line 159
    if-eqz p0, :cond_9

    .line 160
    .line 161
    invoke-virtual {v1}, Lap0/o;->S()V

    .line 162
    .line 163
    .line 164
    goto :goto_0

    .line 165
    :cond_6
    check-cast v1, Lap0/o;

    .line 166
    .line 167
    const/16 p0, 0x9

    .line 168
    .line 169
    invoke-virtual {v1, p0}, Lap0/o;->I(I)Z

    .line 170
    .line 171
    .line 172
    move-result p0

    .line 173
    if-eqz p0, :cond_9

    .line 174
    .line 175
    invoke-virtual {v1}, Lap0/o;->Q()V

    .line 176
    .line 177
    .line 178
    goto :goto_0

    .line 179
    :cond_7
    iget-boolean p0, p0, Ly9/r;->F1:Z

    .line 180
    .line 181
    invoke-static {v1, p0}, Lw7/w;->L(Lt7/l0;Z)Z

    .line 182
    .line 183
    .line 184
    move-result p0

    .line 185
    if-eqz p0, :cond_8

    .line 186
    .line 187
    invoke-static {v1}, Lw7/w;->w(Lt7/l0;)Z

    .line 188
    .line 189
    .line 190
    goto :goto_0

    .line 191
    :cond_8
    check-cast v1, Lap0/o;

    .line 192
    .line 193
    invoke-virtual {v1, v12}, Lap0/o;->I(I)Z

    .line 194
    .line 195
    .line 196
    move-result p0

    .line 197
    if-eqz p0, :cond_9

    .line 198
    .line 199
    check-cast v1, La8/i0;

    .line 200
    .line 201
    invoke-virtual {v1}, La8/i0;->L0()V

    .line 202
    .line 203
    .line 204
    invoke-virtual {v1, v12, v2}, La8/i0;->I0(IZ)V

    .line 205
    .line 206
    .line 207
    :cond_9
    :goto_0
    return v12

    .line 208
    :cond_a
    return v2
.end method

.method public final dispatchKeyEvent(Landroid/view/KeyEvent;)Z
    .locals 1

    .line 1
    invoke-virtual {p0, p1}, Ly9/r;->d(Landroid/view/KeyEvent;)Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-nez v0, :cond_1

    .line 6
    .line 7
    invoke-super {p0, p1}, Landroid/view/View;->dispatchKeyEvent(Landroid/view/KeyEvent;)Z

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    if-eqz p0, :cond_0

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    const/4 p0, 0x0

    .line 15
    return p0

    .line 16
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 17
    return p0
.end method

.method public final e(Lka/y;Landroid/view/View;)V
    .locals 2

    .line 1
    iget-object v0, p0, Ly9/r;->n:Landroidx/recyclerview/widget/RecyclerView;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Landroidx/recyclerview/widget/RecyclerView;->setAdapter(Lka/y;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Ly9/r;->u()V

    .line 7
    .line 8
    .line 9
    const/4 p1, 0x0

    .line 10
    iput-boolean p1, p0, Ly9/r;->R1:Z

    .line 11
    .line 12
    iget-object p1, p0, Ly9/r;->t:Landroid/widget/PopupWindow;

    .line 13
    .line 14
    invoke-virtual {p1}, Landroid/widget/PopupWindow;->dismiss()V

    .line 15
    .line 16
    .line 17
    const/4 v0, 0x1

    .line 18
    iput-boolean v0, p0, Ly9/r;->R1:Z

    .line 19
    .line 20
    invoke-virtual {p0}, Landroid/view/View;->getWidth()I

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    invoke-virtual {p1}, Landroid/widget/PopupWindow;->getWidth()I

    .line 25
    .line 26
    .line 27
    move-result v1

    .line 28
    sub-int/2addr v0, v1

    .line 29
    iget p0, p0, Ly9/r;->u:I

    .line 30
    .line 31
    sub-int/2addr v0, p0

    .line 32
    invoke-virtual {p1}, Landroid/widget/PopupWindow;->getHeight()I

    .line 33
    .line 34
    .line 35
    move-result v1

    .line 36
    neg-int v1, v1

    .line 37
    sub-int/2addr v1, p0

    .line 38
    invoke-virtual {p1, p2, v0, v1}, Landroid/widget/PopupWindow;->showAsDropDown(Landroid/view/View;II)V

    .line 39
    .line 40
    .line 41
    return-void
.end method

.method public final f(Lt7/w0;I)Lhr/x0;
    .locals 11

    .line 1
    const-string v0, "initialCapacity"

    .line 2
    .line 3
    const/4 v1, 0x4

    .line 4
    invoke-static {v1, v0}, Lhr/q;->c(ILjava/lang/String;)V

    .line 5
    .line 6
    .line 7
    new-array v0, v1, [Ljava/lang/Object;

    .line 8
    .line 9
    iget-object v1, p1, Lt7/w0;->a:Lhr/h0;

    .line 10
    .line 11
    const/4 v2, 0x0

    .line 12
    move v3, v2

    .line 13
    move v4, v3

    .line 14
    :goto_0
    invoke-interface {v1}, Ljava/util/List;->size()I

    .line 15
    .line 16
    .line 17
    move-result v5

    .line 18
    if-ge v3, v5, :cond_5

    .line 19
    .line 20
    invoke-interface {v1, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object v5

    .line 24
    check-cast v5, Lt7/v0;

    .line 25
    .line 26
    iget-object v6, v5, Lt7/v0;->b:Lt7/q0;

    .line 27
    .line 28
    iget v6, v6, Lt7/q0;->c:I

    .line 29
    .line 30
    if-eq v6, p2, :cond_0

    .line 31
    .line 32
    goto :goto_4

    .line 33
    :cond_0
    move v6, v2

    .line 34
    :goto_1
    iget v7, v5, Lt7/v0;->a:I

    .line 35
    .line 36
    if-ge v6, v7, :cond_4

    .line 37
    .line 38
    invoke-virtual {v5, v6}, Lt7/v0;->a(I)Z

    .line 39
    .line 40
    .line 41
    move-result v7

    .line 42
    if-nez v7, :cond_1

    .line 43
    .line 44
    goto :goto_3

    .line 45
    :cond_1
    iget-object v7, v5, Lt7/v0;->b:Lt7/q0;

    .line 46
    .line 47
    iget-object v7, v7, Lt7/q0;->d:[Lt7/o;

    .line 48
    .line 49
    aget-object v7, v7, v6

    .line 50
    .line 51
    iget v8, v7, Lt7/o;->e:I

    .line 52
    .line 53
    and-int/lit8 v8, v8, 0x2

    .line 54
    .line 55
    if-eqz v8, :cond_2

    .line 56
    .line 57
    goto :goto_3

    .line 58
    :cond_2
    iget-object v8, p0, Ly9/r;->s:Lro/f;

    .line 59
    .line 60
    invoke-virtual {v8, v7}, Lro/f;->k(Lt7/o;)Ljava/lang/String;

    .line 61
    .line 62
    .line 63
    move-result-object v7

    .line 64
    new-instance v8, Ly9/o;

    .line 65
    .line 66
    invoke-direct {v8, p1, v3, v6, v7}, Ly9/o;-><init>(Lt7/w0;IILjava/lang/String;)V

    .line 67
    .line 68
    .line 69
    array-length v7, v0

    .line 70
    add-int/lit8 v9, v4, 0x1

    .line 71
    .line 72
    invoke-static {v7, v9}, Lhr/b0;->h(II)I

    .line 73
    .line 74
    .line 75
    move-result v7

    .line 76
    array-length v10, v0

    .line 77
    if-gt v7, v10, :cond_3

    .line 78
    .line 79
    goto :goto_2

    .line 80
    :cond_3
    invoke-static {v0, v7}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 81
    .line 82
    .line 83
    move-result-object v0

    .line 84
    :goto_2
    aput-object v8, v0, v4

    .line 85
    .line 86
    move v4, v9

    .line 87
    :goto_3
    add-int/lit8 v6, v6, 0x1

    .line 88
    .line 89
    goto :goto_1

    .line 90
    :cond_4
    :goto_4
    add-int/lit8 v3, v3, 0x1

    .line 91
    .line 92
    goto :goto_0

    .line 93
    :cond_5
    invoke-static {v4, v0}, Lhr/h0;->n(I[Ljava/lang/Object;)Lhr/x0;

    .line 94
    .line 95
    .line 96
    move-result-object p0

    .line 97
    return-object p0
.end method

.method public final g()V
    .locals 2

    .line 1
    iget-object p0, p0, Ly9/r;->d:Ly9/w;

    .line 2
    .line 3
    iget v0, p0, Ly9/w;->z:I

    .line 4
    .line 5
    const/4 v1, 0x3

    .line 6
    if-eq v0, v1, :cond_3

    .line 7
    .line 8
    const/4 v1, 0x2

    .line 9
    if-ne v0, v1, :cond_0

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    invoke-virtual {p0}, Ly9/w;->f()V

    .line 13
    .line 14
    .line 15
    iget-boolean v0, p0, Ly9/w;->C:Z

    .line 16
    .line 17
    if-nez v0, :cond_1

    .line 18
    .line 19
    invoke-virtual {p0, v1}, Ly9/w;->i(I)V

    .line 20
    .line 21
    .line 22
    return-void

    .line 23
    :cond_1
    iget v0, p0, Ly9/w;->z:I

    .line 24
    .line 25
    const/4 v1, 0x1

    .line 26
    if-ne v0, v1, :cond_2

    .line 27
    .line 28
    iget-object p0, p0, Ly9/w;->m:Landroid/animation/AnimatorSet;

    .line 29
    .line 30
    invoke-virtual {p0}, Landroid/animation/AnimatorSet;->start()V

    .line 31
    .line 32
    .line 33
    return-void

    .line 34
    :cond_2
    iget-object p0, p0, Ly9/w;->n:Landroid/animation/AnimatorSet;

    .line 35
    .line 36
    invoke-virtual {p0}, Landroid/animation/AnimatorSet;->start()V

    .line 37
    .line 38
    .line 39
    :cond_3
    :goto_0
    return-void
.end method

.method public getPlayer()Lt7/l0;
    .locals 0

    .line 1
    iget-object p0, p0, Ly9/r;->B1:Lt7/l0;

    .line 2
    .line 3
    return-object p0
.end method

.method public getRepeatToggleModes()I
    .locals 0

    .line 1
    iget p0, p0, Ly9/r;->L1:I

    .line 2
    .line 3
    return p0
.end method

.method public getShowShuffleButton()Z
    .locals 1

    .line 1
    iget-object v0, p0, Ly9/r;->d:Ly9/w;

    .line 2
    .line 3
    iget-object p0, p0, Ly9/r;->D:Landroid/widget/ImageView;

    .line 4
    .line 5
    invoke-virtual {v0, p0}, Ly9/w;->b(Landroid/view/View;)Z

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public getShowSubtitleButton()Z
    .locals 1

    .line 1
    iget-object v0, p0, Ly9/r;->d:Ly9/w;

    .line 2
    .line 3
    iget-object p0, p0, Ly9/r;->F:Landroid/widget/ImageView;

    .line 4
    .line 5
    invoke-virtual {v0, p0}, Ly9/w;->b(Landroid/view/View;)Z

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public getShowTimeoutMs()I
    .locals 0

    .line 1
    iget p0, p0, Ly9/r;->I1:I

    .line 2
    .line 3
    return p0
.end method

.method public getShowVrButton()Z
    .locals 1

    .line 1
    iget-object v0, p0, Ly9/r;->d:Ly9/w;

    .line 2
    .line 3
    iget-object p0, p0, Ly9/r;->E:Landroid/widget/ImageView;

    .line 4
    .line 5
    invoke-virtual {v0, p0}, Ly9/w;->b(Landroid/view/View;)Z

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public final h(Lt7/l0;)Z
    .locals 0

    .line 1
    if-eqz p1, :cond_0

    .line 2
    .line 3
    iget-object p0, p0, Ly9/r;->j:Ljava/lang/Class;

    .line 4
    .line 5
    if-eqz p0, :cond_0

    .line 6
    .line 7
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 8
    .line 9
    .line 10
    move-result-object p1

    .line 11
    invoke-virtual {p0, p1}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    if-eqz p0, :cond_0

    .line 16
    .line 17
    const/4 p0, 0x1

    .line 18
    return p0

    .line 19
    :cond_0
    const/4 p0, 0x0

    .line 20
    return p0
.end method

.method public final i(Lt7/l0;)Z
    .locals 0

    .line 1
    if-eqz p1, :cond_0

    .line 2
    .line 3
    iget-object p0, p0, Ly9/r;->g:Ljava/lang/Class;

    .line 4
    .line 5
    if-eqz p0, :cond_0

    .line 6
    .line 7
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 8
    .line 9
    .line 10
    move-result-object p1

    .line 11
    invoke-virtual {p0, p1}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    if-eqz p0, :cond_0

    .line 16
    .line 17
    const/4 p0, 0x1

    .line 18
    return p0

    .line 19
    :cond_0
    const/4 p0, 0x0

    .line 20
    return p0
.end method

.method public final j()Z
    .locals 1

    .line 1
    iget-object p0, p0, Ly9/r;->d:Ly9/w;

    .line 2
    .line 3
    iget v0, p0, Ly9/w;->z:I

    .line 4
    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    iget-object p0, p0, Ly9/w;->a:Ly9/r;

    .line 8
    .line 9
    invoke-virtual {p0}, Ly9/r;->l()Z

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    if-eqz p0, :cond_0

    .line 14
    .line 15
    const/4 p0, 0x1

    .line 16
    return p0

    .line 17
    :cond_0
    const/4 p0, 0x0

    .line 18
    return p0
.end method

.method public final k(Lt7/l0;)Z
    .locals 2

    .line 1
    :try_start_0
    invoke-virtual {p0, p1}, Ly9/r;->i(Lt7/l0;)Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x0

    .line 6
    if-eqz v0, :cond_0

    .line 7
    .line 8
    iget-object v0, p0, Ly9/r;->i:Ljava/lang/reflect/Method;

    .line 9
    .line 10
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 11
    .line 12
    .line 13
    invoke-virtual {v0, p1, v1}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 18
    .line 19
    .line 20
    check-cast v0, Ljava/lang/Boolean;

    .line 21
    .line 22
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    if-nez v0, :cond_1

    .line 27
    .line 28
    :cond_0
    invoke-virtual {p0, p1}, Ly9/r;->h(Lt7/l0;)Z

    .line 29
    .line 30
    .line 31
    move-result v0

    .line 32
    if-eqz v0, :cond_2

    .line 33
    .line 34
    iget-object p0, p0, Ly9/r;->l:Ljava/lang/reflect/Method;

    .line 35
    .line 36
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 37
    .line 38
    .line 39
    invoke-virtual {p0, p1, v1}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 44
    .line 45
    .line 46
    check-cast p0, Ljava/lang/Boolean;

    .line 47
    .line 48
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 49
    .line 50
    .line 51
    move-result p0
    :try_end_0
    .catch Ljava/lang/IllegalAccessException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/lang/reflect/InvocationTargetException; {:try_start_0 .. :try_end_0} :catch_0

    .line 52
    if-eqz p0, :cond_2

    .line 53
    .line 54
    :cond_1
    const/4 p0, 0x1

    .line 55
    return p0

    .line 56
    :cond_2
    const/4 p0, 0x0

    .line 57
    return p0

    .line 58
    :catch_0
    move-exception p0

    .line 59
    new-instance p1, Ljava/lang/RuntimeException;

    .line 60
    .line 61
    invoke-direct {p1, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 62
    .line 63
    .line 64
    throw p1
.end method

.method public final l()Z
    .locals 0

    .line 1
    invoke-virtual {p0}, Landroid/view/View;->getVisibility()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    if-nez p0, :cond_0

    .line 6
    .line 7
    const/4 p0, 0x1

    .line 8
    return p0

    .line 9
    :cond_0
    const/4 p0, 0x0

    .line 10
    return p0
.end method

.method public final m()V
    .locals 0

    .line 1
    invoke-virtual {p0}, Ly9/r;->q()V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0}, Ly9/r;->p()V

    .line 5
    .line 6
    .line 7
    invoke-virtual {p0}, Ly9/r;->t()V

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0}, Ly9/r;->v()V

    .line 11
    .line 12
    .line 13
    invoke-virtual {p0}, Ly9/r;->x()V

    .line 14
    .line 15
    .line 16
    invoke-virtual {p0}, Ly9/r;->r()V

    .line 17
    .line 18
    .line 19
    invoke-virtual {p0}, Ly9/r;->w()V

    .line 20
    .line 21
    .line 22
    return-void
.end method

.method public final n(Landroid/view/View;Z)V
    .locals 0

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    return-void

    .line 4
    :cond_0
    invoke-virtual {p1, p2}, Landroid/view/View;->setEnabled(Z)V

    .line 5
    .line 6
    .line 7
    if-eqz p2, :cond_1

    .line 8
    .line 9
    iget p0, p0, Ly9/r;->g0:F

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_1
    iget p0, p0, Ly9/r;->q1:F

    .line 13
    .line 14
    :goto_0
    invoke-virtual {p1, p0}, Landroid/view/View;->setAlpha(F)V

    .line 15
    .line 16
    .line 17
    return-void
.end method

.method public final o(Z)V
    .locals 5

    .line 1
    iget-boolean v0, p0, Ly9/r;->C1:Z

    .line 2
    .line 3
    if-ne v0, p1, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    iput-boolean p1, p0, Ly9/r;->C1:Z

    .line 7
    .line 8
    iget-object v0, p0, Ly9/r;->A1:Ljava/lang/String;

    .line 9
    .line 10
    iget-object v1, p0, Ly9/r;->y1:Landroid/graphics/drawable/Drawable;

    .line 11
    .line 12
    iget-object v2, p0, Ly9/r;->z1:Ljava/lang/String;

    .line 13
    .line 14
    iget-object v3, p0, Ly9/r;->x1:Landroid/graphics/drawable/Drawable;

    .line 15
    .line 16
    iget-object v4, p0, Ly9/r;->G:Landroid/widget/ImageView;

    .line 17
    .line 18
    if-nez v4, :cond_1

    .line 19
    .line 20
    goto :goto_0

    .line 21
    :cond_1
    if-eqz p1, :cond_2

    .line 22
    .line 23
    invoke-virtual {v4, v3}, Landroid/widget/ImageView;->setImageDrawable(Landroid/graphics/drawable/Drawable;)V

    .line 24
    .line 25
    .line 26
    invoke-virtual {v4, v2}, Landroid/view/View;->setContentDescription(Ljava/lang/CharSequence;)V

    .line 27
    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_2
    invoke-virtual {v4, v1}, Landroid/widget/ImageView;->setImageDrawable(Landroid/graphics/drawable/Drawable;)V

    .line 31
    .line 32
    .line 33
    invoke-virtual {v4, v0}, Landroid/view/View;->setContentDescription(Ljava/lang/CharSequence;)V

    .line 34
    .line 35
    .line 36
    :goto_0
    iget-object p0, p0, Ly9/r;->H:Landroid/widget/ImageView;

    .line 37
    .line 38
    if-nez p0, :cond_3

    .line 39
    .line 40
    goto :goto_1

    .line 41
    :cond_3
    if-eqz p1, :cond_4

    .line 42
    .line 43
    invoke-virtual {p0, v3}, Landroid/widget/ImageView;->setImageDrawable(Landroid/graphics/drawable/Drawable;)V

    .line 44
    .line 45
    .line 46
    invoke-virtual {p0, v2}, Landroid/view/View;->setContentDescription(Ljava/lang/CharSequence;)V

    .line 47
    .line 48
    .line 49
    goto :goto_1

    .line 50
    :cond_4
    invoke-virtual {p0, v1}, Landroid/widget/ImageView;->setImageDrawable(Landroid/graphics/drawable/Drawable;)V

    .line 51
    .line 52
    .line 53
    invoke-virtual {p0, v0}, Landroid/view/View;->setContentDescription(Ljava/lang/CharSequence;)V

    .line 54
    .line 55
    .line 56
    :goto_1
    return-void
.end method

.method public final onAttachedToWindow()V
    .locals 3

    .line 1
    invoke-super {p0}, Landroid/view/View;->onAttachedToWindow()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Ly9/r;->d:Ly9/w;

    .line 5
    .line 6
    iget-object v1, v0, Ly9/w;->a:Ly9/r;

    .line 7
    .line 8
    iget-object v2, v0, Ly9/w;->x:Lkq/a;

    .line 9
    .line 10
    invoke-virtual {v1, v2}, Landroid/view/View;->addOnLayoutChangeListener(Landroid/view/View$OnLayoutChangeListener;)V

    .line 11
    .line 12
    .line 13
    const/4 v1, 0x1

    .line 14
    iput-boolean v1, p0, Ly9/r;->D1:Z

    .line 15
    .line 16
    invoke-virtual {p0}, Ly9/r;->j()Z

    .line 17
    .line 18
    .line 19
    move-result v1

    .line 20
    if-eqz v1, :cond_0

    .line 21
    .line 22
    invoke-virtual {v0}, Ly9/w;->g()V

    .line 23
    .line 24
    .line 25
    :cond_0
    invoke-virtual {p0}, Ly9/r;->m()V

    .line 26
    .line 27
    .line 28
    return-void
.end method

.method public final onDetachedFromWindow()V
    .locals 3

    .line 1
    invoke-super {p0}, Landroid/view/View;->onDetachedFromWindow()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Ly9/r;->d:Ly9/w;

    .line 5
    .line 6
    iget-object v1, v0, Ly9/w;->a:Ly9/r;

    .line 7
    .line 8
    iget-object v2, v0, Ly9/w;->x:Lkq/a;

    .line 9
    .line 10
    invoke-virtual {v1, v2}, Landroid/view/View;->removeOnLayoutChangeListener(Landroid/view/View$OnLayoutChangeListener;)V

    .line 11
    .line 12
    .line 13
    const/4 v1, 0x0

    .line 14
    iput-boolean v1, p0, Ly9/r;->D1:Z

    .line 15
    .line 16
    iget-object v1, p0, Ly9/r;->S:Lm8/o;

    .line 17
    .line 18
    invoke-virtual {p0, v1}, Landroid/view/View;->removeCallbacks(Ljava/lang/Runnable;)Z

    .line 19
    .line 20
    .line 21
    invoke-virtual {v0}, Ly9/w;->f()V

    .line 22
    .line 23
    .line 24
    return-void
.end method

.method public final onLayout(ZIIII)V
    .locals 0

    .line 1
    invoke-super/range {p0 .. p5}, Landroid/widget/FrameLayout;->onLayout(ZIIII)V

    .line 2
    .line 3
    .line 4
    iget-object p0, p0, Ly9/r;->d:Ly9/w;

    .line 5
    .line 6
    iget-object p0, p0, Ly9/w;->b:Landroid/view/View;

    .line 7
    .line 8
    if-eqz p0, :cond_0

    .line 9
    .line 10
    sub-int/2addr p4, p2

    .line 11
    sub-int/2addr p5, p3

    .line 12
    const/4 p1, 0x0

    .line 13
    invoke-virtual {p0, p1, p1, p4, p5}, Landroid/view/View;->layout(IIII)V

    .line 14
    .line 15
    .line 16
    :cond_0
    return-void
.end method

.method public final p()V
    .locals 12

    .line 1
    invoke-virtual {p0}, Ly9/r;->l()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_9

    .line 6
    .line 7
    iget-boolean v0, p0, Ly9/r;->D1:Z

    .line 8
    .line 9
    if-nez v0, :cond_0

    .line 10
    .line 11
    goto/16 :goto_4

    .line 12
    .line 13
    :cond_0
    iget-object v0, p0, Ly9/r;->B1:Lt7/l0;

    .line 14
    .line 15
    if-eqz v0, :cond_2

    .line 16
    .line 17
    iget-boolean v1, p0, Ly9/r;->E1:Z

    .line 18
    .line 19
    if-eqz v1, :cond_1

    .line 20
    .line 21
    iget-object v1, p0, Ly9/r;->R:Lt7/o0;

    .line 22
    .line 23
    invoke-static {v0, v1}, Ly9/r;->c(Lt7/l0;Lt7/o0;)Z

    .line 24
    .line 25
    .line 26
    move-result v1

    .line 27
    if-eqz v1, :cond_1

    .line 28
    .line 29
    const/16 v1, 0xa

    .line 30
    .line 31
    move-object v2, v0

    .line 32
    check-cast v2, Lap0/o;

    .line 33
    .line 34
    invoke-virtual {v2, v1}, Lap0/o;->I(I)Z

    .line 35
    .line 36
    .line 37
    move-result v1

    .line 38
    goto :goto_0

    .line 39
    :cond_1
    const/4 v1, 0x5

    .line 40
    move-object v2, v0

    .line 41
    check-cast v2, Lap0/o;

    .line 42
    .line 43
    invoke-virtual {v2, v1}, Lap0/o;->I(I)Z

    .line 44
    .line 45
    .line 46
    move-result v1

    .line 47
    :goto_0
    check-cast v0, Lap0/o;

    .line 48
    .line 49
    const/4 v2, 0x7

    .line 50
    invoke-virtual {v0, v2}, Lap0/o;->I(I)Z

    .line 51
    .line 52
    .line 53
    move-result v2

    .line 54
    const/16 v3, 0xb

    .line 55
    .line 56
    invoke-virtual {v0, v3}, Lap0/o;->I(I)Z

    .line 57
    .line 58
    .line 59
    move-result v3

    .line 60
    const/16 v4, 0xc

    .line 61
    .line 62
    invoke-virtual {v0, v4}, Lap0/o;->I(I)Z

    .line 63
    .line 64
    .line 65
    move-result v4

    .line 66
    const/16 v5, 0x9

    .line 67
    .line 68
    invoke-virtual {v0, v5}, Lap0/o;->I(I)Z

    .line 69
    .line 70
    .line 71
    move-result v0

    .line 72
    goto :goto_1

    .line 73
    :cond_2
    const/4 v1, 0x0

    .line 74
    move v0, v1

    .line 75
    move v2, v0

    .line 76
    move v3, v2

    .line 77
    move v4, v3

    .line 78
    :goto_1
    iget-object v5, p0, Ly9/r;->e:Landroid/content/res/Resources;

    .line 79
    .line 80
    iget-object v6, p0, Ly9/r;->z:Landroid/view/View;

    .line 81
    .line 82
    const-wide/16 v7, 0x3e8

    .line 83
    .line 84
    if-eqz v3, :cond_5

    .line 85
    .line 86
    iget-object v9, p0, Ly9/r;->B1:Lt7/l0;

    .line 87
    .line 88
    if-eqz v9, :cond_3

    .line 89
    .line 90
    check-cast v9, La8/i0;

    .line 91
    .line 92
    invoke-virtual {v9}, La8/i0;->L0()V

    .line 93
    .line 94
    .line 95
    iget-wide v9, v9, La8/i0;->z:J

    .line 96
    .line 97
    goto :goto_2

    .line 98
    :cond_3
    const-wide/16 v9, 0x1388

    .line 99
    .line 100
    :goto_2
    div-long/2addr v9, v7

    .line 101
    long-to-int v9, v9

    .line 102
    iget-object v10, p0, Ly9/r;->B:Landroid/widget/TextView;

    .line 103
    .line 104
    if-eqz v10, :cond_4

    .line 105
    .line 106
    invoke-static {v9}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 107
    .line 108
    .line 109
    move-result-object v11

    .line 110
    invoke-virtual {v10, v11}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

    .line 111
    .line 112
    .line 113
    :cond_4
    if-eqz v6, :cond_5

    .line 114
    .line 115
    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 116
    .line 117
    .line 118
    move-result-object v10

    .line 119
    filled-new-array {v10}, [Ljava/lang/Object;

    .line 120
    .line 121
    .line 122
    move-result-object v10

    .line 123
    const v11, 0x7f100001

    .line 124
    .line 125
    .line 126
    invoke-virtual {v5, v11, v9, v10}, Landroid/content/res/Resources;->getQuantityString(II[Ljava/lang/Object;)Ljava/lang/String;

    .line 127
    .line 128
    .line 129
    move-result-object v9

    .line 130
    invoke-virtual {v6, v9}, Landroid/view/View;->setContentDescription(Ljava/lang/CharSequence;)V

    .line 131
    .line 132
    .line 133
    :cond_5
    iget-object v9, p0, Ly9/r;->y:Landroid/view/View;

    .line 134
    .line 135
    if-eqz v4, :cond_8

    .line 136
    .line 137
    iget-object v10, p0, Ly9/r;->B1:Lt7/l0;

    .line 138
    .line 139
    if-eqz v10, :cond_6

    .line 140
    .line 141
    check-cast v10, La8/i0;

    .line 142
    .line 143
    invoke-virtual {v10}, La8/i0;->L0()V

    .line 144
    .line 145
    .line 146
    iget-wide v10, v10, La8/i0;->A:J

    .line 147
    .line 148
    goto :goto_3

    .line 149
    :cond_6
    const-wide/16 v10, 0x3a98

    .line 150
    .line 151
    :goto_3
    div-long/2addr v10, v7

    .line 152
    long-to-int v7, v10

    .line 153
    iget-object v8, p0, Ly9/r;->A:Landroid/widget/TextView;

    .line 154
    .line 155
    if-eqz v8, :cond_7

    .line 156
    .line 157
    invoke-static {v7}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 158
    .line 159
    .line 160
    move-result-object v10

    .line 161
    invoke-virtual {v8, v10}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

    .line 162
    .line 163
    .line 164
    :cond_7
    if-eqz v9, :cond_8

    .line 165
    .line 166
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 167
    .line 168
    .line 169
    move-result-object v8

    .line 170
    filled-new-array {v8}, [Ljava/lang/Object;

    .line 171
    .line 172
    .line 173
    move-result-object v8

    .line 174
    const/high16 v10, 0x7f100000

    .line 175
    .line 176
    invoke-virtual {v5, v10, v7, v8}, Landroid/content/res/Resources;->getQuantityString(II[Ljava/lang/Object;)Ljava/lang/String;

    .line 177
    .line 178
    .line 179
    move-result-object v5

    .line 180
    invoke-virtual {v9, v5}, Landroid/view/View;->setContentDescription(Ljava/lang/CharSequence;)V

    .line 181
    .line 182
    .line 183
    :cond_8
    iget-object v5, p0, Ly9/r;->v:Landroid/widget/ImageView;

    .line 184
    .line 185
    invoke-virtual {p0, v5, v2}, Ly9/r;->n(Landroid/view/View;Z)V

    .line 186
    .line 187
    .line 188
    invoke-virtual {p0, v6, v3}, Ly9/r;->n(Landroid/view/View;Z)V

    .line 189
    .line 190
    .line 191
    invoke-virtual {p0, v9, v4}, Ly9/r;->n(Landroid/view/View;Z)V

    .line 192
    .line 193
    .line 194
    iget-object v2, p0, Ly9/r;->w:Landroid/widget/ImageView;

    .line 195
    .line 196
    invoke-virtual {p0, v2, v0}, Ly9/r;->n(Landroid/view/View;Z)V

    .line 197
    .line 198
    .line 199
    iget-object p0, p0, Ly9/r;->N:Ly9/h0;

    .line 200
    .line 201
    if-eqz p0, :cond_9

    .line 202
    .line 203
    check-cast p0, Ly9/d;

    .line 204
    .line 205
    invoke-virtual {p0, v1}, Ly9/d;->setEnabled(Z)V

    .line 206
    .line 207
    .line 208
    :cond_9
    :goto_4
    return-void
.end method

.method public final q()V
    .locals 5

    .line 1
    invoke-virtual {p0}, Ly9/r;->l()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_5

    .line 6
    .line 7
    iget-boolean v0, p0, Ly9/r;->D1:Z

    .line 8
    .line 9
    if-nez v0, :cond_0

    .line 10
    .line 11
    goto :goto_3

    .line 12
    :cond_0
    iget-object v0, p0, Ly9/r;->x:Landroid/widget/ImageView;

    .line 13
    .line 14
    if-eqz v0, :cond_5

    .line 15
    .line 16
    iget-object v1, p0, Ly9/r;->B1:Lt7/l0;

    .line 17
    .line 18
    iget-boolean v2, p0, Ly9/r;->F1:Z

    .line 19
    .line 20
    invoke-static {v1, v2}, Lw7/w;->L(Lt7/l0;Z)Z

    .line 21
    .line 22
    .line 23
    move-result v1

    .line 24
    if-eqz v1, :cond_1

    .line 25
    .line 26
    iget-object v2, p0, Ly9/r;->T:Landroid/graphics/drawable/Drawable;

    .line 27
    .line 28
    goto :goto_0

    .line 29
    :cond_1
    iget-object v2, p0, Ly9/r;->U:Landroid/graphics/drawable/Drawable;

    .line 30
    .line 31
    :goto_0
    if-eqz v1, :cond_2

    .line 32
    .line 33
    const v1, 0x7f1202d6

    .line 34
    .line 35
    .line 36
    goto :goto_1

    .line 37
    :cond_2
    const v1, 0x7f1202d5

    .line 38
    .line 39
    .line 40
    :goto_1
    invoke-virtual {v0, v2}, Landroid/widget/ImageView;->setImageDrawable(Landroid/graphics/drawable/Drawable;)V

    .line 41
    .line 42
    .line 43
    iget-object v2, p0, Ly9/r;->e:Landroid/content/res/Resources;

    .line 44
    .line 45
    invoke-virtual {v2, v1}, Landroid/content/res/Resources;->getString(I)Ljava/lang/String;

    .line 46
    .line 47
    .line 48
    move-result-object v1

    .line 49
    invoke-virtual {v0, v1}, Landroid/view/View;->setContentDescription(Ljava/lang/CharSequence;)V

    .line 50
    .line 51
    .line 52
    iget-object v1, p0, Ly9/r;->B1:Lt7/l0;

    .line 53
    .line 54
    if-eqz v1, :cond_3

    .line 55
    .line 56
    move-object v2, v1

    .line 57
    check-cast v2, Lap0/o;

    .line 58
    .line 59
    const/4 v3, 0x1

    .line 60
    invoke-virtual {v2, v3}, Lap0/o;->I(I)Z

    .line 61
    .line 62
    .line 63
    move-result v4

    .line 64
    if-eqz v4, :cond_3

    .line 65
    .line 66
    const/16 v4, 0x11

    .line 67
    .line 68
    invoke-virtual {v2, v4}, Lap0/o;->I(I)Z

    .line 69
    .line 70
    .line 71
    move-result v2

    .line 72
    if-eqz v2, :cond_4

    .line 73
    .line 74
    check-cast v1, La8/i0;

    .line 75
    .line 76
    invoke-virtual {v1}, La8/i0;->k0()Lt7/p0;

    .line 77
    .line 78
    .line 79
    move-result-object v1

    .line 80
    invoke-virtual {v1}, Lt7/p0;->p()Z

    .line 81
    .line 82
    .line 83
    move-result v1

    .line 84
    if-nez v1, :cond_3

    .line 85
    .line 86
    goto :goto_2

    .line 87
    :cond_3
    const/4 v3, 0x0

    .line 88
    :cond_4
    :goto_2
    invoke-virtual {p0, v0, v3}, Ly9/r;->n(Landroid/view/View;Z)V

    .line 89
    .line 90
    .line 91
    :cond_5
    :goto_3
    return-void
.end method

.method public final r()V
    .locals 8

    .line 1
    iget-object v0, p0, Ly9/r;->B1:Lt7/l0;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    check-cast v0, La8/i0;

    .line 7
    .line 8
    invoke-virtual {v0}, La8/i0;->L0()V

    .line 9
    .line 10
    .line 11
    iget-object v0, v0, La8/i0;->y1:La8/i1;

    .line 12
    .line 13
    iget-object v0, v0, La8/i1;->o:Lt7/g0;

    .line 14
    .line 15
    iget v0, v0, Lt7/g0;->a:F

    .line 16
    .line 17
    const/4 v1, 0x0

    .line 18
    const v2, 0x7f7fffff    # Float.MAX_VALUE

    .line 19
    .line 20
    .line 21
    move v3, v1

    .line 22
    move v4, v3

    .line 23
    :goto_0
    iget-object v5, p0, Ly9/r;->p:Ly9/j;

    .line 24
    .line 25
    iget-object v6, v5, Ly9/j;->e:[F

    .line 26
    .line 27
    array-length v7, v6

    .line 28
    if-ge v3, v7, :cond_2

    .line 29
    .line 30
    aget v5, v6, v3

    .line 31
    .line 32
    sub-float v5, v0, v5

    .line 33
    .line 34
    invoke-static {v5}, Ljava/lang/Math;->abs(F)F

    .line 35
    .line 36
    .line 37
    move-result v5

    .line 38
    cmpg-float v6, v5, v2

    .line 39
    .line 40
    if-gez v6, :cond_1

    .line 41
    .line 42
    move v4, v3

    .line 43
    move v2, v5

    .line 44
    :cond_1
    add-int/lit8 v3, v3, 0x1

    .line 45
    .line 46
    goto :goto_0

    .line 47
    :cond_2
    iput v4, v5, Ly9/j;->f:I

    .line 48
    .line 49
    iget-object v0, v5, Ly9/j;->d:[Ljava/lang/String;

    .line 50
    .line 51
    aget-object v0, v0, v4

    .line 52
    .line 53
    iget-object v2, p0, Ly9/r;->o:Ly9/m;

    .line 54
    .line 55
    iget-object v3, v2, Ly9/m;->e:[Ljava/lang/String;

    .line 56
    .line 57
    aput-object v0, v3, v1

    .line 58
    .line 59
    const/4 v0, 0x1

    .line 60
    invoke-virtual {v2, v0}, Ly9/m;->e(I)Z

    .line 61
    .line 62
    .line 63
    move-result v3

    .line 64
    if-nez v3, :cond_3

    .line 65
    .line 66
    invoke-virtual {v2, v1}, Ly9/m;->e(I)Z

    .line 67
    .line 68
    .line 69
    move-result v2

    .line 70
    if-eqz v2, :cond_4

    .line 71
    .line 72
    :cond_3
    move v1, v0

    .line 73
    :cond_4
    iget-object v0, p0, Ly9/r;->I:Landroid/view/View;

    .line 74
    .line 75
    invoke-virtual {p0, v0, v1}, Ly9/r;->n(Landroid/view/View;Z)V

    .line 76
    .line 77
    .line 78
    return-void
.end method

.method public final s()V
    .locals 13

    .line 1
    invoke-virtual {p0}, Ly9/r;->l()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_c

    .line 6
    .line 7
    iget-boolean v0, p0, Ly9/r;->D1:Z

    .line 8
    .line 9
    if-nez v0, :cond_0

    .line 10
    .line 11
    goto/16 :goto_5

    .line 12
    .line 13
    :cond_0
    iget-object v0, p0, Ly9/r;->B1:Lt7/l0;

    .line 14
    .line 15
    const-wide/16 v1, 0x0

    .line 16
    .line 17
    if-eqz v0, :cond_4

    .line 18
    .line 19
    const/16 v3, 0x10

    .line 20
    .line 21
    move-object v4, v0

    .line 22
    check-cast v4, Lap0/o;

    .line 23
    .line 24
    invoke-virtual {v4, v3}, Lap0/o;->I(I)Z

    .line 25
    .line 26
    .line 27
    move-result v3

    .line 28
    if-eqz v3, :cond_4

    .line 29
    .line 30
    iget-wide v3, p0, Ly9/r;->Q1:J

    .line 31
    .line 32
    move-object v5, v0

    .line 33
    check-cast v5, La8/i0;

    .line 34
    .line 35
    invoke-virtual {v5}, La8/i0;->L0()V

    .line 36
    .line 37
    .line 38
    iget-object v6, v5, La8/i0;->y1:La8/i1;

    .line 39
    .line 40
    invoke-virtual {v5, v6}, La8/i0;->e0(La8/i1;)J

    .line 41
    .line 42
    .line 43
    move-result-wide v6

    .line 44
    add-long/2addr v6, v3

    .line 45
    iget-wide v3, p0, Ly9/r;->Q1:J

    .line 46
    .line 47
    invoke-virtual {v5}, La8/i0;->L0()V

    .line 48
    .line 49
    .line 50
    iget-object v8, v5, La8/i0;->y1:La8/i1;

    .line 51
    .line 52
    iget-object v8, v8, La8/i1;->a:Lt7/p0;

    .line 53
    .line 54
    invoke-virtual {v8}, Lt7/p0;->p()Z

    .line 55
    .line 56
    .line 57
    move-result v8

    .line 58
    if-eqz v8, :cond_1

    .line 59
    .line 60
    iget-wide v1, v5, La8/i0;->A1:J

    .line 61
    .line 62
    goto :goto_1

    .line 63
    :cond_1
    iget-object v8, v5, La8/i0;->y1:La8/i1;

    .line 64
    .line 65
    iget-object v9, v8, La8/i1;->k:Lh8/b0;

    .line 66
    .line 67
    iget-wide v9, v9, Lh8/b0;->d:J

    .line 68
    .line 69
    iget-object v11, v8, La8/i1;->b:Lh8/b0;

    .line 70
    .line 71
    iget-wide v11, v11, Lh8/b0;->d:J

    .line 72
    .line 73
    cmp-long v9, v9, v11

    .line 74
    .line 75
    if-eqz v9, :cond_2

    .line 76
    .line 77
    iget-object v8, v8, La8/i1;->a:Lt7/p0;

    .line 78
    .line 79
    invoke-virtual {v5}, La8/i0;->h0()I

    .line 80
    .line 81
    .line 82
    move-result v9

    .line 83
    iget-object v5, v5, Lap0/o;->e:Ljava/lang/Object;

    .line 84
    .line 85
    check-cast v5, Lt7/o0;

    .line 86
    .line 87
    invoke-virtual {v8, v9, v5, v1, v2}, Lt7/p0;->m(ILt7/o0;J)Lt7/o0;

    .line 88
    .line 89
    .line 90
    move-result-object v1

    .line 91
    iget-wide v1, v1, Lt7/o0;->l:J

    .line 92
    .line 93
    invoke-static {v1, v2}, Lw7/w;->N(J)J

    .line 94
    .line 95
    .line 96
    move-result-wide v1

    .line 97
    goto :goto_1

    .line 98
    :cond_2
    iget-wide v8, v8, La8/i1;->q:J

    .line 99
    .line 100
    iget-object v10, v5, La8/i0;->y1:La8/i1;

    .line 101
    .line 102
    iget-object v10, v10, La8/i1;->k:Lh8/b0;

    .line 103
    .line 104
    invoke-virtual {v10}, Lh8/b0;->b()Z

    .line 105
    .line 106
    .line 107
    move-result v10

    .line 108
    if-eqz v10, :cond_3

    .line 109
    .line 110
    iget-object v8, v5, La8/i0;->y1:La8/i1;

    .line 111
    .line 112
    iget-object v9, v8, La8/i1;->a:Lt7/p0;

    .line 113
    .line 114
    iget-object v8, v8, La8/i1;->k:Lh8/b0;

    .line 115
    .line 116
    iget-object v8, v8, Lh8/b0;->a:Ljava/lang/Object;

    .line 117
    .line 118
    iget-object v10, v5, La8/i0;->s:Lt7/n0;

    .line 119
    .line 120
    invoke-virtual {v9, v8, v10}, Lt7/p0;->g(Ljava/lang/Object;Lt7/n0;)Lt7/n0;

    .line 121
    .line 122
    .line 123
    move-result-object v8

    .line 124
    iget-object v9, v5, La8/i0;->y1:La8/i1;

    .line 125
    .line 126
    iget-object v9, v9, La8/i1;->k:Lh8/b0;

    .line 127
    .line 128
    iget v9, v9, Lh8/b0;->b:I

    .line 129
    .line 130
    invoke-virtual {v8, v9}, Lt7/n0;->d(I)J

    .line 131
    .line 132
    .line 133
    goto :goto_0

    .line 134
    :cond_3
    move-wide v1, v8

    .line 135
    :goto_0
    iget-object v8, v5, La8/i0;->y1:La8/i1;

    .line 136
    .line 137
    iget-object v9, v8, La8/i1;->a:Lt7/p0;

    .line 138
    .line 139
    iget-object v8, v8, La8/i1;->k:Lh8/b0;

    .line 140
    .line 141
    iget-object v8, v8, Lh8/b0;->a:Ljava/lang/Object;

    .line 142
    .line 143
    iget-object v5, v5, La8/i0;->s:Lt7/n0;

    .line 144
    .line 145
    invoke-virtual {v9, v8, v5}, Lt7/p0;->g(Ljava/lang/Object;Lt7/n0;)Lt7/n0;

    .line 146
    .line 147
    .line 148
    iget-wide v8, v5, Lt7/n0;->e:J

    .line 149
    .line 150
    add-long/2addr v1, v8

    .line 151
    invoke-static {v1, v2}, Lw7/w;->N(J)J

    .line 152
    .line 153
    .line 154
    move-result-wide v1

    .line 155
    :goto_1
    add-long/2addr v1, v3

    .line 156
    move-wide v3, v1

    .line 157
    move-wide v1, v6

    .line 158
    goto :goto_2

    .line 159
    :cond_4
    move-wide v3, v1

    .line 160
    :goto_2
    iget-object v5, p0, Ly9/r;->M:Landroid/widget/TextView;

    .line 161
    .line 162
    if-eqz v5, :cond_5

    .line 163
    .line 164
    iget-boolean v6, p0, Ly9/r;->H1:Z

    .line 165
    .line 166
    if-nez v6, :cond_5

    .line 167
    .line 168
    iget-object v6, p0, Ly9/r;->O:Ljava/lang/StringBuilder;

    .line 169
    .line 170
    iget-object v7, p0, Ly9/r;->P:Ljava/util/Formatter;

    .line 171
    .line 172
    invoke-static {v6, v7, v1, v2}, Lw7/w;->u(Ljava/lang/StringBuilder;Ljava/util/Formatter;J)Ljava/lang/String;

    .line 173
    .line 174
    .line 175
    move-result-object v6

    .line 176
    invoke-virtual {v5, v6}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

    .line 177
    .line 178
    .line 179
    :cond_5
    iget-object v5, p0, Ly9/r;->N:Ly9/h0;

    .line 180
    .line 181
    if-eqz v5, :cond_7

    .line 182
    .line 183
    check-cast v5, Ly9/d;

    .line 184
    .line 185
    invoke-virtual {v5, v1, v2}, Ly9/d;->setPosition(J)V

    .line 186
    .line 187
    .line 188
    iget-object v5, p0, Ly9/r;->N:Ly9/h0;

    .line 189
    .line 190
    invoke-virtual {p0, v0}, Ly9/r;->k(Lt7/l0;)Z

    .line 191
    .line 192
    .line 193
    move-result v6

    .line 194
    if-eqz v6, :cond_6

    .line 195
    .line 196
    move-wide v3, v1

    .line 197
    :cond_6
    check-cast v5, Ly9/d;

    .line 198
    .line 199
    invoke-virtual {v5, v3, v4}, Ly9/d;->setBufferedPosition(J)V

    .line 200
    .line 201
    .line 202
    :cond_7
    iget-object v3, p0, Ly9/r;->S:Lm8/o;

    .line 203
    .line 204
    invoke-virtual {p0, v3}, Landroid/view/View;->removeCallbacks(Ljava/lang/Runnable;)Z

    .line 205
    .line 206
    .line 207
    const/4 v3, 0x1

    .line 208
    if-nez v0, :cond_8

    .line 209
    .line 210
    move v4, v3

    .line 211
    goto :goto_3

    .line 212
    :cond_8
    move-object v4, v0

    .line 213
    check-cast v4, La8/i0;

    .line 214
    .line 215
    invoke-virtual {v4}, La8/i0;->o0()I

    .line 216
    .line 217
    .line 218
    move-result v4

    .line 219
    :goto_3
    const-wide/16 v5, 0x3e8

    .line 220
    .line 221
    if-eqz v0, :cond_b

    .line 222
    .line 223
    move-object v7, v0

    .line 224
    check-cast v7, Lap0/o;

    .line 225
    .line 226
    check-cast v7, La8/i0;

    .line 227
    .line 228
    invoke-virtual {v7}, La8/i0;->o0()I

    .line 229
    .line 230
    .line 231
    move-result v8

    .line 232
    const/4 v9, 0x3

    .line 233
    if-ne v8, v9, :cond_b

    .line 234
    .line 235
    invoke-virtual {v7}, La8/i0;->n0()Z

    .line 236
    .line 237
    .line 238
    move-result v8

    .line 239
    if-eqz v8, :cond_b

    .line 240
    .line 241
    invoke-virtual {v7}, La8/i0;->L0()V

    .line 242
    .line 243
    .line 244
    iget-object v7, v7, La8/i0;->y1:La8/i1;

    .line 245
    .line 246
    iget v7, v7, La8/i1;->n:I

    .line 247
    .line 248
    if-nez v7, :cond_b

    .line 249
    .line 250
    iget-object v3, p0, Ly9/r;->N:Ly9/h0;

    .line 251
    .line 252
    if-eqz v3, :cond_9

    .line 253
    .line 254
    check-cast v3, Ly9/d;

    .line 255
    .line 256
    invoke-virtual {v3}, Ly9/d;->getPreferredUpdateDelay()J

    .line 257
    .line 258
    .line 259
    move-result-wide v3

    .line 260
    goto :goto_4

    .line 261
    :cond_9
    move-wide v3, v5

    .line 262
    :goto_4
    rem-long/2addr v1, v5

    .line 263
    sub-long v1, v5, v1

    .line 264
    .line 265
    invoke-static {v3, v4, v1, v2}, Ljava/lang/Math;->min(JJ)J

    .line 266
    .line 267
    .line 268
    move-result-wide v1

    .line 269
    check-cast v0, La8/i0;

    .line 270
    .line 271
    invoke-virtual {v0}, La8/i0;->L0()V

    .line 272
    .line 273
    .line 274
    iget-object v0, v0, La8/i0;->y1:La8/i1;

    .line 275
    .line 276
    iget-object v0, v0, La8/i1;->o:Lt7/g0;

    .line 277
    .line 278
    iget v0, v0, Lt7/g0;->a:F

    .line 279
    .line 280
    const/4 v3, 0x0

    .line 281
    cmpl-float v3, v0, v3

    .line 282
    .line 283
    if-lez v3, :cond_a

    .line 284
    .line 285
    long-to-float v1, v1

    .line 286
    div-float/2addr v1, v0

    .line 287
    float-to-long v5, v1

    .line 288
    :cond_a
    move-wide v7, v5

    .line 289
    iget v0, p0, Ly9/r;->K1:I

    .line 290
    .line 291
    int-to-long v9, v0

    .line 292
    const-wide/16 v11, 0x3e8

    .line 293
    .line 294
    invoke-static/range {v7 .. v12}, Lw7/w;->h(JJJ)J

    .line 295
    .line 296
    .line 297
    move-result-wide v0

    .line 298
    iget-object v2, p0, Ly9/r;->S:Lm8/o;

    .line 299
    .line 300
    invoke-virtual {p0, v2, v0, v1}, Landroid/view/View;->postDelayed(Ljava/lang/Runnable;J)Z

    .line 301
    .line 302
    .line 303
    return-void

    .line 304
    :cond_b
    const/4 v0, 0x4

    .line 305
    if-eq v4, v0, :cond_c

    .line 306
    .line 307
    if-eq v4, v3, :cond_c

    .line 308
    .line 309
    iget-object v0, p0, Ly9/r;->S:Lm8/o;

    .line 310
    .line 311
    invoke-virtual {p0, v0, v5, v6}, Landroid/view/View;->postDelayed(Ljava/lang/Runnable;J)Z

    .line 312
    .line 313
    .line 314
    :cond_c
    :goto_5
    return-void
.end method

.method public setAnimationEnabled(Z)V
    .locals 0

    .line 1
    iget-object p0, p0, Ly9/r;->d:Ly9/w;

    .line 2
    .line 3
    iput-boolean p1, p0, Ly9/w;->C:Z

    .line 4
    .line 5
    return-void
.end method

.method public setOnFullScreenModeChangedListener(Ly9/h;)V
    .locals 5
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 1
    const/4 v0, 0x0

    .line 2
    const/4 v1, 0x1

    .line 3
    if-eqz p1, :cond_0

    .line 4
    .line 5
    move v2, v1

    .line 6
    goto :goto_0

    .line 7
    :cond_0
    move v2, v0

    .line 8
    :goto_0
    const/16 v3, 0x8

    .line 9
    .line 10
    iget-object v4, p0, Ly9/r;->G:Landroid/widget/ImageView;

    .line 11
    .line 12
    if-nez v4, :cond_1

    .line 13
    .line 14
    goto :goto_1

    .line 15
    :cond_1
    if-eqz v2, :cond_2

    .line 16
    .line 17
    invoke-virtual {v4, v0}, Landroid/view/View;->setVisibility(I)V

    .line 18
    .line 19
    .line 20
    goto :goto_1

    .line 21
    :cond_2
    invoke-virtual {v4, v3}, Landroid/view/View;->setVisibility(I)V

    .line 22
    .line 23
    .line 24
    :goto_1
    if-eqz p1, :cond_3

    .line 25
    .line 26
    goto :goto_2

    .line 27
    :cond_3
    move v1, v0

    .line 28
    :goto_2
    iget-object p0, p0, Ly9/r;->H:Landroid/widget/ImageView;

    .line 29
    .line 30
    if-nez p0, :cond_4

    .line 31
    .line 32
    return-void

    .line 33
    :cond_4
    if-eqz v1, :cond_5

    .line 34
    .line 35
    invoke-virtual {p0, v0}, Landroid/view/View;->setVisibility(I)V

    .line 36
    .line 37
    .line 38
    return-void

    .line 39
    :cond_5
    invoke-virtual {p0, v3}, Landroid/view/View;->setVisibility(I)V

    .line 40
    .line 41
    .line 42
    return-void
.end method

.method public setPlayer(Lt7/l0;)V
    .locals 4

    .line 1
    invoke-static {}, Landroid/os/Looper;->myLooper()Landroid/os/Looper;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    const/4 v2, 0x0

    .line 10
    const/4 v3, 0x1

    .line 11
    if-ne v0, v1, :cond_0

    .line 12
    .line 13
    move v0, v3

    .line 14
    goto :goto_0

    .line 15
    :cond_0
    move v0, v2

    .line 16
    :goto_0
    invoke-static {v0}, Lw7/a;->j(Z)V

    .line 17
    .line 18
    .line 19
    if-eqz p1, :cond_1

    .line 20
    .line 21
    move-object v0, p1

    .line 22
    check-cast v0, La8/i0;

    .line 23
    .line 24
    iget-object v0, v0, La8/i0;->x:Landroid/os/Looper;

    .line 25
    .line 26
    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;

    .line 27
    .line 28
    .line 29
    move-result-object v1

    .line 30
    if-ne v0, v1, :cond_2

    .line 31
    .line 32
    :cond_1
    move v2, v3

    .line 33
    :cond_2
    invoke-static {v2}, Lw7/a;->c(Z)V

    .line 34
    .line 35
    .line 36
    iget-object v0, p0, Ly9/r;->B1:Lt7/l0;

    .line 37
    .line 38
    if-ne v0, p1, :cond_3

    .line 39
    .line 40
    return-void

    .line 41
    :cond_3
    iget-object v1, p0, Ly9/r;->f:Ly9/g;

    .line 42
    .line 43
    if-eqz v0, :cond_4

    .line 44
    .line 45
    check-cast v0, La8/i0;

    .line 46
    .line 47
    invoke-virtual {v0, v1}, La8/i0;->y0(Lt7/j0;)V

    .line 48
    .line 49
    .line 50
    :cond_4
    iput-object p1, p0, Ly9/r;->B1:Lt7/l0;

    .line 51
    .line 52
    if-eqz p1, :cond_5

    .line 53
    .line 54
    check-cast p1, La8/i0;

    .line 55
    .line 56
    iget-object p1, p1, La8/i0;->q:Le30/v;

    .line 57
    .line 58
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 59
    .line 60
    .line 61
    invoke-virtual {p1, v1}, Le30/v;->a(Ljava/lang/Object;)V

    .line 62
    .line 63
    .line 64
    :cond_5
    invoke-virtual {p0}, Ly9/r;->m()V

    .line 65
    .line 66
    .line 67
    return-void
.end method

.method public setProgressUpdateListener(Ly9/k;)V
    .locals 0

    .line 1
    return-void
.end method

.method public setRepeatToggleModes(I)V
    .locals 4

    .line 1
    iput p1, p0, Ly9/r;->L1:I

    .line 2
    .line 3
    iget-object v0, p0, Ly9/r;->B1:Lt7/l0;

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    const/4 v2, 0x1

    .line 7
    if-eqz v0, :cond_2

    .line 8
    .line 9
    const/16 v3, 0xf

    .line 10
    .line 11
    check-cast v0, Lap0/o;

    .line 12
    .line 13
    invoke-virtual {v0, v3}, Lap0/o;->I(I)Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    if-eqz v0, :cond_2

    .line 18
    .line 19
    iget-object v0, p0, Ly9/r;->B1:Lt7/l0;

    .line 20
    .line 21
    check-cast v0, La8/i0;

    .line 22
    .line 23
    invoke-virtual {v0}, La8/i0;->L0()V

    .line 24
    .line 25
    .line 26
    iget v0, v0, La8/i0;->K:I

    .line 27
    .line 28
    if-nez p1, :cond_0

    .line 29
    .line 30
    if-eqz v0, :cond_0

    .line 31
    .line 32
    iget-object v0, p0, Ly9/r;->B1:Lt7/l0;

    .line 33
    .line 34
    check-cast v0, La8/i0;

    .line 35
    .line 36
    invoke-virtual {v0, v1}, La8/i0;->C0(I)V

    .line 37
    .line 38
    .line 39
    goto :goto_0

    .line 40
    :cond_0
    const/4 v3, 0x2

    .line 41
    if-ne p1, v2, :cond_1

    .line 42
    .line 43
    if-ne v0, v3, :cond_1

    .line 44
    .line 45
    iget-object v0, p0, Ly9/r;->B1:Lt7/l0;

    .line 46
    .line 47
    check-cast v0, La8/i0;

    .line 48
    .line 49
    invoke-virtual {v0, v2}, La8/i0;->C0(I)V

    .line 50
    .line 51
    .line 52
    goto :goto_0

    .line 53
    :cond_1
    if-ne p1, v3, :cond_2

    .line 54
    .line 55
    if-ne v0, v2, :cond_2

    .line 56
    .line 57
    iget-object v0, p0, Ly9/r;->B1:Lt7/l0;

    .line 58
    .line 59
    check-cast v0, La8/i0;

    .line 60
    .line 61
    invoke-virtual {v0, v3}, La8/i0;->C0(I)V

    .line 62
    .line 63
    .line 64
    :cond_2
    :goto_0
    if-eqz p1, :cond_3

    .line 65
    .line 66
    move v1, v2

    .line 67
    :cond_3
    iget-object p1, p0, Ly9/r;->d:Ly9/w;

    .line 68
    .line 69
    iget-object v0, p0, Ly9/r;->C:Landroid/widget/ImageView;

    .line 70
    .line 71
    invoke-virtual {p1, v0, v1}, Ly9/w;->h(Landroid/view/View;Z)V

    .line 72
    .line 73
    .line 74
    invoke-virtual {p0}, Ly9/r;->t()V

    .line 75
    .line 76
    .line 77
    return-void
.end method

.method public setShowFastForwardButton(Z)V
    .locals 2

    .line 1
    iget-object v0, p0, Ly9/r;->d:Ly9/w;

    .line 2
    .line 3
    iget-object v1, p0, Ly9/r;->y:Landroid/view/View;

    .line 4
    .line 5
    invoke-virtual {v0, v1, p1}, Ly9/w;->h(Landroid/view/View;Z)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {p0}, Ly9/r;->p()V

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public setShowMultiWindowTimeBar(Z)V
    .locals 0
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 1
    iput-boolean p1, p0, Ly9/r;->E1:Z

    .line 2
    .line 3
    invoke-virtual {p0}, Ly9/r;->w()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public setShowNextButton(Z)V
    .locals 2

    .line 1
    iget-object v0, p0, Ly9/r;->d:Ly9/w;

    .line 2
    .line 3
    iget-object v1, p0, Ly9/r;->w:Landroid/widget/ImageView;

    .line 4
    .line 5
    invoke-virtual {v0, v1, p1}, Ly9/w;->h(Landroid/view/View;Z)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {p0}, Ly9/r;->p()V

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public setShowPlayButtonIfPlaybackIsSuppressed(Z)V
    .locals 0

    .line 1
    iput-boolean p1, p0, Ly9/r;->F1:Z

    .line 2
    .line 3
    invoke-virtual {p0}, Ly9/r;->q()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public setShowPreviousButton(Z)V
    .locals 2

    .line 1
    iget-object v0, p0, Ly9/r;->d:Ly9/w;

    .line 2
    .line 3
    iget-object v1, p0, Ly9/r;->v:Landroid/widget/ImageView;

    .line 4
    .line 5
    invoke-virtual {v0, v1, p1}, Ly9/w;->h(Landroid/view/View;Z)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {p0}, Ly9/r;->p()V

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public setShowRewindButton(Z)V
    .locals 2

    .line 1
    iget-object v0, p0, Ly9/r;->d:Ly9/w;

    .line 2
    .line 3
    iget-object v1, p0, Ly9/r;->z:Landroid/view/View;

    .line 4
    .line 5
    invoke-virtual {v0, v1, p1}, Ly9/w;->h(Landroid/view/View;Z)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {p0}, Ly9/r;->p()V

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public setShowShuffleButton(Z)V
    .locals 2

    .line 1
    iget-object v0, p0, Ly9/r;->d:Ly9/w;

    .line 2
    .line 3
    iget-object v1, p0, Ly9/r;->D:Landroid/widget/ImageView;

    .line 4
    .line 5
    invoke-virtual {v0, v1, p1}, Ly9/w;->h(Landroid/view/View;Z)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {p0}, Ly9/r;->v()V

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public setShowSubtitleButton(Z)V
    .locals 1

    .line 1
    iget-object v0, p0, Ly9/r;->d:Ly9/w;

    .line 2
    .line 3
    iget-object p0, p0, Ly9/r;->F:Landroid/widget/ImageView;

    .line 4
    .line 5
    invoke-virtual {v0, p0, p1}, Ly9/w;->h(Landroid/view/View;Z)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public setShowTimeoutMs(I)V
    .locals 0

    .line 1
    iput p1, p0, Ly9/r;->I1:I

    .line 2
    .line 3
    invoke-virtual {p0}, Ly9/r;->j()Z

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    if-eqz p1, :cond_0

    .line 8
    .line 9
    iget-object p0, p0, Ly9/r;->d:Ly9/w;

    .line 10
    .line 11
    invoke-virtual {p0}, Ly9/w;->g()V

    .line 12
    .line 13
    .line 14
    :cond_0
    return-void
.end method

.method public setShowVrButton(Z)V
    .locals 1

    .line 1
    iget-object v0, p0, Ly9/r;->d:Ly9/w;

    .line 2
    .line 3
    iget-object p0, p0, Ly9/r;->E:Landroid/widget/ImageView;

    .line 4
    .line 5
    invoke-virtual {v0, p0, p1}, Ly9/w;->h(Landroid/view/View;Z)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public setTimeBarMinUpdateInterval(I)V
    .locals 2

    .line 1
    const/16 v0, 0x10

    .line 2
    .line 3
    const/16 v1, 0x3e8

    .line 4
    .line 5
    invoke-static {p1, v0, v1}, Lw7/w;->g(III)I

    .line 6
    .line 7
    .line 8
    move-result p1

    .line 9
    iput p1, p0, Ly9/r;->K1:I

    .line 10
    .line 11
    return-void
.end method

.method public setTimeBarScrubbingEnabled(Z)V
    .locals 0

    .line 1
    iput-boolean p1, p0, Ly9/r;->J1:Z

    .line 2
    .line 3
    return-void
.end method

.method public setVrButtonListener(Landroid/view/View$OnClickListener;)V
    .locals 1

    .line 1
    iget-object v0, p0, Ly9/r;->E:Landroid/widget/ImageView;

    .line 2
    .line 3
    if-eqz v0, :cond_1

    .line 4
    .line 5
    invoke-virtual {v0, p1}, Landroid/view/View;->setOnClickListener(Landroid/view/View$OnClickListener;)V

    .line 6
    .line 7
    .line 8
    if-eqz p1, :cond_0

    .line 9
    .line 10
    const/4 p1, 0x1

    .line 11
    goto :goto_0

    .line 12
    :cond_0
    const/4 p1, 0x0

    .line 13
    :goto_0
    invoke-virtual {p0, v0, p1}, Ly9/r;->n(Landroid/view/View;Z)V

    .line 14
    .line 15
    .line 16
    :cond_1
    return-void
.end method

.method public final t()V
    .locals 7

    .line 1
    invoke-virtual {p0}, Ly9/r;->l()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_7

    .line 6
    .line 7
    iget-boolean v0, p0, Ly9/r;->D1:Z

    .line 8
    .line 9
    if-eqz v0, :cond_7

    .line 10
    .line 11
    iget-object v0, p0, Ly9/r;->C:Landroid/widget/ImageView;

    .line 12
    .line 13
    if-nez v0, :cond_0

    .line 14
    .line 15
    goto :goto_1

    .line 16
    :cond_0
    iget v1, p0, Ly9/r;->L1:I

    .line 17
    .line 18
    const/4 v2, 0x0

    .line 19
    if-nez v1, :cond_1

    .line 20
    .line 21
    invoke-virtual {p0, v0, v2}, Ly9/r;->n(Landroid/view/View;Z)V

    .line 22
    .line 23
    .line 24
    return-void

    .line 25
    :cond_1
    iget-object v1, p0, Ly9/r;->B1:Lt7/l0;

    .line 26
    .line 27
    iget-object v3, p0, Ly9/r;->b0:Ljava/lang/String;

    .line 28
    .line 29
    iget-object v4, p0, Ly9/r;->V:Landroid/graphics/drawable/Drawable;

    .line 30
    .line 31
    if-eqz v1, :cond_6

    .line 32
    .line 33
    const/16 v5, 0xf

    .line 34
    .line 35
    move-object v6, v1

    .line 36
    check-cast v6, Lap0/o;

    .line 37
    .line 38
    invoke-virtual {v6, v5}, Lap0/o;->I(I)Z

    .line 39
    .line 40
    .line 41
    move-result v5

    .line 42
    if-nez v5, :cond_2

    .line 43
    .line 44
    goto :goto_0

    .line 45
    :cond_2
    const/4 v2, 0x1

    .line 46
    invoke-virtual {p0, v0, v2}, Ly9/r;->n(Landroid/view/View;Z)V

    .line 47
    .line 48
    .line 49
    check-cast v1, La8/i0;

    .line 50
    .line 51
    invoke-virtual {v1}, La8/i0;->L0()V

    .line 52
    .line 53
    .line 54
    iget v1, v1, La8/i0;->K:I

    .line 55
    .line 56
    if-eqz v1, :cond_5

    .line 57
    .line 58
    if-eq v1, v2, :cond_4

    .line 59
    .line 60
    const/4 v2, 0x2

    .line 61
    if-eq v1, v2, :cond_3

    .line 62
    .line 63
    goto :goto_1

    .line 64
    :cond_3
    iget-object v1, p0, Ly9/r;->a0:Landroid/graphics/drawable/Drawable;

    .line 65
    .line 66
    invoke-virtual {v0, v1}, Landroid/widget/ImageView;->setImageDrawable(Landroid/graphics/drawable/Drawable;)V

    .line 67
    .line 68
    .line 69
    iget-object p0, p0, Ly9/r;->d0:Ljava/lang/String;

    .line 70
    .line 71
    invoke-virtual {v0, p0}, Landroid/view/View;->setContentDescription(Ljava/lang/CharSequence;)V

    .line 72
    .line 73
    .line 74
    return-void

    .line 75
    :cond_4
    iget-object v1, p0, Ly9/r;->W:Landroid/graphics/drawable/Drawable;

    .line 76
    .line 77
    invoke-virtual {v0, v1}, Landroid/widget/ImageView;->setImageDrawable(Landroid/graphics/drawable/Drawable;)V

    .line 78
    .line 79
    .line 80
    iget-object p0, p0, Ly9/r;->c0:Ljava/lang/String;

    .line 81
    .line 82
    invoke-virtual {v0, p0}, Landroid/view/View;->setContentDescription(Ljava/lang/CharSequence;)V

    .line 83
    .line 84
    .line 85
    return-void

    .line 86
    :cond_5
    invoke-virtual {v0, v4}, Landroid/widget/ImageView;->setImageDrawable(Landroid/graphics/drawable/Drawable;)V

    .line 87
    .line 88
    .line 89
    invoke-virtual {v0, v3}, Landroid/view/View;->setContentDescription(Ljava/lang/CharSequence;)V

    .line 90
    .line 91
    .line 92
    return-void

    .line 93
    :cond_6
    :goto_0
    invoke-virtual {p0, v0, v2}, Ly9/r;->n(Landroid/view/View;Z)V

    .line 94
    .line 95
    .line 96
    invoke-virtual {v0, v4}, Landroid/widget/ImageView;->setImageDrawable(Landroid/graphics/drawable/Drawable;)V

    .line 97
    .line 98
    .line 99
    invoke-virtual {v0, v3}, Landroid/view/View;->setContentDescription(Ljava/lang/CharSequence;)V

    .line 100
    .line 101
    .line 102
    :cond_7
    :goto_1
    return-void
.end method

.method public final u()V
    .locals 4

    .line 1
    const/4 v0, 0x0

    .line 2
    iget-object v1, p0, Ly9/r;->n:Landroidx/recyclerview/widget/RecyclerView;

    .line 3
    .line 4
    invoke-virtual {v1, v0, v0}, Landroid/view/View;->measure(II)V

    .line 5
    .line 6
    .line 7
    invoke-virtual {p0}, Landroid/view/View;->getWidth()I

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    iget v2, p0, Ly9/r;->u:I

    .line 12
    .line 13
    mul-int/lit8 v3, v2, 0x2

    .line 14
    .line 15
    sub-int/2addr v0, v3

    .line 16
    invoke-virtual {v1}, Landroid/view/View;->getMeasuredWidth()I

    .line 17
    .line 18
    .line 19
    move-result v3

    .line 20
    invoke-static {v3, v0}, Ljava/lang/Math;->min(II)I

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    iget-object v3, p0, Ly9/r;->t:Landroid/widget/PopupWindow;

    .line 25
    .line 26
    invoke-virtual {v3, v0}, Landroid/widget/PopupWindow;->setWidth(I)V

    .line 27
    .line 28
    .line 29
    invoke-virtual {p0}, Landroid/view/View;->getHeight()I

    .line 30
    .line 31
    .line 32
    move-result p0

    .line 33
    mul-int/lit8 v2, v2, 0x2

    .line 34
    .line 35
    sub-int/2addr p0, v2

    .line 36
    invoke-virtual {v1}, Landroid/view/View;->getMeasuredHeight()I

    .line 37
    .line 38
    .line 39
    move-result v0

    .line 40
    invoke-static {p0, v0}, Ljava/lang/Math;->min(II)I

    .line 41
    .line 42
    .line 43
    move-result p0

    .line 44
    invoke-virtual {v3, p0}, Landroid/widget/PopupWindow;->setHeight(I)V

    .line 45
    .line 46
    .line 47
    return-void
.end method

.method public final v()V
    .locals 7

    .line 1
    invoke-virtual {p0}, Ly9/r;->l()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_6

    .line 6
    .line 7
    iget-boolean v0, p0, Ly9/r;->D1:Z

    .line 8
    .line 9
    if-eqz v0, :cond_6

    .line 10
    .line 11
    iget-object v0, p0, Ly9/r;->D:Landroid/widget/ImageView;

    .line 12
    .line 13
    if-nez v0, :cond_0

    .line 14
    .line 15
    goto :goto_1

    .line 16
    :cond_0
    iget-object v1, p0, Ly9/r;->B1:Lt7/l0;

    .line 17
    .line 18
    iget-object v2, p0, Ly9/r;->d:Ly9/w;

    .line 19
    .line 20
    invoke-virtual {v2, v0}, Ly9/w;->b(Landroid/view/View;)Z

    .line 21
    .line 22
    .line 23
    move-result v2

    .line 24
    const/4 v3, 0x0

    .line 25
    if-nez v2, :cond_1

    .line 26
    .line 27
    invoke-virtual {p0, v0, v3}, Ly9/r;->n(Landroid/view/View;Z)V

    .line 28
    .line 29
    .line 30
    return-void

    .line 31
    :cond_1
    iget-object v2, p0, Ly9/r;->s1:Ljava/lang/String;

    .line 32
    .line 33
    iget-object v4, p0, Ly9/r;->f0:Landroid/graphics/drawable/Drawable;

    .line 34
    .line 35
    if-eqz v1, :cond_5

    .line 36
    .line 37
    const/16 v5, 0xe

    .line 38
    .line 39
    move-object v6, v1

    .line 40
    check-cast v6, Lap0/o;

    .line 41
    .line 42
    invoke-virtual {v6, v5}, Lap0/o;->I(I)Z

    .line 43
    .line 44
    .line 45
    move-result v5

    .line 46
    if-nez v5, :cond_2

    .line 47
    .line 48
    goto :goto_0

    .line 49
    :cond_2
    const/4 v3, 0x1

    .line 50
    invoke-virtual {p0, v0, v3}, Ly9/r;->n(Landroid/view/View;Z)V

    .line 51
    .line 52
    .line 53
    check-cast v1, La8/i0;

    .line 54
    .line 55
    invoke-virtual {v1}, La8/i0;->L0()V

    .line 56
    .line 57
    .line 58
    iget-boolean v3, v1, La8/i0;->L:Z

    .line 59
    .line 60
    if-eqz v3, :cond_3

    .line 61
    .line 62
    iget-object v4, p0, Ly9/r;->e0:Landroid/graphics/drawable/Drawable;

    .line 63
    .line 64
    :cond_3
    invoke-virtual {v0, v4}, Landroid/widget/ImageView;->setImageDrawable(Landroid/graphics/drawable/Drawable;)V

    .line 65
    .line 66
    .line 67
    invoke-virtual {v1}, La8/i0;->L0()V

    .line 68
    .line 69
    .line 70
    iget-boolean v1, v1, La8/i0;->L:Z

    .line 71
    .line 72
    if-eqz v1, :cond_4

    .line 73
    .line 74
    iget-object v2, p0, Ly9/r;->r1:Ljava/lang/String;

    .line 75
    .line 76
    :cond_4
    invoke-virtual {v0, v2}, Landroid/view/View;->setContentDescription(Ljava/lang/CharSequence;)V

    .line 77
    .line 78
    .line 79
    return-void

    .line 80
    :cond_5
    :goto_0
    invoke-virtual {p0, v0, v3}, Ly9/r;->n(Landroid/view/View;Z)V

    .line 81
    .line 82
    .line 83
    invoke-virtual {v0, v4}, Landroid/widget/ImageView;->setImageDrawable(Landroid/graphics/drawable/Drawable;)V

    .line 84
    .line 85
    .line 86
    invoke-virtual {v0, v2}, Landroid/view/View;->setContentDescription(Ljava/lang/CharSequence;)V

    .line 87
    .line 88
    .line 89
    :cond_6
    :goto_1
    return-void
.end method

.method public final w()V
    .locals 23

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v1, v0, Ly9/r;->B1:Lt7/l0;

    .line 4
    .line 5
    if-nez v1, :cond_0

    .line 6
    .line 7
    return-void

    .line 8
    :cond_0
    iget-boolean v2, v0, Ly9/r;->E1:Z

    .line 9
    .line 10
    iget-object v3, v0, Ly9/r;->R:Lt7/o0;

    .line 11
    .line 12
    const/4 v4, 0x0

    .line 13
    const/4 v5, 0x1

    .line 14
    if-eqz v2, :cond_1

    .line 15
    .line 16
    invoke-static {v1, v3}, Ly9/r;->c(Lt7/l0;Lt7/o0;)Z

    .line 17
    .line 18
    .line 19
    move-result v2

    .line 20
    if-eqz v2, :cond_1

    .line 21
    .line 22
    move v2, v5

    .line 23
    goto :goto_0

    .line 24
    :cond_1
    move v2, v4

    .line 25
    :goto_0
    iput-boolean v2, v0, Ly9/r;->G1:Z

    .line 26
    .line 27
    const-wide/16 v6, 0x0

    .line 28
    .line 29
    iput-wide v6, v0, Ly9/r;->Q1:J

    .line 30
    .line 31
    move-object v2, v1

    .line 32
    check-cast v2, Lap0/o;

    .line 33
    .line 34
    const/16 v8, 0x11

    .line 35
    .line 36
    invoke-virtual {v2, v8}, Lap0/o;->I(I)Z

    .line 37
    .line 38
    .line 39
    move-result v8

    .line 40
    if-eqz v8, :cond_2

    .line 41
    .line 42
    move-object v8, v1

    .line 43
    check-cast v8, La8/i0;

    .line 44
    .line 45
    invoke-virtual {v8}, La8/i0;->k0()Lt7/p0;

    .line 46
    .line 47
    .line 48
    move-result-object v8

    .line 49
    goto :goto_1

    .line 50
    :cond_2
    sget-object v8, Lt7/p0;->a:Lt7/m0;

    .line 51
    .line 52
    :goto_1
    invoke-virtual {v8}, Lt7/p0;->p()Z

    .line 53
    .line 54
    .line 55
    move-result v9

    .line 56
    const-wide v10, -0x7fffffffffffffffL    # -4.9E-324

    .line 57
    .line 58
    .line 59
    .line 60
    .line 61
    if-nez v9, :cond_11

    .line 62
    .line 63
    check-cast v1, La8/i0;

    .line 64
    .line 65
    invoke-virtual {v1}, La8/i0;->h0()I

    .line 66
    .line 67
    .line 68
    move-result v1

    .line 69
    iget-boolean v2, v0, Ly9/r;->G1:Z

    .line 70
    .line 71
    if-eqz v2, :cond_3

    .line 72
    .line 73
    move v9, v4

    .line 74
    goto :goto_2

    .line 75
    :cond_3
    move v9, v1

    .line 76
    :goto_2
    if-eqz v2, :cond_4

    .line 77
    .line 78
    invoke-virtual {v8}, Lt7/p0;->o()I

    .line 79
    .line 80
    .line 81
    move-result v2

    .line 82
    sub-int/2addr v2, v5

    .line 83
    goto :goto_3

    .line 84
    :cond_4
    move v2, v1

    .line 85
    :goto_3
    move v14, v4

    .line 86
    move-wide v12, v6

    .line 87
    :goto_4
    if-gt v9, v2, :cond_6

    .line 88
    .line 89
    move-wide v15, v6

    .line 90
    if-ne v9, v1, :cond_5

    .line 91
    .line 92
    invoke-static {v12, v13}, Lw7/w;->N(J)J

    .line 93
    .line 94
    .line 95
    move-result-wide v6

    .line 96
    iput-wide v6, v0, Ly9/r;->Q1:J

    .line 97
    .line 98
    :cond_5
    invoke-virtual {v8, v9, v3}, Lt7/p0;->n(ILt7/o0;)V

    .line 99
    .line 100
    .line 101
    iget-wide v6, v3, Lt7/o0;->l:J

    .line 102
    .line 103
    cmp-long v6, v6, v10

    .line 104
    .line 105
    if-nez v6, :cond_7

    .line 106
    .line 107
    iget-boolean v1, v0, Ly9/r;->G1:Z

    .line 108
    .line 109
    xor-int/2addr v1, v5

    .line 110
    invoke-static {v1}, Lw7/a;->j(Z)V

    .line 111
    .line 112
    .line 113
    :cond_6
    move v4, v5

    .line 114
    goto/16 :goto_c

    .line 115
    .line 116
    :cond_7
    iget v6, v3, Lt7/o0;->m:I

    .line 117
    .line 118
    :goto_5
    iget v7, v3, Lt7/o0;->n:I

    .line 119
    .line 120
    if-gt v6, v7, :cond_10

    .line 121
    .line 122
    iget-object v7, v0, Ly9/r;->Q:Lt7/n0;

    .line 123
    .line 124
    invoke-virtual {v8, v6, v7, v4}, Lt7/p0;->f(ILt7/n0;Z)Lt7/n0;

    .line 125
    .line 126
    .line 127
    move-wide/from16 v17, v10

    .line 128
    .line 129
    iget-object v10, v7, Lt7/n0;->g:Lt7/b;

    .line 130
    .line 131
    invoke-virtual {v10}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 132
    .line 133
    .line 134
    iget v10, v10, Lt7/b;->a:I

    .line 135
    .line 136
    move v11, v4

    .line 137
    :goto_6
    if-ge v11, v10, :cond_f

    .line 138
    .line 139
    invoke-virtual {v7, v11}, Lt7/n0;->d(I)J

    .line 140
    .line 141
    .line 142
    iget-wide v4, v7, Lt7/n0;->e:J

    .line 143
    .line 144
    cmp-long v20, v4, v15

    .line 145
    .line 146
    if-ltz v20, :cond_e

    .line 147
    .line 148
    iget-object v15, v0, Ly9/r;->M1:[J

    .line 149
    .line 150
    move/from16 v16, v1

    .line 151
    .line 152
    array-length v1, v15

    .line 153
    if-ne v14, v1, :cond_9

    .line 154
    .line 155
    array-length v1, v15

    .line 156
    if-nez v1, :cond_8

    .line 157
    .line 158
    const/4 v1, 0x1

    .line 159
    goto :goto_7

    .line 160
    :cond_8
    array-length v1, v15

    .line 161
    mul-int/lit8 v1, v1, 0x2

    .line 162
    .line 163
    :goto_7
    invoke-static {v15, v1}, Ljava/util/Arrays;->copyOf([JI)[J

    .line 164
    .line 165
    .line 166
    move-result-object v15

    .line 167
    iput-object v15, v0, Ly9/r;->M1:[J

    .line 168
    .line 169
    iget-object v15, v0, Ly9/r;->N1:[Z

    .line 170
    .line 171
    invoke-static {v15, v1}, Ljava/util/Arrays;->copyOf([ZI)[Z

    .line 172
    .line 173
    .line 174
    move-result-object v1

    .line 175
    iput-object v1, v0, Ly9/r;->N1:[Z

    .line 176
    .line 177
    :cond_9
    iget-object v1, v0, Ly9/r;->M1:[J

    .line 178
    .line 179
    add-long/2addr v4, v12

    .line 180
    invoke-static {v4, v5}, Lw7/w;->N(J)J

    .line 181
    .line 182
    .line 183
    move-result-wide v4

    .line 184
    aput-wide v4, v1, v14

    .line 185
    .line 186
    iget-object v1, v0, Ly9/r;->N1:[Z

    .line 187
    .line 188
    iget-object v4, v7, Lt7/n0;->g:Lt7/b;

    .line 189
    .line 190
    invoke-virtual {v4, v11}, Lt7/b;->a(I)Lt7/a;

    .line 191
    .line 192
    .line 193
    move-result-object v4

    .line 194
    iget v5, v4, Lt7/a;->a:I

    .line 195
    .line 196
    const/4 v15, -0x1

    .line 197
    if-ne v5, v15, :cond_a

    .line 198
    .line 199
    move-object/from16 v21, v1

    .line 200
    .line 201
    const/4 v4, 0x1

    .line 202
    const/16 v19, 0x1

    .line 203
    .line 204
    goto :goto_a

    .line 205
    :cond_a
    const/4 v15, 0x0

    .line 206
    :goto_8
    if-ge v15, v5, :cond_d

    .line 207
    .line 208
    move-object/from16 v21, v1

    .line 209
    .line 210
    iget-object v1, v4, Lt7/a;->e:[I

    .line 211
    .line 212
    aget v1, v1, v15

    .line 213
    .line 214
    if-eqz v1, :cond_c

    .line 215
    .line 216
    move-object/from16 v22, v4

    .line 217
    .line 218
    const/4 v4, 0x1

    .line 219
    if-ne v1, v4, :cond_b

    .line 220
    .line 221
    goto :goto_9

    .line 222
    :cond_b
    add-int/lit8 v15, v15, 0x1

    .line 223
    .line 224
    move-object/from16 v1, v21

    .line 225
    .line 226
    move-object/from16 v4, v22

    .line 227
    .line 228
    goto :goto_8

    .line 229
    :cond_c
    const/4 v4, 0x1

    .line 230
    :goto_9
    move/from16 v19, v4

    .line 231
    .line 232
    goto :goto_a

    .line 233
    :cond_d
    move-object/from16 v21, v1

    .line 234
    .line 235
    const/4 v4, 0x1

    .line 236
    const/16 v19, 0x0

    .line 237
    .line 238
    :goto_a
    xor-int/lit8 v1, v19, 0x1

    .line 239
    .line 240
    aput-boolean v1, v21, v14

    .line 241
    .line 242
    add-int/lit8 v14, v14, 0x1

    .line 243
    .line 244
    goto :goto_b

    .line 245
    :cond_e
    move/from16 v16, v1

    .line 246
    .line 247
    const/4 v4, 0x1

    .line 248
    :goto_b
    add-int/lit8 v11, v11, 0x1

    .line 249
    .line 250
    move v5, v4

    .line 251
    move/from16 v1, v16

    .line 252
    .line 253
    const/4 v4, 0x0

    .line 254
    const-wide/16 v15, 0x0

    .line 255
    .line 256
    goto :goto_6

    .line 257
    :cond_f
    move/from16 v16, v1

    .line 258
    .line 259
    move v4, v5

    .line 260
    add-int/lit8 v6, v6, 0x1

    .line 261
    .line 262
    move-wide/from16 v10, v17

    .line 263
    .line 264
    const/4 v4, 0x0

    .line 265
    const-wide/16 v15, 0x0

    .line 266
    .line 267
    goto/16 :goto_5

    .line 268
    .line 269
    :cond_10
    move/from16 v16, v1

    .line 270
    .line 271
    move v4, v5

    .line 272
    move-wide/from16 v17, v10

    .line 273
    .line 274
    iget-wide v5, v3, Lt7/o0;->l:J

    .line 275
    .line 276
    add-long/2addr v12, v5

    .line 277
    add-int/lit8 v9, v9, 0x1

    .line 278
    .line 279
    move v5, v4

    .line 280
    const/4 v4, 0x0

    .line 281
    const-wide/16 v6, 0x0

    .line 282
    .line 283
    goto/16 :goto_4

    .line 284
    .line 285
    :goto_c
    move-wide v6, v12

    .line 286
    goto :goto_e

    .line 287
    :cond_11
    move v4, v5

    .line 288
    move-wide/from16 v17, v10

    .line 289
    .line 290
    const/16 v1, 0x10

    .line 291
    .line 292
    invoke-virtual {v2, v1}, Lap0/o;->I(I)Z

    .line 293
    .line 294
    .line 295
    move-result v1

    .line 296
    if-eqz v1, :cond_12

    .line 297
    .line 298
    invoke-virtual {v2}, Lap0/o;->C()J

    .line 299
    .line 300
    .line 301
    move-result-wide v1

    .line 302
    cmp-long v3, v1, v17

    .line 303
    .line 304
    if-eqz v3, :cond_12

    .line 305
    .line 306
    invoke-static {v1, v2}, Lw7/w;->D(J)J

    .line 307
    .line 308
    .line 309
    move-result-wide v6

    .line 310
    :goto_d
    const/4 v14, 0x0

    .line 311
    goto :goto_e

    .line 312
    :cond_12
    const-wide/16 v6, 0x0

    .line 313
    .line 314
    goto :goto_d

    .line 315
    :goto_e
    invoke-static {v6, v7}, Lw7/w;->N(J)J

    .line 316
    .line 317
    .line 318
    move-result-wide v1

    .line 319
    iget-object v3, v0, Ly9/r;->L:Landroid/widget/TextView;

    .line 320
    .line 321
    if-eqz v3, :cond_13

    .line 322
    .line 323
    iget-object v5, v0, Ly9/r;->O:Ljava/lang/StringBuilder;

    .line 324
    .line 325
    iget-object v6, v0, Ly9/r;->P:Ljava/util/Formatter;

    .line 326
    .line 327
    invoke-static {v5, v6, v1, v2}, Lw7/w;->u(Ljava/lang/StringBuilder;Ljava/util/Formatter;J)Ljava/lang/String;

    .line 328
    .line 329
    .line 330
    move-result-object v5

    .line 331
    invoke-virtual {v3, v5}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

    .line 332
    .line 333
    .line 334
    :cond_13
    iget-object v3, v0, Ly9/r;->N:Ly9/h0;

    .line 335
    .line 336
    if-eqz v3, :cond_17

    .line 337
    .line 338
    check-cast v3, Ly9/d;

    .line 339
    .line 340
    invoke-virtual {v3, v1, v2}, Ly9/d;->setDuration(J)V

    .line 341
    .line 342
    .line 343
    iget-object v1, v0, Ly9/r;->O1:[J

    .line 344
    .line 345
    array-length v2, v1

    .line 346
    add-int v5, v14, v2

    .line 347
    .line 348
    iget-object v6, v0, Ly9/r;->M1:[J

    .line 349
    .line 350
    array-length v7, v6

    .line 351
    if-le v5, v7, :cond_14

    .line 352
    .line 353
    invoke-static {v6, v5}, Ljava/util/Arrays;->copyOf([JI)[J

    .line 354
    .line 355
    .line 356
    move-result-object v6

    .line 357
    iput-object v6, v0, Ly9/r;->M1:[J

    .line 358
    .line 359
    iget-object v6, v0, Ly9/r;->N1:[Z

    .line 360
    .line 361
    invoke-static {v6, v5}, Ljava/util/Arrays;->copyOf([ZI)[Z

    .line 362
    .line 363
    .line 364
    move-result-object v6

    .line 365
    iput-object v6, v0, Ly9/r;->N1:[Z

    .line 366
    .line 367
    :cond_14
    iget-object v6, v0, Ly9/r;->M1:[J

    .line 368
    .line 369
    const/4 v7, 0x0

    .line 370
    invoke-static {v1, v7, v6, v14, v2}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 371
    .line 372
    .line 373
    iget-object v1, v0, Ly9/r;->P1:[Z

    .line 374
    .line 375
    iget-object v6, v0, Ly9/r;->N1:[Z

    .line 376
    .line 377
    invoke-static {v1, v7, v6, v14, v2}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 378
    .line 379
    .line 380
    iget-object v1, v0, Ly9/r;->M1:[J

    .line 381
    .line 382
    iget-object v2, v0, Ly9/r;->N1:[Z

    .line 383
    .line 384
    if-eqz v5, :cond_16

    .line 385
    .line 386
    if-eqz v1, :cond_15

    .line 387
    .line 388
    if-eqz v2, :cond_15

    .line 389
    .line 390
    goto :goto_f

    .line 391
    :cond_15
    move v4, v7

    .line 392
    :cond_16
    :goto_f
    invoke-static {v4}, Lw7/a;->c(Z)V

    .line 393
    .line 394
    .line 395
    iput v5, v3, Ly9/d;->P:I

    .line 396
    .line 397
    iput-object v1, v3, Ly9/d;->Q:[J

    .line 398
    .line 399
    iput-object v2, v3, Ly9/d;->R:[Z

    .line 400
    .line 401
    invoke-virtual {v3}, Ly9/d;->e()V

    .line 402
    .line 403
    .line 404
    :cond_17
    invoke-virtual {v0}, Ly9/r;->s()V

    .line 405
    .line 406
    .line 407
    return-void
.end method

.method public final x()V
    .locals 11

    .line 1
    iget-object v0, p0, Ly9/r;->q:Ly9/f;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    sget-object v1, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    .line 7
    .line 8
    iput-object v1, v0, Ly9/f;->d:Ljava/util/List;

    .line 9
    .line 10
    iget-object v2, p0, Ly9/r;->r:Ly9/f;

    .line 11
    .line 12
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 13
    .line 14
    .line 15
    iput-object v1, v2, Ly9/f;->d:Ljava/util/List;

    .line 16
    .line 17
    iget-object v1, p0, Ly9/r;->B1:Lt7/l0;

    .line 18
    .line 19
    iget-object v3, p0, Ly9/r;->F:Landroid/widget/ImageView;

    .line 20
    .line 21
    const/4 v4, 0x0

    .line 22
    const/4 v5, 0x1

    .line 23
    if-eqz v1, :cond_6

    .line 24
    .line 25
    const/16 v6, 0x1e

    .line 26
    .line 27
    check-cast v1, Lap0/o;

    .line 28
    .line 29
    invoke-virtual {v1, v6}, Lap0/o;->I(I)Z

    .line 30
    .line 31
    .line 32
    move-result v1

    .line 33
    if-eqz v1, :cond_6

    .line 34
    .line 35
    iget-object v1, p0, Ly9/r;->B1:Lt7/l0;

    .line 36
    .line 37
    const/16 v6, 0x1d

    .line 38
    .line 39
    check-cast v1, Lap0/o;

    .line 40
    .line 41
    invoke-virtual {v1, v6}, Lap0/o;->I(I)Z

    .line 42
    .line 43
    .line 44
    move-result v1

    .line 45
    if-nez v1, :cond_0

    .line 46
    .line 47
    goto/16 :goto_2

    .line 48
    .line 49
    :cond_0
    iget-object v1, p0, Ly9/r;->B1:Lt7/l0;

    .line 50
    .line 51
    check-cast v1, La8/i0;

    .line 52
    .line 53
    invoke-virtual {v1}, La8/i0;->l0()Lt7/w0;

    .line 54
    .line 55
    .line 56
    move-result-object v1

    .line 57
    invoke-virtual {p0, v1, v5}, Ly9/r;->f(Lt7/w0;I)Lhr/x0;

    .line 58
    .line 59
    .line 60
    move-result-object v6

    .line 61
    iput-object v6, v2, Ly9/f;->d:Ljava/util/List;

    .line 62
    .line 63
    iget-object v7, v2, Ly9/f;->g:Ly9/r;

    .line 64
    .line 65
    iget-object v8, v7, Ly9/r;->B1:Lt7/l0;

    .line 66
    .line 67
    iget-object v9, v7, Ly9/r;->o:Ly9/m;

    .line 68
    .line 69
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 70
    .line 71
    .line 72
    check-cast v8, La8/i0;

    .line 73
    .line 74
    invoke-virtual {v8}, La8/i0;->q0()Lt7/u0;

    .line 75
    .line 76
    .line 77
    move-result-object v8

    .line 78
    invoke-virtual {v6}, Ljava/util/AbstractCollection;->isEmpty()Z

    .line 79
    .line 80
    .line 81
    move-result v10

    .line 82
    if-eqz v10, :cond_1

    .line 83
    .line 84
    invoke-virtual {v7}, Landroid/view/View;->getResources()Landroid/content/res/Resources;

    .line 85
    .line 86
    .line 87
    move-result-object v2

    .line 88
    const v6, 0x7f1202f7

    .line 89
    .line 90
    .line 91
    invoke-virtual {v2, v6}, Landroid/content/res/Resources;->getString(I)Ljava/lang/String;

    .line 92
    .line 93
    .line 94
    move-result-object v2

    .line 95
    iget-object v6, v9, Ly9/m;->e:[Ljava/lang/String;

    .line 96
    .line 97
    aput-object v2, v6, v5

    .line 98
    .line 99
    goto :goto_1

    .line 100
    :cond_1
    invoke-virtual {v2, v8}, Ly9/f;->e(Lt7/u0;)Z

    .line 101
    .line 102
    .line 103
    move-result v2

    .line 104
    if-nez v2, :cond_2

    .line 105
    .line 106
    invoke-virtual {v7}, Landroid/view/View;->getResources()Landroid/content/res/Resources;

    .line 107
    .line 108
    .line 109
    move-result-object v2

    .line 110
    const v6, 0x7f1202f6

    .line 111
    .line 112
    .line 113
    invoke-virtual {v2, v6}, Landroid/content/res/Resources;->getString(I)Ljava/lang/String;

    .line 114
    .line 115
    .line 116
    move-result-object v2

    .line 117
    iget-object v6, v9, Ly9/m;->e:[Ljava/lang/String;

    .line 118
    .line 119
    aput-object v2, v6, v5

    .line 120
    .line 121
    goto :goto_1

    .line 122
    :cond_2
    move v2, v4

    .line 123
    :goto_0
    iget v7, v6, Lhr/x0;->g:I

    .line 124
    .line 125
    if-ge v2, v7, :cond_4

    .line 126
    .line 127
    invoke-virtual {v6, v2}, Lhr/x0;->get(I)Ljava/lang/Object;

    .line 128
    .line 129
    .line 130
    move-result-object v7

    .line 131
    check-cast v7, Ly9/o;

    .line 132
    .line 133
    iget-object v8, v7, Ly9/o;->a:Lt7/v0;

    .line 134
    .line 135
    iget v10, v7, Ly9/o;->b:I

    .line 136
    .line 137
    iget-object v8, v8, Lt7/v0;->e:[Z

    .line 138
    .line 139
    aget-boolean v8, v8, v10

    .line 140
    .line 141
    if-eqz v8, :cond_3

    .line 142
    .line 143
    iget-object v2, v7, Ly9/o;->c:Ljava/lang/String;

    .line 144
    .line 145
    iget-object v6, v9, Ly9/m;->e:[Ljava/lang/String;

    .line 146
    .line 147
    aput-object v2, v6, v5

    .line 148
    .line 149
    goto :goto_1

    .line 150
    :cond_3
    add-int/lit8 v2, v2, 0x1

    .line 151
    .line 152
    goto :goto_0

    .line 153
    :cond_4
    :goto_1
    iget-object v2, p0, Ly9/r;->d:Ly9/w;

    .line 154
    .line 155
    invoke-virtual {v2, v3}, Ly9/w;->b(Landroid/view/View;)Z

    .line 156
    .line 157
    .line 158
    move-result v2

    .line 159
    if-eqz v2, :cond_5

    .line 160
    .line 161
    const/4 v2, 0x3

    .line 162
    invoke-virtual {p0, v1, v2}, Ly9/r;->f(Lt7/w0;I)Lhr/x0;

    .line 163
    .line 164
    .line 165
    move-result-object v1

    .line 166
    invoke-virtual {v0, v1}, Ly9/f;->f(Ljava/util/List;)V

    .line 167
    .line 168
    .line 169
    goto :goto_2

    .line 170
    :cond_5
    sget-object v1, Lhr/x0;->h:Lhr/x0;

    .line 171
    .line 172
    invoke-virtual {v0, v1}, Ly9/f;->f(Ljava/util/List;)V

    .line 173
    .line 174
    .line 175
    :cond_6
    :goto_2
    invoke-virtual {v0}, Ly9/f;->a()I

    .line 176
    .line 177
    .line 178
    move-result v0

    .line 179
    if-lez v0, :cond_7

    .line 180
    .line 181
    move v0, v5

    .line 182
    goto :goto_3

    .line 183
    :cond_7
    move v0, v4

    .line 184
    :goto_3
    invoke-virtual {p0, v3, v0}, Ly9/r;->n(Landroid/view/View;Z)V

    .line 185
    .line 186
    .line 187
    iget-object v0, p0, Ly9/r;->o:Ly9/m;

    .line 188
    .line 189
    invoke-virtual {v0, v5}, Ly9/m;->e(I)Z

    .line 190
    .line 191
    .line 192
    move-result v1

    .line 193
    if-nez v1, :cond_8

    .line 194
    .line 195
    invoke-virtual {v0, v4}, Ly9/m;->e(I)Z

    .line 196
    .line 197
    .line 198
    move-result v0

    .line 199
    if-eqz v0, :cond_9

    .line 200
    .line 201
    :cond_8
    move v4, v5

    .line 202
    :cond_9
    iget-object v0, p0, Ly9/r;->I:Landroid/view/View;

    .line 203
    .line 204
    invoke-virtual {p0, v0, v4}, Ly9/r;->n(Landroid/view/View;Z)V

    .line 205
    .line 206
    .line 207
    return-void
.end method
