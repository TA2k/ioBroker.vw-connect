.class public abstract Lj91/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Ll2/u2;

.field public static final b:Lk4/q;


# direct methods
.method static constructor <clinit>()V
    .locals 11

    .line 1
    new-instance v0, Lj00/a;

    .line 2
    .line 3
    const/16 v1, 0xe

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lj00/a;-><init>(I)V

    .line 6
    .line 7
    .line 8
    new-instance v1, Ll2/u2;

    .line 9
    .line 10
    invoke-direct {v1, v0}, Ll2/s1;-><init>(Lay0/a;)V

    .line 11
    .line 12
    .line 13
    sput-object v1, Lj91/j;->a:Ll2/u2;

    .line 14
    .line 15
    sget-object v0, Lk4/x;->e:Lk4/x;

    .line 16
    .line 17
    const v1, 0x7f090003

    .line 18
    .line 19
    .line 20
    const/4 v2, 0x0

    .line 21
    invoke-static {v1, v0, v2}, Llp/xc;->a(ILk4/x;I)Lk4/c0;

    .line 22
    .line 23
    .line 24
    move-result-object v1

    .line 25
    const v3, 0x7f090004

    .line 26
    .line 27
    .line 28
    const/4 v4, 0x1

    .line 29
    invoke-static {v3, v0, v4}, Llp/xc;->a(ILk4/x;I)Lk4/c0;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    sget-object v3, Lk4/x;->f:Lk4/x;

    .line 34
    .line 35
    const v5, 0x7f090005

    .line 36
    .line 37
    .line 38
    invoke-static {v5, v3, v2}, Llp/xc;->a(ILk4/x;I)Lk4/c0;

    .line 39
    .line 40
    .line 41
    move-result-object v5

    .line 42
    const v6, 0x7f090006

    .line 43
    .line 44
    .line 45
    invoke-static {v6, v3, v4}, Llp/xc;->a(ILk4/x;I)Lk4/c0;

    .line 46
    .line 47
    .line 48
    move-result-object v3

    .line 49
    sget-object v6, Lk4/x;->i:Lk4/x;

    .line 50
    .line 51
    const v7, 0x7f090007

    .line 52
    .line 53
    .line 54
    invoke-static {v7, v6, v2}, Llp/xc;->a(ILk4/x;I)Lk4/c0;

    .line 55
    .line 56
    .line 57
    move-result-object v7

    .line 58
    const v8, 0x7f090008

    .line 59
    .line 60
    .line 61
    invoke-static {v8, v6, v4}, Llp/xc;->a(ILk4/x;I)Lk4/c0;

    .line 62
    .line 63
    .line 64
    move-result-object v6

    .line 65
    sget-object v8, Lk4/x;->j:Lk4/x;

    .line 66
    .line 67
    const v9, 0x7f090009

    .line 68
    .line 69
    .line 70
    invoke-static {v9, v8, v2}, Llp/xc;->a(ILk4/x;I)Lk4/c0;

    .line 71
    .line 72
    .line 73
    move-result-object v9

    .line 74
    const v10, 0x7f09000a

    .line 75
    .line 76
    .line 77
    invoke-static {v10, v8, v4}, Llp/xc;->a(ILk4/x;I)Lk4/c0;

    .line 78
    .line 79
    .line 80
    move-result-object v8

    .line 81
    const/16 v10, 0x8

    .line 82
    .line 83
    new-array v10, v10, [Lk4/l;

    .line 84
    .line 85
    aput-object v1, v10, v2

    .line 86
    .line 87
    aput-object v0, v10, v4

    .line 88
    .line 89
    const/4 v0, 0x2

    .line 90
    aput-object v5, v10, v0

    .line 91
    .line 92
    const/4 v0, 0x3

    .line 93
    aput-object v3, v10, v0

    .line 94
    .line 95
    const/4 v0, 0x4

    .line 96
    aput-object v7, v10, v0

    .line 97
    .line 98
    const/4 v0, 0x5

    .line 99
    aput-object v6, v10, v0

    .line 100
    .line 101
    const/4 v0, 0x6

    .line 102
    aput-object v9, v10, v0

    .line 103
    .line 104
    const/4 v0, 0x7

    .line 105
    aput-object v8, v10, v0

    .line 106
    .line 107
    new-instance v0, Lk4/q;

    .line 108
    .line 109
    invoke-static {v10}, Lmx0/n;->b([Ljava/lang/Object;)Ljava/util/List;

    .line 110
    .line 111
    .line 112
    move-result-object v1

    .line 113
    invoke-direct {v0, v1}, Lk4/q;-><init>(Ljava/util/List;)V

    .line 114
    .line 115
    .line 116
    sput-object v0, Lj91/j;->b:Lk4/q;

    .line 117
    .line 118
    return-void
.end method

.method public static final a()Lj91/f;
    .locals 47

    .line 1
    new-instance v0, Lj91/f;

    .line 2
    .line 3
    const/16 v1, 0x28

    .line 4
    .line 5
    invoke-static {v1}, Lgq/b;->c(I)J

    .line 6
    .line 7
    .line 8
    move-result-wide v5

    .line 9
    sget-object v12, Lk4/x;->i:Lk4/x;

    .line 10
    .line 11
    const/16 v1, 0x30

    .line 12
    .line 13
    invoke-static {v1}, Lgq/b;->c(I)J

    .line 14
    .line 15
    .line 16
    move-result-wide v13

    .line 17
    const-wide v21, 0x3f947ae147ae147bL    # 0.02

    .line 18
    .line 19
    .line 20
    .line 21
    .line 22
    invoke-static/range {v21 .. v22}, Lgq/b;->a(D)J

    .line 23
    .line 24
    .line 25
    move-result-wide v10

    .line 26
    new-instance v1, Lg4/p0;

    .line 27
    .line 28
    move-object v7, v12

    .line 29
    const/4 v12, 0x0

    .line 30
    const v15, 0xfdff59

    .line 31
    .line 32
    .line 33
    const-wide/16 v3, 0x0

    .line 34
    .line 35
    const/4 v8, 0x0

    .line 36
    sget-object v30, Lj91/j;->b:Lk4/q;

    .line 37
    .line 38
    move-object v2, v1

    .line 39
    move-object/from16 v9, v30

    .line 40
    .line 41
    invoke-direct/range {v2 .. v15}, Lg4/p0;-><init>(JJLk4/x;Lk4/t;Lk4/n;JIJI)V

    .line 42
    .line 43
    .line 44
    move-object v12, v7

    .line 45
    move-object v14, v9

    .line 46
    const/16 v2, 0x1c

    .line 47
    .line 48
    invoke-static {v2}, Lgq/b;->c(I)J

    .line 49
    .line 50
    .line 51
    move-result-wide v10

    .line 52
    const/16 v2, 0x24

    .line 53
    .line 54
    invoke-static {v2}, Lgq/b;->c(I)J

    .line 55
    .line 56
    .line 57
    move-result-wide v18

    .line 58
    invoke-static/range {v21 .. v22}, Lgq/b;->a(D)J

    .line 59
    .line 60
    .line 61
    move-result-wide v15

    .line 62
    new-instance v2, Lg4/p0;

    .line 63
    .line 64
    const/16 v17, 0x0

    .line 65
    .line 66
    const v20, 0xfdff59

    .line 67
    .line 68
    .line 69
    const-wide/16 v8, 0x0

    .line 70
    .line 71
    const/4 v13, 0x0

    .line 72
    move-object v7, v2

    .line 73
    invoke-direct/range {v7 .. v20}, Lg4/p0;-><init>(JJLk4/x;Lk4/t;Lk4/n;JIJI)V

    .line 74
    .line 75
    .line 76
    const/16 v3, 0x18

    .line 77
    .line 78
    invoke-static {v3}, Lgq/b;->c(I)J

    .line 79
    .line 80
    .line 81
    move-result-wide v10

    .line 82
    const/16 v4, 0x20

    .line 83
    .line 84
    invoke-static {v4}, Lgq/b;->c(I)J

    .line 85
    .line 86
    .line 87
    move-result-wide v18

    .line 88
    invoke-static/range {v21 .. v22}, Lgq/b;->a(D)J

    .line 89
    .line 90
    .line 91
    move-result-wide v15

    .line 92
    new-instance v7, Lg4/p0;

    .line 93
    .line 94
    invoke-direct/range {v7 .. v20}, Lg4/p0;-><init>(JJLk4/x;Lk4/t;Lk4/n;JIJI)V

    .line 95
    .line 96
    .line 97
    move v4, v3

    .line 98
    move-object v3, v7

    .line 99
    const/16 v5, 0x14

    .line 100
    .line 101
    invoke-static {v5}, Lgq/b;->c(I)J

    .line 102
    .line 103
    .line 104
    move-result-wide v10

    .line 105
    invoke-static {v4}, Lgq/b;->c(I)J

    .line 106
    .line 107
    .line 108
    move-result-wide v18

    .line 109
    invoke-static/range {v21 .. v22}, Lgq/b;->a(D)J

    .line 110
    .line 111
    .line 112
    move-result-wide v15

    .line 113
    new-instance v7, Lg4/p0;

    .line 114
    .line 115
    invoke-direct/range {v7 .. v20}, Lg4/p0;-><init>(JJLk4/x;Lk4/t;Lk4/n;JIJI)V

    .line 116
    .line 117
    .line 118
    move v6, v4

    .line 119
    move-object v4, v7

    .line 120
    const/16 v37, 0x10

    .line 121
    .line 122
    invoke-static/range {v37 .. v37}, Lgq/b;->c(I)J

    .line 123
    .line 124
    .line 125
    move-result-wide v10

    .line 126
    invoke-static {v6}, Lgq/b;->c(I)J

    .line 127
    .line 128
    .line 129
    move-result-wide v18

    .line 130
    invoke-static/range {v21 .. v22}, Lgq/b;->a(D)J

    .line 131
    .line 132
    .line 133
    move-result-wide v15

    .line 134
    new-instance v7, Lg4/p0;

    .line 135
    .line 136
    invoke-direct/range {v7 .. v20}, Lg4/p0;-><init>(JJLk4/x;Lk4/t;Lk4/n;JIJI)V

    .line 137
    .line 138
    .line 139
    move/from16 v23, v5

    .line 140
    .line 141
    move-object v5, v7

    .line 142
    const/16 v38, 0xe

    .line 143
    .line 144
    invoke-static/range {v38 .. v38}, Lgq/b;->c(I)J

    .line 145
    .line 146
    .line 147
    move-result-wide v10

    .line 148
    invoke-static/range {v23 .. v23}, Lgq/b;->c(I)J

    .line 149
    .line 150
    .line 151
    move-result-wide v18

    .line 152
    invoke-static/range {v21 .. v22}, Lgq/b;->a(D)J

    .line 153
    .line 154
    .line 155
    move-result-wide v15

    .line 156
    new-instance v7, Lg4/p0;

    .line 157
    .line 158
    invoke-direct/range {v7 .. v20}, Lg4/p0;-><init>(JJLk4/x;Lk4/t;Lk4/n;JIJI)V

    .line 159
    .line 160
    .line 161
    move-object/from16 v46, v7

    .line 162
    .line 163
    move v7, v6

    .line 164
    move-object/from16 v6, v46

    .line 165
    .line 166
    invoke-static/range {v38 .. v38}, Lgq/b;->c(I)J

    .line 167
    .line 168
    .line 169
    move-result-wide v26

    .line 170
    sget-object v28, Lk4/x;->f:Lk4/x;

    .line 171
    .line 172
    invoke-static/range {v23 .. v23}, Lgq/b;->c(I)J

    .line 173
    .line 174
    .line 175
    move-result-wide v34

    .line 176
    invoke-static/range {v21 .. v22}, Lgq/b;->a(D)J

    .line 177
    .line 178
    .line 179
    move-result-wide v31

    .line 180
    new-instance v23, Lg4/p0;

    .line 181
    .line 182
    const/16 v33, 0x0

    .line 183
    .line 184
    const v36, 0xfdff59

    .line 185
    .line 186
    .line 187
    const-wide/16 v24, 0x0

    .line 188
    .line 189
    const/16 v29, 0x0

    .line 190
    .line 191
    move-object/from16 v30, v14

    .line 192
    .line 193
    invoke-direct/range {v23 .. v36}, Lg4/p0;-><init>(JJLk4/x;Lk4/t;Lk4/n;JIJI)V

    .line 194
    .line 195
    .line 196
    move-object/from16 v39, v23

    .line 197
    .line 198
    invoke-static/range {v37 .. v37}, Lgq/b;->c(I)J

    .line 199
    .line 200
    .line 201
    move-result-wide v26

    .line 202
    invoke-static {v7}, Lgq/b;->c(I)J

    .line 203
    .line 204
    .line 205
    move-result-wide v34

    .line 206
    invoke-static/range {v21 .. v22}, Lgq/b;->a(D)J

    .line 207
    .line 208
    .line 209
    move-result-wide v31

    .line 210
    new-instance v23, Lg4/p0;

    .line 211
    .line 212
    invoke-direct/range {v23 .. v36}, Lg4/p0;-><init>(JJLk4/x;Lk4/t;Lk4/n;JIJI)V

    .line 213
    .line 214
    .line 215
    move-object/from16 v40, v23

    .line 216
    .line 217
    invoke-static/range {v37 .. v37}, Lgq/b;->c(I)J

    .line 218
    .line 219
    .line 220
    move-result-wide v26

    .line 221
    invoke-static {v7}, Lgq/b;->c(I)J

    .line 222
    .line 223
    .line 224
    move-result-wide v34

    .line 225
    invoke-static/range {v21 .. v22}, Lgq/b;->a(D)J

    .line 226
    .line 227
    .line 228
    move-result-wide v31

    .line 229
    new-instance v23, Lg4/p0;

    .line 230
    .line 231
    const v36, 0xfdef59

    .line 232
    .line 233
    .line 234
    invoke-direct/range {v23 .. v36}, Lg4/p0;-><init>(JJLk4/x;Lk4/t;Lk4/n;JIJI)V

    .line 235
    .line 236
    .line 237
    move-object/from16 v41, v23

    .line 238
    .line 239
    const/16 v7, 0xa

    .line 240
    .line 241
    invoke-static {v7}, Lgq/b;->c(I)J

    .line 242
    .line 243
    .line 244
    move-result-wide v26

    .line 245
    invoke-static/range {v38 .. v38}, Lgq/b;->c(I)J

    .line 246
    .line 247
    .line 248
    move-result-wide v34

    .line 249
    invoke-static/range {v21 .. v22}, Lgq/b;->a(D)J

    .line 250
    .line 251
    .line 252
    move-result-wide v31

    .line 253
    new-instance v23, Lg4/p0;

    .line 254
    .line 255
    const v36, 0xfdff59

    .line 256
    .line 257
    .line 258
    invoke-direct/range {v23 .. v36}, Lg4/p0;-><init>(JJLk4/x;Lk4/t;Lk4/n;JIJI)V

    .line 259
    .line 260
    .line 261
    move-object/from16 v42, v23

    .line 262
    .line 263
    invoke-static {v7}, Lgq/b;->c(I)J

    .line 264
    .line 265
    .line 266
    move-result-wide v10

    .line 267
    invoke-static/range {v38 .. v38}, Lgq/b;->c(I)J

    .line 268
    .line 269
    .line 270
    move-result-wide v18

    .line 271
    invoke-static/range {v21 .. v22}, Lgq/b;->a(D)J

    .line 272
    .line 273
    .line 274
    move-result-wide v15

    .line 275
    new-instance v7, Lg4/p0;

    .line 276
    .line 277
    invoke-direct/range {v7 .. v20}, Lg4/p0;-><init>(JJLk4/x;Lk4/t;Lk4/n;JIJI)V

    .line 278
    .line 279
    .line 280
    move-object/from16 v43, v7

    .line 281
    .line 282
    const/16 v7, 0xc

    .line 283
    .line 284
    invoke-static {v7}, Lgq/b;->c(I)J

    .line 285
    .line 286
    .line 287
    move-result-wide v26

    .line 288
    invoke-static/range {v37 .. v37}, Lgq/b;->c(I)J

    .line 289
    .line 290
    .line 291
    move-result-wide v34

    .line 292
    invoke-static/range {v21 .. v22}, Lgq/b;->a(D)J

    .line 293
    .line 294
    .line 295
    move-result-wide v31

    .line 296
    new-instance v23, Lg4/p0;

    .line 297
    .line 298
    invoke-direct/range {v23 .. v36}, Lg4/p0;-><init>(JJLk4/x;Lk4/t;Lk4/n;JIJI)V

    .line 299
    .line 300
    .line 301
    move-object/from16 v44, v23

    .line 302
    .line 303
    invoke-static {v7}, Lgq/b;->c(I)J

    .line 304
    .line 305
    .line 306
    move-result-wide v26

    .line 307
    invoke-static/range {v37 .. v37}, Lgq/b;->c(I)J

    .line 308
    .line 309
    .line 310
    move-result-wide v34

    .line 311
    invoke-static/range {v21 .. v22}, Lgq/b;->a(D)J

    .line 312
    .line 313
    .line 314
    move-result-wide v31

    .line 315
    new-instance v23, Lg4/p0;

    .line 316
    .line 317
    const v36, 0xfdef59

    .line 318
    .line 319
    .line 320
    invoke-direct/range {v23 .. v36}, Lg4/p0;-><init>(JJLk4/x;Lk4/t;Lk4/n;JIJI)V

    .line 321
    .line 322
    .line 323
    move-object/from16 v45, v23

    .line 324
    .line 325
    invoke-static {v7}, Lgq/b;->c(I)J

    .line 326
    .line 327
    .line 328
    move-result-wide v10

    .line 329
    invoke-static/range {v37 .. v37}, Lgq/b;->c(I)J

    .line 330
    .line 331
    .line 332
    move-result-wide v18

    .line 333
    invoke-static/range {v21 .. v22}, Lgq/b;->a(D)J

    .line 334
    .line 335
    .line 336
    move-result-wide v15

    .line 337
    new-instance v7, Lg4/p0;

    .line 338
    .line 339
    invoke-direct/range {v7 .. v20}, Lg4/p0;-><init>(JJLk4/x;Lk4/t;Lk4/n;JIJI)V

    .line 340
    .line 341
    .line 342
    const/16 v8, 0xb

    .line 343
    .line 344
    invoke-static {v8}, Lgq/b;->c(I)J

    .line 345
    .line 346
    .line 347
    move-result-wide v26

    .line 348
    sget-object v28, Lk4/x;->j:Lk4/x;

    .line 349
    .line 350
    invoke-static/range {v38 .. v38}, Lgq/b;->c(I)J

    .line 351
    .line 352
    .line 353
    move-result-wide v34

    .line 354
    const-wide v8, 0x3fd0a3d70a3d70a4L    # 0.26

    .line 355
    .line 356
    .line 357
    .line 358
    .line 359
    invoke-static {v8, v9}, Lgq/b;->a(D)J

    .line 360
    .line 361
    .line 362
    move-result-wide v31

    .line 363
    new-instance v23, Lg4/p0;

    .line 364
    .line 365
    const v36, 0xfdff59

    .line 366
    .line 367
    .line 368
    invoke-direct/range {v23 .. v36}, Lg4/p0;-><init>(JJLk4/x;Lk4/t;Lk4/n;JIJI)V

    .line 369
    .line 370
    .line 371
    move-object v14, v7

    .line 372
    move-object/from16 v15, v23

    .line 373
    .line 374
    move-object/from16 v7, v39

    .line 375
    .line 376
    move-object/from16 v8, v40

    .line 377
    .line 378
    move-object/from16 v9, v41

    .line 379
    .line 380
    move-object/from16 v10, v42

    .line 381
    .line 382
    move-object/from16 v11, v43

    .line 383
    .line 384
    move-object/from16 v12, v44

    .line 385
    .line 386
    move-object/from16 v13, v45

    .line 387
    .line 388
    invoke-direct/range {v0 .. v15}, Lj91/f;-><init>(Lg4/p0;Lg4/p0;Lg4/p0;Lg4/p0;Lg4/p0;Lg4/p0;Lg4/p0;Lg4/p0;Lg4/p0;Lg4/p0;Lg4/p0;Lg4/p0;Lg4/p0;Lg4/p0;Lg4/p0;)V

    .line 389
    .line 390
    .line 391
    return-object v0
.end method
