.class public final Lt3/s;
.super Landroidx/datastore/preferences/protobuf/k;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;
.implements Ld6/s;
.implements Landroid/view/View$OnAttachStateChangeListener;


# instance fields
.field public f:Z

.field public g:I

.field public h:Ld6/w1;

.field public final i:Landroidx/collection/q0;

.field public final j:Ll2/g1;

.field public final k:Landroidx/collection/l0;

.field public final l:Lv2/o;


# direct methods
.method public constructor <init>()V
    .locals 4

    .line 1
    const/4 v0, 0x1

    .line 2
    invoke-direct {p0, v0}, Landroidx/datastore/preferences/protobuf/k;-><init>(I)V

    .line 3
    .line 4
    .line 5
    new-instance v0, Landroidx/collection/q0;

    .line 6
    .line 7
    const/16 v1, 0x9

    .line 8
    .line 9
    invoke-direct {v0, v1}, Landroidx/collection/q0;-><init>(I)V

    .line 10
    .line 11
    .line 12
    sget-object v1, Lt3/u1;->a:Lt3/t1;

    .line 13
    .line 14
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 15
    .line 16
    .line 17
    sget-object v1, Lt3/t1;->b:Lt3/v1;

    .line 18
    .line 19
    new-instance v2, Lt3/w1;

    .line 20
    .line 21
    const-string v3, "caption bar"

    .line 22
    .line 23
    invoke-direct {v2, v3}, Lt3/w1;-><init>(Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    invoke-virtual {v0, v1, v2}, Landroidx/collection/q0;->m(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 27
    .line 28
    .line 29
    sget-object v1, Lt3/t1;->c:Lt3/v1;

    .line 30
    .line 31
    new-instance v2, Lt3/w1;

    .line 32
    .line 33
    const-string v3, "display cutout"

    .line 34
    .line 35
    invoke-direct {v2, v3}, Lt3/w1;-><init>(Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    invoke-virtual {v0, v1, v2}, Landroidx/collection/q0;->m(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    sget-object v1, Lt3/t1;->d:Lt3/v1;

    .line 42
    .line 43
    new-instance v2, Lt3/w1;

    .line 44
    .line 45
    const-string v3, "ime"

    .line 46
    .line 47
    invoke-direct {v2, v3}, Lt3/w1;-><init>(Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    invoke-virtual {v0, v1, v2}, Landroidx/collection/q0;->m(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    sget-object v1, Lt3/t1;->e:Lt3/v1;

    .line 54
    .line 55
    new-instance v2, Lt3/w1;

    .line 56
    .line 57
    const-string v3, "mandatory system gestures"

    .line 58
    .line 59
    invoke-direct {v2, v3}, Lt3/w1;-><init>(Ljava/lang/String;)V

    .line 60
    .line 61
    .line 62
    invoke-virtual {v0, v1, v2}, Landroidx/collection/q0;->m(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 63
    .line 64
    .line 65
    sget-object v1, Lt3/t1;->f:Lt3/v1;

    .line 66
    .line 67
    new-instance v2, Lt3/w1;

    .line 68
    .line 69
    const-string v3, "navigation bars"

    .line 70
    .line 71
    invoke-direct {v2, v3}, Lt3/w1;-><init>(Ljava/lang/String;)V

    .line 72
    .line 73
    .line 74
    invoke-virtual {v0, v1, v2}, Landroidx/collection/q0;->m(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 75
    .line 76
    .line 77
    sget-object v1, Lt3/t1;->g:Lt3/v1;

    .line 78
    .line 79
    new-instance v2, Lt3/w1;

    .line 80
    .line 81
    const-string v3, "status bars"

    .line 82
    .line 83
    invoke-direct {v2, v3}, Lt3/w1;-><init>(Ljava/lang/String;)V

    .line 84
    .line 85
    .line 86
    invoke-virtual {v0, v1, v2}, Landroidx/collection/q0;->m(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 87
    .line 88
    .line 89
    sget-object v1, Lt3/t1;->h:Lt3/v1;

    .line 90
    .line 91
    new-instance v2, Lt3/w1;

    .line 92
    .line 93
    const-string v3, "system gestures"

    .line 94
    .line 95
    invoke-direct {v2, v3}, Lt3/w1;-><init>(Ljava/lang/String;)V

    .line 96
    .line 97
    .line 98
    invoke-virtual {v0, v1, v2}, Landroidx/collection/q0;->m(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 99
    .line 100
    .line 101
    sget-object v1, Lt3/t1;->i:Lt3/v1;

    .line 102
    .line 103
    new-instance v2, Lt3/w1;

    .line 104
    .line 105
    const-string v3, "tappable element"

    .line 106
    .line 107
    invoke-direct {v2, v3}, Lt3/w1;-><init>(Ljava/lang/String;)V

    .line 108
    .line 109
    .line 110
    invoke-virtual {v0, v1, v2}, Landroidx/collection/q0;->m(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 111
    .line 112
    .line 113
    sget-object v1, Lt3/t1;->j:Lt3/v1;

    .line 114
    .line 115
    new-instance v2, Lt3/w1;

    .line 116
    .line 117
    const-string v3, "waterfall"

    .line 118
    .line 119
    invoke-direct {v2, v3}, Lt3/w1;-><init>(Ljava/lang/String;)V

    .line 120
    .line 121
    .line 122
    invoke-virtual {v0, v1, v2}, Landroidx/collection/q0;->m(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 123
    .line 124
    .line 125
    iput-object v0, p0, Lt3/s;->i:Landroidx/collection/q0;

    .line 126
    .line 127
    new-instance v0, Ll2/g1;

    .line 128
    .line 129
    const/4 v1, 0x0

    .line 130
    invoke-direct {v0, v1}, Ll2/g1;-><init>(I)V

    .line 131
    .line 132
    .line 133
    iput-object v0, p0, Lt3/s;->j:Ll2/g1;

    .line 134
    .line 135
    new-instance v0, Landroidx/collection/l0;

    .line 136
    .line 137
    const/4 v1, 0x4

    .line 138
    invoke-direct {v0, v1}, Landroidx/collection/l0;-><init>(I)V

    .line 139
    .line 140
    .line 141
    iput-object v0, p0, Lt3/s;->k:Landroidx/collection/l0;

    .line 142
    .line 143
    new-instance v0, Lv2/o;

    .line 144
    .line 145
    invoke-direct {v0}, Lv2/o;-><init>()V

    .line 146
    .line 147
    .line 148
    iput-object v0, p0, Lt3/s;->l:Lv2/o;

    .line 149
    .line 150
    return-void
.end method


# virtual methods
.method public final H(Ld6/w1;)V
    .locals 33

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    sget-object v2, Landroidx/compose/ui/layout/b;->a:Landroidx/collection/b0;

    .line 6
    .line 7
    iget-object v3, v2, Landroidx/collection/p;->b:[I

    .line 8
    .line 9
    iget-object v4, v2, Landroidx/collection/p;->c:[Ljava/lang/Object;

    .line 10
    .line 11
    iget-object v2, v2, Landroidx/collection/p;->a:[J

    .line 12
    .line 13
    array-length v5, v2

    .line 14
    add-int/lit8 v5, v5, -0x2

    .line 15
    .line 16
    const-wide/16 v16, 0x80

    .line 17
    .line 18
    const-wide/16 v18, 0xff

    .line 19
    .line 20
    const/16 v8, 0x8

    .line 21
    .line 22
    const/16 v20, 0x0

    .line 23
    .line 24
    if-ltz v5, :cond_4

    .line 25
    .line 26
    move/from16 v10, v20

    .line 27
    .line 28
    move/from16 v22, v10

    .line 29
    .line 30
    move/from16 v23, v22

    .line 31
    .line 32
    const/16 v21, 0x7

    .line 33
    .line 34
    const/16 v24, 0x10

    .line 35
    .line 36
    const/16 v25, 0x20

    .line 37
    .line 38
    :goto_0
    aget-wide v11, v2, v10

    .line 39
    .line 40
    const/16 v26, 0x30

    .line 41
    .line 42
    const-wide v27, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 43
    .line 44
    .line 45
    .line 46
    .line 47
    not-long v13, v11

    .line 48
    shl-long v13, v13, v21

    .line 49
    .line 50
    and-long/2addr v13, v11

    .line 51
    and-long v13, v13, v27

    .line 52
    .line 53
    cmp-long v13, v13, v27

    .line 54
    .line 55
    if-eqz v13, :cond_3

    .line 56
    .line 57
    sub-int v13, v10, v5

    .line 58
    .line 59
    not-int v13, v13

    .line 60
    ushr-int/lit8 v13, v13, 0x1f

    .line 61
    .line 62
    rsub-int/lit8 v13, v13, 0x8

    .line 63
    .line 64
    move/from16 v14, v20

    .line 65
    .line 66
    :goto_1
    if-ge v14, v13, :cond_2

    .line 67
    .line 68
    and-long v29, v11, v18

    .line 69
    .line 70
    cmp-long v15, v29, v16

    .line 71
    .line 72
    if-gez v15, :cond_0

    .line 73
    .line 74
    shl-int/lit8 v15, v10, 0x3

    .line 75
    .line 76
    add-int/2addr v15, v14

    .line 77
    const/16 v29, 0x1

    .line 78
    .line 79
    aget v9, v3, v15

    .line 80
    .line 81
    aget-object v15, v4, v15

    .line 82
    .line 83
    check-cast v15, Lt3/u1;

    .line 84
    .line 85
    move/from16 v30, v8

    .line 86
    .line 87
    iget-object v8, v1, Ld6/w1;->a:Ld6/s1;

    .line 88
    .line 89
    invoke-virtual {v8, v9}, Ld6/s1;->g(I)Ls5/b;

    .line 90
    .line 91
    .line 92
    move-result-object v8

    .line 93
    iget v9, v8, Ls5/b;->a:I

    .line 94
    .line 95
    int-to-long v6, v9

    .line 96
    shl-long v6, v6, v26

    .line 97
    .line 98
    iget v9, v8, Ls5/b;->b:I

    .line 99
    .line 100
    move-object/from16 v32, v2

    .line 101
    .line 102
    move-object/from16 v31, v3

    .line 103
    .line 104
    int-to-long v2, v9

    .line 105
    shl-long v2, v2, v25

    .line 106
    .line 107
    or-long/2addr v2, v6

    .line 108
    iget v6, v8, Ls5/b;->c:I

    .line 109
    .line 110
    int-to-long v6, v6

    .line 111
    shl-long v6, v6, v24

    .line 112
    .line 113
    or-long/2addr v2, v6

    .line 114
    iget v6, v8, Ls5/b;->d:I

    .line 115
    .line 116
    int-to-long v6, v6

    .line 117
    or-long/2addr v2, v6

    .line 118
    iget-object v6, v0, Lt3/s;->i:Landroidx/collection/q0;

    .line 119
    .line 120
    invoke-virtual {v6, v15}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 121
    .line 122
    .line 123
    move-result-object v6

    .line 124
    invoke-static {v6}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 125
    .line 126
    .line 127
    check-cast v6, Lt3/w1;

    .line 128
    .line 129
    iget-wide v7, v6, Lt3/w1;->h:J

    .line 130
    .line 131
    invoke-static {v2, v3, v7, v8}, Lt3/k1;->h(JJ)Z

    .line 132
    .line 133
    .line 134
    move-result v7

    .line 135
    if-nez v7, :cond_1

    .line 136
    .line 137
    iput-wide v2, v6, Lt3/w1;->h:J

    .line 138
    .line 139
    const-wide/16 v6, 0x0

    .line 140
    .line 141
    invoke-static {v2, v3, v6, v7}, Lt3/k1;->h(JJ)Z

    .line 142
    .line 143
    .line 144
    move-result v2

    .line 145
    move/from16 v22, v29

    .line 146
    .line 147
    if-nez v2, :cond_1

    .line 148
    .line 149
    move/from16 v23, v22

    .line 150
    .line 151
    goto :goto_2

    .line 152
    :cond_0
    move-object/from16 v32, v2

    .line 153
    .line 154
    move-object/from16 v31, v3

    .line 155
    .line 156
    move/from16 v30, v8

    .line 157
    .line 158
    const/16 v29, 0x1

    .line 159
    .line 160
    :cond_1
    :goto_2
    shr-long v11, v11, v30

    .line 161
    .line 162
    add-int/lit8 v14, v14, 0x1

    .line 163
    .line 164
    move/from16 v8, v30

    .line 165
    .line 166
    move-object/from16 v3, v31

    .line 167
    .line 168
    move-object/from16 v2, v32

    .line 169
    .line 170
    goto :goto_1

    .line 171
    :cond_2
    move-object/from16 v32, v2

    .line 172
    .line 173
    move-object/from16 v31, v3

    .line 174
    .line 175
    move v2, v8

    .line 176
    const/16 v29, 0x1

    .line 177
    .line 178
    if-ne v13, v2, :cond_5

    .line 179
    .line 180
    goto :goto_3

    .line 181
    :cond_3
    move-object/from16 v32, v2

    .line 182
    .line 183
    move-object/from16 v31, v3

    .line 184
    .line 185
    const/16 v29, 0x1

    .line 186
    .line 187
    :goto_3
    if-eq v10, v5, :cond_5

    .line 188
    .line 189
    add-int/lit8 v10, v10, 0x1

    .line 190
    .line 191
    move-object/from16 v3, v31

    .line 192
    .line 193
    move-object/from16 v2, v32

    .line 194
    .line 195
    const/16 v8, 0x8

    .line 196
    .line 197
    goto/16 :goto_0

    .line 198
    .line 199
    :cond_4
    const/16 v21, 0x7

    .line 200
    .line 201
    const/16 v24, 0x10

    .line 202
    .line 203
    const/16 v25, 0x20

    .line 204
    .line 205
    const/16 v26, 0x30

    .line 206
    .line 207
    const-wide v27, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 208
    .line 209
    .line 210
    .line 211
    .line 212
    const/16 v29, 0x1

    .line 213
    .line 214
    move/from16 v22, v20

    .line 215
    .line 216
    move/from16 v23, v22

    .line 217
    .line 218
    :cond_5
    sget-object v2, Landroidx/compose/ui/layout/b;->c:Landroidx/collection/b0;

    .line 219
    .line 220
    iget-object v3, v2, Landroidx/collection/p;->b:[I

    .line 221
    .line 222
    iget-object v4, v2, Landroidx/collection/p;->c:[Ljava/lang/Object;

    .line 223
    .line 224
    iget-object v2, v2, Landroidx/collection/p;->a:[J

    .line 225
    .line 226
    array-length v5, v2

    .line 227
    add-int/lit8 v5, v5, -0x2

    .line 228
    .line 229
    if-ltz v5, :cond_b

    .line 230
    .line 231
    move/from16 v6, v20

    .line 232
    .line 233
    :goto_4
    aget-wide v7, v2, v6

    .line 234
    .line 235
    not-long v9, v7

    .line 236
    shl-long v9, v9, v21

    .line 237
    .line 238
    and-long/2addr v9, v7

    .line 239
    and-long v9, v9, v27

    .line 240
    .line 241
    cmp-long v9, v9, v27

    .line 242
    .line 243
    if-eqz v9, :cond_a

    .line 244
    .line 245
    sub-int v9, v6, v5

    .line 246
    .line 247
    not-int v9, v9

    .line 248
    ushr-int/lit8 v9, v9, 0x1f

    .line 249
    .line 250
    const/16 v30, 0x8

    .line 251
    .line 252
    rsub-int/lit8 v9, v9, 0x8

    .line 253
    .line 254
    move/from16 v10, v20

    .line 255
    .line 256
    :goto_5
    if-ge v10, v9, :cond_9

    .line 257
    .line 258
    and-long v11, v7, v18

    .line 259
    .line 260
    cmp-long v11, v11, v16

    .line 261
    .line 262
    if-gez v11, :cond_8

    .line 263
    .line 264
    shl-int/lit8 v11, v6, 0x3

    .line 265
    .line 266
    add-int/2addr v11, v10

    .line 267
    aget v12, v3, v11

    .line 268
    .line 269
    aget-object v11, v4, v11

    .line 270
    .line 271
    check-cast v11, Lt3/u1;

    .line 272
    .line 273
    iget-object v13, v0, Lt3/s;->i:Landroidx/collection/q0;

    .line 274
    .line 275
    invoke-virtual {v13, v11}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 276
    .line 277
    .line 278
    move-result-object v11

    .line 279
    invoke-static {v11}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 280
    .line 281
    .line 282
    check-cast v11, Lt3/w1;

    .line 283
    .line 284
    const/16 v13, 0x8

    .line 285
    .line 286
    if-eq v12, v13, :cond_6

    .line 287
    .line 288
    iget-object v13, v1, Ld6/w1;->a:Ld6/s1;

    .line 289
    .line 290
    invoke-virtual {v13, v12}, Ld6/s1;->h(I)Ls5/b;

    .line 291
    .line 292
    .line 293
    move-result-object v13

    .line 294
    iget v14, v13, Ls5/b;->a:I

    .line 295
    .line 296
    int-to-long v14, v14

    .line 297
    shl-long v14, v14, v26

    .line 298
    .line 299
    move-object/from16 v31, v2

    .line 300
    .line 301
    iget v2, v13, Ls5/b;->b:I

    .line 302
    .line 303
    move-object/from16 v32, v3

    .line 304
    .line 305
    int-to-long v2, v2

    .line 306
    shl-long v2, v2, v25

    .line 307
    .line 308
    or-long/2addr v2, v14

    .line 309
    iget v14, v13, Ls5/b;->c:I

    .line 310
    .line 311
    int-to-long v14, v14

    .line 312
    shl-long v14, v14, v24

    .line 313
    .line 314
    or-long/2addr v2, v14

    .line 315
    iget v13, v13, Ls5/b;->d:I

    .line 316
    .line 317
    int-to-long v13, v13

    .line 318
    or-long/2addr v2, v13

    .line 319
    iget-wide v13, v11, Lt3/w1;->i:J

    .line 320
    .line 321
    invoke-static {v13, v14, v2, v3}, Lt3/k1;->h(JJ)Z

    .line 322
    .line 323
    .line 324
    move-result v13

    .line 325
    if-nez v13, :cond_7

    .line 326
    .line 327
    iput-wide v2, v11, Lt3/w1;->i:J

    .line 328
    .line 329
    const-wide/16 v13, 0x0

    .line 330
    .line 331
    invoke-static {v2, v3, v13, v14}, Lt3/k1;->h(JJ)Z

    .line 332
    .line 333
    .line 334
    move-result v2

    .line 335
    move/from16 v22, v29

    .line 336
    .line 337
    if-nez v2, :cond_7

    .line 338
    .line 339
    move/from16 v23, v22

    .line 340
    .line 341
    goto :goto_6

    .line 342
    :cond_6
    move-object/from16 v31, v2

    .line 343
    .line 344
    move-object/from16 v32, v3

    .line 345
    .line 346
    :cond_7
    :goto_6
    iget-object v2, v1, Ld6/w1;->a:Ld6/s1;

    .line 347
    .line 348
    invoke-virtual {v2, v12}, Ld6/s1;->q(I)Z

    .line 349
    .line 350
    .line 351
    move-result v2

    .line 352
    iget-object v3, v11, Lt3/w1;->a:Ll2/j1;

    .line 353
    .line 354
    invoke-static {v2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 355
    .line 356
    .line 357
    move-result-object v2

    .line 358
    invoke-virtual {v3, v2}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 359
    .line 360
    .line 361
    :goto_7
    const/16 v2, 0x8

    .line 362
    .line 363
    goto :goto_8

    .line 364
    :cond_8
    move-object/from16 v31, v2

    .line 365
    .line 366
    move-object/from16 v32, v3

    .line 367
    .line 368
    goto :goto_7

    .line 369
    :goto_8
    shr-long/2addr v7, v2

    .line 370
    add-int/lit8 v10, v10, 0x1

    .line 371
    .line 372
    move-object/from16 v2, v31

    .line 373
    .line 374
    move-object/from16 v3, v32

    .line 375
    .line 376
    goto :goto_5

    .line 377
    :cond_9
    move-object/from16 v31, v2

    .line 378
    .line 379
    move-object/from16 v32, v3

    .line 380
    .line 381
    const/16 v2, 0x8

    .line 382
    .line 383
    if-ne v9, v2, :cond_b

    .line 384
    .line 385
    goto :goto_9

    .line 386
    :cond_a
    move-object/from16 v31, v2

    .line 387
    .line 388
    move-object/from16 v32, v3

    .line 389
    .line 390
    const/16 v2, 0x8

    .line 391
    .line 392
    :goto_9
    if-eq v6, v5, :cond_b

    .line 393
    .line 394
    add-int/lit8 v6, v6, 0x1

    .line 395
    .line 396
    move-object/from16 v2, v31

    .line 397
    .line 398
    move-object/from16 v3, v32

    .line 399
    .line 400
    goto/16 :goto_4

    .line 401
    .line 402
    :cond_b
    iget-object v1, v1, Ld6/w1;->a:Ld6/s1;

    .line 403
    .line 404
    invoke-virtual {v1}, Ld6/s1;->f()Ld6/i;

    .line 405
    .line 406
    .line 407
    move-result-object v1

    .line 408
    if-nez v1, :cond_c

    .line 409
    .line 410
    const-wide/16 v2, 0x0

    .line 411
    .line 412
    goto :goto_a

    .line 413
    :cond_c
    invoke-virtual {v1}, Ld6/i;->a()Ls5/b;

    .line 414
    .line 415
    .line 416
    move-result-object v2

    .line 417
    iget v3, v2, Ls5/b;->a:I

    .line 418
    .line 419
    int-to-long v3, v3

    .line 420
    shl-long v3, v3, v26

    .line 421
    .line 422
    iget v5, v2, Ls5/b;->b:I

    .line 423
    .line 424
    int-to-long v5, v5

    .line 425
    shl-long v5, v5, v25

    .line 426
    .line 427
    or-long/2addr v3, v5

    .line 428
    iget v5, v2, Ls5/b;->c:I

    .line 429
    .line 430
    int-to-long v5, v5

    .line 431
    shl-long v5, v5, v24

    .line 432
    .line 433
    or-long/2addr v3, v5

    .line 434
    iget v2, v2, Ls5/b;->d:I

    .line 435
    .line 436
    int-to-long v5, v2

    .line 437
    or-long v2, v3, v5

    .line 438
    .line 439
    :goto_a
    iget-object v4, v0, Lt3/s;->i:Landroidx/collection/q0;

    .line 440
    .line 441
    sget-object v5, Lt3/u1;->a:Lt3/t1;

    .line 442
    .line 443
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 444
    .line 445
    .line 446
    sget-object v5, Lt3/t1;->j:Lt3/v1;

    .line 447
    .line 448
    invoke-virtual {v4, v5}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 449
    .line 450
    .line 451
    move-result-object v4

    .line 452
    invoke-static {v4}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 453
    .line 454
    .line 455
    check-cast v4, Lt3/w1;

    .line 456
    .line 457
    iget-wide v5, v4, Lt3/w1;->h:J

    .line 458
    .line 459
    invoke-static {v5, v6, v2, v3}, Lt3/k1;->h(JJ)Z

    .line 460
    .line 461
    .line 462
    move-result v5

    .line 463
    if-nez v5, :cond_d

    .line 464
    .line 465
    iput-wide v2, v4, Lt3/w1;->h:J

    .line 466
    .line 467
    iput-wide v2, v4, Lt3/w1;->i:J

    .line 468
    .line 469
    const-wide/16 v6, 0x0

    .line 470
    .line 471
    invoke-static {v2, v3, v6, v7}, Lt3/k1;->h(JJ)Z

    .line 472
    .line 473
    .line 474
    move-result v2

    .line 475
    move/from16 v22, v29

    .line 476
    .line 477
    if-nez v2, :cond_d

    .line 478
    .line 479
    move/from16 v23, v22

    .line 480
    .line 481
    :cond_d
    if-nez v1, :cond_e

    .line 482
    .line 483
    const-wide/16 v6, 0x0

    .line 484
    .line 485
    goto :goto_b

    .line 486
    :cond_e
    iget-object v2, v1, Ld6/i;->a:Landroid/view/DisplayCutout;

    .line 487
    .line 488
    invoke-virtual {v2}, Landroid/view/DisplayCutout;->getSafeInsetLeft()I

    .line 489
    .line 490
    .line 491
    move-result v2

    .line 492
    iget-object v3, v1, Ld6/i;->a:Landroid/view/DisplayCutout;

    .line 493
    .line 494
    invoke-virtual {v3}, Landroid/view/DisplayCutout;->getSafeInsetTop()I

    .line 495
    .line 496
    .line 497
    move-result v3

    .line 498
    iget-object v4, v1, Ld6/i;->a:Landroid/view/DisplayCutout;

    .line 499
    .line 500
    invoke-virtual {v4}, Landroid/view/DisplayCutout;->getSafeInsetRight()I

    .line 501
    .line 502
    .line 503
    move-result v4

    .line 504
    iget-object v5, v1, Ld6/i;->a:Landroid/view/DisplayCutout;

    .line 505
    .line 506
    invoke-virtual {v5}, Landroid/view/DisplayCutout;->getSafeInsetBottom()I

    .line 507
    .line 508
    .line 509
    move-result v5

    .line 510
    int-to-long v6, v2

    .line 511
    shl-long v6, v6, v26

    .line 512
    .line 513
    int-to-long v2, v3

    .line 514
    shl-long v2, v2, v25

    .line 515
    .line 516
    or-long/2addr v2, v6

    .line 517
    int-to-long v6, v4

    .line 518
    shl-long v6, v6, v24

    .line 519
    .line 520
    or-long/2addr v2, v6

    .line 521
    int-to-long v4, v5

    .line 522
    or-long v6, v2, v4

    .line 523
    .line 524
    :goto_b
    iget-object v2, v0, Lt3/s;->i:Landroidx/collection/q0;

    .line 525
    .line 526
    sget-object v3, Lt3/t1;->c:Lt3/v1;

    .line 527
    .line 528
    invoke-virtual {v2, v3}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 529
    .line 530
    .line 531
    move-result-object v2

    .line 532
    invoke-static {v2}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 533
    .line 534
    .line 535
    check-cast v2, Lt3/w1;

    .line 536
    .line 537
    iget-wide v3, v2, Lt3/w1;->h:J

    .line 538
    .line 539
    invoke-static {v6, v7, v3, v4}, Lt3/k1;->h(JJ)Z

    .line 540
    .line 541
    .line 542
    move-result v3

    .line 543
    if-nez v3, :cond_f

    .line 544
    .line 545
    iput-wide v6, v2, Lt3/w1;->h:J

    .line 546
    .line 547
    iput-wide v6, v2, Lt3/w1;->i:J

    .line 548
    .line 549
    const-wide/16 v13, 0x0

    .line 550
    .line 551
    invoke-static {v6, v7, v13, v14}, Lt3/k1;->h(JJ)Z

    .line 552
    .line 553
    .line 554
    move-result v2

    .line 555
    move/from16 v22, v29

    .line 556
    .line 557
    if-nez v2, :cond_f

    .line 558
    .line 559
    move/from16 v23, v22

    .line 560
    .line 561
    :cond_f
    if-nez v1, :cond_10

    .line 562
    .line 563
    iget-object v1, v0, Lt3/s;->k:Landroidx/collection/l0;

    .line 564
    .line 565
    iget v2, v1, Landroidx/collection/l0;->b:I

    .line 566
    .line 567
    if-lez v2, :cond_15

    .line 568
    .line 569
    invoke-virtual {v1}, Landroidx/collection/l0;->c()V

    .line 570
    .line 571
    .line 572
    iget-object v1, v0, Lt3/s;->l:Lv2/o;

    .line 573
    .line 574
    invoke-virtual {v1}, Lv2/o;->clear()V

    .line 575
    .line 576
    .line 577
    move/from16 v22, v29

    .line 578
    .line 579
    goto/16 :goto_f

    .line 580
    .line 581
    :cond_10
    iget-object v1, v1, Ld6/i;->a:Landroid/view/DisplayCutout;

    .line 582
    .line 583
    invoke-virtual {v1}, Landroid/view/DisplayCutout;->getBoundingRects()Ljava/util/List;

    .line 584
    .line 585
    .line 586
    move-result-object v1

    .line 587
    invoke-interface {v1}, Ljava/util/List;->size()I

    .line 588
    .line 589
    .line 590
    move-result v2

    .line 591
    iget-object v3, v0, Lt3/s;->k:Landroidx/collection/l0;

    .line 592
    .line 593
    iget v4, v3, Landroidx/collection/l0;->b:I

    .line 594
    .line 595
    if-ge v2, v4, :cond_11

    .line 596
    .line 597
    invoke-interface {v1}, Ljava/util/List;->size()I

    .line 598
    .line 599
    .line 600
    move-result v2

    .line 601
    iget-object v4, v0, Lt3/s;->k:Landroidx/collection/l0;

    .line 602
    .line 603
    iget v4, v4, Landroidx/collection/l0;->b:I

    .line 604
    .line 605
    invoke-virtual {v3, v2, v4}, Landroidx/collection/l0;->k(II)V

    .line 606
    .line 607
    .line 608
    iget-object v2, v0, Lt3/s;->l:Lv2/o;

    .line 609
    .line 610
    invoke-interface {v1}, Ljava/util/List;->size()I

    .line 611
    .line 612
    .line 613
    move-result v3

    .line 614
    iget-object v4, v0, Lt3/s;->l:Lv2/o;

    .line 615
    .line 616
    invoke-virtual {v4}, Lv2/o;->size()I

    .line 617
    .line 618
    .line 619
    move-result v4

    .line 620
    invoke-virtual {v2, v3, v4}, Lv2/o;->c(II)V

    .line 621
    .line 622
    .line 623
    move/from16 v22, v29

    .line 624
    .line 625
    goto :goto_d

    .line 626
    :cond_11
    invoke-interface {v1}, Ljava/util/List;->size()I

    .line 627
    .line 628
    .line 629
    move-result v2

    .line 630
    iget-object v3, v0, Lt3/s;->k:Landroidx/collection/l0;

    .line 631
    .line 632
    iget v3, v3, Landroidx/collection/l0;->b:I

    .line 633
    .line 634
    sub-int/2addr v2, v3

    .line 635
    move/from16 v3, v20

    .line 636
    .line 637
    :goto_c
    if-ge v3, v2, :cond_12

    .line 638
    .line 639
    iget-object v4, v0, Lt3/s;->k:Landroidx/collection/l0;

    .line 640
    .line 641
    iget v5, v4, Landroidx/collection/l0;->b:I

    .line 642
    .line 643
    invoke-interface {v1, v5}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 644
    .line 645
    .line 646
    move-result-object v5

    .line 647
    invoke-static {v5}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 648
    .line 649
    .line 650
    move-result-object v5

    .line 651
    invoke-virtual {v4, v5}, Landroidx/collection/l0;->a(Ljava/lang/Object;)V

    .line 652
    .line 653
    .line 654
    iget-object v4, v0, Lt3/s;->l:Lv2/o;

    .line 655
    .line 656
    new-instance v5, Ljava/lang/StringBuilder;

    .line 657
    .line 658
    const-string v6, "display cutout rect "

    .line 659
    .line 660
    invoke-direct {v5, v6}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 661
    .line 662
    .line 663
    iget-object v6, v0, Lt3/s;->k:Landroidx/collection/l0;

    .line 664
    .line 665
    iget v6, v6, Landroidx/collection/l0;->b:I

    .line 666
    .line 667
    invoke-virtual {v5, v6}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 668
    .line 669
    .line 670
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 671
    .line 672
    .line 673
    move-result-object v5

    .line 674
    new-instance v6, Lt3/r;

    .line 675
    .line 676
    invoke-direct {v6, v5}, Lt3/r;-><init>(Ljava/lang/String;)V

    .line 677
    .line 678
    .line 679
    invoke-virtual {v4, v6}, Lv2/o;->add(Ljava/lang/Object;)Z

    .line 680
    .line 681
    .line 682
    add-int/lit8 v3, v3, 0x1

    .line 683
    .line 684
    move/from16 v22, v29

    .line 685
    .line 686
    goto :goto_c

    .line 687
    :cond_12
    :goto_d
    move-object v2, v1

    .line 688
    check-cast v2, Ljava/util/Collection;

    .line 689
    .line 690
    invoke-interface {v2}, Ljava/util/Collection;->size()I

    .line 691
    .line 692
    .line 693
    move-result v3

    .line 694
    move/from16 v4, v20

    .line 695
    .line 696
    :goto_e
    if-ge v4, v3, :cond_14

    .line 697
    .line 698
    invoke-interface {v1, v4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 699
    .line 700
    .line 701
    move-result-object v5

    .line 702
    check-cast v5, Landroid/graphics/Rect;

    .line 703
    .line 704
    iget-object v6, v0, Lt3/s;->k:Landroidx/collection/l0;

    .line 705
    .line 706
    invoke-virtual {v6, v4}, Landroidx/collection/l0;->e(I)Ljava/lang/Object;

    .line 707
    .line 708
    .line 709
    move-result-object v6

    .line 710
    check-cast v6, Ll2/b1;

    .line 711
    .line 712
    invoke-interface {v6}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 713
    .line 714
    .line 715
    move-result-object v7

    .line 716
    invoke-static {v7, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 717
    .line 718
    .line 719
    move-result v7

    .line 720
    if-nez v7, :cond_13

    .line 721
    .line 722
    invoke-interface {v6, v5}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 723
    .line 724
    .line 725
    move/from16 v22, v29

    .line 726
    .line 727
    :cond_13
    add-int/lit8 v4, v4, 0x1

    .line 728
    .line 729
    goto :goto_e

    .line 730
    :cond_14
    invoke-interface {v2}, Ljava/util/Collection;->isEmpty()Z

    .line 731
    .line 732
    .line 733
    move-result v1

    .line 734
    if-nez v1, :cond_15

    .line 735
    .line 736
    move/from16 v23, v29

    .line 737
    .line 738
    :cond_15
    :goto_f
    if-nez v23, :cond_16

    .line 739
    .line 740
    iget-object v1, v0, Lt3/s;->j:Ll2/g1;

    .line 741
    .line 742
    invoke-virtual {v1}, Ll2/g1;->o()I

    .line 743
    .line 744
    .line 745
    move-result v1

    .line 746
    if-eqz v1, :cond_18

    .line 747
    .line 748
    :cond_16
    if-eqz v22, :cond_18

    .line 749
    .line 750
    iget-object v0, v0, Lt3/s;->j:Ll2/g1;

    .line 751
    .line 752
    invoke-virtual {v0}, Ll2/g1;->o()I

    .line 753
    .line 754
    .line 755
    move-result v1

    .line 756
    add-int/lit8 v1, v1, 0x1

    .line 757
    .line 758
    invoke-virtual {v0, v1}, Ll2/g1;->p(I)V

    .line 759
    .line 760
    .line 761
    sget-object v1, Lv2/l;->c:Ljava/lang/Object;

    .line 762
    .line 763
    monitor-enter v1

    .line 764
    :try_start_0
    sget-object v0, Lv2/l;->j:Lv2/a;

    .line 765
    .line 766
    iget-object v0, v0, Lv2/b;->h:Landroidx/collection/r0;

    .line 767
    .line 768
    if-eqz v0, :cond_17

    .line 769
    .line 770
    invoke-virtual {v0}, Landroidx/collection/r0;->h()Z

    .line 771
    .line 772
    .line 773
    move-result v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 774
    move/from16 v2, v29

    .line 775
    .line 776
    if-ne v0, v2, :cond_17

    .line 777
    .line 778
    move v9, v2

    .line 779
    goto :goto_10

    .line 780
    :cond_17
    move/from16 v9, v20

    .line 781
    .line 782
    :goto_10
    monitor-exit v1

    .line 783
    if-eqz v9, :cond_18

    .line 784
    .line 785
    invoke-static {}, Lv2/l;->a()V

    .line 786
    .line 787
    .line 788
    return-void

    .line 789
    :catchall_0
    move-exception v0

    .line 790
    monitor-exit v1

    .line 791
    throw v0

    .line 792
    :cond_18
    return-void
.end method

.method public final g(Ld6/f1;)V
    .locals 5

    .line 1
    const/4 v0, 0x0

    .line 2
    iput-boolean v0, p0, Lt3/s;->f:Z

    .line 3
    .line 4
    iget-object p1, p1, Ld6/f1;->a:Ld6/e1;

    .line 5
    .line 6
    invoke-virtual {p1}, Ld6/e1;->d()I

    .line 7
    .line 8
    .line 9
    move-result p1

    .line 10
    iget v1, p0, Lt3/s;->g:I

    .line 11
    .line 12
    not-int v2, p1

    .line 13
    and-int/2addr v1, v2

    .line 14
    iput v1, p0, Lt3/s;->g:I

    .line 15
    .line 16
    const/4 v1, 0x0

    .line 17
    iput-object v1, p0, Lt3/s;->h:Ld6/w1;

    .line 18
    .line 19
    sget-object v1, Landroidx/compose/ui/layout/b;->c:Landroidx/collection/b0;

    .line 20
    .line 21
    invoke-virtual {v1, p1}, Landroidx/collection/p;->b(I)Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object p1

    .line 25
    check-cast p1, Lt3/u1;

    .line 26
    .line 27
    if-eqz p1, :cond_1

    .line 28
    .line 29
    iget-object v1, p0, Lt3/s;->i:Landroidx/collection/q0;

    .line 30
    .line 31
    invoke-virtual {v1, p1}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p1

    .line 35
    invoke-static {p1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 36
    .line 37
    .line 38
    check-cast p1, Lt3/w1;

    .line 39
    .line 40
    iget-object v1, p1, Lt3/w1;->c:Ll2/f1;

    .line 41
    .line 42
    const/4 v2, 0x0

    .line 43
    invoke-virtual {v1, v2}, Ll2/f1;->p(F)V

    .line 44
    .line 45
    .line 46
    const/high16 v1, 0x3f800000    # 1.0f

    .line 47
    .line 48
    iget-object v3, p1, Lt3/w1;->e:Ll2/f1;

    .line 49
    .line 50
    invoke-virtual {v3, v1}, Ll2/f1;->p(F)V

    .line 51
    .line 52
    .line 53
    const-wide/16 v3, 0x0

    .line 54
    .line 55
    iget-object v1, p1, Lt3/w1;->d:Ll2/h1;

    .line 56
    .line 57
    invoke-virtual {v1, v3, v4}, Ll2/h1;->c(J)V

    .line 58
    .line 59
    .line 60
    iget-object v1, p1, Lt3/w1;->c:Ll2/f1;

    .line 61
    .line 62
    invoke-virtual {v1, v2}, Ll2/f1;->p(F)V

    .line 63
    .line 64
    .line 65
    iget-object v1, p1, Lt3/w1;->b:Ll2/j1;

    .line 66
    .line 67
    sget-object v2, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 68
    .line 69
    invoke-virtual {v1, v2}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 70
    .line 71
    .line 72
    const-wide/16 v1, -0x1

    .line 73
    .line 74
    iput-wide v1, p1, Lt3/w1;->j:J

    .line 75
    .line 76
    iput-wide v1, p1, Lt3/w1;->k:J

    .line 77
    .line 78
    iget-object p0, p0, Lt3/s;->j:Ll2/g1;

    .line 79
    .line 80
    invoke-virtual {p0}, Ll2/g1;->o()I

    .line 81
    .line 82
    .line 83
    move-result p1

    .line 84
    const/4 v1, 0x1

    .line 85
    add-int/2addr p1, v1

    .line 86
    invoke-virtual {p0, p1}, Ll2/g1;->p(I)V

    .line 87
    .line 88
    .line 89
    sget-object p0, Lv2/l;->c:Ljava/lang/Object;

    .line 90
    .line 91
    monitor-enter p0

    .line 92
    :try_start_0
    sget-object p1, Lv2/l;->j:Lv2/a;

    .line 93
    .line 94
    iget-object p1, p1, Lv2/b;->h:Landroidx/collection/r0;

    .line 95
    .line 96
    if-eqz p1, :cond_0

    .line 97
    .line 98
    invoke-virtual {p1}, Landroidx/collection/r0;->h()Z

    .line 99
    .line 100
    .line 101
    move-result p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 102
    if-ne p1, v1, :cond_0

    .line 103
    .line 104
    move v0, v1

    .line 105
    :cond_0
    monitor-exit p0

    .line 106
    if-eqz v0, :cond_1

    .line 107
    .line 108
    invoke-static {}, Lv2/l;->a()V

    .line 109
    .line 110
    .line 111
    return-void

    .line 112
    :catchall_0
    move-exception p1

    .line 113
    monitor-exit p0

    .line 114
    throw p1

    .line 115
    :cond_1
    return-void
.end method

.method public final h()V
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    iput-boolean v0, p0, Lt3/s;->f:Z

    .line 3
    .line 4
    return-void
.end method

.method public final i(Ld6/w1;Ljava/util/List;)Ld6/w1;
    .locals 6

    .line 1
    move-object v0, p2

    .line 2
    check-cast v0, Ljava/util/Collection;

    .line 3
    .line 4
    invoke-interface {v0}, Ljava/util/Collection;->size()I

    .line 5
    .line 6
    .line 7
    move-result v0

    .line 8
    const/4 v1, 0x0

    .line 9
    :goto_0
    if-ge v1, v0, :cond_1

    .line 10
    .line 11
    invoke-interface {p2, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v2

    .line 15
    check-cast v2, Ld6/f1;

    .line 16
    .line 17
    iget-object v3, v2, Ld6/f1;->a:Ld6/e1;

    .line 18
    .line 19
    invoke-virtual {v3}, Ld6/e1;->d()I

    .line 20
    .line 21
    .line 22
    move-result v3

    .line 23
    sget-object v4, Landroidx/compose/ui/layout/b;->c:Landroidx/collection/b0;

    .line 24
    .line 25
    invoke-virtual {v4, v3}, Landroidx/collection/p;->b(I)Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object v3

    .line 29
    check-cast v3, Lt3/u1;

    .line 30
    .line 31
    if-eqz v3, :cond_0

    .line 32
    .line 33
    iget-object v4, p0, Lt3/s;->i:Landroidx/collection/q0;

    .line 34
    .line 35
    invoke-virtual {v4, v3}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object v3

    .line 39
    invoke-static {v3}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    check-cast v3, Lt3/w1;

    .line 43
    .line 44
    iget-object v4, v3, Lt3/w1;->b:Ll2/j1;

    .line 45
    .line 46
    invoke-virtual {v4}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    move-result-object v4

    .line 50
    check-cast v4, Ljava/lang/Boolean;

    .line 51
    .line 52
    invoke-virtual {v4}, Ljava/lang/Boolean;->booleanValue()Z

    .line 53
    .line 54
    .line 55
    move-result v4

    .line 56
    if-eqz v4, :cond_0

    .line 57
    .line 58
    iget-object v2, v2, Ld6/f1;->a:Ld6/e1;

    .line 59
    .line 60
    invoke-virtual {v2}, Ld6/e1;->c()F

    .line 61
    .line 62
    .line 63
    move-result v4

    .line 64
    iget-object v5, v3, Lt3/w1;->c:Ll2/f1;

    .line 65
    .line 66
    invoke-virtual {v5, v4}, Ll2/f1;->p(F)V

    .line 67
    .line 68
    .line 69
    invoke-virtual {v2}, Ld6/e1;->a()F

    .line 70
    .line 71
    .line 72
    move-result v4

    .line 73
    iget-object v5, v3, Lt3/w1;->e:Ll2/f1;

    .line 74
    .line 75
    invoke-virtual {v5, v4}, Ll2/f1;->p(F)V

    .line 76
    .line 77
    .line 78
    invoke-virtual {v2}, Ld6/e1;->b()J

    .line 79
    .line 80
    .line 81
    move-result-wide v4

    .line 82
    iget-object v2, v3, Lt3/w1;->d:Ll2/h1;

    .line 83
    .line 84
    invoke-virtual {v2, v4, v5}, Ll2/h1;->c(J)V

    .line 85
    .line 86
    .line 87
    :cond_0
    add-int/lit8 v1, v1, 0x1

    .line 88
    .line 89
    goto :goto_0

    .line 90
    :cond_1
    invoke-virtual {p0, p1}, Lt3/s;->H(Ld6/w1;)V

    .line 91
    .line 92
    .line 93
    return-object p1
.end method

.method public final j(Ld6/f1;Lb81/d;)Lb81/d;
    .locals 8

    .line 1
    iget-object v0, p0, Lt3/s;->h:Ld6/w1;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    iput-boolean v1, p0, Lt3/s;->f:Z

    .line 5
    .line 6
    const/4 v2, 0x0

    .line 7
    iput-object v2, p0, Lt3/s;->h:Ld6/w1;

    .line 8
    .line 9
    iget-object v2, p1, Ld6/f1;->a:Ld6/e1;

    .line 10
    .line 11
    invoke-virtual {v2}, Ld6/e1;->b()J

    .line 12
    .line 13
    .line 14
    move-result-wide v2

    .line 15
    const-wide/16 v4, 0x0

    .line 16
    .line 17
    cmp-long v2, v2, v4

    .line 18
    .line 19
    if-lez v2, :cond_1

    .line 20
    .line 21
    if-eqz v0, :cond_1

    .line 22
    .line 23
    iget-object v2, p1, Ld6/f1;->a:Ld6/e1;

    .line 24
    .line 25
    invoke-virtual {v2}, Ld6/e1;->d()I

    .line 26
    .line 27
    .line 28
    move-result v2

    .line 29
    iget v3, p0, Lt3/s;->g:I

    .line 30
    .line 31
    or-int/2addr v3, v2

    .line 32
    iput v3, p0, Lt3/s;->g:I

    .line 33
    .line 34
    sget-object v3, Landroidx/compose/ui/layout/b;->c:Landroidx/collection/b0;

    .line 35
    .line 36
    invoke-virtual {v3, v2}, Landroidx/collection/p;->b(I)Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object v3

    .line 40
    check-cast v3, Lt3/u1;

    .line 41
    .line 42
    if-eqz v3, :cond_1

    .line 43
    .line 44
    iget-object v4, p0, Lt3/s;->i:Landroidx/collection/q0;

    .line 45
    .line 46
    invoke-virtual {v4, v3}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    move-result-object v3

    .line 50
    invoke-static {v3}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    check-cast v3, Lt3/w1;

    .line 54
    .line 55
    iget-object v0, v0, Ld6/w1;->a:Ld6/s1;

    .line 56
    .line 57
    invoke-virtual {v0, v2}, Ld6/s1;->g(I)Ls5/b;

    .line 58
    .line 59
    .line 60
    move-result-object v0

    .line 61
    iget v2, v0, Ls5/b;->a:I

    .line 62
    .line 63
    int-to-long v4, v2

    .line 64
    const/16 v2, 0x30

    .line 65
    .line 66
    shl-long/2addr v4, v2

    .line 67
    iget v2, v0, Ls5/b;->b:I

    .line 68
    .line 69
    int-to-long v6, v2

    .line 70
    const/16 v2, 0x20

    .line 71
    .line 72
    shl-long/2addr v6, v2

    .line 73
    or-long/2addr v4, v6

    .line 74
    iget v2, v0, Ls5/b;->c:I

    .line 75
    .line 76
    int-to-long v6, v2

    .line 77
    const/16 v2, 0x10

    .line 78
    .line 79
    shl-long/2addr v6, v2

    .line 80
    or-long/2addr v4, v6

    .line 81
    iget v0, v0, Ls5/b;->d:I

    .line 82
    .line 83
    int-to-long v6, v0

    .line 84
    or-long/2addr v4, v6

    .line 85
    iget-wide v6, v3, Lt3/w1;->h:J

    .line 86
    .line 87
    invoke-static {v4, v5, v6, v7}, Lt3/k1;->h(JJ)Z

    .line 88
    .line 89
    .line 90
    move-result v0

    .line 91
    if-nez v0, :cond_1

    .line 92
    .line 93
    iput-wide v6, v3, Lt3/w1;->j:J

    .line 94
    .line 95
    iput-wide v4, v3, Lt3/w1;->k:J

    .line 96
    .line 97
    iget-object v0, v3, Lt3/w1;->b:Ll2/j1;

    .line 98
    .line 99
    sget-object v2, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 100
    .line 101
    invoke-virtual {v0, v2}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 102
    .line 103
    .line 104
    iget-object p1, p1, Ld6/f1;->a:Ld6/e1;

    .line 105
    .line 106
    invoke-virtual {p1}, Ld6/e1;->c()F

    .line 107
    .line 108
    .line 109
    move-result v0

    .line 110
    iget-object v2, v3, Lt3/w1;->c:Ll2/f1;

    .line 111
    .line 112
    invoke-virtual {v2, v0}, Ll2/f1;->p(F)V

    .line 113
    .line 114
    .line 115
    invoke-virtual {p1}, Ld6/e1;->a()F

    .line 116
    .line 117
    .line 118
    move-result v0

    .line 119
    iget-object v2, v3, Lt3/w1;->e:Ll2/f1;

    .line 120
    .line 121
    invoke-virtual {v2, v0}, Ll2/f1;->p(F)V

    .line 122
    .line 123
    .line 124
    invoke-virtual {p1}, Ld6/e1;->b()J

    .line 125
    .line 126
    .line 127
    move-result-wide v4

    .line 128
    iget-object p1, v3, Lt3/w1;->d:Ll2/h1;

    .line 129
    .line 130
    invoke-virtual {p1, v4, v5}, Ll2/h1;->c(J)V

    .line 131
    .line 132
    .line 133
    iget-object p0, p0, Lt3/s;->j:Ll2/g1;

    .line 134
    .line 135
    invoke-virtual {p0}, Ll2/g1;->o()I

    .line 136
    .line 137
    .line 138
    move-result p1

    .line 139
    const/4 v0, 0x1

    .line 140
    add-int/2addr p1, v0

    .line 141
    invoke-virtual {p0, p1}, Ll2/g1;->p(I)V

    .line 142
    .line 143
    .line 144
    sget-object p0, Lv2/l;->c:Ljava/lang/Object;

    .line 145
    .line 146
    monitor-enter p0

    .line 147
    :try_start_0
    sget-object p1, Lv2/l;->j:Lv2/a;

    .line 148
    .line 149
    iget-object p1, p1, Lv2/b;->h:Landroidx/collection/r0;

    .line 150
    .line 151
    if-eqz p1, :cond_0

    .line 152
    .line 153
    invoke-virtual {p1}, Landroidx/collection/r0;->h()Z

    .line 154
    .line 155
    .line 156
    move-result p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 157
    if-ne p1, v0, :cond_0

    .line 158
    .line 159
    move v1, v0

    .line 160
    :cond_0
    monitor-exit p0

    .line 161
    if-eqz v1, :cond_1

    .line 162
    .line 163
    invoke-static {}, Lv2/l;->a()V

    .line 164
    .line 165
    .line 166
    return-object p2

    .line 167
    :catchall_0
    move-exception p1

    .line 168
    monitor-exit p0

    .line 169
    throw p1

    .line 170
    :cond_1
    return-object p2
.end method

.method public final onApplyWindowInsets(Landroid/view/View;Ld6/w1;)Ld6/w1;
    .locals 2

    .line 1
    iget-boolean v0, p0, Lt3/s;->f:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iput-object p2, p0, Lt3/s;->h:Ld6/w1;

    .line 6
    .line 7
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 8
    .line 9
    const/16 v1, 0x1e

    .line 10
    .line 11
    if-ne v0, v1, :cond_1

    .line 12
    .line 13
    invoke-virtual {p1, p0}, Landroid/view/View;->post(Ljava/lang/Runnable;)Z

    .line 14
    .line 15
    .line 16
    return-object p2

    .line 17
    :cond_0
    iget p1, p0, Lt3/s;->g:I

    .line 18
    .line 19
    if-nez p1, :cond_1

    .line 20
    .line 21
    invoke-virtual {p0, p2}, Lt3/s;->H(Ld6/w1;)V

    .line 22
    .line 23
    .line 24
    :cond_1
    return-object p2
.end method

.method public final onViewAttachedToWindow(Landroid/view/View;)V
    .locals 2

    .line 1
    invoke-virtual {p1}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    instance-of v1, v0, Landroid/view/View;

    .line 6
    .line 7
    if-eqz v1, :cond_0

    .line 8
    .line 9
    check-cast v0, Landroid/view/View;

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    const/4 v0, 0x0

    .line 13
    :goto_0
    if-nez v0, :cond_1

    .line 14
    .line 15
    goto :goto_1

    .line 16
    :cond_1
    move-object p1, v0

    .line 17
    :goto_1
    sget-object v0, Ld6/r0;->a:Ljava/util/WeakHashMap;

    .line 18
    .line 19
    invoke-static {p1, p0}, Ld6/k0;->j(Landroid/view/View;Ld6/s;)V

    .line 20
    .line 21
    .line 22
    invoke-static {p1, p0}, Ld6/r0;->k(Landroid/view/View;Landroidx/datastore/preferences/protobuf/k;)V

    .line 23
    .line 24
    .line 25
    return-void
.end method

.method public final onViewDetachedFromWindow(Landroid/view/View;)V
    .locals 2

    .line 1
    invoke-virtual {p1}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    instance-of v0, p0, Landroid/view/View;

    .line 6
    .line 7
    const/4 v1, 0x0

    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    check-cast p0, Landroid/view/View;

    .line 11
    .line 12
    goto :goto_0

    .line 13
    :cond_0
    move-object p0, v1

    .line 14
    :goto_0
    if-nez p0, :cond_1

    .line 15
    .line 16
    goto :goto_1

    .line 17
    :cond_1
    move-object p1, p0

    .line 18
    :goto_1
    sget-object p0, Ld6/r0;->a:Ljava/util/WeakHashMap;

    .line 19
    .line 20
    invoke-static {p1, v1}, Ld6/k0;->j(Landroid/view/View;Ld6/s;)V

    .line 21
    .line 22
    .line 23
    invoke-static {p1, v1}, Ld6/r0;->k(Landroid/view/View;Landroidx/datastore/preferences/protobuf/k;)V

    .line 24
    .line 25
    .line 26
    return-void
.end method

.method public final run()V
    .locals 1

    .line 1
    iget-boolean v0, p0, Lt3/s;->f:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    const/4 v0, 0x0

    .line 6
    iput v0, p0, Lt3/s;->g:I

    .line 7
    .line 8
    iput-boolean v0, p0, Lt3/s;->f:Z

    .line 9
    .line 10
    iget-object v0, p0, Lt3/s;->h:Ld6/w1;

    .line 11
    .line 12
    if-eqz v0, :cond_0

    .line 13
    .line 14
    invoke-virtual {p0, v0}, Lt3/s;->H(Ld6/w1;)V

    .line 15
    .line 16
    .line 17
    const/4 v0, 0x0

    .line 18
    iput-object v0, p0, Lt3/s;->h:Ld6/w1;

    .line 19
    .line 20
    :cond_0
    return-void
.end method
