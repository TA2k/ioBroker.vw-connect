.class public final Lj2/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lj2/h;

.field public static final b:Ls1/e;

.field public static final c:F

.field public static final d:F

.field public static final e:F


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lj2/h;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lj2/h;->a:Lj2/h;

    .line 7
    .line 8
    sget-object v0, Ls1/f;->a:Ls1/e;

    .line 9
    .line 10
    sput-object v0, Lj2/h;->b:Ls1/e;

    .line 11
    .line 12
    const/16 v0, 0x50

    .line 13
    .line 14
    int-to-float v0, v0

    .line 15
    sput v0, Lj2/h;->c:F

    .line 16
    .line 17
    sput v0, Lj2/h;->d:F

    .line 18
    .line 19
    sget v0, Lk2/p;->c:F

    .line 20
    .line 21
    sput v0, Lj2/h;->e:F

    .line 22
    .line 23
    return-void
.end method


# virtual methods
.method public final a(Lj2/p;ZLx2/s;JJFLl2/o;II)V
    .locals 15

    .line 1
    move-object/from16 v1, p1

    .line 2
    .line 3
    move/from16 v2, p2

    .line 4
    .line 5
    move/from16 v12, p10

    .line 6
    .line 7
    move-object/from16 v10, p9

    .line 8
    .line 9
    check-cast v10, Ll2/t;

    .line 10
    .line 11
    const v0, -0x402fbc70

    .line 12
    .line 13
    .line 14
    invoke-virtual {v10, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 15
    .line 16
    .line 17
    and-int/lit8 v0, v12, 0x6

    .line 18
    .line 19
    if-nez v0, :cond_1

    .line 20
    .line 21
    invoke-virtual {v10, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    move-result v0

    .line 25
    if-eqz v0, :cond_0

    .line 26
    .line 27
    const/4 v0, 0x4

    .line 28
    goto :goto_0

    .line 29
    :cond_0
    const/4 v0, 0x2

    .line 30
    :goto_0
    or-int/2addr v0, v12

    .line 31
    goto :goto_1

    .line 32
    :cond_1
    move v0, v12

    .line 33
    :goto_1
    and-int/lit8 v3, v12, 0x30

    .line 34
    .line 35
    if-nez v3, :cond_3

    .line 36
    .line 37
    invoke-virtual {v10, v2}, Ll2/t;->h(Z)Z

    .line 38
    .line 39
    .line 40
    move-result v3

    .line 41
    if-eqz v3, :cond_2

    .line 42
    .line 43
    const/16 v3, 0x20

    .line 44
    .line 45
    goto :goto_2

    .line 46
    :cond_2
    const/16 v3, 0x10

    .line 47
    .line 48
    :goto_2
    or-int/2addr v0, v3

    .line 49
    :cond_3
    and-int/lit16 v3, v12, 0x180

    .line 50
    .line 51
    move-object/from16 v4, p3

    .line 52
    .line 53
    if-nez v3, :cond_5

    .line 54
    .line 55
    invoke-virtual {v10, v4}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 56
    .line 57
    .line 58
    move-result v3

    .line 59
    if-eqz v3, :cond_4

    .line 60
    .line 61
    const/16 v3, 0x100

    .line 62
    .line 63
    goto :goto_3

    .line 64
    :cond_4
    const/16 v3, 0x80

    .line 65
    .line 66
    :goto_3
    or-int/2addr v0, v3

    .line 67
    :cond_5
    and-int/lit16 v3, v12, 0xc00

    .line 68
    .line 69
    if-nez v3, :cond_7

    .line 70
    .line 71
    and-int/lit8 v3, p11, 0x8

    .line 72
    .line 73
    move-wide/from16 v5, p4

    .line 74
    .line 75
    if-nez v3, :cond_6

    .line 76
    .line 77
    invoke-virtual {v10, v5, v6}, Ll2/t;->f(J)Z

    .line 78
    .line 79
    .line 80
    move-result v3

    .line 81
    if-eqz v3, :cond_6

    .line 82
    .line 83
    const/16 v3, 0x800

    .line 84
    .line 85
    goto :goto_4

    .line 86
    :cond_6
    const/16 v3, 0x400

    .line 87
    .line 88
    :goto_4
    or-int/2addr v0, v3

    .line 89
    goto :goto_5

    .line 90
    :cond_7
    move-wide/from16 v5, p4

    .line 91
    .line 92
    :goto_5
    and-int/lit16 v3, v12, 0x6000

    .line 93
    .line 94
    if-nez v3, :cond_9

    .line 95
    .line 96
    and-int/lit8 v3, p11, 0x10

    .line 97
    .line 98
    move-wide/from16 v7, p6

    .line 99
    .line 100
    if-nez v3, :cond_8

    .line 101
    .line 102
    invoke-virtual {v10, v7, v8}, Ll2/t;->f(J)Z

    .line 103
    .line 104
    .line 105
    move-result v3

    .line 106
    if-eqz v3, :cond_8

    .line 107
    .line 108
    const/16 v3, 0x4000

    .line 109
    .line 110
    goto :goto_6

    .line 111
    :cond_8
    const/16 v3, 0x2000

    .line 112
    .line 113
    :goto_6
    or-int/2addr v0, v3

    .line 114
    goto :goto_7

    .line 115
    :cond_9
    move-wide/from16 v7, p6

    .line 116
    .line 117
    :goto_7
    const/high16 v3, 0x30000

    .line 118
    .line 119
    and-int/2addr v3, v12

    .line 120
    if-nez v3, :cond_a

    .line 121
    .line 122
    const/high16 v3, 0x10000

    .line 123
    .line 124
    or-int/2addr v0, v3

    .line 125
    :cond_a
    const/high16 v3, 0x180000

    .line 126
    .line 127
    and-int/2addr v3, v12

    .line 128
    if-nez v3, :cond_c

    .line 129
    .line 130
    invoke-virtual {v10, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 131
    .line 132
    .line 133
    move-result v3

    .line 134
    if-eqz v3, :cond_b

    .line 135
    .line 136
    const/high16 v3, 0x100000

    .line 137
    .line 138
    goto :goto_8

    .line 139
    :cond_b
    const/high16 v3, 0x80000

    .line 140
    .line 141
    :goto_8
    or-int/2addr v0, v3

    .line 142
    :cond_c
    const v3, 0x92493

    .line 143
    .line 144
    .line 145
    and-int/2addr v3, v0

    .line 146
    const v9, 0x92492

    .line 147
    .line 148
    .line 149
    if-eq v3, v9, :cond_d

    .line 150
    .line 151
    const/4 v3, 0x1

    .line 152
    goto :goto_9

    .line 153
    :cond_d
    const/4 v3, 0x0

    .line 154
    :goto_9
    and-int/lit8 v9, v0, 0x1

    .line 155
    .line 156
    invoke-virtual {v10, v9, v3}, Ll2/t;->O(IZ)Z

    .line 157
    .line 158
    .line 159
    move-result v3

    .line 160
    if-eqz v3, :cond_14

    .line 161
    .line 162
    invoke-virtual {v10}, Ll2/t;->T()V

    .line 163
    .line 164
    .line 165
    and-int/lit8 v3, v12, 0x1

    .line 166
    .line 167
    const v9, -0x70001

    .line 168
    .line 169
    .line 170
    const v11, -0xe001

    .line 171
    .line 172
    .line 173
    if-eqz v3, :cond_11

    .line 174
    .line 175
    invoke-virtual {v10}, Ll2/t;->y()Z

    .line 176
    .line 177
    .line 178
    move-result v3

    .line 179
    if-eqz v3, :cond_e

    .line 180
    .line 181
    goto :goto_b

    .line 182
    :cond_e
    invoke-virtual {v10}, Ll2/t;->R()V

    .line 183
    .line 184
    .line 185
    and-int/lit8 v3, p11, 0x8

    .line 186
    .line 187
    if-eqz v3, :cond_f

    .line 188
    .line 189
    and-int/lit16 v0, v0, -0x1c01

    .line 190
    .line 191
    :cond_f
    and-int/lit8 v3, p11, 0x10

    .line 192
    .line 193
    if-eqz v3, :cond_10

    .line 194
    .line 195
    and-int/2addr v0, v11

    .line 196
    :cond_10
    and-int/2addr v0, v9

    .line 197
    move/from16 v4, p8

    .line 198
    .line 199
    :goto_a
    move-wide v13, v7

    .line 200
    move-wide v6, v5

    .line 201
    goto :goto_c

    .line 202
    :cond_11
    :goto_b
    and-int/lit8 v3, p11, 0x8

    .line 203
    .line 204
    if-eqz v3, :cond_12

    .line 205
    .line 206
    sget-object v3, Lh2/g1;->a:Ll2/u2;

    .line 207
    .line 208
    invoke-virtual {v10, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 209
    .line 210
    .line 211
    move-result-object v3

    .line 212
    check-cast v3, Lh2/f1;

    .line 213
    .line 214
    iget-wide v5, v3, Lh2/f1;->G:J

    .line 215
    .line 216
    and-int/lit16 v0, v0, -0x1c01

    .line 217
    .line 218
    :cond_12
    and-int/lit8 v3, p11, 0x10

    .line 219
    .line 220
    if-eqz v3, :cond_13

    .line 221
    .line 222
    sget-object v3, Lh2/g1;->a:Ll2/u2;

    .line 223
    .line 224
    invoke-virtual {v10, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 225
    .line 226
    .line 227
    move-result-object v3

    .line 228
    check-cast v3, Lh2/f1;

    .line 229
    .line 230
    iget-wide v7, v3, Lh2/f1;->s:J

    .line 231
    .line 232
    and-int/2addr v0, v11

    .line 233
    :cond_13
    and-int/2addr v0, v9

    .line 234
    sget v3, Lj2/h;->d:F

    .line 235
    .line 236
    move v4, v3

    .line 237
    goto :goto_a

    .line 238
    :goto_c
    invoke-virtual {v10}, Ll2/t;->r()V

    .line 239
    .line 240
    .line 241
    new-instance v3, Lj2/g;

    .line 242
    .line 243
    invoke-direct {v3, v2, v13, v14, v1}, Lj2/g;-><init>(ZJLj2/p;)V

    .line 244
    .line 245
    .line 246
    const v5, 0x11c6ab49

    .line 247
    .line 248
    .line 249
    invoke-static {v5, v10, v3}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 250
    .line 251
    .line 252
    move-result-object v9

    .line 253
    and-int/lit8 v3, v0, 0xe

    .line 254
    .line 255
    const/high16 v5, 0xc00000

    .line 256
    .line 257
    or-int/2addr v3, v5

    .line 258
    and-int/lit8 v5, v0, 0x70

    .line 259
    .line 260
    or-int/2addr v3, v5

    .line 261
    and-int/lit16 v5, v0, 0x380

    .line 262
    .line 263
    or-int/2addr v3, v5

    .line 264
    shl-int/lit8 v0, v0, 0x6

    .line 265
    .line 266
    const/high16 v5, 0x70000

    .line 267
    .line 268
    and-int/2addr v5, v0

    .line 269
    or-int/2addr v3, v5

    .line 270
    const/high16 v5, 0xe000000

    .line 271
    .line 272
    and-int/2addr v0, v5

    .line 273
    or-int v11, v3, v0

    .line 274
    .line 275
    const/4 v5, 0x0

    .line 276
    const/4 v8, 0x0

    .line 277
    move-object v0, p0

    .line 278
    move-object/from16 v3, p3

    .line 279
    .line 280
    invoke-virtual/range {v0 .. v11}, Lj2/h;->b(Lj2/p;ZLx2/s;FLe3/n0;JFLt2/b;Ll2/o;I)V

    .line 281
    .line 282
    .line 283
    move v9, v4

    .line 284
    move-wide v5, v6

    .line 285
    move-wide v7, v13

    .line 286
    goto :goto_d

    .line 287
    :cond_14
    invoke-virtual {v10}, Ll2/t;->R()V

    .line 288
    .line 289
    .line 290
    move/from16 v9, p8

    .line 291
    .line 292
    :goto_d
    invoke-virtual {v10}, Ll2/t;->s()Ll2/u1;

    .line 293
    .line 294
    .line 295
    move-result-object v13

    .line 296
    if-eqz v13, :cond_15

    .line 297
    .line 298
    new-instance v0, Lj2/a;

    .line 299
    .line 300
    move-object v1, p0

    .line 301
    move-object/from16 v2, p1

    .line 302
    .line 303
    move/from16 v3, p2

    .line 304
    .line 305
    move-object/from16 v4, p3

    .line 306
    .line 307
    move/from16 v11, p11

    .line 308
    .line 309
    move v10, v12

    .line 310
    invoke-direct/range {v0 .. v11}, Lj2/a;-><init>(Lj2/h;Lj2/p;ZLx2/s;JJFII)V

    .line 311
    .line 312
    .line 313
    iput-object v0, v13, Ll2/u1;->d:Lay0/n;

    .line 314
    .line 315
    :cond_15
    return-void
.end method

.method public final b(Lj2/p;ZLx2/s;FLe3/n0;JFLt2/b;Ll2/o;I)V
    .locals 16

    .line 1
    move-object/from16 v4, p3

    .line 2
    .line 3
    move/from16 v5, p4

    .line 4
    .line 5
    move-wide/from16 v0, p6

    .line 6
    .line 7
    move-object/from16 v2, p9

    .line 8
    .line 9
    move/from16 v11, p11

    .line 10
    .line 11
    move-object/from16 v3, p10

    .line 12
    .line 13
    check-cast v3, Ll2/t;

    .line 14
    .line 15
    const v6, -0x4ff03da9

    .line 16
    .line 17
    .line 18
    invoke-virtual {v3, v6}, Ll2/t;->a0(I)Ll2/t;

    .line 19
    .line 20
    .line 21
    and-int/lit8 v6, v11, 0x6

    .line 22
    .line 23
    if-nez v6, :cond_1

    .line 24
    .line 25
    move-object/from16 v6, p1

    .line 26
    .line 27
    invoke-virtual {v3, v6}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result v8

    .line 31
    if-eqz v8, :cond_0

    .line 32
    .line 33
    const/4 v8, 0x4

    .line 34
    goto :goto_0

    .line 35
    :cond_0
    const/4 v8, 0x2

    .line 36
    :goto_0
    or-int/2addr v8, v11

    .line 37
    goto :goto_1

    .line 38
    :cond_1
    move-object/from16 v6, p1

    .line 39
    .line 40
    move v8, v11

    .line 41
    :goto_1
    and-int/lit8 v9, v11, 0x30

    .line 42
    .line 43
    if-nez v9, :cond_3

    .line 44
    .line 45
    move/from16 v9, p2

    .line 46
    .line 47
    invoke-virtual {v3, v9}, Ll2/t;->h(Z)Z

    .line 48
    .line 49
    .line 50
    move-result v12

    .line 51
    if-eqz v12, :cond_2

    .line 52
    .line 53
    const/16 v12, 0x20

    .line 54
    .line 55
    goto :goto_2

    .line 56
    :cond_2
    const/16 v12, 0x10

    .line 57
    .line 58
    :goto_2
    or-int/2addr v8, v12

    .line 59
    goto :goto_3

    .line 60
    :cond_3
    move/from16 v9, p2

    .line 61
    .line 62
    :goto_3
    and-int/lit16 v12, v11, 0x180

    .line 63
    .line 64
    if-nez v12, :cond_5

    .line 65
    .line 66
    invoke-virtual {v3, v4}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 67
    .line 68
    .line 69
    move-result v12

    .line 70
    if-eqz v12, :cond_4

    .line 71
    .line 72
    const/16 v12, 0x100

    .line 73
    .line 74
    goto :goto_4

    .line 75
    :cond_4
    const/16 v12, 0x80

    .line 76
    .line 77
    :goto_4
    or-int/2addr v8, v12

    .line 78
    :cond_5
    and-int/lit16 v12, v11, 0xc00

    .line 79
    .line 80
    if-nez v12, :cond_7

    .line 81
    .line 82
    invoke-virtual {v3, v5}, Ll2/t;->d(F)Z

    .line 83
    .line 84
    .line 85
    move-result v12

    .line 86
    if-eqz v12, :cond_6

    .line 87
    .line 88
    const/16 v12, 0x800

    .line 89
    .line 90
    goto :goto_5

    .line 91
    :cond_6
    const/16 v12, 0x400

    .line 92
    .line 93
    :goto_5
    or-int/2addr v8, v12

    .line 94
    :cond_7
    and-int/lit16 v12, v11, 0x6000

    .line 95
    .line 96
    if-nez v12, :cond_8

    .line 97
    .line 98
    or-int/lit16 v8, v8, 0x2000

    .line 99
    .line 100
    :cond_8
    const/high16 v12, 0x30000

    .line 101
    .line 102
    and-int/2addr v12, v11

    .line 103
    if-nez v12, :cond_a

    .line 104
    .line 105
    invoke-virtual {v3, v0, v1}, Ll2/t;->f(J)Z

    .line 106
    .line 107
    .line 108
    move-result v12

    .line 109
    if-eqz v12, :cond_9

    .line 110
    .line 111
    const/high16 v12, 0x20000

    .line 112
    .line 113
    goto :goto_6

    .line 114
    :cond_9
    const/high16 v12, 0x10000

    .line 115
    .line 116
    :goto_6
    or-int/2addr v8, v12

    .line 117
    :cond_a
    const/high16 v12, 0x180000

    .line 118
    .line 119
    and-int/2addr v12, v11

    .line 120
    if-nez v12, :cond_b

    .line 121
    .line 122
    const/high16 v12, 0x80000

    .line 123
    .line 124
    or-int/2addr v8, v12

    .line 125
    :cond_b
    const/high16 v12, 0xc00000

    .line 126
    .line 127
    and-int/2addr v12, v11

    .line 128
    if-nez v12, :cond_d

    .line 129
    .line 130
    invoke-virtual {v3, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 131
    .line 132
    .line 133
    move-result v12

    .line 134
    if-eqz v12, :cond_c

    .line 135
    .line 136
    const/high16 v12, 0x800000

    .line 137
    .line 138
    goto :goto_7

    .line 139
    :cond_c
    const/high16 v12, 0x400000

    .line 140
    .line 141
    :goto_7
    or-int/2addr v8, v12

    .line 142
    :cond_d
    const/high16 v12, 0x6000000

    .line 143
    .line 144
    and-int/2addr v12, v11

    .line 145
    if-nez v12, :cond_f

    .line 146
    .line 147
    move-object/from16 v12, p0

    .line 148
    .line 149
    invoke-virtual {v3, v12}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 150
    .line 151
    .line 152
    move-result v14

    .line 153
    if-eqz v14, :cond_e

    .line 154
    .line 155
    const/high16 v14, 0x4000000

    .line 156
    .line 157
    goto :goto_8

    .line 158
    :cond_e
    const/high16 v14, 0x2000000

    .line 159
    .line 160
    :goto_8
    or-int/2addr v8, v14

    .line 161
    goto :goto_9

    .line 162
    :cond_f
    move-object/from16 v12, p0

    .line 163
    .line 164
    :goto_9
    const v14, 0x2492493

    .line 165
    .line 166
    .line 167
    and-int/2addr v14, v8

    .line 168
    const v15, 0x2492492

    .line 169
    .line 170
    .line 171
    if-eq v14, v15, :cond_10

    .line 172
    .line 173
    const/4 v14, 0x1

    .line 174
    goto :goto_a

    .line 175
    :cond_10
    const/4 v14, 0x0

    .line 176
    :goto_a
    and-int/lit8 v15, v8, 0x1

    .line 177
    .line 178
    invoke-virtual {v3, v15, v14}, Ll2/t;->O(IZ)Z

    .line 179
    .line 180
    .line 181
    move-result v14

    .line 182
    if-eqz v14, :cond_1e

    .line 183
    .line 184
    invoke-virtual {v3}, Ll2/t;->T()V

    .line 185
    .line 186
    .line 187
    and-int/lit8 v14, v11, 0x1

    .line 188
    .line 189
    const v15, -0x38e001

    .line 190
    .line 191
    .line 192
    if-eqz v14, :cond_12

    .line 193
    .line 194
    invoke-virtual {v3}, Ll2/t;->y()Z

    .line 195
    .line 196
    .line 197
    move-result v14

    .line 198
    if-eqz v14, :cond_11

    .line 199
    .line 200
    goto :goto_c

    .line 201
    :cond_11
    invoke-virtual {v3}, Ll2/t;->R()V

    .line 202
    .line 203
    .line 204
    and-int/2addr v8, v15

    .line 205
    move-object/from16 v14, p5

    .line 206
    .line 207
    move/from16 v9, p8

    .line 208
    .line 209
    :goto_b
    move v15, v8

    .line 210
    goto :goto_d

    .line 211
    :cond_12
    :goto_c
    and-int/2addr v8, v15

    .line 212
    sget-object v14, Lj2/h;->b:Ls1/e;

    .line 213
    .line 214
    sget v15, Lj2/h;->e:F

    .line 215
    .line 216
    move v9, v15

    .line 217
    goto :goto_b

    .line 218
    :goto_d
    invoke-virtual {v3}, Ll2/t;->r()V

    .line 219
    .line 220
    .line 221
    sget v8, Lj2/i;->d:F

    .line 222
    .line 223
    invoke-static {v4, v8}, Landroidx/compose/foundation/layout/d;->n(Lx2/s;F)Lx2/s;

    .line 224
    .line 225
    .line 226
    move-result-object v8

    .line 227
    invoke-virtual {v3}, Ll2/t;->L()Ljava/lang/Object;

    .line 228
    .line 229
    .line 230
    move-result-object v13

    .line 231
    sget-object v10, Ll2/n;->a:Ll2/x0;

    .line 232
    .line 233
    if-ne v13, v10, :cond_13

    .line 234
    .line 235
    new-instance v13, Lim0/b;

    .line 236
    .line 237
    const/4 v7, 0x7

    .line 238
    invoke-direct {v13, v7}, Lim0/b;-><init>(I)V

    .line 239
    .line 240
    .line 241
    invoke-virtual {v3, v13}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 242
    .line 243
    .line 244
    :cond_13
    check-cast v13, Lay0/k;

    .line 245
    .line 246
    invoke-static {v8, v13}, Landroidx/compose/ui/draw/a;->c(Lx2/s;Lay0/k;)Lx2/s;

    .line 247
    .line 248
    .line 249
    move-result-object v13

    .line 250
    and-int/lit8 v7, v15, 0xe

    .line 251
    .line 252
    const/4 v8, 0x4

    .line 253
    if-ne v7, v8, :cond_14

    .line 254
    .line 255
    const/4 v7, 0x1

    .line 256
    goto :goto_e

    .line 257
    :cond_14
    const/4 v7, 0x0

    .line 258
    :goto_e
    and-int/lit8 v8, v15, 0x70

    .line 259
    .line 260
    const/16 v4, 0x20

    .line 261
    .line 262
    if-ne v8, v4, :cond_15

    .line 263
    .line 264
    const/4 v4, 0x1

    .line 265
    goto :goto_f

    .line 266
    :cond_15
    const/4 v4, 0x0

    .line 267
    :goto_f
    or-int/2addr v4, v7

    .line 268
    and-int/lit16 v7, v15, 0x1c00

    .line 269
    .line 270
    xor-int/lit16 v7, v7, 0xc00

    .line 271
    .line 272
    const/16 v8, 0x800

    .line 273
    .line 274
    if-le v7, v8, :cond_16

    .line 275
    .line 276
    invoke-virtual {v3, v5}, Ll2/t;->d(F)Z

    .line 277
    .line 278
    .line 279
    move-result v7

    .line 280
    if-nez v7, :cond_17

    .line 281
    .line 282
    :cond_16
    and-int/lit16 v7, v15, 0xc00

    .line 283
    .line 284
    if-ne v7, v8, :cond_18

    .line 285
    .line 286
    :cond_17
    const/4 v7, 0x1

    .line 287
    goto :goto_10

    .line 288
    :cond_18
    const/4 v7, 0x0

    .line 289
    :goto_10
    or-int/2addr v4, v7

    .line 290
    invoke-virtual {v3, v9}, Ll2/t;->d(F)Z

    .line 291
    .line 292
    .line 293
    move-result v7

    .line 294
    or-int/2addr v4, v7

    .line 295
    invoke-virtual {v3, v14}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 296
    .line 297
    .line 298
    move-result v7

    .line 299
    or-int/2addr v4, v7

    .line 300
    invoke-virtual {v3}, Ll2/t;->L()Ljava/lang/Object;

    .line 301
    .line 302
    .line 303
    move-result-object v7

    .line 304
    if-nez v4, :cond_1a

    .line 305
    .line 306
    if-ne v7, v10, :cond_19

    .line 307
    .line 308
    goto :goto_11

    .line 309
    :cond_19
    move-object v10, v14

    .line 310
    goto :goto_12

    .line 311
    :cond_1a
    :goto_11
    new-instance v5, Lj2/b;

    .line 312
    .line 313
    move/from16 v7, p2

    .line 314
    .line 315
    move/from16 v8, p4

    .line 316
    .line 317
    move-object v10, v14

    .line 318
    invoke-direct/range {v5 .. v10}, Lj2/b;-><init>(Lj2/p;ZFFLe3/n0;)V

    .line 319
    .line 320
    .line 321
    invoke-virtual {v3, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 322
    .line 323
    .line 324
    move-object v7, v5

    .line 325
    :goto_12
    check-cast v7, Lay0/o;

    .line 326
    .line 327
    invoke-static {v13, v7}, Landroidx/compose/ui/layout/a;->b(Lx2/s;Lay0/o;)Lx2/s;

    .line 328
    .line 329
    .line 330
    move-result-object v4

    .line 331
    invoke-static {v4, v0, v1, v10}, Landroidx/compose/foundation/a;->b(Lx2/s;JLe3/n0;)Lx2/s;

    .line 332
    .line 333
    .line 334
    move-result-object v4

    .line 335
    sget-object v5, Lx2/c;->h:Lx2/j;

    .line 336
    .line 337
    shr-int/lit8 v6, v15, 0xc

    .line 338
    .line 339
    and-int/lit16 v6, v6, 0x1c00

    .line 340
    .line 341
    or-int/lit8 v6, v6, 0x30

    .line 342
    .line 343
    const/4 v7, 0x0

    .line 344
    invoke-static {v5, v7}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 345
    .line 346
    .line 347
    move-result-object v5

    .line 348
    iget-wide v7, v3, Ll2/t;->T:J

    .line 349
    .line 350
    invoke-static {v7, v8}, Ljava/lang/Long;->hashCode(J)I

    .line 351
    .line 352
    .line 353
    move-result v7

    .line 354
    invoke-virtual {v3}, Ll2/t;->m()Ll2/p1;

    .line 355
    .line 356
    .line 357
    move-result-object v8

    .line 358
    invoke-static {v3, v4}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 359
    .line 360
    .line 361
    move-result-object v4

    .line 362
    sget-object v13, Lv3/k;->m1:Lv3/j;

    .line 363
    .line 364
    invoke-virtual {v13}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 365
    .line 366
    .line 367
    sget-object v13, Lv3/j;->b:Lv3/i;

    .line 368
    .line 369
    invoke-virtual {v3}, Ll2/t;->c0()V

    .line 370
    .line 371
    .line 372
    iget-boolean v14, v3, Ll2/t;->S:Z

    .line 373
    .line 374
    if-eqz v14, :cond_1b

    .line 375
    .line 376
    invoke-virtual {v3, v13}, Ll2/t;->l(Lay0/a;)V

    .line 377
    .line 378
    .line 379
    goto :goto_13

    .line 380
    :cond_1b
    invoke-virtual {v3}, Ll2/t;->m0()V

    .line 381
    .line 382
    .line 383
    :goto_13
    sget-object v13, Lv3/j;->g:Lv3/h;

    .line 384
    .line 385
    invoke-static {v13, v5, v3}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 386
    .line 387
    .line 388
    sget-object v5, Lv3/j;->f:Lv3/h;

    .line 389
    .line 390
    invoke-static {v5, v8, v3}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 391
    .line 392
    .line 393
    sget-object v5, Lv3/j;->j:Lv3/h;

    .line 394
    .line 395
    iget-boolean v8, v3, Ll2/t;->S:Z

    .line 396
    .line 397
    if-nez v8, :cond_1c

    .line 398
    .line 399
    invoke-virtual {v3}, Ll2/t;->L()Ljava/lang/Object;

    .line 400
    .line 401
    .line 402
    move-result-object v8

    .line 403
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 404
    .line 405
    .line 406
    move-result-object v13

    .line 407
    invoke-static {v8, v13}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 408
    .line 409
    .line 410
    move-result v8

    .line 411
    if-nez v8, :cond_1d

    .line 412
    .line 413
    :cond_1c
    invoke-static {v7, v3, v7, v5}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 414
    .line 415
    .line 416
    :cond_1d
    sget-object v5, Lv3/j;->d:Lv3/h;

    .line 417
    .line 418
    invoke-static {v5, v4, v3}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 419
    .line 420
    .line 421
    shr-int/lit8 v4, v6, 0x6

    .line 422
    .line 423
    and-int/lit8 v4, v4, 0x70

    .line 424
    .line 425
    or-int/lit8 v4, v4, 0x6

    .line 426
    .line 427
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 428
    .line 429
    .line 430
    move-result-object v4

    .line 431
    sget-object v5, Landroidx/compose/foundation/layout/b;->a:Landroidx/compose/foundation/layout/b;

    .line 432
    .line 433
    invoke-virtual {v2, v5, v3, v4}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 434
    .line 435
    .line 436
    const/4 v4, 0x1

    .line 437
    invoke-virtual {v3, v4}, Ll2/t;->q(Z)V

    .line 438
    .line 439
    .line 440
    move-object v6, v10

    .line 441
    goto :goto_14

    .line 442
    :cond_1e
    invoke-virtual {v3}, Ll2/t;->R()V

    .line 443
    .line 444
    .line 445
    move-object/from16 v6, p5

    .line 446
    .line 447
    move/from16 v9, p8

    .line 448
    .line 449
    :goto_14
    invoke-virtual {v3}, Ll2/t;->s()Ll2/u1;

    .line 450
    .line 451
    .line 452
    move-result-object v13

    .line 453
    if-eqz v13, :cond_1f

    .line 454
    .line 455
    new-instance v0, Lj2/c;

    .line 456
    .line 457
    move/from16 v3, p2

    .line 458
    .line 459
    move-object/from16 v4, p3

    .line 460
    .line 461
    move/from16 v5, p4

    .line 462
    .line 463
    move-wide/from16 v7, p6

    .line 464
    .line 465
    move-object v10, v2

    .line 466
    move-object v1, v12

    .line 467
    move-object/from16 v2, p1

    .line 468
    .line 469
    invoke-direct/range {v0 .. v11}, Lj2/c;-><init>(Lj2/h;Lj2/p;ZLx2/s;FLe3/n0;JFLt2/b;I)V

    .line 470
    .line 471
    .line 472
    iput-object v0, v13, Ll2/u1;->d:Lay0/n;

    .line 473
    .line 474
    :cond_1f
    return-void
.end method
