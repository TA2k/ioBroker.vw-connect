.class public abstract Lf2/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lx4/w;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lx4/w;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    const/16 v2, 0xe

    .line 5
    .line 6
    invoke-direct {v0, v2, v1}, Lx4/w;-><init>(IZ)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lf2/b;->a:Lx4/w;

    .line 10
    .line 11
    return-void
.end method

.method public static final a(ZLay0/a;Lx2/s;JLe1/n1;Lx4/w;Lt2/b;Ll2/o;I)V
    .locals 17

    .line 1
    move-object/from16 v4, p8

    .line 2
    .line 3
    check-cast v4, Ll2/t;

    .line 4
    .line 5
    const v0, 0x4c05d572    # 3.508372E7f

    .line 6
    .line 7
    .line 8
    invoke-virtual {v4, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 9
    .line 10
    .line 11
    move/from16 v7, p0

    .line 12
    .line 13
    invoke-virtual {v4, v7}, Ll2/t;->h(Z)Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    if-eqz v0, :cond_0

    .line 18
    .line 19
    const/4 v0, 0x4

    .line 20
    goto :goto_0

    .line 21
    :cond_0
    const/4 v0, 0x2

    .line 22
    :goto_0
    or-int v0, p9, v0

    .line 23
    .line 24
    move-object/from16 v1, p1

    .line 25
    .line 26
    invoke-virtual {v4, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 27
    .line 28
    .line 29
    move-result v2

    .line 30
    const/16 v3, 0x20

    .line 31
    .line 32
    if-eqz v2, :cond_1

    .line 33
    .line 34
    move v2, v3

    .line 35
    goto :goto_1

    .line 36
    :cond_1
    const/16 v2, 0x10

    .line 37
    .line 38
    :goto_1
    or-int/2addr v0, v2

    .line 39
    move-object/from16 v8, p2

    .line 40
    .line 41
    invoke-virtual {v4, v8}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 42
    .line 43
    .line 44
    move-result v2

    .line 45
    if-eqz v2, :cond_2

    .line 46
    .line 47
    const/16 v2, 0x100

    .line 48
    .line 49
    goto :goto_2

    .line 50
    :cond_2
    const/16 v2, 0x80

    .line 51
    .line 52
    :goto_2
    or-int/2addr v0, v2

    .line 53
    const v2, 0x32c00

    .line 54
    .line 55
    .line 56
    or-int/2addr v0, v2

    .line 57
    const v2, 0x92493

    .line 58
    .line 59
    .line 60
    and-int/2addr v2, v0

    .line 61
    const v5, 0x92492

    .line 62
    .line 63
    .line 64
    const/4 v15, 0x0

    .line 65
    const/4 v6, 0x1

    .line 66
    if-eq v2, v5, :cond_3

    .line 67
    .line 68
    move v2, v6

    .line 69
    goto :goto_3

    .line 70
    :cond_3
    move v2, v15

    .line 71
    :goto_3
    and-int/lit8 v5, v0, 0x1

    .line 72
    .line 73
    invoke-virtual {v4, v5, v2}, Ll2/t;->O(IZ)Z

    .line 74
    .line 75
    .line 76
    move-result v2

    .line 77
    if-eqz v2, :cond_b

    .line 78
    .line 79
    invoke-virtual {v4}, Ll2/t;->T()V

    .line 80
    .line 81
    .line 82
    and-int/lit8 v2, p9, 0x1

    .line 83
    .line 84
    const v5, -0xe001

    .line 85
    .line 86
    .line 87
    if-eqz v2, :cond_5

    .line 88
    .line 89
    invoke-virtual {v4}, Ll2/t;->y()Z

    .line 90
    .line 91
    .line 92
    move-result v2

    .line 93
    if-eqz v2, :cond_4

    .line 94
    .line 95
    goto :goto_4

    .line 96
    :cond_4
    invoke-virtual {v4}, Ll2/t;->R()V

    .line 97
    .line 98
    .line 99
    and-int/2addr v0, v5

    .line 100
    move-wide/from16 v2, p3

    .line 101
    .line 102
    move-object/from16 v11, p5

    .line 103
    .line 104
    move-object/from16 v5, p6

    .line 105
    .line 106
    goto :goto_5

    .line 107
    :cond_5
    :goto_4
    int-to-float v2, v15

    .line 108
    invoke-static {v2}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 109
    .line 110
    .line 111
    move-result v9

    .line 112
    int-to-long v9, v9

    .line 113
    invoke-static {v2}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 114
    .line 115
    .line 116
    move-result v2

    .line 117
    int-to-long v11, v2

    .line 118
    shl-long v2, v9, v3

    .line 119
    .line 120
    const-wide v9, 0xffffffffL

    .line 121
    .line 122
    .line 123
    .line 124
    .line 125
    and-long/2addr v9, v11

    .line 126
    or-long/2addr v2, v9

    .line 127
    invoke-static {v15, v6, v4}, Lkp/n;->b(IILl2/o;)Le1/n1;

    .line 128
    .line 129
    .line 130
    move-result-object v6

    .line 131
    and-int/2addr v0, v5

    .line 132
    sget-object v5, Lf2/b;->a:Lx4/w;

    .line 133
    .line 134
    move-object v11, v6

    .line 135
    :goto_5
    invoke-virtual {v4}, Ll2/t;->r()V

    .line 136
    .line 137
    .line 138
    invoke-virtual {v4}, Ll2/t;->L()Ljava/lang/Object;

    .line 139
    .line 140
    .line 141
    move-result-object v6

    .line 142
    sget-object v9, Ll2/n;->a:Ll2/x0;

    .line 143
    .line 144
    if-ne v6, v9, :cond_6

    .line 145
    .line 146
    new-instance v6, Lc1/n0;

    .line 147
    .line 148
    sget-object v10, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 149
    .line 150
    invoke-direct {v6, v10}, Lc1/n0;-><init>(Ljava/lang/Object;)V

    .line 151
    .line 152
    .line 153
    invoke-virtual {v4, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 154
    .line 155
    .line 156
    :cond_6
    check-cast v6, Lc1/n0;

    .line 157
    .line 158
    invoke-static {v7}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 159
    .line 160
    .line 161
    move-result-object v10

    .line 162
    invoke-virtual {v6, v10}, Lc1/n0;->b0(Ljava/lang/Boolean;)V

    .line 163
    .line 164
    .line 165
    iget-object v10, v6, Lc1/n0;->f:Ll2/j1;

    .line 166
    .line 167
    invoke-virtual {v10}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 168
    .line 169
    .line 170
    move-result-object v10

    .line 171
    check-cast v10, Ljava/lang/Boolean;

    .line 172
    .line 173
    invoke-virtual {v10}, Ljava/lang/Boolean;->booleanValue()Z

    .line 174
    .line 175
    .line 176
    move-result v10

    .line 177
    if-nez v10, :cond_8

    .line 178
    .line 179
    iget-object v10, v6, Lc1/n0;->g:Ll2/j1;

    .line 180
    .line 181
    invoke-virtual {v10}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 182
    .line 183
    .line 184
    move-result-object v10

    .line 185
    check-cast v10, Ljava/lang/Boolean;

    .line 186
    .line 187
    invoke-virtual {v10}, Ljava/lang/Boolean;->booleanValue()Z

    .line 188
    .line 189
    .line 190
    move-result v10

    .line 191
    if-eqz v10, :cond_7

    .line 192
    .line 193
    goto :goto_6

    .line 194
    :cond_7
    const v0, -0x250b1030

    .line 195
    .line 196
    .line 197
    invoke-virtual {v4, v0}, Ll2/t;->Y(I)V

    .line 198
    .line 199
    .line 200
    invoke-virtual {v4, v15}, Ll2/t;->q(Z)V

    .line 201
    .line 202
    .line 203
    move-wide v9, v2

    .line 204
    move-object v2, v5

    .line 205
    goto :goto_7

    .line 206
    :cond_8
    :goto_6
    const v10, -0x25172cea

    .line 207
    .line 208
    .line 209
    invoke-virtual {v4, v10}, Ll2/t;->Y(I)V

    .line 210
    .line 211
    .line 212
    invoke-virtual {v4}, Ll2/t;->L()Ljava/lang/Object;

    .line 213
    .line 214
    .line 215
    move-result-object v10

    .line 216
    if-ne v10, v9, :cond_9

    .line 217
    .line 218
    sget-wide v12, Le3/q0;->b:J

    .line 219
    .line 220
    new-instance v10, Le3/q0;

    .line 221
    .line 222
    invoke-direct {v10, v12, v13}, Le3/q0;-><init>(J)V

    .line 223
    .line 224
    .line 225
    invoke-static {v10}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 226
    .line 227
    .line 228
    move-result-object v10

    .line 229
    invoke-virtual {v4, v10}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 230
    .line 231
    .line 232
    :cond_9
    check-cast v10, Ll2/b1;

    .line 233
    .line 234
    sget-object v12, Lw3/h1;->h:Ll2/u2;

    .line 235
    .line 236
    invoke-virtual {v4, v12}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 237
    .line 238
    .line 239
    move-result-object v12

    .line 240
    check-cast v12, Lt4/c;

    .line 241
    .line 242
    invoke-virtual {v4}, Ll2/t;->L()Ljava/lang/Object;

    .line 243
    .line 244
    .line 245
    move-result-object v13

    .line 246
    if-ne v13, v9, :cond_a

    .line 247
    .line 248
    new-instance v13, Leh/c;

    .line 249
    .line 250
    const/16 v9, 0xb

    .line 251
    .line 252
    invoke-direct {v13, v10, v9}, Leh/c;-><init>(Ll2/b1;I)V

    .line 253
    .line 254
    .line 255
    invoke-virtual {v4, v13}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 256
    .line 257
    .line 258
    :cond_a
    check-cast v13, Lay0/n;

    .line 259
    .line 260
    move/from16 v16, v0

    .line 261
    .line 262
    new-instance v0, Lf2/w;

    .line 263
    .line 264
    invoke-direct {v0, v2, v3, v12, v13}, Lf2/w;-><init>(JLt4/c;Lay0/n;)V

    .line 265
    .line 266
    .line 267
    new-instance v8, Laa/r;

    .line 268
    .line 269
    const/4 v14, 0x1

    .line 270
    move-object/from16 v12, p2

    .line 271
    .line 272
    move-object/from16 v13, p7

    .line 273
    .line 274
    move-object v9, v6

    .line 275
    invoke-direct/range {v8 .. v14}, Laa/r;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 276
    .line 277
    .line 278
    const v6, 0x6a9e70ab

    .line 279
    .line 280
    .line 281
    invoke-static {v6, v4, v8}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 282
    .line 283
    .line 284
    move-result-object v6

    .line 285
    and-int/lit8 v8, v16, 0x70

    .line 286
    .line 287
    or-int/lit16 v8, v8, 0xd80

    .line 288
    .line 289
    move-wide v9, v2

    .line 290
    move-object v3, v6

    .line 291
    const/4 v6, 0x0

    .line 292
    move-object v2, v5

    .line 293
    move v5, v8

    .line 294
    invoke-static/range {v0 .. v6}, Lx4/i;->a(Lx4/v;Lay0/a;Lx4/w;Lt2/b;Ll2/o;II)V

    .line 295
    .line 296
    .line 297
    invoke-virtual {v4, v15}, Ll2/t;->q(Z)V

    .line 298
    .line 299
    .line 300
    :goto_7
    move-object v12, v2

    .line 301
    goto :goto_8

    .line 302
    :cond_b
    invoke-virtual {v4}, Ll2/t;->R()V

    .line 303
    .line 304
    .line 305
    move-wide/from16 v9, p3

    .line 306
    .line 307
    move-object/from16 v11, p5

    .line 308
    .line 309
    move-object/from16 v12, p6

    .line 310
    .line 311
    :goto_8
    invoke-virtual {v4}, Ll2/t;->s()Ll2/u1;

    .line 312
    .line 313
    .line 314
    move-result-object v0

    .line 315
    if-eqz v0, :cond_c

    .line 316
    .line 317
    new-instance v5, Lf2/a;

    .line 318
    .line 319
    move-object/from16 v8, p2

    .line 320
    .line 321
    move-object/from16 v13, p7

    .line 322
    .line 323
    move/from16 v14, p9

    .line 324
    .line 325
    move v6, v7

    .line 326
    move-object/from16 v7, p1

    .line 327
    .line 328
    invoke-direct/range {v5 .. v14}, Lf2/a;-><init>(ZLay0/a;Lx2/s;JLe1/n1;Lx4/w;Lt2/b;I)V

    .line 329
    .line 330
    .line 331
    iput-object v5, v0, Ll2/u1;->d:Lay0/n;

    .line 332
    .line 333
    :cond_c
    return-void
.end method

.method public static final b(Lay0/a;Lx2/s;ZLk1/z0;Lt2/b;Ll2/o;II)V
    .locals 14

    .line 1
    move-object/from16 v4, p5

    .line 2
    .line 3
    check-cast v4, Ll2/t;

    .line 4
    .line 5
    const v0, 0x27f7a2e1

    .line 6
    .line 7
    .line 8
    invoke-virtual {v4, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 9
    .line 10
    .line 11
    invoke-virtual {v4, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    if-eqz v1, :cond_0

    .line 16
    .line 17
    const/4 v1, 0x4

    .line 18
    goto :goto_0

    .line 19
    :cond_0
    const/4 v1, 0x2

    .line 20
    :goto_0
    or-int v1, p6, v1

    .line 21
    .line 22
    and-int/lit8 v2, p7, 0x2

    .line 23
    .line 24
    if-eqz v2, :cond_1

    .line 25
    .line 26
    or-int/lit8 v1, v1, 0x30

    .line 27
    .line 28
    goto :goto_2

    .line 29
    :cond_1
    invoke-virtual {v4, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 30
    .line 31
    .line 32
    move-result v5

    .line 33
    if-eqz v5, :cond_2

    .line 34
    .line 35
    const/16 v5, 0x20

    .line 36
    .line 37
    goto :goto_1

    .line 38
    :cond_2
    const/16 v5, 0x10

    .line 39
    .line 40
    :goto_1
    or-int/2addr v1, v5

    .line 41
    :goto_2
    or-int/lit16 v1, v1, 0x6d80

    .line 42
    .line 43
    const v5, 0x12493

    .line 44
    .line 45
    .line 46
    and-int/2addr v5, v1

    .line 47
    const v6, 0x12492

    .line 48
    .line 49
    .line 50
    const/4 v7, 0x1

    .line 51
    if-eq v5, v6, :cond_3

    .line 52
    .line 53
    move v5, v7

    .line 54
    goto :goto_3

    .line 55
    :cond_3
    const/4 v5, 0x0

    .line 56
    :goto_3
    and-int/lit8 v6, v1, 0x1

    .line 57
    .line 58
    invoke-virtual {v4, v6, v5}, Ll2/t;->O(IZ)Z

    .line 59
    .line 60
    .line 61
    move-result v5

    .line 62
    if-eqz v5, :cond_5

    .line 63
    .line 64
    if-eqz v2, :cond_4

    .line 65
    .line 66
    sget-object v2, Lx2/p;->b:Lx2/p;

    .line 67
    .line 68
    move-object v13, v2

    .line 69
    move v2, v1

    .line 70
    move-object v1, v13

    .line 71
    goto :goto_4

    .line 72
    :cond_4
    move v2, v1

    .line 73
    move-object v1, p1

    .line 74
    :goto_4
    sget-object v3, Lf2/a0;->a:Lk1/a1;

    .line 75
    .line 76
    const v5, 0x7fffe

    .line 77
    .line 78
    .line 79
    and-int/2addr v5, v2

    .line 80
    move-object v0, p0

    .line 81
    move-object v2, v3

    .line 82
    move-object/from16 v3, p4

    .line 83
    .line 84
    invoke-static/range {v0 .. v5}, Lf2/d0;->b(Lay0/a;Lx2/s;Lk1/z0;Lt2/b;Ll2/o;I)V

    .line 85
    .line 86
    .line 87
    move-object v9, v2

    .line 88
    move v8, v7

    .line 89
    move-object v7, v1

    .line 90
    goto :goto_5

    .line 91
    :cond_5
    invoke-virtual {v4}, Ll2/t;->R()V

    .line 92
    .line 93
    .line 94
    move-object v7, p1

    .line 95
    move/from16 v8, p2

    .line 96
    .line 97
    move-object/from16 v9, p3

    .line 98
    .line 99
    :goto_5
    invoke-virtual {v4}, Ll2/t;->s()Ll2/u1;

    .line 100
    .line 101
    .line 102
    move-result-object v0

    .line 103
    if-eqz v0, :cond_6

    .line 104
    .line 105
    new-instance v5, Ld80/k;

    .line 106
    .line 107
    move-object v6, p0

    .line 108
    move-object/from16 v10, p4

    .line 109
    .line 110
    move/from16 v11, p6

    .line 111
    .line 112
    move/from16 v12, p7

    .line 113
    .line 114
    invoke-direct/range {v5 .. v12}, Ld80/k;-><init>(Lay0/a;Lx2/s;ZLk1/z0;Lt2/b;II)V

    .line 115
    .line 116
    .line 117
    iput-object v5, v0, Ll2/u1;->d:Lay0/n;

    .line 118
    .line 119
    :cond_6
    return-void
.end method
