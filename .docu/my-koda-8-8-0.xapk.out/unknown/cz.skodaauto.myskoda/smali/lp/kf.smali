.class public abstract Llp/kf;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Ljava/util/List;Lxh/e;Lay0/k;Lyj/b;Lxh/e;Lbd/a;Ll2/o;I)V
    .locals 10

    .line 1
    const-string v0, "exportFilters"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "defaultTab"

    .line 7
    .line 8
    invoke-static {p5, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    move-object/from16 v0, p6

    .line 12
    .line 13
    check-cast v0, Ll2/t;

    .line 14
    .line 15
    const v1, 0x3727ded9    # 1.0005861E-5f

    .line 16
    .line 17
    .line 18
    invoke-virtual {v0, v1}, Ll2/t;->a0(I)Ll2/t;

    .line 19
    .line 20
    .line 21
    invoke-virtual {v0, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    move-result v1

    .line 25
    if-eqz v1, :cond_0

    .line 26
    .line 27
    const/4 v1, 0x4

    .line 28
    goto :goto_0

    .line 29
    :cond_0
    const/4 v1, 0x2

    .line 30
    :goto_0
    or-int v1, p7, v1

    .line 31
    .line 32
    invoke-virtual {v0, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 33
    .line 34
    .line 35
    move-result v2

    .line 36
    if-eqz v2, :cond_1

    .line 37
    .line 38
    const/16 v2, 0x20

    .line 39
    .line 40
    goto :goto_1

    .line 41
    :cond_1
    const/16 v2, 0x10

    .line 42
    .line 43
    :goto_1
    or-int/2addr v1, v2

    .line 44
    invoke-virtual {v0, p3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 45
    .line 46
    .line 47
    move-result v2

    .line 48
    if-eqz v2, :cond_2

    .line 49
    .line 50
    const/16 v2, 0x800

    .line 51
    .line 52
    goto :goto_2

    .line 53
    :cond_2
    const/16 v2, 0x400

    .line 54
    .line 55
    :goto_2
    or-int/2addr v1, v2

    .line 56
    invoke-virtual {v0, p4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 57
    .line 58
    .line 59
    move-result v2

    .line 60
    if-eqz v2, :cond_3

    .line 61
    .line 62
    const/16 v2, 0x4000

    .line 63
    .line 64
    goto :goto_3

    .line 65
    :cond_3
    const/16 v2, 0x2000

    .line 66
    .line 67
    :goto_3
    or-int/2addr v1, v2

    .line 68
    invoke-virtual {p5}, Ljava/lang/Enum;->ordinal()I

    .line 69
    .line 70
    .line 71
    move-result v2

    .line 72
    invoke-virtual {v0, v2}, Ll2/t;->e(I)Z

    .line 73
    .line 74
    .line 75
    move-result v2

    .line 76
    if-eqz v2, :cond_4

    .line 77
    .line 78
    const/high16 v2, 0x20000

    .line 79
    .line 80
    goto :goto_4

    .line 81
    :cond_4
    const/high16 v2, 0x10000

    .line 82
    .line 83
    :goto_4
    or-int/2addr v1, v2

    .line 84
    const v2, 0x12493

    .line 85
    .line 86
    .line 87
    and-int/2addr v2, v1

    .line 88
    const v3, 0x12492

    .line 89
    .line 90
    .line 91
    const/4 v4, 0x0

    .line 92
    const/4 v5, 0x1

    .line 93
    if-eq v2, v3, :cond_5

    .line 94
    .line 95
    move v2, v5

    .line 96
    goto :goto_5

    .line 97
    :cond_5
    move v2, v4

    .line 98
    :goto_5
    and-int/2addr v1, v5

    .line 99
    invoke-virtual {v0, v1, v2}, Ll2/t;->O(IZ)Z

    .line 100
    .line 101
    .line 102
    move-result v1

    .line 103
    if-eqz v1, :cond_6

    .line 104
    .line 105
    new-array v8, v4, [Ll2/t1;

    .line 106
    .line 107
    new-instance v1, Lld/b;

    .line 108
    .line 109
    move-object v2, p0

    .line 110
    move-object v3, p1

    .line 111
    move-object v4, p2

    .line 112
    move-object v5, p3

    .line 113
    move-object v6, p4

    .line 114
    move-object v7, p5

    .line 115
    invoke-direct/range {v1 .. v7}, Lld/b;-><init>(Ljava/util/List;Lxh/e;Lay0/k;Lyj/b;Lxh/e;Lbd/a;)V

    .line 116
    .line 117
    .line 118
    const v2, -0x753f5de7

    .line 119
    .line 120
    .line 121
    invoke-static {v2, v0, v1}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 122
    .line 123
    .line 124
    move-result-object v1

    .line 125
    const/16 v2, 0x30

    .line 126
    .line 127
    invoke-static {v8, v1, v0, v2}, Ll2/b;->b([Ll2/t1;Lay0/n;Ll2/o;I)V

    .line 128
    .line 129
    .line 130
    goto :goto_6

    .line 131
    :cond_6
    invoke-virtual {v0}, Ll2/t;->R()V

    .line 132
    .line 133
    .line 134
    :goto_6
    invoke-virtual {v0}, Ll2/t;->s()Ll2/u1;

    .line 135
    .line 136
    .line 137
    move-result-object v0

    .line 138
    if-eqz v0, :cond_7

    .line 139
    .line 140
    new-instance v1, Lld/b;

    .line 141
    .line 142
    const/4 v9, 0x1

    .line 143
    move-object v2, p0

    .line 144
    move-object v3, p1

    .line 145
    move-object v4, p2

    .line 146
    move-object v5, p3

    .line 147
    move-object v6, p4

    .line 148
    move-object v7, p5

    .line 149
    move/from16 v8, p7

    .line 150
    .line 151
    invoke-direct/range {v1 .. v9}, Lld/b;-><init>(Ljava/util/List;Lxh/e;Lay0/k;Lyj/b;Lxh/e;Lbd/a;II)V

    .line 152
    .line 153
    .line 154
    iput-object v1, v0, Ll2/u1;->d:Lay0/n;

    .line 155
    .line 156
    :cond_7
    return-void
.end method

.method public static final b(Ljava/util/List;Lxh/e;Lay0/k;Lyj/b;Lxh/e;Lbd/a;Ll2/o;I)V
    .locals 27

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v7, p1

    .line 4
    .line 5
    move-object/from16 v8, p2

    .line 6
    .line 7
    move-object/from16 v9, p3

    .line 8
    .line 9
    move-object/from16 v10, p4

    .line 10
    .line 11
    move-object/from16 v0, p6

    .line 12
    .line 13
    check-cast v0, Ll2/t;

    .line 14
    .line 15
    const v2, -0x3cd8d9df

    .line 16
    .line 17
    .line 18
    invoke-virtual {v0, v2}, Ll2/t;->a0(I)Ll2/t;

    .line 19
    .line 20
    .line 21
    invoke-virtual {v0, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    move-result v2

    .line 25
    if-eqz v2, :cond_0

    .line 26
    .line 27
    const/4 v2, 0x4

    .line 28
    goto :goto_0

    .line 29
    :cond_0
    const/4 v2, 0x2

    .line 30
    :goto_0
    or-int v2, p7, v2

    .line 31
    .line 32
    invoke-virtual {v0, v7}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 33
    .line 34
    .line 35
    move-result v3

    .line 36
    if-eqz v3, :cond_1

    .line 37
    .line 38
    const/16 v3, 0x20

    .line 39
    .line 40
    goto :goto_1

    .line 41
    :cond_1
    const/16 v3, 0x10

    .line 42
    .line 43
    :goto_1
    or-int/2addr v2, v3

    .line 44
    invoke-virtual {v0, v8}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 45
    .line 46
    .line 47
    move-result v3

    .line 48
    if-eqz v3, :cond_2

    .line 49
    .line 50
    const/16 v3, 0x100

    .line 51
    .line 52
    goto :goto_2

    .line 53
    :cond_2
    const/16 v3, 0x80

    .line 54
    .line 55
    :goto_2
    or-int/2addr v2, v3

    .line 56
    invoke-virtual {v0, v9}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 57
    .line 58
    .line 59
    move-result v3

    .line 60
    if-eqz v3, :cond_3

    .line 61
    .line 62
    const/16 v3, 0x800

    .line 63
    .line 64
    goto :goto_3

    .line 65
    :cond_3
    const/16 v3, 0x400

    .line 66
    .line 67
    :goto_3
    or-int/2addr v2, v3

    .line 68
    invoke-virtual {v0, v10}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 69
    .line 70
    .line 71
    move-result v3

    .line 72
    if-eqz v3, :cond_4

    .line 73
    .line 74
    const/16 v3, 0x4000

    .line 75
    .line 76
    goto :goto_4

    .line 77
    :cond_4
    const/16 v3, 0x2000

    .line 78
    .line 79
    :goto_4
    or-int/2addr v2, v3

    .line 80
    invoke-virtual/range {p5 .. p5}, Ljava/lang/Enum;->ordinal()I

    .line 81
    .line 82
    .line 83
    move-result v3

    .line 84
    invoke-virtual {v0, v3}, Ll2/t;->e(I)Z

    .line 85
    .line 86
    .line 87
    move-result v3

    .line 88
    const/high16 v4, 0x20000

    .line 89
    .line 90
    if-eqz v3, :cond_5

    .line 91
    .line 92
    move v3, v4

    .line 93
    goto :goto_5

    .line 94
    :cond_5
    const/high16 v3, 0x10000

    .line 95
    .line 96
    :goto_5
    or-int/2addr v2, v3

    .line 97
    const v3, 0x12493

    .line 98
    .line 99
    .line 100
    and-int/2addr v3, v2

    .line 101
    const v5, 0x12492

    .line 102
    .line 103
    .line 104
    const/4 v6, 0x0

    .line 105
    if-eq v3, v5, :cond_6

    .line 106
    .line 107
    const/4 v3, 0x1

    .line 108
    goto :goto_6

    .line 109
    :cond_6
    move v3, v6

    .line 110
    :goto_6
    and-int/lit8 v5, v2, 0x1

    .line 111
    .line 112
    invoke-virtual {v0, v5, v3}, Ll2/t;->O(IZ)Z

    .line 113
    .line 114
    .line 115
    move-result v3

    .line 116
    if-eqz v3, :cond_14

    .line 117
    .line 118
    sget-object v3, Lk1/j;->c:Lk1/e;

    .line 119
    .line 120
    sget-object v5, Lx2/c;->p:Lx2/h;

    .line 121
    .line 122
    invoke-static {v3, v5, v0, v6}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 123
    .line 124
    .line 125
    move-result-object v3

    .line 126
    iget-wide v12, v0, Ll2/t;->T:J

    .line 127
    .line 128
    invoke-static {v12, v13}, Ljava/lang/Long;->hashCode(J)I

    .line 129
    .line 130
    .line 131
    move-result v5

    .line 132
    invoke-virtual {v0}, Ll2/t;->m()Ll2/p1;

    .line 133
    .line 134
    .line 135
    move-result-object v12

    .line 136
    sget-object v13, Lx2/p;->b:Lx2/p;

    .line 137
    .line 138
    invoke-static {v0, v13}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 139
    .line 140
    .line 141
    move-result-object v13

    .line 142
    sget-object v14, Lv3/k;->m1:Lv3/j;

    .line 143
    .line 144
    invoke-virtual {v14}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 145
    .line 146
    .line 147
    sget-object v14, Lv3/j;->b:Lv3/i;

    .line 148
    .line 149
    invoke-virtual {v0}, Ll2/t;->c0()V

    .line 150
    .line 151
    .line 152
    iget-boolean v15, v0, Ll2/t;->S:Z

    .line 153
    .line 154
    if-eqz v15, :cond_7

    .line 155
    .line 156
    invoke-virtual {v0, v14}, Ll2/t;->l(Lay0/a;)V

    .line 157
    .line 158
    .line 159
    goto :goto_7

    .line 160
    :cond_7
    invoke-virtual {v0}, Ll2/t;->m0()V

    .line 161
    .line 162
    .line 163
    :goto_7
    sget-object v14, Lv3/j;->g:Lv3/h;

    .line 164
    .line 165
    invoke-static {v14, v3, v0}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 166
    .line 167
    .line 168
    sget-object v3, Lv3/j;->f:Lv3/h;

    .line 169
    .line 170
    invoke-static {v3, v12, v0}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 171
    .line 172
    .line 173
    sget-object v3, Lv3/j;->j:Lv3/h;

    .line 174
    .line 175
    iget-boolean v12, v0, Ll2/t;->S:Z

    .line 176
    .line 177
    if-nez v12, :cond_8

    .line 178
    .line 179
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 180
    .line 181
    .line 182
    move-result-object v12

    .line 183
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 184
    .line 185
    .line 186
    move-result-object v14

    .line 187
    invoke-static {v12, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 188
    .line 189
    .line 190
    move-result v12

    .line 191
    if-nez v12, :cond_9

    .line 192
    .line 193
    :cond_8
    invoke-static {v5, v0, v5, v3}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 194
    .line 195
    .line 196
    :cond_9
    sget-object v3, Lv3/j;->d:Lv3/h;

    .line 197
    .line 198
    invoke-static {v3, v13, v0}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 199
    .line 200
    .line 201
    invoke-virtual {v0, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 202
    .line 203
    .line 204
    move-result v3

    .line 205
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 206
    .line 207
    .line 208
    move-result-object v5

    .line 209
    sget-object v12, Ll2/n;->a:Ll2/x0;

    .line 210
    .line 211
    if-nez v3, :cond_a

    .line 212
    .line 213
    if-ne v5, v12, :cond_b

    .line 214
    .line 215
    :cond_a
    new-instance v5, Ld01/v;

    .line 216
    .line 217
    const/4 v3, 0x4

    .line 218
    invoke-direct {v5, v1, v3}, Ld01/v;-><init>(Ljava/util/List;I)V

    .line 219
    .line 220
    .line 221
    invoke-virtual {v0, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 222
    .line 223
    .line 224
    :cond_b
    check-cast v5, Lay0/a;

    .line 225
    .line 226
    const/4 v3, 0x3

    .line 227
    invoke-static {v6, v5, v0, v6, v3}, Lp1/y;->b(ILay0/a;Ll2/o;II)Lp1/b;

    .line 228
    .line 229
    .line 230
    move-result-object v3

    .line 231
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 232
    .line 233
    .line 234
    move-result-object v5

    .line 235
    if-ne v5, v12, :cond_c

    .line 236
    .line 237
    invoke-static {v0}, Ll2/l0;->h(Ll2/o;)Lvy0/b0;

    .line 238
    .line 239
    .line 240
    move-result-object v5

    .line 241
    invoke-virtual {v0, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 242
    .line 243
    .line 244
    :cond_c
    check-cast v5, Lvy0/b0;

    .line 245
    .line 246
    invoke-virtual {v0, v5}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 247
    .line 248
    .line 249
    move-result v13

    .line 250
    invoke-virtual {v0, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 251
    .line 252
    .line 253
    move-result v14

    .line 254
    or-int/2addr v13, v14

    .line 255
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 256
    .line 257
    .line 258
    move-result-object v14

    .line 259
    if-nez v13, :cond_d

    .line 260
    .line 261
    if-ne v14, v12, :cond_e

    .line 262
    .line 263
    :cond_d
    new-instance v14, Ll2/v1;

    .line 264
    .line 265
    const/4 v13, 0x2

    .line 266
    invoke-direct {v14, v13, v5, v3}, Ll2/v1;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 267
    .line 268
    .line 269
    invoke-virtual {v0, v14}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 270
    .line 271
    .line 272
    :cond_e
    check-cast v14, Lay0/k;

    .line 273
    .line 274
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 275
    .line 276
    .line 277
    move-result-object v13

    .line 278
    if-ne v13, v12, :cond_f

    .line 279
    .line 280
    new-instance v13, Lfd/d;

    .line 281
    .line 282
    invoke-direct {v13, v1, v3, v14}, Lfd/d;-><init>(Ljava/util/List;Lp1/b;Lay0/k;)V

    .line 283
    .line 284
    .line 285
    invoke-virtual {v0, v13}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 286
    .line 287
    .line 288
    :cond_f
    check-cast v13, Lfd/d;

    .line 289
    .line 290
    sget-object v14, Lzb/x;->b:Ll2/u2;

    .line 291
    .line 292
    invoke-virtual {v0, v14}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 293
    .line 294
    .line 295
    move-result-object v14

    .line 296
    const-string v15, "null cannot be cast to non-null type cariad.charging.multicharge.kitten.charginghistory.presentation.ChargingHistoryOverviewUi"

    .line 297
    .line 298
    invoke-static {v14, v15}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 299
    .line 300
    .line 301
    check-cast v14, Lfd/a;

    .line 302
    .line 303
    new-instance v15, Lb6/f;

    .line 304
    .line 305
    invoke-virtual {v3}, Lp1/v;->k()I

    .line 306
    .line 307
    .line 308
    move-result v6

    .line 309
    invoke-interface {v1, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 310
    .line 311
    .line 312
    move-result-object v6

    .line 313
    sget-object v11, Lbd/a;->e:Lbd/a;

    .line 314
    .line 315
    if-ne v6, v11, :cond_10

    .line 316
    .line 317
    const/4 v6, 0x1

    .line 318
    goto :goto_8

    .line 319
    :cond_10
    const/4 v6, 0x0

    .line 320
    :goto_8
    invoke-direct {v15, v9, v6}, Lb6/f;-><init>(Ljava/lang/Object;Z)V

    .line 321
    .line 322
    .line 323
    const/4 v6, 0x6

    .line 324
    invoke-interface {v14, v13, v15, v0, v6}, Lfd/a;->i(Lfd/d;Lb6/f;Ll2/o;I)V

    .line 325
    .line 326
    .line 327
    new-instance v6, Leh/j;

    .line 328
    .line 329
    invoke-direct {v6, v1, v10, v7, v8}, Leh/j;-><init>(Ljava/util/List;Lxh/e;Lxh/e;Lay0/k;)V

    .line 330
    .line 331
    .line 332
    const v11, -0x7ee05836

    .line 333
    .line 334
    .line 335
    invoke-static {v11, v0, v6}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 336
    .line 337
    .line 338
    move-result-object v22

    .line 339
    move-object v6, v12

    .line 340
    const/high16 v12, 0x6000000

    .line 341
    .line 342
    const/16 v13, 0x3efe

    .line 343
    .line 344
    const/4 v11, 0x0

    .line 345
    const/4 v14, 0x0

    .line 346
    const/4 v15, 0x0

    .line 347
    const/16 v17, 0x1

    .line 348
    .line 349
    const/16 v16, 0x0

    .line 350
    .line 351
    move/from16 v18, v17

    .line 352
    .line 353
    const/16 v17, 0x0

    .line 354
    .line 355
    const/16 v19, 0x0

    .line 356
    .line 357
    const/16 v20, 0x0

    .line 358
    .line 359
    const/16 v23, 0x0

    .line 360
    .line 361
    const/16 v24, 0x0

    .line 362
    .line 363
    const/16 v25, 0x0

    .line 364
    .line 365
    const/16 v26, 0x0

    .line 366
    .line 367
    move/from16 v21, v18

    .line 368
    .line 369
    move-object/from16 v18, v0

    .line 370
    .line 371
    move/from16 v0, v21

    .line 372
    .line 373
    move-object/from16 v21, v3

    .line 374
    .line 375
    invoke-static/range {v11 .. v26}, Ljp/ad;->b(FIILe1/j;Lh1/g;Lh1/n;Lk1/z0;Ll2/o;Lo3/a;Lp1/f;Lp1/v;Lt2/b;Lx2/i;Lx2/s;ZZ)V

    .line 376
    .line 377
    .line 378
    move-object/from16 v11, v18

    .line 379
    .line 380
    const/high16 v12, 0x70000

    .line 381
    .line 382
    and-int/2addr v2, v12

    .line 383
    if-ne v2, v4, :cond_11

    .line 384
    .line 385
    move v2, v0

    .line 386
    goto :goto_9

    .line 387
    :cond_11
    const/4 v2, 0x0

    .line 388
    :goto_9
    invoke-virtual {v11, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 389
    .line 390
    .line 391
    move-result v4

    .line 392
    or-int/2addr v2, v4

    .line 393
    invoke-virtual {v11, v5}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 394
    .line 395
    .line 396
    move-result v4

    .line 397
    or-int/2addr v2, v4

    .line 398
    invoke-virtual {v11, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 399
    .line 400
    .line 401
    move-result v4

    .line 402
    or-int/2addr v2, v4

    .line 403
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 404
    .line 405
    .line 406
    move-result-object v4

    .line 407
    if-nez v2, :cond_12

    .line 408
    .line 409
    if-ne v4, v6, :cond_13

    .line 410
    .line 411
    :cond_12
    move/from16 v16, v0

    .line 412
    .line 413
    goto :goto_a

    .line 414
    :cond_13
    move v12, v0

    .line 415
    goto :goto_b

    .line 416
    :goto_a
    new-instance v0, Lff/a;

    .line 417
    .line 418
    move-object v4, v3

    .line 419
    move-object v3, v5

    .line 420
    const/4 v5, 0x0

    .line 421
    const/4 v6, 0x2

    .line 422
    move-object v2, v1

    .line 423
    move/from16 v12, v16

    .line 424
    .line 425
    move-object/from16 v1, p5

    .line 426
    .line 427
    invoke-direct/range {v0 .. v6}, Lff/a;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 428
    .line 429
    .line 430
    invoke-virtual {v11, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 431
    .line 432
    .line 433
    move-object v4, v0

    .line 434
    :goto_b
    check-cast v4, Lay0/n;

    .line 435
    .line 436
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 437
    .line 438
    invoke-static {v4, v0, v11}, Ll2/l0;->d(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 439
    .line 440
    .line 441
    invoke-virtual {v11, v12}, Ll2/t;->q(Z)V

    .line 442
    .line 443
    .line 444
    goto :goto_c

    .line 445
    :cond_14
    move-object v11, v0

    .line 446
    invoke-virtual {v11}, Ll2/t;->R()V

    .line 447
    .line 448
    .line 449
    :goto_c
    invoke-virtual {v11}, Ll2/t;->s()Ll2/u1;

    .line 450
    .line 451
    .line 452
    move-result-object v11

    .line 453
    if-eqz v11, :cond_15

    .line 454
    .line 455
    new-instance v0, Lld/b;

    .line 456
    .line 457
    const/4 v8, 0x2

    .line 458
    move-object/from16 v1, p0

    .line 459
    .line 460
    move-object/from16 v3, p2

    .line 461
    .line 462
    move-object/from16 v6, p5

    .line 463
    .line 464
    move-object v2, v7

    .line 465
    move-object v4, v9

    .line 466
    move-object v5, v10

    .line 467
    move/from16 v7, p7

    .line 468
    .line 469
    invoke-direct/range {v0 .. v8}, Lld/b;-><init>(Ljava/util/List;Lxh/e;Lay0/k;Lyj/b;Lxh/e;Lbd/a;II)V

    .line 470
    .line 471
    .line 472
    iput-object v0, v11, Ll2/u1;->d:Lay0/n;

    .line 473
    .line 474
    :cond_15
    return-void
.end method

.method public static final c(Ljava/util/List;Lxh/e;Lay0/k;Lyj/b;Lxh/e;Ll2/o;I)V
    .locals 9

    .line 1
    check-cast p5, Ll2/t;

    .line 2
    .line 3
    const v0, -0x103aac08

    .line 4
    .line 5
    .line 6
    invoke-virtual {p5, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    invoke-virtual {p5, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    if-eqz v0, :cond_0

    .line 14
    .line 15
    const/4 v0, 0x4

    .line 16
    goto :goto_0

    .line 17
    :cond_0
    const/4 v0, 0x2

    .line 18
    :goto_0
    or-int/2addr v0, p6

    .line 19
    invoke-virtual {p5, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    move-result v1

    .line 23
    if-eqz v1, :cond_1

    .line 24
    .line 25
    const/16 v1, 0x20

    .line 26
    .line 27
    goto :goto_1

    .line 28
    :cond_1
    const/16 v1, 0x10

    .line 29
    .line 30
    :goto_1
    or-int/2addr v0, v1

    .line 31
    invoke-virtual {p5, p2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    move-result v1

    .line 35
    if-eqz v1, :cond_2

    .line 36
    .line 37
    const/16 v1, 0x100

    .line 38
    .line 39
    goto :goto_2

    .line 40
    :cond_2
    const/16 v1, 0x80

    .line 41
    .line 42
    :goto_2
    or-int/2addr v0, v1

    .line 43
    invoke-virtual {p5, p3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 44
    .line 45
    .line 46
    move-result v1

    .line 47
    if-eqz v1, :cond_3

    .line 48
    .line 49
    const/16 v1, 0x800

    .line 50
    .line 51
    goto :goto_3

    .line 52
    :cond_3
    const/16 v1, 0x400

    .line 53
    .line 54
    :goto_3
    or-int/2addr v0, v1

    .line 55
    invoke-virtual {p5, p4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 56
    .line 57
    .line 58
    move-result v1

    .line 59
    if-eqz v1, :cond_4

    .line 60
    .line 61
    const/16 v1, 0x4000

    .line 62
    .line 63
    goto :goto_4

    .line 64
    :cond_4
    const/16 v1, 0x2000

    .line 65
    .line 66
    :goto_4
    or-int/2addr v0, v1

    .line 67
    and-int/lit16 v1, v0, 0x2493

    .line 68
    .line 69
    const/16 v2, 0x2492

    .line 70
    .line 71
    const/4 v3, 0x0

    .line 72
    const/4 v4, 0x1

    .line 73
    if-eq v1, v2, :cond_5

    .line 74
    .line 75
    move v1, v4

    .line 76
    goto :goto_5

    .line 77
    :cond_5
    move v1, v3

    .line 78
    :goto_5
    and-int/lit8 v2, v0, 0x1

    .line 79
    .line 80
    invoke-virtual {p5, v2, v1}, Ll2/t;->O(IZ)Z

    .line 81
    .line 82
    .line 83
    move-result v1

    .line 84
    if-eqz v1, :cond_b

    .line 85
    .line 86
    sget-object v1, Lk1/j;->c:Lk1/e;

    .line 87
    .line 88
    sget-object v2, Lx2/c;->p:Lx2/h;

    .line 89
    .line 90
    invoke-static {v1, v2, p5, v3}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 91
    .line 92
    .line 93
    move-result-object v1

    .line 94
    iget-wide v5, p5, Ll2/t;->T:J

    .line 95
    .line 96
    invoke-static {v5, v6}, Ljava/lang/Long;->hashCode(J)I

    .line 97
    .line 98
    .line 99
    move-result v2

    .line 100
    invoke-virtual {p5}, Ll2/t;->m()Ll2/p1;

    .line 101
    .line 102
    .line 103
    move-result-object v5

    .line 104
    sget-object v6, Lx2/p;->b:Lx2/p;

    .line 105
    .line 106
    invoke-static {p5, v6}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 107
    .line 108
    .line 109
    move-result-object v6

    .line 110
    sget-object v7, Lv3/k;->m1:Lv3/j;

    .line 111
    .line 112
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 113
    .line 114
    .line 115
    sget-object v7, Lv3/j;->b:Lv3/i;

    .line 116
    .line 117
    invoke-virtual {p5}, Ll2/t;->c0()V

    .line 118
    .line 119
    .line 120
    iget-boolean v8, p5, Ll2/t;->S:Z

    .line 121
    .line 122
    if-eqz v8, :cond_6

    .line 123
    .line 124
    invoke-virtual {p5, v7}, Ll2/t;->l(Lay0/a;)V

    .line 125
    .line 126
    .line 127
    goto :goto_6

    .line 128
    :cond_6
    invoke-virtual {p5}, Ll2/t;->m0()V

    .line 129
    .line 130
    .line 131
    :goto_6
    sget-object v7, Lv3/j;->g:Lv3/h;

    .line 132
    .line 133
    invoke-static {v7, v1, p5}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 134
    .line 135
    .line 136
    sget-object v1, Lv3/j;->f:Lv3/h;

    .line 137
    .line 138
    invoke-static {v1, v5, p5}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 139
    .line 140
    .line 141
    sget-object v1, Lv3/j;->j:Lv3/h;

    .line 142
    .line 143
    iget-boolean v5, p5, Ll2/t;->S:Z

    .line 144
    .line 145
    if-nez v5, :cond_7

    .line 146
    .line 147
    invoke-virtual {p5}, Ll2/t;->L()Ljava/lang/Object;

    .line 148
    .line 149
    .line 150
    move-result-object v5

    .line 151
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 152
    .line 153
    .line 154
    move-result-object v7

    .line 155
    invoke-static {v5, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 156
    .line 157
    .line 158
    move-result v5

    .line 159
    if-nez v5, :cond_8

    .line 160
    .line 161
    :cond_7
    invoke-static {v2, p5, v2, v1}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 162
    .line 163
    .line 164
    :cond_8
    sget-object v1, Lv3/j;->d:Lv3/h;

    .line 165
    .line 166
    invoke-static {v1, v6, p5}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 167
    .line 168
    .line 169
    invoke-static {p0}, Lmx0/q;->J(Ljava/util/List;)Ljava/lang/Object;

    .line 170
    .line 171
    .line 172
    move-result-object v1

    .line 173
    check-cast v1, Lbd/a;

    .line 174
    .line 175
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 176
    .line 177
    .line 178
    move-result v1

    .line 179
    const-string v2, "null cannot be cast to non-null type cariad.charging.multicharge.kitten.charginghistory.presentation.ChargingHistoryOverviewUi"

    .line 180
    .line 181
    const/4 v5, 0x0

    .line 182
    if-eqz v1, :cond_a

    .line 183
    .line 184
    if-ne v1, v4, :cond_9

    .line 185
    .line 186
    const v1, 0x7688d5e4

    .line 187
    .line 188
    .line 189
    invoke-virtual {p5, v1}, Ll2/t;->Y(I)V

    .line 190
    .line 191
    .line 192
    sget-object v1, Lzb/x;->b:Ll2/u2;

    .line 193
    .line 194
    invoke-virtual {p5, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 195
    .line 196
    .line 197
    move-result-object v1

    .line 198
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 199
    .line 200
    .line 201
    check-cast v1, Lfd/a;

    .line 202
    .line 203
    new-instance v2, Lb6/f;

    .line 204
    .line 205
    invoke-direct {v2, p3, v4}, Lb6/f;-><init>(Ljava/lang/Object;Z)V

    .line 206
    .line 207
    .line 208
    const/4 v6, 0x6

    .line 209
    invoke-interface {v1, v5, v2, p5, v6}, Lfd/a;->i(Lfd/d;Lb6/f;Ll2/o;I)V

    .line 210
    .line 211
    .line 212
    shr-int/lit8 v0, v0, 0x3

    .line 213
    .line 214
    and-int/lit8 v0, v0, 0x7e

    .line 215
    .line 216
    invoke-static {p1, p2, p5, v0}, Llp/kd;->a(Lxh/e;Lay0/k;Ll2/o;I)V

    .line 217
    .line 218
    .line 219
    invoke-virtual {p5, v3}, Ll2/t;->q(Z)V

    .line 220
    .line 221
    .line 222
    goto :goto_7

    .line 223
    :cond_9
    const p0, -0x780c4499

    .line 224
    .line 225
    .line 226
    invoke-static {p0, p5, v3}, Lf2/m0;->b(ILl2/t;Z)La8/r0;

    .line 227
    .line 228
    .line 229
    move-result-object p0

    .line 230
    throw p0

    .line 231
    :cond_a
    const v1, 0x76849390

    .line 232
    .line 233
    .line 234
    invoke-virtual {p5, v1}, Ll2/t;->Y(I)V

    .line 235
    .line 236
    .line 237
    sget-object v1, Lzb/x;->b:Ll2/u2;

    .line 238
    .line 239
    invoke-virtual {p5, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 240
    .line 241
    .line 242
    move-result-object v1

    .line 243
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 244
    .line 245
    .line 246
    check-cast v1, Lfd/a;

    .line 247
    .line 248
    const/16 v2, 0x36

    .line 249
    .line 250
    invoke-interface {v1, v5, v5, p5, v2}, Lfd/a;->i(Lfd/d;Lb6/f;Ll2/o;I)V

    .line 251
    .line 252
    .line 253
    shr-int/lit8 v0, v0, 0xc

    .line 254
    .line 255
    and-int/lit8 v0, v0, 0xe

    .line 256
    .line 257
    invoke-static {p4, p5, v0}, Ljp/ja;->c(Lxh/e;Ll2/o;I)V

    .line 258
    .line 259
    .line 260
    invoke-virtual {p5, v3}, Ll2/t;->q(Z)V

    .line 261
    .line 262
    .line 263
    :goto_7
    invoke-virtual {p5, v4}, Ll2/t;->q(Z)V

    .line 264
    .line 265
    .line 266
    goto :goto_8

    .line 267
    :cond_b
    invoke-virtual {p5}, Ll2/t;->R()V

    .line 268
    .line 269
    .line 270
    :goto_8
    invoke-virtual {p5}, Ll2/t;->s()Ll2/u1;

    .line 271
    .line 272
    .line 273
    move-result-object p5

    .line 274
    if-eqz p5, :cond_c

    .line 275
    .line 276
    new-instance v0, Lb10/c;

    .line 277
    .line 278
    const/16 v7, 0x16

    .line 279
    .line 280
    move-object v1, p0

    .line 281
    move-object v2, p1

    .line 282
    move-object v3, p2

    .line 283
    move-object v4, p3

    .line 284
    move-object v5, p4

    .line 285
    move v6, p6

    .line 286
    invoke-direct/range {v0 .. v7}, Lb10/c;-><init>(Ljava/lang/Object;Ljava/lang/Object;Lay0/k;Llx0/e;Lay0/k;II)V

    .line 287
    .line 288
    .line 289
    iput-object v0, p5, Ll2/u1;->d:Lay0/n;

    .line 290
    .line 291
    :cond_c
    return-void
.end method

.method public static final d(Lxy0/z;Ljava/lang/Throwable;)V
    .locals 1

    .line 1
    instance-of v0, p1, Ljava/util/concurrent/CancellationException;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Ljava/util/concurrent/CancellationException;

    .line 7
    .line 8
    goto :goto_0

    .line 9
    :cond_0
    const/4 v0, 0x0

    .line 10
    :goto_0
    if-nez v0, :cond_1

    .line 11
    .line 12
    const-string v0, "Channel was consumed, consumer had failed"

    .line 13
    .line 14
    invoke-static {v0, p1}, Lvy0/e0;->a(Ljava/lang/String;Ljava/lang/Throwable;)Ljava/util/concurrent/CancellationException;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    :cond_1
    invoke-interface {p0, v0}, Lxy0/z;->d(Ljava/util/concurrent/CancellationException;)V

    .line 19
    .line 20
    .line 21
    return-void
.end method
