.class public abstract Llp/dc;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lx2/s;Lvv/n0;Lxf0/b2;Lay0/o;Ll2/o;II)V
    .locals 12

    .line 1
    move/from16 v5, p5

    .line 2
    .line 3
    const-string v0, "children"

    .line 4
    .line 5
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    move-object/from16 v0, p4

    .line 9
    .line 10
    check-cast v0, Ll2/t;

    .line 11
    .line 12
    const v1, -0x25b76e80

    .line 13
    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ll2/t;->a0(I)Ll2/t;

    .line 16
    .line 17
    .line 18
    and-int/lit8 v1, p6, 0x1

    .line 19
    .line 20
    if-eqz v1, :cond_0

    .line 21
    .line 22
    or-int/lit8 v2, v5, 0x6

    .line 23
    .line 24
    goto :goto_1

    .line 25
    :cond_0
    and-int/lit8 v2, v5, 0xe

    .line 26
    .line 27
    if-nez v2, :cond_2

    .line 28
    .line 29
    invoke-virtual {v0, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 30
    .line 31
    .line 32
    move-result v2

    .line 33
    if-eqz v2, :cond_1

    .line 34
    .line 35
    const/4 v2, 0x4

    .line 36
    goto :goto_0

    .line 37
    :cond_1
    const/4 v2, 0x2

    .line 38
    :goto_0
    or-int/2addr v2, v5

    .line 39
    goto :goto_1

    .line 40
    :cond_2
    move v2, v5

    .line 41
    :goto_1
    and-int/lit8 v3, p6, 0x2

    .line 42
    .line 43
    if-eqz v3, :cond_3

    .line 44
    .line 45
    or-int/lit8 v2, v2, 0x30

    .line 46
    .line 47
    goto :goto_3

    .line 48
    :cond_3
    and-int/lit8 v4, v5, 0x70

    .line 49
    .line 50
    if-nez v4, :cond_5

    .line 51
    .line 52
    invoke-virtual {v0, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 53
    .line 54
    .line 55
    move-result v4

    .line 56
    if-eqz v4, :cond_4

    .line 57
    .line 58
    const/16 v4, 0x20

    .line 59
    .line 60
    goto :goto_2

    .line 61
    :cond_4
    const/16 v4, 0x10

    .line 62
    .line 63
    :goto_2
    or-int/2addr v2, v4

    .line 64
    :cond_5
    :goto_3
    and-int/lit8 v4, p6, 0x4

    .line 65
    .line 66
    if-eqz v4, :cond_6

    .line 67
    .line 68
    or-int/lit16 v2, v2, 0x180

    .line 69
    .line 70
    goto :goto_5

    .line 71
    :cond_6
    and-int/lit16 v6, v5, 0x380

    .line 72
    .line 73
    if-nez v6, :cond_8

    .line 74
    .line 75
    invoke-virtual {v0, p2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 76
    .line 77
    .line 78
    move-result v6

    .line 79
    if-eqz v6, :cond_7

    .line 80
    .line 81
    const/16 v6, 0x100

    .line 82
    .line 83
    goto :goto_4

    .line 84
    :cond_7
    const/16 v6, 0x80

    .line 85
    .line 86
    :goto_4
    or-int/2addr v2, v6

    .line 87
    :cond_8
    :goto_5
    and-int/lit16 v6, v5, 0x1c00

    .line 88
    .line 89
    if-nez v6, :cond_a

    .line 90
    .line 91
    invoke-virtual {v0, p3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 92
    .line 93
    .line 94
    move-result v6

    .line 95
    if-eqz v6, :cond_9

    .line 96
    .line 97
    const/16 v6, 0x800

    .line 98
    .line 99
    goto :goto_6

    .line 100
    :cond_9
    const/16 v6, 0x400

    .line 101
    .line 102
    :goto_6
    or-int/2addr v2, v6

    .line 103
    :cond_a
    and-int/lit16 v2, v2, 0x16db

    .line 104
    .line 105
    const/16 v6, 0x492

    .line 106
    .line 107
    if-ne v2, v6, :cond_c

    .line 108
    .line 109
    invoke-virtual {v0}, Ll2/t;->A()Z

    .line 110
    .line 111
    .line 112
    move-result v2

    .line 113
    if-nez v2, :cond_b

    .line 114
    .line 115
    goto :goto_7

    .line 116
    :cond_b
    invoke-virtual {v0}, Ll2/t;->R()V

    .line 117
    .line 118
    .line 119
    move-object v1, p0

    .line 120
    move-object v2, p1

    .line 121
    move-object v3, p2

    .line 122
    goto :goto_a

    .line 123
    :cond_c
    :goto_7
    if-eqz v1, :cond_d

    .line 124
    .line 125
    sget-object p0, Lx2/p;->b:Lx2/p;

    .line 126
    .line 127
    :cond_d
    move-object v9, p0

    .line 128
    const/4 p0, 0x0

    .line 129
    if-eqz v3, :cond_e

    .line 130
    .line 131
    move-object v7, p0

    .line 132
    goto :goto_8

    .line 133
    :cond_e
    move-object v7, p1

    .line 134
    :goto_8
    if-eqz v4, :cond_f

    .line 135
    .line 136
    move-object v8, p0

    .line 137
    goto :goto_9

    .line 138
    :cond_f
    move-object v8, p2

    .line 139
    :goto_9
    new-instance v6, Lb1/g0;

    .line 140
    .line 141
    const/4 v11, 0x2

    .line 142
    move-object v10, p3

    .line 143
    invoke-direct/range {v6 .. v11}, Lb1/g0;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 144
    .line 145
    .line 146
    const p0, 0x6a067995

    .line 147
    .line 148
    .line 149
    invoke-static {p0, v0, v6}, Lt2/c;->b(ILl2/o;Llx0/e;)Lt2/b;

    .line 150
    .line 151
    .line 152
    move-result-object p0

    .line 153
    const/4 p1, 0x6

    .line 154
    invoke-static {p0, v0, p1}, Lvv/x;->c(Lt2/b;Ll2/o;I)V

    .line 155
    .line 156
    .line 157
    move-object v2, v7

    .line 158
    move-object v3, v8

    .line 159
    move-object v1, v9

    .line 160
    :goto_a
    invoke-virtual {v0}, Ll2/t;->s()Ll2/u1;

    .line 161
    .line 162
    .line 163
    move-result-object p0

    .line 164
    if-eqz p0, :cond_10

    .line 165
    .line 166
    new-instance v0, Lvv/a;

    .line 167
    .line 168
    const/4 v7, 0x0

    .line 169
    move-object v4, p3

    .line 170
    move/from16 v6, p6

    .line 171
    .line 172
    invoke-direct/range {v0 .. v7}, Lvv/a;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lay0/o;III)V

    .line 173
    .line 174
    .line 175
    iput-object v0, p0, Ll2/u1;->d:Lay0/n;

    .line 176
    .line 177
    :cond_10
    return-void
.end method

.method public static final b(Lx2/s;Lay0/k;Ljava/lang/Integer;Lay0/k;JLjava/util/List;Lg4/p0;Ll2/o;I)V
    .locals 25

    .line 1
    move-object/from16 v3, p2

    .line 2
    .line 3
    move-object/from16 v7, p6

    .line 4
    .line 5
    const/4 v12, 0x0

    .line 6
    invoke-static {v12}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 7
    .line 8
    .line 9
    move-result-object v13

    .line 10
    const-string v0, "onValueChange"

    .line 11
    .line 12
    move-object/from16 v6, p3

    .line 13
    .line 14
    invoke-static {v6, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    move-object/from16 v14, p8

    .line 18
    .line 19
    check-cast v14, Ll2/t;

    .line 20
    .line 21
    const v0, 0x36074cdd

    .line 22
    .line 23
    .line 24
    invoke-virtual {v14, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 25
    .line 26
    .line 27
    const/16 v0, 0x8

    .line 28
    .line 29
    int-to-float v15, v0

    .line 30
    const/16 v0, 0x50

    .line 31
    .line 32
    int-to-float v8, v0

    .line 33
    const/4 v0, 0x2

    .line 34
    int-to-float v9, v0

    .line 35
    div-float v0, v8, v9

    .line 36
    .line 37
    sget-object v1, Lw3/h1;->h:Ll2/u2;

    .line 38
    .line 39
    invoke-virtual {v14, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object v1

    .line 43
    check-cast v1, Lt4/c;

    .line 44
    .line 45
    invoke-interface {v1, v0}, Lt4/c;->w0(F)F

    .line 46
    .line 47
    .line 48
    move-result v5

    .line 49
    const v1, -0x2b2019d8

    .line 50
    .line 51
    .line 52
    invoke-virtual {v14, v1}, Ll2/t;->Z(I)V

    .line 53
    .line 54
    .line 55
    const v1, -0x384349

    .line 56
    .line 57
    .line 58
    invoke-virtual {v14, v1}, Ll2/t;->Z(I)V

    .line 59
    .line 60
    .line 61
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    move-result-object v2

    .line 65
    sget-object v4, Ll2/n;->a:Ll2/x0;

    .line 66
    .line 67
    if-ne v2, v4, :cond_0

    .line 68
    .line 69
    invoke-static {v14}, Ll2/l0;->h(Ll2/o;)Lvy0/b0;

    .line 70
    .line 71
    .line 72
    move-result-object v2

    .line 73
    new-instance v1, Ll2/d0;

    .line 74
    .line 75
    invoke-direct {v1, v2}, Ll2/d0;-><init>(Lvy0/b0;)V

    .line 76
    .line 77
    .line 78
    invoke-virtual {v14, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 79
    .line 80
    .line 81
    move-object v2, v1

    .line 82
    :cond_0
    invoke-virtual {v14, v12}, Ll2/t;->q(Z)V

    .line 83
    .line 84
    .line 85
    check-cast v2, Ll2/d0;

    .line 86
    .line 87
    iget-object v1, v2, Ll2/d0;->d:Lvy0/b0;

    .line 88
    .line 89
    invoke-virtual {v14, v12}, Ll2/t;->q(Z)V

    .line 90
    .line 91
    .line 92
    const v2, 0x36074f63

    .line 93
    .line 94
    .line 95
    invoke-virtual {v14, v2}, Ll2/t;->Z(I)V

    .line 96
    .line 97
    .line 98
    const v2, -0x384349

    .line 99
    .line 100
    .line 101
    invoke-virtual {v14, v2}, Ll2/t;->Z(I)V

    .line 102
    .line 103
    .line 104
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 105
    .line 106
    .line 107
    move-result-object v2

    .line 108
    move/from16 v16, v8

    .line 109
    .line 110
    const/4 v8, 0x0

    .line 111
    if-ne v2, v4, :cond_1

    .line 112
    .line 113
    invoke-static {v8}, Lc1/d;->a(F)Lc1/c;

    .line 114
    .line 115
    .line 116
    move-result-object v2

    .line 117
    invoke-virtual {v14, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 118
    .line 119
    .line 120
    :cond_1
    invoke-virtual {v14, v12}, Ll2/t;->q(Z)V

    .line 121
    .line 122
    .line 123
    check-cast v2, Lc1/c;

    .line 124
    .line 125
    invoke-interface {v7, v3}, Ljava/util/List;->indexOf(Ljava/lang/Object;)I

    .line 126
    .line 127
    .line 128
    move-result v8

    .line 129
    const v12, -0x384098

    .line 130
    .line 131
    .line 132
    invoke-virtual {v14, v12}, Ll2/t;->Z(I)V

    .line 133
    .line 134
    .line 135
    invoke-virtual {v14, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 136
    .line 137
    .line 138
    move-result v12

    .line 139
    invoke-virtual {v14, v7}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 140
    .line 141
    .line 142
    move-result v18

    .line 143
    or-int v12, v12, v18

    .line 144
    .line 145
    move/from16 v18, v0

    .line 146
    .line 147
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 148
    .line 149
    .line 150
    move-result-object v0

    .line 151
    move/from16 v19, v9

    .line 152
    .line 153
    const/4 v9, 0x1

    .line 154
    if-nez v12, :cond_3

    .line 155
    .line 156
    if-ne v0, v4, :cond_2

    .line 157
    .line 158
    goto :goto_1

    .line 159
    :cond_2
    :goto_0
    const/4 v8, 0x0

    .line 160
    goto :goto_2

    .line 161
    :cond_3
    :goto_1
    move-object v0, v7

    .line 162
    check-cast v0, Ljava/util/Collection;

    .line 163
    .line 164
    invoke-interface {v0}, Ljava/util/Collection;->size()I

    .line 165
    .line 166
    .line 167
    move-result v0

    .line 168
    sub-int/2addr v0, v9

    .line 169
    sub-int/2addr v0, v8

    .line 170
    neg-int v0, v0

    .line 171
    int-to-float v0, v0

    .line 172
    mul-float/2addr v0, v5

    .line 173
    invoke-static {v0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 174
    .line 175
    .line 176
    move-result-object v0

    .line 177
    int-to-float v8, v8

    .line 178
    mul-float/2addr v8, v5

    .line 179
    invoke-static {v8}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 180
    .line 181
    .line 182
    move-result-object v8

    .line 183
    new-instance v12, Llx0/l;

    .line 184
    .line 185
    invoke-direct {v12, v0, v8}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 186
    .line 187
    .line 188
    invoke-virtual {v14, v12}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 189
    .line 190
    .line 191
    move-object v0, v12

    .line 192
    goto :goto_0

    .line 193
    :goto_2
    invoke-virtual {v14, v8}, Ll2/t;->q(Z)V

    .line 194
    .line 195
    .line 196
    check-cast v0, Llx0/l;

    .line 197
    .line 198
    iget-object v8, v0, Llx0/l;->d:Ljava/lang/Object;

    .line 199
    .line 200
    iget-object v0, v0, Llx0/l;->e:Ljava/lang/Object;

    .line 201
    .line 202
    iget-object v12, v2, Lc1/c;->a:Lc1/b2;

    .line 203
    .line 204
    move/from16 v20, v9

    .line 205
    .line 206
    if-eqz v8, :cond_4

    .line 207
    .line 208
    iget-object v9, v12, Lc1/b2;->a:Lay0/k;

    .line 209
    .line 210
    invoke-interface {v9, v8}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 211
    .line 212
    .line 213
    move-result-object v9

    .line 214
    check-cast v9, Lc1/p;

    .line 215
    .line 216
    if-nez v9, :cond_5

    .line 217
    .line 218
    :cond_4
    iget-object v9, v2, Lc1/c;->j:Lc1/p;

    .line 219
    .line 220
    :cond_5
    if-eqz v0, :cond_7

    .line 221
    .line 222
    iget-object v12, v12, Lc1/b2;->a:Lay0/k;

    .line 223
    .line 224
    invoke-interface {v12, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 225
    .line 226
    .line 227
    move-result-object v12

    .line 228
    check-cast v12, Lc1/p;

    .line 229
    .line 230
    if-nez v12, :cond_6

    .line 231
    .line 232
    goto :goto_4

    .line 233
    :cond_6
    :goto_3
    move/from16 v21, v5

    .line 234
    .line 235
    goto :goto_5

    .line 236
    :cond_7
    :goto_4
    iget-object v12, v2, Lc1/c;->k:Lc1/p;

    .line 237
    .line 238
    goto :goto_3

    .line 239
    :goto_5
    invoke-virtual {v9}, Lc1/p;->b()I

    .line 240
    .line 241
    .line 242
    move-result v5

    .line 243
    const/4 v6, 0x0

    .line 244
    :goto_6
    if-ge v6, v5, :cond_9

    .line 245
    .line 246
    invoke-virtual {v9, v6}, Lc1/p;->a(I)F

    .line 247
    .line 248
    .line 249
    move-result v22

    .line 250
    invoke-virtual {v12, v6}, Lc1/p;->a(I)F

    .line 251
    .line 252
    .line 253
    move-result v23

    .line 254
    cmpg-float v22, v22, v23

    .line 255
    .line 256
    if-gtz v22, :cond_8

    .line 257
    .line 258
    move/from16 v22, v5

    .line 259
    .line 260
    move/from16 v23, v15

    .line 261
    .line 262
    goto :goto_7

    .line 263
    :cond_8
    move/from16 v22, v5

    .line 264
    .line 265
    new-instance v5, Ljava/lang/StringBuilder;

    .line 266
    .line 267
    move/from16 v23, v15

    .line 268
    .line 269
    const-string v15, "Lower bound must be no greater than upper bound on *all* dimensions. The provided lower bound: "

    .line 270
    .line 271
    invoke-direct {v5, v15}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 272
    .line 273
    .line 274
    invoke-virtual {v5, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 275
    .line 276
    .line 277
    const-string v15, " is greater than upper bound "

    .line 278
    .line 279
    invoke-virtual {v5, v15}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 280
    .line 281
    .line 282
    invoke-virtual {v5, v12}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 283
    .line 284
    .line 285
    const-string v15, " on index "

    .line 286
    .line 287
    invoke-virtual {v5, v15}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 288
    .line 289
    .line 290
    invoke-virtual {v5, v6}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 291
    .line 292
    .line 293
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 294
    .line 295
    .line 296
    move-result-object v5

    .line 297
    invoke-static {v5}, Lc1/s0;->b(Ljava/lang/String;)V

    .line 298
    .line 299
    .line 300
    :goto_7
    add-int/lit8 v6, v6, 0x1

    .line 301
    .line 302
    move/from16 v5, v22

    .line 303
    .line 304
    move/from16 v15, v23

    .line 305
    .line 306
    goto :goto_6

    .line 307
    :cond_9
    move/from16 v23, v15

    .line 308
    .line 309
    iput-object v9, v2, Lc1/c;->l:Lc1/p;

    .line 310
    .line 311
    iput-object v12, v2, Lc1/c;->m:Lc1/p;

    .line 312
    .line 313
    iput-object v0, v2, Lc1/c;->g:Ljava/lang/Object;

    .line 314
    .line 315
    iput-object v8, v2, Lc1/c;->f:Ljava/lang/Object;

    .line 316
    .line 317
    invoke-virtual {v2}, Lc1/c;->e()Z

    .line 318
    .line 319
    .line 320
    move-result v0

    .line 321
    if-nez v0, :cond_a

    .line 322
    .line 323
    invoke-virtual {v2}, Lc1/c;->d()Ljava/lang/Object;

    .line 324
    .line 325
    .line 326
    move-result-object v0

    .line 327
    invoke-virtual {v2, v0}, Lc1/c;->c(Ljava/lang/Object;)Ljava/lang/Object;

    .line 328
    .line 329
    .line 330
    move-result-object v0

    .line 331
    invoke-virtual {v2}, Lc1/c;->d()Ljava/lang/Object;

    .line 332
    .line 333
    .line 334
    move-result-object v5

    .line 335
    invoke-static {v0, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 336
    .line 337
    .line 338
    move-result v5

    .line 339
    if-nez v5, :cond_a

    .line 340
    .line 341
    iget-object v5, v2, Lc1/c;->c:Lc1/k;

    .line 342
    .line 343
    iget-object v5, v5, Lc1/k;->e:Ll2/j1;

    .line 344
    .line 345
    invoke-virtual {v5, v0}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 346
    .line 347
    .line 348
    :cond_a
    const/4 v8, 0x0

    .line 349
    invoke-virtual {v14, v8}, Ll2/t;->q(Z)V

    .line 350
    .line 351
    .line 352
    invoke-virtual {v2}, Lc1/c;->d()Ljava/lang/Object;

    .line 353
    .line 354
    .line 355
    move-result-object v0

    .line 356
    check-cast v0, Ljava/lang/Number;

    .line 357
    .line 358
    invoke-virtual {v0}, Ljava/lang/Number;->floatValue()F

    .line 359
    .line 360
    .line 361
    move-result v0

    .line 362
    rem-float v12, v0, v21

    .line 363
    .line 364
    invoke-virtual {v2}, Lc1/c;->d()Ljava/lang/Object;

    .line 365
    .line 366
    .line 367
    move-result-object v0

    .line 368
    check-cast v0, Ljava/lang/Number;

    .line 369
    .line 370
    invoke-virtual {v0}, Ljava/lang/Number;->floatValue()F

    .line 371
    .line 372
    .line 373
    move-result v0

    .line 374
    invoke-interface {v7, v3}, Ljava/util/List;->indexOf(Ljava/lang/Object;)I

    .line 375
    .line 376
    .line 377
    move-result v5

    .line 378
    div-float v0, v0, v21

    .line 379
    .line 380
    float-to-int v0, v0

    .line 381
    sub-int/2addr v5, v0

    .line 382
    move-object v0, v7

    .line 383
    check-cast v0, Ljava/util/Collection;

    .line 384
    .line 385
    invoke-interface {v0}, Ljava/util/Collection;->size()I

    .line 386
    .line 387
    .line 388
    move-result v0

    .line 389
    add-int/lit8 v0, v0, -0x1

    .line 390
    .line 391
    invoke-static {v5, v0}, Ljava/lang/Math;->min(II)I

    .line 392
    .line 393
    .line 394
    move-result v0

    .line 395
    const/4 v8, 0x0

    .line 396
    invoke-static {v8, v0}, Ljava/lang/Math;->max(II)I

    .line 397
    .line 398
    .line 399
    move-result v15

    .line 400
    const v0, -0x384349

    .line 401
    .line 402
    .line 403
    invoke-virtual {v14, v0}, Ll2/t;->Z(I)V

    .line 404
    .line 405
    .line 406
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 407
    .line 408
    .line 409
    move-result-object v0

    .line 410
    if-ne v0, v4, :cond_b

    .line 411
    .line 412
    int-to-float v0, v8

    .line 413
    new-instance v5, Lt4/f;

    .line 414
    .line 415
    invoke-direct {v5, v0}, Lt4/f;-><init>(F)V

    .line 416
    .line 417
    .line 418
    invoke-static {v5}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 419
    .line 420
    .line 421
    move-result-object v0

    .line 422
    invoke-virtual {v14, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 423
    .line 424
    .line 425
    :cond_b
    invoke-virtual {v14, v8}, Ll2/t;->q(Z)V

    .line 426
    .line 427
    .line 428
    move-object v8, v0

    .line 429
    check-cast v8, Ll2/b1;

    .line 430
    .line 431
    sget-object v9, Lg1/w1;->d:Lg1/w1;

    .line 432
    .line 433
    new-instance v0, Lb1/e;

    .line 434
    .line 435
    const/4 v5, 0x5

    .line 436
    invoke-direct {v0, v5, v1, v2}, Lb1/e;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 437
    .line 438
    .line 439
    invoke-static {v0, v14}, Lg1/f1;->b(Lay0/k;Ll2/o;)Lg1/i1;

    .line 440
    .line 441
    .line 442
    move-result-object v22

    .line 443
    new-instance v0, Ljn/j;

    .line 444
    .line 445
    const/4 v7, 0x0

    .line 446
    move-object/from16 v6, p3

    .line 447
    .line 448
    move-object/from16 v24, v4

    .line 449
    .line 450
    move/from16 v5, v21

    .line 451
    .line 452
    move-object v4, v3

    .line 453
    move-object/from16 v3, p6

    .line 454
    .line 455
    invoke-direct/range {v0 .. v7}, Ljn/j;-><init>(Lvy0/b0;Lc1/c;Ljava/util/List;Ljava/lang/Integer;FLay0/k;Lkotlin/coroutines/Continuation;)V

    .line 456
    .line 457
    .line 458
    move-object v7, v0

    .line 459
    move-object v0, v8

    .line 460
    const/4 v8, 0x0

    .line 461
    move-object v2, v9

    .line 462
    const/16 v9, 0xbc

    .line 463
    .line 464
    const/4 v3, 0x0

    .line 465
    const/4 v4, 0x0

    .line 466
    const/4 v5, 0x0

    .line 467
    const/4 v6, 0x0

    .line 468
    const/4 v10, 0x0

    .line 469
    move/from16 v17, v12

    .line 470
    .line 471
    move/from16 p8, v15

    .line 472
    .line 473
    move/from16 v15, v19

    .line 474
    .line 475
    move-object/from16 v1, v22

    .line 476
    .line 477
    move-object v12, v0

    .line 478
    move-object/from16 v0, p0

    .line 479
    .line 480
    invoke-static/range {v0 .. v9}, Lg1/f1;->a(Lx2/s;Lg1/i1;Lg1/w1;ZLi1/l;ZLg1/e1;Lay0/o;ZI)Lx2/s;

    .line 481
    .line 482
    .line 483
    move-result-object v1

    .line 484
    move-object v8, v0

    .line 485
    const/4 v0, 0x3

    .line 486
    int-to-float v0, v0

    .line 487
    div-float v0, v16, v0

    .line 488
    .line 489
    mul-float v2, v23, v15

    .line 490
    .line 491
    add-float/2addr v2, v0

    .line 492
    const/4 v0, 0x1

    .line 493
    invoke-static {v1, v10, v2, v0}, Landroidx/compose/foundation/layout/a;->o(Lx2/s;FFI)Lx2/s;

    .line 494
    .line 495
    .line 496
    move-result-object v1

    .line 497
    new-instance v0, Ljn/k;

    .line 498
    .line 499
    invoke-direct {v0, v12}, Ljn/k;-><init>(Ll2/b1;)V

    .line 500
    .line 501
    .line 502
    const v2, 0x52057532

    .line 503
    .line 504
    .line 505
    invoke-virtual {v14, v2}, Ll2/t;->Z(I)V

    .line 506
    .line 507
    .line 508
    sget-object v3, Lw3/h1;->h:Ll2/u2;

    .line 509
    .line 510
    invoke-virtual {v14, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 511
    .line 512
    .line 513
    move-result-object v4

    .line 514
    check-cast v4, Lt4/c;

    .line 515
    .line 516
    sget-object v5, Lw3/h1;->n:Ll2/u2;

    .line 517
    .line 518
    invoke-virtual {v14, v5}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 519
    .line 520
    .line 521
    move-result-object v6

    .line 522
    check-cast v6, Lt4/m;

    .line 523
    .line 524
    sget-object v7, Lw3/h1;->s:Ll2/u2;

    .line 525
    .line 526
    invoke-virtual {v14, v7}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 527
    .line 528
    .line 529
    move-result-object v9

    .line 530
    check-cast v9, Lw3/h2;

    .line 531
    .line 532
    sget-object v10, Lv3/k;->m1:Lv3/j;

    .line 533
    .line 534
    invoke-virtual {v10}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 535
    .line 536
    .line 537
    sget-object v10, Lv3/j;->b:Lv3/i;

    .line 538
    .line 539
    new-instance v11, Lt3/b0;

    .line 540
    .line 541
    const/4 v2, 0x1

    .line 542
    invoke-direct {v11, v1, v2}, Lt3/b0;-><init>(Lx2/s;I)V

    .line 543
    .line 544
    .line 545
    new-instance v1, Lt2/b;

    .line 546
    .line 547
    const v2, -0x7e903e5b

    .line 548
    .line 549
    .line 550
    move-object/from16 v19, v12

    .line 551
    .line 552
    const/4 v12, 0x1

    .line 553
    invoke-direct {v1, v11, v12, v2}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 554
    .line 555
    .line 556
    invoke-virtual {v14}, Ll2/t;->c0()V

    .line 557
    .line 558
    .line 559
    iget-boolean v11, v14, Ll2/t;->S:Z

    .line 560
    .line 561
    if-eqz v11, :cond_c

    .line 562
    .line 563
    invoke-virtual {v14, v10}, Ll2/t;->l(Lay0/a;)V

    .line 564
    .line 565
    .line 566
    :goto_8
    const/4 v11, 0x0

    .line 567
    goto :goto_9

    .line 568
    :cond_c
    invoke-virtual {v14}, Ll2/t;->m0()V

    .line 569
    .line 570
    .line 571
    goto :goto_8

    .line 572
    :goto_9
    iput-boolean v11, v14, Ll2/t;->y:Z

    .line 573
    .line 574
    sget-object v11, Lv3/j;->g:Lv3/h;

    .line 575
    .line 576
    invoke-static {v11, v0, v14}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 577
    .line 578
    .line 579
    sget-object v0, Lv3/j;->e:Lv3/h;

    .line 580
    .line 581
    invoke-static {v0, v4, v14}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 582
    .line 583
    .line 584
    sget-object v4, Lv3/j;->h:Lv3/h;

    .line 585
    .line 586
    invoke-static {v4, v6, v14}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 587
    .line 588
    .line 589
    sget-object v6, Lv3/j;->i:Lv3/h;

    .line 590
    .line 591
    invoke-static {v6, v9, v14}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 592
    .line 593
    .line 594
    iget v9, v14, Ll2/t;->z:I

    .line 595
    .line 596
    if-ltz v9, :cond_d

    .line 597
    .line 598
    const/4 v9, 0x1

    .line 599
    goto :goto_a

    .line 600
    :cond_d
    const/4 v9, 0x0

    .line 601
    :goto_a
    iput-boolean v9, v14, Ll2/t;->y:Z

    .line 602
    .line 603
    new-instance v9, Ll2/d2;

    .line 604
    .line 605
    invoke-direct {v9, v14}, Ll2/d2;-><init>(Ll2/o;)V

    .line 606
    .line 607
    .line 608
    invoke-virtual {v1, v9, v14, v13}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 609
    .line 610
    .line 611
    const v1, 0x7ab4aae9

    .line 612
    .line 613
    .line 614
    invoke-virtual {v14, v1}, Ll2/t;->Z(I)V

    .line 615
    .line 616
    .line 617
    invoke-interface/range {v19 .. v19}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 618
    .line 619
    .line 620
    move-result-object v9

    .line 621
    check-cast v9, Lt4/f;

    .line 622
    .line 623
    iget v9, v9, Lt4/f;->d:F

    .line 624
    .line 625
    invoke-static {v8, v9}, Landroidx/compose/foundation/layout/d;->r(Lx2/s;F)Lx2/s;

    .line 626
    .line 627
    .line 628
    move-result-object v9

    .line 629
    invoke-static {v9, v15}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 630
    .line 631
    .line 632
    move-result-object v9

    .line 633
    sget-object v12, Le3/j0;->a:Le3/i0;

    .line 634
    .line 635
    move-wide/from16 v1, p4

    .line 636
    .line 637
    invoke-static {v9, v1, v2, v12}, Landroidx/compose/foundation/a;->b(Lx2/s;JLe3/n0;)Lx2/s;

    .line 638
    .line 639
    .line 640
    move-result-object v9

    .line 641
    const/4 v1, 0x0

    .line 642
    invoke-static {v9, v14, v1}, Lk1/n;->a(Lx2/s;Ll2/o;I)V

    .line 643
    .line 644
    .line 645
    const/16 v1, 0x14

    .line 646
    .line 647
    int-to-float v1, v1

    .line 648
    sget-object v2, Lx2/p;->b:Lx2/p;

    .line 649
    .line 650
    move/from16 v9, v23

    .line 651
    .line 652
    invoke-static {v2, v1, v9}, Landroidx/compose/foundation/layout/a;->n(Lx2/s;FF)Lx2/s;

    .line 653
    .line 654
    .line 655
    move-result-object v1

    .line 656
    invoke-static/range {v17 .. v17}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 657
    .line 658
    .line 659
    move-result-object v9

    .line 660
    move-object/from16 v23, v12

    .line 661
    .line 662
    const v12, -0x384212

    .line 663
    .line 664
    .line 665
    invoke-virtual {v14, v12}, Ll2/t;->Z(I)V

    .line 666
    .line 667
    .line 668
    invoke-virtual {v14, v9}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 669
    .line 670
    .line 671
    move-result v9

    .line 672
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 673
    .line 674
    .line 675
    move-result-object v12

    .line 676
    if-nez v9, :cond_f

    .line 677
    .line 678
    move-object/from16 v9, v24

    .line 679
    .line 680
    if-ne v12, v9, :cond_e

    .line 681
    .line 682
    goto :goto_c

    .line 683
    :cond_e
    move/from16 v24, v15

    .line 684
    .line 685
    move/from16 v15, v17

    .line 686
    .line 687
    :goto_b
    const/4 v9, 0x0

    .line 688
    goto :goto_d

    .line 689
    :cond_f
    :goto_c
    new-instance v12, Ljn/h;

    .line 690
    .line 691
    const/4 v9, 0x1

    .line 692
    move/from16 v24, v15

    .line 693
    .line 694
    move/from16 v15, v17

    .line 695
    .line 696
    invoke-direct {v12, v9, v15}, Ljn/h;-><init>(IF)V

    .line 697
    .line 698
    .line 699
    invoke-virtual {v14, v12}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 700
    .line 701
    .line 702
    goto :goto_b

    .line 703
    :goto_d
    invoke-virtual {v14, v9}, Ll2/t;->q(Z)V

    .line 704
    .line 705
    .line 706
    check-cast v12, Lay0/k;

    .line 707
    .line 708
    invoke-static {v1, v12}, Landroidx/compose/foundation/layout/a;->i(Lx2/s;Lay0/k;)Lx2/s;

    .line 709
    .line 710
    .line 711
    move-result-object v1

    .line 712
    const v9, -0x76a43a57

    .line 713
    .line 714
    .line 715
    invoke-virtual {v14, v9}, Ll2/t;->Z(I)V

    .line 716
    .line 717
    .line 718
    invoke-static {v14}, Lk1/n;->e(Ll2/o;)Lk1/p;

    .line 719
    .line 720
    .line 721
    move-result-object v9

    .line 722
    const v12, 0x52057532

    .line 723
    .line 724
    .line 725
    invoke-virtual {v14, v12}, Ll2/t;->Z(I)V

    .line 726
    .line 727
    .line 728
    invoke-virtual {v14, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 729
    .line 730
    .line 731
    move-result-object v3

    .line 732
    check-cast v3, Lt4/c;

    .line 733
    .line 734
    invoke-virtual {v14, v5}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 735
    .line 736
    .line 737
    move-result-object v5

    .line 738
    check-cast v5, Lt4/m;

    .line 739
    .line 740
    invoke-virtual {v14, v7}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 741
    .line 742
    .line 743
    move-result-object v7

    .line 744
    check-cast v7, Lw3/h2;

    .line 745
    .line 746
    new-instance v12, Lt3/b0;

    .line 747
    .line 748
    move/from16 v17, v15

    .line 749
    .line 750
    const/4 v15, 0x1

    .line 751
    invoke-direct {v12, v1, v15}, Lt3/b0;-><init>(Lx2/s;I)V

    .line 752
    .line 753
    .line 754
    new-instance v1, Lt2/b;

    .line 755
    .line 756
    const/4 v8, 0x1

    .line 757
    const v15, -0x7e903e5b

    .line 758
    .line 759
    .line 760
    invoke-direct {v1, v12, v8, v15}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 761
    .line 762
    .line 763
    invoke-virtual {v14}, Ll2/t;->c0()V

    .line 764
    .line 765
    .line 766
    iget-boolean v8, v14, Ll2/t;->S:Z

    .line 767
    .line 768
    if-eqz v8, :cond_10

    .line 769
    .line 770
    invoke-virtual {v14, v10}, Ll2/t;->l(Lay0/a;)V

    .line 771
    .line 772
    .line 773
    :goto_e
    const/4 v8, 0x0

    .line 774
    goto :goto_f

    .line 775
    :cond_10
    invoke-virtual {v14}, Ll2/t;->m0()V

    .line 776
    .line 777
    .line 778
    goto :goto_e

    .line 779
    :goto_f
    iput-boolean v8, v14, Ll2/t;->y:Z

    .line 780
    .line 781
    invoke-static {v11, v9, v14}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 782
    .line 783
    .line 784
    invoke-static {v0, v3, v14}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 785
    .line 786
    .line 787
    invoke-static {v4, v5, v14}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 788
    .line 789
    .line 790
    invoke-static {v6, v7, v14}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 791
    .line 792
    .line 793
    iget v0, v14, Ll2/t;->z:I

    .line 794
    .line 795
    if-ltz v0, :cond_11

    .line 796
    .line 797
    const/4 v9, 0x1

    .line 798
    goto :goto_10

    .line 799
    :cond_11
    const/4 v9, 0x0

    .line 800
    :goto_10
    iput-boolean v9, v14, Ll2/t;->y:Z

    .line 801
    .line 802
    new-instance v0, Ll2/d2;

    .line 803
    .line 804
    invoke-direct {v0, v14}, Ll2/d2;-><init>(Ll2/o;)V

    .line 805
    .line 806
    .line 807
    invoke-virtual {v1, v0, v14, v13}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 808
    .line 809
    .line 810
    const v0, 0x7ab4aae9

    .line 811
    .line 812
    .line 813
    invoke-virtual {v14, v0}, Ll2/t;->Z(I)V

    .line 814
    .line 815
    .line 816
    const v0, -0x4ab8dd79

    .line 817
    .line 818
    .line 819
    invoke-virtual {v14, v0}, Ll2/t;->Z(I)V

    .line 820
    .line 821
    .line 822
    sget-object v0, Landroidx/compose/foundation/layout/b;->a:Landroidx/compose/foundation/layout/b;

    .line 823
    .line 824
    sget-object v1, Lx2/c;->h:Lx2/j;

    .line 825
    .line 826
    invoke-virtual {v0, v2, v1}, Landroidx/compose/foundation/layout/b;->a(Lx2/s;Lx2/e;)Lx2/s;

    .line 827
    .line 828
    .line 829
    move-result-object v4

    .line 830
    new-instance v0, Ljn/l;

    .line 831
    .line 832
    move-object/from16 v2, p1

    .line 833
    .line 834
    move-wide/from16 v10, p4

    .line 835
    .line 836
    move-object/from16 v3, p6

    .line 837
    .line 838
    move/from16 v1, p8

    .line 839
    .line 840
    move/from16 v6, v17

    .line 841
    .line 842
    move/from16 v5, v18

    .line 843
    .line 844
    move/from16 v7, v21

    .line 845
    .line 846
    invoke-direct/range {v0 .. v7}, Ljn/l;-><init>(ILay0/k;Ljava/util/List;Lx2/s;FFF)V

    .line 847
    .line 848
    .line 849
    const v1, -0x30de8a23

    .line 850
    .line 851
    .line 852
    invoke-static {v1, v14, v0}, Lt2/c;->b(ILl2/o;Llx0/e;)Lt2/b;

    .line 853
    .line 854
    .line 855
    move-result-object v0

    .line 856
    shr-int/lit8 v1, p9, 0x12

    .line 857
    .line 858
    and-int/lit8 v1, v1, 0xe

    .line 859
    .line 860
    or-int/lit8 v1, v1, 0x30

    .line 861
    .line 862
    move-object/from16 v8, p7

    .line 863
    .line 864
    invoke-static {v8, v0, v14, v1}, Lf2/v0;->a(Lg4/p0;Lt2/b;Ll2/o;I)V

    .line 865
    .line 866
    .line 867
    const/4 v9, 0x0

    .line 868
    invoke-virtual {v14, v9}, Ll2/t;->q(Z)V

    .line 869
    .line 870
    .line 871
    invoke-virtual {v14, v9}, Ll2/t;->q(Z)V

    .line 872
    .line 873
    .line 874
    const/4 v12, 0x1

    .line 875
    invoke-virtual {v14, v12}, Ll2/t;->q(Z)V

    .line 876
    .line 877
    .line 878
    invoke-virtual {v14, v9}, Ll2/t;->q(Z)V

    .line 879
    .line 880
    .line 881
    invoke-virtual {v14, v9}, Ll2/t;->q(Z)V

    .line 882
    .line 883
    .line 884
    invoke-interface/range {v19 .. v19}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 885
    .line 886
    .line 887
    move-result-object v0

    .line 888
    check-cast v0, Lt4/f;

    .line 889
    .line 890
    iget v0, v0, Lt4/f;->d:F

    .line 891
    .line 892
    move-object/from16 v1, p0

    .line 893
    .line 894
    invoke-static {v1, v0}, Landroidx/compose/foundation/layout/d;->r(Lx2/s;F)Lx2/s;

    .line 895
    .line 896
    .line 897
    move-result-object v0

    .line 898
    move/from16 v15, v24

    .line 899
    .line 900
    invoke-static {v0, v15}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 901
    .line 902
    .line 903
    move-result-object v0

    .line 904
    move-object/from16 v2, v23

    .line 905
    .line 906
    invoke-static {v0, v10, v11, v2}, Landroidx/compose/foundation/a;->b(Lx2/s;JLe3/n0;)Lx2/s;

    .line 907
    .line 908
    .line 909
    move-result-object v0

    .line 910
    invoke-static {v0, v14, v9}, Lk1/n;->a(Lx2/s;Ll2/o;I)V

    .line 911
    .line 912
    .line 913
    invoke-virtual {v14, v9}, Ll2/t;->q(Z)V

    .line 914
    .line 915
    .line 916
    invoke-virtual {v14, v12}, Ll2/t;->q(Z)V

    .line 917
    .line 918
    .line 919
    invoke-virtual {v14, v9}, Ll2/t;->q(Z)V

    .line 920
    .line 921
    .line 922
    invoke-virtual {v14}, Ll2/t;->s()Ll2/u1;

    .line 923
    .line 924
    .line 925
    move-result-object v12

    .line 926
    if-nez v12, :cond_12

    .line 927
    .line 928
    return-void

    .line 929
    :cond_12
    new-instance v0, Ljn/m;

    .line 930
    .line 931
    move-object/from16 v2, p1

    .line 932
    .line 933
    move-object/from16 v3, p2

    .line 934
    .line 935
    move-object/from16 v4, p3

    .line 936
    .line 937
    move-object/from16 v7, p6

    .line 938
    .line 939
    move/from16 v9, p9

    .line 940
    .line 941
    move-wide v5, v10

    .line 942
    invoke-direct/range {v0 .. v9}, Ljn/m;-><init>(Lx2/s;Lay0/k;Ljava/lang/Integer;Lay0/k;JLjava/util/List;Lg4/p0;I)V

    .line 943
    .line 944
    .line 945
    iput-object v0, v12, Ll2/u1;->d:Lay0/n;

    .line 946
    .line 947
    return-void
.end method

.method public static final c(ILjava/lang/String;Ll2/o;Lx2/s;)V
    .locals 20

    .line 1
    move/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v2, p3

    .line 6
    .line 7
    move-object/from16 v3, p2

    .line 8
    .line 9
    check-cast v3, Ll2/t;

    .line 10
    .line 11
    const v4, -0x47af7df2

    .line 12
    .line 13
    .line 14
    invoke-virtual {v3, v4}, Ll2/t;->a0(I)Ll2/t;

    .line 15
    .line 16
    .line 17
    and-int/lit8 v4, v0, 0xe

    .line 18
    .line 19
    const/4 v5, 0x2

    .line 20
    if-nez v4, :cond_1

    .line 21
    .line 22
    invoke-virtual {v3, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 23
    .line 24
    .line 25
    move-result v4

    .line 26
    if-eqz v4, :cond_0

    .line 27
    .line 28
    const/4 v4, 0x4

    .line 29
    goto :goto_0

    .line 30
    :cond_0
    move v4, v5

    .line 31
    :goto_0
    or-int/2addr v4, v0

    .line 32
    goto :goto_1

    .line 33
    :cond_1
    move v4, v0

    .line 34
    :goto_1
    and-int/lit8 v6, v0, 0x70

    .line 35
    .line 36
    if-nez v6, :cond_3

    .line 37
    .line 38
    invoke-virtual {v3, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 39
    .line 40
    .line 41
    move-result v6

    .line 42
    if-eqz v6, :cond_2

    .line 43
    .line 44
    const/16 v6, 0x20

    .line 45
    .line 46
    goto :goto_2

    .line 47
    :cond_2
    const/16 v6, 0x10

    .line 48
    .line 49
    :goto_2
    or-int/2addr v4, v6

    .line 50
    :cond_3
    and-int/lit8 v6, v4, 0x5b

    .line 51
    .line 52
    xor-int/lit8 v6, v6, 0x12

    .line 53
    .line 54
    if-nez v6, :cond_5

    .line 55
    .line 56
    invoke-virtual {v3}, Ll2/t;->A()Z

    .line 57
    .line 58
    .line 59
    move-result v6

    .line 60
    if-nez v6, :cond_4

    .line 61
    .line 62
    goto :goto_3

    .line 63
    :cond_4
    invoke-virtual {v3}, Ll2/t;->R()V

    .line 64
    .line 65
    .line 66
    move-object/from16 v17, v3

    .line 67
    .line 68
    goto :goto_4

    .line 69
    :cond_5
    :goto_3
    new-instance v6, Lal0/m0;

    .line 70
    .line 71
    const/4 v7, 0x0

    .line 72
    const/16 v8, 0xe

    .line 73
    .line 74
    invoke-direct {v6, v5, v7, v8}, Lal0/m0;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 75
    .line 76
    .line 77
    sget-object v5, Llx0/b0;->a:Llx0/b0;

    .line 78
    .line 79
    invoke-static {v2, v5, v6}, Lp3/f0;->c(Lx2/s;Ljava/lang/Object;Lay0/n;)Lx2/s;

    .line 80
    .line 81
    .line 82
    move-result-object v5

    .line 83
    new-instance v9, Lr4/k;

    .line 84
    .line 85
    const/4 v6, 0x3

    .line 86
    invoke-direct {v9, v6}, Lr4/k;-><init>(I)V

    .line 87
    .line 88
    .line 89
    and-int/lit8 v18, v4, 0xe

    .line 90
    .line 91
    const v19, 0xfdfc

    .line 92
    .line 93
    .line 94
    move-object/from16 v17, v3

    .line 95
    .line 96
    const-wide/16 v3, 0x0

    .line 97
    .line 98
    move-object v2, v5

    .line 99
    const-wide/16 v5, 0x0

    .line 100
    .line 101
    const-wide/16 v7, 0x0

    .line 102
    .line 103
    const-wide/16 v10, 0x0

    .line 104
    .line 105
    const/4 v12, 0x0

    .line 106
    const/4 v13, 0x0

    .line 107
    const/4 v14, 0x0

    .line 108
    const/4 v15, 0x0

    .line 109
    const/16 v16, 0x0

    .line 110
    .line 111
    invoke-static/range {v1 .. v19}, Lf2/v0;->c(Ljava/lang/String;Lx2/s;JJJLr4/k;JIZILay0/k;Lg4/p0;Ll2/o;II)V

    .line 112
    .line 113
    .line 114
    :goto_4
    invoke-virtual/range {v17 .. v17}, Ll2/t;->s()Ll2/u1;

    .line 115
    .line 116
    .line 117
    move-result-object v2

    .line 118
    if-nez v2, :cond_6

    .line 119
    .line 120
    return-void

    .line 121
    :cond_6
    new-instance v3, Ljn/g;

    .line 122
    .line 123
    const/4 v4, 0x0

    .line 124
    move-object/from16 v5, p3

    .line 125
    .line 126
    invoke-direct {v3, v0, v4, v1, v5}, Ljn/g;-><init>(IILjava/lang/Object;Ljava/lang/Object;)V

    .line 127
    .line 128
    .line 129
    iput-object v3, v2, Ll2/u1;->d:Lay0/n;

    .line 130
    .line 131
    return-void
.end method
