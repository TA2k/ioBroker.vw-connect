.class public abstract Lp61/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lt2/b;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Llk/b;

    .line 2
    .line 3
    const/16 v1, 0x1b

    .line 4
    .line 5
    invoke-direct {v0, v1}, Llk/b;-><init>(I)V

    .line 6
    .line 7
    .line 8
    new-instance v1, Lt2/b;

    .line 9
    .line 10
    const/4 v2, 0x0

    .line 11
    const v3, -0x65f2a2f9

    .line 12
    .line 13
    .line 14
    invoke-direct {v1, v0, v2, v3}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 15
    .line 16
    .line 17
    sput-object v1, Lp61/a;->a:Lt2/b;

    .line 18
    .line 19
    return-void
.end method

.method public static final a(ILay0/a;Ll2/o;Lx2/s;)V
    .locals 25

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
    const-string v3, "modifier"

    .line 8
    .line 9
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    const-string v3, "onClose"

    .line 13
    .line 14
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    move-object/from16 v11, p2

    .line 18
    .line 19
    check-cast v11, Ll2/t;

    .line 20
    .line 21
    const v3, -0x472b11d3

    .line 22
    .line 23
    .line 24
    invoke-virtual {v11, v3}, Ll2/t;->a0(I)Ll2/t;

    .line 25
    .line 26
    .line 27
    invoke-virtual {v11, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result v3

    .line 31
    const/16 v14, 0x20

    .line 32
    .line 33
    if-eqz v3, :cond_0

    .line 34
    .line 35
    move v3, v14

    .line 36
    goto :goto_0

    .line 37
    :cond_0
    const/16 v3, 0x10

    .line 38
    .line 39
    :goto_0
    or-int/2addr v3, v0

    .line 40
    and-int/lit8 v4, v3, 0x13

    .line 41
    .line 42
    const/16 v5, 0x12

    .line 43
    .line 44
    const/4 v6, 0x1

    .line 45
    if-eq v4, v5, :cond_1

    .line 46
    .line 47
    move v4, v6

    .line 48
    goto :goto_1

    .line 49
    :cond_1
    const/4 v4, 0x0

    .line 50
    :goto_1
    and-int/lit8 v7, v3, 0x1

    .line 51
    .line 52
    invoke-virtual {v11, v7, v4}, Ll2/t;->O(IZ)Z

    .line 53
    .line 54
    .line 55
    move-result v4

    .line 56
    if-eqz v4, :cond_9

    .line 57
    .line 58
    sget-wide v7, Le3/s;->f:J

    .line 59
    .line 60
    const/high16 v4, 0x3f400000    # 0.75f

    .line 61
    .line 62
    invoke-static {v7, v8, v4}, Le3/s;->b(JF)J

    .line 63
    .line 64
    .line 65
    move-result-wide v7

    .line 66
    sget-object v4, Le3/j0;->a:Le3/i0;

    .line 67
    .line 68
    invoke-static {v2, v7, v8, v4}, Landroidx/compose/foundation/a;->b(Lx2/s;JLe3/n0;)Lx2/s;

    .line 69
    .line 70
    .line 71
    move-result-object v4

    .line 72
    sget v7, Ln61/c;->a:F

    .line 73
    .line 74
    const/4 v8, 0x0

    .line 75
    const/4 v9, 0x2

    .line 76
    invoke-static {v4, v7, v8, v9}, Landroidx/compose/foundation/layout/a;->o(Lx2/s;FFI)Lx2/s;

    .line 77
    .line 78
    .line 79
    move-result-object v16

    .line 80
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 81
    .line 82
    .line 83
    move-result-object v4

    .line 84
    sget-object v8, Ll2/n;->a:Ll2/x0;

    .line 85
    .line 86
    if-ne v4, v8, :cond_2

    .line 87
    .line 88
    new-instance v4, Lz81/g;

    .line 89
    .line 90
    const/4 v9, 0x2

    .line 91
    invoke-direct {v4, v9}, Lz81/g;-><init>(I)V

    .line 92
    .line 93
    .line 94
    invoke-virtual {v11, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 95
    .line 96
    .line 97
    :cond_2
    move-object/from16 v20, v4

    .line 98
    .line 99
    check-cast v20, Lay0/a;

    .line 100
    .line 101
    const/16 v21, 0xf

    .line 102
    .line 103
    const/16 v17, 0x0

    .line 104
    .line 105
    const/16 v18, 0x0

    .line 106
    .line 107
    const/16 v19, 0x0

    .line 108
    .line 109
    invoke-static/range {v16 .. v21}, Landroidx/compose/foundation/a;->f(Lx2/s;ZLjava/lang/String;Ld4/i;Lay0/a;I)Lx2/s;

    .line 110
    .line 111
    .line 112
    move-result-object v4

    .line 113
    sget-object v9, Lx2/c;->q:Lx2/h;

    .line 114
    .line 115
    sget-object v10, Lk1/j;->e:Lk1/f;

    .line 116
    .line 117
    const/16 v12, 0x36

    .line 118
    .line 119
    invoke-static {v10, v9, v11, v12}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 120
    .line 121
    .line 122
    move-result-object v9

    .line 123
    iget-wide v12, v11, Ll2/t;->T:J

    .line 124
    .line 125
    invoke-static {v12, v13}, Ljava/lang/Long;->hashCode(J)I

    .line 126
    .line 127
    .line 128
    move-result v10

    .line 129
    invoke-virtual {v11}, Ll2/t;->m()Ll2/p1;

    .line 130
    .line 131
    .line 132
    move-result-object v12

    .line 133
    invoke-static {v11, v4}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 134
    .line 135
    .line 136
    move-result-object v4

    .line 137
    sget-object v13, Lv3/k;->m1:Lv3/j;

    .line 138
    .line 139
    invoke-virtual {v13}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 140
    .line 141
    .line 142
    sget-object v13, Lv3/j;->b:Lv3/i;

    .line 143
    .line 144
    invoke-virtual {v11}, Ll2/t;->c0()V

    .line 145
    .line 146
    .line 147
    iget-boolean v5, v11, Ll2/t;->S:Z

    .line 148
    .line 149
    if-eqz v5, :cond_3

    .line 150
    .line 151
    invoke-virtual {v11, v13}, Ll2/t;->l(Lay0/a;)V

    .line 152
    .line 153
    .line 154
    goto :goto_2

    .line 155
    :cond_3
    invoke-virtual {v11}, Ll2/t;->m0()V

    .line 156
    .line 157
    .line 158
    :goto_2
    sget-object v5, Lv3/j;->g:Lv3/h;

    .line 159
    .line 160
    invoke-static {v5, v9, v11}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 161
    .line 162
    .line 163
    sget-object v5, Lv3/j;->f:Lv3/h;

    .line 164
    .line 165
    invoke-static {v5, v12, v11}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 166
    .line 167
    .line 168
    sget-object v5, Lv3/j;->j:Lv3/h;

    .line 169
    .line 170
    iget-boolean v9, v11, Ll2/t;->S:Z

    .line 171
    .line 172
    if-nez v9, :cond_4

    .line 173
    .line 174
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 175
    .line 176
    .line 177
    move-result-object v9

    .line 178
    invoke-static {v10}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 179
    .line 180
    .line 181
    move-result-object v12

    .line 182
    invoke-static {v9, v12}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 183
    .line 184
    .line 185
    move-result v9

    .line 186
    if-nez v9, :cond_5

    .line 187
    .line 188
    :cond_4
    invoke-static {v10, v11, v10, v5}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 189
    .line 190
    .line 191
    :cond_5
    sget-object v5, Lv3/j;->d:Lv3/h;

    .line 192
    .line 193
    invoke-static {v5, v4, v11}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 194
    .line 195
    .line 196
    const/16 v19, 0x0

    .line 197
    .line 198
    const/16 v21, 0x7

    .line 199
    .line 200
    sget-object v16, Lx2/p;->b:Lx2/p;

    .line 201
    .line 202
    const/16 v17, 0x0

    .line 203
    .line 204
    const/16 v18, 0x0

    .line 205
    .line 206
    move/from16 v20, v7

    .line 207
    .line 208
    invoke-static/range {v16 .. v21}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 209
    .line 210
    .line 211
    move-result-object v4

    .line 212
    const/16 v5, 0x18

    .line 213
    .line 214
    invoke-static {v5}, Lgq/b;->c(I)J

    .line 215
    .line 216
    .line 217
    move-result-wide v9

    .line 218
    const/16 v12, 0x1b6

    .line 219
    .line 220
    const/16 v13, 0x18

    .line 221
    .line 222
    const-string v5, "The Remote Park Assist flow has to be presented fullscreen in order to work properly."

    .line 223
    .line 224
    move-wide/from16 v23, v9

    .line 225
    .line 226
    move v10, v6

    .line 227
    move-wide/from16 v6, v23

    .line 228
    .line 229
    move-object/from16 v17, v8

    .line 230
    .line 231
    const-wide/16 v8, 0x0

    .line 232
    .line 233
    move/from16 v18, v10

    .line 234
    .line 235
    const/4 v10, 0x0

    .line 236
    move-object/from16 v15, v17

    .line 237
    .line 238
    const/16 v22, 0x12

    .line 239
    .line 240
    invoke-static/range {v4 .. v13}, Lp61/a;->b(Lx2/s;Ljava/lang/String;JJILl2/o;II)V

    .line 241
    .line 242
    .line 243
    const/16 v17, 0x0

    .line 244
    .line 245
    const/16 v18, 0x0

    .line 246
    .line 247
    invoke-static/range {v16 .. v21}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 248
    .line 249
    .line 250
    move-result-object v4

    .line 251
    invoke-static/range {v22 .. v22}, Lgq/b;->c(I)J

    .line 252
    .line 253
    .line 254
    move-result-wide v6

    .line 255
    const-string v5, "Hint: the app bar must be part of the RPAScreen as well!"

    .line 256
    .line 257
    invoke-static/range {v4 .. v13}, Lp61/a;->b(Lx2/s;Ljava/lang/String;JJILl2/o;II)V

    .line 258
    .line 259
    .line 260
    and-int/lit8 v3, v3, 0x70

    .line 261
    .line 262
    if-ne v3, v14, :cond_6

    .line 263
    .line 264
    const/4 v3, 0x1

    .line 265
    goto :goto_3

    .line 266
    :cond_6
    const/4 v3, 0x0

    .line 267
    :goto_3
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 268
    .line 269
    .line 270
    move-result-object v4

    .line 271
    if-nez v3, :cond_7

    .line 272
    .line 273
    if-ne v4, v15, :cond_8

    .line 274
    .line 275
    :cond_7
    new-instance v4, Lp61/b;

    .line 276
    .line 277
    const/4 v3, 0x0

    .line 278
    invoke-direct {v4, v1, v3}, Lp61/b;-><init>(Lay0/a;I)V

    .line 279
    .line 280
    .line 281
    invoke-virtual {v11, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 282
    .line 283
    .line 284
    :cond_8
    check-cast v4, Lay0/a;

    .line 285
    .line 286
    const v12, 0x30000180

    .line 287
    .line 288
    .line 289
    const/16 v13, 0x1fa

    .line 290
    .line 291
    const/4 v5, 0x0

    .line 292
    const/4 v6, 0x0

    .line 293
    const/4 v7, 0x0

    .line 294
    const/4 v8, 0x0

    .line 295
    const/4 v9, 0x0

    .line 296
    sget-object v10, Lp61/a;->a:Lt2/b;

    .line 297
    .line 298
    invoke-static/range {v4 .. v13}, Lkp/c7;->a(Lay0/a;Lx2/s;Lf2/p;Le3/n0;Lf2/l;Lk1/z0;Lt2/b;Ll2/o;II)V

    .line 299
    .line 300
    .line 301
    const/4 v10, 0x1

    .line 302
    invoke-virtual {v11, v10}, Ll2/t;->q(Z)V

    .line 303
    .line 304
    .line 305
    goto :goto_4

    .line 306
    :cond_9
    invoke-virtual {v11}, Ll2/t;->R()V

    .line 307
    .line 308
    .line 309
    :goto_4
    invoke-virtual {v11}, Ll2/t;->s()Ll2/u1;

    .line 310
    .line 311
    .line 312
    move-result-object v3

    .line 313
    if-eqz v3, :cond_a

    .line 314
    .line 315
    new-instance v4, Li40/a;

    .line 316
    .line 317
    const/4 v5, 0x1

    .line 318
    invoke-direct {v4, v2, v1, v0, v5}, Li40/a;-><init>(Lx2/s;Lay0/a;II)V

    .line 319
    .line 320
    .line 321
    iput-object v4, v3, Ll2/u1;->d:Lay0/n;

    .line 322
    .line 323
    :cond_a
    return-void
.end method

.method public static final b(Lx2/s;Ljava/lang/String;JJILl2/o;II)V
    .locals 32

    .line 1
    move/from16 v8, p8

    .line 2
    .line 3
    move-object/from16 v0, p7

    .line 4
    .line 5
    check-cast v0, Ll2/t;

    .line 6
    .line 7
    const v1, 0x94a40a1

    .line 8
    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ll2/t;->a0(I)Ll2/t;

    .line 11
    .line 12
    .line 13
    and-int/lit8 v1, p9, 0x4

    .line 14
    .line 15
    if-eqz v1, :cond_0

    .line 16
    .line 17
    or-int/lit16 v2, v8, 0x180

    .line 18
    .line 19
    move v4, v2

    .line 20
    move-wide/from16 v2, p2

    .line 21
    .line 22
    goto :goto_1

    .line 23
    :cond_0
    and-int/lit16 v2, v8, 0x180

    .line 24
    .line 25
    if-nez v2, :cond_2

    .line 26
    .line 27
    move-wide/from16 v2, p2

    .line 28
    .line 29
    invoke-virtual {v0, v2, v3}, Ll2/t;->f(J)Z

    .line 30
    .line 31
    .line 32
    move-result v4

    .line 33
    if-eqz v4, :cond_1

    .line 34
    .line 35
    const/16 v4, 0x100

    .line 36
    .line 37
    goto :goto_0

    .line 38
    :cond_1
    const/16 v4, 0x80

    .line 39
    .line 40
    :goto_0
    or-int/2addr v4, v8

    .line 41
    goto :goto_1

    .line 42
    :cond_2
    move-wide/from16 v2, p2

    .line 43
    .line 44
    move v4, v8

    .line 45
    :goto_1
    or-int/lit16 v4, v4, 0x2c00

    .line 46
    .line 47
    and-int/lit16 v5, v4, 0x2493

    .line 48
    .line 49
    const/16 v6, 0x2492

    .line 50
    .line 51
    const/4 v7, 0x0

    .line 52
    if-eq v5, v6, :cond_3

    .line 53
    .line 54
    const/4 v5, 0x1

    .line 55
    goto :goto_2

    .line 56
    :cond_3
    move v5, v7

    .line 57
    :goto_2
    and-int/lit8 v6, v4, 0x1

    .line 58
    .line 59
    invoke-virtual {v0, v6, v5}, Ll2/t;->O(IZ)Z

    .line 60
    .line 61
    .line 62
    move-result v5

    .line 63
    if-eqz v5, :cond_8

    .line 64
    .line 65
    invoke-virtual {v0}, Ll2/t;->T()V

    .line 66
    .line 67
    .line 68
    and-int/lit8 v5, v8, 0x1

    .line 69
    .line 70
    const v6, -0xe001

    .line 71
    .line 72
    .line 73
    const/4 v9, 0x3

    .line 74
    if-eqz v5, :cond_5

    .line 75
    .line 76
    invoke-virtual {v0}, Ll2/t;->y()Z

    .line 77
    .line 78
    .line 79
    move-result v5

    .line 80
    if-eqz v5, :cond_4

    .line 81
    .line 82
    goto :goto_3

    .line 83
    :cond_4
    invoke-virtual {v0}, Ll2/t;->R()V

    .line 84
    .line 85
    .line 86
    and-int v1, v4, v6

    .line 87
    .line 88
    move-wide/from16 v11, p4

    .line 89
    .line 90
    move-wide v13, v2

    .line 91
    move v3, v1

    .line 92
    move/from16 v1, p6

    .line 93
    .line 94
    goto :goto_5

    .line 95
    :cond_5
    :goto_3
    if-eqz v1, :cond_6

    .line 96
    .line 97
    const/16 v1, 0x10

    .line 98
    .line 99
    invoke-static {v1}, Lgq/b;->c(I)J

    .line 100
    .line 101
    .line 102
    move-result-wide v1

    .line 103
    goto :goto_4

    .line 104
    :cond_6
    move-wide v1, v2

    .line 105
    :goto_4
    sget-wide v10, Le3/s;->e:J

    .line 106
    .line 107
    and-int v3, v4, v6

    .line 108
    .line 109
    move-wide v13, v1

    .line 110
    move v1, v9

    .line 111
    move-wide v11, v10

    .line 112
    :goto_5
    invoke-virtual {v0}, Ll2/t;->r()V

    .line 113
    .line 114
    .line 115
    sget-object v16, Lk4/x;->l:Lk4/x;

    .line 116
    .line 117
    sget-object v27, Lg4/p0;->d:Lg4/p0;

    .line 118
    .line 119
    sget-wide v17, Lt4/o;->c:J

    .line 120
    .line 121
    new-instance v15, Lk4/t;

    .line 122
    .line 123
    invoke-direct {v15, v7}, Lk4/t;-><init>(I)V

    .line 124
    .line 125
    .line 126
    new-instance v2, Lr4/k;

    .line 127
    .line 128
    invoke-direct {v2, v1}, Lr4/k;-><init>(I)V

    .line 129
    .line 130
    .line 131
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 132
    .line 133
    .line 134
    move-result-object v4

    .line 135
    sget-object v5, Ll2/n;->a:Ll2/x0;

    .line 136
    .line 137
    if-ne v4, v5, :cond_7

    .line 138
    .line 139
    new-instance v4, Lod0/g;

    .line 140
    .line 141
    const/16 v5, 0x15

    .line 142
    .line 143
    invoke-direct {v4, v5}, Lod0/g;-><init>(I)V

    .line 144
    .line 145
    .line 146
    invoke-virtual {v0, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 147
    .line 148
    .line 149
    :cond_7
    move-object/from16 v26, v4

    .line 150
    .line 151
    check-cast v26, Lay0/k;

    .line 152
    .line 153
    shl-int/2addr v3, v9

    .line 154
    and-int/lit16 v3, v3, 0x1c00

    .line 155
    .line 156
    const v4, 0x6db01b6

    .line 157
    .line 158
    .line 159
    or-int v29, v4, v3

    .line 160
    .line 161
    const v30, 0x1b0db6

    .line 162
    .line 163
    .line 164
    const/16 v31, 0x4000

    .line 165
    .line 166
    const/16 v22, 0x1

    .line 167
    .line 168
    const/16 v23, 0x1

    .line 169
    .line 170
    const v24, 0x7fffffff

    .line 171
    .line 172
    .line 173
    const/16 v25, 0x0

    .line 174
    .line 175
    move-wide/from16 v20, v17

    .line 176
    .line 177
    move-object/from16 v10, p0

    .line 178
    .line 179
    move-object/from16 v9, p1

    .line 180
    .line 181
    move-object/from16 v28, v0

    .line 182
    .line 183
    move-object/from16 v19, v2

    .line 184
    .line 185
    invoke-static/range {v9 .. v31}, Lf2/v0;->b(Ljava/lang/String;Lx2/s;JJLk4/t;Lk4/x;JLr4/k;JIZIILay0/k;Lg4/p0;Ll2/o;III)V

    .line 186
    .line 187
    .line 188
    move v7, v1

    .line 189
    move-wide v5, v11

    .line 190
    move-wide v3, v13

    .line 191
    goto :goto_6

    .line 192
    :cond_8
    move-object/from16 v28, v0

    .line 193
    .line 194
    invoke-virtual/range {v28 .. v28}, Ll2/t;->R()V

    .line 195
    .line 196
    .line 197
    move-wide/from16 v5, p4

    .line 198
    .line 199
    move/from16 v7, p6

    .line 200
    .line 201
    move-wide v3, v2

    .line 202
    :goto_6
    invoke-virtual/range {v28 .. v28}, Ll2/t;->s()Ll2/u1;

    .line 203
    .line 204
    .line 205
    move-result-object v10

    .line 206
    if-eqz v10, :cond_9

    .line 207
    .line 208
    new-instance v0, Lp61/c;

    .line 209
    .line 210
    move-object/from16 v1, p0

    .line 211
    .line 212
    move-object/from16 v2, p1

    .line 213
    .line 214
    move/from16 v9, p9

    .line 215
    .line 216
    invoke-direct/range {v0 .. v9}, Lp61/c;-><init>(Lx2/s;Ljava/lang/String;JJIII)V

    .line 217
    .line 218
    .line 219
    iput-object v0, v10, Ll2/u1;->d:Lay0/n;

    .line 220
    .line 221
    :cond_9
    return-void
.end method
