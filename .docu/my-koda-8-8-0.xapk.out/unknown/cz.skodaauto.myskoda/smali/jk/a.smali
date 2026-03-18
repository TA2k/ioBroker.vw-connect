.class public abstract Ljk/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lt2/b;

.field public static final b:Lt2/b;

.field public static final c:Lt2/b;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Li40/s;

    .line 2
    .line 3
    const/16 v1, 0xc

    .line 4
    .line 5
    invoke-direct {v0, v1}, Li40/s;-><init>(I)V

    .line 6
    .line 7
    .line 8
    new-instance v1, Lt2/b;

    .line 9
    .line 10
    const/4 v2, 0x0

    .line 11
    const v3, 0x53bda1e2

    .line 12
    .line 13
    .line 14
    invoke-direct {v1, v0, v2, v3}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 15
    .line 16
    .line 17
    sput-object v1, Ljk/a;->a:Lt2/b;

    .line 18
    .line 19
    new-instance v0, Li40/s;

    .line 20
    .line 21
    const/16 v1, 0xd

    .line 22
    .line 23
    invoke-direct {v0, v1}, Li40/s;-><init>(I)V

    .line 24
    .line 25
    .line 26
    new-instance v1, Lt2/b;

    .line 27
    .line 28
    const v3, 0x28d98802

    .line 29
    .line 30
    .line 31
    invoke-direct {v1, v0, v2, v3}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 32
    .line 33
    .line 34
    sput-object v1, Ljk/a;->b:Lt2/b;

    .line 35
    .line 36
    new-instance v0, Ljc0/b;

    .line 37
    .line 38
    const/16 v1, 0x11

    .line 39
    .line 40
    invoke-direct {v0, v1}, Ljc0/b;-><init>(I)V

    .line 41
    .line 42
    .line 43
    new-instance v1, Lt2/b;

    .line 44
    .line 45
    const v3, -0x2638739b

    .line 46
    .line 47
    .line 48
    invoke-direct {v1, v0, v2, v3}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 49
    .line 50
    .line 51
    sput-object v1, Ljk/a;->c:Lt2/b;

    .line 52
    .line 53
    return-void
.end method

.method public static final a(Lhe/h;Lay0/k;Ll2/o;I)V
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move/from16 v2, p3

    .line 6
    .line 7
    move-object/from16 v12, p2

    .line 8
    .line 9
    check-cast v12, Ll2/t;

    .line 10
    .line 11
    const v3, 0x557ad5f2

    .line 12
    .line 13
    .line 14
    invoke-virtual {v12, v3}, Ll2/t;->a0(I)Ll2/t;

    .line 15
    .line 16
    .line 17
    and-int/lit8 v3, v2, 0x6

    .line 18
    .line 19
    const/4 v4, 0x2

    .line 20
    const/4 v9, 0x4

    .line 21
    if-nez v3, :cond_2

    .line 22
    .line 23
    and-int/lit8 v3, v2, 0x8

    .line 24
    .line 25
    if-nez v3, :cond_0

    .line 26
    .line 27
    invoke-virtual {v12, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result v3

    .line 31
    goto :goto_0

    .line 32
    :cond_0
    invoke-virtual {v12, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 33
    .line 34
    .line 35
    move-result v3

    .line 36
    :goto_0
    if-eqz v3, :cond_1

    .line 37
    .line 38
    move v3, v9

    .line 39
    goto :goto_1

    .line 40
    :cond_1
    move v3, v4

    .line 41
    :goto_1
    or-int/2addr v3, v2

    .line 42
    goto :goto_2

    .line 43
    :cond_2
    move v3, v2

    .line 44
    :goto_2
    and-int/lit8 v5, v2, 0x30

    .line 45
    .line 46
    const/16 v6, 0x10

    .line 47
    .line 48
    if-nez v5, :cond_4

    .line 49
    .line 50
    invoke-virtual {v12, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 51
    .line 52
    .line 53
    move-result v5

    .line 54
    if-eqz v5, :cond_3

    .line 55
    .line 56
    const/16 v5, 0x20

    .line 57
    .line 58
    goto :goto_3

    .line 59
    :cond_3
    move v5, v6

    .line 60
    :goto_3
    or-int/2addr v3, v5

    .line 61
    :cond_4
    move v11, v3

    .line 62
    and-int/lit8 v3, v11, 0x13

    .line 63
    .line 64
    const/16 v5, 0x12

    .line 65
    .line 66
    const/4 v13, 0x0

    .line 67
    const/4 v15, 0x1

    .line 68
    if-eq v3, v5, :cond_5

    .line 69
    .line 70
    move v3, v15

    .line 71
    goto :goto_4

    .line 72
    :cond_5
    move v3, v13

    .line 73
    :goto_4
    and-int/lit8 v5, v11, 0x1

    .line 74
    .line 75
    invoke-virtual {v12, v5, v3}, Ll2/t;->O(IZ)Z

    .line 76
    .line 77
    .line 78
    move-result v3

    .line 79
    if-eqz v3, :cond_e

    .line 80
    .line 81
    sget-object v14, Lx2/p;->b:Lx2/p;

    .line 82
    .line 83
    const/high16 v3, 0x3f800000    # 1.0f

    .line 84
    .line 85
    invoke-static {v14, v3}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 86
    .line 87
    .line 88
    move-result-object v5

    .line 89
    sget-object v7, Lk1/j;->c:Lk1/e;

    .line 90
    .line 91
    sget-object v8, Lx2/c;->p:Lx2/h;

    .line 92
    .line 93
    invoke-static {v7, v8, v12, v13}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 94
    .line 95
    .line 96
    move-result-object v7

    .line 97
    move/from16 v16, v11

    .line 98
    .line 99
    iget-wide v10, v12, Ll2/t;->T:J

    .line 100
    .line 101
    invoke-static {v10, v11}, Ljava/lang/Long;->hashCode(J)I

    .line 102
    .line 103
    .line 104
    move-result v8

    .line 105
    invoke-virtual {v12}, Ll2/t;->m()Ll2/p1;

    .line 106
    .line 107
    .line 108
    move-result-object v10

    .line 109
    invoke-static {v12, v5}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 110
    .line 111
    .line 112
    move-result-object v5

    .line 113
    sget-object v11, Lv3/k;->m1:Lv3/j;

    .line 114
    .line 115
    invoke-virtual {v11}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 116
    .line 117
    .line 118
    sget-object v11, Lv3/j;->b:Lv3/i;

    .line 119
    .line 120
    invoke-virtual {v12}, Ll2/t;->c0()V

    .line 121
    .line 122
    .line 123
    iget-boolean v3, v12, Ll2/t;->S:Z

    .line 124
    .line 125
    if-eqz v3, :cond_6

    .line 126
    .line 127
    invoke-virtual {v12, v11}, Ll2/t;->l(Lay0/a;)V

    .line 128
    .line 129
    .line 130
    goto :goto_5

    .line 131
    :cond_6
    invoke-virtual {v12}, Ll2/t;->m0()V

    .line 132
    .line 133
    .line 134
    :goto_5
    sget-object v3, Lv3/j;->g:Lv3/h;

    .line 135
    .line 136
    invoke-static {v3, v7, v12}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 137
    .line 138
    .line 139
    sget-object v3, Lv3/j;->f:Lv3/h;

    .line 140
    .line 141
    invoke-static {v3, v10, v12}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 142
    .line 143
    .line 144
    sget-object v3, Lv3/j;->j:Lv3/h;

    .line 145
    .line 146
    iget-boolean v7, v12, Ll2/t;->S:Z

    .line 147
    .line 148
    if-nez v7, :cond_7

    .line 149
    .line 150
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 151
    .line 152
    .line 153
    move-result-object v7

    .line 154
    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 155
    .line 156
    .line 157
    move-result-object v10

    .line 158
    invoke-static {v7, v10}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 159
    .line 160
    .line 161
    move-result v7

    .line 162
    if-nez v7, :cond_8

    .line 163
    .line 164
    :cond_7
    invoke-static {v8, v12, v8, v3}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 165
    .line 166
    .line 167
    :cond_8
    sget-object v3, Lv3/j;->d:Lv3/h;

    .line 168
    .line 169
    invoke-static {v3, v5, v12}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 170
    .line 171
    .line 172
    int-to-float v3, v6

    .line 173
    const/4 v5, 0x0

    .line 174
    invoke-static {v14, v3, v5, v4}, Landroidx/compose/foundation/layout/a;->o(Lx2/s;FFI)Lx2/s;

    .line 175
    .line 176
    .line 177
    move-result-object v3

    .line 178
    const/4 v7, 0x6

    .line 179
    const/4 v8, 0x6

    .line 180
    const/4 v4, 0x0

    .line 181
    const/4 v5, 0x0

    .line 182
    move-object v6, v12

    .line 183
    const/high16 v10, 0x3f800000    # 1.0f

    .line 184
    .line 185
    invoke-static/range {v3 .. v8}, Ldk/c;->b(Lx2/s;Lg4/p0;Ljava/lang/String;Ll2/o;II)V

    .line 186
    .line 187
    .line 188
    invoke-static {v14, v10}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 189
    .line 190
    .line 191
    move-result-object v3

    .line 192
    and-int/lit8 v4, v16, 0xe

    .line 193
    .line 194
    if-eq v4, v9, :cond_a

    .line 195
    .line 196
    and-int/lit8 v4, v16, 0x8

    .line 197
    .line 198
    if-eqz v4, :cond_9

    .line 199
    .line 200
    invoke-virtual {v12, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 201
    .line 202
    .line 203
    move-result v4

    .line 204
    if-eqz v4, :cond_9

    .line 205
    .line 206
    goto :goto_6

    .line 207
    :cond_9
    move v4, v13

    .line 208
    goto :goto_7

    .line 209
    :cond_a
    :goto_6
    move v4, v15

    .line 210
    :goto_7
    and-int/lit8 v5, v16, 0x70

    .line 211
    .line 212
    const/16 v6, 0x20

    .line 213
    .line 214
    if-ne v5, v6, :cond_b

    .line 215
    .line 216
    move v13, v15

    .line 217
    :cond_b
    or-int/2addr v4, v13

    .line 218
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 219
    .line 220
    .line 221
    move-result-object v5

    .line 222
    if-nez v4, :cond_c

    .line 223
    .line 224
    sget-object v4, Ll2/n;->a:Ll2/x0;

    .line 225
    .line 226
    if-ne v5, v4, :cond_d

    .line 227
    .line 228
    :cond_c
    new-instance v5, Li40/j0;

    .line 229
    .line 230
    const/16 v4, 0x12

    .line 231
    .line 232
    invoke-direct {v5, v4, v0, v1}, Li40/j0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 233
    .line 234
    .line 235
    invoke-virtual {v12, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 236
    .line 237
    .line 238
    :cond_d
    move-object v11, v5

    .line 239
    check-cast v11, Lay0/k;

    .line 240
    .line 241
    const/4 v13, 0x6

    .line 242
    const/16 v14, 0x1fe

    .line 243
    .line 244
    const/4 v4, 0x0

    .line 245
    const/4 v5, 0x0

    .line 246
    const/4 v6, 0x0

    .line 247
    const/4 v7, 0x0

    .line 248
    const/4 v8, 0x0

    .line 249
    const/4 v9, 0x0

    .line 250
    const/4 v10, 0x0

    .line 251
    invoke-static/range {v3 .. v14}, La/a;->a(Lx2/s;Lm1/t;Lk1/z0;Lk1/i;Lx2/d;Lg1/j1;ZLe1/j;Lay0/k;Ll2/o;II)V

    .line 252
    .line 253
    .line 254
    invoke-virtual {v12, v15}, Ll2/t;->q(Z)V

    .line 255
    .line 256
    .line 257
    goto :goto_8

    .line 258
    :cond_e
    invoke-virtual {v12}, Ll2/t;->R()V

    .line 259
    .line 260
    .line 261
    :goto_8
    invoke-virtual {v12}, Ll2/t;->s()Ll2/u1;

    .line 262
    .line 263
    .line 264
    move-result-object v3

    .line 265
    if-eqz v3, :cond_f

    .line 266
    .line 267
    new-instance v4, Ljk/b;

    .line 268
    .line 269
    const/4 v5, 0x0

    .line 270
    invoke-direct {v4, v2, v5, v0, v1}, Ljk/b;-><init>(IILjava/lang/Object;Ljava/lang/Object;)V

    .line 271
    .line 272
    .line 273
    iput-object v4, v3, Ll2/u1;->d:Lay0/n;

    .line 274
    .line 275
    :cond_f
    return-void
.end method

.method public static final b(Lhe/a;ILay0/k;Ll2/o;I)V
    .locals 27

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move/from16 v2, p1

    .line 4
    .line 5
    move-object/from16 v3, p2

    .line 6
    .line 7
    move/from16 v4, p4

    .line 8
    .line 9
    move-object/from16 v0, p3

    .line 10
    .line 11
    check-cast v0, Ll2/t;

    .line 12
    .line 13
    const v5, -0x50276477

    .line 14
    .line 15
    .line 16
    invoke-virtual {v0, v5}, Ll2/t;->a0(I)Ll2/t;

    .line 17
    .line 18
    .line 19
    and-int/lit8 v5, v4, 0x6

    .line 20
    .line 21
    if-nez v5, :cond_2

    .line 22
    .line 23
    and-int/lit8 v5, v4, 0x8

    .line 24
    .line 25
    if-nez v5, :cond_0

    .line 26
    .line 27
    invoke-virtual {v0, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result v5

    .line 31
    goto :goto_0

    .line 32
    :cond_0
    invoke-virtual {v0, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 33
    .line 34
    .line 35
    move-result v5

    .line 36
    :goto_0
    if-eqz v5, :cond_1

    .line 37
    .line 38
    const/4 v5, 0x4

    .line 39
    goto :goto_1

    .line 40
    :cond_1
    const/4 v5, 0x2

    .line 41
    :goto_1
    or-int/2addr v5, v4

    .line 42
    goto :goto_2

    .line 43
    :cond_2
    move v5, v4

    .line 44
    :goto_2
    and-int/lit8 v7, v4, 0x30

    .line 45
    .line 46
    if-nez v7, :cond_4

    .line 47
    .line 48
    invoke-virtual {v0, v2}, Ll2/t;->e(I)Z

    .line 49
    .line 50
    .line 51
    move-result v7

    .line 52
    if-eqz v7, :cond_3

    .line 53
    .line 54
    const/16 v7, 0x20

    .line 55
    .line 56
    goto :goto_3

    .line 57
    :cond_3
    const/16 v7, 0x10

    .line 58
    .line 59
    :goto_3
    or-int/2addr v5, v7

    .line 60
    :cond_4
    and-int/lit16 v7, v4, 0x180

    .line 61
    .line 62
    if-nez v7, :cond_6

    .line 63
    .line 64
    invoke-virtual {v0, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 65
    .line 66
    .line 67
    move-result v7

    .line 68
    if-eqz v7, :cond_5

    .line 69
    .line 70
    const/16 v7, 0x100

    .line 71
    .line 72
    goto :goto_4

    .line 73
    :cond_5
    const/16 v7, 0x80

    .line 74
    .line 75
    :goto_4
    or-int/2addr v5, v7

    .line 76
    :cond_6
    and-int/lit16 v7, v5, 0x93

    .line 77
    .line 78
    const/16 v10, 0x92

    .line 79
    .line 80
    const/4 v11, 0x0

    .line 81
    if-eq v7, v10, :cond_7

    .line 82
    .line 83
    const/4 v7, 0x1

    .line 84
    goto :goto_5

    .line 85
    :cond_7
    move v7, v11

    .line 86
    :goto_5
    and-int/lit8 v10, v5, 0x1

    .line 87
    .line 88
    invoke-virtual {v0, v10, v7}, Ll2/t;->O(IZ)Z

    .line 89
    .line 90
    .line 91
    move-result v7

    .line 92
    if-eqz v7, :cond_17

    .line 93
    .line 94
    sget-object v7, Lk1/j;->c:Lk1/e;

    .line 95
    .line 96
    sget-object v10, Lx2/c;->p:Lx2/h;

    .line 97
    .line 98
    invoke-static {v7, v10, v0, v11}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 99
    .line 100
    .line 101
    move-result-object v13

    .line 102
    iget-wide v14, v0, Ll2/t;->T:J

    .line 103
    .line 104
    invoke-static {v14, v15}, Ljava/lang/Long;->hashCode(J)I

    .line 105
    .line 106
    .line 107
    move-result v14

    .line 108
    invoke-virtual {v0}, Ll2/t;->m()Ll2/p1;

    .line 109
    .line 110
    .line 111
    move-result-object v15

    .line 112
    sget-object v12, Lx2/p;->b:Lx2/p;

    .line 113
    .line 114
    invoke-static {v0, v12}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 115
    .line 116
    .line 117
    move-result-object v11

    .line 118
    sget-object v16, Lv3/k;->m1:Lv3/j;

    .line 119
    .line 120
    invoke-virtual/range {v16 .. v16}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 121
    .line 122
    .line 123
    sget-object v8, Lv3/j;->b:Lv3/i;

    .line 124
    .line 125
    invoke-virtual {v0}, Ll2/t;->c0()V

    .line 126
    .line 127
    .line 128
    iget-boolean v6, v0, Ll2/t;->S:Z

    .line 129
    .line 130
    if-eqz v6, :cond_8

    .line 131
    .line 132
    invoke-virtual {v0, v8}, Ll2/t;->l(Lay0/a;)V

    .line 133
    .line 134
    .line 135
    goto :goto_6

    .line 136
    :cond_8
    invoke-virtual {v0}, Ll2/t;->m0()V

    .line 137
    .line 138
    .line 139
    :goto_6
    sget-object v6, Lv3/j;->g:Lv3/h;

    .line 140
    .line 141
    invoke-static {v6, v13, v0}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 142
    .line 143
    .line 144
    sget-object v13, Lv3/j;->f:Lv3/h;

    .line 145
    .line 146
    invoke-static {v13, v15, v0}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 147
    .line 148
    .line 149
    sget-object v15, Lv3/j;->j:Lv3/h;

    .line 150
    .line 151
    iget-boolean v9, v0, Ll2/t;->S:Z

    .line 152
    .line 153
    if-nez v9, :cond_9

    .line 154
    .line 155
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 156
    .line 157
    .line 158
    move-result-object v9

    .line 159
    invoke-static {v14}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 160
    .line 161
    .line 162
    move-result-object v4

    .line 163
    invoke-static {v9, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 164
    .line 165
    .line 166
    move-result v4

    .line 167
    if-nez v4, :cond_a

    .line 168
    .line 169
    :cond_9
    invoke-static {v14, v0, v14, v15}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 170
    .line 171
    .line 172
    :cond_a
    sget-object v4, Lv3/j;->d:Lv3/h;

    .line 173
    .line 174
    invoke-static {v4, v11, v0}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 175
    .line 176
    .line 177
    and-int/lit16 v9, v5, 0x380

    .line 178
    .line 179
    const/16 v11, 0x100

    .line 180
    .line 181
    if-ne v9, v11, :cond_b

    .line 182
    .line 183
    const/4 v9, 0x1

    .line 184
    goto :goto_7

    .line 185
    :cond_b
    const/4 v9, 0x0

    .line 186
    :goto_7
    and-int/lit8 v11, v5, 0xe

    .line 187
    .line 188
    const/4 v14, 0x4

    .line 189
    const/16 v24, 0x8

    .line 190
    .line 191
    if-eq v11, v14, :cond_d

    .line 192
    .line 193
    and-int/lit8 v5, v5, 0x8

    .line 194
    .line 195
    if-eqz v5, :cond_c

    .line 196
    .line 197
    invoke-virtual {v0, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 198
    .line 199
    .line 200
    move-result v5

    .line 201
    if-eqz v5, :cond_c

    .line 202
    .line 203
    goto :goto_8

    .line 204
    :cond_c
    const/4 v5, 0x0

    .line 205
    goto :goto_9

    .line 206
    :cond_d
    :goto_8
    const/4 v5, 0x1

    .line 207
    :goto_9
    or-int/2addr v5, v9

    .line 208
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 209
    .line 210
    .line 211
    move-result-object v9

    .line 212
    if-nez v5, :cond_e

    .line 213
    .line 214
    sget-object v5, Ll2/n;->a:Ll2/x0;

    .line 215
    .line 216
    if-ne v9, v5, :cond_f

    .line 217
    .line 218
    :cond_e
    new-instance v9, Li2/t;

    .line 219
    .line 220
    const/16 v5, 0x13

    .line 221
    .line 222
    invoke-direct {v9, v5, v3, v1}, Li2/t;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 223
    .line 224
    .line 225
    invoke-virtual {v0, v9}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 226
    .line 227
    .line 228
    :cond_f
    move-object/from16 v20, v9

    .line 229
    .line 230
    check-cast v20, Lay0/a;

    .line 231
    .line 232
    const/16 v21, 0xf

    .line 233
    .line 234
    const/16 v17, 0x0

    .line 235
    .line 236
    const/16 v18, 0x0

    .line 237
    .line 238
    const/16 v19, 0x0

    .line 239
    .line 240
    move-object/from16 v16, v12

    .line 241
    .line 242
    invoke-static/range {v16 .. v21}, Landroidx/compose/foundation/a;->f(Lx2/s;ZLjava/lang/String;Ld4/i;Lay0/a;I)Lx2/s;

    .line 243
    .line 244
    .line 245
    move-result-object v5

    .line 246
    move-object/from16 v9, v16

    .line 247
    .line 248
    const/high16 v11, 0x3f800000    # 1.0f

    .line 249
    .line 250
    invoke-static {v5, v11}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 251
    .line 252
    .line 253
    move-result-object v5

    .line 254
    move/from16 v11, v24

    .line 255
    .line 256
    int-to-float v11, v11

    .line 257
    const/16 v12, 0x10

    .line 258
    .line 259
    int-to-float v12, v12

    .line 260
    invoke-static {v5, v12, v11}, Landroidx/compose/foundation/layout/a;->n(Lx2/s;FF)Lx2/s;

    .line 261
    .line 262
    .line 263
    move-result-object v5

    .line 264
    sget-object v11, Lk1/j;->g:Lk1/f;

    .line 265
    .line 266
    sget-object v12, Lx2/c;->m:Lx2/i;

    .line 267
    .line 268
    const/4 v14, 0x6

    .line 269
    invoke-static {v11, v12, v0, v14}, Lk1/e1;->a(Lk1/g;Lx2/i;Ll2/o;I)Lk1/g1;

    .line 270
    .line 271
    .line 272
    move-result-object v11

    .line 273
    iget-wide v2, v0, Ll2/t;->T:J

    .line 274
    .line 275
    invoke-static {v2, v3}, Ljava/lang/Long;->hashCode(J)I

    .line 276
    .line 277
    .line 278
    move-result v2

    .line 279
    invoke-virtual {v0}, Ll2/t;->m()Ll2/p1;

    .line 280
    .line 281
    .line 282
    move-result-object v3

    .line 283
    invoke-static {v0, v5}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 284
    .line 285
    .line 286
    move-result-object v5

    .line 287
    invoke-virtual {v0}, Ll2/t;->c0()V

    .line 288
    .line 289
    .line 290
    iget-boolean v12, v0, Ll2/t;->S:Z

    .line 291
    .line 292
    if-eqz v12, :cond_10

    .line 293
    .line 294
    invoke-virtual {v0, v8}, Ll2/t;->l(Lay0/a;)V

    .line 295
    .line 296
    .line 297
    goto :goto_a

    .line 298
    :cond_10
    invoke-virtual {v0}, Ll2/t;->m0()V

    .line 299
    .line 300
    .line 301
    :goto_a
    invoke-static {v6, v11, v0}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 302
    .line 303
    .line 304
    invoke-static {v13, v3, v0}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 305
    .line 306
    .line 307
    iget-boolean v3, v0, Ll2/t;->S:Z

    .line 308
    .line 309
    if-nez v3, :cond_11

    .line 310
    .line 311
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 312
    .line 313
    .line 314
    move-result-object v3

    .line 315
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 316
    .line 317
    .line 318
    move-result-object v11

    .line 319
    invoke-static {v3, v11}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 320
    .line 321
    .line 322
    move-result v3

    .line 323
    if-nez v3, :cond_12

    .line 324
    .line 325
    :cond_11
    invoke-static {v2, v0, v2, v15}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 326
    .line 327
    .line 328
    :cond_12
    invoke-static {v4, v5, v0}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 329
    .line 330
    .line 331
    const/4 v2, 0x0

    .line 332
    invoke-static {v7, v10, v0, v2}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 333
    .line 334
    .line 335
    move-result-object v3

    .line 336
    iget-wide v10, v0, Ll2/t;->T:J

    .line 337
    .line 338
    invoke-static {v10, v11}, Ljava/lang/Long;->hashCode(J)I

    .line 339
    .line 340
    .line 341
    move-result v5

    .line 342
    invoke-virtual {v0}, Ll2/t;->m()Ll2/p1;

    .line 343
    .line 344
    .line 345
    move-result-object v7

    .line 346
    invoke-static {v0, v9}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 347
    .line 348
    .line 349
    move-result-object v10

    .line 350
    invoke-virtual {v0}, Ll2/t;->c0()V

    .line 351
    .line 352
    .line 353
    iget-boolean v11, v0, Ll2/t;->S:Z

    .line 354
    .line 355
    if-eqz v11, :cond_13

    .line 356
    .line 357
    invoke-virtual {v0, v8}, Ll2/t;->l(Lay0/a;)V

    .line 358
    .line 359
    .line 360
    goto :goto_b

    .line 361
    :cond_13
    invoke-virtual {v0}, Ll2/t;->m0()V

    .line 362
    .line 363
    .line 364
    :goto_b
    invoke-static {v6, v3, v0}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 365
    .line 366
    .line 367
    invoke-static {v13, v7, v0}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 368
    .line 369
    .line 370
    iget-boolean v3, v0, Ll2/t;->S:Z

    .line 371
    .line 372
    if-nez v3, :cond_14

    .line 373
    .line 374
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 375
    .line 376
    .line 377
    move-result-object v3

    .line 378
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 379
    .line 380
    .line 381
    move-result-object v6

    .line 382
    invoke-static {v3, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 383
    .line 384
    .line 385
    move-result v3

    .line 386
    if-nez v3, :cond_15

    .line 387
    .line 388
    :cond_14
    invoke-static {v5, v0, v5, v15}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 389
    .line 390
    .line 391
    :cond_15
    invoke-static {v4, v10, v0}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 392
    .line 393
    .line 394
    iget-object v5, v1, Lhe/a;->a:Ljava/lang/String;

    .line 395
    .line 396
    sget-object v3, Lj91/j;->a:Ll2/u2;

    .line 397
    .line 398
    invoke-virtual {v0, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 399
    .line 400
    .line 401
    move-result-object v4

    .line 402
    check-cast v4, Lj91/f;

    .line 403
    .line 404
    invoke-virtual {v4}, Lj91/f;->b()Lg4/p0;

    .line 405
    .line 406
    .line 407
    move-result-object v6

    .line 408
    sget-object v4, Lj91/h;->a:Ll2/u2;

    .line 409
    .line 410
    invoke-virtual {v0, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 411
    .line 412
    .line 413
    move-result-object v7

    .line 414
    check-cast v7, Lj91/e;

    .line 415
    .line 416
    invoke-virtual {v7}, Lj91/e;->q()J

    .line 417
    .line 418
    .line 419
    move-result-wide v7

    .line 420
    const-string v10, "invoice_title_"

    .line 421
    .line 422
    move/from16 v11, p1

    .line 423
    .line 424
    invoke-static {v10, v11, v9}, Lc1/j0;->k(Ljava/lang/String;ILx2/p;)Lx2/s;

    .line 425
    .line 426
    .line 427
    move-result-object v10

    .line 428
    const/16 v25, 0x0

    .line 429
    .line 430
    const v26, 0xfff0

    .line 431
    .line 432
    .line 433
    move-object/from16 v16, v9

    .line 434
    .line 435
    move-wide v8, v7

    .line 436
    move-object v7, v10

    .line 437
    const-wide/16 v10, 0x0

    .line 438
    .line 439
    const/4 v12, 0x0

    .line 440
    const-wide/16 v13, 0x0

    .line 441
    .line 442
    const/4 v15, 0x0

    .line 443
    move-object/from16 v17, v16

    .line 444
    .line 445
    const/16 v16, 0x0

    .line 446
    .line 447
    move-object/from16 v19, v17

    .line 448
    .line 449
    const-wide/16 v17, 0x0

    .line 450
    .line 451
    move-object/from16 v20, v19

    .line 452
    .line 453
    const/16 v19, 0x0

    .line 454
    .line 455
    move-object/from16 v21, v20

    .line 456
    .line 457
    const/16 v20, 0x0

    .line 458
    .line 459
    move-object/from16 v22, v21

    .line 460
    .line 461
    const/16 v21, 0x0

    .line 462
    .line 463
    move-object/from16 v23, v22

    .line 464
    .line 465
    const/16 v22, 0x0

    .line 466
    .line 467
    const/16 v24, 0x0

    .line 468
    .line 469
    move-object/from16 v2, v23

    .line 470
    .line 471
    move-object/from16 v23, v0

    .line 472
    .line 473
    move-object v0, v2

    .line 474
    move/from16 v2, p1

    .line 475
    .line 476
    invoke-static/range {v5 .. v26}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 477
    .line 478
    .line 479
    move-object/from16 v5, v23

    .line 480
    .line 481
    iget-object v6, v1, Lhe/a;->d:Ljava/lang/String;

    .line 482
    .line 483
    invoke-virtual {v5, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 484
    .line 485
    .line 486
    move-result-object v7

    .line 487
    check-cast v7, Lj91/f;

    .line 488
    .line 489
    invoke-virtual {v7}, Lj91/f;->e()Lg4/p0;

    .line 490
    .line 491
    .line 492
    move-result-object v7

    .line 493
    invoke-virtual {v5, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 494
    .line 495
    .line 496
    move-result-object v8

    .line 497
    check-cast v8, Lj91/e;

    .line 498
    .line 499
    invoke-virtual {v8}, Lj91/e;->s()J

    .line 500
    .line 501
    .line 502
    move-result-wide v8

    .line 503
    const-string v10, "invoice_subtitle_"

    .line 504
    .line 505
    invoke-static {v10, v2, v0}, Lc1/j0;->k(Ljava/lang/String;ILx2/p;)Lx2/s;

    .line 506
    .line 507
    .line 508
    move-result-object v10

    .line 509
    move-object v5, v6

    .line 510
    move-object v6, v7

    .line 511
    move-object v7, v10

    .line 512
    const-wide/16 v10, 0x0

    .line 513
    .line 514
    invoke-static/range {v5 .. v26}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 515
    .line 516
    .line 517
    move-object/from16 v5, v23

    .line 518
    .line 519
    const/4 v6, 0x1

    .line 520
    invoke-virtual {v5, v6}, Ll2/t;->q(Z)V

    .line 521
    .line 522
    .line 523
    iget-object v6, v1, Lhe/a;->b:Ljava/lang/String;

    .line 524
    .line 525
    invoke-virtual {v5, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 526
    .line 527
    .line 528
    move-result-object v3

    .line 529
    check-cast v3, Lj91/f;

    .line 530
    .line 531
    invoke-virtual {v3}, Lj91/f;->a()Lg4/p0;

    .line 532
    .line 533
    .line 534
    move-result-object v3

    .line 535
    invoke-virtual {v5, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 536
    .line 537
    .line 538
    move-result-object v4

    .line 539
    check-cast v4, Lj91/e;

    .line 540
    .line 541
    invoke-virtual {v4}, Lj91/e;->s()J

    .line 542
    .line 543
    .line 544
    move-result-wide v8

    .line 545
    const-string v4, "invoice_amount_"

    .line 546
    .line 547
    invoke-static {v4, v2, v0}, Lc1/j0;->k(Ljava/lang/String;ILx2/p;)Lx2/s;

    .line 548
    .line 549
    .line 550
    move-result-object v7

    .line 551
    move-object v5, v6

    .line 552
    move-object v6, v3

    .line 553
    invoke-static/range {v5 .. v26}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 554
    .line 555
    .line 556
    move-object/from16 v5, v23

    .line 557
    .line 558
    const/4 v6, 0x1

    .line 559
    invoke-virtual {v5, v6}, Ll2/t;->q(Z)V

    .line 560
    .line 561
    .line 562
    iget-boolean v0, v1, Lhe/a;->e:Z

    .line 563
    .line 564
    if-nez v0, :cond_16

    .line 565
    .line 566
    const v0, 0x4999cac0    # 1259864.0f

    .line 567
    .line 568
    .line 569
    invoke-virtual {v5, v0}, Ll2/t;->Y(I)V

    .line 570
    .line 571
    .line 572
    const/4 v0, 0x0

    .line 573
    const/4 v3, 0x0

    .line 574
    invoke-static {v3, v6, v5, v0}, Li91/j0;->D(IILl2/o;Lx2/s;)V

    .line 575
    .line 576
    .line 577
    :goto_c
    invoke-virtual {v5, v3}, Ll2/t;->q(Z)V

    .line 578
    .line 579
    .line 580
    goto :goto_d

    .line 581
    :cond_16
    const/4 v3, 0x0

    .line 582
    const v0, 0x493220ef

    .line 583
    .line 584
    .line 585
    invoke-virtual {v5, v0}, Ll2/t;->Y(I)V

    .line 586
    .line 587
    .line 588
    goto :goto_c

    .line 589
    :goto_d
    invoke-virtual {v5, v6}, Ll2/t;->q(Z)V

    .line 590
    .line 591
    .line 592
    goto :goto_e

    .line 593
    :cond_17
    move-object v5, v0

    .line 594
    invoke-virtual {v5}, Ll2/t;->R()V

    .line 595
    .line 596
    .line 597
    :goto_e
    invoke-virtual {v5}, Ll2/t;->s()Ll2/u1;

    .line 598
    .line 599
    .line 600
    move-result-object v6

    .line 601
    if-eqz v6, :cond_18

    .line 602
    .line 603
    new-instance v0, Lck/h;

    .line 604
    .line 605
    const/4 v5, 0x7

    .line 606
    move-object/from16 v3, p2

    .line 607
    .line 608
    move/from16 v4, p4

    .line 609
    .line 610
    invoke-direct/range {v0 .. v5}, Lck/h;-><init>(Ljava/lang/Object;ILay0/k;II)V

    .line 611
    .line 612
    .line 613
    iput-object v0, v6, Ll2/u1;->d:Lay0/n;

    .line 614
    .line 615
    :cond_18
    return-void
.end method

.method public static final c(IILjava/lang/String;Ll2/o;)V
    .locals 24

    .line 1
    move/from16 v0, p0

    .line 2
    .line 3
    move/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v2, p2

    .line 6
    .line 7
    move-object/from16 v3, p3

    .line 8
    .line 9
    check-cast v3, Ll2/t;

    .line 10
    .line 11
    const v4, -0x7ba6ffb4

    .line 12
    .line 13
    .line 14
    invoke-virtual {v3, v4}, Ll2/t;->a0(I)Ll2/t;

    .line 15
    .line 16
    .line 17
    and-int/lit8 v4, v1, 0x6

    .line 18
    .line 19
    if-nez v4, :cond_1

    .line 20
    .line 21
    invoke-virtual {v3, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    move-result v4

    .line 25
    if-eqz v4, :cond_0

    .line 26
    .line 27
    const/4 v4, 0x4

    .line 28
    goto :goto_0

    .line 29
    :cond_0
    const/4 v4, 0x2

    .line 30
    :goto_0
    or-int/2addr v4, v1

    .line 31
    goto :goto_1

    .line 32
    :cond_1
    move v4, v1

    .line 33
    :goto_1
    and-int/lit8 v5, v1, 0x30

    .line 34
    .line 35
    const/16 v6, 0x10

    .line 36
    .line 37
    if-nez v5, :cond_3

    .line 38
    .line 39
    invoke-virtual {v3, v0}, Ll2/t;->e(I)Z

    .line 40
    .line 41
    .line 42
    move-result v5

    .line 43
    if-eqz v5, :cond_2

    .line 44
    .line 45
    const/16 v5, 0x20

    .line 46
    .line 47
    goto :goto_2

    .line 48
    :cond_2
    move v5, v6

    .line 49
    :goto_2
    or-int/2addr v4, v5

    .line 50
    :cond_3
    and-int/lit8 v5, v4, 0x13

    .line 51
    .line 52
    const/16 v7, 0x12

    .line 53
    .line 54
    if-eq v5, v7, :cond_4

    .line 55
    .line 56
    const/4 v5, 0x1

    .line 57
    goto :goto_3

    .line 58
    :cond_4
    const/4 v5, 0x0

    .line 59
    :goto_3
    and-int/lit8 v7, v4, 0x1

    .line 60
    .line 61
    invoke-virtual {v3, v7, v5}, Ll2/t;->O(IZ)Z

    .line 62
    .line 63
    .line 64
    move-result v5

    .line 65
    if-eqz v5, :cond_5

    .line 66
    .line 67
    sget-object v5, Lj91/j;->a:Ll2/u2;

    .line 68
    .line 69
    invoke-virtual {v3, v5}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    move-result-object v5

    .line 73
    check-cast v5, Lj91/f;

    .line 74
    .line 75
    invoke-virtual {v5}, Lj91/f;->k()Lg4/p0;

    .line 76
    .line 77
    .line 78
    move-result-object v5

    .line 79
    sget-object v7, Lj91/h;->a:Ll2/u2;

    .line 80
    .line 81
    invoke-virtual {v3, v7}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object v7

    .line 85
    check-cast v7, Lj91/e;

    .line 86
    .line 87
    invoke-virtual {v7}, Lj91/e;->q()J

    .line 88
    .line 89
    .line 90
    move-result-wide v7

    .line 91
    const/16 v9, 0x18

    .line 92
    .line 93
    int-to-float v9, v9

    .line 94
    int-to-float v6, v6

    .line 95
    sget-object v10, Lx2/p;->b:Lx2/p;

    .line 96
    .line 97
    invoke-static {v10, v6, v9, v6, v6}, Landroidx/compose/foundation/layout/a;->p(Lx2/s;FFFF)Lx2/s;

    .line 98
    .line 99
    .line 100
    move-result-object v6

    .line 101
    new-instance v9, Ljava/lang/StringBuilder;

    .line 102
    .line 103
    const-string v10, "invoice_year_"

    .line 104
    .line 105
    invoke-direct {v9, v10}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 106
    .line 107
    .line 108
    invoke-virtual {v9, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 109
    .line 110
    .line 111
    invoke-virtual {v9}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 112
    .line 113
    .line 114
    move-result-object v9

    .line 115
    invoke-static {v6, v9}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 116
    .line 117
    .line 118
    move-result-object v6

    .line 119
    and-int/lit8 v21, v4, 0xe

    .line 120
    .line 121
    const/16 v22, 0x0

    .line 122
    .line 123
    const v23, 0xfff0

    .line 124
    .line 125
    .line 126
    move-object/from16 v20, v3

    .line 127
    .line 128
    move-object v3, v5

    .line 129
    move-object v4, v6

    .line 130
    move-wide v5, v7

    .line 131
    const-wide/16 v7, 0x0

    .line 132
    .line 133
    const/4 v9, 0x0

    .line 134
    const-wide/16 v10, 0x0

    .line 135
    .line 136
    const/4 v12, 0x0

    .line 137
    const/4 v13, 0x0

    .line 138
    const-wide/16 v14, 0x0

    .line 139
    .line 140
    const/16 v16, 0x0

    .line 141
    .line 142
    const/16 v17, 0x0

    .line 143
    .line 144
    const/16 v18, 0x0

    .line 145
    .line 146
    const/16 v19, 0x0

    .line 147
    .line 148
    invoke-static/range {v2 .. v23}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 149
    .line 150
    .line 151
    goto :goto_4

    .line 152
    :cond_5
    move-object/from16 v20, v3

    .line 153
    .line 154
    invoke-virtual/range {v20 .. v20}, Ll2/t;->R()V

    .line 155
    .line 156
    .line 157
    :goto_4
    invoke-virtual/range {v20 .. v20}, Ll2/t;->s()Ll2/u1;

    .line 158
    .line 159
    .line 160
    move-result-object v3

    .line 161
    if-eqz v3, :cond_6

    .line 162
    .line 163
    new-instance v4, Lck/d;

    .line 164
    .line 165
    const/4 v5, 0x1

    .line 166
    invoke-direct {v4, v2, v0, v1, v5}, Lck/d;-><init>(Ljava/lang/String;III)V

    .line 167
    .line 168
    .line 169
    iput-object v4, v3, Ll2/u1;->d:Lay0/n;

    .line 170
    .line 171
    :cond_6
    return-void
.end method

.method public static final d(Ll2/o;I)V
    .locals 8

    .line 1
    move-object v3, p0

    .line 2
    check-cast v3, Ll2/t;

    .line 3
    .line 4
    const p0, 0x14ca9206

    .line 5
    .line 6
    .line 7
    invoke-virtual {v3, p0}, Ll2/t;->a0(I)Ll2/t;

    .line 8
    .line 9
    .line 10
    const/4 p0, 0x0

    .line 11
    const/4 v7, 0x1

    .line 12
    if-eqz p1, :cond_0

    .line 13
    .line 14
    move v0, v7

    .line 15
    goto :goto_0

    .line 16
    :cond_0
    move v0, p0

    .line 17
    :goto_0
    and-int/lit8 v1, p1, 0x1

    .line 18
    .line 19
    invoke-virtual {v3, v1, v0}, Ll2/t;->O(IZ)Z

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    if-eqz v0, :cond_4

    .line 24
    .line 25
    sget-object v0, Lk1/j;->c:Lk1/e;

    .line 26
    .line 27
    sget-object v1, Lx2/c;->p:Lx2/h;

    .line 28
    .line 29
    invoke-static {v0, v1, v3, p0}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    iget-wide v0, v3, Ll2/t;->T:J

    .line 34
    .line 35
    invoke-static {v0, v1}, Ljava/lang/Long;->hashCode(J)I

    .line 36
    .line 37
    .line 38
    move-result v0

    .line 39
    invoke-virtual {v3}, Ll2/t;->m()Ll2/p1;

    .line 40
    .line 41
    .line 42
    move-result-object v1

    .line 43
    sget-object v2, Lx2/p;->b:Lx2/p;

    .line 44
    .line 45
    invoke-static {v3, v2}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 46
    .line 47
    .line 48
    move-result-object v4

    .line 49
    sget-object v5, Lv3/k;->m1:Lv3/j;

    .line 50
    .line 51
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 52
    .line 53
    .line 54
    sget-object v5, Lv3/j;->b:Lv3/i;

    .line 55
    .line 56
    invoke-virtual {v3}, Ll2/t;->c0()V

    .line 57
    .line 58
    .line 59
    iget-boolean v6, v3, Ll2/t;->S:Z

    .line 60
    .line 61
    if-eqz v6, :cond_1

    .line 62
    .line 63
    invoke-virtual {v3, v5}, Ll2/t;->l(Lay0/a;)V

    .line 64
    .line 65
    .line 66
    goto :goto_1

    .line 67
    :cond_1
    invoke-virtual {v3}, Ll2/t;->m0()V

    .line 68
    .line 69
    .line 70
    :goto_1
    sget-object v5, Lv3/j;->g:Lv3/h;

    .line 71
    .line 72
    invoke-static {v5, p0, v3}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 73
    .line 74
    .line 75
    sget-object p0, Lv3/j;->f:Lv3/h;

    .line 76
    .line 77
    invoke-static {p0, v1, v3}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 78
    .line 79
    .line 80
    sget-object p0, Lv3/j;->j:Lv3/h;

    .line 81
    .line 82
    iget-boolean v1, v3, Ll2/t;->S:Z

    .line 83
    .line 84
    if-nez v1, :cond_2

    .line 85
    .line 86
    invoke-virtual {v3}, Ll2/t;->L()Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    move-result-object v1

    .line 90
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 91
    .line 92
    .line 93
    move-result-object v5

    .line 94
    invoke-static {v1, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 95
    .line 96
    .line 97
    move-result v1

    .line 98
    if-nez v1, :cond_3

    .line 99
    .line 100
    :cond_2
    invoke-static {v0, v3, v0, p0}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 101
    .line 102
    .line 103
    :cond_3
    sget-object p0, Lv3/j;->d:Lv3/h;

    .line 104
    .line 105
    invoke-static {p0, v4, v3}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 106
    .line 107
    .line 108
    const/16 p0, 0x10

    .line 109
    .line 110
    int-to-float p0, p0

    .line 111
    const/4 v0, 0x0

    .line 112
    const/4 v1, 0x2

    .line 113
    invoke-static {v2, p0, v0, v1}, Landroidx/compose/foundation/layout/a;->o(Lx2/s;FFI)Lx2/s;

    .line 114
    .line 115
    .line 116
    move-result-object v0

    .line 117
    const/4 v4, 0x6

    .line 118
    const/4 v5, 0x6

    .line 119
    const/4 v1, 0x0

    .line 120
    const/4 v2, 0x0

    .line 121
    invoke-static/range {v0 .. v5}, Ldk/c;->b(Lx2/s;Lg4/p0;Ljava/lang/String;Ll2/o;II)V

    .line 122
    .line 123
    .line 124
    const/4 v4, 0x0

    .line 125
    const/16 v6, 0x6c06

    .line 126
    .line 127
    const-string v0, "invoice"

    .line 128
    .line 129
    const v1, 0x7f120a49

    .line 130
    .line 131
    .line 132
    const v2, 0x7f120a48

    .line 133
    .line 134
    .line 135
    move-object v5, v3

    .line 136
    const/4 v3, 0x0

    .line 137
    invoke-static/range {v0 .. v6}, Ldk/e;->a(Ljava/lang/String;IIILay0/a;Ll2/o;I)V

    .line 138
    .line 139
    .line 140
    move-object v3, v5

    .line 141
    invoke-virtual {v3, v7}, Ll2/t;->q(Z)V

    .line 142
    .line 143
    .line 144
    goto :goto_2

    .line 145
    :cond_4
    invoke-virtual {v3}, Ll2/t;->R()V

    .line 146
    .line 147
    .line 148
    :goto_2
    invoke-virtual {v3}, Ll2/t;->s()Ll2/u1;

    .line 149
    .line 150
    .line 151
    move-result-object p0

    .line 152
    if-eqz p0, :cond_5

    .line 153
    .line 154
    new-instance v0, Ljc0/b;

    .line 155
    .line 156
    const/16 v1, 0x12

    .line 157
    .line 158
    invoke-direct {v0, p1, v1}, Ljc0/b;-><init>(II)V

    .line 159
    .line 160
    .line 161
    iput-object v0, p0, Ll2/u1;->d:Lay0/n;

    .line 162
    .line 163
    :cond_5
    return-void
.end method

.method public static final e(Llc/q;Lay0/k;Ll2/o;I)V
    .locals 10

    .line 1
    const-string v0, "uiState"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "event"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    move-object v7, p2

    .line 12
    check-cast v7, Ll2/t;

    .line 13
    .line 14
    const p2, -0xeff75b6

    .line 15
    .line 16
    .line 17
    invoke-virtual {v7, p2}, Ll2/t;->a0(I)Ll2/t;

    .line 18
    .line 19
    .line 20
    invoke-virtual {v7, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 21
    .line 22
    .line 23
    move-result p2

    .line 24
    if-eqz p2, :cond_0

    .line 25
    .line 26
    const/4 p2, 0x4

    .line 27
    goto :goto_0

    .line 28
    :cond_0
    const/4 p2, 0x2

    .line 29
    :goto_0
    or-int/2addr p2, p3

    .line 30
    invoke-virtual {v7, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    if-eqz v0, :cond_1

    .line 35
    .line 36
    const/16 v0, 0x20

    .line 37
    .line 38
    goto :goto_1

    .line 39
    :cond_1
    const/16 v0, 0x10

    .line 40
    .line 41
    :goto_1
    or-int/2addr p2, v0

    .line 42
    and-int/lit8 v0, p2, 0x13

    .line 43
    .line 44
    const/16 v1, 0x12

    .line 45
    .line 46
    if-eq v0, v1, :cond_2

    .line 47
    .line 48
    const/4 v0, 0x1

    .line 49
    goto :goto_2

    .line 50
    :cond_2
    const/4 v0, 0x0

    .line 51
    :goto_2
    and-int/lit8 v1, p2, 0x1

    .line 52
    .line 53
    invoke-virtual {v7, v1, v0}, Ll2/t;->O(IZ)Z

    .line 54
    .line 55
    .line 56
    move-result v0

    .line 57
    if-eqz v0, :cond_3

    .line 58
    .line 59
    new-instance v0, Lak/l;

    .line 60
    .line 61
    const/16 v1, 0xf

    .line 62
    .line 63
    invoke-direct {v0, v1, p1}, Lak/l;-><init>(ILay0/k;)V

    .line 64
    .line 65
    .line 66
    const v1, -0x75191338

    .line 67
    .line 68
    .line 69
    invoke-static {v1, v7, v0}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 70
    .line 71
    .line 72
    move-result-object v4

    .line 73
    new-instance v0, Lak/l;

    .line 74
    .line 75
    const/16 v1, 0x10

    .line 76
    .line 77
    invoke-direct {v0, v1, p1}, Lak/l;-><init>(ILay0/k;)V

    .line 78
    .line 79
    .line 80
    const v1, -0x5e91dbe5

    .line 81
    .line 82
    .line 83
    invoke-static {v1, v7, v0}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 84
    .line 85
    .line 86
    move-result-object v5

    .line 87
    and-int/lit8 p2, p2, 0xe

    .line 88
    .line 89
    const v0, 0x36db8

    .line 90
    .line 91
    .line 92
    or-int v8, v0, p2

    .line 93
    .line 94
    const/4 v9, 0x0

    .line 95
    sget-object v2, Ljk/a;->a:Lt2/b;

    .line 96
    .line 97
    sget-object v3, Ljk/a;->b:Lt2/b;

    .line 98
    .line 99
    sget-object v6, Ljk/a;->c:Lt2/b;

    .line 100
    .line 101
    move-object v1, p0

    .line 102
    invoke-static/range {v1 .. v9}, Llc/a;->a(Llc/q;Lay0/o;Lay0/o;Lt2/b;Lt2/b;Lay0/n;Ll2/o;II)V

    .line 103
    .line 104
    .line 105
    goto :goto_3

    .line 106
    :cond_3
    move-object v1, p0

    .line 107
    invoke-virtual {v7}, Ll2/t;->R()V

    .line 108
    .line 109
    .line 110
    :goto_3
    invoke-virtual {v7}, Ll2/t;->s()Ll2/u1;

    .line 111
    .line 112
    .line 113
    move-result-object p0

    .line 114
    if-eqz p0, :cond_4

    .line 115
    .line 116
    new-instance p2, Lak/m;

    .line 117
    .line 118
    const/4 v0, 0x5

    .line 119
    invoke-direct {p2, v1, p1, p3, v0}, Lak/m;-><init>(Llc/q;Lay0/k;II)V

    .line 120
    .line 121
    .line 122
    iput-object p2, p0, Ll2/u1;->d:Lay0/n;

    .line 123
    .line 124
    :cond_4
    return-void
.end method
