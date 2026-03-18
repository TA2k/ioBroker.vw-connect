.class public abstract Li00/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:F


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const/16 v0, 0xdc

    .line 2
    .line 3
    int-to-float v0, v0

    .line 4
    sput v0, Li00/c;->a:F

    .line 5
    .line 6
    return-void
.end method

.method public static final a(Lh00/b;Lay0/a;Lx2/s;Ll2/o;I)V
    .locals 29

    .line 1
    move-object/from16 v3, p0

    .line 2
    .line 3
    move-object/from16 v5, p2

    .line 4
    .line 5
    move-object/from16 v12, p3

    .line 6
    .line 7
    check-cast v12, Ll2/t;

    .line 8
    .line 9
    const v0, -0x51196ac4

    .line 10
    .line 11
    .line 12
    invoke-virtual {v12, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 13
    .line 14
    .line 15
    invoke-virtual {v12, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    if-eqz v0, :cond_0

    .line 20
    .line 21
    const/4 v0, 0x4

    .line 22
    goto :goto_0

    .line 23
    :cond_0
    const/4 v0, 0x2

    .line 24
    :goto_0
    or-int v0, p4, v0

    .line 25
    .line 26
    move-object/from16 v4, p1

    .line 27
    .line 28
    invoke-virtual {v12, v4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result v1

    .line 32
    if-eqz v1, :cond_1

    .line 33
    .line 34
    const/16 v1, 0x20

    .line 35
    .line 36
    goto :goto_1

    .line 37
    :cond_1
    const/16 v1, 0x10

    .line 38
    .line 39
    :goto_1
    or-int/2addr v0, v1

    .line 40
    invoke-virtual {v12, v5}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 41
    .line 42
    .line 43
    move-result v1

    .line 44
    if-eqz v1, :cond_2

    .line 45
    .line 46
    const/16 v1, 0x100

    .line 47
    .line 48
    goto :goto_2

    .line 49
    :cond_2
    const/16 v1, 0x80

    .line 50
    .line 51
    :goto_2
    or-int/2addr v0, v1

    .line 52
    and-int/lit16 v1, v0, 0x93

    .line 53
    .line 54
    const/16 v2, 0x92

    .line 55
    .line 56
    const/4 v6, 0x0

    .line 57
    const/4 v7, 0x1

    .line 58
    if-eq v1, v2, :cond_3

    .line 59
    .line 60
    move v1, v7

    .line 61
    goto :goto_3

    .line 62
    :cond_3
    move v1, v6

    .line 63
    :goto_3
    and-int/lit8 v2, v0, 0x1

    .line 64
    .line 65
    invoke-virtual {v12, v2, v1}, Ll2/t;->O(IZ)Z

    .line 66
    .line 67
    .line 68
    move-result v1

    .line 69
    if-eqz v1, :cond_9

    .line 70
    .line 71
    sget-object v1, Lk1/j;->a:Lk1/c;

    .line 72
    .line 73
    sget-object v2, Lx2/c;->m:Lx2/i;

    .line 74
    .line 75
    invoke-static {v1, v2, v12, v6}, Lk1/e1;->a(Lk1/g;Lx2/i;Ll2/o;I)Lk1/g1;

    .line 76
    .line 77
    .line 78
    move-result-object v1

    .line 79
    iget-wide v8, v12, Ll2/t;->T:J

    .line 80
    .line 81
    invoke-static {v8, v9}, Ljava/lang/Long;->hashCode(J)I

    .line 82
    .line 83
    .line 84
    move-result v2

    .line 85
    invoke-virtual {v12}, Ll2/t;->m()Ll2/p1;

    .line 86
    .line 87
    .line 88
    move-result-object v6

    .line 89
    invoke-static {v12, v5}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 90
    .line 91
    .line 92
    move-result-object v8

    .line 93
    sget-object v9, Lv3/k;->m1:Lv3/j;

    .line 94
    .line 95
    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 96
    .line 97
    .line 98
    sget-object v9, Lv3/j;->b:Lv3/i;

    .line 99
    .line 100
    invoke-virtual {v12}, Ll2/t;->c0()V

    .line 101
    .line 102
    .line 103
    iget-boolean v10, v12, Ll2/t;->S:Z

    .line 104
    .line 105
    if-eqz v10, :cond_4

    .line 106
    .line 107
    invoke-virtual {v12, v9}, Ll2/t;->l(Lay0/a;)V

    .line 108
    .line 109
    .line 110
    goto :goto_4

    .line 111
    :cond_4
    invoke-virtual {v12}, Ll2/t;->m0()V

    .line 112
    .line 113
    .line 114
    :goto_4
    sget-object v9, Lv3/j;->g:Lv3/h;

    .line 115
    .line 116
    invoke-static {v9, v1, v12}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 117
    .line 118
    .line 119
    sget-object v1, Lv3/j;->f:Lv3/h;

    .line 120
    .line 121
    invoke-static {v1, v6, v12}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 122
    .line 123
    .line 124
    sget-object v1, Lv3/j;->j:Lv3/h;

    .line 125
    .line 126
    iget-boolean v6, v12, Ll2/t;->S:Z

    .line 127
    .line 128
    if-nez v6, :cond_5

    .line 129
    .line 130
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 131
    .line 132
    .line 133
    move-result-object v6

    .line 134
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 135
    .line 136
    .line 137
    move-result-object v9

    .line 138
    invoke-static {v6, v9}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 139
    .line 140
    .line 141
    move-result v6

    .line 142
    if-nez v6, :cond_6

    .line 143
    .line 144
    :cond_5
    invoke-static {v2, v12, v2, v1}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 145
    .line 146
    .line 147
    :cond_6
    sget-object v1, Lv3/j;->d:Lv3/h;

    .line 148
    .line 149
    invoke-static {v1, v8, v12}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 150
    .line 151
    .line 152
    iget-object v6, v3, Lh00/b;->b:Ljava/lang/String;

    .line 153
    .line 154
    sget-object v1, Lj91/j;->a:Ll2/u2;

    .line 155
    .line 156
    invoke-virtual {v12, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 157
    .line 158
    .line 159
    move-result-object v1

    .line 160
    check-cast v1, Lj91/f;

    .line 161
    .line 162
    invoke-virtual {v1}, Lj91/f;->h()Lg4/p0;

    .line 163
    .line 164
    .line 165
    move-result-object v1

    .line 166
    const/high16 v2, 0x3f800000    # 1.0f

    .line 167
    .line 168
    float-to-double v8, v2

    .line 169
    const-wide/16 v10, 0x0

    .line 170
    .line 171
    cmpl-double v8, v8, v10

    .line 172
    .line 173
    if-lez v8, :cond_7

    .line 174
    .line 175
    goto :goto_5

    .line 176
    :cond_7
    const-string v8, "invalid weight; must be greater than zero"

    .line 177
    .line 178
    invoke-static {v8}, Ll1/a;->a(Ljava/lang/String;)V

    .line 179
    .line 180
    .line 181
    :goto_5
    new-instance v8, Landroidx/compose/foundation/layout/LayoutWeightElement;

    .line 182
    .line 183
    const v9, 0x7f7fffff    # Float.MAX_VALUE

    .line 184
    .line 185
    .line 186
    cmpl-float v10, v2, v9

    .line 187
    .line 188
    if-lez v10, :cond_8

    .line 189
    .line 190
    move v2, v9

    .line 191
    :cond_8
    invoke-direct {v8, v2, v7}, Landroidx/compose/foundation/layout/LayoutWeightElement;-><init>(FZ)V

    .line 192
    .line 193
    .line 194
    iget-boolean v2, v3, Lh00/b;->d:Z

    .line 195
    .line 196
    invoke-static {v8, v2}, Lxf0/y1;->H(Lx2/s;Z)Lx2/s;

    .line 197
    .line 198
    .line 199
    move-result-object v8

    .line 200
    const/16 v26, 0x6180

    .line 201
    .line 202
    const v27, 0xaff8

    .line 203
    .line 204
    .line 205
    const-wide/16 v9, 0x0

    .line 206
    .line 207
    move-object/from16 v24, v12

    .line 208
    .line 209
    const-wide/16 v11, 0x0

    .line 210
    .line 211
    const/4 v13, 0x0

    .line 212
    const-wide/16 v14, 0x0

    .line 213
    .line 214
    const/16 v16, 0x0

    .line 215
    .line 216
    const/16 v17, 0x0

    .line 217
    .line 218
    const-wide/16 v18, 0x0

    .line 219
    .line 220
    const/16 v20, 0x2

    .line 221
    .line 222
    const/16 v21, 0x0

    .line 223
    .line 224
    const/16 v22, 0x1

    .line 225
    .line 226
    const/16 v23, 0x0

    .line 227
    .line 228
    const/16 v25, 0x0

    .line 229
    .line 230
    move/from16 v28, v7

    .line 231
    .line 232
    move-object v7, v1

    .line 233
    move/from16 v1, v28

    .line 234
    .line 235
    invoke-static/range {v6 .. v27}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 236
    .line 237
    .line 238
    move-object/from16 v12, v24

    .line 239
    .line 240
    new-instance v2, Lh60/b;

    .line 241
    .line 242
    const/16 v6, 0xc

    .line 243
    .line 244
    invoke-direct {v2, v6}, Lh60/b;-><init>(I)V

    .line 245
    .line 246
    .line 247
    const v6, 0x4d19db3e    # 1.61330144E8f

    .line 248
    .line 249
    .line 250
    invoke-static {v6, v12, v2}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 251
    .line 252
    .line 253
    move-result-object v11

    .line 254
    shr-int/lit8 v0, v0, 0x3

    .line 255
    .line 256
    and-int/lit8 v0, v0, 0xe

    .line 257
    .line 258
    const/high16 v2, 0x180000

    .line 259
    .line 260
    or-int v13, v0, v2

    .line 261
    .line 262
    const/16 v14, 0x3e

    .line 263
    .line 264
    const/4 v7, 0x0

    .line 265
    const/4 v8, 0x0

    .line 266
    const/4 v9, 0x0

    .line 267
    const/4 v10, 0x0

    .line 268
    move-object v6, v4

    .line 269
    invoke-static/range {v6 .. v14}, Lh2/r;->l(Lay0/a;Lx2/s;ZLh2/d5;Le3/n0;Lay0/n;Ll2/o;II)V

    .line 270
    .line 271
    .line 272
    invoke-virtual {v12, v1}, Ll2/t;->q(Z)V

    .line 273
    .line 274
    .line 275
    goto :goto_6

    .line 276
    :cond_9
    invoke-virtual {v12}, Ll2/t;->R()V

    .line 277
    .line 278
    .line 279
    :goto_6
    invoke-virtual {v12}, Ll2/t;->s()Ll2/u1;

    .line 280
    .line 281
    .line 282
    move-result-object v6

    .line 283
    if-eqz v6, :cond_a

    .line 284
    .line 285
    new-instance v0, Lf20/f;

    .line 286
    .line 287
    const/16 v2, 0xa

    .line 288
    .line 289
    move-object/from16 v4, p1

    .line 290
    .line 291
    move/from16 v1, p4

    .line 292
    .line 293
    invoke-direct/range {v0 .. v5}, Lf20/f;-><init>(IILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 294
    .line 295
    .line 296
    iput-object v0, v6, Ll2/u1;->d:Lay0/n;

    .line 297
    .line 298
    :cond_a
    return-void
.end method

.method public static final b(Ll2/o;I)V
    .locals 13

    .line 1
    move-object v4, p0

    .line 2
    check-cast v4, Ll2/t;

    .line 3
    .line 4
    const p0, -0x5b8eda38

    .line 5
    .line 6
    .line 7
    invoke-virtual {v4, p0}, Ll2/t;->a0(I)Ll2/t;

    .line 8
    .line 9
    .line 10
    const/4 p0, 0x1

    .line 11
    const/4 v0, 0x0

    .line 12
    if-eqz p1, :cond_0

    .line 13
    .line 14
    move v1, p0

    .line 15
    goto :goto_0

    .line 16
    :cond_0
    move v1, v0

    .line 17
    :goto_0
    and-int/lit8 v2, p1, 0x1

    .line 18
    .line 19
    invoke-virtual {v4, v2, v1}, Ll2/t;->O(IZ)Z

    .line 20
    .line 21
    .line 22
    move-result v1

    .line 23
    if-eqz v1, :cond_8

    .line 24
    .line 25
    const v1, -0x6040e0aa

    .line 26
    .line 27
    .line 28
    invoke-virtual {v4, v1}, Ll2/t;->Y(I)V

    .line 29
    .line 30
    .line 31
    invoke-static {v4}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 32
    .line 33
    .line 34
    move-result-object v1

    .line 35
    if-eqz v1, :cond_7

    .line 36
    .line 37
    invoke-static {v1}, Ljp/ib;->a(Landroidx/lifecycle/i1;)Lp7/c;

    .line 38
    .line 39
    .line 40
    move-result-object v8

    .line 41
    invoke-static {v4}, Lw11/c;->b(Ll2/o;)Lk21/a;

    .line 42
    .line 43
    .line 44
    move-result-object v10

    .line 45
    const-class v2, Lh00/c;

    .line 46
    .line 47
    sget-object v3, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 48
    .line 49
    invoke-virtual {v3, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 50
    .line 51
    .line 52
    move-result-object v5

    .line 53
    invoke-interface {v1}, Landroidx/lifecycle/i1;->getViewModelStore()Landroidx/lifecycle/h1;

    .line 54
    .line 55
    .line 56
    move-result-object v6

    .line 57
    const/4 v7, 0x0

    .line 58
    const/4 v9, 0x0

    .line 59
    const/4 v11, 0x0

    .line 60
    invoke-static/range {v5 .. v11}, Ljp/lb;->a(Lhy0/d;Landroidx/lifecycle/h1;Ljava/lang/String;Lp7/c;Lh21/b;Lk21/a;Lay0/a;)Landroidx/lifecycle/b1;

    .line 61
    .line 62
    .line 63
    move-result-object v1

    .line 64
    invoke-virtual {v4, v0}, Ll2/t;->q(Z)V

    .line 65
    .line 66
    .line 67
    check-cast v1, Lql0/j;

    .line 68
    .line 69
    invoke-static {v1, v4, v0, p0}, Lkp/x5;->b(Lql0/j;Ll2/o;II)V

    .line 70
    .line 71
    .line 72
    move-object v7, v1

    .line 73
    check-cast v7, Lh00/c;

    .line 74
    .line 75
    iget-object v0, v7, Lql0/j;->g:Lyy0/l1;

    .line 76
    .line 77
    const/4 v1, 0x0

    .line 78
    invoke-static {v0, v1, v4, p0}, Ll2/b;->f(Lyy0/a2;Lwy0/c;Ll2/o;I)Ll2/b1;

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    invoke-interface {p0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    move-result-object p0

    .line 86
    move-object v0, p0

    .line 87
    check-cast v0, Lh00/b;

    .line 88
    .line 89
    invoke-virtual {v4, v7}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 90
    .line 91
    .line 92
    move-result p0

    .line 93
    invoke-virtual {v4}, Ll2/t;->L()Ljava/lang/Object;

    .line 94
    .line 95
    .line 96
    move-result-object v1

    .line 97
    sget-object v2, Ll2/n;->a:Ll2/x0;

    .line 98
    .line 99
    if-nez p0, :cond_1

    .line 100
    .line 101
    if-ne v1, v2, :cond_2

    .line 102
    .line 103
    :cond_1
    new-instance v5, Lh90/d;

    .line 104
    .line 105
    const/4 v11, 0x0

    .line 106
    const/16 v12, 0xb

    .line 107
    .line 108
    const/4 v6, 0x0

    .line 109
    const-class v8, Lh00/c;

    .line 110
    .line 111
    const-string v9, "onClose"

    .line 112
    .line 113
    const-string v10, "onClose()V"

    .line 114
    .line 115
    invoke-direct/range {v5 .. v12}, Lh90/d;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 116
    .line 117
    .line 118
    invoke-virtual {v4, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 119
    .line 120
    .line 121
    move-object v1, v5

    .line 122
    :cond_2
    check-cast v1, Lhy0/g;

    .line 123
    .line 124
    check-cast v1, Lay0/a;

    .line 125
    .line 126
    invoke-virtual {v4, v7}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 127
    .line 128
    .line 129
    move-result p0

    .line 130
    invoke-virtual {v4}, Ll2/t;->L()Ljava/lang/Object;

    .line 131
    .line 132
    .line 133
    move-result-object v3

    .line 134
    if-nez p0, :cond_3

    .line 135
    .line 136
    if-ne v3, v2, :cond_4

    .line 137
    .line 138
    :cond_3
    new-instance v5, Lh90/d;

    .line 139
    .line 140
    const/4 v11, 0x0

    .line 141
    const/16 v12, 0xc

    .line 142
    .line 143
    const/4 v6, 0x0

    .line 144
    const-class v8, Lh00/c;

    .line 145
    .line 146
    const-string v9, "onOpenEnrollment"

    .line 147
    .line 148
    const-string v10, "onOpenEnrollment()V"

    .line 149
    .line 150
    invoke-direct/range {v5 .. v12}, Lh90/d;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 151
    .line 152
    .line 153
    invoke-virtual {v4, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 154
    .line 155
    .line 156
    move-object v3, v5

    .line 157
    :cond_4
    check-cast v3, Lhy0/g;

    .line 158
    .line 159
    check-cast v3, Lay0/a;

    .line 160
    .line 161
    invoke-virtual {v4, v7}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 162
    .line 163
    .line 164
    move-result p0

    .line 165
    invoke-virtual {v4}, Ll2/t;->L()Ljava/lang/Object;

    .line 166
    .line 167
    .line 168
    move-result-object v5

    .line 169
    if-nez p0, :cond_5

    .line 170
    .line 171
    if-ne v5, v2, :cond_6

    .line 172
    .line 173
    :cond_5
    new-instance v5, Lh90/d;

    .line 174
    .line 175
    const/4 v11, 0x0

    .line 176
    const/16 v12, 0xd

    .line 177
    .line 178
    const/4 v6, 0x0

    .line 179
    const-class v8, Lh00/c;

    .line 180
    .line 181
    const-string v9, "onCloseError"

    .line 182
    .line 183
    const-string v10, "onCloseError()V"

    .line 184
    .line 185
    invoke-direct/range {v5 .. v12}, Lh90/d;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 186
    .line 187
    .line 188
    invoke-virtual {v4, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 189
    .line 190
    .line 191
    :cond_6
    check-cast v5, Lhy0/g;

    .line 192
    .line 193
    check-cast v5, Lay0/a;

    .line 194
    .line 195
    move-object v2, v3

    .line 196
    move-object v3, v5

    .line 197
    const/16 v5, 0x8

    .line 198
    .line 199
    invoke-static/range {v0 .. v5}, Li00/c;->c(Lh00/b;Lay0/a;Lay0/a;Lay0/a;Ll2/o;I)V

    .line 200
    .line 201
    .line 202
    goto :goto_1

    .line 203
    :cond_7
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 204
    .line 205
    const-string p1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 206
    .line 207
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 208
    .line 209
    .line 210
    throw p0

    .line 211
    :cond_8
    invoke-virtual {v4}, Ll2/t;->R()V

    .line 212
    .line 213
    .line 214
    :goto_1
    invoke-virtual {v4}, Ll2/t;->s()Ll2/u1;

    .line 215
    .line 216
    .line 217
    move-result-object p0

    .line 218
    if-eqz p0, :cond_9

    .line 219
    .line 220
    new-instance v0, Lh60/b;

    .line 221
    .line 222
    const/16 v1, 0xd

    .line 223
    .line 224
    invoke-direct {v0, p1, v1}, Lh60/b;-><init>(II)V

    .line 225
    .line 226
    .line 227
    iput-object v0, p0, Ll2/u1;->d:Lay0/n;

    .line 228
    .line 229
    :cond_9
    return-void
.end method

.method public static final c(Lh00/b;Lay0/a;Lay0/a;Lay0/a;Ll2/o;I)V
    .locals 20

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v2, p1

    .line 4
    .line 5
    move-object/from16 v3, p2

    .line 6
    .line 7
    move-object/from16 v4, p3

    .line 8
    .line 9
    move-object/from16 v8, p4

    .line 10
    .line 11
    check-cast v8, Ll2/t;

    .line 12
    .line 13
    const v0, -0xc073145

    .line 14
    .line 15
    .line 16
    invoke-virtual {v8, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 17
    .line 18
    .line 19
    invoke-virtual {v8, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    if-eqz v0, :cond_0

    .line 24
    .line 25
    const/4 v0, 0x4

    .line 26
    goto :goto_0

    .line 27
    :cond_0
    const/4 v0, 0x2

    .line 28
    :goto_0
    or-int v0, p5, v0

    .line 29
    .line 30
    invoke-virtual {v8, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 31
    .line 32
    .line 33
    move-result v5

    .line 34
    if-eqz v5, :cond_1

    .line 35
    .line 36
    const/16 v5, 0x20

    .line 37
    .line 38
    goto :goto_1

    .line 39
    :cond_1
    const/16 v5, 0x10

    .line 40
    .line 41
    :goto_1
    or-int/2addr v0, v5

    .line 42
    invoke-virtual {v8, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 43
    .line 44
    .line 45
    move-result v5

    .line 46
    if-eqz v5, :cond_2

    .line 47
    .line 48
    const/16 v5, 0x100

    .line 49
    .line 50
    goto :goto_2

    .line 51
    :cond_2
    const/16 v5, 0x80

    .line 52
    .line 53
    :goto_2
    or-int/2addr v0, v5

    .line 54
    invoke-virtual {v8, v4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 55
    .line 56
    .line 57
    move-result v5

    .line 58
    const/16 v6, 0x800

    .line 59
    .line 60
    if-eqz v5, :cond_3

    .line 61
    .line 62
    move v5, v6

    .line 63
    goto :goto_3

    .line 64
    :cond_3
    const/16 v5, 0x400

    .line 65
    .line 66
    :goto_3
    or-int/2addr v0, v5

    .line 67
    and-int/lit16 v5, v0, 0x493

    .line 68
    .line 69
    const/16 v7, 0x492

    .line 70
    .line 71
    const/4 v11, 0x0

    .line 72
    const/4 v9, 0x1

    .line 73
    if-eq v5, v7, :cond_4

    .line 74
    .line 75
    move v5, v9

    .line 76
    goto :goto_4

    .line 77
    :cond_4
    move v5, v11

    .line 78
    :goto_4
    and-int/lit8 v7, v0, 0x1

    .line 79
    .line 80
    invoke-virtual {v8, v7, v5}, Ll2/t;->O(IZ)Z

    .line 81
    .line 82
    .line 83
    move-result v5

    .line 84
    if-eqz v5, :cond_9

    .line 85
    .line 86
    iget-object v5, v1, Lh00/b;->e:Lql0/g;

    .line 87
    .line 88
    if-nez v5, :cond_5

    .line 89
    .line 90
    const v0, 0x4704f096

    .line 91
    .line 92
    .line 93
    invoke-virtual {v8, v0}, Ll2/t;->Y(I)V

    .line 94
    .line 95
    .line 96
    invoke-virtual {v8, v11}, Ll2/t;->q(Z)V

    .line 97
    .line 98
    .line 99
    new-instance v0, Li00/b;

    .line 100
    .line 101
    const/4 v5, 0x0

    .line 102
    invoke-direct {v0, v1, v2, v5}, Li00/b;-><init>(Lh00/b;Lay0/a;I)V

    .line 103
    .line 104
    .line 105
    const v5, 0x6e576d77

    .line 106
    .line 107
    .line 108
    invoke-static {v5, v8, v0}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 109
    .line 110
    .line 111
    move-result-object v6

    .line 112
    new-instance v0, Li00/b;

    .line 113
    .line 114
    const/4 v5, 0x1

    .line 115
    invoke-direct {v0, v1, v3, v5}, Li00/b;-><init>(Lh00/b;Lay0/a;I)V

    .line 116
    .line 117
    .line 118
    const v5, -0xb4acdaa

    .line 119
    .line 120
    .line 121
    invoke-static {v5, v8, v0}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 122
    .line 123
    .line 124
    move-result-object v7

    .line 125
    new-instance v0, Lb50/c;

    .line 126
    .line 127
    const/16 v5, 0x11

    .line 128
    .line 129
    invoke-direct {v0, v1, v5}, Lb50/c;-><init>(Ljava/lang/Object;I)V

    .line 130
    .line 131
    .line 132
    const v5, -0x578179b4

    .line 133
    .line 134
    .line 135
    invoke-static {v5, v8, v0}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 136
    .line 137
    .line 138
    move-result-object v16

    .line 139
    const v18, 0x300001b6

    .line 140
    .line 141
    .line 142
    const/16 v19, 0x1f8

    .line 143
    .line 144
    sget-object v5, Lx2/p;->b:Lx2/p;

    .line 145
    .line 146
    move-object/from16 v17, v8

    .line 147
    .line 148
    const/4 v8, 0x0

    .line 149
    const/4 v9, 0x0

    .line 150
    const/4 v10, 0x0

    .line 151
    const-wide/16 v11, 0x0

    .line 152
    .line 153
    const-wide/16 v13, 0x0

    .line 154
    .line 155
    const/4 v15, 0x0

    .line 156
    invoke-static/range {v5 .. v19}, Lh2/c8;->a(Lx2/s;Lay0/n;Lay0/n;Lay0/n;Lay0/n;IJJLk1/q1;Lay0/o;Ll2/o;II)V

    .line 157
    .line 158
    .line 159
    move-object/from16 v8, v17

    .line 160
    .line 161
    goto :goto_7

    .line 162
    :cond_5
    const v7, 0x4704f097

    .line 163
    .line 164
    .line 165
    invoke-virtual {v8, v7}, Ll2/t;->Y(I)V

    .line 166
    .line 167
    .line 168
    and-int/lit16 v0, v0, 0x1c00

    .line 169
    .line 170
    if-ne v0, v6, :cond_6

    .line 171
    .line 172
    goto :goto_5

    .line 173
    :cond_6
    move v9, v11

    .line 174
    :goto_5
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 175
    .line 176
    .line 177
    move-result-object v0

    .line 178
    if-nez v9, :cond_7

    .line 179
    .line 180
    sget-object v6, Ll2/n;->a:Ll2/x0;

    .line 181
    .line 182
    if-ne v0, v6, :cond_8

    .line 183
    .line 184
    :cond_7
    new-instance v0, Lh2/n8;

    .line 185
    .line 186
    const/4 v6, 0x5

    .line 187
    invoke-direct {v0, v4, v6}, Lh2/n8;-><init>(Lay0/a;I)V

    .line 188
    .line 189
    .line 190
    invoke-virtual {v8, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 191
    .line 192
    .line 193
    :cond_8
    move-object v6, v0

    .line 194
    check-cast v6, Lay0/k;

    .line 195
    .line 196
    const/4 v9, 0x0

    .line 197
    const/4 v10, 0x4

    .line 198
    const/4 v7, 0x0

    .line 199
    invoke-static/range {v5 .. v10}, Lyg0/a;->a(Lql0/g;Lay0/k;Lay0/k;Ll2/o;II)V

    .line 200
    .line 201
    .line 202
    invoke-virtual {v8, v11}, Ll2/t;->q(Z)V

    .line 203
    .line 204
    .line 205
    invoke-virtual {v8}, Ll2/t;->s()Ll2/u1;

    .line 206
    .line 207
    .line 208
    move-result-object v7

    .line 209
    if-eqz v7, :cond_a

    .line 210
    .line 211
    new-instance v0, Li00/a;

    .line 212
    .line 213
    const/4 v6, 0x0

    .line 214
    move/from16 v5, p5

    .line 215
    .line 216
    invoke-direct/range {v0 .. v6}, Li00/a;-><init>(Lh00/b;Lay0/a;Lay0/a;Lay0/a;II)V

    .line 217
    .line 218
    .line 219
    :goto_6
    iput-object v0, v7, Ll2/u1;->d:Lay0/n;

    .line 220
    .line 221
    return-void

    .line 222
    :cond_9
    invoke-virtual {v8}, Ll2/t;->R()V

    .line 223
    .line 224
    .line 225
    :goto_7
    invoke-virtual {v8}, Ll2/t;->s()Ll2/u1;

    .line 226
    .line 227
    .line 228
    move-result-object v7

    .line 229
    if-eqz v7, :cond_a

    .line 230
    .line 231
    new-instance v0, Li00/a;

    .line 232
    .line 233
    const/4 v6, 0x1

    .line 234
    move-object/from16 v1, p0

    .line 235
    .line 236
    move-object/from16 v2, p1

    .line 237
    .line 238
    move-object/from16 v3, p2

    .line 239
    .line 240
    move-object/from16 v4, p3

    .line 241
    .line 242
    move/from16 v5, p5

    .line 243
    .line 244
    invoke-direct/range {v0 .. v6}, Li00/a;-><init>(Lh00/b;Lay0/a;Lay0/a;Lay0/a;II)V

    .line 245
    .line 246
    .line 247
    goto :goto_6

    .line 248
    :cond_a
    return-void
.end method
