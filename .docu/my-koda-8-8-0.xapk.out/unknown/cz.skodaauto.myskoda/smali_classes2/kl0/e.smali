.class public abstract Lkl0/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:F


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const/16 v0, 0x50

    .line 2
    .line 3
    int-to-float v0, v0

    .line 4
    sput v0, Lkl0/e;->a:F

    .line 5
    .line 6
    return-void
.end method

.method public static final a(Lx2/s;Ll2/o;I)V
    .locals 13

    .line 1
    move-object v3, p1

    .line 2
    check-cast v3, Ll2/t;

    .line 3
    .line 4
    const p1, -0x4bd870a9

    .line 5
    .line 6
    .line 7
    invoke-virtual {v3, p1}, Ll2/t;->a0(I)Ll2/t;

    .line 8
    .line 9
    .line 10
    or-int/lit8 p1, p2, 0x6

    .line 11
    .line 12
    and-int/lit8 v0, p1, 0x3

    .line 13
    .line 14
    const/4 v1, 0x2

    .line 15
    const/4 v2, 0x0

    .line 16
    const/4 v4, 0x1

    .line 17
    if-eq v0, v1, :cond_0

    .line 18
    .line 19
    move v0, v4

    .line 20
    goto :goto_0

    .line 21
    :cond_0
    move v0, v2

    .line 22
    :goto_0
    and-int/2addr p1, v4

    .line 23
    invoke-virtual {v3, p1, v0}, Ll2/t;->O(IZ)Z

    .line 24
    .line 25
    .line 26
    move-result p1

    .line 27
    if-eqz p1, :cond_5

    .line 28
    .line 29
    invoke-static {v3}, Lxf0/y1;->F(Ll2/o;)Z

    .line 30
    .line 31
    .line 32
    move-result p0

    .line 33
    if-eqz p0, :cond_1

    .line 34
    .line 35
    const p0, -0x385d06ce

    .line 36
    .line 37
    .line 38
    invoke-virtual {v3, p0}, Ll2/t;->Y(I)V

    .line 39
    .line 40
    .line 41
    invoke-static {v3, v2}, Lkl0/e;->c(Ll2/o;I)V

    .line 42
    .line 43
    .line 44
    invoke-virtual {v3, v2}, Ll2/t;->q(Z)V

    .line 45
    .line 46
    .line 47
    invoke-virtual {v3}, Ll2/t;->s()Ll2/u1;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    if-eqz p0, :cond_6

    .line 52
    .line 53
    new-instance p1, Lk50/a;

    .line 54
    .line 55
    const/16 v0, 0xb

    .line 56
    .line 57
    invoke-direct {p1, p2, v0}, Lk50/a;-><init>(II)V

    .line 58
    .line 59
    .line 60
    iput-object p1, p0, Ll2/u1;->d:Lay0/n;

    .line 61
    .line 62
    return-void

    .line 63
    :cond_1
    const p0, -0x3873d1b5

    .line 64
    .line 65
    .line 66
    const p1, -0x6040e0aa

    .line 67
    .line 68
    .line 69
    invoke-static {p0, p1, v3, v3, v2}, Lvj/b;->c(IILl2/t;Ll2/t;Z)Landroidx/lifecycle/i1;

    .line 70
    .line 71
    .line 72
    move-result-object p0

    .line 73
    if-eqz p0, :cond_4

    .line 74
    .line 75
    invoke-static {p0}, Ljp/ib;->a(Landroidx/lifecycle/i1;)Lp7/c;

    .line 76
    .line 77
    .line 78
    move-result-object v8

    .line 79
    invoke-static {v3}, Lw11/c;->b(Ll2/o;)Lk21/a;

    .line 80
    .line 81
    .line 82
    move-result-object v10

    .line 83
    const-class p1, Ljl0/b;

    .line 84
    .line 85
    sget-object v0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 86
    .line 87
    invoke-virtual {v0, p1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 88
    .line 89
    .line 90
    move-result-object v5

    .line 91
    invoke-interface {p0}, Landroidx/lifecycle/i1;->getViewModelStore()Landroidx/lifecycle/h1;

    .line 92
    .line 93
    .line 94
    move-result-object v6

    .line 95
    const/4 v7, 0x0

    .line 96
    const/4 v9, 0x0

    .line 97
    const/4 v11, 0x0

    .line 98
    invoke-static/range {v5 .. v11}, Ljp/lb;->a(Lhy0/d;Landroidx/lifecycle/h1;Ljava/lang/String;Lp7/c;Lh21/b;Lk21/a;Lay0/a;)Landroidx/lifecycle/b1;

    .line 99
    .line 100
    .line 101
    move-result-object p0

    .line 102
    invoke-virtual {v3, v2}, Ll2/t;->q(Z)V

    .line 103
    .line 104
    .line 105
    check-cast p0, Lql0/j;

    .line 106
    .line 107
    const/16 p1, 0x8

    .line 108
    .line 109
    invoke-static {p0, v3, p1, v4}, Lkp/x5;->b(Lql0/j;Ll2/o;II)V

    .line 110
    .line 111
    .line 112
    move-object v7, p0

    .line 113
    check-cast v7, Ljl0/b;

    .line 114
    .line 115
    iget-object p0, v7, Lql0/j;->g:Lyy0/l1;

    .line 116
    .line 117
    const/4 p1, 0x0

    .line 118
    invoke-static {p0, p1, v3, v4}, Ll2/b;->f(Lyy0/a2;Lwy0/c;Ll2/o;I)Ll2/b1;

    .line 119
    .line 120
    .line 121
    move-result-object p0

    .line 122
    invoke-interface {p0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 123
    .line 124
    .line 125
    move-result-object p0

    .line 126
    move-object v0, p0

    .line 127
    check-cast v0, Ljl0/a;

    .line 128
    .line 129
    invoke-virtual {v3, v7}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 130
    .line 131
    .line 132
    move-result p0

    .line 133
    invoke-virtual {v3}, Ll2/t;->L()Ljava/lang/Object;

    .line 134
    .line 135
    .line 136
    move-result-object p1

    .line 137
    if-nez p0, :cond_2

    .line 138
    .line 139
    sget-object p0, Ll2/n;->a:Ll2/x0;

    .line 140
    .line 141
    if-ne p1, p0, :cond_3

    .line 142
    .line 143
    :cond_2
    new-instance v5, Lio/ktor/utils/io/g0;

    .line 144
    .line 145
    const/4 v11, 0x0

    .line 146
    const/16 v12, 0x16

    .line 147
    .line 148
    const/4 v6, 0x1

    .line 149
    const-class v8, Ljl0/b;

    .line 150
    .line 151
    const-string v9, "onSelectTileType"

    .line 152
    .line 153
    const-string v10, "onSelectTileType(Lcz/skodaauto/myskoda/library/map/model/MapTileType;)V"

    .line 154
    .line 155
    invoke-direct/range {v5 .. v12}, Lio/ktor/utils/io/g0;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 156
    .line 157
    .line 158
    invoke-virtual {v3, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 159
    .line 160
    .line 161
    move-object p1, v5

    .line 162
    :cond_3
    check-cast p1, Lhy0/g;

    .line 163
    .line 164
    move-object v2, p1

    .line 165
    check-cast v2, Lay0/k;

    .line 166
    .line 167
    const/16 v4, 0x30

    .line 168
    .line 169
    const/4 v5, 0x0

    .line 170
    sget-object v1, Lx2/p;->b:Lx2/p;

    .line 171
    .line 172
    invoke-static/range {v0 .. v5}, Lkl0/e;->b(Ljl0/a;Lx2/s;Lay0/k;Ll2/o;II)V

    .line 173
    .line 174
    .line 175
    move-object p0, v1

    .line 176
    goto :goto_1

    .line 177
    :cond_4
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 178
    .line 179
    const-string p1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 180
    .line 181
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 182
    .line 183
    .line 184
    throw p0

    .line 185
    :cond_5
    invoke-virtual {v3}, Ll2/t;->R()V

    .line 186
    .line 187
    .line 188
    :goto_1
    invoke-virtual {v3}, Ll2/t;->s()Ll2/u1;

    .line 189
    .line 190
    .line 191
    move-result-object p1

    .line 192
    if-eqz p1, :cond_6

    .line 193
    .line 194
    new-instance v0, Lb71/j;

    .line 195
    .line 196
    const/16 v1, 0x1d

    .line 197
    .line 198
    invoke-direct {v0, p0, p2, v1}, Lb71/j;-><init>(Lx2/s;II)V

    .line 199
    .line 200
    .line 201
    iput-object v0, p1, Ll2/u1;->d:Lay0/n;

    .line 202
    .line 203
    :cond_6
    return-void
.end method

.method public static final b(Ljl0/a;Lx2/s;Lay0/k;Ll2/o;II)V
    .locals 35

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v3, p2

    .line 4
    .line 5
    move/from16 v4, p4

    .line 6
    .line 7
    move-object/from16 v11, p3

    .line 8
    .line 9
    check-cast v11, Ll2/t;

    .line 10
    .line 11
    const v0, 0x202bef2f

    .line 12
    .line 13
    .line 14
    invoke-virtual {v11, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 15
    .line 16
    .line 17
    and-int/lit8 v0, v4, 0x6

    .line 18
    .line 19
    if-nez v0, :cond_1

    .line 20
    .line 21
    invoke-virtual {v11, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

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
    or-int/2addr v0, v4

    .line 31
    goto :goto_1

    .line 32
    :cond_1
    move v0, v4

    .line 33
    :goto_1
    and-int/lit8 v2, p5, 0x2

    .line 34
    .line 35
    if-eqz v2, :cond_3

    .line 36
    .line 37
    or-int/lit8 v0, v0, 0x30

    .line 38
    .line 39
    :cond_2
    move-object/from16 v5, p1

    .line 40
    .line 41
    goto :goto_3

    .line 42
    :cond_3
    and-int/lit8 v5, v4, 0x30

    .line 43
    .line 44
    if-nez v5, :cond_2

    .line 45
    .line 46
    move-object/from16 v5, p1

    .line 47
    .line 48
    invoke-virtual {v11, v5}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 49
    .line 50
    .line 51
    move-result v6

    .line 52
    if-eqz v6, :cond_4

    .line 53
    .line 54
    const/16 v6, 0x20

    .line 55
    .line 56
    goto :goto_2

    .line 57
    :cond_4
    const/16 v6, 0x10

    .line 58
    .line 59
    :goto_2
    or-int/2addr v0, v6

    .line 60
    :goto_3
    and-int/lit16 v6, v4, 0x180

    .line 61
    .line 62
    if-nez v6, :cond_6

    .line 63
    .line 64
    invoke-virtual {v11, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 65
    .line 66
    .line 67
    move-result v6

    .line 68
    if-eqz v6, :cond_5

    .line 69
    .line 70
    const/16 v6, 0x100

    .line 71
    .line 72
    goto :goto_4

    .line 73
    :cond_5
    const/16 v6, 0x80

    .line 74
    .line 75
    :goto_4
    or-int/2addr v0, v6

    .line 76
    :cond_6
    and-int/lit16 v6, v0, 0x93

    .line 77
    .line 78
    const/16 v8, 0x92

    .line 79
    .line 80
    const/4 v10, 0x0

    .line 81
    if-eq v6, v8, :cond_7

    .line 82
    .line 83
    const/4 v6, 0x1

    .line 84
    goto :goto_5

    .line 85
    :cond_7
    move v6, v10

    .line 86
    :goto_5
    and-int/lit8 v8, v0, 0x1

    .line 87
    .line 88
    invoke-virtual {v11, v8, v6}, Ll2/t;->O(IZ)Z

    .line 89
    .line 90
    .line 91
    move-result v6

    .line 92
    if-eqz v6, :cond_18

    .line 93
    .line 94
    sget-object v6, Lx2/p;->b:Lx2/p;

    .line 95
    .line 96
    if-eqz v2, :cond_8

    .line 97
    .line 98
    move-object v2, v6

    .line 99
    goto :goto_6

    .line 100
    :cond_8
    move-object v2, v5

    .line 101
    :goto_6
    sget-object v5, Lk1/j;->c:Lk1/e;

    .line 102
    .line 103
    sget-object v8, Lx2/c;->p:Lx2/h;

    .line 104
    .line 105
    invoke-static {v5, v8, v11, v10}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 106
    .line 107
    .line 108
    move-result-object v5

    .line 109
    iget-wide v12, v11, Ll2/t;->T:J

    .line 110
    .line 111
    invoke-static {v12, v13}, Ljava/lang/Long;->hashCode(J)I

    .line 112
    .line 113
    .line 114
    move-result v8

    .line 115
    invoke-virtual {v11}, Ll2/t;->m()Ll2/p1;

    .line 116
    .line 117
    .line 118
    move-result-object v12

    .line 119
    invoke-static {v11, v2}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 120
    .line 121
    .line 122
    move-result-object v13

    .line 123
    sget-object v14, Lv3/k;->m1:Lv3/j;

    .line 124
    .line 125
    invoke-virtual {v14}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 126
    .line 127
    .line 128
    sget-object v14, Lv3/j;->b:Lv3/i;

    .line 129
    .line 130
    invoke-virtual {v11}, Ll2/t;->c0()V

    .line 131
    .line 132
    .line 133
    iget-boolean v15, v11, Ll2/t;->S:Z

    .line 134
    .line 135
    if-eqz v15, :cond_9

    .line 136
    .line 137
    invoke-virtual {v11, v14}, Ll2/t;->l(Lay0/a;)V

    .line 138
    .line 139
    .line 140
    goto :goto_7

    .line 141
    :cond_9
    invoke-virtual {v11}, Ll2/t;->m0()V

    .line 142
    .line 143
    .line 144
    :goto_7
    sget-object v15, Lv3/j;->g:Lv3/h;

    .line 145
    .line 146
    invoke-static {v15, v5, v11}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 147
    .line 148
    .line 149
    sget-object v5, Lv3/j;->f:Lv3/h;

    .line 150
    .line 151
    invoke-static {v5, v12, v11}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 152
    .line 153
    .line 154
    sget-object v12, Lv3/j;->j:Lv3/h;

    .line 155
    .line 156
    iget-boolean v7, v11, Ll2/t;->S:Z

    .line 157
    .line 158
    if-nez v7, :cond_a

    .line 159
    .line 160
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 161
    .line 162
    .line 163
    move-result-object v7

    .line 164
    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 165
    .line 166
    .line 167
    move-result-object v9

    .line 168
    invoke-static {v7, v9}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 169
    .line 170
    .line 171
    move-result v7

    .line 172
    if-nez v7, :cond_b

    .line 173
    .line 174
    :cond_a
    invoke-static {v8, v11, v8, v12}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 175
    .line 176
    .line 177
    :cond_b
    sget-object v7, Lv3/j;->d:Lv3/h;

    .line 178
    .line 179
    invoke-static {v7, v13, v11}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 180
    .line 181
    .line 182
    const v8, 0x7f12070e

    .line 183
    .line 184
    .line 185
    invoke-static {v11, v8}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 186
    .line 187
    .line 188
    move-result-object v8

    .line 189
    sget-object v9, Lj91/j;->a:Ll2/u2;

    .line 190
    .line 191
    invoke-virtual {v11, v9}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 192
    .line 193
    .line 194
    move-result-object v9

    .line 195
    check-cast v9, Lj91/f;

    .line 196
    .line 197
    invoke-virtual {v9}, Lj91/f;->k()Lg4/p0;

    .line 198
    .line 199
    .line 200
    move-result-object v9

    .line 201
    const-string v13, "maps_settings_map_view"

    .line 202
    .line 203
    invoke-static {v6, v13}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 204
    .line 205
    .line 206
    move-result-object v13

    .line 207
    const/16 v25, 0x0

    .line 208
    .line 209
    const v26, 0xfff8

    .line 210
    .line 211
    .line 212
    move-object/from16 v17, v5

    .line 213
    .line 214
    move-object/from16 v18, v6

    .line 215
    .line 216
    move-object v5, v8

    .line 217
    move-object v6, v9

    .line 218
    const-wide/16 v8, 0x0

    .line 219
    .line 220
    move/from16 v19, v10

    .line 221
    .line 222
    move-object/from16 v23, v11

    .line 223
    .line 224
    const-wide/16 v10, 0x0

    .line 225
    .line 226
    move-object/from16 v20, v12

    .line 227
    .line 228
    const/4 v12, 0x0

    .line 229
    move-object/from16 v22, v7

    .line 230
    .line 231
    move-object v7, v13

    .line 232
    move-object/from16 v21, v14

    .line 233
    .line 234
    const-wide/16 v13, 0x0

    .line 235
    .line 236
    move-object/from16 v24, v15

    .line 237
    .line 238
    const/4 v15, 0x0

    .line 239
    const/16 v27, 0x1

    .line 240
    .line 241
    const/16 v16, 0x0

    .line 242
    .line 243
    move-object/from16 v28, v17

    .line 244
    .line 245
    move-object/from16 v29, v18

    .line 246
    .line 247
    const-wide/16 v17, 0x0

    .line 248
    .line 249
    move/from16 v30, v19

    .line 250
    .line 251
    const/16 v19, 0x0

    .line 252
    .line 253
    move-object/from16 v31, v20

    .line 254
    .line 255
    const/16 v20, 0x0

    .line 256
    .line 257
    move-object/from16 v32, v21

    .line 258
    .line 259
    const/16 v21, 0x0

    .line 260
    .line 261
    move-object/from16 v33, v22

    .line 262
    .line 263
    const/16 v22, 0x0

    .line 264
    .line 265
    move-object/from16 v34, v24

    .line 266
    .line 267
    const/16 v24, 0x180

    .line 268
    .line 269
    move-object/from16 p1, v2

    .line 270
    .line 271
    move-object/from16 v3, v28

    .line 272
    .line 273
    move-object/from16 v1, v29

    .line 274
    .line 275
    move-object/from16 v2, v32

    .line 276
    .line 277
    move-object/from16 v4, v34

    .line 278
    .line 279
    move/from16 v28, v0

    .line 280
    .line 281
    move/from16 v0, v30

    .line 282
    .line 283
    invoke-static/range {v5 .. v26}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 284
    .line 285
    .line 286
    move-object/from16 v11, v23

    .line 287
    .line 288
    sget-object v13, Lj91/a;->a:Ll2/u2;

    .line 289
    .line 290
    invoke-virtual {v11, v13}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 291
    .line 292
    .line 293
    move-result-object v5

    .line 294
    check-cast v5, Lj91/c;

    .line 295
    .line 296
    iget v5, v5, Lj91/c;->e:F

    .line 297
    .line 298
    const/high16 v6, 0x3f800000    # 1.0f

    .line 299
    .line 300
    invoke-static {v1, v5, v11, v1, v6}, Lp3/m;->v(Lx2/p;FLl2/t;Lx2/p;F)Lx2/s;

    .line 301
    .line 302
    .line 303
    move-result-object v5

    .line 304
    sget-object v6, Lk1/j;->a:Lk1/c;

    .line 305
    .line 306
    sget-object v7, Lx2/c;->m:Lx2/i;

    .line 307
    .line 308
    invoke-static {v6, v7, v11, v0}, Lk1/e1;->a(Lk1/g;Lx2/i;Ll2/o;I)Lk1/g1;

    .line 309
    .line 310
    .line 311
    move-result-object v6

    .line 312
    iget-wide v7, v11, Ll2/t;->T:J

    .line 313
    .line 314
    invoke-static {v7, v8}, Ljava/lang/Long;->hashCode(J)I

    .line 315
    .line 316
    .line 317
    move-result v7

    .line 318
    invoke-virtual {v11}, Ll2/t;->m()Ll2/p1;

    .line 319
    .line 320
    .line 321
    move-result-object v8

    .line 322
    invoke-static {v11, v5}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 323
    .line 324
    .line 325
    move-result-object v5

    .line 326
    invoke-virtual {v11}, Ll2/t;->c0()V

    .line 327
    .line 328
    .line 329
    iget-boolean v9, v11, Ll2/t;->S:Z

    .line 330
    .line 331
    if-eqz v9, :cond_c

    .line 332
    .line 333
    invoke-virtual {v11, v2}, Ll2/t;->l(Lay0/a;)V

    .line 334
    .line 335
    .line 336
    goto :goto_8

    .line 337
    :cond_c
    invoke-virtual {v11}, Ll2/t;->m0()V

    .line 338
    .line 339
    .line 340
    :goto_8
    invoke-static {v4, v6, v11}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 341
    .line 342
    .line 343
    invoke-static {v3, v8, v11}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 344
    .line 345
    .line 346
    iget-boolean v2, v11, Ll2/t;->S:Z

    .line 347
    .line 348
    if-nez v2, :cond_d

    .line 349
    .line 350
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 351
    .line 352
    .line 353
    move-result-object v2

    .line 354
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 355
    .line 356
    .line 357
    move-result-object v3

    .line 358
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 359
    .line 360
    .line 361
    move-result v2

    .line 362
    if-nez v2, :cond_e

    .line 363
    .line 364
    :cond_d
    move-object/from16 v2, v31

    .line 365
    .line 366
    goto :goto_a

    .line 367
    :cond_e
    :goto_9
    move-object/from16 v2, v33

    .line 368
    .line 369
    goto :goto_b

    .line 370
    :goto_a
    invoke-static {v7, v11, v7, v2}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 371
    .line 372
    .line 373
    goto :goto_9

    .line 374
    :goto_b
    invoke-static {v2, v5, v11}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 375
    .line 376
    .line 377
    move-object/from16 v2, p0

    .line 378
    .line 379
    iget-object v3, v2, Ljl0/a;->a:Lxj0/j;

    .line 380
    .line 381
    sget-object v4, Lxj0/j;->d:Lxj0/j;

    .line 382
    .line 383
    if-ne v3, v4, :cond_f

    .line 384
    .line 385
    const/4 v5, 0x1

    .line 386
    goto :goto_c

    .line 387
    :cond_f
    move v5, v0

    .line 388
    :goto_c
    invoke-static {v11}, Lkp/k;->c(Ll2/o;)Z

    .line 389
    .line 390
    .line 391
    move-result v3

    .line 392
    if-eqz v3, :cond_10

    .line 393
    .line 394
    const v3, 0x7f080254

    .line 395
    .line 396
    .line 397
    :goto_d
    move v6, v3

    .line 398
    goto :goto_e

    .line 399
    :cond_10
    const v3, 0x7f080255

    .line 400
    .line 401
    .line 402
    goto :goto_d

    .line 403
    :goto_e
    const v3, 0x7f12066e

    .line 404
    .line 405
    .line 406
    invoke-static {v11, v3}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 407
    .line 408
    .line 409
    move-result-object v8

    .line 410
    move/from16 v3, v28

    .line 411
    .line 412
    and-int/lit16 v3, v3, 0x380

    .line 413
    .line 414
    const/16 v4, 0x100

    .line 415
    .line 416
    if-ne v3, v4, :cond_11

    .line 417
    .line 418
    const/4 v9, 0x1

    .line 419
    goto :goto_f

    .line 420
    :cond_11
    move v9, v0

    .line 421
    :goto_f
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 422
    .line 423
    .line 424
    move-result-object v7

    .line 425
    sget-object v14, Ll2/n;->a:Ll2/x0;

    .line 426
    .line 427
    if-nez v9, :cond_13

    .line 428
    .line 429
    if-ne v7, v14, :cond_12

    .line 430
    .line 431
    goto :goto_10

    .line 432
    :cond_12
    move-object/from16 v15, p2

    .line 433
    .line 434
    goto :goto_11

    .line 435
    :cond_13
    :goto_10
    new-instance v7, Lik/b;

    .line 436
    .line 437
    const/16 v9, 0x13

    .line 438
    .line 439
    move-object/from16 v15, p2

    .line 440
    .line 441
    invoke-direct {v7, v9, v15}, Lik/b;-><init>(ILay0/k;)V

    .line 442
    .line 443
    .line 444
    invoke-virtual {v11, v7}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 445
    .line 446
    .line 447
    :goto_11
    move-object v10, v7

    .line 448
    check-cast v10, Lay0/a;

    .line 449
    .line 450
    const/16 v12, 0x6180

    .line 451
    .line 452
    sget v7, Lkl0/e;->a:F

    .line 453
    .line 454
    const-string v9, "map_settings_default_map_type"

    .line 455
    .line 456
    invoke-static/range {v5 .. v12}, Lkl0/d;->a(ZIFLjava/lang/String;Ljava/lang/String;Lay0/a;Ll2/o;I)V

    .line 457
    .line 458
    .line 459
    invoke-virtual {v11, v13}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 460
    .line 461
    .line 462
    move-result-object v5

    .line 463
    check-cast v5, Lj91/c;

    .line 464
    .line 465
    iget v5, v5, Lj91/c;->e:F

    .line 466
    .line 467
    invoke-static {v1, v5}, Landroidx/compose/foundation/layout/d;->r(Lx2/s;F)Lx2/s;

    .line 468
    .line 469
    .line 470
    move-result-object v1

    .line 471
    invoke-static {v11, v1}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 472
    .line 473
    .line 474
    iget-object v1, v2, Ljl0/a;->a:Lxj0/j;

    .line 475
    .line 476
    sget-object v5, Lxj0/j;->e:Lxj0/j;

    .line 477
    .line 478
    if-ne v1, v5, :cond_14

    .line 479
    .line 480
    const/4 v5, 0x1

    .line 481
    goto :goto_12

    .line 482
    :cond_14
    move v5, v0

    .line 483
    :goto_12
    const v1, 0x7f12066f

    .line 484
    .line 485
    .line 486
    invoke-static {v11, v1}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 487
    .line 488
    .line 489
    move-result-object v8

    .line 490
    if-ne v3, v4, :cond_15

    .line 491
    .line 492
    const/4 v9, 0x1

    .line 493
    goto :goto_13

    .line 494
    :cond_15
    move v9, v0

    .line 495
    :goto_13
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 496
    .line 497
    .line 498
    move-result-object v0

    .line 499
    if-nez v9, :cond_16

    .line 500
    .line 501
    if-ne v0, v14, :cond_17

    .line 502
    .line 503
    :cond_16
    new-instance v0, Lik/b;

    .line 504
    .line 505
    const/16 v1, 0x14

    .line 506
    .line 507
    invoke-direct {v0, v1, v15}, Lik/b;-><init>(ILay0/k;)V

    .line 508
    .line 509
    .line 510
    invoke-virtual {v11, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 511
    .line 512
    .line 513
    :cond_17
    move-object v10, v0

    .line 514
    check-cast v10, Lay0/a;

    .line 515
    .line 516
    const/16 v12, 0x6180

    .line 517
    .line 518
    const v6, 0x7f080256

    .line 519
    .line 520
    .line 521
    const-string v9, "map_settings_satelit_map_type"

    .line 522
    .line 523
    invoke-static/range {v5 .. v12}, Lkl0/d;->a(ZIFLjava/lang/String;Ljava/lang/String;Lay0/a;Ll2/o;I)V

    .line 524
    .line 525
    .line 526
    const/4 v0, 0x1

    .line 527
    invoke-virtual {v11, v0}, Ll2/t;->q(Z)V

    .line 528
    .line 529
    .line 530
    invoke-virtual {v11, v0}, Ll2/t;->q(Z)V

    .line 531
    .line 532
    .line 533
    move-object/from16 v5, p1

    .line 534
    .line 535
    goto :goto_14

    .line 536
    :cond_18
    move-object v2, v1

    .line 537
    move-object v15, v3

    .line 538
    invoke-virtual {v11}, Ll2/t;->R()V

    .line 539
    .line 540
    .line 541
    :goto_14
    invoke-virtual {v11}, Ll2/t;->s()Ll2/u1;

    .line 542
    .line 543
    .line 544
    move-result-object v7

    .line 545
    if-eqz v7, :cond_19

    .line 546
    .line 547
    new-instance v0, Lc71/c;

    .line 548
    .line 549
    const/16 v6, 0xc

    .line 550
    .line 551
    move/from16 v4, p4

    .line 552
    .line 553
    move-object v1, v2

    .line 554
    move-object v2, v5

    .line 555
    move-object v3, v15

    .line 556
    move/from16 v5, p5

    .line 557
    .line 558
    invoke-direct/range {v0 .. v6}, Lc71/c;-><init>(Ljava/lang/Object;Lx2/s;Ljava/lang/Object;III)V

    .line 559
    .line 560
    .line 561
    iput-object v0, v7, Ll2/u1;->d:Lay0/n;

    .line 562
    .line 563
    :cond_19
    return-void
.end method

.method public static final c(Ll2/o;I)V
    .locals 4

    .line 1
    check-cast p0, Ll2/t;

    .line 2
    .line 3
    const v0, 0xbf48efc

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    const/4 v0, 0x0

    .line 10
    const/4 v1, 0x1

    .line 11
    if-eqz p1, :cond_0

    .line 12
    .line 13
    move v2, v1

    .line 14
    goto :goto_0

    .line 15
    :cond_0
    move v2, v0

    .line 16
    :goto_0
    and-int/lit8 v3, p1, 0x1

    .line 17
    .line 18
    invoke-virtual {p0, v3, v2}, Ll2/t;->O(IZ)Z

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    if-eqz v2, :cond_1

    .line 23
    .line 24
    sget-object v2, Lkl0/a;->a:Lt2/b;

    .line 25
    .line 26
    const/16 v3, 0x30

    .line 27
    .line 28
    invoke-static {v0, v2, p0, v3, v1}, Lxf0/y1;->i(ZLay0/n;Ll2/o;II)V

    .line 29
    .line 30
    .line 31
    goto :goto_1

    .line 32
    :cond_1
    invoke-virtual {p0}, Ll2/t;->R()V

    .line 33
    .line 34
    .line 35
    :goto_1
    invoke-virtual {p0}, Ll2/t;->s()Ll2/u1;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    if-eqz p0, :cond_2

    .line 40
    .line 41
    new-instance v0, Lk50/a;

    .line 42
    .line 43
    const/16 v1, 0xc

    .line 44
    .line 45
    invoke-direct {v0, p1, v1}, Lk50/a;-><init>(II)V

    .line 46
    .line 47
    .line 48
    iput-object v0, p0, Ll2/u1;->d:Lay0/n;

    .line 49
    .line 50
    :cond_2
    return-void
.end method
