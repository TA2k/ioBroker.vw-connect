.class public abstract Lh70/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lt2/b;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lh60/b;

    .line 2
    .line 3
    const/4 v1, 0x3

    .line 4
    invoke-direct {v0, v1}, Lh60/b;-><init>(I)V

    .line 5
    .line 6
    .line 7
    new-instance v1, Lt2/b;

    .line 8
    .line 9
    const/4 v2, 0x0

    .line 10
    const v3, -0xa824411

    .line 11
    .line 12
    .line 13
    invoke-direct {v1, v0, v2, v3}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 14
    .line 15
    .line 16
    sput-object v1, Lh70/a;->a:Lt2/b;

    .line 17
    .line 18
    return-void
.end method

.method public static final a(Lx2/s;Ll2/o;I)V
    .locals 16

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move/from16 v7, p2

    .line 4
    .line 5
    const-string v0, "modifier"

    .line 6
    .line 7
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    move-object/from16 v5, p1

    .line 11
    .line 12
    check-cast v5, Ll2/t;

    .line 13
    .line 14
    const v0, 0x29b3cbf4

    .line 15
    .line 16
    .line 17
    invoke-virtual {v5, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 18
    .line 19
    .line 20
    and-int/lit8 v0, v7, 0x6

    .line 21
    .line 22
    const/4 v2, 0x2

    .line 23
    if-nez v0, :cond_1

    .line 24
    .line 25
    invoke-virtual {v5, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    if-eqz v0, :cond_0

    .line 30
    .line 31
    const/4 v0, 0x4

    .line 32
    goto :goto_0

    .line 33
    :cond_0
    move v0, v2

    .line 34
    :goto_0
    or-int/2addr v0, v7

    .line 35
    goto :goto_1

    .line 36
    :cond_1
    move v0, v7

    .line 37
    :goto_1
    and-int/lit8 v3, v0, 0x3

    .line 38
    .line 39
    const/4 v4, 0x1

    .line 40
    const/4 v6, 0x0

    .line 41
    if-eq v3, v2, :cond_2

    .line 42
    .line 43
    move v2, v4

    .line 44
    goto :goto_2

    .line 45
    :cond_2
    move v2, v6

    .line 46
    :goto_2
    and-int/lit8 v3, v0, 0x1

    .line 47
    .line 48
    invoke-virtual {v5, v3, v2}, Ll2/t;->O(IZ)Z

    .line 49
    .line 50
    .line 51
    move-result v2

    .line 52
    if-eqz v2, :cond_a

    .line 53
    .line 54
    const v2, -0x6040e0aa

    .line 55
    .line 56
    .line 57
    invoke-virtual {v5, v2}, Ll2/t;->Y(I)V

    .line 58
    .line 59
    .line 60
    invoke-static {v5}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 61
    .line 62
    .line 63
    move-result-object v2

    .line 64
    if-eqz v2, :cond_9

    .line 65
    .line 66
    invoke-static {v2}, Ljp/ib;->a(Landroidx/lifecycle/i1;)Lp7/c;

    .line 67
    .line 68
    .line 69
    move-result-object v11

    .line 70
    invoke-static {v5}, Lw11/c;->b(Ll2/o;)Lk21/a;

    .line 71
    .line 72
    .line 73
    move-result-object v13

    .line 74
    const-class v3, Lg70/b;

    .line 75
    .line 76
    sget-object v8, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 77
    .line 78
    invoke-virtual {v8, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 79
    .line 80
    .line 81
    move-result-object v8

    .line 82
    invoke-interface {v2}, Landroidx/lifecycle/i1;->getViewModelStore()Landroidx/lifecycle/h1;

    .line 83
    .line 84
    .line 85
    move-result-object v9

    .line 86
    const/4 v10, 0x0

    .line 87
    const/4 v12, 0x0

    .line 88
    const/4 v14, 0x0

    .line 89
    invoke-static/range {v8 .. v14}, Ljp/lb;->a(Lhy0/d;Landroidx/lifecycle/h1;Ljava/lang/String;Lp7/c;Lh21/b;Lk21/a;Lay0/a;)Landroidx/lifecycle/b1;

    .line 90
    .line 91
    .line 92
    move-result-object v2

    .line 93
    invoke-virtual {v5, v6}, Ll2/t;->q(Z)V

    .line 94
    .line 95
    .line 96
    check-cast v2, Lql0/j;

    .line 97
    .line 98
    invoke-static {v2, v5, v6, v4}, Lkp/x5;->b(Lql0/j;Ll2/o;II)V

    .line 99
    .line 100
    .line 101
    move-object v10, v2

    .line 102
    check-cast v10, Lg70/b;

    .line 103
    .line 104
    iget-object v2, v10, Lql0/j;->g:Lyy0/l1;

    .line 105
    .line 106
    const/4 v3, 0x0

    .line 107
    invoke-static {v2, v3, v5, v4}, Ll2/b;->f(Lyy0/a2;Lwy0/c;Ll2/o;I)Ll2/b1;

    .line 108
    .line 109
    .line 110
    move-result-object v2

    .line 111
    invoke-interface {v2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 112
    .line 113
    .line 114
    move-result-object v2

    .line 115
    check-cast v2, Lg70/a;

    .line 116
    .line 117
    invoke-virtual {v5, v10}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 118
    .line 119
    .line 120
    move-result v3

    .line 121
    invoke-virtual {v5}, Ll2/t;->L()Ljava/lang/Object;

    .line 122
    .line 123
    .line 124
    move-result-object v4

    .line 125
    sget-object v6, Ll2/n;->a:Ll2/x0;

    .line 126
    .line 127
    if-nez v3, :cond_3

    .line 128
    .line 129
    if-ne v4, v6, :cond_4

    .line 130
    .line 131
    :cond_3
    new-instance v8, Lh10/e;

    .line 132
    .line 133
    const/4 v14, 0x0

    .line 134
    const/16 v15, 0x9

    .line 135
    .line 136
    const/4 v9, 0x0

    .line 137
    const-class v11, Lg70/b;

    .line 138
    .line 139
    const-string v12, "onOpenRemoteParking"

    .line 140
    .line 141
    const-string v13, "onOpenRemoteParking()V"

    .line 142
    .line 143
    invoke-direct/range {v8 .. v15}, Lh10/e;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 144
    .line 145
    .line 146
    invoke-virtual {v5, v8}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 147
    .line 148
    .line 149
    move-object v4, v8

    .line 150
    :cond_4
    check-cast v4, Lhy0/g;

    .line 151
    .line 152
    check-cast v4, Lay0/a;

    .line 153
    .line 154
    invoke-virtual {v5, v10}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 155
    .line 156
    .line 157
    move-result v3

    .line 158
    invoke-virtual {v5}, Ll2/t;->L()Ljava/lang/Object;

    .line 159
    .line 160
    .line 161
    move-result-object v8

    .line 162
    if-nez v3, :cond_5

    .line 163
    .line 164
    if-ne v8, v6, :cond_6

    .line 165
    .line 166
    :cond_5
    new-instance v8, Lh10/e;

    .line 167
    .line 168
    const/4 v14, 0x0

    .line 169
    const/16 v15, 0xa

    .line 170
    .line 171
    const/4 v9, 0x0

    .line 172
    const-class v11, Lg70/b;

    .line 173
    .line 174
    const-string v12, "onOpenPermissionSettings"

    .line 175
    .line 176
    const-string v13, "onOpenPermissionSettings()V"

    .line 177
    .line 178
    invoke-direct/range {v8 .. v15}, Lh10/e;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 179
    .line 180
    .line 181
    invoke-virtual {v5, v8}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 182
    .line 183
    .line 184
    :cond_6
    check-cast v8, Lhy0/g;

    .line 185
    .line 186
    move-object v3, v8

    .line 187
    check-cast v3, Lay0/a;

    .line 188
    .line 189
    invoke-virtual {v5, v10}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 190
    .line 191
    .line 192
    move-result v8

    .line 193
    invoke-virtual {v5}, Ll2/t;->L()Ljava/lang/Object;

    .line 194
    .line 195
    .line 196
    move-result-object v9

    .line 197
    if-nez v8, :cond_7

    .line 198
    .line 199
    if-ne v9, v6, :cond_8

    .line 200
    .line 201
    :cond_7
    new-instance v8, Lh10/e;

    .line 202
    .line 203
    const/4 v14, 0x0

    .line 204
    const/16 v15, 0xb

    .line 205
    .line 206
    const/4 v9, 0x0

    .line 207
    const-class v11, Lg70/b;

    .line 208
    .line 209
    const-string v12, "onPermissionDialogDismiss"

    .line 210
    .line 211
    const-string v13, "onPermissionDialogDismiss()V"

    .line 212
    .line 213
    invoke-direct/range {v8 .. v15}, Lh10/e;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 214
    .line 215
    .line 216
    invoke-virtual {v5, v8}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 217
    .line 218
    .line 219
    move-object v9, v8

    .line 220
    :cond_8
    check-cast v9, Lhy0/g;

    .line 221
    .line 222
    check-cast v9, Lay0/a;

    .line 223
    .line 224
    shl-int/lit8 v0, v0, 0x3

    .line 225
    .line 226
    and-int/lit8 v6, v0, 0x70

    .line 227
    .line 228
    move-object v0, v2

    .line 229
    move-object v2, v4

    .line 230
    move-object v4, v9

    .line 231
    invoke-static/range {v0 .. v6}, Lh70/a;->b(Lg70/a;Lx2/s;Lay0/a;Lay0/a;Lay0/a;Ll2/o;I)V

    .line 232
    .line 233
    .line 234
    goto :goto_3

    .line 235
    :cond_9
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 236
    .line 237
    const-string v1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 238
    .line 239
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 240
    .line 241
    .line 242
    throw v0

    .line 243
    :cond_a
    invoke-virtual {v5}, Ll2/t;->R()V

    .line 244
    .line 245
    .line 246
    :goto_3
    invoke-virtual {v5}, Ll2/t;->s()Ll2/u1;

    .line 247
    .line 248
    .line 249
    move-result-object v0

    .line 250
    if-eqz v0, :cond_b

    .line 251
    .line 252
    new-instance v2, Ld00/b;

    .line 253
    .line 254
    const/16 v3, 0xa

    .line 255
    .line 256
    invoke-direct {v2, v1, v7, v3}, Ld00/b;-><init>(Lx2/s;II)V

    .line 257
    .line 258
    .line 259
    iput-object v2, v0, Ll2/u1;->d:Lay0/n;

    .line 260
    .line 261
    :cond_b
    return-void
.end method

.method public static final b(Lg70/a;Lx2/s;Lay0/a;Lay0/a;Lay0/a;Ll2/o;I)V
    .locals 26

    .line 1
    move/from16 v6, p6

    .line 2
    .line 3
    move-object/from16 v0, p5

    .line 4
    .line 5
    check-cast v0, Ll2/t;

    .line 6
    .line 7
    const v1, 0x3d5edf95

    .line 8
    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ll2/t;->a0(I)Ll2/t;

    .line 11
    .line 12
    .line 13
    and-int/lit8 v1, v6, 0x6

    .line 14
    .line 15
    if-nez v1, :cond_1

    .line 16
    .line 17
    move-object/from16 v1, p0

    .line 18
    .line 19
    invoke-virtual {v0, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    move-result v2

    .line 23
    if-eqz v2, :cond_0

    .line 24
    .line 25
    const/4 v2, 0x4

    .line 26
    goto :goto_0

    .line 27
    :cond_0
    const/4 v2, 0x2

    .line 28
    :goto_0
    or-int/2addr v2, v6

    .line 29
    goto :goto_1

    .line 30
    :cond_1
    move-object/from16 v1, p0

    .line 31
    .line 32
    move v2, v6

    .line 33
    :goto_1
    and-int/lit8 v3, v6, 0x30

    .line 34
    .line 35
    move-object/from16 v7, p1

    .line 36
    .line 37
    if-nez v3, :cond_3

    .line 38
    .line 39
    invoke-virtual {v0, v7}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    move-result v3

    .line 43
    if-eqz v3, :cond_2

    .line 44
    .line 45
    const/16 v3, 0x20

    .line 46
    .line 47
    goto :goto_2

    .line 48
    :cond_2
    const/16 v3, 0x10

    .line 49
    .line 50
    :goto_2
    or-int/2addr v2, v3

    .line 51
    :cond_3
    and-int/lit16 v3, v6, 0x180

    .line 52
    .line 53
    move-object/from16 v11, p2

    .line 54
    .line 55
    if-nez v3, :cond_5

    .line 56
    .line 57
    invoke-virtual {v0, v11}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 58
    .line 59
    .line 60
    move-result v3

    .line 61
    if-eqz v3, :cond_4

    .line 62
    .line 63
    const/16 v3, 0x100

    .line 64
    .line 65
    goto :goto_3

    .line 66
    :cond_4
    const/16 v3, 0x80

    .line 67
    .line 68
    :goto_3
    or-int/2addr v2, v3

    .line 69
    :cond_5
    and-int/lit16 v3, v6, 0xc00

    .line 70
    .line 71
    move-object/from16 v4, p3

    .line 72
    .line 73
    if-nez v3, :cond_7

    .line 74
    .line 75
    invoke-virtual {v0, v4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 76
    .line 77
    .line 78
    move-result v3

    .line 79
    if-eqz v3, :cond_6

    .line 80
    .line 81
    const/16 v3, 0x800

    .line 82
    .line 83
    goto :goto_4

    .line 84
    :cond_6
    const/16 v3, 0x400

    .line 85
    .line 86
    :goto_4
    or-int/2addr v2, v3

    .line 87
    :cond_7
    and-int/lit16 v3, v6, 0x6000

    .line 88
    .line 89
    move-object/from16 v5, p4

    .line 90
    .line 91
    if-nez v3, :cond_9

    .line 92
    .line 93
    invoke-virtual {v0, v5}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 94
    .line 95
    .line 96
    move-result v3

    .line 97
    if-eqz v3, :cond_8

    .line 98
    .line 99
    const/16 v3, 0x4000

    .line 100
    .line 101
    goto :goto_5

    .line 102
    :cond_8
    const/16 v3, 0x2000

    .line 103
    .line 104
    :goto_5
    or-int/2addr v2, v3

    .line 105
    :cond_9
    and-int/lit16 v3, v2, 0x2493

    .line 106
    .line 107
    const/16 v8, 0x2492

    .line 108
    .line 109
    const/4 v9, 0x1

    .line 110
    const/4 v10, 0x0

    .line 111
    if-eq v3, v8, :cond_a

    .line 112
    .line 113
    move v3, v9

    .line 114
    goto :goto_6

    .line 115
    :cond_a
    move v3, v10

    .line 116
    :goto_6
    and-int/2addr v2, v9

    .line 117
    invoke-virtual {v0, v2, v3}, Ll2/t;->O(IZ)Z

    .line 118
    .line 119
    .line 120
    move-result v2

    .line 121
    if-eqz v2, :cond_b

    .line 122
    .line 123
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 124
    .line 125
    .line 126
    const v2, -0x3c90c813

    .line 127
    .line 128
    .line 129
    invoke-virtual {v0, v2}, Ll2/t;->Y(I)V

    .line 130
    .line 131
    .line 132
    invoke-virtual {v0, v10}, Ll2/t;->q(Z)V

    .line 133
    .line 134
    .line 135
    invoke-virtual {v0, v2}, Ll2/t;->Y(I)V

    .line 136
    .line 137
    .line 138
    invoke-virtual {v0, v10}, Ll2/t;->q(Z)V

    .line 139
    .line 140
    .line 141
    const v2, 0x7f120f53

    .line 142
    .line 143
    .line 144
    invoke-static {v0, v2}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 145
    .line 146
    .line 147
    move-result-object v2

    .line 148
    const v3, 0x7f120f52

    .line 149
    .line 150
    .line 151
    invoke-static {v0, v3}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 152
    .line 153
    .line 154
    move-result-object v13

    .line 155
    const/4 v10, 0x0

    .line 156
    const/16 v12, 0xf

    .line 157
    .line 158
    const/4 v8, 0x0

    .line 159
    const/4 v9, 0x0

    .line 160
    invoke-static/range {v7 .. v12}, Landroidx/compose/foundation/a;->f(Lx2/s;ZLjava/lang/String;Ld4/i;Lay0/a;I)Lx2/s;

    .line 161
    .line 162
    .line 163
    move-result-object v8

    .line 164
    invoke-static {v8, v3}, Lxf0/i0;->H(Lx2/s;I)Lx2/s;

    .line 165
    .line 166
    .line 167
    move-result-object v9

    .line 168
    const/16 v24, 0x0

    .line 169
    .line 170
    const/16 v25, 0x7f08

    .line 171
    .line 172
    const-string v10, ""

    .line 173
    .line 174
    const/4 v11, 0x0

    .line 175
    const/4 v12, 0x0

    .line 176
    move-object v8, v13

    .line 177
    const/4 v13, 0x0

    .line 178
    const/4 v14, 0x0

    .line 179
    const-wide/16 v15, 0x0

    .line 180
    .line 181
    const/16 v17, 0x0

    .line 182
    .line 183
    const/16 v18, 0x0

    .line 184
    .line 185
    const/16 v19, 0x0

    .line 186
    .line 187
    const/16 v20, 0x0

    .line 188
    .line 189
    const/16 v21, 0x0

    .line 190
    .line 191
    const v23, 0xdb6000

    .line 192
    .line 193
    .line 194
    move-object/from16 v22, v0

    .line 195
    .line 196
    move-object v7, v2

    .line 197
    invoke-static/range {v7 .. v25}, Lxf0/i0;->r(Ljava/lang/String;Ljava/lang/String;Lx2/s;Ljava/lang/String;ZZZLe3/s;JZLay0/k;Lay0/a;Ljava/lang/String;Lx2/s;Ll2/o;III)V

    .line 198
    .line 199
    .line 200
    goto :goto_7

    .line 201
    :cond_b
    move-object/from16 v22, v0

    .line 202
    .line 203
    invoke-virtual/range {v22 .. v22}, Ll2/t;->R()V

    .line 204
    .line 205
    .line 206
    :goto_7
    invoke-virtual/range {v22 .. v22}, Ll2/t;->s()Ll2/u1;

    .line 207
    .line 208
    .line 209
    move-result-object v8

    .line 210
    if-eqz v8, :cond_c

    .line 211
    .line 212
    new-instance v0, La71/c0;

    .line 213
    .line 214
    const/16 v7, 0x9

    .line 215
    .line 216
    move-object/from16 v2, p1

    .line 217
    .line 218
    move-object/from16 v3, p2

    .line 219
    .line 220
    invoke-direct/range {v0 .. v7}, La71/c0;-><init>(Lql0/h;Lx2/s;Lay0/a;Lay0/a;Lay0/a;II)V

    .line 221
    .line 222
    .line 223
    iput-object v0, v8, Ll2/u1;->d:Lay0/n;

    .line 224
    .line 225
    :cond_c
    return-void
.end method

.method public static final c(Ll2/o;I)V
    .locals 12

    .line 1
    check-cast p0, Ll2/t;

    .line 2
    .line 3
    const v0, 0x316756b

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    const/4 v0, 0x1

    .line 10
    const/4 v1, 0x0

    .line 11
    if-eqz p1, :cond_0

    .line 12
    .line 13
    move v2, v0

    .line 14
    goto :goto_0

    .line 15
    :cond_0
    move v2, v1

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
    if-eqz v2, :cond_6

    .line 23
    .line 24
    const v2, -0x6040e0aa

    .line 25
    .line 26
    .line 27
    invoke-virtual {p0, v2}, Ll2/t;->Y(I)V

    .line 28
    .line 29
    .line 30
    invoke-static {p0}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 31
    .line 32
    .line 33
    move-result-object v2

    .line 34
    if-eqz v2, :cond_5

    .line 35
    .line 36
    invoke-static {v2}, Ljp/ib;->a(Landroidx/lifecycle/i1;)Lp7/c;

    .line 37
    .line 38
    .line 39
    move-result-object v6

    .line 40
    invoke-static {p0}, Lw11/c;->b(Ll2/o;)Lk21/a;

    .line 41
    .line 42
    .line 43
    move-result-object v8

    .line 44
    const-class v3, Lg70/e;

    .line 45
    .line 46
    sget-object v4, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 47
    .line 48
    invoke-virtual {v4, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 49
    .line 50
    .line 51
    move-result-object v3

    .line 52
    invoke-interface {v2}, Landroidx/lifecycle/i1;->getViewModelStore()Landroidx/lifecycle/h1;

    .line 53
    .line 54
    .line 55
    move-result-object v4

    .line 56
    const/4 v5, 0x0

    .line 57
    const/4 v7, 0x0

    .line 58
    const/4 v9, 0x0

    .line 59
    invoke-static/range {v3 .. v9}, Ljp/lb;->a(Lhy0/d;Landroidx/lifecycle/h1;Ljava/lang/String;Lp7/c;Lh21/b;Lk21/a;Lay0/a;)Landroidx/lifecycle/b1;

    .line 60
    .line 61
    .line 62
    move-result-object v2

    .line 63
    invoke-virtual {p0, v1}, Ll2/t;->q(Z)V

    .line 64
    .line 65
    .line 66
    check-cast v2, Lql0/j;

    .line 67
    .line 68
    invoke-static {v2, p0, v1, v0}, Lkp/x5;->b(Lql0/j;Ll2/o;II)V

    .line 69
    .line 70
    .line 71
    move-object v5, v2

    .line 72
    check-cast v5, Lg70/e;

    .line 73
    .line 74
    invoke-virtual {p0, v5}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 75
    .line 76
    .line 77
    move-result v0

    .line 78
    invoke-virtual {p0}, Ll2/t;->L()Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object v2

    .line 82
    sget-object v11, Ll2/n;->a:Ll2/x0;

    .line 83
    .line 84
    if-nez v0, :cond_1

    .line 85
    .line 86
    if-ne v2, v11, :cond_2

    .line 87
    .line 88
    :cond_1
    new-instance v3, Lh10/e;

    .line 89
    .line 90
    const/4 v9, 0x0

    .line 91
    const/16 v10, 0xc

    .line 92
    .line 93
    const/4 v4, 0x0

    .line 94
    const-class v6, Lg70/e;

    .line 95
    .line 96
    const-string v7, "onGoBack"

    .line 97
    .line 98
    const-string v8, "onGoBack()V"

    .line 99
    .line 100
    invoke-direct/range {v3 .. v10}, Lh10/e;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 101
    .line 102
    .line 103
    invoke-virtual {p0, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 104
    .line 105
    .line 106
    move-object v2, v3

    .line 107
    :cond_2
    check-cast v2, Lhy0/g;

    .line 108
    .line 109
    check-cast v2, Lay0/a;

    .line 110
    .line 111
    invoke-virtual {p0, v5}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 112
    .line 113
    .line 114
    move-result v0

    .line 115
    invoke-virtual {p0}, Ll2/t;->L()Ljava/lang/Object;

    .line 116
    .line 117
    .line 118
    move-result-object v3

    .line 119
    if-nez v0, :cond_3

    .line 120
    .line 121
    if-ne v3, v11, :cond_4

    .line 122
    .line 123
    :cond_3
    new-instance v3, Lei/a;

    .line 124
    .line 125
    const/4 v9, 0x0

    .line 126
    const/16 v10, 0x16

    .line 127
    .line 128
    const/4 v4, 0x1

    .line 129
    const-class v6, Lg70/e;

    .line 130
    .line 131
    const-string v7, "onOpenMoreInformation"

    .line 132
    .line 133
    const-string v8, "onOpenMoreInformation(Ljava/lang/String;)V"

    .line 134
    .line 135
    invoke-direct/range {v3 .. v10}, Lei/a;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 136
    .line 137
    .line 138
    invoke-virtual {p0, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 139
    .line 140
    .line 141
    :cond_4
    check-cast v3, Lhy0/g;

    .line 142
    .line 143
    check-cast v3, Lay0/k;

    .line 144
    .line 145
    invoke-static {v1, v2, v3, p0}, Lh70/a;->d(ILay0/a;Lay0/k;Ll2/o;)V

    .line 146
    .line 147
    .line 148
    goto :goto_1

    .line 149
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 150
    .line 151
    const-string p1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 152
    .line 153
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 154
    .line 155
    .line 156
    throw p0

    .line 157
    :cond_6
    invoke-virtual {p0}, Ll2/t;->R()V

    .line 158
    .line 159
    .line 160
    :goto_1
    invoke-virtual {p0}, Ll2/t;->s()Ll2/u1;

    .line 161
    .line 162
    .line 163
    move-result-object p0

    .line 164
    if-eqz p0, :cond_7

    .line 165
    .line 166
    new-instance v0, Lh60/b;

    .line 167
    .line 168
    const/4 v1, 0x4

    .line 169
    invoke-direct {v0, p1, v1}, Lh60/b;-><init>(II)V

    .line 170
    .line 171
    .line 172
    iput-object v0, p0, Ll2/u1;->d:Lay0/n;

    .line 173
    .line 174
    :cond_7
    return-void
.end method

.method public static final d(ILay0/a;Lay0/k;Ll2/o;)V
    .locals 18

    .line 1
    move/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v2, p2

    .line 6
    .line 7
    move-object/from16 v15, p3

    .line 8
    .line 9
    check-cast v15, Ll2/t;

    .line 10
    .line 11
    const v3, 0x22978378

    .line 12
    .line 13
    .line 14
    invoke-virtual {v15, v3}, Ll2/t;->a0(I)Ll2/t;

    .line 15
    .line 16
    .line 17
    invoke-virtual {v15, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v3

    .line 21
    if-eqz v3, :cond_0

    .line 22
    .line 23
    const/4 v3, 0x4

    .line 24
    goto :goto_0

    .line 25
    :cond_0
    const/4 v3, 0x2

    .line 26
    :goto_0
    or-int/2addr v3, v0

    .line 27
    invoke-virtual {v15, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result v4

    .line 31
    if-eqz v4, :cond_1

    .line 32
    .line 33
    const/16 v4, 0x20

    .line 34
    .line 35
    goto :goto_1

    .line 36
    :cond_1
    const/16 v4, 0x10

    .line 37
    .line 38
    :goto_1
    or-int/2addr v3, v4

    .line 39
    and-int/lit8 v4, v3, 0x13

    .line 40
    .line 41
    const/16 v5, 0x12

    .line 42
    .line 43
    const/4 v6, 0x1

    .line 44
    if-eq v4, v5, :cond_2

    .line 45
    .line 46
    move v4, v6

    .line 47
    goto :goto_2

    .line 48
    :cond_2
    const/4 v4, 0x0

    .line 49
    :goto_2
    and-int/2addr v3, v6

    .line 50
    invoke-virtual {v15, v3, v4}, Ll2/t;->O(IZ)Z

    .line 51
    .line 52
    .line 53
    move-result v3

    .line 54
    if-eqz v3, :cond_3

    .line 55
    .line 56
    new-instance v3, Lb60/d;

    .line 57
    .line 58
    const/16 v4, 0x17

    .line 59
    .line 60
    invoke-direct {v3, v1, v4}, Lb60/d;-><init>(Lay0/a;I)V

    .line 61
    .line 62
    .line 63
    const v4, 0x7a90cf34

    .line 64
    .line 65
    .line 66
    invoke-static {v4, v15, v3}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 67
    .line 68
    .line 69
    move-result-object v4

    .line 70
    new-instance v3, Lak/l;

    .line 71
    .line 72
    const/16 v5, 0xc

    .line 73
    .line 74
    invoke-direct {v3, v5, v2}, Lak/l;-><init>(ILay0/k;)V

    .line 75
    .line 76
    .line 77
    const v5, 0x3d0bffc9

    .line 78
    .line 79
    .line 80
    invoke-static {v5, v15, v3}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 81
    .line 82
    .line 83
    move-result-object v14

    .line 84
    const v16, 0x30000030

    .line 85
    .line 86
    .line 87
    const/16 v17, 0x1fd

    .line 88
    .line 89
    const/4 v3, 0x0

    .line 90
    const/4 v5, 0x0

    .line 91
    const/4 v6, 0x0

    .line 92
    const/4 v7, 0x0

    .line 93
    const/4 v8, 0x0

    .line 94
    const-wide/16 v9, 0x0

    .line 95
    .line 96
    const-wide/16 v11, 0x0

    .line 97
    .line 98
    const/4 v13, 0x0

    .line 99
    invoke-static/range {v3 .. v17}, Lh2/c8;->a(Lx2/s;Lay0/n;Lay0/n;Lay0/n;Lay0/n;IJJLk1/q1;Lay0/o;Ll2/o;II)V

    .line 100
    .line 101
    .line 102
    goto :goto_3

    .line 103
    :cond_3
    invoke-virtual {v15}, Ll2/t;->R()V

    .line 104
    .line 105
    .line 106
    :goto_3
    invoke-virtual {v15}, Ll2/t;->s()Ll2/u1;

    .line 107
    .line 108
    .line 109
    move-result-object v3

    .line 110
    if-eqz v3, :cond_4

    .line 111
    .line 112
    new-instance v4, Lcf/b;

    .line 113
    .line 114
    const/4 v5, 0x1

    .line 115
    invoke-direct {v4, v1, v2, v0, v5}, Lcf/b;-><init>(Lay0/a;Lay0/k;II)V

    .line 116
    .line 117
    .line 118
    iput-object v4, v3, Ll2/u1;->d:Lay0/n;

    .line 119
    .line 120
    :cond_4
    return-void
.end method
