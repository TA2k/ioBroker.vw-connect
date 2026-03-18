.class public abstract Ld90/l;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:F


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const/16 v0, 0x66

    .line 2
    .line 3
    int-to-float v0, v0

    .line 4
    sput v0, Ld90/l;->a:F

    .line 5
    .line 6
    return-void
.end method

.method public static final a(Ll2/o;I)V
    .locals 14

    .line 1
    move-object v5, p0

    .line 2
    check-cast v5, Ll2/t;

    .line 3
    .line 4
    const p0, 0xaf39465

    .line 5
    .line 6
    .line 7
    invoke-virtual {v5, p0}, Ll2/t;->a0(I)Ll2/t;

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
    invoke-virtual {v5, v2, v1}, Ll2/t;->O(IZ)Z

    .line 20
    .line 21
    .line 22
    move-result v1

    .line 23
    if-eqz v1, :cond_a

    .line 24
    .line 25
    const v1, -0x6040e0aa

    .line 26
    .line 27
    .line 28
    invoke-virtual {v5, v1}, Ll2/t;->Y(I)V

    .line 29
    .line 30
    .line 31
    invoke-static {v5}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 32
    .line 33
    .line 34
    move-result-object v1

    .line 35
    if-eqz v1, :cond_9

    .line 36
    .line 37
    invoke-static {v1}, Ljp/ib;->a(Landroidx/lifecycle/i1;)Lp7/c;

    .line 38
    .line 39
    .line 40
    move-result-object v9

    .line 41
    invoke-static {v5}, Lw11/c;->b(Ll2/o;)Lk21/a;

    .line 42
    .line 43
    .line 44
    move-result-object v11

    .line 45
    const-class v2, Lc90/g0;

    .line 46
    .line 47
    sget-object v3, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 48
    .line 49
    invoke-virtual {v3, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 50
    .line 51
    .line 52
    move-result-object v6

    .line 53
    invoke-interface {v1}, Landroidx/lifecycle/i1;->getViewModelStore()Landroidx/lifecycle/h1;

    .line 54
    .line 55
    .line 56
    move-result-object v7

    .line 57
    const/4 v8, 0x0

    .line 58
    const/4 v10, 0x0

    .line 59
    const/4 v12, 0x0

    .line 60
    invoke-static/range {v6 .. v12}, Ljp/lb;->a(Lhy0/d;Landroidx/lifecycle/h1;Ljava/lang/String;Lp7/c;Lh21/b;Lk21/a;Lay0/a;)Landroidx/lifecycle/b1;

    .line 61
    .line 62
    .line 63
    move-result-object v1

    .line 64
    invoke-virtual {v5, v0}, Ll2/t;->q(Z)V

    .line 65
    .line 66
    .line 67
    check-cast v1, Lql0/j;

    .line 68
    .line 69
    invoke-static {v1, v5, v0, p0}, Lkp/x5;->b(Lql0/j;Ll2/o;II)V

    .line 70
    .line 71
    .line 72
    move-object v8, v1

    .line 73
    check-cast v8, Lc90/g0;

    .line 74
    .line 75
    iget-object v0, v8, Lql0/j;->g:Lyy0/l1;

    .line 76
    .line 77
    const/4 v1, 0x0

    .line 78
    invoke-static {v0, v1, v5, p0}, Ll2/b;->f(Lyy0/a2;Lwy0/c;Ll2/o;I)Ll2/b1;

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
    check-cast v0, Lc90/e0;

    .line 88
    .line 89
    invoke-virtual {v5, v8}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 90
    .line 91
    .line 92
    move-result p0

    .line 93
    invoke-virtual {v5}, Ll2/t;->L()Ljava/lang/Object;

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
    new-instance v6, Ld80/l;

    .line 104
    .line 105
    const/4 v12, 0x0

    .line 106
    const/16 v13, 0x1c

    .line 107
    .line 108
    const/4 v7, 0x0

    .line 109
    const-class v9, Lc90/g0;

    .line 110
    .line 111
    const-string v10, "onBack"

    .line 112
    .line 113
    const-string v11, "onBack()V"

    .line 114
    .line 115
    invoke-direct/range {v6 .. v13}, Ld80/l;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 116
    .line 117
    .line 118
    invoke-virtual {v5, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 119
    .line 120
    .line 121
    move-object v1, v6

    .line 122
    :cond_2
    check-cast v1, Lhy0/g;

    .line 123
    .line 124
    check-cast v1, Lay0/a;

    .line 125
    .line 126
    invoke-virtual {v5, v8}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 127
    .line 128
    .line 129
    move-result p0

    .line 130
    invoke-virtual {v5}, Ll2/t;->L()Ljava/lang/Object;

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
    new-instance v6, Ld80/l;

    .line 139
    .line 140
    const/4 v12, 0x0

    .line 141
    const/16 v13, 0x1d

    .line 142
    .line 143
    const/4 v7, 0x0

    .line 144
    const-class v9, Lc90/g0;

    .line 145
    .line 146
    const-string v10, "onClose"

    .line 147
    .line 148
    const-string v11, "onClose()V"

    .line 149
    .line 150
    invoke-direct/range {v6 .. v13}, Ld80/l;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 151
    .line 152
    .line 153
    invoke-virtual {v5, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 154
    .line 155
    .line 156
    move-object v3, v6

    .line 157
    :cond_4
    check-cast v3, Lhy0/g;

    .line 158
    .line 159
    check-cast v3, Lay0/a;

    .line 160
    .line 161
    invoke-virtual {v5, v8}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 162
    .line 163
    .line 164
    move-result p0

    .line 165
    invoke-virtual {v5}, Ll2/t;->L()Ljava/lang/Object;

    .line 166
    .line 167
    .line 168
    move-result-object v4

    .line 169
    if-nez p0, :cond_5

    .line 170
    .line 171
    if-ne v4, v2, :cond_6

    .line 172
    .line 173
    :cond_5
    new-instance v6, Lcz/j;

    .line 174
    .line 175
    const/4 v12, 0x0

    .line 176
    const/16 v13, 0xe

    .line 177
    .line 178
    const/4 v7, 0x1

    .line 179
    const-class v9, Lc90/g0;

    .line 180
    .line 181
    const-string v10, "onErrorConsumed"

    .line 182
    .line 183
    const-string v11, "onErrorConsumed(Lcz/skodaauto/myskoda/library/mvvm/presentation/AbstractViewModel$State$Error$Type;)V"

    .line 184
    .line 185
    invoke-direct/range {v6 .. v13}, Lcz/j;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 186
    .line 187
    .line 188
    invoke-virtual {v5, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 189
    .line 190
    .line 191
    move-object v4, v6

    .line 192
    :cond_6
    check-cast v4, Lhy0/g;

    .line 193
    .line 194
    check-cast v4, Lay0/k;

    .line 195
    .line 196
    invoke-virtual {v5, v8}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 197
    .line 198
    .line 199
    move-result p0

    .line 200
    invoke-virtual {v5}, Ll2/t;->L()Ljava/lang/Object;

    .line 201
    .line 202
    .line 203
    move-result-object v6

    .line 204
    if-nez p0, :cond_7

    .line 205
    .line 206
    if-ne v6, v2, :cond_8

    .line 207
    .line 208
    :cond_7
    new-instance v6, Lcz/j;

    .line 209
    .line 210
    const/4 v12, 0x0

    .line 211
    const/16 v13, 0xf

    .line 212
    .line 213
    const/4 v7, 0x1

    .line 214
    const-class v9, Lc90/g0;

    .line 215
    .line 216
    const-string v10, "onModelSelected"

    .line 217
    .line 218
    const-string v11, "onModelSelected(Lcz/skodaauto/myskoda/feature/testdrive/presentation/ModelState;)V"

    .line 219
    .line 220
    invoke-direct/range {v6 .. v13}, Lcz/j;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 221
    .line 222
    .line 223
    invoke-virtual {v5, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 224
    .line 225
    .line 226
    :cond_8
    check-cast v6, Lhy0/g;

    .line 227
    .line 228
    check-cast v6, Lay0/k;

    .line 229
    .line 230
    move-object v2, v3

    .line 231
    move-object v3, v4

    .line 232
    move-object v4, v6

    .line 233
    const/4 v6, 0x0

    .line 234
    invoke-static/range {v0 .. v6}, Ld90/l;->b(Lc90/e0;Lay0/a;Lay0/a;Lay0/k;Lay0/k;Ll2/o;I)V

    .line 235
    .line 236
    .line 237
    goto :goto_1

    .line 238
    :cond_9
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 239
    .line 240
    const-string p1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 241
    .line 242
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 243
    .line 244
    .line 245
    throw p0

    .line 246
    :cond_a
    invoke-virtual {v5}, Ll2/t;->R()V

    .line 247
    .line 248
    .line 249
    :goto_1
    invoke-virtual {v5}, Ll2/t;->s()Ll2/u1;

    .line 250
    .line 251
    .line 252
    move-result-object p0

    .line 253
    if-eqz p0, :cond_b

    .line 254
    .line 255
    new-instance v0, Ld80/m;

    .line 256
    .line 257
    const/16 v1, 0x8

    .line 258
    .line 259
    invoke-direct {v0, p1, v1}, Ld80/m;-><init>(II)V

    .line 260
    .line 261
    .line 262
    iput-object v0, p0, Ll2/u1;->d:Lay0/n;

    .line 263
    .line 264
    :cond_b
    return-void
.end method

.method public static final b(Lc90/e0;Lay0/a;Lay0/a;Lay0/k;Lay0/k;Ll2/o;I)V
    .locals 21

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
    move-object/from16 v5, p4

    .line 8
    .line 9
    move-object/from16 v9, p5

    .line 10
    .line 11
    check-cast v9, Ll2/t;

    .line 12
    .line 13
    const v0, 0x236a7aa0

    .line 14
    .line 15
    .line 16
    invoke-virtual {v9, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 17
    .line 18
    .line 19
    invoke-virtual {v9, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

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
    or-int v0, p6, v0

    .line 29
    .line 30
    invoke-virtual {v9, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 31
    .line 32
    .line 33
    move-result v4

    .line 34
    const/16 v6, 0x20

    .line 35
    .line 36
    if-eqz v4, :cond_1

    .line 37
    .line 38
    move v4, v6

    .line 39
    goto :goto_1

    .line 40
    :cond_1
    const/16 v4, 0x10

    .line 41
    .line 42
    :goto_1
    or-int/2addr v0, v4

    .line 43
    invoke-virtual {v9, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 44
    .line 45
    .line 46
    move-result v4

    .line 47
    if-eqz v4, :cond_2

    .line 48
    .line 49
    const/16 v4, 0x100

    .line 50
    .line 51
    goto :goto_2

    .line 52
    :cond_2
    const/16 v4, 0x80

    .line 53
    .line 54
    :goto_2
    or-int/2addr v0, v4

    .line 55
    move-object/from16 v4, p3

    .line 56
    .line 57
    invoke-virtual {v9, v4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 58
    .line 59
    .line 60
    move-result v7

    .line 61
    if-eqz v7, :cond_3

    .line 62
    .line 63
    const/16 v7, 0x800

    .line 64
    .line 65
    goto :goto_3

    .line 66
    :cond_3
    const/16 v7, 0x400

    .line 67
    .line 68
    :goto_3
    or-int/2addr v0, v7

    .line 69
    invoke-virtual {v9, v5}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 70
    .line 71
    .line 72
    move-result v7

    .line 73
    if-eqz v7, :cond_4

    .line 74
    .line 75
    const/16 v7, 0x4000

    .line 76
    .line 77
    goto :goto_4

    .line 78
    :cond_4
    const/16 v7, 0x2000

    .line 79
    .line 80
    :goto_4
    or-int/2addr v0, v7

    .line 81
    and-int/lit16 v7, v0, 0x2493

    .line 82
    .line 83
    const/16 v8, 0x2492

    .line 84
    .line 85
    const/4 v12, 0x0

    .line 86
    const/4 v10, 0x1

    .line 87
    if-eq v7, v8, :cond_5

    .line 88
    .line 89
    move v7, v10

    .line 90
    goto :goto_5

    .line 91
    :cond_5
    move v7, v12

    .line 92
    :goto_5
    and-int/lit8 v8, v0, 0x1

    .line 93
    .line 94
    invoke-virtual {v9, v8, v7}, Ll2/t;->O(IZ)Z

    .line 95
    .line 96
    .line 97
    move-result v7

    .line 98
    if-eqz v7, :cond_a

    .line 99
    .line 100
    iget-object v7, v1, Lc90/e0;->b:Lql0/g;

    .line 101
    .line 102
    if-nez v7, :cond_6

    .line 103
    .line 104
    const v0, 0x641878bf

    .line 105
    .line 106
    .line 107
    invoke-virtual {v9, v0}, Ll2/t;->Y(I)V

    .line 108
    .line 109
    .line 110
    invoke-virtual {v9, v12}, Ll2/t;->q(Z)V

    .line 111
    .line 112
    .line 113
    new-instance v0, Laa/w;

    .line 114
    .line 115
    const/16 v6, 0x17

    .line 116
    .line 117
    invoke-direct {v0, v2, v3, v1, v6}, Laa/w;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 118
    .line 119
    .line 120
    const v6, -0x70be6aa4

    .line 121
    .line 122
    .line 123
    invoke-static {v6, v9, v0}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 124
    .line 125
    .line 126
    move-result-object v7

    .line 127
    new-instance v0, Lal/d;

    .line 128
    .line 129
    const/16 v6, 0x17

    .line 130
    .line 131
    invoke-direct {v0, v6, v1, v5}, Lal/d;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 132
    .line 133
    .line 134
    const v6, -0x267aaccf

    .line 135
    .line 136
    .line 137
    invoke-static {v6, v9, v0}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 138
    .line 139
    .line 140
    move-result-object v17

    .line 141
    const v19, 0x30000030

    .line 142
    .line 143
    .line 144
    const/16 v20, 0x1fd

    .line 145
    .line 146
    const/4 v6, 0x0

    .line 147
    const/4 v8, 0x0

    .line 148
    move-object/from16 v18, v9

    .line 149
    .line 150
    const/4 v9, 0x0

    .line 151
    const/4 v10, 0x0

    .line 152
    const/4 v11, 0x0

    .line 153
    const-wide/16 v12, 0x0

    .line 154
    .line 155
    const-wide/16 v14, 0x0

    .line 156
    .line 157
    const/16 v16, 0x0

    .line 158
    .line 159
    invoke-static/range {v6 .. v20}, Lh2/c8;->a(Lx2/s;Lay0/n;Lay0/n;Lay0/n;Lay0/n;IJJLk1/q1;Lay0/o;Ll2/o;II)V

    .line 160
    .line 161
    .line 162
    move-object/from16 v9, v18

    .line 163
    .line 164
    goto :goto_8

    .line 165
    :cond_6
    const v8, 0x641878c0

    .line 166
    .line 167
    .line 168
    invoke-virtual {v9, v8}, Ll2/t;->Y(I)V

    .line 169
    .line 170
    .line 171
    and-int/lit8 v8, v0, 0x70

    .line 172
    .line 173
    if-ne v8, v6, :cond_7

    .line 174
    .line 175
    goto :goto_6

    .line 176
    :cond_7
    move v10, v12

    .line 177
    :goto_6
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 178
    .line 179
    .line 180
    move-result-object v6

    .line 181
    if-nez v10, :cond_8

    .line 182
    .line 183
    sget-object v8, Ll2/n;->a:Ll2/x0;

    .line 184
    .line 185
    if-ne v6, v8, :cond_9

    .line 186
    .line 187
    :cond_8
    new-instance v6, Laj0/c;

    .line 188
    .line 189
    const/16 v8, 0x10

    .line 190
    .line 191
    invoke-direct {v6, v2, v8}, Laj0/c;-><init>(Lay0/a;I)V

    .line 192
    .line 193
    .line 194
    invoke-virtual {v9, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 195
    .line 196
    .line 197
    :cond_9
    move-object v8, v6

    .line 198
    check-cast v8, Lay0/k;

    .line 199
    .line 200
    shr-int/lit8 v0, v0, 0x6

    .line 201
    .line 202
    and-int/lit8 v10, v0, 0x70

    .line 203
    .line 204
    const/4 v11, 0x0

    .line 205
    move-object v6, v7

    .line 206
    move-object v7, v4

    .line 207
    invoke-static/range {v6 .. v11}, Lyg0/a;->a(Lql0/g;Lay0/k;Lay0/k;Ll2/o;II)V

    .line 208
    .line 209
    .line 210
    invoke-virtual {v9, v12}, Ll2/t;->q(Z)V

    .line 211
    .line 212
    .line 213
    invoke-virtual {v9}, Ll2/t;->s()Ll2/u1;

    .line 214
    .line 215
    .line 216
    move-result-object v8

    .line 217
    if-eqz v8, :cond_b

    .line 218
    .line 219
    new-instance v0, Ld90/j;

    .line 220
    .line 221
    const/4 v7, 0x0

    .line 222
    move-object/from16 v4, p3

    .line 223
    .line 224
    move/from16 v6, p6

    .line 225
    .line 226
    invoke-direct/range {v0 .. v7}, Ld90/j;-><init>(Lc90/e0;Lay0/a;Lay0/a;Lay0/k;Lay0/k;II)V

    .line 227
    .line 228
    .line 229
    :goto_7
    iput-object v0, v8, Ll2/u1;->d:Lay0/n;

    .line 230
    .line 231
    return-void

    .line 232
    :cond_a
    invoke-virtual {v9}, Ll2/t;->R()V

    .line 233
    .line 234
    .line 235
    :goto_8
    invoke-virtual {v9}, Ll2/t;->s()Ll2/u1;

    .line 236
    .line 237
    .line 238
    move-result-object v8

    .line 239
    if-eqz v8, :cond_b

    .line 240
    .line 241
    new-instance v0, Ld90/j;

    .line 242
    .line 243
    const/4 v7, 0x1

    .line 244
    move-object/from16 v1, p0

    .line 245
    .line 246
    move-object/from16 v2, p1

    .line 247
    .line 248
    move-object/from16 v3, p2

    .line 249
    .line 250
    move-object/from16 v4, p3

    .line 251
    .line 252
    move-object/from16 v5, p4

    .line 253
    .line 254
    move/from16 v6, p6

    .line 255
    .line 256
    invoke-direct/range {v0 .. v7}, Ld90/j;-><init>(Lc90/e0;Lay0/a;Lay0/a;Lay0/k;Lay0/k;II)V

    .line 257
    .line 258
    .line 259
    goto :goto_7

    .line 260
    :cond_b
    return-void
.end method
