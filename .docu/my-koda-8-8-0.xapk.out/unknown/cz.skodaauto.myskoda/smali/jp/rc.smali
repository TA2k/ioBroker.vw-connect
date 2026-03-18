.class public abstract Ljp/rc;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Ll2/o;I)V
    .locals 12

    .line 1
    check-cast p0, Ll2/t;

    .line 2
    .line 3
    const v0, -0x3e088d4c

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
    const-class v3, Lb40/c;

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
    check-cast v5, Lb40/c;

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
    new-instance v3, Lc3/g;

    .line 89
    .line 90
    const/4 v9, 0x0

    .line 91
    const/4 v10, 0x4

    .line 92
    const/4 v4, 0x0

    .line 93
    const-class v6, Lb40/c;

    .line 94
    .line 95
    const-string v7, "onLogin"

    .line 96
    .line 97
    const-string v8, "onLogin()V"

    .line 98
    .line 99
    invoke-direct/range {v3 .. v10}, Lc3/g;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 100
    .line 101
    .line 102
    invoke-virtual {p0, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 103
    .line 104
    .line 105
    move-object v2, v3

    .line 106
    :cond_2
    check-cast v2, Lhy0/g;

    .line 107
    .line 108
    check-cast v2, Lay0/a;

    .line 109
    .line 110
    invoke-virtual {p0, v5}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 111
    .line 112
    .line 113
    move-result v0

    .line 114
    invoke-virtual {p0}, Ll2/t;->L()Ljava/lang/Object;

    .line 115
    .line 116
    .line 117
    move-result-object v3

    .line 118
    if-nez v0, :cond_3

    .line 119
    .line 120
    if-ne v3, v11, :cond_4

    .line 121
    .line 122
    :cond_3
    new-instance v3, Lc3/g;

    .line 123
    .line 124
    const/4 v9, 0x0

    .line 125
    const/4 v10, 0x5

    .line 126
    const/4 v4, 0x0

    .line 127
    const-class v6, Lb40/c;

    .line 128
    .line 129
    const-string v7, "onDemoOnboarding"

    .line 130
    .line 131
    const-string v8, "onDemoOnboarding()V"

    .line 132
    .line 133
    invoke-direct/range {v3 .. v10}, Lc3/g;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 134
    .line 135
    .line 136
    invoke-virtual {p0, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 137
    .line 138
    .line 139
    :cond_4
    check-cast v3, Lhy0/g;

    .line 140
    .line 141
    check-cast v3, Lay0/a;

    .line 142
    .line 143
    invoke-static {v2, v3, p0, v1}, Ljp/rc;->b(Lay0/a;Lay0/a;Ll2/o;I)V

    .line 144
    .line 145
    .line 146
    goto :goto_1

    .line 147
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 148
    .line 149
    const-string p1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 150
    .line 151
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 152
    .line 153
    .line 154
    throw p0

    .line 155
    :cond_6
    invoke-virtual {p0}, Ll2/t;->R()V

    .line 156
    .line 157
    .line 158
    :goto_1
    invoke-virtual {p0}, Ll2/t;->s()Ll2/u1;

    .line 159
    .line 160
    .line 161
    move-result-object p0

    .line 162
    if-eqz p0, :cond_7

    .line 163
    .line 164
    new-instance v0, Lb60/b;

    .line 165
    .line 166
    const/16 v1, 0x16

    .line 167
    .line 168
    invoke-direct {v0, p1, v1}, Lb60/b;-><init>(II)V

    .line 169
    .line 170
    .line 171
    iput-object v0, p0, Ll2/u1;->d:Lay0/n;

    .line 172
    .line 173
    :cond_7
    return-void
.end method

.method public static final b(Lay0/a;Lay0/a;Ll2/o;I)V
    .locals 16

    .line 1
    move-object/from16 v4, p0

    .line 2
    .line 3
    move-object/from16 v5, p1

    .line 4
    .line 5
    move/from16 v7, p3

    .line 6
    .line 7
    move-object/from16 v8, p2

    .line 8
    .line 9
    check-cast v8, Ll2/t;

    .line 10
    .line 11
    const v0, -0x2c0a1ad4

    .line 12
    .line 13
    .line 14
    invoke-virtual {v8, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 15
    .line 16
    .line 17
    invoke-virtual {v8, v4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    if-eqz v0, :cond_0

    .line 22
    .line 23
    const/4 v0, 0x4

    .line 24
    goto :goto_0

    .line 25
    :cond_0
    const/4 v0, 0x2

    .line 26
    :goto_0
    or-int/2addr v0, v7

    .line 27
    invoke-virtual {v8, v5}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result v1

    .line 31
    if-eqz v1, :cond_1

    .line 32
    .line 33
    const/16 v1, 0x20

    .line 34
    .line 35
    goto :goto_1

    .line 36
    :cond_1
    const/16 v1, 0x10

    .line 37
    .line 38
    :goto_1
    or-int/2addr v0, v1

    .line 39
    and-int/lit8 v1, v0, 0x13

    .line 40
    .line 41
    const/16 v2, 0x12

    .line 42
    .line 43
    const/4 v9, 0x0

    .line 44
    const/4 v3, 0x1

    .line 45
    if-eq v1, v2, :cond_2

    .line 46
    .line 47
    move v1, v3

    .line 48
    goto :goto_2

    .line 49
    :cond_2
    move v1, v9

    .line 50
    :goto_2
    and-int/2addr v0, v3

    .line 51
    invoke-virtual {v8, v0, v1}, Ll2/t;->O(IZ)Z

    .line 52
    .line 53
    .line 54
    move-result v0

    .line 55
    if-eqz v0, :cond_d

    .line 56
    .line 57
    sget-object v0, Landroidx/compose/foundation/layout/d;->c:Landroidx/compose/foundation/layout/FillElement;

    .line 58
    .line 59
    const v1, -0x3bced2e6

    .line 60
    .line 61
    .line 62
    invoke-virtual {v8, v1}, Ll2/t;->Y(I)V

    .line 63
    .line 64
    .line 65
    const v1, 0xca3d8b5

    .line 66
    .line 67
    .line 68
    invoke-virtual {v8, v1}, Ll2/t;->Y(I)V

    .line 69
    .line 70
    .line 71
    invoke-virtual {v8, v9}, Ll2/t;->q(Z)V

    .line 72
    .line 73
    .line 74
    sget-object v1, Lw3/h1;->h:Ll2/u2;

    .line 75
    .line 76
    invoke-virtual {v8, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 77
    .line 78
    .line 79
    move-result-object v1

    .line 80
    check-cast v1, Lt4/c;

    .line 81
    .line 82
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    move-result-object v2

    .line 86
    sget-object v3, Ll2/n;->a:Ll2/x0;

    .line 87
    .line 88
    if-ne v2, v3, :cond_3

    .line 89
    .line 90
    invoke-static {v1, v8}, Lvj/b;->t(Lt4/c;Ll2/t;)Lz4/p;

    .line 91
    .line 92
    .line 93
    move-result-object v2

    .line 94
    :cond_3
    move-object v12, v2

    .line 95
    check-cast v12, Lz4/p;

    .line 96
    .line 97
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 98
    .line 99
    .line 100
    move-result-object v1

    .line 101
    if-ne v1, v3, :cond_4

    .line 102
    .line 103
    invoke-static {v8}, Lvj/b;->r(Ll2/t;)Lz4/k;

    .line 104
    .line 105
    .line 106
    move-result-object v1

    .line 107
    :cond_4
    move-object v2, v1

    .line 108
    check-cast v2, Lz4/k;

    .line 109
    .line 110
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 111
    .line 112
    .line 113
    move-result-object v1

    .line 114
    if-ne v1, v3, :cond_5

    .line 115
    .line 116
    sget-object v1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 117
    .line 118
    invoke-static {v1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 119
    .line 120
    .line 121
    move-result-object v1

    .line 122
    invoke-virtual {v8, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 123
    .line 124
    .line 125
    :cond_5
    move-object v14, v1

    .line 126
    check-cast v14, Ll2/b1;

    .line 127
    .line 128
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 129
    .line 130
    .line 131
    move-result-object v1

    .line 132
    if-ne v1, v3, :cond_6

    .line 133
    .line 134
    invoke-static {v2, v8}, Lvj/b;->s(Lz4/k;Ll2/t;)Lz4/m;

    .line 135
    .line 136
    .line 137
    move-result-object v1

    .line 138
    :cond_6
    move-object v13, v1

    .line 139
    check-cast v13, Lz4/m;

    .line 140
    .line 141
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 142
    .line 143
    .line 144
    move-result-object v1

    .line 145
    if-ne v1, v3, :cond_7

    .line 146
    .line 147
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 148
    .line 149
    sget-object v6, Ll2/x0;->f:Ll2/x0;

    .line 150
    .line 151
    invoke-static {v1, v6, v8}, Lf2/m0;->r(Llx0/b0;Ll2/x0;Ll2/t;)Ll2/j1;

    .line 152
    .line 153
    .line 154
    move-result-object v1

    .line 155
    :cond_7
    check-cast v1, Ll2/b1;

    .line 156
    .line 157
    invoke-virtual {v8, v12}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 158
    .line 159
    .line 160
    move-result v6

    .line 161
    const/16 v10, 0x101

    .line 162
    .line 163
    invoke-virtual {v8, v10}, Ll2/t;->e(I)Z

    .line 164
    .line 165
    .line 166
    move-result v10

    .line 167
    or-int/2addr v6, v10

    .line 168
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 169
    .line 170
    .line 171
    move-result-object v10

    .line 172
    if-nez v6, :cond_8

    .line 173
    .line 174
    if-ne v10, v3, :cond_9

    .line 175
    .line 176
    :cond_8
    new-instance v10, Lc40/b;

    .line 177
    .line 178
    const/4 v15, 0x0

    .line 179
    move-object v11, v1

    .line 180
    invoke-direct/range {v10 .. v15}, Lc40/b;-><init>(Ll2/b1;Lz4/p;Lz4/m;Ll2/b1;I)V

    .line 181
    .line 182
    .line 183
    invoke-virtual {v8, v10}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 184
    .line 185
    .line 186
    :cond_9
    check-cast v10, Lt3/q0;

    .line 187
    .line 188
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 189
    .line 190
    .line 191
    move-result-object v6

    .line 192
    if-ne v6, v3, :cond_a

    .line 193
    .line 194
    new-instance v6, Lc40/c;

    .line 195
    .line 196
    const/4 v11, 0x0

    .line 197
    invoke-direct {v6, v14, v13, v11}, Lc40/c;-><init>(Ll2/b1;Lz4/m;I)V

    .line 198
    .line 199
    .line 200
    invoke-virtual {v8, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 201
    .line 202
    .line 203
    :cond_a
    check-cast v6, Lay0/a;

    .line 204
    .line 205
    invoke-virtual {v8, v12}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 206
    .line 207
    .line 208
    move-result v11

    .line 209
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 210
    .line 211
    .line 212
    move-result-object v13

    .line 213
    if-nez v11, :cond_b

    .line 214
    .line 215
    if-ne v13, v3, :cond_c

    .line 216
    .line 217
    :cond_b
    new-instance v13, Lc40/d;

    .line 218
    .line 219
    const/4 v3, 0x0

    .line 220
    invoke-direct {v13, v12, v3}, Lc40/d;-><init>(Lz4/p;I)V

    .line 221
    .line 222
    .line 223
    invoke-virtual {v8, v13}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 224
    .line 225
    .line 226
    :cond_c
    check-cast v13, Lay0/k;

    .line 227
    .line 228
    invoke-static {v0, v9, v13}, Ld4/n;->b(Lx2/s;ZLay0/k;)Lx2/s;

    .line 229
    .line 230
    .line 231
    move-result-object v11

    .line 232
    new-instance v0, Lc40/e;

    .line 233
    .line 234
    move-object v3, v6

    .line 235
    const/4 v6, 0x0

    .line 236
    invoke-direct/range {v0 .. v6}, Lc40/e;-><init>(Ll2/b1;Lz4/k;Lay0/a;Lay0/a;Lay0/a;I)V

    .line 237
    .line 238
    .line 239
    const v1, 0x478ef317

    .line 240
    .line 241
    .line 242
    invoke-static {v1, v8, v0}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 243
    .line 244
    .line 245
    move-result-object v0

    .line 246
    const/16 v1, 0x30

    .line 247
    .line 248
    invoke-static {v11, v0, v10, v8, v1}, Lt3/k1;->a(Lx2/s;Lt2/b;Lt3/q0;Ll2/o;I)V

    .line 249
    .line 250
    .line 251
    invoke-virtual {v8, v9}, Ll2/t;->q(Z)V

    .line 252
    .line 253
    .line 254
    goto :goto_3

    .line 255
    :cond_d
    invoke-virtual {v8}, Ll2/t;->R()V

    .line 256
    .line 257
    .line 258
    :goto_3
    invoke-virtual {v8}, Ll2/t;->s()Ll2/u1;

    .line 259
    .line 260
    .line 261
    move-result-object v0

    .line 262
    if-eqz v0, :cond_e

    .line 263
    .line 264
    new-instance v1, Lbf/b;

    .line 265
    .line 266
    const/4 v2, 0x1

    .line 267
    invoke-direct {v1, v4, v5, v7, v2}, Lbf/b;-><init>(Lay0/a;Lay0/a;II)V

    .line 268
    .line 269
    .line 270
    iput-object v1, v0, Ll2/u1;->d:Lay0/n;

    .line 271
    .line 272
    :cond_e
    return-void
.end method

.method public static final c(Low0/z;Ljava/lang/StringBuilder;)V
    .locals 8

    .line 1
    invoke-virtual {p0}, Low0/z;->d()Low0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    iget-object v0, v0, Low0/b0;->d:Ljava/lang/String;

    .line 6
    .line 7
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/CharSequence;)Ljava/lang/Appendable;

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0}, Low0/z;->d()Low0/b0;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    iget-object v0, v0, Low0/b0;->d:Ljava/lang/String;

    .line 15
    .line 16
    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

    .line 17
    .line 18
    .line 19
    move-result v1

    .line 20
    const/16 v2, 0x2f

    .line 21
    .line 22
    const-string v3, "://"

    .line 23
    .line 24
    const-string v4, ":"

    .line 25
    .line 26
    sparse-switch v1, :sswitch_data_0

    .line 27
    .line 28
    .line 29
    goto :goto_0

    .line 30
    :sswitch_0
    const-string v1, "about"

    .line 31
    .line 32
    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 33
    .line 34
    .line 35
    move-result v0

    .line 36
    if-nez v0, :cond_0

    .line 37
    .line 38
    goto :goto_0

    .line 39
    :cond_0
    iget-object p0, p0, Low0/z;->a:Ljava/lang/String;

    .line 40
    .line 41
    invoke-virtual {p1, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/CharSequence;)Ljava/lang/Appendable;

    .line 42
    .line 43
    .line 44
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/CharSequence;)Ljava/lang/Appendable;

    .line 45
    .line 46
    .line 47
    return-void

    .line 48
    :sswitch_1
    const-string v1, "file"

    .line 49
    .line 50
    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 51
    .line 52
    .line 53
    move-result v0

    .line 54
    if-nez v0, :cond_1

    .line 55
    .line 56
    goto :goto_0

    .line 57
    :cond_1
    iget-object v0, p0, Low0/z;->a:Ljava/lang/String;

    .line 58
    .line 59
    invoke-static {p0}, Ljp/rc;->e(Low0/z;)Ljava/lang/String;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    invoke-virtual {p1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/CharSequence;)Ljava/lang/Appendable;

    .line 64
    .line 65
    .line 66
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/CharSequence;)Ljava/lang/Appendable;

    .line 67
    .line 68
    .line 69
    invoke-static {p0, v2}, Lly0/p;->b0(Ljava/lang/String;C)Z

    .line 70
    .line 71
    .line 72
    move-result v0

    .line 73
    if-nez v0, :cond_2

    .line 74
    .line 75
    invoke-virtual {p1, v2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/Appendable;

    .line 76
    .line 77
    .line 78
    :cond_2
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/CharSequence;)Ljava/lang/Appendable;

    .line 79
    .line 80
    .line 81
    return-void

    .line 82
    :sswitch_2
    const-string v1, "data"

    .line 83
    .line 84
    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 85
    .line 86
    .line 87
    move-result v0

    .line 88
    if-nez v0, :cond_3

    .line 89
    .line 90
    goto :goto_0

    .line 91
    :cond_3
    iget-object p0, p0, Low0/z;->a:Ljava/lang/String;

    .line 92
    .line 93
    invoke-virtual {p1, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/CharSequence;)Ljava/lang/Appendable;

    .line 94
    .line 95
    .line 96
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/CharSequence;)Ljava/lang/Appendable;

    .line 97
    .line 98
    .line 99
    return-void

    .line 100
    :sswitch_3
    const-string v1, "tel"

    .line 101
    .line 102
    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 103
    .line 104
    .line 105
    move-result v0

    .line 106
    if-nez v0, :cond_4

    .line 107
    .line 108
    goto :goto_0

    .line 109
    :cond_4
    iget-object p0, p0, Low0/z;->a:Ljava/lang/String;

    .line 110
    .line 111
    invoke-virtual {p1, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/CharSequence;)Ljava/lang/Appendable;

    .line 112
    .line 113
    .line 114
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/CharSequence;)Ljava/lang/Appendable;

    .line 115
    .line 116
    .line 117
    return-void

    .line 118
    :sswitch_4
    const-string v1, "mailto"

    .line 119
    .line 120
    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 121
    .line 122
    .line 123
    move-result v0

    .line 124
    if-nez v0, :cond_c

    .line 125
    .line 126
    :goto_0
    invoke-virtual {p1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/CharSequence;)Ljava/lang/Appendable;

    .line 127
    .line 128
    .line 129
    invoke-static {p0}, Ljp/rc;->d(Low0/z;)Ljava/lang/String;

    .line 130
    .line 131
    .line 132
    move-result-object v0

    .line 133
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/CharSequence;)Ljava/lang/Appendable;

    .line 134
    .line 135
    .line 136
    invoke-static {p0}, Ljp/rc;->e(Low0/z;)Ljava/lang/String;

    .line 137
    .line 138
    .line 139
    move-result-object v0

    .line 140
    iget-object v1, p0, Low0/z;->i:Low0/n;

    .line 141
    .line 142
    iget-boolean v3, p0, Low0/z;->b:Z

    .line 143
    .line 144
    const-string v4, "encodedPath"

    .line 145
    .line 146
    invoke-static {v0, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 147
    .line 148
    .line 149
    const-string v4, "encodedQueryParameters"

    .line 150
    .line 151
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 152
    .line 153
    .line 154
    invoke-static {v0}, Lly0/p;->M(Ljava/lang/CharSequence;)Z

    .line 155
    .line 156
    .line 157
    move-result v4

    .line 158
    if-nez v4, :cond_5

    .line 159
    .line 160
    const-string v4, "/"

    .line 161
    .line 162
    const/4 v5, 0x0

    .line 163
    invoke-static {v0, v4, v5}, Lly0/w;->x(Ljava/lang/String;Ljava/lang/String;Z)Z

    .line 164
    .line 165
    .line 166
    move-result v4

    .line 167
    if-nez v4, :cond_5

    .line 168
    .line 169
    invoke-virtual {p1, v2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/Appendable;

    .line 170
    .line 171
    .line 172
    :cond_5
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/CharSequence;)Ljava/lang/Appendable;

    .line 173
    .line 174
    .line 175
    iget-object v0, v1, Lap0/o;->e:Ljava/lang/Object;

    .line 176
    .line 177
    check-cast v0, Ljava/util/Map;

    .line 178
    .line 179
    invoke-interface {v0}, Ljava/util/Map;->isEmpty()Z

    .line 180
    .line 181
    .line 182
    move-result v0

    .line 183
    if-eqz v0, :cond_6

    .line 184
    .line 185
    if-eqz v3, :cond_7

    .line 186
    .line 187
    :cond_6
    const-string v0, "?"

    .line 188
    .line 189
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/CharSequence;)Ljava/lang/Appendable;

    .line 190
    .line 191
    .line 192
    :cond_7
    invoke-virtual {v1}, Lap0/o;->a()Ljava/util/Set;

    .line 193
    .line 194
    .line 195
    move-result-object v0

    .line 196
    check-cast v0, Ljava/lang/Iterable;

    .line 197
    .line 198
    new-instance v1, Ljava/util/ArrayList;

    .line 199
    .line 200
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 201
    .line 202
    .line 203
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 204
    .line 205
    .line 206
    move-result-object v0

    .line 207
    :goto_1
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 208
    .line 209
    .line 210
    move-result v2

    .line 211
    if-eqz v2, :cond_a

    .line 212
    .line 213
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 214
    .line 215
    .line 216
    move-result-object v2

    .line 217
    check-cast v2, Ljava/util/Map$Entry;

    .line 218
    .line 219
    invoke-interface {v2}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 220
    .line 221
    .line 222
    move-result-object v3

    .line 223
    check-cast v3, Ljava/lang/String;

    .line 224
    .line 225
    invoke-interface {v2}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 226
    .line 227
    .line 228
    move-result-object v2

    .line 229
    check-cast v2, Ljava/util/List;

    .line 230
    .line 231
    invoke-interface {v2}, Ljava/util/List;->isEmpty()Z

    .line 232
    .line 233
    .line 234
    move-result v4

    .line 235
    if-eqz v4, :cond_8

    .line 236
    .line 237
    new-instance v2, Llx0/l;

    .line 238
    .line 239
    const/4 v4, 0x0

    .line 240
    invoke-direct {v2, v3, v4}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 241
    .line 242
    .line 243
    invoke-static {v2}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 244
    .line 245
    .line 246
    move-result-object v2

    .line 247
    goto :goto_3

    .line 248
    :cond_8
    check-cast v2, Ljava/lang/Iterable;

    .line 249
    .line 250
    new-instance v4, Ljava/util/ArrayList;

    .line 251
    .line 252
    const/16 v5, 0xa

    .line 253
    .line 254
    invoke-static {v2, v5}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 255
    .line 256
    .line 257
    move-result v5

    .line 258
    invoke-direct {v4, v5}, Ljava/util/ArrayList;-><init>(I)V

    .line 259
    .line 260
    .line 261
    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 262
    .line 263
    .line 264
    move-result-object v2

    .line 265
    :goto_2
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 266
    .line 267
    .line 268
    move-result v5

    .line 269
    if-eqz v5, :cond_9

    .line 270
    .line 271
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 272
    .line 273
    .line 274
    move-result-object v5

    .line 275
    check-cast v5, Ljava/lang/String;

    .line 276
    .line 277
    new-instance v6, Llx0/l;

    .line 278
    .line 279
    invoke-direct {v6, v3, v5}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 280
    .line 281
    .line 282
    invoke-virtual {v4, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 283
    .line 284
    .line 285
    goto :goto_2

    .line 286
    :cond_9
    move-object v2, v4

    .line 287
    :goto_3
    check-cast v2, Ljava/lang/Iterable;

    .line 288
    .line 289
    invoke-static {v2, v1}, Lmx0/q;->w(Ljava/lang/Iterable;Ljava/util/Collection;)V

    .line 290
    .line 291
    .line 292
    goto :goto_1

    .line 293
    :cond_a
    new-instance v6, Lod0/g;

    .line 294
    .line 295
    const/16 v0, 0x11

    .line 296
    .line 297
    invoke-direct {v6, v0}, Lod0/g;-><init>(I)V

    .line 298
    .line 299
    .line 300
    const/16 v7, 0x3c

    .line 301
    .line 302
    const-string v3, "&"

    .line 303
    .line 304
    const/4 v4, 0x0

    .line 305
    const/4 v5, 0x0

    .line 306
    move-object v2, p1

    .line 307
    invoke-static/range {v1 .. v7}, Lmx0/q;->Q(Ljava/lang/Iterable;Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lay0/k;I)V

    .line 308
    .line 309
    .line 310
    iget-object p1, p0, Low0/z;->g:Ljava/lang/String;

    .line 311
    .line 312
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 313
    .line 314
    .line 315
    move-result p1

    .line 316
    if-lez p1, :cond_b

    .line 317
    .line 318
    const/16 p1, 0x23

    .line 319
    .line 320
    invoke-virtual {v2, p1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/Appendable;

    .line 321
    .line 322
    .line 323
    iget-object p0, p0, Low0/z;->g:Ljava/lang/String;

    .line 324
    .line 325
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/CharSequence;)Ljava/lang/Appendable;

    .line 326
    .line 327
    .line 328
    :cond_b
    return-void

    .line 329
    :cond_c
    move-object v2, p1

    .line 330
    new-instance p1, Ljava/lang/StringBuilder;

    .line 331
    .line 332
    invoke-direct {p1}, Ljava/lang/StringBuilder;-><init>()V

    .line 333
    .line 334
    .line 335
    iget-object v0, p0, Low0/z;->e:Ljava/lang/String;

    .line 336
    .line 337
    iget-object v1, p0, Low0/z;->f:Ljava/lang/String;

    .line 338
    .line 339
    if-nez v0, :cond_d

    .line 340
    .line 341
    goto :goto_4

    .line 342
    :cond_d
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 343
    .line 344
    .line 345
    if-eqz v1, :cond_e

    .line 346
    .line 347
    const/16 v0, 0x3a

    .line 348
    .line 349
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 350
    .line 351
    .line 352
    invoke-virtual {p1, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 353
    .line 354
    .line 355
    :cond_e
    const-string v0, "@"

    .line 356
    .line 357
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 358
    .line 359
    .line 360
    :goto_4
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 361
    .line 362
    .line 363
    move-result-object p1

    .line 364
    iget-object p0, p0, Low0/z;->a:Ljava/lang/String;

    .line 365
    .line 366
    invoke-virtual {v2, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/CharSequence;)Ljava/lang/Appendable;

    .line 367
    .line 368
    .line 369
    invoke-virtual {v2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/CharSequence;)Ljava/lang/Appendable;

    .line 370
    .line 371
    .line 372
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/CharSequence;)Ljava/lang/Appendable;

    .line 373
    .line 374
    .line 375
    return-void

    .line 376
    nop

    .line 377
    :sswitch_data_0
    .sparse-switch
        -0x40777d8e -> :sswitch_4
        0x1c01b -> :sswitch_3
        0x2eefaa -> :sswitch_2
        0x2ff57c -> :sswitch_1
        0x585238d -> :sswitch_0
    .end sparse-switch
.end method

.method public static final d(Low0/z;)Ljava/lang/String;
    .locals 4

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Ljava/lang/StringBuilder;

    .line 7
    .line 8
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 9
    .line 10
    .line 11
    new-instance v1, Ljava/lang/StringBuilder;

    .line 12
    .line 13
    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    .line 14
    .line 15
    .line 16
    iget-object v2, p0, Low0/z;->e:Ljava/lang/String;

    .line 17
    .line 18
    iget-object v3, p0, Low0/z;->f:Ljava/lang/String;

    .line 19
    .line 20
    if-nez v2, :cond_0

    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_0
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 24
    .line 25
    .line 26
    if-eqz v3, :cond_1

    .line 27
    .line 28
    const/16 v2, 0x3a

    .line 29
    .line 30
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 34
    .line 35
    .line 36
    :cond_1
    const-string v2, "@"

    .line 37
    .line 38
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 39
    .line 40
    .line 41
    :goto_0
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 42
    .line 43
    .line 44
    move-result-object v1

    .line 45
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    iget-object v1, p0, Low0/z;->a:Ljava/lang/String;

    .line 49
    .line 50
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    iget v1, p0, Low0/z;->c:I

    .line 54
    .line 55
    if-eqz v1, :cond_2

    .line 56
    .line 57
    invoke-virtual {p0}, Low0/z;->d()Low0/b0;

    .line 58
    .line 59
    .line 60
    move-result-object v2

    .line 61
    iget v2, v2, Low0/b0;->e:I

    .line 62
    .line 63
    if-eq v1, v2, :cond_2

    .line 64
    .line 65
    const-string v1, ":"

    .line 66
    .line 67
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 68
    .line 69
    .line 70
    iget p0, p0, Low0/z;->c:I

    .line 71
    .line 72
    invoke-static {p0}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 73
    .line 74
    .line 75
    move-result-object p0

    .line 76
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 77
    .line 78
    .line 79
    :cond_2
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 80
    .line 81
    .line 82
    move-result-object p0

    .line 83
    return-object p0
.end method

.method public static final e(Low0/z;)Ljava/lang/String;
    .locals 6

    .line 1
    iget-object p0, p0, Low0/z;->h:Ljava/util/List;

    .line 2
    .line 3
    invoke-interface {p0}, Ljava/util/List;->isEmpty()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    const-string p0, ""

    .line 10
    .line 11
    return-object p0

    .line 12
    :cond_0
    invoke-interface {p0}, Ljava/util/List;->size()I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    const/4 v1, 0x1

    .line 17
    if-ne v0, v1, :cond_2

    .line 18
    .line 19
    invoke-static {p0}, Lmx0/q;->J(Ljava/util/List;)Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    check-cast v0, Ljava/lang/CharSequence;

    .line 24
    .line 25
    invoke-interface {v0}, Ljava/lang/CharSequence;->length()I

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    if-nez v0, :cond_1

    .line 30
    .line 31
    const-string p0, "/"

    .line 32
    .line 33
    return-object p0

    .line 34
    :cond_1
    invoke-static {p0}, Lmx0/q;->J(Ljava/util/List;)Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    check-cast p0, Ljava/lang/String;

    .line 39
    .line 40
    return-object p0

    .line 41
    :cond_2
    move-object v0, p0

    .line 42
    check-cast v0, Ljava/lang/Iterable;

    .line 43
    .line 44
    const/4 v4, 0x0

    .line 45
    const/16 v5, 0x3e

    .line 46
    .line 47
    const-string v1, "/"

    .line 48
    .line 49
    const/4 v2, 0x0

    .line 50
    const/4 v3, 0x0

    .line 51
    invoke-static/range {v0 .. v5}, Lmx0/q;->R(Ljava/lang/Iterable;Ljava/lang/CharSequence;Ljava/lang/String;Ljava/lang/String;Lay0/k;I)Ljava/lang/String;

    .line 52
    .line 53
    .line 54
    move-result-object p0

    .line 55
    return-object p0
.end method

.method public static final f(Low0/z;Ljava/lang/String;)V
    .locals 3

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "value"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-static {p1}, Lly0/p;->M(Ljava/lang/CharSequence;)Z

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    if-eqz v0, :cond_0

    .line 16
    .line 17
    sget-object p1, Lmx0/s;->d:Lmx0/s;

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    const-string v0, "/"

    .line 21
    .line 22
    invoke-virtual {p1, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    if-eqz v0, :cond_1

    .line 27
    .line 28
    sget-object p1, Low0/a0;->a:Ljava/util/List;

    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_1
    const/4 v0, 0x1

    .line 32
    new-array v0, v0, [C

    .line 33
    .line 34
    const/16 v1, 0x2f

    .line 35
    .line 36
    const/4 v2, 0x0

    .line 37
    aput-char v1, v0, v2

    .line 38
    .line 39
    invoke-static {p1, v0}, Lly0/p;->X(Ljava/lang/CharSequence;[C)Ljava/util/List;

    .line 40
    .line 41
    .line 42
    move-result-object p1

    .line 43
    check-cast p1, Ljava/util/Collection;

    .line 44
    .line 45
    invoke-static {p1}, Lmx0/q;->z0(Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 46
    .line 47
    .line 48
    move-result-object p1

    .line 49
    :goto_0
    const-string v0, "<set-?>"

    .line 50
    .line 51
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    iput-object p1, p0, Low0/z;->h:Ljava/util/List;

    .line 55
    .line 56
    return-void
.end method
