.class public abstract Lkp/aa;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lay0/k;Lth/g;Lay0/k;Ll2/o;I)V
    .locals 12

    .line 1
    move-object v0, p3

    .line 2
    check-cast v0, Ll2/t;

    .line 3
    .line 4
    const v1, -0x700d04bf

    .line 5
    .line 6
    .line 7
    invoke-virtual {v0, v1}, Ll2/t;->a0(I)Ll2/t;

    .line 8
    .line 9
    .line 10
    invoke-virtual {v0, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 11
    .line 12
    .line 13
    move-result v1

    .line 14
    if-eqz v1, :cond_0

    .line 15
    .line 16
    const/4 v1, 0x4

    .line 17
    goto :goto_0

    .line 18
    :cond_0
    const/4 v1, 0x2

    .line 19
    :goto_0
    or-int v1, p4, v1

    .line 20
    .line 21
    invoke-virtual {v0, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    move-result v2

    .line 25
    if-eqz v2, :cond_1

    .line 26
    .line 27
    const/16 v2, 0x20

    .line 28
    .line 29
    goto :goto_1

    .line 30
    :cond_1
    const/16 v2, 0x10

    .line 31
    .line 32
    :goto_1
    or-int/2addr v1, v2

    .line 33
    invoke-virtual {v0, p2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 34
    .line 35
    .line 36
    move-result v2

    .line 37
    const/16 v6, 0x100

    .line 38
    .line 39
    if-eqz v2, :cond_2

    .line 40
    .line 41
    move v2, v6

    .line 42
    goto :goto_2

    .line 43
    :cond_2
    const/16 v2, 0x80

    .line 44
    .line 45
    :goto_2
    or-int/2addr v1, v2

    .line 46
    and-int/lit16 v2, v1, 0x93

    .line 47
    .line 48
    const/16 v7, 0x92

    .line 49
    .line 50
    const/4 v8, 0x0

    .line 51
    const/4 v9, 0x1

    .line 52
    if-eq v2, v7, :cond_3

    .line 53
    .line 54
    move v2, v9

    .line 55
    goto :goto_3

    .line 56
    :cond_3
    move v2, v8

    .line 57
    :goto_3
    and-int/lit8 v7, v1, 0x1

    .line 58
    .line 59
    invoke-virtual {v0, v7, v2}, Ll2/t;->O(IZ)Z

    .line 60
    .line 61
    .line 62
    move-result v2

    .line 63
    if-eqz v2, :cond_7

    .line 64
    .line 65
    move v2, v8

    .line 66
    invoke-static {p0, v0}, Ll2/b;->s(Ljava/lang/Object;Ll2/o;)Ll2/b1;

    .line 67
    .line 68
    .line 69
    move-result-object v8

    .line 70
    iget-object v10, p1, Lth/g;->c:Lth/a;

    .line 71
    .line 72
    invoke-virtual {v0, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 73
    .line 74
    .line 75
    move-result v7

    .line 76
    invoke-virtual {v0, v8}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 77
    .line 78
    .line 79
    move-result v11

    .line 80
    or-int/2addr v7, v11

    .line 81
    and-int/lit16 v1, v1, 0x380

    .line 82
    .line 83
    if-ne v1, v6, :cond_4

    .line 84
    .line 85
    move v2, v9

    .line 86
    :cond_4
    or-int v1, v7, v2

    .line 87
    .line 88
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 89
    .line 90
    .line 91
    move-result-object v2

    .line 92
    if-nez v1, :cond_5

    .line 93
    .line 94
    sget-object v1, Ll2/n;->a:Ll2/x0;

    .line 95
    .line 96
    if-ne v2, v1, :cond_6

    .line 97
    .line 98
    :cond_5
    new-instance v4, Lqh/a;

    .line 99
    .line 100
    const/4 v9, 0x0

    .line 101
    const/4 v5, 0x7

    .line 102
    move-object v6, p1

    .line 103
    move-object v7, p2

    .line 104
    invoke-direct/range {v4 .. v9}, Lqh/a;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 105
    .line 106
    .line 107
    invoke-virtual {v0, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 108
    .line 109
    .line 110
    move-object v2, v4

    .line 111
    :cond_6
    check-cast v2, Lay0/n;

    .line 112
    .line 113
    invoke-static {v2, v10, v0}, Ll2/l0;->d(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 114
    .line 115
    .line 116
    goto :goto_4

    .line 117
    :cond_7
    invoke-virtual {v0}, Ll2/t;->R()V

    .line 118
    .line 119
    .line 120
    :goto_4
    invoke-virtual {v0}, Ll2/t;->s()Ll2/u1;

    .line 121
    .line 122
    .line 123
    move-result-object v6

    .line 124
    if-eqz v6, :cond_8

    .line 125
    .line 126
    new-instance v0, Lqv0/f;

    .line 127
    .line 128
    const/16 v2, 0xd

    .line 129
    .line 130
    move-object v3, p0

    .line 131
    move-object v4, p1

    .line 132
    move-object v5, p2

    .line 133
    move/from16 v1, p4

    .line 134
    .line 135
    invoke-direct/range {v0 .. v5}, Lqv0/f;-><init>(IILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 136
    .line 137
    .line 138
    iput-object v0, v6, Ll2/u1;->d:Lay0/n;

    .line 139
    .line 140
    :cond_8
    return-void
.end method

.method public static final b(Lay0/k;Ll2/o;I)V
    .locals 19

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move/from16 v1, p2

    .line 4
    .line 5
    const-string v2, "onWallboxSelected"

    .line 6
    .line 7
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    move-object/from16 v8, p1

    .line 11
    .line 12
    check-cast v8, Ll2/t;

    .line 13
    .line 14
    const v2, 0x1ae9acb6

    .line 15
    .line 16
    .line 17
    invoke-virtual {v8, v2}, Ll2/t;->a0(I)Ll2/t;

    .line 18
    .line 19
    .line 20
    invoke-virtual {v8, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 21
    .line 22
    .line 23
    move-result v2

    .line 24
    const/4 v3, 0x2

    .line 25
    if-eqz v2, :cond_0

    .line 26
    .line 27
    const/4 v2, 0x4

    .line 28
    goto :goto_0

    .line 29
    :cond_0
    move v2, v3

    .line 30
    :goto_0
    or-int/2addr v2, v1

    .line 31
    and-int/lit8 v4, v2, 0x3

    .line 32
    .line 33
    const/4 v9, 0x0

    .line 34
    if-eq v4, v3, :cond_1

    .line 35
    .line 36
    const/4 v3, 0x1

    .line 37
    goto :goto_1

    .line 38
    :cond_1
    move v3, v9

    .line 39
    :goto_1
    and-int/lit8 v4, v2, 0x1

    .line 40
    .line 41
    invoke-virtual {v8, v4, v3}, Ll2/t;->O(IZ)Z

    .line 42
    .line 43
    .line 44
    move-result v3

    .line 45
    if-eqz v3, :cond_a

    .line 46
    .line 47
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object v3

    .line 51
    sget-object v10, Ll2/n;->a:Ll2/x0;

    .line 52
    .line 53
    if-ne v3, v10, :cond_2

    .line 54
    .line 55
    new-instance v3, Lt40/a;

    .line 56
    .line 57
    const/16 v4, 0xe

    .line 58
    .line 59
    invoke-direct {v3, v4}, Lt40/a;-><init>(I)V

    .line 60
    .line 61
    .line 62
    invoke-virtual {v8, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 63
    .line 64
    .line 65
    :cond_2
    check-cast v3, Lay0/k;

    .line 66
    .line 67
    sget-object v4, Lw3/q1;->a:Ll2/u2;

    .line 68
    .line 69
    invoke-virtual {v8, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    move-result-object v4

    .line 73
    check-cast v4, Ljava/lang/Boolean;

    .line 74
    .line 75
    invoke-virtual {v4}, Ljava/lang/Boolean;->booleanValue()Z

    .line 76
    .line 77
    .line 78
    move-result v4

    .line 79
    if-eqz v4, :cond_3

    .line 80
    .line 81
    const v4, -0x105bcaaa

    .line 82
    .line 83
    .line 84
    invoke-virtual {v8, v4}, Ll2/t;->Y(I)V

    .line 85
    .line 86
    .line 87
    invoke-virtual {v8, v9}, Ll2/t;->q(Z)V

    .line 88
    .line 89
    .line 90
    const/4 v4, 0x0

    .line 91
    goto :goto_2

    .line 92
    :cond_3
    const v4, 0x31054eee

    .line 93
    .line 94
    .line 95
    invoke-virtual {v8, v4}, Ll2/t;->Y(I)V

    .line 96
    .line 97
    .line 98
    sget-object v4, Lzb/x;->a:Ll2/u2;

    .line 99
    .line 100
    invoke-virtual {v8, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 101
    .line 102
    .line 103
    move-result-object v4

    .line 104
    check-cast v4, Lhi/a;

    .line 105
    .line 106
    invoke-virtual {v8, v9}, Ll2/t;->q(Z)V

    .line 107
    .line 108
    .line 109
    :goto_2
    new-instance v6, Lnd/e;

    .line 110
    .line 111
    const/16 v5, 0x19

    .line 112
    .line 113
    invoke-direct {v6, v4, v3, v5}, Lnd/e;-><init>(Lhi/a;Lay0/k;I)V

    .line 114
    .line 115
    .line 116
    invoke-static {v8}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 117
    .line 118
    .line 119
    move-result-object v4

    .line 120
    if-eqz v4, :cond_9

    .line 121
    .line 122
    instance-of v3, v4, Landroidx/lifecycle/k;

    .line 123
    .line 124
    if-eqz v3, :cond_4

    .line 125
    .line 126
    move-object v3, v4

    .line 127
    check-cast v3, Landroidx/lifecycle/k;

    .line 128
    .line 129
    invoke-interface {v3}, Landroidx/lifecycle/k;->getDefaultViewModelCreationExtras()Lp7/c;

    .line 130
    .line 131
    .line 132
    move-result-object v3

    .line 133
    :goto_3
    move-object v7, v3

    .line 134
    goto :goto_4

    .line 135
    :cond_4
    sget-object v3, Lp7/a;->b:Lp7/a;

    .line 136
    .line 137
    goto :goto_3

    .line 138
    :goto_4
    const-class v3, Lth/i;

    .line 139
    .line 140
    sget-object v5, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 141
    .line 142
    invoke-virtual {v5, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 143
    .line 144
    .line 145
    move-result-object v3

    .line 146
    const/4 v5, 0x0

    .line 147
    invoke-static/range {v3 .. v8}, Ljp/se;->b(Lhy0/d;Landroidx/lifecycle/i1;Ljava/lang/String;Landroidx/lifecycle/e1;Lp7/c;Ll2/o;)Landroidx/lifecycle/b1;

    .line 148
    .line 149
    .line 150
    move-result-object v3

    .line 151
    move-object v13, v3

    .line 152
    check-cast v13, Lth/i;

    .line 153
    .line 154
    iget-object v3, v13, Lth/i;->h:Lyy0/l1;

    .line 155
    .line 156
    invoke-static {v3, v8}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 157
    .line 158
    .line 159
    move-result-object v3

    .line 160
    invoke-interface {v3}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 161
    .line 162
    .line 163
    move-result-object v4

    .line 164
    check-cast v4, Lth/g;

    .line 165
    .line 166
    invoke-virtual {v8, v13}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 167
    .line 168
    .line 169
    move-result v5

    .line 170
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 171
    .line 172
    .line 173
    move-result-object v6

    .line 174
    if-nez v5, :cond_5

    .line 175
    .line 176
    if-ne v6, v10, :cond_6

    .line 177
    .line 178
    :cond_5
    new-instance v11, Lt10/k;

    .line 179
    .line 180
    const/16 v17, 0x0

    .line 181
    .line 182
    const/16 v18, 0xb

    .line 183
    .line 184
    const/4 v12, 0x1

    .line 185
    const-class v14, Lth/i;

    .line 186
    .line 187
    const-string v15, "onUiEvent"

    .line 188
    .line 189
    const-string v16, "onUiEvent(Lcariad/charging/multicharge/kitten/wallboxes/presentation/onboarding/selection/WallboxSelectionUiEvent;)V"

    .line 190
    .line 191
    invoke-direct/range {v11 .. v18}, Lt10/k;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 192
    .line 193
    .line 194
    invoke-virtual {v8, v11}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 195
    .line 196
    .line 197
    move-object v6, v11

    .line 198
    :cond_6
    check-cast v6, Lhy0/g;

    .line 199
    .line 200
    check-cast v6, Lay0/k;

    .line 201
    .line 202
    and-int/lit8 v2, v2, 0xe

    .line 203
    .line 204
    invoke-static {v0, v4, v6, v8, v2}, Lkp/aa;->a(Lay0/k;Lth/g;Lay0/k;Ll2/o;I)V

    .line 205
    .line 206
    .line 207
    invoke-static {v8}, Leh/a;->b(Ll2/o;)Leh/n;

    .line 208
    .line 209
    .line 210
    move-result-object v2

    .line 211
    invoke-interface {v3}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 212
    .line 213
    .line 214
    move-result-object v3

    .line 215
    check-cast v3, Lth/g;

    .line 216
    .line 217
    invoke-virtual {v8, v13}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 218
    .line 219
    .line 220
    move-result v4

    .line 221
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 222
    .line 223
    .line 224
    move-result-object v5

    .line 225
    if-nez v4, :cond_7

    .line 226
    .line 227
    if-ne v5, v10, :cond_8

    .line 228
    .line 229
    :cond_7
    new-instance v11, Lt10/k;

    .line 230
    .line 231
    const/16 v17, 0x0

    .line 232
    .line 233
    const/16 v18, 0xc

    .line 234
    .line 235
    const/4 v12, 0x1

    .line 236
    const-class v14, Lth/i;

    .line 237
    .line 238
    const-string v15, "onUiEvent"

    .line 239
    .line 240
    const-string v16, "onUiEvent(Lcariad/charging/multicharge/kitten/wallboxes/presentation/onboarding/selection/WallboxSelectionUiEvent;)V"

    .line 241
    .line 242
    invoke-direct/range {v11 .. v18}, Lt10/k;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 243
    .line 244
    .line 245
    invoke-virtual {v8, v11}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 246
    .line 247
    .line 248
    move-object v5, v11

    .line 249
    :cond_8
    check-cast v5, Lhy0/g;

    .line 250
    .line 251
    check-cast v5, Lay0/k;

    .line 252
    .line 253
    invoke-interface {v2, v3, v5, v8, v9}, Leh/n;->l0(Lth/g;Lay0/k;Ll2/o;I)V

    .line 254
    .line 255
    .line 256
    goto :goto_5

    .line 257
    :cond_9
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 258
    .line 259
    const-string v1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 260
    .line 261
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 262
    .line 263
    .line 264
    throw v0

    .line 265
    :cond_a
    invoke-virtual {v8}, Ll2/t;->R()V

    .line 266
    .line 267
    .line 268
    :goto_5
    invoke-virtual {v8}, Ll2/t;->s()Ll2/u1;

    .line 269
    .line 270
    .line 271
    move-result-object v2

    .line 272
    if-eqz v2, :cond_b

    .line 273
    .line 274
    new-instance v3, Lal/c;

    .line 275
    .line 276
    const/16 v4, 0x12

    .line 277
    .line 278
    invoke-direct {v3, v1, v4, v0}, Lal/c;-><init>(IILay0/k;)V

    .line 279
    .line 280
    .line 281
    iput-object v3, v2, Ll2/u1;->d:Lay0/n;

    .line 282
    .line 283
    :cond_b
    return-void
.end method

.method public static c(Lh0/g2;Lh0/e2;Lh0/c2;)Lh0/h2;
    .locals 1

    .line 1
    const-string v0, "size"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "streamUseCase"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    new-instance v0, Lh0/h2;

    .line 12
    .line 13
    invoke-direct {v0, p0, p1, p2}, Lh0/h2;-><init>(Lh0/g2;Lh0/e2;Lh0/c2;)V

    .line 14
    .line 15
    .line 16
    return-object v0
.end method

.method public static d(ILandroid/util/Size;Lh0/l;ILh0/f2;Lh0/c2;)Lh0/h2;
    .locals 5

    .line 1
    const-string v0, "size"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "surfaceSizeDefinition"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    iget-object v0, p2, Lh0/l;->f:Ljava/util/HashMap;

    .line 12
    .line 13
    const-string v1, "configSource"

    .line 14
    .line 15
    invoke-static {p4, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    const-string v1, "streamUseCase"

    .line 19
    .line 20
    invoke-static {p5, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    sget-object v1, Lh0/h2;->h:Ljava/util/LinkedHashMap;

    .line 24
    .line 25
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 26
    .line 27
    .line 28
    move-result-object v2

    .line 29
    invoke-virtual {v1, v2}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object v1

    .line 33
    check-cast v1, Lh0/g2;

    .line 34
    .line 35
    if-nez v1, :cond_0

    .line 36
    .line 37
    sget-object v1, Lh0/g2;->d:Lh0/g2;

    .line 38
    .line 39
    :cond_0
    sget-object v2, Lh0/e2;->t:Lh0/e2;

    .line 40
    .line 41
    sget-object v3, Lo0/a;->a:Landroid/util/Size;

    .line 42
    .line 43
    invoke-virtual {p1}, Landroid/util/Size;->getWidth()I

    .line 44
    .line 45
    .line 46
    move-result v3

    .line 47
    invoke-virtual {p1}, Landroid/util/Size;->getHeight()I

    .line 48
    .line 49
    .line 50
    move-result v4

    .line 51
    mul-int/2addr v4, v3

    .line 52
    const/4 v3, 0x1

    .line 53
    if-ne p3, v3, :cond_2

    .line 54
    .line 55
    iget-object p1, p2, Lh0/l;->b:Ljava/util/HashMap;

    .line 56
    .line 57
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 58
    .line 59
    .line 60
    move-result-object p3

    .line 61
    invoke-virtual {p1, p3}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    move-result-object p1

    .line 65
    check-cast p1, Landroid/util/Size;

    .line 66
    .line 67
    invoke-static {p1}, Lo0/a;->a(Landroid/util/Size;)I

    .line 68
    .line 69
    .line 70
    move-result p1

    .line 71
    if-gt v4, p1, :cond_1

    .line 72
    .line 73
    sget-object v2, Lh0/e2;->h:Lh0/e2;

    .line 74
    .line 75
    goto/16 :goto_2

    .line 76
    .line 77
    :cond_1
    iget-object p1, p2, Lh0/l;->d:Ljava/util/HashMap;

    .line 78
    .line 79
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 80
    .line 81
    .line 82
    move-result-object p0

    .line 83
    invoke-virtual {p1, p0}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 84
    .line 85
    .line 86
    move-result-object p0

    .line 87
    check-cast p0, Landroid/util/Size;

    .line 88
    .line 89
    invoke-static {p0}, Lo0/a;->a(Landroid/util/Size;)I

    .line 90
    .line 91
    .line 92
    move-result p0

    .line 93
    if-gt v4, p0, :cond_b

    .line 94
    .line 95
    sget-object v2, Lh0/e2;->l:Lh0/e2;

    .line 96
    .line 97
    goto/16 :goto_2

    .line 98
    .line 99
    :cond_2
    sget-object v3, Lh0/f2;->d:Lh0/f2;

    .line 100
    .line 101
    if-ne p4, v3, :cond_5

    .line 102
    .line 103
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 104
    .line 105
    .line 106
    move-result-object p0

    .line 107
    invoke-virtual {v0, p0}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 108
    .line 109
    .line 110
    move-result-object p0

    .line 111
    check-cast p0, Landroid/util/Size;

    .line 112
    .line 113
    sget-object p2, Lh0/h2;->f:[Lh0/e2;

    .line 114
    .line 115
    array-length p3, p2

    .line 116
    const/4 p4, 0x0

    .line 117
    :goto_0
    if-ge p4, p3, :cond_4

    .line 118
    .line 119
    aget-object v0, p2, p4

    .line 120
    .line 121
    iget-object v3, v0, Lh0/e2;->e:Landroid/util/Size;

    .line 122
    .line 123
    invoke-virtual {p1, v3}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 124
    .line 125
    .line 126
    move-result v3

    .line 127
    if-eqz v3, :cond_3

    .line 128
    .line 129
    move-object v2, v0

    .line 130
    goto :goto_1

    .line 131
    :cond_3
    add-int/lit8 p4, p4, 0x1

    .line 132
    .line 133
    goto :goto_0

    .line 134
    :cond_4
    :goto_1
    sget-object p2, Lh0/e2;->t:Lh0/e2;

    .line 135
    .line 136
    if-ne v2, p2, :cond_b

    .line 137
    .line 138
    invoke-virtual {p1, p0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 139
    .line 140
    .line 141
    move-result p0

    .line 142
    if-eqz p0, :cond_b

    .line 143
    .line 144
    sget-object v2, Lh0/e2;->p:Lh0/e2;

    .line 145
    .line 146
    goto :goto_2

    .line 147
    :cond_5
    iget-object p1, p2, Lh0/l;->a:Landroid/util/Size;

    .line 148
    .line 149
    invoke-static {p1}, Lo0/a;->a(Landroid/util/Size;)I

    .line 150
    .line 151
    .line 152
    move-result p1

    .line 153
    if-gt v4, p1, :cond_6

    .line 154
    .line 155
    sget-object v2, Lh0/e2;->f:Lh0/e2;

    .line 156
    .line 157
    goto :goto_2

    .line 158
    :cond_6
    iget-object p1, p2, Lh0/l;->c:Landroid/util/Size;

    .line 159
    .line 160
    invoke-static {p1}, Lo0/a;->a(Landroid/util/Size;)I

    .line 161
    .line 162
    .line 163
    move-result p1

    .line 164
    if-gt v4, p1, :cond_7

    .line 165
    .line 166
    sget-object v2, Lh0/e2;->i:Lh0/e2;

    .line 167
    .line 168
    goto :goto_2

    .line 169
    :cond_7
    iget-object p1, p2, Lh0/l;->e:Landroid/util/Size;

    .line 170
    .line 171
    invoke-static {p1}, Lo0/a;->a(Landroid/util/Size;)I

    .line 172
    .line 173
    .line 174
    move-result p1

    .line 175
    if-gt v4, p1, :cond_8

    .line 176
    .line 177
    sget-object v2, Lh0/e2;->o:Lh0/e2;

    .line 178
    .line 179
    goto :goto_2

    .line 180
    :cond_8
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 181
    .line 182
    .line 183
    move-result-object p1

    .line 184
    invoke-virtual {v0, p1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 185
    .line 186
    .line 187
    move-result-object p1

    .line 188
    check-cast p1, Landroid/util/Size;

    .line 189
    .line 190
    iget-object p2, p2, Lh0/l;->i:Ljava/util/HashMap;

    .line 191
    .line 192
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 193
    .line 194
    .line 195
    move-result-object p0

    .line 196
    invoke-virtual {p2, p0}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 197
    .line 198
    .line 199
    move-result-object p0

    .line 200
    check-cast p0, Landroid/util/Size;

    .line 201
    .line 202
    if-eqz p1, :cond_9

    .line 203
    .line 204
    invoke-virtual {p1}, Landroid/util/Size;->getWidth()I

    .line 205
    .line 206
    .line 207
    move-result p2

    .line 208
    invoke-virtual {p1}, Landroid/util/Size;->getHeight()I

    .line 209
    .line 210
    .line 211
    move-result p1

    .line 212
    mul-int/2addr p1, p2

    .line 213
    if-gt v4, p1, :cond_a

    .line 214
    .line 215
    :cond_9
    const/4 p1, 0x2

    .line 216
    if-eq p3, p1, :cond_a

    .line 217
    .line 218
    sget-object v2, Lh0/e2;->p:Lh0/e2;

    .line 219
    .line 220
    goto :goto_2

    .line 221
    :cond_a
    if-eqz p0, :cond_b

    .line 222
    .line 223
    invoke-virtual {p0}, Landroid/util/Size;->getWidth()I

    .line 224
    .line 225
    .line 226
    move-result p1

    .line 227
    invoke-virtual {p0}, Landroid/util/Size;->getHeight()I

    .line 228
    .line 229
    .line 230
    move-result p0

    .line 231
    mul-int/2addr p0, p1

    .line 232
    if-gt v4, p0, :cond_b

    .line 233
    .line 234
    sget-object v2, Lh0/e2;->s:Lh0/e2;

    .line 235
    .line 236
    :cond_b
    :goto_2
    invoke-static {v1, v2, p5}, Lkp/aa;->c(Lh0/g2;Lh0/e2;Lh0/c2;)Lh0/h2;

    .line 237
    .line 238
    .line 239
    move-result-object p0

    .line 240
    return-object p0
.end method
