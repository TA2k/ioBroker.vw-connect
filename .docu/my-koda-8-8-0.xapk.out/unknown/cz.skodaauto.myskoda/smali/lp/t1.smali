.class public abstract Llp/t1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static a(Le3/f;I)Li3/a;
    .locals 6

    .line 1
    iget-object v0, p0, Le3/f;->a:Landroid/graphics/Bitmap;

    .line 2
    .line 3
    invoke-virtual {v0}, Landroid/graphics/Bitmap;->getWidth()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    iget-object v1, p0, Le3/f;->a:Landroid/graphics/Bitmap;

    .line 8
    .line 9
    invoke-virtual {v1}, Landroid/graphics/Bitmap;->getHeight()I

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    int-to-long v2, v0

    .line 14
    const/16 v0, 0x20

    .line 15
    .line 16
    shl-long/2addr v2, v0

    .line 17
    int-to-long v0, v1

    .line 18
    const-wide v4, 0xffffffffL

    .line 19
    .line 20
    .line 21
    .line 22
    .line 23
    and-long/2addr v0, v4

    .line 24
    or-long/2addr v0, v2

    .line 25
    new-instance v2, Li3/a;

    .line 26
    .line 27
    invoke-direct {v2, p0, v0, v1}, Li3/a;-><init>(Le3/f;J)V

    .line 28
    .line 29
    .line 30
    iput p1, v2, Li3/a;->k:I

    .line 31
    .line 32
    return-object v2
.end method

.method public static final b(Lay0/a;Lay0/a;Luh/e;Lay0/k;Ll2/o;I)V
    .locals 16

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
    move/from16 v0, p5

    .line 8
    .line 9
    move-object/from16 v10, p4

    .line 10
    .line 11
    check-cast v10, Ll2/t;

    .line 12
    .line 13
    const v4, -0x15d1aa21

    .line 14
    .line 15
    .line 16
    invoke-virtual {v10, v4}, Ll2/t;->a0(I)Ll2/t;

    .line 17
    .line 18
    .line 19
    and-int/lit8 v4, v0, 0x6

    .line 20
    .line 21
    if-nez v4, :cond_1

    .line 22
    .line 23
    invoke-virtual {v10, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 24
    .line 25
    .line 26
    move-result v4

    .line 27
    if-eqz v4, :cond_0

    .line 28
    .line 29
    const/4 v4, 0x4

    .line 30
    goto :goto_0

    .line 31
    :cond_0
    const/4 v4, 0x2

    .line 32
    :goto_0
    or-int/2addr v4, v0

    .line 33
    goto :goto_1

    .line 34
    :cond_1
    move v4, v0

    .line 35
    :goto_1
    and-int/lit8 v5, v0, 0x30

    .line 36
    .line 37
    if-nez v5, :cond_3

    .line 38
    .line 39
    invoke-virtual {v10, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

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
    const/16 v5, 0x10

    .line 49
    .line 50
    :goto_2
    or-int/2addr v4, v5

    .line 51
    :cond_3
    and-int/lit16 v5, v0, 0x180

    .line 52
    .line 53
    const/16 v6, 0x100

    .line 54
    .line 55
    if-nez v5, :cond_5

    .line 56
    .line 57
    invoke-virtual {v10, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 58
    .line 59
    .line 60
    move-result v5

    .line 61
    if-eqz v5, :cond_4

    .line 62
    .line 63
    move v5, v6

    .line 64
    goto :goto_3

    .line 65
    :cond_4
    const/16 v5, 0x80

    .line 66
    .line 67
    :goto_3
    or-int/2addr v4, v5

    .line 68
    :cond_5
    and-int/lit16 v5, v0, 0xc00

    .line 69
    .line 70
    const/16 v7, 0x800

    .line 71
    .line 72
    if-nez v5, :cond_7

    .line 73
    .line 74
    move-object/from16 v5, p3

    .line 75
    .line 76
    invoke-virtual {v10, v5}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 77
    .line 78
    .line 79
    move-result v8

    .line 80
    if-eqz v8, :cond_6

    .line 81
    .line 82
    move v8, v7

    .line 83
    goto :goto_4

    .line 84
    :cond_6
    const/16 v8, 0x400

    .line 85
    .line 86
    :goto_4
    or-int/2addr v4, v8

    .line 87
    goto :goto_5

    .line 88
    :cond_7
    move-object/from16 v5, p3

    .line 89
    .line 90
    :goto_5
    and-int/lit16 v8, v4, 0x493

    .line 91
    .line 92
    const/16 v9, 0x492

    .line 93
    .line 94
    const/4 v11, 0x0

    .line 95
    const/4 v12, 0x1

    .line 96
    if-eq v8, v9, :cond_8

    .line 97
    .line 98
    move v8, v12

    .line 99
    goto :goto_6

    .line 100
    :cond_8
    move v8, v11

    .line 101
    :goto_6
    and-int/lit8 v9, v4, 0x1

    .line 102
    .line 103
    invoke-virtual {v10, v9, v8}, Ll2/t;->O(IZ)Z

    .line 104
    .line 105
    .line 106
    move-result v8

    .line 107
    if-eqz v8, :cond_d

    .line 108
    .line 109
    invoke-static {v1, v10}, Ll2/b;->s(Ljava/lang/Object;Ll2/o;)Ll2/b1;

    .line 110
    .line 111
    .line 112
    move-result-object v8

    .line 113
    invoke-static {v2, v10}, Ll2/b;->s(Ljava/lang/Object;Ll2/o;)Ll2/b1;

    .line 114
    .line 115
    .line 116
    move-result-object v9

    .line 117
    iget-boolean v13, v3, Luh/e;->a:Z

    .line 118
    .line 119
    invoke-static {v13}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 120
    .line 121
    .line 122
    move-result-object v13

    .line 123
    iget-boolean v14, v3, Luh/e;->b:Z

    .line 124
    .line 125
    invoke-static {v14}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 126
    .line 127
    .line 128
    move-result-object v14

    .line 129
    and-int/lit16 v15, v4, 0x380

    .line 130
    .line 131
    if-ne v15, v6, :cond_9

    .line 132
    .line 133
    move v6, v12

    .line 134
    goto :goto_7

    .line 135
    :cond_9
    move v6, v11

    .line 136
    :goto_7
    invoke-virtual {v10, v9}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 137
    .line 138
    .line 139
    move-result v15

    .line 140
    or-int/2addr v6, v15

    .line 141
    and-int/lit16 v4, v4, 0x1c00

    .line 142
    .line 143
    if-ne v4, v7, :cond_a

    .line 144
    .line 145
    move v11, v12

    .line 146
    :cond_a
    or-int v4, v6, v11

    .line 147
    .line 148
    invoke-virtual {v10, v8}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 149
    .line 150
    .line 151
    move-result v6

    .line 152
    or-int/2addr v4, v6

    .line 153
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 154
    .line 155
    .line 156
    move-result-object v6

    .line 157
    if-nez v4, :cond_b

    .line 158
    .line 159
    sget-object v4, Ll2/n;->a:Ll2/x0;

    .line 160
    .line 161
    if-ne v6, v4, :cond_c

    .line 162
    .line 163
    :cond_b
    new-instance v3, Lff/a;

    .line 164
    .line 165
    move-object v7, v8

    .line 166
    const/4 v8, 0x0

    .line 167
    move-object v6, v9

    .line 168
    const/16 v9, 0xb

    .line 169
    .line 170
    move-object/from16 v4, p2

    .line 171
    .line 172
    invoke-direct/range {v3 .. v9}, Lff/a;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 173
    .line 174
    .line 175
    invoke-virtual {v10, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 176
    .line 177
    .line 178
    move-object v6, v3

    .line 179
    :cond_c
    check-cast v6, Lay0/n;

    .line 180
    .line 181
    invoke-static {v13, v14, v6, v10}, Ll2/l0;->e(Ljava/lang/Object;Ljava/lang/Object;Lay0/n;Ll2/o;)V

    .line 182
    .line 183
    .line 184
    goto :goto_8

    .line 185
    :cond_d
    invoke-virtual {v10}, Ll2/t;->R()V

    .line 186
    .line 187
    .line 188
    :goto_8
    invoke-virtual {v10}, Ll2/t;->s()Ll2/u1;

    .line 189
    .line 190
    .line 191
    move-result-object v7

    .line 192
    if-eqz v7, :cond_e

    .line 193
    .line 194
    new-instance v0, Lr40/f;

    .line 195
    .line 196
    const/4 v6, 0x6

    .line 197
    move-object/from16 v3, p2

    .line 198
    .line 199
    move-object/from16 v4, p3

    .line 200
    .line 201
    move/from16 v5, p5

    .line 202
    .line 203
    invoke-direct/range {v0 .. v6}, Lr40/f;-><init>(Lay0/a;Lay0/a;Ljava/lang/Object;Ljava/lang/Object;II)V

    .line 204
    .line 205
    .line 206
    iput-object v0, v7, Ll2/u1;->d:Lay0/n;

    .line 207
    .line 208
    :cond_e
    return-void
.end method

.method public static final c(ILay0/a;Lay0/a;Ll2/o;Z)V
    .locals 20

    .line 1
    move/from16 v4, p0

    .line 2
    .line 3
    move-object/from16 v2, p1

    .line 4
    .line 5
    move-object/from16 v3, p2

    .line 6
    .line 7
    const-string v0, "goToOverview"

    .line 8
    .line 9
    invoke-static {v2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    const-string v0, "goToNextStep"

    .line 13
    .line 14
    invoke-static {v3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    move-object/from16 v9, p3

    .line 18
    .line 19
    check-cast v9, Ll2/t;

    .line 20
    .line 21
    const v0, 0x5c95396a

    .line 22
    .line 23
    .line 24
    invoke-virtual {v9, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 25
    .line 26
    .line 27
    invoke-virtual {v9, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result v0

    .line 31
    if-eqz v0, :cond_0

    .line 32
    .line 33
    const/16 v0, 0x20

    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_0
    const/16 v0, 0x10

    .line 37
    .line 38
    :goto_0
    or-int/2addr v0, v4

    .line 39
    and-int/lit16 v1, v4, 0x180

    .line 40
    .line 41
    if-nez v1, :cond_2

    .line 42
    .line 43
    invoke-virtual {v9, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 44
    .line 45
    .line 46
    move-result v1

    .line 47
    if-eqz v1, :cond_1

    .line 48
    .line 49
    const/16 v1, 0x100

    .line 50
    .line 51
    goto :goto_1

    .line 52
    :cond_1
    const/16 v1, 0x80

    .line 53
    .line 54
    :goto_1
    or-int/2addr v0, v1

    .line 55
    :cond_2
    and-int/lit16 v1, v0, 0x93

    .line 56
    .line 57
    const/16 v5, 0x92

    .line 58
    .line 59
    const/4 v6, 0x0

    .line 60
    if-eq v1, v5, :cond_3

    .line 61
    .line 62
    const/4 v1, 0x1

    .line 63
    goto :goto_2

    .line 64
    :cond_3
    move v1, v6

    .line 65
    :goto_2
    and-int/lit8 v5, v0, 0x1

    .line 66
    .line 67
    invoke-virtual {v9, v5, v1}, Ll2/t;->O(IZ)Z

    .line 68
    .line 69
    .line 70
    move-result v1

    .line 71
    if-eqz v1, :cond_c

    .line 72
    .line 73
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 74
    .line 75
    .line 76
    move-result-object v1

    .line 77
    sget-object v11, Ll2/n;->a:Ll2/x0;

    .line 78
    .line 79
    if-ne v1, v11, :cond_4

    .line 80
    .line 81
    new-instance v1, Lu2/d;

    .line 82
    .line 83
    const/16 v5, 0xe

    .line 84
    .line 85
    invoke-direct {v1, v5}, Lu2/d;-><init>(I)V

    .line 86
    .line 87
    .line 88
    invoke-virtual {v9, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 89
    .line 90
    .line 91
    :cond_4
    check-cast v1, Lay0/k;

    .line 92
    .line 93
    sget-object v5, Lw3/q1;->a:Ll2/u2;

    .line 94
    .line 95
    invoke-virtual {v9, v5}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 96
    .line 97
    .line 98
    move-result-object v5

    .line 99
    check-cast v5, Ljava/lang/Boolean;

    .line 100
    .line 101
    invoke-virtual {v5}, Ljava/lang/Boolean;->booleanValue()Z

    .line 102
    .line 103
    .line 104
    move-result v5

    .line 105
    if-eqz v5, :cond_5

    .line 106
    .line 107
    const v5, -0x105bcaaa

    .line 108
    .line 109
    .line 110
    invoke-virtual {v9, v5}, Ll2/t;->Y(I)V

    .line 111
    .line 112
    .line 113
    invoke-virtual {v9, v6}, Ll2/t;->q(Z)V

    .line 114
    .line 115
    .line 116
    const/4 v5, 0x0

    .line 117
    goto :goto_3

    .line 118
    :cond_5
    const v5, 0x31054eee

    .line 119
    .line 120
    .line 121
    invoke-virtual {v9, v5}, Ll2/t;->Y(I)V

    .line 122
    .line 123
    .line 124
    sget-object v5, Lzb/x;->a:Ll2/u2;

    .line 125
    .line 126
    invoke-virtual {v9, v5}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 127
    .line 128
    .line 129
    move-result-object v5

    .line 130
    check-cast v5, Lhi/a;

    .line 131
    .line 132
    invoke-virtual {v9, v6}, Ll2/t;->q(Z)V

    .line 133
    .line 134
    .line 135
    :goto_3
    new-instance v8, Lnd/e;

    .line 136
    .line 137
    const/16 v6, 0x1c

    .line 138
    .line 139
    invoke-direct {v8, v5, v1, v6}, Lnd/e;-><init>(Lhi/a;Lay0/k;I)V

    .line 140
    .line 141
    .line 142
    invoke-static {v9}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 143
    .line 144
    .line 145
    move-result-object v6

    .line 146
    if-eqz v6, :cond_b

    .line 147
    .line 148
    instance-of v1, v6, Landroidx/lifecycle/k;

    .line 149
    .line 150
    if-eqz v1, :cond_6

    .line 151
    .line 152
    move-object v1, v6

    .line 153
    check-cast v1, Landroidx/lifecycle/k;

    .line 154
    .line 155
    invoke-interface {v1}, Landroidx/lifecycle/k;->getDefaultViewModelCreationExtras()Lp7/c;

    .line 156
    .line 157
    .line 158
    move-result-object v1

    .line 159
    goto :goto_4

    .line 160
    :cond_6
    sget-object v1, Lp7/a;->b:Lp7/a;

    .line 161
    .line 162
    :goto_4
    const-class v5, Luh/g;

    .line 163
    .line 164
    sget-object v7, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 165
    .line 166
    invoke-virtual {v7, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 167
    .line 168
    .line 169
    move-result-object v5

    .line 170
    const/4 v7, 0x0

    .line 171
    move-object v10, v9

    .line 172
    move-object v9, v1

    .line 173
    invoke-static/range {v5 .. v10}, Ljp/se;->b(Lhy0/d;Landroidx/lifecycle/i1;Ljava/lang/String;Landroidx/lifecycle/e1;Lp7/c;Ll2/o;)Landroidx/lifecycle/b1;

    .line 174
    .line 175
    .line 176
    move-result-object v1

    .line 177
    move-object v9, v10

    .line 178
    move-object v14, v1

    .line 179
    check-cast v14, Luh/g;

    .line 180
    .line 181
    iget-object v1, v14, Luh/g;->e:Lyy0/l1;

    .line 182
    .line 183
    invoke-static {v1, v9}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 184
    .line 185
    .line 186
    move-result-object v1

    .line 187
    invoke-interface {v1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 188
    .line 189
    .line 190
    move-result-object v1

    .line 191
    move-object v7, v1

    .line 192
    check-cast v7, Luh/e;

    .line 193
    .line 194
    invoke-virtual {v9, v14}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 195
    .line 196
    .line 197
    move-result v1

    .line 198
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 199
    .line 200
    .line 201
    move-result-object v5

    .line 202
    if-nez v1, :cond_7

    .line 203
    .line 204
    if-ne v5, v11, :cond_8

    .line 205
    .line 206
    :cond_7
    new-instance v12, Lt10/k;

    .line 207
    .line 208
    const/16 v18, 0x0

    .line 209
    .line 210
    const/16 v19, 0x13

    .line 211
    .line 212
    const/4 v13, 0x1

    .line 213
    const-class v15, Luh/g;

    .line 214
    .line 215
    const-string v16, "onUiEvent"

    .line 216
    .line 217
    const-string v17, "onUiEvent(Lcariad/charging/multicharge/kitten/wallboxes/presentation/onboarding/success/WallboxSuccessUiEvent;)V"

    .line 218
    .line 219
    invoke-direct/range {v12 .. v19}, Lt10/k;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 220
    .line 221
    .line 222
    invoke-virtual {v9, v12}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 223
    .line 224
    .line 225
    move-object v5, v12

    .line 226
    :cond_8
    check-cast v5, Lhy0/g;

    .line 227
    .line 228
    move-object v8, v5

    .line 229
    check-cast v8, Lay0/k;

    .line 230
    .line 231
    shr-int/lit8 v0, v0, 0x3

    .line 232
    .line 233
    and-int/lit8 v10, v0, 0x7e

    .line 234
    .line 235
    move-object v5, v2

    .line 236
    move-object v6, v3

    .line 237
    invoke-static/range {v5 .. v10}, Llp/t1;->b(Lay0/a;Lay0/a;Luh/e;Lay0/k;Ll2/o;I)V

    .line 238
    .line 239
    .line 240
    invoke-static {v9}, Leh/a;->b(Ll2/o;)Leh/n;

    .line 241
    .line 242
    .line 243
    move-result-object v0

    .line 244
    invoke-virtual {v9, v14}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 245
    .line 246
    .line 247
    move-result v1

    .line 248
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 249
    .line 250
    .line 251
    move-result-object v2

    .line 252
    if-nez v1, :cond_9

    .line 253
    .line 254
    if-ne v2, v11, :cond_a

    .line 255
    .line 256
    :cond_9
    new-instance v12, Lt10/k;

    .line 257
    .line 258
    const/16 v18, 0x0

    .line 259
    .line 260
    const/16 v19, 0x14

    .line 261
    .line 262
    const/4 v13, 0x1

    .line 263
    const-class v15, Luh/g;

    .line 264
    .line 265
    const-string v16, "onUiEvent"

    .line 266
    .line 267
    const-string v17, "onUiEvent(Lcariad/charging/multicharge/kitten/wallboxes/presentation/onboarding/success/WallboxSuccessUiEvent;)V"

    .line 268
    .line 269
    invoke-direct/range {v12 .. v19}, Lt10/k;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 270
    .line 271
    .line 272
    invoke-virtual {v9, v12}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 273
    .line 274
    .line 275
    move-object v2, v12

    .line 276
    :cond_a
    check-cast v2, Lhy0/g;

    .line 277
    .line 278
    check-cast v2, Lay0/k;

    .line 279
    .line 280
    const/4 v1, 0x6

    .line 281
    move/from16 v3, p4

    .line 282
    .line 283
    invoke-interface {v0, v3, v2, v9, v1}, Leh/n;->D(ZLay0/k;Ll2/o;I)V

    .line 284
    .line 285
    .line 286
    goto :goto_5

    .line 287
    :cond_b
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 288
    .line 289
    const-string v1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 290
    .line 291
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 292
    .line 293
    .line 294
    throw v0

    .line 295
    :cond_c
    move/from16 v3, p4

    .line 296
    .line 297
    invoke-virtual {v9}, Ll2/t;->R()V

    .line 298
    .line 299
    .line 300
    :goto_5
    invoke-virtual {v9}, Ll2/t;->s()Ll2/u1;

    .line 301
    .line 302
    .line 303
    move-result-object v6

    .line 304
    if-eqz v6, :cond_d

    .line 305
    .line 306
    new-instance v0, Le2/x0;

    .line 307
    .line 308
    const/16 v5, 0xb

    .line 309
    .line 310
    move-object/from16 v2, p1

    .line 311
    .line 312
    move v1, v3

    .line 313
    move-object/from16 v3, p2

    .line 314
    .line 315
    invoke-direct/range {v0 .. v5}, Le2/x0;-><init>(ZLjava/lang/Object;Ljava/lang/Object;II)V

    .line 316
    .line 317
    .line 318
    iput-object v0, v6, Ll2/u1;->d:Lay0/n;

    .line 319
    .line 320
    :cond_d
    return-void
.end method
