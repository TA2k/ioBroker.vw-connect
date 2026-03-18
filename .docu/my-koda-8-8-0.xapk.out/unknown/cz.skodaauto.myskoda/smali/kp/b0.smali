.class public abstract Lkp/b0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lay0/a;Lay0/a;Lay0/k;Lre/i;Ll2/o;I)V
    .locals 13

    .line 1
    move-object/from16 v4, p3

    .line 2
    .line 3
    move/from16 v0, p5

    .line 4
    .line 5
    move-object/from16 v1, p4

    .line 6
    .line 7
    check-cast v1, Ll2/t;

    .line 8
    .line 9
    const v2, -0x4075ec00

    .line 10
    .line 11
    .line 12
    invoke-virtual {v1, v2}, Ll2/t;->a0(I)Ll2/t;

    .line 13
    .line 14
    .line 15
    and-int/lit8 v2, v0, 0x6

    .line 16
    .line 17
    const/4 v5, 0x4

    .line 18
    if-nez v2, :cond_1

    .line 19
    .line 20
    invoke-virtual {v1, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 21
    .line 22
    .line 23
    move-result v2

    .line 24
    if-eqz v2, :cond_0

    .line 25
    .line 26
    move v2, v5

    .line 27
    goto :goto_0

    .line 28
    :cond_0
    const/4 v2, 0x2

    .line 29
    :goto_0
    or-int/2addr v2, v0

    .line 30
    goto :goto_1

    .line 31
    :cond_1
    move v2, v0

    .line 32
    :goto_1
    and-int/lit8 v6, v0, 0x30

    .line 33
    .line 34
    if-nez v6, :cond_3

    .line 35
    .line 36
    invoke-virtual {v1, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 37
    .line 38
    .line 39
    move-result v6

    .line 40
    if-eqz v6, :cond_2

    .line 41
    .line 42
    const/16 v6, 0x20

    .line 43
    .line 44
    goto :goto_2

    .line 45
    :cond_2
    const/16 v6, 0x10

    .line 46
    .line 47
    :goto_2
    or-int/2addr v2, v6

    .line 48
    :cond_3
    and-int/lit16 v6, v0, 0x180

    .line 49
    .line 50
    if-nez v6, :cond_5

    .line 51
    .line 52
    invoke-virtual {v1, p2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 53
    .line 54
    .line 55
    move-result v6

    .line 56
    if-eqz v6, :cond_4

    .line 57
    .line 58
    const/16 v6, 0x100

    .line 59
    .line 60
    goto :goto_3

    .line 61
    :cond_4
    const/16 v6, 0x80

    .line 62
    .line 63
    :goto_3
    or-int/2addr v2, v6

    .line 64
    :cond_5
    and-int/lit16 v6, v0, 0xc00

    .line 65
    .line 66
    const/16 v7, 0x800

    .line 67
    .line 68
    if-nez v6, :cond_8

    .line 69
    .line 70
    and-int/lit16 v6, v0, 0x1000

    .line 71
    .line 72
    if-nez v6, :cond_6

    .line 73
    .line 74
    invoke-virtual {v1, v4}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 75
    .line 76
    .line 77
    move-result v6

    .line 78
    goto :goto_4

    .line 79
    :cond_6
    invoke-virtual {v1, v4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 80
    .line 81
    .line 82
    move-result v6

    .line 83
    :goto_4
    if-eqz v6, :cond_7

    .line 84
    .line 85
    move v6, v7

    .line 86
    goto :goto_5

    .line 87
    :cond_7
    const/16 v6, 0x400

    .line 88
    .line 89
    :goto_5
    or-int/2addr v2, v6

    .line 90
    :cond_8
    and-int/lit16 v6, v2, 0x493

    .line 91
    .line 92
    const/16 v8, 0x492

    .line 93
    .line 94
    const/4 v9, 0x0

    .line 95
    const/4 v10, 0x1

    .line 96
    if-eq v6, v8, :cond_9

    .line 97
    .line 98
    move v6, v10

    .line 99
    goto :goto_6

    .line 100
    :cond_9
    move v6, v9

    .line 101
    :goto_6
    and-int/lit8 v8, v2, 0x1

    .line 102
    .line 103
    invoke-virtual {v1, v8, v6}, Ll2/t;->O(IZ)Z

    .line 104
    .line 105
    .line 106
    move-result v6

    .line 107
    if-eqz v6, :cond_f

    .line 108
    .line 109
    invoke-static {p1, v1}, Ll2/b;->s(Ljava/lang/Object;Ll2/o;)Ll2/b1;

    .line 110
    .line 111
    .line 112
    move-result-object v6

    .line 113
    invoke-static {p2, v1}, Ll2/b;->s(Ljava/lang/Object;Ll2/o;)Ll2/b1;

    .line 114
    .line 115
    .line 116
    move-result-object v8

    .line 117
    and-int/lit16 v11, v2, 0x1c00

    .line 118
    .line 119
    if-eq v11, v7, :cond_b

    .line 120
    .line 121
    and-int/lit16 v7, v2, 0x1000

    .line 122
    .line 123
    if-eqz v7, :cond_a

    .line 124
    .line 125
    invoke-virtual {v1, v4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 126
    .line 127
    .line 128
    move-result v7

    .line 129
    if-eqz v7, :cond_a

    .line 130
    .line 131
    goto :goto_7

    .line 132
    :cond_a
    move v7, v9

    .line 133
    goto :goto_8

    .line 134
    :cond_b
    :goto_7
    move v7, v10

    .line 135
    :goto_8
    invoke-virtual {v1, v6}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 136
    .line 137
    .line 138
    move-result v11

    .line 139
    or-int/2addr v7, v11

    .line 140
    and-int/lit8 v2, v2, 0xe

    .line 141
    .line 142
    if-ne v2, v5, :cond_c

    .line 143
    .line 144
    move v9, v10

    .line 145
    :cond_c
    or-int v2, v7, v9

    .line 146
    .line 147
    invoke-virtual {v1, v8}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 148
    .line 149
    .line 150
    move-result v5

    .line 151
    or-int/2addr v2, v5

    .line 152
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 153
    .line 154
    .line 155
    move-result-object v5

    .line 156
    if-nez v2, :cond_e

    .line 157
    .line 158
    sget-object v2, Ll2/n;->a:Ll2/x0;

    .line 159
    .line 160
    if-ne v5, v2, :cond_d

    .line 161
    .line 162
    goto :goto_9

    .line 163
    :cond_d
    move-object v12, v5

    .line 164
    move-object v5, v4

    .line 165
    move-object v4, v12

    .line 166
    goto :goto_a

    .line 167
    :cond_e
    :goto_9
    new-instance v4, Lff/a;

    .line 168
    .line 169
    const/4 v9, 0x0

    .line 170
    const/4 v10, 0x7

    .line 171
    move-object/from16 v5, p3

    .line 172
    .line 173
    move-object v7, v6

    .line 174
    move-object v6, p0

    .line 175
    invoke-direct/range {v4 .. v10}, Lff/a;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 176
    .line 177
    .line 178
    invoke-virtual {v1, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 179
    .line 180
    .line 181
    :goto_a
    check-cast v4, Lay0/n;

    .line 182
    .line 183
    invoke-static {v4, v5, v1}, Ll2/l0;->d(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 184
    .line 185
    .line 186
    goto :goto_b

    .line 187
    :cond_f
    move-object v5, v4

    .line 188
    invoke-virtual {v1}, Ll2/t;->R()V

    .line 189
    .line 190
    .line 191
    :goto_b
    invoke-virtual {v1}, Ll2/t;->s()Ll2/u1;

    .line 192
    .line 193
    .line 194
    move-result-object v6

    .line 195
    if-eqz v6, :cond_10

    .line 196
    .line 197
    new-instance v0, Lr40/f;

    .line 198
    .line 199
    move-object v1, p0

    .line 200
    move-object v2, p1

    .line 201
    move-object v3, p2

    .line 202
    move-object v4, v5

    .line 203
    move/from16 v5, p5

    .line 204
    .line 205
    invoke-direct/range {v0 .. v5}, Lr40/f;-><init>(Lay0/a;Lay0/a;Lay0/k;Lre/i;I)V

    .line 206
    .line 207
    .line 208
    iput-object v0, v6, Ll2/u1;->d:Lay0/n;

    .line 209
    .line 210
    :cond_10
    return-void
.end method

.method public static final b(ILay0/a;Lay0/k;Ll2/o;)V
    .locals 20

    .line 1
    move/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v2, p1

    .line 4
    .line 5
    move-object/from16 v3, p2

    .line 6
    .line 7
    const-string v1, "goToBack"

    .line 8
    .line 9
    invoke-static {v2, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    const-string v1, "goToNext"

    .line 13
    .line 14
    invoke-static {v3, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    move-object/from16 v5, p3

    .line 18
    .line 19
    check-cast v5, Ll2/t;

    .line 20
    .line 21
    const v1, -0x79aa6b36

    .line 22
    .line 23
    .line 24
    invoke-virtual {v5, v1}, Ll2/t;->a0(I)Ll2/t;

    .line 25
    .line 26
    .line 27
    invoke-virtual {v5, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result v1

    .line 31
    if-eqz v1, :cond_0

    .line 32
    .line 33
    const/4 v1, 0x4

    .line 34
    goto :goto_0

    .line 35
    :cond_0
    const/4 v1, 0x2

    .line 36
    :goto_0
    or-int/2addr v1, v0

    .line 37
    invoke-virtual {v5, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 38
    .line 39
    .line 40
    move-result v4

    .line 41
    if-eqz v4, :cond_1

    .line 42
    .line 43
    const/16 v4, 0x20

    .line 44
    .line 45
    goto :goto_1

    .line 46
    :cond_1
    const/16 v4, 0x10

    .line 47
    .line 48
    :goto_1
    or-int/2addr v1, v4

    .line 49
    and-int/lit8 v4, v1, 0x13

    .line 50
    .line 51
    const/16 v6, 0x12

    .line 52
    .line 53
    const/4 v10, 0x0

    .line 54
    if-eq v4, v6, :cond_2

    .line 55
    .line 56
    const/4 v4, 0x1

    .line 57
    goto :goto_2

    .line 58
    :cond_2
    move v4, v10

    .line 59
    :goto_2
    and-int/lit8 v6, v1, 0x1

    .line 60
    .line 61
    invoke-virtual {v5, v6, v4}, Ll2/t;->O(IZ)Z

    .line 62
    .line 63
    .line 64
    move-result v4

    .line 65
    if-eqz v4, :cond_b

    .line 66
    .line 67
    invoke-virtual {v5}, Ll2/t;->L()Ljava/lang/Object;

    .line 68
    .line 69
    .line 70
    move-result-object v4

    .line 71
    sget-object v11, Ll2/n;->a:Ll2/x0;

    .line 72
    .line 73
    if-ne v4, v11, :cond_3

    .line 74
    .line 75
    new-instance v4, Lr40/e;

    .line 76
    .line 77
    const/4 v6, 0x5

    .line 78
    invoke-direct {v4, v6}, Lr40/e;-><init>(I)V

    .line 79
    .line 80
    .line 81
    invoke-virtual {v5, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 82
    .line 83
    .line 84
    :cond_3
    check-cast v4, Lay0/k;

    .line 85
    .line 86
    sget-object v6, Lw3/q1;->a:Ll2/u2;

    .line 87
    .line 88
    invoke-virtual {v5, v6}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 89
    .line 90
    .line 91
    move-result-object v6

    .line 92
    check-cast v6, Ljava/lang/Boolean;

    .line 93
    .line 94
    invoke-virtual {v6}, Ljava/lang/Boolean;->booleanValue()Z

    .line 95
    .line 96
    .line 97
    move-result v6

    .line 98
    if-eqz v6, :cond_4

    .line 99
    .line 100
    const v6, -0x105bcaaa

    .line 101
    .line 102
    .line 103
    invoke-virtual {v5, v6}, Ll2/t;->Y(I)V

    .line 104
    .line 105
    .line 106
    invoke-virtual {v5, v10}, Ll2/t;->q(Z)V

    .line 107
    .line 108
    .line 109
    const/4 v6, 0x0

    .line 110
    goto :goto_3

    .line 111
    :cond_4
    const v6, 0x31054eee

    .line 112
    .line 113
    .line 114
    invoke-virtual {v5, v6}, Ll2/t;->Y(I)V

    .line 115
    .line 116
    .line 117
    sget-object v6, Lzb/x;->a:Ll2/u2;

    .line 118
    .line 119
    invoke-virtual {v5, v6}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 120
    .line 121
    .line 122
    move-result-object v6

    .line 123
    check-cast v6, Lhi/a;

    .line 124
    .line 125
    invoke-virtual {v5, v10}, Ll2/t;->q(Z)V

    .line 126
    .line 127
    .line 128
    :goto_3
    new-instance v7, Lnd/e;

    .line 129
    .line 130
    const/16 v8, 0xd

    .line 131
    .line 132
    invoke-direct {v7, v6, v4, v8}, Lnd/e;-><init>(Lhi/a;Lay0/k;I)V

    .line 133
    .line 134
    .line 135
    move-object v9, v5

    .line 136
    invoke-static {v9}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 137
    .line 138
    .line 139
    move-result-object v5

    .line 140
    if-eqz v5, :cond_a

    .line 141
    .line 142
    instance-of v4, v5, Landroidx/lifecycle/k;

    .line 143
    .line 144
    if-eqz v4, :cond_5

    .line 145
    .line 146
    move-object v4, v5

    .line 147
    check-cast v4, Landroidx/lifecycle/k;

    .line 148
    .line 149
    invoke-interface {v4}, Landroidx/lifecycle/k;->getDefaultViewModelCreationExtras()Lp7/c;

    .line 150
    .line 151
    .line 152
    move-result-object v4

    .line 153
    :goto_4
    move-object v8, v4

    .line 154
    goto :goto_5

    .line 155
    :cond_5
    sget-object v4, Lp7/a;->b:Lp7/a;

    .line 156
    .line 157
    goto :goto_4

    .line 158
    :goto_5
    const-class v4, Lre/k;

    .line 159
    .line 160
    sget-object v6, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 161
    .line 162
    invoke-virtual {v6, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 163
    .line 164
    .line 165
    move-result-object v4

    .line 166
    const/4 v6, 0x0

    .line 167
    invoke-static/range {v4 .. v9}, Ljp/se;->b(Lhy0/d;Landroidx/lifecycle/i1;Ljava/lang/String;Landroidx/lifecycle/e1;Lp7/c;Ll2/o;)Landroidx/lifecycle/b1;

    .line 168
    .line 169
    .line 170
    move-result-object v4

    .line 171
    move-object v14, v4

    .line 172
    check-cast v14, Lre/k;

    .line 173
    .line 174
    iget-object v4, v14, Lre/k;->f:Lyy0/l1;

    .line 175
    .line 176
    invoke-static {v4, v9}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 177
    .line 178
    .line 179
    move-result-object v7

    .line 180
    invoke-virtual {v9, v14}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 181
    .line 182
    .line 183
    move-result v4

    .line 184
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 185
    .line 186
    .line 187
    move-result-object v5

    .line 188
    if-nez v4, :cond_6

    .line 189
    .line 190
    if-ne v5, v11, :cond_7

    .line 191
    .line 192
    :cond_6
    new-instance v5, Lr1/b;

    .line 193
    .line 194
    const/16 v4, 0x8

    .line 195
    .line 196
    invoke-direct {v5, v14, v4}, Lr1/b;-><init>(Ljava/lang/Object;I)V

    .line 197
    .line 198
    .line 199
    invoke-virtual {v9, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 200
    .line 201
    .line 202
    :cond_7
    check-cast v5, Lay0/a;

    .line 203
    .line 204
    invoke-interface {v7}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 205
    .line 206
    .line 207
    move-result-object v4

    .line 208
    check-cast v4, Lre/i;

    .line 209
    .line 210
    shl-int/lit8 v1, v1, 0x3

    .line 211
    .line 212
    and-int/lit16 v6, v1, 0x3f0

    .line 213
    .line 214
    move-object v1, v5

    .line 215
    move-object v5, v9

    .line 216
    invoke-static/range {v1 .. v6}, Lkp/b0;->a(Lay0/a;Lay0/a;Lay0/k;Lre/i;Ll2/o;I)V

    .line 217
    .line 218
    .line 219
    invoke-static {v9}, Llp/nf;->a(Ll2/o;)Lle/c;

    .line 220
    .line 221
    .line 222
    move-result-object v1

    .line 223
    invoke-interface {v7}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 224
    .line 225
    .line 226
    move-result-object v4

    .line 227
    check-cast v4, Lre/i;

    .line 228
    .line 229
    invoke-virtual {v9, v14}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 230
    .line 231
    .line 232
    move-result v5

    .line 233
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 234
    .line 235
    .line 236
    move-result-object v6

    .line 237
    if-nez v5, :cond_8

    .line 238
    .line 239
    if-ne v6, v11, :cond_9

    .line 240
    .line 241
    :cond_8
    new-instance v12, Lo90/f;

    .line 242
    .line 243
    const/16 v18, 0x0

    .line 244
    .line 245
    const/16 v19, 0x13

    .line 246
    .line 247
    const/4 v13, 0x1

    .line 248
    const-class v15, Lre/k;

    .line 249
    .line 250
    const-string v16, "onUiEvent"

    .line 251
    .line 252
    const-string v17, "onUiEvent(Lcariad/charging/multicharge/kitten/kola/presentation/wizard/common/currency/KolaWizardSetupCurrencyUiEvent;)V"

    .line 253
    .line 254
    invoke-direct/range {v12 .. v19}, Lo90/f;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 255
    .line 256
    .line 257
    invoke-virtual {v9, v12}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 258
    .line 259
    .line 260
    move-object v6, v12

    .line 261
    :cond_9
    check-cast v6, Lhy0/g;

    .line 262
    .line 263
    check-cast v6, Lay0/k;

    .line 264
    .line 265
    invoke-interface {v1, v4, v6, v9, v10}, Lle/c;->M(Lre/i;Lay0/k;Ll2/o;I)V

    .line 266
    .line 267
    .line 268
    goto :goto_6

    .line 269
    :cond_a
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 270
    .line 271
    const-string v1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 272
    .line 273
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 274
    .line 275
    .line 276
    throw v0

    .line 277
    :cond_b
    move-object v9, v5

    .line 278
    invoke-virtual {v9}, Ll2/t;->R()V

    .line 279
    .line 280
    .line 281
    :goto_6
    invoke-virtual {v9}, Ll2/t;->s()Ll2/u1;

    .line 282
    .line 283
    .line 284
    move-result-object v1

    .line 285
    if-eqz v1, :cond_c

    .line 286
    .line 287
    new-instance v4, Lcf/b;

    .line 288
    .line 289
    const/4 v5, 0x4

    .line 290
    invoke-direct {v4, v2, v3, v0, v5}, Lcf/b;-><init>(Lay0/a;Lay0/k;II)V

    .line 291
    .line 292
    .line 293
    iput-object v4, v1, Ll2/u1;->d:Lay0/n;

    .line 294
    .line 295
    :cond_c
    return-void
.end method

.method public static c(Ld5/f;Le5/b;Le5/f;Ljava/lang/String;Lz4/q;)V
    .locals 22

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v2, p2

    .line 6
    .line 7
    move-object/from16 v3, p3

    .line 8
    .line 9
    move-object/from16 v4, p4

    .line 10
    .line 11
    const/4 v5, 0x0

    .line 12
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 13
    .line 14
    .line 15
    move-result-object v6

    .line 16
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 17
    .line 18
    .line 19
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 20
    .line 21
    .line 22
    move-result v7

    .line 23
    const/16 v9, 0xa

    .line 24
    .line 25
    const/16 v10, 0x8

    .line 26
    .line 27
    const/4 v11, 0x5

    .line 28
    const/4 v13, 0x4

    .line 29
    const/4 v15, 0x6

    .line 30
    const/4 v12, 0x1

    .line 31
    const/4 v8, -0x1

    .line 32
    sparse-switch v7, :sswitch_data_0

    .line 33
    .line 34
    .line 35
    :goto_0
    move v7, v8

    .line 36
    goto/16 :goto_1

    .line 37
    .line 38
    :sswitch_0
    const-string v7, "visibility"

    .line 39
    .line 40
    invoke-virtual {v3, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 41
    .line 42
    .line 43
    move-result v7

    .line 44
    if-nez v7, :cond_0

    .line 45
    .line 46
    goto :goto_0

    .line 47
    :cond_0
    const/16 v7, 0x17

    .line 48
    .line 49
    goto/16 :goto_1

    .line 50
    .line 51
    :sswitch_1
    const-string v7, "centerHorizontally"

    .line 52
    .line 53
    invoke-virtual {v3, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 54
    .line 55
    .line 56
    move-result v7

    .line 57
    if-nez v7, :cond_1

    .line 58
    .line 59
    goto :goto_0

    .line 60
    :cond_1
    const/16 v7, 0x16

    .line 61
    .line 62
    goto/16 :goto_1

    .line 63
    .line 64
    :sswitch_2
    const-string v7, "hWeight"

    .line 65
    .line 66
    invoke-virtual {v3, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 67
    .line 68
    .line 69
    move-result v7

    .line 70
    if-nez v7, :cond_2

    .line 71
    .line 72
    goto :goto_0

    .line 73
    :cond_2
    const/16 v7, 0x15

    .line 74
    .line 75
    goto/16 :goto_1

    .line 76
    .line 77
    :sswitch_3
    const-string v7, "width"

    .line 78
    .line 79
    invoke-virtual {v3, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 80
    .line 81
    .line 82
    move-result v7

    .line 83
    if-nez v7, :cond_3

    .line 84
    .line 85
    goto :goto_0

    .line 86
    :cond_3
    const/16 v7, 0x14

    .line 87
    .line 88
    goto/16 :goto_1

    .line 89
    .line 90
    :sswitch_4
    const-string v7, "vBias"

    .line 91
    .line 92
    invoke-virtual {v3, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 93
    .line 94
    .line 95
    move-result v7

    .line 96
    if-nez v7, :cond_4

    .line 97
    .line 98
    goto :goto_0

    .line 99
    :cond_4
    const/16 v7, 0x13

    .line 100
    .line 101
    goto/16 :goto_1

    .line 102
    .line 103
    :sswitch_5
    const-string v7, "hBias"

    .line 104
    .line 105
    invoke-virtual {v3, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 106
    .line 107
    .line 108
    move-result v7

    .line 109
    if-nez v7, :cond_5

    .line 110
    .line 111
    goto :goto_0

    .line 112
    :cond_5
    const/16 v7, 0x12

    .line 113
    .line 114
    goto/16 :goto_1

    .line 115
    .line 116
    :sswitch_6
    const-string v7, "alpha"

    .line 117
    .line 118
    invoke-virtual {v3, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 119
    .line 120
    .line 121
    move-result v7

    .line 122
    if-nez v7, :cond_6

    .line 123
    .line 124
    goto :goto_0

    .line 125
    :cond_6
    const/16 v7, 0x11

    .line 126
    .line 127
    goto/16 :goto_1

    .line 128
    .line 129
    :sswitch_7
    const-string v7, "vWeight"

    .line 130
    .line 131
    invoke-virtual {v3, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 132
    .line 133
    .line 134
    move-result v7

    .line 135
    if-nez v7, :cond_7

    .line 136
    .line 137
    goto :goto_0

    .line 138
    :cond_7
    const/16 v7, 0x10

    .line 139
    .line 140
    goto/16 :goto_1

    .line 141
    .line 142
    :sswitch_8
    const-string v7, "hRtlBias"

    .line 143
    .line 144
    invoke-virtual {v3, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 145
    .line 146
    .line 147
    move-result v7

    .line 148
    if-nez v7, :cond_8

    .line 149
    .line 150
    goto :goto_0

    .line 151
    :cond_8
    const/16 v7, 0xf

    .line 152
    .line 153
    goto/16 :goto_1

    .line 154
    .line 155
    :sswitch_9
    const-string v7, "scaleY"

    .line 156
    .line 157
    invoke-virtual {v3, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 158
    .line 159
    .line 160
    move-result v7

    .line 161
    if-nez v7, :cond_9

    .line 162
    .line 163
    goto/16 :goto_0

    .line 164
    .line 165
    :cond_9
    const/16 v7, 0xe

    .line 166
    .line 167
    goto/16 :goto_1

    .line 168
    .line 169
    :sswitch_a
    const-string v7, "scaleX"

    .line 170
    .line 171
    invoke-virtual {v3, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 172
    .line 173
    .line 174
    move-result v7

    .line 175
    if-nez v7, :cond_a

    .line 176
    .line 177
    goto/16 :goto_0

    .line 178
    .line 179
    :cond_a
    const/16 v7, 0xd

    .line 180
    .line 181
    goto/16 :goto_1

    .line 182
    .line 183
    :sswitch_b
    const-string v7, "pivotY"

    .line 184
    .line 185
    invoke-virtual {v3, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 186
    .line 187
    .line 188
    move-result v7

    .line 189
    if-nez v7, :cond_b

    .line 190
    .line 191
    goto/16 :goto_0

    .line 192
    .line 193
    :cond_b
    const/16 v7, 0xc

    .line 194
    .line 195
    goto/16 :goto_1

    .line 196
    .line 197
    :sswitch_c
    const-string v7, "pivotX"

    .line 198
    .line 199
    invoke-virtual {v3, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 200
    .line 201
    .line 202
    move-result v7

    .line 203
    if-nez v7, :cond_c

    .line 204
    .line 205
    goto/16 :goto_0

    .line 206
    .line 207
    :cond_c
    const/16 v7, 0xb

    .line 208
    .line 209
    goto/16 :goto_1

    .line 210
    .line 211
    :sswitch_d
    const-string v7, "motion"

    .line 212
    .line 213
    invoke-virtual {v3, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 214
    .line 215
    .line 216
    move-result v7

    .line 217
    if-nez v7, :cond_d

    .line 218
    .line 219
    goto/16 :goto_0

    .line 220
    .line 221
    :cond_d
    move v7, v9

    .line 222
    goto/16 :goto_1

    .line 223
    .line 224
    :sswitch_e
    const-string v7, "height"

    .line 225
    .line 226
    invoke-virtual {v3, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 227
    .line 228
    .line 229
    move-result v7

    .line 230
    if-nez v7, :cond_e

    .line 231
    .line 232
    goto/16 :goto_0

    .line 233
    .line 234
    :cond_e
    const/16 v7, 0x9

    .line 235
    .line 236
    goto/16 :goto_1

    .line 237
    .line 238
    :sswitch_f
    const-string v7, "translationZ"

    .line 239
    .line 240
    invoke-virtual {v3, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 241
    .line 242
    .line 243
    move-result v7

    .line 244
    if-nez v7, :cond_f

    .line 245
    .line 246
    goto/16 :goto_0

    .line 247
    .line 248
    :cond_f
    move v7, v10

    .line 249
    goto/16 :goto_1

    .line 250
    .line 251
    :sswitch_10
    const-string v7, "translationY"

    .line 252
    .line 253
    invoke-virtual {v3, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 254
    .line 255
    .line 256
    move-result v7

    .line 257
    if-nez v7, :cond_10

    .line 258
    .line 259
    goto/16 :goto_0

    .line 260
    .line 261
    :cond_10
    const/4 v7, 0x7

    .line 262
    goto :goto_1

    .line 263
    :sswitch_11
    const-string v7, "translationX"

    .line 264
    .line 265
    invoke-virtual {v3, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 266
    .line 267
    .line 268
    move-result v7

    .line 269
    if-nez v7, :cond_11

    .line 270
    .line 271
    goto/16 :goto_0

    .line 272
    .line 273
    :cond_11
    move v7, v15

    .line 274
    goto :goto_1

    .line 275
    :sswitch_12
    const-string v7, "rotationZ"

    .line 276
    .line 277
    invoke-virtual {v3, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 278
    .line 279
    .line 280
    move-result v7

    .line 281
    if-nez v7, :cond_12

    .line 282
    .line 283
    goto/16 :goto_0

    .line 284
    .line 285
    :cond_12
    move v7, v11

    .line 286
    goto :goto_1

    .line 287
    :sswitch_13
    const-string v7, "rotationY"

    .line 288
    .line 289
    invoke-virtual {v3, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 290
    .line 291
    .line 292
    move-result v7

    .line 293
    if-nez v7, :cond_13

    .line 294
    .line 295
    goto/16 :goto_0

    .line 296
    .line 297
    :cond_13
    move v7, v13

    .line 298
    goto :goto_1

    .line 299
    :sswitch_14
    const-string v7, "rotationX"

    .line 300
    .line 301
    invoke-virtual {v3, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 302
    .line 303
    .line 304
    move-result v7

    .line 305
    if-nez v7, :cond_14

    .line 306
    .line 307
    goto/16 :goto_0

    .line 308
    .line 309
    :cond_14
    const/4 v7, 0x3

    .line 310
    goto :goto_1

    .line 311
    :sswitch_15
    const-string v7, "custom"

    .line 312
    .line 313
    invoke-virtual {v3, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 314
    .line 315
    .line 316
    move-result v7

    .line 317
    if-nez v7, :cond_15

    .line 318
    .line 319
    goto/16 :goto_0

    .line 320
    .line 321
    :cond_15
    const/4 v7, 0x2

    .line 322
    goto :goto_1

    .line 323
    :sswitch_16
    const-string v7, "center"

    .line 324
    .line 325
    invoke-virtual {v3, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 326
    .line 327
    .line 328
    move-result v7

    .line 329
    if-nez v7, :cond_16

    .line 330
    .line 331
    goto/16 :goto_0

    .line 332
    .line 333
    :cond_16
    move v7, v12

    .line 334
    goto :goto_1

    .line 335
    :sswitch_17
    const-string v7, "centerVertically"

    .line 336
    .line 337
    invoke-virtual {v3, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 338
    .line 339
    .line 340
    move-result v7

    .line 341
    if-nez v7, :cond_17

    .line 342
    .line 343
    goto/16 :goto_0

    .line 344
    .line 345
    :cond_17
    move v7, v5

    .line 346
    :goto_1
    const-string v14, "parent"

    .line 347
    .line 348
    packed-switch v7, :pswitch_data_0

    .line 349
    .line 350
    .line 351
    invoke-static/range {p0 .. p4}, Lkp/b0;->e(Ld5/f;Le5/b;Le5/f;Ljava/lang/String;Lz4/q;)V

    .line 352
    .line 353
    .line 354
    return-void

    .line 355
    :pswitch_0
    invoke-virtual {v0, v3}, Ld5/b;->z(Ljava/lang/String;)Ljava/lang/String;

    .line 356
    .line 357
    .line 358
    move-result-object v0

    .line 359
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 360
    .line 361
    .line 362
    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

    .line 363
    .line 364
    .line 365
    move-result v2

    .line 366
    sparse-switch v2, :sswitch_data_1

    .line 367
    .line 368
    .line 369
    :goto_2
    move v14, v8

    .line 370
    goto :goto_3

    .line 371
    :sswitch_18
    const-string v2, "visible"

    .line 372
    .line 373
    invoke-virtual {v0, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 374
    .line 375
    .line 376
    move-result v0

    .line 377
    if-nez v0, :cond_18

    .line 378
    .line 379
    goto :goto_2

    .line 380
    :cond_18
    const/4 v14, 0x2

    .line 381
    goto :goto_3

    .line 382
    :sswitch_19
    const-string v2, "gone"

    .line 383
    .line 384
    invoke-virtual {v0, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 385
    .line 386
    .line 387
    move-result v0

    .line 388
    if-nez v0, :cond_19

    .line 389
    .line 390
    goto :goto_2

    .line 391
    :cond_19
    move v14, v12

    .line 392
    goto :goto_3

    .line 393
    :sswitch_1a
    const-string v2, "invisible"

    .line 394
    .line 395
    invoke-virtual {v0, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 396
    .line 397
    .line 398
    move-result v0

    .line 399
    if-nez v0, :cond_1a

    .line 400
    .line 401
    goto :goto_2

    .line 402
    :cond_1a
    move v14, v5

    .line 403
    :goto_3
    packed-switch v14, :pswitch_data_1

    .line 404
    .line 405
    .line 406
    goto/16 :goto_e

    .line 407
    .line 408
    :pswitch_1
    iput v5, v1, Le5/b;->I:I

    .line 409
    .line 410
    return-void

    .line 411
    :pswitch_2
    iput v10, v1, Le5/b;->I:I

    .line 412
    .line 413
    return-void

    .line 414
    :pswitch_3
    iput v13, v1, Le5/b;->I:I

    .line 415
    .line 416
    const/4 v0, 0x0

    .line 417
    iput v0, v1, Le5/b;->F:F

    .line 418
    .line 419
    return-void

    .line 420
    :pswitch_4
    invoke-virtual {v0, v3}, Ld5/b;->z(Ljava/lang/String;)Ljava/lang/String;

    .line 421
    .line 422
    .line 423
    move-result-object v0

    .line 424
    invoke-virtual {v0, v14}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 425
    .line 426
    .line 427
    move-result v2

    .line 428
    if-eqz v2, :cond_1b

    .line 429
    .line 430
    invoke-virtual {v4, v6}, Lz4/q;->b(Ljava/lang/Object;)Le5/b;

    .line 431
    .line 432
    .line 433
    move-result-object v0

    .line 434
    goto :goto_4

    .line 435
    :cond_1b
    invoke-virtual {v4, v0}, Lz4/q;->b(Ljava/lang/Object;)Le5/b;

    .line 436
    .line 437
    .line 438
    move-result-object v0

    .line 439
    :goto_4
    invoke-virtual {v1, v0}, Le5/b;->o(Ljava/lang/Object;)V

    .line 440
    .line 441
    .line 442
    invoke-virtual {v1, v0}, Le5/b;->i(Ljava/lang/Object;)V

    .line 443
    .line 444
    .line 445
    return-void

    .line 446
    :pswitch_5
    invoke-virtual {v0, v3}, Ld5/b;->s(Ljava/lang/String;)Ld5/c;

    .line 447
    .line 448
    .line 449
    move-result-object v0

    .line 450
    invoke-virtual {v2, v0}, Le5/f;->a(Ld5/c;)F

    .line 451
    .line 452
    .line 453
    move-result v0

    .line 454
    iput v0, v1, Le5/b;->f:F

    .line 455
    .line 456
    return-void

    .line 457
    :pswitch_6
    iget-object v2, v4, Lz4/q;->a:Lrx/b;

    .line 458
    .line 459
    invoke-static {v0, v3, v4, v2}, Lkp/b0;->f(Ld5/f;Ljava/lang/String;Lz4/q;Lrx/b;)Le5/g;

    .line 460
    .line 461
    .line 462
    move-result-object v0

    .line 463
    iput-object v0, v1, Le5/b;->d0:Le5/g;

    .line 464
    .line 465
    return-void

    .line 466
    :pswitch_7
    invoke-virtual {v0, v3}, Ld5/b;->s(Ljava/lang/String;)Ld5/c;

    .line 467
    .line 468
    .line 469
    move-result-object v0

    .line 470
    invoke-virtual {v2, v0}, Le5/f;->a(Ld5/c;)F

    .line 471
    .line 472
    .line 473
    move-result v0

    .line 474
    iput v0, v1, Le5/b;->i:F

    .line 475
    .line 476
    return-void

    .line 477
    :pswitch_8
    invoke-virtual {v0, v3}, Ld5/b;->s(Ljava/lang/String;)Ld5/c;

    .line 478
    .line 479
    .line 480
    move-result-object v0

    .line 481
    invoke-virtual {v2, v0}, Le5/f;->a(Ld5/c;)F

    .line 482
    .line 483
    .line 484
    move-result v0

    .line 485
    iput v0, v1, Le5/b;->h:F

    .line 486
    .line 487
    return-void

    .line 488
    :pswitch_9
    invoke-virtual {v0, v3}, Ld5/b;->s(Ljava/lang/String;)Ld5/c;

    .line 489
    .line 490
    .line 491
    move-result-object v0

    .line 492
    invoke-virtual {v2, v0}, Le5/f;->a(Ld5/c;)F

    .line 493
    .line 494
    .line 495
    move-result v0

    .line 496
    iput v0, v1, Le5/b;->F:F

    .line 497
    .line 498
    return-void

    .line 499
    :pswitch_a
    invoke-virtual {v0, v3}, Ld5/b;->s(Ljava/lang/String;)Ld5/c;

    .line 500
    .line 501
    .line 502
    move-result-object v0

    .line 503
    invoke-virtual {v2, v0}, Le5/f;->a(Ld5/c;)F

    .line 504
    .line 505
    .line 506
    move-result v0

    .line 507
    iput v0, v1, Le5/b;->g:F

    .line 508
    .line 509
    return-void

    .line 510
    :pswitch_b
    invoke-virtual {v0, v3}, Ld5/b;->s(Ljava/lang/String;)Ld5/c;

    .line 511
    .line 512
    .line 513
    move-result-object v0

    .line 514
    invoke-virtual {v2, v0}, Le5/f;->a(Ld5/c;)F

    .line 515
    .line 516
    .line 517
    move-result v0

    .line 518
    iget-boolean v2, v4, Lz4/q;->b:Z

    .line 519
    .line 520
    if-nez v2, :cond_1c

    .line 521
    .line 522
    const/high16 v2, 0x3f800000    # 1.0f

    .line 523
    .line 524
    sub-float v0, v2, v0

    .line 525
    .line 526
    :cond_1c
    iput v0, v1, Le5/b;->h:F

    .line 527
    .line 528
    return-void

    .line 529
    :pswitch_c
    invoke-virtual {v0, v3}, Ld5/b;->s(Ljava/lang/String;)Ld5/c;

    .line 530
    .line 531
    .line 532
    move-result-object v0

    .line 533
    invoke-virtual {v2, v0}, Le5/f;->a(Ld5/c;)F

    .line 534
    .line 535
    .line 536
    move-result v0

    .line 537
    iput v0, v1, Le5/b;->H:F

    .line 538
    .line 539
    return-void

    .line 540
    :pswitch_d
    invoke-virtual {v0, v3}, Ld5/b;->s(Ljava/lang/String;)Ld5/c;

    .line 541
    .line 542
    .line 543
    move-result-object v0

    .line 544
    invoke-virtual {v2, v0}, Le5/f;->a(Ld5/c;)F

    .line 545
    .line 546
    .line 547
    move-result v0

    .line 548
    iput v0, v1, Le5/b;->G:F

    .line 549
    .line 550
    return-void

    .line 551
    :pswitch_e
    invoke-virtual {v0, v3}, Ld5/b;->s(Ljava/lang/String;)Ld5/c;

    .line 552
    .line 553
    .line 554
    move-result-object v0

    .line 555
    invoke-virtual {v2, v0}, Le5/f;->a(Ld5/c;)F

    .line 556
    .line 557
    .line 558
    move-result v0

    .line 559
    iput v0, v1, Le5/b;->y:F

    .line 560
    .line 561
    return-void

    .line 562
    :pswitch_f
    invoke-virtual {v0, v3}, Ld5/b;->s(Ljava/lang/String;)Ld5/c;

    .line 563
    .line 564
    .line 565
    move-result-object v0

    .line 566
    invoke-virtual {v2, v0}, Le5/f;->a(Ld5/c;)F

    .line 567
    .line 568
    .line 569
    move-result v0

    .line 570
    iput v0, v1, Le5/b;->x:F

    .line 571
    .line 572
    return-void

    .line 573
    :pswitch_10
    invoke-virtual {v0, v3}, Ld5/b;->s(Ljava/lang/String;)Ld5/c;

    .line 574
    .line 575
    .line 576
    move-result-object v0

    .line 577
    instance-of v2, v0, Ld5/f;

    .line 578
    .line 579
    if-nez v2, :cond_1d

    .line 580
    .line 581
    goto/16 :goto_e

    .line 582
    .line 583
    :cond_1d
    check-cast v0, Ld5/f;

    .line 584
    .line 585
    new-instance v2, Lc5/b;

    .line 586
    .line 587
    invoke-direct {v2}, Ljava/lang/Object;-><init>()V

    .line 588
    .line 589
    .line 590
    new-array v3, v9, [I

    .line 591
    .line 592
    iput-object v3, v2, Lc5/b;->a:[I

    .line 593
    .line 594
    new-array v3, v9, [I

    .line 595
    .line 596
    iput-object v3, v2, Lc5/b;->b:[I

    .line 597
    .line 598
    iput v5, v2, Lc5/b;->c:I

    .line 599
    .line 600
    new-array v3, v9, [I

    .line 601
    .line 602
    iput-object v3, v2, Lc5/b;->d:[I

    .line 603
    .line 604
    new-array v3, v9, [F

    .line 605
    .line 606
    iput-object v3, v2, Lc5/b;->e:[F

    .line 607
    .line 608
    iput v5, v2, Lc5/b;->f:I

    .line 609
    .line 610
    new-array v3, v11, [I

    .line 611
    .line 612
    iput-object v3, v2, Lc5/b;->g:[I

    .line 613
    .line 614
    new-array v3, v11, [Ljava/lang/String;

    .line 615
    .line 616
    iput-object v3, v2, Lc5/b;->h:[Ljava/lang/String;

    .line 617
    .line 618
    iput v5, v2, Lc5/b;->i:I

    .line 619
    .line 620
    invoke-virtual {v0}, Ld5/b;->C()Ljava/util/ArrayList;

    .line 621
    .line 622
    .line 623
    move-result-object v3

    .line 624
    invoke-virtual {v3}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 625
    .line 626
    .line 627
    move-result-object v3

    .line 628
    :cond_1e
    :goto_5
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 629
    .line 630
    .line 631
    move-result v4

    .line 632
    if-eqz v4, :cond_2a

    .line 633
    .line 634
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 635
    .line 636
    .line 637
    move-result-object v4

    .line 638
    check-cast v4, Ljava/lang/String;

    .line 639
    .line 640
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 641
    .line 642
    .line 643
    invoke-virtual {v4}, Ljava/lang/String;->hashCode()I

    .line 644
    .line 645
    .line 646
    move-result v6

    .line 647
    sparse-switch v6, :sswitch_data_2

    .line 648
    .line 649
    .line 650
    :goto_6
    move v6, v8

    .line 651
    goto :goto_7

    .line 652
    :sswitch_1b
    const-string v6, "relativeTo"

    .line 653
    .line 654
    invoke-virtual {v4, v6}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 655
    .line 656
    .line 657
    move-result v6

    .line 658
    if-nez v6, :cond_1f

    .line 659
    .line 660
    goto :goto_6

    .line 661
    :cond_1f
    move v6, v13

    .line 662
    goto :goto_7

    .line 663
    :sswitch_1c
    const-string v6, "pathArc"

    .line 664
    .line 665
    invoke-virtual {v4, v6}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 666
    .line 667
    .line 668
    move-result v6

    .line 669
    if-nez v6, :cond_20

    .line 670
    .line 671
    goto :goto_6

    .line 672
    :cond_20
    const/4 v6, 0x3

    .line 673
    goto :goto_7

    .line 674
    :sswitch_1d
    const-string v6, "quantize"

    .line 675
    .line 676
    invoke-virtual {v4, v6}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 677
    .line 678
    .line 679
    move-result v6

    .line 680
    if-nez v6, :cond_21

    .line 681
    .line 682
    goto :goto_6

    .line 683
    :cond_21
    const/4 v6, 0x2

    .line 684
    goto :goto_7

    .line 685
    :sswitch_1e
    const-string v6, "easing"

    .line 686
    .line 687
    invoke-virtual {v4, v6}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 688
    .line 689
    .line 690
    move-result v6

    .line 691
    if-nez v6, :cond_22

    .line 692
    .line 693
    goto :goto_6

    .line 694
    :cond_22
    move v6, v12

    .line 695
    goto :goto_7

    .line 696
    :sswitch_1f
    const-string v6, "stagger"

    .line 697
    .line 698
    invoke-virtual {v4, v6}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 699
    .line 700
    .line 701
    move-result v6

    .line 702
    if-nez v6, :cond_23

    .line 703
    .line 704
    goto :goto_6

    .line 705
    :cond_23
    move v6, v5

    .line 706
    :goto_7
    packed-switch v6, :pswitch_data_2

    .line 707
    .line 708
    .line 709
    goto/16 :goto_a

    .line 710
    .line 711
    :pswitch_11
    const/16 v6, 0x25d

    .line 712
    .line 713
    invoke-virtual {v0, v4}, Ld5/b;->z(Ljava/lang/String;)Ljava/lang/String;

    .line 714
    .line 715
    .line 716
    move-result-object v4

    .line 717
    invoke-virtual {v2, v6, v4}, Lc5/b;->c(ILjava/lang/String;)V

    .line 718
    .line 719
    .line 720
    goto/16 :goto_a

    .line 721
    .line 722
    :pswitch_12
    invoke-virtual {v0, v4}, Ld5/b;->z(Ljava/lang/String;)Ljava/lang/String;

    .line 723
    .line 724
    .line 725
    move-result-object v4

    .line 726
    const-string v20, "below"

    .line 727
    .line 728
    const-string v21, "above"

    .line 729
    .line 730
    const-string v16, "none"

    .line 731
    .line 732
    const-string v17, "startVertical"

    .line 733
    .line 734
    const-string v18, "startHorizontal"

    .line 735
    .line 736
    const-string v19, "flip"

    .line 737
    .line 738
    filled-new-array/range {v16 .. v21}, [Ljava/lang/String;

    .line 739
    .line 740
    .line 741
    move-result-object v6

    .line 742
    move v7, v5

    .line 743
    :goto_8
    if-ge v7, v15, :cond_25

    .line 744
    .line 745
    aget-object v9, v6, v7

    .line 746
    .line 747
    invoke-virtual {v9, v4}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 748
    .line 749
    .line 750
    move-result v9

    .line 751
    if-eqz v9, :cond_24

    .line 752
    .line 753
    goto :goto_9

    .line 754
    :cond_24
    add-int/lit8 v7, v7, 0x1

    .line 755
    .line 756
    goto :goto_8

    .line 757
    :cond_25
    move v7, v8

    .line 758
    :goto_9
    if-ne v7, v8, :cond_26

    .line 759
    .line 760
    sget-object v6, Ljava/lang/System;->err:Ljava/io/PrintStream;

    .line 761
    .line 762
    new-instance v7, Ljava/lang/StringBuilder;

    .line 763
    .line 764
    const-string v9, "0 pathArc = \'"

    .line 765
    .line 766
    invoke-direct {v7, v9}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 767
    .line 768
    .line 769
    invoke-virtual {v7, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 770
    .line 771
    .line 772
    const-string v4, "\'"

    .line 773
    .line 774
    invoke-virtual {v7, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 775
    .line 776
    .line 777
    invoke-virtual {v7}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 778
    .line 779
    .line 780
    move-result-object v4

    .line 781
    invoke-virtual {v6, v4}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V

    .line 782
    .line 783
    .line 784
    goto :goto_a

    .line 785
    :cond_26
    const/16 v4, 0x25f

    .line 786
    .line 787
    invoke-virtual {v2, v4, v7}, Lc5/b;->b(II)V

    .line 788
    .line 789
    .line 790
    goto :goto_a

    .line 791
    :pswitch_13
    invoke-virtual {v0, v4}, Ld5/b;->s(Ljava/lang/String;)Ld5/c;

    .line 792
    .line 793
    .line 794
    move-result-object v6

    .line 795
    instance-of v7, v6, Ld5/a;

    .line 796
    .line 797
    const/16 v9, 0x262

    .line 798
    .line 799
    if-eqz v7, :cond_28

    .line 800
    .line 801
    check-cast v6, Ld5/a;

    .line 802
    .line 803
    iget-object v4, v6, Ld5/b;->h:Ljava/util/ArrayList;

    .line 804
    .line 805
    invoke-virtual {v4}, Ljava/util/ArrayList;->size()I

    .line 806
    .line 807
    .line 808
    move-result v4

    .line 809
    if-lez v4, :cond_27

    .line 810
    .line 811
    invoke-virtual {v6, v5}, Ld5/b;->v(I)I

    .line 812
    .line 813
    .line 814
    move-result v7

    .line 815
    invoke-virtual {v2, v9, v7}, Lc5/b;->b(II)V

    .line 816
    .line 817
    .line 818
    if-le v4, v12, :cond_27

    .line 819
    .line 820
    const/16 v7, 0x263

    .line 821
    .line 822
    invoke-virtual {v6, v12}, Ld5/b;->y(I)Ljava/lang/String;

    .line 823
    .line 824
    .line 825
    move-result-object v9

    .line 826
    invoke-virtual {v2, v7, v9}, Lc5/b;->c(ILjava/lang/String;)V

    .line 827
    .line 828
    .line 829
    const/4 v7, 0x2

    .line 830
    if-le v4, v7, :cond_1e

    .line 831
    .line 832
    const/16 v4, 0x25a

    .line 833
    .line 834
    invoke-virtual {v6, v7}, Ld5/b;->t(I)F

    .line 835
    .line 836
    .line 837
    move-result v6

    .line 838
    invoke-virtual {v2, v4, v6}, Lc5/b;->a(IF)V

    .line 839
    .line 840
    .line 841
    goto/16 :goto_5

    .line 842
    .line 843
    :cond_27
    :goto_a
    const/4 v7, 0x2

    .line 844
    goto/16 :goto_5

    .line 845
    .line 846
    :cond_28
    const/4 v7, 0x2

    .line 847
    invoke-virtual {v0, v4}, Ld5/b;->s(Ljava/lang/String;)Ld5/c;

    .line 848
    .line 849
    .line 850
    move-result-object v6

    .line 851
    if-eqz v6, :cond_29

    .line 852
    .line 853
    invoke-virtual {v6}, Ld5/c;->k()I

    .line 854
    .line 855
    .line 856
    move-result v4

    .line 857
    invoke-virtual {v2, v9, v4}, Lc5/b;->b(II)V

    .line 858
    .line 859
    .line 860
    goto/16 :goto_5

    .line 861
    .line 862
    :cond_29
    new-instance v1, Ld5/g;

    .line 863
    .line 864
    const-string v2, "no int found for key <"

    .line 865
    .line 866
    const-string v3, ">, found ["

    .line 867
    .line 868
    invoke-static {v2, v4, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->q(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 869
    .line 870
    .line 871
    move-result-object v2

    .line 872
    invoke-virtual {v6}, Ld5/c;->m()Ljava/lang/String;

    .line 873
    .line 874
    .line 875
    move-result-object v3

    .line 876
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 877
    .line 878
    .line 879
    const-string v3, "] : "

    .line 880
    .line 881
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 882
    .line 883
    .line 884
    invoke-virtual {v2, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 885
    .line 886
    .line 887
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 888
    .line 889
    .line 890
    move-result-object v2

    .line 891
    invoke-direct {v1, v2, v0}, Ld5/g;-><init>(Ljava/lang/String;Ld5/c;)V

    .line 892
    .line 893
    .line 894
    throw v1

    .line 895
    :pswitch_14
    const/4 v7, 0x2

    .line 896
    const/16 v6, 0x25b

    .line 897
    .line 898
    invoke-virtual {v0, v4}, Ld5/b;->z(Ljava/lang/String;)Ljava/lang/String;

    .line 899
    .line 900
    .line 901
    move-result-object v4

    .line 902
    invoke-virtual {v2, v6, v4}, Lc5/b;->c(ILjava/lang/String;)V

    .line 903
    .line 904
    .line 905
    goto/16 :goto_5

    .line 906
    .line 907
    :pswitch_15
    const/4 v7, 0x2

    .line 908
    const/16 v6, 0x258

    .line 909
    .line 910
    invoke-virtual {v0, v4}, Ld5/b;->u(Ljava/lang/String;)F

    .line 911
    .line 912
    .line 913
    move-result v4

    .line 914
    invoke-virtual {v2, v6, v4}, Lc5/b;->a(IF)V

    .line 915
    .line 916
    .line 917
    goto/16 :goto_5

    .line 918
    .line 919
    :cond_2a
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 920
    .line 921
    .line 922
    return-void

    .line 923
    :pswitch_16
    iget-object v2, v4, Lz4/q;->a:Lrx/b;

    .line 924
    .line 925
    invoke-static {v0, v3, v4, v2}, Lkp/b0;->f(Ld5/f;Ljava/lang/String;Lz4/q;Lrx/b;)Le5/g;

    .line 926
    .line 927
    .line 928
    move-result-object v0

    .line 929
    iput-object v0, v1, Le5/b;->e0:Le5/g;

    .line 930
    .line 931
    return-void

    .line 932
    :pswitch_17
    invoke-virtual {v0, v3}, Ld5/b;->s(Ljava/lang/String;)Ld5/c;

    .line 933
    .line 934
    .line 935
    move-result-object v0

    .line 936
    invoke-virtual {v2, v0}, Le5/f;->a(Ld5/c;)F

    .line 937
    .line 938
    .line 939
    move-result v0

    .line 940
    iget-object v2, v4, Lz4/q;->a:Lrx/b;

    .line 941
    .line 942
    invoke-virtual {v2, v0}, Lrx/b;->e(F)F

    .line 943
    .line 944
    .line 945
    move-result v0

    .line 946
    iput v0, v1, Le5/b;->E:F

    .line 947
    .line 948
    return-void

    .line 949
    :pswitch_18
    invoke-virtual {v0, v3}, Ld5/b;->s(Ljava/lang/String;)Ld5/c;

    .line 950
    .line 951
    .line 952
    move-result-object v0

    .line 953
    invoke-virtual {v2, v0}, Le5/f;->a(Ld5/c;)F

    .line 954
    .line 955
    .line 956
    move-result v0

    .line 957
    iget-object v2, v4, Lz4/q;->a:Lrx/b;

    .line 958
    .line 959
    invoke-virtual {v2, v0}, Lrx/b;->e(F)F

    .line 960
    .line 961
    .line 962
    move-result v0

    .line 963
    iput v0, v1, Le5/b;->D:F

    .line 964
    .line 965
    return-void

    .line 966
    :pswitch_19
    invoke-virtual {v0, v3}, Ld5/b;->s(Ljava/lang/String;)Ld5/c;

    .line 967
    .line 968
    .line 969
    move-result-object v0

    .line 970
    invoke-virtual {v2, v0}, Le5/f;->a(Ld5/c;)F

    .line 971
    .line 972
    .line 973
    move-result v0

    .line 974
    iget-object v2, v4, Lz4/q;->a:Lrx/b;

    .line 975
    .line 976
    invoke-virtual {v2, v0}, Lrx/b;->e(F)F

    .line 977
    .line 978
    .line 979
    move-result v0

    .line 980
    iput v0, v1, Le5/b;->C:F

    .line 981
    .line 982
    return-void

    .line 983
    :pswitch_1a
    invoke-virtual {v0, v3}, Ld5/b;->s(Ljava/lang/String;)Ld5/c;

    .line 984
    .line 985
    .line 986
    move-result-object v0

    .line 987
    invoke-virtual {v2, v0}, Le5/f;->a(Ld5/c;)F

    .line 988
    .line 989
    .line 990
    move-result v0

    .line 991
    iput v0, v1, Le5/b;->B:F

    .line 992
    .line 993
    return-void

    .line 994
    :pswitch_1b
    invoke-virtual {v0, v3}, Ld5/b;->s(Ljava/lang/String;)Ld5/c;

    .line 995
    .line 996
    .line 997
    move-result-object v0

    .line 998
    invoke-virtual {v2, v0}, Le5/f;->a(Ld5/c;)F

    .line 999
    .line 1000
    .line 1001
    move-result v0

    .line 1002
    iput v0, v1, Le5/b;->A:F

    .line 1003
    .line 1004
    return-void

    .line 1005
    :pswitch_1c
    invoke-virtual {v0, v3}, Ld5/b;->s(Ljava/lang/String;)Ld5/c;

    .line 1006
    .line 1007
    .line 1008
    move-result-object v0

    .line 1009
    invoke-virtual {v2, v0}, Le5/f;->a(Ld5/c;)F

    .line 1010
    .line 1011
    .line 1012
    move-result v0

    .line 1013
    iput v0, v1, Le5/b;->z:F

    .line 1014
    .line 1015
    return-void

    .line 1016
    :pswitch_1d
    invoke-virtual {v0, v3}, Ld5/b;->x(Ljava/lang/String;)Ld5/c;

    .line 1017
    .line 1018
    .line 1019
    move-result-object v0

    .line 1020
    instance-of v2, v0, Ld5/f;

    .line 1021
    .line 1022
    if-eqz v2, :cond_2b

    .line 1023
    .line 1024
    check-cast v0, Ld5/f;

    .line 1025
    .line 1026
    goto :goto_b

    .line 1027
    :cond_2b
    const/4 v0, 0x0

    .line 1028
    :goto_b
    if-nez v0, :cond_2c

    .line 1029
    .line 1030
    goto/16 :goto_e

    .line 1031
    .line 1032
    :cond_2c
    invoke-virtual {v0}, Ld5/b;->C()Ljava/util/ArrayList;

    .line 1033
    .line 1034
    .line 1035
    move-result-object v2

    .line 1036
    invoke-virtual {v2}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 1037
    .line 1038
    .line 1039
    move-result-object v2

    .line 1040
    :cond_2d
    :goto_c
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 1041
    .line 1042
    .line 1043
    move-result v3

    .line 1044
    if-eqz v3, :cond_33

    .line 1045
    .line 1046
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1047
    .line 1048
    .line 1049
    move-result-object v3

    .line 1050
    check-cast v3, Ljava/lang/String;

    .line 1051
    .line 1052
    invoke-virtual {v0, v3}, Ld5/b;->s(Ljava/lang/String;)Ld5/c;

    .line 1053
    .line 1054
    .line 1055
    move-result-object v4

    .line 1056
    instance-of v5, v4, Ld5/e;

    .line 1057
    .line 1058
    if-eqz v5, :cond_30

    .line 1059
    .line 1060
    invoke-virtual {v4}, Ld5/c;->i()F

    .line 1061
    .line 1062
    .line 1063
    move-result v4

    .line 1064
    iget-object v5, v1, Le5/b;->i0:Ljava/util/HashMap;

    .line 1065
    .line 1066
    if-nez v5, :cond_2e

    .line 1067
    .line 1068
    new-instance v5, Ljava/util/HashMap;

    .line 1069
    .line 1070
    invoke-direct {v5}, Ljava/util/HashMap;-><init>()V

    .line 1071
    .line 1072
    .line 1073
    iput-object v5, v1, Le5/b;->i0:Ljava/util/HashMap;

    .line 1074
    .line 1075
    :cond_2e
    iget-object v5, v1, Le5/b;->i0:Ljava/util/HashMap;

    .line 1076
    .line 1077
    invoke-static {v4}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 1078
    .line 1079
    .line 1080
    move-result-object v4

    .line 1081
    invoke-virtual {v5, v3, v4}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 1082
    .line 1083
    .line 1084
    :cond_2f
    const/16 v5, 0x10

    .line 1085
    .line 1086
    goto :goto_c

    .line 1087
    :cond_30
    instance-of v5, v4, Ld5/h;

    .line 1088
    .line 1089
    if-eqz v5, :cond_2f

    .line 1090
    .line 1091
    invoke-virtual {v4}, Ld5/c;->e()Ljava/lang/String;

    .line 1092
    .line 1093
    .line 1094
    move-result-object v4

    .line 1095
    const-string v5, "#"

    .line 1096
    .line 1097
    invoke-virtual {v4, v5}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    .line 1098
    .line 1099
    .line 1100
    move-result v5

    .line 1101
    const-wide/16 v6, -0x1

    .line 1102
    .line 1103
    if-eqz v5, :cond_32

    .line 1104
    .line 1105
    invoke-virtual {v4, v12}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    .line 1106
    .line 1107
    .line 1108
    move-result-object v4

    .line 1109
    invoke-virtual {v4}, Ljava/lang/String;->length()I

    .line 1110
    .line 1111
    .line 1112
    move-result v5

    .line 1113
    if-ne v5, v15, :cond_31

    .line 1114
    .line 1115
    const-string v5, "FF"

    .line 1116
    .line 1117
    invoke-virtual {v5, v4}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 1118
    .line 1119
    .line 1120
    move-result-object v4

    .line 1121
    :cond_31
    const/16 v5, 0x10

    .line 1122
    .line 1123
    invoke-static {v4, v5}, Ljava/lang/Long;->parseLong(Ljava/lang/String;I)J

    .line 1124
    .line 1125
    .line 1126
    move-result-wide v8

    .line 1127
    goto :goto_d

    .line 1128
    :cond_32
    const/16 v5, 0x10

    .line 1129
    .line 1130
    move-wide v8, v6

    .line 1131
    :goto_d
    cmp-long v4, v8, v6

    .line 1132
    .line 1133
    if-eqz v4, :cond_2d

    .line 1134
    .line 1135
    long-to-int v4, v8

    .line 1136
    iget-object v6, v1, Le5/b;->h0:Ljava/util/HashMap;

    .line 1137
    .line 1138
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1139
    .line 1140
    .line 1141
    move-result-object v4

    .line 1142
    invoke-virtual {v6, v3, v4}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 1143
    .line 1144
    .line 1145
    goto :goto_c

    .line 1146
    :cond_33
    :goto_e
    return-void

    .line 1147
    :pswitch_1e
    invoke-virtual {v0, v3}, Ld5/b;->z(Ljava/lang/String;)Ljava/lang/String;

    .line 1148
    .line 1149
    .line 1150
    move-result-object v0

    .line 1151
    invoke-virtual {v0, v14}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1152
    .line 1153
    .line 1154
    move-result v2

    .line 1155
    if-eqz v2, :cond_34

    .line 1156
    .line 1157
    invoke-virtual {v4, v6}, Lz4/q;->b(Ljava/lang/Object;)Le5/b;

    .line 1158
    .line 1159
    .line 1160
    move-result-object v0

    .line 1161
    goto :goto_f

    .line 1162
    :cond_34
    invoke-virtual {v4, v0}, Lz4/q;->b(Ljava/lang/Object;)Le5/b;

    .line 1163
    .line 1164
    .line 1165
    move-result-object v0

    .line 1166
    :goto_f
    invoke-virtual {v1, v0}, Le5/b;->o(Ljava/lang/Object;)V

    .line 1167
    .line 1168
    .line 1169
    invoke-virtual {v1, v0}, Le5/b;->i(Ljava/lang/Object;)V

    .line 1170
    .line 1171
    .line 1172
    invoke-virtual {v1, v0}, Le5/b;->p(Ljava/lang/Object;)V

    .line 1173
    .line 1174
    .line 1175
    invoke-virtual {v1, v0}, Le5/b;->e(Ljava/lang/Object;)V

    .line 1176
    .line 1177
    .line 1178
    return-void

    .line 1179
    :pswitch_1f
    invoke-virtual {v0, v3}, Ld5/b;->z(Ljava/lang/String;)Ljava/lang/String;

    .line 1180
    .line 1181
    .line 1182
    move-result-object v0

    .line 1183
    invoke-virtual {v0, v14}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1184
    .line 1185
    .line 1186
    move-result v2

    .line 1187
    if-eqz v2, :cond_35

    .line 1188
    .line 1189
    invoke-virtual {v4, v6}, Lz4/q;->b(Ljava/lang/Object;)Le5/b;

    .line 1190
    .line 1191
    .line 1192
    move-result-object v0

    .line 1193
    goto :goto_10

    .line 1194
    :cond_35
    invoke-virtual {v4, v0}, Lz4/q;->b(Ljava/lang/Object;)Le5/b;

    .line 1195
    .line 1196
    .line 1197
    move-result-object v0

    .line 1198
    :goto_10
    invoke-virtual {v1, v0}, Le5/b;->p(Ljava/lang/Object;)V

    .line 1199
    .line 1200
    .line 1201
    invoke-virtual {v1, v0}, Le5/b;->e(Ljava/lang/Object;)V

    .line 1202
    .line 1203
    .line 1204
    return-void

    .line 1205
    :sswitch_data_0
    .sparse-switch
        -0x565a8e48 -> :sswitch_17
        -0x514d33ab -> :sswitch_16
        -0x5069748f -> :sswitch_15
        -0x4a771f66 -> :sswitch_14
        -0x4a771f65 -> :sswitch_13
        -0x4a771f64 -> :sswitch_12
        -0x490b9c39 -> :sswitch_11
        -0x490b9c38 -> :sswitch_10
        -0x490b9c37 -> :sswitch_f
        -0x48c76ed9 -> :sswitch_e
        -0x3fad404a -> :sswitch_d
        -0x3ae243aa -> :sswitch_c
        -0x3ae243a9 -> :sswitch_b
        -0x3621dfb2 -> :sswitch_a
        -0x3621dfb1 -> :sswitch_9
        -0xec32145 -> :sswitch_8
        -0x3aa8172 -> :sswitch_7
        0x589b15e -> :sswitch_6
        0x5d92341 -> :sswitch_5
        0x69e6c4f -> :sswitch_4
        0x6be2dc6 -> :sswitch_3
        0x17be4100 -> :sswitch_2
        0x53b069a6 -> :sswitch_1
        0x73b66312 -> :sswitch_0
    .end sparse-switch

    .line 1206
    .line 1207
    .line 1208
    .line 1209
    .line 1210
    .line 1211
    .line 1212
    .line 1213
    .line 1214
    .line 1215
    .line 1216
    .line 1217
    .line 1218
    .line 1219
    .line 1220
    .line 1221
    .line 1222
    .line 1223
    .line 1224
    .line 1225
    .line 1226
    .line 1227
    .line 1228
    .line 1229
    .line 1230
    .line 1231
    .line 1232
    .line 1233
    .line 1234
    .line 1235
    .line 1236
    .line 1237
    .line 1238
    .line 1239
    .line 1240
    .line 1241
    .line 1242
    .line 1243
    .line 1244
    .line 1245
    .line 1246
    .line 1247
    .line 1248
    .line 1249
    .line 1250
    .line 1251
    .line 1252
    .line 1253
    .line 1254
    .line 1255
    .line 1256
    .line 1257
    .line 1258
    .line 1259
    .line 1260
    .line 1261
    .line 1262
    .line 1263
    .line 1264
    .line 1265
    .line 1266
    .line 1267
    .line 1268
    .line 1269
    .line 1270
    .line 1271
    .line 1272
    .line 1273
    .line 1274
    .line 1275
    .line 1276
    .line 1277
    .line 1278
    .line 1279
    .line 1280
    .line 1281
    .line 1282
    .line 1283
    .line 1284
    .line 1285
    .line 1286
    .line 1287
    .line 1288
    .line 1289
    .line 1290
    .line 1291
    .line 1292
    .line 1293
    .line 1294
    .line 1295
    .line 1296
    .line 1297
    .line 1298
    .line 1299
    .line 1300
    .line 1301
    .line 1302
    .line 1303
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1f
        :pswitch_1e
        :pswitch_1d
        :pswitch_1c
        :pswitch_1b
        :pswitch_1a
        :pswitch_19
        :pswitch_18
        :pswitch_17
        :pswitch_16
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_0
    .end packed-switch

    .line 1304
    .line 1305
    .line 1306
    .line 1307
    .line 1308
    .line 1309
    .line 1310
    .line 1311
    .line 1312
    .line 1313
    .line 1314
    .line 1315
    .line 1316
    .line 1317
    .line 1318
    .line 1319
    .line 1320
    .line 1321
    .line 1322
    .line 1323
    .line 1324
    .line 1325
    .line 1326
    .line 1327
    .line 1328
    .line 1329
    .line 1330
    .line 1331
    .line 1332
    .line 1333
    .line 1334
    .line 1335
    .line 1336
    .line 1337
    .line 1338
    .line 1339
    .line 1340
    .line 1341
    .line 1342
    .line 1343
    .line 1344
    .line 1345
    .line 1346
    .line 1347
    .line 1348
    .line 1349
    .line 1350
    .line 1351
    .line 1352
    .line 1353
    .line 1354
    .line 1355
    :sswitch_data_1
    .sparse-switch
        -0x715b4053 -> :sswitch_1a
        0x30809f -> :sswitch_19
        0x1bd1f072 -> :sswitch_18
    .end sparse-switch

    .line 1356
    .line 1357
    .line 1358
    .line 1359
    .line 1360
    .line 1361
    .line 1362
    .line 1363
    .line 1364
    .line 1365
    .line 1366
    .line 1367
    .line 1368
    .line 1369
    :pswitch_data_1
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
    .end packed-switch

    .line 1370
    .line 1371
    .line 1372
    .line 1373
    .line 1374
    .line 1375
    .line 1376
    .line 1377
    .line 1378
    .line 1379
    :sswitch_data_2
    .sparse-switch
        -0x7119f053 -> :sswitch_1f
        -0x4e19c2d5 -> :sswitch_1e
        -0x4c979acf -> :sswitch_1d
        -0x2f2d1013 -> :sswitch_1c
        -0xe1f7d99 -> :sswitch_1b
    .end sparse-switch

    .line 1380
    .line 1381
    .line 1382
    .line 1383
    .line 1384
    .line 1385
    .line 1386
    .line 1387
    .line 1388
    .line 1389
    .line 1390
    .line 1391
    .line 1392
    .line 1393
    .line 1394
    .line 1395
    .line 1396
    .line 1397
    .line 1398
    .line 1399
    .line 1400
    .line 1401
    :pswitch_data_2
    .packed-switch 0x0
        :pswitch_15
        :pswitch_14
        :pswitch_13
        :pswitch_12
        :pswitch_11
    .end packed-switch
.end method

.method public static d(ILz4/q;Le5/f;Ld5/a;)V
    .locals 6

    .line 1
    const/4 v0, 0x2

    .line 2
    const/4 v1, 0x1

    .line 3
    if-nez p0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p1, v1}, Lz4/q;->e(I)Le5/h;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Lf5/h;

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    invoke-virtual {p1, v0}, Lz4/q;->e(I)Le5/h;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    check-cast p0, Lf5/i;

    .line 17
    .line 18
    :goto_0
    invoke-virtual {p3, v1}, Ld5/b;->r(I)Ld5/c;

    .line 19
    .line 20
    .line 21
    move-result-object v2

    .line 22
    instance-of v3, v2, Ld5/a;

    .line 23
    .line 24
    if-eqz v3, :cond_8

    .line 25
    .line 26
    check-cast v2, Ld5/a;

    .line 27
    .line 28
    iget-object v3, v2, Ld5/b;->h:Ljava/util/ArrayList;

    .line 29
    .line 30
    invoke-virtual {v3}, Ljava/util/ArrayList;->size()I

    .line 31
    .line 32
    .line 33
    move-result v3

    .line 34
    if-ge v3, v1, :cond_1

    .line 35
    .line 36
    goto/16 :goto_4

    .line 37
    .line 38
    :cond_1
    const/4 v3, 0x0

    .line 39
    move v4, v3

    .line 40
    :goto_1
    iget-object v5, v2, Ld5/b;->h:Ljava/util/ArrayList;

    .line 41
    .line 42
    invoke-virtual {v5}, Ljava/util/ArrayList;->size()I

    .line 43
    .line 44
    .line 45
    move-result v5

    .line 46
    if-ge v4, v5, :cond_2

    .line 47
    .line 48
    invoke-virtual {v2, v4}, Ld5/b;->y(I)Ljava/lang/String;

    .line 49
    .line 50
    .line 51
    move-result-object v5

    .line 52
    filled-new-array {v5}, [Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object v5

    .line 56
    invoke-virtual {p0, v5}, Le5/h;->q([Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    add-int/lit8 v4, v4, 0x1

    .line 60
    .line 61
    goto :goto_1

    .line 62
    :cond_2
    iget-object v2, p3, Ld5/b;->h:Ljava/util/ArrayList;

    .line 63
    .line 64
    invoke-virtual {v2}, Ljava/util/ArrayList;->size()I

    .line 65
    .line 66
    .line 67
    move-result v2

    .line 68
    if-le v2, v0, :cond_8

    .line 69
    .line 70
    invoke-virtual {p3, v0}, Ld5/b;->r(I)Ld5/c;

    .line 71
    .line 72
    .line 73
    move-result-object p3

    .line 74
    instance-of v0, p3, Ld5/f;

    .line 75
    .line 76
    if-nez v0, :cond_3

    .line 77
    .line 78
    goto :goto_4

    .line 79
    :cond_3
    check-cast p3, Ld5/f;

    .line 80
    .line 81
    invoke-virtual {p3}, Ld5/b;->C()Ljava/util/ArrayList;

    .line 82
    .line 83
    .line 84
    move-result-object v0

    .line 85
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 86
    .line 87
    .line 88
    move-result-object v0

    .line 89
    :goto_2
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 90
    .line 91
    .line 92
    move-result v2

    .line 93
    if-eqz v2, :cond_8

    .line 94
    .line 95
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 96
    .line 97
    .line 98
    move-result-object v2

    .line 99
    check-cast v2, Ljava/lang/String;

    .line 100
    .line 101
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 102
    .line 103
    .line 104
    const-string v4, "style"

    .line 105
    .line 106
    invoke-virtual {v2, v4}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 107
    .line 108
    .line 109
    move-result v4

    .line 110
    if-nez v4, :cond_4

    .line 111
    .line 112
    invoke-static {p3, p0, p2, v2, p1}, Lkp/b0;->e(Ld5/f;Le5/b;Le5/f;Ljava/lang/String;Lz4/q;)V

    .line 113
    .line 114
    .line 115
    goto :goto_2

    .line 116
    :cond_4
    invoke-virtual {p3, v2}, Ld5/b;->s(Ljava/lang/String;)Ld5/c;

    .line 117
    .line 118
    .line 119
    move-result-object v2

    .line 120
    instance-of v4, v2, Ld5/a;

    .line 121
    .line 122
    if-eqz v4, :cond_5

    .line 123
    .line 124
    move-object v4, v2

    .line 125
    check-cast v4, Ld5/a;

    .line 126
    .line 127
    iget-object v5, v4, Ld5/b;->h:Ljava/util/ArrayList;

    .line 128
    .line 129
    invoke-virtual {v5}, Ljava/util/ArrayList;->size()I

    .line 130
    .line 131
    .line 132
    move-result v5

    .line 133
    if-le v5, v1, :cond_5

    .line 134
    .line 135
    invoke-virtual {v4, v3}, Ld5/b;->y(I)Ljava/lang/String;

    .line 136
    .line 137
    .line 138
    move-result-object v2

    .line 139
    invoke-virtual {v4, v1}, Ld5/b;->t(I)F

    .line 140
    .line 141
    .line 142
    move-result v4

    .line 143
    iput v4, p0, Lf5/c;->n0:F

    .line 144
    .line 145
    goto :goto_3

    .line 146
    :cond_5
    invoke-virtual {v2}, Ld5/c;->e()Ljava/lang/String;

    .line 147
    .line 148
    .line 149
    move-result-object v2

    .line 150
    :goto_3
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 151
    .line 152
    .line 153
    const-string v4, "packed"

    .line 154
    .line 155
    invoke-virtual {v2, v4}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 156
    .line 157
    .line 158
    move-result v4

    .line 159
    if-nez v4, :cond_7

    .line 160
    .line 161
    const-string v4, "spread_inside"

    .line 162
    .line 163
    invoke-virtual {v2, v4}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 164
    .line 165
    .line 166
    move-result v2

    .line 167
    if-nez v2, :cond_6

    .line 168
    .line 169
    sget-object v2, Le5/j;->d:Le5/j;

    .line 170
    .line 171
    iput-object v2, p0, Lf5/c;->t0:Le5/j;

    .line 172
    .line 173
    goto :goto_2

    .line 174
    :cond_6
    sget-object v2, Le5/j;->e:Le5/j;

    .line 175
    .line 176
    iput-object v2, p0, Lf5/c;->t0:Le5/j;

    .line 177
    .line 178
    goto :goto_2

    .line 179
    :cond_7
    sget-object v2, Le5/j;->f:Le5/j;

    .line 180
    .line 181
    iput-object v2, p0, Lf5/c;->t0:Le5/j;

    .line 182
    .line 183
    goto :goto_2

    .line 184
    :cond_8
    :goto_4
    return-void
.end method

.method public static e(Ld5/f;Le5/b;Le5/f;Ljava/lang/String;Lz4/q;)V
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v2, p2

    .line 6
    .line 7
    move-object/from16 v3, p3

    .line 8
    .line 9
    move-object/from16 v4, p4

    .line 10
    .line 11
    const/4 v5, 0x0

    .line 12
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 13
    .line 14
    .line 15
    move-result-object v6

    .line 16
    iget-boolean v7, v4, Lz4/q;->b:Z

    .line 17
    .line 18
    invoke-virtual {v0, v3}, Ld5/b;->x(Ljava/lang/String;)Ld5/c;

    .line 19
    .line 20
    .line 21
    move-result-object v8

    .line 22
    instance-of v9, v8, Ld5/a;

    .line 23
    .line 24
    if-eqz v9, :cond_0

    .line 25
    .line 26
    check-cast v8, Ld5/a;

    .line 27
    .line 28
    goto :goto_0

    .line 29
    :cond_0
    const/4 v8, 0x0

    .line 30
    :goto_0
    const-string v9, "start"

    .line 31
    .line 32
    const-string v11, "end"

    .line 33
    .line 34
    const-string v12, "top"

    .line 35
    .line 36
    const-string v13, "bottom"

    .line 37
    .line 38
    const-string v14, "baseline"

    .line 39
    .line 40
    const-string v15, "parent"

    .line 41
    .line 42
    const/4 v10, 0x1

    .line 43
    if-eqz v8, :cond_1e

    .line 44
    .line 45
    iget-object v5, v8, Ld5/b;->h:Ljava/util/ArrayList;

    .line 46
    .line 47
    invoke-virtual {v5}, Ljava/util/ArrayList;->size()I

    .line 48
    .line 49
    .line 50
    move-result v5

    .line 51
    if-le v5, v10, :cond_1e

    .line 52
    .line 53
    const/4 v5, 0x0

    .line 54
    invoke-virtual {v8, v5}, Ld5/b;->y(I)Ljava/lang/String;

    .line 55
    .line 56
    .line 57
    move-result-object v0

    .line 58
    invoke-virtual {v8, v10}, Ld5/b;->w(I)Ld5/c;

    .line 59
    .line 60
    .line 61
    move-result-object v5

    .line 62
    instance-of v10, v5, Ld5/h;

    .line 63
    .line 64
    if-eqz v10, :cond_1

    .line 65
    .line 66
    invoke-virtual {v5}, Ld5/c;->e()Ljava/lang/String;

    .line 67
    .line 68
    .line 69
    move-result-object v10

    .line 70
    goto :goto_1

    .line 71
    :cond_1
    const/4 v10, 0x0

    .line 72
    :goto_1
    iget-object v5, v8, Ld5/b;->h:Ljava/util/ArrayList;

    .line 73
    .line 74
    invoke-virtual {v5}, Ljava/util/ArrayList;->size()I

    .line 75
    .line 76
    .line 77
    move-result v5

    .line 78
    const/16 v16, 0x0

    .line 79
    .line 80
    move/from16 v17, v7

    .line 81
    .line 82
    const/4 v7, 0x2

    .line 83
    if-le v5, v7, :cond_2

    .line 84
    .line 85
    invoke-virtual {v8, v7}, Ld5/b;->w(I)Ld5/c;

    .line 86
    .line 87
    .line 88
    move-result-object v5

    .line 89
    invoke-virtual {v2, v5}, Le5/f;->a(Ld5/c;)F

    .line 90
    .line 91
    .line 92
    move-result v5

    .line 93
    iget-object v7, v4, Lz4/q;->a:Lrx/b;

    .line 94
    .line 95
    invoke-virtual {v7, v5}, Lrx/b;->e(F)F

    .line 96
    .line 97
    .line 98
    move-result v5

    .line 99
    goto :goto_2

    .line 100
    :cond_2
    move/from16 v5, v16

    .line 101
    .line 102
    :goto_2
    iget-object v7, v8, Ld5/b;->h:Ljava/util/ArrayList;

    .line 103
    .line 104
    invoke-virtual {v7}, Ljava/util/ArrayList;->size()I

    .line 105
    .line 106
    .line 107
    move-result v7

    .line 108
    move/from16 p0, v5

    .line 109
    .line 110
    const/4 v5, 0x3

    .line 111
    if-le v7, v5, :cond_3

    .line 112
    .line 113
    invoke-virtual {v8, v5}, Ld5/b;->w(I)Ld5/c;

    .line 114
    .line 115
    .line 116
    move-result-object v7

    .line 117
    invoke-virtual {v2, v7}, Le5/f;->a(Ld5/c;)F

    .line 118
    .line 119
    .line 120
    move-result v5

    .line 121
    iget-object v7, v4, Lz4/q;->a:Lrx/b;

    .line 122
    .line 123
    invoke-virtual {v7, v5}, Lrx/b;->e(F)F

    .line 124
    .line 125
    .line 126
    move-result v5

    .line 127
    goto :goto_3

    .line 128
    :cond_3
    move/from16 v5, v16

    .line 129
    .line 130
    :goto_3
    invoke-virtual {v0, v15}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 131
    .line 132
    .line 133
    move-result v7

    .line 134
    if-eqz v7, :cond_4

    .line 135
    .line 136
    invoke-virtual {v4, v6}, Lz4/q;->b(Ljava/lang/Object;)Le5/b;

    .line 137
    .line 138
    .line 139
    move-result-object v0

    .line 140
    goto :goto_4

    .line 141
    :cond_4
    invoke-virtual {v4, v0}, Lz4/q;->b(Ljava/lang/Object;)Le5/b;

    .line 142
    .line 143
    .line 144
    move-result-object v0

    .line 145
    :goto_4
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 146
    .line 147
    .line 148
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 149
    .line 150
    .line 151
    move-result v6

    .line 152
    const-string v7, "right"

    .line 153
    .line 154
    sparse-switch v6, :sswitch_data_0

    .line 155
    .line 156
    .line 157
    :goto_5
    const/4 v3, -0x1

    .line 158
    goto :goto_6

    .line 159
    :sswitch_0
    invoke-virtual {v3, v9}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 160
    .line 161
    .line 162
    move-result v3

    .line 163
    if-nez v3, :cond_5

    .line 164
    .line 165
    goto :goto_5

    .line 166
    :cond_5
    const/4 v3, 0x7

    .line 167
    goto :goto_6

    .line 168
    :sswitch_1
    invoke-virtual {v3, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 169
    .line 170
    .line 171
    move-result v3

    .line 172
    if-nez v3, :cond_6

    .line 173
    .line 174
    goto :goto_5

    .line 175
    :cond_6
    const/4 v3, 0x6

    .line 176
    goto :goto_6

    .line 177
    :sswitch_2
    const-string v6, "left"

    .line 178
    .line 179
    invoke-virtual {v3, v6}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 180
    .line 181
    .line 182
    move-result v3

    .line 183
    if-nez v3, :cond_7

    .line 184
    .line 185
    goto :goto_5

    .line 186
    :cond_7
    const/4 v3, 0x5

    .line 187
    goto :goto_6

    .line 188
    :sswitch_3
    invoke-virtual {v3, v12}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 189
    .line 190
    .line 191
    move-result v3

    .line 192
    if-nez v3, :cond_8

    .line 193
    .line 194
    goto :goto_5

    .line 195
    :cond_8
    const/4 v3, 0x4

    .line 196
    goto :goto_6

    .line 197
    :sswitch_4
    invoke-virtual {v3, v11}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 198
    .line 199
    .line 200
    move-result v3

    .line 201
    if-nez v3, :cond_9

    .line 202
    .line 203
    goto :goto_5

    .line 204
    :cond_9
    const/4 v3, 0x3

    .line 205
    goto :goto_6

    .line 206
    :sswitch_5
    invoke-virtual {v3, v13}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 207
    .line 208
    .line 209
    move-result v3

    .line 210
    if-nez v3, :cond_a

    .line 211
    .line 212
    goto :goto_5

    .line 213
    :cond_a
    const/4 v3, 0x2

    .line 214
    goto :goto_6

    .line 215
    :sswitch_6
    const-string v6, "circular"

    .line 216
    .line 217
    invoke-virtual {v3, v6}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 218
    .line 219
    .line 220
    move-result v3

    .line 221
    if-nez v3, :cond_b

    .line 222
    .line 223
    goto :goto_5

    .line 224
    :cond_b
    const/4 v3, 0x1

    .line 225
    goto :goto_6

    .line 226
    :sswitch_7
    invoke-virtual {v3, v14}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 227
    .line 228
    .line 229
    move-result v3

    .line 230
    if-nez v3, :cond_c

    .line 231
    .line 232
    goto :goto_5

    .line 233
    :cond_c
    const/4 v3, 0x0

    .line 234
    :goto_6
    packed-switch v3, :pswitch_data_0

    .line 235
    .line 236
    .line 237
    goto/16 :goto_f

    .line 238
    .line 239
    :pswitch_0
    move/from16 v3, v17

    .line 240
    .line 241
    :goto_7
    const/4 v2, 0x1

    .line 242
    goto/16 :goto_10

    .line 243
    .line 244
    :pswitch_1
    const/4 v2, 0x1

    .line 245
    const/4 v3, 0x0

    .line 246
    goto/16 :goto_10

    .line 247
    .line 248
    :pswitch_2
    const/4 v2, 0x1

    .line 249
    :goto_8
    const/4 v3, 0x1

    .line 250
    goto/16 :goto_10

    .line 251
    .line 252
    :pswitch_3
    invoke-virtual {v10}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 253
    .line 254
    .line 255
    invoke-virtual {v10}, Ljava/lang/String;->hashCode()I

    .line 256
    .line 257
    .line 258
    move-result v2

    .line 259
    sparse-switch v2, :sswitch_data_1

    .line 260
    .line 261
    .line 262
    :goto_9
    const/4 v2, -0x1

    .line 263
    goto :goto_a

    .line 264
    :sswitch_8
    invoke-virtual {v10, v12}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 265
    .line 266
    .line 267
    move-result v2

    .line 268
    if-nez v2, :cond_d

    .line 269
    .line 270
    goto :goto_9

    .line 271
    :cond_d
    const/4 v2, 0x2

    .line 272
    goto :goto_a

    .line 273
    :sswitch_9
    invoke-virtual {v10, v13}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 274
    .line 275
    .line 276
    move-result v2

    .line 277
    if-nez v2, :cond_e

    .line 278
    .line 279
    goto :goto_9

    .line 280
    :cond_e
    const/4 v2, 0x1

    .line 281
    goto :goto_a

    .line 282
    :sswitch_a
    invoke-virtual {v10, v14}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 283
    .line 284
    .line 285
    move-result v2

    .line 286
    if-nez v2, :cond_f

    .line 287
    .line 288
    goto :goto_9

    .line 289
    :cond_f
    const/4 v2, 0x0

    .line 290
    :goto_a
    packed-switch v2, :pswitch_data_1

    .line 291
    .line 292
    .line 293
    goto/16 :goto_f

    .line 294
    .line 295
    :pswitch_4
    invoke-virtual {v1, v0}, Le5/b;->p(Ljava/lang/Object;)V

    .line 296
    .line 297
    .line 298
    goto/16 :goto_f

    .line 299
    .line 300
    :pswitch_5
    const/16 v2, 0xa

    .line 301
    .line 302
    iput v2, v1, Le5/b;->j0:I

    .line 303
    .line 304
    iput-object v0, v1, Le5/b;->S:Ljava/lang/Object;

    .line 305
    .line 306
    goto/16 :goto_f

    .line 307
    .line 308
    :pswitch_6
    iget-object v2, v0, Le5/b;->a:Ljava/lang/Object;

    .line 309
    .line 310
    invoke-virtual {v4, v2}, Lz4/q;->a(Ljava/lang/Object;)V

    .line 311
    .line 312
    .line 313
    const/16 v2, 0xb

    .line 314
    .line 315
    iput v2, v1, Le5/b;->j0:I

    .line 316
    .line 317
    iput-object v0, v1, Le5/b;->T:Le5/b;

    .line 318
    .line 319
    goto/16 :goto_f

    .line 320
    .line 321
    :pswitch_7
    xor-int/lit8 v2, v17, 0x1

    .line 322
    .line 323
    move v3, v2

    .line 324
    goto :goto_7

    .line 325
    :pswitch_8
    invoke-virtual {v10}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 326
    .line 327
    .line 328
    invoke-virtual {v10}, Ljava/lang/String;->hashCode()I

    .line 329
    .line 330
    .line 331
    move-result v2

    .line 332
    sparse-switch v2, :sswitch_data_2

    .line 333
    .line 334
    .line 335
    :goto_b
    const/4 v2, -0x1

    .line 336
    goto :goto_c

    .line 337
    :sswitch_b
    invoke-virtual {v10, v12}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 338
    .line 339
    .line 340
    move-result v2

    .line 341
    if-nez v2, :cond_10

    .line 342
    .line 343
    goto :goto_b

    .line 344
    :cond_10
    const/4 v2, 0x2

    .line 345
    goto :goto_c

    .line 346
    :sswitch_c
    invoke-virtual {v10, v13}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 347
    .line 348
    .line 349
    move-result v2

    .line 350
    if-nez v2, :cond_11

    .line 351
    .line 352
    goto :goto_b

    .line 353
    :cond_11
    const/4 v2, 0x1

    .line 354
    goto :goto_c

    .line 355
    :sswitch_d
    invoke-virtual {v10, v14}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 356
    .line 357
    .line 358
    move-result v2

    .line 359
    if-nez v2, :cond_12

    .line 360
    .line 361
    goto :goto_b

    .line 362
    :cond_12
    const/4 v2, 0x0

    .line 363
    :goto_c
    packed-switch v2, :pswitch_data_2

    .line 364
    .line 365
    .line 366
    goto/16 :goto_f

    .line 367
    .line 368
    :pswitch_9
    const/16 v2, 0xc

    .line 369
    .line 370
    iput v2, v1, Le5/b;->j0:I

    .line 371
    .line 372
    iput-object v0, v1, Le5/b;->U:Ljava/lang/Object;

    .line 373
    .line 374
    goto/16 :goto_f

    .line 375
    .line 376
    :pswitch_a
    invoke-virtual {v1, v0}, Le5/b;->e(Ljava/lang/Object;)V

    .line 377
    .line 378
    .line 379
    goto/16 :goto_f

    .line 380
    .line 381
    :pswitch_b
    iget-object v2, v0, Le5/b;->a:Ljava/lang/Object;

    .line 382
    .line 383
    invoke-virtual {v4, v2}, Lz4/q;->a(Ljava/lang/Object;)V

    .line 384
    .line 385
    .line 386
    const/16 v2, 0xe

    .line 387
    .line 388
    iput v2, v1, Le5/b;->j0:I

    .line 389
    .line 390
    iput-object v0, v1, Le5/b;->W:Le5/b;

    .line 391
    .line 392
    goto/16 :goto_f

    .line 393
    .line 394
    :pswitch_c
    const/4 v3, 0x1

    .line 395
    invoke-virtual {v8, v3}, Ld5/b;->r(I)Ld5/c;

    .line 396
    .line 397
    .line 398
    move-result-object v6

    .line 399
    invoke-virtual {v2, v6}, Le5/f;->a(Ld5/c;)F

    .line 400
    .line 401
    .line 402
    move-result v3

    .line 403
    iget-object v6, v8, Ld5/b;->h:Ljava/util/ArrayList;

    .line 404
    .line 405
    invoke-virtual {v6}, Ljava/util/ArrayList;->size()I

    .line 406
    .line 407
    .line 408
    move-result v6

    .line 409
    const/4 v12, 0x2

    .line 410
    if-le v6, v12, :cond_13

    .line 411
    .line 412
    invoke-virtual {v8, v12}, Ld5/b;->w(I)Ld5/c;

    .line 413
    .line 414
    .line 415
    move-result-object v6

    .line 416
    invoke-virtual {v2, v6}, Le5/f;->a(Ld5/c;)F

    .line 417
    .line 418
    .line 419
    move-result v2

    .line 420
    iget-object v4, v4, Lz4/q;->a:Lrx/b;

    .line 421
    .line 422
    invoke-virtual {v4, v2}, Lrx/b;->e(F)F

    .line 423
    .line 424
    .line 425
    move-result v16

    .line 426
    :cond_13
    move/from16 v2, v16

    .line 427
    .line 428
    invoke-virtual {v1, v0}, Le5/b;->j(Ljava/lang/Object;)Ljava/lang/Object;

    .line 429
    .line 430
    .line 431
    move-result-object v4

    .line 432
    iput-object v4, v1, Le5/b;->a0:Ljava/lang/Object;

    .line 433
    .line 434
    iput v3, v1, Le5/b;->b0:F

    .line 435
    .line 436
    iput v2, v1, Le5/b;->c0:F

    .line 437
    .line 438
    const/16 v2, 0x14

    .line 439
    .line 440
    iput v2, v1, Le5/b;->j0:I

    .line 441
    .line 442
    goto :goto_f

    .line 443
    :pswitch_d
    invoke-virtual {v10}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 444
    .line 445
    .line 446
    invoke-virtual {v10}, Ljava/lang/String;->hashCode()I

    .line 447
    .line 448
    .line 449
    move-result v2

    .line 450
    sparse-switch v2, :sswitch_data_3

    .line 451
    .line 452
    .line 453
    :goto_d
    const/4 v2, -0x1

    .line 454
    goto :goto_e

    .line 455
    :sswitch_e
    invoke-virtual {v10, v12}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 456
    .line 457
    .line 458
    move-result v2

    .line 459
    if-nez v2, :cond_14

    .line 460
    .line 461
    goto :goto_d

    .line 462
    :cond_14
    const/4 v2, 0x2

    .line 463
    goto :goto_e

    .line 464
    :sswitch_f
    invoke-virtual {v10, v13}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 465
    .line 466
    .line 467
    move-result v2

    .line 468
    if-nez v2, :cond_15

    .line 469
    .line 470
    goto :goto_d

    .line 471
    :cond_15
    const/4 v2, 0x1

    .line 472
    goto :goto_e

    .line 473
    :sswitch_10
    invoke-virtual {v10, v14}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 474
    .line 475
    .line 476
    move-result v2

    .line 477
    if-nez v2, :cond_16

    .line 478
    .line 479
    goto :goto_d

    .line 480
    :cond_16
    const/4 v2, 0x0

    .line 481
    :goto_e
    packed-switch v2, :pswitch_data_3

    .line 482
    .line 483
    .line 484
    goto :goto_f

    .line 485
    :pswitch_e
    iget-object v2, v1, Le5/b;->a:Ljava/lang/Object;

    .line 486
    .line 487
    invoke-virtual {v4, v2}, Lz4/q;->a(Ljava/lang/Object;)V

    .line 488
    .line 489
    .line 490
    const/16 v2, 0x10

    .line 491
    .line 492
    iput v2, v1, Le5/b;->j0:I

    .line 493
    .line 494
    iput-object v0, v1, Le5/b;->Y:Ljava/lang/Object;

    .line 495
    .line 496
    goto :goto_f

    .line 497
    :pswitch_f
    iget-object v2, v1, Le5/b;->a:Ljava/lang/Object;

    .line 498
    .line 499
    invoke-virtual {v4, v2}, Lz4/q;->a(Ljava/lang/Object;)V

    .line 500
    .line 501
    .line 502
    const/16 v2, 0x11

    .line 503
    .line 504
    iput v2, v1, Le5/b;->j0:I

    .line 505
    .line 506
    iput-object v0, v1, Le5/b;->Z:Ljava/lang/Object;

    .line 507
    .line 508
    goto :goto_f

    .line 509
    :pswitch_10
    iget-object v2, v1, Le5/b;->a:Ljava/lang/Object;

    .line 510
    .line 511
    invoke-virtual {v4, v2}, Lz4/q;->a(Ljava/lang/Object;)V

    .line 512
    .line 513
    .line 514
    iget-object v2, v0, Le5/b;->a:Ljava/lang/Object;

    .line 515
    .line 516
    invoke-virtual {v4, v2}, Lz4/q;->a(Ljava/lang/Object;)V

    .line 517
    .line 518
    .line 519
    const/16 v2, 0xf

    .line 520
    .line 521
    iput v2, v1, Le5/b;->j0:I

    .line 522
    .line 523
    iput-object v0, v1, Le5/b;->X:Ljava/lang/Object;

    .line 524
    .line 525
    :goto_f
    const/4 v2, 0x0

    .line 526
    goto/16 :goto_8

    .line 527
    .line 528
    :goto_10
    if-eqz v2, :cond_1d

    .line 529
    .line 530
    invoke-virtual {v10}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 531
    .line 532
    .line 533
    invoke-virtual {v10}, Ljava/lang/String;->hashCode()I

    .line 534
    .line 535
    .line 536
    move-result v2

    .line 537
    sparse-switch v2, :sswitch_data_4

    .line 538
    .line 539
    .line 540
    :goto_11
    const/4 v15, -0x1

    .line 541
    goto :goto_12

    .line 542
    :sswitch_11
    invoke-virtual {v10, v9}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 543
    .line 544
    .line 545
    move-result v2

    .line 546
    if-nez v2, :cond_17

    .line 547
    .line 548
    goto :goto_11

    .line 549
    :cond_17
    const/4 v15, 0x2

    .line 550
    goto :goto_12

    .line 551
    :sswitch_12
    invoke-virtual {v10, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 552
    .line 553
    .line 554
    move-result v2

    .line 555
    if-nez v2, :cond_18

    .line 556
    .line 557
    goto :goto_11

    .line 558
    :cond_18
    const/4 v15, 0x1

    .line 559
    goto :goto_12

    .line 560
    :sswitch_13
    invoke-virtual {v10, v11}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 561
    .line 562
    .line 563
    move-result v2

    .line 564
    if-nez v2, :cond_19

    .line 565
    .line 566
    goto :goto_11

    .line 567
    :cond_19
    const/4 v15, 0x0

    .line 568
    :goto_12
    packed-switch v15, :pswitch_data_4

    .line 569
    .line 570
    .line 571
    const/4 v2, 0x1

    .line 572
    goto :goto_13

    .line 573
    :pswitch_11
    move/from16 v2, v17

    .line 574
    .line 575
    goto :goto_13

    .line 576
    :pswitch_12
    const/4 v2, 0x0

    .line 577
    goto :goto_13

    .line 578
    :pswitch_13
    xor-int/lit8 v2, v17, 0x1

    .line 579
    .line 580
    :goto_13
    if-eqz v3, :cond_1b

    .line 581
    .line 582
    if-eqz v2, :cond_1a

    .line 583
    .line 584
    const/4 v3, 0x1

    .line 585
    iput v3, v1, Le5/b;->j0:I

    .line 586
    .line 587
    iput-object v0, v1, Le5/b;->J:Ljava/lang/Object;

    .line 588
    .line 589
    goto :goto_14

    .line 590
    :cond_1a
    const/4 v7, 0x2

    .line 591
    iput v7, v1, Le5/b;->j0:I

    .line 592
    .line 593
    iput-object v0, v1, Le5/b;->K:Ljava/lang/Object;

    .line 594
    .line 595
    goto :goto_14

    .line 596
    :cond_1b
    if-eqz v2, :cond_1c

    .line 597
    .line 598
    const/4 v2, 0x3

    .line 599
    iput v2, v1, Le5/b;->j0:I

    .line 600
    .line 601
    iput-object v0, v1, Le5/b;->L:Ljava/lang/Object;

    .line 602
    .line 603
    goto :goto_14

    .line 604
    :cond_1c
    const/4 v2, 0x4

    .line 605
    iput v2, v1, Le5/b;->j0:I

    .line 606
    .line 607
    iput-object v0, v1, Le5/b;->M:Ljava/lang/Object;

    .line 608
    .line 609
    :cond_1d
    :goto_14
    invoke-static/range {p0 .. p0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 610
    .line 611
    .line 612
    move-result-object v0

    .line 613
    invoke-virtual {v1, v0}, Le5/b;->l(Ljava/lang/Float;)Le5/b;

    .line 614
    .line 615
    .line 616
    move-result-object v0

    .line 617
    invoke-static {v5}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 618
    .line 619
    .line 620
    move-result-object v1

    .line 621
    invoke-virtual {v0, v1}, Le5/b;->n(Ljava/lang/Float;)V

    .line 622
    .line 623
    .line 624
    return-void

    .line 625
    :cond_1e
    move/from16 v17, v7

    .line 626
    .line 627
    const/4 v2, 0x3

    .line 628
    const/4 v7, 0x2

    .line 629
    invoke-virtual {v0, v3}, Ld5/b;->A(Ljava/lang/String;)Ljava/lang/String;

    .line 630
    .line 631
    .line 632
    move-result-object v0

    .line 633
    if-eqz v0, :cond_27

    .line 634
    .line 635
    invoke-virtual {v0, v15}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 636
    .line 637
    .line 638
    move-result v5

    .line 639
    if-eqz v5, :cond_1f

    .line 640
    .line 641
    invoke-virtual {v4, v6}, Lz4/q;->b(Ljava/lang/Object;)Le5/b;

    .line 642
    .line 643
    .line 644
    move-result-object v0

    .line 645
    goto :goto_15

    .line 646
    :cond_1f
    invoke-virtual {v4, v0}, Lz4/q;->b(Ljava/lang/Object;)Le5/b;

    .line 647
    .line 648
    .line 649
    move-result-object v0

    .line 650
    :goto_15
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 651
    .line 652
    .line 653
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 654
    .line 655
    .line 656
    move-result v5

    .line 657
    sparse-switch v5, :sswitch_data_5

    .line 658
    .line 659
    .line 660
    :goto_16
    const/4 v5, -0x1

    .line 661
    goto :goto_17

    .line 662
    :sswitch_14
    invoke-virtual {v3, v9}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 663
    .line 664
    .line 665
    move-result v2

    .line 666
    if-nez v2, :cond_20

    .line 667
    .line 668
    goto :goto_16

    .line 669
    :cond_20
    const/4 v5, 0x4

    .line 670
    goto :goto_17

    .line 671
    :sswitch_15
    invoke-virtual {v3, v12}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 672
    .line 673
    .line 674
    move-result v3

    .line 675
    if-nez v3, :cond_21

    .line 676
    .line 677
    goto :goto_16

    .line 678
    :cond_21
    move v5, v2

    .line 679
    goto :goto_17

    .line 680
    :sswitch_16
    invoke-virtual {v3, v11}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 681
    .line 682
    .line 683
    move-result v2

    .line 684
    if-nez v2, :cond_22

    .line 685
    .line 686
    goto :goto_16

    .line 687
    :cond_22
    move v5, v7

    .line 688
    goto :goto_17

    .line 689
    :sswitch_17
    invoke-virtual {v3, v13}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 690
    .line 691
    .line 692
    move-result v2

    .line 693
    if-nez v2, :cond_23

    .line 694
    .line 695
    goto :goto_16

    .line 696
    :cond_23
    const/4 v5, 0x1

    .line 697
    goto :goto_17

    .line 698
    :sswitch_18
    invoke-virtual {v3, v14}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 699
    .line 700
    .line 701
    move-result v2

    .line 702
    if-nez v2, :cond_24

    .line 703
    .line 704
    goto :goto_16

    .line 705
    :cond_24
    const/4 v5, 0x0

    .line 706
    :goto_17
    packed-switch v5, :pswitch_data_5

    .line 707
    .line 708
    .line 709
    goto :goto_18

    .line 710
    :pswitch_14
    if-eqz v17, :cond_25

    .line 711
    .line 712
    const/4 v3, 0x1

    .line 713
    iput v3, v1, Le5/b;->j0:I

    .line 714
    .line 715
    iput-object v0, v1, Le5/b;->J:Ljava/lang/Object;

    .line 716
    .line 717
    return-void

    .line 718
    :cond_25
    const/4 v2, 0x4

    .line 719
    iput v2, v1, Le5/b;->j0:I

    .line 720
    .line 721
    iput-object v0, v1, Le5/b;->M:Ljava/lang/Object;

    .line 722
    .line 723
    return-void

    .line 724
    :pswitch_15
    invoke-virtual {v1, v0}, Le5/b;->p(Ljava/lang/Object;)V

    .line 725
    .line 726
    .line 727
    return-void

    .line 728
    :pswitch_16
    const/4 v2, 0x4

    .line 729
    if-eqz v17, :cond_26

    .line 730
    .line 731
    iput v2, v1, Le5/b;->j0:I

    .line 732
    .line 733
    iput-object v0, v1, Le5/b;->M:Ljava/lang/Object;

    .line 734
    .line 735
    return-void

    .line 736
    :cond_26
    const/4 v3, 0x1

    .line 737
    iput v3, v1, Le5/b;->j0:I

    .line 738
    .line 739
    iput-object v0, v1, Le5/b;->J:Ljava/lang/Object;

    .line 740
    .line 741
    return-void

    .line 742
    :pswitch_17
    invoke-virtual {v1, v0}, Le5/b;->e(Ljava/lang/Object;)V

    .line 743
    .line 744
    .line 745
    return-void

    .line 746
    :pswitch_18
    iget-object v2, v1, Le5/b;->a:Ljava/lang/Object;

    .line 747
    .line 748
    invoke-virtual {v4, v2}, Lz4/q;->a(Ljava/lang/Object;)V

    .line 749
    .line 750
    .line 751
    iget-object v2, v0, Le5/b;->a:Ljava/lang/Object;

    .line 752
    .line 753
    invoke-virtual {v4, v2}, Lz4/q;->a(Ljava/lang/Object;)V

    .line 754
    .line 755
    .line 756
    const/16 v2, 0xf

    .line 757
    .line 758
    iput v2, v1, Le5/b;->j0:I

    .line 759
    .line 760
    iput-object v0, v1, Le5/b;->X:Ljava/lang/Object;

    .line 761
    .line 762
    :cond_27
    :goto_18
    return-void

    .line 763
    :sswitch_data_0
    .sparse-switch
        -0x669119bb -> :sswitch_7
        -0x594af961 -> :sswitch_6
        -0x527265d5 -> :sswitch_5
        0x188db -> :sswitch_4
        0x1c155 -> :sswitch_3
        0x32a007 -> :sswitch_2
        0x677c21c -> :sswitch_1
        0x68ac462 -> :sswitch_0
    .end sparse-switch

    .line 764
    .line 765
    .line 766
    .line 767
    .line 768
    .line 769
    .line 770
    .line 771
    .line 772
    .line 773
    .line 774
    .line 775
    .line 776
    .line 777
    .line 778
    .line 779
    .line 780
    .line 781
    .line 782
    .line 783
    .line 784
    .line 785
    .line 786
    .line 787
    .line 788
    .line 789
    .line 790
    .line 791
    .line 792
    .line 793
    .line 794
    .line 795
    .line 796
    .line 797
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_d
        :pswitch_c
        :pswitch_8
        :pswitch_7
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch

    .line 798
    .line 799
    .line 800
    .line 801
    .line 802
    .line 803
    .line 804
    .line 805
    .line 806
    .line 807
    .line 808
    .line 809
    .line 810
    .line 811
    .line 812
    .line 813
    .line 814
    .line 815
    .line 816
    .line 817
    :sswitch_data_1
    .sparse-switch
        -0x669119bb -> :sswitch_a
        -0x527265d5 -> :sswitch_9
        0x1c155 -> :sswitch_8
    .end sparse-switch

    .line 818
    .line 819
    .line 820
    .line 821
    .line 822
    .line 823
    .line 824
    .line 825
    .line 826
    .line 827
    .line 828
    .line 829
    .line 830
    .line 831
    :pswitch_data_1
    .packed-switch 0x0
        :pswitch_6
        :pswitch_5
        :pswitch_4
    .end packed-switch

    .line 832
    .line 833
    .line 834
    .line 835
    .line 836
    .line 837
    .line 838
    .line 839
    .line 840
    .line 841
    :sswitch_data_2
    .sparse-switch
        -0x669119bb -> :sswitch_d
        -0x527265d5 -> :sswitch_c
        0x1c155 -> :sswitch_b
    .end sparse-switch

    .line 842
    .line 843
    .line 844
    .line 845
    .line 846
    .line 847
    .line 848
    .line 849
    .line 850
    .line 851
    .line 852
    .line 853
    .line 854
    .line 855
    :pswitch_data_2
    .packed-switch 0x0
        :pswitch_b
        :pswitch_a
        :pswitch_9
    .end packed-switch

    .line 856
    .line 857
    .line 858
    .line 859
    .line 860
    .line 861
    .line 862
    .line 863
    .line 864
    .line 865
    :sswitch_data_3
    .sparse-switch
        -0x669119bb -> :sswitch_10
        -0x527265d5 -> :sswitch_f
        0x1c155 -> :sswitch_e
    .end sparse-switch

    .line 866
    .line 867
    .line 868
    .line 869
    .line 870
    .line 871
    .line 872
    .line 873
    .line 874
    .line 875
    .line 876
    .line 877
    .line 878
    .line 879
    :pswitch_data_3
    .packed-switch 0x0
        :pswitch_10
        :pswitch_f
        :pswitch_e
    .end packed-switch

    .line 880
    .line 881
    .line 882
    .line 883
    .line 884
    .line 885
    .line 886
    .line 887
    .line 888
    .line 889
    :sswitch_data_4
    .sparse-switch
        0x188db -> :sswitch_13
        0x677c21c -> :sswitch_12
        0x68ac462 -> :sswitch_11
    .end sparse-switch

    .line 890
    .line 891
    .line 892
    .line 893
    .line 894
    .line 895
    .line 896
    .line 897
    .line 898
    .line 899
    .line 900
    .line 901
    .line 902
    .line 903
    :pswitch_data_4
    .packed-switch 0x0
        :pswitch_13
        :pswitch_12
        :pswitch_11
    .end packed-switch

    .line 904
    .line 905
    .line 906
    .line 907
    .line 908
    .line 909
    .line 910
    .line 911
    .line 912
    .line 913
    :sswitch_data_5
    .sparse-switch
        -0x669119bb -> :sswitch_18
        -0x527265d5 -> :sswitch_17
        0x188db -> :sswitch_16
        0x1c155 -> :sswitch_15
        0x68ac462 -> :sswitch_14
    .end sparse-switch

    .line 914
    .line 915
    .line 916
    .line 917
    .line 918
    .line 919
    .line 920
    .line 921
    .line 922
    .line 923
    .line 924
    .line 925
    .line 926
    .line 927
    .line 928
    .line 929
    .line 930
    .line 931
    .line 932
    .line 933
    .line 934
    .line 935
    :pswitch_data_5
    .packed-switch 0x0
        :pswitch_18
        :pswitch_17
        :pswitch_16
        :pswitch_15
        :pswitch_14
    .end packed-switch
.end method

.method public static f(Ld5/f;Ljava/lang/String;Lz4/q;Lrx/b;)Le5/g;
    .locals 3

    .line 1
    invoke-virtual {p0, p1}, Ld5/b;->s(Ljava/lang/String;)Ld5/c;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    const/4 v1, 0x0

    .line 6
    invoke-static {v1}, Le5/g;->b(I)Le5/g;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    instance-of v2, v0, Ld5/h;

    .line 11
    .line 12
    if-eqz v2, :cond_0

    .line 13
    .line 14
    invoke-virtual {v0}, Ld5/c;->e()Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    invoke-static {p0}, Lkp/b0;->g(Ljava/lang/String;)Le5/g;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :cond_0
    instance-of v2, v0, Ld5/e;

    .line 24
    .line 25
    if-eqz v2, :cond_1

    .line 26
    .line 27
    invoke-virtual {p0, p1}, Ld5/b;->u(Ljava/lang/String;)F

    .line 28
    .line 29
    .line 30
    move-result p0

    .line 31
    invoke-virtual {p3, p0}, Lrx/b;->e(F)F

    .line 32
    .line 33
    .line 34
    move-result p0

    .line 35
    invoke-static {p0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    invoke-virtual {p2, p0}, Lz4/q;->c(Ljava/lang/Float;)I

    .line 40
    .line 41
    .line 42
    move-result p0

    .line 43
    invoke-static {p0}, Le5/g;->b(I)Le5/g;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    return-object p0

    .line 48
    :cond_1
    instance-of p0, v0, Ld5/f;

    .line 49
    .line 50
    if-eqz p0, :cond_6

    .line 51
    .line 52
    check-cast v0, Ld5/f;

    .line 53
    .line 54
    const-string p0, "value"

    .line 55
    .line 56
    invoke-virtual {v0, p0}, Ld5/b;->A(Ljava/lang/String;)Ljava/lang/String;

    .line 57
    .line 58
    .line 59
    move-result-object p0

    .line 60
    if-eqz p0, :cond_2

    .line 61
    .line 62
    invoke-static {p0}, Lkp/b0;->g(Ljava/lang/String;)Le5/g;

    .line 63
    .line 64
    .line 65
    move-result-object v1

    .line 66
    :cond_2
    const-string p0, "min"

    .line 67
    .line 68
    invoke-virtual {v0, p0}, Ld5/b;->x(Ljava/lang/String;)Ld5/c;

    .line 69
    .line 70
    .line 71
    move-result-object p0

    .line 72
    if-eqz p0, :cond_4

    .line 73
    .line 74
    instance-of p1, p0, Ld5/e;

    .line 75
    .line 76
    if-eqz p1, :cond_3

    .line 77
    .line 78
    check-cast p0, Ld5/e;

    .line 79
    .line 80
    invoke-virtual {p0}, Ld5/e;->i()F

    .line 81
    .line 82
    .line 83
    move-result p0

    .line 84
    invoke-virtual {p3, p0}, Lrx/b;->e(F)F

    .line 85
    .line 86
    .line 87
    move-result p0

    .line 88
    invoke-static {p0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 89
    .line 90
    .line 91
    move-result-object p0

    .line 92
    invoke-virtual {p2, p0}, Lz4/q;->c(Ljava/lang/Float;)I

    .line 93
    .line 94
    .line 95
    move-result p0

    .line 96
    if-ltz p0, :cond_4

    .line 97
    .line 98
    iput p0, v1, Le5/g;->a:I

    .line 99
    .line 100
    goto :goto_0

    .line 101
    :cond_3
    instance-of p0, p0, Ld5/h;

    .line 102
    .line 103
    if-eqz p0, :cond_4

    .line 104
    .line 105
    const/4 p0, -0x2

    .line 106
    iput p0, v1, Le5/g;->a:I

    .line 107
    .line 108
    :cond_4
    :goto_0
    const-string p0, "max"

    .line 109
    .line 110
    invoke-virtual {v0, p0}, Ld5/b;->x(Ljava/lang/String;)Ld5/c;

    .line 111
    .line 112
    .line 113
    move-result-object p0

    .line 114
    if-eqz p0, :cond_6

    .line 115
    .line 116
    instance-of p1, p0, Ld5/e;

    .line 117
    .line 118
    if-eqz p1, :cond_5

    .line 119
    .line 120
    check-cast p0, Ld5/e;

    .line 121
    .line 122
    invoke-virtual {p0}, Ld5/e;->i()F

    .line 123
    .line 124
    .line 125
    move-result p0

    .line 126
    invoke-virtual {p3, p0}, Lrx/b;->e(F)F

    .line 127
    .line 128
    .line 129
    move-result p0

    .line 130
    invoke-static {p0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 131
    .line 132
    .line 133
    move-result-object p0

    .line 134
    invoke-virtual {p2, p0}, Lz4/q;->c(Ljava/lang/Float;)I

    .line 135
    .line 136
    .line 137
    move-result p0

    .line 138
    iget p1, v1, Le5/g;->b:I

    .line 139
    .line 140
    if-ltz p1, :cond_6

    .line 141
    .line 142
    iput p0, v1, Le5/g;->b:I

    .line 143
    .line 144
    return-object v1

    .line 145
    :cond_5
    instance-of p0, p0, Ld5/h;

    .line 146
    .line 147
    if-eqz p0, :cond_6

    .line 148
    .line 149
    iget-boolean p0, v1, Le5/g;->g:Z

    .line 150
    .line 151
    if-eqz p0, :cond_6

    .line 152
    .line 153
    sget-object p0, Le5/g;->i:Ljava/lang/String;

    .line 154
    .line 155
    iput-object p0, v1, Le5/g;->f:Ljava/lang/String;

    .line 156
    .line 157
    const p0, 0x7fffffff

    .line 158
    .line 159
    .line 160
    iput p0, v1, Le5/g;->b:I

    .line 161
    .line 162
    :cond_6
    return-object v1
.end method

.method public static g(Ljava/lang/String;)Le5/g;
    .locals 6

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-static {v0}, Le5/g;->b(I)Le5/g;

    .line 3
    .line 4
    .line 5
    move-result-object v1

    .line 6
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 7
    .line 8
    .line 9
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 10
    .line 11
    .line 12
    move-result v2

    .line 13
    const/4 v3, 0x1

    .line 14
    const/4 v4, -0x1

    .line 15
    sparse-switch v2, :sswitch_data_0

    .line 16
    .line 17
    .line 18
    goto :goto_0

    .line 19
    :sswitch_0
    const-string v2, "wrap"

    .line 20
    .line 21
    invoke-virtual {p0, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    move-result v2

    .line 25
    if-nez v2, :cond_0

    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_0
    const/4 v4, 0x3

    .line 29
    goto :goto_0

    .line 30
    :sswitch_1
    const-string v2, "spread"

    .line 31
    .line 32
    invoke-virtual {p0, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 33
    .line 34
    .line 35
    move-result v2

    .line 36
    if-nez v2, :cond_1

    .line 37
    .line 38
    goto :goto_0

    .line 39
    :cond_1
    const/4 v4, 0x2

    .line 40
    goto :goto_0

    .line 41
    :sswitch_2
    const-string v2, "parent"

    .line 42
    .line 43
    invoke-virtual {p0, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 44
    .line 45
    .line 46
    move-result v2

    .line 47
    if-nez v2, :cond_2

    .line 48
    .line 49
    goto :goto_0

    .line 50
    :cond_2
    move v4, v3

    .line 51
    goto :goto_0

    .line 52
    :sswitch_3
    const-string v2, "preferWrap"

    .line 53
    .line 54
    invoke-virtual {p0, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 55
    .line 56
    .line 57
    move-result v2

    .line 58
    if-nez v2, :cond_3

    .line 59
    .line 60
    goto :goto_0

    .line 61
    :cond_3
    move v4, v0

    .line 62
    :goto_0
    sget-object v2, Le5/g;->i:Ljava/lang/String;

    .line 63
    .line 64
    sget-object v5, Le5/g;->j:Ljava/lang/String;

    .line 65
    .line 66
    packed-switch v4, :pswitch_data_0

    .line 67
    .line 68
    .line 69
    const-string v2, "%"

    .line 70
    .line 71
    invoke-virtual {p0, v2}, Ljava/lang/String;->endsWith(Ljava/lang/String;)Z

    .line 72
    .line 73
    .line 74
    move-result v2

    .line 75
    if-eqz v2, :cond_4

    .line 76
    .line 77
    const/16 v1, 0x25

    .line 78
    .line 79
    invoke-virtual {p0, v1}, Ljava/lang/String;->indexOf(I)I

    .line 80
    .line 81
    .line 82
    move-result v1

    .line 83
    invoke-virtual {p0, v0, v1}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 84
    .line 85
    .line 86
    move-result-object p0

    .line 87
    invoke-static {p0}, Ljava/lang/Float;->parseFloat(Ljava/lang/String;)F

    .line 88
    .line 89
    .line 90
    move-result p0

    .line 91
    const/high16 v1, 0x42c80000    # 100.0f

    .line 92
    .line 93
    div-float/2addr p0, v1

    .line 94
    new-instance v1, Le5/g;

    .line 95
    .line 96
    sget-object v2, Le5/g;->l:Ljava/lang/String;

    .line 97
    .line 98
    invoke-direct {v1, v2}, Le5/g;-><init>(Ljava/lang/String;)V

    .line 99
    .line 100
    .line 101
    iput p0, v1, Le5/g;->c:F

    .line 102
    .line 103
    iput-boolean v3, v1, Le5/g;->g:Z

    .line 104
    .line 105
    iput v0, v1, Le5/g;->b:I

    .line 106
    .line 107
    return-object v1

    .line 108
    :cond_4
    const-string v0, ":"

    .line 109
    .line 110
    invoke-virtual {p0, v0}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    .line 111
    .line 112
    .line 113
    move-result v0

    .line 114
    if-eqz v0, :cond_5

    .line 115
    .line 116
    new-instance v0, Le5/g;

    .line 117
    .line 118
    sget-object v1, Le5/g;->m:Ljava/lang/String;

    .line 119
    .line 120
    invoke-direct {v0, v1}, Le5/g;-><init>(Ljava/lang/String;)V

    .line 121
    .line 122
    .line 123
    iput-object p0, v0, Le5/g;->e:Ljava/lang/String;

    .line 124
    .line 125
    iput-object v5, v0, Le5/g;->f:Ljava/lang/String;

    .line 126
    .line 127
    iput-boolean v3, v0, Le5/g;->g:Z

    .line 128
    .line 129
    return-object v0

    .line 130
    :cond_5
    return-object v1

    .line 131
    :pswitch_0
    new-instance p0, Le5/g;

    .line 132
    .line 133
    invoke-direct {p0, v2}, Le5/g;-><init>(Ljava/lang/String;)V

    .line 134
    .line 135
    .line 136
    return-object p0

    .line 137
    :pswitch_1
    invoke-static {v5}, Le5/g;->c(Ljava/lang/String;)Le5/g;

    .line 138
    .line 139
    .line 140
    move-result-object p0

    .line 141
    return-object p0

    .line 142
    :pswitch_2
    new-instance p0, Le5/g;

    .line 143
    .line 144
    sget-object v0, Le5/g;->k:Ljava/lang/String;

    .line 145
    .line 146
    invoke-direct {p0, v0}, Le5/g;-><init>(Ljava/lang/String;)V

    .line 147
    .line 148
    .line 149
    return-object p0

    .line 150
    :pswitch_3
    invoke-static {v2}, Le5/g;->c(Ljava/lang/String;)Le5/g;

    .line 151
    .line 152
    .line 153
    move-result-object p0

    .line 154
    return-object p0

    .line 155
    :sswitch_data_0
    .sparse-switch
        -0x57099186 -> :sswitch_3
        -0x3b54f756 -> :sswitch_2
        -0x35630e8d -> :sswitch_1
        0x37d04a -> :sswitch_0
    .end sparse-switch

    .line 156
    .line 157
    .line 158
    .line 159
    .line 160
    .line 161
    .line 162
    .line 163
    .line 164
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public static h(ILz4/q;Ljava/lang/String;Ld5/f;)V
    .locals 17

    .line 1
    move-object/from16 v0, p1

    .line 2
    .line 3
    move-object/from16 v1, p2

    .line 4
    .line 5
    move-object/from16 v2, p3

    .line 6
    .line 7
    invoke-virtual {v2}, Ld5/b;->C()Ljava/util/ArrayList;

    .line 8
    .line 9
    .line 10
    move-result-object v3

    .line 11
    invoke-virtual/range {p1 .. p2}, Lz4/q;->b(Ljava/lang/Object;)Le5/b;

    .line 12
    .line 13
    .line 14
    move-result-object v4

    .line 15
    const/4 v5, 0x0

    .line 16
    const/4 v6, 0x1

    .line 17
    if-nez p0, :cond_0

    .line 18
    .line 19
    invoke-virtual {v0, v5, v1}, Lz4/q;->d(ILjava/lang/String;)Lf5/g;

    .line 20
    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_0
    invoke-virtual {v0, v6, v1}, Lz4/q;->d(ILjava/lang/String;)Lf5/g;

    .line 24
    .line 25
    .line 26
    :goto_0
    iget-boolean v1, v0, Lz4/q;->b:Z

    .line 27
    .line 28
    if-nez v1, :cond_2

    .line 29
    .line 30
    if-nez p0, :cond_1

    .line 31
    .line 32
    goto :goto_1

    .line 33
    :cond_1
    move v1, v5

    .line 34
    goto :goto_2

    .line 35
    :cond_2
    :goto_1
    move v1, v6

    .line 36
    :goto_2
    iget-object v4, v4, Le5/b;->c:Ljava/lang/Object;

    .line 37
    .line 38
    check-cast v4, Lf5/g;

    .line 39
    .line 40
    invoke-virtual {v3}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 41
    .line 42
    .line 43
    move-result-object v3

    .line 44
    move v8, v5

    .line 45
    move v9, v6

    .line 46
    const/4 v10, 0x0

    .line 47
    :goto_3
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 48
    .line 49
    .line 50
    move-result v11

    .line 51
    if-eqz v11, :cond_f

    .line 52
    .line 53
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 54
    .line 55
    .line 56
    move-result-object v11

    .line 57
    check-cast v11, Ljava/lang/String;

    .line 58
    .line 59
    invoke-virtual {v11}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 60
    .line 61
    .line 62
    invoke-virtual {v11}, Ljava/lang/String;->hashCode()I

    .line 63
    .line 64
    .line 65
    move-result v13

    .line 66
    const-string v14, "start"

    .line 67
    .line 68
    const-string v15, "right"

    .line 69
    .line 70
    const/16 v16, 0x2

    .line 71
    .line 72
    const-string v7, "left"

    .line 73
    .line 74
    const-string v12, "end"

    .line 75
    .line 76
    sparse-switch v13, :sswitch_data_0

    .line 77
    .line 78
    .line 79
    :goto_4
    const/4 v13, -0x1

    .line 80
    goto :goto_5

    .line 81
    :sswitch_0
    invoke-virtual {v11, v14}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 82
    .line 83
    .line 84
    move-result v13

    .line 85
    if-nez v13, :cond_3

    .line 86
    .line 87
    goto :goto_4

    .line 88
    :cond_3
    const/4 v13, 0x4

    .line 89
    goto :goto_5

    .line 90
    :sswitch_1
    invoke-virtual {v11, v15}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 91
    .line 92
    .line 93
    move-result v13

    .line 94
    if-nez v13, :cond_4

    .line 95
    .line 96
    goto :goto_4

    .line 97
    :cond_4
    const/4 v13, 0x3

    .line 98
    goto :goto_5

    .line 99
    :sswitch_2
    invoke-virtual {v11, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 100
    .line 101
    .line 102
    move-result v13

    .line 103
    if-nez v13, :cond_5

    .line 104
    .line 105
    goto :goto_4

    .line 106
    :cond_5
    move/from16 v13, v16

    .line 107
    .line 108
    goto :goto_5

    .line 109
    :sswitch_3
    invoke-virtual {v11, v12}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 110
    .line 111
    .line 112
    move-result v13

    .line 113
    if-nez v13, :cond_6

    .line 114
    .line 115
    goto :goto_4

    .line 116
    :cond_6
    move v13, v6

    .line 117
    goto :goto_5

    .line 118
    :sswitch_4
    const-string v13, "percent"

    .line 119
    .line 120
    invoke-virtual {v11, v13}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 121
    .line 122
    .line 123
    move-result v13

    .line 124
    if-nez v13, :cond_7

    .line 125
    .line 126
    goto :goto_4

    .line 127
    :cond_7
    move v13, v5

    .line 128
    :goto_5
    packed-switch v13, :pswitch_data_0

    .line 129
    .line 130
    .line 131
    goto :goto_3

    .line 132
    :pswitch_0
    invoke-virtual {v2, v11}, Ld5/b;->u(Ljava/lang/String;)F

    .line 133
    .line 134
    .line 135
    move-result v7

    .line 136
    iget-object v9, v0, Lz4/q;->a:Lrx/b;

    .line 137
    .line 138
    invoke-virtual {v9, v7}, Lrx/b;->e(F)F

    .line 139
    .line 140
    .line 141
    move-result v10

    .line 142
    move v9, v1

    .line 143
    goto :goto_3

    .line 144
    :pswitch_1
    invoke-virtual {v2, v11}, Ld5/b;->u(Ljava/lang/String;)F

    .line 145
    .line 146
    .line 147
    move-result v7

    .line 148
    iget-object v9, v0, Lz4/q;->a:Lrx/b;

    .line 149
    .line 150
    invoke-virtual {v9, v7}, Lrx/b;->e(F)F

    .line 151
    .line 152
    .line 153
    move-result v10

    .line 154
    move v9, v5

    .line 155
    goto :goto_3

    .line 156
    :pswitch_2
    invoke-virtual {v2, v11}, Ld5/b;->u(Ljava/lang/String;)F

    .line 157
    .line 158
    .line 159
    move-result v7

    .line 160
    iget-object v9, v0, Lz4/q;->a:Lrx/b;

    .line 161
    .line 162
    invoke-virtual {v9, v7}, Lrx/b;->e(F)F

    .line 163
    .line 164
    .line 165
    move-result v10

    .line 166
    move v9, v6

    .line 167
    goto :goto_3

    .line 168
    :pswitch_3
    invoke-virtual {v2, v11}, Ld5/b;->u(Ljava/lang/String;)F

    .line 169
    .line 170
    .line 171
    move-result v7

    .line 172
    iget-object v9, v0, Lz4/q;->a:Lrx/b;

    .line 173
    .line 174
    invoke-virtual {v9, v7}, Lrx/b;->e(F)F

    .line 175
    .line 176
    .line 177
    move-result v10

    .line 178
    xor-int/lit8 v9, v1, 0x1

    .line 179
    .line 180
    goto/16 :goto_3

    .line 181
    .line 182
    :pswitch_4
    invoke-virtual {v2, v11}, Ld5/b;->x(Ljava/lang/String;)Ld5/c;

    .line 183
    .line 184
    .line 185
    move-result-object v8

    .line 186
    instance-of v13, v8, Ld5/a;

    .line 187
    .line 188
    if-eqz v13, :cond_8

    .line 189
    .line 190
    check-cast v8, Ld5/a;

    .line 191
    .line 192
    goto :goto_6

    .line 193
    :cond_8
    const/4 v8, 0x0

    .line 194
    :goto_6
    if-nez v8, :cond_9

    .line 195
    .line 196
    invoke-virtual {v2, v11}, Ld5/b;->u(Ljava/lang/String;)F

    .line 197
    .line 198
    .line 199
    move-result v10

    .line 200
    move v8, v6

    .line 201
    move v9, v8

    .line 202
    goto/16 :goto_3

    .line 203
    .line 204
    :cond_9
    iget-object v11, v8, Ld5/b;->h:Ljava/util/ArrayList;

    .line 205
    .line 206
    invoke-virtual {v11}, Ljava/util/ArrayList;->size()I

    .line 207
    .line 208
    .line 209
    move-result v11

    .line 210
    if-le v11, v6, :cond_e

    .line 211
    .line 212
    invoke-virtual {v8, v5}, Ld5/b;->y(I)Ljava/lang/String;

    .line 213
    .line 214
    .line 215
    move-result-object v10

    .line 216
    invoke-virtual {v8, v6}, Ld5/b;->t(I)F

    .line 217
    .line 218
    .line 219
    move-result v8

    .line 220
    invoke-virtual {v10}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 221
    .line 222
    .line 223
    invoke-virtual {v10}, Ljava/lang/String;->hashCode()I

    .line 224
    .line 225
    .line 226
    move-result v11

    .line 227
    sparse-switch v11, :sswitch_data_1

    .line 228
    .line 229
    .line 230
    :goto_7
    const/4 v12, -0x1

    .line 231
    goto :goto_8

    .line 232
    :sswitch_5
    invoke-virtual {v10, v14}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 233
    .line 234
    .line 235
    move-result v7

    .line 236
    if-nez v7, :cond_a

    .line 237
    .line 238
    goto :goto_7

    .line 239
    :cond_a
    const/4 v12, 0x3

    .line 240
    goto :goto_8

    .line 241
    :sswitch_6
    invoke-virtual {v10, v15}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 242
    .line 243
    .line 244
    move-result v7

    .line 245
    if-nez v7, :cond_b

    .line 246
    .line 247
    goto :goto_7

    .line 248
    :cond_b
    move/from16 v12, v16

    .line 249
    .line 250
    goto :goto_8

    .line 251
    :sswitch_7
    invoke-virtual {v10, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 252
    .line 253
    .line 254
    move-result v7

    .line 255
    if-nez v7, :cond_c

    .line 256
    .line 257
    goto :goto_7

    .line 258
    :cond_c
    move v12, v6

    .line 259
    goto :goto_8

    .line 260
    :sswitch_8
    invoke-virtual {v10, v12}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 261
    .line 262
    .line 263
    move-result v7

    .line 264
    if-nez v7, :cond_d

    .line 265
    .line 266
    goto :goto_7

    .line 267
    :cond_d
    move v12, v5

    .line 268
    :goto_8
    packed-switch v12, :pswitch_data_1

    .line 269
    .line 270
    .line 271
    :goto_9
    move v10, v8

    .line 272
    :cond_e
    move v8, v6

    .line 273
    goto/16 :goto_3

    .line 274
    .line 275
    :pswitch_5
    move v9, v1

    .line 276
    goto :goto_9

    .line 277
    :pswitch_6
    move v9, v5

    .line 278
    goto :goto_9

    .line 279
    :pswitch_7
    move v9, v6

    .line 280
    move v10, v8

    .line 281
    move v8, v9

    .line 282
    goto/16 :goto_3

    .line 283
    .line 284
    :pswitch_8
    xor-int/lit8 v9, v1, 0x1

    .line 285
    .line 286
    goto :goto_9

    .line 287
    :cond_f
    if-eqz v8, :cond_11

    .line 288
    .line 289
    if-eqz v9, :cond_10

    .line 290
    .line 291
    const/4 v0, -0x1

    .line 292
    iput v0, v4, Lf5/g;->d:I

    .line 293
    .line 294
    iput v0, v4, Lf5/g;->e:I

    .line 295
    .line 296
    iput v10, v4, Lf5/g;->f:F

    .line 297
    .line 298
    return-void

    .line 299
    :cond_10
    const/4 v0, -0x1

    .line 300
    const/high16 v1, 0x3f800000    # 1.0f

    .line 301
    .line 302
    sub-float/2addr v1, v10

    .line 303
    iput v0, v4, Lf5/g;->d:I

    .line 304
    .line 305
    iput v0, v4, Lf5/g;->e:I

    .line 306
    .line 307
    iput v1, v4, Lf5/g;->f:F

    .line 308
    .line 309
    return-void

    .line 310
    :cond_11
    const/4 v0, -0x1

    .line 311
    if-eqz v9, :cond_12

    .line 312
    .line 313
    invoke-static {v10}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 314
    .line 315
    .line 316
    move-result-object v1

    .line 317
    iget-object v2, v4, Lf5/g;->a:Lz4/q;

    .line 318
    .line 319
    invoke-virtual {v2, v1}, Lz4/q;->c(Ljava/lang/Float;)I

    .line 320
    .line 321
    .line 322
    move-result v1

    .line 323
    iput v1, v4, Lf5/g;->d:I

    .line 324
    .line 325
    iput v0, v4, Lf5/g;->e:I

    .line 326
    .line 327
    const/4 v1, 0x0

    .line 328
    iput v1, v4, Lf5/g;->f:F

    .line 329
    .line 330
    return-void

    .line 331
    :cond_12
    const/4 v1, 0x0

    .line 332
    invoke-static {v10}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 333
    .line 334
    .line 335
    move-result-object v2

    .line 336
    iput v0, v4, Lf5/g;->d:I

    .line 337
    .line 338
    iget-object v0, v4, Lf5/g;->a:Lz4/q;

    .line 339
    .line 340
    invoke-virtual {v0, v2}, Lz4/q;->c(Ljava/lang/Float;)I

    .line 341
    .line 342
    .line 343
    move-result v0

    .line 344
    iput v0, v4, Lf5/g;->e:I

    .line 345
    .line 346
    iput v1, v4, Lf5/g;->f:F

    .line 347
    .line 348
    return-void

    .line 349
    :sswitch_data_0
    .sparse-switch
        -0x28779bbb -> :sswitch_4
        0x188db -> :sswitch_3
        0x32a007 -> :sswitch_2
        0x677c21c -> :sswitch_1
        0x68ac462 -> :sswitch_0
    .end sparse-switch

    .line 350
    .line 351
    .line 352
    .line 353
    .line 354
    .line 355
    .line 356
    .line 357
    .line 358
    .line 359
    .line 360
    .line 361
    .line 362
    .line 363
    .line 364
    .line 365
    .line 366
    .line 367
    .line 368
    .line 369
    .line 370
    .line 371
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch

    .line 372
    .line 373
    .line 374
    .line 375
    .line 376
    .line 377
    .line 378
    .line 379
    .line 380
    .line 381
    .line 382
    .line 383
    .line 384
    .line 385
    :sswitch_data_1
    .sparse-switch
        0x188db -> :sswitch_8
        0x32a007 -> :sswitch_7
        0x677c21c -> :sswitch_6
        0x68ac462 -> :sswitch_5
    .end sparse-switch

    .line 386
    .line 387
    .line 388
    .line 389
    .line 390
    .line 391
    .line 392
    .line 393
    .line 394
    .line 395
    .line 396
    .line 397
    .line 398
    .line 399
    .line 400
    .line 401
    .line 402
    .line 403
    :pswitch_data_1
    .packed-switch 0x0
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
    .end packed-switch
.end method

.method public static i(Lz4/q;Le5/f;Ljava/lang/String;Ld5/f;)V
    .locals 2

    .line 1
    invoke-virtual {p0, p2}, Lz4/q;->b(Ljava/lang/Object;)Le5/b;

    .line 2
    .line 3
    .line 4
    move-result-object p2

    .line 5
    iget-object v0, p2, Le5/b;->d0:Le5/g;

    .line 6
    .line 7
    sget-object v1, Le5/g;->i:Ljava/lang/String;

    .line 8
    .line 9
    if-nez v0, :cond_0

    .line 10
    .line 11
    new-instance v0, Le5/g;

    .line 12
    .line 13
    invoke-direct {v0, v1}, Le5/g;-><init>(Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    iput-object v0, p2, Le5/b;->d0:Le5/g;

    .line 17
    .line 18
    :cond_0
    iget-object v0, p2, Le5/b;->e0:Le5/g;

    .line 19
    .line 20
    if-nez v0, :cond_1

    .line 21
    .line 22
    new-instance v0, Le5/g;

    .line 23
    .line 24
    invoke-direct {v0, v1}, Le5/g;-><init>(Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    iput-object v0, p2, Le5/b;->e0:Le5/g;

    .line 28
    .line 29
    :cond_1
    invoke-virtual {p3}, Ld5/b;->C()Ljava/util/ArrayList;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 38
    .line 39
    .line 40
    move-result v1

    .line 41
    if-eqz v1, :cond_2

    .line 42
    .line 43
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object v1

    .line 47
    check-cast v1, Ljava/lang/String;

    .line 48
    .line 49
    invoke-static {p3, p2, p1, v1, p0}, Lkp/b0;->c(Ld5/f;Le5/b;Le5/f;Ljava/lang/String;Lz4/q;)V

    .line 50
    .line 51
    .line 52
    goto :goto_0

    .line 53
    :cond_2
    return-void
.end method
