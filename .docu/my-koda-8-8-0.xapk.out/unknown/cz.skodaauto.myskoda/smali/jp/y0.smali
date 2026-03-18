.class public abstract Ljp/y0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lxh/e;Lxh/e;Lyy0/l1;Ll2/o;I)V
    .locals 20

    .line 1
    move-object/from16 v3, p0

    .line 2
    .line 3
    move-object/from16 v4, p1

    .line 4
    .line 5
    move-object/from16 v5, p2

    .line 6
    .line 7
    move-object/from16 v11, p3

    .line 8
    .line 9
    check-cast v11, Ll2/t;

    .line 10
    .line 11
    const v0, -0x2c6e2a68

    .line 12
    .line 13
    .line 14
    invoke-virtual {v11, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 15
    .line 16
    .line 17
    invoke-virtual {v11, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    const/4 v1, 0x4

    .line 22
    if-eqz v0, :cond_0

    .line 23
    .line 24
    move v0, v1

    .line 25
    goto :goto_0

    .line 26
    :cond_0
    const/4 v0, 0x2

    .line 27
    :goto_0
    or-int v0, p4, v0

    .line 28
    .line 29
    invoke-virtual {v11, v4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 30
    .line 31
    .line 32
    move-result v2

    .line 33
    const/16 v6, 0x20

    .line 34
    .line 35
    if-eqz v2, :cond_1

    .line 36
    .line 37
    move v2, v6

    .line 38
    goto :goto_1

    .line 39
    :cond_1
    const/16 v2, 0x10

    .line 40
    .line 41
    :goto_1
    or-int/2addr v0, v2

    .line 42
    invoke-virtual {v11, v5}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 43
    .line 44
    .line 45
    move-result v2

    .line 46
    if-eqz v2, :cond_2

    .line 47
    .line 48
    const/16 v2, 0x100

    .line 49
    .line 50
    goto :goto_2

    .line 51
    :cond_2
    const/16 v2, 0x80

    .line 52
    .line 53
    :goto_2
    or-int/2addr v0, v2

    .line 54
    and-int/lit16 v2, v0, 0x93

    .line 55
    .line 56
    const/16 v7, 0x92

    .line 57
    .line 58
    const/4 v8, 0x1

    .line 59
    const/4 v9, 0x0

    .line 60
    if-eq v2, v7, :cond_3

    .line 61
    .line 62
    move v2, v8

    .line 63
    goto :goto_3

    .line 64
    :cond_3
    move v2, v9

    .line 65
    :goto_3
    and-int/lit8 v7, v0, 0x1

    .line 66
    .line 67
    invoke-virtual {v11, v7, v2}, Ll2/t;->O(IZ)Z

    .line 68
    .line 69
    .line 70
    move-result v2

    .line 71
    if-eqz v2, :cond_d

    .line 72
    .line 73
    invoke-virtual {v11, v5}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 74
    .line 75
    .line 76
    move-result v2

    .line 77
    and-int/lit8 v7, v0, 0xe

    .line 78
    .line 79
    if-ne v7, v1, :cond_4

    .line 80
    .line 81
    move v1, v8

    .line 82
    goto :goto_4

    .line 83
    :cond_4
    move v1, v9

    .line 84
    :goto_4
    or-int/2addr v1, v2

    .line 85
    and-int/lit8 v0, v0, 0x70

    .line 86
    .line 87
    if-ne v0, v6, :cond_5

    .line 88
    .line 89
    goto :goto_5

    .line 90
    :cond_5
    move v8, v9

    .line 91
    :goto_5
    or-int v0, v1, v8

    .line 92
    .line 93
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 94
    .line 95
    .line 96
    move-result-object v1

    .line 97
    sget-object v2, Ll2/n;->a:Ll2/x0;

    .line 98
    .line 99
    if-nez v0, :cond_6

    .line 100
    .line 101
    if-ne v1, v2, :cond_7

    .line 102
    .line 103
    :cond_6
    new-instance v1, Lxc/b;

    .line 104
    .line 105
    const/4 v0, 0x7

    .line 106
    invoke-direct {v1, v5, v3, v4, v0}, Lxc/b;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 107
    .line 108
    .line 109
    invoke-virtual {v11, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 110
    .line 111
    .line 112
    :cond_7
    check-cast v1, Lay0/k;

    .line 113
    .line 114
    sget-object v0, Lw3/q1;->a:Ll2/u2;

    .line 115
    .line 116
    invoke-virtual {v11, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 117
    .line 118
    .line 119
    move-result-object v0

    .line 120
    check-cast v0, Ljava/lang/Boolean;

    .line 121
    .line 122
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 123
    .line 124
    .line 125
    move-result v0

    .line 126
    if-eqz v0, :cond_8

    .line 127
    .line 128
    const v0, -0x105bcaaa

    .line 129
    .line 130
    .line 131
    invoke-virtual {v11, v0}, Ll2/t;->Y(I)V

    .line 132
    .line 133
    .line 134
    invoke-virtual {v11, v9}, Ll2/t;->q(Z)V

    .line 135
    .line 136
    .line 137
    const/4 v0, 0x0

    .line 138
    goto :goto_6

    .line 139
    :cond_8
    const v0, 0x31054eee

    .line 140
    .line 141
    .line 142
    invoke-virtual {v11, v0}, Ll2/t;->Y(I)V

    .line 143
    .line 144
    .line 145
    sget-object v0, Lzb/x;->a:Ll2/u2;

    .line 146
    .line 147
    invoke-virtual {v11, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 148
    .line 149
    .line 150
    move-result-object v0

    .line 151
    check-cast v0, Lhi/a;

    .line 152
    .line 153
    invoke-virtual {v11, v9}, Ll2/t;->q(Z)V

    .line 154
    .line 155
    .line 156
    :goto_6
    new-instance v9, Lvh/i;

    .line 157
    .line 158
    const/16 v6, 0xa

    .line 159
    .line 160
    invoke-direct {v9, v6, v0, v1}, Lvh/i;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 161
    .line 162
    .line 163
    invoke-static {v11}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 164
    .line 165
    .line 166
    move-result-object v7

    .line 167
    if-eqz v7, :cond_c

    .line 168
    .line 169
    instance-of v0, v7, Landroidx/lifecycle/k;

    .line 170
    .line 171
    if-eqz v0, :cond_9

    .line 172
    .line 173
    move-object v0, v7

    .line 174
    check-cast v0, Landroidx/lifecycle/k;

    .line 175
    .line 176
    invoke-interface {v0}, Landroidx/lifecycle/k;->getDefaultViewModelCreationExtras()Lp7/c;

    .line 177
    .line 178
    .line 179
    move-result-object v0

    .line 180
    :goto_7
    move-object v10, v0

    .line 181
    goto :goto_8

    .line 182
    :cond_9
    sget-object v0, Lp7/a;->b:Lp7/a;

    .line 183
    .line 184
    goto :goto_7

    .line 185
    :goto_8
    const-class v0, Lzc/k;

    .line 186
    .line 187
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 188
    .line 189
    invoke-virtual {v1, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 190
    .line 191
    .line 192
    move-result-object v6

    .line 193
    const/4 v8, 0x0

    .line 194
    invoke-static/range {v6 .. v11}, Ljp/se;->b(Lhy0/d;Landroidx/lifecycle/i1;Ljava/lang/String;Landroidx/lifecycle/e1;Lp7/c;Ll2/o;)Landroidx/lifecycle/b1;

    .line 195
    .line 196
    .line 197
    move-result-object v0

    .line 198
    move-object v14, v0

    .line 199
    check-cast v14, Lzc/k;

    .line 200
    .line 201
    invoke-static {v11}, Llp/kb;->c(Ll2/o;)Lvc/b;

    .line 202
    .line 203
    .line 204
    move-result-object v0

    .line 205
    iget-object v1, v14, Lzc/k;->m:Lyy0/c2;

    .line 206
    .line 207
    invoke-static {v1, v11}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 208
    .line 209
    .line 210
    move-result-object v1

    .line 211
    invoke-interface {v1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 212
    .line 213
    .line 214
    move-result-object v1

    .line 215
    check-cast v1, Llc/q;

    .line 216
    .line 217
    invoke-virtual {v11, v14}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 218
    .line 219
    .line 220
    move-result v6

    .line 221
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 222
    .line 223
    .line 224
    move-result-object v7

    .line 225
    if-nez v6, :cond_a

    .line 226
    .line 227
    if-ne v7, v2, :cond_b

    .line 228
    .line 229
    :cond_a
    new-instance v12, Lz70/u;

    .line 230
    .line 231
    const/16 v18, 0x0

    .line 232
    .line 233
    const/16 v19, 0x7

    .line 234
    .line 235
    const/4 v13, 0x1

    .line 236
    const-class v15, Lzc/k;

    .line 237
    .line 238
    const-string v16, "onUiEvent"

    .line 239
    .line 240
    const-string v17, "onUiEvent(Lcariad/charging/multicharge/kitten/chargingcard/presentation/overview/ChargingCardOverviewUiEvent;)V"

    .line 241
    .line 242
    invoke-direct/range {v12 .. v19}, Lz70/u;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 243
    .line 244
    .line 245
    invoke-virtual {v11, v12}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 246
    .line 247
    .line 248
    move-object v7, v12

    .line 249
    :cond_b
    check-cast v7, Lhy0/g;

    .line 250
    .line 251
    check-cast v7, Lay0/k;

    .line 252
    .line 253
    const/16 v2, 0x8

    .line 254
    .line 255
    invoke-interface {v0, v1, v7, v11, v2}, Lvc/b;->r0(Llc/q;Lay0/k;Ll2/o;I)V

    .line 256
    .line 257
    .line 258
    goto :goto_9

    .line 259
    :cond_c
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 260
    .line 261
    const-string v1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 262
    .line 263
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 264
    .line 265
    .line 266
    throw v0

    .line 267
    :cond_d
    invoke-virtual {v11}, Ll2/t;->R()V

    .line 268
    .line 269
    .line 270
    :goto_9
    invoke-virtual {v11}, Ll2/t;->s()Ll2/u1;

    .line 271
    .line 272
    .line 273
    move-result-object v6

    .line 274
    if-eqz v6, :cond_e

    .line 275
    .line 276
    new-instance v0, Lza0/f;

    .line 277
    .line 278
    const/4 v2, 0x4

    .line 279
    move/from16 v1, p4

    .line 280
    .line 281
    invoke-direct/range {v0 .. v5}, Lza0/f;-><init>(IILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 282
    .line 283
    .line 284
    iput-object v0, v6, Ll2/u1;->d:Lay0/n;

    .line 285
    .line 286
    :cond_e
    return-void
.end method

.method public static final b(Ljava/util/List;Lle/a;Ll2/o;I)V
    .locals 20

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
    const-string v3, "selectedKolaDays"

    .line 8
    .line 9
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    move-object/from16 v9, p2

    .line 13
    .line 14
    check-cast v9, Ll2/t;

    .line 15
    .line 16
    const v3, -0x66050681

    .line 17
    .line 18
    .line 19
    invoke-virtual {v9, v3}, Ll2/t;->a0(I)Ll2/t;

    .line 20
    .line 21
    .line 22
    invoke-virtual {v9, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 23
    .line 24
    .line 25
    move-result v3

    .line 26
    if-eqz v3, :cond_0

    .line 27
    .line 28
    const/4 v3, 0x4

    .line 29
    goto :goto_0

    .line 30
    :cond_0
    const/4 v3, 0x2

    .line 31
    :goto_0
    or-int/2addr v3, v2

    .line 32
    invoke-virtual {v9, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 33
    .line 34
    .line 35
    move-result v4

    .line 36
    const/16 v5, 0x20

    .line 37
    .line 38
    if-eqz v4, :cond_1

    .line 39
    .line 40
    move v4, v5

    .line 41
    goto :goto_1

    .line 42
    :cond_1
    const/16 v4, 0x10

    .line 43
    .line 44
    :goto_1
    or-int/2addr v3, v4

    .line 45
    and-int/lit8 v4, v3, 0x13

    .line 46
    .line 47
    const/16 v6, 0x12

    .line 48
    .line 49
    const/4 v7, 0x1

    .line 50
    const/4 v10, 0x0

    .line 51
    if-eq v4, v6, :cond_2

    .line 52
    .line 53
    move v4, v7

    .line 54
    goto :goto_2

    .line 55
    :cond_2
    move v4, v10

    .line 56
    :goto_2
    and-int/lit8 v6, v3, 0x1

    .line 57
    .line 58
    invoke-virtual {v9, v6, v4}, Ll2/t;->O(IZ)Z

    .line 59
    .line 60
    .line 61
    move-result v4

    .line 62
    if-eqz v4, :cond_b

    .line 63
    .line 64
    invoke-virtual {v9, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 65
    .line 66
    .line 67
    move-result v4

    .line 68
    and-int/lit8 v3, v3, 0x70

    .line 69
    .line 70
    if-ne v3, v5, :cond_3

    .line 71
    .line 72
    goto :goto_3

    .line 73
    :cond_3
    move v7, v10

    .line 74
    :goto_3
    or-int v3, v4, v7

    .line 75
    .line 76
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 77
    .line 78
    .line 79
    move-result-object v4

    .line 80
    sget-object v11, Ll2/n;->a:Ll2/x0;

    .line 81
    .line 82
    if-nez v3, :cond_4

    .line 83
    .line 84
    if-ne v4, v11, :cond_5

    .line 85
    .line 86
    :cond_4
    new-instance v4, Laa/z;

    .line 87
    .line 88
    const/4 v3, 0x3

    .line 89
    invoke-direct {v4, v3, v0, v1}, Laa/z;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 90
    .line 91
    .line 92
    invoke-virtual {v9, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 93
    .line 94
    .line 95
    :cond_5
    check-cast v4, Lay0/k;

    .line 96
    .line 97
    sget-object v3, Lw3/q1;->a:Ll2/u2;

    .line 98
    .line 99
    invoke-virtual {v9, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 100
    .line 101
    .line 102
    move-result-object v3

    .line 103
    check-cast v3, Ljava/lang/Boolean;

    .line 104
    .line 105
    invoke-virtual {v3}, Ljava/lang/Boolean;->booleanValue()Z

    .line 106
    .line 107
    .line 108
    move-result v3

    .line 109
    if-eqz v3, :cond_6

    .line 110
    .line 111
    const v3, -0x105bcaaa

    .line 112
    .line 113
    .line 114
    invoke-virtual {v9, v3}, Ll2/t;->Y(I)V

    .line 115
    .line 116
    .line 117
    invoke-virtual {v9, v10}, Ll2/t;->q(Z)V

    .line 118
    .line 119
    .line 120
    const/4 v3, 0x0

    .line 121
    goto :goto_4

    .line 122
    :cond_6
    const v3, 0x31054eee

    .line 123
    .line 124
    .line 125
    invoke-virtual {v9, v3}, Ll2/t;->Y(I)V

    .line 126
    .line 127
    .line 128
    sget-object v3, Lzb/x;->a:Ll2/u2;

    .line 129
    .line 130
    invoke-virtual {v9, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 131
    .line 132
    .line 133
    move-result-object v3

    .line 134
    check-cast v3, Lhi/a;

    .line 135
    .line 136
    invoke-virtual {v9, v10}, Ll2/t;->q(Z)V

    .line 137
    .line 138
    .line 139
    :goto_4
    new-instance v7, Laf/a;

    .line 140
    .line 141
    const/4 v5, 0x0

    .line 142
    invoke-direct {v7, v3, v4, v5}, Laf/a;-><init>(Lhi/a;Lay0/k;I)V

    .line 143
    .line 144
    .line 145
    invoke-static {v9}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 146
    .line 147
    .line 148
    move-result-object v5

    .line 149
    if-eqz v5, :cond_a

    .line 150
    .line 151
    instance-of v3, v5, Landroidx/lifecycle/k;

    .line 152
    .line 153
    if-eqz v3, :cond_7

    .line 154
    .line 155
    move-object v3, v5

    .line 156
    check-cast v3, Landroidx/lifecycle/k;

    .line 157
    .line 158
    invoke-interface {v3}, Landroidx/lifecycle/k;->getDefaultViewModelCreationExtras()Lp7/c;

    .line 159
    .line 160
    .line 161
    move-result-object v3

    .line 162
    :goto_5
    move-object v8, v3

    .line 163
    goto :goto_6

    .line 164
    :cond_7
    sget-object v3, Lp7/a;->b:Lp7/a;

    .line 165
    .line 166
    goto :goto_5

    .line 167
    :goto_6
    const-class v3, Laf/e;

    .line 168
    .line 169
    sget-object v4, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 170
    .line 171
    invoke-virtual {v4, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 172
    .line 173
    .line 174
    move-result-object v4

    .line 175
    const/4 v6, 0x0

    .line 176
    invoke-static/range {v4 .. v9}, Ljp/se;->b(Lhy0/d;Landroidx/lifecycle/i1;Ljava/lang/String;Landroidx/lifecycle/e1;Lp7/c;Ll2/o;)Landroidx/lifecycle/b1;

    .line 177
    .line 178
    .line 179
    move-result-object v3

    .line 180
    move-object v14, v3

    .line 181
    check-cast v14, Laf/e;

    .line 182
    .line 183
    iget-object v3, v14, Laf/e;->e:Lyy0/l1;

    .line 184
    .line 185
    invoke-static {v3, v9}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 186
    .line 187
    .line 188
    move-result-object v3

    .line 189
    invoke-static {v9}, Llp/nf;->a(Ll2/o;)Lle/c;

    .line 190
    .line 191
    .line 192
    move-result-object v4

    .line 193
    invoke-interface {v3}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 194
    .line 195
    .line 196
    move-result-object v3

    .line 197
    check-cast v3, Laf/d;

    .line 198
    .line 199
    invoke-virtual {v9, v14}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 200
    .line 201
    .line 202
    move-result v5

    .line 203
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 204
    .line 205
    .line 206
    move-result-object v6

    .line 207
    if-nez v5, :cond_8

    .line 208
    .line 209
    if-ne v6, v11, :cond_9

    .line 210
    .line 211
    :cond_8
    new-instance v12, Laf/b;

    .line 212
    .line 213
    const/16 v18, 0x0

    .line 214
    .line 215
    const/16 v19, 0x0

    .line 216
    .line 217
    const/4 v13, 0x1

    .line 218
    const-class v15, Laf/e;

    .line 219
    .line 220
    const-string v16, "onUiEvent"

    .line 221
    .line 222
    const-string v17, "onUiEvent(Lcariad/charging/multicharge/kitten/kola/presentation/wizard/multiplefixedrate/intermediatedaysuccess/IntermediateDaySuccessUiEvent;)V"

    .line 223
    .line 224
    invoke-direct/range {v12 .. v19}, Laf/b;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 225
    .line 226
    .line 227
    invoke-virtual {v9, v12}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 228
    .line 229
    .line 230
    move-object v6, v12

    .line 231
    :cond_9
    check-cast v6, Lhy0/g;

    .line 232
    .line 233
    check-cast v6, Lay0/k;

    .line 234
    .line 235
    invoke-interface {v4, v3, v6, v9, v10}, Lle/c;->H(Laf/d;Lay0/k;Ll2/o;I)V

    .line 236
    .line 237
    .line 238
    goto :goto_7

    .line 239
    :cond_a
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 240
    .line 241
    const-string v1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 242
    .line 243
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 244
    .line 245
    .line 246
    throw v0

    .line 247
    :cond_b
    invoke-virtual {v9}, Ll2/t;->R()V

    .line 248
    .line 249
    .line 250
    :goto_7
    invoke-virtual {v9}, Ll2/t;->s()Ll2/u1;

    .line 251
    .line 252
    .line 253
    move-result-object v3

    .line 254
    if-eqz v3, :cond_c

    .line 255
    .line 256
    new-instance v4, Laa/m;

    .line 257
    .line 258
    const/4 v5, 0x2

    .line 259
    invoke-direct {v4, v2, v5, v0, v1}, Laa/m;-><init>(IILjava/lang/Object;Ljava/lang/Object;)V

    .line 260
    .line 261
    .line 262
    iput-object v4, v3, Ll2/u1;->d:Lay0/n;

    .line 263
    .line 264
    :cond_c
    return-void
.end method

.method public static final c(Lmb/o;)Lmb/i;
    .locals 2

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Lmb/i;

    .line 7
    .line 8
    iget-object v1, p0, Lmb/o;->a:Ljava/lang/String;

    .line 9
    .line 10
    iget p0, p0, Lmb/o;->t:I

    .line 11
    .line 12
    invoke-direct {v0, v1, p0}, Lmb/i;-><init>(Ljava/lang/String;I)V

    .line 13
    .line 14
    .line 15
    return-object v0
.end method
