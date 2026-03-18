.class public abstract Ljp/dg;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Ljava/util/List;Lay0/k;Li91/i4;Ll2/o;I)V
    .locals 21

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
    const-string v0, "goToNext"

    .line 8
    .line 9
    invoke-static {v4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    move-object/from16 v11, p3

    .line 13
    .line 14
    check-cast v11, Ll2/t;

    .line 15
    .line 16
    const v0, 0x4e88dfd7

    .line 17
    .line 18
    .line 19
    invoke-virtual {v11, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 20
    .line 21
    .line 22
    invoke-virtual {v11, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    if-eqz v0, :cond_0

    .line 27
    .line 28
    const/4 v0, 0x4

    .line 29
    goto :goto_0

    .line 30
    :cond_0
    const/4 v0, 0x2

    .line 31
    :goto_0
    or-int v0, p4, v0

    .line 32
    .line 33
    invoke-virtual {v11, v4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 34
    .line 35
    .line 36
    move-result v1

    .line 37
    const/16 v2, 0x20

    .line 38
    .line 39
    if-eqz v1, :cond_1

    .line 40
    .line 41
    move v1, v2

    .line 42
    goto :goto_1

    .line 43
    :cond_1
    const/16 v1, 0x10

    .line 44
    .line 45
    :goto_1
    or-int/2addr v0, v1

    .line 46
    invoke-virtual {v11, v5}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 47
    .line 48
    .line 49
    move-result v1

    .line 50
    const/16 v6, 0x100

    .line 51
    .line 52
    if-eqz v1, :cond_2

    .line 53
    .line 54
    move v1, v6

    .line 55
    goto :goto_2

    .line 56
    :cond_2
    const/16 v1, 0x80

    .line 57
    .line 58
    :goto_2
    or-int/2addr v0, v1

    .line 59
    and-int/lit16 v1, v0, 0x93

    .line 60
    .line 61
    const/16 v7, 0x92

    .line 62
    .line 63
    const/4 v8, 0x1

    .line 64
    const/4 v12, 0x0

    .line 65
    if-eq v1, v7, :cond_3

    .line 66
    .line 67
    move v1, v8

    .line 68
    goto :goto_3

    .line 69
    :cond_3
    move v1, v12

    .line 70
    :goto_3
    and-int/lit8 v7, v0, 0x1

    .line 71
    .line 72
    invoke-virtual {v11, v7, v1}, Ll2/t;->O(IZ)Z

    .line 73
    .line 74
    .line 75
    move-result v1

    .line 76
    if-eqz v1, :cond_d

    .line 77
    .line 78
    invoke-virtual {v11, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 79
    .line 80
    .line 81
    move-result v1

    .line 82
    and-int/lit8 v7, v0, 0x70

    .line 83
    .line 84
    if-ne v7, v2, :cond_4

    .line 85
    .line 86
    move v2, v8

    .line 87
    goto :goto_4

    .line 88
    :cond_4
    move v2, v12

    .line 89
    :goto_4
    or-int/2addr v1, v2

    .line 90
    and-int/lit16 v0, v0, 0x380

    .line 91
    .line 92
    if-ne v0, v6, :cond_5

    .line 93
    .line 94
    goto :goto_5

    .line 95
    :cond_5
    move v8, v12

    .line 96
    :goto_5
    or-int v0, v1, v8

    .line 97
    .line 98
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 99
    .line 100
    .line 101
    move-result-object v1

    .line 102
    sget-object v2, Ll2/n;->a:Ll2/x0;

    .line 103
    .line 104
    if-nez v0, :cond_6

    .line 105
    .line 106
    if-ne v1, v2, :cond_7

    .line 107
    .line 108
    :cond_6
    new-instance v1, Laa/o;

    .line 109
    .line 110
    const/16 v0, 0x8

    .line 111
    .line 112
    invoke-direct {v1, v3, v4, v5, v0}, Laa/o;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 113
    .line 114
    .line 115
    invoke-virtual {v11, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 116
    .line 117
    .line 118
    :cond_7
    check-cast v1, Lay0/k;

    .line 119
    .line 120
    sget-object v0, Lw3/q1;->a:Ll2/u2;

    .line 121
    .line 122
    invoke-virtual {v11, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 123
    .line 124
    .line 125
    move-result-object v0

    .line 126
    check-cast v0, Ljava/lang/Boolean;

    .line 127
    .line 128
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 129
    .line 130
    .line 131
    move-result v0

    .line 132
    if-eqz v0, :cond_8

    .line 133
    .line 134
    const v0, -0x105bcaaa

    .line 135
    .line 136
    .line 137
    invoke-virtual {v11, v0}, Ll2/t;->Y(I)V

    .line 138
    .line 139
    .line 140
    invoke-virtual {v11, v12}, Ll2/t;->q(Z)V

    .line 141
    .line 142
    .line 143
    const/4 v0, 0x0

    .line 144
    goto :goto_6

    .line 145
    :cond_8
    const v0, 0x31054eee

    .line 146
    .line 147
    .line 148
    invoke-virtual {v11, v0}, Ll2/t;->Y(I)V

    .line 149
    .line 150
    .line 151
    sget-object v0, Lzb/x;->a:Ll2/u2;

    .line 152
    .line 153
    invoke-virtual {v11, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 154
    .line 155
    .line 156
    move-result-object v0

    .line 157
    check-cast v0, Lhi/a;

    .line 158
    .line 159
    invoke-virtual {v11, v12}, Ll2/t;->q(Z)V

    .line 160
    .line 161
    .line 162
    :goto_6
    new-instance v9, Laf/a;

    .line 163
    .line 164
    const/4 v6, 0x7

    .line 165
    invoke-direct {v9, v0, v1, v6}, Laf/a;-><init>(Lhi/a;Lay0/k;I)V

    .line 166
    .line 167
    .line 168
    invoke-static {v11}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 169
    .line 170
    .line 171
    move-result-object v7

    .line 172
    if-eqz v7, :cond_c

    .line 173
    .line 174
    instance-of v0, v7, Landroidx/lifecycle/k;

    .line 175
    .line 176
    if-eqz v0, :cond_9

    .line 177
    .line 178
    move-object v0, v7

    .line 179
    check-cast v0, Landroidx/lifecycle/k;

    .line 180
    .line 181
    invoke-interface {v0}, Landroidx/lifecycle/k;->getDefaultViewModelCreationExtras()Lp7/c;

    .line 182
    .line 183
    .line 184
    move-result-object v0

    .line 185
    :goto_7
    move-object v10, v0

    .line 186
    goto :goto_8

    .line 187
    :cond_9
    sget-object v0, Lp7/a;->b:Lp7/a;

    .line 188
    .line 189
    goto :goto_7

    .line 190
    :goto_8
    const-class v0, Ldf/d;

    .line 191
    .line 192
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 193
    .line 194
    invoke-virtual {v1, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 195
    .line 196
    .line 197
    move-result-object v6

    .line 198
    const/4 v8, 0x0

    .line 199
    invoke-static/range {v6 .. v11}, Ljp/se;->b(Lhy0/d;Landroidx/lifecycle/i1;Ljava/lang/String;Landroidx/lifecycle/e1;Lp7/c;Ll2/o;)Landroidx/lifecycle/b1;

    .line 200
    .line 201
    .line 202
    move-result-object v0

    .line 203
    move-object v15, v0

    .line 204
    check-cast v15, Ldf/d;

    .line 205
    .line 206
    iget-object v0, v15, Ldf/d;->g:Lyy0/l1;

    .line 207
    .line 208
    invoke-static {v0, v11}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 209
    .line 210
    .line 211
    move-result-object v0

    .line 212
    invoke-static {v11}, Llp/nf;->a(Ll2/o;)Lle/c;

    .line 213
    .line 214
    .line 215
    move-result-object v1

    .line 216
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 217
    .line 218
    .line 219
    move-result-object v0

    .line 220
    check-cast v0, Ldf/c;

    .line 221
    .line 222
    invoke-virtual {v11, v15}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 223
    .line 224
    .line 225
    move-result v6

    .line 226
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 227
    .line 228
    .line 229
    move-result-object v7

    .line 230
    if-nez v6, :cond_a

    .line 231
    .line 232
    if-ne v7, v2, :cond_b

    .line 233
    .line 234
    :cond_a
    new-instance v13, Lcz/j;

    .line 235
    .line 236
    const/16 v19, 0x0

    .line 237
    .line 238
    const/16 v20, 0x14

    .line 239
    .line 240
    const/4 v14, 0x1

    .line 241
    const-class v16, Ldf/d;

    .line 242
    .line 243
    const-string v17, "onUiEvent"

    .line 244
    .line 245
    const-string v18, "onUiEvent(Lcariad/charging/multicharge/kitten/kola/presentation/wizard/multiplefixedrate/multipledayselection/MultipleDaysSelectionUiEvent;)V"

    .line 246
    .line 247
    invoke-direct/range {v13 .. v20}, Lcz/j;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 248
    .line 249
    .line 250
    invoke-virtual {v11, v13}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 251
    .line 252
    .line 253
    move-object v7, v13

    .line 254
    :cond_b
    check-cast v7, Lhy0/g;

    .line 255
    .line 256
    check-cast v7, Lay0/k;

    .line 257
    .line 258
    invoke-interface {v1, v0, v7, v11, v12}, Lle/c;->w(Ldf/c;Lay0/k;Ll2/o;I)V

    .line 259
    .line 260
    .line 261
    goto :goto_9

    .line 262
    :cond_c
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 263
    .line 264
    const-string v1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 265
    .line 266
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 267
    .line 268
    .line 269
    throw v0

    .line 270
    :cond_d
    invoke-virtual {v11}, Ll2/t;->R()V

    .line 271
    .line 272
    .line 273
    :goto_9
    invoke-virtual {v11}, Ll2/t;->s()Ll2/u1;

    .line 274
    .line 275
    .line 276
    move-result-object v6

    .line 277
    if-eqz v6, :cond_e

    .line 278
    .line 279
    new-instance v0, Laa/w;

    .line 280
    .line 281
    const/16 v2, 0x19

    .line 282
    .line 283
    move/from16 v1, p4

    .line 284
    .line 285
    invoke-direct/range {v0 .. v5}, Laa/w;-><init>(IILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 286
    .line 287
    .line 288
    iput-object v0, v6, Ll2/u1;->d:Lay0/n;

    .line 289
    .line 290
    :cond_e
    return-void
.end method

.method public static final b(Lqp0/x;)Lqp0/b0;
    .locals 19

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    const-string v1, "<this>"

    .line 4
    .line 5
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    new-instance v2, Lqp0/b0;

    .line 9
    .line 10
    invoke-virtual {v0}, Lqp0/x;->c()Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object v3

    .line 14
    invoke-virtual {v0}, Lqp0/x;->b()Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object v4

    .line 18
    instance-of v1, v0, Lqp0/t;

    .line 19
    .line 20
    if-eqz v1, :cond_0

    .line 21
    .line 22
    sget-object v1, Lqp0/h0;->a:Lqp0/h0;

    .line 23
    .line 24
    :goto_0
    move-object v5, v1

    .line 25
    goto :goto_1

    .line 26
    :cond_0
    instance-of v1, v0, Lqp0/w;

    .line 27
    .line 28
    if-eqz v1, :cond_1

    .line 29
    .line 30
    sget-object v1, Lqp0/s0;->a:Lqp0/s0;

    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_1
    instance-of v1, v0, Lqp0/u;

    .line 34
    .line 35
    if-eqz v1, :cond_2

    .line 36
    .line 37
    sget-object v1, Lqp0/p0;->a:Lqp0/p0;

    .line 38
    .line 39
    goto :goto_0

    .line 40
    :cond_2
    instance-of v1, v0, Lqp0/v;

    .line 41
    .line 42
    if-eqz v1, :cond_3

    .line 43
    .line 44
    sget-object v1, Lqp0/k0;->a:Lqp0/k0;

    .line 45
    .line 46
    goto :goto_0

    .line 47
    :goto_1
    invoke-virtual {v0}, Lqp0/x;->a()Lxj0/f;

    .line 48
    .line 49
    .line 50
    move-result-object v6

    .line 51
    const/16 v17, 0x0

    .line 52
    .line 53
    const/16 v16, 0x0

    .line 54
    .line 55
    const/4 v7, 0x0

    .line 56
    const/4 v8, 0x0

    .line 57
    const/4 v9, 0x0

    .line 58
    const/4 v10, 0x0

    .line 59
    const/4 v11, 0x0

    .line 60
    const/4 v12, 0x0

    .line 61
    const/4 v13, 0x0

    .line 62
    const/4 v14, 0x0

    .line 63
    const/4 v15, 0x0

    .line 64
    const/16 v18, 0x0

    .line 65
    .line 66
    invoke-direct/range {v2 .. v18}, Lqp0/b0;-><init>(Ljava/lang/String;Ljava/lang/String;Lqp0/t0;Lxj0/f;Lbl0/a;Lqr0/d;Lmy0/c;Ljava/lang/Integer;Ljava/lang/Integer;Lmy0/c;Lqp0/a0;Ljava/lang/String;Lqp0/z;Ljava/lang/Boolean;Ljava/lang/Boolean;Lqp0/n;)V

    .line 67
    .line 68
    .line 69
    return-object v2

    .line 70
    :cond_3
    new-instance v0, La8/r0;

    .line 71
    .line 72
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 73
    .line 74
    .line 75
    throw v0
.end method
