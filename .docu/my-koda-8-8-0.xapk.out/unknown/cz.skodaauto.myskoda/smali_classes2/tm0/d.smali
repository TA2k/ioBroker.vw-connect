.class public abstract Ltm0/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lye/e;Lle/a;Lay0/a;Lay0/a;Ll2/o;I)V
    .locals 10

    .line 1
    move-object v7, p4

    .line 2
    check-cast v7, Ll2/t;

    .line 3
    .line 4
    const v0, 0x78e818e

    .line 5
    .line 6
    .line 7
    invoke-virtual {v7, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 8
    .line 9
    .line 10
    invoke-virtual {v7, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    const/4 v2, 0x4

    .line 15
    if-eqz v0, :cond_0

    .line 16
    .line 17
    move v0, v2

    .line 18
    goto :goto_0

    .line 19
    :cond_0
    const/4 v0, 0x2

    .line 20
    :goto_0
    or-int/2addr v0, p5

    .line 21
    invoke-virtual {v7, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    move-result v3

    .line 25
    if-eqz v3, :cond_1

    .line 26
    .line 27
    const/16 v3, 0x20

    .line 28
    .line 29
    goto :goto_1

    .line 30
    :cond_1
    const/16 v3, 0x10

    .line 31
    .line 32
    :goto_1
    or-int/2addr v0, v3

    .line 33
    invoke-virtual {v7, p2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 34
    .line 35
    .line 36
    move-result v3

    .line 37
    if-eqz v3, :cond_2

    .line 38
    .line 39
    const/16 v3, 0x100

    .line 40
    .line 41
    goto :goto_2

    .line 42
    :cond_2
    const/16 v3, 0x80

    .line 43
    .line 44
    :goto_2
    or-int/2addr v0, v3

    .line 45
    invoke-virtual {v7, p3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 46
    .line 47
    .line 48
    move-result v3

    .line 49
    const/16 v5, 0x800

    .line 50
    .line 51
    if-eqz v3, :cond_3

    .line 52
    .line 53
    move v3, v5

    .line 54
    goto :goto_3

    .line 55
    :cond_3
    const/16 v3, 0x400

    .line 56
    .line 57
    :goto_3
    or-int/2addr v0, v3

    .line 58
    and-int/lit16 v3, v0, 0x493

    .line 59
    .line 60
    const/16 v6, 0x492

    .line 61
    .line 62
    const/4 v8, 0x0

    .line 63
    const/4 v9, 0x1

    .line 64
    if-eq v3, v6, :cond_4

    .line 65
    .line 66
    move v3, v9

    .line 67
    goto :goto_4

    .line 68
    :cond_4
    move v3, v8

    .line 69
    :goto_4
    and-int/lit8 v6, v0, 0x1

    .line 70
    .line 71
    invoke-virtual {v7, v6, v3}, Ll2/t;->O(IZ)Z

    .line 72
    .line 73
    .line 74
    move-result v3

    .line 75
    if-eqz v3, :cond_9

    .line 76
    .line 77
    invoke-static {p1, v7}, Ll2/b;->s(Ljava/lang/Object;Ll2/o;)Ll2/b1;

    .line 78
    .line 79
    .line 80
    move-result-object v3

    .line 81
    invoke-static {p2, v7}, Ll2/b;->s(Ljava/lang/Object;Ll2/o;)Ll2/b1;

    .line 82
    .line 83
    .line 84
    move-result-object v4

    .line 85
    and-int/lit8 v6, v0, 0xe

    .line 86
    .line 87
    if-ne v6, v2, :cond_5

    .line 88
    .line 89
    move v2, v9

    .line 90
    goto :goto_5

    .line 91
    :cond_5
    move v2, v8

    .line 92
    :goto_5
    invoke-virtual {v7, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 93
    .line 94
    .line 95
    move-result v6

    .line 96
    or-int/2addr v2, v6

    .line 97
    and-int/lit16 v0, v0, 0x1c00

    .line 98
    .line 99
    if-ne v0, v5, :cond_6

    .line 100
    .line 101
    move v8, v9

    .line 102
    :cond_6
    or-int v0, v2, v8

    .line 103
    .line 104
    invoke-virtual {v7, v4}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 105
    .line 106
    .line 107
    move-result v2

    .line 108
    or-int/2addr v0, v2

    .line 109
    invoke-virtual {v7}, Ll2/t;->L()Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    move-result-object v2

    .line 113
    if-nez v0, :cond_7

    .line 114
    .line 115
    sget-object v0, Ll2/n;->a:Ll2/x0;

    .line 116
    .line 117
    if-ne v2, v0, :cond_8

    .line 118
    .line 119
    :cond_7
    new-instance v0, Lff/a;

    .line 120
    .line 121
    const/4 v5, 0x0

    .line 122
    const/16 v6, 0xe

    .line 123
    .line 124
    move-object v1, p0

    .line 125
    move-object v2, p3

    .line 126
    invoke-direct/range {v0 .. v6}, Lff/a;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 127
    .line 128
    .line 129
    invoke-virtual {v7, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 130
    .line 131
    .line 132
    move-object v2, v0

    .line 133
    :cond_8
    check-cast v2, Lay0/n;

    .line 134
    .line 135
    invoke-static {v2, p0, v7}, Ll2/l0;->d(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 136
    .line 137
    .line 138
    goto :goto_6

    .line 139
    :cond_9
    invoke-virtual {v7}, Ll2/t;->R()V

    .line 140
    .line 141
    .line 142
    :goto_6
    invoke-virtual {v7}, Ll2/t;->s()Ll2/u1;

    .line 143
    .line 144
    .line 145
    move-result-object v7

    .line 146
    if-eqz v7, :cond_a

    .line 147
    .line 148
    new-instance v0, Lx40/c;

    .line 149
    .line 150
    const/16 v6, 0xa

    .line 151
    .line 152
    move-object v1, p0

    .line 153
    move-object v2, p1

    .line 154
    move-object v3, p2

    .line 155
    move-object v4, p3

    .line 156
    move v5, p5

    .line 157
    invoke-direct/range {v0 .. v6}, Lx40/c;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;II)V

    .line 158
    .line 159
    .line 160
    iput-object v0, v7, Ll2/u1;->d:Lay0/n;

    .line 161
    .line 162
    :cond_a
    return-void
.end method

.method public static final b(Lqe/a;Lle/a;Lay0/a;Ll2/o;I)V
    .locals 20

    .line 1
    move-object/from16 v3, p0

    .line 2
    .line 3
    move-object/from16 v5, p2

    .line 4
    .line 5
    const-string v0, "season"

    .line 6
    .line 7
    invoke-static {v3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    const-string v0, "noDaysSelect"

    .line 11
    .line 12
    invoke-static {v5, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    move-object/from16 v11, p3

    .line 16
    .line 17
    check-cast v11, Ll2/t;

    .line 18
    .line 19
    const v0, 0x32759c4b

    .line 20
    .line 21
    .line 22
    invoke-virtual {v11, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 23
    .line 24
    .line 25
    invoke-virtual {v3}, Ljava/lang/Enum;->ordinal()I

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    invoke-virtual {v11, v0}, Ll2/t;->e(I)Z

    .line 30
    .line 31
    .line 32
    move-result v0

    .line 33
    if-eqz v0, :cond_0

    .line 34
    .line 35
    const/4 v0, 0x4

    .line 36
    goto :goto_0

    .line 37
    :cond_0
    const/4 v0, 0x2

    .line 38
    :goto_0
    or-int v0, p4, v0

    .line 39
    .line 40
    move-object/from16 v4, p1

    .line 41
    .line 42
    invoke-virtual {v11, v4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 43
    .line 44
    .line 45
    move-result v1

    .line 46
    if-eqz v1, :cond_1

    .line 47
    .line 48
    const/16 v1, 0x20

    .line 49
    .line 50
    goto :goto_1

    .line 51
    :cond_1
    const/16 v1, 0x10

    .line 52
    .line 53
    :goto_1
    or-int/2addr v0, v1

    .line 54
    invoke-virtual {v11, v5}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 55
    .line 56
    .line 57
    move-result v1

    .line 58
    if-eqz v1, :cond_2

    .line 59
    .line 60
    const/16 v1, 0x100

    .line 61
    .line 62
    goto :goto_2

    .line 63
    :cond_2
    const/16 v1, 0x80

    .line 64
    .line 65
    :goto_2
    or-int/2addr v0, v1

    .line 66
    and-int/lit16 v1, v0, 0x93

    .line 67
    .line 68
    const/16 v2, 0x92

    .line 69
    .line 70
    const/4 v6, 0x0

    .line 71
    if-eq v1, v2, :cond_3

    .line 72
    .line 73
    const/4 v1, 0x1

    .line 74
    goto :goto_3

    .line 75
    :cond_3
    move v1, v6

    .line 76
    :goto_3
    and-int/lit8 v2, v0, 0x1

    .line 77
    .line 78
    invoke-virtual {v11, v2, v1}, Ll2/t;->O(IZ)Z

    .line 79
    .line 80
    .line 81
    move-result v1

    .line 82
    if-eqz v1, :cond_c

    .line 83
    .line 84
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    move-result-object v1

    .line 88
    sget-object v2, Ll2/n;->a:Ll2/x0;

    .line 89
    .line 90
    if-ne v1, v2, :cond_4

    .line 91
    .line 92
    new-instance v1, Lxy/f;

    .line 93
    .line 94
    const/16 v7, 0xa

    .line 95
    .line 96
    invoke-direct {v1, v7}, Lxy/f;-><init>(I)V

    .line 97
    .line 98
    .line 99
    invoke-virtual {v11, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 100
    .line 101
    .line 102
    :cond_4
    check-cast v1, Lay0/k;

    .line 103
    .line 104
    sget-object v7, Lw3/q1;->a:Ll2/u2;

    .line 105
    .line 106
    invoke-virtual {v11, v7}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 107
    .line 108
    .line 109
    move-result-object v7

    .line 110
    check-cast v7, Ljava/lang/Boolean;

    .line 111
    .line 112
    invoke-virtual {v7}, Ljava/lang/Boolean;->booleanValue()Z

    .line 113
    .line 114
    .line 115
    move-result v7

    .line 116
    if-eqz v7, :cond_5

    .line 117
    .line 118
    const v7, -0x105bcaaa

    .line 119
    .line 120
    .line 121
    invoke-virtual {v11, v7}, Ll2/t;->Y(I)V

    .line 122
    .line 123
    .line 124
    invoke-virtual {v11, v6}, Ll2/t;->q(Z)V

    .line 125
    .line 126
    .line 127
    const/4 v6, 0x0

    .line 128
    goto :goto_4

    .line 129
    :cond_5
    const v7, 0x31054eee

    .line 130
    .line 131
    .line 132
    invoke-virtual {v11, v7}, Ll2/t;->Y(I)V

    .line 133
    .line 134
    .line 135
    sget-object v7, Lzb/x;->a:Ll2/u2;

    .line 136
    .line 137
    invoke-virtual {v11, v7}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 138
    .line 139
    .line 140
    move-result-object v7

    .line 141
    check-cast v7, Lhi/a;

    .line 142
    .line 143
    invoke-virtual {v11, v6}, Ll2/t;->q(Z)V

    .line 144
    .line 145
    .line 146
    move-object v6, v7

    .line 147
    :goto_4
    new-instance v9, Lvh/i;

    .line 148
    .line 149
    const/4 v7, 0x7

    .line 150
    invoke-direct {v9, v7, v6, v1}, Lvh/i;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 151
    .line 152
    .line 153
    invoke-static {v11}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 154
    .line 155
    .line 156
    move-result-object v7

    .line 157
    if-eqz v7, :cond_b

    .line 158
    .line 159
    instance-of v1, v7, Landroidx/lifecycle/k;

    .line 160
    .line 161
    if-eqz v1, :cond_6

    .line 162
    .line 163
    move-object v1, v7

    .line 164
    check-cast v1, Landroidx/lifecycle/k;

    .line 165
    .line 166
    invoke-interface {v1}, Landroidx/lifecycle/k;->getDefaultViewModelCreationExtras()Lp7/c;

    .line 167
    .line 168
    .line 169
    move-result-object v1

    .line 170
    :goto_5
    move-object v10, v1

    .line 171
    goto :goto_6

    .line 172
    :cond_6
    sget-object v1, Lp7/a;->b:Lp7/a;

    .line 173
    .line 174
    goto :goto_5

    .line 175
    :goto_6
    const-class v1, Lye/f;

    .line 176
    .line 177
    sget-object v6, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 178
    .line 179
    invoke-virtual {v6, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 180
    .line 181
    .line 182
    move-result-object v6

    .line 183
    const/4 v8, 0x0

    .line 184
    invoke-static/range {v6 .. v11}, Ljp/se;->b(Lhy0/d;Landroidx/lifecycle/i1;Ljava/lang/String;Landroidx/lifecycle/e1;Lp7/c;Ll2/o;)Landroidx/lifecycle/b1;

    .line 185
    .line 186
    .line 187
    move-result-object v1

    .line 188
    move-object v14, v1

    .line 189
    check-cast v14, Lye/f;

    .line 190
    .line 191
    iget-object v1, v14, Lye/f;->e:Lyy0/l1;

    .line 192
    .line 193
    invoke-static {v1, v11}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 194
    .line 195
    .line 196
    move-result-object v1

    .line 197
    invoke-interface {v1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 198
    .line 199
    .line 200
    move-result-object v1

    .line 201
    check-cast v1, Lye/e;

    .line 202
    .line 203
    invoke-virtual {v11, v14}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 204
    .line 205
    .line 206
    move-result v6

    .line 207
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 208
    .line 209
    .line 210
    move-result-object v7

    .line 211
    if-nez v6, :cond_7

    .line 212
    .line 213
    if-ne v7, v2, :cond_8

    .line 214
    .line 215
    :cond_7
    new-instance v7, Ly1/i;

    .line 216
    .line 217
    const/4 v6, 0x7

    .line 218
    invoke-direct {v7, v14, v6}, Ly1/i;-><init>(Ljava/lang/Object;I)V

    .line 219
    .line 220
    .line 221
    invoke-virtual {v11, v7}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 222
    .line 223
    .line 224
    :cond_8
    check-cast v7, Lay0/a;

    .line 225
    .line 226
    and-int/lit16 v9, v0, 0x3f0

    .line 227
    .line 228
    move-object v6, v5

    .line 229
    move-object v8, v11

    .line 230
    move-object v5, v4

    .line 231
    move-object v4, v1

    .line 232
    invoke-static/range {v4 .. v9}, Ltm0/d;->a(Lye/e;Lle/a;Lay0/a;Lay0/a;Ll2/o;I)V

    .line 233
    .line 234
    .line 235
    invoke-static {v11}, Llp/nf;->a(Ll2/o;)Lle/c;

    .line 236
    .line 237
    .line 238
    move-result-object v1

    .line 239
    invoke-virtual {v11, v14}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 240
    .line 241
    .line 242
    move-result v4

    .line 243
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 244
    .line 245
    .line 246
    move-result-object v5

    .line 247
    if-nez v4, :cond_9

    .line 248
    .line 249
    if-ne v5, v2, :cond_a

    .line 250
    .line 251
    :cond_9
    new-instance v12, Ly21/d;

    .line 252
    .line 253
    const/16 v18, 0x0

    .line 254
    .line 255
    const/16 v19, 0x7

    .line 256
    .line 257
    const/4 v13, 0x1

    .line 258
    const-class v15, Lye/f;

    .line 259
    .line 260
    const-string v16, "onUiEvent"

    .line 261
    .line 262
    const-string v17, "onUiEvent(Lcariad/charging/multicharge/kitten/kola/presentation/wizard/multiplefixedrate/daysselection/KolaWizardDaysSelectionUiEvent;)V"

    .line 263
    .line 264
    invoke-direct/range {v12 .. v19}, Ly21/d;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 265
    .line 266
    .line 267
    invoke-virtual {v11, v12}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 268
    .line 269
    .line 270
    move-object v5, v12

    .line 271
    :cond_a
    check-cast v5, Lhy0/g;

    .line 272
    .line 273
    check-cast v5, Lay0/k;

    .line 274
    .line 275
    and-int/lit8 v0, v0, 0xe

    .line 276
    .line 277
    invoke-interface {v1, v3, v5, v11, v0}, Lle/c;->d(Lqe/a;Lay0/k;Ll2/o;I)V

    .line 278
    .line 279
    .line 280
    goto :goto_7

    .line 281
    :cond_b
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 282
    .line 283
    const-string v1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 284
    .line 285
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 286
    .line 287
    .line 288
    throw v0

    .line 289
    :cond_c
    invoke-virtual {v11}, Ll2/t;->R()V

    .line 290
    .line 291
    .line 292
    :goto_7
    invoke-virtual {v11}, Ll2/t;->s()Ll2/u1;

    .line 293
    .line 294
    .line 295
    move-result-object v6

    .line 296
    if-eqz v6, :cond_d

    .line 297
    .line 298
    new-instance v0, Luj/j0;

    .line 299
    .line 300
    const/16 v2, 0x18

    .line 301
    .line 302
    move-object/from16 v4, p1

    .line 303
    .line 304
    move-object/from16 v5, p2

    .line 305
    .line 306
    move/from16 v1, p4

    .line 307
    .line 308
    invoke-direct/range {v0 .. v5}, Luj/j0;-><init>(IILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 309
    .line 310
    .line 311
    iput-object v0, v6, Ll2/u1;->d:Lay0/n;

    .line 312
    .line 313
    :cond_d
    return-void
.end method

.method public static final c(Ljava/util/regex/Matcher;ILjava/lang/CharSequence;)Lly0/l;
    .locals 0

    .line 1
    invoke-virtual {p0, p1}, Ljava/util/regex/Matcher;->find(I)Z

    .line 2
    .line 3
    .line 4
    move-result p1

    .line 5
    if-nez p1, :cond_0

    .line 6
    .line 7
    const/4 p0, 0x0

    .line 8
    return-object p0

    .line 9
    :cond_0
    new-instance p1, Lly0/l;

    .line 10
    .line 11
    invoke-direct {p1, p0, p2}, Lly0/l;-><init>(Ljava/util/regex/Matcher;Ljava/lang/CharSequence;)V

    .line 12
    .line 13
    .line 14
    return-object p1
.end method
