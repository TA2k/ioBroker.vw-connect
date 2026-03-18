.class public abstract Ljp/d1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lay0/a;Lay0/a;Lme/d;Ll2/o;I)V
    .locals 13

    .line 1
    move/from16 v1, p4

    .line 2
    .line 3
    move-object/from16 v0, p3

    .line 4
    .line 5
    check-cast v0, Ll2/t;

    .line 6
    .line 7
    const v2, -0x66577bf7

    .line 8
    .line 9
    .line 10
    invoke-virtual {v0, v2}, Ll2/t;->a0(I)Ll2/t;

    .line 11
    .line 12
    .line 13
    and-int/lit8 v2, v1, 0x6

    .line 14
    .line 15
    const/4 v3, 0x4

    .line 16
    if-nez v2, :cond_1

    .line 17
    .line 18
    invoke-virtual {v0, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    if-eqz v2, :cond_0

    .line 23
    .line 24
    move v2, v3

    .line 25
    goto :goto_0

    .line 26
    :cond_0
    const/4 v2, 0x2

    .line 27
    :goto_0
    or-int/2addr v2, v1

    .line 28
    goto :goto_1

    .line 29
    :cond_1
    move v2, v1

    .line 30
    :goto_1
    and-int/lit8 v6, v1, 0x30

    .line 31
    .line 32
    if-nez v6, :cond_3

    .line 33
    .line 34
    invoke-virtual {v0, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 35
    .line 36
    .line 37
    move-result v6

    .line 38
    if-eqz v6, :cond_2

    .line 39
    .line 40
    const/16 v6, 0x20

    .line 41
    .line 42
    goto :goto_2

    .line 43
    :cond_2
    const/16 v6, 0x10

    .line 44
    .line 45
    :goto_2
    or-int/2addr v2, v6

    .line 46
    :cond_3
    and-int/lit16 v6, v1, 0x180

    .line 47
    .line 48
    const/16 v8, 0x100

    .line 49
    .line 50
    if-nez v6, :cond_5

    .line 51
    .line 52
    invoke-virtual {v0, p2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 53
    .line 54
    .line 55
    move-result v6

    .line 56
    if-eqz v6, :cond_4

    .line 57
    .line 58
    move v6, v8

    .line 59
    goto :goto_3

    .line 60
    :cond_4
    const/16 v6, 0x80

    .line 61
    .line 62
    :goto_3
    or-int/2addr v2, v6

    .line 63
    :cond_5
    and-int/lit16 v6, v2, 0x93

    .line 64
    .line 65
    const/16 v9, 0x92

    .line 66
    .line 67
    const/4 v10, 0x0

    .line 68
    const/4 v11, 0x1

    .line 69
    if-eq v6, v9, :cond_6

    .line 70
    .line 71
    move v6, v11

    .line 72
    goto :goto_4

    .line 73
    :cond_6
    move v6, v10

    .line 74
    :goto_4
    and-int/lit8 v9, v2, 0x1

    .line 75
    .line 76
    invoke-virtual {v0, v9, v6}, Ll2/t;->O(IZ)Z

    .line 77
    .line 78
    .line 79
    move-result v6

    .line 80
    if-eqz v6, :cond_b

    .line 81
    .line 82
    invoke-static {p1, v0}, Ll2/b;->s(Ljava/lang/Object;Ll2/o;)Ll2/b1;

    .line 83
    .line 84
    .line 85
    move-result-object v6

    .line 86
    iget-boolean v9, p2, Lme/d;->a:Z

    .line 87
    .line 88
    invoke-static {v9}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 89
    .line 90
    .line 91
    move-result-object v12

    .line 92
    and-int/lit16 v9, v2, 0x380

    .line 93
    .line 94
    if-ne v9, v8, :cond_7

    .line 95
    .line 96
    move v8, v11

    .line 97
    goto :goto_5

    .line 98
    :cond_7
    move v8, v10

    .line 99
    :goto_5
    invoke-virtual {v0, v6}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 100
    .line 101
    .line 102
    move-result v9

    .line 103
    or-int/2addr v8, v9

    .line 104
    and-int/lit8 v2, v2, 0xe

    .line 105
    .line 106
    if-ne v2, v3, :cond_8

    .line 107
    .line 108
    move v10, v11

    .line 109
    :cond_8
    or-int v2, v8, v10

    .line 110
    .line 111
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 112
    .line 113
    .line 114
    move-result-object v3

    .line 115
    if-nez v2, :cond_9

    .line 116
    .line 117
    sget-object v2, Ll2/n;->a:Ll2/x0;

    .line 118
    .line 119
    if-ne v3, v2, :cond_a

    .line 120
    .line 121
    :cond_9
    new-instance v5, Laa/s;

    .line 122
    .line 123
    const/4 v9, 0x0

    .line 124
    const/16 v10, 0x14

    .line 125
    .line 126
    move-object v7, p0

    .line 127
    move-object v8, v6

    .line 128
    move-object v6, p2

    .line 129
    invoke-direct/range {v5 .. v10}, Laa/s;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ll2/b1;Lkotlin/coroutines/Continuation;I)V

    .line 130
    .line 131
    .line 132
    invoke-virtual {v0, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 133
    .line 134
    .line 135
    move-object v3, v5

    .line 136
    :cond_a
    check-cast v3, Lay0/n;

    .line 137
    .line 138
    invoke-static {v3, v12, v0}, Ll2/l0;->d(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 139
    .line 140
    .line 141
    goto :goto_6

    .line 142
    :cond_b
    invoke-virtual {v0}, Ll2/t;->R()V

    .line 143
    .line 144
    .line 145
    :goto_6
    invoke-virtual {v0}, Ll2/t;->s()Ll2/u1;

    .line 146
    .line 147
    .line 148
    move-result-object v6

    .line 149
    if-eqz v6, :cond_c

    .line 150
    .line 151
    new-instance v0, Li50/j0;

    .line 152
    .line 153
    const/16 v2, 0xf

    .line 154
    .line 155
    move-object v3, p0

    .line 156
    move-object v4, p1

    .line 157
    move-object v5, p2

    .line 158
    invoke-direct/range {v0 .. v5}, Li50/j0;-><init>(IILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 159
    .line 160
    .line 161
    iput-object v0, v6, Ll2/u1;->d:Lay0/n;

    .line 162
    .line 163
    :cond_c
    return-void
.end method

.method public static final b(Lay0/a;Ll2/o;I)V
    .locals 19

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move/from16 v1, p2

    .line 4
    .line 5
    const-string v2, "addElectricPlanSelect"

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
    const v2, 0x9c9ad9d

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
    new-instance v3, Lm40/e;

    .line 56
    .line 57
    const/16 v4, 0x18

    .line 58
    .line 59
    invoke-direct {v3, v4}, Lm40/e;-><init>(I)V

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
    new-instance v6, Laf/a;

    .line 110
    .line 111
    const/16 v5, 0x1b

    .line 112
    .line 113
    invoke-direct {v6, v4, v3, v5}, Laf/a;-><init>(Lhi/a;Lay0/k;I)V

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
    const-class v3, Lme/f;

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
    check-cast v13, Lme/f;

    .line 153
    .line 154
    iget-object v3, v13, Lme/f;->e:Lyy0/l1;

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
    move-result-object v3

    .line 164
    check-cast v3, Lme/d;

    .line 165
    .line 166
    invoke-virtual {v8, v13}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 167
    .line 168
    .line 169
    move-result v4

    .line 170
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 171
    .line 172
    .line 173
    move-result-object v5

    .line 174
    if-nez v4, :cond_5

    .line 175
    .line 176
    if-ne v5, v10, :cond_6

    .line 177
    .line 178
    :cond_5
    new-instance v5, Lmc/e;

    .line 179
    .line 180
    const/4 v4, 0x1

    .line 181
    invoke-direct {v5, v13, v4}, Lmc/e;-><init>(Ljava/lang/Object;I)V

    .line 182
    .line 183
    .line 184
    invoke-virtual {v8, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 185
    .line 186
    .line 187
    :cond_6
    check-cast v5, Lay0/a;

    .line 188
    .line 189
    shl-int/lit8 v2, v2, 0x3

    .line 190
    .line 191
    and-int/lit8 v2, v2, 0x70

    .line 192
    .line 193
    invoke-static {v5, v0, v3, v8, v2}, Ljp/d1;->a(Lay0/a;Lay0/a;Lme/d;Ll2/o;I)V

    .line 194
    .line 195
    .line 196
    invoke-static {v8}, Llp/nf;->a(Ll2/o;)Lle/c;

    .line 197
    .line 198
    .line 199
    move-result-object v2

    .line 200
    invoke-virtual {v8, v13}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 201
    .line 202
    .line 203
    move-result v3

    .line 204
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 205
    .line 206
    .line 207
    move-result-object v4

    .line 208
    if-nez v3, :cond_7

    .line 209
    .line 210
    if-ne v4, v10, :cond_8

    .line 211
    .line 212
    :cond_7
    new-instance v11, Ll20/g;

    .line 213
    .line 214
    const/16 v17, 0x0

    .line 215
    .line 216
    const/16 v18, 0xc

    .line 217
    .line 218
    const/4 v12, 0x1

    .line 219
    const-class v14, Lme/f;

    .line 220
    .line 221
    const-string v15, "onUiEvent"

    .line 222
    .line 223
    const-string v16, "onUiEvent(Lcariad/charging/multicharge/kitten/kola/presentation/onboarding/KolaWizardOnboardingUiEvent;)V"

    .line 224
    .line 225
    invoke-direct/range {v11 .. v18}, Ll20/g;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 226
    .line 227
    .line 228
    invoke-virtual {v8, v11}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 229
    .line 230
    .line 231
    move-object v4, v11

    .line 232
    :cond_8
    check-cast v4, Lhy0/g;

    .line 233
    .line 234
    check-cast v4, Lay0/k;

    .line 235
    .line 236
    invoke-interface {v2, v4, v8, v9}, Lle/c;->A(Lay0/k;Ll2/o;I)V

    .line 237
    .line 238
    .line 239
    goto :goto_5

    .line 240
    :cond_9
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 241
    .line 242
    const-string v1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 243
    .line 244
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 245
    .line 246
    .line 247
    throw v0

    .line 248
    :cond_a
    invoke-virtual {v8}, Ll2/t;->R()V

    .line 249
    .line 250
    .line 251
    :goto_5
    invoke-virtual {v8}, Ll2/t;->s()Ll2/u1;

    .line 252
    .line 253
    .line 254
    move-result-object v2

    .line 255
    if-eqz v2, :cond_b

    .line 256
    .line 257
    new-instance v3, Li40/r0;

    .line 258
    .line 259
    const/16 v4, 0x1a

    .line 260
    .line 261
    invoke-direct {v3, v0, v1, v4}, Li40/r0;-><init>(Lay0/a;II)V

    .line 262
    .line 263
    .line 264
    iput-object v3, v2, Ll2/u1;->d:Lay0/n;

    .line 265
    .line 266
    :cond_b
    return-void
.end method

.method public static c(JLij0/a;ZI)Ljava/lang/String;
    .locals 8

    .line 1
    and-int/lit8 v0, p4, 0x2

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    move p3, v1

    .line 7
    :cond_0
    and-int/lit8 p4, p4, 0x4

    .line 8
    .line 9
    if-eqz p4, :cond_1

    .line 10
    .line 11
    const/4 v1, 0x1

    .line 12
    :cond_1
    const-string p4, "stringResource"

    .line 13
    .line 14
    invoke-static {p2, p4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    invoke-static {p0, p1, p2, p3, v1}, Ljp/d1;->g(JLij0/a;ZZ)Ljava/util/ArrayList;

    .line 18
    .line 19
    .line 20
    move-result-object v2

    .line 21
    new-instance v6, Lz70/e0;

    .line 22
    .line 23
    const/16 p0, 0x10

    .line 24
    .line 25
    invoke-direct {v6, p0}, Lz70/e0;-><init>(I)V

    .line 26
    .line 27
    .line 28
    const/16 v7, 0x1e

    .line 29
    .line 30
    const-string v3, " "

    .line 31
    .line 32
    const/4 v4, 0x0

    .line 33
    const/4 v5, 0x0

    .line 34
    invoke-static/range {v2 .. v7}, Lmx0/q;->R(Ljava/lang/Iterable;Ljava/lang/CharSequence;Ljava/lang/String;Ljava/lang/String;Lay0/k;I)Ljava/lang/String;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    return-object p0
.end method

.method public static final d(JLij0/a;)Ljava/lang/String;
    .locals 5

    .line 1
    const-string v0, "stringResource"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget v0, Lmy0/c;->g:I

    .line 7
    .line 8
    sget-object v0, Lmy0/e;->i:Lmy0/e;

    .line 9
    .line 10
    invoke-static {p0, p1, v0}, Lmy0/c;->n(JLmy0/e;)J

    .line 11
    .line 12
    .line 13
    move-result-wide v1

    .line 14
    const-wide/16 v3, 0x64

    .line 15
    .line 16
    cmp-long v1, v1, v3

    .line 17
    .line 18
    if-gez v1, :cond_0

    .line 19
    .line 20
    invoke-static {p0, p1, p2}, Ljp/d1;->f(JLij0/a;)Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    return-object p0

    .line 25
    :cond_0
    const/4 v1, 0x0

    .line 26
    new-array v1, v1, [Ljava/lang/Object;

    .line 27
    .line 28
    check-cast p2, Ljj0/f;

    .line 29
    .line 30
    const v2, 0x7f1203c7

    .line 31
    .line 32
    .line 33
    invoke-virtual {p2, v2, v1}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object p2

    .line 37
    invoke-static {p0, p1, v0}, Lmy0/c;->n(JLmy0/e;)J

    .line 38
    .line 39
    .line 40
    move-result-wide v0

    .line 41
    const/16 v2, 0x3c

    .line 42
    .line 43
    int-to-long v2, v2

    .line 44
    rem-long/2addr v0, v2

    .line 45
    new-instance v2, Ljava/lang/StringBuilder;

    .line 46
    .line 47
    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    .line 48
    .line 49
    .line 50
    sget-object v3, Lmy0/e;->j:Lmy0/e;

    .line 51
    .line 52
    invoke-static {p0, p1, v3}, Lmy0/c;->n(JLmy0/e;)J

    .line 53
    .line 54
    .line 55
    move-result-wide p0

    .line 56
    invoke-static {p0, p1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 57
    .line 58
    .line 59
    move-result-object p0

    .line 60
    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 61
    .line 62
    .line 63
    move-result-object p1

    .line 64
    filled-new-array {p0, p1}, [Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    move-result-object p0

    .line 68
    const/4 p1, 0x2

    .line 69
    invoke-static {p0, p1}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    move-result-object p0

    .line 73
    const-string p1, "%02d:%02d"

    .line 74
    .line 75
    invoke-static {p1, p0}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 76
    .line 77
    .line 78
    move-result-object p0

    .line 79
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 80
    .line 81
    .line 82
    const-string p0, " "

    .line 83
    .line 84
    invoke-virtual {p0, p2}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 85
    .line 86
    .line 87
    move-result-object p0

    .line 88
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 89
    .line 90
    .line 91
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 92
    .line 93
    .line 94
    move-result-object p0

    .line 95
    return-object p0
.end method

.method public static final e(J)Ljava/lang/String;
    .locals 8

    .line 1
    sget v0, Lmy0/c;->g:I

    .line 2
    .line 3
    sget-object v0, Lmy0/e;->j:Lmy0/e;

    .line 4
    .line 5
    invoke-static {p0, p1, v0}, Lmy0/c;->n(JLmy0/e;)J

    .line 6
    .line 7
    .line 8
    move-result-wide v1

    .line 9
    invoke-static {v1, v2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    sget-object v2, Lmy0/e;->i:Lmy0/e;

    .line 14
    .line 15
    invoke-static {p0, p1, v2}, Lmy0/c;->n(JLmy0/e;)J

    .line 16
    .line 17
    .line 18
    move-result-wide v3

    .line 19
    const/4 v5, 0x1

    .line 20
    invoke-static {v5, v0}, Lmy0/h;->s(ILmy0/e;)J

    .line 21
    .line 22
    .line 23
    move-result-wide v6

    .line 24
    invoke-static {v6, v7, v2}, Lmy0/c;->n(JLmy0/e;)J

    .line 25
    .line 26
    .line 27
    move-result-wide v6

    .line 28
    rem-long/2addr v3, v6

    .line 29
    invoke-static {v3, v4}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    sget-object v3, Lmy0/e;->h:Lmy0/e;

    .line 34
    .line 35
    invoke-static {p0, p1, v3}, Lmy0/c;->n(JLmy0/e;)J

    .line 36
    .line 37
    .line 38
    move-result-wide p0

    .line 39
    invoke-static {v5, v2}, Lmy0/h;->s(ILmy0/e;)J

    .line 40
    .line 41
    .line 42
    move-result-wide v4

    .line 43
    invoke-static {v4, v5, v3}, Lmy0/c;->n(JLmy0/e;)J

    .line 44
    .line 45
    .line 46
    move-result-wide v2

    .line 47
    rem-long/2addr p0, v2

    .line 48
    invoke-static {p0, p1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    filled-new-array {v1, v0, p0}, [Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    const/4 p1, 0x3

    .line 57
    invoke-static {p0, p1}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    const-string p1, "%02d:%02d:%02d"

    .line 62
    .line 63
    invoke-static {p1, p0}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 64
    .line 65
    .line 66
    move-result-object p0

    .line 67
    return-object p0
.end method

.method public static final f(JLij0/a;)Ljava/lang/String;
    .locals 4

    .line 1
    const-string v0, "stringResource"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const/4 v0, 0x0

    .line 7
    new-array v0, v0, [Ljava/lang/Object;

    .line 8
    .line 9
    check-cast p2, Ljj0/f;

    .line 10
    .line 11
    const v1, 0x7f1203c8

    .line 12
    .line 13
    .line 14
    invoke-virtual {p2, v1, v0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object p2

    .line 18
    sget v0, Lmy0/c;->g:I

    .line 19
    .line 20
    sget-object v0, Lmy0/e;->h:Lmy0/e;

    .line 21
    .line 22
    invoke-static {p0, p1, v0}, Lmy0/c;->n(JLmy0/e;)J

    .line 23
    .line 24
    .line 25
    move-result-wide v0

    .line 26
    const-wide/16 v2, 0x0

    .line 27
    .line 28
    cmp-long v0, v0, v2

    .line 29
    .line 30
    if-lez v0, :cond_2

    .line 31
    .line 32
    sget-object v0, Lmy0/e;->i:Lmy0/e;

    .line 33
    .line 34
    invoke-static {p0, p1, v0}, Lmy0/c;->n(JLmy0/e;)J

    .line 35
    .line 36
    .line 37
    move-result-wide p0

    .line 38
    invoke-static {p0, p1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    invoke-virtual {p0}, Ljava/lang/Number;->longValue()J

    .line 43
    .line 44
    .line 45
    move-result-wide v0

    .line 46
    cmp-long p1, v0, v2

    .line 47
    .line 48
    if-lez p1, :cond_0

    .line 49
    .line 50
    goto :goto_0

    .line 51
    :cond_0
    const/4 p0, 0x0

    .line 52
    :goto_0
    if-eqz p0, :cond_1

    .line 53
    .line 54
    invoke-virtual {p0}, Ljava/lang/Long;->longValue()J

    .line 55
    .line 56
    .line 57
    move-result-wide v2

    .line 58
    goto :goto_1

    .line 59
    :cond_1
    const-wide/16 v2, 0x1

    .line 60
    .line 61
    :cond_2
    :goto_1
    new-instance p0, Ljava/lang/StringBuilder;

    .line 62
    .line 63
    invoke-direct {p0}, Ljava/lang/StringBuilder;-><init>()V

    .line 64
    .line 65
    .line 66
    new-instance p1, Ljava/lang/StringBuilder;

    .line 67
    .line 68
    invoke-direct {p1}, Ljava/lang/StringBuilder;-><init>()V

    .line 69
    .line 70
    .line 71
    invoke-virtual {p1, v2, v3}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 72
    .line 73
    .line 74
    const-string v0, " "

    .line 75
    .line 76
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 77
    .line 78
    .line 79
    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 80
    .line 81
    .line 82
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 83
    .line 84
    .line 85
    move-result-object p1

    .line 86
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 87
    .line 88
    .line 89
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 90
    .line 91
    .line 92
    move-result-object p0

    .line 93
    return-object p0
.end method

.method public static final g(JLij0/a;ZZ)Ljava/util/ArrayList;
    .locals 16

    .line 1
    move-wide/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v2, p2

    .line 4
    .line 5
    const-string v3, "stringResource"

    .line 6
    .line 7
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    const/4 v3, 0x0

    .line 11
    new-array v4, v3, [Ljava/lang/Object;

    .line 12
    .line 13
    check-cast v2, Ljj0/f;

    .line 14
    .line 15
    const v5, 0x7f1203c6

    .line 16
    .line 17
    .line 18
    invoke-virtual {v2, v5, v4}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object v4

    .line 22
    const v5, 0x7f1203c7

    .line 23
    .line 24
    .line 25
    new-array v6, v3, [Ljava/lang/Object;

    .line 26
    .line 27
    invoke-virtual {v2, v5, v6}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 28
    .line 29
    .line 30
    move-result-object v5

    .line 31
    const v6, 0x7f1203c8

    .line 32
    .line 33
    .line 34
    new-array v7, v3, [Ljava/lang/Object;

    .line 35
    .line 36
    invoke-virtual {v2, v6, v7}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 37
    .line 38
    .line 39
    move-result-object v6

    .line 40
    const v7, 0x7f1203c9

    .line 41
    .line 42
    .line 43
    new-array v3, v3, [Ljava/lang/Object;

    .line 44
    .line 45
    invoke-virtual {v2, v7, v3}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 46
    .line 47
    .line 48
    move-result-object v2

    .line 49
    sget v3, Lmy0/c;->g:I

    .line 50
    .line 51
    sget-object v3, Lmy0/e;->k:Lmy0/e;

    .line 52
    .line 53
    invoke-static {v0, v1, v3}, Lmy0/c;->n(JLmy0/e;)J

    .line 54
    .line 55
    .line 56
    move-result-wide v7

    .line 57
    sget-object v3, Lmy0/e;->j:Lmy0/e;

    .line 58
    .line 59
    invoke-static {v0, v1, v3}, Lmy0/c;->n(JLmy0/e;)J

    .line 60
    .line 61
    .line 62
    move-result-wide v9

    .line 63
    const/16 v3, 0x18

    .line 64
    .line 65
    int-to-long v11, v3

    .line 66
    rem-long/2addr v9, v11

    .line 67
    sget-object v3, Lmy0/e;->i:Lmy0/e;

    .line 68
    .line 69
    invoke-static {v0, v1, v3}, Lmy0/c;->n(JLmy0/e;)J

    .line 70
    .line 71
    .line 72
    move-result-wide v11

    .line 73
    const/16 v3, 0x3c

    .line 74
    .line 75
    int-to-long v13, v3

    .line 76
    rem-long/2addr v11, v13

    .line 77
    sget-object v3, Lmy0/e;->h:Lmy0/e;

    .line 78
    .line 79
    invoke-static {v0, v1, v3}, Lmy0/c;->n(JLmy0/e;)J

    .line 80
    .line 81
    .line 82
    move-result-wide v0

    .line 83
    rem-long/2addr v0, v13

    .line 84
    new-instance v3, Ljava/util/ArrayList;

    .line 85
    .line 86
    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    .line 87
    .line 88
    .line 89
    const-wide/16 v13, 0x0

    .line 90
    .line 91
    cmp-long v15, v7, v13

    .line 92
    .line 93
    if-lez v15, :cond_0

    .line 94
    .line 95
    invoke-static {v7, v8}, Ljava/lang/String;->valueOf(J)Ljava/lang/String;

    .line 96
    .line 97
    .line 98
    move-result-object v7

    .line 99
    new-instance v8, Llx0/l;

    .line 100
    .line 101
    invoke-direct {v8, v7, v4}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 102
    .line 103
    .line 104
    invoke-virtual {v3, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 105
    .line 106
    .line 107
    :cond_0
    cmp-long v4, v9, v13

    .line 108
    .line 109
    if-lez v4, :cond_1

    .line 110
    .line 111
    invoke-static {v9, v10}, Ljava/lang/String;->valueOf(J)Ljava/lang/String;

    .line 112
    .line 113
    .line 114
    move-result-object v4

    .line 115
    new-instance v7, Llx0/l;

    .line 116
    .line 117
    invoke-direct {v7, v4, v5}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 118
    .line 119
    .line 120
    invoke-virtual {v3, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 121
    .line 122
    .line 123
    :cond_1
    cmp-long v4, v11, v13

    .line 124
    .line 125
    if-lez v4, :cond_2

    .line 126
    .line 127
    invoke-static {v11, v12}, Ljava/lang/String;->valueOf(J)Ljava/lang/String;

    .line 128
    .line 129
    .line 130
    move-result-object v4

    .line 131
    new-instance v5, Llx0/l;

    .line 132
    .line 133
    invoke-direct {v5, v4, v6}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 134
    .line 135
    .line 136
    invoke-virtual {v3, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 137
    .line 138
    .line 139
    :cond_2
    if-eqz p3, :cond_3

    .line 140
    .line 141
    cmp-long v4, v0, v13

    .line 142
    .line 143
    if-lez v4, :cond_3

    .line 144
    .line 145
    invoke-static {v0, v1}, Ljava/lang/String;->valueOf(J)Ljava/lang/String;

    .line 146
    .line 147
    .line 148
    move-result-object v4

    .line 149
    new-instance v5, Llx0/l;

    .line 150
    .line 151
    invoke-direct {v5, v4, v2}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 152
    .line 153
    .line 154
    invoke-virtual {v3, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 155
    .line 156
    .line 157
    :cond_3
    invoke-virtual {v3}, Ljava/util/ArrayList;->isEmpty()Z

    .line 158
    .line 159
    .line 160
    move-result v4

    .line 161
    if-eqz v4, :cond_6

    .line 162
    .line 163
    const-string v4, "0"

    .line 164
    .line 165
    if-eqz p3, :cond_4

    .line 166
    .line 167
    new-instance v0, Llx0/l;

    .line 168
    .line 169
    invoke-direct {v0, v4, v2}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 170
    .line 171
    .line 172
    invoke-virtual {v3, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 173
    .line 174
    .line 175
    return-object v3

    .line 176
    :cond_4
    const-wide/16 v7, 0x1

    .line 177
    .line 178
    cmp-long v2, v11, v7

    .line 179
    .line 180
    if-gez v2, :cond_5

    .line 181
    .line 182
    cmp-long v0, v0, v13

    .line 183
    .line 184
    if-lez v0, :cond_5

    .line 185
    .line 186
    if-nez p4, :cond_5

    .line 187
    .line 188
    new-instance v0, Llx0/l;

    .line 189
    .line 190
    const-string v1, "<1"

    .line 191
    .line 192
    invoke-direct {v0, v1, v6}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 193
    .line 194
    .line 195
    invoke-virtual {v3, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 196
    .line 197
    .line 198
    return-object v3

    .line 199
    :cond_5
    new-instance v0, Llx0/l;

    .line 200
    .line 201
    invoke-direct {v0, v4, v6}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 202
    .line 203
    .line 204
    invoke-virtual {v3, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 205
    .line 206
    .line 207
    :cond_6
    return-object v3
.end method


# virtual methods
.method public abstract h([BII)V
.end method
