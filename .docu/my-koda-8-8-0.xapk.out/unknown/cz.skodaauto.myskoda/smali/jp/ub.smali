.class public abstract Ljp/ub;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lfh/f;Lay0/a;Lay0/a;Ll2/o;I)V
    .locals 10

    .line 1
    move-object v6, p3

    .line 2
    check-cast v6, Ll2/t;

    .line 3
    .line 4
    const v0, -0x24fa8caf

    .line 5
    .line 6
    .line 7
    invoke-virtual {v6, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 8
    .line 9
    .line 10
    invoke-virtual {v6, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

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
    or-int/2addr v0, p4

    .line 21
    invoke-virtual {v6, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

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
    invoke-virtual {v6, p2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 34
    .line 35
    .line 36
    move-result v3

    .line 37
    const/16 v4, 0x100

    .line 38
    .line 39
    if-eqz v3, :cond_2

    .line 40
    .line 41
    move v3, v4

    .line 42
    goto :goto_2

    .line 43
    :cond_2
    const/16 v3, 0x80

    .line 44
    .line 45
    :goto_2
    or-int/2addr v0, v3

    .line 46
    and-int/lit16 v3, v0, 0x93

    .line 47
    .line 48
    const/16 v7, 0x92

    .line 49
    .line 50
    const/4 v8, 0x0

    .line 51
    const/4 v9, 0x1

    .line 52
    if-eq v3, v7, :cond_3

    .line 53
    .line 54
    move v3, v9

    .line 55
    goto :goto_3

    .line 56
    :cond_3
    move v3, v8

    .line 57
    :goto_3
    and-int/lit8 v7, v0, 0x1

    .line 58
    .line 59
    invoke-virtual {v6, v7, v3}, Ll2/t;->O(IZ)Z

    .line 60
    .line 61
    .line 62
    move-result v3

    .line 63
    if-eqz v3, :cond_8

    .line 64
    .line 65
    invoke-static {p1, v6}, Ll2/b;->s(Ljava/lang/Object;Ll2/o;)Ll2/b1;

    .line 66
    .line 67
    .line 68
    move-result-object v3

    .line 69
    and-int/lit8 v7, v0, 0xe

    .line 70
    .line 71
    if-ne v7, v2, :cond_4

    .line 72
    .line 73
    move v2, v9

    .line 74
    goto :goto_4

    .line 75
    :cond_4
    move v2, v8

    .line 76
    :goto_4
    invoke-virtual {v6, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 77
    .line 78
    .line 79
    move-result v7

    .line 80
    or-int/2addr v2, v7

    .line 81
    and-int/lit16 v0, v0, 0x380

    .line 82
    .line 83
    if-ne v0, v4, :cond_5

    .line 84
    .line 85
    move v8, v9

    .line 86
    :cond_5
    or-int v0, v2, v8

    .line 87
    .line 88
    invoke-virtual {v6}, Ll2/t;->L()Ljava/lang/Object;

    .line 89
    .line 90
    .line 91
    move-result-object v2

    .line 92
    if-nez v0, :cond_6

    .line 93
    .line 94
    sget-object v0, Ll2/n;->a:Ll2/x0;

    .line 95
    .line 96
    if-ne v2, v0, :cond_7

    .line 97
    .line 98
    :cond_6
    new-instance v0, Laa/s;

    .line 99
    .line 100
    const/4 v4, 0x0

    .line 101
    const/16 v5, 0x1b

    .line 102
    .line 103
    move-object v1, p0

    .line 104
    move-object v2, p2

    .line 105
    invoke-direct/range {v0 .. v5}, Laa/s;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ll2/b1;Lkotlin/coroutines/Continuation;I)V

    .line 106
    .line 107
    .line 108
    invoke-virtual {v6, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 109
    .line 110
    .line 111
    move-object v2, v0

    .line 112
    :cond_7
    check-cast v2, Lay0/n;

    .line 113
    .line 114
    invoke-static {v2, p0, v6}, Ll2/l0;->d(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 115
    .line 116
    .line 117
    goto :goto_5

    .line 118
    :cond_8
    invoke-virtual {v6}, Ll2/t;->R()V

    .line 119
    .line 120
    .line 121
    :goto_5
    invoke-virtual {v6}, Ll2/t;->s()Ll2/u1;

    .line 122
    .line 123
    .line 124
    move-result-object v6

    .line 125
    if-eqz v6, :cond_9

    .line 126
    .line 127
    new-instance v0, Li91/k3;

    .line 128
    .line 129
    const/16 v2, 0x1b

    .line 130
    .line 131
    move-object v3, p0

    .line 132
    move-object v4, p1

    .line 133
    move-object v5, p2

    .line 134
    move v1, p4

    .line 135
    invoke-direct/range {v0 .. v5}, Li91/k3;-><init>(IILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 136
    .line 137
    .line 138
    iput-object v0, v6, Ll2/u1;->d:Lay0/n;

    .line 139
    .line 140
    :cond_9
    return-void
.end method

.method public static final b(ZLay0/n;Ll2/o;I)V
    .locals 8

    .line 1
    check-cast p2, Ll2/t;

    .line 2
    .line 3
    const v0, -0x264426c9

    .line 4
    .line 5
    .line 6
    invoke-virtual {p2, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    and-int/lit8 v0, p3, 0x6

    .line 10
    .line 11
    const/4 v1, 0x4

    .line 12
    if-nez v0, :cond_1

    .line 13
    .line 14
    invoke-virtual {p2, p0}, Ll2/t;->h(Z)Z

    .line 15
    .line 16
    .line 17
    move-result v0

    .line 18
    if-eqz v0, :cond_0

    .line 19
    .line 20
    move v0, v1

    .line 21
    goto :goto_0

    .line 22
    :cond_0
    const/4 v0, 0x2

    .line 23
    :goto_0
    or-int/2addr v0, p3

    .line 24
    goto :goto_1

    .line 25
    :cond_1
    move v0, p3

    .line 26
    :goto_1
    and-int/lit8 v2, p3, 0x30

    .line 27
    .line 28
    if-nez v2, :cond_3

    .line 29
    .line 30
    invoke-virtual {p2, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 31
    .line 32
    .line 33
    move-result v2

    .line 34
    if-eqz v2, :cond_2

    .line 35
    .line 36
    const/16 v2, 0x20

    .line 37
    .line 38
    goto :goto_2

    .line 39
    :cond_2
    const/16 v2, 0x10

    .line 40
    .line 41
    :goto_2
    or-int/2addr v0, v2

    .line 42
    :cond_3
    and-int/lit8 v2, v0, 0x13

    .line 43
    .line 44
    const/16 v3, 0x12

    .line 45
    .line 46
    if-ne v2, v3, :cond_5

    .line 47
    .line 48
    invoke-virtual {p2}, Ll2/t;->A()Z

    .line 49
    .line 50
    .line 51
    move-result v2

    .line 52
    if-nez v2, :cond_4

    .line 53
    .line 54
    goto :goto_3

    .line 55
    :cond_4
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 56
    .line 57
    .line 58
    goto/16 :goto_5

    .line 59
    .line 60
    :cond_5
    :goto_3
    invoke-static {p1, p2}, Ll2/b;->s(Ljava/lang/Object;Ll2/o;)Ll2/b1;

    .line 61
    .line 62
    .line 63
    move-result-object v2

    .line 64
    invoke-virtual {p2}, Ll2/t;->L()Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    move-result-object v3

    .line 68
    sget-object v4, Ll2/n;->a:Ll2/x0;

    .line 69
    .line 70
    if-ne v3, v4, :cond_6

    .line 71
    .line 72
    invoke-static {p2}, Ll2/l0;->h(Ll2/o;)Lvy0/b0;

    .line 73
    .line 74
    .line 75
    move-result-object v3

    .line 76
    new-instance v5, Ll2/d0;

    .line 77
    .line 78
    invoke-direct {v5, v3}, Ll2/d0;-><init>(Lvy0/b0;)V

    .line 79
    .line 80
    .line 81
    invoke-virtual {p2, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 82
    .line 83
    .line 84
    move-object v3, v5

    .line 85
    :cond_6
    check-cast v3, Ll2/d0;

    .line 86
    .line 87
    iget-object v3, v3, Ll2/d0;->d:Lvy0/b0;

    .line 88
    .line 89
    invoke-virtual {p2}, Ll2/t;->L()Ljava/lang/Object;

    .line 90
    .line 91
    .line 92
    move-result-object v5

    .line 93
    if-ne v5, v4, :cond_7

    .line 94
    .line 95
    new-instance v5, Lc/l;

    .line 96
    .line 97
    invoke-interface {v2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 98
    .line 99
    .line 100
    move-result-object v6

    .line 101
    check-cast v6, Lay0/n;

    .line 102
    .line 103
    invoke-direct {v5, p0}, Lb/a0;-><init>(Z)V

    .line 104
    .line 105
    .line 106
    iput-object v3, v5, Lc/l;->b:Lvy0/b0;

    .line 107
    .line 108
    iput-object v6, v5, Lc/l;->c:Lay0/n;

    .line 109
    .line 110
    invoke-virtual {p2, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 111
    .line 112
    .line 113
    :cond_7
    check-cast v5, Lc/l;

    .line 114
    .line 115
    invoke-interface {v2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 116
    .line 117
    .line 118
    move-result-object v6

    .line 119
    check-cast v6, Lay0/n;

    .line 120
    .line 121
    invoke-virtual {p2, v6}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 122
    .line 123
    .line 124
    move-result v6

    .line 125
    invoke-virtual {p2, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 126
    .line 127
    .line 128
    move-result v7

    .line 129
    or-int/2addr v6, v7

    .line 130
    invoke-virtual {p2}, Ll2/t;->L()Ljava/lang/Object;

    .line 131
    .line 132
    .line 133
    move-result-object v7

    .line 134
    if-nez v6, :cond_8

    .line 135
    .line 136
    if-ne v7, v4, :cond_9

    .line 137
    .line 138
    :cond_8
    invoke-interface {v2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 139
    .line 140
    .line 141
    move-result-object v2

    .line 142
    check-cast v2, Lay0/n;

    .line 143
    .line 144
    iput-object v2, v5, Lc/l;->c:Lay0/n;

    .line 145
    .line 146
    iput-object v3, v5, Lc/l;->b:Lvy0/b0;

    .line 147
    .line 148
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 149
    .line 150
    invoke-virtual {p2, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 151
    .line 152
    .line 153
    :cond_9
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 154
    .line 155
    .line 156
    move-result-object v2

    .line 157
    invoke-virtual {p2, v5}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 158
    .line 159
    .line 160
    move-result v3

    .line 161
    and-int/lit8 v0, v0, 0xe

    .line 162
    .line 163
    if-ne v0, v1, :cond_a

    .line 164
    .line 165
    const/4 v0, 0x1

    .line 166
    goto :goto_4

    .line 167
    :cond_a
    const/4 v0, 0x0

    .line 168
    :goto_4
    or-int/2addr v0, v3

    .line 169
    invoke-virtual {p2}, Ll2/t;->L()Ljava/lang/Object;

    .line 170
    .line 171
    .line 172
    move-result-object v1

    .line 173
    if-nez v0, :cond_b

    .line 174
    .line 175
    if-ne v1, v4, :cond_c

    .line 176
    .line 177
    :cond_b
    new-instance v1, Lc/m;

    .line 178
    .line 179
    const/4 v0, 0x0

    .line 180
    const/4 v3, 0x0

    .line 181
    invoke-direct {v1, v5, p0, v0, v3}, Lc/m;-><init>(Ljava/lang/Object;ZLkotlin/coroutines/Continuation;I)V

    .line 182
    .line 183
    .line 184
    invoke-virtual {p2, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 185
    .line 186
    .line 187
    :cond_c
    check-cast v1, Lay0/n;

    .line 188
    .line 189
    invoke-static {v1, v2, p2}, Ll2/l0;->d(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 190
    .line 191
    .line 192
    invoke-static {p2}, Lc/j;->a(Ll2/o;)Lb/j0;

    .line 193
    .line 194
    .line 195
    move-result-object v0

    .line 196
    if-eqz v0, :cond_10

    .line 197
    .line 198
    invoke-interface {v0}, Lb/j0;->getOnBackPressedDispatcher()Lb/h0;

    .line 199
    .line 200
    .line 201
    move-result-object v0

    .line 202
    invoke-static {}, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->getLocalLifecycleOwner()Ll2/s1;

    .line 203
    .line 204
    .line 205
    move-result-object v1

    .line 206
    invoke-virtual {p2, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 207
    .line 208
    .line 209
    move-result-object v1

    .line 210
    check-cast v1, Landroidx/lifecycle/x;

    .line 211
    .line 212
    invoke-virtual {p2, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 213
    .line 214
    .line 215
    move-result v2

    .line 216
    invoke-virtual {p2, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 217
    .line 218
    .line 219
    move-result v3

    .line 220
    or-int/2addr v2, v3

    .line 221
    invoke-virtual {p2, v5}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 222
    .line 223
    .line 224
    move-result v3

    .line 225
    or-int/2addr v2, v3

    .line 226
    invoke-virtual {p2}, Ll2/t;->L()Ljava/lang/Object;

    .line 227
    .line 228
    .line 229
    move-result-object v3

    .line 230
    if-nez v2, :cond_d

    .line 231
    .line 232
    if-ne v3, v4, :cond_e

    .line 233
    .line 234
    :cond_d
    new-instance v3, Laa/o;

    .line 235
    .line 236
    const/4 v2, 0x4

    .line 237
    invoke-direct {v3, v0, v1, v5, v2}, Laa/o;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 238
    .line 239
    .line 240
    invoke-virtual {p2, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 241
    .line 242
    .line 243
    :cond_e
    check-cast v3, Lay0/k;

    .line 244
    .line 245
    invoke-static {v1, v0, v3, p2}, Ll2/l0;->b(Ljava/lang/Object;Ljava/lang/Object;Lay0/k;Ll2/o;)V

    .line 246
    .line 247
    .line 248
    :goto_5
    invoke-virtual {p2}, Ll2/t;->s()Ll2/u1;

    .line 249
    .line 250
    .line 251
    move-result-object p2

    .line 252
    if-eqz p2, :cond_f

    .line 253
    .line 254
    new-instance v0, La71/e0;

    .line 255
    .line 256
    const/4 v1, 0x2

    .line 257
    invoke-direct {v0, p0, p1, p3, v1}, La71/e0;-><init>(ZLlx0/e;II)V

    .line 258
    .line 259
    .line 260
    iput-object v0, p2, Ll2/u1;->d:Lay0/n;

    .line 261
    .line 262
    :cond_f
    return-void

    .line 263
    :cond_10
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 264
    .line 265
    const-string p1, "No OnBackPressedDispatcherOwner was provided via LocalOnBackPressedDispatcherOwner"

    .line 266
    .line 267
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 268
    .line 269
    .line 270
    throw p0
.end method

.method public static final c(Ldi/a;Lay0/a;Ll2/o;I)V
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
    const-string v3, "authorizationSaved"

    .line 8
    .line 9
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    move-object/from16 v9, p2

    .line 13
    .line 14
    check-cast v9, Ll2/t;

    .line 15
    .line 16
    const v3, -0x4a126729

    .line 17
    .line 18
    .line 19
    invoke-virtual {v9, v3}, Ll2/t;->a0(I)Ll2/t;

    .line 20
    .line 21
    .line 22
    invoke-virtual {v9, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 23
    .line 24
    .line 25
    move-result v3

    .line 26
    const/4 v4, 0x4

    .line 27
    if-eqz v3, :cond_0

    .line 28
    .line 29
    move v3, v4

    .line 30
    goto :goto_0

    .line 31
    :cond_0
    const/4 v3, 0x2

    .line 32
    :goto_0
    or-int/2addr v3, v2

    .line 33
    invoke-virtual {v9, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 34
    .line 35
    .line 36
    move-result v5

    .line 37
    if-eqz v5, :cond_1

    .line 38
    .line 39
    const/16 v5, 0x20

    .line 40
    .line 41
    goto :goto_1

    .line 42
    :cond_1
    const/16 v5, 0x10

    .line 43
    .line 44
    :goto_1
    or-int/2addr v3, v5

    .line 45
    and-int/lit8 v5, v3, 0x13

    .line 46
    .line 47
    const/16 v6, 0x12

    .line 48
    .line 49
    const/4 v7, 0x1

    .line 50
    const/4 v10, 0x0

    .line 51
    if-eq v5, v6, :cond_2

    .line 52
    .line 53
    move v5, v7

    .line 54
    goto :goto_2

    .line 55
    :cond_2
    move v5, v10

    .line 56
    :goto_2
    and-int/lit8 v6, v3, 0x1

    .line 57
    .line 58
    invoke-virtual {v9, v6, v5}, Ll2/t;->O(IZ)Z

    .line 59
    .line 60
    .line 61
    move-result v5

    .line 62
    if-eqz v5, :cond_d

    .line 63
    .line 64
    and-int/lit8 v5, v3, 0xe

    .line 65
    .line 66
    if-ne v5, v4, :cond_3

    .line 67
    .line 68
    goto :goto_3

    .line 69
    :cond_3
    move v7, v10

    .line 70
    :goto_3
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object v4

    .line 74
    sget-object v11, Ll2/n;->a:Ll2/x0;

    .line 75
    .line 76
    if-nez v7, :cond_4

    .line 77
    .line 78
    if-ne v4, v11, :cond_5

    .line 79
    .line 80
    :cond_4
    new-instance v4, Lfh/a;

    .line 81
    .line 82
    const/4 v5, 0x1

    .line 83
    invoke-direct {v4, v0, v5}, Lfh/a;-><init>(Ldi/a;I)V

    .line 84
    .line 85
    .line 86
    invoke-virtual {v9, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 87
    .line 88
    .line 89
    :cond_5
    check-cast v4, Lay0/k;

    .line 90
    .line 91
    sget-object v5, Lw3/q1;->a:Ll2/u2;

    .line 92
    .line 93
    invoke-virtual {v9, v5}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 94
    .line 95
    .line 96
    move-result-object v5

    .line 97
    check-cast v5, Ljava/lang/Boolean;

    .line 98
    .line 99
    invoke-virtual {v5}, Ljava/lang/Boolean;->booleanValue()Z

    .line 100
    .line 101
    .line 102
    move-result v5

    .line 103
    if-eqz v5, :cond_6

    .line 104
    .line 105
    const v5, -0x105bcaaa

    .line 106
    .line 107
    .line 108
    invoke-virtual {v9, v5}, Ll2/t;->Y(I)V

    .line 109
    .line 110
    .line 111
    invoke-virtual {v9, v10}, Ll2/t;->q(Z)V

    .line 112
    .line 113
    .line 114
    const/4 v5, 0x0

    .line 115
    goto :goto_4

    .line 116
    :cond_6
    const v5, 0x31054eee

    .line 117
    .line 118
    .line 119
    invoke-virtual {v9, v5}, Ll2/t;->Y(I)V

    .line 120
    .line 121
    .line 122
    sget-object v5, Lzb/x;->a:Ll2/u2;

    .line 123
    .line 124
    invoke-virtual {v9, v5}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 125
    .line 126
    .line 127
    move-result-object v5

    .line 128
    check-cast v5, Lhi/a;

    .line 129
    .line 130
    invoke-virtual {v9, v10}, Ll2/t;->q(Z)V

    .line 131
    .line 132
    .line 133
    :goto_4
    new-instance v7, Lnd/e;

    .line 134
    .line 135
    const/4 v6, 0x6

    .line 136
    invoke-direct {v7, v5, v4, v6}, Lnd/e;-><init>(Lhi/a;Lay0/k;I)V

    .line 137
    .line 138
    .line 139
    invoke-static {v9}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 140
    .line 141
    .line 142
    move-result-object v5

    .line 143
    if-eqz v5, :cond_c

    .line 144
    .line 145
    instance-of v4, v5, Landroidx/lifecycle/k;

    .line 146
    .line 147
    if-eqz v4, :cond_7

    .line 148
    .line 149
    move-object v4, v5

    .line 150
    check-cast v4, Landroidx/lifecycle/k;

    .line 151
    .line 152
    invoke-interface {v4}, Landroidx/lifecycle/k;->getDefaultViewModelCreationExtras()Lp7/c;

    .line 153
    .line 154
    .line 155
    move-result-object v4

    .line 156
    :goto_5
    move-object v8, v4

    .line 157
    goto :goto_6

    .line 158
    :cond_7
    sget-object v4, Lp7/a;->b:Lp7/a;

    .line 159
    .line 160
    goto :goto_5

    .line 161
    :goto_6
    const-class v4, Lfh/g;

    .line 162
    .line 163
    sget-object v6, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 164
    .line 165
    invoke-virtual {v6, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 166
    .line 167
    .line 168
    move-result-object v4

    .line 169
    const/4 v6, 0x0

    .line 170
    invoke-static/range {v4 .. v9}, Ljp/se;->b(Lhy0/d;Landroidx/lifecycle/i1;Ljava/lang/String;Landroidx/lifecycle/e1;Lp7/c;Ll2/o;)Landroidx/lifecycle/b1;

    .line 171
    .line 172
    .line 173
    move-result-object v4

    .line 174
    move-object v14, v4

    .line 175
    check-cast v14, Lfh/g;

    .line 176
    .line 177
    iget-object v4, v14, Lfh/g;->g:Lyy0/l1;

    .line 178
    .line 179
    invoke-static {v4, v9}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 180
    .line 181
    .line 182
    move-result-object v4

    .line 183
    invoke-interface {v4}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 184
    .line 185
    .line 186
    move-result-object v5

    .line 187
    check-cast v5, Lfh/f;

    .line 188
    .line 189
    invoke-virtual {v9, v14}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 190
    .line 191
    .line 192
    move-result v6

    .line 193
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 194
    .line 195
    .line 196
    move-result-object v7

    .line 197
    if-nez v6, :cond_8

    .line 198
    .line 199
    if-ne v7, v11, :cond_9

    .line 200
    .line 201
    :cond_8
    new-instance v7, Lmc/e;

    .line 202
    .line 203
    const/16 v6, 0x11

    .line 204
    .line 205
    invoke-direct {v7, v14, v6}, Lmc/e;-><init>(Ljava/lang/Object;I)V

    .line 206
    .line 207
    .line 208
    invoke-virtual {v9, v7}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 209
    .line 210
    .line 211
    :cond_9
    check-cast v7, Lay0/a;

    .line 212
    .line 213
    and-int/lit8 v3, v3, 0x70

    .line 214
    .line 215
    invoke-static {v5, v1, v7, v9, v3}, Ljp/ub;->a(Lfh/f;Lay0/a;Lay0/a;Ll2/o;I)V

    .line 216
    .line 217
    .line 218
    invoke-static {v9}, Leh/a;->b(Ll2/o;)Leh/n;

    .line 219
    .line 220
    .line 221
    move-result-object v3

    .line 222
    invoke-interface {v4}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 223
    .line 224
    .line 225
    move-result-object v4

    .line 226
    check-cast v4, Lfh/f;

    .line 227
    .line 228
    invoke-virtual {v9, v14}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 229
    .line 230
    .line 231
    move-result v5

    .line 232
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 233
    .line 234
    .line 235
    move-result-object v6

    .line 236
    if-nez v5, :cond_a

    .line 237
    .line 238
    if-ne v6, v11, :cond_b

    .line 239
    .line 240
    :cond_a
    new-instance v12, Lo90/f;

    .line 241
    .line 242
    const/16 v18, 0x0

    .line 243
    .line 244
    const/16 v19, 0x5

    .line 245
    .line 246
    const/4 v13, 0x1

    .line 247
    const-class v15, Lfh/g;

    .line 248
    .line 249
    const-string v16, "onUiEvent"

    .line 250
    .line 251
    const-string v17, "onUiEvent(Lcariad/charging/multicharge/kitten/wallboxes/presentation/authorization/WallboxChangeAuthModeUiEvent;)V"

    .line 252
    .line 253
    invoke-direct/range {v12 .. v19}, Lo90/f;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 254
    .line 255
    .line 256
    invoke-virtual {v9, v12}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 257
    .line 258
    .line 259
    move-object v6, v12

    .line 260
    :cond_b
    check-cast v6, Lhy0/g;

    .line 261
    .line 262
    check-cast v6, Lay0/k;

    .line 263
    .line 264
    invoke-interface {v3, v4, v6, v9, v10}, Leh/n;->v(Lfh/f;Lay0/k;Ll2/o;I)V

    .line 265
    .line 266
    .line 267
    goto :goto_7

    .line 268
    :cond_c
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 269
    .line 270
    const-string v1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 271
    .line 272
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 273
    .line 274
    .line 275
    throw v0

    .line 276
    :cond_d
    invoke-virtual {v9}, Ll2/t;->R()V

    .line 277
    .line 278
    .line 279
    :goto_7
    invoke-virtual {v9}, Ll2/t;->s()Ll2/u1;

    .line 280
    .line 281
    .line 282
    move-result-object v3

    .line 283
    if-eqz v3, :cond_e

    .line 284
    .line 285
    new-instance v4, Lo50/b;

    .line 286
    .line 287
    const/4 v5, 0x4

    .line 288
    invoke-direct {v4, v0, v1, v2, v5}, Lo50/b;-><init>(Ljava/lang/Object;Lay0/a;II)V

    .line 289
    .line 290
    .line 291
    iput-object v4, v3, Ll2/u1;->d:Lay0/n;

    .line 292
    .line 293
    :cond_e
    return-void
.end method
