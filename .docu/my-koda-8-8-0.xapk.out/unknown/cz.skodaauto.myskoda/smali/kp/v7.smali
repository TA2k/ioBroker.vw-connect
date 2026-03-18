.class public abstract Lkp/v7;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lse/f;Lay0/k;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Ll2/o;I)V
    .locals 16

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v9, p2

    .line 4
    .line 5
    move-object/from16 v10, p3

    .line 6
    .line 7
    move-object/from16 v11, p4

    .line 8
    .line 9
    move/from16 v12, p7

    .line 10
    .line 11
    move-object/from16 v13, p6

    .line 12
    .line 13
    check-cast v13, Ll2/t;

    .line 14
    .line 15
    const v0, -0x4dfb0b7d

    .line 16
    .line 17
    .line 18
    invoke-virtual {v13, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 19
    .line 20
    .line 21
    and-int/lit8 v0, v12, 0x6

    .line 22
    .line 23
    const/4 v2, 0x4

    .line 24
    if-nez v0, :cond_1

    .line 25
    .line 26
    invoke-virtual {v13, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 27
    .line 28
    .line 29
    move-result v0

    .line 30
    if-eqz v0, :cond_0

    .line 31
    .line 32
    move v0, v2

    .line 33
    goto :goto_0

    .line 34
    :cond_0
    const/4 v0, 0x2

    .line 35
    :goto_0
    or-int/2addr v0, v12

    .line 36
    goto :goto_1

    .line 37
    :cond_1
    move v0, v12

    .line 38
    :goto_1
    and-int/lit8 v3, v12, 0x30

    .line 39
    .line 40
    const/16 v4, 0x20

    .line 41
    .line 42
    if-nez v3, :cond_3

    .line 43
    .line 44
    move-object/from16 v3, p1

    .line 45
    .line 46
    invoke-virtual {v13, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 47
    .line 48
    .line 49
    move-result v5

    .line 50
    if-eqz v5, :cond_2

    .line 51
    .line 52
    move v5, v4

    .line 53
    goto :goto_2

    .line 54
    :cond_2
    const/16 v5, 0x10

    .line 55
    .line 56
    :goto_2
    or-int/2addr v0, v5

    .line 57
    goto :goto_3

    .line 58
    :cond_3
    move-object/from16 v3, p1

    .line 59
    .line 60
    :goto_3
    and-int/lit16 v5, v12, 0x180

    .line 61
    .line 62
    if-nez v5, :cond_5

    .line 63
    .line 64
    invoke-virtual {v13, v9}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 65
    .line 66
    .line 67
    move-result v5

    .line 68
    if-eqz v5, :cond_4

    .line 69
    .line 70
    const/16 v5, 0x100

    .line 71
    .line 72
    goto :goto_4

    .line 73
    :cond_4
    const/16 v5, 0x80

    .line 74
    .line 75
    :goto_4
    or-int/2addr v0, v5

    .line 76
    :cond_5
    and-int/lit16 v5, v12, 0xc00

    .line 77
    .line 78
    if-nez v5, :cond_7

    .line 79
    .line 80
    invoke-virtual {v13, v10}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 81
    .line 82
    .line 83
    move-result v5

    .line 84
    if-eqz v5, :cond_6

    .line 85
    .line 86
    const/16 v5, 0x800

    .line 87
    .line 88
    goto :goto_5

    .line 89
    :cond_6
    const/16 v5, 0x400

    .line 90
    .line 91
    :goto_5
    or-int/2addr v0, v5

    .line 92
    :cond_7
    and-int/lit16 v5, v12, 0x6000

    .line 93
    .line 94
    if-nez v5, :cond_9

    .line 95
    .line 96
    invoke-virtual {v13, v11}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 97
    .line 98
    .line 99
    move-result v5

    .line 100
    if-eqz v5, :cond_8

    .line 101
    .line 102
    const/16 v5, 0x4000

    .line 103
    .line 104
    goto :goto_6

    .line 105
    :cond_8
    const/16 v5, 0x2000

    .line 106
    .line 107
    :goto_6
    or-int/2addr v0, v5

    .line 108
    :cond_9
    const/high16 v5, 0x30000

    .line 109
    .line 110
    and-int/2addr v5, v12

    .line 111
    const/high16 v6, 0x20000

    .line 112
    .line 113
    if-nez v5, :cond_b

    .line 114
    .line 115
    move-object/from16 v5, p5

    .line 116
    .line 117
    invoke-virtual {v13, v5}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 118
    .line 119
    .line 120
    move-result v7

    .line 121
    if-eqz v7, :cond_a

    .line 122
    .line 123
    move v7, v6

    .line 124
    goto :goto_7

    .line 125
    :cond_a
    const/high16 v7, 0x10000

    .line 126
    .line 127
    :goto_7
    or-int/2addr v0, v7

    .line 128
    goto :goto_8

    .line 129
    :cond_b
    move-object/from16 v5, p5

    .line 130
    .line 131
    :goto_8
    const v7, 0x12493

    .line 132
    .line 133
    .line 134
    and-int/2addr v7, v0

    .line 135
    const v8, 0x12492

    .line 136
    .line 137
    .line 138
    const/4 v15, 0x1

    .line 139
    if-eq v7, v8, :cond_c

    .line 140
    .line 141
    move v7, v15

    .line 142
    goto :goto_9

    .line 143
    :cond_c
    const/4 v7, 0x0

    .line 144
    :goto_9
    and-int/lit8 v8, v0, 0x1

    .line 145
    .line 146
    invoke-virtual {v13, v8, v7}, Ll2/t;->O(IZ)Z

    .line 147
    .line 148
    .line 149
    move-result v7

    .line 150
    if-eqz v7, :cond_12

    .line 151
    .line 152
    invoke-static {v9, v13}, Ll2/b;->s(Ljava/lang/Object;Ll2/o;)Ll2/b1;

    .line 153
    .line 154
    .line 155
    move-result-object v7

    .line 156
    invoke-static {v10, v13}, Ll2/b;->s(Ljava/lang/Object;Ll2/o;)Ll2/b1;

    .line 157
    .line 158
    .line 159
    move-result-object v5

    .line 160
    invoke-static {v11, v13}, Ll2/b;->s(Ljava/lang/Object;Ll2/o;)Ll2/b1;

    .line 161
    .line 162
    .line 163
    move-result-object v8

    .line 164
    and-int/lit8 v14, v0, 0xe

    .line 165
    .line 166
    if-ne v14, v2, :cond_d

    .line 167
    .line 168
    move v2, v15

    .line 169
    goto :goto_a

    .line 170
    :cond_d
    const/4 v2, 0x0

    .line 171
    :goto_a
    invoke-virtual {v13, v7}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 172
    .line 173
    .line 174
    move-result v14

    .line 175
    or-int/2addr v2, v14

    .line 176
    const/high16 v14, 0x70000

    .line 177
    .line 178
    and-int/2addr v14, v0

    .line 179
    if-ne v14, v6, :cond_e

    .line 180
    .line 181
    move v6, v15

    .line 182
    goto :goto_b

    .line 183
    :cond_e
    const/4 v6, 0x0

    .line 184
    :goto_b
    or-int/2addr v2, v6

    .line 185
    and-int/lit8 v0, v0, 0x70

    .line 186
    .line 187
    if-ne v0, v4, :cond_f

    .line 188
    .line 189
    move v14, v15

    .line 190
    goto :goto_c

    .line 191
    :cond_f
    const/4 v14, 0x0

    .line 192
    :goto_c
    or-int v0, v2, v14

    .line 193
    .line 194
    invoke-virtual {v13, v5}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 195
    .line 196
    .line 197
    move-result v2

    .line 198
    or-int/2addr v0, v2

    .line 199
    invoke-virtual {v13, v8}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 200
    .line 201
    .line 202
    move-result v2

    .line 203
    or-int/2addr v0, v2

    .line 204
    invoke-virtual {v13}, Ll2/t;->L()Ljava/lang/Object;

    .line 205
    .line 206
    .line 207
    move-result-object v2

    .line 208
    if-nez v0, :cond_10

    .line 209
    .line 210
    sget-object v0, Ll2/n;->a:Ll2/x0;

    .line 211
    .line 212
    if-ne v2, v0, :cond_11

    .line 213
    .line 214
    :cond_10
    new-instance v0, Laa/l0;

    .line 215
    .line 216
    move-object v4, v7

    .line 217
    const/4 v7, 0x0

    .line 218
    move-object v6, v8

    .line 219
    const/4 v8, 0x1

    .line 220
    move-object/from16 v2, p5

    .line 221
    .line 222
    invoke-direct/range {v0 .. v8}, Laa/l0;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ll2/t2;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 223
    .line 224
    .line 225
    invoke-virtual {v13, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 226
    .line 227
    .line 228
    move-object v2, v0

    .line 229
    :cond_11
    check-cast v2, Lay0/n;

    .line 230
    .line 231
    invoke-static {v2, v1, v13}, Ll2/l0;->d(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 232
    .line 233
    .line 234
    goto :goto_d

    .line 235
    :cond_12
    invoke-virtual {v13}, Ll2/t;->R()V

    .line 236
    .line 237
    .line 238
    :goto_d
    invoke-virtual {v13}, Ll2/t;->s()Ll2/u1;

    .line 239
    .line 240
    .line 241
    move-result-object v8

    .line 242
    if-eqz v8, :cond_13

    .line 243
    .line 244
    new-instance v0, Ld80/d;

    .line 245
    .line 246
    move-object/from16 v2, p1

    .line 247
    .line 248
    move-object/from16 v6, p5

    .line 249
    .line 250
    move-object v3, v9

    .line 251
    move-object v4, v10

    .line 252
    move-object v5, v11

    .line 253
    move v7, v12

    .line 254
    invoke-direct/range {v0 .. v7}, Ld80/d;-><init>(Lse/f;Lay0/k;Lay0/a;Lay0/a;Lay0/a;Lay0/a;I)V

    .line 255
    .line 256
    .line 257
    iput-object v0, v8, Ll2/u1;->d:Lay0/n;

    .line 258
    .line 259
    :cond_13
    return-void
.end method

.method public static final b(Lay0/k;Lay0/a;Lay0/a;Lay0/a;Ll2/o;I)V
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
    move-object/from16 v4, p3

    .line 8
    .line 9
    const-string v0, "selectedRateType"

    .line 10
    .line 11
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    const-string v0, "fixRateSelect"

    .line 15
    .line 16
    invoke-static {v2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    const-string v0, "multipleFixedRateSelect"

    .line 20
    .line 21
    invoke-static {v3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    const-string v0, "dynamicRateSelect"

    .line 25
    .line 26
    invoke-static {v4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    move-object/from16 v10, p4

    .line 30
    .line 31
    check-cast v10, Ll2/t;

    .line 32
    .line 33
    const v0, -0x120d76e9

    .line 34
    .line 35
    .line 36
    invoke-virtual {v10, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 37
    .line 38
    .line 39
    invoke-virtual {v10, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    move-result v0

    .line 43
    if-eqz v0, :cond_0

    .line 44
    .line 45
    const/4 v0, 0x4

    .line 46
    goto :goto_0

    .line 47
    :cond_0
    const/4 v0, 0x2

    .line 48
    :goto_0
    or-int v0, p5, v0

    .line 49
    .line 50
    invoke-virtual {v10, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 51
    .line 52
    .line 53
    move-result v5

    .line 54
    if-eqz v5, :cond_1

    .line 55
    .line 56
    const/16 v5, 0x20

    .line 57
    .line 58
    goto :goto_1

    .line 59
    :cond_1
    const/16 v5, 0x10

    .line 60
    .line 61
    :goto_1
    or-int/2addr v0, v5

    .line 62
    invoke-virtual {v10, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 63
    .line 64
    .line 65
    move-result v5

    .line 66
    if-eqz v5, :cond_2

    .line 67
    .line 68
    const/16 v5, 0x100

    .line 69
    .line 70
    goto :goto_2

    .line 71
    :cond_2
    const/16 v5, 0x80

    .line 72
    .line 73
    :goto_2
    or-int/2addr v0, v5

    .line 74
    invoke-virtual {v10, v4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 75
    .line 76
    .line 77
    move-result v5

    .line 78
    if-eqz v5, :cond_3

    .line 79
    .line 80
    const/16 v5, 0x800

    .line 81
    .line 82
    goto :goto_3

    .line 83
    :cond_3
    const/16 v5, 0x400

    .line 84
    .line 85
    :goto_3
    or-int/2addr v0, v5

    .line 86
    and-int/lit16 v5, v0, 0x493

    .line 87
    .line 88
    const/16 v6, 0x492

    .line 89
    .line 90
    const/4 v11, 0x0

    .line 91
    if-eq v5, v6, :cond_4

    .line 92
    .line 93
    const/4 v5, 0x1

    .line 94
    goto :goto_4

    .line 95
    :cond_4
    move v5, v11

    .line 96
    :goto_4
    and-int/lit8 v6, v0, 0x1

    .line 97
    .line 98
    invoke-virtual {v10, v6, v5}, Ll2/t;->O(IZ)Z

    .line 99
    .line 100
    .line 101
    move-result v5

    .line 102
    if-eqz v5, :cond_d

    .line 103
    .line 104
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 105
    .line 106
    .line 107
    move-result-object v5

    .line 108
    sget-object v12, Ll2/n;->a:Ll2/x0;

    .line 109
    .line 110
    if-ne v5, v12, :cond_5

    .line 111
    .line 112
    new-instance v5, Lsb/a;

    .line 113
    .line 114
    const/4 v6, 0x6

    .line 115
    invoke-direct {v5, v6}, Lsb/a;-><init>(I)V

    .line 116
    .line 117
    .line 118
    invoke-virtual {v10, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 119
    .line 120
    .line 121
    :cond_5
    check-cast v5, Lay0/k;

    .line 122
    .line 123
    sget-object v6, Lw3/q1;->a:Ll2/u2;

    .line 124
    .line 125
    invoke-virtual {v10, v6}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 126
    .line 127
    .line 128
    move-result-object v6

    .line 129
    check-cast v6, Ljava/lang/Boolean;

    .line 130
    .line 131
    invoke-virtual {v6}, Ljava/lang/Boolean;->booleanValue()Z

    .line 132
    .line 133
    .line 134
    move-result v6

    .line 135
    if-eqz v6, :cond_6

    .line 136
    .line 137
    const v6, -0x105bcaaa

    .line 138
    .line 139
    .line 140
    invoke-virtual {v10, v6}, Ll2/t;->Y(I)V

    .line 141
    .line 142
    .line 143
    invoke-virtual {v10, v11}, Ll2/t;->q(Z)V

    .line 144
    .line 145
    .line 146
    const/4 v6, 0x0

    .line 147
    goto :goto_5

    .line 148
    :cond_6
    const v6, 0x31054eee

    .line 149
    .line 150
    .line 151
    invoke-virtual {v10, v6}, Ll2/t;->Y(I)V

    .line 152
    .line 153
    .line 154
    sget-object v6, Lzb/x;->a:Ll2/u2;

    .line 155
    .line 156
    invoke-virtual {v10, v6}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 157
    .line 158
    .line 159
    move-result-object v6

    .line 160
    check-cast v6, Lhi/a;

    .line 161
    .line 162
    invoke-virtual {v10, v11}, Ll2/t;->q(Z)V

    .line 163
    .line 164
    .line 165
    :goto_5
    new-instance v8, Lnd/e;

    .line 166
    .line 167
    const/16 v7, 0x12

    .line 168
    .line 169
    invoke-direct {v8, v6, v5, v7}, Lnd/e;-><init>(Lhi/a;Lay0/k;I)V

    .line 170
    .line 171
    .line 172
    invoke-static {v10}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 173
    .line 174
    .line 175
    move-result-object v6

    .line 176
    if-eqz v6, :cond_c

    .line 177
    .line 178
    instance-of v5, v6, Landroidx/lifecycle/k;

    .line 179
    .line 180
    if-eqz v5, :cond_7

    .line 181
    .line 182
    move-object v5, v6

    .line 183
    check-cast v5, Landroidx/lifecycle/k;

    .line 184
    .line 185
    invoke-interface {v5}, Landroidx/lifecycle/k;->getDefaultViewModelCreationExtras()Lp7/c;

    .line 186
    .line 187
    .line 188
    move-result-object v5

    .line 189
    :goto_6
    move-object v9, v5

    .line 190
    goto :goto_7

    .line 191
    :cond_7
    sget-object v5, Lp7/a;->b:Lp7/a;

    .line 192
    .line 193
    goto :goto_6

    .line 194
    :goto_7
    const-class v5, Lse/g;

    .line 195
    .line 196
    sget-object v7, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 197
    .line 198
    invoke-virtual {v7, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 199
    .line 200
    .line 201
    move-result-object v5

    .line 202
    const/4 v7, 0x0

    .line 203
    invoke-static/range {v5 .. v10}, Ljp/se;->b(Lhy0/d;Landroidx/lifecycle/i1;Ljava/lang/String;Landroidx/lifecycle/e1;Lp7/c;Ll2/o;)Landroidx/lifecycle/b1;

    .line 204
    .line 205
    .line 206
    move-result-object v5

    .line 207
    move-object v15, v5

    .line 208
    check-cast v15, Lse/g;

    .line 209
    .line 210
    iget-object v5, v15, Lse/g;->e:Lyy0/l1;

    .line 211
    .line 212
    invoke-static {v5, v10}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 213
    .line 214
    .line 215
    move-result-object v5

    .line 216
    invoke-interface {v5}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 217
    .line 218
    .line 219
    move-result-object v5

    .line 220
    check-cast v5, Lse/f;

    .line 221
    .line 222
    invoke-virtual {v10, v15}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 223
    .line 224
    .line 225
    move-result v6

    .line 226
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 227
    .line 228
    .line 229
    move-result-object v7

    .line 230
    if-nez v6, :cond_8

    .line 231
    .line 232
    if-ne v7, v12, :cond_9

    .line 233
    .line 234
    :cond_8
    new-instance v7, Lr1/b;

    .line 235
    .line 236
    const/16 v6, 0xc

    .line 237
    .line 238
    invoke-direct {v7, v15, v6}, Lr1/b;-><init>(Ljava/lang/Object;I)V

    .line 239
    .line 240
    .line 241
    invoke-virtual {v10, v7}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 242
    .line 243
    .line 244
    :cond_9
    check-cast v7, Lay0/a;

    .line 245
    .line 246
    shl-int/lit8 v0, v0, 0x3

    .line 247
    .line 248
    const v6, 0xfff0

    .line 249
    .line 250
    .line 251
    and-int/2addr v0, v6

    .line 252
    move-object v6, v7

    .line 253
    move v7, v0

    .line 254
    move-object v0, v5

    .line 255
    move-object v5, v6

    .line 256
    move-object v6, v10

    .line 257
    invoke-static/range {v0 .. v7}, Lkp/v7;->a(Lse/f;Lay0/k;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Ll2/o;I)V

    .line 258
    .line 259
    .line 260
    invoke-static {v10}, Llp/nf;->a(Ll2/o;)Lle/c;

    .line 261
    .line 262
    .line 263
    move-result-object v0

    .line 264
    invoke-virtual {v10, v15}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 265
    .line 266
    .line 267
    move-result v1

    .line 268
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 269
    .line 270
    .line 271
    move-result-object v2

    .line 272
    if-nez v1, :cond_a

    .line 273
    .line 274
    if-ne v2, v12, :cond_b

    .line 275
    .line 276
    :cond_a
    new-instance v13, Ls60/h;

    .line 277
    .line 278
    const/16 v19, 0x0

    .line 279
    .line 280
    const/16 v20, 0xf

    .line 281
    .line 282
    const/4 v14, 0x1

    .line 283
    const-class v16, Lse/g;

    .line 284
    .line 285
    const-string v17, "onUiEvent"

    .line 286
    .line 287
    const-string v18, "onUiEvent(Lcariad/charging/multicharge/kitten/kola/presentation/wizard/common/ratetypeselection/KolaWizardRateTypeSelectionUiEvent;)V"

    .line 288
    .line 289
    invoke-direct/range {v13 .. v20}, Ls60/h;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 290
    .line 291
    .line 292
    invoke-virtual {v10, v13}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 293
    .line 294
    .line 295
    move-object v2, v13

    .line 296
    :cond_b
    check-cast v2, Lhy0/g;

    .line 297
    .line 298
    check-cast v2, Lay0/k;

    .line 299
    .line 300
    invoke-interface {v0, v2, v10, v11}, Lle/c;->K(Lay0/k;Ll2/o;I)V

    .line 301
    .line 302
    .line 303
    goto :goto_8

    .line 304
    :cond_c
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 305
    .line 306
    const-string v1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 307
    .line 308
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 309
    .line 310
    .line 311
    throw v0

    .line 312
    :cond_d
    invoke-virtual {v10}, Ll2/t;->R()V

    .line 313
    .line 314
    .line 315
    :goto_8
    invoke-virtual {v10}, Ll2/t;->s()Ll2/u1;

    .line 316
    .line 317
    .line 318
    move-result-object v7

    .line 319
    if-eqz v7, :cond_e

    .line 320
    .line 321
    new-instance v0, Lo50/p;

    .line 322
    .line 323
    const/16 v6, 0x9

    .line 324
    .line 325
    move-object/from16 v1, p0

    .line 326
    .line 327
    move-object/from16 v2, p1

    .line 328
    .line 329
    move-object/from16 v3, p2

    .line 330
    .line 331
    move-object/from16 v4, p3

    .line 332
    .line 333
    move/from16 v5, p5

    .line 334
    .line 335
    invoke-direct/range {v0 .. v6}, Lo50/p;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Llx0/e;II)V

    .line 336
    .line 337
    .line 338
    iput-object v0, v7, Ll2/u1;->d:Lay0/n;

    .line 339
    .line 340
    :cond_e
    return-void
.end method

.method public static c(Lvy0/i0;)Ly4/k;
    .locals 2

    .line 1
    new-instance v0, La8/t;

    .line 2
    .line 3
    const/16 v1, 0x1a

    .line 4
    .line 5
    invoke-direct {v0, p0, v1}, La8/t;-><init>(Ljava/lang/Object;I)V

    .line 6
    .line 7
    .line 8
    invoke-static {v0}, Llp/uf;->b(Ly4/i;)Ly4/k;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    return-object p0
.end method
