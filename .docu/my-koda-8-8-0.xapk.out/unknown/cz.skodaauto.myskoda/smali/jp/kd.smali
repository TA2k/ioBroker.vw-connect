.class public abstract Ljp/kd;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(ILay0/a;Lay0/k;Ll2/o;)V
    .locals 20

    .line 1
    move/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v2, p2

    .line 6
    .line 7
    const-string v3, "resetSeason"

    .line 8
    .line 9
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    const-string v3, "goToNext"

    .line 13
    .line 14
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    move-object/from16 v9, p3

    .line 18
    .line 19
    check-cast v9, Ll2/t;

    .line 20
    .line 21
    const v3, -0x769414da

    .line 22
    .line 23
    .line 24
    invoke-virtual {v9, v3}, Ll2/t;->a0(I)Ll2/t;

    .line 25
    .line 26
    .line 27
    invoke-virtual {v9, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result v3

    .line 31
    const/4 v4, 0x4

    .line 32
    if-eqz v3, :cond_0

    .line 33
    .line 34
    move v3, v4

    .line 35
    goto :goto_0

    .line 36
    :cond_0
    const/4 v3, 0x2

    .line 37
    :goto_0
    or-int/2addr v3, v0

    .line 38
    invoke-virtual {v9, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 39
    .line 40
    .line 41
    move-result v5

    .line 42
    const/16 v6, 0x20

    .line 43
    .line 44
    if-eqz v5, :cond_1

    .line 45
    .line 46
    move v5, v6

    .line 47
    goto :goto_1

    .line 48
    :cond_1
    const/16 v5, 0x10

    .line 49
    .line 50
    :goto_1
    or-int/2addr v3, v5

    .line 51
    and-int/lit8 v5, v3, 0x13

    .line 52
    .line 53
    const/16 v7, 0x12

    .line 54
    .line 55
    const/4 v8, 0x1

    .line 56
    const/4 v10, 0x0

    .line 57
    if-eq v5, v7, :cond_2

    .line 58
    .line 59
    move v5, v8

    .line 60
    goto :goto_2

    .line 61
    :cond_2
    move v5, v10

    .line 62
    :goto_2
    and-int/lit8 v7, v3, 0x1

    .line 63
    .line 64
    invoke-virtual {v9, v7, v5}, Ll2/t;->O(IZ)Z

    .line 65
    .line 66
    .line 67
    move-result v5

    .line 68
    if-eqz v5, :cond_c

    .line 69
    .line 70
    and-int/lit8 v5, v3, 0xe

    .line 71
    .line 72
    if-ne v5, v4, :cond_3

    .line 73
    .line 74
    move v4, v8

    .line 75
    goto :goto_3

    .line 76
    :cond_3
    move v4, v10

    .line 77
    :goto_3
    and-int/lit8 v3, v3, 0x70

    .line 78
    .line 79
    if-ne v3, v6, :cond_4

    .line 80
    .line 81
    goto :goto_4

    .line 82
    :cond_4
    move v8, v10

    .line 83
    :goto_4
    or-int v3, v4, v8

    .line 84
    .line 85
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 86
    .line 87
    .line 88
    move-result-object v4

    .line 89
    sget-object v11, Ll2/n;->a:Ll2/x0;

    .line 90
    .line 91
    if-nez v3, :cond_5

    .line 92
    .line 93
    if-ne v4, v11, :cond_6

    .line 94
    .line 95
    :cond_5
    new-instance v4, Lcf/a;

    .line 96
    .line 97
    invoke-direct {v4, v1, v2}, Lcf/a;-><init>(Lay0/a;Lay0/k;)V

    .line 98
    .line 99
    .line 100
    invoke-virtual {v9, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 101
    .line 102
    .line 103
    :cond_6
    check-cast v4, Lay0/k;

    .line 104
    .line 105
    sget-object v3, Lw3/q1;->a:Ll2/u2;

    .line 106
    .line 107
    invoke-virtual {v9, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 108
    .line 109
    .line 110
    move-result-object v3

    .line 111
    check-cast v3, Ljava/lang/Boolean;

    .line 112
    .line 113
    invoke-virtual {v3}, Ljava/lang/Boolean;->booleanValue()Z

    .line 114
    .line 115
    .line 116
    move-result v3

    .line 117
    if-eqz v3, :cond_7

    .line 118
    .line 119
    const v3, -0x105bcaaa

    .line 120
    .line 121
    .line 122
    invoke-virtual {v9, v3}, Ll2/t;->Y(I)V

    .line 123
    .line 124
    .line 125
    invoke-virtual {v9, v10}, Ll2/t;->q(Z)V

    .line 126
    .line 127
    .line 128
    const/4 v3, 0x0

    .line 129
    goto :goto_5

    .line 130
    :cond_7
    const v3, 0x31054eee

    .line 131
    .line 132
    .line 133
    invoke-virtual {v9, v3}, Ll2/t;->Y(I)V

    .line 134
    .line 135
    .line 136
    sget-object v3, Lzb/x;->a:Ll2/u2;

    .line 137
    .line 138
    invoke-virtual {v9, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 139
    .line 140
    .line 141
    move-result-object v3

    .line 142
    check-cast v3, Lhi/a;

    .line 143
    .line 144
    invoke-virtual {v9, v10}, Ll2/t;->q(Z)V

    .line 145
    .line 146
    .line 147
    :goto_5
    new-instance v7, Laf/a;

    .line 148
    .line 149
    const/4 v5, 0x5

    .line 150
    invoke-direct {v7, v3, v4, v5}, Laf/a;-><init>(Lhi/a;Lay0/k;I)V

    .line 151
    .line 152
    .line 153
    invoke-static {v9}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 154
    .line 155
    .line 156
    move-result-object v5

    .line 157
    if-eqz v5, :cond_b

    .line 158
    .line 159
    instance-of v3, v5, Landroidx/lifecycle/k;

    .line 160
    .line 161
    if-eqz v3, :cond_8

    .line 162
    .line 163
    move-object v3, v5

    .line 164
    check-cast v3, Landroidx/lifecycle/k;

    .line 165
    .line 166
    invoke-interface {v3}, Landroidx/lifecycle/k;->getDefaultViewModelCreationExtras()Lp7/c;

    .line 167
    .line 168
    .line 169
    move-result-object v3

    .line 170
    :goto_6
    move-object v8, v3

    .line 171
    goto :goto_7

    .line 172
    :cond_8
    sget-object v3, Lp7/a;->b:Lp7/a;

    .line 173
    .line 174
    goto :goto_6

    .line 175
    :goto_7
    const-class v3, Lcf/e;

    .line 176
    .line 177
    sget-object v4, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 178
    .line 179
    invoke-virtual {v4, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 180
    .line 181
    .line 182
    move-result-object v4

    .line 183
    const/4 v6, 0x0

    .line 184
    invoke-static/range {v4 .. v9}, Ljp/se;->b(Lhy0/d;Landroidx/lifecycle/i1;Ljava/lang/String;Landroidx/lifecycle/e1;Lp7/c;Ll2/o;)Landroidx/lifecycle/b1;

    .line 185
    .line 186
    .line 187
    move-result-object v3

    .line 188
    move-object v14, v3

    .line 189
    check-cast v14, Lcf/e;

    .line 190
    .line 191
    iget-object v3, v14, Lcf/e;->g:Lyy0/l1;

    .line 192
    .line 193
    invoke-static {v3, v9}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 194
    .line 195
    .line 196
    move-result-object v3

    .line 197
    invoke-static {v9}, Llp/nf;->a(Ll2/o;)Lle/c;

    .line 198
    .line 199
    .line 200
    move-result-object v4

    .line 201
    invoke-interface {v3}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 202
    .line 203
    .line 204
    move-result-object v3

    .line 205
    check-cast v3, Lcf/d;

    .line 206
    .line 207
    invoke-virtual {v9, v14}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 208
    .line 209
    .line 210
    move-result v5

    .line 211
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 212
    .line 213
    .line 214
    move-result-object v6

    .line 215
    if-nez v5, :cond_9

    .line 216
    .line 217
    if-ne v6, v11, :cond_a

    .line 218
    .line 219
    :cond_9
    new-instance v12, Laf/b;

    .line 220
    .line 221
    const/16 v18, 0x0

    .line 222
    .line 223
    const/16 v19, 0x11

    .line 224
    .line 225
    const/4 v13, 0x1

    .line 226
    const-class v15, Lcf/e;

    .line 227
    .line 228
    const-string v16, "onUiEvent"

    .line 229
    .line 230
    const-string v17, "onUiEvent(Lcariad/charging/multicharge/kitten/kola/presentation/wizard/multiplefixedrate/monthselection/MonthsSelectionUiEvent;)V"

    .line 231
    .line 232
    invoke-direct/range {v12 .. v19}, Laf/b;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 233
    .line 234
    .line 235
    invoke-virtual {v9, v12}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 236
    .line 237
    .line 238
    move-object v6, v12

    .line 239
    :cond_a
    check-cast v6, Lhy0/g;

    .line 240
    .line 241
    check-cast v6, Lay0/k;

    .line 242
    .line 243
    invoke-interface {v4, v3, v6, v9, v10}, Lle/c;->x(Lcf/d;Lay0/k;Ll2/o;I)V

    .line 244
    .line 245
    .line 246
    goto :goto_8

    .line 247
    :cond_b
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 248
    .line 249
    const-string v1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 250
    .line 251
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 252
    .line 253
    .line 254
    throw v0

    .line 255
    :cond_c
    invoke-virtual {v9}, Ll2/t;->R()V

    .line 256
    .line 257
    .line 258
    :goto_8
    invoke-virtual {v9}, Ll2/t;->s()Ll2/u1;

    .line 259
    .line 260
    .line 261
    move-result-object v3

    .line 262
    if-eqz v3, :cond_d

    .line 263
    .line 264
    new-instance v4, Lcf/b;

    .line 265
    .line 266
    const/4 v5, 0x0

    .line 267
    invoke-direct {v4, v1, v2, v0, v5}, Lcf/b;-><init>(Lay0/a;Lay0/k;II)V

    .line 268
    .line 269
    .line 270
    iput-object v4, v3, Ll2/u1;->d:Lay0/n;

    .line 271
    .line 272
    :cond_d
    return-void
.end method

.method public static final b(Lay0/k;Lay0/k;Ll2/o;I)V
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
    const-string v3, "downloadFileUseCase"

    .line 8
    .line 9
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    const-string v3, "onResult"

    .line 13
    .line 14
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    move-object/from16 v9, p2

    .line 18
    .line 19
    check-cast v9, Ll2/t;

    .line 20
    .line 21
    const v3, 0x2eb2f210

    .line 22
    .line 23
    .line 24
    invoke-virtual {v9, v3}, Ll2/t;->a0(I)Ll2/t;

    .line 25
    .line 26
    .line 27
    invoke-virtual {v9, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result v3

    .line 31
    if-eqz v3, :cond_0

    .line 32
    .line 33
    const/4 v3, 0x4

    .line 34
    goto :goto_0

    .line 35
    :cond_0
    const/4 v3, 0x2

    .line 36
    :goto_0
    or-int/2addr v3, v2

    .line 37
    invoke-virtual {v9, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 38
    .line 39
    .line 40
    move-result v4

    .line 41
    const/16 v5, 0x20

    .line 42
    .line 43
    if-eqz v4, :cond_1

    .line 44
    .line 45
    move v4, v5

    .line 46
    goto :goto_1

    .line 47
    :cond_1
    const/16 v4, 0x10

    .line 48
    .line 49
    :goto_1
    or-int/2addr v3, v4

    .line 50
    and-int/lit8 v4, v3, 0x13

    .line 51
    .line 52
    const/16 v6, 0x12

    .line 53
    .line 54
    const/4 v7, 0x1

    .line 55
    const/4 v10, 0x0

    .line 56
    if-eq v4, v6, :cond_2

    .line 57
    .line 58
    move v4, v7

    .line 59
    goto :goto_2

    .line 60
    :cond_2
    move v4, v10

    .line 61
    :goto_2
    and-int/lit8 v6, v3, 0x1

    .line 62
    .line 63
    invoke-virtual {v9, v6, v4}, Ll2/t;->O(IZ)Z

    .line 64
    .line 65
    .line 66
    move-result v4

    .line 67
    if-eqz v4, :cond_b

    .line 68
    .line 69
    invoke-virtual {v9, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 70
    .line 71
    .line 72
    move-result v4

    .line 73
    and-int/lit8 v3, v3, 0x70

    .line 74
    .line 75
    if-ne v3, v5, :cond_3

    .line 76
    .line 77
    goto :goto_3

    .line 78
    :cond_3
    move v7, v10

    .line 79
    :goto_3
    or-int v3, v4, v7

    .line 80
    .line 81
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object v4

    .line 85
    sget-object v11, Ll2/n;->a:Ll2/x0;

    .line 86
    .line 87
    if-nez v3, :cond_4

    .line 88
    .line 89
    if-ne v4, v11, :cond_5

    .line 90
    .line 91
    :cond_4
    new-instance v4, Lpc/a;

    .line 92
    .line 93
    const/4 v3, 0x0

    .line 94
    invoke-direct {v4, v0, v1, v3}, Lpc/a;-><init>(Lay0/k;Lay0/k;I)V

    .line 95
    .line 96
    .line 97
    invoke-virtual {v9, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 98
    .line 99
    .line 100
    :cond_5
    check-cast v4, Lay0/k;

    .line 101
    .line 102
    sget-object v3, Lw3/q1;->a:Ll2/u2;

    .line 103
    .line 104
    invoke-virtual {v9, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 105
    .line 106
    .line 107
    move-result-object v3

    .line 108
    check-cast v3, Ljava/lang/Boolean;

    .line 109
    .line 110
    invoke-virtual {v3}, Ljava/lang/Boolean;->booleanValue()Z

    .line 111
    .line 112
    .line 113
    move-result v3

    .line 114
    if-eqz v3, :cond_6

    .line 115
    .line 116
    const v3, -0x105bcaaa

    .line 117
    .line 118
    .line 119
    invoke-virtual {v9, v3}, Ll2/t;->Y(I)V

    .line 120
    .line 121
    .line 122
    invoke-virtual {v9, v10}, Ll2/t;->q(Z)V

    .line 123
    .line 124
    .line 125
    const/4 v3, 0x0

    .line 126
    goto :goto_4

    .line 127
    :cond_6
    const v3, 0x31054eee

    .line 128
    .line 129
    .line 130
    invoke-virtual {v9, v3}, Ll2/t;->Y(I)V

    .line 131
    .line 132
    .line 133
    sget-object v3, Lzb/x;->a:Ll2/u2;

    .line 134
    .line 135
    invoke-virtual {v9, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 136
    .line 137
    .line 138
    move-result-object v3

    .line 139
    check-cast v3, Lhi/a;

    .line 140
    .line 141
    invoke-virtual {v9, v10}, Ll2/t;->q(Z)V

    .line 142
    .line 143
    .line 144
    :goto_4
    new-instance v7, Lvh/i;

    .line 145
    .line 146
    const/16 v5, 0x9

    .line 147
    .line 148
    invoke-direct {v7, v5, v3, v4}, Lvh/i;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 149
    .line 150
    .line 151
    invoke-static {v9}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 152
    .line 153
    .line 154
    move-result-object v5

    .line 155
    if-eqz v5, :cond_a

    .line 156
    .line 157
    instance-of v3, v5, Landroidx/lifecycle/k;

    .line 158
    .line 159
    if-eqz v3, :cond_7

    .line 160
    .line 161
    move-object v3, v5

    .line 162
    check-cast v3, Landroidx/lifecycle/k;

    .line 163
    .line 164
    invoke-interface {v3}, Landroidx/lifecycle/k;->getDefaultViewModelCreationExtras()Lp7/c;

    .line 165
    .line 166
    .line 167
    move-result-object v3

    .line 168
    :goto_5
    move-object v8, v3

    .line 169
    goto :goto_6

    .line 170
    :cond_7
    sget-object v3, Lp7/a;->b:Lp7/a;

    .line 171
    .line 172
    goto :goto_5

    .line 173
    :goto_6
    const-class v3, Lpc/c;

    .line 174
    .line 175
    sget-object v4, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 176
    .line 177
    invoke-virtual {v4, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 178
    .line 179
    .line 180
    move-result-object v4

    .line 181
    const/4 v6, 0x0

    .line 182
    invoke-static/range {v4 .. v9}, Ljp/se;->b(Lhy0/d;Landroidx/lifecycle/i1;Ljava/lang/String;Landroidx/lifecycle/e1;Lp7/c;Ll2/o;)Landroidx/lifecycle/b1;

    .line 183
    .line 184
    .line 185
    move-result-object v3

    .line 186
    move-object v14, v3

    .line 187
    check-cast v14, Lpc/c;

    .line 188
    .line 189
    invoke-static {v9}, Lzb/b;->u(Ll2/o;)Lzb/j;

    .line 190
    .line 191
    .line 192
    move-result-object v3

    .line 193
    iget-object v4, v14, Lpc/c;->g:Lyy0/c2;

    .line 194
    .line 195
    invoke-static {v4, v9}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 196
    .line 197
    .line 198
    move-result-object v4

    .line 199
    invoke-interface {v4}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 200
    .line 201
    .line 202
    move-result-object v4

    .line 203
    check-cast v4, Llc/q;

    .line 204
    .line 205
    invoke-virtual {v9, v14}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 206
    .line 207
    .line 208
    move-result v5

    .line 209
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 210
    .line 211
    .line 212
    move-result-object v6

    .line 213
    if-nez v5, :cond_8

    .line 214
    .line 215
    if-ne v6, v11, :cond_9

    .line 216
    .line 217
    :cond_8
    new-instance v12, Loz/c;

    .line 218
    .line 219
    const/16 v18, 0x0

    .line 220
    .line 221
    const/16 v19, 0x1

    .line 222
    .line 223
    const/4 v13, 0x0

    .line 224
    const-class v15, Lpc/c;

    .line 225
    .line 226
    const-string v16, "retry"

    .line 227
    .line 228
    const-string v17, "retry()V"

    .line 229
    .line 230
    invoke-direct/range {v12 .. v19}, Loz/c;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 231
    .line 232
    .line 233
    invoke-virtual {v9, v12}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 234
    .line 235
    .line 236
    move-object v6, v12

    .line 237
    :cond_9
    check-cast v6, Lhy0/g;

    .line 238
    .line 239
    check-cast v6, Lay0/a;

    .line 240
    .line 241
    invoke-interface {v3, v4, v6, v9, v10}, Lzb/j;->E0(Llc/q;Lay0/a;Ll2/o;I)V

    .line 242
    .line 243
    .line 244
    goto :goto_7

    .line 245
    :cond_a
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 246
    .line 247
    const-string v1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 248
    .line 249
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 250
    .line 251
    .line 252
    throw v0

    .line 253
    :cond_b
    invoke-virtual {v9}, Ll2/t;->R()V

    .line 254
    .line 255
    .line 256
    :goto_7
    invoke-virtual {v9}, Ll2/t;->s()Ll2/u1;

    .line 257
    .line 258
    .line 259
    move-result-object v3

    .line 260
    if-eqz v3, :cond_c

    .line 261
    .line 262
    new-instance v4, Lpc/b;

    .line 263
    .line 264
    const/4 v5, 0x0

    .line 265
    invoke-direct {v4, v0, v1, v2, v5}, Lpc/b;-><init>(Lay0/k;Lay0/k;II)V

    .line 266
    .line 267
    .line 268
    iput-object v4, v3, Ll2/u1;->d:Lay0/n;

    .line 269
    .line 270
    :cond_c
    return-void
.end method
