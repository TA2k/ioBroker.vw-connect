.class public abstract Llp/ld;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lz9/y;Lay0/n;Ll2/o;I)V
    .locals 12

    .line 1
    const-string v0, "navController"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    check-cast p2, Ll2/t;

    .line 7
    .line 8
    const v0, -0x3ecbc8e1

    .line 9
    .line 10
    .line 11
    invoke-virtual {p2, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 12
    .line 13
    .line 14
    invoke-virtual {p2, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 15
    .line 16
    .line 17
    move-result v0

    .line 18
    if-eqz v0, :cond_0

    .line 19
    .line 20
    const/4 v0, 0x4

    .line 21
    goto :goto_0

    .line 22
    :cond_0
    const/4 v0, 0x2

    .line 23
    :goto_0
    or-int/2addr v0, p3

    .line 24
    and-int/lit8 v1, v0, 0x13

    .line 25
    .line 26
    const/16 v2, 0x12

    .line 27
    .line 28
    const/4 v3, 0x1

    .line 29
    const/4 v4, 0x0

    .line 30
    if-eq v1, v2, :cond_1

    .line 31
    .line 32
    move v1, v3

    .line 33
    goto :goto_1

    .line 34
    :cond_1
    move v1, v4

    .line 35
    :goto_1
    and-int/2addr v0, v3

    .line 36
    invoke-virtual {p2, v0, v1}, Ll2/t;->O(IZ)Z

    .line 37
    .line 38
    .line 39
    move-result v0

    .line 40
    if-eqz v0, :cond_7

    .line 41
    .line 42
    const v0, -0x6040e0aa

    .line 43
    .line 44
    .line 45
    invoke-virtual {p2, v0}, Ll2/t;->Y(I)V

    .line 46
    .line 47
    .line 48
    invoke-static {p2}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 49
    .line 50
    .line 51
    move-result-object v0

    .line 52
    if-eqz v0, :cond_6

    .line 53
    .line 54
    invoke-static {v0}, Ljp/ib;->a(Landroidx/lifecycle/i1;)Lp7/c;

    .line 55
    .line 56
    .line 57
    move-result-object v8

    .line 58
    invoke-static {p2}, Lw11/c;->b(Ll2/o;)Lk21/a;

    .line 59
    .line 60
    .line 61
    move-result-object v10

    .line 62
    const-class v1, Lvl0/b;

    .line 63
    .line 64
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 65
    .line 66
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 67
    .line 68
    .line 69
    move-result-object v5

    .line 70
    invoke-interface {v0}, Landroidx/lifecycle/i1;->getViewModelStore()Landroidx/lifecycle/h1;

    .line 71
    .line 72
    .line 73
    move-result-object v6

    .line 74
    const/4 v7, 0x0

    .line 75
    const/4 v9, 0x0

    .line 76
    const/4 v11, 0x0

    .line 77
    invoke-static/range {v5 .. v11}, Ljp/lb;->a(Lhy0/d;Landroidx/lifecycle/h1;Ljava/lang/String;Lp7/c;Lh21/b;Lk21/a;Lay0/a;)Landroidx/lifecycle/b1;

    .line 78
    .line 79
    .line 80
    move-result-object v0

    .line 81
    invoke-virtual {p2, v4}, Ll2/t;->q(Z)V

    .line 82
    .line 83
    .line 84
    check-cast v0, Lql0/j;

    .line 85
    .line 86
    invoke-static {v0, p2, v4, v3}, Lkp/x5;->b(Lql0/j;Ll2/o;II)V

    .line 87
    .line 88
    .line 89
    check-cast v0, Lvl0/b;

    .line 90
    .line 91
    iget-object v1, v0, Lql0/j;->g:Lyy0/l1;

    .line 92
    .line 93
    const/4 v2, 0x0

    .line 94
    invoke-static {v1, v2, p2, v3}, Ll2/b;->f(Lyy0/a2;Lwy0/c;Ll2/o;I)Ll2/b1;

    .line 95
    .line 96
    .line 97
    move-result-object v1

    .line 98
    invoke-interface {v1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 99
    .line 100
    .line 101
    move-result-object v2

    .line 102
    check-cast v2, Lvl0/a;

    .line 103
    .line 104
    iget-boolean v2, v2, Lvl0/a;->b:Z

    .line 105
    .line 106
    if-eqz v2, :cond_5

    .line 107
    .line 108
    const v2, 0x45031fdd

    .line 109
    .line 110
    .line 111
    invoke-virtual {p2, v2}, Ll2/t;->Y(I)V

    .line 112
    .line 113
    .line 114
    invoke-interface {v1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 115
    .line 116
    .line 117
    move-result-object v2

    .line 118
    check-cast v2, Lvl0/a;

    .line 119
    .line 120
    iget-object v2, v2, Lvl0/a;->a:Lul0/e;

    .line 121
    .line 122
    if-nez v2, :cond_2

    .line 123
    .line 124
    const v0, 0x5b60dbc4

    .line 125
    .line 126
    .line 127
    invoke-virtual {p2, v0}, Ll2/t;->Y(I)V

    .line 128
    .line 129
    .line 130
    :goto_2
    invoke-virtual {p2, v4}, Ll2/t;->q(Z)V

    .line 131
    .line 132
    .line 133
    goto :goto_3

    .line 134
    :cond_2
    const v3, 0x5b60dbc5

    .line 135
    .line 136
    .line 137
    invoke-virtual {p2, v3}, Ll2/t;->Y(I)V

    .line 138
    .line 139
    .line 140
    invoke-virtual {p2, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 141
    .line 142
    .line 143
    move-result v3

    .line 144
    invoke-virtual {p2, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 145
    .line 146
    .line 147
    move-result v5

    .line 148
    or-int/2addr v3, v5

    .line 149
    invoke-virtual {p2, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 150
    .line 151
    .line 152
    move-result v5

    .line 153
    or-int/2addr v3, v5

    .line 154
    invoke-virtual {p2}, Ll2/t;->L()Ljava/lang/Object;

    .line 155
    .line 156
    .line 157
    move-result-object v5

    .line 158
    if-nez v3, :cond_3

    .line 159
    .line 160
    sget-object v3, Ll2/n;->a:Ll2/x0;

    .line 161
    .line 162
    if-ne v5, v3, :cond_4

    .line 163
    .line 164
    :cond_3
    new-instance v5, Ltechnology/cariad/cat/genx/bluetooth/g;

    .line 165
    .line 166
    const/4 v3, 0x6

    .line 167
    invoke-direct {v5, v2, p0, v0, v3}, Ltechnology/cariad/cat/genx/bluetooth/g;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 168
    .line 169
    .line 170
    invoke-virtual {p2, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 171
    .line 172
    .line 173
    :cond_4
    check-cast v5, Lay0/a;

    .line 174
    .line 175
    invoke-static {v5, p2}, Ll2/l0;->g(Lay0/a;Ll2/o;)V

    .line 176
    .line 177
    .line 178
    goto :goto_2

    .line 179
    :goto_3
    invoke-virtual {p2, v4}, Ll2/t;->q(Z)V

    .line 180
    .line 181
    .line 182
    goto :goto_4

    .line 183
    :cond_5
    const v0, 0x5b4bba83

    .line 184
    .line 185
    .line 186
    invoke-virtual {p2, v0}, Ll2/t;->Y(I)V

    .line 187
    .line 188
    .line 189
    goto :goto_3

    .line 190
    :goto_4
    if-eqz p1, :cond_8

    .line 191
    .line 192
    invoke-interface {v1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 193
    .line 194
    .line 195
    move-result-object v0

    .line 196
    check-cast v0, Lvl0/a;

    .line 197
    .line 198
    iget-object v0, v0, Lvl0/a;->a:Lul0/e;

    .line 199
    .line 200
    invoke-interface {v1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 201
    .line 202
    .line 203
    move-result-object v1

    .line 204
    check-cast v1, Lvl0/a;

    .line 205
    .line 206
    iget-boolean v1, v1, Lvl0/a;->b:Z

    .line 207
    .line 208
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 209
    .line 210
    .line 211
    move-result-object v1

    .line 212
    invoke-interface {p1, v0, v1}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 213
    .line 214
    .line 215
    goto :goto_5

    .line 216
    :cond_6
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 217
    .line 218
    const-string p1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 219
    .line 220
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 221
    .line 222
    .line 223
    throw p0

    .line 224
    :cond_7
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 225
    .line 226
    .line 227
    :cond_8
    :goto_5
    invoke-virtual {p2}, Ll2/t;->s()Ll2/u1;

    .line 228
    .line 229
    .line 230
    move-result-object p2

    .line 231
    if-eqz p2, :cond_9

    .line 232
    .line 233
    new-instance v0, Luu/q0;

    .line 234
    .line 235
    const/16 v1, 0x10

    .line 236
    .line 237
    invoke-direct {v0, p3, v1, p0, p1}, Luu/q0;-><init>(IILjava/lang/Object;Ljava/lang/Object;)V

    .line 238
    .line 239
    .line 240
    iput-object v0, p2, Ll2/u1;->d:Lay0/n;

    .line 241
    .line 242
    :cond_9
    return-void
.end method

.method public static final b(Ljava/lang/String;Ll2/o;I)V
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move/from16 v1, p2

    .line 4
    .line 5
    move-object/from16 v7, p1

    .line 6
    .line 7
    check-cast v7, Ll2/t;

    .line 8
    .line 9
    const v2, -0x67862896

    .line 10
    .line 11
    .line 12
    invoke-virtual {v7, v2}, Ll2/t;->a0(I)Ll2/t;

    .line 13
    .line 14
    .line 15
    invoke-virtual {v7, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    move-result v2

    .line 19
    const/4 v3, 0x2

    .line 20
    const/4 v4, 0x4

    .line 21
    if-eqz v2, :cond_0

    .line 22
    .line 23
    move v2, v4

    .line 24
    goto :goto_0

    .line 25
    :cond_0
    move v2, v3

    .line 26
    :goto_0
    or-int/2addr v2, v1

    .line 27
    and-int/lit8 v5, v2, 0x3

    .line 28
    .line 29
    const/4 v6, 0x1

    .line 30
    const/4 v8, 0x0

    .line 31
    if-eq v5, v3, :cond_1

    .line 32
    .line 33
    move v3, v6

    .line 34
    goto :goto_1

    .line 35
    :cond_1
    move v3, v8

    .line 36
    :goto_1
    and-int/lit8 v5, v2, 0x1

    .line 37
    .line 38
    invoke-virtual {v7, v5, v3}, Ll2/t;->O(IZ)Z

    .line 39
    .line 40
    .line 41
    move-result v3

    .line 42
    if-eqz v3, :cond_a

    .line 43
    .line 44
    and-int/lit8 v2, v2, 0xe

    .line 45
    .line 46
    if-ne v2, v4, :cond_2

    .line 47
    .line 48
    goto :goto_2

    .line 49
    :cond_2
    move v6, v8

    .line 50
    :goto_2
    invoke-virtual {v7}, Ll2/t;->L()Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    move-result-object v2

    .line 54
    sget-object v9, Ll2/n;->a:Ll2/x0;

    .line 55
    .line 56
    if-nez v6, :cond_3

    .line 57
    .line 58
    if-ne v2, v9, :cond_4

    .line 59
    .line 60
    :cond_3
    new-instance v2, Lif0/d;

    .line 61
    .line 62
    const/4 v3, 0x6

    .line 63
    invoke-direct {v2, v0, v3}, Lif0/d;-><init>(Ljava/lang/String;I)V

    .line 64
    .line 65
    .line 66
    invoke-virtual {v7, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 67
    .line 68
    .line 69
    :cond_4
    check-cast v2, Lay0/k;

    .line 70
    .line 71
    sget-object v3, Lw3/q1;->a:Ll2/u2;

    .line 72
    .line 73
    invoke-virtual {v7, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 74
    .line 75
    .line 76
    move-result-object v3

    .line 77
    check-cast v3, Ljava/lang/Boolean;

    .line 78
    .line 79
    invoke-virtual {v3}, Ljava/lang/Boolean;->booleanValue()Z

    .line 80
    .line 81
    .line 82
    move-result v3

    .line 83
    if-eqz v3, :cond_5

    .line 84
    .line 85
    const v3, -0x105bcaaa

    .line 86
    .line 87
    .line 88
    invoke-virtual {v7, v3}, Ll2/t;->Y(I)V

    .line 89
    .line 90
    .line 91
    invoke-virtual {v7, v8}, Ll2/t;->q(Z)V

    .line 92
    .line 93
    .line 94
    const/4 v3, 0x0

    .line 95
    goto :goto_3

    .line 96
    :cond_5
    const v3, 0x31054eee

    .line 97
    .line 98
    .line 99
    invoke-virtual {v7, v3}, Ll2/t;->Y(I)V

    .line 100
    .line 101
    .line 102
    sget-object v3, Lzb/x;->a:Ll2/u2;

    .line 103
    .line 104
    invoke-virtual {v7, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 105
    .line 106
    .line 107
    move-result-object v3

    .line 108
    check-cast v3, Lhi/a;

    .line 109
    .line 110
    invoke-virtual {v7, v8}, Ll2/t;->q(Z)V

    .line 111
    .line 112
    .line 113
    :goto_3
    new-instance v5, Laf/a;

    .line 114
    .line 115
    const/16 v4, 0x18

    .line 116
    .line 117
    invoke-direct {v5, v3, v2, v4}, Laf/a;-><init>(Lhi/a;Lay0/k;I)V

    .line 118
    .line 119
    .line 120
    invoke-static {v7}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 121
    .line 122
    .line 123
    move-result-object v3

    .line 124
    if-eqz v3, :cond_9

    .line 125
    .line 126
    instance-of v2, v3, Landroidx/lifecycle/k;

    .line 127
    .line 128
    if-eqz v2, :cond_6

    .line 129
    .line 130
    move-object v2, v3

    .line 131
    check-cast v2, Landroidx/lifecycle/k;

    .line 132
    .line 133
    invoke-interface {v2}, Landroidx/lifecycle/k;->getDefaultViewModelCreationExtras()Lp7/c;

    .line 134
    .line 135
    .line 136
    move-result-object v2

    .line 137
    :goto_4
    move-object v6, v2

    .line 138
    goto :goto_5

    .line 139
    :cond_6
    sget-object v2, Lp7/a;->b:Lp7/a;

    .line 140
    .line 141
    goto :goto_4

    .line 142
    :goto_5
    const-class v2, Lkh/k;

    .line 143
    .line 144
    sget-object v4, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 145
    .line 146
    invoke-virtual {v4, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 147
    .line 148
    .line 149
    move-result-object v2

    .line 150
    const/4 v4, 0x0

    .line 151
    invoke-static/range {v2 .. v7}, Ljp/se;->b(Lhy0/d;Landroidx/lifecycle/i1;Ljava/lang/String;Landroidx/lifecycle/e1;Lp7/c;Ll2/o;)Landroidx/lifecycle/b1;

    .line 152
    .line 153
    .line 154
    move-result-object v2

    .line 155
    move-object v12, v2

    .line 156
    check-cast v12, Lkh/k;

    .line 157
    .line 158
    invoke-static {v7}, Leh/a;->b(Ll2/o;)Leh/n;

    .line 159
    .line 160
    .line 161
    move-result-object v2

    .line 162
    iget-object v3, v12, Lkh/k;->g:Lyy0/l1;

    .line 163
    .line 164
    invoke-static {v3, v7}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 165
    .line 166
    .line 167
    move-result-object v3

    .line 168
    invoke-interface {v3}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 169
    .line 170
    .line 171
    move-result-object v3

    .line 172
    check-cast v3, Lkh/i;

    .line 173
    .line 174
    invoke-virtual {v7, v12}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 175
    .line 176
    .line 177
    move-result v4

    .line 178
    invoke-virtual {v7}, Ll2/t;->L()Ljava/lang/Object;

    .line 179
    .line 180
    .line 181
    move-result-object v5

    .line 182
    if-nez v4, :cond_7

    .line 183
    .line 184
    if-ne v5, v9, :cond_8

    .line 185
    .line 186
    :cond_7
    new-instance v10, Lio/ktor/utils/io/g0;

    .line 187
    .line 188
    const/16 v16, 0x0

    .line 189
    .line 190
    const/16 v17, 0x15

    .line 191
    .line 192
    const/4 v11, 0x1

    .line 193
    const-class v13, Lkh/k;

    .line 194
    .line 195
    const-string v14, "event"

    .line 196
    .line 197
    const-string v15, "event(Lcariad/charging/multicharge/kitten/wallboxes/presentation/location/WallboxLocationUiEvent;)V"

    .line 198
    .line 199
    invoke-direct/range {v10 .. v17}, Lio/ktor/utils/io/g0;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 200
    .line 201
    .line 202
    invoke-virtual {v7, v10}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 203
    .line 204
    .line 205
    move-object v5, v10

    .line 206
    :cond_8
    check-cast v5, Lhy0/g;

    .line 207
    .line 208
    check-cast v5, Lay0/k;

    .line 209
    .line 210
    invoke-interface {v2, v3, v5, v7, v8}, Leh/n;->q0(Lkh/i;Lay0/k;Ll2/o;I)V

    .line 211
    .line 212
    .line 213
    goto :goto_6

    .line 214
    :cond_9
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 215
    .line 216
    const-string v1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 217
    .line 218
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 219
    .line 220
    .line 221
    throw v0

    .line 222
    :cond_a
    invoke-virtual {v7}, Ll2/t;->R()V

    .line 223
    .line 224
    .line 225
    :goto_6
    invoke-virtual {v7}, Ll2/t;->s()Ll2/u1;

    .line 226
    .line 227
    .line 228
    move-result-object v2

    .line 229
    if-eqz v2, :cond_b

    .line 230
    .line 231
    new-instance v3, La71/d;

    .line 232
    .line 233
    const/16 v4, 0x1d

    .line 234
    .line 235
    invoke-direct {v3, v0, v1, v4}, La71/d;-><init>(Ljava/lang/String;II)V

    .line 236
    .line 237
    .line 238
    iput-object v3, v2, Ll2/u1;->d:Lay0/n;

    .line 239
    .line 240
    :cond_b
    return-void
.end method
