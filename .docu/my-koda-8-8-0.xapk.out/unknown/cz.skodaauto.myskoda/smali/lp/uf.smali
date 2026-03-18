.class public abstract Llp/uf;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Ldi/b;Ll2/o;I)V
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
    const v2, 0x525f5b85

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
    new-instance v2, Llh/a;

    .line 61
    .line 62
    const/4 v3, 0x0

    .line 63
    invoke-direct {v2, v0, v3}, Llh/a;-><init>(Ldi/b;I)V

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
    const/16 v4, 0x19

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
    const-class v2, Llh/h;

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
    check-cast v12, Llh/h;

    .line 157
    .line 158
    invoke-static {v7}, Leh/a;->b(Ll2/o;)Leh/n;

    .line 159
    .line 160
    .line 161
    move-result-object v2

    .line 162
    iget-object v3, v12, Llh/h;->f:Lyy0/l1;

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
    check-cast v3, Llh/g;

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
    new-instance v10, Ll20/g;

    .line 187
    .line 188
    const/16 v16, 0x0

    .line 189
    .line 190
    const/16 v17, 0x6

    .line 191
    .line 192
    const/4 v11, 0x1

    .line 193
    const-class v13, Llh/h;

    .line 194
    .line 195
    const-string v14, "onUiEvent"

    .line 196
    .line 197
    const-string v15, "onUiEvent(Lcariad/charging/multicharge/kitten/wallboxes/presentation/name/WallboxChangeNameUiEvent;)V"

    .line 198
    .line 199
    invoke-direct/range {v10 .. v17}, Ll20/g;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

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
    invoke-interface {v2, v3, v5, v7, v8}, Leh/n;->g(Llh/g;Lay0/k;Ll2/o;I)V

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
    new-instance v3, Lh2/y5;

    .line 232
    .line 233
    const/16 v4, 0x1d

    .line 234
    .line 235
    invoke-direct {v3, v0, v1, v4}, Lh2/y5;-><init>(Ljava/lang/Object;II)V

    .line 236
    .line 237
    .line 238
    iput-object v3, v2, Ll2/u1;->d:Lay0/n;

    .line 239
    .line 240
    :cond_b
    return-void
.end method

.method public static b(Ly4/i;)Ly4/k;
    .locals 3

    .line 1
    new-instance v0, Ly4/h;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    new-instance v1, Ly4/m;

    .line 7
    .line 8
    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    .line 9
    .line 10
    .line 11
    iput-object v1, v0, Ly4/h;->c:Ly4/m;

    .line 12
    .line 13
    new-instance v1, Ly4/k;

    .line 14
    .line 15
    invoke-direct {v1, v0}, Ly4/k;-><init>(Ly4/h;)V

    .line 16
    .line 17
    .line 18
    iput-object v1, v0, Ly4/h;->b:Ly4/k;

    .line 19
    .line 20
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 21
    .line 22
    .line 23
    move-result-object v2

    .line 24
    iput-object v2, v0, Ly4/h;->a:Ljava/lang/Object;

    .line 25
    .line 26
    :try_start_0
    invoke-interface {p0, v0}, Ly4/i;->h(Ly4/h;)Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    if-eqz p0, :cond_0

    .line 31
    .line 32
    iput-object p0, v0, Ly4/h;->a:Ljava/lang/Object;
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 33
    .line 34
    return-object v1

    .line 35
    :catch_0
    move-exception p0

    .line 36
    goto :goto_0

    .line 37
    :cond_0
    return-object v1

    .line 38
    :goto_0
    iget-object v0, v1, Ly4/k;->e:Ly4/j;

    .line 39
    .line 40
    invoke-virtual {v0, p0}, Ly4/g;->k(Ljava/lang/Throwable;)Z

    .line 41
    .line 42
    .line 43
    return-object v1
.end method
