.class public abstract Lkp/z7;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lay0/a;Lay0/a;Lsh/e;Lay0/k;Ll2/o;I)V
    .locals 11

    .line 1
    move-object v0, p4

    .line 2
    check-cast v0, Ll2/t;

    .line 3
    .line 4
    const v1, 0x3b068d0a

    .line 5
    .line 6
    .line 7
    invoke-virtual {v0, v1}, Ll2/t;->a0(I)Ll2/t;

    .line 8
    .line 9
    .line 10
    invoke-virtual {v0, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 11
    .line 12
    .line 13
    move-result v1

    .line 14
    if-eqz v1, :cond_0

    .line 15
    .line 16
    const/4 v1, 0x4

    .line 17
    goto :goto_0

    .line 18
    :cond_0
    const/4 v1, 0x2

    .line 19
    :goto_0
    or-int v1, p5, v1

    .line 20
    .line 21
    invoke-virtual {v0, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    move-result v2

    .line 25
    if-eqz v2, :cond_1

    .line 26
    .line 27
    const/16 v2, 0x20

    .line 28
    .line 29
    goto :goto_1

    .line 30
    :cond_1
    const/16 v2, 0x10

    .line 31
    .line 32
    :goto_1
    or-int/2addr v1, v2

    .line 33
    invoke-virtual {v0, p2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 34
    .line 35
    .line 36
    move-result v2

    .line 37
    const/16 v3, 0x100

    .line 38
    .line 39
    if-eqz v2, :cond_2

    .line 40
    .line 41
    move v2, v3

    .line 42
    goto :goto_2

    .line 43
    :cond_2
    const/16 v2, 0x80

    .line 44
    .line 45
    :goto_2
    or-int/2addr v1, v2

    .line 46
    invoke-virtual {v0, p3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 47
    .line 48
    .line 49
    move-result v2

    .line 50
    const/16 v4, 0x800

    .line 51
    .line 52
    if-eqz v2, :cond_3

    .line 53
    .line 54
    move v2, v4

    .line 55
    goto :goto_3

    .line 56
    :cond_3
    const/16 v2, 0x400

    .line 57
    .line 58
    :goto_3
    or-int/2addr v1, v2

    .line 59
    and-int/lit16 v2, v1, 0x493

    .line 60
    .line 61
    const/16 v5, 0x492

    .line 62
    .line 63
    const/4 v7, 0x0

    .line 64
    const/4 v8, 0x1

    .line 65
    if-eq v2, v5, :cond_4

    .line 66
    .line 67
    move v2, v8

    .line 68
    goto :goto_4

    .line 69
    :cond_4
    move v2, v7

    .line 70
    :goto_4
    and-int/lit8 v5, v1, 0x1

    .line 71
    .line 72
    invoke-virtual {v0, v5, v2}, Ll2/t;->O(IZ)Z

    .line 73
    .line 74
    .line 75
    move-result v2

    .line 76
    if-eqz v2, :cond_9

    .line 77
    .line 78
    move v2, v7

    .line 79
    invoke-static {p0, v0}, Ll2/b;->s(Ljava/lang/Object;Ll2/o;)Ll2/b1;

    .line 80
    .line 81
    .line 82
    move-result-object v7

    .line 83
    move v5, v8

    .line 84
    invoke-static {p1, v0}, Ll2/b;->s(Ljava/lang/Object;Ll2/o;)Ll2/b1;

    .line 85
    .line 86
    .line 87
    move-result-object v8

    .line 88
    and-int/lit16 v9, v1, 0x380

    .line 89
    .line 90
    if-ne v9, v3, :cond_5

    .line 91
    .line 92
    move v3, v5

    .line 93
    goto :goto_5

    .line 94
    :cond_5
    move v3, v2

    .line 95
    :goto_5
    invoke-virtual {v0, v7}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 96
    .line 97
    .line 98
    move-result v9

    .line 99
    or-int/2addr v3, v9

    .line 100
    and-int/lit16 v1, v1, 0x1c00

    .line 101
    .line 102
    if-ne v1, v4, :cond_6

    .line 103
    .line 104
    move v2, v5

    .line 105
    :cond_6
    or-int v1, v3, v2

    .line 106
    .line 107
    invoke-virtual {v0, v8}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 108
    .line 109
    .line 110
    move-result v2

    .line 111
    or-int/2addr v1, v2

    .line 112
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 113
    .line 114
    .line 115
    move-result-object v2

    .line 116
    if-nez v1, :cond_7

    .line 117
    .line 118
    sget-object v1, Ll2/n;->a:Ll2/x0;

    .line 119
    .line 120
    if-ne v2, v1, :cond_8

    .line 121
    .line 122
    :cond_7
    new-instance v4, Lff/a;

    .line 123
    .line 124
    const/4 v9, 0x0

    .line 125
    const/16 v10, 0x9

    .line 126
    .line 127
    move-object v5, p2

    .line 128
    move-object v6, p3

    .line 129
    invoke-direct/range {v4 .. v10}, Lff/a;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 130
    .line 131
    .line 132
    invoke-virtual {v0, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 133
    .line 134
    .line 135
    move-object v2, v4

    .line 136
    :cond_8
    check-cast v2, Lay0/n;

    .line 137
    .line 138
    invoke-static {v2, p2, v0}, Ll2/l0;->d(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 139
    .line 140
    .line 141
    goto :goto_6

    .line 142
    :cond_9
    invoke-virtual {v0}, Ll2/t;->R()V

    .line 143
    .line 144
    .line 145
    :goto_6
    invoke-virtual {v0}, Ll2/t;->s()Ll2/u1;

    .line 146
    .line 147
    .line 148
    move-result-object v0

    .line 149
    if-eqz v0, :cond_a

    .line 150
    .line 151
    new-instance v4, Lo50/p;

    .line 152
    .line 153
    const/16 v10, 0xa

    .line 154
    .line 155
    move-object v5, p0

    .line 156
    move-object v6, p1

    .line 157
    move-object v7, p2

    .line 158
    move-object v8, p3

    .line 159
    move/from16 v9, p5

    .line 160
    .line 161
    invoke-direct/range {v4 .. v10}, Lo50/p;-><init>(Lay0/a;Ljava/lang/Object;Ljava/lang/Object;Llx0/e;II)V

    .line 162
    .line 163
    .line 164
    iput-object v4, v0, Ll2/u1;->d:Lay0/n;

    .line 165
    .line 166
    :cond_a
    return-void
.end method

.method public static final b(Ldi/a;Ll2/o;I)V
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
    const v2, 0x237410a1

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
    new-instance v2, Lfh/a;

    .line 61
    .line 62
    const/4 v3, 0x0

    .line 63
    invoke-direct {v2, v0, v3}, Lfh/a;-><init>(Ldi/a;I)V

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
    const/16 v4, 0xc

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
    const-class v2, Lfh/g;

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
    check-cast v12, Lfh/g;

    .line 157
    .line 158
    invoke-static {v7}, Leh/a;->b(Ll2/o;)Leh/n;

    .line 159
    .line 160
    .line 161
    move-result-object v2

    .line 162
    iget-object v3, v12, Lfh/g;->g:Lyy0/l1;

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
    check-cast v3, Lfh/f;

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
    new-instance v10, Lei/a;

    .line 187
    .line 188
    const/16 v16, 0x0

    .line 189
    .line 190
    const/16 v17, 0xf

    .line 191
    .line 192
    const/4 v11, 0x1

    .line 193
    const-class v13, Lfh/g;

    .line 194
    .line 195
    const-string v14, "onUiEvent"

    .line 196
    .line 197
    const-string v15, "onUiEvent(Lcariad/charging/multicharge/kitten/wallboxes/presentation/authorization/WallboxChangeAuthModeUiEvent;)V"

    .line 198
    .line 199
    invoke-direct/range {v10 .. v17}, Lei/a;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

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
    invoke-interface {v2, v3, v5, v7, v8}, Leh/n;->B0(Lfh/f;Lay0/k;Ll2/o;I)V

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
    new-instance v3, La71/a0;

    .line 232
    .line 233
    const/16 v4, 0x16

    .line 234
    .line 235
    invoke-direct {v3, v0, v1, v4}, La71/a0;-><init>(Ljava/lang/Object;II)V

    .line 236
    .line 237
    .line 238
    iput-object v3, v2, Ll2/u1;->d:Lay0/n;

    .line 239
    .line 240
    :cond_b
    return-void
.end method

.method public static final c(Lay0/a;Lay0/a;Ll2/o;I)V
    .locals 23

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move/from16 v6, p3

    .line 6
    .line 7
    const-string v2, "goToManualPairing"

    .line 8
    .line 9
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    const-string v2, "goToScannerPairing"

    .line 13
    .line 14
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    move-object/from16 v12, p2

    .line 18
    .line 19
    check-cast v12, Ll2/t;

    .line 20
    .line 21
    const v2, 0x39cfaf5

    .line 22
    .line 23
    .line 24
    invoke-virtual {v12, v2}, Ll2/t;->a0(I)Ll2/t;

    .line 25
    .line 26
    .line 27
    invoke-virtual {v12, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result v2

    .line 31
    if-eqz v2, :cond_0

    .line 32
    .line 33
    const/4 v2, 0x4

    .line 34
    goto :goto_0

    .line 35
    :cond_0
    const/4 v2, 0x2

    .line 36
    :goto_0
    or-int/2addr v2, v6

    .line 37
    invoke-virtual {v12, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 38
    .line 39
    .line 40
    move-result v3

    .line 41
    if-eqz v3, :cond_1

    .line 42
    .line 43
    const/16 v3, 0x20

    .line 44
    .line 45
    goto :goto_1

    .line 46
    :cond_1
    const/16 v3, 0x10

    .line 47
    .line 48
    :goto_1
    or-int/2addr v2, v3

    .line 49
    and-int/lit8 v3, v2, 0x13

    .line 50
    .line 51
    const/16 v4, 0x12

    .line 52
    .line 53
    const/4 v13, 0x0

    .line 54
    if-eq v3, v4, :cond_2

    .line 55
    .line 56
    const/4 v3, 0x1

    .line 57
    goto :goto_2

    .line 58
    :cond_2
    move v3, v13

    .line 59
    :goto_2
    and-int/lit8 v4, v2, 0x1

    .line 60
    .line 61
    invoke-virtual {v12, v4, v3}, Ll2/t;->O(IZ)Z

    .line 62
    .line 63
    .line 64
    move-result v3

    .line 65
    if-eqz v3, :cond_b

    .line 66
    .line 67
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 68
    .line 69
    .line 70
    move-result-object v3

    .line 71
    sget-object v14, Ll2/n;->a:Ll2/x0;

    .line 72
    .line 73
    if-ne v3, v14, :cond_3

    .line 74
    .line 75
    new-instance v3, Lsb/a;

    .line 76
    .line 77
    const/16 v4, 0x8

    .line 78
    .line 79
    invoke-direct {v3, v4}, Lsb/a;-><init>(I)V

    .line 80
    .line 81
    .line 82
    invoke-virtual {v12, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 83
    .line 84
    .line 85
    :cond_3
    check-cast v3, Lay0/k;

    .line 86
    .line 87
    sget-object v4, Lw3/q1;->a:Ll2/u2;

    .line 88
    .line 89
    invoke-virtual {v12, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 90
    .line 91
    .line 92
    move-result-object v4

    .line 93
    check-cast v4, Ljava/lang/Boolean;

    .line 94
    .line 95
    invoke-virtual {v4}, Ljava/lang/Boolean;->booleanValue()Z

    .line 96
    .line 97
    .line 98
    move-result v4

    .line 99
    if-eqz v4, :cond_4

    .line 100
    .line 101
    const v4, -0x105bcaaa

    .line 102
    .line 103
    .line 104
    invoke-virtual {v12, v4}, Ll2/t;->Y(I)V

    .line 105
    .line 106
    .line 107
    invoke-virtual {v12, v13}, Ll2/t;->q(Z)V

    .line 108
    .line 109
    .line 110
    const/4 v4, 0x0

    .line 111
    goto :goto_3

    .line 112
    :cond_4
    const v4, 0x31054eee

    .line 113
    .line 114
    .line 115
    invoke-virtual {v12, v4}, Ll2/t;->Y(I)V

    .line 116
    .line 117
    .line 118
    sget-object v4, Lzb/x;->a:Ll2/u2;

    .line 119
    .line 120
    invoke-virtual {v12, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 121
    .line 122
    .line 123
    move-result-object v4

    .line 124
    check-cast v4, Lhi/a;

    .line 125
    .line 126
    invoke-virtual {v12, v13}, Ll2/t;->q(Z)V

    .line 127
    .line 128
    .line 129
    :goto_3
    new-instance v10, Lnd/e;

    .line 130
    .line 131
    const/16 v5, 0x16

    .line 132
    .line 133
    invoke-direct {v10, v4, v3, v5}, Lnd/e;-><init>(Lhi/a;Lay0/k;I)V

    .line 134
    .line 135
    .line 136
    invoke-static {v12}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 137
    .line 138
    .line 139
    move-result-object v8

    .line 140
    if-eqz v8, :cond_a

    .line 141
    .line 142
    instance-of v3, v8, Landroidx/lifecycle/k;

    .line 143
    .line 144
    if-eqz v3, :cond_5

    .line 145
    .line 146
    move-object v3, v8

    .line 147
    check-cast v3, Landroidx/lifecycle/k;

    .line 148
    .line 149
    invoke-interface {v3}, Landroidx/lifecycle/k;->getDefaultViewModelCreationExtras()Lp7/c;

    .line 150
    .line 151
    .line 152
    move-result-object v3

    .line 153
    :goto_4
    move-object v11, v3

    .line 154
    goto :goto_5

    .line 155
    :cond_5
    sget-object v3, Lp7/a;->b:Lp7/a;

    .line 156
    .line 157
    goto :goto_4

    .line 158
    :goto_5
    const-class v3, Lsh/g;

    .line 159
    .line 160
    sget-object v4, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 161
    .line 162
    invoke-virtual {v4, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 163
    .line 164
    .line 165
    move-result-object v7

    .line 166
    const/4 v9, 0x0

    .line 167
    invoke-static/range {v7 .. v12}, Ljp/se;->b(Lhy0/d;Landroidx/lifecycle/i1;Ljava/lang/String;Landroidx/lifecycle/e1;Lp7/c;Ll2/o;)Landroidx/lifecycle/b1;

    .line 168
    .line 169
    .line 170
    move-result-object v3

    .line 171
    check-cast v3, Lsh/g;

    .line 172
    .line 173
    iget-object v4, v3, Lsh/g;->e:Lyy0/l1;

    .line 174
    .line 175
    invoke-static {v4, v12}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 176
    .line 177
    .line 178
    move-result-object v7

    .line 179
    invoke-interface {v7}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 180
    .line 181
    .line 182
    move-result-object v4

    .line 183
    check-cast v4, Lsh/e;

    .line 184
    .line 185
    invoke-virtual {v12, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 186
    .line 187
    .line 188
    move-result v5

    .line 189
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 190
    .line 191
    .line 192
    move-result-object v8

    .line 193
    if-nez v5, :cond_7

    .line 194
    .line 195
    if-ne v8, v14, :cond_6

    .line 196
    .line 197
    goto :goto_6

    .line 198
    :cond_6
    move-object v15, v8

    .line 199
    move-object v8, v3

    .line 200
    goto :goto_7

    .line 201
    :cond_7
    :goto_6
    new-instance v15, Ls60/h;

    .line 202
    .line 203
    const/16 v21, 0x0

    .line 204
    .line 205
    const/16 v22, 0x17

    .line 206
    .line 207
    const/16 v16, 0x1

    .line 208
    .line 209
    const-class v18, Lsh/g;

    .line 210
    .line 211
    const-string v19, "onUiEvent"

    .line 212
    .line 213
    const-string v20, "onUiEvent(Lcariad/charging/multicharge/kitten/wallboxes/presentation/onboarding/pairingoptions/WallboxPairingOptionsUiEvent;)V"

    .line 214
    .line 215
    move-object/from16 v17, v3

    .line 216
    .line 217
    invoke-direct/range {v15 .. v22}, Ls60/h;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 218
    .line 219
    .line 220
    move-object/from16 v8, v17

    .line 221
    .line 222
    invoke-virtual {v12, v15}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 223
    .line 224
    .line 225
    :goto_7
    check-cast v15, Lhy0/g;

    .line 226
    .line 227
    move-object v3, v15

    .line 228
    check-cast v3, Lay0/k;

    .line 229
    .line 230
    and-int/lit8 v5, v2, 0x7e

    .line 231
    .line 232
    move-object v2, v4

    .line 233
    move-object v4, v12

    .line 234
    invoke-static/range {v0 .. v5}, Lkp/z7;->a(Lay0/a;Lay0/a;Lsh/e;Lay0/k;Ll2/o;I)V

    .line 235
    .line 236
    .line 237
    invoke-static {v12}, Leh/a;->b(Ll2/o;)Leh/n;

    .line 238
    .line 239
    .line 240
    move-result-object v2

    .line 241
    invoke-interface {v7}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 242
    .line 243
    .line 244
    move-result-object v3

    .line 245
    check-cast v3, Lsh/e;

    .line 246
    .line 247
    invoke-virtual {v12, v8}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 248
    .line 249
    .line 250
    move-result v4

    .line 251
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 252
    .line 253
    .line 254
    move-result-object v5

    .line 255
    if-nez v4, :cond_8

    .line 256
    .line 257
    if-ne v5, v14, :cond_9

    .line 258
    .line 259
    :cond_8
    new-instance v15, Ls60/h;

    .line 260
    .line 261
    const/16 v21, 0x0

    .line 262
    .line 263
    const/16 v22, 0x18

    .line 264
    .line 265
    const/16 v16, 0x1

    .line 266
    .line 267
    const-class v18, Lsh/g;

    .line 268
    .line 269
    const-string v19, "onUiEvent"

    .line 270
    .line 271
    const-string v20, "onUiEvent(Lcariad/charging/multicharge/kitten/wallboxes/presentation/onboarding/pairingoptions/WallboxPairingOptionsUiEvent;)V"

    .line 272
    .line 273
    move-object/from16 v17, v8

    .line 274
    .line 275
    invoke-direct/range {v15 .. v22}, Ls60/h;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 276
    .line 277
    .line 278
    invoke-virtual {v12, v15}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 279
    .line 280
    .line 281
    move-object v5, v15

    .line 282
    :cond_9
    check-cast v5, Lhy0/g;

    .line 283
    .line 284
    check-cast v5, Lay0/k;

    .line 285
    .line 286
    invoke-interface {v2, v3, v5, v12, v13}, Leh/n;->w0(Lsh/e;Lay0/k;Ll2/o;I)V

    .line 287
    .line 288
    .line 289
    goto :goto_8

    .line 290
    :cond_a
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 291
    .line 292
    const-string v1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 293
    .line 294
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 295
    .line 296
    .line 297
    throw v0

    .line 298
    :cond_b
    invoke-virtual {v12}, Ll2/t;->R()V

    .line 299
    .line 300
    .line 301
    :goto_8
    invoke-virtual {v12}, Ll2/t;->s()Ll2/u1;

    .line 302
    .line 303
    .line 304
    move-result-object v2

    .line 305
    if-eqz v2, :cond_c

    .line 306
    .line 307
    new-instance v3, Lbf/b;

    .line 308
    .line 309
    const/16 v4, 0x13

    .line 310
    .line 311
    invoke-direct {v3, v0, v1, v6, v4}, Lbf/b;-><init>(Lay0/a;Lay0/a;II)V

    .line 312
    .line 313
    .line 314
    iput-object v3, v2, Ll2/u1;->d:Lay0/n;

    .line 315
    .line 316
    :cond_c
    return-void
.end method
