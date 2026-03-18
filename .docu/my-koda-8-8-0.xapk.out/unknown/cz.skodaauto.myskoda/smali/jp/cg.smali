.class public abstract Ljp/cg;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Ll2/o;I)V
    .locals 17

    .line 1
    move/from16 v0, p1

    .line 2
    .line 3
    move-object/from16 v8, p0

    .line 4
    .line 5
    check-cast v8, Ll2/t;

    .line 6
    .line 7
    const v1, -0x6faf2ef1

    .line 8
    .line 9
    .line 10
    invoke-virtual {v8, v1}, Ll2/t;->a0(I)Ll2/t;

    .line 11
    .line 12
    .line 13
    const/4 v1, 0x1

    .line 14
    const/4 v2, 0x0

    .line 15
    if-eqz v0, :cond_0

    .line 16
    .line 17
    move v3, v1

    .line 18
    goto :goto_0

    .line 19
    :cond_0
    move v3, v2

    .line 20
    :goto_0
    and-int/lit8 v4, v0, 0x1

    .line 21
    .line 22
    invoke-virtual {v8, v4, v3}, Ll2/t;->O(IZ)Z

    .line 23
    .line 24
    .line 25
    move-result v3

    .line 26
    if-eqz v3, :cond_8

    .line 27
    .line 28
    const v3, -0x6040e0aa

    .line 29
    .line 30
    .line 31
    invoke-virtual {v8, v3}, Ll2/t;->Y(I)V

    .line 32
    .line 33
    .line 34
    invoke-static {v8}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 35
    .line 36
    .line 37
    move-result-object v3

    .line 38
    if-eqz v3, :cond_7

    .line 39
    .line 40
    invoke-static {v3}, Ljp/ib;->a(Landroidx/lifecycle/i1;)Lp7/c;

    .line 41
    .line 42
    .line 43
    move-result-object v12

    .line 44
    invoke-static {v8}, Lw11/c;->b(Ll2/o;)Lk21/a;

    .line 45
    .line 46
    .line 47
    move-result-object v14

    .line 48
    const-class v4, Lc90/j0;

    .line 49
    .line 50
    sget-object v5, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 51
    .line 52
    invoke-virtual {v5, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 53
    .line 54
    .line 55
    move-result-object v9

    .line 56
    invoke-interface {v3}, Landroidx/lifecycle/i1;->getViewModelStore()Landroidx/lifecycle/h1;

    .line 57
    .line 58
    .line 59
    move-result-object v10

    .line 60
    const/4 v11, 0x0

    .line 61
    const/4 v13, 0x0

    .line 62
    const/4 v15, 0x0

    .line 63
    invoke-static/range {v9 .. v15}, Ljp/lb;->a(Lhy0/d;Landroidx/lifecycle/h1;Ljava/lang/String;Lp7/c;Lh21/b;Lk21/a;Lay0/a;)Landroidx/lifecycle/b1;

    .line 64
    .line 65
    .line 66
    move-result-object v3

    .line 67
    invoke-virtual {v8, v2}, Ll2/t;->q(Z)V

    .line 68
    .line 69
    .line 70
    check-cast v3, Lql0/j;

    .line 71
    .line 72
    invoke-static {v3, v8, v2, v1}, Lkp/x5;->b(Lql0/j;Ll2/o;II)V

    .line 73
    .line 74
    .line 75
    move-object v11, v3

    .line 76
    check-cast v11, Lc90/j0;

    .line 77
    .line 78
    iget-object v3, v11, Lql0/j;->g:Lyy0/l1;

    .line 79
    .line 80
    const/4 v4, 0x0

    .line 81
    invoke-static {v3, v4, v8, v1}, Ll2/b;->f(Lyy0/a2;Lwy0/c;Ll2/o;I)Ll2/b1;

    .line 82
    .line 83
    .line 84
    move-result-object v1

    .line 85
    invoke-interface {v1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 86
    .line 87
    .line 88
    move-result-object v1

    .line 89
    check-cast v1, Lc90/i0;

    .line 90
    .line 91
    invoke-virtual {v8, v11}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 92
    .line 93
    .line 94
    move-result v3

    .line 95
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 96
    .line 97
    .line 98
    move-result-object v4

    .line 99
    sget-object v5, Ll2/n;->a:Ll2/x0;

    .line 100
    .line 101
    if-nez v3, :cond_1

    .line 102
    .line 103
    if-ne v4, v5, :cond_2

    .line 104
    .line 105
    :cond_1
    new-instance v9, Ld90/n;

    .line 106
    .line 107
    const/4 v15, 0x0

    .line 108
    const/16 v16, 0x0

    .line 109
    .line 110
    const/4 v10, 0x0

    .line 111
    const-class v12, Lc90/j0;

    .line 112
    .line 113
    const-string v13, "onFinish"

    .line 114
    .line 115
    const-string v14, "onFinish()V"

    .line 116
    .line 117
    invoke-direct/range {v9 .. v16}, Ld90/n;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 118
    .line 119
    .line 120
    invoke-virtual {v8, v9}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 121
    .line 122
    .line 123
    move-object v4, v9

    .line 124
    :cond_2
    check-cast v4, Lhy0/g;

    .line 125
    .line 126
    check-cast v4, Lay0/a;

    .line 127
    .line 128
    invoke-static {v1, v4, v8, v2}, Ljp/cg;->b(Lc90/i0;Lay0/a;Ll2/o;I)V

    .line 129
    .line 130
    .line 131
    invoke-virtual {v8, v11}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 132
    .line 133
    .line 134
    move-result v1

    .line 135
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 136
    .line 137
    .line 138
    move-result-object v2

    .line 139
    if-nez v1, :cond_3

    .line 140
    .line 141
    if-ne v2, v5, :cond_4

    .line 142
    .line 143
    :cond_3
    new-instance v9, Ld90/n;

    .line 144
    .line 145
    const/4 v15, 0x0

    .line 146
    const/16 v16, 0x1

    .line 147
    .line 148
    const/4 v10, 0x0

    .line 149
    const-class v12, Lc90/j0;

    .line 150
    .line 151
    const-string v13, "onStart"

    .line 152
    .line 153
    const-string v14, "onStart()V"

    .line 154
    .line 155
    invoke-direct/range {v9 .. v16}, Ld90/n;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 156
    .line 157
    .line 158
    invoke-virtual {v8, v9}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 159
    .line 160
    .line 161
    move-object v2, v9

    .line 162
    :cond_4
    check-cast v2, Lhy0/g;

    .line 163
    .line 164
    move-object v3, v2

    .line 165
    check-cast v3, Lay0/a;

    .line 166
    .line 167
    invoke-virtual {v8, v11}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 168
    .line 169
    .line 170
    move-result v1

    .line 171
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 172
    .line 173
    .line 174
    move-result-object v2

    .line 175
    if-nez v1, :cond_5

    .line 176
    .line 177
    if-ne v2, v5, :cond_6

    .line 178
    .line 179
    :cond_5
    new-instance v9, Ld90/n;

    .line 180
    .line 181
    const/4 v15, 0x0

    .line 182
    const/16 v16, 0x2

    .line 183
    .line 184
    const/4 v10, 0x0

    .line 185
    const-class v12, Lc90/j0;

    .line 186
    .line 187
    const-string v13, "onStop"

    .line 188
    .line 189
    const-string v14, "onStop()V"

    .line 190
    .line 191
    invoke-direct/range {v9 .. v16}, Ld90/n;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 192
    .line 193
    .line 194
    invoke-virtual {v8, v9}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 195
    .line 196
    .line 197
    move-object v2, v9

    .line 198
    :cond_6
    check-cast v2, Lhy0/g;

    .line 199
    .line 200
    move-object v6, v2

    .line 201
    check-cast v6, Lay0/a;

    .line 202
    .line 203
    const/4 v9, 0x0

    .line 204
    const/16 v10, 0xdb

    .line 205
    .line 206
    const/4 v1, 0x0

    .line 207
    const/4 v2, 0x0

    .line 208
    const/4 v4, 0x0

    .line 209
    const/4 v5, 0x0

    .line 210
    const/4 v7, 0x0

    .line 211
    invoke-static/range {v1 .. v10}, Lxf0/i0;->z(Landroidx/lifecycle/x;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Ll2/o;II)V

    .line 212
    .line 213
    .line 214
    goto :goto_1

    .line 215
    :cond_7
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 216
    .line 217
    const-string v1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 218
    .line 219
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 220
    .line 221
    .line 222
    throw v0

    .line 223
    :cond_8
    invoke-virtual {v8}, Ll2/t;->R()V

    .line 224
    .line 225
    .line 226
    :goto_1
    invoke-virtual {v8}, Ll2/t;->s()Ll2/u1;

    .line 227
    .line 228
    .line 229
    move-result-object v1

    .line 230
    if-eqz v1, :cond_9

    .line 231
    .line 232
    new-instance v2, Ld80/m;

    .line 233
    .line 234
    const/16 v3, 0x9

    .line 235
    .line 236
    invoke-direct {v2, v0, v3}, Ld80/m;-><init>(II)V

    .line 237
    .line 238
    .line 239
    iput-object v2, v1, Ll2/u1;->d:Lay0/n;

    .line 240
    .line 241
    :cond_9
    return-void
.end method

.method public static final b(Lc90/i0;Lay0/a;Ll2/o;I)V
    .locals 33

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v3, p1

    .line 4
    .line 5
    move/from16 v10, p3

    .line 6
    .line 7
    move-object/from16 v6, p2

    .line 8
    .line 9
    check-cast v6, Ll2/t;

    .line 10
    .line 11
    const v1, -0x35da404a    # -2715629.5f

    .line 12
    .line 13
    .line 14
    invoke-virtual {v6, v1}, Ll2/t;->a0(I)Ll2/t;

    .line 15
    .line 16
    .line 17
    invoke-virtual {v6, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-eqz v1, :cond_0

    .line 22
    .line 23
    const/4 v1, 0x4

    .line 24
    goto :goto_0

    .line 25
    :cond_0
    const/4 v1, 0x2

    .line 26
    :goto_0
    or-int/2addr v1, v10

    .line 27
    invoke-virtual {v6, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result v4

    .line 31
    if-eqz v4, :cond_1

    .line 32
    .line 33
    const/16 v4, 0x20

    .line 34
    .line 35
    goto :goto_1

    .line 36
    :cond_1
    const/16 v4, 0x10

    .line 37
    .line 38
    :goto_1
    or-int/2addr v1, v4

    .line 39
    and-int/lit8 v4, v1, 0x13

    .line 40
    .line 41
    const/16 v5, 0x12

    .line 42
    .line 43
    const/4 v11, 0x1

    .line 44
    const/4 v12, 0x0

    .line 45
    if-eq v4, v5, :cond_2

    .line 46
    .line 47
    move v4, v11

    .line 48
    goto :goto_2

    .line 49
    :cond_2
    move v4, v12

    .line 50
    :goto_2
    and-int/lit8 v5, v1, 0x1

    .line 51
    .line 52
    invoke-virtual {v6, v5, v4}, Ll2/t;->O(IZ)Z

    .line 53
    .line 54
    .line 55
    move-result v4

    .line 56
    if-eqz v4, :cond_b

    .line 57
    .line 58
    sget-object v8, Landroidx/compose/foundation/layout/d;->c:Landroidx/compose/foundation/layout/FillElement;

    .line 59
    .line 60
    sget-object v4, Lj91/h;->a:Ll2/u2;

    .line 61
    .line 62
    invoke-virtual {v6, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object v4

    .line 66
    check-cast v4, Lj91/e;

    .line 67
    .line 68
    invoke-virtual {v4}, Lj91/e;->b()J

    .line 69
    .line 70
    .line 71
    move-result-wide v4

    .line 72
    sget-object v7, Le3/j0;->a:Le3/i0;

    .line 73
    .line 74
    invoke-static {v8, v4, v5, v7}, Landroidx/compose/foundation/a;->b(Lx2/s;JLe3/n0;)Lx2/s;

    .line 75
    .line 76
    .line 77
    move-result-object v4

    .line 78
    sget-object v5, Lx2/c;->d:Lx2/j;

    .line 79
    .line 80
    invoke-static {v5, v12}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 81
    .line 82
    .line 83
    move-result-object v5

    .line 84
    iget-wide v13, v6, Ll2/t;->T:J

    .line 85
    .line 86
    invoke-static {v13, v14}, Ljava/lang/Long;->hashCode(J)I

    .line 87
    .line 88
    .line 89
    move-result v7

    .line 90
    invoke-virtual {v6}, Ll2/t;->m()Ll2/p1;

    .line 91
    .line 92
    .line 93
    move-result-object v9

    .line 94
    invoke-static {v6, v4}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 95
    .line 96
    .line 97
    move-result-object v4

    .line 98
    sget-object v13, Lv3/k;->m1:Lv3/j;

    .line 99
    .line 100
    invoke-virtual {v13}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 101
    .line 102
    .line 103
    sget-object v13, Lv3/j;->b:Lv3/i;

    .line 104
    .line 105
    invoke-virtual {v6}, Ll2/t;->c0()V

    .line 106
    .line 107
    .line 108
    iget-boolean v14, v6, Ll2/t;->S:Z

    .line 109
    .line 110
    if-eqz v14, :cond_3

    .line 111
    .line 112
    invoke-virtual {v6, v13}, Ll2/t;->l(Lay0/a;)V

    .line 113
    .line 114
    .line 115
    goto :goto_3

    .line 116
    :cond_3
    invoke-virtual {v6}, Ll2/t;->m0()V

    .line 117
    .line 118
    .line 119
    :goto_3
    sget-object v14, Lv3/j;->g:Lv3/h;

    .line 120
    .line 121
    invoke-static {v14, v5, v6}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 122
    .line 123
    .line 124
    sget-object v15, Lv3/j;->f:Lv3/h;

    .line 125
    .line 126
    invoke-static {v15, v9, v6}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 127
    .line 128
    .line 129
    sget-object v5, Lv3/j;->j:Lv3/h;

    .line 130
    .line 131
    iget-boolean v9, v6, Ll2/t;->S:Z

    .line 132
    .line 133
    if-nez v9, :cond_4

    .line 134
    .line 135
    invoke-virtual {v6}, Ll2/t;->L()Ljava/lang/Object;

    .line 136
    .line 137
    .line 138
    move-result-object v9

    .line 139
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 140
    .line 141
    .line 142
    move-result-object v2

    .line 143
    invoke-static {v9, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 144
    .line 145
    .line 146
    move-result v2

    .line 147
    if-nez v2, :cond_5

    .line 148
    .line 149
    :cond_4
    invoke-static {v7, v6, v7, v5}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 150
    .line 151
    .line 152
    :cond_5
    sget-object v2, Lv3/j;->d:Lv3/h;

    .line 153
    .line 154
    invoke-static {v2, v4, v6}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 155
    .line 156
    .line 157
    and-int/lit8 v1, v1, 0x70

    .line 158
    .line 159
    invoke-static {v12, v3, v6, v1, v11}, Ljp/tb;->a(ZLay0/a;Ll2/o;II)V

    .line 160
    .line 161
    .line 162
    iget-boolean v4, v0, Lc90/i0;->a:Z

    .line 163
    .line 164
    if-eqz v4, :cond_6

    .line 165
    .line 166
    const v4, 0x6e5cbf52

    .line 167
    .line 168
    .line 169
    invoke-virtual {v6, v4}, Ll2/t;->Y(I)V

    .line 170
    .line 171
    .line 172
    const/16 v4, 0x36

    .line 173
    .line 174
    move-object v7, v5

    .line 175
    const/4 v5, 0x4

    .line 176
    move-object/from16 v29, v6

    .line 177
    .line 178
    const-string v6, "test_drive_player"

    .line 179
    .line 180
    const/4 v9, 0x0

    .line 181
    move-object v11, v7

    .line 182
    move-object/from16 v7, v29

    .line 183
    .line 184
    invoke-static/range {v4 .. v9}, Llp/qa;->a(IILjava/lang/String;Ll2/o;Lx2/s;Z)V

    .line 185
    .line 186
    .line 187
    move-object v6, v7

    .line 188
    :goto_4
    invoke-virtual {v6, v12}, Ll2/t;->q(Z)V

    .line 189
    .line 190
    .line 191
    goto :goto_5

    .line 192
    :cond_6
    move-object v11, v5

    .line 193
    const v4, 0x6e38bcb2

    .line 194
    .line 195
    .line 196
    invoke-virtual {v6, v4}, Ll2/t;->Y(I)V

    .line 197
    .line 198
    .line 199
    goto :goto_4

    .line 200
    :goto_5
    sget-object v4, Lx2/p;->b:Lx2/p;

    .line 201
    .line 202
    invoke-static {v4}, Lk1/d;->n(Lx2/s;)Lx2/s;

    .line 203
    .line 204
    .line 205
    move-result-object v5

    .line 206
    invoke-static {v5}, Lk1/d;->m(Lx2/s;)Lx2/s;

    .line 207
    .line 208
    .line 209
    move-result-object v5

    .line 210
    sget-object v7, Lj91/a;->a:Ll2/u2;

    .line 211
    .line 212
    invoke-virtual {v6, v7}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 213
    .line 214
    .line 215
    move-result-object v8

    .line 216
    check-cast v8, Lj91/c;

    .line 217
    .line 218
    iget v8, v8, Lj91/c;->d:F

    .line 219
    .line 220
    const/4 v9, 0x0

    .line 221
    const/4 v12, 0x2

    .line 222
    invoke-static {v5, v8, v9, v12}, Landroidx/compose/foundation/layout/a;->o(Lx2/s;FFI)Lx2/s;

    .line 223
    .line 224
    .line 225
    move-result-object v5

    .line 226
    sget-object v8, Lk1/j;->c:Lk1/e;

    .line 227
    .line 228
    sget-object v9, Lx2/c;->p:Lx2/h;

    .line 229
    .line 230
    const/4 v12, 0x0

    .line 231
    invoke-static {v8, v9, v6, v12}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 232
    .line 233
    .line 234
    move-result-object v8

    .line 235
    move/from16 p2, v1

    .line 236
    .line 237
    iget-wide v0, v6, Ll2/t;->T:J

    .line 238
    .line 239
    invoke-static {v0, v1}, Ljava/lang/Long;->hashCode(J)I

    .line 240
    .line 241
    .line 242
    move-result v0

    .line 243
    invoke-virtual {v6}, Ll2/t;->m()Ll2/p1;

    .line 244
    .line 245
    .line 246
    move-result-object v1

    .line 247
    invoke-static {v6, v5}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 248
    .line 249
    .line 250
    move-result-object v5

    .line 251
    invoke-virtual {v6}, Ll2/t;->c0()V

    .line 252
    .line 253
    .line 254
    iget-boolean v9, v6, Ll2/t;->S:Z

    .line 255
    .line 256
    if-eqz v9, :cond_7

    .line 257
    .line 258
    invoke-virtual {v6, v13}, Ll2/t;->l(Lay0/a;)V

    .line 259
    .line 260
    .line 261
    goto :goto_6

    .line 262
    :cond_7
    invoke-virtual {v6}, Ll2/t;->m0()V

    .line 263
    .line 264
    .line 265
    :goto_6
    invoke-static {v14, v8, v6}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 266
    .line 267
    .line 268
    invoke-static {v15, v1, v6}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 269
    .line 270
    .line 271
    iget-boolean v1, v6, Ll2/t;->S:Z

    .line 272
    .line 273
    if-nez v1, :cond_8

    .line 274
    .line 275
    invoke-virtual {v6}, Ll2/t;->L()Ljava/lang/Object;

    .line 276
    .line 277
    .line 278
    move-result-object v1

    .line 279
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 280
    .line 281
    .line 282
    move-result-object v8

    .line 283
    invoke-static {v1, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 284
    .line 285
    .line 286
    move-result v1

    .line 287
    if-nez v1, :cond_9

    .line 288
    .line 289
    :cond_8
    invoke-static {v0, v6, v0, v11}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 290
    .line 291
    .line 292
    :cond_9
    invoke-static {v2, v5, v6}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 293
    .line 294
    .line 295
    invoke-virtual {v6, v7}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 296
    .line 297
    .line 298
    move-result-object v0

    .line 299
    check-cast v0, Lj91/c;

    .line 300
    .line 301
    iget v0, v0, Lj91/c;->i:F

    .line 302
    .line 303
    const v1, 0x7f121291

    .line 304
    .line 305
    .line 306
    invoke-static {v4, v0, v6, v1, v6}, Lvj/b;->m(Lx2/p;FLl2/t;ILl2/t;)Ljava/lang/String;

    .line 307
    .line 308
    .line 309
    move-result-object v11

    .line 310
    sget-object v0, Lj91/j;->a:Ll2/u2;

    .line 311
    .line 312
    invoke-virtual {v6, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 313
    .line 314
    .line 315
    move-result-object v1

    .line 316
    check-cast v1, Lj91/f;

    .line 317
    .line 318
    invoke-virtual {v1}, Lj91/f;->i()Lg4/p0;

    .line 319
    .line 320
    .line 321
    move-result-object v12

    .line 322
    sget-wide v14, Le3/s;->e:J

    .line 323
    .line 324
    const/16 v31, 0x0

    .line 325
    .line 326
    const v32, 0xfff4

    .line 327
    .line 328
    .line 329
    const/4 v13, 0x0

    .line 330
    const/4 v1, 0x1

    .line 331
    const-wide/16 v16, 0x0

    .line 332
    .line 333
    const/16 v18, 0x0

    .line 334
    .line 335
    const-wide/16 v19, 0x0

    .line 336
    .line 337
    const/16 v21, 0x0

    .line 338
    .line 339
    const/16 v22, 0x0

    .line 340
    .line 341
    const-wide/16 v23, 0x0

    .line 342
    .line 343
    const/16 v25, 0x0

    .line 344
    .line 345
    const/16 v26, 0x0

    .line 346
    .line 347
    const/16 v27, 0x0

    .line 348
    .line 349
    const/16 v28, 0x0

    .line 350
    .line 351
    const/16 v30, 0xc00

    .line 352
    .line 353
    move-object/from16 v29, v6

    .line 354
    .line 355
    invoke-static/range {v11 .. v32}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 356
    .line 357
    .line 358
    invoke-virtual {v6, v7}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 359
    .line 360
    .line 361
    move-result-object v2

    .line 362
    check-cast v2, Lj91/c;

    .line 363
    .line 364
    iget v2, v2, Lj91/c;->e:F

    .line 365
    .line 366
    const v5, 0x7f121290

    .line 367
    .line 368
    .line 369
    invoke-static {v4, v2, v6, v5, v6}, Lvj/b;->m(Lx2/p;FLl2/t;ILl2/t;)Ljava/lang/String;

    .line 370
    .line 371
    .line 372
    move-result-object v11

    .line 373
    invoke-virtual {v6, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 374
    .line 375
    .line 376
    move-result-object v0

    .line 377
    check-cast v0, Lj91/f;

    .line 378
    .line 379
    invoke-virtual {v0}, Lj91/f;->b()Lg4/p0;

    .line 380
    .line 381
    .line 382
    move-result-object v12

    .line 383
    const-wide v4, 0xffc4c6c7L

    .line 384
    .line 385
    .line 386
    .line 387
    .line 388
    invoke-static {v4, v5}, Le3/j0;->e(J)J

    .line 389
    .line 390
    .line 391
    move-result-wide v14

    .line 392
    invoke-static/range {v11 .. v32}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 393
    .line 394
    .line 395
    const/high16 v0, 0x3f800000    # 1.0f

    .line 396
    .line 397
    float-to-double v4, v0

    .line 398
    const-wide/16 v8, 0x0

    .line 399
    .line 400
    cmpl-double v2, v4, v8

    .line 401
    .line 402
    if-lez v2, :cond_a

    .line 403
    .line 404
    goto :goto_7

    .line 405
    :cond_a
    const-string v2, "invalid weight; must be greater than zero"

    .line 406
    .line 407
    invoke-static {v2}, Ll1/a;->a(Ljava/lang/String;)V

    .line 408
    .line 409
    .line 410
    :goto_7
    new-instance v2, Landroidx/compose/foundation/layout/LayoutWeightElement;

    .line 411
    .line 412
    invoke-direct {v2, v0, v1}, Landroidx/compose/foundation/layout/LayoutWeightElement;-><init>(FZ)V

    .line 413
    .line 414
    .line 415
    invoke-static {v6, v2}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 416
    .line 417
    .line 418
    const v0, 0x7f120382

    .line 419
    .line 420
    .line 421
    invoke-static {v6, v0}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 422
    .line 423
    .line 424
    move-result-object v5

    .line 425
    sget-object v0, Lx2/c;->q:Lx2/h;

    .line 426
    .line 427
    new-instance v11, Landroidx/compose/foundation/layout/HorizontalAlignElement;

    .line 428
    .line 429
    invoke-direct {v11, v0}, Landroidx/compose/foundation/layout/HorizontalAlignElement;-><init>(Lx2/h;)V

    .line 430
    .line 431
    .line 432
    invoke-virtual {v6, v7}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 433
    .line 434
    .line 435
    move-result-object v0

    .line 436
    check-cast v0, Lj91/c;

    .line 437
    .line 438
    iget v15, v0, Lj91/c;->f:F

    .line 439
    .line 440
    const/16 v16, 0x7

    .line 441
    .line 442
    const/4 v12, 0x0

    .line 443
    const/4 v13, 0x0

    .line 444
    const/4 v14, 0x0

    .line 445
    invoke-static/range {v11 .. v16}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 446
    .line 447
    .line 448
    move-result-object v7

    .line 449
    const/4 v9, 0x0

    .line 450
    const/16 v2, 0x38

    .line 451
    .line 452
    const/4 v4, 0x0

    .line 453
    const/4 v8, 0x0

    .line 454
    move v0, v1

    .line 455
    move/from16 v1, p2

    .line 456
    .line 457
    invoke-static/range {v1 .. v9}, Li91/j0;->X(IILay0/a;Ljava/lang/Integer;Ljava/lang/String;Ll2/o;Lx2/s;ZZ)V

    .line 458
    .line 459
    .line 460
    invoke-virtual {v6, v0}, Ll2/t;->q(Z)V

    .line 461
    .line 462
    .line 463
    invoke-virtual {v6, v0}, Ll2/t;->q(Z)V

    .line 464
    .line 465
    .line 466
    goto :goto_8

    .line 467
    :cond_b
    invoke-virtual {v6}, Ll2/t;->R()V

    .line 468
    .line 469
    .line 470
    :goto_8
    invoke-virtual {v6}, Ll2/t;->s()Ll2/u1;

    .line 471
    .line 472
    .line 473
    move-result-object v0

    .line 474
    if-eqz v0, :cond_c

    .line 475
    .line 476
    new-instance v1, Ld90/m;

    .line 477
    .line 478
    const/4 v2, 0x0

    .line 479
    move-object/from16 v4, p0

    .line 480
    .line 481
    invoke-direct {v1, v10, v2, v4, v3}, Ld90/m;-><init>(IILjava/lang/Object;Ljava/lang/Object;)V

    .line 482
    .line 483
    .line 484
    iput-object v1, v0, Ll2/u1;->d:Lay0/n;

    .line 485
    .line 486
    :cond_c
    return-void
.end method

.method public static final c(Lqp0/r;Z)Ljava/util/List;
    .locals 5

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-boolean v0, p0, Lqp0/r;->a:Z

    .line 7
    .line 8
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    const/4 v2, 0x0

    .line 13
    if-nez v0, :cond_0

    .line 14
    .line 15
    goto :goto_0

    .line 16
    :cond_0
    move-object v1, v2

    .line 17
    :goto_0
    if-eqz v1, :cond_1

    .line 18
    .line 19
    const-string v0, "FERRIES"

    .line 20
    .line 21
    goto :goto_1

    .line 22
    :cond_1
    move-object v0, v2

    .line 23
    :goto_1
    iget-boolean v1, p0, Lqp0/r;->b:Z

    .line 24
    .line 25
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 26
    .line 27
    .line 28
    move-result-object v3

    .line 29
    if-nez v1, :cond_2

    .line 30
    .line 31
    goto :goto_2

    .line 32
    :cond_2
    move-object v3, v2

    .line 33
    :goto_2
    if-eqz v3, :cond_3

    .line 34
    .line 35
    const-string v1, "MOTORWAYS"

    .line 36
    .line 37
    goto :goto_3

    .line 38
    :cond_3
    move-object v1, v2

    .line 39
    :goto_3
    iget-boolean v3, p0, Lqp0/r;->c:Z

    .line 40
    .line 41
    invoke-static {v3}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 42
    .line 43
    .line 44
    move-result-object v4

    .line 45
    if-nez v3, :cond_4

    .line 46
    .line 47
    goto :goto_4

    .line 48
    :cond_4
    move-object v4, v2

    .line 49
    :goto_4
    if-eqz v4, :cond_5

    .line 50
    .line 51
    const-string v3, "TOLL_ROADS"

    .line 52
    .line 53
    goto :goto_5

    .line 54
    :cond_5
    move-object v3, v2

    .line 55
    :goto_5
    iget-boolean p0, p0, Lqp0/r;->d:Z

    .line 56
    .line 57
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 58
    .line 59
    .line 60
    move-result-object v4

    .line 61
    if-eqz p1, :cond_6

    .line 62
    .line 63
    if-nez p0, :cond_6

    .line 64
    .line 65
    goto :goto_6

    .line 66
    :cond_6
    move-object v4, v2

    .line 67
    :goto_6
    if-eqz v4, :cond_7

    .line 68
    .line 69
    const-string p0, "BORDER_CROSSINGS"

    .line 70
    .line 71
    goto :goto_7

    .line 72
    :cond_7
    move-object p0, v2

    .line 73
    :goto_7
    filled-new-array {v0, v1, v3, p0}, [Ljava/lang/String;

    .line 74
    .line 75
    .line 76
    move-result-object p0

    .line 77
    invoke-static {p0}, Lmx0/n;->t([Ljava/lang/Object;)Ljava/util/List;

    .line 78
    .line 79
    .line 80
    move-result-object p0

    .line 81
    invoke-interface {p0}, Ljava/util/Collection;->isEmpty()Z

    .line 82
    .line 83
    .line 84
    move-result p1

    .line 85
    if-eqz p1, :cond_8

    .line 86
    .line 87
    return-object v2

    .line 88
    :cond_8
    return-object p0
.end method
