.class public abstract Llp/ac;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Ll2/o;I)V
    .locals 13

    .line 1
    move-object v4, p0

    .line 2
    check-cast v4, Ll2/t;

    .line 3
    .line 4
    const p0, 0x5bb8d42

    .line 5
    .line 6
    .line 7
    invoke-virtual {v4, p0}, Ll2/t;->a0(I)Ll2/t;

    .line 8
    .line 9
    .line 10
    const/4 p0, 0x1

    .line 11
    const/4 v0, 0x0

    .line 12
    if-eqz p1, :cond_0

    .line 13
    .line 14
    move v1, p0

    .line 15
    goto :goto_0

    .line 16
    :cond_0
    move v1, v0

    .line 17
    :goto_0
    and-int/lit8 v2, p1, 0x1

    .line 18
    .line 19
    invoke-virtual {v4, v2, v1}, Ll2/t;->O(IZ)Z

    .line 20
    .line 21
    .line 22
    move-result v1

    .line 23
    if-eqz v1, :cond_8

    .line 24
    .line 25
    const v1, -0x6040e0aa

    .line 26
    .line 27
    .line 28
    invoke-virtual {v4, v1}, Ll2/t;->Y(I)V

    .line 29
    .line 30
    .line 31
    invoke-static {v4}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 32
    .line 33
    .line 34
    move-result-object v1

    .line 35
    if-eqz v1, :cond_7

    .line 36
    .line 37
    invoke-static {v1}, Ljp/ib;->a(Landroidx/lifecycle/i1;)Lp7/c;

    .line 38
    .line 39
    .line 40
    move-result-object v8

    .line 41
    invoke-static {v4}, Lw11/c;->b(Ll2/o;)Lk21/a;

    .line 42
    .line 43
    .line 44
    move-result-object v10

    .line 45
    const-class v2, Luo0/q;

    .line 46
    .line 47
    sget-object v3, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 48
    .line 49
    invoke-virtual {v3, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 50
    .line 51
    .line 52
    move-result-object v5

    .line 53
    invoke-interface {v1}, Landroidx/lifecycle/i1;->getViewModelStore()Landroidx/lifecycle/h1;

    .line 54
    .line 55
    .line 56
    move-result-object v6

    .line 57
    const/4 v7, 0x0

    .line 58
    const/4 v9, 0x0

    .line 59
    const/4 v11, 0x0

    .line 60
    invoke-static/range {v5 .. v11}, Ljp/lb;->a(Lhy0/d;Landroidx/lifecycle/h1;Ljava/lang/String;Lp7/c;Lh21/b;Lk21/a;Lay0/a;)Landroidx/lifecycle/b1;

    .line 61
    .line 62
    .line 63
    move-result-object v1

    .line 64
    invoke-virtual {v4, v0}, Ll2/t;->q(Z)V

    .line 65
    .line 66
    .line 67
    check-cast v1, Lql0/j;

    .line 68
    .line 69
    invoke-static {v1, v4, v0, p0}, Lkp/x5;->b(Lql0/j;Ll2/o;II)V

    .line 70
    .line 71
    .line 72
    move-object v7, v1

    .line 73
    check-cast v7, Luo0/q;

    .line 74
    .line 75
    iget-object v0, v7, Lql0/j;->g:Lyy0/l1;

    .line 76
    .line 77
    const/4 v1, 0x0

    .line 78
    invoke-static {v0, v1, v4, p0}, Ll2/b;->f(Lyy0/a2;Lwy0/c;Ll2/o;I)Ll2/b1;

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    invoke-interface {p0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    move-result-object p0

    .line 86
    move-object v0, p0

    .line 87
    check-cast v0, Luo0/o;

    .line 88
    .line 89
    invoke-virtual {v4, v7}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 90
    .line 91
    .line 92
    move-result p0

    .line 93
    invoke-virtual {v4}, Ll2/t;->L()Ljava/lang/Object;

    .line 94
    .line 95
    .line 96
    move-result-object v1

    .line 97
    sget-object v2, Ll2/n;->a:Ll2/x0;

    .line 98
    .line 99
    if-nez p0, :cond_1

    .line 100
    .line 101
    if-ne v1, v2, :cond_2

    .line 102
    .line 103
    :cond_1
    new-instance v5, Lv50/j;

    .line 104
    .line 105
    const/4 v11, 0x0

    .line 106
    const/16 v12, 0x11

    .line 107
    .line 108
    const/4 v6, 0x0

    .line 109
    const-class v8, Luo0/q;

    .line 110
    .line 111
    const-string v9, "onCloseError"

    .line 112
    .line 113
    const-string v10, "onCloseError()V"

    .line 114
    .line 115
    invoke-direct/range {v5 .. v12}, Lv50/j;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 116
    .line 117
    .line 118
    invoke-virtual {v4, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 119
    .line 120
    .line 121
    move-object v1, v5

    .line 122
    :cond_2
    check-cast v1, Lhy0/g;

    .line 123
    .line 124
    check-cast v1, Lay0/a;

    .line 125
    .line 126
    invoke-virtual {v4, v7}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 127
    .line 128
    .line 129
    move-result p0

    .line 130
    invoke-virtual {v4}, Ll2/t;->L()Ljava/lang/Object;

    .line 131
    .line 132
    .line 133
    move-result-object v3

    .line 134
    if-nez p0, :cond_3

    .line 135
    .line 136
    if-ne v3, v2, :cond_4

    .line 137
    .line 138
    :cond_3
    new-instance v5, Lv50/j;

    .line 139
    .line 140
    const/4 v11, 0x0

    .line 141
    const/16 v12, 0x12

    .line 142
    .line 143
    const/4 v6, 0x0

    .line 144
    const-class v8, Luo0/q;

    .line 145
    .line 146
    const-string v9, "onPowerpassSdkError"

    .line 147
    .line 148
    const-string v10, "onPowerpassSdkError()V"

    .line 149
    .line 150
    invoke-direct/range {v5 .. v12}, Lv50/j;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 151
    .line 152
    .line 153
    invoke-virtual {v4, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 154
    .line 155
    .line 156
    move-object v3, v5

    .line 157
    :cond_4
    check-cast v3, Lhy0/g;

    .line 158
    .line 159
    check-cast v3, Lay0/a;

    .line 160
    .line 161
    invoke-virtual {v4, v7}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 162
    .line 163
    .line 164
    move-result p0

    .line 165
    invoke-virtual {v4}, Ll2/t;->L()Ljava/lang/Object;

    .line 166
    .line 167
    .line 168
    move-result-object v5

    .line 169
    if-nez p0, :cond_5

    .line 170
    .line 171
    if-ne v5, v2, :cond_6

    .line 172
    .line 173
    :cond_5
    new-instance v5, Lv50/j;

    .line 174
    .line 175
    const/4 v11, 0x0

    .line 176
    const/16 v12, 0x13

    .line 177
    .line 178
    const/4 v6, 0x0

    .line 179
    const-class v8, Luo0/q;

    .line 180
    .line 181
    const-string v9, "onSubscribeSuccess"

    .line 182
    .line 183
    const-string v10, "onSubscribeSuccess()V"

    .line 184
    .line 185
    invoke-direct/range {v5 .. v12}, Lv50/j;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 186
    .line 187
    .line 188
    invoke-virtual {v4, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 189
    .line 190
    .line 191
    :cond_6
    check-cast v5, Lhy0/g;

    .line 192
    .line 193
    check-cast v5, Lay0/a;

    .line 194
    .line 195
    move-object v2, v3

    .line 196
    move-object v3, v5

    .line 197
    const/4 v5, 0x0

    .line 198
    invoke-static/range {v0 .. v5}, Llp/ac;->b(Luo0/o;Lay0/a;Lay0/a;Lay0/a;Ll2/o;I)V

    .line 199
    .line 200
    .line 201
    goto :goto_1

    .line 202
    :cond_7
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 203
    .line 204
    const-string p1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 205
    .line 206
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 207
    .line 208
    .line 209
    throw p0

    .line 210
    :cond_8
    invoke-virtual {v4}, Ll2/t;->R()V

    .line 211
    .line 212
    .line 213
    :goto_1
    invoke-virtual {v4}, Ll2/t;->s()Ll2/u1;

    .line 214
    .line 215
    .line 216
    move-result-object p0

    .line 217
    if-eqz p0, :cond_9

    .line 218
    .line 219
    new-instance v0, Lvj0/b;

    .line 220
    .line 221
    const/16 v1, 0xd

    .line 222
    .line 223
    invoke-direct {v0, p1, v1}, Lvj0/b;-><init>(II)V

    .line 224
    .line 225
    .line 226
    iput-object v0, p0, Ll2/u1;->d:Lay0/n;

    .line 227
    .line 228
    :cond_9
    return-void
.end method

.method public static final b(Luo0/o;Lay0/a;Lay0/a;Lay0/a;Ll2/o;I)V
    .locals 8

    .line 1
    move-object v3, p4

    .line 2
    check-cast v3, Ll2/t;

    .line 3
    .line 4
    const p4, 0x5ba3a499

    .line 5
    .line 6
    .line 7
    invoke-virtual {v3, p4}, Ll2/t;->a0(I)Ll2/t;

    .line 8
    .line 9
    .line 10
    invoke-virtual {v3, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 11
    .line 12
    .line 13
    move-result p4

    .line 14
    if-eqz p4, :cond_0

    .line 15
    .line 16
    const/4 p4, 0x4

    .line 17
    goto :goto_0

    .line 18
    :cond_0
    const/4 p4, 0x2

    .line 19
    :goto_0
    or-int/2addr p4, p5

    .line 20
    invoke-virtual {v3, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    const/16 v1, 0x20

    .line 25
    .line 26
    if-eqz v0, :cond_1

    .line 27
    .line 28
    move v0, v1

    .line 29
    goto :goto_1

    .line 30
    :cond_1
    const/16 v0, 0x10

    .line 31
    .line 32
    :goto_1
    or-int/2addr p4, v0

    .line 33
    invoke-virtual {v3, p2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 34
    .line 35
    .line 36
    move-result v0

    .line 37
    if-eqz v0, :cond_2

    .line 38
    .line 39
    const/16 v0, 0x100

    .line 40
    .line 41
    goto :goto_2

    .line 42
    :cond_2
    const/16 v0, 0x80

    .line 43
    .line 44
    :goto_2
    or-int/2addr p4, v0

    .line 45
    invoke-virtual {v3, p3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 46
    .line 47
    .line 48
    move-result v0

    .line 49
    if-eqz v0, :cond_3

    .line 50
    .line 51
    const/16 v0, 0x800

    .line 52
    .line 53
    goto :goto_3

    .line 54
    :cond_3
    const/16 v0, 0x400

    .line 55
    .line 56
    :goto_3
    or-int/2addr p4, v0

    .line 57
    and-int/lit16 v0, p4, 0x493

    .line 58
    .line 59
    const/16 v2, 0x492

    .line 60
    .line 61
    const/4 v4, 0x1

    .line 62
    const/4 v6, 0x0

    .line 63
    if-eq v0, v2, :cond_4

    .line 64
    .line 65
    move v0, v4

    .line 66
    goto :goto_4

    .line 67
    :cond_4
    move v0, v6

    .line 68
    :goto_4
    and-int/lit8 v2, p4, 0x1

    .line 69
    .line 70
    invoke-virtual {v3, v2, v0}, Ll2/t;->O(IZ)Z

    .line 71
    .line 72
    .line 73
    move-result v0

    .line 74
    if-eqz v0, :cond_a

    .line 75
    .line 76
    iget-object v0, p0, Luo0/o;->a:Lql0/g;

    .line 77
    .line 78
    if-nez v0, :cond_6

    .line 79
    .line 80
    const v0, 0x2852a3da

    .line 81
    .line 82
    .line 83
    invoke-virtual {v3, v0}, Ll2/t;->Y(I)V

    .line 84
    .line 85
    .line 86
    invoke-virtual {v3, v6}, Ll2/t;->q(Z)V

    .line 87
    .line 88
    .line 89
    iget-object v0, p0, Luo0/o;->b:Llp/v1;

    .line 90
    .line 91
    if-nez v0, :cond_5

    .line 92
    .line 93
    const p4, 0x28551f5a

    .line 94
    .line 95
    .line 96
    invoke-virtual {v3, p4}, Ll2/t;->Y(I)V

    .line 97
    .line 98
    .line 99
    :goto_5
    invoke-virtual {v3, v6}, Ll2/t;->q(Z)V

    .line 100
    .line 101
    .line 102
    goto :goto_6

    .line 103
    :cond_5
    const v1, 0x14d1187

    .line 104
    .line 105
    .line 106
    invoke-virtual {v3, v1}, Ll2/t;->Y(I)V

    .line 107
    .line 108
    .line 109
    shr-int/lit8 p4, p4, 0x3

    .line 110
    .line 111
    and-int/lit16 p4, p4, 0x3f0

    .line 112
    .line 113
    invoke-static {v0, p2, p3, v3, p4}, Llp/ac;->c(Llp/v1;Lay0/a;Lay0/a;Ll2/o;I)V

    .line 114
    .line 115
    .line 116
    goto :goto_5

    .line 117
    :goto_6
    move-object v1, p0

    .line 118
    move-object v2, p1

    .line 119
    move-object v4, p2

    .line 120
    move-object v5, p3

    .line 121
    move v6, p5

    .line 122
    goto :goto_8

    .line 123
    :cond_6
    const v2, 0x2852a3db

    .line 124
    .line 125
    .line 126
    invoke-virtual {v3, v2}, Ll2/t;->Y(I)V

    .line 127
    .line 128
    .line 129
    and-int/lit8 p4, p4, 0x70

    .line 130
    .line 131
    if-ne p4, v1, :cond_7

    .line 132
    .line 133
    goto :goto_7

    .line 134
    :cond_7
    move v4, v6

    .line 135
    :goto_7
    invoke-virtual {v3}, Ll2/t;->L()Ljava/lang/Object;

    .line 136
    .line 137
    .line 138
    move-result-object p4

    .line 139
    if-nez v4, :cond_8

    .line 140
    .line 141
    sget-object v1, Ll2/n;->a:Ll2/x0;

    .line 142
    .line 143
    if-ne p4, v1, :cond_9

    .line 144
    .line 145
    :cond_8
    new-instance p4, Lvo0/g;

    .line 146
    .line 147
    const/4 v1, 0x0

    .line 148
    invoke-direct {p4, p1, v1}, Lvo0/g;-><init>(Lay0/a;I)V

    .line 149
    .line 150
    .line 151
    invoke-virtual {v3, p4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 152
    .line 153
    .line 154
    :cond_9
    move-object v1, p4

    .line 155
    check-cast v1, Lay0/k;

    .line 156
    .line 157
    const/4 v4, 0x0

    .line 158
    const/4 v5, 0x4

    .line 159
    const/4 v2, 0x0

    .line 160
    invoke-static/range {v0 .. v5}, Lyg0/a;->a(Lql0/g;Lay0/k;Lay0/k;Ll2/o;II)V

    .line 161
    .line 162
    .line 163
    invoke-virtual {v3, v6}, Ll2/t;->q(Z)V

    .line 164
    .line 165
    .line 166
    invoke-virtual {v3}, Ll2/t;->s()Ll2/u1;

    .line 167
    .line 168
    .line 169
    move-result-object p4

    .line 170
    if-eqz p4, :cond_b

    .line 171
    .line 172
    new-instance v0, Lvo0/h;

    .line 173
    .line 174
    const/4 v6, 0x0

    .line 175
    move-object v1, p0

    .line 176
    move-object v2, p1

    .line 177
    move-object v3, p2

    .line 178
    move-object v4, p3

    .line 179
    move v5, p5

    .line 180
    invoke-direct/range {v0 .. v6}, Lvo0/h;-><init>(Luo0/o;Lay0/a;Lay0/a;Lay0/a;II)V

    .line 181
    .line 182
    .line 183
    iput-object v0, p4, Ll2/u1;->d:Lay0/n;

    .line 184
    .line 185
    return-void

    .line 186
    :cond_a
    move-object v1, p0

    .line 187
    move-object v2, p1

    .line 188
    move-object v4, p2

    .line 189
    move-object v5, p3

    .line 190
    move v6, p5

    .line 191
    invoke-virtual {v3}, Ll2/t;->R()V

    .line 192
    .line 193
    .line 194
    :goto_8
    invoke-virtual {v3}, Ll2/t;->s()Ll2/u1;

    .line 195
    .line 196
    .line 197
    move-result-object p0

    .line 198
    if-eqz p0, :cond_b

    .line 199
    .line 200
    move-object v3, v2

    .line 201
    move-object v2, v1

    .line 202
    new-instance v1, Lvo0/h;

    .line 203
    .line 204
    const/4 v7, 0x1

    .line 205
    invoke-direct/range {v1 .. v7}, Lvo0/h;-><init>(Luo0/o;Lay0/a;Lay0/a;Lay0/a;II)V

    .line 206
    .line 207
    .line 208
    iput-object v1, p0, Ll2/u1;->d:Lay0/n;

    .line 209
    .line 210
    :cond_b
    return-void
.end method

.method public static final c(Llp/v1;Lay0/a;Lay0/a;Ll2/o;I)V
    .locals 8

    .line 1
    check-cast p3, Ll2/t;

    .line 2
    .line 3
    const v0, -0x74ead577

    .line 4
    .line 5
    .line 6
    invoke-virtual {p3, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    and-int/lit8 v0, p4, 0x6

    .line 10
    .line 11
    const/4 v1, 0x4

    .line 12
    if-nez v0, :cond_1

    .line 13
    .line 14
    invoke-virtual {p3, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

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
    or-int/2addr v0, p4

    .line 24
    goto :goto_1

    .line 25
    :cond_1
    move v0, p4

    .line 26
    :goto_1
    and-int/lit8 v2, p4, 0x30

    .line 27
    .line 28
    if-nez v2, :cond_3

    .line 29
    .line 30
    invoke-virtual {p3, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

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
    and-int/lit16 v2, p4, 0x180

    .line 43
    .line 44
    const/16 v3, 0x100

    .line 45
    .line 46
    if-nez v2, :cond_5

    .line 47
    .line 48
    invoke-virtual {p3, p2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 49
    .line 50
    .line 51
    move-result v2

    .line 52
    if-eqz v2, :cond_4

    .line 53
    .line 54
    move v2, v3

    .line 55
    goto :goto_3

    .line 56
    :cond_4
    const/16 v2, 0x80

    .line 57
    .line 58
    :goto_3
    or-int/2addr v0, v2

    .line 59
    :cond_5
    and-int/lit16 v2, v0, 0x93

    .line 60
    .line 61
    const/16 v4, 0x92

    .line 62
    .line 63
    const/4 v5, 0x1

    .line 64
    const/4 v6, 0x0

    .line 65
    if-eq v2, v4, :cond_6

    .line 66
    .line 67
    move v2, v5

    .line 68
    goto :goto_4

    .line 69
    :cond_6
    move v2, v6

    .line 70
    :goto_4
    and-int/lit8 v4, v0, 0x1

    .line 71
    .line 72
    invoke-virtual {p3, v4, v2}, Ll2/t;->O(IZ)Z

    .line 73
    .line 74
    .line 75
    move-result v2

    .line 76
    if-eqz v2, :cond_1b

    .line 77
    .line 78
    sget-object v2, Lvo0/j;->a:Ll2/e0;

    .line 79
    .line 80
    invoke-virtual {p3, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 81
    .line 82
    .line 83
    move-result-object v2

    .line 84
    check-cast v2, Ll2/b1;

    .line 85
    .line 86
    invoke-interface {v2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    move-result-object v2

    .line 90
    check-cast v2, Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;

    .line 91
    .line 92
    if-nez v2, :cond_7

    .line 93
    .line 94
    invoke-interface {p1}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 95
    .line 96
    .line 97
    invoke-virtual {p3}, Ll2/t;->s()Ll2/u1;

    .line 98
    .line 99
    .line 100
    move-result-object p3

    .line 101
    if-eqz p3, :cond_1c

    .line 102
    .line 103
    new-instance v0, Lvo0/i;

    .line 104
    .line 105
    const/4 v5, 0x0

    .line 106
    move-object v1, p0

    .line 107
    move-object v2, p1

    .line 108
    move-object v3, p2

    .line 109
    move v4, p4

    .line 110
    invoke-direct/range {v0 .. v5}, Lvo0/i;-><init>(Llp/v1;Lay0/a;Lay0/a;II)V

    .line 111
    .line 112
    .line 113
    iput-object v0, p3, Ll2/u1;->d:Lay0/n;

    .line 114
    .line 115
    return-void

    .line 116
    :cond_7
    move-object v4, v2

    .line 117
    move-object v2, p0

    .line 118
    move-object p0, v4

    .line 119
    move v4, v3

    .line 120
    move-object v3, p1

    .line 121
    move p1, v4

    .line 122
    move-object v4, p2

    .line 123
    move p2, v5

    .line 124
    move v5, p4

    .line 125
    and-int/lit8 p4, v0, 0xe

    .line 126
    .line 127
    if-ne p4, v1, :cond_8

    .line 128
    .line 129
    move p4, p2

    .line 130
    goto :goto_5

    .line 131
    :cond_8
    move p4, v6

    .line 132
    :goto_5
    invoke-virtual {p3}, Ll2/t;->L()Ljava/lang/Object;

    .line 133
    .line 134
    .line 135
    move-result-object v1

    .line 136
    sget-object v7, Ll2/n;->a:Ll2/x0;

    .line 137
    .line 138
    if-nez p4, :cond_9

    .line 139
    .line 140
    if-ne v1, v7, :cond_a

    .line 141
    .line 142
    :cond_9
    new-instance v1, Lu2/a;

    .line 143
    .line 144
    const/16 p4, 0xd

    .line 145
    .line 146
    invoke-direct {v1, v2, p4}, Lu2/a;-><init>(Ljava/lang/Object;I)V

    .line 147
    .line 148
    .line 149
    invoke-virtual {p3, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 150
    .line 151
    .line 152
    :cond_a
    check-cast v1, Lay0/a;

    .line 153
    .line 154
    const-string p4, "MULTI.MySkoda"

    .line 155
    .line 156
    invoke-static {p4, v2, v1}, Llp/nd;->f(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 157
    .line 158
    .line 159
    sget-object p4, Luo0/c;->a:Luo0/c;

    .line 160
    .line 161
    invoke-virtual {v2, p4}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 162
    .line 163
    .line 164
    move-result p4

    .line 165
    if-eqz p4, :cond_b

    .line 166
    .line 167
    const p1, 0x1a74d43b

    .line 168
    .line 169
    .line 170
    invoke-virtual {p3, p1}, Ll2/t;->Y(I)V

    .line 171
    .line 172
    .line 173
    invoke-virtual {p0, p3, v6}, Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;->ChargingCardFlow(Ll2/o;I)V

    .line 174
    .line 175
    .line 176
    invoke-virtual {p3, v6}, Ll2/t;->q(Z)V

    .line 177
    .line 178
    .line 179
    goto/16 :goto_8

    .line 180
    .line 181
    :cond_b
    sget-object p4, Luo0/d;->a:Luo0/d;

    .line 182
    .line 183
    invoke-virtual {v2, p4}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 184
    .line 185
    .line 186
    move-result p4

    .line 187
    if-eqz p4, :cond_c

    .line 188
    .line 189
    const p1, 0x1a74dc22

    .line 190
    .line 191
    .line 192
    invoke-virtual {p3, p1}, Ll2/t;->Y(I)V

    .line 193
    .line 194
    .line 195
    sget-object p1, Lki/a;->d:Lki/a;

    .line 196
    .line 197
    sget-object p2, Lki/a;->e:Lki/a;

    .line 198
    .line 199
    filled-new-array {p1, p2}, [Lki/a;

    .line 200
    .line 201
    .line 202
    move-result-object p1

    .line 203
    invoke-virtual {p0, p1, p3, v6}, Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;->ChargingHistoryFlow([Lki/a;Ll2/o;I)V

    .line 204
    .line 205
    .line 206
    invoke-virtual {p3, v6}, Ll2/t;->q(Z)V

    .line 207
    .line 208
    .line 209
    goto/16 :goto_8

    .line 210
    .line 211
    :cond_c
    instance-of p4, v2, Luo0/e;

    .line 212
    .line 213
    if-eqz p4, :cond_e

    .line 214
    .line 215
    const p1, 0x1a74ee43

    .line 216
    .line 217
    .line 218
    invoke-virtual {p3, p1}, Ll2/t;->Y(I)V

    .line 219
    .line 220
    .line 221
    sget-object p1, Lki/j;->Companion:Lki/d;

    .line 222
    .line 223
    move-object p2, v2

    .line 224
    check-cast p2, Luo0/e;

    .line 225
    .line 226
    iget-object p2, p2, Luo0/e;->a:Ljava/lang/String;

    .line 227
    .line 228
    if-eqz p2, :cond_d

    .line 229
    .line 230
    sget-object p4, Lki/e;->a:Ljava/util/List;

    .line 231
    .line 232
    new-instance p4, Lki/h;

    .line 233
    .line 234
    invoke-direct {p4, p2}, Lki/h;-><init>(Ljava/lang/String;)V

    .line 235
    .line 236
    .line 237
    invoke-static {p4}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 238
    .line 239
    .line 240
    move-result-object p2

    .line 241
    goto :goto_6

    .line 242
    :cond_d
    sget-object p2, Lki/e;->a:Ljava/util/List;

    .line 243
    .line 244
    sget-object p2, Lmx0/s;->d:Lmx0/s;

    .line 245
    .line 246
    :goto_6
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 247
    .line 248
    .line 249
    new-instance p1, Lki/j;

    .line 250
    .line 251
    invoke-direct {p1, p2}, Lki/j;-><init>(Ljava/util/List;)V

    .line 252
    .line 253
    .line 254
    const/16 p2, 0x8

    .line 255
    .line 256
    invoke-virtual {p0, p1, p3, p2}, Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;->ChargingStatisticsFlow(Lki/j;Ll2/o;I)V

    .line 257
    .line 258
    .line 259
    invoke-virtual {p3, v6}, Ll2/t;->q(Z)V

    .line 260
    .line 261
    .line 262
    goto/16 :goto_8

    .line 263
    .line 264
    :cond_e
    sget-object p4, Luo0/f;->a:Luo0/f;

    .line 265
    .line 266
    invoke-virtual {v2, p4}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 267
    .line 268
    .line 269
    move-result p4

    .line 270
    if-eqz p4, :cond_f

    .line 271
    .line 272
    const p1, 0x1a7518d7

    .line 273
    .line 274
    .line 275
    invoke-virtual {p3, p1}, Ll2/t;->Y(I)V

    .line 276
    .line 277
    .line 278
    invoke-virtual {p0, p3, v6}, Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;->ConsentsFlow(Ll2/o;I)V

    .line 279
    .line 280
    .line 281
    invoke-virtual {p3, v6}, Ll2/t;->q(Z)V

    .line 282
    .line 283
    .line 284
    goto/16 :goto_8

    .line 285
    .line 286
    :cond_f
    instance-of p4, v2, Luo0/g;

    .line 287
    .line 288
    if-eqz p4, :cond_10

    .line 289
    .line 290
    const p1, 0x1a751f5f

    .line 291
    .line 292
    .line 293
    invoke-virtual {p3, p1}, Ll2/t;->Y(I)V

    .line 294
    .line 295
    .line 296
    move-object p1, v2

    .line 297
    check-cast p1, Luo0/g;

    .line 298
    .line 299
    iget-object p1, p1, Luo0/g;->a:Ljava/lang/String;

    .line 300
    .line 301
    invoke-virtual {p0, p1, p3, v6}, Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;->CouponsFlow(Ljava/lang/String;Ll2/o;I)V

    .line 302
    .line 303
    .line 304
    invoke-virtual {p3, v6}, Ll2/t;->q(Z)V

    .line 305
    .line 306
    .line 307
    goto/16 :goto_8

    .line 308
    .line 309
    :cond_10
    sget-object p4, Luo0/h;->a:Luo0/h;

    .line 310
    .line 311
    invoke-virtual {v2, p4}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 312
    .line 313
    .line 314
    move-result p4

    .line 315
    if-eqz p4, :cond_11

    .line 316
    .line 317
    const p1, 0x1a752697

    .line 318
    .line 319
    .line 320
    invoke-virtual {p3, p1}, Ll2/t;->Y(I)V

    .line 321
    .line 322
    .line 323
    invoke-virtual {p0, p3, v6}, Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;->InvoicesFlow(Ll2/o;I)V

    .line 324
    .line 325
    .line 326
    invoke-virtual {p3, v6}, Ll2/t;->q(Z)V

    .line 327
    .line 328
    .line 329
    goto/16 :goto_8

    .line 330
    .line 331
    :cond_11
    sget-object p4, Luo0/i;->a:Luo0/i;

    .line 332
    .line 333
    invoke-virtual {v2, p4}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 334
    .line 335
    .line 336
    move-result p4

    .line 337
    if-eqz p4, :cond_12

    .line 338
    .line 339
    const p1, 0x1a752d96

    .line 340
    .line 341
    .line 342
    invoke-virtual {p3, p1}, Ll2/t;->Y(I)V

    .line 343
    .line 344
    .line 345
    invoke-virtual {p0, p3, v6}, Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;->PaymentFlow(Ll2/o;I)V

    .line 346
    .line 347
    .line 348
    invoke-virtual {p3, v6}, Ll2/t;->q(Z)V

    .line 349
    .line 350
    .line 351
    goto/16 :goto_8

    .line 352
    .line 353
    :cond_12
    instance-of p4, v2, Luo0/j;

    .line 354
    .line 355
    if-eqz p4, :cond_13

    .line 356
    .line 357
    const p1, 0x1a7534c5

    .line 358
    .line 359
    .line 360
    invoke-virtual {p3, p1}, Ll2/t;->Y(I)V

    .line 361
    .line 362
    .line 363
    move-object p1, v2

    .line 364
    check-cast p1, Luo0/j;

    .line 365
    .line 366
    iget-object p1, p1, Luo0/j;->a:Ljava/lang/String;

    .line 367
    .line 368
    invoke-virtual {p0, p1, p3, v6}, Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;->PlugAndChargeFlow(Ljava/lang/String;Ll2/o;I)V

    .line 369
    .line 370
    .line 371
    invoke-virtual {p3, v6}, Ll2/t;->q(Z)V

    .line 372
    .line 373
    .line 374
    goto/16 :goto_8

    .line 375
    .line 376
    :cond_13
    instance-of p4, v2, Luo0/l;

    .line 377
    .line 378
    if-eqz p4, :cond_17

    .line 379
    .line 380
    const p4, 0x1a753d67

    .line 381
    .line 382
    .line 383
    invoke-virtual {p3, p4}, Ll2/t;->Y(I)V

    .line 384
    .line 385
    .line 386
    move-object p4, v2

    .line 387
    check-cast p4, Luo0/l;

    .line 388
    .line 389
    iget-object p4, p4, Luo0/l;->a:Ljava/lang/String;

    .line 390
    .line 391
    and-int/lit16 v0, v0, 0x380

    .line 392
    .line 393
    if-ne v0, p1, :cond_14

    .line 394
    .line 395
    move p1, p2

    .line 396
    goto :goto_7

    .line 397
    :cond_14
    move p1, v6

    .line 398
    :goto_7
    invoke-virtual {p3}, Ll2/t;->L()Ljava/lang/Object;

    .line 399
    .line 400
    .line 401
    move-result-object v0

    .line 402
    if-nez p1, :cond_15

    .line 403
    .line 404
    if-ne v0, v7, :cond_16

    .line 405
    .line 406
    :cond_15
    new-instance v0, Lvo0/g;

    .line 407
    .line 408
    invoke-direct {v0, v4, p2}, Lvo0/g;-><init>(Lay0/a;I)V

    .line 409
    .line 410
    .line 411
    invoke-virtual {p3, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 412
    .line 413
    .line 414
    :cond_16
    check-cast v0, Lay0/k;

    .line 415
    .line 416
    invoke-virtual {p0, p4, v0, p3, v6}, Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;->SubscribeFlow(Ljava/lang/String;Lay0/k;Ll2/o;I)V

    .line 417
    .line 418
    .line 419
    invoke-virtual {p3, v6}, Ll2/t;->q(Z)V

    .line 420
    .line 421
    .line 422
    goto :goto_8

    .line 423
    :cond_17
    instance-of p1, v2, Luo0/m;

    .line 424
    .line 425
    if-eqz p1, :cond_18

    .line 426
    .line 427
    const p1, 0x1a754b4e

    .line 428
    .line 429
    .line 430
    invoke-virtual {p3, p1}, Ll2/t;->Y(I)V

    .line 431
    .line 432
    .line 433
    move-object p1, v2

    .line 434
    check-cast p1, Luo0/m;

    .line 435
    .line 436
    iget-object p1, p1, Luo0/m;->a:Ljava/lang/String;

    .line 437
    .line 438
    invoke-virtual {p0, p1, p3, v6}, Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;->SubscriptionManagementFlow(Ljava/lang/String;Ll2/o;I)V

    .line 439
    .line 440
    .line 441
    invoke-virtual {p3, v6}, Ll2/t;->q(Z)V

    .line 442
    .line 443
    .line 444
    goto :goto_8

    .line 445
    :cond_18
    sget-object p1, Luo0/n;->a:Luo0/n;

    .line 446
    .line 447
    invoke-virtual {v2, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 448
    .line 449
    .line 450
    move-result p1

    .line 451
    if-eqz p1, :cond_19

    .line 452
    .line 453
    const p1, 0x1a755478

    .line 454
    .line 455
    .line 456
    invoke-virtual {p3, p1}, Ll2/t;->Y(I)V

    .line 457
    .line 458
    .line 459
    invoke-virtual {p0, p3, v6}, Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;->WallboxesFlow(Ll2/o;I)V

    .line 460
    .line 461
    .line 462
    invoke-virtual {p3, v6}, Ll2/t;->q(Z)V

    .line 463
    .line 464
    .line 465
    goto :goto_8

    .line 466
    :cond_19
    instance-of p1, v2, Luo0/k;

    .line 467
    .line 468
    if-eqz p1, :cond_1a

    .line 469
    .line 470
    const p1, 0x1a755cae

    .line 471
    .line 472
    .line 473
    invoke-virtual {p3, p1}, Ll2/t;->Y(I)V

    .line 474
    .line 475
    .line 476
    move-object p1, v2

    .line 477
    check-cast p1, Luo0/k;

    .line 478
    .line 479
    iget-object p1, p1, Luo0/k;->a:Ljava/lang/String;

    .line 480
    .line 481
    invoke-virtual {p0, p1, p3, v6}, Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;->RemoteAuthorizationFlow(Ljava/lang/String;Ll2/o;I)V

    .line 482
    .line 483
    .line 484
    invoke-virtual {p3, v6}, Ll2/t;->q(Z)V

    .line 485
    .line 486
    .line 487
    goto :goto_8

    .line 488
    :cond_1a
    const p0, 0x1a74d22c

    .line 489
    .line 490
    .line 491
    invoke-static {p0, p3, v6}, Lf2/m0;->b(ILl2/t;Z)La8/r0;

    .line 492
    .line 493
    .line 494
    move-result-object p0

    .line 495
    throw p0

    .line 496
    :cond_1b
    move-object v2, p0

    .line 497
    move-object v3, p1

    .line 498
    move-object v4, p2

    .line 499
    move v5, p4

    .line 500
    invoke-virtual {p3}, Ll2/t;->R()V

    .line 501
    .line 502
    .line 503
    :goto_8
    invoke-virtual {p3}, Ll2/t;->s()Ll2/u1;

    .line 504
    .line 505
    .line 506
    move-result-object p0

    .line 507
    if-eqz p0, :cond_1c

    .line 508
    .line 509
    new-instance v1, Lvo0/i;

    .line 510
    .line 511
    const/4 v6, 0x1

    .line 512
    invoke-direct/range {v1 .. v6}, Lvo0/i;-><init>(Llp/v1;Lay0/a;Lay0/a;II)V

    .line 513
    .line 514
    .line 515
    iput-object v1, p0, Ll2/u1;->d:Lay0/n;

    .line 516
    .line 517
    :cond_1c
    return-void
.end method

.method public static final d(Lmk0/b;)Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    packed-switch p0, :pswitch_data_0

    .line 11
    .line 12
    .line 13
    new-instance p0, La8/r0;

    .line 14
    .line 15
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 16
    .line 17
    .line 18
    throw p0

    .line 19
    :pswitch_0
    const-string p0, "LOCATION"

    .line 20
    .line 21
    return-object p0

    .line 22
    :pswitch_1
    const-string p0, "RESTAURANT"

    .line 23
    .line 24
    return-object p0

    .line 25
    :pswitch_2
    const-string p0, "PAY_GAS_STATION"

    .line 26
    .line 27
    return-object p0

    .line 28
    :pswitch_3
    const-string p0, "GAS_STATION"

    .line 29
    .line 30
    return-object p0

    .line 31
    :pswitch_4
    const-string p0, "PAY_PARKING_ZONE"

    .line 32
    .line 33
    return-object p0

    .line 34
    :pswitch_5
    const-string p0, "PAY_PARKING"

    .line 35
    .line 36
    return-object p0

    .line 37
    :pswitch_6
    const-string p0, "PARKING"

    .line 38
    .line 39
    return-object p0

    .line 40
    :pswitch_7
    const-string p0, "HOTEL"

    .line 41
    .line 42
    return-object p0

    .line 43
    :pswitch_8
    const-string p0, "CHARGING_STATION"

    .line 44
    .line 45
    return-object p0

    .line 46
    :pswitch_9
    const-string p0, "WORK"

    .line 47
    .line 48
    return-object p0

    .line 49
    :pswitch_a
    const-string p0, "HOME"

    .line 50
    .line 51
    return-object p0

    .line 52
    nop

    .line 53
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
