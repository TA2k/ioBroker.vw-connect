.class public final Landroidx/datastore/preferences/protobuf/o1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic a:I


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Landroidx/datastore/preferences/protobuf/o1;->a:I

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public static final a(Ly1/i;Lyj/b;Lmh/r;Ll2/o;I)V
    .locals 11

    .line 1
    move-object v0, p3

    .line 2
    check-cast v0, Ll2/t;

    .line 3
    .line 4
    const v2, 0x4e913d0f

    .line 5
    .line 6
    .line 7
    invoke-virtual {v0, v2}, Ll2/t;->a0(I)Ll2/t;

    .line 8
    .line 9
    .line 10
    and-int/lit8 v2, p4, 0x6

    .line 11
    .line 12
    if-nez v2, :cond_1

    .line 13
    .line 14
    invoke-virtual {v0, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 15
    .line 16
    .line 17
    move-result v2

    .line 18
    if-eqz v2, :cond_0

    .line 19
    .line 20
    const/4 v2, 0x4

    .line 21
    goto :goto_0

    .line 22
    :cond_0
    const/4 v2, 0x2

    .line 23
    :goto_0
    or-int/2addr v2, p4

    .line 24
    goto :goto_1

    .line 25
    :cond_1
    move v2, p4

    .line 26
    :goto_1
    and-int/lit8 v6, p4, 0x30

    .line 27
    .line 28
    if-nez v6, :cond_3

    .line 29
    .line 30
    invoke-virtual {v0, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 31
    .line 32
    .line 33
    move-result v6

    .line 34
    if-eqz v6, :cond_2

    .line 35
    .line 36
    const/16 v6, 0x20

    .line 37
    .line 38
    goto :goto_2

    .line 39
    :cond_2
    const/16 v6, 0x10

    .line 40
    .line 41
    :goto_2
    or-int/2addr v2, v6

    .line 42
    :cond_3
    and-int/lit16 v6, p4, 0x180

    .line 43
    .line 44
    const/16 v7, 0x100

    .line 45
    .line 46
    if-nez v6, :cond_5

    .line 47
    .line 48
    invoke-virtual {v0, p2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 49
    .line 50
    .line 51
    move-result v6

    .line 52
    if-eqz v6, :cond_4

    .line 53
    .line 54
    move v6, v7

    .line 55
    goto :goto_3

    .line 56
    :cond_4
    const/16 v6, 0x80

    .line 57
    .line 58
    :goto_3
    or-int/2addr v2, v6

    .line 59
    :cond_5
    and-int/lit16 v6, v2, 0x93

    .line 60
    .line 61
    const/16 v8, 0x92

    .line 62
    .line 63
    const/4 v9, 0x0

    .line 64
    const/4 v10, 0x1

    .line 65
    if-eq v6, v8, :cond_6

    .line 66
    .line 67
    move v6, v10

    .line 68
    goto :goto_4

    .line 69
    :cond_6
    move v6, v9

    .line 70
    :goto_4
    and-int/lit8 v8, v2, 0x1

    .line 71
    .line 72
    invoke-virtual {v0, v8, v6}, Ll2/t;->O(IZ)Z

    .line 73
    .line 74
    .line 75
    move-result v6

    .line 76
    if-eqz v6, :cond_a

    .line 77
    .line 78
    invoke-static {p0, v0}, Ll2/b;->s(Ljava/lang/Object;Ll2/o;)Ll2/b1;

    .line 79
    .line 80
    .line 81
    move-result-object v8

    .line 82
    invoke-static {p1, v0}, Ll2/b;->s(Ljava/lang/Object;Ll2/o;)Ll2/b1;

    .line 83
    .line 84
    .line 85
    move-result-object v6

    .line 86
    and-int/lit16 v2, v2, 0x380

    .line 87
    .line 88
    if-ne v2, v7, :cond_7

    .line 89
    .line 90
    move v9, v10

    .line 91
    :cond_7
    invoke-virtual {v0, v6}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 92
    .line 93
    .line 94
    move-result v2

    .line 95
    or-int/2addr v2, v9

    .line 96
    invoke-virtual {v0, v8}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 97
    .line 98
    .line 99
    move-result v7

    .line 100
    or-int/2addr v2, v7

    .line 101
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    move-result-object v7

    .line 105
    if-nez v2, :cond_8

    .line 106
    .line 107
    sget-object v2, Ll2/n;->a:Ll2/x0;

    .line 108
    .line 109
    if-ne v7, v2, :cond_9

    .line 110
    .line 111
    :cond_8
    new-instance v5, Laa/s;

    .line 112
    .line 113
    const/4 v9, 0x0

    .line 114
    const/16 v10, 0x15

    .line 115
    .line 116
    move-object v7, v6

    .line 117
    move-object v6, p2

    .line 118
    invoke-direct/range {v5 .. v10}, Laa/s;-><init>(Ljava/lang/Object;Ll2/b1;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 119
    .line 120
    .line 121
    invoke-virtual {v0, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 122
    .line 123
    .line 124
    move-object v7, v5

    .line 125
    :cond_9
    check-cast v7, Lay0/n;

    .line 126
    .line 127
    invoke-static {v7, p2, v0}, Ll2/l0;->d(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 128
    .line 129
    .line 130
    goto :goto_5

    .line 131
    :cond_a
    invoke-virtual {v0}, Ll2/t;->R()V

    .line 132
    .line 133
    .line 134
    :goto_5
    invoke-virtual {v0}, Ll2/t;->s()Ll2/u1;

    .line 135
    .line 136
    .line 137
    move-result-object v7

    .line 138
    if-eqz v7, :cond_b

    .line 139
    .line 140
    new-instance v0, Li50/j0;

    .line 141
    .line 142
    const/16 v2, 0x10

    .line 143
    .line 144
    move-object v3, p0

    .line 145
    move-object v4, p1

    .line 146
    move-object v5, p2

    .line 147
    move v1, p4

    .line 148
    invoke-direct/range {v0 .. v5}, Li50/j0;-><init>(IILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 149
    .line 150
    .line 151
    iput-object v0, v7, Ll2/u1;->d:Lay0/n;

    .line 152
    .line 153
    :cond_b
    return-void
.end method

.method public static final b(Lmh/r;Lay0/k;Ll2/o;I)V
    .locals 16

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
    move-object/from16 v12, p2

    .line 8
    .line 9
    check-cast v12, Ll2/t;

    .line 10
    .line 11
    const v3, -0x64634fc2

    .line 12
    .line 13
    .line 14
    invoke-virtual {v12, v3}, Ll2/t;->a0(I)Ll2/t;

    .line 15
    .line 16
    .line 17
    invoke-virtual {v12, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v3

    .line 21
    const/4 v4, 0x4

    .line 22
    if-eqz v3, :cond_0

    .line 23
    .line 24
    move v3, v4

    .line 25
    goto :goto_0

    .line 26
    :cond_0
    const/4 v3, 0x2

    .line 27
    :goto_0
    or-int/2addr v3, v2

    .line 28
    invoke-virtual {v12, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result v5

    .line 32
    const/16 v6, 0x20

    .line 33
    .line 34
    if-eqz v5, :cond_1

    .line 35
    .line 36
    move v5, v6

    .line 37
    goto :goto_1

    .line 38
    :cond_1
    const/16 v5, 0x10

    .line 39
    .line 40
    :goto_1
    or-int/2addr v3, v5

    .line 41
    and-int/lit8 v5, v3, 0x13

    .line 42
    .line 43
    const/16 v7, 0x12

    .line 44
    .line 45
    const/4 v9, 0x0

    .line 46
    if-eq v5, v7, :cond_2

    .line 47
    .line 48
    const/4 v5, 0x1

    .line 49
    goto :goto_2

    .line 50
    :cond_2
    move v5, v9

    .line 51
    :goto_2
    and-int/lit8 v7, v3, 0x1

    .line 52
    .line 53
    invoke-virtual {v12, v7, v5}, Ll2/t;->O(IZ)Z

    .line 54
    .line 55
    .line 56
    move-result v5

    .line 57
    if-eqz v5, :cond_b

    .line 58
    .line 59
    new-array v5, v9, [Ljava/lang/Object;

    .line 60
    .line 61
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    move-result-object v7

    .line 65
    sget-object v10, Ll2/n;->a:Ll2/x0;

    .line 66
    .line 67
    if-ne v7, v10, :cond_3

    .line 68
    .line 69
    new-instance v7, Ll31/b;

    .line 70
    .line 71
    const/16 v11, 0x17

    .line 72
    .line 73
    invoke-direct {v7, v11}, Ll31/b;-><init>(I)V

    .line 74
    .line 75
    .line 76
    invoke-virtual {v12, v7}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 77
    .line 78
    .line 79
    :cond_3
    check-cast v7, Lay0/a;

    .line 80
    .line 81
    const/16 v11, 0x30

    .line 82
    .line 83
    invoke-static {v5, v7, v12, v11}, Lu2/m;->c([Ljava/lang/Object;Lay0/a;Ll2/o;I)Ljava/lang/Object;

    .line 84
    .line 85
    .line 86
    move-result-object v5

    .line 87
    check-cast v5, Ll2/b1;

    .line 88
    .line 89
    new-array v7, v9, [Lz9/j0;

    .line 90
    .line 91
    invoke-static {v7, v12}, Ljp/s0;->b([Lz9/j0;Ll2/o;)Lz9/y;

    .line 92
    .line 93
    .line 94
    move-result-object v7

    .line 95
    iget-object v11, v0, Lmh/r;->a:Lmh/j;

    .line 96
    .line 97
    invoke-virtual {v12, v7}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 98
    .line 99
    .line 100
    move-result v13

    .line 101
    and-int/lit8 v14, v3, 0xe

    .line 102
    .line 103
    if-ne v14, v4, :cond_4

    .line 104
    .line 105
    const/4 v15, 0x1

    .line 106
    goto :goto_3

    .line 107
    :cond_4
    move v15, v9

    .line 108
    :goto_3
    or-int/2addr v13, v15

    .line 109
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    move-result-object v15

    .line 113
    if-nez v13, :cond_5

    .line 114
    .line 115
    if-ne v15, v10, :cond_6

    .line 116
    .line 117
    :cond_5
    new-instance v15, Llb0/q0;

    .line 118
    .line 119
    const/4 v13, 0x0

    .line 120
    const/16 v8, 0x10

    .line 121
    .line 122
    invoke-direct {v15, v8, v7, v0, v13}, Llb0/q0;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 123
    .line 124
    .line 125
    invoke-virtual {v12, v15}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 126
    .line 127
    .line 128
    :cond_6
    check-cast v15, Lay0/n;

    .line 129
    .line 130
    invoke-static {v15, v11, v12}, Ll2/l0;->d(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 131
    .line 132
    .line 133
    and-int/lit8 v3, v3, 0x70

    .line 134
    .line 135
    if-ne v3, v6, :cond_7

    .line 136
    .line 137
    const/4 v3, 0x1

    .line 138
    goto :goto_4

    .line 139
    :cond_7
    move v3, v9

    .line 140
    :goto_4
    if-ne v14, v4, :cond_8

    .line 141
    .line 142
    const/4 v8, 0x1

    .line 143
    goto :goto_5

    .line 144
    :cond_8
    move v8, v9

    .line 145
    :goto_5
    or-int/2addr v3, v8

    .line 146
    invoke-virtual {v12, v5}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 147
    .line 148
    .line 149
    move-result v4

    .line 150
    or-int/2addr v3, v4

    .line 151
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 152
    .line 153
    .line 154
    move-result-object v4

    .line 155
    if-nez v3, :cond_9

    .line 156
    .line 157
    if-ne v4, v10, :cond_a

    .line 158
    .line 159
    :cond_9
    new-instance v4, Lkv0/e;

    .line 160
    .line 161
    const/4 v3, 0x4

    .line 162
    invoke-direct {v4, v1, v0, v5, v3}, Lkv0/e;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 163
    .line 164
    .line 165
    invoke-virtual {v12, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 166
    .line 167
    .line 168
    :cond_a
    move-object v11, v4

    .line 169
    check-cast v11, Lay0/k;

    .line 170
    .line 171
    const/4 v14, 0x0

    .line 172
    const/16 v15, 0x3fc

    .line 173
    .line 174
    const-string v4, "WALLBOX_ONBOARDING_SELECTION"

    .line 175
    .line 176
    const/4 v5, 0x0

    .line 177
    const/4 v6, 0x0

    .line 178
    move-object v3, v7

    .line 179
    const/4 v7, 0x0

    .line 180
    const/4 v8, 0x0

    .line 181
    const/4 v9, 0x0

    .line 182
    const/4 v10, 0x0

    .line 183
    const/16 v13, 0x30

    .line 184
    .line 185
    invoke-static/range {v3 .. v15}, Ljp/w0;->b(Lz9/y;Ljava/lang/String;Lx2/s;Lx2/e;Lay0/k;Lay0/k;Lay0/k;Lay0/k;Lay0/k;Ll2/o;III)V

    .line 186
    .line 187
    .line 188
    goto :goto_6

    .line 189
    :cond_b
    invoke-virtual {v12}, Ll2/t;->R()V

    .line 190
    .line 191
    .line 192
    :goto_6
    invoke-virtual {v12}, Ll2/t;->s()Ll2/u1;

    .line 193
    .line 194
    .line 195
    move-result-object v3

    .line 196
    if-eqz v3, :cond_c

    .line 197
    .line 198
    new-instance v4, Lal/f;

    .line 199
    .line 200
    const/4 v5, 0x1

    .line 201
    invoke-direct {v4, v0, v1, v2, v5}, Lal/f;-><init>(Lmh/r;Lay0/k;II)V

    .line 202
    .line 203
    .line 204
    iput-object v4, v3, Ll2/u1;->d:Lay0/n;

    .line 205
    .line 206
    :cond_c
    return-void
.end method

.method public static final c(Lyj/b;Ly1/i;Ll2/o;I)V
    .locals 21

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
    move-object/from16 v8, p2

    .line 8
    .line 9
    check-cast v8, Ll2/t;

    .line 10
    .line 11
    const v3, -0x41b1f1c5

    .line 12
    .line 13
    .line 14
    invoke-virtual {v8, v3}, Ll2/t;->a0(I)Ll2/t;

    .line 15
    .line 16
    .line 17
    invoke-virtual {v8, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v3

    .line 21
    if-eqz v3, :cond_0

    .line 22
    .line 23
    const/4 v3, 0x4

    .line 24
    goto :goto_0

    .line 25
    :cond_0
    const/4 v3, 0x2

    .line 26
    :goto_0
    or-int/2addr v3, v2

    .line 27
    invoke-virtual {v8, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

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
    or-int v9, v3, v4

    .line 39
    .line 40
    and-int/lit8 v3, v9, 0x13

    .line 41
    .line 42
    const/16 v4, 0x12

    .line 43
    .line 44
    const/4 v10, 0x1

    .line 45
    const/4 v11, 0x0

    .line 46
    if-eq v3, v4, :cond_2

    .line 47
    .line 48
    move v3, v10

    .line 49
    goto :goto_2

    .line 50
    :cond_2
    move v3, v11

    .line 51
    :goto_2
    and-int/lit8 v4, v9, 0x1

    .line 52
    .line 53
    invoke-virtual {v8, v4, v3}, Ll2/t;->O(IZ)Z

    .line 54
    .line 55
    .line 56
    move-result v3

    .line 57
    if-eqz v3, :cond_10

    .line 58
    .line 59
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object v3

    .line 63
    sget-object v12, Ll2/n;->a:Ll2/x0;

    .line 64
    .line 65
    if-ne v3, v12, :cond_3

    .line 66
    .line 67
    new-instance v3, Lmg/i;

    .line 68
    .line 69
    const/16 v4, 0x12

    .line 70
    .line 71
    invoke-direct {v3, v4}, Lmg/i;-><init>(I)V

    .line 72
    .line 73
    .line 74
    invoke-virtual {v8, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 75
    .line 76
    .line 77
    :cond_3
    check-cast v3, Lay0/k;

    .line 78
    .line 79
    sget-object v4, Lw3/q1;->a:Ll2/u2;

    .line 80
    .line 81
    invoke-virtual {v8, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object v4

    .line 85
    check-cast v4, Ljava/lang/Boolean;

    .line 86
    .line 87
    invoke-virtual {v4}, Ljava/lang/Boolean;->booleanValue()Z

    .line 88
    .line 89
    .line 90
    move-result v4

    .line 91
    if-eqz v4, :cond_4

    .line 92
    .line 93
    const v4, -0x105bcaaa

    .line 94
    .line 95
    .line 96
    invoke-virtual {v8, v4}, Ll2/t;->Y(I)V

    .line 97
    .line 98
    .line 99
    invoke-virtual {v8, v11}, Ll2/t;->q(Z)V

    .line 100
    .line 101
    .line 102
    const/4 v4, 0x0

    .line 103
    goto :goto_3

    .line 104
    :cond_4
    const v4, 0x31054eee

    .line 105
    .line 106
    .line 107
    invoke-virtual {v8, v4}, Ll2/t;->Y(I)V

    .line 108
    .line 109
    .line 110
    sget-object v4, Lzb/x;->a:Ll2/u2;

    .line 111
    .line 112
    invoke-virtual {v8, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 113
    .line 114
    .line 115
    move-result-object v4

    .line 116
    check-cast v4, Lhi/a;

    .line 117
    .line 118
    invoke-virtual {v8, v11}, Ll2/t;->q(Z)V

    .line 119
    .line 120
    .line 121
    :goto_3
    new-instance v6, Laf/a;

    .line 122
    .line 123
    const/16 v5, 0x1d

    .line 124
    .line 125
    invoke-direct {v6, v4, v3, v5}, Laf/a;-><init>(Lhi/a;Lay0/k;I)V

    .line 126
    .line 127
    .line 128
    invoke-static {v8}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 129
    .line 130
    .line 131
    move-result-object v4

    .line 132
    if-eqz v4, :cond_f

    .line 133
    .line 134
    instance-of v3, v4, Landroidx/lifecycle/k;

    .line 135
    .line 136
    if-eqz v3, :cond_5

    .line 137
    .line 138
    move-object v3, v4

    .line 139
    check-cast v3, Landroidx/lifecycle/k;

    .line 140
    .line 141
    invoke-interface {v3}, Landroidx/lifecycle/k;->getDefaultViewModelCreationExtras()Lp7/c;

    .line 142
    .line 143
    .line 144
    move-result-object v3

    .line 145
    :goto_4
    move-object v7, v3

    .line 146
    goto :goto_5

    .line 147
    :cond_5
    sget-object v3, Lp7/a;->b:Lp7/a;

    .line 148
    .line 149
    goto :goto_4

    .line 150
    :goto_5
    const-class v3, Lmh/t;

    .line 151
    .line 152
    sget-object v5, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 153
    .line 154
    invoke-virtual {v5, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 155
    .line 156
    .line 157
    move-result-object v3

    .line 158
    const/4 v5, 0x0

    .line 159
    invoke-static/range {v3 .. v8}, Ljp/se;->b(Lhy0/d;Landroidx/lifecycle/i1;Ljava/lang/String;Landroidx/lifecycle/e1;Lp7/c;Ll2/o;)Landroidx/lifecycle/b1;

    .line 160
    .line 161
    .line 162
    move-result-object v3

    .line 163
    move-object v15, v3

    .line 164
    check-cast v15, Lmh/t;

    .line 165
    .line 166
    iget-object v3, v15, Lmh/t;->e:Lyy0/l1;

    .line 167
    .line 168
    invoke-static {v3, v8}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 169
    .line 170
    .line 171
    move-result-object v3

    .line 172
    invoke-interface {v3}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 173
    .line 174
    .line 175
    move-result-object v4

    .line 176
    check-cast v4, Lmh/r;

    .line 177
    .line 178
    shr-int/lit8 v5, v9, 0x3

    .line 179
    .line 180
    and-int/lit8 v5, v5, 0xe

    .line 181
    .line 182
    shl-int/lit8 v6, v9, 0x3

    .line 183
    .line 184
    and-int/lit8 v6, v6, 0x70

    .line 185
    .line 186
    or-int/2addr v5, v6

    .line 187
    invoke-static {v1, v0, v4, v8, v5}, Landroidx/datastore/preferences/protobuf/o1;->a(Ly1/i;Lyj/b;Lmh/r;Ll2/o;I)V

    .line 188
    .line 189
    .line 190
    sget-object v4, Landroidx/compose/foundation/layout/d;->c:Landroidx/compose/foundation/layout/FillElement;

    .line 191
    .line 192
    sget-object v5, Lk1/j;->c:Lk1/e;

    .line 193
    .line 194
    sget-object v6, Lx2/c;->p:Lx2/h;

    .line 195
    .line 196
    invoke-static {v5, v6, v8, v11}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 197
    .line 198
    .line 199
    move-result-object v5

    .line 200
    iget-wide v6, v8, Ll2/t;->T:J

    .line 201
    .line 202
    invoke-static {v6, v7}, Ljava/lang/Long;->hashCode(J)I

    .line 203
    .line 204
    .line 205
    move-result v6

    .line 206
    invoke-virtual {v8}, Ll2/t;->m()Ll2/p1;

    .line 207
    .line 208
    .line 209
    move-result-object v7

    .line 210
    invoke-static {v8, v4}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 211
    .line 212
    .line 213
    move-result-object v4

    .line 214
    sget-object v9, Lv3/k;->m1:Lv3/j;

    .line 215
    .line 216
    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 217
    .line 218
    .line 219
    sget-object v9, Lv3/j;->b:Lv3/i;

    .line 220
    .line 221
    invoke-virtual {v8}, Ll2/t;->c0()V

    .line 222
    .line 223
    .line 224
    iget-boolean v13, v8, Ll2/t;->S:Z

    .line 225
    .line 226
    if-eqz v13, :cond_6

    .line 227
    .line 228
    invoke-virtual {v8, v9}, Ll2/t;->l(Lay0/a;)V

    .line 229
    .line 230
    .line 231
    goto :goto_6

    .line 232
    :cond_6
    invoke-virtual {v8}, Ll2/t;->m0()V

    .line 233
    .line 234
    .line 235
    :goto_6
    sget-object v9, Lv3/j;->g:Lv3/h;

    .line 236
    .line 237
    invoke-static {v9, v5, v8}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 238
    .line 239
    .line 240
    sget-object v5, Lv3/j;->f:Lv3/h;

    .line 241
    .line 242
    invoke-static {v5, v7, v8}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 243
    .line 244
    .line 245
    sget-object v5, Lv3/j;->j:Lv3/h;

    .line 246
    .line 247
    iget-boolean v7, v8, Ll2/t;->S:Z

    .line 248
    .line 249
    if-nez v7, :cond_7

    .line 250
    .line 251
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 252
    .line 253
    .line 254
    move-result-object v7

    .line 255
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 256
    .line 257
    .line 258
    move-result-object v9

    .line 259
    invoke-static {v7, v9}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 260
    .line 261
    .line 262
    move-result v7

    .line 263
    if-nez v7, :cond_8

    .line 264
    .line 265
    :cond_7
    invoke-static {v6, v8, v6, v5}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 266
    .line 267
    .line 268
    :cond_8
    sget-object v5, Lv3/j;->d:Lv3/h;

    .line 269
    .line 270
    invoke-static {v5, v4, v8}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 271
    .line 272
    .line 273
    invoke-static {v8}, Leh/a;->b(Ll2/o;)Leh/n;

    .line 274
    .line 275
    .line 276
    move-result-object v4

    .line 277
    invoke-interface {v3}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 278
    .line 279
    .line 280
    move-result-object v5

    .line 281
    check-cast v5, Lmh/r;

    .line 282
    .line 283
    invoke-virtual {v8, v15}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 284
    .line 285
    .line 286
    move-result v6

    .line 287
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 288
    .line 289
    .line 290
    move-result-object v7

    .line 291
    if-nez v6, :cond_9

    .line 292
    .line 293
    if-ne v7, v12, :cond_a

    .line 294
    .line 295
    :cond_9
    new-instance v13, Ll20/g;

    .line 296
    .line 297
    const/16 v19, 0x0

    .line 298
    .line 299
    const/16 v20, 0xf

    .line 300
    .line 301
    const/4 v14, 0x1

    .line 302
    const-class v16, Lmh/t;

    .line 303
    .line 304
    const-string v17, "onUiEvent"

    .line 305
    .line 306
    const-string v18, "onUiEvent(Lcariad/charging/multicharge/kitten/wallboxes/presentation/onboarding/WallboxOnboardingUiEvent;)V"

    .line 307
    .line 308
    invoke-direct/range {v13 .. v20}, Ll20/g;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 309
    .line 310
    .line 311
    invoke-virtual {v8, v13}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 312
    .line 313
    .line 314
    move-object v7, v13

    .line 315
    :cond_a
    check-cast v7, Lhy0/g;

    .line 316
    .line 317
    check-cast v7, Lay0/k;

    .line 318
    .line 319
    invoke-interface {v4, v5, v7, v8, v11}, Leh/n;->G0(Lmh/r;Lay0/k;Ll2/o;I)V

    .line 320
    .line 321
    .line 322
    invoke-interface {v3}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 323
    .line 324
    .line 325
    move-result-object v3

    .line 326
    check-cast v3, Lmh/r;

    .line 327
    .line 328
    invoke-virtual {v8, v15}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 329
    .line 330
    .line 331
    move-result v4

    .line 332
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 333
    .line 334
    .line 335
    move-result-object v5

    .line 336
    if-nez v4, :cond_b

    .line 337
    .line 338
    if-ne v5, v12, :cond_c

    .line 339
    .line 340
    :cond_b
    new-instance v13, Ll20/g;

    .line 341
    .line 342
    const/16 v19, 0x0

    .line 343
    .line 344
    const/16 v20, 0x10

    .line 345
    .line 346
    const/4 v14, 0x1

    .line 347
    const-class v16, Lmh/t;

    .line 348
    .line 349
    const-string v17, "onUiEvent"

    .line 350
    .line 351
    const-string v18, "onUiEvent(Lcariad/charging/multicharge/kitten/wallboxes/presentation/onboarding/WallboxOnboardingUiEvent;)V"

    .line 352
    .line 353
    invoke-direct/range {v13 .. v20}, Ll20/g;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 354
    .line 355
    .line 356
    invoke-virtual {v8, v13}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 357
    .line 358
    .line 359
    move-object v5, v13

    .line 360
    :cond_c
    check-cast v5, Lhy0/g;

    .line 361
    .line 362
    check-cast v5, Lay0/k;

    .line 363
    .line 364
    invoke-static {v3, v5, v8, v11}, Landroidx/datastore/preferences/protobuf/o1;->b(Lmh/r;Lay0/k;Ll2/o;I)V

    .line 365
    .line 366
    .line 367
    invoke-virtual {v8, v10}, Ll2/t;->q(Z)V

    .line 368
    .line 369
    .line 370
    invoke-virtual {v8, v15}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 371
    .line 372
    .line 373
    move-result v3

    .line 374
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 375
    .line 376
    .line 377
    move-result-object v4

    .line 378
    if-nez v3, :cond_d

    .line 379
    .line 380
    if-ne v4, v12, :cond_e

    .line 381
    .line 382
    :cond_d
    new-instance v4, Lmc/e;

    .line 383
    .line 384
    const/4 v3, 0x3

    .line 385
    invoke-direct {v4, v15, v3}, Lmc/e;-><init>(Ljava/lang/Object;I)V

    .line 386
    .line 387
    .line 388
    invoke-virtual {v8, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 389
    .line 390
    .line 391
    :cond_e
    check-cast v4, Lay0/a;

    .line 392
    .line 393
    invoke-static {v11, v4, v8, v11, v10}, Ljp/tb;->a(ZLay0/a;Ll2/o;II)V

    .line 394
    .line 395
    .line 396
    goto :goto_7

    .line 397
    :cond_f
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 398
    .line 399
    const-string v1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 400
    .line 401
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 402
    .line 403
    .line 404
    throw v0

    .line 405
    :cond_10
    invoke-virtual {v8}, Ll2/t;->R()V

    .line 406
    .line 407
    .line 408
    :goto_7
    invoke-virtual {v8}, Ll2/t;->s()Ll2/u1;

    .line 409
    .line 410
    .line 411
    move-result-object v3

    .line 412
    if-eqz v3, :cond_11

    .line 413
    .line 414
    new-instance v4, Ll2/u;

    .line 415
    .line 416
    const/4 v5, 0x7

    .line 417
    invoke-direct {v4, v2, v5, v0, v1}, Ll2/u;-><init>(IILjava/lang/Object;Ljava/lang/Object;)V

    .line 418
    .line 419
    .line 420
    iput-object v4, v3, Ll2/u1;->d:Lay0/n;

    .line 421
    .line 422
    :cond_11
    return-void
.end method

.method public static final d(Lmh/r;)Ljava/lang/String;
    .locals 1

    .line 1
    iget-object p0, p0, Lmh/r;->a:Lmh/j;

    .line 2
    .line 3
    instance-of v0, p0, Lmh/g;

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    const-string p0, "WALLBOX_ONBOARDING_PAIRING"

    .line 8
    .line 9
    return-object p0

    .line 10
    :cond_0
    sget-object v0, Lmh/h;->b:Lmh/h;

    .line 11
    .line 12
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    if-eqz v0, :cond_1

    .line 17
    .line 18
    const-string p0, "WALLBOX_ONBOARDING_PAIRING_OPTIONS"

    .line 19
    .line 20
    return-object p0

    .line 21
    :cond_1
    sget-object v0, Lmh/i;->b:Lmh/i;

    .line 22
    .line 23
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    if-eqz v0, :cond_2

    .line 28
    .line 29
    const-string p0, "WALLBOX_ONBOARDING_SELECTION"

    .line 30
    .line 31
    return-object p0

    .line 32
    :cond_2
    sget-object v0, Lmh/f;->b:Lmh/f;

    .line 33
    .line 34
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 35
    .line 36
    .line 37
    move-result v0

    .line 38
    if-eqz v0, :cond_3

    .line 39
    .line 40
    const-string p0, "WALLBOX_ONBOARDING_PAIR_SUCCESS"

    .line 41
    .line 42
    return-object p0

    .line 43
    :cond_3
    sget-object v0, Lmh/a;->b:Lmh/a;

    .line 44
    .line 45
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 46
    .line 47
    .line 48
    move-result v0

    .line 49
    if-eqz v0, :cond_4

    .line 50
    .line 51
    const-string p0, "WALLBOX_ONBOARDING_ADD_CHARGING_CARD"

    .line 52
    .line 53
    return-object p0

    .line 54
    :cond_4
    sget-object v0, Lmh/b;->b:Lmh/b;

    .line 55
    .line 56
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 57
    .line 58
    .line 59
    move-result v0

    .line 60
    if-eqz v0, :cond_5

    .line 61
    .line 62
    const-string p0, "WALLBOX_ONBOARDING_AUTHENTICATION"

    .line 63
    .line 64
    return-object p0

    .line 65
    :cond_5
    sget-object v0, Lmh/c;->b:Lmh/c;

    .line 66
    .line 67
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 68
    .line 69
    .line 70
    move-result v0

    .line 71
    if-eqz v0, :cond_6

    .line 72
    .line 73
    const-string p0, "WALLBOX_ONBOARDING_AUTOMATIC_UPDATE"

    .line 74
    .line 75
    return-object p0

    .line 76
    :cond_6
    sget-object v0, Lmh/d;->b:Lmh/d;

    .line 77
    .line 78
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 79
    .line 80
    .line 81
    move-result v0

    .line 82
    if-eqz v0, :cond_7

    .line 83
    .line 84
    const-string p0, "WALLBOX_ONBOARDING_NAME"

    .line 85
    .line 86
    return-object p0

    .line 87
    :cond_7
    sget-object v0, Lmh/e;->b:Lmh/e;

    .line 88
    .line 89
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 90
    .line 91
    .line 92
    move-result p0

    .line 93
    if-eqz p0, :cond_8

    .line 94
    .line 95
    const-string p0, "WALLBOX_ONBOARDING_ONBOARDING_SUCCESS"

    .line 96
    .line 97
    return-object p0

    .line 98
    :cond_8
    new-instance p0, La8/r0;

    .line 99
    .line 100
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 101
    .line 102
    .line 103
    throw p0
.end method

.method public static g(Ljava/util/List;Lai/d;)Lzh/j;
    .locals 24

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    const-string v2, "chargingStations"

    .line 6
    .line 7
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    const-string v2, "downloadChargingStationImageUseCase"

    .line 11
    .line 12
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    new-instance v2, Ljava/util/ArrayList;

    .line 16
    .line 17
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 18
    .line 19
    .line 20
    check-cast v0, Ljava/lang/Iterable;

    .line 21
    .line 22
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 23
    .line 24
    .line 25
    move-result-object v3

    .line 26
    :goto_0
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 27
    .line 28
    .line 29
    move-result v4

    .line 30
    if-eqz v4, :cond_e

    .line 31
    .line 32
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object v4

    .line 36
    check-cast v4, Lzg/h;

    .line 37
    .line 38
    iget-object v8, v4, Lzg/h;->i:Ljava/lang/String;

    .line 39
    .line 40
    iget-object v7, v4, Lzg/h;->e:Lzg/g;

    .line 41
    .line 42
    iget-object v9, v4, Lzg/h;->h:Ljava/lang/String;

    .line 43
    .line 44
    iget-object v10, v4, Lzg/h;->p:Ljava/lang/Boolean;

    .line 45
    .line 46
    sget-object v11, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 47
    .line 48
    invoke-static {v10, v11}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 49
    .line 50
    .line 51
    move-result v10

    .line 52
    const-string v11, "<this>"

    .line 53
    .line 54
    invoke-static {v7, v11}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    invoke-virtual {v7}, Ljava/lang/Enum;->ordinal()I

    .line 58
    .line 59
    .line 60
    move-result v11

    .line 61
    packed-switch v11, :pswitch_data_0

    .line 62
    .line 63
    .line 64
    new-instance v0, La8/r0;

    .line 65
    .line 66
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 67
    .line 68
    .line 69
    throw v0

    .line 70
    :pswitch_0
    sget-object v11, Lgh/a;->f:Lgh/a;

    .line 71
    .line 72
    goto :goto_1

    .line 73
    :pswitch_1
    sget-object v11, Lgh/a;->h:Lgh/a;

    .line 74
    .line 75
    goto :goto_1

    .line 76
    :pswitch_2
    sget-object v11, Lgh/a;->g:Lgh/a;

    .line 77
    .line 78
    goto :goto_1

    .line 79
    :pswitch_3
    sget-object v11, Lgh/a;->e:Lgh/a;

    .line 80
    .line 81
    goto :goto_1

    .line 82
    :pswitch_4
    sget-object v11, Lgh/a;->d:Lgh/a;

    .line 83
    .line 84
    :goto_1
    iget-object v12, v4, Lzg/h;->m:Ljava/lang/String;

    .line 85
    .line 86
    const-string v13, ""

    .line 87
    .line 88
    move-object v14, v12

    .line 89
    if-nez v12, :cond_0

    .line 90
    .line 91
    move-object v12, v13

    .line 92
    :cond_0
    iget-object v15, v4, Lzg/h;->k:Ljava/lang/String;

    .line 93
    .line 94
    move-object/from16 v16, v13

    .line 95
    .line 96
    if-nez v15, :cond_1

    .line 97
    .line 98
    goto :goto_2

    .line 99
    :cond_1
    move-object v13, v15

    .line 100
    :goto_2
    if-eqz v14, :cond_2

    .line 101
    .line 102
    move-object v14, v15

    .line 103
    const/4 v15, 0x1

    .line 104
    goto :goto_3

    .line 105
    :cond_2
    move-object v14, v15

    .line 106
    const/4 v15, 0x0

    .line 107
    :goto_3
    if-eqz v14, :cond_3

    .line 108
    .line 109
    const/4 v14, 0x1

    .line 110
    goto :goto_4

    .line 111
    :cond_3
    const/4 v14, 0x0

    .line 112
    :goto_4
    iget-boolean v5, v4, Lzg/h;->v:Z

    .line 113
    .line 114
    sget-object v6, Lzg/g;->e:Lzg/g;

    .line 115
    .line 116
    if-ne v7, v6, :cond_4

    .line 117
    .line 118
    move-object/from16 v6, v16

    .line 119
    .line 120
    const/16 v16, 0x1

    .line 121
    .line 122
    :goto_5
    move-object/from16 v23, v3

    .line 123
    .line 124
    goto :goto_6

    .line 125
    :cond_4
    move-object/from16 v6, v16

    .line 126
    .line 127
    const/16 v16, 0x0

    .line 128
    .line 129
    goto :goto_5

    .line 130
    :goto_6
    sget-object v3, Lzg/g;->g:Lzg/g;

    .line 131
    .line 132
    if-ne v7, v3, :cond_5

    .line 133
    .line 134
    const/16 v17, 0x1

    .line 135
    .line 136
    goto :goto_7

    .line 137
    :cond_5
    const/16 v17, 0x0

    .line 138
    .line 139
    :goto_7
    sget-object v3, Lzg/g;->i:Lzg/g;

    .line 140
    .line 141
    if-ne v7, v3, :cond_6

    .line 142
    .line 143
    const/16 v18, 0x1

    .line 144
    .line 145
    goto :goto_8

    .line 146
    :cond_6
    const/16 v18, 0x0

    .line 147
    .line 148
    :goto_8
    sget-object v3, Lzg/g;->f:Lzg/g;

    .line 149
    .line 150
    if-ne v7, v3, :cond_7

    .line 151
    .line 152
    const/16 v19, 0x1

    .line 153
    .line 154
    :goto_9
    const/4 v3, 0x0

    .line 155
    goto :goto_a

    .line 156
    :cond_7
    const/16 v19, 0x0

    .line 157
    .line 158
    goto :goto_9

    .line 159
    :goto_a
    iget-object v7, v4, Lzg/h;->d:Ljava/util/List;

    .line 160
    .line 161
    check-cast v7, Ljava/lang/Iterable;

    .line 162
    .line 163
    new-instance v3, Ljava/util/ArrayList;

    .line 164
    .line 165
    move/from16 v21, v5

    .line 166
    .line 167
    const/16 v5, 0xa

    .line 168
    .line 169
    invoke-static {v7, v5}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 170
    .line 171
    .line 172
    move-result v5

    .line 173
    invoke-direct {v3, v5}, Ljava/util/ArrayList;-><init>(I)V

    .line 174
    .line 175
    .line 176
    invoke-interface {v7}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 177
    .line 178
    .line 179
    move-result-object v5

    .line 180
    :goto_b
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 181
    .line 182
    .line 183
    move-result v7

    .line 184
    if-eqz v7, :cond_8

    .line 185
    .line 186
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 187
    .line 188
    .line 189
    move-result-object v7

    .line 190
    check-cast v7, Ljava/lang/String;

    .line 191
    .line 192
    invoke-virtual {v1, v7}, Lai/d;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 193
    .line 194
    .line 195
    move-result-object v7

    .line 196
    check-cast v7, Lkc/e;

    .line 197
    .line 198
    invoke-virtual {v3, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 199
    .line 200
    .line 201
    goto :goto_b

    .line 202
    :cond_8
    new-instance v5, Lzg/i2;

    .line 203
    .line 204
    iget-object v7, v4, Lzg/h;->f:Ljava/lang/String;

    .line 205
    .line 206
    iget-object v4, v4, Lzg/h;->g:Lzg/q;

    .line 207
    .line 208
    if-eqz v4, :cond_9

    .line 209
    .line 210
    const/4 v1, 0x1

    .line 211
    goto :goto_c

    .line 212
    :cond_9
    const/4 v1, 0x0

    .line 213
    :goto_c
    const/16 v20, 0x0

    .line 214
    .line 215
    move-object/from16 v22, v3

    .line 216
    .line 217
    if-eqz v4, :cond_a

    .line 218
    .line 219
    iget-object v3, v4, Lzg/q;->d:Ljava/lang/String;

    .line 220
    .line 221
    goto :goto_d

    .line 222
    :cond_a
    move-object/from16 v3, v20

    .line 223
    .line 224
    :goto_d
    if-nez v3, :cond_b

    .line 225
    .line 226
    move-object v3, v6

    .line 227
    :cond_b
    if-eqz v4, :cond_c

    .line 228
    .line 229
    iget-object v4, v4, Lzg/q;->e:Ljava/lang/String;

    .line 230
    .line 231
    move-object/from16 v20, v4

    .line 232
    .line 233
    :cond_c
    if-nez v20, :cond_d

    .line 234
    .line 235
    goto :goto_e

    .line 236
    :cond_d
    move-object/from16 v6, v20

    .line 237
    .line 238
    :goto_e
    invoke-direct {v5, v1, v7, v3, v6}, Lzg/i2;-><init>(ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 239
    .line 240
    .line 241
    new-instance v7, Lzh/a;

    .line 242
    .line 243
    move-object/from16 v20, v22

    .line 244
    .line 245
    move-object/from16 v22, v5

    .line 246
    .line 247
    invoke-direct/range {v7 .. v22}, Lzh/a;-><init>(Ljava/lang/String;Ljava/lang/String;ZLgh/a;Ljava/lang/String;Ljava/lang/String;ZZZZZZLjava/util/ArrayList;ZLzg/i2;)V

    .line 248
    .line 249
    .line 250
    invoke-virtual {v2, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 251
    .line 252
    .line 253
    move-object/from16 v1, p1

    .line 254
    .line 255
    move-object/from16 v3, v23

    .line 256
    .line 257
    goto/16 :goto_0

    .line 258
    .line 259
    :cond_e
    instance-of v1, v0, Ljava/util/Collection;

    .line 260
    .line 261
    if-eqz v1, :cond_10

    .line 262
    .line 263
    move-object v1, v0

    .line 264
    check-cast v1, Ljava/util/Collection;

    .line 265
    .line 266
    invoke-interface {v1}, Ljava/util/Collection;->isEmpty()Z

    .line 267
    .line 268
    .line 269
    move-result v1

    .line 270
    if-eqz v1, :cond_10

    .line 271
    .line 272
    :cond_f
    const/4 v5, 0x0

    .line 273
    goto :goto_f

    .line 274
    :cond_10
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 275
    .line 276
    .line 277
    move-result-object v0

    .line 278
    :cond_11
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 279
    .line 280
    .line 281
    move-result v1

    .line 282
    if-eqz v1, :cond_f

    .line 283
    .line 284
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 285
    .line 286
    .line 287
    move-result-object v1

    .line 288
    check-cast v1, Lzg/h;

    .line 289
    .line 290
    iget-boolean v1, v1, Lzg/h;->v:Z

    .line 291
    .line 292
    if-eqz v1, :cond_11

    .line 293
    .line 294
    const/4 v5, 0x1

    .line 295
    :goto_f
    new-instance v0, Lzh/j;

    .line 296
    .line 297
    invoke-direct {v0, v2, v5}, Lzh/j;-><init>(Ljava/util/ArrayList;Z)V

    .line 298
    .line 299
    .line 300
    return-object v0

    .line 301
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_2
        :pswitch_3
        :pswitch_1
        :pswitch_0
        :pswitch_4
        :pswitch_3
    .end packed-switch
.end method


# virtual methods
.method public final e([BII)Ljava/lang/String;
    .locals 9

    .line 1
    iget p0, p0, Landroidx/datastore/preferences/protobuf/o1;->a:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p0, Ljava/lang/String;

    .line 7
    .line 8
    sget-object v0, Landroidx/datastore/preferences/protobuf/a0;->a:Ljava/nio/charset/Charset;

    .line 9
    .line 10
    invoke-direct {p0, p1, p2, p3, v0}, Ljava/lang/String;-><init>([BIILjava/nio/charset/Charset;)V

    .line 11
    .line 12
    .line 13
    const v1, 0xfffd

    .line 14
    .line 15
    .line 16
    invoke-virtual {p0, v1}, Ljava/lang/String;->indexOf(I)I

    .line 17
    .line 18
    .line 19
    move-result v1

    .line 20
    if-gez v1, :cond_0

    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_0
    invoke-virtual {p0, v0}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    .line 24
    .line 25
    .line 26
    move-result-object v0

    .line 27
    add-int/2addr p3, p2

    .line 28
    invoke-static {p1, p2, p3}, Ljava/util/Arrays;->copyOfRange([BII)[B

    .line 29
    .line 30
    .line 31
    move-result-object p1

    .line 32
    invoke-static {v0, p1}, Ljava/util/Arrays;->equals([B[B)Z

    .line 33
    .line 34
    .line 35
    move-result p1

    .line 36
    if-eqz p1, :cond_1

    .line 37
    .line 38
    :goto_0
    return-object p0

    .line 39
    :cond_1
    invoke-static {}, Landroidx/datastore/preferences/protobuf/c0;->a()Landroidx/datastore/preferences/protobuf/c0;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    throw p0

    .line 44
    :pswitch_0
    or-int p0, p2, p3

    .line 45
    .line 46
    array-length v0, p1

    .line 47
    sub-int/2addr v0, p2

    .line 48
    sub-int/2addr v0, p3

    .line 49
    or-int/2addr p0, v0

    .line 50
    if-ltz p0, :cond_10

    .line 51
    .line 52
    add-int p0, p2, p3

    .line 53
    .line 54
    new-array p3, p3, [C

    .line 55
    .line 56
    const/4 v0, 0x0

    .line 57
    move v1, v0

    .line 58
    :goto_1
    if-ge p2, p0, :cond_2

    .line 59
    .line 60
    aget-byte v2, p1, p2

    .line 61
    .line 62
    if-ltz v2, :cond_2

    .line 63
    .line 64
    add-int/lit8 p2, p2, 0x1

    .line 65
    .line 66
    add-int/lit8 v3, v1, 0x1

    .line 67
    .line 68
    int-to-char v2, v2

    .line 69
    aput-char v2, p3, v1

    .line 70
    .line 71
    move v1, v3

    .line 72
    goto :goto_1

    .line 73
    :cond_2
    :goto_2
    if-ge p2, p0, :cond_f

    .line 74
    .line 75
    add-int/lit8 v2, p2, 0x1

    .line 76
    .line 77
    aget-byte v3, p1, p2

    .line 78
    .line 79
    if-ltz v3, :cond_4

    .line 80
    .line 81
    add-int/lit8 p2, v1, 0x1

    .line 82
    .line 83
    int-to-char v3, v3

    .line 84
    aput-char v3, p3, v1

    .line 85
    .line 86
    :goto_3
    if-ge v2, p0, :cond_3

    .line 87
    .line 88
    aget-byte v1, p1, v2

    .line 89
    .line 90
    if-ltz v1, :cond_3

    .line 91
    .line 92
    add-int/lit8 v2, v2, 0x1

    .line 93
    .line 94
    add-int/lit8 v3, p2, 0x1

    .line 95
    .line 96
    int-to-char v1, v1

    .line 97
    aput-char v1, p3, p2

    .line 98
    .line 99
    move p2, v3

    .line 100
    goto :goto_3

    .line 101
    :cond_3
    move v1, p2

    .line 102
    move p2, v2

    .line 103
    goto :goto_2

    .line 104
    :cond_4
    const/16 v4, -0x20

    .line 105
    .line 106
    if-ge v3, v4, :cond_7

    .line 107
    .line 108
    if-ge v2, p0, :cond_6

    .line 109
    .line 110
    add-int/lit8 p2, p2, 0x2

    .line 111
    .line 112
    aget-byte v2, p1, v2

    .line 113
    .line 114
    add-int/lit8 v4, v1, 0x1

    .line 115
    .line 116
    const/16 v5, -0x3e

    .line 117
    .line 118
    if-lt v3, v5, :cond_5

    .line 119
    .line 120
    invoke-static {v2}, Ljp/f1;->b(B)Z

    .line 121
    .line 122
    .line 123
    move-result v5

    .line 124
    if-nez v5, :cond_5

    .line 125
    .line 126
    and-int/lit8 v3, v3, 0x1f

    .line 127
    .line 128
    shl-int/lit8 v3, v3, 0x6

    .line 129
    .line 130
    and-int/lit8 v2, v2, 0x3f

    .line 131
    .line 132
    or-int/2addr v2, v3

    .line 133
    int-to-char v2, v2

    .line 134
    aput-char v2, p3, v1

    .line 135
    .line 136
    move v1, v4

    .line 137
    goto :goto_2

    .line 138
    :cond_5
    invoke-static {}, Landroidx/datastore/preferences/protobuf/c0;->a()Landroidx/datastore/preferences/protobuf/c0;

    .line 139
    .line 140
    .line 141
    move-result-object p0

    .line 142
    throw p0

    .line 143
    :cond_6
    invoke-static {}, Landroidx/datastore/preferences/protobuf/c0;->a()Landroidx/datastore/preferences/protobuf/c0;

    .line 144
    .line 145
    .line 146
    move-result-object p0

    .line 147
    throw p0

    .line 148
    :cond_7
    const/16 v5, -0x10

    .line 149
    .line 150
    if-ge v3, v5, :cond_c

    .line 151
    .line 152
    add-int/lit8 v5, p0, -0x1

    .line 153
    .line 154
    if-ge v2, v5, :cond_b

    .line 155
    .line 156
    add-int/lit8 v5, p2, 0x2

    .line 157
    .line 158
    aget-byte v2, p1, v2

    .line 159
    .line 160
    add-int/lit8 p2, p2, 0x3

    .line 161
    .line 162
    aget-byte v5, p1, v5

    .line 163
    .line 164
    add-int/lit8 v6, v1, 0x1

    .line 165
    .line 166
    invoke-static {v2}, Ljp/f1;->b(B)Z

    .line 167
    .line 168
    .line 169
    move-result v7

    .line 170
    if-nez v7, :cond_a

    .line 171
    .line 172
    const/16 v7, -0x60

    .line 173
    .line 174
    if-ne v3, v4, :cond_8

    .line 175
    .line 176
    if-lt v2, v7, :cond_a

    .line 177
    .line 178
    :cond_8
    const/16 v4, -0x13

    .line 179
    .line 180
    if-ne v3, v4, :cond_9

    .line 181
    .line 182
    if-ge v2, v7, :cond_a

    .line 183
    .line 184
    :cond_9
    invoke-static {v5}, Ljp/f1;->b(B)Z

    .line 185
    .line 186
    .line 187
    move-result v4

    .line 188
    if-nez v4, :cond_a

    .line 189
    .line 190
    and-int/lit8 v3, v3, 0xf

    .line 191
    .line 192
    shl-int/lit8 v3, v3, 0xc

    .line 193
    .line 194
    and-int/lit8 v2, v2, 0x3f

    .line 195
    .line 196
    shl-int/lit8 v2, v2, 0x6

    .line 197
    .line 198
    or-int/2addr v2, v3

    .line 199
    and-int/lit8 v3, v5, 0x3f

    .line 200
    .line 201
    or-int/2addr v2, v3

    .line 202
    int-to-char v2, v2

    .line 203
    aput-char v2, p3, v1

    .line 204
    .line 205
    move v1, v6

    .line 206
    goto/16 :goto_2

    .line 207
    .line 208
    :cond_a
    invoke-static {}, Landroidx/datastore/preferences/protobuf/c0;->a()Landroidx/datastore/preferences/protobuf/c0;

    .line 209
    .line 210
    .line 211
    move-result-object p0

    .line 212
    throw p0

    .line 213
    :cond_b
    invoke-static {}, Landroidx/datastore/preferences/protobuf/c0;->a()Landroidx/datastore/preferences/protobuf/c0;

    .line 214
    .line 215
    .line 216
    move-result-object p0

    .line 217
    throw p0

    .line 218
    :cond_c
    add-int/lit8 v4, p0, -0x2

    .line 219
    .line 220
    if-ge v2, v4, :cond_e

    .line 221
    .line 222
    add-int/lit8 v4, p2, 0x2

    .line 223
    .line 224
    aget-byte v2, p1, v2

    .line 225
    .line 226
    add-int/lit8 v5, p2, 0x3

    .line 227
    .line 228
    aget-byte v4, p1, v4

    .line 229
    .line 230
    add-int/lit8 p2, p2, 0x4

    .line 231
    .line 232
    aget-byte v5, p1, v5

    .line 233
    .line 234
    add-int/lit8 v6, v1, 0x1

    .line 235
    .line 236
    invoke-static {v2}, Ljp/f1;->b(B)Z

    .line 237
    .line 238
    .line 239
    move-result v7

    .line 240
    if-nez v7, :cond_d

    .line 241
    .line 242
    shl-int/lit8 v7, v3, 0x1c

    .line 243
    .line 244
    add-int/lit8 v8, v2, 0x70

    .line 245
    .line 246
    add-int/2addr v8, v7

    .line 247
    shr-int/lit8 v7, v8, 0x1e

    .line 248
    .line 249
    if-nez v7, :cond_d

    .line 250
    .line 251
    invoke-static {v4}, Ljp/f1;->b(B)Z

    .line 252
    .line 253
    .line 254
    move-result v7

    .line 255
    if-nez v7, :cond_d

    .line 256
    .line 257
    invoke-static {v5}, Ljp/f1;->b(B)Z

    .line 258
    .line 259
    .line 260
    move-result v7

    .line 261
    if-nez v7, :cond_d

    .line 262
    .line 263
    and-int/lit8 v3, v3, 0x7

    .line 264
    .line 265
    shl-int/lit8 v3, v3, 0x12

    .line 266
    .line 267
    and-int/lit8 v2, v2, 0x3f

    .line 268
    .line 269
    shl-int/lit8 v2, v2, 0xc

    .line 270
    .line 271
    or-int/2addr v2, v3

    .line 272
    and-int/lit8 v3, v4, 0x3f

    .line 273
    .line 274
    shl-int/lit8 v3, v3, 0x6

    .line 275
    .line 276
    or-int/2addr v2, v3

    .line 277
    and-int/lit8 v3, v5, 0x3f

    .line 278
    .line 279
    or-int/2addr v2, v3

    .line 280
    ushr-int/lit8 v3, v2, 0xa

    .line 281
    .line 282
    const v4, 0xd7c0

    .line 283
    .line 284
    .line 285
    add-int/2addr v3, v4

    .line 286
    int-to-char v3, v3

    .line 287
    aput-char v3, p3, v1

    .line 288
    .line 289
    and-int/lit16 v2, v2, 0x3ff

    .line 290
    .line 291
    const v3, 0xdc00

    .line 292
    .line 293
    .line 294
    add-int/2addr v2, v3

    .line 295
    int-to-char v2, v2

    .line 296
    aput-char v2, p3, v6

    .line 297
    .line 298
    add-int/lit8 v1, v1, 0x2

    .line 299
    .line 300
    goto/16 :goto_2

    .line 301
    .line 302
    :cond_d
    invoke-static {}, Landroidx/datastore/preferences/protobuf/c0;->a()Landroidx/datastore/preferences/protobuf/c0;

    .line 303
    .line 304
    .line 305
    move-result-object p0

    .line 306
    throw p0

    .line 307
    :cond_e
    invoke-static {}, Landroidx/datastore/preferences/protobuf/c0;->a()Landroidx/datastore/preferences/protobuf/c0;

    .line 308
    .line 309
    .line 310
    move-result-object p0

    .line 311
    throw p0

    .line 312
    :cond_f
    new-instance p0, Ljava/lang/String;

    .line 313
    .line 314
    invoke-direct {p0, p3, v0, v1}, Ljava/lang/String;-><init>([CII)V

    .line 315
    .line 316
    .line 317
    return-object p0

    .line 318
    :cond_10
    new-instance p0, Ljava/lang/ArrayIndexOutOfBoundsException;

    .line 319
    .line 320
    array-length p1, p1

    .line 321
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 322
    .line 323
    .line 324
    move-result-object p1

    .line 325
    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 326
    .line 327
    .line 328
    move-result-object p2

    .line 329
    invoke-static {p3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 330
    .line 331
    .line 332
    move-result-object p3

    .line 333
    filled-new-array {p1, p2, p3}, [Ljava/lang/Object;

    .line 334
    .line 335
    .line 336
    move-result-object p1

    .line 337
    const-string p2, "buffer length=%d, index=%d, size=%d"

    .line 338
    .line 339
    invoke-static {p2, p1}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 340
    .line 341
    .line 342
    move-result-object p1

    .line 343
    invoke-direct {p0, p1}, Ljava/lang/ArrayIndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    .line 344
    .line 345
    .line 346
    throw p0

    .line 347
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final f(IILjava/lang/String;[B)I
    .locals 23

    .line 1
    move/from16 v0, p1

    .line 2
    .line 3
    move/from16 v1, p2

    .line 4
    .line 5
    move-object/from16 v2, p3

    .line 6
    .line 7
    move-object/from16 v3, p0

    .line 8
    .line 9
    move-object/from16 v4, p4

    .line 10
    .line 11
    iget v3, v3, Landroidx/datastore/preferences/protobuf/o1;->a:I

    .line 12
    .line 13
    packed-switch v3, :pswitch_data_0

    .line 14
    .line 15
    .line 16
    int-to-long v5, v0

    .line 17
    int-to-long v7, v1

    .line 18
    add-long/2addr v7, v5

    .line 19
    invoke-virtual {v2}, Ljava/lang/String;->length()I

    .line 20
    .line 21
    .line 22
    move-result v3

    .line 23
    const-string v9, " at index "

    .line 24
    .line 25
    const-string v10, "Failed writing "

    .line 26
    .line 27
    if-gt v3, v1, :cond_c

    .line 28
    .line 29
    array-length v11, v4

    .line 30
    sub-int/2addr v11, v1

    .line 31
    if-lt v11, v0, :cond_c

    .line 32
    .line 33
    const/4 v0, 0x0

    .line 34
    :goto_0
    const-wide/16 v11, 0x1

    .line 35
    .line 36
    const/16 v1, 0x80

    .line 37
    .line 38
    if-ge v0, v3, :cond_0

    .line 39
    .line 40
    invoke-virtual {v2, v0}, Ljava/lang/String;->charAt(I)C

    .line 41
    .line 42
    .line 43
    move-result v13

    .line 44
    if-ge v13, v1, :cond_0

    .line 45
    .line 46
    add-long/2addr v11, v5

    .line 47
    int-to-byte v1, v13

    .line 48
    invoke-static {v4, v5, v6, v1}, Landroidx/datastore/preferences/protobuf/n1;->j([BJB)V

    .line 49
    .line 50
    .line 51
    add-int/lit8 v0, v0, 0x1

    .line 52
    .line 53
    move-wide v5, v11

    .line 54
    goto :goto_0

    .line 55
    :cond_0
    if-ne v0, v3, :cond_2

    .line 56
    .line 57
    :cond_1
    long-to-int v0, v5

    .line 58
    goto/16 :goto_5

    .line 59
    .line 60
    :cond_2
    :goto_1
    if-ge v0, v3, :cond_1

    .line 61
    .line 62
    invoke-virtual {v2, v0}, Ljava/lang/String;->charAt(I)C

    .line 63
    .line 64
    .line 65
    move-result v13

    .line 66
    if-ge v13, v1, :cond_3

    .line 67
    .line 68
    cmp-long v14, v5, v7

    .line 69
    .line 70
    if-gez v14, :cond_3

    .line 71
    .line 72
    add-long v14, v5, v11

    .line 73
    .line 74
    int-to-byte v13, v13

    .line 75
    invoke-static {v4, v5, v6, v13}, Landroidx/datastore/preferences/protobuf/n1;->j([BJB)V

    .line 76
    .line 77
    .line 78
    move-wide/from16 v19, v7

    .line 79
    .line 80
    move-wide/from16 p0, v11

    .line 81
    .line 82
    move-wide v5, v14

    .line 83
    goto/16 :goto_4

    .line 84
    .line 85
    :cond_3
    const/16 v14, 0x800

    .line 86
    .line 87
    const-wide/16 v15, 0x2

    .line 88
    .line 89
    if-ge v13, v14, :cond_4

    .line 90
    .line 91
    sub-long v17, v7, v15

    .line 92
    .line 93
    cmp-long v14, v5, v17

    .line 94
    .line 95
    if-gtz v14, :cond_4

    .line 96
    .line 97
    move-wide/from16 p0, v11

    .line 98
    .line 99
    add-long v11, v5, p0

    .line 100
    .line 101
    ushr-int/lit8 v14, v13, 0x6

    .line 102
    .line 103
    or-int/lit16 v14, v14, 0x3c0

    .line 104
    .line 105
    int-to-byte v14, v14

    .line 106
    invoke-static {v4, v5, v6, v14}, Landroidx/datastore/preferences/protobuf/n1;->j([BJB)V

    .line 107
    .line 108
    .line 109
    add-long/2addr v5, v15

    .line 110
    and-int/lit8 v13, v13, 0x3f

    .line 111
    .line 112
    or-int/2addr v13, v1

    .line 113
    int-to-byte v13, v13

    .line 114
    invoke-static {v4, v11, v12, v13}, Landroidx/datastore/preferences/protobuf/n1;->j([BJB)V

    .line 115
    .line 116
    .line 117
    move-wide/from16 v19, v7

    .line 118
    .line 119
    goto/16 :goto_4

    .line 120
    .line 121
    :cond_4
    move-wide/from16 p0, v11

    .line 122
    .line 123
    const v11, 0xdfff

    .line 124
    .line 125
    .line 126
    const v12, 0xd800

    .line 127
    .line 128
    .line 129
    const-wide/16 v17, 0x3

    .line 130
    .line 131
    if-lt v13, v12, :cond_6

    .line 132
    .line 133
    if-ge v11, v13, :cond_5

    .line 134
    .line 135
    goto :goto_2

    .line 136
    :cond_5
    move-wide/from16 v19, v7

    .line 137
    .line 138
    goto :goto_3

    .line 139
    :cond_6
    :goto_2
    sub-long v19, v7, v17

    .line 140
    .line 141
    cmp-long v14, v5, v19

    .line 142
    .line 143
    if-gtz v14, :cond_5

    .line 144
    .line 145
    add-long v11, v5, p0

    .line 146
    .line 147
    ushr-int/lit8 v14, v13, 0xc

    .line 148
    .line 149
    or-int/lit16 v14, v14, 0x1e0

    .line 150
    .line 151
    int-to-byte v14, v14

    .line 152
    invoke-static {v4, v5, v6, v14}, Landroidx/datastore/preferences/protobuf/n1;->j([BJB)V

    .line 153
    .line 154
    .line 155
    add-long v14, v5, v15

    .line 156
    .line 157
    ushr-int/lit8 v16, v13, 0x6

    .line 158
    .line 159
    move-wide/from16 v19, v7

    .line 160
    .line 161
    and-int/lit8 v7, v16, 0x3f

    .line 162
    .line 163
    or-int/2addr v7, v1

    .line 164
    int-to-byte v7, v7

    .line 165
    invoke-static {v4, v11, v12, v7}, Landroidx/datastore/preferences/protobuf/n1;->j([BJB)V

    .line 166
    .line 167
    .line 168
    add-long v5, v5, v17

    .line 169
    .line 170
    and-int/lit8 v7, v13, 0x3f

    .line 171
    .line 172
    or-int/2addr v7, v1

    .line 173
    int-to-byte v7, v7

    .line 174
    invoke-static {v4, v14, v15, v7}, Landroidx/datastore/preferences/protobuf/n1;->j([BJB)V

    .line 175
    .line 176
    .line 177
    goto :goto_4

    .line 178
    :goto_3
    const-wide/16 v7, 0x4

    .line 179
    .line 180
    sub-long v21, v19, v7

    .line 181
    .line 182
    cmp-long v14, v5, v21

    .line 183
    .line 184
    if-gtz v14, :cond_9

    .line 185
    .line 186
    add-int/lit8 v11, v0, 0x1

    .line 187
    .line 188
    if-eq v11, v3, :cond_8

    .line 189
    .line 190
    invoke-virtual {v2, v11}, Ljava/lang/String;->charAt(I)C

    .line 191
    .line 192
    .line 193
    move-result v0

    .line 194
    invoke-static {v13, v0}, Ljava/lang/Character;->isSurrogatePair(CC)Z

    .line 195
    .line 196
    .line 197
    move-result v12

    .line 198
    if-eqz v12, :cond_7

    .line 199
    .line 200
    invoke-static {v13, v0}, Ljava/lang/Character;->toCodePoint(CC)I

    .line 201
    .line 202
    .line 203
    move-result v0

    .line 204
    add-long v12, v5, p0

    .line 205
    .line 206
    ushr-int/lit8 v14, v0, 0x12

    .line 207
    .line 208
    or-int/lit16 v14, v14, 0xf0

    .line 209
    .line 210
    int-to-byte v14, v14

    .line 211
    invoke-static {v4, v5, v6, v14}, Landroidx/datastore/preferences/protobuf/n1;->j([BJB)V

    .line 212
    .line 213
    .line 214
    add-long v14, v5, v15

    .line 215
    .line 216
    ushr-int/lit8 v16, v0, 0xc

    .line 217
    .line 218
    move-wide/from16 v21, v7

    .line 219
    .line 220
    and-int/lit8 v7, v16, 0x3f

    .line 221
    .line 222
    or-int/2addr v7, v1

    .line 223
    int-to-byte v7, v7

    .line 224
    invoke-static {v4, v12, v13, v7}, Landroidx/datastore/preferences/protobuf/n1;->j([BJB)V

    .line 225
    .line 226
    .line 227
    add-long v7, v5, v17

    .line 228
    .line 229
    ushr-int/lit8 v12, v0, 0x6

    .line 230
    .line 231
    and-int/lit8 v12, v12, 0x3f

    .line 232
    .line 233
    or-int/2addr v12, v1

    .line 234
    int-to-byte v12, v12

    .line 235
    invoke-static {v4, v14, v15, v12}, Landroidx/datastore/preferences/protobuf/n1;->j([BJB)V

    .line 236
    .line 237
    .line 238
    add-long v5, v5, v21

    .line 239
    .line 240
    and-int/lit8 v0, v0, 0x3f

    .line 241
    .line 242
    or-int/2addr v0, v1

    .line 243
    int-to-byte v0, v0

    .line 244
    invoke-static {v4, v7, v8, v0}, Landroidx/datastore/preferences/protobuf/n1;->j([BJB)V

    .line 245
    .line 246
    .line 247
    move v0, v11

    .line 248
    :goto_4
    add-int/lit8 v0, v0, 0x1

    .line 249
    .line 250
    move-wide/from16 v11, p0

    .line 251
    .line 252
    move-wide/from16 v7, v19

    .line 253
    .line 254
    goto/16 :goto_1

    .line 255
    .line 256
    :cond_7
    move v0, v11

    .line 257
    :cond_8
    new-instance v1, Landroidx/datastore/preferences/protobuf/p1;

    .line 258
    .line 259
    add-int/lit8 v0, v0, -0x1

    .line 260
    .line 261
    invoke-direct {v1, v0, v3}, Landroidx/datastore/preferences/protobuf/p1;-><init>(II)V

    .line 262
    .line 263
    .line 264
    throw v1

    .line 265
    :cond_9
    if-gt v12, v13, :cond_b

    .line 266
    .line 267
    if-gt v13, v11, :cond_b

    .line 268
    .line 269
    add-int/lit8 v1, v0, 0x1

    .line 270
    .line 271
    if-eq v1, v3, :cond_a

    .line 272
    .line 273
    invoke-virtual {v2, v1}, Ljava/lang/String;->charAt(I)C

    .line 274
    .line 275
    .line 276
    move-result v1

    .line 277
    invoke-static {v13, v1}, Ljava/lang/Character;->isSurrogatePair(CC)Z

    .line 278
    .line 279
    .line 280
    move-result v1

    .line 281
    if-nez v1, :cond_b

    .line 282
    .line 283
    :cond_a
    new-instance v1, Landroidx/datastore/preferences/protobuf/p1;

    .line 284
    .line 285
    invoke-direct {v1, v0, v3}, Landroidx/datastore/preferences/protobuf/p1;-><init>(II)V

    .line 286
    .line 287
    .line 288
    throw v1

    .line 289
    :cond_b
    new-instance v0, Ljava/lang/ArrayIndexOutOfBoundsException;

    .line 290
    .line 291
    new-instance v1, Ljava/lang/StringBuilder;

    .line 292
    .line 293
    invoke-direct {v1, v10}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 294
    .line 295
    .line 296
    invoke-virtual {v1, v13}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 297
    .line 298
    .line 299
    invoke-virtual {v1, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 300
    .line 301
    .line 302
    invoke-virtual {v1, v5, v6}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 303
    .line 304
    .line 305
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 306
    .line 307
    .line 308
    move-result-object v1

    .line 309
    invoke-direct {v0, v1}, Ljava/lang/ArrayIndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    .line 310
    .line 311
    .line 312
    throw v0

    .line 313
    :goto_5
    return v0

    .line 314
    :cond_c
    new-instance v4, Ljava/lang/ArrayIndexOutOfBoundsException;

    .line 315
    .line 316
    new-instance v5, Ljava/lang/StringBuilder;

    .line 317
    .line 318
    invoke-direct {v5, v10}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 319
    .line 320
    .line 321
    add-int/lit8 v3, v3, -0x1

    .line 322
    .line 323
    invoke-virtual {v2, v3}, Ljava/lang/String;->charAt(I)C

    .line 324
    .line 325
    .line 326
    move-result v2

    .line 327
    invoke-virtual {v5, v2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 328
    .line 329
    .line 330
    invoke-virtual {v5, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 331
    .line 332
    .line 333
    add-int/2addr v0, v1

    .line 334
    invoke-virtual {v5, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 335
    .line 336
    .line 337
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 338
    .line 339
    .line 340
    move-result-object v0

    .line 341
    invoke-direct {v4, v0}, Ljava/lang/ArrayIndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    .line 342
    .line 343
    .line 344
    throw v4

    .line 345
    :pswitch_0
    invoke-virtual {v2}, Ljava/lang/String;->length()I

    .line 346
    .line 347
    .line 348
    move-result v3

    .line 349
    add-int/2addr v1, v0

    .line 350
    const/4 v5, 0x0

    .line 351
    :goto_6
    const/16 v6, 0x80

    .line 352
    .line 353
    if-ge v5, v3, :cond_d

    .line 354
    .line 355
    add-int v7, v5, v0

    .line 356
    .line 357
    if-ge v7, v1, :cond_d

    .line 358
    .line 359
    invoke-virtual {v2, v5}, Ljava/lang/String;->charAt(I)C

    .line 360
    .line 361
    .line 362
    move-result v8

    .line 363
    if-ge v8, v6, :cond_d

    .line 364
    .line 365
    int-to-byte v6, v8

    .line 366
    aput-byte v6, v4, v7

    .line 367
    .line 368
    add-int/lit8 v5, v5, 0x1

    .line 369
    .line 370
    goto :goto_6

    .line 371
    :cond_d
    if-ne v5, v3, :cond_e

    .line 372
    .line 373
    add-int/2addr v0, v3

    .line 374
    goto/16 :goto_9

    .line 375
    .line 376
    :cond_e
    add-int/2addr v0, v5

    .line 377
    :goto_7
    if-ge v5, v3, :cond_18

    .line 378
    .line 379
    invoke-virtual {v2, v5}, Ljava/lang/String;->charAt(I)C

    .line 380
    .line 381
    .line 382
    move-result v7

    .line 383
    if-ge v7, v6, :cond_f

    .line 384
    .line 385
    if-ge v0, v1, :cond_f

    .line 386
    .line 387
    add-int/lit8 v8, v0, 0x1

    .line 388
    .line 389
    int-to-byte v7, v7

    .line 390
    aput-byte v7, v4, v0

    .line 391
    .line 392
    move v0, v8

    .line 393
    goto/16 :goto_8

    .line 394
    .line 395
    :cond_f
    const/16 v8, 0x800

    .line 396
    .line 397
    if-ge v7, v8, :cond_10

    .line 398
    .line 399
    add-int/lit8 v8, v1, -0x2

    .line 400
    .line 401
    if-gt v0, v8, :cond_10

    .line 402
    .line 403
    add-int/lit8 v8, v0, 0x1

    .line 404
    .line 405
    ushr-int/lit8 v9, v7, 0x6

    .line 406
    .line 407
    or-int/lit16 v9, v9, 0x3c0

    .line 408
    .line 409
    int-to-byte v9, v9

    .line 410
    aput-byte v9, v4, v0

    .line 411
    .line 412
    add-int/lit8 v0, v0, 0x2

    .line 413
    .line 414
    and-int/lit8 v7, v7, 0x3f

    .line 415
    .line 416
    or-int/2addr v7, v6

    .line 417
    int-to-byte v7, v7

    .line 418
    aput-byte v7, v4, v8

    .line 419
    .line 420
    goto :goto_8

    .line 421
    :cond_10
    const v8, 0xdfff

    .line 422
    .line 423
    .line 424
    const v9, 0xd800

    .line 425
    .line 426
    .line 427
    if-lt v7, v9, :cond_11

    .line 428
    .line 429
    if-ge v8, v7, :cond_12

    .line 430
    .line 431
    :cond_11
    add-int/lit8 v10, v1, -0x3

    .line 432
    .line 433
    if-gt v0, v10, :cond_12

    .line 434
    .line 435
    add-int/lit8 v8, v0, 0x1

    .line 436
    .line 437
    ushr-int/lit8 v9, v7, 0xc

    .line 438
    .line 439
    or-int/lit16 v9, v9, 0x1e0

    .line 440
    .line 441
    int-to-byte v9, v9

    .line 442
    aput-byte v9, v4, v0

    .line 443
    .line 444
    add-int/lit8 v9, v0, 0x2

    .line 445
    .line 446
    ushr-int/lit8 v10, v7, 0x6

    .line 447
    .line 448
    and-int/lit8 v10, v10, 0x3f

    .line 449
    .line 450
    or-int/2addr v10, v6

    .line 451
    int-to-byte v10, v10

    .line 452
    aput-byte v10, v4, v8

    .line 453
    .line 454
    add-int/lit8 v0, v0, 0x3

    .line 455
    .line 456
    and-int/lit8 v7, v7, 0x3f

    .line 457
    .line 458
    or-int/2addr v7, v6

    .line 459
    int-to-byte v7, v7

    .line 460
    aput-byte v7, v4, v9

    .line 461
    .line 462
    goto :goto_8

    .line 463
    :cond_12
    add-int/lit8 v10, v1, -0x4

    .line 464
    .line 465
    if-gt v0, v10, :cond_15

    .line 466
    .line 467
    add-int/lit8 v8, v5, 0x1

    .line 468
    .line 469
    invoke-virtual {v2}, Ljava/lang/String;->length()I

    .line 470
    .line 471
    .line 472
    move-result v9

    .line 473
    if-eq v8, v9, :cond_14

    .line 474
    .line 475
    invoke-virtual {v2, v8}, Ljava/lang/String;->charAt(I)C

    .line 476
    .line 477
    .line 478
    move-result v5

    .line 479
    invoke-static {v7, v5}, Ljava/lang/Character;->isSurrogatePair(CC)Z

    .line 480
    .line 481
    .line 482
    move-result v9

    .line 483
    if-eqz v9, :cond_13

    .line 484
    .line 485
    invoke-static {v7, v5}, Ljava/lang/Character;->toCodePoint(CC)I

    .line 486
    .line 487
    .line 488
    move-result v5

    .line 489
    add-int/lit8 v7, v0, 0x1

    .line 490
    .line 491
    ushr-int/lit8 v9, v5, 0x12

    .line 492
    .line 493
    or-int/lit16 v9, v9, 0xf0

    .line 494
    .line 495
    int-to-byte v9, v9

    .line 496
    aput-byte v9, v4, v0

    .line 497
    .line 498
    add-int/lit8 v9, v0, 0x2

    .line 499
    .line 500
    ushr-int/lit8 v10, v5, 0xc

    .line 501
    .line 502
    and-int/lit8 v10, v10, 0x3f

    .line 503
    .line 504
    or-int/2addr v10, v6

    .line 505
    int-to-byte v10, v10

    .line 506
    aput-byte v10, v4, v7

    .line 507
    .line 508
    add-int/lit8 v7, v0, 0x3

    .line 509
    .line 510
    ushr-int/lit8 v10, v5, 0x6

    .line 511
    .line 512
    and-int/lit8 v10, v10, 0x3f

    .line 513
    .line 514
    or-int/2addr v10, v6

    .line 515
    int-to-byte v10, v10

    .line 516
    aput-byte v10, v4, v9

    .line 517
    .line 518
    add-int/lit8 v0, v0, 0x4

    .line 519
    .line 520
    and-int/lit8 v5, v5, 0x3f

    .line 521
    .line 522
    or-int/2addr v5, v6

    .line 523
    int-to-byte v5, v5

    .line 524
    aput-byte v5, v4, v7

    .line 525
    .line 526
    move v5, v8

    .line 527
    :goto_8
    add-int/lit8 v5, v5, 0x1

    .line 528
    .line 529
    goto/16 :goto_7

    .line 530
    .line 531
    :cond_13
    move v5, v8

    .line 532
    :cond_14
    new-instance v0, Landroidx/datastore/preferences/protobuf/p1;

    .line 533
    .line 534
    add-int/lit8 v5, v5, -0x1

    .line 535
    .line 536
    invoke-direct {v0, v5, v3}, Landroidx/datastore/preferences/protobuf/p1;-><init>(II)V

    .line 537
    .line 538
    .line 539
    throw v0

    .line 540
    :cond_15
    if-gt v9, v7, :cond_17

    .line 541
    .line 542
    if-gt v7, v8, :cond_17

    .line 543
    .line 544
    add-int/lit8 v1, v5, 0x1

    .line 545
    .line 546
    invoke-virtual {v2}, Ljava/lang/String;->length()I

    .line 547
    .line 548
    .line 549
    move-result v4

    .line 550
    if-eq v1, v4, :cond_16

    .line 551
    .line 552
    invoke-virtual {v2, v1}, Ljava/lang/String;->charAt(I)C

    .line 553
    .line 554
    .line 555
    move-result v1

    .line 556
    invoke-static {v7, v1}, Ljava/lang/Character;->isSurrogatePair(CC)Z

    .line 557
    .line 558
    .line 559
    move-result v1

    .line 560
    if-nez v1, :cond_17

    .line 561
    .line 562
    :cond_16
    new-instance v0, Landroidx/datastore/preferences/protobuf/p1;

    .line 563
    .line 564
    invoke-direct {v0, v5, v3}, Landroidx/datastore/preferences/protobuf/p1;-><init>(II)V

    .line 565
    .line 566
    .line 567
    throw v0

    .line 568
    :cond_17
    new-instance v1, Ljava/lang/ArrayIndexOutOfBoundsException;

    .line 569
    .line 570
    new-instance v2, Ljava/lang/StringBuilder;

    .line 571
    .line 572
    const-string v3, "Failed writing "

    .line 573
    .line 574
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 575
    .line 576
    .line 577
    invoke-virtual {v2, v7}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 578
    .line 579
    .line 580
    const-string v3, " at index "

    .line 581
    .line 582
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 583
    .line 584
    .line 585
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 586
    .line 587
    .line 588
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 589
    .line 590
    .line 591
    move-result-object v0

    .line 592
    invoke-direct {v1, v0}, Ljava/lang/ArrayIndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    .line 593
    .line 594
    .line 595
    throw v1

    .line 596
    :cond_18
    :goto_9
    return v0

    .line 597
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
