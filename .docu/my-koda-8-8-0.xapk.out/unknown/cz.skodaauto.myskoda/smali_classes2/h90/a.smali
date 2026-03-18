.class public abstract Lh90/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lt2/b;

.field public static final b:Lt2/b;


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lh60/b;

    .line 2
    .line 3
    const/4 v1, 0x6

    .line 4
    invoke-direct {v0, v1}, Lh60/b;-><init>(I)V

    .line 5
    .line 6
    .line 7
    new-instance v1, Lt2/b;

    .line 8
    .line 9
    const/4 v2, 0x0

    .line 10
    const v3, -0x25b36b39

    .line 11
    .line 12
    .line 13
    invoke-direct {v1, v0, v2, v3}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 14
    .line 15
    .line 16
    sput-object v1, Lh90/a;->a:Lt2/b;

    .line 17
    .line 18
    new-instance v0, Lh60/b;

    .line 19
    .line 20
    const/4 v1, 0x7

    .line 21
    invoke-direct {v0, v1}, Lh60/b;-><init>(I)V

    .line 22
    .line 23
    .line 24
    new-instance v1, Lt2/b;

    .line 25
    .line 26
    const v3, -0xc4e82f9

    .line 27
    .line 28
    .line 29
    invoke-direct {v1, v0, v2, v3}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 30
    .line 31
    .line 32
    sput-object v1, Lh90/a;->b:Lt2/b;

    .line 33
    .line 34
    return-void
.end method

.method public static final a(Ljava/lang/String;Ljava/util/List;Lay0/k;Lay0/a;Ljava/lang/String;Ll2/o;I)V
    .locals 12

    .line 1
    move-object/from16 v8, p4

    .line 2
    .line 3
    move/from16 v9, p6

    .line 4
    .line 5
    const-string v0, "title"

    .line 6
    .line 7
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    const-string v0, "preferences"

    .line 11
    .line 12
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    const-string v0, "onPreferenceSelected"

    .line 16
    .line 17
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    const-string v0, "onDismissed"

    .line 21
    .line 22
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    move-object/from16 v10, p5

    .line 26
    .line 27
    check-cast v10, Ll2/t;

    .line 28
    .line 29
    const v0, -0x26e4ccde

    .line 30
    .line 31
    .line 32
    invoke-virtual {v10, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 33
    .line 34
    .line 35
    and-int/lit8 v0, v9, 0x6

    .line 36
    .line 37
    if-nez v0, :cond_1

    .line 38
    .line 39
    invoke-virtual {v10, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

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
    or-int/2addr v0, v9

    .line 49
    goto :goto_1

    .line 50
    :cond_1
    move v0, v9

    .line 51
    :goto_1
    and-int/lit8 v4, v9, 0x30

    .line 52
    .line 53
    if-nez v4, :cond_3

    .line 54
    .line 55
    invoke-virtual {v10, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 56
    .line 57
    .line 58
    move-result v4

    .line 59
    if-eqz v4, :cond_2

    .line 60
    .line 61
    const/16 v4, 0x20

    .line 62
    .line 63
    goto :goto_2

    .line 64
    :cond_2
    const/16 v4, 0x10

    .line 65
    .line 66
    :goto_2
    or-int/2addr v0, v4

    .line 67
    :cond_3
    and-int/lit16 v4, v9, 0x180

    .line 68
    .line 69
    if-nez v4, :cond_5

    .line 70
    .line 71
    invoke-virtual {v10, p2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 72
    .line 73
    .line 74
    move-result v4

    .line 75
    if-eqz v4, :cond_4

    .line 76
    .line 77
    const/16 v4, 0x100

    .line 78
    .line 79
    goto :goto_3

    .line 80
    :cond_4
    const/16 v4, 0x80

    .line 81
    .line 82
    :goto_3
    or-int/2addr v0, v4

    .line 83
    :cond_5
    and-int/lit16 v4, v9, 0xc00

    .line 84
    .line 85
    if-nez v4, :cond_7

    .line 86
    .line 87
    invoke-virtual {v10, p3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 88
    .line 89
    .line 90
    move-result v4

    .line 91
    if-eqz v4, :cond_6

    .line 92
    .line 93
    const/16 v4, 0x800

    .line 94
    .line 95
    goto :goto_4

    .line 96
    :cond_6
    const/16 v4, 0x400

    .line 97
    .line 98
    :goto_4
    or-int/2addr v0, v4

    .line 99
    :cond_7
    and-int/lit16 v4, v9, 0x6000

    .line 100
    .line 101
    if-nez v4, :cond_9

    .line 102
    .line 103
    invoke-virtual {v10, v8}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 104
    .line 105
    .line 106
    move-result v4

    .line 107
    if-eqz v4, :cond_8

    .line 108
    .line 109
    const/16 v4, 0x4000

    .line 110
    .line 111
    goto :goto_5

    .line 112
    :cond_8
    const/16 v4, 0x2000

    .line 113
    .line 114
    :goto_5
    or-int/2addr v0, v4

    .line 115
    :cond_9
    move v11, v0

    .line 116
    and-int/lit16 v0, v11, 0x2493

    .line 117
    .line 118
    const/16 v4, 0x2492

    .line 119
    .line 120
    if-eq v0, v4, :cond_a

    .line 121
    .line 122
    const/4 v0, 0x1

    .line 123
    goto :goto_6

    .line 124
    :cond_a
    const/4 v0, 0x0

    .line 125
    :goto_6
    and-int/lit8 v4, v11, 0x1

    .line 126
    .line 127
    invoke-virtual {v10, v4, v0}, Ll2/t;->O(IZ)Z

    .line 128
    .line 129
    .line 130
    move-result v0

    .line 131
    if-eqz v0, :cond_d

    .line 132
    .line 133
    if-nez v8, :cond_b

    .line 134
    .line 135
    const-string v0, "preferences_picker"

    .line 136
    .line 137
    goto :goto_7

    .line 138
    :cond_b
    const-string v0, "_preferences_picker"

    .line 139
    .line 140
    invoke-virtual {v8, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 141
    .line 142
    .line 143
    move-result-object v0

    .line 144
    :goto_7
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 145
    .line 146
    .line 147
    move-result-object v4

    .line 148
    sget-object v5, Ll2/n;->a:Ll2/x0;

    .line 149
    .line 150
    if-ne v4, v5, :cond_c

    .line 151
    .line 152
    invoke-static {v10}, Ll2/l0;->h(Ll2/o;)Lvy0/b0;

    .line 153
    .line 154
    .line 155
    move-result-object v4

    .line 156
    invoke-virtual {v10, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 157
    .line 158
    .line 159
    :cond_c
    check-cast v4, Lvy0/b0;

    .line 160
    .line 161
    move-object v2, v0

    .line 162
    new-instance v0, Lb50/d;

    .line 163
    .line 164
    const/4 v6, 0x6

    .line 165
    move-object v1, p0

    .line 166
    move-object v3, p1

    .line 167
    move-object v5, p2

    .line 168
    invoke-direct/range {v0 .. v6}, Lb50/d;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 169
    .line 170
    .line 171
    const v1, 0x23c1be9e

    .line 172
    .line 173
    .line 174
    invoke-static {v1, v10, v0}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 175
    .line 176
    .line 177
    move-result-object v3

    .line 178
    shr-int/lit8 v0, v11, 0x9

    .line 179
    .line 180
    and-int/lit8 v0, v0, 0xe

    .line 181
    .line 182
    or-int/lit16 v5, v0, 0xc00

    .line 183
    .line 184
    const/4 v1, 0x0

    .line 185
    const/4 v2, 0x0

    .line 186
    move-object v0, p3

    .line 187
    move-object v4, v10

    .line 188
    invoke-static/range {v0 .. v5}, Lxf0/y1;->h(Lay0/a;ZZLt2/b;Ll2/o;I)V

    .line 189
    .line 190
    .line 191
    goto :goto_8

    .line 192
    :cond_d
    move-object v4, v10

    .line 193
    invoke-virtual {v4}, Ll2/t;->R()V

    .line 194
    .line 195
    .line 196
    :goto_8
    invoke-virtual {v4}, Ll2/t;->s()Ll2/u1;

    .line 197
    .line 198
    .line 199
    move-result-object v10

    .line 200
    if-eqz v10, :cond_e

    .line 201
    .line 202
    new-instance v0, La71/c0;

    .line 203
    .line 204
    const/16 v7, 0xa

    .line 205
    .line 206
    move-object v1, p0

    .line 207
    move-object v2, p1

    .line 208
    move-object v3, p2

    .line 209
    move-object v4, p3

    .line 210
    move-object v5, v8

    .line 211
    move v6, v9

    .line 212
    invoke-direct/range {v0 .. v7}, La71/c0;-><init>(Ljava/lang/String;Ljava/lang/Object;Ljava/lang/Object;Lay0/a;Ljava/lang/Object;II)V

    .line 213
    .line 214
    .line 215
    iput-object v0, v10, Ll2/u1;->d:Lay0/n;

    .line 216
    .line 217
    :cond_e
    return-void
.end method

.method public static final b(Lx2/s;Ll2/o;I)V
    .locals 17

    .line 1
    move-object/from16 v4, p0

    .line 2
    .line 3
    move/from16 v8, p2

    .line 4
    .line 5
    move-object/from16 v5, p1

    .line 6
    .line 7
    check-cast v5, Ll2/t;

    .line 8
    .line 9
    const v0, -0x72abaa83

    .line 10
    .line 11
    .line 12
    invoke-virtual {v5, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 13
    .line 14
    .line 15
    and-int/lit8 v0, v8, 0x3

    .line 16
    .line 17
    const/4 v1, 0x2

    .line 18
    const/4 v2, 0x0

    .line 19
    const/4 v3, 0x1

    .line 20
    if-eq v0, v1, :cond_0

    .line 21
    .line 22
    move v0, v3

    .line 23
    goto :goto_0

    .line 24
    :cond_0
    move v0, v2

    .line 25
    :goto_0
    and-int/lit8 v1, v8, 0x1

    .line 26
    .line 27
    invoke-virtual {v5, v1, v0}, Ll2/t;->O(IZ)Z

    .line 28
    .line 29
    .line 30
    move-result v0

    .line 31
    if-eqz v0, :cond_9

    .line 32
    .line 33
    invoke-static {v5}, Lxf0/y1;->F(Ll2/o;)Z

    .line 34
    .line 35
    .line 36
    move-result v0

    .line 37
    if-eqz v0, :cond_1

    .line 38
    .line 39
    const v0, -0x56f661f3

    .line 40
    .line 41
    .line 42
    invoke-virtual {v5, v0}, Ll2/t;->Y(I)V

    .line 43
    .line 44
    .line 45
    invoke-static {v5, v2}, Lh90/a;->d(Ll2/o;I)V

    .line 46
    .line 47
    .line 48
    invoke-virtual {v5, v2}, Ll2/t;->q(Z)V

    .line 49
    .line 50
    .line 51
    invoke-virtual {v5}, Ll2/t;->s()Ll2/u1;

    .line 52
    .line 53
    .line 54
    move-result-object v0

    .line 55
    if-eqz v0, :cond_a

    .line 56
    .line 57
    new-instance v1, Lb71/j;

    .line 58
    .line 59
    const/16 v2, 0x10

    .line 60
    .line 61
    invoke-direct {v1, v4, v8, v2}, Lb71/j;-><init>(Lx2/s;II)V

    .line 62
    .line 63
    .line 64
    :goto_1
    iput-object v1, v0, Ll2/u1;->d:Lay0/n;

    .line 65
    .line 66
    return-void

    .line 67
    :cond_1
    const v0, -0x570adbdb

    .line 68
    .line 69
    .line 70
    const v1, -0x6040e0aa

    .line 71
    .line 72
    .line 73
    invoke-static {v0, v1, v5, v5, v2}, Lvj/b;->c(IILl2/t;Ll2/t;Z)Landroidx/lifecycle/i1;

    .line 74
    .line 75
    .line 76
    move-result-object v0

    .line 77
    if-eqz v0, :cond_8

    .line 78
    .line 79
    invoke-static {v0}, Ljp/ib;->a(Landroidx/lifecycle/i1;)Lp7/c;

    .line 80
    .line 81
    .line 82
    move-result-object v12

    .line 83
    invoke-static {v5}, Lw11/c;->b(Ll2/o;)Lk21/a;

    .line 84
    .line 85
    .line 86
    move-result-object v14

    .line 87
    const-class v1, Lg90/c;

    .line 88
    .line 89
    sget-object v6, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 90
    .line 91
    invoke-virtual {v6, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 92
    .line 93
    .line 94
    move-result-object v9

    .line 95
    invoke-interface {v0}, Landroidx/lifecycle/i1;->getViewModelStore()Landroidx/lifecycle/h1;

    .line 96
    .line 97
    .line 98
    move-result-object v10

    .line 99
    const/4 v11, 0x0

    .line 100
    const/4 v13, 0x0

    .line 101
    const/4 v15, 0x0

    .line 102
    invoke-static/range {v9 .. v15}, Ljp/lb;->a(Lhy0/d;Landroidx/lifecycle/h1;Ljava/lang/String;Lp7/c;Lh21/b;Lk21/a;Lay0/a;)Landroidx/lifecycle/b1;

    .line 103
    .line 104
    .line 105
    move-result-object v0

    .line 106
    invoke-virtual {v5, v2}, Ll2/t;->q(Z)V

    .line 107
    .line 108
    .line 109
    check-cast v0, Lql0/j;

    .line 110
    .line 111
    invoke-static {v0, v5, v2, v3}, Lkp/x5;->b(Lql0/j;Ll2/o;II)V

    .line 112
    .line 113
    .line 114
    move-object v11, v0

    .line 115
    check-cast v11, Lg90/c;

    .line 116
    .line 117
    iget-object v0, v11, Lql0/j;->g:Lyy0/l1;

    .line 118
    .line 119
    const/4 v1, 0x0

    .line 120
    invoke-static {v0, v1, v5, v3}, Ll2/b;->f(Lyy0/a2;Lwy0/c;Ll2/o;I)Ll2/b1;

    .line 121
    .line 122
    .line 123
    move-result-object v0

    .line 124
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 125
    .line 126
    .line 127
    move-result-object v0

    .line 128
    check-cast v0, Lg90/a;

    .line 129
    .line 130
    invoke-virtual {v5, v11}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 131
    .line 132
    .line 133
    move-result v1

    .line 134
    invoke-virtual {v5}, Ll2/t;->L()Ljava/lang/Object;

    .line 135
    .line 136
    .line 137
    move-result-object v2

    .line 138
    sget-object v3, Ll2/n;->a:Ll2/x0;

    .line 139
    .line 140
    if-nez v1, :cond_2

    .line 141
    .line 142
    if-ne v2, v3, :cond_3

    .line 143
    .line 144
    :cond_2
    new-instance v9, Lh10/e;

    .line 145
    .line 146
    const/4 v15, 0x0

    .line 147
    const/16 v16, 0x1c

    .line 148
    .line 149
    const/4 v10, 0x0

    .line 150
    const-class v12, Lg90/c;

    .line 151
    .line 152
    const-string v13, "onShowPicker"

    .line 153
    .line 154
    const-string v14, "onShowPicker()V"

    .line 155
    .line 156
    invoke-direct/range {v9 .. v16}, Lh10/e;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 157
    .line 158
    .line 159
    invoke-virtual {v5, v9}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 160
    .line 161
    .line 162
    move-object v2, v9

    .line 163
    :cond_3
    check-cast v2, Lhy0/g;

    .line 164
    .line 165
    move-object v1, v2

    .line 166
    check-cast v1, Lay0/a;

    .line 167
    .line 168
    invoke-virtual {v5, v11}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 169
    .line 170
    .line 171
    move-result v2

    .line 172
    invoke-virtual {v5}, Ll2/t;->L()Ljava/lang/Object;

    .line 173
    .line 174
    .line 175
    move-result-object v6

    .line 176
    if-nez v2, :cond_4

    .line 177
    .line 178
    if-ne v6, v3, :cond_5

    .line 179
    .line 180
    :cond_4
    new-instance v9, Lei/a;

    .line 181
    .line 182
    const/4 v15, 0x0

    .line 183
    const/16 v16, 0x19

    .line 184
    .line 185
    const/4 v10, 0x1

    .line 186
    const-class v12, Lg90/c;

    .line 187
    .line 188
    const-string v13, "onPickTheme"

    .line 189
    .line 190
    const-string v14, "onPickTheme(I)V"

    .line 191
    .line 192
    invoke-direct/range {v9 .. v16}, Lei/a;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 193
    .line 194
    .line 195
    invoke-virtual {v5, v9}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 196
    .line 197
    .line 198
    move-object v6, v9

    .line 199
    :cond_5
    check-cast v6, Lhy0/g;

    .line 200
    .line 201
    move-object v2, v6

    .line 202
    check-cast v2, Lay0/k;

    .line 203
    .line 204
    invoke-virtual {v5, v11}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 205
    .line 206
    .line 207
    move-result v6

    .line 208
    invoke-virtual {v5}, Ll2/t;->L()Ljava/lang/Object;

    .line 209
    .line 210
    .line 211
    move-result-object v7

    .line 212
    if-nez v6, :cond_6

    .line 213
    .line 214
    if-ne v7, v3, :cond_7

    .line 215
    .line 216
    :cond_6
    new-instance v9, Lh10/e;

    .line 217
    .line 218
    const/4 v15, 0x0

    .line 219
    const/16 v16, 0x1d

    .line 220
    .line 221
    const/4 v10, 0x0

    .line 222
    const-class v12, Lg90/c;

    .line 223
    .line 224
    const-string v13, "onDismissPicker"

    .line 225
    .line 226
    const-string v14, "onDismissPicker()V"

    .line 227
    .line 228
    invoke-direct/range {v9 .. v16}, Lh10/e;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 229
    .line 230
    .line 231
    invoke-virtual {v5, v9}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 232
    .line 233
    .line 234
    move-object v7, v9

    .line 235
    :cond_7
    check-cast v7, Lhy0/g;

    .line 236
    .line 237
    move-object v3, v7

    .line 238
    check-cast v3, Lay0/a;

    .line 239
    .line 240
    const/16 v6, 0x6000

    .line 241
    .line 242
    const/4 v7, 0x0

    .line 243
    invoke-static/range {v0 .. v7}, Lh90/a;->c(Lg90/a;Lay0/a;Lay0/k;Lay0/a;Lx2/s;Ll2/o;II)V

    .line 244
    .line 245
    .line 246
    goto :goto_2

    .line 247
    :cond_8
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
    :cond_9
    invoke-virtual {v5}, Ll2/t;->R()V

    .line 256
    .line 257
    .line 258
    :goto_2
    invoke-virtual {v5}, Ll2/t;->s()Ll2/u1;

    .line 259
    .line 260
    .line 261
    move-result-object v0

    .line 262
    if-eqz v0, :cond_a

    .line 263
    .line 264
    new-instance v1, Lb71/j;

    .line 265
    .line 266
    const/16 v2, 0x11

    .line 267
    .line 268
    invoke-direct {v1, v4, v8, v2}, Lb71/j;-><init>(Lx2/s;II)V

    .line 269
    .line 270
    .line 271
    goto/16 :goto_1

    .line 272
    .line 273
    :cond_a
    return-void
.end method

.method public static final c(Lg90/a;Lay0/a;Lay0/k;Lay0/a;Lx2/s;Ll2/o;II)V
    .locals 22

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move/from16 v6, p6

    .line 4
    .line 5
    move-object/from16 v12, p5

    .line 6
    .line 7
    check-cast v12, Ll2/t;

    .line 8
    .line 9
    const v0, -0xe5c106d

    .line 10
    .line 11
    .line 12
    invoke-virtual {v12, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 13
    .line 14
    .line 15
    and-int/lit8 v0, v6, 0x6

    .line 16
    .line 17
    const/4 v2, 0x2

    .line 18
    if-nez v0, :cond_1

    .line 19
    .line 20
    invoke-virtual {v12, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    if-eqz v0, :cond_0

    .line 25
    .line 26
    const/4 v0, 0x4

    .line 27
    goto :goto_0

    .line 28
    :cond_0
    move v0, v2

    .line 29
    :goto_0
    or-int/2addr v0, v6

    .line 30
    goto :goto_1

    .line 31
    :cond_1
    move v0, v6

    .line 32
    :goto_1
    and-int/lit8 v3, v6, 0x30

    .line 33
    .line 34
    move-object/from16 v14, p1

    .line 35
    .line 36
    if-nez v3, :cond_3

    .line 37
    .line 38
    invoke-virtual {v12, v14}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 39
    .line 40
    .line 41
    move-result v3

    .line 42
    if-eqz v3, :cond_2

    .line 43
    .line 44
    const/16 v3, 0x20

    .line 45
    .line 46
    goto :goto_2

    .line 47
    :cond_2
    const/16 v3, 0x10

    .line 48
    .line 49
    :goto_2
    or-int/2addr v0, v3

    .line 50
    :cond_3
    and-int/lit16 v3, v6, 0x180

    .line 51
    .line 52
    move-object/from16 v9, p2

    .line 53
    .line 54
    if-nez v3, :cond_5

    .line 55
    .line 56
    invoke-virtual {v12, v9}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 57
    .line 58
    .line 59
    move-result v3

    .line 60
    if-eqz v3, :cond_4

    .line 61
    .line 62
    const/16 v3, 0x100

    .line 63
    .line 64
    goto :goto_3

    .line 65
    :cond_4
    const/16 v3, 0x80

    .line 66
    .line 67
    :goto_3
    or-int/2addr v0, v3

    .line 68
    :cond_5
    and-int/lit16 v3, v6, 0xc00

    .line 69
    .line 70
    move-object/from16 v10, p3

    .line 71
    .line 72
    if-nez v3, :cond_7

    .line 73
    .line 74
    invoke-virtual {v12, v10}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 75
    .line 76
    .line 77
    move-result v3

    .line 78
    if-eqz v3, :cond_6

    .line 79
    .line 80
    const/16 v3, 0x800

    .line 81
    .line 82
    goto :goto_4

    .line 83
    :cond_6
    const/16 v3, 0x400

    .line 84
    .line 85
    :goto_4
    or-int/2addr v0, v3

    .line 86
    :cond_7
    and-int/lit8 v3, p7, 0x10

    .line 87
    .line 88
    if-eqz v3, :cond_9

    .line 89
    .line 90
    or-int/lit16 v0, v0, 0x6000

    .line 91
    .line 92
    :cond_8
    move-object/from16 v4, p4

    .line 93
    .line 94
    goto :goto_6

    .line 95
    :cond_9
    and-int/lit16 v4, v6, 0x6000

    .line 96
    .line 97
    if-nez v4, :cond_8

    .line 98
    .line 99
    move-object/from16 v4, p4

    .line 100
    .line 101
    invoke-virtual {v12, v4}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 102
    .line 103
    .line 104
    move-result v5

    .line 105
    if-eqz v5, :cond_a

    .line 106
    .line 107
    const/16 v5, 0x4000

    .line 108
    .line 109
    goto :goto_5

    .line 110
    :cond_a
    const/16 v5, 0x2000

    .line 111
    .line 112
    :goto_5
    or-int/2addr v0, v5

    .line 113
    :goto_6
    and-int/lit16 v5, v0, 0x2493

    .line 114
    .line 115
    const/16 v7, 0x2492

    .line 116
    .line 117
    const/4 v15, 0x0

    .line 118
    if-eq v5, v7, :cond_b

    .line 119
    .line 120
    const/4 v5, 0x1

    .line 121
    goto :goto_7

    .line 122
    :cond_b
    move v5, v15

    .line 123
    :goto_7
    and-int/lit8 v7, v0, 0x1

    .line 124
    .line 125
    invoke-virtual {v12, v7, v5}, Ll2/t;->O(IZ)Z

    .line 126
    .line 127
    .line 128
    move-result v5

    .line 129
    if-eqz v5, :cond_e

    .line 130
    .line 131
    sget-object v5, Lx2/p;->b:Lx2/p;

    .line 132
    .line 133
    if-eqz v3, :cond_c

    .line 134
    .line 135
    move-object v4, v5

    .line 136
    :cond_c
    iget-boolean v3, v1, Lg90/a;->c:Z

    .line 137
    .line 138
    if-eqz v3, :cond_d

    .line 139
    .line 140
    const v3, -0xb97e66e

    .line 141
    .line 142
    .line 143
    invoke-virtual {v12, v3}, Ll2/t;->Y(I)V

    .line 144
    .line 145
    .line 146
    iget-object v7, v1, Lg90/a;->a:Ljava/lang/String;

    .line 147
    .line 148
    iget-object v8, v1, Lg90/a;->b:Ljava/util/List;

    .line 149
    .line 150
    and-int/lit16 v3, v0, 0x380

    .line 151
    .line 152
    or-int/lit16 v3, v3, 0x6000

    .line 153
    .line 154
    and-int/lit16 v11, v0, 0x1c00

    .line 155
    .line 156
    or-int v13, v3, v11

    .line 157
    .line 158
    const-string v11, "theme"

    .line 159
    .line 160
    invoke-static/range {v7 .. v13}, Lh90/a;->a(Ljava/lang/String;Ljava/util/List;Lay0/k;Lay0/a;Ljava/lang/String;Ll2/o;I)V

    .line 161
    .line 162
    .line 163
    :goto_8
    invoke-virtual {v12, v15}, Ll2/t;->q(Z)V

    .line 164
    .line 165
    .line 166
    goto :goto_9

    .line 167
    :cond_d
    const v3, -0xbb6de51

    .line 168
    .line 169
    .line 170
    invoke-virtual {v12, v3}, Ll2/t;->Y(I)V

    .line 171
    .line 172
    .line 173
    goto :goto_8

    .line 174
    :goto_9
    const v3, 0x7f1211f2

    .line 175
    .line 176
    .line 177
    invoke-static {v12, v3}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 178
    .line 179
    .line 180
    move-result-object v7

    .line 181
    new-instance v11, Li91/z1;

    .line 182
    .line 183
    new-instance v8, Lg4/g;

    .line 184
    .line 185
    iget-object v9, v1, Lg90/a;->d:Ljava/lang/String;

    .line 186
    .line 187
    invoke-direct {v8, v9}, Lg4/g;-><init>(Ljava/lang/String;)V

    .line 188
    .line 189
    .line 190
    const v9, 0x7f08033b

    .line 191
    .line 192
    .line 193
    invoke-direct {v11, v8, v9}, Li91/z1;-><init>(Lg4/g;I)V

    .line 194
    .line 195
    .line 196
    sget-object v8, Lj91/a;->a:Ll2/u2;

    .line 197
    .line 198
    invoke-virtual {v12, v8}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 199
    .line 200
    .line 201
    move-result-object v9

    .line 202
    check-cast v9, Lj91/c;

    .line 203
    .line 204
    iget v9, v9, Lj91/c;->k:F

    .line 205
    .line 206
    invoke-static {v4, v3}, Lxf0/i0;->M(Lx2/s;I)Lx2/s;

    .line 207
    .line 208
    .line 209
    move-result-object v3

    .line 210
    shl-int/lit8 v0, v0, 0x12

    .line 211
    .line 212
    const/high16 v10, 0x1c00000

    .line 213
    .line 214
    and-int v18, v0, v10

    .line 215
    .line 216
    const/16 v19, 0x30

    .line 217
    .line 218
    const/16 v20, 0x66c

    .line 219
    .line 220
    move v0, v15

    .line 221
    move v15, v9

    .line 222
    const/4 v9, 0x0

    .line 223
    const/4 v10, 0x0

    .line 224
    move-object/from16 v17, v12

    .line 225
    .line 226
    const/4 v12, 0x0

    .line 227
    const/4 v13, 0x0

    .line 228
    const-string v16, "settings_general_item_appearance"

    .line 229
    .line 230
    move-object/from16 v21, v3

    .line 231
    .line 232
    move v3, v0

    .line 233
    move-object v0, v8

    .line 234
    move-object/from16 v8, v21

    .line 235
    .line 236
    invoke-static/range {v7 .. v20}, Li91/j0;->L(Ljava/lang/String;Lx2/s;Ljava/lang/String;Li91/x1;Li91/v1;ZLi91/t1;Lay0/a;FLjava/lang/String;Ll2/o;III)V

    .line 237
    .line 238
    .line 239
    move-object/from16 v12, v17

    .line 240
    .line 241
    invoke-virtual {v12, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 242
    .line 243
    .line 244
    move-result-object v0

    .line 245
    check-cast v0, Lj91/c;

    .line 246
    .line 247
    iget v0, v0, Lj91/c;->k:F

    .line 248
    .line 249
    const/4 v7, 0x0

    .line 250
    invoke-static {v5, v0, v7, v2}, Landroidx/compose/foundation/layout/a;->o(Lx2/s;FFI)Lx2/s;

    .line 251
    .line 252
    .line 253
    move-result-object v0

    .line 254
    invoke-static {v3, v3, v12, v0}, Li91/j0;->D(IILl2/o;Lx2/s;)V

    .line 255
    .line 256
    .line 257
    :goto_a
    move-object v5, v4

    .line 258
    goto :goto_b

    .line 259
    :cond_e
    invoke-virtual {v12}, Ll2/t;->R()V

    .line 260
    .line 261
    .line 262
    goto :goto_a

    .line 263
    :goto_b
    invoke-virtual {v12}, Ll2/t;->s()Ll2/u1;

    .line 264
    .line 265
    .line 266
    move-result-object v9

    .line 267
    if-eqz v9, :cond_f

    .line 268
    .line 269
    new-instance v0, Ld80/n;

    .line 270
    .line 271
    const/4 v8, 0x2

    .line 272
    move-object/from16 v2, p1

    .line 273
    .line 274
    move-object/from16 v3, p2

    .line 275
    .line 276
    move-object/from16 v4, p3

    .line 277
    .line 278
    move/from16 v7, p7

    .line 279
    .line 280
    invoke-direct/range {v0 .. v8}, Ld80/n;-><init>(Lql0/h;Lay0/a;Lay0/k;Lay0/a;Lx2/s;III)V

    .line 281
    .line 282
    .line 283
    iput-object v0, v9, Ll2/u1;->d:Lay0/n;

    .line 284
    .line 285
    :cond_f
    return-void
.end method

.method public static final d(Ll2/o;I)V
    .locals 4

    .line 1
    check-cast p0, Ll2/t;

    .line 2
    .line 3
    const v0, 0x64c9f356

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    const/4 v0, 0x0

    .line 10
    const/4 v1, 0x1

    .line 11
    if-eqz p1, :cond_0

    .line 12
    .line 13
    move v2, v1

    .line 14
    goto :goto_0

    .line 15
    :cond_0
    move v2, v0

    .line 16
    :goto_0
    and-int/lit8 v3, p1, 0x1

    .line 17
    .line 18
    invoke-virtual {p0, v3, v2}, Ll2/t;->O(IZ)Z

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    if-eqz v2, :cond_1

    .line 23
    .line 24
    sget-object v2, Lh90/a;->a:Lt2/b;

    .line 25
    .line 26
    const/16 v3, 0x30

    .line 27
    .line 28
    invoke-static {v0, v2, p0, v3, v1}, Lxf0/y1;->i(ZLay0/n;Ll2/o;II)V

    .line 29
    .line 30
    .line 31
    goto :goto_1

    .line 32
    :cond_1
    invoke-virtual {p0}, Ll2/t;->R()V

    .line 33
    .line 34
    .line 35
    :goto_1
    invoke-virtual {p0}, Ll2/t;->s()Ll2/u1;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    if-eqz p0, :cond_2

    .line 40
    .line 41
    new-instance v0, Lh60/b;

    .line 42
    .line 43
    const/16 v1, 0x8

    .line 44
    .line 45
    invoke-direct {v0, p1, v1}, Lh60/b;-><init>(II)V

    .line 46
    .line 47
    .line 48
    iput-object v0, p0, Ll2/u1;->d:Lay0/n;

    .line 49
    .line 50
    :cond_2
    return-void
.end method

.method public static final e(Lx2/s;Ll2/o;I)V
    .locals 17

    .line 1
    move-object/from16 v4, p0

    .line 2
    .line 3
    move/from16 v8, p2

    .line 4
    .line 5
    move-object/from16 v5, p1

    .line 6
    .line 7
    check-cast v5, Ll2/t;

    .line 8
    .line 9
    const v0, 0xabf9ec9

    .line 10
    .line 11
    .line 12
    invoke-virtual {v5, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 13
    .line 14
    .line 15
    and-int/lit8 v0, v8, 0x3

    .line 16
    .line 17
    const/4 v1, 0x2

    .line 18
    const/4 v2, 0x0

    .line 19
    const/4 v3, 0x1

    .line 20
    if-eq v0, v1, :cond_0

    .line 21
    .line 22
    move v0, v3

    .line 23
    goto :goto_0

    .line 24
    :cond_0
    move v0, v2

    .line 25
    :goto_0
    and-int/lit8 v1, v8, 0x1

    .line 26
    .line 27
    invoke-virtual {v5, v1, v0}, Ll2/t;->O(IZ)Z

    .line 28
    .line 29
    .line 30
    move-result v0

    .line 31
    if-eqz v0, :cond_9

    .line 32
    .line 33
    invoke-static {v5}, Lxf0/y1;->F(Ll2/o;)Z

    .line 34
    .line 35
    .line 36
    move-result v0

    .line 37
    if-eqz v0, :cond_1

    .line 38
    .line 39
    const v0, -0x2eefbebf

    .line 40
    .line 41
    .line 42
    invoke-virtual {v5, v0}, Ll2/t;->Y(I)V

    .line 43
    .line 44
    .line 45
    invoke-static {v5, v2}, Lh90/a;->g(Ll2/o;I)V

    .line 46
    .line 47
    .line 48
    invoke-virtual {v5, v2}, Ll2/t;->q(Z)V

    .line 49
    .line 50
    .line 51
    invoke-virtual {v5}, Ll2/t;->s()Ll2/u1;

    .line 52
    .line 53
    .line 54
    move-result-object v0

    .line 55
    if-eqz v0, :cond_a

    .line 56
    .line 57
    new-instance v1, Lb71/j;

    .line 58
    .line 59
    const/16 v2, 0x12

    .line 60
    .line 61
    invoke-direct {v1, v4, v8, v2}, Lb71/j;-><init>(Lx2/s;II)V

    .line 62
    .line 63
    .line 64
    :goto_1
    iput-object v1, v0, Ll2/u1;->d:Lay0/n;

    .line 65
    .line 66
    return-void

    .line 67
    :cond_1
    const v0, -0x2f0438a7

    .line 68
    .line 69
    .line 70
    const v1, -0x6040e0aa

    .line 71
    .line 72
    .line 73
    invoke-static {v0, v1, v5, v5, v2}, Lvj/b;->c(IILl2/t;Ll2/t;Z)Landroidx/lifecycle/i1;

    .line 74
    .line 75
    .line 76
    move-result-object v0

    .line 77
    if-eqz v0, :cond_8

    .line 78
    .line 79
    invoke-static {v0}, Ljp/ib;->a(Landroidx/lifecycle/i1;)Lp7/c;

    .line 80
    .line 81
    .line 82
    move-result-object v12

    .line 83
    invoke-static {v5}, Lw11/c;->b(Ll2/o;)Lk21/a;

    .line 84
    .line 85
    .line 86
    move-result-object v14

    .line 87
    const-class v1, Lg90/e;

    .line 88
    .line 89
    sget-object v6, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 90
    .line 91
    invoke-virtual {v6, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 92
    .line 93
    .line 94
    move-result-object v9

    .line 95
    invoke-interface {v0}, Landroidx/lifecycle/i1;->getViewModelStore()Landroidx/lifecycle/h1;

    .line 96
    .line 97
    .line 98
    move-result-object v10

    .line 99
    const/4 v11, 0x0

    .line 100
    const/4 v13, 0x0

    .line 101
    const/4 v15, 0x0

    .line 102
    invoke-static/range {v9 .. v15}, Ljp/lb;->a(Lhy0/d;Landroidx/lifecycle/h1;Ljava/lang/String;Lp7/c;Lh21/b;Lk21/a;Lay0/a;)Landroidx/lifecycle/b1;

    .line 103
    .line 104
    .line 105
    move-result-object v0

    .line 106
    invoke-virtual {v5, v2}, Ll2/t;->q(Z)V

    .line 107
    .line 108
    .line 109
    check-cast v0, Lql0/j;

    .line 110
    .line 111
    invoke-static {v0, v5, v2, v3}, Lkp/x5;->b(Lql0/j;Ll2/o;II)V

    .line 112
    .line 113
    .line 114
    move-object v11, v0

    .line 115
    check-cast v11, Lg90/e;

    .line 116
    .line 117
    iget-object v0, v11, Lql0/j;->g:Lyy0/l1;

    .line 118
    .line 119
    const/4 v1, 0x0

    .line 120
    invoke-static {v0, v1, v5, v3}, Ll2/b;->f(Lyy0/a2;Lwy0/c;Ll2/o;I)Ll2/b1;

    .line 121
    .line 122
    .line 123
    move-result-object v0

    .line 124
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 125
    .line 126
    .line 127
    move-result-object v0

    .line 128
    check-cast v0, Lg90/d;

    .line 129
    .line 130
    invoke-virtual {v5, v11}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 131
    .line 132
    .line 133
    move-result v1

    .line 134
    invoke-virtual {v5}, Ll2/t;->L()Ljava/lang/Object;

    .line 135
    .line 136
    .line 137
    move-result-object v2

    .line 138
    sget-object v3, Ll2/n;->a:Ll2/x0;

    .line 139
    .line 140
    if-nez v1, :cond_2

    .line 141
    .line 142
    if-ne v2, v3, :cond_3

    .line 143
    .line 144
    :cond_2
    new-instance v9, Lh90/d;

    .line 145
    .line 146
    const/4 v15, 0x0

    .line 147
    const/16 v16, 0x0

    .line 148
    .line 149
    const/4 v10, 0x0

    .line 150
    const-class v12, Lg90/e;

    .line 151
    .line 152
    const-string v13, "onShowPicker"

    .line 153
    .line 154
    const-string v14, "onShowPicker()V"

    .line 155
    .line 156
    invoke-direct/range {v9 .. v16}, Lh90/d;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 157
    .line 158
    .line 159
    invoke-virtual {v5, v9}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 160
    .line 161
    .line 162
    move-object v2, v9

    .line 163
    :cond_3
    check-cast v2, Lhy0/g;

    .line 164
    .line 165
    move-object v1, v2

    .line 166
    check-cast v1, Lay0/a;

    .line 167
    .line 168
    invoke-virtual {v5, v11}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 169
    .line 170
    .line 171
    move-result v2

    .line 172
    invoke-virtual {v5}, Ll2/t;->L()Ljava/lang/Object;

    .line 173
    .line 174
    .line 175
    move-result-object v6

    .line 176
    if-nez v2, :cond_4

    .line 177
    .line 178
    if-ne v6, v3, :cond_5

    .line 179
    .line 180
    :cond_4
    new-instance v9, Lei/a;

    .line 181
    .line 182
    const/4 v15, 0x0

    .line 183
    const/16 v16, 0x1a

    .line 184
    .line 185
    const/4 v10, 0x1

    .line 186
    const-class v12, Lg90/e;

    .line 187
    .line 188
    const-string v13, "onPickUnits"

    .line 189
    .line 190
    const-string v14, "onPickUnits(I)V"

    .line 191
    .line 192
    invoke-direct/range {v9 .. v16}, Lei/a;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 193
    .line 194
    .line 195
    invoke-virtual {v5, v9}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 196
    .line 197
    .line 198
    move-object v6, v9

    .line 199
    :cond_5
    check-cast v6, Lhy0/g;

    .line 200
    .line 201
    move-object v2, v6

    .line 202
    check-cast v2, Lay0/k;

    .line 203
    .line 204
    invoke-virtual {v5, v11}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 205
    .line 206
    .line 207
    move-result v6

    .line 208
    invoke-virtual {v5}, Ll2/t;->L()Ljava/lang/Object;

    .line 209
    .line 210
    .line 211
    move-result-object v7

    .line 212
    if-nez v6, :cond_6

    .line 213
    .line 214
    if-ne v7, v3, :cond_7

    .line 215
    .line 216
    :cond_6
    new-instance v9, Lh90/d;

    .line 217
    .line 218
    const/4 v15, 0x0

    .line 219
    const/16 v16, 0x1

    .line 220
    .line 221
    const/4 v10, 0x0

    .line 222
    const-class v12, Lg90/e;

    .line 223
    .line 224
    const-string v13, "onDismissPicker"

    .line 225
    .line 226
    const-string v14, "onDismissPicker()V"

    .line 227
    .line 228
    invoke-direct/range {v9 .. v16}, Lh90/d;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 229
    .line 230
    .line 231
    invoke-virtual {v5, v9}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 232
    .line 233
    .line 234
    move-object v7, v9

    .line 235
    :cond_7
    check-cast v7, Lhy0/g;

    .line 236
    .line 237
    move-object v3, v7

    .line 238
    check-cast v3, Lay0/a;

    .line 239
    .line 240
    const/16 v6, 0x6000

    .line 241
    .line 242
    const/4 v7, 0x0

    .line 243
    invoke-static/range {v0 .. v7}, Lh90/a;->f(Lg90/d;Lay0/a;Lay0/k;Lay0/a;Lx2/s;Ll2/o;II)V

    .line 244
    .line 245
    .line 246
    goto :goto_2

    .line 247
    :cond_8
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
    :cond_9
    invoke-virtual {v5}, Ll2/t;->R()V

    .line 256
    .line 257
    .line 258
    :goto_2
    invoke-virtual {v5}, Ll2/t;->s()Ll2/u1;

    .line 259
    .line 260
    .line 261
    move-result-object v0

    .line 262
    if-eqz v0, :cond_a

    .line 263
    .line 264
    new-instance v1, Lb71/j;

    .line 265
    .line 266
    const/16 v2, 0x13

    .line 267
    .line 268
    invoke-direct {v1, v4, v8, v2}, Lb71/j;-><init>(Lx2/s;II)V

    .line 269
    .line 270
    .line 271
    goto/16 :goto_1

    .line 272
    .line 273
    :cond_a
    return-void
.end method

.method public static final f(Lg90/d;Lay0/a;Lay0/k;Lay0/a;Lx2/s;Ll2/o;II)V
    .locals 22

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move/from16 v6, p6

    .line 4
    .line 5
    move-object/from16 v12, p5

    .line 6
    .line 7
    check-cast v12, Ll2/t;

    .line 8
    .line 9
    const v0, 0x54eb9adf

    .line 10
    .line 11
    .line 12
    invoke-virtual {v12, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 13
    .line 14
    .line 15
    and-int/lit8 v0, v6, 0x6

    .line 16
    .line 17
    const/4 v2, 0x2

    .line 18
    if-nez v0, :cond_1

    .line 19
    .line 20
    invoke-virtual {v12, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    if-eqz v0, :cond_0

    .line 25
    .line 26
    const/4 v0, 0x4

    .line 27
    goto :goto_0

    .line 28
    :cond_0
    move v0, v2

    .line 29
    :goto_0
    or-int/2addr v0, v6

    .line 30
    goto :goto_1

    .line 31
    :cond_1
    move v0, v6

    .line 32
    :goto_1
    and-int/lit8 v3, v6, 0x30

    .line 33
    .line 34
    move-object/from16 v14, p1

    .line 35
    .line 36
    if-nez v3, :cond_3

    .line 37
    .line 38
    invoke-virtual {v12, v14}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 39
    .line 40
    .line 41
    move-result v3

    .line 42
    if-eqz v3, :cond_2

    .line 43
    .line 44
    const/16 v3, 0x20

    .line 45
    .line 46
    goto :goto_2

    .line 47
    :cond_2
    const/16 v3, 0x10

    .line 48
    .line 49
    :goto_2
    or-int/2addr v0, v3

    .line 50
    :cond_3
    and-int/lit16 v3, v6, 0x180

    .line 51
    .line 52
    move-object/from16 v9, p2

    .line 53
    .line 54
    if-nez v3, :cond_5

    .line 55
    .line 56
    invoke-virtual {v12, v9}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 57
    .line 58
    .line 59
    move-result v3

    .line 60
    if-eqz v3, :cond_4

    .line 61
    .line 62
    const/16 v3, 0x100

    .line 63
    .line 64
    goto :goto_3

    .line 65
    :cond_4
    const/16 v3, 0x80

    .line 66
    .line 67
    :goto_3
    or-int/2addr v0, v3

    .line 68
    :cond_5
    and-int/lit16 v3, v6, 0xc00

    .line 69
    .line 70
    move-object/from16 v10, p3

    .line 71
    .line 72
    if-nez v3, :cond_7

    .line 73
    .line 74
    invoke-virtual {v12, v10}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 75
    .line 76
    .line 77
    move-result v3

    .line 78
    if-eqz v3, :cond_6

    .line 79
    .line 80
    const/16 v3, 0x800

    .line 81
    .line 82
    goto :goto_4

    .line 83
    :cond_6
    const/16 v3, 0x400

    .line 84
    .line 85
    :goto_4
    or-int/2addr v0, v3

    .line 86
    :cond_7
    and-int/lit8 v3, p7, 0x10

    .line 87
    .line 88
    if-eqz v3, :cond_9

    .line 89
    .line 90
    or-int/lit16 v0, v0, 0x6000

    .line 91
    .line 92
    :cond_8
    move-object/from16 v4, p4

    .line 93
    .line 94
    goto :goto_6

    .line 95
    :cond_9
    and-int/lit16 v4, v6, 0x6000

    .line 96
    .line 97
    if-nez v4, :cond_8

    .line 98
    .line 99
    move-object/from16 v4, p4

    .line 100
    .line 101
    invoke-virtual {v12, v4}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 102
    .line 103
    .line 104
    move-result v5

    .line 105
    if-eqz v5, :cond_a

    .line 106
    .line 107
    const/16 v5, 0x4000

    .line 108
    .line 109
    goto :goto_5

    .line 110
    :cond_a
    const/16 v5, 0x2000

    .line 111
    .line 112
    :goto_5
    or-int/2addr v0, v5

    .line 113
    :goto_6
    and-int/lit16 v5, v0, 0x2493

    .line 114
    .line 115
    const/16 v7, 0x2492

    .line 116
    .line 117
    const/4 v15, 0x0

    .line 118
    if-eq v5, v7, :cond_b

    .line 119
    .line 120
    const/4 v5, 0x1

    .line 121
    goto :goto_7

    .line 122
    :cond_b
    move v5, v15

    .line 123
    :goto_7
    and-int/lit8 v7, v0, 0x1

    .line 124
    .line 125
    invoke-virtual {v12, v7, v5}, Ll2/t;->O(IZ)Z

    .line 126
    .line 127
    .line 128
    move-result v5

    .line 129
    if-eqz v5, :cond_e

    .line 130
    .line 131
    sget-object v5, Lx2/p;->b:Lx2/p;

    .line 132
    .line 133
    if-eqz v3, :cond_c

    .line 134
    .line 135
    move-object v4, v5

    .line 136
    :cond_c
    iget-boolean v3, v1, Lg90/d;->c:Z

    .line 137
    .line 138
    if-eqz v3, :cond_d

    .line 139
    .line 140
    const v3, 0x459f1ac6

    .line 141
    .line 142
    .line 143
    invoke-virtual {v12, v3}, Ll2/t;->Y(I)V

    .line 144
    .line 145
    .line 146
    iget-object v7, v1, Lg90/d;->a:Ljava/lang/String;

    .line 147
    .line 148
    iget-object v8, v1, Lg90/d;->b:Ljava/util/List;

    .line 149
    .line 150
    and-int/lit16 v3, v0, 0x380

    .line 151
    .line 152
    or-int/lit16 v3, v3, 0x6000

    .line 153
    .line 154
    and-int/lit16 v11, v0, 0x1c00

    .line 155
    .line 156
    or-int v13, v3, v11

    .line 157
    .line 158
    const-string v11, "units"

    .line 159
    .line 160
    invoke-static/range {v7 .. v13}, Lh90/a;->a(Ljava/lang/String;Ljava/util/List;Lay0/k;Lay0/a;Ljava/lang/String;Ll2/o;I)V

    .line 161
    .line 162
    .line 163
    :goto_8
    invoke-virtual {v12, v15}, Ll2/t;->q(Z)V

    .line 164
    .line 165
    .line 166
    goto :goto_9

    .line 167
    :cond_d
    const v3, 0x458022e3

    .line 168
    .line 169
    .line 170
    invoke-virtual {v12, v3}, Ll2/t;->Y(I)V

    .line 171
    .line 172
    .line 173
    goto :goto_8

    .line 174
    :goto_9
    const v3, 0x7f1211fa

    .line 175
    .line 176
    .line 177
    invoke-static {v12, v3}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 178
    .line 179
    .line 180
    move-result-object v7

    .line 181
    new-instance v11, Li91/z1;

    .line 182
    .line 183
    new-instance v8, Lg4/g;

    .line 184
    .line 185
    iget-object v9, v1, Lg90/d;->d:Ljava/lang/String;

    .line 186
    .line 187
    invoke-direct {v8, v9}, Lg4/g;-><init>(Ljava/lang/String;)V

    .line 188
    .line 189
    .line 190
    const v9, 0x7f08033b

    .line 191
    .line 192
    .line 193
    invoke-direct {v11, v8, v9}, Li91/z1;-><init>(Lg4/g;I)V

    .line 194
    .line 195
    .line 196
    sget-object v8, Lj91/a;->a:Ll2/u2;

    .line 197
    .line 198
    invoke-virtual {v12, v8}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 199
    .line 200
    .line 201
    move-result-object v9

    .line 202
    check-cast v9, Lj91/c;

    .line 203
    .line 204
    iget v9, v9, Lj91/c;->k:F

    .line 205
    .line 206
    invoke-static {v4, v3}, Lxf0/i0;->M(Lx2/s;I)Lx2/s;

    .line 207
    .line 208
    .line 209
    move-result-object v3

    .line 210
    shl-int/lit8 v0, v0, 0x12

    .line 211
    .line 212
    const/high16 v10, 0x1c00000

    .line 213
    .line 214
    and-int v18, v0, v10

    .line 215
    .line 216
    const/16 v19, 0x30

    .line 217
    .line 218
    const/16 v20, 0x66c

    .line 219
    .line 220
    move v0, v15

    .line 221
    move v15, v9

    .line 222
    const/4 v9, 0x0

    .line 223
    const/4 v10, 0x0

    .line 224
    move-object/from16 v17, v12

    .line 225
    .line 226
    const/4 v12, 0x0

    .line 227
    const/4 v13, 0x0

    .line 228
    const-string v16, "settings_general_item_units"

    .line 229
    .line 230
    move-object/from16 v21, v3

    .line 231
    .line 232
    move v3, v0

    .line 233
    move-object v0, v8

    .line 234
    move-object/from16 v8, v21

    .line 235
    .line 236
    invoke-static/range {v7 .. v20}, Li91/j0;->L(Ljava/lang/String;Lx2/s;Ljava/lang/String;Li91/x1;Li91/v1;ZLi91/t1;Lay0/a;FLjava/lang/String;Ll2/o;III)V

    .line 237
    .line 238
    .line 239
    move-object/from16 v12, v17

    .line 240
    .line 241
    invoke-virtual {v12, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 242
    .line 243
    .line 244
    move-result-object v0

    .line 245
    check-cast v0, Lj91/c;

    .line 246
    .line 247
    iget v0, v0, Lj91/c;->k:F

    .line 248
    .line 249
    const/4 v7, 0x0

    .line 250
    invoke-static {v5, v0, v7, v2}, Landroidx/compose/foundation/layout/a;->o(Lx2/s;FFI)Lx2/s;

    .line 251
    .line 252
    .line 253
    move-result-object v0

    .line 254
    invoke-static {v3, v3, v12, v0}, Li91/j0;->D(IILl2/o;Lx2/s;)V

    .line 255
    .line 256
    .line 257
    :goto_a
    move-object v5, v4

    .line 258
    goto :goto_b

    .line 259
    :cond_e
    invoke-virtual {v12}, Ll2/t;->R()V

    .line 260
    .line 261
    .line 262
    goto :goto_a

    .line 263
    :goto_b
    invoke-virtual {v12}, Ll2/t;->s()Ll2/u1;

    .line 264
    .line 265
    .line 266
    move-result-object v9

    .line 267
    if-eqz v9, :cond_f

    .line 268
    .line 269
    new-instance v0, Ld80/n;

    .line 270
    .line 271
    const/4 v8, 0x3

    .line 272
    move-object/from16 v2, p1

    .line 273
    .line 274
    move-object/from16 v3, p2

    .line 275
    .line 276
    move-object/from16 v4, p3

    .line 277
    .line 278
    move/from16 v7, p7

    .line 279
    .line 280
    invoke-direct/range {v0 .. v8}, Ld80/n;-><init>(Lql0/h;Lay0/a;Lay0/k;Lay0/a;Lx2/s;III)V

    .line 281
    .line 282
    .line 283
    iput-object v0, v9, Ll2/u1;->d:Lay0/n;

    .line 284
    .line 285
    :cond_f
    return-void
.end method

.method public static final g(Ll2/o;I)V
    .locals 4

    .line 1
    check-cast p0, Ll2/t;

    .line 2
    .line 3
    const v0, 0x7e2edb96

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    const/4 v0, 0x0

    .line 10
    const/4 v1, 0x1

    .line 11
    if-eqz p1, :cond_0

    .line 12
    .line 13
    move v2, v1

    .line 14
    goto :goto_0

    .line 15
    :cond_0
    move v2, v0

    .line 16
    :goto_0
    and-int/lit8 v3, p1, 0x1

    .line 17
    .line 18
    invoke-virtual {p0, v3, v2}, Ll2/t;->O(IZ)Z

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    if-eqz v2, :cond_1

    .line 23
    .line 24
    sget-object v2, Lh90/a;->b:Lt2/b;

    .line 25
    .line 26
    const/16 v3, 0x30

    .line 27
    .line 28
    invoke-static {v0, v2, p0, v3, v1}, Lxf0/y1;->i(ZLay0/n;Ll2/o;II)V

    .line 29
    .line 30
    .line 31
    goto :goto_1

    .line 32
    :cond_1
    invoke-virtual {p0}, Ll2/t;->R()V

    .line 33
    .line 34
    .line 35
    :goto_1
    invoke-virtual {p0}, Ll2/t;->s()Ll2/u1;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    if-eqz p0, :cond_2

    .line 40
    .line 41
    new-instance v0, Lh60/b;

    .line 42
    .line 43
    const/16 v1, 0x9

    .line 44
    .line 45
    invoke-direct {v0, p1, v1}, Lh60/b;-><init>(II)V

    .line 46
    .line 47
    .line 48
    iput-object v0, p0, Ll2/u1;->d:Lay0/n;

    .line 49
    .line 50
    :cond_2
    return-void
.end method
