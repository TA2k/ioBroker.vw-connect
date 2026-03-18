.class public abstract Lf20/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lt2/b;

.field public static final b:Lt2/b;


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lew/g;

    .line 2
    .line 3
    const/4 v1, 0x2

    .line 4
    invoke-direct {v0, v1}, Lew/g;-><init>(I)V

    .line 5
    .line 6
    .line 7
    new-instance v1, Lt2/b;

    .line 8
    .line 9
    const/4 v2, 0x0

    .line 10
    const v3, 0x1d60f8ab

    .line 11
    .line 12
    .line 13
    invoke-direct {v1, v0, v2, v3}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 14
    .line 15
    .line 16
    sput-object v1, Lf20/a;->a:Lt2/b;

    .line 17
    .line 18
    new-instance v0, Lel/a;

    .line 19
    .line 20
    const/4 v1, 0x2

    .line 21
    invoke-direct {v0, v1}, Lel/a;-><init>(I)V

    .line 22
    .line 23
    .line 24
    new-instance v1, Lt2/b;

    .line 25
    .line 26
    const v3, -0x3026e91e

    .line 27
    .line 28
    .line 29
    invoke-direct {v1, v0, v2, v3}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 30
    .line 31
    .line 32
    sput-object v1, Lf20/a;->b:Lt2/b;

    .line 33
    .line 34
    return-void
.end method

.method public static final a(Lx2/s;Ll2/o;I)V
    .locals 13

    .line 1
    check-cast p1, Ll2/t;

    .line 2
    .line 3
    const v0, 0x1def1d6f

    .line 4
    .line 5
    .line 6
    invoke-virtual {p1, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    and-int/lit8 v0, p2, 0x6

    .line 10
    .line 11
    const/4 v1, 0x2

    .line 12
    if-nez v0, :cond_1

    .line 13
    .line 14
    invoke-virtual {p1, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

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
    move v0, v1

    .line 23
    :goto_0
    or-int/2addr v0, p2

    .line 24
    goto :goto_1

    .line 25
    :cond_1
    move v0, p2

    .line 26
    :goto_1
    and-int/lit8 v2, v0, 0x3

    .line 27
    .line 28
    const/4 v3, 0x0

    .line 29
    const/4 v4, 0x1

    .line 30
    if-eq v2, v1, :cond_2

    .line 31
    .line 32
    move v1, v4

    .line 33
    goto :goto_2

    .line 34
    :cond_2
    move v1, v3

    .line 35
    :goto_2
    and-int/lit8 v2, v0, 0x1

    .line 36
    .line 37
    invoke-virtual {p1, v2, v1}, Ll2/t;->O(IZ)Z

    .line 38
    .line 39
    .line 40
    move-result v1

    .line 41
    if-eqz v1, :cond_7

    .line 42
    .line 43
    invoke-static {p1}, Lxf0/y1;->F(Ll2/o;)Z

    .line 44
    .line 45
    .line 46
    move-result v1

    .line 47
    if-eqz v1, :cond_3

    .line 48
    .line 49
    const v0, 0x751378db

    .line 50
    .line 51
    .line 52
    invoke-virtual {p1, v0}, Ll2/t;->Y(I)V

    .line 53
    .line 54
    .line 55
    invoke-static {p1, v3}, Lf20/a;->c(Ll2/o;I)V

    .line 56
    .line 57
    .line 58
    invoke-virtual {p1, v3}, Ll2/t;->q(Z)V

    .line 59
    .line 60
    .line 61
    invoke-virtual {p1}, Ll2/t;->s()Ll2/u1;

    .line 62
    .line 63
    .line 64
    move-result-object p1

    .line 65
    if-eqz p1, :cond_8

    .line 66
    .line 67
    new-instance v0, Ld00/b;

    .line 68
    .line 69
    const/16 v1, 0x8

    .line 70
    .line 71
    invoke-direct {v0, p0, p2, v1}, Ld00/b;-><init>(Lx2/s;II)V

    .line 72
    .line 73
    .line 74
    :goto_3
    iput-object v0, p1, Ll2/u1;->d:Lay0/n;

    .line 75
    .line 76
    return-void

    .line 77
    :cond_3
    const v1, 0x75059c53

    .line 78
    .line 79
    .line 80
    const v2, -0x6040e0aa

    .line 81
    .line 82
    .line 83
    invoke-static {v1, v2, p1, p1, v3}, Lvj/b;->c(IILl2/t;Ll2/t;Z)Landroidx/lifecycle/i1;

    .line 84
    .line 85
    .line 86
    move-result-object v1

    .line 87
    if-eqz v1, :cond_6

    .line 88
    .line 89
    invoke-static {v1}, Ljp/ib;->a(Landroidx/lifecycle/i1;)Lp7/c;

    .line 90
    .line 91
    .line 92
    move-result-object v8

    .line 93
    invoke-static {p1}, Lw11/c;->b(Ll2/o;)Lk21/a;

    .line 94
    .line 95
    .line 96
    move-result-object v10

    .line 97
    const-class v2, Le20/b;

    .line 98
    .line 99
    sget-object v5, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 100
    .line 101
    invoke-virtual {v5, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 102
    .line 103
    .line 104
    move-result-object v5

    .line 105
    invoke-interface {v1}, Landroidx/lifecycle/i1;->getViewModelStore()Landroidx/lifecycle/h1;

    .line 106
    .line 107
    .line 108
    move-result-object v6

    .line 109
    const/4 v7, 0x0

    .line 110
    const/4 v9, 0x0

    .line 111
    const/4 v11, 0x0

    .line 112
    invoke-static/range {v5 .. v11}, Ljp/lb;->a(Lhy0/d;Landroidx/lifecycle/h1;Ljava/lang/String;Lp7/c;Lh21/b;Lk21/a;Lay0/a;)Landroidx/lifecycle/b1;

    .line 113
    .line 114
    .line 115
    move-result-object v1

    .line 116
    invoke-virtual {p1, v3}, Ll2/t;->q(Z)V

    .line 117
    .line 118
    .line 119
    check-cast v1, Lql0/j;

    .line 120
    .line 121
    invoke-static {v1, p1, v3, v4}, Lkp/x5;->b(Lql0/j;Ll2/o;II)V

    .line 122
    .line 123
    .line 124
    move-object v7, v1

    .line 125
    check-cast v7, Le20/b;

    .line 126
    .line 127
    invoke-virtual {p1, v7}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 128
    .line 129
    .line 130
    move-result v1

    .line 131
    invoke-virtual {p1}, Ll2/t;->L()Ljava/lang/Object;

    .line 132
    .line 133
    .line 134
    move-result-object v2

    .line 135
    if-nez v1, :cond_4

    .line 136
    .line 137
    sget-object v1, Ll2/n;->a:Ll2/x0;

    .line 138
    .line 139
    if-ne v2, v1, :cond_5

    .line 140
    .line 141
    :cond_4
    new-instance v5, Ld90/n;

    .line 142
    .line 143
    const/4 v11, 0x0

    .line 144
    const/16 v12, 0x1c

    .line 145
    .line 146
    const/4 v6, 0x0

    .line 147
    const-class v8, Le20/b;

    .line 148
    .line 149
    const-string v9, "onOpenDrivingScore"

    .line 150
    .line 151
    const-string v10, "onOpenDrivingScore()V"

    .line 152
    .line 153
    invoke-direct/range {v5 .. v12}, Ld90/n;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 154
    .line 155
    .line 156
    invoke-virtual {p1, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 157
    .line 158
    .line 159
    move-object v2, v5

    .line 160
    :cond_5
    check-cast v2, Lhy0/g;

    .line 161
    .line 162
    check-cast v2, Lay0/a;

    .line 163
    .line 164
    and-int/lit8 v0, v0, 0xe

    .line 165
    .line 166
    invoke-static {p0, v2, p1, v0, v3}, Lf20/a;->b(Lx2/s;Lay0/a;Ll2/o;II)V

    .line 167
    .line 168
    .line 169
    goto :goto_4

    .line 170
    :cond_6
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 171
    .line 172
    const-string p1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 173
    .line 174
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 175
    .line 176
    .line 177
    throw p0

    .line 178
    :cond_7
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 179
    .line 180
    .line 181
    :goto_4
    invoke-virtual {p1}, Ll2/t;->s()Ll2/u1;

    .line 182
    .line 183
    .line 184
    move-result-object p1

    .line 185
    if-eqz p1, :cond_8

    .line 186
    .line 187
    new-instance v0, Ld00/b;

    .line 188
    .line 189
    const/16 v1, 0x9

    .line 190
    .line 191
    invoke-direct {v0, p0, p2, v1}, Ld00/b;-><init>(Lx2/s;II)V

    .line 192
    .line 193
    .line 194
    goto :goto_3

    .line 195
    :cond_8
    return-void
.end method

.method public static final b(Lx2/s;Lay0/a;Ll2/o;II)V
    .locals 12

    .line 1
    move-object v9, p2

    .line 2
    check-cast v9, Ll2/t;

    .line 3
    .line 4
    const v0, 0x3cf44ea3

    .line 5
    .line 6
    .line 7
    invoke-virtual {v9, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 8
    .line 9
    .line 10
    and-int/lit8 v0, p4, 0x1

    .line 11
    .line 12
    if-eqz v0, :cond_0

    .line 13
    .line 14
    or-int/lit8 v1, p3, 0x6

    .line 15
    .line 16
    goto :goto_1

    .line 17
    :cond_0
    and-int/lit8 v1, p3, 0x6

    .line 18
    .line 19
    if-nez v1, :cond_2

    .line 20
    .line 21
    invoke-virtual {v9, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    move-result v1

    .line 25
    if-eqz v1, :cond_1

    .line 26
    .line 27
    const/4 v1, 0x4

    .line 28
    goto :goto_0

    .line 29
    :cond_1
    const/4 v1, 0x2

    .line 30
    :goto_0
    or-int/2addr v1, p3

    .line 31
    goto :goto_1

    .line 32
    :cond_2
    move v1, p3

    .line 33
    :goto_1
    and-int/lit8 v2, p4, 0x2

    .line 34
    .line 35
    if-eqz v2, :cond_3

    .line 36
    .line 37
    or-int/lit8 v1, v1, 0x30

    .line 38
    .line 39
    goto :goto_3

    .line 40
    :cond_3
    and-int/lit8 v3, p3, 0x30

    .line 41
    .line 42
    if-nez v3, :cond_5

    .line 43
    .line 44
    invoke-virtual {v9, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 45
    .line 46
    .line 47
    move-result v3

    .line 48
    if-eqz v3, :cond_4

    .line 49
    .line 50
    const/16 v3, 0x20

    .line 51
    .line 52
    goto :goto_2

    .line 53
    :cond_4
    const/16 v3, 0x10

    .line 54
    .line 55
    :goto_2
    or-int/2addr v1, v3

    .line 56
    :cond_5
    :goto_3
    and-int/lit8 v3, v1, 0x13

    .line 57
    .line 58
    const/16 v4, 0x12

    .line 59
    .line 60
    if-eq v3, v4, :cond_6

    .line 61
    .line 62
    const/4 v3, 0x1

    .line 63
    goto :goto_4

    .line 64
    :cond_6
    const/4 v3, 0x0

    .line 65
    :goto_4
    and-int/lit8 v4, v1, 0x1

    .line 66
    .line 67
    invoke-virtual {v9, v4, v3}, Ll2/t;->O(IZ)Z

    .line 68
    .line 69
    .line 70
    move-result v3

    .line 71
    if-eqz v3, :cond_a

    .line 72
    .line 73
    if-eqz v0, :cond_7

    .line 74
    .line 75
    sget-object p0, Lx2/p;->b:Lx2/p;

    .line 76
    .line 77
    :cond_7
    if-eqz v2, :cond_9

    .line 78
    .line 79
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 80
    .line 81
    .line 82
    move-result-object p1

    .line 83
    sget-object v0, Ll2/n;->a:Ll2/x0;

    .line 84
    .line 85
    if-ne p1, v0, :cond_8

    .line 86
    .line 87
    new-instance p1, Lz81/g;

    .line 88
    .line 89
    const/4 v0, 0x2

    .line 90
    invoke-direct {p1, v0}, Lz81/g;-><init>(I)V

    .line 91
    .line 92
    .line 93
    invoke-virtual {v9, p1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 94
    .line 95
    .line 96
    :cond_8
    check-cast p1, Lay0/a;

    .line 97
    .line 98
    :cond_9
    move-object v7, p1

    .line 99
    const p1, 0x7f1204c7

    .line 100
    .line 101
    .line 102
    invoke-static {v9, p1}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 103
    .line 104
    .line 105
    move-result-object v0

    .line 106
    const v2, 0x7f1204c6

    .line 107
    .line 108
    .line 109
    invoke-static {v9, v2}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 110
    .line 111
    .line 112
    move-result-object v2

    .line 113
    invoke-static {p0, p1}, Lxf0/i0;->H(Lx2/s;I)Lx2/s;

    .line 114
    .line 115
    .line 116
    move-result-object v3

    .line 117
    shl-int/lit8 p1, v1, 0xf

    .line 118
    .line 119
    const/high16 v1, 0x380000

    .line 120
    .line 121
    and-int v10, p1, v1

    .line 122
    .line 123
    const/16 v11, 0xb0

    .line 124
    .line 125
    move-object v1, v2

    .line 126
    const v2, 0x7f0803d3

    .line 127
    .line 128
    .line 129
    const/4 v4, 0x0

    .line 130
    const-wide/16 v5, 0x0

    .line 131
    .line 132
    const/4 v8, 0x0

    .line 133
    invoke-static/range {v0 .. v11}, Lxf0/r0;->b(Ljava/lang/String;Ljava/lang/String;ILx2/s;ZJLay0/a;ZLl2/o;II)V

    .line 134
    .line 135
    .line 136
    move-object v2, v7

    .line 137
    :goto_5
    move-object v1, p0

    .line 138
    goto :goto_6

    .line 139
    :cond_a
    invoke-virtual {v9}, Ll2/t;->R()V

    .line 140
    .line 141
    .line 142
    move-object v2, p1

    .line 143
    goto :goto_5

    .line 144
    :goto_6
    invoke-virtual {v9}, Ll2/t;->s()Ll2/u1;

    .line 145
    .line 146
    .line 147
    move-result-object p0

    .line 148
    if-eqz p0, :cond_b

    .line 149
    .line 150
    new-instance v0, Lf20/b;

    .line 151
    .line 152
    const/4 v5, 0x0

    .line 153
    move v3, p3

    .line 154
    move/from16 v4, p4

    .line 155
    .line 156
    invoke-direct/range {v0 .. v5}, Lf20/b;-><init>(Lx2/s;Lay0/a;III)V

    .line 157
    .line 158
    .line 159
    iput-object v0, p0, Ll2/u1;->d:Lay0/n;

    .line 160
    .line 161
    :cond_b
    return-void
.end method

.method public static final c(Ll2/o;I)V
    .locals 4

    .line 1
    check-cast p0, Ll2/t;

    .line 2
    .line 3
    const v0, -0x11d84384

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
    sget-object v2, Lf20/a;->a:Lt2/b;

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
    new-instance v0, Lew/g;

    .line 42
    .line 43
    const/4 v1, 0x3

    .line 44
    invoke-direct {v0, p1, v1}, Lew/g;-><init>(II)V

    .line 45
    .line 46
    .line 47
    iput-object v0, p0, Ll2/u1;->d:Lay0/n;

    .line 48
    .line 49
    :cond_2
    return-void
.end method

.method public static final d(Lf20/k;Ll2/o;I)V
    .locals 29

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v9, p1

    .line 4
    .line 5
    check-cast v9, Ll2/t;

    .line 6
    .line 7
    const v2, 0x1c07adf9

    .line 8
    .line 9
    .line 10
    invoke-virtual {v9, v2}, Ll2/t;->a0(I)Ll2/t;

    .line 11
    .line 12
    .line 13
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 14
    .line 15
    .line 16
    move-result v2

    .line 17
    invoke-virtual {v9, v2}, Ll2/t;->e(I)Z

    .line 18
    .line 19
    .line 20
    move-result v2

    .line 21
    const/4 v3, 0x2

    .line 22
    if-eqz v2, :cond_0

    .line 23
    .line 24
    const/4 v2, 0x4

    .line 25
    goto :goto_0

    .line 26
    :cond_0
    move v2, v3

    .line 27
    :goto_0
    or-int v2, p2, v2

    .line 28
    .line 29
    and-int/lit8 v4, v2, 0x3

    .line 30
    .line 31
    const/4 v12, 0x1

    .line 32
    const/4 v5, 0x0

    .line 33
    if-eq v4, v3, :cond_1

    .line 34
    .line 35
    move v3, v12

    .line 36
    goto :goto_1

    .line 37
    :cond_1
    move v3, v5

    .line 38
    :goto_1
    and-int/2addr v2, v12

    .line 39
    invoke-virtual {v9, v2, v3}, Ll2/t;->O(IZ)Z

    .line 40
    .line 41
    .line 42
    move-result v2

    .line 43
    if-eqz v2, :cond_5

    .line 44
    .line 45
    sget-object v2, Lk1/j;->c:Lk1/e;

    .line 46
    .line 47
    sget-object v3, Lx2/c;->p:Lx2/h;

    .line 48
    .line 49
    invoke-static {v2, v3, v9, v5}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 50
    .line 51
    .line 52
    move-result-object v2

    .line 53
    iget-wide v3, v9, Ll2/t;->T:J

    .line 54
    .line 55
    invoke-static {v3, v4}, Ljava/lang/Long;->hashCode(J)I

    .line 56
    .line 57
    .line 58
    move-result v3

    .line 59
    invoke-virtual {v9}, Ll2/t;->m()Ll2/p1;

    .line 60
    .line 61
    .line 62
    move-result-object v4

    .line 63
    sget-object v13, Lx2/p;->b:Lx2/p;

    .line 64
    .line 65
    invoke-static {v9, v13}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 66
    .line 67
    .line 68
    move-result-object v6

    .line 69
    sget-object v7, Lv3/k;->m1:Lv3/j;

    .line 70
    .line 71
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 72
    .line 73
    .line 74
    sget-object v7, Lv3/j;->b:Lv3/i;

    .line 75
    .line 76
    invoke-virtual {v9}, Ll2/t;->c0()V

    .line 77
    .line 78
    .line 79
    iget-boolean v8, v9, Ll2/t;->S:Z

    .line 80
    .line 81
    if-eqz v8, :cond_2

    .line 82
    .line 83
    invoke-virtual {v9, v7}, Ll2/t;->l(Lay0/a;)V

    .line 84
    .line 85
    .line 86
    goto :goto_2

    .line 87
    :cond_2
    invoke-virtual {v9}, Ll2/t;->m0()V

    .line 88
    .line 89
    .line 90
    :goto_2
    sget-object v7, Lv3/j;->g:Lv3/h;

    .line 91
    .line 92
    invoke-static {v7, v2, v9}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 93
    .line 94
    .line 95
    sget-object v2, Lv3/j;->f:Lv3/h;

    .line 96
    .line 97
    invoke-static {v2, v4, v9}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 98
    .line 99
    .line 100
    sget-object v2, Lv3/j;->j:Lv3/h;

    .line 101
    .line 102
    iget-boolean v4, v9, Ll2/t;->S:Z

    .line 103
    .line 104
    if-nez v4, :cond_3

    .line 105
    .line 106
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 107
    .line 108
    .line 109
    move-result-object v4

    .line 110
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 111
    .line 112
    .line 113
    move-result-object v7

    .line 114
    invoke-static {v4, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 115
    .line 116
    .line 117
    move-result v4

    .line 118
    if-nez v4, :cond_4

    .line 119
    .line 120
    :cond_3
    invoke-static {v3, v9, v3, v2}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 121
    .line 122
    .line 123
    :cond_4
    sget-object v2, Lv3/j;->d:Lv3/h;

    .line 124
    .line 125
    invoke-static {v2, v6, v9}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 126
    .line 127
    .line 128
    const/high16 v2, 0x3f800000    # 1.0f

    .line 129
    .line 130
    invoke-static {v13, v2}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 131
    .line 132
    .line 133
    move-result-object v4

    .line 134
    iget v2, v0, Lf20/k;->d:I

    .line 135
    .line 136
    invoke-static {v2, v5, v9}, Ljp/fa;->b(IILl2/o;)Li3/c;

    .line 137
    .line 138
    .line 139
    move-result-object v2

    .line 140
    const/16 v10, 0x1b0

    .line 141
    .line 142
    const/16 v11, 0x78

    .line 143
    .line 144
    const/4 v3, 0x0

    .line 145
    const/4 v5, 0x0

    .line 146
    const/4 v6, 0x0

    .line 147
    const/4 v7, 0x0

    .line 148
    const/4 v8, 0x0

    .line 149
    invoke-static/range {v2 .. v11}, Lkp/m;->a(Li3/c;Ljava/lang/String;Lx2/s;Lx2/e;Lt3/k;FLe3/m;Ll2/o;II)V

    .line 150
    .line 151
    .line 152
    sget-object v2, Lj91/a;->a:Ll2/u2;

    .line 153
    .line 154
    invoke-virtual {v9, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 155
    .line 156
    .line 157
    move-result-object v3

    .line 158
    check-cast v3, Lj91/c;

    .line 159
    .line 160
    iget v3, v3, Lj91/c;->c:F

    .line 161
    .line 162
    invoke-static {v13, v3}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 163
    .line 164
    .line 165
    move-result-object v3

    .line 166
    invoke-static {v9, v3}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 167
    .line 168
    .line 169
    iget v3, v0, Lf20/k;->e:I

    .line 170
    .line 171
    invoke-static {v9, v3}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 172
    .line 173
    .line 174
    move-result-object v3

    .line 175
    sget-object v4, Lj91/j;->a:Ll2/u2;

    .line 176
    .line 177
    invoke-virtual {v9, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 178
    .line 179
    .line 180
    move-result-object v5

    .line 181
    check-cast v5, Lj91/f;

    .line 182
    .line 183
    invoke-virtual {v5}, Lj91/f;->l()Lg4/p0;

    .line 184
    .line 185
    .line 186
    move-result-object v5

    .line 187
    const/16 v22, 0x0

    .line 188
    .line 189
    const v23, 0xfffc

    .line 190
    .line 191
    .line 192
    move-object v6, v4

    .line 193
    const/4 v4, 0x0

    .line 194
    move-object v8, v2

    .line 195
    move-object v2, v3

    .line 196
    move-object v3, v5

    .line 197
    move-object v7, v6

    .line 198
    const-wide/16 v5, 0x0

    .line 199
    .line 200
    move-object v11, v7

    .line 201
    move-object v10, v8

    .line 202
    const-wide/16 v7, 0x0

    .line 203
    .line 204
    move-object/from16 v20, v9

    .line 205
    .line 206
    const/4 v9, 0x0

    .line 207
    move-object v14, v10

    .line 208
    move-object v15, v11

    .line 209
    const-wide/16 v10, 0x0

    .line 210
    .line 211
    move/from16 v16, v12

    .line 212
    .line 213
    const/4 v12, 0x0

    .line 214
    move-object/from16 v17, v13

    .line 215
    .line 216
    const/4 v13, 0x0

    .line 217
    move-object/from16 v18, v14

    .line 218
    .line 219
    move-object/from16 v19, v15

    .line 220
    .line 221
    const-wide/16 v14, 0x0

    .line 222
    .line 223
    move/from16 v21, v16

    .line 224
    .line 225
    const/16 v16, 0x0

    .line 226
    .line 227
    move-object/from16 v24, v17

    .line 228
    .line 229
    const/16 v17, 0x0

    .line 230
    .line 231
    move-object/from16 v25, v18

    .line 232
    .line 233
    const/16 v18, 0x0

    .line 234
    .line 235
    move-object/from16 v26, v19

    .line 236
    .line 237
    const/16 v19, 0x0

    .line 238
    .line 239
    move/from16 v27, v21

    .line 240
    .line 241
    const/16 v21, 0x0

    .line 242
    .line 243
    move-object/from16 v0, v24

    .line 244
    .line 245
    move-object/from16 v1, v25

    .line 246
    .line 247
    move-object/from16 v28, v26

    .line 248
    .line 249
    invoke-static/range {v2 .. v23}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 250
    .line 251
    .line 252
    move-object/from16 v9, v20

    .line 253
    .line 254
    invoke-virtual {v9, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 255
    .line 256
    .line 257
    move-result-object v1

    .line 258
    check-cast v1, Lj91/c;

    .line 259
    .line 260
    iget v1, v1, Lj91/c;->b:F

    .line 261
    .line 262
    invoke-static {v0, v1}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 263
    .line 264
    .line 265
    move-result-object v0

    .line 266
    invoke-static {v9, v0}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 267
    .line 268
    .line 269
    move-object/from16 v0, p0

    .line 270
    .line 271
    iget v1, v0, Lf20/k;->f:I

    .line 272
    .line 273
    invoke-static {v9, v1}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 274
    .line 275
    .line 276
    move-result-object v2

    .line 277
    move-object/from16 v15, v28

    .line 278
    .line 279
    invoke-virtual {v9, v15}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 280
    .line 281
    .line 282
    move-result-object v1

    .line 283
    check-cast v1, Lj91/f;

    .line 284
    .line 285
    invoke-virtual {v1}, Lj91/f;->b()Lg4/p0;

    .line 286
    .line 287
    .line 288
    move-result-object v3

    .line 289
    const/4 v9, 0x0

    .line 290
    const-wide/16 v14, 0x0

    .line 291
    .line 292
    invoke-static/range {v2 .. v23}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 293
    .line 294
    .line 295
    move-object/from16 v9, v20

    .line 296
    .line 297
    const/4 v1, 0x1

    .line 298
    invoke-virtual {v9, v1}, Ll2/t;->q(Z)V

    .line 299
    .line 300
    .line 301
    goto :goto_3

    .line 302
    :cond_5
    invoke-virtual {v9}, Ll2/t;->R()V

    .line 303
    .line 304
    .line 305
    :goto_3
    invoke-virtual {v9}, Ll2/t;->s()Ll2/u1;

    .line 306
    .line 307
    .line 308
    move-result-object v1

    .line 309
    if-eqz v1, :cond_6

    .line 310
    .line 311
    new-instance v2, La71/a0;

    .line 312
    .line 313
    const/16 v3, 0x14

    .line 314
    .line 315
    move/from16 v4, p2

    .line 316
    .line 317
    invoke-direct {v2, v0, v4, v3}, La71/a0;-><init>(Ljava/lang/Object;II)V

    .line 318
    .line 319
    .line 320
    iput-object v2, v1, Ll2/u1;->d:Lay0/n;

    .line 321
    .line 322
    :cond_6
    return-void
.end method

.method public static final e(Ll2/o;I)V
    .locals 16

    .line 1
    move/from16 v0, p1

    .line 2
    .line 3
    move-object/from16 v4, p0

    .line 4
    .line 5
    check-cast v4, Ll2/t;

    .line 6
    .line 7
    const v1, 0x7c90bf46

    .line 8
    .line 9
    .line 10
    invoke-virtual {v4, v1}, Ll2/t;->a0(I)Ll2/t;

    .line 11
    .line 12
    .line 13
    const/4 v1, 0x1

    .line 14
    const/4 v7, 0x0

    .line 15
    if-eqz v0, :cond_0

    .line 16
    .line 17
    move v2, v1

    .line 18
    goto :goto_0

    .line 19
    :cond_0
    move v2, v7

    .line 20
    :goto_0
    and-int/lit8 v3, v0, 0x1

    .line 21
    .line 22
    invoke-virtual {v4, v3, v2}, Ll2/t;->O(IZ)Z

    .line 23
    .line 24
    .line 25
    move-result v2

    .line 26
    if-eqz v2, :cond_c

    .line 27
    .line 28
    const v2, -0x6040e0aa

    .line 29
    .line 30
    .line 31
    invoke-virtual {v4, v2}, Ll2/t;->Y(I)V

    .line 32
    .line 33
    .line 34
    invoke-static {v4}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 35
    .line 36
    .line 37
    move-result-object v2

    .line 38
    if-eqz v2, :cond_b

    .line 39
    .line 40
    invoke-static {v2}, Ljp/ib;->a(Landroidx/lifecycle/i1;)Lp7/c;

    .line 41
    .line 42
    .line 43
    move-result-object v11

    .line 44
    invoke-static {v4}, Lw11/c;->b(Ll2/o;)Lk21/a;

    .line 45
    .line 46
    .line 47
    move-result-object v13

    .line 48
    const-class v3, Le20/d;

    .line 49
    .line 50
    sget-object v5, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 51
    .line 52
    invoke-virtual {v5, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 53
    .line 54
    .line 55
    move-result-object v8

    .line 56
    invoke-interface {v2}, Landroidx/lifecycle/i1;->getViewModelStore()Landroidx/lifecycle/h1;

    .line 57
    .line 58
    .line 59
    move-result-object v9

    .line 60
    const/4 v10, 0x0

    .line 61
    const/4 v12, 0x0

    .line 62
    const/4 v14, 0x0

    .line 63
    invoke-static/range {v8 .. v14}, Ljp/lb;->a(Lhy0/d;Landroidx/lifecycle/h1;Ljava/lang/String;Lp7/c;Lh21/b;Lk21/a;Lay0/a;)Landroidx/lifecycle/b1;

    .line 64
    .line 65
    .line 66
    move-result-object v2

    .line 67
    invoke-virtual {v4, v7}, Ll2/t;->q(Z)V

    .line 68
    .line 69
    .line 70
    check-cast v2, Lql0/j;

    .line 71
    .line 72
    invoke-static {v2, v4, v7, v1}, Lkp/x5;->b(Lql0/j;Ll2/o;II)V

    .line 73
    .line 74
    .line 75
    move-object v10, v2

    .line 76
    check-cast v10, Le20/d;

    .line 77
    .line 78
    iget-object v2, v10, Lql0/j;->g:Lyy0/l1;

    .line 79
    .line 80
    const/4 v3, 0x0

    .line 81
    invoke-static {v2, v3, v4, v1}, Ll2/b;->f(Lyy0/a2;Lwy0/c;Ll2/o;I)Ll2/b1;

    .line 82
    .line 83
    .line 84
    move-result-object v1

    .line 85
    invoke-interface {v1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 86
    .line 87
    .line 88
    move-result-object v2

    .line 89
    check-cast v2, Le20/c;

    .line 90
    .line 91
    iget-boolean v2, v2, Le20/c;->b:Z

    .line 92
    .line 93
    const v3, -0x2fbac1c4

    .line 94
    .line 95
    .line 96
    sget-object v5, Ll2/n;->a:Ll2/x0;

    .line 97
    .line 98
    if-eqz v2, :cond_5

    .line 99
    .line 100
    const v2, -0x2f9a0d39

    .line 101
    .line 102
    .line 103
    invoke-virtual {v4, v2}, Ll2/t;->Y(I)V

    .line 104
    .line 105
    .line 106
    invoke-interface {v1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 107
    .line 108
    .line 109
    move-result-object v2

    .line 110
    check-cast v2, Le20/c;

    .line 111
    .line 112
    iget-object v2, v2, Le20/c;->c:Ljava/util/List;

    .line 113
    .line 114
    invoke-virtual {v4, v10}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 115
    .line 116
    .line 117
    move-result v6

    .line 118
    invoke-virtual {v4}, Ll2/t;->L()Ljava/lang/Object;

    .line 119
    .line 120
    .line 121
    move-result-object v8

    .line 122
    if-nez v6, :cond_1

    .line 123
    .line 124
    if-ne v8, v5, :cond_2

    .line 125
    .line 126
    :cond_1
    new-instance v8, Lf20/h;

    .line 127
    .line 128
    const/4 v14, 0x0

    .line 129
    const/4 v15, 0x5

    .line 130
    const/4 v9, 0x0

    .line 131
    const-class v11, Le20/d;

    .line 132
    .line 133
    const-string v12, "onDismissPicker"

    .line 134
    .line 135
    const-string v13, "onDismissPicker()V"

    .line 136
    .line 137
    invoke-direct/range {v8 .. v15}, Lf20/h;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 138
    .line 139
    .line 140
    invoke-virtual {v4, v8}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 141
    .line 142
    .line 143
    :cond_2
    check-cast v8, Lhy0/g;

    .line 144
    .line 145
    move-object v6, v8

    .line 146
    check-cast v6, Lay0/a;

    .line 147
    .line 148
    invoke-virtual {v4, v10}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 149
    .line 150
    .line 151
    move-result v8

    .line 152
    invoke-virtual {v4}, Ll2/t;->L()Ljava/lang/Object;

    .line 153
    .line 154
    .line 155
    move-result-object v9

    .line 156
    if-nez v8, :cond_3

    .line 157
    .line 158
    if-ne v9, v5, :cond_4

    .line 159
    .line 160
    :cond_3
    new-instance v8, Lei/a;

    .line 161
    .line 162
    const/4 v14, 0x0

    .line 163
    const/4 v15, 0x4

    .line 164
    const/4 v9, 0x1

    .line 165
    const-class v11, Le20/d;

    .line 166
    .line 167
    const-string v12, "onInsuranceCompanySelected"

    .line 168
    .line 169
    const-string v13, "onInsuranceCompanySelected(Ljava/lang/String;)V"

    .line 170
    .line 171
    invoke-direct/range {v8 .. v15}, Lei/a;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 172
    .line 173
    .line 174
    invoke-virtual {v4, v8}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 175
    .line 176
    .line 177
    move-object v9, v8

    .line 178
    :cond_4
    check-cast v9, Lhy0/g;

    .line 179
    .line 180
    check-cast v9, Lay0/k;

    .line 181
    .line 182
    invoke-static {v7, v6, v9, v2, v4}, Lf20/a;->g(ILay0/a;Lay0/k;Ljava/util/List;Ll2/o;)V

    .line 183
    .line 184
    .line 185
    :goto_1
    invoke-virtual {v4, v7}, Ll2/t;->q(Z)V

    .line 186
    .line 187
    .line 188
    goto :goto_2

    .line 189
    :cond_5
    invoke-virtual {v4, v3}, Ll2/t;->Y(I)V

    .line 190
    .line 191
    .line 192
    goto :goto_1

    .line 193
    :goto_2
    invoke-interface {v1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 194
    .line 195
    .line 196
    move-result-object v2

    .line 197
    check-cast v2, Le20/c;

    .line 198
    .line 199
    invoke-virtual {v4, v10}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 200
    .line 201
    .line 202
    move-result v6

    .line 203
    invoke-virtual {v4}, Ll2/t;->L()Ljava/lang/Object;

    .line 204
    .line 205
    .line 206
    move-result-object v8

    .line 207
    if-nez v6, :cond_6

    .line 208
    .line 209
    if-ne v8, v5, :cond_7

    .line 210
    .line 211
    :cond_6
    new-instance v8, Lf20/h;

    .line 212
    .line 213
    const/4 v14, 0x0

    .line 214
    const/4 v15, 0x6

    .line 215
    const/4 v9, 0x0

    .line 216
    const-class v11, Le20/d;

    .line 217
    .line 218
    const-string v12, "onBack"

    .line 219
    .line 220
    const-string v13, "onBack()V"

    .line 221
    .line 222
    invoke-direct/range {v8 .. v15}, Lf20/h;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 223
    .line 224
    .line 225
    invoke-virtual {v4, v8}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 226
    .line 227
    .line 228
    :cond_7
    check-cast v8, Lhy0/g;

    .line 229
    .line 230
    move-object v6, v8

    .line 231
    check-cast v6, Lay0/a;

    .line 232
    .line 233
    invoke-virtual {v4, v10}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 234
    .line 235
    .line 236
    move-result v8

    .line 237
    invoke-virtual {v4}, Ll2/t;->L()Ljava/lang/Object;

    .line 238
    .line 239
    .line 240
    move-result-object v9

    .line 241
    if-nez v8, :cond_8

    .line 242
    .line 243
    if-ne v9, v5, :cond_9

    .line 244
    .line 245
    :cond_8
    new-instance v8, Lf20/h;

    .line 246
    .line 247
    const/4 v14, 0x0

    .line 248
    const/4 v15, 0x7

    .line 249
    const/4 v9, 0x0

    .line 250
    const-class v11, Le20/d;

    .line 251
    .line 252
    const-string v12, "onGetInsurance"

    .line 253
    .line 254
    const-string v13, "onGetInsurance()V"

    .line 255
    .line 256
    invoke-direct/range {v8 .. v15}, Lf20/h;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 257
    .line 258
    .line 259
    invoke-virtual {v4, v8}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 260
    .line 261
    .line 262
    move-object v9, v8

    .line 263
    :cond_9
    check-cast v9, Lhy0/g;

    .line 264
    .line 265
    check-cast v9, Lay0/a;

    .line 266
    .line 267
    invoke-static {v2, v6, v9, v4, v7}, Lf20/a;->f(Le20/c;Lay0/a;Lay0/a;Ll2/o;I)V

    .line 268
    .line 269
    .line 270
    invoke-interface {v1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 271
    .line 272
    .line 273
    move-result-object v1

    .line 274
    check-cast v1, Le20/c;

    .line 275
    .line 276
    iget-boolean v1, v1, Le20/c;->a:Z

    .line 277
    .line 278
    if-eqz v1, :cond_a

    .line 279
    .line 280
    const v1, -0x2f93cf83

    .line 281
    .line 282
    .line 283
    invoke-virtual {v4, v1}, Ll2/t;->Y(I)V

    .line 284
    .line 285
    .line 286
    const/4 v5, 0x0

    .line 287
    const/4 v6, 0x7

    .line 288
    const/4 v1, 0x0

    .line 289
    const/4 v2, 0x0

    .line 290
    const/4 v3, 0x0

    .line 291
    invoke-static/range {v1 .. v6}, Lxf0/y1;->b(Lx2/s;Ljava/lang/String;Lay0/a;Ll2/o;II)V

    .line 292
    .line 293
    .line 294
    :goto_3
    invoke-virtual {v4, v7}, Ll2/t;->q(Z)V

    .line 295
    .line 296
    .line 297
    goto :goto_4

    .line 298
    :cond_a
    invoke-virtual {v4, v3}, Ll2/t;->Y(I)V

    .line 299
    .line 300
    .line 301
    goto :goto_3

    .line 302
    :cond_b
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 303
    .line 304
    const-string v1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 305
    .line 306
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 307
    .line 308
    .line 309
    throw v0

    .line 310
    :cond_c
    invoke-virtual {v4}, Ll2/t;->R()V

    .line 311
    .line 312
    .line 313
    :goto_4
    invoke-virtual {v4}, Ll2/t;->s()Ll2/u1;

    .line 314
    .line 315
    .line 316
    move-result-object v1

    .line 317
    if-eqz v1, :cond_d

    .line 318
    .line 319
    new-instance v2, Lew/g;

    .line 320
    .line 321
    const/4 v3, 0x6

    .line 322
    invoke-direct {v2, v0, v3}, Lew/g;-><init>(II)V

    .line 323
    .line 324
    .line 325
    iput-object v2, v1, Ll2/u1;->d:Lay0/n;

    .line 326
    .line 327
    :cond_d
    return-void
.end method

.method public static final f(Le20/c;Lay0/a;Lay0/a;Ll2/o;I)V
    .locals 21

    .line 1
    move-object/from16 v3, p0

    .line 2
    .line 3
    move-object/from16 v4, p1

    .line 4
    .line 5
    move-object/from16 v5, p2

    .line 6
    .line 7
    move-object/from16 v0, p3

    .line 8
    .line 9
    check-cast v0, Ll2/t;

    .line 10
    .line 11
    const v1, -0xff91ead

    .line 12
    .line 13
    .line 14
    invoke-virtual {v0, v1}, Ll2/t;->a0(I)Ll2/t;

    .line 15
    .line 16
    .line 17
    invoke-virtual {v0, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

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
    or-int v1, p4, v1

    .line 27
    .line 28
    invoke-virtual {v0, v4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result v2

    .line 32
    if-eqz v2, :cond_1

    .line 33
    .line 34
    const/16 v2, 0x20

    .line 35
    .line 36
    goto :goto_1

    .line 37
    :cond_1
    const/16 v2, 0x10

    .line 38
    .line 39
    :goto_1
    or-int/2addr v1, v2

    .line 40
    invoke-virtual {v0, v5}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 41
    .line 42
    .line 43
    move-result v2

    .line 44
    if-eqz v2, :cond_2

    .line 45
    .line 46
    const/16 v2, 0x100

    .line 47
    .line 48
    goto :goto_2

    .line 49
    :cond_2
    const/16 v2, 0x80

    .line 50
    .line 51
    :goto_2
    or-int/2addr v1, v2

    .line 52
    and-int/lit16 v2, v1, 0x93

    .line 53
    .line 54
    const/16 v6, 0x92

    .line 55
    .line 56
    const/4 v7, 0x1

    .line 57
    if-eq v2, v6, :cond_3

    .line 58
    .line 59
    move v2, v7

    .line 60
    goto :goto_3

    .line 61
    :cond_3
    const/4 v2, 0x0

    .line 62
    :goto_3
    and-int/2addr v1, v7

    .line 63
    invoke-virtual {v0, v1, v2}, Ll2/t;->O(IZ)Z

    .line 64
    .line 65
    .line 66
    move-result v1

    .line 67
    if-eqz v1, :cond_4

    .line 68
    .line 69
    sget-object v1, Lj91/h;->a:Ll2/u2;

    .line 70
    .line 71
    invoke-virtual {v0, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    move-result-object v1

    .line 75
    check-cast v1, Lj91/e;

    .line 76
    .line 77
    invoke-virtual {v1}, Lj91/e;->b()J

    .line 78
    .line 79
    .line 80
    move-result-wide v1

    .line 81
    sget-object v6, Le3/j0;->a:Le3/i0;

    .line 82
    .line 83
    sget-object v7, Lx2/p;->b:Lx2/p;

    .line 84
    .line 85
    invoke-static {v7, v1, v2, v6}, Landroidx/compose/foundation/a;->b(Lx2/s;JLe3/n0;)Lx2/s;

    .line 86
    .line 87
    .line 88
    move-result-object v6

    .line 89
    new-instance v1, Lb60/d;

    .line 90
    .line 91
    const/16 v2, 0x12

    .line 92
    .line 93
    invoke-direct {v1, v4, v2}, Lb60/d;-><init>(Lay0/a;I)V

    .line 94
    .line 95
    .line 96
    const v2, -0x25e8d1e9

    .line 97
    .line 98
    .line 99
    invoke-static {v2, v0, v1}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 100
    .line 101
    .line 102
    move-result-object v7

    .line 103
    new-instance v1, Ld90/m;

    .line 104
    .line 105
    const/16 v2, 0xd

    .line 106
    .line 107
    invoke-direct {v1, v2, v3, v5}, Ld90/m;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 108
    .line 109
    .line 110
    const v2, 0x3edda18

    .line 111
    .line 112
    .line 113
    invoke-static {v2, v0, v1}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 114
    .line 115
    .line 116
    move-result-object v8

    .line 117
    const v19, 0x300001b0

    .line 118
    .line 119
    .line 120
    const/16 v20, 0x1f8

    .line 121
    .line 122
    const/4 v9, 0x0

    .line 123
    const/4 v10, 0x0

    .line 124
    const/4 v11, 0x0

    .line 125
    const-wide/16 v12, 0x0

    .line 126
    .line 127
    const-wide/16 v14, 0x0

    .line 128
    .line 129
    const/16 v16, 0x0

    .line 130
    .line 131
    sget-object v17, Lf20/a;->b:Lt2/b;

    .line 132
    .line 133
    move-object/from16 v18, v0

    .line 134
    .line 135
    invoke-static/range {v6 .. v20}, Lh2/c8;->a(Lx2/s;Lay0/n;Lay0/n;Lay0/n;Lay0/n;IJJLk1/q1;Lay0/o;Ll2/o;II)V

    .line 136
    .line 137
    .line 138
    goto :goto_4

    .line 139
    :cond_4
    move-object/from16 v18, v0

    .line 140
    .line 141
    invoke-virtual/range {v18 .. v18}, Ll2/t;->R()V

    .line 142
    .line 143
    .line 144
    :goto_4
    invoke-virtual/range {v18 .. v18}, Ll2/t;->s()Ll2/u1;

    .line 145
    .line 146
    .line 147
    move-result-object v6

    .line 148
    if-eqz v6, :cond_5

    .line 149
    .line 150
    new-instance v0, Lf20/f;

    .line 151
    .line 152
    const/4 v2, 0x2

    .line 153
    move/from16 v1, p4

    .line 154
    .line 155
    invoke-direct/range {v0 .. v5}, Lf20/f;-><init>(IILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 156
    .line 157
    .line 158
    iput-object v0, v6, Ll2/u1;->d:Lay0/n;

    .line 159
    .line 160
    :cond_5
    return-void
.end method

.method public static final g(ILay0/a;Lay0/k;Ljava/util/List;Ll2/o;)V
    .locals 12

    .line 1
    const-string v0, "insuranceCompanies"

    .line 2
    .line 3
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    move-object/from16 v10, p4

    .line 7
    .line 8
    check-cast v10, Ll2/t;

    .line 9
    .line 10
    const v0, 0x1b676d2f

    .line 11
    .line 12
    .line 13
    invoke-virtual {v10, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 14
    .line 15
    .line 16
    invoke-virtual {v10, p3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 17
    .line 18
    .line 19
    move-result v0

    .line 20
    if-eqz v0, :cond_0

    .line 21
    .line 22
    const/4 v0, 0x4

    .line 23
    goto :goto_0

    .line 24
    :cond_0
    const/4 v0, 0x2

    .line 25
    :goto_0
    or-int/2addr v0, p0

    .line 26
    invoke-virtual {v10, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 27
    .line 28
    .line 29
    move-result v1

    .line 30
    if-eqz v1, :cond_1

    .line 31
    .line 32
    const/16 v1, 0x20

    .line 33
    .line 34
    goto :goto_1

    .line 35
    :cond_1
    const/16 v1, 0x10

    .line 36
    .line 37
    :goto_1
    or-int/2addr v0, v1

    .line 38
    invoke-virtual {v10, p2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 39
    .line 40
    .line 41
    move-result v1

    .line 42
    if-eqz v1, :cond_2

    .line 43
    .line 44
    const/16 v1, 0x100

    .line 45
    .line 46
    goto :goto_2

    .line 47
    :cond_2
    const/16 v1, 0x80

    .line 48
    .line 49
    :goto_2
    or-int/2addr v0, v1

    .line 50
    and-int/lit16 v1, v0, 0x93

    .line 51
    .line 52
    const/16 v2, 0x92

    .line 53
    .line 54
    if-eq v1, v2, :cond_3

    .line 55
    .line 56
    const/4 v1, 0x1

    .line 57
    goto :goto_3

    .line 58
    :cond_3
    const/4 v1, 0x0

    .line 59
    :goto_3
    and-int/lit8 v2, v0, 0x1

    .line 60
    .line 61
    invoke-virtual {v10, v2, v1}, Ll2/t;->O(IZ)Z

    .line 62
    .line 63
    .line 64
    move-result v1

    .line 65
    if-eqz v1, :cond_5

    .line 66
    .line 67
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 68
    .line 69
    .line 70
    move-result-object v1

    .line 71
    sget-object v2, Ll2/n;->a:Ll2/x0;

    .line 72
    .line 73
    if-ne v1, v2, :cond_4

    .line 74
    .line 75
    invoke-static {v10}, Ll2/l0;->h(Ll2/o;)Lvy0/b0;

    .line 76
    .line 77
    .line 78
    move-result-object v1

    .line 79
    invoke-virtual {v10, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 80
    .line 81
    .line 82
    :cond_4
    check-cast v1, Lvy0/b0;

    .line 83
    .line 84
    new-instance v2, La71/a1;

    .line 85
    .line 86
    const/16 v6, 0x11

    .line 87
    .line 88
    invoke-direct {v2, p3, v1, p2, v6}, La71/a1;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 89
    .line 90
    .line 91
    const v1, -0x4c6539cd

    .line 92
    .line 93
    .line 94
    invoke-static {v1, v10, v2}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 95
    .line 96
    .line 97
    move-result-object v9

    .line 98
    shr-int/lit8 v0, v0, 0x3

    .line 99
    .line 100
    and-int/lit8 v0, v0, 0xe

    .line 101
    .line 102
    or-int/lit16 v11, v0, 0xc00

    .line 103
    .line 104
    const/4 v7, 0x0

    .line 105
    const/4 v8, 0x0

    .line 106
    move-object v6, p1

    .line 107
    invoke-static/range {v6 .. v11}, Lxf0/y1;->h(Lay0/a;ZZLt2/b;Ll2/o;I)V

    .line 108
    .line 109
    .line 110
    goto :goto_4

    .line 111
    :cond_5
    invoke-virtual {v10}, Ll2/t;->R()V

    .line 112
    .line 113
    .line 114
    :goto_4
    invoke-virtual {v10}, Ll2/t;->s()Ll2/u1;

    .line 115
    .line 116
    .line 117
    move-result-object v6

    .line 118
    if-eqz v6, :cond_6

    .line 119
    .line 120
    new-instance v0, Lf20/f;

    .line 121
    .line 122
    const/4 v2, 0x3

    .line 123
    move v1, p0

    .line 124
    move-object v4, p1

    .line 125
    move-object v5, p2

    .line 126
    move-object v3, p3

    .line 127
    invoke-direct/range {v0 .. v5}, Lf20/f;-><init>(IILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 128
    .line 129
    .line 130
    iput-object v0, v6, Ll2/u1;->d:Lay0/n;

    .line 131
    .line 132
    :cond_6
    return-void
.end method
