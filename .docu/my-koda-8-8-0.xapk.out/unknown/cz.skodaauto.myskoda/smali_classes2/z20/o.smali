.class public abstract Lz20/o;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:F

.field public static final b:F


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const/16 v0, 0x5b

    .line 2
    .line 3
    int-to-float v0, v0

    .line 4
    sput v0, Lz20/o;->a:F

    .line 5
    .line 6
    const/16 v0, 0xb1

    .line 7
    .line 8
    int-to-float v0, v0

    .line 9
    sput v0, Lz20/o;->b:F

    .line 10
    .line 11
    return-void
.end method

.method public static final a(Lx2/s;Ll2/o;I)V
    .locals 12

    .line 1
    move-object v3, p1

    .line 2
    check-cast v3, Ll2/t;

    .line 3
    .line 4
    const p1, 0x2957f77d

    .line 5
    .line 6
    .line 7
    invoke-virtual {v3, p1}, Ll2/t;->a0(I)Ll2/t;

    .line 8
    .line 9
    .line 10
    and-int/lit8 p1, p2, 0x3

    .line 11
    .line 12
    const/4 v0, 0x2

    .line 13
    const/4 v1, 0x0

    .line 14
    const/4 v2, 0x1

    .line 15
    if-eq p1, v0, :cond_0

    .line 16
    .line 17
    move p1, v2

    .line 18
    goto :goto_0

    .line 19
    :cond_0
    move p1, v1

    .line 20
    :goto_0
    and-int/lit8 v0, p2, 0x1

    .line 21
    .line 22
    invoke-virtual {v3, v0, p1}, Ll2/t;->O(IZ)Z

    .line 23
    .line 24
    .line 25
    move-result p1

    .line 26
    if-eqz p1, :cond_5

    .line 27
    .line 28
    invoke-static {v3}, Lxf0/y1;->F(Ll2/o;)Z

    .line 29
    .line 30
    .line 31
    move-result p1

    .line 32
    if-eqz p1, :cond_1

    .line 33
    .line 34
    const p1, 0x33cac80a

    .line 35
    .line 36
    .line 37
    invoke-virtual {v3, p1}, Ll2/t;->Y(I)V

    .line 38
    .line 39
    .line 40
    invoke-static {v3, v1}, Lz20/o;->c(Ll2/o;I)V

    .line 41
    .line 42
    .line 43
    invoke-virtual {v3, v1}, Ll2/t;->q(Z)V

    .line 44
    .line 45
    .line 46
    invoke-virtual {v3}, Ll2/t;->s()Ll2/u1;

    .line 47
    .line 48
    .line 49
    move-result-object p1

    .line 50
    if-eqz p1, :cond_6

    .line 51
    .line 52
    new-instance v0, Luz/e;

    .line 53
    .line 54
    const/16 v1, 0xb

    .line 55
    .line 56
    invoke-direct {v0, p0, p2, v1}, Luz/e;-><init>(Lx2/s;II)V

    .line 57
    .line 58
    .line 59
    iput-object v0, p1, Ll2/u1;->d:Lay0/n;

    .line 60
    .line 61
    return-void

    .line 62
    :cond_1
    const p1, 0x33b26225

    .line 63
    .line 64
    .line 65
    const v0, -0x6040e0aa

    .line 66
    .line 67
    .line 68
    invoke-static {p1, v0, v3, v3, v1}, Lvj/b;->c(IILl2/t;Ll2/t;Z)Landroidx/lifecycle/i1;

    .line 69
    .line 70
    .line 71
    move-result-object p1

    .line 72
    if-eqz p1, :cond_4

    .line 73
    .line 74
    invoke-static {p1}, Ljp/ib;->a(Landroidx/lifecycle/i1;)Lp7/c;

    .line 75
    .line 76
    .line 77
    move-result-object v7

    .line 78
    invoke-static {v3}, Lw11/c;->b(Ll2/o;)Lk21/a;

    .line 79
    .line 80
    .line 81
    move-result-object v9

    .line 82
    const-class v0, Ly20/p;

    .line 83
    .line 84
    sget-object v4, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 85
    .line 86
    invoke-virtual {v4, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 87
    .line 88
    .line 89
    move-result-object v4

    .line 90
    invoke-interface {p1}, Landroidx/lifecycle/i1;->getViewModelStore()Landroidx/lifecycle/h1;

    .line 91
    .line 92
    .line 93
    move-result-object v5

    .line 94
    const/4 v6, 0x0

    .line 95
    const/4 v8, 0x0

    .line 96
    const/4 v10, 0x0

    .line 97
    invoke-static/range {v4 .. v10}, Ljp/lb;->a(Lhy0/d;Landroidx/lifecycle/h1;Ljava/lang/String;Lp7/c;Lh21/b;Lk21/a;Lay0/a;)Landroidx/lifecycle/b1;

    .line 98
    .line 99
    .line 100
    move-result-object p1

    .line 101
    invoke-virtual {v3, v1}, Ll2/t;->q(Z)V

    .line 102
    .line 103
    .line 104
    check-cast p1, Lql0/j;

    .line 105
    .line 106
    const/16 v0, 0x30

    .line 107
    .line 108
    invoke-static {p1, v3, v0, v1}, Lkp/x5;->b(Lql0/j;Ll2/o;II)V

    .line 109
    .line 110
    .line 111
    move-object v6, p1

    .line 112
    check-cast v6, Ly20/p;

    .line 113
    .line 114
    iget-object p1, v6, Lql0/j;->g:Lyy0/l1;

    .line 115
    .line 116
    const/4 v0, 0x0

    .line 117
    invoke-static {p1, v0, v3, v2}, Ll2/b;->f(Lyy0/a2;Lwy0/c;Ll2/o;I)Ll2/b1;

    .line 118
    .line 119
    .line 120
    move-result-object p1

    .line 121
    invoke-interface {p1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 122
    .line 123
    .line 124
    move-result-object p1

    .line 125
    move-object v0, p1

    .line 126
    check-cast v0, Ly20/o;

    .line 127
    .line 128
    invoke-virtual {v3, v6}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 129
    .line 130
    .line 131
    move-result p1

    .line 132
    invoke-virtual {v3}, Ll2/t;->L()Ljava/lang/Object;

    .line 133
    .line 134
    .line 135
    move-result-object v1

    .line 136
    if-nez p1, :cond_2

    .line 137
    .line 138
    sget-object p1, Ll2/n;->a:Ll2/x0;

    .line 139
    .line 140
    if-ne v1, p1, :cond_3

    .line 141
    .line 142
    :cond_2
    new-instance v4, Lz20/j;

    .line 143
    .line 144
    const/4 v10, 0x0

    .line 145
    const/16 v11, 0x9

    .line 146
    .line 147
    const/4 v5, 0x0

    .line 148
    const-class v7, Ly20/p;

    .line 149
    .line 150
    const-string v8, "onOpenGarage"

    .line 151
    .line 152
    const-string v9, "onOpenGarage()V"

    .line 153
    .line 154
    invoke-direct/range {v4 .. v11}, Lz20/j;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 155
    .line 156
    .line 157
    invoke-virtual {v3, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 158
    .line 159
    .line 160
    move-object v1, v4

    .line 161
    :cond_3
    check-cast v1, Lhy0/g;

    .line 162
    .line 163
    check-cast v1, Lay0/a;

    .line 164
    .line 165
    const/16 v4, 0x188

    .line 166
    .line 167
    const/4 v5, 0x0

    .line 168
    move-object v2, p0

    .line 169
    invoke-static/range {v0 .. v5}, Lz20/o;->b(Ly20/o;Lay0/a;Lx2/s;Ll2/o;II)V

    .line 170
    .line 171
    .line 172
    goto :goto_1

    .line 173
    :cond_4
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 174
    .line 175
    const-string p1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 176
    .line 177
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 178
    .line 179
    .line 180
    throw p0

    .line 181
    :cond_5
    move-object v2, p0

    .line 182
    invoke-virtual {v3}, Ll2/t;->R()V

    .line 183
    .line 184
    .line 185
    :goto_1
    invoke-virtual {v3}, Ll2/t;->s()Ll2/u1;

    .line 186
    .line 187
    .line 188
    move-result-object p0

    .line 189
    if-eqz p0, :cond_6

    .line 190
    .line 191
    new-instance p1, Luz/e;

    .line 192
    .line 193
    const/16 v0, 0xc

    .line 194
    .line 195
    invoke-direct {p1, v2, p2, v0}, Luz/e;-><init>(Lx2/s;II)V

    .line 196
    .line 197
    .line 198
    iput-object p1, p0, Ll2/u1;->d:Lay0/n;

    .line 199
    .line 200
    :cond_6
    return-void
.end method

.method public static final b(Ly20/o;Lay0/a;Lx2/s;Ll2/o;II)V
    .locals 12

    .line 1
    move/from16 v4, p4

    .line 2
    .line 3
    move-object v9, p3

    .line 4
    check-cast v9, Ll2/t;

    .line 5
    .line 6
    const p3, -0x5d8e0034

    .line 7
    .line 8
    .line 9
    invoke-virtual {v9, p3}, Ll2/t;->a0(I)Ll2/t;

    .line 10
    .line 11
    .line 12
    and-int/lit8 p3, v4, 0x6

    .line 13
    .line 14
    const/4 v0, 0x2

    .line 15
    if-nez p3, :cond_2

    .line 16
    .line 17
    and-int/lit8 p3, v4, 0x8

    .line 18
    .line 19
    if-nez p3, :cond_0

    .line 20
    .line 21
    invoke-virtual {v9, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    move-result p3

    .line 25
    goto :goto_0

    .line 26
    :cond_0
    invoke-virtual {v9, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 27
    .line 28
    .line 29
    move-result p3

    .line 30
    :goto_0
    if-eqz p3, :cond_1

    .line 31
    .line 32
    const/4 p3, 0x4

    .line 33
    goto :goto_1

    .line 34
    :cond_1
    move p3, v0

    .line 35
    :goto_1
    or-int/2addr p3, v4

    .line 36
    goto :goto_2

    .line 37
    :cond_2
    move p3, v4

    .line 38
    :goto_2
    and-int/lit8 v1, v4, 0x30

    .line 39
    .line 40
    if-nez v1, :cond_4

    .line 41
    .line 42
    invoke-virtual {v9, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 43
    .line 44
    .line 45
    move-result v1

    .line 46
    if-eqz v1, :cond_3

    .line 47
    .line 48
    const/16 v1, 0x20

    .line 49
    .line 50
    goto :goto_3

    .line 51
    :cond_3
    const/16 v1, 0x10

    .line 52
    .line 53
    :goto_3
    or-int/2addr p3, v1

    .line 54
    :cond_4
    and-int/lit8 v1, p5, 0x4

    .line 55
    .line 56
    if-eqz v1, :cond_5

    .line 57
    .line 58
    or-int/lit16 p3, p3, 0x180

    .line 59
    .line 60
    goto :goto_5

    .line 61
    :cond_5
    and-int/lit16 v2, v4, 0x180

    .line 62
    .line 63
    if-nez v2, :cond_7

    .line 64
    .line 65
    invoke-virtual {v9, p2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 66
    .line 67
    .line 68
    move-result v2

    .line 69
    if-eqz v2, :cond_6

    .line 70
    .line 71
    const/16 v2, 0x100

    .line 72
    .line 73
    goto :goto_4

    .line 74
    :cond_6
    const/16 v2, 0x80

    .line 75
    .line 76
    :goto_4
    or-int/2addr p3, v2

    .line 77
    :cond_7
    :goto_5
    and-int/lit16 v2, p3, 0x93

    .line 78
    .line 79
    const/16 v3, 0x92

    .line 80
    .line 81
    if-eq v2, v3, :cond_8

    .line 82
    .line 83
    const/4 v2, 0x1

    .line 84
    goto :goto_6

    .line 85
    :cond_8
    const/4 v2, 0x0

    .line 86
    :goto_6
    and-int/lit8 v3, p3, 0x1

    .line 87
    .line 88
    invoke-virtual {v9, v3, v2}, Ll2/t;->O(IZ)Z

    .line 89
    .line 90
    .line 91
    move-result v2

    .line 92
    if-eqz v2, :cond_a

    .line 93
    .line 94
    if-eqz v1, :cond_9

    .line 95
    .line 96
    sget-object p2, Lx2/p;->b:Lx2/p;

    .line 97
    .line 98
    :cond_9
    const/high16 v1, 0x3f800000    # 1.0f

    .line 99
    .line 100
    invoke-static {p2, v1}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 101
    .line 102
    .line 103
    move-result-object v1

    .line 104
    sget-object v2, Lj91/a;->a:Ll2/u2;

    .line 105
    .line 106
    invoke-virtual {v9, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 107
    .line 108
    .line 109
    move-result-object v2

    .line 110
    check-cast v2, Lj91/c;

    .line 111
    .line 112
    iget v2, v2, Lj91/c;->d:F

    .line 113
    .line 114
    const/4 v3, 0x0

    .line 115
    invoke-static {v1, v2, v3, v0}, Landroidx/compose/foundation/layout/a;->o(Lx2/s;FFI)Lx2/s;

    .line 116
    .line 117
    .line 118
    move-result-object v0

    .line 119
    const-string v1, "settings_garage_card"

    .line 120
    .line 121
    invoke-static {v0, v1}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 122
    .line 123
    .line 124
    move-result-object v5

    .line 125
    new-instance v0, Ltj/g;

    .line 126
    .line 127
    const/16 v1, 0x1a

    .line 128
    .line 129
    invoke-direct {v0, p0, v1}, Ltj/g;-><init>(Ljava/lang/Object;I)V

    .line 130
    .line 131
    .line 132
    const v1, -0x2f39b07f

    .line 133
    .line 134
    .line 135
    invoke-static {v1, v9, v0}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 136
    .line 137
    .line 138
    move-result-object v8

    .line 139
    and-int/lit8 p3, p3, 0x70

    .line 140
    .line 141
    or-int/lit16 v10, p3, 0xc00

    .line 142
    .line 143
    const/4 v11, 0x4

    .line 144
    const/4 v7, 0x0

    .line 145
    move-object v6, p1

    .line 146
    invoke-static/range {v5 .. v11}, Li91/d0;->a(Lx2/s;Lay0/a;ZLay0/n;Ll2/o;II)V

    .line 147
    .line 148
    .line 149
    :goto_7
    move-object v3, p2

    .line 150
    goto :goto_8

    .line 151
    :cond_a
    invoke-virtual {v9}, Ll2/t;->R()V

    .line 152
    .line 153
    .line 154
    goto :goto_7

    .line 155
    :goto_8
    invoke-virtual {v9}, Ll2/t;->s()Ll2/u1;

    .line 156
    .line 157
    .line 158
    move-result-object p2

    .line 159
    if-eqz p2, :cond_b

    .line 160
    .line 161
    new-instance v0, Lc71/c;

    .line 162
    .line 163
    const/16 v6, 0x18

    .line 164
    .line 165
    move-object v1, p0

    .line 166
    move-object v2, p1

    .line 167
    move/from16 v5, p5

    .line 168
    .line 169
    invoke-direct/range {v0 .. v6}, Lc71/c;-><init>(Lql0/h;Lay0/a;Lx2/s;III)V

    .line 170
    .line 171
    .line 172
    iput-object v0, p2, Ll2/u1;->d:Lay0/n;

    .line 173
    .line 174
    :cond_b
    return-void
.end method

.method public static final c(Ll2/o;I)V
    .locals 3

    .line 1
    check-cast p0, Ll2/t;

    .line 2
    .line 3
    const v0, -0x4c3c29dc

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    const/4 v0, 0x0

    .line 10
    if-eqz p1, :cond_0

    .line 11
    .line 12
    const/4 v1, 0x1

    .line 13
    goto :goto_0

    .line 14
    :cond_0
    move v1, v0

    .line 15
    :goto_0
    and-int/lit8 v2, p1, 0x1

    .line 16
    .line 17
    invoke-virtual {p0, v2, v1}, Ll2/t;->O(IZ)Z

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-eqz v1, :cond_1

    .line 22
    .line 23
    sget-object v1, Lz20/a;->h:Lt2/b;

    .line 24
    .line 25
    const/16 v2, 0x36

    .line 26
    .line 27
    invoke-static {v0, v1, p0, v2, v0}, Lxf0/y1;->i(ZLay0/n;Ll2/o;II)V

    .line 28
    .line 29
    .line 30
    goto :goto_1

    .line 31
    :cond_1
    invoke-virtual {p0}, Ll2/t;->R()V

    .line 32
    .line 33
    .line 34
    :goto_1
    invoke-virtual {p0}, Ll2/t;->s()Ll2/u1;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    if-eqz p0, :cond_2

    .line 39
    .line 40
    new-instance v0, Lym0/b;

    .line 41
    .line 42
    const/16 v1, 0x18

    .line 43
    .line 44
    invoke-direct {v0, p1, v1}, Lym0/b;-><init>(II)V

    .line 45
    .line 46
    .line 47
    iput-object v0, p0, Ll2/u1;->d:Lay0/n;

    .line 48
    .line 49
    :cond_2
    return-void
.end method
