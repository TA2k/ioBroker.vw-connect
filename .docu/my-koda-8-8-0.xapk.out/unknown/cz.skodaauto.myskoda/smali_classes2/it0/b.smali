.class public abstract Lit0/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lt2/b;

.field public static final b:Lt2/b;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Li91/i0;

    .line 2
    .line 3
    const/16 v1, 0x10

    .line 4
    .line 5
    invoke-direct {v0, v1}, Li91/i0;-><init>(I)V

    .line 6
    .line 7
    .line 8
    new-instance v1, Lt2/b;

    .line 9
    .line 10
    const/4 v2, 0x0

    .line 11
    const v3, -0x192a173e

    .line 12
    .line 13
    .line 14
    invoke-direct {v1, v0, v2, v3}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 15
    .line 16
    .line 17
    sput-object v1, Lit0/b;->a:Lt2/b;

    .line 18
    .line 19
    new-instance v0, Li91/i0;

    .line 20
    .line 21
    const/16 v1, 0x11

    .line 22
    .line 23
    invoke-direct {v0, v1}, Li91/i0;-><init>(I)V

    .line 24
    .line 25
    .line 26
    new-instance v1, Lt2/b;

    .line 27
    .line 28
    const v3, 0x14b670c7

    .line 29
    .line 30
    .line 31
    invoke-direct {v1, v0, v2, v3}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 32
    .line 33
    .line 34
    sput-object v1, Lit0/b;->b:Lt2/b;

    .line 35
    .line 36
    return-void
.end method

.method public static final a(ZZLay0/a;Ll2/o;I)V
    .locals 7

    .line 1
    const-string v0, "onClick"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    check-cast p3, Ll2/t;

    .line 7
    .line 8
    const v0, -0x207d5093

    .line 9
    .line 10
    .line 11
    invoke-virtual {p3, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 12
    .line 13
    .line 14
    and-int/lit8 v0, p4, 0x6

    .line 15
    .line 16
    if-nez v0, :cond_1

    .line 17
    .line 18
    invoke-virtual {p3, p0}, Ll2/t;->h(Z)Z

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    if-eqz v0, :cond_0

    .line 23
    .line 24
    const/4 v0, 0x4

    .line 25
    goto :goto_0

    .line 26
    :cond_0
    const/4 v0, 0x2

    .line 27
    :goto_0
    or-int/2addr v0, p4

    .line 28
    goto :goto_1

    .line 29
    :cond_1
    move v0, p4

    .line 30
    :goto_1
    and-int/lit8 v1, p4, 0x30

    .line 31
    .line 32
    if-nez v1, :cond_3

    .line 33
    .line 34
    invoke-virtual {p3, p1}, Ll2/t;->h(Z)Z

    .line 35
    .line 36
    .line 37
    move-result v1

    .line 38
    if-eqz v1, :cond_2

    .line 39
    .line 40
    const/16 v1, 0x20

    .line 41
    .line 42
    goto :goto_2

    .line 43
    :cond_2
    const/16 v1, 0x10

    .line 44
    .line 45
    :goto_2
    or-int/2addr v0, v1

    .line 46
    :cond_3
    and-int/lit16 v1, p4, 0x180

    .line 47
    .line 48
    if-nez v1, :cond_5

    .line 49
    .line 50
    invoke-virtual {p3, p2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 51
    .line 52
    .line 53
    move-result v1

    .line 54
    if-eqz v1, :cond_4

    .line 55
    .line 56
    const/16 v1, 0x100

    .line 57
    .line 58
    goto :goto_3

    .line 59
    :cond_4
    const/16 v1, 0x80

    .line 60
    .line 61
    :goto_3
    or-int/2addr v0, v1

    .line 62
    :cond_5
    and-int/lit16 v1, v0, 0x93

    .line 63
    .line 64
    const/16 v2, 0x92

    .line 65
    .line 66
    const/4 v3, 0x0

    .line 67
    if-eq v1, v2, :cond_6

    .line 68
    .line 69
    const/4 v1, 0x1

    .line 70
    goto :goto_4

    .line 71
    :cond_6
    move v1, v3

    .line 72
    :goto_4
    and-int/lit8 v2, v0, 0x1

    .line 73
    .line 74
    invoke-virtual {p3, v2, v1}, Ll2/t;->O(IZ)Z

    .line 75
    .line 76
    .line 77
    move-result v1

    .line 78
    if-eqz v1, :cond_9

    .line 79
    .line 80
    invoke-static {p3}, Lxf0/y1;->F(Ll2/o;)Z

    .line 81
    .line 82
    .line 83
    move-result v1

    .line 84
    if-eqz v1, :cond_7

    .line 85
    .line 86
    const v0, 0x28fe8857

    .line 87
    .line 88
    .line 89
    invoke-virtual {p3, v0}, Ll2/t;->Y(I)V

    .line 90
    .line 91
    .line 92
    invoke-static {p3, v3}, Lit0/b;->b(Ll2/o;I)V

    .line 93
    .line 94
    .line 95
    invoke-virtual {p3, v3}, Ll2/t;->q(Z)V

    .line 96
    .line 97
    .line 98
    invoke-virtual {p3}, Ll2/t;->s()Ll2/u1;

    .line 99
    .line 100
    .line 101
    move-result-object p3

    .line 102
    if-eqz p3, :cond_a

    .line 103
    .line 104
    new-instance v0, Lit0/a;

    .line 105
    .line 106
    const/4 v2, 0x0

    .line 107
    move v4, p0

    .line 108
    move v5, p1

    .line 109
    move-object v3, p2

    .line 110
    move v1, p4

    .line 111
    invoke-direct/range {v0 .. v5}, Lit0/a;-><init>(IILay0/a;ZZ)V

    .line 112
    .line 113
    .line 114
    iput-object v0, p3, Ll2/u1;->d:Lay0/n;

    .line 115
    .line 116
    return-void

    .line 117
    :cond_7
    move v4, p0

    .line 118
    move v5, p1

    .line 119
    move-object p0, p2

    .line 120
    move v1, p4

    .line 121
    const p1, 0x28e0ce15

    .line 122
    .line 123
    .line 124
    invoke-virtual {p3, p1}, Ll2/t;->Y(I)V

    .line 125
    .line 126
    .line 127
    invoke-virtual {p3, v3}, Ll2/t;->q(Z)V

    .line 128
    .line 129
    .line 130
    if-eqz v4, :cond_8

    .line 131
    .line 132
    const p1, 0x28ffca92

    .line 133
    .line 134
    .line 135
    invoke-virtual {p3, p1}, Ll2/t;->Y(I)V

    .line 136
    .line 137
    .line 138
    shr-int/lit8 p1, v0, 0x3

    .line 139
    .line 140
    and-int/lit8 p1, p1, 0x7e

    .line 141
    .line 142
    invoke-static {v5, p0, p3, p1}, Lit0/b;->d(ZLay0/a;Ll2/o;I)V

    .line 143
    .line 144
    .line 145
    invoke-virtual {p3, v3}, Ll2/t;->q(Z)V

    .line 146
    .line 147
    .line 148
    goto :goto_5

    .line 149
    :cond_8
    const p1, 0x2901d7a2

    .line 150
    .line 151
    .line 152
    invoke-virtual {p3, p1}, Ll2/t;->Y(I)V

    .line 153
    .line 154
    .line 155
    shr-int/lit8 p1, v0, 0x6

    .line 156
    .line 157
    and-int/lit8 p1, p1, 0xe

    .line 158
    .line 159
    invoke-static {p0, p3, p1}, Lit0/b;->c(Lay0/a;Ll2/o;I)V

    .line 160
    .line 161
    .line 162
    invoke-virtual {p3, v3}, Ll2/t;->q(Z)V

    .line 163
    .line 164
    .line 165
    goto :goto_5

    .line 166
    :cond_9
    move v4, p0

    .line 167
    move v5, p1

    .line 168
    move-object p0, p2

    .line 169
    move v1, p4

    .line 170
    invoke-virtual {p3}, Ll2/t;->R()V

    .line 171
    .line 172
    .line 173
    :goto_5
    invoke-virtual {p3}, Ll2/t;->s()Ll2/u1;

    .line 174
    .line 175
    .line 176
    move-result-object p1

    .line 177
    if-eqz p1, :cond_a

    .line 178
    .line 179
    move v2, v1

    .line 180
    new-instance v1, Lit0/a;

    .line 181
    .line 182
    const/4 v3, 0x1

    .line 183
    move v6, v5

    .line 184
    move v5, v4

    .line 185
    move-object v4, p0

    .line 186
    invoke-direct/range {v1 .. v6}, Lit0/a;-><init>(IILay0/a;ZZ)V

    .line 187
    .line 188
    .line 189
    iput-object v1, p1, Ll2/u1;->d:Lay0/n;

    .line 190
    .line 191
    :cond_a
    return-void
.end method

.method public static final b(Ll2/o;I)V
    .locals 4

    .line 1
    check-cast p0, Ll2/t;

    .line 2
    .line 3
    const v0, 0x73690318

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
    sget-object v2, Lit0/b;->b:Lt2/b;

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
    new-instance v0, Li91/i0;

    .line 42
    .line 43
    const/16 v1, 0xf

    .line 44
    .line 45
    invoke-direct {v0, p1, v1}, Li91/i0;-><init>(II)V

    .line 46
    .line 47
    .line 48
    iput-object v0, p0, Ll2/u1;->d:Lay0/n;

    .line 49
    .line 50
    :cond_2
    return-void
.end method

.method public static final c(Lay0/a;Ll2/o;I)V
    .locals 12

    .line 1
    move-object v4, p1

    .line 2
    check-cast v4, Ll2/t;

    .line 3
    .line 4
    const p1, 0x567a1457

    .line 5
    .line 6
    .line 7
    invoke-virtual {v4, p1}, Ll2/t;->a0(I)Ll2/t;

    .line 8
    .line 9
    .line 10
    and-int/lit8 p1, p2, 0x6

    .line 11
    .line 12
    const/4 v0, 0x2

    .line 13
    const/4 v1, 0x4

    .line 14
    if-nez p1, :cond_1

    .line 15
    .line 16
    invoke-virtual {v4, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 17
    .line 18
    .line 19
    move-result p1

    .line 20
    if-eqz p1, :cond_0

    .line 21
    .line 22
    move p1, v1

    .line 23
    goto :goto_0

    .line 24
    :cond_0
    move p1, v0

    .line 25
    :goto_0
    or-int/2addr p1, p2

    .line 26
    goto :goto_1

    .line 27
    :cond_1
    move p1, p2

    .line 28
    :goto_1
    and-int/lit8 v2, p1, 0x3

    .line 29
    .line 30
    const/4 v3, 0x0

    .line 31
    const/4 v5, 0x1

    .line 32
    if-eq v2, v0, :cond_2

    .line 33
    .line 34
    move v0, v5

    .line 35
    goto :goto_2

    .line 36
    :cond_2
    move v0, v3

    .line 37
    :goto_2
    and-int/lit8 v2, p1, 0x1

    .line 38
    .line 39
    invoke-virtual {v4, v2, v0}, Ll2/t;->O(IZ)Z

    .line 40
    .line 41
    .line 42
    move-result v0

    .line 43
    if-eqz v0, :cond_6

    .line 44
    .line 45
    sget-object v0, Lx2/p;->b:Lx2/p;

    .line 46
    .line 47
    const/high16 v2, 0x3f800000    # 1.0f

    .line 48
    .line 49
    invoke-static {v0, v2}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 50
    .line 51
    .line 52
    move-result-object v6

    .line 53
    and-int/lit8 p1, p1, 0xe

    .line 54
    .line 55
    if-ne p1, v1, :cond_3

    .line 56
    .line 57
    move v3, v5

    .line 58
    :cond_3
    invoke-virtual {v4}, Ll2/t;->L()Ljava/lang/Object;

    .line 59
    .line 60
    .line 61
    move-result-object p1

    .line 62
    if-nez v3, :cond_4

    .line 63
    .line 64
    sget-object v0, Ll2/n;->a:Ll2/x0;

    .line 65
    .line 66
    if-ne p1, v0, :cond_5

    .line 67
    .line 68
    :cond_4
    new-instance p1, Lha0/f;

    .line 69
    .line 70
    const/4 v0, 0x6

    .line 71
    invoke-direct {p1, p0, v0}, Lha0/f;-><init>(Lay0/a;I)V

    .line 72
    .line 73
    .line 74
    invoke-virtual {v4, p1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 75
    .line 76
    .line 77
    :cond_5
    move-object v10, p1

    .line 78
    check-cast v10, Lay0/a;

    .line 79
    .line 80
    const/16 v11, 0xf

    .line 81
    .line 82
    const/4 v7, 0x0

    .line 83
    const/4 v8, 0x0

    .line 84
    const/4 v9, 0x0

    .line 85
    invoke-static/range {v6 .. v11}, Landroidx/compose/foundation/a;->f(Lx2/s;ZLjava/lang/String;Ld4/i;Lay0/a;I)Lx2/s;

    .line 86
    .line 87
    .line 88
    move-result-object p1

    .line 89
    const-string v0, "garage_car_configurator_card"

    .line 90
    .line 91
    invoke-static {p1, v0}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 92
    .line 93
    .line 94
    move-result-object v0

    .line 95
    const/16 v5, 0xc00

    .line 96
    .line 97
    const/4 v6, 0x6

    .line 98
    const/4 v1, 0x0

    .line 99
    const/4 v2, 0x0

    .line 100
    sget-object v3, Lit0/b;->a:Lt2/b;

    .line 101
    .line 102
    invoke-static/range {v0 .. v6}, Li91/d0;->a(Lx2/s;Lay0/a;ZLay0/n;Ll2/o;II)V

    .line 103
    .line 104
    .line 105
    goto :goto_3

    .line 106
    :cond_6
    invoke-virtual {v4}, Ll2/t;->R()V

    .line 107
    .line 108
    .line 109
    :goto_3
    invoke-virtual {v4}, Ll2/t;->s()Ll2/u1;

    .line 110
    .line 111
    .line 112
    move-result-object p1

    .line 113
    if-eqz p1, :cond_7

    .line 114
    .line 115
    new-instance v0, Lcz/s;

    .line 116
    .line 117
    const/16 v1, 0xd

    .line 118
    .line 119
    invoke-direct {v0, p0, p2, v1}, Lcz/s;-><init>(Lay0/a;II)V

    .line 120
    .line 121
    .line 122
    iput-object v0, p1, Ll2/u1;->d:Lay0/n;

    .line 123
    .line 124
    :cond_7
    return-void
.end method

.method public static final d(ZLay0/a;Ll2/o;I)V
    .locals 18

    .line 1
    move/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move/from16 v2, p3

    .line 6
    .line 7
    move-object/from16 v7, p2

    .line 8
    .line 9
    check-cast v7, Ll2/t;

    .line 10
    .line 11
    const v3, 0x548d2ae4

    .line 12
    .line 13
    .line 14
    invoke-virtual {v7, v3}, Ll2/t;->a0(I)Ll2/t;

    .line 15
    .line 16
    .line 17
    and-int/lit8 v3, v2, 0x6

    .line 18
    .line 19
    if-nez v3, :cond_1

    .line 20
    .line 21
    invoke-virtual {v7, v0}, Ll2/t;->h(Z)Z

    .line 22
    .line 23
    .line 24
    move-result v3

    .line 25
    if-eqz v3, :cond_0

    .line 26
    .line 27
    const/4 v3, 0x4

    .line 28
    goto :goto_0

    .line 29
    :cond_0
    const/4 v3, 0x2

    .line 30
    :goto_0
    or-int/2addr v3, v2

    .line 31
    goto :goto_1

    .line 32
    :cond_1
    move v3, v2

    .line 33
    :goto_1
    and-int/lit8 v4, v2, 0x30

    .line 34
    .line 35
    const/16 v5, 0x20

    .line 36
    .line 37
    if-nez v4, :cond_3

    .line 38
    .line 39
    invoke-virtual {v7, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    move-result v4

    .line 43
    if-eqz v4, :cond_2

    .line 44
    .line 45
    move v4, v5

    .line 46
    goto :goto_2

    .line 47
    :cond_2
    const/16 v4, 0x10

    .line 48
    .line 49
    :goto_2
    or-int/2addr v3, v4

    .line 50
    :cond_3
    and-int/lit8 v4, v3, 0x13

    .line 51
    .line 52
    const/16 v6, 0x12

    .line 53
    .line 54
    const/4 v8, 0x0

    .line 55
    const/4 v9, 0x1

    .line 56
    if-eq v4, v6, :cond_4

    .line 57
    .line 58
    move v4, v9

    .line 59
    goto :goto_3

    .line 60
    :cond_4
    move v4, v8

    .line 61
    :goto_3
    and-int/lit8 v6, v3, 0x1

    .line 62
    .line 63
    invoke-virtual {v7, v6, v4}, Ll2/t;->O(IZ)Z

    .line 64
    .line 65
    .line 66
    move-result v4

    .line 67
    if-eqz v4, :cond_8

    .line 68
    .line 69
    new-instance v4, Lym/n;

    .line 70
    .line 71
    const/high16 v6, 0x7f110000

    .line 72
    .line 73
    invoke-direct {v4, v6}, Lym/n;-><init>(I)V

    .line 74
    .line 75
    .line 76
    invoke-static {v4, v7}, Lcom/google/android/gms/internal/measurement/c4;->d(Lym/n;Ll2/o;)Lym/m;

    .line 77
    .line 78
    .line 79
    move-result-object v4

    .line 80
    invoke-virtual {v4}, Lym/m;->getValue()Ljava/lang/Object;

    .line 81
    .line 82
    .line 83
    move-result-object v6

    .line 84
    check-cast v6, Lum/a;

    .line 85
    .line 86
    const v10, 0x7fffffff

    .line 87
    .line 88
    .line 89
    const/16 v11, 0x3be

    .line 90
    .line 91
    invoke-static {v6, v8, v10, v7, v11}, Lc21/c;->a(Lum/a;ZILl2/o;I)Lym/g;

    .line 92
    .line 93
    .line 94
    move-result-object v6

    .line 95
    sget-object v10, Lx2/p;->b:Lx2/p;

    .line 96
    .line 97
    const/high16 v11, 0x3f800000    # 1.0f

    .line 98
    .line 99
    invoke-static {v10, v11}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 100
    .line 101
    .line 102
    move-result-object v10

    .line 103
    const-string v11, "garage_car_configurator_card"

    .line 104
    .line 105
    invoke-static {v10, v11}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 106
    .line 107
    .line 108
    move-result-object v12

    .line 109
    and-int/lit8 v3, v3, 0x70

    .line 110
    .line 111
    if-ne v3, v5, :cond_5

    .line 112
    .line 113
    move v8, v9

    .line 114
    :cond_5
    invoke-virtual {v7}, Ll2/t;->L()Ljava/lang/Object;

    .line 115
    .line 116
    .line 117
    move-result-object v3

    .line 118
    if-nez v8, :cond_6

    .line 119
    .line 120
    sget-object v5, Ll2/n;->a:Ll2/x0;

    .line 121
    .line 122
    if-ne v3, v5, :cond_7

    .line 123
    .line 124
    :cond_6
    new-instance v3, Lha0/f;

    .line 125
    .line 126
    const/4 v5, 0x7

    .line 127
    invoke-direct {v3, v1, v5}, Lha0/f;-><init>(Lay0/a;I)V

    .line 128
    .line 129
    .line 130
    invoke-virtual {v7, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 131
    .line 132
    .line 133
    :cond_7
    move-object/from16 v16, v3

    .line 134
    .line 135
    check-cast v16, Lay0/a;

    .line 136
    .line 137
    const/16 v17, 0xf

    .line 138
    .line 139
    const/4 v13, 0x0

    .line 140
    const/4 v14, 0x0

    .line 141
    const/4 v15, 0x0

    .line 142
    invoke-static/range {v12 .. v17}, Landroidx/compose/foundation/a;->f(Lx2/s;ZLjava/lang/String;Ld4/i;Lay0/a;I)Lx2/s;

    .line 143
    .line 144
    .line 145
    move-result-object v3

    .line 146
    new-instance v5, Lb71/l;

    .line 147
    .line 148
    invoke-direct {v5, v6, v0, v1, v4}, Lb71/l;-><init>(Lym/g;ZLay0/a;Lym/m;)V

    .line 149
    .line 150
    .line 151
    const v4, -0x190de127

    .line 152
    .line 153
    .line 154
    invoke-static {v4, v7, v5}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 155
    .line 156
    .line 157
    move-result-object v6

    .line 158
    const/16 v8, 0xc00

    .line 159
    .line 160
    const/4 v9, 0x6

    .line 161
    const/4 v4, 0x0

    .line 162
    const/4 v5, 0x0

    .line 163
    invoke-static/range {v3 .. v9}, Li91/d0;->a(Lx2/s;Lay0/a;ZLay0/n;Ll2/o;II)V

    .line 164
    .line 165
    .line 166
    goto :goto_4

    .line 167
    :cond_8
    invoke-virtual {v7}, Ll2/t;->R()V

    .line 168
    .line 169
    .line 170
    :goto_4
    invoke-virtual {v7}, Ll2/t;->s()Ll2/u1;

    .line 171
    .line 172
    .line 173
    move-result-object v3

    .line 174
    if-eqz v3, :cond_9

    .line 175
    .line 176
    new-instance v4, Li2/r;

    .line 177
    .line 178
    const/4 v5, 0x2

    .line 179
    invoke-direct {v4, v0, v1, v2, v5}, Li2/r;-><init>(ZLay0/a;II)V

    .line 180
    .line 181
    .line 182
    iput-object v4, v3, Ll2/u1;->d:Lay0/n;

    .line 183
    .line 184
    :cond_9
    return-void
.end method
