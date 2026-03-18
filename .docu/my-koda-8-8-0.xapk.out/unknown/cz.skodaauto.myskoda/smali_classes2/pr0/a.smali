.class public abstract Lpr0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lt2/b;

.field public static final b:Lt2/b;

.field public static final c:Lt2/b;


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lpd0/a;

    .line 2
    .line 3
    const/16 v1, 0xb

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lpd0/a;-><init>(I)V

    .line 6
    .line 7
    .line 8
    new-instance v1, Lt2/b;

    .line 9
    .line 10
    const/4 v2, 0x0

    .line 11
    const v3, -0x72768cbb

    .line 12
    .line 13
    .line 14
    invoke-direct {v1, v0, v2, v3}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 15
    .line 16
    .line 17
    sput-object v1, Lpr0/a;->a:Lt2/b;

    .line 18
    .line 19
    new-instance v0, Lpd0/a;

    .line 20
    .line 21
    const/16 v1, 0xc

    .line 22
    .line 23
    invoke-direct {v0, v1}, Lpd0/a;-><init>(I)V

    .line 24
    .line 25
    .line 26
    new-instance v1, Lt2/b;

    .line 27
    .line 28
    const v3, -0x6b9dfd76

    .line 29
    .line 30
    .line 31
    invoke-direct {v1, v0, v2, v3}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 32
    .line 33
    .line 34
    sput-object v1, Lpr0/a;->b:Lt2/b;

    .line 35
    .line 36
    new-instance v0, Lpd0/a;

    .line 37
    .line 38
    const/16 v1, 0xd

    .line 39
    .line 40
    invoke-direct {v0, v1}, Lpd0/a;-><init>(I)V

    .line 41
    .line 42
    .line 43
    new-instance v1, Lt2/b;

    .line 44
    .line 45
    const v3, 0x580be317

    .line 46
    .line 47
    .line 48
    invoke-direct {v1, v0, v2, v3}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 49
    .line 50
    .line 51
    sput-object v1, Lpr0/a;->c:Lt2/b;

    .line 52
    .line 53
    return-void
.end method

.method public static final a(Lx2/s;Ll2/o;I)V
    .locals 13

    .line 1
    check-cast p1, Ll2/t;

    .line 2
    .line 3
    const v0, 0x7996df93

    .line 4
    .line 5
    .line 6
    invoke-virtual {p1, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    or-int/lit8 v0, p2, 0x6

    .line 10
    .line 11
    and-int/lit8 v1, v0, 0x3

    .line 12
    .line 13
    const/4 v2, 0x2

    .line 14
    const/4 v3, 0x0

    .line 15
    const/4 v4, 0x1

    .line 16
    if-eq v1, v2, :cond_0

    .line 17
    .line 18
    move v1, v4

    .line 19
    goto :goto_0

    .line 20
    :cond_0
    move v1, v3

    .line 21
    :goto_0
    and-int/2addr v0, v4

    .line 22
    invoke-virtual {p1, v0, v1}, Ll2/t;->O(IZ)Z

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    if-eqz v0, :cond_5

    .line 27
    .line 28
    invoke-static {p1}, Lxf0/y1;->F(Ll2/o;)Z

    .line 29
    .line 30
    .line 31
    move-result p0

    .line 32
    if-eqz p0, :cond_1

    .line 33
    .line 34
    const p0, 0x7c4cfb73

    .line 35
    .line 36
    .line 37
    invoke-virtual {p1, p0}, Ll2/t;->Y(I)V

    .line 38
    .line 39
    .line 40
    invoke-static {p1, v3}, Lpr0/a;->c(Ll2/o;I)V

    .line 41
    .line 42
    .line 43
    invoke-virtual {p1, v3}, Ll2/t;->q(Z)V

    .line 44
    .line 45
    .line 46
    invoke-virtual {p1}, Ll2/t;->s()Ll2/u1;

    .line 47
    .line 48
    .line 49
    move-result-object p0

    .line 50
    if-eqz p0, :cond_6

    .line 51
    .line 52
    new-instance p1, Lpd0/a;

    .line 53
    .line 54
    const/16 v0, 0xf

    .line 55
    .line 56
    invoke-direct {p1, p2, v0}, Lpd0/a;-><init>(II)V

    .line 57
    .line 58
    .line 59
    iput-object p1, p0, Ll2/u1;->d:Lay0/n;

    .line 60
    .line 61
    return-void

    .line 62
    :cond_1
    const p0, 0x7c33d78f

    .line 63
    .line 64
    .line 65
    const v0, -0x6040e0aa

    .line 66
    .line 67
    .line 68
    invoke-static {p0, v0, p1, p1, v3}, Lvj/b;->c(IILl2/t;Ll2/t;Z)Landroidx/lifecycle/i1;

    .line 69
    .line 70
    .line 71
    move-result-object p0

    .line 72
    if-eqz p0, :cond_4

    .line 73
    .line 74
    invoke-static {p0}, Ljp/ib;->a(Landroidx/lifecycle/i1;)Lp7/c;

    .line 75
    .line 76
    .line 77
    move-result-object v8

    .line 78
    invoke-static {p1}, Lw11/c;->b(Ll2/o;)Lk21/a;

    .line 79
    .line 80
    .line 81
    move-result-object v10

    .line 82
    const-class v0, Lor0/d;

    .line 83
    .line 84
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 85
    .line 86
    invoke-virtual {v1, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 87
    .line 88
    .line 89
    move-result-object v5

    .line 90
    invoke-interface {p0}, Landroidx/lifecycle/i1;->getViewModelStore()Landroidx/lifecycle/h1;

    .line 91
    .line 92
    .line 93
    move-result-object v6

    .line 94
    const/4 v7, 0x0

    .line 95
    const/4 v9, 0x0

    .line 96
    const/4 v11, 0x0

    .line 97
    invoke-static/range {v5 .. v11}, Ljp/lb;->a(Lhy0/d;Landroidx/lifecycle/h1;Ljava/lang/String;Lp7/c;Lh21/b;Lk21/a;Lay0/a;)Landroidx/lifecycle/b1;

    .line 98
    .line 99
    .line 100
    move-result-object p0

    .line 101
    invoke-virtual {p1, v3}, Ll2/t;->q(Z)V

    .line 102
    .line 103
    .line 104
    check-cast p0, Lql0/j;

    .line 105
    .line 106
    invoke-static {p0, p1, v3, v4}, Lkp/x5;->b(Lql0/j;Ll2/o;II)V

    .line 107
    .line 108
    .line 109
    move-object v7, p0

    .line 110
    check-cast v7, Lor0/d;

    .line 111
    .line 112
    invoke-virtual {p1, v7}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 113
    .line 114
    .line 115
    move-result p0

    .line 116
    invoke-virtual {p1}, Ll2/t;->L()Ljava/lang/Object;

    .line 117
    .line 118
    .line 119
    move-result-object v0

    .line 120
    if-nez p0, :cond_2

    .line 121
    .line 122
    sget-object p0, Ll2/n;->a:Ll2/x0;

    .line 123
    .line 124
    if-ne v0, p0, :cond_3

    .line 125
    .line 126
    :cond_2
    new-instance v5, Loz/c;

    .line 127
    .line 128
    const/4 v11, 0x0

    .line 129
    const/4 v12, 0x7

    .line 130
    const/4 v6, 0x0

    .line 131
    const-class v8, Lor0/d;

    .line 132
    .line 133
    const-string v9, "onOpenTestDrive"

    .line 134
    .line 135
    const-string v10, "onOpenTestDrive()V"

    .line 136
    .line 137
    invoke-direct/range {v5 .. v12}, Loz/c;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 138
    .line 139
    .line 140
    invoke-virtual {p1, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 141
    .line 142
    .line 143
    move-object v0, v5

    .line 144
    :cond_3
    check-cast v0, Lhy0/g;

    .line 145
    .line 146
    check-cast v0, Lay0/a;

    .line 147
    .line 148
    sget-object p0, Lx2/p;->b:Lx2/p;

    .line 149
    .line 150
    const/4 v1, 0x6

    .line 151
    invoke-static {p0, v0, p1, v1, v3}, Lpr0/a;->b(Lx2/s;Lay0/a;Ll2/o;II)V

    .line 152
    .line 153
    .line 154
    goto :goto_1

    .line 155
    :cond_4
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 156
    .line 157
    const-string p1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 158
    .line 159
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 160
    .line 161
    .line 162
    throw p0

    .line 163
    :cond_5
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 164
    .line 165
    .line 166
    :goto_1
    invoke-virtual {p1}, Ll2/t;->s()Ll2/u1;

    .line 167
    .line 168
    .line 169
    move-result-object p1

    .line 170
    if-eqz p1, :cond_6

    .line 171
    .line 172
    new-instance v0, Ll30/a;

    .line 173
    .line 174
    const/16 v1, 0x16

    .line 175
    .line 176
    invoke-direct {v0, p0, p2, v1}, Ll30/a;-><init>(Lx2/s;II)V

    .line 177
    .line 178
    .line 179
    iput-object v0, p1, Ll2/u1;->d:Lay0/n;

    .line 180
    .line 181
    :cond_6
    return-void
.end method

.method public static final b(Lx2/s;Lay0/a;Ll2/o;II)V
    .locals 11

    .line 1
    move-object v4, p2

    .line 2
    check-cast v4, Ll2/t;

    .line 3
    .line 4
    const p2, -0x54566321

    .line 5
    .line 6
    .line 7
    invoke-virtual {v4, p2}, Ll2/t;->a0(I)Ll2/t;

    .line 8
    .line 9
    .line 10
    and-int/lit8 p2, p4, 0x1

    .line 11
    .line 12
    if-eqz p2, :cond_0

    .line 13
    .line 14
    or-int/lit8 v0, p3, 0x6

    .line 15
    .line 16
    goto :goto_1

    .line 17
    :cond_0
    and-int/lit8 v0, p3, 0x6

    .line 18
    .line 19
    if-nez v0, :cond_2

    .line 20
    .line 21
    invoke-virtual {v4, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    move-result v0

    .line 25
    if-eqz v0, :cond_1

    .line 26
    .line 27
    const/4 v0, 0x4

    .line 28
    goto :goto_0

    .line 29
    :cond_1
    const/4 v0, 0x2

    .line 30
    :goto_0
    or-int/2addr v0, p3

    .line 31
    goto :goto_1

    .line 32
    :cond_2
    move v0, p3

    .line 33
    :goto_1
    and-int/lit8 v1, p4, 0x2

    .line 34
    .line 35
    if-eqz v1, :cond_3

    .line 36
    .line 37
    or-int/lit8 v0, v0, 0x30

    .line 38
    .line 39
    goto :goto_3

    .line 40
    :cond_3
    and-int/lit8 v2, p3, 0x30

    .line 41
    .line 42
    if-nez v2, :cond_5

    .line 43
    .line 44
    invoke-virtual {v4, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 45
    .line 46
    .line 47
    move-result v2

    .line 48
    if-eqz v2, :cond_4

    .line 49
    .line 50
    const/16 v2, 0x20

    .line 51
    .line 52
    goto :goto_2

    .line 53
    :cond_4
    const/16 v2, 0x10

    .line 54
    .line 55
    :goto_2
    or-int/2addr v0, v2

    .line 56
    :cond_5
    :goto_3
    and-int/lit8 v2, v0, 0x13

    .line 57
    .line 58
    const/16 v3, 0x12

    .line 59
    .line 60
    if-eq v2, v3, :cond_6

    .line 61
    .line 62
    const/4 v2, 0x1

    .line 63
    goto :goto_4

    .line 64
    :cond_6
    const/4 v2, 0x0

    .line 65
    :goto_4
    and-int/lit8 v3, v0, 0x1

    .line 66
    .line 67
    invoke-virtual {v4, v3, v2}, Ll2/t;->O(IZ)Z

    .line 68
    .line 69
    .line 70
    move-result v2

    .line 71
    if-eqz v2, :cond_a

    .line 72
    .line 73
    if-eqz p2, :cond_7

    .line 74
    .line 75
    sget-object p0, Lx2/p;->b:Lx2/p;

    .line 76
    .line 77
    :cond_7
    if-eqz v1, :cond_9

    .line 78
    .line 79
    invoke-virtual {v4}, Ll2/t;->L()Ljava/lang/Object;

    .line 80
    .line 81
    .line 82
    move-result-object p1

    .line 83
    sget-object p2, Ll2/n;->a:Ll2/x0;

    .line 84
    .line 85
    if-ne p1, p2, :cond_8

    .line 86
    .line 87
    new-instance p1, Lz81/g;

    .line 88
    .line 89
    const/4 p2, 0x2

    .line 90
    invoke-direct {p1, p2}, Lz81/g;-><init>(I)V

    .line 91
    .line 92
    .line 93
    invoke-virtual {v4, p1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 94
    .line 95
    .line 96
    :cond_8
    check-cast p1, Lay0/a;

    .line 97
    .line 98
    :cond_9
    move-object v1, p1

    .line 99
    const/high16 p1, 0x3f800000    # 1.0f

    .line 100
    .line 101
    invoke-static {p0, p1}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 102
    .line 103
    .line 104
    move-result-object p1

    .line 105
    const-string p2, "test_drive_compact_card"

    .line 106
    .line 107
    invoke-static {p1, p2}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 108
    .line 109
    .line 110
    move-result-object p1

    .line 111
    invoke-static {p1, p2}, Lxf0/i0;->I(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 112
    .line 113
    .line 114
    move-result-object p1

    .line 115
    and-int/lit8 p2, v0, 0x70

    .line 116
    .line 117
    or-int/lit16 v5, p2, 0xc00

    .line 118
    .line 119
    const/4 v6, 0x4

    .line 120
    const/4 v2, 0x0

    .line 121
    sget-object v3, Lpr0/a;->b:Lt2/b;

    .line 122
    .line 123
    move-object v0, p1

    .line 124
    invoke-static/range {v0 .. v6}, Li91/d0;->a(Lx2/s;Lay0/a;ZLay0/n;Ll2/o;II)V

    .line 125
    .line 126
    .line 127
    move-object v7, v1

    .line 128
    :goto_5
    move-object v6, p0

    .line 129
    goto :goto_6

    .line 130
    :cond_a
    invoke-virtual {v4}, Ll2/t;->R()V

    .line 131
    .line 132
    .line 133
    move-object v7, p1

    .line 134
    goto :goto_5

    .line 135
    :goto_6
    invoke-virtual {v4}, Ll2/t;->s()Ll2/u1;

    .line 136
    .line 137
    .line 138
    move-result-object p0

    .line 139
    if-eqz p0, :cond_b

    .line 140
    .line 141
    new-instance v5, Lf20/b;

    .line 142
    .line 143
    const/4 v10, 0x5

    .line 144
    move v8, p3

    .line 145
    move v9, p4

    .line 146
    invoke-direct/range {v5 .. v10}, Lf20/b;-><init>(Lx2/s;Lay0/a;III)V

    .line 147
    .line 148
    .line 149
    iput-object v5, p0, Ll2/u1;->d:Lay0/n;

    .line 150
    .line 151
    :cond_b
    return-void
.end method

.method public static final c(Ll2/o;I)V
    .locals 3

    .line 1
    check-cast p0, Ll2/t;

    .line 2
    .line 3
    const v0, 0x38abd9e6

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
    sget-object v1, Lpr0/a;->c:Lt2/b;

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
    new-instance v0, Lpd0/a;

    .line 41
    .line 42
    const/16 v1, 0x10

    .line 43
    .line 44
    invoke-direct {v0, p1, v1}, Lpd0/a;-><init>(II)V

    .line 45
    .line 46
    .line 47
    iput-object v0, p0, Ll2/u1;->d:Lay0/n;

    .line 48
    .line 49
    :cond_2
    return-void
.end method
