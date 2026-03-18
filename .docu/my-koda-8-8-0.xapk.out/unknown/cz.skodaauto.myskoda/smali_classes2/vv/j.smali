.class public abstract Lvv/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lg4/p0;

.field public static final b:J

.field public static final c:Lx2/s;

.field public static final d:J


# direct methods
.method static constructor <clinit>()V
    .locals 14

    .line 1
    new-instance v0, Lg4/p0;

    .line 2
    .line 3
    const-wide/16 v11, 0x0

    .line 4
    .line 5
    const v13, 0xffffdf

    .line 6
    .line 7
    .line 8
    const-wide/16 v1, 0x0

    .line 9
    .line 10
    const-wide/16 v3, 0x0

    .line 11
    .line 12
    const/4 v5, 0x0

    .line 13
    const/4 v6, 0x0

    .line 14
    sget-object v7, Lk4/n;->g:Lk4/z;

    .line 15
    .line 16
    const-wide/16 v8, 0x0

    .line 17
    .line 18
    const/4 v10, 0x0

    .line 19
    invoke-direct/range {v0 .. v13}, Lg4/p0;-><init>(JJLk4/x;Lk4/t;Lk4/n;JIJI)V

    .line 20
    .line 21
    .line 22
    sput-object v0, Lvv/j;->a:Lg4/p0;

    .line 23
    .line 24
    sget-wide v0, Le3/s;->d:J

    .line 25
    .line 26
    const/high16 v2, 0x3f000000    # 0.5f

    .line 27
    .line 28
    invoke-static {v0, v1, v2}, Le3/s;->b(JF)J

    .line 29
    .line 30
    .line 31
    move-result-wide v0

    .line 32
    sput-wide v0, Lvv/j;->b:J

    .line 33
    .line 34
    sget-object v2, Lx2/p;->b:Lx2/p;

    .line 35
    .line 36
    sget-object v3, Le3/j0;->a:Le3/i0;

    .line 37
    .line 38
    invoke-static {v2, v0, v1, v3}, Landroidx/compose/foundation/a;->b(Lx2/s;JLe3/n0;)Lx2/s;

    .line 39
    .line 40
    .line 41
    move-result-object v0

    .line 42
    sput-object v0, Lvv/j;->c:Lx2/s;

    .line 43
    .line 44
    const/16 v0, 0x10

    .line 45
    .line 46
    invoke-static {v0}, Lgq/b;->c(I)J

    .line 47
    .line 48
    .line 49
    move-result-wide v0

    .line 50
    sput-wide v0, Lvv/j;->d:J

    .line 51
    .line 52
    return-void
.end method

.method public static final a(Lvv/m0;Ljava/lang/String;Ll2/o;I)V
    .locals 6

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "text"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    check-cast p2, Ll2/t;

    .line 12
    .line 13
    const v0, -0x46860766

    .line 14
    .line 15
    .line 16
    invoke-virtual {p2, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 17
    .line 18
    .line 19
    and-int/lit8 v0, p3, 0xe

    .line 20
    .line 21
    if-nez v0, :cond_1

    .line 22
    .line 23
    invoke-virtual {p2, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    if-eqz v0, :cond_0

    .line 28
    .line 29
    const/4 v0, 0x4

    .line 30
    goto :goto_0

    .line 31
    :cond_0
    const/4 v0, 0x2

    .line 32
    :goto_0
    or-int/2addr v0, p3

    .line 33
    goto :goto_1

    .line 34
    :cond_1
    move v0, p3

    .line 35
    :goto_1
    and-int/lit8 v1, p3, 0x70

    .line 36
    .line 37
    if-nez v1, :cond_3

    .line 38
    .line 39
    invoke-virtual {p2, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    move-result v1

    .line 43
    if-eqz v1, :cond_2

    .line 44
    .line 45
    const/16 v1, 0x20

    .line 46
    .line 47
    goto :goto_2

    .line 48
    :cond_2
    const/16 v1, 0x10

    .line 49
    .line 50
    :goto_2
    or-int/2addr v0, v1

    .line 51
    :cond_3
    or-int/lit16 v0, v0, 0x180

    .line 52
    .line 53
    and-int/lit16 v1, v0, 0x2db

    .line 54
    .line 55
    const/16 v2, 0x92

    .line 56
    .line 57
    if-ne v1, v2, :cond_5

    .line 58
    .line 59
    invoke-virtual {p2}, Ll2/t;->A()Z

    .line 60
    .line 61
    .line 62
    move-result v1

    .line 63
    if-nez v1, :cond_4

    .line 64
    .line 65
    goto :goto_3

    .line 66
    :cond_4
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 67
    .line 68
    .line 69
    goto :goto_4

    .line 70
    :cond_5
    :goto_3
    new-instance v1, Lb1/f;

    .line 71
    .line 72
    const/4 v2, 0x2

    .line 73
    invoke-direct {v1, p1, v2}, Lb1/f;-><init>(Ljava/lang/Object;I)V

    .line 74
    .line 75
    .line 76
    const v2, 0x5cd0ce23

    .line 77
    .line 78
    .line 79
    invoke-static {v2, p2, v1}, Lt2/c;->b(ILl2/o;Llx0/e;)Lt2/b;

    .line 80
    .line 81
    .line 82
    move-result-object v1

    .line 83
    and-int/lit8 v2, v0, 0xe

    .line 84
    .line 85
    or-int/lit16 v2, v2, 0x180

    .line 86
    .line 87
    shr-int/lit8 v0, v0, 0x3

    .line 88
    .line 89
    and-int/lit8 v0, v0, 0x70

    .line 90
    .line 91
    or-int/2addr v0, v2

    .line 92
    invoke-static {p0, v1, p2, v0}, Lvv/j;->b(Lvv/m0;Lt2/b;Ll2/o;I)V

    .line 93
    .line 94
    .line 95
    :goto_4
    invoke-virtual {p2}, Ll2/t;->s()Ll2/u1;

    .line 96
    .line 97
    .line 98
    move-result-object p2

    .line 99
    if-eqz p2, :cond_6

    .line 100
    .line 101
    new-instance v0, Ljn/g;

    .line 102
    .line 103
    const/4 v5, 0x2

    .line 104
    const/4 v3, 0x0

    .line 105
    move-object v1, p0

    .line 106
    move-object v2, p1

    .line 107
    move v4, p3

    .line 108
    invoke-direct/range {v0 .. v5}, Ljn/g;-><init>(Ljava/lang/Object;Ljava/lang/Object;ZII)V

    .line 109
    .line 110
    .line 111
    iput-object v0, p2, Ll2/u1;->d:Lay0/n;

    .line 112
    .line 113
    :cond_6
    return-void
.end method

.method public static final b(Lvv/m0;Lt2/b;Ll2/o;I)V
    .locals 7

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    check-cast p2, Ll2/t;

    .line 7
    .line 8
    const v0, -0x6bb2970

    .line 9
    .line 10
    .line 11
    invoke-virtual {p2, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 12
    .line 13
    .line 14
    and-int/lit8 v0, p3, 0xe

    .line 15
    .line 16
    if-nez v0, :cond_1

    .line 17
    .line 18
    invoke-virtual {p2, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

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
    or-int/2addr v0, p3

    .line 28
    goto :goto_1

    .line 29
    :cond_1
    move v0, p3

    .line 30
    :goto_1
    and-int/lit8 v1, p3, 0x70

    .line 31
    .line 32
    if-nez v1, :cond_3

    .line 33
    .line 34
    const/4 v1, 0x0

    .line 35
    invoke-virtual {p2, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 36
    .line 37
    .line 38
    move-result v1

    .line 39
    if-eqz v1, :cond_2

    .line 40
    .line 41
    const/16 v1, 0x20

    .line 42
    .line 43
    goto :goto_2

    .line 44
    :cond_2
    const/16 v1, 0x10

    .line 45
    .line 46
    :goto_2
    or-int/2addr v0, v1

    .line 47
    :cond_3
    and-int/lit16 v1, p3, 0x380

    .line 48
    .line 49
    if-nez v1, :cond_5

    .line 50
    .line 51
    invoke-virtual {p2, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 52
    .line 53
    .line 54
    move-result v1

    .line 55
    if-eqz v1, :cond_4

    .line 56
    .line 57
    const/16 v1, 0x100

    .line 58
    .line 59
    goto :goto_3

    .line 60
    :cond_4
    const/16 v1, 0x80

    .line 61
    .line 62
    :goto_3
    or-int/2addr v0, v1

    .line 63
    :cond_5
    and-int/lit16 v1, v0, 0x2db

    .line 64
    .line 65
    const/16 v2, 0x92

    .line 66
    .line 67
    if-ne v1, v2, :cond_7

    .line 68
    .line 69
    invoke-virtual {p2}, Ll2/t;->A()Z

    .line 70
    .line 71
    .line 72
    move-result v1

    .line 73
    if-nez v1, :cond_6

    .line 74
    .line 75
    goto :goto_4

    .line 76
    :cond_6
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 77
    .line 78
    .line 79
    goto :goto_5

    .line 80
    :cond_7
    :goto_4
    and-int/lit8 v0, v0, 0xe

    .line 81
    .line 82
    invoke-static {p0, p2}, Lvv/o0;->b(Lvv/m0;Ll2/o;)Lvv/n0;

    .line 83
    .line 84
    .line 85
    move-result-object v1

    .line 86
    invoke-static {v1}, Lvv/o0;->c(Lvv/n0;)Lvv/n0;

    .line 87
    .line 88
    .line 89
    move-result-object v1

    .line 90
    iget-object v1, v1, Lvv/n0;->e:Lvv/k;

    .line 91
    .line 92
    invoke-static {v1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 93
    .line 94
    .line 95
    invoke-static {p0, p2}, Lvv/l0;->e(Lvv/m0;Ll2/o;)Lg4/p0;

    .line 96
    .line 97
    .line 98
    move-result-object v2

    .line 99
    iget-object v3, v1, Lvv/k;->a:Lg4/p0;

    .line 100
    .line 101
    invoke-virtual {v2, v3}, Lg4/p0;->d(Lg4/p0;)Lg4/p0;

    .line 102
    .line 103
    .line 104
    move-result-object v2

    .line 105
    iget-object v3, v1, Lvv/k;->b:Lx2/s;

    .line 106
    .line 107
    invoke-static {v3}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 108
    .line 109
    .line 110
    sget-object v4, Lw3/h1;->h:Ll2/u2;

    .line 111
    .line 112
    invoke-virtual {p2, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 113
    .line 114
    .line 115
    move-result-object v4

    .line 116
    check-cast v4, Lt4/c;

    .line 117
    .line 118
    iget-object v5, v1, Lvv/k;->c:Lt4/o;

    .line 119
    .line 120
    invoke-static {v5}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 121
    .line 122
    .line 123
    iget-wide v5, v5, Lt4/o;->a:J

    .line 124
    .line 125
    invoke-interface {v4, v5, v6}, Lt4/c;->s(J)F

    .line 126
    .line 127
    .line 128
    move-result v4

    .line 129
    iget-object v1, v1, Lvv/k;->d:Ljava/lang/Boolean;

    .line 130
    .line 131
    invoke-static {v1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 132
    .line 133
    .line 134
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 135
    .line 136
    .line 137
    move-result v1

    .line 138
    new-instance v5, Lvv/i;

    .line 139
    .line 140
    invoke-direct {v5, v3, v4, v2, p1}, Lvv/i;-><init>(Lx2/s;FLg4/p0;Lt2/b;)V

    .line 141
    .line 142
    .line 143
    const v2, -0x46e5b018

    .line 144
    .line 145
    .line 146
    invoke-static {v2, p2, v5}, Lt2/c;->b(ILl2/o;Llx0/e;)Lt2/b;

    .line 147
    .line 148
    .line 149
    move-result-object v2

    .line 150
    or-int/lit16 v0, v0, 0x180

    .line 151
    .line 152
    invoke-static {p0, v1, v2, p2, v0}, Llp/ec;->a(Lvv/m0;ZLt2/b;Ll2/o;I)V

    .line 153
    .line 154
    .line 155
    :goto_5
    invoke-virtual {p2}, Ll2/t;->s()Ll2/u1;

    .line 156
    .line 157
    .line 158
    move-result-object p2

    .line 159
    if-eqz p2, :cond_8

    .line 160
    .line 161
    new-instance v0, Lvv/f;

    .line 162
    .line 163
    const/4 v1, 0x1

    .line 164
    invoke-direct {v0, p3, v1, p1, p0}, Lvv/f;-><init>(IILt2/b;Lvv/m0;)V

    .line 165
    .line 166
    .line 167
    iput-object v0, p2, Ll2/u1;->d:Lay0/n;

    .line 168
    .line 169
    :cond_8
    return-void
.end method
