.class public abstract Lam/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:J

.field public static final synthetic b:I


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    const/4 v0, 0x0

    .line 2
    const/4 v1, 0x5

    .line 3
    invoke-static {v0, v0, v1}, Lt4/b;->b(III)J

    .line 4
    .line 5
    .line 6
    move-result-wide v0

    .line 7
    sput-wide v0, Lam/i;->a:J

    .line 8
    .line 9
    return-void
.end method

.method public static final a(Ll2/o;)Lzl/l;
    .locals 2

    .line 1
    sget-object v0, Lw3/q1;->a:Ll2/u2;

    .line 2
    .line 3
    check-cast p0, Ll2/t;

    .line 4
    .line 5
    invoke-virtual {p0, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    check-cast v0, Ljava/lang/Boolean;

    .line 10
    .line 11
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    const/4 v1, 0x0

    .line 16
    if-eqz v0, :cond_0

    .line 17
    .line 18
    const v0, 0x78589684

    .line 19
    .line 20
    .line 21
    invoke-virtual {p0, v0}, Ll2/t;->Y(I)V

    .line 22
    .line 23
    .line 24
    sget-object v0, Lzl/r;->a:Ll2/u2;

    .line 25
    .line 26
    invoke-virtual {p0, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    check-cast v0, Lzl/l;

    .line 31
    .line 32
    invoke-virtual {p0, v1}, Ll2/t;->q(Z)V

    .line 33
    .line 34
    .line 35
    return-object v0

    .line 36
    :cond_0
    const v0, 0x78597725

    .line 37
    .line 38
    .line 39
    invoke-virtual {p0, v0}, Ll2/t;->Y(I)V

    .line 40
    .line 41
    .line 42
    invoke-virtual {p0, v1}, Ll2/t;->q(Z)V

    .line 43
    .line 44
    .line 45
    const/4 p0, 0x0

    .line 46
    return-object p0
.end method

.method public static final b(Lt3/k;Ll2/o;)Lnm/i;
    .locals 2

    .line 1
    sget-object v0, Lt3/j;->f:Lt3/m;

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    check-cast p1, Ll2/t;

    .line 8
    .line 9
    invoke-virtual {p1, p0}, Ll2/t;->h(Z)Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    invoke-virtual {p1}, Ll2/t;->L()Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    if-nez v0, :cond_0

    .line 18
    .line 19
    sget-object v0, Ll2/n;->a:Ll2/x0;

    .line 20
    .line 21
    if-ne v1, v0, :cond_2

    .line 22
    .line 23
    :cond_0
    if-eqz p0, :cond_1

    .line 24
    .line 25
    sget-object p0, Lnm/i;->a:Lnm/e;

    .line 26
    .line 27
    :goto_0
    move-object v1, p0

    .line 28
    goto :goto_1

    .line 29
    :cond_1
    new-instance p0, Lzl/n;

    .line 30
    .line 31
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 32
    .line 33
    .line 34
    sget-wide v0, Lam/i;->a:J

    .line 35
    .line 36
    iput-wide v0, p0, Lzl/n;->b:J

    .line 37
    .line 38
    new-instance v0, Ljava/util/ArrayList;

    .line 39
    .line 40
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 41
    .line 42
    .line 43
    iput-object v0, p0, Lzl/n;->c:Ljava/util/ArrayList;

    .line 44
    .line 45
    goto :goto_0

    .line 46
    :goto_1
    invoke-virtual {p1, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 47
    .line 48
    .line 49
    :cond_2
    check-cast v1, Lnm/i;

    .line 50
    .line 51
    return-object v1
.end method

.method public static final c(Ljava/lang/Object;Ll2/o;)Lmm/g;
    .locals 4

    .line 1
    check-cast p1, Ll2/t;

    .line 2
    .line 3
    const v0, 0x4ea817fa

    .line 4
    .line 5
    .line 6
    invoke-virtual {p1, v0}, Ll2/t;->Y(I)V

    .line 7
    .line 8
    .line 9
    instance-of v0, p0, Lmm/g;

    .line 10
    .line 11
    const/4 v1, 0x0

    .line 12
    if-eqz v0, :cond_0

    .line 13
    .line 14
    const v0, 0x5b40060c

    .line 15
    .line 16
    .line 17
    invoke-virtual {p1, v0}, Ll2/t;->Y(I)V

    .line 18
    .line 19
    .line 20
    check-cast p0, Lmm/g;

    .line 21
    .line 22
    invoke-virtual {p1, v1}, Ll2/t;->q(Z)V

    .line 23
    .line 24
    .line 25
    invoke-virtual {p1, v1}, Ll2/t;->q(Z)V

    .line 26
    .line 27
    .line 28
    return-object p0

    .line 29
    :cond_0
    const v0, 0x5b409f5a

    .line 30
    .line 31
    .line 32
    invoke-virtual {p1, v0}, Ll2/t;->Y(I)V

    .line 33
    .line 34
    .line 35
    sget-object v0, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->b:Ll2/u2;

    .line 36
    .line 37
    invoke-virtual {p1, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object v0

    .line 41
    check-cast v0, Landroid/content/Context;

    .line 42
    .line 43
    invoke-virtual {p1, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 44
    .line 45
    .line 46
    move-result v2

    .line 47
    invoke-virtual {p1, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 48
    .line 49
    .line 50
    move-result v3

    .line 51
    or-int/2addr v2, v3

    .line 52
    invoke-virtual {p1}, Ll2/t;->L()Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object v3

    .line 56
    if-nez v2, :cond_1

    .line 57
    .line 58
    sget-object v2, Ll2/n;->a:Ll2/x0;

    .line 59
    .line 60
    if-ne v3, v2, :cond_2

    .line 61
    .line 62
    :cond_1
    new-instance v2, Lmm/d;

    .line 63
    .line 64
    invoke-direct {v2, v0}, Lmm/d;-><init>(Landroid/content/Context;)V

    .line 65
    .line 66
    .line 67
    iput-object p0, v2, Lmm/d;->c:Ljava/lang/Object;

    .line 68
    .line 69
    invoke-virtual {v2}, Lmm/d;->a()Lmm/g;

    .line 70
    .line 71
    .line 72
    move-result-object v3

    .line 73
    invoke-virtual {p1, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 74
    .line 75
    .line 76
    :cond_2
    check-cast v3, Lmm/g;

    .line 77
    .line 78
    invoke-virtual {p1, v1}, Ll2/t;->q(Z)V

    .line 79
    .line 80
    .line 81
    invoke-virtual {p1, v1}, Ll2/t;->q(Z)V

    .line 82
    .line 83
    .line 84
    return-object v3
.end method

.method public static final d(Ljava/lang/Object;Lt3/k;Ll2/o;I)Lmm/g;
    .locals 4

    .line 1
    check-cast p2, Ll2/t;

    .line 2
    .line 3
    const p3, -0x13a0feae

    .line 4
    .line 5
    .line 6
    invoke-virtual {p2, p3}, Ll2/t;->Y(I)V

    .line 7
    .line 8
    .line 9
    instance-of p3, p0, Lmm/g;

    .line 10
    .line 11
    sget-object v0, Ll2/n;->a:Ll2/x0;

    .line 12
    .line 13
    const/4 v1, 0x0

    .line 14
    if-eqz p3, :cond_3

    .line 15
    .line 16
    const p3, -0x3c2286e8

    .line 17
    .line 18
    .line 19
    invoke-virtual {p2, p3}, Ll2/t;->Y(I)V

    .line 20
    .line 21
    .line 22
    check-cast p0, Lmm/g;

    .line 23
    .line 24
    iget-object p3, p0, Lmm/g;->s:Lmm/f;

    .line 25
    .line 26
    iget-object p3, p3, Lmm/f;->i:Lnm/i;

    .line 27
    .line 28
    if-eqz p3, :cond_0

    .line 29
    .line 30
    const p1, -0x3c21ea74

    .line 31
    .line 32
    .line 33
    invoke-virtual {p2, p1}, Ll2/t;->Y(I)V

    .line 34
    .line 35
    .line 36
    invoke-virtual {p2, v1}, Ll2/t;->q(Z)V

    .line 37
    .line 38
    .line 39
    invoke-virtual {p2, v1}, Ll2/t;->q(Z)V

    .line 40
    .line 41
    .line 42
    invoke-virtual {p2, v1}, Ll2/t;->q(Z)V

    .line 43
    .line 44
    .line 45
    return-object p0

    .line 46
    :cond_0
    const p3, -0x3c212e46

    .line 47
    .line 48
    .line 49
    invoke-virtual {p2, p3}, Ll2/t;->Y(I)V

    .line 50
    .line 51
    .line 52
    invoke-static {p1, p2}, Lam/i;->b(Lt3/k;Ll2/o;)Lnm/i;

    .line 53
    .line 54
    .line 55
    move-result-object p1

    .line 56
    invoke-virtual {p2, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 57
    .line 58
    .line 59
    move-result p3

    .line 60
    invoke-virtual {p2, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 61
    .line 62
    .line 63
    move-result v2

    .line 64
    or-int/2addr p3, v2

    .line 65
    invoke-virtual {p2}, Ll2/t;->L()Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    move-result-object v2

    .line 69
    if-nez p3, :cond_1

    .line 70
    .line 71
    if-ne v2, v0, :cond_2

    .line 72
    .line 73
    :cond_1
    invoke-static {p0}, Lmm/g;->a(Lmm/g;)Lmm/d;

    .line 74
    .line 75
    .line 76
    move-result-object p0

    .line 77
    iput-object p1, p0, Lmm/d;->o:Lnm/i;

    .line 78
    .line 79
    invoke-virtual {p0}, Lmm/d;->a()Lmm/g;

    .line 80
    .line 81
    .line 82
    move-result-object v2

    .line 83
    invoke-virtual {p2, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 84
    .line 85
    .line 86
    :cond_2
    check-cast v2, Lmm/g;

    .line 87
    .line 88
    invoke-static {p2, v1, v1, v1}, Lf2/m0;->w(Ll2/t;ZZZ)V

    .line 89
    .line 90
    .line 91
    return-object v2

    .line 92
    :cond_3
    const p3, -0x3c1d3dce

    .line 93
    .line 94
    .line 95
    invoke-virtual {p2, p3}, Ll2/t;->Y(I)V

    .line 96
    .line 97
    .line 98
    sget-object p3, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->b:Ll2/u2;

    .line 99
    .line 100
    invoke-virtual {p2, p3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 101
    .line 102
    .line 103
    move-result-object p3

    .line 104
    check-cast p3, Landroid/content/Context;

    .line 105
    .line 106
    invoke-static {p1, p2}, Lam/i;->b(Lt3/k;Ll2/o;)Lnm/i;

    .line 107
    .line 108
    .line 109
    move-result-object p1

    .line 110
    invoke-virtual {p2, p3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 111
    .line 112
    .line 113
    move-result v2

    .line 114
    invoke-virtual {p2, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 115
    .line 116
    .line 117
    move-result v3

    .line 118
    or-int/2addr v2, v3

    .line 119
    invoke-virtual {p2, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 120
    .line 121
    .line 122
    move-result v3

    .line 123
    or-int/2addr v2, v3

    .line 124
    invoke-virtual {p2}, Ll2/t;->L()Ljava/lang/Object;

    .line 125
    .line 126
    .line 127
    move-result-object v3

    .line 128
    if-nez v2, :cond_4

    .line 129
    .line 130
    if-ne v3, v0, :cond_5

    .line 131
    .line 132
    :cond_4
    new-instance v0, Lmm/d;

    .line 133
    .line 134
    invoke-direct {v0, p3}, Lmm/d;-><init>(Landroid/content/Context;)V

    .line 135
    .line 136
    .line 137
    iput-object p0, v0, Lmm/d;->c:Ljava/lang/Object;

    .line 138
    .line 139
    iput-object p1, v0, Lmm/d;->o:Lnm/i;

    .line 140
    .line 141
    invoke-virtual {v0}, Lmm/d;->a()Lmm/g;

    .line 142
    .line 143
    .line 144
    move-result-object v3

    .line 145
    invoke-virtual {p2, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 146
    .line 147
    .line 148
    :cond_5
    check-cast v3, Lmm/g;

    .line 149
    .line 150
    invoke-virtual {p2, v1}, Ll2/t;->q(Z)V

    .line 151
    .line 152
    .line 153
    invoke-virtual {p2, v1}, Ll2/t;->q(Z)V

    .line 154
    .line 155
    .line 156
    return-object v3
.end method

.method public static final e(J)J
    .locals 6

    .line 1
    const/16 v0, 0x20

    .line 2
    .line 3
    shr-long v1, p0, v0

    .line 4
    .line 5
    long-to-int v1, v1

    .line 6
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 7
    .line 8
    .line 9
    move-result v1

    .line 10
    invoke-static {v1}, Lcy0/a;->i(F)I

    .line 11
    .line 12
    .line 13
    move-result v1

    .line 14
    const-wide v2, 0xffffffffL

    .line 15
    .line 16
    .line 17
    .line 18
    .line 19
    and-long/2addr p0, v2

    .line 20
    long-to-int p0, p0

    .line 21
    invoke-static {p0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 22
    .line 23
    .line 24
    move-result p0

    .line 25
    invoke-static {p0}, Lcy0/a;->i(F)I

    .line 26
    .line 27
    .line 28
    move-result p0

    .line 29
    int-to-long v4, v1

    .line 30
    shl-long v0, v4, v0

    .line 31
    .line 32
    int-to-long p0, p0

    .line 33
    and-long/2addr p0, v2

    .line 34
    or-long/2addr p0, v0

    .line 35
    return-wide p0
.end method

.method public static f(Ljava/lang/String;)V
    .locals 4

    .line 1
    const-string v0, "If you wish to display this "

    .line 2
    .line 3
    const-string v1, ", use androidx.compose.foundation.Image."

    .line 4
    .line 5
    invoke-static {v0, p0, v1}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    new-instance v1, Ljava/lang/IllegalArgumentException;

    .line 10
    .line 11
    const-string v2, "Unsupported type: "

    .line 12
    .line 13
    const-string v3, ". "

    .line 14
    .line 15
    invoke-static {v2, p0, v3, v0}, Lu/w;->f(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    invoke-direct {v1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    throw v1
.end method

.method public static final g(Lmm/g;)V
    .locals 3

    .line 1
    iget-object v0, p0, Lmm/g;->b:Ljava/lang/Object;

    .line 2
    .line 3
    instance-of v1, v0, Lmm/d;

    .line 4
    .line 5
    if-nez v1, :cond_5

    .line 6
    .line 7
    instance-of v1, v0, Le3/f;

    .line 8
    .line 9
    const/4 v2, 0x0

    .line 10
    if-nez v1, :cond_4

    .line 11
    .line 12
    instance-of v1, v0, Lj3/f;

    .line 13
    .line 14
    if-nez v1, :cond_3

    .line 15
    .line 16
    instance-of v0, v0, Li3/c;

    .line 17
    .line 18
    if-nez v0, :cond_2

    .line 19
    .line 20
    iget-object v0, p0, Lmm/g;->c:Lqm/a;

    .line 21
    .line 22
    if-nez v0, :cond_1

    .line 23
    .line 24
    sget-object v0, Lmm/i;->e:Ld8/c;

    .line 25
    .line 26
    invoke-static {p0, v0}, Lyl/m;->d(Lmm/g;Ld8/c;)Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    check-cast p0, Landroidx/lifecycle/r;

    .line 31
    .line 32
    if-nez p0, :cond_0

    .line 33
    .line 34
    return-void

    .line 35
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 36
    .line 37
    const-string v0, "request.lifecycle must be null."

    .line 38
    .line 39
    invoke-direct {p0, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 40
    .line 41
    .line 42
    throw p0

    .line 43
    :cond_1
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 44
    .line 45
    const-string v0, "request.target must be null."

    .line 46
    .line 47
    invoke-direct {p0, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    throw p0

    .line 51
    :cond_2
    const-string p0, "Painter"

    .line 52
    .line 53
    invoke-static {p0}, Lam/i;->f(Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    throw v2

    .line 57
    :cond_3
    const-string p0, "ImageVector"

    .line 58
    .line 59
    invoke-static {p0}, Lam/i;->f(Ljava/lang/String;)V

    .line 60
    .line 61
    .line 62
    throw v2

    .line 63
    :cond_4
    const-string p0, "ImageBitmap"

    .line 64
    .line 65
    invoke-static {p0}, Lam/i;->f(Ljava/lang/String;)V

    .line 66
    .line 67
    .line 68
    throw v2

    .line 69
    :cond_5
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 70
    .line 71
    const-string v0, "Unsupported type: ImageRequest.Builder. Did you forget to call ImageRequest.Builder.build()?"

    .line 72
    .line 73
    invoke-direct {p0, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 74
    .line 75
    .line 76
    throw p0
.end method
