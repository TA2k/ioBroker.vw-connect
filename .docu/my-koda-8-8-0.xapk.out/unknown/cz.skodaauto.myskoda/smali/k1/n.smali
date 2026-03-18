.class public abstract Lk1/n;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Landroidx/collection/q0;

.field public static final b:Landroidx/collection/q0;

.field public static final c:Lk1/p;

.field public static final d:Lk1/m;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    const/4 v0, 0x1

    .line 2
    invoke-static {v0}, Lk1/n;->c(Z)Landroidx/collection/q0;

    .line 3
    .line 4
    .line 5
    move-result-object v0

    .line 6
    sput-object v0, Lk1/n;->a:Landroidx/collection/q0;

    .line 7
    .line 8
    const/4 v0, 0x0

    .line 9
    invoke-static {v0}, Lk1/n;->c(Z)Landroidx/collection/q0;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    sput-object v1, Lk1/n;->b:Landroidx/collection/q0;

    .line 14
    .line 15
    new-instance v1, Lk1/p;

    .line 16
    .line 17
    sget-object v2, Lx2/c;->d:Lx2/j;

    .line 18
    .line 19
    invoke-direct {v1, v2, v0}, Lk1/p;-><init>(Lx2/e;Z)V

    .line 20
    .line 21
    .line 22
    sput-object v1, Lk1/n;->c:Lk1/p;

    .line 23
    .line 24
    sget-object v0, Lk1/m;->b:Lk1/m;

    .line 25
    .line 26
    sput-object v0, Lk1/n;->d:Lk1/m;

    .line 27
    .line 28
    return-void
.end method

.method public static final a(Lx2/s;Ll2/o;I)V
    .locals 6

    .line 1
    check-cast p1, Ll2/t;

    .line 2
    .line 3
    const v0, -0xc96ce69

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
    const/4 v3, 0x1

    .line 29
    if-eq v2, v1, :cond_2

    .line 30
    .line 31
    move v1, v3

    .line 32
    goto :goto_2

    .line 33
    :cond_2
    const/4 v1, 0x0

    .line 34
    :goto_2
    and-int/2addr v0, v3

    .line 35
    invoke-virtual {p1, v0, v1}, Ll2/t;->O(IZ)Z

    .line 36
    .line 37
    .line 38
    move-result v0

    .line 39
    if-eqz v0, :cond_6

    .line 40
    .line 41
    iget-wide v0, p1, Ll2/t;->T:J

    .line 42
    .line 43
    invoke-static {v0, v1}, Ljava/lang/Long;->hashCode(J)I

    .line 44
    .line 45
    .line 46
    move-result v0

    .line 47
    invoke-static {p1, p0}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 48
    .line 49
    .line 50
    move-result-object v1

    .line 51
    invoke-virtual {p1}, Ll2/t;->m()Ll2/p1;

    .line 52
    .line 53
    .line 54
    move-result-object v2

    .line 55
    sget-object v4, Lv3/k;->m1:Lv3/j;

    .line 56
    .line 57
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 58
    .line 59
    .line 60
    sget-object v4, Lv3/j;->b:Lv3/i;

    .line 61
    .line 62
    invoke-virtual {p1}, Ll2/t;->c0()V

    .line 63
    .line 64
    .line 65
    iget-boolean v5, p1, Ll2/t;->S:Z

    .line 66
    .line 67
    if-eqz v5, :cond_3

    .line 68
    .line 69
    invoke-virtual {p1, v4}, Ll2/t;->l(Lay0/a;)V

    .line 70
    .line 71
    .line 72
    goto :goto_3

    .line 73
    :cond_3
    invoke-virtual {p1}, Ll2/t;->m0()V

    .line 74
    .line 75
    .line 76
    :goto_3
    sget-object v4, Lv3/j;->g:Lv3/h;

    .line 77
    .line 78
    sget-object v5, Lk1/n;->d:Lk1/m;

    .line 79
    .line 80
    invoke-static {v4, v5, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 81
    .line 82
    .line 83
    sget-object v4, Lv3/j;->f:Lv3/h;

    .line 84
    .line 85
    invoke-static {v4, v2, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 86
    .line 87
    .line 88
    sget-object v2, Lv3/j;->d:Lv3/h;

    .line 89
    .line 90
    invoke-static {v2, v1, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 91
    .line 92
    .line 93
    sget-object v1, Lv3/j;->j:Lv3/h;

    .line 94
    .line 95
    iget-boolean v2, p1, Ll2/t;->S:Z

    .line 96
    .line 97
    if-nez v2, :cond_4

    .line 98
    .line 99
    invoke-virtual {p1}, Ll2/t;->L()Ljava/lang/Object;

    .line 100
    .line 101
    .line 102
    move-result-object v2

    .line 103
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 104
    .line 105
    .line 106
    move-result-object v4

    .line 107
    invoke-static {v2, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 108
    .line 109
    .line 110
    move-result v2

    .line 111
    if-nez v2, :cond_5

    .line 112
    .line 113
    :cond_4
    invoke-static {v0, p1, v0, v1}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 114
    .line 115
    .line 116
    :cond_5
    invoke-virtual {p1, v3}, Ll2/t;->q(Z)V

    .line 117
    .line 118
    .line 119
    goto :goto_4

    .line 120
    :cond_6
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 121
    .line 122
    .line 123
    :goto_4
    invoke-virtual {p1}, Ll2/t;->s()Ll2/u1;

    .line 124
    .line 125
    .line 126
    move-result-object p1

    .line 127
    if-eqz p1, :cond_7

    .line 128
    .line 129
    new-instance v0, Ld00/b;

    .line 130
    .line 131
    const/16 v1, 0x12

    .line 132
    .line 133
    invoke-direct {v0, p0, p2, v1}, Ld00/b;-><init>(Lx2/s;II)V

    .line 134
    .line 135
    .line 136
    iput-object v0, p1, Ll2/u1;->d:Lay0/n;

    .line 137
    .line 138
    :cond_7
    return-void
.end method

.method public static final b(Lt3/d1;Lt3/e1;Lt3/p0;Lt4/m;IILx2/e;)V
    .locals 7

    .line 1
    invoke-interface {p2}, Lt3/p0;->l()Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object p2

    .line 5
    instance-of v0, p2, Lk1/l;

    .line 6
    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    check-cast p2, Lk1/l;

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    const/4 p2, 0x0

    .line 13
    :goto_0
    if-eqz p2, :cond_2

    .line 14
    .line 15
    iget-object p2, p2, Lk1/l;->r:Lx2/e;

    .line 16
    .line 17
    if-nez p2, :cond_1

    .line 18
    .line 19
    goto :goto_1

    .line 20
    :cond_1
    move-object v0, p2

    .line 21
    goto :goto_2

    .line 22
    :cond_2
    :goto_1
    move-object v0, p6

    .line 23
    :goto_2
    iget p2, p1, Lt3/e1;->d:I

    .line 24
    .line 25
    iget p6, p1, Lt3/e1;->e:I

    .line 26
    .line 27
    int-to-long v1, p2

    .line 28
    const/16 p2, 0x20

    .line 29
    .line 30
    shl-long/2addr v1, p2

    .line 31
    int-to-long v3, p6

    .line 32
    const-wide v5, 0xffffffffL

    .line 33
    .line 34
    .line 35
    .line 36
    .line 37
    and-long/2addr v3, v5

    .line 38
    or-long/2addr v1, v3

    .line 39
    int-to-long v3, p4

    .line 40
    shl-long/2addr v3, p2

    .line 41
    int-to-long p4, p5

    .line 42
    and-long/2addr p4, v5

    .line 43
    or-long/2addr v3, p4

    .line 44
    move-object v5, p3

    .line 45
    invoke-interface/range {v0 .. v5}, Lx2/e;->a(JJLt4/m;)J

    .line 46
    .line 47
    .line 48
    move-result-wide p2

    .line 49
    invoke-static {p0, p1, p2, p3}, Lt3/d1;->i(Lt3/d1;Lt3/e1;J)V

    .line 50
    .line 51
    .line 52
    return-void
.end method

.method public static final c(Z)Landroidx/collection/q0;
    .locals 3

    .line 1
    new-instance v0, Landroidx/collection/q0;

    .line 2
    .line 3
    const/16 v1, 0x9

    .line 4
    .line 5
    invoke-direct {v0, v1}, Landroidx/collection/q0;-><init>(I)V

    .line 6
    .line 7
    .line 8
    sget-object v1, Lx2/c;->d:Lx2/j;

    .line 9
    .line 10
    new-instance v2, Lk1/p;

    .line 11
    .line 12
    invoke-direct {v2, v1, p0}, Lk1/p;-><init>(Lx2/e;Z)V

    .line 13
    .line 14
    .line 15
    invoke-virtual {v0, v1, v2}, Landroidx/collection/q0;->m(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 16
    .line 17
    .line 18
    sget-object v1, Lx2/c;->e:Lx2/j;

    .line 19
    .line 20
    new-instance v2, Lk1/p;

    .line 21
    .line 22
    invoke-direct {v2, v1, p0}, Lk1/p;-><init>(Lx2/e;Z)V

    .line 23
    .line 24
    .line 25
    invoke-virtual {v0, v1, v2}, Landroidx/collection/q0;->m(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 26
    .line 27
    .line 28
    sget-object v1, Lx2/c;->f:Lx2/j;

    .line 29
    .line 30
    new-instance v2, Lk1/p;

    .line 31
    .line 32
    invoke-direct {v2, v1, p0}, Lk1/p;-><init>(Lx2/e;Z)V

    .line 33
    .line 34
    .line 35
    invoke-virtual {v0, v1, v2}, Landroidx/collection/q0;->m(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 36
    .line 37
    .line 38
    sget-object v1, Lx2/c;->g:Lx2/j;

    .line 39
    .line 40
    new-instance v2, Lk1/p;

    .line 41
    .line 42
    invoke-direct {v2, v1, p0}, Lk1/p;-><init>(Lx2/e;Z)V

    .line 43
    .line 44
    .line 45
    invoke-virtual {v0, v1, v2}, Landroidx/collection/q0;->m(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 46
    .line 47
    .line 48
    sget-object v1, Lx2/c;->h:Lx2/j;

    .line 49
    .line 50
    new-instance v2, Lk1/p;

    .line 51
    .line 52
    invoke-direct {v2, v1, p0}, Lk1/p;-><init>(Lx2/e;Z)V

    .line 53
    .line 54
    .line 55
    invoke-virtual {v0, v1, v2}, Landroidx/collection/q0;->m(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 56
    .line 57
    .line 58
    sget-object v1, Lx2/c;->i:Lx2/j;

    .line 59
    .line 60
    new-instance v2, Lk1/p;

    .line 61
    .line 62
    invoke-direct {v2, v1, p0}, Lk1/p;-><init>(Lx2/e;Z)V

    .line 63
    .line 64
    .line 65
    invoke-virtual {v0, v1, v2}, Landroidx/collection/q0;->m(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 66
    .line 67
    .line 68
    sget-object v1, Lx2/c;->j:Lx2/j;

    .line 69
    .line 70
    new-instance v2, Lk1/p;

    .line 71
    .line 72
    invoke-direct {v2, v1, p0}, Lk1/p;-><init>(Lx2/e;Z)V

    .line 73
    .line 74
    .line 75
    invoke-virtual {v0, v1, v2}, Landroidx/collection/q0;->m(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 76
    .line 77
    .line 78
    sget-object v1, Lx2/c;->k:Lx2/j;

    .line 79
    .line 80
    new-instance v2, Lk1/p;

    .line 81
    .line 82
    invoke-direct {v2, v1, p0}, Lk1/p;-><init>(Lx2/e;Z)V

    .line 83
    .line 84
    .line 85
    invoke-virtual {v0, v1, v2}, Landroidx/collection/q0;->m(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 86
    .line 87
    .line 88
    sget-object v1, Lx2/c;->l:Lx2/j;

    .line 89
    .line 90
    new-instance v2, Lk1/p;

    .line 91
    .line 92
    invoke-direct {v2, v1, p0}, Lk1/p;-><init>(Lx2/e;Z)V

    .line 93
    .line 94
    .line 95
    invoke-virtual {v0, v1, v2}, Landroidx/collection/q0;->m(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 96
    .line 97
    .line 98
    return-object v0
.end method

.method public static final d(Lx2/e;Z)Lt3/q0;
    .locals 1

    .line 1
    if-eqz p1, :cond_0

    .line 2
    .line 3
    sget-object v0, Lk1/n;->a:Landroidx/collection/q0;

    .line 4
    .line 5
    goto :goto_0

    .line 6
    :cond_0
    sget-object v0, Lk1/n;->b:Landroidx/collection/q0;

    .line 7
    .line 8
    :goto_0
    invoke-virtual {v0, p0}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    check-cast v0, Lt3/q0;

    .line 13
    .line 14
    if-nez v0, :cond_1

    .line 15
    .line 16
    new-instance v0, Lk1/p;

    .line 17
    .line 18
    invoke-direct {v0, p0, p1}, Lk1/p;-><init>(Lx2/e;Z)V

    .line 19
    .line 20
    .line 21
    :cond_1
    return-object v0
.end method

.method public static final e(Ll2/o;)Lk1/p;
    .locals 4

    .line 1
    sget-object v0, Lx2/c;->d:Lx2/j;

    .line 2
    .line 3
    invoke-virtual {v0, v0}, Lx2/j;->equals(Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    const/4 v2, 0x0

    .line 8
    if-eqz v1, :cond_0

    .line 9
    .line 10
    check-cast p0, Ll2/t;

    .line 11
    .line 12
    const v0, 0xe90bed7

    .line 13
    .line 14
    .line 15
    invoke-virtual {p0, v0}, Ll2/t;->Y(I)V

    .line 16
    .line 17
    .line 18
    invoke-virtual {p0, v2}, Ll2/t;->q(Z)V

    .line 19
    .line 20
    .line 21
    sget-object p0, Lk1/n;->c:Lk1/p;

    .line 22
    .line 23
    return-object p0

    .line 24
    :cond_0
    check-cast p0, Ll2/t;

    .line 25
    .line 26
    const v1, 0xe917915

    .line 27
    .line 28
    .line 29
    invoke-virtual {p0, v1}, Ll2/t;->Y(I)V

    .line 30
    .line 31
    .line 32
    invoke-virtual {p0, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 33
    .line 34
    .line 35
    move-result v1

    .line 36
    invoke-virtual {p0, v2}, Ll2/t;->h(Z)Z

    .line 37
    .line 38
    .line 39
    move-result v3

    .line 40
    or-int/2addr v1, v3

    .line 41
    invoke-virtual {p0}, Ll2/t;->L()Ljava/lang/Object;

    .line 42
    .line 43
    .line 44
    move-result-object v3

    .line 45
    if-nez v1, :cond_1

    .line 46
    .line 47
    sget-object v1, Ll2/n;->a:Ll2/x0;

    .line 48
    .line 49
    if-ne v3, v1, :cond_2

    .line 50
    .line 51
    :cond_1
    new-instance v3, Lk1/p;

    .line 52
    .line 53
    invoke-direct {v3, v0, v2}, Lk1/p;-><init>(Lx2/e;Z)V

    .line 54
    .line 55
    .line 56
    invoke-virtual {p0, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    :cond_2
    check-cast v3, Lk1/p;

    .line 60
    .line 61
    invoke-virtual {p0, v2}, Ll2/t;->q(Z)V

    .line 62
    .line 63
    .line 64
    return-object v3
.end method
