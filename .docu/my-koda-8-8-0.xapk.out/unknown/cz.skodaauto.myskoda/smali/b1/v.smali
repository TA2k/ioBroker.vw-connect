.class public final Lb1/v;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lt3/q0;


# instance fields
.field public final a:Lb1/b0;

.field public b:Z


# direct methods
.method public constructor <init>(Lb1/b0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lb1/v;->a:Lb1/b0;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Lt3/t;Ljava/util/List;I)I
    .locals 2

    .line 1
    invoke-interface {p2}, Ljava/util/List;->isEmpty()Z

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    const/4 p1, 0x0

    .line 6
    if-eqz p0, :cond_0

    .line 7
    .line 8
    return p1

    .line 9
    :cond_0
    invoke-interface {p2, p1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    check-cast p0, Lt3/p0;

    .line 14
    .line 15
    invoke-interface {p0, p3}, Lt3/p0;->G(I)I

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    invoke-static {p2}, Ljp/k1;->h(Ljava/util/List;)I

    .line 20
    .line 21
    .line 22
    move-result p1

    .line 23
    const/4 v0, 0x1

    .line 24
    if-gt v0, p1, :cond_2

    .line 25
    .line 26
    :goto_0
    invoke-interface {p2, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object v1

    .line 30
    check-cast v1, Lt3/p0;

    .line 31
    .line 32
    invoke-interface {v1, p3}, Lt3/p0;->G(I)I

    .line 33
    .line 34
    .line 35
    move-result v1

    .line 36
    if-le v1, p0, :cond_1

    .line 37
    .line 38
    move p0, v1

    .line 39
    :cond_1
    if-eq v0, p1, :cond_2

    .line 40
    .line 41
    add-int/lit8 v0, v0, 0x1

    .line 42
    .line 43
    goto :goto_0

    .line 44
    :cond_2
    return p0
.end method

.method public final b(Lt3/s0;Ljava/util/List;J)Lt3/r0;
    .locals 7

    .line 1
    new-instance v0, Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-interface {p2}, Ljava/util/List;->size()I

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 8
    .line 9
    .line 10
    move-object v1, p2

    .line 11
    check-cast v1, Ljava/util/Collection;

    .line 12
    .line 13
    invoke-interface {v1}, Ljava/util/Collection;->size()I

    .line 14
    .line 15
    .line 16
    move-result v1

    .line 17
    const/4 v2, 0x0

    .line 18
    move v3, v2

    .line 19
    move v4, v3

    .line 20
    :goto_0
    if-ge v2, v1, :cond_0

    .line 21
    .line 22
    invoke-interface {p2, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object v5

    .line 26
    check-cast v5, Lt3/p0;

    .line 27
    .line 28
    invoke-interface {v5, p3, p4}, Lt3/p0;->L(J)Lt3/e1;

    .line 29
    .line 30
    .line 31
    move-result-object v5

    .line 32
    iget v6, v5, Lt3/e1;->d:I

    .line 33
    .line 34
    invoke-static {v3, v6}, Ljava/lang/Math;->max(II)I

    .line 35
    .line 36
    .line 37
    move-result v3

    .line 38
    iget v6, v5, Lt3/e1;->e:I

    .line 39
    .line 40
    invoke-static {v4, v6}, Ljava/lang/Math;->max(II)I

    .line 41
    .line 42
    .line 43
    move-result v4

    .line 44
    invoke-virtual {v0, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 45
    .line 46
    .line 47
    add-int/lit8 v2, v2, 0x1

    .line 48
    .line 49
    goto :goto_0

    .line 50
    :cond_0
    invoke-interface {p1}, Lt3/t;->I()Z

    .line 51
    .line 52
    .line 53
    move-result p2

    .line 54
    const-wide p3, 0xffffffffL

    .line 55
    .line 56
    .line 57
    .line 58
    .line 59
    const/16 v1, 0x20

    .line 60
    .line 61
    iget-object v2, p0, Lb1/v;->a:Lb1/b0;

    .line 62
    .line 63
    if-eqz p2, :cond_1

    .line 64
    .line 65
    const/4 p2, 0x1

    .line 66
    iput-boolean p2, p0, Lb1/v;->b:Z

    .line 67
    .line 68
    iget-object p0, v2, Lb1/b0;->a:Ll2/j1;

    .line 69
    .line 70
    int-to-long v5, v3

    .line 71
    shl-long v1, v5, v1

    .line 72
    .line 73
    int-to-long v5, v4

    .line 74
    and-long p2, v5, p3

    .line 75
    .line 76
    or-long/2addr p2, v1

    .line 77
    new-instance p4, Lt4/l;

    .line 78
    .line 79
    invoke-direct {p4, p2, p3}, Lt4/l;-><init>(J)V

    .line 80
    .line 81
    .line 82
    invoke-virtual {p0, p4}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 83
    .line 84
    .line 85
    goto :goto_1

    .line 86
    :cond_1
    iget-boolean p0, p0, Lb1/v;->b:Z

    .line 87
    .line 88
    if-nez p0, :cond_2

    .line 89
    .line 90
    iget-object p0, v2, Lb1/b0;->a:Ll2/j1;

    .line 91
    .line 92
    int-to-long v5, v3

    .line 93
    shl-long v1, v5, v1

    .line 94
    .line 95
    int-to-long v5, v4

    .line 96
    and-long p2, v5, p3

    .line 97
    .line 98
    or-long/2addr p2, v1

    .line 99
    new-instance p4, Lt4/l;

    .line 100
    .line 101
    invoke-direct {p4, p2, p3}, Lt4/l;-><init>(J)V

    .line 102
    .line 103
    .line 104
    invoke-virtual {p0, p4}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 105
    .line 106
    .line 107
    :cond_2
    :goto_1
    new-instance p0, Lb1/u;

    .line 108
    .line 109
    const/4 p2, 0x0

    .line 110
    invoke-direct {p0, v0, p2}, Lb1/u;-><init>(Ljava/util/ArrayList;I)V

    .line 111
    .line 112
    .line 113
    sget-object p2, Lmx0/t;->d:Lmx0/t;

    .line 114
    .line 115
    invoke-interface {p1, v3, v4, p2, p0}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 116
    .line 117
    .line 118
    move-result-object p0

    .line 119
    return-object p0
.end method

.method public final c(Lt3/t;Ljava/util/List;I)I
    .locals 2

    .line 1
    invoke-interface {p2}, Ljava/util/List;->isEmpty()Z

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    const/4 p1, 0x0

    .line 6
    if-eqz p0, :cond_0

    .line 7
    .line 8
    return p1

    .line 9
    :cond_0
    invoke-interface {p2, p1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    check-cast p0, Lt3/p0;

    .line 14
    .line 15
    invoke-interface {p0, p3}, Lt3/p0;->c(I)I

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    invoke-static {p2}, Ljp/k1;->h(Ljava/util/List;)I

    .line 20
    .line 21
    .line 22
    move-result p1

    .line 23
    const/4 v0, 0x1

    .line 24
    if-gt v0, p1, :cond_2

    .line 25
    .line 26
    :goto_0
    invoke-interface {p2, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object v1

    .line 30
    check-cast v1, Lt3/p0;

    .line 31
    .line 32
    invoke-interface {v1, p3}, Lt3/p0;->c(I)I

    .line 33
    .line 34
    .line 35
    move-result v1

    .line 36
    if-le v1, p0, :cond_1

    .line 37
    .line 38
    move p0, v1

    .line 39
    :cond_1
    if-eq v0, p1, :cond_2

    .line 40
    .line 41
    add-int/lit8 v0, v0, 0x1

    .line 42
    .line 43
    goto :goto_0

    .line 44
    :cond_2
    return p0
.end method

.method public final d(Lt3/t;Ljava/util/List;I)I
    .locals 2

    .line 1
    invoke-interface {p2}, Ljava/util/List;->isEmpty()Z

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    const/4 p1, 0x0

    .line 6
    if-eqz p0, :cond_0

    .line 7
    .line 8
    return p1

    .line 9
    :cond_0
    invoke-interface {p2, p1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    check-cast p0, Lt3/p0;

    .line 14
    .line 15
    invoke-interface {p0, p3}, Lt3/p0;->A(I)I

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    invoke-static {p2}, Ljp/k1;->h(Ljava/util/List;)I

    .line 20
    .line 21
    .line 22
    move-result p1

    .line 23
    const/4 v0, 0x1

    .line 24
    if-gt v0, p1, :cond_2

    .line 25
    .line 26
    :goto_0
    invoke-interface {p2, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object v1

    .line 30
    check-cast v1, Lt3/p0;

    .line 31
    .line 32
    invoke-interface {v1, p3}, Lt3/p0;->A(I)I

    .line 33
    .line 34
    .line 35
    move-result v1

    .line 36
    if-le v1, p0, :cond_1

    .line 37
    .line 38
    move p0, v1

    .line 39
    :cond_1
    if-eq v0, p1, :cond_2

    .line 40
    .line 41
    add-int/lit8 v0, v0, 0x1

    .line 42
    .line 43
    goto :goto_0

    .line 44
    :cond_2
    return p0
.end method

.method public final e(Lt3/t;Ljava/util/List;I)I
    .locals 2

    .line 1
    invoke-interface {p2}, Ljava/util/List;->isEmpty()Z

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    const/4 p1, 0x0

    .line 6
    if-eqz p0, :cond_0

    .line 7
    .line 8
    return p1

    .line 9
    :cond_0
    invoke-interface {p2, p1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    check-cast p0, Lt3/p0;

    .line 14
    .line 15
    invoke-interface {p0, p3}, Lt3/p0;->J(I)I

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    invoke-static {p2}, Ljp/k1;->h(Ljava/util/List;)I

    .line 20
    .line 21
    .line 22
    move-result p1

    .line 23
    const/4 v0, 0x1

    .line 24
    if-gt v0, p1, :cond_2

    .line 25
    .line 26
    :goto_0
    invoke-interface {p2, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object v1

    .line 30
    check-cast v1, Lt3/p0;

    .line 31
    .line 32
    invoke-interface {v1, p3}, Lt3/p0;->J(I)I

    .line 33
    .line 34
    .line 35
    move-result v1

    .line 36
    if-le v1, p0, :cond_1

    .line 37
    .line 38
    move p0, v1

    .line 39
    :cond_1
    if-eq v0, p1, :cond_2

    .line 40
    .line 41
    add-int/lit8 v0, v0, 0x1

    .line 42
    .line 43
    goto :goto_0

    .line 44
    :cond_2
    return p0
.end method
