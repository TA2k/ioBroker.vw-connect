.class public final Lv3/w0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lv3/h0;

.field public final b:Lrn/i;

.field public c:Z

.field public d:Z

.field public final e:Lvp/y1;

.field public final f:Ln2/b;

.field public final g:J

.field public final h:Ln2/b;

.field public i:Lt4/a;


# direct methods
.method public constructor <init>(Lv3/h0;)V
    .locals 3

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lv3/w0;->a:Lv3/h0;

    .line 5
    .line 6
    new-instance p1, Lrn/i;

    .line 7
    .line 8
    const/16 v0, 0xe

    .line 9
    .line 10
    invoke-direct {p1, v0}, Lrn/i;-><init>(I)V

    .line 11
    .line 12
    .line 13
    iput-object p1, p0, Lv3/w0;->b:Lrn/i;

    .line 14
    .line 15
    new-instance p1, Lvp/y1;

    .line 16
    .line 17
    const/16 v0, 0x1a

    .line 18
    .line 19
    invoke-direct {p1, v0}, Lvp/y1;-><init>(I)V

    .line 20
    .line 21
    .line 22
    iput-object p1, p0, Lv3/w0;->e:Lvp/y1;

    .line 23
    .line 24
    new-instance p1, Ln2/b;

    .line 25
    .line 26
    const/16 v0, 0x10

    .line 27
    .line 28
    new-array v1, v0, [Lv3/h0;

    .line 29
    .line 30
    invoke-direct {p1, v1}, Ln2/b;-><init>([Ljava/lang/Object;)V

    .line 31
    .line 32
    .line 33
    iput-object p1, p0, Lv3/w0;->f:Ln2/b;

    .line 34
    .line 35
    const-wide/16 v1, 0x1

    .line 36
    .line 37
    iput-wide v1, p0, Lv3/w0;->g:J

    .line 38
    .line 39
    new-instance p1, Ln2/b;

    .line 40
    .line 41
    new-array v0, v0, [Lv3/v0;

    .line 42
    .line 43
    invoke-direct {p1, v0}, Ln2/b;-><init>([Ljava/lang/Object;)V

    .line 44
    .line 45
    .line 46
    iput-object p1, p0, Lv3/w0;->h:Ln2/b;

    .line 47
    .line 48
    return-void
.end method

.method public static b(Lv3/h0;Lt4/a;)Z
    .locals 5

    .line 1
    iget-object v0, p0, Lv3/h0;->j:Lv3/h0;

    .line 2
    .line 3
    iget-object v1, p0, Lv3/h0;->I:Lv3/l0;

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    if-nez v0, :cond_0

    .line 7
    .line 8
    return v2

    .line 9
    :cond_0
    if-eqz p1, :cond_2

    .line 10
    .line 11
    if-eqz v0, :cond_1

    .line 12
    .line 13
    iget-object v0, v1, Lv3/l0;->q:Lv3/u0;

    .line 14
    .line 15
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 16
    .line 17
    .line 18
    iget-wide v3, p1, Lt4/a;->a:J

    .line 19
    .line 20
    invoke-virtual {v0, v3, v4}, Lv3/u0;->L0(J)Z

    .line 21
    .line 22
    .line 23
    move-result p1

    .line 24
    goto :goto_1

    .line 25
    :cond_1
    move p1, v2

    .line 26
    goto :goto_1

    .line 27
    :cond_2
    iget-object p1, v1, Lv3/l0;->q:Lv3/u0;

    .line 28
    .line 29
    if-eqz p1, :cond_3

    .line 30
    .line 31
    iget-object v1, p1, Lv3/u0;->q:Lt4/a;

    .line 32
    .line 33
    goto :goto_0

    .line 34
    :cond_3
    const/4 v1, 0x0

    .line 35
    :goto_0
    if-eqz v1, :cond_1

    .line 36
    .line 37
    if-eqz v0, :cond_1

    .line 38
    .line 39
    invoke-static {p1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    iget-wide v0, v1, Lt4/a;->a:J

    .line 43
    .line 44
    invoke-virtual {p1, v0, v1}, Lv3/u0;->L0(J)Z

    .line 45
    .line 46
    .line 47
    move-result p1

    .line 48
    :goto_1
    invoke-virtual {p0}, Lv3/h0;->v()Lv3/h0;

    .line 49
    .line 50
    .line 51
    move-result-object v0

    .line 52
    if-eqz p1, :cond_6

    .line 53
    .line 54
    if-eqz v0, :cond_6

    .line 55
    .line 56
    iget-object v1, v0, Lv3/h0;->j:Lv3/h0;

    .line 57
    .line 58
    const/4 v3, 0x3

    .line 59
    if-nez v1, :cond_4

    .line 60
    .line 61
    invoke-static {v0, v2, v3}, Lv3/h0;->Y(Lv3/h0;ZI)V

    .line 62
    .line 63
    .line 64
    return p1

    .line 65
    :cond_4
    invoke-virtual {p0}, Lv3/h0;->t()Lv3/f0;

    .line 66
    .line 67
    .line 68
    move-result-object v1

    .line 69
    sget-object v4, Lv3/f0;->d:Lv3/f0;

    .line 70
    .line 71
    if-ne v1, v4, :cond_5

    .line 72
    .line 73
    invoke-static {v0, v2, v3}, Lv3/h0;->W(Lv3/h0;ZI)V

    .line 74
    .line 75
    .line 76
    return p1

    .line 77
    :cond_5
    invoke-virtual {p0}, Lv3/h0;->t()Lv3/f0;

    .line 78
    .line 79
    .line 80
    move-result-object p0

    .line 81
    sget-object v1, Lv3/f0;->e:Lv3/f0;

    .line 82
    .line 83
    if-ne p0, v1, :cond_6

    .line 84
    .line 85
    invoke-virtual {v0, v2}, Lv3/h0;->V(Z)V

    .line 86
    .line 87
    .line 88
    :cond_6
    return p1
.end method

.method public static c(Lv3/h0;Lt4/a;)Z
    .locals 4

    .line 1
    if-eqz p1, :cond_0

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lv3/h0;->Q(Lt4/a;)Z

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    goto :goto_0

    .line 8
    :cond_0
    invoke-static {p0}, Lv3/h0;->R(Lv3/h0;)Z

    .line 9
    .line 10
    .line 11
    move-result p1

    .line 12
    :goto_0
    invoke-virtual {p0}, Lv3/h0;->v()Lv3/h0;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    if-eqz p1, :cond_2

    .line 17
    .line 18
    if-eqz v0, :cond_2

    .line 19
    .line 20
    invoke-virtual {p0}, Lv3/h0;->s()Lv3/f0;

    .line 21
    .line 22
    .line 23
    move-result-object v1

    .line 24
    sget-object v2, Lv3/f0;->d:Lv3/f0;

    .line 25
    .line 26
    const/4 v3, 0x0

    .line 27
    if-ne v1, v2, :cond_1

    .line 28
    .line 29
    const/4 p0, 0x3

    .line 30
    invoke-static {v0, v3, p0}, Lv3/h0;->Y(Lv3/h0;ZI)V

    .line 31
    .line 32
    .line 33
    return p1

    .line 34
    :cond_1
    invoke-virtual {p0}, Lv3/h0;->s()Lv3/f0;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    sget-object v1, Lv3/f0;->e:Lv3/f0;

    .line 39
    .line 40
    if-ne p0, v1, :cond_2

    .line 41
    .line 42
    invoke-virtual {v0, v3}, Lv3/h0;->X(Z)V

    .line 43
    .line 44
    .line 45
    :cond_2
    return p1
.end method

.method public static h(Lv3/h0;)Z
    .locals 3

    .line 1
    iget-object v0, p0, Lv3/h0;->I:Lv3/l0;

    .line 2
    .line 3
    iget-boolean v0, v0, Lv3/l0;->e:Z

    .line 4
    .line 5
    if-eqz v0, :cond_1

    .line 6
    .line 7
    invoke-virtual {p0}, Lv3/h0;->t()Lv3/f0;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    sget-object v1, Lv3/f0;->f:Lv3/f0;

    .line 12
    .line 13
    const/4 v2, 0x1

    .line 14
    if-ne v0, v1, :cond_0

    .line 15
    .line 16
    iget-object p0, p0, Lv3/h0;->I:Lv3/l0;

    .line 17
    .line 18
    iget-object p0, p0, Lv3/l0;->q:Lv3/u0;

    .line 19
    .line 20
    if-eqz p0, :cond_1

    .line 21
    .line 22
    iget-object p0, p0, Lv3/u0;->v:Lv3/i0;

    .line 23
    .line 24
    if-eqz p0, :cond_1

    .line 25
    .line 26
    invoke-virtual {p0}, Lv3/i0;->e()Z

    .line 27
    .line 28
    .line 29
    move-result p0

    .line 30
    if-ne p0, v2, :cond_1

    .line 31
    .line 32
    :cond_0
    return v2

    .line 33
    :cond_1
    const/4 p0, 0x0

    .line 34
    return p0
.end method

.method public static i(Lv3/h0;)Z
    .locals 2

    .line 1
    invoke-virtual {p0}, Lv3/h0;->r()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_4

    .line 6
    .line 7
    :cond_0
    invoke-virtual {p0}, Lv3/h0;->s()Lv3/f0;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    sget-object v1, Lv3/f0;->f:Lv3/f0;

    .line 12
    .line 13
    if-ne v0, v1, :cond_2

    .line 14
    .line 15
    iget-object v0, p0, Lv3/h0;->I:Lv3/l0;

    .line 16
    .line 17
    iget-object v0, v0, Lv3/l0;->p:Lv3/y0;

    .line 18
    .line 19
    iget-object v0, v0, Lv3/y0;->B:Lv3/i0;

    .line 20
    .line 21
    invoke-virtual {v0}, Lv3/i0;->e()Z

    .line 22
    .line 23
    .line 24
    move-result v0

    .line 25
    if-nez v0, :cond_2

    .line 26
    .line 27
    invoke-virtual {p0}, Lv3/h0;->v()Lv3/h0;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    if-eqz v0, :cond_1

    .line 32
    .line 33
    iget-object v0, v0, Lv3/h0;->I:Lv3/l0;

    .line 34
    .line 35
    iget-object v0, v0, Lv3/l0;->d:Lv3/d0;

    .line 36
    .line 37
    goto :goto_0

    .line 38
    :cond_1
    const/4 v0, 0x0

    .line 39
    :goto_0
    sget-object v1, Lv3/d0;->d:Lv3/d0;

    .line 40
    .line 41
    if-ne v0, v1, :cond_4

    .line 42
    .line 43
    :cond_2
    invoke-virtual {p0}, Lv3/h0;->v()Lv3/h0;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    if-nez p0, :cond_3

    .line 48
    .line 49
    goto :goto_1

    .line 50
    :cond_3
    invoke-virtual {p0}, Lv3/h0;->J()Z

    .line 51
    .line 52
    .line 53
    move-result v0

    .line 54
    if-eqz v0, :cond_0

    .line 55
    .line 56
    const/4 p0, 0x1

    .line 57
    return p0

    .line 58
    :cond_4
    :goto_1
    const/4 p0, 0x0

    .line 59
    return p0
.end method


# virtual methods
.method public final a(Z)V
    .locals 6

    .line 1
    const/4 v0, 0x1

    .line 2
    iget-object v1, p0, Lv3/w0;->e:Lvp/y1;

    .line 3
    .line 4
    if-eqz p1, :cond_0

    .line 5
    .line 6
    iget-object p1, v1, Lvp/y1;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p1, Ln2/b;

    .line 9
    .line 10
    iget-object p0, p0, Lv3/w0;->a:Lv3/h0;

    .line 11
    .line 12
    iget v2, p0, Lv3/h0;->R:I

    .line 13
    .line 14
    if-lez v2, :cond_0

    .line 15
    .line 16
    invoke-virtual {p1}, Ln2/b;->i()V

    .line 17
    .line 18
    .line 19
    invoke-virtual {p1, p0}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 20
    .line 21
    .line 22
    iput-boolean v0, p0, Lv3/h0;->Q:Z

    .line 23
    .line 24
    :cond_0
    iget-object p0, v1, Lvp/y1;->e:Ljava/lang/Object;

    .line 25
    .line 26
    check-cast p0, Ln2/b;

    .line 27
    .line 28
    iget p1, p0, Ln2/b;->f:I

    .line 29
    .line 30
    if-eqz p1, :cond_6

    .line 31
    .line 32
    sget-object v2, Lv3/l1;->e:Lv3/l1;

    .line 33
    .line 34
    iget-object v3, p0, Ln2/b;->d:[Ljava/lang/Object;

    .line 35
    .line 36
    const/4 v4, 0x0

    .line 37
    invoke-static {v3, v2, v4, p1}, Lmx0/n;->T([Ljava/lang/Object;Ljava/util/Comparator;II)V

    .line 38
    .line 39
    .line 40
    iget p1, p0, Ln2/b;->f:I

    .line 41
    .line 42
    iget-object v2, v1, Lvp/y1;->f:Ljava/lang/Object;

    .line 43
    .line 44
    check-cast v2, [Lv3/h0;

    .line 45
    .line 46
    if-eqz v2, :cond_1

    .line 47
    .line 48
    array-length v3, v2

    .line 49
    if-ge v3, p1, :cond_2

    .line 50
    .line 51
    :cond_1
    const/16 v2, 0x10

    .line 52
    .line 53
    invoke-static {v2, p1}, Ljava/lang/Math;->max(II)I

    .line 54
    .line 55
    .line 56
    move-result v2

    .line 57
    new-array v2, v2, [Lv3/h0;

    .line 58
    .line 59
    :cond_2
    const/4 v3, 0x0

    .line 60
    iput-object v3, v1, Lvp/y1;->f:Ljava/lang/Object;

    .line 61
    .line 62
    :goto_0
    if-ge v4, p1, :cond_3

    .line 63
    .line 64
    iget-object v5, p0, Ln2/b;->d:[Ljava/lang/Object;

    .line 65
    .line 66
    aget-object v5, v5, v4

    .line 67
    .line 68
    aput-object v5, v2, v4

    .line 69
    .line 70
    add-int/lit8 v4, v4, 0x1

    .line 71
    .line 72
    goto :goto_0

    .line 73
    :cond_3
    invoke-virtual {p0}, Ln2/b;->i()V

    .line 74
    .line 75
    .line 76
    sub-int/2addr p1, v0

    .line 77
    :goto_1
    const/4 p0, -0x1

    .line 78
    if-ge p0, p1, :cond_5

    .line 79
    .line 80
    aget-object p0, v2, p1

    .line 81
    .line 82
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 83
    .line 84
    .line 85
    iget-boolean v0, p0, Lv3/h0;->Q:Z

    .line 86
    .line 87
    if-eqz v0, :cond_4

    .line 88
    .line 89
    invoke-static {p0}, Lvp/y1;->P(Lv3/h0;)V

    .line 90
    .line 91
    .line 92
    :cond_4
    aput-object v3, v2, p1

    .line 93
    .line 94
    add-int/lit8 p1, p1, -0x1

    .line 95
    .line 96
    goto :goto_1

    .line 97
    :cond_5
    iput-object v2, v1, Lvp/y1;->f:Ljava/lang/Object;

    .line 98
    .line 99
    :cond_6
    return-void
.end method

.method public final d()V
    .locals 7

    .line 1
    iget-object p0, p0, Lv3/w0;->h:Ln2/b;

    .line 2
    .line 3
    iget v0, p0, Ln2/b;->f:I

    .line 4
    .line 5
    if-eqz v0, :cond_3

    .line 6
    .line 7
    iget-object v1, p0, Ln2/b;->d:[Ljava/lang/Object;

    .line 8
    .line 9
    const/4 v2, 0x0

    .line 10
    :goto_0
    if-ge v2, v0, :cond_2

    .line 11
    .line 12
    aget-object v3, v1, v2

    .line 13
    .line 14
    check-cast v3, Lv3/v0;

    .line 15
    .line 16
    iget-object v4, v3, Lv3/v0;->a:Lv3/h0;

    .line 17
    .line 18
    iget-boolean v5, v3, Lv3/v0;->c:Z

    .line 19
    .line 20
    iget-object v6, v3, Lv3/v0;->a:Lv3/h0;

    .line 21
    .line 22
    invoke-virtual {v4}, Lv3/h0;->I()Z

    .line 23
    .line 24
    .line 25
    move-result v4

    .line 26
    if-eqz v4, :cond_1

    .line 27
    .line 28
    iget-boolean v3, v3, Lv3/v0;->b:Z

    .line 29
    .line 30
    const/4 v4, 0x2

    .line 31
    if-nez v3, :cond_0

    .line 32
    .line 33
    invoke-static {v6, v5, v4}, Lv3/h0;->Y(Lv3/h0;ZI)V

    .line 34
    .line 35
    .line 36
    goto :goto_1

    .line 37
    :cond_0
    invoke-static {v6, v5, v4}, Lv3/h0;->W(Lv3/h0;ZI)V

    .line 38
    .line 39
    .line 40
    :cond_1
    :goto_1
    add-int/lit8 v2, v2, 0x1

    .line 41
    .line 42
    goto :goto_0

    .line 43
    :cond_2
    invoke-virtual {p0}, Ln2/b;->i()V

    .line 44
    .line 45
    .line 46
    :cond_3
    return-void
.end method

.method public final e(Lv3/h0;)V
    .locals 5

    .line 1
    invoke-virtual {p1}, Lv3/h0;->z()Ln2/b;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    iget-object v0, p1, Ln2/b;->d:[Ljava/lang/Object;

    .line 6
    .line 7
    iget p1, p1, Ln2/b;->f:I

    .line 8
    .line 9
    const/4 v1, 0x0

    .line 10
    :goto_0
    if-ge v1, p1, :cond_2

    .line 11
    .line 12
    aget-object v2, v0, v1

    .line 13
    .line 14
    check-cast v2, Lv3/h0;

    .line 15
    .line 16
    invoke-virtual {v2}, Lv3/h0;->K()Ljava/lang/Boolean;

    .line 17
    .line 18
    .line 19
    move-result-object v3

    .line 20
    sget-object v4, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 21
    .line 22
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 23
    .line 24
    .line 25
    move-result v3

    .line 26
    if-eqz v3, :cond_1

    .line 27
    .line 28
    iget-boolean v3, v2, Lv3/h0;->S:Z

    .line 29
    .line 30
    if-nez v3, :cond_1

    .line 31
    .line 32
    iget-object v3, p0, Lv3/w0;->b:Lrn/i;

    .line 33
    .line 34
    invoke-virtual {v3, v2}, Lrn/i;->p(Lv3/h0;)Z

    .line 35
    .line 36
    .line 37
    move-result v3

    .line 38
    if-eqz v3, :cond_0

    .line 39
    .line 40
    invoke-virtual {v2}, Lv3/h0;->L()V

    .line 41
    .line 42
    .line 43
    :cond_0
    invoke-virtual {p0, v2}, Lv3/w0;->e(Lv3/h0;)V

    .line 44
    .line 45
    .line 46
    :cond_1
    add-int/lit8 v1, v1, 0x1

    .line 47
    .line 48
    goto :goto_0

    .line 49
    :cond_2
    return-void
.end method

.method public final f(Lv3/h0;Z)V
    .locals 1

    .line 1
    iget-boolean v0, p0, Lv3/w0;->c:Z

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    const-string v0, "forceMeasureTheSubtree should be executed during the measureAndLayout pass"

    .line 6
    .line 7
    invoke-static {v0}, Ls3/a;->b(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    :cond_0
    if-eqz p2, :cond_1

    .line 11
    .line 12
    iget-object v0, p1, Lv3/h0;->I:Lv3/l0;

    .line 13
    .line 14
    iget-boolean v0, v0, Lv3/l0;->e:Z

    .line 15
    .line 16
    goto :goto_0

    .line 17
    :cond_1
    invoke-virtual {p1}, Lv3/h0;->r()Z

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    :goto_0
    if-eqz v0, :cond_2

    .line 22
    .line 23
    const-string v0, "node not yet measured"

    .line 24
    .line 25
    invoke-static {v0}, Ls3/a;->a(Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    :cond_2
    invoke-virtual {p0, p1, p2}, Lv3/w0;->g(Lv3/h0;Z)V

    .line 29
    .line 30
    .line 31
    return-void
.end method

.method public final g(Lv3/h0;Z)V
    .locals 8

    .line 1
    invoke-virtual {p1}, Lv3/h0;->z()Ln2/b;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    iget-object v1, v0, Ln2/b;->d:[Ljava/lang/Object;

    .line 6
    .line 7
    iget v0, v0, Ln2/b;->f:I

    .line 8
    .line 9
    const/4 v2, 0x0

    .line 10
    move v3, v2

    .line 11
    :goto_0
    if-ge v3, v0, :cond_8

    .line 12
    .line 13
    aget-object v4, v1, v3

    .line 14
    .line 15
    check-cast v4, Lv3/h0;

    .line 16
    .line 17
    const/4 v5, 0x1

    .line 18
    if-nez p2, :cond_0

    .line 19
    .line 20
    invoke-virtual {v4}, Lv3/h0;->s()Lv3/f0;

    .line 21
    .line 22
    .line 23
    move-result-object v6

    .line 24
    sget-object v7, Lv3/f0;->d:Lv3/f0;

    .line 25
    .line 26
    if-eq v6, v7, :cond_1

    .line 27
    .line 28
    iget-object v6, v4, Lv3/h0;->I:Lv3/l0;

    .line 29
    .line 30
    iget-object v6, v6, Lv3/l0;->p:Lv3/y0;

    .line 31
    .line 32
    iget-object v6, v6, Lv3/y0;->B:Lv3/i0;

    .line 33
    .line 34
    invoke-virtual {v6}, Lv3/i0;->e()Z

    .line 35
    .line 36
    .line 37
    move-result v6

    .line 38
    if-eqz v6, :cond_0

    .line 39
    .line 40
    goto :goto_1

    .line 41
    :cond_0
    if-eqz p2, :cond_7

    .line 42
    .line 43
    invoke-virtual {v4}, Lv3/h0;->t()Lv3/f0;

    .line 44
    .line 45
    .line 46
    move-result-object v6

    .line 47
    sget-object v7, Lv3/f0;->d:Lv3/f0;

    .line 48
    .line 49
    if-eq v6, v7, :cond_1

    .line 50
    .line 51
    iget-object v6, v4, Lv3/h0;->I:Lv3/l0;

    .line 52
    .line 53
    iget-object v6, v6, Lv3/l0;->q:Lv3/u0;

    .line 54
    .line 55
    if-eqz v6, :cond_7

    .line 56
    .line 57
    iget-object v6, v6, Lv3/u0;->v:Lv3/i0;

    .line 58
    .line 59
    if-eqz v6, :cond_7

    .line 60
    .line 61
    invoke-virtual {v6}, Lv3/i0;->e()Z

    .line 62
    .line 63
    .line 64
    move-result v6

    .line 65
    if-ne v6, v5, :cond_7

    .line 66
    .line 67
    :cond_1
    :goto_1
    invoke-static {v4}, Lv3/f;->s(Lv3/h0;)Z

    .line 68
    .line 69
    .line 70
    move-result v6

    .line 71
    iget-object v7, v4, Lv3/h0;->I:Lv3/l0;

    .line 72
    .line 73
    if-eqz v6, :cond_3

    .line 74
    .line 75
    if-nez p2, :cond_3

    .line 76
    .line 77
    iget-boolean v6, v7, Lv3/l0;->e:Z

    .line 78
    .line 79
    if-eqz v6, :cond_2

    .line 80
    .line 81
    iget-object v6, p0, Lv3/w0;->b:Lrn/i;

    .line 82
    .line 83
    invoke-virtual {v6, v4}, Lrn/i;->p(Lv3/h0;)Z

    .line 84
    .line 85
    .line 86
    move-result v6

    .line 87
    if-eqz v6, :cond_2

    .line 88
    .line 89
    invoke-virtual {p0, v4, v5, v2}, Lv3/w0;->m(Lv3/h0;ZZ)Z

    .line 90
    .line 91
    .line 92
    goto :goto_2

    .line 93
    :cond_2
    invoke-virtual {p0, v4, v5}, Lv3/w0;->f(Lv3/h0;Z)V

    .line 94
    .line 95
    .line 96
    :cond_3
    :goto_2
    if-eqz p2, :cond_4

    .line 97
    .line 98
    iget-boolean v5, v7, Lv3/l0;->e:Z

    .line 99
    .line 100
    goto :goto_3

    .line 101
    :cond_4
    invoke-virtual {v4}, Lv3/h0;->r()Z

    .line 102
    .line 103
    .line 104
    move-result v5

    .line 105
    :goto_3
    if-eqz v5, :cond_5

    .line 106
    .line 107
    invoke-virtual {p0, v4, p2, v2}, Lv3/w0;->m(Lv3/h0;ZZ)Z

    .line 108
    .line 109
    .line 110
    :cond_5
    if-eqz p2, :cond_6

    .line 111
    .line 112
    iget-boolean v5, v7, Lv3/l0;->e:Z

    .line 113
    .line 114
    goto :goto_4

    .line 115
    :cond_6
    invoke-virtual {v4}, Lv3/h0;->r()Z

    .line 116
    .line 117
    .line 118
    move-result v5

    .line 119
    :goto_4
    if-nez v5, :cond_7

    .line 120
    .line 121
    invoke-virtual {p0, v4, p2}, Lv3/w0;->g(Lv3/h0;Z)V

    .line 122
    .line 123
    .line 124
    :cond_7
    add-int/lit8 v3, v3, 0x1

    .line 125
    .line 126
    goto :goto_0

    .line 127
    :cond_8
    if-eqz p2, :cond_9

    .line 128
    .line 129
    iget-object v0, p1, Lv3/h0;->I:Lv3/l0;

    .line 130
    .line 131
    iget-boolean v0, v0, Lv3/l0;->e:Z

    .line 132
    .line 133
    goto :goto_5

    .line 134
    :cond_9
    invoke-virtual {p1}, Lv3/h0;->r()Z

    .line 135
    .line 136
    .line 137
    move-result v0

    .line 138
    :goto_5
    if-eqz v0, :cond_a

    .line 139
    .line 140
    invoke-virtual {p0, p1, p2, v2}, Lv3/w0;->m(Lv3/h0;ZZ)Z

    .line 141
    .line 142
    .line 143
    :cond_a
    return-void
.end method

.method public final j(Lw3/q;)Z
    .locals 16

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    iget-object v0, v1, Lv3/w0;->b:Lrn/i;

    .line 4
    .line 5
    iget-object v2, v1, Lv3/w0;->a:Lv3/h0;

    .line 6
    .line 7
    invoke-virtual {v2}, Lv3/h0;->I()Z

    .line 8
    .line 9
    .line 10
    move-result v3

    .line 11
    if-nez v3, :cond_0

    .line 12
    .line 13
    const-string v3, "performMeasureAndLayout called with unattached root"

    .line 14
    .line 15
    invoke-static {v3}, Ls3/a;->a(Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    :cond_0
    invoke-virtual {v2}, Lv3/h0;->J()Z

    .line 19
    .line 20
    .line 21
    move-result v3

    .line 22
    if-nez v3, :cond_1

    .line 23
    .line 24
    const-string v3, "performMeasureAndLayout called with unplaced root"

    .line 25
    .line 26
    invoke-static {v3}, Ls3/a;->a(Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    :cond_1
    iget-boolean v3, v1, Lv3/w0;->c:Z

    .line 30
    .line 31
    if-eqz v3, :cond_2

    .line 32
    .line 33
    const-string v3, "performMeasureAndLayout called during measure layout"

    .line 34
    .line 35
    invoke-static {v3}, Ls3/a;->a(Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    :cond_2
    iget-object v3, v1, Lv3/w0;->i:Lt4/a;

    .line 39
    .line 40
    const/4 v4, 0x0

    .line 41
    const/4 v5, 0x1

    .line 42
    if-eqz v3, :cond_d

    .line 43
    .line 44
    iput-boolean v5, v1, Lv3/w0;->c:Z

    .line 45
    .line 46
    iput-boolean v5, v1, Lv3/w0;->d:Z

    .line 47
    .line 48
    :try_start_0
    invoke-virtual {v0}, Lrn/i;->w()Z

    .line 49
    .line 50
    .line 51
    move-result v3
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 52
    iget-object v6, v0, Lrn/i;->e:Ljava/lang/Object;

    .line 53
    .line 54
    check-cast v6, Lt1/j0;

    .line 55
    .line 56
    if-eqz v3, :cond_b

    .line 57
    .line 58
    move v3, v4

    .line 59
    :cond_3
    :goto_0
    :try_start_1
    iget-object v7, v0, Lrn/i;->g:Ljava/lang/Object;

    .line 60
    .line 61
    check-cast v7, Lt1/j0;

    .line 62
    .line 63
    iget-object v8, v0, Lrn/i;->f:Ljava/lang/Object;

    .line 64
    .line 65
    check-cast v8, Lt1/j0;

    .line 66
    .line 67
    iget-object v9, v6, Lt1/j0;->e:Ljava/lang/Object;

    .line 68
    .line 69
    check-cast v9, Lv3/y1;

    .line 70
    .line 71
    invoke-virtual {v9}, Ljava/util/AbstractCollection;->isEmpty()Z

    .line 72
    .line 73
    .line 74
    move-result v9

    .line 75
    if-nez v9, :cond_5

    .line 76
    .line 77
    iget-object v7, v6, Lt1/j0;->e:Ljava/lang/Object;

    .line 78
    .line 79
    check-cast v7, Lv3/y1;

    .line 80
    .line 81
    invoke-virtual {v7}, Ljava/util/TreeSet;->first()Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object v7

    .line 85
    check-cast v7, Lv3/h0;

    .line 86
    .line 87
    invoke-virtual {v6, v7}, Lt1/j0;->n(Lv3/h0;)Z

    .line 88
    .line 89
    .line 90
    iget-object v8, v7, Lv3/h0;->j:Lv3/h0;

    .line 91
    .line 92
    if-eqz v8, :cond_4

    .line 93
    .line 94
    move v8, v5

    .line 95
    goto :goto_1

    .line 96
    :cond_4
    move v8, v4

    .line 97
    :goto_1
    move v9, v4

    .line 98
    goto :goto_3

    .line 99
    :catchall_0
    move-exception v0

    .line 100
    goto/16 :goto_5

    .line 101
    .line 102
    :cond_5
    iget-object v9, v8, Lt1/j0;->e:Ljava/lang/Object;

    .line 103
    .line 104
    check-cast v9, Lv3/y1;

    .line 105
    .line 106
    invoke-virtual {v9}, Ljava/util/AbstractCollection;->isEmpty()Z

    .line 107
    .line 108
    .line 109
    move-result v9

    .line 110
    if-nez v9, :cond_7

    .line 111
    .line 112
    iget-object v7, v8, Lt1/j0;->e:Ljava/lang/Object;

    .line 113
    .line 114
    check-cast v7, Lv3/y1;

    .line 115
    .line 116
    invoke-virtual {v7}, Ljava/util/TreeSet;->first()Ljava/lang/Object;

    .line 117
    .line 118
    .line 119
    move-result-object v7

    .line 120
    check-cast v7, Lv3/h0;

    .line 121
    .line 122
    invoke-virtual {v8, v7}, Lt1/j0;->n(Lv3/h0;)Z

    .line 123
    .line 124
    .line 125
    iget-object v8, v7, Lv3/h0;->j:Lv3/h0;

    .line 126
    .line 127
    if-eqz v8, :cond_6

    .line 128
    .line 129
    move v8, v5

    .line 130
    goto :goto_2

    .line 131
    :cond_6
    move v8, v4

    .line 132
    :goto_2
    move v9, v5

    .line 133
    goto :goto_3

    .line 134
    :cond_7
    iget-object v8, v7, Lt1/j0;->e:Ljava/lang/Object;

    .line 135
    .line 136
    check-cast v8, Lv3/y1;

    .line 137
    .line 138
    invoke-virtual {v8}, Ljava/util/AbstractCollection;->isEmpty()Z

    .line 139
    .line 140
    .line 141
    move-result v8

    .line 142
    if-nez v8, :cond_a

    .line 143
    .line 144
    iget-object v8, v7, Lt1/j0;->e:Ljava/lang/Object;

    .line 145
    .line 146
    check-cast v8, Lv3/y1;

    .line 147
    .line 148
    invoke-virtual {v8}, Ljava/util/TreeSet;->first()Ljava/lang/Object;

    .line 149
    .line 150
    .line 151
    move-result-object v8

    .line 152
    check-cast v8, Lv3/h0;

    .line 153
    .line 154
    invoke-virtual {v7, v8}, Lt1/j0;->n(Lv3/h0;)Z

    .line 155
    .line 156
    .line 157
    move v9, v5

    .line 158
    move-object v7, v8

    .line 159
    move v8, v4

    .line 160
    :goto_3
    invoke-virtual {v1, v7, v8, v9}, Lv3/w0;->m(Lv3/h0;ZZ)Z

    .line 161
    .line 162
    .line 163
    move-result v8

    .line 164
    if-nez v9, :cond_9

    .line 165
    .line 166
    iget-object v9, v7, Lv3/h0;->I:Lv3/l0;

    .line 167
    .line 168
    iget-boolean v9, v9, Lv3/l0;->f:Z

    .line 169
    .line 170
    if-eqz v9, :cond_8

    .line 171
    .line 172
    sget-object v9, Lv3/v;->e:Lv3/v;

    .line 173
    .line 174
    invoke-virtual {v0, v7, v9}, Lrn/i;->n(Lv3/h0;Lv3/v;)V

    .line 175
    .line 176
    .line 177
    :cond_8
    invoke-virtual {v7}, Lv3/h0;->q()Z

    .line 178
    .line 179
    .line 180
    move-result v9

    .line 181
    if-eqz v9, :cond_9

    .line 182
    .line 183
    sget-object v9, Lv3/v;->g:Lv3/v;

    .line 184
    .line 185
    invoke-virtual {v0, v7, v9}, Lrn/i;->n(Lv3/h0;Lv3/v;)V

    .line 186
    .line 187
    .line 188
    :cond_9
    if-ne v7, v2, :cond_3

    .line 189
    .line 190
    if-eqz v8, :cond_3

    .line 191
    .line 192
    move v3, v5

    .line 193
    goto/16 :goto_0

    .line 194
    .line 195
    :cond_a
    if-eqz p1, :cond_c

    .line 196
    .line 197
    invoke-virtual/range {p1 .. p1}, Lw3/q;->invoke()Ljava/lang/Object;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 198
    .line 199
    .line 200
    goto :goto_4

    .line 201
    :cond_b
    move v3, v4

    .line 202
    :cond_c
    :goto_4
    iput-boolean v4, v1, Lv3/w0;->c:Z

    .line 203
    .line 204
    iput-boolean v4, v1, Lv3/w0;->d:Z

    .line 205
    .line 206
    goto :goto_6

    .line 207
    :goto_5
    :try_start_2
    throw v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 208
    :catchall_1
    move-exception v0

    .line 209
    iput-boolean v4, v1, Lv3/w0;->c:Z

    .line 210
    .line 211
    iput-boolean v4, v1, Lv3/w0;->d:Z

    .line 212
    .line 213
    throw v0

    .line 214
    :cond_d
    move v3, v4

    .line 215
    :goto_6
    iget-object v0, v1, Lv3/w0;->f:Ln2/b;

    .line 216
    .line 217
    iget-object v1, v0, Ln2/b;->d:[Ljava/lang/Object;

    .line 218
    .line 219
    iget v2, v0, Ln2/b;->f:I

    .line 220
    .line 221
    move v6, v4

    .line 222
    :goto_7
    if-ge v6, v2, :cond_19

    .line 223
    .line 224
    aget-object v7, v1, v6

    .line 225
    .line 226
    check-cast v7, Lv3/h0;

    .line 227
    .line 228
    iget-object v7, v7, Lv3/h0;->H:Lg1/q;

    .line 229
    .line 230
    iget-object v8, v7, Lg1/q;->d:Ljava/lang/Object;

    .line 231
    .line 232
    check-cast v8, Lv3/u;

    .line 233
    .line 234
    const/16 v9, 0x80

    .line 235
    .line 236
    invoke-static {v9}, Lv3/g1;->g(I)Z

    .line 237
    .line 238
    .line 239
    move-result v10

    .line 240
    if-eqz v10, :cond_e

    .line 241
    .line 242
    iget-object v11, v8, Lv3/u;->S:Lv3/z1;

    .line 243
    .line 244
    goto :goto_8

    .line 245
    :cond_e
    iget-object v11, v8, Lv3/u;->S:Lv3/z1;

    .line 246
    .line 247
    iget-object v11, v11, Lx2/r;->h:Lx2/r;

    .line 248
    .line 249
    if-nez v11, :cond_f

    .line 250
    .line 251
    goto/16 :goto_f

    .line 252
    .line 253
    :cond_f
    :goto_8
    sget-object v12, Lv3/f1;->N:Le3/k0;

    .line 254
    .line 255
    invoke-virtual {v8, v10}, Lv3/f1;->h1(Z)Lx2/r;

    .line 256
    .line 257
    .line 258
    move-result-object v8

    .line 259
    :goto_9
    if-eqz v8, :cond_18

    .line 260
    .line 261
    iget v10, v8, Lx2/r;->g:I

    .line 262
    .line 263
    and-int/2addr v10, v9

    .line 264
    if-eqz v10, :cond_18

    .line 265
    .line 266
    iget v10, v8, Lx2/r;->f:I

    .line 267
    .line 268
    and-int/2addr v10, v9

    .line 269
    if-eqz v10, :cond_17

    .line 270
    .line 271
    const/4 v10, 0x0

    .line 272
    move-object v12, v8

    .line 273
    move-object v13, v10

    .line 274
    :goto_a
    if-eqz v12, :cond_17

    .line 275
    .line 276
    instance-of v14, v12, Lv3/x;

    .line 277
    .line 278
    if-eqz v14, :cond_10

    .line 279
    .line 280
    check-cast v12, Lv3/x;

    .line 281
    .line 282
    iget-object v14, v7, Lg1/q;->d:Ljava/lang/Object;

    .line 283
    .line 284
    check-cast v14, Lv3/u;

    .line 285
    .line 286
    invoke-interface {v12, v14}, Lv3/x;->R(Lt3/y;)V

    .line 287
    .line 288
    .line 289
    goto :goto_e

    .line 290
    :cond_10
    iget v14, v12, Lx2/r;->f:I

    .line 291
    .line 292
    and-int/2addr v14, v9

    .line 293
    if-eqz v14, :cond_16

    .line 294
    .line 295
    instance-of v14, v12, Lv3/n;

    .line 296
    .line 297
    if-eqz v14, :cond_16

    .line 298
    .line 299
    move-object v14, v12

    .line 300
    check-cast v14, Lv3/n;

    .line 301
    .line 302
    iget-object v14, v14, Lv3/n;->s:Lx2/r;

    .line 303
    .line 304
    move v15, v4

    .line 305
    :goto_b
    if-eqz v14, :cond_15

    .line 306
    .line 307
    iget v4, v14, Lx2/r;->f:I

    .line 308
    .line 309
    and-int/2addr v4, v9

    .line 310
    if-eqz v4, :cond_14

    .line 311
    .line 312
    add-int/lit8 v15, v15, 0x1

    .line 313
    .line 314
    if-ne v15, v5, :cond_11

    .line 315
    .line 316
    move-object v12, v14

    .line 317
    goto :goto_c

    .line 318
    :cond_11
    if-nez v13, :cond_12

    .line 319
    .line 320
    new-instance v13, Ln2/b;

    .line 321
    .line 322
    const/16 v4, 0x10

    .line 323
    .line 324
    new-array v4, v4, [Lx2/r;

    .line 325
    .line 326
    invoke-direct {v13, v4}, Ln2/b;-><init>([Ljava/lang/Object;)V

    .line 327
    .line 328
    .line 329
    :cond_12
    if-eqz v12, :cond_13

    .line 330
    .line 331
    invoke-virtual {v13, v12}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 332
    .line 333
    .line 334
    move-object v12, v10

    .line 335
    :cond_13
    invoke-virtual {v13, v14}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 336
    .line 337
    .line 338
    :cond_14
    :goto_c
    iget-object v14, v14, Lx2/r;->i:Lx2/r;

    .line 339
    .line 340
    const/4 v4, 0x0

    .line 341
    goto :goto_b

    .line 342
    :cond_15
    if-ne v15, v5, :cond_16

    .line 343
    .line 344
    :goto_d
    const/4 v4, 0x0

    .line 345
    goto :goto_a

    .line 346
    :cond_16
    :goto_e
    invoke-static {v13}, Lv3/f;->f(Ln2/b;)Lx2/r;

    .line 347
    .line 348
    .line 349
    move-result-object v12

    .line 350
    goto :goto_d

    .line 351
    :cond_17
    if-eq v8, v11, :cond_18

    .line 352
    .line 353
    iget-object v8, v8, Lx2/r;->i:Lx2/r;

    .line 354
    .line 355
    const/4 v4, 0x0

    .line 356
    goto :goto_9

    .line 357
    :cond_18
    :goto_f
    add-int/lit8 v6, v6, 0x1

    .line 358
    .line 359
    const/4 v4, 0x0

    .line 360
    goto/16 :goto_7

    .line 361
    .line 362
    :cond_19
    invoke-virtual {v0}, Ln2/b;->i()V

    .line 363
    .line 364
    .line 365
    return v3
.end method

.method public final k(Lv3/h0;J)V
    .locals 12

    .line 1
    iget-boolean v0, p1, Lv3/h0;->S:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    iget-object v0, p0, Lv3/w0;->a:Lv3/h0;

    .line 7
    .line 8
    invoke-virtual {p1, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 9
    .line 10
    .line 11
    move-result v1

    .line 12
    if-eqz v1, :cond_1

    .line 13
    .line 14
    const-string v1, "measureAndLayout called on root"

    .line 15
    .line 16
    invoke-static {v1}, Ls3/a;->a(Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    :cond_1
    invoke-virtual {v0}, Lv3/h0;->I()Z

    .line 20
    .line 21
    .line 22
    move-result v1

    .line 23
    if-nez v1, :cond_2

    .line 24
    .line 25
    const-string v1, "performMeasureAndLayout called with unattached root"

    .line 26
    .line 27
    invoke-static {v1}, Ls3/a;->a(Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    :cond_2
    invoke-virtual {v0}, Lv3/h0;->J()Z

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    if-nez v0, :cond_3

    .line 35
    .line 36
    const-string v0, "performMeasureAndLayout called with unplaced root"

    .line 37
    .line 38
    invoke-static {v0}, Ls3/a;->a(Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    :cond_3
    iget-boolean v0, p0, Lv3/w0;->c:Z

    .line 42
    .line 43
    if-eqz v0, :cond_4

    .line 44
    .line 45
    const-string v0, "performMeasureAndLayout called during measure layout"

    .line 46
    .line 47
    invoke-static {v0}, Ls3/a;->a(Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    :cond_4
    iget-object v0, p0, Lv3/w0;->i:Lt4/a;

    .line 51
    .line 52
    const/4 v1, 0x1

    .line 53
    const/4 v2, 0x0

    .line 54
    if-eqz v0, :cond_8

    .line 55
    .line 56
    iput-boolean v1, p0, Lv3/w0;->c:Z

    .line 57
    .line 58
    iput-boolean v2, p0, Lv3/w0;->d:Z

    .line 59
    .line 60
    :try_start_0
    iget-object v0, p0, Lv3/w0;->b:Lrn/i;

    .line 61
    .line 62
    iget-object v3, v0, Lrn/i;->e:Ljava/lang/Object;

    .line 63
    .line 64
    check-cast v3, Lt1/j0;

    .line 65
    .line 66
    invoke-virtual {v3, p1}, Lt1/j0;->n(Lv3/h0;)Z

    .line 67
    .line 68
    .line 69
    iget-object v3, v0, Lrn/i;->f:Ljava/lang/Object;

    .line 70
    .line 71
    check-cast v3, Lt1/j0;

    .line 72
    .line 73
    invoke-virtual {v3, p1}, Lt1/j0;->n(Lv3/h0;)Z

    .line 74
    .line 75
    .line 76
    iget-object v0, v0, Lrn/i;->g:Ljava/lang/Object;

    .line 77
    .line 78
    check-cast v0, Lt1/j0;

    .line 79
    .line 80
    invoke-virtual {v0, p1}, Lt1/j0;->n(Lv3/h0;)Z

    .line 81
    .line 82
    .line 83
    new-instance v0, Lt4/a;

    .line 84
    .line 85
    invoke-direct {v0, p2, p3}, Lt4/a;-><init>(J)V

    .line 86
    .line 87
    .line 88
    invoke-static {p1, v0}, Lv3/w0;->b(Lv3/h0;Lt4/a;)Z

    .line 89
    .line 90
    .line 91
    move-result v0

    .line 92
    if-nez v0, :cond_5

    .line 93
    .line 94
    iget-object v0, p1, Lv3/h0;->I:Lv3/l0;

    .line 95
    .line 96
    iget-boolean v0, v0, Lv3/l0;->f:Z

    .line 97
    .line 98
    if-eqz v0, :cond_6

    .line 99
    .line 100
    :cond_5
    invoke-virtual {p1}, Lv3/h0;->K()Ljava/lang/Boolean;

    .line 101
    .line 102
    .line 103
    move-result-object v0

    .line 104
    sget-object v3, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 105
    .line 106
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 107
    .line 108
    .line 109
    move-result v0

    .line 110
    if-eqz v0, :cond_6

    .line 111
    .line 112
    invoke-virtual {p1}, Lv3/h0;->L()V

    .line 113
    .line 114
    .line 115
    goto :goto_0

    .line 116
    :catchall_0
    move-exception p1

    .line 117
    goto :goto_1

    .line 118
    :cond_6
    :goto_0
    invoke-virtual {p0, p1}, Lv3/w0;->e(Lv3/h0;)V

    .line 119
    .line 120
    .line 121
    new-instance v0, Lt4/a;

    .line 122
    .line 123
    invoke-direct {v0, p2, p3}, Lt4/a;-><init>(J)V

    .line 124
    .line 125
    .line 126
    invoke-static {p1, v0}, Lv3/w0;->c(Lv3/h0;Lt4/a;)Z

    .line 127
    .line 128
    .line 129
    invoke-virtual {p1}, Lv3/h0;->q()Z

    .line 130
    .line 131
    .line 132
    move-result p2

    .line 133
    if-eqz p2, :cond_7

    .line 134
    .line 135
    invoke-virtual {p1}, Lv3/h0;->J()Z

    .line 136
    .line 137
    .line 138
    move-result p2

    .line 139
    if-eqz p2, :cond_7

    .line 140
    .line 141
    invoke-virtual {p1}, Lv3/h0;->U()V

    .line 142
    .line 143
    .line 144
    iget-object p2, p0, Lv3/w0;->e:Lvp/y1;

    .line 145
    .line 146
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 147
    .line 148
    .line 149
    iget p3, p1, Lv3/h0;->R:I

    .line 150
    .line 151
    if-lez p3, :cond_7

    .line 152
    .line 153
    iget-object p2, p2, Lvp/y1;->e:Ljava/lang/Object;

    .line 154
    .line 155
    check-cast p2, Ln2/b;

    .line 156
    .line 157
    invoke-virtual {p2, p1}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 158
    .line 159
    .line 160
    iput-boolean v1, p1, Lv3/h0;->Q:Z

    .line 161
    .line 162
    :cond_7
    invoke-virtual {p0}, Lv3/w0;->d()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 163
    .line 164
    .line 165
    iput-boolean v2, p0, Lv3/w0;->c:Z

    .line 166
    .line 167
    iput-boolean v2, p0, Lv3/w0;->d:Z

    .line 168
    .line 169
    goto :goto_2

    .line 170
    :goto_1
    :try_start_1
    throw p1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 171
    :catchall_1
    move-exception p1

    .line 172
    iput-boolean v2, p0, Lv3/w0;->c:Z

    .line 173
    .line 174
    iput-boolean v2, p0, Lv3/w0;->d:Z

    .line 175
    .line 176
    throw p1

    .line 177
    :cond_8
    :goto_2
    iget-object p0, p0, Lv3/w0;->f:Ln2/b;

    .line 178
    .line 179
    iget-object p1, p0, Ln2/b;->d:[Ljava/lang/Object;

    .line 180
    .line 181
    iget p2, p0, Ln2/b;->f:I

    .line 182
    .line 183
    move p3, v2

    .line 184
    :goto_3
    if-ge p3, p2, :cond_14

    .line 185
    .line 186
    aget-object v0, p1, p3

    .line 187
    .line 188
    check-cast v0, Lv3/h0;

    .line 189
    .line 190
    iget-object v0, v0, Lv3/h0;->H:Lg1/q;

    .line 191
    .line 192
    iget-object v3, v0, Lg1/q;->d:Ljava/lang/Object;

    .line 193
    .line 194
    check-cast v3, Lv3/u;

    .line 195
    .line 196
    const/16 v4, 0x80

    .line 197
    .line 198
    invoke-static {v4}, Lv3/g1;->g(I)Z

    .line 199
    .line 200
    .line 201
    move-result v5

    .line 202
    if-eqz v5, :cond_9

    .line 203
    .line 204
    iget-object v6, v3, Lv3/u;->S:Lv3/z1;

    .line 205
    .line 206
    goto :goto_4

    .line 207
    :cond_9
    iget-object v6, v3, Lv3/u;->S:Lv3/z1;

    .line 208
    .line 209
    iget-object v6, v6, Lx2/r;->h:Lx2/r;

    .line 210
    .line 211
    if-nez v6, :cond_a

    .line 212
    .line 213
    goto/16 :goto_a

    .line 214
    .line 215
    :cond_a
    :goto_4
    sget-object v7, Lv3/f1;->N:Le3/k0;

    .line 216
    .line 217
    invoke-virtual {v3, v5}, Lv3/f1;->h1(Z)Lx2/r;

    .line 218
    .line 219
    .line 220
    move-result-object v3

    .line 221
    :goto_5
    if-eqz v3, :cond_13

    .line 222
    .line 223
    iget v5, v3, Lx2/r;->g:I

    .line 224
    .line 225
    and-int/2addr v5, v4

    .line 226
    if-eqz v5, :cond_13

    .line 227
    .line 228
    iget v5, v3, Lx2/r;->f:I

    .line 229
    .line 230
    and-int/2addr v5, v4

    .line 231
    if-eqz v5, :cond_12

    .line 232
    .line 233
    const/4 v5, 0x0

    .line 234
    move-object v7, v3

    .line 235
    move-object v8, v5

    .line 236
    :goto_6
    if-eqz v7, :cond_12

    .line 237
    .line 238
    instance-of v9, v7, Lv3/x;

    .line 239
    .line 240
    if-eqz v9, :cond_b

    .line 241
    .line 242
    check-cast v7, Lv3/x;

    .line 243
    .line 244
    iget-object v9, v0, Lg1/q;->d:Ljava/lang/Object;

    .line 245
    .line 246
    check-cast v9, Lv3/u;

    .line 247
    .line 248
    invoke-interface {v7, v9}, Lv3/x;->R(Lt3/y;)V

    .line 249
    .line 250
    .line 251
    goto :goto_9

    .line 252
    :cond_b
    iget v9, v7, Lx2/r;->f:I

    .line 253
    .line 254
    and-int/2addr v9, v4

    .line 255
    if-eqz v9, :cond_11

    .line 256
    .line 257
    instance-of v9, v7, Lv3/n;

    .line 258
    .line 259
    if-eqz v9, :cond_11

    .line 260
    .line 261
    move-object v9, v7

    .line 262
    check-cast v9, Lv3/n;

    .line 263
    .line 264
    iget-object v9, v9, Lv3/n;->s:Lx2/r;

    .line 265
    .line 266
    move v10, v2

    .line 267
    :goto_7
    if-eqz v9, :cond_10

    .line 268
    .line 269
    iget v11, v9, Lx2/r;->f:I

    .line 270
    .line 271
    and-int/2addr v11, v4

    .line 272
    if-eqz v11, :cond_f

    .line 273
    .line 274
    add-int/lit8 v10, v10, 0x1

    .line 275
    .line 276
    if-ne v10, v1, :cond_c

    .line 277
    .line 278
    move-object v7, v9

    .line 279
    goto :goto_8

    .line 280
    :cond_c
    if-nez v8, :cond_d

    .line 281
    .line 282
    new-instance v8, Ln2/b;

    .line 283
    .line 284
    const/16 v11, 0x10

    .line 285
    .line 286
    new-array v11, v11, [Lx2/r;

    .line 287
    .line 288
    invoke-direct {v8, v11}, Ln2/b;-><init>([Ljava/lang/Object;)V

    .line 289
    .line 290
    .line 291
    :cond_d
    if-eqz v7, :cond_e

    .line 292
    .line 293
    invoke-virtual {v8, v7}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 294
    .line 295
    .line 296
    move-object v7, v5

    .line 297
    :cond_e
    invoke-virtual {v8, v9}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 298
    .line 299
    .line 300
    :cond_f
    :goto_8
    iget-object v9, v9, Lx2/r;->i:Lx2/r;

    .line 301
    .line 302
    goto :goto_7

    .line 303
    :cond_10
    if-ne v10, v1, :cond_11

    .line 304
    .line 305
    goto :goto_6

    .line 306
    :cond_11
    :goto_9
    invoke-static {v8}, Lv3/f;->f(Ln2/b;)Lx2/r;

    .line 307
    .line 308
    .line 309
    move-result-object v7

    .line 310
    goto :goto_6

    .line 311
    :cond_12
    if-eq v3, v6, :cond_13

    .line 312
    .line 313
    iget-object v3, v3, Lx2/r;->i:Lx2/r;

    .line 314
    .line 315
    goto :goto_5

    .line 316
    :cond_13
    :goto_a
    add-int/lit8 p3, p3, 0x1

    .line 317
    .line 318
    goto/16 :goto_3

    .line 319
    .line 320
    :cond_14
    invoke-virtual {p0}, Ln2/b;->i()V

    .line 321
    .line 322
    .line 323
    return-void
.end method

.method public final l()V
    .locals 5

    .line 1
    iget-object v0, p0, Lv3/w0;->b:Lrn/i;

    .line 2
    .line 3
    invoke-virtual {v0}, Lrn/i;->w()Z

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    if-eqz v1, :cond_5

    .line 8
    .line 9
    iget-object v1, p0, Lv3/w0;->a:Lv3/h0;

    .line 10
    .line 11
    invoke-virtual {v1}, Lv3/h0;->I()Z

    .line 12
    .line 13
    .line 14
    move-result v2

    .line 15
    if-nez v2, :cond_0

    .line 16
    .line 17
    const-string v2, "performMeasureAndLayout called with unattached root"

    .line 18
    .line 19
    invoke-static {v2}, Ls3/a;->a(Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    :cond_0
    invoke-virtual {v1}, Lv3/h0;->J()Z

    .line 23
    .line 24
    .line 25
    move-result v2

    .line 26
    if-nez v2, :cond_1

    .line 27
    .line 28
    const-string v2, "performMeasureAndLayout called with unplaced root"

    .line 29
    .line 30
    invoke-static {v2}, Ls3/a;->a(Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    :cond_1
    iget-boolean v2, p0, Lv3/w0;->c:Z

    .line 34
    .line 35
    if-eqz v2, :cond_2

    .line 36
    .line 37
    const-string v2, "performMeasureAndLayout called during measure layout"

    .line 38
    .line 39
    invoke-static {v2}, Ls3/a;->a(Ljava/lang/String;)V

    .line 40
    .line 41
    .line 42
    :cond_2
    iget-object v2, p0, Lv3/w0;->i:Lt4/a;

    .line 43
    .line 44
    if-eqz v2, :cond_5

    .line 45
    .line 46
    const/4 v2, 0x1

    .line 47
    iput-boolean v2, p0, Lv3/w0;->c:Z

    .line 48
    .line 49
    const/4 v3, 0x0

    .line 50
    iput-boolean v3, p0, Lv3/w0;->d:Z

    .line 51
    .line 52
    :try_start_0
    iget-object v4, v0, Lrn/i;->g:Ljava/lang/Object;

    .line 53
    .line 54
    check-cast v4, Lt1/j0;

    .line 55
    .line 56
    iget-object v4, v4, Lt1/j0;->e:Ljava/lang/Object;

    .line 57
    .line 58
    check-cast v4, Lv3/y1;

    .line 59
    .line 60
    invoke-virtual {v4}, Ljava/util/AbstractCollection;->isEmpty()Z

    .line 61
    .line 62
    .line 63
    move-result v4

    .line 64
    if-nez v4, :cond_4

    .line 65
    .line 66
    iget-object v0, v0, Lrn/i;->e:Ljava/lang/Object;

    .line 67
    .line 68
    check-cast v0, Lt1/j0;

    .line 69
    .line 70
    iget-object v0, v0, Lt1/j0;->e:Ljava/lang/Object;

    .line 71
    .line 72
    check-cast v0, Lv3/y1;

    .line 73
    .line 74
    invoke-virtual {v0}, Ljava/util/AbstractCollection;->isEmpty()Z

    .line 75
    .line 76
    .line 77
    move-result v0

    .line 78
    if-nez v0, :cond_4

    .line 79
    .line 80
    iget-object v0, v1, Lv3/h0;->j:Lv3/h0;

    .line 81
    .line 82
    if-eqz v0, :cond_3

    .line 83
    .line 84
    invoke-virtual {p0, v1, v2}, Lv3/w0;->o(Lv3/h0;Z)V

    .line 85
    .line 86
    .line 87
    goto :goto_0

    .line 88
    :catchall_0
    move-exception v0

    .line 89
    goto :goto_1

    .line 90
    :cond_3
    invoke-virtual {p0, v1}, Lv3/w0;->n(Lv3/h0;)V

    .line 91
    .line 92
    .line 93
    :cond_4
    :goto_0
    invoke-virtual {p0, v1, v3}, Lv3/w0;->o(Lv3/h0;Z)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 94
    .line 95
    .line 96
    iput-boolean v3, p0, Lv3/w0;->c:Z

    .line 97
    .line 98
    iput-boolean v3, p0, Lv3/w0;->d:Z

    .line 99
    .line 100
    return-void

    .line 101
    :goto_1
    :try_start_1
    throw v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 102
    :catchall_1
    move-exception v0

    .line 103
    iput-boolean v3, p0, Lv3/w0;->c:Z

    .line 104
    .line 105
    iput-boolean v3, p0, Lv3/w0;->d:Z

    .line 106
    .line 107
    throw v0

    .line 108
    :cond_5
    return-void
.end method

.method public final m(Lv3/h0;ZZ)Z
    .locals 5

    .line 1
    iget-boolean v0, p1, Lv3/h0;->S:Z

    .line 2
    .line 3
    iget-object v1, p1, Lv3/h0;->I:Lv3/l0;

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    if-eqz v0, :cond_0

    .line 7
    .line 8
    goto :goto_0

    .line 9
    :cond_0
    invoke-virtual {p1}, Lv3/h0;->J()Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    const/4 v3, 0x1

    .line 14
    if-nez v0, :cond_2

    .line 15
    .line 16
    iget-object v0, v1, Lv3/l0;->p:Lv3/y0;

    .line 17
    .line 18
    iget-boolean v0, v0, Lv3/y0;->x:Z

    .line 19
    .line 20
    if-nez v0, :cond_2

    .line 21
    .line 22
    invoke-static {p1}, Lv3/w0;->i(Lv3/h0;)Z

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    if-nez v0, :cond_2

    .line 27
    .line 28
    invoke-virtual {p1}, Lv3/h0;->K()Ljava/lang/Boolean;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    sget-object v4, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 33
    .line 34
    invoke-static {v0, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 35
    .line 36
    .line 37
    move-result v0

    .line 38
    if-nez v0, :cond_2

    .line 39
    .line 40
    invoke-static {p1}, Lv3/w0;->h(Lv3/h0;)Z

    .line 41
    .line 42
    .line 43
    move-result v0

    .line 44
    if-nez v0, :cond_2

    .line 45
    .line 46
    iget-object v0, v1, Lv3/l0;->p:Lv3/y0;

    .line 47
    .line 48
    iget-object v0, v0, Lv3/y0;->B:Lv3/i0;

    .line 49
    .line 50
    invoke-virtual {v0}, Lv3/i0;->e()Z

    .line 51
    .line 52
    .line 53
    move-result v0

    .line 54
    if-nez v0, :cond_2

    .line 55
    .line 56
    iget-object v0, v1, Lv3/l0;->q:Lv3/u0;

    .line 57
    .line 58
    if-eqz v0, :cond_1

    .line 59
    .line 60
    iget-object v0, v0, Lv3/u0;->v:Lv3/i0;

    .line 61
    .line 62
    if-eqz v0, :cond_1

    .line 63
    .line 64
    invoke-virtual {v0}, Lv3/i0;->e()Z

    .line 65
    .line 66
    .line 67
    move-result v0

    .line 68
    if-ne v0, v3, :cond_1

    .line 69
    .line 70
    goto :goto_1

    .line 71
    :cond_1
    :goto_0
    return v2

    .line 72
    :cond_2
    :goto_1
    iget-object v0, p0, Lv3/w0;->a:Lv3/h0;

    .line 73
    .line 74
    if-ne p1, v0, :cond_3

    .line 75
    .line 76
    iget-object v4, p0, Lv3/w0;->i:Lt4/a;

    .line 77
    .line 78
    invoke-static {v4}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 79
    .line 80
    .line 81
    goto :goto_2

    .line 82
    :cond_3
    const/4 v4, 0x0

    .line 83
    :goto_2
    if-eqz p2, :cond_6

    .line 84
    .line 85
    iget-boolean p2, v1, Lv3/l0;->e:Z

    .line 86
    .line 87
    if-eqz p2, :cond_4

    .line 88
    .line 89
    invoke-static {p1, v4}, Lv3/w0;->b(Lv3/h0;Lt4/a;)Z

    .line 90
    .line 91
    .line 92
    move-result v2

    .line 93
    :cond_4
    if-eqz p3, :cond_f

    .line 94
    .line 95
    if-nez v2, :cond_5

    .line 96
    .line 97
    iget-boolean p2, v1, Lv3/l0;->f:Z

    .line 98
    .line 99
    if-eqz p2, :cond_f

    .line 100
    .line 101
    :cond_5
    invoke-virtual {p1}, Lv3/h0;->K()Ljava/lang/Boolean;

    .line 102
    .line 103
    .line 104
    move-result-object p2

    .line 105
    sget-object p3, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 106
    .line 107
    invoke-static {p2, p3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 108
    .line 109
    .line 110
    move-result p2

    .line 111
    if-eqz p2, :cond_f

    .line 112
    .line 113
    invoke-virtual {p1}, Lv3/h0;->L()V

    .line 114
    .line 115
    .line 116
    goto/16 :goto_5

    .line 117
    .line 118
    :cond_6
    invoke-virtual {p1}, Lv3/h0;->r()Z

    .line 119
    .line 120
    .line 121
    move-result p2

    .line 122
    if-eqz p2, :cond_7

    .line 123
    .line 124
    invoke-static {p1, v4}, Lv3/w0;->c(Lv3/h0;Lt4/a;)Z

    .line 125
    .line 126
    .line 127
    move-result p2

    .line 128
    goto :goto_3

    .line 129
    :cond_7
    move p2, v2

    .line 130
    :goto_3
    if-eqz p3, :cond_e

    .line 131
    .line 132
    invoke-virtual {p1}, Lv3/h0;->q()Z

    .line 133
    .line 134
    .line 135
    move-result p3

    .line 136
    if-eqz p3, :cond_e

    .line 137
    .line 138
    if-eq p1, v0, :cond_8

    .line 139
    .line 140
    invoke-virtual {p1}, Lv3/h0;->v()Lv3/h0;

    .line 141
    .line 142
    .line 143
    move-result-object p3

    .line 144
    if-eqz p3, :cond_e

    .line 145
    .line 146
    invoke-virtual {p3}, Lv3/h0;->J()Z

    .line 147
    .line 148
    .line 149
    move-result p3

    .line 150
    if-ne p3, v3, :cond_e

    .line 151
    .line 152
    iget-object p3, v1, Lv3/l0;->p:Lv3/y0;

    .line 153
    .line 154
    iget-boolean p3, p3, Lv3/y0;->x:Z

    .line 155
    .line 156
    if-eqz p3, :cond_e

    .line 157
    .line 158
    :cond_8
    if-ne p1, v0, :cond_c

    .line 159
    .line 160
    iget-object p3, p1, Lv3/h0;->E:Lv3/f0;

    .line 161
    .line 162
    sget-object v0, Lv3/f0;->f:Lv3/f0;

    .line 163
    .line 164
    if-ne p3, v0, :cond_9

    .line 165
    .line 166
    invoke-virtual {p1}, Lv3/h0;->g()V

    .line 167
    .line 168
    .line 169
    :cond_9
    invoke-virtual {p1}, Lv3/h0;->v()Lv3/h0;

    .line 170
    .line 171
    .line 172
    move-result-object p3

    .line 173
    if-eqz p3, :cond_a

    .line 174
    .line 175
    iget-object p3, p3, Lv3/h0;->H:Lg1/q;

    .line 176
    .line 177
    iget-object p3, p3, Lg1/q;->d:Ljava/lang/Object;

    .line 178
    .line 179
    check-cast p3, Lv3/u;

    .line 180
    .line 181
    if-eqz p3, :cond_a

    .line 182
    .line 183
    iget-object p3, p3, Lv3/p0;->o:Lt3/n0;

    .line 184
    .line 185
    if-nez p3, :cond_b

    .line 186
    .line 187
    :cond_a
    invoke-static {p1}, Lv3/k0;->a(Lv3/h0;)Lv3/o1;

    .line 188
    .line 189
    .line 190
    move-result-object p3

    .line 191
    check-cast p3, Lw3/t;

    .line 192
    .line 193
    invoke-virtual {p3}, Lw3/t;->getPlacementScope()Lt3/d1;

    .line 194
    .line 195
    .line 196
    move-result-object p3

    .line 197
    :cond_b
    iget-object v0, v1, Lv3/l0;->p:Lv3/y0;

    .line 198
    .line 199
    invoke-static {p3, v0, v2, v2}, Lt3/d1;->l(Lt3/d1;Lt3/e1;II)V

    .line 200
    .line 201
    .line 202
    goto :goto_4

    .line 203
    :cond_c
    invoke-virtual {p1}, Lv3/h0;->U()V

    .line 204
    .line 205
    .line 206
    :goto_4
    iget-object p3, p0, Lv3/w0;->e:Lvp/y1;

    .line 207
    .line 208
    invoke-virtual {p3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 209
    .line 210
    .line 211
    iget v0, p1, Lv3/h0;->R:I

    .line 212
    .line 213
    if-lez v0, :cond_d

    .line 214
    .line 215
    iget-object p3, p3, Lvp/y1;->e:Ljava/lang/Object;

    .line 216
    .line 217
    check-cast p3, Ln2/b;

    .line 218
    .line 219
    invoke-virtual {p3, p1}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 220
    .line 221
    .line 222
    iput-boolean v3, p1, Lv3/h0;->Q:Z

    .line 223
    .line 224
    :cond_d
    invoke-static {p1}, Lv3/k0;->a(Lv3/h0;)Lv3/o1;

    .line 225
    .line 226
    .line 227
    move-result-object p3

    .line 228
    check-cast p3, Lw3/t;

    .line 229
    .line 230
    invoke-virtual {p3}, Lw3/t;->getRectManager()Le4/a;

    .line 231
    .line 232
    .line 233
    move-result-object p3

    .line 234
    invoke-virtual {p3, p1}, Le4/a;->e(Lv3/h0;)V

    .line 235
    .line 236
    .line 237
    :cond_e
    move v2, p2

    .line 238
    :cond_f
    :goto_5
    invoke-virtual {p0}, Lv3/w0;->d()V

    .line 239
    .line 240
    .line 241
    return v2
.end method

.method public final n(Lv3/h0;)V
    .locals 5

    .line 1
    invoke-virtual {p1}, Lv3/h0;->z()Ln2/b;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    iget-object v0, p1, Ln2/b;->d:[Ljava/lang/Object;

    .line 6
    .line 7
    iget p1, p1, Ln2/b;->f:I

    .line 8
    .line 9
    const/4 v1, 0x0

    .line 10
    :goto_0
    if-ge v1, p1, :cond_3

    .line 11
    .line 12
    aget-object v2, v0, v1

    .line 13
    .line 14
    check-cast v2, Lv3/h0;

    .line 15
    .line 16
    invoke-virtual {v2}, Lv3/h0;->s()Lv3/f0;

    .line 17
    .line 18
    .line 19
    move-result-object v3

    .line 20
    sget-object v4, Lv3/f0;->d:Lv3/f0;

    .line 21
    .line 22
    if-eq v3, v4, :cond_0

    .line 23
    .line 24
    iget-object v3, v2, Lv3/h0;->I:Lv3/l0;

    .line 25
    .line 26
    iget-object v3, v3, Lv3/l0;->p:Lv3/y0;

    .line 27
    .line 28
    iget-object v3, v3, Lv3/y0;->B:Lv3/i0;

    .line 29
    .line 30
    invoke-virtual {v3}, Lv3/i0;->e()Z

    .line 31
    .line 32
    .line 33
    move-result v3

    .line 34
    if-eqz v3, :cond_2

    .line 35
    .line 36
    :cond_0
    invoke-static {v2}, Lv3/f;->s(Lv3/h0;)Z

    .line 37
    .line 38
    .line 39
    move-result v3

    .line 40
    if-eqz v3, :cond_1

    .line 41
    .line 42
    const/4 v3, 0x1

    .line 43
    invoke-virtual {p0, v2, v3}, Lv3/w0;->o(Lv3/h0;Z)V

    .line 44
    .line 45
    .line 46
    goto :goto_1

    .line 47
    :cond_1
    invoke-virtual {p0, v2}, Lv3/w0;->n(Lv3/h0;)V

    .line 48
    .line 49
    .line 50
    :cond_2
    :goto_1
    add-int/lit8 v1, v1, 0x1

    .line 51
    .line 52
    goto :goto_0

    .line 53
    :cond_3
    return-void
.end method

.method public final o(Lv3/h0;Z)V
    .locals 1

    .line 1
    iget-boolean v0, p1, Lv3/h0;->S:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    iget-object v0, p0, Lv3/w0;->a:Lv3/h0;

    .line 7
    .line 8
    if-ne p1, v0, :cond_1

    .line 9
    .line 10
    iget-object p0, p0, Lv3/w0;->i:Lt4/a;

    .line 11
    .line 12
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 13
    .line 14
    .line 15
    goto :goto_0

    .line 16
    :cond_1
    const/4 p0, 0x0

    .line 17
    :goto_0
    if-eqz p2, :cond_2

    .line 18
    .line 19
    invoke-static {p1, p0}, Lv3/w0;->b(Lv3/h0;Lt4/a;)Z

    .line 20
    .line 21
    .line 22
    return-void

    .line 23
    :cond_2
    invoke-static {p1, p0}, Lv3/w0;->c(Lv3/h0;Lt4/a;)Z

    .line 24
    .line 25
    .line 26
    return-void
.end method

.method public final p(Lv3/h0;Z)Z
    .locals 4

    .line 1
    iget-object v0, p1, Lv3/h0;->I:Lv3/l0;

    .line 2
    .line 3
    iget-object v0, v0, Lv3/l0;->d:Lv3/d0;

    .line 4
    .line 5
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    const/4 v1, 0x0

    .line 10
    if-eqz v0, :cond_6

    .line 11
    .line 12
    const/4 v2, 0x1

    .line 13
    if-eq v0, v2, :cond_6

    .line 14
    .line 15
    const/4 v3, 0x2

    .line 16
    if-eq v0, v3, :cond_5

    .line 17
    .line 18
    const/4 v3, 0x3

    .line 19
    if-eq v0, v3, :cond_5

    .line 20
    .line 21
    const/4 v3, 0x4

    .line 22
    if-ne v0, v3, :cond_4

    .line 23
    .line 24
    invoke-virtual {p1}, Lv3/h0;->r()Z

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    if-eqz v0, :cond_0

    .line 29
    .line 30
    if-nez p2, :cond_0

    .line 31
    .line 32
    goto :goto_1

    .line 33
    :cond_0
    iget-object p2, p1, Lv3/h0;->I:Lv3/l0;

    .line 34
    .line 35
    iget-object p2, p2, Lv3/l0;->p:Lv3/y0;

    .line 36
    .line 37
    iput-boolean v2, p2, Lv3/y0;->y:Z

    .line 38
    .line 39
    iget-boolean p2, p1, Lv3/h0;->S:Z

    .line 40
    .line 41
    if-eqz p2, :cond_1

    .line 42
    .line 43
    goto :goto_1

    .line 44
    :cond_1
    invoke-virtual {p1}, Lv3/h0;->J()Z

    .line 45
    .line 46
    .line 47
    move-result p2

    .line 48
    if-nez p2, :cond_2

    .line 49
    .line 50
    invoke-static {p1}, Lv3/w0;->i(Lv3/h0;)Z

    .line 51
    .line 52
    .line 53
    move-result p2

    .line 54
    if-eqz p2, :cond_6

    .line 55
    .line 56
    :cond_2
    invoke-virtual {p1}, Lv3/h0;->v()Lv3/h0;

    .line 57
    .line 58
    .line 59
    move-result-object p2

    .line 60
    if-eqz p2, :cond_3

    .line 61
    .line 62
    invoke-virtual {p2}, Lv3/h0;->r()Z

    .line 63
    .line 64
    .line 65
    move-result p2

    .line 66
    if-ne p2, v2, :cond_3

    .line 67
    .line 68
    goto :goto_0

    .line 69
    :cond_3
    iget-object p2, p0, Lv3/w0;->b:Lrn/i;

    .line 70
    .line 71
    sget-object v0, Lv3/v;->f:Lv3/v;

    .line 72
    .line 73
    invoke-virtual {p2, p1, v0}, Lrn/i;->n(Lv3/h0;Lv3/v;)V

    .line 74
    .line 75
    .line 76
    :goto_0
    iget-boolean p0, p0, Lv3/w0;->d:Z

    .line 77
    .line 78
    if-nez p0, :cond_6

    .line 79
    .line 80
    return v2

    .line 81
    :cond_4
    new-instance p0, La8/r0;

    .line 82
    .line 83
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 84
    .line 85
    .line 86
    throw p0

    .line 87
    :cond_5
    new-instance v0, Lv3/v0;

    .line 88
    .line 89
    invoke-direct {v0, p1, v1, p2}, Lv3/v0;-><init>(Lv3/h0;ZZ)V

    .line 90
    .line 91
    .line 92
    iget-object p0, p0, Lv3/w0;->h:Ln2/b;

    .line 93
    .line 94
    invoke-virtual {p0, v0}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 95
    .line 96
    .line 97
    :cond_6
    :goto_1
    return v1
.end method

.method public final q(J)V
    .locals 2

    .line 1
    iget-object v0, p0, Lv3/w0;->i:Lt4/a;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    const/4 v0, 0x0

    .line 6
    goto :goto_0

    .line 7
    :cond_0
    iget-wide v0, v0, Lt4/a;->a:J

    .line 8
    .line 9
    invoke-static {v0, v1, p1, p2}, Lt4/a;->b(JJ)Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    :goto_0
    if-nez v0, :cond_4

    .line 14
    .line 15
    iget-boolean v0, p0, Lv3/w0;->c:Z

    .line 16
    .line 17
    if-eqz v0, :cond_1

    .line 18
    .line 19
    const-string v0, "updateRootConstraints called while measuring"

    .line 20
    .line 21
    invoke-static {v0}, Ls3/a;->a(Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    :cond_1
    new-instance v0, Lt4/a;

    .line 25
    .line 26
    invoke-direct {v0, p1, p2}, Lt4/a;-><init>(J)V

    .line 27
    .line 28
    .line 29
    iput-object v0, p0, Lv3/w0;->i:Lt4/a;

    .line 30
    .line 31
    iget-object p1, p0, Lv3/w0;->a:Lv3/h0;

    .line 32
    .line 33
    iget-object p2, p1, Lv3/h0;->j:Lv3/h0;

    .line 34
    .line 35
    iget-object v0, p1, Lv3/h0;->I:Lv3/l0;

    .line 36
    .line 37
    const/4 v1, 0x1

    .line 38
    if-eqz p2, :cond_2

    .line 39
    .line 40
    iput-boolean v1, v0, Lv3/l0;->e:Z

    .line 41
    .line 42
    :cond_2
    iget-object v0, v0, Lv3/l0;->p:Lv3/y0;

    .line 43
    .line 44
    iput-boolean v1, v0, Lv3/y0;->y:Z

    .line 45
    .line 46
    if-eqz p2, :cond_3

    .line 47
    .line 48
    sget-object p2, Lv3/v;->d:Lv3/v;

    .line 49
    .line 50
    goto :goto_1

    .line 51
    :cond_3
    sget-object p2, Lv3/v;->f:Lv3/v;

    .line 52
    .line 53
    :goto_1
    iget-object p0, p0, Lv3/w0;->b:Lrn/i;

    .line 54
    .line 55
    invoke-virtual {p0, p1, p2}, Lrn/i;->n(Lv3/h0;Lv3/v;)V

    .line 56
    .line 57
    .line 58
    :cond_4
    return-void
.end method
