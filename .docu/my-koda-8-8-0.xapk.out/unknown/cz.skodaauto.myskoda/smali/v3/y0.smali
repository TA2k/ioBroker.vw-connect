.class public final Lv3/y0;
.super Lt3/e1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lt3/p0;
.implements Lv3/a;
.implements Lv3/a1;


# instance fields
.field public A:Z

.field public final B:Lv3/i0;

.field public final C:Ln2/b;

.field public D:Z

.field public E:Z

.field public F:J

.field public final G:Lv3/x0;

.field public final H:Lv3/x0;

.field public I:F

.field public J:Z

.field public K:Lay0/k;

.field public L:Lh3/c;

.field public M:J

.field public N:F

.field public final O:Lv3/x0;

.field public P:Z

.field public final i:Lv3/l0;

.field public j:Z

.field public k:I

.field public l:I

.field public m:Z

.field public n:Z

.field public o:Lv3/f0;

.field public p:Z

.field public q:J

.field public r:Lay0/k;

.field public s:Lh3/c;

.field public t:F

.field public u:Z

.field public v:Ljava/lang/Object;

.field public w:Z

.field public x:Z

.field public y:Z

.field public z:Z


# direct methods
.method public constructor <init>(Lv3/l0;)V
    .locals 4

    .line 1
    invoke-direct {p0}, Lt3/e1;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lv3/y0;->i:Lv3/l0;

    .line 5
    .line 6
    const p1, 0x7fffffff

    .line 7
    .line 8
    .line 9
    iput p1, p0, Lv3/y0;->k:I

    .line 10
    .line 11
    iput p1, p0, Lv3/y0;->l:I

    .line 12
    .line 13
    sget-object p1, Lv3/f0;->f:Lv3/f0;

    .line 14
    .line 15
    iput-object p1, p0, Lv3/y0;->o:Lv3/f0;

    .line 16
    .line 17
    const-wide/16 v0, 0x0

    .line 18
    .line 19
    iput-wide v0, p0, Lv3/y0;->q:J

    .line 20
    .line 21
    const/4 p1, 0x1

    .line 22
    iput-boolean p1, p0, Lv3/y0;->u:Z

    .line 23
    .line 24
    new-instance v2, Lv3/i0;

    .line 25
    .line 26
    const/4 v3, 0x0

    .line 27
    invoke-direct {v2, p0, v3}, Lv3/i0;-><init>(Lv3/a;I)V

    .line 28
    .line 29
    .line 30
    iput-object v2, p0, Lv3/y0;->B:Lv3/i0;

    .line 31
    .line 32
    new-instance v2, Ln2/b;

    .line 33
    .line 34
    const/16 v3, 0x10

    .line 35
    .line 36
    new-array v3, v3, [Lv3/y0;

    .line 37
    .line 38
    invoke-direct {v2, v3}, Ln2/b;-><init>([Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    iput-object v2, p0, Lv3/y0;->C:Ln2/b;

    .line 42
    .line 43
    iput-boolean p1, p0, Lv3/y0;->D:Z

    .line 44
    .line 45
    const/4 p1, 0x0

    .line 46
    const/16 v2, 0xf

    .line 47
    .line 48
    invoke-static {p1, p1, v2}, Lt4/b;->b(III)J

    .line 49
    .line 50
    .line 51
    move-result-wide v2

    .line 52
    iput-wide v2, p0, Lv3/y0;->F:J

    .line 53
    .line 54
    new-instance p1, Lv3/x0;

    .line 55
    .line 56
    const/4 v2, 0x1

    .line 57
    invoke-direct {p1, p0, v2}, Lv3/x0;-><init>(Lv3/y0;I)V

    .line 58
    .line 59
    .line 60
    iput-object p1, p0, Lv3/y0;->G:Lv3/x0;

    .line 61
    .line 62
    new-instance p1, Lv3/x0;

    .line 63
    .line 64
    const/4 v2, 0x0

    .line 65
    invoke-direct {p1, p0, v2}, Lv3/x0;-><init>(Lv3/y0;I)V

    .line 66
    .line 67
    .line 68
    iput-object p1, p0, Lv3/y0;->H:Lv3/x0;

    .line 69
    .line 70
    iput-wide v0, p0, Lv3/y0;->M:J

    .line 71
    .line 72
    new-instance p1, Lv3/x0;

    .line 73
    .line 74
    const/4 v0, 0x2

    .line 75
    invoke-direct {p1, p0, v0}, Lv3/x0;-><init>(Lv3/y0;I)V

    .line 76
    .line 77
    .line 78
    iput-object p1, p0, Lv3/y0;->O:Lv3/x0;

    .line 79
    .line 80
    return-void
.end method


# virtual methods
.method public final A(I)I
    .locals 2

    .line 1
    iget-object v0, p0, Lv3/y0;->i:Lv3/l0;

    .line 2
    .line 3
    iget-object v1, v0, Lv3/l0;->a:Lv3/h0;

    .line 4
    .line 5
    invoke-static {v1}, Lv3/f;->s(Lv3/h0;)Z

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    if-eqz v1, :cond_0

    .line 10
    .line 11
    iget-object p0, v0, Lv3/l0;->q:Lv3/u0;

    .line 12
    .line 13
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {p0, p1}, Lv3/u0;->A(I)I

    .line 17
    .line 18
    .line 19
    move-result p0

    .line 20
    return p0

    .line 21
    :cond_0
    invoke-virtual {p0}, Lv3/y0;->H0()V

    .line 22
    .line 23
    .line 24
    invoke-virtual {v0}, Lv3/l0;->a()Lv3/f1;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    invoke-interface {p0, p1}, Lt3/p0;->A(I)I

    .line 29
    .line 30
    .line 31
    move-result p0

    .line 32
    return p0
.end method

.method public final B0()Ljava/util/List;
    .locals 9

    .line 1
    iget-object v0, p0, Lv3/y0;->i:Lv3/l0;

    .line 2
    .line 3
    iget-object v1, v0, Lv3/l0;->a:Lv3/h0;

    .line 4
    .line 5
    invoke-virtual {v1}, Lv3/h0;->k0()V

    .line 6
    .line 7
    .line 8
    iget-boolean v1, p0, Lv3/y0;->D:Z

    .line 9
    .line 10
    iget-object v2, p0, Lv3/y0;->C:Ln2/b;

    .line 11
    .line 12
    if-nez v1, :cond_0

    .line 13
    .line 14
    invoke-virtual {v2}, Ln2/b;->h()Ljava/util/List;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    return-object p0

    .line 19
    :cond_0
    iget-object v0, v0, Lv3/l0;->a:Lv3/h0;

    .line 20
    .line 21
    invoke-virtual {v0}, Lv3/h0;->z()Ln2/b;

    .line 22
    .line 23
    .line 24
    move-result-object v1

    .line 25
    iget-object v3, v1, Ln2/b;->d:[Ljava/lang/Object;

    .line 26
    .line 27
    iget v1, v1, Ln2/b;->f:I

    .line 28
    .line 29
    const/4 v4, 0x0

    .line 30
    move v5, v4

    .line 31
    :goto_0
    if-ge v5, v1, :cond_2

    .line 32
    .line 33
    aget-object v6, v3, v5

    .line 34
    .line 35
    check-cast v6, Lv3/h0;

    .line 36
    .line 37
    iget v7, v2, Ln2/b;->f:I

    .line 38
    .line 39
    if-gt v7, v5, :cond_1

    .line 40
    .line 41
    iget-object v6, v6, Lv3/h0;->I:Lv3/l0;

    .line 42
    .line 43
    iget-object v6, v6, Lv3/l0;->p:Lv3/y0;

    .line 44
    .line 45
    invoke-virtual {v2, v6}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 46
    .line 47
    .line 48
    goto :goto_1

    .line 49
    :cond_1
    iget-object v6, v6, Lv3/h0;->I:Lv3/l0;

    .line 50
    .line 51
    iget-object v6, v6, Lv3/l0;->p:Lv3/y0;

    .line 52
    .line 53
    iget-object v7, v2, Ln2/b;->d:[Ljava/lang/Object;

    .line 54
    .line 55
    aget-object v8, v7, v5

    .line 56
    .line 57
    aput-object v6, v7, v5

    .line 58
    .line 59
    :goto_1
    add-int/lit8 v5, v5, 0x1

    .line 60
    .line 61
    goto :goto_0

    .line 62
    :cond_2
    invoke-virtual {v0}, Lv3/h0;->o()Ljava/util/List;

    .line 63
    .line 64
    .line 65
    move-result-object v0

    .line 66
    check-cast v0, Landroidx/collection/j0;

    .line 67
    .line 68
    iget-object v0, v0, Landroidx/collection/j0;->e:Ljava/lang/Object;

    .line 69
    .line 70
    check-cast v0, Ln2/b;

    .line 71
    .line 72
    iget v0, v0, Ln2/b;->f:I

    .line 73
    .line 74
    iget v1, v2, Ln2/b;->f:I

    .line 75
    .line 76
    invoke-virtual {v2, v0, v1}, Ln2/b;->n(II)V

    .line 77
    .line 78
    .line 79
    iput-boolean v4, p0, Lv3/y0;->D:Z

    .line 80
    .line 81
    invoke-virtual {v2}, Ln2/b;->h()Ljava/util/List;

    .line 82
    .line 83
    .line 84
    move-result-object p0

    .line 85
    return-object p0
.end method

.method public final C0()V
    .locals 5

    .line 1
    iget-boolean v0, p0, Lv3/y0;->w:Z

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    iput-boolean v1, p0, Lv3/y0;->w:Z

    .line 5
    .line 6
    iget-object p0, p0, Lv3/y0;->i:Lv3/l0;

    .line 7
    .line 8
    iget-object p0, p0, Lv3/l0;->a:Lv3/h0;

    .line 9
    .line 10
    iget-object v2, p0, Lv3/h0;->H:Lg1/q;

    .line 11
    .line 12
    if-nez v0, :cond_1

    .line 13
    .line 14
    iget-object v0, v2, Lg1/q;->d:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast v0, Lv3/u;

    .line 17
    .line 18
    invoke-virtual {v0}, Lv3/f1;->r1()V

    .line 19
    .line 20
    .line 21
    invoke-virtual {p0}, Lv3/h0;->r()Z

    .line 22
    .line 23
    .line 24
    move-result v0

    .line 25
    const/4 v3, 0x6

    .line 26
    if-eqz v0, :cond_0

    .line 27
    .line 28
    invoke-static {p0, v1, v3}, Lv3/h0;->Y(Lv3/h0;ZI)V

    .line 29
    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_0
    iget-object v0, p0, Lv3/h0;->I:Lv3/l0;

    .line 33
    .line 34
    iget-boolean v0, v0, Lv3/l0;->e:Z

    .line 35
    .line 36
    if-eqz v0, :cond_1

    .line 37
    .line 38
    invoke-static {p0, v1, v3}, Lv3/h0;->W(Lv3/h0;ZI)V

    .line 39
    .line 40
    .line 41
    :cond_1
    :goto_0
    iget-object v0, v2, Lg1/q;->e:Ljava/lang/Object;

    .line 42
    .line 43
    check-cast v0, Lv3/f1;

    .line 44
    .line 45
    iget-object v1, v2, Lg1/q;->d:Ljava/lang/Object;

    .line 46
    .line 47
    check-cast v1, Lv3/u;

    .line 48
    .line 49
    iget-object v1, v1, Lv3/f1;->s:Lv3/f1;

    .line 50
    .line 51
    :goto_1
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 52
    .line 53
    .line 54
    move-result v2

    .line 55
    if-nez v2, :cond_3

    .line 56
    .line 57
    if-eqz v0, :cond_3

    .line 58
    .line 59
    iget-boolean v2, v0, Lv3/f1;->K:Z

    .line 60
    .line 61
    if-eqz v2, :cond_2

    .line 62
    .line 63
    invoke-virtual {v0}, Lv3/f1;->m1()V

    .line 64
    .line 65
    .line 66
    :cond_2
    iget-object v0, v0, Lv3/f1;->s:Lv3/f1;

    .line 67
    .line 68
    goto :goto_1

    .line 69
    :cond_3
    invoke-virtual {p0}, Lv3/h0;->z()Ln2/b;

    .line 70
    .line 71
    .line 72
    move-result-object p0

    .line 73
    iget-object v0, p0, Ln2/b;->d:[Ljava/lang/Object;

    .line 74
    .line 75
    iget p0, p0, Ln2/b;->f:I

    .line 76
    .line 77
    const/4 v1, 0x0

    .line 78
    :goto_2
    if-ge v1, p0, :cond_5

    .line 79
    .line 80
    aget-object v2, v0, v1

    .line 81
    .line 82
    check-cast v2, Lv3/h0;

    .line 83
    .line 84
    invoke-virtual {v2}, Lv3/h0;->w()I

    .line 85
    .line 86
    .line 87
    move-result v3

    .line 88
    const v4, 0x7fffffff

    .line 89
    .line 90
    .line 91
    if-eq v3, v4, :cond_4

    .line 92
    .line 93
    iget-object v3, v2, Lv3/h0;->I:Lv3/l0;

    .line 94
    .line 95
    iget-object v3, v3, Lv3/l0;->p:Lv3/y0;

    .line 96
    .line 97
    invoke-virtual {v3}, Lv3/y0;->C0()V

    .line 98
    .line 99
    .line 100
    invoke-static {v2}, Lv3/h0;->Z(Lv3/h0;)V

    .line 101
    .line 102
    .line 103
    :cond_4
    add-int/lit8 v1, v1, 0x1

    .line 104
    .line 105
    goto :goto_2

    .line 106
    :cond_5
    return-void
.end method

.method public final D(La3/f;)V
    .locals 3

    .line 1
    iget-object p0, p0, Lv3/y0;->i:Lv3/l0;

    .line 2
    .line 3
    iget-object p0, p0, Lv3/l0;->a:Lv3/h0;

    .line 4
    .line 5
    invoke-virtual {p0}, Lv3/h0;->z()Ln2/b;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    iget-object v0, p0, Ln2/b;->d:[Ljava/lang/Object;

    .line 10
    .line 11
    iget p0, p0, Ln2/b;->f:I

    .line 12
    .line 13
    const/4 v1, 0x0

    .line 14
    :goto_0
    if-ge v1, p0, :cond_0

    .line 15
    .line 16
    aget-object v2, v0, v1

    .line 17
    .line 18
    check-cast v2, Lv3/h0;

    .line 19
    .line 20
    iget-object v2, v2, Lv3/h0;->I:Lv3/l0;

    .line 21
    .line 22
    iget-object v2, v2, Lv3/l0;->p:Lv3/y0;

    .line 23
    .line 24
    invoke-virtual {p1, v2}, La3/f;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    add-int/lit8 v1, v1, 0x1

    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_0
    return-void
.end method

.method public final E()Lv3/u;
    .locals 0

    .line 1
    iget-object p0, p0, Lv3/y0;->i:Lv3/l0;

    .line 2
    .line 3
    iget-object p0, p0, Lv3/l0;->a:Lv3/h0;

    .line 4
    .line 5
    iget-object p0, p0, Lv3/h0;->H:Lg1/q;

    .line 6
    .line 7
    iget-object p0, p0, Lg1/q;->d:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast p0, Lv3/u;

    .line 10
    .line 11
    return-object p0
.end method

.method public final E0()V
    .locals 13

    .line 1
    iget-boolean v0, p0, Lv3/y0;->w:Z

    .line 2
    .line 3
    if-eqz v0, :cond_b

    .line 4
    .line 5
    const/4 v0, 0x0

    .line 6
    iput-boolean v0, p0, Lv3/y0;->w:Z

    .line 7
    .line 8
    iget-object p0, p0, Lv3/y0;->i:Lv3/l0;

    .line 9
    .line 10
    iget-object v1, p0, Lv3/l0;->a:Lv3/h0;

    .line 11
    .line 12
    iget-object v1, v1, Lv3/h0;->H:Lg1/q;

    .line 13
    .line 14
    iget-object v2, v1, Lg1/q;->e:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast v2, Lv3/f1;

    .line 17
    .line 18
    iget-object v1, v1, Lg1/q;->d:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast v1, Lv3/u;

    .line 21
    .line 22
    iget-object v1, v1, Lv3/f1;->s:Lv3/f1;

    .line 23
    .line 24
    :goto_0
    invoke-static {v2, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 25
    .line 26
    .line 27
    move-result v3

    .line 28
    if-nez v3, :cond_a

    .line 29
    .line 30
    if-eqz v2, :cond_a

    .line 31
    .line 32
    const/high16 v3, 0x100000

    .line 33
    .line 34
    invoke-static {v3}, Lv3/g1;->g(I)Z

    .line 35
    .line 36
    .line 37
    move-result v4

    .line 38
    invoke-virtual {v2, v4}, Lv3/f1;->h1(Z)Lx2/r;

    .line 39
    .line 40
    .line 41
    move-result-object v4

    .line 42
    if-eqz v4, :cond_9

    .line 43
    .line 44
    iget-object v4, v4, Lx2/r;->d:Lx2/r;

    .line 45
    .line 46
    iget v4, v4, Lx2/r;->g:I

    .line 47
    .line 48
    and-int/2addr v4, v3

    .line 49
    if-eqz v4, :cond_9

    .line 50
    .line 51
    invoke-static {v3}, Lv3/g1;->g(I)Z

    .line 52
    .line 53
    .line 54
    move-result v4

    .line 55
    invoke-virtual {v2}, Lv3/f1;->f1()Lx2/r;

    .line 56
    .line 57
    .line 58
    move-result-object v5

    .line 59
    if-eqz v4, :cond_0

    .line 60
    .line 61
    goto :goto_1

    .line 62
    :cond_0
    iget-object v5, v5, Lx2/r;->h:Lx2/r;

    .line 63
    .line 64
    if-nez v5, :cond_1

    .line 65
    .line 66
    goto :goto_6

    .line 67
    :cond_1
    :goto_1
    invoke-virtual {v2, v4}, Lv3/f1;->h1(Z)Lx2/r;

    .line 68
    .line 69
    .line 70
    move-result-object v4

    .line 71
    :goto_2
    if-eqz v4, :cond_9

    .line 72
    .line 73
    iget v6, v4, Lx2/r;->g:I

    .line 74
    .line 75
    and-int/2addr v6, v3

    .line 76
    if-eqz v6, :cond_9

    .line 77
    .line 78
    iget v6, v4, Lx2/r;->f:I

    .line 79
    .line 80
    and-int/2addr v6, v3

    .line 81
    if-eqz v6, :cond_8

    .line 82
    .line 83
    const/4 v6, 0x0

    .line 84
    move-object v7, v4

    .line 85
    move-object v8, v6

    .line 86
    :goto_3
    if-eqz v7, :cond_8

    .line 87
    .line 88
    iget v9, v7, Lx2/r;->f:I

    .line 89
    .line 90
    and-int/2addr v9, v3

    .line 91
    if-eqz v9, :cond_7

    .line 92
    .line 93
    instance-of v9, v7, Lv3/n;

    .line 94
    .line 95
    if-eqz v9, :cond_7

    .line 96
    .line 97
    move-object v9, v7

    .line 98
    check-cast v9, Lv3/n;

    .line 99
    .line 100
    iget-object v9, v9, Lv3/n;->s:Lx2/r;

    .line 101
    .line 102
    move v10, v0

    .line 103
    :goto_4
    const/4 v11, 0x1

    .line 104
    if-eqz v9, :cond_6

    .line 105
    .line 106
    iget v12, v9, Lx2/r;->f:I

    .line 107
    .line 108
    and-int/2addr v12, v3

    .line 109
    if-eqz v12, :cond_5

    .line 110
    .line 111
    add-int/lit8 v10, v10, 0x1

    .line 112
    .line 113
    if-ne v10, v11, :cond_2

    .line 114
    .line 115
    move-object v7, v9

    .line 116
    goto :goto_5

    .line 117
    :cond_2
    if-nez v8, :cond_3

    .line 118
    .line 119
    new-instance v8, Ln2/b;

    .line 120
    .line 121
    const/16 v11, 0x10

    .line 122
    .line 123
    new-array v11, v11, [Lx2/r;

    .line 124
    .line 125
    invoke-direct {v8, v11}, Ln2/b;-><init>([Ljava/lang/Object;)V

    .line 126
    .line 127
    .line 128
    :cond_3
    if-eqz v7, :cond_4

    .line 129
    .line 130
    invoke-virtual {v8, v7}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 131
    .line 132
    .line 133
    move-object v7, v6

    .line 134
    :cond_4
    invoke-virtual {v8, v9}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 135
    .line 136
    .line 137
    :cond_5
    :goto_5
    iget-object v9, v9, Lx2/r;->i:Lx2/r;

    .line 138
    .line 139
    goto :goto_4

    .line 140
    :cond_6
    if-ne v10, v11, :cond_7

    .line 141
    .line 142
    goto :goto_3

    .line 143
    :cond_7
    invoke-static {v8}, Lv3/f;->f(Ln2/b;)Lx2/r;

    .line 144
    .line 145
    .line 146
    move-result-object v7

    .line 147
    goto :goto_3

    .line 148
    :cond_8
    if-eq v4, v5, :cond_9

    .line 149
    .line 150
    iget-object v4, v4, Lx2/r;->i:Lx2/r;

    .line 151
    .line 152
    goto :goto_2

    .line 153
    :cond_9
    :goto_6
    invoke-virtual {v2}, Lv3/f1;->x1()V

    .line 154
    .line 155
    .line 156
    iget-object v2, v2, Lv3/f1;->s:Lv3/f1;

    .line 157
    .line 158
    goto/16 :goto_0

    .line 159
    .line 160
    :cond_a
    iget-object p0, p0, Lv3/l0;->a:Lv3/h0;

    .line 161
    .line 162
    invoke-virtual {p0}, Lv3/h0;->z()Ln2/b;

    .line 163
    .line 164
    .line 165
    move-result-object p0

    .line 166
    iget-object v1, p0, Ln2/b;->d:[Ljava/lang/Object;

    .line 167
    .line 168
    iget p0, p0, Ln2/b;->f:I

    .line 169
    .line 170
    :goto_7
    if-ge v0, p0, :cond_b

    .line 171
    .line 172
    aget-object v2, v1, v0

    .line 173
    .line 174
    check-cast v2, Lv3/h0;

    .line 175
    .line 176
    iget-object v2, v2, Lv3/h0;->I:Lv3/l0;

    .line 177
    .line 178
    iget-object v2, v2, Lv3/l0;->p:Lv3/y0;

    .line 179
    .line 180
    invoke-virtual {v2}, Lv3/y0;->E0()V

    .line 181
    .line 182
    .line 183
    add-int/lit8 v0, v0, 0x1

    .line 184
    .line 185
    goto :goto_7

    .line 186
    :cond_b
    return-void
.end method

.method public final F0()V
    .locals 7

    .line 1
    iget-object p0, p0, Lv3/y0;->i:Lv3/l0;

    .line 2
    .line 3
    iget v0, p0, Lv3/l0;->l:I

    .line 4
    .line 5
    if-lez v0, :cond_2

    .line 6
    .line 7
    iget-object p0, p0, Lv3/l0;->a:Lv3/h0;

    .line 8
    .line 9
    invoke-virtual {p0}, Lv3/h0;->z()Ln2/b;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    iget-object v0, p0, Ln2/b;->d:[Ljava/lang/Object;

    .line 14
    .line 15
    iget p0, p0, Ln2/b;->f:I

    .line 16
    .line 17
    const/4 v1, 0x0

    .line 18
    move v2, v1

    .line 19
    :goto_0
    if-ge v2, p0, :cond_2

    .line 20
    .line 21
    aget-object v3, v0, v2

    .line 22
    .line 23
    check-cast v3, Lv3/h0;

    .line 24
    .line 25
    iget-object v4, v3, Lv3/h0;->I:Lv3/l0;

    .line 26
    .line 27
    iget-boolean v5, v4, Lv3/l0;->j:Z

    .line 28
    .line 29
    iget-object v6, v4, Lv3/l0;->p:Lv3/y0;

    .line 30
    .line 31
    if-nez v5, :cond_0

    .line 32
    .line 33
    iget-boolean v4, v4, Lv3/l0;->k:Z

    .line 34
    .line 35
    if-eqz v4, :cond_1

    .line 36
    .line 37
    :cond_0
    iget-boolean v4, v6, Lv3/y0;->z:Z

    .line 38
    .line 39
    if-nez v4, :cond_1

    .line 40
    .line 41
    invoke-virtual {v3, v1}, Lv3/h0;->X(Z)V

    .line 42
    .line 43
    .line 44
    :cond_1
    invoke-virtual {v6}, Lv3/y0;->F0()V

    .line 45
    .line 46
    .line 47
    add-int/lit8 v2, v2, 0x1

    .line 48
    .line 49
    goto :goto_0

    .line 50
    :cond_2
    return-void
.end method

.method public final G(I)I
    .locals 2

    .line 1
    iget-object v0, p0, Lv3/y0;->i:Lv3/l0;

    .line 2
    .line 3
    iget-object v1, v0, Lv3/l0;->a:Lv3/h0;

    .line 4
    .line 5
    invoke-static {v1}, Lv3/f;->s(Lv3/h0;)Z

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    if-eqz v1, :cond_0

    .line 10
    .line 11
    iget-object p0, v0, Lv3/l0;->q:Lv3/u0;

    .line 12
    .line 13
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {p0, p1}, Lv3/u0;->G(I)I

    .line 17
    .line 18
    .line 19
    move-result p0

    .line 20
    return p0

    .line 21
    :cond_0
    invoke-virtual {p0}, Lv3/y0;->H0()V

    .line 22
    .line 23
    .line 24
    invoke-virtual {v0}, Lv3/l0;->a()Lv3/f1;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    invoke-interface {p0, p1}, Lt3/p0;->G(I)I

    .line 29
    .line 30
    .line 31
    move-result p0

    .line 32
    return p0
.end method

.method public final H0()V
    .locals 3

    .line 1
    iget-object p0, p0, Lv3/y0;->i:Lv3/l0;

    .line 2
    .line 3
    iget-object v0, p0, Lv3/l0;->a:Lv3/h0;

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    const/4 v2, 0x7

    .line 7
    invoke-static {v0, v1, v2}, Lv3/h0;->Y(Lv3/h0;ZI)V

    .line 8
    .line 9
    .line 10
    iget-object p0, p0, Lv3/l0;->a:Lv3/h0;

    .line 11
    .line 12
    invoke-virtual {p0}, Lv3/h0;->v()Lv3/h0;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    if-eqz v0, :cond_2

    .line 17
    .line 18
    iget-object v1, p0, Lv3/h0;->E:Lv3/f0;

    .line 19
    .line 20
    sget-object v2, Lv3/f0;->f:Lv3/f0;

    .line 21
    .line 22
    if-ne v1, v2, :cond_2

    .line 23
    .line 24
    iget-object v1, v0, Lv3/h0;->I:Lv3/l0;

    .line 25
    .line 26
    iget-object v1, v1, Lv3/l0;->d:Lv3/d0;

    .line 27
    .line 28
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 29
    .line 30
    .line 31
    move-result v1

    .line 32
    if-eqz v1, :cond_1

    .line 33
    .line 34
    const/4 v2, 0x2

    .line 35
    if-eq v1, v2, :cond_0

    .line 36
    .line 37
    iget-object v0, v0, Lv3/h0;->E:Lv3/f0;

    .line 38
    .line 39
    goto :goto_0

    .line 40
    :cond_0
    sget-object v0, Lv3/f0;->e:Lv3/f0;

    .line 41
    .line 42
    goto :goto_0

    .line 43
    :cond_1
    sget-object v0, Lv3/f0;->d:Lv3/f0;

    .line 44
    .line 45
    :goto_0
    iput-object v0, p0, Lv3/h0;->E:Lv3/f0;

    .line 46
    .line 47
    :cond_2
    return-void
.end method

.method public final J(I)I
    .locals 2

    .line 1
    iget-object v0, p0, Lv3/y0;->i:Lv3/l0;

    .line 2
    .line 3
    iget-object v1, v0, Lv3/l0;->a:Lv3/h0;

    .line 4
    .line 5
    invoke-static {v1}, Lv3/f;->s(Lv3/h0;)Z

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    if-eqz v1, :cond_0

    .line 10
    .line 11
    iget-object p0, v0, Lv3/l0;->q:Lv3/u0;

    .line 12
    .line 13
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {p0, p1}, Lv3/u0;->J(I)I

    .line 17
    .line 18
    .line 19
    move-result p0

    .line 20
    return p0

    .line 21
    :cond_0
    invoke-virtual {p0}, Lv3/y0;->H0()V

    .line 22
    .line 23
    .line 24
    invoke-virtual {v0}, Lv3/l0;->a()Lv3/f1;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    invoke-interface {p0, p1}, Lt3/p0;->J(I)I

    .line 29
    .line 30
    .line 31
    move-result p0

    .line 32
    return p0
.end method

.method public final J0()V
    .locals 7

    .line 1
    const/4 v0, 0x1

    .line 2
    iput-boolean v0, p0, Lv3/y0;->J:Z

    .line 3
    .line 4
    iget-object v1, p0, Lv3/y0;->i:Lv3/l0;

    .line 5
    .line 6
    iget-object v2, v1, Lv3/l0;->a:Lv3/h0;

    .line 7
    .line 8
    invoke-virtual {v2}, Lv3/h0;->v()Lv3/h0;

    .line 9
    .line 10
    .line 11
    move-result-object v2

    .line 12
    invoke-virtual {p0}, Lv3/y0;->E()Lv3/u;

    .line 13
    .line 14
    .line 15
    move-result-object v3

    .line 16
    iget v3, v3, Lv3/f1;->D:F

    .line 17
    .line 18
    iget-object v1, v1, Lv3/l0;->a:Lv3/h0;

    .line 19
    .line 20
    iget-object v4, v1, Lv3/h0;->H:Lg1/q;

    .line 21
    .line 22
    iget-object v5, v4, Lg1/q;->e:Ljava/lang/Object;

    .line 23
    .line 24
    check-cast v5, Lv3/f1;

    .line 25
    .line 26
    iget-object v4, v4, Lg1/q;->d:Ljava/lang/Object;

    .line 27
    .line 28
    check-cast v4, Lv3/u;

    .line 29
    .line 30
    :goto_0
    if-eq v5, v4, :cond_0

    .line 31
    .line 32
    const-string v6, "null cannot be cast to non-null type androidx.compose.ui.node.LayoutModifierNodeCoordinator"

    .line 33
    .line 34
    invoke-static {v5, v6}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    check-cast v5, Lv3/a0;

    .line 38
    .line 39
    iget v6, v5, Lv3/f1;->D:F

    .line 40
    .line 41
    add-float/2addr v3, v6

    .line 42
    iget-object v5, v5, Lv3/f1;->s:Lv3/f1;

    .line 43
    .line 44
    goto :goto_0

    .line 45
    :cond_0
    iget v4, p0, Lv3/y0;->I:F

    .line 46
    .line 47
    cmpg-float v4, v3, v4

    .line 48
    .line 49
    if-nez v4, :cond_1

    .line 50
    .line 51
    goto :goto_1

    .line 52
    :cond_1
    iput v3, p0, Lv3/y0;->I:F

    .line 53
    .line 54
    if-eqz v2, :cond_2

    .line 55
    .line 56
    invoke-virtual {v2}, Lv3/h0;->P()V

    .line 57
    .line 58
    .line 59
    :cond_2
    if-eqz v2, :cond_3

    .line 60
    .line 61
    invoke-virtual {v2}, Lv3/h0;->C()V

    .line 62
    .line 63
    .line 64
    :cond_3
    :goto_1
    iget-boolean v3, p0, Lv3/y0;->w:Z

    .line 65
    .line 66
    const/4 v4, 0x0

    .line 67
    if-nez v3, :cond_5

    .line 68
    .line 69
    if-eqz v2, :cond_4

    .line 70
    .line 71
    invoke-virtual {v2}, Lv3/h0;->C()V

    .line 72
    .line 73
    .line 74
    :cond_4
    invoke-virtual {p0}, Lv3/y0;->C0()V

    .line 75
    .line 76
    .line 77
    iget-boolean v1, p0, Lv3/y0;->j:Z

    .line 78
    .line 79
    if-eqz v1, :cond_6

    .line 80
    .line 81
    if-eqz v2, :cond_6

    .line 82
    .line 83
    invoke-virtual {v2, v4}, Lv3/h0;->X(Z)V

    .line 84
    .line 85
    .line 86
    goto :goto_2

    .line 87
    :cond_5
    iget-object v1, v1, Lv3/h0;->H:Lg1/q;

    .line 88
    .line 89
    iget-object v1, v1, Lg1/q;->d:Ljava/lang/Object;

    .line 90
    .line 91
    check-cast v1, Lv3/u;

    .line 92
    .line 93
    invoke-virtual {v1}, Lv3/f1;->r1()V

    .line 94
    .line 95
    .line 96
    :cond_6
    :goto_2
    if-eqz v2, :cond_8

    .line 97
    .line 98
    iget-object v1, v2, Lv3/h0;->I:Lv3/l0;

    .line 99
    .line 100
    iget-boolean v2, p0, Lv3/y0;->j:Z

    .line 101
    .line 102
    if-nez v2, :cond_9

    .line 103
    .line 104
    iget-object v2, v1, Lv3/l0;->d:Lv3/d0;

    .line 105
    .line 106
    sget-object v3, Lv3/d0;->f:Lv3/d0;

    .line 107
    .line 108
    if-ne v2, v3, :cond_9

    .line 109
    .line 110
    iget v2, p0, Lv3/y0;->l:I

    .line 111
    .line 112
    const v3, 0x7fffffff

    .line 113
    .line 114
    .line 115
    if-ne v2, v3, :cond_7

    .line 116
    .line 117
    goto :goto_3

    .line 118
    :cond_7
    const-string v2, "Place was called on a node which was placed already"

    .line 119
    .line 120
    invoke-static {v2}, Ls3/a;->b(Ljava/lang/String;)V

    .line 121
    .line 122
    .line 123
    :goto_3
    iget v2, v1, Lv3/l0;->i:I

    .line 124
    .line 125
    iput v2, p0, Lv3/y0;->l:I

    .line 126
    .line 127
    add-int/2addr v2, v0

    .line 128
    iput v2, v1, Lv3/l0;->i:I

    .line 129
    .line 130
    goto :goto_4

    .line 131
    :cond_8
    iput v4, p0, Lv3/y0;->l:I

    .line 132
    .line 133
    :cond_9
    :goto_4
    invoke-virtual {p0}, Lv3/y0;->t()V

    .line 134
    .line 135
    .line 136
    return-void
.end method

.method public final L(J)Lt3/e1;
    .locals 4

    .line 1
    iget-object v0, p0, Lv3/y0;->i:Lv3/l0;

    .line 2
    .line 3
    iget-object v1, v0, Lv3/l0;->a:Lv3/h0;

    .line 4
    .line 5
    iget-object v2, v1, Lv3/h0;->E:Lv3/f0;

    .line 6
    .line 7
    sget-object v3, Lv3/f0;->f:Lv3/f0;

    .line 8
    .line 9
    if-ne v2, v3, :cond_0

    .line 10
    .line 11
    invoke-virtual {v1}, Lv3/h0;->d()V

    .line 12
    .line 13
    .line 14
    :cond_0
    iget-object v1, v0, Lv3/l0;->a:Lv3/h0;

    .line 15
    .line 16
    invoke-static {v1}, Lv3/f;->s(Lv3/h0;)Z

    .line 17
    .line 18
    .line 19
    move-result v1

    .line 20
    if-eqz v1, :cond_1

    .line 21
    .line 22
    iget-object v1, v0, Lv3/l0;->q:Lv3/u0;

    .line 23
    .line 24
    invoke-static {v1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 25
    .line 26
    .line 27
    iput-object v3, v1, Lv3/u0;->m:Lv3/f0;

    .line 28
    .line 29
    invoke-virtual {v1, p1, p2}, Lv3/u0;->L(J)Lt3/e1;

    .line 30
    .line 31
    .line 32
    :cond_1
    iget-object v0, v0, Lv3/l0;->a:Lv3/h0;

    .line 33
    .line 34
    invoke-virtual {v0}, Lv3/h0;->v()Lv3/h0;

    .line 35
    .line 36
    .line 37
    move-result-object v1

    .line 38
    if-eqz v1, :cond_6

    .line 39
    .line 40
    iget-object v1, v1, Lv3/h0;->I:Lv3/l0;

    .line 41
    .line 42
    iget-object v2, p0, Lv3/y0;->o:Lv3/f0;

    .line 43
    .line 44
    if-eq v2, v3, :cond_3

    .line 45
    .line 46
    iget-boolean v0, v0, Lv3/h0;->G:Z

    .line 47
    .line 48
    if-eqz v0, :cond_2

    .line 49
    .line 50
    goto :goto_0

    .line 51
    :cond_2
    const-string v0, "measure() may not be called multiple times on the same Measurable. If you want to get the content size of the Measurable before calculating the final constraints, please use methods like minIntrinsicWidth()/maxIntrinsicWidth() and minIntrinsicHeight()/maxIntrinsicHeight()"

    .line 52
    .line 53
    invoke-static {v0}, Ls3/a;->b(Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    :cond_3
    :goto_0
    iget-object v0, v1, Lv3/l0;->d:Lv3/d0;

    .line 57
    .line 58
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 59
    .line 60
    .line 61
    move-result v0

    .line 62
    if-eqz v0, :cond_5

    .line 63
    .line 64
    const/4 v2, 0x2

    .line 65
    if-ne v0, v2, :cond_4

    .line 66
    .line 67
    sget-object v0, Lv3/f0;->e:Lv3/f0;

    .line 68
    .line 69
    goto :goto_1

    .line 70
    :cond_4
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 71
    .line 72
    new-instance p1, Ljava/lang/StringBuilder;

    .line 73
    .line 74
    const-string p2, "Measurable could be only measured from the parent\'s measure or layout block. Parents state is "

    .line 75
    .line 76
    invoke-direct {p1, p2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 77
    .line 78
    .line 79
    iget-object p2, v1, Lv3/l0;->d:Lv3/d0;

    .line 80
    .line 81
    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 82
    .line 83
    .line 84
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 85
    .line 86
    .line 87
    move-result-object p1

    .line 88
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 89
    .line 90
    .line 91
    throw p0

    .line 92
    :cond_5
    sget-object v0, Lv3/f0;->d:Lv3/f0;

    .line 93
    .line 94
    :goto_1
    iput-object v0, p0, Lv3/y0;->o:Lv3/f0;

    .line 95
    .line 96
    goto :goto_2

    .line 97
    :cond_6
    iput-object v3, p0, Lv3/y0;->o:Lv3/f0;

    .line 98
    .line 99
    :goto_2
    invoke-virtual {p0, p1, p2}, Lv3/y0;->O0(J)Z

    .line 100
    .line 101
    .line 102
    return-object p0
.end method

.method public final L0(J)V
    .locals 5

    .line 1
    iget-object v0, p0, Lv3/y0;->i:Lv3/l0;

    .line 2
    .line 3
    iget-object v1, v0, Lv3/l0;->d:Lv3/d0;

    .line 4
    .line 5
    iget-object v2, v0, Lv3/l0;->a:Lv3/h0;

    .line 6
    .line 7
    sget-object v3, Lv3/d0;->h:Lv3/d0;

    .line 8
    .line 9
    if-ne v1, v3, :cond_0

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    const-string v1, "layout state is not idle before measure starts"

    .line 13
    .line 14
    invoke-static {v1}, Ls3/a;->b(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    :goto_0
    iput-wide p1, p0, Lv3/y0;->F:J

    .line 18
    .line 19
    sget-object p1, Lv3/d0;->d:Lv3/d0;

    .line 20
    .line 21
    iput-object p1, v0, Lv3/l0;->d:Lv3/d0;

    .line 22
    .line 23
    const/4 p2, 0x0

    .line 24
    iput-boolean p2, p0, Lv3/y0;->y:Z

    .line 25
    .line 26
    invoke-static {v2}, Lv3/k0;->a(Lv3/h0;)Lv3/o1;

    .line 27
    .line 28
    .line 29
    move-result-object p2

    .line 30
    check-cast p2, Lw3/t;

    .line 31
    .line 32
    invoke-virtual {p2}, Lw3/t;->getSnapshotObserver()Lv3/q1;

    .line 33
    .line 34
    .line 35
    move-result-object p2

    .line 36
    iget-object v1, p0, Lv3/y0;->G:Lv3/x0;

    .line 37
    .line 38
    iget-object v4, p2, Lv3/q1;->c:Lv3/e;

    .line 39
    .line 40
    invoke-virtual {p2, v2, v4, v1}, Lv3/q1;->a(Lv3/p1;Lay0/k;Lay0/a;)V

    .line 41
    .line 42
    .line 43
    iget-object p2, v0, Lv3/l0;->d:Lv3/d0;

    .line 44
    .line 45
    if-ne p2, p1, :cond_1

    .line 46
    .line 47
    const/4 p1, 0x1

    .line 48
    iput-boolean p1, p0, Lv3/y0;->z:Z

    .line 49
    .line 50
    iput-boolean p1, p0, Lv3/y0;->A:Z

    .line 51
    .line 52
    iput-object v3, v0, Lv3/l0;->d:Lv3/d0;

    .line 53
    .line 54
    :cond_1
    return-void
.end method

.method public final M0(JFLay0/k;Lh3/c;)V
    .locals 8

    .line 1
    iget-object v6, p0, Lv3/y0;->i:Lv3/l0;

    .line 2
    .line 3
    iget-object v0, v6, Lv3/l0;->a:Lv3/h0;

    .line 4
    .line 5
    iget-object v1, v6, Lv3/l0;->a:Lv3/h0;

    .line 6
    .line 7
    iget-boolean v0, v0, Lv3/h0;->S:Z

    .line 8
    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    const-string v0, "place is called on a deactivated node"

    .line 12
    .line 13
    invoke-static {v0}, Ls3/a;->a(Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    :cond_0
    sget-object v0, Lv3/d0;->f:Lv3/d0;

    .line 17
    .line 18
    iput-object v0, v6, Lv3/l0;->d:Lv3/d0;

    .line 19
    .line 20
    iput-wide p1, p0, Lv3/y0;->q:J

    .line 21
    .line 22
    iput p3, p0, Lv3/y0;->t:F

    .line 23
    .line 24
    iput-object p4, p0, Lv3/y0;->r:Lay0/k;

    .line 25
    .line 26
    iput-object p5, p0, Lv3/y0;->s:Lh3/c;

    .line 27
    .line 28
    const/4 v0, 0x0

    .line 29
    iput-boolean v0, p0, Lv3/y0;->J:Z

    .line 30
    .line 31
    invoke-static {v1}, Lv3/k0;->a(Lv3/h0;)Lv3/o1;

    .line 32
    .line 33
    .line 34
    move-result-object v2

    .line 35
    iget-boolean v3, p0, Lv3/y0;->z:Z

    .line 36
    .line 37
    if-nez v3, :cond_1

    .line 38
    .line 39
    iget-boolean v3, p0, Lv3/y0;->w:Z

    .line 40
    .line 41
    if-eqz v3, :cond_1

    .line 42
    .line 43
    invoke-virtual {v6}, Lv3/l0;->a()Lv3/f1;

    .line 44
    .line 45
    .line 46
    move-result-object v0

    .line 47
    iget-wide v1, v0, Lt3/e1;->h:J

    .line 48
    .line 49
    invoke-static {p1, p2, v1, v2}, Lt4/j;->d(JJ)J

    .line 50
    .line 51
    .line 52
    move-result-wide v1

    .line 53
    move v3, p3

    .line 54
    move-object v4, p4

    .line 55
    move-object v5, p5

    .line 56
    invoke-virtual/range {v0 .. v5}, Lv3/f1;->v1(JFLay0/k;Lh3/c;)V

    .line 57
    .line 58
    .line 59
    invoke-virtual {p0}, Lv3/y0;->J0()V

    .line 60
    .line 61
    .line 62
    goto :goto_0

    .line 63
    :cond_1
    iget-object v7, p0, Lv3/y0;->B:Lv3/i0;

    .line 64
    .line 65
    iput-boolean v0, v7, Lv3/i0;->g:Z

    .line 66
    .line 67
    invoke-virtual {v6, v0}, Lv3/l0;->f(Z)V

    .line 68
    .line 69
    .line 70
    iput-object p4, p0, Lv3/y0;->K:Lay0/k;

    .line 71
    .line 72
    iput-wide p1, p0, Lv3/y0;->M:J

    .line 73
    .line 74
    iput p3, p0, Lv3/y0;->N:F

    .line 75
    .line 76
    iput-object p5, p0, Lv3/y0;->L:Lh3/c;

    .line 77
    .line 78
    check-cast v2, Lw3/t;

    .line 79
    .line 80
    invoke-virtual {v2}, Lw3/t;->getSnapshotObserver()Lv3/q1;

    .line 81
    .line 82
    .line 83
    move-result-object p1

    .line 84
    iget-object p2, p0, Lv3/y0;->O:Lv3/x0;

    .line 85
    .line 86
    iget-object p3, p1, Lv3/q1;->f:Lv3/e;

    .line 87
    .line 88
    invoke-virtual {p1, v1, p3, p2}, Lv3/q1;->a(Lv3/p1;Lay0/k;Lay0/a;)V

    .line 89
    .line 90
    .line 91
    :goto_0
    sget-object p1, Lv3/d0;->h:Lv3/d0;

    .line 92
    .line 93
    iput-object p1, v6, Lv3/l0;->d:Lv3/d0;

    .line 94
    .line 95
    const/4 p1, 0x1

    .line 96
    iput-boolean p1, p0, Lv3/y0;->n:Z

    .line 97
    .line 98
    return-void
.end method

.method public final N0(JFLay0/k;Lh3/c;)V
    .locals 9

    .line 1
    iget-object v0, p0, Lv3/y0;->i:Lv3/l0;

    .line 2
    .line 3
    iget-object v1, v0, Lv3/l0;->a:Lv3/h0;

    .line 4
    .line 5
    iget-object v2, v0, Lv3/l0;->a:Lv3/h0;

    .line 6
    .line 7
    const/4 v3, 0x1

    .line 8
    :try_start_0
    iput-boolean v3, p0, Lv3/y0;->x:Z

    .line 9
    .line 10
    iget-wide v4, p0, Lv3/y0;->q:J

    .line 11
    .line 12
    invoke-static {p1, p2, v4, v5}, Lt4/j;->b(JJ)Z

    .line 13
    .line 14
    .line 15
    move-result v4

    .line 16
    const/4 v5, 0x0

    .line 17
    if-eqz v4, :cond_0

    .line 18
    .line 19
    iget-boolean v4, p0, Lv3/y0;->P:Z

    .line 20
    .line 21
    if-eqz v4, :cond_3

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :catchall_0
    move-exception v0

    .line 25
    move-object p0, v0

    .line 26
    goto/16 :goto_3

    .line 27
    .line 28
    :cond_0
    :goto_0
    iget-boolean v4, v0, Lv3/l0;->k:Z

    .line 29
    .line 30
    if-nez v4, :cond_1

    .line 31
    .line 32
    iget-boolean v4, v0, Lv3/l0;->j:Z

    .line 33
    .line 34
    if-nez v4, :cond_1

    .line 35
    .line 36
    iget-boolean v4, p0, Lv3/y0;->P:Z

    .line 37
    .line 38
    if-eqz v4, :cond_2

    .line 39
    .line 40
    :cond_1
    iput-boolean v3, p0, Lv3/y0;->z:Z

    .line 41
    .line 42
    iput-boolean v5, p0, Lv3/y0;->P:Z

    .line 43
    .line 44
    :cond_2
    invoke-virtual {p0}, Lv3/y0;->F0()V

    .line 45
    .line 46
    .line 47
    :cond_3
    iget-object v4, v0, Lv3/l0;->q:Lv3/u0;

    .line 48
    .line 49
    if-eqz v4, :cond_9

    .line 50
    .line 51
    iget-object v6, v4, Lv3/u0;->i:Lv3/l0;

    .line 52
    .line 53
    iget-object v7, v6, Lv3/l0;->a:Lv3/h0;

    .line 54
    .line 55
    invoke-static {v7}, Lv3/f;->s(Lv3/h0;)Z

    .line 56
    .line 57
    .line 58
    move-result v7

    .line 59
    if-eqz v7, :cond_4

    .line 60
    .line 61
    move v4, v3

    .line 62
    goto :goto_1

    .line 63
    :cond_4
    iget-object v4, v4, Lv3/u0;->u:Lv3/r0;

    .line 64
    .line 65
    sget-object v7, Lv3/r0;->f:Lv3/r0;

    .line 66
    .line 67
    if-ne v4, v7, :cond_5

    .line 68
    .line 69
    iget-boolean v4, v6, Lv3/l0;->b:Z

    .line 70
    .line 71
    if-nez v4, :cond_5

    .line 72
    .line 73
    iput-boolean v3, v6, Lv3/l0;->c:Z

    .line 74
    .line 75
    :cond_5
    iget-boolean v4, v6, Lv3/l0;->c:Z

    .line 76
    .line 77
    :goto_1
    if-ne v4, v3, :cond_9

    .line 78
    .line 79
    invoke-virtual {v0}, Lv3/l0;->a()Lv3/f1;

    .line 80
    .line 81
    .line 82
    move-result-object v4

    .line 83
    iget-object v4, v4, Lv3/f1;->t:Lv3/f1;

    .line 84
    .line 85
    if-eqz v4, :cond_6

    .line 86
    .line 87
    iget-object v4, v4, Lv3/p0;->o:Lt3/n0;

    .line 88
    .line 89
    if-nez v4, :cond_7

    .line 90
    .line 91
    :cond_6
    invoke-static {v2}, Lv3/k0;->a(Lv3/h0;)Lv3/o1;

    .line 92
    .line 93
    .line 94
    move-result-object v4

    .line 95
    check-cast v4, Lw3/t;

    .line 96
    .line 97
    invoke-virtual {v4}, Lw3/t;->getPlacementScope()Lt3/d1;

    .line 98
    .line 99
    .line 100
    move-result-object v4

    .line 101
    :cond_7
    iget-object v6, v0, Lv3/l0;->q:Lv3/u0;

    .line 102
    .line 103
    invoke-static {v6}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 104
    .line 105
    .line 106
    invoke-virtual {v2}, Lv3/h0;->v()Lv3/h0;

    .line 107
    .line 108
    .line 109
    move-result-object v2

    .line 110
    if-eqz v2, :cond_8

    .line 111
    .line 112
    iget-object v2, v2, Lv3/h0;->I:Lv3/l0;

    .line 113
    .line 114
    iput v5, v2, Lv3/l0;->h:I

    .line 115
    .line 116
    :cond_8
    const v2, 0x7fffffff

    .line 117
    .line 118
    .line 119
    iput v2, v6, Lv3/u0;->l:I

    .line 120
    .line 121
    const/16 v2, 0x20

    .line 122
    .line 123
    shr-long v7, p1, v2

    .line 124
    .line 125
    long-to-int v2, v7

    .line 126
    const-wide v7, 0xffffffffL

    .line 127
    .line 128
    .line 129
    .line 130
    .line 131
    and-long/2addr v7, p1

    .line 132
    long-to-int v7, v7

    .line 133
    invoke-static {v4, v6, v2, v7}, Lt3/d1;->h(Lt3/d1;Lt3/e1;II)V

    .line 134
    .line 135
    .line 136
    :cond_9
    iget-object v0, v0, Lv3/l0;->q:Lv3/u0;

    .line 137
    .line 138
    if-eqz v0, :cond_a

    .line 139
    .line 140
    iget-boolean v0, v0, Lv3/u0;->o:Z

    .line 141
    .line 142
    if-nez v0, :cond_a

    .line 143
    .line 144
    goto :goto_2

    .line 145
    :cond_a
    move v3, v5

    .line 146
    :goto_2
    if-eqz v3, :cond_b

    .line 147
    .line 148
    const-string v0, "Error: Placement happened before lookahead."

    .line 149
    .line 150
    invoke-static {v0}, Ls3/a;->b(Ljava/lang/String;)V

    .line 151
    .line 152
    .line 153
    :cond_b
    move-object v2, p0

    .line 154
    move-wide v3, p1

    .line 155
    move v5, p3

    .line 156
    move-object v6, p4

    .line 157
    move-object v7, p5

    .line 158
    invoke-virtual/range {v2 .. v7}, Lv3/y0;->M0(JFLay0/k;Lh3/c;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 159
    .line 160
    .line 161
    return-void

    .line 162
    :goto_3
    invoke-virtual {v1, p0}, Lv3/h0;->b0(Ljava/lang/Throwable;)V

    .line 163
    .line 164
    .line 165
    const/4 p0, 0x0

    .line 166
    throw p0
.end method

.method public final O0(J)Z
    .locals 8

    .line 1
    iget-object v0, p0, Lv3/y0;->i:Lv3/l0;

    .line 2
    .line 3
    iget-object v1, v0, Lv3/l0;->a:Lv3/h0;

    .line 4
    .line 5
    iget-object v2, v0, Lv3/l0;->a:Lv3/h0;

    .line 6
    .line 7
    :try_start_0
    iget-boolean v3, v1, Lv3/h0;->S:Z

    .line 8
    .line 9
    if-eqz v3, :cond_0

    .line 10
    .line 11
    const-string v3, "measure is called on a deactivated node"

    .line 12
    .line 13
    invoke-static {v3}, Ls3/a;->a(Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    goto :goto_0

    .line 17
    :catchall_0
    move-exception p0

    .line 18
    goto/16 :goto_6

    .line 19
    .line 20
    :cond_0
    :goto_0
    invoke-static {v2}, Lv3/k0;->a(Lv3/h0;)Lv3/o1;

    .line 21
    .line 22
    .line 23
    move-result-object v3

    .line 24
    invoke-virtual {v2}, Lv3/h0;->v()Lv3/h0;

    .line 25
    .line 26
    .line 27
    move-result-object v4

    .line 28
    iget-boolean v5, v2, Lv3/h0;->G:Z

    .line 29
    .line 30
    const/4 v6, 0x1

    .line 31
    const/4 v7, 0x0

    .line 32
    if-nez v5, :cond_2

    .line 33
    .line 34
    if-eqz v4, :cond_1

    .line 35
    .line 36
    iget-boolean v4, v4, Lv3/h0;->G:Z

    .line 37
    .line 38
    if-eqz v4, :cond_1

    .line 39
    .line 40
    goto :goto_1

    .line 41
    :cond_1
    move v4, v7

    .line 42
    goto :goto_2

    .line 43
    :cond_2
    :goto_1
    move v4, v6

    .line 44
    :goto_2
    iput-boolean v4, v2, Lv3/h0;->G:Z

    .line 45
    .line 46
    invoke-virtual {v2}, Lv3/h0;->r()Z

    .line 47
    .line 48
    .line 49
    move-result v4

    .line 50
    if-nez v4, :cond_4

    .line 51
    .line 52
    iget-wide v4, p0, Lt3/e1;->g:J

    .line 53
    .line 54
    invoke-static {v4, v5, p1, p2}, Lt4/a;->b(JJ)Z

    .line 55
    .line 56
    .line 57
    move-result v4

    .line 58
    if-nez v4, :cond_3

    .line 59
    .line 60
    goto :goto_3

    .line 61
    :cond_3
    check-cast v3, Lw3/t;

    .line 62
    .line 63
    invoke-virtual {v3, v2, v7}, Lw3/t;->i(Lv3/h0;Z)V

    .line 64
    .line 65
    .line 66
    invoke-virtual {v2}, Lv3/h0;->a0()V

    .line 67
    .line 68
    .line 69
    return v7

    .line 70
    :cond_4
    :goto_3
    iget-object v3, p0, Lv3/y0;->B:Lv3/i0;

    .line 71
    .line 72
    iput-boolean v7, v3, Lv3/i0;->f:Z

    .line 73
    .line 74
    invoke-virtual {v2}, Lv3/h0;->z()Ln2/b;

    .line 75
    .line 76
    .line 77
    move-result-object v2

    .line 78
    iget-object v3, v2, Ln2/b;->d:[Ljava/lang/Object;

    .line 79
    .line 80
    iget v2, v2, Ln2/b;->f:I

    .line 81
    .line 82
    move v4, v7

    .line 83
    :goto_4
    if-ge v4, v2, :cond_5

    .line 84
    .line 85
    aget-object v5, v3, v4

    .line 86
    .line 87
    check-cast v5, Lv3/h0;

    .line 88
    .line 89
    iget-object v5, v5, Lv3/h0;->I:Lv3/l0;

    .line 90
    .line 91
    iget-object v5, v5, Lv3/l0;->p:Lv3/y0;

    .line 92
    .line 93
    iget-object v5, v5, Lv3/y0;->B:Lv3/i0;

    .line 94
    .line 95
    iput-boolean v7, v5, Lv3/i0;->c:Z

    .line 96
    .line 97
    add-int/lit8 v4, v4, 0x1

    .line 98
    .line 99
    goto :goto_4

    .line 100
    :cond_5
    iput-boolean v6, p0, Lv3/y0;->m:Z

    .line 101
    .line 102
    invoke-virtual {v0}, Lv3/l0;->a()Lv3/f1;

    .line 103
    .line 104
    .line 105
    move-result-object v2

    .line 106
    iget-wide v2, v2, Lt3/e1;->f:J

    .line 107
    .line 108
    invoke-virtual {p0, p1, p2}, Lt3/e1;->y0(J)V

    .line 109
    .line 110
    .line 111
    invoke-virtual {p0, p1, p2}, Lv3/y0;->L0(J)V

    .line 112
    .line 113
    .line 114
    invoke-virtual {v0}, Lv3/l0;->a()Lv3/f1;

    .line 115
    .line 116
    .line 117
    move-result-object p1

    .line 118
    iget-wide p1, p1, Lt3/e1;->f:J

    .line 119
    .line 120
    invoke-static {p1, p2, v2, v3}, Lt4/l;->a(JJ)Z

    .line 121
    .line 122
    .line 123
    move-result p1

    .line 124
    if-eqz p1, :cond_7

    .line 125
    .line 126
    invoke-virtual {v0}, Lv3/l0;->a()Lv3/f1;

    .line 127
    .line 128
    .line 129
    move-result-object p1

    .line 130
    iget p1, p1, Lt3/e1;->d:I

    .line 131
    .line 132
    iget p2, p0, Lt3/e1;->d:I

    .line 133
    .line 134
    if-ne p1, p2, :cond_7

    .line 135
    .line 136
    invoke-virtual {v0}, Lv3/l0;->a()Lv3/f1;

    .line 137
    .line 138
    .line 139
    move-result-object p1

    .line 140
    iget p1, p1, Lt3/e1;->e:I

    .line 141
    .line 142
    iget p2, p0, Lt3/e1;->e:I

    .line 143
    .line 144
    if-eq p1, p2, :cond_6

    .line 145
    .line 146
    goto :goto_5

    .line 147
    :cond_6
    move v6, v7

    .line 148
    :cond_7
    :goto_5
    invoke-virtual {v0}, Lv3/l0;->a()Lv3/f1;

    .line 149
    .line 150
    .line 151
    move-result-object p1

    .line 152
    iget p1, p1, Lt3/e1;->d:I

    .line 153
    .line 154
    invoke-virtual {v0}, Lv3/l0;->a()Lv3/f1;

    .line 155
    .line 156
    .line 157
    move-result-object p2

    .line 158
    iget p2, p2, Lt3/e1;->e:I

    .line 159
    .line 160
    int-to-long v2, p1

    .line 161
    const/16 p1, 0x20

    .line 162
    .line 163
    shl-long/2addr v2, p1

    .line 164
    int-to-long p1, p2

    .line 165
    const-wide v4, 0xffffffffL

    .line 166
    .line 167
    .line 168
    .line 169
    .line 170
    and-long/2addr p1, v4

    .line 171
    or-long/2addr p1, v2

    .line 172
    invoke-virtual {p0, p1, p2}, Lt3/e1;->v0(J)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 173
    .line 174
    .line 175
    return v6

    .line 176
    :goto_6
    invoke-virtual {v1, p0}, Lv3/h0;->b0(Ljava/lang/Throwable;)V

    .line 177
    .line 178
    .line 179
    const/4 p0, 0x0

    .line 180
    throw p0
.end method

.method public final X()V
    .locals 2

    .line 1
    iget-object p0, p0, Lv3/y0;->i:Lv3/l0;

    .line 2
    .line 3
    iget-object p0, p0, Lv3/l0;->a:Lv3/h0;

    .line 4
    .line 5
    const/4 v0, 0x0

    .line 6
    const/4 v1, 0x7

    .line 7
    invoke-static {p0, v0, v1}, Lv3/h0;->Y(Lv3/h0;ZI)V

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public final a0(Lt3/a;)I
    .locals 6

    .line 1
    iget-object v0, p0, Lv3/y0;->i:Lv3/l0;

    .line 2
    .line 3
    iget-object v1, v0, Lv3/l0;->a:Lv3/h0;

    .line 4
    .line 5
    invoke-virtual {v1}, Lv3/h0;->v()Lv3/h0;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    const/4 v2, 0x0

    .line 10
    if-eqz v1, :cond_0

    .line 11
    .line 12
    iget-object v1, v1, Lv3/h0;->I:Lv3/l0;

    .line 13
    .line 14
    iget-object v1, v1, Lv3/l0;->d:Lv3/d0;

    .line 15
    .line 16
    goto :goto_0

    .line 17
    :cond_0
    move-object v1, v2

    .line 18
    :goto_0
    sget-object v3, Lv3/d0;->d:Lv3/d0;

    .line 19
    .line 20
    iget-object v4, p0, Lv3/y0;->B:Lv3/i0;

    .line 21
    .line 22
    const/4 v5, 0x1

    .line 23
    if-ne v1, v3, :cond_1

    .line 24
    .line 25
    iput-boolean v5, v4, Lv3/i0;->c:Z

    .line 26
    .line 27
    goto :goto_1

    .line 28
    :cond_1
    iget-object v1, v0, Lv3/l0;->a:Lv3/h0;

    .line 29
    .line 30
    invoke-virtual {v1}, Lv3/h0;->v()Lv3/h0;

    .line 31
    .line 32
    .line 33
    move-result-object v1

    .line 34
    if-eqz v1, :cond_2

    .line 35
    .line 36
    iget-object v1, v1, Lv3/h0;->I:Lv3/l0;

    .line 37
    .line 38
    iget-object v2, v1, Lv3/l0;->d:Lv3/d0;

    .line 39
    .line 40
    :cond_2
    sget-object v1, Lv3/d0;->f:Lv3/d0;

    .line 41
    .line 42
    if-ne v2, v1, :cond_3

    .line 43
    .line 44
    iput-boolean v5, v4, Lv3/i0;->d:Z

    .line 45
    .line 46
    :cond_3
    :goto_1
    iput-boolean v5, p0, Lv3/y0;->p:Z

    .line 47
    .line 48
    invoke-virtual {v0}, Lv3/l0;->a()Lv3/f1;

    .line 49
    .line 50
    .line 51
    move-result-object v0

    .line 52
    invoke-virtual {v0, p1}, Lv3/p0;->a0(Lt3/a;)I

    .line 53
    .line 54
    .line 55
    move-result p1

    .line 56
    const/4 v0, 0x0

    .line 57
    iput-boolean v0, p0, Lv3/y0;->p:Z

    .line 58
    .line 59
    return p1
.end method

.method public final b()Lv3/i0;
    .locals 0

    .line 1
    iget-object p0, p0, Lv3/y0;->B:Lv3/i0;

    .line 2
    .line 3
    return-object p0
.end method

.method public final b0()I
    .locals 0

    .line 1
    iget-object p0, p0, Lv3/y0;->i:Lv3/l0;

    .line 2
    .line 3
    invoke-virtual {p0}, Lv3/l0;->a()Lv3/f1;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    invoke-virtual {p0}, Lt3/e1;->b0()I

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    return p0
.end method

.method public final c(I)I
    .locals 2

    .line 1
    iget-object v0, p0, Lv3/y0;->i:Lv3/l0;

    .line 2
    .line 3
    iget-object v1, v0, Lv3/l0;->a:Lv3/h0;

    .line 4
    .line 5
    invoke-static {v1}, Lv3/f;->s(Lv3/h0;)Z

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    if-eqz v1, :cond_0

    .line 10
    .line 11
    iget-object p0, v0, Lv3/l0;->q:Lv3/u0;

    .line 12
    .line 13
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {p0, p1}, Lv3/u0;->c(I)I

    .line 17
    .line 18
    .line 19
    move-result p0

    .line 20
    return p0

    .line 21
    :cond_0
    invoke-virtual {p0}, Lv3/y0;->H0()V

    .line 22
    .line 23
    .line 24
    invoke-virtual {v0}, Lv3/l0;->a()Lv3/f1;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    invoke-interface {p0, p1}, Lt3/p0;->c(I)I

    .line 29
    .line 30
    .line 31
    move-result p0

    .line 32
    return p0
.end method

.method public final d0()I
    .locals 0

    .line 1
    iget-object p0, p0, Lv3/y0;->i:Lv3/l0;

    .line 2
    .line 3
    invoke-virtual {p0}, Lv3/l0;->a()Lv3/f1;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    invoke-virtual {p0}, Lt3/e1;->d0()I

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    return p0
.end method

.method public final f()Lv3/a;
    .locals 0

    .line 1
    iget-object p0, p0, Lv3/y0;->i:Lv3/l0;

    .line 2
    .line 3
    iget-object p0, p0, Lv3/l0;->a:Lv3/h0;

    .line 4
    .line 5
    invoke-virtual {p0}, Lv3/h0;->v()Lv3/h0;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    if-eqz p0, :cond_0

    .line 10
    .line 11
    iget-object p0, p0, Lv3/h0;->I:Lv3/l0;

    .line 12
    .line 13
    if-eqz p0, :cond_0

    .line 14
    .line 15
    iget-object p0, p0, Lv3/l0;->p:Lv3/y0;

    .line 16
    .line 17
    return-object p0

    .line 18
    :cond_0
    const/4 p0, 0x0

    .line 19
    return-object p0
.end method

.method public final l()Ljava/lang/Object;
    .locals 0

    .line 1
    iget-object p0, p0, Lv3/y0;->v:Ljava/lang/Object;

    .line 2
    .line 3
    return-object p0
.end method

.method public final l0(JFLay0/k;)V
    .locals 6

    .line 1
    const/4 v5, 0x0

    .line 2
    move-object v0, p0

    .line 3
    move-wide v1, p1

    .line 4
    move v3, p3

    .line 5
    move-object v4, p4

    .line 6
    invoke-virtual/range {v0 .. v5}, Lv3/y0;->N0(JFLay0/k;Lh3/c;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method

.method public final m0(JFLh3/c;)V
    .locals 6

    .line 1
    const/4 v4, 0x0

    .line 2
    move-object v0, p0

    .line 3
    move-wide v1, p1

    .line 4
    move v3, p3

    .line 5
    move-object v5, p4

    .line 6
    invoke-virtual/range {v0 .. v5}, Lv3/y0;->N0(JFLay0/k;Lh3/c;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method

.method public final p(Z)V
    .locals 2

    .line 1
    iget-object v0, p0, Lv3/y0;->i:Lv3/l0;

    .line 2
    .line 3
    invoke-virtual {v0}, Lv3/l0;->a()Lv3/f1;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    iget-boolean v1, v1, Lv3/p0;->l:Z

    .line 8
    .line 9
    if-eq p1, v1, :cond_0

    .line 10
    .line 11
    invoke-virtual {v0}, Lv3/l0;->a()Lv3/f1;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    iput-boolean p1, v0, Lv3/p0;->l:Z

    .line 16
    .line 17
    const/4 p1, 0x1

    .line 18
    iput-boolean p1, p0, Lv3/y0;->P:Z

    .line 19
    .line 20
    :cond_0
    return-void
.end method

.method public final requestLayout()V
    .locals 1

    .line 1
    iget-object p0, p0, Lv3/y0;->i:Lv3/l0;

    .line 2
    .line 3
    iget-object p0, p0, Lv3/l0;->a:Lv3/h0;

    .line 4
    .line 5
    const/4 v0, 0x0

    .line 6
    invoke-virtual {p0, v0}, Lv3/h0;->X(Z)V

    .line 7
    .line 8
    .line 9
    return-void
.end method

.method public final t()V
    .locals 10

    .line 1
    const/4 v0, 0x1

    .line 2
    iput-boolean v0, p0, Lv3/y0;->E:Z

    .line 3
    .line 4
    iget-object v1, p0, Lv3/y0;->B:Lv3/i0;

    .line 5
    .line 6
    invoke-virtual {v1}, Lv3/i0;->h()V

    .line 7
    .line 8
    .line 9
    iget-boolean v2, p0, Lv3/y0;->z:Z

    .line 10
    .line 11
    iget-object v3, p0, Lv3/y0;->i:Lv3/l0;

    .line 12
    .line 13
    const/4 v4, 0x0

    .line 14
    if-eqz v2, :cond_1

    .line 15
    .line 16
    iget-object v2, v3, Lv3/l0;->a:Lv3/h0;

    .line 17
    .line 18
    invoke-virtual {v2}, Lv3/h0;->z()Ln2/b;

    .line 19
    .line 20
    .line 21
    move-result-object v2

    .line 22
    iget-object v5, v2, Ln2/b;->d:[Ljava/lang/Object;

    .line 23
    .line 24
    iget v2, v2, Ln2/b;->f:I

    .line 25
    .line 26
    move v6, v4

    .line 27
    :goto_0
    if-ge v6, v2, :cond_1

    .line 28
    .line 29
    aget-object v7, v5, v6

    .line 30
    .line 31
    check-cast v7, Lv3/h0;

    .line 32
    .line 33
    invoke-virtual {v7}, Lv3/h0;->r()Z

    .line 34
    .line 35
    .line 36
    move-result v8

    .line 37
    if-eqz v8, :cond_0

    .line 38
    .line 39
    invoke-virtual {v7}, Lv3/h0;->s()Lv3/f0;

    .line 40
    .line 41
    .line 42
    move-result-object v8

    .line 43
    sget-object v9, Lv3/f0;->d:Lv3/f0;

    .line 44
    .line 45
    if-ne v8, v9, :cond_0

    .line 46
    .line 47
    invoke-static {v7}, Lv3/h0;->R(Lv3/h0;)Z

    .line 48
    .line 49
    .line 50
    move-result v7

    .line 51
    if-eqz v7, :cond_0

    .line 52
    .line 53
    iget-object v7, v3, Lv3/l0;->a:Lv3/h0;

    .line 54
    .line 55
    const/4 v8, 0x7

    .line 56
    invoke-static {v7, v4, v8}, Lv3/h0;->Y(Lv3/h0;ZI)V

    .line 57
    .line 58
    .line 59
    :cond_0
    add-int/lit8 v6, v6, 0x1

    .line 60
    .line 61
    goto :goto_0

    .line 62
    :cond_1
    iget-boolean v2, p0, Lv3/y0;->A:Z

    .line 63
    .line 64
    if-nez v2, :cond_2

    .line 65
    .line 66
    iget-boolean v2, p0, Lv3/y0;->p:Z

    .line 67
    .line 68
    if-nez v2, :cond_4

    .line 69
    .line 70
    invoke-virtual {p0}, Lv3/y0;->E()Lv3/u;

    .line 71
    .line 72
    .line 73
    move-result-object v2

    .line 74
    iget-boolean v2, v2, Lv3/p0;->n:Z

    .line 75
    .line 76
    if-nez v2, :cond_4

    .line 77
    .line 78
    iget-boolean v2, p0, Lv3/y0;->z:Z

    .line 79
    .line 80
    if-eqz v2, :cond_4

    .line 81
    .line 82
    :cond_2
    iput-boolean v4, p0, Lv3/y0;->z:Z

    .line 83
    .line 84
    iget-object v2, v3, Lv3/l0;->d:Lv3/d0;

    .line 85
    .line 86
    sget-object v5, Lv3/d0;->f:Lv3/d0;

    .line 87
    .line 88
    iput-object v5, v3, Lv3/l0;->d:Lv3/d0;

    .line 89
    .line 90
    invoke-virtual {v3, v4}, Lv3/l0;->g(Z)V

    .line 91
    .line 92
    .line 93
    iget-object v5, v3, Lv3/l0;->a:Lv3/h0;

    .line 94
    .line 95
    invoke-static {v5}, Lv3/k0;->a(Lv3/h0;)Lv3/o1;

    .line 96
    .line 97
    .line 98
    move-result-object v6

    .line 99
    check-cast v6, Lw3/t;

    .line 100
    .line 101
    invoke-virtual {v6}, Lw3/t;->getSnapshotObserver()Lv3/q1;

    .line 102
    .line 103
    .line 104
    move-result-object v6

    .line 105
    iget-object v7, p0, Lv3/y0;->H:Lv3/x0;

    .line 106
    .line 107
    iget-object v8, v6, Lv3/q1;->e:Lv3/e;

    .line 108
    .line 109
    invoke-virtual {v6, v5, v8, v7}, Lv3/q1;->a(Lv3/p1;Lay0/k;Lay0/a;)V

    .line 110
    .line 111
    .line 112
    iput-object v2, v3, Lv3/l0;->d:Lv3/d0;

    .line 113
    .line 114
    invoke-virtual {p0}, Lv3/y0;->E()Lv3/u;

    .line 115
    .line 116
    .line 117
    move-result-object v2

    .line 118
    iget-boolean v2, v2, Lv3/p0;->n:Z

    .line 119
    .line 120
    if-eqz v2, :cond_3

    .line 121
    .line 122
    iget-boolean v2, v3, Lv3/l0;->j:Z

    .line 123
    .line 124
    if-eqz v2, :cond_3

    .line 125
    .line 126
    invoke-virtual {p0}, Lv3/y0;->requestLayout()V

    .line 127
    .line 128
    .line 129
    :cond_3
    iput-boolean v4, p0, Lv3/y0;->A:Z

    .line 130
    .line 131
    :cond_4
    iget-boolean v2, v1, Lv3/i0;->d:Z

    .line 132
    .line 133
    if-eqz v2, :cond_5

    .line 134
    .line 135
    iput-boolean v0, v1, Lv3/i0;->e:Z

    .line 136
    .line 137
    :cond_5
    iget-boolean v0, v1, Lv3/i0;->b:Z

    .line 138
    .line 139
    if-eqz v0, :cond_6

    .line 140
    .line 141
    invoke-virtual {v1}, Lv3/i0;->e()Z

    .line 142
    .line 143
    .line 144
    move-result v0

    .line 145
    if-eqz v0, :cond_6

    .line 146
    .line 147
    invoke-virtual {v1}, Lv3/i0;->g()V

    .line 148
    .line 149
    .line 150
    :cond_6
    iput-boolean v4, p0, Lv3/y0;->E:Z

    .line 151
    .line 152
    return-void
.end method

.method public final w()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lv3/y0;->w:Z

    .line 2
    .line 3
    return p0
.end method
