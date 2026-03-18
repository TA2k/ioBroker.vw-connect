.class public final Lv3/u0;
.super Lt3/e1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lt3/p0;
.implements Lv3/a;
.implements Lv3/a1;


# instance fields
.field public A:Ljava/lang/Object;

.field public B:Z

.field public final i:Lv3/l0;

.field public j:Z

.field public k:I

.field public l:I

.field public m:Lv3/f0;

.field public n:Z

.field public o:Z

.field public p:Z

.field public q:Lt4/a;

.field public r:J

.field public s:Lay0/k;

.field public t:Lh3/c;

.field public u:Lv3/r0;

.field public final v:Lv3/i0;

.field public final w:Ln2/b;

.field public x:Z

.field public y:Z

.field public z:Z


# direct methods
.method public constructor <init>(Lv3/l0;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Lt3/e1;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lv3/u0;->i:Lv3/l0;

    .line 5
    .line 6
    const v0, 0x7fffffff

    .line 7
    .line 8
    .line 9
    iput v0, p0, Lv3/u0;->k:I

    .line 10
    .line 11
    iput v0, p0, Lv3/u0;->l:I

    .line 12
    .line 13
    sget-object v0, Lv3/f0;->f:Lv3/f0;

    .line 14
    .line 15
    iput-object v0, p0, Lv3/u0;->m:Lv3/f0;

    .line 16
    .line 17
    const-wide/16 v0, 0x0

    .line 18
    .line 19
    iput-wide v0, p0, Lv3/u0;->r:J

    .line 20
    .line 21
    sget-object v0, Lv3/r0;->f:Lv3/r0;

    .line 22
    .line 23
    iput-object v0, p0, Lv3/u0;->u:Lv3/r0;

    .line 24
    .line 25
    new-instance v0, Lv3/i0;

    .line 26
    .line 27
    const/4 v1, 0x1

    .line 28
    invoke-direct {v0, p0, v1}, Lv3/i0;-><init>(Lv3/a;I)V

    .line 29
    .line 30
    .line 31
    iput-object v0, p0, Lv3/u0;->v:Lv3/i0;

    .line 32
    .line 33
    new-instance v0, Ln2/b;

    .line 34
    .line 35
    const/16 v1, 0x10

    .line 36
    .line 37
    new-array v1, v1, [Lv3/u0;

    .line 38
    .line 39
    invoke-direct {v0, v1}, Ln2/b;-><init>([Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    iput-object v0, p0, Lv3/u0;->w:Ln2/b;

    .line 43
    .line 44
    const/4 v0, 0x1

    .line 45
    iput-boolean v0, p0, Lv3/u0;->x:Z

    .line 46
    .line 47
    iput-boolean v0, p0, Lv3/u0;->z:Z

    .line 48
    .line 49
    iget-object p1, p1, Lv3/l0;->p:Lv3/y0;

    .line 50
    .line 51
    iget-object p1, p1, Lv3/y0;->v:Ljava/lang/Object;

    .line 52
    .line 53
    iput-object p1, p0, Lv3/u0;->A:Ljava/lang/Object;

    .line 54
    .line 55
    return-void
.end method


# virtual methods
.method public final A(I)I
    .locals 0

    .line 1
    invoke-virtual {p0}, Lv3/u0;->F0()V

    .line 2
    .line 3
    .line 4
    iget-object p0, p0, Lv3/u0;->i:Lv3/l0;

    .line 5
    .line 6
    invoke-virtual {p0}, Lv3/l0;->a()Lv3/f1;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    invoke-virtual {p0}, Lv3/f1;->d1()Lv3/q0;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    invoke-interface {p0, p1}, Lt3/p0;->A(I)I

    .line 18
    .line 19
    .line 20
    move-result p0

    .line 21
    return p0
.end method

.method public final B0(Z)V
    .locals 3

    .line 1
    iget-object v0, p0, Lv3/u0;->i:Lv3/l0;

    .line 2
    .line 3
    if-eqz p1, :cond_0

    .line 4
    .line 5
    iget-boolean v1, v0, Lv3/l0;->c:Z

    .line 6
    .line 7
    if-nez v1, :cond_2

    .line 8
    .line 9
    :cond_0
    if-nez p1, :cond_1

    .line 10
    .line 11
    iget-boolean p1, v0, Lv3/l0;->c:Z

    .line 12
    .line 13
    if-nez p1, :cond_1

    .line 14
    .line 15
    goto :goto_1

    .line 16
    :cond_1
    sget-object p1, Lv3/r0;->f:Lv3/r0;

    .line 17
    .line 18
    iput-object p1, p0, Lv3/u0;->u:Lv3/r0;

    .line 19
    .line 20
    iget-object p0, v0, Lv3/l0;->a:Lv3/h0;

    .line 21
    .line 22
    invoke-virtual {p0}, Lv3/h0;->z()Ln2/b;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    iget-object p1, p0, Ln2/b;->d:[Ljava/lang/Object;

    .line 27
    .line 28
    iget p0, p0, Ln2/b;->f:I

    .line 29
    .line 30
    const/4 v0, 0x0

    .line 31
    :goto_0
    if-ge v0, p0, :cond_2

    .line 32
    .line 33
    aget-object v1, p1, v0

    .line 34
    .line 35
    check-cast v1, Lv3/h0;

    .line 36
    .line 37
    iget-object v1, v1, Lv3/h0;->I:Lv3/l0;

    .line 38
    .line 39
    iget-object v1, v1, Lv3/l0;->q:Lv3/u0;

    .line 40
    .line 41
    invoke-static {v1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    const/4 v2, 0x1

    .line 45
    invoke-virtual {v1, v2}, Lv3/u0;->B0(Z)V

    .line 46
    .line 47
    .line 48
    add-int/lit8 v0, v0, 0x1

    .line 49
    .line 50
    goto :goto_0

    .line 51
    :cond_2
    :goto_1
    return-void
.end method

.method public final C0()V
    .locals 6

    .line 1
    iget-object v0, p0, Lv3/u0;->u:Lv3/r0;

    .line 2
    .line 3
    iget-object v1, p0, Lv3/u0;->i:Lv3/l0;

    .line 4
    .line 5
    iget-boolean v2, v1, Lv3/l0;->c:Z

    .line 6
    .line 7
    iget-object v3, v1, Lv3/l0;->a:Lv3/h0;

    .line 8
    .line 9
    if-eqz v2, :cond_0

    .line 10
    .line 11
    sget-object v2, Lv3/r0;->e:Lv3/r0;

    .line 12
    .line 13
    iput-object v2, p0, Lv3/u0;->u:Lv3/r0;

    .line 14
    .line 15
    goto :goto_0

    .line 16
    :cond_0
    sget-object v2, Lv3/r0;->d:Lv3/r0;

    .line 17
    .line 18
    iput-object v2, p0, Lv3/u0;->u:Lv3/r0;

    .line 19
    .line 20
    :goto_0
    sget-object p0, Lv3/r0;->d:Lv3/r0;

    .line 21
    .line 22
    if-eq v0, p0, :cond_1

    .line 23
    .line 24
    iget-boolean p0, v1, Lv3/l0;->e:Z

    .line 25
    .line 26
    if-eqz p0, :cond_1

    .line 27
    .line 28
    const/4 p0, 0x6

    .line 29
    const/4 v0, 0x1

    .line 30
    invoke-static {v3, v0, p0}, Lv3/h0;->W(Lv3/h0;ZI)V

    .line 31
    .line 32
    .line 33
    :cond_1
    invoke-virtual {v3}, Lv3/h0;->z()Ln2/b;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    iget-object v0, p0, Ln2/b;->d:[Ljava/lang/Object;

    .line 38
    .line 39
    iget p0, p0, Ln2/b;->f:I

    .line 40
    .line 41
    const/4 v1, 0x0

    .line 42
    :goto_1
    if-ge v1, p0, :cond_4

    .line 43
    .line 44
    aget-object v2, v0, v1

    .line 45
    .line 46
    check-cast v2, Lv3/h0;

    .line 47
    .line 48
    iget-object v3, v2, Lv3/h0;->I:Lv3/l0;

    .line 49
    .line 50
    iget-object v3, v3, Lv3/l0;->q:Lv3/u0;

    .line 51
    .line 52
    if-eqz v3, :cond_3

    .line 53
    .line 54
    iget v4, v3, Lv3/u0;->l:I

    .line 55
    .line 56
    const v5, 0x7fffffff

    .line 57
    .line 58
    .line 59
    if-eq v4, v5, :cond_2

    .line 60
    .line 61
    invoke-virtual {v3}, Lv3/u0;->C0()V

    .line 62
    .line 63
    .line 64
    invoke-static {v2}, Lv3/h0;->Z(Lv3/h0;)V

    .line 65
    .line 66
    .line 67
    :cond_2
    add-int/lit8 v1, v1, 0x1

    .line 68
    .line 69
    goto :goto_1

    .line 70
    :cond_3
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 71
    .line 72
    const-string v0, "Error: Child node\'s lookahead pass delegate cannot be null when in a lookahead scope."

    .line 73
    .line 74
    invoke-direct {p0, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 75
    .line 76
    .line 77
    throw p0

    .line 78
    :cond_4
    return-void
.end method

.method public final D(La3/f;)V
    .locals 3

    .line 1
    iget-object p0, p0, Lv3/u0;->i:Lv3/l0;

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
    iget-object v2, v2, Lv3/l0;->q:Lv3/u0;

    .line 23
    .line 24
    invoke-static {v2}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 25
    .line 26
    .line 27
    invoke-virtual {p1, v2}, La3/f;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    add-int/lit8 v1, v1, 0x1

    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_0
    return-void
.end method

.method public final E()Lv3/u;
    .locals 0

    .line 1
    iget-object p0, p0, Lv3/u0;->i:Lv3/l0;

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
    .locals 6

    .line 1
    iget-object p0, p0, Lv3/u0;->i:Lv3/l0;

    .line 2
    .line 3
    iget v0, p0, Lv3/l0;->o:I

    .line 4
    .line 5
    if-lez v0, :cond_3

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
    if-ge v2, p0, :cond_3

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
    iget-boolean v5, v4, Lv3/l0;->m:Z

    .line 28
    .line 29
    if-nez v5, :cond_0

    .line 30
    .line 31
    iget-boolean v5, v4, Lv3/l0;->n:Z

    .line 32
    .line 33
    if-eqz v5, :cond_1

    .line 34
    .line 35
    :cond_0
    iget-boolean v5, v4, Lv3/l0;->f:Z

    .line 36
    .line 37
    if-nez v5, :cond_1

    .line 38
    .line 39
    invoke-virtual {v3, v1}, Lv3/h0;->V(Z)V

    .line 40
    .line 41
    .line 42
    :cond_1
    iget-object v3, v4, Lv3/l0;->q:Lv3/u0;

    .line 43
    .line 44
    if-eqz v3, :cond_2

    .line 45
    .line 46
    invoke-virtual {v3}, Lv3/u0;->E0()V

    .line 47
    .line 48
    .line 49
    :cond_2
    add-int/lit8 v2, v2, 0x1

    .line 50
    .line 51
    goto :goto_0

    .line 52
    :cond_3
    return-void
.end method

.method public final F0()V
    .locals 3

    .line 1
    iget-object p0, p0, Lv3/u0;->i:Lv3/l0;

    .line 2
    .line 3
    iget-object v0, p0, Lv3/l0;->a:Lv3/h0;

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    const/4 v2, 0x7

    .line 7
    invoke-static {v0, v1, v2}, Lv3/h0;->W(Lv3/h0;ZI)V

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

.method public final G(I)I
    .locals 0

    .line 1
    invoke-virtual {p0}, Lv3/u0;->F0()V

    .line 2
    .line 3
    .line 4
    iget-object p0, p0, Lv3/u0;->i:Lv3/l0;

    .line 5
    .line 6
    invoke-virtual {p0}, Lv3/l0;->a()Lv3/f1;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    invoke-virtual {p0}, Lv3/f1;->d1()Lv3/q0;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    invoke-interface {p0, p1}, Lt3/p0;->G(I)I

    .line 18
    .line 19
    .line 20
    move-result p0

    .line 21
    return p0
.end method

.method public final H0()V
    .locals 6

    .line 1
    const/4 v0, 0x1

    .line 2
    iput-boolean v0, p0, Lv3/u0;->B:Z

    .line 3
    .line 4
    iget-object v1, p0, Lv3/u0;->i:Lv3/l0;

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
    iget-object v3, p0, Lv3/u0;->u:Lv3/r0;

    .line 13
    .line 14
    sget-object v4, Lv3/r0;->d:Lv3/r0;

    .line 15
    .line 16
    const/4 v5, 0x0

    .line 17
    if-eq v3, v4, :cond_0

    .line 18
    .line 19
    iget-boolean v4, v1, Lv3/l0;->c:Z

    .line 20
    .line 21
    if-eqz v4, :cond_1

    .line 22
    .line 23
    :cond_0
    sget-object v4, Lv3/r0;->e:Lv3/r0;

    .line 24
    .line 25
    if-eq v3, v4, :cond_2

    .line 26
    .line 27
    iget-boolean v1, v1, Lv3/l0;->c:Z

    .line 28
    .line 29
    if-eqz v1, :cond_2

    .line 30
    .line 31
    :cond_1
    invoke-virtual {p0}, Lv3/u0;->C0()V

    .line 32
    .line 33
    .line 34
    iget-boolean v1, p0, Lv3/u0;->j:Z

    .line 35
    .line 36
    if-eqz v1, :cond_2

    .line 37
    .line 38
    if-eqz v2, :cond_2

    .line 39
    .line 40
    invoke-virtual {v2, v5}, Lv3/h0;->V(Z)V

    .line 41
    .line 42
    .line 43
    :cond_2
    if-eqz v2, :cond_5

    .line 44
    .line 45
    iget-object v1, v2, Lv3/h0;->I:Lv3/l0;

    .line 46
    .line 47
    iget-boolean v2, p0, Lv3/u0;->j:Z

    .line 48
    .line 49
    if-nez v2, :cond_6

    .line 50
    .line 51
    iget-object v2, v1, Lv3/l0;->d:Lv3/d0;

    .line 52
    .line 53
    sget-object v3, Lv3/d0;->f:Lv3/d0;

    .line 54
    .line 55
    if-eq v2, v3, :cond_3

    .line 56
    .line 57
    sget-object v3, Lv3/d0;->g:Lv3/d0;

    .line 58
    .line 59
    if-ne v2, v3, :cond_6

    .line 60
    .line 61
    :cond_3
    iget v2, p0, Lv3/u0;->l:I

    .line 62
    .line 63
    const v3, 0x7fffffff

    .line 64
    .line 65
    .line 66
    if-ne v2, v3, :cond_4

    .line 67
    .line 68
    goto :goto_0

    .line 69
    :cond_4
    const-string v2, "Place was called on a node which was placed already"

    .line 70
    .line 71
    invoke-static {v2}, Ls3/a;->b(Ljava/lang/String;)V

    .line 72
    .line 73
    .line 74
    :goto_0
    iget v2, v1, Lv3/l0;->h:I

    .line 75
    .line 76
    iput v2, p0, Lv3/u0;->l:I

    .line 77
    .line 78
    add-int/2addr v2, v0

    .line 79
    iput v2, v1, Lv3/l0;->h:I

    .line 80
    .line 81
    goto :goto_1

    .line 82
    :cond_5
    iput v5, p0, Lv3/u0;->l:I

    .line 83
    .line 84
    :cond_6
    :goto_1
    invoke-virtual {p0}, Lv3/u0;->t()V

    .line 85
    .line 86
    .line 87
    return-void
.end method

.method public final J(I)I
    .locals 0

    .line 1
    invoke-virtual {p0}, Lv3/u0;->F0()V

    .line 2
    .line 3
    .line 4
    iget-object p0, p0, Lv3/u0;->i:Lv3/l0;

    .line 5
    .line 6
    invoke-virtual {p0}, Lv3/l0;->a()Lv3/f1;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    invoke-virtual {p0}, Lv3/f1;->d1()Lv3/q0;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    invoke-interface {p0, p1}, Lt3/p0;->J(I)I

    .line 18
    .line 19
    .line 20
    move-result p0

    .line 21
    return p0
.end method

.method public final J0(JLay0/k;Lh3/c;)V
    .locals 9

    .line 1
    iget-object v0, p0, Lv3/u0;->i:Lv3/l0;

    .line 2
    .line 3
    iget-object v1, v0, Lv3/l0;->a:Lv3/h0;

    .line 4
    .line 5
    iget-object v2, v0, Lv3/l0;->a:Lv3/h0;

    .line 6
    .line 7
    const/4 v3, 0x0

    .line 8
    :try_start_0
    invoke-virtual {v1}, Lv3/h0;->v()Lv3/h0;

    .line 9
    .line 10
    .line 11
    move-result-object v4

    .line 12
    if-eqz v4, :cond_0

    .line 13
    .line 14
    iget-object v4, v4, Lv3/h0;->I:Lv3/l0;

    .line 15
    .line 16
    iget-object v4, v4, Lv3/l0;->d:Lv3/d0;

    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_0
    move-object v4, v3

    .line 20
    :goto_0
    sget-object v5, Lv3/d0;->g:Lv3/d0;

    .line 21
    .line 22
    const/4 v6, 0x0

    .line 23
    if-ne v4, v5, :cond_1

    .line 24
    .line 25
    iput-boolean v6, v0, Lv3/l0;->c:Z

    .line 26
    .line 27
    goto :goto_1

    .line 28
    :catchall_0
    move-exception p0

    .line 29
    goto/16 :goto_3

    .line 30
    .line 31
    :cond_1
    :goto_1
    iget-boolean v4, v2, Lv3/h0;->S:Z

    .line 32
    .line 33
    if-eqz v4, :cond_2

    .line 34
    .line 35
    const-string v4, "place is called on a deactivated node"

    .line 36
    .line 37
    invoke-static {v4}, Ls3/a;->a(Ljava/lang/String;)V

    .line 38
    .line 39
    .line 40
    :cond_2
    iput-object v5, v0, Lv3/l0;->d:Lv3/d0;

    .line 41
    .line 42
    const/4 v4, 0x1

    .line 43
    iput-boolean v4, p0, Lv3/u0;->o:Z

    .line 44
    .line 45
    iput-boolean v6, p0, Lv3/u0;->B:Z

    .line 46
    .line 47
    iget-wide v7, p0, Lv3/u0;->r:J

    .line 48
    .line 49
    invoke-static {p1, p2, v7, v8}, Lt4/j;->b(JJ)Z

    .line 50
    .line 51
    .line 52
    move-result v5

    .line 53
    if-nez v5, :cond_5

    .line 54
    .line 55
    iget-boolean v5, v0, Lv3/l0;->n:Z

    .line 56
    .line 57
    if-nez v5, :cond_3

    .line 58
    .line 59
    iget-boolean v5, v0, Lv3/l0;->m:Z

    .line 60
    .line 61
    if-eqz v5, :cond_4

    .line 62
    .line 63
    :cond_3
    iput-boolean v4, v0, Lv3/l0;->f:Z

    .line 64
    .line 65
    :cond_4
    invoke-virtual {p0}, Lv3/u0;->E0()V

    .line 66
    .line 67
    .line 68
    :cond_5
    invoke-static {v2}, Lv3/k0;->a(Lv3/h0;)Lv3/o1;

    .line 69
    .line 70
    .line 71
    move-result-object v4

    .line 72
    iget-boolean v5, v0, Lv3/l0;->f:Z

    .line 73
    .line 74
    if-nez v5, :cond_6

    .line 75
    .line 76
    invoke-virtual {p0}, Lv3/u0;->w()Z

    .line 77
    .line 78
    .line 79
    move-result v5

    .line 80
    if-eqz v5, :cond_6

    .line 81
    .line 82
    invoke-virtual {v0}, Lv3/l0;->a()Lv3/f1;

    .line 83
    .line 84
    .line 85
    move-result-object v2

    .line 86
    invoke-virtual {v2}, Lv3/f1;->d1()Lv3/q0;

    .line 87
    .line 88
    .line 89
    move-result-object v2

    .line 90
    invoke-static {v2}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 91
    .line 92
    .line 93
    iget-wide v4, v2, Lt3/e1;->h:J

    .line 94
    .line 95
    invoke-static {p1, p2, v4, v5}, Lt4/j;->d(JJ)J

    .line 96
    .line 97
    .line 98
    move-result-wide v4

    .line 99
    invoke-virtual {v2, v4, v5}, Lv3/q0;->W0(J)V

    .line 100
    .line 101
    .line 102
    invoke-virtual {p0}, Lv3/u0;->H0()V

    .line 103
    .line 104
    .line 105
    goto :goto_2

    .line 106
    :cond_6
    invoke-virtual {v0, v6}, Lv3/l0;->h(Z)V

    .line 107
    .line 108
    .line 109
    iget-object v5, p0, Lv3/u0;->v:Lv3/i0;

    .line 110
    .line 111
    iput-boolean v6, v5, Lv3/i0;->g:Z

    .line 112
    .line 113
    move-object v5, v4

    .line 114
    check-cast v5, Lw3/t;

    .line 115
    .line 116
    invoke-virtual {v5}, Lw3/t;->getSnapshotObserver()Lv3/q1;

    .line 117
    .line 118
    .line 119
    move-result-object v5

    .line 120
    new-instance v6, Lv3/t0;

    .line 121
    .line 122
    invoke-direct {v6, p0, v4, p1, p2}, Lv3/t0;-><init>(Lv3/u0;Lv3/o1;J)V

    .line 123
    .line 124
    .line 125
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 126
    .line 127
    .line 128
    iget-object v4, v2, Lv3/h0;->j:Lv3/h0;

    .line 129
    .line 130
    if-eqz v4, :cond_7

    .line 131
    .line 132
    iget-object v4, v5, Lv3/q1;->g:Lv3/e;

    .line 133
    .line 134
    invoke-virtual {v5, v2, v4, v6}, Lv3/q1;->a(Lv3/p1;Lay0/k;Lay0/a;)V

    .line 135
    .line 136
    .line 137
    goto :goto_2

    .line 138
    :cond_7
    iget-object v4, v5, Lv3/q1;->f:Lv3/e;

    .line 139
    .line 140
    invoke-virtual {v5, v2, v4, v6}, Lv3/q1;->a(Lv3/p1;Lay0/k;Lay0/a;)V

    .line 141
    .line 142
    .line 143
    :goto_2
    iput-wide p1, p0, Lv3/u0;->r:J

    .line 144
    .line 145
    iput-object p3, p0, Lv3/u0;->s:Lay0/k;

    .line 146
    .line 147
    iput-object p4, p0, Lv3/u0;->t:Lh3/c;

    .line 148
    .line 149
    sget-object p0, Lv3/d0;->h:Lv3/d0;

    .line 150
    .line 151
    iput-object p0, v0, Lv3/l0;->d:Lv3/d0;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 152
    .line 153
    return-void

    .line 154
    :goto_3
    invoke-virtual {v1, p0}, Lv3/h0;->b0(Ljava/lang/Throwable;)V

    .line 155
    .line 156
    .line 157
    throw v3
.end method

.method public final L(J)Lt3/e1;
    .locals 5

    .line 1
    iget-object v0, p0, Lv3/u0;->i:Lv3/l0;

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
    sget-object v3, Lv3/d0;->e:Lv3/d0;

    .line 19
    .line 20
    if-eq v1, v3, :cond_2

    .line 21
    .line 22
    iget-object v1, v0, Lv3/l0;->a:Lv3/h0;

    .line 23
    .line 24
    invoke-virtual {v1}, Lv3/h0;->v()Lv3/h0;

    .line 25
    .line 26
    .line 27
    move-result-object v1

    .line 28
    if-eqz v1, :cond_1

    .line 29
    .line 30
    iget-object v1, v1, Lv3/h0;->I:Lv3/l0;

    .line 31
    .line 32
    iget-object v2, v1, Lv3/l0;->d:Lv3/d0;

    .line 33
    .line 34
    :cond_1
    sget-object v1, Lv3/d0;->g:Lv3/d0;

    .line 35
    .line 36
    if-ne v2, v1, :cond_3

    .line 37
    .line 38
    :cond_2
    const/4 v1, 0x0

    .line 39
    iput-boolean v1, v0, Lv3/l0;->b:Z

    .line 40
    .line 41
    :cond_3
    iget-object v1, v0, Lv3/l0;->a:Lv3/h0;

    .line 42
    .line 43
    invoke-virtual {v1}, Lv3/h0;->v()Lv3/h0;

    .line 44
    .line 45
    .line 46
    move-result-object v2

    .line 47
    if-eqz v2, :cond_9

    .line 48
    .line 49
    iget-object v2, v2, Lv3/h0;->I:Lv3/l0;

    .line 50
    .line 51
    iget-object v3, p0, Lv3/u0;->m:Lv3/f0;

    .line 52
    .line 53
    sget-object v4, Lv3/f0;->f:Lv3/f0;

    .line 54
    .line 55
    if-eq v3, v4, :cond_5

    .line 56
    .line 57
    iget-boolean v1, v1, Lv3/h0;->G:Z

    .line 58
    .line 59
    if-eqz v1, :cond_4

    .line 60
    .line 61
    goto :goto_1

    .line 62
    :cond_4
    const-string v1, "measure() may not be called multiple times on the same Measurable. If you want to get the content size of the Measurable before calculating the final constraints, please use methods like minIntrinsicWidth()/maxIntrinsicWidth() and minIntrinsicHeight()/maxIntrinsicHeight()"

    .line 63
    .line 64
    invoke-static {v1}, Ls3/a;->b(Ljava/lang/String;)V

    .line 65
    .line 66
    .line 67
    :cond_5
    :goto_1
    iget-object v1, v2, Lv3/l0;->d:Lv3/d0;

    .line 68
    .line 69
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 70
    .line 71
    .line 72
    move-result v1

    .line 73
    if-eqz v1, :cond_8

    .line 74
    .line 75
    const/4 v3, 0x1

    .line 76
    if-eq v1, v3, :cond_8

    .line 77
    .line 78
    const/4 v3, 0x2

    .line 79
    if-eq v1, v3, :cond_7

    .line 80
    .line 81
    const/4 v3, 0x3

    .line 82
    if-ne v1, v3, :cond_6

    .line 83
    .line 84
    goto :goto_2

    .line 85
    :cond_6
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 86
    .line 87
    new-instance p1, Ljava/lang/StringBuilder;

    .line 88
    .line 89
    const-string p2, "Measurable could be only measured from the parent\'s measure or layout block. Parents state is "

    .line 90
    .line 91
    invoke-direct {p1, p2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 92
    .line 93
    .line 94
    iget-object p2, v2, Lv3/l0;->d:Lv3/d0;

    .line 95
    .line 96
    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 97
    .line 98
    .line 99
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 100
    .line 101
    .line 102
    move-result-object p1

    .line 103
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 104
    .line 105
    .line 106
    throw p0

    .line 107
    :cond_7
    :goto_2
    sget-object v1, Lv3/f0;->e:Lv3/f0;

    .line 108
    .line 109
    goto :goto_3

    .line 110
    :cond_8
    sget-object v1, Lv3/f0;->d:Lv3/f0;

    .line 111
    .line 112
    :goto_3
    iput-object v1, p0, Lv3/u0;->m:Lv3/f0;

    .line 113
    .line 114
    goto :goto_4

    .line 115
    :cond_9
    sget-object v1, Lv3/f0;->f:Lv3/f0;

    .line 116
    .line 117
    iput-object v1, p0, Lv3/u0;->m:Lv3/f0;

    .line 118
    .line 119
    :goto_4
    iget-object v0, v0, Lv3/l0;->a:Lv3/h0;

    .line 120
    .line 121
    iget-object v1, v0, Lv3/h0;->E:Lv3/f0;

    .line 122
    .line 123
    sget-object v2, Lv3/f0;->f:Lv3/f0;

    .line 124
    .line 125
    if-ne v1, v2, :cond_a

    .line 126
    .line 127
    invoke-virtual {v0}, Lv3/h0;->d()V

    .line 128
    .line 129
    .line 130
    :cond_a
    invoke-virtual {p0, p1, p2}, Lv3/u0;->L0(J)Z

    .line 131
    .line 132
    .line 133
    return-object p0
.end method

.method public final L0(J)Z
    .locals 12

    .line 1
    iget-object v0, p0, Lv3/u0;->i:Lv3/l0;

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
    goto/16 :goto_9

    .line 19
    .line 20
    :cond_0
    :goto_0
    invoke-virtual {v2}, Lv3/h0;->v()Lv3/h0;

    .line 21
    .line 22
    .line 23
    move-result-object v3

    .line 24
    iget-boolean v4, v2, Lv3/h0;->G:Z

    .line 25
    .line 26
    const/4 v5, 0x1

    .line 27
    const/4 v6, 0x0

    .line 28
    if-nez v4, :cond_2

    .line 29
    .line 30
    if-eqz v3, :cond_1

    .line 31
    .line 32
    iget-boolean v3, v3, Lv3/h0;->G:Z

    .line 33
    .line 34
    if-eqz v3, :cond_1

    .line 35
    .line 36
    goto :goto_1

    .line 37
    :cond_1
    move v3, v6

    .line 38
    goto :goto_2

    .line 39
    :cond_2
    :goto_1
    move v3, v5

    .line 40
    :goto_2
    iput-boolean v3, v2, Lv3/h0;->G:Z

    .line 41
    .line 42
    iget-object v3, v2, Lv3/h0;->I:Lv3/l0;

    .line 43
    .line 44
    iget-boolean v3, v3, Lv3/l0;->e:Z

    .line 45
    .line 46
    if-nez v3, :cond_6

    .line 47
    .line 48
    iget-object v3, p0, Lv3/u0;->q:Lt4/a;

    .line 49
    .line 50
    if-nez v3, :cond_3

    .line 51
    .line 52
    move v3, v6

    .line 53
    goto :goto_3

    .line 54
    :cond_3
    iget-wide v3, v3, Lt4/a;->a:J

    .line 55
    .line 56
    invoke-static {v3, v4, p1, p2}, Lt4/a;->b(JJ)Z

    .line 57
    .line 58
    .line 59
    move-result v3

    .line 60
    :goto_3
    if-nez v3, :cond_4

    .line 61
    .line 62
    goto :goto_4

    .line 63
    :cond_4
    iget-object p0, v2, Lv3/h0;->p:Lv3/o1;

    .line 64
    .line 65
    if-eqz p0, :cond_5

    .line 66
    .line 67
    check-cast p0, Lw3/t;

    .line 68
    .line 69
    invoke-virtual {p0, v2, v5}, Lw3/t;->i(Lv3/h0;Z)V

    .line 70
    .line 71
    .line 72
    :cond_5
    invoke-virtual {v2}, Lv3/h0;->a0()V

    .line 73
    .line 74
    .line 75
    return v6

    .line 76
    :cond_6
    :goto_4
    new-instance v3, Lt4/a;

    .line 77
    .line 78
    invoke-direct {v3, p1, p2}, Lt4/a;-><init>(J)V

    .line 79
    .line 80
    .line 81
    iput-object v3, p0, Lv3/u0;->q:Lt4/a;

    .line 82
    .line 83
    invoke-virtual {p0, p1, p2}, Lt3/e1;->y0(J)V

    .line 84
    .line 85
    .line 86
    iget-object v3, p0, Lv3/u0;->v:Lv3/i0;

    .line 87
    .line 88
    iput-boolean v6, v3, Lv3/i0;->f:Z

    .line 89
    .line 90
    invoke-virtual {v2}, Lv3/h0;->z()Ln2/b;

    .line 91
    .line 92
    .line 93
    move-result-object v2

    .line 94
    iget-object v3, v2, Ln2/b;->d:[Ljava/lang/Object;

    .line 95
    .line 96
    iget v2, v2, Ln2/b;->f:I

    .line 97
    .line 98
    move v4, v6

    .line 99
    :goto_5
    if-ge v4, v2, :cond_7

    .line 100
    .line 101
    aget-object v7, v3, v4

    .line 102
    .line 103
    check-cast v7, Lv3/h0;

    .line 104
    .line 105
    iget-object v7, v7, Lv3/h0;->I:Lv3/l0;

    .line 106
    .line 107
    iget-object v7, v7, Lv3/l0;->q:Lv3/u0;

    .line 108
    .line 109
    invoke-static {v7}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 110
    .line 111
    .line 112
    iget-object v7, v7, Lv3/u0;->v:Lv3/i0;

    .line 113
    .line 114
    iput-boolean v6, v7, Lv3/i0;->c:Z

    .line 115
    .line 116
    add-int/lit8 v4, v4, 0x1

    .line 117
    .line 118
    goto :goto_5

    .line 119
    :cond_7
    iget-boolean v2, p0, Lv3/u0;->p:Z

    .line 120
    .line 121
    const-wide v3, 0xffffffffL

    .line 122
    .line 123
    .line 124
    .line 125
    .line 126
    const/16 v7, 0x20

    .line 127
    .line 128
    if-eqz v2, :cond_8

    .line 129
    .line 130
    iget-wide v8, p0, Lt3/e1;->f:J

    .line 131
    .line 132
    goto :goto_6

    .line 133
    :cond_8
    const/high16 v2, -0x80000000

    .line 134
    .line 135
    int-to-long v8, v2

    .line 136
    shl-long v10, v8, v7

    .line 137
    .line 138
    and-long/2addr v8, v3

    .line 139
    or-long/2addr v8, v10

    .line 140
    :goto_6
    iput-boolean v5, p0, Lv3/u0;->p:Z

    .line 141
    .line 142
    invoke-virtual {v0}, Lv3/l0;->a()Lv3/f1;

    .line 143
    .line 144
    .line 145
    move-result-object v2

    .line 146
    invoke-virtual {v2}, Lv3/f1;->d1()Lv3/q0;

    .line 147
    .line 148
    .line 149
    move-result-object v2

    .line 150
    if-eqz v2, :cond_9

    .line 151
    .line 152
    move v10, v5

    .line 153
    goto :goto_7

    .line 154
    :cond_9
    move v10, v6

    .line 155
    :goto_7
    if-nez v10, :cond_a

    .line 156
    .line 157
    const-string v10, "Lookahead result from lookaheadRemeasure cannot be null"

    .line 158
    .line 159
    invoke-static {v10}, Ls3/a;->b(Ljava/lang/String;)V

    .line 160
    .line 161
    .line 162
    :cond_a
    invoke-virtual {v0, p1, p2}, Lv3/l0;->c(J)V

    .line 163
    .line 164
    .line 165
    iget p1, v2, Lt3/e1;->d:I

    .line 166
    .line 167
    iget p2, v2, Lt3/e1;->e:I

    .line 168
    .line 169
    int-to-long v10, p1

    .line 170
    shl-long/2addr v10, v7

    .line 171
    int-to-long p1, p2

    .line 172
    and-long/2addr p1, v3

    .line 173
    or-long/2addr p1, v10

    .line 174
    invoke-virtual {p0, p1, p2}, Lt3/e1;->v0(J)V

    .line 175
    .line 176
    .line 177
    shr-long p0, v8, v7

    .line 178
    .line 179
    long-to-int p0, p0

    .line 180
    iget p1, v2, Lt3/e1;->d:I

    .line 181
    .line 182
    if-ne p0, p1, :cond_c

    .line 183
    .line 184
    and-long p0, v8, v3

    .line 185
    .line 186
    long-to-int p0, p0

    .line 187
    iget p1, v2, Lt3/e1;->e:I
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 188
    .line 189
    if-eq p0, p1, :cond_b

    .line 190
    .line 191
    goto :goto_8

    .line 192
    :cond_b
    return v6

    .line 193
    :cond_c
    :goto_8
    return v5

    .line 194
    :goto_9
    invoke-virtual {v1, p0}, Lv3/h0;->b0(Ljava/lang/Throwable;)V

    .line 195
    .line 196
    .line 197
    const/4 p0, 0x0

    .line 198
    throw p0
.end method

.method public final X()V
    .locals 2

    .line 1
    iget-object p0, p0, Lv3/u0;->i:Lv3/l0;

    .line 2
    .line 3
    iget-object p0, p0, Lv3/l0;->a:Lv3/h0;

    .line 4
    .line 5
    const/4 v0, 0x0

    .line 6
    const/4 v1, 0x7

    .line 7
    invoke-static {p0, v0, v1}, Lv3/h0;->W(Lv3/h0;ZI)V

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public final a0(Lt3/a;)I
    .locals 6

    .line 1
    iget-object v0, p0, Lv3/u0;->i:Lv3/l0;

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
    sget-object v3, Lv3/d0;->e:Lv3/d0;

    .line 19
    .line 20
    iget-object v4, p0, Lv3/u0;->v:Lv3/i0;

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
    sget-object v1, Lv3/d0;->g:Lv3/d0;

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
    iput-boolean v5, p0, Lv3/u0;->n:Z

    .line 47
    .line 48
    invoke-virtual {v0}, Lv3/l0;->a()Lv3/f1;

    .line 49
    .line 50
    .line 51
    move-result-object v0

    .line 52
    invoke-virtual {v0}, Lv3/f1;->d1()Lv3/q0;

    .line 53
    .line 54
    .line 55
    move-result-object v0

    .line 56
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    invoke-virtual {v0, p1}, Lv3/p0;->a0(Lt3/a;)I

    .line 60
    .line 61
    .line 62
    move-result p1

    .line 63
    const/4 v0, 0x0

    .line 64
    iput-boolean v0, p0, Lv3/u0;->n:Z

    .line 65
    .line 66
    return p1
.end method

.method public final b()Lv3/i0;
    .locals 0

    .line 1
    iget-object p0, p0, Lv3/u0;->v:Lv3/i0;

    .line 2
    .line 3
    return-object p0
.end method

.method public final b0()I
    .locals 0

    .line 1
    iget-object p0, p0, Lv3/u0;->i:Lv3/l0;

    .line 2
    .line 3
    invoke-virtual {p0}, Lv3/l0;->a()Lv3/f1;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    invoke-virtual {p0}, Lv3/f1;->d1()Lv3/q0;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 12
    .line 13
    .line 14
    invoke-virtual {p0}, Lt3/e1;->b0()I

    .line 15
    .line 16
    .line 17
    move-result p0

    .line 18
    return p0
.end method

.method public final c(I)I
    .locals 0

    .line 1
    invoke-virtual {p0}, Lv3/u0;->F0()V

    .line 2
    .line 3
    .line 4
    iget-object p0, p0, Lv3/u0;->i:Lv3/l0;

    .line 5
    .line 6
    invoke-virtual {p0}, Lv3/l0;->a()Lv3/f1;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    invoke-virtual {p0}, Lv3/f1;->d1()Lv3/q0;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    invoke-interface {p0, p1}, Lt3/p0;->c(I)I

    .line 18
    .line 19
    .line 20
    move-result p0

    .line 21
    return p0
.end method

.method public final d0()I
    .locals 0

    .line 1
    iget-object p0, p0, Lv3/u0;->i:Lv3/l0;

    .line 2
    .line 3
    invoke-virtual {p0}, Lv3/l0;->a()Lv3/f1;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    invoke-virtual {p0}, Lv3/f1;->d1()Lv3/q0;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 12
    .line 13
    .line 14
    invoke-virtual {p0}, Lt3/e1;->d0()I

    .line 15
    .line 16
    .line 17
    move-result p0

    .line 18
    return p0
.end method

.method public final f()Lv3/a;
    .locals 0

    .line 1
    iget-object p0, p0, Lv3/u0;->i:Lv3/l0;

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
    iget-object p0, p0, Lv3/l0;->q:Lv3/u0;

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
    iget-object p0, p0, Lv3/u0;->A:Ljava/lang/Object;

    .line 2
    .line 3
    return-object p0
.end method

.method public final l0(JFLay0/k;)V
    .locals 0

    .line 1
    const/4 p3, 0x0

    .line 2
    invoke-virtual {p0, p1, p2, p4, p3}, Lv3/u0;->J0(JLay0/k;Lh3/c;)V

    .line 3
    .line 4
    .line 5
    return-void
.end method

.method public final m0(JFLh3/c;)V
    .locals 0

    .line 1
    const/4 p3, 0x0

    .line 2
    invoke-virtual {p0, p1, p2, p3, p4}, Lv3/u0;->J0(JLay0/k;Lh3/c;)V

    .line 3
    .line 4
    .line 5
    return-void
.end method

.method public final p(Z)V
    .locals 2

    .line 1
    iget-object p0, p0, Lv3/u0;->i:Lv3/l0;

    .line 2
    .line 3
    invoke-virtual {p0}, Lv3/l0;->a()Lv3/f1;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-virtual {v0}, Lv3/f1;->d1()Lv3/q0;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    if-eqz v0, :cond_0

    .line 12
    .line 13
    iget-boolean v0, v0, Lv3/p0;->l:Z

    .line 14
    .line 15
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    goto :goto_0

    .line 20
    :cond_0
    const/4 v0, 0x0

    .line 21
    :goto_0
    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 22
    .line 23
    .line 24
    move-result-object v1

    .line 25
    invoke-virtual {v1, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    if-nez v0, :cond_1

    .line 30
    .line 31
    invoke-virtual {p0}, Lv3/l0;->a()Lv3/f1;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    invoke-virtual {p0}, Lv3/f1;->d1()Lv3/q0;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    if-eqz p0, :cond_1

    .line 40
    .line 41
    iput-boolean p1, p0, Lv3/p0;->l:Z

    .line 42
    .line 43
    :cond_1
    return-void
.end method

.method public final requestLayout()V
    .locals 1

    .line 1
    iget-object p0, p0, Lv3/u0;->i:Lv3/l0;

    .line 2
    .line 3
    iget-object p0, p0, Lv3/l0;->a:Lv3/h0;

    .line 4
    .line 5
    const/4 v0, 0x0

    .line 6
    invoke-virtual {p0, v0}, Lv3/h0;->V(Z)V

    .line 7
    .line 8
    .line 9
    return-void
.end method

.method public final t()V
    .locals 11

    .line 1
    const/4 v0, 0x1

    .line 2
    iput-boolean v0, p0, Lv3/u0;->y:Z

    .line 3
    .line 4
    iget-object v1, p0, Lv3/u0;->v:Lv3/i0;

    .line 5
    .line 6
    invoke-virtual {v1}, Lv3/i0;->h()V

    .line 7
    .line 8
    .line 9
    iget-object v2, p0, Lv3/u0;->i:Lv3/l0;

    .line 10
    .line 11
    iget-boolean v3, v2, Lv3/l0;->f:Z

    .line 12
    .line 13
    iget-object v4, v2, Lv3/l0;->a:Lv3/h0;

    .line 14
    .line 15
    const/4 v5, 0x0

    .line 16
    if-eqz v3, :cond_2

    .line 17
    .line 18
    invoke-virtual {v4}, Lv3/h0;->z()Ln2/b;

    .line 19
    .line 20
    .line 21
    move-result-object v3

    .line 22
    iget-object v6, v3, Ln2/b;->d:[Ljava/lang/Object;

    .line 23
    .line 24
    iget v3, v3, Ln2/b;->f:I

    .line 25
    .line 26
    move v7, v5

    .line 27
    :goto_0
    if-ge v7, v3, :cond_2

    .line 28
    .line 29
    aget-object v8, v6, v7

    .line 30
    .line 31
    check-cast v8, Lv3/h0;

    .line 32
    .line 33
    iget-object v9, v8, Lv3/h0;->I:Lv3/l0;

    .line 34
    .line 35
    iget-boolean v10, v9, Lv3/l0;->e:Z

    .line 36
    .line 37
    if-eqz v10, :cond_1

    .line 38
    .line 39
    invoke-virtual {v8}, Lv3/h0;->t()Lv3/f0;

    .line 40
    .line 41
    .line 42
    move-result-object v8

    .line 43
    sget-object v10, Lv3/f0;->d:Lv3/f0;

    .line 44
    .line 45
    if-ne v8, v10, :cond_1

    .line 46
    .line 47
    iget-object v8, v9, Lv3/l0;->q:Lv3/u0;

    .line 48
    .line 49
    invoke-static {v8}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 50
    .line 51
    .line 52
    iget-object v9, v9, Lv3/l0;->q:Lv3/u0;

    .line 53
    .line 54
    if-eqz v9, :cond_0

    .line 55
    .line 56
    iget-object v9, v9, Lv3/u0;->q:Lt4/a;

    .line 57
    .line 58
    goto :goto_1

    .line 59
    :cond_0
    const/4 v9, 0x0

    .line 60
    :goto_1
    invoke-static {v9}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 61
    .line 62
    .line 63
    iget-wide v9, v9, Lt4/a;->a:J

    .line 64
    .line 65
    invoke-virtual {v8, v9, v10}, Lv3/u0;->L0(J)Z

    .line 66
    .line 67
    .line 68
    move-result v8

    .line 69
    if-eqz v8, :cond_1

    .line 70
    .line 71
    const/4 v8, 0x7

    .line 72
    invoke-static {v4, v5, v8}, Lv3/h0;->W(Lv3/h0;ZI)V

    .line 73
    .line 74
    .line 75
    :cond_1
    add-int/lit8 v7, v7, 0x1

    .line 76
    .line 77
    goto :goto_0

    .line 78
    :cond_2
    invoke-virtual {p0}, Lv3/u0;->E()Lv3/u;

    .line 79
    .line 80
    .line 81
    move-result-object v3

    .line 82
    iget-object v3, v3, Lv3/u;->T:Lv3/t;

    .line 83
    .line 84
    invoke-static {v3}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 85
    .line 86
    .line 87
    iget-boolean v6, v2, Lv3/l0;->g:Z

    .line 88
    .line 89
    if-nez v6, :cond_3

    .line 90
    .line 91
    iget-boolean v6, p0, Lv3/u0;->n:Z

    .line 92
    .line 93
    if-nez v6, :cond_6

    .line 94
    .line 95
    iget-boolean v6, v3, Lv3/p0;->n:Z

    .line 96
    .line 97
    if-nez v6, :cond_6

    .line 98
    .line 99
    iget-boolean v6, v2, Lv3/l0;->f:Z

    .line 100
    .line 101
    if-eqz v6, :cond_6

    .line 102
    .line 103
    :cond_3
    iput-boolean v5, v2, Lv3/l0;->f:Z

    .line 104
    .line 105
    iget-object v6, v2, Lv3/l0;->d:Lv3/d0;

    .line 106
    .line 107
    sget-object v7, Lv3/d0;->g:Lv3/d0;

    .line 108
    .line 109
    iput-object v7, v2, Lv3/l0;->d:Lv3/d0;

    .line 110
    .line 111
    invoke-static {v4}, Lv3/k0;->a(Lv3/h0;)Lv3/o1;

    .line 112
    .line 113
    .line 114
    move-result-object v7

    .line 115
    invoke-virtual {v2, v5}, Lv3/l0;->i(Z)V

    .line 116
    .line 117
    .line 118
    check-cast v7, Lw3/t;

    .line 119
    .line 120
    invoke-virtual {v7}, Lw3/t;->getSnapshotObserver()Lv3/q1;

    .line 121
    .line 122
    .line 123
    move-result-object v7

    .line 124
    new-instance v8, La4/b;

    .line 125
    .line 126
    const/16 v9, 0x8

    .line 127
    .line 128
    invoke-direct {v8, v9, p0, v3}, La4/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 129
    .line 130
    .line 131
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 132
    .line 133
    .line 134
    iget-object v9, v4, Lv3/h0;->j:Lv3/h0;

    .line 135
    .line 136
    if-eqz v9, :cond_4

    .line 137
    .line 138
    iget-object v9, v7, Lv3/q1;->h:Lv3/e;

    .line 139
    .line 140
    invoke-virtual {v7, v4, v9, v8}, Lv3/q1;->a(Lv3/p1;Lay0/k;Lay0/a;)V

    .line 141
    .line 142
    .line 143
    goto :goto_2

    .line 144
    :cond_4
    iget-object v9, v7, Lv3/q1;->e:Lv3/e;

    .line 145
    .line 146
    invoke-virtual {v7, v4, v9, v8}, Lv3/q1;->a(Lv3/p1;Lay0/k;Lay0/a;)V

    .line 147
    .line 148
    .line 149
    :goto_2
    iput-object v6, v2, Lv3/l0;->d:Lv3/d0;

    .line 150
    .line 151
    iget-boolean v4, v2, Lv3/l0;->m:Z

    .line 152
    .line 153
    if-eqz v4, :cond_5

    .line 154
    .line 155
    iget-boolean v3, v3, Lv3/p0;->n:Z

    .line 156
    .line 157
    if-eqz v3, :cond_5

    .line 158
    .line 159
    invoke-virtual {p0}, Lv3/u0;->requestLayout()V

    .line 160
    .line 161
    .line 162
    :cond_5
    iput-boolean v5, v2, Lv3/l0;->g:Z

    .line 163
    .line 164
    :cond_6
    iget-boolean v2, v1, Lv3/i0;->d:Z

    .line 165
    .line 166
    if-eqz v2, :cond_7

    .line 167
    .line 168
    iput-boolean v0, v1, Lv3/i0;->e:Z

    .line 169
    .line 170
    :cond_7
    iget-boolean v0, v1, Lv3/i0;->b:Z

    .line 171
    .line 172
    if-eqz v0, :cond_8

    .line 173
    .line 174
    invoke-virtual {v1}, Lv3/i0;->e()Z

    .line 175
    .line 176
    .line 177
    move-result v0

    .line 178
    if-eqz v0, :cond_8

    .line 179
    .line 180
    invoke-virtual {v1}, Lv3/i0;->g()V

    .line 181
    .line 182
    .line 183
    :cond_8
    iput-boolean v5, p0, Lv3/u0;->y:Z

    .line 184
    .line 185
    return-void
.end method

.method public final w()Z
    .locals 1

    .line 1
    iget-object p0, p0, Lv3/u0;->u:Lv3/r0;

    .line 2
    .line 3
    sget-object v0, Lv3/r0;->f:Lv3/r0;

    .line 4
    .line 5
    if-eq p0, v0, :cond_0

    .line 6
    .line 7
    const/4 p0, 0x1

    .line 8
    return p0

    .line 9
    :cond_0
    const/4 p0, 0x0

    .line 10
    return p0
.end method
