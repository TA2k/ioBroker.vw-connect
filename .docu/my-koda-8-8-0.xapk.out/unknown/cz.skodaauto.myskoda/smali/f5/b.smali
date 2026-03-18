.class public final Lf5/b;
.super Le5/h;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public n0:I

.field public o0:I

.field public p0:Lh5/a;


# virtual methods
.method public final apply()V
    .locals 3

    .line 1
    invoke-virtual {p0}, Lf5/b;->s()Lh5/i;

    .line 2
    .line 3
    .line 4
    iget v0, p0, Lf5/b;->n0:I

    .line 5
    .line 6
    invoke-static {v0}, Lu/w;->o(I)I

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    const/4 v1, 0x1

    .line 11
    if-eq v0, v1, :cond_2

    .line 12
    .line 13
    const/4 v2, 0x3

    .line 14
    if-eq v0, v2, :cond_2

    .line 15
    .line 16
    const/4 v1, 0x4

    .line 17
    if-eq v0, v1, :cond_1

    .line 18
    .line 19
    const/4 v1, 0x5

    .line 20
    if-eq v0, v1, :cond_0

    .line 21
    .line 22
    const/4 v1, 0x0

    .line 23
    goto :goto_0

    .line 24
    :cond_0
    move v1, v2

    .line 25
    goto :goto_0

    .line 26
    :cond_1
    const/4 v1, 0x2

    .line 27
    :cond_2
    :goto_0
    iget-object v0, p0, Lf5/b;->p0:Lh5/a;

    .line 28
    .line 29
    iput v1, v0, Lh5/a;->t0:I

    .line 30
    .line 31
    iget p0, p0, Lf5/b;->o0:I

    .line 32
    .line 33
    iput p0, v0, Lh5/a;->v0:I

    .line 34
    .line 35
    return-void
.end method

.method public final k(I)Le5/b;
    .locals 0

    .line 1
    iput p1, p0, Lf5/b;->o0:I

    .line 2
    .line 3
    return-object p0
.end method

.method public final l(Ljava/lang/Float;)Le5/b;
    .locals 1

    .line 1
    iget-object v0, p0, Le5/h;->k0:Lz4/q;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Lz4/q;->c(Ljava/lang/Float;)I

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    iput p1, p0, Lf5/b;->o0:I

    .line 8
    .line 9
    return-object p0
.end method

.method public final s()Lh5/i;
    .locals 1

    .line 1
    iget-object v0, p0, Lf5/b;->p0:Lh5/a;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Lh5/a;

    .line 6
    .line 7
    invoke-direct {v0}, Lh5/a;-><init>()V

    .line 8
    .line 9
    .line 10
    iput-object v0, p0, Lf5/b;->p0:Lh5/a;

    .line 11
    .line 12
    :cond_0
    iget-object p0, p0, Lf5/b;->p0:Lh5/a;

    .line 13
    .line 14
    return-object p0
.end method
