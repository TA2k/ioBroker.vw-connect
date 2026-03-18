.class public final Lhr/j0;
.super Lhr/b0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# virtual methods
.method public final c(Ljava/lang/Object;)Lhr/b0;
    .locals 0

    .line 1
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0, p1}, Lhr/b0;->a(Ljava/lang/Object;)V

    .line 5
    .line 6
    .line 7
    return-object p0
.end method

.method public final i()Lhr/k0;
    .locals 3

    .line 1
    iget v0, p0, Lhr/b0;->e:I

    .line 2
    .line 3
    if-eqz v0, :cond_1

    .line 4
    .line 5
    const/4 v1, 0x1

    .line 6
    if-eq v0, v1, :cond_0

    .line 7
    .line 8
    iget-object v2, p0, Lhr/b0;->f:[Ljava/lang/Object;

    .line 9
    .line 10
    invoke-static {v0, v2}, Lhr/k0;->o(I[Ljava/lang/Object;)Lhr/k0;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    invoke-virtual {v0}, Ljava/util/AbstractCollection;->size()I

    .line 15
    .line 16
    .line 17
    move-result v2

    .line 18
    iput v2, p0, Lhr/b0;->e:I

    .line 19
    .line 20
    iput-boolean v1, p0, Lhr/b0;->d:Z

    .line 21
    .line 22
    return-object v0

    .line 23
    :cond_0
    iget-object p0, p0, Lhr/b0;->f:[Ljava/lang/Object;

    .line 24
    .line 25
    const/4 v0, 0x0

    .line 26
    aget-object p0, p0, v0

    .line 27
    .line 28
    invoke-static {p0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    sget v0, Lhr/k0;->f:I

    .line 32
    .line 33
    new-instance v0, Lhr/j1;

    .line 34
    .line 35
    invoke-direct {v0, p0}, Lhr/j1;-><init>(Ljava/lang/Object;)V

    .line 36
    .line 37
    .line 38
    return-object v0

    .line 39
    :cond_1
    sget p0, Lhr/k0;->f:I

    .line 40
    .line 41
    sget-object p0, Lhr/d1;->m:Lhr/d1;

    .line 42
    .line 43
    return-object p0
.end method
