.class public final Ly6/b;
.super Leb/j0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# virtual methods
.method public final J()Ljava/util/ArrayList;
    .locals 1

    .line 1
    iget-object p0, p0, Leb/j0;->g:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Ly6/l;

    .line 4
    .line 5
    instance-of v0, p0, Ly6/n;

    .line 6
    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    check-cast p0, Ly6/n;

    .line 10
    .line 11
    iget-object p0, p0, Ly6/n;->b:Ljava/util/ArrayList;

    .line 12
    .line 13
    return-object p0

    .line 14
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 15
    .line 16
    const-string v0, "Current node cannot accept children"

    .line 17
    .line 18
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    throw p0
.end method

.method public final b(III)V
    .locals 0

    .line 1
    invoke-virtual {p0}, Ly6/b;->J()Ljava/util/ArrayList;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-static {p0, p1, p2, p3}, Leb/j0;->y(Ljava/util/ArrayList;III)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public final c(II)V
    .locals 1

    .line 1
    invoke-virtual {p0}, Ly6/b;->J()Ljava/util/ArrayList;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    const/4 v0, 0x1

    .line 6
    if-ne p2, v0, :cond_0

    .line 7
    .line 8
    invoke-virtual {p0, p1}, Ljava/util/ArrayList;->remove(I)Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    return-void

    .line 12
    :cond_0
    add-int/2addr p2, p1

    .line 13
    invoke-virtual {p0, p1, p2}, Ljava/util/ArrayList;->subList(II)Ljava/util/List;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    invoke-interface {p0}, Ljava/util/List;->clear()V

    .line 18
    .line 19
    .line 20
    return-void
.end method

.method public final e(ILjava/lang/Object;)V
    .locals 2

    .line 1
    check-cast p2, Ly6/l;

    .line 2
    .line 3
    iget-object v0, p0, Leb/j0;->g:Ljava/lang/Object;

    .line 4
    .line 5
    const-string v1, "null cannot be cast to non-null type androidx.glance.EmittableWithChildren"

    .line 6
    .line 7
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    check-cast v0, Ly6/n;

    .line 11
    .line 12
    iget v0, v0, Ly6/n;->a:I

    .line 13
    .line 14
    if-lez v0, :cond_1

    .line 15
    .line 16
    instance-of v1, p2, Ly6/n;

    .line 17
    .line 18
    if-eqz v1, :cond_0

    .line 19
    .line 20
    move-object v1, p2

    .line 21
    check-cast v1, Ly6/n;

    .line 22
    .line 23
    add-int/lit8 v0, v0, -0x1

    .line 24
    .line 25
    iput v0, v1, Ly6/n;->a:I

    .line 26
    .line 27
    :cond_0
    invoke-virtual {p0}, Ly6/b;->J()Ljava/util/ArrayList;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    invoke-virtual {p0, p1, p2}, Ljava/util/ArrayList;->add(ILjava/lang/Object;)V

    .line 32
    .line 33
    .line 34
    return-void

    .line 35
    :cond_1
    new-instance p1, Ljava/lang/StringBuilder;

    .line 36
    .line 37
    const-string p2, "Too many embedded views for the current surface. The maximum depth is: "

    .line 38
    .line 39
    invoke-direct {p1, p2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 40
    .line 41
    .line 42
    iget-object p0, p0, Leb/j0;->e:Ljava/lang/Object;

    .line 43
    .line 44
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    check-cast p0, Ly6/n;

    .line 48
    .line 49
    iget p0, p0, Ly6/n;->a:I

    .line 50
    .line 51
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 52
    .line 53
    .line 54
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 55
    .line 56
    .line 57
    move-result-object p0

    .line 58
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 59
    .line 60
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 61
    .line 62
    .line 63
    move-result-object p0

    .line 64
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 65
    .line 66
    .line 67
    throw p1
.end method

.method public final bridge synthetic k(ILjava/lang/Object;)V
    .locals 0

    .line 1
    check-cast p2, Ly6/l;

    .line 2
    .line 3
    return-void
.end method

.method public final z()V
    .locals 1

    .line 1
    iget-object p0, p0, Leb/j0;->e:Ljava/lang/Object;

    .line 2
    .line 3
    const-string v0, "null cannot be cast to non-null type androidx.glance.EmittableWithChildren"

    .line 4
    .line 5
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    check-cast p0, Ly6/n;

    .line 9
    .line 10
    iget-object p0, p0, Ly6/n;->b:Ljava/util/ArrayList;

    .line 11
    .line 12
    invoke-virtual {p0}, Ljava/util/ArrayList;->clear()V

    .line 13
    .line 14
    .line 15
    return-void
.end method
