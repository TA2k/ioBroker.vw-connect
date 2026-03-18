.class public abstract Llp/b1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static a(Lh0/e2;Lh0/e2;)Ljava/util/ArrayList;
    .locals 5

    .line 1
    new-instance v0, Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 4
    .line 5
    .line 6
    new-instance v1, Lh0/d2;

    .line 7
    .line 8
    sget-object v2, Lh0/g2;->d:Lh0/g2;

    .line 9
    .line 10
    invoke-static {v2, p0}, Lh0/h2;->a(Lh0/g2;Lh0/e2;)Lh0/h2;

    .line 11
    .line 12
    .line 13
    move-result-object v3

    .line 14
    sget-object v4, Lh0/g2;->f:Lh0/g2;

    .line 15
    .line 16
    invoke-static {v4, p1}, Lh0/h2;->a(Lh0/g2;Lh0/e2;)Lh0/h2;

    .line 17
    .line 18
    .line 19
    move-result-object v4

    .line 20
    filled-new-array {v3, v4}, [Lh0/h2;

    .line 21
    .line 22
    .line 23
    move-result-object v3

    .line 24
    invoke-direct {v1, v3}, Lh0/d2;-><init>([Lh0/h2;)V

    .line 25
    .line 26
    .line 27
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    new-instance v1, Lh0/d2;

    .line 31
    .line 32
    invoke-static {v2, p0}, Lh0/h2;->a(Lh0/g2;Lh0/e2;)Lh0/h2;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    sget-object v2, Lh0/g2;->g:Lh0/g2;

    .line 37
    .line 38
    invoke-static {v2, p1}, Lh0/h2;->a(Lh0/g2;Lh0/e2;)Lh0/h2;

    .line 39
    .line 40
    .line 41
    move-result-object p1

    .line 42
    filled-new-array {p0, p1}, [Lh0/h2;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    invoke-direct {v1, p0}, Lh0/d2;-><init>([Lh0/h2;)V

    .line 47
    .line 48
    .line 49
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 50
    .line 51
    .line 52
    return-object v0
.end method

.method public static final b(Ljava/util/List;Lhp0/d;)Lhp0/e;
    .locals 2

    .line 1
    check-cast p0, Ljava/lang/Iterable;

    .line 2
    .line 3
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    :cond_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    if-eqz v0, :cond_1

    .line 12
    .line 13
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    move-object v1, v0

    .line 18
    check-cast v1, Lhp0/e;

    .line 19
    .line 20
    iget-object v1, v1, Lhp0/e;->c:Lhp0/d;

    .line 21
    .line 22
    if-ne v1, p1, :cond_0

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_1
    const/4 v0, 0x0

    .line 26
    :goto_0
    check-cast v0, Lhp0/e;

    .line 27
    .line 28
    return-object v0
.end method

.method public static final c(Ljava/util/List;Ljava/util/List;)Ljava/util/ArrayList;
    .locals 5

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Ljava/util/ArrayList;

    .line 7
    .line 8
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 9
    .line 10
    .line 11
    check-cast p1, Ljava/lang/Iterable;

    .line 12
    .line 13
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 14
    .line 15
    .line 16
    move-result-object p1

    .line 17
    :cond_0
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-eqz v1, :cond_3

    .line 22
    .line 23
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object v1

    .line 27
    check-cast v1, Lhp0/d;

    .line 28
    .line 29
    move-object v2, p0

    .line 30
    check-cast v2, Ljava/lang/Iterable;

    .line 31
    .line 32
    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 33
    .line 34
    .line 35
    move-result-object v2

    .line 36
    :cond_1
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 37
    .line 38
    .line 39
    move-result v3

    .line 40
    if-eqz v3, :cond_2

    .line 41
    .line 42
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    move-result-object v3

    .line 46
    move-object v4, v3

    .line 47
    check-cast v4, Lhp0/e;

    .line 48
    .line 49
    iget-object v4, v4, Lhp0/e;->c:Lhp0/d;

    .line 50
    .line 51
    if-ne v4, v1, :cond_1

    .line 52
    .line 53
    goto :goto_1

    .line 54
    :cond_2
    const/4 v3, 0x0

    .line 55
    :goto_1
    check-cast v3, Lhp0/e;

    .line 56
    .line 57
    if-eqz v3, :cond_0

    .line 58
    .line 59
    invoke-virtual {v0, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 60
    .line 61
    .line 62
    goto :goto_0

    .line 63
    :cond_3
    return-object v0
.end method
