.class public abstract Lkp/u6;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lqz0/a;)Luz0/d;
    .locals 2

    .line 1
    const-string v0, "elementSerializer"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Luz0/d;

    .line 7
    .line 8
    const/4 v1, 0x0

    .line 9
    invoke-direct {v0, p0, v1}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 10
    .line 11
    .line 12
    return-object v0
.end method

.method public static final b(Lqz0/a;Lqz0/a;)Luz0/e0;
    .locals 2

    .line 1
    const-string v0, "keySerializer"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "valueSerializer"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    new-instance v0, Luz0/e0;

    .line 12
    .line 13
    const/4 v1, 0x1

    .line 14
    invoke-direct {v0, p0, p1, v1}, Luz0/e0;-><init>(Lqz0/a;Lqz0/a;I)V

    .line 15
    .line 16
    .line 17
    return-object v0
.end method

.method public static final c(Lqz0/a;)Lqz0/a;
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p0}, Lqz0/a;->getDescriptor()Lsz0/g;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    invoke-interface {v0}, Lsz0/g;->b()Z

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    if-eqz v0, :cond_0

    .line 15
    .line 16
    return-object p0

    .line 17
    :cond_0
    new-instance v0, Luz0/y0;

    .line 18
    .line 19
    invoke-direct {v0, p0}, Luz0/y0;-><init>(Lqz0/a;)V

    .line 20
    .line 21
    .line 22
    return-object v0
.end method

.method public static final d(Lss0/b;Lss0/e;)Ler0/g;
    .locals 3

    .line 1
    const-string v0, "capabilityId"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    if-eqz p0, :cond_6

    .line 7
    .line 8
    iget-object p0, p0, Lss0/b;->a:Ljava/util/List;

    .line 9
    .line 10
    if-eqz p0, :cond_6

    .line 11
    .line 12
    check-cast p0, Ljava/lang/Iterable;

    .line 13
    .line 14
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    :cond_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    const/4 v1, 0x0

    .line 23
    if-eqz v0, :cond_1

    .line 24
    .line 25
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    move-object v2, v0

    .line 30
    check-cast v2, Lss0/c;

    .line 31
    .line 32
    iget-object v2, v2, Lss0/c;->a:Lss0/e;

    .line 33
    .line 34
    if-ne v2, p1, :cond_0

    .line 35
    .line 36
    goto :goto_0

    .line 37
    :cond_1
    move-object v0, v1

    .line 38
    :goto_0
    check-cast v0, Lss0/c;

    .line 39
    .line 40
    if-eqz v0, :cond_6

    .line 41
    .line 42
    iget-object p0, v0, Lss0/c;->c:Ljava/lang/Object;

    .line 43
    .line 44
    sget-object p1, Lss0/f;->d:Lss0/f;

    .line 45
    .line 46
    invoke-interface {p0, p1}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 47
    .line 48
    .line 49
    move-result p1

    .line 50
    if-eqz p1, :cond_2

    .line 51
    .line 52
    sget-object v1, Ler0/g;->g:Ler0/g;

    .line 53
    .line 54
    goto :goto_1

    .line 55
    :cond_2
    sget-object p1, Lss0/f;->e:Lss0/f;

    .line 56
    .line 57
    invoke-interface {p0, p1}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 58
    .line 59
    .line 60
    move-result p1

    .line 61
    if-eqz p1, :cond_3

    .line 62
    .line 63
    sget-object v1, Ler0/g;->f:Ler0/g;

    .line 64
    .line 65
    goto :goto_1

    .line 66
    :cond_3
    sget-object p1, Lss0/f;->f:Lss0/f;

    .line 67
    .line 68
    invoke-interface {p0, p1}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 69
    .line 70
    .line 71
    move-result p0

    .line 72
    if-eqz p0, :cond_4

    .line 73
    .line 74
    sget-object v1, Ler0/g;->e:Ler0/g;

    .line 75
    .line 76
    :cond_4
    :goto_1
    if-nez v1, :cond_5

    .line 77
    .line 78
    goto :goto_2

    .line 79
    :cond_5
    return-object v1

    .line 80
    :cond_6
    :goto_2
    sget-object p0, Ler0/g;->d:Ler0/g;

    .line 81
    .line 82
    return-object p0
.end method

.method public static final e(Lyy0/i;Lss0/e;Lay0/n;)Lzy0/j;
    .locals 3

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "id"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    new-instance v0, Ler0/a;

    .line 12
    .line 13
    const/4 v1, 0x0

    .line 14
    const/4 v2, 0x0

    .line 15
    invoke-direct {v0, p1, p2, v1, v2}, Ler0/a;-><init>(Lss0/e;Lay0/n;Lkotlin/coroutines/Continuation;I)V

    .line 16
    .line 17
    .line 18
    invoke-static {p0, v0}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0
.end method
