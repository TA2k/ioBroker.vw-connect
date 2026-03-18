.class public abstract Ljp/b1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lmb0/n;)Z
    .locals 3

    .line 1
    iget-object v0, p0, Lmb0/n;->b:Lmb0/o;

    .line 2
    .line 3
    iget-object p0, p0, Lmb0/n;->a:Lmb0/o;

    .line 4
    .line 5
    sget-object v1, Lmb0/o;->e:Lmb0/o;

    .line 6
    .line 7
    if-ne p0, v1, :cond_0

    .line 8
    .line 9
    sget-object v2, Lmb0/o;->d:Lmb0/o;

    .line 10
    .line 11
    if-ne v0, v2, :cond_1

    .line 12
    .line 13
    :cond_0
    if-ne v0, v1, :cond_2

    .line 14
    .line 15
    sget-object v0, Lmb0/o;->d:Lmb0/o;

    .line 16
    .line 17
    if-eq p0, v0, :cond_2

    .line 18
    .line 19
    :cond_1
    const/4 p0, 0x1

    .line 20
    return p0

    .line 21
    :cond_2
    const/4 p0, 0x0

    .line 22
    return p0
.end method

.method public static final b(Lmb0/n;)Z
    .locals 2

    .line 1
    iget-object v0, p0, Lmb0/n;->a:Lmb0/o;

    .line 2
    .line 3
    sget-object v1, Lmb0/o;->d:Lmb0/o;

    .line 4
    .line 5
    if-eq v0, v1, :cond_1

    .line 6
    .line 7
    iget-object p0, p0, Lmb0/n;->b:Lmb0/o;

    .line 8
    .line 9
    if-ne p0, v1, :cond_0

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    const/4 p0, 0x0

    .line 13
    return p0

    .line 14
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 15
    return p0
.end method

.method public static final c(Ljava/util/List;)Ljava/util/ArrayList;
    .locals 5

    .line 1
    check-cast p0, Ljava/lang/Iterable;

    .line 2
    .line 3
    new-instance v0, Ljava/util/ArrayList;

    .line 4
    .line 5
    const/16 v1, 0xa

    .line 6
    .line 7
    invoke-static {p0, v1}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 12
    .line 13
    .line 14
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 19
    .line 20
    .line 21
    move-result v1

    .line 22
    if-eqz v1, :cond_3

    .line 23
    .line 24
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object v1

    .line 28
    check-cast v1, Lze/g;

    .line 29
    .line 30
    iget-object v2, v1, Lze/g;->b:Ljava/lang/String;

    .line 31
    .line 32
    const-string v3, ""

    .line 33
    .line 34
    if-nez v2, :cond_0

    .line 35
    .line 36
    move-object v2, v3

    .line 37
    :cond_0
    iget-object v4, v1, Lze/g;->c:Ljava/lang/String;

    .line 38
    .line 39
    if-nez v4, :cond_1

    .line 40
    .line 41
    goto :goto_1

    .line 42
    :cond_1
    move-object v3, v4

    .line 43
    :goto_1
    iget-object v1, v1, Lze/g;->e:Ljava/lang/String;

    .line 44
    .line 45
    if-eqz v1, :cond_2

    .line 46
    .line 47
    invoke-static {v1}, Ljava/lang/Float;->parseFloat(Ljava/lang/String;)F

    .line 48
    .line 49
    .line 50
    move-result v1

    .line 51
    goto :goto_2

    .line 52
    :cond_2
    const/4 v1, 0x0

    .line 53
    :goto_2
    new-instance v4, Lje/i0;

    .line 54
    .line 55
    invoke-direct {v4, v1, v2, v3}, Lje/i0;-><init>(FLjava/lang/String;Ljava/lang/String;)V

    .line 56
    .line 57
    .line 58
    invoke-virtual {v0, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 59
    .line 60
    .line 61
    goto :goto_0

    .line 62
    :cond_3
    return-object v0
.end method
