.class public abstract Ljp/ye;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lg4/g;)Z
    .locals 6

    .line 1
    iget-object v0, p0, Lg4/g;->e:Ljava/lang/String;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    iget-object p0, p0, Lg4/g;->d:Ljava/util/List;

    .line 8
    .line 9
    const/4 v1, 0x0

    .line 10
    if-eqz p0, :cond_1

    .line 11
    .line 12
    move-object v2, p0

    .line 13
    check-cast v2, Ljava/util/Collection;

    .line 14
    .line 15
    invoke-interface {v2}, Ljava/util/Collection;->size()I

    .line 16
    .line 17
    .line 18
    move-result v2

    .line 19
    move v3, v1

    .line 20
    :goto_0
    if-ge v3, v2, :cond_1

    .line 21
    .line 22
    invoke-interface {p0, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object v4

    .line 26
    check-cast v4, Lg4/e;

    .line 27
    .line 28
    iget-object v5, v4, Lg4/e;->a:Ljava/lang/Object;

    .line 29
    .line 30
    instance-of v5, v5, Lg4/n;

    .line 31
    .line 32
    if-eqz v5, :cond_0

    .line 33
    .line 34
    iget v5, v4, Lg4/e;->b:I

    .line 35
    .line 36
    iget v4, v4, Lg4/e;->c:I

    .line 37
    .line 38
    invoke-static {v1, v0, v5, v4}, Lg4/h;->b(IIII)Z

    .line 39
    .line 40
    .line 41
    move-result v4

    .line 42
    if-eqz v4, :cond_0

    .line 43
    .line 44
    const/4 p0, 0x1

    .line 45
    return p0

    .line 46
    :cond_0
    add-int/lit8 v3, v3, 0x1

    .line 47
    .line 48
    goto :goto_0

    .line 49
    :cond_1
    return v1
.end method

.method public static final b(Landroidx/collection/f;Lay0/k;)V
    .locals 8

    .line 1
    const-string v0, "map"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Landroidx/collection/f;

    .line 7
    .line 8
    const/16 v1, 0x3e7

    .line 9
    .line 10
    invoke-direct {v0, v1}, Landroidx/collection/a1;-><init>(I)V

    .line 11
    .line 12
    .line 13
    invoke-virtual {p0}, Landroidx/collection/a1;->size()I

    .line 14
    .line 15
    .line 16
    move-result v2

    .line 17
    const/4 v3, 0x0

    .line 18
    move v4, v3

    .line 19
    move v5, v4

    .line 20
    :cond_0
    :goto_0
    if-ge v4, v2, :cond_1

    .line 21
    .line 22
    invoke-virtual {p0, v4}, Landroidx/collection/a1;->keyAt(I)Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object v6

    .line 26
    invoke-virtual {p0, v4}, Landroidx/collection/a1;->valueAt(I)Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object v7

    .line 30
    invoke-interface {v0, v6, v7}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    add-int/lit8 v4, v4, 0x1

    .line 34
    .line 35
    add-int/lit8 v5, v5, 0x1

    .line 36
    .line 37
    if-ne v5, v1, :cond_0

    .line 38
    .line 39
    invoke-interface {p1, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    invoke-virtual {v0}, Landroidx/collection/a1;->clear()V

    .line 43
    .line 44
    .line 45
    move v5, v3

    .line 46
    goto :goto_0

    .line 47
    :cond_1
    if-lez v5, :cond_2

    .line 48
    .line 49
    invoke-interface {p1, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    :cond_2
    return-void
.end method

.method public static final c(Landroidx/collection/u;Lay0/k;)V
    .locals 9

    .line 1
    const-string v0, "map"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Landroidx/collection/u;

    .line 7
    .line 8
    const/16 v1, 0x3e7

    .line 9
    .line 10
    invoke-direct {v0, v1}, Landroidx/collection/u;-><init>(I)V

    .line 11
    .line 12
    .line 13
    invoke-virtual {p0}, Landroidx/collection/u;->h()I

    .line 14
    .line 15
    .line 16
    move-result v2

    .line 17
    const/4 v3, 0x0

    .line 18
    move v4, v3

    .line 19
    move v5, v4

    .line 20
    :cond_0
    :goto_0
    if-ge v4, v2, :cond_1

    .line 21
    .line 22
    invoke-virtual {p0, v4}, Landroidx/collection/u;->d(I)J

    .line 23
    .line 24
    .line 25
    move-result-wide v6

    .line 26
    invoke-virtual {p0, v4}, Landroidx/collection/u;->i(I)Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object v8

    .line 30
    invoke-virtual {v0, v6, v7, v8}, Landroidx/collection/u;->e(JLjava/lang/Object;)V

    .line 31
    .line 32
    .line 33
    add-int/lit8 v4, v4, 0x1

    .line 34
    .line 35
    add-int/lit8 v5, v5, 0x1

    .line 36
    .line 37
    if-ne v5, v1, :cond_0

    .line 38
    .line 39
    invoke-interface {p1, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    invoke-virtual {v0}, Landroidx/collection/u;->a()V

    .line 43
    .line 44
    .line 45
    move v5, v3

    .line 46
    goto :goto_0

    .line 47
    :cond_1
    if-lez v5, :cond_2

    .line 48
    .line 49
    invoke-interface {p1, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    :cond_2
    return-void
.end method
