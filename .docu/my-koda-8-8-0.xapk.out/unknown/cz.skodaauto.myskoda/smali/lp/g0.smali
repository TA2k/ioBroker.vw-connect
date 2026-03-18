.class public abstract Llp/g0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lne0/t;)Z
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    instance-of v0, p0, Lne0/e;

    .line 7
    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    check-cast p0, Lne0/e;

    .line 11
    .line 12
    iget-object p0, p0, Lne0/e;->a:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast p0, Lto0/s;

    .line 15
    .line 16
    iget-object p0, p0, Lto0/s;->a:Lla/w;

    .line 17
    .line 18
    instance-of p0, p0, Lto0/p;

    .line 19
    .line 20
    if-eqz p0, :cond_0

    .line 21
    .line 22
    const/4 p0, 0x1

    .line 23
    return p0

    .line 24
    :cond_0
    const/4 p0, 0x0

    .line 25
    return p0
.end method

.method public static final b(Lto0/s;)Z
    .locals 2

    .line 1
    const/4 v0, 0x0

    .line 2
    if-eqz p0, :cond_0

    .line 3
    .line 4
    iget-object v1, p0, Lto0/s;->a:Lla/w;

    .line 5
    .line 6
    goto :goto_0

    .line 7
    :cond_0
    move-object v1, v0

    .line 8
    :goto_0
    instance-of v1, v1, Lto0/p;

    .line 9
    .line 10
    if-nez v1, :cond_3

    .line 11
    .line 12
    if-eqz p0, :cond_1

    .line 13
    .line 14
    iget-object v0, p0, Lto0/s;->a:Lla/w;

    .line 15
    .line 16
    :cond_1
    instance-of p0, v0, Lto0/q;

    .line 17
    .line 18
    if-eqz p0, :cond_2

    .line 19
    .line 20
    goto :goto_1

    .line 21
    :cond_2
    const/4 p0, 0x0

    .line 22
    return p0

    .line 23
    :cond_3
    :goto_1
    const/4 p0, 0x1

    .line 24
    return p0
.end method

.method public static final c(Lg40/a;)Lh40/w;
    .locals 10

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v1, Lh40/w;

    .line 7
    .line 8
    iget-object v2, p0, Lg40/a;->a:Ljava/lang/String;

    .line 9
    .line 10
    iget-object v3, p0, Lg40/a;->b:Ljava/lang/String;

    .line 11
    .line 12
    new-instance v4, Lh40/v;

    .line 13
    .line 14
    iget-object v0, p0, Lg40/a;->g:Lg40/z;

    .line 15
    .line 16
    const/4 v5, 0x0

    .line 17
    if-eqz v0, :cond_0

    .line 18
    .line 19
    iget-object v6, v0, Lg40/z;->a:Ljava/lang/String;

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    move-object v6, v5

    .line 23
    :goto_0
    if-eqz v0, :cond_1

    .line 24
    .line 25
    iget-object v7, v0, Lg40/z;->b:Ljava/lang/String;

    .line 26
    .line 27
    goto :goto_1

    .line 28
    :cond_1
    move-object v7, v5

    .line 29
    :goto_1
    if-eqz v0, :cond_2

    .line 30
    .line 31
    iget-object v8, v0, Lg40/z;->c:Ljava/lang/String;

    .line 32
    .line 33
    goto :goto_2

    .line 34
    :cond_2
    move-object v8, v5

    .line 35
    :goto_2
    if-eqz v0, :cond_3

    .line 36
    .line 37
    iget-object v0, v0, Lg40/z;->d:Lcq0/h;

    .line 38
    .line 39
    if-eqz v0, :cond_3

    .line 40
    .line 41
    const/4 v9, 0x1

    .line 42
    invoke-static {v0, v9}, Ljp/gg;->c(Lcq0/h;Z)Ljava/lang/String;

    .line 43
    .line 44
    .line 45
    move-result-object v0

    .line 46
    goto :goto_3

    .line 47
    :cond_3
    move-object v0, v5

    .line 48
    :goto_3
    invoke-direct {v4, v6, v7, v8, v0}, Lh40/v;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    iget-object v0, p0, Lg40/a;->i:Ljava/util/List;

    .line 52
    .line 53
    invoke-static {v0}, Lmx0/q;->L(Ljava/util/List;)Ljava/lang/Object;

    .line 54
    .line 55
    .line 56
    move-result-object v0

    .line 57
    check-cast v0, Ljava/lang/String;

    .line 58
    .line 59
    if-eqz v0, :cond_4

    .line 60
    .line 61
    invoke-static {v0}, Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;

    .line 62
    .line 63
    .line 64
    move-result-object v5

    .line 65
    :cond_4
    iget-object v6, p0, Lg40/a;->f:Ljava/lang/String;

    .line 66
    .line 67
    iget-object p0, p0, Lg40/a;->h:Lg40/b;

    .line 68
    .line 69
    invoke-static {p0}, Llp/g0;->d(Lg40/b;)Lh40/a;

    .line 70
    .line 71
    .line 72
    move-result-object v7

    .line 73
    invoke-direct/range {v1 .. v7}, Lh40/w;-><init>(Ljava/lang/String;Ljava/lang/String;Lh40/v;Landroid/net/Uri;Ljava/lang/String;Lh40/a;)V

    .line 74
    .line 75
    .line 76
    return-object v1
.end method

.method public static final d(Lg40/b;)Lh40/a;
    .locals 1

    .line 1
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    if-eqz p0, :cond_2

    .line 6
    .line 7
    const/4 v0, 0x1

    .line 8
    if-eq p0, v0, :cond_1

    .line 9
    .line 10
    const/4 v0, 0x2

    .line 11
    if-ne p0, v0, :cond_0

    .line 12
    .line 13
    sget-object p0, Lh40/a;->h:Lh40/a;

    .line 14
    .line 15
    return-object p0

    .line 16
    :cond_0
    new-instance p0, La8/r0;

    .line 17
    .line 18
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 19
    .line 20
    .line 21
    throw p0

    .line 22
    :cond_1
    sget-object p0, Lh40/a;->f:Lh40/a;

    .line 23
    .line 24
    return-object p0

    .line 25
    :cond_2
    sget-object p0, Lh40/a;->g:Lh40/a;

    .line 26
    .line 27
    return-object p0
.end method

.method public static final e(Lg40/f;I)Lh40/x;
    .locals 10

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v2, p0, Lg40/f;->a:Ljava/lang/String;

    .line 7
    .line 8
    iget-object v3, p0, Lg40/f;->b:Ljava/lang/String;

    .line 9
    .line 10
    iget v5, p0, Lg40/f;->e:I

    .line 11
    .line 12
    iget-object v0, p0, Lg40/f;->f:Ljava/util/List;

    .line 13
    .line 14
    check-cast v0, Ljava/lang/Iterable;

    .line 15
    .line 16
    new-instance v4, Ljava/util/ArrayList;

    .line 17
    .line 18
    const/16 v1, 0xa

    .line 19
    .line 20
    invoke-static {v0, v1}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 21
    .line 22
    .line 23
    move-result v1

    .line 24
    invoke-direct {v4, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 25
    .line 26
    .line 27
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 32
    .line 33
    .line 34
    move-result v1

    .line 35
    if-eqz v1, :cond_0

    .line 36
    .line 37
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object v1

    .line 41
    check-cast v1, Ljava/lang/String;

    .line 42
    .line 43
    invoke-static {v1}, Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;

    .line 44
    .line 45
    .line 46
    move-result-object v1

    .line 47
    invoke-interface {v4, v1}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z

    .line 48
    .line 49
    .line 50
    goto :goto_0

    .line 51
    :cond_0
    iget v0, p0, Lg40/f;->e:I

    .line 52
    .line 53
    sub-int v6, v0, p1

    .line 54
    .line 55
    iget-object v8, p0, Lg40/f;->c:Ljava/lang/String;

    .line 56
    .line 57
    iget-object v9, p0, Lg40/f;->d:Ljava/lang/String;

    .line 58
    .line 59
    int-to-float p0, p1

    .line 60
    int-to-float p1, v0

    .line 61
    div-float v7, p0, p1

    .line 62
    .line 63
    new-instance v1, Lh40/x;

    .line 64
    .line 65
    invoke-direct/range {v1 .. v9}, Lh40/x;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/util/List;IIFLjava/lang/String;Ljava/lang/String;)V

    .line 66
    .line 67
    .line 68
    return-object v1
.end method

.method public static final f(Lg40/g;I)Lh40/y;
    .locals 13

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v2, p0, Lg40/g;->a:Ljava/lang/String;

    .line 7
    .line 8
    iget-object v3, p0, Lg40/g;->b:Ljava/lang/String;

    .line 9
    .line 10
    iget v8, p0, Lg40/g;->f:I

    .line 11
    .line 12
    iget-object v0, p0, Lg40/g;->g:Ljava/util/List;

    .line 13
    .line 14
    check-cast v0, Ljava/lang/Iterable;

    .line 15
    .line 16
    new-instance v4, Ljava/util/ArrayList;

    .line 17
    .line 18
    const/16 v1, 0xa

    .line 19
    .line 20
    invoke-static {v0, v1}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 21
    .line 22
    .line 23
    move-result v1

    .line 24
    invoke-direct {v4, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 25
    .line 26
    .line 27
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 32
    .line 33
    .line 34
    move-result v1

    .line 35
    if-eqz v1, :cond_0

    .line 36
    .line 37
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object v1

    .line 41
    check-cast v1, Ljava/lang/String;

    .line 42
    .line 43
    invoke-static {v1}, Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;

    .line 44
    .line 45
    .line 46
    move-result-object v1

    .line 47
    invoke-interface {v4, v1}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z

    .line 48
    .line 49
    .line 50
    goto :goto_0

    .line 51
    :cond_0
    iget v0, p0, Lg40/g;->f:I

    .line 52
    .line 53
    sub-int v9, v0, p1

    .line 54
    .line 55
    iget-object v5, p0, Lg40/g;->c:Ljava/lang/String;

    .line 56
    .line 57
    iget-object v6, p0, Lg40/g;->d:Ljava/lang/String;

    .line 58
    .line 59
    int-to-float p1, p1

    .line 60
    int-to-float v0, v0

    .line 61
    div-float v12, p1, v0

    .line 62
    .line 63
    iget-object v7, p0, Lg40/g;->e:Ljava/lang/String;

    .line 64
    .line 65
    iget-object v10, p0, Lg40/g;->h:Ljava/lang/Double;

    .line 66
    .line 67
    iget-object v11, p0, Lg40/g;->i:Ljava/lang/String;

    .line 68
    .line 69
    new-instance v1, Lh40/y;

    .line 70
    .line 71
    invoke-direct/range {v1 .. v12}, Lh40/y;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/util/List;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;IILjava/lang/Double;Ljava/lang/String;F)V

    .line 72
    .line 73
    .line 74
    return-object v1
.end method

.method public static final g(Lg40/b0;)Lh40/z;
    .locals 14

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v4, p0, Lg40/b0;->a:Ljava/lang/String;

    .line 7
    .line 8
    iget-object v2, p0, Lg40/b0;->b:Lg40/c0;

    .line 9
    .line 10
    iget-object v5, p0, Lg40/b0;->c:Ljava/lang/String;

    .line 11
    .line 12
    iget-object v6, p0, Lg40/b0;->d:Ljava/lang/String;

    .line 13
    .line 14
    iget-object v7, p0, Lg40/b0;->e:Ljava/lang/String;

    .line 15
    .line 16
    iget-object v8, p0, Lg40/b0;->f:Ljava/lang/String;

    .line 17
    .line 18
    iget-object v9, p0, Lg40/b0;->g:Ljava/lang/String;

    .line 19
    .line 20
    iget-object v12, p0, Lg40/b0;->h:Ljava/time/LocalDate;

    .line 21
    .line 22
    iget-object v0, p0, Lg40/b0;->i:Ljava/util/List;

    .line 23
    .line 24
    check-cast v0, Ljava/lang/Iterable;

    .line 25
    .line 26
    new-instance v13, Ljava/util/ArrayList;

    .line 27
    .line 28
    const/16 v1, 0xa

    .line 29
    .line 30
    invoke-static {v0, v1}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 31
    .line 32
    .line 33
    move-result v1

    .line 34
    invoke-direct {v13, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 35
    .line 36
    .line 37
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 38
    .line 39
    .line 40
    move-result-object v0

    .line 41
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 42
    .line 43
    .line 44
    move-result v1

    .line 45
    if-eqz v1, :cond_0

    .line 46
    .line 47
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object v1

    .line 51
    check-cast v1, Ljava/lang/String;

    .line 52
    .line 53
    invoke-static {v1}, Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;

    .line 54
    .line 55
    .line 56
    move-result-object v1

    .line 57
    invoke-interface {v13, v1}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z

    .line 58
    .line 59
    .line 60
    goto :goto_0

    .line 61
    :cond_0
    iget-object v10, p0, Lg40/b0;->j:Ljava/lang/String;

    .line 62
    .line 63
    iget-object v3, p0, Lg40/b0;->k:Ljava/lang/Double;

    .line 64
    .line 65
    iget-object v11, p0, Lg40/b0;->l:Ljava/lang/String;

    .line 66
    .line 67
    new-instance v1, Lh40/z;

    .line 68
    .line 69
    invoke-direct/range {v1 .. v13}, Lh40/z;-><init>(Lg40/c0;Ljava/lang/Double;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/time/LocalDate;Ljava/util/List;)V

    .line 70
    .line 71
    .line 72
    return-object v1
.end method

.method public static final h(Lg40/p0;)Lh40/a0;
    .locals 4

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lg40/p0;->a:Ljava/lang/String;

    .line 7
    .line 8
    iget-object v1, p0, Lg40/p0;->b:Ljava/lang/String;

    .line 9
    .line 10
    iget-object p0, p0, Lg40/p0;->c:Ljava/util/List;

    .line 11
    .line 12
    check-cast p0, Ljava/lang/Iterable;

    .line 13
    .line 14
    new-instance v2, Ljava/util/ArrayList;

    .line 15
    .line 16
    const/16 v3, 0xa

    .line 17
    .line 18
    invoke-static {p0, v3}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 19
    .line 20
    .line 21
    move-result v3

    .line 22
    invoke-direct {v2, v3}, Ljava/util/ArrayList;-><init>(I)V

    .line 23
    .line 24
    .line 25
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 30
    .line 31
    .line 32
    move-result v3

    .line 33
    if-eqz v3, :cond_0

    .line 34
    .line 35
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object v3

    .line 39
    check-cast v3, Ljava/lang/String;

    .line 40
    .line 41
    invoke-static {v3}, Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;

    .line 42
    .line 43
    .line 44
    move-result-object v3

    .line 45
    invoke-interface {v2, v3}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z

    .line 46
    .line 47
    .line 48
    goto :goto_0

    .line 49
    :cond_0
    new-instance p0, Lh40/a0;

    .line 50
    .line 51
    invoke-direct {p0, v0, v1, v2}, Lh40/a0;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/util/List;)V

    .line 52
    .line 53
    .line 54
    return-object p0
.end method
