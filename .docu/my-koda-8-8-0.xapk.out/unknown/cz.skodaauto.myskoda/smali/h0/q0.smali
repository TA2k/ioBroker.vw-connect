.class public interface abstract Lh0/q0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static G(Lh0/j1;Lh0/q0;Lh0/q0;Lh0/g;)V
    .locals 3

    .line 1
    sget-object v0, Lh0/a1;->N0:Lh0/g;

    .line 2
    .line 3
    invoke-static {p3, v0}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_4

    .line 8
    .line 9
    const/4 v0, 0x0

    .line 10
    invoke-interface {p2, p3, v0}, Lh0/q0;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object v1

    .line 14
    check-cast v1, Ls0/b;

    .line 15
    .line 16
    invoke-interface {p1, p3, v0}, Lh0/q0;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object p1

    .line 20
    check-cast p1, Ls0/b;

    .line 21
    .line 22
    invoke-interface {p2, p3}, Lh0/q0;->e(Lh0/g;)Lh0/p0;

    .line 23
    .line 24
    .line 25
    move-result-object p2

    .line 26
    if-nez v1, :cond_0

    .line 27
    .line 28
    move-object v1, p1

    .line 29
    goto :goto_0

    .line 30
    :cond_0
    if-nez p1, :cond_1

    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_1
    iget-object v0, p1, Ls0/b;->a:Ls0/a;

    .line 34
    .line 35
    iget-object p1, p1, Ls0/b;->b:Ls0/c;

    .line 36
    .line 37
    iget-object v2, v1, Ls0/b;->a:Ls0/a;

    .line 38
    .line 39
    if-eqz v2, :cond_2

    .line 40
    .line 41
    move-object v0, v2

    .line 42
    :cond_2
    iget-object v1, v1, Ls0/b;->b:Ls0/c;

    .line 43
    .line 44
    if-eqz v1, :cond_3

    .line 45
    .line 46
    move-object p1, v1

    .line 47
    :cond_3
    new-instance v1, Ls0/b;

    .line 48
    .line 49
    invoke-direct {v1, v0, p1}, Ls0/b;-><init>(Ls0/a;Ls0/c;)V

    .line 50
    .line 51
    .line 52
    :goto_0
    invoke-virtual {p0, p3, p2, v1}, Lh0/j1;->m(Lh0/g;Lh0/p0;Ljava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    return-void

    .line 56
    :cond_4
    invoke-interface {p2, p3}, Lh0/q0;->e(Lh0/g;)Lh0/p0;

    .line 57
    .line 58
    .line 59
    move-result-object p1

    .line 60
    invoke-interface {p2, p3}, Lh0/q0;->f(Lh0/g;)Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object p2

    .line 64
    invoke-virtual {p0, p3, p1, p2}, Lh0/j1;->m(Lh0/g;Lh0/p0;Ljava/lang/Object;)V

    .line 65
    .line 66
    .line 67
    return-void
.end method

.method public static w(Lh0/q0;Lh0/q0;)Lh0/n1;
    .locals 3

    .line 1
    if-nez p0, :cond_0

    .line 2
    .line 3
    if-nez p1, :cond_0

    .line 4
    .line 5
    sget-object p0, Lh0/n1;->f:Lh0/n1;

    .line 6
    .line 7
    return-object p0

    .line 8
    :cond_0
    if-eqz p1, :cond_1

    .line 9
    .line 10
    invoke-static {p1}, Lh0/j1;->h(Lh0/q0;)Lh0/j1;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    goto :goto_0

    .line 15
    :cond_1
    invoke-static {}, Lh0/j1;->c()Lh0/j1;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    :goto_0
    if-eqz p0, :cond_2

    .line 20
    .line 21
    invoke-interface {p0}, Lh0/q0;->d()Ljava/util/Set;

    .line 22
    .line 23
    .line 24
    move-result-object v1

    .line 25
    invoke-interface {v1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 26
    .line 27
    .line 28
    move-result-object v1

    .line 29
    :goto_1
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 30
    .line 31
    .line 32
    move-result v2

    .line 33
    if-eqz v2, :cond_2

    .line 34
    .line 35
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object v2

    .line 39
    check-cast v2, Lh0/g;

    .line 40
    .line 41
    invoke-static {v0, p1, p0, v2}, Lh0/q0;->G(Lh0/j1;Lh0/q0;Lh0/q0;Lh0/g;)V

    .line 42
    .line 43
    .line 44
    goto :goto_1

    .line 45
    :cond_2
    invoke-static {v0}, Lh0/n1;->a(Lh0/q0;)Lh0/n1;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    return-object p0
.end method


# virtual methods
.method public abstract b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;
.end method

.method public abstract d()Ljava/util/Set;
.end method

.method public abstract e(Lh0/g;)Lh0/p0;
.end method

.method public abstract f(Lh0/g;)Ljava/lang/Object;
.end method

.method public abstract g(Lh0/g;)Ljava/util/Set;
.end method

.method public abstract i(Lh0/g;Lh0/p0;)Ljava/lang/Object;
.end method

.method public abstract j(Lh0/g;)Z
.end method

.method public abstract k(La0/h;)V
.end method
