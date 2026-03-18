.class public interface abstract Lgs/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# virtual methods
.method public a(Ljava/lang/Class;)Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-static {p1}, Lgs/s;->a(Ljava/lang/Class;)Lgs/s;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    invoke-interface {p0, p1}, Lgs/c;->b(Lgs/s;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method public b(Lgs/s;)Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-interface {p0, p1}, Lgs/c;->e(Lgs/s;)Lgt/b;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    if-nez p0, :cond_0

    .line 6
    .line 7
    const/4 p0, 0x0

    .line 8
    return-object p0

    .line 9
    :cond_0
    invoke-interface {p0}, Lgt/b;->get()Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    return-object p0
.end method

.method public c(Lgs/s;)Ljava/util/Set;
    .locals 0

    .line 1
    invoke-interface {p0, p1}, Lgs/c;->d(Lgs/s;)Lgt/b;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-interface {p0}, Lgt/b;->get()Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Ljava/util/Set;

    .line 10
    .line 11
    return-object p0
.end method

.method public abstract d(Lgs/s;)Lgt/b;
.end method

.method public abstract e(Lgs/s;)Lgt/b;
.end method

.method public f(Ljava/lang/Class;)Lgt/b;
    .locals 0

    .line 1
    invoke-static {p1}, Lgs/s;->a(Ljava/lang/Class;)Lgs/s;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    invoke-interface {p0, p1}, Lgs/c;->e(Lgs/s;)Lgt/b;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method public abstract g(Lgs/s;)Lgs/q;
.end method
