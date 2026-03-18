.class public abstract Lkp/l8;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final varargs a([Ljava/lang/Object;)Lg21/a;
    .locals 4

    .line 1
    new-instance v0, Lg21/a;

    .line 2
    .line 3
    new-instance v1, Ljava/util/ArrayList;

    .line 4
    .line 5
    new-instance v2, Lmx0/k;

    .line 6
    .line 7
    const/4 v3, 0x0

    .line 8
    invoke-direct {v2, p0, v3}, Lmx0/k;-><init>([Ljava/lang/Object;Z)V

    .line 9
    .line 10
    .line 11
    invoke-direct {v1, v2}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 12
    .line 13
    .line 14
    const/4 p0, 0x2

    .line 15
    invoke-direct {v0, v1, p0}, Lg21/a;-><init>(Ljava/util/ArrayList;I)V

    .line 16
    .line 17
    .line 18
    return-object v0
.end method

.method public static final b(Ljava/lang/Object;Lay0/k;)Lne0/t;
    .locals 6

    .line 1
    invoke-static {p0}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 2
    .line 3
    .line 4
    move-result-object v1

    .line 5
    if-nez v1, :cond_0

    .line 6
    .line 7
    new-instance v0, Lne0/e;

    .line 8
    .line 9
    invoke-interface {p1, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    invoke-direct {v0, p0}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 14
    .line 15
    .line 16
    return-object v0

    .line 17
    :cond_0
    new-instance v0, Lne0/c;

    .line 18
    .line 19
    const/4 v4, 0x0

    .line 20
    const/16 v5, 0x1e

    .line 21
    .line 22
    const/4 v2, 0x0

    .line 23
    const/4 v3, 0x0

    .line 24
    invoke-direct/range {v0 .. v5}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 25
    .line 26
    .line 27
    return-object v0
.end method
