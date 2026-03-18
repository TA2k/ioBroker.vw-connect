.class public interface abstract Lx2/s;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# virtual methods
.method public abstract a(Ljava/lang/Object;Lay0/n;)Ljava/lang/Object;
.end method

.method public abstract b(Lay0/k;)Z
.end method

.method public g(Lx2/s;)Lx2/s;
    .locals 1

    .line 1
    sget-object v0, Lx2/p;->b:Lx2/p;

    .line 2
    .line 3
    if-ne p1, v0, :cond_0

    .line 4
    .line 5
    return-object p0

    .line 6
    :cond_0
    new-instance v0, Lx2/l;

    .line 7
    .line 8
    invoke-direct {v0, p0, p1}, Lx2/l;-><init>(Lx2/s;Lx2/s;)V

    .line 9
    .line 10
    .line 11
    return-object v0
.end method
