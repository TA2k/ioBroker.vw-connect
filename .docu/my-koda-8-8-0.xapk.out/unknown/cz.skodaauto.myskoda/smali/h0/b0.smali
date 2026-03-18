.class public interface abstract Lh0/b0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lb0/k;
.implements Lb0/y1;


# virtual methods
.method public a()Lh0/z;
    .locals 0

    .line 1
    invoke-interface {p0}, Lh0/b0;->l()Lh0/z;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public abstract b()Lcom/google/common/util/concurrent/ListenableFuture;
.end method

.method public abstract c()Lh0/m1;
.end method

.method public d()V
    .locals 0

    .line 1
    return-void
.end method

.method public abstract g()Lh0/y;
.end method

.method public h()Lh0/t;
    .locals 0

    .line 1
    sget-object p0, Lh0/w;->a:Lh0/v;

    .line 2
    .line 3
    return-object p0
.end method

.method public i(Lh0/t;)V
    .locals 0

    .line 1
    return-void
.end method

.method public j(Z)V
    .locals 0

    .line 1
    return-void
.end method

.method public abstract k(Ljava/util/Collection;)V
.end method

.method public abstract l()Lh0/z;
.end method

.method public n()Z
    .locals 0

    .line 1
    invoke-interface {p0}, Lh0/b0;->a()Lh0/z;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-interface {p0}, Lh0/z;->h()I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    if-nez p0, :cond_0

    .line 10
    .line 11
    const/4 p0, 0x1

    .line 12
    return p0

    .line 13
    :cond_0
    const/4 p0, 0x0

    .line 14
    return p0
.end method

.method public abstract o(Ljava/util/ArrayList;)V
.end method

.method public p()Z
    .locals 0

    .line 1
    const/4 p0, 0x1

    .line 2
    return p0
.end method

.method public q(Z)V
    .locals 0

    .line 1
    return-void
.end method
