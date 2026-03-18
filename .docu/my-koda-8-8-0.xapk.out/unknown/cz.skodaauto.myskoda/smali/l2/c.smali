.class public interface abstract Ll2/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# virtual methods
.method public abstract b(III)V
.end method

.method public abstract c(II)V
.end method

.method public d(Ljava/lang/Object;Lay0/n;)V
    .locals 0

    .line 1
    invoke-interface {p0}, Ll2/c;->g()Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-interface {p2, p0, p1}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public abstract e(ILjava/lang/Object;)V
.end method

.method public f()V
    .locals 0

    .line 1
    return-void
.end method

.method public abstract g()Ljava/lang/Object;
.end method

.method public abstract k(ILjava/lang/Object;)V
.end method

.method public abstract l(Ljava/lang/Object;)V
.end method

.method public m()V
    .locals 1

    .line 1
    invoke-interface {p0}, Ll2/c;->g()Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    instance-of v0, p0, Ll2/j;

    .line 6
    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    check-cast p0, Ll2/j;

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    const/4 p0, 0x0

    .line 13
    :goto_0
    if-eqz p0, :cond_1

    .line 14
    .line 15
    invoke-interface {p0}, Ll2/j;->e()V

    .line 16
    .line 17
    .line 18
    :cond_1
    return-void
.end method

.method public abstract o()V
.end method
