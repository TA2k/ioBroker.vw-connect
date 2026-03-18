.class public abstract Lj3/c0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public a:Lay0/k;


# virtual methods
.method public abstract a(Lg3/d;)V
.end method

.method public b()Lay0/k;
    .locals 0

    .line 1
    iget-object p0, p0, Lj3/c0;->a:Lay0/k;

    .line 2
    .line 3
    return-object p0
.end method

.method public final c()V
    .locals 1

    .line 1
    invoke-virtual {p0}, Lj3/c0;->b()Lay0/k;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    invoke-interface {v0, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    :cond_0
    return-void
.end method

.method public d(La3/f;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lj3/c0;->a:Lay0/k;

    .line 2
    .line 3
    return-void
.end method
