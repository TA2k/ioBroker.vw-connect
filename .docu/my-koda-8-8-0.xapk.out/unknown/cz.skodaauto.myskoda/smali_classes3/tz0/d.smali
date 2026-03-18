.class public interface abstract Ltz0/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# virtual methods
.method public abstract B(I)V
.end method

.method public abstract D(Lqz0/a;Ljava/lang/Object;)V
.end method

.method public abstract E(Ljava/lang/String;)V
.end method

.method public abstract a(Lsz0/g;)Ltz0/b;
.end method

.method public abstract c()Lwq/f;
.end method

.method public abstract d(D)V
.end method

.method public abstract f(B)V
.end method

.method public g(Lqz0/a;Ljava/lang/Object;)V
    .locals 1

    .line 1
    const-string v0, "serializer"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p1}, Lqz0/a;->getDescriptor()Lsz0/g;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    invoke-interface {v0}, Lsz0/g;->b()Z

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    if-eqz v0, :cond_0

    .line 15
    .line 16
    invoke-interface {p0, p1, p2}, Ltz0/d;->D(Lqz0/a;Ljava/lang/Object;)V

    .line 17
    .line 18
    .line 19
    return-void

    .line 20
    :cond_0
    if-nez p2, :cond_1

    .line 21
    .line 22
    invoke-interface {p0}, Ltz0/d;->p()V

    .line 23
    .line 24
    .line 25
    return-void

    .line 26
    :cond_1
    invoke-interface {p0, p1, p2}, Ltz0/d;->D(Lqz0/a;Ljava/lang/Object;)V

    .line 27
    .line 28
    .line 29
    return-void
.end method

.method public abstract i(Lsz0/g;I)V
.end method

.method public abstract j(Lsz0/g;)Ltz0/d;
.end method

.method public abstract m(J)V
.end method

.method public abstract p()V
.end method

.method public abstract q(Lsz0/g;I)Ltz0/b;
.end method

.method public abstract r(S)V
.end method

.method public abstract s(Z)V
.end method

.method public abstract u(F)V
.end method

.method public abstract v(C)V
.end method
