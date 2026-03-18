.class public interface abstract Lhz0/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lhz0/a0;


# virtual methods
.method public build()Ljz0/d;
    .locals 2

    .line 1
    new-instance v0, Ljz0/d;

    .line 2
    .line 3
    invoke-interface {p0}, Lhz0/b;->e()Lbn/c;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    iget-object p0, p0, Lbn/c;->d:Ljava/util/ArrayList;

    .line 8
    .line 9
    const-string v1, "formats"

    .line 10
    .line 11
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    invoke-direct {v0, p0}, Ljz0/d;-><init>(Ljava/util/List;)V

    .line 15
    .line 16
    .line 17
    return-object v0
.end method

.method public c(Ljava/lang/String;)V
    .locals 1

    .line 1
    const-string v0, "value"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p0}, Lhz0/b;->e()Lbn/c;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    new-instance v0, Ljz0/h;

    .line 11
    .line 12
    invoke-direct {v0, p1}, Ljz0/h;-><init>(Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    invoke-virtual {p0, v0}, Lbn/c;->f(Ljz0/k;)V

    .line 16
    .line 17
    .line 18
    return-void
.end method

.method public abstract e()Lbn/c;
.end method

.method public abstract l()Lhz0/b;
.end method
