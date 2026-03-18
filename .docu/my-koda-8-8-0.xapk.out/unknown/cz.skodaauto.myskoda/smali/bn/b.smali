.class public final Lbn/b;
.super Lap0/o;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# virtual methods
.method public final b0()Lxm/f;
    .locals 2

    .line 1
    new-instance v0, Lxm/f;

    .line 2
    .line 3
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast p0, Ljava/util/List;

    .line 6
    .line 7
    const/4 v1, 0x1

    .line 8
    invoke-direct {v0, p0, v1}, Lxm/f;-><init>(Ljava/util/List;I)V

    .line 9
    .line 10
    .line 11
    return-object v0
.end method

.method public final bridge synthetic p()Lxm/e;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lbn/b;->b0()Lxm/f;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method
