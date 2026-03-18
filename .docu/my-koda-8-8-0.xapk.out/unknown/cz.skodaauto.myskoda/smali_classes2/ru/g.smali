.class public final Lru/g;
.super Lap0/o;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lru/f;


# instance fields
.field public f:Lru/e;


# virtual methods
.method public final b()Ljava/util/Collection;
    .locals 0

    .line 1
    iget-object p0, p0, Lru/g;->f:Lru/e;

    .line 2
    .line 3
    iget-object p0, p0, Lru/e;->f:Lru/c;

    .line 4
    .line 5
    invoke-virtual {p0}, Lru/c;->b()Ljava/util/Collection;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method public final c(Lcom/google/android/gms/maps/model/CameraPosition;)V
    .locals 0

    .line 1
    return-void
.end method

.method public final e(Ljava/util/Collection;)Z
    .locals 0

    .line 1
    iget-object p0, p0, Lru/g;->f:Lru/e;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lru/e;->e(Ljava/util/Collection;)Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final g()V
    .locals 0

    .line 1
    iget-object p0, p0, Lru/g;->f:Lru/e;

    .line 2
    .line 3
    invoke-virtual {p0}, Lru/e;->g()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final k()Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public final m(F)Ljava/util/Set;
    .locals 0

    .line 1
    iget-object p0, p0, Lru/g;->f:Lru/e;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lru/e;->m(F)Ljava/util/Set;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final o()I
    .locals 0

    .line 1
    iget-object p0, p0, Lru/g;->f:Lru/e;

    .line 2
    .line 3
    iget-object p0, p0, Lru/e;->f:Lru/c;

    .line 4
    .line 5
    invoke-virtual {p0}, Lru/c;->o()I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method
