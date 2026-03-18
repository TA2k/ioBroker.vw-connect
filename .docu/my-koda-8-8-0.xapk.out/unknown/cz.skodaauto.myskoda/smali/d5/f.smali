.class public final Ld5/f;
.super Ld5/b;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Iterable;


# virtual methods
.method public final E()Ld5/f;
    .locals 0

    .line 1
    invoke-super {p0}, Ld5/b;->p()Ld5/b;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    check-cast p0, Ld5/f;

    .line 6
    .line 7
    return-object p0
.end method

.method public final bridge synthetic c()Ld5/c;
    .locals 0

    .line 1
    invoke-virtual {p0}, Ld5/f;->E()Ld5/f;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public final clone()Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-super {p0}, Ld5/b;->p()Ld5/b;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    check-cast p0, Ld5/f;

    .line 6
    .line 7
    return-object p0
.end method

.method public final iterator()Ljava/util/Iterator;
    .locals 2

    .line 1
    new-instance v0, Lcom/google/android/gms/internal/measurement/d;

    .line 2
    .line 3
    invoke-direct {v0}, Lcom/google/android/gms/internal/measurement/d;-><init>()V

    .line 4
    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    iput v1, v0, Lcom/google/android/gms/internal/measurement/d;->e:I

    .line 8
    .line 9
    iput-object p0, v0, Lcom/google/android/gms/internal/measurement/d;->f:Ljava/lang/Iterable;

    .line 10
    .line 11
    return-object v0
.end method

.method public final bridge synthetic p()Ld5/b;
    .locals 0

    .line 1
    invoke-virtual {p0}, Ld5/f;->E()Ld5/f;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method
