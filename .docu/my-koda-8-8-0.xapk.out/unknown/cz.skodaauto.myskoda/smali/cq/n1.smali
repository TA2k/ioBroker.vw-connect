.class public final Lcq/n1;
.super Lcq/m1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# virtual methods
.method public final y(Lcom/google/android/gms/common/data/DataHolder;)V
    .locals 1

    .line 1
    new-instance v0, Lbq/d;

    .line 2
    .line 3
    invoke-direct {v0, p1}, Lbq/d;-><init>(Lcom/google/android/gms/common/data/DataHolder;)V

    .line 4
    .line 5
    .line 6
    iget-object p1, p0, Lcq/m1;->d:Llo/e;

    .line 7
    .line 8
    if-eqz p1, :cond_0

    .line 9
    .line 10
    invoke-interface {p1, v0}, Llo/e;->z(Ljava/lang/Object;)V

    .line 11
    .line 12
    .line 13
    const/4 p1, 0x0

    .line 14
    iput-object p1, p0, Lcq/m1;->d:Llo/e;

    .line 15
    .line 16
    :cond_0
    return-void
.end method
