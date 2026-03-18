.class public final Lvp/d0;
.super Lbp/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lvp/e0;


# virtual methods
.method public final s(Ljava/util/List;)V
    .locals 1

    .line 1
    invoke-virtual {p0}, Lbp/a;->S()Landroid/os/Parcel;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-virtual {v0, p1}, Landroid/os/Parcel;->writeTypedList(Ljava/util/List;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {p0, v0}, Lbp/a;->V(Landroid/os/Parcel;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method
