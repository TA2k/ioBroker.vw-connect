.class public final Lno/z;
.super Lbp/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lno/b0;


# virtual methods
.method public final W()Z
    .locals 2

    .line 1
    const/4 v0, 0x7

    .line 2
    invoke-virtual {p0}, Lbp/a;->S()Landroid/os/Parcel;

    .line 3
    .line 4
    .line 5
    move-result-object v1

    .line 6
    invoke-virtual {p0, v1, v0}, Lbp/a;->b(Landroid/os/Parcel;I)Landroid/os/Parcel;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    sget v0, Lep/a;->a:I

    .line 11
    .line 12
    invoke-virtual {p0}, Landroid/os/Parcel;->readInt()I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    if-eqz v0, :cond_0

    .line 17
    .line 18
    const/4 v0, 0x1

    .line 19
    goto :goto_0

    .line 20
    :cond_0
    const/4 v0, 0x0

    .line 21
    :goto_0
    invoke-virtual {p0}, Landroid/os/Parcel;->recycle()V

    .line 22
    .line 23
    .line 24
    return v0
.end method
