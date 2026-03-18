.class public final Lrp/e;
.super Lbp/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# virtual methods
.method public final W()Lrp/a;
    .locals 4

    .line 1
    const/4 v0, 0x4

    .line 2
    invoke-virtual {p0}, Lbp/a;->S()Landroid/os/Parcel;

    .line 3
    .line 4
    .line 5
    move-result-object v1

    .line 6
    invoke-virtual {p0, v1, v0}, Lbp/a;->c(Landroid/os/Parcel;I)Landroid/os/Parcel;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    invoke-virtual {p0}, Landroid/os/Parcel;->readStrongBinder()Landroid/os/IBinder;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    if-nez v0, :cond_0

    .line 15
    .line 16
    const/4 v0, 0x0

    .line 17
    goto :goto_0

    .line 18
    :cond_0
    const-string v1, "com.google.android.gms.maps.internal.ICameraUpdateFactoryDelegate"

    .line 19
    .line 20
    invoke-interface {v0, v1}, Landroid/os/IBinder;->queryLocalInterface(Ljava/lang/String;)Landroid/os/IInterface;

    .line 21
    .line 22
    .line 23
    move-result-object v2

    .line 24
    instance-of v3, v2, Lrp/a;

    .line 25
    .line 26
    if-eqz v3, :cond_1

    .line 27
    .line 28
    move-object v0, v2

    .line 29
    check-cast v0, Lrp/a;

    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_1
    new-instance v2, Lrp/a;

    .line 33
    .line 34
    const/4 v3, 0x5

    .line 35
    invoke-direct {v2, v0, v1, v3}, Lbp/a;-><init>(Landroid/os/IBinder;Ljava/lang/String;I)V

    .line 36
    .line 37
    .line 38
    move-object v0, v2

    .line 39
    :goto_0
    invoke-virtual {p0}, Landroid/os/Parcel;->recycle()V

    .line 40
    .line 41
    .line 42
    return-object v0
.end method

.method public final X(Lyo/b;Lcom/google/android/gms/maps/GoogleMapOptions;)Lrp/g;
    .locals 2

    .line 1
    invoke-virtual {p0}, Lbp/a;->S()Landroid/os/Parcel;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-static {v0, p1}, Lhp/j;->d(Landroid/os/Parcel;Landroid/os/IInterface;)V

    .line 6
    .line 7
    .line 8
    invoke-static {v0, p2}, Lhp/j;->c(Landroid/os/Parcel;Landroid/os/Parcelable;)V

    .line 9
    .line 10
    .line 11
    const/4 p1, 0x3

    .line 12
    invoke-virtual {p0, v0, p1}, Lbp/a;->c(Landroid/os/Parcel;I)Landroid/os/Parcel;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    invoke-virtual {p0}, Landroid/os/Parcel;->readStrongBinder()Landroid/os/IBinder;

    .line 17
    .line 18
    .line 19
    move-result-object p1

    .line 20
    if-nez p1, :cond_0

    .line 21
    .line 22
    const/4 p1, 0x0

    .line 23
    goto :goto_0

    .line 24
    :cond_0
    const-string p2, "com.google.android.gms.maps.internal.IMapViewDelegate"

    .line 25
    .line 26
    invoke-interface {p1, p2}, Landroid/os/IBinder;->queryLocalInterface(Ljava/lang/String;)Landroid/os/IInterface;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    instance-of v1, v0, Lrp/g;

    .line 31
    .line 32
    if-eqz v1, :cond_1

    .line 33
    .line 34
    move-object p1, v0

    .line 35
    check-cast p1, Lrp/g;

    .line 36
    .line 37
    goto :goto_0

    .line 38
    :cond_1
    new-instance v0, Lrp/g;

    .line 39
    .line 40
    const/4 v1, 0x5

    .line 41
    invoke-direct {v0, p1, p2, v1}, Lbp/a;-><init>(Landroid/os/IBinder;Ljava/lang/String;I)V

    .line 42
    .line 43
    .line 44
    move-object p1, v0

    .line 45
    :goto_0
    invoke-virtual {p0}, Landroid/os/Parcel;->recycle()V

    .line 46
    .line 47
    .line 48
    return-object p1
.end method

.method public final Y()Lhp/m;
    .locals 5

    .line 1
    invoke-virtual {p0}, Lbp/a;->S()Landroid/os/Parcel;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    const/4 v1, 0x5

    .line 6
    invoke-virtual {p0, v0, v1}, Lbp/a;->c(Landroid/os/Parcel;I)Landroid/os/Parcel;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    invoke-virtual {p0}, Landroid/os/Parcel;->readStrongBinder()Landroid/os/IBinder;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    sget v2, Lhp/l;->d:I

    .line 15
    .line 16
    if-nez v0, :cond_0

    .line 17
    .line 18
    const/4 v0, 0x0

    .line 19
    goto :goto_0

    .line 20
    :cond_0
    const-string v2, "com.google.android.gms.maps.model.internal.IBitmapDescriptorFactoryDelegate"

    .line 21
    .line 22
    invoke-interface {v0, v2}, Landroid/os/IBinder;->queryLocalInterface(Ljava/lang/String;)Landroid/os/IInterface;

    .line 23
    .line 24
    .line 25
    move-result-object v3

    .line 26
    instance-of v4, v3, Lhp/m;

    .line 27
    .line 28
    if-eqz v4, :cond_1

    .line 29
    .line 30
    move-object v0, v3

    .line 31
    check-cast v0, Lhp/m;

    .line 32
    .line 33
    goto :goto_0

    .line 34
    :cond_1
    new-instance v3, Lhp/k;

    .line 35
    .line 36
    invoke-direct {v3, v0, v2, v1}, Lbp/a;-><init>(Landroid/os/IBinder;Ljava/lang/String;I)V

    .line 37
    .line 38
    .line 39
    move-object v0, v3

    .line 40
    :goto_0
    invoke-virtual {p0}, Landroid/os/Parcel;->recycle()V

    .line 41
    .line 42
    .line 43
    return-object v0
.end method
