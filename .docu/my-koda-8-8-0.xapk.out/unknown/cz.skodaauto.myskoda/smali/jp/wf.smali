.class public abstract Ljp/wf;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static a:Lrp/a;


# direct methods
.method public static final a(Lt71/c;)Z
    .locals 1

    .line 1
    instance-of v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/status/ConnectionErrorStatus$UnknownError;

    .line 2
    .line 3
    if-nez v0, :cond_3

    .line 4
    .line 5
    instance-of v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/status/ConnectionErrorStatus$BackgroundActivityError;

    .line 6
    .line 7
    if-nez v0, :cond_3

    .line 8
    .line 9
    instance-of v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/status/ConnectionErrorStatus$ConnectionEstablishmentError;

    .line 10
    .line 11
    if-nez v0, :cond_3

    .line 12
    .line 13
    instance-of v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/status/ConnectionErrorStatus$ConnectionLostError;

    .line 14
    .line 15
    if-nez v0, :cond_3

    .line 16
    .line 17
    instance-of v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/status/ConnectionErrorStatus$NoError;

    .line 18
    .line 19
    if-nez v0, :cond_3

    .line 20
    .line 21
    if-nez p0, :cond_0

    .line 22
    .line 23
    goto :goto_1

    .line 24
    :cond_0
    instance-of v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/status/ConnectionErrorStatus$PlayProtectionError;

    .line 25
    .line 26
    if-nez v0, :cond_2

    .line 27
    .line 28
    instance-of v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/status/ConnectionErrorStatus$UnsupportedRpaVersionError;

    .line 29
    .line 30
    if-nez v0, :cond_2

    .line 31
    .line 32
    instance-of v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/status/ConnectionErrorStatus$AntennaVersionOutdated;

    .line 33
    .line 34
    if-nez v0, :cond_2

    .line 35
    .line 36
    instance-of p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/status/ConnectionErrorStatus$AppVersionOutdated;

    .line 37
    .line 38
    if-eqz p0, :cond_1

    .line 39
    .line 40
    goto :goto_0

    .line 41
    :cond_1
    new-instance p0, La8/r0;

    .line 42
    .line 43
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 44
    .line 45
    .line 46
    throw p0

    .line 47
    :cond_2
    :goto_0
    const/4 p0, 0x0

    .line 48
    return p0

    .line 49
    :cond_3
    :goto_1
    const/4 p0, 0x1

    .line 50
    return p0
.end method

.method public static b(Lcom/google/android/gms/maps/model/CameraPosition;)Lpv/g;
    .locals 3

    .line 1
    const-string v0, "cameraPosition must not be null"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lno/c0;->i(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    :try_start_0
    new-instance v0, Lpv/g;

    .line 7
    .line 8
    sget-object v1, Ljp/wf;->a:Lrp/a;

    .line 9
    .line 10
    const-string v2, "CameraUpdateFactory is not initialized"

    .line 11
    .line 12
    invoke-static {v1, v2}, Lno/c0;->i(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    invoke-virtual {v1}, Lbp/a;->S()Landroid/os/Parcel;

    .line 16
    .line 17
    .line 18
    move-result-object v2

    .line 19
    invoke-static {v2, p0}, Lhp/j;->c(Landroid/os/Parcel;Landroid/os/Parcelable;)V

    .line 20
    .line 21
    .line 22
    const/4 p0, 0x7

    .line 23
    invoke-virtual {v1, v2, p0}, Lbp/a;->c(Landroid/os/Parcel;I)Landroid/os/Parcel;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    invoke-virtual {p0}, Landroid/os/Parcel;->readStrongBinder()Landroid/os/IBinder;

    .line 28
    .line 29
    .line 30
    move-result-object v1

    .line 31
    invoke-static {v1}, Lyo/b;->T(Landroid/os/IBinder;)Lyo/a;

    .line 32
    .line 33
    .line 34
    move-result-object v1

    .line 35
    invoke-virtual {p0}, Landroid/os/Parcel;->recycle()V

    .line 36
    .line 37
    .line 38
    invoke-direct {v0, v1}, Lpv/g;-><init>(Lyo/a;)V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 39
    .line 40
    .line 41
    return-object v0

    .line 42
    :catch_0
    move-exception p0

    .line 43
    new-instance v0, La8/r0;

    .line 44
    .line 45
    invoke-direct {v0, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 46
    .line 47
    .line 48
    throw v0
.end method

.method public static c(Lcom/google/android/gms/maps/model/LatLng;)Lpv/g;
    .locals 3

    .line 1
    :try_start_0
    new-instance v0, Lpv/g;

    .line 2
    .line 3
    sget-object v1, Ljp/wf;->a:Lrp/a;

    .line 4
    .line 5
    const-string v2, "CameraUpdateFactory is not initialized"

    .line 6
    .line 7
    invoke-static {v1, v2}, Lno/c0;->i(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {v1}, Lbp/a;->S()Landroid/os/Parcel;

    .line 11
    .line 12
    .line 13
    move-result-object v2

    .line 14
    invoke-static {v2, p0}, Lhp/j;->c(Landroid/os/Parcel;Landroid/os/Parcelable;)V

    .line 15
    .line 16
    .line 17
    const/16 p0, 0x8

    .line 18
    .line 19
    invoke-virtual {v1, v2, p0}, Lbp/a;->c(Landroid/os/Parcel;I)Landroid/os/Parcel;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    invoke-virtual {p0}, Landroid/os/Parcel;->readStrongBinder()Landroid/os/IBinder;

    .line 24
    .line 25
    .line 26
    move-result-object v1

    .line 27
    invoke-static {v1}, Lyo/b;->T(Landroid/os/IBinder;)Lyo/a;

    .line 28
    .line 29
    .line 30
    move-result-object v1

    .line 31
    invoke-virtual {p0}, Landroid/os/Parcel;->recycle()V

    .line 32
    .line 33
    .line 34
    invoke-direct {v0, v1}, Lpv/g;-><init>(Lyo/a;)V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 35
    .line 36
    .line 37
    return-object v0

    .line 38
    :catch_0
    move-exception p0

    .line 39
    new-instance v0, La8/r0;

    .line 40
    .line 41
    invoke-direct {v0, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 42
    .line 43
    .line 44
    throw v0
.end method

.method public static d(Lcom/google/android/gms/maps/model/LatLngBounds;I)Lpv/g;
    .locals 3

    .line 1
    :try_start_0
    new-instance v0, Lpv/g;

    .line 2
    .line 3
    sget-object v1, Ljp/wf;->a:Lrp/a;

    .line 4
    .line 5
    const-string v2, "CameraUpdateFactory is not initialized"

    .line 6
    .line 7
    invoke-static {v1, v2}, Lno/c0;->i(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {v1}, Lbp/a;->S()Landroid/os/Parcel;

    .line 11
    .line 12
    .line 13
    move-result-object v2

    .line 14
    invoke-static {v2, p0}, Lhp/j;->c(Landroid/os/Parcel;Landroid/os/Parcelable;)V

    .line 15
    .line 16
    .line 17
    invoke-virtual {v2, p1}, Landroid/os/Parcel;->writeInt(I)V

    .line 18
    .line 19
    .line 20
    const/16 p0, 0xa

    .line 21
    .line 22
    invoke-virtual {v1, v2, p0}, Lbp/a;->c(Landroid/os/Parcel;I)Landroid/os/Parcel;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    invoke-virtual {p0}, Landroid/os/Parcel;->readStrongBinder()Landroid/os/IBinder;

    .line 27
    .line 28
    .line 29
    move-result-object p1

    .line 30
    invoke-static {p1}, Lyo/b;->T(Landroid/os/IBinder;)Lyo/a;

    .line 31
    .line 32
    .line 33
    move-result-object p1

    .line 34
    invoke-virtual {p0}, Landroid/os/Parcel;->recycle()V

    .line 35
    .line 36
    .line 37
    invoke-direct {v0, p1}, Lpv/g;-><init>(Lyo/a;)V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 38
    .line 39
    .line 40
    return-object v0

    .line 41
    :catch_0
    move-exception p0

    .line 42
    new-instance p1, La8/r0;

    .line 43
    .line 44
    invoke-direct {p1, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 45
    .line 46
    .line 47
    throw p1
.end method

.method public static e(Lcom/google/android/gms/maps/model/LatLng;F)Lpv/g;
    .locals 3

    .line 1
    const-string v0, "latLng must not be null"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lno/c0;->i(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    :try_start_0
    new-instance v0, Lpv/g;

    .line 7
    .line 8
    sget-object v1, Ljp/wf;->a:Lrp/a;

    .line 9
    .line 10
    const-string v2, "CameraUpdateFactory is not initialized"

    .line 11
    .line 12
    invoke-static {v1, v2}, Lno/c0;->i(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    invoke-virtual {v1}, Lbp/a;->S()Landroid/os/Parcel;

    .line 16
    .line 17
    .line 18
    move-result-object v2

    .line 19
    invoke-static {v2, p0}, Lhp/j;->c(Landroid/os/Parcel;Landroid/os/Parcelable;)V

    .line 20
    .line 21
    .line 22
    invoke-virtual {v2, p1}, Landroid/os/Parcel;->writeFloat(F)V

    .line 23
    .line 24
    .line 25
    const/16 p0, 0x9

    .line 26
    .line 27
    invoke-virtual {v1, v2, p0}, Lbp/a;->c(Landroid/os/Parcel;I)Landroid/os/Parcel;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    invoke-virtual {p0}, Landroid/os/Parcel;->readStrongBinder()Landroid/os/IBinder;

    .line 32
    .line 33
    .line 34
    move-result-object p1

    .line 35
    invoke-static {p1}, Lyo/b;->T(Landroid/os/IBinder;)Lyo/a;

    .line 36
    .line 37
    .line 38
    move-result-object p1

    .line 39
    invoke-virtual {p0}, Landroid/os/Parcel;->recycle()V

    .line 40
    .line 41
    .line 42
    invoke-direct {v0, p1}, Lpv/g;-><init>(Lyo/a;)V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 43
    .line 44
    .line 45
    return-object v0

    .line 46
    :catch_0
    move-exception p0

    .line 47
    new-instance p1, La8/r0;

    .line 48
    .line 49
    invoke-direct {p1, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 50
    .line 51
    .line 52
    throw p1
.end method
