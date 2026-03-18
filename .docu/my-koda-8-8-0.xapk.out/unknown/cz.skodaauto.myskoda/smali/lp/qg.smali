.class public final Llp/qg;
.super Lbp/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Llp/sg;


# virtual methods
.method public final W(Lyo/b;)Llp/pg;
    .locals 2

    .line 1
    invoke-virtual {p0}, Lbp/a;->S()Landroid/os/Parcel;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    sget v1, Llp/s;->a:I

    .line 6
    .line 7
    invoke-virtual {v0, p1}, Landroid/os/Parcel;->writeStrongBinder(Landroid/os/IBinder;)V

    .line 8
    .line 9
    .line 10
    const/4 p1, 0x1

    .line 11
    invoke-virtual {p0, v0, p1}, Lbp/a;->T(Landroid/os/Parcel;I)Landroid/os/Parcel;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    invoke-virtual {p0}, Landroid/os/Parcel;->readStrongBinder()Landroid/os/IBinder;

    .line 16
    .line 17
    .line 18
    move-result-object p1

    .line 19
    if-nez p1, :cond_0

    .line 20
    .line 21
    const/4 p1, 0x0

    .line 22
    goto :goto_0

    .line 23
    :cond_0
    const-string v0, "com.google.mlkit.vision.text.aidls.ITextRecognizer"

    .line 24
    .line 25
    invoke-interface {p1, v0}, Landroid/os/IBinder;->queryLocalInterface(Ljava/lang/String;)Landroid/os/IInterface;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    instance-of v1, v0, Llp/pg;

    .line 30
    .line 31
    if-eqz v1, :cond_1

    .line 32
    .line 33
    move-object p1, v0

    .line 34
    check-cast p1, Llp/pg;

    .line 35
    .line 36
    goto :goto_0

    .line 37
    :cond_1
    new-instance v0, Llp/pg;

    .line 38
    .line 39
    invoke-direct {v0, p1}, Llp/pg;-><init>(Landroid/os/IBinder;)V

    .line 40
    .line 41
    .line 42
    move-object p1, v0

    .line 43
    :goto_0
    invoke-virtual {p0}, Landroid/os/Parcel;->recycle()V

    .line 44
    .line 45
    .line 46
    return-object p1
.end method

.method public final X(Lyo/b;Llp/xg;)Llp/pg;
    .locals 2

    .line 1
    invoke-virtual {p0}, Lbp/a;->S()Landroid/os/Parcel;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    sget v1, Llp/s;->a:I

    .line 6
    .line 7
    invoke-virtual {v0, p1}, Landroid/os/Parcel;->writeStrongBinder(Landroid/os/IBinder;)V

    .line 8
    .line 9
    .line 10
    const/4 p1, 0x1

    .line 11
    invoke-virtual {v0, p1}, Landroid/os/Parcel;->writeInt(I)V

    .line 12
    .line 13
    .line 14
    const/4 p1, 0x0

    .line 15
    invoke-virtual {p2, v0, p1}, Llp/xg;->writeToParcel(Landroid/os/Parcel;I)V

    .line 16
    .line 17
    .line 18
    const/4 p1, 0x2

    .line 19
    invoke-virtual {p0, v0, p1}, Lbp/a;->T(Landroid/os/Parcel;I)Landroid/os/Parcel;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    invoke-virtual {p0}, Landroid/os/Parcel;->readStrongBinder()Landroid/os/IBinder;

    .line 24
    .line 25
    .line 26
    move-result-object p1

    .line 27
    if-nez p1, :cond_0

    .line 28
    .line 29
    const/4 p1, 0x0

    .line 30
    goto :goto_0

    .line 31
    :cond_0
    const-string p2, "com.google.mlkit.vision.text.aidls.ITextRecognizer"

    .line 32
    .line 33
    invoke-interface {p1, p2}, Landroid/os/IBinder;->queryLocalInterface(Ljava/lang/String;)Landroid/os/IInterface;

    .line 34
    .line 35
    .line 36
    move-result-object p2

    .line 37
    instance-of v0, p2, Llp/pg;

    .line 38
    .line 39
    if-eqz v0, :cond_1

    .line 40
    .line 41
    move-object p1, p2

    .line 42
    check-cast p1, Llp/pg;

    .line 43
    .line 44
    goto :goto_0

    .line 45
    :cond_1
    new-instance p2, Llp/pg;

    .line 46
    .line 47
    invoke-direct {p2, p1}, Llp/pg;-><init>(Landroid/os/IBinder;)V

    .line 48
    .line 49
    .line 50
    move-object p1, p2

    .line 51
    :goto_0
    invoke-virtual {p0}, Landroid/os/Parcel;->recycle()V

    .line 52
    .line 53
    .line 54
    return-object p1
.end method
