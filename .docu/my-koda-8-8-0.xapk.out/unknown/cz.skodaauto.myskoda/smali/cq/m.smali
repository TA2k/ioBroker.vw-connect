.class public final Lcq/m;
.super Lcq/b2;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# virtual methods
.method public final c(Lcom/google/android/gms/common/api/Status;)Lko/p;
    .locals 2

    .line 1
    new-instance p0, Lbq/d;

    .line 2
    .line 3
    iget p1, p1, Lcom/google/android/gms/common/api/Status;->d:I

    .line 4
    .line 5
    new-instance v0, Lcom/google/android/gms/common/data/DataHolder;

    .line 6
    .line 7
    sget-object v1, Lcom/google/android/gms/common/data/DataHolder;->n:Lb81/a;

    .line 8
    .line 9
    invoke-direct {v0, v1, p1}, Lcom/google/android/gms/common/data/DataHolder;-><init>(Lb81/a;I)V

    .line 10
    .line 11
    .line 12
    invoke-direct {p0, v0}, Lbq/d;-><init>(Lcom/google/android/gms/common/data/DataHolder;)V

    .line 13
    .line 14
    .line 15
    return-object p0
.end method

.method public final i(Lko/c;)V
    .locals 2

    .line 1
    check-cast p1, Lcq/t1;

    .line 2
    .line 3
    invoke-virtual {p1}, Lno/e;->r()Landroid/os/IInterface;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    check-cast p1, Lcq/w0;

    .line 8
    .line 9
    new-instance v0, Lcq/n1;

    .line 10
    .line 11
    invoke-direct {v0, p0}, Lcq/m1;-><init>(Llo/e;)V

    .line 12
    .line 13
    .line 14
    invoke-static {}, Landroid/os/Parcel;->obtain()Landroid/os/Parcel;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    iget-object v1, p1, Lbp/a;->e:Ljava/lang/String;

    .line 19
    .line 20
    invoke-virtual {p0, v1}, Landroid/os/Parcel;->writeInterfaceToken(Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    sget v1, Lop/e;->a:I

    .line 24
    .line 25
    invoke-virtual {p0, v0}, Landroid/os/Parcel;->writeStrongBinder(Landroid/os/IBinder;)V

    .line 26
    .line 27
    .line 28
    const/16 v0, 0x8

    .line 29
    .line 30
    invoke-virtual {p1, p0, v0}, Lbp/a;->R(Landroid/os/Parcel;I)V

    .line 31
    .line 32
    .line 33
    return-void
.end method
