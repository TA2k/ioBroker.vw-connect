.class public final Lbp/x;
.super Lhr/b0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Llo/e;


# instance fields
.field public g:Laq/k;

.field public final synthetic h:[Lbp/p;


# direct methods
.method public constructor <init>([Lbp/p;)V
    .locals 2

    .line 1
    iput-object p1, p0, Lbp/x;->h:[Lbp/p;

    .line 2
    .line 3
    const/4 p1, 0x0

    .line 4
    const/16 v0, 0x70e6

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    invoke-direct {p0, v1, p1, v0}, Lhr/b0;-><init>([Ljo/d;ZI)V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final f(Lko/c;Laq/k;)V
    .locals 2

    .line 1
    check-cast p1, Lbp/o;

    .line 2
    .line 3
    invoke-virtual {p1}, Lno/e;->r()Landroid/os/IInterface;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    check-cast p1, Lbp/n;

    .line 8
    .line 9
    iput-object p2, p0, Lbp/x;->g:Laq/k;

    .line 10
    .line 11
    new-instance p2, Lbp/y;

    .line 12
    .line 13
    invoke-direct {p2, p0}, Lbp/y;-><init>(Lbp/x;)V

    .line 14
    .line 15
    .line 16
    invoke-static {}, Landroid/os/Parcel;->obtain()Landroid/os/Parcel;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    iget-object v1, p1, Lbp/a;->e:Ljava/lang/String;

    .line 21
    .line 22
    invoke-virtual {v0, v1}, Landroid/os/Parcel;->writeInterfaceToken(Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    sget v1, Lbp/k;->a:I

    .line 26
    .line 27
    invoke-virtual {v0, p2}, Landroid/os/Parcel;->writeStrongBinder(Landroid/os/IBinder;)V

    .line 28
    .line 29
    .line 30
    iget-object p0, p0, Lbp/x;->h:[Lbp/p;

    .line 31
    .line 32
    const/4 p2, 0x0

    .line 33
    invoke-virtual {v0, p0, p2}, Landroid/os/Parcel;->writeTypedArray([Landroid/os/Parcelable;I)V

    .line 34
    .line 35
    .line 36
    invoke-static {}, Landroid/os/Parcel;->obtain()Landroid/os/Parcel;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    :try_start_0
    iget-object p1, p1, Lbp/a;->d:Landroid/os/IBinder;

    .line 41
    .line 42
    const/4 v1, 0x7

    .line 43
    invoke-interface {p1, v1, v0, p0, p2}, Landroid/os/IBinder;->transact(ILandroid/os/Parcel;Landroid/os/Parcel;I)Z

    .line 44
    .line 45
    .line 46
    invoke-virtual {p0}, Landroid/os/Parcel;->readException()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 47
    .line 48
    .line 49
    invoke-virtual {v0}, Landroid/os/Parcel;->recycle()V

    .line 50
    .line 51
    .line 52
    invoke-virtual {p0}, Landroid/os/Parcel;->recycle()V

    .line 53
    .line 54
    .line 55
    return-void

    .line 56
    :catchall_0
    move-exception p1

    .line 57
    invoke-virtual {v0}, Landroid/os/Parcel;->recycle()V

    .line 58
    .line 59
    .line 60
    invoke-virtual {p0}, Landroid/os/Parcel;->recycle()V

    .line 61
    .line 62
    .line 63
    throw p1
.end method

.method public final z(Ljava/lang/Object;)V
    .locals 1

    .line 1
    check-cast p1, Lcom/google/android/gms/common/api/Status;

    .line 2
    .line 3
    invoke-virtual {p1}, Lcom/google/android/gms/common/api/Status;->x0()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    iget-object p0, p0, Lbp/x;->g:Laq/k;

    .line 10
    .line 11
    const/4 p1, 0x0

    .line 12
    invoke-virtual {p0, p1}, Laq/k;->b(Ljava/lang/Object;)V

    .line 13
    .line 14
    .line 15
    return-void

    .line 16
    :cond_0
    iget-object p0, p0, Lbp/x;->g:Laq/k;

    .line 17
    .line 18
    const-string v0, "User Action indexing error, please try again."

    .line 19
    .line 20
    invoke-static {p1, v0}, Lbp/m;->a(Lcom/google/android/gms/common/api/Status;Ljava/lang/String;)Lb0/l;

    .line 21
    .line 22
    .line 23
    move-result-object p1

    .line 24
    invoke-virtual {p0, p1}, Laq/k;->a(Ljava/lang/Exception;)V

    .line 25
    .line 26
    .line 27
    return-void
.end method
