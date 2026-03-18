.class public final Lc2/k;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lf8/l;
.implements Llo/n;
.implements Lh1/l;
.implements Lju/b;
.implements Lretrofit2/CallAdapter;
.implements Laq/e;
.implements Lmy0/i;
.implements Lh0/s;
.implements Luz0/m1;


# instance fields
.field public final synthetic d:I

.field public e:Ljava/lang/Object;

.field public f:Ljava/lang/Object;


# direct methods
.method public constructor <init>(I)V
    .locals 3

    iput p1, p0, Lc2/k;->d:I

    sparse-switch p1, :sswitch_data_0

    .line 37
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 38
    sget-object p1, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    iput-object p1, p0, Lc2/k;->e:Ljava/lang/Object;

    .line 39
    iput-object p1, p0, Lc2/k;->f:Ljava/lang/Object;

    return-void

    .line 40
    :sswitch_0
    sget-object p1, Ljo/e;->d:Ljo/e;

    .line 41
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Landroid/util/SparseIntArray;

    invoke-direct {v0}, Landroid/util/SparseIntArray;-><init>()V

    iput-object v0, p0, Lc2/k;->e:Ljava/lang/Object;

    .line 42
    iput-object p1, p0, Lc2/k;->f:Ljava/lang/Object;

    return-void

    .line 43
    :sswitch_1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 44
    new-instance p1, Ljava/util/ArrayList;

    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    iput-object p1, p0, Lc2/k;->e:Ljava/lang/Object;

    const/4 p1, 0x5

    .line 45
    new-array v0, p1, [F

    const/4 v1, 0x0

    :goto_0
    if-ge v1, p1, :cond_0

    const/high16 v2, 0x7fc00000    # Float.NaN

    aput v2, v0, v1

    add-int/lit8 v1, v1, 0x1

    goto :goto_0

    :cond_0
    iput-object v0, p0, Lc2/k;->f:Ljava/lang/Object;

    return-void

    :sswitch_data_0
    .sparse-switch
        0x6 -> :sswitch_1
        0x13 -> :sswitch_0
    .end sparse-switch
.end method

.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput p1, p0, Lc2/k;->d:I

    iput-object p2, p0, Lc2/k;->e:Ljava/lang/Object;

    iput-object p3, p0, Lc2/k;->f:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(IZ)V
    .locals 0

    .line 2
    iput p1, p0, Lc2/k;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(Landroid/content/Context;)V
    .locals 1

    const/4 v0, 0x2

    iput v0, p0, Lc2/k;->d:I

    .line 27
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    if-nez p1, :cond_0

    const/4 p1, 0x0

    goto :goto_0

    .line 28
    :cond_0
    invoke-virtual {p1}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    move-result-object p1

    :goto_0
    iput-object p1, p0, Lc2/k;->e:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Landroid/os/IBinder;)V
    .locals 3

    const/16 v0, 0xa

    iput v0, p0, Lc2/k;->d:I

    .line 4
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    invoke-interface {p1}, Landroid/os/IBinder;->getInterfaceDescriptor()Ljava/lang/String;

    move-result-object v0

    const-string v1, "android.os.IMessenger"

    .line 5
    invoke-static {v0, v1}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    const/4 v2, 0x0

    if-eqz v1, :cond_0

    .line 6
    new-instance v0, Landroid/os/Messenger;

    invoke-direct {v0, p1}, Landroid/os/Messenger;-><init>(Landroid/os/IBinder;)V

    iput-object v0, p0, Lc2/k;->e:Ljava/lang/Object;

    iput-object v2, p0, Lc2/k;->f:Ljava/lang/Object;

    goto :goto_0

    :cond_0
    const-string v1, "com.google.android.gms.iid.IMessengerCompat"

    .line 7
    invoke-static {v0, v1}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_1

    .line 8
    new-instance v0, Lio/g;

    .line 9
    invoke-direct {v0, p1}, Lio/g;-><init>(Landroid/os/IBinder;)V

    iput-object v0, p0, Lc2/k;->f:Ljava/lang/Object;

    iput-object v2, p0, Lc2/k;->e:Ljava/lang/Object;

    :goto_0
    return-void

    .line 10
    :cond_1
    invoke-static {v0}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p0

    const-string p1, "MessengerIpcClient"

    const-string v0, "Invalid interface descriptor: "

    invoke-virtual {v0, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    .line 11
    invoke-static {p1, p0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 12
    new-instance p0, Landroid/os/RemoteException;

    invoke-direct {p0}, Landroid/os/RemoteException;-><init>()V

    throw p0
.end method

.method public constructor <init>(Landroid/view/View;)V
    .locals 2

    const/4 v0, 0x0

    iput v0, p0, Lc2/k;->d:I

    .line 25
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lc2/k;->e:Ljava/lang/Object;

    .line 26
    sget-object p1, Llx0/j;->f:Llx0/j;

    new-instance v0, La71/u;

    const/16 v1, 0x16

    invoke-direct {v0, p0, v1}, La71/u;-><init>(Ljava/lang/Object;I)V

    invoke-static {p1, v0}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    move-result-object p1

    iput-object p1, p0, Lc2/k;->f:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Landroidx/lifecycle/s0;Ljava/util/LinkedHashMap;)V
    .locals 1

    const/4 v0, 0x3

    iput v0, p0, Lc2/k;->d:I

    const-string v0, "handle"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 34
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 35
    iput-object p1, p0, Lc2/k;->e:Ljava/lang/Object;

    .line 36
    iput-object p2, p0, Lc2/k;->f:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lay0/k;)V
    .locals 1

    const/16 v0, 0x19

    iput v0, p0, Lc2/k;->d:I

    .line 23
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lc2/k;->e:Ljava/lang/Object;

    .line 24
    new-instance p1, Luz0/q;

    invoke-direct {p1}, Luz0/q;-><init>()V

    iput-object p1, p0, Lc2/k;->f:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lhr/x0;[I)V
    .locals 1

    const/16 v0, 0x1c

    iput v0, p0, Lc2/k;->d:I

    .line 46
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 47
    invoke-static {p1}, Lhr/h0;->p(Ljava/util/Collection;)Lhr/h0;

    move-result-object p1

    iput-object p1, p0, Lc2/k;->e:Ljava/lang/Object;

    .line 48
    iput-object p2, p0, Lc2/k;->f:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lj0/h;)V
    .locals 1

    const/16 p1, 0x18

    iput p1, p0, Lc2/k;->d:I

    .line 49
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 50
    new-instance p1, Ljava/util/concurrent/atomic/AtomicBoolean;

    const/4 v0, 0x1

    invoke-direct {p1, v0}, Ljava/util/concurrent/atomic/AtomicBoolean;-><init>(Z)V

    iput-object p1, p0, Lc2/k;->f:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;ZI)V
    .locals 0

    .line 3
    iput p4, p0, Lc2/k;->d:I

    iput-object p1, p0, Lc2/k;->f:Ljava/lang/Object;

    iput-object p2, p0, Lc2/k;->e:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;)V
    .locals 1

    const/16 v0, 0x12

    iput v0, p0, Lc2/k;->d:I

    const-string v0, "error"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 51
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lc2/k;->e:Ljava/lang/Object;

    iput-object p2, p0, Lc2/k;->f:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;Llp/wd;Lko/d;)V
    .locals 0

    const/16 p3, 0xd

    iput p3, p0, Lc2/k;->d:I

    .line 13
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 14
    iput-object p1, p0, Lc2/k;->f:Ljava/lang/Object;

    iput-object p2, p0, Lc2/k;->e:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lkw0/c;Lzv0/c;)V
    .locals 1

    const/16 v0, 0x10

    iput v0, p0, Lc2/k;->d:I

    const-string v0, "client"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 18
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 19
    iput-object p1, p0, Lc2/k;->e:Ljava/lang/Object;

    .line 20
    iput-object p2, p0, Lc2/k;->f:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lp1/v;Li50/j;Lp1/q;)V
    .locals 0

    const/16 p3, 0x8

    iput p3, p0, Lc2/k;->d:I

    .line 21
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 22
    iput-object p1, p0, Lc2/k;->e:Ljava/lang/Object;

    iput-object p2, p0, Lc2/k;->f:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lro/f;Lb81/a;)V
    .locals 1

    const/16 v0, 0x1d

    iput v0, p0, Lc2/k;->d:I

    .line 15
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Lc2/k;->f:Ljava/lang/Object;

    new-instance p2, Lxr/b;

    const/4 v0, 0x0

    invoke-direct {p2, p0, v0}, Lxr/b;-><init>(Ljava/lang/Object;I)V

    .line 16
    invoke-virtual {p1, p2}, Lro/f;->o(Lxr/b;)V

    new-instance p1, Ljava/util/HashSet;

    .line 17
    invoke-direct {p1}, Ljava/util/HashSet;-><init>()V

    iput-object p1, p0, Lc2/k;->e:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lsr/f;)V
    .locals 1

    const/16 v0, 0xc

    iput v0, p0, Lc2/k;->d:I

    .line 29
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 30
    iput-object p1, p0, Lc2/k;->f:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lu/g0;)V
    .locals 1

    const/16 v0, 0xe

    iput v0, p0, Lc2/k;->d:I

    .line 31
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 32
    iput-object p1, p0, Lc2/k;->e:Ljava/lang/Object;

    const/4 p1, 0x0

    .line 33
    iput-object p1, p0, Lc2/k;->f:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public A(Lfv/b;[Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 1

    .line 1
    const-string v0, "keyNamespace"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "keyComponents"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "value"

    .line 12
    .line 13
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    array-length v0, p2

    .line 17
    invoke-static {p2, v0}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object p2

    .line 21
    invoke-virtual {p1, p2}, Lfv/b;->c([Ljava/lang/Object;)Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object p1

    .line 25
    iget-object p2, p0, Lc2/k;->e:Ljava/lang/Object;

    .line 26
    .line 27
    check-cast p2, Ljava/util/Map;

    .line 28
    .line 29
    invoke-interface {p2, p1, p3}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    iget-object p0, p0, Lc2/k;->f:Ljava/lang/Object;

    .line 33
    .line 34
    check-cast p0, Ljava/util/LinkedHashMap;

    .line 35
    .line 36
    invoke-interface {p0, p1, p3}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    return-void
.end method

.method public a()I
    .locals 4

    .line 1
    iget-object p0, p0, Lc2/k;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Landroid/hardware/camera2/CaptureResult;

    .line 4
    .line 5
    sget-object v0, Landroid/hardware/camera2/CaptureResult;->FLASH_STATE:Landroid/hardware/camera2/CaptureResult$Key;

    .line 6
    .line 7
    invoke-virtual {p0, v0}, Landroid/hardware/camera2/CaptureResult;->get(Landroid/hardware/camera2/CaptureResult$Key;)Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    check-cast p0, Ljava/lang/Integer;

    .line 12
    .line 13
    const/4 v0, 0x1

    .line 14
    if-nez p0, :cond_0

    .line 15
    .line 16
    return v0

    .line 17
    :cond_0
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    const/4 v2, 0x2

    .line 22
    if-eqz v1, :cond_3

    .line 23
    .line 24
    if-eq v1, v0, :cond_3

    .line 25
    .line 26
    const/4 v3, 0x3

    .line 27
    if-eq v1, v2, :cond_2

    .line 28
    .line 29
    const/4 v2, 0x4

    .line 30
    if-eq v1, v3, :cond_1

    .line 31
    .line 32
    if-eq v1, v2, :cond_1

    .line 33
    .line 34
    new-instance v1, Ljava/lang/StringBuilder;

    .line 35
    .line 36
    const-string v2, "Undefined flash state: "

    .line 37
    .line 38
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 42
    .line 43
    .line 44
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    const-string v1, "C2CameraCaptureResult"

    .line 49
    .line 50
    invoke-static {v1, p0}, Ljp/v1;->e(Ljava/lang/String;Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    return v0

    .line 54
    :cond_1
    return v2

    .line 55
    :cond_2
    return v3

    .line 56
    :cond_3
    return v2
.end method

.method public accept(Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 7

    .line 1
    check-cast p2, Laq/k;

    .line 2
    .line 3
    check-cast p1, Lgp/f;

    .line 4
    .line 5
    iget-object v0, p0, Lc2/k;->e:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v0, Lpp/c;

    .line 8
    .line 9
    iget-object p0, p0, Lc2/k;->f:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast p0, Landroid/app/PendingIntent;

    .line 12
    .line 13
    invoke-virtual {p1}, Lno/e;->k()[Ljo/d;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    if-eqz v1, :cond_3

    .line 18
    .line 19
    const/4 v2, 0x0

    .line 20
    :goto_0
    array-length v3, v1

    .line 21
    const/4 v4, 0x0

    .line 22
    if-ge v2, v3, :cond_1

    .line 23
    .line 24
    aget-object v3, v1, v2

    .line 25
    .line 26
    const-string v5, "geofences_with_callback"

    .line 27
    .line 28
    iget-object v6, v3, Ljo/d;->d:Ljava/lang/String;

    .line 29
    .line 30
    invoke-virtual {v5, v6}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 31
    .line 32
    .line 33
    move-result v5

    .line 34
    if-eqz v5, :cond_0

    .line 35
    .line 36
    goto :goto_1

    .line 37
    :cond_0
    add-int/lit8 v2, v2, 0x1

    .line 38
    .line 39
    goto :goto_0

    .line 40
    :cond_1
    move-object v3, v4

    .line 41
    :goto_1
    if-nez v3, :cond_2

    .line 42
    .line 43
    goto :goto_2

    .line 44
    :cond_2
    invoke-virtual {v3}, Ljo/d;->x0()J

    .line 45
    .line 46
    .line 47
    move-result-wide v1

    .line 48
    const-wide/16 v5, 0x1

    .line 49
    .line 50
    cmp-long v1, v1, v5

    .line 51
    .line 52
    if-ltz v1, :cond_3

    .line 53
    .line 54
    invoke-virtual {p1}, Lno/e;->r()Landroid/os/IInterface;

    .line 55
    .line 56
    .line 57
    move-result-object p1

    .line 58
    check-cast p1, Lgp/v;

    .line 59
    .line 60
    new-instance v1, Lbp/r;

    .line 61
    .line 62
    const/4 v2, 0x1

    .line 63
    invoke-direct {v1, v4, p2, v2}, Lbp/r;-><init>(Ljava/lang/Object;Laq/k;I)V

    .line 64
    .line 65
    .line 66
    invoke-virtual {p1}, Lbp/a;->S()Landroid/os/Parcel;

    .line 67
    .line 68
    .line 69
    move-result-object p2

    .line 70
    invoke-static {p2, v0}, Lgp/b;->b(Landroid/os/Parcel;Landroid/os/Parcelable;)V

    .line 71
    .line 72
    .line 73
    invoke-static {p2, p0}, Lgp/b;->b(Landroid/os/Parcel;Landroid/os/Parcelable;)V

    .line 74
    .line 75
    .line 76
    invoke-virtual {p2, v1}, Landroid/os/Parcel;->writeStrongBinder(Landroid/os/IBinder;)V

    .line 77
    .line 78
    .line 79
    const/16 p0, 0x61

    .line 80
    .line 81
    invoke-virtual {p1, p2, p0}, Lbp/a;->U(Landroid/os/Parcel;I)V

    .line 82
    .line 83
    .line 84
    return-void

    .line 85
    :cond_3
    :goto_2
    invoke-virtual {p1}, Lno/e;->r()Landroid/os/IInterface;

    .line 86
    .line 87
    .line 88
    move-result-object p1

    .line 89
    check-cast p1, Lgp/v;

    .line 90
    .line 91
    new-instance v1, Lgp/d;

    .line 92
    .line 93
    const/4 v2, 0x1

    .line 94
    invoke-direct {v1, v2, p2}, Lgp/d;-><init>(ILaq/k;)V

    .line 95
    .line 96
    .line 97
    invoke-virtual {p1}, Lbp/a;->S()Landroid/os/Parcel;

    .line 98
    .line 99
    .line 100
    move-result-object p2

    .line 101
    invoke-static {p2, v0}, Lgp/b;->b(Landroid/os/Parcel;Landroid/os/Parcelable;)V

    .line 102
    .line 103
    .line 104
    invoke-static {p2, p0}, Lgp/b;->b(Landroid/os/Parcel;Landroid/os/Parcelable;)V

    .line 105
    .line 106
    .line 107
    invoke-virtual {p2, v1}, Landroid/os/Parcel;->writeStrongBinder(Landroid/os/IBinder;)V

    .line 108
    .line 109
    .line 110
    const/16 p0, 0x39

    .line 111
    .line 112
    invoke-virtual {p1, p2, p0}, Lbp/a;->U(Landroid/os/Parcel;I)V

    .line 113
    .line 114
    .line 115
    return-void
.end method

.method public b()Lh0/j2;
    .locals 0

    .line 1
    iget-object p0, p0, Lc2/k;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lh0/j2;

    .line 4
    .line 5
    return-object p0
.end method

.method public c()J
    .locals 2

    .line 1
    iget-object p0, p0, Lc2/k;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Landroid/hardware/camera2/CaptureResult;

    .line 4
    .line 5
    sget-object v0, Landroid/hardware/camera2/CaptureResult;->SENSOR_TIMESTAMP:Landroid/hardware/camera2/CaptureResult$Key;

    .line 6
    .line 7
    invoke-virtual {p0, v0}, Landroid/hardware/camera2/CaptureResult;->get(Landroid/hardware/camera2/CaptureResult$Key;)Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    check-cast p0, Ljava/lang/Long;

    .line 12
    .line 13
    if-nez p0, :cond_0

    .line 14
    .line 15
    const-wide/16 v0, -0x1

    .line 16
    .line 17
    return-wide v0

    .line 18
    :cond_0
    invoke-virtual {p0}, Ljava/lang/Long;->longValue()J

    .line 19
    .line 20
    .line 21
    move-result-wide v0

    .line 22
    return-wide v0
.end method

.method public d()Ljava/lang/reflect/Type;
    .locals 0

    .line 1
    iget-object p0, p0, Lc2/k;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Ljava/lang/Class;

    .line 4
    .line 5
    return-object p0
.end method

.method public e(Lretrofit2/Call;)Ljava/lang/Object;
    .locals 1

    .line 1
    new-instance v0, Lji/d;

    .line 2
    .line 3
    iget-object p0, p0, Lc2/k;->e:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast p0, Lcariad/charging/multicharge/retrofit/coroutineAdapter/a;

    .line 6
    .line 7
    invoke-direct {v0, p1, p0}, Lji/d;-><init>(Lretrofit2/Call;Lcariad/charging/multicharge/retrofit/coroutineAdapter/a;)V

    .line 8
    .line 9
    .line 10
    return-object v0
.end method

.method public f()Landroid/hardware/camera2/CaptureResult;
    .locals 0

    .line 1
    iget-object p0, p0, Lc2/k;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Landroid/hardware/camera2/CaptureResult;

    .line 4
    .line 5
    return-object p0
.end method

.method public g(F)F
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move/from16 v1, p1

    .line 4
    .line 5
    iget-object v2, v0, Lc2/k;->e:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v2, Lp1/v;

    .line 8
    .line 9
    invoke-virtual {v2}, Lp1/v;->l()Lp1/o;

    .line 10
    .line 11
    .line 12
    move-result-object v3

    .line 13
    iget-object v3, v3, Lp1/o;->o:Lh1/n;

    .line 14
    .line 15
    invoke-virtual {v2}, Lp1/v;->l()Lp1/o;

    .line 16
    .line 17
    .line 18
    move-result-object v4

    .line 19
    iget-object v4, v4, Lp1/o;->a:Ljava/util/List;

    .line 20
    .line 21
    move-object v5, v4

    .line 22
    check-cast v5, Ljava/util/Collection;

    .line 23
    .line 24
    invoke-interface {v5}, Ljava/util/Collection;->size()I

    .line 25
    .line 26
    .line 27
    move-result v5

    .line 28
    const/high16 v7, 0x7f800000    # Float.POSITIVE_INFINITY

    .line 29
    .line 30
    const/4 v8, 0x0

    .line 31
    move v10, v7

    .line 32
    const/high16 v9, -0x800000    # Float.NEGATIVE_INFINITY

    .line 33
    .line 34
    :goto_0
    const/4 v11, 0x0

    .line 35
    if-ge v8, v5, :cond_2

    .line 36
    .line 37
    invoke-interface {v4, v8}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object v12

    .line 41
    check-cast v12, Lp1/d;

    .line 42
    .line 43
    invoke-virtual {v2}, Lp1/v;->l()Lp1/o;

    .line 44
    .line 45
    .line 46
    move-result-object v13

    .line 47
    invoke-static {v13}, Ljp/bd;->b(Lp1/o;)I

    .line 48
    .line 49
    .line 50
    move-result v13

    .line 51
    invoke-virtual {v2}, Lp1/v;->l()Lp1/o;

    .line 52
    .line 53
    .line 54
    move-result-object v14

    .line 55
    iget v14, v14, Lp1/o;->f:I

    .line 56
    .line 57
    neg-int v14, v14

    .line 58
    invoke-virtual {v2}, Lp1/v;->l()Lp1/o;

    .line 59
    .line 60
    .line 61
    move-result-object v15

    .line 62
    iget v15, v15, Lp1/o;->d:I

    .line 63
    .line 64
    const/high16 v16, -0x800000    # Float.NEGATIVE_INFINITY

    .line 65
    .line 66
    invoke-virtual {v2}, Lp1/v;->l()Lp1/o;

    .line 67
    .line 68
    .line 69
    move-result-object v6

    .line 70
    iget v6, v6, Lp1/o;->b:I

    .line 71
    .line 72
    iget v12, v12, Lp1/d;->l:I

    .line 73
    .line 74
    invoke-virtual {v2}, Lp1/v;->m()I

    .line 75
    .line 76
    .line 77
    invoke-interface {v3, v13, v6, v14, v15}, Lh1/n;->a(IIII)I

    .line 78
    .line 79
    .line 80
    move-result v6

    .line 81
    int-to-float v6, v6

    .line 82
    int-to-float v12, v12

    .line 83
    sub-float/2addr v12, v6

    .line 84
    cmpg-float v6, v12, v11

    .line 85
    .line 86
    if-gtz v6, :cond_0

    .line 87
    .line 88
    cmpl-float v6, v12, v9

    .line 89
    .line 90
    if-lez v6, :cond_0

    .line 91
    .line 92
    move v9, v12

    .line 93
    :cond_0
    cmpl-float v6, v12, v11

    .line 94
    .line 95
    if-ltz v6, :cond_1

    .line 96
    .line 97
    cmpg-float v6, v12, v10

    .line 98
    .line 99
    if-gez v6, :cond_1

    .line 100
    .line 101
    move v10, v12

    .line 102
    :cond_1
    add-int/lit8 v8, v8, 0x1

    .line 103
    .line 104
    goto :goto_0

    .line 105
    :cond_2
    const/high16 v16, -0x800000    # Float.NEGATIVE_INFINITY

    .line 106
    .line 107
    cmpg-float v3, v9, v16

    .line 108
    .line 109
    if-nez v3, :cond_3

    .line 110
    .line 111
    move v9, v10

    .line 112
    :cond_3
    cmpg-float v3, v10, v7

    .line 113
    .line 114
    if-nez v3, :cond_4

    .line 115
    .line 116
    move v10, v9

    .line 117
    :cond_4
    invoke-virtual {v2}, Lp1/v;->d()Z

    .line 118
    .line 119
    .line 120
    move-result v3

    .line 121
    if-nez v3, :cond_6

    .line 122
    .line 123
    invoke-static {v2, v1}, Lkp/ea;->b(Lp1/v;F)Z

    .line 124
    .line 125
    .line 126
    move-result v3

    .line 127
    if-eqz v3, :cond_5

    .line 128
    .line 129
    move v9, v11

    .line 130
    move v10, v9

    .line 131
    goto :goto_1

    .line 132
    :cond_5
    move v10, v11

    .line 133
    :cond_6
    :goto_1
    invoke-virtual {v2}, Lp1/v;->b()Z

    .line 134
    .line 135
    .line 136
    move-result v3

    .line 137
    if-nez v3, :cond_7

    .line 138
    .line 139
    invoke-static {v2, v1}, Lkp/ea;->b(Lp1/v;F)Z

    .line 140
    .line 141
    .line 142
    move-result v2

    .line 143
    move v9, v11

    .line 144
    if-nez v2, :cond_7

    .line 145
    .line 146
    move v10, v9

    .line 147
    :cond_7
    invoke-static {v9}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 148
    .line 149
    .line 150
    move-result-object v2

    .line 151
    invoke-static {v10}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 152
    .line 153
    .line 154
    move-result-object v3

    .line 155
    invoke-virtual {v2}, Ljava/lang/Number;->floatValue()F

    .line 156
    .line 157
    .line 158
    move-result v2

    .line 159
    invoke-virtual {v3}, Ljava/lang/Number;->floatValue()F

    .line 160
    .line 161
    .line 162
    move-result v3

    .line 163
    iget-object v0, v0, Lc2/k;->f:Ljava/lang/Object;

    .line 164
    .line 165
    check-cast v0, Li50/j;

    .line 166
    .line 167
    invoke-static {v1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 168
    .line 169
    .line 170
    move-result-object v1

    .line 171
    invoke-static {v2}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 172
    .line 173
    .line 174
    move-result-object v4

    .line 175
    invoke-static {v3}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 176
    .line 177
    .line 178
    move-result-object v5

    .line 179
    invoke-virtual {v0, v1, v4, v5}, Li50/j;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 180
    .line 181
    .line 182
    move-result-object v0

    .line 183
    check-cast v0, Ljava/lang/Number;

    .line 184
    .line 185
    invoke-virtual {v0}, Ljava/lang/Number;->floatValue()F

    .line 186
    .line 187
    .line 188
    move-result v0

    .line 189
    cmpg-float v1, v0, v2

    .line 190
    .line 191
    if-nez v1, :cond_8

    .line 192
    .line 193
    goto :goto_2

    .line 194
    :cond_8
    cmpg-float v1, v0, v3

    .line 195
    .line 196
    if-nez v1, :cond_9

    .line 197
    .line 198
    goto :goto_2

    .line 199
    :cond_9
    cmpg-float v1, v0, v11

    .line 200
    .line 201
    if-nez v1, :cond_a

    .line 202
    .line 203
    goto :goto_2

    .line 204
    :cond_a
    new-instance v1, Ljava/lang/StringBuilder;

    .line 205
    .line 206
    const-string v4, "Final Snapping Offset Should Be one of "

    .line 207
    .line 208
    invoke-direct {v1, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 209
    .line 210
    .line 211
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 212
    .line 213
    .line 214
    const-string v2, ", "

    .line 215
    .line 216
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 217
    .line 218
    .line 219
    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 220
    .line 221
    .line 222
    const-string v2, " or 0.0"

    .line 223
    .line 224
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 225
    .line 226
    .line 227
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 228
    .line 229
    .line 230
    move-result-object v1

    .line 231
    invoke-static {v1}, Lj1/b;->c(Ljava/lang/String;)V

    .line 232
    .line 233
    .line 234
    :goto_2
    cmpg-float v1, v0, v7

    .line 235
    .line 236
    if-nez v1, :cond_b

    .line 237
    .line 238
    goto :goto_3

    .line 239
    :cond_b
    cmpg-float v1, v0, v16

    .line 240
    .line 241
    if-nez v1, :cond_c

    .line 242
    .line 243
    :goto_3
    return v11

    .line 244
    :cond_c
    return v0
.end method

.method public get()Ljava/lang/Object;
    .locals 2

    .line 1
    iget-object v0, p0, Lc2/k;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lkx0/a;

    .line 4
    .line 5
    invoke-interface {v0}, Lkx0/a;->get()Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    check-cast v0, Lhu/a1;

    .line 10
    .line 11
    iget-object p0, p0, Lc2/k;->f:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast p0, Lju/c;

    .line 14
    .line 15
    invoke-interface {p0}, Lkx0/a;->get()Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    check-cast p0, Lhu/b1;

    .line 20
    .line 21
    new-instance v1, Lhu/p0;

    .line 22
    .line 23
    invoke-direct {v1, v0, p0}, Lhu/p0;-><init>(Lhu/a1;Lhu/b1;)V

    .line 24
    .line 25
    .line 26
    return-object v1
.end method

.method public h(Lhy0/d;)Lqz0/a;
    .locals 2

    .line 1
    iget-object v0, p0, Lc2/k;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Luz0/q;

    .line 4
    .line 5
    invoke-static {p1}, Ljp/p1;->c(Lhy0/d;)Ljava/lang/Class;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    invoke-static {v0, v1}, Lt51/b;->k(Luz0/q;Ljava/lang/Class;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    const-string v1, "get(...)"

    .line 14
    .line 15
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    check-cast v0, Luz0/u0;

    .line 19
    .line 20
    iget-object v1, v0, Luz0/u0;->a:Ljava/lang/ref/SoftReference;

    .line 21
    .line 22
    invoke-virtual {v1}, Ljava/lang/ref/SoftReference;->get()Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object v1

    .line 26
    if-eqz v1, :cond_0

    .line 27
    .line 28
    goto :goto_0

    .line 29
    :cond_0
    monitor-enter v0

    .line 30
    :try_start_0
    iget-object v1, v0, Luz0/u0;->a:Ljava/lang/ref/SoftReference;

    .line 31
    .line 32
    invoke-virtual {v1}, Ljava/lang/ref/SoftReference;->get()Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 36
    if-eqz v1, :cond_1

    .line 37
    .line 38
    monitor-exit v0

    .line 39
    goto :goto_0

    .line 40
    :cond_1
    :try_start_1
    new-instance v1, Luz0/k;

    .line 41
    .line 42
    iget-object p0, p0, Lc2/k;->e:Ljava/lang/Object;

    .line 43
    .line 44
    check-cast p0, Lay0/k;

    .line 45
    .line 46
    invoke-interface {p0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    move-result-object p0

    .line 50
    check-cast p0, Lqz0/a;

    .line 51
    .line 52
    invoke-direct {v1, p0}, Luz0/k;-><init>(Lqz0/a;)V

    .line 53
    .line 54
    .line 55
    new-instance p0, Ljava/lang/ref/SoftReference;

    .line 56
    .line 57
    invoke-direct {p0, v1}, Ljava/lang/ref/SoftReference;-><init>(Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    iput-object p0, v0, Luz0/u0;->a:Ljava/lang/ref/SoftReference;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 61
    .line 62
    monitor-exit v0

    .line 63
    :goto_0
    check-cast v1, Luz0/k;

    .line 64
    .line 65
    iget-object p0, v1, Luz0/k;->a:Lqz0/a;

    .line 66
    .line 67
    return-object p0

    .line 68
    :catchall_0
    move-exception p0

    .line 69
    :try_start_2
    monitor-exit v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 70
    throw p0
.end method

.method public i()Lh0/q;
    .locals 3

    .line 1
    iget-object p0, p0, Lc2/k;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Landroid/hardware/camera2/CaptureResult;

    .line 4
    .line 5
    sget-object v0, Landroid/hardware/camera2/CaptureResult;->CONTROL_AF_STATE:Landroid/hardware/camera2/CaptureResult$Key;

    .line 6
    .line 7
    invoke-virtual {p0, v0}, Landroid/hardware/camera2/CaptureResult;->get(Landroid/hardware/camera2/CaptureResult$Key;)Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    check-cast p0, Ljava/lang/Integer;

    .line 12
    .line 13
    sget-object v0, Lh0/q;->d:Lh0/q;

    .line 14
    .line 15
    if-nez p0, :cond_0

    .line 16
    .line 17
    return-object v0

    .line 18
    :cond_0
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    .line 19
    .line 20
    .line 21
    move-result v1

    .line 22
    packed-switch v1, :pswitch_data_0

    .line 23
    .line 24
    .line 25
    new-instance v1, Ljava/lang/StringBuilder;

    .line 26
    .line 27
    const-string v2, "Undefined af state: "

    .line 28
    .line 29
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    const-string v1, "C2CameraCaptureResult"

    .line 40
    .line 41
    invoke-static {v1, p0}, Ljp/v1;->e(Ljava/lang/String;Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    return-object v0

    .line 45
    :pswitch_0
    sget-object p0, Lh0/q;->h:Lh0/q;

    .line 46
    .line 47
    return-object p0

    .line 48
    :pswitch_1
    sget-object p0, Lh0/q;->j:Lh0/q;

    .line 49
    .line 50
    return-object p0

    .line 51
    :pswitch_2
    sget-object p0, Lh0/q;->i:Lh0/q;

    .line 52
    .line 53
    return-object p0

    .line 54
    :pswitch_3
    sget-object p0, Lh0/q;->g:Lh0/q;

    .line 55
    .line 56
    return-object p0

    .line 57
    :pswitch_4
    sget-object p0, Lh0/q;->f:Lh0/q;

    .line 58
    .line 59
    return-object p0

    .line 60
    :pswitch_5
    sget-object p0, Lh0/q;->e:Lh0/q;

    .line 61
    .line 62
    return-object p0

    .line 63
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_4
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public j(FF)F
    .locals 12

    .line 1
    iget-object p0, p0, Lc2/k;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lp1/v;

    .line 4
    .line 5
    invoke-virtual {p0}, Lp1/v;->n()I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    iget-object v1, p0, Lp1/v;->p:Ll2/j1;

    .line 10
    .line 11
    invoke-virtual {v1}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v2

    .line 15
    check-cast v2, Lp1/o;

    .line 16
    .line 17
    iget v2, v2, Lp1/o;->c:I

    .line 18
    .line 19
    add-int/2addr v2, v0

    .line 20
    const/4 v0, 0x0

    .line 21
    if-nez v2, :cond_0

    .line 22
    .line 23
    return v0

    .line 24
    :cond_0
    cmpg-float v0, p1, v0

    .line 25
    .line 26
    const/4 v3, 0x1

    .line 27
    if-gez v0, :cond_1

    .line 28
    .line 29
    iget v0, p0, Lp1/v;->e:I

    .line 30
    .line 31
    add-int/2addr v0, v3

    .line 32
    goto :goto_0

    .line 33
    :cond_1
    iget v0, p0, Lp1/v;->e:I

    .line 34
    .line 35
    :goto_0
    int-to-float v4, v2

    .line 36
    div-float/2addr p2, v4

    .line 37
    float-to-int p2, p2

    .line 38
    add-int/2addr p2, v0

    .line 39
    invoke-virtual {p0}, Lp1/v;->m()I

    .line 40
    .line 41
    .line 42
    move-result v4

    .line 43
    const/4 v5, 0x0

    .line 44
    invoke-static {p2, v5, v4}, Lkp/r9;->e(III)I

    .line 45
    .line 46
    .line 47
    move-result p2

    .line 48
    invoke-virtual {p0}, Lp1/v;->n()I

    .line 49
    .line 50
    .line 51
    invoke-virtual {v1}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 52
    .line 53
    .line 54
    move-result-object v1

    .line 55
    check-cast v1, Lp1/o;

    .line 56
    .line 57
    iget v1, v1, Lp1/o;->c:I

    .line 58
    .line 59
    int-to-long v6, v0

    .line 60
    int-to-long v3, v3

    .line 61
    sub-long v8, v6, v3

    .line 62
    .line 63
    const-wide/16 v10, 0x0

    .line 64
    .line 65
    cmp-long v1, v8, v10

    .line 66
    .line 67
    if-gez v1, :cond_2

    .line 68
    .line 69
    move-wide v8, v10

    .line 70
    :cond_2
    long-to-int v1, v8

    .line 71
    add-long/2addr v6, v3

    .line 72
    const-wide/32 v3, 0x7fffffff

    .line 73
    .line 74
    .line 75
    cmp-long v8, v6, v3

    .line 76
    .line 77
    if-lez v8, :cond_3

    .line 78
    .line 79
    move-wide v6, v3

    .line 80
    :cond_3
    long-to-int v3, v6

    .line 81
    invoke-static {p2, v1, v3}, Lkp/r9;->e(III)I

    .line 82
    .line 83
    .line 84
    move-result p2

    .line 85
    invoke-virtual {p0}, Lp1/v;->m()I

    .line 86
    .line 87
    .line 88
    move-result p0

    .line 89
    invoke-static {p2, v5, p0}, Lkp/r9;->e(III)I

    .line 90
    .line 91
    .line 92
    move-result p0

    .line 93
    sub-int/2addr p0, v0

    .line 94
    mul-int/2addr p0, v2

    .line 95
    invoke-static {p0}, Ljava/lang/Math;->abs(I)I

    .line 96
    .line 97
    .line 98
    move-result p0

    .line 99
    sub-int/2addr p0, v2

    .line 100
    if-gez p0, :cond_4

    .line 101
    .line 102
    goto :goto_1

    .line 103
    :cond_4
    move v5, p0

    .line 104
    :goto_1
    if-nez v5, :cond_5

    .line 105
    .line 106
    int-to-float p0, v5

    .line 107
    return p0

    .line 108
    :cond_5
    int-to-float p0, v5

    .line 109
    invoke-static {p1}, Ljava/lang/Math;->signum(F)F

    .line 110
    .line 111
    .line 112
    move-result p1

    .line 113
    mul-float/2addr p1, p0

    .line 114
    return p1
.end method

.method public k()Lh0/r;
    .locals 3

    .line 1
    iget-object p0, p0, Lc2/k;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Landroid/hardware/camera2/CaptureResult;

    .line 4
    .line 5
    sget-object v0, Landroid/hardware/camera2/CaptureResult;->CONTROL_AWB_STATE:Landroid/hardware/camera2/CaptureResult$Key;

    .line 6
    .line 7
    invoke-virtual {p0, v0}, Landroid/hardware/camera2/CaptureResult;->get(Landroid/hardware/camera2/CaptureResult$Key;)Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    check-cast p0, Ljava/lang/Integer;

    .line 12
    .line 13
    sget-object v0, Lh0/r;->d:Lh0/r;

    .line 14
    .line 15
    if-nez p0, :cond_0

    .line 16
    .line 17
    return-object v0

    .line 18
    :cond_0
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    .line 19
    .line 20
    .line 21
    move-result v1

    .line 22
    if-eqz v1, :cond_4

    .line 23
    .line 24
    const/4 v2, 0x1

    .line 25
    if-eq v1, v2, :cond_3

    .line 26
    .line 27
    const/4 v2, 0x2

    .line 28
    if-eq v1, v2, :cond_2

    .line 29
    .line 30
    const/4 v2, 0x3

    .line 31
    if-eq v1, v2, :cond_1

    .line 32
    .line 33
    new-instance v1, Ljava/lang/StringBuilder;

    .line 34
    .line 35
    const-string v2, "Undefined awb state: "

    .line 36
    .line 37
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 38
    .line 39
    .line 40
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    const-string v1, "C2CameraCaptureResult"

    .line 48
    .line 49
    invoke-static {v1, p0}, Ljp/v1;->e(Ljava/lang/String;Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    return-object v0

    .line 53
    :cond_1
    sget-object p0, Lh0/r;->h:Lh0/r;

    .line 54
    .line 55
    return-object p0

    .line 56
    :cond_2
    sget-object p0, Lh0/r;->g:Lh0/r;

    .line 57
    .line 58
    return-object p0

    .line 59
    :cond_3
    sget-object p0, Lh0/r;->f:Lh0/r;

    .line 60
    .line 61
    return-object p0

    .line 62
    :cond_4
    sget-object p0, Lh0/r;->e:Lh0/r;

    .line 63
    .line 64
    return-object p0
.end method

.method public bridge synthetic l(Lu/x0;)Lf8/m;
    .locals 0

    .line 1
    invoke-virtual {p0, p1}, Lc2/k;->r(Lu/x0;)Lf8/d;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public m()Lh0/p;
    .locals 3

    .line 1
    iget-object p0, p0, Lc2/k;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Landroid/hardware/camera2/CaptureResult;

    .line 4
    .line 5
    sget-object v0, Landroid/hardware/camera2/CaptureResult;->CONTROL_AE_STATE:Landroid/hardware/camera2/CaptureResult$Key;

    .line 6
    .line 7
    invoke-virtual {p0, v0}, Landroid/hardware/camera2/CaptureResult;->get(Landroid/hardware/camera2/CaptureResult$Key;)Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    check-cast p0, Ljava/lang/Integer;

    .line 12
    .line 13
    sget-object v0, Lh0/p;->d:Lh0/p;

    .line 14
    .line 15
    if-nez p0, :cond_0

    .line 16
    .line 17
    return-object v0

    .line 18
    :cond_0
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    .line 19
    .line 20
    .line 21
    move-result v1

    .line 22
    if-eqz v1, :cond_5

    .line 23
    .line 24
    const/4 v2, 0x1

    .line 25
    if-eq v1, v2, :cond_4

    .line 26
    .line 27
    const/4 v2, 0x2

    .line 28
    if-eq v1, v2, :cond_3

    .line 29
    .line 30
    const/4 v2, 0x3

    .line 31
    if-eq v1, v2, :cond_2

    .line 32
    .line 33
    const/4 v2, 0x4

    .line 34
    if-eq v1, v2, :cond_1

    .line 35
    .line 36
    const/4 v2, 0x5

    .line 37
    if-eq v1, v2, :cond_4

    .line 38
    .line 39
    new-instance v1, Ljava/lang/StringBuilder;

    .line 40
    .line 41
    const-string v2, "Undefined ae state: "

    .line 42
    .line 43
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 44
    .line 45
    .line 46
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 47
    .line 48
    .line 49
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    const-string v1, "C2CameraCaptureResult"

    .line 54
    .line 55
    invoke-static {v1, p0}, Ljp/v1;->e(Ljava/lang/String;Ljava/lang/String;)V

    .line 56
    .line 57
    .line 58
    return-object v0

    .line 59
    :cond_1
    sget-object p0, Lh0/p;->g:Lh0/p;

    .line 60
    .line 61
    return-object p0

    .line 62
    :cond_2
    sget-object p0, Lh0/p;->i:Lh0/p;

    .line 63
    .line 64
    return-object p0

    .line 65
    :cond_3
    sget-object p0, Lh0/p;->h:Lh0/p;

    .line 66
    .line 67
    return-object p0

    .line 68
    :cond_4
    sget-object p0, Lh0/p;->f:Lh0/p;

    .line 69
    .line 70
    return-object p0

    .line 71
    :cond_5
    sget-object p0, Lh0/p;->e:Lh0/p;

    .line 72
    .line 73
    return-object p0
.end method

.method public n(Lmh/j;)V
    .locals 5

    .line 1
    iget-object v0, p0, Lc2/k;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lvp/y1;

    .line 4
    .line 5
    if-nez v0, :cond_2

    .line 6
    .line 7
    new-instance v1, Lvp/y1;

    .line 8
    .line 9
    iget-object v2, p0, Lc2/k;->e:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast v2, Lvp/y1;

    .line 12
    .line 13
    const/4 v3, 0x2

    .line 14
    const/4 v4, 0x0

    .line 15
    invoke-direct {v1, p1, v4, v3}, Lvp/y1;-><init>(Lmh/j;Lvp/y1;I)V

    .line 16
    .line 17
    .line 18
    if-eqz v2, :cond_0

    .line 19
    .line 20
    iput-object v1, v2, Lvp/y1;->f:Ljava/lang/Object;

    .line 21
    .line 22
    :cond_0
    iput-object v1, p0, Lc2/k;->e:Ljava/lang/Object;

    .line 23
    .line 24
    if-nez v0, :cond_1

    .line 25
    .line 26
    iput-object v1, p0, Lc2/k;->f:Ljava/lang/Object;

    .line 27
    .line 28
    :cond_1
    return-void

    .line 29
    :cond_2
    new-instance v1, Lvp/y1;

    .line 30
    .line 31
    const/4 v2, 0x4

    .line 32
    invoke-direct {v1, p1, v0, v2}, Lvp/y1;-><init>(Lmh/j;Lvp/y1;I)V

    .line 33
    .line 34
    .line 35
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 36
    .line 37
    .line 38
    iput-object v1, p0, Lc2/k;->f:Ljava/lang/Object;

    .line 39
    .line 40
    return-void
.end method

.method public o(Lh2/sa;F)V
    .locals 2

    .line 1
    iget-object v0, p0, Lc2/k;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ljava/util/ArrayList;

    .line 4
    .line 5
    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 6
    .line 7
    .line 8
    iget-object p1, p0, Lc2/k;->f:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast p1, [F

    .line 11
    .line 12
    array-length p1, p1

    .line 13
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 14
    .line 15
    .line 16
    move-result v1

    .line 17
    if-ge p1, v1, :cond_0

    .line 18
    .line 19
    iget-object p1, p0, Lc2/k;->f:Ljava/lang/Object;

    .line 20
    .line 21
    check-cast p1, [F

    .line 22
    .line 23
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 24
    .line 25
    .line 26
    move-result v1

    .line 27
    add-int/lit8 v1, v1, 0x2

    .line 28
    .line 29
    invoke-static {p1, v1}, Ljava/util/Arrays;->copyOf([FI)[F

    .line 30
    .line 31
    .line 32
    move-result-object p1

    .line 33
    const-string v1, "copyOf(...)"

    .line 34
    .line 35
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    iput-object p1, p0, Lc2/k;->f:Ljava/lang/Object;

    .line 39
    .line 40
    :cond_0
    iget-object p0, p0, Lc2/k;->f:Ljava/lang/Object;

    .line 41
    .line 42
    check-cast p0, [F

    .line 43
    .line 44
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 45
    .line 46
    .line 47
    move-result p1

    .line 48
    add-int/lit8 p1, p1, -0x1

    .line 49
    .line 50
    aput p2, p0, p1

    .line 51
    .line 52
    return-void
.end method

.method public onComplete(Laq/j;)V
    .locals 0

    .line 1
    iget-object p1, p0, Lc2/k;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p1, Lvp/y1;

    .line 4
    .line 5
    iget-object p1, p1, Lvp/y1;->f:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p1, Ljava/util/Map;

    .line 8
    .line 9
    iget-object p0, p0, Lc2/k;->e:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast p0, Laq/k;

    .line 12
    .line 13
    invoke-interface {p1, p0}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    return-void
.end method

.method public p(ILh0/z;Ljava/util/ArrayList;Ljava/util/ArrayList;Lh0/t;Landroid/util/Range;Z)Ll0/j;
    .locals 35

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p2

    .line 4
    .line 5
    move-object/from16 v2, p5

    .line 6
    .line 7
    move-object/from16 v3, p6

    .line 8
    .line 9
    const-string v4, "cameraInfoInternal"

    .line 10
    .line 11
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    const-string v4, "cameraConfig"

    .line 15
    .line 16
    invoke-static {v2, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    const-string v4, "targetFrameRate"

    .line 20
    .line 21
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    new-instance v4, Ljava/util/ArrayList;

    .line 25
    .line 26
    invoke-direct {v4}, Ljava/util/ArrayList;-><init>()V

    .line 27
    .line 28
    .line 29
    invoke-interface {v1}, Lh0/z;->f()Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object v5

    .line 33
    const-string v6, "getCameraId(...)"

    .line 34
    .line 35
    invoke-static {v5, v6}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    new-instance v7, Ljava/util/LinkedHashMap;

    .line 39
    .line 40
    invoke-direct {v7}, Ljava/util/LinkedHashMap;-><init>()V

    .line 41
    .line 42
    .line 43
    new-instance v8, Ljava/util/LinkedHashMap;

    .line 44
    .line 45
    invoke-direct {v8}, Ljava/util/LinkedHashMap;-><init>()V

    .line 46
    .line 47
    .line 48
    invoke-virtual/range {p4 .. p4}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 49
    .line 50
    .line 51
    move-result-object v9

    .line 52
    :goto_0
    invoke-interface {v9}, Ljava/util/Iterator;->hasNext()Z

    .line 53
    .line 54
    .line 55
    move-result v10

    .line 56
    const-string v12, "No such camera id in supported combination list: "

    .line 57
    .line 58
    const-string v15, "Required value was null."

    .line 59
    .line 60
    if-eqz v10, :cond_7

    .line 61
    .line 62
    invoke-interface {v9}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object v10

    .line 66
    check-cast v10, Lb0/z1;

    .line 67
    .line 68
    iget-object v11, v10, Lb0/z1;->h:Lh0/k;

    .line 69
    .line 70
    if-eqz v11, :cond_6

    .line 71
    .line 72
    const/16 v16, 0x1

    .line 73
    .line 74
    iget-object v13, v0, Lc2/k;->f:Ljava/lang/Object;

    .line 75
    .line 76
    check-cast v13, Lu/d0;

    .line 77
    .line 78
    if-eqz v13, :cond_5

    .line 79
    .line 80
    const/16 v17, 0x0

    .line 81
    .line 82
    iget-object v14, v10, Lb0/z1;->g:Lh0/o2;

    .line 83
    .line 84
    invoke-interface {v14}, Lh0/z0;->l()I

    .line 85
    .line 86
    .line 87
    move-result v14

    .line 88
    move-object/from16 v24, v9

    .line 89
    .line 90
    iget-object v9, v10, Lb0/z1;->h:Lh0/k;

    .line 91
    .line 92
    if-eqz v9, :cond_0

    .line 93
    .line 94
    iget-object v9, v9, Lh0/k;->a:Landroid/util/Size;

    .line 95
    .line 96
    move-object/from16 v19, v9

    .line 97
    .line 98
    goto :goto_1

    .line 99
    :cond_0
    const/16 v19, 0x0

    .line 100
    .line 101
    :goto_1
    if-eqz v19, :cond_4

    .line 102
    .line 103
    iget-object v9, v10, Lb0/z1;->g:Lh0/o2;

    .line 104
    .line 105
    invoke-interface {v9}, Lh0/o2;->H()Lh0/c2;

    .line 106
    .line 107
    .line 108
    move-result-object v23

    .line 109
    iget-object v9, v13, Lu/d0;->b:Ljava/util/HashMap;

    .line 110
    .line 111
    invoke-virtual {v9, v5}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 112
    .line 113
    .line 114
    move-result-object v9

    .line 115
    check-cast v9, Lu/c1;

    .line 116
    .line 117
    if-eqz v9, :cond_1

    .line 118
    .line 119
    move/from16 v13, v16

    .line 120
    .line 121
    goto :goto_2

    .line 122
    :cond_1
    move/from16 v13, v17

    .line 123
    .line 124
    :goto_2
    invoke-virtual {v12, v5}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 125
    .line 126
    .line 127
    move-result-object v12

    .line 128
    invoke-static {v13, v12}, Ljp/ed;->b(ZLjava/lang/String;)V

    .line 129
    .line 130
    .line 131
    invoke-virtual {v9, v14}, Lu/c1;->l(I)Lh0/l;

    .line 132
    .line 133
    .line 134
    move-result-object v20

    .line 135
    sget-object v22, Lh0/f2;->e:Lh0/f2;

    .line 136
    .line 137
    sget-object v9, Lh0/h2;->e:Lh0/c2;

    .line 138
    .line 139
    move/from16 v21, p1

    .line 140
    .line 141
    move/from16 v18, v14

    .line 142
    .line 143
    invoke-static/range {v18 .. v23}, Lkp/aa;->d(ILandroid/util/Size;Lh0/l;ILh0/f2;Lh0/c2;)Lh0/h2;

    .line 144
    .line 145
    .line 146
    move-result-object v26

    .line 147
    iget-object v9, v10, Lb0/z1;->g:Lh0/o2;

    .line 148
    .line 149
    invoke-interface {v9}, Lh0/z0;->l()I

    .line 150
    .line 151
    .line 152
    move-result v27

    .line 153
    iget-object v9, v10, Lb0/z1;->h:Lh0/k;

    .line 154
    .line 155
    if-eqz v9, :cond_2

    .line 156
    .line 157
    iget-object v9, v9, Lh0/k;->a:Landroid/util/Size;

    .line 158
    .line 159
    move-object/from16 v28, v9

    .line 160
    .line 161
    goto :goto_3

    .line 162
    :cond_2
    const/16 v28, 0x0

    .line 163
    .line 164
    :goto_3
    invoke-static/range {v28 .. v28}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 165
    .line 166
    .line 167
    iget-object v9, v11, Lh0/k;->c:Lb0/y;

    .line 168
    .line 169
    invoke-static {v10}, Lt0/e;->H(Lb0/z1;)Ljava/util/ArrayList;

    .line 170
    .line 171
    .line 172
    move-result-object v30

    .line 173
    iget-object v12, v11, Lh0/k;->f:Lh0/q0;

    .line 174
    .line 175
    iget-object v13, v10, Lb0/z1;->g:Lh0/o2;

    .line 176
    .line 177
    sget-object v14, Lh0/o2;->U0:Lh0/g;

    .line 178
    .line 179
    move-object/from16 v18, v5

    .line 180
    .line 181
    invoke-static/range {v17 .. v17}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 182
    .line 183
    .line 184
    move-result-object v5

    .line 185
    invoke-interface {v13, v14, v5}, Lh0/t1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 186
    .line 187
    .line 188
    move-result-object v5

    .line 189
    check-cast v5, Ljava/lang/Integer;

    .line 190
    .line 191
    invoke-virtual {v5}, Ljava/lang/Integer;->intValue()I

    .line 192
    .line 193
    .line 194
    move-result v32

    .line 195
    iget-object v5, v10, Lb0/z1;->g:Lh0/o2;

    .line 196
    .line 197
    sget-object v13, Lh0/k;->h:Landroid/util/Range;

    .line 198
    .line 199
    sget-object v14, Lh0/o2;->V0:Lh0/g;

    .line 200
    .line 201
    invoke-interface {v5, v14, v13}, Lh0/t1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 202
    .line 203
    .line 204
    move-result-object v5

    .line 205
    move-object/from16 v33, v5

    .line 206
    .line 207
    check-cast v33, Landroid/util/Range;

    .line 208
    .line 209
    if-eqz v33, :cond_3

    .line 210
    .line 211
    iget-object v5, v10, Lb0/z1;->g:Lh0/o2;

    .line 212
    .line 213
    sget-object v13, Lh0/o2;->W0:Lh0/g;

    .line 214
    .line 215
    sget-object v14, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 216
    .line 217
    invoke-interface {v5, v13, v14}, Lh0/t1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 218
    .line 219
    .line 220
    move-result-object v5

    .line 221
    check-cast v5, Ljava/lang/Boolean;

    .line 222
    .line 223
    invoke-static {v5}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 224
    .line 225
    .line 226
    invoke-virtual {v5}, Ljava/lang/Boolean;->booleanValue()Z

    .line 227
    .line 228
    .line 229
    move-result v34

    .line 230
    new-instance v25, Lh0/e;

    .line 231
    .line 232
    move-object/from16 v29, v9

    .line 233
    .line 234
    move-object/from16 v31, v12

    .line 235
    .line 236
    invoke-direct/range {v25 .. v34}, Lh0/e;-><init>(Lh0/h2;ILandroid/util/Size;Lb0/y;Ljava/util/List;Lh0/q0;ILandroid/util/Range;Z)V

    .line 237
    .line 238
    .line 239
    move-object/from16 v5, v25

    .line 240
    .line 241
    invoke-virtual {v4, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 242
    .line 243
    .line 244
    invoke-interface {v8, v5, v10}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 245
    .line 246
    .line 247
    invoke-interface {v7, v10, v11}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 248
    .line 249
    .line 250
    move-object/from16 v5, v18

    .line 251
    .line 252
    move-object/from16 v9, v24

    .line 253
    .line 254
    goto/16 :goto_0

    .line 255
    .line 256
    :cond_3
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 257
    .line 258
    invoke-direct {v0, v15}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 259
    .line 260
    .line 261
    throw v0

    .line 262
    :cond_4
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 263
    .line 264
    const-string v1, "Attached surface resolution cannot be null for already attached use cases."

    .line 265
    .line 266
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 267
    .line 268
    .line 269
    throw v0

    .line 270
    :cond_5
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 271
    .line 272
    invoke-direct {v0, v15}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 273
    .line 274
    .line 275
    throw v0

    .line 276
    :cond_6
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 277
    .line 278
    const-string v1, "Attached stream spec cannot be null for already attached use cases."

    .line 279
    .line 280
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 281
    .line 282
    .line 283
    throw v0

    .line 284
    :cond_7
    const/16 v16, 0x1

    .line 285
    .line 286
    const/16 v17, 0x0

    .line 287
    .line 288
    new-instance v4, Landroid/util/Pair;

    .line 289
    .line 290
    invoke-direct {v4, v7, v8}, Landroid/util/Pair;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 291
    .line 292
    .line 293
    iget-object v5, v4, Landroid/util/Pair;->second:Ljava/lang/Object;

    .line 294
    .line 295
    const-string v7, "second"

    .line 296
    .line 297
    invoke-static {v5, v7}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 298
    .line 299
    .line 300
    check-cast v5, Ljava/util/Map;

    .line 301
    .line 302
    sget-object v7, Lh0/t;->x0:Lh0/g;

    .line 303
    .line 304
    sget-object v8, Lh0/r2;->a:Lh0/p2;

    .line 305
    .line 306
    invoke-interface {v2, v7, v8}, Lh0/t1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 307
    .line 308
    .line 309
    move-result-object v2

    .line 310
    check-cast v2, Lh0/r2;

    .line 311
    .line 312
    iget-object v7, v0, Lc2/k;->e:Ljava/lang/Object;

    .line 313
    .line 314
    check-cast v7, Lu/g0;

    .line 315
    .line 316
    move-object/from16 v8, p3

    .line 317
    .line 318
    invoke-static {v8, v2, v7, v3}, Ll0/g;->x(Ljava/util/ArrayList;Lh0/r2;Lh0/r2;Landroid/util/Range;)Ljava/util/HashMap;

    .line 319
    .line 320
    .line 321
    move-result-object v2

    .line 322
    invoke-interface {v1}, Lh0/z;->f()Ljava/lang/String;

    .line 323
    .line 324
    .line 325
    move-result-object v3

    .line 326
    invoke-static {v3, v6}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 327
    .line 328
    .line 329
    new-instance v6, Ljava/util/LinkedHashMap;

    .line 330
    .line 331
    invoke-direct {v6}, Ljava/util/LinkedHashMap;-><init>()V

    .line 332
    .line 333
    .line 334
    invoke-virtual {v8}, Ljava/util/ArrayList;->isEmpty()Z

    .line 335
    .line 336
    .line 337
    move-result v7

    .line 338
    if-nez v7, :cond_16

    .line 339
    .line 340
    new-instance v7, Ljava/util/LinkedHashMap;

    .line 341
    .line 342
    invoke-direct {v7}, Ljava/util/LinkedHashMap;-><init>()V

    .line 343
    .line 344
    .line 345
    new-instance v9, Ljava/util/LinkedHashMap;

    .line 346
    .line 347
    invoke-direct {v9}, Ljava/util/LinkedHashMap;-><init>()V

    .line 348
    .line 349
    .line 350
    :try_start_0
    invoke-interface {v1}, Lh0/z;->g()Landroid/graphics/Rect;

    .line 351
    .line 352
    .line 353
    move-result-object v10
    :try_end_0
    .catch Ljava/lang/NullPointerException; {:try_start_0 .. :try_end_0} :catch_0

    .line 354
    goto :goto_4

    .line 355
    :catch_0
    const/4 v10, 0x0

    .line 356
    :goto_4
    new-instance v11, Lil/g;

    .line 357
    .line 358
    if-eqz v10, :cond_8

    .line 359
    .line 360
    invoke-static {v10}, Li0/f;->f(Landroid/graphics/Rect;)Landroid/util/Size;

    .line 361
    .line 362
    .line 363
    move-result-object v10

    .line 364
    goto :goto_5

    .line 365
    :cond_8
    const/4 v10, 0x0

    .line 366
    :goto_5
    invoke-direct {v11, v1, v10}, Lil/g;-><init>(Lh0/z;Landroid/util/Size;)V

    .line 367
    .line 368
    .line 369
    invoke-virtual {v8}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 370
    .line 371
    .line 372
    move-result-object v10

    .line 373
    move/from16 v31, v17

    .line 374
    .line 375
    :goto_6
    invoke-interface {v10}, Ljava/util/Iterator;->hasNext()Z

    .line 376
    .line 377
    .line 378
    move-result v13

    .line 379
    if-eqz v13, :cond_d

    .line 380
    .line 381
    invoke-interface {v10}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 382
    .line 383
    .line 384
    move-result-object v13

    .line 385
    check-cast v13, Lb0/z1;

    .line 386
    .line 387
    invoke-virtual {v2, v13}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 388
    .line 389
    .line 390
    move-result-object v14

    .line 391
    if-eqz v14, :cond_c

    .line 392
    .line 393
    check-cast v14, Ll0/f;

    .line 394
    .line 395
    move-object/from16 p4, v2

    .line 396
    .line 397
    iget-object v2, v14, Ll0/f;->a:Lh0/o2;

    .line 398
    .line 399
    iget-object v14, v14, Ll0/f;->b:Lh0/o2;

    .line 400
    .line 401
    invoke-virtual {v13, v1, v2, v14}, Lb0/z1;->n(Lh0/z;Lh0/o2;Lh0/o2;)Lh0/o2;

    .line 402
    .line 403
    .line 404
    move-result-object v2

    .line 405
    const-string v14, "mergeConfigs(...)"

    .line 406
    .line 407
    invoke-static {v2, v14}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 408
    .line 409
    .line 410
    invoke-interface {v7, v2, v13}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 411
    .line 412
    .line 413
    invoke-virtual {v11, v2}, Lil/g;->J(Lh0/o2;)Ljava/util/ArrayList;

    .line 414
    .line 415
    .line 416
    move-result-object v14

    .line 417
    invoke-interface {v9, v2, v14}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 418
    .line 419
    .line 420
    instance-of v14, v13, Lb0/k1;

    .line 421
    .line 422
    if-nez v14, :cond_a

    .line 423
    .line 424
    instance-of v13, v13, Lt0/e;

    .line 425
    .line 426
    if-eqz v13, :cond_9

    .line 427
    .line 428
    goto :goto_8

    .line 429
    :cond_9
    :goto_7
    move-object/from16 v2, p4

    .line 430
    .line 431
    goto :goto_6

    .line 432
    :cond_a
    :goto_8
    invoke-interface {v2}, Lh0/o2;->v()I

    .line 433
    .line 434
    .line 435
    move-result v2

    .line 436
    const/4 v13, 0x2

    .line 437
    if-ne v2, v13, :cond_b

    .line 438
    .line 439
    move/from16 v31, v16

    .line 440
    .line 441
    goto :goto_7

    .line 442
    :cond_b
    move/from16 v31, v17

    .line 443
    .line 444
    goto :goto_7

    .line 445
    :cond_c
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 446
    .line 447
    invoke-direct {v0, v15}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 448
    .line 449
    .line 450
    throw v0

    .line 451
    :cond_d
    iget-object v0, v0, Lc2/k;->f:Ljava/lang/Object;

    .line 452
    .line 453
    check-cast v0, Lu/d0;

    .line 454
    .line 455
    if-eqz v0, :cond_15

    .line 456
    .line 457
    new-instance v1, Ljava/util/ArrayList;

    .line 458
    .line 459
    invoke-interface {v5}, Ljava/util/Map;->keySet()Ljava/util/Set;

    .line 460
    .line 461
    .line 462
    move-result-object v2

    .line 463
    check-cast v2, Ljava/util/Collection;

    .line 464
    .line 465
    invoke-direct {v1, v2}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 466
    .line 467
    .line 468
    invoke-virtual {v8}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 469
    .line 470
    .line 471
    move-result-object v2

    .line 472
    :cond_e
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 473
    .line 474
    .line 475
    move-result v8

    .line 476
    if-eqz v8, :cond_f

    .line 477
    .line 478
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 479
    .line 480
    .line 481
    move-result-object v8

    .line 482
    check-cast v8, Lb0/z1;

    .line 483
    .line 484
    invoke-static {v8}, Ll0/g;->B(Lb0/z1;)Z

    .line 485
    .line 486
    .line 487
    move-result v8

    .line 488
    if-eqz v8, :cond_e

    .line 489
    .line 490
    move/from16 v32, v16

    .line 491
    .line 492
    goto :goto_9

    .line 493
    :cond_f
    move/from16 v32, v17

    .line 494
    .line 495
    :goto_9
    invoke-interface {v9}, Ljava/util/Map;->isEmpty()Z

    .line 496
    .line 497
    .line 498
    move-result v2

    .line 499
    xor-int/lit8 v2, v2, 0x1

    .line 500
    .line 501
    const-string v8, "No new use cases to be bound."

    .line 502
    .line 503
    invoke-static {v2, v8}, Ljp/ed;->b(ZLjava/lang/String;)V

    .line 504
    .line 505
    .line 506
    iget-object v0, v0, Lu/d0;->b:Ljava/util/HashMap;

    .line 507
    .line 508
    invoke-virtual {v0, v3}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 509
    .line 510
    .line 511
    move-result-object v0

    .line 512
    move-object/from16 v27, v0

    .line 513
    .line 514
    check-cast v27, Lu/c1;

    .line 515
    .line 516
    if-eqz v27, :cond_10

    .line 517
    .line 518
    move/from16 v13, v16

    .line 519
    .line 520
    goto :goto_a

    .line 521
    :cond_10
    move/from16 v13, v17

    .line 522
    .line 523
    :goto_a
    invoke-virtual {v12, v3}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 524
    .line 525
    .line 526
    move-result-object v0

    .line 527
    invoke-static {v13, v0}, Ljp/ed;->b(ZLjava/lang/String;)V

    .line 528
    .line 529
    .line 530
    move/from16 v28, p1

    .line 531
    .line 532
    move/from16 v33, p7

    .line 533
    .line 534
    move-object/from16 v29, v1

    .line 535
    .line 536
    move-object/from16 v30, v9

    .line 537
    .line 538
    invoke-virtual/range {v27 .. v33}, Lu/c1;->j(ILjava/util/ArrayList;Ljava/util/HashMap;ZZZ)Lh0/i2;

    .line 539
    .line 540
    .line 541
    move-result-object v0

    .line 542
    iget-object v1, v0, Lh0/i2;->a:Ljava/util/HashMap;

    .line 543
    .line 544
    iget-object v2, v0, Lh0/i2;->b:Ljava/util/HashMap;

    .line 545
    .line 546
    iget v0, v0, Lh0/i2;->c:I

    .line 547
    .line 548
    invoke-virtual {v7}, Ljava/util/LinkedHashMap;->entrySet()Ljava/util/Set;

    .line 549
    .line 550
    .line 551
    move-result-object v3

    .line 552
    invoke-interface {v3}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 553
    .line 554
    .line 555
    move-result-object v3

    .line 556
    :goto_b
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 557
    .line 558
    .line 559
    move-result v7

    .line 560
    if-eqz v7, :cond_12

    .line 561
    .line 562
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 563
    .line 564
    .line 565
    move-result-object v7

    .line 566
    check-cast v7, Ljava/util/Map$Entry;

    .line 567
    .line 568
    invoke-interface {v7}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 569
    .line 570
    .line 571
    move-result-object v8

    .line 572
    invoke-interface {v7}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 573
    .line 574
    .line 575
    move-result-object v7

    .line 576
    invoke-virtual {v1, v7}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 577
    .line 578
    .line 579
    move-result-object v7

    .line 580
    if-eqz v7, :cond_11

    .line 581
    .line 582
    invoke-interface {v6, v8, v7}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 583
    .line 584
    .line 585
    goto :goto_b

    .line 586
    :cond_11
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 587
    .line 588
    invoke-direct {v0, v15}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 589
    .line 590
    .line 591
    throw v0

    .line 592
    :cond_12
    invoke-virtual {v2}, Ljava/util/HashMap;->entrySet()Ljava/util/Set;

    .line 593
    .line 594
    .line 595
    move-result-object v1

    .line 596
    invoke-interface {v1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 597
    .line 598
    .line 599
    move-result-object v1

    .line 600
    :cond_13
    :goto_c
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 601
    .line 602
    .line 603
    move-result v2

    .line 604
    if-eqz v2, :cond_17

    .line 605
    .line 606
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 607
    .line 608
    .line 609
    move-result-object v2

    .line 610
    check-cast v2, Ljava/util/Map$Entry;

    .line 611
    .line 612
    invoke-interface {v2}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 613
    .line 614
    .line 615
    move-result-object v3

    .line 616
    invoke-interface {v5, v3}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    .line 617
    .line 618
    .line 619
    move-result v3

    .line 620
    if-eqz v3, :cond_13

    .line 621
    .line 622
    invoke-interface {v2}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 623
    .line 624
    .line 625
    move-result-object v3

    .line 626
    invoke-interface {v5, v3}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 627
    .line 628
    .line 629
    move-result-object v3

    .line 630
    if-eqz v3, :cond_14

    .line 631
    .line 632
    invoke-interface {v2}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 633
    .line 634
    .line 635
    move-result-object v2

    .line 636
    invoke-interface {v6, v3, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 637
    .line 638
    .line 639
    goto :goto_c

    .line 640
    :cond_14
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 641
    .line 642
    invoke-direct {v0, v15}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 643
    .line 644
    .line 645
    throw v0

    .line 646
    :cond_15
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 647
    .line 648
    invoke-direct {v0, v15}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 649
    .line 650
    .line 651
    throw v0

    .line 652
    :cond_16
    const v0, 0x7fffffff

    .line 653
    .line 654
    .line 655
    :cond_17
    new-instance v1, Ll0/j;

    .line 656
    .line 657
    iget-object v2, v4, Landroid/util/Pair;->first:Ljava/lang/Object;

    .line 658
    .line 659
    const-string v3, "first"

    .line 660
    .line 661
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 662
    .line 663
    .line 664
    check-cast v2, Ljava/util/Map;

    .line 665
    .line 666
    invoke-static {v2, v6}, Lmx0/x;->p(Ljava/util/Map;Ljava/util/Map;)Ljava/util/LinkedHashMap;

    .line 667
    .line 668
    .line 669
    move-result-object v2

    .line 670
    invoke-direct {v1, v2, v0}, Ll0/j;-><init>(Ljava/util/Map;I)V

    .line 671
    .line 672
    .line 673
    return-object v1
.end method

.method public q(Law0/h;Lrx0/c;)Ljava/lang/Object;
    .locals 4

    .line 1
    instance-of v0, p2, Llw0/d;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Llw0/d;

    .line 7
    .line 8
    iget v1, v0, Llw0/d;->f:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Llw0/d;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Llw0/d;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Llw0/d;-><init>(Lc2/k;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p0, v0, Llw0/d;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object p2, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v1, v0, Llw0/d;->f:I

    .line 30
    .line 31
    const/4 v2, 0x1

    .line 32
    if-eqz v1, :cond_2

    .line 33
    .line 34
    if-ne v1, v2, :cond_1

    .line 35
    .line 36
    invoke-static {p0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    goto :goto_1

    .line 40
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 41
    .line 42
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 43
    .line 44
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    throw p0

    .line 48
    :cond_2
    invoke-static {p0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    invoke-interface {p1}, Lvy0/b0;->getCoroutineContext()Lpx0/g;

    .line 52
    .line 53
    .line 54
    move-result-object p0

    .line 55
    invoke-static {p0}, Lvy0/e0;->w(Lpx0/g;)Lvy0/i1;

    .line 56
    .line 57
    .line 58
    move-result-object p0

    .line 59
    check-cast p0, Lvy0/s;

    .line 60
    .line 61
    move-object v1, p0

    .line 62
    check-cast v1, Lvy0/k1;

    .line 63
    .line 64
    invoke-virtual {v1}, Lvy0/k1;->l0()Z

    .line 65
    .line 66
    .line 67
    invoke-static {p1}, Lfw0/k;->b(Law0/h;)Z

    .line 68
    .line 69
    .line 70
    move-result v1

    .line 71
    if-nez v1, :cond_3

    .line 72
    .line 73
    :try_start_0
    invoke-virtual {p1}, Law0/h;->b()Lio/ktor/utils/io/t;

    .line 74
    .line 75
    .line 76
    move-result-object p1

    .line 77
    invoke-static {p1}, Lio/ktor/utils/io/h0;->a(Lio/ktor/utils/io/t;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 78
    .line 79
    .line 80
    :catchall_0
    :cond_3
    iput v2, v0, Llw0/d;->f:I

    .line 81
    .line 82
    check-cast p0, Lvy0/p1;

    .line 83
    .line 84
    invoke-virtual {p0, v0}, Lvy0/p1;->l(Lrx0/c;)Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    move-result-object p0

    .line 88
    if-ne p0, p2, :cond_4

    .line 89
    .line 90
    return-object p2

    .line 91
    :cond_4
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 92
    .line 93
    return-object p0
.end method

.method public r(Lu/x0;)Lf8/d;
    .locals 6

    .line 1
    const-string v0, "createCodec:"

    .line 2
    .line 3
    iget-object v1, p1, Lu/x0;->a:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast v1, Lf8/p;

    .line 6
    .line 7
    iget-object v1, v1, Lf8/p;->a:Ljava/lang/String;

    .line 8
    .line 9
    const/4 v2, 0x0

    .line 10
    :try_start_0
    new-instance v3, Ljava/lang/StringBuilder;

    .line 11
    .line 12
    invoke-direct {v3, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    invoke-static {v0}, Landroid/os/Trace;->beginSection(Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    invoke-static {v1}, Landroid/media/MediaCodec;->createByCodecName(Ljava/lang/String;)Landroid/media/MediaCodec;

    .line 26
    .line 27
    .line 28
    move-result-object v0
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_2

    .line 29
    :try_start_1
    new-instance v1, Lf8/g;

    .line 30
    .line 31
    iget-object v3, p0, Lc2/k;->f:Ljava/lang/Object;

    .line 32
    .line 33
    check-cast v3, Lf8/c;

    .line 34
    .line 35
    invoke-virtual {v3}, Lf8/c;->get()Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object v3

    .line 39
    check-cast v3, Landroid/os/HandlerThread;

    .line 40
    .line 41
    invoke-direct {v1, v0, v3}, Lf8/g;-><init>(Landroid/media/MediaCodec;Landroid/os/HandlerThread;)V

    .line 42
    .line 43
    .line 44
    new-instance v3, Lf8/d;

    .line 45
    .line 46
    iget-object p0, p0, Lc2/k;->e:Ljava/lang/Object;

    .line 47
    .line 48
    check-cast p0, Lf8/c;

    .line 49
    .line 50
    invoke-virtual {p0}, Lf8/c;->get()Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    move-result-object p0

    .line 54
    check-cast p0, Landroid/os/HandlerThread;

    .line 55
    .line 56
    iget-object v4, p1, Lu/x0;->f:Ljava/lang/Object;

    .line 57
    .line 58
    check-cast v4, Lgw0/c;

    .line 59
    .line 60
    invoke-direct {v3}, Ljava/lang/Object;-><init>()V

    .line 61
    .line 62
    .line 63
    iput-object v0, v3, Lf8/d;->f:Ljava/lang/Object;

    .line 64
    .line 65
    new-instance v5, Lf8/h;

    .line 66
    .line 67
    invoke-direct {v5, p0}, Lf8/h;-><init>(Landroid/os/HandlerThread;)V

    .line 68
    .line 69
    .line 70
    iput-object v5, v3, Lf8/d;->g:Ljava/lang/Object;

    .line 71
    .line 72
    iput-object v1, v3, Lf8/d;->h:Ljava/lang/Object;

    .line 73
    .line 74
    iput-object v4, v3, Lf8/d;->i:Ljava/lang/Object;

    .line 75
    .line 76
    const/4 p0, 0x0

    .line 77
    iput p0, v3, Lf8/d;->d:I
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_1

    .line 78
    .line 79
    :try_start_2
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 80
    .line 81
    .line 82
    iget-object p0, p1, Lu/x0;->d:Ljava/lang/Object;

    .line 83
    .line 84
    check-cast p0, Landroid/view/Surface;

    .line 85
    .line 86
    if-nez p0, :cond_0

    .line 87
    .line 88
    iget-object v1, p1, Lu/x0;->a:Ljava/lang/Object;

    .line 89
    .line 90
    check-cast v1, Lf8/p;

    .line 91
    .line 92
    iget-boolean v1, v1, Lf8/p;->h:Z

    .line 93
    .line 94
    if-eqz v1, :cond_0

    .line 95
    .line 96
    sget v1, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 97
    .line 98
    const/16 v2, 0x23

    .line 99
    .line 100
    if-lt v1, v2, :cond_0

    .line 101
    .line 102
    const/16 v1, 0x8

    .line 103
    .line 104
    goto :goto_0

    .line 105
    :catch_0
    move-exception p0

    .line 106
    move-object v2, v3

    .line 107
    goto :goto_1

    .line 108
    :cond_0
    const/4 v1, 0x0

    .line 109
    :goto_0
    iget-object v2, p1, Lu/x0;->b:Ljava/lang/Object;

    .line 110
    .line 111
    check-cast v2, Landroid/media/MediaFormat;

    .line 112
    .line 113
    iget-object p1, p1, Lu/x0;->e:Ljava/lang/Object;

    .line 114
    .line 115
    check-cast p1, Landroid/media/MediaCrypto;

    .line 116
    .line 117
    invoke-static {v3, v2, p0, p1, v1}, Lf8/d;->c(Lf8/d;Landroid/media/MediaFormat;Landroid/view/Surface;Landroid/media/MediaCrypto;I)V
    :try_end_2
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_0

    .line 118
    .line 119
    .line 120
    return-object v3

    .line 121
    :catch_1
    move-exception p0

    .line 122
    goto :goto_1

    .line 123
    :catch_2
    move-exception p0

    .line 124
    move-object v0, v2

    .line 125
    :goto_1
    if-nez v2, :cond_1

    .line 126
    .line 127
    if-eqz v0, :cond_2

    .line 128
    .line 129
    invoke-virtual {v0}, Landroid/media/MediaCodec;->release()V

    .line 130
    .line 131
    .line 132
    goto :goto_2

    .line 133
    :cond_1
    invoke-virtual {v2}, Lf8/d;->b()V

    .line 134
    .line 135
    .line 136
    :cond_2
    :goto_2
    throw p0
.end method

.method public s(Lrx0/c;)Ljava/lang/Object;
    .locals 8

    .line 1
    instance-of v0, p1, Llw0/e;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Llw0/e;

    .line 7
    .line 8
    iget v1, v0, Llw0/e;->j:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Llw0/e;->j:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Llw0/e;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Llw0/e;-><init>(Lc2/k;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Llw0/e;->h:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Llw0/e;->j:I

    .line 30
    .line 31
    const/4 v3, 0x3

    .line 32
    const/4 v4, 0x2

    .line 33
    const/4 v5, 0x1

    .line 34
    if-eqz v2, :cond_4

    .line 35
    .line 36
    if-eq v2, v5, :cond_3

    .line 37
    .line 38
    if-eq v2, v4, :cond_2

    .line 39
    .line 40
    if-ne v2, v3, :cond_1

    .line 41
    .line 42
    iget-object p0, v0, Llw0/e;->g:Law0/h;

    .line 43
    .line 44
    :try_start_0
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catch Ljava/util/concurrent/CancellationException; {:try_start_0 .. :try_end_0} :catch_0

    .line 45
    .line 46
    .line 47
    return-object p0

    .line 48
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 49
    .line 50
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 51
    .line 52
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    throw p0

    .line 56
    :cond_2
    iget v2, v0, Llw0/e;->e:I

    .line 57
    .line 58
    iget v4, v0, Llw0/e;->d:I

    .line 59
    .line 60
    iget-object v5, v0, Llw0/e;->f:Law0/c;

    .line 61
    .line 62
    :try_start_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_1
    .catch Ljava/util/concurrent/CancellationException; {:try_start_1 .. :try_end_1} :catch_0

    .line 63
    .line 64
    .line 65
    goto :goto_2

    .line 66
    :cond_3
    iget v2, v0, Llw0/e;->e:I

    .line 67
    .line 68
    iget v5, v0, Llw0/e;->d:I

    .line 69
    .line 70
    :try_start_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_2
    .catch Ljava/util/concurrent/CancellationException; {:try_start_2 .. :try_end_2} :catch_0

    .line 71
    .line 72
    .line 73
    goto :goto_1

    .line 74
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 75
    .line 76
    .line 77
    :try_start_3
    new-instance p1, Lkw0/c;

    .line 78
    .line 79
    invoke-direct {p1}, Lkw0/c;-><init>()V

    .line 80
    .line 81
    .line 82
    iget-object v2, p0, Lc2/k;->e:Ljava/lang/Object;

    .line 83
    .line 84
    check-cast v2, Lkw0/c;

    .line 85
    .line 86
    iget-object v6, v2, Lkw0/c;->e:Lvy0/z1;

    .line 87
    .line 88
    iput-object v6, p1, Lkw0/c;->e:Lvy0/z1;

    .line 89
    .line 90
    invoke-virtual {p1, v2}, Lkw0/c;->c(Lkw0/c;)V

    .line 91
    .line 92
    .line 93
    iget-object v2, p0, Lc2/k;->f:Ljava/lang/Object;

    .line 94
    .line 95
    check-cast v2, Lzv0/c;

    .line 96
    .line 97
    const/4 v6, 0x0

    .line 98
    iput v6, v0, Llw0/e;->d:I

    .line 99
    .line 100
    iput v6, v0, Llw0/e;->e:I

    .line 101
    .line 102
    iput v5, v0, Llw0/e;->j:I

    .line 103
    .line 104
    invoke-virtual {v2, p1, v0}, Lzv0/c;->a(Lkw0/c;Lrx0/c;)Ljava/lang/Object;

    .line 105
    .line 106
    .line 107
    move-result-object p1

    .line 108
    if-ne p1, v1, :cond_5

    .line 109
    .line 110
    goto :goto_3

    .line 111
    :cond_5
    move v2, v6

    .line 112
    move v5, v2

    .line 113
    :goto_1
    check-cast p1, Law0/c;

    .line 114
    .line 115
    iput-object p1, v0, Llw0/e;->f:Law0/c;

    .line 116
    .line 117
    iput v5, v0, Llw0/e;->d:I

    .line 118
    .line 119
    iput v2, v0, Llw0/e;->e:I

    .line 120
    .line 121
    iput v4, v0, Llw0/e;->j:I

    .line 122
    .line 123
    invoke-static {p1, v0}, Ljp/o1;->c(Law0/c;Lrx0/c;)Ljava/lang/Object;

    .line 124
    .line 125
    .line 126
    move-result-object v4

    .line 127
    if-ne v4, v1, :cond_6

    .line 128
    .line 129
    goto :goto_3

    .line 130
    :cond_6
    move v7, v5

    .line 131
    move-object v5, p1

    .line 132
    move-object p1, v4

    .line 133
    move v4, v7

    .line 134
    :goto_2
    check-cast p1, Law0/c;

    .line 135
    .line 136
    invoke-virtual {p1}, Law0/c;->d()Law0/h;

    .line 137
    .line 138
    .line 139
    move-result-object p1

    .line 140
    invoke-virtual {v5}, Law0/c;->d()Law0/h;

    .line 141
    .line 142
    .line 143
    move-result-object v5

    .line 144
    const/4 v6, 0x0

    .line 145
    iput-object v6, v0, Llw0/e;->f:Law0/c;

    .line 146
    .line 147
    iput-object p1, v0, Llw0/e;->g:Law0/h;

    .line 148
    .line 149
    iput v4, v0, Llw0/e;->d:I

    .line 150
    .line 151
    iput v2, v0, Llw0/e;->e:I

    .line 152
    .line 153
    iput v3, v0, Llw0/e;->j:I

    .line 154
    .line 155
    invoke-virtual {p0, v5, v0}, Lc2/k;->q(Law0/h;Lrx0/c;)Ljava/lang/Object;

    .line 156
    .line 157
    .line 158
    move-result-object p0
    :try_end_3
    .catch Ljava/util/concurrent/CancellationException; {:try_start_3 .. :try_end_3} :catch_0

    .line 159
    if-ne p0, v1, :cond_7

    .line 160
    .line 161
    :goto_3
    return-object v1

    .line 162
    :cond_7
    return-object p1

    .line 163
    :catch_0
    move-exception p0

    .line 164
    invoke-static {p0}, Lmw0/a;->a(Ljava/lang/Throwable;)Ljava/lang/Throwable;

    .line 165
    .line 166
    .line 167
    move-result-object p0

    .line 168
    throw p0
.end method

.method public t(Ljava/lang/String;)Ljava/lang/Object;
    .locals 7

    .line 1
    const-string v0, "key"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lc2/k;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Landroidx/lifecycle/s0;

    .line 9
    .line 10
    invoke-virtual {v0, p1}, Landroidx/lifecycle/s0;->a(Ljava/lang/String;)Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object v1

    .line 14
    new-instance v2, Llx0/l;

    .line 15
    .line 16
    invoke-direct {v2, p1, v1}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 17
    .line 18
    .line 19
    invoke-static {v2}, Lmx0/x;->l(Llx0/l;)Ljava/util/Map;

    .line 20
    .line 21
    .line 22
    move-result-object v1

    .line 23
    invoke-interface {v1}, Ljava/util/Map;->isEmpty()Z

    .line 24
    .line 25
    .line 26
    move-result v2

    .line 27
    const/4 v3, 0x0

    .line 28
    if-eqz v2, :cond_0

    .line 29
    .line 30
    new-array v1, v3, [Llx0/l;

    .line 31
    .line 32
    goto :goto_1

    .line 33
    :cond_0
    new-instance v2, Ljava/util/ArrayList;

    .line 34
    .line 35
    invoke-interface {v1}, Ljava/util/Map;->size()I

    .line 36
    .line 37
    .line 38
    move-result v4

    .line 39
    invoke-direct {v2, v4}, Ljava/util/ArrayList;-><init>(I)V

    .line 40
    .line 41
    .line 42
    invoke-interface {v1}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 43
    .line 44
    .line 45
    move-result-object v1

    .line 46
    invoke-interface {v1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 47
    .line 48
    .line 49
    move-result-object v1

    .line 50
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 51
    .line 52
    .line 53
    move-result v4

    .line 54
    if-eqz v4, :cond_1

    .line 55
    .line 56
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 57
    .line 58
    .line 59
    move-result-object v4

    .line 60
    check-cast v4, Ljava/util/Map$Entry;

    .line 61
    .line 62
    invoke-interface {v4}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object v5

    .line 66
    check-cast v5, Ljava/lang/String;

    .line 67
    .line 68
    invoke-interface {v4}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    move-result-object v4

    .line 72
    new-instance v6, Llx0/l;

    .line 73
    .line 74
    invoke-direct {v6, v5, v4}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 75
    .line 76
    .line 77
    invoke-virtual {v2, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 78
    .line 79
    .line 80
    goto :goto_0

    .line 81
    :cond_1
    new-array v1, v3, [Llx0/l;

    .line 82
    .line 83
    invoke-virtual {v2, v1}, Ljava/util/ArrayList;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 84
    .line 85
    .line 86
    move-result-object v1

    .line 87
    check-cast v1, [Llx0/l;

    .line 88
    .line 89
    :goto_1
    array-length v2, v1

    .line 90
    invoke-static {v1, v2}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 91
    .line 92
    .line 93
    move-result-object v1

    .line 94
    check-cast v1, [Llx0/l;

    .line 95
    .line 96
    invoke-static {v1}, Llp/xf;->a([Llx0/l;)Landroid/os/Bundle;

    .line 97
    .line 98
    .line 99
    move-result-object v1

    .line 100
    iget-object p0, p0, Lc2/k;->f:Ljava/lang/Object;

    .line 101
    .line 102
    check-cast p0, Ljava/util/LinkedHashMap;

    .line 103
    .line 104
    invoke-virtual {p0, p1}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 105
    .line 106
    .line 107
    move-result-object p0

    .line 108
    if-eqz p0, :cond_2

    .line 109
    .line 110
    check-cast p0, Lz9/g0;

    .line 111
    .line 112
    invoke-virtual {p0, p1, v1}, Lz9/g0;->a(Ljava/lang/String;Landroid/os/Bundle;)Ljava/lang/Object;

    .line 113
    .line 114
    .line 115
    move-result-object p0

    .line 116
    return-object p0

    .line 117
    :cond_2
    new-instance p0, Ljava/lang/StringBuilder;

    .line 118
    .line 119
    const-string v1, "Failed to find type for "

    .line 120
    .line 121
    invoke-direct {p0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 122
    .line 123
    .line 124
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 125
    .line 126
    .line 127
    const-string p1, " when decoding "

    .line 128
    .line 129
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 130
    .line 131
    .line 132
    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 133
    .line 134
    .line 135
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 136
    .line 137
    .line 138
    move-result-object p0

    .line 139
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 140
    .line 141
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 142
    .line 143
    .line 144
    move-result-object p0

    .line 145
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 146
    .line 147
    .line 148
    throw p1
.end method

.method public toInstant()Lmy0/f;
    .locals 3

    .line 1
    new-instance v0, Lgz0/a;

    .line 2
    .line 3
    new-instance v1, Ljava/lang/StringBuilder;

    .line 4
    .line 5
    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    .line 6
    .line 7
    .line 8
    iget-object v2, p0, Lc2/k;->e:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v2, Ljava/lang/String;

    .line 11
    .line 12
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 13
    .line 14
    .line 15
    const-string v2, " when parsing an Instant from \""

    .line 16
    .line 17
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 18
    .line 19
    .line 20
    iget-object p0, p0, Lc2/k;->f:Ljava/lang/Object;

    .line 21
    .line 22
    check-cast p0, Ljava/lang/String;

    .line 23
    .line 24
    const/16 v2, 0x40

    .line 25
    .line 26
    invoke-static {v2, p0}, Lmy0/h;->u(ILjava/lang/String;)Ljava/lang/String;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const/16 p0, 0x22

    .line 34
    .line 35
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    const/4 v1, 0x2

    .line 43
    invoke-direct {v0, p0, v1}, Lgz0/a;-><init>(Ljava/lang/String;I)V

    .line 44
    .line 45
    .line 46
    throw v0
.end method

.method public toString()Ljava/lang/String;
    .locals 2

    .line 1
    iget v0, p0, Lc2/k;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0

    .line 11
    :pswitch_0
    new-instance v0, Ljava/lang/StringBuilder;

    .line 12
    .line 13
    const-string v1, "HttpStatement["

    .line 14
    .line 15
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    iget-object p0, p0, Lc2/k;->e:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast p0, Lkw0/c;

    .line 21
    .line 22
    iget-object p0, p0, Lkw0/c;->a:Low0/z;

    .line 23
    .line 24
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 25
    .line 26
    .line 27
    const/16 p0, 0x5d

    .line 28
    .line 29
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 30
    .line 31
    .line 32
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    return-object p0

    .line 37
    :pswitch_data_0
    .packed-switch 0x10
        :pswitch_0
    .end packed-switch
.end method

.method public u()Ljava/io/File;
    .locals 4

    .line 1
    const-string v0, "PersistedInstallation."

    .line 2
    .line 3
    iget-object v1, p0, Lc2/k;->e:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast v1, Ljava/io/File;

    .line 6
    .line 7
    if-nez v1, :cond_1

    .line 8
    .line 9
    monitor-enter p0

    .line 10
    :try_start_0
    iget-object v1, p0, Lc2/k;->e:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast v1, Ljava/io/File;

    .line 13
    .line 14
    if-nez v1, :cond_0

    .line 15
    .line 16
    new-instance v1, Ljava/io/File;

    .line 17
    .line 18
    iget-object v2, p0, Lc2/k;->f:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast v2, Lsr/f;

    .line 21
    .line 22
    invoke-virtual {v2}, Lsr/f;->a()V

    .line 23
    .line 24
    .line 25
    iget-object v2, v2, Lsr/f;->a:Landroid/content/Context;

    .line 26
    .line 27
    invoke-virtual {v2}, Landroid/content/Context;->getFilesDir()Ljava/io/File;

    .line 28
    .line 29
    .line 30
    move-result-object v2

    .line 31
    new-instance v3, Ljava/lang/StringBuilder;

    .line 32
    .line 33
    invoke-direct {v3, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    iget-object v0, p0, Lc2/k;->f:Ljava/lang/Object;

    .line 37
    .line 38
    check-cast v0, Lsr/f;

    .line 39
    .line 40
    invoke-virtual {v0}, Lsr/f;->d()Ljava/lang/String;

    .line 41
    .line 42
    .line 43
    move-result-object v0

    .line 44
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 45
    .line 46
    .line 47
    const-string v0, ".json"

    .line 48
    .line 49
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 50
    .line 51
    .line 52
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object v0

    .line 56
    invoke-direct {v1, v2, v0}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    iput-object v1, p0, Lc2/k;->e:Ljava/lang/Object;

    .line 60
    .line 61
    goto :goto_0

    .line 62
    :catchall_0
    move-exception v0

    .line 63
    goto :goto_1

    .line 64
    :cond_0
    :goto_0
    monitor-exit p0

    .line 65
    goto :goto_2

    .line 66
    :goto_1
    monitor-exit p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 67
    throw v0

    .line 68
    :cond_1
    :goto_2
    iget-object p0, p0, Lc2/k;->e:Ljava/lang/Object;

    .line 69
    .line 70
    check-cast p0, Ljava/io/File;

    .line 71
    .line 72
    return-object p0
.end method

.method public v()Landroid/view/inputmethod/InputMethodManager;
    .locals 0

    .line 1
    iget-object p0, p0, Lc2/k;->f:Ljava/lang/Object;

    .line 2
    .line 3
    invoke-interface {p0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Landroid/view/inputmethod/InputMethodManager;

    .line 8
    .line 9
    return-object p0
.end method

.method public varargs w(Lfv/b;[Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    const-string v0, "keyNamespace"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "keyComponents"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    array-length v0, p2

    .line 12
    invoke-static {p2, v0}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object p2

    .line 16
    invoke-virtual {p1, p2}, Lfv/b;->c([Ljava/lang/Object;)Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object p1

    .line 20
    iget-object p2, p0, Lc2/k;->e:Ljava/lang/Object;

    .line 21
    .line 22
    check-cast p2, Ljava/util/Map;

    .line 23
    .line 24
    invoke-interface {p2, p1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object p2

    .line 28
    if-eqz p2, :cond_0

    .line 29
    .line 30
    iget-object p0, p0, Lc2/k;->f:Ljava/lang/Object;

    .line 31
    .line 32
    check-cast p0, Ljava/util/LinkedHashMap;

    .line 33
    .line 34
    invoke-interface {p0, p1, p2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    :cond_0
    return-object p2
.end method

.method public x(Ljt/b;)V
    .locals 4

    .line 1
    :try_start_0
    new-instance v0, Lorg/json/JSONObject;

    .line 2
    .line 3
    invoke-direct {v0}, Lorg/json/JSONObject;-><init>()V

    .line 4
    .line 5
    .line 6
    const-string v1, "Fid"

    .line 7
    .line 8
    iget-object v2, p1, Ljt/b;->a:Ljava/lang/String;

    .line 9
    .line 10
    invoke-virtual {v0, v1, v2}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 11
    .line 12
    .line 13
    const-string v1, "Status"

    .line 14
    .line 15
    iget v2, p1, Ljt/b;->b:I

    .line 16
    .line 17
    invoke-static {v2}, Lu/w;->o(I)I

    .line 18
    .line 19
    .line 20
    move-result v2

    .line 21
    invoke-virtual {v0, v1, v2}, Lorg/json/JSONObject;->put(Ljava/lang/String;I)Lorg/json/JSONObject;

    .line 22
    .line 23
    .line 24
    const-string v1, "AuthToken"

    .line 25
    .line 26
    iget-object v2, p1, Ljt/b;->c:Ljava/lang/String;

    .line 27
    .line 28
    invoke-virtual {v0, v1, v2}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 29
    .line 30
    .line 31
    const-string v1, "RefreshToken"

    .line 32
    .line 33
    iget-object v2, p1, Ljt/b;->d:Ljava/lang/String;

    .line 34
    .line 35
    invoke-virtual {v0, v1, v2}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 36
    .line 37
    .line 38
    const-string v1, "TokenCreationEpochInSecs"

    .line 39
    .line 40
    iget-wide v2, p1, Ljt/b;->f:J

    .line 41
    .line 42
    invoke-virtual {v0, v1, v2, v3}, Lorg/json/JSONObject;->put(Ljava/lang/String;J)Lorg/json/JSONObject;

    .line 43
    .line 44
    .line 45
    const-string v1, "ExpiresInSecs"

    .line 46
    .line 47
    iget-wide v2, p1, Ljt/b;->e:J

    .line 48
    .line 49
    invoke-virtual {v0, v1, v2, v3}, Lorg/json/JSONObject;->put(Ljava/lang/String;J)Lorg/json/JSONObject;

    .line 50
    .line 51
    .line 52
    const-string v1, "FisError"

    .line 53
    .line 54
    iget-object p1, p1, Ljt/b;->g:Ljava/lang/String;

    .line 55
    .line 56
    invoke-virtual {v0, v1, p1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 57
    .line 58
    .line 59
    const-string p1, "PersistedInstallation"

    .line 60
    .line 61
    const-string v1, "tmp"

    .line 62
    .line 63
    iget-object v2, p0, Lc2/k;->f:Ljava/lang/Object;

    .line 64
    .line 65
    check-cast v2, Lsr/f;

    .line 66
    .line 67
    invoke-virtual {v2}, Lsr/f;->a()V

    .line 68
    .line 69
    .line 70
    iget-object v2, v2, Lsr/f;->a:Landroid/content/Context;

    .line 71
    .line 72
    invoke-virtual {v2}, Landroid/content/Context;->getFilesDir()Ljava/io/File;

    .line 73
    .line 74
    .line 75
    move-result-object v2

    .line 76
    invoke-static {p1, v1, v2}, Ljava/io/File;->createTempFile(Ljava/lang/String;Ljava/lang/String;Ljava/io/File;)Ljava/io/File;

    .line 77
    .line 78
    .line 79
    move-result-object p1

    .line 80
    new-instance v1, Ljava/io/FileOutputStream;

    .line 81
    .line 82
    invoke-direct {v1, p1}, Ljava/io/FileOutputStream;-><init>(Ljava/io/File;)V

    .line 83
    .line 84
    .line 85
    invoke-virtual {v0}, Lorg/json/JSONObject;->toString()Ljava/lang/String;

    .line 86
    .line 87
    .line 88
    move-result-object v0

    .line 89
    const-string v2, "UTF-8"

    .line 90
    .line 91
    invoke-virtual {v0, v2}, Ljava/lang/String;->getBytes(Ljava/lang/String;)[B

    .line 92
    .line 93
    .line 94
    move-result-object v0

    .line 95
    invoke-virtual {v1, v0}, Ljava/io/FileOutputStream;->write([B)V

    .line 96
    .line 97
    .line 98
    invoke-virtual {v1}, Ljava/io/FileOutputStream;->close()V

    .line 99
    .line 100
    .line 101
    invoke-virtual {p0}, Lc2/k;->u()Ljava/io/File;

    .line 102
    .line 103
    .line 104
    move-result-object p0

    .line 105
    invoke-virtual {p1, p0}, Ljava/io/File;->renameTo(Ljava/io/File;)Z

    .line 106
    .line 107
    .line 108
    move-result p0

    .line 109
    if-eqz p0, :cond_0

    .line 110
    .line 111
    goto :goto_0

    .line 112
    :cond_0
    new-instance p0, Ljava/io/IOException;

    .line 113
    .line 114
    const-string p1, "unable to rename the tmpfile to PersistedInstallation"

    .line 115
    .line 116
    invoke-direct {p0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 117
    .line 118
    .line 119
    throw p0
    :try_end_0
    .catch Lorg/json/JSONException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 120
    :catch_0
    :goto_0
    return-void
.end method

.method public y(ILdx/l;)V
    .locals 7

    .line 1
    iget-object v0, p0, Lc2/k;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lam0/z;

    .line 4
    .line 5
    iget-object p0, p0, Lc2/k;->e:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p0, Lpx0/i;

    .line 8
    .line 9
    const-string v1, "type"

    .line 10
    .line 11
    invoke-static {p1, v1}, Lia/b;->q(ILjava/lang/String;)V

    .line 12
    .line 13
    .line 14
    const-string v1, "result"

    .line 15
    .line 16
    invoke-static {p2, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    sget-object v1, Ldx/l;->d:Ldx/l;

    .line 20
    .line 21
    if-ne p2, v1, :cond_0

    .line 22
    .line 23
    new-instance p1, Lne0/e;

    .line 24
    .line 25
    sget-object p2, Llx0/b0;->a:Llx0/b0;

    .line 26
    .line 27
    invoke-direct {p1, p2}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 28
    .line 29
    .line 30
    invoke-virtual {p0, p1}, Lpx0/i;->resumeWith(Ljava/lang/Object;)V

    .line 31
    .line 32
    .line 33
    goto :goto_1

    .line 34
    :cond_0
    new-instance v1, Lne0/c;

    .line 35
    .line 36
    new-instance v2, Ljava/lang/IllegalStateException;

    .line 37
    .line 38
    new-instance v3, Ljava/lang/StringBuilder;

    .line 39
    .line 40
    const-string v4, "Failed to update SSL certificates. Type: "

    .line 41
    .line 42
    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    const/4 v4, 0x1

    .line 46
    if-eq p1, v4, :cond_3

    .line 47
    .line 48
    const/4 v4, 0x2

    .line 49
    if-eq p1, v4, :cond_2

    .line 50
    .line 51
    const/4 v4, 0x3

    .line 52
    if-eq p1, v4, :cond_1

    .line 53
    .line 54
    const-string p1, "null"

    .line 55
    .line 56
    goto :goto_0

    .line 57
    :cond_1
    const-string p1, "NO_UPDATE"

    .line 58
    .line 59
    goto :goto_0

    .line 60
    :cond_2
    const-string p1, "SILENT"

    .line 61
    .line 62
    goto :goto_0

    .line 63
    :cond_3
    const-string p1, "DIRECT"

    .line 64
    .line 65
    :goto_0
    invoke-virtual {v3, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 66
    .line 67
    .line 68
    const-string p1, ", Result: "

    .line 69
    .line 70
    invoke-virtual {v3, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 71
    .line 72
    .line 73
    invoke-virtual {v3, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 74
    .line 75
    .line 76
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 77
    .line 78
    .line 79
    move-result-object p1

    .line 80
    invoke-direct {v2, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 81
    .line 82
    .line 83
    const/4 v5, 0x0

    .line 84
    const/16 v6, 0x1e

    .line 85
    .line 86
    const/4 v3, 0x0

    .line 87
    const/4 v4, 0x0

    .line 88
    invoke-direct/range {v1 .. v6}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 89
    .line 90
    .line 91
    new-instance p1, Lam0/y;

    .line 92
    .line 93
    const/4 p2, 0x0

    .line 94
    invoke-direct {p1, v1, p2}, Lam0/y;-><init>(Lne0/c;I)V

    .line 95
    .line 96
    .line 97
    invoke-static {v0, p1}, Llp/nd;->e(Ljava/lang/Object;Lay0/a;)V

    .line 98
    .line 99
    .line 100
    invoke-virtual {p0, v1}, Lpx0/i;->resumeWith(Ljava/lang/Object;)V

    .line 101
    .line 102
    .line 103
    :goto_1
    iget-object p0, v0, Lam0/z;->b:Lam0/u;

    .line 104
    .line 105
    const/4 p1, 0x1

    .line 106
    check-cast p0, Lxl0/h;

    .line 107
    .line 108
    iput p1, p0, Lxl0/h;->a:I

    .line 109
    .line 110
    return-void
.end method

.method public z()Ljt/b;
    .locals 14

    .line 1
    new-instance v0, Ljava/io/ByteArrayOutputStream;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/io/ByteArrayOutputStream;-><init>()V

    .line 4
    .line 5
    .line 6
    const/16 v1, 0x4000

    .line 7
    .line 8
    new-array v2, v1, [B

    .line 9
    .line 10
    const/4 v3, 0x0

    .line 11
    :try_start_0
    new-instance v4, Ljava/io/FileInputStream;

    .line 12
    .line 13
    invoke-virtual {p0}, Lc2/k;->u()Ljava/io/File;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    invoke-direct {v4, p0}, Ljava/io/FileInputStream;-><init>(Ljava/io/File;)V
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Lorg/json/JSONException; {:try_start_0 .. :try_end_0} :catch_0

    .line 18
    .line 19
    .line 20
    :goto_0
    :try_start_1
    invoke-virtual {v4, v2, v3, v1}, Ljava/io/FileInputStream;->read([BII)I

    .line 21
    .line 22
    .line 23
    move-result p0

    .line 24
    if-gez p0, :cond_0

    .line 25
    .line 26
    new-instance p0, Lorg/json/JSONObject;

    .line 27
    .line 28
    invoke-virtual {v0}, Ljava/io/ByteArrayOutputStream;->toString()Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    invoke-direct {p0, v0}, Lorg/json/JSONObject;-><init>(Ljava/lang/String;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 33
    .line 34
    .line 35
    :try_start_2
    invoke-virtual {v4}, Ljava/io/FileInputStream;->close()V
    :try_end_2
    .catch Ljava/io/IOException; {:try_start_2 .. :try_end_2} :catch_0
    .catch Lorg/json/JSONException; {:try_start_2 .. :try_end_2} :catch_0

    .line 36
    .line 37
    .line 38
    goto :goto_3

    .line 39
    :catchall_0
    move-exception v0

    .line 40
    move-object p0, v0

    .line 41
    goto :goto_1

    .line 42
    :cond_0
    :try_start_3
    invoke-virtual {v0, v2, v3, p0}, Ljava/io/ByteArrayOutputStream;->write([BII)V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 43
    .line 44
    .line 45
    goto :goto_0

    .line 46
    :goto_1
    :try_start_4
    invoke-virtual {v4}, Ljava/io/FileInputStream;->close()V
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 47
    .line 48
    .line 49
    goto :goto_2

    .line 50
    :catchall_1
    move-exception v0

    .line 51
    :try_start_5
    invoke-virtual {p0, v0}, Ljava/lang/Throwable;->addSuppressed(Ljava/lang/Throwable;)V

    .line 52
    .line 53
    .line 54
    :goto_2
    throw p0
    :try_end_5
    .catch Ljava/io/IOException; {:try_start_5 .. :try_end_5} :catch_0
    .catch Lorg/json/JSONException; {:try_start_5 .. :try_end_5} :catch_0

    .line 55
    :catch_0
    new-instance p0, Lorg/json/JSONObject;

    .line 56
    .line 57
    invoke-direct {p0}, Lorg/json/JSONObject;-><init>()V

    .line 58
    .line 59
    .line 60
    :goto_3
    const-string v0, "Fid"

    .line 61
    .line 62
    const/4 v1, 0x0

    .line 63
    invoke-virtual {p0, v0, v1}, Lorg/json/JSONObject;->optString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 64
    .line 65
    .line 66
    move-result-object v5

    .line 67
    const-string v0, "Status"

    .line 68
    .line 69
    invoke-virtual {p0, v0, v3}, Lorg/json/JSONObject;->optInt(Ljava/lang/String;I)I

    .line 70
    .line 71
    .line 72
    move-result v0

    .line 73
    const-string v2, "AuthToken"

    .line 74
    .line 75
    invoke-virtual {p0, v2, v1}, Lorg/json/JSONObject;->optString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 76
    .line 77
    .line 78
    move-result-object v7

    .line 79
    const-string v2, "RefreshToken"

    .line 80
    .line 81
    invoke-virtual {p0, v2, v1}, Lorg/json/JSONObject;->optString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 82
    .line 83
    .line 84
    move-result-object v8

    .line 85
    const-string v2, "TokenCreationEpochInSecs"

    .line 86
    .line 87
    const-wide/16 v3, 0x0

    .line 88
    .line 89
    invoke-virtual {p0, v2, v3, v4}, Lorg/json/JSONObject;->optLong(Ljava/lang/String;J)J

    .line 90
    .line 91
    .line 92
    move-result-wide v11

    .line 93
    const-string v2, "ExpiresInSecs"

    .line 94
    .line 95
    invoke-virtual {p0, v2, v3, v4}, Lorg/json/JSONObject;->optLong(Ljava/lang/String;J)J

    .line 96
    .line 97
    .line 98
    move-result-wide v9

    .line 99
    const-string v2, "FisError"

    .line 100
    .line 101
    invoke-virtual {p0, v2, v1}, Lorg/json/JSONObject;->optString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 102
    .line 103
    .line 104
    move-result-object v13

    .line 105
    sget p0, Ljt/b;->h:I

    .line 106
    .line 107
    const/4 p0, 0x0

    .line 108
    or-int/lit8 p0, p0, 0x2

    .line 109
    .line 110
    int-to-byte p0, p0

    .line 111
    or-int/lit8 p0, p0, 0x1

    .line 112
    .line 113
    int-to-byte p0, p0

    .line 114
    const/4 v1, 0x5

    .line 115
    invoke-static {v1}, Lu/w;->r(I)[I

    .line 116
    .line 117
    .line 118
    move-result-object v1

    .line 119
    aget v6, v1, v0

    .line 120
    .line 121
    if-eqz v6, :cond_6

    .line 122
    .line 123
    or-int/lit8 p0, p0, 0x2

    .line 124
    .line 125
    int-to-byte p0, p0

    .line 126
    or-int/lit8 p0, p0, 0x1

    .line 127
    .line 128
    int-to-byte p0, p0

    .line 129
    const/4 v0, 0x3

    .line 130
    if-ne p0, v0, :cond_2

    .line 131
    .line 132
    if-nez v6, :cond_1

    .line 133
    .line 134
    goto :goto_4

    .line 135
    :cond_1
    new-instance v4, Ljt/b;

    .line 136
    .line 137
    invoke-direct/range {v4 .. v13}, Ljt/b;-><init>(Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;JJLjava/lang/String;)V

    .line 138
    .line 139
    .line 140
    return-object v4

    .line 141
    :cond_2
    :goto_4
    new-instance v0, Ljava/lang/StringBuilder;

    .line 142
    .line 143
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 144
    .line 145
    .line 146
    if-nez v6, :cond_3

    .line 147
    .line 148
    const-string v1, " registrationStatus"

    .line 149
    .line 150
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 151
    .line 152
    .line 153
    :cond_3
    and-int/lit8 v1, p0, 0x1

    .line 154
    .line 155
    if-nez v1, :cond_4

    .line 156
    .line 157
    const-string v1, " expiresInSecs"

    .line 158
    .line 159
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 160
    .line 161
    .line 162
    :cond_4
    and-int/lit8 p0, p0, 0x2

    .line 163
    .line 164
    if-nez p0, :cond_5

    .line 165
    .line 166
    const-string p0, " tokenCreationEpochInSecs"

    .line 167
    .line 168
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 169
    .line 170
    .line 171
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 172
    .line 173
    const-string v1, "Missing required properties:"

    .line 174
    .line 175
    invoke-static {v1, v0}, Lkx/a;->j(Ljava/lang/String;Ljava/lang/StringBuilder;)Ljava/lang/String;

    .line 176
    .line 177
    .line 178
    move-result-object v0

    .line 179
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 180
    .line 181
    .line 182
    throw p0

    .line 183
    :cond_6
    new-instance p0, Ljava/lang/NullPointerException;

    .line 184
    .line 185
    const-string v0, "Null registrationStatus"

    .line 186
    .line 187
    invoke-direct {p0, v0}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 188
    .line 189
    .line 190
    throw p0
.end method
