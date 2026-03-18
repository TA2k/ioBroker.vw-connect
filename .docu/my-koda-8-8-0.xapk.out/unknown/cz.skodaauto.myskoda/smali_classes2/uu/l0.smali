.class public final synthetic Luu/l0;
.super Lkotlin/jvm/internal/k;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# static fields
.field public static final d:Luu/l0;


# direct methods
.method static constructor <clinit>()V
    .locals 6

    .line 1
    new-instance v0, Luu/l0;

    .line 2
    .line 3
    const-string v4, "setOnMapClickListener(Lcom/google/android/gms/maps/GoogleMap$OnMapClickListener;)V"

    .line 4
    .line 5
    const/4 v5, 0x0

    .line 6
    const/4 v1, 0x2

    .line 7
    const-class v2, Lqp/g;

    .line 8
    .line 9
    const-string v3, "setOnMapClickListener"

    .line 10
    .line 11
    invoke-direct/range {v0 .. v5}, Lkotlin/jvm/internal/k;-><init>(ILjava/lang/Class;Ljava/lang/String;Ljava/lang/String;I)V

    .line 12
    .line 13
    .line 14
    sput-object v0, Luu/l0;->d:Luu/l0;

    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    check-cast p1, Lqp/g;

    .line 2
    .line 3
    check-cast p2, Luu/a0;

    .line 4
    .line 5
    const-string p0, "p0"

    .line 6
    .line 7
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    iget-object p0, p1, Lqp/g;->a:Lrp/f;

    .line 11
    .line 12
    const/16 p1, 0x1c

    .line 13
    .line 14
    if-nez p2, :cond_0

    .line 15
    .line 16
    :try_start_0
    invoke-virtual {p0}, Lbp/a;->S()Landroid/os/Parcel;

    .line 17
    .line 18
    .line 19
    move-result-object p2

    .line 20
    const/4 v0, 0x0

    .line 21
    invoke-static {p2, v0}, Lhp/j;->d(Landroid/os/Parcel;Landroid/os/IInterface;)V

    .line 22
    .line 23
    .line 24
    invoke-virtual {p0, p2, p1}, Lbp/a;->U(Landroid/os/Parcel;I)V

    .line 25
    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_0
    new-instance v0, Lqp/j;

    .line 29
    .line 30
    invoke-direct {v0, p2}, Lqp/j;-><init>(Luu/a0;)V

    .line 31
    .line 32
    .line 33
    invoke-virtual {p0}, Lbp/a;->S()Landroid/os/Parcel;

    .line 34
    .line 35
    .line 36
    move-result-object p2

    .line 37
    invoke-static {p2, v0}, Lhp/j;->d(Landroid/os/Parcel;Landroid/os/IInterface;)V

    .line 38
    .line 39
    .line 40
    invoke-virtual {p0, p2, p1}, Lbp/a;->U(Landroid/os/Parcel;I)V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 41
    .line 42
    .line 43
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 44
    .line 45
    return-object p0

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
