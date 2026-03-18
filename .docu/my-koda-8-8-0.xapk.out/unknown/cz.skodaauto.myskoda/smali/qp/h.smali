.class public final Lqp/h;
.super Landroid/widget/FrameLayout;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Lqn/s;


# direct methods
.method public constructor <init>(Landroid/content/Context;Lcom/google/android/gms/maps/GoogleMapOptions;)V
    .locals 3

    .line 1
    invoke-direct {p0, p1}, Landroid/widget/FrameLayout;-><init>(Landroid/content/Context;)V

    .line 2
    .line 3
    .line 4
    new-instance v0, Lqn/s;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    new-instance v1, Lro/f;

    .line 10
    .line 11
    const/16 v2, 0x15

    .line 12
    .line 13
    invoke-direct {v1, v0, v2}, Lro/f;-><init>(Ljava/lang/Object;I)V

    .line 14
    .line 15
    .line 16
    iput-object v1, v0, Lqn/s;->d:Ljava/lang/Object;

    .line 17
    .line 18
    new-instance v1, Ljava/util/ArrayList;

    .line 19
    .line 20
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 21
    .line 22
    .line 23
    iput-object v1, v0, Lqn/s;->i:Ljava/lang/Object;

    .line 24
    .line 25
    iput-object p0, v0, Lqn/s;->e:Ljava/lang/Object;

    .line 26
    .line 27
    iput-object p1, v0, Lqn/s;->f:Ljava/lang/Object;

    .line 28
    .line 29
    iput-object p2, v0, Lqn/s;->h:Ljava/lang/Object;

    .line 30
    .line 31
    iput-object v0, p0, Lqp/h;->d:Lqn/s;

    .line 32
    .line 33
    const/4 p1, 0x1

    .line 34
    invoke-virtual {p0, p1}, Landroid/view/View;->setClickable(Z)V

    .line 35
    .line 36
    .line 37
    return-void
.end method


# virtual methods
.method public final a()V
    .locals 2

    .line 1
    iget-object p0, p0, Lqp/h;->d:Lqn/s;

    .line 2
    .line 3
    iget-object p0, p0, Lqn/s;->a:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast p0, Lil/g;

    .line 6
    .line 7
    if-eqz p0, :cond_0

    .line 8
    .line 9
    :try_start_0
    iget-object p0, p0, Lil/g;->f:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast p0, Lrp/g;

    .line 12
    .line 13
    invoke-virtual {p0}, Lbp/a;->S()Landroid/os/Parcel;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    const/4 v1, 0x6

    .line 18
    invoke-virtual {p0, v0, v1}, Lbp/a;->U(Landroid/os/Parcel;I)V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 19
    .line 20
    .line 21
    return-void

    .line 22
    :catch_0
    move-exception p0

    .line 23
    new-instance v0, La8/r0;

    .line 24
    .line 25
    invoke-direct {v0, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 26
    .line 27
    .line 28
    throw v0

    .line 29
    :cond_0
    return-void
.end method
