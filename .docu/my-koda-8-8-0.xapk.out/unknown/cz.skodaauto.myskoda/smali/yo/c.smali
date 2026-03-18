.class public final Lyo/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyo/f;


# instance fields
.field public final synthetic a:Landroid/os/Bundle;

.field public final synthetic b:Lqn/s;


# direct methods
.method public constructor <init>(Lqn/s;Landroid/os/Bundle;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lyo/c;->b:Lqn/s;

    .line 5
    .line 6
    iput-object p2, p0, Lyo/c;->a:Landroid/os/Bundle;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a()I
    .locals 0

    .line 1
    const/4 p0, 0x1

    .line 2
    return p0
.end method

.method public final b()V
    .locals 5

    .line 1
    iget-object v0, p0, Lyo/c;->b:Lqn/s;

    .line 2
    .line 3
    iget-object v0, v0, Lqn/s;->a:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast v0, Lil/g;

    .line 6
    .line 7
    iget-object p0, p0, Lyo/c;->a:Landroid/os/Bundle;

    .line 8
    .line 9
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 10
    .line 11
    .line 12
    :try_start_0
    new-instance v1, Landroid/os/Bundle;

    .line 13
    .line 14
    invoke-direct {v1}, Landroid/os/Bundle;-><init>()V

    .line 15
    .line 16
    .line 17
    invoke-static {p0, v1}, Lrp/d;->f(Landroid/os/Bundle;Landroid/os/Bundle;)V

    .line 18
    .line 19
    .line 20
    iget-object v2, v0, Lil/g;->f:Ljava/lang/Object;

    .line 21
    .line 22
    check-cast v2, Lrp/g;

    .line 23
    .line 24
    invoke-virtual {v2}, Lbp/a;->S()Landroid/os/Parcel;

    .line 25
    .line 26
    .line 27
    move-result-object v3

    .line 28
    invoke-static {v3, v1}, Lhp/j;->c(Landroid/os/Parcel;Landroid/os/Parcelable;)V

    .line 29
    .line 30
    .line 31
    const/4 v4, 0x2

    .line 32
    invoke-virtual {v2, v3, v4}, Lbp/a;->U(Landroid/os/Parcel;I)V

    .line 33
    .line 34
    .line 35
    invoke-static {v1, p0}, Lrp/d;->f(Landroid/os/Bundle;Landroid/os/Bundle;)V

    .line 36
    .line 37
    .line 38
    invoke-virtual {v2}, Lbp/a;->S()Landroid/os/Parcel;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    const/16 v1, 0x8

    .line 43
    .line 44
    invoke-virtual {v2, p0, v1}, Lbp/a;->c(Landroid/os/Parcel;I)Landroid/os/Parcel;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    invoke-virtual {p0}, Landroid/os/Parcel;->readStrongBinder()Landroid/os/IBinder;

    .line 49
    .line 50
    .line 51
    move-result-object v1

    .line 52
    invoke-static {v1}, Lyo/b;->T(Landroid/os/IBinder;)Lyo/a;

    .line 53
    .line 54
    .line 55
    move-result-object v1

    .line 56
    invoke-virtual {p0}, Landroid/os/Parcel;->recycle()V

    .line 57
    .line 58
    .line 59
    invoke-static {v1}, Lyo/b;->U(Lyo/a;)Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    check-cast p0, Landroid/view/View;

    .line 64
    .line 65
    iput-object p0, v0, Lil/g;->g:Ljava/lang/Object;

    .line 66
    .line 67
    iget-object p0, v0, Lil/g;->e:Ljava/lang/Object;

    .line 68
    .line 69
    check-cast p0, Landroid/view/ViewGroup;

    .line 70
    .line 71
    invoke-virtual {p0}, Landroid/view/ViewGroup;->removeAllViews()V

    .line 72
    .line 73
    .line 74
    iget-object v0, v0, Lil/g;->g:Ljava/lang/Object;

    .line 75
    .line 76
    check-cast v0, Landroid/view/View;

    .line 77
    .line 78
    invoke-virtual {p0, v0}, Landroid/view/ViewGroup;->addView(Landroid/view/View;)V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 79
    .line 80
    .line 81
    return-void

    .line 82
    :catch_0
    move-exception p0

    .line 83
    new-instance v0, La8/r0;

    .line 84
    .line 85
    invoke-direct {v0, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 86
    .line 87
    .line 88
    throw v0
.end method
