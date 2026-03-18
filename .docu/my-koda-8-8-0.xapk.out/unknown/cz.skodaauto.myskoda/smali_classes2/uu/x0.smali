.class public final Luu/x0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Luu/s0;


# instance fields
.field public final a:Lqp/g;

.field public b:Lt4/c;

.field public c:Lt4/m;

.field public d:Luu/g;


# direct methods
.method public constructor <init>(Lqp/g;Luu/g;Ljava/lang/String;Lt4/c;Lt4/m;Lk1/z0;)V
    .locals 1

    .line 1
    const-string v0, "map"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "cameraPositionState"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "density"

    .line 12
    .line 13
    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    const-string v0, "layoutDirection"

    .line 17
    .line 18
    invoke-static {p5, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    const-string v0, "contentPadding"

    .line 22
    .line 23
    invoke-static {p6, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 27
    .line 28
    .line 29
    iput-object p1, p0, Luu/x0;->a:Lqp/g;

    .line 30
    .line 31
    iput-object p4, p0, Luu/x0;->b:Lt4/c;

    .line 32
    .line 33
    iput-object p5, p0, Luu/x0;->c:Lt4/m;

    .line 34
    .line 35
    invoke-static {p0, p1, p6}, Luu/d1;->a(Luu/x0;Lqp/g;Lk1/z0;)V

    .line 36
    .line 37
    .line 38
    invoke-virtual {p2, p1}, Luu/g;->f(Lqp/g;)V

    .line 39
    .line 40
    .line 41
    if-eqz p3, :cond_0

    .line 42
    .line 43
    invoke-virtual {p1, p3}, Lqp/g;->f(Ljava/lang/String;)V

    .line 44
    .line 45
    .line 46
    :cond_0
    iput-object p2, p0, Luu/x0;->d:Luu/g;

    .line 47
    .line 48
    return-void
.end method


# virtual methods
.method public final a()V
    .locals 4

    .line 1
    new-instance v0, Luu/v0;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Luu/v0;-><init>(Luu/x0;)V

    .line 4
    .line 5
    .line 6
    iget-object v1, p0, Luu/x0;->a:Lqp/g;

    .line 7
    .line 8
    iget-object v2, v1, Lqp/g;->a:Lrp/f;

    .line 9
    .line 10
    iget-object v1, v1, Lqp/g;->a:Lrp/f;

    .line 11
    .line 12
    :try_start_0
    new-instance v3, Lqp/j;

    .line 13
    .line 14
    invoke-direct {v3, v0}, Lqp/j;-><init>(Luu/v0;)V

    .line 15
    .line 16
    .line 17
    invoke-virtual {v2}, Lbp/a;->S()Landroid/os/Parcel;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    invoke-static {v0, v3}, Lhp/j;->d(Landroid/os/Parcel;Landroid/os/IInterface;)V

    .line 22
    .line 23
    .line 24
    const/16 v3, 0x63

    .line 25
    .line 26
    invoke-virtual {v2, v0, v3}, Lbp/a;->U(Landroid/os/Parcel;I)V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_3

    .line 27
    .line 28
    .line 29
    new-instance v0, Luu/w0;

    .line 30
    .line 31
    invoke-direct {v0, p0}, Luu/w0;-><init>(Luu/x0;)V

    .line 32
    .line 33
    .line 34
    :try_start_1
    new-instance v2, Lqp/j;

    .line 35
    .line 36
    invoke-direct {v2, v0}, Lqp/j;-><init>(Luu/w0;)V

    .line 37
    .line 38
    .line 39
    invoke-virtual {v1}, Lbp/a;->S()Landroid/os/Parcel;

    .line 40
    .line 41
    .line 42
    move-result-object v0

    .line 43
    invoke-static {v0, v2}, Lhp/j;->d(Landroid/os/Parcel;Landroid/os/IInterface;)V

    .line 44
    .line 45
    .line 46
    const/16 v2, 0x62

    .line 47
    .line 48
    invoke-virtual {v1, v0, v2}, Lbp/a;->U(Landroid/os/Parcel;I)V
    :try_end_1
    .catch Landroid/os/RemoteException; {:try_start_1 .. :try_end_1} :catch_2

    .line 49
    .line 50
    .line 51
    new-instance v0, Luu/w0;

    .line 52
    .line 53
    invoke-direct {v0, p0}, Luu/w0;-><init>(Luu/x0;)V

    .line 54
    .line 55
    .line 56
    :try_start_2
    new-instance v2, Lqp/j;

    .line 57
    .line 58
    const/4 v3, 0x0

    .line 59
    invoke-direct {v2, v0, v3}, Lqp/j;-><init>(Luu/w0;B)V

    .line 60
    .line 61
    .line 62
    invoke-virtual {v1}, Lbp/a;->S()Landroid/os/Parcel;

    .line 63
    .line 64
    .line 65
    move-result-object v0

    .line 66
    invoke-static {v0, v2}, Lhp/j;->d(Landroid/os/Parcel;Landroid/os/IInterface;)V

    .line 67
    .line 68
    .line 69
    const/16 v2, 0x60

    .line 70
    .line 71
    invoke-virtual {v1, v0, v2}, Lbp/a;->U(Landroid/os/Parcel;I)V
    :try_end_2
    .catch Landroid/os/RemoteException; {:try_start_2 .. :try_end_2} :catch_1

    .line 72
    .line 73
    .line 74
    new-instance v0, Luu/w0;

    .line 75
    .line 76
    invoke-direct {v0, p0}, Luu/w0;-><init>(Luu/x0;)V

    .line 77
    .line 78
    .line 79
    :try_start_3
    new-instance p0, Lqp/j;

    .line 80
    .line 81
    const/4 v2, 0x0

    .line 82
    invoke-direct {p0, v0, v2}, Lqp/j;-><init>(Luu/w0;C)V

    .line 83
    .line 84
    .line 85
    invoke-virtual {v1}, Lbp/a;->S()Landroid/os/Parcel;

    .line 86
    .line 87
    .line 88
    move-result-object v0

    .line 89
    invoke-static {v0, p0}, Lhp/j;->d(Landroid/os/Parcel;Landroid/os/IInterface;)V

    .line 90
    .line 91
    .line 92
    const/16 p0, 0x61

    .line 93
    .line 94
    invoke-virtual {v1, v0, p0}, Lbp/a;->U(Landroid/os/Parcel;I)V
    :try_end_3
    .catch Landroid/os/RemoteException; {:try_start_3 .. :try_end_3} :catch_0

    .line 95
    .line 96
    .line 97
    return-void

    .line 98
    :catch_0
    move-exception p0

    .line 99
    new-instance v0, La8/r0;

    .line 100
    .line 101
    invoke-direct {v0, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 102
    .line 103
    .line 104
    throw v0

    .line 105
    :catch_1
    move-exception p0

    .line 106
    new-instance v0, La8/r0;

    .line 107
    .line 108
    invoke-direct {v0, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 109
    .line 110
    .line 111
    throw v0

    .line 112
    :catch_2
    move-exception p0

    .line 113
    new-instance v0, La8/r0;

    .line 114
    .line 115
    invoke-direct {v0, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 116
    .line 117
    .line 118
    throw v0

    .line 119
    :catch_3
    move-exception p0

    .line 120
    new-instance v0, La8/r0;

    .line 121
    .line 122
    invoke-direct {v0, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 123
    .line 124
    .line 125
    throw v0
.end method

.method public final b()V
    .locals 1

    .line 1
    iget-object p0, p0, Luu/x0;->d:Luu/g;

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    invoke-virtual {p0, v0}, Luu/g;->f(Lqp/g;)V

    .line 5
    .line 6
    .line 7
    return-void
.end method

.method public final d()V
    .locals 1

    .line 1
    iget-object p0, p0, Luu/x0;->d:Luu/g;

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    invoke-virtual {p0, v0}, Luu/g;->f(Lqp/g;)V

    .line 5
    .line 6
    .line 7
    return-void
.end method
