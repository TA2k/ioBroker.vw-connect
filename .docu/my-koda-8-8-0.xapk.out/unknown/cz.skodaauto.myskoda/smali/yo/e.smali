.class public final Lyo/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyo/f;


# instance fields
.field public final synthetic a:I

.field public final synthetic b:Lqn/s;


# direct methods
.method public synthetic constructor <init>(Lqn/s;I)V
    .locals 0

    .line 1
    iput p2, p0, Lyo/e;->a:I

    .line 2
    .line 3
    iput-object p1, p0, Lyo/e;->b:Lqn/s;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a()I
    .locals 0

    .line 1
    iget p0, p0, Lyo/e;->a:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    const/4 p0, 0x5

    .line 7
    return p0

    .line 8
    :pswitch_0
    const/4 p0, 0x4

    .line 9
    return p0

    .line 10
    nop

    .line 11
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final b()V
    .locals 2

    .line 1
    iget v0, p0, Lyo/e;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lyo/e;->b:Lqn/s;

    .line 7
    .line 8
    iget-object p0, p0, Lqn/s;->a:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast p0, Lil/g;

    .line 11
    .line 12
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 13
    .line 14
    .line 15
    :try_start_0
    iget-object p0, p0, Lil/g;->f:Ljava/lang/Object;

    .line 16
    .line 17
    check-cast p0, Lrp/g;

    .line 18
    .line 19
    invoke-virtual {p0}, Lbp/a;->S()Landroid/os/Parcel;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    const/4 v1, 0x3

    .line 24
    invoke-virtual {p0, v0, v1}, Lbp/a;->U(Landroid/os/Parcel;I)V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 25
    .line 26
    .line 27
    return-void

    .line 28
    :catch_0
    move-exception p0

    .line 29
    new-instance v0, La8/r0;

    .line 30
    .line 31
    invoke-direct {v0, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 32
    .line 33
    .line 34
    throw v0

    .line 35
    :pswitch_0
    iget-object p0, p0, Lyo/e;->b:Lqn/s;

    .line 36
    .line 37
    iget-object p0, p0, Lqn/s;->a:Ljava/lang/Object;

    .line 38
    .line 39
    check-cast p0, Lil/g;

    .line 40
    .line 41
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 42
    .line 43
    .line 44
    :try_start_1
    iget-object p0, p0, Lil/g;->f:Ljava/lang/Object;

    .line 45
    .line 46
    check-cast p0, Lrp/g;

    .line 47
    .line 48
    invoke-virtual {p0}, Lbp/a;->S()Landroid/os/Parcel;

    .line 49
    .line 50
    .line 51
    move-result-object v0

    .line 52
    const/16 v1, 0xc

    .line 53
    .line 54
    invoke-virtual {p0, v0, v1}, Lbp/a;->U(Landroid/os/Parcel;I)V
    :try_end_1
    .catch Landroid/os/RemoteException; {:try_start_1 .. :try_end_1} :catch_1

    .line 55
    .line 56
    .line 57
    return-void

    .line 58
    :catch_1
    move-exception p0

    .line 59
    new-instance v0, La8/r0;

    .line 60
    .line 61
    invoke-direct {v0, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 62
    .line 63
    .line 64
    throw v0

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
