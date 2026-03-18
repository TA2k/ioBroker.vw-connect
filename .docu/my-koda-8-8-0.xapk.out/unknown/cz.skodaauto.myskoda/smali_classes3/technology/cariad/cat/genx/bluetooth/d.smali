.class public final synthetic Ltechnology/cariad/cat/genx/bluetooth/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, Ltechnology/cariad/cat/genx/bluetooth/d;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ltechnology/cariad/cat/genx/bluetooth/d;->e:Ljava/lang/Object;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Ltechnology/cariad/cat/genx/bluetooth/d;->d:I

    .line 2
    .line 3
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/d;->e:Ljava/lang/Object;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    check-cast p0, Ljava/lang/String;

    .line 9
    .line 10
    invoke-static {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->k0(Ljava/lang/String;)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    return-object p0

    .line 15
    :pswitch_0
    check-cast p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;

    .line 16
    .line 17
    invoke-static {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->q0(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;)Llx0/b0;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    return-object p0

    .line 22
    :pswitch_1
    check-cast p0, Ltechnology/cariad/cat/genx/ClientDelegate;

    .line 23
    .line 24
    invoke-static {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->h(Ltechnology/cariad/cat/genx/ClientDelegate;)Llx0/b0;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    return-object p0

    .line 29
    :pswitch_2
    check-cast p0, Ltechnology/cariad/cat/genx/Channel;

    .line 30
    .line 31
    invoke-static {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->l0(Ltechnology/cariad/cat/genx/Channel;)Ljava/lang/String;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    nop

    .line 37
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
