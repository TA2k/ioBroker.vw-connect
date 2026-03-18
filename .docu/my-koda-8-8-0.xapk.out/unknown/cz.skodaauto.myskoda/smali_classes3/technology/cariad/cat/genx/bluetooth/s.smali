.class public final synthetic Ltechnology/cariad/cat/genx/bluetooth/s;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;

.field public final synthetic f:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;


# direct methods
.method public synthetic constructor <init>(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    iput v0, p0, Ltechnology/cariad/cat/genx/bluetooth/s;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Ltechnology/cariad/cat/genx/bluetooth/s;->f:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;

    iput-object p2, p0, Ltechnology/cariad/cat/genx/bluetooth/s;->e:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;

    return-void
.end method

.method public synthetic constructor <init>(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;I)V
    .locals 0

    .line 2
    iput p3, p0, Ltechnology/cariad/cat/genx/bluetooth/s;->d:I

    iput-object p1, p0, Ltechnology/cariad/cat/genx/bluetooth/s;->e:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;

    iput-object p2, p0, Ltechnology/cariad/cat/genx/bluetooth/s;->f:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Ltechnology/cariad/cat/genx/bluetooth/s;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/s;->e:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;

    .line 7
    .line 8
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/s;->f:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;

    .line 9
    .line 10
    invoke-static {p0, v0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->W(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;)Llx0/b0;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    return-object p0

    .line 15
    :pswitch_0
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/s;->e:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;

    .line 16
    .line 17
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/s;->f:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;

    .line 18
    .line 19
    invoke-static {p0, v0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->f(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;)Llx0/b0;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    return-object p0

    .line 24
    :pswitch_1
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/s;->f:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;

    .line 25
    .line 26
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/s;->e:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;

    .line 27
    .line 28
    invoke-static {v0, p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->M(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;)Llx0/b0;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    return-object p0

    .line 33
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
