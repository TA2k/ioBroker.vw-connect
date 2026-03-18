.class public final synthetic Ltechnology/cariad/cat/genx/bluetooth/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/io/Closeable;

.field public final synthetic f:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/io/Closeable;Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p3, p0, Ltechnology/cariad/cat/genx/bluetooth/b;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ltechnology/cariad/cat/genx/bluetooth/b;->e:Ljava/io/Closeable;

    .line 4
    .line 5
    iput-object p2, p0, Ltechnology/cariad/cat/genx/bluetooth/b;->f:Ljava/lang/Object;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Ltechnology/cariad/cat/genx/bluetooth/b;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/b;->e:Ljava/io/Closeable;

    .line 7
    .line 8
    check-cast v0, Ltechnology/cariad/cat/genx/ClientManagerDelegate;

    .line 9
    .line 10
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/b;->f:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;

    .line 13
    .line 14
    invoke-static {v0, p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->g(Ltechnology/cariad/cat/genx/ClientManagerDelegate;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;)Llx0/b0;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    return-object p0

    .line 19
    :pswitch_0
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/b;->e:Ljava/io/Closeable;

    .line 20
    .line 21
    check-cast v0, Ltechnology/cariad/cat/genx/ClientDelegate;

    .line 22
    .line 23
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/b;->f:Ljava/lang/Object;

    .line 24
    .line 25
    check-cast p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;

    .line 26
    .line 27
    invoke-static {v0, p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->g(Ltechnology/cariad/cat/genx/ClientDelegate;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)Llx0/b0;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    return-object p0

    .line 32
    :pswitch_1
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/b;->e:Ljava/io/Closeable;

    .line 33
    .line 34
    check-cast v0, Ltechnology/cariad/cat/genx/ClientDelegate;

    .line 35
    .line 36
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/b;->f:Ljava/lang/Object;

    .line 37
    .line 38
    check-cast p0, Ltechnology/cariad/cat/genx/TypedFrame;

    .line 39
    .line 40
    invoke-static {v0, p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->N0(Ltechnology/cariad/cat/genx/ClientDelegate;Ltechnology/cariad/cat/genx/TypedFrame;)Llx0/b0;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    return-object p0

    .line 45
    :pswitch_2
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/b;->e:Ljava/io/Closeable;

    .line 46
    .line 47
    check-cast v0, Ltechnology/cariad/cat/genx/TypedFrame;

    .line 48
    .line 49
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/b;->f:Ljava/lang/Object;

    .line 50
    .line 51
    check-cast p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;

    .line 52
    .line 53
    invoke-static {v0, p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->J0(Ltechnology/cariad/cat/genx/TypedFrame;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)Ljava/lang/String;

    .line 54
    .line 55
    .line 56
    move-result-object p0

    .line 57
    return-object p0

    .line 58
    :pswitch_3
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/b;->e:Ljava/io/Closeable;

    .line 59
    .line 60
    check-cast v0, Ltechnology/cariad/cat/genx/ClientDelegate;

    .line 61
    .line 62
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/b;->f:Ljava/lang/Object;

    .line 63
    .line 64
    check-cast p0, Ltechnology/cariad/cat/genx/Channel;

    .line 65
    .line 66
    invoke-static {v0, p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->B0(Ltechnology/cariad/cat/genx/ClientDelegate;Ltechnology/cariad/cat/genx/Channel;)Llx0/b0;

    .line 67
    .line 68
    .line 69
    move-result-object p0

    .line 70
    return-object p0

    .line 71
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
