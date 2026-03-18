.class public final synthetic Ltechnology/cariad/cat/genx/bluetooth/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Landroid/bluetooth/BluetoothDevice;


# direct methods
.method public synthetic constructor <init>(ILandroid/bluetooth/BluetoothDevice;)V
    .locals 0

    .line 1
    iput p1, p0, Ltechnology/cariad/cat/genx/bluetooth/c;->d:I

    .line 2
    .line 3
    iput-object p2, p0, Ltechnology/cariad/cat/genx/bluetooth/c;->e:Landroid/bluetooth/BluetoothDevice;

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
    iget v0, p0, Ltechnology/cariad/cat/genx/bluetooth/c;->d:I

    .line 2
    .line 3
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/c;->e:Landroid/bluetooth/BluetoothDevice;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    invoke-static {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$scanCallback$1;->b(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    return-object p0

    .line 13
    :pswitch_0
    invoke-static {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$scanCallback$1;->h(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0

    .line 18
    :pswitch_1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$scanCallback$1;->a(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_2
    invoke-static {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$scanCallback$1;->g(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    return-object p0

    .line 28
    :pswitch_3
    invoke-static {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->k(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    return-object p0

    .line 33
    :pswitch_4
    invoke-static {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->U(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    return-object p0

    .line 38
    :pswitch_5
    invoke-static {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$2$1;->d(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    return-object p0

    .line 43
    :pswitch_6
    invoke-static {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$2$1;->f(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    return-object p0

    .line 48
    :pswitch_7
    invoke-static {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$2$1;->a(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    return-object p0

    .line 53
    :pswitch_8
    invoke-static {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$2$1;->e(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;

    .line 54
    .line 55
    .line 56
    move-result-object p0

    .line 57
    return-object p0

    .line 58
    :pswitch_9
    invoke-static {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->e0(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;

    .line 59
    .line 60
    .line 61
    move-result-object p0

    .line 62
    return-object p0

    .line 63
    :pswitch_a
    invoke-static {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->q(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;

    .line 64
    .line 65
    .line 66
    move-result-object p0

    .line 67
    return-object p0

    .line 68
    nop

    .line 69
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
