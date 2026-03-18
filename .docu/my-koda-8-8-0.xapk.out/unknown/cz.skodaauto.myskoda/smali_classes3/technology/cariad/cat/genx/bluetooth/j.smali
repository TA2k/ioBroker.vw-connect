.class public final synthetic Ltechnology/cariad/cat/genx/bluetooth/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/String;

.field public final synthetic f:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;I)V
    .locals 0

    .line 1
    iput p3, p0, Ltechnology/cariad/cat/genx/bluetooth/j;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ltechnology/cariad/cat/genx/bluetooth/j;->e:Ljava/lang/String;

    .line 4
    .line 5
    iput-object p2, p0, Ltechnology/cariad/cat/genx/bluetooth/j;->f:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;

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
    iget v0, p0, Ltechnology/cariad/cat/genx/bluetooth/j;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/j;->e:Ljava/lang/String;

    .line 7
    .line 8
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/j;->f:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;

    .line 9
    .line 10
    invoke-static {v0, p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->g(Ljava/lang/String;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    return-object p0

    .line 15
    :pswitch_0
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/j;->e:Ljava/lang/String;

    .line 16
    .line 17
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/j;->f:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;

    .line 18
    .line 19
    invoke-static {v0, p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->y(Ljava/lang/String;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    return-object p0

    .line 24
    :pswitch_1
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/j;->e:Ljava/lang/String;

    .line 25
    .line 26
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/j;->f:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;

    .line 27
    .line 28
    invoke-static {v0, p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->v(Ljava/lang/String;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    return-object p0

    .line 33
    :pswitch_2
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/j;->e:Ljava/lang/String;

    .line 34
    .line 35
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/j;->f:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;

    .line 36
    .line 37
    invoke-static {v0, p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->k(Ljava/lang/String;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)Ljava/lang/String;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    return-object p0

    .line 42
    :pswitch_3
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/j;->e:Ljava/lang/String;

    .line 43
    .line 44
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/j;->f:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;

    .line 45
    .line 46
    invoke-static {v0, p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->i(Ljava/lang/String;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)Ljava/lang/String;

    .line 47
    .line 48
    .line 49
    move-result-object p0

    .line 50
    return-object p0

    .line 51
    :pswitch_4
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/j;->e:Ljava/lang/String;

    .line 52
    .line 53
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/j;->f:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;

    .line 54
    .line 55
    invoke-static {v0, p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->c(Ljava/lang/String;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)Ljava/lang/String;

    .line 56
    .line 57
    .line 58
    move-result-object p0

    .line 59
    return-object p0

    .line 60
    nop

    .line 61
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
