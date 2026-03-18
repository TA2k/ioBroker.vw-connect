.class public final synthetic Ltechnology/cariad/cat/genx/bluetooth/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:I

.field public final synthetic f:Landroid/os/Parcelable;


# direct methods
.method public synthetic constructor <init>(IILandroid/bluetooth/BluetoothDevice;)V
    .locals 0

    .line 1
    iput p2, p0, Ltechnology/cariad/cat/genx/bluetooth/i;->d:I

    iput-object p3, p0, Ltechnology/cariad/cat/genx/bluetooth/i;->f:Landroid/os/Parcelable;

    iput p1, p0, Ltechnology/cariad/cat/genx/bluetooth/i;->e:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(ILandroid/os/Parcelable;I)V
    .locals 0

    .line 2
    iput p3, p0, Ltechnology/cariad/cat/genx/bluetooth/i;->d:I

    iput p1, p0, Ltechnology/cariad/cat/genx/bluetooth/i;->e:I

    iput-object p2, p0, Ltechnology/cariad/cat/genx/bluetooth/i;->f:Landroid/os/Parcelable;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Ltechnology/cariad/cat/genx/bluetooth/i;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/i;->f:Landroid/os/Parcelable;

    .line 7
    .line 8
    check-cast v0, Landroid/bluetooth/le/ScanResult;

    .line 9
    .line 10
    iget p0, p0, Ltechnology/cariad/cat/genx/bluetooth/i;->e:I

    .line 11
    .line 12
    invoke-static {p0, v0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$scanCallback$1;->c(ILandroid/bluetooth/le/ScanResult;)Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    return-object p0

    .line 17
    :pswitch_0
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/i;->f:Landroid/os/Parcelable;

    .line 18
    .line 19
    check-cast v0, Landroid/bluetooth/BluetoothDevice;

    .line 20
    .line 21
    iget p0, p0, Ltechnology/cariad/cat/genx/bluetooth/i;->e:I

    .line 22
    .line 23
    invoke-static {p0, v0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$2$1;->b(ILandroid/bluetooth/BluetoothDevice;)Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    return-object p0

    .line 28
    :pswitch_1
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/i;->f:Landroid/os/Parcelable;

    .line 29
    .line 30
    check-cast v0, Landroid/bluetooth/BluetoothDevice;

    .line 31
    .line 32
    iget p0, p0, Ltechnology/cariad/cat/genx/bluetooth/i;->e:I

    .line 33
    .line 34
    invoke-static {p0, v0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$2$1;->c(ILandroid/bluetooth/BluetoothDevice;)Ljava/lang/String;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    return-object p0

    .line 39
    :pswitch_2
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/i;->f:Landroid/os/Parcelable;

    .line 40
    .line 41
    check-cast v0, Landroid/bluetooth/BluetoothDevice;

    .line 42
    .line 43
    iget p0, p0, Ltechnology/cariad/cat/genx/bluetooth/i;->e:I

    .line 44
    .line 45
    invoke-static {p0, v0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->f(ILandroid/bluetooth/BluetoothDevice;)Ljava/lang/String;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    return-object p0

    .line 50
    :pswitch_3
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/i;->f:Landroid/os/Parcelable;

    .line 51
    .line 52
    check-cast v0, Landroid/bluetooth/BluetoothDevice;

    .line 53
    .line 54
    iget p0, p0, Ltechnology/cariad/cat/genx/bluetooth/i;->e:I

    .line 55
    .line 56
    invoke-static {p0, v0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->W(ILandroid/bluetooth/BluetoothDevice;)Ljava/lang/String;

    .line 57
    .line 58
    .line 59
    move-result-object p0

    .line 60
    return-object p0

    .line 61
    :pswitch_4
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/i;->f:Landroid/os/Parcelable;

    .line 62
    .line 63
    check-cast v0, Landroid/bluetooth/BluetoothDevice;

    .line 64
    .line 65
    iget p0, p0, Ltechnology/cariad/cat/genx/bluetooth/i;->e:I

    .line 66
    .line 67
    invoke-static {p0, v0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->o(ILandroid/bluetooth/BluetoothDevice;)Ljava/lang/String;

    .line 68
    .line 69
    .line 70
    move-result-object p0

    .line 71
    return-object p0

    .line 72
    :pswitch_5
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/i;->f:Landroid/os/Parcelable;

    .line 73
    .line 74
    check-cast v0, Landroid/bluetooth/BluetoothDevice;

    .line 75
    .line 76
    iget p0, p0, Ltechnology/cariad/cat/genx/bluetooth/i;->e:I

    .line 77
    .line 78
    invoke-static {p0, v0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->u(ILandroid/bluetooth/BluetoothDevice;)Ljava/lang/String;

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    return-object p0

    .line 83
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
