.class public final synthetic Ltechnology/cariad/cat/genx/bluetooth/o;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyz0/b;
.implements Lyz0/d;
.implements Lyz0/c;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;


# direct methods
.method public synthetic constructor <init>(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;I)V
    .locals 0

    .line 1
    iput p2, p0, Ltechnology/cariad/cat/genx/bluetooth/o;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ltechnology/cariad/cat/genx/bluetooth/o;->e:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public a(Landroid/bluetooth/BluetoothDevice;Lzz0/a;)V
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/o;->e:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;

    .line 2
    .line 3
    invoke-static {p0, p1, p2}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->h(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;Landroid/bluetooth/BluetoothDevice;Lzz0/a;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public b(ILandroid/bluetooth/BluetoothDevice;)V
    .locals 1

    .line 1
    iget v0, p0, Ltechnology/cariad/cat/genx/bluetooth/o;->d:I

    .line 2
    .line 3
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/o;->e:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    invoke-static {p0, p2, p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->y0(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;Landroid/bluetooth/BluetoothDevice;I)V

    .line 9
    .line 10
    .line 11
    return-void

    .line 12
    :pswitch_0
    invoke-static {p0, p2, p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->H0(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;Landroid/bluetooth/BluetoothDevice;I)V

    .line 13
    .line 14
    .line 15
    return-void

    .line 16
    nop

    .line 17
    :pswitch_data_0
    .packed-switch 0x2
        :pswitch_0
    .end packed-switch
.end method

.method public e(Landroid/bluetooth/BluetoothDevice;)V
    .locals 1

    .line 1
    iget v0, p0, Ltechnology/cariad/cat/genx/bluetooth/o;->d:I

    .line 2
    .line 3
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/o;->e:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    invoke-static {p0, p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->E0(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;Landroid/bluetooth/BluetoothDevice;)V

    .line 9
    .line 10
    .line 11
    return-void

    .line 12
    :pswitch_0
    invoke-static {p0, p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->C0(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;Landroid/bluetooth/BluetoothDevice;)V

    .line 13
    .line 14
    .line 15
    return-void

    .line 16
    nop

    .line 17
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method
