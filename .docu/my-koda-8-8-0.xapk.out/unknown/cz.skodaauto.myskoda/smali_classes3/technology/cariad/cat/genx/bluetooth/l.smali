.class public final synthetic Ltechnology/cariad/cat/genx/bluetooth/l;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyz0/b;
.implements Lyz0/c;


# instance fields
.field public final synthetic d:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;

.field public final synthetic e:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput-object p1, p0, Ltechnology/cariad/cat/genx/bluetooth/l;->d:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;

    .line 2
    .line 3
    iput-object p2, p0, Ltechnology/cariad/cat/genx/bluetooth/l;->e:Ljava/lang/Object;

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
    .locals 1

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/l;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;

    .line 4
    .line 5
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/l;->d:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;

    .line 6
    .line 7
    invoke-static {p0, v0, p1, p2}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->a(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;Landroid/bluetooth/BluetoothDevice;Lzz0/a;)V

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public b(ILandroid/bluetooth/BluetoothDevice;)V
    .locals 1

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/l;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ltechnology/cariad/cat/genx/Channel;

    .line 4
    .line 5
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/l;->d:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;

    .line 6
    .line 7
    invoke-static {p0, v0, p2, p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->j(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;Ltechnology/cariad/cat/genx/Channel;Landroid/bluetooth/BluetoothDevice;I)V

    .line 8
    .line 9
    .line 10
    return-void
.end method
