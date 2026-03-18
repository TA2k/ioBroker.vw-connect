.class public final synthetic Ltechnology/cariad/cat/genx/bluetooth/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyz0/c;
.implements Lyz0/d;


# instance fields
.field public final synthetic d:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;

.field public final synthetic e:Ltechnology/cariad/cat/genx/TypedFrame;

.field public final synthetic f:Ljava/util/UUID;


# direct methods
.method public synthetic constructor <init>(Ltechnology/cariad/cat/genx/TypedFrame;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;Ljava/util/UUID;)V
    .locals 0

    .line 1
    iput-object p2, p0, Ltechnology/cariad/cat/genx/bluetooth/h;->d:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;

    .line 2
    .line 3
    iput-object p1, p0, Ltechnology/cariad/cat/genx/bluetooth/h;->e:Ltechnology/cariad/cat/genx/TypedFrame;

    .line 4
    .line 5
    iput-object p3, p0, Ltechnology/cariad/cat/genx/bluetooth/h;->f:Ljava/util/UUID;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public b(ILandroid/bluetooth/BluetoothDevice;)V
    .locals 2

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/h;->e:Ltechnology/cariad/cat/genx/TypedFrame;

    .line 2
    .line 3
    iget-object v1, p0, Ltechnology/cariad/cat/genx/bluetooth/h;->f:Ljava/util/UUID;

    .line 4
    .line 5
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/h;->d:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;

    .line 6
    .line 7
    invoke-static {p0, v0, v1, p2, p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->H(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;Ltechnology/cariad/cat/genx/TypedFrame;Ljava/util/UUID;Landroid/bluetooth/BluetoothDevice;I)V

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public e(Landroid/bluetooth/BluetoothDevice;)V
    .locals 2

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/h;->e:Ltechnology/cariad/cat/genx/TypedFrame;

    .line 2
    .line 3
    iget-object v1, p0, Ltechnology/cariad/cat/genx/bluetooth/h;->f:Ljava/util/UUID;

    .line 4
    .line 5
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/h;->d:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;

    .line 6
    .line 7
    invoke-static {p0, v0, v1, p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->I0(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;Ltechnology/cariad/cat/genx/TypedFrame;Ljava/util/UUID;Landroid/bluetooth/BluetoothDevice;)V

    .line 8
    .line 9
    .line 10
    return-void
.end method
