.class public final synthetic Ltechnology/cariad/cat/genx/bluetooth/r;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:I

.field public final synthetic f:Landroid/bluetooth/BluetoothDevice;


# direct methods
.method public synthetic constructor <init>(IILandroid/bluetooth/BluetoothDevice;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Ltechnology/cariad/cat/genx/bluetooth/r;->d:I

    .line 5
    .line 6
    iput p2, p0, Ltechnology/cariad/cat/genx/bluetooth/r;->e:I

    .line 7
    .line 8
    iput-object p3, p0, Ltechnology/cariad/cat/genx/bluetooth/r;->f:Landroid/bluetooth/BluetoothDevice;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Ltechnology/cariad/cat/genx/bluetooth/r;->e:I

    .line 2
    .line 3
    iget-object v1, p0, Ltechnology/cariad/cat/genx/bluetooth/r;->f:Landroid/bluetooth/BluetoothDevice;

    .line 4
    .line 5
    iget p0, p0, Ltechnology/cariad/cat/genx/bluetooth/r;->d:I

    .line 6
    .line 7
    invoke-static {p0, v0, v1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->j(IILandroid/bluetooth/BluetoothDevice;)Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method
