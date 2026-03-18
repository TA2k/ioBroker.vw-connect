.class public final synthetic Ltechnology/cariad/cat/genx/bluetooth/q;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic a:I

.field public final synthetic b:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;

.field public final synthetic c:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;


# direct methods
.method public synthetic constructor <init>(ILtechnology/cariad/cat/genx/bluetooth/BluetoothClient;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Ltechnology/cariad/cat/genx/bluetooth/q;->a:I

    .line 5
    .line 6
    iput-object p2, p0, Ltechnology/cariad/cat/genx/bluetooth/q;->b:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;

    .line 7
    .line 8
    iput-object p3, p0, Ltechnology/cariad/cat/genx/bluetooth/q;->c:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final a(ILandroid/bluetooth/BluetoothDevice;)V
    .locals 2

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/q;->b:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;

    .line 2
    .line 3
    iget-object v1, p0, Ltechnology/cariad/cat/genx/bluetooth/q;->c:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;

    .line 4
    .line 5
    iget p0, p0, Ltechnology/cariad/cat/genx/bluetooth/q;->a:I

    .line 6
    .line 7
    invoke-static {p0, v0, v1, p2, p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->x(ILtechnology/cariad/cat/genx/bluetooth/BluetoothClient;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;Landroid/bluetooth/BluetoothDevice;I)V

    .line 8
    .line 9
    .line 10
    return-void
.end method
