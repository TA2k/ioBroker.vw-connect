.class public final Lno/nordicsemi/android/ble/x;
.super Lno/nordicsemi/android/ble/p0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final p:Landroid/bluetooth/BluetoothDevice;

.field public q:I

.field public r:I

.field public s:I

.field public t:I

.field public u:Z

.field public final v:Z


# direct methods
.method public constructor <init>(Landroid/bluetooth/BluetoothDevice;)V
    .locals 1

    .line 1
    const/4 v0, 0x2

    .line 2
    invoke-direct {p0, v0}, Lno/nordicsemi/android/ble/i0;-><init>(I)V

    .line 3
    .line 4
    .line 5
    const/4 v0, 0x0

    .line 6
    iput v0, p0, Lno/nordicsemi/android/ble/x;->r:I

    .line 7
    .line 8
    iput v0, p0, Lno/nordicsemi/android/ble/x;->s:I

    .line 9
    .line 10
    iput v0, p0, Lno/nordicsemi/android/ble/x;->t:I

    .line 11
    .line 12
    iput-boolean v0, p0, Lno/nordicsemi/android/ble/x;->u:Z

    .line 13
    .line 14
    const/4 v0, 0x1

    .line 15
    iput-boolean v0, p0, Lno/nordicsemi/android/ble/x;->v:Z

    .line 16
    .line 17
    iput-object p1, p0, Lno/nordicsemi/android/ble/x;->p:Landroid/bluetooth/BluetoothDevice;

    .line 18
    .line 19
    iput v0, p0, Lno/nordicsemi/android/ble/x;->q:I

    .line 20
    .line 21
    return-void
.end method


# virtual methods
.method public final e(Lno/nordicsemi/android/ble/d;)Lno/nordicsemi/android/ble/i0;
    .locals 0

    .line 1
    invoke-virtual {p0, p1}, Lno/nordicsemi/android/ble/p0;->g(Lno/nordicsemi/android/ble/d;)V

    .line 2
    .line 3
    .line 4
    return-object p0
.end method
