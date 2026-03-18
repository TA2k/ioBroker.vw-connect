.class public abstract Lno/nordicsemi/android/ble/i0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final synthetic l:I


# instance fields
.field public a:Lno/nordicsemi/android/ble/d;

.field public b:Lno/nordicsemi/android/ble/d;

.field public final c:I

.field public final d:Landroid/bluetooth/BluetoothGattCharacteristic;

.field public final e:Landroid/bluetooth/BluetoothGattDescriptor;

.field public f:Lno/nordicsemi/android/ble/b;

.field public g:Lyz0/d;

.field public h:Lyz0/c;

.field public i:Z

.field public j:Z

.field public k:Z


# direct methods
.method public constructor <init>(I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput p1, p0, Lno/nordicsemi/android/ble/i0;->c:I

    const/4 p1, 0x0

    .line 3
    iput-object p1, p0, Lno/nordicsemi/android/ble/i0;->d:Landroid/bluetooth/BluetoothGattCharacteristic;

    .line 4
    iput-object p1, p0, Lno/nordicsemi/android/ble/i0;->e:Landroid/bluetooth/BluetoothGattDescriptor;

    .line 5
    new-instance p0, Landroid/os/ConditionVariable;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Landroid/os/ConditionVariable;-><init>(Z)V

    return-void
.end method

.method public constructor <init>(ILandroid/bluetooth/BluetoothGattCharacteristic;)V
    .locals 0

    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    iput p1, p0, Lno/nordicsemi/android/ble/i0;->c:I

    .line 8
    iput-object p2, p0, Lno/nordicsemi/android/ble/i0;->d:Landroid/bluetooth/BluetoothGattCharacteristic;

    const/4 p1, 0x0

    .line 9
    iput-object p1, p0, Lno/nordicsemi/android/ble/i0;->e:Landroid/bluetooth/BluetoothGattDescriptor;

    .line 10
    new-instance p0, Landroid/os/ConditionVariable;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Landroid/os/ConditionVariable;-><init>(Z)V

    return-void
.end method

.method public constructor <init>(ILandroid/bluetooth/BluetoothGattDescriptor;)V
    .locals 0

    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    iput p1, p0, Lno/nordicsemi/android/ble/i0;->c:I

    const/4 p1, 0x0

    .line 13
    iput-object p1, p0, Lno/nordicsemi/android/ble/i0;->d:Landroid/bluetooth/BluetoothGattCharacteristic;

    .line 14
    iput-object p2, p0, Lno/nordicsemi/android/ble/i0;->e:Landroid/bluetooth/BluetoothGattDescriptor;

    .line 15
    new-instance p0, Landroid/os/ConditionVariable;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Landroid/os/ConditionVariable;-><init>(Z)V

    return-void
.end method


# virtual methods
.method public a(ILandroid/bluetooth/BluetoothDevice;)V
    .locals 3

    .line 1
    iget-boolean v0, p0, Lno/nordicsemi/android/ble/i0;->k:Z

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    const/4 v0, 0x1

    .line 6
    iput-boolean v0, p0, Lno/nordicsemi/android/ble/i0;->k:Z

    .line 7
    .line 8
    iget-object v0, p0, Lno/nordicsemi/android/ble/i0;->b:Lno/nordicsemi/android/ble/d;

    .line 9
    .line 10
    new-instance v1, Lno/nordicsemi/android/ble/p;

    .line 11
    .line 12
    const/4 v2, 0x2

    .line 13
    invoke-direct {v1, p0, p2, p1, v2}, Lno/nordicsemi/android/ble/p;-><init>(Lno/nordicsemi/android/ble/i0;Landroid/bluetooth/BluetoothDevice;II)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {v0, v1}, Lno/nordicsemi/android/ble/d;->C(Ljava/lang/Runnable;)V

    .line 17
    .line 18
    .line 19
    :cond_0
    return-void
.end method

.method public b()V
    .locals 2

    .line 1
    iget-boolean v0, p0, Lno/nordicsemi/android/ble/i0;->k:Z

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    const/4 v0, 0x1

    .line 6
    iput-boolean v0, p0, Lno/nordicsemi/android/ble/i0;->k:Z

    .line 7
    .line 8
    iget-object v0, p0, Lno/nordicsemi/android/ble/i0;->b:Lno/nordicsemi/android/ble/d;

    .line 9
    .line 10
    new-instance v1, Lno/nordicsemi/android/ble/h0;

    .line 11
    .line 12
    invoke-direct {v1, p0}, Lno/nordicsemi/android/ble/h0;-><init>(Lno/nordicsemi/android/ble/i0;)V

    .line 13
    .line 14
    .line 15
    invoke-virtual {v0, v1}, Lno/nordicsemi/android/ble/d;->C(Ljava/lang/Runnable;)V

    .line 16
    .line 17
    .line 18
    :cond_0
    return-void
.end method

.method public c(Landroid/bluetooth/BluetoothDevice;)V
    .locals 2

    .line 1
    iget-boolean v0, p0, Lno/nordicsemi/android/ble/i0;->j:Z

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    const/4 v0, 0x1

    .line 6
    iput-boolean v0, p0, Lno/nordicsemi/android/ble/i0;->j:Z

    .line 7
    .line 8
    iget-object v0, p0, Lno/nordicsemi/android/ble/i0;->b:Lno/nordicsemi/android/ble/d;

    .line 9
    .line 10
    new-instance v1, Lno/nordicsemi/android/ble/h0;

    .line 11
    .line 12
    invoke-direct {v1, p0, p1}, Lno/nordicsemi/android/ble/h0;-><init>(Lno/nordicsemi/android/ble/i0;Landroid/bluetooth/BluetoothDevice;)V

    .line 13
    .line 14
    .line 15
    invoke-virtual {v0, v1}, Lno/nordicsemi/android/ble/d;->C(Ljava/lang/Runnable;)V

    .line 16
    .line 17
    .line 18
    :cond_0
    return-void
.end method

.method public d(Landroid/bluetooth/BluetoothDevice;)Z
    .locals 4

    .line 1
    iget-boolean v0, p0, Lno/nordicsemi/android/ble/i0;->k:Z

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    const/4 v0, 0x1

    .line 6
    iput-boolean v0, p0, Lno/nordicsemi/android/ble/i0;->k:Z

    .line 7
    .line 8
    iget-object v1, p0, Lno/nordicsemi/android/ble/i0;->b:Lno/nordicsemi/android/ble/d;

    .line 9
    .line 10
    new-instance v2, Lh0/h0;

    .line 11
    .line 12
    const/16 v3, 0x1d

    .line 13
    .line 14
    invoke-direct {v2, v3, p0, p1}, Lh0/h0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    invoke-virtual {v1, v2}, Lno/nordicsemi/android/ble/d;->C(Ljava/lang/Runnable;)V

    .line 18
    .line 19
    .line 20
    return v0

    .line 21
    :cond_0
    const/4 p0, 0x0

    .line 22
    return p0
.end method

.method public e(Lno/nordicsemi/android/ble/d;)Lno/nordicsemi/android/ble/i0;
    .locals 1

    .line 1
    iput-object p1, p0, Lno/nordicsemi/android/ble/i0;->a:Lno/nordicsemi/android/ble/d;

    .line 2
    .line 3
    iget-object v0, p0, Lno/nordicsemi/android/ble/i0;->b:Lno/nordicsemi/android/ble/d;

    .line 4
    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    iput-object p1, p0, Lno/nordicsemi/android/ble/i0;->b:Lno/nordicsemi/android/ble/d;

    .line 8
    .line 9
    :cond_0
    return-object p0
.end method
