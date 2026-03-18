.class public abstract Lno/nordicsemi/android/ble/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public A:Lno/nordicsemi/android/ble/j0;

.field public final B:Ljava/util/HashMap;

.field public final C:Ljava/util/HashMap;

.field public D:Lno/nordicsemi/android/ble/r0;

.field public E:Lno/nordicsemi/android/ble/a;

.field public final F:Lno/nordicsemi/android/ble/l;

.field public final G:Lno/nordicsemi/android/ble/l;

.field public final H:Landroid/bluetooth/BluetoothGattCallback;

.field public final a:Ljava/lang/Object;

.field public b:Landroid/bluetooth/BluetoothDevice;

.field public c:Landroid/bluetooth/BluetoothGatt;

.field public d:Lno/nordicsemi/android/ble/e;

.field public e:Landroid/os/Handler;

.field public final f:Ljava/util/concurrent/LinkedBlockingDeque;

.field public g:Ljava/util/concurrent/LinkedBlockingDeque;

.field public h:Z

.field public i:Z

.field public j:Z

.field public k:Z

.field public l:J

.field public m:I

.field public n:Z

.field public o:Z

.field public p:Z

.field public q:Z

.field public r:Z

.field public s:I

.field public t:Z

.field public u:Z

.field public v:I

.field public w:I

.field public x:I

.field public y:Lno/nordicsemi/android/ble/x;

.field public z:Lno/nordicsemi/android/ble/i0;


# direct methods
.method public constructor <init>()V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/lang/Object;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lno/nordicsemi/android/ble/d;->a:Ljava/lang/Object;

    .line 10
    .line 11
    new-instance v0, Ljava/util/concurrent/LinkedBlockingDeque;

    .line 12
    .line 13
    invoke-direct {v0}, Ljava/util/concurrent/LinkedBlockingDeque;-><init>()V

    .line 14
    .line 15
    .line 16
    iput-object v0, p0, Lno/nordicsemi/android/ble/d;->f:Ljava/util/concurrent/LinkedBlockingDeque;

    .line 17
    .line 18
    const/4 v0, 0x0

    .line 19
    iput v0, p0, Lno/nordicsemi/android/ble/d;->m:I

    .line 20
    .line 21
    iput v0, p0, Lno/nordicsemi/android/ble/d;->s:I

    .line 22
    .line 23
    iput-boolean v0, p0, Lno/nordicsemi/android/ble/d;->t:Z

    .line 24
    .line 25
    const/16 v0, 0x17

    .line 26
    .line 27
    iput v0, p0, Lno/nordicsemi/android/ble/d;->v:I

    .line 28
    .line 29
    const/4 v0, -0x1

    .line 30
    iput v0, p0, Lno/nordicsemi/android/ble/d;->x:I

    .line 31
    .line 32
    new-instance v0, Ljava/util/HashMap;

    .line 33
    .line 34
    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    .line 35
    .line 36
    .line 37
    iput-object v0, p0, Lno/nordicsemi/android/ble/d;->B:Ljava/util/HashMap;

    .line 38
    .line 39
    new-instance v0, Ljava/util/HashMap;

    .line 40
    .line 41
    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    .line 42
    .line 43
    .line 44
    iput-object v0, p0, Lno/nordicsemi/android/ble/d;->C:Ljava/util/HashMap;

    .line 45
    .line 46
    new-instance v0, Lno/nordicsemi/android/ble/l;

    .line 47
    .line 48
    const/4 v1, 0x0

    .line 49
    invoke-direct {v0, p0, v1}, Lno/nordicsemi/android/ble/l;-><init>(Ljava/lang/Object;I)V

    .line 50
    .line 51
    .line 52
    iput-object v0, p0, Lno/nordicsemi/android/ble/d;->F:Lno/nordicsemi/android/ble/l;

    .line 53
    .line 54
    new-instance v0, Lno/nordicsemi/android/ble/l;

    .line 55
    .line 56
    const/4 v1, 0x1

    .line 57
    invoke-direct {v0, p0, v1}, Lno/nordicsemi/android/ble/l;-><init>(Ljava/lang/Object;I)V

    .line 58
    .line 59
    .line 60
    iput-object v0, p0, Lno/nordicsemi/android/ble/d;->G:Lno/nordicsemi/android/ble/l;

    .line 61
    .line 62
    new-instance v0, Lno/nordicsemi/android/ble/BleManagerHandler$4;

    .line 63
    .line 64
    invoke-direct {v0, p0}, Lno/nordicsemi/android/ble/BleManagerHandler$4;-><init>(Lno/nordicsemi/android/ble/d;)V

    .line 65
    .line 66
    .line 67
    iput-object v0, p0, Lno/nordicsemi/android/ble/d;->H:Landroid/bluetooth/BluetoothGattCallback;

    .line 68
    .line 69
    return-void
.end method

.method public static G(Lnm/c;Lnm/g;)I
    .locals 1

    .line 1
    instance-of v0, p0, Lnm/a;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    check-cast p0, Lnm/a;

    .line 6
    .line 7
    iget p0, p0, Lnm/a;->a:I

    .line 8
    .line 9
    return p0

    .line 10
    :cond_0
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 11
    .line 12
    .line 13
    move-result p0

    .line 14
    if-eqz p0, :cond_2

    .line 15
    .line 16
    const/4 p1, 0x1

    .line 17
    if-ne p0, p1, :cond_1

    .line 18
    .line 19
    const p0, 0x7fffffff

    .line 20
    .line 21
    .line 22
    return p0

    .line 23
    :cond_1
    new-instance p0, La8/r0;

    .line 24
    .line 25
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 26
    .line 27
    .line 28
    throw p0

    .line 29
    :cond_2
    const/high16 p0, -0x80000000

    .line 30
    .line 31
    return p0
.end method

.method public static a(Lno/nordicsemi/android/ble/d;I)V
    .locals 2

    .line 1
    new-instance v0, La8/w;

    .line 2
    .line 3
    const/4 v1, 0x6

    .line 4
    invoke-direct {v0, p1, v1}, La8/w;-><init>(II)V

    .line 5
    .line 6
    .line 7
    const/4 p1, 0x6

    .line 8
    invoke-virtual {p0, p1, v0}, Lno/nordicsemi/android/ble/d;->z(ILno/nordicsemi/android/ble/t;)V

    .line 9
    .line 10
    .line 11
    iget-object p0, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 12
    .line 13
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 14
    .line 15
    .line 16
    return-void
.end method

.method public static final d(IILnm/h;Lnm/g;Lnm/h;)J
    .locals 2

    .line 1
    sget-object v0, Lnm/h;->c:Lnm/h;

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    iget-object p0, p2, Lnm/h;->a:Lnm/c;

    .line 11
    .line 12
    invoke-static {p0, p3}, Lno/nordicsemi/android/ble/d;->G(Lnm/c;Lnm/g;)I

    .line 13
    .line 14
    .line 15
    move-result p0

    .line 16
    iget-object p1, p2, Lnm/h;->b:Lnm/c;

    .line 17
    .line 18
    invoke-static {p1, p3}, Lno/nordicsemi/android/ble/d;->G(Lnm/c;Lnm/g;)I

    .line 19
    .line 20
    .line 21
    move-result p1

    .line 22
    :goto_0
    iget-object p2, p4, Lnm/h;->a:Lnm/c;

    .line 23
    .line 24
    iget-object p3, p4, Lnm/h;->b:Lnm/c;

    .line 25
    .line 26
    instance-of p4, p2, Lnm/a;

    .line 27
    .line 28
    const v0, 0x7fffffff

    .line 29
    .line 30
    .line 31
    const/high16 v1, -0x80000000

    .line 32
    .line 33
    if-eqz p4, :cond_2

    .line 34
    .line 35
    if-eq p0, v1, :cond_2

    .line 36
    .line 37
    if-ne p0, v0, :cond_1

    .line 38
    .line 39
    goto :goto_1

    .line 40
    :cond_1
    check-cast p2, Lnm/a;

    .line 41
    .line 42
    iget p2, p2, Lnm/a;->a:I

    .line 43
    .line 44
    if-le p0, p2, :cond_2

    .line 45
    .line 46
    move p0, p2

    .line 47
    :cond_2
    :goto_1
    instance-of p2, p3, Lnm/a;

    .line 48
    .line 49
    if-eqz p2, :cond_4

    .line 50
    .line 51
    if-eq p1, v1, :cond_4

    .line 52
    .line 53
    if-ne p1, v0, :cond_3

    .line 54
    .line 55
    goto :goto_2

    .line 56
    :cond_3
    check-cast p3, Lnm/a;

    .line 57
    .line 58
    iget p2, p3, Lnm/a;->a:I

    .line 59
    .line 60
    if-le p1, p2, :cond_4

    .line 61
    .line 62
    move p1, p2

    .line 63
    :cond_4
    :goto_2
    int-to-long p2, p0

    .line 64
    const/16 p0, 0x20

    .line 65
    .line 66
    shl-long/2addr p2, p0

    .line 67
    int-to-long p0, p1

    .line 68
    const-wide v0, 0xffffffffL

    .line 69
    .line 70
    .line 71
    .line 72
    .line 73
    and-long/2addr p0, v0

    .line 74
    or-long/2addr p0, p2

    .line 75
    return-wide p0
.end method

.method public static final e(IIIILnm/g;)D
    .locals 4

    .line 1
    int-to-double v0, p2

    .line 2
    int-to-double v2, p0

    .line 3
    div-double/2addr v0, v2

    .line 4
    int-to-double p2, p3

    .line 5
    int-to-double p0, p1

    .line 6
    div-double/2addr p2, p0

    .line 7
    invoke-virtual {p4}, Ljava/lang/Enum;->ordinal()I

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    if-eqz p0, :cond_1

    .line 12
    .line 13
    const/4 p1, 0x1

    .line 14
    if-ne p0, p1, :cond_0

    .line 15
    .line 16
    invoke-static {v0, v1, p2, p3}, Ljava/lang/Math;->min(DD)D

    .line 17
    .line 18
    .line 19
    move-result-wide p0

    .line 20
    return-wide p0

    .line 21
    :cond_0
    new-instance p0, La8/r0;

    .line 22
    .line 23
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 24
    .line 25
    .line 26
    throw p0

    .line 27
    :cond_1
    invoke-static {v0, v1, p2, p3}, Ljava/lang/Math;->max(DD)D

    .line 28
    .line 29
    .line 30
    move-result-wide p0

    .line 31
    return-wide p0
.end method

.method public static h(ILandroid/bluetooth/BluetoothGattCharacteristic;)Landroid/bluetooth/BluetoothGattDescriptor;
    .locals 1

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    goto :goto_0

    .line 4
    :cond_0
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGattCharacteristic;->getProperties()I

    .line 5
    .line 6
    .line 7
    move-result v0

    .line 8
    and-int/2addr p0, v0

    .line 9
    if-nez p0, :cond_1

    .line 10
    .line 11
    :goto_0
    const/4 p0, 0x0

    .line 12
    return-object p0

    .line 13
    :cond_1
    sget-object p0, Lno/nordicsemi/android/ble/e;->CLIENT_CHARACTERISTIC_CONFIG_DESCRIPTOR_UUID:Ljava/util/UUID;

    .line 14
    .line 15
    invoke-virtual {p1, p0}, Landroid/bluetooth/BluetoothGattCharacteristic;->getDescriptor(Ljava/util/UUID;)Landroid/bluetooth/BluetoothGattDescriptor;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    return-object p0
.end method


# virtual methods
.method public final declared-synchronized A(Z)V
    .locals 16

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    monitor-enter p0

    .line 4
    const/4 v2, 0x0

    .line 5
    const/4 v3, 0x1

    .line 6
    if-eqz p1, :cond_1

    .line 7
    .line 8
    :try_start_0
    iget-boolean v0, v1, Lno/nordicsemi/android/ble/d;->p:Z

    .line 9
    .line 10
    if-eqz v0, :cond_1

    .line 11
    .line 12
    iget-object v0, v1, Lno/nordicsemi/android/ble/d;->E:Lno/nordicsemi/android/ble/a;

    .line 13
    .line 14
    if-eqz v0, :cond_0

    .line 15
    .line 16
    move v0, v3

    .line 17
    goto :goto_0

    .line 18
    :cond_0
    move v0, v2

    .line 19
    :goto_0
    iput-boolean v0, v1, Lno/nordicsemi/android/ble/d;->p:Z

    .line 20
    .line 21
    goto :goto_1

    .line 22
    :catchall_0
    move-exception v0

    .line 23
    goto/16 :goto_1b

    .line 24
    .line 25
    :cond_1
    :goto_1
    iget-boolean v0, v1, Lno/nordicsemi/android/ble/d;->p:Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 26
    .line 27
    if-eqz v0, :cond_2

    .line 28
    .line 29
    monitor-exit p0

    .line 30
    return-void

    .line 31
    :cond_2
    :try_start_1
    iget-object v4, v1, Lno/nordicsemi/android/ble/d;->b:Landroid/bluetooth/BluetoothDevice;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 32
    .line 33
    const/4 v5, 0x0

    .line 34
    :try_start_2
    iget-object v0, v1, Lno/nordicsemi/android/ble/d;->A:Lno/nordicsemi/android/ble/j0;

    .line 35
    .line 36
    if-eqz v0, :cond_5

    .line 37
    .line 38
    invoke-virtual {v0}, Lno/nordicsemi/android/ble/j0;->j()Z

    .line 39
    .line 40
    .line 41
    move-result v0

    .line 42
    if-eqz v0, :cond_3

    .line 43
    .line 44
    iget-object v0, v1, Lno/nordicsemi/android/ble/d;->A:Lno/nordicsemi/android/ble/j0;

    .line 45
    .line 46
    invoke-virtual {v0}, Lno/nordicsemi/android/ble/j0;->i()Lno/nordicsemi/android/ble/i0;

    .line 47
    .line 48
    .line 49
    move-result-object v0

    .line 50
    invoke-virtual {v0, v1}, Lno/nordicsemi/android/ble/i0;->e(Lno/nordicsemi/android/ble/d;)Lno/nordicsemi/android/ble/i0;

    .line 51
    .line 52
    .line 53
    move-result-object v0

    .line 54
    goto :goto_2

    .line 55
    :cond_3
    iget-object v0, v1, Lno/nordicsemi/android/ble/d;->A:Lno/nordicsemi/android/ble/j0;

    .line 56
    .line 57
    instance-of v6, v0, Lno/nordicsemi/android/ble/g0;

    .line 58
    .line 59
    if-eqz v6, :cond_4

    .line 60
    .line 61
    move-object v6, v0

    .line 62
    check-cast v6, Lno/nordicsemi/android/ble/g0;

    .line 63
    .line 64
    iget-boolean v6, v6, Lno/nordicsemi/android/ble/p0;->n:Z

    .line 65
    .line 66
    if-eqz v6, :cond_4

    .line 67
    .line 68
    const/4 v6, -0x7

    .line 69
    invoke-virtual {v0, v6, v4}, Lno/nordicsemi/android/ble/j0;->a(ILandroid/bluetooth/BluetoothDevice;)V

    .line 70
    .line 71
    .line 72
    :cond_4
    iget-object v0, v1, Lno/nordicsemi/android/ble/d;->A:Lno/nordicsemi/android/ble/j0;

    .line 73
    .line 74
    invoke-virtual {v0, v4}, Lno/nordicsemi/android/ble/p0;->d(Landroid/bluetooth/BluetoothDevice;)Z

    .line 75
    .line 76
    .line 77
    iput-object v5, v1, Lno/nordicsemi/android/ble/d;->A:Lno/nordicsemi/android/ble/j0;
    :try_end_2
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_0
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 78
    .line 79
    :cond_5
    move-object v0, v5

    .line 80
    :goto_2
    if-nez v0, :cond_7

    .line 81
    .line 82
    :try_start_3
    iget-object v6, v1, Lno/nordicsemi/android/ble/d;->g:Ljava/util/concurrent/LinkedBlockingDeque;

    .line 83
    .line 84
    if-eqz v6, :cond_6

    .line 85
    .line 86
    invoke-virtual {v6}, Ljava/util/concurrent/LinkedBlockingDeque;->poll()Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    move-result-object v6

    .line 90
    check-cast v6, Lno/nordicsemi/android/ble/i0;
    :try_end_3
    .catch Ljava/lang/Exception; {:try_start_3 .. :try_end_3} :catch_1
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 91
    .line 92
    move-object v0, v6

    .line 93
    goto :goto_3

    .line 94
    :catch_0
    :cond_6
    move-object v0, v5

    .line 95
    :catch_1
    :cond_7
    :goto_3
    if-nez v0, :cond_a

    .line 96
    .line 97
    :try_start_4
    iget-object v0, v1, Lno/nordicsemi/android/ble/d;->g:Ljava/util/concurrent/LinkedBlockingDeque;

    .line 98
    .line 99
    if-eqz v0, :cond_9

    .line 100
    .line 101
    iput-object v5, v1, Lno/nordicsemi/android/ble/d;->g:Ljava/util/concurrent/LinkedBlockingDeque;

    .line 102
    .line 103
    iput-boolean v3, v1, Lno/nordicsemi/android/ble/d;->p:Z

    .line 104
    .line 105
    iput-boolean v3, v1, Lno/nordicsemi/android/ble/d;->o:Z

    .line 106
    .line 107
    iget-object v0, v1, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 108
    .line 109
    invoke-virtual {v0}, Lno/nordicsemi/android/ble/e;->onDeviceReady()V

    .line 110
    .line 111
    .line 112
    if-eqz v4, :cond_8

    .line 113
    .line 114
    iget-object v0, v1, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 115
    .line 116
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 117
    .line 118
    .line 119
    new-instance v0, Lno/nordicsemi/android/ble/g;

    .line 120
    .line 121
    const/4 v6, 0x4

    .line 122
    invoke-direct {v0, v6, v4}, Lno/nordicsemi/android/ble/g;-><init>(ILandroid/bluetooth/BluetoothDevice;)V

    .line 123
    .line 124
    .line 125
    invoke-virtual {v1, v0}, Lno/nordicsemi/android/ble/d;->D(Lno/nordicsemi/android/ble/s;)V

    .line 126
    .line 127
    .line 128
    :cond_8
    iget-object v0, v1, Lno/nordicsemi/android/ble/d;->y:Lno/nordicsemi/android/ble/x;

    .line 129
    .line 130
    if-eqz v0, :cond_9

    .line 131
    .line 132
    iget-object v6, v0, Lno/nordicsemi/android/ble/x;->p:Landroid/bluetooth/BluetoothDevice;

    .line 133
    .line 134
    invoke-virtual {v0, v6}, Lno/nordicsemi/android/ble/p0;->d(Landroid/bluetooth/BluetoothDevice;)Z

    .line 135
    .line 136
    .line 137
    iput-object v5, v1, Lno/nordicsemi/android/ble/d;->y:Lno/nordicsemi/android/ble/x;
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 138
    .line 139
    :cond_9
    :try_start_5
    iget-object v0, v1, Lno/nordicsemi/android/ble/d;->f:Ljava/util/concurrent/LinkedBlockingDeque;

    .line 140
    .line 141
    invoke-virtual {v0}, Ljava/util/concurrent/LinkedBlockingDeque;->remove()Ljava/lang/Object;

    .line 142
    .line 143
    .line 144
    move-result-object v0

    .line 145
    check-cast v0, Lno/nordicsemi/android/ble/i0;
    :try_end_5
    .catch Ljava/lang/Exception; {:try_start_5 .. :try_end_5} :catch_2
    .catchall {:try_start_5 .. :try_end_5} :catchall_0

    .line 146
    .line 147
    :cond_a
    move-object v6, v0

    .line 148
    goto :goto_4

    .line 149
    :catch_2
    :try_start_6
    iput-boolean v2, v1, Lno/nordicsemi/android/ble/d;->p:Z

    .line 150
    .line 151
    iput-object v5, v1, Lno/nordicsemi/android/ble/d;->z:Lno/nordicsemi/android/ble/i0;

    .line 152
    .line 153
    iget-object v0, v1, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 154
    .line 155
    invoke-virtual {v0}, Lno/nordicsemi/android/ble/e;->onManagerReady()V
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_0

    .line 156
    .line 157
    .line 158
    monitor-exit p0

    .line 159
    return-void

    .line 160
    :goto_4
    :try_start_7
    iget-boolean v0, v6, Lno/nordicsemi/android/ble/i0;->k:Z

    .line 161
    .line 162
    if-eqz v0, :cond_b

    .line 163
    .line 164
    invoke-virtual {v1, v2}, Lno/nordicsemi/android/ble/d;->A(Z)V
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_0

    .line 165
    .line 166
    .line 167
    monitor-exit p0

    .line 168
    return-void

    .line 169
    :cond_b
    :try_start_8
    iput-boolean v3, v1, Lno/nordicsemi/android/ble/d;->p:Z

    .line 170
    .line 171
    iput-object v6, v1, Lno/nordicsemi/android/ble/d;->z:Lno/nordicsemi/android/ble/i0;

    .line 172
    .line 173
    instance-of v0, v6, Lno/nordicsemi/android/ble/a;

    .line 174
    .line 175
    const/4 v7, 0x4

    .line 176
    const/4 v8, 0x2

    .line 177
    if-eqz v0, :cond_13

    .line 178
    .line 179
    move-object v0, v6

    .line 180
    check-cast v0, Lno/nordicsemi/android/ble/a;

    .line 181
    .line 182
    iget v9, v6, Lno/nordicsemi/android/ble/i0;->c:I

    .line 183
    .line 184
    invoke-static {v9}, Lu/w;->o(I)I

    .line 185
    .line 186
    .line 187
    move-result v9

    .line 188
    packed-switch v9, :pswitch_data_0

    .line 189
    .line 190
    .line 191
    move v9, v2

    .line 192
    goto :goto_5

    .line 193
    :pswitch_0
    const/16 v9, 0x4c

    .line 194
    .line 195
    goto :goto_5

    .line 196
    :pswitch_1
    move v9, v8

    .line 197
    goto :goto_5

    .line 198
    :pswitch_2
    const/16 v9, 0x20

    .line 199
    .line 200
    goto :goto_5

    .line 201
    :pswitch_3
    const/16 v9, 0x10

    .line 202
    .line 203
    :goto_5
    iget-boolean v10, v1, Lno/nordicsemi/android/ble/d;->n:Z

    .line 204
    .line 205
    if-eqz v10, :cond_d

    .line 206
    .line 207
    if-eqz v4, :cond_d

    .line 208
    .line 209
    iget-object v10, v0, Lno/nordicsemi/android/ble/i0;->d:Landroid/bluetooth/BluetoothGattCharacteristic;

    .line 210
    .line 211
    if-eqz v10, :cond_c

    .line 212
    .line 213
    invoke-virtual {v10}, Landroid/bluetooth/BluetoothGattCharacteristic;->getProperties()I

    .line 214
    .line 215
    .line 216
    move-result v10

    .line 217
    and-int/2addr v9, v10

    .line 218
    if-eqz v9, :cond_d

    .line 219
    .line 220
    :cond_c
    move v9, v3

    .line 221
    goto :goto_6

    .line 222
    :cond_d
    move v9, v2

    .line 223
    :goto_6
    if-eqz v9, :cond_14

    .line 224
    .line 225
    instance-of v10, v0, Lno/nordicsemi/android/ble/w;

    .line 226
    .line 227
    if-eqz v10, :cond_10

    .line 228
    .line 229
    move-object v10, v0

    .line 230
    check-cast v10, Lno/nordicsemi/android/ble/w;

    .line 231
    .line 232
    iget-object v11, v1, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 233
    .line 234
    invoke-virtual {v11}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 235
    .line 236
    .line 237
    move-result v11

    .line 238
    if-lt v8, v11, :cond_e

    .line 239
    .line 240
    iget-object v11, v1, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 241
    .line 242
    const-string v12, "Waiting for fulfillment of condition..."

    .line 243
    .line 244
    invoke-virtual {v11, v8, v12}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 245
    .line 246
    .line 247
    :cond_e
    invoke-virtual {v10}, Lno/nordicsemi/android/ble/w;->h()Z

    .line 248
    .line 249
    .line 250
    move-result v11

    .line 251
    if-eqz v11, :cond_10

    .line 252
    .line 253
    invoke-virtual {v10, v4}, Lno/nordicsemi/android/ble/p0;->c(Landroid/bluetooth/BluetoothDevice;)V

    .line 254
    .line 255
    .line 256
    iget-object v0, v1, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 257
    .line 258
    invoke-virtual {v0}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 259
    .line 260
    .line 261
    move-result v0

    .line 262
    if-lt v7, v0, :cond_f

    .line 263
    .line 264
    iget-object v0, v1, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 265
    .line 266
    const-string v2, "Condition fulfilled"

    .line 267
    .line 268
    invoke-virtual {v0, v7, v2}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 269
    .line 270
    .line 271
    :cond_f
    invoke-virtual {v10, v4}, Lno/nordicsemi/android/ble/p0;->d(Landroid/bluetooth/BluetoothDevice;)Z

    .line 272
    .line 273
    .line 274
    invoke-virtual {v1, v3}, Lno/nordicsemi/android/ble/d;->A(Z)V
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_0

    .line 275
    .line 276
    .line 277
    monitor-exit p0

    .line 278
    return-void

    .line 279
    :cond_10
    :try_start_9
    instance-of v10, v0, Lno/nordicsemi/android/ble/s0;

    .line 280
    .line 281
    if-eqz v10, :cond_11

    .line 282
    .line 283
    iget-object v10, v1, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 284
    .line 285
    invoke-virtual {v10}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 286
    .line 287
    .line 288
    move-result v10

    .line 289
    if-lt v8, v10, :cond_11

    .line 290
    .line 291
    iget-object v10, v1, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 292
    .line 293
    const-string v11, "Waiting for read request..."

    .line 294
    .line 295
    invoke-virtual {v10, v8, v11}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 296
    .line 297
    .line 298
    :cond_11
    instance-of v10, v0, Lno/nordicsemi/android/ble/t0;

    .line 299
    .line 300
    if-eqz v10, :cond_12

    .line 301
    .line 302
    iget-object v10, v1, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 303
    .line 304
    invoke-virtual {v10}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 305
    .line 306
    .line 307
    move-result v10

    .line 308
    if-lt v8, v10, :cond_12

    .line 309
    .line 310
    iget-object v10, v1, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 311
    .line 312
    const-string v11, "Waiting for value change..."

    .line 313
    .line 314
    invoke-virtual {v10, v8, v11}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 315
    .line 316
    .line 317
    :cond_12
    iput-object v0, v1, Lno/nordicsemi/android/ble/d;->E:Lno/nordicsemi/android/ble/a;

    .line 318
    .line 319
    goto :goto_7

    .line 320
    :cond_13
    move v9, v2

    .line 321
    :cond_14
    :goto_7
    instance-of v0, v6, Lno/nordicsemi/android/ble/x;

    .line 322
    .line 323
    if-eqz v0, :cond_15

    .line 324
    .line 325
    move-object v0, v6

    .line 326
    check-cast v0, Lno/nordicsemi/android/ble/x;

    .line 327
    .line 328
    iget-object v10, v0, Lno/nordicsemi/android/ble/x;->p:Landroid/bluetooth/BluetoothDevice;

    .line 329
    .line 330
    invoke-virtual {v0, v10}, Lno/nordicsemi/android/ble/p0;->c(Landroid/bluetooth/BluetoothDevice;)V

    .line 331
    .line 332
    .line 333
    goto :goto_8

    .line 334
    :cond_15
    if-eqz v4, :cond_3b

    .line 335
    .line 336
    invoke-virtual {v6, v4}, Lno/nordicsemi/android/ble/i0;->c(Landroid/bluetooth/BluetoothDevice;)V

    .line 337
    .line 338
    .line 339
    :goto_8
    iget v0, v6, Lno/nordicsemi/android/ble/i0;->c:I

    .line 340
    .line 341
    invoke-static {v0}, Lu/w;->o(I)I

    .line 342
    .line 343
    .line 344
    move-result v0

    .line 345
    const/4 v10, 0x3

    .line 346
    packed-switch v0, :pswitch_data_1

    .line 347
    .line 348
    .line 349
    const/16 v11, 0x200

    .line 350
    .line 351
    const-wide/16 v12, 0x3e8

    .line 352
    .line 353
    const-wide/16 v14, 0xc8

    .line 354
    .line 355
    packed-switch v0, :pswitch_data_2

    .line 356
    .line 357
    .line 358
    goto/16 :goto_19

    .line 359
    .line 360
    :pswitch_4
    move-object v0, v6

    .line 361
    check-cast v0, Lno/nordicsemi/android/ble/n0;

    .line 362
    .line 363
    iget-object v7, v1, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 364
    .line 365
    invoke-virtual {v7}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 366
    .line 367
    .line 368
    move-result v7

    .line 369
    if-lt v10, v7, :cond_16

    .line 370
    .line 371
    iget-object v7, v1, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 372
    .line 373
    new-instance v8, Ljava/lang/StringBuilder;

    .line 374
    .line 375
    const-string v9, "sleep("

    .line 376
    .line 377
    invoke-direct {v8, v9}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 378
    .line 379
    .line 380
    iget-wide v11, v0, Lno/nordicsemi/android/ble/p0;->o:J

    .line 381
    .line 382
    invoke-virtual {v8, v11, v12}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 383
    .line 384
    .line 385
    const-string v0, ")"

    .line 386
    .line 387
    invoke-virtual {v8, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 388
    .line 389
    .line 390
    invoke-virtual {v8}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 391
    .line 392
    .line 393
    move-result-object v0

    .line 394
    invoke-virtual {v7, v10, v0}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 395
    .line 396
    .line 397
    :cond_16
    :goto_9
    move v9, v3

    .line 398
    goto/16 :goto_19

    .line 399
    .line 400
    :pswitch_5
    invoke-virtual {v1}, Lno/nordicsemi/android/ble/d;->u()Z

    .line 401
    .line 402
    .line 403
    move-result v9

    .line 404
    if-eqz v9, :cond_37

    .line 405
    .line 406
    new-instance v0, Lno/nordicsemi/android/ble/k;

    .line 407
    .line 408
    const/4 v7, 0x1

    .line 409
    invoke-direct {v0, v1, v6, v4, v7}, Lno/nordicsemi/android/ble/k;-><init>(Lno/nordicsemi/android/ble/d;Lno/nordicsemi/android/ble/i0;Landroid/bluetooth/BluetoothDevice;I)V

    .line 410
    .line 411
    .line 412
    invoke-virtual {v1, v0, v14, v15}, Lno/nordicsemi/android/ble/d;->E(Ljava/lang/Runnable;J)V

    .line 413
    .line 414
    .line 415
    goto/16 :goto_19

    .line 416
    .line 417
    :pswitch_6
    iget-object v0, v1, Lno/nordicsemi/android/ble/d;->c:Landroid/bluetooth/BluetoothGatt;

    .line 418
    .line 419
    if-eqz v0, :cond_1a

    .line 420
    .line 421
    iget-boolean v7, v1, Lno/nordicsemi/android/ble/d;->n:Z

    .line 422
    .line 423
    if-nez v7, :cond_17

    .line 424
    .line 425
    goto :goto_a

    .line 426
    :cond_17
    iget-object v7, v1, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 427
    .line 428
    invoke-virtual {v7}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 429
    .line 430
    .line 431
    move-result v7

    .line 432
    if-lt v8, v7, :cond_18

    .line 433
    .line 434
    iget-object v7, v1, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 435
    .line 436
    const-string v9, "Reading remote RSSI..."

    .line 437
    .line 438
    invoke-virtual {v7, v8, v9}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 439
    .line 440
    .line 441
    :cond_18
    iget-object v7, v1, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 442
    .line 443
    invoke-virtual {v7}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 444
    .line 445
    .line 446
    move-result v7

    .line 447
    if-lt v10, v7, :cond_19

    .line 448
    .line 449
    iget-object v7, v1, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 450
    .line 451
    const-string v8, "gatt.readRemoteRssi()"

    .line 452
    .line 453
    invoke-virtual {v7, v10, v8}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 454
    .line 455
    .line 456
    :cond_19
    invoke-virtual {v0}, Landroid/bluetooth/BluetoothGatt;->readRemoteRssi()Z

    .line 457
    .line 458
    .line 459
    move-result v0

    .line 460
    move v9, v0

    .line 461
    goto :goto_b

    .line 462
    :cond_1a
    :goto_a
    move v9, v2

    .line 463
    :goto_b
    if-eqz v9, :cond_37

    .line 464
    .line 465
    new-instance v0, Lno/nordicsemi/android/ble/k;

    .line 466
    .line 467
    const/4 v7, 0x0

    .line 468
    invoke-direct {v0, v1, v6, v4, v7}, Lno/nordicsemi/android/ble/k;-><init>(Lno/nordicsemi/android/ble/d;Lno/nordicsemi/android/ble/i0;Landroid/bluetooth/BluetoothDevice;I)V

    .line 469
    .line 470
    .line 471
    invoke-virtual {v1, v0, v12, v13}, Lno/nordicsemi/android/ble/d;->E(Ljava/lang/Runnable;J)V

    .line 472
    .line 473
    .line 474
    goto/16 :goto_19

    .line 475
    .line 476
    :pswitch_7
    move-object v0, v6

    .line 477
    check-cast v0, Lno/nordicsemi/android/ble/c0;

    .line 478
    .line 479
    invoke-virtual {v1}, Lno/nordicsemi/android/ble/d;->t()Z

    .line 480
    .line 481
    .line 482
    move-result v9

    .line 483
    goto/16 :goto_19

    .line 484
    .line 485
    :pswitch_8
    move-object v0, v6

    .line 486
    check-cast v0, Lno/nordicsemi/android/ble/c0;

    .line 487
    .line 488
    sget v7, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 489
    .line 490
    iget v9, v0, Lno/nordicsemi/android/ble/c0;->n:I

    .line 491
    .line 492
    iget v11, v0, Lno/nordicsemi/android/ble/c0;->o:I

    .line 493
    .line 494
    iget v14, v0, Lno/nordicsemi/android/ble/c0;->p:I

    .line 495
    .line 496
    iget-object v15, v1, Lno/nordicsemi/android/ble/d;->c:Landroid/bluetooth/BluetoothGatt;

    .line 497
    .line 498
    if-eqz v15, :cond_1d

    .line 499
    .line 500
    iget-boolean v5, v1, Lno/nordicsemi/android/ble/d;->n:Z

    .line 501
    .line 502
    if-nez v5, :cond_1b

    .line 503
    .line 504
    goto :goto_c

    .line 505
    :cond_1b
    iget-object v5, v1, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 506
    .line 507
    invoke-virtual {v5}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 508
    .line 509
    .line 510
    move-result v5

    .line 511
    if-lt v8, v5, :cond_1c

    .line 512
    .line 513
    iget-object v5, v1, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 514
    .line 515
    const-string v2, "Requesting preferred PHYs..."

    .line 516
    .line 517
    invoke-virtual {v5, v8, v2}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 518
    .line 519
    .line 520
    :cond_1c
    new-instance v2, Lno/nordicsemi/android/ble/q;

    .line 521
    .line 522
    const/4 v5, 0x2

    .line 523
    invoke-direct {v2, v9, v11, v14, v5}, Lno/nordicsemi/android/ble/q;-><init>(IIII)V

    .line 524
    .line 525
    .line 526
    invoke-virtual {v1, v10, v2}, Lno/nordicsemi/android/ble/d;->z(ILno/nordicsemi/android/ble/t;)V

    .line 527
    .line 528
    .line 529
    invoke-virtual {v15, v9, v11, v14}, Landroid/bluetooth/BluetoothGatt;->setPreferredPhy(III)V

    .line 530
    .line 531
    .line 532
    move v9, v3

    .line 533
    goto :goto_d

    .line 534
    :cond_1d
    :goto_c
    const/4 v9, 0x0

    .line 535
    :goto_d
    const/16 v2, 0x21

    .line 536
    .line 537
    if-ne v7, v2, :cond_37

    .line 538
    .line 539
    iget-object v2, v1, Lno/nordicsemi/android/ble/d;->e:Landroid/os/Handler;

    .line 540
    .line 541
    new-instance v5, Lh0/h0;

    .line 542
    .line 543
    const/16 v7, 0x1c

    .line 544
    .line 545
    invoke-direct {v5, v7, v1, v0}, Lh0/h0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 546
    .line 547
    .line 548
    invoke-virtual {v2, v5, v12, v13}, Landroid/os/Handler;->postDelayed(Ljava/lang/Runnable;J)Z

    .line 549
    .line 550
    .line 551
    goto/16 :goto_19

    .line 552
    .line 553
    :pswitch_9
    move-object v0, v6

    .line 554
    check-cast v0, Lno/nordicsemi/android/ble/z;

    .line 555
    .line 556
    iput-boolean v3, v1, Lno/nordicsemi/android/ble/d;->t:Z

    .line 557
    .line 558
    iget v2, v0, Lno/nordicsemi/android/ble/z;->n:I

    .line 559
    .line 560
    iget-object v5, v1, Lno/nordicsemi/android/ble/d;->c:Landroid/bluetooth/BluetoothGatt;

    .line 561
    .line 562
    if-eqz v5, :cond_1f

    .line 563
    .line 564
    iget-boolean v7, v1, Lno/nordicsemi/android/ble/d;->n:Z

    .line 565
    .line 566
    if-nez v7, :cond_1e

    .line 567
    .line 568
    goto :goto_e

    .line 569
    :cond_1e
    new-instance v7, La8/w;

    .line 570
    .line 571
    const/4 v9, 0x4

    .line 572
    invoke-direct {v7, v2, v9}, La8/w;-><init>(II)V

    .line 573
    .line 574
    .line 575
    invoke-virtual {v1, v8, v7}, Lno/nordicsemi/android/ble/d;->z(ILno/nordicsemi/android/ble/t;)V

    .line 576
    .line 577
    .line 578
    new-instance v7, La8/w;

    .line 579
    .line 580
    const/4 v8, 0x5

    .line 581
    invoke-direct {v7, v2, v8}, La8/w;-><init>(II)V

    .line 582
    .line 583
    .line 584
    invoke-virtual {v1, v10, v7}, Lno/nordicsemi/android/ble/d;->z(ILno/nordicsemi/android/ble/t;)V

    .line 585
    .line 586
    .line 587
    invoke-virtual {v5, v2}, Landroid/bluetooth/BluetoothGatt;->requestConnectionPriority(I)Z

    .line 588
    .line 589
    .line 590
    move-result v2

    .line 591
    move v9, v2

    .line 592
    goto :goto_f

    .line 593
    :cond_1f
    :goto_e
    const/4 v9, 0x0

    .line 594
    :goto_f
    if-eqz v9, :cond_20

    .line 595
    .line 596
    new-instance v2, Lno/nordicsemi/android/ble/n;

    .line 597
    .line 598
    const/4 v5, 0x2

    .line 599
    invoke-direct {v2, v1, v0, v4, v5}, Lno/nordicsemi/android/ble/n;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 600
    .line 601
    .line 602
    invoke-virtual {v1, v2, v14, v15}, Lno/nordicsemi/android/ble/d;->E(Ljava/lang/Runnable;J)V

    .line 603
    .line 604
    .line 605
    goto/16 :goto_19

    .line 606
    .line 607
    :cond_20
    const/4 v2, 0x0

    .line 608
    iput-boolean v2, v1, Lno/nordicsemi/android/ble/d;->t:Z

    .line 609
    .line 610
    goto/16 :goto_19

    .line 611
    .line 612
    :pswitch_a
    move-object v0, v6

    .line 613
    check-cast v0, Lno/nordicsemi/android/ble/b0;

    .line 614
    .line 615
    iget v2, v1, Lno/nordicsemi/android/ble/d;->v:I

    .line 616
    .line 617
    iget v5, v0, Lno/nordicsemi/android/ble/b0;->n:I

    .line 618
    .line 619
    if-eq v2, v5, :cond_24

    .line 620
    .line 621
    iget-object v0, v1, Lno/nordicsemi/android/ble/d;->c:Landroid/bluetooth/BluetoothGatt;

    .line 622
    .line 623
    if-eqz v0, :cond_35

    .line 624
    .line 625
    iget-boolean v2, v1, Lno/nordicsemi/android/ble/d;->n:Z

    .line 626
    .line 627
    if-nez v2, :cond_21

    .line 628
    .line 629
    goto/16 :goto_17

    .line 630
    .line 631
    :cond_21
    iget-object v2, v1, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 632
    .line 633
    invoke-virtual {v2}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 634
    .line 635
    .line 636
    move-result v2

    .line 637
    if-lt v8, v2, :cond_22

    .line 638
    .line 639
    iget-object v2, v1, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 640
    .line 641
    const-string v7, "Requesting new MTU..."

    .line 642
    .line 643
    invoke-virtual {v2, v8, v7}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 644
    .line 645
    .line 646
    :cond_22
    iget-object v2, v1, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 647
    .line 648
    invoke-virtual {v2}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 649
    .line 650
    .line 651
    move-result v2

    .line 652
    if-lt v10, v2, :cond_23

    .line 653
    .line 654
    iget-object v2, v1, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 655
    .line 656
    new-instance v7, Ljava/lang/StringBuilder;

    .line 657
    .line 658
    const-string v8, "gatt.requestMtu("

    .line 659
    .line 660
    invoke-direct {v7, v8}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 661
    .line 662
    .line 663
    invoke-virtual {v7, v5}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 664
    .line 665
    .line 666
    const-string v8, ")"

    .line 667
    .line 668
    invoke-virtual {v7, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 669
    .line 670
    .line 671
    invoke-virtual {v7}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 672
    .line 673
    .line 674
    move-result-object v7

    .line 675
    invoke-virtual {v2, v10, v7}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 676
    .line 677
    .line 678
    :cond_23
    invoke-virtual {v0, v5}, Landroid/bluetooth/BluetoothGatt;->requestMtu(I)Z

    .line 679
    .line 680
    .line 681
    move-result v0

    .line 682
    :goto_10
    move v9, v0

    .line 683
    goto/16 :goto_19

    .line 684
    .line 685
    :cond_24
    iget-boolean v9, v1, Lno/nordicsemi/android/ble/d;->n:Z

    .line 686
    .line 687
    if-eqz v9, :cond_37

    .line 688
    .line 689
    iget-object v5, v0, Lno/nordicsemi/android/ble/i0;->b:Lno/nordicsemi/android/ble/d;

    .line 690
    .line 691
    new-instance v6, Lno/nordicsemi/android/ble/p;

    .line 692
    .line 693
    const/4 v7, 0x1

    .line 694
    invoke-direct {v6, v0, v4, v2, v7}, Lno/nordicsemi/android/ble/p;-><init>(Lno/nordicsemi/android/ble/i0;Landroid/bluetooth/BluetoothDevice;II)V

    .line 695
    .line 696
    .line 697
    invoke-virtual {v5, v6}, Lno/nordicsemi/android/ble/d;->C(Ljava/lang/Runnable;)V

    .line 698
    .line 699
    .line 700
    invoke-virtual {v0, v4}, Lno/nordicsemi/android/ble/i0;->d(Landroid/bluetooth/BluetoothDevice;)Z

    .line 701
    .line 702
    .line 703
    invoke-virtual {v1, v3}, Lno/nordicsemi/android/ble/d;->A(Z)V
    :try_end_9
    .catchall {:try_start_9 .. :try_end_9} :catchall_0

    .line 704
    .line 705
    .line 706
    monitor-exit p0

    .line 707
    return-void

    .line 708
    :pswitch_b
    :try_start_a
    iget-object v0, v1, Lno/nordicsemi/android/ble/d;->c:Landroid/bluetooth/BluetoothGatt;

    .line 709
    .line 710
    if-eqz v0, :cond_35

    .line 711
    .line 712
    iget-boolean v2, v1, Lno/nordicsemi/android/ble/d;->n:Z

    .line 713
    .line 714
    if-nez v2, :cond_25

    .line 715
    .line 716
    goto/16 :goto_17

    .line 717
    .line 718
    :cond_25
    invoke-virtual {v0}, Landroid/bluetooth/BluetoothGatt;->getDevice()Landroid/bluetooth/BluetoothDevice;

    .line 719
    .line 720
    .line 721
    move-result-object v2

    .line 722
    invoke-virtual {v2}, Landroid/bluetooth/BluetoothDevice;->getBondState()I

    .line 723
    .line 724
    .line 725
    move-result v2

    .line 726
    const/16 v5, 0xc

    .line 727
    .line 728
    if-eq v2, v5, :cond_26

    .line 729
    .line 730
    goto/16 :goto_17

    .line 731
    .line 732
    :cond_26
    sget-object v2, Lno/nordicsemi/android/ble/e;->GENERIC_ATTRIBUTE_SERVICE:Ljava/util/UUID;

    .line 733
    .line 734
    invoke-virtual {v0, v2}, Landroid/bluetooth/BluetoothGatt;->getService(Ljava/util/UUID;)Landroid/bluetooth/BluetoothGattService;

    .line 735
    .line 736
    .line 737
    move-result-object v0

    .line 738
    if-nez v0, :cond_27

    .line 739
    .line 740
    goto/16 :goto_17

    .line 741
    .line 742
    :cond_27
    sget-object v2, Lno/nordicsemi/android/ble/e;->SERVICE_CHANGED_CHARACTERISTIC:Ljava/util/UUID;

    .line 743
    .line 744
    invoke-virtual {v0, v2}, Landroid/bluetooth/BluetoothGattService;->getCharacteristic(Ljava/util/UUID;)Landroid/bluetooth/BluetoothGattCharacteristic;

    .line 745
    .line 746
    .line 747
    move-result-object v0

    .line 748
    if-nez v0, :cond_28

    .line 749
    .line 750
    goto/16 :goto_17

    .line 751
    .line 752
    :cond_28
    iget-object v2, v1, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 753
    .line 754
    invoke-virtual {v2}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 755
    .line 756
    .line 757
    move-result v2

    .line 758
    if-lt v7, v2, :cond_29

    .line 759
    .line 760
    iget-object v2, v1, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 761
    .line 762
    const-string v5, "Service Changed characteristic found on a bonded device"

    .line 763
    .line 764
    invoke-virtual {v2, v7, v5}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 765
    .line 766
    .line 767
    :cond_29
    invoke-virtual {v1, v0}, Lno/nordicsemi/android/ble/d;->p(Landroid/bluetooth/BluetoothGattCharacteristic;)Z

    .line 768
    .line 769
    .line 770
    move-result v0

    .line 771
    goto :goto_10

    .line 772
    :pswitch_c
    invoke-virtual {v1, v2}, Lno/nordicsemi/android/ble/d;->w(Z)Z

    .line 773
    .line 774
    .line 775
    move-result v9

    .line 776
    goto/16 :goto_19

    .line 777
    .line 778
    :pswitch_d
    invoke-virtual {v1, v3}, Lno/nordicsemi/android/ble/d;->w(Z)Z

    .line 779
    .line 780
    .line 781
    move-result v9

    .line 782
    goto/16 :goto_19

    .line 783
    .line 784
    :pswitch_e
    iget-object v0, v1, Lno/nordicsemi/android/ble/d;->c:Landroid/bluetooth/BluetoothGatt;

    .line 785
    .line 786
    if-eqz v0, :cond_35

    .line 787
    .line 788
    iget-boolean v2, v1, Lno/nordicsemi/android/ble/d;->n:Z

    .line 789
    .line 790
    if-nez v2, :cond_2a

    .line 791
    .line 792
    goto/16 :goto_17

    .line 793
    .line 794
    :cond_2a
    sget-object v2, Lno/nordicsemi/android/ble/e;->BATTERY_SERVICE:Ljava/util/UUID;

    .line 795
    .line 796
    invoke-virtual {v0, v2}, Landroid/bluetooth/BluetoothGatt;->getService(Ljava/util/UUID;)Landroid/bluetooth/BluetoothGattService;

    .line 797
    .line 798
    .line 799
    move-result-object v0

    .line 800
    if-nez v0, :cond_2b

    .line 801
    .line 802
    goto/16 :goto_17

    .line 803
    .line 804
    :cond_2b
    sget-object v2, Lno/nordicsemi/android/ble/e;->BATTERY_LEVEL_CHARACTERISTIC:Ljava/util/UUID;

    .line 805
    .line 806
    invoke-virtual {v0, v2}, Landroid/bluetooth/BluetoothGattService;->getCharacteristic(Ljava/util/UUID;)Landroid/bluetooth/BluetoothGattCharacteristic;

    .line 807
    .line 808
    .line 809
    move-result-object v0

    .line 810
    invoke-virtual {v1, v0}, Lno/nordicsemi/android/ble/d;->s(Landroid/bluetooth/BluetoothGattCharacteristic;)Z

    .line 811
    .line 812
    .line 813
    move-result v0

    .line 814
    goto/16 :goto_10

    .line 815
    .line 816
    :pswitch_f
    move-object v0, v6

    .line 817
    check-cast v0, Lno/nordicsemi/android/ble/k0;

    .line 818
    .line 819
    iget-object v2, v0, Lno/nordicsemi/android/ble/i0;->e:Landroid/bluetooth/BluetoothGattDescriptor;

    .line 820
    .line 821
    if-eqz v2, :cond_37

    .line 822
    .line 823
    iget v5, v1, Lno/nordicsemi/android/ble/d;->v:I

    .line 824
    .line 825
    iget-boolean v7, v0, Lno/nordicsemi/android/ble/k0;->n:Z

    .line 826
    .line 827
    if-eqz v7, :cond_2c

    .line 828
    .line 829
    goto :goto_11

    .line 830
    :cond_2c
    add-int/lit8 v11, v5, -0x3

    .line 831
    .line 832
    :goto_11
    iget-object v5, v0, Lno/nordicsemi/android/ble/k0;->m:[B

    .line 833
    .line 834
    array-length v7, v5

    .line 835
    if-ge v7, v11, :cond_2d

    .line 836
    .line 837
    goto :goto_12

    .line 838
    :cond_2d
    const/4 v7, 0x0

    .line 839
    invoke-static {v5, v7, v11}, Ljp/ta;->a([BII)[B

    .line 840
    .line 841
    .line 842
    move-result-object v5

    .line 843
    :goto_12
    invoke-virtual {v2, v5}, Landroid/bluetooth/BluetoothGattDescriptor;->setValue([B)Z

    .line 844
    .line 845
    .line 846
    invoke-virtual {v0, v4}, Lno/nordicsemi/android/ble/i0;->d(Landroid/bluetooth/BluetoothDevice;)Z

    .line 847
    .line 848
    .line 849
    invoke-virtual {v1, v3}, Lno/nordicsemi/android/ble/d;->A(Z)V

    .line 850
    .line 851
    .line 852
    goto/16 :goto_9

    .line 853
    .line 854
    :pswitch_10
    move-object v0, v6

    .line 855
    check-cast v0, Lno/nordicsemi/android/ble/k0;

    .line 856
    .line 857
    iget-object v2, v0, Lno/nordicsemi/android/ble/i0;->d:Landroid/bluetooth/BluetoothGattCharacteristic;

    .line 858
    .line 859
    if-eqz v2, :cond_37

    .line 860
    .line 861
    iget v5, v1, Lno/nordicsemi/android/ble/d;->v:I

    .line 862
    .line 863
    iget-boolean v7, v0, Lno/nordicsemi/android/ble/k0;->n:Z

    .line 864
    .line 865
    if-eqz v7, :cond_2e

    .line 866
    .line 867
    goto :goto_13

    .line 868
    :cond_2e
    add-int/lit8 v11, v5, -0x3

    .line 869
    .line 870
    :goto_13
    iget-object v5, v0, Lno/nordicsemi/android/ble/k0;->m:[B

    .line 871
    .line 872
    array-length v7, v5

    .line 873
    if-ge v7, v11, :cond_2f

    .line 874
    .line 875
    goto :goto_14

    .line 876
    :cond_2f
    const/4 v7, 0x0

    .line 877
    invoke-static {v5, v7, v11}, Ljp/ta;->a([BII)[B

    .line 878
    .line 879
    .line 880
    move-result-object v5

    .line 881
    :goto_14
    invoke-virtual {v2, v5}, Landroid/bluetooth/BluetoothGattCharacteristic;->setValue([B)Z

    .line 882
    .line 883
    .line 884
    invoke-virtual {v0, v4}, Lno/nordicsemi/android/ble/i0;->d(Landroid/bluetooth/BluetoothDevice;)Z

    .line 885
    .line 886
    .line 887
    invoke-virtual {v1, v3}, Lno/nordicsemi/android/ble/d;->A(Z)V

    .line 888
    .line 889
    .line 890
    goto/16 :goto_9

    .line 891
    .line 892
    :pswitch_11
    iget-object v0, v6, Lno/nordicsemi/android/ble/i0;->d:Landroid/bluetooth/BluetoothGattCharacteristic;

    .line 893
    .line 894
    invoke-virtual {v1, v0}, Lno/nordicsemi/android/ble/d;->n(Landroid/bluetooth/BluetoothGattCharacteristic;)Z

    .line 895
    .line 896
    .line 897
    move-result v9

    .line 898
    goto/16 :goto_19

    .line 899
    .line 900
    :pswitch_12
    iget-object v0, v6, Lno/nordicsemi/android/ble/i0;->d:Landroid/bluetooth/BluetoothGattCharacteristic;

    .line 901
    .line 902
    invoke-virtual {v1, v0}, Lno/nordicsemi/android/ble/d;->n(Landroid/bluetooth/BluetoothGattCharacteristic;)Z

    .line 903
    .line 904
    .line 905
    move-result v9

    .line 906
    goto/16 :goto_19

    .line 907
    .line 908
    :pswitch_13
    iget-object v0, v6, Lno/nordicsemi/android/ble/i0;->d:Landroid/bluetooth/BluetoothGattCharacteristic;

    .line 909
    .line 910
    invoke-virtual {v1, v0}, Lno/nordicsemi/android/ble/d;->p(Landroid/bluetooth/BluetoothGattCharacteristic;)Z

    .line 911
    .line 912
    .line 913
    move-result v9

    .line 914
    goto/16 :goto_19

    .line 915
    .line 916
    :pswitch_14
    iget-object v0, v6, Lno/nordicsemi/android/ble/i0;->d:Landroid/bluetooth/BluetoothGattCharacteristic;

    .line 917
    .line 918
    invoke-virtual {v1, v0}, Lno/nordicsemi/android/ble/d;->q(Landroid/bluetooth/BluetoothGattCharacteristic;)Z

    .line 919
    .line 920
    .line 921
    move-result v9

    .line 922
    goto/16 :goto_19

    .line 923
    .line 924
    :pswitch_15
    invoke-virtual {v1}, Lno/nordicsemi/android/ble/d;->j()Z

    .line 925
    .line 926
    .line 927
    move-result v9

    .line 928
    goto/16 :goto_19

    .line 929
    .line 930
    :pswitch_16
    invoke-virtual {v1}, Lno/nordicsemi/android/ble/d;->r()Z

    .line 931
    .line 932
    .line 933
    move-result v9

    .line 934
    goto/16 :goto_19

    .line 935
    .line 936
    :pswitch_17
    invoke-virtual {v1}, Lno/nordicsemi/android/ble/d;->k()Z

    .line 937
    .line 938
    .line 939
    move-result v9

    .line 940
    if-eqz v9, :cond_37

    .line 941
    .line 942
    iget-object v0, v1, Lno/nordicsemi/android/ble/d;->z:Lno/nordicsemi/android/ble/i0;

    .line 943
    .line 944
    invoke-virtual {v0, v4}, Lno/nordicsemi/android/ble/i0;->d(Landroid/bluetooth/BluetoothDevice;)Z

    .line 945
    .line 946
    .line 947
    invoke-virtual {v1, v3}, Lno/nordicsemi/android/ble/d;->A(Z)V
    :try_end_a
    .catchall {:try_start_a .. :try_end_a} :catchall_0

    .line 948
    .line 949
    .line 950
    monitor-exit p0

    .line 951
    return-void

    .line 952
    :pswitch_18
    :try_start_b
    iget-object v0, v6, Lno/nordicsemi/android/ble/i0;->e:Landroid/bluetooth/BluetoothGattDescriptor;

    .line 953
    .line 954
    iget-object v2, v1, Lno/nordicsemi/android/ble/d;->c:Landroid/bluetooth/BluetoothGatt;

    .line 955
    .line 956
    if-eqz v2, :cond_35

    .line 957
    .line 958
    if-eqz v0, :cond_35

    .line 959
    .line 960
    iget-boolean v5, v1, Lno/nordicsemi/android/ble/d;->n:Z
    :try_end_b
    .catchall {:try_start_b .. :try_end_b} :catchall_0

    .line 961
    .line 962
    if-nez v5, :cond_30

    .line 963
    .line 964
    goto/16 :goto_17

    .line 965
    .line 966
    :cond_30
    :try_start_c
    iget-object v5, v1, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 967
    .line 968
    invoke-virtual {v5}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 969
    .line 970
    .line 971
    move-result v5

    .line 972
    if-lt v8, v5, :cond_31

    .line 973
    .line 974
    iget-object v5, v1, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 975
    .line 976
    new-instance v7, Ljava/lang/StringBuilder;

    .line 977
    .line 978
    const-string v9, "Reading descriptor "

    .line 979
    .line 980
    invoke-direct {v7, v9}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 981
    .line 982
    .line 983
    invoke-virtual {v0}, Landroid/bluetooth/BluetoothGattDescriptor;->getUuid()Ljava/util/UUID;

    .line 984
    .line 985
    .line 986
    move-result-object v9

    .line 987
    invoke-virtual {v7, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 988
    .line 989
    .line 990
    invoke-virtual {v7}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 991
    .line 992
    .line 993
    move-result-object v7

    .line 994
    invoke-virtual {v5, v8, v7}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 995
    .line 996
    .line 997
    :cond_31
    iget-object v5, v1, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 998
    .line 999
    invoke-virtual {v5}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 1000
    .line 1001
    .line 1002
    move-result v5

    .line 1003
    if-lt v10, v5, :cond_32

    .line 1004
    .line 1005
    iget-object v5, v1, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 1006
    .line 1007
    new-instance v7, Ljava/lang/StringBuilder;

    .line 1008
    .line 1009
    const-string v8, "gatt.readDescriptor("

    .line 1010
    .line 1011
    invoke-direct {v7, v8}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 1012
    .line 1013
    .line 1014
    invoke-virtual {v0}, Landroid/bluetooth/BluetoothGattDescriptor;->getUuid()Ljava/util/UUID;

    .line 1015
    .line 1016
    .line 1017
    move-result-object v8

    .line 1018
    invoke-virtual {v7, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 1019
    .line 1020
    .line 1021
    const-string v8, ")"

    .line 1022
    .line 1023
    invoke-virtual {v7, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1024
    .line 1025
    .line 1026
    invoke-virtual {v7}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1027
    .line 1028
    .line 1029
    move-result-object v7

    .line 1030
    invoke-virtual {v5, v10, v7}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 1031
    .line 1032
    .line 1033
    :cond_32
    invoke-virtual {v2, v0}, Landroid/bluetooth/BluetoothGatt;->readDescriptor(Landroid/bluetooth/BluetoothGattDescriptor;)Z

    .line 1034
    .line 1035
    .line 1036
    move-result v0
    :try_end_c
    .catch Ljava/lang/SecurityException; {:try_start_c .. :try_end_c} :catch_3
    .catchall {:try_start_c .. :try_end_c} :catchall_0

    .line 1037
    goto/16 :goto_10

    .line 1038
    .line 1039
    :catch_3
    move-exception v0

    .line 1040
    :try_start_d
    iget-object v2, v1, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 1041
    .line 1042
    invoke-virtual {v2}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 1043
    .line 1044
    .line 1045
    move-result v2

    .line 1046
    const/4 v5, 0x6

    .line 1047
    if-lt v5, v2, :cond_35

    .line 1048
    .line 1049
    iget-object v2, v1, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 1050
    .line 1051
    invoke-virtual {v0}, Ljava/lang/Throwable;->getLocalizedMessage()Ljava/lang/String;

    .line 1052
    .line 1053
    .line 1054
    move-result-object v0

    .line 1055
    invoke-virtual {v2, v5, v0}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 1056
    .line 1057
    .line 1058
    goto :goto_17

    .line 1059
    :pswitch_19
    move-object v0, v6

    .line 1060
    check-cast v0, Lno/nordicsemi/android/ble/v0;

    .line 1061
    .line 1062
    iget-object v2, v0, Lno/nordicsemi/android/ble/i0;->e:Landroid/bluetooth/BluetoothGattDescriptor;

    .line 1063
    .line 1064
    iput-boolean v3, v0, Lno/nordicsemi/android/ble/v0;->u:Z

    .line 1065
    .line 1066
    iget-object v5, v0, Lno/nordicsemi/android/ble/v0;->q:[B

    .line 1067
    .line 1068
    iput-object v5, v0, Lno/nordicsemi/android/ble/v0;->s:[B

    .line 1069
    .line 1070
    if-eqz v5, :cond_33

    .line 1071
    .line 1072
    goto :goto_15

    .line 1073
    :cond_33
    const/4 v7, 0x0

    .line 1074
    new-array v5, v7, [B

    .line 1075
    .line 1076
    :goto_15
    invoke-virtual {v1, v2, v5}, Lno/nordicsemi/android/ble/d;->y(Landroid/bluetooth/BluetoothGattDescriptor;[B)Z

    .line 1077
    .line 1078
    .line 1079
    move-result v9

    .line 1080
    goto :goto_19

    .line 1081
    :pswitch_1a
    iget-object v0, v6, Lno/nordicsemi/android/ble/i0;->d:Landroid/bluetooth/BluetoothGattCharacteristic;

    .line 1082
    .line 1083
    invoke-virtual {v1, v0}, Lno/nordicsemi/android/ble/d;->s(Landroid/bluetooth/BluetoothGattCharacteristic;)Z

    .line 1084
    .line 1085
    .line 1086
    move-result v9

    .line 1087
    goto :goto_19

    .line 1088
    :pswitch_1b
    move-object v0, v6

    .line 1089
    check-cast v0, Lno/nordicsemi/android/ble/v0;

    .line 1090
    .line 1091
    iput-boolean v3, v0, Lno/nordicsemi/android/ble/v0;->u:Z

    .line 1092
    .line 1093
    iget-object v2, v0, Lno/nordicsemi/android/ble/v0;->q:[B

    .line 1094
    .line 1095
    iput-object v2, v0, Lno/nordicsemi/android/ble/v0;->s:[B

    .line 1096
    .line 1097
    if-eqz v2, :cond_34

    .line 1098
    .line 1099
    goto :goto_16

    .line 1100
    :cond_34
    const/4 v7, 0x0

    .line 1101
    new-array v2, v7, [B

    .line 1102
    .line 1103
    :goto_16
    iget-object v0, v0, Lno/nordicsemi/android/ble/i0;->d:Landroid/bluetooth/BluetoothGattCharacteristic;

    .line 1104
    .line 1105
    if-eqz v0, :cond_35

    .line 1106
    .line 1107
    invoke-virtual {v0, v2}, Landroid/bluetooth/BluetoothGattCharacteristic;->setValue([B)Z

    .line 1108
    .line 1109
    .line 1110
    :cond_35
    :goto_17
    const/4 v9, 0x0

    .line 1111
    goto :goto_19

    .line 1112
    :pswitch_1c
    move-object v0, v6

    .line 1113
    check-cast v0, Lno/nordicsemi/android/ble/v0;

    .line 1114
    .line 1115
    iget-object v2, v0, Lno/nordicsemi/android/ble/i0;->d:Landroid/bluetooth/BluetoothGattCharacteristic;

    .line 1116
    .line 1117
    iput-boolean v3, v0, Lno/nordicsemi/android/ble/v0;->u:Z

    .line 1118
    .line 1119
    iget-object v5, v0, Lno/nordicsemi/android/ble/v0;->q:[B

    .line 1120
    .line 1121
    iput-object v5, v0, Lno/nordicsemi/android/ble/v0;->s:[B

    .line 1122
    .line 1123
    if-eqz v5, :cond_36

    .line 1124
    .line 1125
    goto :goto_18

    .line 1126
    :cond_36
    const/4 v7, 0x0

    .line 1127
    new-array v5, v7, [B

    .line 1128
    .line 1129
    :goto_18
    iget v0, v0, Lno/nordicsemi/android/ble/v0;->r:I

    .line 1130
    .line 1131
    invoke-virtual {v1, v2, v5, v0}, Lno/nordicsemi/android/ble/d;->x(Landroid/bluetooth/BluetoothGattCharacteristic;[BI)Z

    .line 1132
    .line 1133
    .line 1134
    move-result v9

    .line 1135
    goto :goto_19

    .line 1136
    :pswitch_1d
    invoke-virtual {v1}, Lno/nordicsemi/android/ble/d;->v()Z

    .line 1137
    .line 1138
    .line 1139
    move-result v9

    .line 1140
    goto :goto_19

    .line 1141
    :pswitch_1e
    invoke-virtual {v1, v3}, Lno/nordicsemi/android/ble/d;->m(Z)Z

    .line 1142
    .line 1143
    .line 1144
    move-result v9

    .line 1145
    goto :goto_19

    .line 1146
    :pswitch_1f
    move v7, v2

    .line 1147
    invoke-virtual {v1, v7}, Lno/nordicsemi/android/ble/d;->m(Z)Z

    .line 1148
    .line 1149
    .line 1150
    move-result v9

    .line 1151
    goto :goto_19

    .line 1152
    :pswitch_20
    move v7, v2

    .line 1153
    invoke-virtual {v1, v7}, Lno/nordicsemi/android/ble/d;->o(I)V

    .line 1154
    .line 1155
    .line 1156
    goto/16 :goto_9

    .line 1157
    .line 1158
    :pswitch_21
    move-object v0, v6

    .line 1159
    check-cast v0, Lno/nordicsemi/android/ble/x;

    .line 1160
    .line 1161
    iput-object v0, v1, Lno/nordicsemi/android/ble/d;->y:Lno/nordicsemi/android/ble/x;

    .line 1162
    .line 1163
    const/4 v2, 0x0

    .line 1164
    iput-object v2, v1, Lno/nordicsemi/android/ble/d;->z:Lno/nordicsemi/android/ble/i0;

    .line 1165
    .line 1166
    iget-object v2, v0, Lno/nordicsemi/android/ble/x;->p:Landroid/bluetooth/BluetoothDevice;

    .line 1167
    .line 1168
    invoke-virtual {v1, v2, v0}, Lno/nordicsemi/android/ble/d;->l(Landroid/bluetooth/BluetoothDevice;Lno/nordicsemi/android/ble/x;)Z

    .line 1169
    .line 1170
    .line 1171
    move-result v9

    .line 1172
    :cond_37
    :goto_19
    if-nez v9, :cond_3a

    .line 1173
    .line 1174
    if-eqz v4, :cond_3a

    .line 1175
    .line 1176
    iget-boolean v0, v1, Lno/nordicsemi/android/ble/d;->n:Z

    .line 1177
    .line 1178
    if-eqz v0, :cond_38

    .line 1179
    .line 1180
    const/4 v0, -0x3

    .line 1181
    goto :goto_1a

    .line 1182
    :cond_38
    invoke-static {}, Landroid/bluetooth/BluetoothAdapter;->getDefaultAdapter()Landroid/bluetooth/BluetoothAdapter;

    .line 1183
    .line 1184
    .line 1185
    move-result-object v0

    .line 1186
    invoke-virtual {v0}, Landroid/bluetooth/BluetoothAdapter;->isEnabled()Z

    .line 1187
    .line 1188
    .line 1189
    move-result v0

    .line 1190
    if-eqz v0, :cond_39

    .line 1191
    .line 1192
    const/4 v0, -0x1

    .line 1193
    goto :goto_1a

    .line 1194
    :cond_39
    const/16 v0, -0x64

    .line 1195
    .line 1196
    :goto_1a
    invoke-virtual {v6, v0, v4}, Lno/nordicsemi/android/ble/i0;->a(ILandroid/bluetooth/BluetoothDevice;)V

    .line 1197
    .line 1198
    .line 1199
    const/4 v2, 0x0

    .line 1200
    iput-object v2, v1, Lno/nordicsemi/android/ble/d;->E:Lno/nordicsemi/android/ble/a;

    .line 1201
    .line 1202
    const/4 v7, 0x0

    .line 1203
    iput-boolean v7, v1, Lno/nordicsemi/android/ble/d;->t:Z

    .line 1204
    .line 1205
    invoke-virtual {v1, v3}, Lno/nordicsemi/android/ble/d;->A(Z)V
    :try_end_d
    .catchall {:try_start_d .. :try_end_d} :catchall_0

    .line 1206
    .line 1207
    .line 1208
    :cond_3a
    monitor-exit p0

    .line 1209
    return-void

    .line 1210
    :pswitch_22
    :try_start_e
    check-cast v6, Lno/nordicsemi/android/ble/j0;

    .line 1211
    .line 1212
    iput-object v6, v1, Lno/nordicsemi/android/ble/d;->A:Lno/nordicsemi/android/ble/j0;

    .line 1213
    .line 1214
    invoke-virtual {v1, v3}, Lno/nordicsemi/android/ble/d;->A(Z)V
    :try_end_e
    .catchall {:try_start_e .. :try_end_e} :catchall_0

    .line 1215
    .line 1216
    .line 1217
    monitor-exit p0

    .line 1218
    return-void

    .line 1219
    :cond_3b
    :try_start_f
    invoke-virtual {v6}, Lno/nordicsemi/android/ble/i0;->b()V

    .line 1220
    .line 1221
    .line 1222
    const/4 v2, 0x0

    .line 1223
    iput-object v2, v1, Lno/nordicsemi/android/ble/d;->E:Lno/nordicsemi/android/ble/a;

    .line 1224
    .line 1225
    invoke-virtual {v1, v3}, Lno/nordicsemi/android/ble/d;->A(Z)V
    :try_end_f
    .catchall {:try_start_f .. :try_end_f} :catchall_0

    .line 1226
    .line 1227
    .line 1228
    monitor-exit p0

    .line 1229
    return-void

    .line 1230
    :goto_1b
    :try_start_10
    monitor-exit p0
    :try_end_10
    .catchall {:try_start_10 .. :try_end_10} :catchall_0

    .line 1231
    throw v0

    .line 1232
    nop

    .line 1233
    :pswitch_data_0
    .packed-switch 0x13
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch

    .line 1234
    .line 1235
    .line 1236
    .line 1237
    .line 1238
    .line 1239
    .line 1240
    .line 1241
    .line 1242
    .line 1243
    .line 1244
    .line 1245
    :pswitch_data_1
    .packed-switch 0x0
        :pswitch_22
        :pswitch_21
        :pswitch_20
        :pswitch_1f
        :pswitch_1e
        :pswitch_1d
        :pswitch_1c
        :pswitch_1b
        :pswitch_1b
        :pswitch_1a
        :pswitch_19
        :pswitch_18
        :pswitch_17
        :pswitch_16
        :pswitch_15
        :pswitch_14
        :pswitch_13
        :pswitch_12
        :pswitch_11
    .end packed-switch

    .line 1246
    .line 1247
    .line 1248
    .line 1249
    .line 1250
    .line 1251
    .line 1252
    .line 1253
    .line 1254
    .line 1255
    .line 1256
    .line 1257
    .line 1258
    .line 1259
    .line 1260
    .line 1261
    .line 1262
    .line 1263
    .line 1264
    .line 1265
    .line 1266
    .line 1267
    .line 1268
    .line 1269
    .line 1270
    .line 1271
    .line 1272
    .line 1273
    .line 1274
    .line 1275
    .line 1276
    .line 1277
    .line 1278
    .line 1279
    .line 1280
    .line 1281
    .line 1282
    .line 1283
    .line 1284
    .line 1285
    .line 1286
    .line 1287
    :pswitch_data_2
    .packed-switch 0x18
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
    .end packed-switch
.end method

.method public final B(ILandroid/bluetooth/BluetoothDevice;)V
    .locals 6

    .line 1
    iget v0, p0, Lno/nordicsemi/android/ble/d;->s:I

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    goto/16 :goto_2

    .line 6
    .line 7
    :cond_0
    iget-boolean v0, p0, Lno/nordicsemi/android/ble/d;->n:Z

    .line 8
    .line 9
    iget-boolean v1, p0, Lno/nordicsemi/android/ble/d;->i:Z

    .line 10
    .line 11
    const/4 v2, 0x0

    .line 12
    iput-boolean v2, p0, Lno/nordicsemi/android/ble/d;->n:Z

    .line 13
    .line 14
    iput-boolean v2, p0, Lno/nordicsemi/android/ble/d;->o:Z

    .line 15
    .line 16
    iput-boolean v2, p0, Lno/nordicsemi/android/ble/d;->i:Z

    .line 17
    .line 18
    iput-boolean v2, p0, Lno/nordicsemi/android/ble/d;->k:Z

    .line 19
    .line 20
    iput-boolean v2, p0, Lno/nordicsemi/android/ble/d;->j:Z

    .line 21
    .line 22
    const/16 v3, 0x17

    .line 23
    .line 24
    iput v3, p0, Lno/nordicsemi/android/ble/d;->v:I

    .line 25
    .line 26
    iput v2, p0, Lno/nordicsemi/android/ble/d;->w:I

    .line 27
    .line 28
    iput v2, p0, Lno/nordicsemi/android/ble/d;->s:I

    .line 29
    .line 30
    invoke-virtual {p0}, Lno/nordicsemi/android/ble/d;->b()Z

    .line 31
    .line 32
    .line 33
    const/4 v2, 0x0

    .line 34
    const/4 v3, 0x5

    .line 35
    if-nez v0, :cond_2

    .line 36
    .line 37
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 38
    .line 39
    invoke-virtual {v0}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 40
    .line 41
    .line 42
    move-result v0

    .line 43
    if-lt v3, v0, :cond_1

    .line 44
    .line 45
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 46
    .line 47
    const-string v4, "Connection attempt timed out"

    .line 48
    .line 49
    invoke-virtual {v0, v3, v4}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 50
    .line 51
    .line 52
    :cond_1
    invoke-virtual {p0}, Lno/nordicsemi/android/ble/d;->c()V

    .line 53
    .line 54
    .line 55
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 56
    .line 57
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 58
    .line 59
    .line 60
    new-instance v0, Lno/nordicsemi/android/ble/i;

    .line 61
    .line 62
    const/4 v3, 0x0

    .line 63
    invoke-direct {v0, p1, v3, p2}, Lno/nordicsemi/android/ble/i;-><init>(IILandroid/bluetooth/BluetoothDevice;)V

    .line 64
    .line 65
    .line 66
    invoke-virtual {p0, v0}, Lno/nordicsemi/android/ble/d;->D(Lno/nordicsemi/android/ble/s;)V

    .line 67
    .line 68
    .line 69
    goto :goto_0

    .line 70
    :cond_2
    iget-boolean v0, p0, Lno/nordicsemi/android/ble/d;->q:Z

    .line 71
    .line 72
    const/4 v4, 0x3

    .line 73
    if-eqz v0, :cond_6

    .line 74
    .line 75
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 76
    .line 77
    invoke-virtual {v0}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 78
    .line 79
    .line 80
    move-result v0

    .line 81
    const/4 v3, 0x4

    .line 82
    if-lt v3, v0, :cond_3

    .line 83
    .line 84
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 85
    .line 86
    const-string v5, "Disconnected"

    .line 87
    .line 88
    invoke-virtual {v0, v3, v5}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 89
    .line 90
    .line 91
    :cond_3
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->z:Lno/nordicsemi/android/ble/i0;

    .line 92
    .line 93
    if-eqz v0, :cond_4

    .line 94
    .line 95
    iget v3, v0, Lno/nordicsemi/android/ble/i0;->c:I

    .line 96
    .line 97
    const/4 v5, 0x6

    .line 98
    if-eq v3, v5, :cond_5

    .line 99
    .line 100
    :cond_4
    invoke-virtual {p0}, Lno/nordicsemi/android/ble/d;->c()V

    .line 101
    .line 102
    .line 103
    :cond_5
    iget-object v3, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 104
    .line 105
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 106
    .line 107
    .line 108
    new-instance v3, Lno/nordicsemi/android/ble/i;

    .line 109
    .line 110
    const/4 v5, 0x1

    .line 111
    invoke-direct {v3, p1, v5, p2}, Lno/nordicsemi/android/ble/i;-><init>(IILandroid/bluetooth/BluetoothDevice;)V

    .line 112
    .line 113
    .line 114
    invoke-virtual {p0, v3}, Lno/nordicsemi/android/ble/d;->D(Lno/nordicsemi/android/ble/s;)V

    .line 115
    .line 116
    .line 117
    if-eqz v0, :cond_9

    .line 118
    .line 119
    iget p1, v0, Lno/nordicsemi/android/ble/i0;->c:I

    .line 120
    .line 121
    if-ne p1, v4, :cond_9

    .line 122
    .line 123
    invoke-virtual {v0, p2}, Lno/nordicsemi/android/ble/i0;->d(Landroid/bluetooth/BluetoothDevice;)Z

    .line 124
    .line 125
    .line 126
    iput-object v2, p0, Lno/nordicsemi/android/ble/d;->z:Lno/nordicsemi/android/ble/i0;

    .line 127
    .line 128
    goto :goto_0

    .line 129
    :cond_6
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 130
    .line 131
    invoke-virtual {v0}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 132
    .line 133
    .line 134
    move-result v0

    .line 135
    if-lt v3, v0, :cond_7

    .line 136
    .line 137
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 138
    .line 139
    const-string v5, "Connection lost"

    .line 140
    .line 141
    invoke-virtual {v0, v3, v5}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 142
    .line 143
    .line 144
    :cond_7
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 145
    .line 146
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 147
    .line 148
    .line 149
    const/4 v0, 0x2

    .line 150
    if-ne p1, v0, :cond_8

    .line 151
    .line 152
    move v4, v0

    .line 153
    :cond_8
    new-instance p1, Lno/nordicsemi/android/ble/i;

    .line 154
    .line 155
    const/4 v0, 0x2

    .line 156
    invoke-direct {p1, v4, v0, p2}, Lno/nordicsemi/android/ble/i;-><init>(IILandroid/bluetooth/BluetoothDevice;)V

    .line 157
    .line 158
    .line 159
    invoke-virtual {p0, p1}, Lno/nordicsemi/android/ble/d;->D(Lno/nordicsemi/android/ble/s;)V

    .line 160
    .line 161
    .line 162
    :cond_9
    :goto_0
    iget-object p1, p0, Lno/nordicsemi/android/ble/d;->B:Ljava/util/HashMap;

    .line 163
    .line 164
    monitor-enter p1

    .line 165
    :try_start_0
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->B:Ljava/util/HashMap;

    .line 166
    .line 167
    invoke-virtual {p2}, Ljava/util/HashMap;->values()Ljava/util/Collection;

    .line 168
    .line 169
    .line 170
    move-result-object p2

    .line 171
    invoke-interface {p2}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 172
    .line 173
    .line 174
    move-result-object p2

    .line 175
    :goto_1
    invoke-interface {p2}, Ljava/util/Iterator;->hasNext()Z

    .line 176
    .line 177
    .line 178
    move-result v0

    .line 179
    if-eqz v0, :cond_a

    .line 180
    .line 181
    invoke-interface {p2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 182
    .line 183
    .line 184
    move-result-object v0

    .line 185
    check-cast v0, Lno/nordicsemi/android/ble/r0;

    .line 186
    .line 187
    iput-object v2, v0, Lno/nordicsemi/android/ble/r0;->a:Lyz0/b;

    .line 188
    .line 189
    goto :goto_1

    .line 190
    :catchall_0
    move-exception p0

    .line 191
    goto :goto_3

    .line 192
    :cond_a
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->B:Ljava/util/HashMap;

    .line 193
    .line 194
    invoke-virtual {p2}, Ljava/util/HashMap;->clear()V

    .line 195
    .line 196
    .line 197
    monitor-exit p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 198
    iget-object p1, p0, Lno/nordicsemi/android/ble/d;->C:Ljava/util/HashMap;

    .line 199
    .line 200
    invoke-virtual {p1}, Ljava/util/HashMap;->clear()V

    .line 201
    .line 202
    .line 203
    iput-object v2, p0, Lno/nordicsemi/android/ble/d;->D:Lno/nordicsemi/android/ble/r0;

    .line 204
    .line 205
    const/4 p1, -0x1

    .line 206
    iput p1, p0, Lno/nordicsemi/android/ble/d;->x:I

    .line 207
    .line 208
    if-eqz v1, :cond_b

    .line 209
    .line 210
    iget-object p0, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 211
    .line 212
    invoke-virtual {p0}, Lno/nordicsemi/android/ble/e;->onServicesInvalidated()V

    .line 213
    .line 214
    .line 215
    :cond_b
    :goto_2
    return-void

    .line 216
    :goto_3
    :try_start_1
    monitor-exit p1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 217
    throw p0
.end method

.method public final C(Ljava/lang/Runnable;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lno/nordicsemi/android/ble/d;->e:Landroid/os/Handler;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final D(Lno/nordicsemi/android/ble/s;)V
    .locals 3

    .line 1
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 2
    .line 3
    iget-object v0, v0, Lno/nordicsemi/android/ble/e;->connectionObserver:Lb01/b;

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    new-instance v1, Lh0/h0;

    .line 8
    .line 9
    const/16 v2, 0x1b

    .line 10
    .line 11
    invoke-direct {v1, v2, p1, v0}, Lh0/h0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 12
    .line 13
    .line 14
    invoke-virtual {p0, v1}, Lno/nordicsemi/android/ble/d;->C(Ljava/lang/Runnable;)V

    .line 15
    .line 16
    .line 17
    :cond_0
    return-void
.end method

.method public final E(Ljava/lang/Runnable;J)V
    .locals 2

    .line 1
    new-instance p0, Ljava/util/Timer;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/util/Timer;-><init>()V

    .line 4
    .line 5
    .line 6
    new-instance v0, Lhg0/e;

    .line 7
    .line 8
    const/4 v1, 0x1

    .line 9
    invoke-direct {v0, p1, v1}, Lhg0/e;-><init>(Ljava/lang/Object;I)V

    .line 10
    .line 11
    .line 12
    invoke-virtual {p0, v0, p2, p3}, Ljava/util/Timer;->schedule(Ljava/util/TimerTask;J)V

    .line 13
    .line 14
    .line 15
    return-void
.end method

.method public final F(Landroid/os/Parcelable;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->B:Ljava/util/HashMap;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object p0, p0, Lno/nordicsemi/android/ble/d;->B:Ljava/util/HashMap;

    .line 5
    .line 6
    invoke-virtual {p0, p1}, Ljava/util/HashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    check-cast p0, Lno/nordicsemi/android/ble/r0;

    .line 11
    .line 12
    if-eqz p0, :cond_0

    .line 13
    .line 14
    const/4 p1, 0x0

    .line 15
    iput-object p1, p0, Lno/nordicsemi/android/ble/r0;->a:Lyz0/b;

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :catchall_0
    move-exception p0

    .line 19
    goto :goto_1

    .line 20
    :cond_0
    :goto_0
    monitor-exit v0

    .line 21
    return-void

    .line 22
    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 23
    throw p0
.end method

.method public final b()Z
    .locals 4

    .line 1
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->E:Lno/nordicsemi/android/ble/a;

    .line 2
    .line 3
    instance-of v1, v0, Lno/nordicsemi/android/ble/w;

    .line 4
    .line 5
    if-eqz v1, :cond_1

    .line 6
    .line 7
    check-cast v0, Lno/nordicsemi/android/ble/w;

    .line 8
    .line 9
    invoke-virtual {v0}, Lno/nordicsemi/android/ble/w;->h()Z

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    if-eqz v1, :cond_1

    .line 14
    .line 15
    iget-object v1, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 16
    .line 17
    invoke-virtual {v1}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    const/4 v2, 0x4

    .line 22
    if-lt v2, v1, :cond_0

    .line 23
    .line 24
    iget-object v1, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 25
    .line 26
    const-string v3, "Condition fulfilled"

    .line 27
    .line 28
    invoke-virtual {v1, v2, v3}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 29
    .line 30
    .line 31
    :cond_0
    iget-object v1, p0, Lno/nordicsemi/android/ble/d;->b:Landroid/bluetooth/BluetoothDevice;

    .line 32
    .line 33
    invoke-virtual {v0, v1}, Lno/nordicsemi/android/ble/p0;->d(Landroid/bluetooth/BluetoothDevice;)Z

    .line 34
    .line 35
    .line 36
    const/4 v0, 0x0

    .line 37
    iput-object v0, p0, Lno/nordicsemi/android/ble/d;->E:Lno/nordicsemi/android/ble/a;

    .line 38
    .line 39
    const/4 p0, 0x1

    .line 40
    return p0

    .line 41
    :cond_1
    const/4 p0, 0x0

    .line 42
    return p0
.end method

.method public final c()V
    .locals 7

    .line 1
    :try_start_0
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 2
    .line 3
    invoke-virtual {v0}, Lno/nordicsemi/android/ble/e;->getContext()Landroid/content/Context;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    iget-object v1, p0, Lno/nordicsemi/android/ble/d;->F:Lno/nordicsemi/android/ble/l;

    .line 8
    .line 9
    invoke-virtual {v0, v1}, Landroid/content/Context;->unregisterReceiver(Landroid/content/BroadcastReceiver;)V

    .line 10
    .line 11
    .line 12
    iget-object v1, p0, Lno/nordicsemi/android/ble/d;->G:Lno/nordicsemi/android/ble/l;

    .line 13
    .line 14
    invoke-virtual {v0, v1}, Landroid/content/Context;->unregisterReceiver(Landroid/content/BroadcastReceiver;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 15
    .line 16
    .line 17
    :catch_0
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->a:Ljava/lang/Object;

    .line 18
    .line 19
    monitor-enter v0

    .line 20
    :try_start_1
    iget-boolean v1, p0, Lno/nordicsemi/android/ble/d;->n:Z

    .line 21
    .line 22
    iget-object v2, p0, Lno/nordicsemi/android/ble/d;->b:Landroid/bluetooth/BluetoothDevice;

    .line 23
    .line 24
    iget-object v3, p0, Lno/nordicsemi/android/ble/d;->c:Landroid/bluetooth/BluetoothGatt;

    .line 25
    .line 26
    const/4 v4, 0x0

    .line 27
    if-eqz v3, :cond_3

    .line 28
    .line 29
    iget-object v3, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 30
    .line 31
    invoke-virtual {v3}, Lno/nordicsemi/android/ble/e;->shouldClearCacheWhenDisconnected()Z

    .line 32
    .line 33
    .line 34
    move-result v3

    .line 35
    if-eqz v3, :cond_1

    .line 36
    .line 37
    invoke-virtual {p0}, Lno/nordicsemi/android/ble/d;->u()Z

    .line 38
    .line 39
    .line 40
    move-result v3

    .line 41
    if-eqz v3, :cond_0

    .line 42
    .line 43
    iget-object v3, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 44
    .line 45
    invoke-virtual {v3}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 46
    .line 47
    .line 48
    move-result v3

    .line 49
    const/4 v5, 0x4

    .line 50
    if-lt v5, v3, :cond_1

    .line 51
    .line 52
    iget-object v3, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 53
    .line 54
    const-string v6, "Cache refreshed"

    .line 55
    .line 56
    invoke-virtual {v3, v5, v6}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 57
    .line 58
    .line 59
    goto :goto_0

    .line 60
    :cond_0
    iget-object v3, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 61
    .line 62
    invoke-virtual {v3}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 63
    .line 64
    .line 65
    move-result v3

    .line 66
    const/4 v5, 0x5

    .line 67
    if-lt v5, v3, :cond_1

    .line 68
    .line 69
    iget-object v3, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 70
    .line 71
    const-string v6, "Refreshing failed"

    .line 72
    .line 73
    invoke-virtual {v3, v5, v6}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 74
    .line 75
    .line 76
    goto :goto_0

    .line 77
    :catchall_0
    move-exception p0

    .line 78
    goto :goto_1

    .line 79
    :cond_1
    :goto_0
    iget-object v3, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 80
    .line 81
    invoke-virtual {v3}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 82
    .line 83
    .line 84
    move-result v3

    .line 85
    const/4 v5, 0x3

    .line 86
    if-lt v5, v3, :cond_2

    .line 87
    .line 88
    iget-object v3, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 89
    .line 90
    const-string v6, "gatt.close()"

    .line 91
    .line 92
    invoke-virtual {v3, v5, v6}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 93
    .line 94
    .line 95
    :cond_2
    :try_start_2
    iget-object v3, p0, Lno/nordicsemi/android/ble/d;->c:Landroid/bluetooth/BluetoothGatt;

    .line 96
    .line 97
    invoke-virtual {v3}, Landroid/bluetooth/BluetoothGatt;->close()V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 98
    .line 99
    .line 100
    :catchall_1
    :try_start_3
    iput-object v4, p0, Lno/nordicsemi/android/ble/d;->c:Landroid/bluetooth/BluetoothGatt;

    .line 101
    .line 102
    :cond_3
    const/4 v3, 0x0

    .line 103
    iput-boolean v3, p0, Lno/nordicsemi/android/ble/d;->u:Z

    .line 104
    .line 105
    iput-boolean v3, p0, Lno/nordicsemi/android/ble/d;->r:Z

    .line 106
    .line 107
    const/4 v5, -0x1

    .line 108
    invoke-virtual {p0, v5}, Lno/nordicsemi/android/ble/d;->f(I)V

    .line 109
    .line 110
    .line 111
    iput-boolean v3, p0, Lno/nordicsemi/android/ble/d;->h:Z

    .line 112
    .line 113
    iput-object v4, p0, Lno/nordicsemi/android/ble/d;->b:Landroid/bluetooth/BluetoothDevice;

    .line 114
    .line 115
    iput-boolean v3, p0, Lno/nordicsemi/android/ble/d;->n:Z

    .line 116
    .line 117
    iput v3, p0, Lno/nordicsemi/android/ble/d;->s:I

    .line 118
    .line 119
    const/16 v4, 0x17

    .line 120
    .line 121
    iput v4, p0, Lno/nordicsemi/android/ble/d;->v:I

    .line 122
    .line 123
    iput v3, p0, Lno/nordicsemi/android/ble/d;->w:I

    .line 124
    .line 125
    if-eqz v1, :cond_4

    .line 126
    .line 127
    if-eqz v2, :cond_4

    .line 128
    .line 129
    iget-object v1, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 130
    .line 131
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 132
    .line 133
    .line 134
    new-instance v1, Lno/nordicsemi/android/ble/g;

    .line 135
    .line 136
    const/4 v3, 0x2

    .line 137
    invoke-direct {v1, v3, v2}, Lno/nordicsemi/android/ble/g;-><init>(ILandroid/bluetooth/BluetoothDevice;)V

    .line 138
    .line 139
    .line 140
    invoke-virtual {p0, v1}, Lno/nordicsemi/android/ble/d;->D(Lno/nordicsemi/android/ble/s;)V

    .line 141
    .line 142
    .line 143
    :cond_4
    monitor-exit v0

    .line 144
    return-void

    .line 145
    :goto_1
    monitor-exit v0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 146
    throw p0
.end method

.method public final f(I)V
    .locals 4

    .line 1
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->b:Landroid/bluetooth/BluetoothDevice;

    .line 2
    .line 3
    iget-object v1, p0, Lno/nordicsemi/android/ble/d;->g:Ljava/util/concurrent/LinkedBlockingDeque;

    .line 4
    .line 5
    if-eqz v1, :cond_2

    .line 6
    .line 7
    invoke-virtual {v1}, Ljava/util/concurrent/LinkedBlockingDeque;->iterator()Ljava/util/Iterator;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 12
    .line 13
    .line 14
    move-result v2

    .line 15
    if-eqz v2, :cond_1

    .line 16
    .line 17
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object v2

    .line 21
    check-cast v2, Lno/nordicsemi/android/ble/i0;

    .line 22
    .line 23
    if-eqz v0, :cond_0

    .line 24
    .line 25
    invoke-virtual {v2, p1, v0}, Lno/nordicsemi/android/ble/i0;->a(ILandroid/bluetooth/BluetoothDevice;)V

    .line 26
    .line 27
    .line 28
    goto :goto_0

    .line 29
    :cond_0
    invoke-virtual {v2}, Lno/nordicsemi/android/ble/i0;->b()V

    .line 30
    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_1
    const/4 v1, 0x0

    .line 34
    iput-object v1, p0, Lno/nordicsemi/android/ble/d;->g:Ljava/util/concurrent/LinkedBlockingDeque;

    .line 35
    .line 36
    :cond_2
    iget-object p0, p0, Lno/nordicsemi/android/ble/d;->f:Ljava/util/concurrent/LinkedBlockingDeque;

    .line 37
    .line 38
    invoke-virtual {p0}, Ljava/util/concurrent/LinkedBlockingDeque;->iterator()Ljava/util/Iterator;

    .line 39
    .line 40
    .line 41
    move-result-object v1

    .line 42
    :goto_1
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 43
    .line 44
    .line 45
    move-result v2

    .line 46
    if-eqz v2, :cond_6

    .line 47
    .line 48
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 49
    .line 50
    .line 51
    move-result-object v2

    .line 52
    check-cast v2, Lno/nordicsemi/android/ble/i0;

    .line 53
    .line 54
    if-eqz v0, :cond_5

    .line 55
    .line 56
    const/16 v3, -0x64

    .line 57
    .line 58
    if-eq p1, v3, :cond_4

    .line 59
    .line 60
    iget-object v3, v2, Lno/nordicsemi/android/ble/i0;->d:Landroid/bluetooth/BluetoothGattCharacteristic;

    .line 61
    .line 62
    if-nez v3, :cond_4

    .line 63
    .line 64
    iget-object v3, v2, Lno/nordicsemi/android/ble/i0;->e:Landroid/bluetooth/BluetoothGattDescriptor;

    .line 65
    .line 66
    if-eqz v3, :cond_3

    .line 67
    .line 68
    goto :goto_2

    .line 69
    :cond_3
    const/4 v3, -0x7

    .line 70
    invoke-virtual {v2, v3, v0}, Lno/nordicsemi/android/ble/i0;->a(ILandroid/bluetooth/BluetoothDevice;)V

    .line 71
    .line 72
    .line 73
    goto :goto_1

    .line 74
    :cond_4
    :goto_2
    invoke-virtual {v2, p1, v0}, Lno/nordicsemi/android/ble/i0;->a(ILandroid/bluetooth/BluetoothDevice;)V

    .line 75
    .line 76
    .line 77
    goto :goto_1

    .line 78
    :cond_5
    invoke-virtual {v2}, Lno/nordicsemi/android/ble/i0;->b()V

    .line 79
    .line 80
    .line 81
    goto :goto_1

    .line 82
    :cond_6
    invoke-virtual {p0}, Ljava/util/concurrent/LinkedBlockingDeque;->clear()V

    .line 83
    .line 84
    .line 85
    return-void
.end method

.method public final g(Lno/nordicsemi/android/ble/i0;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->A:Lno/nordicsemi/android/ble/j0;

    .line 2
    .line 3
    if-nez v0, :cond_1

    .line 4
    .line 5
    iget-boolean v0, p0, Lno/nordicsemi/android/ble/d;->h:Z

    .line 6
    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->g:Ljava/util/concurrent/LinkedBlockingDeque;

    .line 10
    .line 11
    if-eqz v0, :cond_0

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->f:Ljava/util/concurrent/LinkedBlockingDeque;

    .line 15
    .line 16
    :goto_0
    invoke-interface {v0, p1}, Ljava/util/Deque;->addFirst(Ljava/lang/Object;)V

    .line 17
    .line 18
    .line 19
    goto :goto_1

    .line 20
    :cond_1
    iget-object v0, v0, Lno/nordicsemi/android/ble/j0;->p:Ljava/util/LinkedList;

    .line 21
    .line 22
    invoke-virtual {v0, p1}, Ljava/util/LinkedList;->addFirst(Ljava/lang/Object;)V

    .line 23
    .line 24
    .line 25
    :goto_1
    const/4 v0, 0x1

    .line 26
    iput-boolean v0, p1, Lno/nordicsemi/android/ble/i0;->i:Z

    .line 27
    .line 28
    const/4 p1, 0x0

    .line 29
    iput-boolean p1, p0, Lno/nordicsemi/android/ble/d;->p:Z

    .line 30
    .line 31
    return-void
.end method

.method public final i(Landroid/os/Parcelable;)Lno/nordicsemi/android/ble/r0;
    .locals 2

    .line 1
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->B:Ljava/util/HashMap;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Lno/nordicsemi/android/ble/r0;

    .line 8
    .line 9
    if-nez v0, :cond_1

    .line 10
    .line 11
    new-instance v0, Lno/nordicsemi/android/ble/r0;

    .line 12
    .line 13
    invoke-direct {v0, p0}, Lno/nordicsemi/android/ble/r0;-><init>(Lno/nordicsemi/android/ble/d;)V

    .line 14
    .line 15
    .line 16
    if-eqz p1, :cond_0

    .line 17
    .line 18
    iget-object v1, p0, Lno/nordicsemi/android/ble/d;->B:Ljava/util/HashMap;

    .line 19
    .line 20
    monitor-enter v1

    .line 21
    :try_start_0
    iget-object p0, p0, Lno/nordicsemi/android/ble/d;->B:Ljava/util/HashMap;

    .line 22
    .line 23
    invoke-virtual {p0, p1, v0}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    monitor-exit v1

    .line 27
    return-object v0

    .line 28
    :catchall_0
    move-exception p0

    .line 29
    monitor-exit v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 30
    throw p0

    .line 31
    :cond_0
    return-object v0

    .line 32
    :cond_1
    iget-object p0, p0, Lno/nordicsemi/android/ble/d;->b:Landroid/bluetooth/BluetoothDevice;

    .line 33
    .line 34
    if-eqz p0, :cond_2

    .line 35
    .line 36
    const/4 p0, 0x0

    .line 37
    iput-object p0, v0, Lno/nordicsemi/android/ble/r0;->a:Lyz0/b;

    .line 38
    .line 39
    :cond_2
    return-object v0
.end method

.method public final j()Z
    .locals 4

    .line 1
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->c:Landroid/bluetooth/BluetoothGatt;

    .line 2
    .line 3
    if-eqz v0, :cond_4

    .line 4
    .line 5
    iget-boolean v1, p0, Lno/nordicsemi/android/ble/d;->n:Z

    .line 6
    .line 7
    if-nez v1, :cond_0

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    iget-boolean v1, p0, Lno/nordicsemi/android/ble/d;->u:Z

    .line 11
    .line 12
    if-nez v1, :cond_1

    .line 13
    .line 14
    goto :goto_0

    .line 15
    :cond_1
    :try_start_0
    iget-object v1, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 16
    .line 17
    invoke-virtual {v1}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    const/4 v2, 0x2

    .line 22
    if-lt v2, v1, :cond_2

    .line 23
    .line 24
    iget-object v1, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 25
    .line 26
    const-string v3, "Aborting reliable write..."

    .line 27
    .line 28
    invoke-virtual {v1, v2, v3}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 29
    .line 30
    .line 31
    :cond_2
    iget-object v1, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 32
    .line 33
    invoke-virtual {v1}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 34
    .line 35
    .line 36
    move-result v1

    .line 37
    const/4 v2, 0x3

    .line 38
    if-lt v2, v1, :cond_3

    .line 39
    .line 40
    iget-object v1, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 41
    .line 42
    const-string v3, "gatt.abortReliableWrite()"

    .line 43
    .line 44
    invoke-virtual {v1, v2, v3}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 45
    .line 46
    .line 47
    :cond_3
    invoke-virtual {v0}, Landroid/bluetooth/BluetoothGatt;->abortReliableWrite()V
    :try_end_0
    .catch Ljava/lang/SecurityException; {:try_start_0 .. :try_end_0} :catch_0

    .line 48
    .line 49
    .line 50
    const/4 p0, 0x1

    .line 51
    return p0

    .line 52
    :catch_0
    move-exception v0

    .line 53
    iget-object v1, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 54
    .line 55
    invoke-virtual {v1}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 56
    .line 57
    .line 58
    move-result v1

    .line 59
    const/4 v2, 0x6

    .line 60
    if-lt v2, v1, :cond_4

    .line 61
    .line 62
    iget-object p0, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 63
    .line 64
    invoke-virtual {v0}, Ljava/lang/Throwable;->getLocalizedMessage()Ljava/lang/String;

    .line 65
    .line 66
    .line 67
    move-result-object v0

    .line 68
    invoke-virtual {p0, v2, v0}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 69
    .line 70
    .line 71
    :cond_4
    :goto_0
    const/4 p0, 0x0

    .line 72
    return p0
.end method

.method public final k()Z
    .locals 4

    .line 1
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->c:Landroid/bluetooth/BluetoothGatt;

    .line 2
    .line 3
    if-eqz v0, :cond_4

    .line 4
    .line 5
    iget-boolean v1, p0, Lno/nordicsemi/android/ble/d;->n:Z

    .line 6
    .line 7
    if-nez v1, :cond_0

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    iget-boolean v1, p0, Lno/nordicsemi/android/ble/d;->u:Z

    .line 11
    .line 12
    if-eqz v1, :cond_1

    .line 13
    .line 14
    const/4 p0, 0x1

    .line 15
    return p0

    .line 16
    :cond_1
    iget-object v1, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 17
    .line 18
    invoke-virtual {v1}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 19
    .line 20
    .line 21
    move-result v1

    .line 22
    const/4 v2, 0x2

    .line 23
    if-lt v2, v1, :cond_2

    .line 24
    .line 25
    iget-object v1, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 26
    .line 27
    const-string v3, "Beginning reliable write..."

    .line 28
    .line 29
    invoke-virtual {v1, v2, v3}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 30
    .line 31
    .line 32
    :cond_2
    iget-object v1, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 33
    .line 34
    invoke-virtual {v1}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 35
    .line 36
    .line 37
    move-result v1

    .line 38
    const/4 v2, 0x3

    .line 39
    if-lt v2, v1, :cond_3

    .line 40
    .line 41
    iget-object v1, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 42
    .line 43
    const-string v3, "gatt.beginReliableWrite()"

    .line 44
    .line 45
    invoke-virtual {v1, v2, v3}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 46
    .line 47
    .line 48
    :cond_3
    :try_start_0
    invoke-virtual {v0}, Landroid/bluetooth/BluetoothGatt;->beginReliableWrite()Z

    .line 49
    .line 50
    .line 51
    move-result v0

    .line 52
    iput-boolean v0, p0, Lno/nordicsemi/android/ble/d;->u:Z
    :try_end_0
    .catch Ljava/lang/SecurityException; {:try_start_0 .. :try_end_0} :catch_0

    .line 53
    .line 54
    return v0

    .line 55
    :catch_0
    move-exception v0

    .line 56
    iget-object v1, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 57
    .line 58
    invoke-virtual {v1}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 59
    .line 60
    .line 61
    move-result v1

    .line 62
    const/4 v2, 0x6

    .line 63
    if-lt v2, v1, :cond_4

    .line 64
    .line 65
    iget-object p0, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 66
    .line 67
    invoke-virtual {v0}, Ljava/lang/Throwable;->getLocalizedMessage()Ljava/lang/String;

    .line 68
    .line 69
    .line 70
    move-result-object v0

    .line 71
    invoke-virtual {p0, v2, v0}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 72
    .line 73
    .line 74
    :cond_4
    :goto_0
    const/4 p0, 0x0

    .line 75
    return p0
.end method

.method public final l(Landroid/bluetooth/BluetoothDevice;Lno/nordicsemi/android/ble/x;)Z
    .locals 11

    .line 1
    invoke-static {}, Landroid/bluetooth/BluetoothAdapter;->getDefaultAdapter()Landroid/bluetooth/BluetoothAdapter;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-virtual {v0}, Landroid/bluetooth/BluetoothAdapter;->isEnabled()Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    iget-boolean v1, p0, Lno/nordicsemi/android/ble/d;->n:Z

    .line 10
    .line 11
    const/4 v2, 0x0

    .line 12
    const/4 v3, 0x1

    .line 13
    if-nez v1, :cond_0

    .line 14
    .line 15
    if-nez v0, :cond_1

    .line 16
    .line 17
    :cond_0
    move-object v4, p1

    .line 18
    goto/16 :goto_6

    .line 19
    .line 20
    :cond_1
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 21
    .line 22
    invoke-virtual {v0}, Lno/nordicsemi/android/ble/e;->getContext()Landroid/content/Context;

    .line 23
    .line 24
    .line 25
    move-result-object v5

    .line 26
    iget-object v1, p0, Lno/nordicsemi/android/ble/d;->a:Ljava/lang/Object;

    .line 27
    .line 28
    monitor-enter v1

    .line 29
    :try_start_0
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->c:Landroid/bluetooth/BluetoothGatt;

    .line 30
    .line 31
    const/4 v4, 0x0

    .line 32
    const/4 v6, 0x2

    .line 33
    const/4 v7, 0x3

    .line 34
    if-eqz v0, :cond_c

    .line 35
    .line 36
    iget-boolean v0, p0, Lno/nordicsemi/android/ble/d;->r:Z

    .line 37
    .line 38
    if-nez v0, :cond_5

    .line 39
    .line 40
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 41
    .line 42
    invoke-virtual {v0}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 43
    .line 44
    .line 45
    move-result v0

    .line 46
    if-lt v7, v0, :cond_2

    .line 47
    .line 48
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 49
    .line 50
    const-string v8, "gatt.close()"

    .line 51
    .line 52
    invoke-virtual {v0, v7, v8}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 53
    .line 54
    .line 55
    :cond_2
    :try_start_1
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->c:Landroid/bluetooth/BluetoothGatt;

    .line 56
    .line 57
    invoke-virtual {v0}, Landroid/bluetooth/BluetoothGatt;->close()V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 58
    .line 59
    .line 60
    :catchall_0
    :try_start_2
    iput-object v2, p0, Lno/nordicsemi/android/ble/d;->c:Landroid/bluetooth/BluetoothGatt;
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 61
    .line 62
    :try_start_3
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 63
    .line 64
    invoke-virtual {v0}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 65
    .line 66
    .line 67
    move-result v0

    .line 68
    if-lt v7, v0, :cond_3

    .line 69
    .line 70
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 71
    .line 72
    const-string v8, "wait(200)"

    .line 73
    .line 74
    invoke-virtual {v0, v7, v8}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 75
    .line 76
    .line 77
    :cond_3
    const-wide/16 v8, 0xc8

    .line 78
    .line 79
    invoke-static {v8, v9}, Ljava/lang/Thread;->sleep(J)V

    .line 80
    .line 81
    .line 82
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->c:Landroid/bluetooth/BluetoothGatt;

    .line 83
    .line 84
    if-nez v0, :cond_4

    .line 85
    .line 86
    if-eqz p2, :cond_d

    .line 87
    .line 88
    iget-boolean v0, p2, Lno/nordicsemi/android/ble/i0;->k:Z
    :try_end_3
    .catch Ljava/lang/InterruptedException; {:try_start_3 .. :try_end_3} :catch_0
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 89
    .line 90
    if-eqz v0, :cond_d

    .line 91
    .line 92
    goto :goto_0

    .line 93
    :catchall_1
    move-exception v0

    .line 94
    move-object p0, v0

    .line 95
    goto/16 :goto_5

    .line 96
    .line 97
    :cond_4
    :goto_0
    :try_start_4
    monitor-exit v1

    .line 98
    goto/16 :goto_4

    .line 99
    .line 100
    :cond_5
    iput-boolean v4, p0, Lno/nordicsemi/android/ble/d;->r:Z

    .line 101
    .line 102
    const-wide/16 v8, 0x0

    .line 103
    .line 104
    iput-wide v8, p0, Lno/nordicsemi/android/ble/d;->l:J

    .line 105
    .line 106
    iput v3, p0, Lno/nordicsemi/android/ble/d;->s:I

    .line 107
    .line 108
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 109
    .line 110
    invoke-virtual {v0}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 111
    .line 112
    .line 113
    move-result v0

    .line 114
    if-lt v6, v0, :cond_6

    .line 115
    .line 116
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 117
    .line 118
    const-string v2, "Connecting..."

    .line 119
    .line 120
    invoke-virtual {v0, v6, v2}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 121
    .line 122
    .line 123
    :cond_6
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 124
    .line 125
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 126
    .line 127
    .line 128
    new-instance v0, Lno/nordicsemi/android/ble/g;

    .line 129
    .line 130
    const/4 v2, 0x1

    .line 131
    invoke-direct {v0, v2, p1}, Lno/nordicsemi/android/ble/g;-><init>(ILandroid/bluetooth/BluetoothDevice;)V

    .line 132
    .line 133
    .line 134
    invoke-virtual {p0, v0}, Lno/nordicsemi/android/ble/d;->D(Lno/nordicsemi/android/ble/s;)V

    .line 135
    .line 136
    .line 137
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 138
    .line 139
    const/16 v2, 0x22

    .line 140
    .line 141
    if-lt v0, v2, :cond_a

    .line 142
    .line 143
    if-eqz p2, :cond_7

    .line 144
    .line 145
    iget p2, p2, Lno/nordicsemi/android/ble/x;->q:I

    .line 146
    .line 147
    move v9, p2

    .line 148
    goto :goto_1

    .line 149
    :cond_7
    move v9, v3

    .line 150
    :goto_1
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->c:Landroid/bluetooth/BluetoothGatt;

    .line 151
    .line 152
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 153
    .line 154
    invoke-virtual {v0}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 155
    .line 156
    .line 157
    move-result v0

    .line 158
    if-lt v7, v0, :cond_8

    .line 159
    .line 160
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 161
    .line 162
    const-string v2, "gatt.close()"

    .line 163
    .line 164
    invoke-virtual {v0, v7, v2}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 165
    .line 166
    .line 167
    :cond_8
    invoke-virtual {p2}, Landroid/bluetooth/BluetoothGatt;->close()V

    .line 168
    .line 169
    .line 170
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 171
    .line 172
    invoke-virtual {p2}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 173
    .line 174
    .line 175
    move-result p2

    .line 176
    if-lt v7, p2, :cond_9

    .line 177
    .line 178
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 179
    .line 180
    new-instance v0, Ljava/lang/StringBuilder;

    .line 181
    .line 182
    const-string v2, "gatt = device.connectGatt(autoConnect = true, TRANSPORT_LE, "

    .line 183
    .line 184
    invoke-direct {v0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 185
    .line 186
    .line 187
    invoke-static {v9}, Lc01/a;->c(I)Ljava/lang/String;

    .line 188
    .line 189
    .line 190
    move-result-object v2

    .line 191
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 192
    .line 193
    .line 194
    const-string v2, ")"

    .line 195
    .line 196
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 197
    .line 198
    .line 199
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 200
    .line 201
    .line 202
    move-result-object v0

    .line 203
    invoke-virtual {p2, v7, v0}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 204
    .line 205
    .line 206
    :cond_9
    iget-object v7, p0, Lno/nordicsemi/android/ble/d;->H:Landroid/bluetooth/BluetoothGattCallback;

    .line 207
    .line 208
    iget-object v10, p0, Lno/nordicsemi/android/ble/d;->e:Landroid/os/Handler;

    .line 209
    .line 210
    const/4 v6, 0x1

    .line 211
    const/4 v8, 0x2

    .line 212
    move-object v4, p1

    .line 213
    invoke-virtual/range {v4 .. v10}, Landroid/bluetooth/BluetoothDevice;->connectGatt(Landroid/content/Context;ZLandroid/bluetooth/BluetoothGattCallback;IILandroid/os/Handler;)Landroid/bluetooth/BluetoothGatt;

    .line 214
    .line 215
    .line 216
    move-result-object p1

    .line 217
    iput-object p1, p0, Lno/nordicsemi/android/ble/d;->c:Landroid/bluetooth/BluetoothGatt;

    .line 218
    .line 219
    goto :goto_2

    .line 220
    :cond_a
    iget-object p1, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 221
    .line 222
    invoke-virtual {p1}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 223
    .line 224
    .line 225
    move-result p1

    .line 226
    if-lt v7, p1, :cond_b

    .line 227
    .line 228
    iget-object p1, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 229
    .line 230
    const-string p2, "gatt.connect()"

    .line 231
    .line 232
    invoke-virtual {p1, v7, p2}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 233
    .line 234
    .line 235
    :cond_b
    iget-object p0, p0, Lno/nordicsemi/android/ble/d;->c:Landroid/bluetooth/BluetoothGatt;

    .line 236
    .line 237
    invoke-virtual {p0}, Landroid/bluetooth/BluetoothGatt;->connect()Z

    .line 238
    .line 239
    .line 240
    :goto_2
    monitor-exit v1

    .line 241
    return v3

    .line 242
    :cond_c
    if-eqz p2, :cond_d

    .line 243
    .line 244
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->F:Lno/nordicsemi/android/ble/l;

    .line 245
    .line 246
    new-instance v8, Landroid/content/IntentFilter;

    .line 247
    .line 248
    const-string v9, "android.bluetooth.adapter.action.STATE_CHANGED"

    .line 249
    .line 250
    invoke-direct {v8, v9}, Landroid/content/IntentFilter;-><init>(Ljava/lang/String;)V

    .line 251
    .line 252
    .line 253
    invoke-static {v5, v0, v8, v6}, Ln5/a;->d(Landroid/content/Context;Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;I)V

    .line 254
    .line 255
    .line 256
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->G:Lno/nordicsemi/android/ble/l;

    .line 257
    .line 258
    new-instance v8, Landroid/content/IntentFilter;

    .line 259
    .line 260
    const-string v9, "android.bluetooth.device.action.BOND_STATE_CHANGED"

    .line 261
    .line 262
    invoke-direct {v8, v9}, Landroid/content/IntentFilter;-><init>(Ljava/lang/String;)V

    .line 263
    .line 264
    .line 265
    invoke-static {v5, v0, v8, v6}, Ln5/a;->d(Landroid/content/Context;Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;I)V

    .line 266
    .line 267
    .line 268
    :catch_0
    :cond_d
    monitor-exit v1
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 269
    if-nez p2, :cond_e

    .line 270
    .line 271
    return v4

    .line 272
    :cond_e
    iget-boolean v0, p2, Lno/nordicsemi/android/ble/x;->u:Z

    .line 273
    .line 274
    if-eqz v0, :cond_f

    .line 275
    .line 276
    iget-boolean v1, p2, Lno/nordicsemi/android/ble/x;->v:Z

    .line 277
    .line 278
    iput-boolean v1, p0, Lno/nordicsemi/android/ble/d;->r:Z

    .line 279
    .line 280
    xor-int/lit8 v4, v1, 0x1

    .line 281
    .line 282
    :cond_f
    xor-int/2addr v0, v3

    .line 283
    iput-boolean v0, p0, Lno/nordicsemi/android/ble/d;->q:Z

    .line 284
    .line 285
    iput-object p1, p0, Lno/nordicsemi/android/ble/d;->b:Landroid/bluetooth/BluetoothDevice;

    .line 286
    .line 287
    if-nez v4, :cond_12

    .line 288
    .line 289
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 290
    .line 291
    invoke-virtual {v0}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 292
    .line 293
    .line 294
    move-result v0

    .line 295
    if-lt v6, v0, :cond_11

    .line 296
    .line 297
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 298
    .line 299
    iget v1, p2, Lno/nordicsemi/android/ble/x;->r:I

    .line 300
    .line 301
    add-int/lit8 v8, v1, 0x1

    .line 302
    .line 303
    iput v8, p2, Lno/nordicsemi/android/ble/x;->r:I

    .line 304
    .line 305
    if-nez v1, :cond_10

    .line 306
    .line 307
    const-string v1, "Connecting..."

    .line 308
    .line 309
    goto :goto_3

    .line 310
    :cond_10
    const-string v1, "Retrying..."

    .line 311
    .line 312
    :goto_3
    invoke-virtual {v0, v6, v1}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 313
    .line 314
    .line 315
    :cond_11
    iput v3, p0, Lno/nordicsemi/android/ble/d;->s:I

    .line 316
    .line 317
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 318
    .line 319
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 320
    .line 321
    .line 322
    new-instance v0, Lno/nordicsemi/android/ble/g;

    .line 323
    .line 324
    const/4 v1, 0x0

    .line 325
    invoke-direct {v0, v1, p1}, Lno/nordicsemi/android/ble/g;-><init>(ILandroid/bluetooth/BluetoothDevice;)V

    .line 326
    .line 327
    .line 328
    invoke-virtual {p0, v0}, Lno/nordicsemi/android/ble/d;->D(Lno/nordicsemi/android/ble/s;)V

    .line 329
    .line 330
    .line 331
    :cond_12
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 332
    .line 333
    .line 334
    move-result-wide v0

    .line 335
    iput-wide v0, p0, Lno/nordicsemi/android/ble/d;->l:J

    .line 336
    .line 337
    iget v9, p2, Lno/nordicsemi/android/ble/x;->q:I

    .line 338
    .line 339
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 340
    .line 341
    invoke-virtual {p2}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 342
    .line 343
    .line 344
    move-result p2

    .line 345
    if-lt v7, p2, :cond_13

    .line 346
    .line 347
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 348
    .line 349
    new-instance v0, Ljava/lang/StringBuilder;

    .line 350
    .line 351
    const-string v1, "gatt = device.connectGatt(autoConnect = "

    .line 352
    .line 353
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 354
    .line 355
    .line 356
    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 357
    .line 358
    .line 359
    const-string v1, ", TRANSPORT_LE, "

    .line 360
    .line 361
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 362
    .line 363
    .line 364
    invoke-static {v9}, Lc01/a;->c(I)Ljava/lang/String;

    .line 365
    .line 366
    .line 367
    move-result-object v1

    .line 368
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 369
    .line 370
    .line 371
    const-string v1, ")"

    .line 372
    .line 373
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 374
    .line 375
    .line 376
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 377
    .line 378
    .line 379
    move-result-object v0

    .line 380
    invoke-virtual {p2, v7, v0}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 381
    .line 382
    .line 383
    :cond_13
    iget-object v7, p0, Lno/nordicsemi/android/ble/d;->H:Landroid/bluetooth/BluetoothGattCallback;

    .line 384
    .line 385
    const/4 v8, 0x2

    .line 386
    iget-object v10, p0, Lno/nordicsemi/android/ble/d;->e:Landroid/os/Handler;

    .line 387
    .line 388
    move v6, v4

    .line 389
    move-object v4, p1

    .line 390
    invoke-virtual/range {v4 .. v10}, Landroid/bluetooth/BluetoothDevice;->connectGatt(Landroid/content/Context;ZLandroid/bluetooth/BluetoothGattCallback;IILandroid/os/Handler;)Landroid/bluetooth/BluetoothGatt;

    .line 391
    .line 392
    .line 393
    move-result-object p1

    .line 394
    iput-object p1, p0, Lno/nordicsemi/android/ble/d;->c:Landroid/bluetooth/BluetoothGatt;

    .line 395
    .line 396
    if-eqz v6, :cond_14

    .line 397
    .line 398
    iget-object p1, p0, Lno/nordicsemi/android/ble/d;->y:Lno/nordicsemi/android/ble/x;

    .line 399
    .line 400
    if-eqz p1, :cond_14

    .line 401
    .line 402
    invoke-virtual {p1, v4}, Lno/nordicsemi/android/ble/p0;->d(Landroid/bluetooth/BluetoothDevice;)Z

    .line 403
    .line 404
    .line 405
    iput-object v2, p0, Lno/nordicsemi/android/ble/d;->y:Lno/nordicsemi/android/ble/x;

    .line 406
    .line 407
    :cond_14
    :goto_4
    return v3

    .line 408
    :goto_5
    :try_start_5
    monitor-exit v1
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_1

    .line 409
    throw p0

    .line 410
    :goto_6
    iget-object p1, p0, Lno/nordicsemi/android/ble/d;->b:Landroid/bluetooth/BluetoothDevice;

    .line 411
    .line 412
    if-eqz v0, :cond_15

    .line 413
    .line 414
    if-eqz p1, :cond_15

    .line 415
    .line 416
    invoke-virtual {p1, v4}, Landroid/bluetooth/BluetoothDevice;->equals(Ljava/lang/Object;)Z

    .line 417
    .line 418
    .line 419
    move-result p1

    .line 420
    if-eqz p1, :cond_15

    .line 421
    .line 422
    iget-object p1, p0, Lno/nordicsemi/android/ble/d;->y:Lno/nordicsemi/android/ble/x;

    .line 423
    .line 424
    if-eqz p1, :cond_17

    .line 425
    .line 426
    invoke-virtual {p1, v4}, Lno/nordicsemi/android/ble/p0;->d(Landroid/bluetooth/BluetoothDevice;)Z

    .line 427
    .line 428
    .line 429
    goto :goto_8

    .line 430
    :cond_15
    iget-object p1, p0, Lno/nordicsemi/android/ble/d;->y:Lno/nordicsemi/android/ble/x;

    .line 431
    .line 432
    if-eqz p1, :cond_17

    .line 433
    .line 434
    if-eqz v0, :cond_16

    .line 435
    .line 436
    const/4 p2, -0x4

    .line 437
    goto :goto_7

    .line 438
    :cond_16
    const/16 p2, -0x64

    .line 439
    .line 440
    :goto_7
    invoke-virtual {p1, p2, v4}, Lno/nordicsemi/android/ble/p0;->a(ILandroid/bluetooth/BluetoothDevice;)V

    .line 441
    .line 442
    .line 443
    :cond_17
    :goto_8
    iput-object v2, p0, Lno/nordicsemi/android/ble/d;->y:Lno/nordicsemi/android/ble/x;

    .line 444
    .line 445
    invoke-virtual {p0, v3}, Lno/nordicsemi/android/ble/d;->A(Z)V

    .line 446
    .line 447
    .line 448
    return v3
.end method

.method public final m(Z)Z
    .locals 5

    .line 1
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->b:Landroid/bluetooth/BluetoothDevice;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    const/4 p0, 0x0

    .line 6
    return p0

    .line 7
    :cond_0
    const/4 v1, 0x2

    .line 8
    if-eqz p1, :cond_1

    .line 9
    .line 10
    iget-object v2, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 11
    .line 12
    invoke-virtual {v2}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 13
    .line 14
    .line 15
    move-result v2

    .line 16
    if-lt v1, v2, :cond_2

    .line 17
    .line 18
    iget-object v2, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 19
    .line 20
    const-string v3, "Ensuring bonding..."

    .line 21
    .line 22
    invoke-virtual {v2, v1, v3}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 23
    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_1
    iget-object v2, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 27
    .line 28
    invoke-virtual {v2}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 29
    .line 30
    .line 31
    move-result v2

    .line 32
    if-lt v1, v2, :cond_2

    .line 33
    .line 34
    iget-object v2, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 35
    .line 36
    const-string v3, "Starting bonding..."

    .line 37
    .line 38
    invoke-virtual {v2, v1, v3}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 39
    .line 40
    .line 41
    :cond_2
    :goto_0
    const/4 v1, 0x1

    .line 42
    if-nez p1, :cond_4

    .line 43
    .line 44
    invoke-virtual {v0}, Landroid/bluetooth/BluetoothDevice;->getBondState()I

    .line 45
    .line 46
    .line 47
    move-result v2

    .line 48
    const/16 v3, 0xc

    .line 49
    .line 50
    if-ne v2, v3, :cond_4

    .line 51
    .line 52
    iget-object p1, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 53
    .line 54
    invoke-virtual {p1}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 55
    .line 56
    .line 57
    move-result p1

    .line 58
    const/4 v2, 0x5

    .line 59
    if-lt v2, p1, :cond_3

    .line 60
    .line 61
    iget-object p1, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 62
    .line 63
    const-string v3, "Bond information present on client, skipping bonding"

    .line 64
    .line 65
    invoke-virtual {p1, v2, v3}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 66
    .line 67
    .line 68
    :cond_3
    iget-object p1, p0, Lno/nordicsemi/android/ble/d;->z:Lno/nordicsemi/android/ble/i0;

    .line 69
    .line 70
    invoke-virtual {p1, v0}, Lno/nordicsemi/android/ble/i0;->d(Landroid/bluetooth/BluetoothDevice;)Z

    .line 71
    .line 72
    .line 73
    invoke-virtual {p0, v1}, Lno/nordicsemi/android/ble/d;->A(Z)V

    .line 74
    .line 75
    .line 76
    return v1

    .line 77
    :cond_4
    iget-object v2, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 78
    .line 79
    invoke-virtual {v2}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 80
    .line 81
    .line 82
    move-result v2

    .line 83
    const/4 v3, 0x3

    .line 84
    if-lt v3, v2, :cond_5

    .line 85
    .line 86
    iget-object v2, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 87
    .line 88
    const-string v4, "device.createBond()"

    .line 89
    .line 90
    invoke-virtual {v2, v3, v4}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 91
    .line 92
    .line 93
    :cond_5
    invoke-virtual {v0}, Landroid/bluetooth/BluetoothDevice;->createBond()Z

    .line 94
    .line 95
    .line 96
    move-result v0

    .line 97
    if-eqz p1, :cond_6

    .line 98
    .line 99
    if-nez v0, :cond_6

    .line 100
    .line 101
    new-instance p1, Lno/nordicsemi/android/ble/l0;

    .line 102
    .line 103
    const/4 v0, 0x4

    .line 104
    invoke-direct {p1, v0}, Lno/nordicsemi/android/ble/i0;-><init>(I)V

    .line 105
    .line 106
    .line 107
    invoke-virtual {p1, p0}, Lno/nordicsemi/android/ble/i0;->e(Lno/nordicsemi/android/ble/d;)Lno/nordicsemi/android/ble/i0;

    .line 108
    .line 109
    .line 110
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->z:Lno/nordicsemi/android/ble/i0;

    .line 111
    .line 112
    iget-object v2, v0, Lno/nordicsemi/android/ble/i0;->g:Lyz0/d;

    .line 113
    .line 114
    iput-object v2, p1, Lno/nordicsemi/android/ble/i0;->g:Lyz0/d;

    .line 115
    .line 116
    iget-object v2, v0, Lno/nordicsemi/android/ble/i0;->h:Lyz0/c;

    .line 117
    .line 118
    iput-object v2, p1, Lno/nordicsemi/android/ble/i0;->h:Lyz0/c;

    .line 119
    .line 120
    const/4 v2, 0x0

    .line 121
    iput-object v2, v0, Lno/nordicsemi/android/ble/i0;->g:Lyz0/d;

    .line 122
    .line 123
    iput-object v2, v0, Lno/nordicsemi/android/ble/i0;->h:Lyz0/c;

    .line 124
    .line 125
    invoke-virtual {p0, p1}, Lno/nordicsemi/android/ble/d;->g(Lno/nordicsemi/android/ble/i0;)V

    .line 126
    .line 127
    .line 128
    new-instance p1, Lno/nordicsemi/android/ble/l0;

    .line 129
    .line 130
    const/4 v0, 0x6

    .line 131
    invoke-direct {p1, v0}, Lno/nordicsemi/android/ble/i0;-><init>(I)V

    .line 132
    .line 133
    .line 134
    invoke-virtual {p1, p0}, Lno/nordicsemi/android/ble/i0;->e(Lno/nordicsemi/android/ble/d;)Lno/nordicsemi/android/ble/i0;

    .line 135
    .line 136
    .line 137
    invoke-virtual {p0, p1}, Lno/nordicsemi/android/ble/d;->g(Lno/nordicsemi/android/ble/i0;)V

    .line 138
    .line 139
    .line 140
    invoke-virtual {p0, v1}, Lno/nordicsemi/android/ble/d;->A(Z)V

    .line 141
    .line 142
    .line 143
    return v1

    .line 144
    :cond_6
    return v0
.end method

.method public final n(Landroid/bluetooth/BluetoothGattCharacteristic;)Z
    .locals 9

    .line 1
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->c:Landroid/bluetooth/BluetoothGatt;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_7

    .line 5
    .line 6
    if-eqz p1, :cond_7

    .line 7
    .line 8
    iget-boolean v2, p0, Lno/nordicsemi/android/ble/d;->n:Z

    .line 9
    .line 10
    if-nez v2, :cond_0

    .line 11
    .line 12
    goto/16 :goto_1

    .line 13
    .line 14
    :cond_0
    const/16 v2, 0x30

    .line 15
    .line 16
    invoke-static {v2, p1}, Lno/nordicsemi/android/ble/d;->h(ILandroid/bluetooth/BluetoothGattCharacteristic;)Landroid/bluetooth/BluetoothGattDescriptor;

    .line 17
    .line 18
    .line 19
    move-result-object v2

    .line 20
    if-eqz v2, :cond_7

    .line 21
    .line 22
    iget-object v3, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 23
    .line 24
    invoke-virtual {v3}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 25
    .line 26
    .line 27
    move-result v3

    .line 28
    const/4 v4, 0x3

    .line 29
    if-lt v4, v3, :cond_1

    .line 30
    .line 31
    iget-object v3, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 32
    .line 33
    new-instance v5, Ljava/lang/StringBuilder;

    .line 34
    .line 35
    const-string v6, "gatt.setCharacteristicNotification("

    .line 36
    .line 37
    invoke-direct {v5, v6}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 38
    .line 39
    .line 40
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGattCharacteristic;->getUuid()Ljava/util/UUID;

    .line 41
    .line 42
    .line 43
    move-result-object v6

    .line 44
    invoke-virtual {v5, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 45
    .line 46
    .line 47
    const-string v6, ", false)"

    .line 48
    .line 49
    invoke-virtual {v5, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 50
    .line 51
    .line 52
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object v5

    .line 56
    invoke-virtual {v3, v4, v5}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 57
    .line 58
    .line 59
    :cond_1
    const/4 v3, 0x6

    .line 60
    :try_start_0
    invoke-virtual {v0, p1, v1}, Landroid/bluetooth/BluetoothGatt;->setCharacteristicNotification(Landroid/bluetooth/BluetoothGattCharacteristic;Z)Z
    :try_end_0
    .catch Ljava/lang/SecurityException; {:try_start_0 .. :try_end_0} :catch_1

    .line 61
    .line 62
    .line 63
    iget-object v5, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 64
    .line 65
    invoke-virtual {v5}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 66
    .line 67
    .line 68
    move-result v5

    .line 69
    const/4 v6, 0x2

    .line 70
    if-lt v6, v5, :cond_2

    .line 71
    .line 72
    iget-object v5, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 73
    .line 74
    new-instance v7, Ljava/lang/StringBuilder;

    .line 75
    .line 76
    const-string v8, "Disabling notifications and indications for "

    .line 77
    .line 78
    invoke-direct {v7, v8}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 79
    .line 80
    .line 81
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGattCharacteristic;->getUuid()Ljava/util/UUID;

    .line 82
    .line 83
    .line 84
    move-result-object p1

    .line 85
    invoke-virtual {v7, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 86
    .line 87
    .line 88
    invoke-virtual {v7}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 89
    .line 90
    .line 91
    move-result-object p1

    .line 92
    invoke-virtual {v5, v6, p1}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 93
    .line 94
    .line 95
    :cond_2
    :try_start_1
    sget p1, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 96
    .line 97
    const/16 v5, 0x21

    .line 98
    .line 99
    if-lt p1, v5, :cond_4

    .line 100
    .line 101
    iget-object p1, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 102
    .line 103
    invoke-virtual {p1}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 104
    .line 105
    .line 106
    move-result p1

    .line 107
    if-lt v4, p1, :cond_3

    .line 108
    .line 109
    iget-object p1, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 110
    .line 111
    const-string v5, "gatt.writeDescriptor(00002902-0000-1000-8000-00805f9b34fb, value=0x00-00)"

    .line 112
    .line 113
    invoke-virtual {p1, v4, v5}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 114
    .line 115
    .line 116
    :cond_3
    sget-object p1, Landroid/bluetooth/BluetoothGattDescriptor;->DISABLE_NOTIFICATION_VALUE:[B

    .line 117
    .line 118
    invoke-static {v0, v2, p1}, Li2/p0;->c(Landroid/bluetooth/BluetoothGatt;Landroid/bluetooth/BluetoothGattDescriptor;[B)I

    .line 119
    .line 120
    .line 121
    move-result p0

    .line 122
    if-nez p0, :cond_7

    .line 123
    .line 124
    const/4 p0, 0x1

    .line 125
    return p0

    .line 126
    :catch_0
    move-exception p1

    .line 127
    goto :goto_0

    .line 128
    :cond_4
    iget-object p1, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 129
    .line 130
    invoke-virtual {p1}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 131
    .line 132
    .line 133
    move-result p1

    .line 134
    if-lt v4, p1, :cond_5

    .line 135
    .line 136
    iget-object p1, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 137
    .line 138
    const-string v5, "descriptor.setValue(0x00-00)"

    .line 139
    .line 140
    invoke-virtual {p1, v4, v5}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 141
    .line 142
    .line 143
    :cond_5
    sget-object p1, Landroid/bluetooth/BluetoothGattDescriptor;->DISABLE_NOTIFICATION_VALUE:[B

    .line 144
    .line 145
    invoke-virtual {v2, p1}, Landroid/bluetooth/BluetoothGattDescriptor;->setValue([B)Z

    .line 146
    .line 147
    .line 148
    iget-object p1, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 149
    .line 150
    invoke-virtual {p1}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 151
    .line 152
    .line 153
    move-result p1

    .line 154
    if-lt v4, p1, :cond_6

    .line 155
    .line 156
    iget-object p1, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 157
    .line 158
    const-string v5, "gatt.writeDescriptor(00002902-0000-1000-8000-00805f9b34fb)"

    .line 159
    .line 160
    invoke-virtual {p1, v4, v5}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 161
    .line 162
    .line 163
    :cond_6
    invoke-virtual {v0, v2}, Landroid/bluetooth/BluetoothGatt;->writeDescriptor(Landroid/bluetooth/BluetoothGattDescriptor;)Z

    .line 164
    .line 165
    .line 166
    move-result p0
    :try_end_1
    .catch Ljava/lang/SecurityException; {:try_start_1 .. :try_end_1} :catch_0

    .line 167
    return p0

    .line 168
    :goto_0
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 169
    .line 170
    invoke-virtual {v0}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 171
    .line 172
    .line 173
    move-result v0

    .line 174
    if-lt v3, v0, :cond_7

    .line 175
    .line 176
    iget-object p0, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 177
    .line 178
    invoke-virtual {p1}, Ljava/lang/Throwable;->getLocalizedMessage()Ljava/lang/String;

    .line 179
    .line 180
    .line 181
    move-result-object p1

    .line 182
    invoke-virtual {p0, v3, p1}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 183
    .line 184
    .line 185
    goto :goto_1

    .line 186
    :catch_1
    move-exception p1

    .line 187
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 188
    .line 189
    invoke-virtual {v0}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 190
    .line 191
    .line 192
    move-result v0

    .line 193
    if-lt v3, v0, :cond_7

    .line 194
    .line 195
    iget-object p0, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 196
    .line 197
    invoke-virtual {p1}, Ljava/lang/Throwable;->getLocalizedMessage()Ljava/lang/String;

    .line 198
    .line 199
    .line 200
    move-result-object p1

    .line 201
    invoke-virtual {p0, v3, p1}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 202
    .line 203
    .line 204
    :cond_7
    :goto_1
    return v1
.end method

.method public final o(I)V
    .locals 10

    .line 1
    const/4 v0, 0x1

    .line 2
    iput-boolean v0, p0, Lno/nordicsemi/android/ble/d;->q:Z

    .line 3
    .line 4
    const/4 v1, 0x0

    .line 5
    iput-boolean v1, p0, Lno/nordicsemi/android/ble/d;->r:Z

    .line 6
    .line 7
    iput-boolean v1, p0, Lno/nordicsemi/android/ble/d;->o:Z

    .line 8
    .line 9
    iget-object v2, p0, Lno/nordicsemi/android/ble/d;->b:Landroid/bluetooth/BluetoothDevice;

    .line 10
    .line 11
    iget-object v3, p0, Lno/nordicsemi/android/ble/d;->c:Landroid/bluetooth/BluetoothGatt;

    .line 12
    .line 13
    const/4 v4, 0x3

    .line 14
    if-eqz v3, :cond_7

    .line 15
    .line 16
    iget-boolean v5, p0, Lno/nordicsemi/android/ble/d;->n:Z

    .line 17
    .line 18
    iput v4, p0, Lno/nordicsemi/android/ble/d;->s:I

    .line 19
    .line 20
    iget-object v6, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 21
    .line 22
    invoke-virtual {v6}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 23
    .line 24
    .line 25
    move-result v6

    .line 26
    const/4 v7, 0x2

    .line 27
    if-lt v7, v6, :cond_1

    .line 28
    .line 29
    iget-object v6, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 30
    .line 31
    if-eqz v5, :cond_0

    .line 32
    .line 33
    const-string v8, "Disconnecting..."

    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_0
    const-string v8, "Cancelling connection..."

    .line 37
    .line 38
    :goto_0
    invoke-virtual {v6, v7, v8}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 39
    .line 40
    .line 41
    :cond_1
    invoke-virtual {v3}, Landroid/bluetooth/BluetoothGatt;->getDevice()Landroid/bluetooth/BluetoothDevice;

    .line 42
    .line 43
    .line 44
    move-result-object v6

    .line 45
    if-eqz v5, :cond_2

    .line 46
    .line 47
    iget-object v7, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 48
    .line 49
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 50
    .line 51
    .line 52
    new-instance v7, Lno/nordicsemi/android/ble/g;

    .line 53
    .line 54
    const/4 v8, 0x3

    .line 55
    invoke-direct {v7, v8, v6}, Lno/nordicsemi/android/ble/g;-><init>(ILandroid/bluetooth/BluetoothDevice;)V

    .line 56
    .line 57
    .line 58
    invoke-virtual {p0, v7}, Lno/nordicsemi/android/ble/d;->D(Lno/nordicsemi/android/ble/s;)V

    .line 59
    .line 60
    .line 61
    :cond_2
    iget-object v7, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 62
    .line 63
    invoke-virtual {v7}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 64
    .line 65
    .line 66
    move-result v7

    .line 67
    if-lt v4, v7, :cond_3

    .line 68
    .line 69
    iget-object v7, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 70
    .line 71
    const-string v8, "gatt.disconnect()"

    .line 72
    .line 73
    invoke-virtual {v7, v4, v8}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 74
    .line 75
    .line 76
    :cond_3
    :try_start_0
    invoke-virtual {v3}, Landroid/bluetooth/BluetoothGatt;->disconnect()V
    :try_end_0
    .catch Ljava/lang/SecurityException; {:try_start_0 .. :try_end_0} :catch_0

    .line 77
    .line 78
    .line 79
    goto :goto_1

    .line 80
    :catch_0
    move-exception v7

    .line 81
    iget-object v8, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 82
    .line 83
    invoke-virtual {v8}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 84
    .line 85
    .line 86
    move-result v8

    .line 87
    const/4 v9, 0x6

    .line 88
    if-lt v9, v8, :cond_4

    .line 89
    .line 90
    iget-object v8, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 91
    .line 92
    invoke-virtual {v7}, Ljava/lang/Throwable;->getLocalizedMessage()Ljava/lang/String;

    .line 93
    .line 94
    .line 95
    move-result-object v7

    .line 96
    invoke-virtual {v8, v9, v7}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 97
    .line 98
    .line 99
    :cond_4
    :goto_1
    if-eqz v5, :cond_5

    .line 100
    .line 101
    return-void

    .line 102
    :cond_5
    iput v1, p0, Lno/nordicsemi/android/ble/d;->s:I

    .line 103
    .line 104
    iget-object v1, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 105
    .line 106
    invoke-virtual {v1}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 107
    .line 108
    .line 109
    move-result v1

    .line 110
    const/4 v5, 0x4

    .line 111
    if-lt v5, v1, :cond_6

    .line 112
    .line 113
    iget-object v1, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 114
    .line 115
    const-string v7, "Disconnected"

    .line 116
    .line 117
    invoke-virtual {v1, v5, v7}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 118
    .line 119
    .line 120
    :cond_6
    invoke-virtual {p0}, Lno/nordicsemi/android/ble/d;->c()V

    .line 121
    .line 122
    .line 123
    iget-object v1, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 124
    .line 125
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 126
    .line 127
    .line 128
    new-instance v1, Lno/nordicsemi/android/ble/i;

    .line 129
    .line 130
    const/4 v5, 0x3

    .line 131
    invoke-direct {v1, p1, v5, v6}, Lno/nordicsemi/android/ble/i;-><init>(IILandroid/bluetooth/BluetoothDevice;)V

    .line 132
    .line 133
    .line 134
    invoke-virtual {p0, v1}, Lno/nordicsemi/android/ble/d;->D(Lno/nordicsemi/android/ble/s;)V

    .line 135
    .line 136
    .line 137
    :cond_7
    iget-object p1, p0, Lno/nordicsemi/android/ble/d;->z:Lno/nordicsemi/android/ble/i0;

    .line 138
    .line 139
    if-eqz p1, :cond_b

    .line 140
    .line 141
    iget v1, p1, Lno/nordicsemi/android/ble/i0;->c:I

    .line 142
    .line 143
    if-ne v1, v4, :cond_b

    .line 144
    .line 145
    if-nez v2, :cond_9

    .line 146
    .line 147
    if-eqz v3, :cond_8

    .line 148
    .line 149
    goto :goto_2

    .line 150
    :cond_8
    invoke-virtual {p1}, Lno/nordicsemi/android/ble/i0;->b()V

    .line 151
    .line 152
    .line 153
    goto :goto_4

    .line 154
    :cond_9
    :goto_2
    if-eqz v2, :cond_a

    .line 155
    .line 156
    goto :goto_3

    .line 157
    :cond_a
    invoke-virtual {v3}, Landroid/bluetooth/BluetoothGatt;->getDevice()Landroid/bluetooth/BluetoothDevice;

    .line 158
    .line 159
    .line 160
    move-result-object v2

    .line 161
    :goto_3
    invoke-virtual {p1, v2}, Lno/nordicsemi/android/ble/i0;->d(Landroid/bluetooth/BluetoothDevice;)Z

    .line 162
    .line 163
    .line 164
    :cond_b
    :goto_4
    invoke-virtual {p0, v0}, Lno/nordicsemi/android/ble/d;->A(Z)V

    .line 165
    .line 166
    .line 167
    return-void
.end method

.method public final p(Landroid/bluetooth/BluetoothGattCharacteristic;)Z
    .locals 9

    .line 1
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->c:Landroid/bluetooth/BluetoothGatt;

    .line 2
    .line 3
    if-eqz v0, :cond_7

    .line 4
    .line 5
    if-eqz p1, :cond_7

    .line 6
    .line 7
    iget-boolean v1, p0, Lno/nordicsemi/android/ble/d;->n:Z

    .line 8
    .line 9
    if-nez v1, :cond_0

    .line 10
    .line 11
    goto/16 :goto_1

    .line 12
    .line 13
    :cond_0
    const/16 v1, 0x20

    .line 14
    .line 15
    invoke-static {v1, p1}, Lno/nordicsemi/android/ble/d;->h(ILandroid/bluetooth/BluetoothGattCharacteristic;)Landroid/bluetooth/BluetoothGattDescriptor;

    .line 16
    .line 17
    .line 18
    move-result-object v1

    .line 19
    if-eqz v1, :cond_7

    .line 20
    .line 21
    iget-object v2, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 22
    .line 23
    invoke-virtual {v2}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 24
    .line 25
    .line 26
    move-result v2

    .line 27
    const/4 v3, 0x3

    .line 28
    if-lt v3, v2, :cond_1

    .line 29
    .line 30
    iget-object v2, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 31
    .line 32
    new-instance v4, Ljava/lang/StringBuilder;

    .line 33
    .line 34
    const-string v5, "gatt.setCharacteristicNotification("

    .line 35
    .line 36
    invoke-direct {v4, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGattCharacteristic;->getUuid()Ljava/util/UUID;

    .line 40
    .line 41
    .line 42
    move-result-object v5

    .line 43
    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 44
    .line 45
    .line 46
    const-string v5, ", true)"

    .line 47
    .line 48
    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 49
    .line 50
    .line 51
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 52
    .line 53
    .line 54
    move-result-object v4

    .line 55
    invoke-virtual {v2, v3, v4}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 56
    .line 57
    .line 58
    :cond_1
    const/4 v2, 0x6

    .line 59
    const/4 v4, 0x1

    .line 60
    :try_start_0
    invoke-virtual {v0, p1, v4}, Landroid/bluetooth/BluetoothGatt;->setCharacteristicNotification(Landroid/bluetooth/BluetoothGattCharacteristic;Z)Z
    :try_end_0
    .catch Ljava/lang/SecurityException; {:try_start_0 .. :try_end_0} :catch_1

    .line 61
    .line 62
    .line 63
    iget-object v5, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 64
    .line 65
    invoke-virtual {v5}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 66
    .line 67
    .line 68
    move-result v5

    .line 69
    const/4 v6, 0x2

    .line 70
    if-lt v6, v5, :cond_2

    .line 71
    .line 72
    iget-object v5, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 73
    .line 74
    new-instance v7, Ljava/lang/StringBuilder;

    .line 75
    .line 76
    const-string v8, "Enabling indications for "

    .line 77
    .line 78
    invoke-direct {v7, v8}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 79
    .line 80
    .line 81
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGattCharacteristic;->getUuid()Ljava/util/UUID;

    .line 82
    .line 83
    .line 84
    move-result-object p1

    .line 85
    invoke-virtual {v7, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 86
    .line 87
    .line 88
    invoke-virtual {v7}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 89
    .line 90
    .line 91
    move-result-object p1

    .line 92
    invoke-virtual {v5, v6, p1}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 93
    .line 94
    .line 95
    :cond_2
    :try_start_1
    sget p1, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 96
    .line 97
    const/16 v5, 0x21

    .line 98
    .line 99
    if-lt p1, v5, :cond_4

    .line 100
    .line 101
    iget-object p1, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 102
    .line 103
    invoke-virtual {p1}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 104
    .line 105
    .line 106
    move-result p1

    .line 107
    if-lt v3, p1, :cond_3

    .line 108
    .line 109
    iget-object p1, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 110
    .line 111
    const-string v5, "gatt.writeDescriptor(00002902-0000-1000-8000-00805f9b34fb, value=0x02-00)"

    .line 112
    .line 113
    invoke-virtual {p1, v3, v5}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 114
    .line 115
    .line 116
    :cond_3
    sget-object p1, Landroid/bluetooth/BluetoothGattDescriptor;->ENABLE_INDICATION_VALUE:[B

    .line 117
    .line 118
    invoke-static {v0, v1, p1}, Li2/p0;->c(Landroid/bluetooth/BluetoothGatt;Landroid/bluetooth/BluetoothGattDescriptor;[B)I

    .line 119
    .line 120
    .line 121
    move-result p0

    .line 122
    if-nez p0, :cond_7

    .line 123
    .line 124
    return v4

    .line 125
    :catch_0
    move-exception p1

    .line 126
    goto :goto_0

    .line 127
    :cond_4
    iget-object p1, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 128
    .line 129
    invoke-virtual {p1}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 130
    .line 131
    .line 132
    move-result p1

    .line 133
    if-lt v3, p1, :cond_5

    .line 134
    .line 135
    iget-object p1, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 136
    .line 137
    const-string v4, "descriptor.setValue(0x02-00)"

    .line 138
    .line 139
    invoke-virtual {p1, v3, v4}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 140
    .line 141
    .line 142
    :cond_5
    sget-object p1, Landroid/bluetooth/BluetoothGattDescriptor;->ENABLE_INDICATION_VALUE:[B

    .line 143
    .line 144
    invoke-virtual {v1, p1}, Landroid/bluetooth/BluetoothGattDescriptor;->setValue([B)Z

    .line 145
    .line 146
    .line 147
    iget-object p1, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 148
    .line 149
    invoke-virtual {p1}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 150
    .line 151
    .line 152
    move-result p1

    .line 153
    if-lt v3, p1, :cond_6

    .line 154
    .line 155
    iget-object p1, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 156
    .line 157
    const-string v4, "gatt.writeDescriptor(00002902-0000-1000-8000-00805f9b34fb)"

    .line 158
    .line 159
    invoke-virtual {p1, v3, v4}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 160
    .line 161
    .line 162
    :cond_6
    invoke-virtual {v0, v1}, Landroid/bluetooth/BluetoothGatt;->writeDescriptor(Landroid/bluetooth/BluetoothGattDescriptor;)Z

    .line 163
    .line 164
    .line 165
    move-result p0
    :try_end_1
    .catch Ljava/lang/SecurityException; {:try_start_1 .. :try_end_1} :catch_0

    .line 166
    return p0

    .line 167
    :goto_0
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 168
    .line 169
    invoke-virtual {v0}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 170
    .line 171
    .line 172
    move-result v0

    .line 173
    if-lt v2, v0, :cond_7

    .line 174
    .line 175
    iget-object p0, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 176
    .line 177
    invoke-virtual {p1}, Ljava/lang/Throwable;->getLocalizedMessage()Ljava/lang/String;

    .line 178
    .line 179
    .line 180
    move-result-object p1

    .line 181
    invoke-virtual {p0, v2, p1}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 182
    .line 183
    .line 184
    goto :goto_1

    .line 185
    :catch_1
    move-exception p1

    .line 186
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 187
    .line 188
    invoke-virtual {v0}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 189
    .line 190
    .line 191
    move-result v0

    .line 192
    if-lt v2, v0, :cond_7

    .line 193
    .line 194
    iget-object p0, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 195
    .line 196
    invoke-virtual {p1}, Ljava/lang/Throwable;->getLocalizedMessage()Ljava/lang/String;

    .line 197
    .line 198
    .line 199
    move-result-object p1

    .line 200
    invoke-virtual {p0, v2, p1}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 201
    .line 202
    .line 203
    :cond_7
    :goto_1
    const/4 p0, 0x0

    .line 204
    return p0
.end method

.method public final q(Landroid/bluetooth/BluetoothGattCharacteristic;)Z
    .locals 9

    .line 1
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->c:Landroid/bluetooth/BluetoothGatt;

    .line 2
    .line 3
    if-eqz v0, :cond_7

    .line 4
    .line 5
    if-eqz p1, :cond_7

    .line 6
    .line 7
    iget-boolean v1, p0, Lno/nordicsemi/android/ble/d;->n:Z

    .line 8
    .line 9
    if-nez v1, :cond_0

    .line 10
    .line 11
    goto/16 :goto_1

    .line 12
    .line 13
    :cond_0
    const/16 v1, 0x10

    .line 14
    .line 15
    invoke-static {v1, p1}, Lno/nordicsemi/android/ble/d;->h(ILandroid/bluetooth/BluetoothGattCharacteristic;)Landroid/bluetooth/BluetoothGattDescriptor;

    .line 16
    .line 17
    .line 18
    move-result-object v1

    .line 19
    if-eqz v1, :cond_7

    .line 20
    .line 21
    iget-object v2, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 22
    .line 23
    invoke-virtual {v2}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 24
    .line 25
    .line 26
    move-result v2

    .line 27
    const/4 v3, 0x3

    .line 28
    if-lt v3, v2, :cond_1

    .line 29
    .line 30
    iget-object v2, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 31
    .line 32
    new-instance v4, Ljava/lang/StringBuilder;

    .line 33
    .line 34
    const-string v5, "gatt.setCharacteristicNotification("

    .line 35
    .line 36
    invoke-direct {v4, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGattCharacteristic;->getUuid()Ljava/util/UUID;

    .line 40
    .line 41
    .line 42
    move-result-object v5

    .line 43
    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 44
    .line 45
    .line 46
    const-string v5, ", true)"

    .line 47
    .line 48
    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 49
    .line 50
    .line 51
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 52
    .line 53
    .line 54
    move-result-object v4

    .line 55
    invoke-virtual {v2, v3, v4}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 56
    .line 57
    .line 58
    :cond_1
    const/4 v2, 0x6

    .line 59
    const/4 v4, 0x1

    .line 60
    :try_start_0
    invoke-virtual {v0, p1, v4}, Landroid/bluetooth/BluetoothGatt;->setCharacteristicNotification(Landroid/bluetooth/BluetoothGattCharacteristic;Z)Z
    :try_end_0
    .catch Ljava/lang/SecurityException; {:try_start_0 .. :try_end_0} :catch_1

    .line 61
    .line 62
    .line 63
    iget-object v5, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 64
    .line 65
    invoke-virtual {v5}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 66
    .line 67
    .line 68
    move-result v5

    .line 69
    const/4 v6, 0x2

    .line 70
    if-lt v6, v5, :cond_2

    .line 71
    .line 72
    iget-object v5, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 73
    .line 74
    new-instance v7, Ljava/lang/StringBuilder;

    .line 75
    .line 76
    const-string v8, "Enabling notifications for "

    .line 77
    .line 78
    invoke-direct {v7, v8}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 79
    .line 80
    .line 81
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGattCharacteristic;->getUuid()Ljava/util/UUID;

    .line 82
    .line 83
    .line 84
    move-result-object p1

    .line 85
    invoke-virtual {v7, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 86
    .line 87
    .line 88
    invoke-virtual {v7}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 89
    .line 90
    .line 91
    move-result-object p1

    .line 92
    invoke-virtual {v5, v6, p1}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 93
    .line 94
    .line 95
    :cond_2
    :try_start_1
    sget p1, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 96
    .line 97
    const/16 v5, 0x21

    .line 98
    .line 99
    if-lt p1, v5, :cond_4

    .line 100
    .line 101
    iget-object p1, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 102
    .line 103
    invoke-virtual {p1}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 104
    .line 105
    .line 106
    move-result p1

    .line 107
    if-lt v3, p1, :cond_3

    .line 108
    .line 109
    iget-object p1, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 110
    .line 111
    const-string v5, "gatt.writeDescriptor(00002902-0000-1000-8000-00805f9b34fb, value=0x01-00)"

    .line 112
    .line 113
    invoke-virtual {p1, v3, v5}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 114
    .line 115
    .line 116
    :cond_3
    sget-object p1, Landroid/bluetooth/BluetoothGattDescriptor;->ENABLE_NOTIFICATION_VALUE:[B

    .line 117
    .line 118
    invoke-static {v0, v1, p1}, Li2/p0;->c(Landroid/bluetooth/BluetoothGatt;Landroid/bluetooth/BluetoothGattDescriptor;[B)I

    .line 119
    .line 120
    .line 121
    move-result p0

    .line 122
    if-nez p0, :cond_7

    .line 123
    .line 124
    return v4

    .line 125
    :catch_0
    move-exception p1

    .line 126
    goto :goto_0

    .line 127
    :cond_4
    iget-object p1, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 128
    .line 129
    invoke-virtual {p1}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 130
    .line 131
    .line 132
    move-result p1

    .line 133
    if-lt v3, p1, :cond_5

    .line 134
    .line 135
    iget-object p1, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 136
    .line 137
    const-string v4, "descriptor.setValue(0x01-00)"

    .line 138
    .line 139
    invoke-virtual {p1, v3, v4}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 140
    .line 141
    .line 142
    :cond_5
    sget-object p1, Landroid/bluetooth/BluetoothGattDescriptor;->ENABLE_NOTIFICATION_VALUE:[B

    .line 143
    .line 144
    invoke-virtual {v1, p1}, Landroid/bluetooth/BluetoothGattDescriptor;->setValue([B)Z

    .line 145
    .line 146
    .line 147
    iget-object p1, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 148
    .line 149
    invoke-virtual {p1}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 150
    .line 151
    .line 152
    move-result p1

    .line 153
    if-lt v3, p1, :cond_6

    .line 154
    .line 155
    iget-object p1, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 156
    .line 157
    const-string v4, "gatt.writeDescriptor(00002902-0000-1000-8000-00805f9b34fb)"

    .line 158
    .line 159
    invoke-virtual {p1, v3, v4}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 160
    .line 161
    .line 162
    :cond_6
    invoke-virtual {v0, v1}, Landroid/bluetooth/BluetoothGatt;->writeDescriptor(Landroid/bluetooth/BluetoothGattDescriptor;)Z

    .line 163
    .line 164
    .line 165
    move-result p0
    :try_end_1
    .catch Ljava/lang/SecurityException; {:try_start_1 .. :try_end_1} :catch_0

    .line 166
    return p0

    .line 167
    :goto_0
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 168
    .line 169
    invoke-virtual {v0}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 170
    .line 171
    .line 172
    move-result v0

    .line 173
    if-lt v2, v0, :cond_7

    .line 174
    .line 175
    iget-object p0, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 176
    .line 177
    invoke-virtual {p1}, Ljava/lang/Throwable;->getLocalizedMessage()Ljava/lang/String;

    .line 178
    .line 179
    .line 180
    move-result-object p1

    .line 181
    invoke-virtual {p0, v2, p1}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 182
    .line 183
    .line 184
    goto :goto_1

    .line 185
    :catch_1
    move-exception p1

    .line 186
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 187
    .line 188
    invoke-virtual {v0}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 189
    .line 190
    .line 191
    move-result v0

    .line 192
    if-lt v2, v0, :cond_7

    .line 193
    .line 194
    iget-object p0, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 195
    .line 196
    invoke-virtual {p1}, Ljava/lang/Throwable;->getLocalizedMessage()Ljava/lang/String;

    .line 197
    .line 198
    .line 199
    move-result-object p1

    .line 200
    invoke-virtual {p0, v2, p1}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 201
    .line 202
    .line 203
    :cond_7
    :goto_1
    const/4 p0, 0x0

    .line 204
    return p0
.end method

.method public final r()Z
    .locals 4

    .line 1
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->c:Landroid/bluetooth/BluetoothGatt;

    .line 2
    .line 3
    if-eqz v0, :cond_4

    .line 4
    .line 5
    iget-boolean v1, p0, Lno/nordicsemi/android/ble/d;->n:Z

    .line 6
    .line 7
    if-nez v1, :cond_0

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    iget-boolean v1, p0, Lno/nordicsemi/android/ble/d;->u:Z

    .line 11
    .line 12
    if-nez v1, :cond_1

    .line 13
    .line 14
    goto :goto_0

    .line 15
    :cond_1
    iget-object v1, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 16
    .line 17
    invoke-virtual {v1}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    const/4 v2, 0x2

    .line 22
    if-lt v2, v1, :cond_2

    .line 23
    .line 24
    iget-object v1, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 25
    .line 26
    const-string v3, "Executing reliable write..."

    .line 27
    .line 28
    invoke-virtual {v1, v2, v3}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 29
    .line 30
    .line 31
    :cond_2
    iget-object v1, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 32
    .line 33
    invoke-virtual {v1}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 34
    .line 35
    .line 36
    move-result v1

    .line 37
    const/4 v2, 0x3

    .line 38
    if-lt v2, v1, :cond_3

    .line 39
    .line 40
    iget-object v1, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 41
    .line 42
    const-string v3, "gatt.executeReliableWrite()"

    .line 43
    .line 44
    invoke-virtual {v1, v2, v3}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 45
    .line 46
    .line 47
    :cond_3
    :try_start_0
    invoke-virtual {v0}, Landroid/bluetooth/BluetoothGatt;->executeReliableWrite()Z

    .line 48
    .line 49
    .line 50
    move-result p0
    :try_end_0
    .catch Ljava/lang/SecurityException; {:try_start_0 .. :try_end_0} :catch_0

    .line 51
    return p0

    .line 52
    :catch_0
    move-exception v0

    .line 53
    iget-object v1, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 54
    .line 55
    invoke-virtual {v1}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 56
    .line 57
    .line 58
    move-result v1

    .line 59
    const/4 v2, 0x6

    .line 60
    if-lt v2, v1, :cond_4

    .line 61
    .line 62
    iget-object p0, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 63
    .line 64
    invoke-virtual {v0}, Ljava/lang/Throwable;->getLocalizedMessage()Ljava/lang/String;

    .line 65
    .line 66
    .line 67
    move-result-object v0

    .line 68
    invoke-virtual {p0, v2, v0}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 69
    .line 70
    .line 71
    :cond_4
    :goto_0
    const/4 p0, 0x0

    .line 72
    return p0
.end method

.method public final s(Landroid/bluetooth/BluetoothGattCharacteristic;)Z
    .locals 5

    .line 1
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->c:Landroid/bluetooth/BluetoothGatt;

    .line 2
    .line 3
    if-eqz v0, :cond_4

    .line 4
    .line 5
    if-eqz p1, :cond_4

    .line 6
    .line 7
    iget-boolean v1, p0, Lno/nordicsemi/android/ble/d;->n:Z

    .line 8
    .line 9
    if-nez v1, :cond_0

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGattCharacteristic;->getProperties()I

    .line 13
    .line 14
    .line 15
    move-result v1

    .line 16
    const/4 v2, 0x2

    .line 17
    and-int/2addr v1, v2

    .line 18
    if-nez v1, :cond_1

    .line 19
    .line 20
    goto :goto_0

    .line 21
    :cond_1
    :try_start_0
    iget-object v1, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 22
    .line 23
    invoke-virtual {v1}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 24
    .line 25
    .line 26
    move-result v1

    .line 27
    if-lt v2, v1, :cond_2

    .line 28
    .line 29
    iget-object v1, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 30
    .line 31
    new-instance v3, Ljava/lang/StringBuilder;

    .line 32
    .line 33
    const-string v4, "Reading characteristic "

    .line 34
    .line 35
    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGattCharacteristic;->getUuid()Ljava/util/UUID;

    .line 39
    .line 40
    .line 41
    move-result-object v4

    .line 42
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 43
    .line 44
    .line 45
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 46
    .line 47
    .line 48
    move-result-object v3

    .line 49
    invoke-virtual {v1, v2, v3}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 50
    .line 51
    .line 52
    :cond_2
    iget-object v1, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 53
    .line 54
    invoke-virtual {v1}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 55
    .line 56
    .line 57
    move-result v1

    .line 58
    const/4 v2, 0x3

    .line 59
    if-lt v2, v1, :cond_3

    .line 60
    .line 61
    iget-object v1, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 62
    .line 63
    new-instance v3, Ljava/lang/StringBuilder;

    .line 64
    .line 65
    const-string v4, "gatt.readCharacteristic("

    .line 66
    .line 67
    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 68
    .line 69
    .line 70
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGattCharacteristic;->getUuid()Ljava/util/UUID;

    .line 71
    .line 72
    .line 73
    move-result-object v4

    .line 74
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 75
    .line 76
    .line 77
    const-string v4, ")"

    .line 78
    .line 79
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 80
    .line 81
    .line 82
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 83
    .line 84
    .line 85
    move-result-object v3

    .line 86
    invoke-virtual {v1, v2, v3}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 87
    .line 88
    .line 89
    :cond_3
    invoke-virtual {v0, p1}, Landroid/bluetooth/BluetoothGatt;->readCharacteristic(Landroid/bluetooth/BluetoothGattCharacteristic;)Z

    .line 90
    .line 91
    .line 92
    move-result p0
    :try_end_0
    .catch Ljava/lang/SecurityException; {:try_start_0 .. :try_end_0} :catch_0

    .line 93
    return p0

    .line 94
    :catch_0
    move-exception p1

    .line 95
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 96
    .line 97
    invoke-virtual {v0}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 98
    .line 99
    .line 100
    move-result v0

    .line 101
    const/4 v1, 0x6

    .line 102
    if-lt v1, v0, :cond_4

    .line 103
    .line 104
    iget-object p0, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 105
    .line 106
    invoke-virtual {p1}, Ljava/lang/Throwable;->getLocalizedMessage()Ljava/lang/String;

    .line 107
    .line 108
    .line 109
    move-result-object p1

    .line 110
    invoke-virtual {p0, v1, p1}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 111
    .line 112
    .line 113
    :cond_4
    :goto_0
    const/4 p0, 0x0

    .line 114
    return p0
.end method

.method public final t()Z
    .locals 4

    .line 1
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->c:Landroid/bluetooth/BluetoothGatt;

    .line 2
    .line 3
    if-eqz v0, :cond_3

    .line 4
    .line 5
    iget-boolean v1, p0, Lno/nordicsemi/android/ble/d;->n:Z

    .line 6
    .line 7
    if-nez v1, :cond_0

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    iget-object v1, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 11
    .line 12
    invoke-virtual {v1}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 13
    .line 14
    .line 15
    move-result v1

    .line 16
    const/4 v2, 0x2

    .line 17
    if-lt v2, v1, :cond_1

    .line 18
    .line 19
    iget-object v1, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 20
    .line 21
    const-string v3, "Reading PHY..."

    .line 22
    .line 23
    invoke-virtual {v1, v2, v3}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 24
    .line 25
    .line 26
    :cond_1
    iget-object v1, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 27
    .line 28
    invoke-virtual {v1}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 29
    .line 30
    .line 31
    move-result v1

    .line 32
    const/4 v2, 0x3

    .line 33
    if-lt v2, v1, :cond_2

    .line 34
    .line 35
    iget-object p0, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 36
    .line 37
    const-string v1, "gatt.readPhy()"

    .line 38
    .line 39
    invoke-virtual {p0, v2, v1}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 40
    .line 41
    .line 42
    :cond_2
    invoke-virtual {v0}, Landroid/bluetooth/BluetoothGatt;->readPhy()V

    .line 43
    .line 44
    .line 45
    const/4 p0, 0x1

    .line 46
    return p0

    .line 47
    :cond_3
    :goto_0
    const/4 p0, 0x0

    .line 48
    return p0
.end method

.method public final u()Z
    .locals 5

    .line 1
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->c:Landroid/bluetooth/BluetoothGatt;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-nez v0, :cond_0

    .line 5
    .line 6
    return v1

    .line 7
    :cond_0
    new-instance v2, Lj9/d;

    .line 8
    .line 9
    const/16 v3, 0xc

    .line 10
    .line 11
    invoke-direct {v2, v3}, Lj9/d;-><init>(I)V

    .line 12
    .line 13
    .line 14
    const/4 v3, 0x2

    .line 15
    invoke-virtual {p0, v3, v2}, Lno/nordicsemi/android/ble/d;->z(ILno/nordicsemi/android/ble/t;)V

    .line 16
    .line 17
    .line 18
    new-instance v2, Lj9/d;

    .line 19
    .line 20
    const/16 v3, 0xd

    .line 21
    .line 22
    invoke-direct {v2, v3}, Lj9/d;-><init>(I)V

    .line 23
    .line 24
    .line 25
    const/4 v3, 0x3

    .line 26
    invoke-virtual {p0, v3, v2}, Lno/nordicsemi/android/ble/d;->z(ILno/nordicsemi/android/ble/t;)V

    .line 27
    .line 28
    .line 29
    :try_start_0
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 30
    .line 31
    .line 32
    move-result-object v2

    .line 33
    const-string v3, "refresh"

    .line 34
    .line 35
    const/4 v4, 0x0

    .line 36
    invoke-virtual {v2, v3, v4}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 37
    .line 38
    .line 39
    move-result-object v2

    .line 40
    invoke-virtual {v2, v0, v4}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object v0

    .line 44
    sget-object p0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 45
    .line 46
    if-ne v0, p0, :cond_1

    .line 47
    .line 48
    const/4 p0, 0x1

    .line 49
    return p0

    .line 50
    :cond_1
    return v1

    .line 51
    :catch_0
    move-exception v0

    .line 52
    const-string v2, "BleManager"

    .line 53
    .line 54
    const-string v3, "An exception occurred while refreshing device"

    .line 55
    .line 56
    invoke-static {v2, v3, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 57
    .line 58
    .line 59
    new-instance v0, Lj9/d;

    .line 60
    .line 61
    const/16 v2, 0xe

    .line 62
    .line 63
    invoke-direct {v0, v2}, Lj9/d;-><init>(I)V

    .line 64
    .line 65
    .line 66
    const/4 v2, 0x5

    .line 67
    invoke-virtual {p0, v2, v0}, Lno/nordicsemi/android/ble/d;->z(ILno/nordicsemi/android/ble/t;)V

    .line 68
    .line 69
    .line 70
    return v1
.end method

.method public final v()Z
    .locals 8

    .line 1
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->b:Landroid/bluetooth/BluetoothDevice;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-nez v0, :cond_0

    .line 5
    .line 6
    return v1

    .line 7
    :cond_0
    iget-object v2, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 8
    .line 9
    invoke-virtual {v2}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 10
    .line 11
    .line 12
    move-result v2

    .line 13
    const/4 v3, 0x2

    .line 14
    if-lt v3, v2, :cond_1

    .line 15
    .line 16
    iget-object v2, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 17
    .line 18
    const-string v4, "Removing bond information..."

    .line 19
    .line 20
    invoke-virtual {v2, v3, v4}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 21
    .line 22
    .line 23
    :cond_1
    invoke-virtual {v0}, Landroid/bluetooth/BluetoothDevice;->getBondState()I

    .line 24
    .line 25
    .line 26
    move-result v2

    .line 27
    const/16 v3, 0xa

    .line 28
    .line 29
    const/4 v4, 0x1

    .line 30
    if-ne v2, v3, :cond_3

    .line 31
    .line 32
    iget-object v1, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 33
    .line 34
    invoke-virtual {v1}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 35
    .line 36
    .line 37
    move-result v1

    .line 38
    const/4 v2, 0x5

    .line 39
    if-lt v2, v1, :cond_2

    .line 40
    .line 41
    iget-object v1, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 42
    .line 43
    const-string v3, "Device is not bonded"

    .line 44
    .line 45
    invoke-virtual {v1, v2, v3}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 46
    .line 47
    .line 48
    :cond_2
    iget-object v1, p0, Lno/nordicsemi/android/ble/d;->z:Lno/nordicsemi/android/ble/i0;

    .line 49
    .line 50
    invoke-virtual {v1, v0}, Lno/nordicsemi/android/ble/i0;->d(Landroid/bluetooth/BluetoothDevice;)Z

    .line 51
    .line 52
    .line 53
    invoke-virtual {p0, v4}, Lno/nordicsemi/android/ble/d;->A(Z)V

    .line 54
    .line 55
    .line 56
    return v4

    .line 57
    :cond_3
    :try_start_0
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 58
    .line 59
    .line 60
    move-result-object v2

    .line 61
    const-string v3, "removeBond"

    .line 62
    .line 63
    const/4 v5, 0x0

    .line 64
    invoke-virtual {v2, v3, v5}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 65
    .line 66
    .line 67
    move-result-object v2

    .line 68
    iget-object v3, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 69
    .line 70
    invoke-virtual {v3}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 71
    .line 72
    .line 73
    move-result v3

    .line 74
    const/4 v6, 0x3

    .line 75
    if-lt v6, v3, :cond_4

    .line 76
    .line 77
    iget-object v3, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 78
    .line 79
    const-string v7, "device.removeBond() (hidden)"

    .line 80
    .line 81
    invoke-virtual {v3, v6, v7}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 82
    .line 83
    .line 84
    :cond_4
    iput-boolean v4, p0, Lno/nordicsemi/android/ble/d;->q:Z

    .line 85
    .line 86
    invoke-virtual {v2, v0, v5}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    move-result-object p0

    .line 90
    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 91
    .line 92
    if-ne p0, v0, :cond_5

    .line 93
    .line 94
    return v4

    .line 95
    :cond_5
    return v1

    .line 96
    :catch_0
    move-exception p0

    .line 97
    const-string v0, "BleManager"

    .line 98
    .line 99
    const-string v2, "An exception occurred while removing bond"

    .line 100
    .line 101
    invoke-static {v0, v2, p0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 102
    .line 103
    .line 104
    return v1
.end method

.method public final w(Z)Z
    .locals 2

    .line 1
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->c:Landroid/bluetooth/BluetoothGatt;

    .line 2
    .line 3
    if-eqz v0, :cond_3

    .line 4
    .line 5
    iget-boolean v1, p0, Lno/nordicsemi/android/ble/d;->n:Z

    .line 6
    .line 7
    if-nez v1, :cond_0

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    sget-object v1, Lno/nordicsemi/android/ble/e;->BATTERY_SERVICE:Ljava/util/UUID;

    .line 11
    .line 12
    invoke-virtual {v0, v1}, Landroid/bluetooth/BluetoothGatt;->getService(Ljava/util/UUID;)Landroid/bluetooth/BluetoothGattService;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    if-nez v0, :cond_1

    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_1
    sget-object v1, Lno/nordicsemi/android/ble/e;->BATTERY_LEVEL_CHARACTERISTIC:Ljava/util/UUID;

    .line 20
    .line 21
    invoke-virtual {v0, v1}, Landroid/bluetooth/BluetoothGattService;->getCharacteristic(Ljava/util/UUID;)Landroid/bluetooth/BluetoothGattCharacteristic;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    if-eqz p1, :cond_2

    .line 26
    .line 27
    invoke-virtual {p0, v0}, Lno/nordicsemi/android/ble/d;->q(Landroid/bluetooth/BluetoothGattCharacteristic;)Z

    .line 28
    .line 29
    .line 30
    move-result p0

    .line 31
    return p0

    .line 32
    :cond_2
    invoke-virtual {p0, v0}, Lno/nordicsemi/android/ble/d;->n(Landroid/bluetooth/BluetoothGattCharacteristic;)Z

    .line 33
    .line 34
    .line 35
    move-result p0

    .line 36
    return p0

    .line 37
    :cond_3
    :goto_0
    const/4 p0, 0x0

    .line 38
    return p0
.end method

.method public final x(Landroid/bluetooth/BluetoothGattCharacteristic;[BI)Z
    .locals 8

    .line 1
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->c:Landroid/bluetooth/BluetoothGatt;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_7

    .line 5
    .line 6
    if-eqz p1, :cond_7

    .line 7
    .line 8
    iget-boolean v2, p0, Lno/nordicsemi/android/ble/d;->n:Z

    .line 9
    .line 10
    if-nez v2, :cond_0

    .line 11
    .line 12
    goto/16 :goto_2

    .line 13
    .line 14
    :cond_0
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGattCharacteristic;->getProperties()I

    .line 15
    .line 16
    .line 17
    move-result v2

    .line 18
    and-int/lit8 v2, v2, 0xc

    .line 19
    .line 20
    if-nez v2, :cond_1

    .line 21
    .line 22
    goto/16 :goto_2

    .line 23
    .line 24
    :cond_1
    if-eqz p2, :cond_2

    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_2
    :try_start_0
    new-array p2, v1, [B

    .line 28
    .line 29
    :goto_0
    sget v2, Landroid/os/Build$VERSION;->SDK_INT:I
    :try_end_0
    .catch Ljava/lang/SecurityException; {:try_start_0 .. :try_end_0} :catch_0

    .line 30
    .line 31
    const/16 v3, 0x21

    .line 32
    .line 33
    const-string v4, "gatt.writeCharacteristic("

    .line 34
    .line 35
    const-string v5, ")"

    .line 36
    .line 37
    const/4 v6, 0x2

    .line 38
    const/4 v7, 0x3

    .line 39
    if-lt v2, v3, :cond_4

    .line 40
    .line 41
    :try_start_1
    new-instance v2, Lno/nordicsemi/android/ble/h;

    .line 42
    .line 43
    const/4 v3, 0x0

    .line 44
    invoke-direct {v2, p1, p3, v3}, Lno/nordicsemi/android/ble/h;-><init>(Landroid/bluetooth/BluetoothGattCharacteristic;II)V

    .line 45
    .line 46
    .line 47
    invoke-virtual {p0, v6, v2}, Lno/nordicsemi/android/ble/d;->z(ILno/nordicsemi/android/ble/t;)V

    .line 48
    .line 49
    .line 50
    iget-object v2, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 51
    .line 52
    invoke-virtual {v2}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 53
    .line 54
    .line 55
    move-result v2

    .line 56
    if-lt v7, v2, :cond_3

    .line 57
    .line 58
    iget-object v2, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 59
    .line 60
    new-instance v3, Ljava/lang/StringBuilder;

    .line 61
    .line 62
    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 63
    .line 64
    .line 65
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGattCharacteristic;->getUuid()Ljava/util/UUID;

    .line 66
    .line 67
    .line 68
    move-result-object v4

    .line 69
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 70
    .line 71
    .line 72
    const-string v4, ", value="

    .line 73
    .line 74
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 75
    .line 76
    .line 77
    invoke-static {p2}, Lc01/a;->b([B)Ljava/lang/String;

    .line 78
    .line 79
    .line 80
    move-result-object v4

    .line 81
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 82
    .line 83
    .line 84
    const-string v4, ", "

    .line 85
    .line 86
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 87
    .line 88
    .line 89
    invoke-static {p3}, Lc01/a;->e(I)Ljava/lang/String;

    .line 90
    .line 91
    .line 92
    move-result-object v4

    .line 93
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 94
    .line 95
    .line 96
    invoke-virtual {v3, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 97
    .line 98
    .line 99
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 100
    .line 101
    .line 102
    move-result-object v3

    .line 103
    invoke-virtual {v2, v7, v3}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 104
    .line 105
    .line 106
    :cond_3
    invoke-static {v0, p1, p2, p3}, Li2/p0;->b(Landroid/bluetooth/BluetoothGatt;Landroid/bluetooth/BluetoothGattCharacteristic;[BI)I

    .line 107
    .line 108
    .line 109
    move-result p0

    .line 110
    if-nez p0, :cond_7

    .line 111
    .line 112
    const/4 p0, 0x1

    .line 113
    return p0

    .line 114
    :catch_0
    move-exception p1

    .line 115
    goto :goto_1

    .line 116
    :cond_4
    new-instance v2, Lno/nordicsemi/android/ble/h;

    .line 117
    .line 118
    const/4 v3, 0x1

    .line 119
    invoke-direct {v2, p1, p3, v3}, Lno/nordicsemi/android/ble/h;-><init>(Landroid/bluetooth/BluetoothGattCharacteristic;II)V

    .line 120
    .line 121
    .line 122
    invoke-virtual {p0, v6, v2}, Lno/nordicsemi/android/ble/d;->z(ILno/nordicsemi/android/ble/t;)V

    .line 123
    .line 124
    .line 125
    iget-object v2, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 126
    .line 127
    invoke-virtual {v2}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 128
    .line 129
    .line 130
    move-result v2

    .line 131
    if-lt v7, v2, :cond_5

    .line 132
    .line 133
    iget-object v2, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 134
    .line 135
    new-instance v3, Ljava/lang/StringBuilder;

    .line 136
    .line 137
    const-string v6, "characteristic.setValue("

    .line 138
    .line 139
    invoke-direct {v3, v6}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 140
    .line 141
    .line 142
    invoke-static {p2}, Lc01/a;->b([B)Ljava/lang/String;

    .line 143
    .line 144
    .line 145
    move-result-object v6

    .line 146
    invoke-virtual {v3, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 147
    .line 148
    .line 149
    invoke-virtual {v3, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 150
    .line 151
    .line 152
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 153
    .line 154
    .line 155
    move-result-object v3

    .line 156
    invoke-virtual {v2, v7, v3}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 157
    .line 158
    .line 159
    :cond_5
    invoke-virtual {p1, p2}, Landroid/bluetooth/BluetoothGattCharacteristic;->setValue([B)Z

    .line 160
    .line 161
    .line 162
    new-instance p2, La8/w;

    .line 163
    .line 164
    const/4 v2, 0x7

    .line 165
    invoke-direct {p2, p3, v2}, La8/w;-><init>(II)V

    .line 166
    .line 167
    .line 168
    invoke-virtual {p0, v7, p2}, Lno/nordicsemi/android/ble/d;->z(ILno/nordicsemi/android/ble/t;)V

    .line 169
    .line 170
    .line 171
    invoke-virtual {p1, p3}, Landroid/bluetooth/BluetoothGattCharacteristic;->setWriteType(I)V

    .line 172
    .line 173
    .line 174
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 175
    .line 176
    invoke-virtual {p2}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 177
    .line 178
    .line 179
    move-result p2

    .line 180
    if-lt v7, p2, :cond_6

    .line 181
    .line 182
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 183
    .line 184
    new-instance p3, Ljava/lang/StringBuilder;

    .line 185
    .line 186
    invoke-direct {p3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 187
    .line 188
    .line 189
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGattCharacteristic;->getUuid()Ljava/util/UUID;

    .line 190
    .line 191
    .line 192
    move-result-object v2

    .line 193
    invoke-virtual {p3, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 194
    .line 195
    .line 196
    invoke-virtual {p3, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 197
    .line 198
    .line 199
    invoke-virtual {p3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 200
    .line 201
    .line 202
    move-result-object p3

    .line 203
    invoke-virtual {p2, v7, p3}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 204
    .line 205
    .line 206
    :cond_6
    invoke-virtual {v0, p1}, Landroid/bluetooth/BluetoothGatt;->writeCharacteristic(Landroid/bluetooth/BluetoothGattCharacteristic;)Z

    .line 207
    .line 208
    .line 209
    move-result p0
    :try_end_1
    .catch Ljava/lang/SecurityException; {:try_start_1 .. :try_end_1} :catch_0

    .line 210
    return p0

    .line 211
    :goto_1
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 212
    .line 213
    invoke-virtual {p2}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 214
    .line 215
    .line 216
    move-result p2

    .line 217
    const/4 p3, 0x6

    .line 218
    if-lt p3, p2, :cond_7

    .line 219
    .line 220
    iget-object p0, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 221
    .line 222
    invoke-virtual {p1}, Ljava/lang/Throwable;->getLocalizedMessage()Ljava/lang/String;

    .line 223
    .line 224
    .line 225
    move-result-object p1

    .line 226
    invoke-virtual {p0, p3, p1}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 227
    .line 228
    .line 229
    :cond_7
    :goto_2
    return v1
.end method

.method public final y(Landroid/bluetooth/BluetoothGattDescriptor;[B)Z
    .locals 8

    .line 1
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->c:Landroid/bluetooth/BluetoothGatt;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_9

    .line 5
    .line 6
    if-eqz p1, :cond_9

    .line 7
    .line 8
    iget-boolean v2, p0, Lno/nordicsemi/android/ble/d;->n:Z

    .line 9
    .line 10
    if-nez v2, :cond_0

    .line 11
    .line 12
    goto/16 :goto_3

    .line 13
    .line 14
    :cond_0
    if-eqz p2, :cond_1

    .line 15
    .line 16
    goto :goto_0

    .line 17
    :cond_1
    :try_start_0
    new-array p2, v1, [B

    .line 18
    .line 19
    :goto_0
    iget-object v2, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 20
    .line 21
    invoke-virtual {v2}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 22
    .line 23
    .line 24
    move-result v2

    .line 25
    const/4 v3, 0x2

    .line 26
    if-lt v3, v2, :cond_2

    .line 27
    .line 28
    iget-object v2, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 29
    .line 30
    new-instance v4, Ljava/lang/StringBuilder;

    .line 31
    .line 32
    const-string v5, "Writing descriptor "

    .line 33
    .line 34
    invoke-direct {v4, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGattDescriptor;->getUuid()Ljava/util/UUID;

    .line 38
    .line 39
    .line 40
    move-result-object v5

    .line 41
    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 42
    .line 43
    .line 44
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 45
    .line 46
    .line 47
    move-result-object v4

    .line 48
    invoke-virtual {v2, v3, v4}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 49
    .line 50
    .line 51
    :cond_2
    sget v2, Landroid/os/Build$VERSION;->SDK_INT:I
    :try_end_0
    .catch Ljava/lang/SecurityException; {:try_start_0 .. :try_end_0} :catch_0

    .line 52
    .line 53
    const/16 v4, 0x21

    .line 54
    .line 55
    const-string v5, "gatt.writeDescriptor("

    .line 56
    .line 57
    const-string v6, ")"

    .line 58
    .line 59
    const/4 v7, 0x3

    .line 60
    if-lt v2, v4, :cond_4

    .line 61
    .line 62
    :try_start_1
    iget-object v2, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 63
    .line 64
    invoke-virtual {v2}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 65
    .line 66
    .line 67
    move-result v2

    .line 68
    if-lt v7, v2, :cond_3

    .line 69
    .line 70
    iget-object v2, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 71
    .line 72
    new-instance v3, Ljava/lang/StringBuilder;

    .line 73
    .line 74
    invoke-direct {v3, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 75
    .line 76
    .line 77
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGattDescriptor;->getUuid()Ljava/util/UUID;

    .line 78
    .line 79
    .line 80
    move-result-object v4

    .line 81
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 82
    .line 83
    .line 84
    const-string v4, ", value="

    .line 85
    .line 86
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 87
    .line 88
    .line 89
    invoke-static {p2}, Lc01/a;->b([B)Ljava/lang/String;

    .line 90
    .line 91
    .line 92
    move-result-object v4

    .line 93
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 94
    .line 95
    .line 96
    invoke-virtual {v3, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 97
    .line 98
    .line 99
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 100
    .line 101
    .line 102
    move-result-object v3

    .line 103
    invoke-virtual {v2, v7, v3}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 104
    .line 105
    .line 106
    :cond_3
    invoke-static {v0, p1, p2}, Li2/p0;->c(Landroid/bluetooth/BluetoothGatt;Landroid/bluetooth/BluetoothGattDescriptor;[B)I

    .line 107
    .line 108
    .line 109
    move-result p0

    .line 110
    if-nez p0, :cond_9

    .line 111
    .line 112
    const/4 p0, 0x1

    .line 113
    return p0

    .line 114
    :catch_0
    move-exception p1

    .line 115
    goto :goto_2

    .line 116
    :cond_4
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 117
    .line 118
    invoke-virtual {v0}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 119
    .line 120
    .line 121
    move-result v0

    .line 122
    if-lt v7, v0, :cond_5

    .line 123
    .line 124
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 125
    .line 126
    new-instance v2, Ljava/lang/StringBuilder;

    .line 127
    .line 128
    const-string v4, "descriptor.setValue("

    .line 129
    .line 130
    invoke-direct {v2, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 131
    .line 132
    .line 133
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGattDescriptor;->getUuid()Ljava/util/UUID;

    .line 134
    .line 135
    .line 136
    move-result-object v4

    .line 137
    invoke-virtual {v2, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 138
    .line 139
    .line 140
    invoke-virtual {v2, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 141
    .line 142
    .line 143
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 144
    .line 145
    .line 146
    move-result-object v2

    .line 147
    invoke-virtual {v0, v7, v2}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 148
    .line 149
    .line 150
    :cond_5
    invoke-virtual {p1, p2}, Landroid/bluetooth/BluetoothGattDescriptor;->setValue([B)Z

    .line 151
    .line 152
    .line 153
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 154
    .line 155
    invoke-virtual {p2}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 156
    .line 157
    .line 158
    move-result p2

    .line 159
    if-lt v7, p2, :cond_6

    .line 160
    .line 161
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 162
    .line 163
    new-instance v0, Ljava/lang/StringBuilder;

    .line 164
    .line 165
    invoke-direct {v0, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 166
    .line 167
    .line 168
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGattDescriptor;->getUuid()Ljava/util/UUID;

    .line 169
    .line 170
    .line 171
    move-result-object v2

    .line 172
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 173
    .line 174
    .line 175
    invoke-virtual {v0, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 176
    .line 177
    .line 178
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 179
    .line 180
    .line 181
    move-result-object v0

    .line 182
    invoke-virtual {p2, v7, v0}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 183
    .line 184
    .line 185
    :cond_6
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->c:Landroid/bluetooth/BluetoothGatt;

    .line 186
    .line 187
    if-eqz p2, :cond_8

    .line 188
    .line 189
    iget-boolean v0, p0, Lno/nordicsemi/android/ble/d;->n:Z

    .line 190
    .line 191
    if-nez v0, :cond_7

    .line 192
    .line 193
    goto :goto_1

    .line 194
    :cond_7
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGattDescriptor;->getCharacteristic()Landroid/bluetooth/BluetoothGattCharacteristic;

    .line 195
    .line 196
    .line 197
    move-result-object v0

    .line 198
    invoke-virtual {v0}, Landroid/bluetooth/BluetoothGattCharacteristic;->getWriteType()I

    .line 199
    .line 200
    .line 201
    move-result v2

    .line 202
    invoke-virtual {v0, v3}, Landroid/bluetooth/BluetoothGattCharacteristic;->setWriteType(I)V

    .line 203
    .line 204
    .line 205
    invoke-virtual {p2, p1}, Landroid/bluetooth/BluetoothGatt;->writeDescriptor(Landroid/bluetooth/BluetoothGattDescriptor;)Z

    .line 206
    .line 207
    .line 208
    move-result p1

    .line 209
    invoke-virtual {v0, v2}, Landroid/bluetooth/BluetoothGattCharacteristic;->setWriteType(I)V
    :try_end_1
    .catch Ljava/lang/SecurityException; {:try_start_1 .. :try_end_1} :catch_0

    .line 210
    .line 211
    .line 212
    return p1

    .line 213
    :cond_8
    :goto_1
    return v1

    .line 214
    :goto_2
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 215
    .line 216
    invoke-virtual {p2}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 217
    .line 218
    .line 219
    move-result p2

    .line 220
    const/4 v0, 0x6

    .line 221
    if-lt v0, p2, :cond_9

    .line 222
    .line 223
    iget-object p0, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 224
    .line 225
    invoke-virtual {p1}, Ljava/lang/Throwable;->getLocalizedMessage()Ljava/lang/String;

    .line 226
    .line 227
    .line 228
    move-result-object p1

    .line 229
    invoke-virtual {p0, v0, p1}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 230
    .line 231
    .line 232
    :cond_9
    :goto_3
    return v1
.end method

.method public final z(ILno/nordicsemi/android/ble/t;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 2
    .line 3
    invoke-virtual {v0}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-lt p1, v0, :cond_0

    .line 8
    .line 9
    iget-object p0, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 10
    .line 11
    invoke-interface {p2}, Lno/nordicsemi/android/ble/t;->d()Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object p2

    .line 15
    invoke-virtual {p0, p1, p2}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 16
    .line 17
    .line 18
    :cond_0
    return-void
.end method
