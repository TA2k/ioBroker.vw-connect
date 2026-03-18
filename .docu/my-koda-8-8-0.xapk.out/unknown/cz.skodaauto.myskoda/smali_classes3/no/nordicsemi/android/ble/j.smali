.class public final synthetic Lno/nordicsemi/android/ble/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyz0/b;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lno/nordicsemi/android/ble/d;


# direct methods
.method public synthetic constructor <init>(Lno/nordicsemi/android/ble/d;I)V
    .locals 0

    .line 1
    iput p2, p0, Lno/nordicsemi/android/ble/j;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lno/nordicsemi/android/ble/j;->e:Lno/nordicsemi/android/ble/d;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Landroid/bluetooth/BluetoothDevice;Lzz0/a;)V
    .locals 3

    .line 1
    iget p1, p0, Lno/nordicsemi/android/ble/j;->d:I

    .line 2
    .line 3
    iget-object p0, p0, Lno/nordicsemi/android/ble/j;->e:Lno/nordicsemi/android/ble/d;

    .line 4
    .line 5
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 6
    .line 7
    .line 8
    packed-switch p1, :pswitch_data_0

    .line 9
    .line 10
    .line 11
    iget-object p1, p2, Lzz0/a;->d:[B

    .line 12
    .line 13
    if-eqz p1, :cond_0

    .line 14
    .line 15
    array-length p1, p1

    .line 16
    goto :goto_0

    .line 17
    :cond_0
    const/4 p1, 0x0

    .line 18
    :goto_0
    const/4 v0, 0x1

    .line 19
    if-ne p1, v0, :cond_2

    .line 20
    .line 21
    invoke-virtual {p2}, Lzz0/a;->h()Ljava/lang/Integer;

    .line 22
    .line 23
    .line 24
    move-result-object p1

    .line 25
    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    .line 26
    .line 27
    .line 28
    move-result p1

    .line 29
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 30
    .line 31
    invoke-virtual {p2}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 32
    .line 33
    .line 34
    move-result p2

    .line 35
    const/4 v0, 0x4

    .line 36
    if-lt v0, p2, :cond_1

    .line 37
    .line 38
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 39
    .line 40
    new-instance v1, Ljava/lang/StringBuilder;

    .line 41
    .line 42
    const-string v2, "Battery Level received: "

    .line 43
    .line 44
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 48
    .line 49
    .line 50
    const-string v2, "%"

    .line 51
    .line 52
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 53
    .line 54
    .line 55
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 56
    .line 57
    .line 58
    move-result-object v1

    .line 59
    invoke-virtual {p2, v0, v1}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 60
    .line 61
    .line 62
    :cond_1
    iput p1, p0, Lno/nordicsemi/android/ble/d;->x:I

    .line 63
    .line 64
    iget-object p0, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 65
    .line 66
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 67
    .line 68
    .line 69
    :cond_2
    return-void

    .line 70
    :pswitch_0
    iget-object p1, p2, Lzz0/a;->d:[B

    .line 71
    .line 72
    if-eqz p1, :cond_3

    .line 73
    .line 74
    array-length p1, p1

    .line 75
    goto :goto_1

    .line 76
    :cond_3
    const/4 p1, 0x0

    .line 77
    :goto_1
    const/4 v0, 0x1

    .line 78
    if-ne p1, v0, :cond_4

    .line 79
    .line 80
    invoke-virtual {p2}, Lzz0/a;->h()Ljava/lang/Integer;

    .line 81
    .line 82
    .line 83
    move-result-object p1

    .line 84
    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    .line 85
    .line 86
    .line 87
    move-result p1

    .line 88
    iput p1, p0, Lno/nordicsemi/android/ble/d;->x:I

    .line 89
    .line 90
    iget-object p0, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 91
    .line 92
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 93
    .line 94
    .line 95
    :cond_4
    return-void

    .line 96
    nop

    .line 97
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
