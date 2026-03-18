.class public final Lno/nordicsemi/android/ble/b0;
.super Lno/nordicsemi/android/ble/m0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final n:I


# direct methods
.method public constructor <init>(I)V
    .locals 1

    .line 1
    const/16 v0, 0x1f

    .line 2
    .line 3
    invoke-direct {p0, v0}, Lno/nordicsemi/android/ble/i0;-><init>(I)V

    .line 4
    .line 5
    .line 6
    const/16 v0, 0x17

    .line 7
    .line 8
    if-ge p1, v0, :cond_0

    .line 9
    .line 10
    move p1, v0

    .line 11
    :cond_0
    const/16 v0, 0x205

    .line 12
    .line 13
    if-le p1, v0, :cond_1

    .line 14
    .line 15
    move p1, v0

    .line 16
    :cond_1
    iput p1, p0, Lno/nordicsemi/android/ble/b0;->n:I

    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public final e(Lno/nordicsemi/android/ble/d;)Lno/nordicsemi/android/ble/i0;
    .locals 0

    .line 1
    invoke-super {p0, p1}, Lno/nordicsemi/android/ble/i0;->e(Lno/nordicsemi/android/ble/d;)Lno/nordicsemi/android/ble/i0;

    .line 2
    .line 3
    .line 4
    return-object p0
.end method

.method public final f(Lno/nordicsemi/android/ble/d;)V
    .locals 0

    .line 1
    invoke-super {p0, p1}, Lno/nordicsemi/android/ble/i0;->e(Lno/nordicsemi/android/ble/d;)Lno/nordicsemi/android/ble/i0;

    .line 2
    .line 3
    .line 4
    return-void
.end method
