.class public final Lno/nordicsemi/android/ble/c0;
.super Lno/nordicsemi/android/ble/m0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final n:I

.field public final o:I

.field public final p:I


# direct methods
.method public constructor <init>()V
    .locals 1

    const/16 v0, 0x22

    .line 1
    invoke-direct {p0, v0}, Lno/nordicsemi/android/ble/i0;-><init>(I)V

    const/4 v0, 0x0

    .line 2
    iput v0, p0, Lno/nordicsemi/android/ble/c0;->n:I

    .line 3
    iput v0, p0, Lno/nordicsemi/android/ble/c0;->o:I

    .line 4
    iput v0, p0, Lno/nordicsemi/android/ble/c0;->p:I

    return-void
.end method

.method public constructor <init>(III)V
    .locals 2

    const/16 v0, 0x21

    .line 5
    invoke-direct {p0, v0}, Lno/nordicsemi/android/ble/i0;-><init>(I)V

    and-int/lit8 v0, p1, -0x8

    const/4 v1, 0x1

    if-lez v0, :cond_0

    move p1, v1

    :cond_0
    and-int/lit8 v0, p2, -0x8

    if-lez v0, :cond_1

    move p2, v1

    :cond_1
    if-ltz p3, :cond_2

    const/4 v0, 0x2

    if-le p3, v0, :cond_3

    :cond_2
    const/4 p3, 0x0

    .line 6
    :cond_3
    iput p1, p0, Lno/nordicsemi/android/ble/c0;->n:I

    .line 7
    iput p2, p0, Lno/nordicsemi/android/ble/c0;->o:I

    .line 8
    iput p3, p0, Lno/nordicsemi/android/ble/c0;->p:I

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
