.class public final Lno/nordicsemi/android/ble/w;
.super Lno/nordicsemi/android/ble/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final q:Lno/nordicsemi/android/ble/v;

.field public final r:Ljava/lang/Object;

.field public s:Z


# direct methods
.method public constructor <init>(Ljava/lang/Object;Lno/nordicsemi/android/ble/v;)V
    .locals 1

    .line 1
    const/16 v0, 0x18

    .line 2
    .line 3
    invoke-direct {p0, v0}, Lno/nordicsemi/android/ble/i0;-><init>(I)V

    .line 4
    .line 5
    .line 6
    const/4 v0, 0x0

    .line 7
    iput-boolean v0, p0, Lno/nordicsemi/android/ble/w;->s:Z

    .line 8
    .line 9
    iput-object p2, p0, Lno/nordicsemi/android/ble/w;->q:Lno/nordicsemi/android/ble/v;

    .line 10
    .line 11
    iput-object p1, p0, Lno/nordicsemi/android/ble/w;->r:Ljava/lang/Object;

    .line 12
    .line 13
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

.method public final h()Z
    .locals 3

    .line 1
    const/4 v0, 0x1

    .line 2
    :try_start_0
    iget-object v1, p0, Lno/nordicsemi/android/ble/w;->q:Lno/nordicsemi/android/ble/v;

    .line 3
    .line 4
    iget-object v2, p0, Lno/nordicsemi/android/ble/w;->r:Ljava/lang/Object;

    .line 5
    .line 6
    invoke-interface {v1, v2}, Lno/nordicsemi/android/ble/v;->a(Ljava/lang/Object;)Z

    .line 7
    .line 8
    .line 9
    move-result v1

    .line 10
    iget-boolean p0, p0, Lno/nordicsemi/android/ble/w;->s:Z
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 11
    .line 12
    if-ne v1, p0, :cond_0

    .line 13
    .line 14
    return v0

    .line 15
    :cond_0
    const/4 p0, 0x0

    .line 16
    return p0

    .line 17
    :catch_0
    move-exception p0

    .line 18
    const-string v1, "ConditionalWaitRequest"

    .line 19
    .line 20
    const-string v2, "Error while checking predicate"

    .line 21
    .line 22
    invoke-static {v1, v2, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 23
    .line 24
    .line 25
    return v0
.end method
