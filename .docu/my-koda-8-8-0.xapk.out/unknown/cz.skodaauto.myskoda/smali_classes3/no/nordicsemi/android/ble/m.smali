.class public final synthetic Lno/nordicsemi/android/ble/m;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lno/nordicsemi/android/ble/t;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:I


# direct methods
.method public synthetic constructor <init>(II)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Lno/nordicsemi/android/ble/m;->d:I

    .line 5
    .line 6
    iput p2, p0, Lno/nordicsemi/android/ble/m;->e:I

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final d()Ljava/lang/String;
    .locals 4

    .line 1
    sget v0, Lno/nordicsemi/android/ble/BleManagerHandler$4;->b:I

    .line 2
    .line 3
    const-string v0, " and new state: "

    .line 4
    .line 5
    const-string v1, " ("

    .line 6
    .line 7
    iget v2, p0, Lno/nordicsemi/android/ble/m;->d:I

    .line 8
    .line 9
    iget p0, p0, Lno/nordicsemi/android/ble/m;->e:I

    .line 10
    .line 11
    const-string v3, "[Callback] Connection state changed with status: "

    .line 12
    .line 13
    invoke-static {v2, p0, v3, v0, v1}, Lu/w;->j(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    sget-object v1, Lc01/a;->a:[C

    .line 18
    .line 19
    const-string v1, ")"

    .line 20
    .line 21
    if-eqz p0, :cond_3

    .line 22
    .line 23
    const/4 v2, 0x1

    .line 24
    if-eq p0, v2, :cond_2

    .line 25
    .line 26
    const/4 v2, 0x2

    .line 27
    if-eq p0, v2, :cond_1

    .line 28
    .line 29
    const/4 v2, 0x3

    .line 30
    if-eq p0, v2, :cond_0

    .line 31
    .line 32
    const-string v2, "UNKNOWN ("

    .line 33
    .line 34
    invoke-static {v2, p0, v1}, Lu/w;->e(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/String;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    goto :goto_0

    .line 39
    :cond_0
    const-string p0, "DISCONNECTING"

    .line 40
    .line 41
    goto :goto_0

    .line 42
    :cond_1
    const-string p0, "CONNECTED"

    .line 43
    .line 44
    goto :goto_0

    .line 45
    :cond_2
    const-string p0, "CONNECTING"

    .line 46
    .line 47
    goto :goto_0

    .line 48
    :cond_3
    const-string p0, "DISCONNECTED"

    .line 49
    .line 50
    :goto_0
    invoke-static {v0, p0, v1}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 51
    .line 52
    .line 53
    move-result-object p0

    .line 54
    return-object p0
.end method
