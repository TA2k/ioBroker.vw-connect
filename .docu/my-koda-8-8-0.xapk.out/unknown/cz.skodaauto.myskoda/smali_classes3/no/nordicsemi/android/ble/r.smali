.class public final synthetic Lno/nordicsemi/android/ble/r;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lno/nordicsemi/android/ble/t;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:I

.field public final synthetic f:I

.field public final synthetic g:I


# direct methods
.method public synthetic constructor <init>(IIII)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Lno/nordicsemi/android/ble/r;->d:I

    .line 5
    .line 6
    iput p2, p0, Lno/nordicsemi/android/ble/r;->e:I

    .line 7
    .line 8
    iput p3, p0, Lno/nordicsemi/android/ble/r;->f:I

    .line 9
    .line 10
    iput p4, p0, Lno/nordicsemi/android/ble/r;->g:I

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final d()Ljava/lang/String;
    .locals 5

    .line 1
    sget v0, Lno/nordicsemi/android/ble/BleManagerHandler$4;->b:I

    .line 2
    .line 3
    const-string v0, "Connection parameters update failed with status "

    .line 4
    .line 5
    const-string v1, " (interval: "

    .line 6
    .line 7
    iget v2, p0, Lno/nordicsemi/android/ble/r;->d:I

    .line 8
    .line 9
    invoke-static {v0, v2, v1}, Lp3/m;->p(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/StringBuilder;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    iget v1, p0, Lno/nordicsemi/android/ble/r;->e:I

    .line 14
    .line 15
    int-to-double v1, v1

    .line 16
    const-wide/high16 v3, 0x3ff4000000000000L    # 1.25

    .line 17
    .line 18
    mul-double/2addr v1, v3

    .line 19
    invoke-virtual {v0, v1, v2}, Ljava/lang/StringBuilder;->append(D)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    const-string v1, "ms, latency: "

    .line 23
    .line 24
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 25
    .line 26
    .line 27
    iget v1, p0, Lno/nordicsemi/android/ble/r;->f:I

    .line 28
    .line 29
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 30
    .line 31
    .line 32
    const-string v1, ", timeout: "

    .line 33
    .line 34
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 35
    .line 36
    .line 37
    iget p0, p0, Lno/nordicsemi/android/ble/r;->g:I

    .line 38
    .line 39
    mul-int/lit8 p0, p0, 0xa

    .line 40
    .line 41
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 42
    .line 43
    .line 44
    const-string p0, "ms)"

    .line 45
    .line 46
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 47
    .line 48
    .line 49
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    return-object p0
.end method
