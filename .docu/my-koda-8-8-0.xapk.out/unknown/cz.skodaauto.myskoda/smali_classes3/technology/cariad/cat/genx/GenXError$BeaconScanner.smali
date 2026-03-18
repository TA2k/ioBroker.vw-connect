.class public final Ltechnology/cariad/cat/genx/GenXError$BeaconScanner;
.super Ltechnology/cariad/cat/genx/GenXError;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Ltechnology/cariad/cat/genx/GenXError;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "BeaconScanner"
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000.\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0007\n\u0002\u0010\u000e\n\u0002\u0008\u0002\n\u0002\u0010\u0008\n\u0002\u0008\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u000b\n\u0002\u0008\u0005\u0008\u0086\u0008\u0018\u00002\u00020\u0001B\u000f\u0012\u0006\u0010\u0003\u001a\u00020\u0002\u00a2\u0006\u0004\u0008\u0004\u0010\u0005J\u0010\u0010\u0006\u001a\u00020\u0002H\u00c6\u0003\u00a2\u0006\u0004\u0008\u0006\u0010\u0007J\u001a\u0010\u0008\u001a\u00020\u00002\u0008\u0008\u0002\u0010\u0003\u001a\u00020\u0002H\u00c6\u0001\u00a2\u0006\u0004\u0008\u0008\u0010\tJ\u0010\u0010\u000b\u001a\u00020\nH\u00d6\u0001\u00a2\u0006\u0004\u0008\u000b\u0010\u000cJ\u0010\u0010\u000e\u001a\u00020\rH\u00d6\u0001\u00a2\u0006\u0004\u0008\u000e\u0010\u000fJ\u001a\u0010\u0013\u001a\u00020\u00122\u0008\u0010\u0011\u001a\u0004\u0018\u00010\u0010H\u00d6\u0003\u00a2\u0006\u0004\u0008\u0013\u0010\u0014R\u0017\u0010\u0003\u001a\u00020\u00028\u0006\u00a2\u0006\u000c\n\u0004\u0008\u0003\u0010\u0015\u001a\u0004\u0008\u0016\u0010\u0007\u00a8\u0006\u0017"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/GenXError$BeaconScanner;",
        "Ltechnology/cariad/cat/genx/GenXError;",
        "Lt41/k;",
        "beaconScannerError",
        "<init>",
        "(Lt41/k;)V",
        "component1",
        "()Lt41/k;",
        "copy",
        "(Lt41/k;)Ltechnology/cariad/cat/genx/GenXError$BeaconScanner;",
        "",
        "toString",
        "()Ljava/lang/String;",
        "",
        "hashCode",
        "()I",
        "",
        "other",
        "",
        "equals",
        "(Ljava/lang/Object;)Z",
        "Lt41/k;",
        "getBeaconScannerError",
        "genx_release"
    }
    k = 0x1
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation


# instance fields
.field private final beaconScannerError:Lt41/k;


# direct methods
.method public constructor <init>(Lt41/k;)V
    .locals 1

    .line 1
    const-string v0, "beaconScannerError"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const/4 v0, 0x0

    .line 7
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/genx/GenXError;-><init>(Lkotlin/jvm/internal/g;)V

    .line 8
    .line 9
    .line 10
    iput-object p1, p0, Ltechnology/cariad/cat/genx/GenXError$BeaconScanner;->beaconScannerError:Lt41/k;

    .line 11
    .line 12
    return-void
.end method

.method public static synthetic copy$default(Ltechnology/cariad/cat/genx/GenXError$BeaconScanner;Lt41/k;ILjava/lang/Object;)Ltechnology/cariad/cat/genx/GenXError$BeaconScanner;
    .locals 0

    .line 1
    and-int/lit8 p2, p2, 0x1

    .line 2
    .line 3
    if-eqz p2, :cond_0

    .line 4
    .line 5
    iget-object p1, p0, Ltechnology/cariad/cat/genx/GenXError$BeaconScanner;->beaconScannerError:Lt41/k;

    .line 6
    .line 7
    :cond_0
    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/genx/GenXError$BeaconScanner;->copy(Lt41/k;)Ltechnology/cariad/cat/genx/GenXError$BeaconScanner;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method


# virtual methods
.method public final component1()Lt41/k;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/GenXError$BeaconScanner;->beaconScannerError:Lt41/k;

    .line 2
    .line 3
    return-object p0
.end method

.method public final copy(Lt41/k;)Ltechnology/cariad/cat/genx/GenXError$BeaconScanner;
    .locals 0

    .line 1
    const-string p0, "beaconScannerError"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance p0, Ltechnology/cariad/cat/genx/GenXError$BeaconScanner;

    .line 7
    .line 8
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/genx/GenXError$BeaconScanner;-><init>(Lt41/k;)V

    .line 9
    .line 10
    .line 11
    return-object p0
.end method

.method public equals(Ljava/lang/Object;)Z
    .locals 3

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Ltechnology/cariad/cat/genx/GenXError$BeaconScanner;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-nez v1, :cond_1

    .line 9
    .line 10
    return v2

    .line 11
    :cond_1
    check-cast p1, Ltechnology/cariad/cat/genx/GenXError$BeaconScanner;

    .line 12
    .line 13
    iget-object p0, p0, Ltechnology/cariad/cat/genx/GenXError$BeaconScanner;->beaconScannerError:Lt41/k;

    .line 14
    .line 15
    iget-object p1, p1, Ltechnology/cariad/cat/genx/GenXError$BeaconScanner;->beaconScannerError:Lt41/k;

    .line 16
    .line 17
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result p0

    .line 21
    if-nez p0, :cond_2

    .line 22
    .line 23
    return v2

    .line 24
    :cond_2
    return v0
.end method

.method public final getBeaconScannerError()Lt41/k;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/GenXError$BeaconScanner;->beaconScannerError:Lt41/k;

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/GenXError$BeaconScanner;->beaconScannerError:Lt41/k;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public toString()Ljava/lang/String;
    .locals 2

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/GenXError$BeaconScanner;->beaconScannerError:Lt41/k;

    .line 2
    .line 3
    new-instance v0, Ljava/lang/StringBuilder;

    .line 4
    .line 5
    const-string v1, "BeaconScanner(beaconScannerError="

    .line 6
    .line 7
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string p0, ")"

    .line 14
    .line 15
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0
.end method
