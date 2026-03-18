.class public final Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$TrafficDetected;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError;
.implements Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/StoppingReasonError;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "TrafficDetected"
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u00002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0007\n\u0002\u0010\u000e\n\u0002\u0008\u0002\n\u0002\u0010\u0008\n\u0002\u0008\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u000b\n\u0002\u0008\u0005\u0008\u0086\u0008\u0018\u00002\u00020\u00012\u00020\u0002B\u000f\u0012\u0006\u0010\u0004\u001a\u00020\u0003\u00a2\u0006\u0004\u0008\u0005\u0010\u0006J\u0010\u0010\u0007\u001a\u00020\u0003H\u00c6\u0003\u00a2\u0006\u0004\u0008\u0007\u0010\u0008J\u001a\u0010\t\u001a\u00020\u00002\u0008\u0008\u0002\u0010\u0004\u001a\u00020\u0003H\u00c6\u0001\u00a2\u0006\u0004\u0008\t\u0010\nJ\u0010\u0010\u000c\u001a\u00020\u000bH\u00d6\u0001\u00a2\u0006\u0004\u0008\u000c\u0010\rJ\u0010\u0010\u000f\u001a\u00020\u000eH\u00d6\u0001\u00a2\u0006\u0004\u0008\u000f\u0010\u0010J\u001a\u0010\u0014\u001a\u00020\u00132\u0008\u0010\u0012\u001a\u0004\u0018\u00010\u0011H\u00d6\u0003\u00a2\u0006\u0004\u0008\u0014\u0010\u0015R\u001a\u0010\u0004\u001a\u00020\u00038\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008\u0004\u0010\u0016\u001a\u0004\u0008\u0017\u0010\u0008\u00a8\u0006\u0018"
    }
    d2 = {
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$TrafficDetected;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/StoppingReasonError;",
        "Ls71/c;",
        "type",
        "<init>",
        "(Ls71/c;)V",
        "component1",
        "()Ls71/c;",
        "copy",
        "(Ls71/c;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$TrafficDetected;",
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
        "Ls71/c;",
        "getType",
        "remoteparkassistcoremeb_release"
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
.field private final type:Ls71/c;


# direct methods
.method public constructor <init>(Ls71/c;)V
    .locals 1

    .line 1
    const-string v0, "type"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$TrafficDetected;->type:Ls71/c;

    .line 10
    .line 11
    return-void
.end method

.method public static synthetic copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$TrafficDetected;Ls71/c;ILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$TrafficDetected;
    .locals 0

    .line 1
    and-int/lit8 p2, p2, 0x1

    .line 2
    .line 3
    if-eqz p2, :cond_0

    .line 4
    .line 5
    iget-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$TrafficDetected;->type:Ls71/c;

    .line 6
    .line 7
    :cond_0
    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$TrafficDetected;->copy(Ls71/c;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$TrafficDetected;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method


# virtual methods
.method public final component1()Ls71/c;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$TrafficDetected;->type:Ls71/c;

    .line 2
    .line 3
    return-object p0
.end method

.method public final copy(Ls71/c;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$TrafficDetected;
    .locals 0

    .line 1
    const-string p0, "type"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$TrafficDetected;

    .line 7
    .line 8
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$TrafficDetected;-><init>(Ls71/c;)V

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
    instance-of v1, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$TrafficDetected;

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
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$TrafficDetected;

    .line 12
    .line 13
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$TrafficDetected;->type:Ls71/c;

    .line 14
    .line 15
    iget-object p1, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$TrafficDetected;->type:Ls71/c;

    .line 16
    .line 17
    if-eq p0, p1, :cond_2

    .line 18
    .line 19
    return v2

    .line 20
    :cond_2
    return v0
.end method

.method public getType()Ls71/c;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$TrafficDetected;->type:Ls71/c;

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$TrafficDetected;->type:Ls71/c;

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
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$TrafficDetected;->type:Ls71/c;

    .line 2
    .line 3
    const-string v0, "TrafficDetected(type="

    .line 4
    .line 5
    const-string v1, ")"

    .line 6
    .line 7
    invoke-static {v0, p0, v1}, Lkx/a;->k(Ljava/lang/String;Ls71/c;Ljava/lang/String;)Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method
