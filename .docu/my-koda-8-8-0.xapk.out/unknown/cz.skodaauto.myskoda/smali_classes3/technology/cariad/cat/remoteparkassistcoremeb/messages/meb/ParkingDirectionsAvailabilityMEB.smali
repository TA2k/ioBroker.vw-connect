.class public final Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionsAvailabilityMEB;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u001e\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u000b\n\u0002\u0008\n\n\u0002\u0010\u0008\n\u0000\n\u0002\u0010\u000e\n\u0000\u0008\u0086\u0008\u0018\u00002\u00020\u0001B\u001b\u0012\u0008\u0008\u0002\u0010\u0002\u001a\u00020\u0003\u0012\u0008\u0008\u0002\u0010\u0004\u001a\u00020\u0003\u00a2\u0006\u0004\u0008\u0005\u0010\u0006J\t\u0010\u0008\u001a\u00020\u0003H\u00c6\u0003J\t\u0010\t\u001a\u00020\u0003H\u00c6\u0003J\u001d\u0010\n\u001a\u00020\u00002\u0008\u0008\u0002\u0010\u0002\u001a\u00020\u00032\u0008\u0008\u0002\u0010\u0004\u001a\u00020\u0003H\u00c6\u0001J\u0013\u0010\u000b\u001a\u00020\u00032\u0008\u0010\u000c\u001a\u0004\u0018\u00010\u0001H\u00d6\u0003J\t\u0010\r\u001a\u00020\u000eH\u00d6\u0001J\t\u0010\u000f\u001a\u00020\u0010H\u00d6\u0001R\u0011\u0010\u0002\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0002\u0010\u0007R\u0011\u0010\u0004\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0004\u0010\u0007\u00a8\u0006\u0011"
    }
    d2 = {
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionsAvailabilityMEB;",
        "",
        "isForwardAvailable",
        "",
        "isBackwardAvailable",
        "<init>",
        "(ZZ)V",
        "()Z",
        "component1",
        "component2",
        "copy",
        "equals",
        "other",
        "hashCode",
        "",
        "toString",
        "",
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
.field private final isBackwardAvailable:Z

.field private final isForwardAvailable:Z


# direct methods
.method public constructor <init>()V
    .locals 3

    .line 1
    const/4 v0, 0x3

    const/4 v1, 0x0

    const/4 v2, 0x0

    invoke-direct {p0, v2, v2, v0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionsAvailabilityMEB;-><init>(ZZILkotlin/jvm/internal/g;)V

    return-void
.end method

.method public constructor <init>(ZZ)V
    .locals 0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    iput-boolean p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionsAvailabilityMEB;->isForwardAvailable:Z

    .line 4
    iput-boolean p2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionsAvailabilityMEB;->isBackwardAvailable:Z

    return-void
.end method

.method public synthetic constructor <init>(ZZILkotlin/jvm/internal/g;)V
    .locals 1

    and-int/lit8 p4, p3, 0x1

    const/4 v0, 0x0

    if-eqz p4, :cond_0

    move p1, v0

    :cond_0
    and-int/lit8 p3, p3, 0x2

    if-eqz p3, :cond_1

    move p2, v0

    .line 5
    :cond_1
    invoke-direct {p0, p1, p2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionsAvailabilityMEB;-><init>(ZZ)V

    return-void
.end method

.method public static synthetic copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionsAvailabilityMEB;ZZILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionsAvailabilityMEB;
    .locals 0

    .line 1
    and-int/lit8 p4, p3, 0x1

    .line 2
    .line 3
    if-eqz p4, :cond_0

    .line 4
    .line 5
    iget-boolean p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionsAvailabilityMEB;->isForwardAvailable:Z

    .line 6
    .line 7
    :cond_0
    and-int/lit8 p3, p3, 0x2

    .line 8
    .line 9
    if-eqz p3, :cond_1

    .line 10
    .line 11
    iget-boolean p2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionsAvailabilityMEB;->isBackwardAvailable:Z

    .line 12
    .line 13
    :cond_1
    invoke-virtual {p0, p1, p2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionsAvailabilityMEB;->copy(ZZ)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionsAvailabilityMEB;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method


# virtual methods
.method public final component1()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionsAvailabilityMEB;->isForwardAvailable:Z

    .line 2
    .line 3
    return p0
.end method

.method public final component2()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionsAvailabilityMEB;->isBackwardAvailable:Z

    .line 2
    .line 3
    return p0
.end method

.method public final copy(ZZ)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionsAvailabilityMEB;
    .locals 0

    .line 1
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionsAvailabilityMEB;

    .line 2
    .line 3
    invoke-direct {p0, p1, p2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionsAvailabilityMEB;-><init>(ZZ)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public equals(Ljava/lang/Object;)Z
    .locals 4

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionsAvailabilityMEB;

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
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionsAvailabilityMEB;

    .line 12
    .line 13
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionsAvailabilityMEB;->isForwardAvailable:Z

    .line 14
    .line 15
    iget-boolean v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionsAvailabilityMEB;->isForwardAvailable:Z

    .line 16
    .line 17
    if-eq v1, v3, :cond_2

    .line 18
    .line 19
    return v2

    .line 20
    :cond_2
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionsAvailabilityMEB;->isBackwardAvailable:Z

    .line 21
    .line 22
    iget-boolean p1, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionsAvailabilityMEB;->isBackwardAvailable:Z

    .line 23
    .line 24
    if-eq p0, p1, :cond_3

    .line 25
    .line 26
    return v2

    .line 27
    :cond_3
    return v0
.end method

.method public hashCode()I
    .locals 1

    .line 1
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionsAvailabilityMEB;->isForwardAvailable:Z

    .line 2
    .line 3
    invoke-static {v0}, Ljava/lang/Boolean;->hashCode(Z)I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    mul-int/lit8 v0, v0, 0x1f

    .line 8
    .line 9
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionsAvailabilityMEB;->isBackwardAvailable:Z

    .line 10
    .line 11
    invoke-static {p0}, Ljava/lang/Boolean;->hashCode(Z)I

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    add-int/2addr p0, v0

    .line 16
    return p0
.end method

.method public final isBackwardAvailable()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionsAvailabilityMEB;->isBackwardAvailable:Z

    .line 2
    .line 3
    return p0
.end method

.method public final isForwardAvailable()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionsAvailabilityMEB;->isForwardAvailable:Z

    .line 2
    .line 3
    return p0
.end method

.method public toString()Ljava/lang/String;
    .locals 3

    .line 1
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionsAvailabilityMEB;->isForwardAvailable:Z

    .line 2
    .line 3
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionsAvailabilityMEB;->isBackwardAvailable:Z

    .line 4
    .line 5
    new-instance v1, Ljava/lang/StringBuilder;

    .line 6
    .line 7
    const-string v2, "ParkingDirectionsAvailabilityMEB(isForwardAvailable="

    .line 8
    .line 9
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 13
    .line 14
    .line 15
    const-string v0, ", isBackwardAvailable="

    .line 16
    .line 17
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 18
    .line 19
    .line 20
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string p0, ")"

    .line 24
    .line 25
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    return-object p0
.end method
