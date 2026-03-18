.class public final Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u001e\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u000b\n\u0002\u0008\u0010\n\u0002\u0010\u0008\n\u0000\n\u0002\u0010\u000e\n\u0000\u0008\u0086\u0008\u0018\u00002\u00020\u0001B9\u0012\u0008\u0008\u0002\u0010\u0002\u001a\u00020\u0003\u0012\u0008\u0008\u0002\u0010\u0004\u001a\u00020\u0003\u0012\u0008\u0008\u0002\u0010\u0005\u001a\u00020\u0003\u0012\u0008\u0008\u0002\u0010\u0006\u001a\u00020\u0003\u0012\u0008\u0008\u0002\u0010\u0007\u001a\u00020\u0003\u00a2\u0006\u0004\u0008\u0008\u0010\tJ\t\u0010\u000b\u001a\u00020\u0003H\u00c6\u0003J\t\u0010\u000c\u001a\u00020\u0003H\u00c6\u0003J\t\u0010\r\u001a\u00020\u0003H\u00c6\u0003J\t\u0010\u000e\u001a\u00020\u0003H\u00c6\u0003J\t\u0010\u000f\u001a\u00020\u0003H\u00c6\u0003J;\u0010\u0010\u001a\u00020\u00002\u0008\u0008\u0002\u0010\u0002\u001a\u00020\u00032\u0008\u0008\u0002\u0010\u0004\u001a\u00020\u00032\u0008\u0008\u0002\u0010\u0005\u001a\u00020\u00032\u0008\u0008\u0002\u0010\u0006\u001a\u00020\u00032\u0008\u0008\u0002\u0010\u0007\u001a\u00020\u0003H\u00c6\u0001J\u0013\u0010\u0011\u001a\u00020\u00032\u0008\u0010\u0012\u001a\u0004\u0018\u00010\u0001H\u00d6\u0003J\t\u0010\u0013\u001a\u00020\u0014H\u00d6\u0001J\t\u0010\u0015\u001a\u00020\u0016H\u00d6\u0001R\u0011\u0010\u0002\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0002\u0010\nR\u0011\u0010\u0004\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0004\u0010\nR\u0011\u0010\u0005\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0005\u0010\nR\u0011\u0010\u0006\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0006\u0010\nR\u0011\u0010\u0007\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0007\u0010\n\u00a8\u0006\u0017"
    }
    d2 = {
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;",
        "",
        "isParallelAvailable",
        "",
        "isPerpendicularAvailable",
        "isGarageAvailable",
        "isBasicAvailable",
        "isTPAorAAAAvailable",
        "<init>",
        "(ZZZZZ)V",
        "()Z",
        "component1",
        "component2",
        "component3",
        "component4",
        "component5",
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
.field private final isBasicAvailable:Z

.field private final isGarageAvailable:Z

.field private final isParallelAvailable:Z

.field private final isPerpendicularAvailable:Z

.field private final isTPAorAAAAvailable:Z


# direct methods
.method public constructor <init>()V
    .locals 8

    .line 1
    const/16 v6, 0x1f

    const/4 v7, 0x0

    const/4 v1, 0x0

    const/4 v2, 0x0

    const/4 v3, 0x0

    const/4 v4, 0x0

    const/4 v5, 0x0

    move-object v0, p0

    invoke-direct/range {v0 .. v7}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;-><init>(ZZZZZILkotlin/jvm/internal/g;)V

    return-void
.end method

.method public constructor <init>(ZZZZZ)V
    .locals 0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    iput-boolean p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;->isParallelAvailable:Z

    .line 4
    iput-boolean p2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;->isPerpendicularAvailable:Z

    .line 5
    iput-boolean p3, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;->isGarageAvailable:Z

    .line 6
    iput-boolean p4, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;->isBasicAvailable:Z

    .line 7
    iput-boolean p5, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;->isTPAorAAAAvailable:Z

    return-void
.end method

.method public synthetic constructor <init>(ZZZZZILkotlin/jvm/internal/g;)V
    .locals 1

    and-int/lit8 p7, p6, 0x1

    const/4 v0, 0x0

    if-eqz p7, :cond_0

    move p1, v0

    :cond_0
    and-int/lit8 p7, p6, 0x2

    if-eqz p7, :cond_1

    move p2, v0

    :cond_1
    and-int/lit8 p7, p6, 0x4

    if-eqz p7, :cond_2

    move p3, v0

    :cond_2
    and-int/lit8 p7, p6, 0x8

    if-eqz p7, :cond_3

    move p4, v0

    :cond_3
    and-int/lit8 p6, p6, 0x10

    if-eqz p6, :cond_4

    move p5, v0

    .line 8
    :cond_4
    invoke-direct/range {p0 .. p5}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;-><init>(ZZZZZ)V

    return-void
.end method

.method public static synthetic copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;ZZZZZILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;
    .locals 0

    .line 1
    and-int/lit8 p7, p6, 0x1

    .line 2
    .line 3
    if-eqz p7, :cond_0

    .line 4
    .line 5
    iget-boolean p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;->isParallelAvailable:Z

    .line 6
    .line 7
    :cond_0
    and-int/lit8 p7, p6, 0x2

    .line 8
    .line 9
    if-eqz p7, :cond_1

    .line 10
    .line 11
    iget-boolean p2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;->isPerpendicularAvailable:Z

    .line 12
    .line 13
    :cond_1
    and-int/lit8 p7, p6, 0x4

    .line 14
    .line 15
    if-eqz p7, :cond_2

    .line 16
    .line 17
    iget-boolean p3, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;->isGarageAvailable:Z

    .line 18
    .line 19
    :cond_2
    and-int/lit8 p7, p6, 0x8

    .line 20
    .line 21
    if-eqz p7, :cond_3

    .line 22
    .line 23
    iget-boolean p4, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;->isBasicAvailable:Z

    .line 24
    .line 25
    :cond_3
    and-int/lit8 p6, p6, 0x10

    .line 26
    .line 27
    if-eqz p6, :cond_4

    .line 28
    .line 29
    iget-boolean p5, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;->isTPAorAAAAvailable:Z

    .line 30
    .line 31
    :cond_4
    move p6, p4

    .line 32
    move p7, p5

    .line 33
    move p4, p2

    .line 34
    move p5, p3

    .line 35
    move-object p2, p0

    .line 36
    move p3, p1

    .line 37
    invoke-virtual/range {p2 .. p7}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;->copy(ZZZZZ)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    return-object p0
.end method


# virtual methods
.method public final component1()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;->isParallelAvailable:Z

    .line 2
    .line 3
    return p0
.end method

.method public final component2()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;->isPerpendicularAvailable:Z

    .line 2
    .line 3
    return p0
.end method

.method public final component3()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;->isGarageAvailable:Z

    .line 2
    .line 3
    return p0
.end method

.method public final component4()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;->isBasicAvailable:Z

    .line 2
    .line 3
    return p0
.end method

.method public final component5()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;->isTPAorAAAAvailable:Z

    .line 2
    .line 3
    return p0
.end method

.method public final copy(ZZZZZ)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;
    .locals 0

    .line 1
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;

    .line 2
    .line 3
    invoke-direct/range {p0 .. p5}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;-><init>(ZZZZZ)V

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
    instance-of v1, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;

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
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;

    .line 12
    .line 13
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;->isParallelAvailable:Z

    .line 14
    .line 15
    iget-boolean v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;->isParallelAvailable:Z

    .line 16
    .line 17
    if-eq v1, v3, :cond_2

    .line 18
    .line 19
    return v2

    .line 20
    :cond_2
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;->isPerpendicularAvailable:Z

    .line 21
    .line 22
    iget-boolean v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;->isPerpendicularAvailable:Z

    .line 23
    .line 24
    if-eq v1, v3, :cond_3

    .line 25
    .line 26
    return v2

    .line 27
    :cond_3
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;->isGarageAvailable:Z

    .line 28
    .line 29
    iget-boolean v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;->isGarageAvailable:Z

    .line 30
    .line 31
    if-eq v1, v3, :cond_4

    .line 32
    .line 33
    return v2

    .line 34
    :cond_4
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;->isBasicAvailable:Z

    .line 35
    .line 36
    iget-boolean v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;->isBasicAvailable:Z

    .line 37
    .line 38
    if-eq v1, v3, :cond_5

    .line 39
    .line 40
    return v2

    .line 41
    :cond_5
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;->isTPAorAAAAvailable:Z

    .line 42
    .line 43
    iget-boolean p1, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;->isTPAorAAAAvailable:Z

    .line 44
    .line 45
    if-eq p0, p1, :cond_6

    .line 46
    .line 47
    return v2

    .line 48
    :cond_6
    return v0
.end method

.method public hashCode()I
    .locals 3

    .line 1
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;->isParallelAvailable:Z

    .line 2
    .line 3
    invoke-static {v0}, Ljava/lang/Boolean;->hashCode(Z)I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/16 v1, 0x1f

    .line 8
    .line 9
    mul-int/2addr v0, v1

    .line 10
    iget-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;->isPerpendicularAvailable:Z

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;->isGarageAvailable:Z

    .line 17
    .line 18
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    iget-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;->isBasicAvailable:Z

    .line 23
    .line 24
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;->isTPAorAAAAvailable:Z

    .line 29
    .line 30
    invoke-static {p0}, Ljava/lang/Boolean;->hashCode(Z)I

    .line 31
    .line 32
    .line 33
    move-result p0

    .line 34
    add-int/2addr p0, v0

    .line 35
    return p0
.end method

.method public final isBasicAvailable()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;->isBasicAvailable:Z

    .line 2
    .line 3
    return p0
.end method

.method public final isGarageAvailable()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;->isGarageAvailable:Z

    .line 2
    .line 3
    return p0
.end method

.method public final isParallelAvailable()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;->isParallelAvailable:Z

    .line 2
    .line 3
    return p0
.end method

.method public final isPerpendicularAvailable()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;->isPerpendicularAvailable:Z

    .line 2
    .line 3
    return p0
.end method

.method public final isTPAorAAAAvailable()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;->isTPAorAAAAvailable:Z

    .line 2
    .line 3
    return p0
.end method

.method public toString()Ljava/lang/String;
    .locals 7

    .line 1
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;->isParallelAvailable:Z

    .line 2
    .line 3
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;->isPerpendicularAvailable:Z

    .line 4
    .line 5
    iget-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;->isGarageAvailable:Z

    .line 6
    .line 7
    iget-boolean v3, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;->isBasicAvailable:Z

    .line 8
    .line 9
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;->isTPAorAAAAvailable:Z

    .line 10
    .line 11
    const-string v4, ", isPerpendicularAvailable="

    .line 12
    .line 13
    const-string v5, ", isGarageAvailable="

    .line 14
    .line 15
    const-string v6, "ParkingScenariosAvailabilityMEB(isParallelAvailable="

    .line 16
    .line 17
    invoke-static {v6, v4, v5, v0, v1}, Lvj/b;->o(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZ)Ljava/lang/StringBuilder;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    const-string v1, ", isBasicAvailable="

    .line 22
    .line 23
    const-string v4, ", isTPAorAAAAvailable="

    .line 24
    .line 25
    invoke-static {v0, v2, v1, v3, v4}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 26
    .line 27
    .line 28
    const-string v1, ")"

    .line 29
    .line 30
    invoke-static {v0, p0, v1}, Lf2/m0;->m(Ljava/lang/StringBuilder;ZLjava/lang/String;)Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    return-object p0
.end method
