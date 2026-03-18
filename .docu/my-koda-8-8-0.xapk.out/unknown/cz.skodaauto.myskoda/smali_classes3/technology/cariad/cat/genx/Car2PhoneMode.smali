.class public final Ltechnology/cariad/cat/genx/Car2PhoneMode;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Ltechnology/cariad/cat/genx/Car2PhoneMode$Companion;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\"\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u0008\n\u0002\u0008\u0007\n\u0002\u0010\u000b\n\u0002\u0008\u0003\n\u0002\u0010\u000e\n\u0002\u0008\u0002\u0008\u0086\u0008\u0018\u0000 \u00102\u00020\u0001:\u0001\u0010B\u000f\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u00a2\u0006\u0004\u0008\u0004\u0010\u0005J\t\u0010\u0008\u001a\u00020\u0003H\u00c6\u0003J\u0013\u0010\t\u001a\u00020\u00002\u0008\u0008\u0002\u0010\u0002\u001a\u00020\u0003H\u00c6\u0001J\u0013\u0010\n\u001a\u00020\u000b2\u0008\u0010\u000c\u001a\u0004\u0018\u00010\u0001H\u00d6\u0003J\t\u0010\r\u001a\u00020\u0003H\u00d6\u0001J\t\u0010\u000e\u001a\u00020\u000fH\u00d6\u0001R\u0011\u0010\u0002\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0006\u0010\u0007\u00a8\u0006\u0011"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/Car2PhoneMode;",
        "",
        "rawValue",
        "",
        "<init>",
        "(I)V",
        "getRawValue",
        "()I",
        "component1",
        "copy",
        "equals",
        "",
        "other",
        "hashCode",
        "toString",
        "",
        "Companion",
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


# static fields
.field public static final Companion:Ltechnology/cariad/cat/genx/Car2PhoneMode$Companion;

.field private static final batteryProtectionAntenna:Ltechnology/cariad/cat/genx/Car2PhoneMode;

.field private static final batteryProtectionCan:Ltechnology/cariad/cat/genx/Car2PhoneMode;

.field private static final functionActive:Ltechnology/cariad/cat/genx/Car2PhoneMode;

.field private static final invalid:Ltechnology/cariad/cat/genx/Car2PhoneMode;

.field private static final mainControllerAwakeBusOff:Ltechnology/cariad/cat/genx/Car2PhoneMode;

.field private static final mainControllerAwakeBusOn:Ltechnology/cariad/cat/genx/Car2PhoneMode;

.field private static final pairingActive:Ltechnology/cariad/cat/genx/Car2PhoneMode;

.field private static final sleep:Ltechnology/cariad/cat/genx/Car2PhoneMode;


# instance fields
.field private final rawValue:I


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Ltechnology/cariad/cat/genx/Car2PhoneMode$Companion;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Ltechnology/cariad/cat/genx/Car2PhoneMode$Companion;-><init>(Lkotlin/jvm/internal/g;)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Ltechnology/cariad/cat/genx/Car2PhoneMode;->Companion:Ltechnology/cariad/cat/genx/Car2PhoneMode$Companion;

    .line 8
    .line 9
    new-instance v0, Ltechnology/cariad/cat/genx/Car2PhoneMode;

    .line 10
    .line 11
    const/4 v1, 0x0

    .line 12
    invoke-direct {v0, v1}, Ltechnology/cariad/cat/genx/Car2PhoneMode;-><init>(I)V

    .line 13
    .line 14
    .line 15
    sput-object v0, Ltechnology/cariad/cat/genx/Car2PhoneMode;->sleep:Ltechnology/cariad/cat/genx/Car2PhoneMode;

    .line 16
    .line 17
    new-instance v0, Ltechnology/cariad/cat/genx/Car2PhoneMode;

    .line 18
    .line 19
    const/4 v1, 0x1

    .line 20
    invoke-direct {v0, v1}, Ltechnology/cariad/cat/genx/Car2PhoneMode;-><init>(I)V

    .line 21
    .line 22
    .line 23
    sput-object v0, Ltechnology/cariad/cat/genx/Car2PhoneMode;->batteryProtectionCan:Ltechnology/cariad/cat/genx/Car2PhoneMode;

    .line 24
    .line 25
    new-instance v0, Ltechnology/cariad/cat/genx/Car2PhoneMode;

    .line 26
    .line 27
    const/4 v1, 0x2

    .line 28
    invoke-direct {v0, v1}, Ltechnology/cariad/cat/genx/Car2PhoneMode;-><init>(I)V

    .line 29
    .line 30
    .line 31
    sput-object v0, Ltechnology/cariad/cat/genx/Car2PhoneMode;->mainControllerAwakeBusOff:Ltechnology/cariad/cat/genx/Car2PhoneMode;

    .line 32
    .line 33
    new-instance v0, Ltechnology/cariad/cat/genx/Car2PhoneMode;

    .line 34
    .line 35
    const/4 v1, 0x3

    .line 36
    invoke-direct {v0, v1}, Ltechnology/cariad/cat/genx/Car2PhoneMode;-><init>(I)V

    .line 37
    .line 38
    .line 39
    sput-object v0, Ltechnology/cariad/cat/genx/Car2PhoneMode;->mainControllerAwakeBusOn:Ltechnology/cariad/cat/genx/Car2PhoneMode;

    .line 40
    .line 41
    new-instance v0, Ltechnology/cariad/cat/genx/Car2PhoneMode;

    .line 42
    .line 43
    const/4 v1, 0x7

    .line 44
    invoke-direct {v0, v1}, Ltechnology/cariad/cat/genx/Car2PhoneMode;-><init>(I)V

    .line 45
    .line 46
    .line 47
    sput-object v0, Ltechnology/cariad/cat/genx/Car2PhoneMode;->batteryProtectionAntenna:Ltechnology/cariad/cat/genx/Car2PhoneMode;

    .line 48
    .line 49
    new-instance v0, Ltechnology/cariad/cat/genx/Car2PhoneMode;

    .line 50
    .line 51
    const/4 v1, 0x5

    .line 52
    invoke-direct {v0, v1}, Ltechnology/cariad/cat/genx/Car2PhoneMode;-><init>(I)V

    .line 53
    .line 54
    .line 55
    sput-object v0, Ltechnology/cariad/cat/genx/Car2PhoneMode;->functionActive:Ltechnology/cariad/cat/genx/Car2PhoneMode;

    .line 56
    .line 57
    new-instance v0, Ltechnology/cariad/cat/genx/Car2PhoneMode;

    .line 58
    .line 59
    const/4 v1, 0x4

    .line 60
    invoke-direct {v0, v1}, Ltechnology/cariad/cat/genx/Car2PhoneMode;-><init>(I)V

    .line 61
    .line 62
    .line 63
    sput-object v0, Ltechnology/cariad/cat/genx/Car2PhoneMode;->pairingActive:Ltechnology/cariad/cat/genx/Car2PhoneMode;

    .line 64
    .line 65
    new-instance v0, Ltechnology/cariad/cat/genx/Car2PhoneMode;

    .line 66
    .line 67
    const/4 v1, -0x1

    .line 68
    invoke-direct {v0, v1}, Ltechnology/cariad/cat/genx/Car2PhoneMode;-><init>(I)V

    .line 69
    .line 70
    .line 71
    sput-object v0, Ltechnology/cariad/cat/genx/Car2PhoneMode;->invalid:Ltechnology/cariad/cat/genx/Car2PhoneMode;

    .line 72
    .line 73
    return-void
.end method

.method public constructor <init>(I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Ltechnology/cariad/cat/genx/Car2PhoneMode;->rawValue:I

    .line 5
    .line 6
    return-void
.end method

.method public static final synthetic access$getBatteryProtectionAntenna$cp()Ltechnology/cariad/cat/genx/Car2PhoneMode;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/genx/Car2PhoneMode;->batteryProtectionAntenna:Ltechnology/cariad/cat/genx/Car2PhoneMode;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getBatteryProtectionCan$cp()Ltechnology/cariad/cat/genx/Car2PhoneMode;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/genx/Car2PhoneMode;->batteryProtectionCan:Ltechnology/cariad/cat/genx/Car2PhoneMode;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getFunctionActive$cp()Ltechnology/cariad/cat/genx/Car2PhoneMode;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/genx/Car2PhoneMode;->functionActive:Ltechnology/cariad/cat/genx/Car2PhoneMode;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getInvalid$cp()Ltechnology/cariad/cat/genx/Car2PhoneMode;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/genx/Car2PhoneMode;->invalid:Ltechnology/cariad/cat/genx/Car2PhoneMode;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getMainControllerAwakeBusOff$cp()Ltechnology/cariad/cat/genx/Car2PhoneMode;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/genx/Car2PhoneMode;->mainControllerAwakeBusOff:Ltechnology/cariad/cat/genx/Car2PhoneMode;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getMainControllerAwakeBusOn$cp()Ltechnology/cariad/cat/genx/Car2PhoneMode;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/genx/Car2PhoneMode;->mainControllerAwakeBusOn:Ltechnology/cariad/cat/genx/Car2PhoneMode;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getPairingActive$cp()Ltechnology/cariad/cat/genx/Car2PhoneMode;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/genx/Car2PhoneMode;->pairingActive:Ltechnology/cariad/cat/genx/Car2PhoneMode;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getSleep$cp()Ltechnology/cariad/cat/genx/Car2PhoneMode;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/genx/Car2PhoneMode;->sleep:Ltechnology/cariad/cat/genx/Car2PhoneMode;

    .line 2
    .line 3
    return-object v0
.end method

.method public static synthetic copy$default(Ltechnology/cariad/cat/genx/Car2PhoneMode;IILjava/lang/Object;)Ltechnology/cariad/cat/genx/Car2PhoneMode;
    .locals 0

    .line 1
    and-int/lit8 p2, p2, 0x1

    .line 2
    .line 3
    if-eqz p2, :cond_0

    .line 4
    .line 5
    iget p1, p0, Ltechnology/cariad/cat/genx/Car2PhoneMode;->rawValue:I

    .line 6
    .line 7
    :cond_0
    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/genx/Car2PhoneMode;->copy(I)Ltechnology/cariad/cat/genx/Car2PhoneMode;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method


# virtual methods
.method public final component1()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/genx/Car2PhoneMode;->rawValue:I

    .line 2
    .line 3
    return p0
.end method

.method public final copy(I)Ltechnology/cariad/cat/genx/Car2PhoneMode;
    .locals 0

    .line 1
    new-instance p0, Ltechnology/cariad/cat/genx/Car2PhoneMode;

    .line 2
    .line 3
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/genx/Car2PhoneMode;-><init>(I)V

    .line 4
    .line 5
    .line 6
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
    instance-of v1, p1, Ltechnology/cariad/cat/genx/Car2PhoneMode;

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
    check-cast p1, Ltechnology/cariad/cat/genx/Car2PhoneMode;

    .line 12
    .line 13
    iget p0, p0, Ltechnology/cariad/cat/genx/Car2PhoneMode;->rawValue:I

    .line 14
    .line 15
    iget p1, p1, Ltechnology/cariad/cat/genx/Car2PhoneMode;->rawValue:I

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

.method public final getRawValue()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/genx/Car2PhoneMode;->rawValue:I

    .line 2
    .line 3
    return p0
.end method

.method public hashCode()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/genx/Car2PhoneMode;->rawValue:I

    .line 2
    .line 3
    invoke-static {p0}, Ljava/lang/Integer;->hashCode(I)I

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
    iget p0, p0, Ltechnology/cariad/cat/genx/Car2PhoneMode;->rawValue:I

    .line 2
    .line 3
    const-string v0, "Car2PhoneMode(rawValue="

    .line 4
    .line 5
    const-string v1, ")"

    .line 6
    .line 7
    invoke-static {v0, p0, v1}, Lu/w;->e(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method
