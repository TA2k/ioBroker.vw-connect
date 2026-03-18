.class public final Lcz/myskoda/api/bff/v1/ParkingAccountDto;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000F\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0002\u0008\u0002\n\u0002\u0010\u0008\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008)\n\u0002\u0010\u000b\n\u0002\u0008\u0004\u0008\u0086\u0008\u0018\u00002\u00020\u0001B}\u0012\u0008\u0008\u0001\u0010\u0002\u001a\u00020\u0003\u0012\u0008\u0008\u0001\u0010\u0004\u001a\u00020\u0005\u0012\u0008\u0008\u0001\u0010\u0006\u001a\u00020\u0005\u0012\u0008\u0008\u0001\u0010\u0007\u001a\u00020\u0008\u0012\u0008\u0008\u0001\u0010\t\u001a\u00020\n\u0012\u000e\u0008\u0001\u0010\u000b\u001a\u0008\u0012\u0004\u0012\u00020\r0\u000c\u0012\u000e\u0008\u0001\u0010\u000e\u001a\u0008\u0012\u0004\u0012\u00020\u000f0\u000c\u0012\n\u0008\u0003\u0010\u0010\u001a\u0004\u0018\u00010\u0005\u0012\n\u0008\u0003\u0010\u0011\u001a\u0004\u0018\u00010\u0005\u0012\n\u0008\u0003\u0010\u0012\u001a\u0004\u0018\u00010\u0013\u00a2\u0006\u0004\u0008\u0014\u0010\u0015J\t\u00101\u001a\u00020\u0003H\u00c6\u0003J\t\u00102\u001a\u00020\u0005H\u00c6\u0003J\t\u00103\u001a\u00020\u0005H\u00c6\u0003J\t\u00104\u001a\u00020\u0008H\u00c6\u0003J\t\u00105\u001a\u00020\nH\u00c6\u0003J\u000f\u00106\u001a\u0008\u0012\u0004\u0012\u00020\r0\u000cH\u00c6\u0003J\u000f\u00107\u001a\u0008\u0012\u0004\u0012\u00020\u000f0\u000cH\u00c6\u0003J\u000b\u00108\u001a\u0004\u0018\u00010\u0005H\u00c6\u0003J\u000b\u00109\u001a\u0004\u0018\u00010\u0005H\u00c6\u0003J\u000b\u0010:\u001a\u0004\u0018\u00010\u0013H\u00c6\u0003J\u007f\u0010;\u001a\u00020\u00002\u0008\u0008\u0003\u0010\u0002\u001a\u00020\u00032\u0008\u0008\u0003\u0010\u0004\u001a\u00020\u00052\u0008\u0008\u0003\u0010\u0006\u001a\u00020\u00052\u0008\u0008\u0003\u0010\u0007\u001a\u00020\u00082\u0008\u0008\u0003\u0010\t\u001a\u00020\n2\u000e\u0008\u0003\u0010\u000b\u001a\u0008\u0012\u0004\u0012\u00020\r0\u000c2\u000e\u0008\u0003\u0010\u000e\u001a\u0008\u0012\u0004\u0012\u00020\u000f0\u000c2\n\u0008\u0003\u0010\u0010\u001a\u0004\u0018\u00010\u00052\n\u0008\u0003\u0010\u0011\u001a\u0004\u0018\u00010\u00052\n\u0008\u0003\u0010\u0012\u001a\u0004\u0018\u00010\u0013H\u00c6\u0001J\u0013\u0010<\u001a\u00020=2\u0008\u0010>\u001a\u0004\u0018\u00010\u0001H\u00d6\u0003J\t\u0010?\u001a\u00020\u0008H\u00d6\u0001J\t\u0010@\u001a\u00020\u0005H\u00d6\u0001R\u001c\u0010\u0002\u001a\u00020\u00038\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u0016\u0010\u0017\u001a\u0004\u0008\u0018\u0010\u0019R\u001c\u0010\u0004\u001a\u00020\u00058\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u001a\u0010\u0017\u001a\u0004\u0008\u001b\u0010\u001cR\u001c\u0010\u0006\u001a\u00020\u00058\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u001d\u0010\u0017\u001a\u0004\u0008\u001e\u0010\u001cR\u001c\u0010\u0007\u001a\u00020\u00088\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u001f\u0010\u0017\u001a\u0004\u0008 \u0010!R\u001c\u0010\t\u001a\u00020\n8\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\"\u0010\u0017\u001a\u0004\u0008#\u0010$R\"\u0010\u000b\u001a\u0008\u0012\u0004\u0012\u00020\r0\u000c8\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008%\u0010\u0017\u001a\u0004\u0008&\u0010\'R\"\u0010\u000e\u001a\u0008\u0012\u0004\u0012\u00020\u000f0\u000c8\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008(\u0010\u0017\u001a\u0004\u0008)\u0010\'R\u001e\u0010\u0010\u001a\u0004\u0018\u00010\u00058\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008*\u0010\u0017\u001a\u0004\u0008+\u0010\u001cR\u001e\u0010\u0011\u001a\u0004\u0018\u00010\u00058\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008,\u0010\u0017\u001a\u0004\u0008-\u0010\u001cR\u001e\u0010\u0012\u001a\u0004\u0018\u00010\u00138\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008.\u0010\u0017\u001a\u0004\u0008/\u00100\u00a8\u0006A"
    }
    d2 = {
        "Lcz/myskoda/api/bff/v1/ParkingAccountDto;",
        "",
        "status",
        "Lcz/myskoda/api/bff/v1/ParkingAccountStatusDto;",
        "email",
        "",
        "username",
        "userId",
        "",
        "address",
        "Lcz/myskoda/api/bff/v1/UserAddressDto;",
        "vehicles",
        "",
        "Lcz/myskoda/api/bff/v1/UserVehicleDto;",
        "cards",
        "Lcz/myskoda/api/bff/v1/CardDto;",
        "firstName",
        "lastName",
        "lastUpdated",
        "Ljava/time/OffsetDateTime;",
        "<init>",
        "(Lcz/myskoda/api/bff/v1/ParkingAccountStatusDto;Ljava/lang/String;Ljava/lang/String;ILcz/myskoda/api/bff/v1/UserAddressDto;Ljava/util/List;Ljava/util/List;Ljava/lang/String;Ljava/lang/String;Ljava/time/OffsetDateTime;)V",
        "getStatus$annotations",
        "()V",
        "getStatus",
        "()Lcz/myskoda/api/bff/v1/ParkingAccountStatusDto;",
        "getEmail$annotations",
        "getEmail",
        "()Ljava/lang/String;",
        "getUsername$annotations",
        "getUsername",
        "getUserId$annotations",
        "getUserId",
        "()I",
        "getAddress$annotations",
        "getAddress",
        "()Lcz/myskoda/api/bff/v1/UserAddressDto;",
        "getVehicles$annotations",
        "getVehicles",
        "()Ljava/util/List;",
        "getCards$annotations",
        "getCards",
        "getFirstName$annotations",
        "getFirstName",
        "getLastName$annotations",
        "getLastName",
        "getLastUpdated$annotations",
        "getLastUpdated",
        "()Ljava/time/OffsetDateTime;",
        "component1",
        "component2",
        "component3",
        "component4",
        "component5",
        "component6",
        "component7",
        "component8",
        "component9",
        "component10",
        "copy",
        "equals",
        "",
        "other",
        "hashCode",
        "toString",
        "bff-api_release"
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
.field private final address:Lcz/myskoda/api/bff/v1/UserAddressDto;

.field private final cards:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lcz/myskoda/api/bff/v1/CardDto;",
            ">;"
        }
    .end annotation
.end field

.field private final email:Ljava/lang/String;

.field private final firstName:Ljava/lang/String;

.field private final lastName:Ljava/lang/String;

.field private final lastUpdated:Ljava/time/OffsetDateTime;

.field private final status:Lcz/myskoda/api/bff/v1/ParkingAccountStatusDto;

.field private final userId:I

.field private final username:Ljava/lang/String;

.field private final vehicles:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lcz/myskoda/api/bff/v1/UserVehicleDto;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Lcz/myskoda/api/bff/v1/ParkingAccountStatusDto;Ljava/lang/String;Ljava/lang/String;ILcz/myskoda/api/bff/v1/UserAddressDto;Ljava/util/List;Ljava/util/List;Ljava/lang/String;Ljava/lang/String;Ljava/time/OffsetDateTime;)V
    .locals 1
    .param p1    # Lcz/myskoda/api/bff/v1/ParkingAccountStatusDto;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "status"
        .end annotation
    .end param
    .param p2    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "email"
        .end annotation
    .end param
    .param p3    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "username"
        .end annotation
    .end param
    .param p4    # I
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "userId"
        .end annotation
    .end param
    .param p5    # Lcz/myskoda/api/bff/v1/UserAddressDto;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "address"
        .end annotation
    .end param
    .param p6    # Ljava/util/List;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "vehicles"
        .end annotation
    .end param
    .param p7    # Ljava/util/List;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "cards"
        .end annotation
    .end param
    .param p8    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "firstName"
        .end annotation
    .end param
    .param p9    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "lastName"
        .end annotation
    .end param
    .param p10    # Ljava/time/OffsetDateTime;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "lastUpdated"
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lcz/myskoda/api/bff/v1/ParkingAccountStatusDto;",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "I",
            "Lcz/myskoda/api/bff/v1/UserAddressDto;",
            "Ljava/util/List<",
            "Lcz/myskoda/api/bff/v1/UserVehicleDto;",
            ">;",
            "Ljava/util/List<",
            "Lcz/myskoda/api/bff/v1/CardDto;",
            ">;",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Ljava/time/OffsetDateTime;",
            ")V"
        }
    .end annotation

    const-string v0, "status"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "email"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "username"

    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "address"

    invoke-static {p5, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "vehicles"

    invoke-static {p6, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "cards"

    invoke-static {p7, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Lcz/myskoda/api/bff/v1/ParkingAccountDto;->status:Lcz/myskoda/api/bff/v1/ParkingAccountStatusDto;

    .line 3
    iput-object p2, p0, Lcz/myskoda/api/bff/v1/ParkingAccountDto;->email:Ljava/lang/String;

    .line 4
    iput-object p3, p0, Lcz/myskoda/api/bff/v1/ParkingAccountDto;->username:Ljava/lang/String;

    .line 5
    iput p4, p0, Lcz/myskoda/api/bff/v1/ParkingAccountDto;->userId:I

    .line 6
    iput-object p5, p0, Lcz/myskoda/api/bff/v1/ParkingAccountDto;->address:Lcz/myskoda/api/bff/v1/UserAddressDto;

    .line 7
    iput-object p6, p0, Lcz/myskoda/api/bff/v1/ParkingAccountDto;->vehicles:Ljava/util/List;

    .line 8
    iput-object p7, p0, Lcz/myskoda/api/bff/v1/ParkingAccountDto;->cards:Ljava/util/List;

    .line 9
    iput-object p8, p0, Lcz/myskoda/api/bff/v1/ParkingAccountDto;->firstName:Ljava/lang/String;

    .line 10
    iput-object p9, p0, Lcz/myskoda/api/bff/v1/ParkingAccountDto;->lastName:Ljava/lang/String;

    .line 11
    iput-object p10, p0, Lcz/myskoda/api/bff/v1/ParkingAccountDto;->lastUpdated:Ljava/time/OffsetDateTime;

    return-void
.end method

.method public synthetic constructor <init>(Lcz/myskoda/api/bff/v1/ParkingAccountStatusDto;Ljava/lang/String;Ljava/lang/String;ILcz/myskoda/api/bff/v1/UserAddressDto;Ljava/util/List;Ljava/util/List;Ljava/lang/String;Ljava/lang/String;Ljava/time/OffsetDateTime;ILkotlin/jvm/internal/g;)V
    .locals 1

    and-int/lit16 p12, p11, 0x80

    const/4 v0, 0x0

    if-eqz p12, :cond_0

    move-object p8, v0

    :cond_0
    and-int/lit16 p12, p11, 0x100

    if-eqz p12, :cond_1

    move-object p9, v0

    :cond_1
    and-int/lit16 p11, p11, 0x200

    if-eqz p11, :cond_2

    move-object p10, v0

    .line 12
    :cond_2
    invoke-direct/range {p0 .. p10}, Lcz/myskoda/api/bff/v1/ParkingAccountDto;-><init>(Lcz/myskoda/api/bff/v1/ParkingAccountStatusDto;Ljava/lang/String;Ljava/lang/String;ILcz/myskoda/api/bff/v1/UserAddressDto;Ljava/util/List;Ljava/util/List;Ljava/lang/String;Ljava/lang/String;Ljava/time/OffsetDateTime;)V

    return-void
.end method

.method public static synthetic copy$default(Lcz/myskoda/api/bff/v1/ParkingAccountDto;Lcz/myskoda/api/bff/v1/ParkingAccountStatusDto;Ljava/lang/String;Ljava/lang/String;ILcz/myskoda/api/bff/v1/UserAddressDto;Ljava/util/List;Ljava/util/List;Ljava/lang/String;Ljava/lang/String;Ljava/time/OffsetDateTime;ILjava/lang/Object;)Lcz/myskoda/api/bff/v1/ParkingAccountDto;
    .locals 0

    .line 1
    and-int/lit8 p12, p11, 0x1

    .line 2
    .line 3
    if-eqz p12, :cond_0

    .line 4
    .line 5
    iget-object p1, p0, Lcz/myskoda/api/bff/v1/ParkingAccountDto;->status:Lcz/myskoda/api/bff/v1/ParkingAccountStatusDto;

    .line 6
    .line 7
    :cond_0
    and-int/lit8 p12, p11, 0x2

    .line 8
    .line 9
    if-eqz p12, :cond_1

    .line 10
    .line 11
    iget-object p2, p0, Lcz/myskoda/api/bff/v1/ParkingAccountDto;->email:Ljava/lang/String;

    .line 12
    .line 13
    :cond_1
    and-int/lit8 p12, p11, 0x4

    .line 14
    .line 15
    if-eqz p12, :cond_2

    .line 16
    .line 17
    iget-object p3, p0, Lcz/myskoda/api/bff/v1/ParkingAccountDto;->username:Ljava/lang/String;

    .line 18
    .line 19
    :cond_2
    and-int/lit8 p12, p11, 0x8

    .line 20
    .line 21
    if-eqz p12, :cond_3

    .line 22
    .line 23
    iget p4, p0, Lcz/myskoda/api/bff/v1/ParkingAccountDto;->userId:I

    .line 24
    .line 25
    :cond_3
    and-int/lit8 p12, p11, 0x10

    .line 26
    .line 27
    if-eqz p12, :cond_4

    .line 28
    .line 29
    iget-object p5, p0, Lcz/myskoda/api/bff/v1/ParkingAccountDto;->address:Lcz/myskoda/api/bff/v1/UserAddressDto;

    .line 30
    .line 31
    :cond_4
    and-int/lit8 p12, p11, 0x20

    .line 32
    .line 33
    if-eqz p12, :cond_5

    .line 34
    .line 35
    iget-object p6, p0, Lcz/myskoda/api/bff/v1/ParkingAccountDto;->vehicles:Ljava/util/List;

    .line 36
    .line 37
    :cond_5
    and-int/lit8 p12, p11, 0x40

    .line 38
    .line 39
    if-eqz p12, :cond_6

    .line 40
    .line 41
    iget-object p7, p0, Lcz/myskoda/api/bff/v1/ParkingAccountDto;->cards:Ljava/util/List;

    .line 42
    .line 43
    :cond_6
    and-int/lit16 p12, p11, 0x80

    .line 44
    .line 45
    if-eqz p12, :cond_7

    .line 46
    .line 47
    iget-object p8, p0, Lcz/myskoda/api/bff/v1/ParkingAccountDto;->firstName:Ljava/lang/String;

    .line 48
    .line 49
    :cond_7
    and-int/lit16 p12, p11, 0x100

    .line 50
    .line 51
    if-eqz p12, :cond_8

    .line 52
    .line 53
    iget-object p9, p0, Lcz/myskoda/api/bff/v1/ParkingAccountDto;->lastName:Ljava/lang/String;

    .line 54
    .line 55
    :cond_8
    and-int/lit16 p11, p11, 0x200

    .line 56
    .line 57
    if-eqz p11, :cond_9

    .line 58
    .line 59
    iget-object p10, p0, Lcz/myskoda/api/bff/v1/ParkingAccountDto;->lastUpdated:Ljava/time/OffsetDateTime;

    .line 60
    .line 61
    :cond_9
    move-object p11, p9

    .line 62
    move-object p12, p10

    .line 63
    move-object p9, p7

    .line 64
    move-object p10, p8

    .line 65
    move-object p7, p5

    .line 66
    move-object p8, p6

    .line 67
    move-object p5, p3

    .line 68
    move p6, p4

    .line 69
    move-object p3, p1

    .line 70
    move-object p4, p2

    .line 71
    move-object p2, p0

    .line 72
    invoke-virtual/range {p2 .. p12}, Lcz/myskoda/api/bff/v1/ParkingAccountDto;->copy(Lcz/myskoda/api/bff/v1/ParkingAccountStatusDto;Ljava/lang/String;Ljava/lang/String;ILcz/myskoda/api/bff/v1/UserAddressDto;Ljava/util/List;Ljava/util/List;Ljava/lang/String;Ljava/lang/String;Ljava/time/OffsetDateTime;)Lcz/myskoda/api/bff/v1/ParkingAccountDto;

    .line 73
    .line 74
    .line 75
    move-result-object p0

    .line 76
    return-object p0
.end method

.method public static synthetic getAddress$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "address"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getCards$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "cards"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getEmail$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "email"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getFirstName$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "firstName"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getLastName$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "lastName"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getLastUpdated$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "lastUpdated"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getStatus$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "status"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getUserId$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "userId"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getUsername$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "username"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getVehicles$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "vehicles"
    .end annotation

    .line 1
    return-void
.end method


# virtual methods
.method public final component1()Lcz/myskoda/api/bff/v1/ParkingAccountStatusDto;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/ParkingAccountDto;->status:Lcz/myskoda/api/bff/v1/ParkingAccountStatusDto;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component10()Ljava/time/OffsetDateTime;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/ParkingAccountDto;->lastUpdated:Ljava/time/OffsetDateTime;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component2()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/ParkingAccountDto;->email:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component3()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/ParkingAccountDto;->username:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component4()I
    .locals 0

    .line 1
    iget p0, p0, Lcz/myskoda/api/bff/v1/ParkingAccountDto;->userId:I

    .line 2
    .line 3
    return p0
.end method

.method public final component5()Lcz/myskoda/api/bff/v1/UserAddressDto;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/ParkingAccountDto;->address:Lcz/myskoda/api/bff/v1/UserAddressDto;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component6()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lcz/myskoda/api/bff/v1/UserVehicleDto;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/ParkingAccountDto;->vehicles:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component7()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lcz/myskoda/api/bff/v1/CardDto;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/ParkingAccountDto;->cards:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component8()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/ParkingAccountDto;->firstName:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component9()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/ParkingAccountDto;->lastName:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final copy(Lcz/myskoda/api/bff/v1/ParkingAccountStatusDto;Ljava/lang/String;Ljava/lang/String;ILcz/myskoda/api/bff/v1/UserAddressDto;Ljava/util/List;Ljava/util/List;Ljava/lang/String;Ljava/lang/String;Ljava/time/OffsetDateTime;)Lcz/myskoda/api/bff/v1/ParkingAccountDto;
    .locals 11
    .param p1    # Lcz/myskoda/api/bff/v1/ParkingAccountStatusDto;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "status"
        .end annotation
    .end param
    .param p2    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "email"
        .end annotation
    .end param
    .param p3    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "username"
        .end annotation
    .end param
    .param p4    # I
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "userId"
        .end annotation
    .end param
    .param p5    # Lcz/myskoda/api/bff/v1/UserAddressDto;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "address"
        .end annotation
    .end param
    .param p6    # Ljava/util/List;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "vehicles"
        .end annotation
    .end param
    .param p7    # Ljava/util/List;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "cards"
        .end annotation
    .end param
    .param p8    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "firstName"
        .end annotation
    .end param
    .param p9    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "lastName"
        .end annotation
    .end param
    .param p10    # Ljava/time/OffsetDateTime;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "lastUpdated"
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lcz/myskoda/api/bff/v1/ParkingAccountStatusDto;",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "I",
            "Lcz/myskoda/api/bff/v1/UserAddressDto;",
            "Ljava/util/List<",
            "Lcz/myskoda/api/bff/v1/UserVehicleDto;",
            ">;",
            "Ljava/util/List<",
            "Lcz/myskoda/api/bff/v1/CardDto;",
            ">;",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Ljava/time/OffsetDateTime;",
            ")",
            "Lcz/myskoda/api/bff/v1/ParkingAccountDto;"
        }
    .end annotation

    .line 1
    const-string p0, "status"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string p0, "email"

    .line 7
    .line 8
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string p0, "username"

    .line 12
    .line 13
    invoke-static {p3, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    const-string p0, "address"

    .line 17
    .line 18
    move-object/from16 v5, p5

    .line 19
    .line 20
    invoke-static {v5, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    const-string p0, "vehicles"

    .line 24
    .line 25
    move-object/from16 v6, p6

    .line 26
    .line 27
    invoke-static {v6, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    const-string p0, "cards"

    .line 31
    .line 32
    move-object/from16 v7, p7

    .line 33
    .line 34
    invoke-static {v7, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    new-instance v0, Lcz/myskoda/api/bff/v1/ParkingAccountDto;

    .line 38
    .line 39
    move-object v1, p1

    .line 40
    move-object v2, p2

    .line 41
    move-object v3, p3

    .line 42
    move v4, p4

    .line 43
    move-object/from16 v8, p8

    .line 44
    .line 45
    move-object/from16 v9, p9

    .line 46
    .line 47
    move-object/from16 v10, p10

    .line 48
    .line 49
    invoke-direct/range {v0 .. v10}, Lcz/myskoda/api/bff/v1/ParkingAccountDto;-><init>(Lcz/myskoda/api/bff/v1/ParkingAccountStatusDto;Ljava/lang/String;Ljava/lang/String;ILcz/myskoda/api/bff/v1/UserAddressDto;Ljava/util/List;Ljava/util/List;Ljava/lang/String;Ljava/lang/String;Ljava/time/OffsetDateTime;)V

    .line 50
    .line 51
    .line 52
    return-object v0
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
    instance-of v1, p1, Lcz/myskoda/api/bff/v1/ParkingAccountDto;

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
    check-cast p1, Lcz/myskoda/api/bff/v1/ParkingAccountDto;

    .line 12
    .line 13
    iget-object v1, p0, Lcz/myskoda/api/bff/v1/ParkingAccountDto;->status:Lcz/myskoda/api/bff/v1/ParkingAccountStatusDto;

    .line 14
    .line 15
    iget-object v3, p1, Lcz/myskoda/api/bff/v1/ParkingAccountDto;->status:Lcz/myskoda/api/bff/v1/ParkingAccountStatusDto;

    .line 16
    .line 17
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-nez v1, :cond_2

    .line 22
    .line 23
    return v2

    .line 24
    :cond_2
    iget-object v1, p0, Lcz/myskoda/api/bff/v1/ParkingAccountDto;->email:Ljava/lang/String;

    .line 25
    .line 26
    iget-object v3, p1, Lcz/myskoda/api/bff/v1/ParkingAccountDto;->email:Ljava/lang/String;

    .line 27
    .line 28
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result v1

    .line 32
    if-nez v1, :cond_3

    .line 33
    .line 34
    return v2

    .line 35
    :cond_3
    iget-object v1, p0, Lcz/myskoda/api/bff/v1/ParkingAccountDto;->username:Ljava/lang/String;

    .line 36
    .line 37
    iget-object v3, p1, Lcz/myskoda/api/bff/v1/ParkingAccountDto;->username:Ljava/lang/String;

    .line 38
    .line 39
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    move-result v1

    .line 43
    if-nez v1, :cond_4

    .line 44
    .line 45
    return v2

    .line 46
    :cond_4
    iget v1, p0, Lcz/myskoda/api/bff/v1/ParkingAccountDto;->userId:I

    .line 47
    .line 48
    iget v3, p1, Lcz/myskoda/api/bff/v1/ParkingAccountDto;->userId:I

    .line 49
    .line 50
    if-eq v1, v3, :cond_5

    .line 51
    .line 52
    return v2

    .line 53
    :cond_5
    iget-object v1, p0, Lcz/myskoda/api/bff/v1/ParkingAccountDto;->address:Lcz/myskoda/api/bff/v1/UserAddressDto;

    .line 54
    .line 55
    iget-object v3, p1, Lcz/myskoda/api/bff/v1/ParkingAccountDto;->address:Lcz/myskoda/api/bff/v1/UserAddressDto;

    .line 56
    .line 57
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 58
    .line 59
    .line 60
    move-result v1

    .line 61
    if-nez v1, :cond_6

    .line 62
    .line 63
    return v2

    .line 64
    :cond_6
    iget-object v1, p0, Lcz/myskoda/api/bff/v1/ParkingAccountDto;->vehicles:Ljava/util/List;

    .line 65
    .line 66
    iget-object v3, p1, Lcz/myskoda/api/bff/v1/ParkingAccountDto;->vehicles:Ljava/util/List;

    .line 67
    .line 68
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 69
    .line 70
    .line 71
    move-result v1

    .line 72
    if-nez v1, :cond_7

    .line 73
    .line 74
    return v2

    .line 75
    :cond_7
    iget-object v1, p0, Lcz/myskoda/api/bff/v1/ParkingAccountDto;->cards:Ljava/util/List;

    .line 76
    .line 77
    iget-object v3, p1, Lcz/myskoda/api/bff/v1/ParkingAccountDto;->cards:Ljava/util/List;

    .line 78
    .line 79
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 80
    .line 81
    .line 82
    move-result v1

    .line 83
    if-nez v1, :cond_8

    .line 84
    .line 85
    return v2

    .line 86
    :cond_8
    iget-object v1, p0, Lcz/myskoda/api/bff/v1/ParkingAccountDto;->firstName:Ljava/lang/String;

    .line 87
    .line 88
    iget-object v3, p1, Lcz/myskoda/api/bff/v1/ParkingAccountDto;->firstName:Ljava/lang/String;

    .line 89
    .line 90
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 91
    .line 92
    .line 93
    move-result v1

    .line 94
    if-nez v1, :cond_9

    .line 95
    .line 96
    return v2

    .line 97
    :cond_9
    iget-object v1, p0, Lcz/myskoda/api/bff/v1/ParkingAccountDto;->lastName:Ljava/lang/String;

    .line 98
    .line 99
    iget-object v3, p1, Lcz/myskoda/api/bff/v1/ParkingAccountDto;->lastName:Ljava/lang/String;

    .line 100
    .line 101
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 102
    .line 103
    .line 104
    move-result v1

    .line 105
    if-nez v1, :cond_a

    .line 106
    .line 107
    return v2

    .line 108
    :cond_a
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/ParkingAccountDto;->lastUpdated:Ljava/time/OffsetDateTime;

    .line 109
    .line 110
    iget-object p1, p1, Lcz/myskoda/api/bff/v1/ParkingAccountDto;->lastUpdated:Ljava/time/OffsetDateTime;

    .line 111
    .line 112
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 113
    .line 114
    .line 115
    move-result p0

    .line 116
    if-nez p0, :cond_b

    .line 117
    .line 118
    return v2

    .line 119
    :cond_b
    return v0
.end method

.method public final getAddress()Lcz/myskoda/api/bff/v1/UserAddressDto;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/ParkingAccountDto;->address:Lcz/myskoda/api/bff/v1/UserAddressDto;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getCards()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lcz/myskoda/api/bff/v1/CardDto;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/ParkingAccountDto;->cards:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getEmail()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/ParkingAccountDto;->email:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getFirstName()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/ParkingAccountDto;->firstName:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getLastName()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/ParkingAccountDto;->lastName:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getLastUpdated()Ljava/time/OffsetDateTime;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/ParkingAccountDto;->lastUpdated:Ljava/time/OffsetDateTime;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getStatus()Lcz/myskoda/api/bff/v1/ParkingAccountStatusDto;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/ParkingAccountDto;->status:Lcz/myskoda/api/bff/v1/ParkingAccountStatusDto;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getUserId()I
    .locals 0

    .line 1
    iget p0, p0, Lcz/myskoda/api/bff/v1/ParkingAccountDto;->userId:I

    .line 2
    .line 3
    return p0
.end method

.method public final getUsername()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/ParkingAccountDto;->username:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getVehicles()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lcz/myskoda/api/bff/v1/UserVehicleDto;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/ParkingAccountDto;->vehicles:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 4

    .line 1
    iget-object v0, p0, Lcz/myskoda/api/bff/v1/ParkingAccountDto;->status:Lcz/myskoda/api/bff/v1/ParkingAccountStatusDto;

    .line 2
    .line 3
    invoke-virtual {v0}, Lcz/myskoda/api/bff/v1/ParkingAccountStatusDto;->hashCode()I

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
    iget-object v2, p0, Lcz/myskoda/api/bff/v1/ParkingAccountDto;->email:Ljava/lang/String;

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-object v2, p0, Lcz/myskoda/api/bff/v1/ParkingAccountDto;->username:Ljava/lang/String;

    .line 17
    .line 18
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    iget v2, p0, Lcz/myskoda/api/bff/v1/ParkingAccountDto;->userId:I

    .line 23
    .line 24
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    iget-object v2, p0, Lcz/myskoda/api/bff/v1/ParkingAccountDto;->address:Lcz/myskoda/api/bff/v1/UserAddressDto;

    .line 29
    .line 30
    invoke-virtual {v2}, Lcz/myskoda/api/bff/v1/UserAddressDto;->hashCode()I

    .line 31
    .line 32
    .line 33
    move-result v2

    .line 34
    add-int/2addr v2, v0

    .line 35
    mul-int/2addr v2, v1

    .line 36
    iget-object v0, p0, Lcz/myskoda/api/bff/v1/ParkingAccountDto;->vehicles:Ljava/util/List;

    .line 37
    .line 38
    invoke-static {v2, v1, v0}, Lia/b;->a(IILjava/util/List;)I

    .line 39
    .line 40
    .line 41
    move-result v0

    .line 42
    iget-object v2, p0, Lcz/myskoda/api/bff/v1/ParkingAccountDto;->cards:Ljava/util/List;

    .line 43
    .line 44
    invoke-static {v0, v1, v2}, Lia/b;->a(IILjava/util/List;)I

    .line 45
    .line 46
    .line 47
    move-result v0

    .line 48
    iget-object v2, p0, Lcz/myskoda/api/bff/v1/ParkingAccountDto;->firstName:Ljava/lang/String;

    .line 49
    .line 50
    const/4 v3, 0x0

    .line 51
    if-nez v2, :cond_0

    .line 52
    .line 53
    move v2, v3

    .line 54
    goto :goto_0

    .line 55
    :cond_0
    invoke-virtual {v2}, Ljava/lang/String;->hashCode()I

    .line 56
    .line 57
    .line 58
    move-result v2

    .line 59
    :goto_0
    add-int/2addr v0, v2

    .line 60
    mul-int/2addr v0, v1

    .line 61
    iget-object v2, p0, Lcz/myskoda/api/bff/v1/ParkingAccountDto;->lastName:Ljava/lang/String;

    .line 62
    .line 63
    if-nez v2, :cond_1

    .line 64
    .line 65
    move v2, v3

    .line 66
    goto :goto_1

    .line 67
    :cond_1
    invoke-virtual {v2}, Ljava/lang/String;->hashCode()I

    .line 68
    .line 69
    .line 70
    move-result v2

    .line 71
    :goto_1
    add-int/2addr v0, v2

    .line 72
    mul-int/2addr v0, v1

    .line 73
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/ParkingAccountDto;->lastUpdated:Ljava/time/OffsetDateTime;

    .line 74
    .line 75
    if-nez p0, :cond_2

    .line 76
    .line 77
    goto :goto_2

    .line 78
    :cond_2
    invoke-virtual {p0}, Ljava/time/OffsetDateTime;->hashCode()I

    .line 79
    .line 80
    .line 81
    move-result v3

    .line 82
    :goto_2
    add-int/2addr v0, v3

    .line 83
    return v0
.end method

.method public toString()Ljava/lang/String;
    .locals 11

    .line 1
    iget-object v0, p0, Lcz/myskoda/api/bff/v1/ParkingAccountDto;->status:Lcz/myskoda/api/bff/v1/ParkingAccountStatusDto;

    .line 2
    .line 3
    iget-object v1, p0, Lcz/myskoda/api/bff/v1/ParkingAccountDto;->email:Ljava/lang/String;

    .line 4
    .line 5
    iget-object v2, p0, Lcz/myskoda/api/bff/v1/ParkingAccountDto;->username:Ljava/lang/String;

    .line 6
    .line 7
    iget v3, p0, Lcz/myskoda/api/bff/v1/ParkingAccountDto;->userId:I

    .line 8
    .line 9
    iget-object v4, p0, Lcz/myskoda/api/bff/v1/ParkingAccountDto;->address:Lcz/myskoda/api/bff/v1/UserAddressDto;

    .line 10
    .line 11
    iget-object v5, p0, Lcz/myskoda/api/bff/v1/ParkingAccountDto;->vehicles:Ljava/util/List;

    .line 12
    .line 13
    iget-object v6, p0, Lcz/myskoda/api/bff/v1/ParkingAccountDto;->cards:Ljava/util/List;

    .line 14
    .line 15
    iget-object v7, p0, Lcz/myskoda/api/bff/v1/ParkingAccountDto;->firstName:Ljava/lang/String;

    .line 16
    .line 17
    iget-object v8, p0, Lcz/myskoda/api/bff/v1/ParkingAccountDto;->lastName:Ljava/lang/String;

    .line 18
    .line 19
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/ParkingAccountDto;->lastUpdated:Ljava/time/OffsetDateTime;

    .line 20
    .line 21
    new-instance v9, Ljava/lang/StringBuilder;

    .line 22
    .line 23
    const-string v10, "ParkingAccountDto(status="

    .line 24
    .line 25
    invoke-direct {v9, v10}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    invoke-virtual {v9, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 29
    .line 30
    .line 31
    const-string v0, ", email="

    .line 32
    .line 33
    invoke-virtual {v9, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 34
    .line 35
    .line 36
    invoke-virtual {v9, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 37
    .line 38
    .line 39
    const-string v0, ", username="

    .line 40
    .line 41
    invoke-virtual {v9, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 42
    .line 43
    .line 44
    const-string v0, ", userId="

    .line 45
    .line 46
    const-string v1, ", address="

    .line 47
    .line 48
    invoke-static {v9, v2, v0, v3, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->z(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;)V

    .line 49
    .line 50
    .line 51
    invoke-virtual {v9, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 52
    .line 53
    .line 54
    const-string v0, ", vehicles="

    .line 55
    .line 56
    invoke-virtual {v9, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 57
    .line 58
    .line 59
    invoke-virtual {v9, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 60
    .line 61
    .line 62
    const-string v0, ", cards="

    .line 63
    .line 64
    invoke-virtual {v9, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 65
    .line 66
    .line 67
    invoke-virtual {v9, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 68
    .line 69
    .line 70
    const-string v0, ", firstName="

    .line 71
    .line 72
    invoke-virtual {v9, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 73
    .line 74
    .line 75
    invoke-virtual {v9, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 76
    .line 77
    .line 78
    const-string v0, ", lastName="

    .line 79
    .line 80
    invoke-virtual {v9, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 81
    .line 82
    .line 83
    invoke-virtual {v9, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 84
    .line 85
    .line 86
    const-string v0, ", lastUpdated="

    .line 87
    .line 88
    invoke-virtual {v9, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 89
    .line 90
    .line 91
    invoke-virtual {v9, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 92
    .line 93
    .line 94
    const-string p0, ")"

    .line 95
    .line 96
    invoke-virtual {v9, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 97
    .line 98
    .line 99
    invoke-virtual {v9}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 100
    .line 101
    .line 102
    move-result-object p0

    .line 103
    return-object p0
.end method
