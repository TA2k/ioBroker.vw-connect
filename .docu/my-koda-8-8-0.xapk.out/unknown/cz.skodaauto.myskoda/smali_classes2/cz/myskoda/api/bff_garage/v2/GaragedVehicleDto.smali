.class public final Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u00002\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u000e\n\u0002\u0008\u0005\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0008\n\u0002\u0008(\n\u0002\u0010\u000b\n\u0002\u0008\u0004\u0008\u0086\u0008\u0018\u00002\u00020\u0001B{\u0012\u0008\u0008\u0001\u0010\u0002\u001a\u00020\u0003\u0012\u0008\u0008\u0001\u0010\u0004\u001a\u00020\u0003\u0012\u0008\u0008\u0001\u0010\u0005\u001a\u00020\u0003\u0012\u0008\u0008\u0001\u0010\u0006\u001a\u00020\u0003\u0012\u0008\u0008\u0001\u0010\u0007\u001a\u00020\u0003\u0012\u000e\u0008\u0001\u0010\u0008\u001a\u0008\u0012\u0004\u0012\u00020\n0\t\u0012\u000e\u0008\u0001\u0010\u000b\u001a\u0008\u0012\u0004\u0012\u00020\u000c0\t\u0012\u0008\u0008\u0001\u0010\r\u001a\u00020\u000e\u0012\n\u0008\u0003\u0010\u000f\u001a\u0004\u0018\u00010\u0003\u0012\n\u0008\u0003\u0010\u0010\u001a\u0004\u0018\u00010\u0003\u00a2\u0006\u0004\u0008\u0011\u0010\u0012J\t\u0010+\u001a\u00020\u0003H\u00c6\u0003J\t\u0010,\u001a\u00020\u0003H\u00c6\u0003J\t\u0010-\u001a\u00020\u0003H\u00c6\u0003J\t\u0010.\u001a\u00020\u0003H\u00c6\u0003J\t\u0010/\u001a\u00020\u0003H\u00c6\u0003J\u000f\u00100\u001a\u0008\u0012\u0004\u0012\u00020\n0\tH\u00c6\u0003J\u000f\u00101\u001a\u0008\u0012\u0004\u0012\u00020\u000c0\tH\u00c6\u0003J\t\u00102\u001a\u00020\u000eH\u00c6\u0003J\u000b\u00103\u001a\u0004\u0018\u00010\u0003H\u00c6\u0003J\u000b\u00104\u001a\u0004\u0018\u00010\u0003H\u00c6\u0003J}\u00105\u001a\u00020\u00002\u0008\u0008\u0003\u0010\u0002\u001a\u00020\u00032\u0008\u0008\u0003\u0010\u0004\u001a\u00020\u00032\u0008\u0008\u0003\u0010\u0005\u001a\u00020\u00032\u0008\u0008\u0003\u0010\u0006\u001a\u00020\u00032\u0008\u0008\u0003\u0010\u0007\u001a\u00020\u00032\u000e\u0008\u0003\u0010\u0008\u001a\u0008\u0012\u0004\u0012\u00020\n0\t2\u000e\u0008\u0003\u0010\u000b\u001a\u0008\u0012\u0004\u0012\u00020\u000c0\t2\u0008\u0008\u0003\u0010\r\u001a\u00020\u000e2\n\u0008\u0003\u0010\u000f\u001a\u0004\u0018\u00010\u00032\n\u0008\u0003\u0010\u0010\u001a\u0004\u0018\u00010\u0003H\u00c6\u0001J\u0013\u00106\u001a\u0002072\u0008\u00108\u001a\u0004\u0018\u00010\u0001H\u00d6\u0003J\t\u00109\u001a\u00020\u000eH\u00d6\u0001J\t\u0010:\u001a\u00020\u0003H\u00d6\u0001R\u001c\u0010\u0002\u001a\u00020\u00038\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u0013\u0010\u0014\u001a\u0004\u0008\u0015\u0010\u0016R\u001c\u0010\u0004\u001a\u00020\u00038\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u0017\u0010\u0014\u001a\u0004\u0008\u0018\u0010\u0016R\u001c\u0010\u0005\u001a\u00020\u00038\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u0019\u0010\u0014\u001a\u0004\u0008\u001a\u0010\u0016R\u001c\u0010\u0006\u001a\u00020\u00038\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u001b\u0010\u0014\u001a\u0004\u0008\u001c\u0010\u0016R\u001c\u0010\u0007\u001a\u00020\u00038\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u001d\u0010\u0014\u001a\u0004\u0008\u001e\u0010\u0016R\"\u0010\u0008\u001a\u0008\u0012\u0004\u0012\u00020\n0\t8\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u001f\u0010\u0014\u001a\u0004\u0008 \u0010!R\"\u0010\u000b\u001a\u0008\u0012\u0004\u0012\u00020\u000c0\t8\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\"\u0010\u0014\u001a\u0004\u0008#\u0010!R\u001c\u0010\r\u001a\u00020\u000e8\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008$\u0010\u0014\u001a\u0004\u0008%\u0010&R\u001e\u0010\u000f\u001a\u0004\u0018\u00010\u00038\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\'\u0010\u0014\u001a\u0004\u0008(\u0010\u0016R\u001e\u0010\u0010\u001a\u0004\u0018\u00010\u00038\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008)\u0010\u0014\u001a\u0004\u0008*\u0010\u0016\u00a8\u0006;"
    }
    d2 = {
        "Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;",
        "",
        "vin",
        "",
        "state",
        "devicePlatform",
        "systemModelId",
        "title",
        "renders",
        "",
        "Lcz/myskoda/api/bff_garage/v2/RenderDto;",
        "compositeRenders",
        "Lcz/myskoda/api/bff_garage/v2/CompositeRenderDto;",
        "priority",
        "",
        "name",
        "licensePlate",
        "<init>",
        "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/List;Ljava/util/List;ILjava/lang/String;Ljava/lang/String;)V",
        "getVin$annotations",
        "()V",
        "getVin",
        "()Ljava/lang/String;",
        "getState$annotations",
        "getState",
        "getDevicePlatform$annotations",
        "getDevicePlatform",
        "getSystemModelId$annotations",
        "getSystemModelId",
        "getTitle$annotations",
        "getTitle",
        "getRenders$annotations",
        "getRenders",
        "()Ljava/util/List;",
        "getCompositeRenders$annotations",
        "getCompositeRenders",
        "getPriority$annotations",
        "getPriority",
        "()I",
        "getName$annotations",
        "getName",
        "getLicensePlate$annotations",
        "getLicensePlate",
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
.field private final compositeRenders:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lcz/myskoda/api/bff_garage/v2/CompositeRenderDto;",
            ">;"
        }
    .end annotation
.end field

.field private final devicePlatform:Ljava/lang/String;

.field private final licensePlate:Ljava/lang/String;

.field private final name:Ljava/lang/String;

.field private final priority:I

.field private final renders:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lcz/myskoda/api/bff_garage/v2/RenderDto;",
            ">;"
        }
    .end annotation
.end field

.field private final state:Ljava/lang/String;

.field private final systemModelId:Ljava/lang/String;

.field private final title:Ljava/lang/String;

.field private final vin:Ljava/lang/String;


# direct methods
.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/List;Ljava/util/List;ILjava/lang/String;Ljava/lang/String;)V
    .locals 1
    .param p1    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "vin"
        .end annotation
    .end param
    .param p2    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "state"
        .end annotation
    .end param
    .param p3    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "devicePlatform"
        .end annotation
    .end param
    .param p4    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "systemModelId"
        .end annotation
    .end param
    .param p5    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "title"
        .end annotation
    .end param
    .param p6    # Ljava/util/List;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "renders"
        .end annotation
    .end param
    .param p7    # Ljava/util/List;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "compositeRenders"
        .end annotation
    .end param
    .param p8    # I
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "priority"
        .end annotation
    .end param
    .param p9    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "name"
        .end annotation
    .end param
    .param p10    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "licensePlate"
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Ljava/util/List<",
            "Lcz/myskoda/api/bff_garage/v2/RenderDto;",
            ">;",
            "Ljava/util/List<",
            "Lcz/myskoda/api/bff_garage/v2/CompositeRenderDto;",
            ">;I",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ")V"
        }
    .end annotation

    const-string v0, "vin"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "state"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "devicePlatform"

    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "systemModelId"

    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "title"

    invoke-static {p5, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "renders"

    invoke-static {p6, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "compositeRenders"

    invoke-static {p7, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;->vin:Ljava/lang/String;

    .line 3
    iput-object p2, p0, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;->state:Ljava/lang/String;

    .line 4
    iput-object p3, p0, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;->devicePlatform:Ljava/lang/String;

    .line 5
    iput-object p4, p0, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;->systemModelId:Ljava/lang/String;

    .line 6
    iput-object p5, p0, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;->title:Ljava/lang/String;

    .line 7
    iput-object p6, p0, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;->renders:Ljava/util/List;

    .line 8
    iput-object p7, p0, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;->compositeRenders:Ljava/util/List;

    .line 9
    iput p8, p0, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;->priority:I

    .line 10
    iput-object p9, p0, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;->name:Ljava/lang/String;

    .line 11
    iput-object p10, p0, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;->licensePlate:Ljava/lang/String;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/List;Ljava/util/List;ILjava/lang/String;Ljava/lang/String;ILkotlin/jvm/internal/g;)V
    .locals 1

    and-int/lit16 p12, p11, 0x100

    const/4 v0, 0x0

    if-eqz p12, :cond_0

    move-object p9, v0

    :cond_0
    and-int/lit16 p11, p11, 0x200

    if-eqz p11, :cond_1

    move-object p10, v0

    .line 12
    :cond_1
    invoke-direct/range {p0 .. p10}, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/List;Ljava/util/List;ILjava/lang/String;Ljava/lang/String;)V

    return-void
.end method

.method public static synthetic copy$default(Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/List;Ljava/util/List;ILjava/lang/String;Ljava/lang/String;ILjava/lang/Object;)Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;
    .locals 0

    .line 1
    and-int/lit8 p12, p11, 0x1

    .line 2
    .line 3
    if-eqz p12, :cond_0

    .line 4
    .line 5
    iget-object p1, p0, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;->vin:Ljava/lang/String;

    .line 6
    .line 7
    :cond_0
    and-int/lit8 p12, p11, 0x2

    .line 8
    .line 9
    if-eqz p12, :cond_1

    .line 10
    .line 11
    iget-object p2, p0, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;->state:Ljava/lang/String;

    .line 12
    .line 13
    :cond_1
    and-int/lit8 p12, p11, 0x4

    .line 14
    .line 15
    if-eqz p12, :cond_2

    .line 16
    .line 17
    iget-object p3, p0, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;->devicePlatform:Ljava/lang/String;

    .line 18
    .line 19
    :cond_2
    and-int/lit8 p12, p11, 0x8

    .line 20
    .line 21
    if-eqz p12, :cond_3

    .line 22
    .line 23
    iget-object p4, p0, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;->systemModelId:Ljava/lang/String;

    .line 24
    .line 25
    :cond_3
    and-int/lit8 p12, p11, 0x10

    .line 26
    .line 27
    if-eqz p12, :cond_4

    .line 28
    .line 29
    iget-object p5, p0, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;->title:Ljava/lang/String;

    .line 30
    .line 31
    :cond_4
    and-int/lit8 p12, p11, 0x20

    .line 32
    .line 33
    if-eqz p12, :cond_5

    .line 34
    .line 35
    iget-object p6, p0, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;->renders:Ljava/util/List;

    .line 36
    .line 37
    :cond_5
    and-int/lit8 p12, p11, 0x40

    .line 38
    .line 39
    if-eqz p12, :cond_6

    .line 40
    .line 41
    iget-object p7, p0, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;->compositeRenders:Ljava/util/List;

    .line 42
    .line 43
    :cond_6
    and-int/lit16 p12, p11, 0x80

    .line 44
    .line 45
    if-eqz p12, :cond_7

    .line 46
    .line 47
    iget p8, p0, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;->priority:I

    .line 48
    .line 49
    :cond_7
    and-int/lit16 p12, p11, 0x100

    .line 50
    .line 51
    if-eqz p12, :cond_8

    .line 52
    .line 53
    iget-object p9, p0, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;->name:Ljava/lang/String;

    .line 54
    .line 55
    :cond_8
    and-int/lit16 p11, p11, 0x200

    .line 56
    .line 57
    if-eqz p11, :cond_9

    .line 58
    .line 59
    iget-object p10, p0, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;->licensePlate:Ljava/lang/String;

    .line 60
    .line 61
    :cond_9
    move-object p11, p9

    .line 62
    move-object p12, p10

    .line 63
    move-object p9, p7

    .line 64
    move p10, p8

    .line 65
    move-object p7, p5

    .line 66
    move-object p8, p6

    .line 67
    move-object p5, p3

    .line 68
    move-object p6, p4

    .line 69
    move-object p3, p1

    .line 70
    move-object p4, p2

    .line 71
    move-object p2, p0

    .line 72
    invoke-virtual/range {p2 .. p12}, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;->copy(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/List;Ljava/util/List;ILjava/lang/String;Ljava/lang/String;)Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;

    .line 73
    .line 74
    .line 75
    move-result-object p0

    .line 76
    return-object p0
.end method

.method public static synthetic getCompositeRenders$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "compositeRenders"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getDevicePlatform$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "devicePlatform"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getLicensePlate$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "licensePlate"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getName$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "name"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getPriority$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "priority"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getRenders$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "renders"
    .end annotation

    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getState$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "state"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getSystemModelId$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "systemModelId"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getTitle$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "title"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getVin$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "vin"
    .end annotation

    .line 1
    return-void
.end method


# virtual methods
.method public final component1()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;->vin:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component10()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;->licensePlate:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component2()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;->state:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component3()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;->devicePlatform:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component4()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;->systemModelId:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component5()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;->title:Ljava/lang/String;

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
            "Lcz/myskoda/api/bff_garage/v2/RenderDto;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;->renders:Ljava/util/List;

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
            "Lcz/myskoda/api/bff_garage/v2/CompositeRenderDto;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;->compositeRenders:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component8()I
    .locals 0

    .line 1
    iget p0, p0, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;->priority:I

    .line 2
    .line 3
    return p0
.end method

.method public final component9()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;->name:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final copy(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/List;Ljava/util/List;ILjava/lang/String;Ljava/lang/String;)Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;
    .locals 11
    .param p1    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "vin"
        .end annotation
    .end param
    .param p2    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "state"
        .end annotation
    .end param
    .param p3    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "devicePlatform"
        .end annotation
    .end param
    .param p4    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "systemModelId"
        .end annotation
    .end param
    .param p5    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "title"
        .end annotation
    .end param
    .param p6    # Ljava/util/List;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "renders"
        .end annotation
    .end param
    .param p7    # Ljava/util/List;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "compositeRenders"
        .end annotation
    .end param
    .param p8    # I
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "priority"
        .end annotation
    .end param
    .param p9    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "name"
        .end annotation
    .end param
    .param p10    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "licensePlate"
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Ljava/util/List<",
            "Lcz/myskoda/api/bff_garage/v2/RenderDto;",
            ">;",
            "Ljava/util/List<",
            "Lcz/myskoda/api/bff_garage/v2/CompositeRenderDto;",
            ">;I",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ")",
            "Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;"
        }
    .end annotation

    .line 1
    const-string p0, "vin"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string p0, "state"

    .line 7
    .line 8
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string p0, "devicePlatform"

    .line 12
    .line 13
    invoke-static {p3, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    const-string p0, "systemModelId"

    .line 17
    .line 18
    invoke-static {p4, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    const-string p0, "title"

    .line 22
    .line 23
    move-object/from16 v5, p5

    .line 24
    .line 25
    invoke-static {v5, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    const-string p0, "renders"

    .line 29
    .line 30
    move-object/from16 v6, p6

    .line 31
    .line 32
    invoke-static {v6, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    const-string p0, "compositeRenders"

    .line 36
    .line 37
    move-object/from16 v7, p7

    .line 38
    .line 39
    invoke-static {v7, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 40
    .line 41
    .line 42
    new-instance v0, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;

    .line 43
    .line 44
    move-object v1, p1

    .line 45
    move-object v2, p2

    .line 46
    move-object v3, p3

    .line 47
    move-object v4, p4

    .line 48
    move/from16 v8, p8

    .line 49
    .line 50
    move-object/from16 v9, p9

    .line 51
    .line 52
    move-object/from16 v10, p10

    .line 53
    .line 54
    invoke-direct/range {v0 .. v10}, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/List;Ljava/util/List;ILjava/lang/String;Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
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
    instance-of v1, p1, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;

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
    check-cast p1, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;

    .line 12
    .line 13
    iget-object v1, p0, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;->vin:Ljava/lang/String;

    .line 14
    .line 15
    iget-object v3, p1, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;->vin:Ljava/lang/String;

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
    iget-object v1, p0, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;->state:Ljava/lang/String;

    .line 25
    .line 26
    iget-object v3, p1, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;->state:Ljava/lang/String;

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
    iget-object v1, p0, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;->devicePlatform:Ljava/lang/String;

    .line 36
    .line 37
    iget-object v3, p1, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;->devicePlatform:Ljava/lang/String;

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
    iget-object v1, p0, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;->systemModelId:Ljava/lang/String;

    .line 47
    .line 48
    iget-object v3, p1, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;->systemModelId:Ljava/lang/String;

    .line 49
    .line 50
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 51
    .line 52
    .line 53
    move-result v1

    .line 54
    if-nez v1, :cond_5

    .line 55
    .line 56
    return v2

    .line 57
    :cond_5
    iget-object v1, p0, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;->title:Ljava/lang/String;

    .line 58
    .line 59
    iget-object v3, p1, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;->title:Ljava/lang/String;

    .line 60
    .line 61
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 62
    .line 63
    .line 64
    move-result v1

    .line 65
    if-nez v1, :cond_6

    .line 66
    .line 67
    return v2

    .line 68
    :cond_6
    iget-object v1, p0, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;->renders:Ljava/util/List;

    .line 69
    .line 70
    iget-object v3, p1, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;->renders:Ljava/util/List;

    .line 71
    .line 72
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 73
    .line 74
    .line 75
    move-result v1

    .line 76
    if-nez v1, :cond_7

    .line 77
    .line 78
    return v2

    .line 79
    :cond_7
    iget-object v1, p0, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;->compositeRenders:Ljava/util/List;

    .line 80
    .line 81
    iget-object v3, p1, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;->compositeRenders:Ljava/util/List;

    .line 82
    .line 83
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 84
    .line 85
    .line 86
    move-result v1

    .line 87
    if-nez v1, :cond_8

    .line 88
    .line 89
    return v2

    .line 90
    :cond_8
    iget v1, p0, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;->priority:I

    .line 91
    .line 92
    iget v3, p1, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;->priority:I

    .line 93
    .line 94
    if-eq v1, v3, :cond_9

    .line 95
    .line 96
    return v2

    .line 97
    :cond_9
    iget-object v1, p0, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;->name:Ljava/lang/String;

    .line 98
    .line 99
    iget-object v3, p1, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;->name:Ljava/lang/String;

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
    iget-object p0, p0, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;->licensePlate:Ljava/lang/String;

    .line 109
    .line 110
    iget-object p1, p1, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;->licensePlate:Ljava/lang/String;

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

.method public final getCompositeRenders()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lcz/myskoda/api/bff_garage/v2/CompositeRenderDto;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;->compositeRenders:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getDevicePlatform()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;->devicePlatform:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getLicensePlate()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;->licensePlate:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getName()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;->name:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getPriority()I
    .locals 0

    .line 1
    iget p0, p0, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;->priority:I

    .line 2
    .line 3
    return p0
.end method

.method public final getRenders()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lcz/myskoda/api/bff_garage/v2/RenderDto;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;->renders:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getState()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;->state:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getSystemModelId()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;->systemModelId:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getTitle()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;->title:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getVin()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;->vin:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 4

    .line 1
    iget-object v0, p0, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;->vin:Ljava/lang/String;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

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
    iget-object v2, p0, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;->state:Ljava/lang/String;

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-object v2, p0, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;->devicePlatform:Ljava/lang/String;

    .line 17
    .line 18
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    iget-object v2, p0, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;->systemModelId:Ljava/lang/String;

    .line 23
    .line 24
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    iget-object v2, p0, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;->title:Ljava/lang/String;

    .line 29
    .line 30
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    iget-object v2, p0, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;->renders:Ljava/util/List;

    .line 35
    .line 36
    invoke-static {v0, v1, v2}, Lia/b;->a(IILjava/util/List;)I

    .line 37
    .line 38
    .line 39
    move-result v0

    .line 40
    iget-object v2, p0, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;->compositeRenders:Ljava/util/List;

    .line 41
    .line 42
    invoke-static {v0, v1, v2}, Lia/b;->a(IILjava/util/List;)I

    .line 43
    .line 44
    .line 45
    move-result v0

    .line 46
    iget v2, p0, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;->priority:I

    .line 47
    .line 48
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 49
    .line 50
    .line 51
    move-result v0

    .line 52
    iget-object v2, p0, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;->name:Ljava/lang/String;

    .line 53
    .line 54
    const/4 v3, 0x0

    .line 55
    if-nez v2, :cond_0

    .line 56
    .line 57
    move v2, v3

    .line 58
    goto :goto_0

    .line 59
    :cond_0
    invoke-virtual {v2}, Ljava/lang/String;->hashCode()I

    .line 60
    .line 61
    .line 62
    move-result v2

    .line 63
    :goto_0
    add-int/2addr v0, v2

    .line 64
    mul-int/2addr v0, v1

    .line 65
    iget-object p0, p0, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;->licensePlate:Ljava/lang/String;

    .line 66
    .line 67
    if-nez p0, :cond_1

    .line 68
    .line 69
    goto :goto_1

    .line 70
    :cond_1
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 71
    .line 72
    .line 73
    move-result v3

    .line 74
    :goto_1
    add-int/2addr v0, v3

    .line 75
    return v0
.end method

.method public toString()Ljava/lang/String;
    .locals 12

    .line 1
    iget-object v0, p0, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;->vin:Ljava/lang/String;

    .line 2
    .line 3
    iget-object v1, p0, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;->state:Ljava/lang/String;

    .line 4
    .line 5
    iget-object v2, p0, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;->devicePlatform:Ljava/lang/String;

    .line 6
    .line 7
    iget-object v3, p0, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;->systemModelId:Ljava/lang/String;

    .line 8
    .line 9
    iget-object v4, p0, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;->title:Ljava/lang/String;

    .line 10
    .line 11
    iget-object v5, p0, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;->renders:Ljava/util/List;

    .line 12
    .line 13
    iget-object v6, p0, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;->compositeRenders:Ljava/util/List;

    .line 14
    .line 15
    iget v7, p0, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;->priority:I

    .line 16
    .line 17
    iget-object v8, p0, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;->name:Ljava/lang/String;

    .line 18
    .line 19
    iget-object p0, p0, Lcz/myskoda/api/bff_garage/v2/GaragedVehicleDto;->licensePlate:Ljava/lang/String;

    .line 20
    .line 21
    const-string v9, ", state="

    .line 22
    .line 23
    const-string v10, ", devicePlatform="

    .line 24
    .line 25
    const-string v11, "GaragedVehicleDto(vin="

    .line 26
    .line 27
    invoke-static {v11, v0, v9, v1, v10}, Lu/w;->k(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    const-string v1, ", systemModelId="

    .line 32
    .line 33
    const-string v9, ", title="

    .line 34
    .line 35
    invoke-static {v0, v2, v1, v3, v9}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    const-string v1, ", renders="

    .line 39
    .line 40
    const-string v2, ", compositeRenders="

    .line 41
    .line 42
    invoke-static {v0, v4, v1, v5, v2}, Lu/w;->m(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/util/List;Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    invoke-virtual {v0, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    const-string v1, ", priority="

    .line 49
    .line 50
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    invoke-virtual {v0, v7}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 54
    .line 55
    .line 56
    const-string v1, ", name="

    .line 57
    .line 58
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 59
    .line 60
    .line 61
    const-string v1, ", licensePlate="

    .line 62
    .line 63
    const-string v2, ")"

    .line 64
    .line 65
    invoke-static {v0, v8, v1, p0, v2}, Lvj/b;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 66
    .line 67
    .line 68
    move-result-object p0

    .line 69
    return-object p0
.end method
