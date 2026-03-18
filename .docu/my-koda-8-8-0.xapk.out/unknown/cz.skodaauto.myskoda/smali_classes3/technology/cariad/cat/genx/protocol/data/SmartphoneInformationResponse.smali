.class public final Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponse;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\"\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u000e\n\u0002\u0008\u0016\n\u0002\u0010\u000b\n\u0002\u0008\u0002\n\u0002\u0010\u0008\n\u0002\u0008\u0002\u0008\u0080\u0008\u0018\u00002\u00020\u0001B7\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u0012\u0006\u0010\u0004\u001a\u00020\u0003\u0012\u0006\u0010\u0005\u001a\u00020\u0003\u0012\u0006\u0010\u0006\u001a\u00020\u0003\u0012\u0006\u0010\u0007\u001a\u00020\u0003\u0012\u0006\u0010\u0008\u001a\u00020\u0003\u00a2\u0006\u0004\u0008\t\u0010\nJ\t\u0010\u0012\u001a\u00020\u0003H\u00c6\u0003J\t\u0010\u0013\u001a\u00020\u0003H\u00c6\u0003J\t\u0010\u0014\u001a\u00020\u0003H\u00c6\u0003J\t\u0010\u0015\u001a\u00020\u0003H\u00c6\u0003J\t\u0010\u0016\u001a\u00020\u0003H\u00c6\u0003J\t\u0010\u0017\u001a\u00020\u0003H\u00c6\u0003JE\u0010\u0018\u001a\u00020\u00002\u0008\u0008\u0002\u0010\u0002\u001a\u00020\u00032\u0008\u0008\u0002\u0010\u0004\u001a\u00020\u00032\u0008\u0008\u0002\u0010\u0005\u001a\u00020\u00032\u0008\u0008\u0002\u0010\u0006\u001a\u00020\u00032\u0008\u0008\u0002\u0010\u0007\u001a\u00020\u00032\u0008\u0008\u0002\u0010\u0008\u001a\u00020\u0003H\u00c6\u0001J\u0013\u0010\u0019\u001a\u00020\u001a2\u0008\u0010\u001b\u001a\u0004\u0018\u00010\u0001H\u00d6\u0003J\t\u0010\u001c\u001a\u00020\u001dH\u00d6\u0001J\t\u0010\u001e\u001a\u00020\u0003H\u00d6\u0001R\u0011\u0010\u0002\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u000b\u0010\u000cR\u0011\u0010\u0004\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\r\u0010\u000cR\u0011\u0010\u0005\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u000e\u0010\u000cR\u0011\u0010\u0006\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u000f\u0010\u000cR\u0011\u0010\u0007\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0010\u0010\u000cR\u0011\u0010\u0008\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0011\u0010\u000c\u00a8\u0006\u001f"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponse;",
        "",
        "phoneName",
        "",
        "appName",
        "manufacturerName",
        "modelName",
        "swVersion",
        "appVersion",
        "<init>",
        "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V",
        "getPhoneName",
        "()Ljava/lang/String;",
        "getAppName",
        "getManufacturerName",
        "getModelName",
        "getSwVersion",
        "getAppVersion",
        "component1",
        "component2",
        "component3",
        "component4",
        "component5",
        "component6",
        "copy",
        "equals",
        "",
        "other",
        "hashCode",
        "",
        "toString",
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
.field private final appName:Ljava/lang/String;

.field private final appVersion:Ljava/lang/String;

.field private final manufacturerName:Ljava/lang/String;

.field private final modelName:Ljava/lang/String;

.field private final phoneName:Ljava/lang/String;

.field private final swVersion:Ljava/lang/String;


# direct methods
.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V
    .locals 1

    .line 1
    const-string v0, "phoneName"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "appName"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "manufacturerName"

    .line 12
    .line 13
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    const-string v0, "modelName"

    .line 17
    .line 18
    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    const-string v0, "swVersion"

    .line 22
    .line 23
    invoke-static {p5, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    const-string v0, "appVersion"

    .line 27
    .line 28
    invoke-static {p6, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 32
    .line 33
    .line 34
    iput-object p1, p0, Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponse;->phoneName:Ljava/lang/String;

    .line 35
    .line 36
    iput-object p2, p0, Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponse;->appName:Ljava/lang/String;

    .line 37
    .line 38
    iput-object p3, p0, Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponse;->manufacturerName:Ljava/lang/String;

    .line 39
    .line 40
    iput-object p4, p0, Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponse;->modelName:Ljava/lang/String;

    .line 41
    .line 42
    iput-object p5, p0, Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponse;->swVersion:Ljava/lang/String;

    .line 43
    .line 44
    iput-object p6, p0, Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponse;->appVersion:Ljava/lang/String;

    .line 45
    .line 46
    return-void
.end method

.method public static synthetic copy$default(Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponse;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ILjava/lang/Object;)Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponse;
    .locals 0

    .line 1
    and-int/lit8 p8, p7, 0x1

    .line 2
    .line 3
    if-eqz p8, :cond_0

    .line 4
    .line 5
    iget-object p1, p0, Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponse;->phoneName:Ljava/lang/String;

    .line 6
    .line 7
    :cond_0
    and-int/lit8 p8, p7, 0x2

    .line 8
    .line 9
    if-eqz p8, :cond_1

    .line 10
    .line 11
    iget-object p2, p0, Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponse;->appName:Ljava/lang/String;

    .line 12
    .line 13
    :cond_1
    and-int/lit8 p8, p7, 0x4

    .line 14
    .line 15
    if-eqz p8, :cond_2

    .line 16
    .line 17
    iget-object p3, p0, Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponse;->manufacturerName:Ljava/lang/String;

    .line 18
    .line 19
    :cond_2
    and-int/lit8 p8, p7, 0x8

    .line 20
    .line 21
    if-eqz p8, :cond_3

    .line 22
    .line 23
    iget-object p4, p0, Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponse;->modelName:Ljava/lang/String;

    .line 24
    .line 25
    :cond_3
    and-int/lit8 p8, p7, 0x10

    .line 26
    .line 27
    if-eqz p8, :cond_4

    .line 28
    .line 29
    iget-object p5, p0, Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponse;->swVersion:Ljava/lang/String;

    .line 30
    .line 31
    :cond_4
    and-int/lit8 p7, p7, 0x20

    .line 32
    .line 33
    if-eqz p7, :cond_5

    .line 34
    .line 35
    iget-object p6, p0, Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponse;->appVersion:Ljava/lang/String;

    .line 36
    .line 37
    :cond_5
    move-object p7, p5

    .line 38
    move-object p8, p6

    .line 39
    move-object p5, p3

    .line 40
    move-object p6, p4

    .line 41
    move-object p3, p1

    .line 42
    move-object p4, p2

    .line 43
    move-object p2, p0

    .line 44
    invoke-virtual/range {p2 .. p8}, Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponse;->copy(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponse;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    return-object p0
.end method


# virtual methods
.method public final component1()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponse;->phoneName:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component2()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponse;->appName:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component3()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponse;->manufacturerName:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component4()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponse;->modelName:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component5()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponse;->swVersion:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component6()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponse;->appVersion:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final copy(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponse;
    .locals 7

    .line 1
    const-string p0, "phoneName"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string p0, "appName"

    .line 7
    .line 8
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string p0, "manufacturerName"

    .line 12
    .line 13
    invoke-static {p3, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    const-string p0, "modelName"

    .line 17
    .line 18
    invoke-static {p4, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    const-string p0, "swVersion"

    .line 22
    .line 23
    invoke-static {p5, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    const-string p0, "appVersion"

    .line 27
    .line 28
    invoke-static {p6, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    new-instance v0, Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponse;

    .line 32
    .line 33
    move-object v1, p1

    .line 34
    move-object v2, p2

    .line 35
    move-object v3, p3

    .line 36
    move-object v4, p4

    .line 37
    move-object v5, p5

    .line 38
    move-object v6, p6

    .line 39
    invoke-direct/range {v0 .. v6}, Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponse;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 40
    .line 41
    .line 42
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
    instance-of v1, p1, Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponse;

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
    check-cast p1, Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponse;

    .line 12
    .line 13
    iget-object v1, p0, Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponse;->phoneName:Ljava/lang/String;

    .line 14
    .line 15
    iget-object v3, p1, Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponse;->phoneName:Ljava/lang/String;

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
    iget-object v1, p0, Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponse;->appName:Ljava/lang/String;

    .line 25
    .line 26
    iget-object v3, p1, Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponse;->appName:Ljava/lang/String;

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
    iget-object v1, p0, Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponse;->manufacturerName:Ljava/lang/String;

    .line 36
    .line 37
    iget-object v3, p1, Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponse;->manufacturerName:Ljava/lang/String;

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
    iget-object v1, p0, Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponse;->modelName:Ljava/lang/String;

    .line 47
    .line 48
    iget-object v3, p1, Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponse;->modelName:Ljava/lang/String;

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
    iget-object v1, p0, Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponse;->swVersion:Ljava/lang/String;

    .line 58
    .line 59
    iget-object v3, p1, Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponse;->swVersion:Ljava/lang/String;

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
    iget-object p0, p0, Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponse;->appVersion:Ljava/lang/String;

    .line 69
    .line 70
    iget-object p1, p1, Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponse;->appVersion:Ljava/lang/String;

    .line 71
    .line 72
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 73
    .line 74
    .line 75
    move-result p0

    .line 76
    if-nez p0, :cond_7

    .line 77
    .line 78
    return v2

    .line 79
    :cond_7
    return v0
.end method

.method public final getAppName()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponse;->appName:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getAppVersion()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponse;->appVersion:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getManufacturerName()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponse;->manufacturerName:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getModelName()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponse;->modelName:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getPhoneName()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponse;->phoneName:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getSwVersion()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponse;->swVersion:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 3

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponse;->phoneName:Ljava/lang/String;

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
    iget-object v2, p0, Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponse;->appName:Ljava/lang/String;

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-object v2, p0, Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponse;->manufacturerName:Ljava/lang/String;

    .line 17
    .line 18
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    iget-object v2, p0, Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponse;->modelName:Ljava/lang/String;

    .line 23
    .line 24
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    iget-object v2, p0, Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponse;->swVersion:Ljava/lang/String;

    .line 29
    .line 30
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    iget-object p0, p0, Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponse;->appVersion:Ljava/lang/String;

    .line 35
    .line 36
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 37
    .line 38
    .line 39
    move-result p0

    .line 40
    add-int/2addr p0, v0

    .line 41
    return p0
.end method

.method public toString()Ljava/lang/String;
    .locals 8

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponse;->phoneName:Ljava/lang/String;

    .line 2
    .line 3
    iget-object v1, p0, Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponse;->appName:Ljava/lang/String;

    .line 4
    .line 5
    iget-object v2, p0, Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponse;->manufacturerName:Ljava/lang/String;

    .line 6
    .line 7
    iget-object v3, p0, Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponse;->modelName:Ljava/lang/String;

    .line 8
    .line 9
    iget-object v4, p0, Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponse;->swVersion:Ljava/lang/String;

    .line 10
    .line 11
    iget-object p0, p0, Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponse;->appVersion:Ljava/lang/String;

    .line 12
    .line 13
    const-string v5, ", appName="

    .line 14
    .line 15
    const-string v6, ", manufacturerName="

    .line 16
    .line 17
    const-string v7, "SmartphoneInformationResponse(phoneName="

    .line 18
    .line 19
    invoke-static {v7, v0, v5, v1, v6}, Lu/w;->k(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    const-string v1, ", modelName="

    .line 24
    .line 25
    const-string v5, ", swVersion="

    .line 26
    .line 27
    invoke-static {v0, v2, v1, v3, v5}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    const-string v1, ", appVersion="

    .line 31
    .line 32
    const-string v2, ")"

    .line 33
    .line 34
    invoke-static {v0, v4, v1, p0, v2}, Lvj/b;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    return-object p0
.end method
