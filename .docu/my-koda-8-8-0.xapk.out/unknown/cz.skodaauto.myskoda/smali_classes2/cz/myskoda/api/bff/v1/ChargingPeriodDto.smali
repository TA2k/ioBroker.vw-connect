.class public final Lcz/myskoda/api/bff/v1/ChargingPeriodDto;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u00000\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0006\n\u0002\u0008\u000f\n\u0002\u0010\u000b\n\u0002\u0008\u0002\n\u0002\u0010\u0008\n\u0000\n\u0002\u0010\u000e\n\u0000\u0008\u0086\u0008\u0018\u00002\u00020\u0001B#\u0012\u000e\u0008\u0001\u0010\u0002\u001a\u0008\u0012\u0004\u0012\u00020\u00040\u0003\u0012\n\u0008\u0003\u0010\u0005\u001a\u0004\u0018\u00010\u0006\u00a2\u0006\u0004\u0008\u0007\u0010\u0008J\u000f\u0010\u0011\u001a\u0008\u0012\u0004\u0012\u00020\u00040\u0003H\u00c6\u0003J\u0010\u0010\u0012\u001a\u0004\u0018\u00010\u0006H\u00c6\u0003\u00a2\u0006\u0002\u0010\u000fJ*\u0010\u0013\u001a\u00020\u00002\u000e\u0008\u0003\u0010\u0002\u001a\u0008\u0012\u0004\u0012\u00020\u00040\u00032\n\u0008\u0003\u0010\u0005\u001a\u0004\u0018\u00010\u0006H\u00c6\u0001\u00a2\u0006\u0002\u0010\u0014J\u0013\u0010\u0015\u001a\u00020\u00162\u0008\u0010\u0017\u001a\u0004\u0018\u00010\u0001H\u00d6\u0003J\t\u0010\u0018\u001a\u00020\u0019H\u00d6\u0001J\t\u0010\u001a\u001a\u00020\u001bH\u00d6\u0001R\"\u0010\u0002\u001a\u0008\u0012\u0004\u0012\u00020\u00040\u00038\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\t\u0010\n\u001a\u0004\u0008\u000b\u0010\u000cR \u0010\u0005\u001a\u0004\u0018\u00010\u00068\u0006X\u0087\u0004\u00a2\u0006\u0010\n\u0002\u0010\u0010\u0012\u0004\u0008\r\u0010\n\u001a\u0004\u0008\u000e\u0010\u000f\u00a8\u0006\u001c"
    }
    d2 = {
        "Lcz/myskoda/api/bff/v1/ChargingPeriodDto;",
        "",
        "sessions",
        "",
        "Lcz/myskoda/api/bff/v1/ChargingSessionDto;",
        "totalChargedInKWh",
        "",
        "<init>",
        "(Ljava/util/List;Ljava/lang/Double;)V",
        "getSessions$annotations",
        "()V",
        "getSessions",
        "()Ljava/util/List;",
        "getTotalChargedInKWh$annotations",
        "getTotalChargedInKWh",
        "()Ljava/lang/Double;",
        "Ljava/lang/Double;",
        "component1",
        "component2",
        "copy",
        "(Ljava/util/List;Ljava/lang/Double;)Lcz/myskoda/api/bff/v1/ChargingPeriodDto;",
        "equals",
        "",
        "other",
        "hashCode",
        "",
        "toString",
        "",
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
.field private final sessions:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lcz/myskoda/api/bff/v1/ChargingSessionDto;",
            ">;"
        }
    .end annotation
.end field

.field private final totalChargedInKWh:Ljava/lang/Double;


# direct methods
.method public constructor <init>(Ljava/util/List;Ljava/lang/Double;)V
    .locals 1
    .param p1    # Ljava/util/List;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "sessions"
        .end annotation
    .end param
    .param p2    # Ljava/lang/Double;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "totalChargedInKWh"
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Lcz/myskoda/api/bff/v1/ChargingSessionDto;",
            ">;",
            "Ljava/lang/Double;",
            ")V"
        }
    .end annotation

    const-string v0, "sessions"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Lcz/myskoda/api/bff/v1/ChargingPeriodDto;->sessions:Ljava/util/List;

    .line 3
    iput-object p2, p0, Lcz/myskoda/api/bff/v1/ChargingPeriodDto;->totalChargedInKWh:Ljava/lang/Double;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/util/List;Ljava/lang/Double;ILkotlin/jvm/internal/g;)V
    .locals 0

    and-int/lit8 p3, p3, 0x2

    if-eqz p3, :cond_0

    const/4 p2, 0x0

    .line 4
    :cond_0
    invoke-direct {p0, p1, p2}, Lcz/myskoda/api/bff/v1/ChargingPeriodDto;-><init>(Ljava/util/List;Ljava/lang/Double;)V

    return-void
.end method

.method public static synthetic copy$default(Lcz/myskoda/api/bff/v1/ChargingPeriodDto;Ljava/util/List;Ljava/lang/Double;ILjava/lang/Object;)Lcz/myskoda/api/bff/v1/ChargingPeriodDto;
    .locals 0

    .line 1
    and-int/lit8 p4, p3, 0x1

    .line 2
    .line 3
    if-eqz p4, :cond_0

    .line 4
    .line 5
    iget-object p1, p0, Lcz/myskoda/api/bff/v1/ChargingPeriodDto;->sessions:Ljava/util/List;

    .line 6
    .line 7
    :cond_0
    and-int/lit8 p3, p3, 0x2

    .line 8
    .line 9
    if-eqz p3, :cond_1

    .line 10
    .line 11
    iget-object p2, p0, Lcz/myskoda/api/bff/v1/ChargingPeriodDto;->totalChargedInKWh:Ljava/lang/Double;

    .line 12
    .line 13
    :cond_1
    invoke-virtual {p0, p1, p2}, Lcz/myskoda/api/bff/v1/ChargingPeriodDto;->copy(Ljava/util/List;Ljava/lang/Double;)Lcz/myskoda/api/bff/v1/ChargingPeriodDto;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method

.method public static synthetic getSessions$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "sessions"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getTotalChargedInKWh$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "totalChargedInKWh"
    .end annotation

    .line 1
    return-void
.end method


# virtual methods
.method public final component1()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lcz/myskoda/api/bff/v1/ChargingSessionDto;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/ChargingPeriodDto;->sessions:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component2()Ljava/lang/Double;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/ChargingPeriodDto;->totalChargedInKWh:Ljava/lang/Double;

    .line 2
    .line 3
    return-object p0
.end method

.method public final copy(Ljava/util/List;Ljava/lang/Double;)Lcz/myskoda/api/bff/v1/ChargingPeriodDto;
    .locals 0
    .param p1    # Ljava/util/List;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "sessions"
        .end annotation
    .end param
    .param p2    # Ljava/lang/Double;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "totalChargedInKWh"
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Lcz/myskoda/api/bff/v1/ChargingSessionDto;",
            ">;",
            "Ljava/lang/Double;",
            ")",
            "Lcz/myskoda/api/bff/v1/ChargingPeriodDto;"
        }
    .end annotation

    .line 1
    const-string p0, "sessions"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance p0, Lcz/myskoda/api/bff/v1/ChargingPeriodDto;

    .line 7
    .line 8
    invoke-direct {p0, p1, p2}, Lcz/myskoda/api/bff/v1/ChargingPeriodDto;-><init>(Ljava/util/List;Ljava/lang/Double;)V

    .line 9
    .line 10
    .line 11
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
    instance-of v1, p1, Lcz/myskoda/api/bff/v1/ChargingPeriodDto;

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
    check-cast p1, Lcz/myskoda/api/bff/v1/ChargingPeriodDto;

    .line 12
    .line 13
    iget-object v1, p0, Lcz/myskoda/api/bff/v1/ChargingPeriodDto;->sessions:Ljava/util/List;

    .line 14
    .line 15
    iget-object v3, p1, Lcz/myskoda/api/bff/v1/ChargingPeriodDto;->sessions:Ljava/util/List;

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
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/ChargingPeriodDto;->totalChargedInKWh:Ljava/lang/Double;

    .line 25
    .line 26
    iget-object p1, p1, Lcz/myskoda/api/bff/v1/ChargingPeriodDto;->totalChargedInKWh:Ljava/lang/Double;

    .line 27
    .line 28
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result p0

    .line 32
    if-nez p0, :cond_3

    .line 33
    .line 34
    return v2

    .line 35
    :cond_3
    return v0
.end method

.method public final getSessions()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lcz/myskoda/api/bff/v1/ChargingSessionDto;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/ChargingPeriodDto;->sessions:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getTotalChargedInKWh()Ljava/lang/Double;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/ChargingPeriodDto;->totalChargedInKWh:Ljava/lang/Double;

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 1

    .line 1
    iget-object v0, p0, Lcz/myskoda/api/bff/v1/ChargingPeriodDto;->sessions:Ljava/util/List;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    mul-int/lit8 v0, v0, 0x1f

    .line 8
    .line 9
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/ChargingPeriodDto;->totalChargedInKWh:Ljava/lang/Double;

    .line 10
    .line 11
    if-nez p0, :cond_0

    .line 12
    .line 13
    const/4 p0, 0x0

    .line 14
    goto :goto_0

    .line 15
    :cond_0
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    :goto_0
    add-int/2addr v0, p0

    .line 20
    return v0
.end method

.method public toString()Ljava/lang/String;
    .locals 3

    .line 1
    iget-object v0, p0, Lcz/myskoda/api/bff/v1/ChargingPeriodDto;->sessions:Ljava/util/List;

    .line 2
    .line 3
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/ChargingPeriodDto;->totalChargedInKWh:Ljava/lang/Double;

    .line 4
    .line 5
    new-instance v1, Ljava/lang/StringBuilder;

    .line 6
    .line 7
    const-string v2, "ChargingPeriodDto(sessions="

    .line 8
    .line 9
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 13
    .line 14
    .line 15
    const-string v0, ", totalChargedInKWh="

    .line 16
    .line 17
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 18
    .line 19
    .line 20
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

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
