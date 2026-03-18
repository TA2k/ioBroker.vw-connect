.class public final Lcz/myskoda/api/bff_data_plan/v2/DataPlanAccountBalanceDto;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000.\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u0007\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0014\n\u0002\u0010\u000b\n\u0002\u0008\u0002\n\u0002\u0010\u0008\n\u0000\n\u0002\u0010\u000e\n\u0000\u0008\u0086\u0008\u0018\u00002\u00020\u0001B/\u0012\u0008\u0008\u0001\u0010\u0002\u001a\u00020\u0003\u0012\u0008\u0008\u0001\u0010\u0004\u001a\u00020\u0003\u0012\u0008\u0008\u0001\u0010\u0005\u001a\u00020\u0006\u0012\u0008\u0008\u0001\u0010\u0007\u001a\u00020\u0006\u00a2\u0006\u0004\u0008\u0008\u0010\tJ\t\u0010\u0015\u001a\u00020\u0003H\u00c6\u0003J\t\u0010\u0016\u001a\u00020\u0003H\u00c6\u0003J\t\u0010\u0017\u001a\u00020\u0006H\u00c6\u0003J\t\u0010\u0018\u001a\u00020\u0006H\u00c6\u0003J1\u0010\u0019\u001a\u00020\u00002\u0008\u0008\u0003\u0010\u0002\u001a\u00020\u00032\u0008\u0008\u0003\u0010\u0004\u001a\u00020\u00032\u0008\u0008\u0003\u0010\u0005\u001a\u00020\u00062\u0008\u0008\u0003\u0010\u0007\u001a\u00020\u0006H\u00c6\u0001J\u0013\u0010\u001a\u001a\u00020\u001b2\u0008\u0010\u001c\u001a\u0004\u0018\u00010\u0001H\u00d6\u0003J\t\u0010\u001d\u001a\u00020\u001eH\u00d6\u0001J\t\u0010\u001f\u001a\u00020 H\u00d6\u0001R\u001c\u0010\u0002\u001a\u00020\u00038\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\n\u0010\u000b\u001a\u0004\u0008\u000c\u0010\rR\u001c\u0010\u0004\u001a\u00020\u00038\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u000e\u0010\u000b\u001a\u0004\u0008\u000f\u0010\rR\u001c\u0010\u0005\u001a\u00020\u00068\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u0010\u0010\u000b\u001a\u0004\u0008\u0011\u0010\u0012R\u001c\u0010\u0007\u001a\u00020\u00068\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u0013\u0010\u000b\u001a\u0004\u0008\u0014\u0010\u0012\u00a8\u0006!"
    }
    d2 = {
        "Lcz/myskoda/api/bff_data_plan/v2/DataPlanAccountBalanceDto;",
        "",
        "totalDataInGB",
        "",
        "availableDataInGB",
        "renewalDate",
        "Ljava/time/OffsetDateTime;",
        "endDate",
        "<init>",
        "(FFLjava/time/OffsetDateTime;Ljava/time/OffsetDateTime;)V",
        "getTotalDataInGB$annotations",
        "()V",
        "getTotalDataInGB",
        "()F",
        "getAvailableDataInGB$annotations",
        "getAvailableDataInGB",
        "getRenewalDate$annotations",
        "getRenewalDate",
        "()Ljava/time/OffsetDateTime;",
        "getEndDate$annotations",
        "getEndDate",
        "component1",
        "component2",
        "component3",
        "component4",
        "copy",
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
.field private final availableDataInGB:F

.field private final endDate:Ljava/time/OffsetDateTime;

.field private final renewalDate:Ljava/time/OffsetDateTime;

.field private final totalDataInGB:F


# direct methods
.method public constructor <init>(FFLjava/time/OffsetDateTime;Ljava/time/OffsetDateTime;)V
    .locals 1
    .param p1    # F
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "totalDataInGB"
        .end annotation
    .end param
    .param p2    # F
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "availableDataInGB"
        .end annotation
    .end param
    .param p3    # Ljava/time/OffsetDateTime;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "renewalDate"
        .end annotation
    .end param
    .param p4    # Ljava/time/OffsetDateTime;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "endDate"
        .end annotation
    .end param

    .line 1
    const-string v0, "renewalDate"

    .line 2
    .line 3
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "endDate"

    .line 7
    .line 8
    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    iput p1, p0, Lcz/myskoda/api/bff_data_plan/v2/DataPlanAccountBalanceDto;->totalDataInGB:F

    .line 15
    .line 16
    iput p2, p0, Lcz/myskoda/api/bff_data_plan/v2/DataPlanAccountBalanceDto;->availableDataInGB:F

    .line 17
    .line 18
    iput-object p3, p0, Lcz/myskoda/api/bff_data_plan/v2/DataPlanAccountBalanceDto;->renewalDate:Ljava/time/OffsetDateTime;

    .line 19
    .line 20
    iput-object p4, p0, Lcz/myskoda/api/bff_data_plan/v2/DataPlanAccountBalanceDto;->endDate:Ljava/time/OffsetDateTime;

    .line 21
    .line 22
    return-void
.end method

.method public static synthetic copy$default(Lcz/myskoda/api/bff_data_plan/v2/DataPlanAccountBalanceDto;FFLjava/time/OffsetDateTime;Ljava/time/OffsetDateTime;ILjava/lang/Object;)Lcz/myskoda/api/bff_data_plan/v2/DataPlanAccountBalanceDto;
    .locals 0

    .line 1
    and-int/lit8 p6, p5, 0x1

    .line 2
    .line 3
    if-eqz p6, :cond_0

    .line 4
    .line 5
    iget p1, p0, Lcz/myskoda/api/bff_data_plan/v2/DataPlanAccountBalanceDto;->totalDataInGB:F

    .line 6
    .line 7
    :cond_0
    and-int/lit8 p6, p5, 0x2

    .line 8
    .line 9
    if-eqz p6, :cond_1

    .line 10
    .line 11
    iget p2, p0, Lcz/myskoda/api/bff_data_plan/v2/DataPlanAccountBalanceDto;->availableDataInGB:F

    .line 12
    .line 13
    :cond_1
    and-int/lit8 p6, p5, 0x4

    .line 14
    .line 15
    if-eqz p6, :cond_2

    .line 16
    .line 17
    iget-object p3, p0, Lcz/myskoda/api/bff_data_plan/v2/DataPlanAccountBalanceDto;->renewalDate:Ljava/time/OffsetDateTime;

    .line 18
    .line 19
    :cond_2
    and-int/lit8 p5, p5, 0x8

    .line 20
    .line 21
    if-eqz p5, :cond_3

    .line 22
    .line 23
    iget-object p4, p0, Lcz/myskoda/api/bff_data_plan/v2/DataPlanAccountBalanceDto;->endDate:Ljava/time/OffsetDateTime;

    .line 24
    .line 25
    :cond_3
    invoke-virtual {p0, p1, p2, p3, p4}, Lcz/myskoda/api/bff_data_plan/v2/DataPlanAccountBalanceDto;->copy(FFLjava/time/OffsetDateTime;Ljava/time/OffsetDateTime;)Lcz/myskoda/api/bff_data_plan/v2/DataPlanAccountBalanceDto;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    return-object p0
.end method

.method public static synthetic getAvailableDataInGB$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "availableDataInGB"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getEndDate$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "endDate"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getRenewalDate$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "renewalDate"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getTotalDataInGB$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "totalDataInGB"
    .end annotation

    .line 1
    return-void
.end method


# virtual methods
.method public final component1()F
    .locals 0

    .line 1
    iget p0, p0, Lcz/myskoda/api/bff_data_plan/v2/DataPlanAccountBalanceDto;->totalDataInGB:F

    .line 2
    .line 3
    return p0
.end method

.method public final component2()F
    .locals 0

    .line 1
    iget p0, p0, Lcz/myskoda/api/bff_data_plan/v2/DataPlanAccountBalanceDto;->availableDataInGB:F

    .line 2
    .line 3
    return p0
.end method

.method public final component3()Ljava/time/OffsetDateTime;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_data_plan/v2/DataPlanAccountBalanceDto;->renewalDate:Ljava/time/OffsetDateTime;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component4()Ljava/time/OffsetDateTime;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_data_plan/v2/DataPlanAccountBalanceDto;->endDate:Ljava/time/OffsetDateTime;

    .line 2
    .line 3
    return-object p0
.end method

.method public final copy(FFLjava/time/OffsetDateTime;Ljava/time/OffsetDateTime;)Lcz/myskoda/api/bff_data_plan/v2/DataPlanAccountBalanceDto;
    .locals 0
    .param p1    # F
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "totalDataInGB"
        .end annotation
    .end param
    .param p2    # F
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "availableDataInGB"
        .end annotation
    .end param
    .param p3    # Ljava/time/OffsetDateTime;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "renewalDate"
        .end annotation
    .end param
    .param p4    # Ljava/time/OffsetDateTime;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "endDate"
        .end annotation
    .end param

    .line 1
    const-string p0, "renewalDate"

    .line 2
    .line 3
    invoke-static {p3, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string p0, "endDate"

    .line 7
    .line 8
    invoke-static {p4, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    new-instance p0, Lcz/myskoda/api/bff_data_plan/v2/DataPlanAccountBalanceDto;

    .line 12
    .line 13
    invoke-direct {p0, p1, p2, p3, p4}, Lcz/myskoda/api/bff_data_plan/v2/DataPlanAccountBalanceDto;-><init>(FFLjava/time/OffsetDateTime;Ljava/time/OffsetDateTime;)V

    .line 14
    .line 15
    .line 16
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
    instance-of v1, p1, Lcz/myskoda/api/bff_data_plan/v2/DataPlanAccountBalanceDto;

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
    check-cast p1, Lcz/myskoda/api/bff_data_plan/v2/DataPlanAccountBalanceDto;

    .line 12
    .line 13
    iget v1, p0, Lcz/myskoda/api/bff_data_plan/v2/DataPlanAccountBalanceDto;->totalDataInGB:F

    .line 14
    .line 15
    iget v3, p1, Lcz/myskoda/api/bff_data_plan/v2/DataPlanAccountBalanceDto;->totalDataInGB:F

    .line 16
    .line 17
    invoke-static {v1, v3}, Ljava/lang/Float;->compare(FF)I

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-eqz v1, :cond_2

    .line 22
    .line 23
    return v2

    .line 24
    :cond_2
    iget v1, p0, Lcz/myskoda/api/bff_data_plan/v2/DataPlanAccountBalanceDto;->availableDataInGB:F

    .line 25
    .line 26
    iget v3, p1, Lcz/myskoda/api/bff_data_plan/v2/DataPlanAccountBalanceDto;->availableDataInGB:F

    .line 27
    .line 28
    invoke-static {v1, v3}, Ljava/lang/Float;->compare(FF)I

    .line 29
    .line 30
    .line 31
    move-result v1

    .line 32
    if-eqz v1, :cond_3

    .line 33
    .line 34
    return v2

    .line 35
    :cond_3
    iget-object v1, p0, Lcz/myskoda/api/bff_data_plan/v2/DataPlanAccountBalanceDto;->renewalDate:Ljava/time/OffsetDateTime;

    .line 36
    .line 37
    iget-object v3, p1, Lcz/myskoda/api/bff_data_plan/v2/DataPlanAccountBalanceDto;->renewalDate:Ljava/time/OffsetDateTime;

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
    iget-object p0, p0, Lcz/myskoda/api/bff_data_plan/v2/DataPlanAccountBalanceDto;->endDate:Ljava/time/OffsetDateTime;

    .line 47
    .line 48
    iget-object p1, p1, Lcz/myskoda/api/bff_data_plan/v2/DataPlanAccountBalanceDto;->endDate:Ljava/time/OffsetDateTime;

    .line 49
    .line 50
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 51
    .line 52
    .line 53
    move-result p0

    .line 54
    if-nez p0, :cond_5

    .line 55
    .line 56
    return v2

    .line 57
    :cond_5
    return v0
.end method

.method public final getAvailableDataInGB()F
    .locals 0

    .line 1
    iget p0, p0, Lcz/myskoda/api/bff_data_plan/v2/DataPlanAccountBalanceDto;->availableDataInGB:F

    .line 2
    .line 3
    return p0
.end method

.method public final getEndDate()Ljava/time/OffsetDateTime;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_data_plan/v2/DataPlanAccountBalanceDto;->endDate:Ljava/time/OffsetDateTime;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getRenewalDate()Ljava/time/OffsetDateTime;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_data_plan/v2/DataPlanAccountBalanceDto;->renewalDate:Ljava/time/OffsetDateTime;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getTotalDataInGB()F
    .locals 0

    .line 1
    iget p0, p0, Lcz/myskoda/api/bff_data_plan/v2/DataPlanAccountBalanceDto;->totalDataInGB:F

    .line 2
    .line 3
    return p0
.end method

.method public hashCode()I
    .locals 3

    .line 1
    iget v0, p0, Lcz/myskoda/api/bff_data_plan/v2/DataPlanAccountBalanceDto;->totalDataInGB:F

    .line 2
    .line 3
    invoke-static {v0}, Ljava/lang/Float;->hashCode(F)I

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
    iget v2, p0, Lcz/myskoda/api/bff_data_plan/v2/DataPlanAccountBalanceDto;->availableDataInGB:F

    .line 11
    .line 12
    invoke-static {v2, v0, v1}, La7/g0;->c(FII)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-object v2, p0, Lcz/myskoda/api/bff_data_plan/v2/DataPlanAccountBalanceDto;->renewalDate:Ljava/time/OffsetDateTime;

    .line 17
    .line 18
    invoke-static {v2, v0, v1}, Lia/b;->b(Ljava/time/OffsetDateTime;II)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    iget-object p0, p0, Lcz/myskoda/api/bff_data_plan/v2/DataPlanAccountBalanceDto;->endDate:Ljava/time/OffsetDateTime;

    .line 23
    .line 24
    invoke-virtual {p0}, Ljava/time/OffsetDateTime;->hashCode()I

    .line 25
    .line 26
    .line 27
    move-result p0

    .line 28
    add-int/2addr p0, v0

    .line 29
    return p0
.end method

.method public toString()Ljava/lang/String;
    .locals 5

    .line 1
    iget v0, p0, Lcz/myskoda/api/bff_data_plan/v2/DataPlanAccountBalanceDto;->totalDataInGB:F

    .line 2
    .line 3
    iget v1, p0, Lcz/myskoda/api/bff_data_plan/v2/DataPlanAccountBalanceDto;->availableDataInGB:F

    .line 4
    .line 5
    iget-object v2, p0, Lcz/myskoda/api/bff_data_plan/v2/DataPlanAccountBalanceDto;->renewalDate:Ljava/time/OffsetDateTime;

    .line 6
    .line 7
    iget-object p0, p0, Lcz/myskoda/api/bff_data_plan/v2/DataPlanAccountBalanceDto;->endDate:Ljava/time/OffsetDateTime;

    .line 8
    .line 9
    new-instance v3, Ljava/lang/StringBuilder;

    .line 10
    .line 11
    const-string v4, "DataPlanAccountBalanceDto(totalDataInGB="

    .line 12
    .line 13
    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 17
    .line 18
    .line 19
    const-string v0, ", availableDataInGB="

    .line 20
    .line 21
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 22
    .line 23
    .line 24
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 25
    .line 26
    .line 27
    const-string v0, ", renewalDate="

    .line 28
    .line 29
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 30
    .line 31
    .line 32
    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    const-string v0, ", endDate="

    .line 36
    .line 37
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 38
    .line 39
    .line 40
    invoke-virtual {v3, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    const-string p0, ")"

    .line 44
    .line 45
    invoke-virtual {v3, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    return-object p0
.end method
