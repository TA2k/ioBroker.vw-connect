.class public final Lcz/myskoda/api/bff_consents/v2/ThirdPartyOffersConsentDto;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000 \n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u000b\n\u0000\n\u0002\u0010\u000e\n\u0002\u0008\u000f\n\u0002\u0010\u0008\n\u0002\u0008\u0002\u0008\u0086\u0008\u0018\u00002\u00020\u0001B\u001b\u0012\u0008\u0008\u0001\u0010\u0002\u001a\u00020\u0003\u0012\u0008\u0008\u0001\u0010\u0004\u001a\u00020\u0005\u00a2\u0006\u0004\u0008\u0006\u0010\u0007J\t\u0010\u000f\u001a\u00020\u0003H\u00c6\u0003J\t\u0010\u0010\u001a\u00020\u0005H\u00c6\u0003J\u001d\u0010\u0011\u001a\u00020\u00002\u0008\u0008\u0003\u0010\u0002\u001a\u00020\u00032\u0008\u0008\u0003\u0010\u0004\u001a\u00020\u0005H\u00c6\u0001J\u0013\u0010\u0012\u001a\u00020\u00032\u0008\u0010\u0013\u001a\u0004\u0018\u00010\u0001H\u00d6\u0003J\t\u0010\u0014\u001a\u00020\u0015H\u00d6\u0001J\t\u0010\u0016\u001a\u00020\u0005H\u00d6\u0001R\u001c\u0010\u0002\u001a\u00020\u00038\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u0008\u0010\t\u001a\u0004\u0008\n\u0010\u000bR\u001c\u0010\u0004\u001a\u00020\u00058\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u000c\u0010\t\u001a\u0004\u0008\r\u0010\u000e\u00a8\u0006\u0017"
    }
    d2 = {
        "Lcz/myskoda/api/bff_consents/v2/ThirdPartyOffersConsentDto;",
        "",
        "consented",
        "",
        "text",
        "",
        "<init>",
        "(ZLjava/lang/String;)V",
        "getConsented$annotations",
        "()V",
        "getConsented",
        "()Z",
        "getText$annotations",
        "getText",
        "()Ljava/lang/String;",
        "component1",
        "component2",
        "copy",
        "equals",
        "other",
        "hashCode",
        "",
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
.field private final consented:Z

.field private final text:Ljava/lang/String;


# direct methods
.method public constructor <init>(ZLjava/lang/String;)V
    .locals 1
    .param p1    # Z
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "consented"
        .end annotation
    .end param
    .param p2    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "text"
        .end annotation
    .end param

    .line 1
    const-string v0, "text"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-boolean p1, p0, Lcz/myskoda/api/bff_consents/v2/ThirdPartyOffersConsentDto;->consented:Z

    .line 10
    .line 11
    iput-object p2, p0, Lcz/myskoda/api/bff_consents/v2/ThirdPartyOffersConsentDto;->text:Ljava/lang/String;

    .line 12
    .line 13
    return-void
.end method

.method public static synthetic copy$default(Lcz/myskoda/api/bff_consents/v2/ThirdPartyOffersConsentDto;ZLjava/lang/String;ILjava/lang/Object;)Lcz/myskoda/api/bff_consents/v2/ThirdPartyOffersConsentDto;
    .locals 0

    .line 1
    and-int/lit8 p4, p3, 0x1

    .line 2
    .line 3
    if-eqz p4, :cond_0

    .line 4
    .line 5
    iget-boolean p1, p0, Lcz/myskoda/api/bff_consents/v2/ThirdPartyOffersConsentDto;->consented:Z

    .line 6
    .line 7
    :cond_0
    and-int/lit8 p3, p3, 0x2

    .line 8
    .line 9
    if-eqz p3, :cond_1

    .line 10
    .line 11
    iget-object p2, p0, Lcz/myskoda/api/bff_consents/v2/ThirdPartyOffersConsentDto;->text:Ljava/lang/String;

    .line 12
    .line 13
    :cond_1
    invoke-virtual {p0, p1, p2}, Lcz/myskoda/api/bff_consents/v2/ThirdPartyOffersConsentDto;->copy(ZLjava/lang/String;)Lcz/myskoda/api/bff_consents/v2/ThirdPartyOffersConsentDto;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method

.method public static synthetic getConsented$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "consented"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getText$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "text"
    .end annotation

    .line 1
    return-void
.end method


# virtual methods
.method public final component1()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lcz/myskoda/api/bff_consents/v2/ThirdPartyOffersConsentDto;->consented:Z

    .line 2
    .line 3
    return p0
.end method

.method public final component2()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_consents/v2/ThirdPartyOffersConsentDto;->text:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final copy(ZLjava/lang/String;)Lcz/myskoda/api/bff_consents/v2/ThirdPartyOffersConsentDto;
    .locals 0
    .param p1    # Z
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "consented"
        .end annotation
    .end param
    .param p2    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "text"
        .end annotation
    .end param

    .line 1
    const-string p0, "text"

    .line 2
    .line 3
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance p0, Lcz/myskoda/api/bff_consents/v2/ThirdPartyOffersConsentDto;

    .line 7
    .line 8
    invoke-direct {p0, p1, p2}, Lcz/myskoda/api/bff_consents/v2/ThirdPartyOffersConsentDto;-><init>(ZLjava/lang/String;)V

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
    instance-of v1, p1, Lcz/myskoda/api/bff_consents/v2/ThirdPartyOffersConsentDto;

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
    check-cast p1, Lcz/myskoda/api/bff_consents/v2/ThirdPartyOffersConsentDto;

    .line 12
    .line 13
    iget-boolean v1, p0, Lcz/myskoda/api/bff_consents/v2/ThirdPartyOffersConsentDto;->consented:Z

    .line 14
    .line 15
    iget-boolean v3, p1, Lcz/myskoda/api/bff_consents/v2/ThirdPartyOffersConsentDto;->consented:Z

    .line 16
    .line 17
    if-eq v1, v3, :cond_2

    .line 18
    .line 19
    return v2

    .line 20
    :cond_2
    iget-object p0, p0, Lcz/myskoda/api/bff_consents/v2/ThirdPartyOffersConsentDto;->text:Ljava/lang/String;

    .line 21
    .line 22
    iget-object p1, p1, Lcz/myskoda/api/bff_consents/v2/ThirdPartyOffersConsentDto;->text:Ljava/lang/String;

    .line 23
    .line 24
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 25
    .line 26
    .line 27
    move-result p0

    .line 28
    if-nez p0, :cond_3

    .line 29
    .line 30
    return v2

    .line 31
    :cond_3
    return v0
.end method

.method public final getConsented()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lcz/myskoda/api/bff_consents/v2/ThirdPartyOffersConsentDto;->consented:Z

    .line 2
    .line 3
    return p0
.end method

.method public final getText()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_consents/v2/ThirdPartyOffersConsentDto;->text:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 1

    .line 1
    iget-boolean v0, p0, Lcz/myskoda/api/bff_consents/v2/ThirdPartyOffersConsentDto;->consented:Z

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
    iget-object p0, p0, Lcz/myskoda/api/bff_consents/v2/ThirdPartyOffersConsentDto;->text:Ljava/lang/String;

    .line 10
    .line 11
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    add-int/2addr p0, v0

    .line 16
    return p0
.end method

.method public toString()Ljava/lang/String;
    .locals 3

    .line 1
    iget-boolean v0, p0, Lcz/myskoda/api/bff_consents/v2/ThirdPartyOffersConsentDto;->consented:Z

    .line 2
    .line 3
    iget-object p0, p0, Lcz/myskoda/api/bff_consents/v2/ThirdPartyOffersConsentDto;->text:Ljava/lang/String;

    .line 4
    .line 5
    new-instance v1, Ljava/lang/StringBuilder;

    .line 6
    .line 7
    const-string v2, "ThirdPartyOffersConsentDto(consented="

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
    const-string v0, ", text="

    .line 16
    .line 17
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 18
    .line 19
    .line 20
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

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
