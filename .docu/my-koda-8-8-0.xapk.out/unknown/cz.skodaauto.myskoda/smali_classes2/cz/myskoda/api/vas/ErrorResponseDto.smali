.class public final Lcz/myskoda/api/vas/ErrorResponseDto;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u00000\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\r\n\u0002\u0010\u000b\n\u0002\u0008\u0002\n\u0002\u0010\u0008\n\u0000\n\u0002\u0010\u000e\n\u0000\u0008\u0086\u0008\u0018\u00002\u00020\u0001B%\u0012\u0010\u0008\u0003\u0010\u0002\u001a\n\u0012\u0004\u0012\u00020\u0004\u0018\u00010\u0003\u0012\n\u0008\u0003\u0010\u0005\u001a\u0004\u0018\u00010\u0006\u00a2\u0006\u0004\u0008\u0007\u0010\u0008J\u0011\u0010\u0010\u001a\n\u0012\u0004\u0012\u00020\u0004\u0018\u00010\u0003H\u00c6\u0003J\u000b\u0010\u0011\u001a\u0004\u0018\u00010\u0006H\u00c6\u0003J\'\u0010\u0012\u001a\u00020\u00002\u0010\u0008\u0003\u0010\u0002\u001a\n\u0012\u0004\u0012\u00020\u0004\u0018\u00010\u00032\n\u0008\u0003\u0010\u0005\u001a\u0004\u0018\u00010\u0006H\u00c6\u0001J\u0013\u0010\u0013\u001a\u00020\u00142\u0008\u0010\u0015\u001a\u0004\u0018\u00010\u0001H\u00d6\u0003J\t\u0010\u0016\u001a\u00020\u0017H\u00d6\u0001J\t\u0010\u0018\u001a\u00020\u0019H\u00d6\u0001R$\u0010\u0002\u001a\n\u0012\u0004\u0012\u00020\u0004\u0018\u00010\u00038\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\t\u0010\n\u001a\u0004\u0008\u000b\u0010\u000cR\u001e\u0010\u0005\u001a\u0004\u0018\u00010\u00068\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\r\u0010\n\u001a\u0004\u0008\u000e\u0010\u000f\u00a8\u0006\u001a"
    }
    d2 = {
        "Lcz/myskoda/api/vas/ErrorResponseDto;",
        "",
        "errors",
        "",
        "Lcz/myskoda/api/vas/ValidationErrorDto;",
        "errorDetail",
        "Lcz/myskoda/api/vas/ErrorDetailDto;",
        "<init>",
        "(Ljava/util/List;Lcz/myskoda/api/vas/ErrorDetailDto;)V",
        "getErrors$annotations",
        "()V",
        "getErrors",
        "()Ljava/util/List;",
        "getErrorDetail$annotations",
        "getErrorDetail",
        "()Lcz/myskoda/api/vas/ErrorDetailDto;",
        "component1",
        "component2",
        "copy",
        "equals",
        "",
        "other",
        "hashCode",
        "",
        "toString",
        "",
        "vas-api_release"
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
.field private final errorDetail:Lcz/myskoda/api/vas/ErrorDetailDto;

.field private final errors:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lcz/myskoda/api/vas/ValidationErrorDto;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>()V
    .locals 2

    .line 1
    const/4 v0, 0x0

    const/4 v1, 0x3

    invoke-direct {p0, v0, v0, v1, v0}, Lcz/myskoda/api/vas/ErrorResponseDto;-><init>(Ljava/util/List;Lcz/myskoda/api/vas/ErrorDetailDto;ILkotlin/jvm/internal/g;)V

    return-void
.end method

.method public constructor <init>(Ljava/util/List;Lcz/myskoda/api/vas/ErrorDetailDto;)V
    .locals 0
    .param p1    # Ljava/util/List;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "errors"
        .end annotation
    .end param
    .param p2    # Lcz/myskoda/api/vas/ErrorDetailDto;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "errorDetail"
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Lcz/myskoda/api/vas/ValidationErrorDto;",
            ">;",
            "Lcz/myskoda/api/vas/ErrorDetailDto;",
            ")V"
        }
    .end annotation

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    iput-object p1, p0, Lcz/myskoda/api/vas/ErrorResponseDto;->errors:Ljava/util/List;

    .line 4
    iput-object p2, p0, Lcz/myskoda/api/vas/ErrorResponseDto;->errorDetail:Lcz/myskoda/api/vas/ErrorDetailDto;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/util/List;Lcz/myskoda/api/vas/ErrorDetailDto;ILkotlin/jvm/internal/g;)V
    .locals 1

    and-int/lit8 p4, p3, 0x1

    const/4 v0, 0x0

    if-eqz p4, :cond_0

    move-object p1, v0

    :cond_0
    and-int/lit8 p3, p3, 0x2

    if-eqz p3, :cond_1

    move-object p2, v0

    .line 5
    :cond_1
    invoke-direct {p0, p1, p2}, Lcz/myskoda/api/vas/ErrorResponseDto;-><init>(Ljava/util/List;Lcz/myskoda/api/vas/ErrorDetailDto;)V

    return-void
.end method

.method public static synthetic copy$default(Lcz/myskoda/api/vas/ErrorResponseDto;Ljava/util/List;Lcz/myskoda/api/vas/ErrorDetailDto;ILjava/lang/Object;)Lcz/myskoda/api/vas/ErrorResponseDto;
    .locals 0

    .line 1
    and-int/lit8 p4, p3, 0x1

    .line 2
    .line 3
    if-eqz p4, :cond_0

    .line 4
    .line 5
    iget-object p1, p0, Lcz/myskoda/api/vas/ErrorResponseDto;->errors:Ljava/util/List;

    .line 6
    .line 7
    :cond_0
    and-int/lit8 p3, p3, 0x2

    .line 8
    .line 9
    if-eqz p3, :cond_1

    .line 10
    .line 11
    iget-object p2, p0, Lcz/myskoda/api/vas/ErrorResponseDto;->errorDetail:Lcz/myskoda/api/vas/ErrorDetailDto;

    .line 12
    .line 13
    :cond_1
    invoke-virtual {p0, p1, p2}, Lcz/myskoda/api/vas/ErrorResponseDto;->copy(Ljava/util/List;Lcz/myskoda/api/vas/ErrorDetailDto;)Lcz/myskoda/api/vas/ErrorResponseDto;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method

.method public static synthetic getErrorDetail$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "errorDetail"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getErrors$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "errors"
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
            "Lcz/myskoda/api/vas/ValidationErrorDto;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/vas/ErrorResponseDto;->errors:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component2()Lcz/myskoda/api/vas/ErrorDetailDto;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/vas/ErrorResponseDto;->errorDetail:Lcz/myskoda/api/vas/ErrorDetailDto;

    .line 2
    .line 3
    return-object p0
.end method

.method public final copy(Ljava/util/List;Lcz/myskoda/api/vas/ErrorDetailDto;)Lcz/myskoda/api/vas/ErrorResponseDto;
    .locals 0
    .param p1    # Ljava/util/List;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "errors"
        .end annotation
    .end param
    .param p2    # Lcz/myskoda/api/vas/ErrorDetailDto;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "errorDetail"
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Lcz/myskoda/api/vas/ValidationErrorDto;",
            ">;",
            "Lcz/myskoda/api/vas/ErrorDetailDto;",
            ")",
            "Lcz/myskoda/api/vas/ErrorResponseDto;"
        }
    .end annotation

    .line 1
    new-instance p0, Lcz/myskoda/api/vas/ErrorResponseDto;

    .line 2
    .line 3
    invoke-direct {p0, p1, p2}, Lcz/myskoda/api/vas/ErrorResponseDto;-><init>(Ljava/util/List;Lcz/myskoda/api/vas/ErrorDetailDto;)V

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
    instance-of v1, p1, Lcz/myskoda/api/vas/ErrorResponseDto;

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
    check-cast p1, Lcz/myskoda/api/vas/ErrorResponseDto;

    .line 12
    .line 13
    iget-object v1, p0, Lcz/myskoda/api/vas/ErrorResponseDto;->errors:Ljava/util/List;

    .line 14
    .line 15
    iget-object v3, p1, Lcz/myskoda/api/vas/ErrorResponseDto;->errors:Ljava/util/List;

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
    iget-object p0, p0, Lcz/myskoda/api/vas/ErrorResponseDto;->errorDetail:Lcz/myskoda/api/vas/ErrorDetailDto;

    .line 25
    .line 26
    iget-object p1, p1, Lcz/myskoda/api/vas/ErrorResponseDto;->errorDetail:Lcz/myskoda/api/vas/ErrorDetailDto;

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

.method public final getErrorDetail()Lcz/myskoda/api/vas/ErrorDetailDto;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/vas/ErrorResponseDto;->errorDetail:Lcz/myskoda/api/vas/ErrorDetailDto;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getErrors()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lcz/myskoda/api/vas/ValidationErrorDto;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/vas/ErrorResponseDto;->errors:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 2

    .line 1
    iget-object v0, p0, Lcz/myskoda/api/vas/ErrorResponseDto;->errors:Ljava/util/List;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-nez v0, :cond_0

    .line 5
    .line 6
    move v0, v1

    .line 7
    goto :goto_0

    .line 8
    :cond_0
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    :goto_0
    mul-int/lit8 v0, v0, 0x1f

    .line 13
    .line 14
    iget-object p0, p0, Lcz/myskoda/api/vas/ErrorResponseDto;->errorDetail:Lcz/myskoda/api/vas/ErrorDetailDto;

    .line 15
    .line 16
    if-nez p0, :cond_1

    .line 17
    .line 18
    goto :goto_1

    .line 19
    :cond_1
    invoke-virtual {p0}, Lcz/myskoda/api/vas/ErrorDetailDto;->hashCode()I

    .line 20
    .line 21
    .line 22
    move-result v1

    .line 23
    :goto_1
    add-int/2addr v0, v1

    .line 24
    return v0
.end method

.method public toString()Ljava/lang/String;
    .locals 3

    .line 1
    iget-object v0, p0, Lcz/myskoda/api/vas/ErrorResponseDto;->errors:Ljava/util/List;

    .line 2
    .line 3
    iget-object p0, p0, Lcz/myskoda/api/vas/ErrorResponseDto;->errorDetail:Lcz/myskoda/api/vas/ErrorDetailDto;

    .line 4
    .line 5
    new-instance v1, Ljava/lang/StringBuilder;

    .line 6
    .line 7
    const-string v2, "ErrorResponseDto(errors="

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
    const-string v0, ", errorDetail="

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
