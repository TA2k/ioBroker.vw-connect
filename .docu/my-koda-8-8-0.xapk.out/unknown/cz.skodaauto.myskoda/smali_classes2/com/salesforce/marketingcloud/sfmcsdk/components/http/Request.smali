.class public final Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request$Builder;,
        Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request$Companion;,
        Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request$Method;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u00002\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u000e\n\u0002\u0008\u0002\n\u0002\u0010\u0008\n\u0002\u0008\u0002\n\u0002\u0010 \n\u0002\u0008\u0002\n\u0002\u0010\t\n\u0002\u0008\u0011\n\u0002\u0018\u0002\n\u0002\u0008\u0005\u0018\u0000 !2\u00020\u0001:\u0003 !\"BS\u0008\u0000\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u0012\u0008\u0010\u0004\u001a\u0004\u0018\u00010\u0003\u0012\u0006\u0010\u0005\u001a\u00020\u0006\u0012\u0006\u0010\u0007\u001a\u00020\u0003\u0012\u000c\u0010\u0008\u001a\u0008\u0012\u0004\u0012\u00020\u00030\t\u0012\u0006\u0010\n\u001a\u00020\u0003\u0012\u0006\u0010\u000b\u001a\u00020\u000c\u0012\n\u0008\u0002\u0010\r\u001a\u0004\u0018\u00010\u0003\u00a2\u0006\u0002\u0010\u000eJ\r\u0010\u001d\u001a\u00020\u001eH\u0000\u00a2\u0006\u0002\u0008\u001fR\u0011\u0010\u0005\u001a\u00020\u0006\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u000f\u0010\u0010R\u0017\u0010\u0008\u001a\u0008\u0012\u0004\u0012\u00020\u00030\t\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0011\u0010\u0012R\u0011\u0010\u0002\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0013\u0010\u0014R\u0011\u0010\n\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0015\u0010\u0014R\u0011\u0010\u000b\u001a\u00020\u000c\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0016\u0010\u0017R\u0013\u0010\u0004\u001a\u0004\u0018\u00010\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0018\u0010\u0014R\u001c\u0010\r\u001a\u0004\u0018\u00010\u0003X\u0086\u000e\u00a2\u0006\u000e\n\u0000\u001a\u0004\u0008\u0019\u0010\u0014\"\u0004\u0008\u001a\u0010\u001bR\u0011\u0010\u0007\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u001c\u0010\u0014\u00a8\u0006#"
    }
    d2 = {
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;",
        "",
        "method",
        "",
        "requestBody",
        "connectionTimeout",
        "",
        "url",
        "headers",
        "",
        "name",
        "rateLimit",
        "",
        "tag",
        "(Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;Ljava/util/List;Ljava/lang/String;JLjava/lang/String;)V",
        "getConnectionTimeout",
        "()I",
        "getHeaders",
        "()Ljava/util/List;",
        "getMethod",
        "()Ljava/lang/String;",
        "getName",
        "getRateLimit",
        "()J",
        "getRequestBody",
        "getTag",
        "setTag",
        "(Ljava/lang/String;)V",
        "getUrl",
        "toBuilder",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request$Builder;",
        "toBuilder$sfmcsdk_release",
        "Builder",
        "Companion",
        "Method",
        "sfmcsdk_release"
    }
    k = 0x1
    mv = {
        0x1,
        0x9,
        0x0
    }
    xi = 0x30
.end annotation


# static fields
.field public static final Companion:Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request$Companion;

.field private static final DEFAULT_CONNECTION_TIMEOUT:I = 0x7530

.field public static final GET:Ljava/lang/String; = "GET"

.field public static final PATCH:Ljava/lang/String; = "PATCH"

.field public static final POST:Ljava/lang/String; = "POST"

.field public static final PUT:Ljava/lang/String; = "PUT"

.field public static final RESPONSE_REQUEST_FAILED:I = -0x64


# instance fields
.field private final connectionTimeout:I

.field private final headers:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field private final method:Ljava/lang/String;

.field private final name:Ljava/lang/String;

.field private final rateLimit:J

.field private final requestBody:Ljava/lang/String;

.field private tag:Ljava/lang/String;

.field private final url:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request$Companion;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request$Companion;-><init>(Lkotlin/jvm/internal/g;)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;->Companion:Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request$Companion;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;Ljava/util/List;Ljava/lang/String;JLjava/lang/String;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "I",
            "Ljava/lang/String;",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;",
            "Ljava/lang/String;",
            "J",
            "Ljava/lang/String;",
            ")V"
        }
    .end annotation

    const-string v0, "method"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "url"

    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "headers"

    invoke-static {p5, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "name"

    invoke-static {p6, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;->method:Ljava/lang/String;

    .line 3
    iput-object p2, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;->requestBody:Ljava/lang/String;

    .line 4
    iput p3, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;->connectionTimeout:I

    .line 5
    iput-object p4, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;->url:Ljava/lang/String;

    .line 6
    iput-object p5, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;->headers:Ljava/util/List;

    .line 7
    iput-object p6, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;->name:Ljava/lang/String;

    .line 8
    iput-wide p7, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;->rateLimit:J

    .line 9
    iput-object p9, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;->tag:Ljava/lang/String;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;Ljava/util/List;Ljava/lang/String;JLjava/lang/String;ILkotlin/jvm/internal/g;)V
    .locals 11

    move/from16 v0, p10

    and-int/lit16 v0, v0, 0x80

    if-eqz v0, :cond_0

    const/4 v0, 0x0

    move-object v10, v0

    :goto_0
    move-object v1, p0

    move-object v2, p1

    move-object v3, p2

    move v4, p3

    move-object v5, p4

    move-object/from16 v6, p5

    move-object/from16 v7, p6

    move-wide/from16 v8, p7

    goto :goto_1

    :cond_0
    move-object/from16 v10, p9

    goto :goto_0

    .line 10
    :goto_1
    invoke-direct/range {v1 .. v10}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;-><init>(Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;Ljava/util/List;Ljava/lang/String;JLjava/lang/String;)V

    return-void
.end method


# virtual methods
.method public final getConnectionTimeout()I
    .locals 0

    .line 1
    iget p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;->connectionTimeout:I

    .line 2
    .line 3
    return p0
.end method

.method public final getHeaders()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;->headers:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getMethod()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;->method:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getName()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;->name:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getRateLimit()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;->rateLimit:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public final getRequestBody()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;->requestBody:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getTag()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;->tag:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getUrl()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;->url:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final setTag(Ljava/lang/String;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;->tag:Ljava/lang/String;

    .line 2
    .line 3
    return-void
.end method

.method public final toBuilder$sfmcsdk_release()Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request$Builder;
    .locals 2

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request$Builder;

    .line 2
    .line 3
    invoke-direct {v0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request$Builder;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object v1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;->method:Ljava/lang/String;

    .line 7
    .line 8
    invoke-virtual {v0, v1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request$Builder;->method(Ljava/lang/String;)Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request$Builder;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    iget-object v1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;->url:Ljava/lang/String;

    .line 13
    .line 14
    invoke-virtual {v0, v1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request$Builder;->url(Ljava/lang/String;)Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request$Builder;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    iget v1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;->connectionTimeout:I

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request$Builder;->connectionTimeout(I)Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request$Builder;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    iget-object v1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;->name:Ljava/lang/String;

    .line 25
    .line 26
    invoke-virtual {v0, v1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request$Builder;->name(Ljava/lang/String;)Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request$Builder;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    iget-object v1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;->headers:Ljava/util/List;

    .line 31
    .line 32
    invoke-virtual {v0, v1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request$Builder;->headers(Ljava/util/List;)Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request$Builder;

    .line 33
    .line 34
    .line 35
    move-result-object v0

    .line 36
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;->requestBody:Ljava/lang/String;

    .line 37
    .line 38
    if-eqz p0, :cond_0

    .line 39
    .line 40
    invoke-virtual {v0, p0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request$Builder;->requestBody(Ljava/lang/String;)Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request$Builder;

    .line 41
    .line 42
    .line 43
    :cond_0
    return-object v0
.end method
