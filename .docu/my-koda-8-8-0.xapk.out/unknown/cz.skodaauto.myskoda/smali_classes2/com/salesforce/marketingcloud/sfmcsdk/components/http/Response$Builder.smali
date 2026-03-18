.class public final Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response$Builder;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "Builder"
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u00000\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0008\u0002\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\u0008\n\u0000\n\u0002\u0010\t\n\u0000\n\u0002\u0010$\n\u0002\u0010 \n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0000\u0018\u00002\u00020\u0001B\u0005\u00a2\u0006\u0002\u0010\u0002J\u000e\u0010\u0003\u001a\u00020\u00002\u0006\u0010\u0003\u001a\u00020\u0004J\u0006\u0010\u000e\u001a\u00020\u000fJ\u000e\u0010\u0005\u001a\u00020\u00002\u0006\u0010\u0005\u001a\u00020\u0006J\u000e\u0010\u0007\u001a\u00020\u00002\u0006\u0010\u0007\u001a\u00020\u0008J \u0010\t\u001a\u00020\u00002\u0018\u0010\t\u001a\u0014\u0012\u0004\u0012\u00020\u0004\u0012\n\u0012\u0008\u0012\u0004\u0012\u00020\u00040\u000b0\nJ\u000e\u0010\u000c\u001a\u00020\u00002\u0006\u0010\u000c\u001a\u00020\u0004J\u000e\u0010\r\u001a\u00020\u00002\u0006\u0010\r\u001a\u00020\u0008R\u0010\u0010\u0003\u001a\u0004\u0018\u00010\u0004X\u0082\u000e\u00a2\u0006\u0002\n\u0000R\u000e\u0010\u0005\u001a\u00020\u0006X\u0082\u000e\u00a2\u0006\u0002\n\u0000R\u000e\u0010\u0007\u001a\u00020\u0008X\u0082\u000e\u00a2\u0006\u0002\n\u0000R\"\u0010\t\u001a\u0016\u0012\u0004\u0012\u00020\u0004\u0012\n\u0012\u0008\u0012\u0004\u0012\u00020\u00040\u000b\u0018\u00010\nX\u0082\u000e\u00a2\u0006\u0002\n\u0000R\u0010\u0010\u000c\u001a\u0004\u0018\u00010\u0004X\u0082\u000e\u00a2\u0006\u0002\n\u0000R\u000e\u0010\r\u001a\u00020\u0008X\u0082\u000e\u00a2\u0006\u0002\n\u0000\u00a8\u0006\u0010"
    }
    d2 = {
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response$Builder;",
        "",
        "()V",
        "body",
        "",
        "code",
        "",
        "endTimeMillis",
        "",
        "headers",
        "",
        "",
        "message",
        "startTimeMillis",
        "build",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response;",
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


# instance fields
.field private body:Ljava/lang/String;

.field private code:I

.field private endTimeMillis:J

.field private headers:Ljava/util/Map;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "+",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;>;"
        }
    .end annotation
.end field

.field private message:Ljava/lang/String;

.field private startTimeMillis:J


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public final body(Ljava/lang/String;)Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response$Builder;
    .locals 1

    .line 1
    const-string v0, "body"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response$Builder;->body:Ljava/lang/String;

    .line 7
    .line 8
    return-object p0
.end method

.method public final build()Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response;
    .locals 9

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response;

    .line 2
    .line 3
    iget v1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response$Builder;->code:I

    .line 4
    .line 5
    iget-object v2, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response$Builder;->body:Ljava/lang/String;

    .line 6
    .line 7
    iget-object v3, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response$Builder;->message:Ljava/lang/String;

    .line 8
    .line 9
    iget-wide v4, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response$Builder;->startTimeMillis:J

    .line 10
    .line 11
    iget-wide v6, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response$Builder;->endTimeMillis:J

    .line 12
    .line 13
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response$Builder;->headers:Ljava/util/Map;

    .line 14
    .line 15
    if-nez p0, :cond_0

    .line 16
    .line 17
    sget-object p0, Lmx0/t;->d:Lmx0/t;

    .line 18
    .line 19
    :cond_0
    move-object v8, p0

    .line 20
    invoke-direct/range {v0 .. v8}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response;-><init>(ILjava/lang/String;Ljava/lang/String;JJLjava/util/Map;)V

    .line 21
    .line 22
    .line 23
    return-object v0
.end method

.method public final code(I)Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response$Builder;
    .locals 0

    .line 1
    iput p1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response$Builder;->code:I

    .line 2
    .line 3
    return-object p0
.end method

.method public final endTimeMillis(J)Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response$Builder;
    .locals 0

    .line 1
    iput-wide p1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response$Builder;->endTimeMillis:J

    .line 2
    .line 3
    return-object p0
.end method

.method public final headers(Ljava/util/Map;)Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response$Builder;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "+",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;>;)",
            "Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response$Builder;"
        }
    .end annotation

    .line 1
    const-string v0, "headers"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response$Builder;->headers:Ljava/util/Map;

    .line 7
    .line 8
    return-object p0
.end method

.method public final message(Ljava/lang/String;)Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response$Builder;
    .locals 1

    .line 1
    const-string v0, "message"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response$Builder;->message:Ljava/lang/String;

    .line 7
    .line 8
    return-object p0
.end method

.method public final startTimeMillis(J)Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response$Builder;
    .locals 0

    .line 1
    iput-wide p1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response$Builder;->startTimeMillis:J

    .line 2
    .line 3
    return-object p0
.end method
