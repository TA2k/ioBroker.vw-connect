.class final Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager$executeSync$2;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager;->executeSync(Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;)Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = null
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Lkotlin/jvm/internal/n;",
        "Lay0/a;"
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0008\n\u0000\n\u0002\u0010\u000e\n\u0000\u0010\u0000\u001a\u00020\u0001H\n\u00a2\u0006\u0002\u0008\u0002"
    }
    d2 = {
        "<anonymous>",
        "",
        "invoke"
    }
    k = 0x3
    mv = {
        0x1,
        0x9,
        0x0
    }
    xi = 0x30
.end annotation


# instance fields
.field final synthetic $request:Lkotlin/jvm/internal/f0;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lkotlin/jvm/internal/f0;"
        }
    .end annotation
.end field

.field final synthetic $response:Lkotlin/jvm/internal/f0;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lkotlin/jvm/internal/f0;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Lkotlin/jvm/internal/f0;Lkotlin/jvm/internal/f0;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lkotlin/jvm/internal/f0;",
            "Lkotlin/jvm/internal/f0;",
            ")V"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager$executeSync$2;->$request:Lkotlin/jvm/internal/f0;

    .line 2
    .line 3
    iput-object p2, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager$executeSync$2;->$response:Lkotlin/jvm/internal/f0;

    .line 4
    .line 5
    const/4 p1, 0x0

    .line 6
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public bridge synthetic invoke()Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager$executeSync$2;->invoke()Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

.method public final invoke()Ljava/lang/String;
    .locals 6

    .line 2
    iget-object v0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager$executeSync$2;->$request:Lkotlin/jvm/internal/f0;

    iget-object v0, v0, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    check-cast v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;

    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;->getName()Ljava/lang/String;

    move-result-object v0

    iget-object v1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager$executeSync$2;->$request:Lkotlin/jvm/internal/f0;

    iget-object v1, v1, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    check-cast v1, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;

    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;->getUrl()Ljava/lang/String;

    move-result-object v1

    iget-object v2, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager$executeSync$2;->$response:Lkotlin/jvm/internal/f0;

    iget-object v2, v2, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    check-cast v2, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response;

    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response;->timeToExecute()J

    move-result-wide v2

    iget-object v4, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager$executeSync$2;->$response:Lkotlin/jvm/internal/f0;

    iget-object v4, v4, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    check-cast v4, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response;

    invoke-virtual {v4}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response;->getCode()I

    move-result v4

    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager$executeSync$2;->$response:Lkotlin/jvm/internal/f0;

    iget-object p0, p0, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    check-cast p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response;

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response;->getMessage()Ljava/lang/String;

    move-result-object p0

    new-instance v5, Ljava/lang/StringBuilder;

    invoke-direct {v5}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v5, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v0, " request to "

    invoke-virtual {v5, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v5, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v0, " took "

    invoke-virtual {v5, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v5, v2, v3}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    const-string v0, "ms and resulted in a "

    invoke-virtual {v5, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v5, v4}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v0, " - "

    const-string v1, " response."

    .line 3
    invoke-static {v5, v0, p0, v1}, Lu/w;->h(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method
