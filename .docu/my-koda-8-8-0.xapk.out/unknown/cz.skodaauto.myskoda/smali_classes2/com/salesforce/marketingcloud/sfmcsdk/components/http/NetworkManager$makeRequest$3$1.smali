.class final Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager$makeRequest$3$1;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager;->makeRequest$sfmcsdk_release(Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;)Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response;
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
.field final synthetic $it:Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response;

.field final synthetic $request:Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;


# direct methods
.method public constructor <init>(Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response;Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager$makeRequest$3$1;->$it:Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response;

    .line 2
    .line 3
    iput-object p2, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager$makeRequest$3$1;->$request:Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;

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
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager$makeRequest$3$1;->invoke()Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

.method public final invoke()Ljava/lang/String;
    .locals 6

    .line 2
    iget-object v0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager$makeRequest$3$1;->$it:Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response;

    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response;->getCode()I

    move-result v0

    iget-object v1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager$makeRequest$3$1;->$request:Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;

    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;->getName()Ljava/lang/String;

    move-result-object v1

    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager$makeRequest$3$1;->$it:Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response;

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response;->timeToExecute()J

    move-result-wide v2

    const-string p0, " for "

    const-string v4, " request. Request took "

    .line 3
    const-string v5, "HTTP response "

    invoke-static {v5, v0, p0, v1, v4}, Lf2/m0;->o(Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object p0

    .line 4
    const-string v0, "ms."

    .line 5
    invoke-static {v2, v3, v0, p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->k(JLjava/lang/String;Ljava/lang/StringBuilder;)Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method
