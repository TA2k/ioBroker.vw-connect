.class final Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager$executeAsync$1;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager;->executeAsync(Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Callback;)V
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
        "\u0000\u0008\n\u0002\u0018\u0002\n\u0002\u0008\u0003\u0010\u0003\u001a\u00020\u0000H\n\u00a2\u0006\u0004\u0008\u0001\u0010\u0002"
    }
    d2 = {
        "Llx0/b0;",
        "invoke",
        "()V",
        "<anonymous>"
    }
    k = 0x3
    mv = {
        0x1,
        0x9,
        0x0
    }
.end annotation


# instance fields
.field final synthetic $callback:Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Callback;

.field final synthetic $request:Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;

.field final synthetic this$0:Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager;


# direct methods
.method public constructor <init>(Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Callback;Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager$executeAsync$1;->$callback:Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Callback;

    .line 2
    .line 3
    iput-object p2, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager$executeAsync$1;->$request:Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;

    .line 4
    .line 5
    iput-object p3, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager$executeAsync$1;->this$0:Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager;

    .line 6
    .line 7
    const/4 p1, 0x0

    .line 8
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 9
    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public bridge synthetic invoke()Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager$executeAsync$1;->invoke()V

    sget-object p0, Llx0/b0;->a:Llx0/b0;

    return-object p0
.end method

.method public final invoke()V
    .locals 2

    .line 2
    iget-object v0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager$executeAsync$1;->$callback:Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Callback;

    iget-object v1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager$executeAsync$1;->$request:Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;

    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager$executeAsync$1;->this$0:Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager;

    invoke-virtual {p0, v1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager;->executeSync(Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;)Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response;

    move-result-object p0

    invoke-interface {v0, v1, p0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Callback;->onResponse(Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response;)V

    return-void
.end method
