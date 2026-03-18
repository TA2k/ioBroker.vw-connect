.class Lcom/salesforce/marketingcloud/messages/inbox/c$b;
.super Lcom/salesforce/marketingcloud/internal/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/salesforce/marketingcloud/messages/inbox/c;->a(Z)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field final synthetic c:Z

.field final synthetic d:Lcom/salesforce/marketingcloud/messages/inbox/c;


# direct methods
.method public varargs constructor <init>(Lcom/salesforce/marketingcloud/messages/inbox/c;Ljava/lang/String;[Ljava/lang/Object;Z)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/inbox/c$b;->d:Lcom/salesforce/marketingcloud/messages/inbox/c;

    .line 2
    .line 3
    iput-boolean p4, p0, Lcom/salesforce/marketingcloud/messages/inbox/c$b;->c:Z

    .line 4
    .line 5
    invoke-direct {p0, p2, p3}, Lcom/salesforce/marketingcloud/internal/i;-><init>(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public a()V
    .locals 2

    .line 1
    iget-boolean v0, p0, Lcom/salesforce/marketingcloud/messages/inbox/c$b;->c:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    sget-object v0, Lcom/salesforce/marketingcloud/http/b;->l:Lcom/salesforce/marketingcloud/http/b;

    .line 6
    .line 7
    goto :goto_0

    .line 8
    :cond_0
    sget-object v0, Lcom/salesforce/marketingcloud/http/b;->k:Lcom/salesforce/marketingcloud/http/b;

    .line 9
    .line 10
    :goto_0
    new-instance v1, Lcom/salesforce/marketingcloud/messages/inbox/c$b$a;

    .line 11
    .line 12
    invoke-direct {v1, p0, v0}, Lcom/salesforce/marketingcloud/messages/inbox/c$b$a;-><init>(Lcom/salesforce/marketingcloud/messages/inbox/c$b;Lcom/salesforce/marketingcloud/http/b;)V

    .line 13
    .line 14
    .line 15
    invoke-static {v1}, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->requestSdk(Lcom/salesforce/marketingcloud/MarketingCloudSdk$WhenReadyListener;)V

    .line 16
    .line 17
    .line 18
    return-void
.end method
