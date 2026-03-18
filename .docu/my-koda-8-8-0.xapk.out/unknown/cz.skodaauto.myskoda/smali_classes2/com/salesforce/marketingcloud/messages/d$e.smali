.class Lcom/salesforce/marketingcloud/messages/d$e;
.super Lcom/salesforce/marketingcloud/internal/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/salesforce/marketingcloud/messages/d;->d(Lcom/salesforce/marketingcloud/messages/Region;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field final synthetic c:Lcom/salesforce/marketingcloud/messages/Region;

.field final synthetic d:Lcom/salesforce/marketingcloud/messages/d;


# direct methods
.method public varargs constructor <init>(Lcom/salesforce/marketingcloud/messages/d;Ljava/lang/String;[Ljava/lang/Object;Lcom/salesforce/marketingcloud/messages/Region;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/d$e;->d:Lcom/salesforce/marketingcloud/messages/d;

    .line 2
    .line 3
    iput-object p4, p0, Lcom/salesforce/marketingcloud/messages/d$e;->c:Lcom/salesforce/marketingcloud/messages/Region;

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
    .locals 3

    .line 1
    :try_start_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/d$e;->d:Lcom/salesforce/marketingcloud/messages/d;

    .line 2
    .line 3
    iget-object v0, v0, Lcom/salesforce/marketingcloud/messages/d;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 4
    .line 5
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/storage/h;->o()Lcom/salesforce/marketingcloud/storage/j;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/d$e;->c:Lcom/salesforce/marketingcloud/messages/Region;

    .line 10
    .line 11
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/d$e;->d:Lcom/salesforce/marketingcloud/messages/d;

    .line 12
    .line 13
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/d;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 14
    .line 15
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/h;->b()Lcom/salesforce/marketingcloud/util/Crypto;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    invoke-interface {v0, v1, p0}, Lcom/salesforce/marketingcloud/storage/j;->a(Lcom/salesforce/marketingcloud/messages/Region;Lcom/salesforce/marketingcloud/util/Crypto;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 20
    .line 21
    .line 22
    return-void

    .line 23
    :catch_0
    move-exception p0

    .line 24
    sget-object v0, Lcom/salesforce/marketingcloud/messages/d;->B:Ljava/lang/String;

    .line 25
    .line 26
    const/4 v1, 0x0

    .line 27
    new-array v1, v1, [Ljava/lang/Object;

    .line 28
    .line 29
    const-string v2, "Unable to set magic region"

    .line 30
    .line 31
    invoke-static {v0, p0, v2, v1}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 32
    .line 33
    .line 34
    return-void
.end method
