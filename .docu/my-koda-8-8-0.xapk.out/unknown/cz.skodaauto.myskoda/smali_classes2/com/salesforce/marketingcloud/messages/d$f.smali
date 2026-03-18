.class Lcom/salesforce/marketingcloud/messages/d$f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/salesforce/marketingcloud/notifications/a$b;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/salesforce/marketingcloud/messages/d;->a(Lcom/salesforce/marketingcloud/messages/Region;Lcom/salesforce/marketingcloud/messages/Message;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field final synthetic a:Lcom/salesforce/marketingcloud/messages/Message;

.field final synthetic b:Lcom/salesforce/marketingcloud/messages/d;


# direct methods
.method public constructor <init>(Lcom/salesforce/marketingcloud/messages/d;Lcom/salesforce/marketingcloud/messages/Message;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()V"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/d$f;->b:Lcom/salesforce/marketingcloud/messages/d;

    .line 2
    .line 3
    iput-object p2, p0, Lcom/salesforce/marketingcloud/messages/d$f;->a:Lcom/salesforce/marketingcloud/messages/Message;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public a(I)V
    .locals 2

    .line 1
    const/4 v0, -0x1

    .line 2
    if-eq p1, v0, :cond_0

    .line 3
    .line 4
    :try_start_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/d$f;->a:Lcom/salesforce/marketingcloud/messages/Message;

    .line 5
    .line 6
    invoke-static {v0, p1}, Lcom/salesforce/marketingcloud/internal/h;->a(Lcom/salesforce/marketingcloud/messages/Message;I)V

    .line 7
    .line 8
    .line 9
    iget-object p1, p0, Lcom/salesforce/marketingcloud/messages/d$f;->b:Lcom/salesforce/marketingcloud/messages/d;

    .line 10
    .line 11
    iget-object p1, p1, Lcom/salesforce/marketingcloud/messages/d;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 12
    .line 13
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/storage/h;->n()Lcom/salesforce/marketingcloud/storage/i;

    .line 14
    .line 15
    .line 16
    move-result-object p1

    .line 17
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/d$f;->a:Lcom/salesforce/marketingcloud/messages/Message;

    .line 18
    .line 19
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/d$f;->b:Lcom/salesforce/marketingcloud/messages/d;

    .line 20
    .line 21
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/d;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 22
    .line 23
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/h;->b()Lcom/salesforce/marketingcloud/util/Crypto;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    invoke-interface {p1, v0, p0}, Lcom/salesforce/marketingcloud/storage/i;->a(Lcom/salesforce/marketingcloud/messages/Message;Lcom/salesforce/marketingcloud/util/Crypto;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 28
    .line 29
    .line 30
    return-void

    .line 31
    :catch_0
    move-exception p0

    .line 32
    sget-object p1, Lcom/salesforce/marketingcloud/messages/d;->B:Ljava/lang/String;

    .line 33
    .line 34
    const/4 v0, 0x0

    .line 35
    new-array v0, v0, [Ljava/lang/Object;

    .line 36
    .line 37
    const-string v1, "Unable to update message id with notification id."

    .line 38
    .line 39
    invoke-static {p1, p0, v1, v0}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    :cond_0
    return-void
.end method
