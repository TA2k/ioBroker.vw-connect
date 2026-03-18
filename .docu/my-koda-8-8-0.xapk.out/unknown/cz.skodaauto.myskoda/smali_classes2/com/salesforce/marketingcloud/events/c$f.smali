.class Lcom/salesforce/marketingcloud/events/c$f;
.super Lcom/salesforce/marketingcloud/internal/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/salesforce/marketingcloud/events/c;->onBehavior(Lcom/salesforce/marketingcloud/behaviors/a;Landroid/os/Bundle;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field final synthetic c:Lcom/salesforce/marketingcloud/events/c;


# direct methods
.method public varargs constructor <init>(Lcom/salesforce/marketingcloud/events/c;Ljava/lang/String;[Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/events/c$f;->c:Lcom/salesforce/marketingcloud/events/c;

    .line 2
    .line 3
    invoke-direct {p0, p2, p3}, Lcom/salesforce/marketingcloud/internal/i;-><init>(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public a()V
    .locals 2

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/events/c;->u:Ljava/lang/String;

    .line 2
    .line 3
    iget-object p0, p0, Lcom/salesforce/marketingcloud/events/c$f;->c:Lcom/salesforce/marketingcloud/events/c;

    .line 4
    .line 5
    iget-object p0, p0, Lcom/salesforce/marketingcloud/events/c;->f:Lcom/salesforce/marketingcloud/storage/h;

    .line 6
    .line 7
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/h;->h()Lcom/salesforce/marketingcloud/storage/a;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    invoke-interface {p0}, Lcom/salesforce/marketingcloud/storage/a;->a()I

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    filled-new-array {p0}, [Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    const-string v1, "Purged %d outdated analytic events."

    .line 24
    .line 25
    invoke-static {v0, v1, p0}, Lcom/salesforce/marketingcloud/g;->c(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 26
    .line 27
    .line 28
    return-void
.end method
