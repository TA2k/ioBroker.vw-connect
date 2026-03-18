.class Lcom/salesforce/marketingcloud/registration/e$c;
.super Lcom/salesforce/marketingcloud/internal/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/salesforce/marketingcloud/registration/e;->a(ILjava/lang/String;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field final synthetic c:Lcom/salesforce/marketingcloud/registration/e;


# direct methods
.method public varargs constructor <init>(Lcom/salesforce/marketingcloud/registration/e;Ljava/lang/String;[Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/registration/e$c;->c:Lcom/salesforce/marketingcloud/registration/e;

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
    iget-object v0, p0, Lcom/salesforce/marketingcloud/registration/e$c;->c:Lcom/salesforce/marketingcloud/registration/e;

    .line 2
    .line 3
    iget-object v1, v0, Lcom/salesforce/marketingcloud/registration/e;->f:Lcom/salesforce/marketingcloud/storage/h;

    .line 4
    .line 5
    iget-object v0, v0, Lcom/salesforce/marketingcloud/registration/e;->e:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    .line 6
    .line 7
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->delayRegistrationUntilContactKeyIsSet()Z

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    invoke-static {v1, v0}, Lcom/salesforce/marketingcloud/registration/e;->a(Lcom/salesforce/marketingcloud/storage/h;Z)Z

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    if-eqz v0, :cond_0

    .line 16
    .line 17
    iget-object p0, p0, Lcom/salesforce/marketingcloud/registration/e$c;->c:Lcom/salesforce/marketingcloud/registration/e;

    .line 18
    .line 19
    iget-object p0, p0, Lcom/salesforce/marketingcloud/registration/e;->g:Lcom/salesforce/marketingcloud/alarms/b;

    .line 20
    .line 21
    sget-object v0, Lcom/salesforce/marketingcloud/alarms/a$a;->c:Lcom/salesforce/marketingcloud/alarms/a$a;

    .line 22
    .line 23
    filled-new-array {v0}, [Lcom/salesforce/marketingcloud/alarms/a$a;

    .line 24
    .line 25
    .line 26
    move-result-object v0

    .line 27
    invoke-virtual {p0, v0}, Lcom/salesforce/marketingcloud/alarms/b;->b([Lcom/salesforce/marketingcloud/alarms/a$a;)V

    .line 28
    .line 29
    .line 30
    :cond_0
    return-void
.end method
