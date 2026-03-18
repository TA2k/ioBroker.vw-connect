.class public final Lcom/salesforce/marketingcloud/http/c$b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/http/c;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "b"
.end annotation


# direct methods
.method private constructor <init>()V
    .locals 0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lkotlin/jvm/internal/g;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/http/c$b;-><init>()V

    return-void
.end method


# virtual methods
.method public final a()Lcom/salesforce/marketingcloud/http/c$a;
    .locals 0

    .line 1
    new-instance p0, Lcom/salesforce/marketingcloud/http/c$a;

    invoke-direct {p0}, Lcom/salesforce/marketingcloud/http/c$a;-><init>()V

    return-object p0
.end method

.method public final a(Landroid/os/Bundle;)Lcom/salesforce/marketingcloud/http/c;
    .locals 3

    const-string p0, "data"

    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    sget-object p0, Lcom/salesforce/marketingcloud/http/c;->j:Lcom/salesforce/marketingcloud/http/c$b;

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/http/c$b;->a()Lcom/salesforce/marketingcloud/http/c$a;

    move-result-object p0

    .line 3
    const-string v0, "method"

    invoke-virtual {p1, v0}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    if-eqz v0, :cond_0

    invoke-virtual {p0, v0}, Lcom/salesforce/marketingcloud/http/c$a;->b(Ljava/lang/String;)Lcom/salesforce/marketingcloud/http/c$a;

    .line 4
    :cond_0
    const-string v0, "requestBody"

    invoke-virtual {p1, v0}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    if-eqz v0, :cond_1

    invoke-virtual {p0, v0}, Lcom/salesforce/marketingcloud/http/c$a;->c(Ljava/lang/String;)Lcom/salesforce/marketingcloud/http/c$a;

    .line 5
    :cond_1
    const-string v0, "connectionTimeout"

    invoke-virtual {p1, v0}, Landroid/os/BaseBundle;->getInt(Ljava/lang/String;)I

    move-result v0

    invoke-virtual {p0, v0}, Lcom/salesforce/marketingcloud/http/c$a;->a(I)Lcom/salesforce/marketingcloud/http/c$a;

    .line 6
    const-string v0, "contentType"

    invoke-virtual {p1, v0}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    if-eqz v0, :cond_2

    invoke-virtual {p0, v0}, Lcom/salesforce/marketingcloud/http/c$a;->a(Ljava/lang/String;)Lcom/salesforce/marketingcloud/http/c$a;

    .line 7
    :cond_2
    const-string v0, "url"

    invoke-virtual {p1, v0}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    if-eqz v0, :cond_3

    invoke-virtual {p0, v0}, Lcom/salesforce/marketingcloud/http/c$a;->d(Ljava/lang/String;)Lcom/salesforce/marketingcloud/http/c$a;

    .line 8
    :cond_3
    const-string v0, "headers"

    invoke-virtual {p1, v0}, Landroid/os/Bundle;->getStringArrayList(Ljava/lang/String;)Ljava/util/ArrayList;

    move-result-object v0

    if-eqz v0, :cond_4

    invoke-virtual {p0, v0}, Lcom/salesforce/marketingcloud/http/c$a;->a(Ljava/util/List;)V

    .line 9
    :cond_4
    invoke-static {}, Lcom/salesforce/marketingcloud/http/b;->values()[Lcom/salesforce/marketingcloud/http/b;

    move-result-object v0

    const-string v1, "mcRequestId"

    const/4 v2, 0x0

    invoke-virtual {p1, v1, v2}, Landroid/os/BaseBundle;->getInt(Ljava/lang/String;I)I

    move-result v1

    aget-object v0, v0, v1

    invoke-virtual {p0, v0}, Lcom/salesforce/marketingcloud/http/c$a;->a(Lcom/salesforce/marketingcloud/http/b;)Lcom/salesforce/marketingcloud/http/c$a;

    .line 10
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/http/c$a;->a()Lcom/salesforce/marketingcloud/http/c;

    move-result-object p0

    .line 11
    const-string v0, "tag"

    invoke-virtual {p1, v0}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/http/c;->a(Ljava/lang/String;)V

    return-object p0
.end method

.method public final b()Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {}, Lcom/salesforce/marketingcloud/http/c;->a()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method
