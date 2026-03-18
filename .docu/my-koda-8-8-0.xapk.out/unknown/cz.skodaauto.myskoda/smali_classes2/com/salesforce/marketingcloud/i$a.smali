.class public final Lcom/salesforce/marketingcloud/i$a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/i;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "a"
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
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/i$a;-><init>()V

    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/String;Lcom/salesforce/marketingcloud/registration/RegistrationManager;)Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/ModuleIdentity;
    .locals 1

    .line 1
    const-string p0, "applicationId"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string p0, "registrationManager"

    .line 7
    .line 8
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-static {}, Lcom/salesforce/marketingcloud/i;->a()Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/ModuleIdentity;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    if-nez p0, :cond_0

    .line 16
    .line 17
    new-instance p0, Lcom/salesforce/marketingcloud/i;

    .line 18
    .line 19
    const/4 v0, 0x0

    .line 20
    invoke-direct {p0, p1, p2, v0}, Lcom/salesforce/marketingcloud/i;-><init>(Ljava/lang/String;Lcom/salesforce/marketingcloud/registration/RegistrationManager;Lkotlin/jvm/internal/g;)V

    .line 21
    .line 22
    .line 23
    invoke-static {p0}, Lcom/salesforce/marketingcloud/i;->a(Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/ModuleIdentity;)V

    .line 24
    .line 25
    .line 26
    :cond_0
    invoke-static {}, Lcom/salesforce/marketingcloud/i;->a()Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/ModuleIdentity;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    return-object p0
.end method
