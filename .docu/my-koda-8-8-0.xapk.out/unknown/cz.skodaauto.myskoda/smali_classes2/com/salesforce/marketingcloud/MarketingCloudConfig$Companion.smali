.class public final Lcom/salesforce/marketingcloud/MarketingCloudConfig$Companion;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Lcom/salesforce/marketingcloud/MCKeep;
.end annotation

.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/MarketingCloudConfig;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "Companion"
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
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/MarketingCloudConfig$Companion;-><init>()V

    return-void
.end method


# virtual methods
.method public final builder()Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;
    .locals 0

    .line 1
    new-instance p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;

    .line 2
    .line 3
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;-><init>()V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method
