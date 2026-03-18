.class public final Lcom/salesforce/marketingcloud/InitializationStatus$b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/InitializationStatus;
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
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/InitializationStatus$b;-><init>()V

    return-void
.end method


# virtual methods
.method public final a()Lcom/salesforce/marketingcloud/InitializationStatus;
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/InitializationStatus$b;->b()Lcom/salesforce/marketingcloud/InitializationStatus$a;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 6
    .line 7
    const-string v1, "Amazon devices are not supported"

    .line 8
    .line 9
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    invoke-virtual {p0, v0}, Lcom/salesforce/marketingcloud/InitializationStatus$a;->a(Ljava/lang/Throwable;)V

    .line 13
    .line 14
    .line 15
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/InitializationStatus$a;->a()Lcom/salesforce/marketingcloud/InitializationStatus;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    return-object p0
.end method

.method public final b()Lcom/salesforce/marketingcloud/InitializationStatus$a;
    .locals 0

    .line 1
    new-instance p0, Lcom/salesforce/marketingcloud/InitializationStatus$a;

    .line 2
    .line 3
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/InitializationStatus$a;-><init>()V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public final c()Lcom/salesforce/marketingcloud/InitializationStatus;
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/InitializationStatus$b;->b()Lcom/salesforce/marketingcloud/InitializationStatus$a;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 6
    .line 7
    const-string v1, "The SDK no longer includes the legacy encryption dependency. If you wish to proceed, please set the configuration parameter legacyEncryptionDependencyForciblyRemoved to true."

    .line 8
    .line 9
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    invoke-virtual {p0, v0}, Lcom/salesforce/marketingcloud/InitializationStatus$a;->a(Ljava/lang/Throwable;)V

    .line 13
    .line 14
    .line 15
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/InitializationStatus$a;->a()Lcom/salesforce/marketingcloud/InitializationStatus;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    return-object p0
.end method
