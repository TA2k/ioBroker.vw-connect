.class public final Lcom/salesforce/marketingcloud/util/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/salesforce/marketingcloud/util/Crypto;


# instance fields
.field private final a:Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptionManager;


# direct methods
.method public constructor <init>(Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptionManager;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcom/salesforce/marketingcloud/util/h;->a:Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptionManager;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public decString(Ljava/lang/String;)Ljava/lang/String;
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    if-nez p1, :cond_0

    .line 3
    .line 4
    return-object v0

    .line 5
    :cond_0
    iget-object p0, p0, Lcom/salesforce/marketingcloud/util/h;->a:Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptionManager;

    .line 6
    .line 7
    if-eqz p0, :cond_1

    .line 8
    .line 9
    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptionManager;->decrypt(Ljava/lang/String;)Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    return-object p0

    .line 14
    :cond_1
    return-object v0
.end method

.method public encString(Ljava/lang/String;)Ljava/lang/String;
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    if-nez p1, :cond_0

    .line 3
    .line 4
    return-object v0

    .line 5
    :cond_0
    iget-object p0, p0, Lcom/salesforce/marketingcloud/util/h;->a:Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptionManager;

    .line 6
    .line 7
    if-eqz p0, :cond_1

    .line 8
    .line 9
    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptionManager;->encrypt(Ljava/lang/String;)Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    return-object p0

    .line 14
    :cond_1
    return-object v0
.end method
