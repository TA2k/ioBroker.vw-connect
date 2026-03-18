.class public final Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptionManager;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000 \n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0002\u0008\u0008\n\u0002\u0010\u0012\n\u0002\u0008\u0002\u0018\u00002\u00020\u0001B\u0017\u0008\u0000\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u0012\u0006\u0010\u0004\u001a\u00020\u0005\u00a2\u0006\u0002\u0010\u0006J\u0010\u0010\n\u001a\u0004\u0018\u00010\u00052\u0006\u0010\u000b\u001a\u00020\u0005J\u0010\u0010\u000c\u001a\u0004\u0018\u00010\u00052\u0006\u0010\u000b\u001a\u00020\u0005J\u0018\u0010\u000c\u001a\u0004\u0018\u00010\u00052\u0006\u0010\u000b\u001a\u00020\u00052\u0006\u0010\r\u001a\u00020\u000eJ\u0006\u0010\u000f\u001a\u00020\u000eR\u0014\u0010\u0007\u001a\u00020\u0005X\u0080\u0004\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0008\u0010\t\u00a8\u0006\u0010"
    }
    d2 = {
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptionManager;",
        "",
        "context",
        "Landroid/content/Context;",
        "moduleApplicationId",
        "",
        "(Landroid/content/Context;Ljava/lang/String;)V",
        "encryptionKey",
        "getEncryptionKey$sfmcsdk_release",
        "()Ljava/lang/String;",
        "decrypt",
        "data",
        "encrypt",
        "iv",
        "",
        "generateIV",
        "sfmcsdk_release"
    }
    k = 0x1
    mv = {
        0x1,
        0x9,
        0x0
    }
    xi = 0x30
.end annotation


# instance fields
.field private final encryptionKey:Ljava/lang/String;


# direct methods
.method public constructor <init>(Landroid/content/Context;Ljava/lang/String;)V
    .locals 2

    .line 1
    const-string v0, "context"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "moduleApplicationId"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    new-instance v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/KeyStoreWrapper;

    .line 15
    .line 16
    invoke-direct {v0, p1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/KeyStoreWrapper;-><init>(Landroid/content/Context;)V

    .line 17
    .line 18
    .line 19
    new-instance v1, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/SalesforceKeyGenerator;

    .line 20
    .line 21
    invoke-direct {v1, p1, v0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/SalesforceKeyGenerator;-><init>(Landroid/content/Context;Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/KeyStoreWrapper;)V

    .line 22
    .line 23
    .line 24
    invoke-virtual {v1, p2}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/SalesforceKeyGenerator;->getEncryptionKey(Ljava/lang/String;)Ljava/lang/String;

    .line 25
    .line 26
    .line 27
    move-result-object p1

    .line 28
    const-string p2, "getEncryptionKey(...)"

    .line 29
    .line 30
    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    iput-object p1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptionManager;->encryptionKey:Ljava/lang/String;

    .line 34
    .line 35
    return-void
.end method


# virtual methods
.method public final decrypt(Ljava/lang/String;)Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "data"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptionManager;->encryptionKey:Ljava/lang/String;

    .line 7
    .line 8
    invoke-static {p1, p0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/Encryptor;->decrypt(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    return-object p0
.end method

.method public final encrypt(Ljava/lang/String;)Ljava/lang/String;
    .locals 1

    const-string v0, "data"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptionManager;->encryptionKey:Ljava/lang/String;

    invoke-static {p1, p0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/Encryptor;->encrypt(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

.method public final encrypt(Ljava/lang/String;[B)Ljava/lang/String;
    .locals 1

    const-string v0, "data"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "iv"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptionManager;->encryptionKey:Ljava/lang/String;

    invoke-static {p1, p0, p2}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/Encryptor;->encrypt(Ljava/lang/String;Ljava/lang/String;[B)Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

.method public final generateIV()[B
    .locals 1

    .line 1
    invoke-static {}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/Encryptor;->generateInitVector()[B

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    const-string v0, "generateInitVector(...)"

    .line 6
    .line 7
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    return-object p0
.end method

.method public final getEncryptionKey$sfmcsdk_release()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptionManager;->encryptionKey:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method
