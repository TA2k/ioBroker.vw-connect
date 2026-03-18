.class public final Lcom/salesforce/marketingcloud/sfmcsdk/components/storage/StorageManager;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000&\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0002\u0018\u00002\u00020\u0001B\'\u0008\u0000\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u0012\u0006\u0010\u0004\u001a\u00020\u0005\u0012\u0006\u0010\u0006\u001a\u00020\u0007\u0012\u0006\u0010\u0008\u001a\u00020\u0007\u00a2\u0006\u0002\u0010\tJ\u000e\u0010\n\u001a\u00020\u000b2\u0006\u0010\u000c\u001a\u00020\u0007R\u000e\u0010\u0002\u001a\u00020\u0003X\u0082\u0004\u00a2\u0006\u0002\n\u0000R\u000e\u0010\u0004\u001a\u00020\u0005X\u0082\u0004\u00a2\u0006\u0002\n\u0000R\u000e\u0010\u0006\u001a\u00020\u0007X\u0082\u0004\u00a2\u0006\u0002\n\u0000R\u000e\u0010\u0008\u001a\u00020\u0007X\u0082\u0004\u00a2\u0006\u0002\n\u0000\u00a8\u0006\r"
    }
    d2 = {
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/storage/StorageManager;",
        "",
        "context",
        "Landroid/content/Context;",
        "encryptionManager",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptionManager;",
        "moduleAppId",
        "",
        "registrationId",
        "(Landroid/content/Context;Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptionManager;Ljava/lang/String;Ljava/lang/String;)V",
        "getSecurePrefs",
        "Landroid/content/SharedPreferences;",
        "name",
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
.field private final context:Landroid/content/Context;

.field private final encryptionManager:Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptionManager;

.field private final moduleAppId:Ljava/lang/String;

.field private final registrationId:Ljava/lang/String;


# direct methods
.method public constructor <init>(Landroid/content/Context;Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptionManager;Ljava/lang/String;Ljava/lang/String;)V
    .locals 1

    .line 1
    const-string v0, "context"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "encryptionManager"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "moduleAppId"

    .line 12
    .line 13
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    const-string v0, "registrationId"

    .line 17
    .line 18
    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 22
    .line 23
    .line 24
    iput-object p1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/storage/StorageManager;->context:Landroid/content/Context;

    .line 25
    .line 26
    iput-object p2, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/storage/StorageManager;->encryptionManager:Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptionManager;

    .line 27
    .line 28
    iput-object p3, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/storage/StorageManager;->moduleAppId:Ljava/lang/String;

    .line 29
    .line 30
    iput-object p4, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/storage/StorageManager;->registrationId:Ljava/lang/String;

    .line 31
    .line 32
    return-void
.end method


# virtual methods
.method public final getSecurePrefs(Ljava/lang/String;)Landroid/content/SharedPreferences;
    .locals 4

    .line 1
    const-string v0, "name"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences;->Companion:Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$Companion;

    .line 7
    .line 8
    iget-object v1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/storage/StorageManager;->context:Landroid/content/Context;

    .line 9
    .line 10
    iget-object v2, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/storage/StorageManager;->moduleAppId:Ljava/lang/String;

    .line 11
    .line 12
    iget-object v3, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/storage/StorageManager;->registrationId:Ljava/lang/String;

    .line 13
    .line 14
    invoke-static {p1, v2, v3}, Lcom/salesforce/marketingcloud/sfmcsdk/util/FileUtilsKt;->getFilenameForModuleInstallation(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object p1

    .line 18
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/storage/StorageManager;->encryptionManager:Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptionManager;

    .line 19
    .line 20
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptionManager;->getEncryptionKey$sfmcsdk_release()Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    invoke-virtual {v0, v1, p1, p0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$Companion;->create(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    return-object p0
.end method
