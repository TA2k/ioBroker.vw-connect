.class final Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$Editor;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/content/SharedPreferences$Editor;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "Editor"
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000^\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\u0012\n\u0002\u0008\u0006\n\u0002\u0010#\n\u0002\u0008\u0003\n\u0002\u0010\u0008\n\u0002\u0008\u0002\n\u0002\u0010\t\n\u0002\u0008\u0002\n\u0002\u0010\u0007\n\u0002\u0008\u0002\n\u0002\u0010\u000b\n\u0002\u0008\u000c\n\u0002\u0010!\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\u0008\u0002\u0018\u00002\u00020\u0001B\u0019\u0008\u0000\u0012\u0006\u0010\u0003\u001a\u00020\u0002\u0012\u0006\u0010\u0004\u001a\u00020\u0001\u00a2\u0006\u0004\u0008\u0005\u0010\u0006J\u000f\u0010\u0008\u001a\u00020\u0007H\u0002\u00a2\u0006\u0004\u0008\u0008\u0010\tJ!\u0010\u000e\u001a\u00020\u00072\u0008\u0010\u000b\u001a\u0004\u0018\u00010\n2\u0006\u0010\r\u001a\u00020\u000cH\u0002\u00a2\u0006\u0004\u0008\u000e\u0010\u000fJ\u000f\u0010\u0010\u001a\u00020\u0007H\u0002\u00a2\u0006\u0004\u0008\u0010\u0010\tJ#\u0010\u0011\u001a\u00020\u00012\u0008\u0010\u000b\u001a\u0004\u0018\u00010\n2\u0008\u0010\r\u001a\u0004\u0018\u00010\nH\u0016\u00a2\u0006\u0004\u0008\u0011\u0010\u0012J)\u0010\u0015\u001a\u00020\u00012\u0008\u0010\u000b\u001a\u0004\u0018\u00010\n2\u000e\u0010\u0014\u001a\n\u0012\u0004\u0012\u00020\n\u0018\u00010\u0013H\u0016\u00a2\u0006\u0004\u0008\u0015\u0010\u0016J!\u0010\u0018\u001a\u00020\u00012\u0008\u0010\u000b\u001a\u0004\u0018\u00010\n2\u0006\u0010\r\u001a\u00020\u0017H\u0016\u00a2\u0006\u0004\u0008\u0018\u0010\u0019J!\u0010\u001b\u001a\u00020\u00012\u0008\u0010\u000b\u001a\u0004\u0018\u00010\n2\u0006\u0010\r\u001a\u00020\u001aH\u0016\u00a2\u0006\u0004\u0008\u001b\u0010\u001cJ!\u0010\u001e\u001a\u00020\u00012\u0008\u0010\u000b\u001a\u0004\u0018\u00010\n2\u0006\u0010\r\u001a\u00020\u001dH\u0016\u00a2\u0006\u0004\u0008\u001e\u0010\u001fJ!\u0010!\u001a\u00020\u00012\u0008\u0010\u000b\u001a\u0004\u0018\u00010\n2\u0006\u0010\r\u001a\u00020 H\u0016\u00a2\u0006\u0004\u0008!\u0010\"J\u0019\u0010#\u001a\u00020\u00012\u0008\u0010\u000b\u001a\u0004\u0018\u00010\nH\u0016\u00a2\u0006\u0004\u0008#\u0010$J\u001f\u0010#\u001a\u00020\u00012\u0008\u0010\u000b\u001a\u0004\u0018\u00010\n2\u0006\u0010%\u001a\u00020 \u00a2\u0006\u0004\u0008#\u0010\"J\u000f\u0010&\u001a\u00020\u0001H\u0016\u00a2\u0006\u0004\u0008&\u0010\'J\u000f\u0010(\u001a\u00020 H\u0016\u00a2\u0006\u0004\u0008(\u0010)J\u000f\u0010*\u001a\u00020\u0007H\u0016\u00a2\u0006\u0004\u0008*\u0010\tR\u0014\u0010\u0003\u001a\u00020\u00028\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008\u0003\u0010+R\u0014\u0010\u0004\u001a\u00020\u00018\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008\u0004\u0010,R\u001c\u0010.\u001a\n\u0012\u0006\u0012\u0004\u0018\u00010\n0-8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008.\u0010/R\u0014\u00101\u001a\u0002008\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u00081\u00102\u00a8\u00063"
    }
    d2 = {
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$Editor;",
        "Landroid/content/SharedPreferences$Editor;",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences;",
        "mEncryptedSharedPreferences",
        "mEditor",
        "<init>",
        "(Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences;Landroid/content/SharedPreferences$Editor;)V",
        "Llx0/b0;",
        "clearKeysIfNeeded",
        "()V",
        "",
        "key",
        "",
        "value",
        "putEncryptedObject",
        "(Ljava/lang/String;[B)V",
        "notifyListeners",
        "putString",
        "(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;",
        "",
        "values",
        "putStringSet",
        "(Ljava/lang/String;Ljava/util/Set;)Landroid/content/SharedPreferences$Editor;",
        "",
        "putInt",
        "(Ljava/lang/String;I)Landroid/content/SharedPreferences$Editor;",
        "",
        "putLong",
        "(Ljava/lang/String;J)Landroid/content/SharedPreferences$Editor;",
        "",
        "putFloat",
        "(Ljava/lang/String;F)Landroid/content/SharedPreferences$Editor;",
        "",
        "putBoolean",
        "(Ljava/lang/String;Z)Landroid/content/SharedPreferences$Editor;",
        "remove",
        "(Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;",
        "encryptKey",
        "clear",
        "()Landroid/content/SharedPreferences$Editor;",
        "commit",
        "()Z",
        "apply",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences;",
        "Landroid/content/SharedPreferences$Editor;",
        "",
        "mKeysChanged",
        "Ljava/util/List;",
        "Ljava/util/concurrent/atomic/AtomicBoolean;",
        "mClearRequested",
        "Ljava/util/concurrent/atomic/AtomicBoolean;",
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
.field private final mClearRequested:Ljava/util/concurrent/atomic/AtomicBoolean;

.field private final mEditor:Landroid/content/SharedPreferences$Editor;

.field private final mEncryptedSharedPreferences:Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences;

.field private final mKeysChanged:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences;Landroid/content/SharedPreferences$Editor;)V
    .locals 1

    .line 1
    const-string v0, "mEncryptedSharedPreferences"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "mEditor"

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
    iput-object p1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$Editor;->mEncryptedSharedPreferences:Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences;

    .line 15
    .line 16
    iput-object p2, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$Editor;->mEditor:Landroid/content/SharedPreferences$Editor;

    .line 17
    .line 18
    new-instance p1, Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 19
    .line 20
    const/4 p2, 0x0

    .line 21
    invoke-direct {p1, p2}, Ljava/util/concurrent/atomic/AtomicBoolean;-><init>(Z)V

    .line 22
    .line 23
    .line 24
    iput-object p1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$Editor;->mClearRequested:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 25
    .line 26
    new-instance p1, Ljava/util/concurrent/CopyOnWriteArrayList;

    .line 27
    .line 28
    invoke-direct {p1}, Ljava/util/concurrent/CopyOnWriteArrayList;-><init>()V

    .line 29
    .line 30
    .line 31
    iput-object p1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$Editor;->mKeysChanged:Ljava/util/List;

    .line 32
    .line 33
    return-void
.end method

.method private final clearKeysIfNeeded()V
    .locals 4

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$Editor;->mClearRequested:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-virtual {v0, v1}, Ljava/util/concurrent/atomic/AtomicBoolean;->getAndSet(Z)Z

    .line 5
    .line 6
    .line 7
    move-result v0

    .line 8
    if-eqz v0, :cond_1

    .line 9
    .line 10
    iget-object v0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$Editor;->mEncryptedSharedPreferences:Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences;

    .line 11
    .line 12
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences;->getAllKeys()Ljava/util/Set;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    :cond_0
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 21
    .line 22
    .line 23
    move-result v2

    .line 24
    if-eqz v2, :cond_1

    .line 25
    .line 26
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object v2

    .line 30
    check-cast v2, Ljava/lang/String;

    .line 31
    .line 32
    iget-object v3, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$Editor;->mKeysChanged:Ljava/util/List;

    .line 33
    .line 34
    invoke-interface {v3, v2}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 35
    .line 36
    .line 37
    move-result v3

    .line 38
    if-nez v3, :cond_0

    .line 39
    .line 40
    iget-object v3, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$Editor;->mEncryptedSharedPreferences:Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences;

    .line 41
    .line 42
    invoke-virtual {v3, v2}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences;->isReservedKey(Ljava/lang/String;)Z

    .line 43
    .line 44
    .line 45
    move-result v3

    .line 46
    if-nez v3, :cond_0

    .line 47
    .line 48
    invoke-virtual {p0, v2, v1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$Editor;->remove(Ljava/lang/String;Z)Landroid/content/SharedPreferences$Editor;

    .line 49
    .line 50
    .line 51
    goto :goto_0

    .line 52
    :cond_1
    return-void
.end method

.method private final notifyListeners()V
    .locals 5

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$Editor;->mEncryptedSharedPreferences:Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences;

    .line 2
    .line 3
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences;->getMListeners()Ljava/util/List;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-interface {v0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    :cond_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    if-eqz v1, :cond_1

    .line 16
    .line 17
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    check-cast v1, Landroid/content/SharedPreferences$OnSharedPreferenceChangeListener;

    .line 22
    .line 23
    iget-object v2, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$Editor;->mKeysChanged:Ljava/util/List;

    .line 24
    .line 25
    invoke-interface {v2}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 26
    .line 27
    .line 28
    move-result-object v2

    .line 29
    :goto_0
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 30
    .line 31
    .line 32
    move-result v3

    .line 33
    if-eqz v3, :cond_0

    .line 34
    .line 35
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object v3

    .line 39
    check-cast v3, Ljava/lang/String;

    .line 40
    .line 41
    iget-object v4, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$Editor;->mEncryptedSharedPreferences:Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences;

    .line 42
    .line 43
    invoke-interface {v1, v4, v3}, Landroid/content/SharedPreferences$OnSharedPreferenceChangeListener;->onSharedPreferenceChanged(Landroid/content/SharedPreferences;Ljava/lang/String;)V

    .line 44
    .line 45
    .line 46
    goto :goto_0

    .line 47
    :cond_1
    return-void
.end method

.method private final putEncryptedObject(Ljava/lang/String;[B)V
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$Editor;->mEncryptedSharedPreferences:Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences;->isReservedKey(Ljava/lang/String;)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-nez v0, :cond_1

    .line 8
    .line 9
    iget-object v0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$Editor;->mKeysChanged:Ljava/util/List;

    .line 10
    .line 11
    invoke-interface {v0, p1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    if-nez p1, :cond_0

    .line 15
    .line 16
    const-string p1, "__NULL__"

    .line 17
    .line 18
    :cond_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$Editor;->mEncryptedSharedPreferences:Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences;

    .line 19
    .line 20
    invoke-static {v0, p1, p2}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences;->access$encryptKeyValuePair(Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences;Ljava/lang/String;[B)Landroid/util/Pair;

    .line 21
    .line 22
    .line 23
    move-result-object p1

    .line 24
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$Editor;->mEditor:Landroid/content/SharedPreferences$Editor;

    .line 25
    .line 26
    iget-object p2, p1, Landroid/util/Pair;->first:Ljava/lang/Object;

    .line 27
    .line 28
    check-cast p2, Ljava/lang/String;

    .line 29
    .line 30
    iget-object p1, p1, Landroid/util/Pair;->second:Ljava/lang/Object;

    .line 31
    .line 32
    check-cast p1, Ljava/lang/String;

    .line 33
    .line 34
    invoke-interface {p0, p2, p1}, Landroid/content/SharedPreferences$Editor;->putString(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;

    .line 35
    .line 36
    .line 37
    return-void

    .line 38
    :cond_1
    new-instance p0, Ljava/lang/SecurityException;

    .line 39
    .line 40
    const-string p2, " is a reserved key for the encryption keyset."

    .line 41
    .line 42
    invoke-static {p1, p2}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 43
    .line 44
    .line 45
    move-result-object p1

    .line 46
    invoke-direct {p0, p1}, Ljava/lang/SecurityException;-><init>(Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    throw p0
.end method


# virtual methods
.method public apply()V
    .locals 1

    .line 1
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$Editor;->clearKeysIfNeeded()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$Editor;->mEditor:Landroid/content/SharedPreferences$Editor;

    .line 5
    .line 6
    invoke-interface {v0}, Landroid/content/SharedPreferences$Editor;->apply()V

    .line 7
    .line 8
    .line 9
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$Editor;->notifyListeners()V

    .line 10
    .line 11
    .line 12
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$Editor;->mKeysChanged:Ljava/util/List;

    .line 13
    .line 14
    invoke-interface {p0}, Ljava/util/List;->clear()V

    .line 15
    .line 16
    .line 17
    return-void
.end method

.method public clear()Landroid/content/SharedPreferences$Editor;
    .locals 2

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$Editor;->mClearRequested:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    invoke-virtual {v0, v1}, Ljava/util/concurrent/atomic/AtomicBoolean;->set(Z)V

    .line 5
    .line 6
    .line 7
    return-object p0
.end method

.method public commit()Z
    .locals 1

    .line 1
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$Editor;->clearKeysIfNeeded()V

    .line 2
    .line 3
    .line 4
    :try_start_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$Editor;->mEditor:Landroid/content/SharedPreferences$Editor;

    .line 5
    .line 6
    invoke-interface {v0}, Landroid/content/SharedPreferences$Editor;->commit()Z

    .line 7
    .line 8
    .line 9
    move-result v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 10
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$Editor;->notifyListeners()V

    .line 11
    .line 12
    .line 13
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$Editor;->mKeysChanged:Ljava/util/List;

    .line 14
    .line 15
    invoke-interface {p0}, Ljava/util/List;->clear()V

    .line 16
    .line 17
    .line 18
    return v0

    .line 19
    :catchall_0
    move-exception v0

    .line 20
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$Editor;->notifyListeners()V

    .line 21
    .line 22
    .line 23
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$Editor;->mKeysChanged:Ljava/util/List;

    .line 24
    .line 25
    invoke-interface {p0}, Ljava/util/List;->clear()V

    .line 26
    .line 27
    .line 28
    throw v0
.end method

.method public putBoolean(Ljava/lang/String;Z)Landroid/content/SharedPreferences$Editor;
    .locals 2

    .line 1
    const/4 v0, 0x5

    .line 2
    invoke-static {v0}, Ljava/nio/ByteBuffer;->allocate(I)Ljava/nio/ByteBuffer;

    .line 3
    .line 4
    .line 5
    move-result-object v0

    .line 6
    sget-object v1, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType;->BOOLEAN:Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType;

    .line 7
    .line 8
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType;->getId()I

    .line 9
    .line 10
    .line 11
    move-result v1

    .line 12
    invoke-virtual {v0, v1}, Ljava/nio/ByteBuffer;->putInt(I)Ljava/nio/ByteBuffer;

    .line 13
    .line 14
    .line 15
    invoke-virtual {v0, p2}, Ljava/nio/ByteBuffer;->put(B)Ljava/nio/ByteBuffer;

    .line 16
    .line 17
    .line 18
    invoke-virtual {v0}, Ljava/nio/ByteBuffer;->array()[B

    .line 19
    .line 20
    .line 21
    move-result-object p2

    .line 22
    const-string v0, "array(...)"

    .line 23
    .line 24
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    invoke-direct {p0, p1, p2}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$Editor;->putEncryptedObject(Ljava/lang/String;[B)V

    .line 28
    .line 29
    .line 30
    return-object p0
.end method

.method public putFloat(Ljava/lang/String;F)Landroid/content/SharedPreferences$Editor;
    .locals 2

    .line 1
    const/16 v0, 0x8

    .line 2
    .line 3
    invoke-static {v0}, Ljava/nio/ByteBuffer;->allocate(I)Ljava/nio/ByteBuffer;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sget-object v1, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType;->FLOAT:Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType;

    .line 8
    .line 9
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType;->getId()I

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    invoke-virtual {v0, v1}, Ljava/nio/ByteBuffer;->putInt(I)Ljava/nio/ByteBuffer;

    .line 14
    .line 15
    .line 16
    invoke-virtual {v0, p2}, Ljava/nio/ByteBuffer;->putFloat(F)Ljava/nio/ByteBuffer;

    .line 17
    .line 18
    .line 19
    invoke-virtual {v0}, Ljava/nio/ByteBuffer;->array()[B

    .line 20
    .line 21
    .line 22
    move-result-object p2

    .line 23
    const-string v0, "array(...)"

    .line 24
    .line 25
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    invoke-direct {p0, p1, p2}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$Editor;->putEncryptedObject(Ljava/lang/String;[B)V

    .line 29
    .line 30
    .line 31
    return-object p0
.end method

.method public putInt(Ljava/lang/String;I)Landroid/content/SharedPreferences$Editor;
    .locals 2

    .line 1
    const/16 v0, 0x8

    .line 2
    .line 3
    invoke-static {v0}, Ljava/nio/ByteBuffer;->allocate(I)Ljava/nio/ByteBuffer;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sget-object v1, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType;->INT:Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType;

    .line 8
    .line 9
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType;->getId()I

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    invoke-virtual {v0, v1}, Ljava/nio/ByteBuffer;->putInt(I)Ljava/nio/ByteBuffer;

    .line 14
    .line 15
    .line 16
    invoke-virtual {v0, p2}, Ljava/nio/ByteBuffer;->putInt(I)Ljava/nio/ByteBuffer;

    .line 17
    .line 18
    .line 19
    invoke-virtual {v0}, Ljava/nio/ByteBuffer;->array()[B

    .line 20
    .line 21
    .line 22
    move-result-object p2

    .line 23
    const-string v0, "array(...)"

    .line 24
    .line 25
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    invoke-direct {p0, p1, p2}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$Editor;->putEncryptedObject(Ljava/lang/String;[B)V

    .line 29
    .line 30
    .line 31
    return-object p0
.end method

.method public putLong(Ljava/lang/String;J)Landroid/content/SharedPreferences$Editor;
    .locals 2

    .line 1
    const/16 v0, 0xc

    .line 2
    .line 3
    invoke-static {v0}, Ljava/nio/ByteBuffer;->allocate(I)Ljava/nio/ByteBuffer;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sget-object v1, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType;->LONG:Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType;

    .line 8
    .line 9
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType;->getId()I

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    invoke-virtual {v0, v1}, Ljava/nio/ByteBuffer;->putInt(I)Ljava/nio/ByteBuffer;

    .line 14
    .line 15
    .line 16
    invoke-virtual {v0, p2, p3}, Ljava/nio/ByteBuffer;->putLong(J)Ljava/nio/ByteBuffer;

    .line 17
    .line 18
    .line 19
    invoke-virtual {v0}, Ljava/nio/ByteBuffer;->array()[B

    .line 20
    .line 21
    .line 22
    move-result-object p2

    .line 23
    const-string p3, "array(...)"

    .line 24
    .line 25
    invoke-static {p2, p3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    invoke-direct {p0, p1, p2}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$Editor;->putEncryptedObject(Ljava/lang/String;[B)V

    .line 29
    .line 30
    .line 31
    return-object p0
.end method

.method public putString(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;
    .locals 2

    .line 1
    if-nez p2, :cond_0

    .line 2
    .line 3
    const-string p2, "__NULL__"

    .line 4
    .line 5
    :cond_0
    sget-object v0, Ljava/nio/charset/StandardCharsets;->UTF_8:Ljava/nio/charset/Charset;

    .line 6
    .line 7
    const-string v1, "UTF_8"

    .line 8
    .line 9
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    invoke-virtual {p2, v0}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    .line 13
    .line 14
    .line 15
    move-result-object p2

    .line 16
    const-string v0, "this as java.lang.String).getBytes(charset)"

    .line 17
    .line 18
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    array-length v0, p2

    .line 22
    add-int/lit8 v0, v0, 0x8

    .line 23
    .line 24
    invoke-static {v0}, Ljava/nio/ByteBuffer;->allocate(I)Ljava/nio/ByteBuffer;

    .line 25
    .line 26
    .line 27
    move-result-object v0

    .line 28
    sget-object v1, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType;->STRING:Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType;

    .line 29
    .line 30
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType;->getId()I

    .line 31
    .line 32
    .line 33
    move-result v1

    .line 34
    invoke-virtual {v0, v1}, Ljava/nio/ByteBuffer;->putInt(I)Ljava/nio/ByteBuffer;

    .line 35
    .line 36
    .line 37
    array-length v1, p2

    .line 38
    invoke-virtual {v0, v1}, Ljava/nio/ByteBuffer;->putInt(I)Ljava/nio/ByteBuffer;

    .line 39
    .line 40
    .line 41
    invoke-virtual {v0, p2}, Ljava/nio/ByteBuffer;->put([B)Ljava/nio/ByteBuffer;

    .line 42
    .line 43
    .line 44
    invoke-virtual {v0}, Ljava/nio/ByteBuffer;->array()[B

    .line 45
    .line 46
    .line 47
    move-result-object p2

    .line 48
    const-string v0, "array(...)"

    .line 49
    .line 50
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    invoke-direct {p0, p1, p2}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$Editor;->putEncryptedObject(Ljava/lang/String;[B)V

    .line 54
    .line 55
    .line 56
    return-object p0
.end method

.method public putStringSet(Ljava/lang/String;Ljava/util/Set;)Landroid/content/SharedPreferences$Editor;
    .locals 5
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Ljava/util/Set<",
            "Ljava/lang/String;",
            ">;)",
            "Landroid/content/SharedPreferences$Editor;"
        }
    .end annotation

    .line 1
    const-string v0, "this as java.lang.String).getBytes(charset)"

    .line 2
    .line 3
    if-eqz p2, :cond_0

    .line 4
    .line 5
    check-cast p2, Ljava/lang/Iterable;

    .line 6
    .line 7
    new-instance v1, Ljava/util/ArrayList;

    .line 8
    .line 9
    const/16 v2, 0xa

    .line 10
    .line 11
    invoke-static {p2, v2}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 12
    .line 13
    .line 14
    move-result v2

    .line 15
    invoke-direct {v1, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 16
    .line 17
    .line 18
    invoke-interface {p2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 19
    .line 20
    .line 21
    move-result-object p2

    .line 22
    :goto_0
    invoke-interface {p2}, Ljava/util/Iterator;->hasNext()Z

    .line 23
    .line 24
    .line 25
    move-result v2

    .line 26
    if-eqz v2, :cond_1

    .line 27
    .line 28
    invoke-interface {p2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object v2

    .line 32
    check-cast v2, Ljava/lang/String;

    .line 33
    .line 34
    sget-object v3, Ljava/nio/charset/StandardCharsets;->UTF_8:Ljava/nio/charset/Charset;

    .line 35
    .line 36
    const-string v4, "UTF_8"

    .line 37
    .line 38
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    invoke-virtual {v2, v3}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    .line 42
    .line 43
    .line 44
    move-result-object v2

    .line 45
    invoke-static {v2, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    invoke-interface {v1, v2}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z

    .line 49
    .line 50
    .line 51
    goto :goto_0

    .line 52
    :cond_0
    const-string p2, "__NULL__"

    .line 53
    .line 54
    sget-object v1, Lly0/a;->a:Ljava/nio/charset/Charset;

    .line 55
    .line 56
    invoke-virtual {p2, v1}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    .line 57
    .line 58
    .line 59
    move-result-object p2

    .line 60
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 61
    .line 62
    .line 63
    invoke-static {p2}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 64
    .line 65
    .line 66
    move-result-object v1

    .line 67
    :cond_1
    move-object p2, v1

    .line 68
    check-cast p2, Ljava/lang/Iterable;

    .line 69
    .line 70
    invoke-interface {p2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 71
    .line 72
    .line 73
    move-result-object v0

    .line 74
    const/4 v2, 0x0

    .line 75
    :goto_1
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 76
    .line 77
    .line 78
    move-result v3

    .line 79
    if-eqz v3, :cond_2

    .line 80
    .line 81
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object v3

    .line 85
    check-cast v3, [B

    .line 86
    .line 87
    array-length v3, v3

    .line 88
    add-int/2addr v2, v3

    .line 89
    goto :goto_1

    .line 90
    :cond_2
    invoke-interface {v1}, Ljava/util/List;->size()I

    .line 91
    .line 92
    .line 93
    move-result v0

    .line 94
    add-int/lit8 v0, v0, 0x1

    .line 95
    .line 96
    mul-int/lit8 v0, v0, 0x4

    .line 97
    .line 98
    add-int/2addr v0, v2

    .line 99
    invoke-static {v0}, Ljava/nio/ByteBuffer;->allocate(I)Ljava/nio/ByteBuffer;

    .line 100
    .line 101
    .line 102
    move-result-object v0

    .line 103
    sget-object v1, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType;->STRING_SET:Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType;

    .line 104
    .line 105
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType;->getId()I

    .line 106
    .line 107
    .line 108
    move-result v1

    .line 109
    invoke-virtual {v0, v1}, Ljava/nio/ByteBuffer;->putInt(I)Ljava/nio/ByteBuffer;

    .line 110
    .line 111
    .line 112
    invoke-interface {p2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 113
    .line 114
    .line 115
    move-result-object p2

    .line 116
    :goto_2
    invoke-interface {p2}, Ljava/util/Iterator;->hasNext()Z

    .line 117
    .line 118
    .line 119
    move-result v1

    .line 120
    if-eqz v1, :cond_3

    .line 121
    .line 122
    invoke-interface {p2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 123
    .line 124
    .line 125
    move-result-object v1

    .line 126
    check-cast v1, [B

    .line 127
    .line 128
    array-length v2, v1

    .line 129
    invoke-virtual {v0, v2}, Ljava/nio/ByteBuffer;->putInt(I)Ljava/nio/ByteBuffer;

    .line 130
    .line 131
    .line 132
    invoke-virtual {v0, v1}, Ljava/nio/ByteBuffer;->put([B)Ljava/nio/ByteBuffer;

    .line 133
    .line 134
    .line 135
    goto :goto_2

    .line 136
    :cond_3
    invoke-virtual {v0}, Ljava/nio/ByteBuffer;->array()[B

    .line 137
    .line 138
    .line 139
    move-result-object p2

    .line 140
    const-string v0, "array(...)"

    .line 141
    .line 142
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 143
    .line 144
    .line 145
    invoke-direct {p0, p1, p2}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$Editor;->putEncryptedObject(Ljava/lang/String;[B)V

    .line 146
    .line 147
    .line 148
    return-object p0
.end method

.method public remove(Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;
    .locals 1

    const/4 v0, 0x1

    .line 1
    invoke-virtual {p0, p1, v0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$Editor;->remove(Ljava/lang/String;Z)Landroid/content/SharedPreferences$Editor;

    move-result-object p0

    return-object p0
.end method

.method public final remove(Ljava/lang/String;Z)Landroid/content/SharedPreferences$Editor;
    .locals 1

    .line 2
    iget-object v0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$Editor;->mEncryptedSharedPreferences:Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences;

    invoke-virtual {v0, p1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences;->isReservedKey(Ljava/lang/String;)Z

    move-result v0

    if-nez v0, :cond_1

    if-eqz p2, :cond_0

    .line 3
    iget-object p2, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$Editor;->mEncryptedSharedPreferences:Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences;

    invoke-static {p2, p1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences;->access$encryptKey(Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p2

    goto :goto_0

    :cond_0
    move-object p2, p1

    .line 4
    :goto_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$Editor;->mEditor:Landroid/content/SharedPreferences$Editor;

    invoke-interface {v0, p2}, Landroid/content/SharedPreferences$Editor;->remove(Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;

    .line 5
    iget-object p2, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$Editor;->mKeysChanged:Ljava/util/List;

    invoke-interface {p2, p1}, Ljava/util/List;->remove(Ljava/lang/Object;)Z

    return-object p0

    .line 6
    :cond_1
    new-instance p0, Ljava/lang/SecurityException;

    const-string p2, " is a reserved key for the encryption keyset."

    .line 7
    invoke-static {p1, p2}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    .line 8
    invoke-direct {p0, p1}, Ljava/lang/SecurityException;-><init>(Ljava/lang/String;)V

    throw p0
.end method
