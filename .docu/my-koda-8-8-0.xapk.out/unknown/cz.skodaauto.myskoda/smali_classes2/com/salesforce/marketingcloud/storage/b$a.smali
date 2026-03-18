.class public Lcom/salesforce/marketingcloud/storage/b$a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/salesforce/marketingcloud/storage/b;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/storage/b;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "a"
.end annotation


# static fields
.field public static final p:Ljava/lang/String; = "true"


# instance fields
.field private final m:Landroid/content/SharedPreferences;

.field private final n:Lcom/salesforce/marketingcloud/util/Crypto;

.field private final o:Lcom/salesforce/marketingcloud/util/Crypto;


# direct methods
.method public constructor <init>(Landroid/content/Context;Lcom/salesforce/marketingcloud/util/Crypto;Ljava/lang/String;)V
    .locals 1

    const/4 v0, 0x0

    .line 1
    invoke-direct {p0, p1, p2, p3, v0}, Lcom/salesforce/marketingcloud/storage/b$a;-><init>(Landroid/content/Context;Lcom/salesforce/marketingcloud/util/Crypto;Ljava/lang/String;Lcom/salesforce/marketingcloud/util/Crypto;)V

    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Lcom/salesforce/marketingcloud/util/Crypto;Ljava/lang/String;Lcom/salesforce/marketingcloud/util/Crypto;)V
    .locals 6

    const/4 v5, 0x0

    move-object v0, p0

    move-object v1, p1

    move-object v2, p2

    move-object v3, p3

    move-object v4, p4

    .line 2
    invoke-direct/range {v0 .. v5}, Lcom/salesforce/marketingcloud/storage/b$a;-><init>(Landroid/content/Context;Lcom/salesforce/marketingcloud/util/Crypto;Ljava/lang/String;Lcom/salesforce/marketingcloud/util/Crypto;Z)V

    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Lcom/salesforce/marketingcloud/util/Crypto;Ljava/lang/String;Lcom/salesforce/marketingcloud/util/Crypto;Z)V
    .locals 1

    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    invoke-static {p3}, Lcom/salesforce/marketingcloud/storage/b$a;->b(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p3

    const/4 v0, 0x0

    invoke-virtual {p1, p3, v0}, Landroid/content/Context;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;

    move-result-object p1

    iput-object p1, p0, Lcom/salesforce/marketingcloud/storage/b$a;->m:Landroid/content/SharedPreferences;

    if-eqz p5, :cond_0

    .line 5
    sget-object p1, Lcom/salesforce/marketingcloud/storage/l;->f:Ljava/lang/String;

    new-array p3, v0, [Ljava/lang/Object;

    const-string v0, "SFMC New Installation or Encryption Change detected. Resetting the SDK data."

    invoke-static {p1, v0, p3}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 6
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/b$a;->a()V

    .line 7
    :cond_0
    iput-object p2, p0, Lcom/salesforce/marketingcloud/storage/b$a;->n:Lcom/salesforce/marketingcloud/util/Crypto;

    .line 8
    iput-object p4, p0, Lcom/salesforce/marketingcloud/storage/b$a;->o:Lcom/salesforce/marketingcloud/util/Crypto;

    .line 9
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/storage/b$a;->b()V

    .line 10
    invoke-direct {p0, p5}, Lcom/salesforce/marketingcloud/storage/b$a;->a(Z)V

    return-void
.end method

.method private a(Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/util/Crypto;)Ljava/lang/String;
    .locals 2

    .line 12
    iget-object p0, p0, Lcom/salesforce/marketingcloud/storage/b$a;->m:Landroid/content/SharedPreferences;

    const/4 v0, 0x0

    invoke-interface {p0, p1, v0}, Landroid/content/SharedPreferences;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    if-eqz p0, :cond_0

    .line 13
    :try_start_0
    invoke-interface {p3, p0}, Lcom/salesforce/marketingcloud/util/Crypto;->decString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_0

    :catch_0
    move-exception p0

    .line 14
    sget-object p3, Lcom/salesforce/marketingcloud/storage/l;->f:Ljava/lang/String;

    filled-new-array {p1}, [Ljava/lang/Object;

    move-result-object p1

    const-string v1, "Failed to encrypt %s"

    invoke-static {p3, p0, v1, p1}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    :cond_0
    :goto_0
    if-nez v0, :cond_1

    goto :goto_1

    :cond_1
    move-object p2, v0

    :goto_1
    return-object p2
.end method

.method private a(Z)V
    .locals 6

    const-string v0, "true"

    const-string v1, "data_migration_complete"

    const/4 v2, 0x0

    if-eqz p1, :cond_0

    .line 15
    sget-object p1, Lcom/salesforce/marketingcloud/storage/l;->f:Ljava/lang/String;

    new-array v2, v2, [Ljava/lang/Object;

    const-string v3, "migration not needed skipping ..."

    invoke-static {p1, v3, v2}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 16
    invoke-virtual {p0, v1, v0}, Lcom/salesforce/marketingcloud/storage/b$a;->a(Ljava/lang/String;Ljava/lang/String;)V

    return-void

    .line 17
    :cond_0
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/storage/b$a;->c()Z

    move-result p1

    if-eqz p1, :cond_1

    .line 18
    iget-object v3, p0, Lcom/salesforce/marketingcloud/storage/b$a;->o:Lcom/salesforce/marketingcloud/util/Crypto;

    if-nez v3, :cond_1

    .line 19
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/b$a;->a()V

    return-void

    :cond_1
    if-eqz p1, :cond_5

    .line 20
    iget-object p1, p0, Lcom/salesforce/marketingcloud/storage/b$a;->o:Lcom/salesforce/marketingcloud/util/Crypto;

    if-nez p1, :cond_2

    goto :goto_2

    .line 21
    :cond_2
    :try_start_0
    iget-object p1, p0, Lcom/salesforce/marketingcloud/storage/b$a;->m:Landroid/content/SharedPreferences;

    invoke-interface {p1}, Landroid/content/SharedPreferences;->getAll()Ljava/util/Map;

    move-result-object p1

    invoke-interface {p1}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    move-result-object p1

    invoke-interface {p1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_4

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Ljava/util/Map$Entry;

    .line 22
    invoke-interface {v3}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Ljava/lang/String;

    .line 23
    iget-object v4, p0, Lcom/salesforce/marketingcloud/storage/b$a;->o:Lcom/salesforce/marketingcloud/util/Crypto;

    const/4 v5, 0x0

    invoke-direct {p0, v3, v5, v4}, Lcom/salesforce/marketingcloud/storage/b$a;->a(Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/util/Crypto;)Ljava/lang/String;

    move-result-object v4

    if-nez v4, :cond_3

    goto :goto_0

    .line 24
    :cond_3
    invoke-virtual {p0, v3, v4}, Lcom/salesforce/marketingcloud/storage/b$a;->a(Ljava/lang/String;Ljava/lang/String;)V

    goto :goto_0

    :catch_0
    move-exception p1

    goto :goto_1

    .line 25
    :cond_4
    invoke-virtual {p0, v1, v0}, Lcom/salesforce/marketingcloud/storage/b$a;->a(Ljava/lang/String;Ljava/lang/String;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return-void

    .line 26
    :goto_1
    sget-object v0, Lcom/salesforce/marketingcloud/storage/l;->f:Ljava/lang/String;

    new-array v1, v2, [Ljava/lang/Object;

    const-string v2, "Unable to migrate preferences. Starting fresh ..."

    invoke-static {v0, p1, v2, v1}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 27
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/b$a;->a()V

    :cond_5
    :goto_2
    return-void
.end method

.method public static b(Ljava/lang/String;)Ljava/lang/String;
    .locals 1

    .line 1
    sget-object v0, Ljava/util/Locale;->ENGLISH:Ljava/util/Locale;

    const-string v0, "mcsdk_custprefs_"

    .line 2
    invoke-static {v0, p0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

.method private b()V
    .locals 2

    .line 7
    iget-object v0, p0, Lcom/salesforce/marketingcloud/storage/b$a;->m:Landroid/content/SharedPreferences;

    const-string v1, "gcm_sender_id"

    invoke-interface {v0, v1}, Landroid/content/SharedPreferences;->contains(Ljava/lang/String;)Z

    move-result v0

    if-eqz v0, :cond_0

    .line 8
    iget-object p0, p0, Lcom/salesforce/marketingcloud/storage/b$a;->m:Landroid/content/SharedPreferences;

    invoke-interface {p0}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    move-result-object p0

    invoke-interface {p0, v1}, Landroid/content/SharedPreferences$Editor;->remove(Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;

    move-result-object p0

    invoke-interface {p0}, Landroid/content/SharedPreferences$Editor;->apply()V

    :cond_0
    return-void
.end method

.method private c(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/storage/b$a;->n:Lcom/salesforce/marketingcloud/util/Crypto;

    invoke-direct {p0, p1, p2, v0}, Lcom/salesforce/marketingcloud/storage/b$a;->a(Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/util/Crypto;)Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

.method private c()Z
    .locals 1

    .line 2
    iget-object p0, p0, Lcom/salesforce/marketingcloud/storage/b$a;->m:Landroid/content/SharedPreferences;

    const-string v0, "data_migration_complete"

    invoke-interface {p0, v0}, Landroid/content/SharedPreferences;->contains(Ljava/lang/String;)Z

    move-result p0

    xor-int/lit8 p0, p0, 0x1

    return p0
.end method

.method private d(Ljava/lang/String;Ljava/lang/String;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/storage/b$a;->m:Landroid/content/SharedPreferences;

    .line 2
    .line 3
    invoke-interface {v0}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    iget-object p0, p0, Lcom/salesforce/marketingcloud/storage/b$a;->n:Lcom/salesforce/marketingcloud/util/Crypto;

    .line 8
    .line 9
    invoke-interface {p0, p2}, Lcom/salesforce/marketingcloud/util/Crypto;->encString(Ljava/lang/String;)Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    invoke-interface {v0, p1, p0}, Landroid/content/SharedPreferences$Editor;->putString(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    invoke-interface {p0}, Landroid/content/SharedPreferences$Editor;->apply()V

    .line 18
    .line 19
    .line 20
    return-void
.end method


# virtual methods
.method public final a()V
    .locals 0

    .line 11
    iget-object p0, p0, Lcom/salesforce/marketingcloud/storage/b$a;->m:Landroid/content/SharedPreferences;

    invoke-interface {p0}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    move-result-object p0

    invoke-interface {p0}, Landroid/content/SharedPreferences$Editor;->clear()Landroid/content/SharedPreferences$Editor;

    move-result-object p0

    invoke-interface {p0}, Landroid/content/SharedPreferences$Editor;->apply()V

    return-void
.end method

.method public final a(Ljava/lang/String;)V
    .locals 0

    .line 10
    iget-object p0, p0, Lcom/salesforce/marketingcloud/storage/b$a;->m:Landroid/content/SharedPreferences;

    invoke-interface {p0}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    move-result-object p0

    invoke-interface {p0, p1}, Landroid/content/SharedPreferences$Editor;->remove(Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;

    move-result-object p0

    invoke-interface {p0}, Landroid/content/SharedPreferences$Editor;->apply()V

    return-void
.end method

.method public final a(Ljava/lang/String;Ljava/lang/String;)V
    .locals 2

    .line 1
    :try_start_0
    invoke-direct {p0, p1, p2}, Lcom/salesforce/marketingcloud/storage/b$a;->d(Ljava/lang/String;Ljava/lang/String;)V
    :try_end_0
    .catch Ljava/security/GeneralSecurityException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/io/UnsupportedEncodingException; {:try_start_0 .. :try_end_0} :catch_0

    return-void

    :catch_0
    move-exception p0

    .line 2
    sget-object p2, Lcom/salesforce/marketingcloud/storage/l;->f:Ljava/lang/String;

    sget-object v0, Ljava/util/Locale;->ENGLISH:Ljava/util/Locale;

    const-string v0, "Value for key "

    const-string v1, " not stored."

    .line 3
    invoke-static {v0, p1, v1}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    .line 4
    filled-new-array {p0}, [Ljava/lang/Object;

    move-result-object p0

    invoke-static {p2, p1, p0}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void
.end method

.method public final b(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;
    .locals 0

    .line 9
    invoke-direct {p0, p1, p2}, Lcom/salesforce/marketingcloud/storage/b$a;->c(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method
