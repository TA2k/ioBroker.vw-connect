.class public Lcom/salesforce/marketingcloud/registration/a;
.super Lcom/salesforce/marketingcloud/internal/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field private final c:Lcom/salesforce/marketingcloud/storage/k;

.field private final d:Lcom/salesforce/marketingcloud/util/Crypto;

.field private final e:Lcom/salesforce/marketingcloud/registration/Registration;

.field private final f:Z


# direct methods
.method public constructor <init>(Lcom/salesforce/marketingcloud/storage/k;Lcom/salesforce/marketingcloud/util/Crypto;Lcom/salesforce/marketingcloud/registration/Registration;Z)V
    .locals 2

    .line 1
    if-eqz p4, :cond_0

    .line 2
    .line 3
    const-string v0, "update_registration"

    .line 4
    .line 5
    goto :goto_0

    .line 6
    :cond_0
    const-string v0, "add_registration"

    .line 7
    .line 8
    :goto_0
    const/4 v1, 0x0

    .line 9
    new-array v1, v1, [Ljava/lang/Object;

    .line 10
    .line 11
    invoke-direct {p0, v0, v1}, Lcom/salesforce/marketingcloud/internal/i;-><init>(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 12
    .line 13
    .line 14
    iput-object p1, p0, Lcom/salesforce/marketingcloud/registration/a;->c:Lcom/salesforce/marketingcloud/storage/k;

    .line 15
    .line 16
    iput-object p2, p0, Lcom/salesforce/marketingcloud/registration/a;->d:Lcom/salesforce/marketingcloud/util/Crypto;

    .line 17
    .line 18
    iput-object p3, p0, Lcom/salesforce/marketingcloud/registration/a;->e:Lcom/salesforce/marketingcloud/registration/Registration;

    .line 19
    .line 20
    iput-boolean p4, p0, Lcom/salesforce/marketingcloud/registration/a;->f:Z

    .line 21
    .line 22
    return-void
.end method


# virtual methods
.method public a()V
    .locals 3

    .line 1
    :try_start_0
    iget-boolean v0, p0, Lcom/salesforce/marketingcloud/registration/a;->f:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-object v0, p0, Lcom/salesforce/marketingcloud/registration/a;->c:Lcom/salesforce/marketingcloud/storage/k;

    .line 6
    .line 7
    iget-object v1, p0, Lcom/salesforce/marketingcloud/registration/a;->e:Lcom/salesforce/marketingcloud/registration/Registration;

    .line 8
    .line 9
    iget-object v2, p0, Lcom/salesforce/marketingcloud/registration/a;->d:Lcom/salesforce/marketingcloud/util/Crypto;

    .line 10
    .line 11
    invoke-interface {v0, v1, v2}, Lcom/salesforce/marketingcloud/storage/k;->b(Lcom/salesforce/marketingcloud/registration/Registration;Lcom/salesforce/marketingcloud/util/Crypto;)I

    .line 12
    .line 13
    .line 14
    return-void

    .line 15
    :catch_0
    move-exception v0

    .line 16
    goto :goto_0

    .line 17
    :cond_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/registration/a;->c:Lcom/salesforce/marketingcloud/storage/k;

    .line 18
    .line 19
    iget-object v1, p0, Lcom/salesforce/marketingcloud/registration/a;->e:Lcom/salesforce/marketingcloud/registration/Registration;

    .line 20
    .line 21
    iget-object v2, p0, Lcom/salesforce/marketingcloud/registration/a;->d:Lcom/salesforce/marketingcloud/util/Crypto;

    .line 22
    .line 23
    invoke-interface {v0, v1, v2}, Lcom/salesforce/marketingcloud/storage/k;->a(Lcom/salesforce/marketingcloud/registration/Registration;Lcom/salesforce/marketingcloud/util/Crypto;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 24
    .line 25
    .line 26
    return-void

    .line 27
    :goto_0
    sget-object v1, Lcom/salesforce/marketingcloud/registration/RegistrationManager;->a:Ljava/lang/String;

    .line 28
    .line 29
    iget-boolean p0, p0, Lcom/salesforce/marketingcloud/registration/a;->f:Z

    .line 30
    .line 31
    if-eqz p0, :cond_1

    .line 32
    .line 33
    const-string p0, "update"

    .line 34
    .line 35
    goto :goto_1

    .line 36
    :cond_1
    const-string p0, "add"

    .line 37
    .line 38
    :goto_1
    filled-new-array {p0}, [Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    const-string v2, "Unable to %s registration"

    .line 43
    .line 44
    invoke-static {v1, v0, v2, p0}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    return-void
.end method
