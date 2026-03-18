.class Lcom/salesforce/marketingcloud/registration/e$a$a$a;
.super Lcom/salesforce/marketingcloud/internal/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/salesforce/marketingcloud/registration/e$a$a;->onFinish()V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field final synthetic c:Lcom/salesforce/marketingcloud/registration/e$a$a;


# direct methods
.method public varargs constructor <init>(Lcom/salesforce/marketingcloud/registration/e$a$a;Ljava/lang/String;[Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/registration/e$a$a$a;->c:Lcom/salesforce/marketingcloud/registration/e$a$a;

    .line 2
    .line 3
    invoke-direct {p0, p2, p3}, Lcom/salesforce/marketingcloud/internal/i;-><init>(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public a()V
    .locals 5

    .line 1
    :try_start_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/registration/e$a$a$a;->c:Lcom/salesforce/marketingcloud/registration/e$a$a;

    .line 2
    .line 3
    iget-object v0, v0, Lcom/salesforce/marketingcloud/registration/e$a$a;->a:Lcom/salesforce/marketingcloud/registration/e$a;

    .line 4
    .line 5
    iget-object v0, v0, Lcom/salesforce/marketingcloud/registration/e$a;->b:Lcom/salesforce/marketingcloud/registration/e;

    .line 6
    .line 7
    iget-object v0, v0, Lcom/salesforce/marketingcloud/registration/e;->j:Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;

    .line 8
    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;->getRegistrationId()Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    goto :goto_0

    .line 16
    :cond_0
    const/4 v0, 0x0

    .line 17
    :goto_0
    iget-object v1, p0, Lcom/salesforce/marketingcloud/registration/e$a$a$a;->c:Lcom/salesforce/marketingcloud/registration/e$a$a;

    .line 18
    .line 19
    iget-object v1, v1, Lcom/salesforce/marketingcloud/registration/e$a$a;->a:Lcom/salesforce/marketingcloud/registration/e$a;

    .line 20
    .line 21
    iget-object v1, v1, Lcom/salesforce/marketingcloud/registration/e$a;->b:Lcom/salesforce/marketingcloud/registration/e;

    .line 22
    .line 23
    iget-object v1, v1, Lcom/salesforce/marketingcloud/registration/e;->f:Lcom/salesforce/marketingcloud/storage/h;

    .line 24
    .line 25
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/storage/h;->p()Lcom/salesforce/marketingcloud/storage/k;

    .line 26
    .line 27
    .line 28
    move-result-object v1

    .line 29
    iget-object v2, p0, Lcom/salesforce/marketingcloud/registration/e$a$a$a;->c:Lcom/salesforce/marketingcloud/registration/e$a$a;

    .line 30
    .line 31
    iget-object v2, v2, Lcom/salesforce/marketingcloud/registration/e$a$a;->a:Lcom/salesforce/marketingcloud/registration/e$a;

    .line 32
    .line 33
    iget-object v2, v2, Lcom/salesforce/marketingcloud/registration/e$a;->b:Lcom/salesforce/marketingcloud/registration/e;

    .line 34
    .line 35
    iget-object v2, v2, Lcom/salesforce/marketingcloud/registration/e;->f:Lcom/salesforce/marketingcloud/storage/h;

    .line 36
    .line 37
    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/storage/h;->b()Lcom/salesforce/marketingcloud/util/Crypto;

    .line 38
    .line 39
    .line 40
    move-result-object v2

    .line 41
    invoke-interface {v1, v2}, Lcom/salesforce/marketingcloud/storage/k;->k(Lcom/salesforce/marketingcloud/util/Crypto;)Lcom/salesforce/marketingcloud/registration/Registration;

    .line 42
    .line 43
    .line 44
    move-result-object v1

    .line 45
    iget-object v2, p0, Lcom/salesforce/marketingcloud/registration/e$a$a$a;->c:Lcom/salesforce/marketingcloud/registration/e$a$a;

    .line 46
    .line 47
    iget-object v2, v2, Lcom/salesforce/marketingcloud/registration/e$a$a;->a:Lcom/salesforce/marketingcloud/registration/e$a;

    .line 48
    .line 49
    iget-object v2, v2, Lcom/salesforce/marketingcloud/registration/e$a;->b:Lcom/salesforce/marketingcloud/registration/e;

    .line 50
    .line 51
    iget-object v3, v2, Lcom/salesforce/marketingcloud/registration/e;->f:Lcom/salesforce/marketingcloud/storage/h;

    .line 52
    .line 53
    iget-object v2, v2, Lcom/salesforce/marketingcloud/registration/e;->e:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    .line 54
    .line 55
    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->delayRegistrationUntilContactKeyIsSet()Z

    .line 56
    .line 57
    .line 58
    move-result v2

    .line 59
    invoke-static {v1, v3, v2}, Lcom/salesforce/marketingcloud/registration/e;->a(Lcom/salesforce/marketingcloud/registration/Registration;Lcom/salesforce/marketingcloud/storage/h;Z)Z

    .line 60
    .line 61
    .line 62
    move-result v2

    .line 63
    if-eqz v2, :cond_1

    .line 64
    .line 65
    iget-object v2, p0, Lcom/salesforce/marketingcloud/registration/e$a$a$a;->c:Lcom/salesforce/marketingcloud/registration/e$a$a;

    .line 66
    .line 67
    iget-object v2, v2, Lcom/salesforce/marketingcloud/registration/e$a$a;->a:Lcom/salesforce/marketingcloud/registration/e$a;

    .line 68
    .line 69
    iget-object v2, v2, Lcom/salesforce/marketingcloud/registration/e$a;->b:Lcom/salesforce/marketingcloud/registration/e;

    .line 70
    .line 71
    iget-object v2, v2, Lcom/salesforce/marketingcloud/registration/e;->g:Lcom/salesforce/marketingcloud/alarms/b;

    .line 72
    .line 73
    sget-object v3, Lcom/salesforce/marketingcloud/alarms/a$a;->c:Lcom/salesforce/marketingcloud/alarms/a$a;

    .line 74
    .line 75
    filled-new-array {v3}, [Lcom/salesforce/marketingcloud/alarms/a$a;

    .line 76
    .line 77
    .line 78
    move-result-object v3

    .line 79
    invoke-virtual {v2, v3}, Lcom/salesforce/marketingcloud/alarms/b;->d([Lcom/salesforce/marketingcloud/alarms/a$a;)V

    .line 80
    .line 81
    .line 82
    iget-object p0, p0, Lcom/salesforce/marketingcloud/registration/e$a$a$a;->c:Lcom/salesforce/marketingcloud/registration/e$a$a;

    .line 83
    .line 84
    iget-object p0, p0, Lcom/salesforce/marketingcloud/registration/e$a$a;->a:Lcom/salesforce/marketingcloud/registration/e$a;

    .line 85
    .line 86
    iget-object p0, p0, Lcom/salesforce/marketingcloud/registration/e$a;->b:Lcom/salesforce/marketingcloud/registration/e;

    .line 87
    .line 88
    iget-object v2, p0, Lcom/salesforce/marketingcloud/registration/e;->h:Lcom/salesforce/marketingcloud/http/e;

    .line 89
    .line 90
    sget-object v3, Lcom/salesforce/marketingcloud/http/b;->p:Lcom/salesforce/marketingcloud/http/b;

    .line 91
    .line 92
    iget-object v4, p0, Lcom/salesforce/marketingcloud/registration/e;->e:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    .line 93
    .line 94
    iget-object p0, p0, Lcom/salesforce/marketingcloud/registration/e;->f:Lcom/salesforce/marketingcloud/storage/h;

    .line 95
    .line 96
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/h;->c()Lcom/salesforce/marketingcloud/storage/b;

    .line 97
    .line 98
    .line 99
    move-result-object p0

    .line 100
    invoke-static {v1, v0}, Lcom/salesforce/marketingcloud/registration/d;->a(Lcom/salesforce/marketingcloud/registration/Registration;Ljava/lang/String;)Ljava/lang/String;

    .line 101
    .line 102
    .line 103
    move-result-object v0

    .line 104
    invoke-virtual {v3, v4, p0, v0}, Lcom/salesforce/marketingcloud/http/b;->a(Lcom/salesforce/marketingcloud/MarketingCloudConfig;Lcom/salesforce/marketingcloud/storage/b;Ljava/lang/String;)Lcom/salesforce/marketingcloud/http/c;

    .line 105
    .line 106
    .line 107
    move-result-object p0

    .line 108
    invoke-virtual {v2, p0}, Lcom/salesforce/marketingcloud/http/e;->a(Lcom/salesforce/marketingcloud/http/c;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 109
    .line 110
    .line 111
    :cond_1
    return-void

    .line 112
    :catch_0
    move-exception p0

    .line 113
    sget-object v0, Lcom/salesforce/marketingcloud/registration/RegistrationManager;->a:Ljava/lang/String;

    .line 114
    .line 115
    const/4 v1, 0x0

    .line 116
    new-array v1, v1, [Ljava/lang/Object;

    .line 117
    .line 118
    const-string v2, "Failed to get our Registration from local storage."

    .line 119
    .line 120
    invoke-static {v0, p0, v2, v1}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 121
    .line 122
    .line 123
    return-void
.end method
