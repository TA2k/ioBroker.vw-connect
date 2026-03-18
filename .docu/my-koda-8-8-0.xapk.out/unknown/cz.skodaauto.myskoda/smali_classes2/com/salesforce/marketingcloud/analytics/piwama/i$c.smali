.class Lcom/salesforce/marketingcloud/analytics/piwama/i$c;
.super Lcom/salesforce/marketingcloud/internal/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/salesforce/marketingcloud/analytics/piwama/i;->a(Lcom/salesforce/marketingcloud/notifications/NotificationMessage;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field final synthetic c:Lcom/salesforce/marketingcloud/notifications/NotificationMessage;

.field final synthetic d:Lcom/salesforce/marketingcloud/analytics/piwama/i;


# direct methods
.method public varargs constructor <init>(Lcom/salesforce/marketingcloud/analytics/piwama/i;Ljava/lang/String;[Ljava/lang/Object;Lcom/salesforce/marketingcloud/notifications/NotificationMessage;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/analytics/piwama/i$c;->d:Lcom/salesforce/marketingcloud/analytics/piwama/i;

    .line 2
    .line 3
    iput-object p4, p0, Lcom/salesforce/marketingcloud/analytics/piwama/i$c;->c:Lcom/salesforce/marketingcloud/notifications/NotificationMessage;

    .line 4
    .line 5
    invoke-direct {p0, p2, p3}, Lcom/salesforce/marketingcloud/internal/i;-><init>(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public a()V
    .locals 5

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/piwama/i$c;->d:Lcom/salesforce/marketingcloud/analytics/piwama/i;

    .line 2
    .line 3
    iget-object v0, v0, Lcom/salesforce/marketingcloud/analytics/piwama/i;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 4
    .line 5
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/storage/h;->h()Lcom/salesforce/marketingcloud/storage/a;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    const/4 v1, 0x1

    .line 10
    invoke-interface {v0, v1}, Lcom/salesforce/marketingcloud/storage/a;->c(I)Z

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    if-eqz v0, :cond_0

    .line 15
    .line 16
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/piwama/i$c;->d:Lcom/salesforce/marketingcloud/analytics/piwama/i;

    .line 17
    .line 18
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 19
    .line 20
    .line 21
    move-result-wide v2

    .line 22
    invoke-virtual {v0, v2, v3}, Lcom/salesforce/marketingcloud/analytics/piwama/i;->a(J)V

    .line 23
    .line 24
    .line 25
    :cond_0
    new-instance v0, Ljava/util/Date;

    .line 26
    .line 27
    invoke-direct {v0}, Ljava/util/Date;-><init>()V

    .line 28
    .line 29
    .line 30
    new-instance v2, Ljava/util/ArrayList;

    .line 31
    .line 32
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 33
    .line 34
    .line 35
    iget-object v3, p0, Lcom/salesforce/marketingcloud/analytics/piwama/i$c;->c:Lcom/salesforce/marketingcloud/notifications/NotificationMessage;

    .line 36
    .line 37
    invoke-virtual {v3}, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->id()Ljava/lang/String;

    .line 38
    .line 39
    .line 40
    move-result-object v3

    .line 41
    invoke-virtual {v2, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 42
    .line 43
    .line 44
    iget-object v3, p0, Lcom/salesforce/marketingcloud/analytics/piwama/i$c;->c:Lcom/salesforce/marketingcloud/notifications/NotificationMessage;

    .line 45
    .line 46
    invoke-virtual {v3}, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->region()Lcom/salesforce/marketingcloud/messages/Region;

    .line 47
    .line 48
    .line 49
    move-result-object v3

    .line 50
    if-eqz v3, :cond_1

    .line 51
    .line 52
    invoke-virtual {v3}, Lcom/salesforce/marketingcloud/messages/Region;->id()Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object v3

    .line 56
    invoke-virtual {v2, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 57
    .line 58
    .line 59
    :cond_1
    const/4 v3, 0x5

    .line 60
    const/4 v4, 0x0

    .line 61
    invoke-static {v0, v1, v3, v2, v4}, Lcom/salesforce/marketingcloud/analytics/b;->a(Ljava/util/Date;IILjava/util/List;Z)Lcom/salesforce/marketingcloud/analytics/b;

    .line 62
    .line 63
    .line 64
    move-result-object v2

    .line 65
    iget-object v3, p0, Lcom/salesforce/marketingcloud/analytics/piwama/i$c;->d:Lcom/salesforce/marketingcloud/analytics/piwama/i;

    .line 66
    .line 67
    invoke-virtual {v3}, Lcom/salesforce/marketingcloud/analytics/piwama/i;->a()Ljava/lang/String;

    .line 68
    .line 69
    .line 70
    move-result-object v3

    .line 71
    invoke-virtual {v2, v3}, Lcom/salesforce/marketingcloud/analytics/b;->d(Ljava/lang/String;)V

    .line 72
    .line 73
    .line 74
    new-instance v3, Lcom/salesforce/marketingcloud/analytics/piwama/e;

    .line 75
    .line 76
    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/analytics/b;->i()Ljava/util/List;

    .line 77
    .line 78
    .line 79
    move-result-object v4

    .line 80
    invoke-direct {v3, v0, v1, v4}, Lcom/salesforce/marketingcloud/analytics/piwama/e;-><init>(Ljava/util/Date;ZLjava/util/List;)V

    .line 81
    .line 82
    .line 83
    invoke-virtual {v3}, Lcom/salesforce/marketingcloud/analytics/piwama/e;->c()Lorg/json/JSONObject;

    .line 84
    .line 85
    .line 86
    move-result-object v0

    .line 87
    invoke-virtual {v0}, Lorg/json/JSONObject;->toString()Ljava/lang/String;

    .line 88
    .line 89
    .line 90
    move-result-object v0

    .line 91
    invoke-virtual {v2, v0}, Lcom/salesforce/marketingcloud/analytics/b;->c(Ljava/lang/String;)V

    .line 92
    .line 93
    .line 94
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/piwama/i$c;->d:Lcom/salesforce/marketingcloud/analytics/piwama/i;

    .line 95
    .line 96
    iget-object v0, v0, Lcom/salesforce/marketingcloud/analytics/piwama/i;->f:Lcom/salesforce/marketingcloud/internal/n;

    .line 97
    .line 98
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/internal/n;->b()Ljava/util/concurrent/ExecutorService;

    .line 99
    .line 100
    .line 101
    move-result-object v0

    .line 102
    new-instance v1, Lcom/salesforce/marketingcloud/analytics/a;

    .line 103
    .line 104
    iget-object v3, p0, Lcom/salesforce/marketingcloud/analytics/piwama/i$c;->d:Lcom/salesforce/marketingcloud/analytics/piwama/i;

    .line 105
    .line 106
    iget-object v3, v3, Lcom/salesforce/marketingcloud/analytics/piwama/i;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 107
    .line 108
    invoke-virtual {v3}, Lcom/salesforce/marketingcloud/storage/h;->h()Lcom/salesforce/marketingcloud/storage/a;

    .line 109
    .line 110
    .line 111
    move-result-object v3

    .line 112
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/piwama/i$c;->d:Lcom/salesforce/marketingcloud/analytics/piwama/i;

    .line 113
    .line 114
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/piwama/i;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 115
    .line 116
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/h;->b()Lcom/salesforce/marketingcloud/util/Crypto;

    .line 117
    .line 118
    .line 119
    move-result-object p0

    .line 120
    invoke-direct {v1, v3, p0, v2}, Lcom/salesforce/marketingcloud/analytics/a;-><init>(Lcom/salesforce/marketingcloud/storage/a;Lcom/salesforce/marketingcloud/util/Crypto;Lcom/salesforce/marketingcloud/analytics/b;)V

    .line 121
    .line 122
    .line 123
    invoke-interface {v0, v1}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    .line 124
    .line 125
    .line 126
    return-void
.end method
