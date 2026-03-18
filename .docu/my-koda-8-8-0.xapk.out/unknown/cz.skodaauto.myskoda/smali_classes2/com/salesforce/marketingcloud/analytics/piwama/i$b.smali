.class Lcom/salesforce/marketingcloud/analytics/piwama/i$b;
.super Lcom/salesforce/marketingcloud/internal/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/salesforce/marketingcloud/analytics/piwama/i;->a(J)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field final synthetic c:J

.field final synthetic d:Lcom/salesforce/marketingcloud/analytics/piwama/i;


# direct methods
.method public varargs constructor <init>(Lcom/salesforce/marketingcloud/analytics/piwama/i;Ljava/lang/String;[Ljava/lang/Object;J)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/analytics/piwama/i$b;->d:Lcom/salesforce/marketingcloud/analytics/piwama/i;

    .line 2
    .line 3
    iput-wide p4, p0, Lcom/salesforce/marketingcloud/analytics/piwama/i$b;->c:J

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
    .locals 9

    .line 1
    :try_start_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/piwama/i$b;->d:Lcom/salesforce/marketingcloud/analytics/piwama/i;

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
    iget-object v1, p0, Lcom/salesforce/marketingcloud/analytics/piwama/i$b;->d:Lcom/salesforce/marketingcloud/analytics/piwama/i;

    .line 10
    .line 11
    iget-object v1, v1, Lcom/salesforce/marketingcloud/analytics/piwama/i;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 12
    .line 13
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/storage/h;->b()Lcom/salesforce/marketingcloud/util/Crypto;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    invoke-interface {v0, v1}, Lcom/salesforce/marketingcloud/storage/a;->h(Lcom/salesforce/marketingcloud/util/Crypto;)Ljava/util/List;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    invoke-interface {v1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 22
    .line 23
    .line 24
    move-result-object v1

    .line 25
    :cond_0
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 26
    .line 27
    .line 28
    move-result v2

    .line 29
    const/4 v3, 0x1

    .line 30
    if-eqz v2, :cond_1

    .line 31
    .line 32
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object v2

    .line 36
    check-cast v2, Lcom/salesforce/marketingcloud/analytics/b;

    .line 37
    .line 38
    sget-object v4, Ljava/util/concurrent/TimeUnit;->MILLISECONDS:Ljava/util/concurrent/TimeUnit;

    .line 39
    .line 40
    iget-wide v5, p0, Lcom/salesforce/marketingcloud/analytics/piwama/i$b;->c:J

    .line 41
    .line 42
    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/analytics/b;->b()Ljava/util/Date;

    .line 43
    .line 44
    .line 45
    move-result-object v7

    .line 46
    invoke-virtual {v7}, Ljava/util/Date;->getTime()J

    .line 47
    .line 48
    .line 49
    move-result-wide v7

    .line 50
    sub-long/2addr v5, v7

    .line 51
    invoke-virtual {v4, v5, v6}, Ljava/util/concurrent/TimeUnit;->toSeconds(J)J

    .line 52
    .line 53
    .line 54
    move-result-wide v4

    .line 55
    long-to-int v4, v4

    .line 56
    if-lez v4, :cond_0

    .line 57
    .line 58
    invoke-virtual {v2, v4}, Lcom/salesforce/marketingcloud/analytics/b;->b(I)V

    .line 59
    .line 60
    .line 61
    invoke-virtual {v2, v3}, Lcom/salesforce/marketingcloud/analytics/b;->a(Z)V

    .line 62
    .line 63
    .line 64
    iget-object v3, p0, Lcom/salesforce/marketingcloud/analytics/piwama/i$b;->d:Lcom/salesforce/marketingcloud/analytics/piwama/i;

    .line 65
    .line 66
    invoke-virtual {v3}, Lcom/salesforce/marketingcloud/analytics/piwama/i;->a()Ljava/lang/String;

    .line 67
    .line 68
    .line 69
    move-result-object v3

    .line 70
    invoke-virtual {v2, v3}, Lcom/salesforce/marketingcloud/analytics/b;->d(Ljava/lang/String;)V

    .line 71
    .line 72
    .line 73
    iget-object v3, p0, Lcom/salesforce/marketingcloud/analytics/piwama/i$b;->d:Lcom/salesforce/marketingcloud/analytics/piwama/i;

    .line 74
    .line 75
    iget-object v3, v3, Lcom/salesforce/marketingcloud/analytics/piwama/i;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 76
    .line 77
    invoke-virtual {v3}, Lcom/salesforce/marketingcloud/storage/h;->b()Lcom/salesforce/marketingcloud/util/Crypto;

    .line 78
    .line 79
    .line 80
    move-result-object v3

    .line 81
    invoke-interface {v0, v2, v3}, Lcom/salesforce/marketingcloud/storage/a;->b(Lcom/salesforce/marketingcloud/analytics/b;Lcom/salesforce/marketingcloud/util/Crypto;)I

    .line 82
    .line 83
    .line 84
    goto :goto_0

    .line 85
    :cond_1
    new-instance v1, Ljava/util/Date;

    .line 86
    .line 87
    iget-wide v4, p0, Lcom/salesforce/marketingcloud/analytics/piwama/i$b;->c:J

    .line 88
    .line 89
    invoke-direct {v1, v4, v5}, Ljava/util/Date;-><init>(J)V

    .line 90
    .line 91
    .line 92
    const/4 v2, 0x2

    .line 93
    invoke-static {v1, v3, v2}, Lcom/salesforce/marketingcloud/analytics/b;->a(Ljava/util/Date;II)Lcom/salesforce/marketingcloud/analytics/b;

    .line 94
    .line 95
    .line 96
    move-result-object v1

    .line 97
    iget-object v2, p0, Lcom/salesforce/marketingcloud/analytics/piwama/i$b;->d:Lcom/salesforce/marketingcloud/analytics/piwama/i;

    .line 98
    .line 99
    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/analytics/piwama/i;->a()Ljava/lang/String;

    .line 100
    .line 101
    .line 102
    move-result-object v2

    .line 103
    invoke-virtual {v1, v2}, Lcom/salesforce/marketingcloud/analytics/b;->d(Ljava/lang/String;)V

    .line 104
    .line 105
    .line 106
    invoke-virtual {v1, v3}, Lcom/salesforce/marketingcloud/analytics/b;->a(Z)V

    .line 107
    .line 108
    .line 109
    new-instance v2, Lcom/salesforce/marketingcloud/analytics/piwama/b;

    .line 110
    .line 111
    new-instance v3, Ljava/util/Date;

    .line 112
    .line 113
    iget-wide v4, p0, Lcom/salesforce/marketingcloud/analytics/piwama/i$b;->c:J

    .line 114
    .line 115
    invoke-direct {v3, v4, v5}, Ljava/util/Date;-><init>(J)V

    .line 116
    .line 117
    .line 118
    invoke-direct {v2, v3}, Lcom/salesforce/marketingcloud/analytics/piwama/b;-><init>(Ljava/util/Date;)V

    .line 119
    .line 120
    .line 121
    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/analytics/piwama/b;->c()Lorg/json/JSONObject;

    .line 122
    .line 123
    .line 124
    move-result-object v2

    .line 125
    invoke-virtual {v2}, Lorg/json/JSONObject;->toString()Ljava/lang/String;

    .line 126
    .line 127
    .line 128
    move-result-object v2

    .line 129
    invoke-virtual {v1, v2}, Lcom/salesforce/marketingcloud/analytics/b;->c(Ljava/lang/String;)V

    .line 130
    .line 131
    .line 132
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/piwama/i$b;->d:Lcom/salesforce/marketingcloud/analytics/piwama/i;

    .line 133
    .line 134
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/piwama/i;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 135
    .line 136
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/h;->b()Lcom/salesforce/marketingcloud/util/Crypto;

    .line 137
    .line 138
    .line 139
    move-result-object p0

    .line 140
    invoke-interface {v0, v1, p0}, Lcom/salesforce/marketingcloud/storage/a;->a(Lcom/salesforce/marketingcloud/analytics/b;Lcom/salesforce/marketingcloud/util/Crypto;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 141
    .line 142
    .line 143
    return-void

    .line 144
    :catch_0
    move-exception p0

    .line 145
    sget-object v0, Lcom/salesforce/marketingcloud/analytics/piwama/i;->k:Ljava/lang/String;

    .line 146
    .line 147
    const/4 v1, 0x0

    .line 148
    new-array v1, v1, [Ljava/lang/Object;

    .line 149
    .line 150
    const-string v2, "Failed to update our PiWama TimeInApp."

    .line 151
    .line 152
    invoke-static {v0, p0, v2, v1}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 153
    .line 154
    .line 155
    return-void
.end method
