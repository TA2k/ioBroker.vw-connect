.class Lcom/salesforce/marketingcloud/messages/iam/m$d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/salesforce/marketingcloud/messages/iam/m;->d(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field final synthetic b:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;

.field final synthetic c:Lcom/salesforce/marketingcloud/messages/iam/m;


# direct methods
.method public constructor <init>(Lcom/salesforce/marketingcloud/messages/iam/m;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()V"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/iam/m$d;->c:Lcom/salesforce/marketingcloud/messages/iam/m;

    .line 2
    .line 3
    iput-object p2, p0, Lcom/salesforce/marketingcloud/messages/iam/m$d;->b:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public run()V
    .locals 6

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/m$d;->c:Lcom/salesforce/marketingcloud/messages/iam/m;

    .line 2
    .line 3
    iget-object v0, v0, Lcom/salesforce/marketingcloud/messages/iam/m;->g:Ljava/lang/Object;

    .line 4
    .line 5
    monitor-enter v0

    .line 6
    :try_start_0
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/iam/m$d;->c:Lcom/salesforce/marketingcloud/messages/iam/m;

    .line 7
    .line 8
    iget-object v1, v1, Lcom/salesforce/marketingcloud/messages/iam/m;->p:Lcom/salesforce/marketingcloud/messages/iam/InAppMessageManager$EventListener;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 9
    .line 10
    const/4 v2, 0x0

    .line 11
    if-eqz v1, :cond_0

    .line 12
    .line 13
    :try_start_1
    iget-object v3, p0, Lcom/salesforce/marketingcloud/messages/iam/m$d;->b:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;

    .line 14
    .line 15
    invoke-interface {v1, v3}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessageManager$EventListener;->shouldShowMessage(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;)Z

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    if-nez v1, :cond_0

    .line 20
    .line 21
    sget-object v1, Lcom/salesforce/marketingcloud/messages/iam/m;->v:Ljava/lang/String;

    .line 22
    .line 23
    const-string v3, "InAppMessage EventListener[%s] returned false for shouldShowMessage [%s]"

    .line 24
    .line 25
    iget-object v4, p0, Lcom/salesforce/marketingcloud/messages/iam/m$d;->c:Lcom/salesforce/marketingcloud/messages/iam/m;

    .line 26
    .line 27
    iget-object v4, v4, Lcom/salesforce/marketingcloud/messages/iam/m;->p:Lcom/salesforce/marketingcloud/messages/iam/InAppMessageManager$EventListener;

    .line 28
    .line 29
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 30
    .line 31
    .line 32
    move-result-object v4

    .line 33
    invoke-virtual {v4}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object v4

    .line 37
    iget-object v5, p0, Lcom/salesforce/marketingcloud/messages/iam/m$d;->b:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;

    .line 38
    .line 39
    invoke-virtual {v5}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->id()Ljava/lang/String;

    .line 40
    .line 41
    .line 42
    move-result-object v5

    .line 43
    filled-new-array {v4, v5}, [Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object v4

    .line 47
    invoke-static {v1, v3, v4}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 48
    .line 49
    .line 50
    :try_start_2
    monitor-exit v0

    .line 51
    return-void

    .line 52
    :catchall_0
    move-exception p0

    .line 53
    goto :goto_2

    .line 54
    :catch_0
    move-exception v1

    .line 55
    sget-object v3, Lcom/salesforce/marketingcloud/messages/iam/m;->v:Ljava/lang/String;

    .line 56
    .line 57
    const-string v4, "InAppMessage EventListener threw exception during shouldShowMessage"

    .line 58
    .line 59
    new-array v5, v2, [Ljava/lang/Object;

    .line 60
    .line 61
    invoke-static {v3, v1, v4, v5}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 62
    .line 63
    .line 64
    :cond_0
    monitor-exit v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 65
    :try_start_3
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/m$d;->c:Lcom/salesforce/marketingcloud/messages/iam/m;

    .line 66
    .line 67
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/iam/m$d;->b:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;

    .line 68
    .line 69
    invoke-virtual {v0, v1}, Lcom/salesforce/marketingcloud/messages/iam/m;->a(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;)Ljava/lang/Class;

    .line 70
    .line 71
    .line 72
    move-result-object v0

    .line 73
    if-eqz v0, :cond_1

    .line 74
    .line 75
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/iam/m$d;->c:Lcom/salesforce/marketingcloud/messages/iam/m;

    .line 76
    .line 77
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/iam/m$d;->b:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;

    .line 78
    .line 79
    iget-object v3, v1, Lcom/salesforce/marketingcloud/messages/iam/m;->d:Landroid/content/Context;

    .line 80
    .line 81
    invoke-virtual {v1, v0, v2, v3}, Lcom/salesforce/marketingcloud/messages/iam/m;->a(Ljava/lang/Class;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;Landroid/content/Context;)Z

    .line 82
    .line 83
    .line 84
    move-result v1

    .line 85
    if-eqz v1, :cond_2

    .line 86
    .line 87
    new-instance v1, Landroid/content/Intent;

    .line 88
    .line 89
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/iam/m$d;->c:Lcom/salesforce/marketingcloud/messages/iam/m;

    .line 90
    .line 91
    iget-object v2, v2, Lcom/salesforce/marketingcloud/messages/iam/m;->d:Landroid/content/Context;

    .line 92
    .line 93
    invoke-direct {v1, v2, v0}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

    .line 94
    .line 95
    .line 96
    const/high16 v0, 0x10810000

    .line 97
    .line 98
    invoke-virtual {v1, v0}, Landroid/content/Intent;->setFlags(I)Landroid/content/Intent;

    .line 99
    .line 100
    .line 101
    move-result-object v0

    .line 102
    const-string v1, "messageHandler"

    .line 103
    .line 104
    new-instance v2, Lcom/salesforce/marketingcloud/messages/iam/k;

    .line 105
    .line 106
    iget-object v3, p0, Lcom/salesforce/marketingcloud/messages/iam/m$d;->b:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;

    .line 107
    .line 108
    invoke-direct {v2, v3}, Lcom/salesforce/marketingcloud/messages/iam/k;-><init>(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;)V

    .line 109
    .line 110
    .line 111
    invoke-virtual {v0, v1, v2}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Landroid/os/Parcelable;)Landroid/content/Intent;

    .line 112
    .line 113
    .line 114
    move-result-object v0

    .line 115
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/iam/m$d;->c:Lcom/salesforce/marketingcloud/messages/iam/m;

    .line 116
    .line 117
    iget-object v1, v1, Lcom/salesforce/marketingcloud/messages/iam/m;->d:Landroid/content/Context;

    .line 118
    .line 119
    invoke-virtual {v1, v0}, Landroid/content/Context;->startActivity(Landroid/content/Intent;)V

    .line 120
    .line 121
    .line 122
    goto :goto_1

    .line 123
    :catch_1
    move-exception v0

    .line 124
    goto :goto_0

    .line 125
    :cond_1
    sget-object v0, Lcom/salesforce/marketingcloud/messages/iam/m;->v:Ljava/lang/String;

    .line 126
    .line 127
    const-string v1, "Not supported"

    .line 128
    .line 129
    new-array v2, v2, [Ljava/lang/Object;

    .line 130
    .line 131
    invoke-static {v0, v1, v2}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V
    :try_end_3
    .catch Ljava/lang/Exception; {:try_start_3 .. :try_end_3} :catch_1

    .line 132
    .line 133
    .line 134
    goto :goto_1

    .line 135
    :goto_0
    sget-object v1, Lcom/salesforce/marketingcloud/messages/iam/m;->v:Ljava/lang/String;

    .line 136
    .line 137
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/m$d;->b:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;

    .line 138
    .line 139
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->id()Ljava/lang/String;

    .line 140
    .line 141
    .line 142
    move-result-object p0

    .line 143
    filled-new-array {p0}, [Ljava/lang/Object;

    .line 144
    .line 145
    .line 146
    move-result-object p0

    .line 147
    const-string v2, "Failed to display InAppMessage [%s]"

    .line 148
    .line 149
    invoke-static {v1, v0, v2, p0}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 150
    .line 151
    .line 152
    :cond_2
    :goto_1
    return-void

    .line 153
    :goto_2
    :try_start_4
    monitor-exit v0
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 154
    throw p0
.end method
