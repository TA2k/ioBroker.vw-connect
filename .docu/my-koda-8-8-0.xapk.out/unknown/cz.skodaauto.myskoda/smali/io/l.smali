.class public final synthetic Lio/l;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/os/Handler$Callback;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, Lio/l;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lio/l;->e:Ljava/lang/Object;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final handleMessage(Landroid/os/Message;)Z
    .locals 4

    .line 1
    iget v0, p0, Lio/l;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget v0, p1, Landroid/os/Message;->what:I

    .line 7
    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    const/4 p0, 0x0

    .line 11
    return p0

    .line 12
    :cond_0
    iget-object p0, p0, Lio/l;->e:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast p0, Lry0/c;

    .line 15
    .line 16
    iget-object p1, p1, Landroid/os/Message;->obj:Ljava/lang/Object;

    .line 17
    .line 18
    if-nez p1, :cond_1

    .line 19
    .line 20
    iget-object p0, p0, Lry0/c;->a:Ljava/lang/Object;

    .line 21
    .line 22
    monitor-enter p0

    .line 23
    const/4 p1, 0x0

    .line 24
    :try_start_0
    throw p1

    .line 25
    :catchall_0
    move-exception p1

    .line 26
    monitor-exit p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 27
    throw p1

    .line 28
    :cond_1
    new-instance p0, Ljava/lang/ClassCastException;

    .line 29
    .line 30
    invoke-direct {p0}, Ljava/lang/ClassCastException;-><init>()V

    .line 31
    .line 32
    .line 33
    throw p0

    .line 34
    :pswitch_0
    const-string v0, "Received response for unknown request: "

    .line 35
    .line 36
    const-string v1, "MessengerIpcClient"

    .line 37
    .line 38
    iget v2, p1, Landroid/os/Message;->arg1:I

    .line 39
    .line 40
    const/4 v3, 0x3

    .line 41
    invoke-static {v1, v3}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 42
    .line 43
    .line 44
    move-result v1

    .line 45
    if-eqz v1, :cond_2

    .line 46
    .line 47
    new-instance v1, Ljava/lang/StringBuilder;

    .line 48
    .line 49
    const-string v3, "Received response to request: "

    .line 50
    .line 51
    invoke-direct {v1, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 55
    .line 56
    .line 57
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 58
    .line 59
    .line 60
    move-result-object v1

    .line 61
    const-string v3, "MessengerIpcClient"

    .line 62
    .line 63
    invoke-static {v3, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 64
    .line 65
    .line 66
    :cond_2
    iget-object p0, p0, Lio/l;->e:Ljava/lang/Object;

    .line 67
    .line 68
    check-cast p0, Lio/m;

    .line 69
    .line 70
    monitor-enter p0

    .line 71
    :try_start_1
    iget-object v1, p0, Lio/m;->e:Landroid/util/SparseArray;

    .line 72
    .line 73
    invoke-virtual {v1, v2}, Landroid/util/SparseArray;->get(I)Ljava/lang/Object;

    .line 74
    .line 75
    .line 76
    move-result-object v1

    .line 77
    check-cast v1, Lio/n;

    .line 78
    .line 79
    if-nez v1, :cond_3

    .line 80
    .line 81
    const-string p1, "MessengerIpcClient"

    .line 82
    .line 83
    new-instance v1, Ljava/lang/StringBuilder;

    .line 84
    .line 85
    invoke-direct {v1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 86
    .line 87
    .line 88
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 89
    .line 90
    .line 91
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 92
    .line 93
    .line 94
    move-result-object v0

    .line 95
    invoke-static {p1, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 96
    .line 97
    .line 98
    monitor-exit p0

    .line 99
    goto :goto_0

    .line 100
    :catchall_1
    move-exception p1

    .line 101
    goto :goto_1

    .line 102
    :cond_3
    iget-object v0, p0, Lio/m;->e:Landroid/util/SparseArray;

    .line 103
    .line 104
    invoke-virtual {v0, v2}, Landroid/util/SparseArray;->remove(I)V

    .line 105
    .line 106
    .line 107
    invoke-virtual {p0}, Lio/m;->c()V

    .line 108
    .line 109
    .line 110
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 111
    invoke-virtual {p1}, Landroid/os/Message;->getData()Landroid/os/Bundle;

    .line 112
    .line 113
    .line 114
    move-result-object p0

    .line 115
    const-string p1, "unsupported"

    .line 116
    .line 117
    const/4 v0, 0x0

    .line 118
    invoke-virtual {p0, p1, v0}, Landroid/os/BaseBundle;->getBoolean(Ljava/lang/String;Z)Z

    .line 119
    .line 120
    .line 121
    move-result p1

    .line 122
    if-eqz p1, :cond_4

    .line 123
    .line 124
    const-string p0, "Not supported by GmsCore"

    .line 125
    .line 126
    new-instance p1, Lb0/l;

    .line 127
    .line 128
    const/4 v0, 0x0

    .line 129
    invoke-direct {p1, p0, v0}, Ljava/lang/Exception;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 130
    .line 131
    .line 132
    invoke-virtual {v1, p1}, Lio/n;->b(Lb0/l;)V

    .line 133
    .line 134
    .line 135
    goto :goto_0

    .line 136
    :cond_4
    iget p1, v1, Lio/n;->e:I

    .line 137
    .line 138
    packed-switch p1, :pswitch_data_1

    .line 139
    .line 140
    .line 141
    const-string p1, "data"

    .line 142
    .line 143
    invoke-virtual {p0, p1}, Landroid/os/Bundle;->getBundle(Ljava/lang/String;)Landroid/os/Bundle;

    .line 144
    .line 145
    .line 146
    move-result-object p0

    .line 147
    if-nez p0, :cond_5

    .line 148
    .line 149
    sget-object p0, Landroid/os/Bundle;->EMPTY:Landroid/os/Bundle;

    .line 150
    .line 151
    :cond_5
    invoke-virtual {v1, p0}, Lio/n;->c(Landroid/os/Bundle;)V

    .line 152
    .line 153
    .line 154
    goto :goto_0

    .line 155
    :pswitch_1
    const-string p1, "ack"

    .line 156
    .line 157
    const/4 v0, 0x0

    .line 158
    invoke-virtual {p0, p1, v0}, Landroid/os/BaseBundle;->getBoolean(Ljava/lang/String;Z)Z

    .line 159
    .line 160
    .line 161
    move-result p0

    .line 162
    const/4 p1, 0x0

    .line 163
    if-eqz p0, :cond_6

    .line 164
    .line 165
    invoke-virtual {v1, p1}, Lio/n;->c(Landroid/os/Bundle;)V

    .line 166
    .line 167
    .line 168
    goto :goto_0

    .line 169
    :cond_6
    const-string p0, "Invalid response to one way request"

    .line 170
    .line 171
    new-instance v0, Lb0/l;

    .line 172
    .line 173
    invoke-direct {v0, p0, p1}, Ljava/lang/Exception;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 174
    .line 175
    .line 176
    invoke-virtual {v1, v0}, Lio/n;->b(Lb0/l;)V

    .line 177
    .line 178
    .line 179
    :goto_0
    const/4 p0, 0x1

    .line 180
    return p0

    .line 181
    :goto_1
    :try_start_2
    monitor-exit p0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 182
    throw p1

    .line 183
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch

    .line 184
    .line 185
    .line 186
    .line 187
    .line 188
    .line 189
    :pswitch_data_1
    .packed-switch 0x0
        :pswitch_1
    .end packed-switch
.end method
