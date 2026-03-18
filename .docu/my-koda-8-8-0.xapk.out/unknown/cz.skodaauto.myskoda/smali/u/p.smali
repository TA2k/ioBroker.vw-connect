.class public final synthetic Lu/p;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ly4/i;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lu/y;


# direct methods
.method public synthetic constructor <init>(Lu/y;I)V
    .locals 0

    .line 1
    iput p2, p0, Lu/p;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lu/p;->e:Lu/y;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public h(Ly4/h;)Ljava/lang/Object;
    .locals 4

    .line 1
    iget v0, p0, Lu/p;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    :pswitch_0
    iget-object p0, p0, Lu/p;->e:Lu/y;

    .line 7
    .line 8
    iget-object v0, p0, Lu/y;->f:Lj0/h;

    .line 9
    .line 10
    new-instance v1, Lu/q;

    .line 11
    .line 12
    const/4 v2, 0x0

    .line 13
    invoke-direct {v1, p0, p1, v2}, Lu/q;-><init>(Lu/y;Ly4/h;I)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {v0, v1}, Lj0/h;->execute(Ljava/lang/Runnable;)V

    .line 17
    .line 18
    .line 19
    new-instance p1, Ljava/lang/StringBuilder;

    .line 20
    .line 21
    const-string v0, "Release[request="

    .line 22
    .line 23
    invoke-direct {p1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    iget-object p0, p0, Lu/y;->p:Ljava/util/concurrent/atomic/AtomicInteger;

    .line 27
    .line 28
    invoke-virtual {p0}, Ljava/util/concurrent/atomic/AtomicInteger;->getAndIncrement()I

    .line 29
    .line 30
    .line 31
    move-result p0

    .line 32
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    const-string p0, "]"

    .line 36
    .line 37
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 38
    .line 39
    .line 40
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    return-object p0

    .line 45
    :pswitch_1
    iget-object p0, p0, Lu/p;->e:Lu/y;

    .line 46
    .line 47
    :try_start_0
    iget-object v0, p0, Lu/y;->f:Lj0/h;

    .line 48
    .line 49
    new-instance v1, Lu/q;

    .line 50
    .line 51
    const/4 v2, 0x1

    .line 52
    invoke-direct {v1, p0, p1, v2}, Lu/q;-><init>(Lu/y;Ly4/h;I)V

    .line 53
    .line 54
    .line 55
    invoke-virtual {v0, v1}, Lj0/h;->execute(Ljava/lang/Runnable;)V
    :try_end_0
    .catch Ljava/util/concurrent/RejectedExecutionException; {:try_start_0 .. :try_end_0} :catch_0

    .line 56
    .line 57
    .line 58
    goto :goto_0

    .line 59
    :catch_0
    new-instance p0, Ljava/lang/RuntimeException;

    .line 60
    .line 61
    const-string v0, "Unable to check if MeteringRepeating is attached. Camera executor shut down."

    .line 62
    .line 63
    invoke-direct {p0, v0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 64
    .line 65
    .line 66
    invoke-virtual {p1, p0}, Ly4/h;->d(Ljava/lang/Throwable;)Z

    .line 67
    .line 68
    .line 69
    :goto_0
    const-string p0, "isMeteringRepeatingAttached"

    .line 70
    .line 71
    return-object p0

    .line 72
    :pswitch_2
    iget-object p0, p0, Lu/p;->e:Lu/y;

    .line 73
    .line 74
    iget-object v0, p0, Lu/y;->r:Ly4/h;

    .line 75
    .line 76
    if-nez v0, :cond_0

    .line 77
    .line 78
    const/4 v0, 0x1

    .line 79
    goto :goto_1

    .line 80
    :cond_0
    const/4 v0, 0x0

    .line 81
    :goto_1
    const-string v1, "Camera can only be released once, so release completer should be null on creation."

    .line 82
    .line 83
    invoke-static {v1, v0}, Ljp/ed;->f(Ljava/lang/String;Z)V

    .line 84
    .line 85
    .line 86
    iput-object p1, p0, Lu/y;->r:Ly4/h;

    .line 87
    .line 88
    new-instance p1, Ljava/lang/StringBuilder;

    .line 89
    .line 90
    const-string v0, "Release[camera="

    .line 91
    .line 92
    invoke-direct {p1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 93
    .line 94
    .line 95
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 96
    .line 97
    .line 98
    const-string p0, "]"

    .line 99
    .line 100
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 101
    .line 102
    .line 103
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 104
    .line 105
    .line 106
    move-result-object p0

    .line 107
    return-object p0

    .line 108
    :pswitch_3
    iget-object p0, p0, Lu/p;->e:Lu/y;

    .line 109
    .line 110
    :try_start_1
    iget-object v0, p0, Lu/y;->d:Lb81/c;

    .line 111
    .line 112
    invoke-virtual {v0}, Lb81/c;->n()Lh0/y1;

    .line 113
    .line 114
    .line 115
    move-result-object v0

    .line 116
    invoke-virtual {v0}, Lh0/y1;->b()Lh0/z1;

    .line 117
    .line 118
    .line 119
    move-result-object v0

    .line 120
    new-instance v1, Ljava/util/ArrayList;

    .line 121
    .line 122
    iget-object v0, v0, Lh0/z1;->c:Ljava/util/List;

    .line 123
    .line 124
    invoke-direct {v1, v0}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 125
    .line 126
    .line 127
    iget-object v0, p0, Lu/y;->E:Lu/x0;

    .line 128
    .line 129
    iget-object v0, v0, Lu/x0;->f:Ljava/lang/Object;

    .line 130
    .line 131
    check-cast v0, Lu/j0;

    .line 132
    .line 133
    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 134
    .line 135
    .line 136
    new-instance v0, Lu/t;

    .line 137
    .line 138
    invoke-direct {v0, p0, p1}, Lu/t;-><init>(Lu/y;Ly4/h;)V

    .line 139
    .line 140
    .line 141
    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 142
    .line 143
    .line 144
    iget-object v0, p0, Lu/y;->e:Lv/d;

    .line 145
    .line 146
    iget-object v2, p0, Lu/y;->l:Lu/z;

    .line 147
    .line 148
    iget-object v2, v2, Lu/z;->a:Ljava/lang/String;

    .line 149
    .line 150
    iget-object v3, p0, Lu/y;->f:Lj0/h;

    .line 151
    .line 152
    invoke-static {v1}, Llp/x0;->b(Ljava/util/ArrayList;)Landroid/hardware/camera2/CameraDevice$StateCallback;

    .line 153
    .line 154
    .line 155
    move-result-object v1

    .line 156
    iget-object v0, v0, Lv/d;->a:Lv/e;

    .line 157
    .line 158
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;
    :try_end_1
    .catch Lv/a; {:try_start_1 .. :try_end_1} :catch_2
    .catch Ljava/lang/RuntimeException; {:try_start_1 .. :try_end_1} :catch_2

    .line 159
    .line 160
    .line 161
    :try_start_2
    iget-object v0, v0, Lh/w;->b:Ljava/lang/Object;

    .line 162
    .line 163
    check-cast v0, Landroid/hardware/camera2/CameraManager;

    .line 164
    .line 165
    invoke-virtual {v0, v2, v3, v1}, Landroid/hardware/camera2/CameraManager;->openCamera(Ljava/lang/String;Ljava/util/concurrent/Executor;Landroid/hardware/camera2/CameraDevice$StateCallback;)V
    :try_end_2
    .catch Landroid/hardware/camera2/CameraAccessException; {:try_start_2 .. :try_end_2} :catch_1
    .catch Lv/a; {:try_start_2 .. :try_end_2} :catch_2
    .catch Ljava/lang/RuntimeException; {:try_start_2 .. :try_end_2} :catch_2

    .line 166
    .line 167
    .line 168
    goto :goto_2

    .line 169
    :catch_1
    move-exception v0

    .line 170
    :try_start_3
    new-instance v1, Lv/a;

    .line 171
    .line 172
    invoke-direct {v1, v0}, Lv/a;-><init>(Landroid/hardware/camera2/CameraAccessException;)V

    .line 173
    .line 174
    .line 175
    throw v1
    :try_end_3
    .catch Lv/a; {:try_start_3 .. :try_end_3} :catch_2
    .catch Ljava/lang/RuntimeException; {:try_start_3 .. :try_end_3} :catch_2

    .line 176
    :catch_2
    move-exception v0

    .line 177
    new-instance v1, Ljava/lang/StringBuilder;

    .line 178
    .line 179
    const-string v2, "Unable to open camera for configAndClose: "

    .line 180
    .line 181
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 182
    .line 183
    .line 184
    invoke-virtual {v0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 185
    .line 186
    .line 187
    move-result-object v2

    .line 188
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 189
    .line 190
    .line 191
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 192
    .line 193
    .line 194
    move-result-object v1

    .line 195
    invoke-virtual {p0, v1, v0}, Lu/y;->w(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 196
    .line 197
    .line 198
    invoke-virtual {p1, v0}, Ly4/h;->d(Ljava/lang/Throwable;)Z

    .line 199
    .line 200
    .line 201
    :goto_2
    const-string p0, "configAndCloseTask"

    .line 202
    .line 203
    return-object p0

    .line 204
    nop

    .line 205
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_0
        :pswitch_2
        :pswitch_1
    .end packed-switch
.end method
