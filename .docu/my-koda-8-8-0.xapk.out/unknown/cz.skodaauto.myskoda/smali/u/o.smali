.class public final synthetic Lu/o;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lu/y;


# direct methods
.method public synthetic constructor <init>(Lu/y;I)V
    .locals 0

    .line 1
    iput p2, p0, Lu/o;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lu/o;->e:Lu/y;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final run()V
    .locals 5

    .line 1
    iget v0, p0, Lu/o;->d:I

    .line 2
    .line 3
    iget-object p0, p0, Lu/o;->e:Lu/y;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    const/4 v0, 0x0

    .line 9
    iput-boolean v0, p0, Lu/y;->B:Z

    .line 10
    .line 11
    iput-boolean v0, p0, Lu/y;->A:Z

    .line 12
    .line 13
    iget v1, p0, Lu/y;->O:I

    .line 14
    .line 15
    invoke-static {v1}, Lu/w;->p(I)Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object v1

    .line 19
    const-string v2, "OpenCameraConfigAndClose is done, state: "

    .line 20
    .line 21
    invoke-virtual {v2, v1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object v1

    .line 25
    const/4 v2, 0x0

    .line 26
    invoke-virtual {p0, v1, v2}, Lu/y;->w(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 27
    .line 28
    .line 29
    iget v1, p0, Lu/y;->O:I

    .line 30
    .line 31
    invoke-static {v1}, Lu/w;->o(I)I

    .line 32
    .line 33
    .line 34
    move-result v1

    .line 35
    const/4 v3, 0x1

    .line 36
    if-eq v1, v3, :cond_2

    .line 37
    .line 38
    const/4 v3, 0x5

    .line 39
    if-eq v1, v3, :cond_2

    .line 40
    .line 41
    const/4 v3, 0x7

    .line 42
    if-eq v1, v3, :cond_0

    .line 43
    .line 44
    iget v0, p0, Lu/y;->O:I

    .line 45
    .line 46
    invoke-static {v0}, Lu/w;->p(I)Ljava/lang/String;

    .line 47
    .line 48
    .line 49
    move-result-object v0

    .line 50
    const-string v1, "OpenCameraConfigAndClose finished while in state: "

    .line 51
    .line 52
    invoke-virtual {v1, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object v0

    .line 56
    invoke-virtual {p0, v0, v2}, Lu/y;->w(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 57
    .line 58
    .line 59
    goto :goto_0

    .line 60
    :cond_0
    iget v1, p0, Lu/y;->n:I

    .line 61
    .line 62
    if-eqz v1, :cond_1

    .line 63
    .line 64
    invoke-static {v1}, Lu/y;->y(I)Ljava/lang/String;

    .line 65
    .line 66
    .line 67
    move-result-object v0

    .line 68
    const-string v1, "OpenCameraConfigAndClose in error: "

    .line 69
    .line 70
    invoke-virtual {v1, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 71
    .line 72
    .line 73
    move-result-object v0

    .line 74
    invoke-virtual {p0, v0, v2}, Lu/y;->w(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 75
    .line 76
    .line 77
    iget-object p0, p0, Lu/y;->k:Lu/x;

    .line 78
    .line 79
    invoke-virtual {p0}, Lu/x;->b()V

    .line 80
    .line 81
    .line 82
    goto :goto_0

    .line 83
    :cond_1
    invoke-virtual {p0, v0}, Lu/y;->L(Z)V

    .line 84
    .line 85
    .line 86
    goto :goto_0

    .line 87
    :cond_2
    iget-object v0, p0, Lu/y;->s:Ljava/util/LinkedHashMap;

    .line 88
    .line 89
    invoke-interface {v0}, Ljava/util/Map;->isEmpty()Z

    .line 90
    .line 91
    .line 92
    move-result v0

    .line 93
    invoke-static {v2, v0}, Ljp/ed;->f(Ljava/lang/String;Z)V

    .line 94
    .line 95
    .line 96
    invoke-virtual {p0}, Lu/y;->x()V

    .line 97
    .line 98
    .line 99
    :goto_0
    return-void

    .line 100
    :pswitch_0
    const-string v0, "Camera is removed. Updating state and cleaning up."

    .line 101
    .line 102
    const/4 v1, 0x0

    .line 103
    invoke-virtual {p0, v0, v1}, Lu/y;->w(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 104
    .line 105
    .line 106
    iget v0, p0, Lu/y;->O:I

    .line 107
    .line 108
    const/4 v2, 0x2

    .line 109
    if-eq v0, v2, :cond_5

    .line 110
    .line 111
    iget v0, p0, Lu/y;->O:I

    .line 112
    .line 113
    const/4 v3, 0x1

    .line 114
    if-ne v0, v3, :cond_3

    .line 115
    .line 116
    goto :goto_1

    .line 117
    :cond_3
    new-instance v0, Lb0/e;

    .line 118
    .line 119
    const/16 v4, 0x8

    .line 120
    .line 121
    invoke-direct {v0, v4, v1}, Lb0/e;-><init>(ILjava/lang/Throwable;)V

    .line 122
    .line 123
    .line 124
    iget-object v1, p0, Lu/y;->i:Lb81/c;

    .line 125
    .line 126
    sget-object v4, Lh0/a0;->g:Lh0/a0;

    .line 127
    .line 128
    invoke-virtual {v1, v4, v0}, Lb81/c;->x(Lh0/a0;Lb0/e;)V

    .line 129
    .line 130
    .line 131
    invoke-virtual {p0, v2, v0, v3}, Lu/y;->H(ILb0/e;Z)V

    .line 132
    .line 133
    .line 134
    iget-object v0, p0, Lu/y;->k:Lu/x;

    .line 135
    .line 136
    invoke-virtual {v0}, Lu/x;->a()Z

    .line 137
    .line 138
    .line 139
    iget-object v0, p0, Lu/y;->N:Lb81/b;

    .line 140
    .line 141
    invoke-virtual {v0}, Lb81/b;->j()V

    .line 142
    .line 143
    .line 144
    iget-object v0, p0, Lu/y;->m:Landroid/hardware/camera2/CameraDevice;

    .line 145
    .line 146
    if-eqz v0, :cond_4

    .line 147
    .line 148
    invoke-virtual {p0}, Lu/y;->t()V

    .line 149
    .line 150
    .line 151
    goto :goto_1

    .line 152
    :cond_4
    invoke-virtual {p0}, Lu/y;->x()V

    .line 153
    .line 154
    .line 155
    :cond_5
    :goto_1
    return-void

    .line 156
    nop

    .line 157
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
