.class public final synthetic Lvp/z0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/concurrent/Callable;


# instance fields
.field public final synthetic a:I

.field public final synthetic b:Lvp/a1;

.field public final synthetic c:Ljava/lang/String;


# direct methods
.method public synthetic constructor <init>(Lvp/a1;Ljava/lang/String;I)V
    .locals 0

    .line 1
    iput p3, p0, Lvp/z0;->a:I

    .line 2
    .line 3
    iput-object p1, p0, Lvp/z0;->b:Lvp/a1;

    .line 4
    .line 5
    iput-object p2, p0, Lvp/z0;->c:Ljava/lang/String;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final call()Ljava/lang/Object;
    .locals 5

    .line 1
    iget v0, p0, Lvp/z0;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lcom/google/android/gms/internal/measurement/y5;

    .line 7
    .line 8
    new-instance v1, Lb81/c;

    .line 9
    .line 10
    iget-object v2, p0, Lvp/z0;->b:Lvp/a1;

    .line 11
    .line 12
    iget-object p0, p0, Lvp/z0;->c:Ljava/lang/String;

    .line 13
    .line 14
    invoke-direct {v1, v2, p0}, Lb81/c;-><init>(Lvp/a1;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    const-string p0, "internal.remoteConfig"

    .line 18
    .line 19
    const/4 v2, 0x0

    .line 20
    invoke-direct {v0, p0, v2}, Lcom/google/android/gms/internal/measurement/y5;-><init>(Ljava/lang/String;I)V

    .line 21
    .line 22
    .line 23
    new-instance p0, Lcom/google/android/gms/internal/measurement/k4;

    .line 24
    .line 25
    invoke-direct {p0, v0, v1}, Lcom/google/android/gms/internal/measurement/k4;-><init>(Lcom/google/android/gms/internal/measurement/y5;Lb81/c;)V

    .line 26
    .line 27
    .line 28
    iget-object v1, v0, Lcom/google/android/gms/internal/measurement/i;->e:Ljava/util/HashMap;

    .line 29
    .line 30
    const-string v2, "getValue"

    .line 31
    .line 32
    invoke-virtual {v1, v2, p0}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    return-object v0

    .line 36
    :pswitch_0
    iget-object v0, p0, Lvp/z0;->b:Lvp/a1;

    .line 37
    .line 38
    iget-object v1, v0, Lvp/q3;->f:Lvp/z3;

    .line 39
    .line 40
    iget-object v1, v1, Lvp/z3;->f:Lvp/n;

    .line 41
    .line 42
    invoke-static {v1}, Lvp/z3;->T(Lvp/u3;)V

    .line 43
    .line 44
    .line 45
    iget-object p0, p0, Lvp/z0;->c:Ljava/lang/String;

    .line 46
    .line 47
    invoke-virtual {v1, p0}, Lvp/n;->c1(Ljava/lang/String;)Lvp/t0;

    .line 48
    .line 49
    .line 50
    move-result-object v1

    .line 51
    new-instance v2, Ljava/util/HashMap;

    .line 52
    .line 53
    invoke-direct {v2}, Ljava/util/HashMap;-><init>()V

    .line 54
    .line 55
    .line 56
    const-string v3, "platform"

    .line 57
    .line 58
    const-string v4, "android"

    .line 59
    .line 60
    invoke-virtual {v2, v3, v4}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    const-string v3, "package_name"

    .line 64
    .line 65
    invoke-virtual {v2, v3, p0}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    iget-object p0, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 69
    .line 70
    check-cast p0, Lvp/g1;

    .line 71
    .line 72
    iget-object p0, p0, Lvp/g1;->g:Lvp/h;

    .line 73
    .line 74
    invoke-virtual {p0}, Lvp/h;->f0()V

    .line 75
    .line 76
    .line 77
    const-wide/32 v3, 0x2078d

    .line 78
    .line 79
    .line 80
    invoke-static {v3, v4}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 81
    .line 82
    .line 83
    move-result-object p0

    .line 84
    const-string v0, "gmp_version"

    .line 85
    .line 86
    invoke-virtual {v2, v0, p0}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    if-eqz v1, :cond_1

    .line 90
    .line 91
    invoke-virtual {v1}, Lvp/t0;->N()Ljava/lang/String;

    .line 92
    .line 93
    .line 94
    move-result-object p0

    .line 95
    if-eqz p0, :cond_0

    .line 96
    .line 97
    const-string v0, "app_version"

    .line 98
    .line 99
    invoke-virtual {v2, v0, p0}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 100
    .line 101
    .line 102
    :cond_0
    invoke-virtual {v1}, Lvp/t0;->P()J

    .line 103
    .line 104
    .line 105
    move-result-wide v3

    .line 106
    invoke-static {v3, v4}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 107
    .line 108
    .line 109
    move-result-object p0

    .line 110
    const-string v0, "app_version_int"

    .line 111
    .line 112
    invoke-virtual {v2, v0, p0}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 113
    .line 114
    .line 115
    invoke-virtual {v1}, Lvp/t0;->b()J

    .line 116
    .line 117
    .line 118
    move-result-wide v0

    .line 119
    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 120
    .line 121
    .line 122
    move-result-object p0

    .line 123
    const-string v0, "dynamite_version"

    .line 124
    .line 125
    invoke-virtual {v2, v0, p0}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 126
    .line 127
    .line 128
    :cond_1
    return-object v2

    .line 129
    :pswitch_1
    new-instance v0, Lcom/google/android/gms/internal/measurement/k4;

    .line 130
    .line 131
    new-instance v1, Lvp/z0;

    .line 132
    .line 133
    iget-object v2, p0, Lvp/z0;->c:Ljava/lang/String;

    .line 134
    .line 135
    const/4 v3, 0x1

    .line 136
    iget-object p0, p0, Lvp/z0;->b:Lvp/a1;

    .line 137
    .line 138
    invoke-direct {v1, p0, v2, v3}, Lvp/z0;-><init>(Lvp/a1;Ljava/lang/String;I)V

    .line 139
    .line 140
    .line 141
    invoke-direct {v0, v1}, Lcom/google/android/gms/internal/measurement/k4;-><init>(Lvp/z0;)V

    .line 142
    .line 143
    .line 144
    return-object v0

    .line 145
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
