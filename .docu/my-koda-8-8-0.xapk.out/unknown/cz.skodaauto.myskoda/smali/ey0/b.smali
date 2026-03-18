.class public final Ley0/b;
.super Ljava/lang/ThreadLocal;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic a:I


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Ley0/b;->a:I

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/ThreadLocal;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final initialValue()Ljava/lang/Object;
    .locals 2

    .line 1
    iget p0, p0, Ley0/b;->a:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    const-wide/16 v0, 0x0

    .line 7
    .line 8
    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    return-object p0

    .line 13
    :pswitch_0
    new-instance p0, Lw3/m1;

    .line 14
    .line 15
    invoke-direct {p0}, Lw3/m1;-><init>()V

    .line 16
    .line 17
    .line 18
    return-object p0

    .line 19
    :pswitch_1
    new-instance p0, Lw3/p0;

    .line 20
    .line 21
    invoke-static {}, Landroid/view/Choreographer;->getInstance()Landroid/view/Choreographer;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    invoke-static {}, Landroid/os/Looper;->myLooper()Landroid/os/Looper;

    .line 26
    .line 27
    .line 28
    move-result-object v1

    .line 29
    if-eqz v1, :cond_0

    .line 30
    .line 31
    invoke-static {v1}, Landroid/os/Handler;->createAsync(Landroid/os/Looper;)Landroid/os/Handler;

    .line 32
    .line 33
    .line 34
    move-result-object v1

    .line 35
    invoke-direct {p0, v0, v1}, Lw3/p0;-><init>(Landroid/view/Choreographer;Landroid/os/Handler;)V

    .line 36
    .line 37
    .line 38
    iget-object v0, p0, Lw3/p0;->n:Ll2/l1;

    .line 39
    .line 40
    invoke-virtual {p0, v0}, Lpx0/a;->plus(Lpx0/g;)Lpx0/g;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    return-object p0

    .line 45
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 46
    .line 47
    const-string v0, "no Looper on this thread"

    .line 48
    .line 49
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    throw p0

    .line 53
    :pswitch_2
    new-instance p0, Ljava/security/SecureRandom;

    .line 54
    .line 55
    invoke-direct {p0}, Ljava/security/SecureRandom;-><init>()V

    .line 56
    .line 57
    .line 58
    invoke-virtual {p0}, Ljava/util/Random;->nextLong()J

    .line 59
    .line 60
    .line 61
    return-object p0

    .line 62
    :pswitch_3
    sget-object p0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 63
    .line 64
    return-object p0

    .line 65
    :pswitch_4
    invoke-static {}, Landroid/os/Looper;->myLooper()Landroid/os/Looper;

    .line 66
    .line 67
    .line 68
    move-result-object p0

    .line 69
    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;

    .line 70
    .line 71
    .line 72
    move-result-object v0

    .line 73
    if-ne p0, v0, :cond_1

    .line 74
    .line 75
    invoke-static {}, Llp/hb;->d()Lj0/c;

    .line 76
    .line 77
    .line 78
    move-result-object p0

    .line 79
    goto :goto_0

    .line 80
    :cond_1
    invoke-static {}, Landroid/os/Looper;->myLooper()Landroid/os/Looper;

    .line 81
    .line 82
    .line 83
    move-result-object p0

    .line 84
    if-eqz p0, :cond_2

    .line 85
    .line 86
    new-instance p0, Landroid/os/Handler;

    .line 87
    .line 88
    invoke-static {}, Landroid/os/Looper;->myLooper()Landroid/os/Looper;

    .line 89
    .line 90
    .line 91
    move-result-object v0

    .line 92
    invoke-direct {p0, v0}, Landroid/os/Handler;-><init>(Landroid/os/Looper;)V

    .line 93
    .line 94
    .line 95
    new-instance v0, Lj0/c;

    .line 96
    .line 97
    invoke-direct {v0, p0}, Lj0/c;-><init>(Landroid/os/Handler;)V

    .line 98
    .line 99
    .line 100
    move-object p0, v0

    .line 101
    goto :goto_0

    .line 102
    :cond_2
    const/4 p0, 0x0

    .line 103
    :goto_0
    return-object p0

    .line 104
    :pswitch_5
    new-instance p0, Ljava/text/SimpleDateFormat;

    .line 105
    .line 106
    const-string v0, "EEE, dd MMM yyyy HH:mm:ss \'GMT\'"

    .line 107
    .line 108
    sget-object v1, Ljava/util/Locale;->US:Ljava/util/Locale;

    .line 109
    .line 110
    invoke-direct {p0, v0, v1}, Ljava/text/SimpleDateFormat;-><init>(Ljava/lang/String;Ljava/util/Locale;)V

    .line 111
    .line 112
    .line 113
    const/4 v0, 0x0

    .line 114
    invoke-virtual {p0, v0}, Ljava/text/DateFormat;->setLenient(Z)V

    .line 115
    .line 116
    .line 117
    sget-object v0, Le01/g;->a:Ljava/util/TimeZone;

    .line 118
    .line 119
    invoke-virtual {p0, v0}, Ljava/text/DateFormat;->setTimeZone(Ljava/util/TimeZone;)V

    .line 120
    .line 121
    .line 122
    return-object p0

    .line 123
    :pswitch_6
    const/4 p0, 0x4

    .line 124
    new-array p0, p0, [F

    .line 125
    .line 126
    return-object p0

    .line 127
    :pswitch_7
    new-instance p0, Landroid/graphics/Path;

    .line 128
    .line 129
    invoke-direct {p0}, Landroid/graphics/Path;-><init>()V

    .line 130
    .line 131
    .line 132
    return-object p0

    .line 133
    :pswitch_8
    new-instance p0, Landroid/graphics/Path;

    .line 134
    .line 135
    invoke-direct {p0}, Landroid/graphics/Path;-><init>()V

    .line 136
    .line 137
    .line 138
    return-object p0

    .line 139
    :pswitch_9
    new-instance p0, Landroid/graphics/PathMeasure;

    .line 140
    .line 141
    invoke-direct {p0}, Landroid/graphics/PathMeasure;-><init>()V

    .line 142
    .line 143
    .line 144
    return-object p0

    .line 145
    :pswitch_a
    new-instance p0, Ljava/util/Random;

    .line 146
    .line 147
    invoke-direct {p0}, Ljava/util/Random;-><init>()V

    .line 148
    .line 149
    .line 150
    return-object p0

    .line 151
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
