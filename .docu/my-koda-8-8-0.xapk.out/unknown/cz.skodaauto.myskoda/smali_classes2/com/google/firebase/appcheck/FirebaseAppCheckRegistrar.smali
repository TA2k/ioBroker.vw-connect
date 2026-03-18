.class public Lcom/google/firebase/appcheck/FirebaseAppCheckRegistrar;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/google/firebase/components/ComponentRegistrar;


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public final getComponents()Ljava/util/List;
    .locals 8

    .line 1
    new-instance p0, Lgs/s;

    .line 2
    .line 3
    const-class v0, Lyr/d;

    .line 4
    .line 5
    const-class v1, Ljava/util/concurrent/Executor;

    .line 6
    .line 7
    invoke-direct {p0, v0, v1}, Lgs/s;-><init>(Ljava/lang/Class;Ljava/lang/Class;)V

    .line 8
    .line 9
    .line 10
    new-instance v0, Lgs/s;

    .line 11
    .line 12
    const-class v2, Lyr/c;

    .line 13
    .line 14
    invoke-direct {v0, v2, v1}, Lgs/s;-><init>(Ljava/lang/Class;Ljava/lang/Class;)V

    .line 15
    .line 16
    .line 17
    new-instance v2, Lgs/s;

    .line 18
    .line 19
    const-class v3, Lyr/a;

    .line 20
    .line 21
    invoke-direct {v2, v3, v1}, Lgs/s;-><init>(Ljava/lang/Class;Ljava/lang/Class;)V

    .line 22
    .line 23
    .line 24
    new-instance v1, Lgs/s;

    .line 25
    .line 26
    const-class v3, Lyr/b;

    .line 27
    .line 28
    const-class v4, Ljava/util/concurrent/ScheduledExecutorService;

    .line 29
    .line 30
    invoke-direct {v1, v3, v4}, Lgs/s;-><init>(Ljava/lang/Class;Ljava/lang/Class;)V

    .line 31
    .line 32
    .line 33
    const-class v3, Lcs/a;

    .line 34
    .line 35
    filled-new-array {v3}, [Ljava/lang/Class;

    .line 36
    .line 37
    .line 38
    move-result-object v3

    .line 39
    new-instance v4, Lgs/a;

    .line 40
    .line 41
    const-class v5, Las/d;

    .line 42
    .line 43
    invoke-direct {v4, v5, v3}, Lgs/a;-><init>(Ljava/lang/Class;[Ljava/lang/Class;)V

    .line 44
    .line 45
    .line 46
    const-string v3, "fire-app-check"

    .line 47
    .line 48
    iput-object v3, v4, Lgs/a;->a:Ljava/lang/String;

    .line 49
    .line 50
    const-class v5, Lsr/f;

    .line 51
    .line 52
    invoke-static {v5}, Lgs/k;->c(Ljava/lang/Class;)Lgs/k;

    .line 53
    .line 54
    .line 55
    move-result-object v5

    .line 56
    invoke-virtual {v4, v5}, Lgs/a;->a(Lgs/k;)V

    .line 57
    .line 58
    .line 59
    new-instance v5, Lgs/k;

    .line 60
    .line 61
    const/4 v6, 0x1

    .line 62
    const/4 v7, 0x0

    .line 63
    invoke-direct {v5, p0, v6, v7}, Lgs/k;-><init>(Lgs/s;II)V

    .line 64
    .line 65
    .line 66
    invoke-virtual {v4, v5}, Lgs/a;->a(Lgs/k;)V

    .line 67
    .line 68
    .line 69
    new-instance v5, Lgs/k;

    .line 70
    .line 71
    invoke-direct {v5, v0, v6, v7}, Lgs/k;-><init>(Lgs/s;II)V

    .line 72
    .line 73
    .line 74
    invoke-virtual {v4, v5}, Lgs/a;->a(Lgs/k;)V

    .line 75
    .line 76
    .line 77
    new-instance v5, Lgs/k;

    .line 78
    .line 79
    invoke-direct {v5, v2, v6, v7}, Lgs/k;-><init>(Lgs/s;II)V

    .line 80
    .line 81
    .line 82
    invoke-virtual {v4, v5}, Lgs/a;->a(Lgs/k;)V

    .line 83
    .line 84
    .line 85
    new-instance v5, Lgs/k;

    .line 86
    .line 87
    invoke-direct {v5, v1, v6, v7}, Lgs/k;-><init>(Lgs/s;II)V

    .line 88
    .line 89
    .line 90
    invoke-virtual {v4, v5}, Lgs/a;->a(Lgs/k;)V

    .line 91
    .line 92
    .line 93
    const-class v5, Let/e;

    .line 94
    .line 95
    invoke-static {v5}, Lgs/k;->a(Ljava/lang/Class;)Lgs/k;

    .line 96
    .line 97
    .line 98
    move-result-object v5

    .line 99
    invoke-virtual {v4, v5}, Lgs/a;->a(Lgs/k;)V

    .line 100
    .line 101
    .line 102
    new-instance v5, Lcom/salesforce/marketingcloud/sfmcsdk/modules/a;

    .line 103
    .line 104
    invoke-direct {v5, p0, v0, v2, v1}, Lcom/salesforce/marketingcloud/sfmcsdk/modules/a;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 105
    .line 106
    .line 107
    iput-object v5, v4, Lgs/a;->f:Lgs/e;

    .line 108
    .line 109
    invoke-virtual {v4, v6}, Lgs/a;->c(I)V

    .line 110
    .line 111
    .line 112
    invoke-virtual {v4}, Lgs/a;->b()Lgs/b;

    .line 113
    .line 114
    .line 115
    move-result-object p0

    .line 116
    new-instance v0, Let/d;

    .line 117
    .line 118
    const/4 v1, 0x0

    .line 119
    invoke-direct {v0, v1}, Let/d;-><init>(I)V

    .line 120
    .line 121
    .line 122
    const-class v1, Let/d;

    .line 123
    .line 124
    invoke-static {v1}, Lgs/b;->b(Ljava/lang/Class;)Lgs/a;

    .line 125
    .line 126
    .line 127
    move-result-object v1

    .line 128
    iput v6, v1, Lgs/a;->e:I

    .line 129
    .line 130
    new-instance v2, Lb8/c;

    .line 131
    .line 132
    invoke-direct {v2, v0}, Lb8/c;-><init>(Ljava/lang/Object;)V

    .line 133
    .line 134
    .line 135
    iput-object v2, v1, Lgs/a;->f:Lgs/e;

    .line 136
    .line 137
    invoke-virtual {v1}, Lgs/a;->b()Lgs/b;

    .line 138
    .line 139
    .line 140
    move-result-object v0

    .line 141
    const-string v1, "19.0.1"

    .line 142
    .line 143
    invoke-static {v3, v1}, Ljp/gb;->a(Ljava/lang/String;Ljava/lang/String;)Lgs/b;

    .line 144
    .line 145
    .line 146
    move-result-object v1

    .line 147
    filled-new-array {p0, v0, v1}, [Lgs/b;

    .line 148
    .line 149
    .line 150
    move-result-object p0

    .line 151
    invoke-static {p0}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 152
    .line 153
    .line 154
    move-result-object p0

    .line 155
    return-object p0
.end method
