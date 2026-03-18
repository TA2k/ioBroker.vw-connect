.class public final Ldm0/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Landroid/content/Context;

.field public final b:Lam0/b;

.field public final c:Ldm0/d;


# direct methods
.method public constructor <init>(Landroid/content/Context;Lam0/b;Ldm0/d;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ldm0/f;->a:Landroid/content/Context;

    .line 5
    .line 6
    iput-object p2, p0, Ldm0/f;->b:Lam0/b;

    .line 7
    .line 8
    iput-object p3, p0, Ldm0/f;->c:Ldm0/d;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final a(Lrx0/c;)Ljava/lang/Object;
    .locals 6

    .line 1
    instance-of v0, p1, Ldm0/e;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Ldm0/e;

    .line 7
    .line 8
    iget v1, v0, Ldm0/e;->g:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Ldm0/e;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Ldm0/e;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Ldm0/e;-><init>(Ldm0/f;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Ldm0/e;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Ldm0/e;->g:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    if-eqz v2, :cond_2

    .line 33
    .line 34
    if-ne v2, v3, :cond_1

    .line 35
    .line 36
    iget-object v0, v0, Ldm0/e;->d:Ldm0/d;

    .line 37
    .line 38
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    goto :goto_1

    .line 42
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 43
    .line 44
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 45
    .line 46
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    throw p0

    .line 50
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    iget-object p1, p0, Ldm0/f;->c:Ldm0/d;

    .line 54
    .line 55
    iput-object p1, v0, Ldm0/e;->d:Ldm0/d;

    .line 56
    .line 57
    iput v3, v0, Ldm0/e;->g:I

    .line 58
    .line 59
    iget-object v2, p0, Ldm0/f;->b:Lam0/b;

    .line 60
    .line 61
    check-cast v2, Lxl0/o;

    .line 62
    .line 63
    invoke-virtual {v2, v0}, Lxl0/o;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Enum;

    .line 64
    .line 65
    .line 66
    move-result-object v0

    .line 67
    if-ne v0, v1, :cond_3

    .line 68
    .line 69
    return-object v1

    .line 70
    :cond_3
    move-object v5, v0

    .line 71
    move-object v0, p1

    .line 72
    move-object p1, v5

    .line 73
    :goto_1
    check-cast p1, Lcm0/b;

    .line 74
    .line 75
    check-cast v0, Lcz/skodaauto/myskoda/library/networking/system/JniCertStoreConfigurationResource;

    .line 76
    .line 77
    invoke-virtual {v0, p1}, Lcz/skodaauto/myskoda/library/networking/system/JniCertStoreConfigurationResource;->a(Lcm0/b;)Lcm0/a;

    .line 78
    .line 79
    .line 80
    move-result-object p1

    .line 81
    const/4 v0, 0x0

    .line 82
    if-eqz p1, :cond_4

    .line 83
    .line 84
    new-instance v1, Ldx/j;

    .line 85
    .line 86
    new-instance v2, Ljava/net/URL;

    .line 87
    .line 88
    iget-object v4, p1, Lcm0/a;->a:Ljava/lang/String;

    .line 89
    .line 90
    invoke-direct {v2, v4}, Ljava/net/URL;-><init>(Ljava/lang/String;)V

    .line 91
    .line 92
    .line 93
    invoke-static {}, Ljava/util/Base64;->getDecoder()Ljava/util/Base64$Decoder;

    .line 94
    .line 95
    .line 96
    move-result-object v4

    .line 97
    iget-object p1, p1, Lcm0/a;->b:Ljava/lang/String;

    .line 98
    .line 99
    invoke-virtual {v4, p1}, Ljava/util/Base64$Decoder;->decode(Ljava/lang/String;)[B

    .line 100
    .line 101
    .line 102
    move-result-object p1

    .line 103
    const-string v4, "decode(...)"

    .line 104
    .line 105
    invoke-static {p1, v4}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 106
    .line 107
    .line 108
    invoke-direct {v1, v2, p1}, Ldx/j;-><init>(Ljava/net/URL;[B)V

    .line 109
    .line 110
    .line 111
    iput-boolean v3, v1, Ldx/j;->c:Z

    .line 112
    .line 113
    new-instance p1, Ldx/k;

    .line 114
    .line 115
    invoke-direct {p1, v1}, Ldx/k;-><init>(Ldx/j;)V

    .line 116
    .line 117
    .line 118
    sget-object v1, Ldx/i;->j:Lcom/google/gson/j;

    .line 119
    .line 120
    new-instance v1, Laq/a;

    .line 121
    .line 122
    const/4 v2, 0x6

    .line 123
    iget-object p0, p0, Ldm0/f;->a:Landroid/content/Context;

    .line 124
    .line 125
    invoke-direct {v1, p0, v0, v2}, Laq/a;-><init>(Landroid/content/Context;Ljava/lang/String;I)V

    .line 126
    .line 127
    .line 128
    new-instance p0, Ldx/i;

    .line 129
    .line 130
    new-instance v0, Lbu/c;

    .line 131
    .line 132
    const/16 v2, 0x15

    .line 133
    .line 134
    invoke-direct {v0, v2}, Lbu/c;-><init>(I)V

    .line 135
    .line 136
    .line 137
    invoke-direct {p0, p1, v0, v1}, Ldx/i;-><init>(Ldx/k;Lbu/c;Laq/a;)V

    .line 138
    .line 139
    .line 140
    return-object p0

    .line 141
    :cond_4
    return-object v0
.end method
