.class public final Lkc0/l;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lkc0/g;


# direct methods
.method public constructor <init>(Lkc0/g;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lkc0/l;->a:Lkc0/g;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 6

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    :try_start_0
    iget-object p0, p0, Lkc0/l;->a:Lkc0/g;

    .line 4
    .line 5
    check-cast p0, Lic0/p;

    .line 6
    .line 7
    iget-object p0, p0, Lic0/p;->f:Lyy0/c2;

    .line 8
    .line 9
    invoke-virtual {p0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    check-cast p0, Llc0/d;

    .line 14
    .line 15
    const/4 p1, 0x0

    .line 16
    if-eqz p0, :cond_0

    .line 17
    .line 18
    iget-object p0, p0, Llc0/d;->a:Ljava/lang/String;

    .line 19
    .line 20
    goto :goto_0

    .line 21
    :cond_0
    move-object p0, p1

    .line 22
    :goto_0
    if-eqz p0, :cond_1

    .line 23
    .line 24
    new-instance p1, Llc0/d;

    .line 25
    .line 26
    invoke-direct {p1, p0}, Llc0/d;-><init>(Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    goto :goto_2

    .line 30
    :goto_1
    move-object v1, p0

    .line 31
    goto :goto_3

    .line 32
    :cond_1
    :goto_2
    if-eqz p1, :cond_4

    .line 33
    .line 34
    iget-object p0, p1, Llc0/d;->a:Ljava/lang/String;

    .line 35
    .line 36
    const-string p1, "$v$c$cz-skodaauto-myskoda-library-authcomponent-model-IdToken$-$this$toJwt$0"

    .line 37
    .line 38
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    new-instance p1, Lcom/auth0/android/jwt/c;

    .line 42
    .line 43
    invoke-direct {p1, p0}, Lcom/auth0/android/jwt/c;-><init>(Ljava/lang/String;)V

    .line 44
    .line 45
    .line 46
    const-string p0, "sub"

    .line 47
    .line 48
    invoke-virtual {p1, p0}, Lcom/auth0/android/jwt/c;->b(Ljava/lang/String;)Lcom/auth0/android/jwt/a;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    invoke-virtual {p0}, Lcom/auth0/android/jwt/a;->a()Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    if-eqz p0, :cond_3

    .line 57
    .line 58
    const-string p2, "email"

    .line 59
    .line 60
    invoke-virtual {p1, p2}, Lcom/auth0/android/jwt/c;->b(Ljava/lang/String;)Lcom/auth0/android/jwt/a;

    .line 61
    .line 62
    .line 63
    move-result-object p1

    .line 64
    invoke-virtual {p1}, Lcom/auth0/android/jwt/a;->a()Ljava/lang/String;

    .line 65
    .line 66
    .line 67
    move-result-object p1

    .line 68
    if-eqz p1, :cond_2

    .line 69
    .line 70
    new-instance p2, Lne0/e;

    .line 71
    .line 72
    new-instance v0, Llc0/n;

    .line 73
    .line 74
    invoke-direct {v0, p0, p1}, Llc0/n;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 75
    .line 76
    .line 77
    invoke-direct {p2, v0}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 78
    .line 79
    .line 80
    return-object p2

    .line 81
    :cond_2
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 82
    .line 83
    const-string p1, "Unable to get email from connect token. Email value is null."

    .line 84
    .line 85
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 86
    .line 87
    .line 88
    throw p0

    .line 89
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 90
    .line 91
    const-string p1, "Unable to get user id from connect token. UserId value is null."

    .line 92
    .line 93
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 94
    .line 95
    .line 96
    throw p0

    .line 97
    :cond_4
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 98
    .line 99
    const-string p1, "Unable to get user id from connect token. Id token is not available."

    .line 100
    .line 101
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 102
    .line 103
    .line 104
    throw p0
    :try_end_0
    .catch Ljava/lang/IllegalStateException; {:try_start_0 .. :try_end_0} :catch_0

    .line 105
    :catch_0
    move-exception v0

    .line 106
    move-object p0, v0

    .line 107
    goto :goto_1

    .line 108
    :goto_3
    new-instance v0, Lne0/c;

    .line 109
    .line 110
    const/4 v4, 0x0

    .line 111
    const/16 v5, 0x1e

    .line 112
    .line 113
    const/4 v2, 0x0

    .line 114
    const/4 v3, 0x0

    .line 115
    invoke-direct/range {v0 .. v5}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 116
    .line 117
    .line 118
    return-object v0
.end method
