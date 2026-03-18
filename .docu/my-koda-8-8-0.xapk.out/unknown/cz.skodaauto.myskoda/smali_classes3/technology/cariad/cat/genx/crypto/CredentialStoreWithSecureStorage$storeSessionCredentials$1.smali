.class final Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage$storeSessionCredentials$1;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage;->storeSessionCredentials$genx_release(Ltechnology/cariad/cat/genx/crypto/SessionCredentials;B)I
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = null
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Lrx0/i;",
        "Lay0/n;"
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u000c\n\u0002\u0018\u0002\n\u0002\u0010\u0008\n\u0002\u0008\u0002\u0010\u0002\u001a\u00020\u0001*\u00020\u0000H\n\u00a2\u0006\u0004\u0008\u0002\u0010\u0003"
    }
    d2 = {
        "Lvy0/b0;",
        "",
        "<anonymous>",
        "(Lvy0/b0;)I"
    }
    k = 0x3
    mv = {
        0x2,
        0x2,
        0x0
    }
.end annotation

.annotation runtime Lrx0/e;
    c = "technology.cariad.cat.genx.crypto.CredentialStoreWithSecureStorage$storeSessionCredentials$1"
    f = "CredentialStoreWithSecureStorage.kt"
    l = {
        0x61
    }
    m = "invokeSuspend"
    v = 0x1
.end annotation


# instance fields
.field final synthetic $sessionCredentialsEntry:Ltechnology/cariad/cat/genx/crypto/SessionCredentials;

.field final synthetic $uniqueKey:Ljava/lang/String;

.field I$0:I

.field private synthetic L$0:Ljava/lang/Object;

.field L$1:Ljava/lang/Object;

.field L$2:Ljava/lang/Object;

.field L$3:Ljava/lang/Object;

.field label:I

.field final synthetic this$0:Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage;


# direct methods
.method public constructor <init>(Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage;Ljava/lang/String;Ltechnology/cariad/cat/genx/crypto/SessionCredentials;Lkotlin/coroutines/Continuation;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage;",
            "Ljava/lang/String;",
            "Ltechnology/cariad/cat/genx/crypto/SessionCredentials;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage$storeSessionCredentials$1;",
            ">;)V"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage$storeSessionCredentials$1;->this$0:Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage;

    .line 2
    .line 3
    iput-object p2, p0, Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage$storeSessionCredentials$1;->$uniqueKey:Ljava/lang/String;

    .line 4
    .line 5
    iput-object p3, p0, Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage$storeSessionCredentials$1;->$sessionCredentialsEntry:Ltechnology/cariad/cat/genx/crypto/SessionCredentials;

    .line 6
    .line 7
    const/4 p1, 0x2

    .line 8
    invoke-direct {p0, p1, p4}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public static synthetic b(Ltechnology/cariad/cat/genx/crypto/SessionCredentials;Ljava/lang/String;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage$storeSessionCredentials$1;->invokeSuspend$lambda$0(Ltechnology/cariad/cat/genx/crypto/SessionCredentials;Ljava/lang/String;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic d(Ltechnology/cariad/cat/genx/crypto/SessionCredentials;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage$storeSessionCredentials$1;->invokeSuspend$lambda$2$0(Ltechnology/cariad/cat/genx/crypto/SessionCredentials;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static final invokeSuspend$lambda$0(Ltechnology/cariad/cat/genx/crypto/SessionCredentials;Ljava/lang/String;)Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "storeSessionCredentials(): Save "

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 9
    .line 10
    .line 11
    const-string p0, " for "

    .line 12
    .line 13
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 14
    .line 15
    .line 16
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 17
    .line 18
    .line 19
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    return-object p0
.end method

.method private static final invokeSuspend$lambda$2$0(Ltechnology/cariad/cat/genx/crypto/SessionCredentials;)Ljava/lang/String;
    .locals 1

    .line 1
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/crypto/SessionCredentials;->getLocalIdentifier()[B

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-static {p0}, Lly0/d;->l([B)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    const-string v0, "storeSessionCredentials(): Failed to store session credentials for localIdentifier = "

    .line 10
    .line 11
    invoke-virtual {v0, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/Object;",
            "Lkotlin/coroutines/Continuation<",
            "*>;)",
            "Lkotlin/coroutines/Continuation<",
            "Llx0/b0;",
            ">;"
        }
    .end annotation

    .line 1
    new-instance v0, Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage$storeSessionCredentials$1;

    .line 2
    .line 3
    iget-object v1, p0, Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage$storeSessionCredentials$1;->this$0:Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage;

    .line 4
    .line 5
    iget-object v2, p0, Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage$storeSessionCredentials$1;->$uniqueKey:Ljava/lang/String;

    .line 6
    .line 7
    iget-object p0, p0, Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage$storeSessionCredentials$1;->$sessionCredentialsEntry:Ltechnology/cariad/cat/genx/crypto/SessionCredentials;

    .line 8
    .line 9
    invoke-direct {v0, v1, v2, p0, p2}, Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage$storeSessionCredentials$1;-><init>(Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage;Ljava/lang/String;Ltechnology/cariad/cat/genx/crypto/SessionCredentials;Lkotlin/coroutines/Continuation;)V

    .line 10
    .line 11
    .line 12
    iput-object p1, v0, Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage$storeSessionCredentials$1;->L$0:Ljava/lang/Object;

    .line 13
    .line 14
    return-object v0
.end method

.method public bridge synthetic invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lvy0/b0;

    check-cast p2, Lkotlin/coroutines/Continuation;

    invoke-virtual {p0, p1, p2}, Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage$storeSessionCredentials$1;->invoke(Lvy0/b0;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    move-result-object p0

    return-object p0
.end method

.method public final invoke(Lvy0/b0;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lvy0/b0;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Ljava/lang/Integer;",
            ">;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .line 2
    invoke-virtual {p0, p1, p2}, Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage$storeSessionCredentials$1;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    move-result-object p0

    check-cast p0, Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage$storeSessionCredentials$1;

    sget-object p1, Llx0/b0;->a:Llx0/b0;

    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage$storeSessionCredentials$1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 12

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage$storeSessionCredentials$1;->L$0:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lvy0/b0;

    .line 4
    .line 5
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 6
    .line 7
    iget v2, p0, Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage$storeSessionCredentials$1;->label:I

    .line 8
    .line 9
    const-string v3, "getName(...)"

    .line 10
    .line 11
    const/4 v4, 0x1

    .line 12
    if-eqz v2, :cond_1

    .line 13
    .line 14
    if-ne v2, v4, :cond_0

    .line 15
    .line 16
    iget-object v1, p0, Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage$storeSessionCredentials$1;->L$3:Ljava/lang/Object;

    .line 17
    .line 18
    check-cast v1, Ltechnology/cariad/cat/genx/crypto/SessionCredentials;

    .line 19
    .line 20
    iget-object v1, p0, Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage$storeSessionCredentials$1;->L$2:Ljava/lang/Object;

    .line 21
    .line 22
    check-cast v1, Ljava/lang/String;

    .line 23
    .line 24
    iget-object v1, p0, Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage$storeSessionCredentials$1;->L$1:Ljava/lang/Object;

    .line 25
    .line 26
    check-cast v1, Lu51/g;

    .line 27
    .line 28
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 29
    .line 30
    .line 31
    check-cast p1, Llx0/o;

    .line 32
    .line 33
    iget-object p1, p1, Llx0/o;->d:Ljava/lang/Object;

    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 37
    .line 38
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 39
    .line 40
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    throw p0

    .line 44
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    iget-object p1, p0, Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage$storeSessionCredentials$1;->$sessionCredentialsEntry:Ltechnology/cariad/cat/genx/crypto/SessionCredentials;

    .line 48
    .line 49
    iget-object v2, p0, Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage$storeSessionCredentials$1;->$uniqueKey:Ljava/lang/String;

    .line 50
    .line 51
    new-instance v8, Ltechnology/cariad/cat/genx/crypto/a;

    .line 52
    .line 53
    const/4 v5, 0x0

    .line 54
    invoke-direct {v8, p1, v2, v5}, Ltechnology/cariad/cat/genx/crypto/a;-><init>(Ljava/lang/Object;Ljava/io/Serializable;I)V

    .line 55
    .line 56
    .line 57
    new-instance v5, Lt51/j;

    .line 58
    .line 59
    invoke-static {v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 60
    .line 61
    .line 62
    move-result-object v10

    .line 63
    invoke-static {v3}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 64
    .line 65
    .line 66
    move-result-object v11

    .line 67
    const-string v6, "GenX"

    .line 68
    .line 69
    sget-object v7, Lt51/d;->a:Lt51/d;

    .line 70
    .line 71
    const/4 v9, 0x0

    .line 72
    invoke-direct/range {v5 .. v11}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 73
    .line 74
    .line 75
    invoke-static {v5}, Lt51/a;->a(Lt51/j;)V

    .line 76
    .line 77
    .line 78
    iget-object p1, p0, Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage$storeSessionCredentials$1;->this$0:Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage;

    .line 79
    .line 80
    invoke-static {p1}, Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage;->access$getSecureStorage$p(Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage;)Lu51/g;

    .line 81
    .line 82
    .line 83
    move-result-object p1

    .line 84
    iget-object v2, p0, Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage$storeSessionCredentials$1;->$uniqueKey:Ljava/lang/String;

    .line 85
    .line 86
    iget-object v5, p0, Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage$storeSessionCredentials$1;->$sessionCredentialsEntry:Ltechnology/cariad/cat/genx/crypto/SessionCredentials;

    .line 87
    .line 88
    const-class v6, Ltechnology/cariad/cat/genx/crypto/SessionCredentials;

    .line 89
    .line 90
    invoke-static {v6}, Lkotlin/jvm/internal/g0;->b(Ljava/lang/Class;)Lhy0/a0;

    .line 91
    .line 92
    .line 93
    move-result-object v6

    .line 94
    iput-object v0, p0, Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage$storeSessionCredentials$1;->L$0:Ljava/lang/Object;

    .line 95
    .line 96
    const/4 v7, 0x0

    .line 97
    iput-object v7, p0, Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage$storeSessionCredentials$1;->L$1:Ljava/lang/Object;

    .line 98
    .line 99
    iput-object v7, p0, Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage$storeSessionCredentials$1;->L$2:Ljava/lang/Object;

    .line 100
    .line 101
    iput-object v7, p0, Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage$storeSessionCredentials$1;->L$3:Ljava/lang/Object;

    .line 102
    .line 103
    const/4 v7, 0x0

    .line 104
    iput v7, p0, Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage$storeSessionCredentials$1;->I$0:I

    .line 105
    .line 106
    iput v4, p0, Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage$storeSessionCredentials$1;->label:I

    .line 107
    .line 108
    check-cast p1, Lv51/f;

    .line 109
    .line 110
    invoke-virtual {p1, v2, v5, v6, p0}, Lv51/f;->d(Ljava/lang/String;Ljava/lang/Object;Lhy0/a0;Lrx0/c;)Ljava/lang/Object;

    .line 111
    .line 112
    .line 113
    move-result-object p1

    .line 114
    if-ne p1, v1, :cond_2

    .line 115
    .line 116
    return-object v1

    .line 117
    :cond_2
    :goto_0
    iget-object p0, p0, Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage$storeSessionCredentials$1;->$sessionCredentialsEntry:Ltechnology/cariad/cat/genx/crypto/SessionCredentials;

    .line 118
    .line 119
    invoke-static {p1}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 120
    .line 121
    .line 122
    move-result-object v8

    .line 123
    if-nez v8, :cond_3

    .line 124
    .line 125
    check-cast p1, Llx0/b0;

    .line 126
    .line 127
    sget-object p0, Ltechnology/cariad/cat/genx/CoreGenXStatus;->Companion:Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;

    .line 128
    .line 129
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getSuccess()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 130
    .line 131
    .line 132
    move-result-object p0

    .line 133
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 134
    .line 135
    .line 136
    move-result p0

    .line 137
    new-instance p1, Ljava/lang/Integer;

    .line 138
    .line 139
    invoke-direct {p1, p0}, Ljava/lang/Integer;-><init>(I)V

    .line 140
    .line 141
    .line 142
    return-object p1

    .line 143
    :cond_3
    new-instance v7, Ltechnology/cariad/cat/genx/crypto/b;

    .line 144
    .line 145
    const/4 p1, 0x0

    .line 146
    invoke-direct {v7, p0, p1}, Ltechnology/cariad/cat/genx/crypto/b;-><init>(Ljava/lang/Object;I)V

    .line 147
    .line 148
    .line 149
    new-instance v4, Lt51/j;

    .line 150
    .line 151
    invoke-static {v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 152
    .line 153
    .line 154
    move-result-object v9

    .line 155
    invoke-static {v3}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 156
    .line 157
    .line 158
    move-result-object v10

    .line 159
    const-string v5, "GenX"

    .line 160
    .line 161
    sget-object v6, Lt51/e;->a:Lt51/e;

    .line 162
    .line 163
    invoke-direct/range {v4 .. v10}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 164
    .line 165
    .line 166
    invoke-static {v4}, Lt51/a;->a(Lt51/j;)V

    .line 167
    .line 168
    .line 169
    sget-object p0, Ltechnology/cariad/cat/genx/CoreGenXStatus;->Companion:Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;

    .line 170
    .line 171
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getCryptoOperationFailed()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 172
    .line 173
    .line 174
    move-result-object p0

    .line 175
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 176
    .line 177
    .line 178
    move-result p0

    .line 179
    new-instance p1, Ljava/lang/Integer;

    .line 180
    .line 181
    invoke-direct {p1, p0}, Ljava/lang/Integer;-><init>(I)V

    .line 182
    .line 183
    .line 184
    return-object p1
.end method
