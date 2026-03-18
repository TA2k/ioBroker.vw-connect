.class final Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage$retrieveSessionCredentials$2;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage;->retrieveSessionCredentials$genx_release([B[BB)Ltechnology/cariad/cat/genx/crypto/SessionCredentials;
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
        "\u0000\u0010\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\u0010\u0003\u001a\u0008\u0012\u0004\u0012\u00020\u00020\u0001*\u00020\u0000H\n\u00a2\u0006\u0004\u0008\u0003\u0010\u0004"
    }
    d2 = {
        "Lvy0/b0;",
        "Llx0/o;",
        "Llx0/b0;",
        "<anonymous>",
        "(Lvy0/b0;)Llx0/o;"
    }
    k = 0x3
    mv = {
        0x2,
        0x2,
        0x0
    }
.end annotation

.annotation runtime Lrx0/e;
    c = "technology.cariad.cat.genx.crypto.CredentialStoreWithSecureStorage$retrieveSessionCredentials$2"
    f = "CredentialStoreWithSecureStorage.kt"
    l = {
        0x47
    }
    m = "invokeSuspend"
    v = 0x1
.end annotation


# instance fields
.field final synthetic $uniqueKey:Ljava/lang/String;

.field label:I

.field final synthetic this$0:Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage;


# direct methods
.method public constructor <init>(Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage;Ljava/lang/String;Lkotlin/coroutines/Continuation;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage;",
            "Ljava/lang/String;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage$retrieveSessionCredentials$2;",
            ">;)V"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage$retrieveSessionCredentials$2;->this$0:Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage;

    .line 2
    .line 3
    iput-object p2, p0, Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage$retrieveSessionCredentials$2;->$uniqueKey:Ljava/lang/String;

    .line 4
    .line 5
    const/4 p1, 0x2

    .line 6
    invoke-direct {p0, p1, p3}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 1
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
    new-instance p1, Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage$retrieveSessionCredentials$2;

    .line 2
    .line 3
    iget-object v0, p0, Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage$retrieveSessionCredentials$2;->this$0:Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage;

    .line 4
    .line 5
    iget-object p0, p0, Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage$retrieveSessionCredentials$2;->$uniqueKey:Ljava/lang/String;

    .line 6
    .line 7
    invoke-direct {p1, v0, p0, p2}, Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage$retrieveSessionCredentials$2;-><init>(Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage;Ljava/lang/String;Lkotlin/coroutines/Continuation;)V

    .line 8
    .line 9
    .line 10
    return-object p1
.end method

.method public bridge synthetic invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lvy0/b0;

    check-cast p2, Lkotlin/coroutines/Continuation;

    invoke-virtual {p0, p1, p2}, Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage$retrieveSessionCredentials$2;->invoke(Lvy0/b0;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

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
            "Llx0/o;",
            ">;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .line 2
    invoke-virtual {p0, p1, p2}, Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage$retrieveSessionCredentials$2;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    move-result-object p0

    check-cast p0, Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage$retrieveSessionCredentials$2;

    sget-object p1, Llx0/b0;->a:Llx0/b0;

    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage$retrieveSessionCredentials$2;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    .line 1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 2
    .line 3
    iget v1, p0, Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage$retrieveSessionCredentials$2;->label:I

    .line 4
    .line 5
    const/4 v2, 0x1

    .line 6
    if-eqz v1, :cond_1

    .line 7
    .line 8
    if-ne v1, v2, :cond_0

    .line 9
    .line 10
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 11
    .line 12
    .line 13
    check-cast p1, Llx0/o;

    .line 14
    .line 15
    iget-object p0, p1, Llx0/o;->d:Ljava/lang/Object;

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 19
    .line 20
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 21
    .line 22
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    throw p0

    .line 26
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 27
    .line 28
    .line 29
    iget-object p1, p0, Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage$retrieveSessionCredentials$2;->this$0:Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage;

    .line 30
    .line 31
    invoke-static {p1}, Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage;->access$getSecureStorage$p(Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage;)Lu51/g;

    .line 32
    .line 33
    .line 34
    move-result-object p1

    .line 35
    iget-object v1, p0, Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage$retrieveSessionCredentials$2;->$uniqueKey:Ljava/lang/String;

    .line 36
    .line 37
    iput v2, p0, Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage$retrieveSessionCredentials$2;->label:I

    .line 38
    .line 39
    check-cast p1, Lv51/f;

    .line 40
    .line 41
    invoke-virtual {p1, v1, p0}, Lv51/f;->b(Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    if-ne p0, v0, :cond_2

    .line 46
    .line 47
    return-object v0

    .line 48
    :cond_2
    :goto_0
    new-instance p1, Llx0/o;

    .line 49
    .line 50
    invoke-direct {p1, p0}, Llx0/o;-><init>(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    return-object p1
.end method
