.class public final Li61/i;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/p;


# instance fields
.field public d:I

.field public synthetic e:Ltechnology/cariad/cat/genx/Car2PhoneMode;

.field public synthetic f:Z

.field public synthetic g:Lg61/h;

.field public final synthetic h:Lvy0/b0;

.field public final synthetic i:Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;


# direct methods
.method public constructor <init>(Lvy0/b0;Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Li61/i;->h:Lvy0/b0;

    .line 2
    .line 3
    iput-object p2, p0, Li61/i;->i:Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;

    .line 4
    .line 5
    const/4 p1, 0x4

    .line 6
    invoke-direct {p0, p1, p3}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    check-cast p1, Ltechnology/cariad/cat/genx/Car2PhoneMode;

    .line 2
    .line 3
    check-cast p2, Ljava/lang/Boolean;

    .line 4
    .line 5
    invoke-virtual {p2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 6
    .line 7
    .line 8
    move-result p2

    .line 9
    check-cast p3, Lg61/h;

    .line 10
    .line 11
    check-cast p4, Lkotlin/coroutines/Continuation;

    .line 12
    .line 13
    new-instance v0, Li61/i;

    .line 14
    .line 15
    iget-object v1, p0, Li61/i;->h:Lvy0/b0;

    .line 16
    .line 17
    iget-object p0, p0, Li61/i;->i:Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;

    .line 18
    .line 19
    invoke-direct {v0, v1, p0, p4}, Li61/i;-><init>(Lvy0/b0;Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;Lkotlin/coroutines/Continuation;)V

    .line 20
    .line 21
    .line 22
    iput-object p1, v0, Li61/i;->e:Ltechnology/cariad/cat/genx/Car2PhoneMode;

    .line 23
    .line 24
    iput-boolean p2, v0, Li61/i;->f:Z

    .line 25
    .line 26
    iput-object p3, v0, Li61/i;->g:Lg61/h;

    .line 27
    .line 28
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 29
    .line 30
    invoke-virtual {v0, p0}, Li61/i;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    .line 1
    iget-object v0, p0, Li61/i;->e:Ltechnology/cariad/cat/genx/Car2PhoneMode;

    .line 2
    .line 3
    iget-boolean v1, p0, Li61/i;->f:Z

    .line 4
    .line 5
    iget-object v2, p0, Li61/i;->g:Lg61/h;

    .line 6
    .line 7
    sget-object v3, Lqx0/a;->d:Lqx0/a;

    .line 8
    .line 9
    iget v4, p0, Li61/i;->d:I

    .line 10
    .line 11
    sget-object v5, Llx0/b0;->a:Llx0/b0;

    .line 12
    .line 13
    const/4 v6, 0x1

    .line 14
    if-eqz v4, :cond_1

    .line 15
    .line 16
    if-ne v4, v6, :cond_0

    .line 17
    .line 18
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 19
    .line 20
    .line 21
    return-object v5

    .line 22
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 23
    .line 24
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 25
    .line 26
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    throw p0

    .line 30
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 31
    .line 32
    .line 33
    new-instance p1, Lb71/o;

    .line 34
    .line 35
    const/4 v4, 0x2

    .line 36
    invoke-direct {p1, v0, v1, v2, v4}, Lb71/o;-><init>(Ljava/lang/Object;ZLjava/lang/Enum;I)V

    .line 37
    .line 38
    .line 39
    iget-object v4, p0, Li61/i;->h:Lvy0/b0;

    .line 40
    .line 41
    invoke-static {v4, p1}, Llp/i1;->b(Ljava/lang/Object;Lay0/a;)V

    .line 42
    .line 43
    .line 44
    iget-object p1, p0, Li61/i;->i:Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;

    .line 45
    .line 46
    invoke-static {p1, v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->access$createRPAStatus(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;Ltechnology/cariad/cat/genx/Car2PhoneMode;ZLg61/h;)Lg61/p;

    .line 47
    .line 48
    .line 49
    move-result-object v0

    .line 50
    invoke-static {p1}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->access$get_status$p(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;)Lyy0/j1;

    .line 51
    .line 52
    .line 53
    move-result-object p1

    .line 54
    const/4 v2, 0x0

    .line 55
    iput-object v2, p0, Li61/i;->e:Ltechnology/cariad/cat/genx/Car2PhoneMode;

    .line 56
    .line 57
    iput-object v2, p0, Li61/i;->g:Lg61/h;

    .line 58
    .line 59
    iput-boolean v1, p0, Li61/i;->f:Z

    .line 60
    .line 61
    iput v6, p0, Li61/i;->d:I

    .line 62
    .line 63
    check-cast p1, Lyy0/c2;

    .line 64
    .line 65
    invoke-virtual {p1, v0, p0}, Lyy0/c2;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    if-ne v5, v3, :cond_2

    .line 69
    .line 70
    return-object v3

    .line 71
    :cond_2
    return-object v5
.end method
