.class public final Li61/a;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public synthetic e:Z

.field public final synthetic f:Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAPluginImpl;


# direct methods
.method public synthetic constructor <init>(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAPluginImpl;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Li61/a;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Li61/a;->f:Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAPluginImpl;

    .line 4
    .line 5
    const/4 p1, 0x2

    .line 6
    invoke-direct {p0, p1, p2}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 2

    .line 1
    iget v0, p0, Li61/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Li61/a;

    .line 7
    .line 8
    iget-object p0, p0, Li61/a;->f:Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAPluginImpl;

    .line 9
    .line 10
    const/4 v1, 0x1

    .line 11
    invoke-direct {v0, p0, p2, v1}, Li61/a;-><init>(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAPluginImpl;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    check-cast p1, Ljava/lang/Boolean;

    .line 15
    .line 16
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 17
    .line 18
    .line 19
    move-result p0

    .line 20
    iput-boolean p0, v0, Li61/a;->e:Z

    .line 21
    .line 22
    return-object v0

    .line 23
    :pswitch_0
    new-instance v0, Li61/a;

    .line 24
    .line 25
    iget-object p0, p0, Li61/a;->f:Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAPluginImpl;

    .line 26
    .line 27
    const/4 v1, 0x0

    .line 28
    invoke-direct {v0, p0, p2, v1}, Li61/a;-><init>(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAPluginImpl;Lkotlin/coroutines/Continuation;I)V

    .line 29
    .line 30
    .line 31
    check-cast p1, Ljava/lang/Boolean;

    .line 32
    .line 33
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 34
    .line 35
    .line 36
    move-result p0

    .line 37
    iput-boolean p0, v0, Li61/a;->e:Z

    .line 38
    .line 39
    return-object v0

    .line 40
    nop

    .line 41
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Li61/a;->d:I

    .line 2
    .line 3
    check-cast p1, Ljava/lang/Boolean;

    .line 4
    .line 5
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 6
    .line 7
    .line 8
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 9
    .line 10
    packed-switch v0, :pswitch_data_0

    .line 11
    .line 12
    .line 13
    invoke-virtual {p0, p1, p2}, Li61/a;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    check-cast p0, Li61/a;

    .line 18
    .line 19
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 20
    .line 21
    invoke-virtual {p0, p1}, Li61/a;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    return-object p1

    .line 25
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Li61/a;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    check-cast p0, Li61/a;

    .line 30
    .line 31
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 32
    .line 33
    invoke-virtual {p0, p1}, Li61/a;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    return-object p1

    .line 37
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    .line 1
    iget v0, p0, Li61/a;->d:I

    .line 2
    .line 3
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 4
    .line 5
    iget-object v2, p0, Li61/a;->f:Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAPluginImpl;

    .line 6
    .line 7
    iget-boolean p0, p0, Li61/a;->e:Z

    .line 8
    .line 9
    packed-switch v0, :pswitch_data_0

    .line 10
    .line 11
    .line 12
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 13
    .line 14
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    new-instance p1, Lfw0/n;

    .line 18
    .line 19
    const/4 v0, 0x3

    .line 20
    invoke-direct {p1, v0, p0}, Lfw0/n;-><init>(IZ)V

    .line 21
    .line 22
    .line 23
    invoke-static {v2, p1}, Llp/i1;->e(Ljava/lang/Object;Lay0/a;)V

    .line 24
    .line 25
    .line 26
    if-nez p0, :cond_0

    .line 27
    .line 28
    sget-object p0, Lg61/h;->e:Lg61/h;

    .line 29
    .line 30
    invoke-static {v2, p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAPluginImpl;->b(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAPluginImpl;Lg61/h;)V

    .line 31
    .line 32
    .line 33
    goto :goto_0

    .line 34
    :cond_0
    sget-object p0, Lg61/h;->e:Lg61/h;

    .line 35
    .line 36
    invoke-static {v2, p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAPluginImpl;->a(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAPluginImpl;Lg61/h;)V

    .line 37
    .line 38
    .line 39
    :goto_0
    return-object v1

    .line 40
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 41
    .line 42
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 43
    .line 44
    .line 45
    new-instance p1, Lfw0/n;

    .line 46
    .line 47
    const/4 v0, 0x2

    .line 48
    invoke-direct {p1, v0, p0}, Lfw0/n;-><init>(IZ)V

    .line 49
    .line 50
    .line 51
    invoke-static {v2, p1}, Llp/i1;->e(Ljava/lang/Object;Lay0/a;)V

    .line 52
    .line 53
    .line 54
    if-nez p0, :cond_1

    .line 55
    .line 56
    sget-object p0, Lg61/h;->d:Lg61/h;

    .line 57
    .line 58
    invoke-static {v2, p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAPluginImpl;->b(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAPluginImpl;Lg61/h;)V

    .line 59
    .line 60
    .line 61
    goto :goto_1

    .line 62
    :cond_1
    sget-object p0, Lg61/h;->d:Lg61/h;

    .line 63
    .line 64
    invoke-static {v2, p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAPluginImpl;->a(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAPluginImpl;Lg61/h;)V

    .line 65
    .line 66
    .line 67
    :goto_1
    return-object v1

    .line 68
    nop

    .line 69
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
