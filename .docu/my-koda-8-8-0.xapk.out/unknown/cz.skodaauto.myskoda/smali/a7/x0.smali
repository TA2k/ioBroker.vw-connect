.class public final La7/x0;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public d:La7/z0;

.field public e:Landroid/content/Context;

.field public f:I

.field public g:I

.field public h:I

.field public synthetic i:Ljava/lang/Object;

.field public final synthetic j:La7/z0;

.field public final synthetic k:Landroid/content/Context;

.field public final synthetic l:[I


# direct methods
.method public constructor <init>(La7/z0;Landroid/content/Context;[ILkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, La7/x0;->j:La7/z0;

    .line 2
    .line 3
    iput-object p2, p0, La7/x0;->k:Landroid/content/Context;

    .line 4
    .line 5
    iput-object p3, p0, La7/x0;->l:[I

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


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 3

    .line 1
    new-instance v0, La7/x0;

    .line 2
    .line 3
    iget-object v1, p0, La7/x0;->k:Landroid/content/Context;

    .line 4
    .line 5
    iget-object v2, p0, La7/x0;->l:[I

    .line 6
    .line 7
    iget-object p0, p0, La7/x0;->j:La7/z0;

    .line 8
    .line 9
    invoke-direct {v0, p0, v1, v2, p2}, La7/x0;-><init>(La7/z0;Landroid/content/Context;[ILkotlin/coroutines/Continuation;)V

    .line 10
    .line 11
    .line 12
    iput-object p1, v0, La7/x0;->i:Ljava/lang/Object;

    .line 13
    .line 14
    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lvy0/b0;

    .line 2
    .line 3
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    invoke-virtual {p0, p1, p2}, La7/x0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, La7/x0;

    .line 10
    .line 11
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 12
    .line 13
    invoke-virtual {p0, p1}, La7/x0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    .line 1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 2
    .line 3
    iget v1, p0, La7/x0;->h:I

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
    iget v1, p0, La7/x0;->g:I

    .line 11
    .line 12
    iget v3, p0, La7/x0;->f:I

    .line 13
    .line 14
    iget-object v4, p0, La7/x0;->e:Landroid/content/Context;

    .line 15
    .line 16
    iget-object v5, p0, La7/x0;->d:La7/z0;

    .line 17
    .line 18
    iget-object v6, p0, La7/x0;->i:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast v6, [I

    .line 21
    .line 22
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 23
    .line 24
    .line 25
    goto :goto_1

    .line 26
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 27
    .line 28
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 29
    .line 30
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    throw p0

    .line 34
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 35
    .line 36
    .line 37
    iget-object p1, p0, La7/x0;->i:Ljava/lang/Object;

    .line 38
    .line 39
    check-cast p1, Lvy0/b0;

    .line 40
    .line 41
    iget-object v1, p0, La7/x0;->j:La7/z0;

    .line 42
    .line 43
    iget-object v3, p0, La7/x0;->k:Landroid/content/Context;

    .line 44
    .line 45
    invoke-static {v1, p1, v3}, La7/z0;->a(La7/z0;Lvy0/b0;Landroid/content/Context;)V

    .line 46
    .line 47
    .line 48
    iget-object p1, p0, La7/x0;->l:[I

    .line 49
    .line 50
    array-length v4, p1

    .line 51
    const/4 v5, 0x0

    .line 52
    move v6, v5

    .line 53
    move-object v5, v1

    .line 54
    move v1, v4

    .line 55
    move-object v4, v3

    .line 56
    move v3, v6

    .line 57
    move-object v6, p1

    .line 58
    :goto_0
    if-ge v3, v1, :cond_3

    .line 59
    .line 60
    aget p1, v6, v3

    .line 61
    .line 62
    move-object v7, v5

    .line 63
    check-cast v7, Lcz/skodaauto/myskoda/feature/widget/system/WidgetReceiver;

    .line 64
    .line 65
    iget-object v7, v7, Lcz/skodaauto/myskoda/feature/widget/system/WidgetReceiver;->f:Lza0/q;

    .line 66
    .line 67
    iput-object v6, p0, La7/x0;->i:Ljava/lang/Object;

    .line 68
    .line 69
    iput-object v5, p0, La7/x0;->d:La7/z0;

    .line 70
    .line 71
    iput-object v4, p0, La7/x0;->e:Landroid/content/Context;

    .line 72
    .line 73
    iput v3, p0, La7/x0;->f:I

    .line 74
    .line 75
    iput v1, p0, La7/x0;->g:I

    .line 76
    .line 77
    iput v2, p0, La7/x0;->h:I

    .line 78
    .line 79
    invoke-virtual {v7, v4, p1, p0}, La7/m0;->a(Landroid/content/Context;ILrx0/c;)Ljava/lang/Object;

    .line 80
    .line 81
    .line 82
    move-result-object p1

    .line 83
    if-ne p1, v0, :cond_2

    .line 84
    .line 85
    return-object v0

    .line 86
    :cond_2
    :goto_1
    add-int/2addr v3, v2

    .line 87
    goto :goto_0

    .line 88
    :cond_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 89
    .line 90
    return-object p0
.end method
