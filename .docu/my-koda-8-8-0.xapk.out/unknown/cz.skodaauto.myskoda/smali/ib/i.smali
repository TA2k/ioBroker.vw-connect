.class public final Lib/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/i;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:[Lyy0/i;


# direct methods
.method public synthetic constructor <init>([Lyy0/i;I)V
    .locals 0

    .line 1
    iput p2, p0, Lib/i;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lib/i;->e:[Lyy0/i;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 5

    .line 1
    iget v0, p0, Lib/i;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lac/j;

    .line 7
    .line 8
    const/4 v1, 0x3

    .line 9
    iget-object p0, p0, Lib/i;->e:[Lyy0/i;

    .line 10
    .line 11
    invoke-direct {v0, p0, v1}, Lac/j;-><init>([Lyy0/i;I)V

    .line 12
    .line 13
    .line 14
    new-instance v1, Lib/h;

    .line 15
    .line 16
    const/4 v2, 0x3

    .line 17
    const/4 v3, 0x2

    .line 18
    const/4 v4, 0x0

    .line 19
    invoke-direct {v1, v2, v4, v3}, Lib/h;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 20
    .line 21
    .line 22
    invoke-static {v0, v1, p2, p1, p0}, Lzy0/c;->a(Lay0/a;Lay0/o;Lkotlin/coroutines/Continuation;Lyy0/j;[Lyy0/i;)Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 27
    .line 28
    if-ne p0, p1, :cond_0

    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 32
    .line 33
    :goto_0
    return-object p0

    .line 34
    :pswitch_0
    new-instance v0, Lac/j;

    .line 35
    .line 36
    const/4 v1, 0x2

    .line 37
    iget-object p0, p0, Lib/i;->e:[Lyy0/i;

    .line 38
    .line 39
    invoke-direct {v0, p0, v1}, Lac/j;-><init>([Lyy0/i;I)V

    .line 40
    .line 41
    .line 42
    new-instance v1, Lib/h;

    .line 43
    .line 44
    const/4 v2, 0x3

    .line 45
    const/4 v3, 0x1

    .line 46
    const/4 v4, 0x0

    .line 47
    invoke-direct {v1, v2, v4, v3}, Lib/h;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 48
    .line 49
    .line 50
    invoke-static {v0, v1, p2, p1, p0}, Lzy0/c;->a(Lay0/a;Lay0/o;Lkotlin/coroutines/Continuation;Lyy0/j;[Lyy0/i;)Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    move-result-object p0

    .line 54
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 55
    .line 56
    if-ne p0, p1, :cond_1

    .line 57
    .line 58
    goto :goto_1

    .line 59
    :cond_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 60
    .line 61
    :goto_1
    return-object p0

    .line 62
    :pswitch_1
    new-instance v0, Lac/j;

    .line 63
    .line 64
    const/4 v1, 0x1

    .line 65
    iget-object p0, p0, Lib/i;->e:[Lyy0/i;

    .line 66
    .line 67
    invoke-direct {v0, p0, v1}, Lac/j;-><init>([Lyy0/i;I)V

    .line 68
    .line 69
    .line 70
    new-instance v1, Lib/h;

    .line 71
    .line 72
    const/4 v2, 0x3

    .line 73
    const/4 v3, 0x0

    .line 74
    const/4 v4, 0x0

    .line 75
    invoke-direct {v1, v2, v4, v3}, Lib/h;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 76
    .line 77
    .line 78
    invoke-static {v0, v1, p2, p1, p0}, Lzy0/c;->a(Lay0/a;Lay0/o;Lkotlin/coroutines/Continuation;Lyy0/j;[Lyy0/i;)Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 83
    .line 84
    if-ne p0, p1, :cond_2

    .line 85
    .line 86
    goto :goto_2

    .line 87
    :cond_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 88
    .line 89
    :goto_2
    return-object p0

    .line 90
    nop

    .line 91
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
