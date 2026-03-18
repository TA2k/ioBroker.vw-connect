.class public final Lyy0/f1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/i;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:[Lyy0/i;

.field public final synthetic f:Lrx0/i;


# direct methods
.method public constructor <init>([Lyy0/i;Lay0/p;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lyy0/f1;->d:I

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Lyy0/f1;->e:[Lyy0/i;

    check-cast p2, Lrx0/i;

    iput-object p2, p0, Lyy0/f1;->f:Lrx0/i;

    return-void
.end method

.method public constructor <init>([Lyy0/i;Lay0/r;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lyy0/f1;->d:I

    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    iput-object p1, p0, Lyy0/f1;->e:[Lyy0/i;

    check-cast p2, Lrx0/i;

    iput-object p2, p0, Lyy0/f1;->f:Lrx0/i;

    return-void
.end method


# virtual methods
.method public final collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 3

    .line 1
    iget v0, p0, Lyy0/f1;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lyy0/e1;

    .line 7
    .line 8
    const/4 v1, 0x0

    .line 9
    iget-object v2, p0, Lyy0/f1;->f:Lrx0/i;

    .line 10
    .line 11
    invoke-direct {v0, v1, v2}, Lyy0/e1;-><init>(Lkotlin/coroutines/Continuation;Lay0/r;)V

    .line 12
    .line 13
    .line 14
    sget-object v1, Lyy0/h1;->d:Lyy0/h1;

    .line 15
    .line 16
    iget-object p0, p0, Lyy0/f1;->e:[Lyy0/i;

    .line 17
    .line 18
    invoke-static {v1, v0, p2, p1, p0}, Lzy0/c;->a(Lay0/a;Lay0/o;Lkotlin/coroutines/Continuation;Lyy0/j;[Lyy0/i;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 23
    .line 24
    if-ne p0, p1, :cond_0

    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 28
    .line 29
    :goto_0
    return-object p0

    .line 30
    :pswitch_0
    new-instance v0, Lyy0/e1;

    .line 31
    .line 32
    const/4 v1, 0x0

    .line 33
    iget-object v2, p0, Lyy0/f1;->f:Lrx0/i;

    .line 34
    .line 35
    invoke-direct {v0, v1, v2}, Lyy0/e1;-><init>(Lkotlin/coroutines/Continuation;Lay0/p;)V

    .line 36
    .line 37
    .line 38
    sget-object v1, Lyy0/h1;->d:Lyy0/h1;

    .line 39
    .line 40
    iget-object p0, p0, Lyy0/f1;->e:[Lyy0/i;

    .line 41
    .line 42
    invoke-static {v1, v0, p2, p1, p0}, Lzy0/c;->a(Lay0/a;Lay0/o;Lkotlin/coroutines/Continuation;Lyy0/j;[Lyy0/i;)Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 47
    .line 48
    if-ne p0, p1, :cond_1

    .line 49
    .line 50
    goto :goto_1

    .line 51
    :cond_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 52
    .line 53
    :goto_1
    return-object p0

    .line 54
    nop

    .line 55
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
