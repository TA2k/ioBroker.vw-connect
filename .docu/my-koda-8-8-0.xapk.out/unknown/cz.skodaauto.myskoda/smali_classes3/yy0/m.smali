.class public final Lyy0/m;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/i;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, Lyy0/m;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lyy0/m;->e:Ljava/lang/Object;

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
    .locals 2

    .line 1
    iget v0, p0, Lyy0/m;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lyy0/m;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Lzy0/w;

    .line 9
    .line 10
    new-instance v0, Lwk0/o0;

    .line 11
    .line 12
    const/16 v1, 0x15

    .line 13
    .line 14
    invoke-direct {v0, p1, v1}, Lwk0/o0;-><init>(Lyy0/j;I)V

    .line 15
    .line 16
    .line 17
    invoke-virtual {p0, v0, p2}, Lyy0/q1;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    sget-object p0, Lqx0/a;->d:Lqx0/a;

    .line 21
    .line 22
    return-object p0

    .line 23
    :pswitch_0
    iget-object p0, p0, Lyy0/m;->e:Ljava/lang/Object;

    .line 24
    .line 25
    check-cast p0, Lne0/n;

    .line 26
    .line 27
    new-instance v0, Lwk0/o0;

    .line 28
    .line 29
    const/16 v1, 0x10

    .line 30
    .line 31
    invoke-direct {v0, p1, v1}, Lwk0/o0;-><init>(Lyy0/j;I)V

    .line 32
    .line 33
    .line 34
    invoke-virtual {p0, v0, p2}, Lne0/n;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 39
    .line 40
    if-ne p0, p1, :cond_0

    .line 41
    .line 42
    goto :goto_0

    .line 43
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 44
    .line 45
    :goto_0
    return-object p0

    .line 46
    :pswitch_1
    iget-object p0, p0, Lyy0/m;->e:Ljava/lang/Object;

    .line 47
    .line 48
    invoke-interface {p1, p0, p2}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 53
    .line 54
    if-ne p0, p1, :cond_1

    .line 55
    .line 56
    goto :goto_1

    .line 57
    :cond_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 58
    .line 59
    :goto_1
    return-object p0

    .line 60
    nop

    .line 61
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
