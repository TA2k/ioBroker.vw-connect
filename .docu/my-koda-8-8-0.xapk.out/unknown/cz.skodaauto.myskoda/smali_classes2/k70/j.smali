.class public final Lk70/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/i;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lne0/n;


# direct methods
.method public synthetic constructor <init>(Lne0/n;I)V
    .locals 0

    .line 1
    iput p2, p0, Lk70/j;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lk70/j;->e:Lne0/n;

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
    iget v0, p0, Lk70/j;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lkf0/x;

    .line 7
    .line 8
    const/16 v1, 0xc

    .line 9
    .line 10
    invoke-direct {v0, p1, v1}, Lkf0/x;-><init>(Lyy0/j;I)V

    .line 11
    .line 12
    .line 13
    iget-object p0, p0, Lk70/j;->e:Lne0/n;

    .line 14
    .line 15
    invoke-virtual {p0, v0, p2}, Lne0/n;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 20
    .line 21
    if-ne p0, p1, :cond_0

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 25
    .line 26
    :goto_0
    return-object p0

    .line 27
    :pswitch_0
    new-instance v0, Lhg/u;

    .line 28
    .line 29
    const/16 v1, 0x17

    .line 30
    .line 31
    invoke-direct {v0, p1, v1}, Lhg/u;-><init>(Lyy0/j;I)V

    .line 32
    .line 33
    .line 34
    iget-object p0, p0, Lk70/j;->e:Lne0/n;

    .line 35
    .line 36
    invoke-virtual {p0, v0, p2}, Lne0/n;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 41
    .line 42
    if-ne p0, p1, :cond_1

    .line 43
    .line 44
    goto :goto_1

    .line 45
    :cond_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 46
    .line 47
    :goto_1
    return-object p0

    .line 48
    nop

    .line 49
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
