.class public final Lic0/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/i;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lna/j;


# direct methods
.method public synthetic constructor <init>(Lna/j;I)V
    .locals 0

    .line 1
    iput p2, p0, Lic0/i;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lic0/i;->e:Lna/j;

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
    iget v0, p0, Lic0/i;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Ln50/a1;

    .line 7
    .line 8
    const/16 v1, 0xf

    .line 9
    .line 10
    invoke-direct {v0, p1, v1}, Ln50/a1;-><init>(Lyy0/j;I)V

    .line 11
    .line 12
    .line 13
    iget-object p0, p0, Lic0/i;->e:Lna/j;

    .line 14
    .line 15
    invoke-virtual {p0, v0, p2}, Lna/j;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

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
    new-instance v0, Lkf0/x;

    .line 28
    .line 29
    const/16 v1, 0xe

    .line 30
    .line 31
    invoke-direct {v0, p1, v1}, Lkf0/x;-><init>(Lyy0/j;I)V

    .line 32
    .line 33
    .line 34
    iget-object p0, p0, Lic0/i;->e:Lna/j;

    .line 35
    .line 36
    invoke-virtual {p0, v0, p2}, Lna/j;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

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
    :pswitch_1
    new-instance v0, Lhg/u;

    .line 49
    .line 50
    const/16 v1, 0xf

    .line 51
    .line 52
    invoke-direct {v0, p1, v1}, Lhg/u;-><init>(Lyy0/j;I)V

    .line 53
    .line 54
    .line 55
    iget-object p0, p0, Lic0/i;->e:Lna/j;

    .line 56
    .line 57
    invoke-virtual {p0, v0, p2}, Lna/j;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 62
    .line 63
    if-ne p0, p1, :cond_2

    .line 64
    .line 65
    goto :goto_2

    .line 66
    :cond_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 67
    .line 68
    :goto_2
    return-object p0

    .line 69
    :pswitch_2
    new-instance v0, Lhg/u;

    .line 70
    .line 71
    const/16 v1, 0xe

    .line 72
    .line 73
    invoke-direct {v0, p1, v1}, Lhg/u;-><init>(Lyy0/j;I)V

    .line 74
    .line 75
    .line 76
    iget-object p0, p0, Lic0/i;->e:Lna/j;

    .line 77
    .line 78
    invoke-virtual {p0, v0, p2}, Lna/j;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 83
    .line 84
    if-ne p0, p1, :cond_3

    .line 85
    .line 86
    goto :goto_3

    .line 87
    :cond_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 88
    .line 89
    :goto_3
    return-object p0

    .line 90
    nop

    .line 91
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
