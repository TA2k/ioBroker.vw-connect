.class public final Lig0/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/i;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lyy0/i;

.field public final synthetic f:J


# direct methods
.method public synthetic constructor <init>(Lyy0/q1;JI)V
    .locals 0

    .line 1
    iput p4, p0, Lig0/c;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lig0/c;->e:Lyy0/i;

    .line 4
    .line 5
    iput-wide p2, p0, Lig0/c;->f:J

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 4

    .line 1
    iget v0, p0, Lig0/c;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lig0/b;

    .line 7
    .line 8
    iget-wide v1, p0, Lig0/c;->f:J

    .line 9
    .line 10
    const/4 v3, 0x2

    .line 11
    invoke-direct {v0, p1, v1, v2, v3}, Lig0/b;-><init>(Lyy0/j;JI)V

    .line 12
    .line 13
    .line 14
    iget-object p0, p0, Lig0/c;->e:Lyy0/i;

    .line 15
    .line 16
    invoke-interface {p0, v0, p2}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 21
    .line 22
    if-ne p0, p1, :cond_0

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 26
    .line 27
    :goto_0
    return-object p0

    .line 28
    :pswitch_0
    new-instance v0, Lig0/b;

    .line 29
    .line 30
    iget-wide v1, p0, Lig0/c;->f:J

    .line 31
    .line 32
    const/4 v3, 0x1

    .line 33
    invoke-direct {v0, p1, v1, v2, v3}, Lig0/b;-><init>(Lyy0/j;JI)V

    .line 34
    .line 35
    .line 36
    iget-object p0, p0, Lig0/c;->e:Lyy0/i;

    .line 37
    .line 38
    invoke-interface {p0, v0, p2}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 43
    .line 44
    if-ne p0, p1, :cond_1

    .line 45
    .line 46
    goto :goto_1

    .line 47
    :cond_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 48
    .line 49
    :goto_1
    return-object p0

    .line 50
    :pswitch_1
    new-instance v0, Lig0/b;

    .line 51
    .line 52
    iget-wide v1, p0, Lig0/c;->f:J

    .line 53
    .line 54
    const/4 v3, 0x0

    .line 55
    invoke-direct {v0, p1, v1, v2, v3}, Lig0/b;-><init>(Lyy0/j;JI)V

    .line 56
    .line 57
    .line 58
    iget-object p0, p0, Lig0/c;->e:Lyy0/i;

    .line 59
    .line 60
    invoke-interface {p0, v0, p2}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object p0

    .line 64
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 65
    .line 66
    if-ne p0, p1, :cond_2

    .line 67
    .line 68
    goto :goto_2

    .line 69
    :cond_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 70
    .line 71
    :goto_2
    return-object p0

    .line 72
    nop

    .line 73
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
