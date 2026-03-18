.class public final Lbn0/d;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I

.field public synthetic e:Ljava/lang/String;

.field public synthetic f:Ljava/lang/String;


# direct methods
.method public synthetic constructor <init>(ILkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lbn0/d;->d:I

    .line 2
    .line 3
    invoke-direct {p0, p1, p2}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget p0, p0, Lbn0/d;->d:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ljava/lang/String;

    .line 7
    .line 8
    check-cast p2, Ljava/lang/String;

    .line 9
    .line 10
    check-cast p3, Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    new-instance p0, Lbn0/d;

    .line 13
    .line 14
    const/4 v0, 0x3

    .line 15
    const/4 v1, 0x1

    .line 16
    invoke-direct {p0, v0, p3, v1}, Lbn0/d;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 17
    .line 18
    .line 19
    iput-object p1, p0, Lbn0/d;->e:Ljava/lang/String;

    .line 20
    .line 21
    iput-object p2, p0, Lbn0/d;->f:Ljava/lang/String;

    .line 22
    .line 23
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 24
    .line 25
    invoke-virtual {p0, p1}, Lbn0/d;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    return-object p0

    .line 30
    :pswitch_0
    check-cast p1, Lss0/j0;

    .line 31
    .line 32
    if-eqz p1, :cond_0

    .line 33
    .line 34
    iget-object p0, p1, Lss0/j0;->d:Ljava/lang/String;

    .line 35
    .line 36
    goto :goto_0

    .line 37
    :cond_0
    const/4 p0, 0x0

    .line 38
    :goto_0
    check-cast p2, Ljava/lang/String;

    .line 39
    .line 40
    check-cast p3, Lkotlin/coroutines/Continuation;

    .line 41
    .line 42
    new-instance p1, Lbn0/d;

    .line 43
    .line 44
    const/4 v0, 0x3

    .line 45
    const/4 v1, 0x0

    .line 46
    invoke-direct {p1, v0, p3, v1}, Lbn0/d;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 47
    .line 48
    .line 49
    iput-object p0, p1, Lbn0/d;->e:Ljava/lang/String;

    .line 50
    .line 51
    iput-object p2, p1, Lbn0/d;->f:Ljava/lang/String;

    .line 52
    .line 53
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 54
    .line 55
    invoke-virtual {p1, p0}, Lbn0/d;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object p0

    .line 59
    return-object p0

    .line 60
    nop

    .line 61
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Lbn0/d;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lbn0/d;->e:Ljava/lang/String;

    .line 7
    .line 8
    iget-object p0, p0, Lbn0/d;->f:Ljava/lang/String;

    .line 9
    .line 10
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 11
    .line 12
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 13
    .line 14
    .line 15
    new-instance p1, Llx0/l;

    .line 16
    .line 17
    invoke-direct {p1, v0, p0}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 18
    .line 19
    .line 20
    return-object p1

    .line 21
    :pswitch_0
    iget-object v0, p0, Lbn0/d;->e:Ljava/lang/String;

    .line 22
    .line 23
    iget-object p0, p0, Lbn0/d;->f:Ljava/lang/String;

    .line 24
    .line 25
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 26
    .line 27
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 28
    .line 29
    .line 30
    if-eqz v0, :cond_0

    .line 31
    .line 32
    new-instance p1, Lss0/j0;

    .line 33
    .line 34
    invoke-direct {p1, v0}, Lss0/j0;-><init>(Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    goto :goto_0

    .line 38
    :cond_0
    const/4 p1, 0x0

    .line 39
    :goto_0
    new-instance v0, Llx0/l;

    .line 40
    .line 41
    invoke-direct {v0, p1, p0}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    return-object v0

    .line 45
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
