.class public final Lna/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/i;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Z

.field public final synthetic f:Lyy0/i;

.field public final synthetic g:Ljava/lang/Object;

.field public final synthetic h:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Lyy0/i;Lla/u;ZLay0/k;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lna/j;->d:I

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Lna/j;->f:Lyy0/i;

    iput-object p2, p0, Lna/j;->g:Ljava/lang/Object;

    iput-boolean p3, p0, Lna/j;->e:Z

    iput-object p4, p0, Lna/j;->h:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lyy0/m1;Lyb0/l;Lzb0/c;Z)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lna/j;->d:I

    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    iput-object p1, p0, Lna/j;->f:Lyy0/i;

    iput-object p2, p0, Lna/j;->g:Ljava/lang/Object;

    iput-object p3, p0, Lna/j;->h:Ljava/lang/Object;

    iput-boolean p4, p0, Lna/j;->e:Z

    return-void
.end method


# virtual methods
.method public final collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 4

    .line 1
    iget v0, p0, Lna/j;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lna/j;->f:Lyy0/i;

    .line 7
    .line 8
    check-cast v0, Lyy0/m1;

    .line 9
    .line 10
    new-instance v1, Lna/i;

    .line 11
    .line 12
    iget-object v2, p0, Lna/j;->g:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast v2, Lyb0/l;

    .line 15
    .line 16
    iget-object v3, p0, Lna/j;->h:Ljava/lang/Object;

    .line 17
    .line 18
    check-cast v3, Lzb0/c;

    .line 19
    .line 20
    iget-boolean p0, p0, Lna/j;->e:Z

    .line 21
    .line 22
    invoke-direct {v1, p1, v2, v3, p0}, Lna/i;-><init>(Lyy0/j;Lyb0/l;Lzb0/c;Z)V

    .line 23
    .line 24
    .line 25
    invoke-virtual {v0, v1, p2}, Lyy0/m1;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 30
    .line 31
    if-ne p0, p1, :cond_0

    .line 32
    .line 33
    goto :goto_0

    .line 34
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 35
    .line 36
    :goto_0
    return-object p0

    .line 37
    :pswitch_0
    new-instance v0, Lna/i;

    .line 38
    .line 39
    iget-object v1, p0, Lna/j;->g:Ljava/lang/Object;

    .line 40
    .line 41
    check-cast v1, Lla/u;

    .line 42
    .line 43
    iget-object v2, p0, Lna/j;->h:Ljava/lang/Object;

    .line 44
    .line 45
    check-cast v2, Lay0/k;

    .line 46
    .line 47
    iget-boolean v3, p0, Lna/j;->e:Z

    .line 48
    .line 49
    invoke-direct {v0, p1, v1, v3, v2}, Lna/i;-><init>(Lyy0/j;Lla/u;ZLay0/k;)V

    .line 50
    .line 51
    .line 52
    iget-object p0, p0, Lna/j;->f:Lyy0/i;

    .line 53
    .line 54
    invoke-interface {p0, v0, p2}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 55
    .line 56
    .line 57
    move-result-object p0

    .line 58
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 59
    .line 60
    if-ne p0, p1, :cond_1

    .line 61
    .line 62
    goto :goto_1

    .line 63
    :cond_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 64
    .line 65
    :goto_1
    return-object p0

    .line 66
    nop

    .line 67
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
